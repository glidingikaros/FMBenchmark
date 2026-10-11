from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from test_iteration2_generation import clock_receipt, clock_run, load

protocol = load("clock_protocol")


class SimulatedConnection:
    def __init__(
        self,
        *,
        launch_delay=0.0,
        offset=36000.0,
        outbound=0.2,
        inbound=0.2,
        setter_delay=0.0,
    ):
        self.now = launch_delay
        self.offset = offset
        self.outbound, self.inbound, self.setter_delay = outbound, inbound, setter_delay
        self.calls = []
        self.service = "Running"
        self.host_step = 0.0
        self.rtc_bias = 480

    def wall(self):
        return datetime(2026, 9, 12, 12, tzinfo=timezone.utc) + timedelta(
            seconds=self.now + self.host_step
        )

    def mono(self):
        return self.now

    def execute(self, script):
        self.calls.append(script)
        self.now += self.outbound
        if script == protocol.RTC_BIAS_SCRIPT:
            stdout = str(self.rtc_bias)
        elif script == protocol.STOP_SERVICE_SCRIPT:
            self.service = "Stopped"
            stdout = ""
        elif "Set-Date" in script:
            self.now += self.setter_delay
            delta = int(re.search(r"AddTicks\((-?\d+)\)", script).group(1))
            self.offset += delta / 10_000_000
            self.service = "Stopped"
            stdout = ""
        else:
            stamp = datetime(2026, 9, 12, 12, tzinfo=timezone.utc) + timedelta(
                seconds=self.now + self.offset
            )
            stdout = json.dumps(
                {"guest_utc": stamp.isoformat(), "w32time_status": self.service}
            )
        self.now += self.inbound
        return {"rc": 0, "stdout": stdout, "stderr": ""}

    def apply(self, *, stage=None, policy="host_sync_then_service_stopped", expected_bias=None):
        return protocol.clock_action(
            self.execute,
            policy=policy,
            stage=stage,
            wall_clock=self.wall,
            monotonic_clock=self.mono,
            expected_rtc_bias_minutes=expected_bias,
        )


def test_relative_correction_is_independent_of_launch_and_setter_startup_delay():
    for launch_delay, setter_delay in [(0, 0), (600, 30)]:
        connection = SimulatedConnection(
            launch_delay=launch_delay, setter_delay=setter_delay
        )
        receipt = connection.apply()
        assert connection.offset == pytest.approx(0)
        assert receipt["applied"] is True and receipt["w32time_status"] == "Stopped"
        assert len(connection.calls) == 4
        assert "UtcNow.AddTicks(-360000000000)" in connection.calls[2]
        assert protocol.require_certain_offset(receipt["measurement"])[
            "offset_seconds"
        ] == pytest.approx(0)
        assert receipt["measurement"]["host_send_utc"] != receipt["host_utc_iso"]


@pytest.fixture
def no_retake_pause(monkeypatch):
    monkeypatch.setattr(protocol, "RETAKE_PAUSE_SECONDS", 0)


def test_wide_calibration_roundtrip_is_unproven_and_never_sets_clock(no_retake_pause):
    connection = SimulatedConnection(outbound=2, inbound=2)
    with pytest.raises(ValueError, match="calibration_timing_uncertain"):
        connection.apply()
    assert len(connection.calls) == 2 + protocol.RETAKES and not any(
        "Set-Date" in s for s in connection.calls
    )


def test_overlap_with_tolerance_is_not_sufficient_checkpoint_proof(no_retake_pause):
    connection = SimulatedConnection(offset=0, outbound=2, inbound=2)
    connection.service = "Stopped"
    with pytest.raises(ValueError, match="offset_not_proven"):
        connection.apply(stage="pre_export")
    assert len(connection.calls) == 1 + protocol.RETAKES


def test_a_slow_reading_on_a_busy_host_is_taken_again(no_retake_pause):
    connection = SimulatedConnection(offset=0, outbound=2, inbound=2)
    connection.service = "Stopped"
    execute = connection.execute

    def settling(script):
        result = execute(script)
        if len(connection.calls) == 2:
            connection.outbound = connection.inbound = 0.2
        return result

    point = protocol.clock_action(settling, policy="host_sync_then_service_stopped", stage="pre_export",
                                  wall_clock=connection.wall, monotonic_clock=connection.mono)
    assert len(connection.calls) == 3
    assert point["measurement"]["monotonic_elapsed_seconds"] == pytest.approx(0.4)
    assert protocol.require_certain_offset(point["measurement"])["offset_seconds"] == pytest.approx(0)


def test_a_reading_across_a_host_clock_step_is_taken_again(no_retake_pause):
    connection = SimulatedConnection(offset=0)
    connection.service = "Stopped"
    execute = connection.execute

    def stepping_once(script):
        result = execute(script)
        if len(connection.calls) == 1:
            connection.host_step += 1
        return result

    point = protocol.clock_action(stepping_once, policy="host_sync_then_service_stopped", stage="pre_export",
                                  wall_clock=connection.wall, monotonic_clock=connection.mono)
    assert len(connection.calls) == 2 and point["stage"] == "pre_export"


def test_host_wall_clock_step_is_not_mistaken_for_transport_delay(no_retake_pause):
    connection = SimulatedConnection()
    execute = connection.execute

    def stepping(script):
        result = execute(script)
        if script == protocol.SAMPLE_SCRIPT:
            connection.host_step += 1
        return result

    with pytest.raises(ValueError, match="host_time_discontinuity"):
        protocol.clock_action(
            stepping,
            policy="host_sync_then_service_stopped",
            wall_clock=connection.wall,
            monotonic_clock=connection.mono,
        )


def test_delayed_ansible_debug_does_not_change_measured_offset_or_drift():
    pipeline = load("pipeline")
    instance, output = clock_run(
        pipeline,
        "host_sync_then_service_stopped",
        receipt=clock_receipt(),
        checkpoints=[
            ("manipulation_start", 61, 60.5),
            ("manipulation_end", 301, 300),
            ("pre_export", 901.5, 900.5),
        ],
    )
    instance.marker_receipt_times = [
        (marker, "2030-01-01T00:00:00+00:00")
        for marker, _ in instance.marker_receipt_times
    ]
    block = instance.capture_clock_receipt(output)
    assert block["policy_met"] is True
    assert block["offset_seconds_after"] == 1
    assert block["offset_drift_seconds"] == pytest.approx(0.520002)


def test_unknown_or_inconsistent_measurement_is_rejected():
    connection = SimulatedConnection(offset=0)
    _, original = protocol.exchange(
        connection.execute, wall_clock=connection.wall, monotonic_clock=connection.mono
    )
    for mutate in [
        lambda m: m.pop("monotonic_elapsed_seconds"),
        lambda m: m.update(monotonic_elapsed_seconds=float("nan")),
        lambda m: m.update(guest_utc="2026-01-01T00:00:00"),
    ]:
        value = deepcopy(original)
        mutate(value)
        with pytest.raises(ValueError):
            protocol.validate_measurement(value)


def test_checkpoint_checks_stopped_service_without_changing_clock():
    connection = SimulatedConnection(offset=0)
    with pytest.raises(ValueError, match="service_not_stopped"):
        connection.apply(stage="pre_export")
    assert not any("Set-Date" in s for s in connection.calls)


def test_remote_failure_has_no_success_receipt():
    with pytest.raises(ValueError, match="service_stop_failed"):
        protocol.clock_action(
            lambda script: {"rc": 1, "stdout": ""},
            policy="host_sync_then_service_stopped",
        )


def test_frozen_bootstrap_only_corrects_forward_and_verifies_native_bias():
    connection = SimulatedConnection(offset=-25)
    receipt = connection.apply(expected_bias=480)
    assert connection.offset == pytest.approx(0)
    assert receipt["boot_clock"] == {"expected_rtc_bias_minutes": 480,
        "observed_rtc_bias_minutes": 480, "clock_adjustment_ticks": 250_000_000, "forward_only": True}
    ahead = SimulatedConnection(offset=25)
    with pytest.raises(ValueError, match="backward_or_unproven"):
        ahead.apply(expected_bias=480)
    assert not any("Set-Date" in call for call in ahead.calls)
    wrong = SimulatedConnection(offset=-25)
    wrong.rtc_bias = 60
    with pytest.raises(ValueError, match="bias_mismatch"):
        wrong.apply(expected_bias=480)
    assert not any("Set-Date" in call for call in wrong.calls)


def test_an_own_boot_clock_bias_keeps_the_pacific_guest_and_corrects_forward_only():
    connection = SimulatedConnection(offset=-120)
    receipt = connection.apply(expected_bias=422)
    assert connection.offset == pytest.approx(0)
    assert receipt["boot_clock"] == {"expected_rtc_bias_minutes": 422,
        "observed_rtc_bias_minutes": 480, "clock_adjustment_ticks": 1_200_000_000, "forward_only": True}
    ahead = SimulatedConnection(offset=3480)
    with pytest.raises(ValueError, match="backward_or_unproven"):
        ahead.apply(expected_bias=422)
    assert not any("Set-Date" in call for call in ahead.calls)


def test_already_accurate_clock_is_not_stepped_backwards():
    connection = SimulatedConnection(offset=.5)
    receipt = connection.apply(expected_bias=480)
    assert receipt["boot_clock"]["clock_adjustment_ticks"] == 0
    assert connection.offset == .5
    assert not any("Set-Date" in call for call in connection.calls)


def test_time_service_correction_precedes_calibration_and_cannot_apply_twice():
    connection = SimulatedConnection(offset=36000)
    original = connection.execute
    def execute(script):
        if script == protocol.STOP_SERVICE_SCRIPT:
            connection.offset = 0
        return original(script)
    protocol.clock_action(execute, policy="host_sync_then_service_stopped",
                          wall_clock=connection.wall, monotonic_clock=connection.mono)
    assert connection.offset == 0
    assert connection.calls[0] == protocol.STOP_SERVICE_SCRIPT


def test_pipeline_rechecks_forward_only_bootstrap_receipt_and_adjustment():
    pipeline = load("pipeline")
    for ticks in (250_000_000, -1, 0):
        connection = SimulatedConnection(offset=-25)
        receipt = connection.apply(expected_bias=480)
        receipt["boot_clock"]["clock_adjustment_ticks"] = ticks
        instance, output = clock_run(pipeline, "host_sync_then_service_stopped", receipt=receipt,
            checkpoints=[("manipulation_start", 61, 61), ("manipulation_end", 301, 301), ("pre_export", 901, 901)])
        instance.recipe_bundle["recipe"]["config"]["vmware_boot_clock_bias_minutes"] = 480
        if ticks == 250_000_000:
            assert instance.capture_clock_receipt(output)["policy_met"] is True
        else:
            with pytest.raises(ValueError, match="forward-only"):
                instance.capture_clock_receipt(output)


def test_pipeline_accepts_an_own_boot_clock_bias_only_on_the_pacific_guest():
    pipeline = load("pipeline")
    for observed in (480, 422):
        connection = SimulatedConnection(offset=-120)
        receipt = connection.apply(expected_bias=422)
        receipt["boot_clock"]["observed_rtc_bias_minutes"] = observed
        instance, output = clock_run(pipeline, "host_sync_then_service_stopped", receipt=receipt,
            checkpoints=[("manipulation_start", 61, 61), ("manipulation_end", 301, 301), ("pre_export", 901, 901)])
        instance.recipe_bundle["recipe"]["config"]["vmware_boot_clock_bias_minutes"] = 422
        if observed == 480:
            assert instance.capture_clock_receipt(output)["policy_met"] is True
        else:
            with pytest.raises(ValueError, match="forward-only"):
                instance.capture_clock_receipt(output)
