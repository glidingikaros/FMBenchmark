from __future__ import annotations

import base64
import json
from test_generation_clock_exchange import SimulatedConnection, protocol
from test_iteration2_generation import load

import pytest

transport = load("clock_transport")


class WinrmConnection:
    shell_id = "existing-authenticated-shell"

    def __init__(self, *, ready=b"FMB_CLOCK_READY_V1\r\n"):
        self.protocol = self
        self.clock = SimulatedConnection(offset=-25)
        self.chunks = [(ready[:7], b"", -1, False), (ready[7:], b"", -1, False)]
        self.cleaned = []
        self.command_active = False
        self.wrong_id = False

    def _winrm_run_command(self, command, args, *, console_mode_stdin):
        self.clock.now += 30
        self.command_active = True
        return "owned-clock-process"

    def _winrm_send_input(self, protocol_, shell, command, message):
        request = json.loads(message)
        result = self.clock.execute(base64.b64decode(request["script"]).decode())
        response = json.dumps({"id": request["id"] + int(self.wrong_id), **result}).encode() + b"\r\n"
        self.chunks += [(response[:11], b"#< CLIXML\r\n", -1, False),
                        (response[11:], b"", -1, False)]

    def _winrm_get_raw_command_output(self, *args):
        return self.chunks.pop(0)

    def cleanup_command(self, shell, command):
        self.cleaned.append((shell, command))
        self.command_active = False


def test_startup_precedes_bracket_but_actual_exchange_duration_is_retained(monkeypatch, capsys):
    connection = WinrmConnection()
    monkeypatch.setattr(transport.time, "perf_counter", connection.clock.mono)
    session = transport.ClockTransport(connection)
    with session as execute:
        receipt = protocol.clock_action(execute, policy="host_sync_then_service_stopped",
            expected_rtc_bias_minutes=480, wall_clock=connection.clock.wall,
            monotonic_clock=connection.clock.mono)
        assert receipt["measurement"]["monotonic_elapsed_seconds"] == pytest.approx(.4)
        assert receipt["calibration_measurement"]["host_send_utc"].endswith("30.800000+00:00")
        assert connection.clock.offset == pytest.approx(0)
    assert connection.cleaned == [(connection.shell_id, "owned-clock-process")]
    assert session.timings[0] == {
        "phase": "remote startup", "outcome": "ok", "elapsed_seconds": 30.0,
    }
    assert session.timings[1] == {
        "phase": "READY receive", "outcome": "ok", "elapsed_seconds": 0.0,
    }
    assert session.timings[-1]["phase"] == "cleanup"
    assert all(row["outcome"] == "ok" for row in session.timings)
    assert sum(row["elapsed_seconds"] for row in session.timings[2:]) == pytest.approx(2.0)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("failure", ["startup", "stale_response", "remote_error", "caller"])
def test_process_is_cleaned_on_each_failure_boundary(failure):
    connection = WinrmConnection(ready=b"WRONG_READY\n" if failure == "startup" else b"FMB_CLOCK_READY_V1\n")
    with pytest.raises(ValueError):
        with transport.ClockTransport(connection) as execute:
            if failure == "stale_response":
                connection.wrong_id = True
                execute(protocol.SAMPLE_SCRIPT)
            elif failure == "remote_error":
                connection.chunks.append((b"", b"actual PowerShell error", -1, False))
                execute(protocol.SAMPLE_SCRIPT)
            else:
                raise ValueError("caller failed")
    assert not connection.command_active
    assert connection.cleaned == [(connection.shell_id, "owned-clock-process")]


class FailingCleanupConnection(WinrmConnection):
    def cleanup_command(self, shell, command):
        self.cleaned.append((shell, command))
        raise OSError("cleanup transport read timed out")


def test_cleanup_failure_preserves_failed_ready():
    connection = FailingCleanupConnection(ready=b"WRONG_READY\n")
    session = transport.ClockTransport(connection)
    with pytest.raises(ValueError) as caught:
        with session:
            pytest.fail("invalid READY must not enter the action body")
    assert str(caught.value) == "clock_transport_ready_invalid"
    assert caught.value.__notes__ == [
        "clock transport phase: READY receive",
        "clock transport cleanup also failed: cleanup transport read timed out"
    ]
    assert connection.cleaned == [(connection.shell_id, "owned-clock-process")]
    assert session.command is None


@pytest.mark.parametrize("error_type", [ValueError, OSError])
def test_cleanup_failure_preserves_action_error(error_type):
    connection = FailingCleanupConnection()
    primary = error_type("clock_action_primary_failure")
    with pytest.raises(error_type) as caught:
        with transport.ClockTransport(connection):
            raise primary
    assert caught.value is primary
    assert str(caught.value) == "clock_action_primary_failure"
    assert caught.value.__notes__ == [
        "clock transport cleanup also failed: cleanup transport read timed out"
    ]
    assert connection.cleaned == [(connection.shell_id, "owned-clock-process")]


def test_cleanup_only_failure_still_fails_the_action():
    connection = FailingCleanupConnection()
    with pytest.raises(OSError) as caught:
        with transport.ClockTransport(connection):
            pass
    assert str(caught.value) == "cleanup transport read timed out"
    assert caught.value.__notes__ == ["clock transport phase: cleanup"]
    assert connection.cleaned == [(connection.shell_id, "owned-clock-process")]


@pytest.mark.parametrize("boundary,phase", [
    ("startup", "remote startup"), ("ready", "READY receive"),
])
def test_startup_failure_keeps_original_exception_and_phase(monkeypatch, boundary, phase):
    connection = WinrmConnection()
    primary = OSError("transport request failed")
    def fail(*args, **kwargs):
        raise primary
    method = "_winrm_run_command" if boundary == "startup" else "_winrm_get_raw_command_output"
    monkeypatch.setattr(connection, method, fail)
    with pytest.raises(OSError) as caught:
        with transport.ClockTransport(connection):
            pytest.fail("failed startup must not enter the body")
    assert caught.value is primary and str(caught.value) == "transport request failed"
    assert caught.value.__notes__ == [f"clock transport phase: {phase}"]
    assert len(connection.cleaned) == int(boundary == "ready")


@pytest.mark.parametrize("boundary", ["send", "receive"])
def test_command_failure_labels_number_without_script_or_payload(monkeypatch, boundary):
    connection = WinrmConnection()
    primary = OSError("transport request failed")
    def fail(*args, **kwargs):
        raise primary
    session = transport.ClockTransport(connection)
    with pytest.raises(OSError) as caught:
        with session as execute:
            execute(protocol.SAMPLE_SCRIPT)
            method = "_winrm_send_input" if boundary == "send" else "_winrm_get_raw_command_output"
            monkeypatch.setattr(connection, method, fail)
            execute("private script content must not enter the diagnostic note")
    assert caught.value is primary and str(caught.value) == "transport request failed"
    assert caught.value.__notes__ == [f"clock transport phase: command 2 {boundary}"]
    assert connection.cleaned == [(connection.shell_id, "owned-clock-process")]
    failure = session.timings[-2]
    assert failure["phase"] == f"command 2 {boundary}"
    assert failure["outcome"] == "error" and failure["error_type"] == "OSError"
    assert failure["elapsed_seconds"] >= 0
    assert session.timings[-1]["phase"] == "cleanup"
    serialized = json.dumps(session.timings)
    assert "private script" not in serialized and str(primary) not in serialized


def test_failed_ready_and_failed_cleanup_keep_separate_timings():
    session = transport.ClockTransport(FailingCleanupConnection(ready=b"WRONG_READY\n"))
    with pytest.raises(ValueError, match="clock_transport_ready_invalid"):
        with session:
            pytest.fail("READY failure must not enter the body")
    assert [(row["phase"], row["outcome"], row.get("error_type")) for row in session.timings] == [
        ("remote startup", "ok", None), ("READY receive", "error", "ValueError"),
        ("cleanup", "error", "OSError"),
    ]


@pytest.mark.parametrize("stderr", ["service operation failed", "x" * 3000])
def test_valid_failed_reply_keeps_bounded_diagnostic_without_changing_result(monkeypatch, stderr):
    connection = WinrmConnection()
    reply = {"rc": 1, "stdout": "private stdout", "stderr": stderr}
    connection.clock.execute = lambda _: reply
    session = transport.ClockTransport(connection)
    with session as execute:
        assert execute("private command script") == reply
        assert connection.cleaned == []
    assert session.remote_failures == [{"command_ordinal": 1, "rc": 1,
        "stderr": stderr[:2048], "stderr_truncated": len(stderr) > 2048}]
    assert connection.cleaned == [(connection.shell_id, "owned-clock-process")]
    assert "private" not in json.dumps(session.remote_failures)


def test_invalid_reply_does_not_enter_remote_diagnostics():
    connection = WinrmConnection()
    connection.clock.execute = lambda _: {"rc": 1, "stdout": "", "stderr": "untrusted stale response"}
    connection.wrong_id = True
    session = transport.ClockTransport(connection)
    with pytest.raises(ValueError, match="response_invalid"):
        with session as execute:
            execute("ignored")
    assert session.remote_failures == []


def test_diagnostic_buffer_failure_preserves_failed_reply():
    class FailedBuffer:
        def append(self, _):
            raise OSError("diagnostic buffer unavailable")
    connection = WinrmConnection()
    reply = {"rc": 1, "stdout": "", "stderr": "original service failure"}
    connection.clock.execute = lambda _: reply
    session = transport.ClockTransport(connection)
    session.remote_failures = FailedBuffer()
    with session as execute:
        assert execute("ignored") == reply
    assert not connection.command_active
