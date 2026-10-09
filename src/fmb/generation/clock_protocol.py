from __future__ import annotations

import json
import math
import time
from datetime import datetime, timezone

PROTOCOL = "winrm_bracketed_relative.v1"
TOLERANCE_SECONDS = 2.0
HOST_WALL_TOLERANCE_SECONDS = 0.05
QUANTIZATION_SECONDS = 0.000001
GUEST_STANDARD_BIAS_MINUTES = 480

SAMPLE_SCRIPT = """$ErrorActionPreference = 'Stop'
$s = Get-Service -Name w32time -ErrorAction SilentlyContinue
[ordered]@{guest_utc=[DateTime]::UtcNow.ToString('o');w32time_status=$(if($s){[string]$s.Status}else{'absent'})} | ConvertTo-Json -Compress
"""
STOP_SERVICE_SCRIPT = """$ErrorActionPreference = 'Stop'
$s = Get-Service -Name w32time -ErrorAction SilentlyContinue
if ($s) { Set-Service -Name w32time -StartupType Disabled -ErrorAction Stop }
if ($s -and $s.Status -ne 'Stopped') { Stop-Service -Name w32time -Force -ErrorAction Stop }
if ($s) {
  $deadline = [DateTime]::UtcNow.AddSeconds(20)
  while ((Get-Service -Name w32time).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline) {
    Start-Sleep -Milliseconds 500
    if ((Get-Service -Name w32time).Status -eq 'Running') { Stop-Service -Name w32time -Force -ErrorAction Stop }
  }
  if ((Get-Service -Name w32time).Status -ne 'Stopped') { throw 'Windows Time service did not stop' }
}
"""
RTC_BIAS_SCRIPT = """$ErrorActionPreference = 'Stop'
$r = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation'
if ($r.RealTimeIsUniversal -eq 1) { 0 }
elseif ($null -ne $r.Bias -and $null -ne $r.StandardBias) {
  $bias = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$r.Bias),0)
  $standard = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$r.StandardBias),0)
  $bias + $standard
} else { throw 'Native RTC timezone bias is unavailable' }
"""


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("clock_instant_invalid")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("clock_instant_offset_missing")
    return stamp


def validate_measurement(measurement):
    fields = {"protocol", "host_send_utc", "host_receive_utc", "guest_utc", "monotonic_elapsed_seconds"}
    if not isinstance(measurement, dict) or set(measurement) != fields or measurement["protocol"] != PROTOCOL:
        raise ValueError("clock_measurement_contract_invalid")
    sent, received, guest = (_instant(measurement[k]) for k in ("host_send_utc", "host_receive_utc", "guest_utc"))
    elapsed = measurement["monotonic_elapsed_seconds"]
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
        raise ValueError("clock_monotonic_duration_invalid")
    wall_elapsed = (received - sent).total_seconds()
    if wall_elapsed < 0 or abs(wall_elapsed - elapsed) > HOST_WALL_TOLERANCE_SECONDS:
        raise ValueError("clock_host_time_discontinuity")
    lower = (guest - received).total_seconds() - QUANTIZATION_SECONDS
    upper = (guest - sent).total_seconds() + QUANTIZATION_SECONDS
    return {"offset_lower_seconds": lower, "offset_upper_seconds": upper,
            "offset_seconds": (lower + upper) / 2, "roundtrip_seconds": elapsed}


def require_certain_offset(measurement):
    bound = validate_measurement(measurement)
    if not (-TOLERANCE_SECONDS <= bound["offset_lower_seconds"] <= bound["offset_upper_seconds"] <= TOLERANCE_SECONDS):
        raise ValueError("clock_offset_not_proven_within_tolerance")
    return bound


def _payload(result):
    if not isinstance(result, dict) or result.get("rc") != 0:
        raise ValueError("clock_remote_command_failed")
    try:
        data = json.loads(result.get("stdout", ""))
    except (ValueError, TypeError) as error:
        raise ValueError("clock_remote_payload_invalid") from error
    if not isinstance(data, dict) or set(data) != {"guest_utc", "w32time_status"}:
        raise ValueError("clock_remote_payload_invalid")
    _instant(data["guest_utc"])
    if data["w32time_status"] not in {"Stopped", "Running", "StartPending", "StopPending", "ContinuePending", "PausePending", "Paused", "absent"}:
        raise ValueError("clock_service_status_invalid")
    return data


def exchange(execute, *, wall_clock=None, monotonic_clock=None):
    wall_clock = wall_clock or (lambda: datetime.now(timezone.utc))
    monotonic_clock = monotonic_clock or time.monotonic
    sent = wall_clock()
    started = monotonic_clock()
    payload = _payload(execute(SAMPLE_SCRIPT))
    finished = monotonic_clock()
    received = wall_clock()
    measurement = {"protocol": PROTOCOL, "host_send_utc": sent.isoformat(),
                   "host_receive_utc": received.isoformat(), "guest_utc": payload["guest_utc"],
                   "monotonic_elapsed_seconds": finished - started}
    validate_measurement(measurement)
    return payload, measurement


def clock_action(execute, *, policy, stage=None, wall_clock=None, monotonic_clock=None,
                 expected_rtc_bias_minutes=None):
    if policy not in {"host_sync_then_service_stopped", "unmanaged"}:
        raise ValueError("clock_policy_invalid")
    if stage is not None and (not isinstance(stage, str) or not stage or len(stage) > 80):
        raise ValueError("clock_stage_invalid")
    boot_clock = None
    if expected_rtc_bias_minutes is not None:
        if (type(expected_rtc_bias_minutes) is not int or not -840 <= expected_rtc_bias_minutes <= 840
                or policy != "host_sync_then_service_stopped"):
            raise ValueError("clock_bootstrap_bias_invalid")
        result = execute(RTC_BIAS_SCRIPT)
        try:
            observed_bias = int(result["stdout"].strip())
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise ValueError("clock_bootstrap_bias_unavailable") from error
        if result.get("rc") != 0 or observed_bias != GUEST_STANDARD_BIAS_MINUTES:
            raise ValueError("clock_bootstrap_bias_mismatch")
        boot_clock = {"expected_rtc_bias_minutes": expected_rtc_bias_minutes,
                      "observed_rtc_bias_minutes": observed_bias,
                      "clock_adjustment_ticks": 0, "forward_only": True}
    if policy != "unmanaged" and stage is None:
        result = execute(STOP_SERVICE_SCRIPT)
        if not isinstance(result, dict) or result.get("rc") != 0:
            raise ValueError("clock_service_stop_failed")
    options = {"wall_clock": wall_clock, "monotonic_clock": monotonic_clock}
    before, calibration = exchange(execute, **options)
    if stage is not None:
        if policy != "unmanaged":
            require_certain_offset(calibration)
            if before["w32time_status"] not in {"Stopped", "absent"}:
                raise ValueError("clock_service_not_stopped")
        return {"stage": stage, "guest_utc": before["guest_utc"], "measurement": calibration}
    applied = policy != "unmanaged"
    measurement = calibration
    after = before
    if applied:
        bounds = validate_measurement(calibration)
        if bounds["offset_upper_seconds"] - bounds["offset_lower_seconds"] > TOLERANCE_SECONDS:
            raise ValueError("clock_calibration_timing_uncertain")
        delta_ticks = round(-bounds["offset_seconds"] * 10_000_000)
        if before["w32time_status"] not in {"Stopped", "absent"}:
            raise ValueError("clock_service_not_stopped")
        if boot_clock is not None:
            if (-TOLERANCE_SECONDS <= bounds["offset_lower_seconds"]
                    <= bounds["offset_upper_seconds"] <= TOLERANCE_SECONDS):
                delta_ticks = 0
            elif bounds["offset_upper_seconds"] >= 0:
                raise ValueError("clock_bootstrap_requires_backward_or_unproven_correction")
            boot_clock["clock_adjustment_ticks"] = delta_ticks
        script = """$ErrorActionPreference = 'Stop'
Set-Date -Date ([DateTime]::UtcNow.AddTicks(%d).ToLocalTime()) | Out-Null
""" % delta_ticks
        if delta_ticks:
            result = execute(script)
            if not isinstance(result, dict) or result.get("rc") != 0:
                raise ValueError("clock_relative_correction_failed")
        after, measurement = exchange(execute, **options)
        require_certain_offset(measurement)
        if after["w32time_status"] not in {"Stopped", "absent"}:
            raise ValueError("clock_service_not_stopped")
    receipt = {"schema_version": "generation_clock_receipt.v2", "policy": policy, "applied": applied,
            "host_utc_iso": calibration["host_send_utc"], "guest_utc_before": before["guest_utc"],
            "guest_utc_after": after["guest_utc"], "w32time_status": after["w32time_status"],
            "calibration_measurement": calibration, "measurement": measurement}
    if boot_clock is not None:
        receipt["boot_clock"] = boot_clock
    return receipt
