from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

PROBE = r'''import importlib.util
import json
import sys
from contextlib import nullcontext
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import ansible
from ansible.errors import AnsibleConnectionFailure
from ansible.parsing.dataloader import DataLoader
from ansible.plugins.action import ActionBase

source = sys.argv[1]
spec = importlib.util.spec_from_file_location("clock_action_plugin", source)
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)
original_spec = importlib.util.spec_from_file_location
rows = []
for name, scalar, valid in [
    ("tagged_480", "480", True), ("zero", "0", True),
    ("lower_boundary", "-840", True), ("upper_boundary", "840", True),
    ("bool_true", "true", False), ("bool_false", "false", False),
    ("quoted_integer", '"480"', False), ("float_integer", "480.0", False),
    ("float_fraction", "480.5", False), ("below_range", "-841", False),
    ("above_range", "841", False), ("omitted", None, True),
]:
    yaml = "policy: host_sync_then_service_stopped\n"
    if scalar is not None:
        yaml += "expected_rtc_bias_minutes: " + scalar + "\n"
    args = DataLoader().load(yaml)
    loaded = args.get("expected_rtc_bias_minutes")
    calls, forwarded, lifecycle = [], [], []

    def execute(script):
        calls.append(script)
        if "StandardBias" in script:
            stdout = str(int(loaded))
        else:
            stdout = json.dumps({"guest_utc": "2026-09-12T12:00:00+00:00",
                                 "w32time_status": "Stopped"})
        return {"rc": 0, "stdout": stdout, "stderr": ""}

    class Transport:
        def __init__(self, connection):
            assert connection.transport == "winrm"
            self.timings = []
        def measure(self, phase):
            return nullcontext()
        def __enter__(self):
            lifecycle.append("entered")
            return execute
        def __exit__(self, *_):
            lifecycle.append("closed")

    class Loader:
        def __init__(self, original, name):
            self.original, self.name = original, name
        def create_module(self, spec):
            return self.original.create_module(spec)
        def exec_module(self, module):
            self.original.exec_module(module)
            if self.name == "fmb_generation_clock_transport":
                module.ClockTransport = Transport
            if self.name == "fmb_generation_clock_protocol":
                actual = module.clock_action
                def clock_action(execute, **kwargs):
                    value = kwargs["expected_rtc_bias_minutes"]
                    forwarded.append({"type": type(value).__name__, "value": value})
                    return actual(execute, **kwargs,
                        wall_clock=lambda: datetime(2026, 9, 12, 12, tzinfo=timezone.utc),
                        monotonic_clock=lambda: 0.0)
                module.clock_action = clock_action

    def spec_for(name, path):
        result = original_spec(name, path)
        result.loader = Loader(result.loader, name)
        return result

    action = object.__new__(plugin.ActionModule)
    action._task = SimpleNamespace(args=args)
    action._connection = SimpleNamespace(transport="winrm")
    action._low_level_execute_command = lambda command: {"rc": 0}
    logs = []
    def display(message):
        assert lifecycle == ["entered", "closed"]
        logs.append(message)
    action._display = SimpleNamespace(display=display)
    with patch.object(ActionBase, "run", return_value={}), \
         patch.object(plugin.importlib.util, "spec_from_file_location", side_effect=spec_for):
        result = action.run(task_vars={})
    rows.append({"name": name, "expected_valid": valid,
                 "loaded_type": type(loaded).__name__,
                 "loaded_is_int": isinstance(loaded, int),
                 "loaded_exact_int": type(loaded) is int,
                 "forwarded": forwarded, "result": result,
                 "protocol_execute_count": len(calls), "lifecycle": lifecycle, "logs": logs})
failure_rows = []
for failure in ("startup", "caller", "cleanup_only", "preparation", "preparation_unreachable", "logging", "remote_stop", "remote_stop_timing"):
    class FailedConnection:
        transport = "winrm"
        shell_id = "existing-authenticated-shell"
        def __init__(self):
            self.protocol = self
            self.cleaned = []
            self.chunks = [b"FMB_CLOCK_READY_V1\n"]
        def _winrm_send_input(self, protocol, shell, command, message):
            import base64
            request = json.loads(message)
            script = base64.b64decode(request["script"]).decode()
            reply = {"id": request["id"], "rc": 0, "stdout": "480", "stderr": ""}
            if "StandardBias" not in script:
                reply.update(rc=1, stdout="", stderr="Cannot disable Windows Time service: controlled remote failure")
            self.chunks.append(json.dumps(reply).encode() + b"\n")
        def _winrm_run_command(self, *args, **kwargs):
            return "owned-clock-process"
        def _winrm_get_raw_command_output(self, *args):
            if failure.startswith("remote_stop"):
                return self.chunks.pop(0), b"", -1, False
            ready = b"WRONG_READY\n" if failure == "startup" else b"FMB_CLOCK_READY_V1\n"
            return ready, b"", -1, False
        def cleanup_command(self, shell, command):
            self.cleaned.append((shell, command))
            raise OSError("cleanup transport read timed out")

    class FailureLoader:
        def __init__(self, original, name):
            self.original, self.name = original, name
        def create_module(self, spec):
            return self.original.create_module(spec)
        def exec_module(self, module):
            self.original.exec_module(module)
            if self.name == "fmb_generation_clock_protocol":
                if failure.startswith("remote_stop"):
                    return
                def clock_action(execute, **kwargs):
                    if failure == "caller":
                        raise ValueError("clock_bootstrap_bias_mismatch")
                    return {"applied": True}
                module.clock_action = clock_action

    def failure_spec(name, path):
        result = original_spec(name, path)
        result.loader = FailureLoader(result.loader, name)
        return result

    connection = FailedConnection()
    action = object.__new__(plugin.ActionModule)
    action._task = SimpleNamespace(args={"policy": "host_sync_then_service_stopped"})
    if failure.startswith("remote_stop"):
        action._task.args["expected_rtc_bias_minutes"] = 480
    action._connection = connection
    preparation_error = (AnsibleConnectionFailure("preparation connection lost")
                         if failure == "preparation_unreachable" else OSError("preparation request failed"))
    def prepare(command):
        if failure in {"preparation", "preparation_unreachable"}:
            raise preparation_error
        return {"rc": 0}
    action._low_level_execute_command = prepare
    logs = []
    def display(message):
        if failure not in {"preparation", "preparation_unreachable"}:
            assert connection.cleaned == [("existing-authenticated-shell", "owned-clock-process")]
        logs.append(message)
        if failure == "logging" or (failure == "remote_stop_timing" and message.startswith("FMB_CLOCK_TIMING ")):
            raise OSError("log sink unavailable")
    action._display = SimpleNamespace(display=display)
    with patch.object(ActionBase, "run", return_value={}), \
         patch.object(plugin.importlib.util, "spec_from_file_location", side_effect=failure_spec):
        try:
            result = action.run(task_vars={})
        except AnsibleConnectionFailure as error:
            result = {"raised_type": type(error).__name__, "same_exception": error is preparation_error,
                      "msg": str(error), "notes": error.__notes__}
    failure_rows.append({"failure": failure, "result": result, "cleaned": connection.cleaned,
                         "logs": logs})
print(json.dumps({"ansible_version": ansible.__version__, "rows": rows,
                  "failure_rows": failure_rows}))
'''


@pytest.fixture(scope="module")
def native_ansible_scalar_rows(tmp_path_factory):
    executable = shutil.which("ansible-playbook")
    if executable:
        shebang = Path(executable).resolve().read_text().splitlines()[0]
        python = shebang.removeprefix("#!").strip()
    else:
        python = sys.executable
    if not Path(python).is_file():
        pytest.skip("installed Ansible Python interpreter is unavailable")
    directory = tmp_path_factory.mktemp("ansible-clock-scalars")
    env = {**os.environ, "ANSIBLE_LOCAL_TEMP": str(directory / "ansible-local")}
    available = subprocess.run([python, "-c", "import ansible"], env=env,
                               capture_output=True, text=True, timeout=10, check=False)
    if available.returncode:
        pytest.skip("Ansible is not installed in the discovered interpreter")
    result = subprocess.run([python, "-c", PROBE,
                             str(ROOT / "src/fmb/generation/ansible/action_plugins/fmb_clock.py")],
                            env=env, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_actual_loader_int_subclass_reaches_protocol_as_exact_int(native_ansible_scalar_rows):
    row = next(row for row in native_ansible_scalar_rows["rows"] if row["name"] == "tagged_480")
    assert row["loaded_is_int"] is True and row["loaded_exact_int"] is False
    assert row["loaded_type"] == "_AnsibleTaggedInt"
    assert row["forwarded"] == [{"type": "int", "value": 480}]
    assert row["result"]["clock_receipt"]["boot_clock"]["expected_rtc_bias_minutes"] == 480


@pytest.mark.parametrize("name", ["tagged_480", "zero", "lower_boundary", "upper_boundary",
                                  "bool_true", "bool_false", "quoted_integer", "float_integer",
                                  "float_fraction", "below_range", "above_range", "omitted"])
def test_action_preserves_strict_protocol_policy(native_ansible_scalar_rows, name):
    row = next(row for row in native_ansible_scalar_rows["rows"] if row["name"] == name)
    assert row["lifecycle"] == ["entered", "closed"]
    if row["expected_valid"]:
        assert not row["result"].get("failed")
        receipt = row["result"]["clock_receipt"]
        assert receipt["schema_version"] == "generation_clock_receipt.v2"
        assert receipt["applied"] is True and row["protocol_execute_count"] > 0
        if name == "omitted":
            assert row["forwarded"] == [{"type": "NoneType", "value": None}]
            assert "boot_clock" not in receipt
    else:
        assert row["result"] == {"failed": True, "msg": "clock_bootstrap_bias_invalid"}
        assert row["protocol_execute_count"] == 0


@pytest.mark.parametrize("failure,primary", [
    ("startup", "clock_transport_ready_invalid"),
    ("caller", "clock_bootstrap_bias_mismatch"),
])
def test_action_reports_primary_failure_and_cleanup_note(native_ansible_scalar_rows, failure, primary):
    row = next(row for row in native_ansible_scalar_rows["failure_rows"] if row["failure"] == failure)
    assert row["result"] == {
        "failed": True,
        "msg": primary + ("\nclock transport phase: READY receive" if failure == "startup" else "")
               + "\nclock transport cleanup also failed: cleanup transport read timed out",
    }
    assert row["cleaned"] == [["existing-authenticated-shell", "owned-clock-process"]]


def test_action_reports_cleanup_only_failure(native_ansible_scalar_rows):
    row = next(row for row in native_ansible_scalar_rows["failure_rows"] if row["failure"] == "cleanup_only")
    assert row["result"] == {
        "failed": True, "msg": "cleanup transport read timed out\nclock transport phase: cleanup"
    }
    assert row["cleaned"] == [["existing-authenticated-shell", "owned-clock-process"]]


def test_preparation_failure_includes_phase(native_ansible_scalar_rows):
    row = next(row for row in native_ansible_scalar_rows["failure_rows"] if row["failure"] == "preparation")
    assert row["result"] == {
        "failed": True, "msg": "preparation request failed\nclock action phase: connection preparation"
    }
    assert row["cleaned"] == []


def test_preparation_connection_failure_preserves_unreachable_exception(native_ansible_scalar_rows):
    row = next(row for row in native_ansible_scalar_rows["failure_rows"]
               if row["failure"] == "preparation_unreachable")
    assert row["result"] == {
        "raised_type": "AnsibleConnectionFailure", "same_exception": True,
        "msg": "preparation connection lost", "notes": ["clock action phase: connection preparation"],
    }
    assert row["cleaned"] == []


def test_clock_timings_reach_host_display_after_cleanup_even_on_unreachable(native_ansible_scalar_rows):
    for row in native_ansible_scalar_rows["rows"] + native_ansible_scalar_rows["failure_rows"]:
        timing_logs = [log for log in row["logs"] if log.startswith("FMB_CLOCK_TIMING ")]
        assert len(timing_logs) == 1
        prefix, payload = timing_logs[0].split(" ", 1)
        assert prefix == "FMB_CLOCK_TIMING"
        diagnostic = json.loads(payload)
        assert set(diagnostic) == {"utc", "phases"}
        assert diagnostic["utc"].endswith("+00:00")
        for phase in diagnostic["phases"]:
            assert set(phase) <= {"phase", "outcome", "elapsed_seconds", "error_type"}
            assert phase["elapsed_seconds"] >= 0
        if row.get("failure") == "preparation_unreachable":
            assert len(diagnostic["phases"]) == 1
            assert diagnostic["phases"][0]["phase"] == "connection preparation"
            assert diagnostic["phases"][0]["error_type"] == "AnsibleConnectionFailure"
        if row.get("failure") == "caller":
            failed = [phase for phase in diagnostic["phases"] if phase["outcome"] == "error"]
            assert [(phase["phase"], phase["error_type"]) for phase in failed] == [
                ("protocol execution", "ValueError"), ("cleanup", "OSError"),
            ]
        assert "clock_receipt" not in diagnostic
        assert "existing-authenticated-shell" not in payload
        assert "owned-clock-process" not in payload
        assert "cleanup transport read timed out" not in payload


def test_logging_failure_cannot_replace_primary_error(native_ansible_scalar_rows):
    row = next(row for row in native_ansible_scalar_rows["failure_rows"] if row["failure"] == "logging")
    assert row["result"] == {
        "failed": True, "msg": "cleanup transport read timed out\nclock transport phase: cleanup",
    }


@pytest.mark.parametrize("failure", ["remote_stop", "remote_stop_timing"])
def test_failed_remote_service_reply_survives_cleanup_and_timing_delivery_failure(native_ansible_scalar_rows, failure):
    row = next(row for row in native_ansible_scalar_rows["failure_rows"] if row["failure"] == failure)
    assert row["result"] == {"failed": True, "msg": "clock_service_stop_failed\nclock transport cleanup also failed: cleanup transport read timed out"}
    assert row["cleaned"] == [["existing-authenticated-shell", "owned-clock-process"]]
    records = [json.loads(log.removeprefix("FMB_CLOCK_REMOTE_FAILURE "))
               for log in row["logs"] if log.startswith("FMB_CLOCK_REMOTE_FAILURE ")]
    assert len(records) == 1
    assert records[0]["command_ordinal"] == 2 and records[0]["rc"] == 1
    assert records[0]["stderr"] == "Cannot disable Windows Time service: controlled remote failure"
    assert records[0]["stderr_truncated"] is False
    assert set(records[0]) == {"utc", "command_ordinal", "rc", "stderr", "stderr_truncated"}
