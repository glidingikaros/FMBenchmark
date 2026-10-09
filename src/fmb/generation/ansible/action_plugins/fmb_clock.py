from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    TRANSFERS_FILES = False
    _supports_check_mode = False

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        args = self._task.args
        if set(args) - {"policy", "stage", "expected_rtc_bias_minutes"} or self._connection.transport != "winrm":
            return {**result, "failed": True, "msg": "clock_action_contract_invalid"}
        bias = args.get("expected_rtc_bias_minutes")
        if isinstance(bias, int) and not isinstance(bias, bool):
            bias = int(bias)
        source = Path(__file__).resolve().parents[2] / "clock_protocol.py"
        spec = importlib.util.spec_from_file_location("fmb_generation_clock_protocol", source)
        protocol = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(protocol)
        transport_spec = importlib.util.spec_from_file_location(
            "fmb_generation_clock_transport", source.with_name("clock_transport.py"))
        transport = importlib.util.module_from_spec(transport_spec)
        transport_spec.loader.exec_module(transport)
        session = transport.ClockTransport(self._connection)
        try:
            try:
                with session.measure("connection preparation"):
                    self._low_level_execute_command("Write-Output 'prepare_clock_transport'")
            except Exception as error:
                error.add_note("clock action phase: connection preparation")
                raise
            with session as execute:
                with session.measure("protocol execution"):
                    receipt = protocol.clock_action(
                        execute, policy=args.get("policy"), stage=args.get("stage"),
                        expected_rtc_bias_minutes=bias)
        except (ValueError, OSError) as error:
            message = "\n".join((str(error), *getattr(error, "__notes__", ())))
            return {**result, "failed": True, "msg": message}
        finally:
            try:
                self._display.display("FMB_CLOCK_TIMING " + json.dumps({
                    "utc": datetime.now(timezone.utc).isoformat(), "phases": session.timings,
                }, separators=(",", ":")))
            except Exception:
                pass
            for failure in getattr(session, "remote_failures", ()):
                try:
                    self._display.display("FMB_CLOCK_REMOTE_FAILURE " + json.dumps({
                        "utc": datetime.now(timezone.utc).isoformat(), **failure,
                    }, separators=(",", ":")))
                except Exception:
                    pass
        return {**result, "changed": bool(receipt.get("applied")),
                "stdout": json.dumps(receipt, separators=(",", ":")), "clock_receipt": receipt}
