from __future__ import annotations

import base64
import json
import time
from contextlib import contextmanager

SERVER = r'''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Get-Service -Name w32time -ErrorAction SilentlyContinue | Out-Null
[Console]::Out.WriteLine('FMB_CLOCK_READY_V1')
[Console]::Out.Flush()
while ($null -ne ($line = [Console]::In.ReadLine())) {
  $request = $line | ConvertFrom-Json
  try {
    $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($request.script))
    $output = (& ([ScriptBlock]::Create($text)) | Out-String).Trim()
    $response = @{id=$request.id;rc=0;stdout=$output;stderr=''} | ConvertTo-Json -Compress
  } catch {
    $response = @{id=$request.id;rc=1;stdout='';stderr=[string]$_} | ConvertTo-Json -Compress
  }
  [Console]::Out.WriteLine($response)
  [Console]::Out.Flush()
}
'''


class ClockTransport:

    def __init__(self, connection, *, monotonic=time.monotonic):
        self.connection = connection
        self.monotonic = monotonic
        self.command = None
        self.pending = b""
        self.sequence = 0
        self.timings = []
        self.remote_failures = []

    @contextmanager
    def measure(self, phase):
        started = time.perf_counter()
        row = {"phase": phase, "outcome": "ok"}
        try:
            yield
        except BaseException as error:
            row.update(outcome="error", error_type=type(error).__name__)
            raise
        finally:
            row["elapsed_seconds"] = round(time.perf_counter() - started, 6)
            self.timings.append(row)

    def __enter__(self):
        phase = "remote startup"
        try:
            with self.measure(phase):
                self.command = self.connection._winrm_run_command(
                    b"powershell.exe",
                    (b"-NoLogo", b"-NoProfile", b"-NonInteractive", b"-EncodedCommand",
                     base64.b64encode(SERVER.encode("utf-16-le"))), console_mode_stdin=False)
            phase = "READY receive"
            with self.measure(phase):
                if self._line() != "FMB_CLOCK_READY_V1":
                    raise ValueError("clock_transport_ready_invalid")
            return self.execute
        except BaseException as error:
            error.add_note(f"clock transport phase: {phase}")
            self._close(error)
            raise

    def __exit__(self, _type, error, _traceback):
        self._close(error)

    def _close(self, primary_error=None):
        if self.command is not None:
            command, self.command = self.command, None
            try:
                with self.measure("cleanup"):
                    self.connection.protocol.cleanup_command(self.connection.shell_id, command)
            except Exception as cleanup_error:
                if primary_error is None:
                    cleanup_error.add_note("clock transport phase: cleanup")
                    raise
                primary_error.add_note(f"clock transport cleanup also failed: {cleanup_error}")

    def _line(self):
        deadline = self.monotonic() + 60
        while b"\n" not in self.pending:
            if self.monotonic() > deadline:
                raise ValueError("clock_transport_receive_timeout")
            out, err, _rc, done = self.connection._winrm_get_raw_command_output(
                self.connection.protocol, self.connection.shell_id, self.command)
            self.pending += out
            if err.strip() not in (b"", b"#< CLIXML") or done:
                raise ValueError("clock_transport_process_failed")
            if len(self.pending) > 65536:
                raise ValueError("clock_transport_response_too_large")
        row, self.pending = self.pending.split(b"\n", 1)
        return row.decode("utf-8").strip()

    def execute(self, script):
        phase = f"command {self.sequence + 1} send"
        try:
            with self.measure(phase):
                if self.command is None:
                    raise ValueError("clock_transport_not_open")
                self.sequence += 1
                message = json.dumps({"id": self.sequence, "script": base64.b64encode(script.encode()).decode()})
                self.connection._winrm_send_input(self.connection.protocol, self.connection.shell_id,
                                                  self.command, message.encode() + b"\n")
            phase = f"command {self.sequence} receive"
            with self.measure(phase):
                result = json.loads(self._line())
                if (not isinstance(result, dict) or set(result) != {"id", "rc", "stdout", "stderr"}
                        or type(result["id"]) is not int or result["id"] != self.sequence
                        or type(result["rc"]) is not int
                        or not isinstance(result["stdout"], str) or not isinstance(result["stderr"], str)):
                    raise ValueError("clock_transport_response_invalid")
            if result["rc"] != 0:
                try:
                    self.remote_failures.append({
                        "command_ordinal": self.sequence, "rc": result["rc"],
                        "stderr": result["stderr"][:2048],
                        "stderr_truncated": len(result["stderr"]) > 2048,
                    })
                except Exception:
                    pass
            return {key: result[key] for key in ("rc", "stdout", "stderr")}
        except Exception as error:
            error.add_note(f"clock transport phase: {phase}")
            raise
