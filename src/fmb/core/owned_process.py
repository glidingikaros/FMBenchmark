from __future__ import annotations

import os
import queue
import signal
import subprocess
import threading
import time
import tempfile


def _stop_group(process):
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        process.kill()
    process.wait(timeout=15)


def run_owned(
    cmd,
    *,
    cwd=None,
    env=None,
    timeout=3600,
    capture_output=False,
    on_line=None,
    max_output_bytes=64 * 1024 * 1024,
):
    if timeout is None or timeout <= 0:
        raise ValueError("command timeout must be positive")
    options = (
        {"start_new_session": True}
        if os.name == "posix"
        else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    )
    capture = capture_output or on_line is not None
    error_file = (
        tempfile.TemporaryFile() if capture_output and on_line is None else None
    )
    try:
        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE if capture else None,
            stderr=error_file
            if error_file is not None
            else subprocess.STDOUT
            if capture
            else None,
            **options,
        )
    except BaseException:
        if error_file is not None:
            error_file.close()
        raise
    events = queue.Queue(maxsize=256)
    stop = threading.Event()
    reader = None
    output = bytearray()
    pending = ""
    primary_error = None

    def read_output():
        try:
            while not stop.is_set():
                chunk = os.read(process.stdout.fileno(), 8192)
                while not stop.is_set():
                    try:
                        events.put(chunk, timeout=0.05)
                        break
                    except queue.Full:
                        continue
                if not chunk:
                    break
        except (OSError, ValueError):
            pass

    try:
        if capture:
            reader = threading.Thread(target=read_output, name="fmb-command-output")
            reader.start()
        deadline = time.monotonic() + timeout
        done = not capture
        while process.poll() is None or not done:
            if (
                error_file is not None
                and os.fstat(error_file.fileno()).st_size > max_output_bytes
            ):
                raise RuntimeError("command exceeded retained stderr limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(
                    cmd, timeout, output=bytes(output).decode("utf-8", "replace")
                )
            if not capture:
                try:
                    process.wait(timeout=min(0.1, remaining))
                except subprocess.TimeoutExpired:
                    pass
                continue
            try:
                chunk = events.get(timeout=min(0.1, remaining))
            except queue.Empty:
                continue
            if not chunk:
                done = True
                continue
            output.extend(chunk)
            if len(output) > max_output_bytes:
                raise RuntimeError("command exceeded retained output limit")
            if on_line:
                pending += chunk.decode("utf-8", "replace")
                while "\n" in pending:
                    line, pending = pending.split("\n", 1)
                    on_line(line + "\n")
        if pending and on_line:
            on_line(pending)
        if error_file is not None:
            error_file.seek(0)
        result = subprocess.CompletedProcess(
            cmd,
            process.returncode,
            bytes(output).decode("utf-8", "replace") if capture else None,
            error_file.read(max_output_bytes).decode("utf-8", "replace")
            if error_file
            else None,
        )
        result.check_returncode()
        return result
    except BaseException as error:
        primary_error = error
        raise
    finally:
        stop.set()
        cleanup_errors = []

        def cleanup_step(label, action):
            try:
                action()
            except BaseException as error:
                cleanup_errors.append((label, error))

        cleanup_step("process group stop and reap", lambda: _stop_group(process))
        if process.stdout:
            cleanup_step("stdout close", process.stdout.close)
        if reader is not None:
            def join_reader():
                reader.join(timeout=15)
                if reader.is_alive():
                    raise RuntimeError("owned command output reader did not terminate")

            cleanup_step("output reader join", join_reader)
        if error_file is not None:
            cleanup_step("stderr close", error_file.close)
        if cleanup_errors:
            reported_error = primary_error if primary_error is not None else cleanup_errors[0][1]
            reported_error.owned_process_cleanup_errors = tuple(cleanup_errors)
            for label, error in cleanup_errors:
                detail = f"owned command cleanup failed during {label}: {type(error).__name__}"
                if isinstance(error, subprocess.TimeoutExpired):
                    detail += f" (timeout_seconds={error.timeout})"
                if label == "process group stop and reap":
                    detail += "; process exit remains unconfirmed"
                reported_error.add_note(detail)
            if primary_error is None:
                raise reported_error
