import os
import io
import subprocess
import sys
import time

import pytest

from fmb.core.owned_process import run_owned
from fmb.core import owned_process
from fmb.core.errors import run_cli


def test_stdout_and_stderr_remain_separate():
    result = run_owned(
        [
            sys.executable,
            "-c",
            "import sys;sys.stdout.buffer.write(b'data\\n');sys.stderr.buffer.write(b'warning\\n')",
        ],
        capture_output=True,
        timeout=3,
    )
    assert result.stdout == "data\n"
    assert result.stderr == "warning\n"


@pytest.mark.parametrize("capture", [False, True])
def test_silent_command_obeys_deadline(capture):
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_owned(
            [sys.executable, "-c", "import time;time.sleep(30)"],
            timeout=0.2,
            capture_output=capture,
        )
    assert time.monotonic() - start < 3


@pytest.mark.skipif(os.name != "posix", reason="POSIX process group assertion")
def test_parent_exit_does_not_orphan_a_descendant_holding_output(tmp_path):
    pidfile = tmp_path / "child.pid"
    child = (
        "import os,time;from pathlib import Path;Path("
        + repr(str(pidfile))
        + ").write_text(str(os.getpid()));time.sleep(30)"
    )
    parent = (
        'import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",'
        + repr(child)
        + "]);time.sleep(.1)"
    )
    with pytest.raises(subprocess.TimeoutExpired):
        run_owned([sys.executable, "-c", parent], on_line=lambda _: None, timeout=0.4)
    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(.02)
    else:
        pytest.fail("owned descendant still exists after cleanup")


def test_partial_line_is_not_a_deadline_bypass():
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        run_owned(
            [
                sys.executable,
                "-c",
                "import sys,time;sys.stdout.write('partial');sys.stdout.flush();time.sleep(30)",
            ],
            on_line=lambda _: None,
            timeout=3,
        )
    assert caught.value.output == "partial"


def test_failed_command_preserves_exit_and_output():
    with pytest.raises(subprocess.CalledProcessError) as caught:
        run_owned(
            [sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'failed\\n');raise SystemExit(7)"],
            capture_output=True,
            timeout=3,
        )
    assert caught.value.returncode == 7 and caught.value.output == "failed\n"


def _mock_interrupted_process(monkeypatch, primary, *, capture=False):
    class Process:
        pid = 999999999
        stdout = io.BytesIO() if capture else None

        def poll(self):
            raise primary

    process = Process()
    monkeypatch.setattr(owned_process.subprocess, "Popen", lambda *a, **k: process)
    return process


@pytest.mark.parametrize("primary", [KeyboardInterrupt("requested stop"), RuntimeError("command failed")])
def test_cleanup_timeout_does_not_replace_initiating_error(monkeypatch, primary):
    _mock_interrupted_process(monkeypatch, primary)
    secondary = subprocess.TimeoutExpired(["synthetic-reap"], 15)

    def cleanup(_process):
        raise secondary

    monkeypatch.setattr(owned_process, "_stop_group", cleanup)
    with pytest.raises(type(primary)) as caught:
        run_owned(["no-child"], timeout=3)
    assert caught.value is primary
    assert caught.value.owned_process_cleanup_errors[0][1] is secondary
    assert any("TimeoutExpired" in note and "process exit remains unconfirmed" in note
               for note in caught.value.__notes__)


def test_normal_cleanup_preserves_interrupt(monkeypatch):
    primary = KeyboardInterrupt("requested stop")
    _mock_interrupted_process(monkeypatch, primary)
    monkeypatch.setattr(owned_process, "_stop_group", lambda _process: None)
    with pytest.raises(KeyboardInterrupt) as caught:
        run_owned(["no-child"], timeout=3)
    assert caught.value is primary
    assert not getattr(caught.value, "__notes__", [])


def test_reap_failure_still_closes_captured_streams_and_joins_reader(monkeypatch):
    primary = KeyboardInterrupt("requested stop")
    process = _mock_interrupted_process(monkeypatch, primary, capture=True)
    stderr = io.BytesIO()
    monkeypatch.setattr(owned_process.tempfile, "TemporaryFile", lambda: stderr)
    readers = []
    real_thread = owned_process.threading.Thread

    def tracked_thread(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        readers.append(thread)
        return thread

    monkeypatch.setattr(owned_process.threading, "Thread", tracked_thread)

    def cleanup(_process):
        raise subprocess.TimeoutExpired(["synthetic-reap"], 15)

    monkeypatch.setattr(owned_process, "_stop_group", cleanup)
    with pytest.raises(KeyboardInterrupt):
        run_owned(["no-child"], capture_output=True, timeout=3)
    assert process.stdout.closed and stderr.closed
    assert len(readers) == 1 and not readers[0].is_alive()


def test_cli_reports_interruption_and_secondary_cleanup_failure(monkeypatch, capsys):
    _mock_interrupted_process(monkeypatch, KeyboardInterrupt("requested stop"))

    def cleanup(_process):
        raise subprocess.TimeoutExpired(["synthetic-reap"], 15)

    monkeypatch.setattr(owned_process, "_stop_group", cleanup)
    code = run_cli("fmb", lambda: run_owned(["no-child"], timeout=3))
    error = capsys.readouterr().err
    assert code == 130 and "interrupted" in error
    assert "TimeoutExpired" in error and "timeout_seconds=15" in error
    assert "process exit remains unconfirmed" in error


def test_successful_command_does_not_hide_cleanup_failure(monkeypatch):
    class Process:
        pid = 999999999
        stdout = None
        returncode = 0

        def poll(self):
            return 0

    monkeypatch.setattr(owned_process.subprocess, "Popen", lambda *a, **k: Process())
    secondary = subprocess.TimeoutExpired(["synthetic-reap"], 15)

    def cleanup(_process):
        raise secondary

    monkeypatch.setattr(owned_process, "_stop_group", cleanup)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        run_owned(["no-child"], timeout=3)
    assert caught.value is secondary


@pytest.mark.parametrize("method", ["run_command", "run_streaming_command"])
@pytest.mark.parametrize("origin", ["command_deadline", "cleanup_only"])
def test_generation_timeout_translation_retains_cleanup_notes(monkeypatch, tmp_path, capsys, method, origin):
    from fmb.generation.pipeline import GenerationPipeline

    controller = GenerationPipeline.__new__(GenerationPipeline)
    controller.vagrant_dir = tmp_path
    controller.resolve_command = lambda command: list(command)
    controller.prepare_env = lambda environment: dict(environment or {})
    timeout = subprocess.TimeoutExpired(["no-child"], 3600 if origin == "command_deadline" else 15,
                                        output="retained output")
    timeout.add_note("owned command cleanup failed: TimeoutExpired; process exit remains unconfirmed")

    def fail(*_args, **_kwargs):
        raise timeout

    monkeypatch.setattr(owned_process, "run_owned", fail)
    def callback():
        return getattr(controller, method)(["no-child"])
    with pytest.raises(subprocess.CalledProcessError) as caught:
        callback()
    assert caught.value.returncode == 124 and caught.value.output == "retained output"
    assert caught.value.__cause__ is timeout
    assert caught.value.__notes__ == timeout.__notes__
    assert run_cli("fmb", callback) == 1
    assert "process exit remains unconfirmed" in capsys.readouterr().err
