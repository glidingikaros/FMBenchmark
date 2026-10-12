from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_generation_logfile_retention import _fixture_volume
from test_iteration2_generation import load
from test_logfile_adapter import driver_document, stomp_record
from test_logfile_scanner import FILETIME_2010, FILETIME_2026_B, file_record_bytes

from fmb.core.ntfs_time import filetime_to_utc_iso
from fmb.index.scanners import logfile_runtime
from fmb.replication import run


def retention(tmp_path, monkeypatch, records, *, entry=10, coverage=True):
    module = load("logfile_retention")
    log = tmp_path / "$LogFile"
    log.write_bytes(b"driver fixture")
    mft = bytearray(11 * 1024)
    mft[10 * 1024:] = file_record_bytes(entry=10, sequence=3, lsn=500)
    document = driver_document(records, logfile=log)
    document["parse"]["page_coverage_complete"] = coverage
    _fixture_volume(monkeypatch, bytes(mft), log.read_bytes(), entry=entry)
    monkeypatch.setattr(logfile_runtime, "logfile_runtime_availability", lambda: {"available": True})
    monkeypatch.setattr(logfile_runtime, "run_logfile_driver", lambda *a, **kw: deepcopy(document))
    target = {"path": r"C:\Records\Files\public.txt", "assigned_timestamp": filetime_to_utc_iso(FILETIME_2010),
              "original_creation_utc": filetime_to_utc_iso(FILETIME_2026_B)}
    return lambda: module.check_logfile_retention(tmp_path / "x.vmdk", targets=[target], output_dir=tmp_path,
                                                  require=True)


def test_only_a_logfile_that_lost_the_change_is_called_a_wrap(tmp_path, monkeypatch):
    check = retention(tmp_path, monkeypatch, [stomp_record(lsn=500, entry=11)])
    with pytest.raises(ValueError) as error:
        check()
    assert run.LOGFILE_WRAP.search(str(error.value))
    assert '"not_retained_reason": "no_candidate_update"' in (tmp_path / "logfile-retention-receipt.json").read_text()


@pytest.mark.parametrize("case, reason", [("coverage", "parse_coverage_unverified"),
                                          ("missing", "target_not_in_image"),
                                          ("uncommitted", "transition_not_committed")])
def test_other_logfile_failures_name_their_reason_and_are_not_a_wrap(tmp_path, monkeypatch, case, reason):
    check = retention(tmp_path, monkeypatch,
                      [stomp_record(lsn=500, entry=10, forgotten=None if case == "uncommitted" else 777)],
                      entry=None if case == "missing" else 10, coverage=case != "coverage")
    with pytest.raises(ValueError, match=rf"not retained \({reason}\)") as error:
        check()
    assert not run.LOGFILE_WRAP.search(str(error.value))


def test_a_retained_receipt_is_unchanged(tmp_path, monkeypatch):
    receipt = retention(tmp_path, monkeypatch, [stomp_record(lsn=500, entry=10)])()
    assert receipt["status"] == "retained"
    assert "not_retained_reason" not in receipt and "not_retained_reason" not in receipt["targets"][0]


def hmp_monitor(reply: bytes, delay: float):
    import socket
    import threading
    import time

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def serve():
        connection, _ = server.accept()
        with connection:
            connection.sendall(b"QEMU 8.2.2 monitor - type 'help' for more information\r\n(qemu) ")
            received = b""
            while not received.endswith(b"\n"):
                received += connection.recv(4096)
            connection.sendall(received.rstrip(b"\n") + b"\r\n")
            time.sleep(delay)
            connection.sendall(reply + b"\r\n(qemu) ")
        server.close()

    threading.Thread(target=serve, daemon=True).start()
    return server.getsockname()[1]


def test_a_late_monitor_error_is_read_up_to_the_prompt():
    from fmb.generation.backends import QemuBackend

    backend = QemuBackend.__new__(QemuBackend)
    backend.monitor_port = hmp_monitor(b"Could not open '/x.vmdk': No space left on device", 1.5)
    with pytest.raises(RuntimeError, match="(?i)QEMU refused .*no space left on device"):
        backend.attach_media({"uuid_bios": "u"}, [{"unit": 8, "port": 1, "path": "/x.vmdk"}])


class Guest:
    """A QEMU process that exits on the given wait() call."""

    def __init__(self, exits_on_wait: int, code: int = 0):
        self.returncode, self.waits, self.exits_on_wait, self.code = None, 0, exits_on_wait, code

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waits += 1
        if self.waits < self.exits_on_wait:
            raise subprocess.TimeoutExpired("qemu", timeout)
        self.returncode = self.code
        return self.code


def qemu_guest(process, shutdown_code: int):
    from fmb.generation.backends import QemuBackend

    backend = QemuBackend.__new__(QemuBackend)
    backend.process, sent = process, []
    backend._guest_powershell = lambda script, timeout=180: subprocess.CompletedProcess([], shutdown_code, "", "")
    backend._monitor = lambda command, timeout=30: sent.append(command) or "(qemu) "
    return backend, sent


def test_a_guest_that_shut_down_is_halted_as_before(capsys):
    backend, sent = qemu_guest(Guest(1), 0)
    backend.halt()
    assert sent == [] and "ACPI" not in capsys.readouterr().out


def test_a_failed_shutdown_request_falls_back_to_the_acpi_power_button(capsys):
    backend, sent = qemu_guest(Guest(2), 1)
    backend.halt()
    assert sent == ["system_powerdown"]
    assert "(asking it over WinRM failed with exit code 1); pressing its ACPI power button" in capsys.readouterr().out
    backend, sent = qemu_guest(Guest(3), 1)
    with pytest.raises(RuntimeError, match="guest shutdown did not finish"):
        backend.halt()


def test_a_qemu_that_died_says_its_exit_code():
    backend, _ = qemu_guest(Guest(1, code=137), 0)
    backend.process.returncode = 137
    with pytest.raises(RuntimeError, match=r"not running \(QEMU exited with 137\)"):
        backend.halt()


@pytest.mark.parametrize("second", [True, False])
def test_a_failed_soft_vmware_halt_is_asked_once_more_while_the_vm_runs(tmp_path, second):
    from fmb.generation.pipeline import GenerationPipeline

    instance = GenerationPipeline.__new__(GenerationPipeline)
    instance.discover_current_vmware_vmx_path = lambda: tmp_path / "box.vmx"
    instance.is_vmware_vm_running = lambda vmx: True
    calls = []

    def vmrun(args, **_):
        calls.append(args[0])
        if len(calls) == 1 or not second:
            raise subprocess.CalledProcessError(124, args)

    instance.run_vmrun = vmrun
    if second:
        instance.halt_vm()
    else:
        with pytest.raises(RuntimeError, match="soft VMware halt failed"):
            instance.halt_vm()
    assert calls == ["stop", "stop"]


@pytest.mark.parametrize("said, converts", [("qemu-img: error while reading sector 42: Input/output error", 2),
                                            ("qemu-img: error while writing at byte 9: No space left on device", 1)])
def test_a_failed_convert_is_tried_once_more_unless_the_disk_is_full(tmp_path, said, converts):
    from fmb.generation.pipeline import GenerationPipeline

    instance = GenerationPipeline.__new__(GenerationPipeline)
    calls = []

    def run_command(command, **_):
        calls.append(command[1])
        if command[1] == "convert":
            Path(command[-1]).write_bytes(b"partial")
            if calls.count("convert") == 1:
                raise subprocess.CalledProcessError(1, command, "", said)

    instance.run_command = run_command
    final = tmp_path / "full_scale.vmdk"
    if converts == 2:
        assert instance.convert_and_publish(tmp_path / "system.qcow2", final, "vmdk") == final
        assert calls == ["convert", "convert", "info"]
    else:
        with pytest.raises(RuntimeError, match="qemu-img convert failed: .*No space left on device"):
            instance.convert_and_publish(tmp_path / "system.qcow2", final, "vmdk")
        assert calls == ["convert"]
    assert not list(tmp_path.glob("*.partial"))


def phase(name, outcome, **extra):
    return "FMB_GENERATION_PHASE " + json.dumps({"phase": name, "outcome": outcome, **extra}) + "\n"


def failed(name, error="it broke"):
    return phase(name, "start") + phase(name, "error", error_type="RuntimeError") + f"fmb: {error}\n"


WRAP = failed("disk_discovery_export", "the intended timestamp transitions are not retained in the exported $LogFile; x")


def attempts_of(tmp_path, monkeypatch, logs):
    """Runs generate_image with a fake step whose attempts end with the given logs (None: published)."""
    folder = tmp_path / "I1"
    (folder / "recipe").mkdir(parents=True)
    monkeypatch.setattr(run, "await_base_clock", lambda recipe: None)
    events = []
    monkeypatch.setattr(run, "remove_leftovers", lambda: events.append("leftovers"))
    monkeypatch.setattr(run, "log", events.append)

    def step(name, *, log_path, output_root, **_):
        events.append(name)
        published = Path(output_root) / "full_scale" / "a"
        published.mkdir(parents=True)
        (published / "full_scale.vmdk").write_bytes(b"\0" * 2**20)
        text = logs[sum(event == "generate" for event in events) - 1]
        if text is None:
            (published / "manifest.json").write_text("{}")
        log_path.write_text(text or "done", encoding="utf-8")
        return 0 if text is None else 1

    monkeypatch.setattr(run, "step", step)
    image = SimpleNamespace(name="I1", paper=True, path=tmp_path / "I1.json")
    return lambda attempts=3: run.generate_image(image, tmp_path / "lock.json", folder, attempts), folder, events


def test_phase_lines_are_read_whatever_their_key_order_or_spacing():
    text = ('FMB_GENERATION_PHASE {"phase":"soft_halt","outcome":"error","outcome_detail":"x"}\n'
            'FMB_GENERATION_PHASE {"outcome": "error", "phase": "cleanup"}\nnot json\n')
    assert run.failed_phase(run.phase_records(text)) == "soft_halt"
    assert run.failed_phase(run.phase_records(phase("cleanup", "error"))) == "cleanup"
    assert run.failure(failed("soft_halt", "guest shutdown did not finish")) == (
        " at 'shut the guest down': guest shutdown did not finish")


@pytest.mark.parametrize("name", ["soft_halt", "disk_discovery_export", "cleanup"])
def test_a_late_failure_is_retried_without_its_disks(tmp_path, monkeypatch, name):
    generate, folder, events = attempts_of(tmp_path, monkeypatch, [failed(name), None])
    assert generate() == folder / "generation" / "attempt-2" / "full_scale" / "a"
    assert not (folder / "generation" / "attempt-1" / "full_scale" / "a" / "full_scale.vmdk").exists()
    assert ("leftovers" in events) == (name == "cleanup")
    assert any(f"attempt 1 failed at '{run.terminal.phase_title(name)}'" in str(event) for event in events)


@pytest.mark.parametrize("log", [failed("disk_discovery_export", "qemu-img convert failed: No space left on device"),
                                 failed("preflight"), "Traceback without a phase\n"])
def test_a_full_disk_or_a_failure_another_attempt_would_repeat_is_not_retried(tmp_path, monkeypatch, log):
    generate, _, events = attempts_of(tmp_path, monkeypatch, [log, None])
    with pytest.raises(SystemExit, match="generation failed"):
        generate()
    assert events.count("generate") == 1


def test_logfile_wraps_have_their_own_attempts(tmp_path, monkeypatch):
    provisioning = failed("ansible_provisioning")
    generate, folder, events = attempts_of(tmp_path, monkeypatch, [WRAP, WRAP, provisioning, provisioning, None])
    assert generate(3) == folder / "generation" / "attempt-5" / "full_scale" / "a"
    generate, folder, events = attempts_of(tmp_path / "again", monkeypatch, [WRAP, WRAP, None])
    with pytest.raises(SystemExit, match="not retained"):
        generate(2)
    assert "I1: attempt 2 lost a timestamp change" in events[-1] and events[-1].endswith("stopping after 2 such attempts")


def test_no_failure_hint_names_a_flag_that_does_not_exist():
    source = (Path(__file__).resolve().parents[2] / "src/fmb/generation/pipeline.py").read_text(encoding="utf-8")
    assert "--resume-post-export" not in source


def test_an_unpublished_attempt_never_keeps_its_disks(tmp_path, monkeypatch):
    generate, folder, events = attempts_of(tmp_path, monkeypatch, [failed("preflight")])
    stale = folder / "generation" / "attempt-1" / "full_scale" / "old"
    stale.mkdir(parents=True)
    (stale / "full_scale.vmdk.0a1b2c3d.partial").write_bytes(b"\0" * 2**26)
    (stale / "full_scale.vmdk").write_bytes(b"\0" * 2**26)
    (stale / "receipt.json").write_text("{}")
    with pytest.raises(SystemExit, match="generation failed"):
        generate()
    assert sorted(path.name for path in (folder / "generation").rglob("*") if path.is_file()) == ["receipt.json"]
    assert "I1: removed the disk images of its earlier unfinished attempts (0.1 GiB); their logs stay" in events


@pytest.mark.parametrize("how", ["code", "signal"])
def test_an_interrupted_attempt_leaves_no_disk_behind(tmp_path, monkeypatch, how):
    generate, folder, events = attempts_of(tmp_path, monkeypatch, [])

    def interrupted(name, **arguments):
        published = Path(arguments["output_root"]) / "full_scale" / "a"
        published.mkdir(parents=True)
        (published / "full_scale.vmdk").write_bytes(b"\0" * 2**27)
        if how == "signal":
            raise KeyboardInterrupt("generate stopped after cleaning up")
        return run.INTERRUPTED

    monkeypatch.setattr(run, "step", interrupted)
    with pytest.raises(KeyboardInterrupt if how == "signal" else SystemExit):
        generate()
    assert not list(folder.rglob("*.vmdk"))
    assert "I1: removed the disk images of interrupted attempt 1 (0.1 GiB); their logs stay" in events


def test_a_published_image_is_never_touched(tmp_path, monkeypatch):
    generate, folder, _ = attempts_of(tmp_path, monkeypatch, [])
    done = folder / "generation" / "attempt-1" / "full_scale" / "a"
    done.mkdir(parents=True)
    (done / "full_scale.vmdk").write_bytes(b"disk")
    (done / "manifest.json").write_text("{}")
    assert generate() == done and (done / "full_scale.vmdk").read_bytes() == b"disk"
