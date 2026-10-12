from __future__ import annotations

import subprocess
from copy import deepcopy

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
