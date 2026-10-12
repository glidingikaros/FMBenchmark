from __future__ import annotations

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
