from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import struct

import pytest
from test_iteration2_generation import load
from test_logfile_adapter import driver_document, stomp_record
from test_logfile_scanner import FILETIME_2010, FILETIME_2026_B, file_record_bytes

from fmb.collection.tools.host import ntfs_index
from fmb.core.ntfs_time import filetime_to_utc_iso
from fmb.index.scanners import logfile_runtime


def test_retention_timestamp_equality_preserves_every_100ns_tick():
    module = load("logfile_retention")
    same = module._same_instant
    assert same("2010-01-01T12:00:00.0000001Z", "2010-01-01T14:00:00.0000001+02:00")
    assert not same("2010-01-01T12:00:00.0000001Z", "2010-01-01T12:00:00.0000000Z")
    assert not same("2010-01-01T12:00:00", "2010-01-01T12:00:00Z")
    assert not same(None, "2010-01-01T12:00:00Z")


def _fixture_volume(monkeypatch, mft: bytes, log: bytes, *, entry=10):
    class FixtureIndex:
        def __init__(self, path):
            pass

        def copy_stream(self, number, name, write):
            write(mft if number == 0 else log)

        def resolve_directories(self, components):
            return [5] if components == ["Records", "Files"] else []

        def iter_links(self, directory):
            return [("public.txt", entry)]

    monkeypatch.setattr(ntfs_index, "VolumeIndex", FixtureIndex)


@pytest.mark.parametrize(
    "defect",
    [
        None,
        "failed_page",
        "truncated",
        "parse_error",
        "multi_client",
        "unknown",
        "missing_lifecycle",
    ],
)
def test_required_retention_refuses_unverified_log_scope_with_real_mft_binding(
    tmp_path, monkeypatch, defect
):
    module = load("logfile_retention")
    log = tmp_path / "$LogFile"
    log.write_bytes(b"public driver document fixture")
    mft = bytearray(11 * 1024)
    mft[10 * 1024 :] = file_record_bytes(entry=10, sequence=3, lsn=500)
    document = driver_document([stomp_record(lsn=500, entry=10)], logfile=log)
    if defect == "failed_page":
        document["parse"]["page_coverage_complete"] = False
    elif defect == "truncated":
        document["parse"]["records_truncated"] = True
    elif defect == "parse_error":
        document["parse"]["parse_error_count"] = 1
    elif defect == "multi_client":
        document["parse"]["multi_client"] = True
    elif defect == "unknown":
        document["parse"].pop("page_coverage_complete")
    elif defect == "missing_lifecycle":
        document.pop("lifecycle_records")
    _fixture_volume(monkeypatch, bytes(mft), log.read_bytes())
    monkeypatch.setattr(
        logfile_runtime, "logfile_runtime_availability", lambda: {"available": True}
    )
    monkeypatch.setattr(
        logfile_runtime,
        "run_logfile_driver",
        lambda *args, **kwargs: deepcopy(document),
    )
    target = {
        "path": r"C:\Records\Files\public.txt",
        "assigned_timestamp": filetime_to_utc_iso(FILETIME_2010),
        "original_creation_utc": filetime_to_utc_iso(FILETIME_2026_B),
    }
    if defect is None:
        receipt = module.check_logfile_retention(
            tmp_path / "public.vmdk",
            targets=[target],
            output_dir=tmp_path,
            require=True,
        )
        assert (
            receipt["status"] == "retained"
            and receipt["targets"][0]["committed"] is True
        )
    else:
        with pytest.raises(ValueError, match="not retained"):
            module.check_logfile_retention(
                tmp_path / "public.vmdk",
                targets=[target],
                output_dir=tmp_path,
                require=True,
            )


def test_actual_failed_native_log_page_cannot_pass_required_retention(
    tmp_path, monkeypatch
):
    if not logfile_runtime.logfile_runtime_availability().get("available"):
        pytest.skip("locked dfir_ntfs runtime unavailable")
    from fmb.index.scanners.logfile import si_updates_from_records

    fixtures = Path(__file__).resolve().parents[1] / "fixtures/logfile"
    mft = fixtures / "current.mft.bin"
    log = fixtures / "corrupt-lifecycle.logfile.bin"
    document = logfile_runtime.run_logfile_driver(
        log, output_path=tmp_path / "native-document.json", timeout_seconds=60
    )
    assert document["parse"]["page_coverage_complete"] is False
    updates, _ = si_updates_from_records(
        document["records"],
        mft_path=mft,
        lifecycle_records=document["lifecycle_records"],
    )
    assert (
        updates
    )
    update = updates[0]
    _fixture_volume(
        monkeypatch, mft.read_bytes(), log.read_bytes(), entry=update["mft_entry"]
    )
    target = {
        "path": r"C:\Records\Files\public.txt",
        "assigned_timestamp": update["new"]["created"],
        "original_creation_utc": update["old"]["created"],
    }
    with pytest.raises(ValueError, match="not retained"):
        load("logfile_retention").check_logfile_retention(
            tmp_path / "public.vmdk",
            targets=[target],
            output_dir=tmp_path,
            require=True,
        )


@pytest.mark.parametrize("committed", [True, False])
def test_archive_restoration_retention_accepts_only_a_committed_modified_field_update(tmp_path, monkeypatch, committed):
    module = load("logfile_retention")
    log = tmp_path / "$LogFile"
    log.write_bytes(b"modified-only native driver fixture")
    mft = bytearray(11 * 1024)
    mft[10 * 1024:] = file_record_bytes(entry=10, sequence=3, lsn=500,
        si_times=(FILETIME_2026_B, FILETIME_2010, FILETIME_2026_B, FILETIME_2026_B))
    update = stomp_record(lsn=500, entry=10, forgotten=777 if committed else None)
    update.update(offset_in_target=88, redo_hex=struct.pack("<Q", FILETIME_2010).hex(),
                  undo_hex=struct.pack("<Q", FILETIME_2026_B).hex())
    document = driver_document([update], logfile=log)
    _fixture_volume(monkeypatch, bytes(mft), log.read_bytes())
    monkeypatch.setattr(logfile_runtime, "logfile_runtime_availability", lambda: {"available": True})
    monkeypatch.setattr(logfile_runtime, "run_logfile_driver", lambda *a, **kw: deepcopy(document))
    target = {"path": r"C:\Records\Files\public.txt", "modified_only": True,
              "assigned_timestamp": filetime_to_utc_iso(FILETIME_2010),
              "original_creation_utc": filetime_to_utc_iso(FILETIME_2026_B)}
    if committed:
        receipt = module.check_logfile_retention(tmp_path / "fixture.vmdk", targets=[target], output_dir=tmp_path, require=True)
        assert receipt["status"] == "retained" and receipt["targets"][0]["committed"] is True
    else:
        with pytest.raises(ValueError, match="not retained"):
            module.check_logfile_retention(tmp_path / "fixture.vmdk", targets=[target], output_dir=tmp_path, require=True)
