from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest
from test_logfile_scanner import (
    FILETIME_2010,
    FILETIME_2026_A,
    FILETIME_2026_B,
    file_record_bytes,
)

from fmb.analysis.inputs import observation_object_id
from fmb.core.schemas import validate_payload
from fmb.index.adapters import logfile as logfile_adapters
from fmb.index.adapters import mft as mft_adapters
from fmb.index.contract import evidence_index
from fmb.index.kape import sources as kape_sources
from fmb.index.scanners.usn import ntfs_reference_set_sha256

VOLUME = "mft-source:test"


def mft_context() -> dict[str, object]:
    return {
        "row_count": 2,
        "mft_volume_id": VOLUME,
        "reference_absence_check_supported": True,
        "path_absence_check_supported": True,
        "active_refs": {(10, 3)},
        "entry_sequences": {10: (3, True), 12: (2, False)},
        "active_full_paths": {r"c:\users\alice\desktop\stomped.txt"},
        "active_basenames": {"stomped.txt"},
        "directory_paths_by_ref": {(5, 1): r"C:\Users\alice\Desktop"},
        "indexed_volumes": {"c"},
        "ambiguous_entries": set(),
    }


def driver_document(records: list[dict[str, object]], *, logfile: Path) -> dict[str, object]:
    return {
        "schema_version": "fmb_logfile_records.v2",
        "logfile": {"path": str(logfile), "size_bytes": logfile.stat().st_size, "sha256": "a" * 64},
        "selection": {"operations": ["UpdateResidentValue", "InitializeFileRecordSegment", "DeallocateFileRecordSegment"]},
        "parse": {
            "log_version": [1, 1], "log_page_size": 4096, "lsn_first": 100, "lsn_last": 9000,
            "record_count": 12, "restart_area_count": 1, "parse_error_count": 0, "emitted_record_count": len(records),
            "records_truncated": False, "forgotten_transaction_count": 2, "rolled_back_transaction_count": 0,
            "open_transaction_count": 0, "duration_seconds": 0.1,
            "page_coverage_complete": True, "record_page_failure_count": 0, "unknown_page_count": 0,
            "client_count": 1, "client_record_counts": {"0": len(records)}, "multi_client": False,
            "lifecycle_record_count": 0,
        },
        "lifecycle_records": [],
        "operation_counts": {"UpdateResidentValue/UpdateResidentValue": len(records)},
        "embedded_usn": {
            "record_count": 3, "first_usn": 1000, "first_timestamp_filetime": FILETIME_2026_A,
            "last_usn": 1200, "last_timestamp_filetime": FILETIME_2026_B,
            "min_timestamp_filetime": FILETIME_2026_A, "max_timestamp_filetime": FILETIME_2026_B,
            "journal_file_reference": 77,
        },
        "restart_areas": [{"lsn": 100}],
        "records": records,
        "runtime": {
            "command_line": "python driver --logfile x",
            "tool_identity": {"name": "dfir_ntfs", "version": "1.1.20", "license": "GPL-3.0", "verification": {"status": "verified"}},
        },
    }


def stomp_record(*, lsn: int, entry: int, forgotten: int | None = 777) -> dict[str, object]:
    redo = struct.pack("<QQQQ", FILETIME_2010, FILETIME_2010, FILETIME_2026_B, FILETIME_2010)
    undo = struct.pack("<QQQQ", FILETIME_2026_B, FILETIME_2026_B, FILETIME_2026_B, FILETIME_2026_B)
    return {
        "lsn": lsn, "transaction_id": 24, "redo_operation_name": "UpdateResidentValue",
        "undo_operation_name": "UpdateResidentValue", "mft_target_number": entry, "offset_in_target": 80,
        "target_block_size": 2, "redo_hex": redo.hex(), "undo_hex": undo.hex(),
        "transaction_forgotten_lsn": forgotten, "transaction_rolled_back": False,
    }


@pytest.fixture
def collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    root = tmp_path / "kape-output"
    (root / "targets" / "F").mkdir(parents=True)
    logfile = root / "targets" / "F" / "$LogFile"
    logfile.write_bytes(b"\xff" * 64)
    table = bytearray(1024 * 13)
    table[10 * 1024 : 11 * 1024] = file_record_bytes(entry=10, sequence=3, lsn=500)
    table[12 * 1024 : 13 * 1024] = file_record_bytes(entry=12, sequence=2, in_use=False, file_name="freed.txt")
    mft = root / "targets" / "F" / "$MFT"
    mft.write_bytes(bytes(table))
    records = [stomp_record(lsn=500, entry=10), stomp_record(lsn=700, entry=12)]
    monkeypatch.setattr(
        logfile_adapters, "logfile_runtime_availability",
        lambda: {"available": True, "reason": None, "tool_identity": {"name": "dfir_ntfs", "version": "1.1.20"}},
    )
    monkeypatch.setattr(
        logfile_adapters, "_logfile_driver_document",
        lambda path, *, normalized_output_dir, operations=None: driver_document(records, logfile=path),
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    return {"root": root, "logfile": logfile, "mft": mft, "normalized": normalized}


def test_reference_scoped_run_binds_the_stomp_transition_to_the_exact_object(collection: dict[str, Path]) -> None:
    references = {(10, 3), (11, 1)}

    run = logfile_adapters.raw_logfile_reference_parser_run(
        logfile_path=collection["logfile"], raw_mft_path=collection["mft"],
        normalized_output_dir=collection["normalized"], collector_run={"collector": "kape"},
        references=references, filesystem_scope_id=VOLUME, mft_context=mft_context(),
    )

    assert run["parser"] == "dfir_ntfs" and run["parser_kind"] == "ntfs_logfile"
    assert run["coverage_status"] == "complete"
    assert run["selection_scope"] == {
        "kind": "ntfs_file_references", "filesystem_scope_id": VOLUME, "reference_count": 2,
        "reference_sha256": ntfs_reference_set_sha256(references), "matched_record_count": 1,
        "retained_record_count": 1, "normalized_record_count": 1,
        "source_size_bytes": 64, "source_bytes_covered": 64, "status": "complete",
    }
    scope = run["coverage_scope"]
    assert scope["kind"] == "ntfs_logfile" and scope["parser_status"] == "completed"
    assert (scope["lsn_first"], scope["lsn_last"]) == (100, 9000)
    assert scope["first_timestamp"] == "2026-09-12T01:01:33.3138548Z"
    assert scope["last_timestamp"] == "2026-09-12T10:58:26.5463544Z"
    assert scope["window_complete"] is True and scope["timestamp_order"] == "monotonic"
    assert scope["si_update_count"] == 2 and scope["si_update_bound_count"] == 1
    assert scope["si_update_unbound_reasons"] == {"record_not_in_use": 1}
    [observation] = run["observations"]
    assert observation["observation_type"] == "logfile_si_update"
    assert observation["artifact_family"] == "ntfs.logfile"
    assert observation["subject_ref"] == r"C:\Users\alice\Desktop\stomped.txt"
    fields = observation["fields"]
    assert observation_object_id(fields, observation["subject_ref"]) == f"ntfs:{VOLUME}:10:3"
    assert fields["mft_lookup_target"]["object_id"] == f"ntfs:{VOLUME}:10:3"
    assert fields["covered_fields"] == "created|modified|record_changed|accessed"
    assert fields["old_si_created"] == "2026-09-12T10:58:26.5463544Z"
    assert fields["new_si_created"] == "2010-01-01T20:00:00Z"
    assert fields["new_si_modified"] == "2010-01-01T20:00:00Z"
    assert fields["current_si_created"] == "2010-01-01T20:00:00Z"
    assert fields["transaction_committed"] is True and fields["transaction_forgotten_lsn"] == 777
    assert fields["record_lsn"] == 500 and fields["record_lsn_retained"] is True
    assert fields["mft_active_presence_status"] == "active_mft_present"
    assert observation["source_record_ref"].endswith("$LogFile:lsn=500")
    normalized = json.loads(Path(run["normalized_output"]["path"]).read_text(encoding="utf-8"))
    assert normalized["record_count"] == 1 and normalized["selection_scope"] == run["selection_scope"]
    assert {item["path"] for item in run["raw_outputs"]} == {str(collection["logfile"]), str(collection["mft"])}


def test_scope_only_run_reports_retention_without_observations(collection: dict[str, Path]) -> None:
    run = logfile_adapters.raw_logfile_parser_run(
        logfile_path=collection["logfile"], raw_mft_path=collection["mft"],
        normalized_output_dir=collection["normalized"], collector_run={"collector": "kape"},
        mft_context=mft_context(),
    )

    assert run["observation_count"] == 0 and run["coverage_status"] == "complete"
    assert run["coverage_scope"]["si_update_bound_count"] == 1
    assert run["tool_identity"]["availability"] == "available"
    assert run["command_line"] == "python driver --logfile x"


def test_unavailable_runtime_yields_a_partial_scope_only_run(collection: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        logfile_adapters, "logfile_runtime_availability",
        lambda: {"available": False, "reason": "dfir_ntfs_environment_mismatch", "detail": "package_missing", "tool_identity": None},
    )

    scoped = logfile_adapters.raw_logfile_reference_parser_run(
        logfile_path=collection["logfile"], raw_mft_path=collection["mft"],
        normalized_output_dir=collection["normalized"], collector_run={"collector": "kape"},
        references={(10, 3)}, filesystem_scope_id=VOLUME, mft_context=mft_context(),
    )
    unscoped = logfile_adapters.raw_logfile_parser_run(
        logfile_path=collection["logfile"], raw_mft_path=collection["mft"],
        normalized_output_dir=collection["normalized"], collector_run={"collector": "kape"},
        mft_context=mft_context(),
    )

    for run in (scoped, unscoped):
        assert run["observation_count"] == 0 and run["coverage_status"] == "partial"
        assert run["coverage_scope"]["parser_status"] == "unavailable"
        assert run["coverage_scope"]["reason"] == "dfir_ntfs_environment_mismatch"
        normalized = json.loads(Path(run["normalized_output"]["path"]).read_text(encoding="utf-8"))
        assert normalized["local_diagnostics"]["availability_detail"] == "package_missing"
        assert run["coverage_scope"]["window_complete"] is False
        assert run["tool_identity"]["availability"] == "unavailable"
    assert scoped["selection_scope"]["status"] == "partial"
    assert scoped["selection_scope"]["source_bytes_covered"] == 0


def test_reference_scoped_run_requires_the_matching_filesystem_scope(collection: dict[str, Path]) -> None:
    with pytest.raises(ValueError, match="does not match"):
        logfile_adapters.raw_logfile_reference_parser_run(
            logfile_path=collection["logfile"], raw_mft_path=collection["mft"],
            normalized_output_dir=collection["normalized"], collector_run={"collector": "kape"},
            references={(10, 3)}, filesystem_scope_id="mft-source:other", mft_context=mft_context(),
        )
    with pytest.raises(ValueError, match="invalid"):
        logfile_adapters.raw_logfile_reference_parser_run(
            logfile_path=collection["logfile"], raw_mft_path=collection["mft"],
            normalized_output_dir=collection["normalized"], collector_run={"collector": "kape"},
            references={(10, -1)}, filesystem_scope_id=VOLUME, mft_context=mft_context(),
        )


def test_kape_discovery_routes_the_raw_logfile_with_the_raw_mft(collection: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_run(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {"source": str(kwargs["logfile_path"])}

    monkeypatch.setattr(kape_sources, "raw_logfile_parser_run", fake_run)
    monkeypatch.setattr(kape_sources, "build_mft_presence_context", lambda root: {"row_count": 0})

    runs = kape_sources.scan_kape_output_root(
        root=collection["root"], collector_run={"collector": "kape", "artifacts": []},
        normalized_output_dir=collection["normalized"],
    )

    assert {"source": str(collection["logfile"])} in runs
    [call] = calls
    assert call["raw_mft_path"] == collection["mft"]
    assert call["mft_context"] == {"row_count": 0}
    assert logfile_adapters.raw_logfile_files(collection["root"]) == [collection["logfile"]]
    assert mft_adapters.raw_mft_path_for_root(collection["root"]) == collection["mft"]


def test_parser_run_validates_against_the_evidence_schema(collection: dict[str, Path]) -> None:
    run = logfile_adapters.raw_logfile_reference_parser_run(
        logfile_path=collection["logfile"], raw_mft_path=collection["mft"],
        normalized_output_dir=collection["normalized"], collector_run={"collector": "kape"},
        references={(10, 3)}, filesystem_scope_id=VOLUME, mft_context=mft_context(),
    )
    collector = evidence_index.inventory_collector_output(
        collector="kape",
        output_root=collection["root"],
        target_or_profile="$LogFile",
        command_line="kape --target $LogFile",
    )
    index = evidence_index.assemble_evidence_index(
        run_id="run-logfile",
        question_id="Q-TIME-01",
        question_text="Question",
        collector_runs=[collector],
        rule_runs=[],
        parser_runs=[run],
    )
    assert index["tool_alignment"]["parser_tools_used"] == ["dfir_ntfs"]
    validate_payload(index, "evidence_index.schema.json")


@pytest.mark.parametrize('parse_error_count', [1, -1, None, True, '0', 0.0])
def test_record_parse_errors_or_unverified_counts_withhold_optional_si_witnesses(
    collection: dict[str, Path], monkeypatch: pytest.MonkeyPatch, parse_error_count
) -> None:
    document = driver_document([stomp_record(lsn=500, entry=10)], logfile=collection['logfile'])
    document['parse']['parse_error_count'] = parse_error_count
    monkeypatch.setattr(logfile_adapters, '_logfile_driver_document', lambda *args, **kwargs: document)
    run = logfile_adapters.raw_logfile_reference_parser_run(
        logfile_path=collection['logfile'], raw_mft_path=collection['mft'],
        normalized_output_dir=collection['normalized'], collector_run={'collector': 'kape'},
        references={(10, 3)}, filesystem_scope_id=VOLUME, mft_context=mft_context(),
    )
    assert run['coverage_status'] == 'partial'
    assert run['observations'] == []
    assert run['coverage_scope']['si_update_unbound_reasons'] == {
        'record_parse_errors_or_unverified_count': 1,
    }
    assert logfile_adapters._logfile_parse_complete(document) is False
    assert len(document['records']) == 1
