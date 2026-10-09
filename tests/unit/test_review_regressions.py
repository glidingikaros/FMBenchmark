from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest
from types import SimpleNamespace
from unittest.mock import patch

from test_deterministic_analysis import (
    _backdated_without_usn,
    _timestomp_index,
    _usb_input,
    evidence_index,
    observation,
)
from test_logfile_runtime import fake_environment, write_lock

from fmb.analysis.catalog import techniques_for_question
from fmb.analysis.deterministic import _setupapi_window_decision, _usn_journal_window
from rule_helpers import analyze_input
from fmb.analysis.inputs import _merge_coverage_scopes, build_analysis_input
from fmb.collection.analysis import add_reference_scoped_usn
from fmb.index.adapters import logfile as logfile_adapters
from fmb.index.adapters import parser_output as parser_output_adapters
from fmb.index.adapters import registry as registry_adapters
from fmb.index.adapters import usn as usn_adapters
import fmb.index.support.windows_artifacts as windows_artifacts
from fmb.index.kape.sources import scan_kape_output_root
from fmb.index.scanners.logfile_runtime import (
    LogFileToolchain,
    logfile_runtime_availability,
    run_logfile_driver,
)
from fmb.analysis.evidence_projection import blinding_violations
from paper_fixtures import projected_input


def _setupapi_scope(first: str, last: str, **extra: object) -> dict[str, object]:
    return {
        "kind": "setupapi_log",
        "first_section_timestamp": first,
        "last_section_timestamp": last,
        "window_complete": True,
        "files": ["setupapi.dev.log"],
        **extra,
    }


def test_install_after_the_retained_setupapi_window_is_not_supported() -> None:
    scope = _setupapi_scope("2026-01-01 00:00:00", "2026-01-02 00:00:00")

    result = analyze_input(_usb_input("2026-01-10 00:00:00", {"windows_setupapi": scope})).assessments[0]

    assert result.outcome == "indeterminate"
    assert result.reason_code == "setupapi_window_excludes_install"


def test_arrival_or_key_timestamps_are_not_installation_evidence() -> None:
    scope = _setupapi_scope("2026-01-01 00:00:00", "2026-01-02 00:00:00")
    value = SimpleNamespace(coverage=[SimpleNamespace(artifact_family="windows.setupapi", scope=scope)])
    records = (SimpleNamespace(fields={"first_install": "", "last_arrival": "2026-01-02 00:00:00"}),)

    decision = _setupapi_window_decision(value, records, ())

    assert decision is not None and decision.reason_code == "setupapi_window_unverifiable"


def test_containment_uses_the_guest_time_zone_not_a_blanket_tolerance() -> None:
    scope = _setupapi_scope("2026-09-12 03:00:00", "2026-09-12 04:10:00", guest_utc_offset_minutes=-420)
    inside = analyze_input(_usb_input("2026-09-12 10:58:00", {"windows_setupapi": scope})).assessments[0]
    assert inside.reason_code != "setupapi_window_excludes_install"
    unknown = _setupapi_scope("2026-09-12 03:00:00", "2026-09-12 04:10:00")
    abstain = analyze_input(_usb_input("2026-09-12 10:58:00", {"windows_setupapi": unknown})).assessments[0]
    assert abstain.reason_code == "setupapi_window_unverifiable"


def test_merged_scopes_keep_their_intervals_and_gaps() -> None:
    first = _setupapi_scope("2026-01-01 00:00:00", "2026-01-02 00:00:00")
    second = _setupapi_scope("2026-01-10 00:00:00", "2026-01-11 00:00:00", files=["setupapi.dev.20260109.log"])

    merged = _merge_coverage_scopes(_merge_coverage_scopes(None, first), second)

    assert [(item["first"], item["last"]) for item in merged["intervals"]] == [
        ("2026-01-01 00:00:00", "2026-01-02 00:00:00"),
        ("2026-01-10 00:00:00", "2026-01-11 00:00:00"),
    ]
    assert merged["gap_count"] == 1
    result = analyze_input(_usb_input("2026-01-05 00:00:00", {"windows_setupapi": merged})).assessments[0]
    assert result.outcome == "indeterminate"
    assert result.reason_code == "setupapi_window_unverifiable"


def test_two_rotated_logs_through_actual_discovery_do_not_cover_the_gap(tmp_path: Path) -> None:
    root = tmp_path / "kape-output"
    folder = root / "targets" / "F" / "Windows" / "INF"
    folder.mkdir(parents=True)

    def log(first: str, second: str) -> str:
        return "\n".join(
            ">>> [Device Install - PCI\\VEN_PUBLIC]\n>>> Section start " + stamp
            + "\n<<< Section end " + stamp + "\n<<< [Exit status: SUCCESS]"
            for stamp in (first, second)
        ) + "\n"

    (folder / "setupapi.dev.old.log").write_text(log("2026/01/01 00:00:00", "2026/01/02 00:00:00"))
    (folder / "setupapi.dev.log").write_text(log("2026/01/10 00:00:00", "2026/01/11 00:00:00"))
    collector = {"collector": "kape", "provenance": {}, "output_root": str(root)}
    runs = scan_kape_output_root(root=root, collector_run=collector, normalized_output_dir=tmp_path / "normalized")
    index = evidence_index(
        observation(
            "usb", "windows.registry.usbstor", "usb_device_seen", "USB Disk",
            serial_number="SERIAL-1", device_instance_id=r"USBSTOR\DISK&VEN_ACME\SERIAL-1",
            control_set="ControlSet001", first_install="2026-01-05 00:00:00",
        ),
        families={"windows.registry.usbstor"},
    )
    index["parser_runs"].extend(runs)

    value = build_analysis_input(index, techniques_for_question("Q-MEDIA-01")[0])
    assessment = analyze_input(value).assessments[0]

    merged = next(item.scope for item in value.coverage if item.artifact_family == "windows.setupapi")
    assert merged["gap_count"] == 1
    assert assessment.outcome == "indeterminate"


def test_records_below_the_lowest_valid_usn_cannot_complete_a_window(tmp_path: Path) -> None:
    root = tmp_path / "kape-output"
    ext = root / "targets" / "F" / "$Extend"
    ext.mkdir(parents=True)
    (ext / "$J").write_bytes(b"public control identity fixture")
    (ext / "$Max").write_bytes(struct.pack("<QQQQ", 33554432, 8388608, 100, 99999999))
    collector = {"collector": "kape", "provenance": {}, "output_root": str(root)}

    scope = usn_adapters.usn_journal_scope(
        first_usn=8192, last_usn=16384, first_timestamp="2026-01-01 00:00:00",
        last_timestamp="2026-01-02 00:00:00", record_count=2, source_file="$J", collector_run=collector,
        journal_path=ext / "$J",
    )

    assert scope["window_validity"] == "all_records_below_lowest_valid_usn"
    assert scope["window_complete"] is False
    value = SimpleNamespace(coverage=[SimpleNamespace(artifact_family="ntfs.usn", scope=scope)])
    assert _usn_journal_window(value) is None
    index = evidence_index(
        _backdated_without_usn(r"C:\Users\alice\Desktop\time.txt"),
        families={"ntfs.mft", "ntfs.usn"},
        coverage_scopes={"ntfs_usn": scope},
    )
    assessment = analyze_input(build_analysis_input(index, techniques_for_question("Q-TIME-01")[0])).assessments[0]
    assert assessment.reason_code == "usn_coverage_unavailable"


def test_window_without_control_record_cannot_certify_absence() -> None:
    scope = usn_adapters.usn_journal_scope(
        first_usn=8192, last_usn=16384, first_timestamp="2026-01-01 00:00:00",
        last_timestamp="2026-01-02 00:00:00", record_count=2, source_file="$J",
        collector_run={"collector": "kape", "provenance": {}},
    )
    assert scope["window_validity"] == "retained_records_without_control_record"
    assert scope["window_complete"] is False
    value = SimpleNamespace(coverage=[SimpleNamespace(artifact_family="ntfs.usn", scope=scope)])
    assert _usn_journal_window(value) is None
    scope["window_complete"] = True
    assert _usn_journal_window(value) is None


def test_zeroed_control_record_cannot_certify_absence(tmp_path: Path) -> None:
    root = tmp_path / "kape-output"
    ext = root / "targets" / "F" / "$Extend"
    ext.mkdir(parents=True)
    (ext / "$J").write_bytes(b"public control identity fixture")
    (ext / "$Max").write_bytes(bytes(32))
    scope = usn_adapters.usn_journal_scope(
        first_usn=8192, last_usn=16384, first_timestamp="2026-01-01 00:00:00",
        last_timestamp="2026-01-02 00:00:00", record_count=2, source_file="$J",
        collector_run={"collector": "kape", "provenance": {}, "output_root": str(root)},
        journal_path=ext / "$J",
    )
    assert scope["window_validity"] == "invalid_control_record"
    assert scope["window_complete"] is False


def test_empty_csv_does_not_override_native_journal_control(tmp_path: Path) -> None:
    root = tmp_path / "kape-output"
    ext = root / "targets" / "F" / "$Extend"
    ext.mkdir(parents=True)
    (ext / "$J").write_bytes(b"public control identity fixture")
    (ext / "$Max").write_bytes(struct.pack("<QQQQ", 33554432, 8388608, 100, 0))
    collector = {"collector": "kape", "provenance": {}, "output_root": str(root)}
    empty = usn_adapters.usn_journal_scope(
        first_usn=None, last_usn=None, first_timestamp=None, last_timestamp=None,
        record_count=0, source_file="empty.csv", collector_run=collector,
    )
    native = usn_adapters.usn_journal_scope(
        first_usn=8192, last_usn=16384, first_timestamp="2026-01-01 00:00:00",
        last_timestamp="2026-01-02 00:00:00", record_count=2, source_file="$J",
        collector_run=collector, journal_path=ext / "$J",
    )
    native.update(order_checked=True, checked_record_count=2, timestamp_reversal_count=0)
    for first, second in ((empty, native), (native, empty)):
        merged = _merge_coverage_scopes(_merge_coverage_scopes(None, first), second)
        assert merged["window_complete"] is True
        assert merged["window_validity"] == "retained_records_within_valid_range"
        assert merged["record_count"] == 2
        value = SimpleNamespace(coverage=[SimpleNamespace(artifact_family="ntfs.usn", scope=merged)])
        assert _usn_journal_window(value) is not None
    unverified = dict(native, journal_id=None, window_validity="retained_records_without_control_record")
    merged = _merge_coverage_scopes(_merge_coverage_scopes(None, native), unverified)
    assert merged["window_complete"] is False


def test_legacy_completeness_without_a_validated_epoch_is_refused() -> None:
    scope = dict(kind="usn_journal", first_timestamp="2026-01-01 00:00:00",
                 last_timestamp="2026-01-02 00:00:00", first_usn=0, last_usn=100,
                 window_complete=True)
    value = SimpleNamespace(coverage=[SimpleNamespace(artifact_family="ntfs.usn", scope=scope)])
    assert _usn_journal_window(value) is None


def test_unknown_shellbag_csv_identity_without_a_hive_is_partial(tmp_path: Path) -> None:
    root = tmp_path / "kape-output"
    folder = root / "modules" / "FileFolderAccess"
    folder.mkdir(parents=True)
    csv = folder / "unrecognized.csv"
    csv.write_text(
        "BagPath,Slot,NodeSlot,MRUPosition,AbsolutePath,ShellType,Value,MFTEntry,MFTSequenceNumber\n"
        "BagMRU\\0,0,1,0,C:\\Users\\alice\\Gone\\,Directory,Gone,42,3\n"
    )
    collector = {"collector": "kape", "provenance": {}, "output_root": str(root)}

    run = registry_adapters.shellbag_parser_run(csv_path=csv, normalized_output_dir=tmp_path / "normalized", collector_run=collector)

    assert run["coverage_status"] == "partial"
    assert run["coverage_scope"]["hive_present"] is None


def test_a_historical_create_and_set_does_not_veto_a_later_stomp() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        usn=(
            ("usn_basic_info_change", "FILE_CREATE|BASIC_INFO_CHANGE|CLOSE", "2026-01-01T12:00:00.0000000Z"),
            ("usn_basic_info_change", "BASIC_INFO_CHANGE|CLOSE", "2026-01-01T12:05:00.0312500Z"),
        ),
        logfile=({},),
    )

    assessment = analyze_input(build_analysis_input(index, definition)).assessments[0]

    assert assessment.outcome == "supported"
    assert assessment.reason_code == "coordinated_si_backdating_with_temporal_basic_info_change"


def test_create_and_set_satisfies_indicator_without_proving_intent() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        fn_created="2026-01-01T12:05:00.0000000Z",
        record_changed="2026-01-01T12:05:00.0000000Z",
        usn=(("usn_basic_info_change", "FILE_CREATE|BASIC_INFO_CHANGE|CLOSE", "2026-01-01T12:05:00.0312500Z"),),
    )

    assessment = analyze_input(build_analysis_input(index, definition)).assessments[0]

    assert assessment.reason_code == "coordinated_si_backdating_with_temporal_basic_info_change"


def test_fn_mirrored_object_is_supported_by_the_logged_transition() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        fn_created="2010-01-01T12:00:00.0000000Z",
        usn=(),
        logfile=({"old_si_created": "2026-01-01T12:00:00.0000000Z", "old_si_modified": "2026-01-01T12:00:00.0000000Z"},),
    )
    for run in index["parser_runs"]:
        for row in run["observations"]:
            if row["artifact_family"] == "ntfs.mft":
                row["observation_type"] = "mft_file_record"
                row["fields"]["mismatch_count"] = 0
                row["fields"]["mismatches"] = []

    result = analyze_input(build_analysis_input(index, definition))
    assessment = result.assessments[0]

    assert assessment.outcome == "supported"
    assert assessment.reason_code == "coordinated_si_backdating_with_logged_si_transition"
    assert result.analyzer_metadata["support_routes"] == {
        assessment.subject_id: "logfile_si_transition",
    }
    assert any(note.startswith("si_fn_gate_not_met") for note in assessment.limitations)


def test_near_creation_logged_restoration_is_still_a_proven_transition() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        fn_created="2010-01-01T12:00:00.0000000Z",
        record_changed="2026-01-01T12:00:01.0000000Z",
        usn=(),
        logfile=(
            {
                "old_si_created": "2026-01-01T12:00:00.0000000Z",
                "old_si_modified": "2026-01-01T12:00:00.0000000Z",
                "new_si_record_changed": "2026-01-01T12:00:01.0000000Z",
            },
        ),
    )

    assessment = analyze_input(build_analysis_input(index, definition)).assessments[0]

    assert assessment.reason_code == "coordinated_si_backdating_with_logged_si_transition"


def test_logfile_transition_is_evaluable_without_the_usn_family() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(usn=(), logfile=({},))
    index["parser_runs"] = [run for run in index["parser_runs"] if run["parser_kind"] != "ntfs_usn"]

    value = build_analysis_input(index, definition)
    result = analyze_input(value)

    assert value.readiness == "ready"
    assert result.status != "insufficient_evidence"
    assert result.assessments[0].reason_code == "coordinated_si_backdating_with_logged_si_transition"


def test_missing_usn_alone_keeps_usn_based_conclusions_unavailable() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(usn=())
    index["parser_runs"] = [run for run in index["parser_runs"] if run["parser_kind"] != "ntfs_usn"]

    value = build_analysis_input(index, definition)

    assert value.readiness == "insufficient_evidence"


def test_reference_preparation_discovers_the_logfile_without_a_raw_journal(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "positive" / "kape-output"
    (root / "targets" / "F").mkdir(parents=True)
    logfile = root / "targets" / "F" / "$LogFile"
    logfile.write_bytes(b"public synthetic control")
    calls: list[dict[str, object]] = []

    def fake_reference_run(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {"parser_kind": "ntfs_logfile", "parser": "dfir_ntfs", "source_module": "$LogFile#reference-scope",
                "selection_scope": {"kind": "ntfs_file_references"}}

    import fmb.collection.analysis as module

    monkeypatch.setattr(module, "raw_logfile_reference_parser_run", fake_reference_run)
    monkeypatch.setattr(module, "build_mft_presence_context", lambda kape_root: {"mft_volume_id": "volume:test"})
    monkeypatch.setattr(module, "validate_payload", lambda payload, schema: None)
    index = {
        "parser_runs": [{"parser_kind": "ntfs_logfile", "raw_outputs": [{"path": str(logfile)}]}],
        "collector_runs": [{"collector": "kape"}],
        "candidate_populations": [
            {
                "question_id": "Q-TIME-01", "technique_id": "timestamp_manipulation", "coverage_status": "complete",
                "subjects": [{"identity": {"object_id": "ntfs:volume:test:42:3"}}],
            }
        ],
    }

    result = add_reference_scoped_usn(index, output_dir=tmp_path / "out")

    assert len(calls) == 1
    assert calls[0]["references"] == {(42, 3)}
    assert any(run.get("source_module") == "$LogFile#reference-scope" for run in result["parser_runs"])


def test_last_journal_record_is_decided_by_usn_order_not_by_clock() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        record_changed="2010-01-01T12:00:00.0000000Z",
        usn=(
            ("usn_basic_info_change", "BASIC_INFO_CHANGE|CLOSE", "2026-01-01T12:05:00.0000000Z"),
            ("usn_filesystem_activity", "DATA_OVERWRITE|CLOSE", "2026-01-01T12:04:00.0000000Z"),
        ),
    )

    assessment = analyze_input(build_analysis_input(index, definition)).assessments[0]

    assert assessment.outcome == "not_supported"
    assert assessment.reason_code == "temporal_basic_info_change_not_observed"


def test_records_without_usn_numbers_do_not_take_the_late_branch() -> None:
    definition = techniques_for_question("Q-TIME-01")[0]
    index = _timestomp_index(
        record_changed="2010-01-01T12:00:00.0000000Z",
        usn=(("usn_basic_info_change", "BASIC_INFO_CHANGE|CLOSE", "2026-01-01T12:05:00.0000000Z"),),
    )
    for run in index["parser_runs"]:
        for row in run["observations"]:
            row["fields"].pop("update_sequence_number", None)

    assessment = analyze_input(build_analysis_input(index, definition)).assessments[0]

    assert assessment.reason_code == "temporal_basic_info_change_not_observed"


def test_clock_reversal_in_the_journal_makes_the_window_unusable() -> None:
    scope = {
        "kind": "usn_journal", "first_usn": 0, "first_timestamp": "2000-01-01 00:00:00",
        "last_usn": 1_000_000, "last_timestamp": "2099-01-01 00:00:00", "window_complete": True,
        "timestamp_reversal_count": 1,
    }
    index = evidence_index(
        _backdated_without_usn(r"C:\Users\alice\Desktop\time.txt"),
        families={"ntfs.mft", "ntfs.usn"},
        coverage_scopes={"ntfs_usn": scope},
    )

    assessment = analyze_input(build_analysis_input(index, techniques_for_question("Q-TIME-01")[0])).assessments[0]

    assert assessment.reason_code == "usn_coverage_unavailable"


FAKE_PUBLISHER = '''import argparse, json, os
parser = argparse.ArgumentParser()
for flag in ("logfile", "output", "ops", "max-records"):
    parser.add_argument("--" + flag)
parser.add_argument("--usn-pages", action="store_true")
args = parser.parse_args()
document = {}
tmp = args.output + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(document, handle, separators=(",", ":"))
os.replace(tmp, args.output)
'''


def test_a_natural_driver_error_never_reaches_the_request_body(tmp_path: Path) -> None:
    env_root, driver = fake_environment(tmp_path / "locked-stub", driver_body=FAKE_PUBLISHER)
    lock = write_lock(tmp_path, env_root, driver)
    toolchain = LogFileToolchain.load(env_root=env_root, driver_path=driver, lock_path=lock)
    logfile = tmp_path / ".fmb" / "smoke" / "replay" / "20260912" / "pair15-positive" / "kape" / "targets" / "F" / "$LogFile"
    logfile.parent.mkdir(parents=True)
    logfile.write_bytes(b"public synthetic logfile bytes")
    normalized = tmp_path / ".fmb" / "smoke" / "replay" / "20260912" / "pair15-positive" / "parser-normalized"
    parser_output_adapters.normalized_output_path(normalized, logfile, logfile_adapters.LOGFILE_DRIVER_DOCUMENT_SUFFIX).mkdir(parents=True)

    def run_actual(path: Path, *, output_path: Path, operations: tuple[str, ...]) -> dict[str, object]:
        return run_logfile_driver(path, output_path=output_path, operations=operations, toolchain=toolchain, timeout_seconds=30)

    with patch.object(logfile_adapters, "logfile_runtime_availability", side_effect=lambda: logfile_runtime_availability(toolchain)), patch.object(logfile_adapters, "run_logfile_driver", side_effect=run_actual):
        parser_run = logfile_adapters.raw_logfile_parser_run(logfile_path=logfile, normalized_output_dir=normalized, collector_run={"collector": "kape"})

    assert parser_run["coverage_scope"]["reason"] == "dfir_ntfs_driver_failed"
    local = json.loads(Path(parser_run["normalized_output"]["path"]).read_text(encoding="utf-8"))
    assert str(tmp_path) in local["local_diagnostics"]["availability_detail"]
    index = _timestomp_index()
    index["parser_runs"].append(parser_run)
    value = build_analysis_input(index, techniques_for_question("Q-TIME-01")[0])
    packet = projected_input(value)
    text = json.dumps(packet)
    assert str(tmp_path) not in text
    assert "pair15-positive" not in text
    assert blinding_violations(packet) == []
    assert blinding_violations(packet) == []


def test_request_planning_refuses_a_packet_with_host_or_case_identifiers() -> None:
    index = _timestomp_index()
    for run in index["parser_runs"]:
        for row in run["observations"]:
            if row["artifact_family"] == "ntfs.usn":
                row["fields"]["reconstructed_path"] = "/Users/analyst/.fmb/smoke/replay/pair15-positive/$J"
    value = build_analysis_input(index, techniques_for_question("Q-TIME-01")[0])
    packet = projected_input(value)

    assert blinding_violations(packet)


def _public_usn_bytes() -> bytes:
    from test_index_parsers_core import NTFS_2020_UTC, usn_v2_record

    result = bytearray()
    for number in range(2):
        record = bytearray(usn_v2_record("public.txt", reason=0x100,
                                       timestamp=NTFS_2020_UTC + number * 10_000_000))
        struct.pack_into("<q", record, 24, 8192 + len(result))
        result.extend(record)
    return bytes(result)


def _public_usn_collector(tmp_path: Path, *, control_volume: str = "F") -> tuple[dict, Path]:
    root = tmp_path / "kape-output"
    journal = root / "targets/F/$Extend/$J"
    journal.parent.mkdir(parents=True)
    journal.write_bytes(_public_usn_bytes())
    control = root / f"targets/{control_volume}/$Extend/$Max"
    control.parent.mkdir(parents=True, exist_ok=True)
    control.write_bytes(struct.pack("<QQQQ", 33554432, 8388608, 123456, 0))
    return {"collector": "kape", "provenance": {}, "output_root": str(root)}, journal


def _public_usn_csv(tmp_path: Path, rows: list[tuple[int, str, str]], *, control_volume: str = "F") -> dict:
    collector, _ = _public_usn_collector(tmp_path, control_volume=control_volume)
    csv = Path(collector["output_root"]) / "modules/FileSystem/MFTECmd_$J_Output.csv"
    csv.parent.mkdir(parents=True)
    csv.write_text("Name,EntryNumber,SequenceNumber,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons,SourceFile\n" +
                   "".join(f"public.txt,42,3,{usn},{stamp},BasicInfoChange,{source}\n" for usn, stamp, source in rows))
    return usn_adapters.mftecmd_usn_parser_run(csv_path=csv, normalized_output_dir=tmp_path / "normalized", collector_run=collector)


def _window_from_scope(scope: dict):
    return _usn_journal_window(SimpleNamespace(coverage=[SimpleNamespace(artifact_family="ntfs.usn", scope=scope)]))


def test_raw_journal_cannot_inherit_another_volume_control(tmp_path: Path) -> None:
    collector, journal = _public_usn_collector(tmp_path, control_volume="G")
    scope = usn_adapters.raw_usn_journal_scope(journal, collector_run=collector)
    assert scope["window_validity"] == "retained_records_without_control_record"
    assert scope["order_checked"] is True and scope["checked_record_count"] == 2
    assert _window_from_scope(scope) is None
    assert scope["first_usn"] == 8192 and scope["last_usn"] > 8192


def test_same_volume_control_and_full_raw_order_are_required(tmp_path: Path) -> None:
    collector, journal = _public_usn_collector(tmp_path)
    scope = usn_adapters.raw_usn_journal_scope(journal, collector_run=collector)
    assert scope["control_identity_bound"] is True
    assert scope["journal_source"] == "targets/F/$Extend/$J"
    assert scope["max_record_source"] == "targets/F/$Extend/$Max"
    assert _window_from_scope(scope) is not None
    assert _window_from_scope(dict(scope, order_checked=False)) is None
    assert _window_from_scope(dict(scope, checked_record_count=0)) is None
    assert _window_from_scope(dict(scope, timestamp_reversal_count=None)) is None
    other = dict(scope, journal_source="targets/G/$Extend/$J")
    assert _window_from_scope(_merge_coverage_scopes(_merge_coverage_scopes(None, scope), other)) is None


@pytest.mark.parametrize("reversal", [False, True])
def test_csv_checks_every_timestamp_in_native_usn_order(tmp_path: Path, reversal: bool) -> None:
    source = r"C:\FMB-Appliance\bundle\kape-output\targets\F\$Extend\$J"
    rows = [(8192, "2026-01-01 12:00:00.0000000", source),
            (16384, "2026-01-02 12:00:00.0000000", source),
            (12288, "2025-12-01 12:00:00.0000000" if reversal else "2026-01-01 18:00:00.0000000", source)]
    run = _public_usn_csv(tmp_path, rows)
    scope = run["coverage_scope"]
    assert len(run["observations"]) == 3
    assert scope["order_checked"] is True and scope["checked_record_count"] == 3
    assert scope["timestamp_reversal_count"] == int(reversal)
    assert (_window_from_scope(scope) is None) is reversal


@pytest.mark.parametrize("source", ["", r"C:\FMB-Appliance\bundle\kape-output\targets\G\$Extend\$J",
                                     r"C:\FMB-Appliance\bundle\kape-output\targets\F\..\F\$Extend\$J"])
def test_csv_without_exact_retained_journal_identity_stays_unverified(tmp_path: Path, source: str) -> None:
    run = _public_usn_csv(tmp_path, [(8192, "2026-01-01 12:00:00.0000000", source),
                                   (16384, "2026-01-02 12:00:00.0000000", source)])
    assert len(run["observations"]) == 2
    assert run["coverage_scope"]["window_complete"] is False
    assert _window_from_scope(run["coverage_scope"]) is None


@pytest.mark.parametrize("defect", ["malformed_time", "conflicting_duplicate", "cap"])
def test_csv_unknown_order_never_certifies_absence(tmp_path: Path, monkeypatch, defect: str) -> None:
    source = r"C:\FMB-Appliance\bundle\kape-output\targets\F\$Extend\$J"
    rows = [(8192, "2026-01-01 12:00:00.0000000", source),
            (16384, "2026-01-02 12:00:00.0000000", source)]
    if defect == "malformed_time":
        rows.insert(1, (12288, "unparseable", source))
    elif defect == "conflicting_duplicate":
        rows.insert(1, (8192, "2025-12-01 12:00:00.0000000", source))
    else:
        monkeypatch.setattr(usn_adapters, "MAX_USN_ORDER_RECORDS", 1)
    scope = _public_usn_csv(tmp_path, rows)["coverage_scope"]
    assert scope["order_checked"] is False
    assert _window_from_scope(scope) is None


def test_unknown_order_interval_cannot_borrow_another_sources_proof(tmp_path: Path) -> None:
    collector, journal = _public_usn_collector(tmp_path)
    complete = usn_adapters.raw_usn_journal_scope(journal, collector_run=collector)
    unknown = dict(complete, source_file="unknown.csv", order_checked=False)
    for first, second in ((complete, unknown), (unknown, complete)):
        merged = _merge_coverage_scopes(_merge_coverage_scopes(None, first), second)
        assert merged["order_checked"] is False
        assert _window_from_scope(merged) is None


def _clock_step_usn_surface(tmp_path: Path, *, active_reversal: bool = False):
    from test_index_parsers_core import usn_v2_record
    from fmb.index.support.windows_artifacts import parse_csv_timestamp

    collector, journal = _public_usn_collector(tmp_path)
    stamps = ["2026-09-12T11:00:00.0000000Z", "2026-09-12T22:00:00.0000000Z",
              "2026-09-12T12:00:00.0000000Z",
              "2026-09-12T11:55:00.0000000Z" if active_reversal else "2026-09-12T12:05:00.0000000Z",
              "2026-09-12T12:10:00.0000000Z"]
    data = bytearray()
    rows = []
    for stamp in stamps:
        usn = 8192 + len(data)
        record = bytearray(usn_v2_record("public.txt", reason=0x8000,
                                       timestamp=(parse_csv_timestamp(stamp).ticks_100ns
                                                  - parse_csv_timestamp("1601-01-01T00:00:00Z").ticks_100ns)))
        struct.pack_into("<q", record, 24, usn)
        data.extend(record)
        rows.append((usn, stamp))
    journal.write_bytes(data)
    csv = Path(collector["output_root"]) / "modules/FileSystem/MFTECmd_$J_Output.csv"
    csv.parent.mkdir(parents=True)
    source = r"C:\FMB-Appliance\bundle\kape-output\targets\F\$Extend\$J"
    csv.write_text("Name,EntryNumber,SequenceNumber,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons,SourceFile\n" +
                   "".join(f"public.txt,42,3,{usn},{stamp},BasicInfoChange,{source}\n" for usn, stamp in rows))
    return collector, journal, csv, rows[2][0]


@pytest.mark.parametrize("active_reversal", [False, True])
def test_raw_and_csv_order_use_the_verified_valid_interval_without_dropping_observations(
    tmp_path: Path, active_reversal: bool,
) -> None:
    collector, journal, csv, minimum = _clock_step_usn_surface(tmp_path, active_reversal=active_reversal)
    before = usn_adapters.mftecmd_usn_parser_run(csv_path=csv, normalized_output_dir=tmp_path / "before", collector_run=collector)
    assert before["coverage_scope"]["timestamp_reversal_count"] == 1 + int(active_reversal)
    (journal.parent / "$Max").write_bytes(struct.pack("<QQQQ", 33554432, 8388608, 123456, minimum))
    after = usn_adapters.mftecmd_usn_parser_run(csv_path=csv, normalized_output_dir=tmp_path / "after", collector_run=collector)
    raw = usn_adapters.raw_usn_journal_scope(journal, collector_run=collector)
    assert after["observations"] == before["observations"] and len(after["observations"]) == 5
    for scope in (raw, after["coverage_scope"]):
        assert scope["control_identity_bound"] is True
        assert scope["first_usn"] == minimum
        assert windows_artifacts.parse_csv_timestamp(scope["first_timestamp"]) == windows_artifacts.parse_csv_timestamp("2026-09-12T12:00:00Z")
        assert scope["checked_record_count"] == 3
        assert scope["stale_head_record_count"] == 2
        assert scope["timestamp_reversal_count"] == int(active_reversal)
        assert (_window_from_scope(scope) is None) is active_reversal
    merged = _merge_coverage_scopes(_merge_coverage_scopes(None, raw), after["coverage_scope"])
    assert (_window_from_scope(merged) is None) is active_reversal


@pytest.mark.parametrize("control_defect", ["missing", "zero_identity", "wrong_volume", "past_all_records"])
def test_chronology_never_borrows_an_unverified_minimum_or_invents_valid_records(
    tmp_path: Path, control_defect: str,
) -> None:
    collector, journal, csv, minimum = _clock_step_usn_surface(tmp_path)
    control = journal.parent / "$Max"
    control.write_bytes(struct.pack("<QQQQ", 33554432, 8388608, 123456, minimum))
    if control_defect == "missing":
        control.unlink()
    elif control_defect == "zero_identity":
        control.write_bytes(struct.pack("<QQQQ", 33554432, 8388608, 0, minimum))
    elif control_defect == "wrong_volume":
        wrong = Path(collector["output_root"]) / "targets/G/$Extend/$Max"
        wrong.parent.mkdir(parents=True)
        control.rename(wrong)
    else:
        control.write_bytes(struct.pack("<QQQQ", 33554432, 8388608, 123456, 999999))
    run = usn_adapters.mftecmd_usn_parser_run(csv_path=csv, normalized_output_dir=tmp_path / "parsed", collector_run=collector)
    assert len(run["observations"]) == 5
    for scope in (usn_adapters.raw_usn_journal_scope(journal, collector_run=collector), run["coverage_scope"]):
        assert _window_from_scope(scope) is None
        if control_defect == "past_all_records":
            assert scope["checked_record_count"] == 0 and scope["first_usn"] is None
        else:
            assert scope["checked_record_count"] == 5 and scope["timestamp_reversal_count"] == 1


@pytest.mark.parametrize("parse_defect", ["malformed_stale_timestamp", "record_cap"])
def test_verified_minimum_does_not_repair_incomplete_csv_order(
    tmp_path: Path, monkeypatch, parse_defect: str,
) -> None:
    collector, journal, csv, minimum = _clock_step_usn_surface(tmp_path)
    (journal.parent / "$Max").write_bytes(struct.pack("<QQQQ", 33554432, 8388608, 123456, minimum))
    if parse_defect == "malformed_stale_timestamp":
        csv.write_text(csv.read_text().replace("2026-09-12T22:00:00.0000000Z", "unparseable"))
    else:
        monkeypatch.setattr(usn_adapters, "MAX_USN_ORDER_RECORDS", 4)
    run = usn_adapters.mftecmd_usn_parser_run(csv_path=csv, normalized_output_dir=tmp_path / "parsed", collector_run=collector)
    assert len(run["observations"]) == 5
    assert run["coverage_scope"]["order_checked"] is False
    assert _window_from_scope(run["coverage_scope"]) is None
