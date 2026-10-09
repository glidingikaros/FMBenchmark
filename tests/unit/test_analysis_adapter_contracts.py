from __future__ import annotations

import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fmb.analysis.catalog import techniques_for_question
from fmb.analysis.inputs import build_analysis_input
from fmb.index.adapters import file_content
from fmb.index.adapters import execution as execution_adapters
from fmb.index.adapters import registry as registry_adapters
from fmb.index.adapters import usn as usn_adapters
from fmb.index.adapters.event_log import evtxecmd_parser_run
from fmb.index.adapters.execution import (
    pecmd_csv_files,
    pecmd_prefetch_parser_run,
    registry_path_parser_run,
)
from fmb.index.adapters.logfile import logfile_parser_run
from fmb.index.adapters.mft import (
    build_mft_presence_context,
    mft_active_presence_fields,
    mftecmd_mft_parser_run,
)
from fmb.index.adapters.ntfs_files import (
    mftecmd_ads_parser_run,
    mftecmd_ads_reference_parser_run,
    mftecmd_size_parser_run,
    q_file_parser_runs,
)
from fmb.index.adapters.parser_output import source_scope_id
from fmb.index.adapters.registry import (
    registry_mru_csv_files,
    shellbag_csv_files,
    setupapi_parser_run,
    typed_paths_parser_run,
    usbstor_csv_files,
    usbstor_parser_run,
)
from fmb.index.adapters.usn import mftecmd_usn_parser_run
from fmb.index.kape.sources import scan_kape_output_root
from fmb.index.scanners import usn


def registry_filetime(value: datetime) -> str:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    ticks = (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10
    return "-".join(f"{byte:02X}" for byte in ticks.to_bytes(8, "little"))


def utf16le(text: str) -> bytes:
    return text.encode("utf-16le")


EVTX_FILE_SIGNATURE = b"ElfFile\x00"
EVTX_CHUNK_SIGNATURE = b"ElfChnk\x00"
EVTX_RECORD_SIGNATURE = b"\x2a\x2a\x00\x00"
EVTX_CHUNK_SIZE = 65536
EVTX_CHUNK_RECORD_START = 512


def security_evtx_bytes(*, event_id: int = 1102, record_id: int = 77) -> bytes:
    payload = b"\x00\x00".join(
        [
            utf16le("Microsoft-Windows-Eventlog"),
            utf16le("EventID")
            + struct.pack("<I", event_id)
            + b"\x00\x00\x00\x00"
            + utf16le("Version"),
            utf16le("Channel"),
            utf16le("Security"),
        ]
    )
    record_size = 24 + len(payload) + 4
    record_size += (-record_size) % 8
    frame = bytearray(record_size)
    frame[:4] = EVTX_RECORD_SIGNATURE
    struct.pack_into("<IQQ", frame, 4, record_size, record_id, 132223104000000000)
    frame[24 : 24 + len(payload)] = payload
    struct.pack_into("<I", frame, record_size - 4, record_size)
    data = bytearray(4096 + EVTX_CHUNK_SIZE)
    data[: len(EVTX_FILE_SIGNATURE)] = EVTX_FILE_SIGNATURE
    struct.pack_into("<QQQ", data, 8, 0, 0, record_id + 1)
    struct.pack_into("<IHHHI", data, 32, 128, 1, 3, 4096, 1)
    struct.pack_into("<I", data, 124, zlib.crc32(bytes(data[:120])))
    chunk = memoryview(data)[4096:]
    chunk[: len(EVTX_CHUNK_SIGNATURE)] = EVTX_CHUNK_SIGNATURE
    struct.pack_into("<QQQQ", chunk, 8, record_id, record_id, record_id, record_id)
    struct.pack_into("<I", chunk, 40, 128)
    start = EVTX_CHUNK_RECORD_START
    chunk[start : start + record_size] = frame
    struct.pack_into(
        "<III", chunk, 44, start, start + record_size,
        zlib.crc32(bytes(chunk[start : start + record_size])),
    )
    struct.pack_into(
        "<I", chunk, 124, zlib.crc32(bytes(chunk[:120]) + bytes(chunk[128:512]))
    )
    return bytes(data)


def test_exact_mft_reference_takes_precedence_over_reused_path() -> None:
    fields = mft_active_presence_fields(
        subject=r"C:\Users\alice\Desktop\reused.txt",
        file_reference=(42, 3),
        mft_context={
            "row_count": 2,
            "active_full_paths": {r"users\alice\desktop\reused.txt"},
            "active_refs": {(42, 4)},
        },
    )

    assert fields["mft_active_path_match"] is True
    assert fields["mft_active_reference_match"] is False
    assert fields["mft_active_presence_status"] == "active_mft_absent"


def test_mft_context_does_not_claim_absence_on_an_unindexed_volume() -> None:
    fields = mft_active_presence_fields(
        subject=r"D:\Users\alice\missing.txt",
        file_reference=None,
        mft_context={
            "row_count": 2,
            "active_full_paths": {r"users\alice\present.txt"},
            "active_refs": {(42, 4)},
            "indexed_volumes": {"c"},
        },
    )

    assert fields["mft_active_presence_check_supported"] is False
    assert fields["mft_active_presence_status"] == "active_mft_absence_undecidable"

    referenced_fields = mft_active_presence_fields(
        subject=r"D:\Users\alice\missing.txt",
        file_reference=(42, 3),
        mft_context={
            "row_count": 2,
            "active_full_paths": {r"users\alice\present.txt"},
            "active_refs": {(42, 4)},
            "entry_sequences": {42: (4, True)},
            "indexed_volumes": {"c"},
        },
    )

    assert referenced_fields["mft_active_presence_check_supported"] is False
    assert (
        referenced_fields["mft_active_presence_status"]
        == "active_mft_absence_undecidable"
    )


def test_mft_context_does_not_claim_absence_when_any_row_lacks_identity(
    tmp_path: Path,
) -> None:
    root = tmp_path / "kape"
    root.mkdir()
    (root / "MFTECmd_Output.csv").write_text(
        "FullPath,EntryNumber,SequenceNumber,InUse\n"
        "C:\\Users\\alice\\present.txt,41,3,true\n"
        "C:\\Users\\alice\\malformed.txt,42,,false\n",
        encoding="utf-8",
    )

    context = build_mft_presence_context(root)
    fields = mft_active_presence_fields(
        subject=r"C:\Users\alice\missing.txt",
        file_reference=(99, 3),
        mft_context=context,
    )

    assert context["absence_check_supported"] is False
    assert context["malformed_identity_row_count"] == 1
    assert fields["mft_active_presence_check_supported"] is False
    assert fields["mft_active_presence_status"] == "active_mft_absence_undecidable"
    assert fields["mft_active_presence_basis"] == "incomplete_mft_reference_surface"


def test_single_mft_source_can_bind_root_relative_paths_to_the_system_volume(
    tmp_path: Path,
) -> None:
    root = tmp_path / "kape"
    root.mkdir()
    (root / "MFTECmd_Output.csv").write_text(
        "FullPath,EntryNumber,SequenceNumber,InUse\n"
        r".\Users\alice\present.txt,41,3,true"
        "\n",
        encoding="utf-8",
    )

    context = build_mft_presence_context(root)
    fields = mft_active_presence_fields(
        subject=r"C:\Users\alice\missing.txt",
        file_reference=(99, 3),
        mft_context=context,
    )

    assert context["absence_check_supported"] is True
    assert fields["mft_active_presence_check_supported"] is True
    assert fields["mft_active_presence_status"] == "active_mft_absent"


def test_mft_reference_and_path_absence_use_their_own_completeness_proofs(
    tmp_path: Path,
) -> None:
    root = tmp_path / "kape"
    root.mkdir()
    (root / "MFTECmd_Output.csv").write_text(
        "FullPath,EntryNumber,SequenceNumber,InUse\n"
        "C:\\Users\\alice\\present.txt,41,3,true\n"
        ",42,3,false\n",
        encoding="utf-8",
    )

    context = build_mft_presence_context(root)
    exact = mft_active_presence_fields(
        subject=r"C:\Users\alice\gone.txt",
        file_reference=(99, 3),
        mft_context=context,
    )
    path_only = mft_active_presence_fields(
        subject=r"C:\Users\alice\gone.txt",
        file_reference=None,
        mft_context=context,
    )

    assert context["reference_absence_check_supported"] is True
    assert context["path_absence_check_supported"] is False
    assert exact["mft_active_presence_status"] == "active_mft_absent"
    assert exact["mft_active_presence_check_supported"] is True
    assert path_only["mft_active_presence_status"] == ("active_mft_absence_undecidable")
    assert path_only["mft_active_presence_check_supported"] is False


def test_mft_conflicting_entry_states_are_ambiguous_in_every_row_order(
    tmp_path: Path,
) -> None:
    results = []
    rows = (
        r"C:\Users\alice\old.txt,42,3,false",
        r"C:\Users\alice\current.txt,42,4,true",
    )
    for case_name, ordered_rows in (("forward", rows), ("reverse", rows[::-1])):
        root = tmp_path / case_name
        root.mkdir()
        (root / "MFTECmd_Output.csv").write_text(
            "FullPath,EntryNumber,SequenceNumber,InUse\n"
            + "\n".join(ordered_rows)
            + "\n",
            encoding="utf-8",
        )
        context = build_mft_presence_context(root)
        fields = mft_active_presence_fields(
            subject=r"C:\Users\alice\old.txt",
            file_reference=(42, 3),
            mft_context=context,
        )
        results.append((context, fields))

    for context, fields in results:
        assert context["ambiguous_entries"] == {42}
        assert 42 not in context["entry_sequences"]
        assert context["absence_check_supported"] is False
        assert fields["mft_active_presence_status"] == "active_mft_absence_undecidable"
        assert fields["mft_active_presence_check_supported"] is False
        assert fields["mft_active_presence_basis"] == "ambiguous_mft_entry"


def test_prefetch_basename_is_checked_against_live_mft_basenames() -> None:
    fields = mft_active_presence_fields(
        subject="RUNNER.EXE",
        file_reference=None,
        mft_context={
            "row_count": 2,
            "active_full_paths": {r"users\alice\downloads\runner.exe"},
            "active_basenames": {"runner.exe"},
            "active_refs": {(42, 4)},
            "indexed_volumes": {"c"},
        },
    )

    assert fields["mft_active_presence_check_supported"] is True
    assert fields["mft_active_presence_status"] == "active_mft_present"
    assert fields["mft_active_presence_basis"] == "basename_volume_search"


def test_pecmd_discovery_excludes_timeline_derivatives(tmp_path: Path) -> None:
    primary = tmp_path / "PECmd_Output.csv"
    timeline = tmp_path / "PECmd_Output_Timeline.csv"
    primary.write_text("ExecutableName\nRUNNER.EXE\n", encoding="utf-8")
    timeline.write_text(
        "RunTime,ExecutableName\n2026-01-01T00:00:00Z,RUNNER.EXE\n",
        encoding="utf-8",
    )

    assert pecmd_csv_files(tmp_path) == [primary]


def test_csv_discovery_ignores_tool_names_above_the_output_root(tmp_path: Path) -> None:
    root = tmp_path / "sbecmd-shellbag-mru" / "kape-output"
    shellbags = root / "modules" / "FileFolderAccess" / "vagrant_UsrClass.csv"
    typed = root / "modules" / "Registry" / "20260828090000_RECmd_Batch_Kroll_Batch_Output.csv"
    prefetch = root / "modules" / "ProgramExecution" / "20260828090000_PECmd_Output.csv"
    for path, header in (
        (shellbags, "AbsolutePath,BagPath,ShellType\n"),
        (typed, "HivePath,KeyPath,ValueName,ValueData\n"),
        (prefetch, "ExecutableName\n"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(header, encoding="utf-8")

    assert shellbag_csv_files(root) == [shellbags]
    assert registry_mru_csv_files(root) == [typed]
    assert pecmd_csv_files(root) == [prefetch]


def test_prefetch_subject_id_is_stable_across_pf_source_paths(tmp_path: Path) -> None:
    subjects = []
    for case_name, source_file in (
        ("first", r"C:\Windows\Prefetch\RUNNER.EXE-AAAA1111.pf"),
        ("second", r"D:\Recovered\RUNNER.EXE-BBBB2222.pf"),
    ):
        case_root = tmp_path / case_name
        case_root.mkdir()
        csv_path = case_root / "pecmd.csv"
        csv_path.write_text(
            f"ExecutableName,SourceFile\nRUNNER.EXE,{source_file}\n",
            encoding="utf-8",
        )
        normalized = case_root / "normalized"
        normalized.mkdir()
        prefetch_run = pecmd_prefetch_parser_run(
            csv_path=csv_path,
            normalized_output_dir=normalized,
            collector_run={"collector": "kape", "provenance": {}},
        )
        analysis_input = build_analysis_input(
            {
                "schema_version": "evidence_index.v1",
                "run_id": f"prefetch-{case_name}",
                "parser_runs": [
                    prefetch_run,
                    {
                        "parser_kind": "ntfs_mft",
                        "status": "consumed",
                        "coverage_status": "complete",
                        "observations": [],
                    },
                ],
            },
            techniques_for_question("Q-EXEC-01")[0],
        )
        subjects.append(analysis_input.candidate_roster.subjects[0])

    assert subjects[0].subject_id == subjects[1].subject_id
    assert (
        subjects[0].identity == subjects[1].identity == {"canonical_name": "runner.exe"}
    )


def test_prefetch_uses_exact_referenced_executable_paths_when_available(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "pecmd.csv"
    csv_path.write_text(
        "ExecutableName,SourceFile,FilesLoaded\n"
        "RUNNER.EXE,C:\\Windows\\Prefetch\\RUNNER-AAAA.pf,"
        "C:\\Tools\\RUNNER.EXE|C:\\Windows\\System32\\ntdll.dll\n"
        "RUNNER.EXE,C:\\Windows\\Prefetch\\RUNNER-BBBB.pf,"
        "D:\\Portable\\RUNNER.EXE|C:\\Windows\\System32\\ntdll.dll\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = pecmd_prefetch_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        mft_context={"row_count": 0},
    )

    assert [item["subject_ref"] for item in run["observations"]] == [
        r"C:\Tools\RUNNER.EXE",
        r"D:\Portable\RUNNER.EXE",
    ]
    assert all(
        item["fields"]["executable_identity_basis"] == "referenced_executable_path"
        for item in run["observations"]
    )


def test_prefetch_uses_comma_separated_referenced_executable_path(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "pecmd.csv"
    csv_path.write_text(
        "ExecutableName,SourceFile,FilesLoaded\n"
        'RUNNER.EXE,C:\\Windows\\Prefetch\\RUNNER-AAAA.pf,"'
        "C:\\Windows\\System32\\ntdll.dll, C:\\Tools\\RUNNER.EXE, "
        'C:\\Windows\\System32\\kernel32.dll"\n',
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = pecmd_prefetch_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        mft_context={"row_count": 0},
    )

    observation = run["observations"][0]
    assert observation["subject_ref"] == r"C:\Tools\RUNNER.EXE"
    assert observation["fields"]["executable_identity_basis"] == (
        "referenced_executable_path"
    )


def test_prefetch_uses_an_explicit_executable_path_without_a_basename_column(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "pecmd.csv"
    csv_path.write_text(
        "ExecutablePath,SourceFile\n"
        "C:\\Tools\\RUNNER.EXE,C:\\Windows\\Prefetch\\RUNNER-AAAA.pf\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = pecmd_prefetch_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        mft_context={"row_count": 0},
    )

    assert run["observations"][0]["subject_ref"] == r"C:\Tools\RUNNER.EXE"
    assert run["observations"][0]["fields"]["executable_identity_basis"] == (
        "referenced_executable_path"
    )


def test_prefetch_candidates_are_bounded_and_truncation_is_partial(
    tmp_path: Path, monkeypatch
) -> None:
    csv_path = tmp_path / "pecmd.csv"
    csv_path.write_text(
        "ExecutableName,SourceFile\n"
        "ONE.EXE,C:\\Windows\\Prefetch\\ONE-AAAA.pf\n"
        "TWO.EXE,C:\\Windows\\Prefetch\\TWO-BBBB.pf\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    monkeypatch.setattr(
        'fmb.index.adapters.execution.MAX_PECMD_PREFETCH_OBSERVATIONS', 1
    )

    run = pecmd_prefetch_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        mft_context={"row_count": 0},
    )

    assert len(run["observations"]) == 1
    assert run["coverage_status"] == "partial"


def test_usn_row_without_an_exact_reference_cannot_use_path_absence(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "usn.csv"
    csv_path.write_text(
        "FullPath,Name,UpdateReasons,EntryNumber,SequenceNumber\n"
        r"C:\Users\alice\gone.txt,gone.txt,FileDelete,not-an-entry,3"
        "\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_usn_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        mft_context={
            "row_count": 1,
            "absence_check_supported": True,
            "active_full_paths": {r"users\alice\present.txt"},
            "active_basenames": {"present.txt"},
            "active_refs": {(41, 3)},
            "entry_sequences": {41: (3, True)},
            "indexed_volumes": {"c"},
        },
    )

    fields = run["observations"][0]["fields"]
    assert run["coverage_status"] == "partial"
    assert fields["file_reference_entry"] is None
    assert fields["mft_active_presence_check_supported"] is False
    assert fields["mft_active_presence_status"] == "active_mft_absence_undecidable"
    assert fields["mft_active_presence_basis"] == "exact_reference_unavailable"


def test_mft_population_keeps_mismatches_beyond_5000_but_requires_raw_validation(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "mft.csv"
    matching_timestamps = ",".join(["2024-01-01 00:00:00"] * 8)
    rows = [
        (
            "FullPath,EntryNumber,SequenceNumber,Created0x10,Created0x30,"
            "LastModified0x10,LastModified0x30,LastRecordChange0x10,"
            "LastRecordChange0x30,LastAccess0x10,LastAccess0x30"
        ),
        *(
            f"C:\\Windows\\System32\\ordinary-{index}.dll,{index},3,"
            f"{matching_timestamps}"
            for index in range(1, 5002)
        ),
        (
            "C:\\Users\\alice\\candidate.docx,6000,3,"
                "2020-01-01 00:00:00,"
                "2024-01-01 00:00:00,2024-01-01 00:00:00,"
                "2024-01-01 00:00:00,2024-01-01 00:00:00,"
                "2024-01-01 00:00:00,2024-01-01 00:00:00,"
                "2024-01-01 00:00:00"
            ),
    ]
    csv_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_mft_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert run["coverage_status"] == "complete"
    population = run["candidate_populations"][0]
    assert population["coverage_status"] == "complete"
    assert [item["subject_ref"] for item in population["subjects"]] == [
        r"C:\Users\alice\candidate.docx"
    ]
    parser_run = {
        key: value for key, value in run.items() if key != "candidate_populations"
    }
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "complete-production-population",
            "parser_runs": [
                parser_run,
                {
                    "parser_kind": "ntfs_usn",
                    "status": "consumed",
                    "observations": [],
                },
            ],
            "candidate_populations": [population],
        },
        techniques_for_question("Q-TIME-01")[0],
    )
    assert analysis_input.readiness == "insufficient_evidence"
    assert len(analysis_input.candidate_roster.subjects) == 1


def test_mft_adapter_keeps_bounded_file_identities_separate_from_mismatches(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text(
        "FullPath,EntryNumber,SequenceNumber,InUse,IsDirectory,Created0x10,"
        "Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,"
        "LastRecordChange0x30,LastAccess0x10,LastAccess0x30\n"
        "C:\\Users\\alice\\comparison.txt,42,3,True,False,"
        "2026-01-01 00:00:00,,2026-01-01 00:00:00,,"
        "2026-01-01 00:00:00,,2026-01-01 00:00:00,\n"
        "C:\\Users\\alice\\mismatch.txt,43,4,True,False,"
        "2020-01-01 00:00:00,2024-01-01 00:00:00,"
        "2020-01-01 00:00:00,2024-01-01 00:00:00,"
        "2026-01-01 00:00:00,2026-01-01 00:00:00,"
        "2020-01-01 00:00:00,2024-01-01 00:00:00\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_mft_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    identities = [
        item
        for item in run["observations"]
        if item["observation_type"] == "mft_file_record"
    ]
    mismatches = [
        item
        for item in run["observations"]
        if item["observation_type"] == "si_fn_timestamp_difference"
    ]
    assert {item["subject_ref"] for item in identities} == {
        r"C:\Users\alice\comparison.txt",
        r"C:\Users\alice\mismatch.txt",
    }
    assert [item["subject_ref"] for item in mismatches] == [
        r"C:\Users\alice\mismatch.txt"
    ]
    assert all(item["fields"]["record_changed_si"].endswith("Z") for item in identities)
    identities_by_subject = {item["subject_ref"]: item for item in identities}
    comparison_fields = identities_by_subject[r"C:\Users\alice\comparison.txt"][
        "fields"
    ]
    assert {
        key: comparison_fields[key]
        for key in (
            "si_created",
            "si_modified",
            "si_record_changed",
            "si_accessed",
            "fn_created",
            "fn_modified",
            "fn_record_changed",
            "fn_accessed",
        )
    } == {
        "si_created": "2026-01-01T00:00:00Z",
        "si_modified": "2026-01-01T00:00:00Z",
        "si_record_changed": "2026-01-01T00:00:00Z",
        "si_accessed": "2026-01-01T00:00:00Z",
        "fn_created": "",
        "fn_modified": "",
        "fn_record_changed": "",
        "fn_accessed": "",
    }
    assert all(
        pair["standard_information"].endswith("Z") and pair["file_name"].endswith("Z")
        for pair in mismatches[0]["fields"]["mismatches"]
    )
    population = run["candidate_populations"][0]
    assert [item["subject_ref"] for item in population["subjects"]] == [
        r"C:\Users\alice\mismatch.txt"
    ]


def test_mft_adapter_recovers_sparse_timestamps_from_the_same_raw_record(
    tmp_path: Path, monkeypatch
) -> None:
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text(
        "FullPath,FileName,EntryNumber,SequenceNumber,ParentEntryNumber,"
        "ParentSequenceNumber,InUse,IsDirectory,Created0x10,Created0x30,"
        "LastModified0x10,LastModified0x30,LastRecordChange0x10,"
        "LastRecordChange0x30,LastAccess0x10,LastAccess0x30\n"
        "C:\\Users\\alice\\comparison.txt,comparison.txt,42,3,66,5,True,False,"
        "2026-01-01 00:00:00,,2026-01-01 00:00:00,,"
        "2026-01-01 00:00:00,,2026-01-01 00:00:00,\n",
        encoding="utf-8",
    )
    raw_mft_path = tmp_path / "$MFT"
    raw_mft_path.write_bytes(bytes(43 * 1024))
    monkeypatch.setattr(
        'fmb.index.adapters.mft.parse_mft_record',
        lambda *args, **kwargs: _timestamp_raw_mft_record(),
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_mft_parser_run(
        csv_path=csv_path,
        raw_mft_path=raw_mft_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    record = next(
        item
        for item in run["observations"]
        if item["observation_type"] == "mft_file_record"
    )
    assert {
        record["fields"][field]
        for field in (
            "si_created",
            "si_modified",
            "si_record_changed",
            "si_accessed",
            "fn_created",
            "fn_modified",
            "fn_record_changed",
            "fn_accessed",
        )
    } == {"2026-01-01T00:00:00Z"}
    assert record["fields"]["mismatch_count"] == 0
    assert run["coverage_status"] == "complete"
    assert {Path(item["path"]).name for item in run["raw_outputs"]} == {
        "mft.csv",
        "$MFT",
    }


def test_mft_adapter_keeps_unrelated_unresolved_records_out_of_verified_coverage(
    tmp_path: Path, monkeypatch
) -> None:
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text(
        "FullPath,FileName,EntryNumber,SequenceNumber,ParentEntryNumber,"
        "ParentSequenceNumber,InUse,IsDirectory,Created0x10,Created0x30,"
        "LastModified0x10,LastModified0x30,LastRecordChange0x10,"
        "LastRecordChange0x30,LastAccess0x10,LastAccess0x30\n"
        "C:\\Users\\alice\\comparison.txt,comparison.txt,42,3,66,5,True,False,"
        "2026-01-01 00:00:00,,2026-01-01 00:00:00,,"
        "2026-01-01 00:00:00,,2026-01-01 00:00:00,\n"
        "C:\\Windows\\unresolved.dll,unresolved.dll,43,3,66,5,True,False,"
        "2026-01-01 00:00:00,,2026-01-01 00:00:00,,"
        "2026-01-01 00:00:00,,2026-01-01 00:00:00,\n",
        encoding="utf-8",
    )
    raw_mft_path = tmp_path / "$MFT"
    raw_mft_path.write_bytes(bytes(44 * 1024))
    monkeypatch.setattr(
        'fmb.index.adapters.mft.parse_mft_record',
        lambda *args, **kwargs: (
            _timestamp_raw_mft_record()
            if kwargs["record_offset"] == 42 * 1024
            else None
        ),
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_mft_parser_run(
        csv_path=csv_path,
        raw_mft_path=raw_mft_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    records = {
        item["subject_ref"]: item["fields"]
        for item in run["observations"]
        if item["observation_type"] == "mft_file_record"
    }
    assert records[r"C:\Users\alice\comparison.txt"][
        "raw_mft_timestamp_validation"
    ] == "verified"
    assert records[r"C:\Windows\unresolved.dll"][
        "raw_mft_timestamp_validation"
    ] == "failed"
    assert run["coverage_status"] == "partial"


def test_kape_indexing_binds_the_collected_raw_mft_to_mftecmd(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "kape"
    raw_mft_path = root / "targets" / "C" / "$MFT"
    raw_mft_path.parent.mkdir(parents=True)
    raw_mft_path.write_bytes(bytes(43 * 1024))
    csv_path = root / "modules" / "FileSystem" / "MFTECmd_$MFT_Output.csv"
    csv_path.parent.mkdir(parents=True)
    csv_path.write_text(
        "FullPath,FileName,EntryNumber,SequenceNumber,ParentEntryNumber,"
        "ParentSequenceNumber,InUse,IsDirectory,Created0x10,Created0x30,"
        "LastModified0x10,LastModified0x30,LastRecordChange0x10,"
        "LastRecordChange0x30,LastAccess0x10,LastAccess0x30\n"
        "C:\\Users\\alice\\comparison.txt,comparison.txt,42,3,66,5,True,False,"
        "2026-01-01 00:00:00,,2026-01-01 00:00:00,,"
        "2026-01-01 00:00:00,,2026-01-01 00:00:00,\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        'fmb.index.adapters.mft.parse_mft_record',
        lambda *args, **kwargs: _timestamp_raw_mft_record(),
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    runs = scan_kape_output_root(
        root=root,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    run = next(item for item in runs if item["parser_kind"] == "ntfs_mft")
    record = next(
        item
        for item in run["observations"]
        if item["observation_type"] == "mft_file_record"
    )
    assert record["fields"]["fn_created"] == "2026-01-01T00:00:00Z"
    assert run["coverage_status"] == "complete"
    assert {Path(item["path"]).name for item in run["raw_outputs"]} == {
        "MFTECmd_$MFT_Output.csv",
        "$MFT",
    }


def test_mft_adapter_rejects_a_csv_and_raw_timestamp_disagreement(
    tmp_path: Path, monkeypatch
) -> None:
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text(
        "FullPath,FileName,EntryNumber,SequenceNumber,ParentEntryNumber,"
        "ParentSequenceNumber,InUse,IsDirectory,Created0x10,Created0x30,"
        "LastModified0x10,LastModified0x30,LastRecordChange0x10,"
        "LastRecordChange0x30,LastAccess0x10,LastAccess0x30\n"
        "C:\\Users\\alice\\comparison.txt,comparison.txt,42,3,66,5,True,False,"
        "2026-01-01 00:00:00,2025-01-01 00:00:00,"
        "2026-01-01 00:00:00,2026-01-01 00:00:00,"
        "2026-01-01 00:00:00,2026-01-01 00:00:00,"
        "2026-01-01 00:00:00,2026-01-01 00:00:00\n",
        encoding="utf-8",
    )
    raw_mft_path = tmp_path / "$MFT"
    raw_mft_path.write_bytes(bytes(43 * 1024))
    monkeypatch.setattr(
        'fmb.index.adapters.mft.parse_mft_record',
        lambda *args, **kwargs: _timestamp_raw_mft_record(),
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_mft_parser_run(
        csv_path=csv_path,
        raw_mft_path=raw_mft_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    record = next(
        item
        for item in run["observations"]
        if item["observation_type"] == "mft_file_record"
    )
    assert record["fields"]["raw_mft_timestamp_validation"] == "failed"
    assert "timestamp mismatch" in record["fields"][
        "raw_mft_timestamp_validation_error"
    ]
    assert run["coverage_status"] == "partial"


def test_mftecmd_usn_adapter_makes_offset_free_utc_explicit(tmp_path: Path) -> None:
    csv_path = tmp_path / "usn.csv"
    csv_path.write_text(
        "FullPath,Name,UpdateReasons,UpdateTimestamp,EntryNumber,SequenceNumber\n"
        "C:\\Users\\alice\\time.txt,time.txt,BasicInfoChange,"
        "2026-01-01 12:05:00.1234567,42,3\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_usn_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert run["observations"][0]["fields"]["update_timestamp"] == (
        "2026-01-01T12:05:00.1234567Z"
    )


def test_mft_population_is_partial_when_timestamp_columns_are_unavailable(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text(
        "FullPath,EntryNumber,SequenceNumber\nC:\\Users\\alice\\ordinary.txt,42,3\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_mft_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert run["coverage_status"] == "partial"
    assert run["candidate_populations"][0]["coverage_status"] == "partial"


def test_mft_population_remains_partial_when_true_candidates_exceed_cap(
    tmp_path: Path, monkeypatch
) -> None:
    csv_path = tmp_path / "mft.csv"
    csv_path.write_text(
        "FullPath,EntryNumber,SequenceNumber,Created0x10,Created0x30,"
        "LastModified0x10,LastModified0x30,LastRecordChange0x10,"
        "LastAccess0x10,LastAccess0x30\n"
        "C:\\Users\\alice\\one.txt,42,3,"
        "2020-01-01 00:00:00,"
        "2024-01-01 00:00:00,2024-01-01 00:00:00,"
        "2024-01-01 00:00:00,2024-01-01 00:00:00,"
        "2024-01-01 00:00:00,2024-01-01 00:00:00\n"
        "C:\\Users\\alice\\two.txt,43,3,"
        "2021-01-01 00:00:00,"
        "2024-01-01 00:00:00,2024-01-01 00:00:00,"
        "2024-01-01 00:00:00,2024-01-01 00:00:00,"
        "2024-01-01 00:00:00,2024-01-01 00:00:00\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    monkeypatch.setattr(
        'fmb.index.adapters.mft.MAX_MFT_TIMESTAMP_OBSERVATIONS', 1
    )

    run = mftecmd_mft_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert run["coverage_status"] == "partial"
    population = run["candidate_populations"][0]
    assert population["coverage_status"] == "partial"
    assert len(population["subjects"]) == 1
    assert population["subjects"][0]["observation_ids"]
    parser_run = {
        key: value for key, value in run.items() if key != "candidate_populations"
    }
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "production-population",
            "parser_runs": [
                parser_run,
                {
                    "parser_kind": "ntfs_usn",
                    "status": "consumed",
                    "observations": [],
                },
            ],
            "candidate_populations": [population],
        },
        techniques_for_question("Q-TIME-01")[0],
    )
    assert analysis_input.readiness == "insufficient_evidence"
    assert len(analysis_input.candidate_roster.subjects) == 1


def test_malformed_ads_csv_cannot_become_a_complete_empty_negative(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "mftecmd_ads.csv"
    csv_path.write_text("Unrelated,Columns\nvalue,other\n", encoding="utf-8")
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_ads_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "malformed-ads",
            "parser_runs": [
                run,
                {
                    "parser_kind": "ntfs_mft",
                    "status": "consumed",
                    "coverage_status": "complete",
                    "observations": [],
                },
            ],
        },
        techniques_for_question("Q-HIDE-01")[0],
    )

    assert run["observations"] == []
    assert run["coverage_status"] == "partial"
    assert analysis_input.readiness == "insufficient_evidence"


def test_ads_csv_without_stream_name_or_stream_capable_path_is_partial(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "mftecmd_ads.csv"
    csv_path.write_text(
        "ParentPath,FileName,StreamSize\n"
        r"C:\Users\alice,file.txt,5"
        "\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_ads_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert run["observations"] == []
    assert run["coverage_status"] == "partial"


def test_ads_csv_without_a_subject_header_is_partial(tmp_path: Path) -> None:
    csv_path = tmp_path / "mftecmd_ads.csv"
    csv_path.write_text("StreamName,StreamSize\nsecret,5\n", encoding="utf-8")
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_ads_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert run["coverage_status"] == "partial"


def test_ads_candidates_are_bounded_and_truncation_is_partial(
    tmp_path: Path, monkeypatch
) -> None:
    csv_path = tmp_path / "mftecmd_ads.csv"
    csv_path.write_text(
        "FullPath,StreamName,StreamSize\n"
        "C:\\Users\\alice\\one.txt,secret-one,5\n"
        "C:\\Users\\alice\\two.txt,secret-two,6\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    monkeypatch.setattr(
        'fmb.index.adapters.ntfs_files.MAX_MFTECMD_ADS_OBSERVATIONS',
        1,
        raising=False,
    )

    run = mftecmd_ads_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "bounded-ads",
            "parser_runs": [
                run,
                {
                    "parser_kind": "ntfs_mft",
                    "status": "consumed",
                    "coverage_status": "complete",
                    "observations": [],
                },
            ],
        },
        techniques_for_question("Q-HIDE-01")[0],
    )

    assert len(run["observations"]) == 1
    assert run["coverage_status"] == "partial"
    assert analysis_input.readiness == "insufficient_evidence"
    assert len(analysis_input.candidate_roster.subjects) == 1


def test_ads_observations_use_exact_host_identity_and_complete_host_population(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "MFTECmd_Output.csv"
    csv_path.write_text(
        "FullPath,EntryNumber,SequenceNumber,StreamName,FileSize\n"
        "C:\\Users\\alice\\owner.txt,42,3,,10\n"
        "C:\\Recovered\\wrong-name.txt:secret:$DATA,42,3,secret,5\n"
        "C:\\Users\\alice\\plain.txt,43,7,,20\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_ads_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert run["coverage_status"] == "complete"
    assert len(run["observations"]) == 1
    observation = run["observations"][0]
    fields = observation["fields"]
    assert observation["subject_ref"] == r"C:\Users\alice\owner.txt:secret"
    assert fields["base_path"] == r"C:\Users\alice\owner.txt"
    assert fields["mft_entry"] == 42
    assert fields["sequence_number"] == 3
    assert fields["mft_volume_id"].startswith("mft-source:")
    assert fields["host_population_complete"] is True
    assert fields["host_population_size"] == 2
    assert fields["hosts_without_named_stream_count"] == 1
    assert fields["host_named_stream_count"] == 1


def test_ads_parser_keeps_every_named_stream_including_dollar_prefixed_names(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "MFTECmd_Output.csv"
    csv_path.write_text(
        "FullPath,EntryNumber,SequenceNumber,StreamName,FileSize\n"
        "C:\\Users\\alice\\owner.txt,42,3,,10\n"
        "C:\\Users\\alice\\owner.txt:$secret:$DATA,42,3,$secret,5\n"
        "C:\\Users\\alice\\owner.txt:Zone.Identifier:$DATA,42,3,"
        "Zone.Identifier,4\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = mftecmd_ads_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert [item["fields"]["stream_name"] for item in run["observations"]] == [
        "$secret",
        "Zone.Identifier",
    ]
    assert all(
        item["fields"]["host_named_stream_count"] == 2 for item in run["observations"]
    )


def test_ads_reference_parser_proves_the_exact_roster_and_emits_named_streams(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "MFTECmd_Output.csv"
    csv_path.write_text(
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,FileSize,"
        "IsDirectory,HasAds,IsAds\n"
        "42,3,True,.\\Users\\alice,owner.txt,10,False,True,False\n"
        "42,3,True,.\\Users\\alice,owner.txt:secret,5,False,True,True\n"
        "43,7,True,.\\Users\\alice,plain.txt,20,False,False,False\n"
        "99,1,True,.\\Windows,unrelated.txt:ignored,8,False,True,True\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    filesystem_scope_id = f"mft-source:{source_scope_id(csv_path)}"

    run = mftecmd_ads_reference_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        references={(42, 3), (43, 7)},
        filesystem_scope_id=filesystem_scope_id,
    )

    assert run["coverage_status"] == "partial"
    assert run["tool_identity"]["name"] == "fmb.ads.truth_blind_reference_scanner"
    assert run["selection_scope"] == {
        "kind": "ntfs_file_references",
        "filesystem_scope_id": filesystem_scope_id,
        "reference_count": 2,
        "reference_sha256": usn.ntfs_reference_set_sha256({(42, 3), (43, 7)}),
        "matched_record_count": 3,
        "retained_record_count": 1,
        "normalized_record_count": 1,
        "source_size_bytes": csv_path.stat().st_size,
        "source_bytes_covered": csv_path.stat().st_size,
        "status": "complete",
    }
    assert len(run["observations"]) == 1
    observation = run["observations"][0]
    reference_hash = run["selection_scope"]["reference_sha256"]
    assert observation["observation_id"].startswith(
        f"obs:fmb-reference-ads:{reference_hash}:"
    )
    assert observation["subject_ref"] == r".\Users\alice\owner.txt:secret"
    assert observation["fields"] == {
        "stream_name": "secret",
        "base_path": r".\Users\alice\owner.txt",
        "stream_size": 5,
        "row_index": 2,
        "base_row_index": 1,
        "mft_volume_id": filesystem_scope_id,
        "mft_entry": 42,
        "sequence_number": 3,
        "in_use": True,
        "has_ads": True,
        "host_population_complete": True,
        "host_population_size": 2,
        "hosts_without_named_stream_count": 1,
        "host_named_stream_count": 1,
        "stream_name_occurrences": 1,
    }
    assert reference_hash in Path(run["normalized_output"]["path"]).name


def test_ads_reference_parser_uses_the_base_rows_host_state(tmp_path: Path) -> None:
    csv_path = tmp_path / "MFTECmd_Output.csv"
    csv_path.write_text(
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,FileSize,"
        "IsDirectory,HasAds,IsAds\n"
        "42,3,True,.\\Users\\alice,owner.txt,10,False,True,False\n"
        "42,3,False,.\\Users\\alice,owner.txt:secret,5,False,False,True\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    filesystem_scope_id = f"mft-source:{source_scope_id(csv_path)}"

    run = mftecmd_ads_reference_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        references={(42, 3)},
        filesystem_scope_id=filesystem_scope_id,
    )

    assert run["observations"][0]["fields"]["in_use"] is True
    assert run["observations"][0]["fields"]["has_ads"] is True


def test_ads_reference_parser_can_prove_an_exact_empty_negative(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "MFTECmd_Output.csv"
    csv_path.write_text(
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,FileSize,"
        "IsDirectory,HasAds,IsAds\n"
        "42,3,True,.\\Users\\alice,owner.txt,10,False,False,False\n"
        "43,7,True,.\\Users\\alice,plain.txt,20,False,False,False\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    filesystem_scope_id = f"mft-source:{source_scope_id(csv_path)}"

    run = mftecmd_ads_reference_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        references={(42, 3), (43, 7)},
        filesystem_scope_id=filesystem_scope_id,
    )

    assert run["observations"] == []
    assert run["selection_scope"]["matched_record_count"] == 2
    assert run["selection_scope"]["retained_record_count"] == 0
    assert run["selection_scope"]["normalized_record_count"] == 0
    assert run["selection_scope"]["status"] == "complete"


def test_ads_reference_parser_fails_closed_on_an_invalid_base_surface(
    tmp_path: Path,
) -> None:
    header = (
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,FileSize,"
        "IsDirectory,HasAds,IsAds\n"
    )
    cases = {
        "missing": (
            "42,3,True,.\\Users\\alice,owner.txt:secret,5,False,True,True\n"
        ),
        "duplicate": (
            "42,3,True,.\\Users\\alice,owner.txt,10,False,True,False\n"
            "42,3,True,.\\Users\\alice,owner.txt,10,False,True,False\n"
            "42,3,True,.\\Users\\alice,owner.txt:secret,5,False,True,True\n"
        ),
        "malformed_is_ads": (
            "42,3,True,.\\Users\\alice,owner.txt,10,False,True,not-a-bool\n"
        ),
        "inactive_base": (
            "42,3,False,.\\Users\\alice,owner.txt,10,False,False,False\n"
        ),
        "directory_base": (
            "42,3,True,.\\Users\\alice,owner.txt,10,True,False,False\n"
        ),
        "inconsistent_has_ads": (
            "42,3,True,.\\Users\\alice,owner.txt,10,False,True,False\n"
        ),
    }

    for case_name, body in cases.items():
        case_root = tmp_path / case_name
        case_root.mkdir()
        csv_path = case_root / "MFTECmd_Output.csv"
        csv_path.write_text(header + body, encoding="utf-8")
        normalized = case_root / "normalized"
        normalized.mkdir()
        run = mftecmd_ads_reference_parser_run(
            csv_path=csv_path,
            normalized_output_dir=normalized,
            collector_run={"collector": "kape", "provenance": {}},
            references={(42, 3)},
            filesystem_scope_id=f"mft-source:{source_scope_id(csv_path)}",
        )

        assert run["selection_scope"]["status"] == "partial", case_name
        assert run["selection_scope"]["source_bytes_covered"] == csv_path.stat().st_size


def test_ads_reference_parser_bounds_named_stream_observations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    csv_path = tmp_path / "MFTECmd_Output.csv"
    csv_path.write_text(
        "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,FileSize,"
        "IsDirectory,HasAds,IsAds\n"
        "42,3,True,.\\Users\\alice,owner.txt,10,False,True,False\n"
        "42,3,True,.\\Users\\alice,owner.txt:first,5,False,True,True\n"
        "42,3,True,.\\Users\\alice,owner.txt:second,6,False,True,True\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    monkeypatch.setattr(
        'fmb.index.adapters.ntfs_files.MAX_MFTECMD_ADS_OBSERVATIONS',
        1,
    )

    run = mftecmd_ads_reference_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        references={(42, 3)},
        filesystem_scope_id=f"mft-source:{source_scope_id(csv_path)}",
    )

    assert len(run["observations"]) == 1
    assert run["selection_scope"]["status"] == "partial"


def test_ads_reference_parser_rejects_invalid_scope_inputs(tmp_path: Path) -> None:
    csv_path = tmp_path / "MFTECmd_Output.csv"
    csv_path.write_text(
        "EntryNumber,SequenceNumber,ParentPath,FileName,FileSize,IsAds\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    common = {
        "csv_path": csv_path,
        "normalized_output_dir": normalized,
        "collector_run": {"collector": "kape", "provenance": {}},
    }
    matching_scope_id = f"mft-source:{source_scope_id(csv_path)}"

    with pytest.raises(ValueError, match="filesystem scope"):
        mftecmd_ads_reference_parser_run(
            **common,
            references={(42, 3)},
            filesystem_scope_id=" ",
        )
    with pytest.raises(ValueError, match="file references"):
        mftecmd_ads_reference_parser_run(
            **common,
            references=set(),
            filesystem_scope_id=matching_scope_id,
        )
    with pytest.raises(ValueError, match="NTFS file reference is invalid"):
        mftecmd_ads_reference_parser_run(
            **common,
            references={(42, -1)},
            filesystem_scope_id=matching_scope_id,
        )
    with pytest.raises(ValueError, match="does not match"):
        mftecmd_ads_reference_parser_run(
            **common,
            references={(42, 3)},
            filesystem_scope_id="mft-source:wrong",
        )


def test_csv_adapters_mark_unrecognized_headers_as_partial(tmp_path: Path) -> None:
    builders = (
        evtxecmd_parser_run,
        logfile_parser_run,
        mftecmd_size_parser_run,
        mftecmd_usn_parser_run,
        pecmd_prefetch_parser_run,
        registry_path_parser_run,
        typed_paths_parser_run,
        usbstor_parser_run,
    )
    for builder in builders:
        case_root = tmp_path / builder.__name__
        case_root.mkdir()
        csv_path = case_root / "unrecognized.csv"
        csv_path.write_text("Unrelated,Columns\nvalue,other\n", encoding="utf-8")
        normalized = case_root / "normalized"
        normalized.mkdir()

        run = builder(
            csv_path=csv_path,
            normalized_output_dir=normalized,
            collector_run={"collector": "kape", "provenance": {}},
        )

        assert run["coverage_status"] == "partial", builder.__name__


def test_event_adapter_proves_its_projection_against_collected_security_evtx(
    tmp_path: Path,
) -> None:
    raw_log = (
        tmp_path
        / "Targets"
        / "C"
        / "Windows"
        / "System32"
        / "winevt"
        / "Logs"
        / "Security.evtx"
    )
    raw_log.parent.mkdir(parents=True)
    raw_log.write_bytes(security_evtx_bytes())
    csv_path = tmp_path / "EvtxECmd_Output.csv"
    csv_path.write_text(
        "EventId,EventRecordId,Channel,SourceFile\n"
        r"1102,77,Security,C:\Windows\System32\winevt\Logs\Security.evtx"
        "\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = evtxecmd_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={
            "collector": "kape",
            "provenance": {},
            "artifacts": [{"path": str(raw_log), "relative_path": str(raw_log)}],
        },
    )

    assert run["coverage_status"] == "complete"
    assert len(run["raw_outputs"]) == 2
    assert {item["path"] for item in run["raw_outputs"]} == {
        str(csv_path),
        str(raw_log),
    }
    clear_event = next(
        item
        for item in run["observations"]
        if item["observation_type"] == "event_id_1102"
    )
    assert clear_event["fields"]["event_record_id"] == 77


def test_event_adapter_marks_incomplete_or_non_unique_projections_partial(
    tmp_path: Path,
) -> None:
    raw_log = tmp_path / "Security.evtx"
    raw_log.write_bytes(security_evtx_bytes())
    collector_run = {
        "collector": "kape",
        "provenance": {},
        "artifacts": [{"path": str(raw_log), "relative_path": "Security.evtx"}],
    }
    cases = {
        "empty": "EventId,EventRecordId,Channel,SourceFile\n",
        "truncated": (
            "EventId,EventRecordId,Channel,SourceFile\n"
            r"1,76,Security,C:\Windows\System32\winevt\Logs\Security.evtx"
            "\n"
        ),
        "malformed": (
            "EventId,EventRecordId,Channel,SourceFile\n"
            r"1102,invalid,Security,C:\Windows\System32\winevt\Logs\Security.evtx"
            "\n"
        ),
        "duplicate": (
            "EventId,EventRecordId,Channel,SourceFile\n"
            r"1102,77,Security,C:\Windows\System32\winevt\Logs\Security.evtx"
            "\n"
            r"1102,77,Security,C:\Windows\System32\winevt\Logs\Security.evtx"
            "\n"
        ),
        "overflow": (
            "EventId,EventRecordId,Channel,SourceFile\n"
            f"1102,{1 << 64},Security,"
            "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx\n"
        ),
    }
    for case_name, content in cases.items():
        case_root = tmp_path / case_name
        case_root.mkdir()
        csv_path = case_root / "EvtxECmd_Output.csv"
        csv_path.write_text(content, encoding="utf-8")
        normalized = case_root / "normalized"
        normalized.mkdir()

        run = evtxecmd_parser_run(
            csv_path=csv_path,
            normalized_output_dir=normalized,
            collector_run=collector_run,
        )

        assert run["coverage_status"] == "partial", case_name


def test_event_observations_are_bounded_and_overflow_is_partial(
    tmp_path: Path, monkeypatch
) -> None:
    csv_path = tmp_path / "EvtxECmd_Output.csv"
    csv_path.write_text(
        "EventId,EventRecordId,Channel,SourceFile\n"
        r"1102,1,Security,C:\Windows\System32\winevt\Logs\Security.evtx"
        "\n"
        r"1102,2,Security,C:\Windows\System32\winevt\Logs\Security.evtx"
        "\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    monkeypatch.setattr('fmb.index.adapters.event_log.MAX_EVTXECMD_OBSERVATIONS', 1)

    run = evtxecmd_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert len(run["observations"]) == 1
    assert run["coverage_status"] == "partial"


def test_typed_paths_adapter_rejects_other_keys_and_nonlocal_values(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "recmd_mru.csv"
    csv_path.write_text(
        "BatchKeyPath,Path\n"
        "OpenSavePidlMRU,C:\\Users\\alice\\wrong-key.txt\n"
        "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths,Documents\\relative.txt\n"
        "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths,C:\\Users\\alice\\absolute.txt\n"
        "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths,D:\\Profiles\\analyst\\custom-root.txt\n"
        "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths,\\\\server\\share\\remote.txt\n"
        "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths,\\\\?\\C:\\Users\\alice\\device-path.txt\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = typed_paths_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert [item["subject_ref"] for item in run["observations"]] == [
        r"C:\Users\alice\absolute.txt",
        r"D:\Profiles\analyst\custom-root.txt",
    ]


def test_typed_paths_adapter_skips_values_recovered_from_deleted_cells(
    tmp_path: Path,
) -> None:
    key = "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"
    csv_path = tmp_path / "recmd_mru.csv"
    csv_path.write_text(
        "BatchKeyPath,Path,Deleted\n"
        f"{key},C:\\Users\\alice\\recovered.txt,True\n"
        f"{key},C:\\Users\\alice\\live.txt,False\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = typed_paths_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert [item["subject_ref"] for item in run["observations"]] == [r"C:\Users\alice\live.txt"]
    assert run["observations"][0]["source_record_ref"].endswith(":row=2")


def test_registry_path_candidates_are_bounded_and_truncation_is_partial(
    tmp_path: Path, monkeypatch
) -> None:
    csv_path = tmp_path / "shimcache.csv"
    csv_path.write_text(
        "Path,LastModifiedTimeUTC\n"
        "C:\\Users\\alice\\one.bat,2026-01-01 10:00:00\n"
        "C:\\Users\\alice\\two.bat,2026-01-01 11:00:00\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    monkeypatch.setattr(
        'fmb.index.adapters.registry.MAX_PATH_TRACE_OBSERVATIONS',
        1,
        raising=False,
    )

    run = registry_path_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        mft_context={"row_count": 0},
    )
    analysis_input = build_analysis_input(
        {
            "schema_version": "evidence_index.v1",
            "run_id": "bounded-registry",
            "parser_runs": [
                run,
                {
                    "parser_kind": "ntfs_mft",
                    "status": "consumed",
                    "coverage_status": "complete",
                    "observations": [],
                },
            ],
        },
        techniques_for_question("Q-EXEC-01")[1],
    )

    assert len(run["observations"]) == 1
    assert run["coverage_status"] == "partial"
    assert analysis_input.readiness == "insufficient_evidence"
    assert len(analysis_input.candidate_roster.subjects) == 1


def _bmp_bytes(*, trailing: bytes = b"") -> bytes:
    payload = bytearray(58)
    payload[:2] = b"BM"
    struct.pack_into("<I", payload, 2, 58)
    struct.pack_into("<I", payload, 10, 54)
    struct.pack_into("<I", payload, 14, 40)
    struct.pack_into("<i", payload, 18, 1)
    struct.pack_into("<i", payload, 22, 1)
    struct.pack_into("<H", payload, 26, 1)
    struct.pack_into("<H", payload, 28, 24)
    struct.pack_into("<I", payload, 34, 4)
    return bytes(payload) + trailing


def _raw_mft_record() -> dict[str, object]:
    return {
        "mft_entry": 42,
        "sequence_number": 3,
        "attribute_list_present": False,
        "attribute_parse_error_count": 0,
        "data_attributes": [
            {
                "attribute_id": 7,
                "stream_name": "",
                "is_named_stream": False,
                "resident_status": "nonresident",
                "attribute_flags": 0,
                "is_sparse": False,
                "is_compressed": False,
                "is_encrypted": False,
                "logical_size": 65,
                "allocated_size": 4096,
                "valid_data_length": 65,
                "lowest_vcn": 0,
                "highest_vcn": 0,
                "data_run_count": 1,
                "allocated_cluster_count": 1,
                "sparse_cluster_count": 0,
                "runlist_complete": True,
            }
        ],
    }


def _timestamp_raw_mft_record() -> dict[str, object]:
    timestamp = {
        "utc": "2026-01-01T00:00:00Z",
        "ntfs_filetime": 134116992000000000,
    }
    return {
        "mft_entry": 42,
        "sequence_number": 3,
        "file_record_flags": 1,
        "metadata_timestamps": {
            "created": timestamp,
            "modified": timestamp,
            "metadata_changed": timestamp,
            "accessed": timestamp,
        },
        "file_name_attributes": [
            {
                "name": "comparison.txt",
                "namespace_name": "win32",
                "parent_inode": 66,
                "parent_sequence": 5,
                "file_name_timestamps": {
                    "created": timestamp,
                    "modified": timestamp,
                    "mft_modified": timestamp,
                    "accessed": timestamp,
                },
            }
        ],
    }


def _bounded_bmp_tree(tmp_path: Path) -> Path:
    root = tmp_path / "kape"
    volume = root / "targets" / "C"
    target = volume / "Users" / "alice" / "Documents" / "PhotoArchive"
    target.mkdir(parents=True)
    (target / "sample.bmp").write_bytes(_bmp_bytes(trailing=b"padding"))
    (volume / "$MFT").write_bytes(bytes(43 * 1024))
    output = root / "modules" / "MFTECmd" / "Output"
    output.mkdir(parents=True)
    (output / "mft.csv").write_text(
        "FullPath,EntryNumber,SequenceNumber,FileSize\n"
        r"C:\Users\alice\Documents\PhotoArchive\sample.bmp,42,3,65"
        "\n",
        encoding="utf-8",
    )
    return root


def test_bounded_bmp_adapter_replaces_generic_size_projection(
    tmp_path: Path, monkeypatch
) -> None:
    root = _bounded_bmp_tree(tmp_path)
    monkeypatch.setattr(
        file_content, "parse_mft_record", lambda *args, **kwargs: _raw_mft_record()
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    collector_run = {"collector": "kape", "provenance": {}}

    direct = q_file_parser_runs(
        root=root,
        normalized_output_dir=normalized,
        collector_run=collector_run,
    )
    indexed = scan_kape_output_root(
        root=root,
        normalized_output_dir=normalized,
        collector_run=collector_run,
    )

    assert [item["parser_kind"] for item in direct] == [
        "ntfs_file_size_allocation",
        "materialized_file_content",
    ]
    assert all(item["coverage_status"] == "complete" for item in direct)
    assert (
        sum(item["parser_kind"] == "ntfs_file_size_allocation" for item in indexed) == 1
    )
    storage = direct[0]["observations"][0]
    content = direct[1]["observations"][0]
    assert storage["fields"]["volume_id"] == content["fields"]["volume_id"]
    assert storage["fields"]["mft_entry"] == content["fields"]["mft_entry"]
    assert storage["fields"]["sequence_number"] == content["fields"]["sequence_number"]


def test_usbstor_adapter_emits_one_identity_bound_device(tmp_path: Path) -> None:
    csv_path = tmp_path / "USBSTOR_Output.csv"
    key = r"ControlSet001\Enum\USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1"
    property_root = key + r"\Properties\{83da6326-97a6-4088-9453-a1923f573b29}"
    arrival = registry_filetime(datetime(2026, 1, 1, 10, tzinfo=timezone.utc))
    removal = registry_filetime(datetime(2026, 1, 1, 11, tzinfo=timezone.utc))
    csv_path.write_text(
        "KeyPath,ValueName,ValueType,ValueData\n"
        f"{key},FriendlyName,RegSz,Test media\n"
        f"{property_root}\\0066,,RegBinary,{arrival}\n"
        f"{property_root}\\0067,,RegBinary,{removal}\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = usbstor_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert len(run["observations"]) == 1
    fields = run["observations"][0]["fields"]
    assert fields["device_instance_id"].casefold() == (
        r"USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1".casefold()
    )
    assert fields["serial_number"] == "SERIAL-1"
    assert fields["control_set"] == "ControlSet001"
    assert fields["timestamp_basis"] == "native_device_property_filetime"
    assert fields["last_arrival"] == "2026-01-01T10:00:00+00:00"
    assert fields["last_removal"] == "2026-01-01T11:00:00+00:00"
    assert "filesystem_path" not in fields


def test_usbstor_discovery_reads_exact_identity_from_generic_registry_csv(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "modules" / "Registry"
    registry.mkdir(parents=True)
    usbstor = registry / "RECmd_AllBatchFiles.csv"
    usbstor.write_text(
        "KeyPath,ValueName,ValueType,ValueData\n"
        r"ControlSet001\Enum\USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1"
        ",FriendlyName,RegSz,Test media\n",
        encoding="utf-8",
    )
    unrelated = registry / "RECmd_Other.csv"
    unrelated.write_text(
        "KeyPath,ValueName,ValueType,ValueData\n"
        r"ControlSet001\Services\Example,DisplayName,RegSz,Example"
        "\n",
        encoding="utf-8",
    )

    assert usbstor_csv_files(tmp_path) == [usbstor]


def test_usbstor_discovery_fails_closed_on_malformed_registry_csv(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "modules" / "Registry"
    registry.mkdir(parents=True)
    malformed = registry / "RECmd_AllBatchFiles.csv"
    malformed.write_text(
        'KeyPath,ValueData\n"ControlSet001\\Enum\\USBSTOR\\Disk&Ven_ACME',
        encoding="utf-8",
    )

    assert usbstor_csv_files(tmp_path) == []


def test_usbstor_discovery_accepts_concrete_three_digit_control_set(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "modules" / "Registry"
    registry.mkdir(parents=True)
    csv_path = registry / "RECmd_AllBatchFiles.csv"
    csv_path.write_text(
        "KeyPath,ValueName,ValueType,ValueData\n"
        r"ControlSet012\Enum\USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1"
        ",FriendlyName,RegSz,Test media\n",
        encoding="utf-8",
    )

    assert usbstor_csv_files(tmp_path) == [csv_path]


def test_usbstor_discovery_stops_at_bounded_registry_row_limit(
    tmp_path: Path, monkeypatch
) -> None:
    registry = tmp_path / "modules" / "Registry"
    registry.mkdir(parents=True)
    csv_path = registry / "RECmd_AllBatchFiles.csv"
    csv_path.write_text(
        "KeyPath,ValueName,ValueType,ValueData\n"
        "ControlSet001\\Services\\One,DisplayName,RegSz,One\n"
        "ControlSet001\\Services\\Two,DisplayName,RegSz,Two\n"
        "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_ACME\\SERIAL-1,"
        "FriendlyName,RegSz,Test media\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(registry_adapters, "MAX_USBSTOR_DISCOVERY_ROWS", 2)

    assert usbstor_csv_files(tmp_path) == []


def test_usbstor_plugin_csv_is_discovered_and_normalized_exactly(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "modules" / "Registry"
    registry.mkdir(parents=True)
    csv_path = registry / "RECmd_Batch_MC.csv"
    csv_path.write_text(
        "Timestamp,BatchKeyPath,Manufacturer,Title,Version,SerialNumber,"
        "DeviceName,DiskId,Installed,FirstInstalled,LastConnected,LastRemoved\n"
        "2026-01-04T09:00:00Z,"
        r"ROOT\ControlSet001\Enum\USBSTOR"
        r"\Disk&Ven_Generic&Prod_Flash_Disk&Rev_1.00"
        ",Generic,Flash Disk,1.00,435A30E52B19,Generic Flash Disk,"
        "{11111111-2222-3333-4444-555555555555},"
        "2026-01-01T08:00:00Z,2026-01-01T07:00:00Z,"
        "2026-01-03T10:30:00Z,2026-01-03T11:00:00Z\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    assert usbstor_csv_files(tmp_path) == [csv_path]
    run = usbstor_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert run["coverage_status"] == "complete"
    assert len(run["observations"]) == 1
    fields = run["observations"][0]["fields"]
    assert fields["device_instance_id"] == (
        r"USBSTOR\Disk&Ven_Generic&Prod_Flash_Disk&Rev_1.00\435A30E52B19"
    )
    assert fields["control_set"] == "ControlSet001"
    assert fields["registry_key_timestamp"] == "2026-01-04T09:00:00+00:00"
    assert fields["installed"] == "2026-01-01T08:00:00+00:00"
    assert fields["first_install"] == "2026-01-01T07:00:00+00:00"
    assert fields["last_arrival"] == "2026-01-03T10:30:00+00:00"
    assert fields["last_removal"] == "2026-01-03T11:00:00+00:00"


def test_bounded_kroll_output_supplies_typed_paths_and_usbstor(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "modules" / "Registry"
    plugin_dir = registry / "20260828090000"
    plugin_dir.mkdir(parents=True)
    kroll = registry / "20260828090000_RECmd_Batch_Kroll_Batch_Output.csv"
    kroll.write_text(
        "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,"
        "ValueData,ValueData2,ValueData3,Comment,Recursive,Deleted,"
        "LastWriteTimestamp,PluginDetailFile\n"
        r"C:\evidence\NTUSER.DAT,NtUser,TypedPaths,User Activity,"
        r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths,"
        "url1,RegSz,C:\\Users\\vagrant\\Desktop\\missing-path,,,,False,False,"
        "2026-01-04T09:00:00Z,\n",
        encoding="utf-8",
    )
    usbstor = plugin_dir / "20260828090000_USBSTOR_SYSTEM.csv"
    usbstor.write_text(
        "Timestamp,BatchKeyPath,Manufacturer,Title,Version,SerialNumber,"
        "DeviceName,DiskId,Installed,FirstInstalled,LastConnected,LastRemoved\n"
        "2026-01-04T09:00:00Z,"
        r"ROOT\ControlSet001\Enum\USBSTOR"
        r"\Disk&Ven_Generic&Prod_Flash_Disk&Rev_1.00"
        ",Generic,Flash Disk,1.00,435A30E52B19,Generic Flash Disk,"
        "{11111111-2222-3333-4444-555555555555},"
        "2026-01-01T08:00:00Z,2026-01-01T07:00:00Z,"
        "2026-01-03T10:30:00Z,2026-01-03T11:00:00Z\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    collector_run = {"collector": "kape", "provenance": {}}

    assert registry_mru_csv_files(tmp_path) == [kroll]
    typed_run = typed_paths_parser_run(
        csv_path=kroll,
        normalized_output_dir=normalized,
        collector_run=collector_run,
    )
    assert typed_run["coverage_status"] == "complete"
    assert [item["subject_ref"] for item in typed_run["observations"]] == [
        r"C:\Users\vagrant\Desktop\missing-path"
    ]

    assert usbstor_csv_files(tmp_path) == [usbstor]
    usb_run = usbstor_parser_run(
        csv_path=usbstor,
        normalized_output_dir=normalized,
        collector_run=collector_run,
    )
    assert usb_run["coverage_status"] == "complete"
    assert len(usb_run["observations"]) == 1


def test_setupapi_adapter_emits_section_identity_and_timestamp(tmp_path: Path) -> None:
    log_path = tmp_path / "setupapi.dev.log"
    log_path.write_text(
        ">>>  [Device Install (Hardware initiated) - "
        r"USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1]"
        "\n"
        ">>>  Section start 2026-01-01T10:00:00Z\n"
        "<<<  Section end 2026-01-01T10:00:01Z\n"
        "<<<  [Exit status: SUCCESS]\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = setupapi_parser_run(
        log_path=log_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert len(run["observations"]) == 1
    fields = run["observations"][0]["fields"]
    assert fields["device_instance_id"].casefold() == (
        r"USBSTOR\Disk&Ven_ACME&Prod_Test\SERIAL-1".casefold()
    )
    assert fields["serial_number"] == "SERIAL-1"
    assert fields["event_timestamp"] == "2026-01-01T10:00:00+00:00"
    assert fields["timestamp_basis"] == "explicit_offset"


def test_setupapi_adapter_marks_valid_zero_usb_surface_complete(tmp_path: Path) -> None:
    log_path = tmp_path / "setupapi.dev.log"
    log_path.write_text(
        ">>>  [Device Install (Hardware initiated) - PCI\\VEN_1234&DEV_5678]\n"
        ">>>  Section start 2026-01-01T10:00:00Z\n"
        "<<<  Section end 2026-01-01T10:00:01Z\n"
        "<<<  [Exit status: SUCCESS]\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = setupapi_parser_run(
        log_path=log_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    assert run["coverage_status"] == "complete"
    assert run["coverage_families"] == ["windows.setupapi"]
    assert run["observations"] == []


def test_setupapi_adapter_marks_empty_and_malformed_logs_partial(
    tmp_path: Path,
) -> None:
    for case_name, content in (
        ("empty", ""),
        (
            "malformed",
            ">>>  [Device Install (Hardware initiated) - USBSTOR\\broken]\n"
            ">>>  Section start not-a-timestamp\n",
        ),
    ):
        case_root = tmp_path / case_name
        case_root.mkdir()
        log_path = case_root / "setupapi.dev.log"
        log_path.write_text(content, encoding="utf-8")
        normalized = case_root / "normalized"
        normalized.mkdir()

        run = setupapi_parser_run(
            log_path=log_path,
            normalized_output_dir=normalized,
            collector_run={"collector": "kape", "provenance": {}},
        )

        assert run["coverage_status"] == "partial"


def _collector_run_with_root(root: Path) -> dict:
    return {"collector": "kape", "provenance": {}, "output_root": str(root)}


def test_mftecmd_usn_adapter_reports_the_retained_journal_window(tmp_path: Path) -> None:
    root = tmp_path / "kape-output"
    extend = root / "targets" / "F" / "$Extend"
    extend.mkdir(parents=True)
    (extend / "$Max").write_bytes(
        struct.pack("<QQQQ", 32 * 1024 * 1024, 8 * 1024 * 1024, 0x1122334455667788, 4096)
    )
    (extend / "$J").write_bytes(b"public control identity fixture")
    csv_path = root / "modules" / "FileSystem" / "MFTECmd_$J_Output.csv"
    csv_path.parent.mkdir(parents=True)
    csv_path.write_text(
        "Name,EntryNumber,SequenceNumber,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons,SourceFile\n"
        "a.txt,42,3,8192,2026-01-01 12:00:00.0000000,FileCreate,C:\\FMB-Appliance\\bundle\\kape-output\\targets\\F\\$Extend\\$J\n"
        "b.txt,43,3,16384,2026-01-02 12:00:00.0000000,BasicInfoChange,C:\\FMB-Appliance\\bundle\\kape-output\\targets\\F\\$Extend\\$J\n"
        "c.txt,44,3,12288,2026-01-01 18:00:00.0000000,FileDelete|Close,C:\\FMB-Appliance\\bundle\\kape-output\\targets\\F\\$Extend\\$J\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = usn_adapters.mftecmd_usn_parser_run(
        csv_path=csv_path, normalized_output_dir=normalized,
        collector_run=_collector_run_with_root(root),
    )

    scope = run["coverage_scope"]
    assert scope["kind"] == "usn_journal"
    assert (scope["first_usn"], scope["last_usn"]) == (8192, 16384)
    assert scope["first_timestamp"] == "2026-01-01T12:00:00.0000000Z"
    assert scope["last_timestamp"] == "2026-01-02T12:00:00.0000000Z"
    assert scope["window_complete"] is True
    assert scope["journal_id"] == 0x1122334455667788 and scope["lowest_valid_usn"] == 4096


def test_setupapi_adapter_reports_the_retained_log_window(tmp_path: Path) -> None:
    inf = tmp_path / "targets" / "F" / "Windows" / "inf"
    inf.mkdir(parents=True)
    log_path = inf / "setupapi.dev.log"
    log_path.write_text(
        ">>>  [Device Install (Hardware initiated) - PCI\\VEN_1234\\1]\n"
        ">>>  Section start 2024/05/01 08:00:00.000\n"
        "<<<  Section end 2024/05/01 08:00:01.000\n"
        "<<<  [Exit status: SUCCESS]\n"
        ">>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_ACME&Prod_Test\\SERIAL-1]\n"
        ">>>  Section start 2026/01/01 10:00:00.000\n"
        "<<<  Section end 2026/01/01 10:00:01.000\n"
        "<<<  [Exit status: SUCCESS]\n",
        encoding="utf-8",
    )
    (inf / "setupapi.dev.20230101_000000.log").write_text(">>>  Section start 2023/01/01 00:00:00.000\n", encoding="utf-8")
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = registry_adapters.setupapi_parser_run(
        log_path=log_path, normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )

    scope = run["coverage_scope"]
    assert scope["kind"] == "setupapi_log"
    assert scope["section_count"] == 2
    assert scope["first_section_timestamp"] == "2024-05-01T08:00:00"
    assert scope["last_section_timestamp"] == "2026-01-01T10:00:00"
    assert scope["rotated_logs_present"] is True
    assert "setupapi.dev.20230101_000000.log" in scope["retained_log_names"]
    assert scope["window_complete"] is True
    assert registry_adapters.setupapi_log_files(tmp_path) == [
        inf / "setupapi.dev.20230101_000000.log", log_path,
    ]


def test_prefetch_adapter_reports_configuration_scope_from_registry_batch(tmp_path: Path) -> None:
    root = tmp_path / "kape-output"
    prefetch_dir = root / "targets" / "F" / "Windows" / "prefetch"
    prefetch_dir.mkdir(parents=True)
    (prefetch_dir / "TOOL.EXE-1234ABCD.pf").write_bytes(b"MAM")
    registry = root / "modules" / "Registry"
    (registry / "20260101000000").mkdir(parents=True)
    (registry / "20260101000000_RECmd_Batch_Kroll_Batch_Output.csv").write_text(
        "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,PluginDetailFile\n"
        "F:\\SYSTEM,System,Prefetch Status,System Info,ROOT\\ControlSet001\\Control\\Session Manager\\Memory Management\\PrefetchParameters,EnablePrefetcher,RegDword,0,,,c,False,False,2026-01-01 00:00:00,\n"
        "F:\\SYSTEM,System,Shutdown Time,System Info,ROOT\\ControlSet001\\Control\\Windows,ShutdownTime,RegBinary,2026-01-05 00:00:00.0000000,,,c,False,False,2026-01-05 00:00:00,\n"
        "F:\\SOFTWARE,Software,System Info (Current),System Info,ROOT\\Microsoft\\Windows NT\\CurrentVersion,ProductName,RegSz,Windows 10 Pro,,,c,False,False,2026-01-01 00:00:00,\n",
        encoding="utf-8",
    )
    (registry / "20260101000000" / "20260101000000_Services__F_Windows_System32_config_SYSTEM.csv").write_text(
        "Name,BatchKeyPath,Description,BatchValueName,DisplayName,StartMode,ServiceType\n"
        "SysMain,ROOT\\ControlSet001\\Services,d,None,SysMain,Disabled,Win32ShareProcess\n",
        encoding="utf-8",
    )
    csv_path = root / "modules" / "ProgramExecution" / "PECmd_Output.csv"
    csv_path.parent.mkdir(parents=True)
    csv_path.write_text(
        "SourceFilename,ExecutableName,RunCount,LastRun\n"
        "C:\\prefetch\\TOOL.EXE-1234ABCD.pf,TOOL.EXE,3,2026-01-02 12:00:00\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    run = execution_adapters.pecmd_prefetch_parser_run(
        csv_path=csv_path, normalized_output_dir=normalized,
        collector_run=_collector_run_with_root(root),
    )

    scope = run["coverage_scope"]
    assert scope["kind"] == "prefetch"
    assert scope["pf_file_count"] == 1
    assert scope["enable_prefetcher"] == 0 and scope["application_prefetch_enabled"] is False
    assert scope["sysmain_start_mode"] == "Disabled" and scope["sysmain_disabled"] is True
    assert scope["os_product_name"] == "Windows 10 Pro"
    shimcache = execution_adapters.shimcache_coverage_scope(
        _collector_run_with_root(root), csv_path=csv_path, record_count=1
    )
    assert shimcache["last_shutdown_time"] == "2026-01-05 00:00:00.0000000"


def test_shellbag_adapter_requires_the_raw_hive_for_complete_coverage(tmp_path: Path) -> None:
    root = tmp_path / "kape-output"
    csv_path = root / "modules" / "FileFolderAccess" / "alice_UsrClass.csv"
    csv_path.parent.mkdir(parents=True)
    csv_path.write_text(
        "BagPath,Slot,NodeSlot,MRUPosition,AbsolutePath,ShellType,Value,MFTEntry,MFTSequenceNumber\n"
        "BagMRU\\0,0,1,0,C:\\Users\\alice\\Gone\\,Directory,Gone,42,3\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()

    absent = registry_adapters.shellbag_parser_run(
        csv_path=csv_path, normalized_output_dir=normalized,
        collector_run=_collector_run_with_root(root),
    )
    assert absent["coverage_status"] == "partial"
    assert absent["coverage_scope"]["hive_present"] is False

    hive = root / "targets" / "F" / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
    hive.parent.mkdir(parents=True)
    hive.write_bytes(b"regf")
    present = registry_adapters.shellbag_parser_run(
        csv_path=csv_path, normalized_output_dir=tmp_path / "normalized2",
        collector_run=_collector_run_with_root(root),
    )
    assert present["coverage_status"] == "complete"
    assert present["coverage_scope"]["hive_present"] is True
    assert present["coverage_scope"]["hive_path"].endswith("UsrClass.dat")


def test_shimcache_time_keeps_its_meaning(tmp_path: Path) -> None:
    from fmb.analysis.evidence_projection import _MODEL_FIELDS_BY_OBSERVATION_TYPE

    csv_path = tmp_path / "shimcache.csv"
    csv_path.write_text(
        "ControlSet,CacheEntryPosition,Path,LastModifiedTimeUTC\n"
        "1,0,C:\\Users\\alice\\one.bat,2026-01-01 10:00:00\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    run = registry_path_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
        mft_context={"row_count": 0},
    )
    fields = run["observations"][0]["fields"]
    assert fields["last_modified_time_utc"] == "2026-01-01 10:00:00"
    shown = _MODEL_FIELDS_BY_OBSERVATION_TYPE["shimcache_path_seen"]
    assert "last_modified_time_utc" in shown and "timestamp" not in shown


def test_setupapi_setup_log_is_not_a_rotated_device_log(tmp_path: Path) -> None:
    inf = tmp_path / "targets" / "C" / "Windows" / "inf"
    inf.mkdir(parents=True)
    log_path = inf / "setupapi.dev.log"
    log_path.write_text(
        ">>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_ACME&Prod_Test\\SERIAL-1]\n"
        ">>>  Section start 2026/01/01 10:00:00.000\n"
        "<<<  Section end 2026/01/01 10:00:01.000\n"
        "<<<  [Exit status: SUCCESS]\n",
        encoding="utf-8",
    )
    (inf / "setupapi.setup.log").write_text(">>>  Section start 2023/01/01 00:00:00.000\n", encoding="utf-8")
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    run = registry_adapters.setupapi_parser_run(
        log_path=log_path, normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )
    assert run["coverage_scope"]["rotated_logs_present"] is False
    assert "setupapi.setup.log" in run["coverage_scope"]["retained_log_names"]


def test_changed_sequence_on_a_free_record_is_a_freed_entry_not_reuse() -> None:
    from fmb.index.adapters.mft import mft_active_presence_fields

    context = {"row_count": 1, "entry_sequences": {42: (4, False)}, "active_paths": set(),
               "active_basenames": set(), "indexed_volumes": {"c"}}
    freed = mft_active_presence_fields(subject=r"C:\Users\alice\gone.txt", file_reference=(42, 3), mft_context=context)
    context["entry_sequences"] = {42: (4, True)}
    reused = mft_active_presence_fields(subject=r"C:\Users\alice\gone.txt", file_reference=(42, 3), mft_context=context)
    assert freed.get("mft_active_presence_basis") == "file_reference_entry_freed"
    assert reused.get("mft_active_presence_basis") == "file_reference_entry_reused"
    assert freed["mft_active_presence_status"] == reused["mft_active_presence_status"] == "active_mft_absent"
