from __future__ import annotations

import csv
from pathlib import Path

import pytest

from fmb.index.adapters.event_log import evtxecmd_security_clear_observation
from fmb.index.adapters.execution import (
    pecmd_prefetch_parser_run,
    registry_path_parser_run,
)
from fmb.index.adapters.mft import mft_active_presence_fields
from fmb.index.adapters.registry import typed_paths_parser_run


def write_row(path: Path, row: dict[str, str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)


@pytest.mark.parametrize("key_column", ["KeyPath", "BatchKeyPath"])
def test_typed_paths_keeps_native_registry_value_and_hive(
    tmp_path: Path, key_column: str
) -> None:
    key = r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
    value = r"c:\users\alice\Desktop\folder"
    hive = r"F:\Users\alice\NTUSER.DAT"
    path = tmp_path / "RECmd.csv"
    write_row(
        path,
        {
            key_column: key,
            "ValueName": "url1",
            "ValueType": "RegSz",
            "ValueData": value,
            "HivePath": hive,
            "HiveType": "NtUser",
        },
    )
    run = typed_paths_parser_run(
        csv_path=path,
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )
    assert len(run["observations"]) == 1
    record = run["observations"][0]
    assert record["subject_ref"] == value
    expected = {
        "source_key": key,
        "key_path": key,
        "value_name": "url1",
        "value_type": "RegSz",
        "value_data": value,
        "hive_path": hive,
        "hive_type": "NtUser",
    }
    assert {name: record["fields"][name] for name in expected} == expected


def test_shimcache_keeps_native_path_source_without_inventing_registry_key(
    tmp_path: Path,
) -> None:
    path = tmp_path / "AppCompatCache.csv"
    executable = r"C:\Tools\tool.exe"
    source = r"F:\Windows\System32\config\SYSTEM"
    write_row(
        path,
        {
            "ControlSet": "ControlSet001",
            "CacheEntryPosition": "7",
            "Path": executable,
            "LastModifiedTimeUTC": "2026-08-28 04:39:35",
            "SourceFile": source,
        },
    )
    run = registry_path_parser_run(
        csv_path=path,
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )
    fields = run["observations"][0]["fields"]
    assert fields["path"] == executable
    assert fields["source_file"] == source
    assert fields["control_set"] == "ControlSet001"
    assert fields["cache_entry_position"] == "7"
    assert fields["timestamp"] == "2026-08-28 04:39:35"
    assert {"key_path", "hive_path", "value_name", "value_data"}.isdisjoint(fields)


def test_prefetch_retains_actual_sourcefilename_and_native_loaded_paths(
    tmp_path: Path,
) -> None:
    path = tmp_path / "PECmd.csv"
    source = r"F:\Windows\Prefetch\TOOL.EXE-01234567.pf"
    loaded = r"C:\Windows\System32\ntdll.dll|C:\Tools\TOOL.EXE"
    write_row(
        path,
        {
            "ExecutableName": "TOOL.EXE",
            "SourceFilename": source,
            "FilesLoaded": loaded,
            "RunCount": "2",
            "LastRun": "2026-08-28 11:41:16.0152325",
        },
    )
    run = pecmd_prefetch_parser_run(
        csv_path=path,
        normalized_output_dir=tmp_path / "normalized",
        collector_run={"collector": "kape", "provenance": {}},
    )
    record = run["observations"][0]
    assert record["subject_ref"] == r"C:\Tools\TOOL.EXE"
    assert record["fields"]["source_file"] == source
    assert record["fields"]["files_loaded"] == loaded
    assert "native_executable_path" not in record["fields"]
    assert record["fields"]["mft_lookup_target"] == {
        "target_role": "candidate", "path": r"C:\Tools\TOOL.EXE"
    }
    assert record["fields"]["mft_active_presence_check_supported"] is False


@pytest.mark.parametrize("time_column", ["TimeCreated", "Timestamp", "Date"])
def test_security_event_retains_native_timestamp_and_available_event_fields(
    time_column: str,
) -> None:
    native_time = "2026-08-28 11:41:29.6246067"
    record = evtxecmd_security_clear_observation(
        csv_path=Path("EvtxECmd.csv"),
        row_index=3,
        row={
            time_column: native_time,
            "Provider": "Microsoft-Windows-Eventlog",
            "Computer": "HOST",
            "UserId": "S-1-5-18",
        },
        event_id=1102,
        record_id=43217,
        channel="Security",
        source_file=r"F:\Windows\System32\winevt\logs\Security.evtx",
    )
    assert record is not None
    assert record["fields"]["time_created"] == native_time
    assert record["fields"]["timestamp"] == native_time
    assert record["fields"]["computer"] == "HOST"
    assert record["fields"]["user_id"] == "S-1-5-18"
    assert "process_id" not in record["fields"]


def test_mft_lookup_identifies_requested_generation_and_observed_reuse() -> None:
    fields = mft_active_presence_fields(
        subject=r"C:\Tools\old.exe",
        file_reference=(42, 3),
        mft_context={
            "row_count": 1,
            "mft_volume_id": "volume-c",
            "indexed_volumes": {"c"},
            "entry_sequences": {42: (4, True)},
        },
    )
    assert fields["mft_lookup_target"] == {
        "target_role": "candidate",
        "path": r"C:\Tools\old.exe",
        "mft_volume_id": "volume-c",
        "object_id": "ntfs:volume-c:42:3",
    }
    assert fields["mft_lookup_observed"] == {"entry": 42, "sequence": 4, "in_use": True}
    assert fields["mft_active_presence_basis"] == "file_reference_entry_reused"
