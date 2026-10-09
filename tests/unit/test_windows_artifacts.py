from __future__ import annotations

from pathlib import Path

import pytest

from fmb.index.support import windows_artifacts


def test_windows_artifact_helpers_score_and_normalize_rows(tmp_path: Path) -> None:
    csv_path = tmp_path / "rows.csv"
    csv_path.write_text(
        "FileName,ParentPath,Created0x10,Created0x30\n"
        "evidence.txt,C:\\\\Users\\\\alice\\\\Desktop,2026-01-02 03:04:05,2025-01-02 03:04:05\n",
        encoding="utf-8",
    )

    rows = list(windows_artifacts.stream_csv_rows(csv_path))
    row = rows[0]
    assert windows_artifacts.sanitize_csv_row(
        {"zero": 0, "false": False, "none": None}
    ) == {
        "zero": "0",
        "false": "False",
        "none": "",
    }
    assert windows_artifacts.first_nonempty(None, "  x  ") == "x"
    assert windows_artifacts.safe_path_component("a/b:c") == "a_b_c"
    assert windows_artifacts.row_value(row, "filename") == "evidence.txt"
    assert windows_artifacts.parse_csv_timestamp("2026-01-02 03:04:05.123").year == 2026
    assert (
        windows_artifacts.parse_csv_timestamp("2026-01-02T03:04:05.123Z").year == 2026
    )
    assert not windows_artifacts.timestamp_semantically_equal(
        "2026-01-02 03:04:05",
        "2026-01-02T03:04:05.999Z",
    )
    assert windows_artifacts.parse_csv_timestamp("bad") is None
    assert windows_artifacts.windows_suffix("C:/Temp/THING.TXT") == ".txt"
    assert (
        windows_artifacts.user_path_score(r"C:\Users\alice\Desktop\evidence.txt") > 80
    )
    assert windows_artifacts.user_path_score(r"C:\Windows\System32\kernel32.dll") < 0
    assert windows_artifacts.row_recency_score(row, "Created0x10") == 90
    assert (
        windows_artifacts.score_candidate_name("evidence.docx", purpose="timestomp")
        > 80
    )
    assert (
        windows_artifacts.score_candidate_name("SVCHOST.EXE-ABC.pf", purpose="prefetch")
        < 0
    )
    assert (
        windows_artifacts.score_candidate_name(
            "recent document", purpose="registry_mru"
        )
        > 0
    )
    with pytest.raises(ValueError, match="unsupported candidate scoring purpose"):
        windows_artifacts.score_candidate_name("recent document", purpose="unknown")
    assert windows_artifacts.mft_path(row).endswith(r"Desktop\evidence.txt")
    assert (
        windows_artifacts.mft_path(
            {
                "ParentPath": r"C:\Users\alice",
                "FileName": r"C:\Users\alice\Desktop\evidence.txt",
            }
        )
        == r"C:\Users\alice\Desktop\evidence.txt"
    )
    assert (
        windows_artifacts.mft_path(
            {
                "FullPath": r"C:\Users\alice\Desktop\evidence.txt",
                "FileName": "other.txt",
            }
        )
        == r"C:\Users\alice\Desktop\evidence.txt"
    )
    mismatches = windows_artifacts.mft_timestamp_mismatches(row)
    assert mismatches == [
        {
            "field": "created",
            "standard_information": "2026-01-02 03:04:05",
            "file_name": "2025-01-02 03:04:05",
        }
    ]
    assert windows_artifacts.max_timestamp_mismatch_gap_days(mismatches) == 365


def test_timestamp_equality_preserves_the_seventh_fractional_digit() -> None:
    assert not windows_artifacts.timestamp_semantically_equal(
        "2026-01-02T03:04:05.1234566Z",
        "2026-01-02T03:04:05.1234567Z",
    )

    assert windows_artifacts.mft_timestamp_mismatches(
        {
            "Created0x10": "2026-01-02T03:04:05.1234566Z",
            "Created0x30": "2026-01-02T03:04:05.1234567Z",
        }
    ) == [
        {
            "field": "created",
            "standard_information": "2026-01-02T03:04:05.1234566Z",
            "file_name": "2026-01-02T03:04:05.1234567Z",
        }
    ]


def test_timestamp_equality_normalizes_explicit_offsets_exactly() -> None:
    assert windows_artifacts.timestamp_semantically_equal(
        "2026-01-02T03:04:05.1234567+01:30",
        "2026-01-02T01:34:05.1234567Z",
    )
    assert (
        windows_artifacts.mft_timestamp_mismatches(
            {
                "Created0x10": "2026-01-02T03:04:05.1234567+01:30",
                "Created0x30": "2026-01-02T01:34:05.1234567Z",
            }
        )
        == []
    )


def test_malformed_timestamps_are_not_semantically_equal() -> None:
    assert not windows_artifacts.timestamp_semantically_equal(
        "not-a-timestamp",
        "not-a-timestamp",
    )


def test_max_timestamp_gap_floors_after_taking_absolute_duration() -> None:
    mismatches = [
        {
            "field": "created",
            "standard_information": "2026-01-01 00:00:00",
            "file_name": "2026-12-31 00:00:01",
        }
    ]

    assert windows_artifacts.max_timestamp_mismatch_gap_days(mismatches) == 364
