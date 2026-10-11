from __future__ import annotations

import os
from pathlib import Path

import pytest

from fmb.index.adapters import mft as mft_adapters
from fmb.index.adapters.mft import build_mft_presence_context, mft_row_full_path, mft_row_is_directory
from fmb.index.support.windows_artifacts import (
    FoldedRow,
    folded_row,
    row_first,
    row_value,
    stream_csv_rows,
    stream_folded_csv_rows,
)
from fmb.index.support.windows_identity import ntfs_reference_from_row

HEADER = "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,IsDirectory\n"
ROWS = (
    "5,5,True,.,.,True\n"
    "41,3,True,.\\Users\\alice,report.txt,False\n"
    "42,7,False,.\\Users\\alice,gone.txt,False\n"
    "43,2,True,.\\Users,alice,True\n"
)


@pytest.fixture(autouse=True)
def empty_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    # Other tests in the same worker may have read a CSV with these bytes already.
    monkeypatch.setattr(mft_adapters, "_MFT_PRESENCE_CONTEXT_CACHE", {})


def mft_root(tmp_path: Path, name: str = "kape", rows: str = ROWS) -> Path:
    root = tmp_path / name
    (root / "modules").mkdir(parents=True)
    (root / "modules" / "MFTECmd_$MFT_Output.csv").write_text(HEADER + rows, encoding="utf-8")
    return root


def counted_scans(monkeypatch: pytest.MonkeyPatch, module) -> list[Path]:
    scans: list[Path] = []
    original = module.stream_folded_csv_rows

    def counting(path: Path):
        scans.append(path)
        return original(path)

    monkeypatch.setattr(module, "stream_folded_csv_rows", counting)
    return scans


def test_presence_context_reads_one_csv_once_and_equals_a_fresh_scan(tmp_path, monkeypatch):
    root = mft_root(tmp_path)
    csv_path = mft_adapters.mftecmd_mft_context_csv_files(root)
    fresh = mft_adapters._scan_mft_presence_context(csv_path)
    scans = counted_scans(monkeypatch, mft_adapters)

    first = build_mft_presence_context(root)
    second = build_mft_presence_context(root)

    assert len(scans) == 1
    assert first == second == fresh
    assert first["row_count"] == 4 and first["active_refs"] == {(5, 5), (41, 3), (43, 2)}


def test_presence_context_is_read_again_when_the_csv_changes(tmp_path, monkeypatch):
    root = mft_root(tmp_path)
    csv_path = mft_adapters.mftecmd_mft_context_csv_files(root)[0]
    before = build_mft_presence_context(root)
    status = csv_path.stat()
    # Same size and timestamps, other bytes: the cache key is the content, not the file's metadata.
    csv_path.write_text(HEADER + ROWS.replace("41,3,True", "41,3,Fals"), encoding="utf-8")
    os.utime(csv_path, ns=(status.st_atime_ns, status.st_mtime_ns))
    assert csv_path.stat().st_size == status.st_size
    scans = counted_scans(monkeypatch, mft_adapters)

    after = build_mft_presence_context(root)

    assert len(scans) == 1
    assert (41, 3) in before["active_refs"] and (41, 3) not in after["active_refs"]
    assert after["malformed_reference_row_count"] == 1
    assert after["mft_volume_id"] != before["mft_volume_id"]


def test_presence_context_callers_never_share_containers(tmp_path):
    root = mft_root(tmp_path)
    first = build_mft_presence_context(root)
    for key, value in first.items():
        if isinstance(value, set):
            value.add("changed by the first caller")
        elif isinstance(value, dict):
            value["changed"] = "by the first caller"
        elif isinstance(value, list):
            value.append("changed by the first caller")
    first["indexed_volumes"] = {"z"}
    second = build_mft_presence_context(root)

    assert second == mft_adapters._scan_mft_presence_context(mft_adapters.mftecmd_mft_context_csv_files(root))
    assert all(second[key] is not value for key, value in first.items() if isinstance(value, (set, dict, list)))


def test_presence_context_names_the_csv_as_each_caller_reached_it(tmp_path):
    first_root = mft_root(tmp_path, "first")
    second_root = mft_root(tmp_path, "second")

    first = build_mft_presence_context(first_root)
    second = build_mft_presence_context(second_root)

    assert first["source_paths"] == [str(mft_adapters.mftecmd_mft_context_csv_files(first_root)[0])]
    assert second["source_paths"] == [str(mft_adapters.mftecmd_mft_context_csv_files(second_root)[0])]
    assert {**first, "source_paths": []} == {**second, "source_paths": []}


def test_presence_context_without_a_unique_csv_is_empty(tmp_path):
    context = build_mft_presence_context(tmp_path)

    assert context["row_count"] == 0 and context["source_paths"] == [] and context["mft_volume_id"] is None


def test_folded_rows_answer_every_row_helper_as_the_raw_row_does(tmp_path):
    csv_path = tmp_path / "rows.csv"
    csv_path.write_text(
        "ENTRYNUMBER,entrynumber,SequenceNumber,In Use,ParentPath,FileName,FileAttributes,Extra\n"
        "1,2,3,true,.\\Users,a.txt,Directory|Archive,x,overflow\n"
        ",9,4,,,,\n",
        encoding="utf-8",
    )
    for raw, folded in zip(stream_csv_rows(csv_path), stream_folded_csv_rows(csv_path), strict=True):
        assert type(folded) is FoldedRow and folded == folded_row(raw)
        assert folded_row(folded) is folded
        for keys in (("EntryNumber",), ("In Use", "InUse"), ("Missing", "FileName"), ("extra",)):
            assert row_value(folded, *keys) == row_value(raw, *keys)
            assert row_first(folded, *keys) == row_first(raw, *keys)
        assert mft_row_full_path(folded) == mft_row_full_path(raw)
        assert mft_row_is_directory(folded) == mft_row_is_directory(raw)
        assert ntfs_reference_from_row(folded, entry_keys=("EntryNumber",), sequence_keys=("SequenceNumber",)) == \
            ntfs_reference_from_row(raw, entry_keys=("EntryNumber",), sequence_keys=("SequenceNumber",))
