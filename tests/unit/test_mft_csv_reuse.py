from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from fmb.analysis import mft_comparison
from fmb.index.adapters import mft as mft_adapters
from fmb.index.adapters.mft import build_mft_presence_context, mft_row_full_path, mft_row_is_directory
from fmb.index.adapters.volume_binding import bind_native_volume
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
    monkeypatch.setattr(mft_comparison, "_IDENTIFIED_MFT_ROWS", {})
    monkeypatch.setattr(mft_adapters, "_MFT_ROW_SCANS", {})


def mft_root(tmp_path: Path, name: str = "kape", rows: str = ROWS, header: str = HEADER) -> Path:
    root = tmp_path / name
    (root / "modules").mkdir(parents=True)
    (root / "modules" / "MFTECmd_$MFT_Output.csv").write_text(header + rows, encoding="utf-8")
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


def test_native_volume_binding_leaves_the_callers_context_unchanged(tmp_path, monkeypatch):
    import fmb.index.adapters.volume_binding as volume_binding

    geometry = {"mft_record_size": 1024, "volume_serial_number": "0000000012345678"}
    monkeypatch.setattr(volume_binding, "load_native_surfaces", lambda manifest, raw: {
        "geometry": geometry, "boot_sector_sha256": "a" * 64, "raw_mft_sha256": "b" * 64, "boot_sector_file": "boot"})
    monkeypatch.setattr(volume_binding, "parse_mft_record", lambda raw, **_: {
        "file_name_attributes": [{"name": "$Volume"}], "metadata_timestamps": {"created": {"ntfs_filetime": 7}}})
    monkeypatch.setattr(volume_binding, "mft_record_is_in_use", lambda record: True)
    monkeypatch.setattr(volume_binding, "sha256_file", lambda path: "c" * 64)
    raw_mft = tmp_path / "$MFT"
    raw_mft.write_bytes(bytes(4096))
    context = build_mft_presence_context(mft_root(tmp_path))
    before = {key: type(value)(value) if isinstance(value, (set, dict, list)) else value for key, value in context.items()}

    bound = bind_native_volume(context, tmp_path / "native.json", raw_mft)
    bound["indexed_volumes"].add("d")

    assert context == before
    assert bound["indexed_volumes"] == {"volume{0000000000000007-12345678}", "d"}
    assert bound["native_volume_bindings"]["volume{0000000000000007-12345678}"]["native_volume_creation_filetime"] == 7


def test_comparison_pool_rows_are_read_once_per_csv_content(tmp_path, monkeypatch):
    root = mft_root(tmp_path)
    csv_path = mft_adapters.mftecmd_mft_context_csv_files(root)[0]
    scans = counted_scans(monkeypatch, mft_comparison)

    first = mft_comparison._identified_mft_rows(csv_path, "digest-1")
    again = mft_comparison._identified_mft_rows(csv_path, "digest-1")
    other = mft_comparison._identified_mft_rows(csv_path, "digest-2")

    assert len(scans) == 2
    assert first is again and first == other
    assert first == (
        (1, 5, 5, True, ".\\.", "."),
        (2, 41, 3, True, ".\\Users\\alice\\report.txt", "users\\alice\\report.txt"),
        (3, 42, 7, False, ".\\Users\\alice\\gone.txt", "users\\alice\\gone.txt"),
        (4, 43, 2, True, ".\\Users\\alice", "users\\alice"),
    )


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


MFT_HEADER = (
    "EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,FileName,IsDirectory,"
    "Created0x10,Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,"
    "LastAccess0x10,LastAccess0x30\n"
)
STAMP, EARLIER = "2024-01-02 03:04:05.1234567", "2023-01-02 03:04:05.1234567"


def mft_row(entry: int, parent: str, name: str, *, created_fn: str = STAMP, in_use: str = "True",
            directory: str = "False") -> str:
    return (f"{entry},2,{in_use},5,5,{parent},{name},{directory},{STAMP},{created_fn},"
            + ",".join([STAMP] * 6) + "\n")


# Timestamp-candidate scores 160, 125, -150, -150 and 160; rows 1 to 3 have an SI/FN mismatch.
RANKED_ROWS = "".join((
    mft_row(41, ".\\Users\\alice\\Desktop", "report.docx", created_fn=EARLIER),
    mft_row(42, ".\\Users\\alice", "notes.txt", created_fn=EARLIER),
    mft_row(43, ".\\Windows\\System32", "a.dll", created_fn=EARLIER),
    mft_row(44, ".\\Windows\\System32", "b.dll"),
    mft_row(45, ".\\Users\\alice\\Desktop", "c.txt"),
    mft_row(46, ".\\Users\\alice\\Desktop", "folder", directory="True"),
    mft_row(47, ".\\Users\\alice", "gone.txt", in_use="False"),
))
PUBLIC = frozenset({
    "C:\\Users\\alice\\Desktop\\report.docx", "C:\\Users\\alice\\notes.txt", "C:\\Windows\\System32\\a.dll",
    "C:\\Windows\\System32\\b.dll", "C:\\Users\\alice\\Desktop\\c.txt", "C:\\Users\\alice\\Desktop\\folder",
    "C:\\Users\\alice\\gone.txt",
})


def mft_parser_run(tmp_path: Path, csv_path: Path, folder: str, public: frozenset[str] = frozenset()) -> dict:
    raw_mft = tmp_path / "$MFT"
    if not raw_mft.exists():
        raw_mft.write_bytes(bytes(64 * 1024))
    return mft_adapters.mftecmd_mft_parser_run(
        csv_path=csv_path, raw_mft_path=raw_mft, normalized_output_dir=tmp_path / folder,
        collector_run={"collector": "kape", "modules": []}, public_paths=public)


def counted_row_scans(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    scans: list[Path] = []
    original = mft_adapters._scan_mft_rows

    def counting(csv_path: Path, **options):
        scans.append(csv_path)
        return original(csv_path, **options)

    monkeypatch.setattr(mft_adapters, "_scan_mft_rows", counting)
    return scans


def rows_of(run: dict, observation_type: str) -> set[int]:
    return {item["fields"]["row_index"] for item in run["observations"] if item["observation_type"] == observation_type}


@pytest.mark.parametrize("limits", [(3, 1), (1, 3)])
def test_public_rows_are_observed_as_the_one_read_of_the_csv_observed_them(tmp_path, monkeypatch, limits):
    monkeypatch.setattr(mft_adapters, "MAX_MFT_IDENTITY_OBSERVATIONS", limits[0])
    monkeypatch.setattr(mft_adapters, "MAX_MFT_TIMESTAMP_OBSERVATIONS", limits[1])
    csv_path = mft_adapters.mftecmd_mft_context_csv_files(mft_root(tmp_path, rows=RANKED_ROWS, header=MFT_HEADER))[0]
    scans = counted_row_scans(monkeypatch)

    plain = mft_parser_run(tmp_path, csv_path, "plain")
    public = mft_parser_run(tmp_path, csv_path, "public", PUBLIC)
    monkeypatch.setattr(mft_adapters, "_MFT_ROW_SCANS", {})
    fresh = mft_parser_run(tmp_path, csv_path, "fresh", PUBLIC)

    assert len(scans) == 2
    ranked, ranked_times = rows_of(plain, "mft_file_record"), rows_of(plain, "si_fn_timestamp_difference")
    # Ranked in one list but not the other with a mismatch, and in neither list.
    assert ranked - ranked_times & {1, 2, 3} if limits == (3, 1) else ranked_times - ranked
    assert {1, 2, 3, 4, 5} - ranked - ranked_times
    assert rows_of(public, "mft_file_record") == {1, 2, 3, 4, 5}
    assert rows_of(public, "si_fn_timestamp_difference") == {1, 2, 3}
    for row_index in (1, 2, 3, 4, 5):
        observations = [item for item in public["observations"] if item["fields"]["row_index"] == row_index]
        # Both observations of a row share their fields, so the raw $MFT check reaches both.
        assert len({id(item["fields"]) for item in observations}) == 1
        assert observations[0]["fields"]["raw_mft_timestamp_validation"] == "failed"
    assert public["observations"] == fresh["observations"]
    assert public["candidate_populations"] == fresh["candidate_populations"]


def test_parser_run_ranks_again_when_the_csv_changes_and_keeps_callers_apart(tmp_path, monkeypatch):
    csv_path = mft_adapters.mftecmd_mft_context_csv_files(mft_root(tmp_path, rows=RANKED_ROWS, header=MFT_HEADER))[0]
    first = mft_parser_run(tmp_path, csv_path, "first", PUBLIC)
    expected = json.dumps(first["observations"])
    for observation in first["observations"]:
        observation["fields"]["mismatches"].append({"field": "changed by the first caller"})
        observation["fields"]["subject"] = "changed by the first caller"
    status = csv_path.stat()
    scans = counted_row_scans(monkeypatch)

    again = mft_parser_run(tmp_path, csv_path, "again", PUBLIC)
    csv_path.write_text(MFT_HEADER + RANKED_ROWS.replace("notes.txt", "nopes.txt"), encoding="utf-8")
    os.utime(csv_path, ns=(status.st_atime_ns, status.st_mtime_ns))
    changed = mft_parser_run(tmp_path, csv_path, "changed", PUBLIC)

    assert json.dumps(again["observations"]) == expected
    assert len(scans) == 1 and csv_path.stat().st_size == status.st_size
    assert "nopes.txt" in json.dumps(changed["observations"]) and "notes.txt" not in json.dumps(changed["observations"])
