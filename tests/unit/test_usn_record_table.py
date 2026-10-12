from __future__ import annotations

import json
import os
import struct
from pathlib import Path

import pytest

from fmb.collection import analysis, factual_challenge
from fmb.core.ntfs_time import filetime_to_utc_iso
from fmb.index.adapters import usn as usn_adapters
from fmb.index.adapters.mft import build_mft_presence_context
from fmb.index.scanners import usn
from fmb.pipeline import reads

FILETIME = 132223104000000000
BASE = 8192
NAMES = ("gone.txt", "kept.txt", "evidence.docx", "setup.dll")
REASONS = (0x200 | 0x80000000, 0x8000, 0x1000, 0x100, 0x2)


def record(offset: int, index: int) -> bytes:
    name = NAMES[index % len(NAMES)].encode("utf-16le")
    length = (60 + len(name) + 7) // 8 * 8
    entry, sequence = 40 + index % len(NAMES), 1 + index % len(NAMES)
    return (struct.pack('<IHHQQqQIIIIHH', length, 2, 0, (sequence << 48) | entry, (1 << 48) | 30,
                        BASE + offset, FILETIME + index * 10_000_000, REASONS[index % len(REASONS)],
                        0, 0, 0, len(name), 60)
            + name + bytes(length - 60 - len(name)))


def journal_bytes(count: int = 40) -> bytes:
    data = bytearray()
    for index in range(count):
        data.extend(record(len(data), index))
    return bytes(data)


@pytest.fixture(autouse=True)
def empty_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    # Other tests in the same worker may have scanned a journal with these bytes already.
    monkeypatch.setattr(usn_adapters, "_USN_RECORD_TABLES", {})


def collected(tmp_path: Path, data: bytes, name: str = "kape-output") -> tuple[Path, dict]:
    root = tmp_path / name
    path = root / "targets" / "C" / "$Extend" / "$J"
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    csv = root / "modules" / "MFTECmd_$MFT_Output.csv"
    csv.parent.mkdir(parents=True)
    csv.write_text("EntryNumber,SequenceNumber,InUse,ParentPath,FileName,IsDirectory\n"
                   "30,1,True,.\\Users\\u,docs,True\n"
                   + "".join(f"{40 + n},{1 + n},True,.\\Users\\u\\docs,{name},False\n"
                             for n, name in enumerate(NAMES)), encoding="utf-8")
    return path, {"collector": "kape", "output_root": str(root)}


def counted_tables(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    built: list[int] = []
    original = usn_adapters.usn_record_table

    def counting(reader, **options):
        built.append(options["stream_size_bytes"])
        return original(reader, **options)

    monkeypatch.setattr(usn_adapters, "usn_record_table", counting)
    return built


def masked(text: str, output: Path) -> str:
    # The run's folder as written, and as JSON writes it (with a Windows path's backslashes escaped).
    return text.replace(json.dumps(str(output))[1:-1], "<output>").replace(str(output), "<output>")


def run_scans(path: Path, collector: dict, output: Path) -> dict:
    # The journal uses of one S2 run: the journal parser run with its order check, two
    # reference-scoped runs and the factual supplement's public membership scan.
    context = build_mft_presence_context(Path(collector["output_root"]))
    results = {"journal": usn_adapters.raw_usn_journal_parser_run(
        journal_path=path, normalized_output_dir=output / "normalized", collector_run=collector,
        mft_context=context)}
    for index, references in enumerate(({(40, 1), (41, 2)}, {(42, 3)})):
        results[f"reference-{index}"] = usn_adapters.raw_usn_reference_parser_run(
            journal_path=path, normalized_output_dir=output / "normalized", collector_run=collector,
            references=references, filesystem_scope_id=context["mft_volume_id"], mft_context=context)
    (output / "factual").mkdir(parents=True)
    original = analysis._raw_usn_journal_path
    analysis._raw_usn_journal_path = lambda _index: path
    try:
        results["membership"] = factual_challenge._membership_usn_run(
            {"collector_runs": [collector]},
            {"members": [{"question_id": "BQ-DELETE-01", "path": "C:\\Users\\u\\docs\\gone.txt"}]},
            output / "factual", context)
    finally:
        analysis._raw_usn_journal_path = original
    results["files"] = {path.relative_to(output).as_posix(): masked(path.read_text(encoding="utf-8"), output)
                        for path in sorted(output.rglob("*")) if path.is_file()}
    return json.loads(masked(json.dumps(results, default=str), output))


def test_a_run_scans_its_journal_once_and_writes_what_a_scan_per_use_writes(tmp_path, monkeypatch):
    path, collector = collected(tmp_path, journal_bytes())
    built = counted_tables(monkeypatch)

    shared = run_scans(path, collector, tmp_path / "shared")
    assert built == [path.stat().st_size]

    # The same uses, each scanning the journal itself, as before the table was kept.
    original = usn_adapters.raw_usn_record_table
    monkeypatch.setattr(usn_adapters, "raw_usn_record_table",
                        lambda journal: (usn_adapters._USN_RECORD_TABLES.clear(), original(journal))[1])
    monkeypatch.setattr(factual_challenge, "raw_usn_record_table", usn_adapters.raw_usn_record_table)
    separate = run_scans(path, collector, tmp_path / "separate")

    assert len(built) == 5 and shared == separate
    assert shared["membership"]["observations"] and shared["reference-0"]["observations"]


def test_a_journal_is_scanned_again_when_its_bytes_change(tmp_path, monkeypatch):
    data = journal_bytes()
    path, _collector = collected(tmp_path, data)
    built = counted_tables(monkeypatch)
    before = usn_adapters.raw_usn_record_table(path)
    status = path.stat()
    # Same size and timestamps, other bytes: the cache key is the content, not the file's metadata.
    path.write_bytes(data.replace("gone.txt".encode("utf-16le"), "lost.txt".encode("utf-16le")))
    os.utime(path, ns=(status.st_atime_ns, status.st_mtime_ns))

    after = usn_adapters.raw_usn_record_table(path)

    assert len(built) == 2 and usn_adapters.raw_usn_record_table(path) is after
    assert "gone.txt" in before.file_names and "gone.txt" not in after.file_names
    assert list(usn_adapters._USN_RECORD_TABLES.values()) == [after]


def test_the_cache_keeps_only_the_last_journal(tmp_path):
    first, _ = collected(tmp_path, journal_bytes(), "first")
    second, _ = collected(tmp_path, journal_bytes(12), "second")

    usn_adapters.raw_usn_record_table(first)
    kept = usn_adapters.raw_usn_record_table(second)

    assert list(usn_adapters._USN_RECORD_TABLES.values()) == [kept]


def test_callers_never_change_the_kept_table(tmp_path):
    path, collector = collected(tmp_path, journal_bytes())
    table = usn_adapters.raw_usn_record_table(path)
    with pytest.raises(TypeError):
        table.scan["parsed_record_count"] = 0
    data = path.read_bytes()

    def reader(offset, size):
        return data[offset:offset + size]

    records, _stats = usn.scan_usn_records_by_reason(reader, stream_size_bytes=len(data), table=table)
    records[0]["reason_labels"].append("changed by the first caller")
    retained, _stats = usn.scan_usn_records_for_references(reader, stream_size_bytes=len(data),
                                                           references={(40, 1)}, table=table)
    retained[0]["file_name"] = "changed by the first caller"

    assert usn.scan_usn_records_by_reason(reader, stream_size_bytes=len(data), table=table)[0] == \
        usn.scan_usn_records_by_reason(reader, stream_size_bytes=len(data))[0]
    assert all(record["file_name"] == "gone.txt" for record in usn.scan_usn_records_for_references(
        reader, stream_size_bytes=len(data), references={(40, 1)}, table=table)[0])


def test_a_step_that_finds_the_table_kept_records_the_journal_read(tmp_path, monkeypatch):
    path, collector = collected(tmp_path, journal_bytes())

    def opened(output: Path) -> set[str]:
        with reads.measured() as files:
            run_scans(path, collector, output)
        # write_json's temporary files have random names.
        return {masked(name, output) for name in files if not name.endswith(".tmp")}

    usn_adapters.raw_usn_record_table(path)
    kept = opened(tmp_path / "kept")
    original = usn_adapters.raw_usn_record_table
    monkeypatch.setattr(usn_adapters, "raw_usn_record_table",
                        lambda journal: (usn_adapters._USN_RECORD_TABLES.clear(), original(journal))[1])
    monkeypatch.setattr(factual_challenge, "raw_usn_record_table", usn_adapters.raw_usn_record_table)
    scanned_each_time = opened(tmp_path / "scanned")

    assert kept == scanned_each_time and str(path) in kept


def test_a_table_record_has_a_timestamp_exactly_when_the_parser_writes_one():
    assert filetime_to_utc_iso(usn._MAX_ISO_FILETIME) is not None
    assert filetime_to_utc_iso(usn._MAX_ISO_FILETIME + 1) is None
