from __future__ import annotations

import heapq
import json
import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from fmb.core.hashing import sha256_bytes
from fmb.core.ntfs_time import filetime_to_utc_iso
from fmb.index.support.windows_identity import split_ntfs_file_reference

DEFAULT_SCAN_CHUNK_SIZE = 4 * 1024 * 1024

MAX_USN_RECORD_LENGTH = 65536

USN_RECORD_V2_HEADER_SIZE = 60

DEFAULT_TRUTH_BLIND_REASON_LABELS = (
    "FILE_DELETE",
    "RENAME_OLD_NAME",
    "BASIC_INFO_CHANGE",
)

USN_REASON_SCANNER = {
    "name": "fmb.usn.truth_blind_record_scanner",
    "version": "0.1.0",
    "scope": "truth_blind_usn_record_v2_signature_scan_by_reason_label",
}

MAX_REFERENCE_RECORDS = 250_000

USN_RECORD_V2_MAJOR_SIGNATURE = b"\x02\x00\x00\x00"

RankedUsnRecord = tuple[tuple[int, str, int], int, dict[str, Any]]

USN_REASON_LABELS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x80000000: "CLOSE",
}


def reason_labels(reason: int) -> list[str]:
    return [label for flag, label in sorted(USN_REASON_LABELS.items()) if reason & flag]


def usn_record_v2_length(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + USN_RECORD_V2_HEADER_SIZE > len(data):
        return None
    record_length = struct.unpack_from("<I", data, offset)[0]
    if (
        record_length < USN_RECORD_V2_HEADER_SIZE
        or record_length > MAX_USN_RECORD_LENGTH
    ):
        return None
    if offset + record_length > len(data):
        return None
    return record_length


def decode_usn_record_v2_name(
    data: bytes,
    *,
    offset: int,
    record_length: int,
    file_name_offset: int,
    file_name_length: int,
) -> str | None:
    if file_name_length <= 0 or file_name_length % 2:
        return None
    if file_name_offset < USN_RECORD_V2_HEADER_SIZE:
        return None
    file_name_end = file_name_offset + file_name_length
    if file_name_end > record_length:
        return None
    raw_name = data[offset + file_name_offset : offset + file_name_end]
    try:
        file_name = raw_name.decode("utf-16le")
    except UnicodeDecodeError:
        return None
    if not file_name or "\x00" in file_name:
        return None
    return file_name


def parse_usn_record_v2(
    data: bytes,
    offset: int = 0,
    *,
    absolute_offset: int | None = None,
) -> dict[str, Any] | None:
    record_length = usn_record_v2_length(data, offset)
    if record_length is None:
        return None
    (
        _record_length,
        major_version,
        minor_version,
        file_reference_number,
        parent_file_reference_number,
        usn,
        timestamp_filetime,
        reason,
        source_info,
        security_id,
        file_attributes,
        file_name_length,
        file_name_offset,
    ) = struct.unpack_from("<IHHQQqQIIIIHH", data, offset)
    if major_version != 2:
        return None
    file_name = decode_usn_record_v2_name(
        data,
        offset=offset,
        record_length=record_length,
        file_name_offset=file_name_offset,
        file_name_length=file_name_length,
    )
    if file_name is None:
        return None
    return {
        "record_offset": int(
            absolute_offset if absolute_offset is not None else offset
        ),
        "record_length": int(record_length),
        "major_version": int(major_version),
        "minor_version": int(minor_version),
        "file_reference_number": int(file_reference_number),
        "parent_file_reference_number": int(parent_file_reference_number),
        "usn": int(usn),
        "timestamp_filetime": int(timestamp_filetime),
        "timestamp_utc": filetime_to_utc_iso(int(timestamp_filetime)),
        "reason": int(reason),
        "reason_labels": reason_labels(int(reason)),
        "source_info": int(source_info),
        "security_id": int(security_id),
        "file_attributes": int(file_attributes),
        "file_name_length": int(file_name_length),
        "file_name_offset": int(file_name_offset),
        "file_name": file_name,
        "parser_status": "parsed",
        "parser_status_reason": "usn_record_v2_parsed",
    }


def usn_record_review_score(record: dict[str, Any]) -> int:
    labels = {str(label) for label in record.get("reason_labels", [])}
    score = 0
    if "FILE_DELETE" in labels:
        score += 120
    if "RENAME_OLD_NAME" in labels:
        score += 95
    if "BASIC_INFO_CHANGE" in labels:
        score += 90
    if "CLOSE" in labels:
        score += 10
    name = str(record.get("file_name", ""))
    folded = name.casefold()
    suffix = Path(name).suffix.casefold()
    if suffix in {".txt", ".doc", ".docx", ".pdf", ".xlsx", ".csv", ".bat", ".ps1"}:
        score += 45
    elif suffix in {".dll", ".sys", ".mui", ".manifest", ".cat", ".mum"}:
        score -= 35
    if any(
        token in folded
        for token in ("evidence", "confidential", "secret", "stolen", "script")
    ):
        score += 25
    if any(token in folded for token in ("microsoft-windows", "winsxs", "system32")):
        score -= 45
    return score


def usn_scan_chunks(
    reader: Callable[[int, int], bytes],
    *,
    stream_size_bytes: int,
    chunk_size_bytes: int,
    overlap: int,
) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset < stream_size_bytes:
        read_size = min(chunk_size_bytes + overlap, stream_size_bytes - offset)
        chunk = reader(offset, read_size)
        if not chunk:
            break
        yield offset, chunk
        offset += chunk_size_bytes


def usn_record_candidate_offsets(
    chunk: bytes,
    *,
    base_offset: int,
) -> Iterator[tuple[int, int]]:
    search_start = 0
    while True:
        signature_offset = chunk.find(USN_RECORD_V2_MAJOR_SIGNATURE, search_start)
        if signature_offset < 0:
            break
        search_start = signature_offset + 1
        if signature_offset < 4:
            continue
        record_relative_offset = signature_offset - 4
        yield record_relative_offset, base_offset + record_relative_offset


def usn_unsupported_record_offsets(chunk: bytes, *, base_offset: int) -> Iterator[int]:
    for signature in (b"\x03\x00\x00\x00", b"\x04\x00\x00\x00"):
        search_start = 0
        while (found := chunk.find(signature, search_start)) >= 0:
            search_start = found + 1
            start = found - 4
            if start < 0 or (base_offset + start) % 8 or start + 0x50 > len(chunk):
                continue
            length = struct.unpack_from("<I", chunk, start)[0]
            if length % 8 or not 0x50 <= length <= MAX_USN_RECORD_LENGTH or start + length > len(chunk):
                continue
            if chunk[found] == 3:
                name_length, name_offset = struct.unpack_from("<HH", chunk, start + 0x48)
                plausible = name_offset == 0x4C and name_length and not name_length % 2 and 0x4C + name_length <= length
            else:
                extents, extent_size = struct.unpack_from("<HH", chunk, start + 0x3C)
                plausible = extent_size == 16 and extents and 0x40 + extents * 16 <= length
            if plausible:
                yield base_offset + start


def record_has_interesting_reason(
    record: dict[str, Any],
    interesting_reason_labels: set[str],
) -> bool:
    labels = {str(label).casefold() for label in record.get("reason_labels", [])}
    return bool(labels.intersection(interesting_reason_labels))


def usn_record_rank_key(record: dict[str, Any]) -> tuple[int, str, int]:
    return (
        int(record.get("candidate_score", 0) or 0),
        str(record.get("timestamp_utc") or ""),
        -int(record.get("record_offset", 0) or 0),
    )


def ntfs_reference_set_sha256(references: set[tuple[int, int]]) -> str:

    normalized = []
    for entry_number, sequence_number in sorted(references):
        if (
            isinstance(entry_number, bool)
            or not isinstance(entry_number, int)
            or not 0 <= entry_number < (1 << 48)
            or isinstance(sequence_number, bool)
            or not isinstance(sequence_number, int)
            or not 0 <= sequence_number < (1 << 16)
        ):
            raise ValueError("NTFS file reference is invalid")
        normalized.append(
            {
                "entry_number": entry_number,
                "sequence_number": sequence_number,
            }
        )
    payload = (
        json.dumps(
            normalized,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    return sha256_bytes(payload)


def _iter_usn_v2_records(
    reader: Callable[[int, int], bytes],
    *,
    stream_size_bytes: int,
    chunk_size_bytes: int,
    scan: dict[str, Any],
) -> Iterator[dict[str, Any]]:

    if stream_size_bytes < 0:
        raise ValueError("USN stream_size_bytes must be non-negative")
    if chunk_size_bytes <= 0:
        raise ValueError("USN chunk_size_bytes must be positive")

    physical_bytes_read = 0
    source_bytes_covered = 0
    complete_reads = True
    candidate_signature_count = 0
    parsed_record_count = 0
    unsupported_offsets: set[int] = set()
    overlap = MAX_USN_RECORD_LENGTH + len(USN_RECORD_V2_MAJOR_SIGNATURE)
    for chunk_offset, chunk in usn_scan_chunks(
        reader,
        stream_size_bytes=stream_size_bytes,
        chunk_size_bytes=chunk_size_bytes,
        overlap=overlap,
    ):
        physical_bytes_read += len(chunk)
        unsupported_offsets.update(
            offset for offset in usn_unsupported_record_offsets(chunk, base_offset=chunk_offset)
            if offset < chunk_offset + chunk_size_bytes
        )
        expected_primary_size = min(
            chunk_size_bytes,
            stream_size_bytes - chunk_offset,
        )
        expected_read_size = min(
            chunk_size_bytes + overlap,
            stream_size_bytes - chunk_offset,
        )
        source_bytes_covered += min(len(chunk), expected_primary_size)
        complete_reads = complete_reads and len(chunk) == expected_read_size
        primary_end = chunk_offset + expected_primary_size
        for (
            record_relative_offset,
            absolute_record_offset,
        ) in usn_record_candidate_offsets(
            chunk,
            base_offset=chunk_offset,
        ):
            if absolute_record_offset >= primary_end:
                continue
            candidate_signature_count += 1
            record = parse_usn_record_v2(
                chunk,
                record_relative_offset,
                absolute_offset=absolute_record_offset,
            )
            if record is None:
                continue
            parsed_record_count += 1
            yield record

    scan.update(
        {
            "physical_bytes_read": physical_bytes_read,
            "source_bytes_covered": source_bytes_covered,
            "candidate_signature_count": candidate_signature_count,
            "parsed_record_count": parsed_record_count,
            "duplicate_record_count": 0,
            "source_truncated": (
                not complete_reads or source_bytes_covered != stream_size_bytes
            ),
        }
    )
    if unsupported_offsets:
        scan["unsupported_record_count"] = len(unsupported_offsets)


def scan_usn_records_for_references(
    reader: Callable[[int, int], bytes],
    *,
    stream_size_bytes: int,
    references: set[tuple[int, int]],
    max_records: int = MAX_REFERENCE_RECORDS,
    chunk_size_bytes: int = DEFAULT_SCAN_CHUNK_SIZE,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:

    if not references:
        raise ValueError("USN reference set must not be empty")
    if max_records <= 0:
        raise ValueError("USN max_records must be positive")
    reference_sha256 = ntfs_reference_set_sha256(references)
    scan: dict[str, Any] = {}
    matched_record_count = 0
    retained: list[dict[str, Any]] = []
    for record in _iter_usn_v2_records(
        reader,
        stream_size_bytes=stream_size_bytes,
        chunk_size_bytes=chunk_size_bytes,
        scan=scan,
    ):
        reference = split_ntfs_file_reference(int(record["file_reference_number"]))
        if reference not in references:
            continue
        matched_record_count += 1
        if len(retained) < max_records:
            retained.append(record)

    complete = (
        not bool(scan["source_truncated"])
        and not scan.get("unsupported_record_count")
        and len(retained) == matched_record_count
    )
    stats = {
        "scan_strategy": "truth_blind_usn_record_v2_reference_scan",
        "chunk_size_bytes": chunk_size_bytes,
        "physical_bytes_read": scan["physical_bytes_read"],
        "source_bytes_covered": scan["source_bytes_covered"],
        "candidate_signature_count": scan["candidate_signature_count"],
        "parsed_record_count": scan["parsed_record_count"],
        "duplicate_record_count": scan["duplicate_record_count"],
        "reference_count": len(references),
        "reference_sha256": reference_sha256,
        "matched_record_count": matched_record_count,
        "retained_record_count": len(retained),
        "max_records": max_records,
        "source_truncated": scan["source_truncated"],
        "status": "complete" if complete else "partial",
    }
    if scan.get("unsupported_record_count"):
        stats["unsupported_record_count"] = scan["unsupported_record_count"]
    return retained, stats


def keep_ranked_usn_record(
    selected_heap: list[RankedUsnRecord],
    *,
    record: dict[str, Any],
    rank_offset: int,
    max_records: int,
) -> None:
    ranked = (usn_record_rank_key(record), rank_offset, record)
    if len(selected_heap) < max_records:
        heapq.heappush(selected_heap, ranked)
    elif ranked[:2] > selected_heap[0][:2]:
        heapq.heapreplace(selected_heap, ranked)


def ranked_usn_records(selected_heap: list[RankedUsnRecord]) -> list[dict[str, Any]]:
    return [
        record
        for _sort_key, _offset, record in sorted(
            selected_heap,
            key=lambda item: item[:2],
            reverse=True,
        )
    ]


def empty_reason_scan_stats(
    *,
    chunk_size_bytes: int,
    interesting_reason_labels: tuple[str, ...],
    max_records: int,
) -> dict[str, Any]:
    return {
        "scan_strategy": "truth_blind_usn_record_v2_signature_scan",
        "chunk_size_bytes": chunk_size_bytes,
        "interesting_reason_labels": list(interesting_reason_labels),
        "bytes_scanned": 0,
        "candidate_signature_count": 0,
        "parsed_record_count": 0,
        "interesting_record_count": 0,
        "emitted_record_count": 0,
        "duplicate_record_count": 0,
        "max_records": max_records,
    }


def scan_usn_records_by_reason(
    reader: Callable[[int, int], bytes],
    *,
    stream_size_bytes: int,
    interesting_reason_labels: tuple[str, ...] = DEFAULT_TRUTH_BLIND_REASON_LABELS,
    max_records: int = 5000,
    chunk_size_bytes: int = DEFAULT_SCAN_CHUNK_SIZE,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:

    interesting = {label.casefold() for label in interesting_reason_labels}
    bytes_scanned = 0
    candidate_signature_count = 0
    parsed_record_count = 0
    selected_heap: list[RankedUsnRecord] = []
    interesting_record_count = 0
    unsupported_offsets: set[int] = set()
    overlap = MAX_USN_RECORD_LENGTH + len(USN_RECORD_V2_MAJOR_SIGNATURE)
    if max_records <= 0:
        return [], empty_reason_scan_stats(
            chunk_size_bytes=chunk_size_bytes,
            interesting_reason_labels=interesting_reason_labels,
            max_records=max_records,
        )
    if chunk_size_bytes <= 0:
        raise ValueError("USN chunk_size_bytes must be positive")

    for chunk_offset, chunk in usn_scan_chunks(
        reader,
        stream_size_bytes=stream_size_bytes,
        chunk_size_bytes=chunk_size_bytes,
        overlap=overlap,
    ):
        bytes_scanned += len(chunk)
        unsupported_offsets.update(
            offset for offset in usn_unsupported_record_offsets(chunk, base_offset=chunk_offset)
            if offset < chunk_offset + chunk_size_bytes
        )
        primary_end = chunk_offset + min(
            chunk_size_bytes,
            stream_size_bytes - chunk_offset,
        )
        for (
            record_relative_offset,
            absolute_record_offset,
        ) in usn_record_candidate_offsets(
            chunk,
            base_offset=chunk_offset,
        ):
            if absolute_record_offset >= primary_end:
                continue
            candidate_signature_count += 1
            record = parse_usn_record_v2(
                chunk,
                record_relative_offset,
                absolute_offset=absolute_record_offset,
            )
            if record is None:
                continue
            parsed_record_count += 1
            if not record_has_interesting_reason(record, interesting):
                continue
            interesting_record_count += 1
            record["candidate_score"] = usn_record_review_score(record)
            keep_ranked_usn_record(
                selected_heap,
                record=record,
                rank_offset=absolute_record_offset,
                max_records=max_records,
            )

    records = ranked_usn_records(selected_heap)
    stats = {
        "scan_strategy": "truth_blind_usn_record_v2_signature_scan",
        "chunk_size_bytes": chunk_size_bytes,
        "interesting_reason_labels": list(interesting_reason_labels),
        "bytes_scanned": bytes_scanned,
        "candidate_signature_count": candidate_signature_count,
        "parsed_record_count": parsed_record_count,
        "interesting_record_count": interesting_record_count,
        "emitted_record_count": len(records),
        "duplicate_record_count": 0,
        "max_records": max_records,
    }
    if unsupported_offsets:
        stats["unsupported_record_count"] = len(unsupported_offsets)
    return records, stats


USN_MAX_RECORD_SIZE = 32


def parse_usn_max(data: bytes) -> dict[str, int] | None:
    if len(data) < USN_MAX_RECORD_SIZE:
        return None
    maximum_size, allocation_delta, journal_id, lowest_valid_usn = struct.unpack_from(
        "<QQQQ", data, 0
    )
    return {
        "maximum_size": int(maximum_size),
        "allocation_delta": int(allocation_delta),
        "journal_id": int(journal_id),
        "lowest_valid_usn": int(lowest_valid_usn),
    }


def usn_journal_window(
    journal_path: Path,
    *,
    tail_bytes: int = 4 * 1024 * 1024,
    minimum_usn: int | None = None,
) -> dict[str, Any]:
    size = journal_path.stat().st_size
    result: dict[str, Any] = {
        "size_bytes": size, "first_usn": None, "first_timestamp": None,
        "last_usn": None, "last_timestamp": None, "window_complete": False,
        "stale_head_record_count": 0,
    }
    if size < USN_RECORD_V2_HEADER_SIZE:
        return result
    with journal_path.open("rb") as handle:
        head = handle.read(min(size, tail_bytes))
        first = _first_valid_record(head)
        if first is None:
            return result
        offset, record = first
        base = int(record["usn"]) - offset
        if minimum_usn is not None and int(record["usn"]) < minimum_usn:
            handle.seek(0)
            data = handle.read()
            found = _first_record_at_or_above(data, base=base, minimum_usn=minimum_usn)
            if found is None:
                result["copy_base_usn"] = base
                result["stale_head_record_count"] = _count_records(data)
                return result
            stale_count, offset, record = found
            result["stale_head_record_count"] = stale_count
        result["first_usn"] = int(record["usn"])
        result["first_timestamp"] = record["timestamp_utc"]
        result["copy_base_usn"] = base
        start = max(0, size - tail_bytes)
        handle.seek(start)
        tail = handle.read(size - start)
    last = None
    position = 0
    while position + USN_RECORD_V2_HEADER_SIZE <= len(tail):
        length = usn_record_v2_length(tail, position)
        if not length:
            position += 8
            continue
        record = parse_usn_record_v2(tail, position)
        if record is None or int(record.get("usn", -1)) != base + start + position:
            position += 8
            continue
        last = record
        position += length
    if last is not None:
        result["last_usn"] = int(last["usn"])
        result["last_timestamp"] = last["timestamp_utc"]
        result["window_complete"] = bool(result["first_timestamp"] and result["last_timestamp"])
    return result


def _count_records(data: bytes) -> int:
    count = 0
    position = 0
    while position + USN_RECORD_V2_HEADER_SIZE <= len(data):
        length = usn_record_v2_length(data, position)
        if not length:
            position += 8
            continue
        count += 1
        position += length
    return count


def _first_record_at_or_above(
    data: bytes, *, base: int, minimum_usn: int
) -> tuple[int, int, dict[str, Any]] | None:
    stale = 0
    position = 0
    while position + USN_RECORD_V2_HEADER_SIZE <= len(data):
        length = usn_record_v2_length(data, position)
        if not length:
            position += 8
            continue
        record = parse_usn_record_v2(data, position)
        if record is None or int(record.get("usn", -1)) != base + position:
            position += 8
            continue
        if int(record["usn"]) >= minimum_usn and record.get("timestamp_utc"):
            return stale, position, record
        stale += 1
        position += length
    return None


def usn_journal_timestamp_order(
    journal_path: Path, *, max_bytes: int = 1024 * 1024 * 1024,
    minimum_usn: int | None = None,
) -> dict[str, Any]:
    if minimum_usn is not None and (type(minimum_usn) is not int or minimum_usn < 0):
        raise ValueError("minimum_usn must be a non-negative integer")
    size = journal_path.stat().st_size
    result: dict[str, Any] = {
        "order_checked": False,
        "checked_record_count": 0,
        "timestamp_reversal_count": 0,
        "first_reversal_usn": None,
        "max_backward_seconds": 0,
    }
    if size > max_bytes or size < USN_RECORD_V2_HEADER_SIZE:
        return result
    with journal_path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) != size or len(data) > max_bytes:
        return result
    first = _first_valid_record(data)
    if first is None:
        return result
    base = int(first[1]["usn"]) - first[0]
    if base < 0 or base % 8:
        return result
    previous: int | None = None
    previous_usn: int | None = None
    position = 0
    while position < len(data):
        if not any(data[position:position + 8]):
            position += 8
            continue
        length = usn_record_v2_length(data, position)
        record = parse_usn_record_v2(data, position) if length else None
        expected_usn = base + position
        if minimum_usn is not None and expected_usn < minimum_usn:
            position += (length if record is not None and length % 8 == 0
                         and int(record["usn"]) == expected_usn else 8)
            continue
        if (record is None or length % 8 != 0 or position % 8 != 0
                or record["minor_version"] != 0 or not record["timestamp_utc"]
                or int(record["usn"]) != expected_usn
                or (previous_usn is not None and int(record["usn"]) <= previous_usn)):
            return result
        stamp = int(record["timestamp_filetime"])
        if previous is not None and stamp < previous:
            result["timestamp_reversal_count"] += 1
            if result["first_reversal_usn"] is None:
                result["first_reversal_usn"] = int(record["usn"])
            backward = (previous - stamp) // 10_000_000
            result["max_backward_seconds"] = max(result["max_backward_seconds"], int(backward))
        previous = stamp
        previous_usn = int(record["usn"])
        result["checked_record_count"] += 1
        position += length
    result["order_checked"] = result["checked_record_count"] > 0
    return result


def _first_valid_record(data: bytes) -> tuple[int, dict[str, Any]] | None:
    position = 0
    while position + USN_RECORD_V2_HEADER_SIZE <= len(data):
        length = usn_record_v2_length(data, position)
        if not length:
            position += 8
            continue
        record = parse_usn_record_v2(data, position)
        if record is not None and record.get("timestamp_utc"):
            return position, record
        position += length
    return None


