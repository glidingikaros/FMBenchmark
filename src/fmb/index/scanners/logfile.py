from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from fmb.core.ntfs_time import filetime_to_utc_iso
from fmb.index.scanners.mft import (
    DEFAULT_MFT_RECORD_SIZE,
    FILE_NAME_ATTR_TYPE,
    MFT_RECORD_IN_USE_FLAG,
    STANDARD_INFORMATION_ATTR_TYPE,
    apply_mft_fixup,
    parse_file_name_attribute,
    parse_standard_information,
    read_attribute_header,
    read_record_header,
    resident_value,
    sector_size_for_record,
)

SI_TIMESTAMP_FIELDS: tuple[tuple[str, int], ...] = (
    ("created", 0),
    ("modified", 8),
    ("record_changed", 16),
    ("accessed", 24),
)
SI_TIMESTAMP_BLOCK_LENGTH = 32
UPDATE_RESIDENT_VALUE = "UpdateResidentValue"
INITIALIZE_FILE_RECORD_SEGMENT = "InitializeFileRecordSegment"
DEALLOCATE_FILE_RECORD_SEGMENT = "DeallocateFileRecordSegment"


@dataclass(frozen=True)
class MftRecordBinding:

    entry: int
    sequence_number: int
    in_use: bool
    record_lsn: int
    si_value_offset: int | None
    si_value_length: int | None
    standard_information: dict[str, Any] | None
    file_names: list[dict[str, Any]] = field(default_factory=list)


def read_mft_record(
    handle: BinaryIO, entry: int, *, record_size: int = DEFAULT_MFT_RECORD_SIZE
) -> bytes | None:
    if entry < 0 or record_size <= 0:
        return None
    handle.seek(entry * record_size)
    record = handle.read(record_size)
    if len(record) != record_size or record[:4] != b"FILE":
        return None
    return record


def bind_mft_record(
    record: bytes, *, entry: int, record_size: int = DEFAULT_MFT_RECORD_SIZE
) -> MftRecordBinding | None:
    if len(record) < 64 or record[:4] != b"FILE":
        return None
    try:
        fixed = apply_mft_fixup(record, sector_size=sector_size_for_record(record, record_size))
    except ValueError:
        return None
    header = read_record_header(fixed)
    if header is None or header.first_attr_offset < 48 or header.first_attr_offset >= len(fixed):
        return None
    record_lsn = struct.unpack_from("<Q", fixed, 8)[0]
    limit = min(len(fixed), header.used_size if header.used_size >= header.first_attr_offset else len(fixed))
    attr_offset = header.first_attr_offset
    si_value_offset: int | None = None
    si_value_length: int | None = None
    standard_information: dict[str, Any] | None = None
    file_names: list[dict[str, Any]] = []
    while attr_offset + 16 <= limit:
        attr_header, reached_end = read_attribute_header(fixed, attr_offset)
        if reached_end or attr_header is None:
            break
        if attr_header.attr_length < 16 or attr_offset + attr_header.attr_length > limit:
            break
        if attr_header.attr_type == STANDARD_INFORMATION_ATTR_TYPE and not attr_header.nonresident:
            value = resident_value(fixed, attr_offset, attr_header.attr_length)
            if value is not None and si_value_offset is None:
                value_offset = struct.unpack_from("<H", fixed, attr_offset + 20)[0]
                si_value_offset = attr_offset + value_offset
                si_value_length = len(value)
                standard_information = parse_standard_information(value)
        elif attr_header.attr_type == FILE_NAME_ATTR_TYPE and not attr_header.nonresident:
            value = resident_value(fixed, attr_offset, attr_header.attr_length)
            parsed = parse_file_name_attribute(value) if value is not None else None
            if parsed is not None:
                file_names.append(parsed)
        attr_offset += attr_header.attr_length
    return MftRecordBinding(
        entry=int(entry),
        sequence_number=int(header.sequence_number),
        in_use=bool(header.flags & MFT_RECORD_IN_USE_FLAG),
        record_lsn=int(record_lsn),
        si_value_offset=si_value_offset,
        si_value_length=si_value_length,
        standard_information=standard_information,
        file_names=file_names,
    )


def decode_si_timestamp_update(
    *, offset_in_target: int, redo: bytes, undo: bytes, si_value_offset: int,
    include_timestamp_fragments: bool = False,
) -> dict[str, Any] | None:
    relative = offset_in_target - si_value_offset
    if relative >= SI_TIMESTAMP_BLOCK_LENGTH:
        return None
    covered: list[str] = []
    old: dict[str, int] = {}
    new: dict[str, int] = {}
    fragments = []
    for name, field_offset in SI_TIMESTAMP_FIELDS:
        start = field_offset - relative
        if start < 0 or start + 8 > len(redo) or start + 8 > len(undo):
            first, last = max(0, start), min(len(redo), start + 8)
            if include_timestamp_fragments and len(redo) == len(undo) and first < last:
                fragments.append({"field": name, "byte_order": "little",
                    "field_width_bytes": 8, "offset_in_field": first - start,
                    "undo_hex": undo[first:last].hex(), "redo_hex": redo[first:last].hex()})
            continue
        new[name] = struct.unpack_from("<Q", redo, start)[0]
        old[name] = struct.unpack_from("<Q", undo, start)[0]
        covered.append(name)
    if not covered and not fragments:
        return None
    result = {
        "update_offset_in_si": int(relative),
        "update_length": len(redo),
        "covered_fields": covered,
        "old": old,
        "new": new,
    }
    if fragments:
        result["si_timestamp_fragments"] = fragments
    return result


def _iso(value: int | None) -> str | None:
    if value is None:
        return None
    return filetime_to_utc_iso(int(value))


_NAMESPACE_RANK = {
    "win32_and_dos": 0, "win32": 0, "posix": 1, "dos": 2,
    3: 0, 1: 0, 0: 1, 2: 2,
}


def preferred_file_name(file_names: list[dict[str, Any]]) -> dict[str, Any] | None:

    def rank(item: dict[str, Any]) -> int:
        for key in ("namespace_name", "namespace"):
            value = item.get(key)
            if value in _NAMESPACE_RANK:
                return _NAMESPACE_RANK[value]
        return 3

    ranked = sorted(file_names, key=rank)
    return ranked[0] if ranked else None


def si_updates_from_records(
    records: list[dict[str, Any]],
    *,
    mft_path: Path,
    default_record_size: int = DEFAULT_MFT_RECORD_SIZE,
    mft_entry_sequences: dict[int, tuple[int, bool]] | None = None,
    lifecycle_records: list[dict[str, Any]] | None = None,
    include_timestamp_fragments: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    lifecycle: dict[int, list[tuple[int, str]]] = {}
    for record in lifecycle_records if lifecycle_records is not None else records:
        name = record.get("redo_operation_name")
        entry = record.get("mft_target_number")
        if name in (INITIALIZE_FILE_RECORD_SEGMENT, DEALLOCATE_FILE_RECORD_SEGMENT) and isinstance(entry, int):
            lifecycle.setdefault(entry, []).append((int(record["lsn"]), str(name)))
    updates: list[dict[str, Any]] = []
    skipped: dict[str, int] = {}
    si_update_count = 0
    bindings: dict[tuple[int, int], MftRecordBinding | None] = {}

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    with mft_path.open("rb") as handle:
        for record in sorted(records, key=lambda item: int(item.get("lsn", 0))):
            if record.get("redo_operation_name") != UPDATE_RESIDENT_VALUE:
                continue
            entry = record.get("mft_target_number")
            offset_in_target = record.get("offset_in_target")
            if not isinstance(entry, int) or not isinstance(offset_in_target, int):
                continue
            block_size = int(record.get("target_block_size") or 0) * 512
            record_size = block_size if block_size > 0 else default_record_size
            if offset_in_target >= record_size:
                continue
            key = (entry, record_size)
            if key not in bindings:
                raw = read_mft_record(handle, entry, record_size=record_size)
                bindings[key] = (
                    bind_mft_record(raw, entry=entry, record_size=record_size)
                    if raw is not None
                    else None
                )
            binding = bindings[key]
            if binding is None:
                si_update_count += 1
                skip("record_unreadable")
                continue
            if binding.si_value_offset is None:
                si_update_count += 1
                skip("si_value_offset_unresolved")
                continue
            try:
                redo = bytes.fromhex(str(record.get("redo_hex", "")))
                undo = bytes.fromhex(str(record.get("undo_hex", "")))
            except ValueError:
                skip("update_bytes_malformed")
                continue
            decoded = decode_si_timestamp_update(
                offset_in_target=offset_in_target,
                redo=redo,
                undo=undo,
                si_value_offset=binding.si_value_offset,
                include_timestamp_fragments=(include_timestamp_fragments
                    and record.get("undo_operation_name") == UPDATE_RESIDENT_VALUE),
            )
            if decoded is None:
                continue
            si_update_count += 1
            lsn = int(record["lsn"])
            later_lifecycle = [
                (event_lsn, name)
                for event_lsn, name in lifecycle.get(entry, [])
                if event_lsn > lsn
            ]
            if later_lifecycle:
                skip("entry_reinitialised_after_update")
                continue
            if binding.record_lsn < lsn:
                skip("record_lsn_precedes_update")
                continue
            if not binding.in_use:
                skip("record_not_in_use")
                continue
            if mft_entry_sequences:
                observed = mft_entry_sequences.get(entry)
                if observed is not None and observed[0] != binding.sequence_number:
                    skip("mft_context_sequence_disagrees")
                    continue
            si_current = binding.standard_information or {}
            updates.append(
                {
                    "lsn": lsn,
                    "transaction_id": int(record.get("transaction_id", 0)),
                    "transaction_forgotten_lsn": record.get("transaction_forgotten_lsn"),
                    "transaction_rolled_back": bool(record.get("transaction_rolled_back", False)),
                    "mft_entry": binding.entry,
                    "sequence_number": binding.sequence_number,
                    "record_in_use": binding.in_use,
                    "record_lsn": binding.record_lsn,
                    "record_size": record_size,
                    "si_value_offset": binding.si_value_offset,
                    "offset_in_target": offset_in_target,
                    "update_offset_in_si": decoded["update_offset_in_si"],
                    "update_length": decoded["update_length"],
                    "covered_fields": list(decoded["covered_fields"]),
                    **({"si_timestamp_fragments": decoded["si_timestamp_fragments"]}
                       if "si_timestamp_fragments" in decoded else {}),
                    "old": {name: _iso(value) for name, value in decoded["old"].items()},
                    "new": {name: _iso(value) for name, value in decoded["new"].items()},
                    "old_filetime": dict(decoded["old"]),
                    "new_filetime": dict(decoded["new"]),
                    "current_si": {
                        name: (si_current.get(name) or {}).get("utc")
                        for name in ("created", "modified", "metadata_changed", "accessed")
                    },
                    "file_names": [
                        {
                            "name": item.get("name"),
                            "namespace": item.get("namespace_name"),
                            "parent_inode": item.get("parent_inode"),
                            "parent_sequence": item.get("parent_sequence"),
                            "fn_created": (item.get("file_name_timestamps") or {}).get("created", {}).get("utc"),
                        }
                        for item in binding.file_names
                    ],
                }
            )
    diagnostics = {
        "si_update_count": si_update_count,
        "bound_count": len(updates),
        "unbound_count": si_update_count - len(updates),
        "unbound_reasons": dict(sorted(skipped.items())),
    }
    return updates, diagnostics
