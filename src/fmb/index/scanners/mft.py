from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from fmb.core.ntfs_time import filetime_to_utc_iso as ntfs_filetime_to_utc_iso

DEFAULT_MFT_RECORD_SIZE = 1024
DEFAULT_SECTOR_SIZE = 512
UPDATE_SEQUENCE_STRIDE = 512

STANDARD_INFORMATION_ATTR_TYPE = 0x10
ATTRIBUTE_LIST_ATTR_TYPE = 0x20
FILE_NAME_ATTR_TYPE = 0x30
DATA_ATTR_TYPE = 0x80
INDEX_ROOT_ATTR_TYPE = 0x90
INDEX_ALLOCATION_ATTR_TYPE = 0xA0
END_ATTR_TYPE = 0xFFFFFFFF
MFT_RECORD_IN_USE_FLAG = 0x0001
MFT_RECORD_DIRECTORY_FLAG = 0x0002
ATTRIBUTE_FLAG_COMPRESSION_MASK = 0x00FF
ATTRIBUTE_FLAG_ENCRYPTED = 0x4000
ATTRIBUTE_FLAG_SPARSE = 0x8000


@dataclass(frozen=True)
class RecordHeader:
    sequence_number: int
    first_attr_offset: int
    flags: int
    used_size: int


@dataclass(frozen=True)
class AttributeHeader:
    attr_type: int
    attr_length: int
    nonresident: int
    flags: int
    attr_id: int


@dataclass
class RecordAttributes:
    metadata_timestamps: dict[str, dict[str, Any]] | None
    file_name_attributes: list[dict[str, Any]]
    data_attributes: list[dict[str, Any]]
    index_attributes: list[dict[str, Any]] | None = None
    attribute_list_present: bool = False
    parse_error_count: int = 0


def filetime_payload(filetime: int) -> dict[str, Any]:
    return {
        "ntfs_filetime": int(filetime),
        "utc": ntfs_filetime_to_utc_iso(int(filetime)),
    }


def ntfs_file_name_namespace(namespace: int) -> str:
    return {
        0: "posix",
        1: "win32",
        2: "dos",
        3: "win32_and_dos",
    }.get(int(namespace), "unknown")


def mft_fixup_header(record: bytes) -> tuple[int, int] | None:
    if len(record) < 48 or record[:4] != b"FILE":
        return None
    try:
        usa_offset = struct.unpack_from("<H", record, 4)[0]
        usa_count = struct.unpack_from("<H", record, 6)[0]
    except struct.error:
        return None
    usa_end = usa_offset + usa_count * 2
    if usa_offset <= 0 or usa_count <= 1 or usa_end > len(record):
        return None
    return usa_offset, usa_count


def apply_mft_fixup(record: bytes, *, sector_size: int = DEFAULT_SECTOR_SIZE) -> bytes:
    fixup_header = mft_fixup_header(record)
    if fixup_header is None:
        return record
    if sector_size <= 0:
        raise ValueError("MFT sector_size must be positive")
    usa_offset, usa_count = fixup_header
    expected = record[usa_offset : usa_offset + 2]
    patched = bytearray(record)
    sector_count = usa_count - 1
    for sector_index in range(sector_count):
        trailer = (sector_index + 1) * sector_size - 2
        replacement = usa_offset + 2 + sector_index * 2
        if trailer + 2 > len(patched) or replacement + 2 > len(record):
            raise ValueError("MFT USA fixup trailer is outside the record")
        if bytes(patched[trailer : trailer + 2]) != expected:
            raise ValueError("MFT USA fixup trailer does not match the update sequence")
        patched[trailer : trailer + 2] = record[replacement : replacement + 2]
    return bytes(patched)


def sector_size_for_record(record: bytes, record_size: int | None) -> int:
    fixup_header = mft_fixup_header(record)
    if fixup_header is None or record_size is None:
        return DEFAULT_SECTOR_SIZE
    _usa_offset, usa_count = fixup_header
    sector_count = usa_count - 1
    if sector_count <= 0 or record_size % sector_count:
        return DEFAULT_SECTOR_SIZE
    return record_size // sector_count


def decode_attribute_name(record: bytes, attr_offset: int, attr_length: int) -> str:
    name_length = record[attr_offset + 9]
    if name_length <= 0:
        return ""
    name_offset = struct.unpack_from("<H", record, attr_offset + 10)[0]
    start = attr_offset + name_offset
    end = start + name_length * 2
    if name_offset < 24 or start < attr_offset or end > attr_offset + attr_length:
        return ""
    return record[start:end].decode("utf-16le", errors="ignore")


def resident_value(record: bytes, attr_offset: int, attr_length: int) -> bytes | None:
    if attr_offset + 24 > len(record):
        return None
    value_length = struct.unpack_from("<I", record, attr_offset + 16)[0]
    value_offset = struct.unpack_from("<H", record, attr_offset + 20)[0]
    start = attr_offset + value_offset
    end = start + value_length
    if value_offset < 24 or start < attr_offset or end > attr_offset + attr_length:
        return None
    return record[start:end]


def parse_standard_information(value: bytes) -> dict[str, dict[str, Any]] | None:
    if len(value) < 32:
        return None
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", value, 0)
    return {
        "created": filetime_payload(created),
        "modified": filetime_payload(modified),
        "metadata_changed": filetime_payload(mft_modified),
        "accessed": filetime_payload(accessed),
    }


def parse_file_name_attribute(value: bytes) -> dict[str, Any] | None:
    if len(value) < 66:
        return None
    parent_reference = struct.unpack_from("<Q", value, 0)[0]
    parent_inode = parent_reference & 0x0000FFFFFFFFFFFF
    parent_sequence = parent_reference >> 48
    created, modified, mft_modified, accessed = struct.unpack_from("<QQQQ", value, 8)
    allocated_size = struct.unpack_from("<Q", value, 40)[0]
    real_size = struct.unpack_from("<Q", value, 48)[0]
    file_flags = struct.unpack_from("<I", value, 56)[0]
    reparse_value = struct.unpack_from("<I", value, 60)[0]
    name_length = value[64]
    namespace = value[65]
    name_end = 66 + name_length * 2
    if name_end > len(value):
        return None
    try:
        name = value[66:name_end].decode("utf-16le")
    except UnicodeDecodeError:
        return None
    return {
        "parent_reference": int(parent_reference),
        "parent_inode": int(parent_inode),
        "parent_sequence": int(parent_sequence),
        "namespace": int(namespace),
        "namespace_name": ntfs_file_name_namespace(namespace),
        "name": name,
        "allocated_size_bytes": int(allocated_size),
        "real_size_bytes": int(real_size),
        "file_flags": int(file_flags),
        "reparse_value": int(reparse_value),
        "file_name_timestamps": {
            "created": filetime_payload(created),
            "modified": filetime_payload(modified),
            "mft_modified": filetime_payload(mft_modified),
            "accessed": filetime_payload(accessed),
        },
    }


def read_record_header(record: bytes) -> RecordHeader | None:
    try:
        return RecordHeader(
            sequence_number=struct.unpack_from("<H", record, 16)[0],
            first_attr_offset=struct.unpack_from("<H", record, 20)[0],
            flags=struct.unpack_from("<H", record, 22)[0],
            used_size=struct.unpack_from("<I", record, 24)[0],
        )
    except struct.error:
        return None


def read_attribute_header(
    record: bytes, attr_offset: int
) -> tuple[AttributeHeader | None, bool]:
    try:
        attr_type = struct.unpack_from("<I", record, attr_offset)[0]
        if attr_type == END_ATTR_TYPE:
            return None, True
        return (
            AttributeHeader(
                attr_type=attr_type,
                attr_length=struct.unpack_from("<I", record, attr_offset + 4)[0],
                nonresident=record[attr_offset + 8],
                flags=struct.unpack_from("<H", record, attr_offset + 12)[0],
                attr_id=struct.unpack_from("<H", record, attr_offset + 14)[0],
            ),
            False,
        )
    except (IndexError, struct.error):
        return None, False


def parse_mapping_pairs(
    record: bytes,
    *,
    start: int,
    end: int,
    expected_cluster_count: int,
    lowest_vcn: int = 0,
) -> dict[str, Any]:

    cursor = start
    data_run_count = 0
    allocated_cluster_count = 0
    sparse_cluster_count = 0
    terminated = False
    current_lcn = 0
    current_vcn = lowest_vcn
    runs: list[dict[str, int | None]] = []
    while cursor < end:
        pair_header = record[cursor]
        cursor += 1
        if pair_header == 0:
            terminated = True
            break
        length_size = pair_header & 0x0F
        offset_size = pair_header >> 4
        if (
            length_size == 0
            or length_size > 8
            or offset_size > 8
            or cursor + length_size + offset_size > end
        ):
            break
        cluster_count = int.from_bytes(
            record[cursor : cursor + length_size],
            byteorder="little",
            signed=False,
        )
        cursor += length_size
        if cluster_count <= 0:
            break
        if offset_size:
            current_lcn += int.from_bytes(
                record[cursor : cursor + offset_size], "little", signed=True
            )
            if current_lcn < 0:
                break
        cursor += offset_size
        runs.append(
            {
                "vcn": current_vcn,
                "lcn": current_lcn if offset_size else None,
                "cluster_count": cluster_count,
            }
        )
        current_vcn += cluster_count
        data_run_count += 1
        if offset_size == 0:
            sparse_cluster_count += cluster_count
        else:
            allocated_cluster_count += cluster_count

    observed_cluster_count = allocated_cluster_count + sparse_cluster_count
    return {
        "data_run_count": data_run_count,
        "allocated_cluster_count": allocated_cluster_count,
        "sparse_cluster_count": sparse_cluster_count,
        "data_runs": runs,
        "runlist_complete": (
            terminated and observed_cluster_count == expected_cluster_count
        ),
    }


def nonresident_data_semantics(
    record: bytes,
    *,
    attr_offset: int,
    attr_length: int,
) -> dict[str, Any]:

    attr_end = attr_offset + attr_length
    if attr_offset + 64 > attr_end or attr_end > len(record):
        return {
            "logical_size": None,
            "allocated_size": None,
            "valid_data_length": None,
            "data_run_count": 0,
            "allocated_cluster_count": 0,
            "sparse_cluster_count": 0,
            "runlist_complete": False,
        }

    lowest_vcn = struct.unpack_from("<Q", record, attr_offset + 16)[0]
    highest_vcn = struct.unpack_from("<Q", record, attr_offset + 24)[0]
    mapping_pairs_offset = struct.unpack_from("<H", record, attr_offset + 32)[0]
    compression_unit_exponent = struct.unpack_from("<H", record, attr_offset + 34)[0]
    expected_cluster_count = (
        highest_vcn - lowest_vcn + 1 if highest_vcn >= lowest_vcn else 0
    )
    mapping_pairs_start = attr_offset + mapping_pairs_offset
    if (
        mapping_pairs_offset < 64
        or mapping_pairs_start < attr_offset
        or mapping_pairs_start >= attr_end
        or expected_cluster_count <= 0
    ):
        run_semantics = {
            "data_run_count": 0,
            "allocated_cluster_count": 0,
            "sparse_cluster_count": 0,
            "runlist_complete": False,
        }
    else:
        run_semantics = parse_mapping_pairs(
            record,
            start=mapping_pairs_start,
            end=attr_end,
            expected_cluster_count=expected_cluster_count,
            lowest_vcn=int(lowest_vcn),
        )

    base_extent = lowest_vcn == 0
    return {
        "lowest_vcn": int(lowest_vcn),
        "highest_vcn": int(highest_vcn),
        "mapping_pairs_offset": int(mapping_pairs_offset),
        "compression_unit_clusters": (
            1 << compression_unit_exponent if 0 < compression_unit_exponent <= 16 else 0
        ),
        "logical_size": (
            int(struct.unpack_from("<Q", record, attr_offset + 48)[0])
            if base_extent
            else None
        ),
        "allocated_size": (
            int(struct.unpack_from("<Q", record, attr_offset + 40)[0])
            if base_extent
            else None
        ),
        "valid_data_length": (
            int(struct.unpack_from("<Q", record, attr_offset + 56)[0])
            if base_extent
            else None
        ),
        **run_semantics,
    }


def scan_record_attributes(record: bytes, header: RecordHeader) -> RecordAttributes:
    limit = min(
        len(record),
        header.used_size
        if header.used_size >= header.first_attr_offset
        else len(record),
    )
    attributes = RecordAttributes(
        metadata_timestamps=None,
        file_name_attributes=[],
        data_attributes=[],
    )
    attr_offset = header.first_attr_offset
    while attr_offset + 16 <= limit:
        attr_header, reached_end = read_attribute_header(record, attr_offset)
        if reached_end:
            break
        if attr_header is None:
            attributes.parse_error_count += 1
            break
        if (
            attr_header.attr_length < 16
            or attr_offset + attr_header.attr_length > limit
        ):
            attributes.parse_error_count += 1
            break

        attr_name = decode_attribute_name(record, attr_offset, attr_header.attr_length)
        add_record_attribute(attributes, record, attr_offset, attr_header, attr_name)
        attr_offset += attr_header.attr_length
    return attributes


def add_record_attribute(
    attributes: RecordAttributes,
    record: bytes,
    attr_offset: int,
    header: AttributeHeader,
    attr_name: str,
) -> None:
    value = (
        None
        if header.nonresident
        else resident_value(record, attr_offset, header.attr_length)
    )
    if header.attr_type == STANDARD_INFORMATION_ATTR_TYPE and value is not None:
        standard_information = parse_standard_information(value)
        if standard_information is not None:
            attributes.metadata_timestamps = standard_information
    elif header.attr_type == FILE_NAME_ATTR_TYPE and value is not None:
        file_name = parse_file_name_attribute(value)
        if file_name is not None:
            attributes.file_name_attributes.append(
                {
                    "attribute_id": int(header.attr_id),
                    "attribute_name": attr_name,
                    **file_name,
                }
            )
    elif header.attr_type == ATTRIBUTE_LIST_ATTR_TYPE:
        attributes.attribute_list_present = True
    elif header.attr_type in (INDEX_ALLOCATION_ATTR_TYPE, 0xB0):
        if attributes.index_attributes is None:
            attributes.index_attributes = []
        attributes.index_attributes.append(
            {
                "attribute_type": header.attr_type,
                "attribute_name": attr_name,
                "attribute_id": header.attr_id,
                "attribute_flags": header.flags,
                "resident_status": "nonresident" if header.nonresident else "resident",
                **(
                    nonresident_data_semantics(
                        record, attr_offset=attr_offset, attr_length=header.attr_length
                    )
                    if header.nonresident
                    else {
                        "resident_value_hex": (value or b"").hex(),
                        "logical_size": len(value) if value is not None else None,
                    }
                ),
            }
        )
    elif header.attr_type == DATA_ATTR_TYPE:
        storage_semantics = (
            nonresident_data_semantics(
                record,
                attr_offset=attr_offset,
                attr_length=header.attr_length,
            )
            if header.nonresident
            else {
                "logical_size": len(value) if value is not None else None,
                "allocated_size": 0 if value is not None else None,
                "valid_data_length": len(value) if value is not None else None,
                "data_run_count": 0,
                "allocated_cluster_count": 0,
                "sparse_cluster_count": 0,
                "runlist_complete": None,
            }
        )
        attributes.data_attributes.append(
            {
                "attribute_id": int(header.attr_id),
                "attribute_name": attr_name,
                "stream_name": attr_name,
                "is_named_stream": bool(attr_name),
                "resident_status": "nonresident" if header.nonresident else "resident",
                "attribute_flags": int(header.flags),
                "is_sparse": bool(header.flags & ATTRIBUTE_FLAG_SPARSE),
                "is_compressed": bool(header.flags & ATTRIBUTE_FLAG_COMPRESSION_MASK),
                "is_encrypted": bool(header.flags & ATTRIBUTE_FLAG_ENCRYPTED),
                **storage_semantics,
            }
        )


def build_record_payload(
    *,
    record_offset: int,
    record_size: int | None,
    header: RecordHeader,
    attributes: RecordAttributes,
) -> dict[str, Any]:
    return {
        "record_offset": int(record_offset),
        "mft_entry": int(record_offset // (record_size or DEFAULT_MFT_RECORD_SIZE)),
        "sequence_number": int(header.sequence_number),
        "file_record_flags": int(header.flags),
        "metadata_timestamps": attributes.metadata_timestamps,
        "file_name_attributes": attributes.file_name_attributes,
        "data_attributes": attributes.data_attributes,
        "index_attributes": attributes.index_attributes or [],
        "attribute_list_present": bool(attributes.attribute_list_present),
        "attribute_parse_error_count": int(attributes.parse_error_count),
    }


def parse_mft_record(
    record: bytes, *, record_offset: int = 0, record_size: int | None = None
) -> dict[str, Any] | None:
    if len(record) < 64 or record[:4] != b"FILE":
        return None
    if record_size is not None and record_size <= 0:
        raise ValueError("MFT record_size must be positive")
    try:
        fixed = apply_mft_fixup(
            record, sector_size=sector_size_for_record(record, record_size)
        )
    except ValueError:
        return None
    header = read_record_header(fixed)
    if header is None:
        return None
    if header.first_attr_offset < 48 or header.first_attr_offset >= len(fixed):
        return None
    attributes = scan_record_attributes(fixed, header)
    return build_record_payload(
        record_offset=record_offset,
        record_size=record_size,
        header=header,
        attributes=attributes,
    )


def _i30_index_entries(
    buffer: bytes,
    *,
    base_offset: int,
    parent_entry: int,
    parent_sequence: int,
    residue_surface: str,
    stop_at_end: bool = False,
) -> list[dict[str, Any]]:

    entries: list[dict[str, Any]] = []
    offset = 0
    while offset + 16 <= len(buffer):
        try:
            file_reference, entry_length, key_length, entry_flags = struct.unpack_from(
                "<QHHH", buffer, offset
            )
        except struct.error:
            break
        if (
            stop_at_end
            and entry_flags & 0x0002
            and entry_length >= 16
            and entry_length % 8 == 0
            and offset + entry_length <= len(buffer)
        ):
            break
        if (
            entry_length < 0x58
            or entry_length % 8
            or key_length < 66
            or 16 + key_length > entry_length
            or offset + entry_length > len(buffer)
        ):
            offset += 8
            continue
        file_name = parse_file_name_attribute(
            buffer[offset + 16 : offset + 16 + key_length]
        )
        reference_entry = file_reference & 0x0000FFFFFFFFFFFF
        reference_sequence = file_reference >> 48
        if (
            file_name is None
            or not reference_entry
            or not reference_sequence
            or file_name.get("parent_inode") != parent_entry
            or file_name.get("parent_sequence") != parent_sequence
            or not str(file_name.get("name") or "")
        ):
            offset += 8
            continue
        entries.append(
            {
                "name": str(file_name["name"]),
                "name_namespace": int(file_name["namespace"]),
                "file_reference_entry": int(reference_entry),
                "file_reference_sequence": int(reference_sequence),
                "parent_reference_entry": int(file_name["parent_inode"]),
                "parent_reference_sequence": int(file_name["parent_sequence"]),
                "entry_offset": int(base_offset + offset),
                "residue_surface": residue_surface,
            }
        )
        offset += entry_length
    return entries


def index_entry_region_complete(buffer: bytes) -> bool:
    offset = 0
    while offset + 16 <= len(buffer):
        _reference, length, key_length, flags = struct.unpack_from(
            "<QHHH", buffer, offset
        )
        extra = 8 if flags & 1 else 0
        if (
            flags & ~3
            or length < 16 + extra
            or length % 8
            or offset + length > len(buffer)
        ):
            return False
        if flags & 2:
            return key_length == 0 and offset + length == len(buffer)
        if key_length < 66 or 16 + key_length + extra > length:
            return False
        if (
            parse_file_name_attribute(buffer[offset + 16 : offset + 16 + key_length])
            is None
        ):
            return False
        offset += length
    return False


def parse_directory_i30_record(
    record: bytes,
    *,
    record_offset: int = 0,
    record_size: int | None = None,
) -> dict[str, Any] | None:

    parsed = parse_mft_record(
        record,
        record_offset=record_offset,
        record_size=record_size,
    )
    if parsed is None:
        return None
    try:
        fixed = apply_mft_fixup(
            record,
            sector_size=sector_size_for_record(record, record_size),
        )
    except ValueError:
        return None
    header = read_record_header(fixed)
    if header is None:
        return None
    mft_entry = int(parsed["mft_entry"])
    sequence_number = int(parsed["sequence_number"])
    resident_entries: list[dict[str, Any]] = []
    root_slack_entries: list[dict[str, Any]] = []
    index_root_present = False
    index_root_parsed = False
    index_allocation_present = False
    index_block_size = None
    limit = min(len(fixed), header.used_size)
    attr_offset = header.first_attr_offset
    while attr_offset + 16 <= limit:
        attr_header, reached_end = read_attribute_header(fixed, attr_offset)
        if reached_end:
            break
        if (
            attr_header is None
            or attr_header.attr_length < 16
            or attr_offset + attr_header.attr_length > limit
        ):
            return None
        if attr_header.attr_type == INDEX_ALLOCATION_ATTR_TYPE:
            index_allocation_present = True
        elif attr_header.attr_type == INDEX_ROOT_ATTR_TYPE:
            index_root_present = True
            if attr_header.nonresident:
                return None
            value_length = struct.unpack_from("<I", fixed, attr_offset + 16)[0]
            value_offset = struct.unpack_from("<H", fixed, attr_offset + 20)[0]
            value_start = attr_offset + value_offset
            value_end = value_start + value_length
            if (
                value_offset < 24
                or value_end > attr_offset + attr_header.attr_length
                or value_length < 32
            ):
                return None
            index_block_size = struct.unpack_from("<I", fixed, value_start + 8)[0]
            entries_offset, entries_size = struct.unpack_from(
                "<II", fixed, value_start + 16
            )
            entries_start = value_start + 16 + entries_offset
            entries_end = value_start + 16 + entries_size
            if (
                entries_offset < 16
                or entries_size < entries_offset
                or entries_start > entries_end
                or entries_end > value_end
            ):
                return None
            if not index_entry_region_complete(fixed[entries_start:entries_end]):
                return None
            resident_entries.extend(
                _i30_index_entries(
                    fixed[entries_start:entries_end],
                    base_offset=entries_start,
                    parent_entry=mft_entry,
                    parent_sequence=sequence_number,
                    residue_surface="index_root",
                    stop_at_end=True,
                )
            )
            root_slack_entries.extend(
                _i30_index_entries(
                    fixed[
                        (entries_end + 7) & ~7 : attr_offset + attr_header.attr_length
                    ],
                    base_offset=(entries_end + 7) & ~7,
                    parent_entry=mft_entry,
                    parent_sequence=sequence_number,
                    residue_surface="index_root_slack",
                )
            )
            index_root_parsed = True
        attr_offset += attr_header.attr_length

    slack_entries: list[dict[str, Any]] = []
    if 0 < header.used_size < len(fixed):
        slack_start = (header.used_size + 7) & ~7
        slack_entries = _i30_index_entries(
            fixed[slack_start:],
            base_offset=slack_start,
            parent_entry=mft_entry,
            parent_sequence=sequence_number,
            residue_surface="record_slack",
        )
    return {
        **parsed,
        "is_active_directory": bool(
            header.flags & MFT_RECORD_IN_USE_FLAG
            and header.flags & MFT_RECORD_DIRECTORY_FLAG
        ),
        "resident_index_root_entries": resident_entries,
        "index_root_slack_entries": root_slack_entries,
        "record_slack_entries": slack_entries,
        "index_root_present": index_root_present,
        "index_root_parsed": index_root_parsed,
        "index_allocation_present": index_allocation_present,
        "index_allocation_parsed": False,
        "index_block_size": index_block_size,
    }


def mft_record_is_in_use(record: dict[str, Any]) -> bool:
    try:
        flags = int(record.get("file_record_flags", 0) or 0)
    except (TypeError, ValueError):
        return False
    return bool(flags & MFT_RECORD_IN_USE_FLAG)


