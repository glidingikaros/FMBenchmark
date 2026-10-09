from __future__ import annotations

import struct
from collections.abc import Callable, Mapping
from typing import Any

from fmb.index.scanners.mft import _i30_index_entries, index_entry_region_complete


def parse_boot_sector(data: bytes) -> dict[str, Any]:
    if len(data) < 512 or data[3:11] != b"NTFS    " or data[510:512] != b"\x55\xaa":
        raise ValueError("invalid native NTFS boot sector")
    sector = struct.unpack_from("<H", data, 11)[0]
    sectors_per_cluster = data[13]
    if sector not in (512, 1024, 2048, 4096) or sectors_per_cluster not in (
        1,
        2,
        4,
        8,
        16,
        32,
        64,
        128,
    ):
        raise ValueError("unsupported NTFS sector/cluster geometry")
    cluster = sector * sectors_per_cluster
    sectors, mft_lcn, mirror_lcn = struct.unpack_from("<QQQ", data, 40)

    def record_size(offset: int) -> int:
        value = struct.unpack_from("<b", data, offset)[0]
        if not value or value < -20:
            raise ValueError("invalid NTFS record size encoding")
        size = (1 << -value) if value < 0 else value * cluster
        if size < sector or size > 1024 * 1024 or size % sector:
            raise ValueError("unsupported NTFS record size")
        return size

    if (
        not sectors
        or mft_lcn >= sectors // sectors_per_cluster
        or mirror_lcn >= sectors // sectors_per_cluster
    ):
        raise ValueError("NTFS MFT location exceeds volume geometry")
    return {
        "bytes_per_sector": sector,
        "bytes_per_cluster": cluster,
        "volume_size_bytes": sectors * sector,
        "total_clusters": sectors // sectors_per_cluster,
        "mft_start_lcn": mft_lcn,
        "mft_mirror_start_lcn": mirror_lcn,
        "mft_record_size": record_size(64),
        "index_record_size": record_size(68),
        "volume_serial_number": f"{struct.unpack_from('<Q', data, 72)[0]:016x}",
        "geometry_source": "native_ntfs_boot_sector",
    }


def read_nonresident_stream(
    read_at: Callable[[int, int], bytes],
    attribute: Mapping[str, Any],
    geometry: Mapping[str, Any],
    *,
    max_bytes: int = 32 * 1024 * 1024,
    allocated: bool = False,
) -> bytes:
    if (
        attribute.get("runlist_complete") is not True
        or attribute.get("lowest_vcn") != 0
    ):
        raise ValueError("native stream has incomplete/nonbase mapping pairs")
    if int(attribute.get("attribute_flags") or 0) & 0x40FF:
        raise ValueError("compressed/encrypted native stream is unsupported")
    cluster = int(geometry["bytes_per_cluster"])
    total = int(geometry["total_clusters"])
    runs = attribute.get("data_runs")
    if runs is None:
        raise ValueError("native stream has no decoded mapping pairs")
    if not isinstance(runs, list):
        raise TypeError("native stream mapping pairs must be a list")
    length = sum(int(run["cluster_count"]) for run in runs) * cluster
    logical = attribute.get("logical_size")
    initialized = attribute.get("valid_data_length")
    if (
        type(logical) is not int
        or type(initialized) is not int
        or not 0 <= initialized <= logical
    ):
        raise ValueError("native stream has invalid or missing initialized length")
    desired = length if allocated else logical
    if desired < 0 or desired > max_bytes or logical > length:
        raise ValueError("native stream length exceeds bound or mapping pairs")
    next_vcn = 0
    for run in runs:
        count, lcn = int(run["cluster_count"]), run["lcn"]
        if count <= 0 or int(run["vcn"]) != next_vcn:
            raise ValueError("noncontiguous native stream VCN coverage")
        next_vcn += count
        if lcn is not None and (int(lcn) < 0 or int(lcn) + count > total):
            raise ValueError("native stream LCN lies outside source volume")
    output = bytearray()
    readable = desired if allocated else initialized
    for run in runs:
        count, lcn = int(run["cluster_count"]), run["lcn"]
        remaining = desired - len(output)
        if remaining <= 0:
            break
        take = min(remaining, count * cluster)
        if lcn is None:
            output.extend(bytes(take))
        else:
            initialized_take = min(take, max(0, readable - len(output)))
            chunk = read_at(int(lcn) * cluster, initialized_take) if initialized_take else b""
            if len(chunk) != initialized_take:
                raise ValueError("native stream backing clusters are truncated")
            output.extend(chunk)
            output.extend(bytes(take - initialized_take))
    if len(output) != desired:
        raise ValueError("native stream mapping pairs do not cover requested bytes")
    return bytes(output)


def parse_index_allocation(
    data: bytes,
    *,
    bitmap: bytes,
    block_size: int,
    sector_size: int,
    cluster_size: int,
    parent_entry: int,
    parent_sequence: int,
) -> dict[str, Any]:
    if (
        block_size < 512
        or block_size > 1024 * 1024
        or block_size % sector_size
        or len(data) % block_size
    ):
        raise ValueError("INDEX_ALLOCATION stream is not index-buffer aligned")
    block_count = len(data) // block_size
    if len(bitmap) * 8 < block_count:
        raise ValueError("INDEX_ALLOCATION bitmap does not cover backing buffers")
    entries: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    parsed_count = 0
    for number in range(block_count):
        offset = number * block_size
        block = data[offset : offset + block_size]
        active = bool(bitmap[number // 8] & (1 << (number % 8)))
        if not active and not any(block):
            continue
        try:
            if block[:4] != b"INDX":
                raise ValueError("missing INDX signature")
            usa_offset, usa_count = struct.unpack_from("<HH", block, 4)
            if (
                usa_count != block_size // sector_size + 1
                or usa_offset < 40
                or usa_offset + 2 * usa_count > block_size
            ):
                raise ValueError("invalid INDX update sequence array")
            fixed = bytearray(block)
            expected = block[usa_offset : usa_offset + 2]
            for sector in range(usa_count - 1):
                end = (sector + 1) * sector_size - 2
                if block[end : end + 2] != expected:
                    raise ValueError("INDX update sequence mismatch")
                fixed[end : end + 2] = block[
                    usa_offset + 2 + 2 * sector : usa_offset + 4 + 2 * sector
                ]
            vcn = struct.unpack_from("<Q", fixed, 16)[0]
            unit = cluster_size if cluster_size <= block_size else sector_size
            if vcn != offset // unit:
                raise ValueError("INDX VCN does not match stream offset")
            first, used, allocated_length = struct.unpack_from("<III", fixed, 24)
            if not (16 <= first <= used <= allocated_length <= block_size - 24):
                raise ValueError("invalid INDX entry bounds")
            if 24 + first < usa_offset + 2 * usa_count:
                raise ValueError("INDX entry region overlaps update sequence array")
            if active and not index_entry_region_complete(
                bytes(fixed[24 + first : 24 + used])
            ):
                raise ValueError("INDX live entry chain is incomplete")
            regions = [
                (24 + first, 24 + used, "index_allocation_active", True),
                (24 + used, 24 + allocated_length, "index_allocation_slack", False),
            ]
            if not active:
                regions = [
                    (
                        24 + first,
                        24 + allocated_length,
                        "index_allocation_unallocated_buffer",
                        False,
                    )
                ]
            for start, end, surface, stop in regions:
                found = _i30_index_entries(
                    bytes(fixed[start:end]),
                    base_offset=offset + start,
                    parent_entry=parent_entry,
                    parent_sequence=parent_sequence,
                    residue_surface=surface,
                    stop_at_end=stop,
                )
                entries.extend(
                    {
                        **item,
                        "index_buffer_number": number,
                        "index_buffer_vcn": vcn,
                        "index_buffer_in_use": active,
                    }
                    for item in found
                )
            parsed_count += 1
        except (ValueError, struct.error) as error:
            failures.append(
                {
                    "index_buffer_number": number,
                    "index_buffer_in_use": active,
                    "error": str(error),
                }
            )
    return {
        "entries": entries,
        "index_allocation_parsed": not failures,
        "index_buffer_count": block_count,
        "parsed_index_buffer_count": parsed_count,
        "index_buffer_errors": failures,
    }
