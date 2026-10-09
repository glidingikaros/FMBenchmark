from __future__ import annotations

import json
import math
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path
from typing import Any

from fmb.index.scanners.mft import (
    apply_mft_fixup,
    parse_mft_record,
    read_attribute_header,
    read_record_header,
    resident_value,
)
from fmb.index.scanners.ntfs import read_nonresident_stream


class QemuImageReader:

    def __init__(self, path: Path, *, max_read_bytes: int = 32 * 1024 * 1024):
        self.path = path.resolve(strict=True)
        result = subprocess.run(
            ["qemu-img", "info", "--output=json", str(self.path)],
            capture_output=True,
            check=True,
            text=True,
            timeout=60,
        )
        info = json.loads(result.stdout)
        self.format = info["format"]
        if self.format not in ("raw", "vmdk", "vpc", "vhdx") or info.get(
            "backing-filename"
        ):
            raise ValueError(
                "bounded NTFS reads require a self-contained supported image"
            )
        self.size = int(info["virtual-size"])
        self.max_read_bytes = max_read_bytes

    def read_at(self, offset: int, length: int) -> bytes:
        if (
            offset < 0
            or length < 0
            or length > self.max_read_bytes
            or offset + length > self.size
        ):
            raise ValueError("logical image read exceeds source or configured bound")
        if not length:
            return b""
        start = offset // 512 * 512
        end = math.ceil((offset + length) / 512) * 512
        options = {
            "driver": "raw",
            "offset": start,
            "size": end - start,
            "file": {
                "driver": self.format,
                "file": {"driver": "file", "filename": str(self.path)},
            },
        }
        with tempfile.TemporaryDirectory(prefix="fmb-native-ntfs-") as temp:
            output = Path(temp) / "range.bin"
            subprocess.run(
                [
                    "qemu-img",
                    "dd",
                    "if=json:" + json.dumps(options),
                    "of=" + str(output),
                    "bs=512",
                    f"count={(end - start) // 512}",
                ],
                capture_output=True,
                check=True,
                timeout=60,
            )
            data = output.read_bytes()
        if len(data) != end - start:
            raise ValueError("QEMU logical read returned a truncated range")
        return data[offset - start : offset - start + length]


def ntfs_partition_offsets(reader: QemuImageReader) -> list[int]:
    first = reader.read_at(0, 512)
    if first[3:11] == b"NTFS    ":
        return [0]
    if first[510:512] != b"\x55\xaa":
        raise ValueError("source has no supported partition table")
    mbr = [first[446 + 16 * i : 462 + 16 * i] for i in range(4)]
    offsets = []
    if any(entry[4] == 0xEE for entry in mbr):
        for sector in (512, 4096):
            header = reader.read_at(sector, sector)
            if header[:8] != b"EFI PART":
                continue
            size, crc = struct.unpack_from("<II", header, 12)
            if not 92 <= size <= sector:
                raise ValueError("invalid GPT header length")
            checked = bytearray(header[:size])
            checked[16:20] = bytes(4)
            if zlib.crc32(checked) != crc:
                raise ValueError("GPT header checksum mismatch")
            lba, count, entry_size, entries_crc = struct.unpack_from(
                "<QIII", header, 72
            )
            if count > 4096 or entry_size < 128 or entry_size > 1024 or entry_size % 8:
                raise ValueError("GPT table exceeds bounded parser contract")
            entries = reader.read_at(lba * sector, count * entry_size)
            if zlib.crc32(entries) != entries_crc:
                raise ValueError("GPT partition table checksum mismatch")
            for index in range(count):
                entry = entries[index * entry_size : (index + 1) * entry_size]
                if any(entry[:16]):
                    first_lba, last_lba = struct.unpack_from("<QQ", entry, 32)
                    if first_lba <= last_lba and (last_lba + 1) * sector <= reader.size:
                        offsets.append(first_lba * sector)
            break
        else:
            raise ValueError("protective MBR has no validated GPT header")
    else:
        offsets = [
            struct.unpack_from("<I", entry, 8)[0] * 512
            for entry in mbr
            if entry[4] == 7
        ]
    return sorted(
        {
            offset
            for offset in offsets
            if offset + 512 <= reader.size
            and reader.read_at(offset, 512)[3:11] == b"NTFS    "
        }
    )


def _stream_range(
    reader: QemuImageReader,
    partition: int,
    geometry: dict[str, Any],
    attribute: dict[str, Any],
    offset: int,
    size: int,
) -> bytes:
    if (
        attribute.get("runlist_complete") is not True
        or attribute.get("lowest_vcn") != 0
    ):
        raise ValueError("incomplete native MFT mapping pairs")
    cluster = geometry["bytes_per_cluster"]
    result = bytearray()
    requested_end = offset + size
    for run in attribute.get("data_runs", []):
        run_start = run["vcn"] * cluster
        run_end = run_start + run["cluster_count"] * cluster
        start, end = max(run_start, offset), min(run_end, requested_end)
        if start >= end:
            continue
        if (
            run["lcn"] is None
            or run["lcn"] + run["cluster_count"] > geometry["total_clusters"]
        ):
            raise ValueError("MFT range maps to missing or out-of-volume clusters")
        result.extend(
            reader.read_at(
                partition + run["lcn"] * cluster + start - run_start, end - start
            )
        )
    if len(result) != size:
        raise ValueError("MFT range is not completely covered")
    return bytes(result)


def read_ntfs_attribute_content(
    reader: QemuImageReader,
    partition: int,
    geometry: dict[str, Any],
    native_record: bytes,
    attribute_id: int,
    *,
    max_bytes: int = 16 * 1024 * 1024,
) -> bytes:
    parsed = parse_mft_record(native_record, record_size=geometry["mft_record_size"])
    if (
        parsed is None
        or parsed["attribute_list_present"]
        or parsed["attribute_parse_error_count"]
    ):
        raise ValueError(
            "DATA stream requires a complete native single-record attribute chain"
        )
    streams = [
        item
        for item in parsed["data_attributes"]
        if item["attribute_id"] == attribute_id
    ]
    if len(streams) != 1:
        raise ValueError("DATA attribute ID is absent or ambiguous")
    stream = streams[0]
    if stream["resident_status"] == "nonresident":
        return read_nonresident_stream(
            lambda offset, size: reader.read_at(partition + offset, size),
            stream,
            geometry,
            max_bytes=max_bytes,
        )
    fixed = apply_mft_fixup(native_record, sector_size=geometry["bytes_per_sector"])
    header = read_record_header(fixed)
    if header is None:
        raise ValueError("DATA resident record header is invalid")
    offset = header.first_attr_offset
    while offset + 16 <= header.used_size:
        attr, end = read_attribute_header(fixed, offset)
        if end or attr is None or attr.attr_length < 16:
            break
        if attr.attr_type == 0x80 and attr.attr_id == attribute_id:
            data = resident_value(fixed, offset, attr.attr_length)
            if data is None or len(data) > max_bytes:
                raise ValueError(
                    "resident DATA content is invalid or exceeds configured bound"
                )
            return data
        offset += attr.attr_length
    raise ValueError("resident DATA attribute could not be read")
