from __future__ import annotations

import json
import os
import struct
import subprocess
import tempfile
from collections.abc import Callable
from itertools import pairwise
from pathlib import Path
from typing import Any

from fmb.generation.qemu_image import (
    QemuImageReader,
    _stream_range,
    ntfs_partition_offsets,
    read_ntfs_attribute_content,
)
from fmb.core.hashing import sha256_bytes
from fmb.index.scanners.mft import (
    UPDATE_SEQUENCE_STRIDE,
    apply_mft_fixup,
    mft_record_is_in_use,
    nonresident_data_semantics,
    parse_directory_i30_record,
    parse_mft_record,
    read_attribute_header,
    read_record_header,
    resident_value,
)
from fmb.index.scanners.ntfs import (
    parse_boot_sector,
    parse_index_allocation,
    read_nonresident_stream,
)
from fmb.index.scanners.usb_volume import parse_retained_journal


def _canonical_path(value: str) -> str:
    result = value.replace("/", "\\")
    if len(result) >= 2 and result[1] == ":":
        result = result[2:]
    result = result.strip("\\")
    if not result or any(part in ("", ".", "..") for part in result.split("\\")):
        raise ValueError(
            "generation NTFS target must be an absolute canonical Windows path"
        )
    return result.casefold()


def _locate(
    reader: QemuImageReader, paths: list[str]
) -> tuple[int, dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    targets = {_canonical_path(path): path for path in paths}
    if len(targets) != len(paths):
        raise ValueError("generation NTFS paths must be unique")
    basename_bytes = {path.rsplit("\\", 1)[-1].encode("utf-16le") for path in paths}
    matches = []
    for partition in ntfs_partition_offsets(reader):
        geometry = parse_boot_sector(reader.read_at(partition, 512))
        size, cluster = geometry["mft_record_size"], geometry["bytes_per_cluster"]
        raw_zero = reader.read_at(partition + geometry["mft_start_lcn"] * cluster, size)
        zero = parse_mft_record(raw_zero, record_size=size)
        if zero is None or zero["attribute_list_present"]:
            continue
        attrs = [item for item in zero["data_attributes"] if not item["stream_name"]]
        if len(attrs) != 1 or attrs[0].get("runlist_complete") is not True:
            continue
        mft = attrs[0]
        if mft["logical_size"] > 1024 * 1024 * 1024:
            raise ValueError("generation bounded MFT lookup exceeds 1GiB")
        cache: dict[int, dict[str, Any]] = {}

        def load(
            entry: int,
            *,
            cache=cache,
            partition=partition,
            geometry=geometry,
            mft=mft,
            size=size,
        ) -> dict[str, Any]:
            if entry not in cache:
                data = _stream_range(
                    reader, partition, geometry, mft, entry * size, size
                )
                parsed = parse_mft_record(
                    data, record_offset=entry * size, record_size=size
                )
                if parsed is None or not mft_record_is_in_use(parsed):
                    raise ValueError(
                        "generation target ancestor is not an active native record"
                    )
                cache[entry] = {**parsed, "raw": data}
            return cache[entry]

        def resolve(parsed: dict[str, Any], seen: frozenset[int] = frozenset()) -> str:
            entry = parsed["mft_entry"]
            if entry == 5:
                return ""
            if entry in seen or len(seen) > 100:
                raise ValueError("generation native path contains a cycle")
            names = [
                name
                for name in parsed["file_name_attributes"]
                if name["namespace"] != 2
            ]
            if len(names) != 1:
                raise ValueError(
                    "generation native path is ambiguous (hardlinks or multiple names)"
                )
            name = names[0]
            parent = load(name["parent_inode"])
            if parent["sequence_number"] != name["parent_sequence"]:
                raise ValueError("generation native parent sequence mismatch")
            base = resolve(parent, seen | {entry})
            return (base + "\\" + name["name"]).strip("\\").casefold()

        found = {}
        for offset in range(0, mft["logical_size"], 16 * 1024 * 1024):
            count = min(16 * 1024 * 1024, mft["logical_size"] - offset)
            chunk = _stream_range(reader, partition, geometry, mft, offset, count)
            offsets = set()
            for needle in basename_bytes:
                position = chunk.find(needle)
                while position >= 0:
                    offsets.add(position // size * size)
                    position = chunk.find(needle, position + 2)
            for local in offsets:
                data = chunk[local : local + size]
                parsed = parse_mft_record(
                    data, record_offset=offset + local, record_size=size
                )
                if (
                    parsed is None
                    or not mft_record_is_in_use(parsed)
                    or parsed["mft_entry"] < 16
                ):
                    continue
                if not any(
                    name["name"].casefold() == target.rsplit("\\", 1)[-1]
                    for target in targets
                    for name in parsed["file_name_attributes"]
                ):
                    continue
                path = resolve(parsed)
                if path in targets:
                    if path in found:
                        raise ValueError(
                            "generation target resolves to duplicate native paths"
                        )
                    found[path] = {**parsed, "raw": data}
        if set(found) == set(targets):
            matches.append((partition, geometry, mft, found))
    if len(matches) != 1:
        raise ValueError(
            "generation paths do not resolve uniquely in one supported NTFS volume"
        )
    return matches[0]


def _protect_record(fixed: bytes, original: bytes, sector_size: int) -> bytes:
    usa_offset, usa_count = struct.unpack_from("<HH", original, 4)
    if usa_count != len(original) // sector_size + 1:
        raise ValueError("generation MFT update sequence coverage is incomplete")
    result = bytearray(fixed)
    for sector in range(usa_count - 1):
        end = (sector + 1) * sector_size - 2
        replacement = usa_offset + 2 + 2 * sector
        result[replacement : replacement + 2] = fixed[end : end + 2]
        result[end : end + 2] = original[usa_offset : usa_offset + 2]
    return bytes(result)


def _volume_reader(
    reader: QemuImageReader, partition: int
) -> Callable[[int, int], bytes]:
    def read(offset: int, length: int) -> bytes:
        return b"".join(
            reader.read_at(
                partition + offset + start, min(16 * 1024 * 1024, length - start)
            )
            for start in range(0, length, 16 * 1024 * 1024)
        )

    return read


QEMU_IO_PAYLOADS_ARE_BINARY = os.name != "nt"


def _write_verified(
    reader: QemuImageReader,
    qemu_io: str,
    offset: int,
    data: bytes,
    *,
    prefix: str,
    name: str,
    readback_error: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix=prefix) as temp:
        if not QEMU_IO_PAYLOADS_ARE_BINARY:
            _write_window(reader, offset, data, Path(temp))
        else:
            (Path(temp) / name).write_bytes(data)
            subprocess.run(
                [
                    qemu_io,
                    "-f",
                    reader.format,
                    "-c",
                    f"write -s {name} {offset} {len(data)}",
                    str(reader.path),
                ],
                cwd=temp,
                capture_output=True,
                check=True,
                timeout=60,
            )
    if reader.read_at(offset, len(data)) != data:
        raise ValueError(readback_error)


def _write_window(reader: QemuImageReader, offset: int, data: bytes, temp: Path) -> None:
    start = offset // 512 * 512
    end = -(-(offset + len(data)) // 512) * 512
    window = bytearray(reader.read_at(start, end - start))
    window[offset - start : offset - start + len(data)] = data
    payload = temp / "window.raw"
    payload.write_bytes(window)
    target = {"driver": "raw", "offset": start, "size": end - start,
              "file": {"driver": reader.format, "file": {"driver": "file", "filename": str(reader.path)}}}
    subprocess.run(["qemu-img", "convert", "-n", "-f", "raw", str(payload), "json:" + json.dumps(target)],
                   capture_output=True, check=True, timeout=120)


def mutate_allocation_headers(
    image_path: Path,
    paths: list[str],
    *,
    validation_paths: list[str] | None = None,
    qemu_io: str = "qemu-io",
) -> dict[str, Any]:
    checked_paths = validation_paths or paths
    if not checked_paths or len(checked_paths) > 100:
        raise ValueError(
            "generation allocation validation requires 1..100 public paths"
        )
    if not set(map(_canonical_path, paths)) <= set(map(_canonical_path, checked_paths)):
        raise ValueError("generation allocation targets fall outside public population")
    reader = QemuImageReader(image_path)
    partition, geometry, mft, found = _locate(reader, checked_paths)
    operations = []
    validations = []
    for path in checked_paths:
        record = found[_canonical_path(path)]
        attrs = [item for item in record["data_attributes"] if not item["stream_name"]]
        if (
            record["attribute_list_present"]
            or record["attribute_parse_error_count"]
            or len(attrs) != 1
        ):
            raise ValueError(
                "generation allocation candidate has incomplete native attribute coverage"
            )
        data = attrs[0]
        validations.append(
            {
                "path": path,
                "mft_entry": record["mft_entry"],
                "sequence_number": record["sequence_number"],
                **{
                    key: data.get(key)
                    for key in (
                        "resident_status",
                        "is_sparse",
                        "is_compressed",
                        "logical_size",
                        "allocated_size",
                        "allocated_cluster_count",
                        "runlist_complete",
                    )
                },
            }
        )
    for path in paths:
        record = found[_canonical_path(path)]
        data = next(
            item for item in record["data_attributes"] if not item["stream_name"]
        )
        cluster = geometry["bytes_per_cluster"]
        if (
            data["resident_status"] != "nonresident"
            or data["attribute_flags"]
            or data.get("runlist_complete") is not True
            or data.get("lowest_vcn") != 0
        ):
            raise ValueError(
                "generation intervention only supports ordinary complete nonresident DATA"
            )
        if (
            data["allocated_size"] != data["allocated_cluster_count"] * cluster
            or data["logical_size"] > data["allocated_size"]
        ):
            raise ValueError("generation candidate is inconsistent before intervention")
        fixed = bytearray(
            apply_mft_fixup(record["raw"], sector_size=UPDATE_SEQUENCE_STRIDE)
        )
        header = read_record_header(fixed)
        attr_offset = header.first_attr_offset
        while attr_offset + 16 <= header.used_size:
            attr, end = read_attribute_header(fixed, attr_offset)
            if end or attr is None or attr.attr_length < 16:
                raise ValueError("generation DATA attribute could not be found")
            if attr.attr_type == 0x80 and attr.attr_id == data["attribute_id"]:
                break
            attr_offset += attr.attr_length
        new_allocated = data["allocated_size"] + cluster
        struct.pack_into("<Q", fixed, attr_offset + 40, new_allocated)
        modified = _protect_record(
            bytes(fixed), record["raw"], UPDATE_SEQUENCE_STRIDE
        )
        entry_offset = record["mft_entry"] * geometry["mft_record_size"]
        mappings = [
            run
            for run in mft["data_runs"]
            if run["vcn"] * cluster <= entry_offset
            and entry_offset + len(modified)
            <= (run["vcn"] + run["cluster_count"]) * cluster
        ]
        if len(mappings) != 1 or mappings[0]["lcn"] is None:
            raise ValueError(
                "generation target MFT record crosses unsupported physical runs"
            )
        disk_offset = (
            partition
            + mappings[0]["lcn"] * cluster
            + entry_offset
            - mappings[0]["vcn"] * cluster
        )
        if reader.read_at(disk_offset, len(modified)) != record["raw"]:
            raise ValueError("generation source changed before intervention")
        _write_verified(
            reader,
            qemu_io,
            disk_offset,
            modified,
            prefix="fmb-allocation-intervention-",
            name="record.bin",
            readback_error="generation allocation intervention readback failed",
        )
        operations.append(
            {
                "path": path,
                "mft_entry": record["mft_entry"],
                "sequence_number": record["sequence_number"],
                "allocated_size_before": data["allocated_size"],
                "allocated_size_after": new_allocated,
                "physical_record_offset": disk_offset,
                "record_sha256_before": sha256_bytes(record["raw"]),
                "record_sha256_after": sha256_bytes(modified),
                "runlist_unchanged": True,
                "content_unchanged": True,
            }
        )
    receipt = {
        "schema_version": "ntfs_allocation_intervention.v1",
        "scenario_id": "ntfs_allocation_01",
        "operation_count": len(operations),
        "postcondition_verified": True,
        "geometry": geometry,
        "intervention": "ordinary_unnamed_DATA_AllocatedLength_plus_one_cluster",
        "operations": operations,
        "validated_candidates": validations,
    }
    return receipt


def _strict_native_attributes(
    raw: bytes, geometry: dict[str, Any], *, reference: int, base_reference: int
) -> list[dict[str, Any]]:
    size, sector = geometry["mft_record_size"], UPDATE_SEQUENCE_STRIDE
    if len(raw) != size or raw[:4] != b"FILE":
        raise ValueError("native attribute chain has an invalid FILE record")
    usa, count = struct.unpack_from("<HH", raw, 4)
    first = struct.unpack_from("<H", raw, 20)[0]
    if (
        count != size // sector + 1
        or usa < 42
        or usa % 2
        or usa + count * 2 > first
        or usa + count * 2 > sector - 2
    ):
        raise ValueError("native attribute chain has incomplete USA coverage")
    fixed = apply_mft_fixup(raw, sector_size=sector)
    sequence, flags = (
        struct.unpack_from("<H", fixed, 16)[0],
        struct.unpack_from("<H", fixed, 22)[0],
    )
    used, allocated = struct.unpack_from("<II", fixed, 24)
    if (
        not flags & 1
        or flags & 2
        or sequence != reference >> 48
        or struct.unpack_from("<Q", fixed, 32)[0] != base_reference
        or first < 48
        or first % 8
        or used > size
        or allocated != size
        or first + 4 > used
    ):
        raise ValueError("native attribute chain record identity/header mismatch")
    result, ids, cursor = [], set(), first
    while cursor + 4 <= used:
        kind = struct.unpack_from("<I", fixed, cursor)[0]
        if kind == 0xFFFFFFFF:
            if used != cursor + 8:
                raise ValueError(
                    "native attribute chain has excess bytes after END marker"
                )
            return result
        if cursor + 16 > used:
            break
        length = struct.unpack_from("<I", fixed, cursor + 4)[0]
        form, name_length, name_offset, attr_flags, attr_id = struct.unpack_from(
            "<BBHHH", fixed, cursor + 8
        )
        minimum = 64 if form else 24
        if (
            kind == 0
            or kind % 16
            or form not in (0, 1)
            or length < minimum
            or length % 8
            or cursor + length > used
            or attr_id in ids
        ):
            raise ValueError("native attribute chain has an invalid attribute header")
        ids.add(attr_id)
        name_end = name_offset + name_length * 2
        if name_length and (
            name_offset < minimum or name_offset % 2 or name_end > length
        ):
            raise ValueError("native attribute chain has an invalid attribute name")
        name = fixed[cursor + name_offset : cursor + name_end] if name_length else b""
        name.decode("utf-16le", errors="strict")
        attribute = {
            "kind": kind,
            "name": name,
            "id": attr_id,
            "resident_status": "nonresident" if form else "resident",
            "attribute_flags": attr_flags,
            "lowest_vcn": 0,
        }
        if form:
            pairs = struct.unpack_from("<H", fixed, cursor + 32)[0]
            if pairs < max(64, name_end if name_length else 64):
                raise ValueError("native attribute chain name overlaps mapping pairs")
            attribute.update(
                nonresident_data_semantics(
                    fixed, attr_offset=cursor, attr_length=length
                )
            )
            attribute["compression_unit_exponent"] = struct.unpack_from(
                "<H", fixed, cursor + 34
            )[0]
            if not attribute["runlist_complete"]:
                raise ValueError("native attribute chain has incomplete mapping pairs")
        else:
            value_size, value_offset = struct.unpack_from("<IH", fixed, cursor + 16)
            if (
                value_offset < max(24, name_end if name_length else 24)
                or value_offset + value_size > length
            ):
                raise ValueError("native attribute chain has an invalid resident value")
            attribute["value"] = fixed[
                cursor + value_offset : cursor + value_offset + value_size
            ]
        result.append(attribute)
        cursor += length
    raise ValueError("native attribute chain lacks a complete END marker")


def _native_list_entries(value: bytes) -> list[dict[str, Any]]:
    if not value or len(value) > 65536:
        raise ValueError("native attribute list exceeds the supported byte bound")
    entries, cursor = [], 0
    while cursor < len(value):
        if cursor + 32 > len(value) or len(entries) >= 1024:
            raise ValueError("native attribute list has a partial/excess entry")
        kind, length, name_length, name_offset, vcn, reference, attr_id = (
            struct.unpack_from("<IHBBQQH", value, cursor)
        )
        if (
            not kind
            or kind == 0x20
            or kind % 16
            or length < 32
            or length % 8
            or cursor + length > len(value)
        ):
            raise ValueError("native attribute list has an invalid entry")
        name_end = name_offset + name_length * 2 if name_length else 26
        if name_length and (name_offset < 26 or name_offset % 2 or name_end > length):
            raise ValueError("native attribute list has an invalid name")
        name = value[cursor + name_offset : cursor + name_end] if name_length else b""
        name.decode("utf-16le", errors="strict")
        if length != (name_end + 7) & ~7:
            raise ValueError("native attribute list has excess alignment padding")
        entries.append(
            {
                "kind": kind,
                "name": name,
                "id": attr_id,
                "lowest_vcn": vcn,
                "reference": reference,
            }
        )
        cursor += length
    return entries


def _validate_native_runs(
    data: dict[str, Any], geometry: dict[str, Any]
) -> list[tuple[int, int]]:
    if (
        data.get("runlist_complete") is not True
        or data.get("lowest_vcn") != 0
        or data.get("attribute_flags")
        or data.get("compression_unit_exponent", 0)
        or not data.get("data_runs")
    ):
        raise ValueError(
            "native ordinary stream has incomplete/unsupported mapping pairs"
        )
    intervals, next_vcn = [], 0
    for run in data["data_runs"]:
        count, lcn = run["cluster_count"], run["lcn"]
        if (
            count <= 0
            or run["vcn"] != next_vcn
            or lcn is None
            or lcn < 0
            or lcn + count > geometry["total_clusters"]
        ):
            raise ValueError("native ordinary stream has invalid VCN/LCN coverage")
        intervals.append((lcn, lcn + count))
        next_vcn += count
    physical = sorted(intervals)
    if any(right[0] < left[1] for left, right in pairwise(physical)):
        raise ValueError("native ordinary stream has overlapping physical runs")
    if (
        data["allocated_size"] != next_vcn * geometry["bytes_per_cluster"]
        or not 0
        <= data["valid_data_length"]
        <= data["logical_size"]
        <= data["allocated_size"]
    ):
        raise ValueError("native ordinary stream sizes disagree with full allocation")
    return physical


def _resolve_native_data_chain(
    reader: QemuImageReader,
    partition: int,
    geometry: dict[str, Any],
    mft: dict[str, Any],
    record: dict[str, Any],
    *,
    max_bytes: int,
) -> tuple[dict[str, Any], dict[int, bytes], dict[str, Any]]:
    mft_ranges = _validate_native_runs(mft, geometry)
    size = geometry["mft_record_size"]
    entry = record["mft_entry"]
    base_ref = entry | (record["sequence_number"] << 48)
    if entry < 16 or (entry + 1) * size > mft["logical_size"]:
        raise ValueError("native base record lies outside bounded MFT coverage")
    base = _strict_native_attributes(
        record["raw"], geometry, reference=base_ref, base_reference=0
    )
    records, attributes = {entry: record["raw"]}, {entry: base}
    lists = [a for a in base if a["kind"] == 0x20]
    listed = []
    if lists:
        if (
            len(lists) != 1
            or lists[0]["resident_status"] != "resident"
            or lists[0]["name"]
            or lists[0]["attribute_flags"]
        ):
            raise ValueError(
                "native writer requires one ordinary resident attribute list"
            )
        listed = _native_list_entries(lists[0]["value"])
        references: dict[int, int] = {entry: base_ref}
        for item in listed:
            ref = item["reference"]
            target = ref & 0xFFFFFFFFFFFF
            if target in references and references[target] != ref:
                raise ValueError(
                    "native list aliases one record with multiple sequences"
                )
            references[target] = ref
        if len(references) > 128:
            raise ValueError("native attribute chain exceeds the record bound")
        for target, ref in references.items():
            if target == entry:
                continue
            if target < 16 or (target + 1) * size > mft["logical_size"]:
                raise ValueError("native extension lies outside bounded MFT coverage")
            raw = _stream_range(reader, partition, geometry, mft, target * size, size)
            attrs = _strict_native_attributes(
                raw, geometry, reference=ref, base_reference=base_ref
            )
            if any(a["kind"] == 0x20 for a in attrs):
                raise ValueError("native extension contains a nested attribute list")
            records[target], attributes[target] = raw, attrs
        expected = {
            (number, a["id"]): a
            for number, attrs in attributes.items()
            for a in attrs
            if a["kind"] != 0x20
        }
        seen = set()
        for item in listed:
            key = (item["reference"] & 0xFFFFFFFFFFFF, item["id"])
            match = expected.get(key)
            if (
                key in seen
                or match is None
                or any(item[k] != match[k] for k in ("kind", "name", "lowest_vcn"))
            ):
                raise ValueError(
                    "native attribute list entry does not resolve uniquely"
                )
            seen.add(key)
        if seen != set(expected):
            raise ValueError("native attribute list omits a native attribute")
    extents = [
        a
        for attrs in attributes.values()
        for a in attrs
        if a["kind"] == 0x80 and not a["name"]
    ]
    if not lists and len(extents) != 1:
        raise ValueError("native file has multiple DATA attributes without a list")
    if not extents or any(
        a["resident_status"] != "nonresident"
        or a["attribute_flags"]
        or a["compression_unit_exponent"]
        for a in extents
    ):
        raise ValueError(
            "native file transformation requires ordinary nonresident DATA"
        )
    extents.sort(key=lambda a: a["lowest_vcn"])
    next_vcn, runs = 0, []
    for extent in extents:
        if extent["lowest_vcn"] != next_vcn:
            raise ValueError("native DATA extent VCN coverage is not contiguous")
        next_vcn = extent["highest_vcn"] + 1
        runs.extend(extent["data_runs"])
    data = {
        **extents[0],
        "data_runs": runs,
        "highest_vcn": next_vcn - 1,
        "allocated_cluster_count": sum(r["cluster_count"] for r in runs),
        "data_run_count": len(runs),
    }
    data_ranges = _validate_native_runs(data, geometry)
    if (
        data["logical_size"] > max_bytes
        or not 0 <= data["valid_data_length"] <= data["logical_size"]
    ):
        raise ValueError("native transform requires bounded, consistently initialized bytes")
    if any(a < d and c < b for a, b in data_ranges for c, d in mft_ranges):
        raise ValueError("native file allocation overlaps MFT metadata")
    proof = {
        "coverage": "complete",
        "attribute_list_entry_count": len(listed),
        "record_count": len(records),
        "data_extent_count": len(extents),
        "record_sha256": {str(n): sha256_bytes(raw) for n, raw in records.items()},
    }
    return data, records, proof


def transform_native_file(
    image_path: Path,
    path: str,
    transform: Callable[[bytes], tuple[bytes, dict[str, Any]]],
    *,
    max_bytes: int = 64 * 1024 * 1024,
    qemu_io: str = "qemu-io",
) -> dict[str, Any]:
    reader = QemuImageReader(image_path)
    partition, geometry, mft, found = _locate(reader, [path])
    record = found[_canonical_path(path)]
    data, chain_records, chain_proof = _resolve_native_data_chain(
        reader, partition, geometry, mft, record, max_bytes=max_bytes
    )

    def verify_metadata() -> None:
        for number, raw in chain_records.items():
            if (
                _stream_range(
                    reader,
                    partition,
                    geometry,
                    mft,
                    number * geometry["mft_record_size"],
                    len(raw),
                )
                != raw
            ):
                raise ValueError("native attribute chain changed during transformation")

    original = read_nonresident_stream(
        _volume_reader(reader, partition), data, geometry, max_bytes=max_bytes
    )
    initialized = int(data["valid_data_length"])
    if initialized < len(original):
        original = original[:initialized] + bytes(len(original) - initialized)
    verify_metadata()
    modified, details = transform(original)
    if not isinstance(modified, bytes) or len(modified) != len(original):
        raise ValueError("native file transformation must return equal-length bytes")
    if modified[initialized:] != original[initialized:]:
        raise ValueError(
            "native file transformation may not write beyond the initialized data length"
        )
    verify_metadata()
    changes = []
    cluster = geometry["bytes_per_cluster"]
    for run in data["data_runs"]:
        if run["lcn"] is None:
            raise ValueError("native file transformation encountered an unmapped run")
        run_start = run["vcn"] * cluster
        run_length = min(run["cluster_count"] * cluster, initialized - run_start)
        for position in range(0, max(0, run_length), 16 * 1024 * 1024):
            offset = run_start + position
            size = min(16 * 1024 * 1024, run_length - position)
            before, after = (
                original[offset : offset + size],
                modified[offset : offset + size],
            )
            if before == after:
                continue
            physical = partition + run["lcn"] * cluster + position
            if reader.read_at(physical, size) != before:
                raise ValueError("native file bytes changed before transformation")
            _write_verified(
                reader,
                qemu_io,
                physical,
                after,
                prefix="fmb-native-file-transform-",
                name="content.bin",
                readback_error="native file transformation readback failed",
            )
            changes.append(
                {"file_offset": offset, "physical_offset": physical, "byte_count": size}
            )
    verify_metadata()
    return {
        "schema_version": "native_file_transformation.v1",
        "path": path,
        "mft_entry": record["mft_entry"],
        "sequence_number": record["sequence_number"],
        "size_bytes": len(original),
        "initialized_bytes": initialized,
        "sha256_before": sha256_bytes(original),
        "sha256_after": sha256_bytes(modified),
        "metadata_unchanged": True,
        "postcondition_verified": True,
        "written_ranges": changes,
        "transformation": details,
        "attribute_chain": chain_proof,
    }


def _mapped_patches(
    attribute: dict[str, Any],
    geometry: dict[str, Any],
    partition: int,
    offset: int,
    before: bytes,
    after: bytes,
) -> list[dict[str, Any]]:
    if len(before) != len(after) or not before:
        raise ValueError("native mapped mutation requires nonempty equal-length bytes")
    cluster = geometry["bytes_per_cluster"]
    cursor, patches = offset, []
    for run in attribute["data_runs"]:
        start, end = run["vcn"] * cluster, (run["vcn"] + run["cluster_count"]) * cluster
        if not start <= cursor < end:
            continue
        length = min(end - cursor, offset + len(before) - cursor)
        if run["lcn"] is None:
            raise ValueError("native mutation would write into a sparse range")
        relative = cursor - offset
        patches.append(
            {
                "logical_offset": cursor,
                "physical_offset": partition + run["lcn"] * cluster + cursor - start,
                "before": before[relative : relative + length],
                "after": after[relative : relative + length],
            }
        )
        cursor += length
        if cursor == offset + len(before):
            return patches
    raise ValueError("native mutation extends beyond complete mapped ranges")


def _rewrite_file_name(
    raw: bytes, attribute_id: int, old: bytes, new: bytes
) -> tuple[bytes, int]:
    fixed = bytearray(apply_mft_fixup(raw, sector_size=UPDATE_SEQUENCE_STRIDE))
    header = read_record_header(fixed)
    attr_offset, name_offset = header.first_attr_offset, None
    while attr_offset + 24 <= header.used_size:
        attr, end = read_attribute_header(fixed, attr_offset)
        if end or attr is None or attr.attr_length < 24:
            break
        if attr.attr_type == 0x30 and attr.attr_id == attribute_id:
            value_offset = struct.unpack_from("<H", fixed, attr_offset + 20)[0]
            name_offset = attr_offset + value_offset + 66
            if fixed[name_offset : name_offset + len(old)] != old:
                raise ValueError(
                    "USB FILE_NAME native value does not match parsed name"
                )
            fixed[name_offset : name_offset + len(old)] = new
            break
        attr_offset += attr.attr_length
    if name_offset is None:
        raise ValueError("USB primary FILE_NAME attribute was not found")
    return _protect_record(bytes(fixed), raw, UPDATE_SEQUENCE_STRIDE), name_offset


def _usn_journal(
    reader: QemuImageReader,
    partition: int,
    geometry: dict[str, Any],
    journal_record: dict[str, Any],
) -> tuple[dict[str, Any], bytes, bytes]:
    if (
        journal_record["attribute_parse_error_count"]
        or journal_record["attribute_list_present"]
    ):
        raise ValueError(
            "USB journal requires complete native attribute-chain coverage"
        )
    journal_attrs = [
        a for a in journal_record["data_attributes"] if a["stream_name"] == "$J"
    ]
    if len(journal_attrs) != 1:
        raise ValueError("USB journal requires one complete native $J stream")
    max_attrs = [
        a for a in journal_record["data_attributes"] if a["stream_name"] == "$Max"
    ]
    if len(max_attrs) != 1:
        raise ValueError("USB journal requires one complete native $Max stream")
    maximum = read_ntfs_attribute_content(
        reader,
        partition,
        geometry,
        journal_record["raw"],
        max_attrs[0]["attribute_id"],
    )
    journal = read_nonresident_stream(
        _volume_reader(reader, partition),
        journal_attrs[0],
        geometry,
        max_bytes=64 * 1024 * 1024,
    )
    return journal_attrs[0], maximum, journal


def _journal_name_rows(
    journal: bytes,
    maximum: bytes,
    file_reference_number: int,
    original_name: str,
    parent_reference: int,
) -> list[dict[str, Any]]:
    history = parse_retained_journal(journal, maximum)
    if not history["scan_complete"]:
        raise ValueError("USB journal includes malformed or unsupported native records")
    all_maximum = maximum[:24] + bytes(8) + maximum[32:]
    all_history = parse_retained_journal(journal, all_maximum)
    selected = [
        row
        for row in all_history["records"]
        if row["file_reference_number"] == file_reference_number
        and row["file_name"] == original_name
    ]
    if not any(
        row["reason"] & 0x200
        and row["file_reference_number"] == file_reference_number
        and row["file_name"] == original_name
        for row in history["records"]
    ):
        raise ValueError("USB exact-reference original-name journal deletion is absent")
    if any(row["reason"] & (0x1000 | 0x2000) for row in selected):
        raise ValueError("USB history target already contains a rename reason")
    if any(row["parent_file_reference_number"] != parent_reference for row in selected):
        raise ValueError(
            "USB historical journal parent differs from inactive FILE_NAME parent"
        )
    return selected


def rewrite_usb_history_names(
    image_path: Path,
    *,
    file_reference_number: int,
    original_name: str,
    replacement_name: str,
    qemu_io: str = "qemu-io",
) -> dict[str, Any]:
    old, new = original_name.encode("utf-16le"), replacement_name.encode("utf-16le")
    if (
        not old
        or len(old) != len(new)
        or old == new
        or len(old) > 510
        or any(char in original_name + replacement_name for char in "\\/\x00")
        or not 0 < file_reference_number < 1 << 64
        or not file_reference_number >> 48
    ):
        raise ValueError(
            "USB history alteration requires distinct equal-length names and exact FRN"
        )
    reader = QemuImageReader(image_path)
    journal_path = r"C:\$Extend\$UsnJrnl"
    partition, geometry, mft, found = _locate(reader, [journal_path])
    size = geometry["mft_record_size"]
    entry, sequence = (
        file_reference_number & ((1 << 48) - 1),
        file_reference_number >> 48,
    )
    raw = _stream_range(reader, partition, geometry, mft, entry * size, size)
    record = parse_mft_record(raw, record_offset=entry * size, record_size=size)
    if (
        record is None
        or sequence >= 65535
        or record["sequence_number"] != sequence + 1
        or mft_record_is_in_use(record)
        or record["attribute_parse_error_count"]
        or record["attribute_list_present"]
    ):
        raise ValueError(
            "USB history target is not the complete inactive immediate successor of the historical MFT identity"
        )
    names = [name for name in record["file_name_attributes"] if name["namespace"] != 2]
    if len(names) != 1 or names[0]["name"] != original_name:
        raise ValueError(
            "USB history target does not have one exact original primary FILE_NAME"
        )
    modified, name_offset = _rewrite_file_name(raw, names[0]["attribute_id"], old, new)
    patches = _mapped_patches(mft, geometry, partition, entry * size, raw, modified)
    journal_attr, maximum, journal = _usn_journal(
        reader, partition, geometry, found[_canonical_path(journal_path)]
    )
    selected = _journal_name_rows(
        journal, maximum, file_reference_number, original_name, names[0]["parent_reference"]
    )
    journal_after = bytearray(journal)
    operations = []
    for row in selected:
        offset = row["record_offset"] + row["file_name_offset"]
        if journal[offset : offset + len(old)] != old or row["file_name_length"] != len(
            old
        ):
            raise ValueError(
                "USB journal native filename bounds differ from parsed name"
            )
        journal_after[offset : offset + len(old)] = new
        patches.extend(
            _mapped_patches(journal_attr, geometry, partition, offset, old, new)
        )
        operations.append(
            {
                "record_offset": row["record_offset"],
                "name_offset": offset,
                "file_reference_number": row["file_reference_number"],
                "usn": row["usn"],
                "reason": row["reason"],
                "timestamp_filetime": row["timestamp_filetime"],
            }
        )
    for patch in patches:
        if (
            reader.read_at(patch["physical_offset"], len(patch["before"]))
            != patch["before"]
        ):
            raise ValueError("USB native source changed before intervention")
    for patch in patches:
        _write_verified(
            reader,
            qemu_io,
            patch["physical_offset"],
            patch["after"],
            prefix="fmb-usb-history-intervention-",
            name="content.bin",
            readback_error="USB native history intervention readback failed",
        )
    return {
        "schema_version": "usb_history_name_intervention.v1",
        "scenario_id": "usb_volume_activity_gap_01",
        "file_reference_number": file_reference_number,
        "original_name": original_name,
        "replacement_name": replacement_name,
        "mft_entry": entry,
        "sequence_number": record["sequence_number"],
        "historical_sequence_number": sequence,
        "mft_sequence_relation": "freed_immediate_successor",
        "mft_name_offset": name_offset,
        "mft_record_sha256_before": sha256_bytes(raw),
        "mft_record_sha256_after": sha256_bytes(modified),
        "journal_sha256_before": sha256_bytes(journal),
        "journal_sha256_after": sha256_bytes(bytes(journal_after)),
        "journal_records": operations,
        "object_activity_preserved": True,
        "postcondition_verified": True,
        "written_ranges": [
            {
                "physical_offset": patch["physical_offset"],
                "logical_offset": patch["logical_offset"],
                "size_bytes": len(patch["after"]),
                "sha256_before": sha256_bytes(patch["before"]),
                "sha256_after": sha256_bytes(patch["after"]),
            }
            for patch in patches
        ],
    }


def _index_streams(
    reader: QemuImageReader,
    partition: int,
    geometry: dict[str, Any],
    record: dict[str, Any],
) -> tuple[bytes, bytes]:
    fixed = apply_mft_fixup(record["raw"], sector_size=UPDATE_SEQUENCE_STRIDE)
    header = read_record_header(fixed)
    if header is None:
        raise ValueError("generation I30 directory record header is invalid")
    wanted_name = "$I30".encode("utf-16le")
    allocation: dict[str, Any] | None = None
    bitmap: bytes | None = None
    offset = header.first_attr_offset
    while offset + 16 <= header.used_size:
        attr, end = read_attribute_header(fixed, offset)
        if end or attr is None or attr.attr_length < 16:
            break
        name_length = fixed[offset + 9]
        name_offset = struct.unpack_from("<H", fixed, offset + 10)[0]
        attr_name = (
            bytes(fixed[offset + name_offset : offset + name_offset + 2 * name_length])
            if name_length
            else b""
        )
        if attr_name == wanted_name and attr.attr_type == 0xA0 and attr.nonresident:
            if allocation is not None:
                raise ValueError("generation I30 directory has duplicate INDEX_ALLOCATION")
            allocation = {
                **nonresident_data_semantics(
                    fixed, attr_offset=offset, attr_length=attr.attr_length
                ),
                "lowest_vcn": struct.unpack_from("<Q", fixed, offset + 16)[0],
                "attribute_flags": attr.flags,
            }
        elif attr_name == wanted_name and attr.attr_type == 0xB0 and not attr.nonresident:
            if bitmap is not None:
                raise ValueError("generation I30 directory has duplicate BITMAP")
            bitmap = resident_value(fixed, offset, attr.attr_length)
        offset += attr.attr_length
    if allocation is None or bitmap is None:
        raise ValueError(
            "generation I30 directory lacks one nonresident INDEX_ALLOCATION "
            "with a resident bitmap"
        )
    data = read_nonresident_stream(
        lambda stream_offset, size: reader.read_at(partition + stream_offset, size),
        allocation,
        geometry,
        max_bytes=64 * 1024 * 1024,
        allocated=True,
    )
    return data, bitmap


def _reference_state(
    reader: QemuImageReader,
    partition: int,
    geometry: dict[str, Any],
    mft: dict[str, Any],
    entry: int,
    sequence: int,
) -> str:
    size = geometry["mft_record_size"]
    if entry < 0 or entry * size + size > mft["logical_size"]:
        return "unknown"
    data = _stream_range(reader, partition, geometry, mft, entry * size, size)
    if not any(data):
        return "unknown"
    parsed = parse_mft_record(data, record_offset=entry * size, record_size=size)
    if parsed is None:
        return "unknown"
    if parsed["sequence_number"] != sequence or not mft_record_is_in_use(parsed):
        return "absent"
    return "present"


def verify_i30_residue(
    image_path: Path, directories: list[str], removed_names: list[str], *,
    removed_references: dict[str, tuple[int, int]] | None = None,
) -> dict[str, Any]:
    if not directories or len(directories) > 100 or not removed_names:
        raise ValueError(
            "generation I30 postcondition requires 1..100 directories and removed names"
        )
    live_surfaces = ("index_root", "index_allocation_active")
    wanted = {name.casefold() for name in removed_names}
    if removed_references is not None and (
        set(removed_references) != set(directories)
        or any(len(value) != 2 or any(type(n) is not int or n < 1 for n in value)
               or value[1] > 65535 for value in removed_references.values())
    ):
        raise ValueError("generation I30 removed references are incomplete or invalid")
    reader = QemuImageReader(image_path)
    partition, geometry, mft, found = _locate(reader, directories)
    size = geometry["mft_record_size"]
    results = []
    for path in directories:
        record = found[_canonical_path(path)]
        entry, sequence = record["mft_entry"], record["sequence_number"]
        parsed = parse_directory_i30_record(
            record["raw"], record_offset=entry * size, record_size=size
        )
        if parsed is None or not parsed["is_active_directory"]:
            raise ValueError(
                "generation I30 target is not an active native directory record"
            )
        entries = [
            *parsed["resident_index_root_entries"],
            *parsed["index_root_slack_entries"],
            *parsed["record_slack_entries"],
        ]
        if parsed["index_allocation_present"]:
            data, bitmap = _index_streams(reader, partition, geometry, record)
            allocation = parse_index_allocation(
                data,
                bitmap=bitmap,
                block_size=int(parsed["index_block_size"]),
                sector_size=UPDATE_SEQUENCE_STRIDE,
                cluster_size=geometry["bytes_per_cluster"],
                parent_entry=entry,
                parent_sequence=sequence,
            )
            if not allocation["index_allocation_parsed"]:
                raise ValueError(
                    "generation I30 index buffers did not parse completely: "
                    + json.dumps(allocation["index_buffer_errors"])[:400]
                )
            entries.extend(allocation["entries"])
        live = {
            str(item["name"]).casefold()
            for item in entries
            if item["residue_surface"] in live_surfaces
        }
        expected_reference = removed_references[path] if removed_references is not None else None
        live_original = any(
            item["residue_surface"] in live_surfaces
            and (int(item["file_reference_entry"]), int(item["file_reference_sequence"])) == expected_reference
            for item in entries
        ) if expected_reference is not None else bool(wanted & live)
        if live_original:
            raise ValueError(
                "generation I30 removed child is still live in the directory index"
            )
        residue = []
        for item in entries:
            if (
                str(item["name"]).casefold() not in wanted
                or item["residue_surface"] in live_surfaces
                or (expected_reference is not None and
                    (int(item["file_reference_entry"]), int(item["file_reference_sequence"])) != expected_reference)
            ):
                continue
            state = _reference_state(
                reader,
                partition,
                geometry,
                mft,
                int(item["file_reference_entry"]),
                int(item["file_reference_sequence"]),
            )
            residue.append(
                {
                    "name": str(item["name"]),
                    "surface": str(item["residue_surface"]),
                    "file_reference_entry": int(item["file_reference_entry"]),
                    "file_reference_sequence": int(item["file_reference_sequence"]),
                    "referenced_record_state": state,
                }
            )
        absent = [item for item in residue if item["referenced_record_state"] == "absent"]
        results.append(
            {
                "directory": path,
                "mft_entry": entry,
                "sequence_number": sequence,
                "removed_name_count": len(wanted),
                "residue_entry_count": len(residue),
                "absent_reference_residue_count": len(absent),
                "residue_names": sorted({item["name"] for item in absent}),
                "residue_surfaces": sorted({item["surface"] for item in absent}),
                "index_allocation_present": bool(parsed["index_allocation_present"]),
                "postcondition_verified": bool(absent),
            }
        )
    if not all(row["postcondition_verified"] for row in results):
        raise ValueError(
            "generation I30 residue postcondition failed: a cleaned directory left "
            "no header-intact residue for its removed children"
        )
    return {
        "schema_version": "i30_residue_postcondition.v1",
        "scenario_id": "directory_cleaning_i30_01",
        "image_modified": False,
        "directories": results,
        "postcondition_verified": True,
    }
