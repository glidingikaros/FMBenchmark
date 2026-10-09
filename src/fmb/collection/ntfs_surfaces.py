from __future__ import annotations

from pathlib import Path
from typing import Any

from fmb.collection.tsk_volume import (
    BITMAP,
    DATA,
    INDEX_ALLOCATION,
    NtfsVolume,
    ntfs_volume_offsets,
    open_image,
)
from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.json_io import write_json
from fmb.index.scanners.mft import parse_directory_i30_record, parse_mft_record

MAX_STREAM_BYTES = 16 * 1024 * 1024


def bind_native_volume(image: Any, raw_mft_path: Path) -> NtfsVolume:
    matches = []
    with raw_mft_path.open("rb") as source:
        for offset in ntfs_volume_offsets(image):
            volume = NtfsVolume(image, offset)
            source.seek(0)
            expected = source.read(volume.record_size)
            if volume.first_mft_record_on_disk() == expected and volume.mft_record(0) == expected:
                matches.append(volume)
    if len(matches) != 1:
        raise ValueError(
            "collected MFT does not bind to exactly one native source volume"
        )
    return matches[0]


def collect_ntfs_surfaces(
    *,
    evidence_image: Path,
    raw_mft_path: Path,
    records: list[dict[str, Any]],
    output_dir: Path,
    evidence_sha256: str | None = None,
) -> Path:
    if len(records) > 2000:
        raise ValueError("native NTFS record request exceeds 2000-member bound")
    volume = bind_native_volume(open_image(evidence_image), raw_mft_path)
    size = volume.record_size
    output_dir.mkdir(parents=True, exist_ok=True)
    boot_path = output_dir / "boot-sector.bin"
    boot_path.write_bytes(volume.boot_sector)
    members = []
    with raw_mft_path.open("rb") as source:
        for item in records:
            entry, sequence = int(item["mft_entry"]), int(item["sequence_number"])
            if entry < 0 or not 0 < sequence <= 65535:
                raise ValueError("invalid requested native MFT identity")
            offset = entry * size
            native = volume.mft_record(entry)
            source.seek(offset)
            if source.read(size) != native:
                raise ValueError(f"native/collected MFT record mismatch at entry {entry}")
            parsed = parse_mft_record(native, record_offset=offset, record_size=size)
            if parsed is None or parsed["sequence_number"] != sequence:
                raise ValueError(
                    f"native identity could not be validated at entry {entry}"
                )
            record_path = output_dir / f"mft-{entry}-{sequence}.bin"
            record_path.write_bytes(native)
            member = {
                **item,
                "native_identity_verified": True,
                "record_file": record_path.name,
                "record_sha256": sha256_bytes(native),
            }
            if item.get("kind") == "ads":
                member["named_streams"] = []
                for stream in parsed["data_attributes"]:
                    if not stream["stream_name"]:
                        continue
                    saved = {
                        "stream_name": stream["stream_name"],
                        "attribute_id": stream["attribute_id"],
                        "logical_size": stream["logical_size"],
                    }
                    try:
                        data = volume.read_attribute(
                            entry, DATA, attribute_id=stream["attribute_id"], max_bytes=MAX_STREAM_BYTES
                        )
                        path = (
                            output_dir
                            / f"ads-{entry}-{sequence}-{stream['attribute_id']}.bin"
                        )
                        path.write_bytes(data)
                        saved.update(
                            {
                                "content_file": path.name,
                                "content_sha256": sha256_bytes(data),
                                "content_complete": True,
                            }
                        )
                    except ValueError as error:
                        saved.update(
                            {"content_complete": False, "content_error": str(error)}
                        )
                    member["named_streams"].append(saved)
            if item.get("kind") == "directory":
                directory = parse_directory_i30_record(
                    native, record_offset=offset, record_size=size
                )
                if directory is None:
                    raise ValueError(f"native I30 directory record is invalid: {entry}")
                member["index_allocation_present"] = directory[
                    "index_allocation_present"
                ]
                member["index_block_size"] = directory["index_block_size"]
                if directory["index_allocation_present"]:
                    try:
                        for attribute_type, label in (
                            (INDEX_ALLOCATION, "index_allocation"),
                            (BITMAP, "index_bitmap"),
                        ):
                            data = volume.read_attribute(
                                entry,
                                attribute_type,
                                name="$I30",
                                allocated=attribute_type == INDEX_ALLOCATION,
                            )
                            path = output_dir / f"{label}-{entry}-{sequence}.bin"
                            path.write_bytes(data)
                            member[label + "_file"] = path.name
                            member[label + "_sha256"] = sha256_bytes(data)
                        member["backing_streams_complete"] = True
                    except ValueError as error:
                        member["backing_streams_complete"] = False
                        member["backing_stream_error"] = str(error)
            members.append(member)
    manifest = output_dir / "native-ntfs.json"
    write_json(
        manifest,
        {
            "schema_version": "native_ntfs_surfaces.v1",
            "evidence_image": str(evidence_image.absolute()),
            "evidence_sha256": evidence_sha256 or sha256_file(evidence_image),
            "raw_mft_sha256": sha256_file(raw_mft_path),
            "partition_offset_bytes": volume.offset,
            "boot_sector_file": boot_path.name,
            "boot_sector_sha256": sha256_file(boot_path),
            "geometry": volume.geometry,
            "records": members,
            "truth_sources_used": [],
        },
    )
    return manifest
