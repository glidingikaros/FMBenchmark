from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re
import struct
import uuid
import zlib

from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.json_io import load_json_object, write_json
from fmb.index.adapters.ntfs_allocation import load_native_surfaces
from fmb.index.scanners.mft import parse_mft_record, mft_record_is_in_use


def bind_native_volume(context: dict, manifest_path: Path, raw_mft_path: Path) -> dict:
    manifest = load_native_surfaces(manifest_path, raw_mft_path)
    geometry = manifest["geometry"]
    size = geometry["mft_record_size"]
    with raw_mft_path.open("rb") as source:
        source.seek(3 * size)
        raw = source.read(size)
    record = parse_mft_record(raw, record_offset=3 * size, record_size=size)
    if (not record or not mft_record_is_in_use(record)
            or not any(r.get("name") == "$Volume" for r in record.get("file_name_attributes", []))):
        raise ValueError("native volume identity requires the active $Volume record")
    created = (record.get("metadata_timestamps") or {}).get("created", {}).get("ntfs_filetime")
    serial = geometry["volume_serial_number"]
    if type(created) is not int or created <= 0 or not context.get("mft_volume_id"):
        raise ValueError("native volume creation or MFT source identity is unavailable")
    alias = f"volume{{{created:016x}-{serial[-8:].lower()}}}"
    proof = {"native_volume_token": alias, "native_volume_creation_filetime": created,
             "native_volume_serial_number": serial,
             "native_volume_boot_source_ref": "source:" + manifest["boot_sector_sha256"][:16] + ":boot",
             "native_volume_mft_source_ref": "source:" + manifest["raw_mft_sha256"][:16] + ":entry=3",
             "native_volume_manifest_sha256": sha256_file(manifest_path)}
    result = deepcopy(context)
    result["indexed_volumes"] = set(result.get("indexed_volumes", set())) | {alias}
    result["native_volume_bindings"] = {alias: proof}
    result["native_volume_source_paths"] = [str(manifest_path), str(raw_mft_path),
                                           str(manifest_path.parent / manifest["boot_sector_file"])]
    return result


def collect_drive_binding(native_manifest_path: Path, kape_root: Path, output: Path) -> dict:
    from Registry import Registry
    from fmb.collection.tsk_volume import ntfs_volume_offsets, open_image, read_image

    if output.exists():
        raise ValueError("native drive binding must be a new record")
    manifest = load_json_object(native_manifest_path, label="native NTFS sources")
    sources = list(kape_root.glob("targets/*/Windows/System32/config/SYSTEM"))
    if len(sources) != 1:
        raise ValueError("drive binding needs the unique collected SYSTEM hive")
    system = sources[0]
    header = system.read_bytes()[:4096]
    if header[:4] != b"regf" or header[4:8] != header[8:12]:
        raise ValueError("drive binding requires a clean native SYSTEM hive")
    image = open_image(Path(manifest["evidence_image"]))
    if manifest["partition_offset_bytes"] not in ntfs_volume_offsets(image):
        raise ValueError("native NTFS offset is not in the validated partition table")
    found = []
    for sector in (512, 4096):
        gpt = read_image(image, sector, sector)
        if gpt[:8] != b"EFI PART":
            continue
        size, crc = struct.unpack_from('<II', gpt, 12)
        checked = bytearray(gpt[:size])
        checked[16:20] = bytes(4)
        if not 92 <= size <= sector or zlib.crc32(checked) != crc:
            raise ValueError("GPT header is invalid")
        lba, count, width, checksum = struct.unpack_from('<QIII', gpt, 72)
        if count > 4096 or not 128 <= width <= 1024:
            raise ValueError("GPT entries exceed the bounded contract")
        entries = read_image(image, lba*sector, count*width)
        if zlib.crc32(entries) != checksum:
            raise ValueError("GPT entry checksum is invalid")
        for n in range(count):
            entry = entries[n*width:(n+1)*width]
            if any(entry[:16]) and struct.unpack_from('<Q', entry, 32)[0]*sector == manifest["partition_offset_bytes"]:
                found.append((entry[16:32], n))
        break
    if len(found) != 1:
        raise ValueError("drive binding requires an unambiguous GPT partition identity")
    guid, ordinal = found[0]
    system_sha256 = sha256_file(system)
    values = []
    for value in Registry.Registry(str(system)).open('MountedDevices').values():
        if re.fullmatch(r"\\DosDevices\\[A-Za-z]:", value.name()):
            raw = value.value()
            if isinstance(raw, bytes):
                values.append({"name": value.name(), "bytes_hex": raw.hex(),
                    "source_record_ref": 'source:'+system_sha256[:16]+':MountedDevices:'+value.name()})
    proof = {"partition_offset_bytes": manifest["partition_offset_bytes"],
             "gpt_partition_id": str(uuid.UUID(bytes_le=guid)),
             "gpt_partition_entry_hex": entries[ordinal*width:(ordinal+1)*width].hex(),
             "gpt_partition_source_ref": 'source:'+sha256_bytes(entries)[:16]+f':GPT-entry={ordinal}',
             "mounted_device_values": values}
    letters = drive_letters_from_proof(proof)
    if not letters:
        raise ValueError("no retained drive-letter mapping matches the native partition")
    write_json(output, {"schema_version": "native_drive_letter_binding.v1", "proof": proof,
        "system_path": str(system.resolve()), "system_sha256": system_sha256,
        "native_manifest_path": str(native_manifest_path.resolve()),
        "native_manifest_sha256": sha256_file(native_manifest_path), "truth_sources_used": []})
    return proof


def drive_letters_from_proof(proof: dict) -> set[str]:
    entry = bytes.fromhex(proof["gpt_partition_entry_hex"])
    if len(entry) < 128 or str(uuid.UUID(bytes_le=entry[16:32])) != proof["gpt_partition_id"]:
        raise ValueError("drive-letter proof contradicts the native partition entry")
    expected = (b'DMIO:ID:' + entry[16:32]).hex()
    return {row["name"][-2].lower() for row in proof["mounted_device_values"]
            if re.fullmatch(r"\\DosDevices\\[A-Za-z]:", row["name"]) and row["bytes_hex"] == expected}


def load_drive_binding(path: Path, *, locate=Path) -> dict:
    value = load_json_object(path, label="native drive-letter binding")
    if value.get("schema_version") != "native_drive_letter_binding.v1":
        raise ValueError("unknown drive-letter binding")
    for label in ("system", "native_manifest"):
        if sha256_file(locate(value[label+"_path"])) != value[label+"_sha256"]:
            raise ValueError("native drive-binding source changed")
    drive_letters_from_proof(value["proof"])
    return value["proof"]
