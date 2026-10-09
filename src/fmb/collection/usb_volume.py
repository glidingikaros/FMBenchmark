from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from fmb.collection.tsk_volume import DATA, NtfsVolume, ntfs_volume_offsets, open_image
from fmb.core.hashing import sha256_file
from fmb.core.json_io import write_json
from fmb.core.truth_guard import COMPANION_MEDIA
from fmb.index.scanners.usb_volume import lecmd_link_row, shell_link_from_lecmd

MAX_COMPANION_BYTES = 64 * 1024 * 1024


def manifest_artifact(manifest_path: Path, name: str) -> Path:
    manifest_path = manifest_path.resolve(strict=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    rows = [row for row in manifest["artifacts"] if row.get("file") == name]
    path = (manifest_path.parent / name).resolve(strict=True)
    if len(rows) != 1 or path.parent != manifest_path.parent:
        raise ValueError("native USB artifact is absent, ambiguous, or outside its manifest")
    row = rows[0]
    if path.stat().st_size != row["size_bytes"] or sha256_file(path) != row["sha256"]:
        raise ValueError("native USB artifact does not match its generation manifest")
    return path


def _companion_of(binding_file: str, companion: Any) -> bool:
    if binding_file == "native_media_binding.json":
        return companion == "native_media.vmdk"
    match = COMPANION_MEDIA.fullmatch(str(companion))
    return bool(match) and match.group(2) != "json" and binding_file == f"media_{match.group(1)}.json"


def extract_companion_streams(companion: Path, binding: dict[str, Any]) -> dict[str, bytes]:
    image = open_image(companion)
    size = int(image.get_size())
    if size != MAX_COMPANION_BYTES or binding["disk_size_bytes"] != size:
        raise ValueError("native USB companion is not the declared bounded disk")
    offsets = ntfs_volume_offsets(image)
    if len(offsets) != 1 or offsets[0] != binding["partition_offset_bytes"]:
        raise ValueError("native USB partition identity is absent or ambiguous")
    volume = NtfsVolume(image, offsets[0], max_read_bytes=MAX_COMPANION_BYTES)
    record_size = volume.record_size
    mft = volume.read_attribute(0, DATA, name="")
    if not mft or len(mft) % record_size or mft[:record_size] != volume.first_mft_record_on_disk():
        raise ValueError("native USB MFT is truncated or not source-bound")
    journal = volume.path_entry("/$Extend/$UsnJrnl")
    result = {"boot": volume.boot_sector, "mft": mft}
    for label, stream in (("journal", "$J"), ("journal_max", "$Max")):
        result[label] = volume.read_attribute(journal, DATA, name=stream)
    return result


def collect_usb_volume(*, generation_manifest_path: Path, kape_root: Path,
                       output_dir: Path, evidence_sha256: str,
                       binding_file: str = "native_media_binding.json") -> Path:
    if binding_file != "native_media_binding.json" and not re.fullmatch(r"media_[0-9a-f]{12}\.json", binding_file):
        raise ValueError("unsupported native USB binding filename")
    binding_path = manifest_artifact(generation_manifest_path, binding_file)
    binding = json.loads(binding_path.read_text(encoding="utf-8-sig"))
    if (binding.get("schema_version") != "native_media_binding.v1"
            or not _companion_of(binding_file, binding.get("companion_file"))
            or binding.get("disk_bus_type") != "USB"
            or binding.get("attachment_kind") != "hypervisor_virtual_usb_mass_storage"
            or binding.get("physical_host_device") is not False):
        raise ValueError("unsupported native USB binding")
    companion = manifest_artifact(generation_manifest_path, binding["companion_file"])
    declared = json.loads(generation_manifest_path.read_text(encoding="utf-8-sig"))
    if not any(row.get("sha256") == evidence_sha256 and row.get("file") != companion.name
               for row in declared["artifacts"]):
        raise ValueError("native USB manifest does not bind the collected operating-system image")
    suffix = binding["link_path"].replace("\\", "/")[2:].casefold()
    links = [path for path in kape_root.rglob("*") if path.is_file()
             and path.suffix.casefold() == ".lnk"
             and path.as_posix().casefold().endswith(suffix)]
    if len(links) != 1 or links[0].stat().st_size > 1024 * 1024:
        raise ValueError("native USB shortcut is absent or ambiguous in the KAPE bundle")
    link = links[0].read_bytes()
    shell_link_from_lecmd(lecmd_link_row(links[0])[1])
    streams = extract_companion_streams(companion, binding)
    output_dir.mkdir(parents=True, exist_ok=True)
    sources = {}
    for label, payload in {**streams, "link": link, "binding": binding_path.read_bytes()}.items():
        path = output_dir / (label + ".bin" if label != "binding" else binding_file)
        path.write_bytes(payload)
        sources[label] = {"file": path.name, "sha256": sha256_file(path), "size_bytes": len(payload)}
    receipt = output_dir / "native-usb-volume.json"
    write_json(receipt, {
        "schema_version": "native_usb_volume_sources.v1", "sources": sources,
        "evidence_sha256": evidence_sha256,
        "companion_path": str(companion), "companion_sha256": sha256_file(companion),
        "source_link_path": str(links[0]), "source_link_sha256": sha256_file(links[0]),
        "generation_manifest_path": str(generation_manifest_path.resolve()),
        "generation_manifest_sha256": sha256_file(generation_manifest_path),
        "native_binding_hash_verified": True, "truth_sources_used": [],
    })
    return receipt


def collect_usb_volumes(*, binding_files: list[str], generation_manifest_path: Path,
                        kape_root: Path, output_dir: Path, evidence_sha256: str) -> Path:
    if binding_files == ["native_media_binding.json"]:
        return collect_usb_volume(generation_manifest_path=generation_manifest_path,
            kape_root=kape_root, output_dir=output_dir, evidence_sha256=evidence_sha256)
    if (len(binding_files) != 3 or len(set(binding_files)) != 3
            or any(not re.fullmatch(r"media_[0-9a-f]{12}\.json", name) for name in binding_files)):
        raise ValueError("multi-volume collection requires three unique registered public bindings")
    rows = []
    for name in sorted(binding_files):
        receipt = collect_usb_volume(generation_manifest_path=generation_manifest_path,
            kape_root=kape_root, output_dir=output_dir / Path(name).stem,
            evidence_sha256=evidence_sha256, binding_file=name)
        rows.append({"binding_file": name, "file": receipt.relative_to(output_dir).as_posix(), "sha256": sha256_file(receipt)})
    index = output_dir / "native-usb-volumes.json"
    write_json(index, {"schema_version": "native_usb_volume_set.v1", "evidence_sha256": evidence_sha256,
                       "volumes": rows, "truth_sources_used": []})
    return index


def usb_volume_source_manifests(path: Path) -> tuple[Path, ...]:
    path = path.resolve(strict=True)
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if value.get("schema_version") == "native_usb_volume_sources.v1":
        return (path,)
    if value.get("schema_version") != "native_usb_volume_set.v1" or len(value.get("volumes", [])) != 3:
        raise ValueError("unsupported native USB source set")
    result, names, identities = [], set(), set()
    for row in value["volumes"]:
        name = row.get("binding_file", "")
        relative = Path(str(row.get("file", "")))
        if (not re.fullmatch(r"media_[0-9a-f]{12}\.json", name) or name in names
                or relative.parts != (Path(name).stem, "native-usb-volume.json")):
            raise ValueError("native USB set repeats or escapes a public binding")
        child = (path.parent / relative).resolve(strict=True)
        if child.parent.parent != path.parent or sha256_file(child) != row.get("sha256"):
            raise ValueError("native USB set source hash/path is invalid")
        manifest = json.loads(child.read_text(encoding="utf-8-sig"))
        if (manifest.get("schema_version") != "native_usb_volume_sources.v1"
                or manifest.get("evidence_sha256") != value["evidence_sha256"]
                or manifest.get("sources", {}).get("binding", {}).get("file") != name):
            raise ValueError("native USB set mixes operating-system evidence or binding names")
        identity = manifest.get("companion_sha256")
        if not identity or identity in identities:
            raise ValueError("native USB set reuses a companion")
        identities.add(identity)
        names.add(name)
        result.append(child)
    return tuple(result)
