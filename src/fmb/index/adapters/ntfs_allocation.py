from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fmb.core.hashing import sha256_file
from fmb.core.json_io import write_json
from fmb.index.contract.evidence_index import normalize_parser_output
from fmb.index.scanners.mft import mft_record_is_in_use, parse_mft_record
from fmb.index.scanners.ntfs import parse_boot_sector


def sidecar_file(manifest_path: Path, name: str, expected_hash: str) -> Path:
    path = (manifest_path.parent / name).resolve(strict=True)
    if (
        path.parent != manifest_path.parent.resolve()
        or sha256_file(path) != expected_hash
    ):
        raise ValueError("native NTFS sidecar path or hash validation failed")
    return path


def native_sidecar_files(manifest_path: Path, manifest: dict[str, Any]) -> list[Path]:
    paths = [
        sidecar_file(
            manifest_path, manifest["boot_sector_file"], manifest["boot_sector_sha256"]
        )
    ]
    for member in manifest["records"]:
        paths.append(
            sidecar_file(manifest_path, member["record_file"], member["record_sha256"])
        )
        for label in ("index_allocation", "index_bitmap"):
            if label + "_file" in member:
                paths.append(
                    sidecar_file(
                        manifest_path,
                        member[label + "_file"],
                        member[label + "_sha256"],
                    )
                )
        for stream in member.get("named_streams", []):
            if stream.get("content_complete") is True:
                paths.append(
                    sidecar_file(
                        manifest_path, stream["content_file"], stream["content_sha256"]
                    )
                )
    return list(dict.fromkeys(paths))


def load_native_surfaces(manifest_path: Path, raw_mft_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "native_ntfs_surfaces.v1" or manifest.get(
        "raw_mft_sha256"
    ) != sha256_file(raw_mft_path):
        raise ValueError("native NTFS manifest does not bind to the collected MFT")
    boot = sidecar_file(
        manifest_path, manifest["boot_sector_file"], manifest["boot_sector_sha256"]
    )
    geometry = parse_boot_sector(boot.read_bytes())
    if manifest.get("geometry") != geometry:
        raise ValueError("native NTFS geometry does not match its boot-sector bytes")
    with raw_mft_path.open("rb") as source:
        identities = set()
        for item in manifest["records"]:
            identity = (int(item["mft_entry"]), int(item["sequence_number"]))
            if (
                identity in identities
                or item.get("native_identity_verified") is not True
            ):
                raise ValueError("native NTFS duplicate or unverified record identity")
            identities.add(identity)
            path = sidecar_file(
                manifest_path, item["record_file"], item["record_sha256"]
            )
            raw = path.read_bytes()
            source.seek(identity[0] * geometry["mft_record_size"])
            if len(raw) != geometry["mft_record_size"] or source.read(len(raw)) != raw:
                raise ValueError(
                    "native NTFS retained record differs from collected MFT"
                )
            parsed = parse_mft_record(
                raw, record_offset=identity[0] * len(raw), record_size=len(raw)
            )
            if parsed is None or parsed["sequence_number"] != identity[1]:
                raise ValueError(
                    "native NTFS retained record cannot validate its identity"
                )
    return manifest


def ntfs_allocation_parser_run(
    *,
    native_manifest_path: Path,
    raw_mft_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    filesystem_scope_id: str,
) -> dict[str, Any]:
    if not filesystem_scope_id:
        raise ValueError(
            "native allocation needs the validated MFT parser filesystem scope"
        )
    manifest = load_native_surfaces(native_manifest_path, raw_mft_path)
    geometry = manifest["geometry"]
    observations = []
    complete = True
    for member in manifest["records"]:
        if member.get("kind") != "file":
            continue
        entry, sequence = int(member["mft_entry"]), int(member["sequence_number"])
        raw_path = sidecar_file(
            native_manifest_path, member["record_file"], member["record_sha256"]
        )
        raw = raw_path.read_bytes()
        parsed = parse_mft_record(
            raw, record_offset=entry * len(raw), record_size=len(raw)
        )
        if parsed is None or not mft_record_is_in_use(parsed):
            complete = False
            continue
        streams = [
            item for item in parsed["data_attributes"] if item["stream_name"] == ""
        ]
        base = [item for item in streams if item.get("lowest_vcn", 0) == 0]
        if len(base) != 1:
            complete = False
            continue
        data = base[0]
        runs = data.get("data_runs", [])
        physical_ranges = sorted(
            (run["lcn"], run["lcn"] + run["cluster_count"])
            for run in runs if run["lcn"] is not None
        )
        fields = {
            key: data.get(key)
            for key in (
                "attribute_id",
                "stream_name",
                "resident_status",
                "attribute_flags",
                "is_sparse",
                "is_compressed",
                "is_encrypted",
                "logical_size",
                "allocated_size",
                "valid_data_length",
                "lowest_vcn",
                "highest_vcn",
                "runlist_complete",
                "allocated_cluster_count",
                "sparse_cluster_count",
            )
        }
        fields.update(
            {
                "mft_entry": entry,
                "sequence_number": sequence,
                "native_identity_verified": True,
                "attribute_chain_complete": not parsed["attribute_list_present"]
                and not parsed["attribute_parse_error_count"]
                and len(streams) == 1,
                "bytes_per_cluster": geometry["bytes_per_cluster"],
                "total_clusters": geometry["total_clusters"],
                "volume_serial_number": geometry["volume_serial_number"],
                "geometry_source": geometry["geometry_source"],
                "data_runs": runs,
                "runlist_physical_overlap": any(
                    left[1] > right[0]
                    for left, right in zip(physical_ranges, physical_ranges[1:])
                ),
                "runlist_in_volume": all(
                    run["lcn"] is None
                    or 0
                    <= run["lcn"]
                    < run["lcn"] + run["cluster_count"]
                    <= geometry["total_clusters"]
                    for run in runs
                ),
                "mft_volume_id": filesystem_scope_id,
            }
        )
        observations.append(
            {
                "observation_id": f"obs:native-allocation:{entry}:{sequence}",
                "artifact_family": "ntfs.file_size_allocation",
                "observation_type": "ntfs_allocation_record",
                "subject_ref": member["subject_ref"],
                "fields": fields,
                "source_record_ref": f"native-mft:{member['record_sha256']}:entry={entry}:sequence={sequence}",
            }
        )
    output = normalized_output_dir / (
        sha256_file(native_manifest_path)[:16] + ".ntfs-allocation.json"
    )
    write_json(
        output,
        {
            "schema_version": "parser_observation_index.v1",
            "parser": "fmb_bounded_parser",
            "parser_kind": "ntfs_file_size_allocation",
            "record_count": len(observations),
            "observations": observations,
            "truth_sources_used": [],
        },
    )
    return normalize_parser_output(
        parser="fmb_bounded_parser",
        parser_kind="ntfs_file_size_allocation",
        source_collector=str(collector_run["collector"]),
        source_module="FMBNativeNTFSAllocation",
        raw_outputs=[
            native_manifest_path,
            raw_mft_path,
            *native_sidecar_files(native_manifest_path, manifest),
        ],
        normalized_output=output,
        observations=observations,
        tool_identity={
            "name": "fmb_bounded_parser",
            "version": None,
            "source": "native boot sector and source-matched MFT DATA runlist",
        },
        observation_families=["ntfs.file_size_allocation"],
        coverage_status="complete" if complete else "partial",
        coverage_families=["ntfs.file_size_allocation"],
    )
