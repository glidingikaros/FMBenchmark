from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from fmb.collection.ntfs_surfaces import collect_ntfs_surfaces
from fmb.collection.usb_volume import collect_usb_volumes, usb_volume_source_manifests
from fmb.core.json_io import write_json
from fmb.index.adapters.i30 import bounded_i30_parser_run
from fmb.index.adapters.ntfs_allocation import ntfs_allocation_parser_run
from fmb.index.adapters.mft import (
    build_mft_presence_context,
    mft_row_full_path,
    mft_row_is_active,
    mftecmd_mft_context_csv_files,
)
from fmb.index.support.windows_identity import (
    normalize_windows_compare_path,
    ntfs_reference_from_row,
)
from fmb.index.adapters.stream_content import named_stream_content_parser_run
from fmb.index.adapters.usb_volume import usb_volume_parser_run
from fmb.index.adapters.volume_binding import bind_native_volume
from fmb.index.support.windows_artifacts import stream_csv_rows


def add_native_population_surfaces(index: Mapping[str, Any], *, manifest: Mapping[str, Any],
                                   evidence_image: Path, evidence_sha256: str,
                                   output_dir: Path, techniques: set[str] | None = None,
                                   system_volume: bool | None = None) -> dict[str, Any]:
    wanted: dict[str, dict[str, str]] = {}
    kinds = {"i30_directory_residue": "directory", "alternate_data_stream": "ads",
             "ntfs_allocation_inconsistency": "file"}
    for scenario in manifest["scenarios"].values():
        if techniques is not None and scenario["technique_id"] not in techniques:
            continue
        kind = kinds.get(scenario["technique_id"])
        if kind is None:
            continue
        for member in scenario["members"]:
            subject = member["identity_hint"].get("base_path") or member["subject_ref"]
            path = normalize_windows_compare_path(subject)
            if path in wanted:
                raise ValueError("native NTFS population repeats a path")
            wanted[path] = {"subject_ref": subject, "kind": kind}
    native_usb = (techniques is None or "usb_volume_activity_gap" in techniques) and any(
                     scenario["technique_id"] == "usb_volume_activity_gap"
                     for scenario in manifest["scenarios"].values())
    collect_system = bool(wanted) or (system_volume if system_volume is not None else native_usb)
    if not collect_system and not native_usb:
        return deepcopy(dict(index))
    collectors = index.get("collector_runs", [])
    if len(collectors) != 1:
        raise ValueError("native NTFS collection requires one KAPE source")
    collector = collectors[0]
    prepared = deepcopy(dict(index))
    runs = prepared["parser_runs"]
    normalized = output_dir / "native-parser-normalized"
    normalized.mkdir(parents=True, exist_ok=True)
    if collect_system:
        raw_paths = {Path(item["path"]) for run in index.get("parser_runs", [])
                     for item in run.get("raw_outputs", [])
                     if isinstance(item, dict) and Path(item.get("path", "")).name == "$MFT"}
        if len(raw_paths) != 1:
            raise ValueError("native NTFS collection requires one raw KAPE MFT")
        raw_mft = next(iter(raw_paths))
        root = next((path for path in raw_mft.parents if path.name == "kape-output"), None)
        if root is None:
            raise ValueError("native NTFS source is outside a recognized KAPE bundle")
        csv_paths = mftecmd_mft_context_csv_files(root)
        if len(csv_paths) != 1:
            raise ValueError("native NTFS collection requires one complete MFT CSV")
        context = build_mft_presence_context(root)
        matches: dict[str, dict[tuple[int, int], dict[str, Any]]] = {path: {} for path in wanted}
        for row in stream_csv_rows(csv_paths[0]):
            path = normalize_windows_compare_path(mft_row_full_path(row))
            if path not in wanted or not mft_row_is_active(row):
                continue
            reference = ntfs_reference_from_row(row, entry_keys=("EntryNumber", "Entry Number"),
                                                sequence_keys=("SequenceNumber", "Sequence Number"))
            if reference is None:
                raise ValueError("native NTFS candidate has invalid MFT identity")
            matches[path][reference] = {**wanted[path], "mft_entry": reference[0], "sequence_number": reference[1]}
        if any(len(items) != 1 for items in matches.values()):
            raise ValueError("native NTFS public candidate path missing or ambiguous")
        records = [next(iter(items.values())) for items in matches.values()]
        native = collect_ntfs_surfaces(evidence_image=evidence_image, raw_mft_path=raw_mft,
            records=records, output_dir=output_dir / "native-ntfs", evidence_sha256=evidence_sha256)
        from fmb.index.adapters.execution import pecmd_prefetch_parser_run
        if any(run.get("parser_kind") == "windows_prefetch" for run in runs):
            context = bind_native_volume(context, native, raw_mft)
        for position, run in enumerate(runs):
            if run.get("parser_kind") != "windows_prefetch":
                continue
            csvs = [Path(r["path"]) for r in run.get("raw_outputs", [])
                    if Path(r.get("path", "")).suffix.casefold() == ".csv"
                    and "pecmd" in Path(r["path"]).name.casefold()]
            if len(csvs) != 1:
                raise ValueError("native Prefetch volume binding needs one retained parser CSV")
            runs[position] = pecmd_prefetch_parser_run(csv_path=csvs[0], normalized_output_dir=normalized,
                collector_run=collector, mft_context=context)
        if any(item["kind"] == "directory" for item in records):
            runs[:] = [run for run in runs if run.get("parser_kind") != "ntfs_i30"]
            runs.append(bounded_i30_parser_run(mft_csv_path=csv_paths[0], raw_mft_path=raw_mft,
                directory_paths=tuple(item["subject_ref"] for item in records if item["kind"] == "directory"),
                normalized_output_dir=normalized, collector_run=collector, native_manifest_path=native))
        if any(item["kind"] == "file" for item in records):
            runs.append(ntfs_allocation_parser_run(native_manifest_path=native, raw_mft_path=raw_mft,
                normalized_output_dir=normalized, collector_run=collector,
                filesystem_scope_id=context["mft_volume_id"]))
        if any(item["kind"] == "ads" for item in records):
            runs.append(named_stream_content_parser_run(native_manifest_path=native, raw_mft_path=raw_mft,
                normalized_output_dir=normalized, collector_run=collector,
                filesystem_scope_id=context["mft_volume_id"]))
    else:
        root = Path(collector["output_root"])
    if native_usb:
        binding_files = sorted({member["identity_hint"]["binding_file"]
            for scenario in manifest["scenarios"].values()
            if scenario["technique_id"] == "usb_volume_activity_gap"
            for member in scenario["members"]})
        usb_native = collect_usb_volumes(binding_files=binding_files,
            generation_manifest_path=evidence_image.parent / "manifest.json",
            kape_root=root, output_dir=output_dir / "native-usb", evidence_sha256=evidence_sha256)
        for source in usb_volume_source_manifests(usb_native):
            runs.append(usb_volume_parser_run(native_manifest_path=source,
                normalized_output_dir=normalized, collector_run=collector))
    if collect_system:
        write_json(output_dir / "native-surface-preparation.json", {
            "schema_version": "native_surface_preparation.v1", "native_manifest": str(native),
            "public_member_count": len(records), "evidence_sha256": evidence_sha256,
        })
    return prepared
