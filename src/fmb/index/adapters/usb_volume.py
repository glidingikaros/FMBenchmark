from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fmb.core.hashing import sha256_file
from fmb.core.json_io import write_json
from fmb.index.contract.evidence_index import normalize_parser_output
from fmb.index.scanners.usb_volume import lecmd_link_row, parse_usb_volume_facts


def usb_volume_parser_run(*, native_manifest_path: Path, normalized_output_dir: Path,
                          collector_run: dict[str, Any]) -> dict[str, Any]:
    manifest = json.loads(native_manifest_path.read_text(encoding="utf-8-sig"))
    if (manifest.get("schema_version") != "native_usb_volume_sources.v1"
            or manifest.get("native_binding_hash_verified") is not True):
        raise ValueError("native USB source receipt is unsupported or unverified")
    raw_paths, payload = [], {}
    for label in ("companion", "source_link"):
        path = Path(manifest[label + "_path"]).resolve(strict=True)
        if sha256_file(path) != manifest[label + "_sha256"]:
            raise ValueError("native USB complete original source hash is invalid")
        raw_paths.append(path)
    for label in ("boot", "mft", "journal", "journal_max", "link", "binding"):
        source = manifest["sources"][label]
        path = (native_manifest_path.parent / source["file"]).resolve(strict=True)
        if (path.parent != native_manifest_path.parent.resolve()
                or path.stat().st_size != source["size_bytes"] or sha256_file(path) != source["sha256"]):
            raise ValueError("native USB retained source path/hash is invalid")
        raw_paths.append(path)
        payload[label] = json.loads(path.read_text(encoding="utf-8-sig")) if label == "binding" else path.read_bytes()
    if manifest["sources"]["link"]["sha256"] != manifest["source_link_sha256"]:
        raise ValueError("native USB retained shortcut is not the collected shortcut")
    lecmd, payload["link"] = lecmd_link_row(Path(manifest["source_link_path"]))
    raw_paths.append(lecmd)
    fields = parse_usb_volume_facts(**payload)
    fields["native_binding_file"] = manifest["sources"]["binding"]["file"]
    fields["native_binding_hash_verified"] = True
    fields["companion_sha256"] = manifest["companion_sha256"]
    fields["source_evidence_sha256"] = manifest["evidence_sha256"]
    fields["native_source_sha256"] = {key: row["sha256"] for key, row in manifest["sources"].items()}
    manifest_sha256 = sha256_file(native_manifest_path)
    observations = [{
        "observation_id": "obs:native-usb-volume:" + manifest_sha256[:16],
        "artifact_family": "usb_volume", "observation_type": "usb_volume_reference_history",
        "subject_ref": fields["device_instance_id"], "fields": fields,
        "source_record_ref": "native-usb-volume:" + manifest_sha256,
    }]
    normalized = normalized_output_dir / (manifest_sha256[:16] + ".usb-volume.json")
    write_json(normalized, {"schema_version": "parser_observation_index.v1", "parser": "fmb_bounded_parser",
        "parser_kind": "native_usb_volume", "record_count": len(observations),
        "observations": observations, "truth_sources_used": []})
    return normalize_parser_output(
        parser="fmb_bounded_parser", parser_kind="native_usb_volume",
        source_collector=str(collector_run["collector"]), source_module="FMBNativeUSBVolume",
        raw_outputs=[native_manifest_path, *raw_paths], normalized_output=normalized,
        observations=observations, observation_families=["usb_volume"],
        tool_identity={"name": "fmb_bounded_parser", "version": None,
                       "source": "native USB Boot/MFT/USN journal and operating-system Shell Link decoded by LECmd"},
        coverage_status="complete" if fields["active_mft_complete"] and fields["journal_scan_complete"] else "partial",
        coverage_families=["usb_volume"],
    )
