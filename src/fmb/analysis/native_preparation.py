from copy import deepcopy
from pathlib import Path
from fmb.core.hashing import sha256_file
from fmb.analysis.shared_evidence import (
    EvidenceBundle,
    pack_event_records,
    unpack_event_records,
)
from fmb.analysis.factual_presentation import _replace_strings
from fmb.core.case_contract import bundle_from_case, prepare_case
from fmb.index.adapters.mft import _recover_one_mft_observation
from fmb.core.sealed_records import canonical_json, read_json


def repair_native_stream_rows(bundle, handle):
    payload, repairs = bundle.payload, []
    for card in payload["candidate_roster"]:
        for record in card["evidence_records"]:
            fields = record["fields"]
            if record["record_type"] != "mft_record" or ":" not in fields.get(
                "file_name", ""
            ):
                continue
            recovered = deepcopy(fields)
            _recover_one_mft_observation(recovered, handle=handle)
            updates = {
                k: v
                for k, v in recovered.items()
                if k.startswith(("si_", "fn_")) or k == "raw_mft_timestamp_source_ref"
            }
            updates["raw_mft_timestamp_validation"] = "verified"
            changes = {
                k: {"before": fields.get(k), "after": v}
                for k, v in updates.items()
                if fields.get(k) != v
            }
            fields.update(updates)
            repairs.append(
                {
                    "subject_id": card["subject_id"],
                    "source_record_ref": record["source_record_ref"],
                    "native_entry": fields["mft_entry"],
                    "sequence": fields["sequence_number"],
                    "changes": changes,
                }
            )
    return EvidenceBundle.from_payload(payload), repairs


def repair_usb_companion_rows(bundle, native_usb_dir: Path, *, locate=Path):
    from fmb.collection.usb_volume import usb_volume_source_manifests

    index = native_usb_dir / "native-usb-volumes.json"
    if not index.exists():
        index = native_usb_dir / "native-usb-volume.json"
    by_device = {}
    from fmb.index.scanners.usb_volume import lecmd_link_row, parse_usb_volume_facts

    for path in usb_volume_source_manifests(index):
        manifest = read_json(path)
        data = {}
        for label in ("boot", "mft", "journal", "journal_max", "link", "binding"):
            row = manifest["sources"][label]
            source = (path.parent / row["file"]).resolve(strict=True)
            if (
                source.parent != path.parent
                or sha256_file(source) != row["sha256"]
                or source.stat().st_size != row["size_bytes"]
            ):
                raise ValueError("native USB card source changed")
            data[label] = (
                read_json(source) if label == "binding" else source.read_bytes()
            )
        if manifest["sources"]["link"]["sha256"] != manifest["source_link_sha256"]:
            raise ValueError("native USB card source changed")
        data["link"] = lecmd_link_row(locate(manifest["source_link_path"]))[1]
        facts = parse_usb_volume_facts(**data)
        device = facts["device_instance_id"]
        if device in by_device:
            raise ValueError("repeated USB card device")
        by_device[device] = facts
    value, used = bundle.payload, set()
    for card in value["candidate_roster"]:
        for record in card["evidence_records"]:
            if record["record_type"] != "native_usb_reference_history":
                continue
            fields = record["fields"]
            facts = by_device.get(fields.get("device_instance_id"))
            if facts is None:
                raise ValueError("retained USB source does not describe the card device and link")
            if any(
                fields.get(key) != facts[key]
                for key in ("link_target_path", "device_instance_id")
            ):
                raise ValueError(
                    "retained USB source does not describe the card device and link"
                )
            used.add(fields["device_instance_id"])
            for key in ("companion_directory_rows", "companion_directory_scope"):
                fields[key] = facts[key]
            for key in ("original_path_lookup", "active_original_path_count"):
                fields.pop(key, None)
    if used != set(by_device):
        raise ValueError("native USB cards omit a retained device")
    return EvidenceBundle.from_payload(value)


def encode_log_case(case):
    if case["question"]["question_id"] != "BQ-LOG-01":
        raise ValueError("lossless LOG encoding requires the complete LOG case")
    value = deepcopy(case)
    references = value.pop("source_reference_map")
    value = _replace_strings(value, references)
    value["source_reference_map"] = {}
    for card in value["candidate_roster"]:
        for record in card["evidence_records"]:
            if record["record_type"] == "retained_security_event_inventory":
                fields = record["fields"]
                native = unpack_event_records(fields["retained_event_records"])
                packed = pack_event_records(native)
                if unpack_event_records(packed) != native:
                    raise ValueError("registered event codec lost a native record")
                fields["retained_event_records"] = packed
    original, decoded = bundle_from_case(case), bundle_from_case(value)
    if original.canonical != decoded.canonical or canonical_json(
        prepare_case(decoded)
    ) != canonical_json(case):
        raise ValueError("lossless LOG encoding cannot reconstruct the original case")
    return value
