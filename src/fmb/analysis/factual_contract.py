from __future__ import annotations

from copy import deepcopy
from typing import Any

from fmb.core.schemas import validate_response_schema

FACTUAL_EVIDENCE_VERSION = "candidate_roster_factual_evidence.v1"
FACTUAL_ANALYZER_VERSION = "shared_native_rules.v3"

COMPONENT_TARGETS = {
    "timestamp_manipulation": "Backdating of creation, modification or metadata-change timestamps; access-time-only changes are outside this target.",
    "deleted_file_journal_residue": "Retained file-deletion history for an original file object now absent from the collected volume.",
    "typed_path_residue": "Retained TypedPaths history for a local directory path now absent.",
    "shellbag_missing_directory": "Retained Shellbag directory-path history for a path now absent.",
    "i30_directory_residue": "Retained directory-index references to child objects absent from the active MFT.",
    "alternate_data_stream": "PE executable content or a ZIP archive with nonempty member content in a named stream; content alone does not establish concealment.",
    "usbstor_setupapi_discrepancy": "Inconsistency in retained USB device installation identity.",
    "usb_volume_activity_gap": "Inconsistency in retained USB companion-volume filename history.",
    "bitmap_trailing_data": "BMP content-length inconsistency, including padding or truncation.",
    "ntfs_allocation_inconsistency": "NTFS data-stream length or allocation-metadata inconsistency.",
    "prefetch_missing_executable": "Prefetch residue for an executable path now absent.",
    "shimcache_path_residue": "Shimcache residue for an executable path now absent; this does not itself establish execution.",
    "security_log_clear_event": "Retained Security-log clearing event.",
    "event_record_sequence_gap": "Internal discontinuity in the retained native Security Event Record ID sequence.",
}


def _applicable(card: dict[str, Any], technique: str) -> bool:
    families = {c["artifact_family"] for c in card["coverage"]}
    kinds = {r["record_type"] for r in card["evidence_records"]}
    if (
        technique == "deleted_file_journal_residue"
        and "windows.registry.typed_paths" in families
    ):
        return "usn_record" in kinds
    if (
        technique == "prefetch_missing_executable"
        and "windows.registry.shimcache" in families
    ):
        return "prefetch_record" in kinds
    primary = {
        "deleted_file_journal_residue": "ntfs.usn",
        "typed_path_residue": "windows.registry.typed_paths",
        "prefetch_missing_executable": "windows.prefetch",
        "shimcache_path_residue": "windows.registry.shimcache",
        "bitmap_trailing_data": "collected.file.content",
        "usbstor_setupapi_discrepancy": "windows.registry.usbstor",
        "usb_volume_activity_gap": "usb_volume",
    }
    if technique == "ntfs_allocation_inconsistency":
        return "collected.file.content" not in families or any(
            r["record_type"] == "ntfs_allocation_attribute"
            for r in card["evidence_records"]
        )
    return technique not in primary or primary[technique] in families


def component_ids(card: dict[str, Any], question_id: str) -> tuple[str, ...]:
    from fmb.analysis.questions import broad_question

    return tuple(t for t in broad_question(question_id).technique_ids if _applicable(card, t))


def factual_response_schema(cards: list[dict], question_id: str) -> dict:
    fields = {
        "status": {"type": "string", "enum": ["supported", "not_supported", "insufficient"]},
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
        "related_object_ids": {"type": "array", "items": {"type": "string"}},
        "statement": {"type": "string"},
    }
    subjects = {}
    for card in cards:
        components = {
            t: {"type": "object", "description": COMPONENT_TARGETS[t],
                "properties": deepcopy(fields), "required": list(fields), "additionalProperties": False}
            for t in component_ids(card, question_id)
        }
        subjects[card["subject_id"]] = {
            "type": "object", "properties": components, "required": list(components),
            "additionalProperties": False,
        }
    return {"type": "object", "properties": {"assessments": {
        "type": "object", "properties": subjects, "required": list(subjects),
        "additionalProperties": False,
    }}, "required": ["assessments"], "additionalProperties": False}


def upgrade_factual_bundle(bundle):
    from fmb.analysis.shared_evidence import EvidenceBundle, EVIDENCE_BUNDLE_VERSION

    value = bundle.payload
    if value["schema_version"] != EVIDENCE_BUNDLE_VERSION:
        raise ValueError("factual upgrade requires a historical factual bundle without intent context")
    value["schema_version"] = FACTUAL_EVIDENCE_VERSION
    for coverage in [value["coverage"], *(c["coverage"] for c in value["candidate_roster"])]:
        for item in coverage:
            scope = item.get("scope", {})
            if "gap_count" in scope:
                scope["coverage_interval_gap_count"] = scope.pop("gap_count")
    value["response_schema"] = factual_response_schema(value["candidate_roster"], bundle.question_id)
    return EvidenceBundle.from_payload(value)


def source_references(card: dict) -> set[str]:
    from fmb.analysis.shared_evidence import unpack_event_records

    refs = set()
    for record in card["evidence_records"]:
        refs.add(record["source_record_ref"])
        fields = record["fields"]
        if fields.get("raw_mft_timestamp_source_ref"):
            refs.add(fields["raw_mft_timestamp_source_ref"])
        refs.update(fields.get("path_resolution_source_refs", []))
        for key in ("active_mft_lookup", "setupapi_lookup"):
            lookup = fields.get(key, {})
            if lookup.get("source_record_ref"):
                refs.add(lookup["source_record_ref"])
            refs.update(lookup.get("source_record_refs", []))
        if record["record_type"] == "retained_security_event_inventory":
            refs.update(r["source_record_ref"] for r in unpack_event_records(fields["retained_event_records"]))
    return refs


def validate_factual_response(bundle, response: dict) -> dict:
    from fmb.analysis.factual_presentation import PRESENTATION_VERSION, expanded_bundle, translate_response
    if bundle.payload["schema_version"] == PRESENTATION_VERSION:
        validate_response_schema(response, bundle.payload["response_schema"])
        return validate_factual_response(expanded_bundle(bundle), translate_response(bundle, response, to_original=True))
    if bundle.payload["schema_version"] != FACTUAL_EVIDENCE_VERSION:
        raise ValueError("wrong factual response contract")
    validate_response_schema(response, bundle.payload["response_schema"])
    supported, insufficient, citation_errors, unsupported_evidence = [], [], [], []
    for card in bundle.payload["candidate_roster"]:
        sid = card["subject_id"]
        decisions = response["assessments"][sid]
        refs = source_references(card)
        for pool in bundle.payload.get("current_mft_pools", []):
            refs.add(pool["source_record_ref"])
            refs.update(r["source_record_ref"] for r in pool["records"])
            for proof in pool["native_volume_observations"]:
                refs.update((proof["native_volume_boot_source_ref"], proof["native_volume_mft_source_ref"]))
            if pool.get("drive_letter_binding"):
                refs.add(pool["drive_letter_binding"]["gpt_partition_source_ref"])
                refs.update(r["source_record_ref"] for r in pool["drive_letter_binding"]["mounted_device_values"])
        if any(d["status"] == "supported" for d in decisions.values()):
            supported.append(sid)
        elif any(d["status"] == "insufficient" for d in decisions.values()):
            insufficient.append(sid)
        for component, decision in decisions.items():
            unknown = sorted(set(decision["evidence_refs"]) - refs)
            if unknown:
                citation_errors.append({"subject_id": sid, "component": component, "unknown_refs": unknown})
            if decision["status"] == "supported" and not decision["evidence_refs"]:
                unsupported_evidence.append({"subject_id": sid, "component": component})
    return {"supported_subject_ids": supported, "insufficient_subject_ids": insufficient,
            "citation_errors": citation_errors, "supported_without_citation": unsupported_evidence,
            "evidence_entailment_review": "not_established_by_identifier_validation"}


def deterministic_factual_response(bundle) -> dict:
    from fmb.analysis.factual_presentation import PRESENTATION_VERSION, expanded_bundle, translate_response
    if bundle.payload["schema_version"] == PRESENTATION_VERSION:
        response = deterministic_factual_response(expanded_bundle(bundle))
        response = translate_response(bundle, response, to_original=False)
        validate_factual_response(bundle, response)
        return response
    from dataclasses import replace
    from fmb.analysis import deterministic as rules
    from fmb.analysis.shared_rules import _card_observation_id, _decode, analyze_evidence_bundle

    if bundle.payload["schema_version"] != FACTUAL_EVIDENCE_VERSION:
        raise ValueError("a versioned factual bundle is required")
    result = analyze_evidence_bundle(bundle)
    assessments = {}
    for card in bundle.payload["candidate_roster"]:
        sid = card["subject_id"]
        components = {}
        for component, decision in result.analyzer_metadata["component_assessments"][sid].items():
            related = []
            refs = list(decision["evidence_refs"])
            if component in {"deleted_file_journal_residue", "typed_path_residue", "prefetch_missing_executable", "shimcache_path_residue",
                             "shellbag_missing_directory", "i30_directory_residue"}:
                from fmb.analysis.mft_comparison import comparison_evidence_refs
                if bundle.payload.get("current_mft_pools"):
                    for record in card["evidence_records"]:
                        refs.extend(comparison_evidence_refs(bundle.payload, card, record))
            if component == "i30_directory_residue" and decision["outcome"] == "supported":
                value = _decode(bundle, card, component)
                subject = value.candidate_roster.subjects[0]
                public = {_card_observation_id(sid, r): r["source_record_ref"] for r in card["evidence_records"]}
                child_refs = set()
                for row in value.observations:
                    if row.observation_type != "i30_filename_residue":
                        continue
                    observations = [row]
                    for scan in value.observations:
                        if scan.observation_type == "i30_directory_scan":
                            observations.append(replace(scan, fields={**scan.fields,
                                "residue_count": int(row.fields.get("i30_entry_state") in {"slack", "unlinked"})}))
                    local_subject = replace(subject, observation_ids=tuple(o.observation_id for o in observations))
                    local = replace(value, observations=tuple(observations))
                    outcome = rules._i30(local, local_subject)
                    if outcome.outcome == "supported":
                        f = row.fields
                        related.append(f"ntfs:{f['mft_volume_id']}:{f['file_reference_entry']}:{f['file_reference_sequence']}")
                        child_refs.update(public.get(ref, ref) for ref in outcome.evidence_refs)
                refs = sorted(child_refs)
            components[component] = {
                "status": "insufficient" if decision["outcome"] == "indeterminate" else decision["outcome"],
                "evidence_refs": sorted(set(refs)),
                "related_object_ids": sorted(set(related)),
                "statement": decision["reason_code"].replace("_", " "),
            }
        assessments[sid] = components
    response = {"assessments": assessments}
    validate_factual_response(bundle, response)
    return response


