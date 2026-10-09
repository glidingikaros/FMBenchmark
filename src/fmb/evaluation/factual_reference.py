from __future__ import annotations

import re

from fmb.analysis.inputs import ntfs_scope_and_reference_from_identity
from fmb.index.support.windows_identity import windows_compare_path_parts


def native_reference(value: str) -> tuple[str, tuple[int, int]]:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{8}:[0-9a-f]{16}", value):
        raise ValueError("host receipt lacks a complete native file reference")
    serial, bits = value.split(":")
    number = int(bits, 16)
    return serial, (number & ((1 << 48) - 1), number >> 48)


def _same_path(question: dict, card: dict, path: str) -> bool:
    wanted_volume, wanted_path = windows_compare_path_parts(path)
    aliases = {wanted_volume}
    if ntfs_scope_and_reference_from_identity(card["identity"]) is not None:
        aliases.add(None)
    for pool_aliases in question["volume_aliases"]:
        if wanted_volume in pool_aliases:
            aliases.update(pool_aliases)
    return any(volume in aliases and suffix == wanted_path
               for volume, suffix in map(windows_compare_path_parts, card["observed_paths"]))


SUPPLEMENTAL_SUPPORTED = {
    "BQ-TIME-01": {"single_tick", "creation_backdate", "superseded", "coordinated", "record_change_backdate", "same_year"},
    "BQ-DELETE-01": {"deleted", "recreated", "entry_reused"},
    "BQ-SHELLBAG-01": {"deleted", "moved", "renamed"},
    "BQ-DIRECTORY-01": {"mixed_children", "recreated_children"},
    "BQ-STREAM-01": {"pe", "zip", "mixed_streams", "second_pe"},
    "BQ-FILE-01": {"append_byte", "truncate_byte", "append_four"},
    "BQ-EXEC-01": {"deleted", "renamed"},
}
SUPPLEMENTAL_NEGATIVE = {
    "BQ-TIME-01": {"unchanged", "access_only", "old_copy", "forward"},
    "BQ-DELETE-01": {"renamed", "moved", "hardlink_survives", "present"},
    "BQ-SHELLBAG-01": {"recreated", "present", "present_case"},
    "BQ-DIRECTORY-01": {"all_present", "renamed_children", "moved_children"},
    "BQ-STREAM-01": {"metadata", "signature_decoy", "empty_zip"},
    "BQ-FILE-01": {"valid_bmp", "valid_resize", "preallocation_then_close"},
    "BQ-EXEC-01": {"recreated", "present"},
}


def supplemental_status(question_id: str, operation: str, *, original: bool = True) -> str:
    supported, negative = SUPPLEMENTAL_SUPPORTED, SUPPLEMENTAL_NEGATIVE
    if question_id not in supported:
        raise ValueError("no supplemental reference for this question")
    if operation not in supported[question_id] | negative[question_id]:
        raise ValueError("undeclared supplemental operation")
    if question_id == "BQ-DELETE-01" and not original:
        return "not_supported"
    return "supported" if operation in supported[question_id] else "not_supported"


def _check_base_reference(table: dict, reference: dict) -> None:
    from fmb.analysis.questions import broad_question
    from fmb.core.schemas import validate_payload

    validate_payload(reference, "generation_finding_reference.schema.json")
    population = table["population"]
    if (
        reference.get("schema_version") != "generation_finding_reference.v1"
        or reference.get("reference_contract") != "broad_native_findings.v1"
        or reference.get("population_manifest_sha256") != population["manifest_sha256"]
        or reference.get("experiment") != population["experiment"]
    ):
        raise ValueError("shared assessment requires population-bound factual finding truth")
    scenarios = reference["scenarios"]
    if len(scenarios) != len(population["scenarios"]) or {
        s["scenario_id"] for s in scenarios
    } != set(population["scenarios"]):
        raise ValueError("factual reference must cover the entire generated population")
    supported = {}
    for row in scenarios:
        ids = row["candidate_ids"]
        members = set(population["scenarios"][row["scenario_id"]]["candidate_ids"])
        if not isinstance(ids, list) or len(ids) != len(set(ids)) or not set(ids) <= members:
            raise ValueError("factual reference contains unknown or repeated generation candidates")
        if row["scenario_id"] not in table["candidate_subjects"]:
            continue
        supported[population["scenarios"][row["scenario_id"]]["technique_id"]] = {
            table["candidate_subjects"][row["scenario_id"]][i] for i in ids}
    for question_id, roster in table["base_rosters"].items():
        expected = set().union(*(supported[t] for t in broad_question(question_id).technique_ids))
        if not expected <= set(roster):
            raise ValueError("factual reference is outside the shared roster")


def bind_from_table(*, table: dict, base_reference: dict, plan: dict, receipt: dict) -> dict:
    from fmb.generation.factual_challenge import validate_receipt

    validate_receipt(plan, receipt)
    _check_base_reference(table, base_reference)
    native_volume_serial_number = table["native_volume_serial_number"]
    needs_native = any(q["question_id"] not in {"BQ-LOG-01", "BQ-USB-01"} for q in table["questions"])
    if needs_native and (not isinstance(native_volume_serial_number, str)
                         or not re.fullmatch(r"[0-9a-f]{16}", native_volume_serial_number)):
        raise ValueError("reference binding requires the collected native boot serial")
    population = table["population"]["scenarios"]
    by_technique = {}
    for scenario in base_reference["scenarios"]:
        key = scenario["scenario_id"]
        if key not in table["candidate_subjects"]:
            continue
        technique = population[key]["technique_id"]
        positives = set(scenario["candidate_ids"])
        by_technique[technique] = {
            sid: {"status": "supported" if cid in positives else "not_supported",
                  "reference_basis": "host_generation_finding_reference",
                  "generation_candidate_id": cid}
            for cid, sid in table["candidate_subjects"][key].items()}
    references = {}
    for question in table["questions"]:
        question_id, cards = question["question_id"], question["cards"]
        decisions = {}
        for card in cards:
            sid = card["subject_id"]
            for technique in card["components"]:
                if sid in by_technique.get(technique, {}):
                    decisions.setdefault(sid, {})[technique] = by_technique[technique][sid]
        for row in receipt["members"]:
            if row["question_id"] != question_id:
                continue
            matched = [c for c in cards if _same_path(question, c, row["path"])]
            old_serial, old_ref = native_reference(row["before"]["file_reference"])
            if old_serial != native_volume_serial_number[-8:]:
                raise ValueError("generation and collected native volume identities differ")
            new_ref = (native_reference(row["after"]["file_reference"])[1]
                       if row["after"].get("exists") else None)
            kind = row["operation_class"]
            wanted_refs = {old_ref, new_ref} if question_id == "BQ-DELETE-01" and kind == "recreated" else {old_ref}
            object_question = question_id in {"BQ-TIME-01", "BQ-DELETE-01", "BQ-STREAM-01", "BQ-FILE-01", "BQ-DIRECTORY-01"}
            expected_count = len(wanted_refs) if object_question else 1
            if len(matched) != expected_count:
                raise ValueError(f"public native subject count differs from the host receipt: {row['path']}")
            seen_refs = set()
            for card in matched:
                sid = card["subject_id"]
                identity = ntfs_scope_and_reference_from_identity(card["identity"])
                if object_question:
                    if identity is None or identity[1] not in wanted_refs:
                        raise ValueError("card identity differs from independently recorded native identity")
                    seen_refs.add(identity[1])
                status = supplemental_status(question_id, kind,
                    original=identity is None or identity[1] == old_ref)
                techniques = card["components"]
                if len(techniques) != 1 or sid in decisions:
                    raise ValueError("supplement overlaps a base subject or an undeclared component")
                truth = {"status": status, "reference_basis": "native_generation_before_after_receipt",
                         "generation_path": row["path"], "native_volume_serial_number": old_serial}
                if question_id == "BQ-DIRECTORY-01":
                    children = []
                    if kind == "mixed_children":
                        if len(row["witnesses"]) != 64:
                            raise ValueError("native child identities are missing from the host receipt")
                        for ordinal in (31, 47):
                            serial, (entry, sequence) = native_reference(row["witnesses"][ordinal]["file_reference"])
                            if serial != old_serial:
                                raise ValueError("child and parent native volumes disagree")
                            children.append(f"ntfs:{identity[0]}:{entry}:{sequence}")
                    elif kind == "recreated_children":
                        original_child = row["child_transition"]["before"]
                        serial, (entry, sequence) = native_reference(original_child["file_reference"])
                        if serial != old_serial:
                            raise ValueError("child and parent native volumes disagree")
                        children.append(f"ntfs:{identity[0]}:{entry}:{sequence}")
                    truth["related_object_ids"] = sorted(children)
                decisions[sid] = {techniques[0]: truth}
            if object_question and seen_refs != wanted_refs:
                raise ValueError("native original/replacement generations were not both represented")
        wanted = {c["subject_id"]: set(c["components"]) for c in cards}
        if set(wanted) != set(decisions) or any(set(decisions[s]) != wanted[s] for s in wanted):
            raise ValueError("independent reference does not cover the complete question roster")
        references[question_id] = {"evidence_bundle_sha256": question["evidence_bundle_sha256"],
            "assessments": decisions,
            "reference_kind": "host_generation_facts_with_native_identity_binding",
            "citation_entailment": "not_scored_by_status_reference"}
    return references


def bind_factual_references(*, base_index: dict, base_reference: dict,
                            bundles, plan: dict, receipt: dict,
                            native_volume_serial_number: str) -> dict:
    from fmb.preparation.binding import binding_table

    table = binding_table(base_index=base_index, bundles=bundles,
                          native_volume_serial_number=native_volume_serial_number)
    return bind_from_table(table=table, base_reference=base_reference, plan=plan, receipt=receipt)
