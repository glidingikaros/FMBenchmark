from __future__ import annotations

SCHEMA = "fmb.reference_binding.v1"


def _card(card: dict, question_id: str) -> dict:
    from fmb.analysis.factual_contract import component_ids

    return {
        "subject_id": card["subject_id"],
        "components": list(component_ids(card, question_id)),
        "identity": card["identity"],
        "observed_paths": [card["display_name"], *(record["subject_ref"] for record in card["evidence_records"])],
    }


def binding_table(*, base_index: dict, bundles: list, native_volume_serial_number: str | None) -> dict:
    from fmb.analysis.catalog import TECHNIQUES
    from fmb.analysis.inputs import build_analysis_input
    from fmb.analysis.population_binding import bind_population_manifest, verify_population_manifest
    from fmb.analysis.shared_evidence import prepare_evidence_bundles
    from fmb.analysis.questions import broad_question
    from fmb.evaluation.reference_binding import _population_candidate_subject_ids

    techniques = {tid for bundle in bundles for tid in broad_question(bundle.question_id).technique_ids}
    rebound = bind_population_manifest(base_index, base_index["population_manifest"], techniques=techniques)
    selected_populations = [p for p in base_index["candidate_populations"] if p["technique_id"] in techniques]
    if rebound["candidate_populations"] != selected_populations:
        raise ValueError("base population membership differs from its public source binding")
    base_inputs = tuple(build_analysis_input(base_index, definition) for definition in TECHNIQUES
                        if definition.technique_id in techniques)
    base_bundles = prepare_evidence_bundles(base_inputs)
    population = verify_population_manifest(base_index["population_manifest"])
    candidates = _population_candidate_subject_ids(base_inputs, base_index, base_index["population_manifest"])
    return {
        "schema_version": SCHEMA,
        "native_volume_serial_number": native_volume_serial_number,
        "population": {
            "manifest_sha256": population["manifest_sha256"],
            "experiment": population["experiment"],
            "scenarios": {key: {"technique_id": scenario["technique_id"],
                                "candidate_ids": [member["candidate_id"] for member in scenario["members"]]}
                          for key, scenario in population["scenarios"].items()},
        },
        "candidate_subjects": candidates,
        "base_rosters": {bundle.question_id: list(bundle.subject_ids) for bundle in base_bundles},
        "questions": [
            {
                "question_id": bundle.question_id,
                "evidence_bundle_sha256": bundle.sha256,
                "volume_aliases": [list(pool["volume_aliases"])
                                   for pool in bundle.payload.get("current_mft_pools", [])],
                "cards": [_card(card, bundle.question_id) for card in bundle.payload["candidate_roster"]],
            }
            for bundle in bundles
        ],
    }
