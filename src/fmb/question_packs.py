from __future__ import annotations

import json
from pathlib import Path

from fmb.core.schemas import validate_payload

PACK_DIR = Path(__file__).parent / "contracts" / "questions"
FAMILY_REGISTRY = Path(__file__).parent / "contracts" / "paper" / "artifact_families.json"
COLLECTION_DECLARATION = Path(__file__).parent / "contracts" / "paper" / "collection.json"
SCENARIO_TASKS = Path(__file__).parent / "generation" / "ansible" / "roles" / "manipulation" / "tasks"
SCHEMA = "question_pack.schema.json"


def load_packs(questions: list[str] | None = None) -> list[dict]:
    packs = []
    for path in sorted(PACK_DIR.glob("*.json")):
        pack = json.loads(path.read_text())
        validate_payload(pack, SCHEMA)
        if path.stem != pack["question_id"]:
            raise ValueError("a question pack must be named after its question: " + path.name)
        packs.append(pack)
    packs.sort(key=lambda pack: pack["order"])
    if len({pack["order"] for pack in packs}) != len(packs):
        raise ValueError("question packs declare the same order twice")
    if questions is None:
        return packs
    known = {pack["question_id"]: pack for pack in packs}
    unknown = sorted(set(questions) - set(known))
    if unknown or len(set(questions)) != len(questions) or not questions:
        raise ValueError("unknown or repeated questions: " + ", ".join(unknown or questions))
    return [pack for pack in packs if pack["question_id"] in set(questions)]


def load_families() -> dict:
    return json.loads(FAMILY_REGISTRY.read_text())["families"]


def family_toolset(families) -> dict:
    registry = load_families()
    missing = sorted(set(families) - set(registry))
    if missing:
        raise ValueError("the artefact-family registry has no entry for: " + ", ".join(missing))
    return {family: registry[family] for family in sorted(families)}


def family_problems() -> list[str]:
    from fmb.collection.tools.host.definitions import KapeDefinitions, KapeDefinitionError
    from fmb.collection.tools.kape.paths import BUNDLED_KAPE_TARGETS
    from fmb.index.contract.constants import PARSER_ARTIFACT_FAMILIES_BY_KIND

    registry = load_families()
    definitions = KapeDefinitions(bundled_targets=BUNDLED_KAPE_TARGETS)
    targets = set(json.loads(COLLECTION_DECLARATION.read_text())["collection"]["kape"]["target_names"])
    required = {family for pack in load_packs() for component in pack["components"]
                for family in component["projected_artifact_families"]}
    problems = [f"{family}: no registry entry" for family in sorted(required - set(registry))]
    problems += [f"{family}: no pack requires it" for family in sorted(set(registry) - required)]
    for family, entry in sorted(registry.items()):
        selection = entry.get("collection", {})
        if not selection.get("targets") or not isinstance(selection.get("modules"), list):
            problems.append(f"{family}: no collection selection")
        else:
            try:
                definitions.target_rules(selection["targets"])
                definitions.module_processors(selection["modules"])
            except KapeDefinitionError as error:
                problems.append(f"{family}: {error}")
        if not entry["parsers"]:
            problems.append(f"{family}: no parser")
        for parser in entry["parsers"]:
            if family not in PARSER_ARTIFACT_FAMILIES_BY_KIND.get(parser["output"], ()):
                problems.append(f"{family}: {parser['parser']} {parser['module']}'s output {parser['output']} "
                                "does not carry it")
        sources = [*entry["sources"], *(s for item in entry.get("inputs", []) for s in item["sources"])]
        for source in sources:
            if source["kind"] == "kape_target" and source["name"] not in targets:
                problems.append(f"{family}: target {source['name']} is not in the collection declaration")
    return problems


def profile_question(pack: dict) -> dict:
    families = set()
    components = []
    for component in pack["components"]:
        families.update(component["projected_artifact_families"])
        components.append({
            "technique_id": component["technique_id"],
            "question_id": component["component_question_id"],
            "subject_type": component["subject_type"],
            "required_artifact_families": list(component["required_artifact_families"]),
            "optional_artifact_families": list(component["optional_artifact_families"]),
            "alternative_required_artifact_families": [list(group) for group in
                                                       component["alternative_required_artifact_families"]],
        })
    return {
        "question_id": pack["question_id"],
        "group_id": pack["group"]["group_id"],
        "title": pack["definition"]["title"],
        "question_text": pack["definition"]["question_text"],
        "technique_ids": [component["technique_id"] for component in pack["components"]],
        "components": components,
        "artifact_families": sorted(families),
        "toolset": family_toolset(families),
    }


def definition(pack: dict) -> dict:
    return {"question_id": pack["question_id"], **pack["definition"]}


def pack_problems(pack: dict) -> list[str]:
    from fmb.analysis.catalog import technique_definition
    from fmb.analysis.questions import BROAD_QUESTIONS
    from fmb.assessment.stage import ENGINES
    from fmb.evaluation.factual_reference import SUPPLEMENTAL_NEGATIVE, SUPPLEMENTAL_SUPPORTED
    from fmb.generation.population import SCENARIO_ANALYSIS
    from fmb.index.contract.constants import PARSER_ARTIFACT_FAMILIES_BY_KIND
    from fmb.preparation.cards import LISTING_QUESTIONS, PRESENTATION, SPLIT_QUESTIONS

    qid, problems = pack["question_id"], []
    known_families = {family for families in PARSER_ARTIFACT_FAMILIES_BY_KIND.values() for family in families}
    techniques = [component["technique_id"] for component in pack["components"]]
    for component in pack["components"]:
        tid = component["technique_id"]
        catalog = technique_definition(tid)
        if catalog is None:
            problems.append(f"component {tid}: no rule component of this name in fmb.analysis.catalog")
            continue
        declared = {
            "component_question_id": catalog.question_id, "subject_type": catalog.subject_type,
            "required_artifact_families": list(catalog.required_artifact_families),
            "optional_artifact_families": list(catalog.optional_artifact_families),
            "alternative_required_artifact_families": [list(g) for g in catalog.alternative_required_artifact_families],
            "projected_artifact_families": sorted(catalog.projected_artifact_families),
        }
        for key, value in declared.items():
            if component[key] != value:
                problems.append(f"component {tid}: {key} differs from the catalog")
        unknown = sorted({f for key in ("required_artifact_families", "optional_artifact_families",
                                        "projected_artifact_families") for f in component[key]} - known_families)
        if unknown:
            problems.append(f"component {tid}: no parser produces {', '.join(unknown)}")
    if pack["assessment"]["engine"] not in ENGINES:
        problems.append("assessment: engine " + pack["assessment"]["engine"] + " is not registered")
    if pack["assessment"]["components"] != techniques:
        problems.append("assessment: the engine's components differ from the pack's components")
    group = next((q for q in BROAD_QUESTIONS if q.question_id == qid), None)
    if group is None:
        problems.append("group: no question group registered in fmb.analysis.questions")
    elif ({"group_id": group.group_id, "title": group.title, "description": group.question_text} != pack["group"]
          or list(group.technique_ids) != techniques):
        problems.append("group: differs from the registered question group")
    presentation = pack["presentation"]
    if presentation["request_per_card"] != (qid in SPLIT_QUESTIONS):
        problems.append("presentation: request_per_card differs from the protocol's split questions")
    if presentation["listing_lookup"] != (qid in LISTING_QUESTIONS):
        problems.append("presentation: listing_lookup differs from the card build")
    if presentation["transforms"] != [transform.__name__ for transform in PRESENTATION.get(qid, [])]:
        problems.append("presentation: transforms differ from the card build")
    if (set(pack["reference"]["supplemental_supported"]) != SUPPLEMENTAL_SUPPORTED.get(qid, set())
            or set(pack["reference"]["supplemental_negative"]) != SUPPLEMENTAL_NEGATIVE.get(qid, set())):
        problems.append("reference: supplemental statuses differ from fmb.evaluation.factual_reference")
    scenarios = sorted(s for s, (_, tid, _) in SCENARIO_ANALYSIS.items() if tid in techniques)
    if sorted(pack["generation"]["scenarios"]) != scenarios:
        problems.append("generation: scenarios differ from the generator's scenario mapping")
    return problems


def scenario_problems(scenario_id: str) -> list[str]:
    from fmb.analysis.catalog import technique_definition
    from fmb.core.case_contract import PHENOMENA
    from fmb.generation.population import _SCENARIO_RECEIPT_FIELDS, SCENARIO_ANALYSIS

    if scenario_id not in SCENARIO_ANALYSIS:
        return ["generation: no entry in fmb.generation.population.SCENARIO_ANALYSIS"]
    technique, problems = SCENARIO_ANALYSIS[scenario_id][1], []
    if scenario_id not in _SCENARIO_RECEIPT_FIELDS:
        problems.append("generation: no receipt fields in fmb.generation.population._SCENARIO_RECEIPT_FIELDS")
    if not any((SCENARIO_TASKS / f"{prefix}{scenario_id}.yml").is_file() for prefix in ("", "pilot_")):
        problems.append(f"generation: no guest task {scenario_id}.yml in the manipulation role")
    if technique_definition(technique) is None:
        problems.append(f"analysis: no technique {technique} in fmb.analysis.catalog")
    if technique not in PHENOMENA:
        problems.append(f"analysis: no phenomenon for {technique} in fmb.core.case_contract.PHENOMENA")
    if not any(scenario_id in pack["generation"]["scenarios"] for pack in load_packs()):
        problems.append("question: no question pack lists the scenario in generation.scenarios")
    return problems


def validate_pack(pack: dict) -> dict:
    validate_payload(pack, SCHEMA)
    problems = pack_problems(pack)
    if problems:
        raise ValueError(f"question pack {pack.get('question_id')} is incomplete: " + "; ".join(problems))
    return pack
