from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict

from fmb.analysis.catalog import TECHNIQUES
from fmb.analysis.questions import BROAD_QUESTION_GROUP_VERSION
from fmb.core.paths import PROJECT_ROOT
from fmb.core.sealed_records import read_json
from fmb.index.contract.constants import PARSER_ARTIFACT_FAMILIES_BY_KIND


def question_definitions(questions: list[str] | None = None) -> dict:
    from fmb.question_packs import definition, load_packs

    return {pack["question_id"]: definition(pack) for pack in load_packs(questions)}


def resolve_paper_profile(questions: list[str] | None = None) -> dict:
    from fmb.question_packs import load_packs, profile_question

    entries = [profile_question(pack) for pack in load_packs(questions)]
    component_ids = [tid for entry in entries for tid in entry["technique_ids"]]
    if len(component_ids) != len(set(component_ids)) or (
            questions is None and set(component_ids) != {item.technique_id for item in TECHNIQUES}):
        raise ValueError("paper questions must cover every component exactly once")
    families = sorted({family for entry in entries for family in entry["artifact_families"]})
    outputs = {kind: list(families) for kind, families in PARSER_ARTIFACT_FAMILIES_BY_KIND.items()}
    declaration = read_json(PROJECT_ROOT / "contracts/paper/collection.json")
    if len(entries) != len(load_packs()):
        needed = {parser["output"] for entry in entries for family in entry["toolset"].values()
                  for parser in [*family["parsers"], *family.get("inputs", [])]}
        outputs = {kind: families for kind, families in outputs.items() if kind in needed}
        requirements = [family["collection"] for entry in entries for family in entry["toolset"].values()]
        for key, field in (("targets", "target_names"), ("modules", "module_names")):
            declaration["collection"]["kape"][field] = list(dict.fromkeys(
                name for family in requirements for name in family[key]))
    return {
        "question_group_version": BROAD_QUESTION_GROUP_VERSION,
        "questions": entries,
        "artifact_families": families,
        "parser_outputs": outputs,
        "collection_declaration": declaration,
    }


def resolve_profile(questions: list[str] | None = None, *, supplied: dict | None = None) -> dict:
    from fmb.pipeline.stages import profile_gate

    return (deepcopy(supplied) if supplied is not None
            else profile_gate(resolve_paper_profile(questions), question_definitions(questions)))


def validate_profile(g2: dict, questions: list[str] | None = None) -> None:
    from fmb.core.schemas import validate_payload
    from fmb.question_packs import load_packs, validate_pack

    validate_payload(g2, "pipeline_g2.schema.json")
    for pack in load_packs(questions):
        validate_pack(pack)
    expected = resolve_profile(questions)
    fixed = deepcopy(g2)
    for key in ("targets", "modules"):
        fixed["collection"][key] = expected["collection"][key]
    if fixed != expected:
        raise ValueError("G2 differs from the profile its question packs declare")
    if g2 == expected:
        return
    from fmb.collection.tools.host.definitions import KapeDefinitions
    from fmb.collection.tools.kape.paths import BUNDLED_KAPE_TARGETS

    definitions = KapeDefinitions(bundled_targets=BUNDLED_KAPE_TARGETS)
    choices = collection_choices(expected)
    for key, expand in (("targets", definitions.target_rules), ("modules", definitions.module_processors)):
        names = g2["collection"][key]
        if set(names) - set(choices[key]):
            raise ValueError("G2 selects undeclared collection " + key)

        def signatures(selection):
            return {tuple((k, v) for k, v in asdict(item).items()
                          if k not in {"requested_target", "requested_module"}) for item in expand(selection)}

        needed = {name for question in expected["questions"] for family in question["toolset"].values()
                  for name in family["collection"][key]}
        if signatures(sorted(needed)) - signatures(names):
            raise ValueError("G2 collection does not cover required " + key)


def collection_choices(g2: dict) -> dict:
    return {key: sorted(set(g2["collection"][key]) | {
        name for question in g2["questions"] for family in question["toolset"].values()
        for name in family["collection"][key]}) for key in ("targets", "modules")}


def validate_paper_profile(g2: dict, questions: list[str] | None = None) -> None:
    validate_profile(g2, questions)
    if g2 != resolve_profile(questions):
        raise ValueError("G2 is valid but differs from the exact paper preset")


def collection_profile(g2: dict) -> dict:
    declaration = read_json(PROJECT_ROOT / "contracts/paper/collection.json")
    declaration["collection"]["kape"].update(
        target_names=list(g2["collection"]["targets"]), module_names=list(g2["collection"]["modules"]))
    declaration["kape_definitions"] = deepcopy(g2["collection"]["kape_definitions"])
    return {**{key: deepcopy(g2[key]) for key in
               ("question_group_version", "questions", "artifact_families", "parser_outputs")},
            "collection_declaration": declaration}
