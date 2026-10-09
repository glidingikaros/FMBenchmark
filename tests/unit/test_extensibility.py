import json
from copy import deepcopy
from pathlib import Path

import pytest

from fmb import question_packs
from fmb.analysis.catalog import TECHNIQUES, technique_definition
from fmb.analysis.questions import BROAD_QUESTIONS, BROAD_QUESTION_GROUP_VERSION
from fmb.analysis.target_contract import TARGET_QUESTIONS
from fmb.core.paths import PROJECT_ROOT
from fmb.core.sealed_records import canonical_json, read_json, seal_directory, write_json
from fmb.index.contract.constants import PARSER_ARTIFACT_FAMILIES_BY_KIND
from fmb.profiles import question_definitions, resolve_paper_profile


def _code_profile() -> dict:
    questions = []
    component_ids = []
    for question in BROAD_QUESTIONS:
        components = []
        families = set()
        for technique_id in question.technique_ids:
            definition = technique_definition(technique_id)
            if definition is None:
                raise ValueError("paper question has unknown component: " + technique_id)
            component_ids.append(technique_id)
            families.update(definition.projected_artifact_families)
            components.append(
                {
                    "technique_id": technique_id,
                    "question_id": definition.question_id,
                    "subject_type": definition.subject_type,
                    "required_artifact_families": list(definition.required_artifact_families),
                    "optional_artifact_families": list(definition.optional_artifact_families),
                    "alternative_required_artifact_families": [
                        list(group)
                        for group in definition.alternative_required_artifact_families
                    ],
                }
            )
        questions.append(
            {
                "question_id": question.question_id,
                "group_id": question.group_id,
                "title": TARGET_QUESTIONS[question.question_id]["title"],
                "question_text": TARGET_QUESTIONS[question.question_id]["question_text"],
                "technique_ids": list(question.technique_ids),
                "components": components,
                "artifact_families": sorted(families),
                "toolset": question_packs.family_toolset(families),
            }
        )
    if (
        len(component_ids) != len(set(component_ids))
        or set(component_ids) != {item.technique_id for item in TECHNIQUES}
    ):
        raise ValueError("paper questions must cover every component exactly once")
    return {
        "question_group_version": BROAD_QUESTION_GROUP_VERSION,
        "questions": questions,
        "artifact_families": sorted(
            {family for question in questions for family in question["artifact_families"]}
        ),
        "parser_outputs": {
            kind: list(families)
            for kind, families in PARSER_ARTIFACT_FAMILIES_BY_KIND.items()
        },
        "collection_declaration": read_json(PROJECT_ROOT / "contracts/paper/collection.json"),
    }


def test_every_question_pack_is_complete():
    packs = question_packs.load_packs()
    assert [pack["question_id"] for pack in packs] == [q["question_id"] for q in _code_profile()["questions"]]
    for pack in packs:
        assert question_packs.pack_problems(pack) == [], pack["question_id"]
        question_packs.validate_pack(pack)


def test_s1_reads_the_packs_and_declares_exactly_what_the_code_did():
    assert json.dumps(resolve_paper_profile(), sort_keys=True) == json.dumps(_code_profile(), sort_keys=True)
    definitions = question_definitions()
    assert definitions["BQ-TIME-01"]["scope"].startswith("Creation, modification")
    assert "scope" not in definitions["BQ-DELETE-01"]


@pytest.mark.parametrize("change, problem", [
    (lambda p: p["components"][0].update(technique_id="unknown_component"), "no rule component of this name"),
    (lambda p: p["components"][0]["required_artifact_families"].append("ntfs.mft.imaginary"), "differs from the catalog"),
    (lambda p: p["presentation"]["transforms"].append("u_not_a_transform"), "transforms differ from the card build"),
    (lambda p: p["presentation"].update(request_per_card=True), "request_per_card differs"),
    (lambda p: p["assessment"].update(engine="oracle"), "engine oracle is not registered"),
    (lambda p: p["reference"]["supplemental_negative"].append("invented"), "supplemental statuses differ"),
    (lambda p: p["generation"]["scenarios"].append("invented_01"), "scenarios differ"),
])
def test_an_incomplete_pack_names_the_hook_that_is_missing(change, problem):
    pack = deepcopy(question_packs.load_packs(["BQ-TIME-01"])[0])
    change(pack)
    assert any(problem in item for item in question_packs.pack_problems(pack))
    with pytest.raises(ValueError, match="is incomplete"):
        question_packs.validate_pack(pack)


def test_a_new_question_without_its_hooks_is_reported_as_such():
    pack = deepcopy(question_packs.load_packs(["BQ-TIME-01"])[0])
    pack.update(question_id="BQ-NEW-01", order=99)
    problems = question_packs.pack_problems(pack)
    assert any("no question group registered" in p for p in problems)


def test_each_question_has_one_text_from_s1_to_the_model():
    from fmb.analysis.target_contract import TARGET_QUESTIONS
    from fmb.core.case_contract import SCOPES
    from fmb.core.paths import PROJECT_ROOT

    definitions = question_definitions()
    for entry in resolve_paper_profile()["questions"]:
        qid = entry["question_id"]
        pack = question_packs.load_packs([qid])[0]
        assert "question_text" not in pack["group"]
        assert (entry["title"], entry["question_text"]) == (pack["definition"]["title"], pack["definition"]["question_text"])
        assert definitions[qid] == {"question_id": qid, **TARGET_QUESTIONS[qid], **({"scope": SCOPES[qid]} if qid in SCOPES else {})}
    for path in sorted((PROJECT_ROOT / "fixtures/paper/i1").rglob("cases/*.json"))[:5]:
        question = read_json(path)["question"]
        assert question["question_text"] == definitions[question["question_id"]]["question_text"]


def test_the_family_registry_agrees_with_the_packs_the_parsers_and_the_collection():
    assert question_packs.family_problems() == []


def test_g2_names_the_sources_and_parsers_behind_each_question():
    from fmb.pipeline import stages

    g2 = stages.profile_gate(resolve_paper_profile(), question_definitions())
    toolset = {q["question_id"]: q["toolset"] for q in g2["questions"]}
    for question in g2["questions"]:
        assert sorted(question["toolset"]) == question["artifact_families"]
    parsers = {(qid, family): {p["parser"] for p in entry["parsers"]} for qid, families in toolset.items()
               for family, entry in families.items()}
    assert parsers[("BQ-TIME-01", "ntfs.logfile")] == {"dfir_ntfs"}
    assert parsers[("BQ-DIRECTORY-01", "ntfs.i30")] == {"fmb_bounded_parser"}
    assert parsers[("BQ-USB-01", "windows.setupapi")] == {"setupapi.dev.log"}
    assert [i["parser"] for i in toolset["BQ-USB-01"]["usb_volume"]["inputs"]] == ["lecmd"]
    subset = stages.profile_gate(resolve_paper_profile(["BQ-LOG-01"]), question_definitions(["BQ-LOG-01"]))
    assert sorted(subset["questions"][0]["toolset"]) == ["windows.event_log.record_sequence",
                                                         "windows.event_log.security"]


def _coverage_case(tmp_path, parser, module="MFTECmd"):
    from fmb.pipeline import stages

    g2 = stages.profile_gate(resolve_paper_profile(["BQ-STREAM-01"]), question_definitions(["BQ-STREAM-01"]))
    runs = [{"parser": parser, "source_module": module, "status": "consumed", "coverage_status": "partial",
             "coverage_families": ["ntfs.mft"]},
            {"parser": "fmb_bounded_parser", "source_module": "FMBNativeStreamContent", "status": "consumed",
             "coverage_status": "complete", "coverage_families": ["ntfs.ads"]}]
    write_json(tmp_path / "evidence_index.json", {"parser_runs": runs})
    return stages, g2


def test_s2_checks_the_parsers_that_covered_each_family_against_g2(tmp_path):
    stages, g2 = _coverage_case(tmp_path, "mftecmd")
    coverage = stages.profile_coverage(tmp_path, g2)
    assert all(run["declared"] for family in coverage["BQ-STREAM-01"].values() for run in family["runs"])
    stages, g2 = _coverage_case(tmp_path, "an_undeclared_parser")
    with pytest.raises(ValueError, match="parsers G2 does not declare: BQ-STREAM-01: ntfs.mft by an_undeclared_parser"):
        stages.profile_coverage(tmp_path, g2)


def test_subsets_of_questions_resolve_in_their_declared_order():
    profile = resolve_paper_profile(["BQ-LOG-01", "BQ-TIME-01"])
    assert [q["question_id"] for q in profile["questions"]] == ["BQ-TIME-01", "BQ-LOG-01"]
    assert set(question_definitions(["BQ-LOG-01"])) == {"BQ-LOG-01"}
    with pytest.raises(ValueError, match="unknown or repeated questions"):
        question_packs.load_packs(["BQ-TIME-01", "BQ-NOPE-01"])
    with pytest.raises(ValueError, match="unknown or repeated questions"):
        question_packs.load_packs(["BQ-TIME-01", "BQ-TIME-01"])


def test_the_runner_refuses_an_unknown_question(tmp_path):
    from fmb.pipeline.runner import run_pipeline

    config = {"case_label": "I1-01", "generation": str(tmp_path), "analysis": str(tmp_path),
              "conditions": ["luna-high"], "output": str(tmp_path / "run"), "questions": ["BQ-NOPE-01"]}
    with pytest.raises(ValueError, match="unknown or repeated questions"):
        run_pipeline(config)
    assert not (tmp_path / "run").exists()


def test_admission_covers_exactly_the_questions_a_build_declares(tmp_path, monkeypatch):
    from fmb.assessment.stage import assess_cards
    from fmb.core import paper_integrity as integrity
    from fmb.core.case_contract import prepare_case, target_catalog
    from fmb.evaluation import admission as paper_admission
    from fmb.paper import workflow
    from paper_fixtures import log_bundle
    from test_s3_stage import _new_format_build

    monkeypatch.setattr(integrity, "source_manifest_sha256", lambda: "test-source-lock")
    monkeypatch.setattr(paper_admission, "QIDS", ("BQ-TIME-01", "BQ-LOG-01"))
    case = prepare_case(log_bundle([100, 103], event_ids=[4624, 4624]))
    references = {"BQ-LOG-01": {"expected_status": {
        fid: "supported" if t["component"] == "event_record_sequence_gap" else "not_supported"
        for fid, t in target_catalog(case).items()}, "basis": "synthetic"},
        "BQ-TIME-01": {"expected_status": {"finding:t": "not_supported"}, "basis": "synthetic"}}

    def admit(root, extra):
        prepared, built = _new_format_build(root, case, report_extra=extra)
        condition = root / "condition"
        workflow.freeze_condition(built=built, condition="luna-high", output=condition)
        rules = root / "rules"
        assess_cards(built=built, output=rules)
        write_json(prepared / "admission" / "references.json", references)
        seal_directory(prepared / "admission", "truth-seal.json")
        return paper_admission.admit_conditions(prepared=prepared, built=built, condition_runs=[condition],
                                                references=references, rules=rules)

    with pytest.raises(ValueError, match="do not cover the complete independent reference"):
        admit(tmp_path / "full", None)
    assert admit(tmp_path / "subset", {"selected_questions": ["BQ-LOG-01"]})["status"] == "passed"


def _g5_run(tmp_path, rows, cards):
    from fmb.pipeline.gates import write_gate

    run = tmp_path / "run"
    (run / "preparation" / "cards" / "sent").mkdir(parents=True)
    for request_id, card in cards.items():
        (run / "preparation" / "cards" / "sent" / (request_id + ".json")).write_text(canonical_json(card))
    g5 = {"gate": "G5", "schema_version": "fmb.pipeline.g5.v1", "case_label": "I1-01",
          "admission": {"status": "passed", "certificates": []}, "scores": {}, "findings": rows,
          "comparison": {"rules": {}, "conditions": {}}}
    entry = write_gate(run, "G5", g5)
    (run / "run-manifest.json").write_text(canonical_json({"gates": {"G5": entry}}))
    return run


def test_the_triviality_battery_flags_a_question_a_naive_rule_answers(tmp_path):
    from fmb.pipeline.contract import naive_battery

    def row(fid, reference):
        return {"question_id": "BQ-TIME-01", "request_id": "r1", "finding_id": fid, "display_id": fid,
                "subject": fid, "component": "timestamp_manipulation", "reference": reference,
                "rules": {"status": reference}, "llm": {}}

    def card(fid, types):
        return {"assessment_targets": [{"finding_id": fid}],
                "evidence_records": [{"record_type": t} for t in types]}

    rows = [row("a", "supported"), row("b", "not_supported"), row("c", "not_supported")]
    trivial = {"candidate_roster": [card("a", ["logfile_si_update", "mft"]), card("b", ["mft"]), card("c", ["mft"])]}
    run = _g5_run(tmp_path, rows, {"r1": trivial})
    assert naive_battery(run) == [{"question_id": "BQ-TIME-01",
                                   "exact_naive_rules": ["card has logfile_si_update"]}]
    mixed = {"candidate_roster": [card("a", ["logfile_si_update", "mft"]), card("b", ["logfile_si_update", "mft"]),
                                  card("c", ["mft"])]}
    run2 = _g5_run(tmp_path / "second", rows, {"r1": mixed})
    assert naive_battery(run2) == []


def test_sealed_runs_of_one_case_must_hold_the_same_cards(tmp_path):
    from fmb.pipeline.evaluation import sealed_findings_table
    from fmb.pipeline.sealed import _named

    for name, digest in (("a", "1" * 64), ("b", "2" * 64)):
        write_json(tmp_path / name / "manifest.json", {"rows": [{"request_id": "r1", "case_sha256": digest}]})
    with pytest.raises(ValueError, match="hold different requests or cards"):
        sealed_findings_table([tmp_path / "a", tmp_path / "b"])
    assert _named("luna-high=/some/run") == ("luna-high", Path("/some/run"))
    assert _named(str(tmp_path / "a")) == (None, tmp_path / "a")


@pytest.mark.parametrize("status, retried", [(408, True), (429, True), (500, True), (501, True), (599, True),
                                             (400, False), (404, False), (600, False), (True, False), (None, False)])
def test_transport_failures_are_408_429_and_any_5xx(status, retried):
    from fmb.interpretation.provider import is_retryable_http_status

    assert is_retryable_http_status(status) is retried
