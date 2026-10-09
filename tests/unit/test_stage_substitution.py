from copy import deepcopy
import json
from pathlib import Path

import pytest

from fmb.core import paper_integrity as integrity
from fmb.core.case_contract import QIDS, prepare_case, target_catalog
from fmb.core.errors import SchemaValidationError
from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.schemas import validate_payload
from fmb.core.sealed_records import canonical_json, read_json, seal_directory, write_json
from fmb.evaluation.admission import admit_evidence
from fmb.paper import workflow
from fmb.pipeline import evaluation, stages
from fmb.pipeline.diff import diff_runs
from fmb.pipeline.gates import read_gate, verify_run
from fmb.pipeline.runner import run_pipeline
from fmb.profiles import collection_profile, resolve_paper_profile, resolve_profile, validate_profile
from paper_fixtures import log_bundle
from test_pipeline_gates import _analysis, _fake_stages, _generation
from test_s3_stage import _admit, _new_format_build, _references


@pytest.fixture
def pipeline_inputs(tmp_path, monkeypatch):
    generation = _generation(tmp_path / "generation")
    analysis = _analysis(tmp_path, generation)
    case = prepare_case(log_bundle([100, 103], event_ids=[4624, 4624]))
    for card in case["candidate_roster"]:
        for record in card["evidence_records"]:
            record["fields"]["retention_scope"] = "retained_interval_only_prior_overwrite_history_unknown"
    source = analysis / "Security.csv"
    source.write_text("EventRecordID,EventID\n100,4624\n103,4624\n")
    index = read_json(analysis / "evidence_index.json")
    parser = next(row for row in index["parser_runs"] if "windows.event_log.security" in row["coverage_families"])
    parser["parser_kind"] = "windows_evtx_security"
    parser["raw_outputs"] = [{"path": str(source), "relative_path": source.name, "sha256": sha256_file(source),
                              "size_bytes": source.stat().st_size, "artifact_record_id": "source:fixture",
                              "artifact_family": "windows.event_log.security"}]
    write_json(analysis / "evidence_index.json", index)
    references = _references(case)

    def prepare(*, output, generation, analysis, questions, planned_counts):
        assert questions == ["BQ-LOG-01"]
        write_json(analysis / "fixture-image-binding.json", {
            "image_sha256": sha256_file(generation / "full_scale.vmdk")})
        write_json(output / "cases/BQ-LOG-01.json", case)
        write_json(output / "manifest.json", {
            "schema_version": "paper_native_preparation.v2", "analysis": str(analysis),
            "selected_questions": questions,
            "generation": str(generation), "collection_original_root": str(analysis),
            "truth_sources_used": [], "oracle_lock_sha256": integrity.source_manifest_sha256(),
            "rows": [{"question_id": "BQ-LOG-01", "subjects": len(case["candidate_roster"]),
                      "targets": len(target_catalog(case))}],
            "planned_counts": {"BQ-LOG-01": [len(case["candidate_roster"]), len(target_catalog(case))]},
            "collection_binding": {"image": "full_scale.vmdk",
                                   "image_sha256": sha256_file(generation / "full_scale.vmdk"),
                                   "image_hash_records": ["fixture-image-binding.json"],
                                   "evidence_index_sha256": sha256_file(analysis / "evidence_index.json")},
        })
        seal_directory(output)

    def reference(prepared, manifest, **_):
        write_json(prepared / "admission/references.json", references)
        seal_directory(prepared / "admission", "truth-seal.json")
        return references

    monkeypatch.setattr(workflow, "prepare_native", prepare)
    monkeypatch.setattr(workflow, "write_native_references", reference)
    monkeypatch.setattr(workflow, "check_preparation_sources", lambda _: {"status": "passed", "source_files": 0})
    return {"case_label": "I1-01", "generation": str(generation), "analysis": str(analysis),
            "conditions": ["luna-high"], "questions": ["BQ-LOG-01"], "question_scope": "shown"}


def test_supplied_profile_uses_the_public_runner_without_changing_results(tmp_path, pipeline_inputs):
    config = pipeline_inputs
    generation, analysis = Path(config["generation"]), Path(config["analysis"])
    inputs = {path: sha256_file(path) for path in (generation / "manifest.json", analysis / "evidence_index.json")}
    original = {**config, "output": str(tmp_path / "packs")}
    run_pipeline(original)
    manifest = read_json(tmp_path / "packs/run-manifest.json")
    supplied = read_gate(tmp_path / "packs", manifest["gates"]["G2"])
    alternate = {**config, "output": str(tmp_path / "supplied"), "stages": {"s1": {"profile": supplied}}}
    saved = deepcopy(alternate)
    assert run_pipeline(alternate)["status"] == "completed"
    assert alternate == saved
    assert inputs == {path: sha256_file(path) for path in inputs}
    result = diff_runs(tmp_path / "packs", tmp_path / "supplied")
    assert result["status"] == "same" and result["code"]["same"]
    assert not result["implementations"]["same"]
    assert result["implementations"]["a"]["S1"]["mode"] == "packs"
    assert result["implementations"]["b"]["S1"]["mode"] == "supplied"
    manifest = read_json(tmp_path / "supplied/run-manifest.json")
    assert manifest["config"]["stages"]["s1"]["profile"] == supplied
    assert manifest["stages"][0]["detail"]["mode"] == "supplied"
    g3 = read_gate(tmp_path / "supplied", manifest["gates"]["G3"])
    assert manifest["stages"][1]["outputs"]["preparation"] == g3["preparation_seal"]


@pytest.mark.parametrize("change", ["shape", "definitions", "parser", "selection"])
def test_invalid_supplied_profile_fails_with_an_s1_record_before_preparation(tmp_path, change):
    generation = _generation(tmp_path / "generation")
    supplied = resolve_profile(["BQ-LOG-01"] if change == "selection" else None)
    if change == "shape":
        supplied = [supplied]
    elif change == "definitions":
        supplied.pop("question_definitions")
    elif change == "parser":
        toolset = supplied["questions"][0]["toolset"]
        next(iter(toolset.values()))["parsers"][0]["parser"] = "undeclared-parser"
    run = tmp_path / "run"
    config = {"case_label": "I1-01", "generation": str(generation), "analysis": str(tmp_path / "unused"),
              "conditions": ["luna-high"], "output": str(run), "stages": {"s1": {"profile": supplied}}}
    with pytest.raises((ValueError, SchemaValidationError)):
        run_pipeline(config)
    manifest = read_json(run / "run-manifest.json")
    assert manifest["failure"]["step"] == "S1"
    assert list(manifest["gates"]) == ["G1"]
    assert [(entry["step"], entry["status"]) for entry in manifest["stages"]] == [("S1", "failed")]
    assert not (run / "preparation").exists()
    assert verify_run(run)["run_status"] == "failed"


@pytest.mark.parametrize("questions", [None, ["BQ-LOG-01"], ["BQ-TIME-01", "BQ-LOG-01"]])
def test_g2_is_a_lossless_collection_input_with_no_mutable_side_profile(questions):
    supplied = resolve_profile(questions)
    g2 = resolve_profile(questions, supplied=supplied)
    validate_profile(g2, questions)
    profile = collection_profile(g2)
    assert profile == resolve_paper_profile(questions)
    profile["questions"].clear()
    profile["collection_declaration"]["collection"]["kape"]["module_names"].clear()
    assert g2 == supplied
    g2["questions"].clear()
    assert supplied == resolve_profile(questions)


def test_native_collection_uses_the_selected_g2(tmp_path, monkeypatch):
    from fmb.preparation import native

    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())
    supplied = resolve_profile()
    observed = []

    def collect(*, evidence, output, profile, **_):
        assert evidence == generation / "full_scale.vmdk"
        observed.append(profile)
        assert _analysis(output.parent, generation) == output

    monkeypatch.setattr(native, "collect_native", collect)
    run = tmp_path / "run"
    run_pipeline({"case_label": "I1-01", "generation": str(generation), "collect": {"windows_parsers": "unused"},
                  "conditions": ["luna-high"], "output": str(run), "stages": {"s1": {"profile": supplied}}})
    manifest = read_json(run / "run-manifest.json")
    g2 = read_gate(run, manifest["gates"]["G2"])
    assert observed == [collection_profile(g2)]
    assert read_gate(run, manifest["gates"]["G3"])["collection"]["mode"] == "collected"


def test_an_incorrect_candidate_cannot_change_admission_and_keeps_its_errors(tmp_path, monkeypatch, pipeline_inputs):
    from fmb.assessment import stage
    from fmb.core.paper_results import response_from_decisions
    from fmb.pipeline.contract import check_presentation

    class Candidate(stage.RulesEngine):
        id = "candidate"
        module = __name__

        def decide(self, case):
            _, decisions = super().decide(case)
            for components in decisions.values():
                for decision in components.values():
                    decision["status"] = "not_supported"
            return response_from_decisions(case, decisions), decisions

    monkeypatch.setitem(stage.ENGINES, "candidate", Candidate())
    results = {}
    for engine in ("rules", "candidate"):
        run = tmp_path / engine
        result = run_pipeline({**pipeline_inputs, "output": str(run), "stages": {"s3": {"engine": engine}}})
        assert result["admission"] == "passed"
        assert verify_run(run)["status"] == "verified"
        assert check_presentation(run)["engine"] == "rules"
        manifest = read_json(run / "run-manifest.json")
        g4 = read_gate(run, manifest["gates"]["G4:rules"])
        assert g4["assessor"]["id"] == engine
        s3 = next(step for step in manifest["stages"] if step["step"] == "S3")
        admission = next(step for step in manifest["stages"] if step["step"] == "S4:admission")
        assert s3["outputs"]["admission_baseline"] == admission["inputs"]["admission_baseline"]
        assert (s3["outputs"]["admission_baseline"] == g4["assessor"]["assessment_seal"]) == (engine == "rules")
        certificate = read_json(run / "conditions/luna-high/admission/admission.json")
        assert certificate["rule_assessment"]["engine"] == "rules"
        assert len(list((run / "assessment").iterdir())) == (1 if engine == "rules" else 2)
        results[engine] = read_gate(run, manifest["gates"]["G5"])
    assert results["rules"]["stage_validation"]["S3"]["status"] == "passed"
    assert results["candidate"]["stage_validation"]["S3"]["status"] == "failed"
    assert [row["reference"] for row in results["rules"]["findings"]] == [
        row["reference"] for row in results["candidate"]["findings"]]
    assert any(row["rules"]["status"] != row["reference"] for row in results["candidate"]["findings"])
    g3 = read_gate(run, manifest["gates"]["G3"])
    roots = {"run": run}
    with pytest.raises(ValueError, match="fixed rules baseline"):
        admit_evidence(g3, g4["assessor"]["assessment_seal"], {}, roots=roots)


def _sealed_build(output, case, *, generation=None, analysis=None):
    prepared, built = _new_format_build(output, case, report_extra={
        "oracle_lock_sha256": integrity.source_manifest_sha256(), "selected_questions": ["BQ-LOG-01"],
        "level": "L0N", "requests_per_pass": 1, "findings": len(target_catalog(case)), "truth_sources_used": [],
        "generation_files_opened": [],
        "questions": {"BQ-LOG-01": {"cards": len(case["candidate_roster"]), "findings": len(target_catalog(case))}}})
    manifest = read_json(prepared / "manifest.json")
    manifest.update(schema_version="paper_native_preparation.v1", oracle_lock_sha256=integrity.source_manifest_sha256(),
                    rows=[{"question_id": qid,
                           "subjects": len(case["candidate_roster"]) if qid == "BQ-LOG-01" else 0,
                           "targets": len(target_catalog(case)) if qid == "BQ-LOG-01" else 0} for qid in QIDS])
    manifest["planned_counts"] = {row["question_id"]: [row["subjects"], row["targets"]] for row in manifest["rows"]}
    if generation is not None:
        write_json(analysis / "fixture-image-binding.json", {"image_sha256": sha256_file(generation / "full_scale.vmdk")})
        manifest.update(generation=str(generation), collection_original_root=str(analysis),
                        collection_binding={"image": "full_scale.vmdk",
                                            "image_sha256": sha256_file(generation / "full_scale.vmdk"),
                                            "image_hash_records": ["fixture-image-binding.json"],
                                            "evidence_index_sha256": sha256_file(analysis / "evidence_index.json")})
    write_json(prepared / "manifest.json", manifest)
    (prepared / "preparation-seal.json").unlink()
    seal_directory(prepared)
    report = read_json(built / "build-report.json")
    report["options_sha256"] = sha256_file(built / "view-options.json")
    report["production_seal_sha256"] = sha256_file(prepared / "preparation-seal.json")
    write_json(built / "build-report.json", report)
    (built / "build-seal.json").unlink()
    seal_directory(built, "build-seal.json")
    seal = read_json(built / "build-seal.json")
    seal["requests"] = {"log": {"sent_sha256": sha256_file(built / "sent/log.json"),
                                "case_sha256": sha256_file(built / "cases/log.json"),
                                "sent_bytes": (built / "sent/log.json").stat().st_size,
                                "findings": len(target_catalog(case))}}
    write_json(built / "build-seal.json", seal)
    return prepared, built


@pytest.fixture
def sealed_stages(tmp_path):
    root = tmp_path / "run"
    case = prepare_case(log_bundle([100, 103], event_ids=[4624, 4624]))
    prepared, built = _sealed_build(root / "preparation", case)
    roots = {"run": root, "analysis": tmp_path / "analysis", "generation": root / "preparation/generation"}
    g3 = stages.cards_gate(built, "I1-01", g2_sha256="a" * 64, coverage={}, collection=None,
                           reference_binding=None, sources={}, roots=roots)
    g3["preparation_seal"] = stages.file_ref(prepared / "preparation-seal.json", roots=roots)
    digest = sha256_bytes((canonical_json(g3) + "\n").encode())
    rules = root / "assessment/rules"
    workflow.assess_rules(built=built, output=rules)
    g4 = stages.rules_gate(rules, built, g3, digest, roots)
    condition = root / "conditions/luna-high"
    workflow.freeze_condition(built=built, condition="luna-high", output=condition)
    references = {qid: {"expected_status": {}, "basis": "unused question in this fixture"} for qid in QIDS}
    references.update(_references(case))
    assert _admit(prepared, built, condition, references, rules=rules)["status"] == "passed"
    return {"roots": roots, "g3": g3, "g4": g4, "prepared": prepared, "built": built,
            "rules": rules, "condition": condition, "references": references}


@pytest.mark.parametrize("executed", [False, True])
def test_s4_consumes_real_declared_artifacts_and_preserves_scoring(sealed_stages, executed):
    from fmb.evaluation.scoring import score_run
    from fmb.interpretation.provider import LLMResponse

    fixture = sealed_stages
    condition, g3, roots = fixture["condition"], fixture["g3"], fixture["roots"]
    if executed:
        def response(**_):
            expected = fixture["references"]["BQ-LOG-01"]["expected_status"]
            return LLMResponse("openai", "gpt-5.6-luna", json.dumps({
                "supported_findings": [fid for fid, status in expected.items() if status == "supported"],
                "insufficient_findings": [], "reasons": {fid: "Synthetic sequence evidence." for fid in expected}}),
                {}, usage={"input_tokens": 100, "output_tokens": 20})

        workflow.execute_condition(condition, cap_usd="1", rates={"input": "1", "output": "1"},
                                   execute=True, provider=response, pass_limit=1)
    model = stages.llm_gate(condition, g3["case_label"], fixture["g4"]["g3_sha256"], roots)
    assert stages.check_preparation(g3, roots) == (fixture["prepared"], fixture["built"])
    assert stages.check_assessment(fixture["g4"], g3, roots) == fixture["rules"]
    assert stages.check_assessment(model, g3, roots) == condition
    sealed = {path: sha256_file(path) for path in (
        fixture["prepared"] / "preparation-seal.json", fixture["built"] / "build-seal.json",
        fixture["rules"] / "assessment-seal.json", condition / "preparation-seal.json")}
    result = evaluation.evaluate({}, g3, {"rules": fixture["g4"], "luna-high": model}, roots=roots,
                                 admission={"status": "passed"}, policy="strict", inputs={},
                                 checks={"presentation": "passed", "sources": "passed"})
    validate_payload(result, "pipeline_g5.schema.json")
    assert all(row["rules"]["status"] == row["reference"] for row in result["findings"])
    assert result["stage_validation"]["S3"]["status"] == "passed"
    assert sealed == {path: sha256_file(path) for path in sealed}
    if executed:
        scored = score_run(condition)
        assert result["scores"]["luna-high"] == {key: scored[key] for key in evaluation.SCORE_KEYS if key in scored}
        assert all(row["llm"]["luna-high"][0]["status"] == row["rules"]["status"] for row in result["findings"])
    else:
        assert result["scores"] == {}


@pytest.mark.parametrize("change", ["result", "g3", "artifact", "layout", "decisions"])
def test_s4_refuses_a_gate_or_decisions_inconsistent_with_sealed_rules(sealed_stages, change):
    fixture = sealed_stages
    gate = deepcopy(fixture["g4"])
    if change == "result":
        gate["results"][0]["supported_findings"] = []
    elif change == "g3":
        gate["g3_sha256"] = "0" * 64
    elif change == "artifact":
        gate["assessor"]["assessment"]["sha256"] = "0" * 64
    elif change == "layout":
        gate["assessor"]["assessment"]["path"] = "elsewhere/assessment.json"
    else:
        write_json(fixture["rules"] / "decisions/log.json", {"decisions": {}})
    with pytest.raises(ValueError, match="G4|sealed file changed"):
        stages.check_assessment(gate, fixture["g3"], fixture["roots"])


@pytest.mark.parametrize("change", ["layout", "seal", "preparation"])
def test_s2_sealed_layout_is_checked_before_consumption(sealed_stages, change):
    fixture = sealed_stages
    gate = deepcopy(fixture["g3"])
    if change == "layout":
        gate["preparation_seal"]["path"] = "elsewhere/preparation-seal.json"
    elif change == "seal":
        gate["preparation_seal"]["sha256"] = "0" * 64
    else:
        write_json(fixture["prepared"] / "manifest.json", {"altered": True})
    with pytest.raises(ValueError, match="layout|seal"):
        stages.check_preparation(gate, fixture["roots"])


def test_collection_guard_receipts_are_allowed_only_at_the_s2_boundary():
    from fmb.pipeline.reads import undeclared

    paths = ["analysis-truth-guard.json", ".analysis-truth-guard.json.abcd.tmp"]
    assert undeclared("S2", {"run": paths}) == []
    assert undeclared("S3", {"run": paths}) == ["run:" + path for path in paths]
    other = ["analysis-truth-guard.json/private", ".analysis-truth-guard.json.other"]
    assert undeclared("S2", {"run": other}) == ["run:" + path for path in other]
