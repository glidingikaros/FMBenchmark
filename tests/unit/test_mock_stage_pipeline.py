import json

import pytest

from fmb.core.case_contract import target_catalog
from fmb.core.sealed_records import read_json
from fmb.pipeline.gates import read_gate, verify_run
from fmb.pipeline.runner import run_pipeline
from test_stage_substitution import pipeline_inputs as pipeline_inputs


def test_mock_s3_is_selected_by_config_and_cannot_admit_itself(tmp_path, pipeline_inputs):
    root = tmp_path / "mock"
    result = run_pipeline({**pipeline_inputs, "output": str(root),
                           "stages": {"s3": {"implementation": "mock-llm"}}})
    assert result["admission"] == "passed"
    manifest = read_json(root / "run-manifest.json")
    assert verify_run(root)["status"] == "verified"
    g4 = read_gate(root, manifest["gates"]["G4:rules"])
    g5 = read_gate(root, manifest["gates"]["G5"])
    assert g4["assessor"]["id"] == "mock-llm"
    assert all(row["rules"]["status"] == "insufficient" for row in g5["findings"])
    assert g5["stage_validation"]["S3"]["status"] == "failed"
    assert read_json(root / "assessment/admission-rules/assessment.json")["engine"]["id"] == "rules"
    assert manifest["implementations"]["S3"]["variant"] == "mock-llm"
    assert len(manifest["mock_calls"]) == 1
    call_path = root / manifest["mock_calls"][0]["path"]
    call = read_json(call_path)
    assert call["transport"] == "mock" and call["status"] == "completed"
    assert "reference" not in call["request"]["input"]
    assert json.loads(call["response"])["insufficient_findings"]
    call_path.write_text('{}\n')
    with pytest.raises(ValueError, match="mock call changed"):
        verify_run(root)


@pytest.mark.parametrize("raw", ['{', '{"supported_findings": ["invented"], "insufficient_findings": []}'])
def test_invalid_mock_answer_fails_before_admission_and_is_retained(tmp_path, pipeline_inputs, raw):
    root = tmp_path / "invalid"
    with pytest.raises(ValueError):
        run_pipeline({**pipeline_inputs, "output": str(root),
                      "stages": {"s3": {"implementation": "mock-llm"}}},
                     stage_responder=lambda request: raw)
    manifest = read_json(root / "run-manifest.json")
    assert manifest["failure"]["step"] == "S3"
    assert not (root / "preparation/prepared/admission").exists()
    assert len(manifest["mock_calls"]) == 1
    call = read_json(root / manifest["mock_calls"][0]["path"])
    assert call["status"] == "failed" and call["response"] == raw
    assert verify_run(root)["run_status"] == "failed"


def test_injected_mock_uses_the_real_adapter_without_mutating_inputs(tmp_path, pipeline_inputs):
    seen = []

    def response(request):
        seen.append(request["stage"])
        ids = list(target_catalog(request["input"]))
        request["input"]["candidate_roster"].clear()
        return json.dumps({"supported_findings": ids, "insufficient_findings": []})

    root = tmp_path / "injected"
    run_pipeline({**pipeline_inputs, "output": str(root),
                  "stages": {"s3": {"implementation": "mock-llm"}}}, stage_responder=response)
    manifest = read_json(root / "run-manifest.json")
    g5 = read_gate(root, manifest["gates"]["G5"])
    assert seen == ["S3"]
    assert all(row["rules"]["status"] == "supported" for row in g5["findings"])
    assert read_json(root / manifest["mock_calls"][0]["path"])["request"]["input"]["candidate_roster"]


def test_default_pipeline_never_invokes_the_mock(tmp_path, pipeline_inputs):
    def refuse(request):
        raise AssertionError("default pipeline invoked a mock")

    root = tmp_path / "default"
    run_pipeline({**pipeline_inputs, "output": str(root)}, stage_responder=refuse)
    assert "mock_calls" not in read_json(root / "run-manifest.json")


def test_ambiguous_engine_and_implementation_are_rejected_before_writes(tmp_path, pipeline_inputs):
    root = tmp_path / "ambiguous"
    with pytest.raises(ValueError, match="or an engine"):
        run_pipeline({**pipeline_inputs, "output": str(root),
                      "stages": {"s3": {"implementation": "mock-llm", "engine": "rules"}}})
    assert not root.exists()


def test_mock_experiments_cannot_dispatch_live_models(tmp_path, pipeline_inputs):
    root = tmp_path / "live"
    with pytest.raises(ValueError, match="cannot dispatch live"):
        run_pipeline({**pipeline_inputs, "output": str(root),
                      "stages": {"s3": {"implementation": "mock-llm"}},
                      "dispatch": {"execute": True, "cap_usd": "1", "input_usd_per_million": "1",
                                   "output_usd_per_million": "1"}})
    assert not root.exists()


def test_mock_s1_selects_a_valid_smaller_plan_without_claiming_paper_equality(tmp_path):
    from fmb.pipeline.implementations import MockCalls, mock_s1
    from fmb.profiles import resolve_profile, validate_paper_profile, validate_profile

    original = resolve_profile()
    candidate = mock_s1(call=MockCalls(tmp_path), questions=None, supplied=None)
    validate_profile(candidate)
    assert candidate["questions"] == original["questions"]
    assert candidate["collection"] != original["collection"]
    assert len(candidate["collection"]["targets"]) < len(original["collection"]["targets"])
    with pytest.raises(ValueError, match="exact paper preset"):
        validate_paper_profile(candidate)
    validate_paper_profile(original)


def test_mock_s1_runs_in_the_public_pipeline(tmp_path, pipeline_inputs):
    root = tmp_path / "s1"
    run_pipeline({**pipeline_inputs, "output": str(root),
                  "stages": {"s1": {"implementation": "mock-llm"}}})
    manifest = read_json(root / "run-manifest.json")
    assert verify_run(root)["status"] == "verified"
    record = read_json(root / manifest["mock_calls"][0]["path"])
    assert record["request"]["stage"] == "S1"
    assert set(record["request"]["input"]) == {"questions", "available"}
    assert read_gate(root, manifest["gates"]["G2"])["collection"]["targets"] == ["EventLogs"]


@pytest.mark.parametrize("change", ["unknown", "missing_dependency", "pin"])
def test_alternate_s1_plan_cannot_invent_tools_or_omit_dependencies(tmp_path, change):
    from copy import deepcopy
    from fmb.profiles import resolve_profile, validate_profile

    profile = deepcopy(resolve_profile())
    if change == "unknown":
        profile["collection"]["targets"].append("ImaginaryTarget")
    elif change == "missing_dependency":
        profile["collection"]["targets"] = ["EventLogs"]
    else:
        profile["collection"]["kape_definitions"]["version"] = "invented"
    with pytest.raises(ValueError):
        validate_profile(profile)


def test_mock_s2_uses_source_backed_selections_in_the_real_builder(tmp_path, pipeline_inputs):
    from fmb.pipeline.implementations import mock_response

    seen = []
    def respond(request):
        if request["stage"] == "S2":
            seen.append(request["input"])
        return mock_response(request)
    root = tmp_path / "s2"
    run_pipeline({**pipeline_inputs, "output": str(root),
                  "stages": {"s2": {"implementation": "mock-llm"}}}, stage_responder=respond)
    assert len(seen) == 1
    manifest = read_json(root / "run-manifest.json")
    assert len(manifest["mock_calls"]) == 1
    assert verify_run(root)["status"] == "verified"
    built = root / "preparation/cards"
    item = read_json(built / "items.json")[0]
    case = read_json(built / item["path"])
    for actual, offered in zip(case["candidate_roster"], seen[0]["candidate_roster"]):
        assert sorted(json.dumps(r, sort_keys=True) for r in actual["evidence_records"]) == sorted(
            json.dumps(r, sort_keys=True) for r in offered["evidence_records"].values())
    assert read_json(root / "checks/presentation.json")["status"] == "passed"


@pytest.mark.parametrize("damage", ["missing_subject", "invented_record", "duplicate_record"])
def test_mock_s2_rejects_invalid_subject_and_record_selections(tmp_path, pipeline_inputs, damage):
    from fmb.pipeline.implementations import mock_response

    def respond(request):
        answer = json.loads(mock_response(request))
        selection = answer["selections"]
        sid = next(iter(selection))
        if damage == "missing_subject":
            del selection[sid]
        elif damage == "invented_record":
            selection[sid].append("invented")
        else:
            selection[sid] += selection[sid][:1]
        return json.dumps(answer)
    root = tmp_path / damage
    with pytest.raises(ValueError, match="violates its contract"):
        run_pipeline({**pipeline_inputs, "output": str(root),
                      "stages": {"s2": {"implementation": "mock-llm"}}}, stage_responder=respond)
    assert read_json(root / "run-manifest.json")["failure"]["step"] == "S2"
    assert not (root / "assessment").exists()


def test_mock_s2_can_select_a_subset_but_cannot_hide_changed_scientific_decisions(tmp_path, pipeline_inputs):
    from fmb.pipeline.implementations import mock_response

    def respond(request):
        answer = json.loads(mock_response(request))
        return json.dumps({"selections": {sid: [] for sid in answer["selections"]}})
    root = tmp_path / "omission"
    with pytest.raises(ValueError, match="presenting the cards changed"):
        run_pipeline({**pipeline_inputs, "output": str(root),
                      "stages": {"s2": {"implementation": "mock-llm"}}}, stage_responder=respond)
    manifest = read_json(root / "run-manifest.json")
    assert manifest["failure"]["step"] == "check:presentation"
    call = read_json(root / manifest["mock_calls"][0]["path"])
    assert call["status"] == "completed"
    assert not (root / "assessment").exists()


def test_mock_s4_cannot_grade_its_own_incorrect_result(tmp_path, pipeline_inputs):
    from fmb.pipeline.implementations import mock_response

    def respond(request):
        answer = json.loads(mock_response(request))
        if request["stage"] == "S4":
            answer["rules"]["finding_counts"]["fp"] += 1
            request["input"]["findings"].clear()
        return json.dumps(answer)
    root = tmp_path / "wrong-evaluation"
    run_pipeline({**pipeline_inputs, "output": str(root),
                  "stages": {"s4": {"implementation": "mock-llm"}}}, stage_responder=respond)
    manifest = read_json(root / "run-manifest.json")
    g5 = read_gate(root, manifest["gates"]["G5"])
    assert g5["stage_validation"]["S4"]["status"] == "failed"
    assert "/rules/finding_counts/fp" in g5["stage_validation"]["S4"]["different_fields"]
    assert g5["comparison"]["rules"]["finding_counts"]["fp"] == 0
    assert g5["candidate_evaluation"]["comparison"]["rules"]["finding_counts"]["fp"] == 1
    assert g5["admission"]["status"] == "passed"
    assert verify_run(root)["status"] == "verified"


@pytest.mark.parametrize("mask", range(16))
def test_every_default_mock_stage_combination(tmp_path, pipeline_inputs, mask):
    root = tmp_path / f"combination-{mask:04b}"
    stages = {stage: {"implementation": "mock-llm"} for bit, stage in enumerate(("s1", "s2", "s3", "s4"))
              if mask & (1 << bit)}
    result = run_pipeline({**pipeline_inputs, "output": str(root), "stages": stages})
    assert result["admission"] == "passed" and not result["dispatched"]
    manifest = read_json(root / "run-manifest.json")
    assert verify_run(root)["status"] == "verified"
    g5 = read_gate(root, manifest["gates"]["G5"])
    assert g5["stage_validation"]["S3"]["status"] == ("failed" if "s3" in stages else "passed")
    if "s4" in stages:
        assert g5["stage_validation"]["S4"]["status"] == "passed"
        assert g5["candidate_evaluation"]["comparison"] == g5["comparison"]
    called = [read_json(root / entry["path"])["request"]["stage"] for entry in manifest.get("mock_calls", [])]
    assert called == [stage.upper() for stage in stages]
    assert all(read_json(root / entry["path"])["transport"] == "mock" for entry in manifest.get("mock_calls", []))
    if stages:
        assert g5["experiment"]["stages"] == [stage.upper() for stage in stages]


@pytest.mark.parametrize("stage", ["s1", "s2", "s3", "s4"])
def test_invalid_json_is_retained_at_every_stage(tmp_path, pipeline_inputs, stage):
    root = tmp_path / stage
    with pytest.raises(ValueError):
        run_pipeline({**pipeline_inputs, "output": str(root),
                      "stages": {stage: {"implementation": "mock-llm"}}}, stage_responder=lambda _: "{")
    manifest = read_json(root / "run-manifest.json")
    assert manifest["failure"]["step"] == ("S4:evaluation" if stage == "s4" else stage.upper())
    assert verify_run(root)["run_status"] == "failed"
    assert read_json(root / manifest["mock_calls"][0]["path"])["response"] == "{"


@pytest.mark.parametrize("damage", ["remove", "duplicate"])
def test_completed_mock_stage_requires_a_complete_call_record(tmp_path, pipeline_inputs, damage):
    from fmb.core.sealed_records import write_json

    root = tmp_path / "missing-calls"
    run_pipeline({**pipeline_inputs, "output": str(root), "stages": {"s3": {"implementation": "mock-llm"}}})
    manifest = read_json(root / "run-manifest.json")
    manifest["mock_calls"] = [] if damage == "remove" else manifest["mock_calls"] * 2
    write_json(root / "run-manifest.json", manifest)
    with pytest.raises(ValueError, match="mock call"):
        verify_run(root)


def test_s2_handles_distinct_observations_with_the_same_source_reference(tmp_path):
    from copy import deepcopy
    from fmb.core.case_contract import prepare_case
    from fmb.pipeline.implementations import MockCalls, assemble_records, mock_response
    from paper_fixtures import log_bundle

    case = prepare_case(log_bundle([100, 103]))
    card = case["candidate_roster"][0]
    extra = deepcopy(card["evidence_records"][0])
    extra["fields"]["record_count"] = 99
    card["evidence_records"].append(extra)
    assert card["evidence_records"][0]["source_record_ref"] == extra["source_record_ref"]

    def respond(request):
        answer = json.loads(mock_response(request))
        answer["selections"][card["subject_id"]] = ["e00001"]
        return json.dumps(answer)
    result = assemble_records(case, MockCalls(tmp_path, respond))
    assert result["candidate_roster"][0]["evidence_records"] == [extra]
    assert len(case["candidate_roster"][0]["evidence_records"]) == 2


def test_report_labels_mocks_and_keeps_the_fixed_evaluator_authoritative(tmp_path, pipeline_inputs):
    from fmb.pipeline.implementations import mock_response
    from fmb.pipeline.report import write_report

    def respond(request):
        answer = json.loads(mock_response(request))
        if request["stage"] == "S4":
            answer["rules"]["finding_counts"]["fp"] += 1
        return json.dumps(answer)
    root = tmp_path / "experiment"
    run_pipeline({**pipeline_inputs, "output": str(root),
                  "stages": {"s3": {"implementation": "mock-llm"},
                             "s4": {"implementation": "mock-llm"}}}, stage_responder=respond)
    report = tmp_path / "report"
    write_report(runs=[root], output=report)
    text = (report / "results.md").read_text()
    assert "Mock stage experiment: S3, S4" in text
    assert "S4 candidate agreement with the fixed evaluator: failed" in text
    assert "| mock-llm |" in text
    assert "| Rule-based baseline |" not in text
