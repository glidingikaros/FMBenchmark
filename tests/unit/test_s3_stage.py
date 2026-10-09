import pytest

from fmb.core import paper_integrity as integrity
from fmb.core.case_contract import prepare_case, target_catalog
from fmb.core.hashing import sha256_file
from fmb.core.sealed_records import canonical_json, read_json, seal_directory, write_json
from fmb.evaluation import admission as paper_admission
from fmb.paper import presentation_check, workflow
from paper_fixtures import log_bundle


def _new_format_build(tmp_path, case, *, deterministic=False, report_extra=None):
    prepared = tmp_path / "prepared"
    (prepared / "cases").mkdir(parents=True)
    (tmp_path / "generation").mkdir(exist_ok=True)
    write_json(prepared / "manifest.json", {"truth_sources_used": [], "generation": str(tmp_path / "generation")})
    (prepared / "cases" / "BQ-LOG-01.json").write_text(canonical_json(case))
    seal_directory(prepared)
    built = tmp_path / "cards"
    for folder in ("sent", "cases"):
        (built / folder).mkdir(parents=True)
    (built / "sent" / "log.json").write_text(canonical_json(case))
    (built / "cases" / "log.json").write_text(canonical_json(case))
    write_json(built / "view-options.json", {"stated_reasons": True})
    write_json(built / "items.json", [{"case_id": "log", "question_id": "BQ-LOG-01"}])
    write_json(built / "build-report.json", {
        "oracle_lock_sha256": "test-source-lock", "production_preparation": str(prepared),
        "production_seal_sha256": sha256_file(prepared / "preparation-seal.json"), "reference_already_opened": False,
        **(report_extra or {})})
    if deterministic:
        from fmb.assessment.rules import assess

        write_json(built / "deterministic" / "log.json", assess(case))
    seal_directory(built, "build-seal.json")
    seal = read_json(built / "build-seal.json")
    seal["requests"] = {"log": {"sent_sha256": sha256_file(built / "sent" / "log.json")}}
    if deterministic:
        seal["requests"]["log"]["deterministic_sha256"] = sha256_file(built / "deterministic" / "log.json")
    write_json(built / "build-seal.json", seal)
    return prepared, built


@pytest.fixture
def case():
    return prepare_case(log_bundle([100, 103], event_ids=[4624, 4624]))


@pytest.fixture
def lock(monkeypatch):
    monkeypatch.setattr(integrity, "source_manifest_sha256", lambda: "test-source-lock")
    monkeypatch.setattr(paper_admission, "QIDS", ("BQ-LOG-01",))


def _references(case):
    expected = {fid: "supported" if t["component"] == "event_record_sequence_gap" else "not_supported"
                for fid, t in target_catalog(case).items()}
    return {"BQ-LOG-01": {"expected_status": expected, "basis": "synthetic event sequence defined in this test"}}


def _admit(prepared, built, condition, references, **kwargs):
    write_json(prepared / "admission" / "references.json", references)
    seal_directory(prepared / "admission", "truth-seal.json")
    return paper_admission.admit_conditions(prepared=prepared, built=built, condition_runs=[condition],
                                            references=references, **kwargs)


def test_a_new_condition_carries_only_what_its_model_receives(tmp_path, case, lock):
    _, built = _new_format_build(tmp_path, case)
    condition = tmp_path / "condition"
    workflow.freeze_condition(built=built, condition="luna-high", output=condition)
    assert not (condition / "deterministic").exists()
    assert (condition / "requests" / "log.json").is_file()


def test_admission_of_a_new_build_reads_s3s_sealed_result_set(tmp_path, case, lock):
    from fmb.assessment.stage import assess_cards

    prepared, built = _new_format_build(tmp_path, case)
    condition = tmp_path / "condition"
    workflow.freeze_condition(built=built, condition="luna-high", output=condition)
    rules = tmp_path / "rules"
    assess_cards(built=built, output=rules)
    with pytest.raises(ValueError, match="needs S3's sealed rule assessment"):
        _admit(prepared, built, condition, _references(case))
    with pytest.raises(ValueError, match="S3 must decide before admission opens the reference"):
        assess_cards(built=built, output=tmp_path / "late")
    import shutil

    shutil.rmtree(prepared / "admission")
    result = _admit(prepared, built, condition, _references(case), rules=rules)
    assert result["status"] == "passed"
    certificate = read_json(condition / "admission" / "admission.json")
    assert certificate["rule_assessment"]["engine"] == "rules"
    assert certificate["rule_assessment"]["assessment_sha256"] == sha256_file(rules / "assessment.json")


def test_admission_of_an_old_build_still_reads_the_condition_baseline(tmp_path, case, lock):
    prepared, built = _new_format_build(tmp_path, case, deterministic=True)
    condition = tmp_path / "condition"
    workflow.freeze_condition(built=built, condition="luna-high", output=condition)
    assert (condition / "deterministic" / "log.json").is_file()
    assert _admit(prepared, built, condition, _references(case))["status"] == "passed"


@pytest.mark.parametrize("valid_hash", [False, True])
def test_failed_native_admission_blocks_later_assessment_and_freeze(tmp_path, case, lock, monkeypatch, valid_hash):
    from fmb.assessment.stage import assess_cards
    from fmb.evaluation import native_reference

    prepared, built = _new_format_build(tmp_path, case)
    workflow.freeze_condition(built=built, condition="luna-high", output=tmp_path / "condition")
    assess_cards(built=built, output=tmp_path / "rules")
    generation = tmp_path / "generation"
    reference = generation / "finding_reference.json"
    write_json(reference, {})
    write_json(generation / "manifest.json", {
        "finding_reference": reference.name,
        "finding_reference_sha256": sha256_file(reference) if valid_hash else "0" * 64,
        "artifacts": [],
    })
    opened = []

    def checked_hash(path):
        assert (prepared / "admission").is_dir()
        opened.append(path)
        return sha256_file(path)

    monkeypatch.setattr(native_reference, "sha256_file", checked_hash)
    with pytest.raises(ValueError, match="not manifest-bound"):
        native_reference.write_native_references(prepared, {"generation": str(generation)})
    assert opened == [reference]
    assert (prepared / "admission").is_dir()
    assert not (prepared / "admission" / "truth-seal.json").exists()
    with pytest.raises(FileExistsError):
        native_reference.write_native_references(prepared, {"generation": str(generation)})
    assert opened == [reference]
    with pytest.raises(ValueError, match="before admission opens"):
        assess_cards(built=built, output=tmp_path / "late-rules")
    with pytest.raises(ValueError, match="before opening reference admission"):
        workflow.freeze_condition(built=built, condition="luna-high", output=tmp_path / "late-condition")


def test_the_presentation_check_passes_and_stops_on_a_changed_decision(tmp_path, case, monkeypatch):
    monkeypatch.setattr(presentation_check, "QIDS", ("BQ-LOG-01",))
    prepared, built = _new_format_build(tmp_path, case)
    result = presentation_check.check_presentation(prepared=prepared, built=built)
    assert result["status"] == "passed" and result["engine"] == "rules"
    assert result["decoded_sent_view_equals_request_case"] == 1
    other = prepare_case(log_bundle([100, 101], event_ids=[4624, 4624]))
    (prepared / "cases" / "BQ-LOG-01.json").write_text(canonical_json(other))
    (prepared / "preparation-seal.json").unlink()
    seal_directory(prepared)
    with pytest.raises(ValueError, match="presenting the cards changed a decision of S3 engine rules"):
        presentation_check.check_presentation(prepared=prepared, built=built)


@pytest.mark.parametrize("scope, shown", [("hidden", False), ("shown", True)])
def test_the_question_scope_is_a_declared_presentation_option(case, scope, shown):
    from fmb.assessment.stage import decode_for_engine
    from fmb.core import paper_contract
    from fmb.profiles import question_definitions

    options = paper_contract.validate_options({"stated_reasons": True, "views": ["no_scope"] if scope == "hidden" else []})
    sent = paper_contract.encode(case, options)
    assert ("scope" in sent["question"]) is shown
    decoded = decode_for_engine(sent, options, question_definitions())
    assert decoded["question"] == question_definitions()["BQ-LOG-01"]


@pytest.mark.parametrize("change, message", [
    ({"question_scope": "partly"}, "question_scope must be hidden or shown"),
    ({"stages": {"s3": {"engine": "magic"}}}, "unknown S3 engine"),
    ({"stages": {"s2": {"collector": "x"}}}, "stages may name only"),
])
def test_the_runner_refuses_undeclared_stage_choices(tmp_path, change, message):
    from fmb.pipeline.runner import run_pipeline

    config = {"case_label": "I1-01", "generation": str(tmp_path), "analysis": str(tmp_path),
              "conditions": ["luna-high"], "output": str(tmp_path / "run")} | change
    with pytest.raises(ValueError, match=message):
        run_pipeline(config)
    assert not (tmp_path / "run").exists()


def test_s2_runs_no_assessor():
    import ast
    from pathlib import Path

    import fmb.paper.presentation as presentation
    import fmb.paper.workflow as flow

    for module in (presentation,):
        tree = ast.parse(Path(module.__file__).read_text())
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                    for alias in node.names} | {node.module for node in ast.walk(tree)
                                                 if isinstance(node, ast.ImportFrom) and node.module}
        assert "fmb.assessment.rules" not in imported and "assess" not in imported
    source = Path(flow.__file__).read_text()
    prepare_native = source[source.index("def prepare_native"):source.index("def prepare(")]
    code = [line for line in prepare_native.splitlines() if not line.strip().startswith(('"""', "#"))
            and "no assessor runs here" not in line]
    assert not any("assess(" in line or "deterministic" in line for line in code)


def test_component_contract_and_reference_binding_need_no_assessor(monkeypatch):
    import builtins
    from fmb.analysis.factual_contract import factual_response_schema
    from fmb.preparation.binding import _card

    card = log_bundle([100, 103]).payload["candidate_roster"][0]
    original_import = builtins.__import__

    def independent_import(name, *args, **kwargs):
        if name in {"fmb.analysis.shared_rules", "fmb.assessment.rules"}:
            pytest.fail("component contract imported the assessor")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", independent_import)
    expected = ["security_log_clear_event", "event_record_sequence_gap"]
    assert _card(card, "BQ-LOG-01")["components"] == expected
    schema = factual_response_schema([card], "BQ-LOG-01")
    assert schema["properties"]["assessments"]["properties"][card["subject_id"]]["required"] == expected


@pytest.mark.parametrize("change", [
    "missing_subject", "extra_subject", "missing_component", "extra_component",
    "invalid_status", "malformed_decision", "contradictory_status",
])
def test_inconsistent_or_incomplete_engine_cannot_seal(tmp_path, case, lock, monkeypatch, change):
    from fmb.assessment import stage

    class BrokenEngine(stage.RulesEngine):
        id = "broken"

        def decide(self, case):
            response, decisions = super().decide(case)
            subject = next(iter(decisions))
            component = next(iter(decisions[subject]))
            if change == "missing_subject":
                del decisions[subject]
            elif change == "extra_subject":
                decisions["extra"] = decisions[subject]
            elif change == "missing_component":
                del decisions[subject][component]
            elif change == "extra_component":
                decisions[subject]["extra"] = decisions[subject][component]
            elif change == "malformed_decision":
                decisions[subject][component] = None
            else:
                decisions[subject][component]["status"] = (
                    "invalid" if change == "invalid_status" else "insufficient")
            return response, decisions

    monkeypatch.setitem(stage.ENGINES, "broken", BrokenEngine())
    _, built = _new_format_build(tmp_path, case)
    with pytest.raises(ValueError, match="rule decision|rule response"):
        stage.assess_cards(built=built, output=tmp_path / "rules", engine_name="broken")
    assert not (tmp_path / "rules" / stage.SEAL).exists()


def test_consistently_wrong_engine_fails_independent_admission(tmp_path, case, lock, monkeypatch):
    from fmb.assessment import stage
    from fmb.core.paper_results import response_from_decisions
    from fmb.pipeline.evaluation import comparison, sealed_findings_table

    class NegativeEngine(stage.RulesEngine):
        id = "negative"

        def decide(self, case):
            _, decisions = super().decide(case)
            for components in decisions.values():
                for decision in components.values():
                    decision["status"] = "not_supported"
            return response_from_decisions(case, decisions), decisions

    monkeypatch.setitem(stage.ENGINES, "negative", NegativeEngine())
    prepared, built = _new_format_build(tmp_path, case)
    condition, rules = tmp_path / "condition", tmp_path / "rules"
    workflow.freeze_condition(built=built, condition="luna-high", output=condition)
    stage.assess_cards(built=built, output=rules, engine_name="negative")
    references = _references(case)
    expected = canonical_json(references)
    result = _admit(prepared, built, condition, references, rules=rules)
    assert result["status"] == "failed" and result["different_requests"][str(condition)] == ["log"]
    assert canonical_json(read_json(prepared / "admission" / "references.json")) == expected
    rows = sealed_findings_table([condition], rules=rules)
    assert comparison(rows)["rules"]["finding_counts"] == {"tp": 0, "fn": 1, "fp": 0, "tn": 1, "unresolved": 0}
    with pytest.raises(ValueError, match="lacks exact independent admission"):
        workflow.execute_condition(condition, cap_usd=1, rates={}, execute=True,
                                   provider=lambda **_: pytest.fail("unadmitted dispatch"))


@pytest.mark.parametrize("change", ["status", "missing_component", "request_id"])
def test_sealed_result_readers_reject_inconsistent_decisions(tmp_path, case, lock, change):
    from fmb.assessment import stage
    from fmb.pipeline import evaluation, stages

    prepared, built = _new_format_build(tmp_path, case)
    condition, rules = tmp_path / "condition", tmp_path / "rules"
    workflow.freeze_condition(built=built, condition="luna-high", output=condition)
    stage.assess_cards(built=built, output=rules)
    references = _references(case)
    assert _admit(prepared, built, condition, references, rules=rules)["status"] == "passed"
    path = rules / "decisions" / "log.json"
    record = read_json(path)
    components = next(iter(record["decisions"].values()))
    if change == "status":
        next(iter(components.values()))["status"] = "insufficient"
    elif change == "missing_component":
        components.pop(next(iter(components)))
    else:
        record["request_id"] = "another-request"
    write_json(path, record)
    (rules / stage.SEAL).unlink()
    seal_directory(rules, stage.SEAL)
    g3 = {"case_label": "I1-01", "view_options": stages.file_ref(built / "view-options.json"),
          "questions": {"BQ-LOG-01": {"requests": [{"request_id": "log",
                              "sent_sha256": sha256_file(built / "sent" / "log.json")}]}}}
    readers = [
        lambda: stage.rule_result(rules, "log", case),
        lambda: stage.verify_assessment(rules, built=built),
        lambda: paper_admission.admit_conditions(prepared=prepared, built=built, condition_runs=[condition],
                                                 references=references, rules=rules),
        lambda: stages.rules_gate(rules, built, g3, "0" * 64),
        lambda: evaluation.findings_table(built, g3, [condition], rules=rules),
        lambda: evaluation.sealed_findings_table([condition], rules=rules),
    ]
    for read in readers:
        with pytest.raises(ValueError, match="rule decision|rule response"):
            read()
