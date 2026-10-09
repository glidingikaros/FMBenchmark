from decimal import Decimal
import json

import pytest

from fmb.evaluation import admission as paper_admission
from fmb.evaluation.scoring import score_run
from fmb.assessment.rules import assess
from fmb.core import paper_integrity as integrity
from fmb.core.paper_artifacts import verify_prepared_condition
from fmb.core.case_contract import prepare_case, target_catalog
from fmb.core.errors import ExternalToolError
from fmb.core.hashing import sha256_file
from fmb.core.sealed_records import (
    canonical_json,
    read_json,
    write_json,
    seal_directory,
    verify_seal,
)
from fmb.paper import workflow as execution
from fmb.interpretation.paper_payload import wire
from fmb.interpretation.provider import LLMResponse
from paper_fixtures import log_bundle


@pytest.fixture
def frozen(tmp_path, monkeypatch):
    monkeypatch.setattr(integrity, "source_manifest_sha256", lambda: "test-source-lock")
    monkeypatch.setattr(paper_admission, "QIDS", ("BQ-LOG-01",))
    prepared = tmp_path / "prepared"
    prepared.mkdir()
    (tmp_path / "generation").mkdir()
    write_json(prepared / "manifest.json", {"truth_sources_used": [], "generation": str(tmp_path / "generation")})
    seal_directory(prepared)
    built = tmp_path / "cards"
    built.mkdir()
    case = prepare_case(log_bundle([100, 103], event_ids=[4624, 4624]))
    path = built / "sent/log.json"
    path.parent.mkdir()
    path.write_text(canonical_json(case))
    write_json(built / "deterministic/log.json", assess(case))
    write_json(built / "view-options.json", {"stated_reasons": True})
    write_json(
        built / "build-report.json",
        {
            "oracle_lock_sha256": "test-source-lock",
            "production_preparation": str(prepared),
            "production_seal_sha256": sha256_file(prepared / "preparation-seal.json"),
            "reference_already_opened": False,
        },
    )
    seal_directory(built, "build-seal.json")
    seal = read_json(built / "build-seal.json")
    seal["requests"] = {"log": {
        "sent_sha256": sha256_file(path),
        "deterministic_sha256": sha256_file(built / "deterministic/log.json"),
    }}
    write_json(built / "build-seal.json", seal)
    out = tmp_path / "condition"
    execution.freeze_condition(built=built, condition="luna-high", output=out)
    expected = {
        fid: "supported"
        if target["component"] == "event_record_sequence_gap"
        else "not_supported"
        for fid, target in target_catalog(case).items()
    }
    refs = {
        "BQ-LOG-01": {
            "expected_status": expected,
            "basis": "synthetic event sequence defined in this test",
        }
    }
    return prepared, built, out, refs


def admit(frozen):
    prepared, built, out, refs = frozen
    write_json(prepared / "admission/references.json", refs)
    seal_directory(prepared / "admission", "truth-seal.json")
    return paper_admission.admit_conditions(
        prepared=prepared, built=built, condition_runs=[out], references=refs
    )


def test_dispatch_checks_authorization_without_opening_reference_labels(frozen):
    from fmb.pipeline.reads import measured

    admit(frozen)
    out = frozen[2]
    with measured() as opened:
        run(out, answer, pass_limit=1)
    assert str(out / "admission" / "admission.json") in opened
    assert str(out / "admission" / "references.json") not in opened
    write_json(out / "admission" / "references.json", {"changed": True})
    with pytest.raises(ValueError, match="sealed file changed"):
        score_run(out)


def test_dispatch_refuses_a_changed_admission_certificate(frozen):
    admit(frozen)
    out = frozen[2]
    write_json(out / "admission" / "admission.json", {"status": "passed"})
    with pytest.raises(ValueError, match="sealed file changed"):
        run(out, lambda **_: pytest.fail("changed authorization dispatched"))


def answer(**kwargs):
    case = json.loads(kwargs["prompt"])
    text = json.dumps(
        {
            "supported_findings": [],
            "insufficient_findings": [],
            "reasons": {fid: "Local mock answer." for fid in target_catalog(case)},
        }
    )
    return LLMResponse(
        "openai",
        "gpt-5.6-luna",
        text,
        {},
        usage={"input_tokens": 100, "output_tokens": 20},
    )


def run(out, provider, **kwargs):
    return execution.execute_condition(
        out,
        cap_usd=kwargs.get("cap", "10"),
        rates={"input": "1", "output": "1"},
        provider=provider,
        sleep=lambda _: None,
        pass_limit=kwargs.get("pass_limit"),
        question_ids=kwargs.get("question_ids"),
        development_unadmitted=kwargs.get("development_unadmitted", False),
        primary=kwargs.get("primary"),
    )


def test_freeze_is_truth_blind_and_complete(frozen):
    prepared, built, out, _ = frozen
    seal = sha256_file(out / "preparation-seal.json")
    assert not (out / "admission").exists()
    _, _, schedule = verify_prepared_condition(out)
    assert [r["call"] for r in schedule] == [1, 2, 3]
    assert [r["pass"] for r in schedule] == [1, 2, 3]
    body = (out / "requests/log.json").read_text()
    assert "expected_status" not in body and "references.json" not in body
    assert admit(frozen)["status"] == "passed"
    assert sha256_file(out / "preparation-seal.json") == seal
    with pytest.raises(ValueError, match="before opening"):
        execution.freeze_condition(
            built=built, condition="luna-high", output=out.parent / "late"
        )


def test_all_conditions_reuse_the_single_bounded_baseline(frozen, monkeypatch):
    from fmb.assessment import rules
    from fmb.core.paper_protocol import paper_protocol
    from fmb.paper import presentation

    _, built, first, _ = frozen

    def reassessed(*_):
        pytest.fail("freezing a condition must reuse the final sealed assessment")

    monkeypatch.setattr(rules, "assess", reassessed)
    monkeypatch.setattr(rules, "assess_with_decisions", reassessed)
    assert not hasattr(presentation, "assess") and not hasattr(execution, "assess")
    baseline = (built / "deterministic/log.json").read_bytes()
    original_case = (first / "cases/log.json").read_bytes()
    for condition in paper_protocol()["conditions"]:
        out = first.parent / condition
        execution.freeze_condition(built=built, condition=condition, output=out)
        assert (out / "deterministic/log.json").read_bytes() == baseline
        assert (out / "cases/log.json").read_bytes() == original_case
        _, _, schedule = verify_prepared_condition(out)
        assert [(r["request_id"], r["pass"], r["call"]) for r in schedule] == [
            ("log", 1, 1), ("log", 2, 2), ("log", 3, 3),
        ]
        if condition in {"luna-max", "glm53flash-high"}:
            completion = out.with_name(condition + "-completion")
            execution.freeze_condition(
                built=built, condition=condition, output=completion, completion=True,
            )
            assert (completion / "deterministic/log.json").read_bytes() == baseline
            verify_prepared_condition(completion)


def test_resealed_condition_cannot_replace_the_canonical_baseline(frozen):
    _, _, out, _ = frozen
    path = out / "deterministic/log.json"
    write_json(path, {"supported_findings": [], "insufficient_findings": []})
    seal = read_json(out / "preparation-seal.json")
    seal["files"]["deterministic/log.json"] = sha256_file(path)
    write_json(out / "preparation-seal.json", seal)
    with pytest.raises(ValueError, match="deterministic result differs"):
        verify_prepared_condition(out)


def test_a_canonical_baseline_must_belong_to_the_build_seal(frozen):
    _, built, out, _ = frozen
    seal = read_json(built / "build-seal.json")
    seal["files"].pop("deterministic/log.json")
    write_json(built / "build-seal.json", seal)
    with pytest.raises(ValueError, match="sealed canonical"):
        execution.freeze_condition(
            built=built, condition="luna-high", output=out.parent / "unbound-baseline",
        )


@pytest.mark.parametrize("change", ["missing_target", "wrong_label"])
def test_failed_or_partial_reference_cannot_authorize_dispatch(frozen, change):
    _, _, out, refs = frozen
    wanted = refs["BQ-LOG-01"]["expected_status"]
    if change == "missing_target":
        wanted.pop(next(iter(wanted)))
        with pytest.raises((KeyError, ValueError)):
            admit(frozen)
    else:
        for key in wanted:
            wanted[key] = "not_supported"
        assert admit(frozen)["status"] == "failed"
    with pytest.raises((ValueError, OSError)):
        run(out, lambda **_: pytest.fail("dispatch must not happen"))


def test_invalid_return_and_valid_wrong_answer_are_not_retried(frozen):
    admit(frozen)
    out = frozen[2]
    calls = []

    def provider(**kwargs):
        calls.append(kwargs)
        return (
            LLMResponse("openai", "gpt-5.6-luna", "broken-json", {})
            if len(calls) == 1
            else answer(**kwargs)
        )

    assert run(out, provider)["completed"] == 2
    assert len(calls) == 3 and all(calls[0] == value for value in calls)
    outcomes = read_json(out / "run/completion.json")["outcomes"]
    assert [r["status"] for r in outcomes] == [
        "invalid_response",
        "completed",
        "completed",
    ]
    assert Decimal(outcomes[0]["conservative_exposure_usd"]) > 0
    verify_seal(out / "run", "prediction-seal.json")
    with pytest.raises(FileExistsError):
        run(out, provider)
    assert len(calls) == 3


def test_a_pass_limit_runs_only_the_first_passes_and_records_the_limit(frozen):
    admit(frozen)
    out = frozen[2]
    calls = []

    def provider(**kwargs):
        calls.append(kwargs)
        return answer(**kwargs)

    assert run(out, provider, pass_limit=1)["completed"] == 1
    assert len(calls) == 1
    assert read_json(out / "run/schedule.json")["pass_limit"] == 1
    assert {row["pass"] for row in read_json(out / "run/completion.json")["outcomes"]} == {1}
    score = score_run(out)
    assert score["passes"] == [1]
    assert score["planned_requests"] == score["planned_question_passes"] == 1


def test_a_question_selection_runs_only_its_rows_and_records_the_selection(frozen):
    admit(frozen)
    out = frozen[2]
    with pytest.raises(ValueError, match="question selection"):
        run(out, lambda **_: pytest.fail("dispatch"), question_ids=["BQ-TIME-01"])
    assert not (out / "run").exists()
    assert run(out, answer, question_ids=["BQ-LOG-01"])["completed"] == 3
    record = read_json(out / "run/schedule.json")
    assert record["question_ids"] == ["BQ-LOG-01"] and "development" not in record


def test_a_failed_admission_dispatches_only_as_a_labelled_development_run(frozen):
    _, _, out, refs = frozen
    wanted = refs["BQ-LOG-01"]["expected_status"]
    for key in wanted:
        wanted[key] = "not_supported"
    assert admit(frozen)["status"] == "failed"
    with pytest.raises(ValueError, match="lacks exact independent admission"):
        run(out, lambda **_: pytest.fail("dispatch must not happen"))
    assert not (out / "run").exists()
    assert run(out, answer, development_unadmitted=True, pass_limit=1)["completed"] == 1
    assert read_json(out / "run/schedule.json")["development"] == {
        "label": "development_not_admitted",
        "admission_status": "failed",
        "admission_sha256": sha256_file(out / "admission/admission.json"),
    }


def test_development_dispatch_still_needs_this_preparations_admission(frozen):
    admit(frozen)
    out = frozen[2]
    record = read_json(out / "admission/admission.json")
    record["preparation_seal_sha256"] = "0" * 64
    write_json(out / "admission/admission.json", record)
    (out / "admission/admission-seal.json").unlink()
    seal_directory(out / "admission", "admission-seal.json")
    with pytest.raises(ValueError, match="lacks exact independent admission"):
        run(out, lambda **_: pytest.fail("dispatch"), development_unadmitted=True)


def test_transport_retries_are_bounded_and_preserve_identical_bytes(frozen):
    admit(frozen)
    calls = []

    def provider(**kwargs):
        calls.append(wire(kwargs))
        if len(calls) <= 3:
            raise ExternalToolError(
                "unavailable", details={"retryable": True, "http_status": 503}
            )
        return answer(**kwargs)

    assert run(frozen[2], provider)["completed"] == 2
    assert len(calls) == 5 and len(set(calls)) == 1
    row = read_json(frozen[2] / "run/call-001/outcome.json")
    assert row["attempts"] == 3 and row["status"] == "execution_failure"


def test_budget_refusal_makes_no_provider_calls(frozen):
    admit(frozen)
    assert (
        run(frozen[2], lambda **_: pytest.fail("over-budget dispatch"), cap="0.000001")[
            "completed"
        ]
        == 0
    )
    rows = read_json(frozen[2] / "run/completion.json")["outcomes"]
    assert len(rows) == 3 and all(row["attempts"] == 0 for row in rows)


def test_interruption_seals_entire_schedule_and_reserved_exposure(frozen):
    admit(frozen)

    def interrupted(**_):
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        run(frozen[2], interrupted)
    rows = read_json(frozen[2] / "run/completion.json")["outcomes"]
    assert len(rows) == 3
    assert Decimal(rows[0]["conservative_exposure_usd"]) > 0
    assert all(row["status"] == "not_attempted" for row in rows[1:])
    verify_seal(frozen[2] / "run", "prediction-seal.json")


def test_reported_failed_answer_keeps_usage_and_is_not_retried(frozen):
    admit(frozen)
    calls = []

    def limited(**_):
        calls.append(1)
        raise ExternalToolError(
            "no output text",
            details={"usage": {"input_tokens": 100, "output_tokens": 20}},
        )

    run(frozen[2], limited)
    assert len(calls) == 3
    rows = read_json(frozen[2] / "run/completion.json")["outcomes"]
    assert all(row["status"] == "invalid_response" for row in rows)
    assert sum(Decimal(r["conservative_exposure_usd"]) for r in rows) == Decimal(
        "0.00036"
    )


@pytest.mark.parametrize("change", [
    {"reasoning_effort": "max", "max_output_tokens": 65536, "timeout_seconds": 1800},
    {"model": "another-model"},
    {"provider": "openrouter", "route": "another-route"},
])
def test_changed_condition_cannot_authorize_dispatch(frozen, change):
    out = frozen[2]
    protocol = read_json(out / "protocol.json")
    protocol["settings"].update(change)
    protocol.pop("condition_id", None)
    write_json(out / "protocol.json", protocol)
    seal = read_json(out / "preparation-seal.json")
    seal["files"]["protocol.json"] = sha256_file(out / "protocol.json")
    write_json(out / "preparation-seal.json", seal)
    with pytest.raises(ValueError, match="condition"):
        run(out, lambda **_: pytest.fail("mismatched condition dispatched"))


def _byte_bound_refuses(monkeypatch):
    from fmb.assessment import llm

    real = llm.preflight_context_fit

    def tight(**kwargs):
        return {**real(**kwargs), "fits": kwargs.get("exact_input_tokens") is not None}

    monkeypatch.setattr(llm, "preflight_context_fit", tight)


def test_a_request_the_byte_bound_refuses_is_sent_when_its_exact_count_fits(frozen, monkeypatch):
    admit(frozen)
    _byte_bound_refuses(monkeypatch)
    counted = []
    execution.execute_condition(frozen[2], cap_usd="10", rates={"input": "1", "output": "1"}, provider=answer,
                                sleep=lambda _: None, counter=lambda kwargs, body: counted.append(body) or 1000)
    outcomes = read_json(frozen[2] / "run/completion.json")["outcomes"]
    assert len(counted) == 3 and [r["status"] for r in outcomes] != ["execution_failure"] * 3
    precheck = read_json(sorted((frozen[2] / "run").glob("call-*/context-precheck.json"))[0])
    assert precheck["input_token_basis"] == "exact" and precheck["exact_input_tokens"] == 1000
    assert precheck["byte_bound"]["input_tokens"] == precheck["request_bytes"]


def test_a_failed_count_keeps_the_byte_bound_and_the_request_counts_as_not_run(frozen, monkeypatch):
    admit(frozen)
    _byte_bound_refuses(monkeypatch)

    def unavailable(kwargs, body):
        raise ExternalToolError("counting endpoint unavailable")

    execution.execute_condition(frozen[2], cap_usd="10", rates={"input": "1", "output": "1"},
                                provider=lambda **_: pytest.fail("a refused request was sent"),
                                sleep=lambda _: None, counter=unavailable)
    outcomes = read_json(frozen[2] / "run/completion.json")["outcomes"]
    assert [r["error"]["type"] for r in outcomes] == ["ContextLimitError"] * 3
    precheck = read_json(sorted((frozen[2] / "run").glob("call-*/context-precheck.json"))[0])
    assert precheck["input_token_basis"] == "utf8_byte_upper_bound"
    assert precheck["exact_count_error"].startswith("ExternalToolError: counting endpoint unavailable")


@pytest.mark.parametrize("admitted_by", ["byte_bound", "exact_count"])
def test_the_live_call_does_not_repeat_the_dispatchers_context_precheck(frozen, monkeypatch, admitted_by):
    from fmb.interpretation import provider

    admit(frozen)
    if admitted_by == "exact_count":
        _byte_bound_refuses(monkeypatch)

    def rerun(**_):
        raise AssertionError("the live call reran the context pre-check")

    monkeypatch.setattr(provider, "preflight_context_fit", rerun)
    monkeypatch.setenv("OPENAI_API_KEY", "offline-test-key")
    sent = []

    def post_json(url, payload, timeout_seconds, *, headers=None):
        sent.append(payload)
        return {"id": "resp_1", "status": "completed", "model": payload["model"],
                "output_text": answer(prompt=payload["input"]).text, "usage": {"input_tokens": 1000, "output_tokens": 20}}

    monkeypatch.setattr(provider, "post_json", post_json)
    frozen_kwargs = {path: path.read_bytes() for path in (frozen[2] / "requests").glob("*.kwargs.json")}
    counter = (lambda kwargs, body: 1000) if admitted_by == "exact_count" else (
        lambda kwargs, body: pytest.fail("the byte bound admitted the request; no count is needed"))
    execution.execute_condition(frozen[2], cap_usd="10", rates={"input": "1", "output": "1"}, execute=True,
                                sleep=lambda _: None, counter=counter)
    outcomes = read_json(frozen[2] / "run/completion.json")["outcomes"]
    assert [outcome["status"] for outcome in outcomes] == ["completed"] * 3 and len(sent) == 3
    assert {path: path.read_bytes() for path in frozen_kwargs} == frozen_kwargs


def test_an_openai_response_without_output_text_is_an_answer_that_arrived(monkeypatch):
    from fmb.interpretation import provider

    monkeypatch.setenv("OPENAI_API_KEY", "offline-test-key")
    monkeypatch.setattr(provider, "post_json", lambda *a, **k: {"id": "resp_1", "status": "completed", "output": []})
    with pytest.raises(ExternalToolError) as caught:
        provider.call_llm(provider="openai", model="gpt-5.6-luna", prompt="{}", temperature=None, timeout_seconds=5,
                          max_output_tokens=16384, reasoning_effort="high", structured_output="json_schema",
                          response_schema={"type": "object", "properties": {}, "additionalProperties": False})
    assert caught.value.details["provider_failure_stage"] == "response_shape"
    assert caught.value.details["usage"] == {}


def test_a_returned_empty_answer_counts_as_wrong_not_as_not_run(frozen):
    admit(frozen)
    calls = []

    def empty(**kwargs):
        calls.append(kwargs)
        raise ExternalToolError("the provider returned no content", details={
            "provider_failure_stage": "response_shape", "provider_failure_kind": "provider_error",
            "retryable": False})

    run(frozen[2], empty)
    outcomes = read_json(frozen[2] / "run/completion.json")["outcomes"]
    assert [r["status"] for r in outcomes] == ["invalid_response"] * 3
    assert len(calls) == 3
    score = score_run(frozen[2])
    assert score["finding_counts"]["fn"] > 0 and score["exact_question_passes"] == 0


def completion_pair(frozen, condition="luna-max"):
    prepared, built, out, refs = frozen
    runs = [out.parent / name for name in ("primary", "companion", "other-primary", "other-companion")]
    for path, completion in zip(runs, (False, True, False, True)):
        execution.freeze_condition(built=built, condition=condition, output=path, completion=completion)
    write_json(prepared / "admission/references.json", refs)
    seal_directory(prepared / "admission", "truth-seal.json")
    paper_admission.admit_conditions(prepared=prepared, built=built, condition_runs=runs, references=refs)
    return runs


def test_completion_requires_sealed_primary_before_any_dispatch(frozen):
    primary, companion, *_ = completion_pair(frozen)
    def blocked(**_):
        pytest.fail("unbound completion dispatched")
    with pytest.raises(ValueError, match="requires its sealed primary"):
        run(companion, blocked)
    with pytest.raises(FileNotFoundError):
        run(companion, blocked, primary=primary)
    assert not (companion / "run").exists()


@pytest.mark.parametrize("returned", ["valid", "malformed", "empty_with_retryable_flag"])
def test_completion_never_resends_a_returned_answer(frozen, returned):
    from fmb.pipeline.reads import measured

    primary, companion, *_ = completion_pair(frozen)
    calls = []

    def provider(**kwargs):
        calls.append(wire(kwargs))
        if returned == "empty_with_retryable_flag":
            raise ExternalToolError("empty", details={"provider_failure_stage": "response_shape", "retryable": True})
        response = answer(**kwargs)
        if returned == "malformed":
            response.text = "broken-json"
        return response

    run(primary, provider)
    with measured() as opened:
        run(companion, lambda **_: pytest.fail("returned answer resent"), primary=primary)
    assert len(calls) == 3
    assert not any(path.endswith("references.json") for path in opened)
    outcomes = read_json(companion / "run/completion.json")["outcomes"]
    assert all(r["attempts"] == 0 and r["total_attempts"] == 1 for r in outcomes)
    score = score_run(primary, companion=companion)
    assert all(row["source"] == "primary" for row in score["selection"])


def test_completion_uses_remaining_total_allowance_and_identical_requests(frozen):
    primary, companion, *_ = completion_pair(frozen)
    body = (primary / "requests/log.json").read_bytes()
    reservation = Decimal(len(body) + 65536) / 1000000
    calls = []

    def unavailable(**kwargs):
        calls.append(wire(kwargs))
        raise ExternalToolError("unavailable", details={"retryable": True, "http_status": 503})

    run(primary, unavailable, cap=reservation * Decimal("1.5"))
    assert len(calls) == 1
    run(companion, unavailable, primary=primary)
    assert len(calls) == 9 and set(calls) == {body}
    outcomes = read_json(companion / "run/completion.json")["outcomes"]
    assert [row["attempts"] for row in outcomes] == [2, 3, 3]
    assert [row["total_attempts"] for row in outcomes] == [3, 3, 3]
    record = read_json(companion / "run/schedule.json")
    assert record["completion_of"]["prediction_seal_sha256"] == sha256_file(primary / "run/prediction-seal.json")


def test_new_directories_and_alternate_templates_cannot_reset_execution(frozen):
    primary, companion, other_primary, other_companion = completion_pair(frozen)
    run(primary, answer, cap="0.000001")
    with pytest.raises(FileExistsError):
        run(other_primary, lambda **_: pytest.fail("second primary dispatched"))
    run(companion, answer, primary=primary)
    with pytest.raises(FileExistsError):
        run(other_companion, lambda **_: pytest.fail("second companion dispatched"), primary=primary)
    with pytest.raises(ValueError, match="primary execution"):
        run(other_companion, lambda **_: pytest.fail("completion chain dispatched"), primary=companion)


@pytest.mark.parametrize("failure", ["transport_exhausted", "permanent"])
def test_completion_cannot_repeat_exhausted_or_permanent_failures(frozen, failure):
    primary, companion, *_ = completion_pair(frozen)

    def unavailable(**_):
        raise ExternalToolError("failure", details={"retryable": failure == "transport_exhausted", "http_status": 503})

    run(primary, unavailable)
    run(companion, lambda **_: pytest.fail("ineligible retry"), primary=primary)
    assert all(row["attempts"] == 0 for row in read_json(companion / "run/completion.json")["outcomes"])


def test_alternate_route_has_a_separate_non_paper_protocol(frozen):
    primary, companion, *_ = completion_pair(frozen, "glm53flash-high")
    run(primary, answer, cap="0.000001")
    run(companion, answer, primary=primary)
    score = score_run(primary, companion=companion)
    assert score["provenance"]["selection_policy"]["request_policy"] == "declared_alternate_route_non_paper"
    assert all(row["source"] == "companion" for row in score["selection"])


def test_completion_refuses_resealed_reset_attempt_counts(frozen):
    primary, companion, *_ = completion_pair(frozen)
    run(primary, answer)
    outcome_path = primary / "run/call-001/outcome.json"
    row = read_json(outcome_path)
    row.update(status="not_attempted", attempts=0, total_attempts=0, response_received=False)
    write_json(outcome_path, row)
    completion = read_json(primary / "run/completion.json")
    completion["outcomes"][0] = row
    write_json(primary / "run/completion.json", completion)
    (primary / "run/prediction-seal.json").unlink()
    seal_directory(primary / "run", "prediction-seal.json")
    with pytest.raises(ValueError, match="attempt evidence"):
        run(companion, lambda **_: pytest.fail("reset attempt counter dispatched"), primary=primary)


def test_a_malformed_completion_is_scored_as_an_answer_and_cannot_be_scored_alone(frozen):
    primary, companion, *_ = completion_pair(frozen)
    run(primary, answer, cap="0.000001")
    run(companion, lambda **_: LLMResponse("openai", "gpt-5.6-luna", "broken-json", {}), primary=primary)
    score = score_run(primary, companion=companion)
    assert score["execution_states"] == {"invalid_response": 3}
    assert score["finding_counts"]["fn"] > 0 and Decimal(score["selected_exposure_usd"]) > 0
    with pytest.raises(ValueError, match="together with its bound primary"):
        score_run(companion)


def test_completion_binds_the_executed_scope_before_prechecks(frozen):
    primary, companion, *_ = completion_pair(frozen)
    run(primary, answer, cap="0.000001", pass_limit=1)
    with pytest.raises(ValueError, match="request/pass universe"):
        run(companion, lambda **_: pytest.fail("wrong scope dispatched"), primary=primary)
    assert not (companion / "run").exists()
    run(companion, answer, primary=primary, pass_limit=1)
    assert score_run(primary, companion=companion)["passes"] == [1]


def test_a_current_binding_is_checked_before_opening_any_reference(frozen):
    from fmb.evaluation.scoring import load_run, score_loaded_runs

    primary, companion, *_ = completion_pair(frozen)
    run(primary, answer, cap="0.000001")
    run(companion, answer, primary=primary)
    a, b = load_run(primary), load_run(companion)
    a["prediction_seal_sha256"] = "not-this-primary"
    with pytest.raises(ValueError, match="different primary execution"):
        score_loaded_runs(a, b, reference_path=primary / "reference-must-not-be-opened.json")


def test_a_retryable_flag_without_a_transport_failure_does_not_authorize_a_retry(frozen):
    admit(frozen)
    calls = []

    def unknown(**_):
        calls.append(1)
        raise ExternalToolError("unspecified failure", details={"retryable": True})

    run(frozen[2], unknown)
    assert len(calls) == 3


@pytest.mark.parametrize("source_state", ["matching", "missing", "tampered", "misleading_claim"])
def test_flattened_lineage_distinguishes_sealed_evidence_from_unsigned_claims(frozen, source_state):
    import shutil
    from fmb.evaluation.scoring import load_run
    from fmb.evaluation.lineage import run_lineage

    admit(frozen)
    primary = frozen[2]
    run(primary, answer)
    flat = primary.with_name("flat")
    shutil.copytree(primary, flat)
    claims = [{"request_id": "log", "pass": p, "selected_source": "claimed-origin", "total_sends": 99,
               "selected_from": str(primary / f"run/call-{p:03d}")}
              for p in (1, 2, 3)]
    write_json(flat / "flatten-provenance.json", {"per_call": claims, "sum_total_sends": 297})
    if source_state == "missing":
        (primary / "run/prediction-seal.json").unlink()
    elif source_state == "tampered":
        write_json(primary / "run/call-001/outcome.json", {"tampered": True})
    elif source_state == "misleading_claim":
        claims[0]["selected_from"] = str(primary / "run/call-002")
        write_json(flat / "flatten-provenance.json", {"per_call": claims})
    result = run_lineage(load_run(flat))
    merged = result["flattened"]
    assert result["status"] == "historical_lineage_not_fully_verified"
    assert not merged["metadata_sealed"]
    assert result["retained_attempts"] == 3
    expected = {"matching": "sealed_source_bytes_match", "missing": "source_seal_unverified",
                "tampered": "source_seal_unverified", "misleading_claim": "source_bytes_differ"}[source_state]
    assert merged["selections"][0]["source_check"]["status"] == expected
    assert merged["selections"][0]["claimed_total_sends"] == 99


def test_unsigned_lineage_does_not_change_selections_or_metrics(frozen):
    admit(frozen)
    root = frozen[2]
    run(root, answer)
    before = score_run(root)
    write_json(root / "flatten-provenance.json", {"per_call": [], "replaces": "not_completed", "every_pass": 9})
    after = score_run(root)
    assert after["selection"] == before["selection"]
    assert after["f1"] == before["f1"] and after["every_pass"] == before["every_pass"]
    assert after["lineage"]["runs"]["primary"]["flattened"]["status"] == "invalid_flattened_metadata"


@pytest.mark.parametrize("policy", ["missing", None])
def test_current_execution_cannot_be_downgraded_to_legacy_by_removing_the_preparation_policy(frozen, policy):
    from fmb.evaluation.scoring import load_run

    admit(frozen)
    root = frozen[2]
    run(root, answer)
    protocol = read_json(root / "protocol.json")
    if policy == "missing":
        protocol.pop("execution_policy")
    else:
        protocol["execution_policy"] = policy
    write_json(root / "protocol.json", protocol)
    seal = read_json(root / "preparation-seal.json")
    seal["files"]["protocol.json"] = sha256_file(root / "protocol.json")
    write_json(root / "preparation-seal.json", seal)
    with pytest.raises(ValueError, match="historical preparations are read-only"):
        load_run(root)


def test_sealed_evaluation_and_aggregate_report_keep_selection_evidence(frozen):
    from fmb.pipeline.sealed import evaluate_sealed
    from fmb.pipeline.report import read_g5, write_report

    admit(frozen)
    root = frozen[2]
    run(root, answer)
    evaluation = root.with_name("evaluation")
    evaluate_sealed(case_label="I1-01", condition_runs=[root], output=evaluation)
    g5, _ = read_g5(evaluation)
    score = g5["scores"]["luna-high"]
    assert len(score["selection"]) == len(score["lineage"]["selected"]) == 3
    assert score["provenance"]["primary_prediction_seal_sha256"] == sha256_file(root / "run/prediction-seal.json")
    report = root.with_name("aggregate")
    write_report(runs=[evaluation], output=report)
    evidence = read_json(report / "report.json")["images"][0]["evaluation_evidence"]["luna-high"]
    assert evidence["lineage"] == score["lineage"]
    assert evidence["provenance"] == score["provenance"]
    assert "paper_transport.v1" in (report / "results.md").read_text()
    assert "declared_execution_record" in (report / "table-results.csv").read_text()
