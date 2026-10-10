from copy import deepcopy
import pytest

from fmb.evaluation.scoring import score_schedule
from fmb.core.paper_policy import completion_eligible, resolve_policy


def fixture():
    schedule = []
    outcomes = []
    references = {
        "c1": {"expected_status": {"a": "supported"}},
        "c2": {"expected_status": {"b": "not_supported"}},
    }
    for p in (1, 2, 3):
        for case in ("c1", "c2"):
            row = {
                "request_id": case,
                "case_id": case,
                "question_id": "DELETE",
                "pass": p,
                "batch_index": 0,
                "batches": 1,
                "binding": {"case": case, "schema": "same-schema"},
            }
            schedule.append(row)
            outcomes.append(
                {
                    **row,
                    "status": "completed",
                    "two_list": {
                        "supported_findings": ["a"] if case == "c1" else [],
                        "insufficient_findings": [],
                    },
                    "started_utc": "2026-09-18T00:00:00+00:00",
                    "finished_utc": "2026-09-18T00:01:00+00:00",
                    "conservative_exposure_usd": "0.01",
                }
            )
    return schedule, references, outcomes


def test_complete_schedule_exact_and_decimal_accounting():
    score = score_schedule(*fixture())
    assert score["exact_question_passes"] == 3 and score["every_pass"] == 1
    assert score["selected_exposure_usd"] == "0.06"
    assert score["selected_request_seconds_sum"] == "360.0"


@pytest.mark.parametrize("declaration,replaces,basis", [
    ({}, "not_completed", "implicit_legacy_default"),
    ({"completion_policy": {"replaces": "not_completed"}}, "not_completed", "declared"),
    ({"completion_policy": {"replaces": "unanswered"}}, "unanswered", "declared"),
])
def test_historical_policy_is_explicit_in_provenance_without_retroactive_attempt_limits(declaration, replaces, basis):
    policy = resolve_policy(declaration)
    assert policy["basis"] == basis and policy["replaces"] == replaces
    assert policy["max_total_attempts"] is None
    assert completion_eligible({"status": "transport_exhausted", "attempts": 12}, policy)
    assert completion_eligible({"status": "invalid_response"}, policy) == (replaces == "not_completed")
    with pytest.raises(ValueError, match="historical preparations are read-only"):
        resolve_policy(declaration, for_execution=True)


def test_unknown_policy_is_rejected_before_scoring():
    with pytest.raises(ValueError, match="unknown completion policy"):
        score_schedule(*fixture(), replaces="choose-correct-answer")


@pytest.mark.parametrize(
    "missing", ["absent_file", "no_answer", "precheck", "invalid", "unresolved"]
)
def test_one_missing_or_unresolved_split_card_prevents_exact(missing):
    schedule, refs, answers = fixture()
    if missing == "absent_file":
        answers.pop()
    elif missing == "no_answer":
        answers[-1].update(
            status="execution_failure", attempts=3, error={"type": "ExternalToolError"}
        )
    elif missing == "precheck":
        answers[-1].update(
            status="execution_failure", attempts=0, error={"type": "ContextLimitError"}
        )
    elif missing == "invalid":
        answers[-1]["status"] = "invalid_response"
    else:
        answers[-1]["two_list"]["insufficient_findings"] = ["b"]
    score = score_schedule(schedule, refs, answers)
    assert score["exact_question_passes"] == 2 and score["every_pass"] == 0
    assert score["planned_requests"] == 6 and score["planned_question_passes"] == 3
    expected = "0.06" if missing in {"invalid", "unresolved"} else "0.05"
    assert score["selected_exposure_usd"] == expected


def test_missing_entire_pass_and_declared_question_stay_in_denominator():
    schedule, refs, answers = fixture()
    score = score_schedule(
        schedule, refs, answers[:4], question_ids=["DELETE", "TIME"], passes=[1, 2, 3]
    )
    assert score["planned_question_passes"] == 6 and score["exact_question_passes"] == 2
    assert score["exact_all_passes"] == {"numerator": 0, "denominator": 2}


def test_absent_primary_can_use_a_bound_completed_companion():
    schedule, refs, answers = fixture()
    companion = [deepcopy(answers[-1])]
    answers.pop()
    score = score_schedule(schedule, refs, answers, companion=companion)
    assert score["every_pass"] == 1 and score["selection"][-1]["source"] == "companion"


@pytest.mark.parametrize("replaces, primary_state, source", [
    ("not_completed", "execution_failure", "companion"),
    ("not_completed", "invalid_response", "companion"),
    ("unanswered", "execution_failure", "companion"),
    ("unanswered", "invalid_response", "primary"),
])
def test_the_declared_completion_policy_decides_what_a_companion_replaces(replaces, primary_state, source):
    schedule, refs, answers = fixture()
    companion = [deepcopy(answers[-1])]
    answers[-1]["status"] = primary_state
    score = score_schedule(schedule, refs, answers, companion=companion, replaces=replaces)
    assert score["selection"][-1]["source"] == source
    assert score["every_pass"] == (1 if source == "companion" else 0)


@pytest.mark.parametrize("change", ["binding", "duplicate", "identity", "extra"])
def test_bad_companions_cannot_enter_scoring(change):
    schedule, refs, answers = fixture()
    companion = [deepcopy(answers[-1])]
    answers.pop()
    if change == "binding":
        companion[0]["binding"]["case"] = "different evidence"
    elif change == "duplicate":
        companion.append(deepcopy(companion[0]))
    elif change == "identity":
        companion[0]["question_id"] = "USB"
    else:
        companion[0]["pass"] = 4
    with pytest.raises(ValueError):
        score_schedule(schedule, refs, answers, companion=companion)


def test_invalid_return_preserves_resources_and_misses_positive_targets():
    schedule, refs, answers = fixture()
    answers[-2]["status"] = "invalid_response"
    score = score_schedule(schedule, refs, answers)
    assert (
        score["finding_counts"]["fn"] == 1 and score["finding_counts"]["unusable"] == 1
    )
    assert (
        score["selected_exposure_usd"] == "0.06"
        and score["selected_request_seconds_sum"] == "360.0"
    )


def test_duplicate_and_unknown_findings_rejected():
    schedule, refs, answers = fixture()
    answers[0]["two_list"]["supported_findings"] = ["a", "a"]
    with pytest.raises(ValueError):
        score_schedule(schedule, refs, answers)
    answers[0]["two_list"]["supported_findings"] = ["alien"]
    with pytest.raises(ValueError):
        score_schedule(schedule, refs, answers)


def test_a_run_limited_to_some_questions_is_scored_on_those_questions(tmp_path):
    import shutil
    from fmb.core.sealed_records import read_json, seal_directory, write_json
    from fmb.evaluation.scoring import score_run
    from fmb.paper.replay import example_root

    if not example_root().is_dir():
        pytest.skip("the study's I1 records are kept out of the public repository")
    root = tmp_path / "i1"
    shutil.copytree(example_root(), root)
    schedule = read_json(root / "run/schedule.json")
    kept = {(row["request_id"], row["pass"]) for row in schedule["rows"] if row["question_id"] == "BQ-LOG-01"}
    write_json(root / "run/schedule.json", {
        "rows": [row for row in schedule["rows"] if (row["request_id"], row["pass"]) in kept],
        "question_ids": ["BQ-LOG-01"],
    })
    for call in (root / "run").glob("call-*"):
        outcome = read_json(call / "outcome.json")
        if (outcome["request_id"], outcome["pass"]) not in kept:
            shutil.rmtree(call)
    (root / "run/prediction-seal.json").unlink()
    seal_directory(root / "run", "prediction-seal.json")
    (root / "preparation-seal.json").unlink()
    seal_directory(root)

    score = score_run(root)
    assert score["questions"] == 1 and set(score["per_question"]) == {"BQ-LOG-01"}
    assert score["planned_requests"] == score["planned_question_passes"] == 3
