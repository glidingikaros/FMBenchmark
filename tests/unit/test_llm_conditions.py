import hashlib
import json

import pytest

from fmb.assessment import llm
from fmb.assessment.rules import assess
from fmb.core import paper_integrity as integrity
from fmb.core import sealed_records
from fmb.core.case_contract import prepare_case, target_catalog
from fmb.core.hashing import sha256_file
from fmb.core.paper_protocol import paper_protocol
from fmb.core.sealed_records import canonical_json, read_json, seal_directory, write_json
from fmb.evaluation import admission
from fmb.evaluation.scoring import score_run
from fmb.interpretation.provider import LLMResponse
from fmb.paper import workflow
from fmb.pipeline import stages
from paper_fixtures import log_bundle

FIXED_UTC = "2026-09-18T00:00:00+00:00"
CASES = {"log-a": [100, 103], "log-b": [200, 201, 205], "log-c": [7, 9], "log-d": [1, 2, 3, 10]}
PAPER_FREEZES = {
    "luna-high": "63f2203fcfe7100e8d767824ae7d67b9e587620a274df4078c07f0d1cbcd4dc3",
    "luna-max": "ce6599c24490e7f362e5b2e3620e16d3cde7c379e374c8d22d83409e010cd14c",
    "luna-max:completion": "0a33343a0719bdc013940740e6b6af70f093e75d7b654f0511e1c752aa61ee5a",
    "sonnet5-high": "2ed20945b9dcd9a4214defb023609c0d6050f5ccee29d5c357a9da822dc99a4d",
    "gemini38flash-high": "09ab8c7e132dd27e2e4e7de19be7c1239ac82494196d0416e6362d1c08acd7cd",
    "deepseekv4pro-high": "53c280898548e71bb8e77c45829dfba41d970150068f04a4c139df2b57b34623",
    "glm53flash-high": "44212cae60c972231adf66fd02e1eef21cb110ad195ce2f465288d58339d512d",
    "glm53flash-high:completion": "f38905d706032d1b349d16cdadd4f541849ab6f23aa6fb27dcb60c7f282abd1c",
    "qwen38-27b-xhigh": "6aa44f1bde91edcec231efae081465d36926154b4cd68768e7ed27122012cb5c",
    "mistralsmall2603-high": "a255c7702833ceee9cee735f7b05b98c25a2caf0bc88a93572d0ae98a78b8ff3",
}
PAPER_G4 = "8bb79ca502afc960541c948b7bbf387d02aca4a0e4015ee74ba7ac587f272c50"
PAPER_SCORE = "a8756738c861c3c8147d6ff56011cf7eabd87142d19522b50e7c3f3ce8f1e4f6"
SCORE_KEYS = ("schema_version", "planned_requests", "questions", "passes", "planned_question_passes",
              "exact_question_passes", "every_pass", "exact_all_passes", "per_question", "finding_counts", "f1",
              "execution_states", "selected_exposure_usd", "selected_request_seconds_sum", "selected_tokens",
              "selection", "metric_policy")


@pytest.fixture
def fixed(monkeypatch):
    monkeypatch.setattr(integrity, "source_manifest_sha256", lambda: "test-source-lock")
    monkeypatch.setattr(sealed_records, "now", lambda: FIXED_UTC)
    monkeypatch.setattr(llm, "now", lambda: FIXED_UTC)
    monkeypatch.setattr(admission, "QIDS", ("BQ-LOG-01",))


def build(root, cases):
    prepared, built, generation = root / "prepared", root / "cards", root / "generation"
    prepared.mkdir()
    generation.mkdir()
    write_json(prepared / "manifest.json", {"truth_sources_used": []})
    seal_directory(prepared)
    requests = {}
    for rid, ids in cases.items():
        case = prepare_case(log_bundle(ids))
        sent = built / "sent" / (rid + ".json")
        sent.parent.mkdir(parents=True, exist_ok=True)
        sent.write_text(canonical_json(case))
        write_json(built / "deterministic" / (rid + ".json"), assess(case))
        requests[rid] = {"sent_sha256": sha256_file(sent),
                         "deterministic_sha256": sha256_file(built / "deterministic" / (rid + ".json"))}
    write_json(built / "view-options.json", {"stated_reasons": True})
    write_json(built / "build-report.json", {
        "oracle_lock_sha256": "test-source-lock", "production_preparation": "../prepared",
        "production_seal_sha256": sha256_file(prepared / "preparation-seal.json"), "reference_already_opened": False})
    seal_directory(built, "build-seal.json")
    write_json(built / "build-seal.json", {**read_json(built / "build-seal.json"), "requests": requests})
    return prepared, built, generation


def freeze(built, generation, out, condition, **options):
    workflow.freeze_condition(built=built, condition=condition, output=out, generation=generation, **options)
    return out


def gap_findings(case):
    return sorted(fid for fid, target in target_catalog(case).items()
                  if target["component"] == "event_record_sequence_gap")


def admit(prepared, built, runs):
    case = read_json(built / "sent" / "log.json")
    refs = {"BQ-LOG-01": {"expected_status": {fid: "supported" if fid in gap_findings(case) else "not_supported"
                                              for fid in target_catalog(case)},
                          "basis": "synthetic event sequence"}}
    write_json(prepared / "admission/references.json", refs)
    seal_directory(prepared / "admission", "truth-seal.json")
    assert admission.admit_conditions(prepared=prepared, built=built, condition_runs=runs,
                                      references=refs)["status"] == "passed"


def rotating(model, calls):
    def answer(**kwargs):
        calls.append(kwargs)
        case = json.loads(kwargs["prompt"])
        reasons = {fid: "r" for fid in target_catalog(case)}
        text = ["{}", json.dumps({"supported_findings": gap_findings(case), "insufficient_findings": [],
                                  "reasons": reasons}),
                json.dumps({"supported_findings": [], "insufficient_findings": [], "reasons": reasons})][len(calls) % 3]
        return LLMResponse(kwargs["provider"], model, text, {}, usage={"input_tokens": 100, "output_tokens": 20})
    return answer


def digest(value):
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def test_the_paper_conditions_freeze_the_same_bytes_as_before(tmp_path, fixed):
    _, built, generation = build(tmp_path, CASES)
    frozen = {}
    for name, declared in paper_protocol()["conditions"].items():
        for completion in (False, True) if declared.get("completion_policy") else (False,):
            key = f"{name}:completion" if completion else name
            out = freeze(built, generation, tmp_path / "frozen" / key.replace(":", "-"), name, completion=completion)
            frozen[key] = sha256_file(out / "preparation-seal.json")
    assert frozen == PAPER_FREEZES
    assert digest(stages.llm_gate(tmp_path / "frozen" / "luna-high", "I1-01", "0" * 64, {"run": tmp_path})) == PAPER_G4


def test_the_paper_three_passes_execute_and_score_as_before(tmp_path, fixed):
    prepared, built, generation = build(tmp_path, {"log": [100, 103]})
    out = freeze(built, generation, tmp_path / "frozen" / "luna-high", "luna-high")
    admit(prepared, built, [out])
    calls = []
    workflow.execute_condition(out, cap_usd="10", rates={"input": "1", "output": "1"},
                               provider=rotating("gpt-5.6-luna", calls), sleep=lambda _: None)
    score = score_run(out)
    assert len(calls) == 3 and score["passes"] == [1, 2, 3]
    assert digest({key: score[key] for key in SCORE_KEYS}) == PAPER_SCORE
