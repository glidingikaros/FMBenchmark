from copy import deepcopy
import hashlib
import json

import pytest

from fmb.assessment import llm
from fmb.assessment.rules import assess
from fmb.core import paper_integrity as integrity
from fmb.core import sealed_records
from fmb.core.case_contract import prepare_case, target_catalog
from fmb.core.errors import ConfigurationError
from fmb.core.hashing import sha256_file
from fmb.core.paper_artifacts import verify_prepared_condition
from fmb.core.paper_protocol import SAMPLING, checked_conditions, declare_conditions, paper_protocol
from fmb.core.sealed_records import canonical_json, read_json, seal_directory, write_json
from fmb.evaluation import admission
from fmb.evaluation.scoring import score_run
from fmb.interpretation.paper_payload import wire
from fmb.interpretation.provider import LLMResponse
from fmb.paper import workflow
from fmb.pipeline import stages
from paper_fixtures import log_bundle
from test_stage_substitution import pipeline_inputs as pipeline_inputs

FIXED_UTC = "2026-09-18T00:00:00+00:00"
OWN = {"mine-t0": {"settings": {"provider": "openrouter", "model": "example/model-1", "route": "example/fp8",
                                "reasoning_effort": "low", "max_output_tokens": 4096, "timeout_seconds": 120,
                                "temperature": 0, "top_p": 0.9, "seed": 7,
                                "price_usd_per_million": {"input": "0.5", "output": "1.5"}},
                   "upstream_provider": "Example"}}
OWN_SAMPLING = {"temperature": 0, "top_p": 0.9, "seed": 7}
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


def reseal(out, protocol):
    write_json(out / "protocol.json", protocol)
    seal = read_json(out / "preparation-seal.json")
    seal["files"]["protocol.json"] = sha256_file(out / "protocol.json")
    write_json(out / "preparation-seal.json", seal)


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


def test_a_paper_condition_freezes_the_same_bytes_beside_a_user_condition_of_its_model(tmp_path, fixed):
    _, built, generation = build(tmp_path, CASES)
    twin = {"sonnet5-t0": {"settings": {**paper_protocol()["conditions"]["sonnet5-high"]["settings"], "temperature": 0}}}
    with declare_conditions(twin):
        paper = freeze(built, generation, tmp_path / "frozen" / "sonnet5-high", "sonnet5-high")
        own = freeze(built, generation, tmp_path / "frozen" / "sonnet5-t0", "sonnet5-t0")
    assert sha256_file(paper / "preparation-seal.json") == PAPER_FREEZES["sonnet5-high"]
    for rid in CASES:
        body = read_json(paper / "requests" / (rid + ".json"))
        assert "temperature" not in body and read_json(own / "requests" / (rid + ".json")) == {**body, "temperature": 0}


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


def test_two_passes_are_frozen_executed_and_scored(tmp_path, fixed):
    prepared, built, generation = build(tmp_path, {"log": [100, 103]})
    out = freeze(built, generation, tmp_path / "frozen" / "luna-high", "luna-high", passes=2)
    assert read_json(out / "protocol.json")["passes"] == 2
    assert [(r["pass"], r["call"]) for r in verify_prepared_condition(out)[2]] == [(1, 1), (2, 2)]
    admit(prepared, built, [out])
    calls = []
    workflow.execute_condition(out, cap_usd="10", rates={"input": "1", "output": "1"},
                               provider=rotating("gpt-5.6-luna", calls), sleep=lambda _: None)
    score = score_run(out)
    assert len(calls) == 2 and score["passes"] == [1, 2] and score["planned_question_passes"] == 2
    question = score["per_question"]["BQ-LOG-01"]
    assert question["exact_passes"] == [1] and question["planned_passes"] == [1, 2]
    assert [row["pass"] for row in score["selection"]] == [1, 2]


def test_passes_rotate_the_schedule_and_stay_within_one_to_ten(tmp_path, fixed):
    _, built, generation = build(tmp_path, CASES)
    out = freeze(built, generation, tmp_path / "two", "luna-high", passes=2)
    assert [(r["request_id"], r["pass"]) for r in read_json(out / "schedule.json")["rows"]] == [
        ("log-a", 1), ("log-b", 1), ("log-c", 1), ("log-d", 1), ("log-c", 2), ("log-d", 2), ("log-a", 2), ("log-b", 2)]
    assert len(read_json(freeze(built, generation, tmp_path / "ten", "luna-high", passes=10)
                         / "schedule.json")["rows"]) == 40
    for passes in (0, 11, True, "2"):
        with pytest.raises(ValueError, match="passes must be a whole number from 1 to 10"):
            freeze(built, generation, tmp_path / f"bad-{passes}", "luna-high", passes=passes)
    reseal(out, {**read_json(out / "protocol.json"), "passes": 3})
    with pytest.raises(ValueError, match="incomplete 3-pass schedule"):
        verify_prepared_condition(out)


@pytest.mark.parametrize("change, message", [
    ({"passes": 11}, "passes must be a whole number from 1 to 10"),
    ({"passes": 2, "dispatch": {"execute": True, "cap_usd": "1", "passes": 3, "rates": {
        "luna-high": {"input": "1", "output": "1"}}}}, "may not exceed the 2 frozen passes"),
])
def test_the_runner_checks_passes_before_it_starts(tmp_path, change, message):
    from fmb.pipeline.runner import run_pipeline

    config = {"case_label": "I1-01", "generation": str(tmp_path), "analysis": str(tmp_path),
              "conditions": ["luna-high"], "output": str(tmp_path / "run")} | change
    with pytest.raises(ValueError, match=message):
        run_pipeline(config)
    assert not (tmp_path / "run").exists()


def openrouter_reply(payload):
    case = json.loads(payload["messages"][1]["content"])
    text = json.dumps({"supported_findings": gap_findings(case), "insufficient_findings": [],
                       "reasons": {fid: "r" for fid in target_catalog(case)}})
    selected = {"provider": "Example", "model": payload["model"], "selected": True}
    return {"id": "gen-1", "model": payload["model"], "provider": "Example",
            "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            "openrouter_metadata": {"requested": payload["model"], "strategy": "direct", "attempt": 1, "pipeline": [],
                                    "endpoints": {"available": [selected]}}}


@pytest.mark.parametrize("change, message", [
    (lambda c: c.update({"luna-high": c.pop("mine-t0")}), "one of the paper's conditions or another of yours"),
    (lambda c: c.update({"Luna-High": c.pop("mine-t0")}), "one of the paper's conditions or another of yours"),
    (lambda c: c.update({"rules": c.pop("mine-t0")}), "a condition name has"),
    (lambda c: c.update({"my condition": c.pop("mine-t0")}), "a condition name has"),
    (lambda c: c["mine-t0"].update(completion_policy={}), "a condition has settings"),
    (lambda c: c["mine-t0"]["settings"].update(base_url="https://example.test"), "settings may name only"),
    (lambda c: c["mine-t0"]["settings"].pop("timeout_seconds"), "settings need timeout_seconds"),
    (lambda c: c["mine-t0"]["settings"].update(provider="anthropic"), "provider is openai or openrouter"),
    (lambda c: c["mine-t0"]["settings"].update(model=" example/model-1"), "model is the provider's name"),
    (lambda c: c["mine-t0"]["settings"].update(reasoning_effort="extreme"), "reasoning_effort is one of"),
    (lambda c: c["mine-t0"]["settings"].update(max_output_tokens=True), "max_output_tokens is a whole number"),
    (lambda c: c["mine-t0"]["settings"].update(context_window_tokens=6144), "or no request fits"),
    (lambda c: c["mine-t0"]["settings"].pop("route"), "names its route"),
    (lambda c: c["mine-t0"]["settings"].update(provider="openai"), "an openai condition has no route"),
    (lambda c: c["mine-t0"]["settings"].update(temperature=2.5), "temperature is a number from 0 to 2"),
    (lambda c: c["mine-t0"]["settings"].update(temperature=None), "temperature is a number from 0 to 2"),
    (lambda c: c["mine-t0"]["settings"].update(top_p=True), "top_p is a number from 0 to 1"),
    (lambda c: c["mine-t0"]["settings"].update(seed=7.5), "seed is a 64-bit whole number"),
    (lambda c: c["mine-t0"]["settings"].update(structured_output="json_object"), "structured_output is json_schema"),
    (lambda c: c["mine-t0"]["settings"].update(price_usd_per_million={"input": "cheap", "output": "1"}),
     "price_usd_per_million is"),
    (lambda c: c["mine-t0"].update(upstream_provider=""), "upstream_provider is the provider name"),
    (lambda c: c["mine-t0"]["settings"].update(model="anthropic/claude-sonnet-5", route="anthropic"),
     "is served by Anthropic"),
    (lambda c: c.clear(), "declare conditions as a JSON object"),
])
def test_user_conditions_are_validated_strictly(change, message):
    conditions = deepcopy(OWN)
    change(conditions)
    with pytest.raises(ValueError, match=message):
        checked_conditions(conditions)


def test_a_valid_declaration_is_kept_exactly_and_may_not_change_within_a_run():
    openai = {"mine-openai": {"settings": {"provider": "openai", "model": "gpt-5.6-luna", "reasoning_effort": "medium",
                                           "max_output_tokens": 2048, "timeout_seconds": 60, "seed": 1}}}
    assert checked_conditions(OWN) == OWN and checked_conditions(openai) == openai
    with declare_conditions(OWN), declare_conditions(openai):
        with pytest.raises(ValueError, match="declared twice with different settings"):
            with declare_conditions({"mine-t0": {**OWN["mine-t0"], "upstream_provider": "Other"}}):
                pass


def test_a_user_condition_is_frozen_recorded_and_dispatched_with_its_sampling(tmp_path, fixed):
    prepared, built, generation = build(tmp_path, {"log": [100, 103]})
    out = tmp_path / "frozen" / "mine-t0"
    with pytest.raises(ValueError, match="unknown paper condition"):
        freeze(built, generation, out, "mine-t0")
    with declare_conditions(OWN):
        freeze(built, generation, out, "mine-t0")
    protocol = read_json(out / "protocol.json")
    assert protocol["settings"] == OWN["mine-t0"]["settings"] and protocol["user_condition"] == OWN["mine-t0"]
    kwargs = read_json(out / "requests" / "log.kwargs.json")
    body = read_json(out / "requests" / "log.json")
    assert {key: kwargs[key] for key in SAMPLING} == {key: body[key] for key in SAMPLING} == OWN_SAMPLING
    assert body["provider"]["only"] == ["example/fp8"] and body["model"] == "example/model-1"
    verify_prepared_condition(out)
    admit(prepared, built, [out])
    calls = []
    workflow.execute_condition(out, cap_usd="10", rates={"input": "0.5", "output": "1.5"},
                               provider=rotating("example/model-1", calls), sleep=lambda _: None)
    assert len(calls) == 3 and all({key: call[key] for key in SAMPLING} == OWN_SAMPLING for call in calls)
    started = read_json(out / "run/call-001/attempts/attempt-0001/started.json")["settings"]["sampling"]
    assert {key: started[key]["sent_value"] for key in SAMPLING} == OWN_SAMPLING
    assert (out / "run/call-001/attempts/attempt-0001/request-body.json").read_bytes() == (
        out / "requests" / "log.json").read_bytes()
    assert score_run(out)["passes"] == [1, 2, 3]
    g4 = stages.llm_gate(out, "I1-01", "0" * 64, {"run": tmp_path})
    assert g4["status"] == "executed" and g4["assessor"]["id"] == "mine-t0"
    assert g4["assessor"]["settings"] == OWN["mine-t0"]["settings"]


@pytest.mark.parametrize("change, message", [
    (lambda p: p["user_condition"]["settings"].update(temperature=1), "settings differ from the declared condition"),
    (lambda p: p.pop("user_condition"), "settings outside the fixed paper condition"),
    (lambda p: p.update(condition_id="luna-high"), "one of the paper's conditions"),
])
def test_a_frozen_user_condition_must_match_its_recorded_declaration(tmp_path, fixed, change, message):
    _, built, generation = build(tmp_path, {"log": [100, 103]})
    with declare_conditions(OWN):
        out = freeze(built, generation, tmp_path / "mine-t0", "mine-t0")
    protocol = read_json(out / "protocol.json")
    change(protocol)
    reseal(out, protocol)
    with pytest.raises(ValueError, match=message):
        verify_prepared_condition(out)


def test_the_provider_layer_sends_a_user_condition_only_as_declared(tmp_path, fixed, monkeypatch):
    from fmb.interpretation import provider

    prepared, built, generation = build(tmp_path, {"log": [100, 103]})
    with declare_conditions(OWN):
        out = freeze(built, generation, tmp_path / "mine-t0", "mine-t0")
    kwargs = read_json(out / "requests" / "log.kwargs.json")
    for declared, request in (({}, kwargs), (OWN, {**kwargs, "temperature": 1})):
        with declare_conditions(declared), pytest.raises(ConfigurationError, match="outside the paper protocol"):
            wire(request)
    admit(prepared, built, [out])
    monkeypatch.delenv("OPENROUTER_BASE_URL", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "offline-test-key")
    sent = []
    monkeypatch.setattr(provider, "post_json", lambda url, payload, timeout, *, headers=None: sent.append(
        payload) or openrouter_reply(payload))
    workflow.execute_condition(out, cap_usd="1", rates={"input": "0.5", "output": "1.5"}, execute=True,
                               sleep=lambda _: None)
    outcomes = read_json(out / "run/completion.json")["outcomes"]
    assert [outcome["status"] for outcome in outcomes] == ["completed"] * 3 and len(sent) == 3
    assert all(canonical_json(payload).encode() == (out / "requests/log.json").read_bytes() for payload in sent)
    assert read_json(out / "run/call-001/provider-response.json")["route"] == "example/fp8"
    assert score_run(out)["exact_question_passes"] == 3


def test_a_user_condition_with_two_passes_runs_through_the_pipeline(tmp_path, pipeline_inputs):
    from fmb.pipeline.gates import read_gate, verify_run
    from fmb.pipeline.runner import run_pipeline

    calls = []
    root = tmp_path / "run"
    config = {**pipeline_inputs, "output": str(tmp_path / "frozen"), "conditions": ["mine-t0"],
              "user_conditions": OWN, "passes": 2}
    assert run_pipeline(config)["admission"] == "passed"
    assert verify_run(tmp_path / "frozen")["status"] == "verified"
    dispatch = {"execute": True, "cap_usd": "1", "rates": {"mine-t0": {"input": "0.5", "output": "1.5"}}}
    result = run_pipeline({**config, "output": str(root), "dispatch": dispatch},
                          provider=rotating("example/model-1", calls))
    assert result["admission"] == "passed" and result["dispatched"]
    assert len(calls) == 2 and all({key: call[key] for key in SAMPLING} == OWN_SAMPLING for call in calls)
    manifest = read_json(root / "run-manifest.json")
    assert manifest["config"]["user_conditions"] == OWN and manifest["config"]["passes"] == 2
    protocol = read_json(root / "conditions/mine-t0/protocol.json")
    assert protocol["user_condition"] == OWN["mine-t0"] and protocol["passes"] == 2
    g4 = read_gate(root, manifest["gates"]["G4:mine-t0"])
    assert g4["assessor"]["settings"] == OWN["mine-t0"]["settings"]
    assert sorted(row["pass"] for row in g4["results"]) == [1, 2]
    g5 = read_gate(root, manifest["gates"]["G5"])
    assert g5["scores"]["mine-t0"]["passes"] == [1, 2]
    assert sorted(g5["comparison"]["conditions"]["mine-t0"]["passes"]) == ["1", "2"]
    assert verify_run(root)["status"] == "verified"
    moved = tmp_path / "moved"
    root.rename(moved)
    assert verify_run(moved)["status"] == "verified"
    outcome = moved / "conditions/mine-t0/run/call-001/outcome.json"
    outcome.write_text(outcome.read_text() + " ")
    with pytest.raises(ValueError, match="lineage/selected/0/outcome differs"):
        verify_run(moved)


@pytest.mark.parametrize("change, message", [
    ({"user_conditions": {"other": OWN["mine-t0"]}}, "declares conditions the run does not freeze: other"),
    ({"user_conditions": {"luna-high": OWN["mine-t0"]}}, "one of the paper's conditions"),
    ({"user_conditions": []}, "declare conditions as a JSON object"),
])
def test_the_runner_checks_user_conditions_before_it_starts(tmp_path, change, message):
    from fmb.pipeline.runner import run_pipeline

    config = {"case_label": "I1-01", "generation": str(tmp_path), "analysis": str(tmp_path),
              "conditions": ["luna-high"], "output": str(tmp_path / "run")} | change
    with pytest.raises(ValueError, match=message):
        run_pipeline(config)
    assert not (tmp_path / "run").exists()


def test_fmb_run_takes_a_conditions_file_and_passes_and_lists_them_in_its_help(tmp_path, monkeypatch, capsys):
    from fmb.cli.app import main
    from fmb.replication import run

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENROUTER_API_KEY", "test")
    monkeypatch.setenv("COLUMNS", "1000")
    (tmp_path / "conditions").mkdir()
    (tmp_path / "conditions/mine.json").write_text(json.dumps(OWN))
    analysed = []
    monkeypatch.setattr(run, "run_images", lambda names, llm, delete_image: analysed.append((names, llm)) or 0)
    assert main(["run", "small", "--conditions", "conditions/mine.json", "--llm", "mine-t0", "--cap-usd", "5",
                 "--passes", "2"]) == 0
    assert main(["run", "small", "--llm", "sonnet5-high", "--cap-usd", "5"]) == 0
    assert analysed == [
        (["small"], {"conditions": ["mine-t0"], "dispatch": {"execute": True, "cap_usd": "5.0", "rates": {
            "mine-t0": {"input": "0.5", "output": "1.5"}}}, "user_conditions": OWN, "passes": 2}),
        (["small"], {"conditions": ["sonnet5-high"], "dispatch": {"execute": True, "cap_usd": "5.0", "rates": {
            "sonnet5-high": {"input": "2.000", "output": "10.000"}}}})]
    for argv, listed in ((["run", "--conditions", "conditions/mine.json", "--help"],
                          "mistralsmall2603-high; yours: mine-t0"),
                         (["run", "--help"],
                          "mistralsmall2603-high; or one of yours, declared in a --conditions FILE")):
        with pytest.raises(SystemExit):
            main(argv)
        help_text = " ".join(capsys.readouterr().out.split())
        assert listed in help_text and "--passes N" in help_text


@pytest.mark.parametrize("conditions, own, prices, passes, message", [
    (["mine-t0"], None, [], None, "declare your own in a JSON file given with --conditions FILE"),
    ([], OWN, [], None, "--conditions and --passes go with --llm"),
    ([], None, [], 2, "--conditions and --passes go with --llm"),
    (["mine-t0"], OWN, [], 11, "--passes is how many times each LLM request is sent, from 1 to 10"),
    (["mine-t0"], {"mine-t0": {"settings": {key: value for key, value in OWN["mine-t0"]["settings"].items()
                                            if key != "price_usd_per_million"}}}, [], None,
     "mine-t0 has no recorded price; add --price mine-t0=INPUT,OUTPUT"),
    (["mine-openai"], {"mine-openai": {"settings": {"provider": "openai", "model": "m", "reasoning_effort": "low",
                                                    "max_output_tokens": 10, "timeout_seconds": 10}}},
     ["mine-openai=1,2"], None, "mine-openai calls openai: set OPENAI_API_KEY"),
])
def test_a_user_condition_keeps_the_price_cap_and_key_checks(conditions, own, prices, passes, message):
    from fmb.replication import image_files

    with pytest.raises(ValueError, match=message):
        image_files.llm_dispatch(conditions, 5, prices, {"OPENROUTER_API_KEY": "test"}, own=own, passes=passes)


def test_a_priced_user_condition_and_passes_reach_the_pipeline_config(tmp_path, monkeypatch):
    from fmb.pipeline.runner import _validated
    from fmb.replication import image_files, run

    unpriced = {"mine-t0": {"settings": {key: value for key, value in OWN["mine-t0"]["settings"].items()
                                         if key != "price_usd_per_million"}, "upstream_provider": "Example"}}
    llm = image_files.llm_dispatch(["mine-t0", "luna-high"], 5, ["mine-t0=1,2", "luna-high=1.25,10"],
                                   {"OPENROUTER_API_KEY": "test", "OPENAI_API_KEY": "test"}, own=unpriced, passes=2)
    assert llm["dispatch"]["rates"]["mine-t0"] == {"input": "1", "output": "2"}
    monkeypatch.setattr(run, "step", lambda name, **arguments: 0)
    monkeypatch.setattr(run.host, "toolchain_root", lambda: tmp_path / "toolchain")
    from fmb.generation import recipe

    (tmp_path / "recipe").mkdir()
    (tmp_path / "recipe/recipe.json").write_text(json.dumps({"config": recipe.paper_config("I1")}))
    run.analyse("small", tmp_path / "generation", tmp_path / "recipe", tmp_path, llm)
    config = json.loads((tmp_path / "pipeline.json").read_text())
    assert config["conditions"] == ["mine-t0", "luna-high"]
    assert config["user_conditions"] == unpriced and config["passes"] == 2
    assert _validated(config)["user_conditions"] == unpriced


def test_a_conditions_file_is_read_strictly(tmp_path):
    from fmb.replication import image_files

    path = tmp_path / "mine.json"
    with pytest.raises(ValueError, match="no such file"):
        image_files.read_conditions(path)
    path.write_text('{"mine-t0": {}, "mine-t0": {}}')
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        image_files.read_conditions(path)
    path.write_text(json.dumps({"luna-high": OWN["mine-t0"]}))
    with pytest.raises(ValueError, match="mine.json: luna-high: one of the paper's conditions"):
        image_files.read_conditions(path)
    path.write_text(json.dumps(OWN))
    assert image_files.read_conditions(path) == OWN
    assert dict(image_files.available_conditions(OWN))["mine-t0"] == (
        "yours: example/model-1 via openrouter, reasoning low, temperature 0, top_p 0.9, seed 7, "
        "$0.5 in / $1.5 out per million tokens")


def test_the_report_names_a_user_condition_and_its_sampling(tmp_path, monkeypatch):
    import fmb.pipeline.report
    from fmb.replication import report, run
    from test_run_report import finished_run

    monkeypatch.setattr(fmb.pipeline.report, "run_table", lambda run: "THE TABLE")
    output, generated, generation = finished_run(tmp_path)
    for path in (output / "run/gates/G5.json", output / "run/run-manifest.json"):
        path.write_text(path.read_text().replace("sonnet5-high", "mine-t0"))
    (output / "pipeline.json").write_text(json.dumps({"dispatch": {"cap_usd": "20"}, "user_conditions": OWN}))
    row = run.summary("small", output / "run/gates/G5.json") | {"paper_image": False, "generation": str(generation)}
    report.complete(output, row, generated, generation)
    assert ("- S3' `mine-t0` (your condition): example/model-1 via openrouter (example/fp8), reasoning low, "
            "temperature 0, top_p 0.9, seed 7, at most 4096 output tokens, 1 passes, $1.23 of a $20 cap.") in (
        output / "report.md").read_text()
