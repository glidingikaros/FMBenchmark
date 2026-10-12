import json
import shutil
from decimal import Decimal
from pathlib import Path

import pytest

from fmb.assessment import llm
from fmb.core.errors import ExternalToolError
from fmb.core.sealed_records import read_json
from fmb.interpretation import provider as provider_module
from fmb.interpretation.provider import LLMResponse
from fmb.paper import workflow as execution
from fmb.replication import host, image_files, run
from test_paper_execution import admit, answer, frozen as frozen  # noqa: F401  (fixture)
from test_stage_substitution import pipeline_inputs as pipeline_inputs  # noqa: F401  (fixture)


def dispatch(out, provider=None, **options):
    sleeps = []
    result = execution.execute_condition(out, cap_usd=options.get("cap", "10"),
                                         rates=options.get("rates", {"input": "1", "output": "1"}),
                                         execute=True, provider=provider, sleep=sleeps.append)
    return result, read_json(out / "run/completion.json")["outcomes"], sleeps


def test_a_base_url_in_the_shell_fails_the_llm_preflight_as_it_would_fail_every_call(monkeypatch):
    environ = {"OPENAI_API_KEY": "key", "OPENAI_BASE_URL": "https://llm-gateway.example.com/v1"}
    with pytest.raises(ValueError, match=r"luna-high calls openai: custom OpenAI-compatible base URLs require "
                                         r"OPENAI_ALLOW_CUSTOM_BASE_URL=1 \(OPENAI_BASE_URL is "
                                         r"https://llm-gateway\.example\.com/v1; unset it to call api\.openai\.com\)"):
        image_files.llm_dispatch(["luna-high"], 5.0, ["luna-high=1,1"], environ)
    allowed = {**environ, "OPENAI_ALLOW_CUSTOM_BASE_URL": "1", "OPENAI_COMPAT_API_KEY": "gateway key"}
    assert image_files.llm_dispatch(["luna-high"], 5.0, ["luna-high=1,1"], allowed)["conditions"] == ["luna-high"]
    official = {"OPENAI_API_KEY": "key", "OPENAI_BASE_URL": "https://api.openai.com/v1/"}
    assert image_files.llm_dispatch(["luna-high"], 5.0, ["luna-high=1,1"], official)["conditions"] == ["luna-high"]


def test_a_configuration_error_stops_the_condition_after_its_first_call(frozen, monkeypatch):  # noqa: F811
    admit(frozen)
    monkeypatch.setenv("OPENAI_API_KEY", "key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://llm-gateway.example.com/v1")
    monkeypatch.setattr(provider_module, "_open_provider_request", lambda *_: pytest.fail("sent"))
    _, outcomes, _ = dispatch(frozen[2])
    assert [(row["attempts"], row["error"]["type"]) for row in outcomes] == [
        (1, "ConfigurationError"), (0, "configuration_stop"), (0, "configuration_stop")]
    assert "OPENAI_ALLOW_CUSTOM_BASE_URL" in outcomes[1]["error"]["message"]



LLM = {"conditions": ["luna-high"],
       "dispatch": {"execute": True, "cap_usd": "5", "rates": {"luna-high": {"input": "1", "output": "1"}}}}


def valid(**kwargs):
    case = json.loads(kwargs["prompt"])
    reasons = {target["finding_id"]: "r" for card in case["candidate_roster"] for target in card["assessment_targets"]}
    text = json.dumps({"supported_findings": [], "insufficient_findings": [], "reasons": reasons})
    return LLMResponse(kwargs["provider"], kwargs["model"], text, {}, usage={"input_tokens": 100, "output_tokens": 20})


def unauthorised(**kwargs):
    raise ExternalToolError("LLM provider HTTP 401 from https://api.openai.com/v1/responses: invalid key",
                            details={"http_status": 401, "provider_failure_stage": "http", "retryable": False})


@pytest.fixture
def wrapped(tmp_path, monkeypatch, pipeline_inputs):  # noqa: F811
    """fmb run around the in-process pipeline: one generated image, I1, whose analyse step runs run_pipeline."""
    from fmb.pipeline.runner import run_pipeline

    root = tmp_path / "generated"
    shutil.copytree(pipeline_inputs["generation"], root / "I1" / "generation" / "attempt-1" / "full_scale" / "a")
    (root / "I1" / "recipe").mkdir()
    (root / "I1" / "recipe" / "recipe.json").write_text(json.dumps({"config": {}}))
    calls = {"provider": valid}

    def step(name, *, log_path, label=None, **arguments):
        config = json.loads(Path(arguments["config"]).read_text())
        with log_path.open("w") as stream:
            try:
                result = run_pipeline({**pipeline_inputs, "output": config["output"],
                                       **({"dispatch": config["dispatch"]} if "dispatch" in config else {})},
                                      provider=calls["provider"])
            except Exception as error:
                stream.write(f"fmb: {error}\n")
                return 2
        return 0 if result["status"] == "completed" else 1

    monkeypatch.setattr(run, "step", step)
    monkeypatch.setattr(run, "implementation", lambda paper: {})
    monkeypatch.setattr(host, "windows_base", lambda: None)
    return root, tmp_path / "results", calls


def test_an_image_whose_s3prime_calls_all_failed_is_kept_and_the_run_says_why(wrapped, capsys):
    root, results, calls = wrapped
    calls["provider"] = unauthorised
    assert run.run_images(["I1"], LLM, root, results, delete_image=True) == 1
    assert run.completed(root / "I1" / "generation") is not None
    out, err = capsys.readouterr()
    assert "S3'  luna-high              0/1 questions exact per pass (3 passes)" in out
    assert "answered 0 of 3 calls" in out
    assert ("not answered: 2 not sent, 1 failed; first error: ExternalToolError: LLM provider HTTP 401 from "
            "https://api.openai.com/v1/responses: invalid key") in out
    assert "I1: kept the generated image" in out and "as S3' luna-high answered 0 of 3 calls" in out
    assert err.splitlines()[-1] == "fmb: 1 of 1 images passed admission (I1); I1: S3' luna-high answered 0 of 3 calls"
    output = next(results.glob("I1/*"))
    assert "answered 0 of 3 calls" in (output / "report.md").read_text()


def test_an_image_whose_s3prime_calls_were_all_answered_is_deleted(wrapped, capsys):
    root, results, _ = wrapped
    assert run.run_images(["I1"], LLM, root, results, delete_image=True) == 0
    assert not (root / "I1").exists()
    out = capsys.readouterr().out
    assert "answered 3 of 3 calls" in out and "not answered" not in out
    assert out.splitlines()[-1] == "[fmb] 1 of 1 images passed admission (I1)"


def test_a_run_that_fails_after_g5_is_written_is_not_a_pass(wrapped, monkeypatch, capsys):
    from fmb.pipeline import reads

    root, results, _ = wrapped
    original = reads.undeclared
    monkeypatch.setattr(reads, "undeclared",
                        lambda step, read: original(step, read) + (["analysis:x"] if step == "S4:evaluation" else []))
    assert run.run_images(["I1"], None, root, results, delete_image=True) == 1
    assert run.completed(root / "I1" / "generation") is not None
    out, err = capsys.readouterr()
    assert ("I1: admission passed, but then the pipeline stopped at S4:evaluation (S4:evaluation read files its gates "
            "do not declare: analysis:x); the run is incomplete, see pipeline.log") in out
    assert "I1: kept the generated image" in out
    assert err.splitlines()[-1] == "fmb: 0 of 1 images passed admission; I1: the pipeline stopped at S4:evaluation"


def test_the_report_after_a_crash_names_the_cause_and_what_s3prime_did(wrapped, monkeypatch, capsys):
    from fmb.paper import workflow

    root, results, _ = wrapped

    def crash(**_):
        raise RuntimeError("parser VM did not come up")

    monkeypatch.setattr(workflow, "prepare_native", crash)
    assert run.run_images(["I1"], LLM, root, results, delete_image=True) == 1
    out = capsys.readouterr().out
    assert ("I1: admission not reached: the pipeline stopped at S2 (parser VM did not come up); see pipeline.log"
            in out)
    assert "  S3'  luna-high              not sent" in out and "add --llm" not in out
    text = next(results.glob("I1/*/report.md")).read_text()
    assert "- S3': not sent." in text and "frozen under" not in text


def test_the_spend_of_a_dispatch_that_crashed_is_reported(wrapped, monkeypatch, capsys):
    root, results, calls = wrapped
    sent = []

    original = llm._validate_answer

    def full_disk(*args, **kwargs):
        sent.append(1)
        if len(sent) == 2:
            raise OSError(28, "No space left on device")
        return original(*args, **kwargs)

    monkeypatch.setattr(llm, "_validate_answer", full_disk)
    assert run.run_images(["I1"], LLM, root, results, delete_image=True) == 1
    out = capsys.readouterr().out
    assert "  S3'  luna-high              not scored; $" in out and "spent before the pipeline stopped" in out


def test_an_image_that_cannot_be_deleted_whole_no_longer_counts_as_generated(wrapped, monkeypatch, capsys):
    root, results, _ = wrapped

    def locked(folder, *args, **kwargs):
        raise PermissionError(13, "in use by another process", str(folder / "generation"))

    monkeypatch.setattr(run.shutil, "rmtree", locked)
    assert run.run_images(["I1"], None, root, results, delete_image=True) == 0
    assert run.completed(root / "I1" / "generation") is None
    assert f"delete {root / 'I1'} by hand" in capsys.readouterr().err
