import _thread
import email.message
import io
import json
import os
import shutil
import subprocess
import threading
import time
import urllib.error
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
    manifest = json.loads(next(results.glob("I1/*/run/run-manifest.json")).read_text())
    dispatched = next(stage for stage in manifest["stages"] if stage["step"] == "S3':dispatch")
    assert Decimal(dispatched["detail"]["exposure_usd"]["luna-high"]) > 0
    assert "  S3'  luna-high              not scored; $" in out and "spent before the pipeline stopped" in out


def test_an_image_that_cannot_be_deleted_whole_no_longer_counts_as_generated(wrapped, monkeypatch, capsys):
    root, results, _ = wrapped

    def locked(folder, *args, **kwargs):
        raise PermissionError(13, "in use by another process", str(folder / "generation"))

    monkeypatch.setattr(run.shutil, "rmtree", locked)
    assert run.run_images(["I1"], None, root, results, delete_image=True) == 0
    assert run.completed(root / "I1" / "generation") is None
    assert f"delete {root / 'I1'} by hand" in capsys.readouterr().err


class Returned(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def rate_limited(retry_after):
    def opener(request, timeout):
        message = email.message.Message()
        message["Retry-After"] = retry_after
        raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", message,
                                     io.BytesIO(b'{"error": {"message": "Rate limit reached for requests"}}'))
    return opener


@pytest.mark.parametrize("retry_after, waits", [("30", [30, 30]), ("3600", [120, 120]), ("1", [2, 5])])
def test_a_rate_limited_call_waits_as_long_as_the_provider_asks_up_to_a_limit(frozen, monkeypatch, retry_after,  # noqa: F811
                                                                               waits):
    admit(frozen)
    monkeypatch.setenv("OPENAI_API_KEY", "key")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr(provider_module, "_open_provider_request", rate_limited(retry_after))
    _, outcomes, sleeps = dispatch(frozen[2])
    assert sleeps == waits * 3 and all(row["attempts"] == 3 for row in outcomes)
    policy = read_json(frozen[2] / "run/schedule.json")["execution_policy"]
    assert policy["backoff_seconds"] == [2, 5] and policy["retry_after_max_seconds"] == 120


def test_the_cap_counts_the_cost_the_provider_reports_when_it_is_more(frozen):  # noqa: F811
    admit(frozen)

    def costly(**kwargs):
        response = answer(**kwargs)
        return LLMResponse(response.provider, response.model, response.text, {},
                           usage={"input_tokens": 100, "output_tokens": 20, "cost_usd": 2.5})

    result, outcomes, _ = dispatch(frozen[2], costly, cap="4")
    assert [row["status"] for row in outcomes] == ["completed", "completed", "execution_failure"]
    assert outcomes[2]["error"]["type"] == "budget_exhausted"
    assert [Decimal(row["conservative_exposure_usd"]) for row in outcomes[:2]] == [Decimal("2.5")] * 2
    assert Decimal(result["conservative_exposure_usd"]) == 5


def test_a_served_model_other_than_the_requested_one_stops_the_condition(frozen, monkeypatch):  # noqa: F811
    admit(frozen)
    monkeypatch.setenv("OPENAI_API_KEY", "key")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    sent = []

    def snapshot(request, timeout):
        payload = json.loads(request.data)
        sent.append(payload["model"])
        reasons = {target["finding_id"]: "r" for card in json.loads(payload["input"])["candidate_roster"]
                   for target in card["assessment_targets"]}
        return Returned(json.dumps({
            "id": "resp_1", "status": "completed", "model": payload["model"] + "-2026-05-14",
            "output_text": json.dumps({"supported_findings": [], "insufficient_findings": [], "reasons": reasons}),
            "usage": {"input_tokens": 1000, "output_tokens": 20}}).encode())

    monkeypatch.setattr(provider_module, "_open_provider_request", snapshot)
    _, outcomes, _ = dispatch(frozen[2])
    assert sent == ["gpt-5.6-luna"]
    assert [(row["attempts"], row["error"]["type"]) for row in outcomes] == [
        (1, "ExternalToolError"), (0, "response_mismatch_stop"), (0, "response_mismatch_stop")]
    assert outcomes[1]["error"]["message"] == ("openai response model gpt-5.6-luna-2026-05-14 does not match the "
                                               "requested model gpt-5.6-luna")


def test_ctrl_c_reaches_fmb_while_a_provider_call_waits_for_its_answer(monkeypatch):
    released = threading.Event()

    def hanging(request, timeout):
        released.wait(20)
        return Returned(b"{}")

    monkeypatch.setattr(provider_module, "_open_provider_request", hanging)
    monkeypatch.setattr(provider_module, "THREADED", True)
    timer = threading.Timer(0.2, _thread.interrupt_main)
    started = time.monotonic()
    timer.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            provider_module.post_json("https://api.openai.com/v1/responses", {}, 1800,
                                      headers={"Authorization": "Bearer key"})
        assert time.monotonic() - started < 10
    finally:
        released.set()
        timer.cancel()


def fake_inhibitor(folder: Path, body: str) -> Path:
    tool = folder / "bin" / "systemd-inhibit"
    tool.parent.mkdir()
    tool.write_text(f"#!/bin/sh\n{body}\n")
    tool.chmod(0o755)
    return tool


@pytest.mark.skipif(not hasattr(os, "fork"), reason="a shell-script stand-in for systemd-inhibit")
def test_linux_holds_a_sleep_inhibitor_until_fmb_is_done(tmp_path, monkeypatch):
    from fmb.replication import awake

    record = tmp_path / "inhibitor.txt"
    tool = fake_inhibitor(tmp_path, f'echo "$@" > {record}; exec cat')
    started, popen = [], subprocess.Popen
    monkeypatch.setattr(host, "WINDOWS", False)
    monkeypatch.setattr(host, "MACOS", False)
    monkeypatch.setattr(awake.shutil, "which", lambda name: str(tool) if name == "systemd-inhibit" else None)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **options: started.append(popen(*args, **options))
                        or started[-1])
    with awake.kept_awake():
        deadline = time.monotonic() + 10
        while not record.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert record.read_text().split() == ["--what=sleep:idle", "--who=fmb", "--why=generating", "or",
                                              "analysing", "a", "disk", "image", "--mode=block", "cat"]
        assert started[0].poll() is None
    assert started[0].poll() is not None


def test_no_inhibitor_or_a_failing_one_never_stops_fmb(tmp_path, monkeypatch):
    from fmb.replication import awake

    monkeypatch.setattr(host, "WINDOWS", False)
    monkeypatch.setattr(host, "MACOS", False)
    monkeypatch.setattr(awake.shutil, "which", lambda name: None)
    with awake.kept_awake():
        pass
    monkeypatch.setattr(awake.shutil, "which", lambda name: str(tmp_path / "missing"))
    with awake.kept_awake():
        pass
    if hasattr(os, "fork"):
        tool = fake_inhibitor(tmp_path, "echo 'Failed to inhibit: no logind' >&2; exit 1")
        monkeypatch.setattr(awake.shutil, "which", lambda name: str(tool))
        with awake.kept_awake():
            pass


def test_macos_and_windows_take_their_own_sleep_assertions(monkeypatch):
    from types import SimpleNamespace

    from fmb.replication import awake

    started = []

    class Process:
        def __init__(self, command, **options):
            started.append(command)
            self.stdin, self.ended = io.BytesIO(), False

        def terminate(self):
            self.ended = True

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(host, "WINDOWS", False)
    monkeypatch.setattr(host, "MACOS", True)
    monkeypatch.setattr(awake.subprocess, "Popen", Process)
    with awake.kept_awake():
        assert started == [["/usr/bin/caffeinate", "-i", "-w", str(os.getpid())]]
    states = []
    kernel = SimpleNamespace(SetThreadExecutionState=lambda state: states.append(state.value) or 1)
    monkeypatch.setattr(host, "WINDOWS", True)
    monkeypatch.setattr(awake.ctypes, "windll", SimpleNamespace(kernel32=kernel), raising=False)
    with awake.kept_awake():
        assert states == [0x80000001]
    assert states == [0x80000001, 0x80000000]


def test_fmb_generate_and_fmb_run_keep_the_computer_awake(monkeypatch):
    from contextlib import contextmanager

    from fmb.cli.app import main
    from fmb.replication import awake

    held = []

    @contextmanager
    def kept_awake():
        held.append("taken")
        yield
        held.append("released")

    monkeypatch.setattr(awake, "kept_awake", kept_awake)
    monkeypatch.setattr(run, "generate_images", lambda *_, **__: held.append("generate") or 0)
    monkeypatch.setattr(run, "run_images", lambda *_, **__: held.append("run") or 0)
    assert main(["generate", "I1"]) == 0 and main(["run", "I1"]) == 0
    assert held == ["taken", "generate", "released", "taken", "run", "released"]


def test_a_generation_that_failed_after_the_computer_slept_says_so(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from fmb.replication import awake

    clocks = iter([(1000.0, 500.0), (4000.0, 1300.0), (1000.0, 500.0), (1003.0, 503.0)])
    monkeypatch.setattr(awake, "_clocks", lambda: next(clocks))
    monkeypatch.setattr(run, "disk_space", lambda name, root: None)

    def failed(*_):
        raise SystemExit("I1: generation failed at 'user activity and manipulations in the guest': clock offset")

    monkeypatch.setattr(run, "generate_image", failed)
    image = SimpleNamespace(name="I1", paper=True, path=tmp_path / "I1.json")
    image.path.write_text("{}")
    (tmp_path / "generated").mkdir()
    with pytest.raises(SystemExit) as error:
        run.generate_one(image, tmp_path / "lock.json", tmp_path / "generated", attempts=3)
    assert str(error.value) == (
        "I1: generation failed at 'user activity and manipulations in the guest': clock offset. The computer slept, "
        "or its clock was set, for about 36m40s during the generation, which needs the guest's clock within 2 s of "
        "the host's: keep the computer awake, on power and with its lid open while fmb generates")
    with pytest.raises(SystemExit, match=r"clock offset$"):
        run.generate_one(image, tmp_path / "lock.json", tmp_path / "generated", attempts=3)
