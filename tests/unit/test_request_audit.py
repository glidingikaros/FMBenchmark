import pytest

from fmb.interpretation.request_audit import settings_record, AuditedProviderCall


def test_omitted_temperature_never_becomes_an_invented_default():
    value = settings_record({"model": "test", "provider": "openrouter", "temperature": None}, {})
    assert value["sampling"]["temperature"] == {
        "configured": None, "request_state": "omitted", "sent_value": None,
        "provider_reported_value": None, "provider_value_available": False,
        "unreported_default": "unknown",
    }


def test_provider_echo_is_recorded_separately_from_omission():
    value = settings_record({"model": "test", "provider": "openai", "temperature": None}, {}, {"temperature": 1.0, "top_p": .98})
    assert value["sampling"]["temperature"]["request_state"] == "omitted"
    assert value["sampling"]["temperature"]["provider_reported_value"] == 1.0
    assert value["sampling"]["top_p"]["provider_reported_value"] == .98


def test_silently_discarding_an_explicit_temperature_is_an_error():
    with pytest.raises(ValueError, match="serialized"):
        settings_record({"model": "test", "provider": "openai", "temperature": 0}, {})


def test_failure_keeps_wire_body_and_clock_without_retry(tmp_path):
    import json
    calls = []
    def fail(**kwargs):
        calls.append(kwargs)
        raise RuntimeError("synthetic transport failure")
    invoke = AuditedProviderCall(tmp_path / "attempts", fail)
    from fmb.core.paths import PROJECT_ROOT
    from fmb.core.paper_contract import response_schema
    from fmb.paper.replay import example_root
    if not example_root().is_dir():
        pytest.skip("the study's I1 records are kept out of the public repository")
    case = json.loads(next((example_root()/"cases").glob("*.json")).read_text())
    kwargs = {**json.loads((PROJECT_ROOT/"contracts/paper/protocol.json").read_text())["conditions"]["luna-high"]["settings"], "temperature":None,"json_mode":True,"prompt":"{}", "system_prompt":"Assess the evidence.",
              "structured_output":"json_schema", "response_schema": response_schema(case)}
    with pytest.raises(RuntimeError, match="transport"):
        invoke(**kwargs)
    assert len(calls) == 1
    folder = tmp_path / "attempts/attempt-0001"
    assert (folder / "request-body.json").is_file()
    result = json.loads((folder / "finished.json").read_text())
    assert result["status"] == "failed" and result["started_utc"] <= result["finished_utc"]
    assert result["elapsed_seconds"] >= 0
