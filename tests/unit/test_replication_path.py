import csv
from pathlib import Path

import pytest

from fmb.core.sealed_records import write_json
from fmb.paper import workflow
from fmb.pipeline.gates import write_gate
from fmb.pipeline.report import write_report
from fmb.pipeline.runner import run_pipeline
from test_pipeline_gates import _analysis, _fake_stages, _generation


def _config(tmp_path, generation, **dispatch):
    return {"case_label": "I1-01", "generation": str(generation), "analysis": str(_analysis(tmp_path, generation)),
            "conditions": ["luna-high", "luna-max", "gemini38flash-high"], "output": str(tmp_path / "run"),
            "dispatch": {"execute": True, **dispatch}}


def test_each_condition_is_priced_and_all_share_one_cap(tmp_path, monkeypatch):
    from fmb.evaluation import scoring

    generation = _generation(tmp_path / "generation")
    _fake_stages(monkeypatch, generation.resolve())
    calls = []

    def execute_condition(run, *, cap_usd, rates, **_):
        calls.append((run.name, cap_usd, rates))
        return {"conservative_exposure_usd": "0.6"}

    monkeypatch.setattr(workflow, "execute_condition", execute_condition)
    monkeypatch.setattr(scoring, "score_run", lambda run: {"passes": [1]})
    rates = {"luna-high": {"input": "1.25", "output": "10"}, "luna-max": {"input": "1.25", "output": "10"},
             "gemini38flash-high": {"input": "0.3", "output": "2.5"}}
    run_pipeline(_config(tmp_path, generation, cap_usd="1.0", rates=rates))
    assert calls == [("luna-high", "1.0", rates["luna-high"]), ("luna-max", "0.4", rates["luna-max"])]
    from fmb.core.sealed_records import read_json

    detail = next(s["detail"] for s in read_json(tmp_path / "run" / "run-manifest.json")["stages"]
                  if s.get("detail", {}).get("dispatched") is not None)
    assert detail["not_dispatched_for_budget"] == ["gemini38flash-high"]
    assert detail["exposure_usd"] == {"luna-high": "0.6", "luna-max": "0.6"}


def test_every_dispatched_condition_needs_a_price(tmp_path):
    generation = _generation(tmp_path / "generation")
    config = _config(tmp_path, generation, cap_usd="1", rates={"luna-high": {"input": "1", "output": "1"}})
    with pytest.raises(ValueError, match="rates for: luna-max, gemini38flash-high"):
        run_pipeline(config)
    config["dispatch"]["rates"]["claude-unknown"] = {"input": "1", "output": "1"}
    with pytest.raises(ValueError, match="frozen conditions only"):
        run_pipeline(config)


def _g5(run: Path, case_label: str, scores: dict, admission: str = "passed", rules: dict | None = None) -> None:
    rules = rules or {"per_question": {"BQ-TIME-01": {"exact": admission == "passed"}, "BQ-LOG-01": {"exact": True}},
                      "f1": 1.0, "finding_counts": {"tp": 4, "fn": 0, "fp": 0, "tn": 6}, "findings": 10}
    policy = "strict" if admission == "passed" else "report-only"
    entry = write_gate(run, "G5", {"gate": "G5", "schema_version": "fmb.pipeline.g5.v1", "case_label": case_label,
                                   "admission": {"status": admission, "policy": policy, "certificates": []},
                                   "scores": scores, "comparison": {"rules": rules, "conditions": {}}})
    write_json(run / "run-manifest.json", {"gates": {"G5": entry}})


def test_the_report_builds_table_3_and_figure_2_from_the_runs(tmp_path):
    score = {"passes": [1, 2, 3], "every_pass": 1, "f1": 0.95, "finding_counts": {"fn": 2, "fp": 1},
             "per_question": {"BQ-TIME-01": {"exact_passes": [1, 2, 3]}, "BQ-LOG-01": {"exact_passes": [3]}},
             "selected_exposure_usd": "0.75", "selected_request_seconds_sum": "30"}
    _g5(tmp_path / "i1", "I1-07", {"luna-high": score})
    _g5(tmp_path / "i2", "I2-07", {})
    _g5(tmp_path / "i3", "I3-07", {"luna-high": score}, admission="failed")
    write_report(runs=[tmp_path / "i1", tmp_path / "i2", tmp_path / "i3"], output=tmp_path / "report")
    rows = list(csv.DictReader((tmp_path / "report" / "table-results.csv").open()))
    assert [(r["image"], r["condition"], r["admission"]) for r in rows] == [
        ("I1", "rules", "passed"), ("I1", "luna-high", "passed"), ("I2", "rules", "passed"),
        ("I3", "rules", "failed"), ("I3", "luna-high", "failed")]
    assert rows[1] == {"image": "I1", "condition": "luna-high", "exact": "1/2", "f1_percent": "95.0", "fn": "2",
                       "fp": "1", "cost_per_pass_usd": "0.25", "summed_request_seconds_per_pass": "10.000",
                       "BQ-TIME-01": "0", "BQ-LOG-01": "2", "admission": "passed",
                       "selection_policy": "not_recorded", "lineage_status": "not_recorded"}
    assert rows[3]["exact"] == "1/2" and rows[3]["BQ-TIME-01"] == "1"
    figure = list(csv.DictReader((tmp_path / "report" / "figure-f1-cost.csv").open()))
    assert figure == [
        {"image": "I1", "condition": "luna-high", "cost_per_pass_usd": "0.250", "f1_percent": "95.0",
         "admission": "passed"},
        {"image": "I3", "condition": "luna-high", "cost_per_pass_usd": "0.250", "f1_percent": "95.0",
         "admission": "failed"}]
    text = (tmp_path / "report" / "results.md").read_text()
    assert "Admission passed (strict)." in text
    assert "Admission failed (report-only). The rule-based answers did not match" in text
    with pytest.raises(FileExistsError):
        write_report(runs=[tmp_path / "i1"], output=tmp_path / "report")


def test_the_report_shows_an_f1_without_positive_or_false_positive_findings_as_missing(tmp_path):
    failed = {"passes": [1, 2, 3], "every_pass": 0, "f1": None, "finding_counts": {"fn": 0, "fp": 0},
              "per_question": {}, "selected_exposure_usd": "0.9", "selected_request_seconds_sum": "0"}
    _g5(tmp_path / "i1", "I1-07", {"luna-high": failed})
    _g5(tmp_path / "i2", "I2-07", {}, rules={
        "per_question": {"BQ-TIME-01": {"exact": True}, "BQ-LOG-01": {"exact": True}}, "f1": None,
        "finding_counts": {"tp": 0, "fn": 0, "fp": 0, "tn": 10}, "findings": 10})
    write_report(runs=[tmp_path / "i1", tmp_path / "i2"], output=tmp_path / "report")
    rows = list(csv.DictReader((tmp_path / "report" / "table-results.csv").open()))
    assert [(r["image"], r["condition"], r["f1_percent"]) for r in rows] == [
        ("I1", "rules", "100.0"), ("I1", "luna-high", ""), ("I2", "rules", "")]
    figure = list(csv.DictReader((tmp_path / "report" / "figure-f1-cost.csv").open()))
    assert [(r["condition"], r["f1_percent"]) for r in figure] == [("luna-high", "")]
    text = (tmp_path / "report" / "results.md").read_text()
    assert "| luna-high | 0/2 | – | 0 | 0 |" in text
    assert "| Rule-based baseline | 2/2 | – | 0 | 0 |" in text


