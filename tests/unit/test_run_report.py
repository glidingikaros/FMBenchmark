import json
from pathlib import Path

from fmb.core.hashing import sha256_file
from fmb.replication import report, run

ROOT = Path(__file__).resolve().parents[2]


def finished_run(tmp_path: Path) -> tuple[Path, Path, Path]:
    output, generated = tmp_path / "results/small/20261009-120000", tmp_path / "generated/small"
    generation = generated / "generation/attempt-1/full_scale/a"
    (output / "run/gates").mkdir(parents=True)
    (generated / "recipe").mkdir(parents=True)
    generation.mkdir(parents=True)
    for name in ("ground_truth.json", "finding_reference.json", "manifest.json", "factual-challenge-receipt.json"):
        (generation / name).write_text("{}")
    (generated / "recipe/recipe.json").write_text('{"recipe_id": "recipe:1"}')
    (generated / "image.json").write_text((ROOT / "images/decoys.json").read_text())
    g5 = {"admission": {"status": "passed"}, "findings": [
        {"question_id": "BQ-TIME-01", "reference": "supported"},
        {"question_id": "BQ-TIME-01", "reference": "not_supported"}], "comparison": {
        "rules": {"f1": 1.0, "finding_counts": {"tp": 1, "fp": 0, "fn": 0, "tn": 1},
                  "per_question": {"BQ-TIME-01": {"exact": True}}},
        "conditions": {"sonnet5-high": {
            "passes": {"1": {"per_question": {"BQ-TIME-01": {"exact": False, "missed": ["f1"]}}}},
            "spread": {"exact_min": 0, "exact_max": 0, "f1_min": None, "f1_max": None}}}}}
    (output / "run/gates/G5.json").write_text(json.dumps(g5))
    (output / "run/run-manifest.json").write_text(json.dumps({
        "gates": {"G5": {"path": "gates/G5.json", "sha256": sha256_file(output / "run/gates/G5.json")}},
        "implementations": {"S3": {"engine": "rules", "module": "fmb.assessment.rules"}},
        "code": {"source_manifest_sha256": "c0de"},
        "stages": [{"step": "S3':dispatch", "detail": {"exposure_usd": {"sonnet5-high": "1.23"}}}]}))
    (output / "pipeline.json").write_text('{"dispatch": {"cap_usd": "20"}}')
    return output, generated, generation


def test_a_finished_run_gets_its_receipts_a_summary_and_a_readable_report(tmp_path, monkeypatch):
    import fmb.pipeline.report

    monkeypatch.setattr(fmb.pipeline.report, "run_table", lambda run: "THE PAPER'S TABLE")
    output, generated, generation = finished_run(tmp_path)
    row = run.summary("small", output / "run/gates/G5.json") | {"paper_image": False, "implementation": "released",
                                                              "changed_files": [], "generation": str(generation)}
    report.complete(output, row, generated, generation)
    assert sorted(path.name for path in (output / "receipts").iterdir()) == [
        "factual-challenge-receipt.json", "finding_reference.json", "ground_truth.json", "image.json",
        "manifest.json", "recipe.json"]
    assert json.loads((output / "summary.json").read_text())["llm"]["sonnet5-high"]["cost_usd"] == "1.23"
    text = (output / "report.md").read_text()
    for expected in ("# small: S3 and S3' against ground truth", "THE PAPER'S TABLE",
                     "| BQ-TIME-01 | 2 | 1 | exact | 1 missed |", "77 objects, 18 manipulated",
                     "sonnet5-high`: anthropic/claude-sonnet-5 via openrouter", "$1.23 of a $20 cap",
                     "| Ground truth | `receipts/ground_truth.json` |", "| G5 Evaluation report | `run/gates/G5.json` |"):
        assert expected in text
    lines = report.headline(row, output)
    assert lines[0].startswith("small: admission passed")
    assert "9/9" not in lines[1] and "1/1 questions exact   F1 1.000   TP 1 FP 0 FN 0 TN 1" in lines[1]
    assert "sonnet5-high" in lines[2] and "0/1 questions exact over 1 passes   F1 –   $1.23" in lines[2]
    assert lines[-1] == f"  report: {output / 'report.md'}"


def test_a_run_that_stopped_still_reports_where_to_look(tmp_path):
    lines = report.headline({"image": "small", "admission": "not reached"}, tmp_path)
    assert "see pipeline.log" in lines[0] and lines[-1].endswith("report.md")
