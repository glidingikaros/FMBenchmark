from __future__ import annotations

import csv
from decimal import Decimal
from pathlib import Path

from fmb.core.case_contract import QIDS
from fmb.core.sealed_records import parse_json, write_json
from fmb.evaluation.lineage import report_labels
from fmb.pipeline import sealed
from fmb.pipeline.gates import RUN_MANIFEST, read_gate

SCHEMA = "fmb.pipeline.report.v1"


def _decimal(value, places: int) -> str:
    from fmb.evaluation.report import decimal_text

    return decimal_text(Decimal(str(value)), places)


def _f1_percent(f1) -> str:
    return "" if f1 is None else _decimal(Decimal(str(f1)) * 100, 1)


def read_g5(run: Path) -> tuple[dict, dict]:
    run = Path(run)
    for name in (RUN_MANIFEST, sealed.MANIFEST):
        if (run / name).is_file():
            entry = parse_json((run / name).read_text())["gates"]["G5"]
            return read_gate(run, entry), entry
    raise ValueError("no run or evaluation manifest in " + str(run))


def _image(case_label: str) -> str:
    return case_label.split("-", 1)[0]


def _rows(g5: dict) -> list[dict]:
    image = _image(g5["case_label"])
    rules = g5["comparison"]["rules"]
    questions = [q for q in QIDS if q in rules["per_question"]]
    rows = [{
        "image": image, "condition": g5.get("experiment", {}).get("s3_assessor", "rules"),
        "exact": f"{sum(entry['exact'] for entry in rules['per_question'].values())}/{len(questions)}",
        "f1_percent": _f1_percent(rules["f1"]),
        "fn": rules["finding_counts"]["fn"], "fp": rules["finding_counts"]["fp"],
        "cost_per_pass_usd": "", "summed_request_seconds_per_pass": "",
        **{q: 0 if rules["per_question"][q]["exact"] else 1 for q in questions},
    }]
    for condition, score in g5["scores"].items():
        passes = len(score.get("passes") or [1, 2, 3])
        exact = score.get("per_question", {})
        seconds = score.get("selected_request_seconds_sum")
        rows.append({
            "image": image, "condition": condition,
            "exact": f"{score['every_pass']}/{len(questions)}",
            "f1_percent": _f1_percent(score["f1"]),
            "fn": score["finding_counts"]["fn"], "fp": score["finding_counts"]["fp"],
            "cost_per_pass_usd": _decimal(Decimal(score["selected_exposure_usd"]) / passes, 2),
            "summed_request_seconds_per_pass": "" if seconds is None else _decimal(Decimal(seconds) / passes, 3),
            **{q: passes - len(exact.get(q, {}).get("exact_passes", [])) for q in questions},
            **report_labels(score),
        })
    return rows


def _markdown(images: list[dict]) -> str:
    lines = ["# Results", "",
             "Exact: questions exact in every pass. FN and FP: findings summed over the passes. Per question: the "
             "passes in which it is not exact. Cost per pass: the selected calls' exposure, USD.", ""]
    for image in images:
        rows = image["rows"]
        questions = [q for q in QIDS if q in rows[0]]
        if image.get("experiment"):
            lines += ["Mock stage experiment: " + ", ".join(image["experiment"]["stages"])
                      + ". Mock outputs are experimental; model conditions remain frozen.", ""]
            if image.get("s4_validation"):
                lines += ["S4 candidate agreement with the fixed evaluator: "
                          + image["s4_validation"]["status"] + ". The table uses the fixed evaluator.", ""]
        lines += [f"## {image['case_label']}: {image['findings']} findings per pass ({image['positive']} positive)", "",
                  f"Admission {image['admission']}"
                  + (f" ({image['admission_policy']})." if image["admission_policy"] else ".")
                  + ("" if image["admission"] == "passed" else
                     " The rule-based answers did not match the reference labels on every request, so the image is "
                     "not admitted, and any model rows below are development runs, not results."), "",
                  "| Approach | Exact | F1 | FN | FP | " + " | ".join(str(i + 1) for i in range(len(questions)))
                  + " | Cost per pass | Selection policy | Lineage |",
                  "|---|---|---|---|---|" + "---|" * len(questions) + "---|---|---|"]
        for row in rows:
            name = "Rule-based baseline" if row["condition"] == "rules" else row["condition"]
            lines.append(f"| {name} | {row['exact']} | {row['f1_percent'] or '–'} | {row['fn']} | {row['fp']} | "
                         + " | ".join(str(row[q]) for q in questions) + f" | {row['cost_per_pass_usd'] or '–'} | "
                         + f"{row.get('selection_policy', '–')} | {row.get('lineage_status', '–')} |")
        lines.append("")
    return "\n".join(lines)


def write_report(*, runs: list[Path], output: Path) -> dict:
    output = Path(output)
    if output.exists():
        raise FileExistsError("report destination already exists")
    images, table, figure = [], [], []
    for run in runs:
        g5, entry = read_g5(run)
        for condition, score in g5["scores"].items():
            passes = len(score.get("passes") or [1, 2, 3])
            figure.append([_image(g5["case_label"]), condition,
                           _decimal(Decimal(score["selected_exposure_usd"]) / passes, 3),
                           _f1_percent(score["f1"]), g5["admission"]["status"]])
        rows = [{**row, "admission": g5["admission"]["status"]} for row in _rows(g5)]
        rules = g5["comparison"]["rules"]
        counts = rules["finding_counts"]
        images.append({"run": str(run), "case_label": g5["case_label"], "g5_sha256": entry["sha256"],
                       **({"experiment": g5["experiment"]} if "experiment" in g5 else {}),
                       **({"s4_validation": g5["stage_validation"]["S4"],
                           "candidate_evaluation": g5["candidate_evaluation"]} if "candidate_evaluation" in g5 else {}),
                       "admission": g5["admission"]["status"], "admission_policy": g5["admission"].get("policy"),
                       "findings": rules["findings"],
                       "positive": counts.get("tp", 0) + counts.get("fn", 0), "rows": rows,
                       "evaluation_evidence": {name: {key: score[key] for key in
                           ("provenance", "selection", "lineage", "metric_policy") if key in score}
                           for name, score in g5["scores"].items()}})
        table.extend(rows)
    labels = [image["case_label"] for image in images]
    if len(set(labels)) != len(labels):
        raise ValueError("two runs report the same case: " + ", ".join(sorted(labels)))
    output.mkdir(parents=True)
    questions = [q for q in QIDS if any(q in row for row in table)]
    columns = ["image", "condition", "exact", "f1_percent", "fn", "fp", "cost_per_pass_usd",
               "summed_request_seconds_per_pass", *questions, "admission", "selection_policy", "lineage_status"]
    with (output / "table-results.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(columns)
        writer.writerows([[row.get(column, "") for column in columns] for row in table])
    with (output / "figure-f1-cost.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["image", "condition", "cost_per_pass_usd", "f1_percent", "admission"])
        writer.writerows(figure)
    (output / "results.md").write_text(_markdown(images) + "\n")
    report = {"schema_version": SCHEMA, "images": images, "provider_calls": 0}
    write_json(output / "report.json", report)
    return {"status": "reported", "output": str(output), "images": labels, "rows": len(table)}
