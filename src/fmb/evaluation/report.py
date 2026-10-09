from __future__ import annotations

from collections import Counter
import csv
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
import re

from fmb.evaluation.admission import reference_file
from fmb.core.case_contract import QIDS
from fmb.paper.replay import replay
from fmb.evaluation.scoring import load_run, score_loaded_runs
from fmb.evaluation.lineage import report_labels
from fmb.core.hashing import sha256_file
from fmb.core.paper_protocol import paper_protocol, validate_condition
from fmb.core.paper_results import finding_status
from fmb.core.sealed_records import contained_path, read_json, write_json
from fmb.core.truth_guard import system_image


def decimal_text(value, places):
    return str(
        Decimal(str(value)).quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP)
    )


def _f1_percent(f1):
    return "" if f1 is None else decimal_text(Decimal(str(f1)) * 100, 1)


def validate_study(study, protocol):
    if study.get("schema_version") != "paper_study.v1":
        raise ValueError("unsupported study index")
    rows = study.get("conditions", [])
    wanted = {
        (image, condition)
        for image in protocol["images"]
        for condition in protocol["conditions"]
    }
    actual = [(r["image"], r["condition"]) for r in rows]
    if len(actual) != len(set(actual)) or set(actual) != wanted:
        raise ValueError("study must contain every image/condition exactly once")
    paths = [r["primary"] for r in rows]
    if len(paths) != len(set(paths)):
        raise ValueError("conditions cannot reuse a primary run")
    analyses = study.get("analyses", {})
    if (
        len(analyses.get("i3_focus_findings", [])) != 8
        or len(set(analyses["i3_focus_findings"])) != 8
    ):
        raise ValueError("study must declare the eight I3 exploratory targets")
    if not analyses.get("i3_access_only_finding"):
        raise ValueError("study must declare the qualitative example target")
    if set(study.get("supplemental_findings", {})) != set(protocol["images"]):
        raise ValueError("study must identify supplemental targets for every image")
    measurements = study.get("measurements", {})
    if set(measurements) != set(protocol["images"]) or any(
        set(paths) != {"generation", "collection", "image_manifest", "preparation"}
        for paths in measurements.values()
    ):
        raise ValueError("study must identify all four measurements for every image")
    sources = study.get("source_inputs", [])
    paths = [entry["path"] for entry in sources]
    if not sources or len(paths) != len(set(paths)) or any(
        not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")) for entry in sources
    ):
        raise ValueError("study source hashes must be nonempty, unique and valid")


def _corpus_binding(primary):
    manifest = read_json(primary / "manifest.json")
    cases = sorted(
        (r["request_id"], r["question_id"], r["case_id"], r["case_sha256"])
        for r in manifest["rows"]
    )
    return cases, sha256_file(reference_file(primary))


def _corpus(primary, supplemental):
    manifest = read_json(primary / "manifest.json")
    references = read_json(reference_file(primary))
    rows = {q: Counter() for q in QIDS}
    status_by_id = {}
    for row in manifest["rows"]:
        q = row["question_id"]
        case = read_json(primary / "cases" / (row["request_id"] + ".json"))
        counts = rows[q]
        counts["requests"] += 1
        counts["cards"] += len(case["candidate_roster"])
        for fid, status in references[row["case_id"]]["expected_status"].items():
            if fid in status_by_id:
                raise ValueError("finding appears in multiple corpus requests")
            status_by_id[fid] = (q, status)
            counts["findings"] += 1
            counts["positive" if status == "supported" else "negative"] += 1
    if len(supplemental) != len(set(supplemental)) or set(supplemental) - set(
        status_by_id
    ):
        raise ValueError(
            "supplemental finding IDs must be a unique subset of the corpus"
        )
    for fid in supplemental:
        q, status = status_by_id[fid]
        rows[q]["added_negative_targets"] += status == "not_supported"
    total = Counter()
    for counts in rows.values():
        total.update(counts)
    return {
        "per_question": {q: dict(c) for q, c in rows.items()},
        "totals": dict(total),
    }


def _i3_judgments(definition, score, a, b):
    outcomes = {
        "primary": {(r["request_id"], r["pass"]): r for r in a["outcomes"]},
        "companion": {(r["request_id"], r["pass"]): r for r in b["outcomes"]}
        if b
        else {},
    }
    references = read_json(reference_file(Path(a["root"])))
    requests = {r["request_id"]: r for r in a["schedule"]}
    result = []
    for selected in score["selection"]:
        if selected["state"] != "completed":
            continue
        outcome = outcomes[selected["source"]][selected["request_id"], selected["pass"]]
        expected = references[requests[selected["request_id"]]["case_id"]][
            "expected_status"
        ]
        answer = outcome["two_list"]
        for fid, want in expected.items():
            got = finding_status(answer, fid)
            result.append(
                {
                    "condition": definition["condition"],
                    "question": selected["question_id"],
                    "request_id": selected["request_id"],
                    "pass": selected["pass"],
                    "source": selected["source"],
                    "finding_id": fid,
                    "expected": want,
                    "observed": got,
                    "error": got != want,
                }
            )
    return result


def _analysis(judgments, declaration):
    focus = set(declaration["i3_focus_findings"])
    if not focus <= {r["finding_id"] for r in judgments}:
        raise ValueError("declared focus finding is absent from valid judgments")
    groups = {}
    for name, selected in (("focus", True), ("remaining", False)):
        rows = [r for r in judgments if (r["finding_id"] in focus) == selected]
        groups[name] = {
            "valid_judgments": len(rows),
            "status_errors": sum(r["error"] for r in rows),
            "unresolved_negative": sum(
                r["expected"] == "not_supported" and r["observed"] == "insufficient"
                for r in rows
            ),
        }
    fid = declaration["i3_access_only_finding"]
    example = [r for r in judgments if r["finding_id"] == fid]
    supported = []
    for condition in sorted({r["condition"] for r in example}):
        rows = [r for r in example if r["condition"] == condition]
        if {r["pass"] for r in rows} == {1, 2, 3} and all(
            r["observed"] == "supported" for r in rows
        ):
            supported.append(condition)
    return {
        "i3_error_concentration": groups,
        "i3_access_only": {
            "finding_id": fid,
            "configurations_supporting_all_passes": supported,
            "distinct_models_supporting_all_passes": len(
                {"luna" if c.startswith("luna-") else c for c in supported}
            ),
            "judgments": example,
            "limits": "Finding-status reproduction. Retained reasons remain available by request/pass; citation entailment is not scored.",
        },
    }


def build_report(*, index: Path, archive_root: Path):
    study = read_json(index)
    protocol = paper_protocol()
    validate_study(study, protocol)
    archive_root = archive_root.resolve(strict=True)
    source_inputs = []
    for entry in study.get("source_inputs", []):
        path = contained_path(archive_root, entry["path"])
        if sha256_file(path) != entry["sha256"]:
            raise ValueError("study source changed: " + entry["path"])
        source_inputs.append(entry)
    measurements = {}
    for image, paths in study.get("measurements", {}).items():
        if set(paths.values()) - {r["path"] for r in source_inputs}:
            raise ValueError("measurement input lacks a verified source hash")
        records = {
            key: read_json(contained_path(archive_root, value))
            for key, value in paths.items()
        }
        system = system_image(records["image_manifest"])
        measurements[image] = {
            "generation_seconds": records["generation"]["elapsed_seconds"],
            "collection_seconds": records["collection"]["elapsed_seconds"],
            "image_bytes": system["size_bytes"],
            "image_sha256": system["sha256"],
            "recorded_rule_seconds": sum(
                r["deterministic_elapsed_seconds"]
                for r in records["preparation"]["rows"]
            ),
        }
    corpus, deterministic, results, judgments = {}, {}, [], []
    image_bindings = {}
    for row in study["conditions"]:
        primary = contained_path(archive_root, row["primary"])
        companion = (
            contained_path(archive_root, row["companion"])
            if row.get("companion")
            else None
        )
        binding = _corpus_binding(primary)
        image = row["image"]
        if image in image_bindings and binding != image_bindings[image]:
            raise ValueError("conditions do not share the same image cases and reference")
        image_bindings[image] = binding
        a = load_run(primary)
        b = load_run(companion) if companion else None
        score = score_loaded_runs(a, b)
        settings = a["protocol"]["settings"]
        validate_condition(settings, condition=row["condition"], completion=False)
        if a["protocol"]["passes"] != protocol["passes"]:
            raise ValueError("paper runs require three planned passes")
        if row["condition"] == "luna-high":
            corpus[image] = _corpus(primary, study["supplemental_findings"][image])
            deterministic[image] = replay(primary)
            if (
                deterministic[image]["requests"]
                != deterministic[image]["exact_requests"]
            ):
                raise ValueError("deterministic replay differs from admitted study")
            if (
                corpus[image]["totals"]["findings"]
                != protocol["images"][image]["findings"]
            ):
                raise ValueError("image corpus differs from paper declaration")
        score["cost_per_pass"] = str(Decimal(score["selected_exposure_usd"]) / 3)
        score["summed_request_seconds_per_pass"] = str(
            Decimal(score["selected_request_seconds_sum"]) / 3
        )
        results.append(
            {
                "image": row["image"],
                "condition": row["condition"],
                "settings": settings,
                **score,
            }
        )
        if row["image"] == "I3":
            judgments.extend(_i3_judgments(row, score, a, b))
    return {
        "schema_version": "paper_full_results.v1",
        "provider_calls": 0,
        "study_index_sha256": sha256_file(index),
        "corpus": corpus,
        "deterministic": deterministic,
        "conditions": results,
        "analyses": _analysis(judgments, study["analyses"]),
        "historical_source_inputs": source_inputs,
        "recorded_measurements": measurements,
        "claim_boundary": "Recomputation from retained inputs and responses; no new image or model execution.",
    }


def write_report(*, index: Path, archive_root: Path, output: Path):
    if output.exists():
        raise FileExistsError("report destination already exists")
    report = build_report(index=index, archive_root=archive_root)
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "results.json", report)
    columns = [
        "image",
        "condition",
        "exact",
        "f1_percent",
        "fn",
        "fp",
        "cost_per_pass_usd",
        "summed_request_seconds_per_pass",
        *QIDS,
        "selection_policy", "lineage_status",
    ]
    table = []
    for row in report["conditions"]:
        table.append(
            [
                row["image"],
                row["condition"],
                f"{row['every_pass']}/9",
                _f1_percent(row["f1"]),
                row["finding_counts"]["fn"],
                row["finding_counts"]["fp"],
                decimal_text(row["cost_per_pass"], 2),
                decimal_text(row["summed_request_seconds_per_pass"], 3),
                *[3 - len(row["per_question"][q]["exact_passes"]) for q in QIDS],
                *report_labels(row).values(),
            ]
        )
    with (output / "table-results.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(columns)
        writer.writerows(table)
    with (output / "question-passes.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["image", "condition", "question", "pass", "exact", "execution_states"])
        for row in report["conditions"]:
            for question in QIDS:
                for pass_id in range(1, 4):
                    states = Counter(
                        item["state"] for item in row["selection"]
                        if item["question_id"] == question and item["pass"] == pass_id
                    )
                    writer.writerow([
                        row["image"], row["condition"], question, pass_id,
                        pass_id in row["per_question"][question]["exact_passes"],
                        ";".join(f"{state}:{count}" for state, count in sorted(states.items())),
                    ])
    with (output / "figure-f1-cost.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["image", "condition", "cost_per_pass_usd", "f1_percent"])
        for row in report["conditions"]:
            writer.writerow(
                [
                    row["image"],
                    row["condition"],
                    decimal_text(row["cost_per_pass"], 3),
                    _f1_percent(row["f1"]),
                ]
            )
    corpus_columns = ["cards", "findings", "positive", "negative", "requests", "added_negative_targets"]
    with (output / "corpus.csv").open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["image", "question", *corpus_columns])
        for image, corpus in report["corpus"].items():
            for q, counts in corpus["per_question"].items():
                writer.writerow([image, q, *[counts.get(k, 0) for k in corpus_columns]])
    lines = [
        "# Recomputed paper results",
        "",
        report["claim_boundary"],
        "",
        "| Image | Configuration | Exact | F1 (%) | FN | FP | Cost/pass (USD) | Selection policy | Lineage |",
        "|---|---|---:|---:|---:|---:|---:|---|---|",
    ]
    lines.extend("| " + " | ".join(map(str, row[:7] + row[-2:])) + " |" for row in table)
    lines += [
        "",
        "Missing planned responses are non-exact. Finding metrics exclude no-answer calls; selected unusable returned answers retain resource costs. Duration is summed request time. Reasons are not scored.",
        "Policy and historical lineage are recorded in results.json. Unsigned flattening metadata does not attest the full execution history or establish paper retry compliance.",
    ]
    (output / "results.md").write_text("\n".join(lines) + "\n")
    return {
        "status": "completed",
        "output": str(output),
        "conditions": len(table),
        "provider_calls": 0,
    }
