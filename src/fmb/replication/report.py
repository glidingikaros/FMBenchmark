from __future__ import annotations

import json
import shutil
from pathlib import Path

from fmb.core.case_contract import QIDS
from fmb.core.hashing import sha256_file
from fmb.core.paper_protocol import SAMPLING, paper_protocol

GATES = {"G1": "Evidence image", "G2": "Artefact profile", "G3": "Evidence cards", "G4": "Analysis results",
         "G5": "Evaluation report"}
KEY_RECEIPTS = {"image.json": "Image definition", "recipe.json": "Generation recipe",
                "manifest.json": "Generation manifest", "ground_truth.json": "Ground truth",
                "finding_reference.json": "Finding reference"}


def _f1(value) -> str:
    return "–" if value is None else f"{value:.3f}"


def _span(values: list, form=str) -> str:
    low, high = values
    return form(low) if low == high else f"{form(low)}–{form(high)}"


def _admission(row: dict) -> str:
    if row["admission"] == "passed":
        return "passed: the rules reproduce the ground truth on every question, so this image's evidence counts"
    if row["admission"] == "failed":
        return ("failed: the rules miss " + ", ".join(row["not_exact"])
                + "; the comparison is a development run, not a result")
    return "not reached: the pipeline stopped; see pipeline.log"


def headline(row: dict, folder: Path) -> list[str]:
    lines = [f"{row['image']}: admission {_admission(row)}"]
    if "exact" in row:
        counts = row["counts"]
        lines.append(f"  S3   {'rules':<22} {row['exact']}/{row['questions']} questions exact   F1 {_f1(row['f1'])}   "
                     f"TP {counts.get('tp', 0)} FP {counts.get('fp', 0)} FN {counts.get('fn', 0)} "
                     f"TN {counts.get('tn', 0)}")
        for condition, llm in row.get("llm", {}).items():
            cost = f"   ${llm['cost_usd']}" if llm.get("cost_usd") is not None else ""
            lines.append(f"  S3'  {condition:<22} {_span(llm['exact'])}/{row['questions']} questions exact over "
                         f"{llm['passes']} passes   F1 {_span(llm['f1'], _f1)}{cost}")
        if not row.get("llm"):
            lines.append("  S3'  not sent: add --compare S3 --llm CONDITION to compare an LLM")
    lines.append(f"  report: {folder / 'report.md'}")
    return lines


def complete(output: Path, row: dict, generated: Path, generation: Path) -> None:
    receipts = output / "receipts"
    receipts.mkdir()
    for path in sorted(generation.glob("*.json")):
        shutil.copyfile(path, receipts / path.name)
    shutil.copyfile(generated / "recipe" / "recipe.json", receipts / "recipe.json")
    if (generated / "image.json").is_file():
        shutil.copyfile(generated / "image.json", receipts / "image.json")
    manifest_path = output / "run" / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else None
    exposure = next((step["detail"].get("exposure_usd", {}) for step in (manifest or {}).get("stages", [])
                     if step.get("step") == "S3':dispatch"), {})
    for condition, llm in row.get("llm", {}).items():
        if condition in exposure:
            llm["cost_usd"] = exposure[condition]
    (output / "summary.json").write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
    (output / "report.md").write_text(markdown(output, row, manifest, generated), encoding="utf-8")


def _verdict(entry: dict) -> str:
    if entry.get("exact"):
        return "exact"
    parts = [f"{len(entry[key])} {key.replace('_', ' ')}" for key in ("missed", "spurious", "unresolved", "not_run")
             if entry.get(key)]
    return ", ".join(parts) or "not exact"


def _questions(g5: dict) -> list[str]:
    counts = {}
    for finding in g5["findings"]:
        total, positive = counts.get(finding["question_id"], (0, 0))
        counts[finding["question_id"]] = (total + 1, positive + (finding["reference"] == "supported"))
    conditions = g5["comparison"].get("conditions") or {}
    columns = [(condition, number) for condition, result in conditions.items() for number in result["passes"]]
    header = ["Question", "Findings", "Supported", "S3 rules"] + [f"S3' {c} pass {n}" for c, n in columns]
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    rules = g5["comparison"]["rules"]["per_question"]
    for qid in [q for q in QIDS if q in rules] + sorted(set(rules) - set(QIDS)):
        total, positive = counts.get(qid, (0, 0))
        cells = [_verdict(conditions[c]["passes"][n]["per_question"].get(qid, {})) for c, n in columns]
        lines.append("| " + " | ".join([qid, str(total), str(positive), _verdict(rules[qid]), *cells]) + " |")
    return lines


def markdown(output: Path, row: dict, manifest: dict | None, generated: Path) -> str:
    from fmb.pipeline.report import run_table
    from fmb.replication import image_files

    lines = [f"# {row['image']}: S3 and S3' against ground truth", "", "```", *headline(row, output)[:-1], "```", ""]
    image = generated / "image.json"
    if image.is_file():
        definition = json.loads(image.read_text(encoding="utf-8"))
        lines += ["## Image", "",
                  f"- Definition: `{row['image']}`" + (" (a paper image)" if row.get("paper_image") else "")
                  + f", {image_files.population_line(definition)}.",
                  f"- Disk image: `{row.get('generation', '')}/full_scale.vmdk`."]
        lock = generated / "recipe" / "dependency-lock.json"
        if lock.is_file():
            guest = json.loads(lock.read_text(encoding="utf-8")).get("guest", {})
            lines.append(f"- Windows guest: build {guest.get('windows_build')}, {guest.get('timezone')}, "
                         f"{guest.get('locale')}.")
        if row.get("windows_base"):
            base = row["windows_base"]
            lines.append(f"- Windows base: build {base.get('build')}"
                         + ("" if base.get("iso_pinned", True) else f", from an unpinned ISO ({base.get('iso_sha256')})")
                         + ".")
        lines.append("")
    gate = output / "run" / "gates" / "G5.json"
    if gate.is_file():
        g5 = json.loads(gate.read_text(encoding="utf-8"))
        lines += ["## Results", "", run_table(output / "run"), "", "## Per question", "", *_questions(g5), ""]
    lines += ["## Assessors", ""]
    if manifest:
        s3 = manifest["implementations"]["S3"]
        lines.append(f"- S3: `{s3['engine']}` ({s3['module']}); code {row.get('implementation', 'released')}, "
                     f"source manifest {manifest['code']['source_manifest_sha256']}.")
        if row.get("changed_files"):
            lines.append("  Changed files: " + ", ".join(f"`{name}`" for name in row["changed_files"]) + ".")
    pipeline = json.loads((output / "pipeline.json").read_text(encoding="utf-8"))
    own = pipeline.get("user_conditions") or {}
    conditions = {**paper_protocol()["conditions"], **own}
    cap = (pipeline.get("dispatch") or {}).get("cap_usd")
    for condition, llm in row.get("llm", {}).items():
        settings = conditions[condition]["settings"]
        lines.append(f"- S3' `{condition}`" + (" (your condition)" if condition in own else "")
                     + f": {settings['model']} via {settings['provider']}"
                     + (f" ({settings['route']})" if settings.get("route") else "")
                     + f", reasoning {settings['reasoning_effort']}"
                     + "".join(f", {key} {settings[key]}" for key in SAMPLING if key in settings)
                     + f", at most {settings['max_output_tokens']} output tokens, {llm['passes']} passes"
                     + (f", ${llm['cost_usd']} of a ${cap} cap" if llm.get("cost_usd") is not None else "") + ".")
    if not row.get("llm"):
        lines.append("- S3': not sent. The LLM requests are frozen under `run/conditions/`.")
    lines += ["", "## Receipts", "", "| Record | File | SHA-256 |", "|---|---|---|"]
    for name, entry in sorted((manifest or {}).get("gates", {}).items()):
        lines.append(f"| {name} {GATES.get(name.split(':')[0], '')} | `run/{entry['path']}` | `{entry['sha256']}` |")
    if manifest:
        lines.append(f"| Run manifest | `run/run-manifest.json` | `{sha256_file(output / 'run' / 'run-manifest.json')}` |")
    for path in sorted((output / "receipts").glob("*.json"), key=lambda p: (p.name not in KEY_RECEIPTS, p.name)):
        lines.append(f"| {KEY_RECEIPTS.get(path.name, 'Generation receipt')} | `receipts/{path.name}` | "
                     f"`{sha256_file(path)}` |")
    return "\n".join(lines) + "\n"
