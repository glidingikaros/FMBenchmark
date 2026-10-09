from __future__ import annotations

from pathlib import Path

from fmb.core import paper_integrity as integrity
from fmb.core.hashing import sha256_file
from fmb.core.sealed_records import canonical_json, now, read_json, verify_seal
from fmb.pipeline import stages
from fmb.pipeline.gates import write_gate
from fmb.pipeline.evaluation import SCORE_KEYS

SCHEMA = "fmb.pipeline.sealed_evaluation.v1"
MANIFEST = "evaluation-manifest.json"


def _named(run: str | Path) -> tuple[str | None, Path]:
    text = str(run)
    if "=" in text and not Path(text).exists():
        name, _, path = text.partition("=")
        return name, Path(path)
    return None, Path(text)


def evaluate_sealed(*, case_label: str, condition_runs: list, output: Path, rules: Path | None = None) -> dict:
    from fmb.evaluation.scoring import score_run
    from fmb.pipeline.evaluation import comparison, sealed_findings_table

    named = [_named(run) for run in condition_runs]
    runs = [path.resolve(strict=True) for _, path in named]
    names = []
    for (name, _), run in zip(named, runs):
        protocol = read_json(run / "protocol.json")
        names.append(name or protocol.get("condition_id") or protocol.get("probe_id"))
    if len(set(names)) != len(names) or not all(names):
        raise ValueError("each sealed run must be a different, named condition")
    certificates, statuses = [], {}
    for name, run in zip(names, runs):
        verify_seal(run)
        if (run / "admission" / "admission.json").is_file():
            verify_seal(run / "admission", "admission-seal.json")
            statuses[name] = read_json(run / "admission" / "admission.json")["status"]
            certificates.append(stages.file_ref(run / "admission" / "admission.json"))
        else:
            statuses[name] = None
            certificates.append(stages.file_ref(run / "preparation-seal.json"))
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    scores = {}
    for name, run in zip(names, runs):
        if (run / "run" / "completion.json").is_file():
            result = score_run(run)
            scores[name] = {key: result[key] for key in SCORE_KEYS if key in result}
    rows = sealed_findings_table(runs, rules=rules, names=names)
    rules_exact = all(row["rules"]["status"] == row["reference"] for row in rows)
    statuses = {name: status or ("passed" if rules_exact else "failed") for name, status in statuses.items()}
    admission = {"status": "passed" if all(status == "passed" for status in statuses.values()) else "failed",
                 "policy": "strict", "certificates": certificates}
    g5 = {"gate": "G5", "schema_version": "fmb.pipeline.g5.v1", "case_label": case_label, "admission": admission,
          "scores": scores, "findings": rows, "comparison": comparison(rows)}
    entry = write_gate(output, "G5", g5)
    manifest = {
        "schema_version": SCHEMA,
        "case_label": case_label,
        "runs": [{"condition": name, "path": str(run), "admission": statuses[name],
                  "preparation_seal_sha256": sha256_file(run / "preparation-seal.json")}
                 for name, run in zip(names, runs)],
        "rules": "S3 sealed result set" if rules is not None else "recomputed and checked against each run's baseline",
        "code": {"source_manifest_sha256": integrity.source_manifest_sha256()},
        "gates": {"G5": entry},
        "provider_calls": 0,
        "evaluated_utc": now(),
    }
    (output / MANIFEST).write_text(canonical_json(manifest) + "\n")
    return {"status": "evaluated", "output": str(output), "case_label": case_label, "admission": admission["status"],
            "conditions": names, "findings": len(rows)}
