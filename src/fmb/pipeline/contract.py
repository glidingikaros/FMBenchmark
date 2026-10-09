from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fmb.core.sealed_records import parse_json, read_json
from fmb.pipeline.gates import RUN_MANIFEST, read_gate, verify_run

SCHEMA = "fmb.pipeline.contract_check.v1"


def _check(fn) -> dict:
    try:
        detail = fn()
        return {"status": "passed", **({"detail": detail} if detail else {})}
    except (ValueError, KeyError, OSError, AssertionError) as error:
        return {"status": "failed", "detail": str(error)[:500]}


def _gates(run: Path) -> tuple[dict, dict]:
    manifest = parse_json((run / RUN_MANIFEST).read_text())
    return manifest, {name: read_gate(run, entry) for name, entry in manifest["gates"].items()}


def check_packs(run: Path) -> dict:
    from fmb.profiles import validate_profile

    _, gates = _gates(run)
    g2 = gates["G2"]
    questions = [q["question_id"] for q in g2["questions"]]
    validate_profile(g2, questions)
    return {"questions": questions}


def check_truth_blindness(run: Path) -> dict:
    manifest, gates = _gates(run)
    roots = manifest.get("roots", {})
    analysis = Path(roots.get("analysis", run / "analysis"))
    guard = read_json(analysis.with_name(analysis.name + "-truth-guard.json"))
    if guard.get("status") != "completed" or guard.get("denied_private_reads", []) != []:
        raise ValueError("the collection's truth guard did not complete without denied reads")
    report = read_json(run / "preparation" / "cards" / "build-report.json")
    if report.get("truth_sources_used") != [] or gates["G3"]["truth_sources_used"] != []:
        raise ValueError("preparation used a truth source")
    assessment = read_json(run / "assessment" / "rules" / "assessment.json")
    if assessment.get("truth_sources_used") != []:
        raise ValueError("S3 used a truth source")
    guarded = {"S3": assessment.get("truth_guard")}
    guarded |= {"S3' freeze of " + c.name: read_json(c / "protocol.json").get("truth_guard")
                for c in sorted((run / "conditions").iterdir())}
    for step, guard in guarded.items():
        if guard is None or guard.get("generation_files_opened") != [] or guard.get("denied_private_reads") != []:
            raise ValueError(f"{step} has no private-read guard record showing no generation read")
    decided = datetime.fromisoformat(assessment["assessed_utc"])
    for condition in sorted((run / "conditions").iterdir()):
        admitted = datetime.fromisoformat(read_json(condition / "admission" / "admission.json")["admitted_utc"])
        if not decided < admitted:
            raise ValueError("S3 decided after admission opened the reference: " + condition.name)
    return {"generation_files_opened": len(report.get("generation_files_opened", []))}


def check_reads(run: Path) -> dict:
    from fmb.pipeline.reads import read_record, undeclared

    manifest, gates = _gates(run)
    steps = {}
    for stage in manifest["stages"]:
        record = read_record(run, stage)
        found = undeclared(record["step"], record["read"])
        if record["step"] == "S2":
            found += ["generation:" + p for p in record["read"].get("generation", [])
                      if p != "." and p not in gates["G1"]["readable_paths"]]
        if found:
            raise ValueError(f"{record['step']} read files its gates do not declare: " + ", ".join(found[:5]))
        steps[record["step"]] = {root: len(paths) for root, paths in record["read"].items()}
    return {"steps": steps, "scope": "observed Python reads under declared roots"}


def check_presentation(run: Path) -> dict:
    manifest = parse_json((run / RUN_MANIFEST).read_text())
    check = read_json(run / "checks" / "presentation.json")
    independent = any("admission_baseline" in stage.get("outputs", {}) for stage in manifest["stages"])
    engine = "rules" if independent else manifest["implementations"]["S3"]["engine"]
    if check.get("status") != "passed" or check.get("engine") != engine:
        raise ValueError("the presentation check did not pass with the declared validation engine")
    return {"engine": engine, "requests": check["requests"]}


def check_admission(run: Path) -> dict:
    manifest = parse_json((run / RUN_MANIFEST).read_text())
    policy = manifest.get("admission_policy", "strict")
    dispatched = []
    for condition in sorted((run / "conditions").iterdir()):
        certificate = read_json(condition / "admission" / "admission.json")
        if not (condition / "run").is_dir():
            continue
        dispatched.append(condition.name)
        schedule = read_json(condition / "run" / "schedule.json")
        if certificate["status"] != "passed":
            if policy != "report-only" or schedule.get("development", {}).get("label") != "development_not_admitted":
                raise ValueError("an unadmitted condition was dispatched without the report-only label: "
                                 + condition.name)
    return {"policy": policy, "dispatched": dispatched}


def naive_battery(run: Path) -> list[dict]:
    _, gates = _gates(run)
    rows = gates["G5"].get("findings", [])
    built = run / "preparation" / "cards"
    types_by_finding = {}
    for request_rows in {row["request_id"] for row in rows}:
        sent = read_json(built / "sent" / (request_rows + ".json"))
        for card in sent["candidate_roster"]:
            types = {record.get("record_type") for record in card.get("evidence_records", [])}
            for target in card.get("assessment_targets", []):
                types_by_finding[(request_rows, target.get("finding_id"))] = types
    trivial = []
    for question in sorted({row["question_id"] for row in rows}):
        selected = [row for row in rows if row["question_id"] == question]
        truth = [row["reference"] == "supported" for row in selected]
        if all(truth) or not any(truth):
            continue
        features = [types_by_finding.get((row["request_id"], row["display_id"]),
                                         types_by_finding.get((row["request_id"], row["finding_id"]), set()))
                    for row in selected]
        rules = {"all supported": [True] * len(selected), "none supported": [False] * len(selected)}
        for record_type in sorted({t for f in features for t in f if t}):
            rules[f"card has {record_type}"] = [record_type in f for f in features]
            rules[f"card lacks {record_type}"] = [record_type not in f for f in features]
        exact = sorted(name for name, predicted in rules.items() if predicted == truth)
        if exact:
            trivial.append({"question_id": question, "exact_naive_rules": exact})
    return trivial


def check_run(run: Path, *, golden: Path | None = None) -> dict:
    run = Path(run)
    checks = {
        "gates": _check(lambda: verify_run(run)),
        "question_packs": _check(lambda: check_packs(run)),
        "truth_blindness": _check(lambda: check_truth_blindness(run)),
        "reads": _check(lambda: check_reads(run)),
        "presentation": _check(lambda: check_presentation(run)),
        "admission": _check(lambda: check_admission(run)),
    }
    try:
        trivial = naive_battery(run)
        checks["triviality"] = ({"status": "passed"} if not trivial
                                else {"status": "warning", "detail": trivial})
    except (ValueError, KeyError, OSError) as error:
        checks["triviality"] = {"status": "failed", "detail": str(error)[:500]}
    if golden is not None:
        from fmb.pipeline.diff import diff_runs

        def compare():
            result = diff_runs(Path(golden), run)
            if result["status"] != "same":
                raise ValueError("differs from the golden run in: " + ", ".join(
                    name for name, entry in result["gates"].items() if entry["status"] != "same"))

        checks["golden"] = _check(compare)
    failed = [name for name, entry in checks.items() if entry["status"] == "failed"]
    return {"schema_version": SCHEMA, "status": "failed" if failed else "passed", "run": str(run),
            "checks": checks, **({"failed": failed} if failed else {})}
