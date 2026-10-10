from __future__ import annotations

import random
import re
from pathlib import Path

from fmb.core.sealed_records import read_json

SCORE_KEYS = ("passes", "exact_question_passes", "planned_question_passes", "every_pass", "per_question", "f1",
              "finding_counts", "execution_states", "selected_exposure_usd", "selected_request_seconds_sum",
              "provenance", "selection", "lineage", "metric_policy")

RECORD_KEY = re.compile(r"\br\d{5,}\b")
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 0


def evaluate(g1: dict, g3: dict, assessments: dict, *, roots: dict[str, Path],
             admission: dict, policy: str, checks: dict, inputs: dict, comparator=None) -> dict:
    from fmb.evaluation.scoring import score_run
    from fmb.pipeline import stages

    built = stages.check_build(g3, roots)
    rules = stages.check_assessment(assessments["rules"], g3, roots)
    runs, scores = [], {}
    for name, g4 in assessments.items():
        if name == "rules":
            continue
        if name != g4["assessor"]["id"]:
            raise ValueError("condition name differs from its G4 assessor: " + name)
        run = stages.check_assessment(g4, g3, roots)
        runs.append(run)
        if g4["status"] == "executed":
            result = score_run(run)
            scores[name] = {key: result[key] for key in SCORE_KEYS if key in result}
    findings = findings_table(built, g3, runs, rules=rules)
    compared = (comparison if comparator is None else comparator)(findings)
    validation = stage_validation(g1=g1, g3=g3, packs_complete=True, checks=checks,
                                  comparison=compared, scores=scores, conditions=[run.name for run in runs])
    return stages.evaluation_gate(g3["case_label"], admission, runs, scores, findings=findings, comparison=compared,
                                  roots=roots, policy=policy, stage_validation=validation, inputs=inputs)


def _references(condition_runs: list[Path]) -> dict:
    from fmb.evaluation.admission import reference_file

    labels = [read_json(reference_file(Path(run))) for run in condition_runs]
    if any(other != labels[0] for other in labels[1:]):
        raise ValueError("condition runs of one case are admitted against different references")
    return labels[0]


def _request_rows(question: str, request_id: str, sent: dict, options: dict, decisions: dict, expected: dict) -> dict:
    from fmb.core import paper_contract
    from fmb.core.case_contract import target_catalog

    case = paper_contract.decode_case(sent, options)
    names = {s["subject_id"]: s["display_name"] for s in case["candidate_roster"]}
    keys = {ref: key for key, ref in sent.get("source_reference_map", {}).items()}
    display = paper_contract.finding_display_ids(case, options)
    card_keys = {decoded["subject_id"]: {r.get("source_record_ref") for r in card.get("evidence_records", [])}
                 for decoded, card in zip(case["candidate_roster"], sent["candidate_roster"])}
    request_keys = set(sent.get("source_reference_map", {}))
    rows = {}
    for finding_id, target in target_catalog(case).items():
        decision = decisions[target["subject_id"]][target["component"]]
        rows[(request_id, finding_id)] = {
            "question_id": question, "request_id": request_id, "finding_id": finding_id,
            "display_id": display[finding_id], "subject": names[target["subject_id"]],
            "component": target["component"], "reference": expected[finding_id],
            "rules": {"status": decision["status"],
                      "cited": sorted(keys.get(ref, ref) for ref in decision.get("evidence_refs", [])),
                      "statement": decision.get("statement")},
            "llm": {},
            "_card_keys": card_keys[target["subject_id"]], "_request_keys": request_keys,
        }
    return rows


def cited_keys(reason: str, request_keys: set) -> list[str]:
    longest = max(map(len, request_keys), default=len("r00000"))
    return sorted({key for key in RECORD_KEY.findall(reason) if len(key) <= longest})


def citations(cited: list[str], card_keys: set, request_keys: set) -> dict:
    return {"on_subject_card": [k for k in cited if k in card_keys],
            "elsewhere_in_request": [k for k in cited if k not in card_keys and k in request_keys],
            "unknown": [k for k in cited if k not in request_keys]}


def _attach_answers(rows: dict, condition_runs: list[Path], names: list[str] | None = None) -> list[dict]:
    from fmb.core.paper_results import finding_status

    for index, run in enumerate(condition_runs):
        run = Path(run)
        if not (run / "run" / "completion.json").is_file():
            continue
        condition = names[index] if names is not None else read_json(run / "protocol.json")["condition_id"]
        for path in sorted((run / "run").glob("call-*/outcome.json")):
            outcome = read_json(path)
            request_id = outcome["request_id"]
            completed = outcome["status"] == "completed"
            two = read_json(path.with_name("two-list.json")) if completed else {}
            reasons = read_json(path.with_name("assessment.json")).get("reasons", {}) if completed else {}
            for (rid, finding_id), row in rows.items():
                if rid != request_id:
                    continue
                reason = reasons.get(row["display_id"], "")
                cited = cited_keys(reason, row["_request_keys"])
                row["llm"].setdefault(condition, []).append({
                    "pass": outcome["pass"], "state": outcome["status"],
                    "status": finding_status(two, finding_id) if completed else None,
                    "cited": cited, "reason": reason,
                    "citations": citations(cited, row["_card_keys"], row["_request_keys"]),
                })
    result = []
    for row in rows.values():
        for answers in row["llm"].values():
            answers.sort(key=lambda answer: answer["pass"])
        result.append({key: value for key, value in row.items() if not key.startswith("_")})
    return result


def findings_table(built: Path, g3: dict, condition_runs: list[Path], rules: Path | None = None) -> list[dict]:
    from fmb.analysis.factual_contract import deterministic_factual_response
    from fmb.core import paper_contract
    from fmb.core.case_contract import bundle_from_case
    from fmb.core.hashing import sha256_file

    built = Path(built)
    view_options = built / "view-options.json"
    if sha256_file(view_options) != g3["view_options"]["sha256"]:
        raise ValueError("view options differ from G3")
    options = paper_contract.bind_options(read_json(view_options), built)
    references = _references(condition_runs)
    rows: dict[tuple[str, str], dict] = {}
    for question, entry in g3["questions"].items():
        for request in entry["requests"]:
            request_id = request["request_id"]
            sent = read_json(built / "sent" / (request_id + ".json"))
            if rules is not None:
                from fmb.assessment.stage import rule_result

                _, decisions = rule_result(rules, request_id, paper_contract.decode_case(sent, options))
            else:
                decisions = deterministic_factual_response(
                    bundle_from_case(paper_contract.decode_case(sent, options)))["assessments"]
            rows.update(_request_rows(question, request_id, sent, options, decisions,
                                      references[request_id]["expected_status"]))
    return _attach_answers(rows, condition_runs)


def sealed_findings_table(condition_runs: list[Path], rules: Path | None = None,
                          names: list[str] | None = None) -> list[dict]:
    from fmb.assessment.rules import assess_with_decisions
    from fmb.core import paper_contract
    from fmb.core.paper_artifacts import condition_options

    runs = [Path(run) for run in condition_runs]
    if not runs:
        raise ValueError("provide at least one sealed condition run")
    universes = [{row["request_id"]: row["case_sha256"] for row in read_json(run / "manifest.json")["rows"]}
                 for run in runs]
    if any(universe != universes[0] for universe in universes[1:]):
        raise ValueError("sealed condition runs of one case hold different requests or cards")
    first = runs[0]
    options = condition_options(first, read_json(first / "protocol.json"))
    references = _references(runs)
    rows: dict[tuple[str, str], dict] = {}
    for row in read_json(first / "manifest.json")["rows"]:
        request_id = row["request_id"]
        sent = read_json(first / "cases" / (request_id + ".json"))
        if rules is not None:
            from fmb.assessment.stage import rule_result

            _, decisions = rule_result(rules, request_id, paper_contract.decode_case(sent, options))
        else:
            response, decisions = assess_with_decisions(paper_contract.decode_case(sent, options))
            for run in runs:
                baseline = run / "deterministic" / (request_id + ".json")
                if baseline.is_file() and read_json(baseline) != response:
                    raise ValueError("the rules engine does not reproduce the sealed baseline: " + request_id)
        rows.update(_request_rows(row["question_id"], request_id, sent, options, decisions,
                                  references[request_id]["expected_status"]))
    return _attach_answers(rows, runs, names)


def _confusion(pairs) -> dict:
    counts = {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "unresolved": 0}
    for reference, answer in pairs:
        if answer is None:
            counts["fn"] += reference == "supported"
            continue
        if reference == "supported":
            counts["tp" if answer == "supported" else "fn"] += 1
        else:
            counts["fp" if answer == "supported" else "unresolved" if answer == "insufficient" else "tn"] += 1
    return counts


def _f1(counts: dict) -> float | None:
    denominator = 2 * counts["tp"] + counts["fp"] + counts["fn"]
    return 2 * counts["tp"] / denominator if denominator else None


NOT_RUN = object()


def per_question(pairs: list[tuple[dict, object]]) -> dict:
    result: dict[str, dict] = {}
    for row, answer in pairs:
        entry = result.setdefault(row["question_id"], {"missed": [], "spurious": [], "unresolved": [], "not_run": [],
                                                       "exact": True})
        if answer is NOT_RUN:
            entry["not_run"].append(row["display_id"])
            entry["exact"] = False
            continue
        if row["reference"] == "supported" and answer != "supported":
            entry["missed"].append(row["display_id"])
        elif row["reference"] != "supported" and answer == "supported":
            entry["spurious"].append(row["display_id"])
        elif row["reference"] != "supported" and answer == "insufficient":
            entry["unresolved"].append(row["display_id"])
        if answer != row["reference"]:
            entry["exact"] = False
    return dict(sorted(result.items()))


def citation_summary(judged: list[tuple[dict, dict]]) -> dict:
    citing = [answer["citations"] for _, answer in judged if answer.get("cited")]
    return {"decisions_citing_records": len(citing),
            "all_on_subject_card": sum(not c["elsewhere_in_request"] and not c["unknown"] for c in citing),
            "some_elsewhere_in_request": sum(bool(c["elsewhere_in_request"]) and not c["unknown"] for c in citing),
            "citing_unknown_records": sum(bool(c["unknown"]) for c in citing)}


def comparison(rows: list[dict]) -> dict:
    result = {}
    conditions = sorted({c for row in rows for c in row["llm"]})
    for condition in conditions:
        passes = sorted({a["pass"] for row in rows for a in row["llm"].get(condition, [])})
        per_pass = {}
        for p in passes:
            answers = [(row, next((a for a in row["llm"].get(condition, []) if a["pass"] == p), None)) for row in rows]
            judged = [(row, a) for row, a in answers if a is not None and a["state"] in {"completed", "invalid_response"}]
            pairs = [(row["reference"], a["status"]) for row, a in judged]
            counts = _confusion(pairs)
            usable = [(row, a) for row, a in judged if a["status"] is not None]
            exact = sum(
                all(a is not None and a["status"] == row["reference"] for row, a in answers if row["question_id"] == q)
                for q in sorted({row["question_id"] for row in rows}))
            rng = random.Random(BOOTSTRAP_SEED)
            samples = sorted(
                f for f in (_f1(_confusion([pairs[rng.randrange(len(pairs))] for _ in pairs]))
                            for _ in range(BOOTSTRAP_RESAMPLES)) if f is not None) if pairs else []
            per_pass[str(p)] = {
                "per_question": per_question([
                    (row, NOT_RUN if a is None or a["state"] not in {"completed", "invalid_response"} else a["status"])
                    for row, a in answers]),
                "citations": citation_summary([(row, a) for row, a in usable if "citations" in a]),
                "findings": len(rows), "judged": len(judged),
                "agreement_with_rules": sum(a["status"] == row["rules"]["status"] for row, a in usable),
                "agreement_with_reference": sum(a["status"] == row["reference"] for row, a in usable),
                "exact_questions": exact, "finding_counts": counts, "f1": _f1(counts),
                "f1_bootstrap_95": [samples[int(0.025 * len(samples))], samples[int(0.975 * len(samples)) - 1]]
                if samples else None,
            }
        f1s = [v["f1"] for v in per_pass.values() if v["f1"] is not None]
        exacts = [v["exact_questions"] for v in per_pass.values()]
        result[condition] = {
            "passes": per_pass,
            "spread": {"f1_min": min(f1s) if f1s else None, "f1_max": max(f1s) if f1s else None,
                       "exact_min": min(exacts) if exacts else None, "exact_max": max(exacts) if exacts else None},
            "method": f"finding-level bootstrap, {BOOTSTRAP_RESAMPLES} resamples, seed {BOOTSTRAP_SEED}; findings of "
                      "one question are not independent, so the interval is optimistic",
        }
    rules = _confusion((row["reference"], row["rules"]["status"]) for row in rows)
    return {"rules": {"finding_counts": rules, "f1": _f1(rules),
                      "agreement_with_reference": sum(row["rules"]["status"] == row["reference"] for row in rows),
                      "findings": len(rows),
                      "per_question": per_question([(row, row["rules"]["status"]) for row in rows])},
            "conditions": result}


def stage_validation(*, g1: dict, g3: dict, packs_complete: bool, checks: dict[str, str], comparison: dict,
                     scores: dict, conditions: list[str]) -> dict:
    coverage = [entry["covered"] for families in g3.get("profile_coverage", {}).values()
                for entry in families.values()]
    collection = g3.get("collection")
    s2 = {
        "required_families_covered": all(coverage),
        "collection_bound_to_g1_image": (None if collection is None
                                         else collection["image_sha256"] == g1["system_image"]["sha256"]),
        "presentation_changed_no_decision": checks.get("presentation") == "passed",
        "sources_unchanged_since_preparation": checks.get("sources") == "passed",
        "subjects_match_generation_receipts": True,
    }
    exact = {question: entry["exact"] for question, entry in comparison.get("rules", {}).get("per_question", {}).items()}
    return {
        "S1": {"status": "passed" if packs_complete else "failed", "checks": {"questions_from_complete_packs": packs_complete}},
        "S2": {"status": "passed" if all(value is not False for value in s2.values()) else "failed", "checks": s2},
        "S3": {"status": "passed" if exact and all(exact.values()) else "failed",
               "exact_questions": f"{sum(exact.values())}/{len(exact)}", "per_question": exact},
        "S3'": {name: ({"status": "executed", **{key: scores[name][key] for key in
                                                 ("exact_question_passes", "planned_question_passes")
                                                 if key in scores[name]}}
                       if name in scores else {"status": "frozen"}) for name in conditions},
    }
