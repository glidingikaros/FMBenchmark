from __future__ import annotations

from collections import Counter
from datetime import datetime
from decimal import Decimal
from pathlib import Path
import jsonschema

from fmb.core import paper_contract
from fmb.evaluation.admission import reference_file
from fmb.core.case_contract import SYSTEM_PROMPT, target_catalog
from fmb.core.paper_artifacts import condition_options
from fmb.core.paper_results import IDENTITY_FIELDS, execution_state, finding_status
from fmb.core.paper_policy import completion_eligible, resolve_policy, validate_attempts
from fmb.core.hashing import sha256_file
from fmb.core.paper_protocol import (
    validate_condition,
    validate_request_settings,
    validate_completion_policy,
)
from fmb.core.sealed_records import (
    canonical_json,
    read_json,
    sha256_json,
    contained_path,
    verify_seal,
)

SCORER_VERSION = "paper_schedule_scores.v2"


def _key(row):
    if (
        not isinstance(row.get("request_id"), str)
        or type(row.get("pass")) is not int
        or row["pass"] < 1
    ):
        raise ValueError("invalid request/pass identity")
    return row["request_id"], row["pass"]


def index_outcomes(rows):
    result = {}
    for row in rows:
        key = _key(row)
        if key in result:
            raise ValueError("duplicate outcome for request/pass: " + str(key))
        result[key] = row
    return result


def _duration(outcome):
    start = datetime.fromisoformat(outcome["started_utc"])
    finish = datetime.fromisoformat(outcome["finished_utc"])
    if start.tzinfo is None or finish.tzinfo is None or finish < start:
        raise ValueError("invalid timezone-aware outcome interval")
    return Decimal(str((finish - start).total_seconds()))


def score_schedule(
    schedule, references, primary, *, companion=None, question_ids=None, passes=None, replaces="not_completed", policy=None
):
    policy = policy or resolve_policy({"completion_policy": {"replaces": replaces}})
    planned = index_outcomes(schedule)
    if not planned:
        raise ValueError("empty schedule")
    primary = index_outcomes(primary)
    companion = index_outcomes(companion or [])
    if (set(primary) | set(companion)) - set(planned):
        raise ValueError("outcome is outside the planned schedule")
    questions = list(question_ids or sorted({r["question_id"] for r in schedule}))
    pass_ids = list(passes or sorted({r["pass"] for r in schedule}))
    if len(set(questions)) != len(questions) or len(set(pass_ids)) != len(pass_ids):
        raise ValueError("duplicate declared question or pass")
    exact = {(q, p): True for q in questions for p in pass_ids}
    counts = {q: Counter() for q in questions}
    scheduled_cells = {(r["question_id"], r["pass"]) for r in schedule}
    if scheduled_cells - set(exact):
        raise ValueError("schedule uses undeclared question/pass")
    for cell in set(exact) - scheduled_cells:
        exact[cell] = False
    seconds = Decimal(0)
    cost = Decimal(0)
    tokens = Counter()
    states = Counter()
    selections = []
    seen_findings = {}
    for key, row in planned.items():
        q, p = row["question_id"], row["pass"]
        expected = references[row["case_id"]]["expected_status"]
        if not expected or set(expected.values()) - {"supported", "not_supported"}:
            raise ValueError("paper references must contain resolved factual findings")
        cell = (q, p)
        seen = seen_findings.setdefault(cell, set())
        if seen & set(expected):
            raise ValueError("finding scored more than once in question/pass")
        seen.update(expected)
        selected = primary.get(key)
        route = "primary"
        alternate = companion.get(key)
        for outcome in (selected, alternate):
            if outcome is None:
                continue
            if any(outcome.get(f) != row.get(f) for f in IDENTITY_FIELDS):
                raise ValueError("outcome identity differs from schedule")
            if not row.get("binding") or outcome.get("binding") != row["binding"]:
                raise ValueError("outcome input/schema binding differs from schedule")
        if (
            completion_eligible(selected, policy, question_id=q)
            and execution_state(alternate) in (
                {"completed", "invalid_response"} if policy["max_total_attempts"] is not None else {"completed"}
            )
        ):
            selected, route = alternate, "companion"
        state = execution_state(selected)
        states[state] += 1
        selections.append(
            {
                "request_id": key[0],
                "pass": key[1],
                "question_id": q,
                "source": route if selected else None,
                "state": state,
            }
        )
        if state not in {"completed", "invalid_response"}:
            exact[cell] = False
            continue
        amount = Decimal(str(selected.get("conservative_exposure_usd", "0")))
        if not amount.is_finite() or amount < 0:
            raise ValueError("invalid selected exposure")
        cost += amount
        seconds += _duration(selected)
        usage = selected.get("usage", {})
        for name in ("input_tokens", "output_tokens"):
            value = usage.get(name, 0)
            if type(value) is not int or value < 0:
                raise ValueError("invalid selected token count")
            tokens[name] += value
        if state == "invalid_response":
            exact[cell] = False
            counts[q]["unusable"] += 1
            counts[q]["fn"] += sum(v == "supported" for v in expected.values())
            continue
        two = selected["two_list"]
        supported, insufficient = (
            two["supported_findings"],
            two["insufficient_findings"],
        )
        if (
            len(supported) != len(set(supported))
            or len(insufficient) != len(set(insufficient))
            or set(supported) & set(insufficient)
            or (set(supported) | set(insufficient)) - set(expected)
        ):
            raise ValueError("invalid or out-of-universe status lists")
        for fid, want in expected.items():
            got = finding_status(two, fid)
            if got != want:
                exact[cell] = False
            if want == "supported":
                counts[q]["tp" if got == "supported" else "fn"] += 1
                counts[q]["fn_abstained"] += got == "insufficient"
            else:
                counts[q][
                    "fp"
                    if got == "supported"
                    else "unresolved"
                    if got == "insufficient"
                    else "tn"
                ] += 1
    total = Counter()
    for c in counts.values():
        total.update(c)

    def f1(c):
        denominator = 2 * c["tp"] + c["fp"] + c["fn"]
        return float(Decimal(2 * c["tp"]) / denominator) if denominator else None

    every = sum(all(exact[q, p] for p in pass_ids) for q in questions)
    return {
        "schema_version": SCORER_VERSION,
        "planned_requests": len(schedule),
        "questions": len(questions),
        "passes": pass_ids,
        "planned_question_passes": len(exact),
        "exact_question_passes": sum(exact.values()),
        "every_pass": every,
        "exact_all_passes": {"numerator": every, "denominator": len(questions)},
        "per_question": {
            q: {
                "exact_passes": [p for p in pass_ids if exact[q, p]],
                "planned_passes": pass_ids,
                "counts": dict(counts[q]),
                "f1": f1(counts[q]),
            }
            for q in questions
        },
        "finding_counts": {
            k: total[k]
            for k in ("tp", "fn", "fp", "tn", "unresolved", "unusable", "fn_abstained")
        },
        "f1": f1(total),
        "execution_states": dict(states),
        "selected_exposure_usd": str(cost),
        "selected_request_seconds_sum": str(seconds),
        "selected_tokens": dict(tokens),
        "selection": selections,
        "metric_policy": {
            "exact": "all planned requests and findings, every declared pass",
            "finding_metrics": "selected completed answers; invalid returned answers miss their positives; no-answer excluded",
            "resources": "selected returned answers including unusable; no-answer and superseded routes excluded",
            "time": "sum of request durations; not elapsed wall-clock time",
            "reasons": "format validated; content not scored",
        },
    }


def _wire_semantics(body):
    if "messages" in body:
        messages = body["messages"]
        if [r.get("role") for r in messages] != ["system", "user"]:
            raise ValueError("request must be one stateless system/user pair")
        instruction, prompt = messages[0]["content"], messages[1]["content"]
        schema = body["response_format"]["json_schema"]["schema"]
    else:
        instruction, prompt = body["instructions"], body["input"]
        schema = body["text"]["format"]["schema"]
    return {
        "instruction": instruction,
        "case": read_case_text(prompt),
        "schema": schema,
        "model": body.get("model"),
        "reasoning": body.get("reasoning"),
        "max_output_tokens": body.get("max_output_tokens", body.get("max_tokens")),
        "sampling": {
            key: body[key] for key in ("temperature", "top_p", "seed") if key in body
        },
    }


def read_case_text(text):
    from fmb.core.sealed_records import parse_json

    if not isinstance(text, str):
        raise ValueError("paper request input must be a JSON string")
    return parse_json(text)


def load_run(root: Path):
    root = Path(root).resolve(strict=True)
    prepared_seal = verify_seal(root)
    prediction_seal = verify_seal(root / "run", "prediction-seal.json")
    if not {"manifest.json", "protocol.json"} <= set(prepared_seal["files"]):
        raise ValueError("preparation metadata is not sealed")
    if "schedule.json" not in prediction_seal["files"]:
        raise ValueError("prediction schedule is not sealed")
    manifest = read_json(root / "manifest.json")
    protocol = read_json(root / "protocol.json")
    validate_condition(protocol.get("settings"), condition=protocol.get("condition_id"))
    if protocol.get("level") != "L0N":
        raise ValueError("only the frozen paper presentation is supported")
    options = condition_options(root, protocol)
    passes = protocol.get("passes")
    if type(passes) is not int or passes != 3:
        raise ValueError("paper runs require three planned passes")
    requests = {}
    cases = {}
    for row in manifest["rows"]:
        request_id = row["request_id"]
        if request_id in requests:
            raise ValueError("duplicate request in manifest")
        path = contained_path(root, "cases/" + request_id + ".json")
        sent = read_json(path)
        if sha256_json(sent) != row["case_sha256"]:
            raise ValueError("case differs from its manifest")
        wire = contained_path(root, "requests/" + request_id + ".json")
        if sha256_file(wire) != row["request_sha256"]:
            raise ValueError("request body differs from its manifest")
        body = read_json(wire)
        kwargs_path = contained_path(root, "requests/" + request_id + ".kwargs.json")
        kwargs = None
        if kwargs_path.exists():
            if kwargs_path.relative_to(root).as_posix() not in prepared_seal["files"]:
                raise ValueError("request kwargs are not sealed")
            kwargs = read_json(kwargs_path)
        validate_request_settings(body, protocol["settings"], kwargs=kwargs)
        semantics = _wire_semantics(body)
        if semantics["instruction"] != SYSTEM_PROMPT:
            raise ValueError("request instruction differs from the paper protocol")
        if canonical_json(semantics["case"]) != canonical_json(sent):
            raise ValueError("wire request contains different case evidence")
        case = paper_contract.decode_case(sent, options)
        if case["question"]["question_id"] != row["question_id"]:
            raise ValueError("manifest question differs from case")
        binding = {
            "semantics_sha256": sha256_json(semantics),
            "finding_ids": sorted(target_catalog(case)),
            "case_sha256": row["case_sha256"],
        }
        requests[request_id] = {**row, "binding": binding}
        cases[request_id] = (case, semantics["schema"])
    run_schedule = read_json(root / "run/schedule.json")
    schedule = run_schedule["rows"]
    executed = run_schedule.get("pass_limit", passes)
    if type(executed) is not int or not 1 <= executed <= passes:
        raise ValueError("invalid recorded pass limit")
    questions = run_schedule.get("question_ids")
    if questions is not None:
        planned = {row["question_id"] for row in requests.values()}
        if (not isinstance(questions, list) or not questions or len(set(questions)) != len(questions)
                or not set(questions) <= planned):
            raise ValueError("invalid recorded question limit")
        requests = {rid: row for rid, row in requests.items() if row["question_id"] in questions}
    indexed = index_outcomes(schedule)
    if set(indexed) != {(rid, p) for rid in requests for p in range(1, executed + 1)}:
        raise ValueError("schedule does not cover the complete request/pass universe")
    bound_schedule = []
    for row in schedule:
        request = requests[row["request_id"]]
        if any(
            row.get(k) != request.get(k)
            for k in (*IDENTITY_FIELDS, "case_sha256", "request_sha256")
        ):
            raise ValueError("schedule differs from preparation manifest")
        bound_schedule.append({**row, "binding": request["binding"]})
    outcomes, outcome_files = [], {}
    for path in sorted((root / "run").glob("call-*/outcome.json")):
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("symlinked outcome")
        if path.relative_to(root / "run").as_posix() not in prediction_seal["files"]:
            raise ValueError("unsealed outcome was added after execution")
        outcome = read_json(path)
        key = _key(outcome)
        outcome_files[key] = {"path": path.relative_to(root / "run").as_posix(), "sha256": sha256_file(path)}
        if key not in indexed:
            raise ValueError("outcome outside schedule")
        outcome["binding"] = requests[key[0]]["binding"]
        if outcome["status"] == "completed":
            for name in ("assessment.json", "two-list.json", "provider-response.json"):
                if (path.parent / name).relative_to(
                    root / "run"
                ).as_posix() not in prediction_seal["files"]:
                    raise ValueError("completed response artifact is not sealed")
            case, schema = cases[key[0]]
            assessment = read_json(path.parent / "assessment.json")
            try:
                normalized = paper_contract.to_two_list(
                    case, assessment, options, sent_schema=schema
                )
            except (
                ValueError,
                KeyError,
                TypeError,
                jsonschema.ValidationError,
            ) as error:
                outcome["status"] = "invalid_response"
                outcome["revalidation_error"] = str(error)[:500]
            else:
                stored = read_json(path.parent / "two-list.json")
                if normalized != stored:
                    raise ValueError(
                        "stored normalized answer differs from original assessment"
                    )
                outcome["two_list"] = normalized
        if (
            outcome["status"] in {"completed", "invalid_response"}
            and (path.parent / "provider-response.json").exists()
        ):
            outcome["usage"] = (
                read_json(path.parent / "provider-response.json").get("usage") or {}
            )
        outcomes.append(outcome)
    index_outcomes(outcomes)
    if "execution_policy" in protocol or {"execution_policy", "execution_claim"} & run_schedule.keys():
        _validate_execution_record(protocol, run_schedule, prediction_seal, outcomes, outcome_files, root)
    return {
        "root": str(root),
        "schedule": bound_schedule,
        "outcomes": outcomes,
        "requests": requests,
        "protocol": protocol,
        "passes_executed": executed,
        "questions_executed": sorted(questions) if questions is not None else None,
        "run_schedule": run_schedule,
        "preparation_files": prepared_seal["files"],
        "prediction_files": prediction_seal["files"],
        "preparation_seal_sha256": sha256_file(root / "preparation-seal.json"),
        "prediction_seal_sha256": sha256_file(root / "run/prediction-seal.json"),
        "outcome_files": outcome_files,
    }


def score_run(
    primary: Path, *, companion: Path | None = None, reference_path: Path | None = None
):
    a = load_run(primary)
    b = load_run(companion) if companion is not None else None
    return score_loaded_runs(a, b, reference_path=reference_path)


def score_loaded_runs(a, b=None, *, reference_path=None):
    primary = Path(a["root"])
    companion = Path(b["root"]) if b else None
    policy = resolve_policy((b or a)["protocol"])
    if a["protocol"].get("execution_policy") and a["protocol"].get("completion_policy"):
        raise ValueError("score a current completion together with its bound primary")
    if b:
        validate_completion_policy(a["protocol"]["settings"], b["protocol"]["settings"])
        if b.get("passes_executed", 3) != a.get("passes_executed", 3):
            raise ValueError("companion executed different passes")
        if b.get("questions_executed") != a.get("questions_executed"):
            raise ValueError("companion executed different questions")
        for rid, row in b["requests"].items():
            if (
                rid not in a["requests"]
                or row["binding"] != a["requests"][rid]["binding"]
            ):
                raise ValueError(
                    "companion has a different frozen input/schema/condition"
                )
        if a["protocol"].get("execution_policy") or b["protocol"].get("execution_policy"):
            _validate_completion_binding(a, b, policy)
    reference_path = reference_file(primary, reference_path)
    refs = read_json(reference_path)
    for row in a["requests"].values():
        if set(refs[row["case_id"]]["expected_status"]) != set(row["binding"]["finding_ids"]):
            raise ValueError("reference does not cover the exact finding universe")
    result = score_schedule(
        a["schedule"],
        refs,
        a["outcomes"],
        companion=b["outcomes"] if b else None,
        question_ids=sorted({r["question_id"] for r in a["requests"].values()}),
        passes=list(range(1, a.get("passes_executed", 3) + 1)),
        policy=policy,
    )
    result["provenance"] = {
        "primary": a["root"],
        "companion": b["root"] if b else None,
        "reference_sha256": sha256_file(reference_path),
        "primary_preparation_seal_sha256": sha256_file(
            Path(primary) / "preparation-seal.json"
        ),
        "companion_preparation_seal_sha256": sha256_file(
            Path(companion) / "preparation-seal.json"
        )
        if b
        else None,
        "completion_replaces": policy["replaces"],
        "selection_policy": policy,
        "primary_prediction_seal_sha256": a["prediction_seal_sha256"],
        "companion_prediction_seal_sha256": b["prediction_seal_sha256"] if b else None,
    }
    from fmb.evaluation.lineage import selection_lineage

    result["lineage"] = selection_lineage(a, b, result["selection"])
    return result


def _validate_execution_record(protocol, record, prediction_seal, outcomes, outcome_files, root):
    policy = resolve_policy(protocol, for_execution=True)
    claim = record.get("execution_claim") or {}
    binding = record.get("completion_of")
    if (record.get("execution_policy") != policy or claim.get("execution_policy") != policy
            or claim.get("preparation_seal_sha256") != sha256_file(root / "preparation-seal.json")
            or claim.get("completion_of") != binding
            or bool(binding) != bool(protocol.get("completion_policy"))
            or "completion.json" not in prediction_seal["files"]):
        raise ValueError("execution record differs from its frozen policy/binding")
    terminal = index_outcomes(read_json(root / "run/completion.json")["outcomes"])
    planned = index_outcomes(record["rows"])
    if set(terminal) != set(planned) or set(outcome_files) != set(planned):
        raise ValueError("terminal execution does not cover its planned schedule")
    prior = index_outcomes(binding["calls"]) if binding else {}
    files = prediction_seal["files"]
    if {name for name in files if name.endswith("/outcome.json")} != {r["path"] for r in outcome_files.values()}:
        raise ValueError("current execution contains unbound additional rounds")
    for outcome in outcomes:
        key = _key(outcome)
        path = outcome_files[key]["path"]
        raw = read_json(root / "run" / path)
        if raw != terminal.get(key) or any(
            raw.get(k) != planned[key].get(k) for k in (*IDENTITY_FIELDS, "pass", "call")
        ):
            raise ValueError("terminal outcome differs from the sealed execution record")
        prefix = path.rsplit("/", 1)[0] + "/attempts/"
        hashes = [digest for name, digest in files.items() if name.startswith(prefix) and name.endswith("/request-body.json")]
        validate_attempts(raw, hashes, planned[key]["request_sha256"], attempts_before=prior.get(key, {}).get("attempts_before", 0))


def _validate_completion_binding(a, b, policy):
    if not a["protocol"].get("execution_policy") or not b["protocol"].get("completion_policy"):
        raise ValueError("current completion cannot use an unbound historical execution")
    binding = b["run_schedule"].get("completion_of") or {}
    if any(binding.get(key) != a[key] for key in ("preparation_seal_sha256", "prediction_seal_sha256")):
        raise ValueError("completion is bound to a different primary execution")
    calls = index_outcomes(binding.get("calls", []))
    primary, companion = index_outcomes(a["outcomes"]), index_outcomes(b["outcomes"])
    if set(calls) != set(primary) or set(companion) != set(primary):
        raise ValueError("completion binding does not cover the executed schedule")
    for key, record in calls.items():
        before, after = primary[key], companion[key]
        if (record.get("primary_outcome_sha256") != a["outcome_files"][key]["sha256"]
                or record.get("primary_request_sha256") != a["requests"][key[0]]["request_sha256"]
                or record.get("attempts_before") != before.get("attempts")
                or record.get("eligible") != completion_eligible(before, policy, question_id=before["question_id"])):
            raise ValueError("completion selection differs from its primary terminal evidence")
        attempts = after.get("attempts")
        total = after.get("total_attempts")
        if (type(attempts) is not int or attempts < 0 or type(total) is not int
                or total != before["attempts"] + attempts or total > policy["max_total_attempts"]
                or (not record["eligible"] and attempts)):
            raise ValueError("completion exceeded its primary attempt allowance")
