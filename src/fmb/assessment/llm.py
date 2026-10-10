from dataclasses import asdict
from decimal import Decimal
from pathlib import Path
import time
from fmb.core import paper_contract
from fmb.core.paper_artifacts import condition_options
from fmb.core.paper_protocol import SAFETY_RESERVE_TOKENS
from fmb.core.paper_results import IDENTITY_FIELDS
from fmb.core.paper_policy import BACKOFF_SECONDS, MAX_ATTEMPTS, completion_eligible, resolve_policy
from fmb.assessment.completion import bind_completion, claim_execution
from fmb.core.errors import FmbError
from fmb.core.hashing import sha256_bytes
from fmb.core.sealed_records import now, read_json, parse_json, write_json, seal_directory
from fmb.interpretation.paper_payload import wire
from fmb.interpretation.provider import call_llm, exact_input_tokens, is_retryable_http_status
from fmb.interpretation.response_audit import RetainedProviderCall
from fmb.interpretation.context_fit import preflight_context_fit

def _selected_rows(schedule: list, protocol: dict, pass_limit: int | None, question_ids: list | None) -> list:
    if pass_limit is not None:
        if isinstance(pass_limit, bool) or not isinstance(pass_limit, int) or not 1 <= pass_limit <= protocol["passes"]:
            raise ValueError("pass limit must be between 1 and the protocol's passes")
        schedule = [row for row in schedule if row["pass"] <= pass_limit]
    if question_ids is not None:
        if (not question_ids or len(set(question_ids)) != len(question_ids)
                or not set(question_ids) <= {row["question_id"] for row in schedule}):
            raise ValueError("question selection must name distinct scheduled questions")
        schedule = [row for row in schedule if row["question_id"] in question_ids]
    return schedule


def _cap_and_rates(cap_usd, rates: dict) -> tuple[Decimal, dict]:
    cap = Decimal(str(cap_usd))
    if not cap.is_finite() or cap <= 0:
        raise ValueError("a positive explicit exposure cap is required")
    rate = {k: Decimal(str(rates[k])) for k in ("input", "output")}
    if any(not r.is_finite() or r < 0 for r in rate.values()):
        raise ValueError("invalid explicit rate policy")
    return cap, rate


def _identity(row: dict) -> dict:
    return {k: row[k] for k in (*IDENTITY_FIELDS, "pass", "call")}


def _precheck(root: Path, row: dict, counter) -> tuple[dict, bytes, dict]:
    kwargs = read_json(root / "requests" / (row["request_id"] + ".kwargs.json"))
    body = wire(kwargs)
    if sha256_bytes(body) != row["request_sha256"]:
        raise ValueError("dispatch body changed")

    def context_fit(**exact):
        return preflight_context_fit(
            request_body=body,
            context_window_tokens=kwargs["context_window_tokens"],
            output_reserve_tokens=kwargs["max_output_tokens"],
            safety_reserve_tokens=SAFETY_RESERVE_TOKENS,
            **exact,
        )

    fit = context_fit()
    if not fit["fits"] and counter is not None:
        try:
            exact = counter(kwargs, body)
        except Exception as error:
            fit["exact_count_error"] = f"{type(error).__name__}: {str(error)[:300]}"
        else:
            if exact is not None:
                fit = {**context_fit(exact_input_tokens=exact),
                       "byte_bound": {k: fit[k] for k in ("input_tokens", "required_total_tokens", "margin_tokens")}}
    return kwargs, body, fit


def _usage_cost(usage, cost) -> Decimal | None:
    if usage and all(type(usage.get(k)) is int and usage[k] >= 0 for k in ("input_tokens", "output_tokens")):
        return cost(usage["input_tokens"], usage["output_tokens"])
    return None


def _validate_answer(root: Path, row: dict, folder: Path, outcome: dict, response, kwargs: dict, options: dict) -> None:
    write_json(folder / "provider-response.json", asdict(response))
    (folder / "response-text.txt").write_text(response.text)
    try:
        parsed = parse_json(response.text)
        sent = read_json(root / "cases" / (row["request_id"] + ".json"))
        decoded = paper_contract.decode_case(sent, options)
        normalized = paper_contract.to_two_list(
            decoded,
            parsed,
            options,
            sent_schema=kwargs["response_schema"],
        )
    except Exception as error:
        outcome["status"] = "invalid_response"
        outcome["error"] = {
            "type": type(error).__name__,
            "message": str(error)[:500],
        }
    else:
        write_json(folder / "assessment.json", parsed)
        write_json(folder / "two-list.json", normalized)
        outcome["status"] = "completed"


def _seal_run(run: Path, schedule: list, outcomes: list, interrupted: dict | None, spent: Decimal, mock: bool,
              prior: dict) -> None:
    completed = {(o["request_id"], o["pass"]) for o in outcomes}
    for row in schedule:
        if (row["request_id"], row["pass"]) not in completed:
            outcome = {
                **_identity(row),
                "status": "not_attempted",
                "attempts": 0,
                "total_attempts": prior.get((row["request_id"], row["pass"]), {}).get("attempts", 0),
                "response_received": False,
                "last_attempt_retryable": False,
                "error": interrupted,
                "conservative_exposure_usd": "0",
            }
            folder = run / f"call-{row['call']:03d}"
            folder.mkdir(exist_ok=True)
            write_json(folder / "outcome.json", outcome)
            outcomes.append(outcome)
    write_json(
        run / "completion.json",
        {
            "finished_utc": now(),
            "outcomes": outcomes,
            "conservative_exposure_usd": str(spent),
            "mock": mock,
            "interrupted": interrupted,
        },
    )
    seal_directory(run, "prediction-seal.json")


def execute_schedule(
    root: Path,
    *,
    protocol: dict,
    schedule: list,
    cap_usd,
    rates: dict,
    execute: bool = False,
    provider=None,
    sleep=time.sleep,
    pass_limit: int | None = None,
    question_ids: list | None = None,
    development: dict | None = None,
    counter=None,
    primary: Path | None = None,
):
    if counter is None and provider is None:
        counter = exact_input_tokens
    if provider is None and execute is not True:
        raise ValueError("live dispatch requires explicit --execute")
    schedule = _selected_rows(schedule, protocol, pass_limit, question_ids)
    cap, rate = _cap_and_rates(cap_usd, rates)
    root = Path(root).resolve(strict=True)
    if protocol != read_json(root / "protocol.json") or schedule != _selected_rows(
        read_json(root / "schedule.json")["rows"], protocol, pass_limit, question_ids
    ):
        raise ValueError("dispatch differs from the frozen protocol/schedule")
    policy = resolve_policy(protocol, for_execution=True)
    binding, prior = (None, {})
    if protocol.get("completion_policy"):
        binding, prior = bind_completion(root, protocol, schedule, primary)
    elif primary is not None:
        raise ValueError("a primary run cannot be used as a completion template")
    options = condition_options(root, protocol)
    run = root / "run"
    if run.exists():
        raise FileExistsError("execution already exists: " + str(run))
    claim = claim_execution(root, protocol, binding)
    run.mkdir(exist_ok=False)
    write_json(
        run / "schedule.json",
        {
            "rows": schedule,
            "cap_usd": str(cap),
            "rates_usd_per_million": {k: str(v) for k, v in rate.items()},
            "mock": provider is not None,
            "execution_policy": policy,
            "execution_claim": claim,
            "completion_of": binding,
            **({"pass_limit": pass_limit} if pass_limit is not None else {}),
            **({"question_ids": sorted(question_ids)} if question_ids is not None else {}),
            **({"development": development} if development is not None else {}),
        },
    )
    spent = Decimal(0)
    outcomes = []
    interrupted = None
    active = None
    auth_failed = False

    def cost(i, o):
        return (Decimal(i) * rate["input"] + Decimal(o) * rate["output"]) / Decimal(
            1000000
        )

    try:
        for row in schedule:
            folder = run / f"call-{row['call']:03d}"
            folder.mkdir()
            previous = prior.get((row["request_id"], row["pass"]))
            attempts_before = previous["attempts"] if previous else 0
            outcome = {
                **_identity(row),
                "status": "execution_failure",
                "attempts": 0,
                "total_attempts": attempts_before,
                "response_received": False,
                "last_attempt_retryable": False,
                "started_utc": now(),
                "conservative_exposure_usd": "0",
                "error": None,
            }
            active = (folder, outcome)
            if binding is not None and not completion_eligible(previous, policy, question_id=row["question_id"]):
                outcome.update(status="not_attempted", error={"type": "completion_ineligible"}, finished_utc=now())
                write_json(folder / "outcome.json", outcome)
                outcomes.append(outcome)
                active = None
                continue
            kwargs, body, fit = _precheck(root, row, counter)
            write_json(folder / "context-precheck.json", fit)
            reservation = cost(len(body), kwargs["max_output_tokens"])
            audit = RetainedProviderCall(
                folder / "attempts", delegate=provider or call_llm
            )
            response = None
            exposure = Decimal(0)
            for attempt in range(1, MAX_ATTEMPTS - attempts_before + 1):
                if not fit["fits"]:
                    outcome["error"] = {
                        "type": "ContextLimitError",
                        "retryable": False,
                        "basis": fit["input_token_basis"],
                    }
                    break
                if auth_failed:
                    outcome["error"] = {
                        "type": "authentication_stop",
                        "retryable": False,
                    }
                    break
                if spent + reservation > cap:
                    outcome["error"] = {"type": "budget_exhausted", "retryable": False}
                    break
                outcome["attempts"] = attempt
                outcome["total_attempts"] = attempts_before + attempt
                charged = reservation
                spent += charged
                exposure += charged
                outcome["conservative_exposure_usd"] = str(exposure)
                write_json(folder / "outcome.json", outcome)
                try:
                    response = audit(**{**kwargs, "context_window_tokens": None})
                    outcome["response_received"] = True
                    outcome["last_attempt_retryable"] = False
                    observed = _usage_cost(response.usage, cost)
                    if observed is not None:
                        spent += observed - charged
                        exposure += observed - charged
                    outcome["error"] = None
                except Exception as error:
                    retryable = (
                        isinstance(error, FmbError)
                        and error.details.get("retryable") is True
                        and error.details.get("provider_failure_stage") != "response_shape"
                        and not error.details.get("usage")
                        and (error.details.get("provider_failure_stage") == "transport" or is_retryable_http_status(
                            error.details.get("http_status", error.details.get("status_code"))))
                    )
                    outcome["last_attempt_retryable"] = retryable
                    outcome["error"] = {
                        "type": type(error).__name__,
                        "message": str(error)[:500],
                        "retryable": retryable,
                    }
                    if isinstance(error, FmbError) and error.details.get(
                        "http_status", error.details.get("status_code")
                    ) in (401, 403):
                        auth_failed = True
                    usage = (
                        error.details.get("usage")
                        if isinstance(error, FmbError)
                        else None
                    )
                    returned_unusable = (
                        isinstance(error, FmbError)
                        and error.details.get("provider_failure_stage") == "response_shape"
                        and error.details.get("provider_failure_kind") != "billing_error"
                    )
                    if (usage or returned_unusable) and not retryable:
                        outcome["status"] = "invalid_response"
                        outcome["response_received"] = True
                        write_json(
                            folder / "provider-response.json",
                            {"usage": usage, "returned_error": outcome["error"]},
                        )
                        observed = _usage_cost(usage, cost)
                        if observed is not None:
                            spent += observed - charged
                            exposure += observed - charged
                    if not retryable or outcome["total_attempts"] == MAX_ATTEMPTS:
                        break
                    sleep(BACKOFF_SECONDS[outcome["total_attempts"] - 1])
                else:
                    break
                finally:
                    outcome["conservative_exposure_usd"] = str(exposure)
            if response is not None:
                _validate_answer(root, row, folder, outcome, response, kwargs, options)
            outcome["finished_utc"] = now()
            write_json(folder / "outcome.json", outcome)
            outcomes.append(outcome)
            active = None
    except BaseException as error:
        interrupted = {"type": type(error).__name__, "message": str(error)[:500]}
        if active:
            folder, outcome = active
            outcome.update(error=interrupted, finished_utc=now())
            write_json(folder / "outcome.json", outcome)
            outcomes.append(outcome)
        raise
    finally:
        _seal_run(run, schedule, outcomes, interrupted, spent, provider is not None, prior)
    return {
        "scheduled_calls": len(schedule),
        "completed": sum(o["status"] == "completed" for o in outcomes),
        "conservative_exposure_usd": str(spent),
        "mock": provider is not None,
    }
