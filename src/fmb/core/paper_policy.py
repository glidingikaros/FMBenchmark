from fmb.core.paper_results import execution_state

MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (2, 5)
PAPER_POLICY = "paper_transport.v1"
ALTERNATE_POLICY = "alternate_route_completion.v1"


def resolve_policy(protocol, *, for_execution=False):
    completion = protocol.get("completion_policy") or {}
    declared = protocol.get("execution_policy")
    if declared is None:
        if for_execution:
            raise ValueError("historical preparations are read-only; freeze the current execution policy before admission")
        replaces = completion.get("replaces", "not_completed")
        if replaces not in {"not_completed", "unanswered"}:
            raise ValueError("unknown completion policy: " + str(replaces))
        return {
            "id": "historical_" + replaces,
            "replaces": replaces,
            "basis": "declared" if "replaces" in completion else "implicit_legacy_default",
            "max_total_attempts": None,
            "request_policy": "not_attested",
        }
    if declared not in {PAPER_POLICY, ALTERNATE_POLICY}:
        raise ValueError("unknown execution policy: " + str(declared))
    if completion and completion.get("replaces") != "unanswered":
        raise ValueError("current completion policy must preserve every returned answer")
    alternate = bool(completion.get("companion_route"))
    if alternate != (declared == ALTERNATE_POLICY):
        raise ValueError("alternate route completion must declare a separate non-paper protocol")
    return {
        "id": declared,
        "replaces": "unanswered",
        "basis": "declared",
        "max_total_attempts": MAX_ATTEMPTS,
        "request_policy": "declared_alternate_route_non_paper" if alternate else "identical_wire_request",
        "backoff_seconds": list(BACKOFF_SECONDS),
        "question": completion.get("question"),
    }


def completion_eligible(outcome, policy, *, question_id=None):
    state = execution_state(outcome)
    if policy["max_total_attempts"] is None:
        return state not in ({"completed"} if policy["replaces"] == "not_completed"
                             else {"completed", "invalid_response"})
    if outcome is None or state in {"completed", "invalid_response"} or outcome.get("response_received"):
        return False
    if policy.get("question") is not None and question_id != policy["question"]:
        return False
    attempts = outcome.get("total_attempts", outcome.get("attempts"))
    if type(attempts) is not int or not 0 <= attempts < MAX_ATTEMPTS:
        return False
    return attempts == 0 or outcome.get("last_attempt_retryable") is True


def validate_attempts(outcome, hashes, request_sha256, *, attempts_before=0):
    attempts = outcome.get("attempts")
    total = outcome.get("total_attempts")
    if (type(attempts) is not int or attempts < 0 or type(total) is not int
            or type(attempts_before) is not int or not 0 <= attempts_before <= MAX_ATTEMPTS
            or total != attempts_before + attempts or total > MAX_ATTEMPTS
            or len(hashes) != attempts or any(digest != request_sha256 for digest in hashes)):
        raise ValueError("attempt evidence or allowance differs from the frozen request")
