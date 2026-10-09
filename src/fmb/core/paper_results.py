from fmb.core.case_contract import target_catalog, validate_response

IDENTITY_FIELDS = ("request_id", "case_id", "question_id", "batch_index", "batches")


def finding_status(two_list: dict, finding_id: str) -> str:
    if finding_id in two_list["supported_findings"]:
        return "supported"
    if finding_id in two_list["insufficient_findings"]:
        return "insufficient"
    return "not_supported"


def finding_statuses(case: dict, response: dict) -> dict:
    validate_response(case, response)
    return {fid: finding_status(response, fid) for fid in target_catalog(case)}


def response_from_decisions(case: dict, decisions: dict) -> dict:
    targets = target_catalog(case)
    expected = {card["subject_id"]: set() for card in case["candidate_roster"]}
    for target in targets.values():
        expected[target["subject_id"]].add(target["component"])
    if not isinstance(decisions, dict) or set(decisions) != set(expected):
        raise ValueError("rule decisions must cover exactly the case subjects")
    for subject, components in expected.items():
        if not isinstance(decisions[subject], dict) or set(decisions[subject]) != components:
            raise ValueError("rule decisions must cover exactly the subject components")
    response = {"supported_findings": [], "insufficient_findings": []}
    for fid, target in targets.items():
        decision = decisions[target["subject_id"]][target["component"]]
        status = decision.get("status") if isinstance(decision, dict) else None
        if status not in ("supported", "not_supported", "insufficient"):
            raise ValueError("rule decision has an invalid status")
        if status != "not_supported":
            response[status + "_findings"].append(fid)
    return {key: sorted(values) for key, values in response.items()}


def validate_rule_result(case: dict, response: dict, decisions: dict) -> None:
    validate_response(case, response)
    expected = response_from_decisions(case, decisions)
    if any(sorted(response[key]) != values for key, values in expected.items()):
        raise ValueError("rule response disagrees with its detailed decisions")


def execution_state(outcome: dict | None) -> str:
    if outcome is None:
        return "missing_outcome"
    status = outcome.get("status")
    if status in {"completed", "invalid_response", "not_attempted", "precheck_refused", "transport_exhausted"}:
        return status
    if status != "execution_failure":
        raise ValueError("unknown terminal execution status: " + str(status))
    kind = (outcome.get("error") or {}).get("type")
    if kind in {"budget_exhausted", "ContextLimitError"}:
        return "precheck_refused"
    return "transport_exhausted" if outcome.get("attempts", 0) else "not_attempted"

