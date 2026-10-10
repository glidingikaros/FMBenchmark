from fmb.analysis.factual_contract import deterministic_factual_response
from fmb.core.case_contract import bundle_from_case
from fmb.core.paper_results import finding_statuses, response_from_decisions

def assess_with_decisions(case: dict) -> tuple[dict, dict]:
    factual = deterministic_factual_response(bundle_from_case(case))
    decisions = {
        sid: {t: {"status": d["status"], "evidence_refs": list(d.get("evidence_refs", [])),
                  "statement": d.get("statement")} for t, d in components.items()}
        for sid, components in factual["assessments"].items()
    }
    return response_from_decisions(case, decisions), decisions


def assess(case: dict) -> dict:
    return assess_with_decisions(case)[0]


def statuses(case: dict) -> dict:
    return finding_statuses(case, assess(case))
