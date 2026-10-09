from fmb.assessment.rules import assess_with_decisions
from fmb.core.paper_results import response_from_decisions


def decide(case):
    _, decisions = assess_with_decisions(case)
    return response_from_decisions(case, decisions), decisions
