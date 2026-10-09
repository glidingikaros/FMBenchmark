from __future__ import annotations

from pathlib import Path

from fmb.core import paper_contract
from fmb.core.case_contract import QIDS
from fmb.core.hashing import sha256_file
from fmb.core.paper_results import finding_statuses, validate_rule_result
from fmb.core.sealed_records import contained_path, now, read_json, verify_seal

SCHEMA = "paper_presentation_check.v1"


def check_presentation(*, prepared: Path, built: Path, engine_name: str = "rules") -> dict:
    from fmb.assessment.stage import engine

    prepared, built = Path(prepared).resolve(strict=True), Path(built).resolve(strict=True)
    verify_seal(prepared)
    verify_seal(built, "build-seal.json")
    chosen = engine(engine_name)
    options = paper_contract.bind_options(read_json(built / "view-options.json"), built)

    def statuses(case: dict) -> dict:
        response, decisions = chosen.decide(case)
        validate_rule_result(case, response, decisions)
        return finding_statuses(case, response)

    selected = read_json(built / "build-report.json").get("selected_questions", list(QIDS))
    production = {qid: statuses(read_json(prepared / "cases" / (qid + ".json"))) for qid in QIDS if qid in selected}
    requests = read_json(built / "build-seal.json")["requests"]
    differences, decoded_equals_case = [], 0
    for item in read_json(built / "items.json"):
        request_id, qid = item["case_id"], item["question_id"]
        case = read_json(contained_path(built, "cases/" + request_id + ".json"))
        sent_path = contained_path(built, "sent/" + request_id + ".json")
        if sha256_file(sent_path) != requests[request_id]["sent_sha256"]:
            raise ValueError("sent card differs from the build: " + request_id)
        decoded = paper_contract.decode_case(read_json(sent_path), options)
        expected = {fid: production[qid][fid] for fid in finding_statuses(case, {"supported_findings": [],
                                                                               "insufficient_findings": []})}
        if statuses(case) != expected:
            differences.append({"request_id": request_id, "view": "request case"})
        if statuses(decoded) != expected:
            differences.append({"request_id": request_id, "view": "decoded sent view"})
        decoded_equals_case += decoded == case
    if differences:
        raise ValueError("presenting the cards changed a decision of S3 engine " + chosen.id + ": "
                         + ", ".join(f"{d['request_id']} ({d['view']})" for d in differences))
    return {
        "schema_version": SCHEMA,
        "status": "passed",
        "engine": chosen.id,
        "questions": len(production),
        "requests": len(requests),
        "decoded_sent_view_equals_request_case": decoded_equals_case,
        "build_seal_sha256": sha256_file(built / "build-seal.json"),
        "preparation_seal_sha256": sha256_file(prepared / "preparation-seal.json"),
        "checked_utc": now(),
    }
