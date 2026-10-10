from __future__ import annotations

import time
from pathlib import Path

from fmb.core import paper_contract
from fmb.core import paper_integrity as integrity
from fmb.core.hashing import sha256_file
from fmb.core.paper_artifacts import build_content_sha256, preparation_folder
from fmb.core.paper_results import validate_rule_result
from fmb.core.sealed_records import contained_path, now, read_json, seal_directory, verify_seal, write_json

SCHEMA = "paper_rule_assessment.v1"
SEAL = "assessment-seal.json"


class RulesEngine:

    id = "rules"
    module = "fmb.assessment.rules"

    def decide(self, case: dict) -> tuple[dict, dict]:
        from fmb.assessment.rules import assess_with_decisions

        return assess_with_decisions(case)


ENGINES = {"rules": RulesEngine()}


def engine(name: str):
    if name not in ENGINES:
        raise ValueError("unknown S3 engine: " + str(name) + "; registered: " + ", ".join(sorted(ENGINES)))
    return ENGINES[name]


def decode_for_engine(sent: dict, options: dict, definitions: dict | None) -> dict:
    case = paper_contract.decode_case(sent, options)
    qid = case["question"]["question_id"]
    if definitions is not None:
        declared = definitions.get(qid)
        if declared is None:
            raise ValueError("G2 declares no definition for " + qid)
        if case["question"] != declared:
            raise ValueError("the decoded question block differs from the declared definition: " + qid)
    return case


def assess_cards(*, built: Path, output: Path, engine_name: str = "rules",
                 question_definitions: dict | None = None, generation: Path | None = None,
                 assessor=None) -> dict:
    from fmb.core.paper_artifacts import build_generation, guard_record
    from fmb.core.truth_guard import truth_blind_reads

    built = Path(built).resolve(strict=True)
    verify_seal(built, "build-seal.json")
    report = read_json(built / "build-report.json")
    if (preparation_folder(built, report) / "admission").exists():
        raise ValueError("S3 must decide before admission opens the reference")
    chosen = engine(engine_name) if assessor is None else assessor
    options = paper_contract.bind_options(read_json(built / "view-options.json"), built)
    requests = read_json(built / "build-seal.json")["requests"]
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    started, rows = time.monotonic(), []
    with truth_blind_reads(Path(generation) if generation is not None else build_generation(built)) as guard:
        for request_id, binding in requests.items():
            path = contained_path(built, "sent/" + request_id + ".json")
            if sha256_file(path) != binding["sent_sha256"]:
                raise ValueError("sent card differs from the build: " + request_id)
            case = decode_for_engine(read_json(path), options, question_definitions)
            measured = time.perf_counter()
            response, decisions = chosen.decide(case)
            elapsed = time.perf_counter() - measured
            validate_rule_result(case, response, decisions)
            write_json(output / "deterministic" / (request_id + ".json"), response)
            write_json(output / "decisions" / (request_id + ".json"),
                       {"request_id": request_id, "question_id": case["question"]["question_id"],
                        "decisions": decisions})
            rows.append({"request_id": request_id, "question_id": case["question"]["question_id"],
                         "supported": len(response["supported_findings"]),
                         "insufficient": len(response["insufficient_findings"]),
                         "elapsed_seconds": round(elapsed, 6)})
    if guard["denied"]:
        raise ValueError("S3 attempted a private read")
    write_json(output / "assessment.json", {
        "schema_version": SCHEMA,
        "engine": {"id": chosen.id, "module": chosen.module,
                   "source_manifest_sha256": integrity.source_manifest_sha256()},
        "reads": "the sent card of every request, decoded by the engine's adapter",
        "build_seal_sha256": sha256_file(built / "build-seal.json"),
        "build_content_sha256": build_content_sha256(built),
        "view_options_sha256": sha256_file(built / "view-options.json"),
        "question_definitions": question_definitions,
        "requests": rows,
        "truth_sources_used": [],
        "truth_guard": guard_record(guard),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "assessed_utc": now(),
    })
    seal_directory(output, SEAL)
    return {"status": "assessed", "engine": chosen.id, "requests": len(rows), "output": str(output),
            "assessment_sha256": sha256_file(output / "assessment.json")}


def verify_assessment(rules: Path, *, built: Path) -> dict:
    rules, built = Path(rules).resolve(strict=True), Path(built).resolve(strict=True)
    verify_seal(rules, SEAL)
    record = read_json(rules / "assessment.json")
    if record.get("schema_version") != SCHEMA or record.get("truth_sources_used") != []:
        raise ValueError("not a sealed S3 rule assessment")
    if record["build_seal_sha256"] != sha256_file(built / "build-seal.json"):
        raise ValueError("the S3 assessment belongs to another build")
    requests = read_json(built / "build-seal.json")["requests"]
    if (len(record["requests"]) != len(requests)
            or {row["request_id"] for row in record["requests"]} != set(requests)):
        raise ValueError("the S3 assessment does not cover every request of the build")
    options = paper_contract.bind_options(read_json(built / "view-options.json"), built)
    for request_id in requests:
        sent = read_json(contained_path(built, "sent/" + request_id + ".json"))
        case = decode_for_engine(sent, options, record["question_definitions"])
        rule_result(rules, request_id, case)
    return record


def rule_result(rules: Path, request_id: str, case: dict) -> tuple[dict, dict]:
    response = read_json(contained_path(Path(rules), "deterministic/" + request_id + ".json"))
    record = read_json(contained_path(Path(rules), "decisions/" + request_id + ".json"))
    if record["request_id"] != request_id or record["question_id"] != case["question"]["question_id"]:
        raise ValueError("rule decisions belong to another request")
    decisions = record["decisions"]
    validate_rule_result(case, response, decisions)
    return response, decisions
