from copy import deepcopy
from pathlib import Path
import time

from jsonschema import ValidationError

from fmb.core.case_contract import response_schema, target_catalog
from fmb.core.paper_results import finding_status
from fmb.core.schemas import validate_response_schema
from fmb.core.sealed_records import canonical_json, parse_json, write_json


def mock_response(request: dict) -> str:
    if request["stage"] == "S4":
        return canonical_json(mock_comparison(request["input"]["findings"]))
    if request["stage"] == "S1":
        return canonical_json({key: sorted({name for q in request["input"]["questions"]
                                           for family in q["toolset"].values()
                                           for name in family["collection"][key]})
                               for key in ("targets", "modules")})
    if request["stage"] == "S3":
        return canonical_json({"supported_findings": [],
                               "insufficient_findings": list(target_catalog(request["input"]))})
    if request["stage"] == "S2":
        return canonical_json({"selections": {
            card["subject_id"]: sorted(card["evidence_records"],
                                       key=lambda key: canonical_json(card["evidence_records"][key]))
            for card in request["input"]["candidate_roster"]}})
    raise ValueError("no mock response for " + request["stage"])


class MockCalls:
    def __init__(self, root: Path, responder=None):
        self.root = Path(root)
        self.responder = responder or mock_response
        self.paths = []

    def __call__(self, stage: str, inputs: dict, schema: dict) -> dict:
        request = {"stage": stage, "input": deepcopy(inputs), "response_schema": deepcopy(schema)}
        path = self.root / "mock-calls" / stage / f"{len(self.paths) + 1:05d}.json"
        record = {"schema_version": "fmb.mock_call.v1", "transport": "mock", "request": request,
                  "status": "started", "response": None}
        write_json(path, record)
        self.paths.append(path)
        started = time.monotonic()
        failure = None
        try:
            raw = self.responder(deepcopy(request))
            if not isinstance(raw, str) or len(raw.encode()) > 16 * 1024 * 1024:
                raise ValueError("mock response must be a JSON string of at most 16 MiB")
            record["response"] = raw
            result = parse_json(raw)
            try:
                validate_response_schema(result, schema)
            except ValidationError as error:
                raise ValueError(f"{stage} mock response violates its contract: {error.message}") from error
            record["status"] = "completed"
            return result
        except BaseException as error:
            failure = error
            record.update(status="failed", error={"type": type(error).__name__, "message": str(error)[:1000]})
            raise
        finally:
            record["elapsed_seconds"] = time.monotonic() - started
            try:
                write_json(path, record)
            except OSError as error:
                if failure is None:
                    raise
                failure.add_note(f"failed to retain mock response: {error}")


def default_s1(*, call=None, **kwargs):
    from fmb.profiles import resolve_profile

    return resolve_profile(**kwargs)


def default_s2(*args, call=None, **kwargs):
    from fmb.pipeline.stages import prepare_evidence

    return prepare_evidence(*args, **kwargs)


def mock_s1(*, call, **kwargs):
    from fmb.profiles import collection_choices, resolve_profile, validate_profile

    profile = resolve_profile(**kwargs)
    validate_profile(profile, kwargs.get("questions"))
    choices = collection_choices(profile)
    schema = {"type": "object", "additionalProperties": False, "required": ["targets", "modules"],
              "properties": {key: {"type": "array", "minItems": 1, "uniqueItems": True,
                                   "items": {"enum": names}} for key, names in choices.items()}}
    answer = call("S1", {"questions": profile["questions"], "available": choices}, schema)
    profile["collection"].update(answer)
    validate_profile(profile, kwargs.get("questions"))
    return profile


def default_s3(*, call=None, **kwargs):
    from fmb.paper.workflow import assess_rules

    return assess_rules(**kwargs)


def default_s4(*args, call=None, **kwargs):
    from fmb.pipeline.evaluation import evaluate

    return evaluate(*args, **kwargs)


class MockAssessor:
    id = "mock-llm"
    module = __name__

    def __init__(self, call):
        self.call = call

    def decide(self, case):
        response = self.call("S3", case, response_schema(case))
        decisions = {}
        for fid, target in target_catalog(case).items():
            decisions.setdefault(target["subject_id"], {})[target["component"]] = {
                "status": finding_status(response, fid), "evidence_refs": [],
                "statement": "Deterministic mock LLM response.",
            }
        return response, decisions


def mock_s3(*, call, **kwargs):
    from fmb.paper.workflow import assess_rules

    return assess_rules(**kwargs, assessor=MockAssessor(call))


def assemble_records(case: dict, call) -> dict:
    request = deepcopy(case)
    properties = {}
    for card in request["candidate_roster"]:
        records = {f"e{n:05d}": record for n, record in enumerate(card["evidence_records"])}
        card["evidence_records"] = records
        properties[card["subject_id"]] = {
            "type": "array", "uniqueItems": True,
            "items": {"enum": list(records)} if records else False,
        }
    schema = {"type": "object", "additionalProperties": False, "required": ["selections"],
              "properties": {"selections": {"type": "object", "additionalProperties": False,
                                              "required": list(properties), "properties": properties}}}
    answer = call("S2", request, schema)["selections"]
    result = deepcopy(case)
    for card, source in zip(result["candidate_roster"], request["candidate_roster"]):
        card["evidence_records"] = [source["evidence_records"][key] for key in answer[card["subject_id"]]]
    return result


def mock_s2(*args, call, **kwargs):
    from fmb.pipeline.stages import prepare_evidence

    return prepare_evidence(*args, **kwargs, assemble=lambda case: assemble_records(case, call))


def mock_comparison(findings: list[dict]) -> dict:
    counts = dict.fromkeys(("tp", "fn", "fp", "tn", "unresolved"), 0)
    questions, agreement = {}, 0
    for row in findings:
        reference, answer = row["reference"], row["answer"]
        question = questions.setdefault(row["question_id"], {
            "missed": [], "spurious": [], "unresolved": [], "not_run": [], "exact": True})
        if reference == "supported":
            key = "tp" if answer == "supported" else "fn"
        else:
            key = "fp" if answer == "supported" else "unresolved" if answer == "insufficient" else "tn"
        counts[key] += 1
        if key in {"fn", "fp", "unresolved"}:
            question[{"fn": "missed", "fp": "spurious", "unresolved": "unresolved"}[key]].append(row["display_id"])
        agreement += answer == reference
        question["exact"] = question["exact"] and answer == reference
    denominator = 2 * counts["tp"] + counts["fp"] + counts["fn"]
    return {"rules": {"finding_counts": counts, "findings": len(findings),
                      "f1": 2 * counts["tp"] / denominator if denominator else None,
                      "agreement_with_reference": agreement, "per_question": questions}, "conditions": {}}


def mock_s4(*args, call, **kwargs):
    from fmb.pipeline.evaluation import evaluate

    def compare(rows):
        if any(row["llm"] for row in rows):
            raise ValueError("the mock S4 fixture evaluates S3; model conditions must remain frozen")
        findings = [{key: row[key] for key in ("question_id", "display_id", "reference")}
                    | {"answer": row["rules"]["status"]} for row in rows]
        integer = {"type": "integer", "minimum": 0, "maximum": len(rows)}
        count_keys = ["tp", "fn", "fp", "tn", "unresolved"]
        question_properties = {}
        for qid in dict.fromkeys(row["question_id"] for row in rows):
            ids = [row["display_id"] for row in rows if row["question_id"] == qid]
            fields = {key: {"type": "array", "uniqueItems": True, "items": {"enum": ids}}
                      for key in ("missed", "spurious", "unresolved", "not_run")}
            fields["exact"] = {"type": "boolean"}
            question_properties[qid] = {"type": "object", "additionalProperties": False,
                                        "required": list(fields), "properties": fields}
        properties = {
            "finding_counts": {"type": "object", "additionalProperties": False, "required": count_keys,
                               "properties": {key: integer for key in count_keys}},
            "findings": integer, "agreement_with_reference": integer,
            "f1": {"type": ["number", "null"], "minimum": 0, "maximum": 1},
            "per_question": {"type": "object", "additionalProperties": False,
                             "required": list(question_properties), "properties": question_properties},
        }
        schema = {"type": "object", "additionalProperties": False, "required": ["rules", "conditions"],
                  "properties": {"rules": {"type": "object", "additionalProperties": False,
                                           "required": list(properties), "properties": properties},
                                 "conditions": {"const": {}}}}
        return call("S4", {"findings": findings}, schema)

    return evaluate(*args, **kwargs, comparator=compare)


IMPLEMENTATIONS = {
    "s1": {"default": default_s1, "mock-llm": mock_s1},
    "s2": {"default": default_s2, "mock-llm": mock_s2},
    "s3": {"default": default_s3, "mock-llm": mock_s3},
    "s4": {"default": default_s4, "mock-llm": mock_s4},
}


def implementation_name(stage: str, config: dict) -> str:
    return (config.get("stages") or {}).get(stage, {}).get("implementation", "default")


def selected(stage: str, config: dict):
    name = implementation_name(stage, config)
    if not isinstance(name, str) or name not in IMPLEMENTATIONS[stage]:
        raise ValueError(f"unknown {stage} implementation: {name}")
    return IMPLEMENTATIONS[stage][name]
