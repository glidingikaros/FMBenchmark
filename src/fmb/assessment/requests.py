import os
from pathlib import Path
from fmb.core import paper_contract
from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.paper_protocol import condition_settings, paper_protocol
from fmb.core.paper_policy import ALTERNATE_POLICY, PAPER_POLICY
from fmb.core.paper_artifacts import rule_result_bytes
from fmb.core.sealed_records import read_json, write_json, contained_path, seal_directory
from fmb.interpretation.paper_payload import wire, request_kwargs

def write_condition(
    *, built: Path, condition: str, output: Path, source_lock: str, completion: bool = False,
    generation: Path | None = None,
):
    from fmb.core.paper_artifacts import build_generation, guard_record
    from fmb.core.truth_guard import truth_blind_reads

    protocol = paper_protocol()
    if condition not in protocol["conditions"]:
        raise ValueError("unknown paper condition")
    declared = protocol["conditions"][condition]
    settings = condition_settings(condition, completion=completion, protocol=protocol)
    built = Path(built).resolve(strict=True)
    options = paper_contract.validate_options(read_json(built / "view-options.json"))
    sealed = read_json(built / "build-seal.json")["requests"]
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    with truth_blind_reads(Path(generation) if generation is not None else build_generation(built)) as guard:
        for rid, binding in sealed.items():
            path = contained_path(built, "sent/" + rid + ".json")
            data = path.read_bytes()
            case = read_json(path)
            if sha256_bytes(data) != binding["sent_sha256"]:
                raise ValueError("sent case changed")
            schema = paper_contract.response_schema(case)
            kwargs = request_kwargs(data.decode(), schema, settings)
            body = wire(kwargs)
            casepath = output / "cases" / (rid + ".json")
            casepath.parent.mkdir(exist_ok=True)
            casepath.write_bytes(data)
            request = output / "requests" / (rid + ".json")
            request.parent.mkdir(exist_ok=True)
            request.write_bytes(body)
            write_json(output / "requests" / (rid + ".kwargs.json"), kwargs)
            if "deterministic_sha256" in binding:
                baseline = output / "deterministic" / (rid + ".json")
                baseline.parent.mkdir(exist_ok=True)
                baseline.write_bytes(rule_result_bytes(built, rid, binding, paper_contract.bind_options(options, built)))
            rows.append(
                {
                    "request_id": rid,
                    "case_id": rid,
                    "question_id": case["question"]["question_id"],
                    "batch_index": 0,
                    "batches": 1,
                    "case_sha256": sha256_bytes(data),
                    "request_sha256": sha256_bytes(body),
                    "request_bytes": len(body),
                    "subjects": len(case["candidate_roster"]),
                    "targets": sum(
                        len(c["assessment_targets"]) for c in case["candidate_roster"]
                    ),
                }
            )
    if guard["denied"]:
        raise ValueError("freezing requests attempted a private read")
    schedule = []
    shift = max(1, len(rows) // 3)
    for p in range(3):
        rotated = rows[p * shift % len(rows) :] + rows[: p * shift % len(rows)]
        offset = len(schedule)
        schedule.extend(
            {**r, "pass": p + 1, "call": offset + i + 1} for i, r in enumerate(rotated)
        )
    write_json(
        output / "manifest.json",
        {"schema_version": "paper_request_manifest.v1", "rows": rows},
    )
    write_json(output / "schedule.json", {"rows": schedule})
    write_json(
        output / "protocol.json",
        {
            "schema_version": "paper_condition.v1",
            "condition_id": condition,
            "level": "L0N",
            "options": options,
            "settings": settings,
            "passes": 3,
            "built": os.path.relpath(built, output),
            "build_seal_sha256": sha256_file(built / "build-seal.json"),
            "source_manifest_sha256": source_lock,
            "execution_policy": ALTERNATE_POLICY
            if completion and declared["completion_policy"].get("companion_route") else PAPER_POLICY,
            "completion_policy": declared.get("completion_policy")
            if completion
            else None,
            "truth_sources_used": [],
            "truth_guard": guard_record(guard),
            "model_calls": 0,
        },
    )
    digest = seal_directory(output)
    return {
        "status": "prepared",
        "condition": condition,
        "requests": len(rows),
        "scheduled_calls": len(schedule),
        "output": str(output),
        "preparation_seal_sha256": digest,
        "provider_calls": 0,
    }
