from pathlib import Path

from fmb.core.hashing import sha256_file
from fmb.core.paper_artifacts import condition_build, verify_prepared_condition
from fmb.core.paper_policy import PAPER_POLICY, completion_eligible, resolve_policy, validate_attempts
from fmb.core.paper_protocol import validate_completion_policy
from fmb.core.paper_results import IDENTITY_FIELDS
from fmb.core.sealed_records import canonical_json, contained_path, read_json, verify_seal


def _identity(root):
    return {"root": str(root), "preparation_seal_sha256": sha256_file(root / "preparation-seal.json")}


def bind_completion(root, protocol, schedule, primary):
    if primary is None:
        raise ValueError("completion dispatch requires its sealed primary run")
    primary = Path(primary).resolve(strict=True)
    original, _, _ = verify_prepared_condition(primary, built=condition_build(root, protocol))
    if original.get("completion_policy") or resolve_policy(original, for_execution=True)["id"] != PAPER_POLICY:
        raise ValueError("completion requires a primary execution, not another completion or historical run")
    validate_completion_policy(original["settings"], protocol["settings"])
    policy = resolve_policy(protocol, for_execution=True)
    sealed = verify_seal(primary / "run", "prediction-seal.json")["files"]
    if not {"schedule.json", "completion.json"} <= set(sealed):
        raise ValueError("primary terminal execution is not sealed")
    recorded = read_json(primary / "run/schedule.json")
    if recorded.get("execution_policy") != resolve_policy(original):
        raise ValueError("primary execution policy differs from preparation")
    previous = {(r["request_id"], r["pass"]): r for r in recorded["rows"]}
    if len(previous) != len(recorded["rows"]) or set(previous) != {(r["request_id"], r["pass"]) for r in schedule}:
        raise ValueError("completion must use the primary's executed request/pass universe")
    prior, bindings = {}, []
    terminal_rows = read_json(primary / "run/completion.json")["outcomes"]
    terminal = {(r["request_id"], r["pass"]): r for r in terminal_rows}
    if len(terminal) != len(terminal_rows) or set(terminal) != set(previous):
        raise ValueError("primary terminal record does not cover its executed schedule")
    for row in schedule:
        key = row["request_id"], row["pass"]
        old = previous[key]
        if any(old.get(k) != row.get(k) for k in (*IDENTITY_FIELDS, "case_sha256")):
            raise ValueError("completion identity differs from primary")
        if policy["id"] == PAPER_POLICY and old["request_sha256"] != row["request_sha256"]:
            raise ValueError("paper completion requires the identical wire request")
        before = read_json(primary / "requests" / (row["request_id"] + ".json"))
        after = read_json(root / "requests" / (row["request_id"] + ".json"))
        if policy["id"] != PAPER_POLICY:
            before["provider"] = after.get("provider")
        if before != after:
            raise ValueError("completion changed more than its declared route")
        folder = f"call-{old['call']:03d}"
        name = folder + "/outcome.json"
        if name not in sealed:
            raise ValueError("primary terminal outcome is missing or unsealed")
        outcome = read_json(contained_path(primary / "run", name))
        if outcome != terminal.get(key) or any(outcome.get(k) != old.get(k) for k in (*IDENTITY_FIELDS, "pass", "call")):
            raise ValueError("primary terminal outcome differs from its schedule/completion record")
        attempts = outcome.get("attempts")
        bodies = [n for n in sealed if n.startswith(folder + "/attempts/") and n.endswith("/request-body.json")]
        validate_attempts(outcome, [sealed[n] for n in bodies], old["request_sha256"])
        returned = folder + "/provider-response.json" in sealed or any(
            read_json(contained_path(primary / "run", n)).get("status") == "returned"
            for n in sealed if n.startswith(folder + "/attempts/") and n.endswith("/finished.json")
        )
        outcome = {**outcome, "response_received": outcome.get("response_received", False) or returned}
        prior[key] = outcome
        bindings.append({"request_id": key[0], "pass": key[1], "primary_call": old["call"],
                         "primary_outcome_sha256": sealed[name], "primary_request_sha256": old["request_sha256"],
                         "attempts_before": attempts,
                         "eligible": completion_eligible(outcome, policy, question_id=row["question_id"])})
    return {**_identity(primary), "prediction_seal_sha256": sha256_file(primary / "run/prediction-seal.json"),
            "calls": bindings}, prior


def claim_execution(root, protocol, binding):
    built = condition_build(root, protocol)
    directory = built / "dispatch" / protocol["condition_id"]
    directory.mkdir(parents=True, exist_ok=True)
    if binding is not None:
        primary = read_json(directory / "primary.json")
        if any(primary.get(k) != binding[k] for k in ("root", "preparation_seal_sha256")):
            raise ValueError("completion is not bound to this build's primary execution")
    record = {**_identity(root), "execution_policy": resolve_policy(protocol), "completion_of": binding}
    role = "completion" if binding is not None else "primary"
    with (directory / (role + ".json")).open("x") as stream:
        stream.write(canonical_json(record) + "\n")
    return record
