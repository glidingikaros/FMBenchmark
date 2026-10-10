from collections import Counter
from pathlib import Path

from fmb.core.hashing import sha256_file
from fmb.core.paper_policy import resolve_policy
from fmb.core.sealed_records import contained_path, read_json, verify_seal


def _rounds(root, files):
    attempts = {}
    for name, digest in files.items():
        if "/attempts/" in name and name.endswith("/request-body.json"):
            attempts.setdefault(name.split("/attempts/", 1)[0], []).append(digest)
    rounds = []
    for name, digest in files.items():
        if not name.endswith("/outcome.json"):
            continue
        row = read_json(contained_path(root / "run", name))
        bodies = attempts.get(name.rsplit("/", 1)[0], [])
        rounds.append({"request_id": row["request_id"], "pass": row["pass"], "path": name,
                       "outcome_sha256": digest, "status": row["status"], "recorded_attempts": row.get("attempts"),
                       "retained_attempts": len(bodies), "request_hashes": dict(Counter(bodies))})
    return rounds


def _source_match(claim, selected, cache):
    source = Path(claim.get("selected_from") or "")
    if not source.is_absolute() or source.parent.name != "run" or not source.name.startswith("call-"):
        return {"status": "source_location_unavailable"}
    run = source.parent
    if run not in cache:
        try:
            seal = verify_seal(run, "prediction-seal.json")
            cache[run] = {"prediction_seal_sha256": sha256_file(run / "prediction-seal.json"), "files": seal["files"]}
        except (OSError, ValueError) as error:
            cache[run] = {"status": "source_seal_unverified", "reason": str(error)[:300]}
    record = cache[run]
    if "files" not in record:
        return record
    prefix = source.name + "/"
    original = {name[len(prefix):]: digest for name, digest in record["files"].items() if name.startswith(prefix)}
    return {"status": "sealed_source_bytes_match" if original == selected else "source_bytes_differ",
            "prediction_seal_sha256": record["prediction_seal_sha256"]}


def _flattened(root, loaded):
    path = root / "flatten-provenance.json"
    if not path.exists():
        return None
    result = {"metadata_sha256": sha256_file(path), "status": "historical_lineage_not_fully_verified",
              "metadata_sealed": "flatten-provenance.json" in loaded["preparation_files"],
              "limitation": "Source byte matches do not prove selection order, eligibility, total sends, or completeness of history."}
    try:
        metadata = read_json(path)
        claims = {(row["request_id"], row["pass"]): row for row in metadata["per_call"]}
        if len(claims) != len(metadata["per_call"]) or set(claims) != set(loaded["outcome_files"]):
            raise ValueError("flattened claims do not cover the selected outcomes exactly once")
        result["unverified_claims"] = {key: metadata.get(key) for key in (
            "primary", "companion", "original_seals", "selected_from", "sum_total_sends", "max_total_sends")}
        records, cache = [], {}
        for key, claim in claims.items():
            outcome = loaded["outcome_files"][key]
            prefix = outcome["path"].rsplit("/", 1)[0] + "/"
            selected = {name[len(prefix):]: digest for name, digest in loaded["prediction_files"].items()
                        if name.startswith(prefix)}
            records.append({"request_id": key[0], "pass": key[1],
                            "selected_outcome_sha256": outcome["sha256"],
                            "claimed_source": claim.get("selected_source"),
                            "claimed_path": claim.get("selected_from"),
                            "claimed_rounds": claim.get("rounds"),
                            "claimed_total_sends": claim.get("total_sends"),
                            "claimed_completion_record": claim.get("completion_record"),
                            "source_check": _source_match(claim, selected, cache)})
        result["selections"] = records
        result["source_checks"] = dict(Counter(row["source_check"]["status"] for row in records))
    except (OSError, ValueError, KeyError, TypeError) as error:
        result.update(status="invalid_flattened_metadata", reason=str(error)[:300])
    return result


def run_lineage(loaded):
    root = Path(loaded["root"])
    policy = resolve_policy(loaded["protocol"])
    rounds = _rounds(root, loaded["prediction_files"])
    flattened = _flattened(root, loaded)
    return {
        "root": str(root), "preparation_seal_sha256": loaded["preparation_seal_sha256"],
        "prediction_seal_sha256": loaded["prediction_seal_sha256"],
        "status": ("historical_lineage_not_fully_verified" if flattened else
                   "declared_execution_record" if policy["max_total_attempts"] is not None else
                   "historical_execution_partially_attested"),
        "policy": policy, "completion_of": loaded["run_schedule"].get("completion_of"),
        "retained_attempts": sum(row["retained_attempts"] for row in rounds),
        "rounds": rounds, "flattened": flattened,
        "evidence_limit": "Sealed retained records; attempt files alone do not prove a network send or a complete execution history.",
    }


def selection_lineage(a, b, selection):
    runs = {"primary": a, **({"companion": b} if b else {})}
    records = {name: run_lineage(run) for name, run in runs.items()}
    selected = []
    for row in selection:
        source = row["source"]
        file = runs[source]["outcome_files"].get((row["request_id"], row["pass"])) if source else None
        selected.append({**row, "outcome": file,
                         "prediction_seal_sha256": records[source]["prediction_seal_sha256"] if source else None})
    return {"runs": records, "selected": selected}


def report_labels(score):
    provenance = score.get("provenance", {})
    policy = provenance.get("selection_policy", {})
    statuses = sorted({run["status"] for run in score.get("lineage", {}).get("runs", {}).values()})
    return {"selection_policy": policy.get("id", "not_recorded"), "lineage_status": "; ".join(statuses) or "not_recorded"}
