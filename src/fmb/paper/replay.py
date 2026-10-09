from pathlib import Path

from fmb.core import paper_contract
from fmb.evaluation.admission import reference_file
from fmb.assessment.rules import statuses
from fmb.core import paper_integrity as integrity
from fmb.core.hashing import sha256_file
from fmb.core.paths import PROJECT_ROOT
from fmb.core.sealed_records import read_json, sha256_json, contained_path, verify_seal


def example_root():
    return PROJECT_ROOT / "fixtures/paper/i1"


def inspect_records(root: Path):
    root = Path(root).resolve(strict=True)
    seal = verify_seal(root)
    if not {"manifest.json", "protocol.json"} <= set(seal["files"]):
        raise ValueError("preparation metadata is not sealed")
    manifest = read_json(root / "manifest.json")
    return {
        "action": "inspect_saved_records",
        "source": str(root),
        "requests": len(manifest["rows"]),
        "questions": len({row["question_id"] for row in manifest["rows"]}),
        "findings": sum(row["targets"] for row in manifest["rows"]),
        "prepared_seal_sha256": sha256_file(root / "preparation-seal.json"),
        "fresh_assessment": False,
        "provider_calls": 0,
    }


def replay(root: Path, *, reference_path: Path | None = None):
    root = Path(root).resolve(strict=True)
    seal = verify_seal(root)
    if not {"manifest.json", "protocol.json"} <= set(seal["files"]):
        raise ValueError("preparation metadata is not sealed")
    source_lock = integrity.source_manifest_sha256()
    manifest = read_json(root / "manifest.json")
    protocol = read_json(root / "protocol.json")
    if protocol.get("level") != "L0N":
        raise ValueError("not the paper presentation")
    options = paper_contract.validate_options(protocol["options"])
    predictions = {}
    ids = set()
    for row in manifest["rows"]:
        rid = row["request_id"]
        if rid in ids:
            raise ValueError("duplicate frozen request")
        ids.add(rid)
        case = read_json(contained_path(root, "cases/" + rid + ".json"))
        if sha256_json(case) != row["case_sha256"]:
            raise ValueError("case hash mismatch")
        decoded = paper_contract.decode_case(case, options)
        if decoded["question"]["question_id"] != row["question_id"]:
            raise ValueError("misbound question")
        predictions[rid] = statuses(decoded)
    reference_path = reference_file(root, reference_path)
    references = read_json(reference_path)
    rows = []
    for row in manifest["rows"]:
        got = predictions[row["request_id"]]
        want = references[row["case_id"]]["expected_status"]
        if set(got) != set(want):
            raise ValueError("reference does not cover exact finding universe")
        rows.append(
            {
                "request_id": row["request_id"],
                "question_id": row["question_id"],
                "findings": len(want),
                "exact": got == want,
                "different_findings": sorted(k for k in got if got[k] != want[k]),
            }
        )
    return {
        "schema_version": "paper_deterministic_replay.v1",
        "action": "recompute_from_prepared_records",
        "requests": len(rows),
        "exact_requests": sum(row["exact"] for row in rows),
        "findings": sum(row["findings"] for row in rows),
        "questions": len({row["question_id"] for row in rows}),
        "rows": rows,
        "provider_calls": 0,
        "source_manifest_sha256": source_lock,
        "case_manifest_sha256": sha256_file(root / "manifest.json"),
        "reference_sha256": sha256_file(reference_path),
        "claim_boundary": "screened prepared-case regression; not new generation or held-out forensic accuracy",
    }
