from __future__ import annotations

from pathlib import Path
from typing import Any

from fmb.core.sealed_records import parse_json
from fmb.pipeline.gates import RUN_MANIFEST, is_file_ref, read_gate, verify_run

SCHEMA = "fmb.pipeline.diff.v1"
TIME_KEYS = {"started_utc", "finished_utc", "sealed_utc", "assessed_utc", "checked_utc", "admitted_utc", "built_utc",
             "elapsed_seconds"}
LOCATION_FIELDS = {
    "G1": {"generation_root"},
    "G3": {"build_seal", "preparation_seal"},
    "G4": {"g3_sha256", "assessor/assessment", "assessor/assessment_seal", "assessor/condition_run",
           "assessor/condition_seal", "assessor/prediction_seal"},
    "G5": {"admission/certificates", "inputs"},
}
MAX_DIFFERENCES = 50


def content(value: Any, *, drop: set[str], prefix: str = "") -> Any:
    if is_file_ref(value):
        return {key: item for key, item in value.items() if key not in {"path", "root"}}
    if isinstance(value, dict):
        kept = {}
        for key, item in value.items():
            path = f"{prefix}/{key}" if prefix else key
            if key in TIME_KEYS or path in drop:
                continue
            kept[key] = content(item, drop=drop, prefix=path)
        return kept
    if isinstance(value, list):
        return [content(item, drop=drop, prefix=prefix) for item in value]
    return value


def differences(a: Any, b: Any, path: str = "") -> list[dict]:
    if isinstance(a, dict) and isinstance(b, dict):
        found = []
        for key in sorted(set(a) | set(b)):
            where = f"{path}/{key}"
            if key not in a or key not in b:
                found.append({"path": where, "a": a.get(key, "<absent>"), "b": b.get(key, "<absent>")})
            else:
                found.extend(differences(a[key], b[key], where))
        return found
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        found = []
        for index, (x, y) in enumerate(zip(a, b)):
            found.extend(differences(x, y, f"{path}/{index}"))
        return found
    return [] if a == b else [{"path": path or "/", "a": a, "b": b}]


def _short(value: Any) -> Any:
    text = repr(value)
    return value if len(text) <= 200 else text[:200] + "…"


def diff_runs(run_a: Path, run_b: Path) -> dict:
    run_a, run_b = Path(run_a), Path(run_b)
    for run in (run_a, run_b):
        verify_run(run)
    manifests = [parse_json((run / RUN_MANIFEST).read_text()) for run in (run_a, run_b)]
    gates: dict[str, dict] = {}
    for name in sorted(set(manifests[0]["gates"]) | set(manifests[1]["gates"])):
        present = [name in manifest["gates"] for manifest in manifests]
        if not all(present):
            gates[name] = {"status": "only_in_a" if present[0] else "only_in_b"}
            continue
        drop = LOCATION_FIELDS.get(name.split(":")[0], set())
        docs = [content(read_gate(run, manifest["gates"][name]), drop=drop)
                for run, manifest in zip((run_a, run_b), manifests)]
        found = differences(*docs)
        gates[name] = {"status": "same" if not found else "different", "differences": len(found),
                       **({"first": [{**d, "a": _short(d["a"]), "b": _short(d["b"])}
                                     for d in found[:MAX_DIFFERENCES]]} if found else {})}
    implementations = [manifest.get("implementations") for manifest in manifests]
    code = [manifest["code"]["source_manifest_sha256"] for manifest in manifests]
    same = all(entry["status"] == "same" for entry in gates.values())
    return {
        "schema_version": SCHEMA,
        "status": "same" if same else "different",
        "runs": {"a": str(run_a), "b": str(run_b)},
        "code": {"a": code[0], "b": code[1], "same": code[0] == code[1]},
        "implementations": {"same": implementations[0] == implementations[1],
                            **({} if implementations[0] == implementations[1]
                               else {"a": implementations[0], "b": implementations[1]})},
        "gates": gates,
        "ignored": "timestamps and durations; file locations (a file is compared by its SHA-256 and size); "
                   "location-bearing fields with a location-free equivalent: " +
                   "; ".join(f"{gate}: {', '.join(sorted(fields))}" for gate, fields in LOCATION_FIELDS.items()),
    }
