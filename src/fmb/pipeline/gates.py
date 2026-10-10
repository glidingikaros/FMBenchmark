from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.schemas import validate_payload
from fmb.core.sealed_records import canonical_json, contained_path, parse_json, verify_seal

GATE_SCHEMAS = {
    "G1": "pipeline_g1.schema.json",
    "G2": "pipeline_g2.schema.json",
    "G3": "pipeline_g3.schema.json",
    "G4": "pipeline_g4.schema.json",
    "G5": "pipeline_g5.schema.json",
}
RUN_MANIFEST_SCHEMA = "pipeline_run_manifest.schema.json"
RUN_MANIFEST = "run-manifest.json"


def write_gate(run_dir: Path, gate: str, payload: dict[str, Any], *, qualifier: str | None = None) -> dict:
    if payload.get("gate") != gate:
        raise ValueError(f"payload declares gate {payload.get('gate')!r}, not {gate}")
    validate_payload(payload, GATE_SCHEMAS[gate])
    name = gate if qualifier is None else f"{gate}:{qualifier}"
    relative = Path("gates") / (name.replace(":", "-") + ".json")
    path = Path(run_dir) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError("gate document already written: " + str(path))
    data = (canonical_json(payload) + "\n").encode()
    path.write_bytes(data)
    return {"path": relative.as_posix(), "sha256": sha256_bytes(data), "schema": GATE_SCHEMAS[gate]}


def read_gate(run_dir: Path, entry: dict) -> dict:
    path = Path(run_dir) / entry["path"]
    if sha256_file(path) != entry["sha256"]:
        raise ValueError("gate document changed after it was written: " + entry["path"])
    payload = parse_json(path.read_text())
    validate_payload(payload, entry["schema"])
    return payload


def is_file_ref(value: Any) -> bool:
    return isinstance(value, dict) and "sha256" in value and "path" in value


def _file_refs(value: Any, trail: str = ""):
    if is_file_ref(value):
        yield trail, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _file_refs(item, f"{trail}/{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _file_refs(item, f"{trail}/{index}")


def _lineage_outcomes(gate: dict, recorded_run: str | None, run_dir: Path):
    for condition, score in (gate.get("scores") or {}).items():
        lineage = score.get("lineage") if isinstance(score, dict) else None
        for index, row in enumerate((lineage or {}).get("selected", [])):
            if row.get("outcome") is None:
                continue
            root = Path(lineage["runs"][row["source"]]["root"])
            if recorded_run and root.is_relative_to(recorded_run):
                root = run_dir / root.relative_to(recorded_run)
            yield (f"/scores/{condition}/lineage/selected/{index}/outcome",
                   contained_path(root / "run", row["outcome"]["path"]), row["outcome"]["sha256"])


def _verify_lifecycle(manifest: dict, gates: dict, roots: dict) -> None:
    from fmb.evaluation.admission import read_admission
    from fmb.pipeline.stages import resolve

    conditions = manifest["config"]["conditions"]
    models = ["G4:" + c for c in conditions]
    entries = manifest["stages"]
    admission = next((s["detail"].get("admission") for s in entries if s["step"] == "S4:admission"), None)
    dispatch = bool(manifest["config"].get("dispatch")) and (
        admission == "passed" or manifest["admission_policy"] == "report-only")
    order = ["S1", "S2", "check:presentation", "check:sources", "S3", "S3':freeze", "S4:admission",
             *(["S3':dispatch"] if dispatch else []), "S3':publish", "S4:evaluation"]
    required_gates = {
        "S1": (["question"], ["G2"]), "S2": (["G1", "G2"], ["G3"]),
        "check:presentation": (["G3"], []), "check:sources": (["G3"], []),
        "S3": (["G2", "G3"], ["G4:rules"]), "S3':freeze": (["G3"], []),
        "S4:admission": (["G3", "G4:rules"], []), "S3':dispatch": (["G3"], []),
        "S3':publish": (["G3"], models), "S4:evaluation": (["G1", "G3", "G4:rules", *models], ["G5"]),
    }
    written = {"G1"} if "G1" in gates else set()
    artifacts = {}
    previous_end = None
    for index, stage in enumerate(entries):
        step = stage["step"]
        if index >= len(order) or step != order[index] or stage["stage"] != step.split(":")[0]:
            raise ValueError("run phases are missing, duplicated, or out of order: " + step)
        failed = stage["status"] == "failed"
        if failed and (index != len(entries) - 1 or manifest["status"] != "failed"):
            raise ValueError("execution continued after a failed phase: " + step)
        start, end = (datetime.fromisoformat(stage[key]) for key in ("started_utc", "finished_utc"))
        if (start.tzinfo is None or end.tzinfo is None or end < start
                or previous_end is not None and start < previous_end):
            raise ValueError("phase timestamps are out of order: " + step)
        previous_end = end
        needed, produced = required_gates[step]
        if stage["reads"] != needed or set(needed) - {"question"} - written:
            raise ValueError("phase reads gates before their production or omits a dependency: " + step)
        if (len(stage["writes"]) != len(set(stage["writes"])) or set(stage["writes"]) & written
                or (set(stage["writes"]) - set(produced) if failed else stage["writes"] != produced)):
            raise ValueError("gate publication does not belong to its recorded phase: " + step)
        written.update(stage["writes"])
        inputs = {}
        if step.startswith("check:") or step == "S4:admission":
            inputs["preparation"] = artifacts["preparation"]
        if step in {"S4:admission", "S3':dispatch", "S3':publish", "S4:evaluation"}:
            inputs.update({k: v for k, v in artifacts.items() if k.startswith("frozen:")})
        if step in {"S3':dispatch", "S4:evaluation"}:
            inputs.update({k: v for k, v in artifacts.items() if k.startswith("admission:")})
        if step in {"S3':publish", "S4:evaluation"}:
            inputs.update({k: v for k, v in artifacts.items() if k.startswith("predictions:")})
        if step == "S4:admission":
            inputs["reference_manifest"] = gates["G1"]["generation_manifest"]
            if "admission_baseline" in artifacts:
                inputs["admission_baseline"] = artifacts["admission_baseline"]
        if stage["inputs"] != inputs:
            raise ValueError("phase artifact dependencies differ from earlier outputs: " + step)
        paths = {}
        if step == "S2":
            paths["preparation"] = "preparation/prepared/preparation-seal.json"
        elif step == "S3" and "admission_baseline" in stage["detail"]:
            if stage["detail"]["admission_baseline"] != "rules":
                raise ValueError("admission must use the fixed rules baseline")
            engine = (manifest["config"].get("stages") or {}).get("s3", {}).get("engine", "rules")
            variant = (manifest["config"].get("stages") or {}).get("s3", {}).get("implementation", "default")
            baseline = "rules" if engine == "rules" and variant == "default" else "admission-rules"
            paths["admission_baseline"] = f"assessment/{baseline}/assessment-seal.json"
        elif step == "S3':freeze":
            paths = {"frozen:" + c: f"conditions/{c}/preparation-seal.json" for c in conditions}
        elif step == "S4:admission":
            paths = {"admission:" + c: f"conditions/{c}/admission/admission-seal.json" for c in conditions}
        elif step == "S3':dispatch":
            dispatched = stage["detail"].get("dispatched", [])
            if len(dispatched) != len(set(dispatched)) or set(dispatched) - set(conditions):
                raise ValueError("dispatch names conditions that were not frozen")
            paths = {"predictions:" + c: f"conditions/{c}/run/prediction-seal.json"
                     for c in (conditions if failed else dispatched)}
        if (set(stage["outputs"]) - set(paths) if failed else set(stage["outputs"]) != set(paths)):
            raise ValueError("phase has missing or unexpected artifact outputs: " + step)
        for key, ref in stage["outputs"].items():
            if ref.get("root") != "run" or ref["path"] != paths[key]:
                raise ValueError("phase output has the wrong path: " + key)
            if key.startswith("admission:"):
                certificate = read_admission(resolve(ref, roots).parent.parent)
                if not failed and certificate["status"] != admission:
                    raise ValueError("admission authorization differs from its recorded phase")
        artifacts.update(stage["outputs"])
    if written != set(gates):
        raise ValueError("stages and recorded gates disagree")
    if manifest["status"] == "completed":
        if len(entries) != len(order) or "failure" in manifest:
            raise ValueError("completed run lacks necessary phases")
    elif (not entries and (manifest.get("failure", {}).get("step") != "G1" or gates)) or (
            entries and (entries[-1]["status"] != "failed" or manifest.get("failure", {}).get("step") != entries[-1]["step"])):
        raise ValueError("failed run does not identify its final attempted phase")
    for name, gate in gates.items():
        dependency = "G2" if name == "G3" else "G3" if name.startswith("G4:") else None
        if dependency and gate.get(dependency.lower() + "_sha256") != manifest["gates"][dependency]["sha256"]:
            raise ValueError(name + " differs from its recorded input gate")
        if name in models and (gate["status"] == "executed") != ("predictions:" + name[3:] in artifacts):
            raise ValueError(name + " has no matching dispatch output")
        declared = {}
        if name == "G3":
            declared["preparation_seal"] = "preparation"
        elif name in models:
            declared = {"condition_seal": "frozen:" + name[3:], "prediction_seal": "predictions:" + name[3:]}
        references = gate["assessor"] if name in models else gate
        for field, key in declared.items():
            if field in references and references[field] != artifacts.get(key):
                raise ValueError(name + " differs from its phase artifact: " + field)
    if "G5" in gates and gates["G5"].get("inputs") != {
            name: manifest["gates"][name]["sha256"] for name in ("G3", "G4:rules", *models)}:
        raise ValueError("G5 does not bind all assessment gates")


def verify_run(run_dir: Path) -> dict:
    from fmb.pipeline.reads import read_record
    from fmb.pipeline.stages import resolve

    run_dir = Path(run_dir)
    manifest = parse_json((run_dir / RUN_MANIFEST).read_text())
    validate_payload(manifest, RUN_MANIFEST_SCHEMA)
    if sha256_bytes(canonical_json(manifest["config"]).encode()) != manifest["config_sha256"]:
        raise ValueError("run configuration differs from its recorded hash")
    gates = {name: read_gate(run_dir, entry) for name, entry in manifest["gates"].items()}
    roots = {name: Path(path) for name, path in manifest.get("roots", {"run": str(run_dir)}).items()}
    roots["run"] = run_dir
    current = manifest["schema_version"] == "fmb.pipeline.run.v2"
    if not current:
        written = {"G1"} | {name for stage in manifest["stages"] for name in stage["writes"]}
        if written != set(gates) or any(set(s["reads"]) - {"question"} - written for s in manifest["stages"]):
            raise ValueError("stages and recorded gates disagree")
    files = 0
    mock_counts = {}
    mock_paths = set()
    selected_mocks = {name.upper() for name, options in (manifest["config"].get("stages") or {}).items()
                      if options.get("implementation") == "mock-llm"}
    for reference in manifest.get("mock_calls", []):
        path = resolve(reference, roots)
        if sha256_file(path) != reference["sha256"]:
            raise ValueError("recorded mock call changed: " + str(path))
        record = parse_json(path.read_text())
        stage = record.get("request", {}).get("stage")
        parts = Path(reference["path"]).parts
        if (reference.get("root") != "run" or len(parts) != 3 or parts[:2] != ("mock-calls", stage)
                or path in mock_paths or stage not in selected_mocks
                or record.get("schema_version") != "fmb.mock_call.v1" or record.get("transport") != "mock"
                or record.get("status") not in {"started", "completed", "failed"}):
            raise ValueError("mock call does not belong to a selected stage: " + str(path))
        mock_paths.add(path)
        mock_counts[stage] = mock_counts.get(stage, 0) + 1
        files += 1
    for phase in manifest["stages"]:
        stage = phase["stage"]
        if stage in selected_mocks and phase["status"] == "completed" and (
                stage != "S4" or phase.get("step") == "S4:evaluation"):
            expected = (len(gates["G3"]["questions"]) if stage == "S2" else
                        gates["G3"]["requests_per_pass"] if stage == "S3" else 1)
            if mock_counts.get(stage, 0) != expected:
                raise ValueError("missing or extra mock calls for " + stage)
    for name, gate in gates.items():
        for trail, path, digest in _lineage_outcomes(gate, manifest.get("roots", {}).get("run"), run_dir):
            if sha256_file(path) != digest:
                raise ValueError(f"{name}{trail} differs from its gate: {path}")
            files += 1
        for trail, reference in _file_refs(gate):
            if trail.startswith("/scores/") and "/lineage/" in trail:
                continue
            path = resolve(reference, roots)
            if reference.get("sha256_source") == "generation_manifest":
                if path.stat().st_size != reference.get("size_bytes"):
                    raise ValueError(f"{name}{trail} differs in size from its gate: {path}")
            elif sha256_file(path) != reference["sha256"]:
                raise ValueError(f"{name}{trail} differs from its gate: {path}")
            files += 1
    if current:
        _verify_lifecycle(manifest, gates, roots)
    if "G3" in gates and "build_seal" in gates["G3"]:
        built = resolve(gates["G3"]["build_seal"], roots).parent
        for entry in gates["G3"]["questions"].values():
            for request in entry["requests"]:
                if sha256_file(built / "sent" / (request["request_id"] + ".json")) != request["sent_sha256"]:
                    raise ValueError("sent card differs from G3: " + request["request_id"])
                files += 1
    if "G5" in gates and "inputs" in gates["G5"]:
        if any(manifest["gates"].get(name, {}).get("sha256") != digest for name, digest in gates["G5"]["inputs"].items()):
            raise ValueError("G5 names input gates other than the ones recorded")
    for stage in manifest["stages"]:
        if current or "reads_record" in stage:
            read_record(run_dir, stage)
        for trail, reference in _file_refs({k: stage[k] for k in ("inputs", "outputs") if k in stage}):
            path = resolve(reference, roots)
            if sha256_file(path) != reference["sha256"]:
                raise ValueError(f"{stage['stage']}{trail} differs from its recorded artifact: {path}")
            if trail.startswith("/outputs/"):
                verify_seal(path.parent, path.name)
            files += 1
    return {"status": "verified", "run_status": manifest.get("status", "completed"), "gates": sorted(gates),
            "stages": [s["stage"] for s in manifest["stages"]], "files_checked": files,
            "lifecycle": "recorded_order_verified" if current else "unverified_legacy",
            **({"limitations": ["legacy manifests lack separate publication and artifact dependency records"]}
               if not current else {})}
