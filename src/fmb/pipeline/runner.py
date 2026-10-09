from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from decimal import Decimal
import json
import os
from pathlib import Path
from typing import Any

from fmb.core import paper_integrity as integrity
from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.paper_protocol import checked_passes, paper_protocol
from fmb.core.schemas import validate_payload
from fmb.core.sealed_records import canonical_json, now, read_json
from fmb.pipeline import stages
from fmb.pipeline.gates import RUN_MANIFEST, RUN_MANIFEST_SCHEMA, write_gate
from fmb.pipeline.implementations import MockCalls, implementation_name, selected

CONFIG_KEYS = {"case_label", "generation", "analysis", "collect", "conditions", "dispatch", "output",
               "question_scope", "stages", "admission", "questions", "passes"}
ADMISSION_POLICIES = {"strict", "report-only"}
STAGE_KEYS = {"s1": {"profile", "implementation"}, "s2": {"implementation"},
              "s3": {"engine", "implementation"}, "s4": {"implementation"}}
DISPATCH_KEYS = {"execute", "cap_usd", "rates", "input_usd_per_million", "output_usd_per_million", "passes"}


def condition_rates(dispatch: dict, condition: str) -> dict:
    own = (dispatch.get("rates") or {}).get(condition)
    if own is not None:
        return {"input": own["input"], "output": own["output"]}
    return {"input": dispatch["input_usd_per_million"], "output": dispatch["output_usd_per_million"]}


def load_config(path: Path) -> dict:
    text = Path(path).read_text()
    if Path(path).suffix.casefold() in {".yaml", ".yml"}:
        import yaml

        config = yaml.safe_load(text)
    else:
        config = json.loads(text)
    if not isinstance(config, dict):
        raise ValueError("pipeline configuration must be a mapping")
    return config


def _validated(config: dict) -> dict:
    unknown = set(config) - CONFIG_KEYS
    if unknown:
        raise ValueError("unknown configuration keys: " + ", ".join(sorted(unknown)))
    for key in ("case_label", "generation", "output"):
        if not config.get(key):
            raise ValueError("configuration requires " + key)
    if not config.get("analysis") and not config.get("collect"):
        raise ValueError("configuration requires an existing analysis or a collect section")
    conditions = config.get("conditions") or []
    if not isinstance(conditions, list) or not conditions or len(set(conditions)) != len(conditions):
        raise ValueError("conditions must name at least one distinct condition: requests are frozen before admission")
    passes = checked_passes(config["passes"]) if "passes" in config else paper_protocol()["passes"]
    dispatch = config.get("dispatch")
    if dispatch is not None:
        if set(dispatch) - DISPATCH_KEYS or dispatch.get("execute") is not True:
            raise ValueError("dispatch requires execute: true and only " + ", ".join(sorted(DISPATCH_KEYS)))
        if "cap_usd" not in dispatch:
            raise ValueError("dispatch requires cap_usd")
        if dispatch.get("passes") is not None and checked_passes(dispatch["passes"]) > passes:
            raise ValueError(f"dispatch passes may not exceed the {passes} frozen passes")
        rates = dispatch.get("rates") or {}
        if not isinstance(rates, dict) or set(rates) - set(conditions) or any(
                not isinstance(pair, dict) or set(pair) != {"input", "output"} for pair in rates.values()):
            raise ValueError("dispatch rates must give input and output prices for frozen conditions only")
        shared = "input_usd_per_million" in dispatch and "output_usd_per_million" in dispatch
        unpriced = [c for c in conditions if c not in rates and not shared]
        if unpriced:
            raise ValueError("dispatch requires input_usd_per_million and output_usd_per_million, or rates for: "
                             + ", ".join(unpriced))
    if config.get("questions") is not None:
        from fmb.question_packs import load_packs

        if not isinstance(config["questions"], list):
            raise ValueError("questions must be a list of question identifiers")
        load_packs(config["questions"])
    if config.get("admission", "strict") not in ADMISSION_POLICIES:
        raise ValueError("admission must be strict or report-only")
    if config.get("question_scope", "hidden") not in {"hidden", "shown"}:
        raise ValueError("question_scope must be hidden or shown")
    named = config.get("stages") or {}
    if not isinstance(named, dict) or set(named) - set(STAGE_KEYS) or any(
            not isinstance(named[key], dict) or set(named[key]) - STAGE_KEYS[key] for key in named):
        raise ValueError("stages may name only s1-s4 implementations, s1.profile and s3.engine")
    for stage in STAGE_KEYS:
        selected(stage, config)
    if dispatch and any(implementation_name(stage, config) == "mock-llm" for stage in STAGE_KEYS):
        raise ValueError("mock stage experiments cannot dispatch live model conditions")
    if implementation_name("s3", config) != "default" and "engine" in named.get("s3", {}):
        raise ValueError("choose an s3 implementation or an engine, not both")
    if "s3" in named:
        from fmb.assessment.stage import engine

        engine(named["s3"].get("engine", "rules"))
    return deepcopy({**config, "conditions": conditions})


def implementations(analysis: Path, built: Path, rules: Path, runs: list[Path], *, collected: bool,
                    supplied_profile: bool) -> dict:
    index = read_json(Path(analysis) / "evidence_index.json")
    assessment = read_json(Path(rules) / "assessment.json")
    return {
        "S1": {"resolver": "fmb.profiles.resolve_profile", "mode": "supplied" if supplied_profile else "packs"},
        "S2": {"implementation": "fmb.pipeline.stages.prepare_evidence",
               "collection": "fmb paper collect" if collected else "reused",
               "parsers": sorted({str(run.get("parser")) for run in index.get("parser_runs", [])}),
               "preparation": "fmb.paper.workflow.prepare",
               "question_scope": stages.question_scope(built)},
        "S3": {"engine": assessment["engine"]["id"], "module": assessment["engine"]["module"]},
        "S3'": {run.name: read_json(run / "protocol.json")["settings"].get("model") for run in runs},
        "S4": {"admission": "fmb.evaluation.admission.admit_evidence", "admission_baseline": "rules",
               "reference_binding": "fmb.evaluation.factual_reference",
               "evaluation": "fmb.pipeline.evaluation.evaluate", "scoring": "fmb.evaluation.scoring"},
    }


def _dispatch(runs: list[Path], cap: Decimal, dispatch: dict, policy: str, provider) -> tuple[list[Path], dict, list]:
    from fmb.paper.workflow import execute_condition

    remaining, exposure, unfunded, executed = cap, {}, [], []
    for run in runs:
        if remaining <= 0:
            unfunded.append(run.name)
            continue
        result = execute_condition(run, cap_usd=str(remaining), execute=True, provider=provider,
                                   rates=condition_rates(dispatch, run.name),
                                   pass_limit=dispatch.get("passes"),
                                   development_unadmitted=policy == "report-only")
        spent = Decimal(str(result.get("conservative_exposure_usd", "0")))
        exposure[run.name], remaining = str(spent), remaining - spent
        executed.append(run)
    return executed, exposure, unfunded


def run_pipeline(config: dict, *, provider=None, stage_responder=None) -> dict:
    from fmb.evaluation.admission import admit_evidence
    from fmb.paper.presentation_check import check_presentation
    from fmb.paper.workflow import assess_rules, check_preparation_sources, freeze_condition
    from fmb.pipeline import reads
    from fmb.profiles import validate_profile

    config = _validated(config)
    run_dir = Path(os.path.normpath(Path(config["output"]).absolute()))
    run_dir.mkdir(parents=True, exist_ok=False)
    choices = {stage: selected(stage, config) for stage in STAGE_KEYS}
    calls = MockCalls(run_dir, stage_responder)
    label = config["case_label"]
    scope = config.get("question_scope", "hidden")
    policy = config.get("admission", "strict")
    questions = config.get("questions")
    engine_name = (config.get("stages") or {}).get("s3", {}).get("engine", "rules")
    supplied_profile = (config.get("stages") or {}).get("s1", {}).get("profile")
    generation = Path(config["generation"]).resolve(strict=True)
    analysis = Path(config["analysis"]).absolute() if config.get("analysis") else run_dir / "analysis"
    roots = {"run": run_dir, "generation": generation, "analysis": analysis}
    gates: dict[str, dict] = {}
    log: list[dict] = []
    state = {"step": "G1"}

    @contextmanager
    def phase(step: str, reads_gates: list[str], *, inputs: dict | None = None,
              produced: dict[str, Path] | None = None, **detail: Any):
        state["step"] = step
        entry = {"stage": step.split(":")[0], "step": step, "status": "failed",
                 "reads": reads_gates, "writes": [], "inputs": inputs or {}, "outputs": {},
                 "started_utc": now(), "detail": detail}
        log.append(entry)
        previous = set(gates)
        error = None
        opened: set[str] = set()
        try:
            with reads.measured() as opened:
                for key, reference in entry["inputs"].items():
                    if sha256_file(stages.resolve(reference, roots)) != reference["sha256"]:
                        raise ValueError("phase input changed since its production: " + key)
                yield entry
        except BaseException as exc:
            error = exc
            raise
        finally:
            entry["writes"] = [name for name in gates if name not in previous]
            entry["finished_utc"] = now()
            found = None
            try:
                found = reads.by_root(opened, roots)
                entry["opened"] = {root: len(paths) for root, paths in found.items()}
                bad = reads.undeclared(step, found)
                if step == "S2":
                    bad += [f"generation:{p}" for p in found.get("generation", [])
                            if p != "." and p not in g1["readable_paths"]]
                name = Path("reads") / (step.replace(":", "-").replace("'", "prime") + ".json")
                (run_dir / name).parent.mkdir(exist_ok=True)
                data = (canonical_json({"step": step, "read": found}) + "\n").encode()
                (run_dir / name).write_bytes(data)
                entry["reads_record"] = {"path": name.as_posix(), "sha256": sha256_bytes(data)}
                entry["outputs"].update({key: stages.file_ref(path, roots=roots)
                                         for key, path in (produced or {}).items() if path.is_file()})
                if bad:
                    raise ValueError(f"{step} read files its gates do not declare: " + ", ".join(bad[:10]))
            except BaseException as audit_error:
                detail["audit_error"] = f"{type(audit_error).__name__}: {audit_error}"
                if found is not None and "reads_record" not in entry:
                    detail["unwritten_reads"] = found
                if error is None:
                    raise
                error.add_note("phase audit failed: " + detail["audit_error"])
            else:
                entry["status"] = "completed" if error is None else "failed"

    def write_manifest(*, collected: bool | None, built: Path | None, rules: Path | None, runs: list[Path],
                       failure: dict | None = None) -> None:
        try:
            code = {"source_manifest_sha256": integrity.source_manifest_sha256()}
        except (ValueError, OSError):
            code = {"source_manifest_sha256": sha256_file(integrity.source_roots()["package"]
                                                          / "paper-source-manifest.json")}
        manifest = {
            "schema_version": "fmb.pipeline.run.v2",
            "config": config,
            "config_sha256": sha256_bytes(canonical_json(config).encode()),
            "code": code,
            **({"implementations": implementations(analysis, built, rules, runs, collected=collected,
                                                   supplied_profile=supplied_profile is not None)}
               if failure is None else {}),
            "roots": {name: str(path) for name, path in roots.items()},
            "admission_policy": policy,
            "status": "completed" if failure is None else "failed",
            **({"failure": failure} if failure is not None else {}),
            "stages": log,
            "gates": gates,
            **({"mock_calls": [stages.file_ref(path, roots=roots) for path in calls.paths]} if calls.paths else {}),
        }
        if failure is None:
            for stage, function in choices.items():
                name = implementation_name(stage, config)
                if name != "default":
                    manifest["implementations"][stage.upper()].update(
                        variant=name, callable=function.__module__ + "." + function.__name__)
                    if name == "mock-llm":
                        manifest["implementations"][stage.upper()]["transport"] = "mock"
        validate_payload(manifest, RUN_MANIFEST_SCHEMA)
        (run_dir / RUN_MANIFEST).write_text(canonical_json(manifest) + "\n")

    collected = built = rules = None
    runs: list[Path] = []
    try:
        g1 = stages.evidence_gate(generation, label, roots)
        gates["G1"] = write_gate(run_dir, "G1", g1)

        with phase("S1", ["question"], resolver="fmb.profiles.resolve_profile",
                   mode="supplied" if supplied_profile is not None else "packs"):
            integrity.source_manifest_sha256()
            g2 = choices["s1"](questions=questions, supplied=supplied_profile, call=calls)
            validate_profile(g2, questions)
            gates["G2"] = write_gate(run_dir, "G2", g2)

        with phase("S2", ["G1", "G2"]) as step:
            collected = not bool(config.get("analysis"))
            g3 = choices["s2"](g1, g2, roots=roots, g2_sha256=gates["G2"]["sha256"],
                                collect=config["collect"] if collected else None, question_scope=scope, call=calls)
            prepared, built = stages.check_preparation(g3, roots)
            gates["G3"] = write_gate(run_dir, "G3", g3)
            step["outputs"]["preparation"] = g3["preparation_seal"]
            step["detail"].update(analysis=str(analysis), collected=collected)
            made_in = read_json(prepared / "manifest.json").get("collection_original_root")
            if made_in and Path(made_in) != analysis.resolve():
                step["detail"]["collection_made_in"] = made_in
        preparation_input = step["outputs"]

        checks: dict[str, str] = {}
        with phase("check:presentation", ["G3"], inputs=preparation_input, engine="rules") as step:
            check = check_presentation(prepared=prepared, built=built, engine_name="rules")
            (run_dir / "checks").mkdir()
            (run_dir / "checks" / "presentation.json").write_text(canonical_json(check) + "\n")
            checks["presentation"] = check["status"]
            step["detail"].update(check="presentation", status=check["status"])
        with phase("check:sources", ["G3"], inputs=preparation_input) as step:
            sources_check = check_preparation_sources(prepared)
            checks["sources"] = sources_check["status"]
            step["detail"].update(check="sources", **sources_check)

        rules = run_dir / "assessment" / "rules"
        baseline = (rules if engine_name == "rules" and implementation_name("s3", config) == "default"
                    else run_dir / "assessment" / "admission-rules")
        with phase("S3", ["G2", "G3"], engine=engine_name, admission_baseline="rules",
                   produced={"admission_baseline": baseline / "assessment-seal.json"}) as step:
            stages.check_build(g3, roots)
            choices["s3"](built=built, output=rules, engine_name=engine_name,
                           question_definitions=g2["question_definitions"], generation=generation, call=calls)
            g4_rules = stages.rules_gate(rules, built, g3, gates["G3"]["sha256"], roots)
            gates["G4:rules"] = write_gate(run_dir, "G4", g4_rules, qualifier="rules")
            if baseline != rules:
                assess_rules(built=built, output=baseline, engine_name="rules",
                             question_definitions=g2["question_definitions"], generation=generation)
        baseline_input = step["outputs"]

        with phase("S3':freeze", ["G3"], produced={
                "frozen:" + c: run_dir / "conditions" / c / "preparation-seal.json"
                for c in config["conditions"]}, frozen=config["conditions"]) as step:
            stages.check_build(g3, roots)
            for condition in config["conditions"]:
                out = run_dir / "conditions" / condition
                freeze_condition(built=built, condition=condition, output=out, generation=generation,
                                 passes=config.get("passes"))
                runs.append(out)
        frozen = step["outputs"]

        with phase("S4:admission", ["G3", "G4:rules"],
                   inputs={**preparation_input, **frozen, **baseline_input,
                           "reference_manifest": g1["generation_manifest"]},
                   produced={"admission:" + r.name: r / "admission" / "admission-seal.json" for r in runs}) as step:
            admission = admit_evidence(g3, baseline_input["admission_baseline"], frozen, roots=roots)
            step["detail"]["admission"] = admission["status"]
        admitted = step["outputs"]

        dispatch = config.get("dispatch")
        dispatching = bool(dispatch) and (admission["status"] == "passed" or policy == "report-only")
        if dispatching:
            with phase("S3':dispatch", ["G3"], inputs={**frozen, **admitted}, produced={
                    "predictions:" + r.name: r / "run" / "prediction-seal.json" for r in runs}) as step:
                cap = Decimal(str(dispatch["cap_usd"]))
                executed, exposure, unfunded = _dispatch(runs, cap, dispatch, policy, provider)
                step["detail"].update(dispatched=[run.name for run in executed], admission=admission["status"],
                                      policy=policy, cap_usd=str(dispatch["cap_usd"]), exposure_usd=exposure,
                                      not_dispatched_for_budget=unfunded)
        predictions = step["outputs"] if dispatching else {}
        llm = []
        assessments = {"rules": g4_rules}
        with phase("S3':publish", ["G3"], inputs={**frozen, **predictions}):
            for run in runs:
                name = "G4:" + run.name
                assessments[run.name] = stages.llm_gate(run, label, gates["G3"]["sha256"], roots)
                gates[name] = write_gate(run_dir, "G4", assessments[run.name], qualifier=run.name)
                llm.append(name)

        with phase("S4:evaluation", ["G1", "G3", "G4:rules", *llm], inputs={**frozen, **admitted, **predictions}):
            evaluation_args = {"roots": roots, "admission": admission, "policy": policy, "checks": checks,
                               "inputs": {name: gates[name]["sha256"] for name in ("G3", "G4:rules", *llm)}}
            if implementation_name("s4", config) == "default":
                g5 = choices["s4"](g1, g3, assessments, **evaluation_args, call=calls)
            else:
                from fmb.pipeline.diff import differences
                from fmb.pipeline.evaluation import evaluate

                trusted = evaluate(g1, g3, assessments, **evaluation_args)
                g5 = choices["s4"](deepcopy(g1), deepcopy(g3), deepcopy(assessments),
                                   **deepcopy(evaluation_args), call=calls)
                validate_payload(g5, "pipeline_g5.schema.json")
                fixed = {k: v for k, v in trusted.items() if k not in {"comparison", "stage_validation"}}
                if fixed != {k: v for k, v in g5.items() if k not in {"comparison", "stage_validation"}}:
                    raise ValueError("S4 candidate changed the verified findings, scores, admission or input bindings")
                changed = differences(trusted["comparison"], g5["comparison"])
                trusted["candidate_evaluation"] = {"implementation": implementation_name("s4", config),
                                                   "comparison": g5["comparison"]}
                trusted["stage_validation"]["S4"] = {
                    "status": "failed" if changed else "passed", "validator": "fmb.pipeline.evaluation.evaluate",
                    "different_fields": [item["path"] for item in changed],
                }
                g5 = trusted
            mocked = [stage.upper() for stage in STAGE_KEYS if implementation_name(stage, config) == "mock-llm"]
            if mocked:
                g5["experiment"] = {"label": "mock_stage_experiment", "stages": mocked,
                                    "s3_assessor": g4_rules["assessor"]["id"]}
            gates["G5"] = write_gate(run_dir, "G5", g5)
    except BaseException as error:
        try:
            write_manifest(collected=collected, built=built, rules=rules, runs=runs,
                           failure={"step": state["step"], "type": type(error).__name__, "message": str(error)[:2000]})
        except BaseException as manifest_error:
            error.add_note(f"failed to record run manifest: {manifest_error}")
        raise
    write_manifest(collected=collected, built=built, rules=rules, runs=runs)
    return {"status": "completed" if admission["status"] == "passed" else "failed", "output": str(run_dir),
            "admission": admission["status"], "admission_policy": policy, "gates": sorted(gates),
            "dispatched": dispatching}
