from __future__ import annotations

from pathlib import Path

from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.paper_artifacts import build_content_sha256
from fmb.core.sealed_records import canonical_json, read_json
from fmb.core.truth_guard import COMPANION_MEDIA, public_generation_files, system_image

SCOPE_RECORD_NAMES = ("population_manifest.json", "population-manifest.json", "factual-challenge-population.json")


ROOT_NAMES = ("run", "generation", "analysis")


def located(path: Path, roots: dict[str, Path] | None) -> dict:
    path = Path(path).absolute()
    for name in ROOT_NAMES:
        root = (roots or {}).get(name)
        if root is not None:
            try:
                return {"root": name, "path": path.relative_to(Path(root).absolute()).as_posix()}
            except ValueError:
                continue
    return {"path": str(path)}


def resolve(reference: dict, roots: dict[str, Path] | None) -> Path:
    if "root" not in reference:
        return Path(reference["path"])
    return Path(roots[reference["root"]]) / reference["path"]


def file_ref(path: Path, *, recorded: dict[str, str] | None = None, roots: dict[str, Path] | None = None) -> dict:
    path = Path(path)
    if recorded is not None:
        if path.name not in recorded:
            raise ValueError("the generation manifest records no hash for " + path.name)
        return {**located(path, roots), "sha256": recorded[path.name], "size_bytes": path.stat().st_size,
                "sha256_source": "generation_manifest"}
    return {**located(path, roots), "sha256": sha256_file(path), "size_bytes": path.stat().st_size,
            "sha256_source": "computed"}


def evidence_gate(generation: Path, case_label: str, roots: dict[str, Path] | None = None) -> dict:
    root = Path(generation).resolve(strict=True)
    manifest_path = root / "manifest.json"
    manifest = read_json(manifest_path)
    recorded = {row["file"]: row["sha256"] for row in manifest.get("artifacts", []) if isinstance(row, dict) and "file" in row}
    image = system_image(manifest)["file"]
    media = []
    for path in sorted(root.iterdir()):
        match = COMPANION_MEDIA.fullmatch(path.name)
        if match and match.group(2) != "json" and not path.is_symlink():
            record = file_ref(root / f"media_{match.group(1)}.json", roots=roots)
            if recorded.get(Path(record["path"]).name, record["sha256"]) != record["sha256"]:
                raise ValueError("acquisition record differs from the generation manifest: " + record["path"])
            media.append({"media_id": match.group(1), "image": file_ref(path, recorded=recorded, roots=roots),
                          "acquisition_record": record})
    scope = [file_ref(root / name, roots=roots) for name in SCOPE_RECORD_NAMES if (root / name).is_file()]
    for record in scope:
        if recorded.get(Path(record["path"]).name, record["sha256"]) != record["sha256"]:
            raise ValueError("scope record differs from the generation manifest: " + record["path"])
    return {
        "gate": "G1",
        "schema_version": "fmb.pipeline.g1.v1",
        "case_label": case_label,
        "mode": "generated_benchmark",
        "generation_root": "generation" if roots else str(root),
        "system_image": file_ref(root / image, recorded=recorded, roots=roots),
        "companion_media": media,
        "scope_records": scope,
        "generation_manifest": file_ref(manifest_path, roots=roots),
        "readable_paths": sorted((p.relative_to(root).as_posix() if roots else str(p))
                                 for p in public_generation_files(root, image) if p.exists()),
    }


def check_reads(opened: list[str], g1: dict, *, stage: str, generation: Path | None = None) -> None:
    g1_root = None if g1.get("generation_root") == "generation" else Path(g1["generation_root"])

    def name(path: str, root: Path | None) -> str:
        if root is None or not Path(path).is_absolute():
            return path
        if not Path(path).is_relative_to(root):
            raise ValueError(f"{stage} recorded a read outside the generation folder it read: {path}")
        return Path(path).relative_to(root).as_posix()

    declared = {name(p, g1_root) for p in g1["readable_paths"]}
    undeclared = sorted({name(p, Path(generation) if generation is not None else g1_root) for p in opened} - declared)
    if undeclared:
        raise ValueError(f"{stage} read generation files that G1 does not declare: " + ", ".join(undeclared))


def profile_gate(profile: dict, definitions: dict | None = None) -> dict:
    kape = profile["collection_declaration"]["collection"]["kape"]
    return {
        "gate": "G2",
        "schema_version": "fmb.pipeline.g2.v1",
        "question_group_version": str(profile["question_group_version"]),
        **({"question_definitions": definitions} if definitions is not None else {}),
        "questions": profile["questions"],
        "artifact_families": profile["artifact_families"],
        "parser_outputs": profile["parser_outputs"],
        "collection": {
            "targets": list(kape["target_names"]),
            "modules": list(kape["module_names"]),
            "kape_definitions": profile["collection_declaration"]["kape_definitions"],
        },
    }


COVERING_STATUSES = {"complete", "partial"}


def profile_coverage(analysis: Path, g2: dict) -> dict:
    runs = read_json(Path(analysis) / "evidence_index.json")["parser_runs"]
    coverage: dict[str, dict] = {}
    undeclared = []
    for question in g2["questions"]:
        toolset = question.get("toolset")
        families = {}
        for family in question["artifact_families"]:
            declared = None if toolset is None else {(p["parser"], p["module"]) for p in toolset[family]["parsers"]}
            matching = []
            for run in runs:
                if family not in (run.get("coverage_families") or []):
                    continue
                entry = {"parser": str(run.get("parser")), "module": run.get("source_module"),
                         "status": str(run.get("status")), "coverage": run.get("coverage_status")}
                if declared is not None:
                    entry["declared"] = (entry["parser"], str(entry["module"]).split("#")[0]) in declared
                matching.append(entry)
            usable = [r for r in matching if r["status"] == "consumed" and r["coverage"] in COVERING_STATUSES]
            undeclared += [f"{question['question_id']}: {family} by {r['parser']} {r['module']}"
                           for r in usable if r.get("declared") is False]
            families[family] = {"covered": bool(usable), "runs": matching}
        coverage[question["question_id"]] = families
    missing = [f"{qid}: {family}" for qid, families in coverage.items()
               for family, entry in families.items() if not entry["covered"]]
    if missing:
        raise ValueError("S2 collected no usable source for families the profile requires: " + ", ".join(missing))
    if undeclared:
        raise ValueError("S2 covered families with parsers G2 does not declare: " + ", ".join(undeclared))
    return coverage


def cards_gate(built: Path, case_label: str, *, g2_sha256: str, coverage: dict, collection: dict,
               reference_binding: Path | None, sources: dict, roots: dict[str, Path] | None = None) -> dict:
    built = Path(built)
    report = read_json(built / "build-report.json")
    seal = read_json(built / "build-seal.json")["requests"]
    questions: dict[str, dict] = {}
    for item in read_json(built / "items.json"):
        request_id, qid = item["case_id"], item["question_id"]
        binding = seal[request_id]
        entry = questions.setdefault(qid, {"cards": report["questions"][qid]["cards"],
                                           "findings": report["questions"][qid]["findings"], "requests": []})
        entry["requests"].append({key: binding[key] for key in ("case_sha256", "sent_sha256", "sent_bytes", "findings")}
                                 | {"request_id": request_id})
    return {
        "gate": "G3",
        "schema_version": "fmb.pipeline.g3.v1",
        "case_label": case_label,
        "level": report["level"],
        "g2_sha256": g2_sha256,
        "build_seal": file_ref(built / "build-seal.json", roots=roots),
        "view_options": file_ref(built / "view-options.json", roots=roots),
        **({"stream_heads": file_ref(built / "stream-heads.json", roots=roots)}
           if (built / "stream-heads.json").is_file() else {}),
        "content_sha256": build_content_sha256(built),
        "view_options_sha256": report["options_sha256"],
        "questions": questions,
        "requests_per_pass": report["requests_per_pass"],
        "findings": report["findings"],
        "truth_sources_used": report["truth_sources_used"],
        "profile_coverage": coverage,
        "collection": collection,
        **({"reference_binding": file_ref(reference_binding, roots=roots)} if reference_binding is not None else {}),
        "sources": sources,
        "question_scope": question_scope(built),
        "views": view_differences(built),
    }


def question_scope(built: Path) -> str:
    return "hidden" if "no_scope" in read_json(Path(built) / "view-options.json").get("views", []) else "shown"


def _paths(value, prefix: str = "") -> set[str]:
    paths = set()
    if isinstance(value, dict):
        for key, item in value.items():
            paths |= {prefix + "/" + key} | _paths(item, prefix + "/" + key)
    elif isinstance(value, list):
        for item in value:
            paths |= _paths(item, prefix + "/*")
    return paths


def view_differences(built: Path) -> dict:
    from fmb.core import paper_contract

    built = Path(built)
    options = paper_contract.bind_options(read_json(built / "view-options.json"), built)
    differences: dict[str, dict] = {}
    for item in read_json(built / "items.json"):
        sent = read_json(built / "sent" / (item["case_id"] + ".json"))
        decoded = paper_contract.decode_case(sent, options)
        entry = differences.setdefault(item["question_id"], {"added": set(), "dropped": set()})
        entry["added"] |= _paths(decoded) - _paths(sent)
        entry["dropped"] |= _paths(sent) - _paths(decoded)
    return {
        "sent": {"read_by": ["S3'", "S3"], "description": "the card as the model receives it; S3 reads the same card"},
        "decoded": {"read_by": ["S3"],
                    "description": "the sent card in S3's own format, made by S3's adapter: it adds the question's "
                                   "scope statement from the G2 definition when the scope is hidden, and fields it "
                                   "recomputes from the card itself; it adds no evidence",
                    "differences_from_sent": {q: {"added": sorted(e["added"]), "dropped": sorted(e["dropped"])}
                                              for q, e in differences.items()}},
    }


def rules_gate(rules: Path, built: Path, g3: dict, g3_sha256: str, roots: dict[str, Path] | None = None) -> dict:
    from fmb.assessment.stage import decode_for_engine, rule_result, verify_assessment
    from fmb.core import paper_contract
    from fmb.core.sealed_records import contained_path

    rules, built = Path(rules), Path(built)
    record = verify_assessment(rules, built=built)
    seal = read_json(built / "build-seal.json")["requests"]
    options = paper_contract.bind_options(read_json(built / "view-options.json"), built)
    results = []
    for question, entry in g3["questions"].items():
        for request in entry["requests"]:
            request_id = request["request_id"]
            if seal[request_id]["sent_sha256"] != request["sent_sha256"]:
                raise ValueError("sent card differs from G3: " + request_id)
            sent = read_json(contained_path(built, "sent/" + request_id + ".json"))
            case = decode_for_engine(sent, options, record["question_definitions"])
            prediction, _ = rule_result(rules, request_id, case)
            results.append({"request_id": request_id, "question_id": question, "pass": None, "state": "completed",
                            "supported_findings": prediction["supported_findings"],
                            "insufficient_findings": prediction["insufficient_findings"]})
    return {"gate": "G4", "schema_version": "fmb.pipeline.g4.v1", "case_label": g3["case_label"],
            "assessor": {"kind": "rules", "id": record["engine"]["id"], "view": "decoded",
                         "engine": {"module": record["engine"]["module"]},
                         "assessment": file_ref(rules / "assessment.json", roots=roots),
                         "assessment_seal": file_ref(rules / "assessment-seal.json", roots=roots)},
            "status": "complete", "g3_sha256": g3_sha256, "build_content_sha256": record["build_content_sha256"],
            "results": results}


def llm_gate(condition_run: Path, case_label: str, g3_sha256: str, roots: dict[str, Path] | None = None) -> dict:
    condition_run = Path(condition_run)
    protocol = read_json(condition_run / "protocol.json")
    manifest = read_json(condition_run / "manifest.json")
    question = {row["request_id"]: row["question_id"] for row in manifest["rows"]}
    results, status, dispatch = [], "frozen", None
    if (condition_run / "run" / "completion.json").is_file():
        from fmb.core.paper_policy import resolve_policy

        status = "executed"
        schedule = read_json(condition_run / "run" / "schedule.json")
        dispatch = {"execution_policy": schedule.get("execution_policy") or resolve_policy(protocol),
                    "policy_recorded_at_execution": "execution_policy" in schedule,
                    **{key: schedule[key] for key in ("cap_usd", "rates_usd_per_million", "pass_limit",
                                                     "execution_claim", "completion_of") if key in schedule}}
        for path in sorted((condition_run / "run").glob("call-*/outcome.json")):
            outcome = read_json(path)
            answer = path.with_name("two-list.json")
            two = read_json(answer) if outcome["status"] == "completed" and answer.is_file() else None
            results.append({"request_id": outcome["request_id"], "question_id": question[outcome["request_id"]],
                            "pass": outcome["pass"], "state": outcome["status"], "attempts": outcome.get("attempts", 0),
                            "supported_findings": two["supported_findings"] if two else [],
                            "insufficient_findings": two["insufficient_findings"] if two else []})
    return {
        "gate": "G4", "schema_version": "fmb.pipeline.g4.v1", "case_label": case_label,
        "assessor": {"kind": "llm", "id": protocol["condition_id"], "view": "sent",
                     "condition_run": located(condition_run, roots)["path"],
                     "condition_seal": file_ref(condition_run / "preparation-seal.json", roots=roots),
                     **({"prediction_seal": file_ref(condition_run / "run" / "prediction-seal.json", roots=roots)}
                        if status == "executed" else {}),
                     "settings": protocol["settings"]},
        "status": status, "g3_sha256": g3_sha256, **({"dispatch": dispatch} if dispatch else {}),
        "requests": [{"request_id": row["request_id"], "request_sha256": row["request_sha256"]} for row in manifest["rows"]],
        "results": results,
    }


def evaluation_gate(case_label: str, admission: dict, condition_runs: list[Path], scores: dict, *,
                    findings: list[dict], comparison: dict, roots: dict[str, Path], policy: str,
                    inputs: dict[str, str], stage_validation: dict) -> dict:
    return {
        "gate": "G5", "schema_version": "fmb.pipeline.g5.v1", "case_label": case_label,
        "admission": {"status": admission["status"], "policy": policy,
                      "certificates": [file_ref(Path(run) / "admission" / "admission.json", roots=roots)
                                       for run in condition_runs]},
        "scores": scores,
        "inputs": inputs,
        "findings": findings,
        "comparison": comparison,
        "stage_validation": stage_validation,
    }


def check_build(g3: dict, roots: dict[str, Path]) -> Path:
    from fmb.core.sealed_records import contained_path

    for key in ("build_seal", "view_options", "stream_heads"):
        if key in g3 and sha256_file(resolve(g3[key], roots)) != g3[key]["sha256"]:
            raise ValueError(f"the build's {key.replace('_', ' ')} differs from G3")
    built = resolve(g3["build_seal"], roots).parent
    for entry in g3["questions"].values():
        for request in entry["requests"]:
            if sha256_file(contained_path(built, "sent/" + request["request_id"] + ".json")) != request["sent_sha256"]:
                raise ValueError("sent card differs from G3: " + request["request_id"])
    return built


def check_preparation(g3: dict, roots: dict[str, Path]) -> tuple[Path, Path]:
    from fmb.core.sealed_records import verify_seal

    built = check_build(g3, roots)
    reference = g3["preparation_seal"]
    seal = resolve(reference, roots)
    if (built != roots["run"] / "preparation/cards"
            or seal != roots["run"] / "preparation/prepared/preparation-seal.json"):
        raise ValueError("G3 does not use the supported sealed preparation layout")
    if sha256_file(seal) != reference["sha256"]:
        raise ValueError("preparation seal differs from G3")
    verify_seal(seal.parent, seal.name)
    verify_seal(built, "build-seal.json")
    return seal.parent, built


def check_assessment(g4: dict, g3: dict, roots: dict[str, Path]) -> Path:
    from fmb.core.paper_artifacts import verify_prepared_condition
    from fmb.core.sealed_records import verify_seal

    if g4["g3_sha256"] != sha256_bytes((canonical_json(g3) + "\n").encode()):
        raise ValueError("G4 belongs to another G3")
    assessor = g4["assessor"]
    kind = assessor["kind"]
    root = roots["run"] / ("assessment/rules" if kind == "rules" else "conditions/" + assessor["id"])
    files = ({"assessment": "assessment.json", "assessment_seal": "assessment-seal.json"} if kind == "rules"
             else {"condition_seal": "preparation-seal.json"})
    if kind == "llm" and g4["status"] == "executed":
        files["prediction_seal"] = "run/prediction-seal.json"
    for key, filename in files.items():
        reference = assessor[key]
        path = resolve(reference, roots)
        if path != root / filename:
            raise ValueError("G4 does not use the supported sealed assessment layout")
        if sha256_file(path) != reference["sha256"]:
            raise ValueError("assessment artifact differs from G4: " + key)
    built = check_build(g3, roots)
    if kind == "rules":
        expected = rules_gate(root, built, g3, g4["g3_sha256"], roots)
    else:
        verify_prepared_condition(root, built=built)
        if g4["status"] == "executed":
            verify_seal(root / "run", "prediction-seal.json")
        expected = llm_gate(root, g3["case_label"], g4["g3_sha256"], roots)
    if g4 != expected:
        raise ValueError("G4 differs from its sealed assessment")
    return root


def checked_binding(g3: dict, roots: dict[str, Path]) -> Path | None:
    if "reference_binding" not in g3:
        return None
    path = resolve(g3["reference_binding"], roots)
    if sha256_file(path) != g3["reference_binding"]["sha256"]:
        raise ValueError("S2's binding table differs from G3")
    return path


def _cited_source(value: str) -> str:
    parts = str(value).split(":")
    if parts[0] == "native" and parts[1:2] == ["mft-source"]:
        return ":".join(parts[:3])
    if parts[0] in {"source", "native-mft", "native-usb-volume"}:
        return ":".join(parts[:2])
    return parts[0]


def source_table(analysis: Path, generation: Path, built: Path, roots: dict[str, Path],
                 *, parser_kinds: set[str] | None = None) -> dict:
    from fmb.core.collection_paths import CollectionPaths

    cited = set()
    for path in sorted((Path(built) / "sent").glob("*.json")):
        cited |= {_cited_source(value) for value in read_json(path).get("source_reference_map", {}).values()}
    if not cited:
        return {}
    analysis = Path(analysis)
    index = read_json(analysis / "evidence_index.json")
    if parser_kinds is not None:
        index["parser_runs"] = [r for r in index["parser_runs"] if r.get("parser_kind") in parser_kinds]
    locate = CollectionPaths(analysis, index, generation=generation)
    by_id: dict[str, dict] = {}
    by_name: dict[str, set[str]] = {}
    for run in index.get("parser_runs", []):
        rows = [*run.get("raw_outputs", []), *([run["normalized_output"]] if run.get("normalized_output") else [])]
        for row in rows:
            source = row.get("artifact_record_id") if isinstance(row, dict) else None
            if not isinstance(source, str) or not source.startswith("source:") or "path" not in row:
                continue
            entry = by_id.setdefault(source, {
                "sha256": row["sha256"], "size_bytes": int(row["size_bytes"]),
                **located(locate(row["path"]), roots), "artifact_family": row.get("artifact_family"), "read_by": []})
            if entry["sha256"] != row["sha256"]:
                raise ValueError("the collection records two files under one source: " + source)
            reader = {"parser": str(run.get("parser")), "module": run.get("source_module")}
            if reader not in entry["read_by"]:
                entry["read_by"].append(reader)
            by_name.setdefault(Path(str(row.get("relative_path", ""))).name, set()).add(source)

    def sidecar(path: Path, digest: str, family: str, parser: str) -> dict:
        if sha256_file(path) != digest:
            raise ValueError("a native sidecar differs from the hash that names it: " + str(path))
        return {"sha256": digest, "size_bytes": path.stat().st_size, **located(path, roots),
                "artifact_family": family, "read_by": [{"parser": parser, "module": None}]}

    native = {}
    if any(key.startswith("native-mft:") for key in cited):
        manifest_path = locate(read_json(analysis / "factual-supplement" / "native-surface-preparation.json")
                               ["native_manifest"])
        for record in read_json(manifest_path)["records"]:
            native["native-mft:" + record["record_sha256"]] = (manifest_path.parent / record["record_file"],
                                                              record["record_sha256"], "ntfs.mft", "native_ntfs")
    if any(key.startswith("native-usb-volume:") for key in cited):
        for path in sorted((analysis / "native-usb").glob("*/native-usb-volume.json")):
            native["native-usb-volume:" + sha256_file(path)] = (path, sha256_file(path), "usb_volume", "native_usb")
    population_binding = analysis / "factual-supplement" / "public-population-binding.json"
    if population_binding.is_file() and any(key.startswith("source:") and key not in by_id for key in cited):
        binding = read_json(locate(read_json(population_binding)["drive_letter_binding"]))
        system = locate(binding["system_path"])
        by_id.setdefault("source:" + binding["system_sha256"][:16], {
            "sha256": binding["system_sha256"], "size_bytes": system.stat().st_size, **located(system, roots),
            "artifact_family": "windows.registry.system", "read_by": [{"parser": "native_drive_binding",
                                                                       "module": "MountedDevices"}]})
        gpt = binding["proof"]["gpt_partition_source_ref"].split(":")
        by_id.setdefault(":".join(gpt[:2]), {
            "sha256_prefix": gpt[1], "image_region": "GPT partition entries",
            **located(Path(generation) / system_image(read_json(Path(generation) / "manifest.json"))["file"], roots),
            "read_by": [{"parser": "native_drive_binding", "module": "GPT"}]})
    table, unknown = {}, []
    for key in sorted(cited):
        if key.startswith("native:mft-source:"):
            key_id = "source:" + key.split(":")[2]
            entry = by_id.get(key_id)
        elif key in native:
            entry = sidecar(*native[key])
        elif key.startswith("source:"):
            entry = by_id.get(key)
        else:
            named = by_name.get(key, set())
            entry = by_id[next(iter(named))] if len(named) == 1 else None
        if entry is None:
            unknown.append(key)
        else:
            table[key] = entry
    if unknown:
        raise ValueError("the cards cite sources the collection does not record: " + ", ".join(unknown[:5]))
    return table


def prepare_evidence(g1: dict, g2: dict, *, roots: dict[str, Path], g2_sha256: str,
                     collect: dict | None = None, question_scope: str = "hidden", assemble=None) -> dict:
    from fmb.paper.workflow import prepare
    from fmb.preparation.native import collect_native
    from fmb.profiles import collection_profile

    run_dir, generation, analysis = roots["run"], roots["generation"], roots["analysis"]
    label = g1["case_label"]
    collected = collect is not None
    if collected:
        collect_native(
            evidence=resolve(g1["system_image"], roots), output=analysis,
            windows_parsers=Path(collect["windows_parsers"]) if collect.get("windows_parsers") else None,
            host_toolchain_root=Path(collect["host_toolchain_root"]) if collect.get("host_toolchain_root") else None,
            vm_work_root=Path(collect["vm_work_root"]) if collect.get("vm_work_root") else None,
            profile=collection_profile(g2),
        )
    collection_guard = read_json(analysis.with_name(analysis.name + "-truth-guard.json"))
    check_reads(collection_guard.get("generation_files_opened", []), g1, stage="S2 collection",
                generation=Path(collection_guard["evidence"]).parent)
    prepare(analysis=analysis, generation=generation, image=label, output=run_dir / "preparation",
            question_scope=question_scope, presentation_check=False, g2=g2,
            **({"assemble": assemble} if assemble is not None else {}))
    built = run_dir / "preparation" / "cards"
    prepared = run_dir / "preparation" / "prepared"
    check_reads(read_json(built / "build-report.json").get("generation_files_opened", []), g1,
                stage="S2 preparation", generation=generation)
    coverage = profile_coverage(analysis, g2)
    preparation = read_json(prepared / "manifest.json")
    binding = {"mode": "collected" if collected else "reused", **preparation["collection_binding"]}
    if binding["image_sha256"] != g1["system_image"]["sha256"]:
        raise ValueError("the collection's image hash differs from G1's")
    table = prepared / "reference-binding.json"
    g3 = cards_gate(built, label, g2_sha256=g2_sha256, coverage=coverage, roots=roots,
                    collection=binding, reference_binding=table if table.is_file() else None,
                    sources=source_table(analysis, generation, built, roots, parser_kinds=set(g2["parser_outputs"])))
    g3["preparation_seal"] = file_ref(prepared / "preparation-seal.json", roots=roots)
    return g3
