from __future__ import annotations
import argparse
from contextlib import nullcontext
from pathlib import Path
from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.sealed_records import canonical_json, now, read_json, write_json
from fmb.core.case_contract import QIDS
from fmb.core.truth_guard import truth_blind_reads
from fmb.analysis.native_preparation import repair_usb_companion_rows, repair_native_stream_rows

def collect_native(*, evidence: Path, output: Path, windows_parsers: Path | None = None,
                   host_toolchain_root: Path | None = None,
                   vm_work_root: Path | None = None, profile: dict | None = None) -> dict:
    from fmb.collection.paper_collection import collect
    from fmb.profiles import resolve_paper_profile

    evidence = evidence.absolute()
    if not evidence.is_file():
        raise FileNotFoundError(str(evidence))
    receipt = output.with_name(output.name + "-truth-guard.json")
    if receipt.exists():
        raise FileExistsError("collection truth-guard record already exists")
    record = {
        "started_utc": now(),
        "status": "running",
        "evidence": str(evidence),
        "inference_calls": 0,
        "guard_scope": "collector Python process; subprocesses receive public image paths",
    }
    write_json(receipt, record)
    with truth_blind_reads(evidence.parent) as guard:
        primary_error = None
        try:
            if profile is None:
                profile = resolve_paper_profile()
            collect(argparse.Namespace(evidence=evidence, output=output,
                windows_parsers=windows_parsers, host_toolchain_root=host_toolchain_root,
                vm_work_root=vm_work_root),
                profile=profile)
        except BaseException as error:
            primary_error = error
            record.update(
                status="failed", error_type=type(error).__name__, error=str(error)
            )
            raise
        else:
            if guard["denied"]:
                record.update(status="failed", error_type="SuppressedPrivateRead")
                primary_error = ValueError(
                    "collector attempted a private read even though it suppressed the exception"
                )
                raise primary_error
            record["status"] = "completed"
        finally:
            record.update(
                finished_utc=now(),
                generation_files_opened=sorted(guard["opened"]),
                denied_private_reads=guard["denied"],
            )
            try:
                write_json(receipt, record)
            except BaseException as record_error:
                if primary_error is None:
                    raise
                primary_error.add_note(
                    f"Failed to write final collection truth-guard record {receipt}: "
                    f"{type(record_error).__name__}: {record_error}"
                )
    return {"status": "collected", "output": str(output), "truth_guard": str(receipt)}


SYSTEM_IMAGE = "full_scale.vmdk"
IMAGE_HASH_RECORDS = ("native-surface-preparation.json", "public-population-binding.json")


def image_binding(*, analysis: Path, generation: Path) -> dict:
    declared = {row["file"]: row["sha256"] for row in read_json(generation / "manifest.json").get("artifacts", [])
                if isinstance(row, dict) and "file" in row}
    collection = read_json(analysis / "factual-collection.json")
    if SYSTEM_IMAGE not in declared or Path(collection["evidence"]).name != SYSTEM_IMAGE:
        raise ValueError("the collection's evidence is not the generation's system image")
    supplement = analysis / "factual-supplement"
    records = ["factual-supplement/" + name for name in IMAGE_HASH_RECORDS]
    if not (supplement / IMAGE_HASH_RECORDS[0]).is_file():
        records[0] = "collection.json"
        if read_json(analysis / "collection.json").get("status") != "completed":
            raise ValueError("the collection has no completed image-hash receipt")
    recorded = {name: read_json(analysis / name).get("evidence_sha256") for name in records}
    if any(value != declared[SYSTEM_IMAGE] for value in recorded.values()):
        raise ValueError("the collection was made from another image than the generation's")
    binding = {"image": SYSTEM_IMAGE, "image_sha256": declared[SYSTEM_IMAGE],
               "image_hash_records": records,
               "evidence_index_sha256": collection["evidence_index_sha256"]}
    population = read_json(supplement / "public-population-binding.json").get("public_manifest_sha256")
    if population is not None:
        scope = generation / "factual-challenge-population.json"
        if not scope.is_file() or sha256_file(scope) != population:
            raise ValueError("the collection was made against another declared population")
        binding["scope_record_sha256"] = population
    return binding


def collected_kape_root(analysis: Path, index: dict, locate=None) -> Path:
    from fmb.collection.analysis import _kape_output_root
    from fmb.core.collection_paths import CollectionPaths

    locate = locate or CollectionPaths(analysis, index)
    roots = {root for run in index["parser_runs"] for row in run.get("raw_outputs", [])
             if _kape_output_root(Path(row["path"])) is not None
             if (root := _kape_output_root(locate(row["path"]))) is not None}
    if len(roots) != 1:
        raise ValueError("the collection must record one collector output root")
    return roots.pop()


def _planned_counts(planned_counts: dict | None) -> dict | None:
    if planned_counts is None:
        return None
    planned_counts = {qid: tuple(value) for qid, value in planned_counts.items()}
    if set(planned_counts) != set(QIDS) or any(
        len(v) != 2 or any(type(n) is not int for n in v)
        for v in planned_counts.values()
    ):
        raise ValueError(
            "planned roster counts must give (cards, targets) for the nine questions"
        )
    return planned_counts


def _verified_collection(analysis: Path, generation: Path) -> dict:
    collection = read_json(analysis / "factual-collection.json")
    collection_guard = read_json(analysis.with_name(analysis.name + "-truth-guard.json"))
    if (
        collection_guard.get("status") != "completed"
        or collection_guard.get("denied_private_reads") != []
        or Path(collection_guard["evidence"]).resolve()
        != Path(collection["evidence"]).resolve()
    ):
        raise ValueError("collection lacks a successful private-read guard")
    if (
        collection.get("status") != "completed"
        or collection.get("truth_sources_used") != []
        or sha256_file(analysis / "evidence_index.json") != collection["evidence_index_sha256"]
    ):
        raise ValueError("native collection is incomplete or not source-bound")
    binding = image_binding(analysis=analysis, generation=generation)
    collectors = read_json(analysis / "evidence_index.json").get("collector_runs", [])
    if not collectors or any(
        row.get("provenance", {}).get("source_evidence", {}).get("hash_verified") is not True
        or any(row["provenance"]["source_evidence"].get(key) != binding["image_sha256"]
               for key in ("sha256", "sha256_expected", "sha256_observed"))
        for row in collectors
    ):
        raise ValueError("collector provenance is not bound to the generation image")
    return binding


def _verified_parser_outputs(index: dict, locate) -> set[Path]:
    verified = {}
    for run in index["parser_runs"]:
        for row in [
            *run.get("raw_outputs", []),
            *([run["normalized_output"]] if run.get("normalized_output") else []),
        ]:
            path = locate(row["path"]).resolve(strict=True)
            expected = (row["size_bytes"], row["sha256"])
            if path in verified:
                if verified[path] != expected:
                    raise ValueError("parser sources disagree about the same file: " + str(path))
                continue
            if (
                path.stat().st_size != row["size_bytes"]
                or sha256_file(path) != row["sha256"]
            ):
                raise ValueError(
                    "parser source changed before native preparation: " + str(path)
                )
            verified[path] = expected
    return set(verified)


def _write_case(output: Path, qid: str, presented) -> dict:
    from fmb.core.case_contract import prepare_case, target_catalog

    (output / "bundles").mkdir(exist_ok=True)
    (output / "bundles" / (qid + ".json")).write_text(presented.canonical)
    case = prepare_case(presented)
    text = canonical_json(case)
    (output / "cases").mkdir(exist_ok=True)
    (output / "cases" / (qid + ".json")).write_text(text)
    return {
        "question_id": qid,
        "case_sha256": sha256_bytes(text.encode()),
        "bundle_sha256": presented.sha256,
        "subjects": len(case["candidate_roster"]),
        "targets": len(target_catalog(case)),
        "case_bytes": len(text.encode()),
    }


def prepare_cases(
    *, analysis: Path, generation: Path, output: Path, planned_counts: dict | None,
    questions: list[str] | None = None,
) -> dict:
    from fmb.analysis.catalog import TECHNIQUES
    from fmb.analysis.factual_contract import upgrade_factual_bundle
    from fmb.analysis.factual_presentation import present_bundle
    from fmb.analysis.inputs import build_analysis_input
    from fmb.analysis.mft_comparison import (
        POOL_QUESTIONS,
        build_comparison_pool,
        with_comparison_pool,
    )
    from fmb.analysis.shared_evidence import prepare_evidence_bundles
    from fmb.core.collection_paths import CollectionPaths
    from fmb.index.adapters.mft import mftecmd_mft_context_csv_files, raw_mft_path_for_root
    from fmb.index.adapters.ntfs_allocation import load_native_surfaces
    from fmb.profiles import resolve_paper_profile
    from fmb.pipeline.stages import profile_coverage

    profile = resolve_paper_profile(questions)
    selected = [q["question_id"] for q in profile["questions"]]
    techniques = {tid for q in profile["questions"] for tid in q["technique_ids"]}
    needs_mft = "ntfs.mft" in profile["artifact_families"]
    planned_counts = _planned_counts(planned_counts)
    generation, analysis = (
        generation.resolve(strict=True),
        analysis.resolve(strict=True),
    )
    output.mkdir(parents=True, exist_ok=False)
    with truth_blind_reads(generation) as guard:
        index_path = analysis / "evidence_index.json"
        guard_path = analysis.with_name(analysis.name + "-truth-guard.json")
        binding = _verified_collection(analysis, generation)
        index = read_json(index_path)
        profile_coverage(analysis, profile)
        verified_index = {"parser_runs": [run for run in index["parser_runs"]
                                          if run["parser_kind"] in profile["parser_outputs"]]}
        locate = CollectionPaths(analysis, verified_index, generation=generation)
        supplement = analysis / "factual-supplement"
        base_index = supplement / "base-evidence-index.json"
        base_data = read_json(base_index)
        from fmb.analysis.population_binding import load_generated_population_bundle
        from fmb.collection.factual_challenge import load_public_population

        generated = load_generated_population_bundle(generation / SYSTEM_IMAGE, verify_evidence_sha256=False)
        if generated is None or base_data.get("population_manifest") != generated.population_manifest:
            raise ValueError("the collection's base population differs from the generation's")
        if base_data.get("collector_runs") != index.get("collector_runs"):
            raise ValueError("the base population belongs to another collection")
        public = load_public_population(generation / SYSTEM_IMAGE)
        if public is None or binding.get("scope_record_sha256") != sha256_file(generation / "factual-challenge-population.json"):
            raise ValueError("the collection lacks a binding to the complete public population")
        population_binding = read_json(supplement / "public-population-binding.json")
        if not set(selected) <= set(population_binding.get("selected_questions", QIDS)):
            raise ValueError("the collection does not cover the selected question scope")
        source_paths = {
            index_path,
            base_index,
            generation / "manifest.json",
            generation / "population_manifest.json",
            analysis / "factual-collection.json",
            guard_path,
            *(analysis / name for name in binding["image_hash_records"]),
            *([generation / "factual-challenge-population.json"] if "scope_record_sha256" in binding else []),
        }
        native, raw_mft, serial, drive_binding = None, None, None, None
        if needs_mft:
            native = locate(read_json(supplement / "native-surface-preparation.json")["native_manifest"])
            kape_root = collected_kape_root(analysis, index, locate)
            csvs = mftecmd_mft_context_csv_files(kape_root)
            if len(csvs) != 1:
                raise ValueError("paper preparation requires one complete current MFT CSV")
            raw_mft = raw_mft_path_for_root(kape_root)
            serial = load_native_surfaces(native, raw_mft)["geometry"]["volume_serial_number"]
            source_paths.update({native, raw_mft, csvs[0]})
        if set(selected) & set(POOL_QUESTIONS):
            drive_binding = locate(read_json(supplement / "public-population-binding.json")["drive_letter_binding"])
            source_paths.add(drive_binding)
        source_paths |= _verified_parser_outputs({"parser_runs": [*verified_index["parser_runs"],
            *(r for r in base_data["parser_runs"] if r["parser_kind"] in profile["parser_outputs"])]}, locate)
        inputs = tuple(
            build_analysis_input(index, definition) for definition in TECHNIQUES if definition.technique_id in techniques
        )
        by_question = {
            bundle.question_id: bundle for bundle in prepare_evidence_bundles(inputs)
        }
        if set(by_question) != set(selected):
            raise ValueError("native image does not produce the selected question rosters")
        rows, repairs, presented_bundles = [], {}, []
        with raw_mft.open("rb") if raw_mft is not None else nullcontext() as handle:
            for qid in selected:
                bundle = upgrade_factual_bundle(by_question[qid])
                if qid in POOL_QUESTIONS:
                    bundle = with_comparison_pool(
                        bundle,
                        build_comparison_pool(
                            csv_path=csvs[0],
                            kape_root=kape_root,
                            cards=bundle.payload["candidate_roster"],
                            native_manifest_path=native,
                            raw_mft_path=raw_mft,
                            drive_binding_path=drive_binding,
                            locate=locate,
                        ),
                    )
                if qid == "BQ-USB-01":
                    bundle = repair_usb_companion_rows(bundle, analysis / "native-usb", locate=locate)
                changed = []
                if handle is not None:
                    bundle, changed = repair_native_stream_rows(bundle, handle)
                repairs[qid] = [row for row in changed if row["changes"]]
                presented = present_bundle(bundle)
                presented_bundles.append(presented)
                rows.append(_write_case(output, qid, presented))
        from fmb.core.schemas import validate_payload
        from fmb.preparation.binding import binding_table

        table = binding_table(base_index=base_data, bundles=presented_bundles,
                              native_volume_serial_number=serial)
        validate_payload(table, "reference_binding.schema.json")
        write_json(output / "reference-binding.json", table)
        source_records = {
            str(path.resolve()): {
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
            for path in sorted(source_paths)
        }
        write_json(output / "source-records.json", source_records)
        manifest = {
            "schema_version": "paper_native_preparation.v1",
            "prepared_utc": now(),
            "realism": "native",
            "status": "development",
            "generation": str(generation),
            "analysis": str(analysis),
            "base_evidence_index": str(base_index),
            "native_manifest": str(native) if native is not None else None,
            "raw_mft": str(raw_mft) if raw_mft is not None else None,
            "native_volume_serial_number": serial,
            "collection_binding": binding,
            "collection_original_root": str(locate.original),
            "source_repairs": repairs,
            "rows": rows,
            "planned_counts": planned_counts,
            "truth_sources_used": [],
            "model_calls": 0,
            "generation_files_opened": sorted(guard["opened"]),
        }
        if selected != list(QIDS):
            manifest.update(schema_version="paper_native_preparation.v2", selected_questions=selected)
    return manifest
