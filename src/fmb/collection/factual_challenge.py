from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from fmb.analysis.catalog import TECHNIQUES
from fmb.analysis.inputs import (assert_truth_blind, canonical_sha256, candidate_identity,
                                 iter_observations, observation_matches_technique)
from fmb.analysis.questions import broad_question
from fmb.core.hashing import sha256_file
from fmb.core.json_io import load_json_object, write_json
from fmb.index.adapters.mft import (
    build_mft_presence_context,
    mftecmd_mft_context_csv_files,
    mftecmd_mft_parser_run,
)
from fmb.index.adapters.parser_output import source_bound_observations
from fmb.index.adapters.usn import raw_usn_observation_from_record
from fmb.index.support.windows_identity import (
    normalize_windows_compare_path,
    windows_compare_path_parts,
)
from fmb.index.contract.evidence_index import normalize_parser_output
from fmb.index.scanners.usn import DEFAULT_SCAN_CHUNK_SIZE, _iter_usn_v2_records


def load_public_population(evidence: Path) -> dict | None:
    manifest_path = evidence.parent / "manifest.json"
    if not manifest_path.is_file():
        return None
    manifest = load_json_object(manifest_path, label="generation manifest")
    name = "factual-challenge-population.json"
    records = [r for r in manifest.get("artifacts", []) if r.get("file") == name]
    path = evidence.parent / name
    if not records:
        if path.exists():
            raise ValueError("supplemental public population is not bound to the image manifest")
        return None
    if (len(records) != 1 or not path.is_file() or path.is_symlink()
            or path.stat().st_size != records[0]["size_bytes"]
            or sha256_file(path) != records[0]["sha256"]):
        raise ValueError("supplemental public population failed its manifest binding")
    public = load_json_object(path, label="public factual population")
    if (set(public) != {"schema_version", "profile", "root", "members"}
            or public["schema_version"] != "factual_challenge_population.v1"
            or public["profile"] not in {"pilot_min.v1"}
            or not isinstance(public["members"], list) or not public["members"]):
        raise ValueError("unknown public factual population contract")
    root = normalize_windows_compare_path(public["root"]) + "\\"
    seen = set()
    for member in public["members"]:
        if set(member) != {"question_id", "path"}:
            raise ValueError("public factual membership contains unregistered fields")
        broad_question(member["question_id"])
        path = member["path"]
        if (not isinstance(path, str) or not normalize_windows_compare_path(path).startswith(root)
                or path in seen or windows_compare_path_parts(path)[0] != "c"):
            raise ValueError("invalid or repeated public factual path")
        seen.add(path)
    return public


def _membership_usn_run(index: dict, public: dict, output: Path, context: dict) -> dict:
    from fmb.collection.analysis import _raw_usn_journal_path

    journal = _raw_usn_journal_path(index)
    if journal is None:
        raise ValueError("public historical membership needs the retained native journal")
    paths = {normalize_windows_compare_path(m["path"]) for m in public["members"]
             if m["question_id"] in {"BQ-DELETE-01", "BQ-TIME-01"}}
    names = {p.rsplit("\\", 1)[-1] for p in paths}
    observations, scan = [], {}
    with journal.open("rb") as handle:
        def reader(offset, size):
            handle.seek(offset)
            return handle.read(size)
        for record in _iter_usn_v2_records(reader, stream_size_bytes=journal.stat().st_size,
                                           chunk_size_bytes=DEFAULT_SCAN_CHUNK_SIZE, scan=scan):
            if str(record.get("file_name", "")).casefold() not in names:
                continue
            observation = raw_usn_observation_from_record(
                journal_path=journal, record_index=len(observations) + 1, record=record,
                scan_strategy="public_path_membership_scan", mft_context=context,
                observation_id_prefix="obs:factual-membership-usn",
                fallback_observation_type="usn_journal_record")
            if observation and normalize_windows_compare_path(observation["subject_ref"]) in paths:
                observations.append(observation)
                if len(observations) > 50000:
                    raise ValueError("public membership scan exceeds its retained-record bound")
    if scan.get("source_truncated"):
        raise ValueError("public historical membership scan did not cover the journal")
    if scan.get("unsupported_record_count"):
        raise ValueError("public historical membership scan met USN record versions it does not decode")
    observations = source_bound_observations(observations, journal)
    path = output / "public-membership-usn.json"
    write_json(path, {"schema_version": "parser_observation_index.v1", "parser": "fmb_bounded_parser",
                      "parser_kind": "ntfs_usn", "source": str(journal), "scan": scan,
                      "record_count": len(observations), "observations": observations,
                      "truth_sources_used": []})
    return normalize_parser_output(parser="fmb_bounded_parser", parser_kind="ntfs_usn",
        source_collector=index["collector_runs"][0]["collector"], source_module="FMBPublicMembershipUSN",
        raw_outputs=[journal, *[Path(p) for p in context["source_paths"]]], normalized_output=path,
        observations=observations, tool_identity={"name": "fmb.public_path_membership_scan", "version": "1"},
        observation_families=["ntfs.usn"], coverage_status="partial")


def _eligible_techniques(member: dict) -> tuple[str, ...]:
    qid = member["question_id"]
    if qid == "BQ-DELETE-01":
        return ("deleted_file_journal_residue",)
    if qid == "BQ-FILE-01":
        return ("bitmap_trailing_data",) if member["path"].casefold().endswith(".bmp") else ("ntfs_allocation_inconsistency",)
    if qid == "BQ-EXEC-01":
        return ("prefetch_missing_executable",)
    return broad_question(qid).technique_ids


def _populations(index: dict, base_populations: list[dict], public: dict) -> list[dict]:
    observations = tuple(iter_observations(index))
    definitions = {t.technique_id: t for t in TECHNIQUES}
    seed = {p["technique_id"]: deepcopy(p) for p in base_populations}
    for member in public["members"]:
        for technique in _eligible_techniques(member):
            if technique not in seed:
                continue
            definition = definitions[technique]
            matches = [o for o in observations
                if o.artifact_family in definition.candidate_artifact_families
                and observation_matches_technique(definition, o)
                and normalize_windows_compare_path(o.subject_ref) == normalize_windows_compare_path(member["path"])
                and (technique != "timestamp_manipulation" or o.artifact_family == "ntfs.mft")
                and (technique != "deleted_file_journal_residue" or o.artifact_family == "ntfs.usn")
                and (technique != "prefetch_missing_executable" or o.artifact_family == "windows.prefetch")
                and (technique != "shellbag_missing_directory" or o.artifact_family == "windows.registry.shellbag")
                and (technique != "bitmap_trailing_data" or o.observation_type == "logical_allocated_size_record")
                and (technique != "ntfs_allocation_inconsistency" or o.observation_type == "ntfs_allocation_record")]
            identities = {}
            for observation in matches:
                display, identity = candidate_identity(definition, observation)
                identities[canonical_sha256(identity)] = {"subject_ref": display, "identity": identity, "observation_ids": []}
            if not identities:
                raise ValueError(f"native public membership is missing for {technique}: {member['path']}")
            if technique != "deleted_file_journal_residue" and len(identities) != 1:
                raise ValueError(f"public path is ambiguous for {technique}: {member['path']}")
            seed[technique]["subjects"].extend(identities.values())
    result = []
    for technique, population in seed.items():
        definition = definitions[technique]
        subjects = {}
        for subject in population["subjects"]:
            identity = subject["identity"]
            key = canonical_sha256(identity)
            matches = [o.observation_id for o in observations
                       if o.artifact_family in definition.projected_artifact_families
                       and observation_matches_technique(definition, o)
                       and candidate_identity(definition, o)[1] == identity]
            if not matches:
                raise ValueError(f"no retained observations for a declared {technique} subject")
            subjects[key] = {**subject, "observation_ids": sorted(matches)}
        population.update(population_id="population:" + canonical_sha256({
            "public": public, "base_id": population["population_id"], "technique": technique})[:24],
            subjects=[subjects[k] for k in sorted(subjects)], coverage_status="complete")
        result.append(population)
    return result


def add_factual_population(index: dict, *, evidence: Path, public: dict, output_dir: Path,
                           questions: list[str] | None = None) -> dict:
    from fmb.collection.alignment import add_native_population_surfaces
    from fmb.collection.analysis import add_reference_scoped_usn, add_reference_scoped_ads
    from fmb.analysis.mft_comparison import POOL_QUESTIONS
    from fmb.profiles import resolve_paper_profile
    from fmb.index.adapters.mft import raw_mft_path_for_root

    prepared = deepcopy(index)
    base_populations = deepcopy(index["candidate_populations"])
    original_manifest = deepcopy(index["population_manifest"])
    techniques = {p["technique_id"] for p in base_populations}
    members = [m for m in public["members"] if questions is None or m["question_id"] in questions]
    needs_mft = questions is None or "ntfs.mft" in resolve_paper_profile(questions)["artifact_families"]
    drive_binding_path = None
    output_dir.mkdir(parents=True, exist_ok=False)
    write_json(output_dir / "base-evidence-index.json", index)
    if needs_mft:
        root = Path(index["collector_runs"][0]["output_root"])
        csvs = mftecmd_mft_context_csv_files(root)
        if len(csvs) != 1:
            raise ValueError("supplemental collection needs one complete native MFT CSV")
        raw_mft = raw_mft_path_for_root(root)
        context = build_mft_presence_context(root)
        from fmb.index.adapters.volume_binding import collect_drive_binding, load_drive_binding, drive_letters_from_proof
        if questions is None or set(questions) & set(POOL_QUESTIONS):
            drive_binding_path = output_dir / "drive-letter-binding.json"
            source_native = Path(load_json_object(
                output_dir.parent / "native-surface-preparation.json", label="base native sources")["native_manifest"])
            collect_drive_binding(source_native, root, drive_binding_path)
            drive_proof = load_drive_binding(drive_binding_path)
            context["indexed_volumes"] = set(context["indexed_volumes"]) | drive_letters_from_proof(drive_proof)
            context["native_drive_binding_source"] = str(drive_binding_path)
        public_paths = frozenset(m["path"] for m in members)
        replacement = mftecmd_mft_parser_run(csv_path=csvs[0], raw_mft_path=raw_mft,
            normalized_output_dir=output_dir, collector_run=index["collector_runs"][0], public_paths=public_paths)
        replacement.pop("candidate_populations", None)
        prepared["parser_runs"] = [r for r in prepared["parser_runs"] if r.get("parser_kind") != "ntfs_mft"]
        prepared["parser_runs"].append(replacement)
        if questions is None or set(questions) & {"BQ-TIME-01", "BQ-DELETE-01"}:
            prepared["parser_runs"].append(_membership_usn_run(
                prepared, {**public, "members": members}, output_dir, context))
        from fmb.index.adapters.registry import shellbag_parser_run
        for position, run in enumerate(prepared["parser_runs"]):
            if run.get("parser_kind") != "windows_shellbag":
                continue
            csvs = [Path(r["path"]) for r in run.get("raw_outputs", [])
                    if Path(r.get("path", "")).name.casefold().endswith(("_usrclass.csv", "_ntuser.csv"))]
            if len(csvs) != 1:
                raise ValueError("native Shellbag ancestry needs one retained SBECmd CSV")
            prepared["parser_runs"][position] = shellbag_parser_run(csv_path=csvs[0],
                normalized_output_dir=output_dir, collector_run=index["collector_runs"][0],
                mft_context=context, resolve_namespace_ancestry=True)

    native = {"scenarios": {k: v for k, v in original_manifest["scenarios"].items()
              if v["technique_id"] in {"i30_directory_residue", "alternate_data_stream", "ntfs_allocation_inconsistency"}
              and v["technique_id"] in techniques}}
    for qid, technique in (("BQ-DIRECTORY-01", "i30_directory_residue"),
                           ("BQ-STREAM-01", "alternate_data_stream"),
                           ("BQ-FILE-01", "ntfs_allocation_inconsistency")):
        if technique not in techniques:
            continue
        native["scenarios"]["supplement-" + qid] = {"technique_id": technique,
            "members": [{"subject_ref": m["path"], "identity_hint": {}}
                        for m in members if m["question_id"] == qid]}
    prepared["parser_runs"] = [r for r in prepared["parser_runs"]
        if r.get("source_module") not in {"FMBNativeNTFSAllocation", "FMBNativeStreamContent"}]
    manifest = load_json_object(evidence.parent / "manifest.json", label="generation manifest")
    images = [r for r in manifest["artifacts"] if r.get("file") == evidence.name]
    if len(images) != 1:
        raise ValueError("primary evidence image must be uniquely bound")
    prepared = add_native_population_surfaces(prepared, manifest=native, evidence_image=evidence,
        evidence_sha256=images[0]["sha256"], output_dir=output_dir,
        **({"system_volume": needs_mft} if questions is not None else {}))
    prepared.pop("population_manifest", None)
    prepared["candidate_populations"] = _populations(prepared, base_populations, public)
    write_json(output_dir / "pre-reference-index.json", prepared)
    prepared = add_reference_scoped_usn(prepared, output_dir=output_dir, include_timestamp_fragments=True)
    prepared = add_reference_scoped_ads(prepared, output_dir=output_dir, defer_population_binding=True)
    prepared["candidate_populations"] = _populations(prepared, base_populations, public)
    from fmb.core.schemas import validate_payload
    validate_payload(prepared, "evidence_index.schema.json")
    assert_truth_blind(prepared)
    write_json(output_dir / "evidence-index.json", prepared)
    write_json(output_dir / "public-population-binding.json", {
        "schema_version": "factual_public_population_binding.v1",
        "public_manifest_sha256": sha256_file(evidence.parent / "factual-challenge-population.json"),
        "evidence_sha256": images[0]["sha256"], "declared_paths": len(public["members"]),
        "criterion_memberships": sum(len(p["subjects"]) for p in prepared["candidate_populations"]),
        "membership_rule": "Every retained native identity at each declared path; all original base members retained.",
        "drive_letter_binding": str(drive_binding_path.resolve()) if drive_binding_path else None,
        **({"selected_questions": questions, "selected_paths": len(members)} if questions is not None else {}),
        "truth_sources_used": []})
    return prepared
