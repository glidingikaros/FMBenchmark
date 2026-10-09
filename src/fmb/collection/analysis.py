from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from fmb.analysis.inputs import population_ntfs_scope_and_references
from fmb.analysis.population_binding import bind_population_manifest
from fmb.core.schemas import validate_payload
from fmb.core.truth_guard import is_disk_image
from fmb.index.adapters.logfile import raw_logfile_reference_parser_run
from fmb.index.adapters.mft import (
    build_mft_presence_context,
    raw_mft_path_for_root,
)
from fmb.index.adapters.ntfs_files import mftecmd_ads_reference_parser_run
from fmb.index.adapters.usn import raw_usn_reference_parser_run
from fmb.index.scanners.usn import ntfs_reference_set_sha256

_REFERENCE_SCOPED_USN_TECHNIQUES = {
    ("Q-TIME-01", "timestamp_manipulation"),
    ("Q-DEL-01", "deleted_file_journal_residue"),
}
_REFERENCE_SCOPED_ADS_TECHNIQUE = ("Q-HIDE-01", "alternate_data_stream")
_REFERENCE_SCOPED_LOGFILE_TECHNIQUES = {("Q-TIME-01", "timestamp_manipulation")}


def _reference_scoped_usn_populations(
    evidence_index: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    populations = evidence_index.get("candidate_populations")
    if not isinstance(populations, list):
        return ()
    return tuple(
        sorted(
            (
                item
                for item in populations
                if isinstance(item, Mapping)
                and (item.get("question_id"), item.get("technique_id"))
                in _REFERENCE_SCOPED_USN_TECHNIQUES
                and item.get("coverage_status") == "complete"
            ),
            key=lambda item: (
                str(item["question_id"]),
                str(item["technique_id"]),
            ),
        ),
    )


def _unique_raw_output(
    evidence_index: Mapping[str, Any],
    parser_kind: str,
    accept: Callable[[Path], bool],
    locate: Callable[[Path], Path] | None = None,
) -> Path | None:
    paths: set[Path] = set()
    for parser_run in evidence_index.get("parser_runs", []):
        if not isinstance(parser_run, Mapping):
            continue
        if parser_run.get("parser_kind") != parser_kind:
            continue
        raw_outputs = parser_run.get("raw_outputs")
        if not isinstance(raw_outputs, list):
            continue
        for raw_output in raw_outputs:
            if not isinstance(raw_output, Mapping):
                continue
            value = raw_output.get("path")
            if not isinstance(value, str):
                continue
            candidate = Path(value).expanduser().resolve()
            if accept(candidate) and (locate(candidate) if locate else candidate).is_file():
                paths.add(candidate)
    return next(iter(paths)) if len(paths) == 1 else None


def _raw_usn_journal_path(
    evidence_index: Mapping[str, Any], locate: Callable[[Path], Path] | None = None
) -> Path | None:
    return _unique_raw_output(evidence_index, "ntfs_usn", lambda path: path.name.casefold() == "$j", locate)


def _raw_logfile_path(evidence_index: Mapping[str, Any]) -> Path | None:
    return _unique_raw_output(evidence_index, "ntfs_logfile", lambda path: path.name == "$LogFile")


def _is_reference_scoped_logfile_run(item: Any) -> bool:
    return bool(
        isinstance(item, Mapping)
        and item.get("parser_kind") == "ntfs_logfile"
        and item.get("parser") == "dfir_ntfs"
        and isinstance(item.get("selection_scope"), Mapping)
        and item["selection_scope"].get("kind") == "ntfs_file_references"
    )


def _kape_output_root(path: Path) -> Path | None:
    return next(
        (
            candidate
            for candidate in (path.parent, *path.parents)
            if candidate.name.casefold() == "kape-output"
        ),
        None,
    )


def add_reference_scoped_usn(
    evidence_index: Mapping[str, Any],
    *,
    output_dir: Path,
    include_timestamp_fragments: bool = False,
) -> dict[str, Any]:

    prepared = deepcopy(dict(evidence_index))
    scoped_population_references: list[tuple[str, set[tuple[int, int]]]] = []
    logfile_population_references: list[tuple[str, set[tuple[int, int]]]] = []
    seen_scopes: set[tuple[str, tuple[tuple[int, int], ...]]] = set()
    seen_logfile_scopes: set[tuple[str, tuple[tuple[int, int], ...]]] = set()
    for population in _reference_scoped_usn_populations(prepared):
        scoped_references = population_ntfs_scope_and_references(population)
        if scoped_references is None:
            continue
        filesystem_scope_id, references = scoped_references
        scope_key = (filesystem_scope_id, tuple(sorted(references)))
        technique = (population.get("question_id"), population.get("technique_id"))
        if (
            technique in _REFERENCE_SCOPED_LOGFILE_TECHNIQUES
            and scope_key not in seen_logfile_scopes
        ):
            seen_logfile_scopes.add(scope_key)
            logfile_population_references.append((filesystem_scope_id, references))
        if scope_key in seen_scopes:
            continue
        seen_scopes.add(scope_key)
        scoped_population_references.append((filesystem_scope_id, references))
    if not scoped_population_references:
        return prepared
    journal_path = _raw_usn_journal_path(prepared)
    logfile_path = _raw_logfile_path(prepared)
    if journal_path is None and logfile_path is None:
        return prepared
    collector_runs = prepared.get("collector_runs")
    if (
        not isinstance(collector_runs, list)
        or len(collector_runs) != 1
        or not isinstance(collector_runs[0], dict)
    ):
        raise ValueError("reference-scoped USN analysis requires one collector run")
    kape_root = _kape_output_root(journal_path or logfile_path)
    if kape_root is None:
        raise ValueError("raw journal or $LogFile is outside a KAPE output root")
    mft_context = build_mft_presence_context(kape_root)
    parser_runs = prepared.get("parser_runs")
    if not isinstance(parser_runs, list):
        raise ValueError("evidence index parser_runs must be an array")
    parser_runs = [
        item
        for item in parser_runs
        if not (
            isinstance(item, Mapping)
            and item.get("parser_kind") == "ntfs_usn"
            and isinstance(item.get("tool_identity"), Mapping)
            and item["tool_identity"].get("name")
            == "fmb.usn.truth_blind_reference_scanner"
            and isinstance(item.get("selection_scope"), Mapping)
            and item["selection_scope"].get("kind") == "ntfs_file_references"
        )
    ]
    normalized_output_dir = (
        (output_dir / "execution/02-normalization")
        / "parser-normalized"
    )
    normalized_output_dir.mkdir(parents=True, exist_ok=True)
    for filesystem_scope_id, references in scoped_population_references:
        if journal_path is None or mft_context.get("mft_volume_id") != filesystem_scope_id:
            continue
        parser_runs.append(
            raw_usn_reference_parser_run(
                journal_path=journal_path,
                normalized_output_dir=normalized_output_dir,
                collector_run=collector_runs[0],
                references=references,
                filesystem_scope_id=filesystem_scope_id,
                mft_context=mft_context,
            )
        )
    if logfile_path is not None and logfile_population_references:
        raw_mft_path = raw_mft_path_for_root(kape_root)
        parser_runs = [
            item for item in parser_runs if not _is_reference_scoped_logfile_run(item)
        ]
        for filesystem_scope_id, references in logfile_population_references:
            if mft_context.get("mft_volume_id") != filesystem_scope_id:
                continue
            parser_runs.append(
                raw_logfile_reference_parser_run(
                    logfile_path=logfile_path,
                    raw_mft_path=raw_mft_path,
                    normalized_output_dir=normalized_output_dir,
                    collector_run=collector_runs[0],
                    references=references,
                    filesystem_scope_id=filesystem_scope_id,
                    mft_context=mft_context,
                    include_timestamp_fragments=include_timestamp_fragments,
                )
            )
    prepared["parser_runs"] = parser_runs
    validate_payload(prepared, "evidence_index.schema.json")
    return prepared


def _reference_scoped_ads_population(
    evidence_index: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    populations = evidence_index.get("candidate_populations")
    if not isinstance(populations, list):
        return None
    matches = [
        item
        for item in populations
        if isinstance(item, Mapping)
        and (item.get("question_id"), item.get("technique_id"))
        == _REFERENCE_SCOPED_ADS_TECHNIQUE
        and item.get("coverage_status") == "complete"
    ]
    if len(matches) > 1:
        raise ValueError("evidence index repeats the ADS candidate population")
    return matches[0] if matches else None


def _raw_mftecmd_ads_csv_path(evidence_index: Mapping[str, Any]) -> Path | None:
    def accept(path: Path) -> bool:
        folded_name = path.name.casefold()
        return path.suffix.casefold() == ".csv" and "mftecmd" in folded_name and "$mft" in folded_name

    return _unique_raw_output(evidence_index, "ntfs_ads", accept)


def add_reference_scoped_ads(
    evidence_index: Mapping[str, Any],
    *,
    output_dir: Path,
    defer_population_binding: bool = False,
) -> dict[str, Any]:

    prepared = deepcopy(dict(evidence_index))
    population = _reference_scoped_ads_population(prepared)
    if population is None:
        return prepared
    scoped_references = population_ntfs_scope_and_references(population)
    if scoped_references is None:
        raise ValueError("ADS population has no exact NTFS reference scope")
    filesystem_scope_id, references = scoped_references
    csv_path = _raw_mftecmd_ads_csv_path(prepared)
    if csv_path is None:
        raise ValueError("ADS population requires one MFTECmd $MFT CSV")
    collector_runs = prepared.get("collector_runs")
    if (
        not isinstance(collector_runs, list)
        or len(collector_runs) != 1
        or not isinstance(collector_runs[0], dict)
    ):
        raise ValueError("reference-scoped ADS analysis requires one collector run")
    parser_runs = prepared.get("parser_runs")
    if not isinstance(parser_runs, list):
        raise ValueError("evidence index parser_runs must be an array")
    normalized_output_dir = (
        (output_dir / "execution/02-normalization")
        / "parser-normalized"
    )
    normalized_output_dir.mkdir(parents=True, exist_ok=True)
    scoped_run = mftecmd_ads_reference_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_runs[0],
        references=references,
        filesystem_scope_id=filesystem_scope_id,
    )
    reference_sha256 = ntfs_reference_set_sha256(references)
    retained_runs: list[Any] = []
    for item in parser_runs:
        if not isinstance(item, Mapping) or item.get("parser_kind") != "ntfs_ads":
            retained_runs.append(item)
            continue
        tool_identity = item.get("tool_identity")
        if isinstance(tool_identity, Mapping) and tool_identity.get("name") == "fmb.ads.native_content_parser":
            retained_runs.append(item)
            continue
        selection_scope = item.get("selection_scope")
        is_scoped = bool(
            isinstance(tool_identity, Mapping)
            and tool_identity.get("name")
            == "fmb.ads.truth_blind_reference_scanner"
        )
        same_scope = bool(
            is_scoped
            and isinstance(selection_scope, Mapping)
            and selection_scope.get("filesystem_scope_id") == filesystem_scope_id
            and selection_scope.get("reference_sha256") == reference_sha256
        )
        if not is_scoped or same_scope:
            continue
        retained_runs.append(item)
    prepared["parser_runs"] = [*retained_runs, scoped_run]
    if defer_population_binding:
        return prepared
    populations = prepared.get("candidate_populations")
    if not isinstance(populations, list):
        raise ValueError("evidence index candidate_populations must be an array")
    prepared["candidate_populations"] = [
        item
        for item in populations
        if not (
            isinstance(item, Mapping)
            and (item.get("question_id"), item.get("technique_id"))
            == _REFERENCE_SCOPED_ADS_TECHNIQUE
        )
    ]
    public_manifest = prepared.get("population_manifest")
    if not isinstance(public_manifest, Mapping):
        raise ValueError("ADS population requires its public population manifest")
    rebound = bind_population_manifest(prepared, public_manifest,
                                      techniques={item["technique_id"] for item in populations})
    validate_payload(rebound, "evidence_index.schema.json")
    return rebound


def collect_evidence_index(evidence: Path, *, profile: dict, output_dir: Path, run_id: str,
                           windows_parsers: Path | None, host_toolchain_root: Path | None = None,
                           vm_work_root: Path | None = None) -> dict:
    from fmb.analysis.population_binding import bind_population_manifest, load_generated_population_bundle
    from fmb.collection.alignment import add_native_population_surfaces
    from fmb.collection.factual_challenge import load_public_population, add_factual_population
    from fmb.collection.paper_host import collect_host

    evidence = evidence.expanduser().absolute()
    if not evidence.is_file() or not is_disk_image(evidence.name):
        raise ValueError('paper collection requires an existing VMDK or raw (.raw, .img, .dd) disk image')
    generated = load_generated_population_bundle(evidence, verify_evidence_sha256=False)
    if generated is None:
        raise ValueError('paper collection requires a bound public population')
    public = load_public_population(evidence)
    from fmb.core.case_contract import QIDS

    questions = [q["question_id"] for q in profile["questions"]]
    selective = questions != list(QIDS)
    families = set(profile["artifact_families"])
    selection = {"techniques": {tid for q in profile["questions"] for tid in q["technique_ids"]}} if selective else {}
    limit = None
    if 'collected.file.content' in families:
        limit = generated.content_subject_limit
        if limit is None:
            raise ValueError('file-content collection requires a bounded content population')
        if public is not None:
            limit += sum(member['path'].casefold().endswith('.bmp') for member in public['members']
                         if not selective or member['question_id'] in questions)
    collected = collect_host(profile=profile, evidence=evidence, output=output_dir, run_id=run_id,
        windows_parsers=windows_parsers, host_toolchain_root=host_toolchain_root,
        vm_work_root=vm_work_root, expected_sha256=generated.evidence_sha256,
        bounded_content_subject_limit=limit,
        bounded_i30_directory_paths=generated.i30_directory_paths if 'ntfs.i30' in families else ())
    collected = add_native_population_surfaces(collected, manifest=generated.population_manifest,
        evidence_image=evidence, evidence_sha256=generated.evidence_sha256, output_dir=output_dir,
        **({**selection, "system_volume": 'ntfs.mft' in families} if selective else {}))
    prepared = bind_population_manifest(collected, generated.population_manifest, **selection)
    prepared = add_reference_scoped_usn(prepared, output_dir=output_dir)
    prepared = add_reference_scoped_ads(prepared, output_dir=output_dir)
    if public is not None:
        prepared = add_factual_population(prepared, evidence=evidence, public=public,
                                         output_dir=output_dir / 'factual-supplement',
                                         **({"questions": questions} if selective else {}))
    return prepared
