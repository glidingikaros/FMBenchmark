from __future__ import annotations

import re

from pathlib import Path
from typing import Any

from fmb.index.adapters.file_content import (
    build_file_observations,
    collected_bmp_paths,
)
from fmb.index.adapters.mft import mftecmd_mft_csv_files
from fmb.index.adapters.parser_output import (
    RankedObservation,
    keep_ranked_observation,
    observed_artifact_families,
    parser_run_from_observations,
    ranked_observations,
    source_bound_observations,
    source_scope_id,
    write_observation_index,
)
from fmb.index.contract.evidence_index import normalize_parser_output
from fmb.index.scanners.usn import ntfs_reference_set_sha256
from fmb.index.support.windows_artifacts import (
    PATH_SUBJECT_HEADERS,
    csv_has_required_headers,
    csv_header_names,
    mft_path,
    parse_explicit_bool,
    parse_int,
    row_first,
    score_candidate_name,
    stream_csv_rows,
)
from fmb.index.support.windows_identity import ntfs_reference_from_row

MAX_MFT_SIZE_OBSERVATIONS = 5000

MAX_MFTECMD_ADS_OBSERVATIONS = 5000

MAX_MFTECMD_ADS_HOSTS = 250000

ADS_STREAM_NAME_HEADERS = (
    "StreamName",
    "Stream Name",
    "ADSName",
    "ADS Name",
    "DataName",
    "Data Name",
    "AttributeName",
    "Attribute Name",
)


_DRIVE_PREFIX = re.compile(r"^(?:\\\\\?\\)?[A-Za-z]:(?=[\\/])")


def _stream_separator(path: str) -> int:
    match = _DRIVE_PREFIX.match(path)
    return path.find(":", match.end() if match else 0)


def ads_subject_ref(base_subject: str, stream_name: str) -> str:
    subject = base_subject.strip()
    stream = stream_name.strip()
    if not subject or subject == "<unknown>" or not stream:
        return subject
    existing = ads_stream_name_from_path(subject)
    if existing:
        return subject
    return f"{subject}:{stream}"


def ads_base_subject_ref(subject: str, stream_name: str) -> str:
    candidate = subject.strip()
    separator = _stream_separator(candidate)
    if separator < 0:
        return candidate
    suffix_name = candidate[separator + 1 :].split(":", 1)[0]
    if suffix_name.casefold() == stream_name.strip().casefold():
        return candidate[:separator]
    return candidate


def ads_csv_contract_evaluable(csv_path: Path) -> bool:
    headers = csv_header_names(csv_path)
    stream_headers = {item.casefold() for item in ADS_STREAM_NAME_HEADERS}
    stream_capable_path_headers = {
        item.casefold() for item in ("FullPath", "FilePath", "Path")
    }
    subject_headers = {item.casefold() for item in PATH_SUBJECT_HEADERS}
    entry_headers = {"entrynumber", "entry number"}
    sequence_headers = {"sequencenumber", "sequence number"}
    has_stream_capable_path = bool(headers & stream_capable_path_headers)
    has_stream_surface = has_stream_capable_path or (
        bool(headers & stream_headers) and bool(headers & subject_headers)
    )
    return bool(
        has_stream_surface and headers & entry_headers and headers & sequence_headers
    )


def ads_stream_name_from_path(path: str) -> str:
    if not path:
        return ""
    colon_index = _stream_separator(path)
    if colon_index < 0 or colon_index >= len(path) - 1:
        return ""
    stream_name = path[colon_index + 1 :].split("\\", 1)[0].split("/", 1)[0]
    if stream_name.casefold().endswith(":$data"):
        stream_name = stream_name[: -len(":$DATA")]
    return stream_name.strip()


def is_meaningful_stream_name(value: str) -> bool:
    folded = value.strip().casefold()
    return bool(folded) and folded not in {"$data", "data", "::$data"}


def mftecmd_ads_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
) -> dict[str, Any]:
    source_id = source_scope_id(csv_path)
    mft_volume_id = f"mft-source:{source_id}"
    staged_streams: list[dict[str, Any]] = []
    hosts: dict[tuple[int, int], dict[str, Any]] = {}
    host_population_overflow = False
    malformed_identity_row_count = 0
    base_row_count = 0
    candidate_count = 0
    for row_index, row in enumerate(stream_csv_rows(csv_path), start=1):
        parsed_subject = mft_path(row)
        stream_name = row_first(row, *ADS_STREAM_NAME_HEADERS)
        if not stream_name:
            stream_name = ads_stream_name_from_path(
                row_first(
                    row, "FullPath", "FilePath", "Path", "File Name", "FileName", "Name"
                )
            )
        named_stream = is_meaningful_stream_name(stream_name)
        if named_stream:
            candidate_count += 1
        base_subject = ads_base_subject_ref(parsed_subject, stream_name)
        reference = ntfs_reference_from_row(
            row,
            entry_keys=("EntryNumber", "Entry Number"),
            sequence_keys=("SequenceNumber", "Sequence Number"),
        )
        if reference is None or not base_subject or base_subject == "<unknown>":
            malformed_identity_row_count += 1
        else:
            host = hosts.get(reference)
            if host is None:
                if len(hosts) >= MAX_MFTECMD_ADS_HOSTS:
                    host_population_overflow = True
                else:
                    host = {
                        "canonical_base_path": "",
                        "stream_names": [],
                        "named_stream_count": 0,
                        "has_base_row": False,
                    }
                    hosts[reference] = host
            if host is not None:
                if named_stream:
                    host["named_stream_count"] += 1
                    if candidate_count <= MAX_MFTECMD_ADS_OBSERVATIONS:
                        host["stream_names"].append(stream_name)
                else:
                    base_row_count += 1
                    host["has_base_row"] = True
                    existing_path = str(host["canonical_base_path"])
                    host["canonical_base_path"] = (
                        min(existing_path, base_subject)
                        if existing_path
                        else base_subject
                    )

        if not named_stream:
            continue
        stream_size = parse_int(
            row_first(
                row,
                "StreamSize",
                "Stream Size",
                "DataSize",
                "Data Size",
                "FileSize",
                "File Size",
                "Size",
            )
        )
        if candidate_count <= MAX_MFTECMD_ADS_OBSERVATIONS:
            staged_streams.append(
                {
                    "row_index": row_index,
                    "stream_name": stream_name,
                    "stream_size": stream_size,
                    "row_base_subject": base_subject,
                    "reference": reference,
                }
            )

    contract_evaluable = ads_csv_contract_evaluable(csv_path)
    named_hosts = {
        reference for reference, host in hosts.items() if host["named_stream_count"]
    }
    population_complete = bool(
        contract_evaluable
        and base_row_count
        and malformed_identity_row_count == 0
        and not host_population_overflow
        and all(host["has_base_row"] for host in hosts.values())
        and candidate_count <= MAX_MFTECMD_ADS_OBSERVATIONS
    )
    stream_name_counts: dict[str, int] = {}
    for host in hosts.values():
        for name in host["stream_names"]:
            folded = str(name).casefold()
            stream_name_counts[folded] = stream_name_counts.get(folded, 0) + 1

    observations = []
    for staged in staged_streams:
        reference = staged["reference"]
        host = hosts.get(reference) if reference is not None else None
        canonical_base_path = str(host["canonical_base_path"]) if host else ""
        base_subject = canonical_base_path or str(staged["row_base_subject"])
        stream_name = str(staged["stream_name"])
        subject = ads_subject_ref(base_subject, stream_name)
        observations.append(
            {
                "observation_id": f"obs:mftecmd-ads:{staged['row_index']:06d}",
                "artifact_family": "ntfs.ads",
                "observation_type": "named_data_stream",
                "subject_ref": subject,
                "fields": {
                    "stream_name": stream_name,
                    "base_path": base_subject,
                    "stream_size": staged["stream_size"],
                    "row_index": staged["row_index"],
                    "mft_volume_id": mft_volume_id,
                    "mft_entry": reference[0] if reference is not None else None,
                    "sequence_number": (
                        reference[1] if reference is not None else None
                    ),
                    "host_population_complete": population_complete,
                    "host_population_size": len(hosts),
                    "hosts_without_named_stream_count": len(hosts) - len(named_hosts),
                    "host_named_stream_count": (
                        host["named_stream_count"] if host is not None else None
                    ),
                    "stream_name_occurrences": stream_name_counts.get(
                        stream_name.casefold(), 0
                    ),
                    "candidate_score": score_candidate_name(
                        subject, purpose="timestomp"
                    ),
                },
                "source_record_ref": (f"{csv_path.name}:row={staged['row_index']}"),
            }
        )
    return parser_run_from_observations(
        parser="MFTECmd",
        parser_kind="ntfs_ads",
        source_module="MFTECmd",
        command_needles=("mftecmd",),
        normalized_suffix="ads",
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        raw_output=csv_path,
        observations=observations,
        coverage_status="complete" if population_complete else "partial",
    )


def mftecmd_ads_reference_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    references: set[tuple[int, int]],
    filesystem_scope_id: str,
) -> dict[str, Any]:

    if not isinstance(filesystem_scope_id, str) or not filesystem_scope_id.strip():
        raise ValueError("reference-scoped ADS analysis requires a filesystem scope")
    expected_scope_id = f"mft-source:{source_scope_id(csv_path)}"
    if filesystem_scope_id != expected_scope_id:
        raise ValueError(
            "reference-scoped ADS filesystem scope does not match MFTECmd source"
        )
    if not references:
        raise ValueError("reference-scoped ADS analysis requires file references")
    reference_sha256 = ntfs_reference_set_sha256(references)
    source_size_bytes = csv_path.stat().st_size
    contract_evaluable = csv_has_required_headers(
        csv_path,
        ("EntryNumber",),
        ("SequenceNumber",),
        ("InUse",),
        ("ParentPath",),
        ("FileName",),
        ("IsDirectory",),
        ("HasAds",),
        ("IsAds",),
        ("FileSize",),
    )
    matched_record_count = 0
    malformed_record_count = 0
    base_rows: dict[tuple[int, int], list[dict[str, Any]]] = {}
    staged_streams: list[dict[str, Any]] = []
    seen_streams: set[tuple[tuple[int, int], str]] = set()
    named_stream_count_by_reference: dict[tuple[int, int], int] = {}
    stream_name_counts: dict[str, int] = {}
    named_stream_count = 0
    duplicate_stream_count = 0
    stream_population_overflow = False

    for row_index, row in enumerate(stream_csv_rows(csv_path), start=1):
        reference = ntfs_reference_from_row(
            row,
            entry_keys=("EntryNumber",),
            sequence_keys=("SequenceNumber",),
        )
        if reference not in references:
            continue
        matched_record_count += 1
        is_ads = parse_explicit_bool(row_first(row, "IsAds"))
        if is_ads is None:
            malformed_record_count += 1
            continue
        if not is_ads:
            base_path = mft_path(row)
            in_use = parse_explicit_bool(row_first(row, "InUse"))
            is_directory = parse_explicit_bool(row_first(row, "IsDirectory"))
            has_ads = parse_explicit_bool(row_first(row, "HasAds"))
            if (
                base_path == "<unknown>"
                or ads_stream_name_from_path(base_path)
                or in_use is not True
                or is_directory is not False
                or not isinstance(has_ads, bool)
            ):
                malformed_record_count += 1
                continue
            base_rows.setdefault(reference, []).append(
                {
                    "base_path": base_path,
                    "row_index": row_index,
                    "in_use": in_use,
                    "has_ads": has_ads,
                }
            )
            continue

        stream_name = ads_stream_name_from_path(
            row_first(row, "FileName", "File Name", "Name")
        )
        if not is_meaningful_stream_name(stream_name):
            malformed_record_count += 1
            continue
        stream_size = parse_int(row_first(row, "FileSize"))
        if stream_size is None or stream_size < 0:
            malformed_record_count += 1
            continue
        stream_key = (reference, stream_name.casefold())
        if stream_key in seen_streams:
            duplicate_stream_count += 1
        seen_streams.add(stream_key)
        folded_stream_name = stream_name.casefold()
        stream_name_counts[folded_stream_name] = (
            stream_name_counts.get(folded_stream_name, 0) + 1
        )
        named_stream_count_by_reference[reference] = (
            named_stream_count_by_reference.get(reference, 0) + 1
        )
        named_stream_count += 1
        if named_stream_count > MAX_MFTECMD_ADS_OBSERVATIONS:
            stream_population_overflow = True
            continue
        staged_streams.append(
            {
                "reference": reference,
                "row_index": row_index,
                "stream_name": stream_name,
                "stream_size": stream_size,
            }
        )

    base_population_complete = all(
        len(base_rows.get(reference, [])) == 1 for reference in references
    )
    complete = bool(
        contract_evaluable
        and malformed_record_count == 0
        and duplicate_stream_count == 0
        and not stream_population_overflow
        and base_population_complete
        and all(
            base_rows[reference][0]["has_ads"]
            is bool(named_stream_count_by_reference.get(reference, 0))
            for reference in references
        )
    )
    observations: list[dict[str, Any]] = []
    named_host_count = sum(
        count > 0 for count in named_stream_count_by_reference.values()
    )
    for retained_index, staged in enumerate(staged_streams, start=1):
        reference = staged["reference"]
        matching_base_rows = base_rows.get(reference, [])
        if len(matching_base_rows) != 1:
            continue
        base_row = matching_base_rows[0]
        stream_name = str(staged["stream_name"])
        base_path = str(base_row["base_path"])
        observations.append(
            {
                "observation_id": (
                    f"obs:fmb-reference-ads:{reference_sha256}:"
                    f"{retained_index:06d}"
                ),
                "artifact_family": "ntfs.ads",
                "observation_type": "named_data_stream",
                "subject_ref": ads_subject_ref(base_path, stream_name),
                "fields": {
                    "stream_name": stream_name,
                    "base_path": base_path,
                    "stream_size": staged["stream_size"],
                    "row_index": staged["row_index"],
                    "base_row_index": base_row["row_index"],
                    "mft_volume_id": filesystem_scope_id,
                    "mft_entry": reference[0],
                    "sequence_number": reference[1],
                    "in_use": base_row["in_use"],
                    "has_ads": base_row["has_ads"],
                    "host_population_complete": complete,
                    "host_population_size": len(references),
                    "hosts_without_named_stream_count": (
                        len(references) - named_host_count
                    ),
                    "host_named_stream_count": (
                        named_stream_count_by_reference.get(reference, 0)
                    ),
                    "stream_name_occurrences": stream_name_counts.get(
                        stream_name.casefold(), 0
                    ),
                },
                "source_record_ref": (
                    f"{csv_path.name}:row={staged['row_index']}"
                ),
            }
        )
    observations = source_bound_observations(observations, csv_path)
    selection_scope = {
        "kind": "ntfs_file_references",
        "filesystem_scope_id": filesystem_scope_id,
        "reference_count": len(references),
        "reference_sha256": reference_sha256,
        "matched_record_count": matched_record_count,
        "retained_record_count": len(staged_streams),
        "normalized_record_count": len(observations),
        "source_size_bytes": source_size_bytes,
        "source_bytes_covered": source_size_bytes,
        "status": "complete" if complete else "partial",
    }
    normalized_output = write_observation_index(
        normalized_output_dir=normalized_output_dir,
        raw_output=csv_path,
        file_suffix=f"reference_ads_observations.{reference_sha256}.json",
        parser="fmb_bounded_parser",
        parser_kind="ntfs_ads",
        observations=observations,
        extra={"selection_scope": selection_scope},
    )
    parser_run = normalize_parser_output(
        parser="fmb_bounded_parser",
        parser_kind="ntfs_ads",
        source_collector=str(collector_run["collector"]),
        source_module="MFTECmd#reference-scope",
        raw_outputs=[csv_path],
        normalized_output=normalized_output,
        observations=observations,
        command_line=None,
        tool_identity={
            "name": "fmb.ads.truth_blind_reference_scanner",
            "version": "0.1.0",
            "scope": "truth_blind_mftecmd_reference_scan",
        },
        observation_families=observed_artifact_families(observations),
        coverage_status="partial",
    )
    parser_run["selection_scope"] = selection_scope
    return parser_run


def mftecmd_size_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
) -> dict[str, Any]:
    candidates: list[RankedObservation] = []
    source_row_count = 0
    candidate_row_count = 0
    contract_evaluable = csv_has_required_headers(
        csv_path,
        PATH_SUBJECT_HEADERS,
        ("LogicalSize", "Logical Size", "FileSize", "File Size", "Size"),
        ("AllocatedSize", "Allocated Size", "Allocated", "PhysicalSize"),
    )
    for row_index, row in enumerate(stream_csv_rows(csv_path), start=1):
        source_row_count = row_index
        logical_size = parse_int(
            row_first(
                row, "LogicalSize", "Logical Size", "FileSize", "File Size", "Size"
            )
        )
        allocated_size = parse_int(
            row_first(
                row, "AllocatedSize", "Allocated Size", "Allocated", "PhysicalSize"
            )
        )
        if logical_size is None and allocated_size is None:
            continue
        candidate_row_count += 1
        subject = mft_path(row)
        score = score_candidate_name(subject, purpose="timestomp")
        observation = {
            "observation_id": f"obs:mftecmd-size:{row_index:06d}",
            "artifact_family": "ntfs.file_size_allocation",
            "observation_type": "logical_allocated_size_record",
            "subject_ref": subject,
            "fields": {
                "logical_size": logical_size,
                "allocated_size": allocated_size,
                "size_delta": (
                    allocated_size - logical_size
                    if allocated_size is not None and logical_size is not None
                    else None
                ),
                "row_index": row_index,
                "candidate_score": score,
            },
            "source_record_ref": f"{csv_path.name}:row={row_index}",
        }
        keep_ranked_observation(
            candidates,
            score=score,
            row_index=row_index,
            observation=observation,
            limit=MAX_MFT_SIZE_OBSERVATIONS,
        )

    return parser_run_from_observations(
        parser="MFTECmd",
        parser_kind="ntfs_file_size_allocation",
        source_module="MFTECmd",
        command_needles=("mftecmd",),
        normalized_suffix="size",
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        raw_output=csv_path,
        observations=ranked_observations(candidates),
        index_extra={
            "source_row_count": source_row_count,
            "candidate_row_count": candidate_row_count,
            "max_observations": MAX_MFT_SIZE_OBSERVATIONS,
        },
        coverage_status=(
            "complete"
            if contract_evaluable and candidate_row_count <= MAX_MFT_SIZE_OBSERVATIONS
            else "partial"
        ),
    )


def q_file_parser_runs(
    *,
    root: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    bounded_content_subject_limit: int | None = None,
) -> list[dict[str, Any]]:

    content_paths = collected_bmp_paths(
        root,
        max_subjects=bounded_content_subject_limit,
    )
    if not content_paths:
        return []
    mft_outputs = mftecmd_mft_csv_files(root)
    if len(mft_outputs) != 1:
        raise ValueError(
            "bounded file-content analysis requires exactly one full MFTECmd output"
        )
    bundle = build_file_observations(
        root=root,
        mftecmd_csv_path=mft_outputs[0],
        max_subjects=bounded_content_subject_limit,
    )
    if bundle is None:
        return []
    coverage_status = "complete" if bundle["complete"] else "partial"
    csv_path = Path(bundle["mftecmd_csv_path"])
    mft_path = Path(bundle["mft_path"])
    storage = parser_run_from_observations(
        parser="fmb_bounded_parser",
        parser_kind="ntfs_file_size_allocation",
        source_module="FMBBoundedUserBMP",
        command_needles=("mftecmd",),
        normalized_suffix="bounded-size",
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        raw_output=csv_path,
        additional_raw_outputs=[mft_path],
        observations=list(bundle["storage_observations"]),
        coverage_status=coverage_status,
        coverage_families=["ntfs.file_size_allocation"],
    )
    content = parser_run_from_observations(
        parser="fmb_bounded_parser",
        parser_kind="materialized_file_content",
        source_module="FMBBoundedUserBMP",
        command_needles=("mftecmd",),
        normalized_suffix="bounded-content",
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        raw_output=csv_path,
        additional_raw_outputs=[mft_path, *content_paths],
        observations=list(bundle["content_observations"]),
        coverage_status=coverage_status,
        coverage_families=["collected.file.content"],
    )
    return [storage, content]
