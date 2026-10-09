from __future__ import annotations

from pathlib import Path
from typing import Any, BinaryIO

from fmb.core.coercion import parse_truncated_int
from fmb.core.hashing import sha256_file
from fmb.core.json_io import write_json
from fmb.index.adapters.ntfs_allocation import (
    load_native_surfaces,
    native_sidecar_files,
    sidecar_file,
)
from fmb.index.adapters.mft import (
    mft_row_is_active,
    mft_row_is_directory,
)
from fmb.index.support.windows_artifacts import (
    csv_has_required_headers,
    mft_path,
    row_value,
    stream_csv_rows,
)
from fmb.index.support.windows_identity import normalize_windows_compare_path
from fmb.index.contract.evidence_index import normalize_parser_output
from fmb.index.scanners.mft import (
    DEFAULT_MFT_RECORD_SIZE,
    UPDATE_SEQUENCE_STRIDE,
    mft_record_is_in_use,
    parse_directory_i30_record,
    parse_mft_record,
)
from fmb.index.scanners.ntfs import parse_index_allocation

SUPPORTED_I30_SURFACE = "resident_index_root_and_mft_record_slack"
FULL_I30_SURFACE = "resident_index_root_mft_slack_and_index_allocation"
DEFAULT_MAX_I30_DIRECTORIES = 500
USER_CONTENT_DIRECTORY_NAMES = {
    "desktop",
    "documents",
    "downloads",
    "music",
    "onedrive",
    "pictures",
    "videos",
}


def _required_int(value: str | None, *, label: str) -> int:
    parsed = parse_truncated_int(str(value or ""))
    if parsed < 0:
        raise ValueError(f"{label} must be non-negative")
    return parsed


def _row_identity(row: dict[str, str]) -> tuple[int, int] | None:
    try:
        return (
            _required_int(
                row_value(row, "EntryNumber", "Entry Number"), label="MFT entry"
            ),
            _required_int(
                row_value(row, "SequenceNumber", "Sequence Number"),
                label="MFT sequence",
            ),
        )
    except (TypeError, ValueError):
        return None


def _directory_rows(
    mft_csv_path: Path,
    directory_paths: tuple[str, ...] | None,
) -> tuple[list[tuple[str, dict[str, str]]], bool, int, str]:
    contract_evaluable = csv_has_required_headers(
        mft_csv_path,
        ("EntryNumber", "Entry Number"),
        ("SequenceNumber", "Sequence Number"),
        ("InUse", "In Use"),
        ("IsDirectory", "Is Directory", "FileAttributes", "Attributes"),
        ("ParentPath", "Parent Path", "FullPath", "Full Path", "Path"),
        ("FileName", "File Name", "Name", "FullPath", "Full Path", "Path"),
    )
    if not contract_evaluable and directory_paths:
        raise ValueError(
            "MFTECmd output cannot resolve bounded I30 directory identities"
        )
    if not directory_paths:
        rows_by_path: dict[str, list[dict[str, str]]] = {}
        for row in stream_csv_rows(mft_csv_path):
            if not mft_row_is_active(row) or not mft_row_is_directory(row):
                continue
            path = mft_path(row)
            normalized = normalize_windows_compare_path(path)
            if normalized and _row_identity(row) is not None:
                rows_by_path.setdefault(normalized, []).append(row)
        ambiguous_count = 0
        discovered: list[tuple[str, dict[str, str]]] = []
        for normalized, candidates in rows_by_path.items():
            identities = {
                identity
                for row in candidates
                if (identity := _row_identity(row)) is not None
            }
            if len(identities) != 1:
                ambiguous_count += 1
                continue
            discovered.append((mft_path(candidates[0]), candidates[0]))
        discovered.sort(key=lambda item: normalize_windows_compare_path(item[0]))
        complete = contract_evaluable and ambiguous_count == 0
        return (
            discovered,
            complete,
            len(discovered) + ambiguous_count,
            "all_active_directory_records_with_bounded_residue_retention",
        )

    expected: dict[str, str] = {}
    for path in directory_paths:
        normalized = normalize_windows_compare_path(path)
        if not normalized:
            raise ValueError("bounded I30 directory paths must be non-empty")
        if normalized in expected:
            raise ValueError("bounded I30 directory paths must be unique")
        expected[normalized] = path
    matches: dict[str, list[dict[str, str]]] = {key: [] for key in expected}
    for row in stream_csv_rows(mft_csv_path):
        normalized = normalize_windows_compare_path(mft_path(row))
        if normalized not in matches:
            continue
        if not mft_row_is_active(row) or not mft_row_is_directory(row):
            continue
        matches[normalized].append(row)
    resolved: list[tuple[str, dict[str, str]]] = []
    for normalized, public_path in expected.items():
        candidates = matches[normalized]
        identities = {
            identity
            for row in candidates
            if (identity := _row_identity(row)) is not None
        }
        if len(identities) != 1:
            raise ValueError(
                "bounded I30 directory did not resolve to one active MFT identity: "
                f"{public_path}"
            )
        resolved.append((public_path, candidates[0]))
    return resolved, True, len(resolved), "exact_public_directory_roster"


def _read_mft_record(
    handle: BinaryIO,
    *,
    entry: int,
) -> tuple[bytes | None, int]:
    offset = entry * DEFAULT_MFT_RECORD_SIZE
    handle.seek(offset)
    record = handle.read(DEFAULT_MFT_RECORD_SIZE)
    return (record if len(record) == DEFAULT_MFT_RECORD_SIZE else None), offset


def _active_presence(
    handle: BinaryIO,
    *,
    entry: int,
    sequence: int,
    volume_id: str,
) -> dict[str, Any]:
    target = {
        "mft_lookup_target": {
            "mft_volume_id": volume_id,
            "object_id": f"ntfs:{volume_id}:{entry}:{sequence}",
            "target_role": "referenced_object",
        }
    }
    record, offset = _read_mft_record(handle, entry=entry)
    if record is None:
        return {
            **target,
            "mft_active_presence_check_supported": False,
            "mft_active_presence_status": "unknown",
            "mft_active_presence_basis": "file_reference_record_outside_source",
        }
    if not any(record):
        return {
            **target,
            "mft_active_presence_check_supported": False,
            "mft_active_presence_status": "unknown",
            "mft_active_presence_basis": "file_reference_record_never_allocated",
        }
    parsed = parse_mft_record(
        record,
        record_offset=offset,
        record_size=DEFAULT_MFT_RECORD_SIZE,
    )
    if parsed is None:
        return {
            **target,
            "mft_active_presence_check_supported": False,
            "mft_active_presence_status": "unknown",
            "mft_active_presence_basis": "file_reference_record_unreadable",
        }
    observed_sequence = parsed.get("sequence_number")
    if observed_sequence != sequence:
        status = "active_mft_absent"
        basis = "file_reference_entry_reused" if mft_record_is_in_use(parsed) else "file_reference_entry_freed"
    elif mft_record_is_in_use(parsed):
        status = "active_mft_present"
        basis = "file_reference_in_use"
    else:
        status = "active_mft_absent"
        basis = "file_reference_record_free"
    return {
        **target,
        "mft_lookup_observed": {
            "entry": entry,
            "sequence": observed_sequence,
            "in_use": mft_record_is_in_use(parsed),
        },
        "mft_active_presence_check_supported": True,
        "mft_active_presence_status": status,
        "mft_active_presence_basis": basis,
    }


def _directory_record(
    handle: BinaryIO,
    *,
    entry: int,
    sequence: int,
    expected_path: str,
) -> dict[str, Any]:
    record, offset = _read_mft_record(handle, entry=entry)
    if record is None:
        raise ValueError(f"bounded I30 directory record is outside raw $MFT: {entry}")
    parsed = parse_directory_i30_record(
        record,
        record_offset=offset,
        record_size=DEFAULT_MFT_RECORD_SIZE,
    )
    expected_name = normalize_windows_compare_path(expected_path).rsplit("\\", 1)[-1]
    names = {
        str(item.get("name") or "").casefold()
        for item in (parsed or {}).get("file_name_attributes", [])
        if isinstance(item, dict)
    }
    if (
        parsed is None
        or parsed.get("mft_entry") != entry
        or parsed.get("sequence_number") != sequence
        or parsed.get("is_active_directory") is not True
        or parsed.get("index_root_present") is not True
        or parsed.get("index_root_parsed") is not True
        or parsed.get("attribute_list_present") is True
        or expected_name not in names
    ):
        raise ValueError(
            "raw $MFT directory identity or resident INDEX_ROOT coverage "
            f"is incomplete for entry {entry}"
        )
    return parsed


def _source_record_ref(source_id: str, *, entry: int, suffix: str = "") -> str:
    return f"source:{source_id}:$MFT:record={entry}{suffix}"


def _residue_retention_key(directory_path: str) -> tuple[int, int, str]:
    normalized = normalize_windows_compare_path(directory_path)
    parts = tuple(part for part in normalized.split("\\") if part)
    under_user_profile = len(parts) >= 2 and parts[0] == "users"
    under_appdata = "appdata" in parts
    under_user_content = under_user_profile and any(
        part in USER_CONTENT_DIRECTORY_NAMES for part in parts[2:]
    )
    if under_user_content and not under_appdata:
        scope_rank = 0
    elif under_user_profile and not under_appdata:
        scope_rank = 1
    elif under_user_profile:
        scope_rank = 2
    else:
        scope_rank = 3
    return scope_rank, len(parts), normalized


def bounded_i30_parser_run(
    *,
    mft_csv_path: Path,
    raw_mft_path: Path,
    directory_paths: tuple[str, ...] | None = None,
    max_directories: int = DEFAULT_MAX_I30_DIRECTORIES,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    native_manifest_path: Path | None = None,
) -> dict[str, Any]:

    if isinstance(max_directories, bool) or max_directories <= 0:
        raise ValueError("bounded I30 max_directories must be positive")
    if not raw_mft_path.is_file() or (
        raw_mft_path.stat().st_size % DEFAULT_MFT_RECORD_SIZE
    ):
        raise ValueError("raw $MFT source is unavailable or not record aligned")
    exact_roster = bool(directory_paths)
    resolved, coverage_complete, discovered_count, selection_mode = _directory_rows(
        mft_csv_path,
        directory_paths,
    )
    source_id = sha256_file(raw_mft_path)[:16]
    volume_id = f"mft-source:{source_id}"
    native = (
        load_native_surfaces(native_manifest_path, raw_mft_path)
        if native_manifest_path is not None
        else None
    )
    native_records = (
        {
            (int(item["mft_entry"]), int(item["sequence_number"])): item
            for item in native["records"]
        }
        if native
        else {}
    )
    observations: list[dict[str, Any]] = []
    scanned_directory_count = 0
    residue_directory_count = 0
    retained_residue_directory_count = 0
    discovered_residue: list[
        tuple[tuple[int, int, str], dict[str, Any], list[dict[str, Any]]]
    ] = []
    with raw_mft_path.open("rb") as handle:
        for position, (directory_path, row) in enumerate(resolved, start=1):
            directory_entry = _required_int(
                row_value(row, "EntryNumber", "Entry Number"), label="MFT entry"
            )
            directory_sequence = _required_int(
                row_value(row, "SequenceNumber", "Sequence Number"),
                label="MFT sequence",
            )
            try:
                parsed = _directory_record(
                    handle,
                    entry=directory_entry,
                    sequence=directory_sequence,
                    expected_path=directory_path,
                )
            except ValueError:
                if exact_roster:
                    raise
                coverage_complete = False
                continue
            scanned_directory_count += 1
            allocation_entries: list[dict[str, Any]] = []
            allocation_errors: list[dict[str, Any]] = []
            allocation_complete = not parsed["index_allocation_present"]
            if parsed["index_allocation_present"]:
                member = native_records.get((directory_entry, directory_sequence))
                if (
                    member is not None
                    and member.get("backing_streams_complete") is True
                    and native_manifest_path is not None
                ):
                    geometry = native["geometry"]
                    allocation_path = sidecar_file(
                        native_manifest_path,
                        member["index_allocation_file"],
                        member["index_allocation_sha256"],
                    )
                    bitmap_path = sidecar_file(
                        native_manifest_path,
                        member["index_bitmap_file"],
                        member["index_bitmap_sha256"],
                    )
                    try:
                        allocation = parse_index_allocation(
                            allocation_path.read_bytes(),
                            bitmap=bitmap_path.read_bytes(),
                            block_size=int(parsed["index_block_size"]),
                            sector_size=UPDATE_SEQUENCE_STRIDE,
                            cluster_size=geometry["bytes_per_cluster"],
                            parent_entry=directory_entry,
                            parent_sequence=directory_sequence,
                        )
                        allocation_entries = allocation["entries"]
                        allocation_complete = allocation["index_allocation_parsed"]
                        allocation_errors = allocation["index_buffer_errors"]
                    except ValueError as error:
                        allocation_errors = [{"error": str(error)}]
                else:
                    allocation_errors = [
                        {
                            "error": "native INDEX_ALLOCATION backing streams are unavailable or incomplete"
                        }
                    ]
            if not allocation_complete:
                coverage_complete = False
            full_surface = native is not None and allocation_complete
            supported_surface = (
                FULL_I30_SURFACE if full_surface else SUPPORTED_I30_SURFACE
            )
            residue: list[dict[str, Any]] = []
            entries = [
                *parsed["resident_index_root_entries"],
                *parsed["index_root_slack_entries"],
                *parsed["record_slack_entries"],
                *allocation_entries,
            ]
            seen_entries: set[tuple[int, int, str, str]] = set()
            directory_base = directory_path.rstrip("\\")
            for entry_position, entry in enumerate(entries, start=1):
                entry_identity = (
                    int(entry["file_reference_entry"]),
                    int(entry["file_reference_sequence"]),
                    str(entry["name"]).casefold(),
                    str(entry["residue_surface"]),
                )
                if entry_identity in seen_entries:
                    continue
                seen_entries.add(entry_identity)
                presence = _active_presence(
                    handle,
                    entry=entry_identity[0],
                    sequence=entry_identity[1],
                    volume_id=volume_id,
                )
                surface = str(entry["residue_surface"])
                if (
                    surface in ("index_root", "index_allocation_active")
                    and presence["mft_active_presence_status"] == "active_mft_present"
                ):
                    continue
                state = (
                    "slack"
                    if surface
                    in (
                        "record_slack",
                        "index_root_slack",
                        "index_allocation_slack",
                        "index_allocation_unallocated_buffer",
                    )
                    else "unlinked"
                )
                entry_name = str(entry["name"])
                residue.append(
                    {
                        "observation_id": (
                            f"obs:bounded-i30-residue:{position:03d}:{entry_position:03d}"
                        ),
                        "artifact_family": "ntfs.i30",
                        "observation_type": "i30_filename_residue",
                        "subject_ref": directory_path,
                        "fields": {
                            "directory_path": directory_path,
                            "mft_volume_id": volume_id,
                            "mft_entry": directory_entry,
                            "sequence_number": directory_sequence,
                            "entry_name": entry_name,
                            "entry_path": f"{directory_base}\\{entry_name}",
                            "file_reference_entry": entry_identity[0],
                            "file_reference_sequence": entry_identity[1],
                            "parent_reference_entry": int(
                                entry["parent_reference_entry"]
                            ),
                            "parent_reference_sequence": int(
                                entry["parent_reference_sequence"]
                            ),
                            "i30_entry_state": state,
                            "residue_surface": surface,
                            "supported_surface": supported_surface,
                            "index_allocation_present": bool(
                                parsed["index_allocation_present"]
                            ),
                            "index_allocation_parsed": bool(
                                parsed["index_allocation_present"]
                                and allocation_complete
                            ),
                            **{
                                key: entry[key]
                                for key in (
                                    "index_buffer_number",
                                    "index_buffer_vcn",
                                    "index_buffer_in_use",
                                )
                                if key in entry
                            },
                            **presence,
                        },
                        "source_record_ref": _source_record_ref(
                            source_id,
                            entry=directory_entry,
                            suffix=f":index={entry_position}",
                        ),
                    }
                )
            if residue:
                residue_directory_count += 1
            if not exact_roster and not residue:
                continue
            scan_observation = {
                "observation_id": f"obs:bounded-i30-scan:{position:03d}",
                "artifact_family": "ntfs.i30",
                "observation_type": "i30_directory_scan",
                "subject_ref": directory_path,
                "fields": {
                    "directory_path": directory_path,
                    "mft_volume_id": volume_id,
                    "mft_entry": directory_entry,
                    "sequence_number": directory_sequence,
                    "scan_complete": allocation_complete,
                    "supported_surface": supported_surface,
                    "resident_index_root_scanned": True,
                    "mft_record_slack_scanned": True,
                    "index_allocation_present": bool(
                        parsed["index_allocation_present"]
                    ),
                    "index_allocation_parsed": bool(
                        parsed["index_allocation_present"] and allocation_complete
                    ),
                    "index_allocation_entry_count": len(allocation_entries),
                    "index_allocation_errors": allocation_errors,
                    "resident_entry_count": len(parsed["resident_index_root_entries"]),
                    "record_slack_entry_count": len(parsed["record_slack_entries"]),
                    "residue_count": len(residue),
                },
                "source_record_ref": _source_record_ref(
                    source_id, entry=directory_entry
                ),
            }
            if exact_roster:
                if residue:
                    retained_residue_directory_count += 1
                observations.append(scan_observation)
                observations.extend(residue)
            else:
                discovered_residue.append(
                    (
                        _residue_retention_key(directory_path),
                        scan_observation,
                        residue,
                    )
                )

    if not exact_roster:
        discovered_residue.sort(key=lambda item: item[0])
        retained = discovered_residue[:max_directories]
        retained_residue_directory_count = len(retained)
        if len(discovered_residue) > max_directories:
            coverage_complete = False
        for _rank, scan_observation, residue in retained:
            observations.append(scan_observation)
            observations.extend(residue)

    normalized_output = normalized_output_dir / f"{source_id}.bounded-i30.json"
    write_json(
        normalized_output,
        {
            "schema_version": "parser_observation_index.v1",
            "parser": "fmb_bounded_parser",
            "parser_kind": "ntfs_i30",
            "source": str(raw_mft_path),
            "directory_count": len(resolved),
            "discovered_directory_count": discovered_count,
            "scanned_directory_count": scanned_directory_count,
            "residue_directory_count": residue_directory_count,
            "retained_residue_directory_count": retained_residue_directory_count,
            "max_directories": max_directories,
            "selection_mode": selection_mode,
            "retention_order": (
                "user_content_then_user_profile_then_other_canonical_path"
                if not exact_roster
                else "exact_public_directory_roster_order"
            ),
            "record_count": len(observations),
            "supported_surface": FULL_I30_SURFACE
            if native is not None
            else SUPPORTED_I30_SURFACE,
            "index_allocation_parsed": native is not None and coverage_complete,
            "observations": observations,
            "truth_sources_used": [],
        },
    )
    return normalize_parser_output(
        parser="fmb_bounded_parser",
        parser_kind="ntfs_i30",
        source_collector=str(collector_run["collector"]),
        source_module="FMBBoundedRawMFTI30",
        raw_outputs=[
            mft_csv_path,
            raw_mft_path,
            *([native_manifest_path] if native_manifest_path is not None else []),
            *(
                native_sidecar_files(native_manifest_path, native)
                if native_manifest_path is not None and native is not None
                else []
            ),
        ],
        normalized_output=normalized_output,
        observations=observations,
        tool_identity={
            "name": "fmb_bounded_parser",
            "version": None,
            "source": "raw $MFT bounded directory projection",
        },
        observation_families=["ntfs.i30"] if observations else None,
        coverage_status="complete" if coverage_complete else "partial",
        coverage_families=["ntfs.i30"],
    )


__all__ = [
    "DEFAULT_MAX_I30_DIRECTORIES",
    "FULL_I30_SURFACE",
    "SUPPORTED_I30_SURFACE",
    "bounded_i30_parser_run",
]
