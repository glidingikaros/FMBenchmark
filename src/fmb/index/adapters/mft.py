from __future__ import annotations

from pathlib import Path
from typing import Any

from fmb.core.ntfs_time import filetime_to_utc_iso
from fmb.index.adapters.parser_output import (
    RankedObservation,
    keep_ranked_observation,
    module_command_line,
    observed_artifact_families,
    ranked_observations,
    source_bound_observations,
    source_scope_id,
    write_observation_index,
)
from fmb.index.contract.evidence_index import normalize_parser_output
from fmb.index.scanners.mft import (
    DEFAULT_MFT_RECORD_SIZE,
    mft_record_is_in_use,
    parse_mft_record,
)
from fmb.index.support.windows_artifacts import (
    MFT_TIMESTAMP_PAIRS,
    canonical_mftecmd_timestamp,
    first_nonempty,
    join_windows_path,
    max_timestamp_mismatch_gap_days,
    mft_path,
    mft_timestamp_mismatches,
    parse_bool,
    parse_csv_timestamp,
    parse_explicit_bool,
    parse_int,
    row_first,
    row_value,
    score_candidate_name,
    stream_csv_rows,
)
from fmb.index.support.windows_identity import (
    REMOTE_PATH_VOLUME,
    normalize_windows_compare_path,
    ntfs_reference_from_row,
    volume_is_comparable,
    windows_compare_path_parts,
)

MAX_MFT_IDENTITY_OBSERVATIONS = 5000

MAX_MFT_TIMESTAMP_OBSERVATIONS = 5000

MFT_TIMESTAMP_POPULATION_RULE = "si_fn_timestamp_difference_present"

MFT_OBSERVATION_TIMESTAMP_FIELDS = (
    ("si_created", "created", True),
    ("si_modified", "modified", True),
    ("si_record_changed", "metadata_changed", True),
    ("si_accessed", "accessed", True),
    ("fn_created", "created", False),
    ("fn_modified", "modified", False),
    ("fn_record_changed", "mft_modified", False),
    ("fn_accessed", "accessed", False),
)


def mft_timestamp_population_rule_evaluable(row: dict[str, str]) -> bool:
    headers = {key.casefold() for key in row}
    available_fields = {
        field
        for field, si_key, fn_key in MFT_TIMESTAMP_PAIRS
        if si_key.casefold() in headers and fn_key.casefold() in headers
    }
    record_change_headers = {
        "lastrecordchange0x10",
        "si mft changed",
    }
    return {"created", "modified", "accessed"}.issubset(available_fields) and bool(
        headers.intersection(record_change_headers)
    )


def timestamp_candidate_population(
    observations: list[dict[str, Any]],
    *,
    source_id: str,
    coverage_status: str,
) -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = {}
    for observation in observations:
        if observation.get("observation_type") not in {
            "mft_file_record",
            "si_fn_timestamp_difference",
        }:
            continue
        subject_ref = str(observation["subject_ref"])
        fields = observation.get("fields", {})
        entry = fields.get("mft_entry") if isinstance(fields, dict) else None
        sequence = fields.get("sequence_number") if isinstance(fields, dict) else None
        volume_id = fields.get("mft_volume_id") if isinstance(fields, dict) else None
        if (
            isinstance(entry, int)
            and not isinstance(entry, bool)
            and entry >= 0
            and isinstance(sequence, int)
            and not isinstance(sequence, bool)
            and sequence >= 0
            and isinstance(volume_id, str)
            and volume_id
        ):
            identity = {"object_id": f"ntfs:{volume_id}:{entry}:{sequence}"}
        else:
            identity = {
                "canonical_name": subject_ref.replace("/", "\\")
                .strip()
                .casefold()
                .rstrip("\\")
            }
        identity_key = next(iter(identity.values()))
        subject = grouped.setdefault(
            identity_key,
            {
                "subject_ref": subject_ref,
                "identity": identity,
                "observation_ids": [],
            },
        )
        subject["observation_ids"].append(str(observation["observation_id"]))
    subjects = sorted(
        grouped.values(), key=lambda item: sorted(item["identity"].items())
    )
    for subject in subjects:
        subject["observation_ids"] = sorted(set(subject["observation_ids"]))
    return {
        "population_id": f"population:timestamp:{source_id}",
        "question_id": "Q-TIME-01",
        "technique_id": "timestamp_manipulation",
        "subject_type": "file",
        "coverage_status": coverage_status,
        "subjects": subjects,
    }


def _raw_mft_timestamp_text(value: Any, *, label: str) -> str:
    if not isinstance(value, dict):
        raise ValueError(f"{label} is missing from the raw $MFT record")
    filetime = value.get("ntfs_filetime")
    utc = value.get("utc")
    if isinstance(filetime, bool) or not isinstance(filetime, int):
        raise ValueError(f"{label} has no valid raw NTFS FILETIME")
    canonical = filetime_to_utc_iso(filetime)
    if (
        canonical is None
        or not isinstance(utc, str)
        or parse_csv_timestamp(utc) != parse_csv_timestamp(canonical)
    ):
        raise ValueError(f"{label} has inconsistent raw timestamp values")
    return canonical


def _matching_raw_mft_file_name(
    parsed: dict[str, Any], fields: dict[str, Any]
) -> dict[str, Any]:
    expected_name = str(fields.get("file_name") or "").casefold()
    if ":" in expected_name:
        host_name, stream_name = expected_name.split(":", 1)
        streams = [item for item in parsed.get("data_attributes", [])
                   if item.get("is_named_stream") is True
                   and str(item.get("stream_name", "")).casefold() == stream_name]
        if not host_name or not stream_name or len(streams) != 1:
            raise ValueError("MFTECmd stream row has no exact native named $DATA identity")
        expected_name = host_name
    expected_parent = fields.get("parent_entry_number")
    expected_parent_sequence = fields.get("parent_sequence_number")
    if (
        not expected_name
        or not isinstance(expected_parent, int)
        or isinstance(expected_parent, bool)
        or not isinstance(expected_parent_sequence, int)
        or isinstance(expected_parent_sequence, bool)
    ):
        raise ValueError("MFTECmd row lacks exact file-name parent identity")
    matches = [
        item
        for item in parsed.get("file_name_attributes", [])
        if isinstance(item, dict)
        and str(item.get("name") or "").casefold() == expected_name
        and item.get("namespace_name") in {"win32", "win32_and_dos"}
        and item.get("parent_inode") == expected_parent
        and item.get("parent_sequence") == expected_parent_sequence
    ]
    if len(matches) != 1:
        raise ValueError(
            "raw $MFT record does not contain one exact Win32 $FILE_NAME identity"
        )
    return matches[0]


def _mft_timestamp_row_from_fields(fields: dict[str, Any]) -> dict[str, str]:
    return {
        "Created0x10": str(fields.get("si_created") or ""),
        "LastModified0x10": str(fields.get("si_modified") or ""),
        "LastRecordChange0x10": str(fields.get("si_record_changed") or ""),
        "LastAccess0x10": str(fields.get("si_accessed") or ""),
        "Created0x30": str(fields.get("fn_created") or ""),
        "LastModified0x30": str(fields.get("fn_modified") or ""),
        "LastRecordChange0x30": str(fields.get("fn_record_changed") or ""),
        "LastAccess0x30": str(fields.get("fn_accessed") or ""),
    }


def _recover_one_mft_observation(fields: dict[str, Any], *, handle: Any) -> int:
    entry = fields.get("mft_entry")
    sequence = fields.get("sequence_number")
    if (
        isinstance(entry, bool)
        or not isinstance(entry, int)
        or entry < 0
        or isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 0
    ):
        raise ValueError("MFTECmd row lacks an exact MFT entry and sequence")
    record_offset = entry * DEFAULT_MFT_RECORD_SIZE
    handle.seek(record_offset)
    raw_record = handle.read(DEFAULT_MFT_RECORD_SIZE)
    if len(raw_record) != DEFAULT_MFT_RECORD_SIZE:
        raise ValueError(f"raw $MFT record {entry} is outside the source")
    parsed = parse_mft_record(
        raw_record,
        record_offset=record_offset,
        record_size=DEFAULT_MFT_RECORD_SIZE,
    )
    if (
        not isinstance(parsed, dict)
        or parsed.get("mft_entry") != entry
        or parsed.get("sequence_number") != sequence
        or not mft_record_is_in_use(parsed)
    ):
        raise ValueError(f"raw $MFT identity mismatch for entry {entry}")
    file_name = _matching_raw_mft_file_name(parsed, fields)
    si_timestamps = parsed.get("metadata_timestamps")
    fn_timestamps = file_name.get("file_name_timestamps")
    if not isinstance(si_timestamps, dict) or not isinstance(fn_timestamps, dict):
        raise ValueError(f"raw $MFT timestamps are missing for entry {entry}")
    recovered_value_count = 0
    for field_name, raw_name, standard_information in MFT_OBSERVATION_TIMESTAMP_FIELDS:
        source = si_timestamps if standard_information else fn_timestamps
        raw_text = _raw_mft_timestamp_text(
            source.get(raw_name), label=f"entry {entry} {field_name}"
        )
        csv_text = str(fields.get(field_name) or "")
        if csv_text:
            if parse_csv_timestamp(csv_text) != parse_csv_timestamp(raw_text):
                raise ValueError(
                    "MFTECmd and raw $MFT timestamp mismatch for "
                    f"entry {entry} field {field_name}"
                )
        else:
            fields[field_name] = raw_text
            recovered_value_count += 1
    mismatches = mft_timestamp_mismatches(_mft_timestamp_row_from_fields(fields))
    fields["mismatch_fields"] = [item["field"] for item in mismatches]
    fields["mismatch_count"] = len(mismatches)
    fields["max_gap_days"] = max_timestamp_mismatch_gap_days(mismatches)
    fields["mismatches"] = mismatches
    if isinstance(fields.get("mft_volume_id"), str):
        fields["raw_mft_timestamp_source_ref"] = (
            f"native:{fields['mft_volume_id']}:$MFT:entry={entry}:sequence={sequence}"
        )
    return recovered_value_count


def _recover_mft_observation_timestamps(
    observations: list[dict[str, Any]], *, raw_mft_path: Path
) -> tuple[int, int, int]:
    if not raw_mft_path.is_file():
        raise ValueError("raw $MFT source is unavailable")
    if raw_mft_path.stat().st_size % DEFAULT_MFT_RECORD_SIZE:
        raise ValueError("raw $MFT source is not record aligned")
    recovered_value_count = 0
    verified_record_count = 0
    failed_record_count = 0
    seen_rows: set[int] = set()
    with raw_mft_path.open("rb") as handle:
        for observation in observations:
            fields = observation.get("fields")
            if not isinstance(fields, dict):
                raise ValueError("MFT observation fields are invalid")
            row_index = fields.get("row_index")
            if isinstance(row_index, int) and row_index in seen_rows:
                continue
            if isinstance(row_index, int):
                seen_rows.add(row_index)
            try:
                recovered_value_count += _recover_one_mft_observation(
                    fields, handle=handle
                )
            except ValueError as error:
                fields["raw_mft_timestamp_validation"] = "failed"
                fields["raw_mft_timestamp_validation_error"] = str(error)
                failed_record_count += 1
            else:
                fields["raw_mft_timestamp_validation"] = "verified"
                fields.pop("raw_mft_timestamp_validation_error", None)
                verified_record_count += 1
    return recovered_value_count, verified_record_count, failed_record_count


def mftecmd_mft_csv_files(root: Path) -> list[Path]:
    full_outputs = []
    file_listing_outputs = []
    for path in sorted(root.rglob("*.csv")):
        folded = str(path).replace("\\", "/").casefold()
        if "mftecmd" not in folded or "output" not in folded:
            continue
        folded_name = path.name.casefold()
        if any(token in folded_name for token in ("$j", "$sds", "$boot", "$i30")):
            continue
        if "filelisting" in folded_name:
            file_listing_outputs.append(path)
        else:
            full_outputs.append(path)
    return full_outputs or file_listing_outputs


def mftecmd_mft_context_csv_files(root: Path) -> list[Path]:
    candidates = mftecmd_mft_csv_files(root)
    return candidates if len(candidates) == 1 else []


def mft_row_full_path(row: dict[str, str]) -> str:
    full_path = first_nonempty(row_value(row, "FullPath", "Full Path", "Path"))
    if full_path:
        return full_path
    parent = first_nonempty(row_value(row, "ParentPath", "Parent Path"))
    name = first_nonempty(
        row_value(row, "FileName", "File Name", "Name"),
    )
    if parent or name:
        return join_windows_path(parent, name)
    return ""


def mft_row_is_active(row: dict[str, str]) -> bool:
    return parse_bool(row_value(row, "InUse", "In Use"), default=True)


def mft_row_is_directory(row: dict[str, str]) -> bool:
    if parse_bool(row_value(row, "IsDirectory", "Is Directory"), default=False):
        return True
    attributes = first_nonempty(row_value(row, "FileAttributes", "Attributes"))
    return "directory" in attributes.casefold()


def build_mft_presence_context(root: Path) -> dict[str, Any]:
    active_full_paths: set[str] = set()
    active_basenames: set[str] = set()
    active_refs: set[tuple[int, int]] = set()
    entry_states: dict[int, set[tuple[int, bool]]] = {}
    directory_paths_by_ref: dict[tuple[int, int], str] = {}
    indexed_volumes: set[str] = set()
    source_paths: list[str] = []
    row_count = 0
    malformed_identity_row_count = 0
    malformed_reference_row_count = 0
    malformed_path_row_count = 0
    for path in mftecmd_mft_context_csv_files(root):
        source_paths.append(str(path))
        for row in stream_csv_rows(path):
            row_count += 1
            full_path = mft_row_full_path(row)
            active_state = parse_explicit_bool(row_value(row, "InUse", "In Use"))
            active = active_state is True
            reference = ntfs_reference_from_row(
                row,
                entry_keys=("EntryNumber", "Entry Number"),
                sequence_keys=("SequenceNumber", "Sequence Number"),
            )
            volume, normalized_full_path = windows_compare_path_parts(full_path)
            reference_incomplete = reference is None or active_state is None
            path_incomplete = (
                not full_path
                or not normalized_full_path
                or volume == REMOTE_PATH_VOLUME
                or active_state is None
            )
            if reference_incomplete:
                malformed_reference_row_count += 1
            if path_incomplete:
                malformed_path_row_count += 1
            if reference_incomplete or path_incomplete:
                malformed_identity_row_count += 1
            if volume is not None:
                indexed_volumes.add(volume)
            if active and full_path:
                active_full_paths.add(normalized_full_path)
                basename = normalized_full_path.rpartition("\\")[2]
                if basename and ":" not in basename:
                    active_basenames.add(basename)
            if active and reference is not None:
                active_refs.add(reference)
            if reference is not None:
                entry, sequence = reference
                entry_states.setdefault(entry, set()).add((sequence, active))
            if reference is not None and full_path and mft_row_is_directory(row):
                directory_paths_by_ref.setdefault(reference, full_path)
    volume_id = (
        f"mft-source:{source_scope_id(Path(source_paths[0]))}"
        if len(source_paths) == 1
        else None
    )
    ambiguous_entries = {
        entry for entry, states in entry_states.items() if len(states) != 1
    }
    entry_sequences = {
        entry: next(iter(states))
        for entry, states in entry_states.items()
        if len(states) == 1
    }
    reference_absence_check_supported = bool(
        len(source_paths) == 1
        and row_count
        and malformed_reference_row_count == 0
        and not ambiguous_entries
    )
    path_absence_check_supported = bool(
        len(source_paths) == 1 and row_count and malformed_path_row_count == 0
    )
    absence_check_supported = bool(
        reference_absence_check_supported and path_absence_check_supported
    )
    return {
        "row_count": row_count,
        "source_paths": source_paths,
        "active_full_paths": active_full_paths,
        "active_basenames": active_basenames,
        "active_refs": active_refs,
        "entry_sequences": entry_sequences,
        "directory_paths_by_ref": directory_paths_by_ref,
        "indexed_volumes": indexed_volumes,
        "mft_volume_id": volume_id,
        "absence_check_supported": absence_check_supported,
        "reference_absence_check_supported": reference_absence_check_supported,
        "path_absence_check_supported": path_absence_check_supported,
        "malformed_identity_row_count": malformed_identity_row_count,
        "malformed_reference_row_count": malformed_reference_row_count,
        "malformed_path_row_count": malformed_path_row_count,
        "ambiguous_entries": ambiguous_entries,
    }


def reconstruct_usn_subject(
    *,
    name: str,
    full_path: str = "",
    parent_path: str = "",
    parent_reference: tuple[int, int] | None = None,
    mft_context: dict[str, Any] | None = None,
) -> str:
    if full_path.strip():
        return full_path.strip()
    if parent_path.strip():
        return join_windows_path(parent_path, name)
    if mft_context is not None and parent_reference is not None:
        paths = mft_context.get("directory_paths_by_ref", {})
        if isinstance(paths, dict):
            parent_from_mft = paths.get(parent_reference)
            if isinstance(parent_from_mft, str) and parent_from_mft.strip():
                return join_windows_path(parent_from_mft, name)
    return name


def mft_active_presence_fields(
    *,
    subject: str,
    file_reference: tuple[int, int] | None,
    mft_context: dict[str, Any] | None,
    exact_reference_required: bool = False,
) -> dict[str, Any]:
    fields = _mft_active_presence_fields(
        subject=subject,
        file_reference=file_reference,
        mft_context=mft_context,
        exact_reference_required=exact_reference_required,
    )
    native_volume, _ = windows_compare_path_parts(subject)
    binding = (mft_context or {}).get("native_volume_bindings", {}).get(native_volume)
    if binding is not None:
        fields.update(binding)
    target: dict[str, Any] = {"target_role": "candidate", "path": subject}
    volume_id = fields.get("mft_volume_id") or (mft_context or {}).get("mft_volume_id")
    if volume_id:
        target["mft_volume_id"] = volume_id
        if file_reference is not None:
            entry, sequence = file_reference
            target["object_id"] = f"ntfs:{volume_id}:{entry}:{sequence}"
    fields["mft_lookup_target"] = target
    if file_reference is not None and mft_context:
        sequences = mft_context.get("entry_sequences")
        if isinstance(sequences, dict) and sequences:
            entry, _ = file_reference
            observed = sequences.get(entry)
            fields["mft_lookup_observed"] = {
                "entry": entry,
                "sequence": observed[0] if observed is not None else None,
                "in_use": observed[1] if observed is not None else None,
            }
    return fields


def _undecidable_presence(basis: str) -> dict[str, Any]:
    return {
        "mft_active_presence_status": "active_mft_absence_undecidable",
        "mft_active_presence_check_supported": False,
        "mft_active_presence_basis": basis,
        "mft_active_path_match": False,
        "mft_active_reference_match": False,
        "mft_volume_id": None,
    }


def _mft_active_presence_fields(
    *,
    subject: str,
    file_reference: tuple[int, int] | None,
    mft_context: dict[str, Any] | None,
    exact_reference_required: bool = False,
) -> dict[str, Any]:
    if not mft_context or not int(mft_context.get("row_count", 0) or 0):
        return {
            "mft_active_presence_status": "mft_context_unavailable",
            "mft_active_presence_check_supported": False,
            "mft_active_path_match": False,
            "mft_active_reference_match": False,
            "mft_volume_id": None,
        }
    if exact_reference_required and file_reference is None:
        return _undecidable_presence("exact_reference_unavailable")
    ambiguous_entries = mft_context.get("ambiguous_entries", set())
    if file_reference is not None and file_reference[0] in ambiguous_entries:
        return _undecidable_presence("ambiguous_mft_entry")
    completeness_key = (
        "reference_absence_check_supported"
        if file_reference is not None
        else "path_absence_check_supported"
    )
    surface_complete = mft_context.get(
        completeness_key,
        mft_context.get("absence_check_supported", True),
    )
    if surface_complete is not True:
        return _undecidable_presence(
            "incomplete_mft_reference_surface"
            if file_reference is not None
            else "incomplete_mft_path_surface"
        )
    active_paths = mft_context.get("active_full_paths", set())
    active_basenames = mft_context.get("active_basenames", set())
    active_refs = mft_context.get("active_refs", set())
    entry_sequences = mft_context.get("entry_sequences", {})
    volume_id = mft_context.get("mft_volume_id")
    subject_volume, normalized_subject = windows_compare_path_parts(subject)
    indexed_volumes = set(mft_context.get("indexed_volumes", set()))
    if not volume_is_comparable(subject_volume, indexed_volumes):
        return _undecidable_presence("unindexed_volume")
    if (
        file_reference is not None
        and isinstance(entry_sequences, dict)
        and entry_sequences
    ):
        entry, sequence = file_reference
        live = entry_sequences.get(entry)
        if live is None:
            status, basis = "active_mft_absent", "file_reference_entry_absent"
        elif live[0] == sequence and live[1]:
            status, basis = "active_mft_present", "file_reference_in_use"
        elif live[0] != sequence:
            status = "active_mft_absent"
            basis = "file_reference_entry_reused" if live[1] else "file_reference_entry_freed"
        else:
            status, basis = "active_mft_absent", "file_reference_record_free"
        return {
            "mft_active_presence_status": status,
            "mft_active_presence_check_supported": True,
            "mft_active_presence_basis": basis,
            "mft_active_path_match": normalize_windows_compare_path(subject)
            in active_paths,
            "mft_active_reference_match": status == "active_mft_present",
            "mft_volume_id": volume_id,
        }
    is_basename = bool(normalized_subject) and "\\" not in normalized_subject
    if is_basename:
        active_path_match = normalized_subject in active_basenames
    else:
        active_path_match = normalized_subject in active_paths
    active_reference_match = (
        file_reference in active_refs if file_reference is not None else False
    )
    active_present = (
        active_reference_match if file_reference is not None else active_path_match
    )
    if active_present:
        status = "active_mft_present"
    elif file_reference is not None or normalized_subject:
        status = "active_mft_absent"
    else:
        status = "active_mft_absence_undecidable"
    return {
        "mft_active_presence_status": status,
        "mft_active_presence_check_supported": status
        != "active_mft_absence_undecidable",
        "mft_active_presence_basis": (
            "basename_volume_search" if is_basename else "path_comparison"
        ),
        "mft_active_path_match": active_path_match,
        "mft_active_reference_match": active_reference_match,
        "mft_volume_id": volume_id,
    }


def mftecmd_mft_parser_run(
    *,
    csv_path: Path,
    raw_mft_path: Path | None = None,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    public_paths: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    identity_candidates: list[RankedObservation] = []
    timestamp_candidates: list[RankedObservation] = []
    source_id = source_scope_id(csv_path)
    mft_volume_id = f"mft-source:{source_id}"
    source_row_count = 0
    identity_candidate_row_count = 0
    candidate_row_count = 0
    population_rule_evaluable: bool | None = None
    public_suffixes = {normalize_windows_compare_path(p) for p in public_paths}
    public_identity_observations: list[dict[str, Any]] = []
    public_timestamp_observations: list[dict[str, Any]] = []
    for row_index, row in enumerate(stream_csv_rows(csv_path), start=1):
        source_row_count = row_index
        if population_rule_evaluable is None:
            population_rule_evaluable = mft_timestamp_population_rule_evaluable(row)
        timestamp_row = canonical_mftecmd_timestamp_row(row)
        subject = mft_path(row)
        if (
            subject == "<unknown>"
            or not mft_row_is_active(row)
            or mft_row_is_directory(row)
        ):
            continue
        entry = parse_int(row_first(row, "EntryNumber", "Entry Number"))
        sequence = parse_int(row_first(row, "SequenceNumber", "Sequence Number"))
        parent_entry = parse_int(
            row_first(row, "ParentEntryNumber", "Parent Entry Number")
        )
        parent_sequence = parse_int(
            row_first(row, "ParentSequenceNumber", "Parent Sequence Number")
        )
        mismatches = mft_timestamp_mismatches(timestamp_row)
        score = score_candidate_name(subject, purpose="timestomp")
        identity_candidate_row_count += 1
        identity_observation = {
            "observation_id": f"obs:mftecmd-mft-subject:{row_index:06d}",
            "artifact_family": "ntfs.mft",
            "observation_type": "mft_file_record",
            "subject_ref": subject,
            "fields": {
                "si_created": row_first(timestamp_row, "Created0x10", "SI Created"),
                "si_modified": row_first(
                    timestamp_row, "LastModified0x10", "SI Modified"
                ),
                "si_record_changed": row_first(
                    timestamp_row, "LastRecordChange0x10", "SI MFT Changed"
                ),
                "si_accessed": row_first(
                    timestamp_row, "LastAccess0x10", "SI Accessed"
                ),
                "fn_created": row_first(timestamp_row, "Created0x30", "FN Created"),
                "fn_modified": row_first(
                    timestamp_row, "LastModified0x30", "FN Modified"
                ),
                "fn_record_changed": row_first(
                    timestamp_row, "LastRecordChange0x30", "FN MFT Changed"
                ),
                "fn_accessed": row_first(
                    timestamp_row, "LastAccess0x30", "FN Accessed"
                ),
                "mismatch_fields": [item["field"] for item in mismatches],
                "mismatch_count": len(mismatches),
                "max_gap_days": max_timestamp_mismatch_gap_days(mismatches),
                "record_changed_si": row_first(
                    timestamp_row, "LastRecordChange0x10", "SI MFT Changed"
                ),
                "candidate_score": score,
                "row_index": row_index,
                "mismatches": mismatches,
                "mft_entry": entry,
                "sequence_number": sequence,
                "file_name": row_first(row, "FileName", "File Name", "Name"),
                "parent_entry_number": parent_entry,
                "parent_sequence_number": parent_sequence,
                "in_use": True,
                "mft_volume_id": mft_volume_id,
            },
            "source_record_ref": f"{csv_path.name}:row={row_index}",
        }
        keep_ranked_observation(
            identity_candidates,
            score=score,
            row_index=row_index,
            observation=identity_observation,
            limit=MAX_MFT_IDENTITY_OBSERVATIONS,
        )
        timestamp_observation = {
            **identity_observation,
            "observation_id": f"obs:mftecmd-mft-timestamp:{row_index:06d}",
            "observation_type": "si_fn_timestamp_difference",
        } if mismatches else None
        if normalize_windows_compare_path(subject) in public_suffixes:
            public_identity_observations.append(identity_observation)
            if timestamp_observation is not None:
                public_timestamp_observations.append(timestamp_observation)
        if timestamp_observation is None:
            continue
        candidate_row_count += 1
        keep_ranked_observation(
            timestamp_candidates,
            score=score,
            row_index=row_index,
            observation=timestamp_observation,
            limit=MAX_MFT_TIMESTAMP_OBSERVATIONS,
        )

    selected_identity_observations = ranked_observations(identity_candidates)
    selected_timestamp_observations = ranked_observations(timestamp_candidates)
    for selected, public in ((selected_identity_observations, public_identity_observations),
                             (selected_timestamp_observations, public_timestamp_observations)):
        seen = {r["observation_id"] for r in selected}
        selected.extend(r for r in public if r["observation_id"] not in seen)
    raw_timestamp_recovered_value_count = 0
    raw_timestamp_verified_record_count = 0
    raw_timestamp_failed_record_count = 0
    if raw_mft_path is not None and population_rule_evaluable is True:
        (
            raw_timestamp_recovered_value_count,
            raw_timestamp_verified_record_count,
            raw_timestamp_failed_record_count,
        ) = _recover_mft_observation_timestamps(
            [*selected_identity_observations, *selected_timestamp_observations],
            raw_mft_path=raw_mft_path,
        )
    timestamps_complete = all(
        all(str(fields.get(field_name) or "") for field_name, _raw, _si in MFT_OBSERVATION_TIMESTAMP_FIELDS)
        for observation in selected_identity_observations
        if isinstance((fields := observation.get("fields")), dict)
    )
    identity_observations = source_bound_observations(
        selected_identity_observations, csv_path, source_id=source_id
    )
    timestamp_observations = source_bound_observations(
        selected_timestamp_observations, csv_path, source_id=source_id
    )
    observations = [*identity_observations, *timestamp_observations]

    normalized_output = write_observation_index(
        normalized_output_dir=normalized_output_dir,
        raw_output=csv_path,
        file_suffix="mft_observations.json",
        parser="MFTECmd",
        parser_kind="ntfs_mft",
        observations=observations,
        extra={
            "source_row_count": source_row_count,
            "candidate_population_rule": MFT_TIMESTAMP_POPULATION_RULE,
            "candidate_population_rule_evaluable": (population_rule_evaluable is True),
            "identity_candidate_row_count": identity_candidate_row_count,
            **({"explicit_public_paths": sorted(public_paths),
                "explicit_public_identity_rows": len(public_identity_observations)} if public_paths else {}),
            "max_identity_subjects": MAX_MFT_IDENTITY_OBSERVATIONS,
            "identity_selection_truncated": (
                identity_candidate_row_count > MAX_MFT_IDENTITY_OBSERVATIONS
            ),
            "candidate_row_count": candidate_row_count,
            "max_candidate_subjects": MAX_MFT_TIMESTAMP_OBSERVATIONS,
            "candidate_selection_truncated": (
                candidate_row_count > MAX_MFT_TIMESTAMP_OBSERVATIONS
            ),
            "raw_timestamp_recovered_value_count": (
                raw_timestamp_recovered_value_count
            ),
            "raw_timestamp_verified_record_count": (
                raw_timestamp_verified_record_count
            ),
            "raw_timestamp_failed_record_count": raw_timestamp_failed_record_count,
            "timestamp_fields_complete": timestamps_complete,
        },
    )
    coverage_status = (
        "complete"
        if population_rule_evaluable is True
        and timestamps_complete
        and raw_timestamp_failed_record_count == 0
        and candidate_row_count <= MAX_MFT_TIMESTAMP_OBSERVATIONS
        else "partial"
    )
    parser_run = normalize_parser_output(
        parser="MFTECmd",
        parser_kind="ntfs_mft",
        source_collector=str(collector_run["collector"]),
        source_module="MFTECmd",
        raw_outputs=[
            csv_path,
            *([raw_mft_path] if raw_mft_path is not None else []),
        ],
        normalized_output=normalized_output,
        observations=observations,
        command_line=module_command_line(collector_run, "mftecmd"),
        tool_identity={
            "name": "MFTECmd",
            "version": None,
            "source": "KAPE module output",
        },
        observation_families=observed_artifact_families(observations),
        coverage_status=coverage_status,
    )
    parser_run["candidate_populations"] = [
        timestamp_candidate_population(
            timestamp_observations,
            source_id=source_id,
            coverage_status=coverage_status,
        )
    ]
    return parser_run


def canonical_mftecmd_timestamp_row(row: dict[str, str]) -> dict[str, str]:
    normalized = dict(row)
    for _field, si_key, fn_key in MFT_TIMESTAMP_PAIRS:
        for key in (si_key, fn_key):
            if key in normalized:
                normalized[key] = canonical_mftecmd_timestamp(normalized[key])
    return normalized


def raw_mft_path_for_root(root: Path) -> Path | None:
    paths = sorted(root.glob("targets/*/$MFT"))
    return paths[0] if len(paths) == 1 else None
