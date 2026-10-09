from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fmb.core.hashing import sha256_file
from fmb.core.json_io import write_json
from fmb.core.ntfs_time import filetime_to_utc_iso
from fmb.index.adapters.mft import (
    mft_active_presence_fields,
    reconstruct_usn_subject,
)
from fmb.index.adapters.parser_output import (
    RankedObservation,
    keep_ranked_observation,
    normalized_output_path,
    observed_artifact_families,
    parser_run_from_observations,
    ranked_observations,
    source_bound_observations,
    write_observation_index,
)
from fmb.index.contract.evidence_index import normalize_parser_output
from fmb.index.scanners.logfile import (
    preferred_file_name,
    si_updates_from_records,
)
from fmb.index.scanners.logfile_runtime import (
    DEFAULT_OPERATIONS as LOGFILE_DEFAULT_OPERATIONS,
)
from fmb.index.scanners.logfile_runtime import (
    RECORDS_SCHEMA_VERSION as LOGFILE_RECORDS_SCHEMA_VERSION,
)
from fmb.index.scanners.logfile_runtime import (
    LogFileRuntimeError,
    logfile_runtime_availability,
    run_logfile_driver,
)
from fmb.index.scanners.usn import ntfs_reference_set_sha256
from fmb.index.support.windows_artifacts import (
    PATH_SUBJECT_HEADERS,
    csv_files_with_tokens,
    csv_has_required_headers,
    first_nonempty,
    row_first,
    row_recency_score,
    score_candidate_name,
    stream_csv_rows,
    user_path_score,
)
from fmb.index.support.windows_identity import (
    NTFS_FILE_REFERENCE_ENTRY_MASK,
    ntfs_reference_fields,
)

MAX_NTFS_LOGFILE_OBSERVATIONS = 5000


def logfile_csv_files(root: Path) -> list[Path]:
    return csv_files_with_tokens(
        root,
        include_any=("ntfslogtracker", "$logfile"),
        exclude_any=("evtxecmd", "hayabusa", "sigma", "timeline"),
    )


LOGFILE_TIMESTAMP_TOKENS = (
    "basicinfochange",
    "filebasicinformation",
    "setbasic",
    "standardinformation",
    "timestamp",
)

LOGFILE_OPERATION_HEADERS = (
    "Operation",
    "OperationName",
    "Action",
    "Event",
    "RedoOperation",
    "UndoOperation",
    "Redo",
    "Undo",
    "Reason",
    "UpdateReasons",
    "Description",
)

LOGFILE_TIMESTAMP_HEADERS = (
    "Timestamp",
    "EventTime",
    "TimeCreated",
    "UpdateTimestamp",
    "FileTime",
)

LOGFILE_DELETE_TOKENS = ("filedelete", "delete", "unlink")

LOGFILE_RENAME_TOKENS = ("renameoldname", "renamenewname", "rename")


def logfile_operation_text(row: dict[str, str]) -> str:
    return " ".join(row_first(row, key) for key in LOGFILE_OPERATION_HEADERS)


def logfile_observation_types(row: dict[str, str]) -> list[str]:
    folded = logfile_operation_text(row).replace("_", "").casefold()
    observation_types: list[str] = []
    if any(token in folded for token in LOGFILE_TIMESTAMP_TOKENS):
        observation_types.append("logfile_timestamp_change")
    if any(token in folded for token in LOGFILE_DELETE_TOKENS):
        observation_types.append("logfile_file_delete")
    if any(token in folded for token in LOGFILE_RENAME_TOKENS):
        observation_types.append("logfile_file_rename")
    return observation_types


def logfile_subject_from_row(row: dict[str, str]) -> str:
    return first_nonempty(
        row_first(
            row,
            "FullPath",
            "FilePath",
            "Path",
            "TargetPath",
            "CurrentPath",
            "OriginalPath",
            "AffectedFile",
            "FileName",
            "File Name",
            "Name",
            "TargetName",
        ),
        "<unknown>",
    )


def logfile_candidate_score(
    row: dict[str, str],
    *,
    subject: str,
    observation_type: str,
) -> int:
    purpose = (
        "timestomp" if observation_type == "logfile_timestamp_change" else "usn_delete"
    )
    score = score_candidate_name(subject, purpose=purpose)
    score += user_path_score(subject)
    score += row_recency_score(row, *LOGFILE_TIMESTAMP_HEADERS)
    score += 80
    return score


def logfile_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
) -> dict[str, Any]:
    candidates: list[RankedObservation] = []
    candidate_count = 0
    contract_evaluable = csv_has_required_headers(
        csv_path, PATH_SUBJECT_HEADERS, LOGFILE_OPERATION_HEADERS
    )
    for row_index, row in enumerate(stream_csv_rows(csv_path), start=1):
        subject = logfile_subject_from_row(row)
        if subject == "<unknown>":
            continue
        for observation_type in logfile_observation_types(row):
            candidate_count += 1
            score = logfile_candidate_score(
                row, subject=subject, observation_type=observation_type
            )
            observation = {
                "observation_id": f"obs:ntfs-logfile:{observation_type}:{row_index:06d}",
                "artifact_family": "ntfs.logfile",
                "observation_type": observation_type,
                "subject_ref": subject,
                "fields": {
                    "row_index": row_index,
                    "timestamp": row_first(row, *LOGFILE_TIMESTAMP_HEADERS),
                    "operation": row_first(
                        row, "Operation", "OperationName", "Action", "Event"
                    ),
                    "redo_operation": row_first(row, "RedoOperation", "Redo"),
                    "undo_operation": row_first(row, "UndoOperation", "Undo"),
                    "lsn": row_first(row, "LSN", "LogSequenceNumber"),
                    "source_file": row_first(row, "SourceFile", "Source File"),
                    "candidate_score": score,
                },
                "source_record_ref": f"{csv_path.name}:row={row_index}",
            }
            keep_ranked_observation(
                candidates,
                score=score,
                row_index=row_index,
                observation=observation,
                limit=MAX_NTFS_LOGFILE_OBSERVATIONS,
            )
    observations = ranked_observations(candidates)
    return parser_run_from_observations(
        parser="NTFSLogTracker",
        parser_kind="ntfs_logfile",
        source_module="NTFSLogTracker_$LogFile",
        command_needles=("ntfslogtracker", "$logfile"),
        normalized_suffix="logfile",
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        raw_output=csv_path,
        observations=observations,
        coverage_status=(
            "complete"
            if contract_evaluable and candidate_count <= MAX_NTFS_LOGFILE_OBSERVATIONS
            else "partial"
        ),
    )


LOGFILE_DRIVER_DOCUMENT_SUFFIX = "logfile_records.json"

LOGFILE_RETENTION_BASIS = (
    "retained $LogFile records only; the circular log overwrites earlier "
    "transactions, so an absent transaction is not evidence of absence"
)


def raw_logfile_files(root: Path) -> list[Path]:
    logs: list[Path] = []
    if not root.exists():
        return logs
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name != "$LogFile":
            continue
        if "/targets/" in str(path).replace("\\", "/").casefold():
            logs.append(path)
    return logs


def _logfile_driver_document(
    logfile_path: Path,
    *,
    normalized_output_dir: Path,
) -> dict[str, Any]:
    document_path = normalized_output_path(
        normalized_output_dir, logfile_path, LOGFILE_DRIVER_DOCUMENT_SUFFIX
    )
    expected_sha256 = sha256_file(logfile_path)
    if document_path.is_file():
        try:
            cached = json.loads(document_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cached = None
        if (
            isinstance(cached, dict)
            and cached.get("schema_version") == LOGFILE_RECORDS_SCHEMA_VERSION
            and (cached.get("logfile") or {}).get("sha256") == expected_sha256
            and set(LOGFILE_DEFAULT_OPERATIONS) <= set((cached.get("selection") or {}).get("operations", []))
            and isinstance(cached.get("runtime"), dict)
        ):
            return cached
    document = run_logfile_driver(
        logfile_path, output_path=document_path, operations=LOGFILE_DEFAULT_OPERATIONS
    )
    document_path.write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
    return document


def _logfile_document(
    logfile_path: Path, *, normalized_output_dir: Path
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    availability = logfile_runtime_availability()
    if not availability.get("available"):
        return None, availability
    try:
        document = _logfile_driver_document(
            logfile_path, normalized_output_dir=normalized_output_dir
        )
    except LogFileRuntimeError as error:
        return None, {
            "available": False,
            "reason": "dfir_ntfs_driver_failed",
            "detail": str(error),
            "tool_identity": availability.get("tool_identity"),
        }
    return document, availability


LOGFILE_UNAVAILABLE_REASON_CODES = frozenset(
    {
        "dfir_ntfs_runtime_unavailable",
        "dfir_ntfs_lock_missing",
        "dfir_ntfs_lock_unsupported",
        "dfir_ntfs_environment_mismatch",
        "dfir_ntfs_driver_failed",
    }
)


def logfile_reason_code(reason: str | None) -> str:
    code = str(reason or "").split(":", 1)[0].strip()
    return code if code in LOGFILE_UNAVAILABLE_REASON_CODES else "dfir_ntfs_runtime_unavailable"


def logfile_unavailable_scope(
    logfile_path: Path, *, reason: str | None
) -> dict[str, Any]:
    return {
        "kind": "ntfs_logfile",
        "source_file": logfile_path.name,
        "size_bytes": logfile_path.stat().st_size,
        "parser_status": "unavailable",
        "reason": logfile_reason_code(reason),
        "window_complete": False,
        "retention_basis": LOGFILE_RETENTION_BASIS,
    }


def logfile_coverage_scope(
    document: dict[str, Any],
    *,
    logfile_path: Path,
    diagnostics: dict[str, Any],
) -> dict[str, Any]:
    parse = document.get("parse") or {}
    usn = document.get("embedded_usn") or {}
    first = usn.get("first_timestamp_filetime")
    last = usn.get("last_timestamp_filetime")
    first_iso = filetime_to_utc_iso(int(first)) if isinstance(first, int) and first > 0 else None
    last_iso = filetime_to_utc_iso(int(last)) if isinstance(last, int) and last > 0 else None
    minimum = usn.get("min_timestamp_filetime")
    maximum = usn.get("max_timestamp_filetime")
    return {
        "kind": "ntfs_logfile",
        "source_file": logfile_path.name,
        "size_bytes": (document.get("logfile") or {}).get("size_bytes"),
        "source_sha256": (document.get("logfile") or {}).get("sha256"),
        "parser_status": "completed",
        "log_version": ".".join(str(item) for item in parse.get("log_version", [])),
        "record_count": parse.get("record_count"),
        "lsn_first": parse.get("lsn_first"),
        "lsn_last": parse.get("lsn_last"),
        "restart_area_count": parse.get("restart_area_count"),
        "parse_error_count": parse.get("parse_error_count"),
        "records_truncated": bool(parse.get("records_truncated")),
        "embedded_usn_record_count": usn.get("record_count"),
        "first_usn": usn.get("first_usn"),
        "last_usn": usn.get("last_usn"),
        "first_timestamp": first_iso,
        "last_timestamp": last_iso,
        "window_complete": bool(first_iso and last_iso),
        "timestamp_order": (
            "monotonic"
            if first is not None and minimum == first and maximum == last
            else "non_monotonic"
            if first is not None
            else None
        ),
        "si_update_count": diagnostics.get("si_update_count"),
        "si_update_bound_count": diagnostics.get("bound_count"),
        "si_update_unbound_count": diagnostics.get("unbound_count"),
        "si_update_unbound_reasons": dict(diagnostics.get("unbound_reasons") or {}),
        "witnesses_withheld": diagnostics.get("witnesses_withheld"),
        "page_coverage_complete": parse.get("page_coverage_complete"),
        "record_page_failure_count": parse.get("record_page_failure_count"),
        "unknown_page_count": parse.get("unknown_page_count"),
        "client_count": parse.get("client_count"),
        "multi_client": bool(parse.get("multi_client")),
        "lifecycle_record_count": parse.get("lifecycle_record_count"),
        "retention_basis": LOGFILE_RETENTION_BASIS,
    }


def _logfile_bound_updates(
    document: dict[str, Any],
    *,
    raw_mft_path: Path | None,
    mft_context: dict[str, Any] | None,
    include_timestamp_fragments: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if raw_mft_path is None or not raw_mft_path.is_file():
        return [], {
            "si_update_count": None,
            "bound_count": 0,
            "unbound_count": None,
            "unbound_reasons": {"raw_mft_unavailable": 1},
        }
    parse = document.get("parse") or {}
    withheld = (
        "record_parse_errors_or_unverified_count"
        if not _logfile_parse_error_free(document)
        else "records_truncated"
        if parse.get("records_truncated")
        else "page_coverage_incomplete"
        if parse.get("page_coverage_complete") is False
        else "multi_client_unsupported"
        if parse.get("multi_client")
        else None
    )
    if withheld is not None:
        return [], {
            "si_update_count": None,
            "bound_count": 0,
            "unbound_count": None,
            "unbound_reasons": {withheld: 1},
            "witnesses_withheld": withheld,
        }
    sequences = (mft_context or {}).get("entry_sequences")
    lifecycle = document.get("lifecycle_records")
    updates, diagnostics = si_updates_from_records(
        list(document.get("records") or []),
        mft_path=raw_mft_path,
        mft_entry_sequences=sequences if isinstance(sequences, dict) else None,
        lifecycle_records=list(lifecycle) if isinstance(lifecycle, list) else None,
        include_timestamp_fragments=include_timestamp_fragments,
    )
    return updates, {**diagnostics, "witnesses_withheld": None}


def logfile_tool_identity(document: dict[str, Any] | None, availability: dict[str, Any]) -> dict[str, Any]:
    identity = None
    if document is not None:
        identity = (document.get("runtime") or {}).get("tool_identity")
    if identity is None:
        identity = availability.get("tool_identity")
    if not isinstance(identity, dict):
        identity = {"name": "dfir_ntfs", "version": None}
    return {
        **identity,
        "source": "raw NTFS $LogFile collected by KAPE, parsed by the locked GPL-3 dfir_ntfs subprocess",
        "scope": "resident $STANDARD_INFORMATION timestamp updates bound to the collected $MFT",
        "availability": "available" if availability.get("available") else "unavailable",
    }


def logfile_si_update_observation(
    update: dict[str, Any],
    *,
    index: int,
    logfile_path: Path,
    mft_context: dict[str, Any] | None,
    observation_id_prefix: str,
    lsn_range: tuple[int | None, int | None],
) -> dict[str, Any]:
    file_name = preferred_file_name(list(update.get("file_names") or []))
    name = str((file_name or {}).get("name") or "<unknown>")
    parent_reference: tuple[int, int] | None = None
    if file_name and isinstance(file_name.get("parent_inode"), int) and isinstance(
        file_name.get("parent_sequence"), int
    ):
        parent_reference = (int(file_name["parent_inode"]), int(file_name["parent_sequence"]))
    subject = reconstruct_usn_subject(
        name=name, parent_reference=parent_reference, mft_context=mft_context
    )
    reference = (int(update["mft_entry"]), int(update["sequence_number"]))
    mft_fields = mft_active_presence_fields(
        subject=subject,
        file_reference=reference,
        mft_context=mft_context,
        exact_reference_required=True,
    )
    lsn_first, lsn_last = lsn_range
    record_lsn = int(update["record_lsn"])
    forgotten = update.get("transaction_forgotten_lsn")
    rolled_back = bool(update.get("transaction_rolled_back"))
    old = update.get("old") or {}
    new = update.get("new") or {}
    current = update.get("current_si") or {}
    fields: dict[str, Any] = {
        "lsn": int(update["lsn"]),
        "transaction_id": int(update["transaction_id"]),
        "transaction_forgotten_lsn": forgotten,
        "transaction_rolled_back": rolled_back,
        "transaction_committed": bool(forgotten is not None and not rolled_back),
        "redo_operation": "UpdateResidentValue",
        "mft_entry": reference[0],
        "sequence_number": reference[1],
        **ntfs_reference_fields(file_reference=reference, parent_reference=parent_reference),
        "record_in_use": bool(update.get("record_in_use")),
        "record_lsn": record_lsn,
        "record_lsn_retained": (
            bool(lsn_first <= record_lsn <= lsn_last)
            if isinstance(lsn_first, int) and isinstance(lsn_last, int)
            else None
        ),
        "record_size": int(update["record_size"]),
        "si_value_offset": int(update["si_value_offset"]),
        "offset_in_target": int(update["offset_in_target"]),
        "update_offset_in_si": int(update["update_offset_in_si"]),
        "update_length": int(update["update_length"]),
        "covered_fields": "|".join(str(item) for item in update.get("covered_fields") or []),
        **({"si_timestamp_fragments": update["si_timestamp_fragments"]}
           if "si_timestamp_fragments" in update else {}),
        "old_si_created": old.get("created"),
        "new_si_created": new.get("created"),
        "old_si_modified": old.get("modified"),
        "new_si_modified": new.get("modified"),
        "old_si_record_changed": old.get("record_changed"),
        "new_si_record_changed": new.get("record_changed"),
        "old_si_accessed": old.get("accessed"),
        "new_si_accessed": new.get("accessed"),
        "current_si_created": current.get("created"),
        "current_si_modified": current.get("modified"),
        "current_si_record_changed": current.get("metadata_changed"),
        "current_si_accessed": current.get("accessed"),
        "name": name,
        "reconstructed_path": subject,
        "binding_basis": "current_mft_record",
        "candidate_score": user_path_score(subject),
        **mft_fields,
    }
    return {
        "observation_id": f"{observation_id_prefix}:{index:06d}",
        "artifact_family": "ntfs.logfile",
        "observation_type": "logfile_si_update",
        "subject_ref": subject,
        "fields": fields,
        "source_record_ref": f"{logfile_path.name}:lsn={int(update['lsn'])}",
    }


def _logfile_parse_error_free(document: dict[str, Any]) -> bool:
    count = (document.get("parse") or {}).get("parse_error_count")
    return type(count) is int and count == 0


def _logfile_parse_complete(document: dict[str, Any]) -> bool:
    parse = document.get("parse") or {}
    return (
        _logfile_parse_error_free(document)
        and not parse.get("records_truncated")
        and parse.get("page_coverage_complete") is not False
        and not parse.get("multi_client")
    )


def raw_logfile_parser_run(
    *,
    logfile_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    raw_mft_path: Path | None = None,
    mft_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    document, availability = _logfile_document(
        logfile_path, normalized_output_dir=normalized_output_dir
    )
    diagnostics: dict[str, Any] = {}
    if document is not None:
        _updates, diagnostics = _logfile_bound_updates(
            document, raw_mft_path=raw_mft_path, mft_context=mft_context
        )
        scope = logfile_coverage_scope(document, logfile_path=logfile_path, diagnostics=diagnostics)
        coverage_status = "complete" if _logfile_parse_complete(document) else "partial"
    else:
        scope = logfile_unavailable_scope(logfile_path, reason=availability.get("reason"))
        coverage_status = "partial"
    normalized_output = normalized_output_path(
        normalized_output_dir, logfile_path, "raw_logfile_scope.json"
    )
    write_json(
        normalized_output,
        {
            "schema_version": "parser_observation_index.v1",
            "parser": "dfir_ntfs",
            "parser_kind": "ntfs_logfile",
            "source": str(logfile_path),
            "record_count": 0,
            "observations": [],
            "coverage_scope": scope,
            "driver_summary": (
                {
                    "parse": document.get("parse"),
                    "operation_counts": document.get("operation_counts"),
                    "restart_area_count": len(document.get("restart_areas") or []),
                    "embedded_usn": document.get("embedded_usn"),
                }
                if document is not None
                else None
            ),
            "si_update_diagnostics": diagnostics,
            "local_diagnostics": {
                "availability_reason": availability.get("reason"),
                "availability_detail": availability.get("detail"),
            },
            "truth_sources_used": [],
        },
    )
    raw_outputs = [logfile_path]
    if raw_mft_path is not None and raw_mft_path.is_file():
        raw_outputs.append(raw_mft_path)
    return normalize_parser_output(
        parser="dfir_ntfs",
        parser_kind="ntfs_logfile",
        source_collector=str(collector_run["collector"]),
        source_module="$LogFile",
        raw_outputs=raw_outputs,
        normalized_output=normalized_output,
        observations=[],
        command_line=(document.get("runtime") or {}).get("command_line") if document else None,
        tool_identity=logfile_tool_identity(document, availability),
        observation_families=[],
        coverage_status=coverage_status,
        coverage_scope=scope,
    )


def raw_logfile_reference_parser_run(
    *,
    logfile_path: Path,
    raw_mft_path: Path | None,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    references: set[tuple[int, int]],
    filesystem_scope_id: str,
    mft_context: dict[str, Any] | None = None,
    include_timestamp_fragments: bool = False,
) -> dict[str, Any]:
    if not filesystem_scope_id:
        raise ValueError("reference-scoped $LogFile analysis requires a filesystem scope")
    if (
        not isinstance(mft_context, dict)
        or mft_context.get("mft_volume_id") != filesystem_scope_id
    ):
        raise ValueError("reference-scoped $LogFile filesystem scope does not match MFT")
    for entry, sequence in references:
        if not (0 <= entry <= NTFS_FILE_REFERENCE_ENTRY_MASK and 0 <= sequence <= 0xFFFF):
            raise ValueError("NTFS file reference is invalid")
    size_bytes = logfile_path.stat().st_size
    reference_sha256 = ntfs_reference_set_sha256(references)
    document, availability = _logfile_document(
        logfile_path, normalized_output_dir=normalized_output_dir
    )
    observations: list[dict[str, Any]] = []
    matched: list[dict[str, Any]] = []
    diagnostics: dict[str, Any] = {}
    if document is not None:
        updates, diagnostics = _logfile_bound_updates(
            document, raw_mft_path=raw_mft_path, mft_context=mft_context,
            include_timestamp_fragments=include_timestamp_fragments,
        )
        matched = [
            item
            for item in updates
            if (int(item["mft_entry"]), int(item["sequence_number"])) in references
        ]
        parse = document.get("parse") or {}
        lsn_range = (parse.get("lsn_first"), parse.get("lsn_last"))
        observations = [
            logfile_si_update_observation(
                item,
                index=index,
                logfile_path=logfile_path,
                mft_context=mft_context,
                observation_id_prefix=f"obs:fmb-reference-logfile:{reference_sha256}",
                lsn_range=lsn_range,
            )
            for index, item in enumerate(matched, start=1)
        ]
        observations = source_bound_observations(observations, logfile_path)
        scope = logfile_coverage_scope(document, logfile_path=logfile_path, diagnostics=diagnostics)
        complete = _logfile_parse_complete(document) and raw_mft_path is not None
    else:
        scope = logfile_unavailable_scope(logfile_path, reason=availability.get("reason"))
        complete = False
    selection_scope = {
        "kind": "ntfs_file_references",
        "filesystem_scope_id": filesystem_scope_id,
        "reference_count": len(references),
        "reference_sha256": reference_sha256,
        "matched_record_count": len(matched),
        "retained_record_count": len(matched),
        "normalized_record_count": len(observations),
        "source_size_bytes": size_bytes,
        "source_bytes_covered": size_bytes if complete else 0,
        "status": "complete" if complete else "partial",
    }
    normalized_output = write_observation_index(
        normalized_output_dir=normalized_output_dir,
        raw_output=logfile_path,
        file_suffix=f"reference_logfile_observations.{reference_sha256}.json",
        parser="dfir_ntfs",
        parser_kind="ntfs_logfile",
        observations=observations,
        extra={
            "selection_scope": selection_scope,
            "coverage_scope": scope,
            "si_update_diagnostics": diagnostics,
            "local_diagnostics": {
                "availability_reason": availability.get("reason"),
                "availability_detail": availability.get("detail"),
            },
        },
    )
    raw_outputs = [logfile_path]
    if raw_mft_path is not None and raw_mft_path.is_file():
        raw_outputs.append(raw_mft_path)
    parser_run = normalize_parser_output(
        parser="dfir_ntfs",
        parser_kind="ntfs_logfile",
        source_collector=str(collector_run["collector"]),
        source_module="$LogFile#reference-scope",
        raw_outputs=raw_outputs,
        normalized_output=normalized_output,
        observations=observations,
        command_line=(document.get("runtime") or {}).get("command_line") if document else None,
        tool_identity={
            **logfile_tool_identity(document, availability),
            "scope": "ntfs_file_references",
        },
        observation_families=observed_artifact_families(observations),
        coverage_status="complete" if complete else "partial",
        coverage_scope=scope,
    )
    parser_run["selection_scope"] = selection_scope
    return parser_run
