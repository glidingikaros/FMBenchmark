from __future__ import annotations

from itertools import pairwise
from pathlib import Path
from typing import Any

from fmb.core.hashing import sha256_text
from fmb.index.adapters.parser_output import parser_run_from_observations
from fmb.index.scanners.evtx_sequence import retained_record_ids
from fmb.index.support.windows_artifacts import (
    csv_files_with_tokens,
    csv_has_required_headers,
    first_nonempty,
    native_row_fields,
    parse_int,
    row_first,
    stream_csv_rows,
)

MAX_EVTXECMD_OBSERVATIONS = 5000

MAX_EVTXECMD_RECORD_IDS = 500000

MAX_RAW_SECURITY_EVTX_BYTES = 512 * 1024 * 1024


def evtxecmd_csv_files(root: Path) -> list[Path]:
    return csv_files_with_tokens(
        root, include_any=("evtxecmd",), exclude_any=("timeline",)
    )


def evtxecmd_row_record_fields(
    row: dict[str, str],
) -> tuple[int | None, int | None, str, str]:
    event_id = parse_int(row_first(row, "EventId", "EventID", "Event ID"))
    record_id = parse_int(
        row_first(row, "EventRecordId", "EventRecordID", "RecordNumber", "Record ID")
    )
    channel = first_nonempty(
        row_first(row, "Channel", "LogName", "EventLog"), "unknown"
    )
    source_file = row_first(row, "SourceFile", "Source File")
    return event_id, record_id, channel, source_file


def event_log_scope_id(channel: str, source_file: str, csv_path: Path) -> str:
    source = source_file.strip() or csv_path.name
    normalized_source = source.replace("/", "\\").casefold()
    normalized = f"{channel.strip().casefold()}|{normalized_source}"
    return f"event-log:{sha256_text(normalized)[:24]}"


def evtxecmd_security_clear_observation(
    *,
    csv_path: Path,
    row_index: int,
    row: dict[str, str],
    event_id: int | None,
    record_id: int | None,
    channel: str,
    source_file: str,
) -> dict[str, Any] | None:
    if event_id != 1102:
        return None
    folded_channel = channel.casefold()
    folded_source = source_file.replace("/", "\\").casefold()
    if folded_channel != "security" and "\\security.evtx" not in folded_source:
        return None
    return {
        "observation_id": f"obs:evtxecmd:1102:{row_index:06d}",
        "artifact_family": "windows.event_log.security",
        "observation_type": "event_id_1102",
        "subject_ref": channel,
        "fields": {
            "event_id": event_id,
            "event_record_id": record_id,
            "channel": channel,
            "timestamp": row_first(row, "TimeCreated", "Timestamp", "Date"),
            **native_row_fields(
                row,
                {
                    "time_created": ("TimeCreated", "Timestamp", "Date"),
                    "computer": ("Computer", "ComputerName"),
                    "user_id": ("UserId", "UserID"),
                    "process_id": ("ProcessId", "ProcessID"),
                    "thread_id": ("ThreadId", "ThreadID"),
                    "level": ("Level",),
                },
            ),
            "provider": row_first(row, "Provider", "ProviderName"),
            "source_file": source_file,
            "event_log_scope_id": event_log_scope_id(channel, source_file, csv_path),
            "row_index": row_index,
        },
        "source_record_ref": f"{csv_path.name}:row={row_index}",
    }


def evtxecmd_gap_observations(
    *,
    csv_path: Path,
    event_records: dict[tuple[str, str], list[tuple[int, int]]],
    scope_labels: dict[tuple[str, str], tuple[str, str]] | None = None,
    limit: int = MAX_EVTXECMD_OBSERVATIONS,
) -> list[dict[str, Any]]:
    observations = []
    for scope, records in event_records.items():
        channel, source_file = (scope_labels or {}).get(scope, scope)
        ordered = sorted(records)
        for (previous_record_id, _), (next_record_id, next_row_index) in pairwise(
            ordered
        ):
            if next_record_id <= previous_record_id + 1:
                continue
            if len(observations) >= limit:
                return observations
            observations.append(
                {
                    "observation_id": f"obs:evtxecmd:gap:{next_row_index:06d}",
                    "artifact_family": "windows.event_log.record_sequence",
                    "observation_type": "event_record_id_gap",
                    "subject_ref": channel,
                    "fields": {
                        "channel": channel,
                        "previous_record_id": previous_record_id,
                        "next_record_id": next_record_id,
                        "gap_size": next_record_id - previous_record_id - 1,
                        "source_file": source_file,
                        "event_log_scope_id": event_log_scope_id(
                            channel, source_file, csv_path
                        ),
                        "row_index": next_row_index,
                    },
                    "source_record_ref": f"{csv_path.name}:row={next_row_index}",
                }
            )
    return observations


def collected_security_evtx_paths(collector_run: dict[str, Any]) -> list[Path]:
    paths: list[Path] = []
    output_root = Path(str(collector_run.get("output_root") or ""))
    for artifact in collector_run.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        raw_path = artifact.get("path")
        if isinstance(raw_path, str) and raw_path:
            path = Path(raw_path)
        else:
            relative_path = artifact.get("relative_path")
            if not isinstance(relative_path, str) or not relative_path:
                continue
            path = output_root / relative_path
        if path.name.casefold() != "security.evtx" or not path.is_file():
            continue
        paths.append(path)
    return sorted(set(paths))


def evtxecmd_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
) -> dict[str, Any]:
    observations = []
    retained_event_records: list[dict[str, Any]] = []
    event_records: dict[tuple[str, str], list[tuple[int, int]]] = {}
    event_scope_labels: dict[tuple[str, str], tuple[str, str]] = {}
    event_scope_rows: dict[tuple[str, str], int] = {}
    source_row_count = 0
    security_row_count = 0
    malformed_security_row_count = 0
    duplicate_record_id_count = 0
    record_id_overflow = False
    stored_record_id_count = 0
    candidate_count = 0
    seen_record_ids: dict[tuple[str, str], set[int]] = {}
    service_event_counts = {1100: 0, 1101: 0, 1104: 0, 1105: 0}
    first_time_created: str | None = None
    last_time_created: str | None = None
    for row_index, row in enumerate(stream_csv_rows(csv_path), start=1):
        source_row_count = row_index
        event_id, record_id, channel, source_file = evtxecmd_row_record_fields(row)
        normalized_source = source_file.replace("/", "\\").strip().casefold()
        is_security = (
            channel.strip().casefold() == "security"
            or normalized_source.endswith("\\security.evtx")
        )
        if not is_security:
            continue
        security_row_count += 1
        if event_id in service_event_counts:
            service_event_counts[event_id] += 1
        time_created = row_first(row, "TimeCreated", "Timestamp", "Date")
        if time_created:
            if first_time_created is None or time_created < first_time_created:
                first_time_created = time_created
            if last_time_created is None or time_created > last_time_created:
                last_time_created = time_created
        scope = (channel.strip().casefold(), normalized_source)
        valid_event_id = event_id is not None and 0 <= event_id <= 0xFFFFFFFF
        valid_record_id = record_id is not None and 0 <= record_id < (1 << 64)
        if len(retained_event_records) < MAX_EVTXECMD_RECORD_IDS:
            retained_event_records.append({
                "event_id": event_id,
                "event_record_id": record_id,
                "channel": channel,
                "time_created": time_created,
                "provider": row_first(row, "Provider", "ProviderName"),
                "source_file": source_file,
                "source_record_ref": f"{csv_path.name}:row={row_index}",
            })
        if not valid_event_id or not valid_record_id or not normalized_source:
            malformed_security_row_count += 1
        elif stored_record_id_count >= MAX_EVTXECMD_RECORD_IDS:
            record_id_overflow = True
        else:
            event_scope_labels.setdefault(scope, (channel, source_file))
            event_scope_rows.setdefault(scope, row_index)
            scoped_ids = seen_record_ids.setdefault(scope, set())
            if record_id in scoped_ids:
                duplicate_record_id_count += 1
            else:
                scoped_ids.add(record_id)
                stored_record_id_count += 1
                event_records.setdefault(scope, []).append((record_id, row_index))
        observation = evtxecmd_security_clear_observation(
            csv_path=csv_path,
            row_index=row_index,
            row=row,
            event_id=event_id,
            record_id=record_id,
            channel=channel,
            source_file=source_file,
        )
        if observation is not None:
            candidate_count += 1
            if len(observations) < MAX_EVTXECMD_OBSERVATIONS:
                observations.append(observation)
    scope_observations = [
        {
            "observation_id": f"obs:evtxecmd:scope:{event_scope_rows[scope]:06d}",
            "artifact_family": "windows.event_log.record_sequence",
            "observation_type": "event_log_scope_seen",
            "subject_ref": event_scope_labels[scope][0],
            "fields": {
                "channel": event_scope_labels[scope][0],
                "source_file": event_scope_labels[scope][1],
                "event_log_scope_id": event_log_scope_id(
                    *event_scope_labels[scope],
                    csv_path,
                ),
                "row_index": event_scope_rows[scope],
            },
            "source_record_ref": (
                f"{csv_path.name}:row={event_scope_rows[scope]}"
            ),
        }
        for scope in sorted(event_records)
    ]
    finding_observation_limit = max(
        0,
        MAX_EVTXECMD_OBSERVATIONS - len(scope_observations),
    )
    observations = [
        *scope_observations[:MAX_EVTXECMD_OBSERVATIONS],
        *observations[:finding_observation_limit],
    ]
    gap_observations = evtxecmd_gap_observations(
        csv_path=csv_path,
        event_records=event_records,
        scope_labels=event_scope_labels,
        limit=max(0, MAX_EVTXECMD_OBSERVATIONS - len(observations)),
    )
    observations.extend(gap_observations)
    total_gap_count = sum(
        1
        for records in event_records.values()
        for (previous, _), (current, _) in pairwise(sorted(records))
        if current > previous + 1
    )
    observation_overflow = bool(
        len(scope_observations) + candidate_count + total_gap_count
        > MAX_EVTXECMD_OBSERVATIONS
    )
    security_paths = collected_security_evtx_paths(collector_run)
    projected_record_ids = {
        record_id for values in seen_record_ids.values() for record_id in values
    }
    projected_scope = next(iter(seen_record_ids), None)
    security_scope_bound = bool(
        projected_scope is not None
        and len(seen_record_ids) == 1
        and projected_scope[0] == "security"
        and (
            projected_scope[1] == "security.evtx"
            or projected_scope[1].endswith("\\security.evtx")
        )
    )
    retained_ids = None
    if len(security_paths) == 1 and security_paths[0].stat().st_size <= MAX_RAW_SECURITY_EVTX_BYTES:
        try:
            retained_ids = retained_record_ids(security_paths[0].read_bytes())
        except (OSError, ValueError):
            pass
    projection_proven = bool(
        retained_ids is not None
        and security_scope_bound
        and set(retained_ids) == projected_record_ids
        and len(retained_ids) == len(projected_record_ids)
    )
    contract_evaluable = csv_has_required_headers(
        csv_path,
        ("EventId", "EventID", "Event ID"),
        (
            "EventRecordId",
            "EventRecordID",
            "RecordNumber",
            "Record ID",
        ),
        ("Channel", "LogName", "EventLog"),
        ("SourceFile", "Source File"),
    )
    coverage_complete = bool(
        contract_evaluable
        and source_row_count
        and security_row_count
        and malformed_security_row_count == 0
        and duplicate_record_id_count == 0
        and not record_id_overflow
        and not observation_overflow
        and projection_proven
    )
    coverage_status = "complete" if coverage_complete else "partial"
    native_sequence_complete = coverage_complete
    for item in scope_observations:
        fields = item["fields"]
        scope = (fields["channel"].strip().casefold(), fields["source_file"].replace("/", "\\").strip().casefold())
        identifiers = sorted(seen_record_ids[scope])
        missing_counts = [b - a - 1 for a, b in pairwise(identifiers) if b > a + 1]
        fields.update({
            "first_event_record_id": identifiers[0],
            "last_event_record_id": identifiers[-1],
            "record_count": len(identifiers),
            "internal_gap_count": len(missing_counts),
            "missing_internal_record_count": sum(missing_counts),
            "native_record_projection_complete": native_sequence_complete,
            "duplicate_record_id_count": duplicate_record_id_count,
            "malformed_record_count": malformed_security_row_count,
            "collection_scope": "complete_retained_native_log" if native_sequence_complete else "unverified_projection",
            "retention_scope": "retained_interval_only_prior_overwrite_history_unknown",
            "retained_event_records": [
                row for row in retained_event_records
                if row["channel"].strip().casefold() == scope[0]
                and row["source_file"].replace("/", "\\").strip().casefold() == scope[1]
            ],
            "retained_event_records_complete": (
                coverage_complete and len(retained_event_records) == security_row_count
            ),
            "eventlog_service_stopped_count": service_event_counts[1100],
            "audit_events_dropped_count": service_event_counts[1101],
            "log_full_count": service_event_counts[1104],
            "log_auto_backup_count": service_event_counts[1105],
        })
    security_scope_fields = next(
        (item["fields"] for item in scope_observations), {}
    )
    return parser_run_from_observations(
        parser="EvtxECmd",
        parser_kind="windows_evtx_security",
        source_module="EvtxECmd",
        command_needles=("evtxecmd",),
        normalized_suffix="evtx",
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        raw_output=csv_path,
        observations=observations,
        coverage_status=coverage_status,
        additional_raw_outputs=security_paths,
        coverage_scope={
            "kind": "security_event_log",
            "source_file": csv_path.name,
            "first_record_id": security_scope_fields.get("first_event_record_id"),
            "last_record_id": security_scope_fields.get("last_event_record_id"),
            "record_count": security_scope_fields.get("record_count", security_row_count),
            "first_time_created": first_time_created,
            "last_time_created": last_time_created,
            "native_record_projection_complete": native_sequence_complete,
            "eventlog_service_stopped_count": service_event_counts[1100],
            "audit_events_dropped_count": service_event_counts[1101],
            "log_full_count": service_event_counts[1104],
            "log_auto_backup_count": service_event_counts[1105],
            "window_complete": bool(first_time_created and last_time_created),
            "retention_basis": (
                "retained Security log interval only; records overwritten or "
                "cleared before the first retained record are unknown"
            ),
        },
    )
