from __future__ import annotations

from itertools import pairwise
from pathlib import Path
from typing import Any

from fmb.core.coercion import parse_integral_int
from fmb.core.json_io import write_json
from fmb.index.adapters.mft import (
    mft_active_presence_fields,
    reconstruct_usn_subject,
)
from fmb.index.adapters.parser_output import (
    RankedObservation,
    collector_output_root,
    keep_ranked_observation,
    module_command_line,
    normalized_output_path,
    observed_artifact_families,
    ranked_observations,
    source_bound_observations,
    write_observation_index,
)
from fmb.index.contract.evidence_index import normalize_parser_output
from fmb.index.scanners.usn import (
    USN_REASON_SCANNER,
    parse_usn_max,
    scan_usn_records_by_reason,
    scan_usn_records_for_references,
    usn_journal_timestamp_order,
    usn_journal_window,
)
from fmb.index.support.windows_artifacts import (
    canonical_mftecmd_timestamp,
    csv_has_required_headers,
    first_nonempty,
    parse_csv_timestamp,
    parse_int,
    row_first,
    row_recency_score,
    row_value,
    score_candidate_name,
    stream_csv_rows,
    user_path_score,
)
from fmb.index.support.windows_identity import (
    ntfs_reference_fields,
    ntfs_reference_from_row,
    split_ntfs_file_reference,
)

MAX_MFTECMD_USN_OBSERVATIONS = 5000

MAX_USN_ORDER_RECORDS = 500000


def usn_observation_type(update_reasons: str) -> str | None:
    folded = update_reasons.replace("_", "").casefold()
    if "filedelete" in folded:
        return "usn_file_delete"
    if "renameoldname" in folded:
        return "usn_rename_old_name"
    if "basicinfochange" in folded:
        return "usn_basic_info_change"
    if any(
        marker in folded
        for marker in (
            "filecreate",
            "dataextend",
            "dataoverwrite",
            "datatruncation",
            "rename new name",
            "renamenewname",
        )
    ):
        return "usn_filesystem_activity"
    return None


def usn_row_score(row: dict[str, str], *, purpose: str) -> int:
    name = first_nonempty(row.get("Name"), row.get("FullPath"), "")
    reasons = row.get("UpdateReasons", "").replace("_", "").casefold()
    score = row_recency_score(row, "UpdateTimestamp")
    score += score_candidate_name(name, purpose=purpose)
    if purpose == "usn_delete":
        if "filedelete" in reasons:
            score += 120
        if "renameoldname" in reasons:
            score += 90
        if "close" in reasons:
            score += 15
    elif purpose == "timestomp":
        if "basicinfochange" in reasons:
            score += 120
        if "filecreate" in reasons:
            score += 15
    if (
        "directory" in row.get("FileAttributes", "").casefold()
        and purpose == "usn_delete"
    ):
        score -= 20
    return score


def mftecmd_usn_csv_files(root: Path) -> list[Path]:
    return [
        path
        for path in sorted(root.rglob("*.csv"))
        if "mftecmd_$j" in str(path).replace("\\", "/").casefold()
    ]


def raw_usn_journal_files(root: Path) -> list[Path]:
    journals: list[Path] = []
    if not root.exists():
        return journals
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name != "$J":
            continue
        folded = str(path).replace("\\", "/").casefold()
        if "/$extend/$j" in folded or "/$usnjrnl/$j" in folded:
            journals.append(path)
    return journals


def mftecmd_usn_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    mft_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    candidates: list[RankedObservation] = []
    source_row_count = 0
    candidate_row_count = 0
    malformed_reference_count = 0
    contract_evaluable = csv_has_required_headers(
        csv_path,
        ("UpdateReasons", "Update Reasons"),
        ("Name", "FileName", "File Name", "FullPath", "Full Path"),
        ("EntryNumber", "Entry Number"),
        ("SequenceNumber", "Sequence Number"),
    )
    first_usn: int | None = None
    last_usn: int | None = None
    first_timestamp: str | None = None
    last_timestamp: str | None = None
    order_rows: dict[int, tuple[int, str]] = {}
    order_complete = True
    journal_sources: set[str] = set()
    journal_source_complete = True
    journal_source_cache: dict[str, Path | None] = {}
    for row_index, row in enumerate(stream_csv_rows(csv_path), start=1):
        source_row_count = row_index
        source = row_first(row, "SourceFile", "Source File")
        if source not in journal_source_cache and len(journal_source_cache) < 2:
            journal_source_cache[source] = collected_usn_journal_path(source, collector_run)
        journal_path = journal_source_cache.get(source)
        if journal_path is None:
            journal_source_complete = False
        else:
            journal_sources.add(str(journal_path))
        usn_value = parse_integral_int(row_first(row, "UpdateSequenceNumber", "Usn", "USN"))
        row_timestamp = canonical_mftecmd_timestamp(row.get("UpdateTimestamp", ""))
        stamp = parse_csv_timestamp(row_timestamp)
        if usn_value is None or usn_value < 0 or stamp is None or stamp.basis != "utc":
            order_complete = False
        elif usn_value in order_rows:
            if order_rows[usn_value][0] != stamp.ticks_100ns:
                order_complete = False
        elif len(order_rows) >= MAX_USN_ORDER_RECORDS:
            order_complete = False
        else:
            order_rows[usn_value] = (stamp.ticks_100ns, row_timestamp)
        if usn_value is not None:
            if first_usn is None or usn_value < first_usn:
                first_usn, first_timestamp = usn_value, row_timestamp
            if last_usn is None or usn_value > last_usn:
                last_usn, last_timestamp = usn_value, row_timestamp
        built = mftecmd_usn_observation_from_row(
            csv_path=csv_path,
            row_index=row_index,
            row=row,
            mft_context=mft_context,
        )
        if built is None:
            continue
        score, observation = built
        fields = observation.get("fields", {})
        if not isinstance(fields, dict) or fields.get("file_reference_entry") is None:
            malformed_reference_count += 1
        candidate_row_count += 1
        keep_ranked_observation(
            candidates,
            score=score,
            row_index=row_index,
            observation=observation,
            limit=MAX_MFTECMD_USN_OBSERVATIONS,
        )

    observations = source_bound_observations(ranked_observations(candidates), csv_path)

    normalized_output = write_observation_index(
        normalized_output_dir=normalized_output_dir,
        raw_output=csv_path,
        file_suffix="usn_observations.json",
        parser="MFTECmd",
        parser_kind="ntfs_usn",
        observations=observations,
        extra={
            "source_row_count": source_row_count,
            "candidate_row_count": candidate_row_count,
            "max_observations": MAX_MFTECMD_USN_OBSERVATIONS,
        },
    )
    journal_path = (
        Path(next(iter(journal_sources)))
        if journal_source_complete and len(journal_sources) == 1 else None
    )
    minimum = _verified_usn_minimum(usn_max_scope(collector_run, journal_path=journal_path))
    ordered = sorted((usn, item[0]) for usn, item in order_rows.items())
    stale_count = 0
    if minimum is not None:
        stale_count = sum(usn < minimum for usn, _ in ordered)
        ordered = [(usn, ticks) for usn, ticks in ordered if usn >= minimum]
        first_usn, first_timestamp = (
            (ordered[0][0], order_rows[ordered[0][0]][1]) if ordered else (None, None)
        )
        last_usn, last_timestamp = (
            (ordered[-1][0], order_rows[ordered[-1][0]][1]) if ordered else (None, None)
        )
    reversals = [(right[0], left[1] - right[1]) for left, right in pairwise(ordered) if right[1] < left[1]]
    return normalize_parser_output(
        parser="MFTECmd",
        parser_kind="ntfs_usn",
        source_collector=str(collector_run["collector"]),
        source_module="MFTECmd_$J",
        raw_outputs=[csv_path],
        normalized_output=normalized_output,
        observations=observations,
        command_line=module_command_line(collector_run, "mftecmd", "$j"),
        tool_identity={
            "name": "MFTECmd",
            "version": None,
            "source": "KAPE module output",
        },
        observation_families=observed_artifact_families(observations),
        coverage_status=(
            "complete"
            if contract_evaluable
            and malformed_reference_count == 0
            and candidate_row_count <= MAX_MFTECMD_USN_OBSERVATIONS
            else "partial"
        ),
        coverage_scope=usn_journal_scope(
            first_usn=first_usn,
            first_timestamp=first_timestamp,
            last_usn=last_usn,
            last_timestamp=last_timestamp,
            record_count=source_row_count,
            source_file=csv_path.name,
            collector_run=collector_run,
            journal_path=journal_path,
        ) | {
            "order_checked": bool(order_complete and source_row_count > 0),
            "checked_record_count": len(ordered),
            "stale_head_record_count": stale_count,
            "timestamp_reversal_count": len(reversals),
            "first_reversal_usn": reversals[0][0] if reversals else None,
            "max_backward_seconds": max((ticks // 10_000_000 for _, ticks in reversals), default=0),
        },
    )


def mftecmd_usn_observation_from_row(
    *,
    csv_path: Path,
    row_index: int,
    row: dict[str, str],
    mft_context: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]] | None:
    observation_type = usn_observation_type(row.get("UpdateReasons", ""))
    if observation_type is None:
        return None
    purpose = (
        "timestomp" if observation_type == "usn_basic_info_change" else "usn_delete"
    )
    name = first_nonempty(row.get("Name"), row_value(row, "FileName"), "<unknown>")
    file_reference = ntfs_reference_from_row(
        row,
        entry_keys=("EntryNumber", "Entry Number"),
        sequence_keys=("SequenceNumber", "Sequence Number"),
    )
    parent_reference = ntfs_reference_from_row(
        row,
        entry_keys=("ParentEntryNumber", "Parent Entry Number"),
        sequence_keys=("ParentSequenceNumber", "Parent Sequence Number"),
    )
    subject = reconstruct_usn_subject(
        name=name,
        full_path=first_nonempty(row.get("FullPath"), row_value(row, "Full Path")),
        parent_path=first_nonempty(
            row.get("ParentPath"), row_value(row, "Parent Path")
        ),
        parent_reference=parent_reference,
        mft_context=mft_context,
    )
    score = usn_row_score(row, purpose=purpose) + user_path_score(subject)
    mft_fields = mft_active_presence_fields(
        subject=subject,
        file_reference=file_reference,
        mft_context=mft_context,
        exact_reference_required=True,
    )
    observation = {
        "observation_id": f"obs:mftecmd-usn:{row_index:06d}",
        "artifact_family": "ntfs.usn",
        "observation_type": observation_type,
        "subject_ref": subject,
        "fields": {
            "update_reasons": row.get("UpdateReasons", ""),
            "update_timestamp": canonical_mftecmd_timestamp(
                row.get("UpdateTimestamp", "")
            ),
            "file_attributes": row.get("FileAttributes", ""),
            "candidate_score": score,
            "row_index": row_index,
            "full_path": row.get("FullPath", ""),
            "reconstructed_path": subject,
            **(
                {"update_sequence_number": usn_number}
                if (usn_number := parse_int(row_first(row, "UpdateSequenceNumber", "Usn", "USN")))
                is not None
                else {}
            ),
            **ntfs_reference_fields(
                file_reference=file_reference,
                parent_reference=parent_reference,
            ),
            **mft_fields,
        },
        "source_record_ref": f"{csv_path.name}:row={row_index}",
    }
    return score, observation


def raw_usn_observation_type(record: dict[str, Any]) -> str | None:
    labels = {str(label) for label in record.get("reason_labels", [])}
    if "FILE_DELETE" in labels:
        return "usn_file_delete"
    if "RENAME_OLD_NAME" in labels:
        return "usn_rename_old_name"
    if "BASIC_INFO_CHANGE" in labels:
        return "usn_basic_info_change"
    if labels.intersection(
        {
            "FILE_CREATE",
            "DATA_EXTEND",
            "DATA_OVERWRITE",
            "DATA_TRUNCATION",
            "RENAME_NEW_NAME",
        }
    ):
        return "usn_filesystem_activity"
    return None


def raw_usn_journal_parser_run(
    *,
    journal_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    mft_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    size_bytes = journal_path.stat().st_size
    with journal_path.open("rb") as handle:

        def reader(offset: int, size: int) -> bytes:
            handle.seek(offset)
            return handle.read(size)

        records, scan = scan_usn_records_by_reason(reader, stream_size_bytes=size_bytes)

    observations: list[dict[str, Any]] = []
    for record_index, record in enumerate(records, start=1):
        observation = raw_usn_observation_from_record(
            journal_path=journal_path,
            record_index=record_index,
            record=record,
            scan_strategy=scan["scan_strategy"],
            mft_context=mft_context,
        )
        if observation is None:
            continue
        observations.append(observation)
    observations = source_bound_observations(observations, journal_path)

    normalized_output = normalized_output_path(
        normalized_output_dir,
        journal_path,
        "raw_usn_observations.json",
    )
    write_json(
        normalized_output,
        {
            "schema_version": "parser_observation_index.v1",
            "parser": USN_REASON_SCANNER["name"],
            "parser_kind": "ntfs_usn",
            "source": str(journal_path),
            "record_count": len(observations),
            "scan": scan,
            "observations": observations,
            "truth_sources_used": [],
        },
    )
    return normalize_parser_output(
        parser="fmb_bounded_parser",
        parser_kind="ntfs_usn",
        source_collector=str(collector_run["collector"]),
        source_module="$Extend\\$UsnJrnl:$J",
        raw_outputs=[journal_path],
        normalized_output=normalized_output,
        observations=observations,
        command_line=None,
        tool_identity={
            "name": USN_REASON_SCANNER["name"],
            "version": USN_REASON_SCANNER["version"],
            "source": "raw NTFS $UsnJrnl:$J collected by KAPE",
            "scope": USN_REASON_SCANNER["scope"],
        },
        observation_families=observed_artifact_families(observations),
        coverage_status=(
            "complete"
            if int(scan.get("interesting_record_count", -1) or 0)
            == int(scan.get("emitted_record_count", -2) or 0)
            and int(scan.get("bytes_scanned", 0) or 0) >= size_bytes
            and not scan.get("unsupported_record_count")
            else "partial"
        ),
        coverage_scope=raw_usn_journal_scope(journal_path, collector_run=collector_run),
    )


def raw_usn_journal_scope(journal_path: Path, *, collector_run: dict[str, Any]) -> dict[str, Any]:
    control = usn_max_scope(collector_run, journal_path=journal_path)
    minimum = _verified_usn_minimum(control)
    try:
        window = usn_journal_window(journal_path, minimum_usn=minimum)
    except (OSError, ValueError):
        window = {"first_usn": None, "first_timestamp": None, "last_usn": None, "last_timestamp": None}
    try:
        order = usn_journal_timestamp_order(journal_path, minimum_usn=minimum)
    except (OSError, ValueError):
        order = {"order_checked": False, "timestamp_reversal_count": 0}
    return usn_journal_scope(
        first_usn=window.get("first_usn"),
        first_timestamp=window.get("first_timestamp"),
        last_usn=window.get("last_usn"),
        last_timestamp=window.get("last_timestamp"),
        record_count=int(window.get("size_bytes") or 0),
        source_file=journal_path.name,
        collector_run=collector_run,
        journal_path=journal_path,
    ) | {
        "record_count_basis": "journal_bytes",
        "stale_head_record_count": int(window.get("stale_head_record_count") or 0),
        "order_checked": bool(order.get("order_checked")),
        "checked_record_count": int(order.get("checked_record_count") or 0),
        "timestamp_reversal_count": int(order.get("timestamp_reversal_count") or 0),
        "first_reversal_usn": order.get("first_reversal_usn"),
        "max_backward_seconds": int(order.get("max_backward_seconds") or 0),
    }


def raw_usn_reference_parser_run(
    *,
    journal_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    references: set[tuple[int, int]],
    filesystem_scope_id: str,
    mft_context: dict[str, Any] | None = None,
) -> dict[str, Any]:

    if not filesystem_scope_id:
        raise ValueError("reference-scoped USN analysis requires a filesystem scope")
    if (
        not isinstance(mft_context, dict)
        or mft_context.get("mft_volume_id") != filesystem_scope_id
    ):
        raise ValueError("reference-scoped USN filesystem scope does not match MFT")
    size_bytes = journal_path.stat().st_size
    with journal_path.open("rb") as handle:

        def reader(offset: int, size: int) -> bytes:
            handle.seek(offset)
            return handle.read(size)

        records, scan = scan_usn_records_for_references(
            reader,
            stream_size_bytes=size_bytes,
            references=references,
        )
    reference_sha256 = str(scan["reference_sha256"])
    observations: list[dict[str, Any]] = []
    for record_index, record in enumerate(records, start=1):
        observation = raw_usn_observation_from_record(
            journal_path=journal_path,
            record_index=record_index,
            record=record,
            scan_strategy=scan["scan_strategy"],
            mft_context=mft_context,
            observation_id_prefix=f"obs:fmb-reference-usn:{reference_sha256}",
            fallback_observation_type="usn_journal_record",
        )
        if observation is not None:
            observations.append(observation)
    observations = source_bound_observations(observations, journal_path)
    if len(observations) != len(records):
        raise ValueError("reference-scoped USN normalization dropped retained records")
    selection_scope = {
        "kind": "ntfs_file_references",
        "filesystem_scope_id": filesystem_scope_id,
        "reference_count": scan["reference_count"],
        "reference_sha256": scan["reference_sha256"],
        "matched_record_count": scan["matched_record_count"],
        "retained_record_count": scan["retained_record_count"],
        "normalized_record_count": len(observations),
        "source_size_bytes": size_bytes,
        "source_bytes_covered": scan["source_bytes_covered"],
        "status": scan["status"],
    }
    normalized_output = write_observation_index(
        normalized_output_dir=normalized_output_dir,
        raw_output=journal_path,
        file_suffix=f"reference_usn_observations.{reference_sha256}.json",
        parser="fmb_bounded_parser",
        parser_kind="ntfs_usn",
        observations=observations,
        extra={"selection_scope": selection_scope, "scan": scan},
    )
    parser_run = normalize_parser_output(
        parser="fmb_bounded_parser",
        parser_kind="ntfs_usn",
        source_collector=str(collector_run["collector"]),
        source_module="$Extend\\$UsnJrnl:$J#reference-scope",
        raw_outputs=[journal_path],
        normalized_output=normalized_output,
        observations=observations,
        command_line=None,
        tool_identity={
            "name": "fmb.usn.truth_blind_reference_scanner",
            "version": "0.1.0",
            "scope": scan["scan_strategy"],
        },
        observation_families=observed_artifact_families(observations),
        coverage_status="partial",
    )
    parser_run["selection_scope"] = selection_scope
    return parser_run


def raw_usn_observation_from_record(
    *,
    journal_path: Path,
    record_index: int,
    record: dict[str, Any],
    scan_strategy: Any,
    mft_context: dict[str, Any] | None = None,
    observation_id_prefix: str = "obs:fmb-raw-usn",
    fallback_observation_type: str | None = None,
) -> dict[str, Any] | None:
    observation_type = raw_usn_observation_type(record) or fallback_observation_type
    if observation_type is None:
        return None
    name = str(record.get("file_name") or "<unknown>")
    file_reference = split_ntfs_file_reference(
        parse_int(str(record.get("file_reference_number", "")))
    )
    parent_reference = split_ntfs_file_reference(
        parse_int(str(record.get("parent_file_reference_number", "")))
    )
    subject = reconstruct_usn_subject(
        name=name,
        parent_reference=parent_reference,
        mft_context=mft_context,
    )
    mft_fields = mft_active_presence_fields(
        subject=subject,
        file_reference=file_reference,
        mft_context=mft_context,
        exact_reference_required=True,
    )
    labels = [str(label) for label in record.get("reason_labels", [])]
    return {
        "observation_id": f"{observation_id_prefix}:{record_index:06d}",
        "artifact_family": "ntfs.usn",
        "observation_type": observation_type,
        "subject_ref": subject,
        "fields": {
            "update_reasons": "|".join(labels),
            "update_timestamp": str(record.get("timestamp_utc") or ""),
            "file_attributes": str(record.get("file_attributes") or ""),
            "candidate_score": int(record.get("candidate_score", 0) or 0)
            + user_path_score(subject),
            "record_offset": int(record.get("record_offset", 0) or 0),
            "update_sequence_number": int(record.get("usn", 0) or 0),
            "file_reference_number": int(record.get("file_reference_number", 0) or 0),
            "parent_file_reference_number": int(
                record.get("parent_file_reference_number", 0) or 0
            ),
            **ntfs_reference_fields(
                file_reference=file_reference,
                parent_reference=parent_reference,
            ),
            "reconstructed_path": subject,
            "scan_strategy": scan_strategy,
            **mft_fields,
        },
        "source_record_ref": f"{journal_path.name}:offset={record.get('record_offset')}",
    }


def collected_usn_journal_path(source: str | Path, collector_run: dict[str, Any]) -> Path | None:
    root = collector_output_root(collector_run)
    if root is None or not str(source):
        return None
    root = root.resolve()
    text = str(source).replace("\\", "/")
    parts = text.split("/")
    if any(part in {".", ".."} for part in parts):
        return None
    try:
        relative = Path(source).resolve().relative_to(root)
    except (OSError, ValueError):
        boundaries = [i for i in range(len(parts) - 1)
                      if parts[i].casefold() == "kape-output" and parts[i + 1].casefold() == "targets"]
        if len(boundaries) != 1:
            return None
        tail = parts[boundaries[0] + 1 :]
        if any(not part for part in tail):
            return None
        relative = Path(*tail)
    if (len(relative.parts) < 4 or relative.parts[0].casefold() != "targets"
            or relative.name != "$J" or relative.parent.name not in {"$Extend", "$UsnJrnl"}):
        return None
    path = root / relative
    try:
        resolved = path.resolve()
        if not resolved.is_relative_to(root) or not resolved.is_file():
            return None
    except OSError:
        return None
    return resolved


def usn_max_scope(collector_run: dict[str, Any], *, journal_path: Path | None = None) -> dict[str, Any]:
    journal = collected_usn_journal_path(journal_path, collector_run) if journal_path is not None else None
    if journal is None:
        return {}
    control = journal.parent / "$Max"
    if not control.is_file() or control.is_symlink():
        return {}
    try:
        decoded = parse_usn_max(control.read_bytes())
    except OSError:
        return {}
    if decoded is None:
        return {}
    root = collector_output_root(collector_run).resolve()
    return {**decoded, "max_record_source": control.relative_to(root).as_posix(),
            "journal_source": journal.relative_to(root).as_posix(),
            "control_identity_bound": True}


def _verified_usn_minimum(control: dict[str, Any]) -> int | None:
    if not (
        control.get("control_identity_bound") is True
        and type(control.get("lowest_valid_usn")) is int and control["lowest_valid_usn"] >= 0
        and type(control.get("journal_id")) is int and control["journal_id"] > 0
        and type(control.get("maximum_size")) is int and control["maximum_size"] > 0
        and type(control.get("allocation_delta")) is int and control["allocation_delta"] > 0
    ):
        return None
    return control["lowest_valid_usn"]


def usn_journal_scope(
    *,
    first_usn: int | None,
    first_timestamp: str | None,
    last_usn: int | None,
    last_timestamp: str | None,
    record_count: int,
    source_file: str,
    collector_run: dict[str, Any],
    journal_path: Path | None = None,
) -> dict[str, Any]:
    endpoints_present = bool(
        first_usn is not None and last_usn is not None and first_timestamp and last_timestamp
    )
    control = usn_max_scope(collector_run, journal_path=journal_path)
    lowest_valid = control.get("lowest_valid_usn")
    if not endpoints_present:
        validity = "endpoints_unavailable"
    elif not control:
        validity = "retained_records_without_control_record"
    elif _verified_usn_minimum(control) is None:
        validity = "invalid_control_record"
    elif last_usn is not None and lowest_valid > last_usn:
        validity = "all_records_below_lowest_valid_usn"
    elif first_usn is not None and lowest_valid > first_usn:
        validity = "head_records_below_lowest_valid_usn"
    else:
        validity = "retained_records_within_valid_range"
    window_complete = validity == "retained_records_within_valid_range"
    return {
        "kind": "usn_journal",
        "source_file": source_file,
        "record_count": record_count,
        "first_usn": first_usn,
        "first_timestamp": first_timestamp,
        "last_usn": last_usn,
        "last_timestamp": last_timestamp,
        "window_complete": window_complete,
        "window_validity": validity,
        "retention_basis": (
            "retained $J records only; earlier journal history is unknown"
        ),
        **control,
    }
