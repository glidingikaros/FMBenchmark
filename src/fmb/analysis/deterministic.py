from __future__ import annotations

import re
from dataclasses import dataclass
from collections.abc import Mapping
from typing import Any, Callable, TypeGuard

from fmb.analysis.domain import (
    AnalysisInput,
    CandidateSubject,
    Observation,
)
from fmb.analysis.inputs import (
    active_mft_presence_fact,
    coverage_status,
    i30_scan_surface_complete,
    is_typed_paths_fields,
    normalized_device_identity,
    normalized_subject_label,
    observation_object_id,
    setupapi_identity_lookup,
)
from fmb.index.support.windows_artifacts import ForensicTimestamp, parse_csv_timestamp
from fmb.index.support.windows_identity import is_absolute_local_windows_path

ANALYZER_VERSION = "7"
TICKS_PER_SECOND = 10_000_000
USN_BASIC_INFO_CHANGE_CORRELATION_WINDOW_TICKS = TICKS_PER_SECOND
SI_FN_BACKDATING_MINIMUM_TICKS = 60 * TICKS_PER_SECOND
LATE_BASIC_INFO_CHANGE_MINIMUM_TICKS = 60 * TICKS_PER_SECOND
MAX_UTC_OFFSET_TICKS = 14 * 3600 * TICKS_PER_SECOND
SETUPAPI_SECTION_SLACK_TICKS = 10 * 60 * TICKS_PER_SECOND


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason_code: str
    evidence_refs: tuple[str, ...]
    limitations: tuple[str, ...] = ()


Analyzer = Callable[[AnalysisInput, CandidateSubject], Decision]


def _candidate_observations(
    value: AnalysisInput, subject: CandidateSubject
) -> tuple[Observation, ...]:
    ids = set(subject.observation_ids)
    return tuple(item for item in value.observations if item.observation_id in ids)


def _same_entity_observations(
    value: AnalysisInput, subject: CandidateSubject
) -> tuple[Observation, ...]:
    canonical_name = subject.identity.get("canonical_name") or subject.identity.get(
        "path"
    )
    exact_object_id = subject.identity.get("object_id")
    matches: dict[str, Observation] = {}
    for item in value.observations:
        item_object_id = observation_object_id(item.fields, item.subject_ref)
        is_candidate_observation = item.observation_id in subject.observation_ids
        if exact_object_id is not None:
            same_entity = item_object_id == exact_object_id
            same_name = False
        else:
            same_entity = False
            same_name = bool(canonical_name) and (
                normalized_subject_label(item.subject_ref) == canonical_name
            )
        if is_candidate_observation or same_entity or same_name:
            matches[item.observation_id] = item
    return tuple(matches[key] for key in sorted(matches))


def _is_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _observation_is_bound(item: Observation, subject: CandidateSubject) -> bool:
    object_id = subject.identity.get("object_id")
    if object_id is not None:
        return observation_object_id(item.fields, item.subject_ref) == object_id
    name = subject.identity.get("canonical_name") or subject.identity.get("path")
    return bool(name) and normalized_subject_label(
        item.subject_ref
    ) == normalized_subject_label(name)


LOGFILE_TRANSITION_REASON = "coordinated_si_backdating_with_logged_si_transition"


def _logfile_si_updates(
    observations: tuple[Observation, ...], subject: CandidateSubject
) -> list[Observation]:
    return [
        item
        for item in observations
        if item.artifact_family == "ntfs.logfile"
        and item.observation_type == "logfile_si_update"
        and _observation_is_bound(item, subject)
    ]


def _logfile_si_transition(
    updates: list[Observation],
    *,
    si_created: ForensicTimestamp,
    si_modified: ForensicTimestamp,
    minimum_backdating_ticks: int = SI_FN_BACKDATING_MINIMUM_TICKS,
) -> tuple[Observation | None, tuple[str, ...]]:
    notes: list[str] = []
    transition: Observation | None = None
    for item in sorted(updates, key=lambda row: int(row.fields.get("lsn") or 0)):
        covered = {
            part for part in str(item.fields.get("covered_fields") or "").split("|") if part
        }
        lsn = item.fields.get("lsn")
        if not {"created", "modified"} <= covered:
            old_accessed = parse_csv_timestamp(item.fields.get("old_si_accessed"))
            if (
                "accessed" in covered
                and old_accessed is not None
                and old_accessed.basis == si_created.basis
                and old_accessed.ticks_100ns in {si_created.ticks_100ns, si_modified.ticks_100ns}
            ):
                notes.append(
                    "logfile_access_rewrite_from_backdated_value: the retained $LogFile "
                    f"records an ordinary last-access rewrite (LSN {lsn}) whose undo value "
                    "equals a current SI created or modified value; "
                    "reported without gating"
                )
            continue
        if item.fields.get("transaction_committed") is not True:
            notes.append(
                f"logfile_transition_uncommitted: the $LogFile update at LSN {lsn} that "
                "rewrote SI created and modified is not a forgotten (committed) "
                "transaction and is not used"
            )
            continue
        if item.fields.get("binding_basis") not in (None, "current_mft_record"):
            notes.append(
                f"logfile_transition_unbound: the $LogFile update at LSN {lsn} is not "
                "bound to the current file record and is not used"
            )
            continue
        old_created = parse_csv_timestamp(item.fields.get("old_si_created"))
        new_created = parse_csv_timestamp(item.fields.get("new_si_created"))
        old_modified = parse_csv_timestamp(item.fields.get("old_si_modified"))
        new_modified = parse_csv_timestamp(item.fields.get("new_si_modified"))
        stamps = (old_created, new_created, old_modified, new_modified)
        if any(stamp is None for stamp in stamps) or len(
            {stamp.basis for stamp in stamps if stamp is not None} | {si_created.basis}
        ) != 1:
            notes.append(
                f"logfile_transition_time_basis_incompatible: the $LogFile update at LSN "
                f"{lsn} carries timestamps that cannot be compared with the MFT record"
            )
            continue
        assert old_created and new_created and old_modified and new_modified
        if (
            old_created.ticks_100ns - new_created.ticks_100ns < minimum_backdating_ticks
            or old_modified.ticks_100ns - new_modified.ticks_100ns
            < minimum_backdating_ticks
        ):
            continue
        if (
            new_created.ticks_100ns != si_created.ticks_100ns
            or new_modified.ticks_100ns != si_modified.ticks_100ns
        ):
            notes.append(
                f"logfile_transition_superseded: the $LogFile update at LSN {lsn} "
                "backdated SI created and modified to values the object no longer "
                "carries; reported without gating"
            )
            continue
        old_change = parse_csv_timestamp(item.fields.get("old_si_record_changed"))
        new_change = parse_csv_timestamp(item.fields.get("new_si_record_changed"))
        if (
            old_change is not None
            and new_change is not None
            and old_change.basis == new_change.basis
            and new_change.ticks_100ns < old_change.ticks_100ns
        ):
            notes.append(
                f"logfile_record_change_backdated: the same $LogFile update (LSN {lsn}) "
                "also moved the SI record-change time backwards; its cause, including "
                "possible clock adjustment, remains unresolved"
            )
        if transition is None:
            transition = item
    return transition, tuple(dict.fromkeys(notes))


def _usn_reason(item: Observation, reason: str) -> bool:
    raw = item.fields.get("update_reasons")
    if not isinstance(raw, str):
        return False
    tokens = {
        re.sub(r"[^a-z]", "", token.casefold()) for token in re.split(r"[|,;]", raw)
    }
    return reason in tokens


def _absence_decision(
    value: AnalysisInput,
    subject: CandidateSubject,
    observations: tuple[Observation, ...],
    *,
    supported_reason: str,
    referenced_object: bool = False,
) -> Decision:
    refs = tuple(item.observation_id for item in observations)
    collection_status = coverage_status(value, "ntfs.mft")
    facts = [
        active_mft_presence_fact(
            item,
            subject,
            collection_status=collection_status,
            referenced_object=referenced_object,
        )
        for item in observations
    ]
    states = {fact["status"] for fact in facts}
    resolved = observations and "unresolved" not in states
    if resolved and states == {"absent"}:
        return Decision("supported", supported_reason, refs)
    if resolved and states == {"present"}:
        return Decision("not_supported", "active_mft_entry_present", refs)
    if states == {"absent", "present"}:
        return Decision(
            "indeterminate",
            "mixed_active_mft_states",
            refs,
            ("the same candidate has contradictory active-MFT states",),
        )
    return Decision(
        "indeterminate",
        "active_mft_absence_unavailable",
        refs,
        ("a complete active-MFT absence check is unavailable",),
    )


_GateRecord = tuple[Observation, ForensicTimestamp, ForensicTimestamp, ForensicTimestamp, ForensicTimestamp]
_MftRecord = tuple[Observation, ForensicTimestamp | None, ForensicTimestamp, ForensicTimestamp, ForensicTimestamp]


def _si_fn_gate(
    mft_records: list[Observation], refs: tuple[str, ...], minimum_backdating_ticks: int
) -> Decision | tuple[list[_GateRecord], list[_MftRecord], list[str], list[str]]:
    gate_records: list[_GateRecord] = []
    all_records: list[_MftRecord] = []
    access_notes: list[str] = []
    signature_notes: list[str] = []
    for item in mft_records:
        pairs = {
            field: (
                parse_csv_timestamp(item.fields.get(f"si_{field}")),
                parse_csv_timestamp(item.fields.get(f"fn_{field}")),
            )
            for field in ("created", "modified", "accessed")
        }
        if any(si is None or fn is None for si, fn in pairs.values()):
            return Decision(
                "indeterminate", "timestamp_delta_contract_unavailable", refs
            )
        parsed_pairs = {
            field: (si, fn)
            for field, (si, fn) in pairs.items()
            if si is not None and fn is not None
        }
        if len({time.basis for pair in parsed_pairs.values() for time in pair}) != 1:
            return Decision(
                "indeterminate", "timestamp_delta_contract_unavailable", refs
            )
        deltas = {
            field: fn.ticks_100ns - si.ticks_100ns
            for field, (si, fn) in parsed_pairs.items()
        }
        record_change = parse_csv_timestamp(item.fields.get("si_record_changed"))
        all_records.append(
            (item, record_change, parsed_pairs["created"][0], parsed_pairs["modified"][0], parsed_pairs["created"][1])
        )
        if (
            deltas["created"] < minimum_backdating_ticks
            or deltas["modified"] < minimum_backdating_ticks
        ):
            continue
        if record_change is None:
            return Decision("indeterminate", "timestamp_change_time_unavailable", refs)
        if record_change.basis != parsed_pairs["created"][0].basis:
            return Decision(
                "indeterminate", "basic_info_change_time_incompatible", refs
            )
        if deltas["created"] == deltas["modified"]:
            signature_notes.append(
                "shared_offset_pattern: SI created and modified share one "
                "offset relative to FN; this does not identify a tool or API call "
                "and is reported without gating"
            )
        whole_second_fields = [
            field
            for field in ("created", "modified")
            if parsed_pairs[field][0].ticks_100ns % TICKS_PER_SECOND == 0
        ]
        if whole_second_fields:
            signature_notes.append(
                "sub_second_zeros: SI " + " and ".join(whole_second_fields)
                + " carry a zero 100-ns fraction; ordinary programs can also write "
                "these values, and this is reported without gating"
            )
        if deltas["accessed"] != deltas["created"]:
            si_accessed = parsed_pairs["accessed"][0]
            relation = (
                "rewritten at or after the SI record-change time"
                if si_accessed.ticks_100ns >= record_change.ticks_100ns
                else "outside the coordinated backdating"
            )
            access_notes.append(
                "SI last-access does not share the coordinated offset ("
                f"{relation}); it is reported without gating the decision"
            )
        gate_records.append(
            (item, record_change, parsed_pairs["created"][0], parsed_pairs["modified"][0], parsed_pairs["created"][1])
        )
    return gate_records, all_records, access_notes, signature_notes


def _basic_info_change_entries(
    usn: list[Observation], gate_records: list[_GateRecord], refs: tuple[str, ...]
) -> Decision | list[tuple[Observation, ForensicTimestamp, int | None]]:
    usn_entries: list[tuple[Observation, ForensicTimestamp, int | None]] = []
    for item in usn:
        observed_at = parse_csv_timestamp(item.fields.get("update_timestamp"))
        if observed_at is None:
            return Decision(
                "indeterminate",
                "basic_info_change_time_unavailable",
                refs,
                ("a same-entity BasicInfoChange has no comparable timestamp",),
            )
        usn_number = item.fields.get("update_sequence_number")
        usn_entries.append((item, observed_at, usn_number if _is_int(usn_number) else None))
    if any(
        record_change.basis != observed_at.basis
        for _item, record_change, *_rest in gate_records
        for _usn_item, observed_at, _number in usn_entries
    ):
        return Decision(
            "indeterminate",
            "basic_info_change_time_incompatible",
            refs,
            (
                "the SI record-change and BasicInfoChange timestamps use "
                "incompatible comparison bases",
            ),
        )
    return usn_entries


def _later_basic_info_change(
    usn_records: list[Observation], gate_records: list[_GateRecord]
) -> tuple[bool, int | None]:
    journal_entries: list[tuple[Observation, ForensicTimestamp, int]] = []
    for item in usn_records:
        observed_at = parse_csv_timestamp(item.fields.get("update_timestamp"))
        usn_number = item.fields.get("update_sequence_number")
        if observed_at is None or not _is_int(usn_number):
            return False, None
        journal_entries.append((item, observed_at, int(usn_number)))
    if not journal_entries:
        return True, None
    last_item, last_at, _last_number = max(journal_entries, key=lambda row: row[2])
    gaps = [
        last_at.ticks_100ns - record_change.ticks_100ns
        for _record, record_change, *_rest in gate_records
        if record_change.basis == last_at.basis
    ]
    if not _usn_reason(last_item, "basicinfochange") or not gaps:
        return True, None
    return True, max(gaps)


def _usn_absence_decision(
    value: AnalysisInput, gate_records: list[_GateRecord], refs: tuple[str, ...]
) -> Decision:
    window = _usn_journal_window(value)
    if window is None:
        return Decision(
            "indeterminate",
            "usn_coverage_unavailable",
            refs,
            ("the retained USN journal window is not established, so a missing "
             "BasicInfoChange cannot be read as absence",),
        )
    first, last = window
    if any(
        not (first.ticks_100ns <= record_change.ticks_100ns <= last.ticks_100ns)
        for _record, record_change, *_rest in gate_records
    ):
        return Decision(
            "indeterminate",
            "usn_coverage_unavailable",
            refs,
            ("the SI record-change time lies outside the retained USN journal "
             "window, so the corroborating BasicInfoChange may have been "
             "overwritten",),
        )
    return Decision("not_supported", "temporal_basic_info_change_not_observed", refs)


def _timestamp(value: AnalysisInput, subject: CandidateSubject, *,
               minimum_backdating_ticks: int = SI_FN_BACKDATING_MINIMUM_TICKS,
               late_minimum_ticks: int = LATE_BASIC_INFO_CHANGE_MINIMUM_TICKS) -> Decision:
    observations = _same_entity_observations(value, subject)
    if not subject.identity.get("object_id"):
        return Decision(
            "indeterminate",
            "timestamp_entity_identity_unavailable",
            tuple(item.observation_id for item in observations),
            (
                "an exact NTFS volume, entry, and sequence identity is required "
                "to correlate MFT and USN timestamps",
            ),
        )
    mft_records = [
        item
        for item in observations
        if item.artifact_family == "ntfs.mft"
        and item.observation_type in {"mft_file_record", "si_fn_timestamp_difference"}
        and (item.observation_type == "mft_file_record" or "si_created" in item.fields)
    ]
    usn_records = [item for item in observations if item.artifact_family == "ntfs.usn"]
    logfile_updates = _logfile_si_updates(observations, subject)
    refs = tuple(
        sorted(
            {item.observation_id for item in (*mft_records, *usn_records, *logfile_updates)}
        )
    )
    if any(
        not _observation_is_bound(item, subject)
        for item in (*mft_records, *usn_records)
    ):
        return Decision("indeterminate", "timestamp_entity_identity_unavailable", refs)
    if any(
        item.observation_type == "usn_basic_info_change"
        and not _usn_reason(item, "basicinfochange")
        for item in usn_records
    ):
        return Decision(
            "indeterminate", "basic_info_change_record_contract_unavailable", refs
        )
    usn = [item for item in usn_records if _usn_reason(item, "basicinfochange")]
    if not mft_records:
        return Decision("indeterminate", "timestamp_delta_contract_unavailable", refs)
    gate = _si_fn_gate(mft_records, refs, minimum_backdating_ticks)
    if isinstance(gate, Decision):
        return gate
    gate_records, all_records, access_notes, signature_notes = gate
    logfile_transition: Observation | None = None
    logfile_notes: tuple[str, ...] = ()
    if logfile_updates:
        _item, _change, si_created_value, si_modified_value, _fn_created_value = (
            gate_records or all_records
        )[0]
        logfile_transition, logfile_notes = _logfile_si_transition(
            logfile_updates,
            si_created=si_created_value,
            si_modified=si_modified_value,
            minimum_backdating_ticks=minimum_backdating_ticks,
        )
    logfile_only = logfile_transition is not None and not gate_records
    if not gate_records and logfile_transition is None:
        return Decision("not_supported", "coordinated_si_backdating_not_observed", refs)
    if logfile_only:
        signature_notes.append(
            "si_fn_gate_not_met: the SI-versus-FN threshold predicate does not hold; "
            "the bound $LogFile update independently supplies the timestamp transition"
        )
    logfile_transition_note = (
        (
            "the retained $LogFile records the same-object $STANDARD_INFORMATION "
            f"update (LSN {logfile_transition.fields.get('lsn')}, transaction "
            f"{logfile_transition.fields.get('transaction_id')}, committed) whose undo "
            "values are the original created and modified times and whose redo "
            "values are the current backdated ones"
        )
        if logfile_transition is not None
        else None
    )
    usn_entries = _basic_info_change_entries(usn, gate_records, refs)
    if isinstance(usn_entries, Decision):
        return usn_entries
    notes = tuple(dict.fromkeys((*access_notes, *signature_notes, *logfile_notes,
        "timestamp_indicator_scope: these bounded measurements do not distinguish "
        "ordinary copying/restoration from anti-forensic purpose; USN BasicInfoChange "
        "alone does not prove which SI fields changed")))
    corroborated_notes = (
        (*notes, logfile_transition_note) if logfile_transition_note else notes
    )
    if gate_records:
        temporal = [
            (item, observed_at)
            for _record, record_change, *_rest in gate_records
            for item, observed_at, _number in usn_entries
            if 0
            <= observed_at.ticks_100ns - record_change.ticks_100ns
            < USN_BASIC_INFO_CHANGE_CORRELATION_WINDOW_TICKS
        ]
        if temporal:
            return Decision(
                "supported",
                "coordinated_si_backdating_with_temporal_basic_info_change",
                refs,
                corroborated_notes,
            )
        order_available, later_gap = _later_basic_info_change(usn_records, gate_records)
        if later_gap is not None and later_gap >= late_minimum_ticks:
            return Decision(
                "supported",
                "si_fn_backdating_with_later_basic_info_change",
                refs,
                (
                    *corroborated_notes,
                    "the highest retained same-object USN is a BasicInfoChange "
                    f"timestamped {later_gap // TICKS_PER_SECOND} seconds after SI "
                    "record-change; this does not prove that record-change was "
                    "rewritten or identify which fields the journal event changed",
                ),
            )
        if not order_available:
            notes = (
                *notes,
                "journal_order_unavailable: same-object USN records without update "
                "sequence numbers cannot establish the object's last journaled record, "
                "so the later-record indicator is not evaluated",
            )
            corroborated_notes = (
                (*notes, logfile_transition_note) if logfile_transition_note else notes
            )
    if logfile_transition is not None and logfile_transition_note is not None:
        return Decision(
            "supported",
            LOGFILE_TRANSITION_REASON,
            refs,
            (
                *notes,
                logfile_transition_note,
                "the $LogFile transition witnesses the backdating independently of "
                "the USN journal; restoration and anti-forensic purpose remain indistinguishable",
            ),
        )
    if not gate_records:
        return Decision("not_supported", "coordinated_si_backdating_not_observed", refs)
    return _usn_absence_decision(value, gate_records, refs)


def _coverage_scope(value: AnalysisInput, family: str) -> dict[str, Any] | None:
    for item in value.coverage:
        if item.artifact_family == family and isinstance(item.scope, Mapping):
            return dict(item.scope)
    return None


def _usn_journal_window(
    value: AnalysisInput,
) -> tuple[ForensicTimestamp, ForensicTimestamp] | None:
    scope = _coverage_scope(value, "ntfs.usn")
    if not scope or scope.get("kind") != "usn_journal" or not scope.get("window_complete"):
        return None
    if scope.get("identity_conflict") or int(scope.get("gap_count") or 0) > 0:
        return None
    if scope.get("window_validity") != "retained_records_within_valid_range":
        return None
    if (scope.get("control_identity_bound") is not True or scope.get("order_checked") is not True
            or type(scope.get("checked_record_count")) is not int or scope["checked_record_count"] <= 0
            or type(scope.get("timestamp_reversal_count")) is not int or scope["timestamp_reversal_count"] != 0):
        return None
    if not (
        type(scope.get("journal_id")) is int and scope["journal_id"] > 0
        and type(scope.get("lowest_valid_usn")) is int and scope["lowest_valid_usn"] >= 0
        and type(scope.get("first_usn")) is int
        and type(scope.get("last_usn")) is int
        and scope["lowest_valid_usn"] <= scope["first_usn"] <= scope["last_usn"]
    ):
        return None
    first = parse_csv_timestamp(scope.get("first_timestamp"))
    last = parse_csv_timestamp(scope.get("last_timestamp"))
    if first is None or last is None or first.basis != last.basis or first.ticks_100ns > last.ticks_100ns:
        return None
    return first, last


def _ads(value: AnalysisInput, subject: CandidateSubject, *, require_parser_verdict: bool = True,
         use_native_format_size_bounds: bool = False) -> Decision:
    observations = _candidate_observations(value, subject)
    streams = [item for item in observations if item.observation_type == "named_data_stream"]
    content = [item for item in observations if item.observation_type == "named_stream_content"]
    refs = tuple(item.observation_id for item in (*streams, *content))
    if not streams:
        return Decision("not_supported", "no_named_stream", refs)
    if any(not _observation_is_bound(item, subject) for item in (*streams, *content)):
        return Decision("indeterminate", "stream_host_identity_unavailable", refs)
    def name(item: Observation) -> str:
        return str(item.fields.get("stream_name") or "").strip().casefold()
    names = [name(item) for item in streams]
    contents = {name(item): item for item in content}
    if (not subject.identity.get("object_id") or any(not key for key in names)
            or len(set(names)) != len(names) or len(contents) != len(content)
            or set(contents) != set(names)):
        return Decision("indeterminate", "stream_content_inventory_unavailable", refs)
    executable_streams = []
    archive_streams = []
    for item in streams:
        fields = contents[name(item)].fields
        size = item.fields.get("stream_size")
        if not (_is_int(size) and size >= 0 and fields.get("content_complete") is True
                and fields.get("native_identity_verified") is True
                and fields.get("materialized_size") == size and fields.get("stream_size") == size
                and re.fullmatch(r"[a-f0-9]{64}", str(fields.get("content_sha256") or ""))):
            return Decision("indeterminate", "stream_native_content_unavailable", refs)
        if use_native_format_size_bounds and size < 22:
            continue
        if fields.get("zip_signature_hex") in {"504b0304", "504b0506"}:
            from fmb.analysis.structured_content import zip_content_evidence
            archive = zip_content_evidence(fields, size, require_parser_verdict=require_parser_verdict)
            if archive is None:
                return Decision("indeterminate", "stream_zip_structure_incomplete", refs)
            if archive:
                archive_streams.append(item)
        if fields.get("dos_signature_hex") != "4d5a":
            if not isinstance(fields.get("zip_signature_hex"), str) or (require_parser_verdict and fields.get("zip_structure_status") not in {"not_zip", "complete"}):
                return Decision("indeterminate", "stream_archive_format_unavailable", refs)
            continue
        if use_native_format_size_bounds and size < 64:
            continue
        if require_parser_verdict and fields.get("pe_structure_status") != "complete":
            return Decision("indeterminate", "stream_pe_structure_incomplete", refs)
        sections = fields.get("pe_sections")
        offset = fields.get("pe_header_offset")
        if use_native_format_size_bounds and not (
            fields.get("pe_signature_hex") == "50450000" and _is_int(offset) and 64 <= offset <= size - 24
        ):
            continue
        optional_size = fields.get("pe_optional_header_size")
        characteristics = fields.get("pe_characteristics")
        count = fields.get("pe_section_count")
        headers_size = fields.get("pe_size_of_headers")
        if not (fields.get("pe_signature_hex") == "50450000"
                and fields.get("pe_optional_magic") in {0x10b, 0x20b}
                and _is_int(offset) and 64 <= offset <= size - 24
                and _is_int(optional_size) and optional_size >= 64
                and _is_int(count) and 1 <= count <= 96
                and _is_int(headers_size) and offset + 24 + optional_size + count * 40 <= headers_size <= size
                and _is_int(characteristics)
                and isinstance(sections, (list, tuple)) and len(sections) == count):
            return Decision("indeterminate", "stream_pe_structure_incomplete", refs)
        for section in sections:
            if not hasattr(section, "get"):
                return Decision("indeterminate", "stream_pe_structure_incomplete", refs)
            length, start, flags = (section.get(key) for key in ("raw_size", "raw_offset", "characteristics"))
            if not (all(_is_int(number) and number >= 0 for number in (length, start, flags))
                    and (length == 0 or headers_size <= start < start + length <= size)):
                return Decision("indeterminate", "stream_pe_structure_incomplete", refs)
        if characteristics & 2 and any(section["raw_size"] > 0 and section["characteristics"] & 0x20000000
                                       for section in sections):
            executable_streams.append(item)
    if executable_streams:
        return Decision("supported", "named_stream_contains_pe_executable_structure", refs)
    if archive_streams:
        return Decision("supported", "named_stream_contains_zip_archive_structure", refs,
                        ("archive content does not establish concealment intent or unauthorized use",))
    return Decision("not_supported", "no_supported_format_named_stream_content", refs)


def _deleted_file(value: AnalysisInput, subject: CandidateSubject) -> Decision:
    observations = tuple(
        item
        for item in _same_entity_observations(value, subject)
        if item.artifact_family == "ntfs.usn"
    )
    if any(
        not _observation_is_bound(item, subject)
        or (
            item.observation_type == "usn_file_delete"
            and not _usn_reason(item, "filedelete")
        )
        for item in observations
    ):
        return Decision(
            "indeterminate",
            "usn_delete_record_contract_unavailable",
            tuple(item.observation_id for item in observations),
        )
    deletes = tuple(item for item in observations if _usn_reason(item, "filedelete"))
    if deletes:
        if not subject.identity.get("object_id"):
            return Decision(
                "indeterminate",
                "active_mft_absence_unavailable",
                tuple(item.observation_id for item in deletes),
            )
        return _absence_decision(
            value,
            subject,
            deletes,
            supported_reason="usn_delete_with_active_mft_absence",
        )
    if any(
        _usn_reason(item, "renameoldname")
        or item.observation_type == "usn_rename_old_name"
        for item in observations
    ):
        return Decision(
            "indeterminate",
            "rename_without_delete",
            tuple(item.observation_id for item in observations),
            ("rename residue alone does not establish deletion",),
        )
    return Decision("not_supported", "no_delete_residue", ())


def _typed_path_residue(value: AnalysisInput, subject: CandidateSubject) -> Decision:
    observations = tuple(
        item
        for item in _same_entity_observations(value, subject)
        if item.observation_type == "typed_path_seen"
    )
    if not observations:
        return Decision("not_supported", "no_path_residue", ())
    if not is_absolute_local_windows_path(subject.display_name):
        return Decision(
            "indeterminate",
            "typed_path_scope_unavailable",
            subject.observation_ids,
            ("an absolute local path is required",),
        )
    if any(
        not is_typed_paths_fields(item.fields)
        or not _observation_is_bound(item, subject)
        or (
            "value_data" in item.fields
            and (
                not isinstance(item.fields["value_data"], str)
                or normalized_subject_label(item.fields["value_data"])
                != normalized_subject_label(item.subject_ref)
            )
        )
        for item in observations
    ):
        return Decision(
            "indeterminate",
            "typed_path_record_contract_unavailable",
            tuple(item.observation_id for item in observations),
        )
    return _absence_decision(
        value,
        subject,
        observations,
        supported_reason="typed_path_residue_with_active_mft_absence",
    )


def _i30(value: AnalysisInput, subject: CandidateSubject) -> Decision:
    observations = _candidate_observations(value, subject)
    refs = tuple(item.observation_id for item in observations)
    scans = [
        item for item in observations if item.observation_type == "i30_directory_scan"
    ]
    i30_records = [
        item for item in observations if item.observation_type == "i30_filename_residue"
    ]
    states = {item.fields.get("i30_entry_state") for item in i30_records}
    if any(state not in {"live", "slack", "unlinked"} for state in states):
        return Decision(
            "indeterminate",
            "i30_state_contract_unavailable",
            refs,
            ("$I30 entry state is not explicitly live, slack, or unlinked",),
        )
    candidate_records = [
        item
        for item in i30_records
        if item.fields.get("i30_entry_state") in {"slack", "unlinked"}
    ]
    if scans:
        scan_contract_complete = len(scans) == 1 and all(
            (
                i30_scan_surface_complete(item.fields)
                and _observation_is_bound(item, subject)
                and _is_int(item.fields.get("sequence_number"))
                and item.fields["sequence_number"] > 0
                and _is_int(item.fields.get("residue_count"))
                and item.fields["residue_count"] >= 0
            )
            for item in scans
        )
        if not scan_contract_complete:
            return Decision(
                "indeterminate",
                "i30_scan_contract_unavailable",
                refs,
                ("the bounded directory-index scan is incomplete or ambiguous",),
            )
        if scans[0].fields["residue_count"] != len(candidate_records):
            return Decision(
                "indeterminate",
                "i30_scan_residue_count_mismatch",
                refs,
                ("the bounded scan count does not match its residue observations",),
            )
    if not candidate_records:
        if scans:
            return Decision(
                "not_supported",
                "i30_supported_surface_has_no_residue",
                refs,
            )
        if observations and all(
            item.fields.get("i30_entry_state") == "live" for item in observations
        ):
            return Decision("not_supported", "i30_entries_are_live", refs)
        return Decision(
            "indeterminate",
            "i30_state_contract_unavailable",
            refs,
            ("$I30 entry state is not explicitly live, slack, or unlinked",),
        )
    for item in candidate_records:
        entry = item.fields.get("file_reference_entry")
        sequence = item.fields.get("file_reference_sequence")
        if not _is_int(entry) or entry < 0 or not _is_int(sequence) or sequence <= 0:
            return Decision(
                "indeterminate",
                "i30_state_contract_unavailable",
                refs,
                ("$I30 file reference identity is unavailable",),
            )
    by_child: dict[tuple[int, int], list[Observation]] = {}
    for item in candidate_records:
        key = (item.fields["file_reference_entry"], item.fields["file_reference_sequence"])
        by_child.setdefault(key, []).append(item)
    for item in i30_records:
        key = (item.fields.get("file_reference_entry"), item.fields.get("file_reference_sequence"))
        if item.fields.get("i30_entry_state") == "live" and key in by_child:
            return Decision("indeterminate", "i30_live_and_residue_states_conflicting", refs)
    decisions = [_absence_decision(value, subject, tuple(items),
        supported_reason="i30_slack_or_unlinked_reference_absent_from_active_mft",
        referenced_object=True) for items in by_child.values()]
    if any(item.reason_code == "mixed_active_mft_states" for item in decisions):
        return Decision("indeterminate", "i30_child_identity_conflicting", refs)
    if any(item.outcome == "supported" for item in decisions):
        return Decision("supported", "i30_slack_or_unlinked_reference_absent_from_active_mft", refs)
    if any(item.outcome == "indeterminate" for item in decisions):
        return Decision("indeterminate", "active_mft_absence_unavailable", refs)
    return Decision("not_supported", "i30_residue_reference_still_active", refs)


def _shellbag(value: AnalysisInput, subject: CandidateSubject) -> Decision:
    records = tuple(item for item in _same_entity_observations(value, subject)
                    if item.observation_type == "shellbag_path_seen")
    refs = tuple(item.observation_id for item in records)
    if not records:
        return Decision("indeterminate", "shellbag_record_unavailable", refs)
    for item in records:
        fields = item.fields
        if not (
            _observation_is_bound(item, subject)
            and is_absolute_local_windows_path(item.subject_ref)
            and normalized_subject_label(str(fields.get("path") or ""))
            == normalized_subject_label(item.subject_ref)
            and str(fields.get("shell_type") or "").casefold() == "directory"
            and re.fullmatch(r"BagMRU(?:\\[0-9]+)*", str(fields.get("bag_path") or ""), re.I)
            and fields.get("source_parser") == "SBECmd"
            and fields.get("path_resolution_basis") in {
                "native_absolute_drive_path", "native_shell_reference_to_mft_directory",
                "native_shell_ancestry_to_mft_directory"
            }
            and item.source_record_ref
        ):
            return Decision("indeterminate", "shellbag_directory_contract_unavailable", refs)
    return _absence_decision(value, subject, records,
                             supported_reason="shellbag_directory_with_active_path_absence")


def _allocation(value: AnalysisInput, subject: CandidateSubject) -> Decision:
    records = tuple(item for item in _candidate_observations(value, subject)
                    if item.observation_type == "ntfs_allocation_record")
    refs = tuple(item.observation_id for item in records)
    if len(records) != 1 or not _observation_is_bound(records[0], subject):
        return Decision("indeterminate", "allocation_identity_or_record_unavailable", refs)
    fields = records[0].fields
    if not (fields.get("native_identity_verified") is True
            and fields.get("attribute_chain_complete") is True
            and fields.get("stream_name") == ""
            and all(isinstance(fields.get(key), bool)
                    for key in ("is_sparse", "is_compressed", "is_encrypted"))):
        return Decision("indeterminate", "allocation_storage_contract_unavailable", refs)
    if any(fields[key] for key in ("is_sparse", "is_compressed", "is_encrypted")):
        return Decision("indeterminate", "allocation_special_storage_not_assessed", refs)
    logical = fields.get("logical_size")
    if not _is_int(logical) or logical < 0:
        return Decision("indeterminate", "allocation_lengths_unavailable", refs)
    if fields.get("resident_status") == "resident":
        return Decision("not_supported", "resident_data_has_no_external_allocation", refs)
    cluster = fields.get("bytes_per_cluster")
    allocated, count = fields.get("allocated_size"), fields.get("allocated_cluster_count")
    if not (
        fields.get("resident_status") == "nonresident"
        and fields.get("geometry_source") == "native_ntfs_boot_sector"
        and _is_int(cluster) and cluster >= 512 and cluster & (cluster - 1) == 0
        and fields.get("runlist_complete") is True
        and fields.get("runlist_in_volume") is True
        and type(fields.get("runlist_physical_overlap")) is bool
        and fields.get("lowest_vcn") == 0
        and fields.get("sparse_cluster_count") == 0
        and _is_int(allocated) and allocated >= 0
        and _is_int(count) and count >= 0
    ):
        return Decision("indeterminate", "allocation_geometry_or_extents_unavailable", refs)
    if fields["runlist_physical_overlap"]:
        return Decision("supported", "ntfs_allocation_physical_runs_overlap", refs,
                        ("distinct logical extents reuse physical clusters; this metadata "
                         "inconsistency does not establish cause or intent",))
    mapped = count * cluster
    if allocated != mapped or logical > mapped or allocated % cluster:
        return Decision("supported", "ntfs_allocation_metadata_inconsistency", refs,
                        ("metadata inconsistency does not establish cropping, padding or intent",))
    return Decision("not_supported", "ordinary_allocation_consistent", refs)


def _file_size(value: AnalysisInput, subject: CandidateSubject) -> Decision:
    observations = _same_entity_observations(value, subject)
    storage = [
        item
        for item in observations
        if item.observation_type == "logical_allocated_size_record"
    ]
    content = [
        item
        for item in observations
        if item.observation_type == "materialized_file_content_record"
    ]
    refs = tuple(item.observation_id for item in (*storage, *content))
    if len(storage) != 1 or len(content) != 1:
        return Decision(
            "indeterminate",
            "file_content_allocation_contract_unavailable",
            refs,
            (
                "exactly one storage record and one materialized-content record are required",
            ),
        )
    storage_fields = storage[0].fields
    content_fields = content[0].fields
    storage_identity = observation_object_id(storage_fields, storage[0].subject_ref)
    content_identity = observation_object_id(content_fields, content[0].subject_ref)
    if (
        storage_identity is None
        or storage_identity != content_identity
        or storage_identity != subject.identity.get("object_id")
    ):
        return Decision(
            "indeterminate",
            "file_identity_join_unavailable",
            refs,
            ("storage and content records do not share an exact file identity",),
        )
    required_storage = {
        "resident_status",
        "attribute_flags",
        "attribute_parse_error_count",
        "is_sparse",
        "is_compressed",
        "is_encrypted",
        "mftecmd_identity_match",
        "attribute_chain_complete",
        "runlist_complete",
        "lowest_vcn",
        "stream_name",
        "logical_size",
        "mftecmd_file_size",
    }
    if any(key not in storage_fields for key in required_storage):
        return Decision(
            "indeterminate",
            "storage_contract_unavailable",
            refs,
            ("the base DATA stream storage contract is incomplete",),
        )
    resident_status = storage_fields.get("resident_status")
    attribute_flags = storage_fields.get("attribute_flags")
    parse_error_count = storage_fields.get("attribute_parse_error_count")
    storage_modes = tuple(
        storage_fields.get(key)
        for key in ("is_sparse", "is_compressed", "is_encrypted")
    )
    runlist_complete = storage_fields.get("runlist_complete")
    runlist_valid = (
        runlist_complete is True
        if resident_status == "nonresident"
        else runlist_complete is None or runlist_complete is True
    )
    if (
        resident_status not in {"resident", "nonresident"}
        or not _is_int(attribute_flags)
        or attribute_flags < 0
        or not _is_int(parse_error_count)
        or parse_error_count != 0
        or any(not isinstance(item, bool) for item in storage_modes)
        or storage_fields.get("stream_name") != ""
        or storage_fields.get("mftecmd_identity_match") is not True
        or storage_fields.get("attribute_chain_complete") is not True
        or not _is_int(storage_fields.get("lowest_vcn"))
        or storage_fields.get("lowest_vcn") != 0
        or not runlist_valid
        or attribute_flags & ~0xC001 != 0
        or bool(attribute_flags & 0x0001) != storage_fields["is_compressed"]
        or bool(attribute_flags & 0x4000) != storage_fields["is_encrypted"]
        or bool(attribute_flags & 0x8000) != storage_fields["is_sparse"]
    ):
        return Decision(
            "indeterminate",
            "storage_contract_unavailable",
            refs,
            ("the unnamed base DATA stream cannot be validated completely",),
        )
    logical = storage_fields.get("logical_size")
    maintained = storage_fields.get("mftecmd_file_size")
    materialized = content_fields.get("materialized_size")
    if not all(
        _is_int(item) and item >= 0 for item in (logical, maintained, materialized)
    ):
        return Decision("indeterminate", "file_length_contract_unavailable", refs)
    if not (logical == maintained == materialized):
        return Decision(
            "indeterminate",
            "file_length_sources_disagree",
            refs,
            ("logical, maintained, and materialized lengths disagree",),
        )
    special_storage = any(
            storage_fields.get(key) is True
            for key in ("is_sparse", "is_compressed", "is_encrypted")
        )
    supported_content = (
        content_fields.get("format_id") == "bmp"
        and content_fields.get("header_parse_status") == "complete"
    )
    if not supported_content:
        return Decision(
            "indeterminate", "self_describing_content_contract_unavailable", refs
        )
    declared = content_fields.get("declared_content_end")
    if not _is_int(declared) or declared < 54:
        return Decision("indeterminate", "content_length_relation_unavailable", refs)
    header_names = ("reserved1", "reserved2", "pixel_offset", "dib_size", "width",
                    "height", "planes", "bits_per_pixel", "compression", "image_size",
                    "colors_used")
    has_header = any(key in content_fields for key in (*header_names, "signature"))
    if has_header:
        if (content_fields.get("signature") != "BM"
                or not all(_is_int(content_fields.get(key)) for key in header_names)):
            return Decision("indeterminate", "bmp_geometry_contract_unavailable", refs)
        width, height = content_fields["width"], content_fields["height"]
        pixel_bytes = ((width * 24 + 31) // 32) * 4 * abs(height)
        if (not 0 < width < 2**31 or not -(2**31) <= height < 2**31 or height == 0
                or content_fields["reserved1"] != 0 or content_fields["reserved2"] != 0
                or content_fields["pixel_offset"] != 54 or content_fields["dib_size"] != 40
                or content_fields["planes"] != 1 or content_fields["bits_per_pixel"] != 24
                or content_fields["compression"] != 0 or content_fields["colors_used"] != 0
                or content_fields["image_size"] not in (0, pixel_bytes)
                or declared != 54 + pixel_bytes or declared > 2**32 - 1):
            return Decision("indeterminate", "bmp_geometry_contract_unavailable", refs)
    if materialized == declared:
        return Decision(
            "not_supported", "self_describing_content_length_consistent", refs
        )
    if materialized > declared:
        if special_storage or (resident_status == "resident" and not has_header):
            return Decision(
                "indeterminate", "length_mismatch_under_benign_storage_mode", refs
            )
        return Decision("supported", "self_describing_content_length_mismatch", refs)
    if has_header and not special_storage and materialized >= 54:
        return Decision("supported", "self_describing_content_truncated", refs,
                        ("complete native file bytes end before the independently computed BMP pixel boundary; cause and intent are unresolved",))
    return Decision("indeterminate", "content_length_relation_unavailable", refs)


def _prefetch(value: AnalysisInput, subject: CandidateSubject) -> Decision:
    observations = tuple(
        item
        for item in _candidate_observations(value, subject)
        if item.observation_type == "prefetch_execution"
    )
    scope = _coverage_scope(value, "windows.prefetch") or {}
    if not observations and (
        scope.get("application_prefetch_enabled") is False
        or scope.get("sysmain_disabled") is True
    ):
        return Decision(
            "indeterminate",
            "prefetch_disabled",
            tuple(item.observation_id for item in observations),
            ("application prefetching is disabled on this system, so Prefetch "
             "residue cannot be expected for any executable",),
        )
    if any(
        not isinstance(item.fields.get("executable_name"), str)
        or normalized_subject_label(item.fields["executable_name"])
        != normalized_subject_label(item.subject_ref).rsplit("\\", 1)[-1]
        or not _is_int(item.fields.get("run_count"))
        or item.fields["run_count"] <= 0
        or parse_csv_timestamp(item.fields.get("last_run")) is None
        for item in observations
    ):
        return Decision(
            "indeterminate",
            "prefetch_record_contract_unavailable",
            tuple(item.observation_id for item in observations),
        )
    if any(
        item.fields.get("executable_identity_basis")
        == "ambiguous_referenced_executable_paths"
        for item in observations
    ):
        return Decision(
            "indeterminate",
            "prefetch_executable_identity_ambiguous",
            tuple(item.observation_id for item in observations),
        )
    return _absence_decision(
        value,
        subject,
        observations,
        supported_reason="prefetch_execution_with_active_mft_absence",
    )


def _shimcache(value: AnalysisInput, subject: CandidateSubject) -> Decision:
    observations = tuple(
        item
        for item in _candidate_observations(value, subject)
        if item.observation_type == "shimcache_path_seen"
    )
    if not observations:
        return Decision(
            "not_supported",
            "no_shimcache_residue",
            (),
            ("Shimcache residue is not proof of execution",),
        )
    decision = _absence_decision(
        value,
        subject,
        observations,
        supported_reason="shimcache_residue_with_active_mft_absence",
    )
    notes = [*decision.limitations, "Shimcache residue is not proof of execution"]
    scope = _coverage_scope(value, "windows.registry.shimcache") or {}
    if scope.get("last_shutdown_time"):
        notes.append(
            "Shimcache entries were persisted at the last recorded shutdown "
            f"({scope['last_shutdown_time']}); later executions are not in the hive"
        )
    return Decision(
        decision.outcome,
        decision.reason_code,
        decision.evidence_refs,
        tuple(dict.fromkeys(notes)),
    )


def _exact_usbstor_identity(
    observation: Observation,
) -> tuple[str, str] | None:
    instance, serial = normalized_device_identity(observation.fields)
    if (
        not serial
        or not instance.startswith("usbstor\\")
        or instance.rsplit("\\", 1)[-1] != serial
    ):
        return None
    return instance, serial


def _external_media(value: AnalysisInput, subject: CandidateSubject, *,
                    section_slack_ticks: int = SETUPAPI_SECTION_SLACK_TICKS) -> Decision:
    device_records = tuple(
        item
        for item in _candidate_observations(value, subject)
        if item.observation_type == "usb_device_seen"
    )
    refs = [item.observation_id for item in device_records]
    if not device_records:
        return Decision(
            "indeterminate",
            "device_identity_contract_unavailable",
            tuple(refs),
            ("at least one scoped USBSTOR identity record is required",),
        )
    identities = tuple(_exact_usbstor_identity(item) for item in device_records)
    if any(identity is None for identity in identities):
        return Decision(
            "indeterminate",
            "usbstor_identity_malformed",
            tuple(refs),
            ("an exact self-consistent USBSTOR instance and serial are required",),
        )
    distinct_identities = {identity for identity in identities if identity is not None}
    if len(distinct_identities) != 1:
        return Decision(
            "indeterminate",
            "usbstor_identity_conflicting",
            tuple(sorted(refs)),
            ("the scoped USBSTOR records do not resolve to one exact identity",),
        )
    control_sets = {
        str(item.fields.get("control_set") or "").strip().casefold()
        for item in device_records
        if str(item.fields.get("control_set") or "").strip()
    }
    if not control_sets:
        return Decision(
            "indeterminate",
            "device_identity_control_set_unavailable",
            tuple(sorted(refs)),
            ("a native SYSTEM ControlSet context is required",),
        )
    if len(control_sets) > 1:
        return Decision(
            "indeterminate",
            "device_identity_control_set_conflicting",
            tuple(sorted(refs)),
            ("the active SYSTEM ControlSet cannot be established unambiguously",),
        )
    lookup = setupapi_identity_lookup(value, subject)
    matching_refs = set(lookup["source_record_refs"])
    refs.extend(
        item.observation_id
        for item in value.observations
        if item.source_record_ref in matching_refs
    )
    if lookup["status"] == "conflicting":
        return Decision(
            "indeterminate",
            "device_identity_correlation_conflicting",
            tuple(sorted(refs)),
            ("SetupAPI retains a partial or conflicting mapping for this device",),
        )
    if lookup["status"] == "present":
        return Decision(
            "not_supported", "consistent_device_identity_observed", tuple(sorted(refs))
        )
    if lookup["status"] != "absent":
        return Decision(
            "indeterminate", "device_identity_lookup_unavailable", tuple(sorted(refs))
        )
    window_decision = _setupapi_window_decision(value, device_records, tuple(sorted(refs)), section_slack_ticks=section_slack_ticks)
    if window_decision is not None:
        return window_decision
    return Decision(
        "supported",
        "usbstor_identity_missing_from_setupapi",
        tuple(sorted(refs)),
        ("identity discrepancy only; device use and file transfer are not inferred",),
    )


def _setupapi_window_decision(
    value: AnalysisInput,
    device_records: tuple[Observation, ...],
    refs: tuple[str, ...],
    *, section_slack_ticks: int = SETUPAPI_SECTION_SLACK_TICKS,
) -> Decision | None:
    scope = _coverage_scope(value, "windows.setupapi")
    if not scope or scope.get("kind") != "setupapi_log" or not scope.get("window_complete"):
        return Decision(
            "indeterminate",
            "setupapi_coverage_unavailable",
            refs,
            ("the retained SetupAPI log window is not established, so a missing "
             "install section cannot be read as absence",),
        )
    raw_intervals = scope.get("intervals") or [
        {
            "first": scope.get("first_section_timestamp"),
            "last": scope.get("last_section_timestamp"),
        }
    ]
    intervals: list[tuple[ForensicTimestamp, ForensicTimestamp]] = []
    for raw in raw_intervals:
        first = parse_csv_timestamp(raw.get("first") if isinstance(raw, Mapping) else None)
        last = parse_csv_timestamp(raw.get("last") if isinstance(raw, Mapping) else None)
        if first is not None and last is not None and first.basis == last.basis:
            intervals.append((first, last))
    if not intervals:
        return Decision("indeterminate", "setupapi_coverage_unavailable", refs)
    install_times: list[ForensicTimestamp] = []
    for item in device_records:
        for key in ("first_install", "installed"):
            parsed = parse_csv_timestamp(item.fields.get(key))
            if parsed is not None:
                install_times.append(parsed)
                break
    if not install_times:
        return Decision(
            "indeterminate",
            "setupapi_window_unverifiable",
            refs,
            ("the USBSTOR record carries no installation timestamp to place "
             "inside the retained SetupAPI window",),
        )
    offset_minutes = scope.get("guest_utc_offset_minutes")
    basis = intervals[0][0].basis
    if any(installed.basis != basis for installed in install_times):
        return Decision(
            "indeterminate",
            "setupapi_window_unverifiable",
            refs,
            ("the installation timestamp and the SetupAPI sections use "
             "incompatible comparison bases",),
        )

    def contained(installed: ForensicTimestamp) -> str:
        if _is_int(offset_minutes):
            local = installed.ticks_100ns + int(offset_minutes) * 60 * TICKS_PER_SECOND
            low = high = local
            basis_note = "guest_time_zone"
        else:
            low = installed.ticks_100ns - MAX_UTC_OFFSET_TICKS
            high = installed.ticks_100ns + MAX_UTC_OFFSET_TICKS
            basis_note = "any_offset"
        for first, last in intervals:
            if first.ticks_100ns <= low and high <= last.ticks_100ns + section_slack_ticks:
                return "inside"
        earliest = min(first.ticks_100ns for first, _last in intervals)
        latest = max(last.ticks_100ns for _first, last in intervals) + section_slack_ticks
        if high < earliest or low > latest:
            return "outside"
        return "unverifiable" if basis_note == "any_offset" or len(intervals) > 1 else "outside"

    placements = [contained(installed) for installed in install_times]
    if all(placement == "inside" for placement in placements):
        return None
    if "unverifiable" in placements:
        return Decision(
            "indeterminate",
            "setupapi_window_unverifiable",
            refs,
            ("the device's installation cannot be placed inside one retained "
             "SetupAPI interval (unknown guest time zone or a gap between "
             "retained logs), so a missing section is not absence",),
        )
    return Decision(
        "indeterminate",
        "setupapi_window_excludes_install",
        refs,
        ("the device's installation lies outside every retained SetupAPI "
         "interval, so its section may have rotated away or postdates the "
         "retained log",),
    )


def _usb_volume(value: AnalysisInput, subject: CandidateSubject) -> Decision:
    records = tuple(item for item in _candidate_observations(value, subject)
                    if item.observation_type == "usb_volume_reference_history")
    refs = tuple(item.observation_id for item in records)
    expected = normalized_device_identity(subject.identity)
    if len(records) != 1 or not all(expected) or _exact_usbstor_identity(records[0]) != expected:
        return Decision("indeterminate", "usb_volume_identity_or_record_unavailable", refs)
    from fmb.analysis.usb_volume import assess_usb_volume_activity
    outcome = assess_usb_volume_activity(records[0].fields)
    reason = {"supported": "usb_link_volume_filename_history_inconsistent",
              "not_supported": "usb_original_path_or_name_history_retained",
              "indeterminate": "usb_volume_history_contract_unavailable"}[outcome]
    return Decision(outcome, reason, refs)

ANALYZERS: dict[str, Analyzer] = {
    "timestamp_manipulation": _timestamp,
    "alternate_data_stream": _ads,
    "deleted_file_journal_residue": _deleted_file,
    "typed_path_residue": _typed_path_residue,
    "shellbag_missing_directory": _shellbag,
    "ntfs_allocation_inconsistency": _allocation,
    "i30_directory_residue": _i30,
    "bitmap_trailing_data": _file_size,
    "prefetch_missing_executable": _prefetch,
    "shimcache_path_residue": _shimcache,
    "usbstor_setupapi_discrepancy": _external_media,
    "usb_volume_activity_gap": _usb_volume,
}


