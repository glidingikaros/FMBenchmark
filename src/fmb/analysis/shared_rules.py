from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import ntpath
from typing import Any

from fmb.analysis import deterministic as rules
from fmb.analysis.catalog import sufficient_family_sets, technique_definition
from fmb.analysis.domain import (
    AnalysisInput,
    CandidateRoster,
    CandidateSubject,
    DeterministicResult,
    EvidenceCoverage,
    Finding,
    Observation,
    SubjectAssessment,
    SupportedSubjects,
)
from fmb.analysis.shared_evidence import EvidenceBundle, unpack_event_records
from fmb.analysis.evidence_projection import _RECORD_TYPES
from fmb.analysis.inputs import (
    active_mft_presence_fact,
    canonical_sha256,
    normalized_device_identity,
    sealed_analysis_input,
    sealed_candidate_roster,
    setupapi_identity_lookup,
)
from fmb.analysis.questions import broad_question
from fmb.analysis.factual_contract import FACTUAL_EVIDENCE_VERSION, FACTUAL_ANALYZER_VERSION, component_ids

_TYPES = {v: k for k, v in _RECORD_TYPES.items() if v != "usn_record"}
_TYPES.update(
    usn_record="usn_filesystem_activity", logfile_si_update="logfile_si_update"
)


def _card_observation_id(subject_id: str, record: dict[str, Any]) -> str:
    digest = canonical_sha256({"subject_id": subject_id, "record": record})
    return f"observation:{digest[:24]}"


def _restore_lookup(
    fields: dict[str, Any], record: dict[str, Any], subject: CandidateSubject
) -> None:
    fact = fields.get("active_mft_lookup")
    if not isinstance(fact, dict):
        return
    target = fact.get("target_identity")
    if not isinstance(target, dict):
        raise ValueError("active MFT lookup needs its exact target")
    if fields.get("mft_volume_id") not in (None, "", target.get("mft_volume_id")):
        raise ValueError("active MFT lookup contradicts the native volume identity")
    fields.update(
        mft_volume_id=target.get("mft_volume_id"),
        mft_active_presence_basis=fact.get("basis"),
        mft_active_presence_status={
            "absent": "active_mft_absent",
            "present": "active_mft_present",
        }.get(fact.get("status")),
        mft_active_presence_check_supported=fact.get("status") in {"absent", "present"},
    )
    probe = Observation(
        "lookup-probe",
        record["artifact_family"],
        _TYPES.get(record["record_type"], record["record_type"]),
        record["subject_ref"],
        fields,
        record["source_record_ref"],
    )
    observed = active_mft_presence_fact(
        probe,
        subject,
        collection_status=fact.get("collection_status"),
        referenced_object=fact.get("target_role") == "referenced_object",
    )
    if observed != fact:
        raise ValueError("active MFT lookup is not bound to the card's native identity")


def _allocation_facts(fields: dict[str, Any]) -> None:
    runs = fields.get("data_runs")
    total = fields.get("total_clusters")
    if not isinstance(runs, list) or type(total) is not int or total <= 0:
        fields.pop("runlist_in_volume", None)
        return
    ranges = sorted(
        (r["lcn"], r["lcn"] + r["cluster_count"]) for r in runs if r["lcn"] is not None
    )
    fields["runlist_in_volume"] = all(
        0 <= start < end <= total for start, end in ranges
    )
    fields["runlist_physical_overlap"] = any(
        b[0] < a[1] for a, b in zip(ranges, ranges[1:])
    )
    allocated = sum(r["cluster_count"] for r in runs if r["lcn"] is not None)
    sparse = sum(r["cluster_count"] for r in runs if r["lcn"] is None)
    contiguous = all(
        b["vcn"] == a["vcn"] + a["cluster_count"] for a, b in zip(runs, runs[1:])
    )
    if (
        fields.get("allocated_cluster_count") != allocated
        or fields.get("sparse_cluster_count") != sparse
        or not contiguous
        or (runs and runs[0]["vcn"] != 0)
    ):
        fields["runlist_complete"] = False


def _usb_facts(fields: dict[str, Any]) -> None:
    lookup = fields.get("original_path_lookup")
    rows, scope = fields.get("companion_directory_rows"), fields.get("companion_directory_scope")
    if isinstance(lookup, dict) and lookup.get("scan_complete") is True:
        fields["active_original_path_count"] = lookup["match_count"]
    elif (isinstance(rows, list) and isinstance(scope, dict) and scope.get("scan_complete") is True
          and isinstance(fields.get("link_target_path"), str)):
        target = fields["link_target_path"][2:].casefold()
        fields["active_original_path_count"] = sum(
            1 for r in rows
            if isinstance(r, dict) and r.get("in_use") is True and str(r.get("path", "")).casefold() == target
        )
    else:
        return
    reference = fields.get("link_file_reference_number")
    history = fields.get("same_reference_usn_records")
    names = fields.get("referenced_entry_file_names")
    if (
        type(reference) is not int
        or not isinstance(history, list)
        or not isinstance(names, list)
        or not isinstance(fields.get("link_target_path"), str)
    ):
        return
    if any(
        not isinstance(r, dict)
        or type(r.get("reason")) is not int
        or not isinstance(r.get("file_name"), str)
        for r in history
    ):
        return
    original = ntpath.basename(fields["link_target_path"]).casefold()
    fields["original_name_usn_record_count"] = sum(
        r["file_name"].casefold() == original for r in history
    )
    fields["alternative_name_usn_record_count"] = (
        len(history) - fields["original_name_usn_record_count"]
    )
    fields["same_reference_rename_record_count"] = sum(
        bool(r["reason"] & 0x3000) for r in history
    )
    fields["same_reference_delete_record_count"] = sum(
        bool(r["reason"] & 0x200) for r in history
    )
    sequence = reference >> 48
    exact = fields.get("referenced_entry_mft_sequence") == sequence
    freed = (
        sequence < 65535
        and fields.get("referenced_entry_mft_sequence") == sequence + 1
        and fields.get("referenced_entry_mft_active") is False
        and any(
            r["reason"] & 0x200
            and any(
                isinstance(fn, dict)
                and str(fn.get("name", "")).casefold() == r["file_name"].casefold()
                and fn.get("parent_file_reference_number")
                == r.get("parent_file_reference_number")
                for fn in names
            )
            for r in history
        )
    )
    fields["native_mft_sequence_relation"] = (
        "exact" if exact else "freed_immediate_successor" if freed else "unresolved"
    )
    serial = str(fields.get("native_boot_volume_serial", ""))[-8:].casefold()
    fields["native_identity_consistent"] = bool(serial) and (
        serial == str(fields.get("link_volume_serial", "")).casefold()
        and (exact or bool(history))
        and reference & ((1 << 48) - 1) >= 24
    )


def _decode(
    bundle: EvidenceBundle, card: dict[str, Any], technique: str
) -> AnalysisInput:
    definition = technique_definition(technique)
    assert definition is not None
    subject = CandidateSubject(
        card["subject_id"],
        card["subject_type"],
        card["display_name"],
        card["identity"],
        (),
    )
    observations = []
    records = card["evidence_records"]
    payload = bundle.payload
    for record in records:
        if record["record_type"] == "retained_security_event_inventory":
            continue
        fields = deepcopy(record["fields"])
        _restore_lookup(fields, record, subject)
        if "current_mft_pools" in payload:
            from fmb.analysis.mft_comparison import comparison_fields
            fields.update(comparison_fields(payload, card, record))
        if record["record_type"] == "file_content":
            fields["declared_content_end"] = fields.get("bmp_header_file_size")
        elif record["record_type"] == "directory_index_scan":
            fields["residue_count"] = sum(
                r["record_type"] == "directory_index_entry"
                and r["fields"].get("i30_entry_state") in {"slack", "unlinked"}
                for r in records
            )
            fields["supported_surface"] = (
                "resident_index_root_mft_slack_and_index_allocation"
                if fields.get("index_allocation_parsed") is True
                else "resident_index_root_and_mft_record_slack"
            )
        elif record["record_type"] == "ntfs_allocation_attribute":
            _allocation_facts(fields)
        elif record["record_type"] == "native_usb_reference_history":
            _usb_facts(fields)
        observations.append(
            Observation(
                _card_observation_id(subject.subject_id, record),
                record["artifact_family"],
                _TYPES.get(record["record_type"], record["record_type"]),
                record["subject_ref"],
                fields,
                record["source_record_ref"],
            )
        )
    observations.sort(key=lambda r: r.observation_id)
    subject = replace(
        subject, observation_ids=tuple(o.observation_id for o in observations)
    )
    coverage_list = []
    for c in card["coverage"]:
        scope = deepcopy(c.get("scope"))
        if isinstance(scope, dict) and "coverage_interval_gap_count" in scope:
            scope["gap_count"] = scope.pop("coverage_interval_gap_count")
        if isinstance(scope, dict) and scope.get("kind") == "setupapi_log":
            if scope.get("last_section_end_timestamp"):
                scope["last_section_timestamp"] = scope["last_section_end_timestamp"]
            for interval in scope.get("intervals", []):
                if interval.get("last_section_end_timestamp"):
                    interval["last"] = interval["last_section_end_timestamp"]
        coverage_list.append(
            EvidenceCoverage(c["artifact_family"], c["collection_status"], scope)
        )
    coverage = tuple(coverage_list)
    roster = sealed_candidate_roster(
        CandidateRoster(
            "",
            bundle.question_id,
            technique,
            f"bundle:{bundle.sha256}",
            bundle.sha256,
            (subject,),
            "complete",
            "",
        )
    )
    value = AnalysisInput(
        "analysis_input.v1",
        "",
        bundle.question_id,
        bundle.payload["question"]["title"],
        bundle.payload["question"]["question_text"],
        technique,
        "Evidence of the stated finding does not establish cause, actor or intent.",
        roster.evidence_index_id,
        bundle.sha256,
        roster,
        definition.required_artifact_families,
        definition.optional_artifact_families,
        coverage,
        tuple(observations),
        subject.observation_ids,
        "ready",
        "",
    )
    for record in records:
        lookup = record["fields"].get("setupapi_lookup")
        if lookup is not None and setupapi_identity_lookup(value, subject) != lookup:
            raise ValueError("shared SetupAPI matches disagree with the native records")
    return sealed_analysis_input(value)


def _log_decision(card: dict[str, Any], technique: str) -> rules.Decision:
    inventories = [
        r
        for r in card["evidence_records"]
        if r["record_type"] == "retained_security_event_inventory"
    ]
    by_source = {}
    for record in inventories:
        source = record["source_record_ref"]
        if source in by_source and by_source[source]["fields"] != record["fields"]:
            return rules.Decision(
                "indeterminate", "event_inventory_conflicting", (source,)
            )
        by_source[source] = record
    refs = tuple(sorted(by_source))
    if len(by_source) != 1:
        return rules.Decision("indeterminate", "event_inventory_unavailable", refs)
    record = next(iter(by_source.values()))
    fields = record["fields"]
    if (
        not card["identity"].get("object_id")
        or fields.get("event_log_scope_id") != card["identity"]["object_id"]
    ):
        return rules.Decision(
            "indeterminate", "event_inventory_identity_unavailable", refs
        )
    rows = unpack_event_records(fields["retained_event_records"])
    complete = (
        fields.get("retained_event_records_complete") is True
        and fields.get("native_record_projection_complete") is True
        and fields.get("collection_scope") == "complete_retained_native_log"
        and str(fields.get("channel", "")).casefold() == "security"
        and rows
        and len(rows) == fields.get("record_count")
    )
    if not complete and not (technique == "security_log_clear_event"
                            and fields.get("native_record_projection_complete") is True
                            and str(fields.get("channel", "")).casefold() == "security" and rows):
        return rules.Decision("indeterminate", "event_inventory_incomplete", refs)
    for row in rows:
        if (
            type(row.get("event_record_id")) is not int
            or row["event_record_id"] <= 0
            or type(row.get("event_id")) is not int
            or row["event_id"] < 0
            or str(row.get("channel", "")).casefold() != "security"
            or row.get("source_file") != fields.get("source_file")
            or not row.get("source_record_ref")
        ):
            return rules.Decision(
                "indeterminate", "event_record_contract_unavailable", refs
            )
    ids = sorted(r["event_record_id"] for r in rows)
    if (
        len(set(ids)) != len(ids)
        or ids[0] != fields.get("first_event_record_id")
        or ids[-1] != fields.get("last_event_record_id")
    ):
        return rules.Decision(
            "indeterminate", "event_inventory_counts_conflicting", refs
        )
    if technique == "security_log_clear_event":
        if any(
            r["event_id"] == 1102
            and str(r.get("provider", "")).casefold() != "microsoft-windows-eventlog"
            for r in rows
        ):
            return rules.Decision(
                "indeterminate", "security_clear_provider_unverified", refs
            )
        clear = any(r["event_id"] == 1102 for r in rows)
        if not clear and not complete:
            return rules.Decision("indeterminate", "event_inventory_incomplete", refs)
        return rules.Decision(
            "supported" if clear else "not_supported",
            "security_log_clear_event_1102" if clear else "no_log_clear_event",
            tuple(r["source_record_ref"] for r in rows if r["event_id"] == 1102) if clear else refs,
            (
                "Clearing evidence does not establish an unauthorized action or its purpose.",
            ),
        )
    gap = any(b > a + 1 for a, b in zip(ids, ids[1:]))
    if gap:
        by_id = {r["event_record_id"]: r["source_record_ref"] for r in rows}
        refs = tuple(sorted({by_id[i] for a, b in zip(ids, ids[1:]) if b > a + 1 for i in (a, b)}))
    return rules.Decision(
        "supported" if gap else "not_supported",
        "internal_native_event_record_gap"
        if gap
        else "retained_event_record_sequence_contiguous",
        refs,
        (
            "A retained internal discontinuity does not establish selective erasure or intent.",
        ),
    )


def _assess(
    bundle: EvidenceBundle, card: dict[str, Any], technique: str
) -> rules.Decision:
    definition = technique_definition(technique)
    assert definition is not None
    coverage = {c["artifact_family"]: c["collection_status"] for c in card["coverage"]}
    covered = any(
        all(coverage.get(f) == "complete" for f in family_set)
        for family_set in sufficient_family_sets(definition)
    )
    if technique in {"alternate_data_stream", "security_log_clear_event"}:
        if technique == "alternate_data_stream":
            value = _decode(bundle, card, technique)
            local = _ads_witness_local(value, value.candidate_roster.subjects[0])
        else:
            local = _log_decision(card, technique)
        if local.outcome == "supported" or covered:
            return local
    if not covered:
        return rules.Decision("indeterminate", "required_evidence_incomplete", ())
    if technique == "event_record_sequence_gap":
        return _log_decision(card, technique)
    value = _decode(bundle, card, technique)
    subject = value.candidate_roster.subjects[0]
    if technique == "timestamp_manipulation":
        return _timestamp_decision(value, subject)
    if technique == "deleted_file_journal_residue":
        rows = tuple(r for r in rules._candidate_observations(value, subject)
                     if r.artifact_family == "ntfs.usn" and rules._observation_is_bound(r, subject))
        if rows:
            state = rules._absence_decision(value, subject, rows, supported_reason="historical_object_absent")
            if state.outcome == "not_supported":
                return state
    if technique == "usbstor_setupapi_discrepancy":
        return rules._external_media(value, subject, section_slack_ticks=0)
    if technique == "usb_volume_activity_gap":
        from fmb.analysis.usb_volume import assess_usb_volume_activity

        rows = [
            r
            for r in value.observations
            if r.observation_type == "usb_volume_reference_history"
        ]
        expected = normalized_device_identity(subject.identity)
        if (
            len(rows) != 1
            or not all(expected)
            or rules._exact_usbstor_identity(rows[0]) != expected
        ):
            return rules.Decision(
                "indeterminate", "usb_volume_identity_or_record_unavailable", ()
            )
        outcome = assess_usb_volume_activity(
            rows[0].fields, require_fixture_device=False
        )
        return rules.Decision(
            outcome,
            "native_usb_filename_history_" + outcome,
            (rows[0].observation_id,),
            ("No physical-device use, transfer or intent is inferred.",),
        )
    decision = rules.ANALYZERS[technique](value, subject)
    if technique == "ntfs_allocation_inconsistency" and decision.outcome == "not_supported":
        rows = [r for r in value.observations if r.observation_type == "ntfs_allocation_record"]
        if len(rows) == 1 and rows[0].fields.get("resident_status") == "nonresident":
            fields = rows[0].fields
            vdl = fields.get("valid_data_length")
            if type(vdl) is not int or vdl < 0:
                return rules.Decision("indeterminate", "native_valid_data_length_unavailable", (rows[0].observation_id,))
            if vdl > fields["logical_size"]:
                return rules.Decision("supported", "native_valid_data_length_exceeds_eof", (rows[0].observation_id,),
                                      ("A native length inconsistency does not establish its cause.",))
    if (
        technique == "prefetch_missing_executable"
        and not any(
            r.observation_type == "prefetch_execution" for r in value.observations
        )
        and decision.reason_code == "active_mft_absence_unavailable"
    ):
        return rules.Decision(
            "not_supported", "no_prefetch_residue_in_retained_scope", ()
        )
    return decision


def _timestamp_decision(value: AnalysisInput, subject: CandidateSubject) -> rules.Decision:
    from fmb.index.support.windows_artifacts import parse_csv_timestamp

    rows = rules._candidate_observations(value, subject)
    current = [r for r in rows if r.observation_type == "mft_file_record"]
    if not current or any(not rules._observation_is_bound(r, subject) for r in current):
        return rules.Decision(
            "indeterminate", "timestamp_entity_identity_unavailable", ()
        )
    updates = rules._logfile_si_updates(rows, subject)
    for update in updates:
        f = update.fields
        if (
            f.get("transaction_committed") is not True
            or f.get("transaction_rolled_back") is True
            or f.get("binding_basis") != "current_mft_record"
        ):
            continue
        if _write_time_restoration(f, current):
            continue
        if _partial_timestamp_backdating(f):
            return rules.Decision("supported", "committed_native_partial_timestamp_backdating",
                tuple(r.observation_id for r in (*current, update)),
                ("The logged byte replacement establishes change direction; omitted timestamp bytes are not reconstructed. Cause and intent remain unresolved.",))
        covered = set(str(f.get("covered_fields", "")).split("|"))
        for field in ("created", "modified", "record_changed"):
            if field not in covered:
                continue
            old, new = (
                parse_csv_timestamp(f.get(k + "_si_" + field)) for k in ("old", "new")
            )
            values = [parse_csv_timestamp(r.fields.get("si_" + field)) for r in current]
            if (
                old is not None
                and new is not None
                and old.basis == new.basis
                and old.ticks_100ns > new.ticks_100ns
                and values
                and (all(
                    t is not None
                    and t.basis == new.basis
                    and t.ticks_100ns == new.ticks_100ns
                    for t in values
                ) or (f.get("record_in_use") is True
                      and f.get("record_lsn_retained") is True
                      and type(f.get("record_lsn")) is int
                      and type(f.get("lsn")) is int
                      and f["record_lsn"] >= f["lsn"]))
            ):
                return rules.Decision(
                    "supported",
                    "committed_native_timestamp_backdating",
                    tuple(r.observation_id for r in (*current, update)),
                    (
                        "A native backwards timestamp transition does not distinguish restoration from anti-forensic purpose.",
                    ),
                )
    return rules._timestamp(
        value, subject, minimum_backdating_ticks=1, late_minimum_ticks=1
    )


RESTORATION_MARGIN_TICKS = 10_000_000
COPY_WINDOW_TICKS = 600_000_000


def _write_time_restoration(fields: dict, current: list) -> bool:
    from fmb.index.support.windows_artifacts import parse_csv_timestamp

    covered = set(str(fields.get("covered_fields", "")).split("|"))
    if "modified" not in covered:
        return False
    moves = {}
    for field in ("created", "modified", "record_changed"):
        if field in covered:
            old, new = (parse_csv_timestamp(fields.get(k + "_si_" + field)) for k in ("old", "new"))
            if old is None or new is None or old.basis != new.basis:
                return False
            moves[field] = new.ticks_100ns - old.ticks_100ns
    if moves["modified"] >= 0 or any(moves.get(field, 0) < 0 for field in ("created", "record_changed")):
        return False
    written, restored = (parse_csv_timestamp(fields.get(k + "_si_modified")) for k in ("old", "new"))
    for row in current:
        created, named = (parse_csv_timestamp(row.fields.get(k)) for k in ("si_created", "fn_created"))
        if (created is None or named is None or not created.basis == named.basis == restored.basis
                or created.ticks_100ns != named.ticks_100ns
                or not created.ticks_100ns <= written.ticks_100ns <= created.ticks_100ns + COPY_WINDOW_TICKS
                or restored.ticks_100ns > created.ticks_100ns - RESTORATION_MARGIN_TICKS):
            return False
    return bool(current)


def _partial_timestamp_backdating(fields: dict) -> bool:
    if (fields.get("record_in_use") is not True or fields.get("record_lsn_retained") is not True
            or type(fields.get("record_lsn")) is not int or type(fields.get("lsn")) is not int
            or fields["record_lsn"] < fields["lsn"]):
        return False
    for fragment in fields.get("si_timestamp_fragments", []):
        if (not isinstance(fragment, dict) or set(fragment) != {
                "field", "byte_order", "field_width_bytes", "offset_in_field", "undo_hex", "redo_hex"}
                or fragment["field"] not in {"created", "modified", "record_changed", "accessed"}
                or fragment["byte_order"] != "little" or fragment["field_width_bytes"] != 8
                or type(fragment["offset_in_field"]) is not int):
            raise ValueError("malformed native SI timestamp fragment")
        try:
            old, new = (bytes.fromhex(fragment[k]) for k in ("undo_hex", "redo_hex"))
        except (ValueError, TypeError) as error:
            raise ValueError("malformed native SI timestamp fragment bytes") from error
        if (not 0 < len(old) == len(new) < 8
                or not 0 <= fragment["offset_in_field"] <= 8 - len(old)):
            raise ValueError("native SI fragment exceeds timestamp boundaries")
        if fragment["field"] != "accessed" and int.from_bytes(new, "little") < int.from_bytes(old, "little"):
            return True
    return False


def _ads_witness_local(value: AnalysisInput, subject: CandidateSubject) -> rules.Decision:
    rows = rules._candidate_observations(value, subject)
    streams = [r for r in rows if r.observation_type == "named_data_stream"]
    if not streams:
        return rules._ads(value, subject, require_parser_verdict=False)
    decisions = []
    for name in sorted({str(r.fields.get("stream_name") or "").casefold() for r in streams}):
        selected = tuple(r for r in rows if r.observation_type in {"named_data_stream", "named_stream_content"}
                         and str(r.fields.get("stream_name") or "").casefold() == name)
        local_subject = replace(subject, observation_ids=tuple(r.observation_id for r in selected))
        local = replace(value, observations=selected)
        decisions.append(rules._ads(local, local_subject, require_parser_verdict=False,
                                    use_native_format_size_bounds=True))
    positives = [d for d in decisions if d.outcome == "supported"]
    if positives:
        return rules.Decision("supported", positives[0].reason_code,
                              tuple(sorted({r for d in positives for r in d.evidence_refs})),
                              ("Support concerns verified streams; other streams may remain unresolved. Content does not establish purpose.",))
    unresolved = [d for d in decisions if d.outcome == "indeterminate"]
    return unresolved[0] if unresolved else rules.Decision(
        "not_supported", "no_supported_format_named_stream_content",
        tuple(sorted({r for d in decisions for r in d.evidence_refs})))


def analyze_evidence_bundle(bundle: EvidenceBundle) -> DeterministicResult:
    payload = bundle.payload
    if payload["schema_version"] != FACTUAL_EVIDENCE_VERSION:
        raise ValueError("a versioned factual bundle is required")
    question = broad_question(bundle.question_id)
    assessments, findings, components = [], [], {}
    for card in payload["candidate_roster"]:
        decisions = {
            t: _assess(bundle, card, t)
            for t in component_ids(card, bundle.question_id)
        }
        public_refs = {
            _card_observation_id(card["subject_id"], r): r["source_record_ref"]
            for r in card["evidence_records"]
        }
        decisions = {
            t: replace(
                d,
                evidence_refs=tuple(
                    sorted({public_refs.get(r, r) for r in d.evidence_refs})
                ),
            )
            for t, d in decisions.items()
        }
        components[card["subject_id"]] = {t: asdict(d) for t, d in decisions.items()}
        supported = [d for d in decisions.values() if d.outcome == "supported"]
        outcome = (
            "supported"
            if supported
            else "indeterminate"
            if not decisions
            or any(d.outcome == "indeterminate" for d in decisions.values())
            else "not_supported"
        )
        relevant = supported or list(decisions.values())
        refs = tuple(sorted({r for d in relevant for r in d.evidence_refs}))
        notes = tuple(sorted({n for d in relevant for n in d.limitations}))
        reason = (
            relevant[0].reason_code
            if len(relevant) == 1
            else "broad_question_" + outcome
        )
        assessments.append(
            SubjectAssessment(card["subject_id"], outcome, reason, refs, notes)
        )
        if supported:
            findings.append(
                Finding(
                    f"finding:{bundle.sha256[:12]}:{card['subject_id'].split(':', 1)[1]}",
                    bundle.question_id,
                    question.group_id,
                    card["subject_id"],
                    "supported",
                    question.title + ": " + card["display_name"],
                    refs,
                    notes,
                )
            )
    digest = canonical_sha256(
        {"evidence_sha256": bundle.sha256, "analyzer_version": FACTUAL_ANALYZER_VERSION}
    )
    return DeterministicResult(
        "deterministic_result.v1",
        f"deterministic:{digest[:24]}",
        f"input:{bundle.sha256[:24]}",
        bundle.sha256,
        bundle.roster_sha256,
        bundle.question_id,
        question.group_id,
        "completed",
        bundle.subject_ids,
        SupportedSubjects(
            tuple(a.subject_id for a in assessments if a.outcome == "supported")
        ),
        tuple(assessments),
        tuple(findings),
        (),
        {
            "analyzer_id": question.group_id,
            "version": FACTUAL_ANALYZER_VERSION,
            "evidence_bundle_sha256": bundle.sha256,
            "component_assessments": components,
        },
    )
