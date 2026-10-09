from __future__ import annotations
from fmb.analysis.evidence_projection import _merge_model_record, _model_coverage_scope, _model_record
from fmb.analysis.inputs import (
    coverage_status, normalized_subject_label, observation_object_id, setupapi_identity_lookup,
)
from fmb.analysis.domain import AnalysisInput
from typing import Any
from fmb.core.json_io import load_json
from pathlib import Path


from fmb.analysis.shared_evidence import EvidenceBundle, EVIDENCE_BUNDLE_VERSION, SHARED_RESPONSE_SCHEMA, prepare_evidence_bundles, pack_event_records


from fmb.analysis.questions import broad_question


from fmb.analysis.inputs import build_analysis_input
from fmb.analysis.catalog import TECHNIQUES, techniques_for_question

def prepare_analysis_inputs(index, *, question_id=None):
    definitions = techniques_for_question(question_id) if question_id else TECHNIQUES
    return tuple(build_analysis_input(index, d) for d in definitions)


def time_bundle():
    path = (
        Path(__file__).resolve().parents[2]
        / "tests/fixtures/assessment/case_time_01.evidence_index.json"
    )
    return prepare_evidence_bundles(
        prepare_analysis_inputs(load_json(path), question_id="Q-TIME-01")
    )[0]


def bundle_for(question_id, fields, *, kind, family, identity=None, families=None):
    question = broad_question(question_id)
    identity = identity or {"object_id": "event-log:fixture"}
    families = families or [family]
    return EvidenceBundle.from_payload(
        {
            "schema_version": EVIDENCE_BUNDLE_VERSION,
            "task": "assess_candidate_roster",
            "question": {
                "question_id": question_id,
                "title": question.title,
                "question_text": question.question_text,
            },
            "coverage": [
                {"artifact_family": f, "status": "complete"} for f in families
            ],
            "candidate_roster": [
                {
                    "subject_id": "subject:fixture",
                    "subject_type": "file",
                    "display_name": "fixture",
                    "identity": identity,
                    "coverage": [
                        {"artifact_family": f, "collection_status": "complete"}
                        for f in families
                    ],
                    "evidence_records": [
                        {
                            "artifact_family": family,
                            "record_type": kind,
                            "subject_ref": "fixture",
                            "source_record_ref": "source:fixture",
                            "fields": fields,
                        }
                    ],
                }
            ],
            "response_schema": SHARED_RESPONSE_SCHEMA,
        }
    )


def log_bundle(ids, *, event_ids=None, complete=True):
    event_ids = event_ids or [4624] * len(ids)
    fields = {
        "channel": "Security",
        "source_file": "Security.evtx",
        "event_log_scope_id": "event-log:fixture",
        "record_count": len(ids),
        "first_event_record_id": min(ids),
        "last_event_record_id": max(ids),
        "native_record_projection_complete": complete,
        "retained_event_records_complete": complete,
        "collection_scope": "complete_retained_native_log",
        "retained_event_records": [
            {
                "event_record_id": rid,
                "event_id": eid,
                "channel": "Security",
                "provider": "Microsoft-Windows-Eventlog"
                if eid in (1101, 1102)
                else "Microsoft-Windows-Security-Auditing",
                "time_created": "2026-09-12T10:00:00Z",
                "source_file": "Security.evtx",
                "source_record_ref": f"Security.csv:row={i}",
            }
            for i, (rid, eid) in enumerate(zip(ids, event_ids))
        ],
    }
    fields["retained_event_records"] = pack_event_records(
        fields["retained_event_records"]
    )
    return bundle_for(
        "BQ-LOG-01",
        fields,
        kind="retained_security_event_inventory",
        family="windows.event_log.record_sequence",
        families=["windows.event_log.record_sequence", "windows.event_log.security"],
    )


def _observation_matches_subject_identity(observation: Any, subject: Any) -> bool:
    expected_object_id = subject.identity.get("object_id")
    if expected_object_id is not None:
        return (
            observation_object_id(observation.fields, observation.subject_ref)
            == expected_object_id
        )
    expected_name = subject.identity.get("canonical_name") or subject.identity.get(
        "path"
    )
    return bool(expected_name) and (
        normalized_subject_label(observation.subject_ref) == expected_name
    )


def _subject_evidence_records(
    analysis_input: AnalysisInput,
    observation_ids: tuple[str, ...],
    observations_by_id: dict[str, Any],
    subject: Any,
) -> list[dict[str, Any]]:
    records: dict[tuple[str, ...], dict[str, Any]] = {}
    for observation_id in observation_ids:
        observation = observations_by_id[observation_id]
        record = _model_record(analysis_input, observation, subject)
        if record is None:
            continue
        source_key = observation.source_record_ref or observation.observation_id
        key = (
            observation.artifact_family,
            source_key,
            *(
                ()
                if analysis_input.technique_id == "timestamp_manipulation"
                else (record["record_type"],)
            ),
        )
        existing = records.get(key)
        if existing is None:
            records[key] = record
        else:
            _merge_model_record(existing, record)
    return [records[key] for key in sorted(records)]


def projected_input(value):
    observations = {item.observation_id: item for item in value.observations}
    return {"candidate_roster": [_subject_card(value, subject, observations)
        for subject in value.candidate_roster.subjects]}


def _subject_card(
    analysis_input: AnalysisInput,
    subject: Any,
    observations_by_id: dict[str, Any],
) -> dict[str, Any]:
    records = _subject_evidence_records(
        analysis_input,
        subject.observation_ids,
        observations_by_id,
        subject,
    )
    observations = [
        observations_by_id[observation_id] for observation_id in subject.observation_ids
    ]
    if coverage_status(analysis_input, "ntfs.mft") == "missing" and any(
        observation.fields.get("mft_active_presence_check_supported") is True
        and observation.fields.get("mft_active_presence_status")
        in {"active_mft_absent", "active_mft_present"}
        for observation in observations
    ):
        raise ValueError("candidate evidence contradicts missing collection status")

    def candidate_presence(artifact_family: str) -> str:
        if artifact_family == "ntfs.mft":
            candidate_checks = [
                lookup
                for record in records
                if isinstance(lookup := record["fields"].get("active_mft_lookup"), dict)
                and lookup["target_role"] == "candidate"
            ]
            explicit = {item["status"] for item in candidate_checks}
            if "present" in explicit and "absent" in explicit:
                return "conflicting"
            if "unresolved" in explicit:
                return "unresolved"
            if len(explicit) > 1:
                return "conflicting"
            if explicit:
                return next(iter(explicit))
            if any(
                observation.artifact_family == "ntfs.mft"
                and observation.fields.get("in_use") is True
                and _observation_matches_subject_identity(observation, subject)
                for observation in observations
            ):
                return "present"
            return "unresolved"
        if artifact_family == "windows.setupapi":
            return str(setupapi_identity_lookup(analysis_input, subject)["status"])
        if any(record["artifact_family"] == artifact_family for record in records):
            return "present"
        return "unresolved"

    coverage = [
        {
            "artifact_family": item.artifact_family,
            "collection_status": item.status,
            "candidate_presence": candidate_presence(item.artifact_family),
            **(
                {"scope": _model_coverage_scope(item.scope)}
                if item.scope
                else {}
            ),
        }
        for item in analysis_input.coverage
    ]
    if any(
        item["collection_status"] == "missing"
        and item["candidate_presence"] != "unresolved"
        for item in coverage
    ):
        raise ValueError("candidate evidence contradicts missing collection status")
    return {
        "subject_id": subject.subject_id,
        "subject_type": subject.subject_type,
        "display_name": subject.display_name,
        "identity": subject.identity,
        "coverage": coverage,
        "evidence_records": records,
    }


def score_case(case, response, expected):
    from fmb.core.case_contract import target_catalog, validate_response
    from fmb.evaluation.scoring import score_schedule

    validate_response(case, response)
    qid = case['question']['question_id']
    schedule = [dict(request_id='case', case_id='case', question_id=qid, pass_=p,
                     batch_index=0, batches=1, binding={'case': 'fixture'}) for p in (1, 2, 3)]
    for row in schedule:
        row['pass'] = row.pop('pass_')
    references = {'case': {'expected_status': {
        fid: 'supported' if fid in expected else 'not_supported' for fid in target_catalog(case)}}}
    return score_schedule(schedule, references,
                          [{**row, 'status': 'completed', 'two_list': response,
                            'started_utc': '2026-09-18T00:00:00+00:00',
                            'finished_utc': '2026-09-18T00:00:01+00:00'} for row in schedule])
