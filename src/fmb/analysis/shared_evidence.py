from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import ntpath
from os.path import commonprefix
from typing import Any, Iterable

from fmb.analysis.domain import AnalysisInput
from fmb.analysis.inputs import assert_analysis_input_integrity, assert_truth_blind
from fmb.analysis.evidence_projection import (
    _collected_artifact_path,
    _model_coverage_scope,
    _model_record,
    _merge_model_record,
    blinding_violations,
    _HISTORICAL_MODEL_FIELDS_BY_RECORD_TYPE,
    _MODEL_FIELDS_BY_OBSERVATION_TYPE,
    _RECORD_TYPES,
    _USN_MODEL_FIELDS,
    _model_native_data_runs,
    _model_format_entries,
    _FORMAT_ENTRY_FIELDS,
)
from fmb.analysis.questions import BROAD_QUESTIONS, BroadQuestion, broad_question
from fmb.core.sealed_records import canonical_json

EVIDENCE_BUNDLE_VERSION = "candidate_roster_shared_evidence.v1"
SHARED_RESPONSE_SCHEMA = {
    "type": "object",
    "required": ["supported_subject_ids"],
    "properties": {
        "supported_subject_ids": {
            "type": "array",
            "items": {"type": "string"},
            "uniqueItems": True,
        }
    },
    "additionalProperties": False,
}
_IDENTITY_KEYS = frozenset(
    {
        "object_id",
        "canonical_name",
        "path",
        "stream_name",
        "device_instance_id",
        "serial_number",
    }
)
EVENT_COLUMNS = (
    "event_id",
    "event_record_id",
    "channel",
    "time_created",
    "provider",
    "source_file",
    "source_record_ref",
)


def pack_event_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    if any(not isinstance(r, dict) or set(r) != set(EVENT_COLUMNS) for r in records):
        raise ValueError("unregistered native event inventory fields")
    constants = {
        k: records[0][k]
        for k in EVENT_COLUMNS
        if records and all(r[k] == records[0][k] for r in records)
    }
    columns = [k for k in EVENT_COLUMNS if k not in constants]
    encoded = {k: [r[k] for r in records] for k in columns}
    encodings = {}
    for key, values in encoded.items():
        if not values or not all(isinstance(v, str) for v in values):
            continue
        dictionary = sorted(set(values))
        if len(dictionary) <= 16 and len(values) > len(dictionary) * 2:
            positions = {v: i for i, v in enumerate(dictionary)}
            encodings[key] = {"kind": "dictionary", "values": dictionary}
            encoded[key] = [positions[v] for v in values]
        else:
            prefix = commonprefix(values)
            if len(prefix) >= 8:
                encodings[key] = {"kind": "prefix", "prefix": prefix}
                encoded[key] = [v[len(prefix) :] for v in values]
            elif key == "time_created":
                best_size = len(canonical_json(values))
                for width in (8, 10, 14, 17, 19, 20, 22):
                    prefixes = sorted({v[:width] for v in values})
                    positions = {v: i for i, v in enumerate(prefixes)}
                    candidate = [[positions[v[:width]], v[width:]] for v in values]
                    encoding = {"kind": "prefix_dictionary", "prefixes": prefixes}
                    size = len(canonical_json(candidate)) + len(
                        canonical_json(encoding)
                    )
                    if size < best_size:
                        encodings[key], encoded[key], best_size = (
                            encoding,
                            candidate,
                            size,
                        )
    return {
        "constant_fields": constants,
        "columns": columns,
        "column_encodings": encodings,
        "dictionary_index_base": 0,
        "rows": [[encoded[k][i] for k in columns] for i in range(len(records))],
    }


def unpack_event_records(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    if (
        not isinstance(inventory, dict)
        or set(inventory)
        != {
            "constant_fields",
            "columns",
            "rows",
            "column_encodings",
            "dictionary_index_base",
        }
        or type(inventory["dictionary_index_base"]) is not int
        or inventory["dictionary_index_base"] != 0
    ):
        raise ValueError("invalid native event table")
    constants, columns, rows = (
        inventory[k] for k in ("constant_fields", "columns", "rows")
    )
    if (
        not isinstance(constants, dict)
        or not isinstance(columns, list)
        or not isinstance(rows, list)
        or any(not isinstance(c, str) for c in columns)
        or len(columns) != len(set(columns))
        or set(constants) & set(columns)
        or set(constants) | set(columns) != set(EVENT_COLUMNS)
        or any(not isinstance(r, list) or len(r) != len(columns) for r in rows)
    ):
        raise ValueError(
            "native event table fields are missing, duplicated or unregistered"
        )
    encodings = inventory["column_encodings"]
    if not isinstance(encodings, dict) or encodings.keys() - set(columns):
        raise ValueError("native event encodings reference unknown columns")
    result = []
    for row in rows:
        decoded = dict(zip(columns, row, strict=True))
        for key, encoding in encodings.items():
            if not isinstance(encoding, dict):
                raise ValueError("invalid native event column encoding")
            if encoding.get("kind") == "dictionary" and set(encoding) == {
                "kind",
                "values",
            }:
                items, position = encoding["values"], decoded[key]
                if (
                    not isinstance(items, list)
                    or any(not isinstance(v, str) for v in items)
                    or type(position) is not int
                    or not 0 <= position < len(items)
                ):
                    raise ValueError("invalid native event dictionary position")
                decoded[key] = items[position]
            elif (
                encoding.get("kind") == "prefix"
                and set(encoding) == {"kind", "prefix"}
                and isinstance(encoding["prefix"], str)
                and isinstance(decoded[key], str)
            ):
                decoded[key] = encoding["prefix"] + decoded[key]
            elif encoding.get("kind") == "prefix_dictionary" and set(encoding) == {
                "kind",
                "prefixes",
            }:
                parts, prefixes = decoded[key], encoding["prefixes"]
                if (
                    not isinstance(parts, list)
                    or len(parts) != 2
                    or type(parts[0]) is not int
                    or not isinstance(parts[1], str)
                    or not isinstance(prefixes, list)
                    or any(not isinstance(p, str) for p in prefixes)
                    or not 0 <= parts[0] < len(prefixes)
                ):
                    raise ValueError("invalid native event timestamp prefix")
                decoded[key] = prefixes[parts[0]] + parts[1]
            else:
                raise ValueError("invalid native event column encoding")
        result.append({**constants, **decoded})
    return result


def _validate_original_path_lookup(fields: dict[str, Any]) -> None:
    lookup = fields.get("original_path_lookup")
    if lookup is None:
        return
    if (
        not isinstance(lookup, dict)
        or set(lookup)
        != {"target_path", "match_count", "scan_complete", "matching_objects"}
        or lookup["target_path"] != fields.get("link_target_path")
        or not isinstance(lookup["target_path"], str)
        or type(lookup["match_count"]) is not int
        or lookup["match_count"] < 0
        or type(lookup["scan_complete"]) is not bool
        or lookup["scan_complete"] != fields.get("active_mft_complete")
    ):
        raise ValueError(
            "original-path lookup is not bound to the native link and scan"
        )
    matches = lookup["matching_objects"]
    if matches is None:
        return
    if not isinstance(matches, list) or len(matches) != lookup["match_count"]:
        raise ValueError("original-path lookup cardinality disagrees with its objects")
    target = ntpath.splitdrive(lookup["target_path"])[1].casefold().lstrip("\\")
    identities = set()
    for row in matches:
        if (
            not isinstance(row, dict)
            or set(row) != {"mft_entry", "sequence_number", "paths"}
            or type(row["mft_entry"]) is not int
            or not 0 <= row["mft_entry"] < 1 << 48
            or type(row["sequence_number"]) is not int
            or not 0 <= row["sequence_number"] < 1 << 16
            or not isinstance(row["paths"], list)
            or any(not isinstance(p, str) for p in row["paths"])
            or target
            not in {
                ntpath.splitdrive(p)[1].casefold().lstrip("\\") for p in row["paths"]
            }
        ):
            raise ValueError(
                "original-path matching object lacks its exact native path"
            )
        identities.add((row["mft_entry"], row["sequence_number"]))
    if len(identities) != len(matches):
        raise ValueError("original-path lookup repeats a native object")


def _validate_nested_facts(fields: dict[str, Any]) -> None:
    _validate_original_path_lookup(fields)
    if "installation_time_zone" in fields and (
        fields["installation_time_zone"] != "UTC"
        or fields.get("timestamp_basis")
        not in {"plugin_naive_clock", "native_device_property_filetime"}
    ):
        raise ValueError("installation time convention differs from its native source")
    if (
        "data_runs" in fields
        and _model_native_data_runs(fields["data_runs"]) != fields["data_runs"]
    ):
        raise ValueError("unregistered native data-run facts")
    for key in _FORMAT_ENTRY_FIELDS:
        if key in fields and _model_format_entries(key, fields[key]) != fields[key]:
            raise ValueError("unregistered native content-entry facts")
    for key, allowed in {
        "active_mft_lookup": {
            "target_identity",
            "target_role",
            "status",
            "basis",
            "collection_status",
            "source_record_ref",
        },
        "setupapi_lookup": {
            "target_identity",
            "collection_status",
            "status",
            "exact_match_count",
            "partial_match_count",
            "source_record_refs",
            "matching_fields",
        },
    }.items():
        if key in fields:
            lookup = fields[key]
            if not isinstance(lookup, dict) or set(lookup) != allowed:
                raise ValueError("unregistered identity lookup facts")
            target = lookup["target_identity"]
            if not isinstance(target, dict) or set(target) - _IDENTITY_KEYS - {"mft_volume_id"}:
                raise ValueError("unregistered identity lookup target")
    nested_rows = {
        "referenced_entry_file_names": {
            "name",
            "parent_file_reference_number",
            "namespace",
        },
        "same_reference_usn_records": {
            "record_offset",
            "record_length",
            "major_version",
            "minor_version",
            "file_reference_number",
            "parent_file_reference_number",
            "usn",
            "timestamp_filetime",
            "timestamp_utc",
            "reason",
            "reason_labels",
            "source_info",
            "security_id",
            "file_attributes",
            "file_name_length",
            "file_name_offset",
            "file_name",
            "parser_status",
            "parser_status_reason",
        },
    }
    for key, allowed in nested_rows.items():
        if key in fields and (
            not isinstance(fields[key], list)
            or any(not isinstance(r, dict) or r.keys() - allowed for r in fields[key])
        ):
            raise ValueError("unregistered nested native records")
    if "setupapi_lookup" in fields:
        rows = fields["setupapi_lookup"]["matching_fields"]
        if not isinstance(rows, list) or any(
            not isinstance(r, dict)
            or r.keys()
            - {
                "device_instance_id",
                "serial_number",
                "event_timestamp",
                "timestamp_basis",
            }
            for r in rows
        ):
            raise ValueError("unregistered native SetupAPI matches")


def _coverage_union(
    values: Iterable[dict[str, Any]], *, aggregate: bool = False
) -> list[dict[str, Any]]:
    by_family = {}
    for value in values:
        family = value["artifact_family"]
        if family in by_family and by_family[family] != value:
            old = by_family[family]
            if aggregate and old.get("scope") == value.get("scope"):
                by_family[family] = {**old, "status": "partial"}
                continue
            raise ValueError(
                "shared evidence contains conflicting coverage for " + family
            )
        by_family[family] = deepcopy(value)
    return [by_family[k] for k in sorted(by_family)]


def _record_union(values: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result = {}
    for record in values:
        key = (
            record["artifact_family"],
            record["source_record_ref"],
            record["record_type"],
        )
        if key in result:
            _merge_model_record(result[key], record)
        else:
            result[key] = deepcopy(record)
    return [result[k] for k in sorted(result)]


def _validate_coverage(
    entries: list[dict[str, Any]], status_key: str, unregistered: str
) -> None:
    _coverage_union(entries)
    for coverage in entries:
        if coverage.keys() - {"artifact_family", status_key, "scope"}:
            raise ValueError(unregistered)
        if (
            "scope" in coverage
            and _model_coverage_scope(coverage["scope"])
            != coverage["scope"]
        ):
            raise ValueError("derived fields in shared coverage")


def _coverage_entries(value: AnalysisInput, status_key: str) -> list[dict[str, Any]]:
    return [
        {
            "artifact_family": item.artifact_family,
            status_key: item.status,
            **(
                {"scope": _model_coverage_scope(item.scope)}
                if item.scope
                else {}
            ),
        }
        for item in value.coverage
    ]


@dataclass(frozen=True)
class EvidenceBundle:

    canonical: str

    def __post_init__(self) -> None:
        value = json.loads(self.canonical)
        validate_evidence_payload(value)
        if self.canonical != canonical_json(value):
            raise ValueError("evidence bundle must use canonical JSON")

    @classmethod
    def from_payload(cls, value: dict[str, Any]) -> EvidenceBundle:
        return cls(canonical_json(value))

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical.encode("utf-8")).hexdigest()

    @property
    def payload(self) -> dict[str, Any]:
        return json.loads(self.canonical)

    @property
    def question_id(self) -> str:
        return self.payload["question"]["question_id"]

    @property
    def subject_ids(self) -> tuple[str, ...]:
        return tuple(c["subject_id"] for c in self.payload["candidate_roster"])

    @property
    def roster_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json(self.payload["candidate_roster"]).encode()
        ).hexdigest()


def validate_evidence_payload(value: dict[str, Any]) -> None:
    from fmb.analysis.factual_presentation import PRESENTATION_VERSION, validate_payload
    if isinstance(value, dict) and value.get("schema_version") == PRESENTATION_VERSION:
        validate_payload(value)
        return
    from fmb.analysis.factual_contract import FACTUAL_EVIDENCE_VERSION, factual_response_schema

    factual = isinstance(value, dict) and value.get("schema_version") == FACTUAL_EVIDENCE_VERSION
    with_comparison = factual and "current_mft_pools" in value
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "task",
        "question",
        "coverage",
        "candidate_roster",
        "response_schema",
    } | ({"current_mft_pools"} if with_comparison else set()):
        raise ValueError("invalid shared evidence envelope")
    if (
        value["schema_version"] not in {EVIDENCE_BUNDLE_VERSION, FACTUAL_EVIDENCE_VERSION}
        or value["task"] != "assess_candidate_roster"
    ):
        raise ValueError("unsupported shared evidence contract")
    question = broad_question(value["question"]["question_id"])
    if with_comparison:
        from fmb.analysis.mft_comparison import POOL_QUESTIONS, validate_pool
        if question.question_id not in POOL_QUESTIONS or not isinstance(value["current_mft_pools"], list) or len(value["current_mft_pools"]) != 1:
            raise ValueError("unsupported MFT comparison scope")
        for pool in value["current_mft_pools"]:
            validate_pool(pool)
        if any("active_mft_lookup" in r["fields"] for c in value["candidate_roster"] for r in c["evidence_records"]):
            raise ValueError("assessment-side comparison must not also expose prepared presence verdicts")
    if value["question"] != {
        "question_id": question.question_id,
        "title": question.title,
        "question_text": question.question_text,
    }:
        raise ValueError("shared evidence question differs from the public contract")
    expected_schema = SHARED_RESPONSE_SCHEMA
    if factual:
        expected_schema = factual_response_schema(value["candidate_roster"], question.question_id)
    if value["response_schema"] != expected_schema:
        raise ValueError("shared response schema must not encode expected answers")
    cards = value["candidate_roster"]
    if not isinstance(cards, list) or not 1 <= len(cards) <= 5000:
        raise ValueError("shared evidence needs a bounded nonempty candidate roster")
    ids = [c.get("subject_id") for c in cards]
    if any(
        not isinstance(s, str) or not s.startswith("subject:") for s in ids
    ) or ids != sorted(set(ids)):
        raise ValueError("shared subject IDs must be sorted, unique and exact")
    for card in cards:
        if set(card) != {
            "subject_id",
            "subject_type",
            "display_name",
            "identity",
            "coverage",
            "evidence_records",
        }:
            raise ValueError("unregistered candidate fields in shared evidence")
        if not isinstance(card["identity"], dict) or not isinstance(
            card["evidence_records"], list
        ):
            raise ValueError("invalid shared candidate identity or records")
        if (
            not card["identity"]
            or card["identity"].keys() - _IDENTITY_KEYS
            or any(not isinstance(v, str) for v in card["identity"].values())
        ):
            raise ValueError("unregistered candidate identity facts")
        _validate_coverage(
            card["coverage"], "collection_status", "unregistered candidate coverage facts"
        )
        for record in card["evidence_records"]:
            if set(record) != {
                "artifact_family",
                "record_type",
                "subject_ref",
                "source_record_ref",
                "fields",
            }:
                raise ValueError("unregistered shared record fields")
            if (
                not isinstance(record["fields"], dict)
                or not record["source_record_ref"]
            ):
                raise ValueError("shared evidence records require facts and provenance")
            allowed = set()
            for kind, names in _MODEL_FIELDS_BY_OBSERVATION_TYPE.items():
                if _RECORD_TYPES.get(kind, kind) == record["record_type"]:
                    allowed.update(names)
            if record["record_type"] == "usn_record":
                allowed.update(_USN_MODEL_FIELDS)
            elif record["record_type"] == "logfile_si_update":
                allowed.update(_MODEL_FIELDS_BY_OBSERVATION_TYPE["logfile_si_update"])
            elif record["record_type"] == "retained_security_event_inventory":
                allowed.update(
                    _MODEL_FIELDS_BY_OBSERVATION_TYPE["event_log_scope_seen"]
                )
                allowed.update(
                    {"retained_event_records", "retained_event_records_complete"}
                )
            allowed.update(
                {
                    "active_mft_lookup",
                    "setupapi_lookup",
                    "bmp_header_file_size",
                    "original_path_lookup",
                    "installation_time_zone",
                }
            )
            allowed.update(_HISTORICAL_MODEL_FIELDS_BY_RECORD_TYPE.get(record["record_type"], ()))
            if record["fields"].keys() - allowed:
                raise ValueError("unregistered native facts in shared record")
            _validate_nested_facts(record["fields"])
            if record["record_type"] == "retained_security_event_inventory":
                unpack_event_records(record["fields"]["retained_event_records"])
        _record_union(card["evidence_records"])
    _validate_coverage(value["coverage"], "status", "unregistered question coverage facts")
    assert_truth_blind(value, path="llm_packet")
    if blinding_violations(value):
        raise ValueError("host paths or case labels in shared evidence")
    forbidden = {
        "claim_boundary",
        "deterministic_verdict",
        "support_routes",
        "category_hint",
        "positive_count",
        "reason_code",
        "detector_result",
        "classification",
        "internal_gap_count",
        "missing_internal_record_count",
        "gap_size",
        "pe_structure_status",
        "zip_structure_status",
        "native_identity_consistent",
        "native_mft_sequence_relation",
        "content_length_relation",
        "trailing_bytes",
        "missing_bytes",
        "runlist_in_volume",
    }

    def check(item: Any) -> None:
        if isinstance(item, dict):
            if forbidden & item.keys():
                raise ValueError("derived finding annotation in shared evidence")
            for child in item.values():
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)

    check(value)


def _record(
    value: AnalysisInput, observation: Any, subject: Any
) -> dict[str, Any] | None:
    kind = observation.observation_type
    fields = observation.fields
    if kind in {"event_id_1102", "event_record_id_gap"}:
        return None
    result = _model_record(value, observation, subject)
    if result is None:
        return None
    projected = result["fields"]
    if kind == "event_log_scope_seen":
        records = fields.get("retained_event_records", [])
        if not isinstance(records, list):
            raise ValueError("retained event inventory must be a list")
        clean_records = []
        for row in records:
            if not isinstance(row, dict) or set(row) != set(EVENT_COLUMNS):
                raise ValueError("unregistered native event inventory fields")
            clean = dict(row)
            clean["source_file"] = _collected_artifact_path(clean["source_file"])
            clean_records.append(clean)
        projected["retained_event_records"] = pack_event_records(clean_records)
        projected["retained_event_records_complete"] = (
            fields.get("retained_event_records_complete") is True
        )
        result["record_type"] = "retained_security_event_inventory"
        result["artifact_family"] = "windows.event_log.security"
    elif kind == "materialized_file_content_record":
        native = fields.get("bmp_header_file_size", fields.get("declared_content_end"))
        if (
            "bmp_header_file_size" in fields
            and "declared_content_end" in fields
            and native != fields["declared_content_end"]
        ):
            raise ValueError("BMP header-size measurements disagree")
        if native is not None:
            projected["bmp_header_file_size"] = native
    elif kind == "usb_volume_reference_history":
        lookup = fields.get("original_path_lookup")
        if lookup is None and type(fields.get("active_original_path_count")) is int:
            lookup = {
                "target_path": fields.get("link_target_path"),
                "match_count": fields["active_original_path_count"],
                "scan_complete": fields.get("active_mft_complete") is True,
                "matching_objects": None,
            }
        if lookup is not None:
            if not isinstance(lookup, dict) or set(lookup) != {
                "target_path",
                "match_count",
                "scan_complete",
                "matching_objects",
            }:
                raise ValueError("unregistered original-path lookup fields")
            if (
                lookup["target_path"] != fields.get("link_target_path")
                or type(lookup["match_count"]) is not int
                or lookup["match_count"] < 0
            ):
                raise ValueError("original-path lookup is not bound to the native link")
            if (
                "active_original_path_count" in fields
                and lookup["match_count"] != fields["active_original_path_count"]
            ):
                raise ValueError("original-path native lookup counts disagree")
    elif kind == "named_data_stream":
        projected.pop("stream_name_occurrences", None)
        projected.pop("host_named_stream_count", None)
        projected.pop("host_population_complete", None)
    elif kind == "ntfs_allocation_record":
        projected.pop("runlist_in_volume", None)
    elif kind == "usb_device_seen":
        if fields.get("timestamp_basis") in {
            "plugin_naive_clock",
            "native_device_property_filetime",
        }:
            projected["installation_time_zone"] = "UTC"
    return result


def _card(value: AnalysisInput, subject: Any) -> dict[str, Any]:
    observations = {o.observation_id: o for o in value.observations}
    records = _record_union(
        record
        for observation_id in subject.observation_ids
        if (record := _record(value, observations[observation_id], subject)) is not None
    )
    if any(r["record_type"] == "usb_device_seen" for r in records):
        bound = set(subject.observation_ids)
        records = _record_union(
            [
                *records,
                *(
                    record
                    for observation in value.observations
                    if observation.observation_type == "setupapi_usb_event"
                    and observation.observation_id not in bound
                    and (record := _record(value, observation, subject)) is not None
                ),
            ]
        )
    return {
        "subject_id": subject.subject_id,
        "subject_type": subject.subject_type,
        "display_name": subject.display_name,
        "identity": deepcopy(subject.identity),
        "coverage": _coverage_entries(value, "collection_status"),
        "evidence_records": records,
    }


def build_evidence_bundle(
    inputs: Iterable[AnalysisInput], question: BroadQuestion | str
) -> EvidenceBundle:
    if isinstance(question, str):
        question = broad_question(question)
    values = tuple(inputs)
    by_technique = {v.technique_id: v for v in values}
    if len(values) != len(by_technique) or set(by_technique) != set(
        question.technique_ids
    ):
        raise ValueError(
            "shared bundle requires exactly the public question's component inputs"
        )
    if len({v.evidence_index_sha256 for v in values}) != 1:
        raise ValueError(
            "shared question components must come from the same evidence index"
        )
    cards: dict[str, dict[str, Any]] = {}
    coverage = []
    for value in values:
        assert_analysis_input_integrity(value)
        coverage.extend(_coverage_entries(value, "status"))
        for subject in value.candidate_roster.subjects:
            incoming = _card(value, subject)
            old = cards.get(subject.subject_id)
            if old is None:
                cards[subject.subject_id] = incoming
            else:
                for key in ("subject_type", "display_name", "identity"):
                    if old[key] != incoming[key]:
                        raise ValueError(
                            "shared question components disagree on subject identity"
                        )
                old["coverage"] = _coverage_union(
                    [*old["coverage"], *incoming["coverage"]]
                )
                old["evidence_records"] = _record_union(
                    [*old["evidence_records"], *incoming["evidence_records"]]
                )
    return EvidenceBundle.from_payload(
        {
            "schema_version": EVIDENCE_BUNDLE_VERSION,
            "task": "assess_candidate_roster",
            "question": {
                "question_id": question.question_id,
                "title": question.title,
                "question_text": question.question_text,
            },
            "coverage": _coverage_union(coverage, aggregate=True),
            "candidate_roster": [cards[k] for k in sorted(cards)],
            "response_schema": deepcopy(SHARED_RESPONSE_SCHEMA),
        }
    )


def prepare_evidence_bundles(
    inputs: Iterable[AnalysisInput],
) -> tuple[EvidenceBundle, ...]:
    values = tuple(inputs)
    by_id = {v.technique_id: v for v in values}
    if len(by_id) != len(values):
        raise ValueError("duplicate technique inputs in shared evidence preparation")
    questions = [q for q in BROAD_QUESTIONS if set(q.technique_ids) & by_id.keys()]
    missing = {t for q in questions for t in q.technique_ids if t not in by_id}
    if missing:
        raise ValueError(
            "complete broad questions require missing component inputs: "
            + ", ".join(sorted(missing))
        )
    return tuple(
        build_evidence_bundle((by_id[t] for t in q.technique_ids), q) for q in questions
    )
