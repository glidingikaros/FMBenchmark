from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import re

from fmb.analysis.factual_contract import (
    COMPONENT_TARGETS, FACTUAL_EVIDENCE_VERSION,
    component_ids, factual_response_schema,
)

PRESENTATION_VERSION = "candidate_roster_factual_evidence.v2"
ALIASES = {
    "usb_volume_activity_gap": "usb_filename_history_inconsistency",
    "bitmap_trailing_data": "bmp_content_length_inconsistency",
}
TARGETS = {ALIASES.get(k, k): v for k, v in COMPONENT_TARGETS.items()}
TARGETS["timestamp_manipulation"] = (
    "Retained historical backdating of creation, modification or metadata-change "
    "timestamps; access-time-only changes are outside this target."
)
TARGETS["event_record_sequence_gap"] = (
    "Internal discontinuity in native Security Event Record IDs over the declared "
    "retained-log scope."
)
TARGETS["usb_filename_history_inconsistency"] = (
    "Mutually incompatible retained filename-history observations for the same "
    "file object on the referenced USB companion volume."
)
ENCODING = {
    "record_field_defaults": "Fields shared by all records of that record_type; combine with each record's fields.",
    "source_reference_map": "Short source_record_ref identifiers resolve to the exact original provenance strings.",
    "timestamps": "UTC uses seven fractional digits. Decimal FILETIME strings are exact counts of 100 ns units since 1601-01-01 UTC.",
    "timestamp_updates": "Each row describes one SI field before and after the native update; null denotes an unavailable complete value.",
    "si_timestamp_fragments": "Known bytes at the stated offset in an eight-byte little-endian FILETIME; unsigned values decode only those bytes, not a complete timestamp.",
    "mft_named_stream_row": "Parser row for a named DATA attribute on the identified host MFT record; the timestamps belong to that host record.",
    "coverage": "Native verification concerns the included observations. Collection status and scope describe which evidence is available.",
}
_UTC = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,7}))?Z$")
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_FIELDS = ("created", "modified", "record_changed", "accessed")


def fixed_utc(value):
    if isinstance(value, str) and (match := _UTC.fullmatch(value)):
        return match[1] + "." + (match[2] or "").ljust(7, "0") + "Z"
    return value


def filetime_decimal(value):
    if value is None or value == "":
        return None
    match = _UTC.fullmatch(value)
    if match is None:
        raise ValueError("timestamp presentation requires an exact native UTC value")
    elapsed = datetime.fromisoformat(match[1]).replace(tzinfo=timezone.utc) - _EPOCH
    return str((elapsed.days * 86400 + elapsed.seconds) * 10000000
               + int((match[2] or "").ljust(7, "0")))


def _walk(value, function):
    if isinstance(value, dict):
        return {k: _walk(v, function) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(v, function) for v in value]
    return function(value)


def _replace_strings(value, table):
    return _walk(value, lambda item: table.get(item, item) if isinstance(item, str) else item)


def normalized_payload(payload):
    return _walk(payload, fixed_utc)


def _references(payload):
    from fmb.analysis.factual_contract import source_references
    result = set()
    for card in payload["candidate_roster"]:
        result.update(source_references(card))

    def collect(item):
        if isinstance(item, dict):
            for key, value in item.items():
                if key.endswith("source_ref") or key.endswith("source_record_ref"):
                    if isinstance(value, str) and value:
                        result.add(value)
                elif key.endswith("source_refs") and isinstance(value, list):
                    result.update(v for v in value if isinstance(v, str) and v)
                collect(value)
        elif isinstance(item, list):
            for value in item:
                collect(value)
    collect(payload["candidate_roster"])
    collect(payload.get("current_mft_pools", []))
    return result


def response_schema(cards, question_id):
    definitions, subjects = {}, {}
    for card in cards:
        components = {}
        for internal in component_ids(card, question_id):
            name = ALIASES.get(internal, internal)
            definitions[name] = {
                "type": "object", "description": TARGETS[name],
                "properties": {
                    "status": {"type": "string", "enum": ["supported", "not_supported", "insufficient"]},
                    "evidence_refs": {"type": "array", "items": {"type": "string"}},
                    "related_object_ids": {"type": "array", "items": {"type": "string"}},
                    "statement": {"type": "string"},
                },
                "required": ["status", "evidence_refs", "related_object_ids", "statement"],
                "additionalProperties": False,
            }
            components[name] = {"$ref": "#/$defs/" + name}
        subjects[card["subject_id"]] = {"type": "object", "properties": components,
            "required": list(components), "additionalProperties": False}
    return {"type": "object", "$defs": definitions,
        "properties": {"assessments": {"type": "object", "properties": subjects,
            "required": list(subjects), "additionalProperties": False}},
        "required": ["assessments"], "additionalProperties": False}


def present_payload(source):
    from fmb.analysis.shared_evidence import EVENT_COLUMNS, unpack_event_records, canonical_json
    value = normalized_payload(source)
    if value["schema_version"] != FACTUAL_EVIDENCE_VERSION:
        raise ValueError("presentation starts from a factual v1 bundle")
    reference_map = {f"r{n:05d}": ref for n, ref in enumerate(sorted(_references(value)), 1)}
    inverse = {ref: key for key, ref in reference_map.items()}
    for card in value["candidate_roster"]:
        for record in card["evidence_records"]:
            if record["record_type"] == "retained_security_event_inventory":
                fields = record["fields"]
                rows = unpack_event_records(fields["retained_event_records"])
                constants = {k: rows[0][k] for k in EVENT_COLUMNS
                             if rows and all(r[k] == rows[0][k] for r in rows)}
                columns = [k for k in EVENT_COLUMNS if k not in constants]
                fields["retained_event_records"] = {
                    "constant_fields": constants, "columns": columns,
                    "column_encodings": {}, "dictionary_index_base": 0,
                    "rows": [[r[k] for k in columns] for r in rows],
                }
    value = _replace_strings(value, inverse)
    value["schema_version"] = PRESENTATION_VERSION
    value["response_schema"] = response_schema(source["candidate_roster"], source["question"]["question_id"])
    value["source_reference_map"] = reference_map
    value["presentation"] = deepcopy(ENCODING)
    by_type = defaultdict(list)
    for card in value["candidate_roster"]:
        for record in card["evidence_records"]:
            fields = record["fields"]
            if record["record_type"] == "logfile_si_update":
                updates = []
                for name in _FIELDS:
                    old, new = "old_si_" + name, "new_si_" + name
                    if old not in fields and new not in fields:
                        continue
                    row = {"field": name}
                    for key, label in ((old, "before"), (new, "after")):
                        if key in fields:
                            row[label + "_utc"] = fields.pop(key)
                            row[label + "_filetime_decimal"] = filetime_decimal(row[label + "_utc"])
                    updates.append(row)
                fields["timestamp_updates"] = updates
                for fragment in fields.get("si_timestamp_fragments", []):
                    for direction in ("undo", "redo"):
                        fragment[direction + "_unsigned_decimal"] = str(int.from_bytes(bytes.fromhex(fragment[direction + "_hex"]), "little"))
            if record["record_type"] == "mft_record" and ":" in fields.get("file_name", ""):
                record["record_type"] = "mft_named_stream_row"
            by_type[record["record_type"]].append(fields)
    defaults = {}
    for kind, rows in by_type.items():
        if len(rows) < 2:
            continue
        shared = {k: v for k, v in rows[0].items()
                  if all(k in r and canonical_json(r[k]) == canonical_json(v) for r in rows[1:])
                  and k not in {"timestamp_updates", "si_timestamp_fragments"}}
        if shared:
            defaults[kind] = deepcopy(shared)
            for row in rows:
                for key in shared:
                    del row[key]
    value["record_field_defaults"] = defaults
    return value


def expand_payload(source):
    from fmb.analysis.shared_evidence import pack_event_records, unpack_event_records
    value = deepcopy(source)
    if value.pop("presentation") != ENCODING:
        raise ValueError("unregistered presentation annotations")
    defaults = value.pop("record_field_defaults")
    references = value.pop("source_reference_map")
    value = _replace_strings(value, references)
    defaults = _replace_strings(defaults, references)
    value["schema_version"] = FACTUAL_EVIDENCE_VERSION
    for card in value["candidate_roster"]:
        for record in card["evidence_records"]:
            fields = {**deepcopy(defaults.get(record["record_type"], {})), **record["fields"]}
            record["fields"] = fields
            if record["record_type"] == "mft_named_stream_row":
                record["record_type"] = "mft_record"
            if record["record_type"] == "logfile_si_update":
                for row in fields.pop("timestamp_updates"):
                    if row["field"] not in _FIELDS:
                        raise ValueError("unregistered SI timestamp field")
                    for prefix, label in (("old_si_", "before"), ("new_si_", "after")):
                        if label + "_utc" in row:
                            utc = row[label + "_utc"]
                            if filetime_decimal(utc) != row[label + "_filetime_decimal"]:
                                raise ValueError("UTC and decimal FILETIME disagree")
                            key = prefix + row["field"]
                            if key in fields:
                                raise ValueError("duplicate timestamp field")
                            fields[key] = utc
                for fragment in fields.get("si_timestamp_fragments", []):
                    for direction in ("undo", "redo"):
                        numeric = fragment.pop(direction + "_unsigned_decimal")
                        if numeric != str(int.from_bytes(bytes.fromhex(fragment[direction + "_hex"]), "little")):
                            raise ValueError("native fragment bytes and decimal value disagree")
            if record["record_type"] == "retained_security_event_inventory":
                fields["retained_event_records"] = pack_event_records(unpack_event_records(fields["retained_event_records"]))
    value["response_schema"] = factual_response_schema(value["candidate_roster"], value["question"]["question_id"])
    return value


def validate_payload(value):
    from fmb.analysis.shared_evidence import validate_evidence_payload, canonical_json
    expanded = expand_payload(value)
    validate_evidence_payload(expanded)
    if canonical_json(present_payload(expanded)) != canonical_json(value):
        raise ValueError("presentation is not the canonical reversible encoding of its evidence")


def present_bundle(bundle):
    from fmb.analysis.shared_evidence import EvidenceBundle, canonical_json
    result = EvidenceBundle.from_payload(present_payload(bundle.payload))
    if canonical_json(expand_payload(result.payload)) != canonical_json(normalized_payload(bundle.payload)):
        raise ValueError("presentation lost native values, types or provenance")
    return result


def expanded_bundle(bundle):
    from fmb.analysis.shared_evidence import EvidenceBundle
    return EvidenceBundle.from_payload(expand_payload(bundle.payload))


def translate_response(bundle, response, *, to_original):
    result = deepcopy(response)
    aliases = {v: k for k, v in ALIASES.items()} if to_original else ALIASES
    references = bundle.payload["source_reference_map"]
    if not to_original:
        references = {v: k for k, v in references.items()}
    for sid, components in result["assessments"].items():
        result["assessments"][sid] = {aliases.get(k, k): v for k, v in components.items()}
        for decision in components.values():
            decision["evidence_refs"] = [references.get(r, r) for r in decision["evidence_refs"]]
    return result
