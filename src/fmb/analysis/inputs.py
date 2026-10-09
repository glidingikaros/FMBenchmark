from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, replace
from typing import Any

from fmb.analysis.catalog import TECHNIQUES, TechniqueDefinition, sufficient_family_sets
from fmb.analysis.domain import (
    AnalysisInput,
    CandidateRoster,
    CandidateSubject,
    EvidenceCoverage,
    Observation,
)
from fmb.index.adapters.registry import is_typed_paths_registry_key
from fmb.index.contract.constants import PARSER_ARTIFACT_FAMILIES_BY_KIND
from fmb.index.contract.evidence_index import validate_candidate_populations
from fmb.index.scanners.usn import ntfs_reference_set_sha256

MAX_CANDIDATE_SUBJECTS = 5000
GENERATION_CONTROL_MARKERS = (
    "fmb_generation_inputs_path",
    "generation_inputs.scenario_inputs",
    "ground_truth_begin",
    "operation_refs",
    "private_assignment",
)
QTIME_REQUIRED_MFT_TIMESTAMP_FIELDS = (
    "si_created",
    "si_modified",
    "si_record_changed",
    "si_accessed",
    "fn_created",
    "fn_modified",
    "fn_record_changed",
    "fn_accessed",
)
FORBIDDEN_INPUT_KEYS = {
    "actual_creation",
    "answer_key",
    "content_snippet",
    "deleted_path",
    "deletion_time",
    "ground_truth",
    "ground_truth_entries",
    "ground_truth_expectations",
    "matched_ground_truth",
    "supported_subject_ids",
    "supported_subjects",
    "expected_supported_subject_ids",
    "expected_supported_subjects",
    "offender_subject_ids",
    "offenders",
    "expected_selection",
    "expected_selection_id",
    "expected_selection_ref",
    "expected_selections",
    "expected_subject_ids",
    "expected_offender_subject_ids",
    "expected_outcome",
    "expected_path",
    "expected_file_name",
    "expected_stream_name",
    "expected_executable_basename",
    "candidate_role",
    "case_role",
    "is_offender",
    "missing_binary",
    "prior_answer",
    "previous_answer",
    "stomped_timestamp",
    "timestamp_cleared",
    "deterministic_result",
    "model_prediction",
    "benchmark_labels",
}


def _is_forbidden_input_key(key: str, *, path: str) -> bool:
    if key == "supported_subject_ids" and path.startswith(
        "llm_packet.response_schema.properties"
    ):
        return False
    return (
        key in FORBIDDEN_INPUT_KEYS
        or "ground_truth" in key
        or "finding_reference" in key
        or key.startswith("expected_case_")
    )


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def assert_truth_blind(value: Any, *, path: str = "evidence_index") -> None:
    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key = str(raw_key).casefold()
            nested_path = f"{path}.{raw_key}"
            if key == "ground_truth_allowed":
                if nested is not False:
                    raise ValueError(
                        f"truth-bearing safety flag must be false: {nested_path}"
                    )
                continue
            if _is_forbidden_input_key(key, path=path):
                raise ValueError(f"truth-bearing field is prohibited: {nested_path}")
            if key == "truth_sources_used" and nested not in (None, [], ()):
                raise ValueError(
                    f"truth-bearing source list is not empty: {nested_path}"
                )
            assert_truth_blind(nested, path=nested_path)
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            assert_truth_blind(nested, path=f"{path}[{index}]")
    elif isinstance(value, str):
        folded = value.casefold()
        for marker in GENERATION_CONTROL_MARKERS:
            if marker in folded:
                raise ValueError(
                    "generation-control marker is prohibited before analysis input "
                    f"construction: {path} contains {marker!r}"
                )


def normalized_subject_label(value: str) -> str:
    normalized = value.replace("/", "\\").strip().casefold()
    if normalized.startswith("\\\\?\\"):
        normalized = normalized[4:]
    return normalized.rstrip("\\")


def is_typed_paths_fields(fields: Mapping[str, Any]) -> bool:

    found = False
    for key in ("source_key", "key_path"):
        if key not in fields:
            continue
        raw_value = fields.get(key)
        if not isinstance(raw_value, str) or not raw_value.strip():
            return False
        if not is_typed_paths_registry_key(raw_value):
            return False
        found = True
    return found


def observation_matches_technique(
    definition: TechniqueDefinition,
    observation: Observation,
) -> bool:

    if (
        definition.technique_id == "typed_path_residue"
        and observation.artifact_family == "windows.registry.typed_paths"
    ):
        return (
            observation.observation_type == "typed_path_seen"
            and is_typed_paths_fields(observation.fields)
        )
    return True


def _path_scope_id(subject_ref: str) -> str | None:
    value = subject_ref.strip().replace("/", "\\")
    folded = value.casefold()
    for prefix in ("\\??\\", "\\\\?\\", "\\\\.\\"):
        if folded.startswith(prefix.casefold()):
            value = value[len(prefix) :]
            folded = value.casefold()
            break
    if len(value) >= 2 and value[1] == ":":
        return f"drive:{value[0].casefold()}"
    if folded.startswith("volume{"):
        return folded.split("\\", 1)[0]
    if value.startswith("\\\\"):
        parts = [item for item in value.split("\\") if item]
        if len(parts) >= 2:
            return f"unc:{parts[0].casefold()}\\{parts[1].casefold()}"
    return None


def observation_object_id(
    fields: Mapping[str, Any], subject_ref: str = ""
) -> str | None:

    scope = next(
        (
            str(fields[key]).strip().casefold()
            for key in ("filesystem_scope_id", "mft_volume_id", "volume_id")
            if fields.get(key) not in (None, "")
        ),
        None,
    ) or _path_scope_id(subject_ref)
    event_scope = fields.get("event_log_scope_id")
    if event_scope not in (None, ""):
        return str(event_scope)
    source_file = fields.get("source_file")
    channel = fields.get("channel")
    if (
        isinstance(source_file, str)
        and source_file.strip()
        and isinstance(channel, str)
        and channel.strip()
    ):
        normalized_channel = channel.strip().casefold()
        source = normalized_subject_label(source_file)
        digest = canonical_sha256(
            {"channel": normalized_channel, "source_file": source}
        )
        return f"event-log:{digest[:24]}"

    entity_id = fields.get("entity_id")
    if entity_id not in (None, ""):
        entity = str(entity_id)
        return f"{scope}:{entity}" if scope is not None else entity
    for entry_key, sequence_key in (
        ("mft_entry", "sequence_number"),
        ("file_reference_entry", "file_reference_sequence"),
    ):
        entry = fields.get(entry_key)
        sequence = fields.get(sequence_key)
        if _is_nonnegative_int(entry) and _is_nonnegative_int(sequence):
            return f"ntfs:{scope}:{entry}:{sequence}" if scope else None
    return None


def ntfs_scope_and_reference_from_identity(
    identity: Mapping[str, str],
) -> tuple[str, tuple[int, int]] | None:
    object_id = identity.get("object_id")
    if not isinstance(object_id, str) or not object_id.startswith("ntfs:"):
        return None
    _scope, separator, sequence_text = object_id.rpartition(":")
    if not separator:
        return None
    scope, separator, entry_text = _scope.rpartition(":")
    if not separator or not scope.startswith("ntfs:"):
        return None
    filesystem_scope_id = scope.removeprefix("ntfs:")
    if not filesystem_scope_id:
        return None
    try:
        entry = int(entry_text)
        sequence = int(sequence_text)
    except ValueError:
        return None
    if not 0 <= entry < (1 << 48) or not 0 <= sequence < (1 << 16):
        return None
    return filesystem_scope_id, (entry, sequence)


def _valid_ntfs_reference(entry: Any, sequence: Any) -> bool:
    return (
        isinstance(entry, int)
        and not isinstance(entry, bool)
        and 0 <= entry < (1 << 48)
        and isinstance(sequence, int)
        and not isinstance(sequence, bool)
        and 0 < sequence < (1 << 16)
    )


def _explicit_target_agrees(
    explicit_target: Any,
    *,
    volume: str,
    target_role: str,
    target: Mapping[str, Any],
    exact_reference: tuple[int, int] | None,
) -> bool:
    if not isinstance(explicit_target, Mapping):
        return False
    if (
        str(explicit_target.get("mft_volume_id") or "").casefold() != volume
        or explicit_target.get("target_role") != target_role
    ):
        return False
    if exact_reference is not None:
        return explicit_target.get("object_id") == target.get("object_id")
    explicit_path = explicit_target.get("canonical_name") or explicit_target.get("path")
    return (
        isinstance(explicit_path, str)
        and normalized_subject_label(explicit_path) == target["canonical_name"]
    )


def _observed_entry_agrees(
    observed: Any, basis: str | None, exact_reference: tuple[int, int]
) -> bool:
    if not isinstance(observed, Mapping) or observed.get("entry") != exact_reference[0]:
        return False
    sequence, in_use = observed.get("sequence"), observed.get("in_use")
    if basis == "file_reference_entry_absent":
        return sequence is None and in_use is None
    if not _valid_ntfs_reference(observed.get("entry"), sequence) or not isinstance(
        in_use, bool
    ):
        return False
    if basis == "file_reference_in_use":
        return sequence == exact_reference[1] and in_use is True
    if basis == "file_reference_record_free":
        return sequence == exact_reference[1] and in_use is False
    if basis == "file_reference_entry_reused":
        return sequence != exact_reference[1] and in_use is True
    if basis == "file_reference_entry_freed":
        return sequence != exact_reference[1] and in_use is False
    return True


def active_mft_presence_fact(
    observation: Observation,
    subject: CandidateSubject,
    *,
    collection_status: str,
    referenced_object: bool = False,
) -> dict[str, Any]:

    fields = observation.fields
    volume = fields.get("mft_volume_id")
    volume = volume.strip().casefold() if isinstance(volume, str) else ""
    basis = fields.get("mft_active_presence_basis")
    basis = basis.strip() if isinstance(basis, str) else None
    target = dict(subject.identity)
    target["mft_volume_id"] = volume or None
    result: dict[str, Any] = {
        "target_identity": target,
        "target_role": "referenced_object" if referenced_object else "candidate",
        "status": "unresolved",
        "basis": basis,
        "collection_status": collection_status,
        "source_record_ref": observation.source_record_ref,
    }
    candidate_reference = ntfs_scope_and_reference_from_identity(subject.identity)
    if referenced_object:
        child_entry = fields.get("file_reference_entry")
        child_sequence = fields.get("file_reference_sequence")
        if _valid_ntfs_reference(child_entry, child_sequence) and volume:
            target = {
                "object_id": f"ntfs:{volume}:{child_entry}:{child_sequence}",
                "mft_volume_id": volume,
            }
            result["target_identity"] = target
        else:
            result["target_identity"] = {"mft_volume_id": volume or None}
            return result
        directory_reference = (fields.get("mft_entry"), fields.get("sequence_number"))
        parent_reference = (
            fields.get("parent_reference_entry"),
            fields.get("parent_reference_sequence"),
        )
        if (
            observation.artifact_family != "ntfs.i30"
            or candidate_reference is None
            or candidate_reference != (volume, directory_reference)
            or parent_reference != directory_reference
            or not _valid_ntfs_reference(*directory_reference)
        ):
            return result
        exact_reference = (child_entry, child_sequence)
    elif candidate_reference is not None:
        if candidate_reference[0] != volume:
            return result
        if observation_object_id(
            fields, observation.subject_ref
        ) != subject.identity.get("object_id"):
            return result
        exact_reference = candidate_reference[1]
        if not _valid_ntfs_reference(*exact_reference):
            return result
        if "file_reference_entry" in fields or "file_reference_sequence" in fields:
            if (
                fields.get("file_reference_entry"),
                fields.get("file_reference_sequence"),
            ) != exact_reference:
                return result
    else:
        if subject.identity.get("object_id") is not None:
            return result
        name = subject.identity.get("canonical_name") or subject.identity.get("path")
        if not isinstance(name, str) or not name.strip():
            return result
        canonical_name = normalized_subject_label(name)
        if normalized_subject_label(observation.subject_ref) != canonical_name:
            return result
        if "path" in fields and (
            not isinstance(fields["path"], str)
            or normalized_subject_label(fields["path"]) != canonical_name
        ):
            return result
        target = {"canonical_name": canonical_name, "mft_volume_id": volume or None}
        result["target_identity"] = target
        exact_reference = None
    if (
        not volume
        or not isinstance(observation.source_record_ref, str)
        or not observation.source_record_ref.strip()
        or fields.get("mft_active_presence_check_supported") is not True
        or collection_status not in {"complete", "partial"}
    ):
        return result
    if any(
        str(fields[key]).strip().casefold() != volume
        for key in ("filesystem_scope_id", "volume_id")
        if fields.get(key) not in (None, "")
    ):
        return result
    state = {
        "active_mft_absent": "absent",
        "active_mft_present": "present",
    }.get(fields.get("mft_active_presence_status"))
    if state is None or (state == "absent" and collection_status != "complete"):
        return result
    if exact_reference is not None:
        combined_reference = fields.get("file_reference_number")
        if "file_reference_number" in fields and (
            not isinstance(combined_reference, int)
            or isinstance(combined_reference, bool)
            or combined_reference != exact_reference[0] + (exact_reference[1] << 48)
        ):
            return result
        allowed_bases = (
            {"file_reference_in_use"}
            if state == "present"
            else {
                "file_reference_entry_absent",
                "file_reference_entry_freed",
                "file_reference_entry_reused",
                "file_reference_record_free",
            }
        )
        match_field = "mft_active_reference_match"
    else:
        allowed_bases = {"basename_volume_search", "path_comparison"}
        match_field = "mft_active_path_match"
        if basis == "basename_volume_search" and "\\" in target["canonical_name"]:
            return result
        if basis == "path_comparison" and "\\" not in target["canonical_name"]:
            return result
    if basis not in allowed_bases:
        return result
    if any(
        key in fields and not isinstance(fields[key], bool)
        for key in ("mft_active_path_match", "mft_active_reference_match")
    ):
        return result
    if match_field in fields and fields[match_field] is not (state == "present"):
        return result
    explicit_target = fields.get("mft_lookup_target")
    if explicit_target is not None and not _explicit_target_agrees(
        explicit_target,
        volume=volume,
        target_role=result["target_role"],
        target=target,
        exact_reference=exact_reference,
    ):
        return result
    observed = fields.get("mft_lookup_observed")
    if (
        observed is not None
        and exact_reference is not None
        and not _observed_entry_agrees(observed, basis, exact_reference)
    ):
        return result
    result["status"] = state
    return result


def coverage_status(value: AnalysisInput, artifact_family: str) -> str:
    return next(
        (
            item.status
            for item in value.coverage
            if item.artifact_family == artifact_family
        ),
        "missing",
    )


def normalized_device_identity(fields: Mapping[str, Any]) -> tuple[str, str]:
    return (
        str(fields.get("device_instance_id") or "")
        .strip()
        .replace("/", "\\")
        .casefold(),
        str(fields.get("serial_number") or "").strip().casefold(),
    )


def setupapi_identity_lookup(
    value: AnalysisInput, subject: CandidateSubject
) -> dict[str, Any]:

    def identity(fields: Mapping[str, Any]) -> tuple[str, str] | None:
        instance = fields.get("device_instance_id")
        serial = fields.get("serial_number")
        if not isinstance(instance, str) or not isinstance(serial, str):
            return None
        instance = instance.strip().replace("/", "\\").casefold()
        serial = serial.strip().casefold()
        if (
            not serial
            or not instance.startswith("usbstor\\")
            or instance.rsplit("\\", 1)[-1] != serial
        ):
            return None
        return instance, serial

    target = identity(subject.identity)
    collection = coverage_status(value, "windows.setupapi")
    result: dict[str, Any] = {
        "target_identity": dict(subject.identity),
        "collection_status": collection,
        "status": "unresolved",
        "exact_match_count": 0,
        "partial_match_count": 0,
        "source_record_refs": [],
        "matching_fields": [],
    }
    if target is None:
        return result
    device_records = [
        item
        for item in value.observations
        if item.observation_id in subject.observation_ids
        and item.artifact_family == "windows.registry.usbstor"
        and item.observation_type == "usb_device_seen"
    ]
    if not device_records:
        return result
    if any(identity(item.fields) != target for item in device_records):
        result["status"] = "conflicting"
        return result
    control_sets = {
        str(item.fields.get("control_set") or "").strip().casefold()
        for item in device_records
    }
    control_sets.discard("")
    if len(control_sets) != 1:
        return result
    for item in value.observations:
        if (
            item.artifact_family != "windows.setupapi"
            or item.observation_type != "setupapi_usb_event"
        ):
            continue
        raw_instance, raw_serial = normalized_device_identity(item.fields)
        exact = identity(item.fields) == target
        partial = not exact and (raw_instance == target[0] or raw_serial == target[1])
        if not exact and not partial:
            continue
        result["exact_match_count" if exact else "partial_match_count"] += 1
        result["source_record_refs"].append(item.source_record_ref)
        result["matching_fields"].append(
            {
                key: item.fields[key]
                for key in (
                    "device_instance_id",
                    "serial_number",
                    "event_timestamp",
                    "timestamp_basis",
                )
                if key in item.fields
            }
        )
    if result["partial_match_count"]:
        result["status"] = "conflicting"
    elif (
        result["exact_match_count"]
        and collection in {"complete", "partial"}
        and all(result["source_record_refs"])
    ):
        result["status"] = "present"
    elif not result["exact_match_count"] and collection == "complete":
        result["status"] = "absent"
    return result


def population_ntfs_scope_and_references(
    population: Mapping[str, Any],
) -> tuple[str, set[tuple[int, int]]] | None:
    subjects = population.get("subjects")
    if not isinstance(subjects, list) or not subjects:
        return None
    scopes: set[str] = set()
    references: set[tuple[int, int]] = set()
    for subject in subjects:
        if not isinstance(subject, Mapping):
            return None
        identity = subject.get("identity")
        if not isinstance(identity, Mapping):
            return None
        scoped_reference = ntfs_scope_and_reference_from_identity(identity)
        if scoped_reference is None:
            return None
        scope, reference = scoped_reference
        scopes.add(scope)
        references.add(reference)
    if len(scopes) != 1 or len(references) != len(subjects):
        return None
    return next(iter(scopes)), references


def _stream_base_label(subject_ref: str, fields: Mapping[str, Any]) -> str:
    explicit = fields.get("base_path")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    stream_name = str(fields.get("stream_name") or "").strip().casefold()
    subject = subject_ref.strip()
    separator = subject.find(":", 2)
    if separator < 0:
        return subject
    suffix = subject[separator + 1 :].casefold()
    suffix_name = suffix.split(":", 1)[0]
    if stream_name and suffix_name == stream_name:
        return subject[:separator]
    return subject


def candidate_identity(
    definition: TechniqueDefinition, observation: Observation
) -> tuple[str, dict[str, str]]:
    path = normalized_subject_label(observation.subject_ref)
    object_id = observation_object_id(observation.fields, observation.subject_ref)
    if definition.technique_id == "alternate_data_stream":
        base_label = _stream_base_label(observation.subject_ref, observation.fields)
        identity = (
            {"object_id": object_id}
            if object_id is not None
            else {"canonical_name": normalized_subject_label(base_label)}
        )
        return base_label, identity
    if definition.subject_type == "device":
        instance, serial = normalized_device_identity(observation.fields)
        identity = {}
        if instance:
            identity["device_instance_id"] = instance
        if serial:
            identity["serial_number"] = serial
        if not identity:
            identity["canonical_name"] = path
        return observation.subject_ref, identity
    identity = (
        {"object_id": object_id} if object_id is not None else {"canonical_name": path}
    )
    return observation.subject_ref, identity


def _subject_id(subject_type: str, identity: Mapping[str, str]) -> str:
    digest = canonical_sha256(
        {"subject_type": subject_type, "identity": dict(identity)}
    )
    return f"subject:{digest[:24]}"


def evidence_index_sha256(evidence_index: Mapping[str, Any]) -> str:
    return canonical_sha256(evidence_index)


def analysis_input_payload(value: AnalysisInput) -> dict[str, Any]:

    payload = asdict(value)
    payload.pop("input_id", None)
    payload.pop("input_sha256", None)
    return payload


def candidate_roster_payload(value: CandidateRoster) -> dict[str, Any]:

    payload = asdict(value)
    payload.pop("roster_id", None)
    payload.pop("roster_sha256", None)
    return payload


def sealed_candidate_roster(value: CandidateRoster) -> CandidateRoster:
    digest = canonical_sha256(candidate_roster_payload(value))
    return replace(value, roster_id=f"roster:{digest[:24]}", roster_sha256=digest)


def sealed_analysis_input(value: AnalysisInput) -> AnalysisInput:
    digest = canonical_sha256(analysis_input_payload(value))
    return replace(value, input_id=f"input:{digest[:24]}", input_sha256=digest)


def assert_candidate_roster_integrity(value: CandidateRoster) -> None:
    observed = canonical_sha256(candidate_roster_payload(value))
    if value.roster_sha256 != observed:
        raise ValueError("candidate roster integrity hash does not match its payload")
    if value.roster_id != f"roster:{observed[:24]}":
        raise ValueError("candidate roster id does not match its integrity hash")
    subject_ids = value.subject_ids()
    if subject_ids != tuple(sorted(set(subject_ids))):
        raise ValueError("candidate roster subject IDs must be sorted and unique")
    for subject in value.subjects:
        if subject.subject_id != _subject_id(subject.subject_type, subject.identity):
            raise ValueError("candidate subject id does not match its identity")
        if subject.observation_ids != tuple(sorted(set(subject.observation_ids))):
            raise ValueError(
                "candidate subject observation IDs must be sorted and unique"
            )


def assert_analysis_input_integrity(value: AnalysisInput) -> None:
    assert_candidate_roster_integrity(value.candidate_roster)
    roster = value.candidate_roster
    if (
        roster.question_id != value.question_id
        or roster.technique_id != value.technique_id
        or roster.evidence_index_id != value.evidence_index_ref
        or roster.evidence_index_hash != value.evidence_index_sha256
    ):
        raise ValueError("candidate roster scope does not match the analysis input")
    observation_ids = tuple(item.observation_id for item in value.observations)
    if observation_ids != tuple(sorted(set(observation_ids))):
        raise ValueError("analysis input observation IDs must be sorted and unique")
    if value.projected_observation_ids != observation_ids:
        raise ValueError(
            "projected observation IDs must match the analysis input observations"
        )
    owned_observation_ids = tuple(
        observation_id
        for subject in roster.subjects
        for observation_id in subject.observation_ids
    )
    if len(owned_observation_ids) != len(set(owned_observation_ids)) or set(
        owned_observation_ids
    ) != set(observation_ids):
        raise ValueError(
            "every projected observation must belong to exactly one candidate subject"
        )
    observed = canonical_sha256(analysis_input_payload(value))
    if value.input_sha256 != observed:
        raise ValueError("analysis input integrity hash does not match its payload")
    if value.input_id != f"input:{observed[:24]}":
        raise ValueError("analysis input id does not match its integrity hash")


def iter_observations(evidence_index: Mapping[str, Any]) -> Iterable[Observation]:
    seen: set[str] = set()
    for parser_run in evidence_index.get("parser_runs", []):
        if not isinstance(parser_run, Mapping):
            continue
        for raw in parser_run.get("observations", []):
            if not isinstance(raw, Mapping):
                continue
            observation_id = str(raw.get("observation_id") or "")
            if not observation_id:
                continue
            if observation_id in seen:
                raise ValueError(
                    f"duplicate observation_id in evidence index: {observation_id}"
                )
            artifact_family = str(raw.get("artifact_family") or "")
            observation_type = str(raw.get("observation_type") or "")
            subject_ref = str(raw.get("subject_ref") or "")
            fields = raw.get("fields")
            source_record_ref = str(raw.get("source_record_ref") or "")
            if not artifact_family or not observation_type or not subject_ref:
                continue
            if not isinstance(fields, dict):
                fields = {}
            seen.add(observation_id)
            yield Observation(
                observation_id=observation_id,
                artifact_family=artifact_family,
                observation_type=observation_type,
                subject_ref=subject_ref,
                fields=dict(fields),
                source_record_ref=source_record_ref,
            )


def _validated_candidate_populations(
    evidence_index: Mapping[str, Any],
    observations: tuple[Observation, ...],
) -> tuple[Mapping[str, Any], ...]:
    raw_populations = evidence_index.get("candidate_populations", [])
    if not isinstance(raw_populations, list):
        raise ValueError("candidate_populations must be a list")
    parser_runs = [
        dict(item)
        for item in evidence_index.get("parser_runs", [])
        if isinstance(item, Mapping)
    ]
    validated = validate_candidate_populations(
        raw_populations,
        parser_runs=parser_runs,
    )
    definitions = {(item.question_id, item.technique_id): item for item in TECHNIQUES}
    observation_by_id = {item.observation_id: item for item in observations}
    for index, raw_population in enumerate(validated):
        label = f"candidate population {index}"
        question_id = raw_population.get("question_id")
        technique_id = raw_population.get("technique_id")
        subject_type = raw_population.get("subject_type")
        scope = (str(question_id), str(technique_id))
        definition = definitions.get(scope)
        if definition is None:
            raise ValueError(
                f"{label} references unknown question/technique: {scope[0]}/{scope[1]}"
            )
        if subject_type != definition.subject_type:
            raise ValueError(
                f"{label} subject_type does not match {definition.technique_id}"
            )
        raw_subjects = raw_population["subjects"]
        if len(raw_subjects) > MAX_CANDIDATE_SUBJECTS:
            raise ValueError(
                f"candidate roster exceeds limit of {MAX_CANDIDATE_SUBJECTS} subjects"
            )
        for subject_index, raw_subject in enumerate(raw_subjects):
            subject_label = f"{label} subject {subject_index}"
            expected_identity = dict(raw_subject["identity"])
            for observation_id in raw_subject["observation_ids"]:
                observation = observation_by_id[observation_id]
                if (
                    observation.artifact_family
                    not in definition.projected_artifact_families
                ):
                    raise ValueError(
                        f"{subject_label} observation {observation_id} is outside "
                        f"technique {definition.technique_id}"
                    )
                if not observation_matches_technique(definition, observation):
                    raise ValueError(
                        f"{subject_label} observation {observation_id} is outside "
                        f"the bounded claim for {definition.technique_id}"
                    )
                _display_name, observed_identity = candidate_identity(
                    definition, observation
                )
                if observed_identity != expected_identity:
                    raise ValueError(
                        f"{subject_label} observation {observation_id} does not "
                        "match subject identity"
                    )
    return tuple(validated)


def _explicit_coverage(evidence_index: Mapping[str, Any]) -> dict[str, str]:
    raw = evidence_index.get("artifact_coverage", [])
    if isinstance(raw, Mapping):
        return {
            str(family): str(status)
            for family, status in raw.items()
            if isinstance(family, str) and isinstance(status, str)
        }
    result: dict[str, str] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            family = item.get("artifact_family")
            status = item.get("status")
            if isinstance(family, str) and isinstance(status, str):
                result[family] = status
    return result


def _scope_interval(scope: Mapping[str, Any]) -> dict[str, Any] | None:
    first = next(
        (scope[key] for key in ("first_timestamp", "first_section_timestamp", "first_time_created")
         if isinstance(scope.get(key), str) and scope[key]),
        None,
    )
    last = next(
        (scope[key] for key in ("last_timestamp", "last_section_timestamp", "last_time_created")
         if isinstance(scope.get(key), str) and scope[key]),
        None,
    )
    if first is None or last is None:
        return None
    files = scope.get("files")
    source = (
        files[0]
        if isinstance(files, list) and files and isinstance(files[0], str)
        else scope.get("source_file")
    )
    interval: dict[str, Any] = {
        "source_file": source,
        "first": first,
        "last": last,
        "complete": bool(scope.get("window_complete")),
    }
    for key in ("journal_id", "first_usn", "last_usn", "lowest_valid_usn", "window_validity",
                "control_identity_bound", "journal_source", "order_checked", "checked_record_count",
                "timestamp_reversal_count", "last_section_end_timestamp"):
        if key in scope:
            interval[key] = scope[key]
    return interval


def _gap_count(intervals: list[Any]) -> int:
    ordered = sorted(
        (item for item in intervals if isinstance(item, Mapping)),
        key=lambda item: (str(item.get("first")), str(item.get("last"))),
    )
    return sum(
        1
        for earlier, later in zip(ordered, ordered[1:], strict=False)
        if str(later.get("first")) > str(earlier.get("last"))
    )


def _scope_identity(scope: Mapping[str, Any]) -> Any:
    journal_id = scope.get("journal_id")
    return (journal_id, scope.get("journal_source")) if journal_id is not None else None


SHELLBAG_HIVE_SCOPE_FIELDS = (
    "user", "hive", "hive_path", "hive_present", "source_file",
    "directory_record_count", "unresolved_record_count",
)


def _merge_shellbag_hives(existing: Mapping[str, Any], incoming: Mapping[str, Any]) -> dict[str, Any]:
    def hives(scope: Mapping[str, Any]) -> list[dict[str, Any]]:
        listed = scope.get("hives")
        if isinstance(listed, list):
            return [dict(item) for item in listed]
        return [{key: scope.get(key) for key in SHELLBAG_HIVE_SCOPE_FIELDS}]

    merged_hives = hives(existing)
    for item in hives(incoming):
        if item not in merged_hives:
            merged_hives.append(item)
    merged_hives.sort(key=lambda item: (str(item.get("user")), str(item.get("hive")), str(item.get("source_file"))))
    return {
        "kind": "shellbag_hives",
        "hives": merged_hives,
        "hive_present": all(item.get("hive_present") is True for item in merged_hives),
        "directory_record_count": sum(int(item.get("directory_record_count") or 0) for item in merged_hives),
        "unresolved_record_count": sum(int(item.get("unresolved_record_count") or 0) for item in merged_hives),
        "intervals": [],
        "gap_count": 0,
        "identity_conflict": bool(existing.get("identity_conflict") or incoming.get("identity_conflict")),
    }


def _merge_coverage_scopes(
    existing: dict[str, Any] | None, incoming: Mapping[str, Any]
) -> dict[str, Any]:
    scope = dict(incoming)
    if scope.get("kind") == "shellbag_hives" and existing is None:
        return _merge_shellbag_hives(scope, scope)
    if existing is None:
        if not isinstance(scope.get("intervals"), list):
            interval = _scope_interval(scope)
            scope["intervals"] = [interval] if interval is not None else []
        scope.setdefault("gap_count", _gap_count(scope["intervals"]))
        scope.setdefault("identity_conflict", False)
        return scope
    if existing.get("kind") != scope.get("kind"):
        return existing
    if scope.get("kind") == "shellbag_hives":
        return _merge_shellbag_hives(existing, scope)
    merged = dict(existing)
    intervals = [dict(item) for item in existing.get("intervals", []) or []]
    incoming_intervals = (
        [dict(item) for item in scope["intervals"]]
        if isinstance(scope.get("intervals"), list)
        else [item for item in (_scope_interval(scope),) if item is not None]
    )
    for incoming_interval in incoming_intervals:
        if incoming_interval not in intervals:
            intervals.append(incoming_interval)
    intervals.sort(key=lambda item: (str(item["first"]), str(item["last"])))
    merged["intervals"] = intervals
    for key in ("first_timestamp", "first_section_timestamp", "first_time_created"):
        values = [item[key] for item in (existing, scope) if isinstance(item.get(key), str) and item[key]]
        if values:
            merged[key] = min(values)
    for key in ("last_timestamp", "last_section_timestamp", "last_time_created", "last_section_end_timestamp"):
        values = [item[key] for item in (existing, scope) if isinstance(item.get(key), str) and item[key]]
        if values:
            merged[key] = max(values)
    for key in ("first_usn", "first_record_id"):
        values = [item[key] for item in (existing, scope) if isinstance(item.get(key), int)]
        if values:
            merged[key] = min(values)
    for key in ("last_usn", "last_record_id"):
        values = [item[key] for item in (existing, scope) if isinstance(item.get(key), int)]
        if values:
            merged[key] = max(values)
    files = []
    for item in (existing, scope):
        for name in item.get("files", []) or []:
            if name not in files:
                files.append(name)
    if files:
        merged["files"] = files
    merged["gap_count"] = _gap_count(intervals)
    identities = {
        _scope_identity(item)
        for item in (existing, scope)
        if _scope_identity(item) is not None
    }
    identity_conflict = bool(existing.get("identity_conflict")) or len(identities) > 1
    merged["identity_conflict"] = identity_conflict
    if "window_complete" in existing or "window_complete" in scope:
        merged["window_complete"] = bool(
            intervals
            and all(item.get("complete") for item in intervals)
            and not identity_conflict
        )
        if merged.get("kind") == "setupapi_log":
            merged["window_complete"] = bool(
                merged["window_complete"] and existing.get("window_complete")
                and scope.get("window_complete")
            )
    if any("timestamp_reversal_count" in item for item in (existing, scope)):
        merged["timestamp_reversal_count"] = max(
            int(item.get("timestamp_reversal_count") or 0) for item in (existing, scope)
        )
    for key, value in scope.items():
        if key not in merged or merged[key] in (None, ""):
            merged[key] = value
    if merged.get("kind") == "usn_journal" and intervals:
        valid = all(
            item.get("window_validity") == "retained_records_within_valid_range"
            and item.get("control_identity_bound") is True
            and type(item.get("journal_id")) is int and item["journal_id"] > 0
            and type(item.get("lowest_valid_usn")) is int
            and type(item.get("first_usn")) is int
            and type(item.get("last_usn")) is int
            and 0 <= item["lowest_valid_usn"] <= item["first_usn"] <= item["last_usn"]
            for item in intervals
        )
        merged["window_validity"] = (
            "retained_records_within_valid_range" if valid else "unverified_contributing_interval"
        )
        merged["window_complete"] = bool(
            merged.get("window_complete") and valid and not merged["gap_count"]
        )
        merged["control_identity_bound"] = all(item.get("control_identity_bound") is True for item in intervals)
        merged["order_checked"] = all(
            item.get("order_checked") is True
            and type(item.get("checked_record_count")) is int and item["checked_record_count"] > 0
            and type(item.get("timestamp_reversal_count")) is int and item["timestamp_reversal_count"] >= 0
            for item in intervals
        )
        merged["checked_record_count"] = max(
            (item.get("checked_record_count", 0) for item in intervals if type(item.get("checked_record_count")) is int),
            default=0,
        )
        counts = [item.get("record_count") for item in (existing, scope)]
        merged["record_count"] = max((n for n in counts if type(n) is int), default=0)
    return merged


def inferred_coverage_scopes(evidence_index: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw_run in evidence_index.get("parser_runs", []):
        if not isinstance(raw_run, Mapping):
            continue
        scope = raw_run.get("coverage_scope")
        if not isinstance(scope, Mapping) or not isinstance(scope.get("kind"), str):
            continue
        parser_kind = raw_run.get("parser_kind")
        families = raw_run.get("coverage_families")
        if not (isinstance(families, list) and all(isinstance(item, str) for item in families)):
            families = list(PARSER_ARTIFACT_FAMILIES_BY_KIND.get(str(parser_kind), ()))
        for family in families:
            result[family] = _merge_coverage_scopes(result.get(family), scope)
    return result


def _inferred_coverage(evidence_index: Mapping[str, Any]) -> dict[str, str]:
    result = _explicit_coverage(evidence_index)
    explicit_families = set(result)
    for raw_run in evidence_index.get("parser_runs", []):
        if not isinstance(raw_run, Mapping):
            continue
        parser_kind = raw_run.get("parser_kind")
        if not isinstance(parser_kind, str):
            continue
        supported_families = PARSER_ARTIFACT_FAMILIES_BY_KIND.get(parser_kind, ())
        declared_families = raw_run.get("coverage_families")
        if isinstance(declared_families, list) and all(
            isinstance(item, str) for item in declared_families
        ):
            families = tuple(
                item for item in declared_families if item in supported_families
            )
        else:
            families = supported_families
        declared_coverage = str(raw_run.get("coverage_status") or "").casefold()
        if declared_coverage in {"complete", "partial", "missing"}:
            status = declared_coverage
        else:
            status = "partial"
        for family in families:
            if family in explicit_families:
                continue
            previous = result.get(family)
            if previous is None:
                result[family] = status
            elif previous != status:
                result[family] = "partial"
    return result


def _has_resolved_active_mft_state(observation: Observation) -> bool:
    return bool(
        observation.fields.get("mft_active_presence_check_supported") is True
        and observation.fields.get("mft_active_presence_status")
        in {"active_mft_absent", "active_mft_present"}
        and str(observation.fields.get("mft_active_presence_basis") or "").strip()
        and str(observation.fields.get("mft_volume_id") or "").strip()
    )


def _population_has_complete_active_mft_checks(
    subjects: list[Any],
    observation_by_id: Mapping[str, Observation],
    *,
    observation_types: set[str],
) -> bool:
    for subject in subjects:
        if not isinstance(subject, Mapping):
            return False
        relevant = tuple(
            observation
            for observation_id in subject.get("observation_ids", [])
            if (observation := observation_by_id.get(str(observation_id))) is not None
            and observation.observation_type in observation_types
        )
        if not relevant or not all(
            _has_resolved_active_mft_state(item) for item in relevant
        ):
            return False
    return True


_ACTIVE_MFT_OBSERVATION_TYPES_BY_TECHNIQUE = {
    "typed_path_residue": {"typed_path_seen"},
    "shellbag_missing_directory": {"shellbag_path_seen"},
    "prefetch_missing_executable": {"prefetch_execution"},
    "shimcache_path_residue": {"shimcache_path_seen"},
}


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def i30_scan_surface_complete(fields: Mapping[str, Any]) -> bool:
    if not (fields.get("scan_complete") is True
            and fields.get("resident_index_root_scanned") is True
            and fields.get("mft_record_slack_scanned") is True):
        return False
    surface = fields.get("supported_surface")
    if surface == "resident_index_root_and_mft_record_slack":
        return (fields.get("index_allocation_parsed") is False
                and fields.get("index_allocation_present") is not True)
    if surface == "resident_index_root_mft_slack_and_index_allocation":
        return (fields.get("index_allocation_present") is False
                or (fields.get("index_allocation_present") is True
                    and fields.get("index_allocation_parsed") is True))
    return False


def _population_has_complete_i30_mft_surface(
    subjects: list[Any],
    observation_by_id: Mapping[str, Observation],
) -> bool:
    for subject in subjects:
        if not isinstance(subject, Mapping):
            return False
        selected = tuple(
            observation
            for observation_id in subject.get("observation_ids", [])
            if (observation := observation_by_id.get(str(observation_id))) is not None
            and observation.observation_type
            in {"i30_directory_scan", "i30_filename_residue"}
        )
        scans = tuple(
            item for item in selected if item.observation_type == "i30_directory_scan"
        )
        residues = tuple(
            item
            for item in selected
            if item.observation_type == "i30_filename_residue"
            and item.fields.get("i30_entry_state") in {"slack", "unlinked"}
        )
        if len(scans) != 1:
            return False
        fields = scans[0].fields
        if not (
            i30_scan_surface_complete(fields)
            and _is_nonnegative_int(fields.get("mft_entry"))
            and _is_nonnegative_int(fields.get("sequence_number"))
            and fields["sequence_number"] > 0
            and str(fields.get("mft_volume_id") or "").strip()
            and _is_nonnegative_int(fields.get("residue_count"))
            and fields["residue_count"] == len(residues)
            and all(_has_resolved_active_mft_state(item) for item in residues)
        ):
            return False
    return True


def _storage_record_proves_raw_mft_support(observation: Observation) -> bool:
    fields = observation.fields
    resident_status = fields.get("resident_status")
    runlist_complete = fields.get("runlist_complete")
    runlist_valid = (
        runlist_complete is True
        if resident_status == "nonresident"
        else runlist_complete in {None, True}
    )
    return bool(
        observation.observation_type == "logical_allocated_size_record"
        and str(fields.get("volume_id") or "").strip()
        and _is_nonnegative_int(fields.get("mft_entry"))
        and _is_nonnegative_int(fields.get("sequence_number"))
        and fields.get("stream_name") == ""
        and resident_status in {"resident", "nonresident"}
        and _is_nonnegative_int(fields.get("attribute_flags"))
        and fields.get("attribute_parse_error_count") == 0
        and all(
            isinstance(fields.get(key), bool)
            for key in ("is_sparse", "is_compressed", "is_encrypted")
        )
        and fields.get("mftecmd_identity_match") is True
        and fields.get("attribute_chain_complete") is True
        and runlist_valid
        and fields.get("lowest_vcn") == 0
        and _is_nonnegative_int(fields.get("logical_size"))
        and _is_nonnegative_int(fields.get("mftecmd_file_size"))
    )


def _population_has_complete_file_size_mft_surface(
    subjects: list[Any],
    observation_by_id: Mapping[str, Observation],
) -> bool:
    for subject in subjects:
        if not isinstance(subject, Mapping):
            return False
        storage = tuple(
            observation
            for observation_id in subject.get("observation_ids", [])
            if (observation := observation_by_id.get(str(observation_id))) is not None
            and observation.observation_type == "logical_allocated_size_record"
        )
        if len(storage) != 1 or not _storage_record_proves_raw_mft_support(storage[0]):
            return False
    return True


def _mft_record_proves_reference_state(observation: Observation) -> bool:
    fields = observation.fields
    return bool(
        observation.artifact_family == "ntfs.mft"
        and observation.observation_type == "mft_file_record"
        and str(fields.get("mft_volume_id") or "").strip()
        and _is_nonnegative_int(fields.get("mft_entry"))
        and _is_nonnegative_int(fields.get("sequence_number"))
        and isinstance(fields.get("in_use"), bool)
        and fields.get("raw_mft_timestamp_validation") == "verified"
    )


def _population_has_complete_deleted_mft_surface(
    subjects: list[Any],
    observation_by_id: Mapping[str, Observation],
) -> bool:
    for subject in subjects:
        if not isinstance(subject, Mapping):
            return False
        selected = tuple(
            observation
            for observation_id in subject.get("observation_ids", [])
            if (observation := observation_by_id.get(str(observation_id))) is not None
        )
        journal_records = tuple(
            item
            for item in selected
            if item.observation_type in {"usn_file_delete", "usn_rename_old_name"}
        )
        if journal_records:
            if not all(
                _has_resolved_active_mft_state(item) for item in journal_records
            ):
                return False
            continue
        if not any(_mft_record_proves_reference_state(item) for item in selected):
            return False
    return True


def _reference_scan_runs(
    evidence_index: Mapping[str, Any],
    *,
    parser_kind: str,
    tool_name: str,
    filesystem_scope_id: str,
    reference_sha256: str,
) -> list[Mapping[str, Any]]:
    runs: list[Mapping[str, Any]] = []
    for parser_run in evidence_index.get("parser_runs", []):
        if not isinstance(parser_run, Mapping):
            continue
        selection_scope = parser_run.get("selection_scope")
        tool_identity = parser_run.get("tool_identity")
        if (
            parser_run.get("parser") == "fmb_bounded_parser"
            and parser_run.get("parser_kind") == parser_kind
            and isinstance(tool_identity, Mapping)
            and tool_identity.get("name") == tool_name
            and isinstance(selection_scope, Mapping)
            and selection_scope.get("kind") == "ntfs_file_references"
            and selection_scope.get("filesystem_scope_id") == filesystem_scope_id
            and selection_scope.get("reference_sha256") == reference_sha256
        ):
            runs.append(parser_run)
    return runs


def _reference_scan_complete(
    parser_run: Mapping[str, Any], *, reference_count: int, matched_record_count: Any
) -> bool:
    selection_scope = parser_run["selection_scope"]
    parser_observations = parser_run.get("observations")
    raw_outputs = parser_run.get("raw_outputs")
    normalized_output = parser_run.get("normalized_output")
    normalized_count = selection_scope.get("normalized_record_count")
    return (
        selection_scope.get("reference_count") == reference_count
        and selection_scope.get("matched_record_count") == matched_record_count
        and selection_scope.get("retained_record_count") == normalized_count
        and selection_scope.get("source_bytes_covered")
        == selection_scope.get("source_size_bytes")
        and selection_scope.get("status") == "complete"
        and parser_run.get("observation_count") == normalized_count
        and isinstance(parser_observations, list)
        and len(parser_observations) == normalized_count
        and isinstance(raw_outputs, list)
        and len(raw_outputs) == 1
        and isinstance(raw_outputs[0], Mapping)
        and raw_outputs[0].get("size_bytes") == selection_scope.get("source_size_bytes")
        and isinstance(normalized_output, Mapping)
        and normalized_output.get("record_count") == normalized_count
    )


def _population_has_complete_ads_surface(
    population: Mapping[str, Any],
    observation_by_id: Mapping[str, Observation],
    evidence_index: Mapping[str, Any],
) -> bool:
    scoped_references = population_ntfs_scope_and_references(population)
    if scoped_references is None:
        return False
    filesystem_scope_id, references = scoped_references
    matching_runs = _reference_scan_runs(
        evidence_index,
        parser_kind="ntfs_ads",
        tool_name="fmb.ads.truth_blind_reference_scanner",
        filesystem_scope_id=filesystem_scope_id,
        reference_sha256=ntfs_reference_set_sha256(references),
    )
    if len(matching_runs) != 1:
        return False
    parser_run = matching_runs[0]
    selection_scope = parser_run["selection_scope"]
    normalized_count = selection_scope.get("normalized_record_count")
    if not (
        _is_nonnegative_int(selection_scope.get("matched_record_count"))
        and _is_nonnegative_int(normalized_count)
        and _is_nonnegative_int(selection_scope.get("retained_record_count"))
        and _reference_scan_complete(
            parser_run,
            reference_count=len(references),
            matched_record_count=len(references) + normalized_count,
        )
    ):
        return False
    seen_ids: set[str] = set()
    named_references: set[tuple[int, int]] = set()
    named_reference_counts: dict[tuple[int, int], int] = {}
    named_stream_counts: dict[str, int] = {}
    validated_fields: list[Mapping[str, Any]] = []
    for raw in parser_run["observations"]:
        if not isinstance(raw, Mapping):
            return False
        observation_id = raw.get("observation_id")
        fields = raw.get("fields")
        if (
            not isinstance(observation_id, str)
            or observation_id in seen_ids
            or observation_id not in observation_by_id
            or raw.get("artifact_family") != "ntfs.ads"
            or raw.get("observation_type") != "named_data_stream"
            or not isinstance(fields, Mapping)
            or fields.get("mft_volume_id") != filesystem_scope_id
            or not _is_nonnegative_int(fields.get("mft_entry"))
            or not _is_nonnegative_int(fields.get("sequence_number"))
            or (fields["mft_entry"], fields["sequence_number"]) not in references
            or not str(fields.get("stream_name") or "").strip()
            or str(fields.get("stream_name")).strip().casefold() == "$data"
            or fields.get("in_use") is not True
            or fields.get("has_ads") is not True
        ):
            return False
        seen_ids.add(observation_id)
        reference = (fields["mft_entry"], fields["sequence_number"])
        stream_name = str(fields["stream_name"]).strip().casefold()
        named_references.add(reference)
        named_reference_counts[reference] = named_reference_counts.get(reference, 0) + 1
        named_stream_counts[stream_name] = named_stream_counts.get(stream_name, 0) + 1
        validated_fields.append(fields)
    named_host_count = len(named_references)
    for fields in validated_fields:
        stream_name = str(fields["stream_name"]).strip().casefold()
        reference = (fields["mft_entry"], fields["sequence_number"])
        if not (
            fields.get("host_population_complete") is True
            and fields.get("host_population_size") == len(references)
            and fields.get("hosts_without_named_stream_count")
            == len(references) - named_host_count
            and fields.get("host_named_stream_count")
            == named_reference_counts[reference]
            and fields.get("stream_name_occurrences")
            == named_stream_counts[stream_name]
        ):
            return False
    return True


def _population_scoped_complete_families(
    population: Mapping[str, Any] | None,
    observations: tuple[Observation, ...],
    definition: TechniqueDefinition,
    evidence_index: Mapping[str, Any],
) -> set[str]:
    if population is None or population.get("coverage_status") != "complete":
        return set()
    subjects = population.get("subjects")
    if not isinstance(subjects, list) or not subjects:
        return set()
    observation_by_id = {item.observation_id: item for item in observations}
    complete: set[str] = set()
    for family in definition.required_artifact_families:
        if family not in definition.candidate_artifact_families:
            continue
        if all(
            any(
                observation_by_id.get(str(observation_id)) is not None
                and observation_by_id[str(observation_id)].artifact_family == family
                for observation_id in subject.get("observation_ids", [])
            )
            for subject in subjects
            if isinstance(subject, Mapping)
        ):
            complete.add(family)
    active_mft_observation_types = _ACTIVE_MFT_OBSERVATION_TYPES_BY_TECHNIQUE.get(
        definition.technique_id
    )
    if active_mft_observation_types and _population_has_complete_active_mft_checks(
        subjects,
        observation_by_id,
        observation_types=active_mft_observation_types,
    ):
        complete.add("ntfs.mft")
    if (
        definition.technique_id == "i30_directory_residue"
        and _population_has_complete_i30_mft_surface(subjects, observation_by_id)
    ):
        complete.add("ntfs.mft")
    if (
        definition.technique_id == "bitmap_trailing_data"
        and _population_has_complete_file_size_mft_surface(subjects, observation_by_id)
    ):
        complete.add("ntfs.mft")
    if definition.technique_id == "ntfs_allocation_inconsistency":
        if all(any(
            (observation := observation_by_id.get(str(identifier))) is not None
            and observation.observation_type == "ntfs_allocation_record"
            and observation.fields.get("native_identity_verified") is True
            and observation.fields.get("attribute_chain_complete") is True
            for identifier in subject.get("observation_ids", [])
        ) for subject in subjects):
            complete.add("ntfs.mft")
    if (
        definition.technique_id == "deleted_file_journal_residue"
        and _population_has_complete_deleted_mft_surface(subjects, observation_by_id)
    ):
        complete.add("ntfs.mft")
    if definition.technique_id == "alternate_data_stream" and (
        _population_has_complete_ads_surface(
            population,
            observation_by_id,
            evidence_index,
        )
    ):
        complete.update({"ntfs.ads", "ntfs.mft"})
    scoped_references = population_ntfs_scope_and_references(population)
    if (
        scoped_references is not None
        and "ntfs.usn" in definition.required_artifact_families
    ):
        filesystem_scope_id, references = scoped_references
        if any(
            _reference_scan_complete(
                parser_run,
                reference_count=len(references),
                matched_record_count=parser_run["selection_scope"].get(
                    "retained_record_count"
                ),
            )
            for parser_run in _reference_scan_runs(
                evidence_index,
                parser_kind="ntfs_usn",
                tool_name="fmb.usn.truth_blind_reference_scanner",
                filesystem_scope_id=filesystem_scope_id,
                reference_sha256=ntfs_reference_set_sha256(references),
            )
        ):
            complete.add("ntfs.usn")
    return complete


def _population_scoped_partial_families(
    population: Mapping[str, Any] | None,
    observations: tuple[Observation, ...],
    definition: TechniqueDefinition,
) -> set[str]:
    if (
        population is None
        or definition.question_id != "Q-TIME-01"
        or definition.technique_id != "timestamp_manipulation"
    ):
        return set()
    observation_by_id = {item.observation_id: item for item in observations}
    for subject in population.get("subjects", []):
        if not isinstance(subject, Mapping):
            return {"ntfs.mft"}
        complete_mft_record = any(
            (observation := observation_by_id.get(str(observation_id))) is not None
            and observation.artifact_family == "ntfs.mft"
            and observation.observation_type
            in {"mft_file_record", "si_fn_timestamp_difference"}
            and observation.fields.get("raw_mft_timestamp_validation") == "verified"
            and all(
                observation.fields.get(field_name) not in (None, "")
                for field_name in QTIME_REQUIRED_MFT_TIMESTAMP_FIELDS
            )
            for observation_id in subject.get("observation_ids", [])
        )
        if not complete_mft_record:
            return {"ntfs.mft"}
    return set()


def _population_with_matching_observations(
    population: Mapping[str, Any],
    observations: tuple[Observation, ...],
    definition: TechniqueDefinition,
) -> dict[str, Any]:
    enriched = dict(population)
    subjects = [dict(item) for item in population["subjects"]]
    observation_by_id = {item.observation_id: item for item in observations}
    subjects_by_identity = {
        tuple(sorted(dict(subject["identity"]).items())): subject
        for subject in subjects
    }
    observation_ids_by_identity = {
        identity: {
            str(observation_id)
            for observation_id in subject.get("observation_ids", [])
            if (observation := observation_by_id.get(str(observation_id))) is not None
            and observation_matches_technique(definition, observation)
        }
        for identity, subject in subjects_by_identity.items()
    }
    for observation in observations:
        if observation.artifact_family not in definition.projected_artifact_families:
            continue
        if not observation_matches_technique(definition, observation):
            continue
        _display_name, identity = candidate_identity(definition, observation)
        identity_key = tuple(sorted(identity.items()))
        matching_keys: set[tuple[tuple[str, str], ...]] = set()
        if definition.subject_type == "device":
            for candidate_key in observation_ids_by_identity:
                candidate = dict(candidate_key)
                if _device_identities_related(candidate, identity):
                    matching_keys.add(candidate_key)
        elif identity_key in observation_ids_by_identity:
            matching_keys.add(identity_key)
        if len(matching_keys) > 1:
            raise ValueError(
                "device observation matches more than one candidate subject: "
                f"{observation.observation_id}"
            )
        if matching_keys:
            observation_ids_by_identity[next(iter(matching_keys))].add(
                observation.observation_id
            )
    if definition.subject_type == "device" and definition.technique_id == "usbstor_setupapi_discrepancy":
        owned = {oid for ids in observation_ids_by_identity.values() for oid in ids}
        for observation in observations:
            if (observation.artifact_family != "windows.setupapi"
                    or observation.observation_type != "setupapi_usb_event"
                    or observation.observation_id in owned):
                continue
            for identity in observation_ids_by_identity:
                suffix = canonical_sha256({"identity": dict(identity)})[:12]
                clone = replace(observation, observation_id=f"{observation.observation_id}:device:{suffix}")
                observation_by_id[clone.observation_id] = clone
                observation_ids_by_identity[identity].add(clone.observation_id)
                enriched.setdefault("_cloned_observations", []).append(clone)
    for identity, subject in subjects_by_identity.items():
        subject["observation_ids"] = sorted(observation_ids_by_identity[identity])
    enriched["subjects"] = subjects
    return enriched


def _device_identities_related(
    candidate: Mapping[str, str], observed: Mapping[str, str]
) -> bool:
    return any(
        candidate.get(key) and candidate.get(key) == observed.get(key)
        for key in ("device_instance_id", "serial_number")
    )


def _build_roster(
    *,
    definition: TechniqueDefinition,
    observations: tuple[Observation, ...],
    index_id: str,
    index_hash: str,
    coverage_status: str,
    population: Mapping[str, Any] | None = None,
) -> CandidateRoster:
    grouped: dict[tuple[tuple[str, str], ...], dict[str, Any]] = {}
    if population is not None:
        for raw_subject in population["subjects"]:
            identity = dict(raw_subject["identity"])
            identity_key = tuple(sorted(identity.items()))
            display_name = raw_subject["subject_ref"]
            if definition.subject_type == "registry_path":
                display_name = identity.get("canonical_name", display_name)
            grouped[identity_key] = {
                "display_name": display_name,
                "identity": identity,
                "observation_ids": list(raw_subject["observation_ids"]),
            }
    else:
        for observation in observations:
            if (
                observation.artifact_family
                not in definition.candidate_artifact_families
            ):
                continue
            if (
                observation.observation_type
                not in definition.candidate_observation_types
            ):
                continue
            if not observation_matches_technique(definition, observation):
                continue
            display_name, identity = candidate_identity(definition, observation)
            identity_key = tuple(sorted(identity.items()))
            record = grouped.setdefault(
                identity_key,
                {
                    "display_name": display_name,
                    "identity": identity,
                    "observation_ids": [],
                },
            )
            record["observation_ids"].append(observation.observation_id)
    for observation in observations:
        if not observation_matches_technique(definition, observation):
            continue
        _display_name, observed_identity = candidate_identity(definition, observation)
        observed_key = tuple(sorted(observed_identity.items()))
        matching_keys: set[tuple[tuple[str, str], ...]] = set()
        if definition.subject_type == "device":
            for identity_key, record in grouped.items():
                candidate = record["identity"]
                if _device_identities_related(candidate, observed_identity):
                    matching_keys.add(identity_key)
        elif observed_key in grouped:
            matching_keys.add(observed_key)
        else:
            observed_object_id = observed_identity.get("object_id")
            observed_name = normalized_subject_label(observation.subject_ref)
            for identity_key, record in grouped.items():
                candidate = record["identity"]
                candidate_object_id = candidate.get("object_id")
                candidate_name = candidate.get("canonical_name") or candidate.get(
                    "path"
                )
                if candidate_object_id is not None:
                    matches = observed_object_id == candidate_object_id
                else:
                    matches = bool(candidate_name) and observed_name == candidate_name
                if matches:
                    matching_keys.add(identity_key)
        if len(matching_keys) > 1:
            raise ValueError(
                "device observation matches more than one candidate subject: "
                f"{observation.observation_id}"
            )
        if matching_keys:
            grouped[next(iter(matching_keys))]["observation_ids"].append(
                observation.observation_id
            )
    if len(grouped) > MAX_CANDIDATE_SUBJECTS:
        raise ValueError(
            f"candidate roster exceeds limit of {MAX_CANDIDATE_SUBJECTS} subjects"
        )
    subjects = tuple(
        sorted(
            (
                CandidateSubject(
                    subject_id=_subject_id(definition.subject_type, record["identity"]),
                    subject_type=definition.subject_type,
                    display_name=str(record["display_name"]),
                    identity=dict(record["identity"]),
                    observation_ids=tuple(sorted(set(record["observation_ids"]))),
                )
                for record in grouped.values()
            ),
            key=lambda item: item.subject_id,
        )
    )
    return sealed_candidate_roster(
        CandidateRoster(
            roster_id="",
            question_id=definition.question_id,
            technique_id=definition.technique_id,
            evidence_index_id=index_id,
            evidence_index_hash=index_hash,
            subjects=subjects,
            coverage_status=coverage_status,
            roster_sha256="",
        )
    )


def build_analysis_input(
    evidence_index: Mapping[str, Any], definition: TechniqueDefinition
) -> AnalysisInput:
    assert_truth_blind(evidence_index)
    index_hash = evidence_index_sha256(evidence_index)
    index_id = str(
        evidence_index.get("evidence_id")
        or evidence_index.get("run_id")
        or f"evidence-index:{index_hash[:24]}"
    )
    all_observations = tuple(iter_observations(evidence_index))
    populations = _validated_candidate_populations(evidence_index, all_observations)
    population = next(
        (
            item
            for item in populations
            if item["question_id"] == definition.question_id
            and item["technique_id"] == definition.technique_id
        ),
        None,
    )
    if population is not None:
        population = _population_with_matching_observations(
            population,
            all_observations,
            definition,
        )
        cloned = tuple(population.pop("_cloned_observations", []))
        if cloned:
            all_observations = (*all_observations, *cloned)
    population_observation_ids = (
        {
            str(observation_id)
            for subject in population["subjects"]
            for observation_id in subject["observation_ids"]
        }
        if population is not None
        else None
    )
    observations = tuple(
        sorted(
            (
                item
                for item in all_observations
                if item.artifact_family in definition.projected_artifact_families
                and observation_matches_technique(definition, item)
                and (
                    population_observation_ids is None
                    or item.observation_id in population_observation_ids
                )
            ),
            key=lambda item: item.observation_id,
        )
    )
    coverage_by_family = _inferred_coverage(evidence_index)
    scoped_complete_families = _population_scoped_complete_families(
        population,
        all_observations,
        definition,
        evidence_index,
    )
    scoped_partial_families = _population_scoped_partial_families(
        population,
        all_observations,
        definition,
    )
    effective_coverage_by_family = {
        **coverage_by_family,
        **{family: "complete" for family in scoped_complete_families},
        **{family: "partial" for family in scoped_partial_families},
    }
    coverage_scopes = inferred_coverage_scopes(evidence_index)
    coverage = tuple(
        EvidenceCoverage(
            artifact_family=family,
            status=effective_coverage_by_family.get(family, "missing"),
            scope=coverage_scopes.get(family),
        )
        for family in definition.projected_artifact_families
    )
    readiness = (
        "ready"
        if any(
            all(
                effective_coverage_by_family.get(family) == "complete"
                for family in family_set
            )
            for family_set in sufficient_family_sets(definition)
        )
        and (population is None or population["coverage_status"] == "complete")
        else "insufficient_evidence"
    )
    roster = _build_roster(
        definition=definition,
        observations=observations,
        index_id=index_id,
        index_hash=index_hash,
        coverage_status=(
            str(population["coverage_status"])
            if population is not None
            else ("complete" if readiness == "ready" else "partial")
        ),
        population=population,
    )
    roster_observation_ids = {
        observation_id
        for subject in roster.subjects
        for observation_id in subject.observation_ids
    }
    observations = tuple(
        item for item in observations if item.observation_id in roster_observation_ids
    )
    projected_ids = tuple(item.observation_id for item in observations)
    return sealed_analysis_input(
        AnalysisInput(
            schema_version="analysis_input.v1",
            input_id="",
            question_id=definition.question_id,
            question_title=definition.question_title,
            question_text=definition.question_text,
            technique_id=definition.technique_id,
            claim_boundary=definition.claim_boundary,
            evidence_index_ref=index_id,
            evidence_index_sha256=index_hash,
            candidate_roster=roster,
            required_artifact_families=definition.required_artifact_families,
            optional_artifact_families=definition.optional_artifact_families,
            coverage=coverage,
            observations=observations,
            projected_observation_ids=projected_ids,
            readiness=readiness,
            input_sha256="",
        )
    )
