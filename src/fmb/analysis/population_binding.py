from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any

from fmb.analysis.catalog import TECHNIQUES, TechniqueDefinition
from fmb.analysis.domain import Observation
from fmb.analysis.inputs import (
    assert_truth_blind,
    candidate_identity,
    canonical_sha256,
    iter_observations,
    normalized_subject_label,
    observation_matches_technique,
)
from fmb.core import population_contracts
from fmb.core.hashing import sha256_file
from fmb.core.json_io import load_json_object
from fmb.core.limits import usb_medium_size
from fmb.index.contract.evidence_index import validate_candidate_populations

MAX_GENERATED_POPULATION_SUBJECTS = 5000
BOUNDED_POPULATION_CONTRACT_SHA256 = (
    '2c2f881362eabd248d2140d7130e55d0045b9f6c856dc232ff06251c6b6d84c4'
)
HISTORICAL_POPULATION_CONTRACT_SHA256 = frozenset(
    {
        '8dd52a5a5607bf9f2c3b6542d37231dcbbacd36c8d665806a6091ae478590d4f',
        'ac39e7b66bceaa53b58c25e4fbe07dc006826cdabfd43725664996b6ecc0ae47',
        '2f818cc2e2fdc5c755f7fd070f6b09e50d67e556e91900db743aeff0133e3b65',
        'a61d6a96fd4f3a478b805d09e3a25196ab7567f715bf51c26a77f888215beb0f',
    }
)
EXPERIMENTAL_POPULATION_CONTRACT_SHA256 = frozenset(
    {
        '60163b82e93c18bf44e04f8e46ae4bc3851636d1fcb0b47bbb6e67ef04c0e730',
        '2f1d322bf7b41917224d385095bc594f56f200783a2e17942f202788998d3f7d',
        'ad6759758c33f8216cc1c404ba94cc4e702d0612858e848a7b2de42f09beef22',
        '1f79866258e213bbd17f8faa51a9bc1a54c1937634bc961fde455268c911ebe9',
        '1eb19210ad1b12f82f65f6ed44d4fee99bb5581f343c66f090b362c74c8a7e0d',
        'fbe21450f18510ee0168902a42a929b52404693fadf8b603f059a582dafcbda3',
        '7a68fe204b28156d325172568d32e8927ba69630bcf5e59a3ed7f595bf60c84e',
        '9ab2a843430afdac1ab689e68c3f542aa224cc03c8cbf945a492e69fff4f7a4f',
        '27a3ddc446c8a0e6e9a948cdcc0dd7639dab885e19e880213d5ddf39be75f2f7',
    }
)
ALLOWED_HINT_KEYS = {
    "base_path",
    "canonical_name",
    "canonical_path",
    "channel",
    "device_instance_id",
    "serial_number",
}
ALLOWED_GENERATION_MANIFEST_KEYS = {
    "artifacts",
    "cleanup",
    "experiment",
    "ground_truth",
    "ground_truth_sha256",
    "finding_reference",
    "finding_reference_sha256",
    "scenario",
    "schema_version",
}


@dataclass(frozen=True)
class GeneratedPopulationBundle:
    population_manifest: dict[str, Any]
    evidence_sha256: str
    content_subject_limit: int | None
    i30_directory_paths: tuple[str, ...] = ()


def _required_text(value: Mapping[str, Any], key: str, *, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"{label} {key} is required")
    return item


def _sha256(value: Mapping[str, Any], key: str, *, label: str) -> str:
    item = _required_text(value, key, label=label)
    if len(item) != 64 or any(
        character not in "0123456789abcdef" for character in item
    ):
        raise ValueError(f"{label} {key} must be lowercase SHA-256")
    return item


def verify_population_manifest(value: Mapping[str, Any]) -> dict[str, Any]:

    manifest = deepcopy(dict(value))
    assert_truth_blind(manifest, path="population_manifest")
    if manifest.get("schema_version") != "population_manifest.v1":
        raise ValueError("unsupported population manifest schema_version")
    if manifest.get("experiment") not in {"timestomp", "full_scale"}:
        raise ValueError(
            "population manifest experiment must be timestomp or full_scale"
        )
    contract_sha256 = _sha256(
        manifest,
        "contract_sha256",
        label="population manifest",
    )
    if contract_sha256 not in {
        BOUNDED_POPULATION_CONTRACT_SHA256,
        *HISTORICAL_POPULATION_CONTRACT_SHA256,
        *EXPERIMENTAL_POPULATION_CONTRACT_SHA256,
        *population_contracts.registered_hashes(),
    }:
        raise ValueError("population manifest contract hash is not supported")
    expected_hash = _sha256(manifest, "manifest_sha256", label="population manifest")
    body = dict(manifest)
    body.pop("manifest_sha256")
    if canonical_sha256(body) != expected_hash:
        raise ValueError("population manifest hash mismatch")
    if manifest.get("expected_completeness") != "complete":
        raise ValueError("population manifest must declare complete coverage")
    scenarios = manifest.get("scenarios")
    if not isinstance(scenarios, Mapping) or not scenarios:
        raise ValueError("population manifest scenarios must be a non-empty object")
    declared_count = manifest.get("declared_count")
    if isinstance(declared_count, bool) or not isinstance(declared_count, int):
        raise ValueError("population manifest declared_count must be an integer")
    if not 1 <= declared_count <= MAX_GENERATED_POPULATION_SUBJECTS:
        raise ValueError(
            "population manifest declared_count is outside the supported bound"
        )
    return manifest


def _i30_directory_paths(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    scenario = manifest["scenarios"].get("directory_cleaning_i30_01")
    if scenario is None:
        return ()
    if not isinstance(scenario, Mapping):
        raise ValueError("directory-index population scenario is invalid")
    if (
        scenario.get("question_id") != "Q-DEL-03"
        or scenario.get("technique_id") != "i30_directory_residue"
        or scenario.get("subject_type") != "directory_entry"
        or scenario.get("expected_completeness") != "complete"
    ):
        raise ValueError("directory-index population scope is invalid")
    members = scenario.get("members")
    if not isinstance(members, list) or scenario.get("declared_count") != len(members):
        raise ValueError("directory-index population cardinality is invalid")
    paths: list[str] = []
    normalized_paths: set[str] = set()
    for member in members:
        if not isinstance(member, Mapping):
            raise ValueError("directory-index population member is invalid")
        path = _required_text(
            member,
            "subject_ref",
            label="directory-index population member",
        )
        normalized = normalized_subject_label(path)
        if normalized in normalized_paths:
            raise ValueError("directory-index population repeats a directory path")
        normalized_paths.add(normalized)
        paths.append(path)
    return tuple(paths)


def _path_forms(value: str) -> tuple[str, str, str]:
    normalized = normalized_subject_label(value)
    while normalized.startswith((".\\", "\\??\\", "\\\\?\\")):
        normalized = normalized.removeprefix(".\\")
        normalized = normalized.removeprefix("\\??\\")
        normalized = normalized.removeprefix("\\\\?\\")
    without_drive = (
        normalized[2:] if len(normalized) > 2 and normalized[1] == ":" else normalized
    )
    return normalized, without_drive.lstrip("\\"), normalized.rsplit("\\", 1)[-1]


def _path_matches(expected: str, observed: str) -> bool:
    expected_full, expected_relative, _expected_name = _path_forms(expected)
    observed_full, observed_relative, _observed_name = _path_forms(observed)
    return expected_full == observed_full or expected_relative == observed_relative


def _observation_labels(observation: Observation) -> tuple[str, ...]:
    fields = observation.fields
    values = [
        observation.subject_ref,
        *[
            str(fields[key])
            for key in (
                "base_path",
                "canonical_path",
                "executable_name",
                "file_name",
                "path",
            )
            if fields.get(key) not in (None, "")
        ],
    ]
    return tuple(dict.fromkeys(values))


def _matches_hint(observation: Observation, hint: Mapping[str, str]) -> bool:
    labels = _observation_labels(observation)
    if "canonical_path" in hint and any(
        _path_matches(hint["canonical_path"], label) for label in labels
    ):
        return True
    if "base_path" in hint and any(
        _path_matches(hint["base_path"], label) for label in labels
    ):
        return True
    if "canonical_name" in hint:
        expected = normalized_subject_label(hint["canonical_name"]).rsplit("\\", 1)[-1]
        if any(_path_forms(label)[2] == expected for label in labels):
            return True
    if "channel" in hint:
        expected = hint["channel"].strip().casefold()
        observed = (
            str(observation.fields.get("channel") or observation.subject_ref)
            .strip()
            .casefold()
        )
        if expected == observed:
            return True
    if "device_instance_id" in hint:
        expected_instance = hint["device_instance_id"].replace("/", "\\").casefold()
        observed_instance = (
            str(observation.fields.get("device_instance_id") or observation.subject_ref)
            .replace("/", "\\")
            .casefold()
        )
        if expected_instance != observed_instance:
            return False
        expected_serial = hint.get("serial_number")
        return (
            expected_serial is None
            or expected_serial.casefold()
            == str(observation.fields.get("serial_number") or "").casefold()
        )
    return False


def _member_hint(definition: TechniqueDefinition, member: Mapping[str, Any]) -> dict:
    raw_hint = member.get("identity_hint")
    if not isinstance(raw_hint, Mapping) or not raw_hint:
        raise ValueError("population member identity_hint must be a non-empty object")
    native_hint_keys = {"attachment_kind", "disk_size_bytes", "binding_file"}
    if set(raw_hint) == native_hint_keys:
        if (definition.subject_type != "device"
                or raw_hint["attachment_kind"] != "hypervisor_virtual_usb_mass_storage"
                or not usb_medium_size(raw_hint["disk_size_bytes"])
                or (raw_hint["binding_file"] != "native_media_binding.json"
                    and not re.fullmatch(r"media_[0-9a-f]{12}\.json", str(raw_hint["binding_file"])))):
            raise ValueError("native USB population hint is invalid")
        return dict(raw_hint)
    if set(raw_hint) - ALLOWED_HINT_KEYS or any(
        not isinstance(key, str) or not isinstance(value, str) or not value.strip()
        for key, value in raw_hint.items()
    ):
        raise ValueError("population member identity_hint is invalid")
    return dict(raw_hint)


def _member_identity(
    definition: TechniqueDefinition,
    member: Mapping[str, Any],
    observations: tuple[Observation, ...],
) -> tuple[dict[str, str], tuple[str, ...]]:
    raw_hint = _member_hint(definition, member)
    if "attachment_kind" in raw_hint:
        native = tuple(item for item in observations
            if item.observation_type == "usb_volume_reference_history"
            and item.fields.get("native_binding_hash_verified") is True
            and item.fields.get("attachment_kind") == raw_hint["attachment_kind"]
            and item.fields.get("disk_size_bytes") == raw_hint["disk_size_bytes"]
            and item.fields.get("native_binding_file") == raw_hint["binding_file"])
        if len(native) != 1:
            raise ValueError("native USB population requires one hash-bound device identity")
        raw_hint = {key: native[0].fields.get(key)
                    for key in ("device_instance_id", "serial_number")}
    if set(raw_hint) - ALLOWED_HINT_KEYS or any(
        not isinstance(key, str) or not isinstance(value, str) or not value.strip()
        for key, value in raw_hint.items()
    ):
        raise ValueError("population member identity_hint is invalid")
    hint = {str(key): str(value) for key, value in raw_hint.items()}
    matches = tuple(
        observation
        for observation in observations
        if observation.artifact_family in definition.projected_artifact_families
        and observation_matches_technique(definition, observation)
        and _matches_hint(observation, hint)
    )
    if not matches:
        raise ValueError(
            f"population candidate cannot be resolved: {member.get('candidate_id')}"
        )
    if definition.technique_id == "alternate_data_stream" and any(
        observation.observation_type == "named_data_stream"
        and not str(observation.fields.get("stream_name") or "").strip()
        for observation in matches
    ):
        raise ValueError("named-stream observation must have a non-empty stream name")
    preferred = tuple(
        observation
        for observation in matches
        if observation.artifact_family in definition.candidate_artifact_families
        and observation.observation_type in definition.candidate_observation_types
    )
    if definition.technique_id == "alternate_data_stream":
        primary = preferred or tuple(
            observation
            for observation in matches
            if observation.artifact_family == "ntfs.mft"
            and observation.observation_type == "mft_file_record"
        )
        primary = primary or matches
    else:
        primary = preferred or matches
    identities: dict[str, dict[str, str]] = {}
    for observation in primary:
        _display_name, identity = candidate_identity(definition, observation)
        identities.setdefault(canonical_sha256(identity), identity)
    if len(identities) != 1:
        raise ValueError(
            f"population candidate resolves ambiguously: {member.get('candidate_id')}"
        )
    identity = next(iter(identities.values()))
    observation_ids = tuple(
        sorted(
            observation.observation_id
            for observation in matches
            if candidate_identity(definition, observation)[1] == identity
        )
    )
    if not observation_ids:
        raise ValueError("population candidate has no identity-bound observations")
    return identity, observation_ids


def bind_population_manifest(
    evidence_index: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *, techniques: set[str] | None = None,
) -> dict[str, Any]:

    bound = deepcopy(dict(evidence_index))
    assert_truth_blind(bound)
    raw_parser_runs = bound.get("parser_runs", [])
    if not isinstance(raw_parser_runs, list) or any(
        not isinstance(item, dict) for item in raw_parser_runs
    ):
        raise ValueError("evidence index parser_runs must be an array of objects")
    raw_existing_populations = bound.get("candidate_populations", [])
    if not isinstance(raw_existing_populations, list):
        raise ValueError("evidence index candidate_populations must be an array")
    existing_populations = validate_candidate_populations(
        raw_existing_populations,
        parser_runs=raw_parser_runs,
    )
    public = verify_population_manifest(manifest)
    observations = tuple(iter_observations(bound))
    definitions = {(item.question_id, item.technique_id): item for item in TECHNIQUES}
    candidate_ids: set[str] = set()
    populations: list[dict[str, Any]] = []
    declared_total = 0
    scopes: set[tuple[str, str]] = set()
    for scenario_id, raw_scenario in public["scenarios"].items():
        if not isinstance(scenario_id, str) or not isinstance(raw_scenario, Mapping):
            raise ValueError("population manifest scenario is invalid")
        label = f"population scenario {scenario_id}"
        question_id = _required_text(raw_scenario, "question_id", label=label)
        technique_id = _required_text(raw_scenario, "technique_id", label=label)
        subject_type = _required_text(raw_scenario, "subject_type", label=label)
        scope = (question_id, technique_id)
        if scope in scopes:
            raise ValueError("population manifest repeats a question/technique scope")
        scopes.add(scope)
        definition = definitions.get(scope)
        if definition is None or definition.subject_type != subject_type:
            raise ValueError(f"{label} does not match the analysis catalog")
        if raw_scenario.get("expected_completeness") != "complete":
            raise ValueError(f"{label} must declare complete coverage")
        members = raw_scenario.get("members")
        if not isinstance(members, list) or raw_scenario.get("declared_count") != len(
            members
        ):
            raise ValueError(f"{label} declared_count does not match members")
        declared_total += len(members)
        subjects: list[dict[str, Any]] = []
        for member in members:
            if not isinstance(member, Mapping):
                raise ValueError(f"{label} member is not an object")
            candidate_id = _required_text(member, "candidate_id", label=label)
            if candidate_id in candidate_ids:
                raise ValueError(
                    "population manifest contains a duplicate candidate ID"
                )
            candidate_ids.add(candidate_id)
            if member.get("subject_type") != subject_type:
                raise ValueError(f"{label} member subject_type does not match")
            subject_ref = _required_text(member, "subject_ref", label=label)
            _member_hint(definition, member)
            if techniques is not None and technique_id not in techniques:
                continue
            identity, observation_ids = _member_identity(
                definition,
                member,
                observations,
            )
            subjects.append(
                {
                    "subject_ref": subject_ref,
                    "identity": identity,
                    "observation_ids": list(observation_ids),
                }
            )
        if techniques is not None and technique_id not in techniques:
            continue
        population_hash = canonical_sha256(
            {
                "manifest_sha256": public["manifest_sha256"],
                "question_id": question_id,
                "technique_id": technique_id,
            }
        )
        populations.append(
            {
                "population_id": f"population:{population_hash[:24]}",
                "question_id": question_id,
                "technique_id": technique_id,
                "subject_type": subject_type,
                "coverage_status": "complete",
                "subjects": subjects,
            }
        )
    if declared_total != public["declared_count"]:
        raise ValueError("population manifest aggregate count does not resolve")
    if techniques is not None and not techniques <= {scope[1] for scope in scopes}:
        raise ValueError("selected technique is absent from the public population")
    manifest_scopes = {
        (population["question_id"], population["technique_id"])
        for population in populations
    }
    retained_populations = [
        population
        for population in existing_populations
        if (population["question_id"], population["technique_id"])
        not in manifest_scopes
        and (techniques is None or population["technique_id"] in techniques)
    ]
    bound["population_manifest"] = public
    bound["candidate_populations"] = validate_candidate_populations(
        [*populations, *retained_populations],
        parser_runs=raw_parser_runs,
    )
    assert_truth_blind(bound)
    return bound


def _artifact_record(
    generation_manifest: Mapping[str, Any],
    *,
    filename: str,
) -> Mapping[str, Any]:
    artifacts = generation_manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("generation manifest artifacts must be an array")
    records: list[Mapping[str, Any]] = []
    seen_files: set[str] = set()
    for item in artifacts:
        if not isinstance(item, Mapping):
            raise ValueError("generation manifest artifact must be an object")
        artifact_file = _required_text(item, "file", label="generation artifact")
        checkpoint_files = {
            "factual-checkpoints/checkpoint-01.evtx", "factual-checkpoints/checkpoint-02.evtx",
            "factual-checkpoints/checkpoint-03.log", "factual-checkpoints/checkpoint-04.vmdk",
        }
        if ((Path(artifact_file).name != artifact_file and artifact_file not in checkpoint_files)
                or "\\" in artifact_file or artifact_file in seen_files):
            raise ValueError("generation manifest artifact file is unsafe or repeated")
        seen_files.add(artifact_file)
        _sha256(item, "sha256", label=f"generation artifact {artifact_file}")
        size = item.get("size_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError(
                f"generation artifact {artifact_file} size_bytes must be non-negative"
            )
        if artifact_file == filename:
            records.append(item)
    if len(records) != 1:
        raise ValueError(
            f"generation manifest must contain exactly one artifact for {filename}"
        )
    return records[0]


def _verified_generation_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    manifest = deepcopy(dict(value))
    unknown = sorted(set(manifest) - ALLOWED_GENERATION_MANIFEST_KEYS)
    if unknown:
        raise ValueError(
            "generation manifest contains unsupported fields: " + ", ".join(unknown)
        )
    if manifest.get("schema_version") != "generation_manifest.v1":
        raise ValueError("unsupported generation manifest schema_version")
    _required_text(manifest, "scenario", label="generation manifest")
    cleanup = manifest.get("cleanup")
    if not isinstance(cleanup, Mapping):
        raise ValueError(
            "generated population requires a successful cleanup receipt"
        )
    if set(cleanup) != {
        "schema_version",
        "provider",
        "status",
        "provider_state_remaining",
    }:
        raise ValueError("generation cleanup receipt fields are invalid")
    if cleanup.get("schema_version") != "generation_cleanup.v1":
        raise ValueError("generation cleanup receipt schema_version is invalid")
    if cleanup.get("provider") not in {
        "virtualbox",
        "libvirt",
        "hyperv",
        "vmware_desktop",
        "qemu",
    }:
        raise ValueError("generation cleanup receipt provider is invalid")
    status = cleanup.get("status")
    remaining = cleanup.get("provider_state_remaining")
    if (
        status not in {"destroyed", "retained"}
        or not isinstance(remaining, bool)
        or (status == "retained") != remaining
    ):
        raise ValueError("generation cleanup receipt status is invalid")
    experiment = manifest.get("experiment")
    if experiment is not None and experiment not in {"timestomp", "full_scale"}:
        raise ValueError("generation manifest experiment is invalid")
    pointer = manifest.get("ground_truth")
    digest = manifest.get("ground_truth_sha256")
    if (pointer is None) != (digest is None):
        raise ValueError(
            "generation manifest ground_truth pointer/hash must be paired"
        )
    if pointer is not None:
        if not isinstance(pointer, str) or Path(pointer).name != pointer:
            raise ValueError("generation manifest ground_truth pointer is unsafe")
        _sha256(manifest, "ground_truth_sha256", label="generation manifest")
    pointer, digest = manifest.get("finding_reference"), manifest.get("finding_reference_sha256")
    if (pointer is None) != (digest is None):
        raise ValueError("generation manifest finding_reference pointer/hash must be paired")
    if pointer is not None:
        if pointer != "finding_reference.json":
            raise ValueError("generation manifest finding_reference pointer is unsafe")
        _sha256(manifest, "finding_reference_sha256", label="generation manifest")
    return manifest


def _verify_artifact_size(path: Path, record: Mapping[str, Any]) -> None:
    if not path.is_file():
        raise ValueError(f"generated artifact is missing: {path.name}")
    if path.stat().st_size != record["size_bytes"]:
        raise ValueError(f"generated artifact size mismatch: {path.name}")


def _verify_artifact(path: Path, record: Mapping[str, Any]) -> None:
    _verify_artifact_size(path, record)
    if sha256_file(path) != record["sha256"]:
        raise ValueError(f"generated artifact SHA-256 mismatch: {path.name}")


def load_generated_population_bundle(
    evidence_path: Path,
    *,
    verify_evidence_sha256: bool = True,
) -> GeneratedPopulationBundle | None:

    evidence = evidence_path.expanduser().absolute()
    population_path = evidence.parent / "population_manifest.json"
    if not population_path.exists():
        return None
    if not population_path.is_file():
        raise ValueError("population manifest sidecar is not a file")
    generation_path = evidence.parent / "manifest.json"
    if not generation_path.is_file():
        raise ValueError("generated population requires manifest.json")

    generation_manifest = _verified_generation_manifest(
        load_json_object(generation_path, label="generation manifest")
    )

    evidence_record = _artifact_record(
        generation_manifest,
        filename=evidence.name,
    )
    population_record = _artifact_record(
        generation_manifest,
        filename=population_path.name,
    )
    if verify_evidence_sha256:
        _verify_artifact(evidence, evidence_record)
    else:
        _verify_artifact_size(evidence, evidence_record)
    _verify_artifact(population_path, population_record)

    public = verify_population_manifest(
        load_json_object(population_path, label="population manifest")
    )
    content_limits = [
        scenario.get("declared_count")
        for scenario in public["scenarios"].values()
        if isinstance(scenario, Mapping)
        and scenario.get("technique_id") == "bitmap_trailing_data"
    ]
    if len(content_limits) > 1:
        raise ValueError("population manifest repeats the file-content scope")
    content_subject_limit = int(content_limits[0]) if content_limits else None
    return GeneratedPopulationBundle(
        population_manifest=public,
        evidence_sha256=str(evidence_record["sha256"]),
        content_subject_limit=content_subject_limit,
        i30_directory_paths=_i30_directory_paths(public),
    )


__all__ = [
    "GeneratedPopulationBundle",
    "bind_population_manifest",
    "load_generated_population_bundle",
    "verify_population_manifest",
]
