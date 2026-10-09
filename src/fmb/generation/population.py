from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


from fmb.core import population_contracts
from fmb.generation import archive_control
from fmb.generation import pilot_profile


POPULATION_CONTRACT_PATH = Path(__file__).with_name("populations.pilot-i1-20260918.json")
RELABELLED_CONTRACTS = {
    "7a68fe204b28156d325172568d32e8927ba69630bcf5e59a3ed7f595bf60c84e": "populations.pilot-i1-20260918.json",
    "9ab2a843430afdac1ab689e68c3f542aa224cc03c8cbf945a492e69fff4f7a4f": "populations.pilot-i2-20260918.json",
    "27a3ddc446c8a0e6e9a948cdcc0dd7639dab885e19e880213d5ddf39be75f2f7": "populations.pilot-i3-20260918.json",
}


class PopulationError(ValueError):
    pass


SCENARIO_ANALYSIS = {
    "timestomp_01": ("Q-TIME-01", "timestamp_manipulation", "file"),
    "ads_injection_01": ("Q-HIDE-01", "alternate_data_stream", "file"),
    "prefetch_wipe_01": (
        "Q-EXEC-01",
        "prefetch_missing_executable",
        "executable",
    ),
    "event_record_sequence_gap_01": ("Q-LOG-01", "event_record_sequence_gap", "event_log"),
    "security_log_clear_event_01": (
        "Q-LOG-01",
        "security_log_clear_event",
        "event_log",
    ),
    "usn_journal_01": ("Q-DEL-01", "deleted_file_journal_residue", "file"),
    "shimcache_path_residue_01": (
        "Q-EXEC-01",
        "shimcache_path_residue",
        "executable",
    ),
    "shellbag_path_residue_01": (
        "Q-DEL-04", "shellbag_missing_directory", "registry_path",
    ),
    "typed_path_residue_01": (
        "Q-DEL-02",
        "typed_path_residue",
        "registry_path",
    ),
    "ntfs_allocation_01": ("Q-FILE-01", "ntfs_allocation_inconsistency", "file"),
    "bitmap_trailing_data_01": (
        "Q-FILE-01",
        "bitmap_trailing_data",
        "file",
    ),
    "directory_cleaning_i30_01": (
        "Q-DEL-03",
        "i30_directory_residue",
        "directory_entry",
    ),
    "usb_volume_activity_gap_01": ("Q-MEDIA-01", "usb_volume_activity_gap", "device"),
    "usbstor_setupapi_discrepancy_01": (
        "Q-MEDIA-01",
        "usbstor_setupapi_discrepancy",
        "device",
    ),
}

_PROHIBITED_PUBLIC_KEYS = frozenset(
    {
        "answer",
        "expected",
        "ground_truth",
        "is_target",
        "manipulation_count",
        "offender",
        "role",
        "selected",
        "target",
    }
)


def canonical_json_bytes(value: Any) -> bytes:

    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _digest(seed: int, scenario_id: str, index: int, purpose: str) -> str:
    return hashlib.sha256(
        f"bounded-population.v1:{seed}:{scenario_id}:{index}:{purpose}".encode("utf-8")
    ).hexdigest()


STOMP_YEAR_RANGE = (2004, datetime.fromisoformat(archive_control.ARCHIVE_LAST_WRITE_UTC).year - 1)
LOGICAL_LENGTH_RANGE = (4097, 8096)
ORDERED_LEAF_COUNT = 22
MAXIMUM_DIRECTORY_CHILDREN = 200
SCENARIO_MAXIMUM_COUNTS = (
    ("typed_path_residue_01", 25, "Explorer keeps 25 typed paths"),
    ("ntfs_allocation_01", 100, "the offline NTFS check reads at most 100 files"),
    ("directory_cleaning_i30_01", 100, "the offline index check reads at most 100 folders"),
)
PADDING_BYTES_RANGE = (4096, 15872)

SHELLBAG_VISIT_BUDGET_KEYS = (
    "match_seconds", "close_seconds", "child_seconds", "dispatch_seconds", "snapshot_ms",
)
SHELLBAG_VISIT_BUDGETS = {
    "match_seconds": 40, "close_seconds": 40, "child_seconds": 360,
    "dispatch_seconds": 480, "snapshot_ms": 2000,
}
SHELLBAG_CHILD_STAGE_MARGIN_SECONDS = 2
SHELLBAG_STARTUP_HEADROOM_SECONDS = 8
SHELLBAG_MINIMUM_SNAPSHOTS_PER_VISIT = 13


def validate_visit_budgets(budgets: Any) -> dict[str, int]:
    if not isinstance(budgets, Mapping) or set(budgets) != set(SHELLBAG_VISIT_BUDGET_KEYS):
        raise PopulationError("Shellbag visit budgets are incomplete")
    for key in SHELLBAG_VISIT_BUDGET_KEYS:
        value = budgets[key]
        limit = 600_000 if key == "snapshot_ms" else 3600
        if type(value) is not int or not 1 <= value <= limit:
            raise PopulationError(f"Shellbag visit budget {key!r} is outside its bounds")
    if budgets["child_seconds"] < (
        budgets["match_seconds"] + budgets["close_seconds"] + SHELLBAG_CHILD_STAGE_MARGIN_SECONDS
    ):
        raise PopulationError("Shellbag child budget cannot hold the match and close waits")
    if budgets["dispatch_seconds"] < budgets["child_seconds"] + SHELLBAG_STARTUP_HEADROOM_SECONDS:
        raise PopulationError("Shellbag dispatch budget leaves no worker startup headroom")
    return {key: int(budgets[key]) for key in SHELLBAG_VISIT_BUDGET_KEYS}


def _assigned_timestamp_matches(assigned: str, requested: str) -> bool:
    if requested.endswith("Z") or requested[-6] in "+-":
        left, right = _instant(assigned), _instant(requested)
        return left is not None and right is not None and left == right
    return assigned.startswith(requested)


def _seeded_stomp_timestamps(seed: int, count: int = 2) -> list[str]:
    stamps: list[str] = []
    for index in range(count):
        attempt = 0
        while True:
            value = int(_digest(seed, "timestomp_01", index, f"stomp:{attempt}")[:16], 16)
            year = STOMP_YEAR_RANGE[0] + value % (STOMP_YEAR_RANGE[1] - STOMP_YEAR_RANGE[0] + 1)
            month = 1 + (value >> 4) % 12
            day = 1 + (value >> 8) % 28
            hour = (value >> 13) % 24
            minute = (value >> 18) % 60
            second = (value >> 24) % 60
            stamp = f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"
            if stamp not in stamps:
                stamps.append(stamp)
                break
            attempt += 1
    return stamps


def _seeded_logical_length(seed: int, index: int) -> int:
    value = int(_digest(seed, "ntfs_allocation_01", index, "logical_length")[:16], 16)
    low, high = LOGICAL_LENGTH_RANGE
    return low + value % (high - low + 1)


def _seeded_padding_bytes(seed: int, index: int = 0) -> int:
    low, high = PADDING_BYTES_RANGE
    value = int(_digest(seed, "bitmap_trailing_data_01", index, f"padding:{index}")[:16], 16)
    return low + (value % ((high - low) // 512 + 1)) * 512


def ads_streams(inputs: Mapping[str, Any], count: int) -> list[tuple[str, str]]:
    names = [inputs["stream_name"], inputs["zip_stream_name"], *inputs.get("extra_stream_names", [])]
    if len(names) != max(2, count):
        raise PopulationError("named-stream inputs do not name one stream for each target")
    return [("pe" if index % 2 == 0 else "zip", names[index]) for index in range(count)]


def _bitmap_operation_valid(operation: Mapping[str, Any], pilot: bool) -> bool:
    if operation.get("mode") == "truncate":
        return operation == {"mode": "truncate", "length": 54} and type(operation["length"]) is int
    count = operation.get("byte_count")
    return (operation.get("mode") == "append" and set(operation) == {"mode", "byte_count"}
            and type(count) is int and count % 512 == 0
            and (count == 1024 if pilot else PADDING_BYTES_RANGE[0] <= count <= PADDING_BYTES_RANGE[1]))


def _instant(text: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None


def load_population_contract(path: Path = POPULATION_CONTRACT_PATH) -> dict[str, Any]:
    return validate_population_contract(json.loads(path.read_text(encoding="utf-8")))


def register_population_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    contract = validate_population_contract(json.loads(canonical_json_bytes(value)))
    population_contracts.register(_sha256(contract), contract)
    return contract


def validate_population_contract(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PopulationError("a population contract must be a JSON object")
    if value.get("schema_version") != "bounded_population.v1":
        raise PopulationError("unsupported bounded-population schema")
    if value.get("native_pilot_profile") not in {None, pilot_profile.PROFILE}:
        raise PopulationError("unsupported native pilot profile")
    if "native_pilot_parameters" in value:
        if value.get("native_pilot_profile") != pilot_profile.PROFILE:
            raise PopulationError("native pilot parameters require the native pilot profile")
        try:
            pilot_profile.validate_parameters(value["native_pilot_parameters"])
        except ValueError as error:
            raise PopulationError(str(error)) from error
    if value.get("stream_name_policy") != "role_independent.v1":
        raise PopulationError("unsupported native stream naming policy")
    if value.get("finding_reference_contract") != "broad_native_findings.v1":
        raise PopulationError("unsupported factual finding reference contract")
    if value.get("contract_revision") != "content_formats.v2":
        raise PopulationError("unsupported native content-format revision")
    experiments = value.get("experiments")
    scenarios = value.get("scenarios")
    if not isinstance(experiments, dict) or "full_scale" not in experiments or set(experiments) - {
            "timestomp", "full_scale"}:
        raise PopulationError("the experiments are full_scale and, as an option, timestomp")
    if not isinstance(scenarios, dict) or not scenarios:
        raise PopulationError("population scenarios must be a non-empty object")
    for experiment, scenario_ids in experiments.items():
        if not isinstance(scenario_ids, list) or not scenario_ids:
            raise PopulationError(f"experiment {experiment!r} has no scenarios")
        unknown = set(scenario_ids).difference(scenarios)
        if unknown:
            raise PopulationError(
                f"experiment {experiment!r} references unknown scenarios: {sorted(unknown)}"
            )
    for scenario_id, item in scenarios.items():
        if not isinstance(item, dict):
            raise PopulationError(f"scenario {scenario_id!r} must be an object")
        count = item.get("configured_count")
        manipulation_count = item.get("manipulation_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise PopulationError(f"scenario {scenario_id!r} has an invalid count")
        if (
            isinstance(manipulation_count, bool)
            or not isinstance(manipulation_count, int)
            or not min(count, 1) <= manipulation_count <= count
        ):
            raise PopulationError(
                f"scenario {scenario_id!r} has an invalid manipulation count"
            )
        assignment_pool_count = item.get("assignment_pool_count", count)
        if (
            isinstance(assignment_pool_count, bool)
            or not isinstance(assignment_pool_count, int)
            or not manipulation_count <= assignment_pool_count <= count
        ):
            raise PopulationError(
                f"scenario {scenario_id!r} has an invalid assignment pool count"
            )

    timestamp = scenarios.get("timestomp_01")
    if timestamp is not None and "restore_stratum_end_indexes" in timestamp:
        endpoints = timestamp["restore_stratum_end_indexes"]
        if (
            not isinstance(endpoints, list)
            or not endpoints
            or any(type(value) is not int or value < 1 for value in endpoints)
            or endpoints != sorted(set(endpoints))
            or endpoints[-1] != timestamp["configured_count"]
        ):
            raise PopulationError("timestamp restoration strata are invalid")

    directory = scenarios.get("directory_cleaning_i30_01")
    if directory is not None and "directory_child_counts" in directory:
        child_counts = directory["directory_child_counts"]
        if (
            not isinstance(child_counts, list)
            or len(child_counts) != directory["configured_count"]
            or any(type(value) is not int or not 1 <= value <= MAXIMUM_DIRECTORY_CHILDREN for value in child_counts)
            or sum(value >= ORDERED_LEAF_COUNT for value in child_counts[:directory.get(
                "assignment_pool_count", directory["configured_count"]
            )]) < directory["manipulation_count"]
        ):
            raise PopulationError("directory child-count strata are invalid")

    allocation = scenarios.get("ntfs_allocation_01")
    if allocation is not None and "storage_modes" in allocation:
        storage_modes = allocation["storage_modes"]
        allowed_modes = {"ordinary", "resident", "preallocation_request_then_close"}
        if (
            not isinstance(storage_modes, list)
            or len(storage_modes) != allocation["configured_count"]
            or any(value not in allowed_modes for value in storage_modes)
            or sum(
                value == "ordinary"
                for value in storage_modes[:allocation.get(
                    "assignment_pool_count", allocation["configured_count"]
                )]
            ) < allocation["manipulation_count"]
        ):
            raise PopulationError("NTFS allocation storage modes are invalid")

    for scenario_id, maximum, reason in SCENARIO_MAXIMUM_COUNTS:
        if scenario_id in scenarios and scenarios[scenario_id]["configured_count"] > maximum:
            raise PopulationError(f"scenario {scenario_id!r} has at most {maximum} objects: {reason}")
    typed = scenarios.get("typed_path_residue_01")
    if (typed is not None and value.get("native_pilot_profile") == pilot_profile.PROFILE
            and typed["configured_count"] and typed["manipulation_count"] >= typed["configured_count"]):
        raise PopulationError("typed_path_residue_01 keeps one folder that is not deleted: the native profile "
                              "deletes and recreates it")
    identity = scenarios.get("usbstor_setupapi_discrepancy_01")
    media = [item for item in (identity, scenarios.get("usb_volume_activity_gap_01"))
             if item is not None and item.get("media_layout") == pilot_profile.PROFILE]
    if media and (media[0] is not identity
                  or not 2 <= identity["configured_count"] <= len(pilot_profile.MEDIA_PORTS)
                  or any(item["configured_count"] != identity["configured_count"] or item["manipulation_count"] != 1
                         for item in media)):
        raise PopulationError(f"the USB scenarios share 2 to {len(pilot_profile.MEDIA_PORTS)} virtual drives and each "
                              "changes one drive; usb_volume_activity_gap_01 needs usbstor_setupapi_discrepancy_01")
    return value


def _member(
    *,
    scenario_id: str,
    item: Mapping[str, Any],
    seed: int,
    index: int,
) -> dict[str, Any]:
    _question_id, _technique_id, subject_type = SCENARIO_ANALYSIS[scenario_id]
    candidate_id = f"candidate:{_digest(seed, scenario_id, index, 'candidate')[:24]}"

    if item["object_kind"] == "event_log":
        channel = str(item["native_name"])
        return {
            "candidate_id": candidate_id,
            "subject_type": subject_type,
            "subject_ref": channel,
            "identity_hint": {"channel": channel},
        }

    if item["object_kind"] == "native_usb_device":
        if item.get("media_layout") == pilot_profile.PROFILE:
            volume = pilot_profile.media_layout(seed, item["configured_count"])[index]
            return {
                "candidate_id": candidate_id,
                "subject_type": subject_type,
                "subject_ref": volume["subject_ref"],
                "identity_hint": {
                    "attachment_kind": "hypervisor_virtual_usb_mass_storage",
                    "disk_size_bytes": volume["disk_size_bytes"],
                    "binding_file": volume["binding_file"],
                },
            }
        return {
            "candidate_id": candidate_id,
            "subject_type": subject_type,
            "subject_ref": "virtual-usb:controlled-disk",
            "identity_hint": {
                "attachment_kind": "hypervisor_virtual_usb_mass_storage",
                "disk_size_bytes": 67108864,
                "binding_file": "native_media_binding.json",
            },
        }

    token = _digest(seed, scenario_id, index, "name")[:12]
    name = f"{item['name_prefix']}_{token}{item['name_extension']}"
    parents = item["parent_cycle"]
    parent = str(parents[index % len(parents)])
    path = f"{parent}\\{name}"
    if scenario_id == "prefetch_wipe_01":
        subject_ref = name.upper()
    elif scenario_id in {"shimcache_path_residue_01", "typed_path_residue_01"}:
        subject_ref = name
    else:
        subject_ref = path
    if scenario_id == "ads_injection_01":
        identity_hint = {"base_path": path.casefold(), "canonical_name": name.casefold()}
    else:
        identity_hint = {"canonical_name": name.casefold(), "canonical_path": path.casefold()}
    return {
        "candidate_id": candidate_id,
        "subject_type": subject_type,
        "subject_ref": subject_ref,
        "identity_hint": identity_hint,
    }


def build_public_manifest(*, experiment: str, seed: int,
                          contract: Mapping[str, Any] | None = None) -> dict[str, Any]:

    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise PopulationError("population seed must be a non-negative integer")
    contract = dict(contract) if contract is not None else load_population_contract()
    try:
        scenario_ids = contract["experiments"][experiment]
    except KeyError as error:
        raise PopulationError(f"unknown generation experiment: {experiment}") from error

    scenarios: dict[str, Any] = {}
    declared_count = 0
    for scenario_id in scenario_ids:
        item = contract["scenarios"][scenario_id]
        question_id, technique_id, subject_type = SCENARIO_ANALYSIS[scenario_id]
        count = item["configured_count"]
        members = [
            _member(
                scenario_id=scenario_id,
                item=item,
                seed=seed,
                index=index,
            )
            for index in range(count)
        ]
        scenarios[scenario_id] = {
            "question_id": question_id,
            "technique_id": technique_id,
            "subject_type": subject_type,
            "declared_count": count,
            "expected_completeness": "complete",
            "members": members,
        }
        declared_count += count

    body = {
        "schema_version": "population_manifest.v1",
        "experiment": experiment,
        "population_seed": seed,
        "contract_sha256": _sha256(contract),
        "declared_count": declared_count,
        "expected_completeness": "complete",
        "scenarios": scenarios,
    }
    return {**body, "manifest_sha256": _sha256(body)}


def _walk_keys(value: Any):
    if isinstance(value, Mapping):
        for key, nested in value.items():
            yield str(key).casefold()
            yield from _walk_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_keys(nested)


def verify_public_manifest(value: Mapping[str, Any]) -> dict[str, Any]:

    manifest = dict(value)
    digest = manifest.pop("manifest_sha256", None)
    if not isinstance(digest, str) or digest != _sha256(manifest):
        raise PopulationError("population manifest hash mismatch")
    if manifest.get("schema_version") != "population_manifest.v1":
        raise PopulationError("unsupported population manifest schema")
    if _PROHIBITED_PUBLIC_KEYS.intersection(_walk_keys(manifest)):
        raise PopulationError("population manifest contains role-bearing fields")

    scenarios = manifest.get("scenarios")
    if not isinstance(scenarios, Mapping):
        raise PopulationError("population manifest scenarios must be an object")
    candidate_ids: list[str] = []
    actual_count = 0
    for scenario_id, raw in scenarios.items():
        if scenario_id not in SCENARIO_ANALYSIS or not isinstance(raw, Mapping):
            raise PopulationError("population manifest has an unknown scenario")
        members = raw.get("members")
        if not isinstance(members, list):
            raise PopulationError("population manifest members must be an array")
        declared_count = raw.get("declared_count")
        if declared_count != len(members):
            raise PopulationError("population scenario count mismatch")
        for member in members:
            if not isinstance(member, Mapping):
                raise PopulationError("population member must be an object")
            candidate_id = member.get("candidate_id")
            if not isinstance(candidate_id, str) or not candidate_id.startswith(
                "candidate:"
            ):
                raise PopulationError("population candidate ID is invalid")
            candidate_ids.append(candidate_id)
        actual_count += len(members)
    if len(candidate_ids) != len(set(candidate_ids)):
        raise PopulationError("population candidate IDs are not unique")
    if manifest.get("declared_count") != actual_count:
        raise PopulationError("population aggregate count mismatch")
    complete = {**manifest, "manifest_sha256": digest}
    try:
        expected = build_public_manifest(
            experiment=str(manifest["experiment"]),
            seed=manifest["population_seed"],
            contract=_contract_for_manifest(manifest),
        )
    except (KeyError, TypeError) as error:
        raise PopulationError(
            "population manifest does not match the generation analysis contract"
        ) from error
    if complete != relabelled_manifest(expected, manifest):
        raise PopulationError(
            "population manifest does not match the generation analysis contract"
        )
    return complete


def relabelled_manifest(expected: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict[str, Any]:
    name = RELABELLED_CONTRACTS.get(str(manifest.get("contract_sha256")))
    if name is None or _sha256(load_population_contract(POPULATION_CONTRACT_PATH.parent / name)) != expected.get(
            "contract_sha256"):
        return dict(expected)
    body = {key: value for key, value in expected.items() if key != "manifest_sha256"}
    body["contract_sha256"] = manifest["contract_sha256"]
    return {**body, "manifest_sha256": _sha256(body)}


def _contract_for_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    for path in sorted(POPULATION_CONTRACT_PATH.parent.glob("populations*.json")):
        if path.is_file():
            contract = load_population_contract(path)
            if _sha256(contract) == manifest.get("contract_sha256"):
                return contract
    relabelled = RELABELLED_CONTRACTS.get(str(manifest.get("contract_sha256")))
    if relabelled is not None:
        return load_population_contract(POPULATION_CONTRACT_PATH.parent / relabelled)
    registered = population_contracts.registered(str(manifest.get("contract_sha256")))
    if registered is not None:
        return registered
    raise PopulationError("population manifest references an unknown frozen contract")


def population_scenario_order(manifest: Mapping[str, Any]) -> tuple[str, ...]:

    public = verify_public_manifest(manifest)
    contract = _contract_for_manifest(public)
    scenario_order = tuple(contract["experiments"][public["experiment"]])
    if set(scenario_order) != set(public["scenarios"]):
        raise PopulationError("population scenarios differ from their frozen experiment")
    return scenario_order


def _ranked_members(
    members: Iterable[Mapping[str, Any]],
    *,
    entropy: bytes,
    scenario_id: str,
) -> list[dict[str, Any]]:
    return sorted(
        (dict(member) for member in members),
        key=lambda member: hashlib.sha256(
            entropy
            + scenario_id.encode("utf-8")
            + str(member["candidate_id"]).encode("utf-8")
        ).digest(),
    )


def select_private_assignment(
    manifest: Mapping[str, Any],
    *,
    entropy: bytes,
) -> dict[str, Any]:

    public = verify_public_manifest(manifest)
    if not isinstance(entropy, bytes) or len(entropy) < 16:
        raise PopulationError("assignment entropy must contain at least 16 bytes")
    contract = _contract_for_manifest(public)
    bindings: dict[str, list[dict[str, Any]]] = {}
    for scenario_id, scenario in public["scenarios"].items():
        scenario_contract = contract["scenarios"][scenario_id]
        count = scenario_contract["manipulation_count"]
        members = scenario["members"][:scenario_contract.get(
            "assignment_pool_count", scenario["declared_count"]
        )]
        if scenario_id == "ntfs_allocation_01":
            modes = scenario_contract.get(
                "storage_modes",
                ["ordinary"] * 8 + ["resident", "preallocation_request_then_close"],
            )[:len(members)]
            bindings[scenario_id] = _ranked_members(
                [member for member, mode in zip(members, modes, strict=True)
                 if mode == "ordinary"],
                entropy=entropy,
                scenario_id=scenario_id,
            )[:count]
        elif scenario_id == "directory_cleaning_i30_01":
            child_counts = scenario_contract.get(
                "directory_child_counts",
                [4 if index < 8 else 80 for index in range(scenario["declared_count"])],
            )[:len(members)]
            bindings[scenario_id] = _ranked_members(
                [member for member, child_count in zip(members, child_counts, strict=True)
                 if child_count >= ORDERED_LEAF_COUNT],
                entropy=entropy,
                scenario_id=scenario_id,
            )[:count]
        elif scenario_id in {"timestomp_01", "bitmap_trailing_data_01"}:
            if scenario_id == "timestomp_01":
                restored = set(archive_restore_paths(public))
                members = [member for member in members if _operational_path(member) not in restored]
            by_parent: dict[str, list[Mapping[str, Any]]] = {}
            for member in members:
                path = str(member["identity_hint"]["canonical_path"])
                parent = path.rsplit("\\", 1)[0]
                by_parent.setdefault(parent, []).append(member)
            strata = [_ranked_members(stratum, entropy=entropy, scenario_id=f"{scenario_id}:{parent}")
                      for parent, stratum in sorted(by_parent.items())]
            picked = [strata[index % len(strata)][index // len(strata)] for index in range(count)
                      if strata and index // len(strata) < len(strata[index % len(strata)])]
            if len(picked) != count:
                raise PopulationError(f"scenario {scenario_id!r} has too few eligible objects for {count} "
                                      "manipulations spread over its folders")
            bindings[scenario_id] = picked
        else:
            bindings[scenario_id] = _ranked_members(
                members,
                entropy=entropy,
                scenario_id=scenario_id,
            )[:count]
    if pilot_profile.is_pilot(contract) and "usbstor_setupapi_discrepancy_01" in public["scenarios"]:
        identity_sid = "usbstor_setupapi_discrepancy_01"
        history_sid = "usb_volume_activity_gap_01"
        ranked = _ranked_members(public["scenarios"][identity_sid]["members"],
                                 entropy=entropy, scenario_id="pilot-usb-components")
        bindings[identity_sid] = ranked[:1]
        if history_sid in public["scenarios"]:
            history_ref = ranked[1]["subject_ref"]
            bindings[history_sid] = [m for m in public["scenarios"][history_sid]["members"]
                                     if m["subject_ref"] == history_ref]
    return {
        "schema_version": "private_assignment.v1",
        "population_manifest_sha256": public["manifest_sha256"],
        "bindings": bindings,
    }


def _operational_path(member: Mapping[str, Any]) -> str:
    hint = member["identity_hint"]
    for key in ("canonical_path", "base_path"):
        value = hint.get(key)
        if isinstance(value, str) and value:
            return value
    raise PopulationError("population member has no operational path")


def _validate_assignment(
    manifest: Mapping[str, Any], assignment: Mapping[str, Any]
) -> None:
    if assignment.get("schema_version") != "private_assignment.v1":
        raise PopulationError("unsupported private assignment schema")
    if assignment.get("population_manifest_sha256") != manifest["manifest_sha256"]:
        raise PopulationError("private assignment does not match population manifest")
    bindings = assignment.get("bindings")
    if not isinstance(bindings, Mapping) or set(bindings) != set(manifest["scenarios"]):
        raise PopulationError("private assignment scenario set mismatch")
    contract = _contract_for_manifest(manifest)
    for scenario_id, raw_members in bindings.items():
        if not isinstance(raw_members, list):
            raise PopulationError("private assignment binding must be an array")
        expected_count = contract["scenarios"][scenario_id]["manipulation_count"]
        if len(raw_members) != expected_count:
            raise PopulationError("private assignment count mismatch")
        if not all(isinstance(member, Mapping) for member in raw_members):
            raise PopulationError("private assignment has invalid candidate membership")
        public_by_id = {
            member["candidate_id"]: member
            for member in manifest["scenarios"][scenario_id]["members"]
        }
        assigned_ids = [member.get("candidate_id") for member in raw_members]
        if len(assigned_ids) != len(set(assigned_ids)) or not set(
            assigned_ids
        ).issubset(public_by_id):
            raise PopulationError("private assignment has invalid candidate membership")
        if any(
            dict(member) != public_by_id[member["candidate_id"]]
            for member in raw_members
        ):
            raise PopulationError("private assignment has invalid candidate membership")


def build_guest_plan(
    manifest: Mapping[str, Any],
    assignment: Mapping[str, Any],
    *,
    case: str = "positive",
) -> dict[str, Any]:

    if case not in {"positive", "benign"}:
        raise PopulationError("generation case must be positive or benign")
    public = verify_public_manifest(manifest)
    _validate_assignment(public, assignment)
    contract = _contract_for_manifest(public)
    scenario_order = population_scenario_order(public)

    population_members: list[dict[str, str]] = []
    scenario_paths: dict[str, list[str]] = {}
    for scenario_id in scenario_order:
        scenario = public["scenarios"][scenario_id]
        object_kind = contract["scenarios"][scenario_id]["object_kind"]
        if object_kind in {"event_log", "native_usb_device"}:
            continue
        paths = []
        for member in scenario["members"]:
            path = _operational_path(member)
            paths.append(path)
            population_members.append(
                {
                    "object_kind": object_kind,
                    "path": path,
                }
            )
        scenario_paths[scenario_id] = paths

    operation_refs: dict[str, list[Any]] = {}
    for scenario_id, members in assignment["bindings"].items():
        if scenario_id in {"security_log_clear_event_01", "event_record_sequence_gap_01",
                           "usbstor_setupapi_discrepancy_01", "usb_volume_activity_gap_01"}:
            operation_refs[scenario_id] = [member["subject_ref"] for member in members]
        else:
            operation_refs[scenario_id] = [
                _operational_path(member) for member in members
            ]

    seed = public["population_seed"]
    scenario_inputs: dict[str, dict[str, Any]] = {}
    for scenario_id in scenario_order:
        if not public["scenarios"][scenario_id]["members"]:
            continue
        selected_refs = operation_refs[scenario_id]
        if case == "benign":
            selected_refs = []
        scenario_contract = contract["scenarios"][scenario_id]
        expected_population_count = len(public["scenarios"][scenario_id]["members"])
        expected_operation_count = (
            scenario_contract["manipulation_count"] if case == "positive" else 0
        )
        item: dict[str, Any] = {
            "case": case,
            "operation_refs": selected_refs,
            "expected_population_count": expected_population_count,
            "expected_operation_count": expected_operation_count,
        }
        if scenario_id in scenario_paths:
            item["population_paths"] = scenario_paths[scenario_id]
        if scenario_id == "timestomp_01":
            item["timestamps"] = _seeded_stomp_timestamps(seed, count=scenario_contract["manipulation_count"])
            item["timestamp_basis"] = "utc"
            item["archive_last_write_utc"] = archive_control.ARCHIVE_LAST_WRITE_UTC
            item["minimum_backdating_seconds"] = archive_control.MINIMUM_BACKDATING_SECONDS
            item["require_logfile_retention"] = case == "positive"
            item["require_archive_retention"] = True
            item["archive_restore_paths"] = archive_restore_paths(public)
        elif scenario_id == "ads_injection_01":
            count = scenario_contract["manipulation_count"]
            names = [f"n_{_digest(seed, scenario_id, index, 'native-name')[:12]}"
                     for index in range(max(3, count + 1))]
            item["stream_name"] = names[0]
            item["content_kind"] = "native_windows_pe_zip.v2"
            item["zip_stream_name"] = names[2]
            item["zip_member_name"] = "records.csv"
            item["zip_member_content"] = "record,value\n1,public-document\n2,retained-data\n"
            item["zip_stage_name"] = f"a_{_digest(seed, scenario_id, 1, 'archive')[:12]}.zip"
            item["benign_stream_name"] = names[1]
            targets = set(operation_refs[scenario_id])
            controls = [path for path in scenario_paths[scenario_id] if path not in targets]
            item["benign_stream_path"] = (controls or scenario_paths[scenario_id])[0]
            item["benign_stream_content"] = "document_revision=3;application=records"
            if count > 2:
                item["extra_stream_names"] = names[3:]

        elif scenario_id == "typed_path_residue_01":
            item["leaf_name"] = f"f_{_digest(seed, scenario_id, 0, 'leaf')[:12]}.txt"
            item["shortcut_name"] = (
                f"f_{_digest(seed, scenario_id, 0, 'shortcut')[:12]}.lnk"
            )
        elif scenario_id == "ntfs_allocation_01":
            modes = contract["scenarios"][scenario_id].get(
                "storage_modes",
                ["ordinary"] * 8 + ["resident", "preallocation_request_then_close"],
            )
            item["storage_cases"] = [
                {"path": path, "storage_mode": mode,
                 "logical_length": 37 if mode == "resident" else _seeded_logical_length(seed, index)}
                for index, (path, mode) in enumerate(zip(scenario_paths[scenario_id], modes, strict=True))
            ]
        elif scenario_id == "bitmap_trailing_data_01":
            item["bitmap_operations"] = [
                {"mode": "append", "byte_count": _seeded_padding_bytes(seed, index)} if index % 2 == 0
                else {"mode": "truncate", "length": 54}
                for index in range(scenario_contract["manipulation_count"])
            ]
        elif scenario_id == "shellbag_path_residue_01":
            item["visit_budgets"] = validate_visit_budgets(SHELLBAG_VISIT_BUDGETS)
        elif scenario_id == "directory_cleaning_i30_01":
            child_counts = contract["scenarios"][scenario_id].get(
                "directory_child_counts",
                [4 if index < 8 else 80 for index in range(len(scenario_paths[scenario_id]))],
            )
            leaf_count = max(80, *child_counts)
            item["leaf_names"] = [
                f"f_{index:02d}{_digest(seed, scenario_id, index, 'leaf')[:46]}.txt"
                for index in range(leaf_count)
            ]
            item["directory_cases"] = [
                {"path": path, "child_count": child_count}
                for path, child_count in zip(scenario_paths[scenario_id], child_counts, strict=True)
            ]
            item["delete_count_per_directory"] = 4
            item["delete_leaf_indexes"] = [13, 14, 15, 16]
            remaining = sorted(
                range(ORDERED_LEAF_COUNT, leaf_count),
                key=lambda index: _digest(seed, scenario_id, index, "order"),
            )
            item["creation_order"] = list(range(ORDERED_LEAF_COUNT)) + remaining
        if scenario_id in {"usbstor_setupapi_discrepancy_01", "usb_volume_activity_gap_01"}:
            item["file_name"] = f"f_{_digest(seed, 'native_media', 0, 'file')[:12]}.txt"
            item["replacement_name"] = f"f_{_digest(seed, 'native_media', 0, 'alternate')[:12]}.txt"
            item["shortcut_name"] = f"f_{_digest(seed, 'native_media', 0, 'shortcut')[:12]}.lnk"
            item["before_name"] = f"f_{_digest(seed, 'native_media', 0, 'before')[:12]}.txt"
            item["after_name"] = f"f_{_digest(seed, 'native_media', 0, 'after')[:12]}.txt"
        scenario_inputs[scenario_id] = item

    plan = {
        "schema_version": "generation_inputs.v1",
        "population_members": population_members,
        "scenario_inputs": scenario_inputs,
    }
    return pilot_profile.adjust_guest_plan(plan, public, contract)


def operation_refs_sha256(refs: Iterable[str]) -> str:

    normalized = list(refs)
    if any(not isinstance(ref, str) or not ref for ref in normalized):
        raise PopulationError("operation references must be non-empty strings")
    payload = b"generation_operation_refs.v1\n" + canonical_json_bytes(normalized)
    return hashlib.sha256(payload).hexdigest()


_COMMON_RECEIPT_FIELDS = {
    "scenario_id",
    "case",
    "operation_count",
    "operation_refs_sha256",
    "postcondition_verified",
}

_SCENARIO_RECEIPT_FIELDS = {
    "timestomp_01": {"instances"},
    "ads_injection_01": {"content_contract", "streams", "zone_stream_count", "metadata_stream_count"},
    "prefetch_wipe_01": {"population_count", "prefetch_count"},
    "security_log_clear_event_01": {"event_id", "record_id"},
    "event_record_sequence_gap_01": {"retained_tail_count"},
    "usn_journal_01": {"population_count"},
    "shimcache_path_residue_01": {"population_count"},
    "typed_path_residue_01": {
        "population_count",
        "registry_value_count",
        "typed_paths_committed",
    },
    "shellbag_path_residue_01": {
        "population_count", "native_receipts", "absent_count", "visit_budgets",
    },
    "bitmap_trailing_data_01": {"population_count", "instances"},
    "ntfs_allocation_01": {"population_count", "prepared_modes", "preallocation_close_controls"},
    "directory_cleaning_i30_01": {
        "population_count",
        "removed_leaf_count",
        "retained_leaf_count",
        "remaining_leaf_count",
    },
    "usbstor_setupapi_discrepancy_01": {
        "registry_identity_present", "setupapi_identity_present", "native_binding",
    },
    "usb_volume_activity_gap_01": {"link_verified", "native_file_absent"},
}


def _receipt_integer(receipt: Mapping[str, Any], field: str, scenario_id: str) -> int:
    value = receipt.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise PopulationError(
            f"scenario {scenario_id!r} receipt field {field!r} must be an integer"
        )
    return value


def _validate_receipt_fields(
    scenario_id: str,
    inputs: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    case: str,
) -> None:
    expected_fields = _COMMON_RECEIPT_FIELDS | _SCENARIO_RECEIPT_FIELDS[scenario_id]
    pilot = inputs.get("native_pilot_profile") == pilot_profile.PROFILE
    if pilot and scenario_id == "usbstor_setupapi_discrepancy_01":
        expected_fields = _COMMON_RECEIPT_FIELDS | {"native_bindings"}
    if pilot and scenario_id == "usb_volume_activity_gap_01":
        expected_fields = _COMMON_RECEIPT_FIELDS | {"media_receipts"}
    if pilot and scenario_id == "typed_path_residue_01":
        expected_fields |= {"recreated_identity"}
    if set(receipt) != expected_fields:
        raise PopulationError(
            f"scenario {scenario_id!r} receipt fields do not match the v1 contract"
        )

    refs = inputs.get("operation_refs")
    if not isinstance(refs, list):
        raise PopulationError(
            f"scenario {scenario_id!r} operational references are invalid"
        )
    expected_digest = operation_refs_sha256(refs)
    if receipt.get("operation_refs_sha256") != expected_digest:
        raise PopulationError(
            f"scenario {scenario_id!r} operation-reference digest mismatch"
        )
    if receipt.get("case") != case:
        raise PopulationError(
            f"scenario {scenario_id!r} receipt has the wrong generation case"
        )
    if receipt.get("postcondition_verified") is not True:
        raise PopulationError(f"scenario {scenario_id!r} postcondition failed")
    if _receipt_integer(receipt, "operation_count", scenario_id) != len(refs):
        raise PopulationError(
            f"scenario {scenario_id!r} operation count does not match assignment"
        )

    population_paths = inputs.get("population_paths", [])
    if not isinstance(population_paths, list):
        raise PopulationError(f"scenario {scenario_id!r} population paths are invalid")
    population_count = len(population_paths)

    if scenario_id == "timestomp_01":
        strict_backdating = "minimum_backdating_seconds" in inputs
        if strict_backdating and (
            type(inputs["minimum_backdating_seconds"]) is not int
            or inputs["minimum_backdating_seconds"] != archive_control.MINIMUM_BACKDATING_SECONDS
            or inputs.get("archive_last_write_utc") != archive_control.ARCHIVE_LAST_WRITE_UTC
        ):
            raise PopulationError("timestamp backdating input contract is invalid")
        instances = receipt.get("instances")
        if not isinstance(instances, list) or len(instances) != len(refs):
            raise PopulationError(
                f"scenario {scenario_id!r} receipt fields have invalid instances"
            )
        for index, instance in enumerate(instances):
            if (
                not isinstance(instance, Mapping)
                or set(instance) not in (
                    [{"original_creation_utc", "original_modified_utc", "assigned_timestamp"}]
                    if strict_backdating else [
                        {"original_creation_utc", "assigned_timestamp"},
                        {"original_creation_utc", "original_modified_utc", "assigned_timestamp"},
                    ]
                )
                or not isinstance(instance.get("original_creation_utc"), str)
                or not instance["original_creation_utc"]
                or not isinstance(instance.get("assigned_timestamp"), str)
                or not instance["assigned_timestamp"]
                or not _assigned_timestamp_matches(
                    instance["assigned_timestamp"], str(inputs["timestamps"][index])
                )
            ):
                raise PopulationError(
                    f"scenario {scenario_id!r} receipt fields have invalid instances"
                )
            if strict_backdating or "original_modified_utc" in instance:
                assigned = _instant(instance["assigned_timestamp"])
                before = [_instant(instance.get(field)) for field in ("original_creation_utc", "original_modified_utc")]
                if (assigned is None or assigned.tzinfo is None
                        or any(stamp is None or stamp.tzinfo is None for stamp in before)
                        or any(stamp - assigned < timedelta(seconds=archive_control.MINIMUM_BACKDATING_SECONDS)
                               for stamp in before)):
                    raise PopulationError("timestamp receipt does not prove both fields backdated by at least 60 seconds")
    elif scenario_id == "ads_injection_01":
        streams = receipt.get("streams")
        expected = ads_streams(inputs, len(refs)) if case == "positive" else []
        if (receipt.get("content_contract") != "named_stream_pe_zip.v2"
                or not isinstance(streams, list) or len(streams) != len(expected)
                or len(refs) != len(expected)
                or _receipt_integer(receipt, "zone_stream_count", scenario_id) != population_count
                or _receipt_integer(receipt, "metadata_stream_count", scenario_id) != 1):
            raise PopulationError("native PE/ZIP stream receipt does not match the declared content contract")
        for item, (kind, stream_name) in zip(streams, expected):
            if (not isinstance(item, Mapping) or set(item) != {"format", "stream_name", "stream_length", "stream_sha256"}
                    or item.get("format") != kind or item.get("stream_name") != stream_name
                    or type(item.get("stream_length")) is not int
                    or not (512 if kind == "pe" else 22) <= item["stream_length"] <= 32 * 1024 * 1024
                    or not isinstance(item.get("stream_sha256"), str) or len(item["stream_sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in item["stream_sha256"])):
                raise PopulationError("native PE/ZIP stream instance receipt is malformed or reordered")
    elif scenario_id == "shellbag_path_residue_01":
        native = receipt.get("native_receipts")
        required_flags = {
            "interactive_vagrant_explorer_verified", "stable_pre_snapshots_verified",
            "native_bagmru_numeric_binary_verified", "native_mrulistex_structure_verified",
            "custom_string_hint_absent", "scheduled_task_completed",
            "scheduled_task_unregistered", "exact_target_window_matched",
            "exact_target_window_closed",
        }
        count_fields = {"changed_key_count", "changed_numeric_value_count", "changed_mrulistex_count"}
        timing_fields = {"visit_elapsed_ms", "explore_elapsed_ms", "snapshot_count"}
        if (
            _receipt_integer(receipt, "population_count", scenario_id) != population_count
            or _receipt_integer(receipt, "absent_count", scenario_id) != len(refs)
            or not isinstance(native, list) or len(native) != population_count
        ):
            raise PopulationError("Shellbag receipt does not verify the complete population")
        budgets = validate_visit_budgets(inputs.get("visit_budgets"))
        if receipt.get("visit_budgets") != budgets:
            raise PopulationError("Shellbag receipt budgets differ from the frozen visit budgets")
        for item in native:
            measured_dispatch = isinstance(item, Mapping) and "dispatch_elapsed_ms" in item
            item_timing_fields = timing_fields | ({"dispatch_elapsed_ms"} if measured_dispatch else set())
            if (not isinstance(item, Mapping)
                or set(item) != required_flags | count_fields | item_timing_fields
                or any(item.get(key) is not True for key in required_flags)
                or any(type(item.get(key)) is not int or item[key] < 1 for key in count_fields)
                or any(type(item.get(key)) is not int or item[key] < 0 for key in item_timing_fields)
                or item["snapshot_count"] < SHELLBAG_MINIMUM_SNAPSHOTS_PER_VISIT
                or item["explore_elapsed_ms"] > item["visit_elapsed_ms"]
                or (measured_dispatch and item["dispatch_elapsed_ms"] > item["explore_elapsed_ms"])):
                raise PopulationError("Shellbag receipt lacks verified native Explorer postconditions")
    elif scenario_id == "prefetch_wipe_01":
        if (
            _receipt_integer(receipt, "population_count", scenario_id)
            != population_count
            or _receipt_integer(receipt, "prefetch_count", scenario_id)
            != population_count
        ):
            raise PopulationError(
                f"scenario {scenario_id!r} receipt fields do not verify Prefetch"
            )
    elif scenario_id == "event_record_sequence_gap_01":
        if _receipt_integer(receipt, "retained_tail_count", scenario_id) != 3:
            raise PopulationError("Event sequence preparation requires three retained tail records")
    elif scenario_id == "security_log_clear_event_01":
        if case == "positive":
            record_id = receipt.get("record_id")
            valid = (
                receipt.get("event_id") == 1102
                and isinstance(record_id, int)
                and not isinstance(record_id, bool)
                and record_id > 0
            )
        else:
            valid = receipt.get("event_id") is None and receipt.get("record_id") is None
        if not valid:
            raise PopulationError(
                f"scenario {scenario_id!r} receipt fields do not verify Event 1102"
            )
    elif scenario_id in {"usn_journal_01", "shimcache_path_residue_01"}:
        if (
            _receipt_integer(receipt, "population_count", scenario_id)
            != population_count
        ):
            raise PopulationError(
                f"scenario {scenario_id!r} receipt fields have invalid population metrics"
            )
    elif scenario_id == "typed_path_residue_01":
        if (
            _receipt_integer(receipt, "population_count", scenario_id)
            != population_count
            or _receipt_integer(receipt, "registry_value_count", scenario_id)
            < population_count
            or receipt.get("typed_paths_committed") is not True
        ):
            raise PopulationError(
                f"scenario {scenario_id!r} receipt fields do not verify path residue"
            )
        if pilot:
            recreation = receipt["recreated_identity"]
            if (not isinstance(recreation, Mapping)
                    or recreation.get("path") != inputs["recreated_path"]
                    or not recreation.get("before") or not recreation.get("after")
                    or recreation["before"] == recreation["after"]):
                raise PopulationError("pilot TypedPaths recreation lacks a new native identity")
    elif scenario_id == "ntfs_allocation_01":
        if (_receipt_integer(receipt, "population_count", scenario_id) != population_count
            or receipt.get("prepared_modes") != [item["storage_mode"] for item in inputs["storage_cases"]]):
            raise PopulationError("NTFS allocation receipt does not verify storage preparation")
        controls = [item for item in inputs["storage_cases"]
                    if item["storage_mode"] == "preallocation_request_then_close"]
        observed = receipt.get("preallocation_close_controls")
        if not isinstance(observed, list) or len(observed) != len(controls):
            raise PopulationError("NTFS allocation receipt lacks the native close lifecycle")
        fields = {"path", "requested_allocation_bytes", "open_allocation_bytes", "open_eof_bytes",
                  "closed_allocation_bytes", "closed_eof_bytes", "content_sha256"}
        for control, actual in zip(controls, observed, strict=True):
            if not isinstance(actual, Mapping) or set(actual) != fields or actual["path"] != control["path"]:
                raise PopulationError("NTFS preallocation lifecycle identity is invalid")
            sizes = {key: _receipt_integer(actual, key, scenario_id)
                     for key in fields - {"path", "content_sha256"}}
            length = control["logical_length"]
            expected_content = hashlib.sha256(bytes((index * 37 + 19) % 251 for index in range(length))).hexdigest()
            if (sizes["requested_allocation_bytes"] != 65536
                    or sizes["open_allocation_bytes"] < sizes["requested_allocation_bytes"]
                    or sizes["open_eof_bytes"] != length or sizes["closed_eof_bytes"] != length
                    or not length <= sizes["closed_allocation_bytes"] < sizes["open_allocation_bytes"]
                    or actual["content_sha256"] != expected_content):
                raise PopulationError("NTFS preallocation lifecycle did not prove allocation and release with unchanged content")
    elif scenario_id == "bitmap_trailing_data_01":
        instances = receipt.get("instances")
        operations = inputs.get("bitmap_operations")
        if (not isinstance(operations, list) or not operations
                or (case == "positive" and len(operations) != len(refs))
                or not all(isinstance(op, Mapping) and _bitmap_operation_valid(op, pilot) for op in operations)
                or _receipt_integer(receipt, "population_count", scenario_id) != population_count
                or not isinstance(instances, list) or len(instances) != len(refs)):
            raise PopulationError("bitmap content-operation contract is invalid")
        for operation, instance in zip(operations, instances, strict=False):
            expected = {"mode": operation["mode"], "declared_length": 58,
                        "materialized_length": 58 + operation["byte_count"]
                        if operation["mode"] == "append" else operation["length"]}
            if instance != expected or any(type(instance[k]) is not int for k in ("declared_length", "materialized_length")):
                raise PopulationError("bitmap content-operation postcondition is invalid")
    elif scenario_id == "directory_cleaning_i30_01":
        expected_removed = len(refs) * inputs["delete_count_per_directory"]
        expected_retained = sum(item["child_count"] for item in inputs["directory_cases"]) - expected_removed
        if (
            _receipt_integer(receipt, "population_count", scenario_id)
            != population_count
            or _receipt_integer(receipt, "removed_leaf_count", scenario_id)
            != expected_removed
            or _receipt_integer(receipt, "retained_leaf_count", scenario_id)
            != expected_retained
            or _receipt_integer(receipt, "remaining_leaf_count", scenario_id)
            != expected_retained
        ):
            raise PopulationError(
                f"scenario {scenario_id!r} receipt fields do not verify directory leaves"
            )
    elif pilot and scenario_id == "usbstor_setupapi_discrepancy_01":
        bindings = receipt["native_bindings"]
        media = inputs["media"]
        if (not isinstance(bindings, list) or len(bindings) != len(media)
                or not 2 <= len(media) <= len(pilot_profile.MEDIA_PORTS)):
            raise PopulationError("pilot requires one complete native USB binding for each drive")
        for expected, actual in zip(media, bindings, strict=True):
            if (not isinstance(actual, Mapping)
                    or set(actual) != {"subject_ref", "binding_file", "native_binding"}
                    or actual["subject_ref"] != expected["subject_ref"]
                    or actual["binding_file"] != expected["binding_file"]
                    or actual.get("native_binding", {}).get("companion_file") != expected["companion_file"]):
                raise PopulationError("pilot native USB binding belongs to another volume")
            legacy_inputs = {k: v for k, v in inputs.items() if k != "native_pilot_profile"}
            legacy_receipt = {k: receipt[k] for k in _COMMON_RECEIPT_FIELDS}
            legacy_receipt.update(registry_identity_present=True, setupapi_identity_present=True,
                                  native_binding={**actual["native_binding"], "companion_file": "native_media.vmdk"})
            _validate_receipt_fields(scenario_id, legacy_inputs, legacy_receipt, case=case)
        for field in ("device_instance_id", "volume_serial_number", "volume_guid_path", "disk_unique_id", "target_path", "link_path"):
            if len({str(r["native_binding"][field]).casefold() for r in bindings}) != len(media):
                raise PopulationError(f"pilot native USB {field} identities are not unique")
    elif pilot and scenario_id == "usb_volume_activity_gap_01":
        rows = receipt["media_receipts"]
        if not isinstance(rows, list) or len(rows) != len(inputs["media"]):
            raise PopulationError("pilot USB history receipt is incomplete")
        for expected, actual in zip(inputs["media"], rows, strict=True):
            if (set(actual) != {"subject_ref", "link_verified", "native_file_absent"}
                    or actual["subject_ref"] != expected["subject_ref"]
                    or actual["link_verified"] is not True
                    or actual["native_file_absent"] is not expected["history_discrepancy"]):
                raise PopulationError("pilot USB history state differs from its assigned component")
    elif scenario_id == "usbstor_setupapi_discrepancy_01":
        if receipt.get("registry_identity_present") is not True or receipt.get(
            "setupapi_identity_present"
        ) is not True:
            raise PopulationError(
                f"scenario {scenario_id!r} receipt fields do not verify the native device identity"
            )
        binding = receipt.get("native_binding")
        binding_fields = {
            "schema_version", "device_instance_id", "parent_device_instance_ids",
            "setupapi_device_instance_id", "disk_bus_type", "attachment_kind",
            "physical_host_device", "disk_size_bytes", "disk_unique_id", "volume_guid_path",
            "volume_serial_number", "partition_offset_bytes", "link_path", "target_path",
            "target_file_reference_number", "observation_start_utc", "observation_end_utc",
            "journal_start_usn", "journal_id", "companion_file",
        }
        if (not isinstance(binding, Mapping) or set(binding) != binding_fields
            or binding.get("schema_version") != "native_media_binding.v1"
            or binding.get("attachment_kind") != "hypervisor_virtual_usb_mass_storage"
            or binding.get("physical_host_device") is not False
            or binding.get("disk_bus_type") != "USB"
            or binding.get("disk_size_bytes") != 67108864
            or not str(binding.get("device_instance_id", "")).upper().startswith("USBSTOR\\")
            or binding.get("companion_file") != "native_media.vmdk"):
            raise PopulationError("native media binding is missing or invalid")
        for key in ("target_file_reference_number", "journal_id"):
            if type(binding.get(key)) is not int or not 0 < binding[key] < 2**64:
                raise PopulationError("native media binding has an invalid native identifier")
        for key in ("journal_start_usn", "partition_offset_bytes"):
            if type(binding.get(key)) is not int or binding[key] < 0:
                raise PopulationError("native media binding has an invalid native extent")
        serial = binding.get("volume_serial_number")
        if (not isinstance(serial, str) or len(serial) != 8
            or any(character not in "0123456789abcdefABCDEF" for character in serial)
            or not isinstance(binding.get("parent_device_instance_ids"), list)):
            raise PopulationError("native media binding has an invalid volume or ancestry")
        for key in ("link_path", "target_path", "volume_guid_path", "setupapi_device_instance_id",
                    "observation_start_utc", "observation_end_utc"):
            if not isinstance(binding.get(key), str) or not binding[key]:
                raise PopulationError("native media binding lacks required native facts")
    elif scenario_id == "usb_volume_activity_gap_01":
        if (receipt.get("link_verified") is not True
            or receipt.get("native_file_absent") is not (case == "positive")):
            raise PopulationError("native media reference preparation is incomplete")


def validate_guest_receipts(
    guest_plan: Mapping[str, Any],
    receipts: Iterable[Mapping[str, Any]],
    *,
    case: str,
) -> list[dict[str, Any]]:

    if case not in {"positive", "benign"}:
        raise PopulationError("generation case must be positive or benign")
    if guest_plan.get("schema_version") != "generation_inputs.v1":
        raise PopulationError("guest plan must use generation_inputs.v1")
    scenario_inputs = guest_plan.get("scenario_inputs")
    if not isinstance(scenario_inputs, Mapping) or not scenario_inputs:
        raise PopulationError("guest plan scenario inputs are invalid")

    receipt_by_scenario: dict[str, dict[str, Any]] = {}
    for raw in receipts:
        if not isinstance(raw, Mapping):
            raise PopulationError("guest receipt must be an object")
        receipt = dict(raw)
        scenario_id = receipt.get("scenario_id")
        if not isinstance(scenario_id, str) or scenario_id in receipt_by_scenario:
            raise PopulationError("guest receipts have duplicate or invalid scenarios")
        receipt_by_scenario[scenario_id] = receipt
    if set(receipt_by_scenario) != set(scenario_inputs):
        raise PopulationError("guest receipt scenario set mismatch")

    validated = []
    for scenario_id, raw_inputs in scenario_inputs.items():
        if scenario_id not in _SCENARIO_RECEIPT_FIELDS:
            raise PopulationError(f"unsupported receipt scenario: {scenario_id}")
        scenario_case = case
        if (guest_plan.get("native_pilot_profile") == pilot_profile.PROFILE
                and scenario_id == "security_log_clear_event_01"):
            scenario_case = "benign"
        if not isinstance(raw_inputs, Mapping) or raw_inputs.get("case") != scenario_case:
            raise PopulationError(
                f"scenario {scenario_id!r} inputs have the wrong generation case"
            )
        receipt = receipt_by_scenario[scenario_id]
        _validate_receipt_fields(
            scenario_id,
            raw_inputs,
            receipt,
            case=scenario_case,
        )
        validated.append(receipt)
    return validated


def build_ground_truth(
    manifest: Mapping[str, Any],
    assignment: Mapping[str, Any],
    receipts: Iterable[Mapping[str, Any]],
    *,
    case: str = "positive",
) -> dict[str, Any]:

    public = verify_public_manifest(manifest)
    _validate_assignment(public, assignment)
    guest_plan = build_guest_plan(public, assignment, case=case)
    validated_receipts = validate_guest_receipts(guest_plan, receipts, case=case)
    receipt_by_scenario = {
        receipt["scenario_id"]: receipt for receipt in validated_receipts
    }

    scenario_truth = []
    for scenario_id in public["scenarios"]:
        if scenario_id not in guest_plan["scenario_inputs"]:
            scenario_truth.append({"scenario_id": scenario_id, "candidate_ids": [], "receipt": {
                "scenario_id": scenario_id, "case": case, "operation_count": 0, "operation_refs": [],
                "postcondition_verified": True, "population_count": 0}})
            continue
        receipt = receipt_by_scenario[scenario_id]
        operation_refs = guest_plan["scenario_inputs"][scenario_id]["operation_refs"]
        host_receipt = {**receipt, "operation_refs": list(operation_refs)}
        scenario_truth.append(
            {
                "scenario_id": scenario_id,
                "candidate_ids": (
                    [
                        member["candidate_id"]
                        for member in assignment["bindings"][scenario_id]
                    ]
                    if guest_plan["scenario_inputs"][scenario_id]["case"] == "positive"
                    else []
                ),
                "receipt": host_receipt,
            }
        )

    return {
        "schema_version": "generation_ground_truth.v1",
        "experiment": public["experiment"],
        "case": case,
        "population_manifest_sha256": public["manifest_sha256"],
        "scenarios": scenario_truth,
    }


def archive_restore_paths(public: Mapping[str, Any]) -> list[str]:
    paths = [_operational_path(m) for m in public["scenarios"]["timestomp_01"]["members"]]
    contract = _contract_for_manifest(public)
    endpoints = contract["scenarios"]["timestomp_01"].get(
        "restore_stratum_end_indexes", [len(paths)]
    )
    selected: list[str] = []
    start = 0
    for end in endpoints:
        ranked = sorted(
            paths[start:end],
            key=lambda p: _sha256({
                "seed": public["population_seed"],
                "path": p,
                "purpose": "archive-restoration-control",
            }),
        )
        selected.extend(ranked[:len(ranked) // 2])
        start = end
    return sorted(selected)


def build_finding_reference(manifest: Mapping[str, Any], operation_truth: Mapping[str, Any],
                            archive_receipt: dict[str, Any] | None = None) -> dict[str, Any]:
    public = verify_public_manifest(manifest)
    if (operation_truth.get("schema_version") != "generation_ground_truth.v1"
            or operation_truth.get("population_manifest_sha256") != public["manifest_sha256"]
            or operation_truth.get("experiment") != public["experiment"]):
        raise PopulationError("finding reference requires population-bound operation truth")
    scenarios = operation_truth.get("scenarios", [])
    if {s["scenario_id"] for s in scenarios} != set(public["scenarios"]) or len(scenarios) != len(public["scenarios"]):
        raise PopulationError("finding reference operation scope differs from the population")
    if ("timestomp_01" in public["scenarios"]) != (archive_receipt is not None):
        raise PopulationError("the finding reference takes the archive receipt exactly when the image has timestomp_01")
    restored = set()
    time_members = public["scenarios"].get("timestomp_01", {}).get("members", [])
    paths = {_operational_path(m).casefold(): m["candidate_id"] for m in time_members}
    if archive_receipt is not None:
        archive_control.validate_receipt(archive_receipt, list(paths), restore_paths=archive_restore_paths(public))
    for row in (archive_receipt or {}).get("records", []):
        before = datetime.fromisoformat(row["write_before_utc"].replace("Z", "+00:00"))
        after = datetime.fromisoformat(row["write_after_utc"].replace("Z", "+00:00"))
        if before.tzinfo is None or after.tzinfo is None:
            raise PopulationError("finding-reference timestamps need an explicit time zone")
        if after < before:
            restored.add(paths[row["path"].casefold()])
    reference = []
    for scenario in scenarios:
        sid = scenario["scenario_id"]
        members = {m["candidate_id"] for m in public["scenarios"][sid]["members"]}
        selected = set(scenario["candidate_ids"])
        if not selected <= members or scenario.get("receipt", {}).get("postcondition_verified") is not True:
            raise PopulationError("finding reference contains unverified operations")
        if sid == "timestomp_01":
            selected |= restored
        reference.append({"scenario_id": sid, "candidate_ids": sorted(selected)})
    return {"schema_version": "generation_finding_reference.v1",
        "reference_contract": "broad_native_findings.v1", "experiment": public["experiment"],
        "case": operation_truth["case"], "population_manifest_sha256": public["manifest_sha256"],
        "operation_truth_payload_sha256": _sha256(operation_truth),
        **({} if archive_receipt is None else {"archive_receipt_payload_sha256": _sha256(archive_receipt)}),
        "scenarios": reference}


__all__ = [
    "POPULATION_CONTRACT_PATH",
    "PopulationError",
    "SCENARIO_ANALYSIS",
    "build_ground_truth",
    "build_guest_plan",
    "build_public_manifest",
    "canonical_json_bytes",
    "load_population_contract",
    "operation_refs_sha256",
    "population_scenario_order",
    "select_private_assignment",
    "validate_guest_receipts",
    "verify_public_manifest",
]
