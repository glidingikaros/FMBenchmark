from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path

import pytest

from fmb.analysis.population_binding import (
    bind_population_manifest,
    load_generated_population_bundle,
)
from rule_helpers import analyze_input
from fmb.analysis.inputs import canonical_sha256
from paper_fixtures import prepare_analysis_inputs
from fmb.index.adapters import event_log as event_log_adapters
from fmb.index.adapters.event_log import (
    event_log_scope_id,
    evtxecmd_parser_run,
)
from fmb.index.adapters.mft import timestamp_candidate_population
from fmb.index.adapters.registry import usbstor_parser_run
from fmb.index.scanners.usn import ntfs_reference_set_sha256


_DESTROYED_CLEANUP_RECEIPT = {
    "schema_version": "generation_cleanup.v1",
    "provider": "virtualbox",
    "status": "destroyed",
    "provider_state_remaining": False,
}


_SCENARIO_OBSERVATION = {
    "shellbag_path_residue_01": ("windows.registry.shellbag", "shellbag_path_seen", "windows_shellbag"),
    "ntfs_allocation_01": ("ntfs.file_size_allocation", "ntfs_allocation_record", "ntfs_file_size_allocation"),
    "event_record_sequence_gap_01": ("windows.event_log.record_sequence", "event_log_scope_seen", "windows_evtx_security"),
    "usb_volume_activity_gap_01": ("usb_volume", "usb_volume_reference_history", "native_usb_volume"),
    "timestomp_01": ("ntfs.mft", "mft_file_record", "ntfs_mft"),
    "prefetch_wipe_01": (
        "windows.prefetch",
        "prefetch_execution",
        "windows_prefetch",
    ),
    "security_log_clear_event_01": (
        "windows.event_log.security",
        "event_id_1102",
        "windows_evtx_security",
    ),
    "usn_journal_01": ("ntfs.usn", "usn_file_delete", "ntfs_usn"),
    "shimcache_path_residue_01": (
        "windows.registry.shimcache",
        "shimcache_path_seen",
        "windows_registry_paths",
    ),
    "typed_path_residue_01": (
        "windows.registry.typed_paths",
        "typed_path_seen",
        "windows_typed_paths",
    ),
    "bitmap_trailing_data_01": (
        "ntfs.file_size_allocation",
        "logical_allocated_size_record",
        "ntfs_file_size_allocation",
    ),
    "directory_cleaning_i30_01": (
        "ntfs.i30",
        "i30_filename_residue",
        "ntfs_i30",
    ),
    "usbstor_setupapi_discrepancy_01": (
        "windows.registry.usbstor",
        "usb_device_seen",
        "windows_usbstor",
    ),
}

_VERIFIED_MFT_TIMESTAMPS = {
    "si_created": "2026-08-26T12:00:00Z",
    "si_modified": "2026-08-26T12:00:00Z",
    "si_record_changed": "2026-08-26T12:00:00Z",
    "si_accessed": "2026-08-26T12:00:00Z",
    "fn_created": "2026-08-26T12:00:00Z",
    "fn_modified": "2026-08-26T12:00:00Z",
    "fn_record_changed": "2026-08-26T12:00:00Z",
    "fn_accessed": "2026-08-26T12:00:00Z",
    "raw_mft_timestamp_validation": "verified",
}


def _build_public_manifest(*, experiment: str, seed: int, legacy: bool = False) -> dict[str, object]:
    module_path = Path(__file__).resolve().parents[2] / "src/fmb/generation" / "population.py"
    spec = importlib.util.spec_from_file_location(
        "population_binding_fixture", module_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    contract = module.load_population_contract(Path(__file__).resolve().parents[1] / "fixtures/generation/populations.v1.json")
    return module.build_public_manifest(experiment=experiment, seed=seed, contract=contract)


def _timestomp_index(manifest: dict[str, object]) -> dict[str, object]:
    scenario = manifest["scenarios"]["timestomp_01"]
    members = scenario["members"]
    observations = [
        {
            "observation_id": f"obs:mft:{index:03d}",
            "artifact_family": "ntfs.mft",
            "observation_type": "mft_file_record",
            "subject_ref": member["subject_ref"],
            "fields": {
                "mft_volume_id": "volume:generated",
                "mft_entry": index + 100,
                "sequence_number": 1,
                "mft_active_status": "active",
                **_VERIFIED_MFT_TIMESTAMPS,
            },
            "source_record_ref": f"mft.csv:{index + 1}",
        }
        for index, member in enumerate(members)
    ]
    return {
        "schema_version": "evidence_index.v1",
        "run_id": "generated-timestomp",
        "parser_runs": [
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "complete",
                "observations": observations,
            },
            {
                "parser_kind": "ntfs_usn",
                "status": "consumed",
                "coverage_status": "complete",
                "observations": [],
            },
        ],
    }


def _full_scale_index(manifest: dict[str, object]) -> dict[str, object]:
    by_parser: dict[str, list[dict[str, object]]] = {}
    scenarios = manifest["scenarios"]
    for scenario_id, scenario in scenarios.items():
        members = scenario["members"]
        if scenario_id == "ads_injection_01":
            for index, member in enumerate(members):
                artifact_family = "ntfs.ads" if index == 0 else "ntfs.mft"
                observation_type = (
                    "named_data_stream" if index == 0 else "mft_file_record"
                )
                parser_kind = "ntfs_ads" if index == 0 else "ntfs_mft"
                fields = {
                    "base_path": member["identity_hint"]["base_path"],
                    "stream_name": "concealed" if index == 0 else "",
                    "mft_volume_id": "volume:generated",
                    "mft_entry": 1000 + index,
                    "sequence_number": 1,
                }
                subject_ref = (
                    f"{member['subject_ref']}:concealed"
                    if index == 0
                    else member["subject_ref"]
                )
                by_parser.setdefault(parser_kind, []).append(
                    {
                        "observation_id": f"obs:{scenario_id}:{index:03d}",
                        "artifact_family": artifact_family,
                        "observation_type": observation_type,
                        "subject_ref": subject_ref,
                        "fields": fields,
                        "source_record_ref": f"{scenario_id}:{index}",
                    }
                )
                if index == 1:
                    by_parser[parser_kind].append(
                        {
                            "observation_id": f"obs:{scenario_id}:{index:03d}:derived",
                            "artifact_family": "ntfs.mft",
                            "observation_type": "si_fn_timestamp_difference",
                            "subject_ref": subject_ref,
                            "fields": dict(fields),
                            "source_record_ref": f"{scenario_id}:{index}:derived",
                        }
                    )
            continue
        artifact_family, observation_type, parser_kind = _SCENARIO_OBSERVATION[
            scenario_id
        ]
        for index, member in enumerate(members):
            fields = dict(member["identity_hint"])
            if scenario_id == "typed_path_residue_01":
                fields["source_key"] = (
                    r"ROOT\Software\Microsoft\Windows\CurrentVersion"
                    r"\Explorer\TypedPaths"
                )
            if scenario_id == "timestomp_01":
                fields.update(_VERIFIED_MFT_TIMESTAMPS)
            if scenario_id in {"usbstor_setupapi_discrepancy_01", "usb_volume_activity_gap_01"}:
                fields.update(device_instance_id=r"USBSTOR\DISK&VEN_TEST\SERIAL-NATIVE&0",
                              serial_number="SERIAL-NATIVE&0", native_binding_hash_verified=True,
                              native_binding_file="native_media_binding.json")
            by_parser.setdefault(parser_kind, []).append(
                {
                    "observation_id": f"obs:{scenario_id}:{index:03d}",
                    "artifact_family": artifact_family,
                    "observation_type": observation_type,
                    "subject_ref": fields.get("canonical_path", member["subject_ref"]),
                    "fields": fields,
                    "source_record_ref": f"{scenario_id}:{index}",
                }
            )
    for parser_kind in (
        "materialized_file_content",
        "windows_setupapi",
    ):
        by_parser.setdefault(parser_kind, [])
    return {
        "schema_version": "evidence_index.v1",
        "run_id": "generated-full-scale",
        "parser_runs": [
            {
                "parser_kind": parser_kind,
                "status": "consumed",
                "coverage_status": "complete",
                "observations": observations,
            }
            for parser_kind, observations in by_parser.items()
        ],
    }


def test_public_population_manifest_binds_the_complete_generated_roster() -> None:
    manifest = _build_public_manifest(experiment="timestomp", seed=20260826)

    bound = bind_population_manifest(_timestomp_index(manifest), manifest)
    analysis_input = prepare_analysis_inputs(
        bound,
        question_id="Q-TIME-01",
    )[0]

    assert (
        bound["population_manifest"]["manifest_sha256"] == manifest["manifest_sha256"]
    )
    assert len(bound["candidate_populations"]) == 1
    assert bound["candidate_populations"][0]["coverage_status"] == "complete"
    assert len(analysis_input.candidate_roster.subjects) == 55
    assert analysis_input.candidate_roster.coverage_status == "complete"
    assert analysis_input.readiness == "ready"


def test_public_device_roster_fails_closed_without_matching_evidence() -> None:
    manifest = _build_public_manifest(experiment="full_scale", seed=20260827)
    external_media = manifest["scenarios"]["usbstor_setupapi_discrepancy_01"]
    manifest = {
        **manifest,
        "scenarios": {"usbstor_setupapi_discrepancy_01": external_media},
        "declared_count": 1,
    }
    manifest.pop("manifest_sha256")
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "generated-device-with-missing-parser-record",
        "parser_runs": [
            {
                "parser_kind": parser_kind,
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [],
            }
            for parser_kind in ("windows_usbstor", "windows_setupapi")
        ],
    }

    with pytest.raises(ValueError, match="native USB population requires one hash-bound device identity"):
        bind_population_manifest(evidence_index, manifest)


def test_public_device_roster_binds_to_stock_usbstor_plugin_evidence(
    tmp_path: Path,
) -> None:
    manifest = _build_public_manifest(experiment="full_scale", seed=20260827, legacy=False)
    external_media = manifest["scenarios"]["usbstor_setupapi_discrepancy_01"]
    manifest = {
        **manifest,
        "scenarios": {"usbstor_setupapi_discrepancy_01": external_media},
        "declared_count": 1,
    }
    manifest.pop("manifest_sha256")
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    member = external_media["members"][0]
    hint = member["identity_hint"]
    instance = r"USBSTOR\Disk&Ven_TEST&Prod_NATIVE\SERIAL-NATIVE&0"
    prefix, hardware, serial = instance.split("\\", 2)
    assert prefix.casefold() == "usbstor"
    assert hint["binding_file"] == "native_media_binding.json"
    csv_path = tmp_path / "RECmd_Batch_MC.csv"
    csv_path.write_text(
        "Timestamp,BatchKeyPath,SerialNumber,DeviceName,Installed,"
        "FirstInstalled,LastConnected,LastRemoved\n"
        f"2026-08-27T01:00:00Z,ROOT\\ControlSet001\\Enum\\USBSTOR\\"
        f"{hardware},{serial},Generated USB device,2026-08-27T01:01:00Z,"
        "2026-08-27T01:02:00Z,2026-08-27T01:03:00Z,"
        "2026-08-27T01:04:00Z\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    parser_run = usbstor_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={"collector": "kape", "provenance": {}},
    )
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "generated-device-with-stock-plugin-record",
        "parser_runs": [parser_run],
    }

    with pytest.raises(ValueError, match="hash-bound device identity"):
        bind_population_manifest(evidence_index, manifest)
    evidence_index["parser_runs"].append({
        "parser_kind": "native_usb_volume", "status": "consumed", "coverage_status": "complete",
        "observations": [{"observation_id": "native:usb", "artifact_family": "usb_volume",
                          "observation_type": "usb_volume_reference_history", "subject_ref": instance,
                          "source_record_ref": "native:binding",
                          "fields": {"attachment_kind": hint["attachment_kind"], "disk_size_bytes": hint["disk_size_bytes"],
                                     "native_binding_file": hint["binding_file"], "native_binding_hash_verified": True,
                                     "device_instance_id": instance, "serial_number": serial}}]})
    bound = bind_population_manifest(evidence_index, manifest)

    subject = bound["candidate_populations"][0]["subjects"][0]
    assert subject["subject_ref"] == member["subject_ref"]
    assert subject["identity"] == {
        "device_instance_id": instance.casefold(),
        "serial_number": serial.casefold(),
    }
    assert subject["observation_ids"] == [
        parser_run["observations"][0]["observation_id"]
    ]


def test_complete_security_log_surface_binds_a_zero_anomaly_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _build_public_manifest(experiment="full_scale", seed=20260827)
    scenario = manifest["scenarios"]["security_log_clear_event_01"]
    manifest = {
        **manifest,
        "scenarios": {"security_log_clear_event_01": scenario},
        "declared_count": 1,
    }
    manifest.pop("manifest_sha256")
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    raw_log = tmp_path / "Security.evtx"
    raw_log.write_bytes(b"bounded raw Security event log")
    csv_path = tmp_path / "EvtxECmd_Output.csv"
    csv_path.write_text(
        "EventId,EventRecordId,Channel,SourceFile\n"
        r"4624,77,Security,C:\Windows\System32\winevt\Logs\Security.evtx"
        "\n",
        encoding="utf-8",
    )
    normalized = tmp_path / "normalized"
    normalized.mkdir()
    monkeypatch.setattr(event_log_adapters, "retained_record_ids", lambda _data: (77,))
    parser_run = evtxecmd_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized,
        collector_run={
            "collector": "kape",
            "provenance": {},
            "artifacts": [{"path": str(raw_log), "relative_path": "Security.evtx"}],
        },
    )
    normalized_parser_run = {
        key: value
        for key, value in parser_run.items()
        if key != "candidate_populations"
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "generated-security-log-with-no-clear-event",
        "parser_runs": [normalized_parser_run],
    }

    bound = bind_population_manifest(evidence_index, manifest)
    subject = bound["candidate_populations"][0]["subjects"][0]
    scope_observation = next(
        item
        for item in normalized_parser_run["observations"]
        if item["observation_type"] == "event_log_scope_seen"
    )
    analysis_input = prepare_analysis_inputs(bound, question_id="Q-LOG-01")[0]

    assert subject == {
        "subject_ref": "Security",
        "identity": {
            "object_id": event_log_scope_id(
                "Security",
                r"C:\Windows\System32\winevt\Logs\Security.evtx",
                csv_path,
            )
        },
        "observation_ids": [scope_observation["observation_id"]],
    }
    assert analysis_input.readiness == "ready"

    normalized_parser_run["coverage_status"] = "partial"
    partial_bound = bind_population_manifest(evidence_index, manifest)
    partial_input = prepare_analysis_inputs(
        partial_bound,
        question_id="Q-LOG-01",
    )[0]
    partial_result = analyze_input(partial_input)

    assert partial_input.readiness == "insufficient_evidence"
    assert partial_result.status == "insufficient_evidence"
    assert {item.outcome for item in partial_result.assessments} == {"indeterminate"}
    assert {item.reason_code for item in partial_result.assessments} == {
        "required_evidence_incomplete"
    }

    normalized_parser_run["coverage_status"] = "complete"
    forged_identity = {"object_id": f"event-log:{'f' * 24}"}
    evidence_index["candidate_populations"] = [
        {
            "population_id": "population:forged-event-log",
            "question_id": "Q-LOG-01",
            "technique_id": "security_log_clear_event",
            "subject_type": "event_log",
            "coverage_status": "complete",
            "subjects": [
                {
                    "subject_ref": "Security",
                    "identity": forged_identity,
                    "observation_ids": [],
                }
            ],
        }
    ]
    forged_bound = bind_population_manifest(evidence_index, manifest)

    assert forged_bound["candidate_populations"][0]["subjects"][0][
        "identity"
    ] != forged_identity


def test_complete_public_roster_scopes_partial_parser_coverage() -> None:
    manifest = _build_public_manifest(experiment="timestomp", seed=20260826)
    evidence_index = _timestomp_index(manifest)
    evidence_index["parser_runs"][0]["coverage_status"] = "partial"
    evidence_index["parser_runs"][1]["coverage_status"] = "partial"
    scenario = manifest["scenarios"]["timestomp_01"]
    references = {
        (index + 100, 1)
        for index, _member in enumerate(scenario["members"])
    }
    evidence_index["parser_runs"][1]["selection_scope"] = {
        "kind": "ntfs_file_references",
        "filesystem_scope_id": "volume:generated",
        "reference_count": len(references),
        "reference_sha256": ntfs_reference_set_sha256(references),
        "matched_record_count": 0,
        "retained_record_count": 0,
        "normalized_record_count": 0,
        "source_size_bytes": 1024,
        "source_bytes_covered": 1024,
        "status": "complete",
    }
    evidence_index["parser_runs"][1].update(
        {
            "parser": "fmb_bounded_parser",
            "tool_identity": {
                "name": "fmb.usn.truth_blind_reference_scanner",
            },
            "observation_count": 0,
            "raw_outputs": [{"size_bytes": 1024}],
            "normalized_output": {"record_count": 0},
        }
    )

    bound = bind_population_manifest(evidence_index, manifest)
    analysis_input = prepare_analysis_inputs(
        bound,
        question_id="Q-TIME-01",
    )[0]

    coverage = {item.artifact_family: item.status for item in analysis_input.coverage}
    assert coverage["ntfs.mft"] == "complete"
    assert coverage["ntfs.usn"] == "complete"
    assert analysis_input.readiness == "ready"


def test_partial_usn_is_not_completed_by_per_subject_observation_presence() -> None:
    manifest = _build_public_manifest(experiment="timestomp", seed=20260826)
    evidence_index = _timestomp_index(manifest)
    evidence_index["parser_runs"][1]["coverage_status"] = "partial"
    scenario = manifest["scenarios"]["timestomp_01"]
    evidence_index["parser_runs"][1]["observations"] = [
        {
            "observation_id": f"obs:usn:{index:03d}",
            "artifact_family": "ntfs.usn",
            "observation_type": "usn_journal_record",
            "subject_ref": member["subject_ref"],
            "fields": {
                "mft_volume_id": "volume:generated",
                "file_reference_entry": index + 100,
                "file_reference_sequence": 1,
            },
            "source_record_ref": f"$J:{index}",
        }
        for index, member in enumerate(scenario["members"])
    ]

    bound = bind_population_manifest(evidence_index, manifest)
    analysis_input = prepare_analysis_inputs(bound, question_id="Q-TIME-01")[0]

    coverage = {item.artifact_family: item.status for item in analysis_input.coverage}
    assert coverage["ntfs.usn"] == "partial"
    assert analysis_input.readiness == "insufficient_evidence"


def test_usn_selection_scope_must_match_the_population_filesystem_scope() -> None:
    manifest = _build_public_manifest(experiment="timestomp", seed=20260826)
    evidence_index = _timestomp_index(manifest)
    evidence_index["parser_runs"][0]["coverage_status"] = "partial"
    evidence_index["parser_runs"][1]["coverage_status"] = "partial"
    scenario = manifest["scenarios"]["timestomp_01"]
    references = {
        (index + 100, 1)
        for index, _member in enumerate(scenario["members"])
    }
    evidence_index["parser_runs"][1].update(
        {
            "parser": "fmb_bounded_parser",
            "tool_identity": {
                "name": "fmb.usn.truth_blind_reference_scanner",
            },
            "observation_count": 0,
            "raw_outputs": [{"size_bytes": 1024}],
            "normalized_output": {"record_count": 0},
            "selection_scope": {
                "kind": "ntfs_file_references",
                "filesystem_scope_id": "volume:other",
                "reference_count": len(references),
                "reference_sha256": ntfs_reference_set_sha256(references),
                "matched_record_count": 0,
                "retained_record_count": 0,
                "normalized_record_count": 0,
                "source_size_bytes": 1024,
                "source_bytes_covered": 1024,
                "status": "complete",
            },
        }
    )

    bound = bind_population_manifest(evidence_index, manifest)
    analysis_input = prepare_analysis_inputs(bound, question_id="Q-TIME-01")[0]

    coverage = {item.artifact_family: item.status for item in analysis_input.coverage}
    assert coverage["ntfs.mft"] == "complete"
    assert coverage["ntfs.usn"] == "partial"
    assert analysis_input.readiness == "insufficient_evidence"


def test_deleted_population_accepts_an_exact_complete_usn_selection_scope() -> None:
    references = {(10, 1), (11, 1)}
    delete_observation = {
        "observation_id": "obs:scoped-delete",
        "artifact_family": "ntfs.usn",
        "observation_type": "usn_file_delete",
        "subject_ref": r"C:\Users\vagrant\Desktop\deleted.txt",
        "fields": {
            "mft_volume_id": "mft-source:test",
            "file_reference_entry": 10,
            "file_reference_sequence": 1,
            "mft_active_presence_check_supported": True,
            "mft_active_presence_status": "active_mft_absent",
            "mft_active_presence_basis": "file_reference_entry_reused",
        },
        "source_record_ref": "$J:1",
    }
    present_observation = {
        "observation_id": "obs:active-mft-record",
        "artifact_family": "ntfs.mft",
        "observation_type": "mft_file_record",
        "subject_ref": r"C:\Users\vagrant\Desktop\present.txt",
        "fields": {
            "mft_volume_id": "mft-source:test",
            "mft_entry": 11,
            "sequence_number": 1,
            "in_use": True,
            "raw_mft_timestamp_validation": "verified",
        },
        "source_record_ref": "$MFT:11",
    }
    evidence_index = {
        "schema_version": "evidence_index.v1",
        "run_id": "scoped-deleted-population",
        "parser_runs": [
            {
                "parser": "fmb_bounded_parser",
                "parser_kind": "ntfs_usn",
                "status": "consumed",
                "coverage_status": "partial",
                "tool_identity": {
                    "name": "fmb.usn.truth_blind_reference_scanner",
                },
                "raw_outputs": [{"size_bytes": 1024}],
                "normalized_output": {"record_count": 1},
                "observation_count": 1,
                "observations": [delete_observation],
                "selection_scope": {
                    "kind": "ntfs_file_references",
                    "filesystem_scope_id": "mft-source:test",
                    "reference_count": 2,
                    "reference_sha256": ntfs_reference_set_sha256(references),
                    "matched_record_count": 1,
                    "retained_record_count": 1,
                    "normalized_record_count": 1,
                    "source_size_bytes": 1024,
                    "source_bytes_covered": 1024,
                    "status": "complete",
                },
            },
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [present_observation],
            },
        ],
        "candidate_populations": [
            {
                "population_id": "population:deleted",
                "question_id": "Q-DEL-01",
                "technique_id": "deleted_file_journal_residue",
                "subject_type": "file",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": delete_observation["subject_ref"],
                        "identity": {"object_id": "ntfs:mft-source:test:10:1"},
                        "observation_ids": [delete_observation["observation_id"]],
                    },
                    {
                        "subject_ref": r"C:\Users\vagrant\Desktop\present.txt",
                        "identity": {"object_id": "ntfs:mft-source:test:11:1"},
                        "observation_ids": [present_observation["observation_id"]],
                    },
                ],
            }
        ],
    }

    analysis_input = prepare_analysis_inputs(
        evidence_index,
        question_id="Q-DEL-01",
    )[0]

    coverage = {item.artifact_family: item.status for item in analysis_input.coverage}
    assert coverage["ntfs.usn"] == "complete"
    assert coverage["ntfs.mft"] == "complete"
    assert analysis_input.readiness == "ready"


def _scoped_ads_population_index() -> dict[str, object]:
    filesystem_scope_id = "mft-source:test"
    references = {(10, 1), (11, 1)}
    ads_observation = {
        "observation_id": "obs:scoped-ads",
        "artifact_family": "ntfs.ads",
        "observation_type": "named_data_stream",
        "subject_ref": r"C:\Users\vagrant\Desktop\owner.txt:secret",
        "fields": {
            "base_path": r"C:\Users\vagrant\Desktop\owner.txt",
            "stream_name": "secret",
            "stream_size": 5,
            "mft_volume_id": filesystem_scope_id,
            "mft_entry": 10,
            "sequence_number": 1,
            "in_use": True,
            "has_ads": True,
            "host_population_complete": True,
            "host_population_size": 2,
            "hosts_without_named_stream_count": 1,
            "host_named_stream_count": 1,
            "stream_name_occurrences": 1,
        },
        "source_record_ref": "mft.csv:2",
    }
    base_observation = {
        "observation_id": "obs:plain-base",
        "artifact_family": "ntfs.mft",
        "observation_type": "mft_file_record",
        "subject_ref": r"C:\Users\vagrant\Desktop\plain.txt",
        "fields": {
            "mft_volume_id": filesystem_scope_id,
            "mft_entry": 11,
            "sequence_number": 1,
            "in_use": True,
        },
        "source_record_ref": "mft.csv:3",
    }
    return {
        "schema_version": "evidence_index.v1",
        "run_id": "scoped-ads-population",
        "parser_runs": [
            {
                "parser_kind": "ntfs_mft",
                "status": "consumed",
                "coverage_status": "partial",
                "observations": [base_observation],
            },
            {
                "parser": "fmb_bounded_parser",
                "parser_kind": "ntfs_ads",
                "status": "consumed",
                "coverage_status": "partial",
                "tool_identity": {
                    "name": "fmb.ads.truth_blind_reference_scanner",
                },
                "raw_outputs": [{"size_bytes": 1024}],
                "normalized_output": {"record_count": 1},
                "observation_count": 1,
                "observations": [ads_observation],
                "selection_scope": {
                    "kind": "ntfs_file_references",
                    "filesystem_scope_id": filesystem_scope_id,
                    "reference_count": 2,
                    "reference_sha256": ntfs_reference_set_sha256(references),
                    "matched_record_count": 3,
                    "retained_record_count": 1,
                    "normalized_record_count": 1,
                    "source_size_bytes": 1024,
                    "source_bytes_covered": 1024,
                    "status": "complete",
                },
            },
        ],
        "candidate_populations": [
            {
                "population_id": "population:ads",
                "question_id": "Q-HIDE-01",
                "technique_id": "alternate_data_stream",
                "subject_type": "file",
                "coverage_status": "complete",
                "subjects": [
                    {
                        "subject_ref": r"C:\Users\vagrant\Desktop\owner.txt",
                        "identity": {
                            "object_id": "ntfs:mft-source:test:10:1",
                        },
                        "observation_ids": [ads_observation["observation_id"]],
                    },
                    {
                        "subject_ref": r"C:\Users\vagrant\Desktop\plain.txt",
                        "identity": {
                            "object_id": "ntfs:mft-source:test:11:1",
                        },
                        "observation_ids": [base_observation["observation_id"]],
                    },
                ],
            }
        ],
    }


def test_ads_population_accepts_an_exact_complete_reference_scan() -> None:
    analysis_input = prepare_analysis_inputs(
        _scoped_ads_population_index(),
        question_id="Q-HIDE-01",
    )[0]

    coverage = {item.artifact_family: item.status for item in analysis_input.coverage}
    assert coverage["ntfs.ads"] == "complete"
    assert coverage["ntfs.mft"] == "complete"
    assert analysis_input.readiness == "ready"


def test_ads_population_rejects_a_mismatched_reference_scan_hash() -> None:
    evidence_index = _scoped_ads_population_index()
    evidence_index["parser_runs"][1]["selection_scope"]["reference_sha256"] = "0" * 64

    analysis_input = prepare_analysis_inputs(
        evidence_index,
        question_id="Q-HIDE-01",
    )[0]

    coverage = {item.artifact_family: item.status for item in analysis_input.coverage}
    assert coverage["ntfs.ads"] == "partial"
    assert coverage["ntfs.mft"] == "partial"
    assert analysis_input.readiness == "insufficient_evidence"


def test_public_roster_scopes_the_shared_input_to_roster_observations() -> None:
    manifest = _build_public_manifest(experiment="timestomp", seed=20260826)
    evidence_index = _timestomp_index(manifest)
    evidence_index["parser_runs"][1]["observations"] = [
        {
            "observation_id": "obs:usn:unrelated",
            "artifact_family": "ntfs.usn",
            "observation_type": "usn_basic_info_change",
            "subject_ref": r"C:\Windows\unrelated.bin",
            "fields": {"update_timestamp": "2026-01-01T00:00:00Z"},
            "source_record_ref": "usn.csv:999",
        }
    ]

    bound = bind_population_manifest(evidence_index, manifest)
    analysis_input = prepare_analysis_inputs(
        bound,
        question_id="Q-TIME-01",
    )[0]
    roster_observation_ids = {
        observation_id
        for subject in analysis_input.candidate_roster.subjects
        for observation_id in subject.observation_ids
    }

    assert set(analysis_input.projected_observation_ids) == roster_observation_ids
    assert {item.observation_id for item in analysis_input.observations} == (
        roster_observation_ids
    )
    assert "obs:usn:unrelated" not in analysis_input.projected_observation_ids


def test_public_population_manifest_replaces_only_its_parser_population_scope() -> None:
    manifest = _build_public_manifest(experiment="timestomp", seed=20260826)
    evidence_index = _timestomp_index(manifest)
    mft_run, usn_run = evidence_index["parser_runs"]
    parser_population = timestamp_candidate_population(
        mft_run["observations"],
        source_id="real-mft-parser-shape",
        coverage_status="complete",
    )
    unrelated_observation = {
        "observation_id": "obs:usn:unrelated-delete",
        "artifact_family": "ntfs.usn",
        "observation_type": "usn_file_delete",
        "subject_ref": r"C:\Users\vagrant\Desktop\unrelated.txt",
        "fields": {"update_reasons": "FILE_DELETE|CLOSE"},
        "source_record_ref": "usn.csv:99",
    }
    usn_run["observations"] = [unrelated_observation]
    unrelated_population = {
        "population_id": "population:unrelated-delete",
        "question_id": "Q-DEL-01",
        "technique_id": "deleted_file_journal_residue",
        "subject_type": "file",
        "coverage_status": "complete",
        "subjects": [
            {
                "subject_ref": unrelated_observation["subject_ref"],
                "identity": {
                    "canonical_name": r"c:\users\vagrant\desktop\unrelated.txt"
                },
                "observation_ids": [unrelated_observation["observation_id"]],
            }
        ],
    }
    evidence_index["candidate_populations"] = [
        parser_population,
        unrelated_population,
    ]

    bound = bind_population_manifest(evidence_index, manifest)

    populations = {
        (item["question_id"], item["technique_id"]): item
        for item in bound["candidate_populations"]
    }
    timestomp = populations[("Q-TIME-01", "timestamp_manipulation")]
    assert timestomp["population_id"] != parser_population["population_id"]
    assert len(timestomp["subjects"]) == 55
    assert populations[("Q-DEL-01", "deleted_file_journal_residue")] == (
        unrelated_population
    )


def test_generated_evidence_uses_only_a_hash_bound_population_sidecar(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "timestomp.vmdk"
    evidence.write_bytes(b"bounded-image-fixture")
    manifest = _build_public_manifest(experiment="timestomp", seed=20260826)
    population_path = tmp_path / "population_manifest.json"
    population_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "ground_truth.json").write_text("not opened", encoding="utf-8")

    def file_hash(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "generation_manifest.v1",
                "scenario": "timestomp_01",
                "experiment": "timestomp",
                "cleanup": _DESTROYED_CLEANUP_RECEIPT,
                "ground_truth": "ground_truth.json",
                "ground_truth_sha256": "f" * 64,
                "artifacts": [
                    {
                        "file": evidence.name,
                        "sha256": file_hash(evidence),
                        "size_bytes": evidence.stat().st_size,
                    },
                    {
                        "file": population_path.name,
                        "sha256": file_hash(population_path),
                        "size_bytes": population_path.stat().st_size,
                    },
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    bound = bind_population_manifest(
        _timestomp_index(manifest),
        load_generated_population_bundle(evidence).population_manifest,
    )

    assert (
        bound["population_manifest"]["manifest_sha256"] == manifest["manifest_sha256"]
    )
    assert len(bound["candidate_populations"][0]["subjects"]) == 55


def test_generated_population_requires_a_successful_cleanup_receipt(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "timestomp.vmdk"
    evidence.write_bytes(b"bounded-image-fixture")
    manifest = _build_public_manifest(experiment="timestomp", seed=20260826)
    population_path = tmp_path / "population_manifest.json"
    population_path.write_text(json.dumps(manifest), encoding="utf-8")

    def artifact(path: Path) -> dict[str, object]:
        return {
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }

    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "generation_manifest.v1",
                "scenario": "timestomp_01",
                "experiment": "timestomp",
                "artifacts": [artifact(evidence), artifact(population_path)],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="cleanup receipt"):
        load_generated_population_bundle(evidence)


def test_generated_manifest_rejects_unknown_metadata(tmp_path: Path) -> None:
    evidence = tmp_path / "timestomp.vmdk"
    evidence.write_bytes(b"bounded-image-fixture")
    manifest = _build_public_manifest(experiment="timestomp", seed=20260826)
    population_path = tmp_path / "population_manifest.json"
    population_path.write_text(json.dumps(manifest), encoding="utf-8")

    def artifact(path: Path) -> dict[str, object]:
        return {
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }

    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "generation_manifest.v1",
                "scenario": "timestomp_01",
                "experiment": "timestomp",
                "cleanup": _DESTROYED_CLEANUP_RECEIPT,
                "unexpected_field": True,
                "artifacts": [artifact(evidence), artifact(population_path)],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported fields.*unexpected_field"):
        load_generated_population_bundle(evidence)


def test_arbitrary_evidence_without_population_sidecar_is_unchanged(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "operator.vhdx"
    evidence.write_bytes(b"operator-image")

    assert load_generated_population_bundle(evidence) is None


def test_generated_bundle_exposes_the_verified_i30_directory_roster(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "full_scale.vmdk"
    evidence.write_bytes(b"bounded-full-scale-image")
    manifest = _build_public_manifest(experiment="full_scale", seed=20260827)
    population_path = tmp_path / "population_manifest.json"
    population_path.write_text(json.dumps(manifest), encoding="utf-8")

    def artifact(path: Path) -> dict[str, object]:
        return {
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }

    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "generation_manifest.v1",
                "scenario": "full_scale",
                "experiment": "full_scale",
                "cleanup": _DESTROYED_CLEANUP_RECEIPT,
                "artifacts": [artifact(evidence), artifact(population_path)],
            }
        ),
        encoding="utf-8",
    )

    bundle = load_generated_population_bundle(evidence)

    assert bundle is not None
    scenario = manifest["scenarios"]["directory_cleaning_i30_01"]
    assert bundle.i30_directory_paths == tuple(
        member["subject_ref"]
        for member in scenario["members"]
    )
    assert len(bundle.i30_directory_paths) == 17


def test_generated_evidence_rejects_a_tampered_population_sidecar(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "timestomp.vmdk"
    evidence.write_bytes(b"bounded-image-fixture")
    manifest = _build_public_manifest(experiment="timestomp", seed=20260826)
    population_path = tmp_path / "population_manifest.json"
    population_path.write_text(json.dumps(manifest), encoding="utf-8")

    def file_hash(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    generation_manifest = {
        "schema_version": "generation_manifest.v1",
        "scenario": "timestomp_01",
        "experiment": "timestomp",
        "cleanup": _DESTROYED_CLEANUP_RECEIPT,
        "artifacts": [
            {
                "file": evidence.name,
                "sha256": file_hash(evidence),
                "size_bytes": evidence.stat().st_size,
            },
            {
                "file": population_path.name,
                "sha256": file_hash(population_path),
                "size_bytes": population_path.stat().st_size,
            },
        ],
    }
    (tmp_path / "manifest.json").write_text(
        json.dumps(generation_manifest),
        encoding="utf-8",
    )
    population_path.write_text(
        json.dumps({**manifest, "declared_count": 1}), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="size mismatch|SHA-256 mismatch"):
        load_generated_population_bundle(evidence)


def test_full_scale_manifest_binds_all_generated_candidates_to_ready_inputs() -> None:
    manifest = _build_public_manifest(experiment="full_scale", seed=20260826)

    bound = bind_population_manifest(_full_scale_index(manifest), manifest)
    inputs = prepare_analysis_inputs(bound)

    assert len(inputs) == 14
    assert sum(len(item.candidate_roster.subjects) for item in inputs) == 473
    assert all(item.readiness == "ready" for item in inputs)
    ads = next(item for item in inputs if item.technique_id == "alternate_data_stream")
    assert len(ads.candidate_roster.subjects) == 130
    assert len({subject.subject_id for subject in ads.candidate_roster.subjects}) == 130
    assert all(
        set(subject.identity) == {"object_id"}
        and subject.identity["object_id"].startswith("ntfs:volume:generated:")
        for subject in ads.candidate_roster.subjects
    )
    observations = {item.observation_id: item for item in ads.observations}
    named_stream_hosts = [
        subject
        for subject in ads.candidate_roster.subjects
        if any(
            observations[observation_id].observation_type == "named_data_stream"
            for observation_id in subject.observation_ids
        )
    ]
    assert len(named_stream_hosts) == 1
    assert {
        observations[observation_id].fields.get("stream_name")
        for observation_id in named_stream_hosts[0].observation_ids
        if observations[observation_id].observation_type == "named_data_stream"
    } == {"concealed"}


def test_registry_population_uses_its_canonical_path_as_the_analysis_label() -> None:
    manifest = _build_public_manifest(experiment="full_scale", seed=20260826)

    bound = bind_population_manifest(_full_scale_index(manifest), manifest)
    registry_input = next(
        item
        for item in prepare_analysis_inputs(bound)
        if item.technique_id == "typed_path_residue"
    )

    assert len(registry_input.candidate_roster.subjects) == 16
    assert all(
        subject.display_name == subject.identity["canonical_name"]
        and subject.display_name.startswith("c:\\")
        for subject in registry_input.candidate_roster.subjects
    )


def test_full_scale_manifest_rejects_a_named_stream_without_a_name() -> None:
    manifest = _build_public_manifest(experiment="full_scale", seed=20260826)
    evidence_index = _full_scale_index(manifest)
    ads_run = next(
        item
        for item in evidence_index["parser_runs"]
        if item["parser_kind"] == "ntfs_ads"
    )
    ads_run["observations"][0]["fields"]["stream_name"] = ""

    with pytest.raises(ValueError, match="non-empty stream name"):
        bind_population_manifest(evidence_index, manifest)


@pytest.mark.parametrize('filename', [
    'populations.v1.json',
])
def test_current_and_pre_content_contract_pins_match_retained_contract_bytes(filename):
    from fmb.analysis.population_binding import (
        BOUNDED_POPULATION_CONTRACT_SHA256,
        HISTORICAL_POPULATION_CONTRACT_SHA256,
        verify_population_manifest,
    )
    path = Path(__file__).resolve().parents[1] / 'fixtures/generation' / filename
    contract = json.loads(path.read_text())
    digest = canonical_sha256(contract)
    if filename == 'populations.v1.json':
        assert digest == BOUNDED_POPULATION_CONTRACT_SHA256
        assert contract['contract_revision'] == 'content_formats.v2'
        assert contract['scenarios']['ads_injection_01']['manipulation_count'] == 2
    else:
        assert digest in HISTORICAL_POPULATION_CONTRACT_SHA256
        assert contract['scenarios']['ads_injection_01']['manipulation_count'] == 1
    spec = importlib.util.spec_from_file_location('public_contract_fixture', Path(__file__).resolve().parents[2] / 'src/fmb/generation/population.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = module.build_public_manifest(experiment='full_scale', seed=2, contract=contract)
    assert manifest['contract_sha256'] == digest
    assert verify_population_manifest(manifest) == manifest
    assert manifest['declared_count'] == 473
    manifest['contract_sha256'] = '0' * 64
    body = {key: value for key, value in manifest.items() if key != 'manifest_sha256'}
    manifest['manifest_sha256'] = canonical_sha256(body)
    with pytest.raises(ValueError, match='contract hash is not supported'):
        verify_population_manifest(manifest)


@pytest.mark.parametrize(('filename', 'expected_count'), [
    ('populations.pilot-i1-20260918.json', 56),
    ('populations.pilot-i2-20260918.json', 56),
    ('populations.pilot-i3-20260918.json', 56),
])
def test_paper_contract_pins_match_retained_contract_bytes(
    filename, expected_count
):
    from fmb.analysis.population_binding import (
        EXPERIMENTAL_POPULATION_CONTRACT_SHA256,
        verify_population_manifest,
    )

    root = Path(__file__).resolve().parents[2] / 'src/fmb/generation'
    contract = json.loads((root / filename).read_text())
    digest = canonical_sha256(contract)
    assert digest in EXPERIMENTAL_POPULATION_CONTRACT_SHA256

    spec = importlib.util.spec_from_file_location(
        'experimental_public_contract_fixture', root / 'population.py'
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = module.build_public_manifest(
        experiment='full_scale', seed=2026091311, contract=contract
    )
    assert manifest['contract_sha256'] == digest
    assert manifest['declared_count'] == expected_count
    assert verify_population_manifest(manifest) == manifest


def test_generated_population_sidecars_are_read_beside_a_symlinked_image(tmp_path: Path) -> None:
    generation = tmp_path / "generation"
    generation.mkdir()
    other_disk = tmp_path / "other-disk"
    other_disk.mkdir()
    image = other_disk / "full_scale.vmdk"
    image.write_bytes(b"bounded-full-scale-image")
    evidence = generation / "full_scale.vmdk"
    evidence.symlink_to(image)
    population_path = generation / "population_manifest.json"
    population_path.write_text(json.dumps(_build_public_manifest(experiment="full_scale", seed=20260827)), encoding="utf-8")

    def artifact(path: Path, name: str) -> dict[str, object]:
        return {"file": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size_bytes": path.stat().st_size}

    (generation / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "generation_manifest.v1",
                "scenario": "full_scale",
                "experiment": "full_scale",
                "cleanup": _DESTROYED_CLEANUP_RECEIPT,
                "artifacts": [artifact(image, "full_scale.vmdk"), artifact(population_path, "population_manifest.json")],
            }
        ),
        encoding="utf-8",
    )

    bundle = load_generated_population_bundle(evidence)

    assert bundle is not None
    assert bundle.evidence_sha256 == hashlib.sha256(image.read_bytes()).hexdigest()
