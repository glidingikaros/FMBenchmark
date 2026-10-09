from __future__ import annotations

import hashlib
import json

import pytest


def _operation_refs_sha256(refs: list[str]) -> str:
    payload = b"generation_operation_refs.v1\n" + json.dumps(
        refs,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _verified_receipts(_population, guest_plan: dict, *, case: str) -> list[dict]:
    receipts = []
    for scenario_id, inputs in guest_plan["scenario_inputs"].items():
        refs = inputs["operation_refs"]
        receipt = {
            "scenario_id": scenario_id,
            "case": case,
            "operation_count": len(refs),
            "operation_refs_sha256": _operation_refs_sha256(refs),
            "postcondition_verified": True,
        }
        population_count = len(inputs.get("population_paths", []))
        if scenario_id == "timestomp_01":
            receipt["instances"] = [
                {
                    "original_creation_utc": "2026-01-01T00:00:00.0000000Z",
                    **({"original_modified_utc": "2018-06-10T12:00:00.0000000Z"}
                       if "minimum_backdating_seconds" in inputs else {}),
                    "assigned_timestamp": (
                        inputs["timestamps"][index].replace("Z", ".0000000Z")
                        if inputs["timestamps"][index].endswith("Z")
                        else f"{inputs['timestamps'][index]}+00:00"
                    ),
                }
                for index in range(len(refs))
            ]
        elif scenario_id == "ads_injection_01":
            receipt["zone_stream_count"] = population_count
            receipt["metadata_stream_count"] = 1
            receipt["content_contract"] = "named_stream_pe_zip.v2"
            receipt["streams"] = [
                {"format": kind, "stream_name": name, "stream_length": 4096 if kind == "pe" else 160,
                 "stream_sha256": "a" * 64}
                for kind, name in _population.ads_streams(inputs, len(refs))
            ] if case == "positive" else []
        elif scenario_id == "shellbag_path_residue_01":
            receipt["population_count"] = population_count
            receipt["absent_count"] = len(refs)
            receipt["native_receipts"] = [{
                **{key: True for key in (
                    "interactive_vagrant_explorer_verified", "stable_pre_snapshots_verified",
                    "native_bagmru_numeric_binary_verified", "native_mrulistex_structure_verified",
                    "custom_string_hint_absent", "scheduled_task_completed",
                    "scheduled_task_unregistered", "exact_target_window_matched",
                    "exact_target_window_closed")},
                "changed_key_count": 1, "changed_numeric_value_count": 1,
                "changed_mrulistex_count": 1,
                "visit_elapsed_ms": 4800, "explore_elapsed_ms": 900, "snapshot_count": 13,
            } for _ in range(population_count)]
            receipt["visit_budgets"] = dict(inputs["visit_budgets"])
        elif scenario_id == "prefetch_wipe_01":
            receipt["population_count"] = population_count
            receipt["prefetch_count"] = population_count
        elif scenario_id == "security_log_clear_event_01":
            receipt["event_id"] = 1102 if case == "positive" else None
            receipt["record_id"] = 1 if case == "positive" else None
        elif scenario_id in {"usn_journal_01", "shimcache_path_residue_01"}:
            receipt["population_count"] = population_count
        elif scenario_id == "typed_path_residue_01":
            receipt["population_count"] = population_count
            receipt["registry_value_count"] = population_count
            receipt["typed_paths_committed"] = True
        elif scenario_id == "ntfs_allocation_01":
            receipt["population_count"] = population_count
            receipt["prepared_modes"] = [item["storage_mode"] for item in inputs["storage_cases"]]
            receipt["preallocation_close_controls"] = [{
                "path": item["path"], "requested_allocation_bytes": 65536,
                "open_allocation_bytes": 65536, "open_eof_bytes": item["logical_length"],
                "closed_allocation_bytes": ((item["logical_length"] + 4095) // 4096) * 4096,
                "closed_eof_bytes": item["logical_length"],
                "content_sha256": hashlib.sha256(bytes((i * 37 + 19) % 251 for i in range(item["logical_length"]))).hexdigest(),
            } for item in inputs["storage_cases"] if item["storage_mode"] == "preallocation_request_then_close"]
        elif scenario_id == "event_record_sequence_gap_01":
            receipt["retained_tail_count"] = 3
        elif scenario_id == "bitmap_trailing_data_01":
            receipt["population_count"] = population_count
            receipt["instances"] = [{"mode": op["mode"], "declared_length": 58,
                "materialized_length": 58 + op["byte_count"] if op["mode"] == "append" else op["length"]}
                for op in inputs["bitmap_operations"][:len(refs)]]
        elif scenario_id == "directory_cleaning_i30_01":
            leaf_count = inputs["delete_count_per_directory"] * len(refs)
            retained_count = sum(item["child_count"] for item in inputs["directory_cases"]) - leaf_count
            receipt["population_count"] = population_count
            receipt["removed_leaf_count"] = leaf_count
            receipt["retained_leaf_count"] = retained_count
            receipt["remaining_leaf_count"] = retained_count
        elif scenario_id == "usbstor_setupapi_discrepancy_01":
            receipt["registry_identity_present"] = True
            receipt["setupapi_identity_present"] = True
            receipt["native_binding"] = {
                "schema_version": "native_media_binding.v1",
                "device_instance_id": "USBSTOR\\Disk&Ven_VMware&Prod_Virtual_Storage&Rev_1.00\\" + "A" * 32 + "&0",
                "parent_device_instance_ids": [], "setupapi_device_instance_id": "SWD\\WPDBUSENUM\\native",
                "disk_bus_type": "USB", "attachment_kind": "hypervisor_virtual_usb_mass_storage",
                "physical_host_device": False, "disk_size_bytes": 67108864, "disk_unique_id": "native-test-id",
                "volume_guid_path": "\\\\?\\Volume{test}\\", "volume_serial_number": "1234ABCD",
                "partition_offset_bytes": 0, "link_path": "C:\\Users\\vagrant\\Recent\\" + inputs["shortcut_name"],
                "target_path": "D:\\Records\\" + inputs["file_name"], "target_file_reference_number": 281474976710698,
                "observation_start_utc": "2026-01-01T00:00:00Z", "observation_end_utc": "2026-01-01T00:01:00Z",
                "journal_start_usn": 0, "journal_id": 12345, "companion_file": "native_media.vmdk",
            }
        elif scenario_id == "usb_volume_activity_gap_01":
            receipt["link_verified"] = True
            receipt["native_file_absent"] = case == "positive"
        else:
            raise AssertionError(f"unsupported generation scenario: {scenario_id}")
        receipts.append(receipt)
    return receipts


@pytest.fixture
def verified_receipts():
    return _verified_receipts


PWSH_TEST_MODULES = frozenset({
    'test_generation_noise_role.py', 'test_paths_and_pipeline_shape.py',
    'test_allocation_lifecycle.py', 'test_native_shellbag_snapshot_retry.py',
    'test_generation_noise_runtime.py', 'test_native_shellbag_snapshot_diagnostics.py',
    'test_native_shellbag_watchdog.py', 'test_failure_class_registry.py',
    'test_generation_scenario_truth_blindness.py', 'test_native_allocation_diagnostics.py',
})


def pytest_collection_modifyitems(items):
    for item in items:
        if item.path.name in PWSH_TEST_MODULES:
            item.add_marker(pytest.mark.pwsh)
