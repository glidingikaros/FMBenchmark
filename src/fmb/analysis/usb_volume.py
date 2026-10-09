from __future__ import annotations

import ntpath
from typing import Any

from fmb.core.limits import usb_medium_size


def assess_usb_volume_activity(fields: dict[str, Any], *, require_fixture_device: bool = True) -> str:
    required = ("native_identity_consistent", "active_mft_complete", "journal_scan_complete")
    if any(fields.get(key) is not True for key in required):
        return "indeterminate"
    integers = ("journal_id", "journal_lowest_valid_usn",
                "journal_retained_end_usn", "same_reference_rename_record_count", "active_original_path_count",
                "original_name_usn_record_count", "alternative_name_usn_record_count",
                "same_reference_delete_record_count", "link_file_reference_number",
                "disk_size_bytes", "unresolved_active_mft_ancestry_count",
                "referenced_entry_mft_entry", "referenced_entry_mft_sequence")
    if any(type(fields.get(key)) is not int or fields[key] < 0 for key in integers):
        return "indeterminate"
    if (fields.get("disk_bus_type") != "USB" or fields["disk_size_bytes"] <= 0
            or (require_fixture_device and (
                fields.get("physical_host_device") is not False
                or fields.get("attachment_kind") != "hypervisor_virtual_usb_mass_storage"
                or not usb_medium_size(fields["disk_size_bytes"])))
            or not fields["link_file_reference_number"] >> 48
            or not fields["journal_lowest_valid_usn"] < fields["journal_retained_end_usn"]):
        return "indeterminate"
    lists = ("same_reference_usn_records", "malformed_mft_entries", "journal_parse_error_offsets", "same_reference_mft_paths",
             "unresolved_active_mft_entries", "referenced_entry_file_names")
    if any(not isinstance(fields.get(key), list) for key in lists):
        return "indeterminate"
    if (fields["malformed_mft_entries"] or fields["journal_parse_error_offsets"]
            or fields["unresolved_active_mft_entries"] or fields["unresolved_active_mft_ancestry_count"]):
        return "indeterminate"
    if type(fields.get("referenced_entry_mft_active")) is not bool:
        return "indeterminate"
    target = fields.get("link_target_path")
    if not isinstance(target, str) or not target or any(not isinstance(path, str) for path in fields["same_reference_mft_paths"]):
        return "indeterminate"
    original_name = ntpath.basename(target).casefold()
    counts = {key: 0 for key in ("original_name_usn_record_count", "alternative_name_usn_record_count",
                                "same_reference_rename_record_count", "same_reference_delete_record_count")}
    for row in fields["same_reference_usn_records"]:
        if (not isinstance(row, dict) or any(type(row.get(key)) is not int or row[key] < 0
                for key in ("file_reference_number", "parent_file_reference_number", "usn", "reason"))
                or row["file_reference_number"] != fields["link_file_reference_number"]
                or not fields["journal_lowest_valid_usn"] <= row["usn"] < fields["journal_retained_end_usn"]
                or not isinstance(row.get("file_name"), str) or not row["file_name"]):
            return "indeterminate"
        key = "original_name_usn_record_count" if row["file_name"].casefold() == original_name else "alternative_name_usn_record_count"
        counts[key] += 1
        counts["same_reference_rename_record_count"] += bool(row["reason"] & 0x3000)
        counts["same_reference_delete_record_count"] += bool(row["reason"] & 0x200)
    if any(fields[key] != value for key, value in counts.items()):
        return "indeterminate"
    native_names = fields["referenced_entry_file_names"]
    if any(not isinstance(row, dict) or not isinstance(row.get("name"), str) or not row["name"]
            or type(row.get("parent_file_reference_number")) is not int or row["parent_file_reference_number"] < 0
            or type(row.get("namespace")) is not int or row["namespace"] not in range(4) for row in native_names):
        return "indeterminate"
    reference = fields["link_file_reference_number"]
    if fields["referenced_entry_mft_entry"] != reference & ((1 << 48) - 1):
        return "indeterminate"
    sequence = reference >> 48
    relation = "unresolved"
    if fields["referenced_entry_mft_sequence"] == sequence:
        relation = "exact"
        if fields.get("same_reference_mft_active") is not fields["referenced_entry_mft_active"]:
            return "indeterminate"
    elif (sequence < 65535 and fields["referenced_entry_mft_sequence"] == sequence + 1
          and fields["referenced_entry_mft_active"] is False
          and any(row["reason"] & 0x200 and any(
              fn["name"].casefold() == row["file_name"].casefold()
              and fn["parent_file_reference_number"] == row["parent_file_reference_number"]
              for fn in native_names) for row in fields["same_reference_usn_records"])):
        relation = "freed_immediate_successor"
        if fields.get("same_reference_mft_active") is not None or fields["same_reference_mft_paths"]:
            return "indeterminate"
    if relation == "unresolved" or fields.get("native_mft_sequence_relation") != relation:
        return "indeterminate"
    if fields["same_reference_rename_record_count"]:
        return "indeterminate"
    if fields["active_original_path_count"] or fields["referenced_entry_mft_active"] or fields["original_name_usn_record_count"]:
        return "not_supported"
    if fields["alternative_name_usn_record_count"] > 0 and fields["same_reference_delete_record_count"] > 0:
        return "supported"
    return "indeterminate"
