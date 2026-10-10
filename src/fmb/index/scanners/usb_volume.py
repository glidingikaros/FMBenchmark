from __future__ import annotations

import ntpath
import re
import struct
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fmb.core.limits import MAX_USB_MEDIUM_BYTES
from fmb.index.scanners.mft import mft_record_is_in_use, parse_mft_record
from fmb.index.scanners.ntfs import parse_boot_sector
from fmb.index.scanners.usn import parse_usn_record_v2
from fmb.index.support.windows_artifacts import kape_relative_path, stream_csv_rows

RENAME_REASON_MASK = 0x00001000 | 0x00002000
LECMD_DRIVE_TYPES = {
    "Unknown": 0, "No root directory": 1, "Removable storage media (Floppy, USB)": 2,
    "Fixed storage media (Hard drive)": 3, "Remote storage": 4,
    "Optical disc (CD-ROM, DVD, BD)": 5, "RAM drive": 6,
}


def lecmd_link_row(link: Path) -> tuple[Path, dict[str, str]]:
    root = next((path for path in link.parents if path.name.casefold() == "kape-output"), None)
    csvs = sorted(root.glob("modules/**/*_LECmd_Output.csv")) if root else []
    if len(csvs) != 1:
        raise ValueError("native USB shortcut needs its bundle's single LECmd output")
    name = kape_relative_path(str(link))
    rows = [row for row in stream_csv_rows(csvs[0])
            if kape_relative_path(row.get("SourceFile", "")) == name]
    if len(rows) != 1:
        raise ValueError("LECmd did not decode the native USB shortcut exactly once")
    return csvs[0], rows[0]


def shell_link_from_lecmd(row: Mapping[str, str]) -> dict[str, Any]:
    drive_type = LECMD_DRIVE_TYPES.get(row.get("DriveType", ""))
    serial = row.get("VolumeSerialNumber", "")
    if drive_type is None or not re.fullmatch(r"[0-9A-Fa-f]{8}", serial):
        raise ValueError("Shell Link has no complete native LinkInfo")
    target = row.get("LocalPath", "") + row.get("CommonPath", "")
    if len(target) < 4 or target[1:3] != ":\\" or target.startswith("\\"):
        raise ValueError("Shell Link target is not an absolute local-volume path")
    try:
        entry, sequence = (int(row.get(key) or "0", 16)
                           for key in ("TargetMFTEntryNumber", "TargetMFTSequenceNumber"))
    except ValueError as error:
        raise ValueError("LECmd target file reference is not numeric") from error
    if not 0 <= entry < 1 << 48 or not 0 <= sequence < 1 << 16:
        raise ValueError("LECmd target file reference is out of range")
    item_name = ntpath.basename(row.get("TargetIDAbsolutePath", "")) or None
    reference = None
    if sequence and item_name and item_name.casefold() == ntpath.basename(target).casefold():
        reference = entry | sequence << 48
    return {"target_path": target, "volume_serial_number": serial.lower(),
            "drive_type": drive_type, "target_file_reference_number": reference,
            "file_entry_name": item_name}


def parse_retained_journal(data: bytes, maximum: bytes) -> dict[str, Any]:
    if len(data) > MAX_USB_MEDIUM_BYTES or len(maximum) < 32:
        raise ValueError("bounded native journal or $Max length is unsupported")
    max_size, allocation_delta, journal_id, lowest_valid = struct.unpack_from("<QQQQ", maximum)
    records, errors = [], []
    cursor = 0
    while cursor < len(data):
        if not any(data[cursor : min(cursor + 8, len(data))]):
            cursor += 8
            continue
        record = parse_usn_record_v2(data, cursor, absolute_offset=cursor)
        if record is None or record["usn"] != cursor:
            errors.append(cursor)
            cursor += 8
            continue
        records.append(record)
        cursor += record["record_length"]
    retained = [row for row in records if row["usn"] >= lowest_valid]
    return {"records": retained, "journal_id": journal_id, "lowest_valid_usn": lowest_valid,
            "maximum_size_bytes": max_size, "allocation_delta_bytes": allocation_delta,
            "logical_stream_size_bytes": len(data), "parse_error_offsets": errors,
            "scan_complete": not errors, "record_count": len(retained),
            "retained_end_usn": max((row["usn"] + row["record_length"] for row in retained), default=lowest_valid)}


def parse_usb_volume_facts(*, boot: bytes, mft: bytes, journal: bytes, journal_max: bytes,
                           link: Mapping[str, str], binding: dict[str, Any]) -> dict[str, Any]:
    geometry = parse_boot_sector(boot)
    lnk = shell_link_from_lecmd(link)
    history = parse_retained_journal(journal, journal_max)
    size = geometry["mft_record_size"]
    if len(mft) % size or len(mft) > MAX_USB_MEDIUM_BYTES:
        raise ValueError("companion MFT is not complete/aligned within its bound")
    records, malformed = {}, []
    for offset in range(0, len(mft), size):
        raw = mft[offset : offset + size]
        if not any(raw):
            continue
        parsed = parse_mft_record(raw, record_offset=offset, record_size=size)
        if (parsed is None or parsed["attribute_parse_error_count"] or parsed["attribute_list_present"]
                or parsed["mft_entry"] != offset // size):
            malformed.append(offset // size)
        else:
            records[parsed["mft_entry"]] = parsed

    unresolved, reserved_empty = set(), set()

    def paths(record, seen=frozenset()):
        entry = record["mft_entry"]
        if entry == 5:
            return [""]
        if entry in seen or len(seen) >= 64:
            unresolved.update(seen | {entry})
            return []
        if not record["file_name_attributes"]:
            streams = record["data_attributes"]
            if (12 <= entry <= 15 and record["file_record_flags"] == 1
                    and record["sequence_number"] == entry and not record["index_attributes"]
                    and len(streams) == 1 and streams[0]["stream_name"] == ""
                    and streams[0]["resident_status"] == "resident"
                    and streams[0]["logical_size"] == 0 and streams[0]["attribute_flags"] == 0):
                reserved_empty.add(entry)
                return []
            unresolved.add(entry)
        result = []
        for name in record["file_name_attributes"]:
            parent = records.get(name["parent_inode"])
            if parent is None or parent["sequence_number"] != name["parent_sequence"] or not mft_record_is_in_use(parent):
                unresolved.add(entry)
                continue
            result += [prefix + "\\" + name["name"] for prefix in paths(parent, seen | {entry})]
        return result

    target_relative = lnk["target_path"][2:].casefold()
    active = [record for record in records.values() if mft_record_is_in_use(record)]
    active_named = [record for record in active if target_relative in {path.casefold() for path in paths(record)}]
    unresolved_active = sorted(record["mft_entry"] for record in active if record["mft_entry"] in unresolved)
    reference = lnk["target_file_reference_number"]
    same = records.get(reference & ((1 << 48) - 1)) if reference else None
    exact = same is not None and same["sequence_number"] == reference >> 48
    same_history = [row for row in history["records"] if row["file_reference_number"] == reference] if reference else []
    name = ntpath.basename(lnk["target_path"]).casefold()
    original = [row for row in same_history if row["file_name"].casefold() == name]
    alternative = [row for row in same_history if row["file_name"].casefold() != name]
    native_names = [{"name": row["name"], "parent_file_reference_number": row["parent_inode"] | row["parent_sequence"] << 48,
                     "namespace": row["namespace"]} for row in same["file_name_attributes"]] if same else []
    free_successor = (same is not None and not mft_record_is_in_use(same)
                      and reference >> 48 < 65535 and same["sequence_number"] == (reference >> 48) + 1
                      and any(row["reason"] & 0x200 and any(
                          fn["name"].casefold() == row["file_name"].casefold()
                          and fn["parent_file_reference_number"] == row["parent_file_reference_number"]
                          for fn in native_names) for row in same_history))
    expected_reference = binding.get("target_file_reference_number")
    serial = geometry["volume_serial_number"][-8:]
    parent_relative = ntpath.dirname(target_relative)
    directory_rows = []
    for record in records.values():
        for path in paths(record):
            if ntpath.dirname(path).casefold() == parent_relative:
                directory_rows.append({"entry": record["mft_entry"], "sequence": record["sequence_number"],
                                       "in_use": mft_record_is_in_use(record), "path": path})
                break
    directory_rows.sort(key=lambda row: (row["entry"], row["sequence"], row["path"]))
    return {
        "device_instance_id": binding["device_instance_id"],
        "serial_number": binding["device_instance_id"].split("\\")[-1],
        "disk_size_bytes": binding["disk_size_bytes"],
        "native_binding_file": "native_media_binding.json",
        "attachment_kind": binding["attachment_kind"],
        "physical_host_device": binding["physical_host_device"], "disk_bus_type": binding["disk_bus_type"],
        "volume_guid_path": binding["volume_guid_path"], "native_boot_volume_serial": geometry["volume_serial_number"],
        "link_volume_serial": lnk["volume_serial_number"], "binding_volume_serial": binding["volume_serial_number"].lower(),
        "link_target_path": lnk["target_path"], "binding_target_path": binding["target_path"],
        "link_file_reference_number": reference, "binding_file_reference_number": expected_reference,
        "native_identity_consistent": serial == lnk["volume_serial_number"]
            and reference is not None and (exact or bool(same_history))
            and reference & ((1 << 48) - 1) >= 24,
        "native_binding_consistent": serial == binding["volume_serial_number"].lower()
            and lnk["target_path"].casefold() == binding["target_path"].casefold()
            and reference == expected_reference,
        "referenced_entry_mft_entry": same["mft_entry"] if same else None,
        "referenced_entry_mft_sequence": same["sequence_number"] if same else None,
        "referenced_entry_mft_active": mft_record_is_in_use(same) if same else None,
        "referenced_entry_file_names": native_names,
        "native_mft_sequence_relation": "exact" if exact else "freed_immediate_successor" if free_successor else "unresolved",
        "active_mft_complete": not malformed and not unresolved_active, "malformed_mft_entries": malformed,
        "unresolved_active_mft_entries": unresolved_active,
        "unresolved_active_mft_ancestry_count": len(unresolved_active),
        "reserved_empty_mft_entries": sorted(reserved_empty),
        "active_original_path_count": len(active_named),
        "companion_directory_rows": directory_rows,
        "companion_directory_scope": {"directory": ntpath.dirname(lnk["target_path"]), "volume_serial": serial,
                                      "scan_complete": not malformed and not unresolved_active,
                                      "row_count": len(directory_rows)},
        "original_path_lookup": {
            "target_path": lnk["target_path"],
            "match_count": len(active_named),
            "scan_complete": not malformed and not unresolved_active,
            "matching_objects": [
                {"mft_entry": record["mft_entry"],
                 "sequence_number": record["sequence_number"],
                 "paths": paths(record)}
                for record in active_named
            ],
        },
        "same_reference_mft_active": mft_record_is_in_use(same) if exact else None,
        "same_reference_mft_paths": paths(same) if exact else [],
        "journal_scan_complete": history["scan_complete"], "journal_parse_error_offsets": history["parse_error_offsets"],
        "journal_id": history["journal_id"], "binding_journal_id": binding["journal_id"],
        "journal_lowest_valid_usn": history["lowest_valid_usn"], "journal_retained_end_usn": history["retained_end_usn"],
        "binding_journal_start_usn": binding["journal_start_usn"],
        "original_name_usn_record_count": len(original), "alternative_name_usn_record_count": len(alternative),
        "same_reference_usn_records": same_history,
        "same_reference_rename_record_count": sum(bool(row["reason"] & RENAME_REASON_MASK) for row in same_history),
        "same_reference_delete_record_count": sum(bool(row["reason"] & 0x200) for row in same_history),
    }
