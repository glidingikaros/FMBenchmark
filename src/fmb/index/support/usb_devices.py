from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from collections.abc import Iterable, Mapping
from typing import Any


_INSTANCE_KEY = re.compile(
    r"^(?:ROOT\\)?(?P<control_set>ControlSet\d{3})\\Enum\\USBSTOR\\"
    r"(?P<hardware>[^\\]+)\\(?P<serial>[^\\]+)$",
    re.IGNORECASE,
)
_HARDWARE_KEY = re.compile(
    r"^(?:ROOT\\)?(?P<control_set>ControlSet\d{3})\\Enum\\USBSTOR\\"
    r"(?P<hardware>[^\\*?]+)$",
    re.IGNORECASE,
)
_PROPERTY_KEY = re.compile(
    r"^(?:ROOT\\)?(?P<control_set>ControlSet\d{3})\\Enum\\USBSTOR\\"
    r"(?P<hardware>[^\\]+)\\(?P<serial>[^\\]+)\\Properties\\"
    r"\{83da6326-97a6-4088-9453-a1923f573b29\}\\(?P<property>006[5-7])$",
    re.IGNORECASE,
)
_DEVICE_HEADER = re.compile(
    r"^\s*>>>\s+\[.*?-\s+(?P<device>(?:USBSTOR|USB)\\[^\]]+)\]\s*$",
    re.IGNORECASE,
)
_WPD_USBSTOR_HEADER = re.compile(
    r"^\s*>>>\s+\[.*?-\s+SWD\\WPDBUSENUM\\_\?\?_USBSTOR#"
    r"(?P<hardware>[^#\\{}\[\]\s]+)#(?P<serial>[^#\\{}\[\]\s]+)#"
    r"\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-"
    r"[0-9A-F]{12}\}\]\s*$",
    re.IGNORECASE,
)
_SECTION_START = re.compile(
    r"^\s*>>>\s+Section start\s+(?P<timestamp>.+?)\s*$", re.IGNORECASE
)
_SECTION_START_LEGACY = re.compile(
    r"^\s*>>>\s+(?P<timestamp>.+?):\s+Section start\s*$", re.IGNORECASE
)
_SECTION_END = re.compile(
    r"^\s*<<<\s+Section end\s+(?P<timestamp>.+?)\s*$", re.IGNORECASE
)
_SECTION_END_LEGACY = re.compile(
    r"^\s*<<<\s+\[(?P<timestamp>.+?):\s+Section end\]\s*$", re.IGNORECASE
)
_SECTION_EXIT = re.compile(
    r"^\s*<<<\s+\[Exit Status(?::\s*[^\]]+|\([^\)]+\))\]\s*$", re.IGNORECASE
)
_SECTION_HEADER = re.compile(r"^\s*>>>\s+\[", re.IGNORECASE)
_FILETIME_BYTES = re.compile(r"[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){7}")
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_TIME_FIELD = {"0065": "first_install", "0066": "last_arrival", "0067": "last_removal"}
_TIMESTAMP_FIELDS = (
    "registry_key_timestamp",
    "installed",
    "first_install",
    "last_arrival",
    "last_removal",
)
_PLUGIN_TIME_FIELD = {
    "Timestamp": "registry_key_timestamp",
    "Installed": "installed",
    "FirstInstalled": "first_install",
    "LastConnected": "last_arrival",
    "LastRemoved": "last_removal",
}


def _first(row: Mapping[str, str], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def explicit_timestamp(value: str) -> str:

    candidate = value.strip()
    if not candidate:
        return ""
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        return ""
    return parsed.astimezone(timezone.utc).isoformat()


def plugin_timestamp(value: str) -> tuple[str, str]:
    candidate = value.strip()
    if not candidate:
        return "", ""
    explicit = explicit_timestamp(candidate)
    if explicit:
        return explicit, "explicit"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return "", ""
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).isoformat(), "explicit"
    return parsed.isoformat(), "naive"


def registry_filetime(*, value_type: str, value_data: str) -> str:
    if value_type.strip().casefold() != "regbinary":
        return ""
    if _FILETIME_BYTES.fullmatch(value_data.strip()) is None:
        return ""
    ticks = int.from_bytes(
        bytes.fromhex(value_data.replace("-", "")), byteorder="little"
    )
    if ticks <= 0:
        return ""
    try:
        return (_FILETIME_EPOCH + timedelta(microseconds=ticks // 10)).isoformat()
    except OverflowError:
        return ""


def _identity(hardware: str, serial: str) -> tuple[str, str]:
    serial = serial.strip()
    return f"USBSTOR\\{hardware.strip()}\\{serial}", serial


def _device_group(
    groups: dict[tuple[str, str], dict[str, Any]],
    *,
    control_set: str,
    instance: str,
    serial: str,
) -> dict[str, Any]:
    return groups.setdefault(
        (control_set.casefold(), instance.casefold()),
        {
            "control_set": control_set,
            "device_instance_id": instance,
            "serial_number": serial,
            "friendly_name": "",
            "friendly_name_conflict": False,
            "time_conflicts": set(),
            "invalid_times": set(),
            "time_provenance": {},
            "source_row_indexes": [],
            **{field: "" for field in _TIMESTAMP_FIELDS},
        },
    )


def _merge_friendly_name(group: dict[str, Any], name: str) -> None:
    previous = str(group["friendly_name"])
    if previous and previous != name:
        group["friendly_name_conflict"] = True
    else:
        group["friendly_name"] = name


def _merge_group_timestamp(
    group: dict[str, Any], *, field: str, timestamp: str, source: str
) -> None:
    previous = str(group[field])
    if previous and previous != timestamp:
        group["time_conflicts"].add(field)
        group["time_provenance"].pop(field, None)
        return
    group[field] = timestamp
    group["time_provenance"].setdefault(field, source)


def _timestamp_basis(conflicts: set[str], provenance_kinds: set[str]) -> str:
    if conflicts:
        return "ambiguous"
    if provenance_kinds == {"native"}:
        return "native_device_property_filetime"
    if provenance_kinds == {"plugin"}:
        return "explicit_plugin_timestamp"
    if provenance_kinds == {"plugin_naive"}:
        return "plugin_naive_clock"
    if provenance_kinds and "plugin_naive" not in provenance_kinds:
        return "multiple_explicit_sources"
    return "multiple_sources" if provenance_kinds else "unavailable"


def normalize_usbstor_rows(
    numbered_rows: Iterable[tuple[int, Mapping[str, str]]],
) -> tuple[list[dict[str, Any]], int]:

    groups: dict[tuple[str, str], dict[str, Any]] = {}
    flattened: list[dict[str, Any]] = []
    source_count = 0
    for row_index, row in numbered_rows:
        source_count = max(source_count, row_index)
        batch_key_path = _first(row, "BatchKeyPath")
        plugin_match = _HARDWARE_KEY.fullmatch(batch_key_path)
        plugin_serial = _first(row, "SerialNumber", "Serial Number")
        if (
            plugin_match is not None
            and plugin_serial
            and not any(character in plugin_serial for character in "\\/*?")
        ):
            instance, serial = _identity(
                plugin_match.group("hardware"), plugin_serial
            )
            group = _device_group(
                groups,
                control_set=plugin_match.group("control_set"),
                instance=instance,
                serial=serial,
            )
            group["source_row_indexes"].append(row_index)
            friendly_name = _first(row, "DeviceName", "Title")
            if friendly_name:
                _merge_friendly_name(group, friendly_name)
            for source_name, field in _PLUGIN_TIME_FIELD.items():
                raw_timestamp = _first(row, source_name)
                if not raw_timestamp:
                    continue
                timestamp, basis = plugin_timestamp(raw_timestamp)
                if not timestamp:
                    group["invalid_times"].add(field)
                    continue
                _merge_group_timestamp(
                    group,
                    field=field,
                    timestamp=timestamp,
                    source=(
                        f"recmd_usbstor_plugin:{source_name}"
                        if basis == "explicit"
                        else f"recmd_usbstor_plugin_naive:{source_name}"
                    ),
                )
            continue
        key_path = _first(row, "KeyPath", "Key Path", "RegistryKey")
        property_match = _PROPERTY_KEY.fullmatch(key_path)
        instance_match = _INSTANCE_KEY.fullmatch(key_path)
        if property_match is not None or instance_match is not None:
            match = property_match or instance_match
            assert match is not None
            instance, serial = _identity(match.group("hardware"), match.group("serial"))
            control_set = match.group("control_set")
            group = _device_group(
                groups,
                control_set=control_set,
                instance=instance,
                serial=serial,
            )
            group["source_row_indexes"].append(row_index)
            if property_match is not None:
                field = _TIME_FIELD[property_match.group("property")]
                timestamp = registry_filetime(
                    value_type=_first(row, "ValueType", "Value Type"),
                    value_data=_first(row, "ValueData", "Value Data"),
                )
                if not timestamp:
                    group["invalid_times"].add(field)
                    continue
                _merge_group_timestamp(
                    group,
                    field=field,
                    timestamp=timestamp,
                    source=f"native_registry_property:{property_match.group('property')}",
                )
                continue
            name = _first(row, "ValueName", "Value Name").casefold()
            if name == "friendlyname":
                _merge_friendly_name(group, _first(row, "ValueData", "Value Data"))
            continue

        instance = _first(
            row,
            "DeviceInstanceId",
            "Device Instance Id",
            "DeviceInstanceID",
            "Device ID",
        )
        serial = _first(row, "SerialNumber", "Serial Number")
        if instance and not serial:
            serial = instance.rsplit("\\", 1)[-1]
        if not instance or not serial:
            continue
        flattened.append(
            {
                "device_instance_id": instance,
                "serial_number": serial,
                "friendly_name": _first(row, "FriendlyName", "Friendly Name"),
                "control_set": "",
                "registry_key_timestamp": "",
                "installed": "",
                "first_install": "",
                "last_arrival": "",
                "last_removal": "",
                "timestamp_basis": "unavailable",
                "time_provenance": {},
                "source_row_indexes": [row_index],
            }
        )

    records = list(flattened)
    for key in sorted(groups):
        group = groups[key]
        conflicts = set(group["time_conflicts"]) | set(group["invalid_times"])
        times = {
            field: "" if field in conflicts else str(group[field])
            for field in _TIMESTAMP_FIELDS
        }
        valid_times = {field: value for field, value in times.items() if value}
        time_provenance = {
            field: source
            for field, source in group["time_provenance"].items()
            if field in valid_times
        }
        provenance_kinds = {
            "native"
            if source.startswith("native_registry_property:")
            else ("plugin_naive" if source.startswith("recmd_usbstor_plugin_naive:") else "plugin")
            for source in time_provenance.values()
        }
        records.append(
            {
                "control_set": group["control_set"],
                "device_instance_id": group["device_instance_id"],
                "serial_number": group["serial_number"],
                "friendly_name": (
                    "" if group["friendly_name_conflict"] else group["friendly_name"]
                ),
                **times,
                "timestamp_basis": _timestamp_basis(conflicts, provenance_kinds),
                "time_provenance": time_provenance,
                "source_row_indexes": list(group["source_row_indexes"]),
            }
        )
    return records, source_count


def _setupapi_device_identity(line: str) -> str:
    direct = _DEVICE_HEADER.match(line)
    if direct is not None:
        return direct.group("device").strip()
    wpd = _WPD_USBSTOR_HEADER.match(line)
    if wpd is None:
        return ""
    return _identity(wpd.group("hardware"), wpd.group("serial"))[0]


def setupapi_timestamp(value: str) -> tuple[str, str]:
    explicit = explicit_timestamp(value)
    if explicit:
        return explicit, "explicit_offset"
    for pattern in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(value.strip(), pattern)
        except ValueError:
            continue
        return parsed.isoformat(), "local_clock"
    return "", "unparsed"


def parse_setupapi_surface(
    numbered_lines: Iterable[tuple[int, str]],
) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:

    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    source_count = 0
    usb_header_count = 0
    recognized_usb_header_count = 0
    malformed_usb_header_count = 0
    section_count = 0
    section_header_count = 0
    complete_section_count = 0
    incomplete_section_count = 0
    unframed_marker_count = 0
    timestamp_reversal_count = 0
    timestamp_basis_conflict_count = 0
    previous_start: tuple[str, str] | None = None
    section: dict[str, Any] | None = None
    first_section_timestamp: str | None = None
    last_section_timestamp: str | None = None
    last_section_end_timestamp: str | None = None

    def finish_section() -> None:
        nonlocal complete_section_count, incomplete_section_count, timestamp_reversal_count
        nonlocal last_section_end_timestamp
        if section is None:
            return
        start, end = section.get("start"), section.get("end")
        timestamps_valid = bool(
            start and end and start[1] == end[1]
            and start[1] in {"explicit_offset", "local_clock"}
        )
        if timestamps_valid and datetime.fromisoformat(end[0]) < datetime.fromisoformat(start[0]):
            timestamp_reversal_count += 1
            timestamps_valid = False
        if (
            timestamps_valid and section["start_count"] == 1
            and section["end_count"] == 1 and section["exit_count"] == 1
            and not section["out_of_order"]
        ):
            complete_section_count += 1
            if last_section_end_timestamp is None or end[0] > last_section_end_timestamp:
                last_section_end_timestamp = end[0]
        else:
            incomplete_section_count += 1

    for line_number, line in numbered_lines:
        source_count = max(source_count, line_number)
        stripped = line.strip()
        any_start = _SECTION_START.match(stripped) or _SECTION_START_LEGACY.match(stripped)
        if any_start is not None:
            section_count += 1
            timestamp, basis = setupapi_timestamp(any_start.group("timestamp"))
            if basis in {"explicit_offset", "local_clock"} and timestamp:
                if previous_start is not None:
                    if previous_start[1] != basis:
                        timestamp_basis_conflict_count += 1
                    elif datetime.fromisoformat(timestamp) < datetime.fromisoformat(previous_start[0]):
                        timestamp_reversal_count += 1
                previous_start = (timestamp, basis)
                if first_section_timestamp is None or timestamp < first_section_timestamp:
                    first_section_timestamp = timestamp
                if last_section_timestamp is None or timestamp > last_section_timestamp:
                    last_section_timestamp = timestamp
            if section is None:
                unframed_marker_count += 1
            else:
                section["start_count"] += 1
                section["start"] = (timestamp, basis)
                section["out_of_order"] |= bool(section["end_count"] or section["exit_count"])
        end = _SECTION_END.match(stripped) or _SECTION_END_LEGACY.match(stripped)
        if end is not None:
            if section is None:
                unframed_marker_count += 1
            else:
                section["end_count"] += 1
                section["end"] = setupapi_timestamp(end.group("timestamp"))
                section["out_of_order"] |= section["start_count"] != 1 or bool(section["exit_count"])
        if _SECTION_EXIT.match(stripped):
            if section is None:
                unframed_marker_count += 1
            else:
                section["exit_count"] += 1
                section["out_of_order"] |= section["end_count"] != 1
        instance = _setupapi_device_identity(stripped)
        is_section_header = bool(_SECTION_HEADER.match(stripped))
        looks_like_usb_header = bool(
            is_section_header
            and ("usbstor" in stripped.casefold() or " - usb\\" in stripped.casefold())
        )
        if looks_like_usb_header:
            usb_header_count += 1
        if is_section_header:
            finish_section()
            section_header_count += 1
            section = {"start_count": 0, "end_count": 0, "exit_count": 0, "out_of_order": False}
            if current is not None:
                records.append(current)
                current = None
            if instance:
                recognized_usb_header_count += 1
                current = {
                    "line_number": line_number,
                    "line": stripped,
                    "device_instance_id": instance,
                    "serial_number": instance.rsplit("\\", 1)[-1],
                    "event_timestamp": "",
                    "timestamp_basis": "missing",
                }
            elif looks_like_usb_header:
                malformed_usb_header_count += 1
            continue
        if current is None:
            continue
        if any_start is not None:
            timestamp, basis = setupapi_timestamp(any_start.group("timestamp"))
            current["event_timestamp"] = timestamp
            current["timestamp_basis"] = basis
    if current is not None:
        records.append(current)
    finish_section()
    return (
        records,
        source_count,
        {
            "usb_header_count": usb_header_count,
            "recognized_usb_header_count": recognized_usb_header_count,
            "malformed_usb_header_count": malformed_usb_header_count,
            "incomplete_section_count": incomplete_section_count,
            "incomplete_identity_section_count": sum(
                1 for record in records
                if record["timestamp_basis"] not in {"explicit_offset", "local_clock"}
            ),
            "section_count": section_count,
            "section_header_count": section_header_count,
            "complete_section_count": complete_section_count,
            "unframed_marker_count": unframed_marker_count,
            "timestamp_reversal_count": timestamp_reversal_count,
            "timestamp_basis_conflict_count": timestamp_basis_conflict_count,
            "section_structure_complete": bool(
                section_header_count and complete_section_count == section_header_count
                and not unframed_marker_count and not timestamp_reversal_count
                and not timestamp_basis_conflict_count
            ),
            "first_section_timestamp": first_section_timestamp,
            "last_section_timestamp": last_section_timestamp,
            "last_section_end_timestamp": last_section_end_timestamp,
        },
    )


__all__ = [
    "explicit_timestamp",
    "normalize_usbstor_rows",
    "parse_setupapi_surface",
    "registry_filetime",
    "setupapi_timestamp",
]
