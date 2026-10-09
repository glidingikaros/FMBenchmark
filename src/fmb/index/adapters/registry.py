from __future__ import annotations

import csv
import fnmatch
import io
import re
from collections.abc import Iterator, Callable
from pathlib import Path
from typing import Any

from fmb.index.adapters.mft import mft_active_presence_fields
from fmb.index.adapters.parser_output import (
    collector_output_root,
    parser_run_from_observations,
)
from fmb.index.support.usb_devices import (
    normalize_usbstor_rows,
    parse_setupapi_surface,
)
from fmb.index.support.windows_artifacts import (
    PATH_SUBJECT_HEADERS,
    csv_files_with_tokens,
    csv_has_required_headers,
    csv_header_names,
    first_nonempty,
    native_row_fields,
    parse_explicit_bool,
    parse_int,
    row_first,
    stream_csv_rows,
    user_path_score,
)
from fmb.index.support.windows_identity import (
    is_absolute_local_windows_path,
    ntfs_reference_from_row,
)

MAX_PATH_TRACE_OBSERVATIONS = 5000

MAX_USBSTOR_DISCOVERY_BYTES = 1024 * 1024

MAX_USBSTOR_DISCOVERY_ROWS = 4096

REGISTRY_MRU_CONTEXT_HEADERS = (
    "Extension",
    "BatchKeyPath",
    "BatchValueName",
    "Description",
    "Category",
    "KeyPath",
    "Comment",
    "PluginDetailFile",
)

TYPED_PATHS_KEY_SUFFIX = (
    r"\software\microsoft\windows\currentversion\explorer\typedpaths"
)

PATH_TRACE_SUBJECT_HEADERS = tuple(
    header for header in PATH_SUBJECT_HEADERS if header != "File Name"
)


def shellbag_csv_files(root: Path) -> list[Path]:
    return sorted(set(csv_files_with_tokens(root, include_any=("sbecmd", "shellbag"))) | {
        path for path in root.rglob("*.csv")
        if csv_has_required_headers(path, ("AbsolutePath",), ("BagPath",), ("ShellType",))
    })


def registry_mru_csv_files(root: Path) -> list[Path]:
    return csv_files_with_tokens(
        root,
        include_any=(
            "mru",
            "recentdocs",
            "typedpaths",
            "opensavepidl",
            "lastvisitedpidl",
            "recmd_batch",
        ),
        exclude_any=("sbecmd", "shellbag", "jumplist", "jlecmd", "lecmd"),
    )


def usbstor_csv_files(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for path in sorted(root.rglob("*.csv")):
        relative = path.relative_to(root)
        folded = relative.as_posix().casefold()
        if "setupapi" in folded:
            continue
        if any(
            token in folded
            for token in ("usbstor", "mounteddevices", "usbdevices", "usbdeview")
        ):
            candidates.append(path)
            continue
        parts = tuple(part.casefold() for part in relative.parts)
        if (
            len(parts) >= 3
            and parts[:2] == ("modules", "registry")
            and _registry_csv_has_exact_usbstor_identity(path)
        ):
            candidates.append(path)
    return candidates


def _registry_csv_has_exact_usbstor_identity(path: Path) -> bool:

    try:
        with path.open("rb") as handle:
            payload = handle.read(MAX_USBSTOR_DISCOVERY_BYTES + 1)
    except OSError:
        return False
    if len(payload) > MAX_USBSTOR_DISCOVERY_BYTES:
        payload = payload[:MAX_USBSTOR_DISCOVERY_BYTES]
        boundary = max(payload.rfind(b"\n"), payload.rfind(b"\r"))
        if boundary < 0:
            return False
        payload = payload[: boundary + 1]
    try:
        reader = csv.DictReader(
            io.StringIO(payload.decode("utf-8-sig")),
            strict=True,
        )
        if not reader.fieldnames or any(
            not str(name).strip() for name in reader.fieldnames
        ):
            return False
        found = False
        for row_index, raw_row in enumerate(reader, start=1):
            if row_index > MAX_USBSTOR_DISCOVERY_ROWS:
                break
            if None in raw_row or any(value is None for value in raw_row.values()):
                return False
            row = {str(key): str(value) for key, value in raw_row.items()}
            records, _source_count = normalize_usbstor_rows(((row_index, row),))
            if any(str(record.get("control_set") or "") for record in records):
                found = True
            instance = row_first(
                row,
                "DeviceInstanceId",
                "Device Instance Id",
                "DeviceInstanceID",
                "Device ID",
            ).replace("/", "\\")
            if instance.casefold().startswith("usbstor\\"):
                found = True
        return found
    except (csv.Error, UnicodeError):
        return False


SETUPAPI_LOG_NAME_PATTERNS = (
    "setupapi.dev.log",
    "setupapi.dev.*.log",
    "setupapi.upgrade.log",
    "setupapi.setup.log",
    "setupapi.offline.log",
)


ROTATED_SETUPAPI_DEV_LOG = re.compile(r"setupapi\.dev\.\d{8}_\d{6}\.log", re.IGNORECASE)


def is_setupapi_log_name(name: str) -> bool:
    folded = name.casefold()
    return any(fnmatch.fnmatchcase(folded, pattern) for pattern in SETUPAPI_LOG_NAME_PATTERNS)


def setupapi_log_files(root: Path) -> list[Path]:
    return [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and is_setupapi_log_name(path.name)
    ]


REGISTRY_MRU_CONTEXT_TOKENS = (
    "recentdocs",
    "typedpaths",
    "opensavepidlmru",
    "lastvisitedpidlmru",
    "runmru",
    "\\comdlg32\\",
    "file access and opening",
)


def registry_mru_subject_from_row(row: dict[str, str]) -> str | None:
    context = " ".join(
        row_first(row, key) for key in REGISTRY_MRU_CONTEXT_HEADERS
    ).casefold()
    if not any(token in context for token in REGISTRY_MRU_CONTEXT_TOKENS):
        return None
    subject = first_nonempty(
        row_first(
            row,
            "Path",
            "FullPath",
            "FilePath",
            "TargetPath",
            "TargetName",
            "LnkName",
            "ValueData",
            "Value",
            "Name",
            "FileName",
            "EntryName",
        ),
        "<unknown>",
    )
    return None if subject == "<unknown>" else subject


def is_typed_paths_registry_key(value: str) -> bool:
    normalized = value.strip().replace("/", "\\").casefold().rstrip("\\")
    return normalized.endswith(TYPED_PATHS_KEY_SUFFIX)


def registry_batch_csv_files(collector_run: dict[str, Any]) -> list[Path]:
    root = collector_output_root(collector_run)
    if root is None:
        return []
    return sorted(
        path
        for path in root.glob("modules/Registry/*.csv")
        if "recmd_batch" in path.name.casefold() and "output" in path.name.casefold()
    )


def _signed_dword(value: int | None) -> int | None:
    if value is None:
        return None
    return value - (1 << 32) if value >= (1 << 31) else value


def live_registry_rows(csv_path: Path) -> Iterator[tuple[int, dict[str, str]]]:
    for row_index, row in enumerate(stream_csv_rows(csv_path), start=1):
        if row_first(row, "Deleted").strip().casefold() == "true":
            continue
        yield row_index, row


def registry_system_facts(collector_run: dict[str, Any]) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "enable_prefetcher": None,
        "last_shutdown_time": None,
        "os_product_name": None,
        "os_edition_id": None,
        "os_current_build": None,
        "sysmain_start_mode": None,
        "time_zone_key_name": None,
        "time_zone_bias_minutes": None,
        "time_zone_active_bias_minutes": None,
        "source_files": [],
    }
    for csv_path in registry_batch_csv_files(collector_run):
        facts["source_files"].append(csv_path.name)
        for _row_index, row in live_registry_rows(csv_path):
            key_path = row_first(row, "KeyPath", "BatchKeyPath").casefold()
            value_name = row_first(row, "ValueName").casefold()
            value_data = row_first(row, "ValueData")
            if key_path.endswith("\\prefetchparameters") and value_name == "enableprefetcher":
                facts["enable_prefetcher"] = parse_int(value_data)
            elif key_path.endswith("\\control\\windows") and value_name == "shutdowntime":
                facts["last_shutdown_time"] = value_data or None
            elif key_path.endswith("\\control\\timezoneinformation"):
                if value_name == "timezonekeyname":
                    facts["time_zone_key_name"] = value_data or None
                elif value_name == "bias":
                    facts["time_zone_bias_minutes"] = _signed_dword(parse_int(value_data))
                elif value_name == "activetimebias":
                    facts["time_zone_active_bias_minutes"] = _signed_dword(parse_int(value_data))
            elif key_path.endswith("\\windows nt\\currentversion"):
                if value_name == "productname":
                    facts["os_product_name"] = value_data or None
                elif value_name == "editionid":
                    facts["os_edition_id"] = value_data or None
                elif value_name == "currentbuild":
                    facts["os_current_build"] = value_data or None
    root = collector_output_root(collector_run)
    if root is not None:
        for csv_path in sorted(root.glob("modules/Registry/*/*Services*SYSTEM*.csv")):
            for row in stream_csv_rows(csv_path):
                if row_first(row, "Name").casefold() == "sysmain":
                    facts["sysmain_start_mode"] = row_first(row, "StartMode") or None
                    facts["source_files"].append(csv_path.name)
                    break
    return facts


def path_trace_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    parser: str,
    parser_kind: str,
    source_module: str,
    command_needles: tuple[str, ...],
    normalized_suffix: str,
    artifact_family: str,
    observation_type: str,
    mft_context: dict[str, Any] | None = None,
    coverage_scope_builder: Callable[[int], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    observations = []
    candidate_count = 0
    required_header_groups = (
        (REGISTRY_MRU_CONTEXT_HEADERS, PATH_SUBJECT_HEADERS)
        if parser_kind == "windows_typed_paths"
        else (PATH_SUBJECT_HEADERS,)
    )
    contract_evaluable = csv_has_required_headers(csv_path, *required_header_groups)
    for row_index, row in live_registry_rows(csv_path):
        if parser_kind == "windows_typed_paths":
            subject = registry_mru_subject_from_row(row)
        else:
            subject = first_nonempty(
                row_first(row, *PATH_TRACE_SUBJECT_HEADERS), "<unknown>"
            )
        source_key = row_first(
            row,
            "BatchKeyPath",
            "KeyPath",
            "Key Path",
            "RegistryKey",
            "HivePath",
            "ProgramId",
            "SourceFile",
        )
        if (
            parser_kind == "windows_typed_paths"
            and not is_typed_paths_registry_key(source_key)
        ):
            continue
        if not subject or subject == "<unknown>":
            continue
        if parser_kind == "windows_typed_paths" and not is_absolute_local_windows_path(
            subject
        ):
            continue
        candidate_count += 1
        if candidate_count > MAX_PATH_TRACE_OBSERVATIONS:
            continue
        observations.append(
            {
                "observation_id": f"obs:{parser_kind}:{row_index:06d}",
                "artifact_family": artifact_family,
                "observation_type": observation_type,
                "subject_ref": subject,
                "fields": {
                    "row_index": row_index,
                    "timestamp": row_first(
                        row,
                        "Timestamp",
                        "LastWriteTimestamp",
                        "Last Write Timestamp",
                        "OpenedOn",
                        "ExtensionLastOpened",
                        "LastModified",
                        "LastModifiedTimeUTC",
                        "FileKeyLastWriteTimestamp",
                        "Created",
                        "Last Run",
                    ),
                    "source_key": source_key,
                    **native_row_fields(
                        row,
                        {
                            "key_path": ("BatchKeyPath", "KeyPath", "Key Path", "RegistryKey"),
                            "value_name": ("ValueName", "BatchValueName", "Value Name"),
                            "value_type": ("ValueType", "Value Type"),
                            "value_data": ("ValueData", "Value Data", "Value"),
                            "hive_path": ("HivePath", "Hive Path"),
                            "hive_type": ("HiveType", "Hive Type"),
                            "source_file": ("SourceFile", "Source File", "SourceFilename"),
                            "path": (
                                "Path", "FullPath", "FilePath", "TargetPath",
                                "ApplicationPath", "BinaryPath",
                            ),
                            "control_set": ("ControlSet", "Control Set"),
                            "cache_entry_position": ("CacheEntryPosition",),
                            "last_modified_time_utc": ("LastModifiedTimeUTC",),
                        },
                    ),
                    "source_parser": parser,
                    "source_module": source_module,
                    "candidate_score": user_path_score(subject),
                    **mft_active_presence_fields(
                        subject=subject,
                        file_reference=None,
                        mft_context=mft_context,
                    ),
                },
                "source_record_ref": f"{csv_path.name}:row={row_index}",
            }
        )
    return parser_run_from_observations(
        parser=parser,
        parser_kind=parser_kind,
        source_module=source_module,
        command_needles=command_needles,
        normalized_suffix=normalized_suffix,
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        raw_output=csv_path,
        observations=observations,
        coverage_status=(
            "complete"
            if contract_evaluable and candidate_count <= MAX_PATH_TRACE_OBSERVATIONS
            else "partial"
        ),
        coverage_families=[artifact_family],
        coverage_scope=(
            coverage_scope_builder(candidate_count) if coverage_scope_builder else None
        ),
    )


def usbstor_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
) -> dict[str, Any]:
    records, _source_count = normalize_usbstor_rows(live_registry_rows(csv_path))
    headers = csv_header_names(csv_path)
    contract_evaluable = any(
        alias.casefold() in headers
        for alias in (
            "KeyPath",
            "Key Path",
            "RegistryKey",
            "DeviceInstanceId",
            "Device Instance Id",
            "DeviceInstanceID",
            "Device ID",
        )
    ) or (
        "batchkeypath" in headers
        and bool({"serialnumber", "serial number"}.intersection(headers))
    )
    observations = []
    for record_index, record in enumerate(records, start=1):
        source_rows = list(record["source_row_indexes"])
        subject = str(record["device_instance_id"])
        observations.append(
            {
                "observation_id": f"obs:usbstor:{record_index:06d}",
                "artifact_family": "windows.registry.usbstor",
                "observation_type": "usb_device_seen",
                "subject_ref": subject,
                "fields": {
                    "device_instance_id": record["device_instance_id"],
                    "serial_number": record["serial_number"],
                    "friendly_name": record["friendly_name"],
                    "control_set": record["control_set"],
                    "registry_key_timestamp": record["registry_key_timestamp"],
                    "installed": record["installed"],
                    "first_install": record["first_install"],
                    "last_arrival": record["last_arrival"],
                    "last_removal": record["last_removal"],
                    "timestamp_basis": record["timestamp_basis"],
                    "time_provenance": record["time_provenance"],
                    "source_row_indexes": source_rows,
                },
                "source_record_ref": (
                    f"{csv_path.name}:rows="
                    + ",".join(str(item) for item in source_rows)
                ),
            }
        )
    return parser_run_from_observations(
        parser="RECmd",
        parser_kind="windows_usbstor",
        source_module="USBSTOR",
        command_needles=("usbstor",),
        normalized_suffix="usbstor",
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        raw_output=csv_path,
        observations=observations,
        coverage_status="complete" if contract_evaluable else "partial",
    )


def shellbag_ancestry_paths(rows, mft_context):
    resolved = {}
    nodes = {}
    context = mft_context or {}
    for ordinal, row in sorted(enumerate(rows, start=1), key=lambda item: row_first(item[1], "BagPath").count("\\")):
        if row_first(row, "ShellType").casefold() != "directory":
            continue
        absolute = row_first(row, "AbsolutePath").replace("/", "\\")
        bag = row_first(row, "BagPath")
        slot = row_first(row, "Slot")
        name = absolute.rsplit("\\", 1)[-1]
        if (not re.fullmatch(r"BagMRU(?:\\[0-9]+)*", bag, re.I)
                or not slot.isdigit() or name in {"", ".", ".."} or ":" in name):
            continue
        parent = nodes.get(bag.casefold())
        subject, sources = "", []
        if parent and absolute.rsplit("\\", 1)[0].casefold() == parent["absolute"].casefold():
            subject = parent["path"].rstrip("\\") + "\\" + name
            sources = [*parent["rows"], ordinal]
        else:
            reference = ntfs_reference_from_row(row, entry_keys=("MFTEntry",), sequence_keys=("MFTSequenceNumber",))
            target = context.get("directory_paths_by_ref", {}).get(reference, "")
            if target and target.rstrip("\\").rsplit("\\", 1)[-1].casefold() == name.casefold():
                if target.startswith(".\\") and len(context.get("indexed_volumes", set())) == 1:
                    target = next(iter(context["indexed_volumes"])).upper() + ":\\" + target[2:]
                if is_absolute_local_windows_path(target):
                    subject, sources = target, [ordinal]
        if subject:
            key = (bag + "\\" + slot).casefold()
            node = {"path": subject, "absolute": absolute, "rows": sources}
            if key in nodes and nodes[key] != node:
                nodes[key] = None
                continue
            nodes[key] = node
            resolved[ordinal] = node
    return resolved


def shellbag_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    mft_context: dict[str, Any] | None = None,
    resolve_namespace_ancestry: bool = False,
) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    native_contract = csv_has_required_headers(
        csv_path, ("AbsolutePath",), ("BagPath",), ("ShellType",)
    )
    unresolved_count = 0
    directory_count = 0
    rows = list(stream_csv_rows(csv_path))
    ancestry = shellbag_ancestry_paths(rows, mft_context) if resolve_namespace_ancestry else {}
    for row_index, row in enumerate(rows, start=1):
        shell_type = row_first(row, "ShellType")
        if shell_type.strip().casefold() != "directory":
            continue
        directory_count += 1
        absolute = row_first(row, "AbsolutePath").replace("/", "\\")
        bag_path = row_first(row, "BagPath")
        reference = ntfs_reference_from_row(
            row, entry_keys=("MFTEntry",), sequence_keys=("MFTSequenceNumber",)
        )
        drive_paths = re.findall(r"(?:^|\\)([A-Za-z]:\\.*)", absolute)
        subject = drive_paths[0] if len(drive_paths) == 1 else ""
        path_basis = "native_absolute_drive_path" if subject else "unresolved"
        path_refs = []
        if not subject and row_index in ancestry:
            anchor = ancestry[row_index]
            subject = anchor["path"]
            path_basis = "native_shell_ancestry_to_mft_directory"
            path_refs = [f"{csv_path.name}:row={n}" for n in anchor["rows"]]
            path_refs += [Path(p).name + ":directory-reference-index" for p in (mft_context or {}).get("source_paths", [])]
        reference_path = (mft_context or {}).get("directory_paths_by_ref", {}).get(reference)
        if not subject and reference_path:
            if (absolute.rsplit("\\", 1)[-1].casefold()
                    == str(reference_path).rstrip("\\").rsplit("\\", 1)[-1].casefold()):
                subject = str(reference_path)
                if subject.startswith(".\\"):
                    volumes = (mft_context or {}).get("indexed_volumes", set())
                    if len(volumes) == 1:
                        subject = next(iter(volumes)).upper() + ":\\" + subject[2:]
                path_basis = "native_shell_reference_to_mft_directory"
        if not is_absolute_local_windows_path(subject):
            unresolved_count += 1
            continue
        if directory_count > MAX_PATH_TRACE_OBSERVATIONS:
            continue
        observations.append({
            "observation_id": f"obs:shellbag:{row_index:06d}",
            "artifact_family": "windows.registry.shellbag",
            "observation_type": "shellbag_path_seen",
            "subject_ref": subject,
            "fields": {
                "path": subject, "absolute_path": absolute, "bag_path": bag_path,
                "shell_type": shell_type, "path_resolution_basis": path_basis,
                **({"path_resolution_source_refs": path_refs} if path_refs else {}),
                "shellbag_mft_entry": reference[0] if reference else None,
                "shellbag_mft_sequence": reference[1] if reference else None,
                "has_explored": parse_explicit_bool(row_first(row, "HasExplored")),
                "first_interacted": row_first(row, "FirstInteracted"),
                "last_interacted": row_first(row, "LastInteracted"),
                "last_write_time": row_first(row, "LastWriteTime"),
                "source_parser": "SBECmd", "source_module": "SBECmd",
                "source_file": str(csv_path),
                **mft_active_presence_fields(subject=subject, file_reference=None, mft_context=mft_context),
            },
            "source_record_ref": f"{csv_path.name}:row={row_index}",
        })
    hive_scope = shellbag_hive_scope(collector_run, csv_path=csv_path)
    hive_missing = hive_scope.get("hive_present") is not True
    return parser_run_from_observations(
        parser="SBECmd", parser_kind="windows_shellbag", source_module="SBECmd",
        command_needles=("sbecmd",), normalized_suffix="shellbag",
        normalized_output_dir=normalized_output_dir, collector_run=collector_run,
        raw_output=csv_path, observations=observations,
        additional_raw_outputs=([Path(p) for p in (mft_context or {}).get("source_paths", [])]
                                if resolve_namespace_ancestry else None),
        coverage_status="complete" if native_contract and not unresolved_count
        and not hive_missing
        and directory_count <= MAX_PATH_TRACE_OBSERVATIONS else "partial",
        coverage_families=["windows.registry.shellbag"],
        coverage_scope={**hive_scope, "directory_record_count": directory_count,
                        "unresolved_record_count": unresolved_count},
    )


SHELLBAG_CSV_NAME = re.compile(r"^(?P<user>.+)_(?P<hive>UsrClass|NTUSER)\.csv$", re.IGNORECASE)


def shellbag_hive_scope(collector_run: dict[str, Any], *, csv_path: Path) -> dict[str, Any]:
    match = SHELLBAG_CSV_NAME.match(csv_path.name)
    scope: dict[str, Any] = {"kind": "shellbag_hives", "source_file": csv_path.name,
                             "user": None, "hive": None, "hive_present": None, "hive_path": None}
    if match is None:
        return scope
    user, hive = match.group("user"), match.group("hive")
    scope.update({"user": user, "hive": hive})
    root = collector_output_root(collector_run)
    if root is None:
        return scope
    if hive.casefold() == "usrclass":
        pattern = f"targets/*/Users/{user}/AppData/Local/Microsoft/Windows/UsrClass.dat"
    else:
        pattern = f"targets/*/Users/{user}/NTUSER.DAT"
    candidates = [path for path in root.glob(pattern) if path.is_file()]
    if not candidates:
        candidates = [
            path for path in root.glob(pattern.replace("/Users/", "/[Uu]sers/"))
            if path.is_file()
        ]
    scope["hive_present"] = bool(candidates)
    scope["hive_path"] = candidates[0].relative_to(root).as_posix() if candidates else None
    return scope


def typed_paths_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    mft_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return path_trace_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        mft_context=mft_context,
        parser="RECmd",
        parser_kind="windows_typed_paths",
        source_module="RECmd_TypedPaths",
        command_needles=("recmd",),
        normalized_suffix="typed_paths",
        artifact_family="windows.registry.typed_paths",
        observation_type="typed_path_seen",
    )


def _guest_clock_offset(collector_run: dict[str, Any]) -> dict[str, Any]:
    facts = registry_system_facts(collector_run)
    bias = facts.get("time_zone_active_bias_minutes")
    if bias is None:
        bias = facts.get("time_zone_bias_minutes")
    return {
        "guest_utc_offset_minutes": -int(bias) if isinstance(bias, int) else None,
        "guest_time_zone": facts.get("time_zone_key_name"),
        "guest_time_zone_source": "SYSTEM\\TimeZoneInformation (ActiveTimeBias)"
        if isinstance(bias, int)
        else None,
    }


def setupapi_parser_run(
    *,
    log_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
) -> dict[str, Any]:
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        records, source_count, surface = parse_setupapi_surface(
            enumerate(handle, start=1)
        )
    observations = [
        {
            "observation_id": f"obs:setupapi:{index:06d}",
            "artifact_family": "windows.setupapi",
            "observation_type": "setupapi_usb_event",
            "subject_ref": str(record["device_instance_id"]),
            "fields": {
                "device_instance_id": record["device_instance_id"],
                "serial_number": record["serial_number"],
                "event_timestamp": record["event_timestamp"],
                "timestamp_basis": record["timestamp_basis"],
                "line_number": record["line_number"],
                "line": record["line"],
            },
            "source_record_ref": (
                f"{log_path.name}:section-start-line={record['line_number']}"
            ),
        }
        for index, record in enumerate(records, start=1)
    ]
    siblings = sorted(
        path.name for path in log_path.parent.iterdir()
        if path.is_file() and is_setupapi_log_name(path.name)
    ) if log_path.parent.is_dir() else [log_path.name]
    return parser_run_from_observations(
        parser="SetupAPI.dev.log",
        parser_kind="windows_setupapi",
        source_module="SetupAPI.dev.log",
        command_needles=("setupapi",),
        normalized_suffix="setupapi",
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        raw_output=log_path,
        observations=observations,
        coverage_status=(
            "complete"
            if source_count > 0
            and surface["recognized_usb_header_count"] == len(records)
            and surface["malformed_usb_header_count"] == 0
            and surface["incomplete_identity_section_count"] == 0
            else "partial"
        ),
        coverage_scope={
            "kind": "setupapi_log",
            "files": [log_path.name],
            "clock_basis": "guest_local",
            **_guest_clock_offset(collector_run),
            "retained_log_names": siblings,
            "rotated_logs_present": any(ROTATED_SETUPAPI_DEV_LOG.fullmatch(name) for name in siblings),
            "section_count": int(surface.get("section_count", 0)),
            "complete_section_count": surface["complete_section_count"],
            "incomplete_section_count": surface["incomplete_section_count"],
            "unframed_marker_count": surface["unframed_marker_count"],
            "timestamp_reversal_count": surface["timestamp_reversal_count"],
            "timestamp_basis_conflict_count": surface["timestamp_basis_conflict_count"],
            "section_structure_complete": surface["section_structure_complete"],
            "first_section_timestamp": surface.get("first_section_timestamp"),
            "last_section_timestamp": surface.get("last_section_timestamp"),
            "last_section_end_timestamp": surface.get("last_section_end_timestamp"),
            "window_complete": bool(
                surface["section_structure_complete"]
                and surface["malformed_usb_header_count"] == 0
                and surface.get("first_section_timestamp") and surface.get("last_section_timestamp")
            ),
            "window_basis": "parse_complete_retained_sections",
            "retention_basis": (
                "timestamp envelope of parsed retained sections only; rotation, "
                "disabled logging and omitted sections are not ruled out, and "
                "installs outside the retained envelope are not observable"
            ),
        },
    )
