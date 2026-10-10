from __future__ import annotations

from collections.abc import Container
from typing import Any

EVIDENCE_INDEX_SCHEMA_VERSION = "evidence_index.v1"

COLLECTION_TOOLS = ("kape", "uac", "native_checkpoint")
RULE_ENGINES = ("yara", "sigma")
PARSER_TOOLS = (
    "mftecmd",
    "evtxecmd",
    "pecmd",
    "sbecmd",
    "recmd",
    "jlecmd",
    "lecmd",
    "setupapi.dev.log",
    "appcompatcacheparser",
    "amcacheparser",
    "ntfslogtracker",
    "fmb_bounded_parser",
    "dfir_ntfs",
)

PARSER_ARTIFACT_FAMILIES_BY_KIND: dict[str, tuple[str, ...]] = {
    "native_usb_volume": ("usb_volume",),
    "ntfs_mft": ("ntfs.mft",),
    "ntfs_usn": ("ntfs.usn",),
    "ntfs_i30": ("ntfs.i30",),
    "ntfs_logfile": ("ntfs.logfile",),
    "ntfs_ads": ("ntfs.ads",),
    "ntfs_file_size_allocation": ("ntfs.file_size_allocation",),
    "windows_evtx_security": (
        "windows.event_log.security",
        "windows.event_log.record_sequence",
    ),
    "windows_prefetch": ("windows.prefetch",),
    "windows_shellbag": ("windows.registry.shellbag",),
    "windows_typed_paths": ("windows.registry.typed_paths",),
    "windows_jump_list": ("windows.jump_list", "windows.lnk"),
    "windows_usbstor": ("windows.registry.usbstor",),
    "windows_setupapi": ("windows.setupapi",),
    "windows_registry_paths": (
        "windows.registry.shimcache",
        "windows.registry.amcache",
    ),
    "materialized_file_content": ("collected.file.content",),
}

PARSER_OBSERVATION_TYPES = (
    "mft_file_record",
    "si_fn_timestamp_difference",
    "usn_file_delete",
    "usn_rename_old_name",
    "usn_basic_info_change",
    "i30_directory_scan",
    "i30_filename_residue",
    "logfile_timestamp_change",
    "logfile_file_delete",
    "logfile_file_rename",
    "logfile_si_update",
    "named_data_stream",
    "named_stream_content",
    "ntfs_allocation_record",
    "logical_allocated_size_record",
    "event_id_1102",
    "event_record_id_gap",
    "event_log_scope_seen",
    "prefetch_execution",
    "shellbag_path_seen",
    "typed_path_seen",
    "jump_list_path_seen",
    "usb_device_seen",
    "usb_volume_reference_history",
    "setupapi_usb_event",
    "shimcache_path_seen",
    "amcache_path_seen",
    "materialized_file_content_record",
    "usn_filesystem_activity",
    "usn_journal_record",
)


def canonical_parser_tool_name(parser: str) -> str:
    return parser.strip().casefold()


def _required_contract_string(
    value: Any,
    *,
    missing_message: str,
    strip_for_presence: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ValueError(missing_message)
    is_missing = not value.strip() if strip_for_presence else not value
    if is_missing:
        raise ValueError(missing_message)
    return value


def _supported_contract_string(
    value: Any,
    *,
    supported_values: Container[str],
    missing_message: str,
    unsupported_message: str,
    strip_for_presence: bool = False,
) -> str:
    candidate = _required_contract_string(
        value,
        missing_message=missing_message,
        strip_for_presence=strip_for_presence,
    )
    if candidate not in supported_values:
        raise ValueError(unsupported_message)
    return candidate


def collection_tool_for_contract(value: Any, *, label: str) -> str:
    return _supported_contract_string(
        value,
        supported_values=COLLECTION_TOOLS,
        missing_message=f"{label} has no collection tool",
        unsupported_message=f"unsupported collection tool: {value}",
    )


def parser_tool_for_contract(value: Any, *, label: str) -> str:
    raw_parser = _required_contract_string(
        value,
        missing_message=f"{label} has no parser",
        strip_for_presence=True,
    )
    parser = canonical_parser_tool_name(raw_parser)
    if parser not in PARSER_TOOLS:
        raise ValueError(f"{label} uses unsupported parser tool: {value}")
    return parser


def artifact_families_for_parser_kind(value: Any, *, label: str) -> set[str]:
    parser_kind = _supported_contract_string(
        value,
        supported_values=PARSER_ARTIFACT_FAMILIES_BY_KIND,
        missing_message=f"{label} has no parser_kind",
        unsupported_message=f"{label} uses unsupported parser_kind: {value}",
        strip_for_presence=True,
    )
    return set(PARSER_ARTIFACT_FAMILIES_BY_KIND[parser_kind])


def observation_type_for_contract(value: Any, *, label: str) -> str:
    return _supported_contract_string(
        value,
        supported_values=PARSER_OBSERVATION_TYPES,
        missing_message=f"{label} has no observation_type",
        unsupported_message=f"{label} has unsupported observation_type: {value}",
    )


__all__ = [
    "COLLECTION_TOOLS",
    "EVIDENCE_INDEX_SCHEMA_VERSION",
    "PARSER_ARTIFACT_FAMILIES_BY_KIND",
    "PARSER_OBSERVATION_TYPES",
    "PARSER_TOOLS",
    "RULE_ENGINES",
    "artifact_families_for_parser_kind",
    "canonical_parser_tool_name",
    "collection_tool_for_contract",
    "observation_type_for_contract",
    "parser_tool_for_contract",
]
