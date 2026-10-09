from __future__ import annotations

import re
from typing import Any
from fmb.analysis.domain import AnalysisInput
from fmb.analysis.inputs import (
    QTIME_REQUIRED_MFT_TIMESTAMP_FIELDS,
    active_mft_presence_fact,
    coverage_status,
)

_MFT_MODEL_FIELDS = (
    *QTIME_REQUIRED_MFT_TIMESTAMP_FIELDS,
    "mft_entry",
    "entry_number",
    "sequence_number",
    "mft_volume_id",
    "file_name",
    "path",
    "parent_entry_number",
    "parent_sequence_number",
    "parent_path",
    "file_size",
    "in_use",
    "is_directory",
    "has_ads",
    "is_ads",
    "si_flags",
    "name_type",
    "update_sequence_number",
)
_USN_MODEL_FIELDS = (
    "mft_volume_id",
    "file_reference_number",
    "file_reference_entry",
    "file_reference_sequence",
    "parent_file_reference_number",
    "parent_reference_entry",
    "parent_reference_sequence",
    "reconstructed_path",
    "record_offset",
    "update_sequence_number",
    "update_reasons",
    "update_timestamp",
    "file_attributes",
)
_USN_RECORD_MODEL_FIELDS = (
    *_USN_MODEL_FIELDS,
    "entry_number",
    "full_path",
    "name",
    "parent_entry_number",
    "parent_path",
    "parent_sequence_number",
    "path",
    "sequence_number",
    "update_sequence_number",
)
_HISTORICAL_MODEL_FIELDS_BY_RECORD_TYPE = {
    "shimcache_record": frozenset({"timestamp"}),
    "native_usb_reference_history": frozenset("""
        attachment_kind physical_host_device volume_guid_path binding_volume_serial
        binding_target_path binding_file_reference_number binding_journal_id
        binding_journal_start_usn native_binding_hash_verified native_binding_file
    """.split()),
}
_MODEL_FIELDS_BY_OBSERVATION_TYPE = {
    "usb_volume_reference_history": (
        "companion_directory_rows", "companion_directory_scope",
        "device_instance_id", "serial_number",
        "disk_bus_type", "disk_size_bytes", "native_boot_volume_serial",
        "link_volume_serial", "link_target_path",
        "link_file_reference_number", "native_identity_consistent",
        "active_mft_complete", "malformed_mft_entries", "active_original_path_count",
        "unresolved_active_mft_entries", "unresolved_active_mft_ancestry_count", "reserved_empty_mft_entries",
        "same_reference_mft_active", "same_reference_mft_paths", "journal_scan_complete",
        "referenced_entry_mft_entry", "referenced_entry_mft_sequence", "referenced_entry_mft_active",
        "referenced_entry_file_names", "native_mft_sequence_relation",
        "journal_parse_error_offsets", "journal_id", "journal_lowest_valid_usn",
        "journal_retained_end_usn", "original_name_usn_record_count",
        "alternative_name_usn_record_count", "same_reference_usn_records",
        "same_reference_rename_record_count", "same_reference_delete_record_count",
        "companion_sha256",
        "source_evidence_sha256", "native_source_sha256",
    ),
    "event_log_scope_seen": (
        "channel",
        "source_file",
        "event_log_scope_id",
        "first_event_record_id", "last_event_record_id", "record_count",
        "internal_gap_count", "missing_internal_record_count",
        "native_record_projection_complete", "duplicate_record_id_count",
        "malformed_record_count", "collection_scope", "retention_scope",
    ),
    "event_id_1102": (
        "channel",
        "event_id",
        "event_record_id",
        "provider",
        "source_file",
        "time_created",
    ),
    "event_record_id_gap": (
        "previous_record_id",
        "next_record_id",
        "gap_size",
        "channel",
        "source_file",
        "first_event_record_id",
        "last_event_record_id",
        "record_count",
    ),
    "i30_directory_scan": (
        "directory_path",
        "index_allocation_parsed",
        "index_allocation_present",
        "index_allocation_entry_count",
        "index_allocation_errors",
        "mft_entry",
        "mft_record_slack_scanned",
        "mft_volume_id",
        "record_slack_entry_count",
        "resident_entry_count",
        "resident_index_root_scanned",
        "residue_count",
        "scan_complete",
        "sequence_number",
        "supported_surface",
    ),
    "i30_filename_residue": (
        "mft_volume_id",
        "directory_entry_number",
        "directory_in_use",
        "directory_path",
        "entry_name",
        "entry_path",
        "entry_reference_entry",
        "entry_reference_sequence",
        "file_reference_entry",
        "file_reference_sequence",
        "from_slack",
        "has_index_allocation",
        "i30_entry_state",
        "i30_state_source",
        "mft_entry",
        "name_namespace",
        "parent_path",
        "parent_reference_entry",
        "parent_reference_sequence",
        "residue_surface",
        "sequence_number",
    ),
    "logical_allocated_size_record": (
        "allocated_cluster_count",
        "allocated_size",
        "attribute_chain_complete",
        "attribute_flags",
        "attribute_id",
        "attribute_parse_error_count",
        "data_run_count",
        "highest_vcn",
        "is_compressed",
        "is_encrypted",
        "is_sparse",
        "logical_size",
        "lowest_vcn",
        "mft_entry",
        "mftecmd_file_size",
        "mftecmd_identity_match",
        "resident_status",
        "runlist_complete",
        "sequence_number",
        "sparse_cluster_count",
        "stream_name",
        "valid_data_length",
        "volume_id",
    ),
    "materialized_file_content_record": (
        "declared_content_end",
        "signature", "reserved1", "reserved2", "pixel_offset", "dib_size", "width", "height",
        "planes", "bits_per_pixel", "compression", "image_size", "colors_used",
        "format_id",
        "header_parse_status",
        "materialized_size",
        "mft_entry",
        "sequence_number",
        "volume_id",
    ),
    "mft_file_record": (
        *_MFT_MODEL_FIELDS,
        "raw_mft_timestamp_validation",
        "raw_mft_timestamp_source_ref",
        "stream_name",
        "volume_id",
    ),
    "named_data_stream": (
        "base_path",
        "entry_number",
        "file_name",
        "file_size",
        "has_ads",
        "host_named_stream_count",
        "host_path",
        "host_population_complete",
        "host_population_size",
        "hosts_without_named_stream_count",
        "in_use",
        "is_ads",
        "is_directory",
        "mft_entry",
        "mft_volume_id",
        "name_type",
        "parent_entry_number",
        "parent_path",
        "parent_sequence_number",
        "path",
        "sequence_number",
        "stream_name",
        "stream_name_occurrences",
        "stream_size",
    ),
    "named_stream_content": (
        "mft_entry", "sequence_number", "mft_volume_id", "stream_name", "stream_size",
        "attribute_id", "content_complete", "native_identity_verified", "materialized_size",
        "content_sha256", "dos_signature_hex", "pe_header_offset", "pe_signature_hex",
        "pe_machine", "pe_section_count", "pe_optional_header_size", "pe_characteristics",
        "pe_optional_magic", "pe_size_of_headers", "pe_sections", "pe_structure_status",
        "zip_signature_hex", "zip_structure_status", "zip_end_record_offset", "zip_end_signature_hex",
        "zip_disk_number", "zip_directory_disk", "zip_disk_entry_count", "zip_entry_count",
        "zip_directory_size", "zip_directory_offset", "zip_comment_length", "zip_entries", "zip_expanded_size",
    ),
    "prefetch_execution": (
        "native_volume_token", "native_volume_creation_filetime", "native_volume_serial_number",
        "native_volume_boot_source_ref", "native_volume_mft_source_ref", "native_volume_manifest_sha256",
        "executable_name",
        "files_loaded",
        "last_run",
        "run_count",
        "path",
        "source_file",
    ),
    "setupapi_usb_event": (
        "device_instance_id",
        "serial_number",
        "event_timestamp",
        "timestamp_basis",
    ),
    "shimcache_path_seen": (
        "native_volume_token", "native_volume_creation_filetime", "native_volume_serial_number",
        "native_volume_boot_source_ref", "native_volume_mft_source_ref", "native_volume_manifest_sha256",
        "cache_entry_position",
        "control_set",
        "last_modified_time_utc",
        "path",
        "key_path",
        "hive_path",
        "source_file",
    ),
    "typed_path_seen": (
        "hive_path",
        "key_path",
        "last_write_timestamp",
        "timestamp",
        "value_data",
        "value_name",
        "value_type",
        "source_key",
        "source_file",
        "source_parser",
        "source_module",
    ),
    "shellbag_path_seen": (
        "path", "absolute_path", "bag_path", "shell_type",
        "path_resolution_basis", "path_resolution_source_refs", "shellbag_mft_entry", "shellbag_mft_sequence",
        "has_explored", "first_interacted", "last_interacted", "last_write_time",
        "source_parser", "source_module",
    ),
    "ntfs_allocation_record": (
        "mft_entry", "sequence_number", "volume_id", "mft_volume_id", "stream_name",
        "resident_status", "is_sparse", "is_compressed", "is_encrypted",
        "attribute_flags", "logical_size", "allocated_size", "valid_data_length",
        "lowest_vcn", "highest_vcn", "runlist_complete", "allocated_cluster_count",
        "sparse_cluster_count", "attribute_chain_complete", "bytes_per_cluster",
        "total_clusters", "volume_serial_number", "geometry_source",
        "native_identity_verified", "runlist_in_volume", "data_runs",
    ),
    "usb_device_seen": (
        "control_set",
        "device_instance_id",
        "serial_number",
        "first_install",
        "installed",
        "timestamp_basis",
    ),
    "logfile_si_update": (
        "lsn", "transaction_id", "transaction_committed", "transaction_forgotten_lsn",
        "transaction_rolled_back", "redo_operation", "mft_entry", "sequence_number",
        "record_in_use", "record_lsn", "record_lsn_retained", "covered_fields",
        "si_timestamp_fragments",
        "old_si_created", "new_si_created", "old_si_modified", "new_si_modified",
        "old_si_record_changed", "new_si_record_changed", "old_si_accessed",
        "new_si_accessed", "current_si_created", "current_si_modified",
        "current_si_record_changed", "current_si_accessed", "binding_basis",
        "mft_volume_id", "mft_lookup_target", "mft_lookup_observed",
    ),
    "usn_basic_info_change": (*_USN_MODEL_FIELDS,),
    "usn_file_delete": _USN_RECORD_MODEL_FIELDS,
    "usn_filesystem_activity": _USN_RECORD_MODEL_FIELDS,
    "usn_rename_old_name": _USN_RECORD_MODEL_FIELDS,
}


_USN_OBSERVATION_TYPES = frozenset(
    {
        "usn_basic_info_change",
        "usn_filesystem_activity",
        "usn_file_delete",
        "usn_rename_old_name",
    }
)
_RECORD_TYPES = {
    "usb_volume_reference_history": "native_usb_reference_history",
    "event_log_scope_seen": "event_log_scope",
    "mft_file_record": "mft_record",
    "logfile_si_update": "logfile_si_update_record",
    "event_id_1102": "event_record",
    "event_record_id_gap": "event_sequence_summary",
    "i30_directory_scan": "directory_index_scan",
    "i30_filename_residue": "directory_index_entry",
    "logical_allocated_size_record": "ntfs_data_attribute",
    "materialized_file_content_record": "file_content",
    "prefetch_execution": "prefetch_record",
    "shimcache_path_seen": "shimcache_record",
    "typed_path_seen": "registry_value",
    "shellbag_path_seen": "shellbag_directory_item",
    "ntfs_allocation_record": "ntfs_allocation_attribute",
    "named_stream_content": "named_stream_native_content",
    **{name: "usn_record" for name in _USN_OBSERVATION_TYPES},
}
_GENERIC_RECORD_TYPES = {
    "event_record_id_gap": "adjacent_event_record_ids",
}
_GENERIC_EXCLUDED_MODEL_FIELDS = {
    "logfile_si_update": frozenset({"mft_lookup_observed"}),
    "event_log_scope_seen": frozenset(
        {"internal_gap_count", "missing_internal_record_count"}
    ),
    "event_record_id_gap": frozenset({"gap_size"}),
    "i30_directory_scan": frozenset({"residue_count", "supported_surface"}),
    "materialized_file_content_record": frozenset({"declared_content_end"}),
    "named_data_stream": frozenset(
        {"host_population_size", "hosts_without_named_stream_count"}
    ),
    "named_stream_content": frozenset(
        {"pe_structure_status", "zip_structure_status"}
    ),
    "usb_volume_reference_history": frozenset(
        {
            "original_path_lookup",
            "active_original_path_count",
            "alternative_name_usn_record_count",
            "native_identity_consistent",
            "native_mft_sequence_relation",
            "original_name_usn_record_count",
            "same_reference_delete_record_count",
            "same_reference_rename_record_count",
        }
    ),
}
_GENERIC_EXCLUDED_SCOPE_FIELDS = {
    "ntfs_logfile": frozenset({"si_update_bound_count", "si_update_count"}),
}


def _present_fields(fields: dict[str, Any], names: tuple[str, ...]) -> dict[str, Any]:
    return {
        name: fields[name]
        for name in names
        if name in fields and fields[name] not in (None, "")
    }


_HOST_PATH_PATTERN = re.compile(
    r"(?:^|[\s\"'(\[=:,])/(?:Users|private|tmp|var|Volumes|home|opt|etc|root|mnt|srv)/",
)
_CASE_LABEL_PATTERN = re.compile(
    r"(?:pair\d+[-_/](?:positive|benign))|(?:[/\\](?:positive|benign)[/\\])|(?:\.fmb[/\\])",
    re.IGNORECASE,
)


def blinding_violations(value: Any, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        if _HOST_PATH_PATTERN.search(value) or _CASE_LABEL_PATTERN.search(value):
            found.append(path)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.extend(blinding_violations(item, f"{path}.{key}"))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(blinding_violations(item, f"{path}[{index}]"))
    return found


def _allowlisted_fields(
    fields: dict[str, Any], names: tuple[str, ...]
) -> dict[str, Any]:
    return {name: fields[name] for name in names if name in fields}


def _collected_artifact_path(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    normalized = value.replace("\\", "/")
    if not (normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized)):
        return value
    parts = normalized.split("/")
    boundaries = [
        index
        for index in range(len(parts) - 2)
        if parts[index].casefold() == "kape-output"
        and parts[index + 1].casefold() == "targets"
    ]
    if len(boundaries) != 1 or any(part in {".", ".."} for part in parts[boundaries[0]:]):
        return value
    relative = parts[boundaries[0] + 1 :]
    if len(relative) < 3 or any(not part for part in relative):
        return value
    return "/".join(["targets", *relative[1:]])


_NON_EVIDENCE_ANNOTATIONS = frozenset({
    "support_routes", "deterministic_verdict", "verdict", "assessment",
    "reason_code", "derived_invariants", "category_hint", "positive_count",
    "supported_count", "classification", "detector_result",
})
_SHELLBAG_HIVE_FIELDS = frozenset("""
    user hive hive_path hive_present source_file directory_record_count unresolved_record_count
""".split())
_SCOPE_COMMON_FIELDS = frozenset({
    "kind", "source_file", "intervals", "gap_count", "coverage_interval_gap_count", "identity_conflict",
})
_SCOPE_FIELDS = {
    "usn_journal": frozenset("""
        allocation_delta checked_record_count control_identity_bound first_reversal_usn
        first_timestamp first_usn journal_id journal_source last_timestamp last_usn
        lowest_valid_usn max_backward_seconds max_record_source maximum_size order_checked
        record_count record_count_basis retention_basis stale_head_record_count
        timestamp_reversal_count window_complete window_validity
    """.split()),
    "setupapi_log": frozenset("""
        clock_basis files first_section_timestamp guest_time_zone guest_time_zone_source
        guest_utc_offset_minutes last_section_timestamp last_section_end_timestamp retained_log_names retention_basis
        rotated_logs_present section_count window_complete complete_section_count incomplete_section_count
        unframed_marker_count timestamp_reversal_count timestamp_basis_conflict_count
        section_structure_complete window_basis
    """.split()),
    "prefetch": frozenset("""
        application_prefetch_enabled enable_prefetcher os_current_build os_edition_id
        os_product_name pf_file_count pf_file_limit record_count registry_sources
        sysmain_disabled sysmain_start_mode
    """.split()),
    "shimcache": frozenset("""
        last_shutdown_time persistence_basis record_count registry_sources
    """.split()),
    "shellbag_hives": frozenset("""
        directory_record_count hive hive_path hive_present hives unresolved_record_count user
    """.split()),
    "security_event_log": frozenset("""
        audit_events_dropped_count eventlog_service_stopped_count first_record_id
        first_time_created last_record_id last_time_created log_auto_backup_count
        log_full_count native_record_projection_complete record_count retention_basis
        window_complete
    """.split()),
    "ntfs_logfile": frozenset("""
        client_count embedded_usn_record_count first_timestamp first_usn last_timestamp
        last_usn lifecycle_record_count log_version lsn_first lsn_last multi_client
        page_coverage_complete parse_error_count parser_status reason record_count
        record_page_failure_count records_truncated restart_area_count retention_basis
        si_update_bound_count si_update_count si_update_unbound_count si_update_unbound_reasons
        size_bytes source_sha256 timestamp_order unknown_page_count window_complete
        witnesses_withheld
    """.split()),
}
_SCOPE_INTERVAL_FIELDS = frozenset("""
    source_file first last complete journal_id first_usn last_usn lowest_valid_usn
    window_validity control_identity_bound journal_source order_checked
    checked_record_count timestamp_reversal_count last_section_end_timestamp
""".split())
_LOGFILE_BINDING_DIAGNOSTICS = frozenset("""
    record_unreadable si_value_offset_unresolved update_bytes_malformed
    entry_reinitialised_after_update record_lsn_precedes_update record_not_in_use
    mft_context_sequence_disagrees raw_mft_unavailable records_truncated
    page_coverage_incomplete multi_client_unsupported record_parse_errors_or_unverified_count
""".split())
_SCOPE_STRING_LIST_FIELDS = frozenset({"files", "retained_log_names", "registry_sources"})


def _scope_fact_mapping(value: Any, allowed: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("model coverage facts must be an object")
    unknown = value.keys() - allowed - _NON_EVIDENCE_ANNOTATIONS
    if unknown:
        raise ValueError("unregistered model coverage fields require review")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key in _NON_EVIDENCE_ANNOTATIONS:
            continue
        if key == "intervals":
            if not isinstance(item, list):
                raise ValueError("model coverage intervals must be a list")
            result[key] = [_scope_fact_mapping(row, _SCOPE_INTERVAL_FIELDS) for row in item]
        elif key == "hives":
            if not isinstance(item, list):
                raise ValueError("model coverage hives must be a list")
            result[key] = [_scope_fact_mapping(row, _SHELLBAG_HIVE_FIELDS) for row in item]
        elif key == "si_update_unbound_reasons":
            reasons = _scope_fact_mapping(item, _LOGFILE_BINDING_DIAGNOSTICS)
            if any(type(count) is not int or count < 0 for count in reasons.values()):
                raise ValueError("model coverage binding diagnostics must be counts")
            result[key] = reasons
        elif key in _SCOPE_STRING_LIST_FIELDS:
            if not isinstance(item, list) or not all(isinstance(name, str) for name in item):
                raise ValueError("model coverage source names must be strings")
            result[key] = list(item)
        elif item is None or type(item) in (str, bool, int, float):
            result[key] = _collected_artifact_path(item) if key in {"source_file", "hive_path"} else item
        else:
            raise ValueError("model coverage scalar facts must not contain annotations")
    return result


def _model_coverage_scope(scope: Any) -> dict[str, Any]:
    if not scope:
        return {}
    fields = _SCOPE_FIELDS.get(scope.get("kind"))
    if fields is None:
        raise ValueError("unregistered model coverage kind requires review")
    result = _scope_fact_mapping(dict(scope), fields | _SCOPE_COMMON_FIELDS)
    for key in _GENERIC_EXCLUDED_SCOPE_FIELDS.get(str(scope.get("kind")), frozenset()):
        result.pop(key, None)
    return result


def _model_native_data_runs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("model native DATA runs must be a list")
    result = []
    names = {"vcn", "lcn", "cluster_count"}
    for run in value:
        if not isinstance(run, dict) or run.keys() - _NON_EVIDENCE_ANNOTATIONS != names:
            raise ValueError("unregistered model native DATA run fields require review")
        if not (
            type(run["vcn"]) is int and run["vcn"] >= 0
            and type(run["cluster_count"]) is int and run["cluster_count"] > 0
            and (run["lcn"] is None or type(run["lcn"]) is int and run["lcn"] >= 0)
        ):
            raise ValueError("model native DATA run values must be decoded integers")
        result.append({name: run[name] for name in ("vcn", "lcn", "cluster_count")})
    return result


_FORMAT_ENTRY_FIELDS = {
    "pe_sections": frozenset({"raw_size", "raw_offset", "characteristics"}),
    "zip_entries": frozenset("""
        central_header_offset central_header_end central_signature_hex local_header_offset
        local_signature_hex data_offset data_end record_end flags compression_method version_needed
        compressed_size uncompressed_size observed_uncompressed_size crc32 observed_crc32
        local_crc32 local_compressed_size local_uncompressed_size
        central_name_hex local_name_hex local_flags local_compression_method local_version_needed
    """.split()),
}


def _model_format_entries(kind: str, value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("model native format entries must be a list")
    names = _FORMAT_ENTRY_FIELDS[kind]
    result = []
    for entry in value:
        if not isinstance(entry, dict) or entry.keys() - names - _NON_EVIDENCE_ANNOTATIONS:
            raise ValueError("unregistered model native format fields require review")
        projected = {key: item for key, item in entry.items() if key in names}
        if any(type(item) not in (str, int) for item in projected.values()):
            raise ValueError("model native format facts must be scalar measurements")
        result.append(projected)
    return result


def _mft_model_fields(fields: dict[str, Any]) -> dict[str, Any]:
    projected = _present_fields(fields, _MFT_MODEL_FIELDS)
    if "si_record_changed" not in projected and fields.get("record_changed_si"):
        projected["si_record_changed"] = fields["record_changed_si"]
    return projected


def _model_record(
    analysis_input: AnalysisInput,
    observation: Any,
    subject: Any,
) -> dict[str, Any] | None:
    fields = observation.fields
    if analysis_input.technique_id == "timestamp_manipulation":
        if observation.artifact_family == "ntfs.mft":
            record_type = "mft_record"
            projected_fields = _mft_model_fields(fields)
        elif observation.artifact_family == "ntfs.usn":
            record_type = "usn_record"
            projected_fields = _present_fields(fields, _USN_MODEL_FIELDS)
        else:
            record_type = observation.observation_type
            projected_fields = _allowlisted_fields(
                fields,
                _MODEL_FIELDS_BY_OBSERVATION_TYPE.get(record_type, ()),
            )
    else:
        record_type = _RECORD_TYPES.get(
            observation.observation_type, observation.observation_type
        )
        projected_fields = _allowlisted_fields(
            fields,
            _MODEL_FIELDS_BY_OBSERVATION_TYPE.get(observation.observation_type, ()),
        )
    if not projected_fields:
        return None
    for key in _FORMAT_ENTRY_FIELDS:
        if key in projected_fields:
            projected_fields[key] = _model_format_entries(key, projected_fields[key])
    if "data_runs" in projected_fields:
        projected_fields["data_runs"] = _model_native_data_runs(projected_fields["data_runs"])
    for key in ("source_file", "hive_path"):
        if key in projected_fields:
            projected_fields[key] = _collected_artifact_path(projected_fields[key])
    if observation.observation_type == "typed_path_seen":
        if "key_path" not in projected_fields and fields.get("source_key"):
            projected_fields["key_path"] = fields["source_key"]
    if observation.observation_type == "event_id_1102":
        if "time_created" not in projected_fields and fields.get("timestamp"):
            projected_fields["time_created"] = fields["timestamp"]
    if (
        analysis_input.technique_id
        in {
            "deleted_file_journal_residue",
            "typed_path_residue",
            "shellbag_missing_directory",
            "i30_directory_residue",
            "prefetch_missing_executable",
            "shimcache_path_residue",
        }
        and "mft_active_presence_check_supported" in fields
    ):
        projected_fields["active_mft_lookup"] = active_mft_presence_fact(
            observation,
            subject,
            collection_status=coverage_status(analysis_input, "ntfs.mft"),
            referenced_object=observation.observation_type == "i30_filename_residue",
        )
    for key in _GENERIC_EXCLUDED_MODEL_FIELDS.get(
        observation.observation_type, frozenset()
    ):
        projected_fields.pop(key, None)
    record_type = _GENERIC_RECORD_TYPES.get(observation.observation_type, record_type)
    return {
        "artifact_family": observation.artifact_family,
        "record_type": record_type,
        "subject_ref": observation.subject_ref,
        "source_record_ref": observation.source_record_ref,
        "fields": projected_fields,
    }


def _merge_model_record(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    if (
        existing["record_type"] != incoming["record_type"]
        or existing["subject_ref"] != incoming["subject_ref"]
    ):
        raise ValueError("duplicate physical evidence records disagree on identity")
    existing_fields = existing["fields"]
    for key, value in incoming["fields"].items():
        previous = existing_fields.get(key)
        if previous in (None, ""):
            existing_fields[key] = value
        elif value not in (None, "") and previous != value:
            raise ValueError(
                f"duplicate physical evidence records disagree on field: {key}"
            )
