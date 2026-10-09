from __future__ import annotations

from pathlib import Path
from typing import Any

from fmb.index.adapters.mft import mft_active_presence_fields
from fmb.index.adapters.parser_output import (
    collector_output_root,
    parser_run_from_observations,
)
from fmb.index.adapters.registry import (
    path_trace_parser_run,
    registry_system_facts,
)
from fmb.index.support.windows_artifacts import (
    csv_files_with_tokens,
    csv_has_required_headers,
    first_nonempty,
    native_row_fields,
    parse_int,
    row_first,
    score_candidate_name,
    stream_csv_rows,
)
from fmb.index.support.windows_identity import (
    REMOTE_PATH_VOLUME,
    windows_compare_path_parts,
)

MAX_PECMD_PREFETCH_OBSERVATIONS = 5000

PECMD_EXECUTABLE_PATH_HEADERS = (
    "ExecutablePath",
    "Executable Path",
    "ApplicationPath",
    "Application Path",
    "BinaryPath",
    "Binary Path",
    "ReferencedExecutable",
    "Referenced Executable",
)

PECMD_FILES_LOADED_HEADERS = (
    "FilesLoaded",
    "Files Loaded",
    "ReferencedFiles",
    "Referenced Files",
)


def pecmd_csv_files(root: Path) -> list[Path]:
    return csv_files_with_tokens(
        root,
        include_any=("pecmd", "prefetch"),
        exclude_any=("timeline",),
    )


def jump_list_csv_files(root: Path) -> list[Path]:
    return csv_files_with_tokens(
        root,
        include_any=(
            "jlecmd",
            "lecmd",
            "jumplist",
            "automaticdestinations",
            "customdestinations",
        ),
        exclude_any=("sbecmd", "shellbag"),
    )


def registry_path_csv_files(root: Path) -> list[Path]:
    return csv_files_with_tokens(
        root,
        include_any=("shimcache", "appcompatcache", "amcache"),
        exclude_any=("prefetch", "pecmd"),
    )


def prefetch_coverage_scope(
    collector_run: dict[str, Any], *, csv_path: Path, record_count: int
) -> dict[str, Any]:
    root = collector_output_root(collector_run)
    pf_count = None
    if root is not None:
        pf_count = sum(
            1
            for path in root.glob("targets/*/Windows/[Pp]refetch/*")
            if path.is_file() and path.suffix.casefold() == ".pf"
        )
    facts = registry_system_facts(collector_run)
    prefetch_enabled = None
    if facts["enable_prefetcher"] is not None:
        prefetch_enabled = facts["enable_prefetcher"] in (1, 3)
    sysmain_disabled = (
        str(facts["sysmain_start_mode"] or "").casefold() == "disabled"
        if facts["sysmain_start_mode"] is not None
        else None
    )
    return {
        "kind": "prefetch",
        "source_file": csv_path.name,
        "record_count": record_count,
        "pf_file_count": pf_count,
        "pf_file_limit": 1024,
        "enable_prefetcher": facts["enable_prefetcher"],
        "application_prefetch_enabled": prefetch_enabled,
        "sysmain_start_mode": facts["sysmain_start_mode"],
        "sysmain_disabled": sysmain_disabled,
        "os_product_name": facts["os_product_name"],
        "os_edition_id": facts["os_edition_id"],
        "os_current_build": facts["os_current_build"],
        "registry_sources": facts["source_files"],
    }


def shimcache_coverage_scope(collector_run: dict[str, Any], *, csv_path: Path, record_count: int) -> dict[str, Any]:
    facts = registry_system_facts(collector_run)
    return {
        "kind": "shimcache",
        "source_file": csv_path.name,
        "record_count": record_count,
        "last_shutdown_time": facts["last_shutdown_time"],
        "persistence_basis": (
            "AppCompatCache is written to the SYSTEM hive at shutdown; entries "
            "created after the last shutdown are not in the collected hive"
        ),
        "registry_sources": facts["source_files"],
    }


def pecmd_prefetch_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    mft_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    observations = []
    candidate_count = 0
    for row_index, row in enumerate(stream_csv_rows(csv_path), start=1):
        executable_name = row_first(row, "ExecutableName", "Executable Name")
        explicit_executable_path = row_first(row, *PECMD_EXECUTABLE_PATH_HEADERS)
        referenced_paths = [explicit_executable_path]
        files_loaded = row_first(row, *PECMD_FILES_LOADED_HEADERS)
        referenced_paths.extend(
            item.strip()
            for item in files_loaded.replace(", ", "|").replace(";", "|").split("|")
            if item.strip()
        )
        matching_paths: dict[tuple[str | None, str], str] = {}
        for path in referenced_paths:
            if not path:
                continue
            identity = windows_compare_path_parts(path)
            if identity[0] in {None, REMOTE_PATH_VOLUME}:
                continue
            if (
                not executable_name and path == explicit_executable_path
                or path.replace("/", "\\").rpartition("\\")[2].casefold()
                == executable_name.casefold()
            ):
                matching_paths.setdefault(identity, path)
        ambiguous_path = len(matching_paths) > 1
        exact_path = next(iter(matching_paths.values())) if len(matching_paths) == 1 else ""
        if not executable_name and exact_path:
            executable_name = exact_path.replace("/", "\\").rpartition("\\")[2]
        subject = first_nonempty(
            exact_path,
            executable_name,
            row_first(row, "FileName", "Filename"),
            "<unknown>",
        )
        if subject == "<unknown>":
            continue
        candidate_count += 1
        if candidate_count > MAX_PECMD_PREFETCH_OBSERVATIONS:
            continue
        mft_fields = mft_active_presence_fields(
            subject=subject,
            file_reference=None,
            mft_context=None if ambiguous_path else mft_context,
        )
        if ambiguous_path:
            mft_fields["mft_active_presence_status"] = "active_mft_absence_undecidable"
            mft_fields["mft_active_presence_basis"] = "ambiguous_prefetch_executable_paths"
        observations.append(
            {
                "observation_id": f"obs:pecmd-prefetch:{row_index:06d}",
                "artifact_family": "windows.prefetch",
                "observation_type": "prefetch_execution",
                "subject_ref": subject,
                "fields": {
                    "run_count": parse_int(row_first(row, "RunCount", "Run Count")),
                    "last_run": row_first(
                        row, "LastRun", "Last Run", "LastRunTime", "Last Run Time"
                    ),
                    "source_file": row_first(
                        row, "SourceFile", "Source File", "SourceFilename",
                        "Source Filename", "Path", "FullPath",
                    ),
                    **native_row_fields(
                        row,
                        {
                            "native_executable_path": PECMD_EXECUTABLE_PATH_HEADERS,
                            "files_loaded": PECMD_FILES_LOADED_HEADERS,
                            "source_created": ("SourceCreated",),
                            "source_modified": ("SourceModified",),
                            "source_accessed": ("SourceAccessed",),
                            "parsing_error": ("ParsingError",),
                        },
                    ),
                    "executable_name": executable_name,
                    "executable_path": exact_path,
                    "executable_identity_basis": (
                        "ambiguous_referenced_executable_paths"
                        if ambiguous_path
                        else "referenced_executable_path"
                        if exact_path
                        else "executable_basename"
                    ),
                    "row_index": row_index,
                    "candidate_score": score_candidate_name(
                        subject, purpose="prefetch"
                    ),
                    **mft_fields,
                },
                "source_record_ref": f"{csv_path.name}:row={row_index}",
            }
        )
    return parser_run_from_observations(
        parser="PECmd",
        parser_kind="windows_prefetch",
        source_module="PECmd",
        command_needles=("pecmd",),
        normalized_suffix="prefetch",
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        raw_output=csv_path,
        observations=observations,
        coverage_scope=prefetch_coverage_scope(
            collector_run, csv_path=csv_path, record_count=candidate_count
        ),
        additional_raw_outputs=[Path(p) for p in (mft_context or {}).get("source_paths", [])]
            + [Path(p) for p in (mft_context or {}).get("native_volume_source_paths", [])],
        coverage_status=(
            "complete"
            if candidate_count <= MAX_PECMD_PREFETCH_OBSERVATIONS
            and csv_has_required_headers(
                csv_path,
                (
                    "ExecutableName",
                    "Executable Name",
                    "SourceFile",
                    "Source File",
                    "FileName",
                    "Filename",
                    "Path",
                    "FullPath",
                    *PECMD_EXECUTABLE_PATH_HEADERS,
                ),
            )
            else "partial"
        ),
    )


def registry_path_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    mft_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    folded_path = str(csv_path).replace("\\", "/").casefold()
    command_needles: tuple[str, ...]
    if "amcache" in folded_path:
        parser = "AmcacheParser"
        source_module = "AmcacheParser"
        command_needles = ("amcacheparser", "amcache")
        artifact_family = "windows.registry.amcache"
    elif "appcompatcache" in folded_path or "shimcache" in folded_path:
        parser = "AppCompatCacheParser"
        source_module = "AppCompatCacheParser"
        command_needles = ("appcompatcacheparser", "appcompatcache", "shimcache")
        artifact_family = "windows.registry.shimcache"
    else:
        parser = "RECmd"
        source_module = "RegistryPaths"
        command_needles = ("recmd",)
        artifact_family = "windows.registry.shimcache"
    return path_trace_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        mft_context=mft_context,
        parser=parser,
        parser_kind="windows_registry_paths",
        source_module=source_module,
        command_needles=command_needles,
        normalized_suffix="registry_paths",
        artifact_family=artifact_family,
        observation_type=(
            "amcache_path_seen"
            if artifact_family == "windows.registry.amcache"
            else "shimcache_path_seen"
        ),
        coverage_scope_builder=(
            (lambda count: shimcache_coverage_scope(collector_run, csv_path=csv_path, record_count=count))
            if artifact_family == "windows.registry.shimcache"
            else None
        ),
    )


def jump_list_parser_run(
    *,
    csv_path: Path,
    normalized_output_dir: Path,
    collector_run: dict[str, Any],
    mft_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    folded_path = str(csv_path).replace("\\", "/").casefold()
    if "lecmd" in folded_path and "jlecmd" not in folded_path:
        parser = "LECmd"
        source_module = "LECmd"
        command_needles = ("lecmd",)
    else:
        parser = "JLECmd"
        source_module = "JLECmd"
        command_needles = ("jlecmd",)
    return path_trace_parser_run(
        csv_path=csv_path,
        normalized_output_dir=normalized_output_dir,
        collector_run=collector_run,
        mft_context=mft_context,
        parser=parser,
        parser_kind="windows_jump_list",
        source_module=source_module,
        command_needles=command_needles,
        normalized_suffix="jump_list",
        artifact_family="windows.jump_list",
        observation_type="jump_list_path_seen",
    )
