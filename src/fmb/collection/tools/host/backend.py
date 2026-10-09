from __future__ import annotations

import argparse
import importlib.util
import shutil
import sys
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fmb.collection.tools.envelope import (
    ExecutionEnvelopeError,
    build_tool_run_request,
    validate_external_tool_bundle,
)
from fmb.collection.tools.host.bundle import (
    KAPEFILES_LABEL,
    COLLECTOR_OUTPUT_HINT,
    HOST_COLLECTOR_CAPABILITY,
    HOST_COLLECTOR_TOOL,
    METADATA_SCHEMA_VERSION,
    TOOL_LOGS_DIR,
    build_host_result,
    host_execution_environment,
    metadata_binding,
    parser_appliance_authorization,
    parser_appliance_request_args,
    write_host_bundle_documents,
)
from fmb.collection.tools.host.definitions import KapeDefinitionError, KapeDefinitions
from fmb.collection.tools.host.extractor import extract_targets, kape_log_stamp, kape_timestamp
from fmb.collection.tools.host.modules import (
    DATA_ROW_BASIS,
    STATUS_COMPLETED,
    STATUS_COMPLETED_EMPTY_OUTPUT,
    HostModuleError,
    ProcessorRun,
    processor_deferral,
    processor_run_record,
    run_module_processors,
)
from fmb.collection.tools.host.ntfs_index import NtfsIndexError, VolumeIndex
from fmb.collection.tools.host.toolchain import (
    HostToolchain,
    HostToolchainError,
    default_toolchain_root,
    resolve_dotnet,
)
from fmb.collection.tools.kape.paths import BUNDLED_KAPE_TARGETS
from fmb.core.errors import ExternalToolError
from fmb.core.hashing import sha256_file, valid_sha256
from fmb.core.json_io import load_json, write_json
from fmb.core.path_policy import is_portable_relative_path

EXTRACTION_BACKEND_HOST_COLLECTOR = "host-collector"
SBECMD_EXECUTABLE = "SBECmd.exe"
HOST_COLLECTOR_PLATFORM = "windows" if sys.platform == "win32" else "unix_like"
PARSER_APPLIANCE_RUN = "run"
PARSER_APPLIANCE_CHOICES = (PARSER_APPLIANCE_RUN,)
DEFAULT_DRIVE_LETTER = "C"
HOST_COLLECTOR_VALIDATION_SCHEMA = "fmb_host_collector_validation.v1"
HOST_COLLECTOR_SUMMARY_SCHEMA = "fmb_host_collector_extraction_summary.v1"


class HostCollectorError(ExternalToolError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def preflight_host_collector_backend(
    args: argparse.Namespace,
    *,
    which: Callable[[str], str | None] = shutil.which,
    exists: Callable[[Path], bool] | None = None,
) -> dict[str, Any]:
    probe = exists or (lambda path: path.exists())

    def exists(path: Path) -> bool:
        try:
            return bool(probe(path))
        except OSError:
            return False

    missing: list[str] = []
    dotnet = resolve_dotnet(which)
    if not dotnet:
        missing.append("dotnet")
    dependencies = ["pytsk3", "pyvmdk"]
    if getattr(args, "require_registry", True):
        dependencies.append("Registry")
    missing.extend(name for name in dependencies if importlib.util.find_spec(name) is None)
    logfile = None
    if getattr(args, "require_logfile", False):
        from fmb.index.scanners.logfile_runtime import logfile_runtime_availability

        logfile = logfile_runtime_availability()
        if not logfile["available"]:
            missing.append("dfir_ntfs_verified")
    expected_definitions = getattr(args, "expected_definitions_sha256", None)
    selected_modules = getattr(args, "selected_modules", None)
    processors = None
    try:
        definitions = KapeDefinitions()
        definitions_sha256 = definitions.tree_sha256
        if selected_modules is not None:
            processors = definitions.module_processors(selected_modules)
    except KapeDefinitionError:
        definitions_sha256 = None
    if definitions_sha256 is None or (
        expected_definitions and definitions_sha256 != str(expected_definitions).lower()
    ):
        missing.append("kape_definitions_verified")
    parsers_value = getattr(args, "windows_parsers", None)
    parsers_dir = Path(str(parsers_value)).expanduser() if parsers_value else None
    toolchain_root = Path(str(getattr(args, "host_toolchain_root", None) or default_toolchain_root())).expanduser()
    toolchain_report: dict[str, Any] = {"root": str(toolchain_root), "status": "unchecked"}
    from fmb.collection.tools.host.parser_appliance import WINDOWS_PARSERS

    windows = WINDOWS_PARSERS if selected_modules is None else ()
    try:
        toolchain = HostToolchain.load(root=toolchain_root)
        executables = {item.executable for item in processors} if processors is not None else None
        unverified = toolchain.unverified(dotnet=dotnet, executables=executables)
        if processors is not None:
            windows = tuple(dict.fromkeys(item.executable for item in processors
                            if processor_deferral(item, toolchain, frozenset({SBECMD_EXECUTABLE}))[1] is not None))
        toolchain_report = {
            "root": str(toolchain.root),
            "lock_path": str(toolchain.lock_path),
            "lock_sha256": toolchain.lock_sha256,
            "status": "verified" if not unverified else "unverified",
            "unverified": unverified,
            "tool_count": (len(toolchain.bindings()) if executables is None else
                           sum(toolchain.binding_for(name) is not None and toolchain.binding_for(name).host_runnable
                               for name in executables)),
            **({"required_executables": sorted(executables)} if executables is not None else {}),
        }
        if unverified:
            missing.append("host_toolchain_verified")
    except HostToolchainError as error:
        toolchain_report = {"root": str(toolchain_root), "status": "missing", "error": str(error)}
        missing.append("host_toolchain_lock")
    provider = getattr(args, "collection_provider", "vmware_desktop")
    if windows and provider == "vmware_desktop" and not which("vmrun") and not exists(
        Path("/Applications/VMware Fusion.app/Contents/Public/vmrun")
    ):
        missing.append("vmrun")
    if windows and provider == "qemu":
        from fmb.generation.backends import QemuBackend

        tools = QemuBackend.discover_tools()
        missing.extend(name for name in ("qemu-system", "qemu-img", "ansible") if not tools[name])
    if windows and parsers_dir is None:
        missing.append("windows_parsers")
    elif windows:
        from fmb.collection.tools.host.parser_appliance import (
            ParserApplianceError,
            windows_parser_binary,
        )

        for executable in windows:
            try:
                windows_parser_binary(parsers_dir, executable)
            except ParserApplianceError:
                missing.append("windows_parser_validated:" + executable)
    return {
        "backend": EXTRACTION_BACKEND_HOST_COLLECTOR,
        "available": not missing,
        "missing": missing,
        "dotnet": dotnet,
        "kape_definitions_sha256": definitions_sha256,
        "windows_parsers": str(parsers_dir) if parsers_dir else None,
        "host_toolchain": toolchain_report,
        **({"logfile": logfile} if logfile is not None else {}),
        "parser_appliance_mode": PARSER_APPLIANCE_RUN,
        "auto_selectable": False,
    }


class _PhaseClock:
    def __init__(self) -> None:
        self.timings: list[dict[str, Any]] = []

    def run(self, phase: str, callback):
        started = _utc_now()
        start = time.monotonic()
        status = "failed"
        try:
            value = callback()
            status = "completed"
            return value
        finally:
            self.timings.append(
                {
                    "phase": phase,
                    "status": status,
                    "started_at": started.isoformat(),
                    "ended_at": _utc_now().isoformat(),
                    "duration_seconds": round(time.monotonic() - start, 3),
                }
            )


def _host_command_lines(
    *, evidence: Path, targets_root: Path, modules_root: Path, targets: str, modules: str
) -> tuple[str, str, list[str]]:
    target_argv = [
        HOST_COLLECTOR_TOOL, "targets", "--evidence", str(evidence),
        "--tdest", str(targets_root), "--target", targets,
    ]
    module_argv = [
        HOST_COLLECTOR_TOOL, "modules", "--msource", str(targets_root),
        "--mdest", str(modules_root), "--module", modules,
    ]
    target_line = " ".join(target_argv)
    module_line = " ".join(module_argv)
    return target_line, module_line, [*target_argv, *module_argv]


def run_host_collector_extraction(
    *,
    args: argparse.Namespace,
    stage_dir: Path,
    extracted_dir: Path,
    targets: list[str],
    modules: list[str],
    question_id: str,
    question_text: str,
    evidence_sha256: str,
    run_id: str,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    if extracted_dir.exists():
        raise HostCollectorError(f"refusing to overwrite existing extracted bundle: {extracted_dir}")
    evidence = Path(str(args.evidence)).expanduser().resolve()
    expected_definitions = getattr(args, "expected_definitions_sha256", None)
    drive_letter = DEFAULT_DRIVE_LETTER
    clock = _PhaseClock()
    log_lines: list[str] = []

    def log(message: str) -> None:
        line = f"{_utc_now().isoformat()} {message}"
        log_lines.append(line)
        if progress is not None:
            progress(line)

    extracted_dir.mkdir(parents=True)
    output_root = extracted_dir / COLLECTOR_OUTPUT_HINT
    targets_root = output_root / "targets"
    modules_root = output_root / "modules"
    tool_logs = extracted_dir / TOOL_LOGS_DIR
    tool_logs.mkdir(parents=True, exist_ok=True)
    targets_csv = ",".join(targets)
    modules_csv = ",".join(modules)
    target_line, module_line, argv = _host_command_lines(
        evidence=evidence, targets_root=targets_root, modules_root=modules_root,
        targets=targets_csv, modules=modules_csv,
    )
    command_line = f"target: {target_line}; module: {module_line}"
    started = _utc_now()

    def load_definitions() -> KapeDefinitions:
        definitions = KapeDefinitions(bundled_targets=BUNDLED_KAPE_TARGETS)
        if expected_definitions and definitions.tree_sha256 != str(expected_definitions).lower():
            raise HostCollectorError(
                "KapeFiles definitions differ from the collection declaration: "
                f"expected {expected_definitions} observed {definitions.tree_sha256}"
            )
        return definitions

    try:
        definitions = clock.run("load_kape_definitions", load_definitions)
        rules = definitions.target_rules(targets)
        processors = definitions.module_processors(modules)
        log(f"definitions {definitions.tree_sha256[:12]}: {len(rules)} target rules, {len(processors)} processors")

        toolchain_root = Path(str(getattr(args, "host_toolchain_root", None) or default_toolchain_root()))
        toolchain = clock.run("load_toolchain", lambda: HostToolchain.load(root=toolchain_root))
        dotnet = resolve_dotnet()
        if not dotnet:
            raise HostCollectorError("dotnet runtime is required to run the host parsers")
        executables = ({item.executable for item in processors}
                       if getattr(args, "selected_modules", None) is not None else None)
        verification = clock.run("verify_toolchain", lambda: toolchain.verify(dotnet=dotnet, executables=executables))
        unverified = [row for row in verification if row["status"] != "verified"]
        if unverified:
            raise HostCollectorError(f"host toolchain differs from its lock: {unverified}")
        windows_only_modules = _windows_only_modules(processors, toolchain)
        extra_args = parser_appliance_request_args(PARSER_APPLIANCE_RUN, windows_only_modules)
        request = build_tool_run_request(
            question_id=question_id,
            question_text=question_text,
            collector="kape",
            run_id=run_id,
            collector_config={
                "source": f"{drive_letter}:\\",
                "output": COLLECTOR_OUTPUT_HINT,
                "targets": targets_csv,
                "modules": modules_csv,
                "extra_args": extra_args,
            },
            source_evidence_sha256=evidence_sha256,
            request_id=f"{run_id}:{EXTRACTION_BACKEND_HOST_COLLECTOR}",
            expected_platform=HOST_COLLECTOR_PLATFORM,
            expected_tool=HOST_COLLECTOR_TOOL,
            required_capability=HOST_COLLECTOR_CAPABILITY,
        )
        request_path = stage_dir / "tool_run_request.json"
        write_json(request_path, request)

        index = clock.run("index_volume", lambda: VolumeIndex(evidence, progress=log))
        log(f"volume at byte {index.partition_offset}: {len(index.entries)} in-use records")
        extraction = clock.run(
            "extract_targets",
            lambda: extract_targets(
                index, rules, output_root=output_root, drive_letter=drive_letter,
                command_line=target_line,
            ),
        )
        log(f"extracted {len(extraction.copied)} files, skipped {len(extraction.skipped)}")
        module_runs: list[ProcessorRun] = clock.run(
            "run_modules",
            lambda: run_module_processors(
                processors,
                toolchain=toolchain,
                dotnet=dotnet,
                targets_root=targets_root,
                modules_root=modules_root,
                tool_logs_dir=tool_logs,
                progress=log,
                skip_executables=frozenset({SBECMD_EXECUTABLE}),
            ),
        )
        appliance_record = clock.run(
            "parser_appliance",
            lambda: _run_windows_only_processors(
                processors, module_runs, mode=PARSER_APPLIANCE_RUN, args=args, stage_dir=stage_dir,
                targets_root=targets_root, modules_root=modules_root, tool_logs=tool_logs,
                progress=log,
            ),
        )
        module_console = modules_root / f"{kape_log_stamp(started)}_ConsoleLog.txt"
        modules_root.mkdir(parents=True, exist_ok=True)
        module_console.write_text(
            "\n".join(
                [
                    f"[{kape_timestamp(_utc_now())} | INF] {HOST_COLLECTOR_TOOL} module phase",
                    f"[{kape_timestamp(_utc_now())} | INF] Command line: {module_line}",
                    *(
                        f"[{run.started_at} | INF] {run.status}: {run.module_name} -> {run.command_line}"
                        for run in module_runs
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        ended = _utc_now()
        stdout_path = tool_logs / "host-collector.stdout.txt"
        stderr_path = tool_logs / "host-collector.stderr.txt"
        stdout_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        toolchain_record = toolchain.describe(verification=verification)
        if executables is not None:
            toolchain_record["required_executables"] = sorted(executables)
        environment = host_execution_environment(
            definitions_sha256=definitions.tree_sha256,
            toolchain=toolchain_record,
            source_hash_basis=(
                "evidence hashed by the host pipeline before extraction; the image was "
                "opened read-only through The Sleuth Kit (a VMDK through libvmdk) and never written"
            ),
        )
        result = build_host_result(
            request=request,
            request_path=request_path,
            evidence_path=evidence,
            evidence_sha256=evidence_sha256,
            evidence_id=None,
            drive_letter=drive_letter,
            targets=targets_csv,
            modules=modules_csv,
            command_line=command_line,
            argv=argv,
            started_at=started.isoformat(),
            ended_at=ended.isoformat(),
            duration_seconds=round((ended - started).total_seconds(), 3),
            stdout_relative=f"{TOOL_LOGS_DIR}/host-collector.stdout.txt",
            stdout_sha256=sha256_file(stdout_path),
            stderr_relative=f"{TOOL_LOGS_DIR}/host-collector.stderr.txt",
            stderr_sha256=sha256_file(stderr_path),
            execution_environment=environment,
            definitions_sha256=definitions.tree_sha256,
            exit_code=0,
            extra_args=extra_args,
        )
        metadata = {
            "evidence": {"path": str(evidence), "sha256": evidence_sha256},
            "definitions": {
                "source": KAPEFILES_LABEL,
                "sha256": definitions.tree_sha256,
                "targets": targets,
                "modules": modules,
                "target_rule_count": len(rules),
                "processors": [
                    {
                        "module": item.module_name, "requested_module": item.requested_module,
                        "definition": item.definition, "category": item.category,
                        "executable": item.executable, "command_line": item.command_line,
                        "file_mask": item.file_mask,
                    }
                    for item in processors
                ],
            },
            "volume": {
                "partition_offset_bytes": index.partition_offset,
                "geometry": index.geometry,
                "in_use_record_count": len(index.entries),
                "drive_letter": drive_letter,
            },
            "extraction": {
                "copied": len(extraction.copied),
                "skipped": len(extraction.skipped),
                "skipped_reasons": _count_reasons(extraction.skipped),
                "logs": {key: path.relative_to(extracted_dir).as_posix() for key, path in extraction.log_files.items()},
                "started_at": extraction.started_at,
                "ended_at": extraction.ended_at,
            },
            "module_runs": [processor_run_record(run) for run in module_runs],
            "parser_appliance": appliance_record,
            "parser_appliance_request": {
                "mode": PARSER_APPLIANCE_RUN,
                "windows_only_modules": windows_only_modules,
                "extra_args": extra_args,
            },
            "toolchain": toolchain_record,
            "phase_timings": clock.timings,
            "command": {"command_line": command_line, "argv": argv},
        }
        documents = write_host_bundle_documents(
            bundle_dir=extracted_dir, request=request, request_path=request_path,
            result=result, metadata=metadata,
        )
    except (KapeDefinitionError, NtfsIndexError, HostModuleError, HostToolchainError, ExecutionEnvelopeError) as error:
        raise HostCollectorError(str(error)) from error
    summary = {
        "schema_version": HOST_COLLECTOR_SUMMARY_SCHEMA,
        "status": "completed",
        "backend": EXTRACTION_BACKEND_HOST_COLLECTOR,
        "host_bundle": None,
        "host_validation": None,
        "bundle_extracted": str(extracted_dir),
        "source_image_path": str(evidence),
        "definitions_sha256": definitions.tree_sha256,
        "toolchain_lock_sha256": toolchain.lock_sha256,
        "parser_appliance_mode": PARSER_APPLIANCE_RUN,
        "documents": {key: str(path) for key, path in documents.items()},
        "phase_timings": clock.timings,
        "data_row_basis": DATA_ROW_BASIS,
        "module_runs": [_module_run_summary(run) for run in module_runs],
        "empty_output_modules": [
            run.module_name for run in module_runs if run.status == STATUS_COMPLETED_EMPTY_OUTPUT
        ],
    }
    write_json(stage_dir / "host-collector-extraction-summary.json", summary)
    return summary


def _module_run_summary(run: ProcessorRun) -> dict[str, Any]:
    return {
        "module": run.module_name,
        "tool": run.tool_name,
        "status": run.status,
        "exit_code": run.exit_code,
        "input_file_count": run.input_file_count,
        "input_byte_count": run.input_byte_count,
        "output_count": len(run.outputs),
        "data_row_count": run.data_row_count,
        "detail": run.detail,
    }


def _count_reasons(skipped) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in skipped:
        counts[item.reason] = counts.get(item.reason, 0) + 1
    return counts


def _windows_only_modules(processors, toolchain: HostToolchain) -> list[str]:
    names: list[str] = []
    for item in processors:
        deferred = processor_deferral(item, toolchain, frozenset({SBECMD_EXECUTABLE}))[1]
        if deferred is not None and item.module_name not in names:
            names.append(item.module_name)
    return names


def _run_windows_only_processors(
    processors,
    module_runs: list[ProcessorRun],
    *,
    mode: str,
    args: argparse.Namespace,
    stage_dir: Path,
    targets_root: Path,
    modules_root: Path,
    tool_logs: Path,
    progress: Callable[[str], None],
) -> dict[str, Any]:
    deferred = {run.module_name for run in module_runs if run.status == "deferred"}
    pending = [item for item in processors if item.module_name in deferred]
    if not pending:
        return {"mode": mode, "status": "not_requested", "modules": []}
    from fmb.collection.tools.host.parser_appliance import run_parser_appliance

    return run_parser_appliance(
        processors=pending,
        args=args,
        stage_dir=stage_dir,
        targets_root=targets_root,
        modules_root=modules_root,
        tool_logs=tool_logs,
        progress=progress,
    )


def validate_host_collector_bundle(
    *,
    request_path: Path,
    result_path: Path,
    manifest_path: Path,
    collector_output_root: Path,
    metadata_path: Path | None = None,
    required_artifact_globs: list[str] | None = None,
) -> dict[str, Any]:
    from fmb.collection.tools.host.validation import (
        KapeApplianceError,
        assert_no_appliance_metadata_contamination,
        assert_required_kape_artifacts,
    )
    from fmb.collection.tools.kape.validation.usn import build_mftecmd_usn_row_validation_checks

    try:
        verified = validate_external_tool_bundle(
            request_path=request_path,
            result_path=result_path,
            manifest_path=manifest_path,
            collector_output_root=collector_output_root,
            require_source_hash_verified=True,
        )
    except ExecutionEnvelopeError as error:
        raise HostCollectorError(str(error)) from error
    result = verified["result"]
    checks: list[dict[str, Any]] = [{"check_id": "external_tool_bundle_contract", "status": "pass"}]
    if result["tool_identity"].get("name") != HOST_COLLECTOR_TOOL:
        raise HostCollectorError("bundle was not produced by the host collector")
    checks.append({"check_id": "host_collector_tool_identity", "status": "pass"})
    source = result["source_evidence"]
    if source.get("read_only_asserted") is not True or source.get("hash_verified") is not True:
        raise HostCollectorError("host collector result must assert read-only, hash-verified evidence")
    checks.append({"check_id": "read_only_asserted", "status": "pass"})
    checks.append({"check_id": "source_hash_verified", "status": "pass"})

    binding = metadata_binding(result)
    if binding is None:
        raise HostCollectorError("host collector result does not bind its metadata record")
    if not is_portable_relative_path(binding["path"]) or not valid_sha256(binding["sha256"]):
        raise HostCollectorError("host collector metadata binding is malformed")
    metadata_file = (metadata_path or (result_path.parent / binding["path"])).expanduser()
    if not metadata_file.is_file():
        raise HostCollectorError(f"host collector metadata is missing: {metadata_file}")
    observed_metadata_sha256 = sha256_file(metadata_file)
    if observed_metadata_sha256 != binding["sha256"]:
        raise HostCollectorError(
            "host collector metadata does not match the hash bound in the result: "
            f"expected {binding['sha256']} observed {observed_metadata_sha256}"
        )
    checks.append(
        {"check_id": "host_metadata_hash_bound", "status": "pass", "sha256": observed_metadata_sha256}
    )
    metadata = load_json(metadata_file)
    if not isinstance(metadata, dict) or metadata.get("schema_version") != METADATA_SCHEMA_VERSION:
        raise HostCollectorError("host collector metadata schema is unsupported")
    module_runs = [run for run in metadata.get("module_runs", []) if isinstance(run, dict)]
    accepted_statuses = {
        STATUS_COMPLETED, STATUS_COMPLETED_EMPTY_OUTPUT, "deferred", "no_source_files",
    }
    failed = [run for run in module_runs if run.get("status") not in accepted_statuses]
    if failed:
        raise HostCollectorError("host collector metadata records a failed processor run")
    checks.append({"check_id": "host_processor_exit_codes", "status": "pass"})
    empty_runs = [run for run in module_runs if run.get("status") == STATUS_COMPLETED_EMPTY_OUTPUT]
    appliance = metadata.get("parser_appliance")
    empty_appliance = (
        [str(name) for name in appliance.get("empty_output_modules") or []]
        if isinstance(appliance, dict) else []
    )
    empty_check: dict[str, Any] = {
        "check_id": "host_processor_empty_outputs",
        "status": "warn" if empty_runs or empty_appliance else "pass",
        "modules": [str(run.get("module")) for run in empty_runs] + empty_appliance,
        "outputs": [str(item) for run in empty_runs for item in (run.get("outputs") or [])],
    }
    if empty_runs or empty_appliance:
        empty_check["message"] = (
            "host processors exited 0 on non-empty input but wrote no CSV data row; "
            "their outputs are recorded as empty and certify no coverage"
        )
    checks.append(empty_check)
    toolchain = metadata.get("toolchain", {})
    if not isinstance(toolchain, dict) or not toolchain.get("lock_sha256"):
        raise HostCollectorError("host collector metadata lacks a toolchain lock identity")
    checks.append({"check_id": "host_toolchain_pinned", "status": "pass"})

    authorization = parser_appliance_authorization(verified["request"])
    requested_mode = authorization["mode"]
    if requested_mode not in PARSER_APPLIANCE_CHOICES:
        raise HostCollectorError("execution request does not declare a parser appliance mode")
    if not isinstance(appliance, dict):
        raise HostCollectorError("host collector metadata lacks a parser appliance record")
    if appliance.get("mode") != requested_mode:
        raise HostCollectorError(
            "parser appliance mode differs between request and execution: "
            f"requested {requested_mode} executed {appliance.get('mode')}"
        )
    appliance_status = appliance.get("status")
    appliance_modules = [str(item) for item in appliance.get("modules") or []]
    if appliance_status not in {"completed", "not_requested"}:
        raise HostCollectorError(f"parser appliance status is not acceptable: {appliance_status}")
    checks.append(
        {
            "check_id": "parser_appliance",
            "status": "pass",
            "mode": appliance.get("mode"),
            "modules": appliance_modules,
            "requested_mode": requested_mode,
            "requested_modules": list(authorization["modules"]),
        }
    )
    output_root = verified["collector_output_root"]
    effective_globs = list(required_artifact_globs or [])
    try:
        assert_no_appliance_metadata_contamination(output_root, checks=checks)
        checks.extend(
            build_mftecmd_usn_row_validation_checks(
                output_root,
                requested_modules=[
                    part.strip()
                    for part in str(result.get("executed_collection", {}).get("modules") or "").split(",")
                    if part.strip()
                ],
            )
        )
        assert_required_kape_artifacts(output_root, effective_globs, checks=checks)
    except KapeApplianceError as error:
        raise HostCollectorError(str(error)) from error
    return {
        "schema_version": HOST_COLLECTOR_VALIDATION_SCHEMA,
        "status": "passed",
        "request_id": str(verified["request"]["request_id"]),
        "run_id": str(verified["request"]["run_id"]),
        "checks": checks,
        "execution_envelope": verified["execution_envelope"],
        "appliance_metadata": None,
        "host_validation_metadata": None,
        "host_collector_metadata": metadata,
    }


__all__ = [
    "DEFAULT_DRIVE_LETTER",
    "EXTRACTION_BACKEND_HOST_COLLECTOR",
    "HostCollectorError",
    "PARSER_APPLIANCE_RUN",
    "PARSER_APPLIANCE_CHOICES",
    "preflight_host_collector_backend",
    "run_host_collector_extraction",
    "validate_host_collector_bundle",
]
