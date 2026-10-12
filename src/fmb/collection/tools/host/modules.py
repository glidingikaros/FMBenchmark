from __future__ import annotations

import csv
import fnmatch
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from fmb.collection.tools.host.definitions import ModuleProcessor, split_file_masks
from fmb.collection.tools.host.toolchain import HostToolchain, ToolBinding
from fmb.core.hashing import sha256_file
from fmb.core.processes import decoded_process_output

DEFAULT_PROCESSOR_TIMEOUT_SECONDS = 1800
TELEMETRY_BLOCKING_PROXY = "http://127.0.0.1:9"
STATUS_COMPLETED = "completed"
STATUS_COMPLETED_EMPTY_OUTPUT = "completed_empty_output"
DATA_ROW_BASIS = "csv reader rows after the header line; quoted newlines stay inside their row"
_CSV_FIELD_SIZE_LIMIT = 1 << 30
# EZ tools prefix their outputs with the run time (yyyyMMddHHmmss_); RECmd also puts plugin outputs in a folder named so.
RUN_STAMP_PREFIX = re.compile(r"^\d{14}_")
RUN_STAMP_FOLDER = re.compile(r"\d{14}")
RECMD_PLUGIN_FOLDER = "Plugins"
# RECmd's own hive masks, in its order; it searches them in parallel, so its rows come in a different order each run.
RECMD_HIVE_MASKS = ("*usrclass.dat", "*user.dat", "*system", "*sam", "*software", "*default", "*amcache.hve",
                    "*syscache.hve", "*security", "*drivers", "*components", "*userclasses.dat", "*settings.dat",
                    "*registry.dat")
# LECmd and JLECmd make -d absolute (Path.GetFullPath) and report the host copy's own file times, so these columns
# name the run folder and the time of extraction; they are rewritten to the bundle path and the image's NTFS times.
SOURCE_COLUMN_TOOLS = frozenset({"lecmd", "jlecmd"})
SOURCE_TIME_COLUMNS = (("SourceCreated", "created"), ("SourceModified", "modified"), ("SourceAccessed", "accessed"))


class HostModuleError(RuntimeError):
    pass


@dataclass(slots=True)
class ProcessorRun:
    module_name: str
    requested_module: str
    executable: str
    tool_name: str | None
    category: str
    argv: list[str]
    command_line: str
    working_directory: str | None
    source_file: str | None
    started_at: str
    ended_at: str = ""
    duration_seconds: float = 0.0
    exit_code: int | None = None
    status: str = "pending"
    stdout_path: str | None = None
    stderr_path: str | None = None
    console_log_relative_path: str | None = None
    outputs: list[str] = field(default_factory=list)
    detail: str | None = None
    input_file_count: int = 0
    input_byte_count: int = 0
    data_row_count: int = 0
    data_row_counts: dict[str, int] = field(default_factory=dict)
    rewritten_outputs: dict[str, str] = field(default_factory=dict)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(value: datetime) -> str:
    return value.strftime("%Y%m%d%H%M%S%f")[:-1]


def processor_environment() -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "DOTNET_ROLL_FORWARD": "Major",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            "DOTNET_NOLOGO": "1",
            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
            "HTTP_PROXY": TELEMETRY_BLOCKING_PROXY,
            "HTTPS_PROXY": TELEMETRY_BLOCKING_PROXY,
            "ALL_PROXY": TELEMETRY_BLOCKING_PROXY,
            "NO_PROXY": "",
            "LC_ALL": "en_US.UTF-8",
            "LANG": "en_US.UTF-8",
        }
    )
    return env


def matching_source_files(targets_root: Path, file_mask: str) -> list[Path]:
    masks = [mask.casefold() for mask in split_file_masks(file_mask)]
    matches: list[Path] = []
    for path in sorted(targets_root.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.casefold()
        if any(fnmatch.fnmatchcase(name, mask) for mask in masks):
            matches.append(path)
    return matches


def render_arguments(
    command_line: str,
    *,
    source_directory: Path,
    destination_directory: Path,
    source_file: Path | None,
    tool_directory: Path,
) -> list[str]:
    rendered: list[str] = []
    for token in command_line.split():
        lowered = token.casefold()
        if lowered == "%sourcefile%":
            if source_file is None:
                raise HostModuleError("processor uses %sourceFile% without a FileMask")
            rendered.append(str(source_file))
        elif lowered == "%sourcedirectory%":
            rendered.append(str(source_directory))
        elif lowered == "%destinationdirectory%":
            rendered.append(str(destination_directory))
        elif lowered == "%kapedirectory%":
            rendered.append(str(tool_directory))
        elif "%" in token:
            raise HostModuleError(f"unsupported KAPE variable in command line: {token}")
        elif "\\" in token and not token.startswith("-"):
            rendered.append(str(tool_directory / token.replace("\\", "/")))
        else:
            rendered.append(token)
    return rendered


def _snapshot(directory: Path) -> set[Path]:
    if not directory.exists():
        return set()
    return {path for path in directory.rglob("*") if path.is_file()}


def csv_data_row_count(path: Path) -> int:
    csv.field_size_limit(_CSV_FIELD_SIZE_LIMIT)
    rows = 0
    header_seen = False
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for record in csv.reader(handle):
            if not any(cell.strip() for cell in record):
                continue
            if not header_seen:
                header_seen = True
                continue
            rows += 1
    return rows


def targets_inventory(targets_root: Path) -> tuple[int, int]:
    if not targets_root.is_dir():
        return 0, 0
    file_count = 0
    byte_count = 0
    for path in targets_root.rglob("*"):
        if not path.is_file() or len(path.relative_to(targets_root).parts) < 2:
            continue
        file_count += 1
        byte_count += path.stat().st_size
    return file_count, byte_count


def processor_deferral(
    processor: ModuleProcessor, toolchain: HostToolchain, skip_executables: frozenset[str]
) -> tuple[ToolBinding | None, str | None]:
    executable_key = processor.executable.replace("/", "\\").casefold()
    if executable_key in {item.casefold() for item in skip_executables}:
        return None, "executable handled outside the host toolchain"
    binding = toolchain.binding_for(processor.executable)
    if binding is not None and not binding.host_runnable:
        return binding, binding.host_runnable_note or "executable is not runnable on this host"
    return binding, None


def _unexecuted_run(
    processor: ModuleProcessor,
    *,
    status: str,
    detail: str,
    tool_name: str | None = None,
    working_directory: str | None = None,
) -> ProcessorRun:
    return ProcessorRun(
        module_name=processor.module_name,
        requested_module=processor.requested_module,
        executable=processor.executable,
        tool_name=tool_name,
        category=processor.category,
        argv=[],
        command_line=processor.command_line,
        working_directory=working_directory,
        source_file=None,
        started_at=_utc_now().isoformat(),
        status=status,
        detail=detail,
    )


def run_module_processors(
    processors: list[ModuleProcessor],
    *,
    toolchain: HostToolchain,
    dotnet: str,
    targets_root: Path,
    modules_root: Path,
    tool_logs_dir: Path,
    timeout_seconds: int = DEFAULT_PROCESSOR_TIMEOUT_SECONDS,
    progress: Callable[[str], None] | None = None,
    skip_executables: frozenset[str] = frozenset(),
    after_processor: Callable[[ModuleProcessor], None] | None = None,
) -> list[ProcessorRun]:
    # after_processor gets each processor that ran, once its outputs are written.
    targets_root, modules_root, tool_logs_dir = (
        targets_root.absolute(), modules_root.absolute(), tool_logs_dir.absolute()
    )
    modules_root.mkdir(parents=True, exist_ok=True)
    tool_logs_dir.mkdir(parents=True, exist_ok=True)
    env = processor_environment()
    directory_inventory = targets_inventory(targets_root)
    runs: list[ProcessorRun] = []
    for processor in processors:
        binding, deferred = processor_deferral(processor, toolchain, skip_executables)
        if deferred is not None:
            runs.append(
                _unexecuted_run(
                    processor,
                    status="deferred",
                    detail=deferred,
                    tool_name=binding.tool_name if binding is not None else None,
                )
            )
            continue
        if binding is None:
            raise HostModuleError(
                f"module {processor.module_name} needs {processor.executable}, "
                "which the host toolchain lock does not bind"
            )
        destination = modules_root / processor.category
        destination.mkdir(parents=True, exist_ok=True)
        if processor.file_mask:
            sources: list[Path | None] = list(matching_source_files(targets_root, processor.file_mask))
            if not sources:
                runs.append(
                    _unexecuted_run(
                        processor,
                        status="no_source_files",
                        detail=f"no file under targets matches {processor.file_mask}",
                        tool_name=binding.tool_name,
                        working_directory=str(binding.working_directory),
                    )
                )
                continue
        else:
            sources = [None]
        for source in sources:
            runs.append(
                _run_processor(
                    processor,
                    binding,
                    dotnet=dotnet,
                    env=env,
                    targets_root=targets_root,
                    destination=destination,
                    modules_root=modules_root,
                    source_file=source,
                    tool_logs_dir=tool_logs_dir,
                    timeout_seconds=timeout_seconds,
                    progress=progress,
                    input_inventory=(
                        (1, source.stat().st_size) if source is not None else directory_inventory
                    ),
                )
            )
        if after_processor is not None:
            after_processor(processor)
    return runs


def _run_processor(
    processor: ModuleProcessor,
    binding: ToolBinding,
    *,
    dotnet: str,
    env: dict[str, str],
    targets_root: Path,
    destination: Path,
    modules_root: Path,
    source_file: Path | None,
    tool_logs_dir: Path,
    timeout_seconds: int,
    progress: Callable[[str], None] | None,
    input_inventory: tuple[int, int] = (0, 0),
) -> ProcessorRun:
    # The tools run in the collector output root on relative paths, so the paths they write into their CSVs
    # (MFTECmd's SourceFile, RECmd's HivePath) name no host folder.
    bundle_root = modules_root.parent
    paths = {
        "source_directory": _bundle_relative(targets_root, bundle_root),
        "destination_directory": _bundle_relative(destination, bundle_root),
        "source_file": _bundle_relative(source_file, bundle_root) if source_file is not None else None,
    }
    arguments = render_arguments(processor.command_line, **paths, tool_directory=binding.working_directory)
    # The console log names a tool's own files as its module does, relative to the tool, so it names no host folder.
    shown = render_arguments(processor.command_line, **paths, tool_directory=PurePosixPath())
    argv = [dotnet, str(binding.entry_assembly), *arguments]
    started = _utc_now()
    label = f"{binding.tool_name}-{_stamp(started)}"
    stdout_path = tool_logs_dir / f"{label}.stdout.txt"
    stderr_path = tool_logs_dir / f"{label}.stderr.txt"
    before = _snapshot(destination)
    run = ProcessorRun(
        module_name=processor.module_name,
        requested_module=processor.requested_module,
        executable=processor.executable,
        tool_name=binding.tool_name,
        category=processor.category,
        argv=argv,
        command_line=" ".join(argv),
        working_directory=str(bundle_root),
        source_file=str(source_file) if source_file is not None else None,
        started_at=started.isoformat(),
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        input_file_count=input_inventory[0],
        input_byte_count=input_inventory[1],
    )
    if progress is not None:
        progress(f"running {binding.tool_name}: {' '.join(arguments)}")
    try:
        completed = subprocess.run(
            argv,
            cwd=bundle_root,
            env=env,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        stdout_path.write_text(decoded_process_output(error.stdout), encoding="utf-8")
        stderr_path.write_text(decoded_process_output(error.stderr), encoding="utf-8")
        raise HostModuleError(
            f"{binding.tool_name} exceeded {timeout_seconds}s for module {processor.module_name}"
        ) from error
    ended = _utc_now()
    stdout_path.write_text(completed.stdout or "", encoding="utf-8")
    stderr_path.write_text(completed.stderr or "", encoding="utf-8")
    console = destination / f"{label}.console.log"
    console.write_text(
        f"Command line: {' '.join(shown)}\n\n{completed.stdout or ''}",
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise HostModuleError(
            f"{binding.tool_name} exited {completed.returncode} for module "
            f"{processor.module_name}; see {stderr_path}"
        )
    if binding.tool_name.casefold() == "recmd":
        flatten_recmd_outputs(destination, created_before=before)
    strip_run_stamps(destination, created_before=before)
    if binding.tool_name.casefold() == "recmd":
        run.rewritten_outputs = canonical_recmd_batches(destination, created_before=before, bundle_root=bundle_root)
    elif binding.tool_name.casefold() in SOURCE_COLUMN_TOOLS:
        from fmb.collection.tools.host.parser_appliance import copy_log_source_times

        run.rewritten_outputs = canonical_source_columns(
            destination, created_before=before, bundle_root=bundle_root,
            source_times=copy_log_source_times(targets_root),
        )
    run.console_log_relative_path = console.relative_to(modules_root.parent).as_posix()
    run.ended_at = ended.isoformat()
    run.duration_seconds = (ended - started).total_seconds()
    run.exit_code = completed.returncode
    run.outputs = sorted(
        path.relative_to(modules_root.parent).as_posix()
        for path in _snapshot(destination) - before
        if path != console
    )
    run.status = STATUS_COMPLETED
    record_data_rows(run, binding.tool_name, bundle_root=modules_root.parent)
    return run


def record_data_rows(run: ProcessorRun, tool_name: str, *, bundle_root: Path) -> None:
    run.data_row_counts = {
        relative: csv_data_row_count(bundle_root / relative)
        for relative in run.outputs
        if relative.casefold().endswith(".csv")
    }
    run.data_row_count = sum(run.data_row_counts.values())
    if run.input_byte_count > 0 and run.data_row_count == 0:
        run.status = STATUS_COMPLETED_EMPTY_OUTPUT
        run.detail = (
            f"{tool_name} exited 0 on {run.input_file_count} non-empty input file(s) "
            f"totalling {run.input_byte_count} bytes but wrote no CSV data row "
            f"({len(run.data_row_counts)} CSV output(s)); the output certifies no coverage"
        )


def flatten_recmd_outputs(destination: Path, *, created_before: set[Path]) -> None:
    for path in sorted(destination.rglob("*.csv"), key=lambda item: len(item.parts), reverse=True):
        if path in created_before or not path.is_file():
            continue
        relative = path.relative_to(destination)
        if len(relative.parts) <= 2:
            continue
        batch_dir = destination / relative.parts[0]
        flattened = batch_dir / "_".join(relative.parts[1:])
        if flattened.exists():
            continue
        path.rename(flattened)
        parent = path.parent
        while parent != batch_dir and parent != destination:
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent


def _bundle_relative(path: Path, bundle_root: Path) -> PurePosixPath:
    return PurePosixPath(path.relative_to(bundle_root).as_posix())


def _unused(path: Path) -> Path:
    candidate, number = path, 1
    while candidate.exists():
        number += 1
        candidate = path.with_name(f"{path.stem}-{number}{path.suffix}")
    return candidate


def strip_run_stamps(destination: Path, *, created_before: set[Path]) -> None:
    for path in sorted(_snapshot(destination) - created_before):
        parts = path.relative_to(destination).parts
        folders = [RECMD_PLUGIN_FOLDER if RUN_STAMP_FOLDER.fullmatch(part) else part for part in parts[:-1]]
        target = destination.joinpath(*folders, RUN_STAMP_PREFIX.sub("", parts[-1], count=1))
        if target == path:
            continue
        target = _unused(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        path.rename(target)
    for folder in sorted(destination.iterdir()):
        if folder.is_dir() and RUN_STAMP_FOLDER.fullmatch(folder.name) and not any(folder.iterdir()):
            folder.rmdir()


def _hive_order(hive_path: str) -> tuple[int, str]:
    normalized = hive_path.replace("\\", "/").casefold()
    name = normalized.rpartition("/")[2]
    rank = next((rank for rank, mask in enumerate(RECMD_HIVE_MASKS) if fnmatch.fnmatchcase(name, mask)),
                len(RECMD_HIVE_MASKS))
    return rank, normalized


def _plugin_detail_file(value: str, folder: str) -> str:
    parts = value.replace("\\", "/").split("/")
    stamps = [index for index, part in enumerate(parts[:-1]) if RUN_STAMP_FOLDER.fullmatch(part)]
    if not stamps:
        return value
    name = RUN_STAMP_PREFIX.sub("", "_".join(parts[stamps[-1] + 1:]), count=1)
    return f"{folder}/{RECMD_PLUGIN_FOLDER}/{name}"


def canonical_recmd_batch(path: Path, *, folder: str) -> None:
    csv.field_size_limit(_CSV_FIELD_SIZE_LIMIT)
    with path.open("r", encoding="utf-8-sig", errors="surrogateescape", newline="") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        return
    header, records = rows[0], rows[1:]
    if "HivePath" in header:
        column = header.index("HivePath")
        records.sort(key=lambda row: _hive_order(row[column] if column < len(row) else ""))
    if "PluginDetailFile" in header:
        column = header.index("PluginDetailFile")
        for row in records:
            if column < len(row):
                row[column] = _plugin_detail_file(row[column], folder)
    with path.open("w", encoding="utf-8-sig", errors="surrogateescape", newline="") as handle:
        csv.writer(handle, lineterminator="\r\n").writerows([header, *records])


def canonical_recmd_batches(destination: Path, *, created_before: set[Path], bundle_root: Path) -> dict[str, str]:
    # Rows go in RECmd's hive-mask order, then by hive path, each hive's rows in the order RECmd wrote them, so a
    # cited row number names the same row in every run. The tool's own bytes are recorded by their hash.
    rewritten = {}
    for path in sorted(_snapshot(destination) - created_before):
        name = path.name.casefold()
        if path.parent == destination and "recmd_batch" in name and name.endswith("_output.csv"):
            rewritten[path.relative_to(bundle_root).as_posix()] = sha256_file(path)
            canonical_recmd_batch(path, folder=destination.relative_to(bundle_root).as_posix())
    return rewritten


def _bundle_source(value: str) -> str:
    parts = re.split(r"[\\/]", value)
    roots = [index for index, part in enumerate(parts) if part.casefold() == "kape-output"]
    return "/".join(parts[roots[-1] + 1:]) if roots else value


def filetime_text(value: int) -> str:
    moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=value // 10_000_000)
    return f"{moment:%Y-%m-%d %H:%M:%S}.{value % 10_000_000:07d}"


def canonical_source_columns(
    destination: Path, *, created_before: set[Path], bundle_root: Path, source_times: dict[str, dict[str, int]]
) -> dict[str, str]:
    rewritten = {}
    csv.field_size_limit(_CSV_FIELD_SIZE_LIMIT)
    for path in sorted(_snapshot(destination) - created_before):
        if path.suffix.casefold() != ".csv":
            continue
        with path.open("r", encoding="utf-8-sig", errors="surrogateescape", newline="") as handle:
            rows = list(csv.reader(handle))
        if not rows or "SourceFile" not in rows[0]:
            continue
        header = rows[0]
        source = header.index("SourceFile")
        times = [(header.index(column), key) for column, key in SOURCE_TIME_COLUMNS if column in header]
        rewritten[path.relative_to(bundle_root).as_posix()] = sha256_file(path)
        for row in rows[1:]:
            if source >= len(row):
                continue
            row[source] = _bundle_source(row[source])
            known = source_times.get(row[source])
            for column, key in times:
                if column < len(row):
                    row[column] = filetime_text(known[key]) if known else ""
        with path.open("w", encoding="utf-8-sig", errors="surrogateescape", newline="") as handle:
            csv.writer(handle, lineterminator="\r\n").writerows(rows)
    return rewritten


def processor_run_record(run: ProcessorRun) -> dict[str, Any]:
    return {
        "module": run.module_name,
        "requested_module": run.requested_module,
        "executable": run.executable,
        "tool": run.tool_name,
        "category": run.category,
        "command_line": run.command_line,
        "argv": list(run.argv),
        "working_directory": run.working_directory,
        "source_file": run.source_file,
        "started_at": run.started_at,
        "ended_at": run.ended_at,
        "duration_seconds": run.duration_seconds,
        "exit_code": run.exit_code,
        "status": run.status,
        "stdout_path": run.stdout_path,
        "stderr_path": run.stderr_path,
        "console_log": run.console_log_relative_path,
        "outputs": list(run.outputs),
        "detail": run.detail,
        "input_file_count": run.input_file_count,
        "input_byte_count": run.input_byte_count,
        "data_row_count": run.data_row_count,
        "data_row_counts": dict(run.data_row_counts),
        "timestamp_basis": "host_utc_clock",
        **({"rewritten_outputs": dict(run.rewritten_outputs)} if run.rewritten_outputs else {}),
    }


__all__ = [
    "DATA_ROW_BASIS",
    "DEFAULT_PROCESSOR_TIMEOUT_SECONDS",
    "HostModuleError",
    "ProcessorRun",
    "STATUS_COMPLETED",
    "STATUS_COMPLETED_EMPTY_OUTPUT",
    "csv_data_row_count",
    "matching_source_files",
    "processor_deferral",
    "processor_environment",
    "processor_run_record",
    "record_data_rows",
    "render_arguments",
    "run_module_processors",
    "strip_run_stamps",
    "targets_inventory",
]
