from __future__ import annotations

import argparse
import contextvars
import csv
import fnmatch
import json
import ntpath
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from fmb.collection.tools.host.definitions import ModuleProcessor
from fmb.collection.tools.host.modules import (
    RUN_STAMP_PREFIX,
    SOURCE_TIME_COLUMNS,
    csv_data_row_count,
    filetime_text,
)
from fmb.collection.tools.host import vmware as runner
from fmb.collection.tools.host.toolchain import DEFAULT_LOCK_PATH
from fmb.core.background import Background
from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.json_io import json_text, write_json

GUEST_ROOT = "C:\\FMB-Parsers"
# The VMware guest gets the inputs package and the script in one archive, copied where any user may write.
GUEST_TRANSPORT = "C:\\Windows\\Temp\\fmb-parsers.zip"
NATIVE_ROOT_LOCK = "fmb-parsers.lock"
WINDOWS_PARSERS = ("PECmd.exe", "SBECmd.exe")
APPLIANCE_DIR_NAME = "parser-appliance"
DEFAULT_GUEST_TIMEOUT_SECONDS = 1200
INPUT_MASKS_BY_EXECUTABLE = {
    "pecmd.exe": ("*.pf",),
    "sbecmd.exe": ("ntuser.dat", "ntuser.dat.log*", "usrclass.dat", "usrclass.dat.log*"),
}
RECEIPT_SCHEMA = "fmb_parser_appliance_receipt.v1"
RECORD_SCHEMA = "fmb_parser_appliance_record.v1"
# A parser VM clone names its fmb run, so a later run can tell whether that run is gone and remove the clone.
PARSER_OWNER_FILE = "fmb-parser-owner.json"
PARSER_PREFIX = "fmb-parser-"
QEMU_STATE_DIR = "qemu-state"
QEMU_STEP_ATTEMPTS = 3
QEMU_STEP_RETRY_DELAY_SECONDS = 10

GUEST_SCRIPT = r"""param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference = 'Stop'
$work = Join-Path $Root 'work'
if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $work | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $Root 'inputs.zip'), $work)
$plan = Get-Content -LiteralPath (Join-Path $work 'plan.json') -Raw | ConvertFrom-Json
if ($plan.file_times) {
  foreach ($entry in @($plan.file_times)) {
    $path = Join-Path $work (([string]$entry.path) -replace '/', '\')
    [System.IO.File]::SetCreationTimeUtc($path, [DateTime]::FromFileTimeUtc([long]$entry.created))
    [System.IO.File]::SetLastWriteTimeUtc($path, [DateTime]::FromFileTimeUtc([long]$entry.modified))
    [System.IO.File]::SetLastAccessTimeUtc($path, [DateTime]::FromFileTimeUtc([long]$entry.accessed))
  }
}
$logs = Join-Path $work 'logs'
New-Item -ItemType Directory -Force -Path $logs | Out-Null
$targets = Join-Path $work 'targets'
# The parsers run at the same time, each writing into its own folder (one whose folder another still writes into
# waits for it), and the receipt lists them in the plan's order whichever ends first.
$runs = @()
$writing = @{}
try {
  foreach ($item in @($plan.commands)) {
    $exe = Join-Path (Join-Path $work 'bin') ([string]$item.executable)
    $outDir = Join-Path (Join-Path $work 'modules') ([string]$item.category)
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $arguments = @()
    foreach ($arg in @($item.arguments)) {
      $value = ([string]$arg).Replace('%targets%', $targets).Replace('%out%', $outDir)
      if ($value.Contains(' ')) { $value = '"' + $value + '"' }
      $arguments += $value
    }
    $stdout = Join-Path $logs ([string]$item.label + '.stdout.txt')
    $stderr = Join-Path $logs ([string]$item.label + '.stderr.txt')
    if ($writing.ContainsKey($outDir)) { $writing[$outDir].WaitForExit() }
    $started = [DateTime]::UtcNow.ToString('o')
    $process = Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory (Split-Path $exe -Parent) -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    # Without -Wait, the exit code and time stay readable only if the handle is taken while the process runs.
    $null = $process.Handle
    $writing[$outDir] = $process
    $runs += @{ item = $item; exe = $exe; arguments = $arguments; process = $process; started = $started }
  }
} catch {
  # A parser that could not start leaves none of the others running.
  $failure = $_
  foreach ($run in $runs) { if (-not $run.process.HasExited) { $run.process.Kill() } }
  throw $failure
}
$results = @()
foreach ($run in $runs) {
  $run.process.WaitForExit()
  $results += [ordered]@{
    label = [string]$run.item.label
    category = [string]$run.item.category
    executable = [string]$run.item.executable
    executable_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $run.exe).Hash.ToLowerInvariant()
    arguments = $run.arguments
    exit_code = [int]$run.process.ExitCode
    started_at = $run.started
    ended_at = $run.process.ExitTime.ToUniversalTime().ToString('o')
  }
}
$receipt = [ordered]@{
  schema_version = 'fmb_parser_appliance_receipt.v1'
  os = [System.Environment]::OSVersion.VersionString
  machine = $env:COMPUTERNAME
  results = $results
}
$receipt | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $work 'receipt.json') -Encoding UTF8
$staging = Join-Path $work 'outputs'
New-Item -ItemType Directory -Force -Path $staging | Out-Null
Copy-Item -LiteralPath (Join-Path $work 'modules') -Destination (Join-Path $staging 'modules') -Recurse -Force
Copy-Item -LiteralPath $logs -Destination (Join-Path $staging 'logs') -Recurse -Force
Copy-Item -LiteralPath (Join-Path $work 'receipt.json') -Destination (Join-Path $staging 'receipt.json') -Force
$outputs = Join-Path $Root 'outputs.zip'
if (Test-Path -LiteralPath $outputs) { Remove-Item -LiteralPath $outputs -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($staging, $outputs)
"""
# Run by vmrun in the VMware guest: GUEST_ROOT then holds the package and the script, as if copied there one by one.
GUEST_BOOTSTRAP = rf"""$ErrorActionPreference = 'Stop'
$root = '{GUEST_ROOT}'
if (Test-Path -LiteralPath $root) {{ Remove-Item -LiteralPath $root -Recurse -Force }}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory('{GUEST_TRANSPORT}', $root)
& (Join-Path $root 'run_parsers.ps1') -Root $root
"""


class ParserApplianceError(runner.KapeApplianceError):
    pass


class _Cancelled(ParserApplianceError):
    """The parsers, or their VM, were no longer needed: the collection failed meanwhile."""


def _script_failed(completed: subprocess.CompletedProcess, stdout_path: Path, stderr_path: Path) -> ParserApplianceError:
    stderr = (completed.stderr or "").strip()
    tail = "\n".join((stderr or (completed.stdout or "").strip()).splitlines()[-12:])
    where = stderr_path if stderr else stdout_path
    return ParserApplianceError(f"parser script exited {completed.returncode}; see {where}" + (f"\n{tail}" if tail else ""))


def _windows_powershell() -> tuple[str, dict[str, str]]:
    # Started from PowerShell 7, powershell.exe inherits its module path, finds PowerShell 7's
    # Microsoft.PowerShell.Utility first, and then lacks the script cmdlets of its own, such as Get-FileHash.
    home = ntpath.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "WindowsPowerShell", "v1.0")
    env = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
    env["PSModulePath"] = ";".join([
        ntpath.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "WindowsPowerShell", "Modules"),
        ntpath.join(home, "Modules"),
    ])
    return ntpath.join(home, "powershell.exe"), env


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def matching_inputs(targets_root: Path, masks: tuple[str, ...]) -> list[Path]:
    lowered = tuple(mask.casefold() for mask in masks)
    return [
        path
        for path in sorted(targets_root.rglob("*"))
        if path.is_file() and any(fnmatch.fnmatchcase(path.name.casefold(), mask) for mask in lowered)
    ]


def render_guest_arguments(command_line: str) -> list[str]:
    rendered: list[str] = []
    for token in command_line.split():
        lowered = token.casefold()
        if lowered == "%sourcedirectory%":
            rendered.append("%targets%")
        elif lowered == "%destinationdirectory%":
            rendered.append("%out%")
        elif "%" in token:
            raise ParserApplianceError(f"parser appliance cannot render {token}")
        else:
            rendered.append(token)
    return rendered


def validated_builds(executable: str, lock_path: Path = DEFAULT_LOCK_PATH) -> dict[str, str]:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    for name, entry in (lock.get("windows_only_processors") or {}).items():
        if name.casefold() == executable.casefold():
            return dict(entry.get("validated_builds") or {})
    return {}


def windows_parser_binary(directory: Path, executable: str) -> tuple[str, bytes]:
    name = Path(executable.replace("\\", "/")).name
    path = Path(directory).expanduser() / name
    if not path.is_file():
        raise ParserApplianceError(f"Windows parser is missing: {path}")
    data = path.read_bytes()
    digest = sha256_bytes(data)
    builds = validated_builds(name)
    if digest not in builds:
        raise ParserApplianceError(
            f"{name} (sha256 {digest}) is not a validated build; validated: {sorted(builds)}. "
            "A different build needs its own validation run."
        )
    return builds[digest], data


_COPY_LOG_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?")


def _copy_log_filetime(text: str) -> int | None:
    match = _COPY_LOG_TIME.fullmatch(text.strip())
    if match is None:
        return None
    *fields, fraction = match.groups()
    moment = datetime(*(int(value) for value in fields), tzinfo=timezone.utc)
    seconds = (moment - datetime(1601, 1, 1, tzinfo=timezone.utc)) // timedelta(seconds=1)
    return seconds * 10_000_000 + int((fraction or "").ljust(7, "0"))


def copy_log_source_times(targets_root: Path) -> dict[str, dict[str, int]]:
    logs = sorted(targets_root.glob("*_CopyLog.csv"))
    if len(logs) != 1:
        return {}
    times: dict[str, dict[str, int]] = {}
    with logs[0].open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            entry = {
                key: _copy_log_filetime(row.get(column) or "")
                for key, column in (("created", "CreatedOnUtc"), ("modified", "ModifiedOnUtc"),
                                    ("accessed", "LastAccessedOnUtc"))
            }
            if all(entry.values()):
                times[str(row.get("DestinationFile") or "")] = entry
    return times


def _guest_input(value: str) -> str:
    """The bundle path (targets/...) of a file the guest read, from the full path a parser names it by."""
    prefix = GUEST_ROOT + "\\work\\"
    return value[len(prefix):].replace("\\", "/") if value[:len(prefix)].casefold() == prefix.casefold() else value


def image_source_times(path: Path, source_times: dict[str, dict[str, int]]) -> None:
    # PECmd reports when it read each prefetch file as SourceAccessed, so that time differs every run although the guest
    # set each input's NTFS times from the CopyLog first. The three Source times of each input become those image times.
    csv.field_size_limit(1 << 30)
    with path.open("rb") as handle:
        encoding = "utf-8-sig" if handle.read(3) == b"\xef\xbb\xbf" else "utf-8"
    with path.open("r", encoding=encoding, errors="surrogateescape", newline="") as handle:
        rows = list(csv.reader(handle))
    if not rows or "SourceFilename" not in rows[0]:
        return
    header = rows[0]
    source = header.index("SourceFilename")
    times = [(header.index(column), key) for column, key in SOURCE_TIME_COLUMNS if column in header]
    for row in rows[1:]:
        known = source_times.get(_guest_input(row[source])) if source < len(row) else None
        for column, key in times if known else ():
            if column < len(row):
                row[column] = filetime_text(known[key])
    with path.open("w", encoding=encoding, errors="surrogateescape", newline="") as handle:
        csv.writer(handle, lineterminator="\r\n").writerows(rows)


def build_input_package(
    *,
    package_path: Path,
    parsers_dir: Path,
    processors: list[ModuleProcessor],
    targets_root: Path,
) -> dict[str, Any]:
    commands: list[dict[str, Any]] = []
    included: set[str] = set()
    input_files = 0
    source_times = copy_log_source_times(targets_root)
    file_times: list[dict[str, Any]] = []
    with zipfile.ZipFile(package_path, "w", zipfile.ZIP_DEFLATED) as package:
        for processor in processors:
            build, data = windows_parser_binary(parsers_dir, processor.executable)
            exe_name = Path(processor.executable.replace("\\", "/")).name
            if f"bin/{exe_name}" not in included:
                package.writestr(f"bin/{exe_name}", data)
                included.add(f"bin/{exe_name}")
            masks = INPUT_MASKS_BY_EXECUTABLE.get(exe_name.casefold())
            files = (
                matching_inputs(targets_root, masks)
                if masks
                else [path for path in sorted(targets_root.rglob("*")) if path.is_file()]
            )
            for path in files:
                arcname = "targets/" + path.relative_to(targets_root).as_posix()
                if arcname in included:
                    continue
                package.write(path, arcname)
                included.add(arcname)
                input_files += 1
                if arcname in source_times:
                    file_times.append({"path": arcname, **source_times[arcname]})
            commands.append(
                {
                    "label": processor.module_name,
                    "category": processor.category,
                    "executable": exe_name,
                    "build": build,
                    "executable_sha256": sha256_bytes(data),
                    "arguments": render_guest_arguments(processor.command_line),
                    "input_file_count": len(files),
                    "input_byte_count": sum(path.stat().st_size for path in files),
                }
            )
        package.writestr("plan.json", json.dumps({"commands": commands, "file_times": file_times}, indent=2))
    return {
        "package": str(package_path),
        "package_sha256": sha256_file(package_path),
        "commands": commands,
        "input_file_count": input_files,
    }


def parser_runtime() -> tuple[str, str | None]:
    if sys.platform == "darwin":
        return "vmware_desktop", "fmb/windows-11-arm64"
    if sys.platform == "win32":
        return "native_windows", None
    from fmb.generation.recipe import qemu_box

    return "qemu", qemu_box()


def native_parser_root() -> Path:
    # Named as in the parser VM, so that PECmd and SBECmd name the same paths in their outputs on every host and run.
    return Path(Path(tempfile.gettempdir()).anchor, ntpath.basename(GUEST_ROOT))


def _lock_native_root(lock: Path) -> int | None:
    from fmb.collection.run.lock import _try_lock

    try:
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    except FileNotFoundError:
        return None
    try:
        if _try_lock(fd) and os.path.samestat(os.fstat(fd), os.stat(lock)):
            return fd
    except FileNotFoundError:
        pass
    os.close(fd)
    return None


@contextmanager
def _held_native_root(root: Path, cancelled: threading.Event | None = None) -> Iterator[Path]:
    # One fmb run at a time uses the fixed folder; the OS drops the lock if that run dies.
    from fmb.collection.run.lock import _unlock

    lock = root / NATIVE_ROOT_LOCK
    deadline = time.monotonic() + DEFAULT_GUEST_TIMEOUT_SECONDS
    stop = cancelled or threading.Event()
    while True:
        root.mkdir(exist_ok=True)
        fd = _lock_native_root(lock)
        if fd is not None:
            break
        if time.monotonic() >= deadline:
            raise ParserApplianceError(f"another fmb run kept {root} for its parsers too long; try again")
        if stop.wait(1):
            raise _Cancelled("the Windows-only parsers were no longer needed")
    try:
        yield root
    finally:
        for path in root.iterdir():
            with suppress(OSError):
                if path.is_dir():
                    shutil.rmtree(path)
                elif path.name != NATIVE_ROOT_LOCK:
                    path.unlink()
        with suppress(OSError):
            _unlock(fd)
        os.close(fd)
        with suppress(OSError):
            lock.unlink()
            root.rmdir()


def _run_native_windows_parsers(*, package_path: Path, script_path: Path, outputs_zip: Path,
                                cancelled: threading.Event | None = None) -> subprocess.CompletedProcess:
    # cancelled stops the parsers of a collection that failed meanwhile, with everything they started.
    from fmb.core.owned_process import run_owned

    with _held_native_root(native_parser_root(), cancelled) as root:
        shutil.copyfile(package_path, root / "inputs.zip")
        shutil.copyfile(script_path, root / "run_parsers.ps1")
        powershell, env = _windows_powershell()
        command = [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                   "-File", str(root / "run_parsers.ps1"), "-Root", str(root)]
        try:
            completed = run_owned(command, env=env, capture_output=True, timeout=DEFAULT_GUEST_TIMEOUT_SECONDS,
                                  cancel=cancelled)
        except subprocess.CalledProcessError as error:
            return subprocess.CompletedProcess(command, error.returncode, error.output or "", error.stderr or "")
        shutil.copyfile(root / "outputs.zip", outputs_zip)
        return completed


def _phase(timings: list[dict[str, Any]], name: str, callback):
    started = _utc_now()
    start = time.monotonic()
    value = callback()
    timings.append(
        {
            "phase": name,
            "started_at": started.isoformat(),
            "ended_at": _utc_now().isoformat(),
            "duration_seconds": round(time.monotonic() - start, 3),
        }
    )
    return value


def assert_no_running_vm(provider: str) -> None:
    completed = subprocess.run(
        runner.vmrun_command(provider, "list"),
        check=True, capture_output=True, text=True, timeout=30,
    )
    lines = completed.stdout.strip().splitlines()
    if lines[:1] != ["Total running VMs: 0"]:
        running = [line.strip() for line in lines[1:] if line.strip()]
        raise ParserApplianceError(
            "another VM is running; the parser appliance needs the single VM slot"
            + "".join(f"\n  running: {vmx}" for vmx in running)
            + "".join(f"\nIf it is not in use (for example left by an fmb run that was killed), stop it with: "
                      f"{shlex.join(runner.vmrun_command(provider, 'stop', vmx, 'hard'))}" for vmx in running))


def _write_owner(folder: Path, run_id: str) -> int:
    # The run keeps the owner file open and locked until close(); the OS drops the lock when the run dies.
    from fmb.collection.run.lock import _try_lock, current_host

    fd = os.open(folder / PARSER_OWNER_FILE, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        if not _try_lock(fd):
            raise ParserApplianceError(f"could not lock the owner file of the new parser VM folder {folder}")
        os.lseek(fd, 0, os.SEEK_SET)  # Windows locks a byte further on
        os.write(fd, json_text({"pid": os.getpid(), "host": current_host(), "run_id": run_id,
                                "started_at": _utc_now().isoformat()}).encode("utf-8"))
    except BaseException:
        os.close(fd)
        raise
    return fd


def reap_dead_parser_clones(work_root: Path, provider: str, log: Callable[[str], None]) -> None:
    """Remove the parser VM clones of fmb runs that are gone (killed, crashed, power lost)."""
    from fmb.collection.run.lock import _try_lock

    for folder in sorted(work_root.glob(PARSER_PREFIX + "*")):
        owner_file = folder / PARSER_OWNER_FILE
        try:
            owner = json.loads(owner_file.read_text(encoding="utf-8"))
            pid = int(owner["pid"])
            fd = os.open(owner_file, os.O_RDWR | getattr(os, "O_BINARY", 0))
        except (OSError, ValueError, KeyError, TypeError):
            continue
        try:
            # Only the lock tells: the Mac's hostname changes with its network, and a pid is reused after a restart.
            if not _try_lock(fd):
                continue
            vmx = folder / ".vmrun-appliance" / "box.vmx"
            if vmx.parent.exists():
                runner.cleanup_disposable_appliance_vm(vmx_path=vmx, provider=provider, graceful=False)
        finally:
            os.close(fd)
        # The whole folder, so that a file someone else left in it (Finder's .DS_Store) does not fail this run.
        shutil.rmtree(folder)
        log(f"parser appliance: removed the parser VM of run {owner.get('run_id')} (pid {pid} is gone): {folder}")


def _parser_qemus() -> list[tuple[int, list[str]]]:
    found = []
    for entry in Path("/proc").glob("[0-9]*"):
        try:
            argv = (entry / "cmdline").read_bytes().decode("utf-8", "replace").split("\0")
        except OSError:
            continue
        if "-name" in argv[:-1] and argv[argv.index("-name") + 1].startswith(PARSER_PREFIX):
            found.append((int(entry.name), argv))
    return found


def reap_orphan_parser_qemus(log: Callable[[str], None]) -> None:
    """Stop the parser QEMUs of fmb runs that are gone, and remove their disposable overlays."""
    from fmb.collection.run.lock import process_is_running

    for pid, argv in _parser_qemus():
        owner = argv[argv.index("-name") + 1].removeprefix(PARSER_PREFIX)
        if not owner.isdigit() or process_is_running(int(owner)):
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            continue
        state = Path(argv[argv.index("-pidfile") + 1]).parent if "-pidfile" in argv[:-1] else None
        if state is not None and state.name == QEMU_STATE_DIR:
            shutil.rmtree(state, ignore_errors=True)
        log(f"parser appliance: stopped the parser QEMU (pid {pid}) of a gone fmb run (pid {owner})")


class ParserVM:
    """The disposable parser VM (VMware on macOS, QEMU elsewhere).

    start() boots it in a background thread, so it boots while the host indexes the volume and runs its own parsers;
    a ParserRun then waits for it, runs the Windows-only parsers in it and removes it.
    """

    def __init__(self, *, args: argparse.Namespace, stage_dir: Path,
                 progress: Callable[[str], None] | None = None,
                 timings: list[dict[str, Any]] | None = None) -> None:
        self.provider = str(args.collection_provider)
        self.windows_box = str(args.windows_box)
        self.run_id = str(getattr(args, "run_id", None) or "host-collector")
        self.work_root = getattr(args, "vm_work_root", None)
        self.appliance_dir = stage_dir / APPLIANCE_DIR_NAME
        self.log = progress or (lambda _message: None)
        self.timings = [] if timings is None else timings
        self.vmx_path: Path | None = None
        self.owned_work_dir: Path | None = None
        self._owner_fd: int | None = None
        self.state: Path | None = None
        self.process: subprocess.Popen | None = None
        self.command: list[str] = []
        self.port = 0
        self.ansible = ""
        self.closed = False
        self._thread: threading.Thread | None = None
        self._boot_error: BaseException | None = None
        self._cancelled = threading.Event()
        self._closing = threading.Lock()

    def start(self) -> ParserVM:
        self._claim()
        # The thread keeps this context, so the run's read audit and truth guard see its file opens too.
        context = contextvars.copy_context()
        self._thread = threading.Thread(target=context.run, args=(self._boot_in_background,),
                                        name="fmb-parser-vm", daemon=True)
        self._thread.start()
        return self

    def _claim(self) -> None:
        # Before the boot thread, so a VM left by a gone run is removed, or a running one named, before host parsing.
        if self.provider == "qemu":
            reap_orphan_parser_qemus(self.log)
            return
        if self.work_root is not None and Path(self.work_root).expanduser().is_dir():
            reap_dead_parser_clones(Path(self.work_root).expanduser().resolve(), self.provider, self.log)
        assert_no_running_vm(self.provider)

    def _boot_in_background(self) -> None:
        try:
            self._boot()
        except BaseException as error:
            self._boot_error = error

    def wait(self) -> None:
        thread = self._thread
        if thread is not None:
            thread.join()
        if self._boot_error is not None:
            raise self._boot_error

    def boot(self) -> None:
        self._claim()
        self._boot()

    def _boot(self) -> None:
        self.appliance_dir.mkdir(parents=True, exist_ok=True)
        if self.provider == "qemu":
            self._boot_qemu()
        else:
            self._boot_vmware()

    def _boot_vmware(self) -> None:
        work_root = self.work_root
        if work_root is not None:
            source_root = runner.ensure_vagrant_box_vmx_path(box=self.windows_box, provider=self.provider).resolve().parent
            work_root = Path(work_root).expanduser().resolve()
            if work_root.is_relative_to(source_root) or source_root.is_relative_to(work_root):
                raise ParserApplianceError("parser VM work directory overlaps its protected source")
            work_root.mkdir(parents=True, exist_ok=True)
            self.owned_work_dir = Path(tempfile.mkdtemp(prefix=PARSER_PREFIX, dir=work_root))
            self._owner_fd = _write_owner(self.owned_work_dir, self.run_id)
        worker_dir = self.owned_work_dir if self.owned_work_dir is not None else self.appliance_dir
        vmx_path = worker_dir / ".vmrun-appliance" / "box.vmx"
        if vmx_path.parent.exists():
            raise ParserApplianceError("refusing to adopt an existing parser VM directory")
        # From here on, close() owns and removes this worker directory.
        self.vmx_path = vmx_path
        plan = {
            "run_id": f"{self.run_id}-parsers",
            "worker": {"windows_box": self.windows_box},
            "evidence": {},
            "transport": {"strategy": "parser_appliance_no_evidence_disk"},
        }
        cloned_vmx = _phase(
            self.timings,
            "clone_appliance",
            lambda: runner.clone_vagrant_box_for_vmrun(
                plan=plan, stage_dir=self.appliance_dir, provider=self.provider, vm_work_dir=self.owned_work_dir),
        )
        if cloned_vmx.resolve() != vmx_path.resolve():
            raise ParserApplianceError("parser clone returned a different owned VM path")
        if self._cancelled.is_set():
            raise _Cancelled("the parser VM was no longer needed")
        _phase(self.timings, "start_appliance",
               lambda: runner.vmrun_start_and_wait(vmx_path=vmx_path, provider=self.provider))

    def _boot_qemu(self) -> None:
        from fmb.generation.backends import QemuBackend

        tools = QemuBackend.discover_tools()
        missing = [name for name in ("qemu-system", "qemu-img", "ansible") if not tools[name]]
        if missing:
            raise ParserApplianceError("the QEMU parser worker needs " + ", ".join(missing))
        base = QemuBackend.base_directory(QemuBackend.base_location(self.windows_box, "0")) / QemuBackend.base_entry
        self.ansible = tools["ansible"]
        # In the run folder rather than $TMPDIR, which is RAM on several distributions; close() removes it.
        state = self.appliance_dir / QEMU_STATE_DIR
        state.mkdir()
        self.state = state
        _phase(self.timings, "start_appliance",
               lambda: self._launch_qemu(tools["qemu-img"], base, Path(tools["qemu-system"]), state))

    def _launch_qemu(self, qemu_img: str, base: Path, qemu: Path, state: Path) -> None:
        from fmb.generation.backends import _free_port, prepare_overlay, qemu_guest_command

        prepare_overlay(qemu_img, base, qemu, state)
        self.port, monitor_port = _free_port(), _free_port()
        self.command = qemu_guest_command(qemu, state, winrm_port=self.port, monitor_port=monitor_port) + [
            "-netdev", f"user,id=nat,restrict=on,hostfwd=tcp:127.0.0.1:{self.port}-:5985", "-device", "e1000e,netdev=nat",
            "-name", f"{PARSER_PREFIX}{os.getpid()}", "-pidfile", str(state / "qemu.pid")]
        with self._qemu_log.open("w", encoding="utf-8") as qemu_log:
            self.process = subprocess.Popen(self.command, stdout=qemu_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 1800
        while not self._answered():
            if self._cancelled.is_set():
                raise _Cancelled("the parser VM was no longer needed")
            if self.process.poll() is not None:
                tail = self._qemu_log.read_text(encoding="utf-8", errors="replace")[-2000:].strip()
                raise ParserApplianceError(
                    f"the parser VM exited during boot with exit code {self.process.returncode}"
                    + (" (killed; the system may have run out of memory)" if self.process.returncode == -9 else "")
                    + f"; the end of {self._qemu_log}:\n{tail or '(empty)'}")
            if time.monotonic() > deadline:
                raise ParserApplianceError("the parser VM did not answer WinRM within 30 minutes")
            time.sleep(2)
        self.log("parser appliance: QEMU worker answered WinRM")

    @property
    def _qemu_log(self) -> Path:
        return self.appliance_dir / "parser-vm-qemu.log"

    def _keep_logs(self) -> None:
        # The VM folder is removed below; its logs stay in the run folder.
        sources = ([self.state / "serial.log"] if self.state is not None else []) + (
            [self.vmx_path.parent / "vmware.log"] if self.vmx_path is not None else [])
        for source in sources:
            # A log that cannot be copied must not keep the VM from being removed.
            with suppress(OSError):
                shutil.copyfile(source, self.appliance_dir / f"parser-vm-{source.name}")

    def _answered(self) -> bool:
        from fmb.generation.backends import ansible_adhoc, winrm_listening

        if not winrm_listening(self.port):
            return False
        try:
            return ansible_adhoc(self.ansible, self.port, "ansible.windows.win_ping", {}, timeout=120).returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def run_qemu_parsers(self, *, package_path: Path, script_path: Path, outputs_zip: Path,
                         log: Callable[[str], None] | None = None) -> subprocess.CompletedProcess:
        from fmb.generation.backends import ansible_adhoc

        log = log or self.log
        outputs = []

        def step(module: str, args: dict, timeout: int = 600) -> None:
            # Creating the folder and copying a file in or out can be repeated, so a dropped WinRM call is retried.
            for attempt in range(1, QEMU_STEP_ATTEMPTS + 1):
                try:
                    result = ansible_adhoc(self.ansible, self.port, module, args, timeout=timeout)
                except subprocess.TimeoutExpired as error:
                    failure = f"no answer within {error.timeout} s"
                else:
                    outputs.append(result.stdout)
                    if result.returncode == 0:
                        return
                    failure = result.stdout[-2000:]
                if attempt == QEMU_STEP_ATTEMPTS:
                    raise ParserApplianceError(f"parser VM step {module} failed {attempt} times; last: {failure}")
                log(f"parser appliance: {module} failed (attempt {attempt}); retrying")
                # A VM closed meanwhile, for a collection that failed, will not answer again.
                if self._cancelled.wait(QEMU_STEP_RETRY_DELAY_SECONDS):
                    raise _Cancelled("the parser VM was no longer needed")
                self._answered()

        step("ansible.windows.win_file", {"path": GUEST_ROOT, "state": "directory"})
        step("ansible.windows.win_copy", {"src": str(package_path), "dest": GUEST_ROOT + "\\inputs.zip"})
        step("ansible.windows.win_copy", {"src": str(script_path), "dest": GUEST_ROOT + "\\run_parsers.ps1"})
        run = ansible_adhoc(self.ansible, self.port, "ansible.windows.win_command", {"argv": [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", GUEST_ROOT + "\\run_parsers.ps1", "-Root", GUEST_ROOT]},
            timeout=DEFAULT_GUEST_TIMEOUT_SECONDS + 120)
        if run.returncode == 0:
            step("ansible.builtin.fetch", {"src": GUEST_ROOT + "\\outputs.zip", "dest": str(outputs_zip),
                                           "flat": True})
        return subprocess.CompletedProcess(self.command, run.returncode, "\n".join(outputs + [run.stdout]),
                                           run.stderr)

    def close(self, *, graceful: bool = True) -> dict[str, Any] | None:
        """Stop and remove the VM. After a run it only holds copied inputs and outputs, so it is powered off."""
        # The parsers' thread and a collection that failed meanwhile may both close it: the second waits, then returns.
        with self._closing:
            if self.closed:
                return None
            self._cancelled.set()
            thread = self._thread
            if thread is not None:
                thread.join()
            self.closed = True
            return self._remove(graceful=graceful)

    def _remove(self, *, graceful: bool) -> dict[str, Any] | None:
        if self.provider == "qemu":
            try:
                if self.process is not None and self.process.poll() is None:
                    self.process.kill()
                    self.process.wait(timeout=60)
            finally:
                if self.state is not None:
                    self._keep_logs()
                    shutil.rmtree(self.state)
            return {"removed": True, "path": None,
                    "policy": "temporary_parser_directory_or_disposable_overlay_removed"}
        cleanup = None
        if self.vmx_path is not None:
            if self.vmx_path.parent.is_dir():
                self._keep_logs()
            cleanup = runner.cleanup_disposable_appliance_vm(vmx_path=self.vmx_path, provider=self.provider,
                                                             graceful=graceful)
        if self.owned_work_dir is not None:
            if self._owner_fd is not None:
                fd, self._owner_fd = self._owner_fd, None
                os.close(fd)
            (self.owned_work_dir / PARSER_OWNER_FILE).unlink(missing_ok=True)
            self.owned_work_dir.rmdir()
        return cleanup

    def discard(self, error: BaseException) -> None:
        """Remove a VM that a failed collection no longer needs, keeping the collection's error."""
        try:
            self.close(graceful=False)
        except BaseException as cleanup_error:
            error.add_note(
                f"Parser VM cleanup failed ({type(cleanup_error).__name__}) at {self.vmx_path}: {cleanup_error}"
            )
        boot_error = self._boot_error
        if boot_error is not None and boot_error is not error and not isinstance(boot_error, _Cancelled):
            error.add_note(f"The parser VM had also failed to boot: {type(boot_error).__name__}: {boot_error}")


class ParserRun:
    """The Windows-only parsers of one collection.

    run() builds their input package, runs them (natively, or in the parser VM, which it then removes) and brings their
    outputs back; start() does that on a thread of its own, so that they run while the host runs its own parsers.
    merge() then adds their outputs to the bundle and writes the record, as when they ran after the host's parsers.
    """

    def __init__(self, *, processors: list[ModuleProcessor], args: argparse.Namespace, stage_dir: Path,
                 targets_root: Path, modules_root: Path, tool_logs: Path,
                 progress: Callable[[str], None] | None = None, vm: ParserVM | None = None) -> None:
        self.processors = processors
        self.args = args
        self.stage_dir = stage_dir
        self.targets_root = targets_root
        self.modules_root = modules_root
        self.tool_logs = tool_logs
        self.log = progress or (lambda _message: None)
        self.provider = str(args.collection_provider)
        self.windows_box = str(args.windows_box)
        self.appliance_dir = stage_dir / APPLIANCE_DIR_NAME
        self.vm = vm
        self.booted_early = vm is not None
        self.timings: list[dict[str, Any]] = []
        self.package: dict[str, Any] = {}
        self.cleanup: dict[str, Any] | None = None
        self._cancelled = threading.Event()
        self._cleanup_error: BaseException | None = None
        self._background: Background | None = None

    def start(self) -> ParserRun:
        self._background = Background(self.run, name="fmb-windows-parsers")
        return self

    def finish(self) -> dict[str, Any]:
        """The record, once the parsers started by start() have ended and their outputs are in the bundle."""
        if self._background is not None:
            self._background.result()
        return self.merge()

    def discard(self, error: BaseException) -> None:
        """Stop the parsers of a collection that failed, keeping its error; their thread and VM are gone after this."""
        self._cancelled.set()
        if self.vm is not None:
            self.vm.discard(error)
        if self._background is None:
            return
        try:
            self._background.result()
        except Exception as raised:
            # The parsers' own error already notes a failed removal of their VM; the collection's error gets it here.
            if raised is not error and self._cleanup_error is not None:
                error.add_note(f"Parser VM cleanup failed ({type(self._cleanup_error).__name__}) at "
                               f"{self.vm.vmx_path}: {self._cleanup_error}")

    def _phase(self, name: str, callback):
        if self._cancelled.is_set():
            raise _Cancelled("the Windows-only parsers were no longer needed")
        return _phase(self.timings, name, callback)

    def run(self) -> None:
        parsers_dir = getattr(self.args, "windows_parsers", None)
        if not parsers_dir:
            raise ParserApplianceError("the parser appliance needs --windows-parsers (PECmd.exe, SBECmd.exe)")
        appliance_dir = self.appliance_dir
        appliance_dir.mkdir(parents=True, exist_ok=True)
        package_path = appliance_dir / "inputs.zip"
        self.package = self._phase(
            "build_input_package",
            lambda: build_input_package(
                package_path=package_path,
                parsers_dir=Path(str(parsers_dir)),
                processors=self.processors,
                targets_root=self.targets_root,
            ),
        )
        self.log(
            f"parser appliance: {len(self.processors)} processors, {self.package['input_file_count']} input files "
            f"({Path(self.package['package']).stat().st_size} bytes packaged)"
        )
        script_path = appliance_dir / "run_parsers.ps1"
        script_path.write_text(GUEST_SCRIPT, encoding="utf-8")
        outputs_zip = appliance_dir / "outputs.zip"
        guest_stdout = self.tool_logs / "parser-appliance.vmrun.stdout.txt"
        guest_stderr = self.tool_logs / "parser-appliance.vmrun.stderr.txt"
        if self.provider == "native_windows":
            completed = self._phase("run_native_parsers", lambda: _run_native_windows_parsers(
                package_path=package_path, script_path=script_path, outputs_zip=outputs_zip,
                cancelled=self._cancelled))
            guest_stdout.write_text(completed.stdout or "", encoding="utf-8")
            guest_stderr.write_text(completed.stderr or "", encoding="utf-8")
            if completed.returncode != 0:
                raise _script_failed(completed, guest_stdout, guest_stderr)
            self.cleanup = {"removed": True, "path": None,
                            "policy": "temporary_parser_directory_or_disposable_overlay_removed"}
            return
        if self.vm is None:
            self.vm = ParserVM(args=self.args, stage_dir=self.stage_dir, progress=self.log, timings=self.timings)
        vm = self.vm
        primary_error = None
        try:
            if self.booted_early:
                self._phase("await_appliance", vm.wait)
            else:
                vm.boot()
            if self.provider == "qemu":
                completed = self._phase("run_qemu_parsers", lambda: vm.run_qemu_parsers(
                    package_path=package_path, script_path=script_path, outputs_zip=outputs_zip, log=self.log))
                guest_stdout.write_text(completed.stdout or "", encoding="utf-8")
                guest_stderr.write_text(completed.stderr or "", encoding="utf-8")
                if completed.returncode != 0:
                    raise _script_failed(completed, guest_stdout, guest_stderr)
            else:
                self._phase(
                    "stage_inputs",
                    lambda: _stage_inputs(vmx_path=vm.vmx_path, provider=self.provider, package_path=package_path),
                )
                completed = self._phase(
                    "run_guest_parsers",
                    lambda: runner.run_powershell_command_with_vmrun(
                        vmx_path=vm.vmx_path,
                        provider=self.provider,
                        command=GUEST_BOOTSTRAP,
                        check=False,
                        timeout_seconds=DEFAULT_GUEST_TIMEOUT_SECONDS,
                    ),
                )
                guest_stdout.write_text(completed.stdout or "", encoding="utf-8")
                guest_stderr.write_text(completed.stderr or "", encoding="utf-8")
                if completed.returncode != 0:
                    raise ParserApplianceError(
                        f"guest parser script exited {completed.returncode}; see {guest_stderr}"
                    )
                self._phase(
                    "collect_outputs",
                    lambda: runner.copy_guest_file_to_host_with_vmrun_retries(
                        vmx_path=vm.vmx_path, provider=self.provider,
                        guest_path=f"{GUEST_ROOT}\\outputs.zip", host_path=outputs_zip,
                    ),
                )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            try:
                self.cleanup = _phase(self.timings, "stop_and_cleanup", lambda: vm.close(graceful=False))
            except BaseException as cleanup_error:
                self._cleanup_error = cleanup_error
                if primary_error is None:
                    raise
                primary_error.add_note(
                    f"Parser VM cleanup failed ({type(cleanup_error).__name__}) at {vm.vmx_path}: {cleanup_error}"
                )

    def merge(self) -> dict[str, Any]:
        record = _phase(
            self.timings,
            "merge_outputs",
            lambda: _merge_outputs(
                outputs_zip=self.appliance_dir / "outputs.zip", appliance_dir=self.appliance_dir,
                modules_root=self.modules_root, tool_logs=self.tool_logs, package=self.package,
                source_times=copy_log_source_times(self.targets_root),
            ),
        )
        record.update(
            {
                "schema_version": RECORD_SCHEMA,
                "mode": "run",
                "windows_box": self.windows_box,
                "provider": self.provider,
                "guest_root": None if self.provider == "native_windows" else GUEST_ROOT,
                "vm_cleanup": self.cleanup,
                "phase_timings": (self.vm.timings if self.booted_early else []) + self.timings,
            }
        )
        write_json(self.appliance_dir / "parser-appliance-record.json", record)
        return record


def run_parser_appliance(
    *,
    processors: list[ModuleProcessor],
    args: argparse.Namespace,
    stage_dir: Path,
    targets_root: Path,
    modules_root: Path,
    tool_logs: Path,
    progress: Callable[[str], None] | None = None,
    vm: ParserVM | None = None,
) -> dict[str, Any]:
    parsers = ParserRun(processors=processors, args=args, stage_dir=stage_dir, targets_root=targets_root,
                        modules_root=modules_root, tool_logs=tool_logs, progress=progress, vm=vm)
    parsers.run()
    return parsers.merge()


def _stage_inputs(*, vmx_path: Path, provider: str, package_path: Path) -> None:
    # One vmrun copy instead of a folder and two files; GUEST_BOOTSTRAP unpacks it. Built outside the run folder, from
    # the script's text, so that the run reads no file it did not read before.
    with tempfile.TemporaryDirectory(prefix="fmb-parser-inputs-") as passing:
        transport = Path(passing) / ntpath.basename(GUEST_TRANSPORT)
        with zipfile.ZipFile(transport, "w", zipfile.ZIP_STORED) as archive:
            archive.write(package_path, "inputs.zip")
            archive.writestr("run_parsers.ps1", GUEST_SCRIPT)
        runner.copy_host_file_to_guest_with_vmrun_retries(
            vmx_path=vmx_path, provider=provider, host_path=transport, guest_path=GUEST_TRANSPORT,
        )


def _merge_outputs(
    *, outputs_zip: Path, appliance_dir: Path, modules_root: Path, tool_logs: Path, package: dict[str, Any],
    source_times: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    if not outputs_zip.is_file():
        raise ParserApplianceError("parser appliance returned no outputs package")
    extracted = appliance_dir / "outputs"
    if extracted.exists():
        shutil.rmtree(extracted)
    with zipfile.ZipFile(outputs_zip) as opened:
        for member in opened.infolist():
            name = member.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                raise ParserApplianceError(f"unsafe member in parser appliance outputs: {name}")
            if member.is_dir() or name.endswith("/"):
                continue
            target = extracted / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with opened.open(member) as source, target.open("wb") as sink:
                shutil.copyfileobj(source, sink)
    receipt_path = extracted / "receipt.json"
    if not receipt_path.is_file():
        raise ParserApplianceError("parser appliance receipt is missing")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8-sig"))
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise ParserApplianceError("parser appliance receipt schema is unsupported")
    results = receipt.get("results") or []
    if isinstance(results, dict):
        results = [results]
    expected = {item["label"]: item for item in package["commands"]}
    merged_outputs: list[str] = []
    empty_output_modules: list[str] = []
    for result in results:
        label = str(result.get("label"))
        planned = expected.get(label)
        if planned is None:
            raise ParserApplianceError(f"parser appliance ran an unplanned processor: {label}")
        if result.get("executable_sha256") != planned["executable_sha256"]:
            raise ParserApplianceError(f"parser appliance executable differs from the packaged build: {label}")
        if int(result.get("exit_code", 1)) != 0:
            raise ParserApplianceError(f"parser appliance processor {label} exited {result.get('exit_code')}")
        category = str(result.get("category") or planned["category"])
        source_dir = extracted / "modules" / category
        destination = modules_root / category
        destination.mkdir(parents=True, exist_ok=True)
        data_rows = 0
        outputs: list[str] = []
        if source_dir.is_dir():
            for path in sorted(source_dir.rglob("*")):
                if not path.is_file():
                    continue
                relative = path.relative_to(source_dir)
                target = destination / relative.parent / RUN_STAMP_PREFIX.sub("", relative.name, count=1)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                outputs.append(target.relative_to(modules_root.parent).as_posix())
                if target.suffix.casefold() == ".csv":
                    if source_times:
                        image_source_times(target, source_times)
                    data_rows += csv_data_row_count(target)
        merged_outputs.extend(outputs)
        result.update(data_row_count=data_rows, outputs=outputs,
                      input_file_count=planned.get("input_file_count"), input_byte_count=planned.get("input_byte_count"))
        if int(planned.get("input_byte_count") or 0) > 0 and data_rows == 0:
            empty_output_modules.append(label)
        for stream in ("stdout", "stderr"):
            log_file = extracted / "logs" / f"{label}.{stream}.txt"
            if log_file.is_file():
                shutil.copyfile(log_file, tool_logs / f"parser-appliance-{label}.{stream}.txt")
        stdout_file = extracted / "logs" / f"{label}.stdout.txt"
        console = destination / f"{label}-parser-appliance.console.log"
        console.write_text(
            "Command line: " + " ".join(str(item) for item in result.get("arguments", [])) + "\n\n"
            + (stdout_file.read_text(encoding="utf-8", errors="replace") if stdout_file.is_file() else ""),
            encoding="utf-8",
        )
        result["console_log"] = console.relative_to(modules_root.parent).as_posix()
        merged_outputs.append(result["console_log"])
    if {item["label"] for item in package["commands"]} != {str(item.get("label")) for item in results}:
        raise ParserApplianceError("parser appliance receipt does not cover every planned processor")
    return {
        "status": "completed",
        "modules": [item["label"] for item in package["commands"]],
        "package_sha256": package["package_sha256"],
        "input_file_count": package["input_file_count"],
        "guest": {"os": receipt.get("os"), "machine": receipt.get("machine")},
        "results": results,
        "outputs": merged_outputs,
        "empty_output_modules": empty_output_modules,
        "outputs_zip_sha256": sha256_file(outputs_zip),
    }


__all__ = [
    "GUEST_ROOT",
    "INPUT_MASKS_BY_EXECUTABLE",
    "ParserApplianceError",
    "ParserRun",
    "ParserVM",
    "build_input_package",
    "matching_inputs",
    "render_guest_arguments",
    "run_parser_appliance",
]
