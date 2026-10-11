from __future__ import annotations

import argparse
import contextvars
import csv
import fnmatch
import json
import ntpath
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from fmb.collection.tools.host.definitions import ModuleProcessor
from fmb.collection.tools.host.modules import csv_data_row_count
from fmb.collection.tools.host import vmware as runner
from fmb.collection.tools.host.toolchain import DEFAULT_LOCK_PATH
from fmb.core.hashing import sha256_bytes, sha256_file
from fmb.core.json_io import write_json

GUEST_ROOT = "C:\\FMB-Parsers"
WINDOWS_PARSERS = ("PECmd.exe", "SBECmd.exe")
APPLIANCE_DIR_NAME = "parser-appliance"
DEFAULT_GUEST_TIMEOUT_SECONDS = 1200
INPUT_MASKS_BY_EXECUTABLE = {
    "pecmd.exe": ("*.pf",),
    "sbecmd.exe": ("ntuser.dat", "ntuser.dat.log*", "usrclass.dat", "usrclass.dat.log*"),
}
RECEIPT_SCHEMA = "fmb_parser_appliance_receipt.v1"
RECORD_SCHEMA = "fmb_parser_appliance_record.v1"

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
$results = @()
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
  $started = [DateTime]::UtcNow.ToString('o')
  $process = Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory (Split-Path $exe -Parent) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  $ended = [DateTime]::UtcNow.ToString('o')
  $results += [ordered]@{
    label = [string]$item.label
    category = [string]$item.category
    executable = [string]$item.executable
    executable_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant()
    arguments = $arguments
    exit_code = [int]$process.ExitCode
    started_at = $started
    ended_at = $ended
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


class ParserApplianceError(runner.KapeApplianceError):
    pass


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


def _run_native_windows_parsers(*, package_path: Path, script_path: Path, outputs_zip: Path) -> subprocess.CompletedProcess:
    from fmb.core.owned_process import run_owned

    with tempfile.TemporaryDirectory(prefix="fmbp-", dir=Path(tempfile.gettempdir()).anchor) as temporary:
        root = Path(temporary)
        shutil.copyfile(package_path, root / "inputs.zip")
        shutil.copyfile(script_path, root / "run_parsers.ps1")
        powershell, env = _windows_powershell()
        command = [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                   "-File", str(root / "run_parsers.ps1"), "-Root", str(root)]
        try:
            completed = run_owned(command, env=env, capture_output=True, timeout=DEFAULT_GUEST_TIMEOUT_SECONDS)
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
    if completed.stdout.strip().splitlines()[:1] != ["Total running VMs: 0"]:
        raise ParserApplianceError("another VM is running; the parser appliance needs the single VM slot")


class ParserVM:
    """The disposable parser VM (VMware on macOS, QEMU elsewhere).

    start() boots it in a background thread, so it boots while the host indexes the volume and runs its own parsers;
    run_parser_appliance then waits for it, runs the Windows-only parsers in it and removes it.
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
        self.state: tempfile.TemporaryDirectory | None = None
        self.process: subprocess.Popen | None = None
        self.command: list[str] = []
        self.port = 0
        self.ansible = ""
        self.closed = False
        self._thread: threading.Thread | None = None
        self._boot_error: BaseException | None = None
        self._cancelled = threading.Event()

    def start(self) -> ParserVM:
        # The thread keeps this context, so the run's read audit and truth guard see its file opens too.
        context = contextvars.copy_context()
        self._thread = threading.Thread(target=context.run, args=(self._boot_in_background,),
                                        name="fmb-parser-vm", daemon=True)
        self._thread.start()
        return self

    def _boot_in_background(self) -> None:
        try:
            self.boot()
        except BaseException as error:
            self._boot_error = error

    def wait(self) -> None:
        if self._thread is not None:
            self._thread.join()
            self._thread = None
        if self._boot_error is not None:
            error, self._boot_error = self._boot_error, None
            raise error

    def boot(self) -> None:
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
            self.owned_work_dir = Path(tempfile.mkdtemp(prefix="fmb-parser-", dir=work_root))
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
        assert_no_running_vm(self.provider)
        cloned_vmx = _phase(
            self.timings,
            "clone_appliance",
            lambda: runner.clone_vagrant_box_for_vmrun(
                plan=plan, stage_dir=self.appliance_dir, provider=self.provider, vm_work_dir=self.owned_work_dir),
        )
        if cloned_vmx.resolve() != vmx_path.resolve():
            raise ParserApplianceError("parser clone returned a different owned VM path")
        if self._cancelled.is_set():
            raise ParserApplianceError("the parser VM was no longer needed")
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
        self.state = tempfile.TemporaryDirectory(prefix="fmb-parser-qemu-")
        _phase(self.timings, "start_appliance",
               lambda: self._launch_qemu(tools["qemu-img"], base, Path(tools["qemu-system"]), Path(self.state.name)))

    def _launch_qemu(self, qemu_img: str, base: Path, qemu: Path, state: Path) -> None:
        from fmb.generation.backends import _free_port, prepare_overlay, qemu_guest_command

        prepare_overlay(qemu_img, base, qemu, state)
        self.port, monitor_port = _free_port(), _free_port()
        self.command = qemu_guest_command(qemu, state, winrm_port=self.port, monitor_port=monitor_port) + [
            "-netdev", f"user,id=nat,restrict=on,hostfwd=tcp:127.0.0.1:{self.port}-:5985", "-device", "e1000e,netdev=nat"]
        with (state / "qemu.log").open("w") as qemu_log:
            self.process = subprocess.Popen(self.command, stdout=qemu_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 1800
        while not self._answered():
            if self._cancelled.is_set():
                raise ParserApplianceError("the parser VM was no longer needed")
            if self.process.poll() is not None:
                raise ParserApplianceError("the parser VM exited during boot")
            if time.monotonic() > deadline:
                raise ParserApplianceError("the parser VM did not answer WinRM within 30 minutes")
            time.sleep(2)
        self.log("parser appliance: QEMU worker answered WinRM")

    def _answered(self) -> bool:
        from fmb.generation.backends import ansible_adhoc, winrm_listening

        if not winrm_listening(self.port):
            return False
        try:
            return ansible_adhoc(self.ansible, self.port, "ansible.windows.win_ping", {}, timeout=120).returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def run_qemu_parsers(self, *, package_path: Path, script_path: Path,
                         outputs_zip: Path) -> subprocess.CompletedProcess:
        from fmb.generation.backends import ansible_adhoc

        outputs = []

        def step(module: str, args: dict, timeout: int = 600) -> None:
            result = ansible_adhoc(self.ansible, self.port, module, args, timeout=timeout)
            outputs.append(result.stdout)
            if result.returncode != 0:
                raise ParserApplianceError(f"parser VM step {module} failed: {result.stdout[-2000:]}")

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
        if self.closed:
            return None
        self._cancelled.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None
        self.closed = True
        if self.provider == "qemu":
            try:
                if self.process is not None and self.process.poll() is None:
                    self.process.kill()
                    self.process.wait(timeout=60)
            finally:
                if self.state is not None:
                    self.state.cleanup()
            return {"removed": True, "path": None,
                    "policy": "temporary_parser_directory_or_disposable_overlay_removed"}
        cleanup = None
        if self.vmx_path is not None:
            cleanup = runner.cleanup_disposable_appliance_vm(vmx_path=self.vmx_path, provider=self.provider,
                                                             graceful=graceful)
        if self.owned_work_dir is not None:
            self.owned_work_dir.rmdir()
        return cleanup

    def discard(self, error: BaseException) -> None:
        """Remove a VM that a failed collection no longer needs, keeping the collection's error."""
        try:
            self.close()
        except BaseException as cleanup_error:
            error.add_note(
                f"Parser VM cleanup failed ({type(cleanup_error).__name__}) at {self.vmx_path}: {cleanup_error}"
            )


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
    log = progress or (lambda _message: None)
    parsers_dir = getattr(args, "windows_parsers", None)
    if not parsers_dir:
        raise ParserApplianceError("the parser appliance needs --windows-parsers (PECmd.exe, SBECmd.exe)")
    provider = str(args.collection_provider)
    windows_box = str(args.windows_box)
    appliance_dir = stage_dir / APPLIANCE_DIR_NAME
    appliance_dir.mkdir(parents=True, exist_ok=True)
    timings: list[dict[str, Any]] = []

    def phase(name: str, callback):
        return _phase(timings, name, callback)

    package = phase(
        "build_input_package",
        lambda: build_input_package(
            package_path=appliance_dir / "inputs.zip",
            parsers_dir=Path(str(parsers_dir)),
            processors=processors,
            targets_root=targets_root,
        ),
    )
    log(
        f"parser appliance: {len(processors)} processors, {package['input_file_count']} input files "
        f"({Path(package['package']).stat().st_size} bytes packaged)"
    )
    script_path = appliance_dir / "run_parsers.ps1"
    script_path.write_text(GUEST_SCRIPT, encoding="utf-8")
    outputs_zip = appliance_dir / "outputs.zip"
    guest_stdout = tool_logs / "parser-appliance.vmrun.stdout.txt"
    guest_stderr = tool_logs / "parser-appliance.vmrun.stderr.txt"
    if provider == "native_windows":
        completed = phase("run_native_parsers", lambda: _run_native_windows_parsers(
            package_path=appliance_dir / "inputs.zip", script_path=script_path, outputs_zip=outputs_zip))
        guest_stdout.write_text(completed.stdout or "", encoding="utf-8")
        guest_stderr.write_text(completed.stderr or "", encoding="utf-8")
        if completed.returncode != 0:
            raise _script_failed(completed, guest_stdout, guest_stderr)
        record = phase("merge_outputs", lambda: _merge_outputs(
            outputs_zip=outputs_zip, appliance_dir=appliance_dir, modules_root=modules_root,
            tool_logs=tool_logs, package=package))
        record.update({"schema_version": RECORD_SCHEMA, "mode": "run", "windows_box": windows_box,
                       "provider": provider, "guest_root": None,
                       "vm_cleanup": {"removed": True, "path": None,
                                      "policy": "temporary_parser_directory_or_disposable_overlay_removed"},
                       "phase_timings": timings})
        write_json(appliance_dir / "parser-appliance-record.json", record)
        return record
    booted_early = vm is not None
    if vm is None:
        vm = ParserVM(args=args, stage_dir=stage_dir, progress=log, timings=timings)
    primary_error = None
    try:
        if booted_early:
            phase("await_appliance", vm.wait)
        else:
            vm.boot()
        if provider == "qemu":
            completed = phase("run_qemu_parsers", lambda: vm.run_qemu_parsers(
                package_path=appliance_dir / "inputs.zip", script_path=script_path, outputs_zip=outputs_zip))
            guest_stdout.write_text(completed.stdout or "", encoding="utf-8")
            guest_stderr.write_text(completed.stderr or "", encoding="utf-8")
            if completed.returncode != 0:
                raise _script_failed(completed, guest_stdout, guest_stderr)
        else:
            phase(
                "stage_inputs",
                lambda: _stage_inputs(vmx_path=vm.vmx_path, provider=provider,
                                      package_path=appliance_dir / "inputs.zip", script_path=script_path),
            )
            completed = phase(
                "run_guest_parsers",
                lambda: runner.run_powershell_file_with_vmrun(
                    vmx_path=vm.vmx_path,
                    provider=provider,
                    script_path=f"{GUEST_ROOT}\\run_parsers.ps1",
                    args=["-Root", GUEST_ROOT],
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
            phase(
                "collect_outputs",
                lambda: runner.copy_guest_file_to_host_with_vmrun_retries(
                    vmx_path=vm.vmx_path, provider=provider,
                    guest_path=f"{GUEST_ROOT}\\outputs.zip", host_path=outputs_zip,
                ),
            )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            cleanup = phase("stop_and_cleanup", lambda: vm.close(graceful=primary_error is not None))
        except BaseException as cleanup_error:
            if primary_error is None:
                raise
            primary_error.add_note(
                f"Parser VM cleanup failed ({type(cleanup_error).__name__}) at {vm.vmx_path}: {cleanup_error}"
            )
    record = phase(
        "merge_outputs",
        lambda: _merge_outputs(
            outputs_zip=outputs_zip, appliance_dir=appliance_dir, modules_root=modules_root,
            tool_logs=tool_logs, package=package,
        ),
    )
    record.update(
        {
            "schema_version": RECORD_SCHEMA,
            "mode": "run",
            "windows_box": windows_box,
            "provider": provider,
            "guest_root": GUEST_ROOT,
            "vm_cleanup": cleanup,
            "phase_timings": (vm.timings if booted_early else []) + timings,
        }
    )
    write_json(appliance_dir / "parser-appliance-record.json", record)
    return record


def _stage_inputs(*, vmx_path: Path, provider: str, package_path: Path, script_path: Path) -> None:
    runner.create_guest_directory_with_vmrun(vmx_path=vmx_path, provider=provider, guest_path=GUEST_ROOT)
    runner.copy_host_file_to_guest_with_vmrun_retries(
        vmx_path=vmx_path, provider=provider, host_path=package_path,
        guest_path=f"{GUEST_ROOT}\\inputs.zip",
    )
    runner.copy_host_file_to_guest_with_vmrun_retries(
        vmx_path=vmx_path, provider=provider, host_path=script_path,
        guest_path=f"{GUEST_ROOT}\\run_parsers.ps1",
    )


def _merge_outputs(
    *, outputs_zip: Path, appliance_dir: Path, modules_root: Path, tool_logs: Path, package: dict[str, Any]
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
        if source_dir.is_dir():
            for path in sorted(source_dir.rglob("*")):
                if not path.is_file():
                    continue
                relative = path.relative_to(source_dir)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                merged_outputs.append(target.relative_to(modules_root.parent).as_posix())
                if target.suffix.casefold() == ".csv":
                    data_rows += csv_data_row_count(target)
        result["data_row_count"] = data_rows
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
        merged_outputs.append(console.relative_to(modules_root.parent).as_posix())
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
    "ParserVM",
    "build_input_package",
    "matching_inputs",
    "render_guest_arguments",
    "run_parser_appliance",
]
