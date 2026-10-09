from __future__ import annotations

import ctypes
from collections.abc import Callable
from functools import partial
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from fmb.core.errors import ExternalToolError
from fmb.core.hashing import sha256_file
from fmb.core.json_io import write_json as _write_json
from fmb.core.processes import process_output_excerpt

DEFAULT_PROVIDER = "vmware_desktop"
DEFAULT_VMRUN_GUEST_COMMAND_TIMEOUT_SECONDS = 300
DEFAULT_VMRUN_GUEST_COPY_TIMEOUT_SECONDS = 1800
DEFAULT_VMRUN_GUEST_POWERSHELL_TIMEOUT_SECONDS = 300
DEFAULT_VMRUN_GUEST_PROBE_TIMEOUT_SECONDS = 30
DEFAULT_VMRUN_GUEST_COPY_RETRIES = 3
DEFAULT_VMRUN_GUEST_COPY_RETRY_DELAY_SECONDS = 10
MIN_VMWARE_RUNTIME_RESERVE_BYTES = 8 * 1024**3
VMRUN_GUEST_LOGIN = ("-gu", "vagrant", "-gp", "vagrant")
APPLIANCE_VMX_SETTINGS = {
    "tools.upgrade.policy": "manual",
    "tools.syncTime": "FALSE",
    "time.synchronize.allow": "FALSE",
    "time.synchronize.continue": "FALSE",
    "time.synchronize.restore": "FALSE",
    "time.synchronize.resume.disk": "FALSE",
    "time.synchronize.shrink": "FALSE",
    "time.synchronize.tools.startup": "FALSE",
    "time.synchronize.tools.enable": "FALSE",
    "time.synchronize.resume.host": "FALSE",
    "memsize": "8192",
    "numvcpus": "4",
}


class KapeApplianceError(ExternalToolError):
    pass


write_json = partial(_write_json, sort_keys=True)


def encoded_vagrant_box_name(box: str) -> str:
    return box.replace("/", "-VAGRANTSLASH-")


def vagrant_home() -> Path:
    return (
        Path(os.environ.get("VAGRANT_HOME", str(Path.home() / ".vagrant.d")))
        .expanduser()
        .resolve()
    )


def safe_identifier_component(value: str, *, fallback: str = "run") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip(".-")
    return cleaned or fallback


def patch_vmx_key_values(vmx_text: str, settings: dict[str, str]) -> str:
    setting_keys = {key.lower() for key in settings}
    filtered_lines = []
    for line in vmx_text.splitlines():
        if "=" in line:
            key = line.split("=", 1)[0].strip().lower()
            if key in setting_keys:
                continue
        filtered_lines.append(line)
    if filtered_lines and filtered_lines[-1].strip():
        filtered_lines.append("")
    filtered_lines.extend(f'{key} = "{value}"' for key, value in settings.items())
    return "\n".join(filtered_lines) + "\n"


def vmware_removable_media_slots(vmx_text: str) -> set[str]:
    slots: set[str] = set()
    for line in vmx_text.splitlines():
        if "=" not in line:
            continue
        raw_key, raw_value = line.split("=", 1)
        key = raw_key.strip().casefold()
        value = raw_value.strip().strip('"').casefold()
        if ":" not in key or "." not in key:
            continue
        slot, attribute = key.rsplit(".", 1)
        if (attribute == "filename" and value.endswith(".iso")) or (
            attribute == "devicetype" and value == "cdrom-image"
        ):
            slots.add(slot)
    return slots


def disable_stale_vmware_removable_media(vmx_text: str) -> str:
    slots = vmware_removable_media_slots(vmx_text)
    if not slots:
        return vmx_text
    filtered: list[str] = []
    for line in vmx_text.splitlines():
        key = line.split("=", 1)[0].strip().casefold() if "=" in line else ""
        if any(key.startswith(f"{slot}.") for slot in slots):
            continue
        filtered.append(line)
    if filtered and filtered[-1].strip():
        filtered.append("")
    for slot in sorted(slots):
        filtered.extend(
            [
                f'{slot}.present = "FALSE"',
                f'{slot}.startConnected = "FALSE"',
            ]
        )
    return "\n".join(filtered) + "\n"


def vmx_disk_descriptors(vmx_path: Path) -> list[Path]:
    descriptors: list[Path] = []
    for line in vmx_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        raw_key, raw_value = line.split("=", 1)
        key = raw_key.strip().casefold()
        value = raw_value.strip().strip('"')
        if not key.endswith(".filename") or not value.casefold().endswith(".vmdk"):
            continue
        descriptor = Path(value).expanduser()
        if not descriptor.is_absolute():
            descriptor = vmx_path.parent / descriptor
        descriptor = descriptor.resolve()
        if descriptor not in descriptors:
            descriptors.append(descriptor)
    return descriptors


def vmsd_snapshot_count(directory: Path) -> int:
    snapshot_count = 0
    for vmsd_path in directory.glob("*.vmsd"):
        text = vmsd_path.read_text(encoding="utf-8", errors="replace")
        count_match = re.search(r'(?im)^\s*snapshot\.numSnapshots\s*=\s*"?(\d+)', text)
        if count_match:
            snapshot_count += int(count_match.group(1))
        elif re.search(r"(?im)^\s*snapshot\d+\.", text):
            snapshot_count += 1
    return snapshot_count


def vmware_disk_descriptors_from_vmx(vmx_path: Path) -> list[Path]:
    vmx_path = vmx_path.expanduser().resolve()
    if not vmx_path.is_file():
        raise KapeApplianceError(f"VMware source VMX does not exist: {vmx_path}")
    descriptors = vmx_disk_descriptors(vmx_path)
    if not descriptors:
        raise KapeApplianceError(f"VMware source VMX has no VMDK disk: {vmx_path}")
    return descriptors


def assert_flat_vmware_source(vmx_path: Path) -> dict[str, Any]:
    vmx_path = vmx_path.expanduser().resolve()
    locks = sorted(str(path) for path in vmx_path.parent.glob("*.lck"))
    if locks:
        raise KapeApplianceError(
            "VMware source has lock directories/files and is not cleanly reusable: "
            + ", ".join(locks)
        )
    descriptors = vmware_disk_descriptors_from_vmx(vmx_path)
    for descriptor in descriptors:
        if not descriptor.is_file():
            raise KapeApplianceError(
                f"VMware source disk descriptor does not exist: {descriptor}"
            )
        descriptor_text = descriptor.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?im)^\s*parentFileNameHint\s*=", descriptor_text):
            raise KapeApplianceError(
                f"VMware source disk has a backing parent: {descriptor}"
            )
        parent_cid = re.search(
            r'(?im)^\s*parentCID\s*=\s*"?([0-9a-f]+)"?\s*$',
            descriptor_text,
        )
        if parent_cid and parent_cid.group(1).casefold() != "ffffffff":
            raise KapeApplianceError(
                f"VMware source disk has a non-flat parent CID: {descriptor}"
            )
        if re.search(r"-\d{6}\.vmdk$", descriptor.name, re.IGNORECASE):
            raise KapeApplianceError(
                f"VMware source VMX selects a snapshot disk: {descriptor}"
            )
    snapshot_count = vmsd_snapshot_count(vmx_path.parent)
    if snapshot_count:
        raise KapeApplianceError(
            f"VMware source has {snapshot_count} snapshot(s); a flat source is required"
        )
    return {
        "vmx_path": str(vmx_path),
        "disk_descriptors": [str(path) for path in descriptors],
        "snapshot_count": snapshot_count,
        "locks": locks,
    }


def assert_isolated_vmware_worker(vmx_path: Path) -> dict[str, Any]:

    vmx_path = vmx_path.expanduser().resolve()
    report = assert_flat_vmware_source(vmx_path)
    worker_root = vmx_path.parent
    for raw_descriptor in report["disk_descriptors"]:
        descriptor = Path(raw_descriptor).resolve()
        try:
            descriptor.relative_to(worker_root)
        except ValueError as error:
            raise KapeApplianceError(
                "VMware worker disk is outside its isolated run directory: "
                f"{descriptor}"
            ) from error
    return report


def allocated_tree_bytes(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        stat = path.stat()
        blocks = getattr(stat, "st_blocks", 0)
        total += blocks * 512 if blocks else stat.st_size
    return total


def preflight_vmware_runtime(
    *, plan: dict[str, Any], source_vmx: Path, stage_dir: Path,
    apfs_clone: bool = False,
    receipt_dir: Path | None = None,
) -> dict[str, Any]:
    stage_dir = stage_dir.expanduser().resolve()
    source_root = source_vmx.expanduser().resolve().parent
    if apfs_clone and (stage_dir.is_relative_to(source_root) or source_root.is_relative_to(stage_dir)):
        raise KapeApplianceError("APFS worker directory overlaps its protected source")
    metadata_dir = receipt_dir.expanduser().resolve() if receipt_dir is not None else stage_dir
    if apfs_clone and metadata_dir.is_relative_to(source_root):
        raise KapeApplianceError("APFS worker metadata overlaps its protected source")
    stage_dir.mkdir(parents=True, exist_ok=True)
    source_allocated_bytes = allocated_tree_bytes(source_vmx.parent)
    if apfs_clone and (sys.platform != "darwin" or source_vmx.stat().st_dev != stage_dir.stat().st_dev):
        raise KapeApplianceError("APFS worker files must share the source's macOS filesystem")
    required_free_bytes = MIN_VMWARE_RUNTIME_RESERVE_BYTES + (0 if apfs_clone else source_allocated_bytes)
    usage = shutil.disk_usage(stage_dir)
    status = "passed" if usage.free >= required_free_bytes else "failed"
    report = {
        "schema_version": "vmware_runtime_preflight.v1",
        "status": status,
        "source_vmx": str(source_vmx.expanduser().resolve()),
        "source_allocated_bytes": source_allocated_bytes,
        "kape_archive_size_bytes": 0,
        "runtime_reserve_bytes": MIN_VMWARE_RUNTIME_RESERVE_BYTES,
        "required_free_bytes": required_free_bytes,
        "available_free_bytes": usage.free,
        "destination_volume_path": str(stage_dir),
        "working_vmx": str(stage_dir / ".vmrun-appliance" / "box.vmx"),
        "evidence_size_bytes": plan.get("evidence", {}).get("size_bytes"),
        "transport": plan.get("transport", {}).get("strategy"),
    }
    if apfs_clone:
        report["copy_method"] = "independent_apfs_clonefiles_no_fallback"
    if not metadata_dir.is_dir():
        raise FileNotFoundError(str(metadata_dir))
    write_json(metadata_dir / "vmware_runtime_preflight.json", report)
    if status == "failed":
        raise KapeApplianceError(
            "insufficient free space for an isolated VMware analysis worker: "
            f"required={required_free_bytes} available={usage.free}"
        )
    return report


def clone_apfs_worker_files(
    source_vmx: Path, destination_vmx: Path, *, receipt_dir: Path | None = None,
) -> None:
    if sys.platform != "darwin":
        raise KapeApplianceError("APFS worker cloning requires macOS")
    source_vmx = source_vmx.resolve()
    destination_vmx = destination_vmx.resolve()
    source_root, destination = source_vmx.parent, destination_vmx.parent
    if destination.is_relative_to(source_root) or source_root.is_relative_to(destination):
        raise KapeApplianceError("APFS worker directory overlaps its protected source")
    metadata_dir = receipt_dir.expanduser().resolve() if receipt_dir is not None else destination.parent
    if metadata_dir.is_relative_to(source_root):
        raise KapeApplianceError("APFS worker metadata overlaps its protected source")
    assert_flat_vmware_source(source_vmx)
    if destination.exists():
        raise KapeApplianceError("APFS worker clone destination already exists")
    destination.mkdir(parents=True, exist_ok=False)
    if source_root.stat().st_dev != destination.stat().st_dev:
        raise KapeApplianceError("APFS source and worker are on different filesystems")
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    library.clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    library.clonefile.restype = ctypes.c_int
    copied = []
    started = time.monotonic()
    for source in sorted(source_root.rglob("*")):
        target = destination / source.relative_to(source_root)
        if source.is_symlink():
            raise KapeApplianceError("APFS source closure contains a symlink")
        if source.is_dir():
            target.mkdir(exist_ok=True)
            continue
        if not source.is_file():
            raise KapeApplianceError("APFS source closure contains a non-file")
        target.parent.mkdir(parents=True, exist_ok=True)
        if library.clonefile(os.fsencode(source), os.fsencode(target), 0):
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(target))
        if source.stat().st_ino == target.stat().st_ino:
            raise KapeApplianceError("worker shares a writable file identity with its source")
        digest = sha256_file(target)
        if digest != sha256_file(source):
            raise KapeApplianceError("APFS worker read-back hash mismatch")
        copied.append({"path": source.relative_to(source_root).as_posix(), "sha256": digest,
                       "size_bytes": source.stat().st_size})
    original_vmx = destination / source_vmx.name
    if original_vmx != destination_vmx:
        original_vmx.rename(destination_vmx)
    report = assert_isolated_vmware_worker(destination_vmx)
    for raw in report["disk_descriptors"]:
        descriptor = Path(raw)
        text = descriptor.read_text()
        for extent in re.findall(r'(?m)^\s*(?:RW|RDONLY|NOACCESS)\s+\d+\s+\S+\s+"([^"]+)"', text):
            if not (descriptor.parent / extent).resolve().is_relative_to(destination):
                raise KapeApplianceError("worker extent lies outside its isolated directory")
    destination_vmx.write_text(patch_vmx_key_values(destination_vmx.read_text(), {
        "uuid.action": "create", "msg.autoanswer": "TRUE",
    }))
    if not metadata_dir.is_dir():
        raise FileNotFoundError(str(metadata_dir))
    write_json(metadata_dir / "apfs-worker-clone.json", {
        "schema_version": "apfs_worker_clone.v1", "status": "verified",
        "source_vmx": str(source_vmx), "working_vmx": str(destination_vmx),
        "copy_method": "independent_apfs_clonefiles_no_fallback",
        "elapsed_seconds": time.monotonic() - started, "files": copied,
    })


def apply_appliance_vmx_settings(vmx_path: Path) -> None:
    vmx_text = disable_stale_vmware_removable_media(
        vmx_path.read_text(encoding="utf-8")
    )
    vmx_path.write_text(
        patch_vmx_key_values(vmx_text, APPLIANCE_VMX_SETTINGS),
        encoding="utf-8",
    )


def run_checked(
    command: list[str], *, cwd: Path, timeout_seconds: int | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            timeout=timeout_seconds,
            text=True,
            capture_output=True,
        )
    except subprocess.TimeoutExpired as error:
        output_excerpt = process_output_excerpt(error.stdout, error.stderr)
        suffix = f": {output_excerpt}" if output_excerpt else ""
        raise KapeApplianceError(
            f"command timed out after {timeout_seconds}s: {' '.join(command)}{suffix}"
        ) from error
    if completed.returncode != 0:
        output_excerpt = process_output_excerpt(completed.stdout, completed.stderr)
        suffix = f": {output_excerpt}" if output_excerpt else ""
        raise KapeApplianceError(
            f"command failed with exit {completed.returncode}: {' '.join(command)}{suffix}"
        )
    return completed


def vmrun_target_for_provider(provider: str) -> str:
    if provider == DEFAULT_PROVIDER:
        return "fusion" if sys.platform == "darwin" else "ws"
    raise KapeApplianceError(f"unsupported vmrun provider target for {provider}")


def vmrun_executable() -> str:
    located = shutil.which("vmrun")
    if located:
        return located
    if sys.platform == "darwin":
        fusion_vmrun = Path("/Applications/VMware Fusion.app/Contents/Public/vmrun")
        if fusion_vmrun.is_file():
            return str(fusion_vmrun)
    return "vmrun"


def vmrun_command(provider: str, *args: str) -> list[str]:
    return [vmrun_executable(), "-T", vmrun_target_for_provider(provider), *args]


def completed_process_is_vmware_tools_unavailable(
    completed: subprocess.CompletedProcess[str],
) -> bool:
    return (
        completed.returncode == 255
        and "tools are not running"
        in process_output_excerpt(completed.stdout, completed.stderr).lower()
    )


def copy_guest_file_to_host_with_vmrun(
    *,
    vmx_path: Path,
    provider: str,
    guest_path: str,
    host_path: Path,
    timeout_seconds: int | None = DEFAULT_VMRUN_GUEST_COPY_TIMEOUT_SECONDS,
) -> Path:
    host_path = host_path.expanduser().resolve()
    host_path.parent.mkdir(parents=True, exist_ok=True)
    command = vmrun_command(
        provider,
        *VMRUN_GUEST_LOGIN,
        "CopyFileFromGuestToHost",
        str(vmx_path.expanduser().resolve()),
        guest_path,
        str(host_path),
    )
    run_checked(command, cwd=host_path.parent, timeout_seconds=timeout_seconds)
    if not host_path.is_file():
        raise KapeApplianceError(
            f"guest package copy did not create host file: {host_path}"
        )
    return host_path


def _copy_with_vmrun_retries(
    label: str, copy: Callable[[], Any], *, vmx_path: Path, provider: str
) -> Any:
    errors: list[str] = []
    attempts = DEFAULT_VMRUN_GUEST_COPY_RETRIES
    for attempt in range(1, attempts + 1):
        try:
            return copy()
        except KapeApplianceError as error:
            errors.append(f"attempt {attempt}: {error}")
            if attempt < attempts:
                try:
                    wait_for_vmrun_guest(
                        vmx_path=vmx_path, provider=provider, timeout_seconds=300
                    )
                except KapeApplianceError as wait_error:
                    errors.append(f"attempt {attempt} tools wait: {wait_error}")
                time.sleep(DEFAULT_VMRUN_GUEST_COPY_RETRY_DELAY_SECONDS)
    raise KapeApplianceError(f"{label} failed after retries: " + " | ".join(errors))


def copy_guest_file_to_host_with_vmrun_retries(
    *, vmx_path: Path, provider: str, guest_path: str, host_path: Path
) -> Path:
    return _copy_with_vmrun_retries(
        "guest file copy",
        lambda: copy_guest_file_to_host_with_vmrun(
            vmx_path=vmx_path, provider=provider, guest_path=guest_path, host_path=host_path
        ),
        vmx_path=vmx_path,
        provider=provider,
    )


def vmrun_guest_command(
    *,
    vmx_path: Path,
    provider: str,
    command: str,
    args: list[str],
    check: bool = True,
    timeout_seconds: int | None = DEFAULT_VMRUN_GUEST_COMMAND_TIMEOUT_SECONDS,
    retry_tools_unavailable: bool = True,
) -> subprocess.CompletedProcess[str]:
    command_line = vmrun_command(
        provider, *VMRUN_GUEST_LOGIN, command, str(vmx_path.expanduser().resolve()), *args
    )

    def run_once() -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command_line,
                cwd=vmx_path.expanduser().resolve().parent,
                check=False,
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            raise KapeApplianceError(
                f"vmrun {command} timed out after {timeout_seconds}s"
            ) from error

    completed = run_once()
    if retry_tools_unavailable and completed_process_is_vmware_tools_unavailable(
        completed
    ):
        wait_for_vmrun_guest(vmx_path=vmx_path, provider=provider, timeout_seconds=300)
        completed = run_once()
    if check and completed.returncode != 0:
        detail = process_output_excerpt(completed.stdout, completed.stderr)
        suffix = f": {detail}" if detail else ""
        raise KapeApplianceError(
            f"vmrun {command} failed with exit {completed.returncode}{suffix}"
        )
    return completed


def wait_for_vmrun_guest(
    *,
    vmx_path: Path,
    provider: str,
    timeout_seconds: int = 600,
    poll_seconds: int = 5,
    probe_timeout_seconds: int = DEFAULT_VMRUN_GUEST_PROBE_TIMEOUT_SECONDS,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: KapeApplianceError | None = None
    while time.monotonic() < deadline:
        try:
            completed = vmrun_guest_command(
                vmx_path=vmx_path,
                provider=provider,
                command="listDirectoryInGuest",
                args=["C:\\"],
                check=False,
                timeout_seconds=probe_timeout_seconds,
                retry_tools_unavailable=False,
            )
        except KapeApplianceError as error:
            last_error = error
            time.sleep(poll_seconds)
            continue
        if completed.returncode == 0:
            return
        time.sleep(poll_seconds)
    detail = f"; last probe error: {last_error}" if last_error else ""
    raise KapeApplianceError(
        f"VMware Tools did not become guest-ready within {timeout_seconds}s{detail}"
    )


def vmrun_start(*, vmx_path: Path, provider: str) -> None:
    run_checked(
        vmrun_command(provider, "start", str(vmx_path), "nogui"),
        cwd=vmx_path.parent,
        timeout_seconds=DEFAULT_VMRUN_GUEST_COMMAND_TIMEOUT_SECONDS,
    )


def vmrun_is_running(*, vmx_path: Path, provider: str) -> bool:
    vmx_text = str(vmx_path.expanduser().resolve())
    executable = vmrun_executable()
    listed = run_checked(
        [executable, "-T", vmrun_target_for_provider(provider), "list"],
        cwd=vmx_path.parent,
        timeout_seconds=DEFAULT_VMRUN_GUEST_PROBE_TIMEOUT_SECONDS,
    )
    if any(line.strip() == vmx_text for line in listed.stdout.splitlines()):
        return True
    if sys.platform != "darwin":
        return False
    vmware_executable = str(Path(executable).resolve().with_name("vmware-vmx"))
    processes = run_checked(
        ["/bin/ps", "-ww", "-axo", "pid=,ruid=,uid=,args="],
        cwd=vmx_path.parent,
        timeout_seconds=15,
    )
    for line in processes.stdout.splitlines():
        fields = line.split(None, 3)
        if len(fields) == 4:
            host_command = fields[3]
            if (host_command.startswith(vmware_executable + " ")
                    and host_command.endswith(" " + vmx_text)):
                return True
    return False


def vagrant_box_vmx_path(*, box: str, provider: str) -> Path:
    encoded_box = encoded_vagrant_box_name(box)
    box_root = vagrant_home() / "boxes" / encoded_box
    candidates = sorted(box_root.glob(f"*/**/{provider}/box.vmx"))
    if not candidates:
        raise KapeApplianceError(
            f"Vagrant box VMX not found for {box!r} provider {provider!r}"
        )
    return candidates[-1].expanduser().resolve()


def ensure_vagrant_box_vmx_path(*, box: str, provider: str) -> Path:
    try:
        return vagrant_box_vmx_path(box=box, provider=provider)
    except KapeApplianceError as error:
        raise KapeApplianceError(
            f"local Vagrant box {box!r} is not installed for provider {provider!r}. "
            "Install or configure a local Windows appliance box with --windows-box."
        ) from error


def clone_vagrant_box_for_vmrun(
    *, plan: dict[str, Any], stage_dir: Path, provider: str,
    vm_work_dir: Path | None = None,
) -> Path:
    worker_dir = stage_dir if vm_work_dir is None else vm_work_dir.expanduser().resolve()
    vmx_path = worker_dir / ".vmrun-appliance" / "box.vmx"
    apfs_clone = vm_work_dir is not None
    if apfs_clone and vmx_path.parent.exists():
        raise KapeApplianceError("refusing to adopt an existing APFS worker directory")
    source_vmx = ensure_vagrant_box_vmx_path(
        box=str(plan["worker"]["windows_box"]), provider=provider
    )
    assert_flat_vmware_source(source_vmx)
    if vmrun_is_running(vmx_path=source_vmx, provider=provider):
        raise KapeApplianceError(
            f"VMware source VM is running and cannot be cloned safely: {source_vmx}"
        )
    preflight_vmware_runtime(
        plan=plan,
        source_vmx=source_vmx,
        stage_dir=worker_dir,
        apfs_clone=apfs_clone,
        receipt_dir=stage_dir if apfs_clone else None,
    )
    if apfs_clone:
        clone_apfs_worker_files(source_vmx, vmx_path, receipt_dir=stage_dir)
        apply_appliance_vmx_settings(vmx_path)
        return vmx_path
    vmx_path.parent.mkdir(parents=True, exist_ok=True)
    run_checked(
        vmrun_command(
            provider,
            "clone",
            str(source_vmx),
            str(vmx_path),
            "full",
            f"-cloneName={safe_identifier_component(str(plan['run_id']))}",
        ),
        cwd=stage_dir,
        timeout_seconds=3600,
    )
    assert_isolated_vmware_worker(vmx_path)
    apply_appliance_vmx_settings(vmx_path)
    return vmx_path


def vmrun_stop(
    *, vmx_path: Path, provider: str, soft_timeout_seconds: int = 120
) -> None:
    try:
        completed = subprocess.run(
            vmrun_command(provider, "stop", str(vmx_path), "soft"),
            cwd=vmx_path.parent,
            check=False,
            capture_output=True,
            text=True,
            timeout=soft_timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise KapeApplianceError(
            f"graceful VMware stop timed out after {soft_timeout_seconds}s; "
            "refusing an implicit hard stop"
        ) from error
    if completed.returncode != 0:
        detail = process_output_excerpt(completed.stdout, completed.stderr)
        suffix = f": {detail}" if detail else ""
        raise KapeApplianceError(
            "graceful VMware stop failed; refusing an implicit hard stop" + suffix
        )


def vmrun_hard_stop(*, vmx_path: Path, provider: str) -> None:
    run_checked(
        vmrun_command(provider, "stop", str(vmx_path), "hard"),
        cwd=vmx_path.parent,
        timeout_seconds=120,
    )


def vmrun_start_and_wait(
    *,
    vmx_path: Path,
    provider: str,
    timeout_seconds: int = 600,
) -> None:
    if not vmrun_is_running(vmx_path=vmx_path, provider=provider):
        vmrun_start(vmx_path=vmx_path, provider=provider)
    wait_for_vmrun_guest(
        vmx_path=vmx_path,
        provider=provider,
        timeout_seconds=timeout_seconds,
    )


def cleanup_disposable_appliance_vm(*, vmx_path: Path, provider: str) -> dict[str, Any]:
    vmx_path = vmx_path.expanduser().resolve()
    appliance_dir = vmx_path.parent
    if appliance_dir.name != ".vmrun-appliance":
        raise KapeApplianceError(
            f"refusing to clean unexpected VM directory: {appliance_dir}"
        )
    if appliance_dir.exists():
        if vmrun_is_running(vmx_path=vmx_path, provider=provider):
            try:
                vmrun_stop(vmx_path=vmx_path, provider=provider)
            except KapeApplianceError:
                vmrun_hard_stop(vmx_path=vmx_path, provider=provider)
            if vmrun_is_running(vmx_path=vmx_path, provider=provider):
                raise KapeApplianceError(
                    f"VMware worker remains running after stop; refusing cleanup: {vmx_path}"
                )
        shutil.rmtree(appliance_dir)
    return {
        "removed": True,
        "path": str(appliance_dir),
        "policy": "delete_disposable_appliance_vm_after_success_preserve_evidence_and_bundles",
    }


def copy_host_file_to_guest_with_vmrun(
    *,
    vmx_path: Path,
    provider: str,
    host_path: Path,
    guest_path: str,
    timeout_seconds: int | None = DEFAULT_VMRUN_GUEST_COPY_TIMEOUT_SECONDS,
) -> None:
    vmrun_guest_command(
        vmx_path=vmx_path,
        provider=provider,
        command="CopyFileFromHostToGuest",
        args=[str(host_path.expanduser().resolve()), guest_path],
        timeout_seconds=timeout_seconds,
    )


def copy_host_file_to_guest_with_vmrun_retries(
    *, vmx_path: Path, provider: str, host_path: Path, guest_path: str
) -> None:
    _copy_with_vmrun_retries(
        "host file copy",
        lambda: copy_host_file_to_guest_with_vmrun(
            vmx_path=vmx_path, provider=provider, host_path=host_path, guest_path=guest_path
        ),
        vmx_path=vmx_path,
        provider=provider,
    )


def create_guest_directory_with_vmrun(
    *,
    vmx_path: Path,
    provider: str,
    guest_path: str,
    timeout_seconds: int | None = DEFAULT_VMRUN_GUEST_COMMAND_TIMEOUT_SECONDS,
) -> None:
    vmrun_guest_command(
        vmx_path=vmx_path,
        provider=provider,
        command="createDirectoryInGuest",
        args=[guest_path],
        check=False,
        timeout_seconds=timeout_seconds,
    )


def run_powershell_file_with_vmrun(
    *,
    vmx_path: Path,
    provider: str,
    script_path: str,
    args: list[str] | None = None,
    check: bool = True,
    timeout_seconds: int | None = DEFAULT_VMRUN_GUEST_POWERSHELL_TIMEOUT_SECONDS,
    retry_tools_unavailable: bool = True,
) -> subprocess.CompletedProcess[str]:
    return vmrun_guest_command(
        vmx_path=vmx_path,
        provider=provider,
        command="runProgramInGuest",
        args=[
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script_path,
            *(args or []),
        ],
        check=check,
        timeout_seconds=timeout_seconds,
        retry_tools_unavailable=retry_tools_unavailable,
    )
