from argparse import Namespace
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
from types import SimpleNamespace

import pytest

from fmb.collection.tools.host import parser_appliance as appliance
from fmb.collection.tools.host import vmware


@pytest.fixture
def parser_case(tmp_path, monkeypatch):
    source = tmp_path / "protected-source" / "box.vmx"
    source.parent.mkdir()
    source.write_text('memsize = "2048"\nnumvcpus = "1"\n')
    stage = tmp_path / "analysis"
    stage.mkdir()
    modules = stage / "modules"
    logs = stage / "logs"
    modules.mkdir()
    logs.mkdir()
    calls = []

    def package(*, package_path, **kwargs):
        package_path.write_bytes(b"pinned test inputs")
        return {"package": str(package_path), "package_sha256": hashlib.sha256(package_path.read_bytes()).hexdigest(),
                "input_file_count": 1, "commands": [{"label": "PECmd"}]}

    def clone(*, plan, stage_dir, provider, vm_work_dir=None):
        owner = stage_dir if vm_work_dir is None else vm_work_dir
        vmx = owner / ".vmrun-appliance" / "box.vmx"
        vmx.parent.mkdir()
        (vmx.parent / "partial.vmdk").write_bytes(b"independent temporary disk")
        vmx.write_bytes(source.read_bytes())
        vmware.apply_appliance_vmx_settings(vmx)
        calls.append({"vmx": vmx, "owner": owner, "plan": plan, "settings": vmx.read_text()})
        return vmx

    def outputs(*, host_path, **kwargs):
        host_path.write_bytes(b"returned test outputs")

    monkeypatch.setattr(appliance, "build_input_package", package)
    monkeypatch.setattr(appliance, "assert_no_running_vm", lambda provider: None)
    monkeypatch.setattr(vmware, "ensure_vagrant_box_vmx_path", lambda **kwargs: source)
    monkeypatch.setattr(vmware, "clone_vagrant_box_for_vmrun", clone)
    monkeypatch.setattr(vmware, "vmrun_start_and_wait", lambda **kwargs: None)
    monkeypatch.setattr(vmware, "vmrun_is_running", lambda **kwargs: False)
    monkeypatch.setattr(appliance, "_stage_inputs", lambda **kwargs: None)
    monkeypatch.setattr(vmware, "run_powershell_command_with_vmrun", lambda **kwargs: subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(vmware, "copy_guest_file_to_host_with_vmrun_retries", outputs)
    monkeypatch.setattr(appliance, "_merge_outputs", lambda **kwargs: {"status": "completed"})

    def run(work_root=None):
        return appliance.run_parser_appliance(
            processors=[object()],
            args=Namespace(vm_work_root=work_root, run_id="analysis", windows_parsers=str(tmp_path / "windows-parsers"),
                           collection_provider="vmware_desktop", windows_box="fmb/windows-11-arm64"),
            stage_dir=stage, targets_root=stage / "targets", modules_root=modules, tool_logs=logs,
        )

    return SimpleNamespace(source=source, stage=stage, calls=calls, run=run,
                           work_root=tmp_path / "vm-work", clone=clone)


@pytest.mark.parametrize("relocated", [False, True])
def test_parser_success_preserves_resources_and_removes_only_owned_clone(parser_case, monkeypatch, relocated):
    monkeypatch.setenv("FMB_APFS_WORKER_CLONE", "1")
    before = parser_case.source.read_bytes()
    result = parser_case.run(parser_case.work_root if relocated else None)
    call = parser_case.calls[0]
    assert 'memsize = "8192"' in call["settings"]
    assert 'numvcpus = "4"' in call["settings"]
    assert result["status"] == "completed" and result["vm_cleanup"]["removed"] is True
    assert not call["vmx"].parent.exists()
    if relocated:
        assert call["owner"].parent == parser_case.work_root
        assert not call["owner"].exists() and list(parser_case.work_root.iterdir()) == []
    else:
        assert call["owner"] == parser_case.stage / appliance.APPLIANCE_DIR_NAME
    assert (parser_case.stage / appliance.APPLIANCE_DIR_NAME / "parser-appliance-record.json").is_file()
    assert parser_case.source.read_bytes() == before


@pytest.mark.parametrize("boundary", ["clone", "start", "external_output_loss"])
def test_parser_failure_cleans_exact_relocated_owner_and_preserves_primary(parser_case, monkeypatch, boundary):
    primary = RuntimeError("initiating parser failure")

    def fail(**kwargs):
        if boundary == "clone":
            parser_case.clone(**kwargs)
        if boundary == "external_output_loss":
            shutil.rmtree(parser_case.stage)
        raise primary

    target = {"clone": (vmware, "clone_vagrant_box_for_vmrun"),
              "start": (vmware, "vmrun_start_and_wait"),
              "external_output_loss": (appliance, "_stage_inputs")}[boundary]
    monkeypatch.setattr(*target, fail)
    before = parser_case.source.read_bytes()
    with pytest.raises(RuntimeError) as error:
        parser_case.run(parser_case.work_root)
    assert error.value is primary
    assert list(parser_case.work_root.iterdir()) == []
    assert parser_case.source.read_bytes() == before


def test_unknown_cleanup_retains_exact_owner_and_original_error(parser_case, monkeypatch):
    primary = KeyboardInterrupt("requested stop")

    def fail_start(**kwargs):
        raise primary

    def uncertain_cleanup(**kwargs):
        raise vmware.KapeApplianceError("worker state unavailable")

    monkeypatch.setattr(vmware, "vmrun_start_and_wait", fail_start)
    monkeypatch.setattr(vmware, "cleanup_disposable_appliance_vm", uncertain_cleanup)
    with pytest.raises(KeyboardInterrupt) as error:
        parser_case.run(parser_case.work_root)
    assert error.value is primary
    assert parser_case.calls[0]["vmx"].is_file()
    assert "worker state unavailable" in " ".join(primary.__notes__)


def test_cleanup_failure_without_primary_is_not_success(parser_case, monkeypatch):
    def uncertain_cleanup(**kwargs):
        raise vmware.KapeApplianceError("worker state unavailable")

    monkeypatch.setattr(vmware, "cleanup_disposable_appliance_vm", uncertain_cleanup)
    with pytest.raises(vmware.KapeApplianceError, match="worker state unavailable"):
        parser_case.run(parser_case.work_root)
    assert parser_case.calls[0]["vmx"].is_file()


@pytest.mark.parametrize("overlap", ["source", "ancestor"])
def test_parser_work_root_overlap_writes_nothing_to_source(parser_case, overlap):
    before = parser_case.source.read_bytes()
    root = parser_case.source.parent if overlap == "source" else parser_case.source.parent.parent
    with pytest.raises(appliance.ParserApplianceError, match="overlaps"):
        parser_case.run(root)
    assert parser_case.source.read_bytes() == before and parser_case.calls == []
    assert sorted(p.name for p in parser_case.source.parent.iterdir()) == ["box.vmx"]


def test_parser_does_not_adopt_or_delete_preexisting_worker(parser_case):
    existing = parser_case.stage / appliance.APPLIANCE_DIR_NAME / ".vmrun-appliance"
    existing.mkdir(parents=True)
    sentinel = existing / "preexisting.vmdk"
    sentinel.write_bytes(b"preserve another owner")
    with pytest.raises(appliance.ParserApplianceError, match="existing parser VM"):
        parser_case.run()
    assert sentinel.read_bytes() == b"preserve another owner" and parser_case.calls == []


@pytest.mark.parametrize("mode", ["copy", "hardlink", "corrupt", "unsupported"])
def test_apfs_clone_checks_file_identity_bytes_and_refuses_fallback(tmp_path, monkeypatch, mode):
    source = tmp_path / "source" / "box.vmx"
    source.parent.mkdir()
    source.write_text('memsize = "8192"\n')
    disk = source.with_name("disk.vmdk")
    disk.write_bytes(b"independent public disk bytes")
    destination = tmp_path / "worker" / ".vmrun-appliance" / "box.vmx"
    destination.parent.parent.mkdir()
    metadata = tmp_path / "analysis"
    metadata.mkdir()
    before = {p.name: p.read_bytes() for p in source.parent.iterdir()}

    def clonefile(old, new, flags):
        if mode == "unsupported":
            ctypes.set_errno(errno.EOPNOTSUPP)
            return -1
        if mode == "hardlink":
            os.link(os.fsdecode(old), os.fsdecode(new))
        elif mode == "corrupt":
            Path(os.fsdecode(new)).write_bytes(b"corrupted")
        else:
            shutil.copyfile(os.fsdecode(old), os.fsdecode(new))
        return 0

    monkeypatch.setattr(vmware.sys, "platform", "darwin")
    monkeypatch.setattr(vmware.ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace(clonefile=clonefile))
    monkeypatch.setattr(vmware, "assert_flat_vmware_source", lambda path: None)
    monkeypatch.setattr(vmware, "assert_isolated_vmware_worker", lambda path: {"disk_descriptors": []})
    if mode == "copy":
        vmware.clone_apfs_worker_files(source, destination, receipt_dir=metadata)
        assert destination.with_name("disk.vmdk").read_bytes() == before["disk.vmdk"]
        assert disk.stat().st_ino != destination.with_name("disk.vmdk").stat().st_ino
        receipt = json.loads((metadata / "apfs-worker-clone.json").read_text())
        assert receipt["status"] == "verified" and receipt["files"] == [
            {"path": name, "sha256": hashlib.sha256(before[name]).hexdigest(), "size_bytes": len(before[name])}
            for name in sorted(before)]
    else:
        with pytest.raises((vmware.KapeApplianceError, OSError)):
            vmware.clone_apfs_worker_files(source, destination, receipt_dir=metadata)
        assert not (metadata / "apfs-worker-clone.json").exists()
    assert {p.name: p.read_bytes() for p in source.parent.iterdir()} == before


@pytest.mark.parametrize("later", ["clone", "hash"])
def test_apfs_clone_reports_the_first_failing_file_in_order(tmp_path, monkeypatch, later):
    # box.vmx, the first file, clones corrupt; disk.vmdk, the last, fails before it is checked: its clone or its hash.
    source = tmp_path / "source" / "box.vmx"
    source.parent.mkdir()
    source.write_text('memsize = "8192"\n')
    source.with_name("disk.vmdk").write_bytes(b"independent public disk bytes")
    destination = tmp_path / "worker" / ".vmrun-appliance" / "box.vmx"
    destination.parent.parent.mkdir()
    real, later_failed = vmware.sha256_file, threading.Event()

    def clonefile(old, new, flags):
        old, new = Path(os.fsdecode(old)), Path(os.fsdecode(new))
        if old.name == "disk.vmdk" and later == "clone":
            later_failed.set()
            ctypes.set_errno(errno.EOPNOTSUPP)
            return -1
        new.write_bytes(b"corrupted" if old.name == "box.vmx" else old.read_bytes())
        return 0

    def sha256_file(path):
        if path.name == "disk.vmdk" and ".vmrun-appliance" in path.parts:
            later_failed.set()
            raise OSError(errno.EIO, "read failed", str(path))
        if path.name == "box.vmx":
            later_failed.wait(5)
        return real(path)

    monkeypatch.setattr(vmware.sys, "platform", "darwin")
    monkeypatch.setattr(vmware.ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace(clonefile=clonefile))
    monkeypatch.setattr(vmware, "assert_flat_vmware_source", lambda path: None)
    monkeypatch.setattr(vmware, "sha256_file", sha256_file)
    with pytest.raises(vmware.KapeApplianceError, match="read-back hash mismatch"):
        vmware.clone_apfs_worker_files(source, destination, receipt_dir=tmp_path)
    assert not (tmp_path / "apfs-worker-clone.json").exists()


def test_apfs_overlap_is_refused_before_source_scan(tmp_path, monkeypatch):
    source = tmp_path / "source" / "box.vmx"
    source.parent.mkdir()
    source.write_text("protected")
    scanned = []
    monkeypatch.setattr(vmware.sys, "platform", "darwin")
    monkeypatch.setattr(vmware, "assert_flat_vmware_source", lambda path: scanned.append(path))
    with pytest.raises(vmware.KapeApplianceError, match="overlaps"):
        vmware.clone_apfs_worker_files(source, source.parent / ".vmrun-appliance" / "box.vmx")
    assert scanned == [] and not (source.parent / ".vmrun-appliance").exists()


@pytest.mark.parametrize("relocated", [False, True])
def test_vmware_clone_selection_uses_only_explicit_work_directory(tmp_path, monkeypatch, relocated):
    source = tmp_path / "source" / "box.vmx"
    source.parent.mkdir()
    source.write_text('memsize = "2048"\nnumvcpus = "1"\n')
    stage = tmp_path / "analysis"
    stage.mkdir()
    work = tmp_path / "fresh-owner"
    calls = []
    preflight = []
    monkeypatch.setenv("FMB_APFS_WORKER_CLONE", "1")
    monkeypatch.setattr(vmware, "ensure_vagrant_box_vmx_path", lambda **kw: source)
    monkeypatch.setattr(vmware, "assert_flat_vmware_source", lambda path: None)
    monkeypatch.setattr(vmware, "vmrun_is_running", lambda **kw: False)
    monkeypatch.setattr(vmware, "preflight_vmware_runtime", lambda **kw: preflight.append(kw))
    monkeypatch.setattr(vmware, "vmrun_executable", lambda: "mock-vmrun")
    monkeypatch.setattr(vmware, "assert_isolated_vmware_worker", lambda path: {})

    def apfs_clone(old, new, *, receipt_dir):
        calls.append(("apfs", receipt_dir))
        new.parent.mkdir(parents=True)
        new.write_bytes(old.read_bytes())

    def full_clone(command, **kwargs):
        calls.append(("full", kwargs))
        assert command[3] == "clone" and command[6] == "full"
        assert kwargs["timeout_seconds"] == 3600
        Path(command[5]).write_bytes(source.read_bytes())

    monkeypatch.setattr(vmware, "clone_apfs_worker_files", apfs_clone)
    monkeypatch.setattr(vmware, "run_checked", full_clone)
    before = source.read_bytes()
    result = vmware.clone_vagrant_box_for_vmrun(
        plan={"run_id": "test", "worker": {"windows_box": "fmb/windows-11-arm64"}},
        stage_dir=stage, provider="vmware_desktop", vm_work_dir=work if relocated else None,
    )
    assert [call[0] for call in calls] == ["apfs" if relocated else "full"]
    assert preflight[0]["stage_dir"] == (work if relocated else stage)
    assert preflight[0]["receipt_dir"] == (stage if relocated else None)
    assert preflight[0]["apfs_clone"] is relocated
    assert 'memsize = "8192"' in result.read_text() and 'numvcpus = "4"' in result.read_text()
    assert source.read_bytes() == before


@pytest.mark.parametrize("apfs_clone,free_bytes,passed", [
    (True, 8 * 1024**3, True), (True, 8 * 1024**3 - 1, False),
    (False, 8 * 1024**3, False),
])
def test_work_volume_capacity_preserves_existing_runtime_reserve(tmp_path, monkeypatch, apfs_clone, free_bytes, passed):
    source = tmp_path / "source" / "box.vmx"
    source.parent.mkdir()
    source.write_text("protected source")
    work = tmp_path / "worker"
    metadata = tmp_path / "analysis"
    metadata.mkdir()
    checked_volumes = []
    monkeypatch.setattr(vmware.sys, "platform", "darwin")
    monkeypatch.setattr(vmware, "allocated_tree_bytes", lambda path: 26 * 1024**3)

    def capacity(path):
        checked_volumes.append(path)
        return SimpleNamespace(free=free_bytes)

    monkeypatch.setattr(vmware.shutil, "disk_usage", capacity)
    if passed:
        vmware.preflight_vmware_runtime(plan={}, source_vmx=source, stage_dir=work,
                                       apfs_clone=apfs_clone, receipt_dir=metadata)
    else:
        with pytest.raises(vmware.KapeApplianceError, match="insufficient free space"):
            vmware.preflight_vmware_runtime(plan={}, source_vmx=source, stage_dir=work,
                                           apfs_clone=apfs_clone, receipt_dir=metadata)
    report = json.loads((metadata / "vmware_runtime_preflight.json").read_text())
    assert checked_volumes == [work]
    assert report["runtime_reserve_bytes"] == 8 * 1024**3
    assert report["required_free_bytes"] == (8 if apfs_clone else 34) * 1024**3
    assert report["working_vmx"] == str(work / ".vmrun-appliance" / "box.vmx")
    assert source.read_text() == "protected source"


def _early_vm(parser_case, work_root=None):
    args = Namespace(vm_work_root=work_root, run_id="analysis", collection_provider="vmware_desktop",
                     windows_box="fmb/windows-11-arm64")
    return appliance.ParserVM(args=args, stage_dir=parser_case.stage)


def test_an_early_booted_vm_is_used_then_powered_off(parser_case, monkeypatch):
    stops = []
    original = vmware.cleanup_disposable_appliance_vm
    monkeypatch.setattr(vmware, "cleanup_disposable_appliance_vm",
                        lambda **kwargs: stops.append(kwargs["graceful"]) or original(**kwargs))
    vm = _early_vm(parser_case, parser_case.work_root).start()
    result = appliance.run_parser_appliance(
        processors=[object()],
        args=Namespace(vm_work_root=parser_case.work_root, run_id="analysis",
                       windows_parsers="windows-parsers", collection_provider="vmware_desktop",
                       windows_box="fmb/windows-11-arm64"),
        stage_dir=parser_case.stage, targets_root=parser_case.stage / "targets",
        modules_root=parser_case.stage / "modules", tool_logs=parser_case.stage / "logs", vm=vm,
    )
    assert [row["phase"] for row in result["phase_timings"]] == [
        "clone_appliance", "start_appliance", "build_input_package", "await_appliance", "stage_inputs",
        "run_guest_parsers", "collect_outputs", "stop_and_cleanup", "merge_outputs"]
    assert stops == [False] and result["vm_cleanup"]["removed"] is True
    assert len(parser_case.calls) == 1 and list(parser_case.work_root.iterdir()) == []


def test_a_failed_early_boot_surfaces_and_removes_the_worker(parser_case, monkeypatch):
    primary = RuntimeError("worker did not boot")

    def fail(**kwargs):
        raise primary

    monkeypatch.setattr(vmware, "vmrun_start_and_wait", fail)
    vm = _early_vm(parser_case, parser_case.work_root).start()
    with pytest.raises(RuntimeError) as error:
        appliance.run_parser_appliance(
            processors=[object()],
            args=Namespace(vm_work_root=parser_case.work_root, run_id="analysis",
                           windows_parsers="windows-parsers", collection_provider="vmware_desktop",
                           windows_box="fmb/windows-11-arm64"),
            stage_dir=parser_case.stage, targets_root=parser_case.stage / "targets",
            modules_root=parser_case.stage / "modules", tool_logs=parser_case.stage / "logs", vm=vm,
        )
    assert error.value is primary
    assert list(parser_case.work_root.iterdir()) == []


def test_a_vm_no_longer_needed_is_not_started_and_is_removed(parser_case, monkeypatch):
    import threading

    cloning, release, started = threading.Event(), threading.Event(), []

    def slow_clone(**kwargs):
        cloning.set()
        release.wait(10)
        return parser_case.clone(**kwargs)

    monkeypatch.setattr(vmware, "clone_vagrant_box_for_vmrun", slow_clone)
    monkeypatch.setattr(vmware, "vmrun_start_and_wait", lambda **kwargs: started.append(kwargs))
    vm = _early_vm(parser_case, parser_case.work_root).start()
    assert cloning.wait(10)
    failure = RuntimeError("host collection failed")
    threading.Timer(0.2, release.set).start()
    vm.discard(failure)
    assert started == [] and not getattr(failure, "__notes__", [])
    assert list(parser_case.work_root.iterdir()) == []
    vm.discard(failure)


def test_the_boot_thread_keeps_the_run_read_audit(parser_case, monkeypatch, tmp_path):
    from fmb.pipeline import reads

    marker = tmp_path / "box-file.vmdk"
    marker.write_bytes(b"box")

    def reading_clone(**kwargs):
        marker.read_bytes()
        return parser_case.clone(**kwargs)

    monkeypatch.setattr(vmware, "clone_vagrant_box_for_vmrun", reading_clone)
    with reads.measured() as opened:
        vm = _early_vm(parser_case).start()
        vm.wait()
        vm.close(graceful=False)
    assert str(marker) in opened


def test_winrm_counts_as_listening_only_when_it_answers_http():
    import socket
    import threading

    from fmb.generation.backends import winrm_listening

    def serve(reply: bytes):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)

        def answer():
            connection, _ = server.accept()
            with connection:
                connection.recv(1024)
                if reply:
                    connection.sendall(reply)

        threading.Thread(target=answer, daemon=True).start()
        return server

    with serve(b"HTTP/1.1 401 \r\nContent-Length: 0\r\n\r\n") as server:
        assert winrm_listening(server.getsockname()[1]) is True
    with serve(b"") as server:
        assert winrm_listening(server.getsockname()[1]) is False
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    assert winrm_listening(port) is False


@pytest.mark.parametrize("provider,modules,parsers,boots", [
    ("vmware_desktop", ["PECmd"], "windows-parsers", True),
    ("qemu", ["PECmd"], "windows-parsers", True),
    ("native_windows", ["SBECmd"], "windows-parsers", False),
    ("vmware_desktop", [], "windows-parsers", False),
    ("vmware_desktop", ["PECmd"], None, False),
])
def test_the_parser_vm_boots_early_only_when_it_will_be_used(tmp_path, monkeypatch, provider, modules, parsers, boots):
    from fmb.collection.tools.host import backend

    started = []
    monkeypatch.setattr(appliance.ParserVM, "start", lambda self: started.append(self.provider) or self)
    args = Namespace(collection_provider=provider, windows_box="fmb/windows-11-arm64", windows_parsers=parsers)
    vm = backend._start_parser_vm(args, tmp_path, modules, progress=lambda line: None)
    assert (vm is not None) is boots and started == ([provider] if boots else [])


def test_an_early_booted_qemu_vm_runs_the_parsers_then_is_killed(tmp_path, monkeypatch):
    from fmb.generation import backends

    stage = tmp_path / "analysis"
    (stage / "modules").mkdir(parents=True)
    (stage / "logs").mkdir()
    killed, modules = [], []

    class Process:
        def poll(self):
            return None if not killed else -9

        def kill(self):
            killed.append(True)

        def wait(self, timeout=None):
            return -9

    def adhoc(ansible, port, module, args, *, timeout):
        modules.append(module)
        if module == "ansible.builtin.fetch":
            Path(args["dest"]).write_bytes(b"returned test outputs")
        return subprocess.CompletedProcess([], 0, "ok", "")

    monkeypatch.setattr(backends.QemuBackend, "discover_tools", staticmethod(
        lambda: {"qemu-system": "qemu-system-x86_64", "qemu-img": "qemu-img", "ansible": "ansible"}))
    monkeypatch.setattr(backends.QemuBackend, "base_location", staticmethod(lambda box, version: {}))
    monkeypatch.setattr(backends.QemuBackend, "base_directory", staticmethod(lambda location: tmp_path / "base"))
    monkeypatch.setattr(backends, "prepare_overlay", lambda *args: None)
    monkeypatch.setattr(backends, "qemu_guest_command", lambda *args, **kwargs: ["qemu-system-x86_64"])
    monkeypatch.setattr(backends, "ansible_adhoc", adhoc)
    monkeypatch.setattr(appliance.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(backends, "winrm_listening", lambda port: True)
    monkeypatch.setattr(appliance, "build_input_package", lambda *, package_path, **kwargs: (
        package_path.write_bytes(b"inputs"), {"package": str(package_path), "input_file_count": 1})[1])
    monkeypatch.setattr(appliance, "_merge_outputs", lambda **kwargs: {"status": "completed"})
    args = Namespace(vm_work_root=None, run_id="analysis", windows_parsers="windows-parsers",
                     collection_provider="qemu", windows_box="fmb/windows-11-x64")
    vm = appliance.ParserVM(args=args, stage_dir=stage).start()
    vm.wait()
    state = vm.state
    assert state.is_dir()
    record = appliance.run_parser_appliance(
        processors=[object()], args=args, stage_dir=stage, targets_root=stage / "targets",
        modules_root=stage / "modules", tool_logs=stage / "logs", vm=vm,
    )
    assert modules == ["ansible.windows.win_ping", "ansible.windows.win_file", "ansible.windows.win_copy",
                       "ansible.windows.win_copy", "ansible.windows.win_command", "ansible.builtin.fetch"]
    assert killed == [True] and not state.exists()
    assert [row["phase"] for row in record["phase_timings"]] == [
        "start_appliance", "build_input_package", "await_appliance", "run_qemu_parsers", "stop_and_cleanup",
        "merge_outputs"]
    assert record["vm_cleanup"]["removed"] is True and record["guest_root"] == appliance.GUEST_ROOT


def _processor(name: str, category: str):
    from fmb.collection.tools.host.definitions import ModuleProcessor

    return ModuleProcessor(name, name, f"{name}.mkape", f"id-{name}", category, "csv", None, f"{name}.exe",
                           "-d %sourceDirectory% --csv %destinationDirectory%")


class _Definitions:
    tree_sha256 = "d" * 64

    def __init__(self, bundled_targets=None):
        pass

    def target_rules(self, targets):
        return []

    def module_processors(self, modules):
        return [_processor("MFTECmd", "FileSystem"), _processor("PECmd", "ProgramExecution"),
                _processor("SBECmd", "FileFolderAccess")]


class _Toolchain:
    lock_sha256 = "e" * 64

    @classmethod
    def load(cls, *, root):
        return cls()

    def verify(self, *, dotnet, executables):
        return []

    def describe(self, *, verification):
        return None

    def binding_for(self, executable):
        return SimpleNamespace(host_runnable=executable != "PECmd.exe", host_runnable_note="Windows only",
                               tool_name=executable.removesuffix(".exe"))


def _parser_threads() -> list[str]:
    import threading

    return [thread.name for thread in threading.enumerate()
            if thread.name in {"fmb-windows-parsers", "fmb-parser-vm"} and thread.is_alive()]


@pytest.fixture
def host_case(parser_case, monkeypatch, tmp_path):
    """A host extraction whose own parsers and the parser VM are stand-ins: run(host_parsers) runs it."""
    from fmb.collection.tools.host import backend
    from fmb.collection.tools.host.extractor import ExtractionResult
    from fmb.collection.tools.host.modules import ProcessorRun

    monkeypatch.setattr(backend, "KapeDefinitions", _Definitions)
    monkeypatch.setattr(backend, "HostToolchain", _Toolchain)
    monkeypatch.setattr(backend, "resolve_dotnet", lambda *args: "dotnet")
    monkeypatch.setattr(backend, "VolumeIndex", lambda evidence, progress: SimpleNamespace(
        partition_offset=1048576, entries={}, geometry={}))

    def extract(index, rules, *, output_root, drive_letter, command_line):
        prefetch = output_root / "targets" / "C" / "Windows" / "prefetch"
        prefetch.mkdir(parents=True)
        (prefetch / "RUNNER.EXE-AAAA1111.pf").write_bytes(b"prefetch")
        return ExtractionResult(targets_root=output_root / "targets", drive_letter=drive_letter)

    monkeypatch.setattr(backend, "extract_targets", extract)
    evidence = tmp_path / "image.raw"
    evidence.write_bytes(b"public test image")

    def run(host_parsers):
        def run_modules(processors, *, progress, **kwargs):
            host_parsers()
            progress("running MFTECmd: -f targets/C/$MFT --csv modules/FileSystem")
            return [ProcessorRun(module_name=item.module_name, requested_module=item.requested_module,
                                 executable=item.executable, tool_name=item.module_name, category=item.category,
                                 argv=[], command_line=item.command_line, working_directory=None, source_file=None,
                                 started_at="2026-10-12T00:00:00+00:00",
                                 status="completed" if item.module_name == "MFTECmd" else "deferred")
                    for item in processors]

        monkeypatch.setattr(backend, "run_module_processors", run_modules)
        args = Namespace(evidence=str(evidence), windows_parsers=str(tmp_path / "windows-parsers"),
                         selected_modules=None, expected_definitions_sha256=None, host_toolchain_root=tmp_path,
                         vm_work_root=parser_case.work_root, run_id="analysis",
                         collection_provider="vmware_desktop", windows_box="fmb/windows-11-arm64")
        return backend.run_host_collector_extraction(
            args=args, stage_dir=parser_case.stage, extracted_dir=parser_case.stage / "extracted",
            targets=["Prefetch"], modules=["MFTECmd", "PECmd", "SBECmd"], question_id="FULL-SCALE",
            question_text="Collect everything.", evidence_sha256="a" * 64, run_id="analysis")

    return SimpleNamespace(run=run, stage=parser_case.stage, work_root=parser_case.work_root)


def test_the_parser_vm_parses_while_the_host_runs_its_own_parsers(host_case, monkeypatch):
    import threading

    guest_ran = threading.Event()
    monkeypatch.setattr(vmware, "run_powershell_command_with_vmrun",
                        lambda **kwargs: guest_ran.set() or subprocess.CompletedProcess([], 0, "", ""))
    overlapped = []
    summary = host_case.run(lambda: overlapped.append(guest_ran.wait(10)))

    assert overlapped == [True] and summary["status"] == "completed"
    assert [row["phase"] for row in summary["phase_timings"]] == [
        "load_kape_definitions", "load_toolchain", "verify_toolchain", "index_volume", "extract_targets",
        "run_modules", "parser_appliance"]
    record = json.loads((host_case.stage / appliance.APPLIANCE_DIR_NAME / "parser-appliance-record.json").read_text())
    assert [row["phase"] for row in record["phase_timings"]] == [
        "clone_appliance", "start_appliance", "build_input_package", "await_appliance", "stage_inputs",
        "run_guest_parsers", "collect_outputs", "stop_and_cleanup", "merge_outputs"]
    # The parser VM's line was logged first, at its own time, and still follows the host's as when it ran after them.
    lines = (host_case.stage / "extracted" / "tool-logs" / "host-collector.stdout.txt").read_text().splitlines()
    host = next(index for index, line in enumerate(lines) if "running MFTECmd" in line)
    parsers = next(index for index, line in enumerate(lines) if "parser appliance: 2 processors" in line)
    assert parsers == host + 1 == len(lines) - 1
    assert lines[parsers].split()[0] < lines[host].split()[0]
    assert list(host_case.work_root.iterdir()) == [] and _parser_threads() == []


@pytest.mark.parametrize("failure", [KeyboardInterrupt, "host parser"])
def test_a_host_failure_stops_the_parser_vm_at_once_and_reports_only_itself(host_case, monkeypatch, failure):
    import threading

    from fmb.collection.tools.host import backend
    from fmb.collection.tools.host.modules import HostModuleError

    guest_started, stopped, collected = threading.Event(), threading.Event(), []
    remove = vmware.cleanup_disposable_appliance_vm

    def cleanup(**kwargs):
        stopped.set()
        return remove(**kwargs)

    def guest_parsers(**kwargs):
        guest_started.set()
        # Still parsing when the host fails: only stopping the VM ends the guest command.
        assert stopped.wait(10)
        raise vmware.KapeApplianceError("vmrun runProgramInGuest failed with exit 255: the VM is not powered on")

    def host_parsers():
        assert guest_started.wait(10)
        if failure is KeyboardInterrupt:
            raise KeyboardInterrupt
        raise HostModuleError("MFTECmd exited 1 for module MFTECmd; see MFTECmd.stderr.txt")

    monkeypatch.setattr(vmware, "cleanup_disposable_appliance_vm", cleanup)
    monkeypatch.setattr(vmware, "run_powershell_command_with_vmrun", guest_parsers)
    monkeypatch.setattr(vmware, "copy_guest_file_to_host_with_vmrun_retries", lambda **kwargs: collected.append(1))
    expected = KeyboardInterrupt if failure is KeyboardInterrupt else backend.HostCollectorError
    with pytest.raises(expected) as raised:
        host_case.run(host_parsers)
    if failure is not KeyboardInterrupt:
        assert str(raised.value) == "MFTECmd exited 1 for module MFTECmd; see MFTECmd.stderr.txt"
    assert not getattr(raised.value, "__notes__", None)
    assert collected == [] and list(host_case.work_root.iterdir()) == [] and _parser_threads() == []


def test_a_parser_vm_failure_surfaces_once_the_host_parsers_are_done(host_case, monkeypatch):
    primary = appliance.ParserApplianceError("guest copy failed")
    finished = []

    def fail(**kwargs):
        raise primary

    monkeypatch.setattr(appliance, "_stage_inputs", fail)
    with pytest.raises(appliance.ParserApplianceError) as raised:
        host_case.run(lambda: finished.append(True))
    assert raised.value is primary and finished == [True] and not getattr(primary, "__notes__", None)
    assert list(host_case.work_root.iterdir()) == [] and _parser_threads() == []


def test_a_boot_failure_is_noted_on_the_host_failure_that_came_with_it(host_case, monkeypatch):
    import threading

    from fmb.collection.tools.host import backend
    from fmb.collection.tools.host.modules import HostModuleError

    failing = threading.Event()

    def fail(**kwargs):
        failing.set()
        raise RuntimeError("worker did not boot")

    def host_parsers():
        # A host that failed sooner stops the boot before it can fail: then there is no boot failure to note.
        assert failing.wait(10)
        raise HostModuleError("MFTECmd exited 1 for module MFTECmd")

    monkeypatch.setattr(vmware, "vmrun_start_and_wait", fail)
    with pytest.raises(backend.HostCollectorError) as raised:
        host_case.run(host_parsers)
    assert raised.value.__notes__ == ["The parser VM had also failed to boot: RuntimeError: worker did not boot"]
    assert list(host_case.work_root.iterdir()) == [] and _parser_threads() == []


def _parsers(parser_case, vm):
    args = Namespace(vm_work_root=parser_case.work_root, run_id="analysis", windows_parsers="windows-parsers",
                     collection_provider="vmware_desktop", windows_box="fmb/windows-11-arm64")
    return appliance.ParserRun(processors=[object()], args=args, stage_dir=parser_case.stage,
                               targets_root=parser_case.stage / "targets", modules_root=parser_case.stage / "modules",
                               tool_logs=parser_case.stage / "logs", vm=vm)


def test_the_parsers_thread_keeps_the_run_read_audit(parser_case, monkeypatch, tmp_path):
    from fmb.pipeline import reads

    marker = tmp_path / "prefetch.pf"
    marker.write_bytes(b"prefetch")
    package = appliance.build_input_package

    def reading_package(**kwargs):
        marker.read_bytes()
        return package(**kwargs)

    monkeypatch.setattr(appliance, "build_input_package", reading_package)
    with reads.measured() as opened:
        record = _parsers(parser_case, _early_vm(parser_case, parser_case.work_root).start()).start().finish()
    assert str(marker) in opened and record["status"] == "completed"


def test_a_failed_vm_cleanup_is_noted_once(parser_case, monkeypatch):
    def uncertain_cleanup(**kwargs):
        raise vmware.KapeApplianceError("worker state unavailable")

    monkeypatch.setattr(vmware, "cleanup_disposable_appliance_vm", uncertain_cleanup)
    # The parsers ended and failed to remove their VM while the host failed: the host's error says so.
    parsers = _parsers(parser_case, _early_vm(parser_case, parser_case.work_root).start()).start()
    parsers._background._thread.join()
    failure = RuntimeError("host collection failed")
    parsers.discard(failure)
    assert len(failure.__notes__) == 1 and "worker state unavailable" in failure.__notes__[0]
    # The cleanup failure is itself the error: no note repeats it.
    parsers = _parsers(parser_case, _early_vm(parser_case).start()).start()
    with pytest.raises(vmware.KapeApplianceError, match="worker state unavailable") as raised:
        parsers.finish()
    parsers.discard(raised.value)
    assert not getattr(raised.value, "__notes__", None) and _parser_threads() == []


def test_the_guest_gets_its_inputs_in_one_copy_and_runs_them_in_one_command(tmp_path, monkeypatch):
    import base64
    import zipfile

    package = tmp_path / "inputs.zip"
    package.write_bytes(b"pinned test inputs")
    copies, commands = [], []

    def copy(*, vmx_path, provider, host_path, guest_path):
        with zipfile.ZipFile(host_path) as archive:
            copies.append((guest_path, {name: archive.read(name) for name in archive.namelist()}, host_path))

    monkeypatch.setattr(vmware, "copy_host_file_to_guest_with_vmrun_retries", copy)
    appliance._stage_inputs(vmx_path=tmp_path / "box.vmx", provider="vmware_desktop", package_path=package)
    [(guest_path, members, host_path)] = copies
    assert guest_path == appliance.GUEST_TRANSPORT and not host_path.parent.exists()
    assert members == {"inputs.zip": b"pinned test inputs", "run_parsers.ps1": appliance.GUEST_SCRIPT.encode()}

    monkeypatch.setattr(vmware, "vmrun_guest_command", lambda **kwargs: commands.append(kwargs))
    vmware.run_powershell_command_with_vmrun(vmx_path=tmp_path / "box.vmx", provider="vmware_desktop",
                                             command=appliance.GUEST_BOOTSTRAP, check=False)
    [command] = commands
    assert command["command"] == "runProgramInGuest" and command["args"][-2] == "-EncodedCommand"
    bootstrap = base64.b64decode(command["args"][-1]).decode("utf-16-le")
    assert bootstrap == appliance.GUEST_BOOTSTRAP and " " not in command["args"][-1]
    assert f"ExtractToDirectory('{appliance.GUEST_TRANSPORT}', $root)" in bootstrap
    assert f"$root = '{appliance.GUEST_ROOT}'" in bootstrap


def test_vmware_tools_are_asked_every_second_and_never_for_a_removed_vm(tmp_path, monkeypatch):
    vmx = tmp_path / "box.vmx"
    vmx.write_text("config.version = \"8\"\n")
    answers = iter([255, 255, 0])
    probes, sleeps = [], []
    monkeypatch.setattr(vmware, "vmrun_guest_command", lambda **kwargs: probes.append(kwargs) or
                        subprocess.CompletedProcess([], next(answers), "", ""))
    monkeypatch.setattr(vmware.time, "sleep", sleeps.append)
    vmware.wait_for_vmrun_guest(vmx_path=vmx, provider="vmware_desktop")
    assert len(probes) == 3 and sleeps == [1, 1]

    vmx.unlink()
    probes.clear()
    with pytest.raises(vmware.KapeApplianceError, match="removed"):
        vmware.wait_for_vmrun_guest(vmx_path=vmx, provider="vmware_desktop")

    def copy():
        probes.append("copy")
        raise vmware.KapeApplianceError("vmrun CopyFileFromHostToGuest failed")

    with pytest.raises(vmware.KapeApplianceError, match="host file copy failed after retries"):
        vmware._copy_with_vmrun_retries("host file copy", copy, vmx_path=vmx, provider="vmware_desktop")
    assert probes == ["copy"] and sleeps == [1, 1]
