import importlib.util
import subprocess
from pathlib import Path

import os

import pytest


@pytest.fixture
def vmware(monkeypatch):
    path = Path(__file__).resolve().parents[2] / "src/fmb/collection/tools/host/vmware.py"
    spec = importlib.util.spec_from_file_location("collection_lifecycle_candidate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "vmrun_executable", lambda: "/Applications/VMware Fusion.app/Contents/Public/vmrun")
    return module


@pytest.fixture
def worker(tmp_path):
    vmx = tmp_path / "External Disk" / ".vmrun-appliance" / "box.vmx"
    vmx.parent.mkdir(parents=True)
    vmx.write_text("owned worker configuration")
    (vmx.parent / "disk.vmdk").write_bytes(b"worker backing preserved")
    return vmx


def test_failed_list_never_authorizes_source_clone(vmware, worker, tmp_path, monkeypatch):
    calls = []
    def failed_list(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="provider query unavailable")
    monkeypatch.setattr(vmware.subprocess, "run", failed_list)
    monkeypatch.setattr(vmware, "ensure_vagrant_box_vmx_path", lambda **kwargs: worker)
    monkeypatch.setattr(vmware, "assert_flat_vmware_source", lambda path: None)
    monkeypatch.setattr(vmware, "preflight_vmware_runtime", lambda **kwargs: pytest.fail("an unknown source state cannot reach clone preflight"))
    monkeypatch.delenv("FMB_APFS_WORKER_CLONE", raising=False)
    with pytest.raises(vmware.KapeApplianceError, match="provider query unavailable"):
        vmware.clone_vagrant_box_for_vmrun(
            plan={"run_id": "unknown-source", "worker": {"windows_box": "fmb/windows-11-arm64"}},
            stage_dir=tmp_path / "collection", provider="vmware_desktop",
        )
    assert len(calls) == 1 and calls[0][-1] == "list"
    assert worker.read_text() == "owned worker configuration"


def test_failed_list_retains_worker_through_parser_cleanup(vmware, worker, monkeypatch):
    calls = []
    def failed_list(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="list unavailable")
    monkeypatch.setattr(vmware.subprocess, "run", failed_list)
    with pytest.raises(vmware.KapeApplianceError, match="list unavailable"):
        vmware.cleanup_disposable_appliance_vm(vmx_path=worker, provider="vmware_desktop")
    assert worker.exists() and (worker.parent / "disk.vmdk").exists()
    assert len(calls) == 1 and calls[0][-1] == "list"


@pytest.mark.parametrize("listed, expected", [
    ("{vmx}", True), ("{vmx}.other", False), ("{vmx}/child.vmx", False),
    ("notice mentioning {vmx}", False), ("{other}", False),
])
def test_running_query_uses_complete_resolved_vmx_lines(vmware, worker, monkeypatch, listed, expected):
    other = worker.parent.parent / "another worker" / "box.vmx"
    def query(command, **kwargs):
        text = "Total running VMs: 1\n" + listed.format(vmx=worker.resolve(), other=other) + "\n" if command[-1] == "list" else ""
        return subprocess.CompletedProcess(command, 0, stdout=text, stderr="")
    monkeypatch.setattr(vmware.subprocess, "run", query)
    alias = worker.parent / "unused" / ".." / worker.name
    assert vmware.vmrun_is_running(vmx_path=alias, provider="vmware_desktop") is expected


@pytest.mark.parametrize("uids", [(501, 0), (0, 0), (502, 502)])
def test_empty_list_does_not_hide_exact_live_host_vmx(vmware, worker, monkeypatch, uids):
    monkeypatch.setattr(vmware.sys, "platform", "darwin")
    executable = str(Path(vmware.vmrun_executable()).resolve().with_name("vmware-vmx"))
    def query(command, **kwargs):
        text = "Total running VMs: 0\n" if command[-1] == "list" else f"62663 {uids[0]} {uids[1]} {executable} -@ duplex=3;msgs=ui {worker}\n"
        return subprocess.CompletedProcess(command, 0, stdout=text, stderr="")
    monkeypatch.setattr(vmware.subprocess, "run", query)
    assert vmware.vmrun_is_running(vmx_path=worker, provider="vmware_desktop") is True


@pytest.mark.parametrize("suffix", [".other", "/child.vmx"])
def test_host_vmx_suffix_must_be_exact(vmware, worker, monkeypatch, suffix):
    monkeypatch.setattr(vmware.sys, "platform", "darwin")
    executable = str(Path(vmware.vmrun_executable()).resolve().with_name("vmware-vmx"))
    def query(command, **kwargs):
        text = "Total running VMs: 0\n" if command[-1] == "list" else f"62663 501 0 {executable} -@ duplex=3;msgs=ui {worker}{suffix}\n"
        return subprocess.CompletedProcess(command, 0, stdout=text, stderr="")
    monkeypatch.setattr(vmware.subprocess, "run", query)
    assert vmware.vmrun_is_running(vmx_path=worker, provider="vmware_desktop") is False


def test_failed_host_query_preserves_worker(vmware, worker, monkeypatch):
    monkeypatch.setattr(vmware.sys, "platform", "darwin")
    def query(command, **kwargs):
        if command[-1] == "list":
            return subprocess.CompletedProcess(command, 0, stdout="Total running VMs: 0\n", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="host state unavailable")
    monkeypatch.setattr(vmware.subprocess, "run", query)
    with pytest.raises(vmware.KapeApplianceError, match="host state unavailable"):
        vmware.cleanup_disposable_appliance_vm(vmx_path=worker, provider="vmware_desktop")
    assert worker.exists() and (worker.parent / "disk.vmdk").exists()


@pytest.mark.parametrize("stop_kind", ["soft", "hard"])
def test_successful_stop_is_confirmed_before_deleting_worker(vmware, worker, monkeypatch, stop_kind):
    calls = []
    def still_running(command, **kwargs):
        calls.append(command)
        if stop_kind == "hard" and command[-1] == "soft":
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="graceful stop rejected")
        text = f"Total running VMs: 1\n{worker}\n" if command[-1] == "list" else ""
        return subprocess.CompletedProcess(command, 0, stdout=text, stderr="")
    monkeypatch.setattr(vmware.subprocess, "run", still_running)
    with pytest.raises(vmware.KapeApplianceError, match="remains running"):
        vmware.cleanup_disposable_appliance_vm(vmx_path=worker, provider="vmware_desktop")
    assert [command[-1] for command in calls] == (["list", "soft", "list"] if stop_kind == "soft" else ["list", "soft", "hard", "list"])
    assert worker.exists() and (worker.parent / "disk.vmdk").exists()


def test_post_stop_query_failure_preserves_worker(vmware, worker, monkeypatch):
    lists = []
    def uncertain_shutdown(command, **kwargs):
        if command[-1] == "list":
            lists.append(command)
            if len(lists) == 2:
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="shutdown confirmation unavailable")
            return subprocess.CompletedProcess(command, 0, stdout=f"Total running VMs: 1\n{worker}\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
    monkeypatch.setattr(vmware.subprocess, "run", uncertain_shutdown)
    with pytest.raises(vmware.KapeApplianceError, match="shutdown confirmation unavailable"):
        vmware.cleanup_disposable_appliance_vm(vmx_path=worker, provider="vmware_desktop")
    assert worker.exists() and (worker.parent / "disk.vmdk").exists()


def test_failed_soft_and_hard_stop_preserve_worker(vmware, worker, monkeypatch):
    def stop_failure(command, **kwargs):
        if command[-1] == "list":
            return subprocess.CompletedProcess(command, 0, stdout=f"Total running VMs: 1\n{worker}\n", stderr="")
        assert kwargs["timeout"] == 120
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="stop rejected")
    monkeypatch.setattr(vmware.subprocess, "run", stop_failure)
    with pytest.raises(vmware.KapeApplianceError, match="stop rejected"):
        vmware.cleanup_disposable_appliance_vm(vmx_path=worker, provider="vmware_desktop")
    assert worker.exists() and (worker.parent / "disk.vmdk").exists()


def test_missing_vmx_metadata_does_not_allow_live_backing_deletion(vmware, worker, monkeypatch):
    monkeypatch.setattr(vmware.sys, "platform", "darwin")
    executable = str(Path(vmware.vmrun_executable()).resolve().with_name("vmware-vmx"))
    worker.unlink()
    def query(command, **kwargs):
        if command[-1] == "list":
            return subprocess.CompletedProcess(command, 0, stdout="Total running VMs: 0\n", stderr="")
        if command[0] == "/bin/ps":
            return subprocess.CompletedProcess(command, 0, stdout=f"62663 501 0 {executable} -@ duplex=3;msgs=ui {worker}\n", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="unregistered stop rejected")
    monkeypatch.setattr(vmware.subprocess, "run", query)
    with pytest.raises(vmware.KapeApplianceError, match="unregistered stop rejected"):
        vmware.cleanup_disposable_appliance_vm(vmx_path=worker, provider="vmware_desktop")
    assert (worker.parent / "disk.vmdk").read_bytes() == b"worker backing preserved"


@pytest.mark.parametrize("operation, expected_timeout", [("start", 300), ("hard_stop", 120), ("list", 30), ("host_query", 15)])
def test_lifecycle_stalls_have_finite_reported_deadlines(vmware, worker, monkeypatch, operation, expected_timeout):
    monkeypatch.setattr(vmware.sys, "platform", "darwin")
    calls = []
    def stalled(command, **kwargs):
        calls.append(command)
        if operation == "host_query" and command[-1] == "list":
            return subprocess.CompletedProcess(command, 0, stdout="Total running VMs: 0\n", stderr="")
        assert kwargs["timeout"] == expected_timeout
        raise subprocess.TimeoutExpired(command, expected_timeout, output=b"operation stalled", stderr=b"diagnostic detail")
    monkeypatch.setattr(vmware.subprocess, "run", stalled)
    method = {"start": vmware.vmrun_start, "hard_stop": vmware.vmrun_hard_stop,
              "list": vmware.vmrun_is_running, "host_query": vmware.vmrun_is_running}[operation]
    with pytest.raises(vmware.KapeApplianceError, match=f"timed out after {expected_timeout}s") as error:
        method(vmx_path=worker, provider="vmware_desktop")
    assert "operation stalled" in str(error.value) and "diagnostic detail" in str(error.value)
    assert len(calls) == (2 if operation == "host_query" else 1)


@pytest.mark.skipif(os.name == "nt", reason="the VMware Fusion generator manages POSIX process groups and runs only on macOS")
def test_start_success_preserves_persistent_guest_lifetime(vmware, worker, monkeypatch):
    guest = {"running": False}
    calls = []
    def started(command, **kwargs):
        calls.append(command)
        assert command[3] == "start" and command[-1] == "nogui"
        assert kwargs["timeout"] == 300
        guest["running"] = True
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
    monkeypatch.setattr(vmware.subprocess, "run", started)
    monkeypatch.setattr(vmware.os, "killpg", lambda *args: pytest.fail("start success must not signal a persistent guest"))
    assert vmware.vmrun_start(vmx_path=worker, provider="vmware_desktop") is None
    assert guest["running"] and len(calls) == 1


def test_confirmed_shutdown_removes_only_disposable_worker(vmware, worker, monkeypatch):
    queries = []
    def stopped(command, **kwargs):
        queries.append(command)
        if command[-1] == "list":
            first = sum(query[-1] == "list" for query in queries) == 1
            text = f"Total running VMs: 1\n{worker}\n" if first else "Total running VMs: 0\n"
        else:
            text = ""
        return subprocess.CompletedProcess(command, 0, stdout=text, stderr="")
    monkeypatch.setattr(vmware.subprocess, "run", stopped)
    receipt = vmware.cleanup_disposable_appliance_vm(vmx_path=worker, provider="vmware_desktop")
    assert receipt["removed"] is True and not worker.parent.exists()
    assert sum(query[-1] == "list" for query in queries) == 2
