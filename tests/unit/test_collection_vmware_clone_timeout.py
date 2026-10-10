import importlib.util
from pathlib import Path
import subprocess

import pytest


def test_collection_full_clone_timeout_is_forwarded_and_reported(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[2] / "src/fmb/collection/tools/host/vmware.py"
    spec = importlib.util.spec_from_file_location("collection_vmware_timeout", path)
    vmware = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vmware)
    monkeypatch.delenv("FMB_APFS_WORKER_CLONE", raising=False)
    source = tmp_path / "read-only-source" / "box.vmx"
    source.parent.mkdir()
    source.write_text("source unchanged")
    monkeypatch.setattr(vmware, "ensure_vagrant_box_vmx_path", lambda **kwargs: source)
    monkeypatch.setattr(vmware, "assert_flat_vmware_source", lambda path: None)
    monkeypatch.setattr(vmware, "vmrun_is_running", lambda **kwargs: False)
    monkeypatch.setattr(vmware, "preflight_vmware_runtime", lambda **kwargs: None)
    monkeypatch.setattr(vmware, "vmrun_executable", lambda: "vmrun")
    calls = []

    def stalled_clone(command, **kwargs):
        calls.append((command, kwargs))
        assert kwargs["timeout"] == 3600
        assert command[3] == "clone" and command[6] == "full"
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output="copy stalled")

    monkeypatch.setattr(vmware.subprocess, "run", stalled_clone)
    stage = tmp_path / "collection"
    stage.mkdir()
    with pytest.raises(vmware.KapeApplianceError, match="timed out after 3600s") as error:
        vmware.clone_vagrant_box_for_vmrun(
            plan={"run_id": "bounded-clone", "worker": {"windows_box": "fmb/windows-11-arm64"}},
            stage_dir=stage, provider="vmware_desktop",
        )
    assert "copy stalled" in str(error.value)
    assert len(calls) == 1 and source.read_text() == "source unchanged"
