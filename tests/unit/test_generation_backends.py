from types import SimpleNamespace

import pytest

from fmb.generation import backends


def _pipeline(**overrides):
    calls = []
    pipeline = SimpleNamespace(
        provider="vmware_desktop", is_macos=True, vagrant_cmd="vagrant", qemu_img_cmd="qemu-img",
        vmrun_cmd="vmrun", ansible_cmd="ansible", ansible_playbook_cmd="ansible-playbook",
        first_available=lambda names: names[0],
        preflight_vmware_source=lambda: calls.append("source") or {"vmx_path": "/box.vmx"},
        preflight_generation_storage=lambda vmx: calls.append(("storage", vmx)),
        vagrant_environment=lambda: {"FMB": "1"},
        run_vmware_vagrant_boot=lambda env: calls.append(("boot", env)) or "booted",
        halt_vm=lambda: calls.append("halt"),
        discover_disk_path=lambda: "/disk.vmdk",
    )
    for key, value in overrides.items():
        setattr(pipeline, key, value)
    return pipeline, calls


def test_the_vmware_backend_delegates_to_the_existing_lifecycle(monkeypatch):
    monkeypatch.setattr(backends.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(backends.platform, "machine", lambda: "arm64")
    pipeline, calls = _pipeline()
    backend = backends.backend_for(pipeline)
    assert backend.name == "vmware_desktop" and backend.boot_phase == "vagrant_boot"
    backend.check_host()
    assert [name for name, _ in backend.required_tools()] == [
        "vagrant", "qemu-img", "qemu-io", "vmrun", "ansible", "ansible-playbook"]
    assert backend.preflight_source() == {"vmx_path": "/box.vmx"}
    assert backend.boot() == "booted"
    backend.halt()
    assert backend.system_disk() == "/disk.vmdk"
    assert calls == ["source", ("storage", "/box.vmx"), ("boot", {"FMB": "1"}), "halt"]


def test_the_vmware_backend_refuses_a_host_other_than_an_arm_mac(monkeypatch):
    monkeypatch.setattr(backends.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(backends.platform, "machine", lambda: "x86_64")
    with pytest.raises(RuntimeError, match="requires macOS on ARM64"):
        backends.backend_for(_pipeline()[0]).check_host()


def test_an_unknown_provider_names_the_available_backends():
    with pytest.raises(ValueError, match="no generation backend for provider 'virtualbox'; available: qemu, vmware_desktop"):
        backends.backend_for(_pipeline(provider="virtualbox")[0])
