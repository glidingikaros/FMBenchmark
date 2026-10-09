from __future__ import annotations

import os

import copy
import json
from pathlib import Path

import pytest

from fmb.core.schemas import validate_payload
from fmb.generation import dependency_lock
from fmb.generation import vmware_clone
from fmb.generation.backends import VmwareFusionBackend
from test_generation_recipe import SOURCE, build_guest_plan, build_public_manifest, pipeline, recipe
from test_generation_recipe import select_private_assignment

BOX_DIRECTORY = "boxes/fmb-VAGRANTSLASH-windows-11-arm64/0/arm64/vmware_desktop"
CORE_FILES = {"executor/powershell/exec_wrapper.ps1": "wrapper", "module_utils/powershell/Legacy.psm1": "legacy",
              "module_utils/csharp/Ansible.Basic.cs": "basic", "plugins/shell/powershell.py": "shell"}


class FakeHost:

    def __init__(self, root, monkeypatch):
        self.root, self.monkeypatch = Path(root), monkeypatch
        self.hypervisor = {"product": "VMware Fusion", "version": "13.6.4", "build": "24832108"}
        self.core_version, self.collection_version = "2.20.5", "3.5.0"
        self.libraries = {"hexdump": "3.3", "libvmdk-python": "20260714", "python-evtx": "0.8.1",
                          "pytsk3": "20260715"}
        box = self.root / "vagrant" / BOX_DIRECTORY
        box.mkdir(parents=True)
        (box / "box.vmx").write_text('nvme0:0.fileName = "disk.vmdk"\n')
        (box / "disk.vmdk").write_text('# Disk DescriptorFile\nparentCID=ffffffff\nRW 1 FLAT "disk-flat.vmdk" 0\n')
        (box / "disk-flat.vmdk").write_bytes(b"retained disk extent")
        (box / "metadata.json").write_text('{"provider":"vmware_desktop"}')
        self.box = box
        self.core = self.root / "site-packages/ansible"
        for relative, text in CORE_FILES.items():
            (self.core / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.core / relative).write_text(text)
        (self.core / "executor/powershell/__pycache__").mkdir()
        (self.core / "executor/powershell/__pycache__/x.cpython-314.pyc").write_bytes(b"cache")
        (self.core / "cli/galaxy.py").parent.mkdir(parents=True)
        (self.core / "cli/galaxy.py").write_text("host-only code")
        self.collection = self.root / "site-packages/ansible_collections/ansible/windows"
        (self.collection / "plugins/modules").mkdir(parents=True)
        (self.collection / "plugins/modules/win_shell.ps1").write_text("win_shell")
        (self.collection / "MANIFEST.json").write_text('{"collection_info": {"version": "3.5.0"}}')
        self.tools = {}
        for name in VmwareFusionBackend.TOOLS:
            path = self.root / "bin" / name
            path.parent.mkdir(exist_ok=True)
            path.write_text("tool " + name)
            self.tools[name] = str(path)
        self.activate()

    def activate(self):
        host = self
        self.monkeypatch.setenv("VAGRANT_HOME", str(self.root / "vagrant"))
        self.monkeypatch.setattr(VmwareFusionBackend, "discover_tools", staticmethod(lambda: dict(host.tools)))
        self.monkeypatch.setattr(VmwareFusionBackend, "hypervisor_identity",
                                 staticmethod(lambda tools: dict(host.hypervisor)))
        self.monkeypatch.setattr(VmwareFusionBackend, "host_facts", staticmethod(lambda tools: {"root": str(host.root)}))
        self.monkeypatch.setattr(VmwareFusionBackend, "supported_host", staticmethod(lambda: None))
        self.monkeypatch.setattr(VmwareFusionBackend, "host_checks", staticmethod(lambda tools: [
            ("vagrant-vmware-desktop plugin", True, ["vagrant-vmware-desktop (3.0.5, global)"])]))
        self.monkeypatch.setattr(dependency_lock, "ansible_layout", lambda ansible, collections=(), cwd=None: {
            "core_version": host.core_version, "core_root": host.core,
            "collections": {"ansible.windows": {"version": host.collection_version, "root": host.collection}}})
        self.monkeypatch.setattr(dependency_lock, "installed_version", lambda name: host.libraries.get(name))
        self.monkeypatch.setattr(dependency_lock, "library_versions", lambda imports: {
            "imports": {"Evtx": ["python-evtx"], "pytsk3": ["pytsk3"], "pyvmdk": ["libvmdk-python"]},
            "distributions": dict(sorted(host.libraries.items()))})
        self.monkeypatch.setattr(dependency_lock, "_tool_versions", lambda tools: {
            name: {"path": path, "version": "test"} for name, path in tools.items()})

    def build(self):
        _, imports = recipe.closure_modules(SOURCE.parent)
        return dependency_lock.build_lock(
            backend_name="vmware_desktop", box="fmb/windows-11-arm64", version="0",
            guest={"windows_build": "22000", "timezone": "Pacific Standard Time", "locale": "en-US"},
            imports=imports)


@pytest.fixture
def host(tmp_path, monkeypatch):
    return FakeHost(tmp_path / "mac-a", monkeypatch)


def freeze(destination, lock, *, assignment=None, origin=None, entropy=b"a" * 32):
    config = recipe.paper_config("I1")
    public = build_public_manifest(experiment="full_scale", seed=config["population_seed"])
    assignment = assignment or select_private_assignment(public, entropy=entropy)
    plan = build_guest_plan(public, assignment, case="positive")
    return recipe.freeze_recipe(destination, source_root=SOURCE, config=config, population=public,
                                assignment=assignment, guest_plan=plan, dependency_lock=lock,
                                activity_seed=config["population_seed"], hardware_seed=config["population_seed"],
                                assignment_origin=origin)


def pinned_strings(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from pinned_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from pinned_strings(item)
    elif isinstance(value, str):
        yield value


def test_portable_lock_pins_evidence_inputs_by_content_not_host_path(host):
    lock = host.build()
    validate_payload(lock, "generation_dependency_lock.v2.schema.json")
    pinned = {section: lock[section] for section in dependency_lock.PINNED_SECTIONS}
    assert not [text for text in pinned_strings(pinned) if text.startswith("/") or str(host.root) in text]
    assert [row["path"] for row in lock["base"]["files"]] == ["box.vmx", "disk-flat.vmdk", "disk.vmdk", "metadata.json"]
    assert lock["base"]["location"] == {"kind": "vagrant_box", "box": "fmb/windows-11-arm64", "version": "0",
                                        "architecture": "arm64", "provider": "vmware_desktop"}
    core = [row["path"] for row in lock["guest_code"]["ansible_core"]["files"]]
    assert core == sorted(CORE_FILES), "only the guest side of ansible-core, without bytecode caches"
    assert lock["host_libraries"]["distributions"]["python-evtx"] == "0.8.1"
    assert lock["recorded_host"]["backend"] == {"root": str(host.root)}


def test_the_same_inputs_on_another_mac_verify_and_share_one_pinned_digest(host, tmp_path, monkeypatch):
    first = host.build()
    other = FakeHost(tmp_path / "mac-b", monkeypatch)
    second = other.build()
    assert first["recorded_host"] != second["recorded_host"]
    assert dependency_lock.pinned_digest(first) == dependency_lock.pinned_digest(second)
    record = dependency_lock.verify_lock(first)
    validate_payload(record, "generation_host_record.schema.json")
    assert record["recorded"]["backend"] == {"root": str(other.root)}


def change_base_byte(host):
    (host.box / "disk-flat.vmdk").write_bytes(b"retained disk extenT")


def add_base_file(host):
    (host.box / "box.vmx.bak").write_text("stray")


def drift_hypervisor(host):
    host.hypervisor["build"] = "24999999"


def drift_core_version(host):
    host.core_version = "2.21.0"


def change_core_guest_file(host):
    (host.core / "executor/powershell/exec_wrapper.ps1").write_text("wrapper changed")


def change_collection_file(host):
    (host.collection / "plugins/modules/win_shell.ps1").write_text("win_shell changed")


def drift_collection_version(host):
    host.collection_version = "3.6.0"


def drift_library(host):
    host.libraries["pytsk3"] = "20270101"


@pytest.mark.parametrize("drift, message", [
    (change_base_byte, "installed base differs from its lock: changed disk-flat.vmdk"),
    (add_base_file, "installed base differs from its lock: unlocked box.vmx.bak"),
    (drift_hypervisor, "hypervisor differs"),
    (drift_core_version, "ansible-core 2.21.0 differs"),
    (change_core_guest_file, "ansible-core guest code differs from its lock: changed executor/powershell"),
    (change_collection_file, "collection ansible.windows differs from its lock: changed plugins/modules"),
    (drift_collection_version, "collection ansible.windows 3.6.0 differs"),
    (drift_library, "host libraries differ from their lock: pytsk3 20270101"),
])
def test_each_pinned_input_is_enforced(host, drift, message):
    lock = host.build()
    drift(host)
    with pytest.raises(ValueError, match=message):
        dependency_lock.verify_lock(lock)


def test_host_only_code_and_recorded_facts_are_not_enforced(host):
    lock = host.build()
    (host.core / "cli/galaxy.py").write_text("another host-side version")
    host.tools["vagrant"] = str(host.root / "bin/qemu-img")
    dependency_lock.verify_lock(lock)


def test_lock_structure_refuses_host_paths_and_unpinned_collections(host):
    lock = host.build()
    for mutate in (lambda bad: bad["base"]["files"][0].update(path="/Users/someone/box.vmx"),
                   lambda bad: bad["guest_code"]["collections"].clear(),
                   lambda bad: bad["base"].update(entry="other.vmx"),
                   lambda bad: bad["host_libraries"]["imports"].update(Evtx=["unlocked-dist"])):
        bad = copy.deepcopy(lock)
        mutate(bad)
        with pytest.raises(ValueError):
            dependency_lock.validate_lock(bad)


def test_v2_recipe_binds_the_fmb_modules_the_generator_imports(host, tmp_path):
    lock = host.build()
    directory = tmp_path / "recipe"
    frozen = freeze(directory, lock)
    validate_payload(frozen, "generation_recipe.v2.schema.json")
    paths = {row["path"] for row in frozen["source"]}
    assert {"generation/pipeline.py", "generation/ansible/playbook.yml", "index/scanners/mft.py",
            "collection/tsk_volume.py", "index/scanners/dfir-ntfs-lock.json"} <= paths
    assert not any(path.startswith(("cli/", "assessment/", "analysis/")) for path in paths)
    assert frozen["assignment_origin"] == {"kind": "fresh_entropy"}
    assert frozen["pinned_inputs_sha256"] == dependency_lock.pinned_digest(lock)
    executing = directory / "source" / "generation"
    recipe.load_recipe(directory, source_root=executing, verify_dependencies=False)
    scanner = directory / "source/index/scanners/mft.py"
    scanner.write_bytes(scanner.read_bytes() + b"\n# a changed post-export reader\n")
    with pytest.raises(ValueError, match="executing generation source differs"):
        recipe.load_recipe(directory, source_root=executing, verify_dependencies=False)


def test_loading_a_v2_recipe_verifies_the_host_and_returns_its_record(host, tmp_path):
    directory = tmp_path / "recipe"
    freeze(directory, host.build())
    loaded = recipe.load_recipe(directory, source_root=SOURCE)
    validate_payload(loaded["host"], "generation_host_record.schema.json")
    assert recipe.base_vmx_path(loaded["lock"]) == (host.box / "box.vmx").resolve()
    change_base_byte(host)
    with pytest.raises(ValueError, match="installed base differs"):
        recipe.load_recipe(directory, source_root=SOURCE)


def test_lock_must_cover_every_third_party_import_of_the_generator(host, tmp_path):
    lock = host.build()
    del lock["host_libraries"]["imports"]["pytsk3"]
    with pytest.raises(ValueError, match="pins no library for the generator's imports: pytsk3"):
        freeze(tmp_path / "recipe", lock)


def test_reused_assignment_needs_a_portable_lock(tmp_path):
    origin = {"kind": "reused", "recipe_id": "recipe:" + "0" * 64, "private_sha256": "0" * 64}
    with pytest.raises(ValueError, match="needs a portable"):
        freeze(tmp_path / "recipe", {"schema_version": recipe.LOCK_SCHEMA}, origin=origin)


def test_the_lock_step_writes_a_private_lock_and_reports_its_digest(host, tmp_path):
    from fmb.replication import steps

    lock_path = tmp_path / "lock.json"
    summary = steps.lock(path=str(lock_path), provider="vmware_desktop")
    lock = recipe.read_json(lock_path)
    assert summary["pinned_inputs_sha256"] == dependency_lock.pinned_digest(lock)
    assert os.name == "nt" or lock_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="already exists"):
        steps.lock(path=str(lock_path), provider="vmware_desktop")


def test_pipeline_runs_a_v2_recipe_with_this_hosts_tools_and_records_them(host, tmp_path, monkeypatch):
    directory = tmp_path / "recipe"
    lock = host.build()
    freeze(directory, lock)
    monkeypatch.setattr(pipeline.sys, "executable", "/no/locked/interpreter")
    instance = pipeline.GenerationPipeline(
        'vmware_desktop', 'baseline', 'vmdk', False, False, experiment='full_scale', case='positive',
        population_seed=2026091811, windows_box='fmb/windows-11-arm64', vmware_bridge=None, recipe=directory,
        output_root=tmp_path / 'run')
    assert instance.vagrant_box_vmx_path() == (host.box / "box.vmx").resolve()
    assert instance.vagrant_environment()["FMB_BOX_VERSION"] == "0"
    files = recipe.base_file_rows(lock)
    receipt = {"schema_version": "generation_vmware_clone.v1", "status": "verified",
               "copy_method": vmware_clone.COPY_METHOD, "recipe_id": instance.recipe_bundle["recipe"]["recipe_id"],
               "dependency_lock_sha256": instance.recipe_bundle["recipe"]["dependency_lock_sha256"],
               "source_vmx": str((host.box / "box.vmx").resolve()), "files": files}
    vmware_clone.validate_receipt(receipt, instance.recipe_bundle)
    change_base_byte(host)
    monkeypatch.setattr(instance, "preflight_checks", lambda: pytest.fail("verification must precede VM preflight"))
    monkeypatch.setattr(instance, "provision_vm", lambda: pytest.fail("VM must not launch"))
    monkeypatch.setattr(instance, "cleanup", lambda: {})
    with pytest.raises(ValueError, match="installed base differs"):
        instance.run()


def test_runtime_receipt_of_a_v2_realization_carries_the_host_record(host, tmp_path):
    directory = tmp_path / "recipe"
    freeze(directory, host.build())
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.recipe_bundle = recipe.load_recipe(directory, source_root=SOURCE)
    instance.host_record = instance.recipe_bundle["host"]
    instance.output_dir = tmp_path
    instance.capture_clock_receipt = lambda _: None
    activity = {"schema_version": "generation_activity_receipt.v1", "completed_count": 12,
                "started_utc": "2026-01-01T00:00:00Z", "completed_utc": "2026-01-01T00:00:10Z"}
    output = "\n".join(["GENERATION_ENVIRONMENT_BEGIN", json.dumps(instance.recipe_bundle["lock"]["guest"]),
                        "GENERATION_ENVIRONMENT_END", "GENERATION_ACTIVITY_BEGIN", json.dumps(activity),
                        "GENERATION_ACTIVITY_END"])
    instance.capture_recipe_runtime(output)
    receipt = json.loads((tmp_path / "recipe-runtime-receipt.json").read_text())
    validate_payload(receipt, "generation_runtime_receipt.schema.json")
    assert receipt["host"]["pinned_inputs_sha256"] == instance.recipe_bundle["recipe"]["pinned_inputs_sha256"]


def test_lock_version_names_both_lock_formats_and_nothing_else():
    assert recipe.lock_version({"schema_version": recipe.LOCK_SCHEMA}) == 1
    assert recipe.lock_version({"schema_version": recipe.LOCK_SCHEMA_V2}) == 2
    with pytest.raises(ValueError, match="unsupported generation dependency lock"):
        recipe.lock_version({"schema_version": "generation_dependency_lock.v3"})


def test_check_host_reports_a_missing_base_box_instead_of_raising(host, tmp_path, monkeypatch):
    monkeypatch.setenv("VAGRANT_HOME", str(tmp_path / "empty-vagrant-home"))
    report = dependency_lock.check_host(backend_name="vmware_desktop", box="fmb/windows-11-arm64", version="0",
                                        imports=["Evtx"])
    assert report["ready"] is False
    assert [row["check"] for row in report["checks"] if not row["ok"]] == ["base box"]


def test_an_image_of_your_own_freezes_and_loads_back(host, tmp_path):
    from fmb.replication import image_files

    image = image_files.load(SOURCE.parents[2] / "examples/decoys.json")
    config = recipe.image_config(image.seed, image.contract)
    contract = recipe.resolved_contract(config)
    public = build_public_manifest(experiment="full_scale", seed=image.seed, contract=contract)
    assignment = select_private_assignment(public, entropy=b"a" * 32)
    directory = tmp_path / "recipe"
    recipe.freeze_recipe(directory, source_root=SOURCE, config=config, population=public, assignment=assignment,
                         guest_plan=build_guest_plan(public, assignment, case="positive"),
                         dependency_lock=host.build(), activity_seed=image.seed, hardware_seed=image.seed)
    loaded = recipe.load_recipe(directory, source_root=directory / "source" / "generation", verify_dependencies=False)
    assert loaded["recipe"]["config"]["population_contract"] == image.contract
