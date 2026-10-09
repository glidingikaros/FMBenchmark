from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if path.name == "population.py":
        module.POPULATION_CONTRACT_PATH = ROOT / "tests/fixtures/generation/populations.v1.json"
        module.load_population_contract.__defaults__ = (module.POPULATION_CONTRACT_PATH,)
    return module


@pytest.mark.parametrize("case", ["positive", "benign"])
def test_native_preallocation_lifecycle_receipt_is_strict_and_preserves_population(case, verified_receipts):
    population = load("allocation_population", ROOT / "src/fmb/generation/population.py")
    public = population.build_public_manifest(experiment="full_scale", seed=91)
    assignment = population.select_private_assignment(public, entropy=b"public-allocation-lifecycle-test")
    plan = population.build_guest_plan(public, assignment, case=case)
    receipts = verified_receipts(population, plan, case=case)
    population.validate_guest_receipts(plan, receipts, case=case)
    assert sum(len(row["members"]) for row in public["scenarios"].values()) == 473
    control = plan["scenario_inputs"]["ntfs_allocation_01"]
    assert len(control["population_paths"]) == 10
    assert len(control["operation_refs"]) == (2 if case == "positive" else 0)
    assert len([row for row in control["storage_cases"] if row["storage_mode"] == "preallocation_request_then_close"]) == 1


@pytest.mark.parametrize("change", ["missing", "identity", "open_allocation", "closed_allocation", "open_eof", "closed_eof", "content", "boolean_size"])
def test_native_preallocation_lifecycle_receipt_rejects_incomplete_or_false_readback(change, verified_receipts):
    population = load("allocation_population_invalid", ROOT / "src/fmb/generation/population.py")
    public = population.build_public_manifest(experiment="full_scale", seed=91)
    assignment = population.select_private_assignment(public, entropy=b"public-allocation-lifecycle-test")
    plan = population.build_guest_plan(public, assignment)
    receipts = verified_receipts(population, plan, case="positive")
    receipt = next(row for row in receipts if row["scenario_id"] == "ntfs_allocation_01")
    control = receipt["preallocation_close_controls"][0]
    if change == "missing":
        receipt["preallocation_close_controls"] = []
    elif change == "identity":
        control["path"] += ".wrong"
    elif change == "open_allocation":
        control["open_allocation_bytes"] = 8192
    elif change == "closed_allocation":
        control["closed_allocation_bytes"] = 65536
    elif change == "open_eof":
        control["open_eof_bytes"] += 1
    elif change == "closed_eof":
        control["closed_eof_bytes"] += 1
    elif change == "content":
        control["content_sha256"] = "0" * 64
    elif change == "boolean_size":
        control["open_allocation_bytes"] = True
    with pytest.raises(population.PopulationError):
        population.validate_guest_receipts(plan, receipts, case="positive")


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell unavailable")
def test_allocation_native_csharp_compiles_and_matches_file_standard_info_abi(tmp_path):
    task = yaml.safe_load((ROOT / "src/fmb/generation/ansible/roles/manipulation/tasks/pilot_ntfs_allocation_01.yml").read_text())[0]
    script = task["ansible.windows.win_shell"]
    code = re.search(r"Add-Type -TypeDefinition @'\n(.*?)\n'@", script, re.DOTALL).group(1)
    source = tmp_path / "compile.ps1"
    source.write_text("$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n" + code + "\n'@\n" + r'''
$standard = [type][LocalAllocationControl+StandardInfo]
$offsets = @{}
foreach ($name in @('AllocationSize','EndOfFile','NumberOfLinks','DeletePending','Directory')) {
  $offsets[$name] = [Runtime.InteropServices.Marshal]::OffsetOf($standard, $name).ToInt64()
}
@{ allocation_size = [Runtime.InteropServices.Marshal]::SizeOf([LocalAllocationControl+AllocationInfo]::new());
   standard_size = [Runtime.InteropServices.Marshal]::SizeOf([LocalAllocationControl+StandardInfo]::new());
   offsets = $offsets; windows_api_invoked = $false } | ConvertTo-Json -Compress
''')
    result = subprocess.run(["pwsh", "-NoProfile", "-File", str(source)], text=True, capture_output=True, check=True, timeout=120)
    value = json.loads(result.stdout)
    assert value == {"allocation_size": 8, "standard_size": 24,
        "offsets": {"AllocationSize": 0, "EndOfFile": 8, "NumberOfLinks": 16, "DeletePending": 20, "Directory": 21},
        "windows_api_invoked": False}


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="QEMU unavailable")
@pytest.mark.parametrize("change", [None, "persistent_excess", "wrong_closed_receipt", "content"])
def test_post_export_verifies_native_release_and_content_without_writing_control(tmp_path, change):
    binary = load("allocation_binary_fixture", Path(__file__).with_name("test_ntfs_surfaces.py"))
    raw, _mft, _csv = binary._fixture(tmp_path)
    data = bytearray(raw.read_bytes())
    length = 4097
    clusters = 3 if change == "persistent_excess" else 2
    record = binary._record(32, [binary._resident(0x30, binary._fn("preallocated.bin")),
                                binary._nonresident(0x80, lcn=55, count=clusters)])
    offset = 4 * 4096 + 32 * 1024
    data[offset:offset + 1024] = record
    content = bytes((i * 37 + 19) % 251 for i in range(length))
    data[55 * 4096:55 * 4096 + length] = content
    if change == "content":
        data[55 * 4096] ^= 1
    raw.write_bytes(data)
    image = tmp_path / "export.vmdk"
    subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "vmdk", str(raw), str(image)], check=True, capture_output=True, timeout=30)
    before = image.read_bytes()
    path = r"C:\Cases\preallocated.bin"
    receipt = {"scenario_id": "ntfs_allocation_01", "preallocation_close_controls": [{
        "path": path, "requested_allocation_bytes": 65536, "open_allocation_bytes": 65536,
        "open_eof_bytes": length, "closed_allocation_bytes": 12288 if change == "wrong_closed_receipt" else 8192,
        "closed_eof_bytes": length, "content_sha256": hashlib.sha256(content).hexdigest(),
    }]}
    pipeline = load("allocation_lifecycle_pipeline", ROOT / "src/fmb/generation/pipeline.py")
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.work_dir = (ROOT / "src/fmb/generation").absolute()
    instance.export_format = "vmdk"
    instance.population_guest_plan = {"scenario_inputs": {"ntfs_allocation_01": {
        "operation_refs": [], "population_paths": [path], "storage_cases": [{"path": path,
            "storage_mode": "preallocation_request_then_close", "logical_length": length}],
    }}}
    instance.ground_truth = [receipt]
    if change:
        with pytest.raises(ValueError, match="storage mode was not realized"):
            instance.apply_post_export_interventions(image)
    else:
        instance.apply_post_export_interventions(image)
        control = receipt["post_export_intervention"]["preallocation_close_controls"][0]
        assert control["exported_allocated_bytes"] == 8192
        assert control["content_sha256"] == hashlib.sha256(content).hexdigest()
        assert control["content_readback"]["written_ranges"] == []
    assert image.read_bytes() == before
