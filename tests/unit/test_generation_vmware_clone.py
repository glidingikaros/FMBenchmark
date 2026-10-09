from pathlib import Path
from types import SimpleNamespace
import ctypes
import errno
import json
import os
import shutil

import pytest

from fmb.generation import vmware_clone as clone
from fmb.generation.pipeline import GenerationPipeline
from fmb.core.schemas import validate_payload
from test_generation_recipe import SOURCE, locked_recipe as locked_recipe


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "base"
    root.mkdir()
    (root / "box.vmx").write_text('nvme0:0.fileName = "disk.vmdk"\n')
    (root / "disk.vmdk").write_text('# Disk DescriptorFile\nparentCID=ffffffff\nRW 1 FLAT "disk-flat.vmdk" 0\n')
    (root / "disk-flat.vmdk").write_bytes(b"protected extent")
    return root / "box.vmx"


def fake_clone(monkeypatch, action=shutil.copyfile):
    def copy(src, dst, flags):
        action(Path(os.fsdecode(src)), Path(os.fsdecode(dst)))
        return 0
    monkeypatch.setattr(clone.sys, "platform", "darwin")
    monkeypatch.setattr(clone.ctypes, "CDLL", lambda *_args, **_kwargs: SimpleNamespace(clonefile=copy))


def test_clone_reads_every_byte_and_keeps_independent_inodes(source, tmp_path, monkeypatch):
    fake_clone(monkeypatch)
    original = {path.name: path.read_bytes() for path in source.parent.iterdir()}
    destination = tmp_path / "owned" / "box.vmx"
    receipt = clone.clone_files(source, destination)
    assert receipt["copy_method"] == clone.COPY_METHOD
    assert {row["path"] for row in receipt["files"]} == set(original)
    assert 'uuid.action = "create"' in destination.read_text()
    for path in source.parent.iterdir():
        assert path.read_bytes() == original[path.name]
        assert path.stat().st_ino != (destination.parent / path.name).stat().st_ino


@pytest.mark.parametrize("boundary", ["hardlink", "corrupt", "unsupported"])
def test_clone_refuses_shared_identity_corruption_and_unsupported_cloning(source, tmp_path, monkeypatch, boundary):
    def operation(src, dst):
        if boundary == "hardlink":
            os.link(src, dst)
        else:
            dst.write_bytes(b"corrupt")
    fake_clone(monkeypatch, operation)
    if boundary == "unsupported":
        def fail(*_):
            ctypes.set_errno(errno.ENOTSUP)
            return 1
        monkeypatch.setattr(clone.ctypes, "CDLL", lambda *_args, **_kwargs: SimpleNamespace(clonefile=fail))
    with pytest.raises((ValueError, OSError), match="identity|hash mismatch|supported"):
        clone.clone_files(source, tmp_path / "owned" / "box.vmx")
    assert (source.parent / "disk-flat.vmdk").read_bytes() == b"protected extent"


@pytest.mark.parametrize("boundary", ["symlink", "absolute", "extent_escape", "parent", "snapshot", "budget"])
def test_clone_rejects_invalid_source_before_copy(source, tmp_path, monkeypatch, boundary):
    if boundary == "symlink":
        (source.parent / "link").symlink_to(source)
    elif boundary == "absolute":
        source.write_text(f'nvme0:0.fileName = "{source.parent / "disk.vmdk"}"\n')
    elif boundary == "extent_escape":
        (source.parent / "disk.vmdk").write_text('parentCID=ffffffff\nRW 1 FLAT "../outside.vmdk" 0\n')
    elif boundary == "parent":
        (source.parent / "disk.vmdk").write_text('parentCID=12345678\nRW 1 FLAT "disk-flat.vmdk" 0\n')
    elif boundary == "snapshot":
        (source.parent / "box.vmsd").write_text('snapshot.numSnapshots = "1"\n')
    else:
        monkeypatch.setattr(clone, "MAX_SOURCE_ENTRIES", 1)
    monkeypatch.setattr(clone.sys, "platform", "darwin")
    monkeypatch.setattr(clone.ctypes, "CDLL", lambda *_args, **_kwargs: pytest.fail("invalid source copied"))
    with pytest.raises(ValueError):
        clone.clone_files(source, tmp_path / "owned" / "box.vmx")
    assert not (tmp_path / "owned").exists()


@pytest.fixture
def pipeline(locked_recipe, tmp_path, monkeypatch):
    directory, lock, *_ = locked_recipe
    import fmb.generation.pipeline as module
    monkeypatch.setattr(module.sys, "executable", lock["tools"]["python"]["path"])
    monkeypatch.setattr(module.sys, "platform", "darwin")
    root = tmp_path / "working"
    root.mkdir()
    instance = GenerationPipeline('vmware_desktop', 'baseline', 'vmdk', False, False,
        experiment='full_scale', case='positive', population_seed=2026091811,
        recipe=directory, output_root=tmp_path / 'outputs', vm_work_root=root)
    instance.vagrant_box_vmx_path = lambda: Path(lock["base"]["vmx_path"])
    monkeypatch.setattr(module.shutil, "disk_usage", lambda _: SimpleNamespace(free=128 * 1024**3))
    instance.preflight_generation_storage(instance.vagrant_box_vmx_path())
    return instance


def test_partial_clone_is_owned_before_copy_and_cleanup_survives_missing_locator(pipeline, monkeypatch):
    def interrupted(source, vmx):
        assert pipeline.vmware_run_vmx_path == vmx
        assert pipeline.vmware_state_identity is not None
        vmx.parent.mkdir(parents=True)
        (vmx.parent / "partial.vmdk").write_bytes(b"partial")
        raise OSError("clone interrupted")
    monkeypatch.setattr(clone, "clone_files", interrupted)
    with pytest.raises(OSError, match="clone interrupted"):
        pipeline.prepare_vmware_clone()
    assert pipeline.no_vm_launch_or_state() is False
    (pipeline.output_dir / ".vagrant").unlink()
    observed = []
    pipeline.is_vmware_vm_running = lambda path: observed.append(path) or False
    assert pipeline.cleanup_vmware_direct() is True
    pipeline.remove_vmware_owned_state()
    assert observed and not pipeline.vagrant_state_dir.exists()
    assert pipeline.vagrant_box_vmx_path().is_file()


def test_cleanup_uses_owned_state_when_output_locator_points_elsewhere(pipeline, monkeypatch):
    fake_clone(monkeypatch)
    pipeline.prepare_vmware_clone()
    locator = pipeline.output_dir / ".vagrant"
    locator.unlink()
    locator.symlink_to(pipeline.vagrant_box_vmx_path().parent)
    pipeline.is_vmware_vm_running = lambda _: False
    assert pipeline.cleanup_vmware_direct() is True
    pipeline.remove_vmware_owned_state()
    assert pipeline.vagrant_box_vmx_path().is_file()
    assert not pipeline.vagrant_state_dir.exists()
    assert (pipeline.output_dir / clone.RECEIPT_NAME).is_file()


def test_owned_state_replacement_is_rejected_without_deletion(pipeline, monkeypatch):
    fake_clone(monkeypatch)
    pipeline.prepare_vmware_clone()
    old = pipeline.vagrant_state_dir.with_name("kept-original")
    pipeline.vagrant_state_dir.rename(old)
    pipeline.vagrant_state_dir.mkdir()
    marker = pipeline.vagrant_state_dir / "unowned.vmdk"
    marker.write_bytes(b"unowned")
    with pytest.raises(ValueError, match="identity changed"):
        pipeline.cleanup_vmware_direct()
    assert marker.read_bytes() == b"unowned"
    assert (old / "machines/default/vmware_desktop/independent-apfs-clone/box.vmx").is_file()


@pytest.mark.parametrize("shared,short", [(True, "artifact"), (False, "artifact"), (False, "working"), (True, None), (False, None)])
@pytest.mark.skipif(os.name == "nt", reason="APFS clone storage checks use POSIX block accounting and paths (macOS generator)")
def test_storage_checks_each_volume_and_preserves_registered_schema(pipeline, monkeypatch, shared, short):
    import fmb.generation.pipeline as module
    output = pipeline.output_dir
    actual_stat = Path.stat
    if not shared:
        def stat(path, *args, **kwargs):
            result = actual_stat(path, *args, **kwargs)
            if path == output:
                values = {name: getattr(result, name) for name in ("st_dev", "st_ino", "st_size", "st_mode", "st_blocks")}
                values["st_dev"] += 1
                return SimpleNamespace(**values)
            return result
        monkeypatch.setattr(Path, "stat", stat)
    def usage(path):
        low = (short == "artifact" and path == output) or (short == "working" and path == pipeline.vm_work_root)
        return SimpleNamespace(free=1 if low else 128 * 1024**3)
    monkeypatch.setattr(module.shutil, "disk_usage", usage)
    if short:
        with pytest.raises(RuntimeError, match="per-volume"):
            pipeline.preflight_generation_storage(pipeline.vagrant_box_vmx_path())
    else:
        pipeline.preflight_generation_storage(pipeline.vagrant_box_vmx_path())
    report = json.loads((output / "vmware-storage-preflight.json").read_text())
    legacy = json.loads((output / "generation_storage_preflight.json").read_text())
    validate_payload(legacy, "generation_storage_preflight.schema.json")
    reserve = module.MIN_GENERATION_RUNTIME_RESERVE_BYTES
    assert report["shared_volume"] == shared
    assert report["auxiliary_media_and_checkpoint_bytes"] == 512 * 1024**2
    assert report["required_free_bytes"] == report["source_allocated_bytes"] + reserve * (2 if shared else 1) + 512 * 1024**2
    assert report["status"] == ("failed" if short else "passed")


@pytest.mark.parametrize("remove", [False, True])
def test_frozen_recipe_binds_clone_helper(locked_recipe, remove):
    from fmb.generation import recipe
    directory, *_ = locked_recipe
    member = directory / "source/vmware_clone.py"
    assert member.read_bytes() == (SOURCE / "vmware_clone.py").read_bytes()
    if remove:
        member.unlink()
    else:
        member.write_bytes(member.read_bytes() + b"\n# changed clone code\n")
    with pytest.raises((ValueError, FileNotFoundError)):
        recipe.load_recipe(directory, source_root=directory / "source", verify_dependencies=False)


@pytest.mark.parametrize("tamper", [None, "receipt", "population", "missing_receipt"])
def test_resume_after_vm_removal_keeps_clone_receipt_and_population_binding(pipeline, monkeypatch, tamper):
    from fmb.generation import factual_challenge
    fake_clone(monkeypatch)
    pipeline.prepare_vmware_clone()
    pipeline.prepare_population()
    image = pipeline.output_dir / "full_scale.vmdk"
    image.write_bytes(b"controlled exported bytes")
    pipeline.native_media_sources = [{"path": pipeline.output_dir / f"media-{i}.vmdk", "unit": i, "port": i} for i in range(3)]
    journal = pipeline.begin_post_export(image)
    journal.run("controlled_export", image, lambda: None, read_only=True)
    receipt_path = pipeline.output_dir / clone.RECEIPT_NAME
    retained_bytes = receipt_path.read_bytes()
    pipeline.is_vmware_vm_running = lambda _: False
    assert pipeline.cleanup_vmware_direct() is True
    pipeline.remove_vmware_owned_state()
    pipeline.cleanup_population_inputs()
    cleanup = {"schema_version": "generation_cleanup.v1", "provider": "vmware_desktop",
               "status": "destroyed", "provider_state_remaining": False}
    pipeline.record_post_export_cleanup(cleanup)
    assert not pipeline.vagrant_state_dir.exists()
    if tamper == "population":
        statepath = pipeline.post_export_directory() / "state.json"
        state = json.loads(statepath.read_text())
        state["guest_plan"]["scenario_inputs"]["shellbag_path_residue_01"]["population_paths"].append("C:\\wrong")
        statepath.write_text(json.dumps(state))
        with pytest.raises(ValueError, match="guest inputs differ"):
            GenerationPipeline.resume_post_export(pipeline.output_dir)
        assert not (pipeline.output_dir / "manifest.json").exists()
        return
    resumed = GenerationPipeline.resume_post_export(pipeline.output_dir)
    assert resumed.population_guest_plan == pipeline.population_guest_plan
    assert resumed.public_population_manifest == pipeline.public_population_manifest
    resumed.apply_post_export_interventions = lambda _: None
    resumed.logfile_retention_planned = lambda: None
    resumed.archive_control_paths = lambda: None
    resumed.pilot_media_module = lambda: SimpleNamespace(export=lambda *_: [])
    monkeypatch.setattr(factual_challenge, "validate_receipt", lambda *_: None)
    (pipeline.output_dir / "factual-challenge-receipt.json").write_text("{}")
    for name in ("checkpoint-01.evtx", "checkpoint-02.evtx", "checkpoint-03.log", "checkpoint-04.vmdk"):
        (pipeline.output_dir / "factual-checkpoints" / name).write_bytes(b"controlled checkpoint")
    if tamper == "receipt":
        receipt = json.loads(receipt_path.read_text())
        receipt["files"][0]["sha256"] = "0" * 64
        receipt_path.write_text(json.dumps(receipt))
    elif tamper == "missing_receipt":
        receipt_path.unlink()
    if tamper:
        with pytest.raises(ValueError, match="clone receipt"):
            resumed.run_post_export_resume()
        assert not (pipeline.output_dir / "manifest.json").exists()
    else:
        resumed.run_post_export_resume()
        manifest = json.loads((pipeline.output_dir / "manifest.json").read_text())
        entry = next(row for row in manifest["artifacts"] if row["file"] == clone.RECEIPT_NAME)
        assert receipt_path.read_bytes() == retained_bytes
        assert entry["sha256"] == resumed.calculate_hash(receipt_path)
        assert entry["size_bytes"] == len(retained_bytes)
        assert "vm_work_root" not in manifest and "copy_method" not in manifest
        validate_payload(manifest, "generation_manifest.schema.json")


def test_vm_work_root_constructor_requires_recipe_before_creating_outputs(tmp_path):
    with pytest.raises(ValueError, match="requires frozen recipe"):
        GenerationPipeline('vmware_desktop', 'baseline', 'vmdk', False, False,
            experiment='full_scale', population_seed=2026091811,
            output_root=tmp_path / "outputs", vm_work_root=tmp_path)
    assert not (tmp_path / "outputs").exists()


@pytest.mark.parametrize("path,valid", [
    ("vmware-clone-receipt.json", True), ("factual-checkpoints/checkpoint-01.evtx", True),
    ("factual-checkpoints/checkpoint-02.evtx", True), ("factual-checkpoints/checkpoint-03.log", True),
    ("factual-checkpoints/checkpoint-04.vmdk", True), ("factual-checkpoints/checkpoint-05.vmdk", False),
    ("factual-checkpoints/checkpoint-01.vmdk", False), ("factual-checkpoints/../disk.vmdk", False),
    ("../outside.vmdk", False), ("/absolute.vmdk", False), ("other/nested.vmdk", False),
    ("factual-checkpoints\\checkpoint-01.evtx", False),
])
def test_generation_manifest_accepts_only_scheduled_checkpoint_paths(path, valid):
    from fmb.core.schemas import schema_validation_errors
    manifest = {"schema_version": "generation_manifest.v1", "scenario": "full-roster", "experiment": "full_scale",
        "artifacts": [{"file": path, "sha256": "a" * 64, "size_bytes": 1}],
        "cleanup": {"schema_version": "generation_cleanup.v1", "provider": "vmware_desktop",
                    "status": "destroyed", "provider_state_remaining": False}}
    assert bool(schema_validation_errors(manifest, "generation_manifest.schema.json")) is not valid


def test_preexisting_state_is_never_adopted_or_destroyed(pipeline):
    pipeline.vagrant_state_dir.mkdir()
    marker = pipeline.vagrant_state_dir / "unowned.vmdk"
    marker.write_bytes(b"unowned")
    with pytest.raises(FileExistsError):
        pipeline.prepare_vmware_clone()
    with pytest.raises(ValueError, match="unowned"):
        pipeline.cleanup_vmware_direct()
    pipeline.destroy_vm = lambda: pytest.fail("unowned state destroyed")
    assert pipeline.cleanup() is None
    assert marker.read_bytes() == b"unowned"


def test_cleanup_rejects_vm_paths_outside_owned_provider_before_query_or_stop(pipeline, monkeypatch):
    fake_clone(monkeypatch)
    pipeline.prepare_vmware_clone()
    (pipeline.vmware_provider_state() / "outside.vmx").symlink_to(pipeline.vagrant_box_vmx_path())
    pipeline.is_vmware_vm_running = lambda _: pytest.fail("outside VM queried")
    assert pipeline.cleanup_vmware_direct() is False
    assert pipeline.vmware_run_vmx_path.is_file() and pipeline.vagrant_box_vmx_path().is_file()
