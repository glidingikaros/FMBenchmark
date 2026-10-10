from __future__ import annotations
import json


from pathlib import Path


import pytest


from fmb.collection.run import lock as run_lock


from fmb.collection.tools.host import vmware as kape_appliance_runner


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_run_lock_rejects_unknown_schema(tmp_path: Path) -> None:
    current_root = tmp_path / "current"
    lock_path = run_lock.evidence_image_run_lock_path(current_root)
    lock_path.parent.mkdir(parents=True)
    write_json(lock_path, {"schema_version": "future", "kind": run_lock.LOCK_KIND})

    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    reclaimable, reason = run_lock.can_reclaim_run_lock(payload)

    assert reclaimable is False
    assert "schema" in reason


def test_run_lock_lifecycle_and_reclaim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    current_root = tmp_path / "current"

    with run_lock.acquire_evidence_image_run_lock(
        current_root=current_root,
        requested_run_id="run-1",
        command=["fmb", "start"],
    ) as lock:
        assert lock.lock_path.is_file()

        with pytest.raises(
            run_lock.ActiveEvidenceImageRunError,
            match="evidence-image run already active",
        ):
            with run_lock.acquire_evidence_image_run_lock(
                current_root=current_root, requested_run_id="run-2"
            ):
                pass

    assert not run_lock.evidence_image_run_lock_path(current_root).exists()

    stale_lock = run_lock.evidence_image_run_lock_path(current_root)
    stale_lock.parent.mkdir(parents=True, exist_ok=True)
    stale_payload = run_lock.build_run_guard_payload(
        current_root=current_root, requested_run_id="run-stale"
    )
    stale_payload["pid"] = -1
    write_json(stale_lock, stale_payload)
    assert run_lock.can_reclaim_run_lock(run_lock.read_lock_payload(stale_lock))[0]

    monkeypatch.setattr(run_lock, "current_host", lambda: "this-host")
    other_host_payload = {**stale_payload, "host": "other-host"}
    assert run_lock.can_reclaim_run_lock(other_host_payload) == (
        False,
        "lock belongs to another host: other-host",
    )


def test_vmware_worker_source_must_be_flat_and_unlocked(tmp_path: Path) -> None:
    disk = tmp_path / "Virtual Disk.vmdk"
    disk.write_text(
        '# Disk DescriptorFile\nparentCID=ffffffff\ncreateType="twoGbMaxExtentSparse"\n'
    )
    vmx = tmp_path / "box.vmx"
    vmx.write_text(
        'nvme0:0.present = "TRUE"\nnvme0:0.fileName = "Virtual Disk.vmdk"\n',
        encoding="utf-8",
    )

    report = kape_appliance_runner.assert_flat_vmware_source(vmx)

    assert report["snapshot_count"] == 0
    assert report["disk_descriptors"] == [str(disk.resolve())]

    disk.write_text(
        '# Disk DescriptorFile\nparentFileNameHint="Virtual Disk-000001.vmdk"\n',
        encoding="utf-8",
    )
    with pytest.raises(
        kape_appliance_runner.KapeApplianceError,
        match="backing parent",
    ):
        kape_appliance_runner.assert_flat_vmware_source(vmx)

    disk.write_text(
        '# Disk DescriptorFile\nparentCID=1234abcd\ncreateType="twoGbMaxExtentSparse"\n',
        encoding="utf-8",
    )
    with pytest.raises(
        kape_appliance_runner.KapeApplianceError,
        match="non-flat parent CID",
    ):
        kape_appliance_runner.assert_flat_vmware_source(vmx)


def test_analysis_worker_box_resolution_honors_vagrant_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    box_root = (
        tmp_path
        / "boxes"
        / "local-VAGRANTSLASH-windows-worker"
        / "1.0.0"
        / "arm64"
        / "vmware_desktop"
    )
    box_root.mkdir(parents=True)
    vmx = box_root / "box.vmx"
    vmx.write_text('config.version = "8"\n', encoding="utf-8")
    monkeypatch.setenv("VAGRANT_HOME", str(tmp_path))

    assert (
        kape_appliance_runner.vagrant_box_vmx_path(
            box="local/windows-worker",
            provider="vmware_desktop",
        )
        == vmx.resolve()
    )


def test_vmware_worker_clone_cannot_reference_a_disk_outside_its_run(
    tmp_path: Path,
) -> None:
    source_disk = tmp_path / "source" / "disk.vmdk"
    source_disk.parent.mkdir()
    source_disk.write_text(
        '# Disk DescriptorFile\nparentCID=ffffffff\ncreateType="twoGbMaxExtentSparse"\n'
    )
    worker_dir = tmp_path / "run" / ".vmrun-appliance"
    worker_dir.mkdir(parents=True)
    worker_vmx = worker_dir / "box.vmx"
    worker_vmx.write_text(
        f'nvme0:0.fileName = "{source_disk}"\n',
        encoding="utf-8",
    )

    with pytest.raises(
        kape_appliance_runner.KapeApplianceError,
        match="outside its isolated run directory",
    ):
        kape_appliance_runner.assert_isolated_vmware_worker(worker_vmx)


def test_vmware_runtime_storage_preflight_fails_before_clone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    vmx = source_dir / "box.vmx"
    vmx.write_text('nvme0:0.fileName = "disk.vmdk"\n')
    (source_dir / "disk.vmdk").write_bytes(b"descriptor")
    stage_dir = tmp_path / "run"
    stage_dir.mkdir()
    plan = {}

    monkeypatch.setattr(
        kape_appliance_runner.shutil,
        "disk_usage",
        lambda _path: __import__("types").SimpleNamespace(total=10, used=9, free=1),
    )

    with pytest.raises(
        kape_appliance_runner.KapeApplianceError,
        match="insufficient free space",
    ):
        kape_appliance_runner.preflight_vmware_runtime(
            plan=plan,
            source_vmx=vmx,
            stage_dir=stage_dir,
        )

    report = json.loads(
        (stage_dir / "vmware_runtime_preflight.json").read_text(encoding="utf-8")
    )
    assert report["status"] == "failed"
    assert report["required_free_bytes"] > report["available_free_bytes"]


def test_appliance_vmx_disables_stale_iso_media(tmp_path: Path) -> None:
    vmx = tmp_path / "box.vmx"
    vmx.write_text(
        'sata0:1.present = "TRUE"\n'
        'sata0:1.deviceType = "cdrom-image"\n'
        'sata0:1.fileName = "/stale/installer.iso"\n'
        'sata0:1.startConnected = "TRUE"\n'
        'nvme0:0.fileName = "Virtual Disk.vmdk"\n',
        encoding="utf-8",
    )

    kape_appliance_runner.apply_appliance_vmx_settings(vmx)

    text = vmx.read_text(encoding="utf-8")
    assert "/stale/installer.iso" not in text
    assert 'sata0:1.present = "FALSE"' in text
    assert 'sata0:1.startConnected = "FALSE"' in text


