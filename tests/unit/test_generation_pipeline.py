from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import os

import pytest


def load_generation_pipeline_module():
    module_path = Path(__file__).resolve().parents[2] / "src/fmb/generation" / "pipeline.py"
    spec = importlib.util.spec_from_file_location("generation_pipeline", module_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def mock_vagrant_boot_process(pipeline, monkeypatch, *, chunks=(), return_code=0, events=None):
    events = events if events is not None else []
    unread = iter((*chunks, b""))

    class Output:
        closed = False

        def fileno(self):
            return 17

        def readline(self):
            pytest.fail("a partial Vagrant line must never enter blocking readline")

        def close(self):
            self.closed = True
            events.append("stdout-closed")

    class Process:
        pid = 123
        stdout = Output()

        def poll(self):
            return return_code

        def wait(self, timeout=None):
            events.append("vagrant-finished")
            return return_code

    process = Process()
    monkeypatch.setattr(pipeline.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(pipeline.select, "select", lambda *args, **kwargs: ([process.stdout], [], []))
    monkeypatch.setattr(pipeline.os, "read", lambda *_args: next(unread, b""))
    return process


def persist_archive_control_fixture(instance):
    paths = instance.archive_control_paths()
    records = []
    for index, path in enumerate(paths):
        records.append({"path": path, "file_id_before": f"0x{index:016x}", "file_id_after": f"0x{index:016x}",
                        "content_sha256_before": "a" * 64, "content_sha256_after": "a" * 64,
                        "creation_before_utc": "2026-09-09T00:00:00Z", "creation_after_utc": "2026-09-09T00:00:00Z",
                        "write_before_utc": "2026-09-09T00:00:00Z", "write_after_utc": "2018-06-10T19:00:00Z",
                        "archive_effective_write_utc": "2018-06-10T19:00:00Z"})
    receipt = {"schema_version": "native_archive_restore_receipt.v1", "archive_requested_write_utc": "2018-06-10T12:00:00Z",
               "operation": "ZipFileExtensions.ExtractToFile_overwrite_existing", "count": len(paths),
               "records": records, "postconditions_verified": True}
    planned = instance.population_guest_plan["scenario_inputs"]["timestomp_01"]
    if "archive_restore_paths" in planned:
        receipt["schema_version"] = "native_archive_restore_receipt.v2"
        selected = {p.casefold() for p in planned["archive_restore_paths"]}
        for row in records:
            row["restored"] = row["path"].casefold() in selected
            if not row["restored"]:
                row["write_after_utc"] = row["archive_effective_write_utc"] = row["write_before_utc"]
    instance.capture_archive_control("ARCHIVE_RESTORE_CONTROL_BEGIN\n" + json.dumps(receipt) + "\nARCHIVE_RESTORE_CONTROL_END")

def test_vmware_disk_from_vmx_accepts_nvme_disk_line(tmp_path: Path) -> None:
    pipeline = load_generation_pipeline_module()
    disk = tmp_path / "Windows 11 ARM64.vmdk"
    disk.write_text("# descriptor\n")
    vmx = tmp_path / "vm.vmx"
    vmx.write_text(
        'config.version = "8"\n'
        'nvme0:0.present = "TRUE"\n'
        'nvme0:0.fileName = "Windows 11 ARM64.vmdk"\n'
    )

    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)

    assert instance.vmware_disk_from_vmx(vmx) == disk


def test_bounded_receipt_parser_preserves_windows_paths_from_ansible_output() -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    receipt = {
        "scenario_id": "timestomp_01",
        "operation_count": 2,
        "postcondition_verified": True,
    }
    payload = json.dumps(receipt, separators=(",", ":"))
    ansible_output = "\n".join(
        (
            '    "msg": [',
            '        "GROUND_TRUTH_BEGIN",',
            f"        {json.dumps(payload)},",
            '        "GROUND_TRUTH_END"',
            "    ]",
        )
    )

    chunks = instance.extract_ground_truth_chunks(ansible_output)

    assert len(chunks) == 1
    assert instance.parse_ground_truth_chunk(chunks[0]) == receipt


def test_bounded_receipt_parser_rejects_a_non_object_payload() -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)

    with pytest.raises(ValueError, match="JSON object"):
        instance.parse_ground_truth_chunk('[{"scenario_id":"timestomp_01"}]')


def test_vmware_keeps_one_nat_management_adapter_and_one_host_only_adapter() -> None:
    vagrantfile = (
        Path(__file__).resolve().parents[2] / "src/fmb/generation" / "Vagrantfile"
    ).read_text(encoding="utf-8")

    assert 'vmware.vmx["ethernet0.connectiontype"] = "nat"' in vagrantfile
    assert 'vmware.vmx["ethernet1.connectiontype"] = "hostonly"' in vagrantfile
    assert "bridged" not in vagrantfile.replace("bridged adapter", "")
    assert "public_network" not in vagrantfile
    assert "vmware.enable_vmrun_ip_lookup = false" in vagrantfile


def test_vmware_generation_never_exports_after_a_failed_soft_halt(
    tmp_path: Path,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    vmx = tmp_path / "worker.vmx"
    vmx.write_text('config.version = "8"\n', encoding="utf-8")
    instance.discover_current_vmware_vmx_path = lambda: vmx
    calls: list[list[str]] = []

    def fail_soft(args, **_kwargs):
        calls.append(args)
        raise __import__("subprocess").CalledProcessError(1, args)

    instance.run_vmrun = fail_soft

    with pytest.raises(RuntimeError, match="soft VMware halt failed"):
        instance.halt_vm()

    assert calls == [["stop", str(vmx), "soft"]]


@pytest.mark.skipif(os.name == "nt", reason="the VMware Fusion generator manages POSIX process groups and runs only on macOS")
def test_macos_generation_terminates_only_its_spawned_process_group(monkeypatch):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.is_macos = True
    signals = []

    class Process:
        pid = 123
        def poll(self):
            return 0
        def wait(self, timeout=None):
            assert timeout == 15
            return 0

    monkeypatch.setattr(pipeline.os, "getpgid", lambda _pid: pytest.fail("the exited leader must not be looked up"))
    monkeypatch.setattr(pipeline.os, "killpg", lambda group, sent: signals.append((group, sent)))
    instance.terminate_process(Process())
    assert signals == [(123, pipeline.signal.SIGTERM), (123, pipeline.signal.SIGKILL)]


def test_vmware_cleanup_removes_provider_state_after_vagrant_reports_success(
    tmp_path: Path,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.is_macos = True
    instance.keep_vm = False
    instance.active_process = None
    instance.population_inputs_path = None
    instance.cleanup_winrm_proxy = lambda: None
    instance.terminate_process = lambda _process: None
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    provider_state = instance.vmware_provider_state()
    provider_state.mkdir(parents=True)
    commands: list[tuple[list[str], dict[str, object]]] = []
    direct_cleanup_calls: list[str] = []
    vagrant_environment = {"VAGRANT_DOTFILE_PATH": str(instance.vagrant_state_dir)}

    instance.vagrant_environment = lambda: vagrant_environment
    instance.run_command = lambda command, **kwargs: commands.append((command, kwargs))

    def remove_provider_state() -> bool:
        direct_cleanup_calls.append("direct")
        __import__("shutil").rmtree(provider_state)
        return True

    instance.cleanup_vmware_direct = remove_provider_state

    instance.cleanup()

    assert commands == [
        (
            ["vagrant", "destroy", "-f"],
            {"timeout_seconds": 120, "env": vagrant_environment},
        )
    ]
    assert direct_cleanup_calls == ["direct"]


def test_vmware_cleanup_failure_is_fatal_after_vagrant_reports_success(
    tmp_path: Path,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.is_macos = True
    instance.keep_vm = False
    instance.active_process = None
    instance.population_inputs_path = None
    instance.cleanup_winrm_proxy = lambda: None
    instance.terminate_process = lambda _process: None
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    instance.vmware_provider_state().mkdir(parents=True)
    instance.vagrant_environment = lambda: {
        "VAGRANT_DOTFILE_PATH": str(instance.vagrant_state_dir)
    }
    instance.run_command = lambda _command, **_kwargs: None
    instance.cleanup_vmware_direct = lambda: False

    with pytest.raises(RuntimeError, match="VMware provider state remains"):
        instance.cleanup()


def test_vmware_cleanup_rejects_a_running_orphan_after_metadata_disappears(
    tmp_path: Path,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.is_macos = True
    instance.keep_vm = False
    instance.active_process = None
    instance.population_inputs_path = None
    instance.cleanup_winrm_proxy = lambda: None
    instance.terminate_process = lambda _process: None
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    provider_state = instance.vmware_provider_state()
    provider_state.mkdir(parents=True)
    vmx_path = provider_state / "worker.vmx"
    vmx_path.write_text('config.version = "8"\n', encoding="utf-8")
    assert instance.discover_current_vmware_vmx_path() == vmx_path
    __import__("shutil").rmtree(provider_state)
    instance.vagrant_environment = lambda: {
        "VAGRANT_DOTFILE_PATH": str(instance.vagrant_state_dir)
    }
    instance.run_command = lambda _command, **_kwargs: None

    class VmrunList:
        stdout = f"Total running VMs: 1\n{vmx_path}\n"

    instance.run_vmrun = lambda _args, **_kwargs: VmrunList()
    instance.cleanup_vmware_direct = lambda: False

    with pytest.raises(RuntimeError, match="VMware provider state remains"):
        instance.cleanup()


def test_vmware_cleanup_ignores_a_different_running_vm_after_metadata_disappears(
    tmp_path: Path,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.is_macos = True
    instance.vmrun_cmd = "/Applications/VMware Fusion.app/Contents/Library/vmrun"
    instance.keep_vm = False
    instance.active_process = None
    instance.population_inputs_path = None
    instance.cleanup_winrm_proxy = lambda: None
    instance.terminate_process = lambda _process: None
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    provider_state = instance.vmware_provider_state()
    provider_state.mkdir(parents=True)
    vmx_path = provider_state / "worker.vmx"
    vmx_path.write_text('config.version = "8"\n', encoding="utf-8")
    assert instance.discover_current_vmware_vmx_path() == vmx_path
    __import__("shutil").rmtree(provider_state)
    instance.vagrant_environment = lambda: {
        "VAGRANT_DOTFILE_PATH": str(instance.vagrant_state_dir)
    }
    instance.run_command = lambda _command, **_kwargs: subprocess.CompletedProcess(_command, 0, stdout="")

    class VmrunList:
        stdout = f"Total running VMs: 1\n{tmp_path / 'unrelated.vmx'}\n"

    instance.run_vmrun = lambda _args, **_kwargs: VmrunList()

    assert instance.cleanup() == {
        "schema_version": "generation_cleanup.v1",
        "provider": "vmware_desktop",
        "status": "destroyed",
        "provider_state_remaining": False,
    }


def test_vmware_cleanup_verifies_state_removal_instead_of_trusting_fallback(
    tmp_path: Path,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.is_macos = True
    instance.keep_vm = False
    instance.active_process = None
    instance.population_inputs_path = None
    instance.cleanup_winrm_proxy = lambda: None
    instance.terminate_process = lambda _process: None
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    instance.vmware_provider_state().mkdir(parents=True)
    instance.vagrant_environment = lambda: {
        "VAGRANT_DOTFILE_PATH": str(instance.vagrant_state_dir)
    }
    instance.run_command = lambda _command, **_kwargs: None
    instance.cleanup_vmware_direct = lambda: True

    with pytest.raises(RuntimeError, match="VMware provider state remains"):
        instance.cleanup()


def test_vmware_cleanup_verifies_state_removal_after_exhausted_vagrant_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.is_macos = True
    instance.keep_vm = False
    instance.active_process = None
    instance.population_inputs_path = None
    instance.cleanup_winrm_proxy = lambda: None
    instance.terminate_process = lambda _process: None
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    instance.vmware_provider_state().mkdir(parents=True)
    instance.vagrant_environment = lambda: {
        "VAGRANT_DOTFILE_PATH": str(instance.vagrant_state_dir)
    }

    def fail_destroy(command, **_kwargs):
        raise __import__("subprocess").CalledProcessError(1, command)

    instance.run_command = fail_destroy
    instance.cleanup_hyperv_direct = lambda: False
    instance.cleanup_vmware_direct = lambda: True
    monkeypatch.setattr(pipeline.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="VMware provider state remains"):
        instance.cleanup()


@pytest.mark.parametrize("provider", ("vmware_desktop",))
def test_cleanup_rejects_remaining_vagrant_provider_state(
    tmp_path: Path,
    provider: str,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = provider
    instance.is_macos = False
    instance.keep_vm = False
    instance.active_process = None
    instance.population_inputs_path = None
    instance.cleanup_winrm_proxy = lambda: None
    instance.terminate_process = lambda _process: None
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    provider_state = (
        instance.vagrant_state_dir / "machines" / "default" / provider
    )
    provider_state.mkdir(parents=True)
    (provider_state / "id").write_text("still-present", encoding="utf-8")
    instance.vagrant_environment = lambda: {
        "VAGRANT_DOTFILE_PATH": str(instance.vagrant_state_dir)
    }
    instance.run_command = lambda _command, **_kwargs: None

    with pytest.raises(RuntimeError, match="provider state remains"):
        instance.cleanup()


def test_run_reports_success_only_after_cleanup_succeeds(capsys) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.is_macos = False
    instance.output_dir = Path("/tmp/generated-output")
    instance.preflight_checks = lambda: None
    instance.prepare_population = lambda: None
    instance.prepare_native_media = lambda: None
    instance.provision_vm = lambda: None
    instance.halt_vm = lambda: None
    instance.discover_disk_path = lambda: Path("/tmp/source.vmdk")
    instance.extract_disk = lambda _source: None

    def fail_cleanup() -> None:
        raise RuntimeError("cleanup failed")

    instance.cleanup = fail_cleanup

    with pytest.raises(RuntimeError, match="cleanup failed"):
        instance.run()

    assert "Pipeline completed successfully" not in capsys.readouterr().out


def _host_phase_records(output):
    prefix = "FMB_GENERATION_PHASE "
    return [json.loads(line[len(prefix):]) for line in output.splitlines() if line.startswith(prefix)]


@pytest.mark.parametrize("error_type", [None, RuntimeError, KeyboardInterrupt])
def test_host_phase_uses_monotonic_duration_and_preserves_errors(monkeypatch, capsys, error_type):
    pipeline = load_generation_pipeline_module()
    ticks = iter([4_000_000_000, 4_250_000_000])
    utc = iter(["2026-09-30T08:01:00+00:00", "2026-09-30T08:00:00+00:00"])
    monkeypatch.setattr(pipeline.time, "monotonic_ns", lambda: next(ticks))
    monkeypatch.setattr(pipeline, "utc_now_iso", lambda: next(utc))
    real_print = print

    def flushed_print(*args, **kwargs):
        assert kwargs == {"flush": True}
        real_print(*args, **kwargs)

    monkeypatch.setattr(pipeline, "print", flushed_print, raising=False)
    failure = error_type("private path, command and password") if error_type else None
    if failure is None:
        with pipeline._host_phase("preflight"):
            pass
    else:
        failure.add_note("existing private note")
        with pytest.raises(error_type) as caught:
            with pipeline._host_phase("preflight"):
                raise failure
        assert caught.value is failure
        assert failure.__notes__ == ["existing private note"]

    completion = {
        "utc": "2026-09-30T08:00:00+00:00",
        "phase": "preflight",
        "outcome": "error" if failure is not None else "ok",
        "elapsed_seconds": 0.25,
    }
    if failure is not None:
        completion["error_type"] = error_type.__name__
    assert _host_phase_records(capsys.readouterr().out) == [
        {"utc": "2026-09-30T08:01:00+00:00", "phase": "preflight",
         "outcome": "start", "elapsed_seconds": 0.0},
        completion,
    ]


@pytest.mark.parametrize("output_error", [BrokenPipeError, OSError, ValueError])
def test_host_phase_output_failure_cannot_abort_work_or_replace_its_error(monkeypatch, output_error):
    pipeline = load_generation_pipeline_module()
    output_attempts = []

    def failed_output(*args, **kwargs):
        output_attempts.append(kwargs)
        raise output_error("stdout unavailable")

    monkeypatch.setattr(pipeline, "print", failed_output, raising=False)
    completed = []
    with pipeline._host_phase("preflight"):
        completed.append(True)
    failure = ValueError("primary private input failure")
    with pytest.raises(ValueError) as caught:
        with pipeline._host_phase("cleanup"):
            raise failure
    assert completed == [True]
    assert caught.value is failure
    assert output_attempts == [{"flush": True}] * 4


@pytest.fixture
def host_phase_pipeline(tmp_path):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.scenario = "ads_payload_01"
    instance.output_dir = tmp_path / "output"
    instance.population_guest_plan = None
    events = []

    def operation(name, result=None):
        def perform(*_args, **_kwargs):
            events.append(name)
            return result
        return perform

    instance.preflight_checks = operation("preflight")
    instance.prepare_population = operation("population")
    instance.prepare_native_media = operation("media")
    instance.vagrant_environment = operation("environment", {})
    instance.run_vmware_vagrant_boot = operation("boot", "provider output")
    instance.run_ansible_playbook = operation("ansible", "playbook output")
    instance.capture_archive_control = operation("archive_control")
    instance.extract_ground_truth_chunks = operation("ground_truth_chunks", ["bounded receipt"])
    instance.parse_ground_truth_chunk = operation("parse_receipt", {"scenario_id": "ads_payload_01"})
    instance.capture_ground_truth = operation("ground_truth")
    instance.halt_vm = operation("halt")
    instance.discover_disk_path = operation("disk", tmp_path / "source.vmdk")
    instance.extract_disk = operation("export", {"artifacts": []})
    instance.cleanup = operation("cleanup", {"status": "destroyed"})
    instance.record_post_export_cleanup = operation("record_cleanup")
    instance.publish_manifest = operation("publish")
    return pipeline, instance, events


def test_host_phases_keep_operation_order_and_separate_boot_from_ansible(host_phase_pipeline, capsys):
    _, instance, events = host_phase_pipeline
    instance.run()
    assert events == [
        "preflight", "population", "media", "environment", "boot", "ansible",
        "archive_control", "ground_truth_chunks", "parse_receipt", "ground_truth",
        "halt", "disk", "export", "cleanup", "publish",
    ]
    records = _host_phase_records(capsys.readouterr().out)
    assert records
    for started, completed in zip(records[::2], records[1::2], strict=True):
        assert started["phase"] == completed["phase"]
        assert (started["outcome"], completed["outcome"]) == ("start", "ok")
        assert started["elapsed_seconds"] == 0.0
        assert completed["elapsed_seconds"] >= 0.0
    boot = next(i for i, row in enumerate(records) if row["phase"] == "vagrant_boot")
    assert records[boot + 2]["phase"] == "ansible_provisioning"
    assert records[-1]["phase"] == "cleanup"


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_failed_host_phase_logs_cleanup_without_replacing_primary_error(host_phase_pipeline, capsys, cleanup_fails):
    _, instance, events = host_phase_pipeline
    failure = RuntimeError("primary private input failure")
    failure.add_note("existing note")
    cleanup_error = OSError("secondary private cleanup failure")

    def failed_ansible():
        events.append("ansible")
        raise failure

    def failed_cleanup():
        events.append("cleanup")
        raise cleanup_error

    instance.run_ansible_playbook = failed_ansible
    if cleanup_fails:
        instance.cleanup = failed_cleanup
    with pytest.raises(RuntimeError) as caught:
        instance.run()
    assert caught.value is failure
    assert failure.__cause__ is (cleanup_error if cleanup_fails else None)
    assert failure.__notes__ == (["existing note", f"cleanup also failed: {cleanup_error}"]
                                if cleanup_fails else ["existing note"])
    assert events == ["preflight", "population", "media", "environment", "boot", "ansible", "cleanup"] + (
        [] if cleanup_fails else ["record_cleanup"]
    )
    records = _host_phase_records(capsys.readouterr().out)
    assert records[-3]["phase"] == "ansible_provisioning"
    assert records[-3]["outcome"] == "error"
    assert records[-3]["error_type"] == "RuntimeError"
    assert records[-2]["phase"] == records[-1]["phase"] == "cleanup"
    assert records[-1]["outcome"] == ("error" if cleanup_fails else "ok")
    if cleanup_fails:
        assert records[-1]["error_type"] == "OSError"
    assert "private" not in json.dumps(records)


def test_cleanup_failure_leaves_no_consumable_generation_manifest(
    tmp_path: Path,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline('vmware_desktop', 'baseline', 'vmdk', False, False, experiment='full_scale', population_seed=2026091811, output_root=tmp_path, case='positive', windows_box='fmb/windows-11-arm64', vmware_bridge=None)
    source = tmp_path / "source.vmdk"
    source.write_bytes(b"source")
    instance.preflight_checks = lambda: None
    instance.provision_vm = lambda: persist_archive_control_fixture(instance)
    instance.halt_vm = lambda: None
    instance.discover_disk_path = lambda: source
    instance.prepare_native_media = lambda: None
    instance.extract_disk = lambda _: {"schema_version":"generation_manifest.v1", "artifacts":[]}

    def fake_run(command, **_kwargs):
        if command[:2] == ["qemu-img", "convert"]:
            Path(command[-1]).write_bytes(b"bounded evidence image")

    instance.run_command = fake_run

    def fail_cleanup() -> None:
        raise RuntimeError("cleanup failed")

    instance.cleanup = fail_cleanup
    try:
        with pytest.raises(RuntimeError, match="cleanup failed"):
            instance.run()
    finally:
        instance.cleanup_population_inputs()

    assert not (instance.output_dir / "manifest.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="the VMware Fusion generator manages POSIX process groups and runs only on macOS")
def test_vmware_generation_lets_vagrant_finish_before_vmrun_readiness_checks(tmp_path, monkeypatch):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.randomize_hw = False
    instance.vagrant_dir = tmp_path
    instance.active_process = None
    instance.vmware_guest_ip = None
    instance.resolve_command = lambda command: command
    instance.prepare_env = lambda values=None: dict(values or {})
    vmx = tmp_path / "worker.vmx"
    vmx.write_text('config.version = "8"\n')
    events = []
    mock_vagrant_boot_process(pipeline, monkeypatch, events=events)
    instance.discover_current_vmware_vmx_path = lambda: vmx
    instance.is_vmware_vm_running = lambda _path: events.append("vm-state") or True
    instance.wait_for_vmware_guest_ip = lambda _path, timeout: events.append("guest-ready") or "192.0.2.40"
    instance.terminate_process = lambda _process: pytest.fail("a successful boot must preserve the persistent guest")
    monkeypatch.setattr(pipeline.os, "killpg", lambda *args: pytest.fail("success must not signal the guest's process group"))
    assert instance.run_vmware_vagrant_boot({"VAGRANT_BOX": "local/worker"}) == ""
    assert instance.vmware_guest_ip == "192.0.2.40"
    assert events.index("vagrant-finished") < events.index("vm-state")


@pytest.mark.parametrize(
    "return_code, vmx_available, running, error_type",
    [(1, False, False, subprocess.CalledProcessError),
     (1, True, False, subprocess.CalledProcessError),
     (0, True, False, RuntimeError), (0, False, False, FileNotFoundError)],
)
def test_vmware_boot_failure_preserves_provider_error(tmp_path, monkeypatch, return_code, vmx_available, running, error_type):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.randomize_hw = False
    instance.vagrant_dir = tmp_path
    instance.active_process = None
    instance.resolve_command = lambda command: command
    instance.prepare_env = lambda values: values
    vmx = tmp_path / "worker.vmx"
    mock_vagrant_boot_process(pipeline, monkeypatch, chunks=[b"Vagrant forwarded-port range exhausted.\n"], return_code=return_code)

    def discover():
        if not vmx_available:
            raise FileNotFoundError("No current VMware VMX")
        return vmx

    instance.discover_current_vmware_vmx_path = discover
    instance.is_vmware_vm_running = lambda path: running
    with pytest.raises(error_type) as error:
        instance.run_vmware_vagrant_boot({})
    if isinstance(error.value, subprocess.CalledProcessError):
        assert error.value.returncode == return_code
        assert error.value.cmd == ["vagrant", "up", "--provider", "vmware_desktop", "--no-provision"]
        assert "forwarded-port range exhausted" in error.value.output
    assert instance.active_process is None


def test_vmware_nonzero_boot_requires_an_observed_running_guest(tmp_path, monkeypatch):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.randomize_hw = False
    instance.vagrant_dir = tmp_path
    instance.active_process = None
    instance.resolve_command = lambda command: command
    instance.prepare_env = lambda values: values
    vmx = tmp_path / "worker.vmx"
    mock_vagrant_boot_process(pipeline, monkeypatch, return_code=1)
    instance.discover_current_vmware_vmx_path = lambda: vmx
    instance.is_vmware_vm_running = lambda path: path == vmx
    instance.wait_for_vmware_guest_ip = lambda path, timeout: "192.0.2.40"
    assert instance.run_vmware_vagrant_boot({}) == ""
    assert instance.vmware_guest_ip == "192.0.2.40"


def test_vmware_generation_falls_back_after_vix_direct_ip_probe_fails(tmp_path, monkeypatch):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.randomize_hw = False
    instance.vagrant_dir = tmp_path
    instance.active_process = None
    instance.vmware_guest_ip = None
    instance.resolve_command = lambda command: command
    instance.prepare_env = lambda values=None: dict(values or {})
    vmx = tmp_path / "worker.vmx"
    vmx.write_text('config.version = "8"\n')
    mock_vagrant_boot_process(pipeline, monkeypatch)
    instance.discover_current_vmware_vmx_path = lambda: vmx
    instance.is_vmware_vm_running = lambda _path: True
    probe_timeouts = []

    def fail_direct_probe(_path, timeout=20):
        probe_timeouts.append(timeout)
        raise TimeoutError("VIX lookup failed")

    instance.wait_for_vmware_guest_ip = fail_direct_probe
    instance.terminate_process = lambda _process: None
    assert instance.run_vmware_vagrant_boot({"VAGRANT_BOX": "local/worker"}) == ""
    assert instance.vmware_guest_ip is None
    assert probe_timeouts == [20]


def test_vagrant_winrm_config_uses_the_run_scoped_state(
    tmp_path: Path,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.vmware_guest_ip = "192.0.2.40"
    vagrant_environment = {"VAGRANT_DOTFILE_PATH": str(tmp_path / ".vagrant")}
    observed: dict[str, object] = {}

    class Result:
        stdout = "Host default\n  HostName 127.0.0.1\n  User vagrant\n  Password vagrant\n  Port 55985\n"

    def run_command(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return Result()

    instance.vagrant_environment = lambda: vagrant_environment
    instance.run_command = run_command
    instance.configure_winrm_proxy = lambda connection: connection

    assert instance.get_ansible_connection() == {
        "host": "127.0.0.1",
        "port": "55985",
        "user": "vagrant",
        "password": "vagrant",
    }
    assert observed == {
        "command": ["vagrant", "winrm-config"],
        "kwargs": {"capture_output": True, "env": vagrant_environment},
    }


def test_direct_ansible_winrm_allows_long_forensic_operations(tmp_path: Path) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.scenario = "prefetch_wipe_01"
    instance.is_macos = True
    instance.population_inputs_path = tmp_path / "generation-inputs.json"
    instance.get_ansible_connection = lambda: {
        "host": "192.0.2.40",
        "port": "5985",
        "user": "vagrant",
        "password": "vagrant",
    }
    observed: dict[str, object] = {}

    def run_streaming(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return "ok"

    instance.run_streaming_command = run_streaming

    assert instance.run_ansible_playbook() == "ok"

    command = observed["command"]
    extra_vars = json.loads(command[command.index("-e") + 1])
    assert extra_vars["ansible_winrm_operation_timeout_sec"] == 120
    assert extra_vars["ansible_winrm_read_timeout_sec"] == 130
    assert "ansible_winrm_message_encryption" not in extra_vars


def test_loopback_ansible_winrm_avoids_connection_bound_message_wrapping(
    tmp_path: Path,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.scenario = "prefetch_wipe_01"
    instance.is_macos = True
    instance.population_inputs_path = tmp_path / "generation-inputs.json"
    instance.get_ansible_connection = lambda: {
        "host": "127.0.0.1",
        "port": "5985",
        "user": "vagrant",
        "password": "vagrant",
    }
    observed: dict[str, object] = {}

    def run_streaming(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return "ok"

    instance.run_streaming_command = run_streaming

    assert instance.run_ansible_playbook() == "ok"

    command = observed["command"]
    extra_vars = json.loads(command[command.index("-e") + 1])
    assert extra_vars["ansible_winrm_message_encryption"] == "never"


def test_generation_rejects_a_vmware_box_with_a_backing_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = load_generation_pipeline_module()
    box_root = (
        tmp_path
        / "boxes"
        / "fmb-VAGRANTSLASH-windows-11-arm64"
        / "0"
        / "arm64"
        / "vmware_desktop"
    )
    box_root.mkdir(parents=True)
    disk = box_root / "Virtual Disk.vmdk"
    disk.write_text(
        '# Disk DescriptorFile\nparentFileNameHint="Virtual Disk-000001.vmdk"\n',
        encoding="utf-8",
    )
    vmx = box_root / "box.vmx"
    vmx.write_text(
        'nvme0:0.fileName = "Virtual Disk.vmdk"\n'
        'sata0:1.deviceType = "cdrom-image"\n'
        'sata0:1.fileName = "/missing/installer.iso"\n'
        'sata0:1.present = "TRUE"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("VAGRANT_HOME", str(tmp_path))
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.windows_box = "local/windows-worker"
    instance.is_vmware_vm_running = lambda _path: False

    with pytest.raises(RuntimeError, match="backing parent"):
        instance.preflight_vmware_source()

    disk.write_text(
        '# Disk DescriptorFile\nparentCID=ffffffff\ncreateType="twoGbMaxExtentSparse"\n'
    )
    report = instance.preflight_vmware_source()
    assert report["vmx_path"] == str(vmx.resolve())
    assert report["snapshot_count"] == 0
    assert report["removable_media_slots"] == ["sata0:1"]
    assert instance.vmware_source_media_slots == ("sata0:1",)

    disk.write_text(
        '# Disk DescriptorFile\nparentCID=1234abcd\ncreateType="twoGbMaxExtentSparse"\n'
    )
    with pytest.raises(RuntimeError, match="non-flat parent CID"):
        instance.preflight_vmware_source()


def test_a_recipe_run_refuses_a_base_that_occupies_a_pilot_usb_slot_before_its_population_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = load_generation_pipeline_module()
    box_root = tmp_path / "boxes" / "fmb-VAGRANTSLASH-windows-11-arm64" / "0" / "arm64" / "vmware_desktop"
    box_root.mkdir(parents=True)
    (box_root / "Virtual Disk.vmdk").write_text(
        '# Disk DescriptorFile\nparentCID=ffffffff\ncreateType="twoGbMaxExtentSparse"\n', encoding="utf-8")
    vmx = box_root / "box.vmx"
    monkeypatch.setenv("VAGRANT_HOME", str(tmp_path))
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.windows_box = "local/windows-worker"
    instance.is_vmware_vm_running = lambda _path: False
    instance.vagrant_box_vmx_path = lambda: vmx.resolve()
    instance.population_guest_plan = None
    media = [{"unit": 8, "port": 5}, {"unit": 9, "port": 3}, {"unit": 10, "port": 2}]
    instance.recipe_bundle = {"private": {"guest_plan": {
        "native_pilot_profile": "pilot_min.v1",
        "scenario_inputs": {"usbstor_setupapi_discrepancy_01": {"media": media}},
    }}}

    vmx.write_text('nvme0:0.fileName = "Virtual Disk.vmdk"\n', encoding="utf-8")
    assert instance.preflight_vmware_source()["vmx_path"] == str(vmx.resolve())
    vmx.write_text('nvme0:0.fileName = "Virtual Disk.vmdk"\nusb_xhci:9.present = "FALSE"\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="occupies a pilot USB slot"):
        instance.preflight_vmware_source()


def test_generation_storage_preflight_uses_the_selected_output_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = load_generation_pipeline_module()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    vmx = source_dir / "box.vmx"
    vmx.write_text('nvme0:0.fileName = "disk.vmdk"\n')
    (source_dir / "disk.vmdk").write_bytes(b"disk")
    output_dir = tmp_path / "outputs" / "timestomp" / "run"
    output_dir.mkdir(parents=True)
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.output_dir = output_dir
    observed_paths: list[Path] = []

    def low_space(path):
        observed_paths.append(Path(path))
        return __import__("types").SimpleNamespace(total=10, used=9, free=1)

    monkeypatch.setattr(pipeline.shutil, "disk_usage", low_space)

    with pytest.raises(RuntimeError, match="insufficient free space"):
        instance.preflight_generation_storage(vmx)

    assert observed_paths == [output_dir]
    report = json.loads((output_dir / "generation_storage_preflight.json").read_text())
    assert report["status"] == "failed"


def test_vmware_disk_from_vmx_rejects_ambiguous_fallback(tmp_path: Path) -> None:
    pipeline = load_generation_pipeline_module()
    (tmp_path / "base.vmdk").write_text("# descriptor\n")
    (tmp_path / "snapshot.vmdk").write_text("# descriptor\n")
    vmx = tmp_path / "vm.vmx"
    vmx.write_text('config.version = "8"\n')

    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)

    try:
        instance.vmware_disk_from_vmx(vmx)
    except Exception as exc:
        assert "fallback is ambiguous" in str(exc)
    else:
        raise AssertionError("ambiguous VMware disk fallback should fail")


def test_cleanup_still_destroys_vm_when_private_input_unlink_fails(
    tmp_path: Path,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    private_path = tmp_path / "private-input-directory"
    private_path.mkdir()
    commands: list[list[str]] = []
    instance.population_inputs_path = private_path
    instance.keep_vm = False
    instance.provider = "vmware_desktop"
    instance.is_macos = False
    instance.active_process = None
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    instance.cleanup_winrm_proxy = lambda: None
    instance.terminate_process = lambda _process: None
    instance.vagrant_environment = lambda: {}
    instance.run_command = lambda command, **_kwargs: commands.append(command)

    with pytest.raises(OSError):
        instance.cleanup()

    assert commands == [["vagrant", "destroy", "-f"]]
    assert instance.population_inputs_path == private_path


@pytest.fixture
def recipe_cleanup_pipeline(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "cleanup_recipe_fixture", Path(__file__).with_name("test_generation_recipe.py")
    )
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    directory, lock, config, *_ = fixture.locked_recipe.__wrapped__(tmp_path)
    pipeline = load_generation_pipeline_module()
    monkeypatch.setattr(pipeline.sys, "executable", lock["tools"]["python"]["path"])
    instance = pipeline.GenerationPipeline('vmware_desktop', 'baseline', 'vmdk', False, False, recipe=directory, output_root=tmp_path / 'out', experiment='full_scale', case='positive', population_seed=2026091811, windows_box='fmb/windows-11-arm64', vmware_bridge=None)
    instance.is_macos = True
    instance.run_command = lambda *args, **kwargs: pytest.fail("unexpected provider dispatch")
    instance.run_vmrun = lambda *args, **kwargs: pytest.fail("unexpected VMware dispatch")
    instance.prepare_native_media = lambda: None
    try:
        yield pipeline, instance
    finally:
        instance.cleanup_population_inputs()


def _assert_frozen_cleanup_inputs(instance, environment):
    assert environment["FMB_RECIPE_MODE"] == "1"
    assert environment["FMB_BOX_VERSION"] == instance.recipe_bundle["lock"]["base"]["version"]
    path = Path(environment["FMB_GENERATION_INPUTS_PATH"])
    assert path.is_file()
    assert os.name == "nt" or path.stat().st_mode & 0o777 == 0o600
    payload = json.loads(path.read_text())
    assert payload["fmb_hardware"] == instance.recipe_bundle["private"]["hardware"]
    assert payload["generation_inputs"] == instance.recipe_bundle["private"]["guest_plan"]
    return path


def test_recipe_inputs_survive_until_vagrant_destroy_completes(recipe_cleanup_pipeline):
    _, instance = recipe_cleanup_pipeline
    instance.prepare_population()
    private_path = instance.population_inputs_path
    instance.provider_launch_attempted = True
    state = instance.vmware_provider_state()
    state.mkdir(parents=True)
    commands = []

    def destroy(command, **kwargs):
        commands.append(command)
        assert _assert_frozen_cleanup_inputs(instance, kwargs["env"]) == private_path
        shutil.rmtree(state)

    instance.run_command = destroy
    assert instance.cleanup()["status"] == "destroyed"
    assert commands == [["vagrant", "destroy", "-f"]]
    assert not private_path.exists()
    assert instance.population_inputs_path is None
    assert (Path(instance.recipe_bundle["directory"]) / "private-generation.json").is_file()


@pytest.mark.parametrize("keep_vm", [False, True])
def test_recipe_preflight_failure_without_state_skips_destroy(recipe_cleanup_pipeline, keep_vm):
    _, instance = recipe_cleanup_pipeline
    instance.keep_vm = keep_vm
    failure = RuntimeError("generation storage preflight failed")
    proxy_cleanup = []
    instance.cleanup_winrm_proxy = lambda: proxy_cleanup.append(True)
    instance.preflight_checks = lambda: (_ for _ in ()).throw(failure)
    with pytest.raises(RuntimeError, match="storage preflight failed") as caught:
        instance.run()
    assert caught.value is failure
    assert caught.value.__cause__ is None
    assert not getattr(caught.value, "__notes__", [])
    assert instance.provider_launch_attempted is False
    assert not instance.vagrant_state_dir.exists()
    assert instance.population_inputs_path is None
    assert not (instance.output_dir / "manifest.json").exists()
    assert proxy_cleanup == []
    assert instance.cleanup() is None


def test_recipe_spawn_failure_still_destroys_with_frozen_inputs(recipe_cleanup_pipeline, monkeypatch):
    pipeline, instance = recipe_cleanup_pipeline
    instance.preflight_checks = lambda: None
    commands = []
    private_paths = []
    failure = OSError("provider spawn failed")

    def failed_spawn(command, **kwargs):
        assert instance.provider_launch_attempted is True
        commands.append("up")
        private_paths.append(_assert_frozen_cleanup_inputs(instance, kwargs["env"]))
        raise failure

    def destroy(command, **kwargs):
        assert command == ["vagrant", "destroy", "-f"]
        commands.append("destroy")
        assert _assert_frozen_cleanup_inputs(instance, kwargs["env"]) == private_paths[0]

    monkeypatch.setattr(pipeline.subprocess, "Popen", failed_spawn)
    instance.run_command = destroy
    with pytest.raises(OSError, match="provider spawn failed") as caught:
        instance.run()
    assert caught.value is failure
    assert caught.value.__cause__ is None
    assert commands == ["up", "destroy"]
    assert not private_paths[0].exists()
    assert not (instance.output_dir / "manifest.json").exists()


def test_partial_provider_state_requires_destroy_even_without_launch(recipe_cleanup_pipeline):
    _, instance = recipe_cleanup_pipeline
    state = instance.vmware_provider_state()
    state.mkdir(parents=True)
    commands = []
    private_paths = []

    def destroy(command, **kwargs):
        commands.append(command)
        private_paths.append(_assert_frozen_cleanup_inputs(instance, kwargs["env"]))
        shutil.rmtree(state)

    instance.run_command = destroy
    assert instance.provider_launch_attempted is False
    assert instance.population_inputs_path is None
    assert instance.cleanup()["status"] == "destroyed"
    assert commands == [["vagrant", "destroy", "-f"]]
    assert not private_paths[0].exists()


def test_failed_destruction_retains_private_inputs_and_primary_error(recipe_cleanup_pipeline):
    _, instance = recipe_cleanup_pipeline
    instance.prepare_population()
    instance.provider_launch_attempted = True
    private_path = instance.population_inputs_path
    failure = RuntimeError("provider destruction failed")
    instance.destroy_vm = lambda: (_ for _ in ()).throw(failure)
    instance.cleanup_winrm_proxy = lambda: (_ for _ in ()).throw(OSError("proxy cleanup failed"))
    with pytest.raises(RuntimeError, match="provider destruction failed") as caught:
        instance.cleanup()
    assert caught.value is failure
    assert private_path.is_file()
    assert instance.population_inputs_path == private_path
    assert any(str(private_path) in note and "host-only" in note for note in failure.__notes__)
    assert not any("proxy cleanup failed" in note for note in failure.__notes__)
    instance.cleanup_winrm_proxy = lambda: None
    instance.destroy_vm = lambda: _assert_frozen_cleanup_inputs(instance, instance.vagrant_environment()) == private_path
    assert instance.cleanup()["status"] == "destroyed"
    assert not private_path.exists()


def test_recipe_unlink_failure_occurs_after_required_destruction(recipe_cleanup_pipeline, monkeypatch):
    _, instance = recipe_cleanup_pipeline
    instance.prepare_population()
    instance.provider_launch_attempted = True
    private_path = instance.population_inputs_path
    commands = []

    def destroy(command, **kwargs):
        commands.append(command)
        _assert_frozen_cleanup_inputs(instance, kwargs["env"])

    unlink = Path.unlink

    def failed_unlink(path, *args, **kwargs):
        if path == private_path:
            raise PermissionError("private input unlink failed")
        return unlink(path, *args, **kwargs)

    instance.run_command = destroy
    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "unlink", failed_unlink)
        with pytest.raises(PermissionError, match="private input unlink failed"):
            instance.cleanup()
    assert commands == [["vagrant", "destroy", "-f"]]
    assert private_path.is_file()
    assert instance.population_inputs_path == private_path


def test_generation_cannot_publish_after_no_launch_cleanup(recipe_cleanup_pipeline):
    _, instance = recipe_cleanup_pipeline
    instance.preflight_checks = lambda: None
    instance.provision_vm = lambda: None
    instance.halt_vm = lambda: None
    instance.discover_disk_path = lambda: None
    instance.extract_disk = lambda *args: {}
    instance.publish_manifest = lambda *args: pytest.fail("must not publish")
    with pytest.raises(RuntimeError, match="never launched a VM"):
        instance.run()
    assert instance.population_inputs_path is None


def test_failed_vmdk_conversion_never_publishes_a_final_image(
    tmp_path: Path,
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline('vmware_desktop', 'baseline', 'vmdk', False, False, experiment='full_scale', population_seed=2026091811, output_root=tmp_path, case='positive', windows_box='fmb/windows-11-arm64', vmware_bridge=None)
    instance.prepare_population()
    instance.ground_truth = []
    source = tmp_path / "source.vmdk"
    source.write_bytes(b"source")

    def fail_convert(command, **_kwargs):
        destination = Path(command[-1])
        destination.write_bytes(b"partial")
        raise __import__("subprocess").CalledProcessError(1, command)

    instance.run_command = fail_convert
    try:
        with pytest.raises(__import__("subprocess").CalledProcessError):
            instance.extract_disk(source)
    finally:
        instance.cleanup_population_inputs()

    assert not (instance.output_dir / "timestomp.vmdk").exists()
    assert not list(instance.output_dir.glob("*.partial"))


def _vmware_probe_instance(pipeline, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.is_macos = True
    instance.output_dir = tmp_path
    monkeypatch.delenv("VMRUN_TARGET", raising=False)
    return instance


def test_vmware_bridged_discovery_is_skipped_when_tools_are_only_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = _vmware_probe_instance(pipeline, tmp_path, monkeypatch)
    commands: list[list[str]] = []

    class ToolsInstalled:
        stdout = "installed\n"

    def fake_vmrun(command, **_kwargs):
        commands.append(command)
        return ToolsInstalled()

    instance.run_command = fake_vmrun
    monkeypatch.setattr(
        pipeline.time, "sleep", lambda _seconds: pytest.fail("the bridged discovery must not wait")
    )
    vmx = tmp_path / "worker.vmx"

    assert instance.wait_for_vmware_guest_ip(vmx, timeout=20) is None

    assert commands == [["vmrun", "-T", "fusion", "checkToolsState", str(vmx)]]


def _running_tools_vmrun(commands: list[list[str]], tools_states: list[str]):
    def fake_vmrun(command, **_kwargs):
        commands.append(command)
        if "checkToolsState" in command:
            return __import__("types").SimpleNamespace(stdout=tools_states.pop(0) + "\n")
        if "copyFileFromGuestToHost" in command:
            Path(command[-1]).write_text(
                "Ethernet adapter Ethernet0:\n"
                "   IPv4 Address. . . . . . . . . . . : 192.168.5.20(Preferred)\n",
                encoding="utf-8",
            )
        return __import__("types").SimpleNamespace(stdout="")

    return fake_vmrun


def test_vmware_bridged_discovery_is_unchanged_when_tools_are_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = _vmware_probe_instance(pipeline, tmp_path, monkeypatch)
    commands: list[list[str]] = []
    validated: list[str] = []
    instance.run_command = _running_tools_vmrun(commands, ["running"])
    instance.wait_for_tcp = lambda host, port, label, timeout=30: None
    instance.validate_vmware_ansible_winrm = lambda address: validated.append(address)
    monkeypatch.setattr(pipeline.time, "sleep", lambda _seconds: None)

    assert instance.wait_for_vmware_guest_ip(tmp_path / "worker.vmx", timeout=20) == "192.168.5.20"

    assert sum("checkToolsState" in command for command in commands) == 1
    assert any("runProgramInGuest" in command for command in commands)
    assert any("copyFileFromGuestToHost" in command for command in commands)
    assert validated == ["192.168.5.20"]


def test_vmware_tools_wait_is_kept_for_an_unknown_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline = load_generation_pipeline_module()
    instance = _vmware_probe_instance(pipeline, tmp_path, monkeypatch)
    commands: list[list[str]] = []
    sleeps: list[int] = []
    instance.run_command = _running_tools_vmrun(commands, ["unknown", "unknown", "running"])
    instance.wait_for_tcp = lambda host, port, label, timeout=30: None
    instance.validate_vmware_ansible_winrm = lambda address: None
    monkeypatch.setattr(pipeline.time, "sleep", lambda seconds: sleeps.append(seconds))

    assert instance.wait_for_vmware_guest_ip(tmp_path / "worker.vmx", timeout=20) == "192.168.5.20"

    assert sum("checkToolsState" in command for command in commands) == 3
    assert sleeps == [5]


def test_vmware_boot_reports_the_unavailable_bridged_path_in_one_line(tmp_path, monkeypatch, capsys):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.randomize_hw = False
    instance.vagrant_dir = tmp_path
    instance.active_process = None
    instance.vmware_guest_ip = None
    instance.resolve_command = lambda command: command
    instance.prepare_env = lambda values=None: dict(values or {})
    vmx = tmp_path / "worker.vmx"
    vmx.write_text('config.version = "8"\n')
    mock_vagrant_boot_process(pipeline, monkeypatch)
    instance.discover_current_vmware_vmx_path = lambda: vmx
    instance.is_vmware_vm_running = lambda _path: True
    instance.wait_for_vmware_guest_ip = lambda _path, timeout=360: None
    instance.terminate_process = lambda _process: None
    assert instance.run_vmware_vagrant_boot({"VAGRANT_BOX": "local/worker"}) == ""
    output = capsys.readouterr().out
    assert instance.vmware_guest_ip is None
    assert output.count("direct WinRM path is unavailable") == 1


def test_vmware_boot_drains_output_bursts_without_sleep_or_text_buffering(tmp_path, monkeypatch):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.randomize_hw = False
    instance.vagrant_dir = tmp_path
    instance.active_process = None
    instance.resolve_command = lambda command: command
    instance.prepare_env = lambda values: values
    vmx = tmp_path / "worker.vmx"
    process = mock_vagrant_boot_process(pipeline, monkeypatch, chunks=[b"Bringing machine up.\r\nCloning VM.\n", b"Booted.\nReady", b" now."])
    instance.discover_current_vmware_vmx_path = lambda: vmx
    instance.is_vmware_vm_running = lambda path: True
    instance.wait_for_vmware_guest_ip = lambda path, timeout: None
    instance.terminate_process = lambda _process: pytest.fail("successful boot must preserve the guest")
    monkeypatch.setattr(pipeline.time, "sleep", lambda seconds: pytest.fail("output bursts must not be paced by sleep"))
    assert instance.run_vmware_vagrant_boot({}) == "Bringing machine up.\nCloning VM.\nBooted.\nReady now."
    assert process.stdout.closed and instance.active_process is None


@pytest.mark.parametrize("return_code", [None, 0])
@pytest.mark.skipif(os.name == "nt", reason="the VMware Fusion generator manages POSIX process groups and runs only on macOS")
def test_vmware_boot_partial_line_and_exited_leader_pipe_obey_deadline(tmp_path, monkeypatch, capsys, return_code):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.provider = "vmware_desktop"
    instance.is_macos = True
    instance.randomize_hw = False
    instance.vagrant_dir = tmp_path
    instance.active_process = None
    instance.resolve_command = lambda command: command
    instance.prepare_env = lambda values: values
    process = mock_vagrant_boot_process(pipeline, monkeypatch, chunks=[b"partial"], return_code=return_code)
    times = iter((0.0, 0.0, 3600.1))
    monkeypatch.setattr(pipeline.time, "monotonic", lambda: next(times))
    signals = []
    monkeypatch.setattr(pipeline.os, "killpg", lambda group, sent: signals.append((group, sent)))
    with pytest.raises(TimeoutError, match="3600 seconds"):
        instance.run_vmware_vagrant_boot({})
    assert signals == [(process.pid, pipeline.signal.SIGTERM), (process.pid, pipeline.signal.SIGKILL)]
    assert "partial" in capsys.readouterr().out
    assert process.stdout.closed and instance.active_process is None


def test_vmware_running_check_propagates_unknown_provider_state(tmp_path):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    def failed_list(_args, **_kwargs):
        raise subprocess.CalledProcessError(1, ["vmrun", "list"])
    instance.run_vmrun = failed_list
    with pytest.raises(subprocess.CalledProcessError):
        instance.is_vmware_vm_running(tmp_path / "worker.vmx")


@pytest.mark.parametrize("failure", ["list", "stop", "confirmation", "still-running"])
def test_vmware_direct_cleanup_retains_state_until_shutdown_is_confirmed(tmp_path, failure):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.is_macos = True
    instance.vmrun_cmd = "/Applications/VMware Fusion.app/Contents/Library/vmrun"
    instance.run_command = lambda command, **kwargs: subprocess.CompletedProcess(command, 0, stdout="")
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    state = instance.vmware_provider_state()
    clone = state / "owned-clone"
    clone.mkdir(parents=True)
    vmx = clone / "worker.vmx"
    vmx.write_text("owned VM configuration")
    calls = []

    def run_vmrun(args, **kwargs):
        calls.append(args)
        if args == ["list"]:
            list_count = calls.count(["list"])
            if failure == "list" or (failure == "confirmation" and list_count == 2):
                raise subprocess.CalledProcessError(1, ["vmrun", "list"])
            return subprocess.CompletedProcess(args, 0, stdout=f"Total running VMs: 1\n{vmx}\n")
        assert args == ["stop", str(vmx), "hard"]
        if failure == "stop":
            raise subprocess.CalledProcessError(1, ["vmrun", *args])
        return subprocess.CompletedProcess(args, 0, stdout="")

    instance.run_vmrun = run_vmrun
    assert instance.cleanup_vmware_direct() is False
    assert vmx.read_text() == "owned VM configuration"
    assert len(calls) == {"list": 1, "stop": 2, "confirmation": 3, "still-running": 3}[failure]


@pytest.mark.parametrize("initially_running", [False, True])
def test_vmware_direct_cleanup_removes_only_confirmed_stopped_clones(tmp_path, initially_running):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.is_macos = True
    instance.vmrun_cmd = "/Applications/VMware Fusion.app/Contents/Library/vmrun"
    instance.run_command = lambda command, **kwargs: subprocess.CompletedProcess(command, 0, stdout="")
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    state = instance.vmware_provider_state()
    clone = state / "owned-clone"
    clone.mkdir(parents=True)
    vmx = clone / "worker.vmx"
    vmx.write_text("owned VM configuration")
    calls = []

    def run_vmrun(args, **kwargs):
        calls.append(args)
        if args == ["list"]:
            running = initially_running and calls.count(["list"]) == 1
            text = f"Total running VMs: 1\n{vmx}\n" if running else "Total running VMs: 0\n"
            return subprocess.CompletedProcess(args, 0, stdout=text)
        assert args == ["stop", str(vmx), "hard"]
        return subprocess.CompletedProcess(args, 0, stdout="")

    instance.run_vmrun = run_vmrun
    assert instance.cleanup_vmware_direct() is True
    assert not state.exists()
    assert calls == ([['list'], ['stop', str(vmx), 'hard'], ['list']] if initially_running else [['list']])


@pytest.mark.parametrize("command, matches", [
    ("/Applications/VMware Fusion.app/Contents/Library/vmware-vmx -s vmx.noUIBuildNumberCheck=TRUE {vmx}", True),
    ("/Applications/VMware Fusion.app/Contents/Library/vmware-vmx -s vmx.noUIBuildNumberCheck=TRUE {vmx}.different", False),
    ("/Applications/VMware Fusion.app/Contents/Library/vmware-vmx -s vmx.noUIBuildNumberCheck=TRUE {vmx}/child.vmx", False),
    ("/Applications/VMware Fusion.app/Contents/Library/vmware-vmx -s vmx.noUIBuildNumberCheck=TRUE {other}", False),
    ("/Applications/VMware Fusion.app/Contents/Library/vmware-vmx-helper -s vmx.noUIBuildNumberCheck=TRUE {vmx}", False),
    ("/bin/cat {vmx}", False),
])
@pytest.mark.parametrize("real_uid,effective_uid", [(501, 0), (0, 0), (502, 502)])
@pytest.mark.skipif(os.name == "nt", reason="the VMware Fusion generator manages POSIX process groups and runs only on macOS")
def test_vmware_running_check_detects_exact_host_vmx_under_any_owner(tmp_path, command, matches, real_uid, effective_uid):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.vmrun_cmd = "/Applications/VMware Fusion.app/Contents/Library/vmrun"
    vmx = tmp_path / "External Disk" / "owned clone" / "box.vmx"
    other = tmp_path / "External Disk" / "different clone" / "box.vmx"
    instance.run_vmrun = lambda args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="Total running VMs: 0\n")
    calls = []

    def ps(command_args, **kwargs):
        calls.append((command_args, kwargs))
        text = f"99033 {real_uid} {effective_uid} " + command.format(vmx=vmx, other=other) + "\n"
        return subprocess.CompletedProcess(command_args, 0, stdout=text)

    instance.run_command = ps
    assert instance.is_vmware_vm_running(vmx) is matches
    assert calls == [(["/bin/ps", "-ww", "-axo", "pid=,ruid=,uid=,args="], {"capture_output": True, "timeout_seconds": 15})]


def test_vmware_running_check_propagates_host_query_failure(tmp_path):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.vmrun_cmd = "/Applications/VMware Fusion.app/Contents/Library/vmrun"
    instance.run_vmrun = lambda args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="Total running VMs: 0\n")
    def failed_ps(args, **kwargs):
        raise subprocess.CalledProcessError(124, args)
    instance.run_command = failed_ps
    with pytest.raises(subprocess.CalledProcessError):
        instance.is_vmware_vm_running(tmp_path / "worker.vmx")


@pytest.mark.skipif(os.name == "nt", reason="the VMware Fusion generator manages POSIX process groups and runs only on macOS")
def test_vmware_direct_cleanup_retains_an_unregistered_live_host_process(tmp_path):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.is_macos = True
    instance.provider = "vmware_desktop"
    instance.vmrun_cmd = "/Applications/VMware Fusion.app/Contents/Library/vmrun"
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    state = instance.vmware_provider_state()
    clone = state / "owned clone"
    clone.mkdir(parents=True)
    vmx = clone / "box.vmx"
    vmx.write_text("source retained")
    instance.vmware_run_vmx_path = vmx
    list_calls = []

    def run_vmrun(args, **kwargs):
        list_calls.append(args)
        if args == ["list"]:
            return subprocess.CompletedProcess(args, 0, stdout="Total running VMs: 0\n")
        assert args == ["stop", str(vmx), "hard"]
        return subprocess.CompletedProcess(args, 0, stdout="")

    instance.run_vmrun = run_vmrun
    text = f"62663 501 0 /Applications/VMware Fusion.app/Contents/Library/vmware-vmx -@ duplex=3;msgs=ui {vmx}\n"
    instance.run_command = lambda args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=text)
    assert instance.cleanup_vmware_direct() is False
    assert vmx.read_text() == "source retained"
    assert list_calls == [["list"], ["stop", str(vmx), "hard"], ["list"]]
    shutil.rmtree(state)
    assert instance.provider_state_remaining() is True


def test_vmware_direct_cleanup_retains_state_when_host_query_fails(tmp_path):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.is_macos = True
    instance.vmrun_cmd = "/Applications/VMware Fusion.app/Contents/Library/vmrun"
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    state = instance.vmware_provider_state()
    clone = state / "owned clone"
    clone.mkdir(parents=True)
    vmx = clone / "box.vmx"
    vmx.write_text("source retained")
    instance.run_vmrun = lambda args, **kwargs: subprocess.CompletedProcess(args, 0, stdout="Total running VMs: 0\n")
    def failed_ps(args, **kwargs):
        raise subprocess.CalledProcessError(124, args)
    instance.run_command = failed_ps
    assert instance.cleanup_vmware_direct() is False
    assert vmx.read_text() == "source retained"


@pytest.mark.parametrize("fallback", ["removed", "retained", "failed"])
def test_missing_recipe_inputs_attempt_direct_cleanup_and_preserve_error(recipe_cleanup_pipeline, fallback):
    _, instance = recipe_cleanup_pipeline
    instance.provider_launch_attempted = True
    state = instance.vmware_provider_state()
    state.mkdir(parents=True)
    failure = FileNotFoundError("recovery input storage unavailable")
    events = []

    def failed_inputs(_plan):
        events.append("reconstruct-inputs")
        raise failure

    def direct_cleanup():
        events.append("direct-cleanup")
        if fallback == "failed":
            raise OSError("direct cleanup storage unavailable")
        if fallback == "removed":
            shutil.rmtree(state)
        return True

    instance.write_population_inputs = failed_inputs
    instance.terminate_process = lambda process: events.append("terminate-owned-process")
    instance.cleanup_vmware_direct = direct_cleanup
    with pytest.raises(FileNotFoundError, match="recovery input storage unavailable") as caught:
        instance.cleanup()
    assert caught.value is failure
    assert events == ["reconstruct-inputs", "terminate-owned-process", "direct-cleanup"]
    assert state.exists() is (fallback != "removed")
    assert instance.population_inputs_path is None
    assert not (instance.output_dir / "manifest.json").exists()
    expected_note = "confirmed destruction" if fallback == "removed" else "could not be confirmed"
    assert any(expected_note in note for note in failure.__notes__)


@pytest.mark.parametrize("remains_running", [False, True])
@pytest.mark.skipif(os.name == "nt", reason="the VMware Fusion generator manages POSIX process groups and runs only on macOS")
def test_direct_cleanup_checks_tracked_vm_after_its_metadata_disappears(tmp_path, remains_running):
    pipeline = load_generation_pipeline_module()
    instance = pipeline.GenerationPipeline.__new__(pipeline.GenerationPipeline)
    instance.is_macos = True
    instance.provider = "vmware_desktop"
    instance.vmrun_cmd = "/Applications/VMware Fusion.app/Contents/Library/vmrun"
    instance.vagrant_state_dir = tmp_path / ".vagrant"
    state = instance.vmware_provider_state()
    clone = state / "owned-clone"
    clone.mkdir(parents=True)
    vmx = clone / "missing.vmx"
    instance.vmware_run_vmx_path = vmx
    disk = clone / "retained.vmdk"
    disk.write_bytes(b"owned disk")
    calls = []

    def vmrun(args, **kwargs):
        calls.append(args)
        assert args == ["list"] or args == ["stop", str(vmx), "hard"]
        return subprocess.CompletedProcess(args, 0, stdout="Total running VMs: 0\n")

    def host_query(args, **kwargs):
        assert args == ["/bin/ps", "-ww", "-axo", "pid=,ruid=,uid=,args="]
        live = calls.count(["list"]) == 1 or remains_running
        text = f"99033 501 0 /Applications/VMware Fusion.app/Contents/Library/vmware-vmx -@ duplex=3 {vmx}\n" if live else ""
        return subprocess.CompletedProcess(args, 0, stdout=text)

    instance.run_vmrun = vmrun
    instance.run_command = host_query
    assert instance.cleanup_vmware_direct() is (not remains_running)
    assert calls == [["list"], ["stop", str(vmx), "hard"], ["list"]]
    assert state.exists() is remains_running
    if remains_running:
        assert disk.read_bytes() == b"owned disk"
