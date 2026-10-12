from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_generation_logfile_retention import _fixture_volume
from test_iteration2_generation import load
from test_logfile_adapter import driver_document, stomp_record
from test_logfile_scanner import FILETIME_2010, FILETIME_2026_B, file_record_bytes

from fmb.core.ntfs_time import filetime_to_utc_iso
from fmb.index.scanners import logfile_runtime
from fmb.replication import run


def retention(tmp_path, monkeypatch, records, *, entry=10, coverage=True):
    module = load("logfile_retention")
    log = tmp_path / "$LogFile"
    log.write_bytes(b"driver fixture")
    mft = bytearray(11 * 1024)
    mft[10 * 1024:] = file_record_bytes(entry=10, sequence=3, lsn=500)
    document = driver_document(records, logfile=log)
    document["parse"]["page_coverage_complete"] = coverage
    _fixture_volume(monkeypatch, bytes(mft), log.read_bytes(), entry=entry)
    monkeypatch.setattr(logfile_runtime, "logfile_runtime_availability", lambda: {"available": True})
    monkeypatch.setattr(logfile_runtime, "run_logfile_driver", lambda *a, **kw: deepcopy(document))
    target = {"path": r"C:\Records\Files\public.txt", "assigned_timestamp": filetime_to_utc_iso(FILETIME_2010),
              "original_creation_utc": filetime_to_utc_iso(FILETIME_2026_B)}
    return lambda: module.check_logfile_retention(tmp_path / "x.vmdk", targets=[target], output_dir=tmp_path,
                                                  require=True)


def written(folder):
    """The receipt as written, which must still match its schema."""
    from test_iteration2_generation import definition_validator

    receipt = json.loads((folder / "logfile-retention-receipt.json").read_text(encoding="utf-8"))
    definition_validator("logfile_retention_receipt").validate(receipt)
    return receipt


def test_only_a_logfile_that_lost_the_change_is_called_a_wrap(tmp_path, monkeypatch):
    check = retention(tmp_path, monkeypatch, [stomp_record(lsn=500, entry=11)])
    with pytest.raises(ValueError) as error:
        check()
    assert run.LOGFILE_WRAP.search(str(error.value))
    assert written(tmp_path)["reason"] == "no_candidate_update"


@pytest.mark.parametrize("case, reason", [("coverage", "parse_coverage_unverified"),
                                          ("missing", "target_not_in_image"),
                                          ("uncommitted", "transition_not_committed")])
def test_other_logfile_failures_name_their_reason_and_are_not_a_wrap(tmp_path, monkeypatch, case, reason):
    check = retention(tmp_path, monkeypatch,
                      [stomp_record(lsn=500, entry=10, forgotten=None if case == "uncommitted" else 777)],
                      entry=None if case == "missing" else 10, coverage=case != "coverage")
    with pytest.raises(ValueError, match=rf"not retained \({reason}\)") as error:
        check()
    assert not run.LOGFILE_WRAP.search(str(error.value))
    assert written(tmp_path)["reason"] == reason


def test_a_retained_receipt_is_unchanged(tmp_path, monkeypatch):
    receipt = retention(tmp_path, monkeypatch, [stomp_record(lsn=500, entry=10)])()
    assert receipt["status"] == "retained" and "reason" not in written(tmp_path)


class Guest:
    """A QEMU process that exits on the given wait() call."""

    def __init__(self, exits_on_wait: int, code: int = 0):
        self.returncode, self.waits, self.exits_on_wait, self.code = None, 0, exits_on_wait, code

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waits += 1
        if self.waits < self.exits_on_wait:
            raise subprocess.TimeoutExpired("qemu", timeout)
        self.returncode = self.code
        return self.code


def qemu_guest(process, shutdown_code: int):
    from fmb.generation.backends import QemuBackend

    backend = QemuBackend.__new__(QemuBackend)
    backend.process, sent = process, []
    backend._guest_powershell = lambda script, timeout=180: subprocess.CompletedProcess([], shutdown_code, "", "")
    backend._monitor = lambda command: sent.append(command) or "(qemu) "
    return backend, sent


def test_a_guest_that_shut_down_is_halted_as_before(capsys):
    backend, sent = qemu_guest(Guest(1), 0)
    backend.halt()
    assert sent == [] and "ACPI" not in capsys.readouterr().out


def test_a_failed_shutdown_request_falls_back_to_the_acpi_power_button(capsys):
    backend, sent = qemu_guest(Guest(2), 1)
    backend.halt()
    assert sent == ["system_powerdown"]
    assert "(asking it over WinRM failed with exit code 1); pressing its ACPI power button" in capsys.readouterr().out
    backend, sent = qemu_guest(Guest(3), 1)
    with pytest.raises(RuntimeError, match="guest shutdown did not finish"):
        backend.halt()


def test_a_qemu_that_died_says_its_exit_code():
    backend, _ = qemu_guest(Guest(1, code=137), 0)
    backend.process.returncode = 137
    with pytest.raises(RuntimeError, match=r"not running \(QEMU exited with 137\)"):
        backend.halt()


@pytest.mark.parametrize("second", [True, False])
def test_a_failed_soft_vmware_halt_is_asked_once_more_while_the_vm_runs(tmp_path, second):
    from fmb.generation.pipeline import GenerationPipeline

    instance = GenerationPipeline.__new__(GenerationPipeline)
    instance.discover_current_vmware_vmx_path = lambda: tmp_path / "box.vmx"
    instance.is_vmware_vm_running = lambda vmx: True
    calls = []

    def vmrun(args, **_):
        calls.append(args[0])
        if len(calls) == 1 or not second:
            raise subprocess.CalledProcessError(124, args)

    instance.run_vmrun = vmrun
    if second:
        instance.halt_vm()
    else:
        with pytest.raises(RuntimeError, match="soft VMware halt failed"):
            instance.halt_vm()
    assert calls == ["stop", "stop"]


@pytest.mark.parametrize("said, converts", [("qemu-img: error while reading sector 42: Input/output error", 2),
                                            ("qemu-img: error while writing at byte 9: No space left on device", 1)])
def test_a_failed_convert_is_tried_once_more_unless_the_disk_is_full(tmp_path, said, converts):
    from fmb.generation.pipeline import GenerationPipeline

    instance = GenerationPipeline.__new__(GenerationPipeline)
    calls = []

    def run_command(command, **_):
        calls.append(command[1])
        if command[1] == "convert":
            Path(command[-1]).write_bytes(b"partial")
            if calls.count("convert") == 1:
                raise subprocess.CalledProcessError(1, command, "", said)

    instance.run_command = run_command
    final = tmp_path / "full_scale.vmdk"
    if converts == 2:
        assert instance.convert_and_publish(tmp_path / "system.qcow2", final, "vmdk") == final
        assert calls == ["convert", "convert", "info"]
    else:
        with pytest.raises(RuntimeError, match="qemu-img convert failed: .*No space left on device"):
            instance.convert_and_publish(tmp_path / "system.qcow2", final, "vmdk")
        assert calls == ["convert"]
    assert not list(tmp_path.glob("*.partial"))


def phase(name, outcome, **extra):
    return "FMB_GENERATION_PHASE " + json.dumps({"phase": name, "outcome": outcome, **extra}) + "\n"


def failed(name, error="it broke"):
    return phase(name, "start") + phase(name, "error", error_type="RuntimeError") + f"fmb: {error}\n"


WRAP = failed("disk_discovery_export", "the intended timestamp transitions are not retained in the exported $LogFile; x")


def attempts_of(tmp_path, monkeypatch, logs):
    """Runs generate_image with a fake step whose attempts end with the given logs (None: published)."""
    folder = tmp_path / "I1"
    (folder / "recipe").mkdir(parents=True)
    monkeypatch.setattr(run, "await_base_clock", lambda recipe: None)
    events = []
    monkeypatch.setattr(run, "remove_leftovers", lambda: events.append("leftovers"))
    monkeypatch.setattr(run, "log", events.append)

    def step(name, *, log_path, output_root, **_):
        events.append(name)
        published = Path(output_root) / "full_scale" / "a"
        published.mkdir(parents=True)
        (published / "full_scale.vmdk").write_bytes(b"\0" * 2**20)
        text = logs[sum(event == "generate" for event in events) - 1]
        if text is None:
            (published / "manifest.json").write_text("{}")
        log_path.write_text(text or "done", encoding="utf-8")
        return 0 if text is None else 1

    monkeypatch.setattr(run, "step", step)
    image = SimpleNamespace(name="I1", paper=True, path=tmp_path / "I1.json")
    return lambda attempts=3: run.generate_image(image, tmp_path / "lock.json", folder, attempts), folder, events


def test_phase_lines_are_read_whatever_their_key_order_or_spacing():
    text = ('FMB_GENERATION_PHASE {"phase":"soft_halt","outcome":"error","outcome_detail":"x"}\n'
            'FMB_GENERATION_PHASE {"outcome": "error", "phase": "cleanup"}\nnot json\n')
    assert run.failed_phase(run.phase_records(text)) == "soft_halt"
    assert run.failed_phase(run.phase_records(phase("cleanup", "error"))) == "cleanup"
    assert run.failure(failed("soft_halt", "guest shutdown did not finish")) == (
        " at 'shut the guest down': guest shutdown did not finish")


def test_a_failed_playbook_is_summed_up_by_the_guest_tasks_own_reason(capsys):
    from fmb.core.errors import run_cli

    run_cli("fmb", lambda: (_ for _ in ()).throw(subprocess.CalledProcessError(2, ["ansible-playbook"])))
    reason = ("Materialize the declared bounded neutral population failed: exit code 1, script line 41, exception "
              "IOException (the rest is hidden: it can name private paths)")
    log = "\n".join([
        phase("ansible_provisioning", "start"),
        "fatal: [127.0.0.1]: FAILED! => {\"censored\": \"the output has been hidden due to the fact that 'no_log: "
        "true' was specified for this result\", \"changed\": true}",
        f'fatal: [127.0.0.1]: FAILED! => {{"changed": false, "msg": "{reason}"}}',
        phase("ansible_provisioning", "error"),
        capsys.readouterr().err,
    ])
    assert "fmb: unexpected internal failure" in log
    assert reason in run.failure(log) and "unexpected internal failure" not in run.failure(log)


@pytest.mark.parametrize("name", ["soft_halt", "disk_discovery_export", "cleanup"])
def test_a_late_failure_is_retried_without_its_disks(tmp_path, monkeypatch, name):
    generate, folder, events = attempts_of(tmp_path, monkeypatch, [failed(name), None])
    assert generate() == folder / "generation" / "attempt-2" / "full_scale" / "a"
    assert not (folder / "generation" / "attempt-1" / "full_scale" / "a" / "full_scale.vmdk").exists()
    assert ("leftovers" in events) == (name == "cleanup")
    assert any(f"attempt 1 failed at '{run.terminal.phase_title(name)}'" in str(event) for event in events)


@pytest.mark.parametrize("log", [failed("disk_discovery_export", "qemu-img convert failed: No space left on device"),
                                 failed("preflight"), "Traceback without a phase\n"])
def test_a_full_disk_or_a_failure_another_attempt_would_repeat_is_not_retried(tmp_path, monkeypatch, log):
    generate, _, events = attempts_of(tmp_path, monkeypatch, [log, None])
    with pytest.raises(SystemExit, match="generation failed"):
        generate()
    assert events.count("generate") == 1


def test_logfile_wraps_have_their_own_attempts(tmp_path, monkeypatch):
    provisioning = failed("ansible_provisioning")
    generate, folder, events = attempts_of(tmp_path, monkeypatch, [WRAP, WRAP, provisioning, provisioning, None])
    assert generate(3) == folder / "generation" / "attempt-5" / "full_scale" / "a"
    generate, folder, events = attempts_of(tmp_path / "again", monkeypatch, [WRAP, WRAP, None])
    with pytest.raises(SystemExit, match="not retained"):
        generate(2)
    assert "I1: attempt 2 lost a timestamp change" in events[-1] and events[-1].endswith("stopping after 2 such attempts")


def test_no_failure_hint_names_a_flag_that_does_not_exist():
    source = (Path(__file__).resolve().parents[2] / "src/fmb/generation/pipeline.py").read_text(encoding="utf-8")
    assert "--resume-post-export" not in source


def test_an_unpublished_attempt_never_keeps_its_disks(tmp_path, monkeypatch):
    generate, folder, events = attempts_of(tmp_path, monkeypatch, [failed("preflight")])
    stale = folder / "generation" / "attempt-1" / "full_scale" / "old"
    stale.mkdir(parents=True)
    (stale / "full_scale.vmdk.0a1b2c3d.partial").write_bytes(b"\0" * 2**26)
    (stale / "full_scale.vmdk").write_bytes(b"\0" * 2**26)
    (stale / "receipt.json").write_text("{}")
    with pytest.raises(SystemExit, match="generation failed"):
        generate()
    assert sorted(path.name for path in (folder / "generation").rglob("*") if path.is_file()) == ["receipt.json"]
    assert "I1: removed the disk images of its earlier unfinished attempts (0.1 GiB); their logs stay" in events


@pytest.mark.parametrize("how", ["code", "signal"])
def test_an_interrupted_attempt_leaves_no_disk_behind(tmp_path, monkeypatch, how):
    generate, folder, events = attempts_of(tmp_path, monkeypatch, [])

    def interrupted(name, **arguments):
        published = Path(arguments["output_root"]) / "full_scale" / "a"
        published.mkdir(parents=True)
        (published / "full_scale.vmdk").write_bytes(b"\0" * 2**27)
        if how == "signal":
            raise KeyboardInterrupt("generate stopped after cleaning up")
        return run.INTERRUPTED

    monkeypatch.setattr(run, "step", interrupted)
    with pytest.raises(KeyboardInterrupt if how == "signal" else SystemExit):
        generate()
    assert not list(folder.rglob("*.vmdk"))
    assert "I1: removed the disk images of interrupted attempt 1 (0.1 GiB); their logs stay" in events


def test_a_published_image_is_never_touched(tmp_path, monkeypatch):
    generate, folder, _ = attempts_of(tmp_path, monkeypatch, [])
    done = folder / "generation" / "attempt-1" / "full_scale" / "a"
    done.mkdir(parents=True)
    (done / "full_scale.vmdk").write_bytes(b"disk")
    (done / "manifest.json").write_text("{}")
    assert generate() == done and (done / "full_scale.vmdk").read_bytes() == b"disk"


def listing(*rows):
    return lambda *_, **__: subprocess.CompletedProcess([], 0, stdout="\n".join(rows))


def test_only_this_users_generation_leftovers_are_removed(tmp_path, monkeypatch):
    from fmb.replication import host

    monkeypatch.setenv("FMB_CACHE", str(tmp_path))
    clone = tmp_path / "vm-work" / "20261010_101010_000000"
    clone.mkdir(parents=True)
    (tmp_path / "vm-work" / "fmb-parser-1a2b3c").mkdir()
    monkeypatch.setattr(host, "WINDOWS", False)
    monkeypatch.setattr(host, "MACOS", True)
    monkeypatch.setattr(host.os, "getuid", lambda: 501, raising=False)
    monkeypatch.setattr(host.subprocess, "run", listing("1 501 /bin/zsh"))
    assert host.leftovers() == [("clone", str(clone))]
    monkeypatch.setattr(host.subprocess, "run", listing("77 0 python -m fmb.replication.steps generate {}"))
    assert host.leftovers() == [("clone", str(clone))]
    monkeypatch.setattr(host, "MACOS", False)
    monkeypatch.setenv("FMB_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(host.subprocess, "run", listing(
        "5 501 qemu-system-x86_64 -drive file=/w/attempt-1/.vagrant/system.qcow2",
        "6 1000 qemu-system-x86_64 -drive file=/home/other/attempt-1/.vagrant/system.qcow2",
        "7 501 qemu-system-x86_64 -name fmb-parser-4242 -pidfile /c/p.pid -drive file=/w/.vagrant/system.qcow2"))
    assert host.leftovers() == [("qemu", "5")]


def test_a_leftover_that_cannot_be_removed_is_reported_and_skipped(tmp_path, monkeypatch):
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    monkeypatch.setattr(run.host, "leftovers", lambda: [("qemu", "5"), ("qemu", "6"), ("overlay", str(overlay))])
    errors = {5: ProcessLookupError(3, "No such process"), 6: PermissionError(1, "Operation not permitted")}

    def kill(pid, _):
        raise errors[pid]

    monkeypatch.setattr(run.os, "kill", kill)
    events = []
    monkeypatch.setattr(run, "log", events.append)
    run.remove_leftovers()
    assert not overlay.exists()
    assert events[0] == "could not remove 6, left by an interrupted generation: [Errno 1] Operation not permitted"
    assert len(events) == 2


HOLDER = """
import os, sys, time
sys.path.insert(0, sys.argv[2])
from pathlib import Path
from fmb.replication import run
with run.generating(Path(sys.argv[1])):
    print("held", os.getpid(), flush=True)
    time.sleep(120)
"""


def stop(holder: subprocess.Popen, pid: str) -> None:
    """Kills the lock holder; on Windows a venv's python.exe is a launcher whose child holds the lock."""
    os.kill(int(pid), getattr(signal, "SIGKILL", signal.SIGTERM))
    holder.kill()
    holder.wait(timeout=30)
    holder.stdout.close()


def test_one_image_is_generated_by_one_fmb_at_a_time(tmp_path):
    import sys

    folder = tmp_path / "I1"
    source = str(Path(run.__file__).resolve().parents[2])
    holder = subprocess.Popen([sys.executable, "-c", HOLDER, str(folder), source], stdout=subprocess.PIPE, text=True)
    try:
        said, pid = holder.stdout.readline().split()
        assert said == "held"
        with pytest.raises(SystemExit, match="I1: another fmb is generating this image now"):
            with run.generating(folder):
                pass
    finally:
        stop(holder, pid)
    with run.generating(folder):
        pass
    with run.generating(folder):
        pass


def failing_pipeline(tmp_path, provider):
    from fmb.generation.pipeline import GenerationPipeline

    instance = GenerationPipeline.__new__(GenerationPipeline)
    instance.provider, instance.output_dir = provider, tmp_path / "attempt"
    instance.vagrant_state_dir, instance.population_guest_plan = tmp_path / "state", None
    instance.output_dir.mkdir()
    instance.vagrant_state_dir.mkdir()
    for step in ("preflight_checks", "prepare_population", "prepare_native_media", "record_post_export_cleanup"):
        setattr(instance, step, lambda *_: None)

    def provision():
        raise RuntimeError("ansible lost the guest")

    def cleanup():
        shutil.rmtree(instance.vagrant_state_dir)
        return {"status": "destroyed"}

    instance.provision_vm, instance.cleanup = provision, cleanup
    return instance


def test_a_failed_attempt_keeps_the_logs_of_its_vm(tmp_path, capsys):
    from fmb.generation.backends import QemuBackend

    instance = failing_pipeline(tmp_path, "qemu")
    (instance.vagrant_state_dir / "qemu.log").write_text("qemu: fatal: KVM internal error\n", encoding="utf-8")
    (instance.vagrant_state_dir / "serial.log").write_text("boot\n", encoding="utf-8")
    instance._vm_backend = QemuBackend(instance)
    instance._vm_backend.process = Guest(1, -9)
    instance._vm_backend.process.wait()
    with pytest.raises(RuntimeError, match="ansible lost the guest"):
        instance.run()
    kept = instance.output_dir / "vm-logs"
    assert sorted(path.name for path in kept.iterdir()) == ["qemu.log", "serial.log"]
    assert "[!] QEMU exited with -9; the end of its log:\nqemu: fatal: KVM internal error" in capsys.readouterr().out


def test_a_failed_vmware_attempt_keeps_its_vmware_log(tmp_path, capsys):
    instance = failing_pipeline(tmp_path, "vmware_desktop")
    machine = instance.vagrant_state_dir / "machines" / "default" / "vmware_desktop" / "1a2b"
    machine.mkdir(parents=True)
    (machine / "vmware.log").write_text("vcpu-0 panic\n", encoding="utf-8")
    with pytest.raises(RuntimeError):
        instance.run()
    assert (instance.output_dir / "vm-logs" / "vmware.log").read_text(encoding="utf-8") == "vcpu-0 panic\n"
    assert "QEMU exited" not in capsys.readouterr().out


def test_a_halted_qemu_says_nothing_about_its_exit(tmp_path):
    from fmb.generation.backends import QemuBackend

    backend = QemuBackend(SimpleNamespace(vagrant_state_dir=tmp_path))
    backend.process = Guest(1, 0)
    backend._guest_powershell = lambda script, timeout=180: subprocess.CompletedProcess([], 0, "", "")
    backend.halt()
    assert backend.exit_report() is None


def test_a_rerun_keeps_the_earlier_log_of_the_same_attempt(tmp_path, monkeypatch):
    generate, folder, _ = attempts_of(tmp_path, monkeypatch, [None])
    (folder / "generate-1.log").write_text("the failure being investigated", encoding="utf-8")
    generate()
    kept = [path for path in folder.glob("generate-1-*.log")]
    assert len(kept) == 1 and kept[0].read_text(encoding="utf-8") == "the failure being investigated"
    assert (folder / "generate-1.log").read_text(encoding="utf-8") == "done"


def test_a_slow_winrm_reply_is_waited_for_well_past_the_operation_timeout():
    from fmb.generation.backends import ansible_winrm_vars

    source = (Path(__file__).resolve().parents[2] / "src/fmb/generation/pipeline.py").read_text(encoding="utf-8")
    pipeline = [int(value) for value in re.findall(r'"ansible_winrm_read_timeout_sec": (\d+)', source)]
    winrm = ansible_winrm_vars(5985)
    assert len(pipeline) == 2 and all(value >= winrm["ansible_winrm_read_timeout_sec"] for value in pipeline)
    assert winrm["ansible_winrm_read_timeout_sec"] >= winrm["ansible_winrm_operation_timeout_sec"] + 120


PINNED = {"ANSIBLE_STDOUT_CALLBACK": "default", "ANSIBLE_CALLBACK_RESULT_FORMAT": "json", "ANSIBLE_NOCOLOR": "1",
          "ANSIBLE_FORCE_COLOR": "0"}


def pinned(env):
    return {key: env.get(key) for key in [*PINNED, "ANSIBLE_CONFIG"]}


@pytest.mark.parametrize("macos", [False, True])
def test_every_ansible_run_gets_fmbs_config_and_output_format(tmp_path, monkeypatch, macos):
    from fmb.generation import backends, recipe
    from fmb.generation.pipeline import GenerationPipeline

    config = Path(backends.__file__).parent / "ansible" / "ansible.cfg"
    expected = {**PINNED, "ANSIBLE_CONFIG": str(config)}
    assert "ansible/ansible.cfg" in {row["path"] for row in recipe.source_inventory(config.parents[1])}
    instance = GenerationPipeline.__new__(GenerationPipeline)
    instance.is_macos, instance.provider, instance.scenario = macos, "qemu", "ads_payload_01"
    instance.population_inputs_path, instance.recipe_bundle = None, None
    instance.get_ansible_connection = lambda: {"host": "127.0.0.1", "port": 5985, "user": "u", "password": "p"}
    seen = []
    instance.run_streaming_command = lambda command, env=None, **_: seen.append(env) or ""
    instance.run_command = lambda command, env=None, **_: seen.append(env)
    instance.run_ansible_playbook()
    instance.validate_vmware_ansible_winrm("10.0.0.5")
    monkeypatch.setattr(subprocess, "run", lambda command, env=None, **_: seen.append(env))
    backends.ansible_adhoc("ansible", 5985, "ansible.windows.win_ping", {}, timeout=10)
    assert [pinned(env) for env in seen] == [expected] * 3


def test_fmbs_own_collections_are_used_alone_once_setup_installed_them(tmp_path, monkeypatch):
    from fmb.generation.backends import ansible_settings

    monkeypatch.setenv("FMB_ANSIBLE_COLLECTIONS", str(tmp_path / "collections"))
    assert "ANSIBLE_COLLECTIONS_PATH" not in ansible_settings()
    (tmp_path / "collections").mkdir()
    assert ansible_settings()["ANSIBLE_COLLECTIONS_PATH"] == str(tmp_path / "collections")


def test_the_lock_reads_ansible_as_the_playbook_sees_it(tmp_path, monkeypatch):
    from fmb.generation import dependency_lock

    monkeypatch.setenv("FMB_ANSIBLE_COLLECTIONS", str(tmp_path))
    seen = []

    def run_owned(command, *, env=None, **_):
        seen.append(env)
        text = ("ansible [core 2.20.5]\n  ansible python module location = /x/ansible\n" if "--version" in command
                else json.dumps({"/c/ansible_collections": {"ansible.windows": {"version": "3.5.0"}}}))
        return subprocess.CompletedProcess(command, 0, text, "")

    monkeypatch.setattr("fmb.core.owned_process.run_owned", run_owned)
    layout = dependency_lock.ansible_layout(str(tmp_path / "ansible"))
    assert layout["collections"]["ansible.windows"]["version"] == "3.5.0"
    assert [env["ANSIBLE_COLLECTIONS_PATH"] for env in seen] == [str(tmp_path)] * 2
    assert all(pinned(env)["ANSIBLE_STDOUT_CALLBACK"] == "default" for env in seen)


def test_the_wsl_shim_passes_the_output_format_and_config_on(monkeypatch):
    import importlib.util

    path = Path(__file__).resolve().parents[2] / "tools/wsl-ansible/fmb_wsl_ansible.py"
    spec = importlib.util.spec_from_file_location("robustness_wsl_ansible", path)
    shim = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shim)
    commands = []
    monkeypatch.setattr(shim.subprocess, "call", lambda command: commands.append(command) or 0)
    monkeypatch.setattr(shim, "HOME", "/mnt/c/fmb-ansible")
    monkeypatch.setattr(shim.sys, "argv", ["ansible-playbook", "play.yml"])
    monkeypatch.setenv("ANSIBLE_CONFIG", "/mnt/c/fmb/src/fmb/generation/ansible/ansible.cfg")
    shim.ansible_playbook()
    variables = dict(part.split("=", 1) for part in commands[0][5:-2])
    assert {key: variables.get(key) for key in [*PINNED, "ANSIBLE_CONFIG"]} == {
        **PINNED, "ANSIBLE_CONFIG": "/mnt/c/fmb/src/fmb/generation/ansible/ansible.cfg"}


@pytest.mark.parametrize("windows", [False, True])
def test_setup_installs_fmbs_ansible_apart_from_the_users(tmp_path, monkeypatch, windows):
    from fmb.replication import host, setup

    monkeypatch.setenv("FMB_CACHE", str(tmp_path))
    monkeypatch.setattr(host, "MACOS", False)
    monkeypatch.setattr(host, "WINDOWS", windows)
    runs = []

    def run(command, env=None, **_):
        runs.append((command, env or {}))
        if "-p" in command:  # ansible-galaxy installs into its -p folder
            (Path(command[command.index("-p") + 1]) / "ansible_collections").mkdir(parents=True)

    monkeypatch.setattr(setup, "run", run)
    setup.ansible()
    installs = [(command, env) for command, env in runs if command[:3] == ["uv", "tool", "install"]]
    assert installs and all(env == {"UV_TOOL_DIR": str(tmp_path / "ansible" / "tools"),
                                    "UV_TOOL_BIN_DIR": str(tmp_path / "ansible" / "bin")} for _, env in installs)
    if not windows:
        galaxy = runs[-1][0]
        assert galaxy[0] == tmp_path / "ansible" / "bin" / "ansible-galaxy"
        assert galaxy[-2:] == ["-p", tmp_path / "ansible" / "collections.partial"]
        assert (tmp_path / "ansible" / "collections" / "ansible_collections").is_dir()


def test_fmbs_own_ansible_comes_first(tmp_path, monkeypatch):
    from fmb.replication import host

    monkeypatch.setenv("FMB_CACHE", str(tmp_path))
    monkeypatch.delenv("FMB_ANSIBLE_COLLECTIONS", raising=False)
    (tmp_path / "ansible" / "bin").mkdir(parents=True)
    (tmp_path / "user-bin").mkdir()
    monkeypatch.setattr(host, "uv_tool_bin", lambda: tmp_path / "user-bin")
    env = host.environment()
    path = env["PATH"].split(os.pathsep)
    assert path.index(str(tmp_path / "ansible" / "bin")) < path.index(str(tmp_path / "user-bin"))
    assert env["FMB_ANSIBLE_COLLECTIONS"] == str(tmp_path / "ansible" / "collections")


def recipe_folder(root, source, *, published=False):
    (root / "recipe").mkdir(parents=True)
    (root / "recipe" / "recipe.json").write_text(json.dumps({"schema_version": "generation_recipe.v2",
                                                             "source": source}), encoding="utf-8")
    if published:
        done = root / "generation" / "attempt-1" / "full_scale" / "a"
        done.mkdir(parents=True)
        (done / "full_scale.vmdk").write_bytes(b"disk")
        (done / "manifest.json").write_text("{}")
    return root


def test_a_recipe_frozen_from_other_generation_code_is_frozen_again(tmp_path, monkeypatch):
    from fmb.core.paths import PROJECT_ROOT
    from fmb.generation.recipe import source_closure

    events = []
    monkeypatch.setattr(run, "log", events.append)
    monkeypatch.setattr(run, "step", lambda name, *, recipe, **_: events.append(name) or Path(recipe).mkdir() or 0)
    image = SimpleNamespace(name="I1", paper=True, path=tmp_path / "I1.json")
    run.freeze(image, tmp_path / "lock.json", recipe_folder(tmp_path / "current", source_closure(PROJECT_ROOT)))
    run.freeze(image, tmp_path / "lock.json", recipe_folder(tmp_path / "published", [], published=True))
    assert events == []
    stale = recipe_folder(tmp_path / "stale", [{"path": "generation/pipeline.py", "sha256": "0" * 64}])
    run.freeze(image, tmp_path / "lock.json", stale)
    assert events[-1] == "freeze" and "an earlier version of fmb's generation code" in events[0]
    assert [path.name.startswith("recipe-") for path in stale.iterdir() if path.name != "recipe"] == [True]


def test_a_killed_lock_write_leaves_no_cut_lock(tmp_path, monkeypatch):
    from fmb.generation import dependency_lock, recipe
    from fmb.replication import steps

    monkeypatch.setattr(dependency_lock, "build_lock", lambda **_: {"schema_version": "x"})
    monkeypatch.setattr(dependency_lock, "pinned_digest", lambda lock: "0" * 64)

    def killed(path, value):
        Path(path).write_text('{"schema_vers', encoding="utf-8")
        raise KeyboardInterrupt

    monkeypatch.setattr(recipe, "write_private", killed)
    with pytest.raises(KeyboardInterrupt):
        steps.lock(path=str(tmp_path / "lock.json"), provider="qemu")
    assert list(tmp_path.iterdir()) == []


def test_freezing_leaves_nothing_in_the_working_directory(tmp_path, monkeypatch):
    from fmb.generation import recipe
    from fmb.replication import steps

    (tmp_path / "lock.json").write_text("{}", encoding="utf-8")
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    roots, real = [], steps._pipeline
    monkeypatch.setattr(steps, "_pipeline", lambda config, output, **options: roots.append(output) or real(
        config, output, **options))
    monkeypatch.setattr(recipe, "freeze_recipe", lambda *_, **__: {"recipe_id": "r", "schema_version": "v"})
    steps.freeze(image="I1", provider="qemu", lock=str(tmp_path / "lock.json"), recipe=str(tmp_path / "recipe"))
    assert list((tmp_path / "cwd").iterdir()) == [] and not roots[0].exists()
