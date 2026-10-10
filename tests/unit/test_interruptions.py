import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from fmb.replication import host, run, steps

POSIX = pytest.mark.skipif(os.name != "posix", reason="POSIX signals")
CLEANING_STEP = """
import sys, time
from pathlib import Path
from fmb.replication import steps
marker = Path(sys.argv[1])
def slow(**_):
    try:
        print("started", flush=True)
        time.sleep(60)
    except BaseException:
        time.sleep(0.5)
        marker.write_text("cleaned")
        raise
steps.STEPS["slow"] = slow
raise SystemExit(steps.main(["slow", "{}"]))
"""
FORWARDING_CLI = """
import subprocess, sys
from fmb.replication import run
child = subprocess.Popen([sys.executable, "-c", sys.argv[1], sys.argv[2]], stdout=subprocess.PIPE, text=True)
assert child.stdout.readline().strip() == "started"
with run.forwarded_signals(child) as received:
    print("ready", flush=True)
    code = child.wait()
print(code, received, flush=True)
"""


def started(process: subprocess.Popen, line: str) -> None:
    assert process.stdout.readline().strip() == line


@POSIX
@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGHUP])
def test_a_stop_signal_lets_the_generator_clean_up_before_it_exits(tmp_path, number):
    marker = tmp_path / "marker"
    process = subprocess.Popen([sys.executable, "-c", CLEANING_STEP, str(marker)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    started(process, "started")
    process.send_signal(number)
    process.send_signal(number)
    assert process.wait(timeout=30) == run.INTERRUPTED
    assert marker.read_text() == "cleaned"
    assert "interrupted" in process.stderr.read()


@POSIX
def test_the_cli_forwards_a_stop_signal_and_waits_for_the_generator(tmp_path):
    marker = tmp_path / "marker"
    process = subprocess.Popen([sys.executable, "-c", FORWARDING_CLI, CLEANING_STEP, str(marker)],
                               stdout=subprocess.PIPE, text=True)
    started(process, "ready")
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=30) == 0
    assert process.stdout.read().split() == [str(run.INTERRUPTED), f"[{int(signal.SIGTERM)}]"]
    assert marker.read_text() == "cleaned"


def test_output_to_a_closed_pipe_does_not_stop_the_cleanup():
    class Closed:
        def write(self, text):
            raise BrokenPipeError

        def flush(self):
            raise BrokenPipeError

    stream = steps.Tolerant(Closed())
    assert stream.write("cleaning up") == len("cleaning up")
    stream.flush()


def generating(tmp_path, monkeypatch, outcomes):
    folder = tmp_path / "I1"
    (folder / "recipe").mkdir(parents=True)
    calls = []
    monkeypatch.setattr(run, "await_base_clock", lambda recipe: None)

    def step(name, *, log_path=None, **arguments):
        calls.append(name)
        attempt = Path(arguments["output_root"])
        published = attempt / "full_scale" / "a"
        published.mkdir(parents=True)
        (published / "full_scale.vmdk").write_bytes(b"disk")
        (published / "logfile-retention-receipt.json").write_text("{}")
        code, text, done = outcomes[len(calls) - 1]
        if done:
            (published / "manifest.json").write_text("{}")
        log_path.write_text(text)
        return code

    monkeypatch.setattr(run, "step", step)
    return folder, calls


def test_a_logfile_that_lost_a_timestamp_change_is_retried_without_its_disk(tmp_path, monkeypatch):
    wrapped = "fmb: the intended timestamp transitions are not retained in the exported $LogFile; the attempt"
    folder, calls = generating(tmp_path, monkeypatch, [(1, wrapped, False), (0, "done", True)])
    image = SimpleNamespace(name="I1", paper=True, path=tmp_path / "I1.json")
    done = run.generate_image(image, tmp_path / "lock.json", folder, attempts=3)
    assert done == folder / "generation" / "attempt-2" / "full_scale" / "a"
    assert calls == ["generate", "generate"]
    failed = folder / "generation" / "attempt-1" / "full_scale" / "a"
    assert not (failed / "full_scale.vmdk").exists()
    assert (failed / "logfile-retention-receipt.json").is_file()


def test_an_interrupted_generation_is_not_retried(tmp_path, monkeypatch):
    provisioning = '{"outcome": "error", "phase": "ansible_provisioning"}'
    folder, calls = generating(tmp_path, monkeypatch, [(run.INTERRUPTED, provisioning, False)])
    image = SimpleNamespace(name="I1", paper=True, path=tmp_path / "I1.json")
    with pytest.raises(SystemExit, match="interrupted"):
        run.generate_image(image, tmp_path / "lock.json", folder, attempts=3)
    assert calls == ["generate"]


def test_a_generation_left_running_is_stopped_and_removed(tmp_path, monkeypatch):
    clone = tmp_path / "vm-work" / "20261010_101010_000000"
    vmx = clone / "machines" / "default" / "vmware_desktop" / "box.vmx"
    vmx.parent.mkdir(parents=True)
    vmx.write_text("")
    commands, killed = [], []
    monkeypatch.setattr(host, "leftovers", lambda: [("clone", str(clone)), ("qemu", "4242")])
    monkeypatch.setattr(run.subprocess, "run", lambda command, **_: commands.append(command))
    monkeypatch.setattr(run.os, "kill", lambda pid, number: killed.append((pid, number)))
    run.remove_leftovers()
    assert commands == [[str(host.VMRUN), "-T", "fusion", "stop", str(vmx), "hard"]]
    assert not clone.exists()
    assert killed == [(4242, signal.SIGTERM)]


def listing(*lines):
    return lambda *_, **__: subprocess.CompletedProcess([], 0, stdout="\n".join(lines))


def test_leftovers_are_only_reported_while_no_generation_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("FMB_CACHE", str(tmp_path))
    (tmp_path / "vm-work" / "20261010_101010_000000").mkdir(parents=True)
    monkeypatch.setattr(host, "WINDOWS", False)
    monkeypatch.setattr(host, "MACOS", True)
    monkeypatch.setattr(host.subprocess, "run", listing("1 /bin/zsh"))
    assert host.leftovers() == [("clone", str(tmp_path / "vm-work" / "20261010_101010_000000"))]
    monkeypatch.setattr(host.subprocess, "run", listing("1 /bin/zsh", "77 python -m fmb.replication.steps generate {}"))
    assert host.leftovers() == []
    monkeypatch.setattr(host, "MACOS", False)
    monkeypatch.setattr(host.subprocess, "run", listing(
        "5 qemu-system-x86_64 -drive file=/w/generated/I1/generation/attempt-1/.vagrant/system.qcow2",
        "6 qemu-system-x86_64 -drive file=/home/me/other.qcow2"))
    assert host.leftovers() == [("qemu", "5")]


def test_the_disk_check_counts_the_box_or_base_and_a_result(tmp_path, monkeypatch):
    monkeypatch.setattr(host, "allocated_gib", lambda folder: 25.0)
    monkeypatch.setenv("VAGRANT_HOME", str(tmp_path))
    (tmp_path / "boxes" / "fmb-VAGRANTSLASH-windows-11-arm64" / "0").mkdir(parents=True)
    monkeypatch.setattr(host, "MACOS", True)
    assert host.image_need_gib() == 25 + 2 * host.RESERVE_GIB + 1 + host.RESULT_GIB
    monkeypatch.setattr(host, "MACOS", False)
    monkeypatch.setenv("FMB_QEMU_BASE_HOME", str(tmp_path / "bases"))
    assert host.image_need_gib() == 2 * 10 + host.RESERVE_GIB + host.RESULT_GIB
    from fmb.generation.recipe import qemu_box

    (tmp_path / "bases" / qemu_box().replace("/", "-VAGRANTSLASH-") / "0").mkdir(parents=True)
    assert host.image_need_gib() == 2 * 25 + host.RESERVE_GIB + host.RESULT_GIB


def test_a_passing_run_deletes_its_image_only_when_asked(tmp_path, monkeypatch):
    from fmb.replication import report

    generated, results = tmp_path / "generated", tmp_path / "results"
    for name in ("kept", "deleted", "failed"):
        published = generated / name / "generation" / "attempt-1" / "full_scale" / "a"
        published.mkdir(parents=True)
        (published / "full_scale.vmdk").write_bytes(b"disk")
        (published / "manifest.json").write_text("{}")
        (generated / name / "recipe").mkdir()
        (generated / name / "recipe" / "recipe.json").write_text(json.dumps({"config": {"population_contract": {}}}))
    monkeypatch.setattr(run, "implementation", lambda paper: {})
    monkeypatch.setattr(run, "analyse", lambda name, *_: {"image": name,
                                                           "admission": "failed" if name == "failed" else "passed"})
    monkeypatch.setattr(host, "windows_base", lambda: None)
    monkeypatch.setattr(report, "complete", lambda *_: None)
    monkeypatch.setattr(report, "headline", lambda row, output: [row["image"]])
    assert run.run_images(["kept"], None, generated, results) == 0
    assert run.run_images(["deleted", "failed"], None, generated, results, delete_image=True) == 1
    assert sorted(folder.name for folder in generated.iterdir()) == ["failed", "kept"]
