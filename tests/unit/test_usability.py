import io
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from fmb.cli.app import main
from fmb.core import progress
from fmb.replication import host, image_files, run, terminal

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "tests/fixtures/images/decoys.json"


def phase(name, outcome, seconds=0.0):
    return "FMB_GENERATION_PHASE " + json.dumps({"elapsed_seconds": seconds, "outcome": outcome, "phase": name}) + "\n"


def stage(step, outcome, seconds=0.0, **extra):
    return progress.PREFIX + json.dumps({"kind": "stage", "step": step, "outcome": outcome,
                                         "elapsed_seconds": seconds, **extra}) + "\n"


def shown(lines, **options):
    stream = io.StringIO()
    out = terminal.Lines("I1", stream=stream, live=False, **options)
    for line in lines:
        out.feed(line)
    out.close(0)
    return stream.getvalue().splitlines()


def test_generation_shows_one_line_per_phase_and_keeps_the_rest_in_the_log():
    assert shown([phase("qemu_boot", "start"), "QEMU says a lot\n", "TASK [manipulation : Create files] ***\n",
                  phase("qemu_boot", "ok", 179.4), phase("disk_discovery_export", "start"),
                  "[*] Post-export intervention 01 ntfs_allocation_01 on full_scale.vmdk\n",
                  phase("disk_discovery_export", "error", 3.0), "{\n", '  "status": "failed"\n', "}\n",
                  "fmb: qemu-img convert failed\n"]) == [
        "[fmb] I1  boot the Windows guest ...",
        "[fmb] I1  boot the Windows guest: 2m59s",
        "[fmb] I1  export the disk image and apply the post-export steps ...",
        "[fmb] I1  export the disk image and apply the post-export steps: failed after 3s",
        "fmb: qemu-img convert failed"]


def test_the_pipeline_shows_figure_1_stages_and_the_llm_plan():
    plan = progress.PREFIX + json.dumps({"kind": "llm_plan", "condition": "luna-high", "requests": 90,
                                         "worst_usd": "12.40", "cap_usd": "5.00", "covered": 36}) + "\n"
    assert shown([stage("S2", "start"), stage("S2", "completed", 185), stage("check:sources", "start"),
                  stage("check:sources", "completed"), stage("S4:admission", "start"),
                  stage("S4:admission", "completed", 1, admission="passed"), plan]) == [
        "[fmb] I1  S2  collect and prepare (G3 evidence cards) ...",
        "[fmb] I1  S2  collect and prepare (G3 evidence cards): 3m05s",
        "[fmb] I1  S4  admission: the rules against ground truth ...",
        "[fmb] I1  S4  admission: the rules against ground truth: 1s (passed)",
        "[fmb] I1  S3' luna-high: 90 requests; at most $12.40 if each uses all its output tokens; $5.00 of the cap is "
        "left, which covers 36 of them for sure"]


def test_the_two_recipe_checks_have_their_own_names_and_an_interruption_is_not_a_failure():
    interrupted = json.dumps({"elapsed_seconds": 213.0, "error_type": "KeyboardInterrupt", "outcome": "error",
                              "phase": "qemu_boot"})
    assert shown([phase("source_recipe_verification", "start"), phase("source_recipe_verification", "ok"),
                  phase("source_recipe_verification", "start"), phase("source_recipe_verification", "ok", 12),
                  phase("qemu_boot", "start"), "fmb: interrupted: SIGTERM\n",
                  "FMB_GENERATION_PHASE " + interrupted + "\n"]) == [
        "[fmb] I1  check the frozen recipe ...",
        "[fmb] I1  check the frozen recipe: 0s",
        "[fmb] I1  check this machine's tools against the recipe's lock ...",
        "[fmb] I1  check this machine's tools against the recipe's lock: 12s",
        "[fmb] I1  boot the Windows guest ...",
        "[fmb] I1  boot the Windows guest: interrupted after 3m33s"]
    log = phase("source_recipe_verification", "start") + phase("source_recipe_verification", "ok") \
        + phase("source_recipe_verification", "start") + phase("source_recipe_verification", "error") \
        + "fmb: host libraries differ from their lock\n"
    assert run.failure(log) == (" at 'check this machine's tools against the recipe's lock': host libraries differ "
                                "from their lock")


def test_verbose_shows_everything_as_it_comes():
    lines = [phase("qemu_boot", "start"), "QEMU says a lot\n"]
    assert shown(lines, verbose=True) == [line.rstrip("\n") for line in lines]


def test_a_step_keeps_its_whole_output_in_its_log(tmp_path, monkeypatch, capsys):
    import sys

    monkeypatch.setattr(run.sys, "executable", sys.executable)
    monkeypatch.setitem(run.__dict__, "VERBOSE", False)
    code = run.step("missing-step", log_path=tmp_path / "step.log", label="I1")
    text = (tmp_path / "step.log").read_text()
    assert code != 0 and text.startswith("[fmb] missing-step {}") and "KeyError" in text
    assert "Traceback" not in capsys.readouterr().out


def lock_text(version):
    return json.dumps({"backend": {"hypervisor": version}})


def test_a_stale_lock_is_renewed_and_the_recipe_frozen_again(tmp_path, monkeypatch):
    root = tmp_path / "generated"
    folder = root / "I1"
    (folder / "recipe").mkdir(parents=True)
    (root / "lock.json").write_text(lock_text("QEMU 10.1.0"))
    (folder / "recipe" / "dependency-lock.json").write_text(lock_text("QEMU 10.1.0"))
    monkeypatch.setattr(run, "await_base_clock", lambda recipe: None)
    monkeypatch.setattr(host, "guest_facts", lambda name=None: {"build": "26300"})
    calls = []

    def step(name, *, log_path, **arguments):
        calls.append(name)
        if name == "lock":
            Path(arguments["path"]).write_text(lock_text("QEMU 10.1.2"))
        elif name == "freeze":
            Path(arguments["recipe"]).mkdir()
            (Path(arguments["recipe"]) / "dependency-lock.json").write_text(lock_text("QEMU 10.1.2"))
        elif len(calls) == 1:
            log_path.write_text("fmb: hypervisor differs from its lock: QEMU 10.1.2 instead of QEMU 10.1.0\n")
            return 2
        else:
            published = Path(arguments["output_root"]) / "full_scale" / "a"
            published.mkdir(parents=True)
            (published / "full_scale.vmdk").write_bytes(b"disk")
            (published / "manifest.json").write_text("{}")
        return 0

    monkeypatch.setattr(run, "step", step)
    image = SimpleNamespace(name="I1", paper=True, path=tmp_path / "I1.json")
    done = run.generate_image(image, root / "lock.json", folder, attempts=1)
    assert calls == ["generate", "lock", "freeze", "generate"]
    assert done == folder / "generation" / "attempt-2" / "full_scale" / "a"
    assert json.loads((root / "lock.json").read_text())["backend"]["hypervisor"] == "QEMU 10.1.2"
    assert [path.name.startswith("lock-") for path in root.glob("lock-*.json")] == [True]
    assert len(list(folder.glob("recipe-*"))) == 1


def test_a_failed_generation_names_the_phase_the_error_and_the_log(tmp_path, monkeypatch):
    folder = tmp_path / "I1"
    (folder / "recipe").mkdir(parents=True)
    monkeypatch.setattr(run, "await_base_clock", lambda recipe: None)

    def step(name, *, log_path, **arguments):
        log_path.write_text(phase("disk_discovery_export", "error") + "Traceback ...\n"
                            "fmb: the exported disk has no NTFS volume\nfmb: note: cleanup ran\n")
        return 2

    monkeypatch.setattr(run, "step", step)
    image = SimpleNamespace(name="I1", paper=True, path=tmp_path / "I1.json")
    with pytest.raises(SystemExit) as error:
        run.generate_image(image, tmp_path / "lock.json", folder, attempts=1)
    assert str(error.value) == (f"I1: generation failed at 'export the disk image and apply the post-export steps': "
                                f"the exported disk has no NTFS volume; see {folder / 'generate-1.log'}")


def test_generation_stops_before_booting_without_the_disk_it_needs(tmp_path, monkeypatch, capsys):
    for name in ("I1", "I2"):
        published = tmp_path / name / "generation" / "attempt-1" / "full_scale" / "a"
        published.mkdir(parents=True)
        (published / "full_scale.vmdk").write_bytes(b"")
        (published / "manifest.json").write_text("{}")
    monkeypatch.setattr(host, "image_need_gib", lambda: 30.0)
    monkeypatch.setattr(host, "free_gib", lambda path: 22.4)
    with pytest.raises(SystemExit, match=r"I3: not generated: generating and analysing it needs about 30\.0 GiB free, "
                                         r"and only 22\.4 GiB are free at .*; free 7\.6 GiB more\. Generated images "
                                         r"there: I1, I2; fmb run with --delete-image"):
        run.disk_space("I3", tmp_path)
    # Just short: within the few GiB free space moves by on its own, so a warning that must not read as enough.
    monkeypatch.setattr(host, "image_need_gib", lambda: 35.97)
    monkeypatch.setattr(host, "free_gib", lambda path: 35.66)
    run.disk_space("I3", tmp_path)
    assert re.search(r"needs about 36\.0 GiB free, and only 35\.6 GiB are free at .*; free 0\.4 GiB more to be safe; "
                     r"going ahead", capsys.readouterr().err)
    monkeypatch.setattr(host, "free_gib", lambda path: 36.0)
    run.disk_space("I3", tmp_path)


def test_fmb_run_generates_runs_and_deletes_one_image_at_a_time(tmp_path, monkeypatch, capsys):
    from fmb.replication import report

    root, results = tmp_path / "generated", tmp_path / "results"
    root.mkdir()
    order = []

    def generate_one(image, lock, where, attempts, again=False):
        order.append(("generate", image.name, sorted(folder.name for folder in where.iterdir())))
        published = where / image.name / "generation" / "attempt-1" / "full_scale" / "a"
        published.mkdir(parents=True)
        (published / "manifest.json").write_text("{}")
        (published / "full_scale.vmdk").write_bytes(b"")
        (where / image.name / "recipe").mkdir()
        return published

    monkeypatch.setattr(run, "implementation", lambda paper: {})
    monkeypatch.setattr(run, "prepare", lambda images, where: order.append(("prepare", [i.name for i in images])))
    monkeypatch.setattr(run, "unfit_parsers", lambda: [])
    monkeypatch.setattr(run, "list_space", lambda *_: None)
    monkeypatch.setattr(run, "generate_one", generate_one)
    monkeypatch.setattr(run, "analyse", lambda name, *_: order.append(("run", name)) or {"image": name,
                                                                                         "admission": "passed"})
    monkeypatch.setattr(host, "windows_base", lambda: None)
    monkeypatch.setattr(report, "complete", lambda *_: None)
    monkeypatch.setattr(report, "headline", lambda row, output: [row["image"]])
    assert run.run_images(["I1", "I2"], None, root, results, delete_image=True) == 0
    assert order == [("prepare", ["I1", "I2"]), ("generate", "I1", []), ("run", "I1"), ("generate", "I2", []),
                     ("run", "I2")]
    assert list(root.iterdir()) == []
    assert capsys.readouterr().out.splitlines()[-1] == "[fmb] 2 of 2 images passed admission (I1, I2)"

    def no_space(image, *_, **__):
        if image.name != "I1":
            raise run.NoSpace(f"{image.name}: not generated: ...")
        return generate_one(image, *_, **__)

    monkeypatch.setattr(run, "generate_one", no_space)
    assert run.run_images(["I1", "I2", "I3"], None, root, tmp_path / "later", delete_image=True) == 1
    assert capsys.readouterr().err.splitlines() == [
        "fmb: I2: not generated: ...", "fmb: I3: not generated: ...",
        "fmb: 1 of 3 images passed admission (I1); I2, I3: not run, too little free disk"]
    assert run.closing(["I1", "I2", "I3"], {"I1": "admission failed", "I2": "generation failed"}) == (
        "0 of 3 images passed admission; I1: admission failed; I2: generation failed; I3: not run")


def test_an_llm_comparison_reuses_the_latest_collection_of_the_same_image_and_code(tmp_path, monkeypatch):
    from fmb.core.hashing import sha256_file

    generation = tmp_path / "generation"
    generation.mkdir()
    (generation / "manifest.json").write_text("{}")
    monkeypatch.setattr(run, "code_identity", lambda: "c0de")

    def earlier(stamp, code, image=sha256_file(generation / "manifest.json"), status="completed"):
        folder = tmp_path / "results" / "I1" / stamp / "run"
        (folder / "gates").mkdir(parents=True)
        (folder / "analysis").mkdir()
        (folder / "analysis-truth-guard.json").write_text("{}")
        (folder / "gates" / "G1.json").write_text(json.dumps({"generation_manifest": {"sha256": image}}))
        (folder / "run-manifest.json").write_text(json.dumps({"code": {"source_manifest_sha256": code}, "stages": [
            {"step": "S2", "status": status, "detail": {"analysis": str(folder / "analysis")}}]}))
        return folder / "analysis"

    assert run.earlier_collection(tmp_path / "results" / "I1", generation) is None
    reused = earlier("20261011-100000", "c0de")
    earlier("20261011-110000", "other code")
    earlier("20261011-120000", "c0de", image="another image")
    earlier("20261011-130000", "c0de", status="failed")
    assert run.earlier_collection(tmp_path / "results" / "I1", generation) == reused


def test_llm_options_list_every_problem_at_once():
    with pytest.raises(ValueError) as error:
        image_files.llm_dispatch(["luna-high", "sonnet5-high"], None, [], {})
    assert str(error.value) == (
        "add --cap-usd USD, the most the LLM requests of one image may cost, in US dollars; luna-high has no recorded "
        "price; add --price luna-high=INPUT,OUTPUT (US dollars per million tokens); luna-high calls openai: set "
        "OPENAI_API_KEY; sonnet5-high calls openrouter: set OPENROUTER_API_KEY")


def test_setup_stops_before_installing_when_something_it_cannot_install_is_missing(monkeypatch, capsys):
    from fmb.replication import setup

    rows = [("QEMU", False, "sudo apt-get install qemu-system-x86"), (".NET runtime 10.0.7", False, "run: fmb setup"),
            ("Windows base image", False, "fmb setup --iso <that file>")]
    monkeypatch.setattr(host, "checks", lambda: rows)
    monkeypatch.setattr(setup, "all_steps", lambda **_: pytest.fail("installed something"))
    with pytest.raises(SystemExit, match=r"first install what fmb setup cannot: QEMU\. The rows above"):
        main(["setup", "--iso", "x.iso"])
    assert "NO  QEMU" in capsys.readouterr().out


def test_fmb_finds_its_folders_from_anywhere(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FMB_HOME", raising=False)
    assert image_files.resolve("I1") == ROOT / "images" / "I1.json"
    assert run.generated_root() == ROOT / "generated"
    monkeypatch.setenv("FMB_HOME", str(tmp_path))
    assert run.results_root() == tmp_path / "results"
    with pytest.raises(ValueError, match=re.escape(f"no image I9 in {tmp_path / 'images'}")):
        image_files.resolve("I9")


def test_a_clock_bias_below_the_hosts_is_refused_when_the_image_is_checked(tmp_path, monkeypatch):
    value = json.loads(EXAMPLE.read_text())
    value["generation"] = {"clock_bias_minutes": 60}
    path = tmp_path / "early.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="early.json: generation.clock_bias_minutes is at least 480 on this host"):
        image_files.check(image_files.load(path))


def test_a_new_workspace_gets_its_disk_checked_before_it_exists(tmp_path, monkeypatch):
    monkeypatch.setenv("FMB_HOME", str(tmp_path / "new" / "workspace"))
    monkeypatch.setattr(host, "image_need_gib", lambda: 1.0)
    monkeypatch.setattr(host, "leftovers", lambda: [])
    monkeypatch.setattr(host, "which", lambda name: None)
    row = next(row for row in host.checks() if row[0].startswith("free disk"))
    assert row[2].endswith(f"free at {tmp_path}")


def test_fmb_run_generates_an_image_given_as_a_path(tmp_path, monkeypatch, capsys):
    from fmb.replication import report

    mine = tmp_path / "elsewhere" / "mine.json"
    mine.parent.mkdir()
    mine.write_text(EXAMPLE.read_text())
    root = tmp_path / "generated"
    root.mkdir()
    generated = []

    def generate_one(image, lock, where, attempts, again=False):
        generated.append((image.name, image.path))
        published = where / image.name / "generation" / "attempt-1" / "full_scale" / "a"
        published.mkdir(parents=True)
        (published / "manifest.json").write_text("{}")
        (published / "full_scale.vmdk").write_bytes(b"")
        (where / image.name / "recipe").mkdir()
        return published

    monkeypatch.setattr(run, "implementation", lambda paper: {})
    monkeypatch.setattr(run, "prepare", lambda images, where: None)
    monkeypatch.setattr(run, "unfit_parsers", lambda: [])
    monkeypatch.setattr(run, "generate_one", generate_one)
    monkeypatch.setattr(run, "paper_image", lambda folder: False)
    monkeypatch.setattr(run, "analyse", lambda name, *_: {"image": name, "admission": "passed"})
    monkeypatch.setattr(host, "windows_base", lambda: None)
    monkeypatch.setattr(report, "complete", lambda *_: None)
    monkeypatch.setattr(report, "headline", lambda row, output: [row["image"]])
    assert run.run_images([str(mine)], None, root, tmp_path / "results") == 0
    assert generated == [("mine", mine)]
