from __future__ import annotations

import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fmb.core.paths import workspace
from fmb.replication import awake, host, terminal
from fmb.replication.setup import log, windows_parsers

RETRYABLE = re.compile(r'"outcome": "error", "phase": "(qemu_boot|vagrant_boot|ansible_provisioning)"')
LOGFILE_WRAP = re.compile(r"timestamp transitions are not retained in the exported \$LogFile")
STALE_LOCK = re.compile(r"^fmb: (.*(?:differs from its lock|differ from their lock|locked base is not installed"
                        r"|lock pins no library for the generator's imports).*)$", re.MULTILINE)
FAILED_PHASE = re.compile(r'^FMB_GENERATION_PHASE (\{.*"outcome": "error".*\})$', re.MULTILINE)
ERROR_LINE = re.compile(r"^(?:fmb: (?!note: |details: )(.+)|fatal: \[[^]]*\]: (.+))$", re.MULTILINE)
INTERRUPTED = 130
# Streams each step's whole output to the terminal, as before these short lines (fmb generate/run --verbose).
VERBOSE = False


def generated_root() -> Path:
    return workspace() / "generated"


def results_root() -> Path:
    return workspace() / "results"


@contextmanager
def forwarded_signals(process: subprocess.Popen):
    received = []

    def forward(number, frame):
        received.append(number)
        if os.name == "posix" and process.poll() is None:
            process.send_signal(signal.SIGTERM)

    names = [name for name in ("SIGINT", "SIGTERM", "SIGHUP") if hasattr(signal, name)]
    previous = {name: signal.signal(getattr(signal, name), forward) for name in names}
    try:
        yield received
    finally:
        for name, handler in previous.items():
            signal.signal(getattr(signal, name), handler)


def step(name: str, *, log_path: Path, label: str | None = None, **arguments) -> int:
    """Runs one step in its own process; its whole output goes to log_path and short lines to the terminal."""
    encoded = json.dumps({key: str(value) if isinstance(value, Path) else value for key, value in arguments.items()})
    command = [sys.executable, "-m", "fmb.replication.steps", name, encoded]
    log_path.parent.mkdir(parents=True, exist_ok=True)
    shown = terminal.Lines(label or name, verbose=VERBOSE)
    with log_path.open("w", encoding="utf-8") as stream:
        stream.write(f"[fmb] {name} {encoded}\n")
        stream.flush()
        process = subprocess.Popen(command, env=host.environment(), stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        with forwarded_signals(process) as received:
            for line in process.stdout:
                stream.write(line)
                stream.flush()
                shown.feed(line)
            code = process.wait()
    shown.close(code)
    if received:
        raise KeyboardInterrupt(f"{name} stopped after cleaning up")
    return code


def remove_leftovers() -> None:
    for kind, target in host.leftovers():
        if kind == "qemu":
            os.kill(int(target), signal.SIGTERM)
            log(f"stopped QEMU process {target}, left by an interrupted generation")
            continue
        if kind == "overlay":
            shutil.rmtree(target)
            log(f"removed {target}, the guest disk of an interrupted generation")
            continue
        for vmx in Path(target).rglob("*.vmx"):
            subprocess.run([str(host.VMRUN), "-T", "fusion", "stop", str(vmx), "hard"], capture_output=True,
                           check=False, timeout=180)
        shutil.rmtree(target)
        log(f"removed {target}, the VM of an interrupted generation")


def discard_disks(attempt: Path) -> float:
    freed = 0
    for disk in [*attempt.rglob("*.vmdk"), *attempt.rglob("*.qcow2")]:
        freed += disk.stat().st_size
        disk.unlink()
    return freed / 2**30


def vm_work_root() -> Path | None:
    if not host.MACOS:
        return None
    root = host.cache() / "vm-work"
    root.mkdir(parents=True, exist_ok=True)
    return root


def dependency_lock(root: Path) -> Path:
    lock = root / "lock.json"
    if lock.is_file():
        return lock
    facts = host.guest_facts()
    if facts is None and host.provider() == "qemu":
        raise SystemExit("no Windows base yet: run fmb setup --iso <Microsoft's ISO>; fmb setup --check lists what "
                         "else is missing")
    build = facts["build"] if facts else None
    log("writing the dependency lock: the hypervisor, the Windows base, Ansible and the host libraries")
    if step("lock", path=lock, provider=host.provider(), windows_build=build, log_path=root / "lock.log",
            label="lock") != 0:
        raise SystemExit(f"writing the dependency lock failed; see {root / 'lock.log'}")
    return lock


def renew_lock(lock: Path) -> None:
    """Writes a new lock for this machine, keeping the earlier one next to it."""
    kept = lock.with_name(f"lock-{datetime.now():%Y%m%d-%H%M%S}.json")
    lock.rename(kept)
    try:
        dependency_lock(lock.parent)
    except BaseException:
        if not lock.exists():
            kept.rename(lock)
        raise
    log(f"wrote a new dependency lock; the earlier one is kept as {kept}")


def same_lock(recipe: Path, lock: Path) -> bool:
    try:
        frozen = json.loads((recipe / "dependency-lock.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    return frozen == json.loads(lock.read_text(encoding="utf-8"))


def set_aside(folder: Path) -> Path:
    kept = folder.with_name(f"{folder.name}-{datetime.now():%Y%m%d-%H%M%S}")
    folder.rename(kept)
    return kept


# finished_utc is taken after the base's guest powered off, and the verify boot writes only to a throwaway
# overlay, so the base's last event is before it; the margin covers the guest clock's drift during the build.
BASE_CLOCK_MARGIN_MINUTES = 3


def base_clock_wait_seconds(finished_utc: str, bias_minutes: int, now: datetime, provider: str) -> float:
    from fmb.generation.recipe import base_clock_lag_minutes

    lag = max(base_clock_lag_minutes(bias_minutes, provider, finished_utc), 0)
    ready = datetime.fromisoformat(finished_utc) + timedelta(minutes=lag + BASE_CLOCK_MARGIN_MINUTES)
    return max(0.0, (ready - now).total_seconds())


def await_base_clock(recipe: Path) -> None:
    facts = host.guest_facts() or {}
    if "finished_utc" not in facts:
        return
    bias = json.loads((recipe / "recipe.json").read_text(encoding="utf-8"))["config"].get("vmware_boot_clock_bias_minutes", 0)
    wait = base_clock_wait_seconds(facts["finished_utc"], int(bias), datetime.now(timezone.utc), host.provider())
    if wait:
        until = datetime.now().astimezone() + timedelta(seconds=wait)
        log(f"waiting until {until:%H:%M} ({terminal.duration(wait)}): the generation clock (bias {bias} minutes) "
            "must start after the base build's last logged events")
        time.sleep(wait)


def completed(root: Path) -> Path | None:
    return next((manifest.parent for manifest in sorted(root.glob("**/manifest.json"))
                 if (manifest.parent / "full_scale.vmdk").is_file()), None)


def failure(text: str) -> str:
    """Where a generation log says it failed: the phase and the last error line."""
    phases = FAILED_PHASE.findall(text)
    phase = json.loads(phases[-1])["phase"] if phases else None
    errors = ERROR_LINE.findall(text)
    error = next((part for part in errors[-1] if part), "") if errors else ""
    started = text.count(f'"outcome": "start", "phase": {json.dumps(phase)}') if phase else 0
    where = f" at '{terminal.phase_title(phase, started)}'" if phase else ""
    return where + (f": {error[:400]}" if error else "")


def stale(name: str, reason: str) -> str:
    return (f"{name}: this machine no longer matches the dependency lock ({reason[:300]}), as after an update of QEMU, "
            "VMware, Ansible or a Python library, a new version of fmb, or a rebuilt base; writing a new lock")


def freeze(image, lock: Path, folder: Path, renew: bool = True) -> None:
    recipe = folder / "recipe"
    if recipe.exists() and not same_lock(recipe, lock):
        kept = set_aside(recipe)
        log(f"{image.name}: its recipe was frozen with an earlier dependency lock ({kept.name}); freezing it again")
    if recipe.exists():
        return
    if step("freeze", image=image.name, provider=host.provider(), lock=lock, recipe=recipe,
            log_path=folder / "freeze.log", label=image.name,
            **({} if image.paper else {"image_file": image.path})) == 0:
        return
    found = STALE_LOCK.search((folder / "freeze.log").read_text(encoding="utf-8", errors="replace")) \
        if (folder / "freeze.log").is_file() else None
    if not (found and renew):
        raise SystemExit(f"{image.name}: freezing the recipe failed; see {folder / 'freeze.log'}")
    log(stale(image.name, found.group(1)))
    renew_lock(lock)
    freeze(image, lock, folder, renew=False)


def generate_image(image, lock: Path, folder: Path, attempts: int) -> Path:
    recipe = folder / "recipe"
    freeze(image, lock, folder)
    await_base_clock(recipe)
    attempt = failures = 0
    renewed, text, log_path = False, "", folder
    while failures < attempts:
        if (done := completed(folder / "generation")) is not None:
            return done
        attempt += 1
        log_path = folder / f"generate-{attempt}.log"
        log(f"{image.name}: generating, attempt {attempt}; its whole output goes to {log_path}")
        code = step("generate", recipe=recipe, output_root=folder / "generation" / f"attempt-{attempt}",
                    vm_work_root=vm_work_root(), log_path=log_path, label=image.name)
        if code == 0 and (done := completed(folder / "generation" / f"attempt-{attempt}")) is not None:
            return done
        if code == INTERRUPTED:
            raise SystemExit(f"{image.name}: generation interrupted; its VM is removed")
        text = log_path.read_text(encoding="utf-8", errors="replace")
        if (found := STALE_LOCK.search(text)) and not renewed:
            log(stale(image.name, found.group(1)))
            renew_lock(lock)
            renewed = True
            freeze(image, lock, folder, renew=False)
            continue
        failures += 1
        then = "retrying with the same recipe" if failures < attempts else f"that was the last of {attempts} attempts"
        if LOGFILE_WRAP.search(text):
            freed = discard_disks(folder / "generation" / f"attempt-{attempt}")
            log(f"{image.name}: attempt {attempt} lost a timestamp change from the $LogFile before export, which "
                f"Windows activity in the guest sometimes causes; removed its disk images ({freed:.0f} GiB); {then}")
            continue
        if not RETRYABLE.search(text):
            raise SystemExit(f"{image.name}: generation failed{failure(text)}; see {log_path}")
        log(f"{image.name}: attempt {attempt} failed while booting or provisioning; {then}")
    raise SystemExit(f"{image.name}: generation failed{failure(text)}; see {log_path}")


def asked(recipe: Path) -> list[str] | None:
    from fmb.core.case_contract import QIDS
    from fmb.replication import image_files

    contract = json.loads((recipe / "recipe.json").read_text(encoding="utf-8"))["config"].get("population_contract")
    questions = None if contract is None else image_files.questions(contract)
    return None if questions is None or set(questions) == set(QIDS) else questions


def analyse(name: str, generation: Path, recipe: Path, folder: Path, llm: dict | None = None,
            analysis: Path | None = None) -> dict:
    questions = asked(recipe)
    config = {"case_label": name, "generation": str(generation),
              "conditions": llm["conditions"] if llm else ["luna-high"],
              **({"questions": questions} if questions else {}),
              **({"dispatch": llm["dispatch"]} if llm else {}),
              **{key: llm[key] for key in ("user_conditions", "passes") if key in (llm or {})},
              **({"analysis": str(analysis)} if analysis else {}),
              "collect": {"windows_parsers": str(windows_parsers()), "host_toolchain_root": str(host.toolchain_root()),
                          **({"vm_work_root": str(host.cache() / "vm-work")} if host.MACOS else {})},
              "output": str(folder / "run")}
    (folder / "pipeline.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    log(f"{name}: running the pipeline (Figure 1, S1 to S4); its whole output goes to {folder / 'pipeline.log'}")
    started = time.monotonic()
    code = step("analyse", config=folder / "pipeline.json", recipe=recipe, log_path=folder / "pipeline.log", label=name)
    if code == INTERRUPTED:
        raise SystemExit(f"{name}: run interrupted")
    row = summary(name, folder / "run" / "gates" / "G5.json") | ({"llm_requested": llm["conditions"]} if llm else {})
    if stopped := unfinished(folder, code, row["admission"]):
        row["stopped"] = stopped
    log(f"{name}: pipeline finished in {terminal.duration(time.monotonic() - started)}")
    return row


def unfinished(folder: Path, code: int, admission: str) -> dict | None:
    """Where the pipeline stopped, from its run manifest or else its log; None when it finished."""
    try:
        manifest = json.loads((folder / "run" / "run-manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = {}
    if manifest.get("status") == "completed":
        return None if code == (0 if admission == "passed" else 1) else {"error": f"exit code {code}"}
    if failure := manifest.get("failure"):
        return {"at": failure["step"], "error": failure["message"][:400]}
    log_path = folder / "pipeline.log"
    errors = ERROR_LINE.findall(log_path.read_text(encoding="utf-8", errors="replace")) if log_path.is_file() else []
    return {"error": next((part for part in errors[-1] if part), "")[:400] if errors else f"exit code {code}"}


def code_identity() -> str:
    """The source manifest SHA-256 a run records for the code it ran (run-manifest.json, code)."""
    import hashlib

    from fmb.core import paper_integrity as integrity
    from fmb.core.hashing import sha256_file

    roots = integrity.source_roots()
    if integrity.modified_files(roots):
        return hashlib.sha256(integrity.record_bytes(integrity.current_record(roots))).hexdigest()
    return sha256_file(roots["package"] / "paper-source-manifest.json")


def earlier_collection(results: Path, generation: Path) -> Path | None:
    """The S2 collection of this image's latest run with the same image and code, which a later run may reuse."""
    from fmb.core.hashing import sha256_file

    image, code = sha256_file(generation / "manifest.json"), code_identity()
    for run in sorted(results.glob("*/run"), reverse=True):
        try:
            manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8"))
            g1 = json.loads((run / "gates" / "G1.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        s2 = next((stage for stage in manifest.get("stages", []) if stage.get("step") == "S2"), {})
        analysis = Path(s2.get("detail", {}).get("analysis", ""))
        if (s2.get("status") == "completed" and manifest.get("code", {}).get("source_manifest_sha256") == code
                and g1.get("generation_manifest", {}).get("sha256") == image and analysis.is_absolute()
                and analysis.is_dir() and analysis.with_name(analysis.name + "-truth-guard.json").is_file()):
            return analysis
    return None


ANSWERED = ("completed", "invalid_response")


def answered(score: dict | None) -> dict:
    """How many of a condition's scheduled S3' calls returned an answer, and what became of the others."""
    states = (score or {}).get("execution_states")
    if not states:
        return {}
    return {"answered": [sum(states.get(state, 0) for state in ANSWERED), sum(states.values())],
            "unanswered": {state: count for state, count in states.items() if state not in ANSWERED}}


def summary(image: str, gate: Path) -> dict:
    if not gate.is_file():
        return {"image": image, "admission": "not reached"}
    g5 = json.loads(gate.read_text(encoding="utf-8"))
    rules, conditions = g5["comparison"]["rules"], g5["comparison"].get("conditions") or {}
    scores = g5.get("scores") or {}
    return {"image": image, "admission": g5["admission"]["status"], "f1": rules["f1"],
            "exact": sum(bool(q["exact"]) for q in rules["per_question"].values()), "questions": len(rules["per_question"]),
            "counts": rules["finding_counts"],
            "not_exact": sorted(name for name, q in rules["per_question"].items() if not q["exact"]),
            **({"llm": {name: {"exact": [c["spread"]["exact_min"], c["spread"]["exact_max"]],
                               "f1": [c["spread"]["f1_min"], c["spread"]["f1_max"]], "passes": len(c["passes"]),
                               **answered(scores.get(name))}
                        for name, c in conditions.items()}} if conditions else {})}


def implementation(paper: list[str]) -> dict:
    from fmb.core import paper_integrity

    changed = paper_integrity.modified_files()
    if changed and paper:
        raise SystemExit(f"{len(changed)} files differ from the released implementation, such as {changed[0]}. "
                         f"The paper's images ({', '.join(paper)}) run with the released code only; images of your "
                         "own may run with changed code.")
    if changed:
        log(f"your images run with changed code: {len(changed)} files differ from the release")
    return {"implementation": "modified" if changed else "released", "changed_files": changed}


def prepare(images: list, root: Path) -> Path:
    """Checks the images and this machine before the first generation; returns the dependency lock."""
    from fmb.replication import image_files

    for image in images:
        log(image_files.check(image))
    root.mkdir(parents=True, exist_ok=True)
    base = host.windows_base()
    if base and base["iso_pinned"] is False:
        log(f"the Windows base is build {base['build']} from an ISO that is not the pinned one "
            f"(SHA-256 {base['iso_sha256']}); every result records it")
    if not host.WINDOWS:
        remove_leftovers()
    return dependency_lock(root)


class NoSpace(SystemExit):
    """Too little free disk to generate and analyse one more image."""


def warn(text: str) -> None:
    print(f"fmb: {text}", file=sys.stderr, flush=True)


# Free space moves by a few GiB on its own (macOS adds and drops 1 GiB swap files as memory fills), so a shortfall
# up to this only warns; a larger one refuses the image.
SLACK_GIB = 3
RESULTS_GIB = 1.1  # what one image's run leaves in results/
KEPT_GIB = 25  # about what one generated image keeps on disk


def shortfall(free: float, need: float) -> tuple[float, float]:
    """Free space rounded down and the shortfall rounded up, so that a refusal never reads as enough."""
    return math.floor(round(free * 10, 6)) / 10, math.ceil(round((need - free) * 10, 6)) / 10


def disk_space(name: str, root: Path) -> None:
    need, free = host.image_need_gib(), host.free_gib(root)
    if free >= need:
        return
    shown, short = shortfall(free, need)
    text = (f"generating and analysing it needs about {need:.1f} GiB free, and only {shown:.1f} GiB are free at "
            f"{root}; free {short:.1f} GiB more")
    if need - free <= SLACK_GIB:
        warn(f"{name}: {text} to be safe; going ahead, as free space moves by a few GiB on its own")
        return
    others = [folder.name for folder in sorted(root.iterdir()) if completed(folder / "generation") is not None]
    raise NoSpace(f"{name}: not generated: {text}"
                  + (f". Generated images there: {', '.join(others)}; fmb run with --delete-image deletes each "
                     "image after its passing run" if others else ""))


def list_space(steps: list[tuple[str, float, bool, float]], root: Path, advice: str) -> None:
    """Warns before the first of several images when they may not all fit; each is checked again before it is
    generated. A step is (image, GiB freed before it, whether it is generated, GiB it leaves taken)."""
    if len(steps) < 2 or not any(generates for _, _, generates, _ in steps):
        return
    need, free = host.image_need_gib(), host.free_gib(root)
    held = worst = 0.0
    for _, freed, generates, leaves in steps:
        held -= freed
        worst = max(worst, held + need) if generates else worst
        held += leaves
    if worst + SLACK_GIB <= free:
        return
    shown, short = shortfall(free, worst + SLACK_GIB)
    warn(f"{', '.join(name for name, *_ in steps)} may need up to about {worst + SLACK_GIB:.1f} GiB free at {root} "
         f"({advice}, and {SLACK_GIB} GiB to spare), and {shown:.1f} GiB are free; free about {short:.1f} GiB more "
         "before they start. Each image is checked again just before it is generated")


def generate_one(image, lock: Path, root: Path, attempts: int, again: bool = False) -> Path:
    folder = root / image.name
    if again and folder.exists():
        size = host.allocated_gib(folder)
        shutil.rmtree(folder)
        log(f"{image.name}: deleted the earlier generation ({size:.0f} GiB) to generate it again")
    if (done := completed(folder / "generation")) is not None:
        log(f"{image.name}: already generated ({done}); fmb generate {image.name} --again generates it again")
        return done
    definition = image.path.read_bytes()
    if (folder / "image.json").is_file() and (folder / "image.json").read_bytes() != definition:
        raise SystemExit(f"{image.path} changed since {folder} was started; fmb generate {image.name} --again "
                         "starts it again")
    disk_space(image.name, root)
    folder.mkdir(exist_ok=True)
    partial = folder / ".image.json.partial"  # an interrupted write must not leave a definition that reads as changed
    try:
        partial.write_bytes(definition)
        os.replace(partial, folder / "image.json")
    finally:
        partial.unlink(missing_ok=True)
    if busy := host.load_warning():
        log(f"{image.name}: {busy}")
    started, asleep = time.monotonic(), awake.asleep()
    try:
        done = generate_image(image, lock, folder, attempts)
    except SystemExit as error:
        if note := awake.slept(asleep):
            raise SystemExit(f"{error}{note}") from error
        raise
    log(f"{image.name}: generated in {terminal.duration(time.monotonic() - started)}: {done / 'full_scale.vmdk'}")
    return done


def load_images(paths: list[Path]) -> list:
    from fmb.replication import image_files

    images = [image_files.load(path) for path in paths]
    names = [image.name for image in images]
    if len(set(names)) != len(names):
        raise SystemExit("two images have the same name: " + ", ".join(names))
    return images


def generate_images(paths: list[Path], attempts: int, root: Path | None = None, again: bool = False) -> int:
    images = load_images(paths)
    implementation([image.name for image in images if image.paper])
    root = (root or generated_root()).resolve()
    lock = prepare(images, root)
    steps = []
    for image in images:
        folder = root / image.name
        generates = again or completed(folder / "generation") is None
        steps.append((image.name, host.allocated_gib(folder) if again and folder.exists() else 0.0, generates,
                      KEPT_GIB if generates else 0.0))
    list_space(steps, root, f"each generated image keeps about {KEPT_GIB} GiB")
    failed = []
    for image in images:
        try:
            generate_one(image, lock, root, attempts, again)
            log(f"{image.name}: analyse it with: fmb run {image.name}")
        except SystemExit as error:
            warn(str(error))
            failed.append(image.name)
    if failed and len(images) > 1:
        warn(f"{len(images) - len(failed)} of {len(images)} images generated; not generated: {', '.join(failed)}")
    return 1 if failed else 0


def generated(root: Path | None = None) -> list[str]:
    return sorted(folder.name for folder in (root or generated_root()).glob("*")
                  if completed(folder / "generation") is not None)


def paper_image(folder: Path) -> bool:
    return "population_contract" not in json.loads(
        (folder / "recipe" / "recipe.json").read_text(encoding="utf-8"))["config"]


def unused(path: Path) -> Path:
    """path, or path-2, path-3, ...: the first name not taken, as two runs can start in the same second."""
    number = 1
    while (candidate := path.with_name(f"{path.name}-{number}" if number > 1 else path.name)).exists():
        number += 1
    return candidate


def new_folder(path: Path) -> Path:
    """Creates the first name unused() finds for path, again if another fmb run took it at the same moment."""
    while True:
        try:
            (folder := unused(path)).mkdir(parents=True)
            return folder.resolve()
        except FileExistsError:
            continue


def summarise(outputs: list[Path], results: Path) -> None:
    """The paper's results table across the images of one fmb run."""
    from fmb.pipeline.report import write_report

    runs = [output / "run" for output in outputs if (output / "run" / "gates" / "G5.json").is_file()]
    if len(runs) < 2:
        return
    folder = unused(results / f"summary-{datetime.now():%Y%m%d-%H%M%S}")
    try:
        write_report(runs=runs, output=folder)
    except (OSError, ValueError) as error:
        log(f"the table across images was not written: {error}")
        return
    print((folder / "results.md").read_text(encoding="utf-8"), flush=True)
    log(f"the table across images, as in the paper: {folder / 'results.md'} (also table-results.csv)")


def run_steps(names: list[str], fresh: dict, root: Path, delete_image: bool) -> list[tuple[str, float, bool, float]]:
    """Each image's turn in fmb run for list_space: whether it is generated, and what it leaves taken afterwards."""
    steps = []
    for name in names:
        if delete_image:
            leaves = RESULTS_GIB - (0.0 if name in fresh else host.allocated_gib(root / name))
        else:
            leaves = RESULTS_GIB + (KEPT_GIB if name in fresh else 0.0)
        steps.append((name, 0.0, name in fresh, leaves))
    return steps


def run_images(names: list[str], llm: dict | None, root: Path | None = None, results: Path | None = None,
               delete_image: bool = False, attempts: int = 3, recollect: bool = False) -> int:
    from fmb.replication import image_files, report

    if host.WINDOWS and not host.long_paths():
        raise SystemExit("long paths are off on this computer, and collection writes paths over 260 characters; "
                         f"turn them on in an {host.LONG_PATHS}, then run fmb run again")
    root = (root or generated_root()).resolve()
    results = (results or results_root()).resolve()
    given: dict[str, str] = {}  # image name -> what was typed, which may be a path ending in .json
    for name in names:
        given.setdefault(Path(name).stem if name.endswith(".json") else name, name)
    names = list(given)
    missing = [name for name in names if completed(root / name / "generation") is None]
    images = {image.name: image for image in load_images([image_files.resolve(given[name]) for name in missing])}
    paper = [name for name in names if (images[name].paper if name in images else paper_image(root / name))]
    provenance = implementation(paper)
    lock = None
    if images:
        log(f"not generated yet: {', '.join(images)}; fmb run generates "
            + ("each one just before it runs it" if len(images) > 1 else "it first"))
        lock = prepare(list(images.values()), root)
        list_space(run_steps(names, images, root, delete_image), root,
                   f"each run keeps about {RESULTS_GIB} GiB of results"
                   + ("" if delete_image else f" and each generated image about {KEPT_GIB} GiB, which --delete-image "
                                              "deletes after its passing run"))
    rows, outputs, outcome = [], [], {}
    for name in names:
        folder = root / name
        if name in images:
            try:
                generate_one(images[name], lock, root, attempts)
            except SystemExit as error:
                warn(str(error))
                outcome[name] = "not run, too little free disk" if isinstance(error, NoSpace) else \
                    "generation failed"
                continue
        generation = completed(folder / "generation")
        output = new_folder(results / name / datetime.now().strftime("%Y%m%d-%H%M%S"))
        reuse = None if not llm or recollect else earlier_collection(results / name, generation)
        if reuse is not None:
            log(f"{name}: S2 reuses the collection of {reuse.parent.parent} (same image and code), so S3 and S3' read "
                "the same evidence cards; --recollect collects again")
        row = analyse(name, generation, folder / "recipe", output, llm, reuse)
        row |= {"paper_image": name in paper, **({} if name in paper else provenance),
                "windows_base": host.windows_base(), "generation": str(generation)}
        report.complete(output, row, folder, generation)
        rows.append(row)
        if not row.get("stopped"):
            outputs.append(output)
        outcome[name] = verdict(row)
        print("\n".join(report.headline(row, output)), flush=True)
        if row["admission"] != "passed":
            continue
        size = host.allocated_gib(folder)
        if delete_image and outcome[name] == "passed":
            delete(name, folder, size, output)
        elif delete_image:
            log(f"{name}: kept the generated image ({size:.0f} GiB) in {folder}, as "
                f"{outcome[name].removeprefix('passed, but ')}; --delete-image deletes it only after a complete run")
        else:
            log(f"{name}: the generated image ({size:.0f} GiB) stays in {folder} for further runs, such as an LLM "
                f"comparison; --delete-image removes it after a passing run")
    summarise(outputs, results)
    text = closing(names, outcome)
    if all(outcome.get(name) == "passed" for name in names):
        log(text)
        return 0
    warn(text)
    return 1


def verdict(row: dict) -> str:
    """How one image's run ended: passed only when it completed and every S3' call it scheduled was answered."""
    if stopped := row.get("stopped"):
        return "the pipeline stopped" + (f" at {stopped['at']}" if stopped.get("at") else "")
    if row["admission"] != "passed":
        return f"admission {row['admission']}"
    gaps = []
    for condition in row.get("llm_requested", []):
        done, planned = row.get("llm", {}).get(condition, {}).get("answered", [0, 0])
        if done < planned or not planned:
            gaps.append(f"S3' {condition} answered {done} of {planned} calls" if planned else f"S3' {condition} not sent")
    return "passed, but " + "; ".join(gaps) if gaps else "passed"


def delete(name: str, folder: Path, size: float, output: Path) -> None:
    """Deletes a generated image, its manifests first, so that what an error leaves no longer counts as generated."""
    try:
        for manifest in sorted((folder / "generation").glob("**/manifest.json")):
            manifest.unlink()
        shutil.rmtree(folder)
    except OSError as error:
        warn(f"{name}: the generated image was not deleted completely ({error}); delete {folder} by hand")
        return
    log(f"{name}: deleted the generated image ({size:.0f} GiB); its result stays in {output}")


def closing(names: list[str], outcome: dict[str, str]) -> str:
    """The last line of fmb run: which images passed and what stopped the others."""
    groups: dict[str, list[str]] = {}
    for name in names:
        groups.setdefault(outcome.get(name, "not run"), []).append(name)
    groups.pop("passed", None)
    passed = [name for name in names if outcome.get(name, "").startswith("passed")]
    return "; ".join([f"{len(passed)} of {len(names)} images passed admission"
                      + (f" ({', '.join(passed)})" if passed else ""),
                      *(f"{', '.join(group)}: {reason.removeprefix('passed, but ')}"
                        for reason, group in groups.items())])
