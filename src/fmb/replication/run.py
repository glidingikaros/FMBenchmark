from __future__ import annotations

import json
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
from zoneinfo import ZoneInfo

from fmb.replication import host
from fmb.replication.setup import log, windows_parsers

RETRYABLE = re.compile(r'"outcome": "error", "phase": "(qemu_boot|vagrant_boot|ansible_provisioning)"')
LOGFILE_WRAP = re.compile(r"timestamp transitions are not retained in the exported \$LogFile")
INTERRUPTED = 130
GENERATED = Path("generated")
RESULTS = Path("results")


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


def echo(line: str) -> None:
    try:
        sys.stdout.write(line)
    except OSError:
        pass


def step(name: str, *, log_path: Path | None = None, **arguments) -> int:
    encoded = json.dumps({key: str(value) if isinstance(value, Path) else value for key, value in arguments.items()})
    command = [sys.executable, "-m", "fmb.replication.steps", name, encoded]
    log(f"{name} {encoded}")
    if log_path is None:
        process = subprocess.Popen(command, env=host.environment())
        with forwarded_signals(process) as received:
            code = process.wait()
    else:
        with log_path.open("w", encoding="utf-8") as stream:
            process = subprocess.Popen(command, env=host.environment(), stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
            with forwarded_signals(process) as received:
                for line in process.stdout:
                    echo(line)
                    stream.write(line)
                code = process.wait()
    if received:
        raise KeyboardInterrupt(f"{name} stopped after cleaning up")
    return code


def remove_leftovers() -> None:
    for kind, target in host.leftovers():
        if kind == "qemu":
            os.kill(int(target), signal.SIGTERM)
            log(f"stopped QEMU process {target}, left by an interrupted generation")
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
        raise SystemExit("no Windows base yet: run `fmb setup` first")
    build = facts["build"] if facts else None
    if step("lock", path=lock, provider=host.provider(), windows_build=build) != 0:
        raise SystemExit("writing the dependency lock failed")
    return lock


def base_clock_wait_seconds(finished_utc: str, bias_minutes: int, now: datetime) -> float:
    finished = datetime.fromisoformat(finished_utc)
    pacific = finished.astimezone(ZoneInfo("America/Los_Angeles")).utcoffset() or timedelta(0)
    ready = finished + max(timedelta(minutes=bias_minutes) + pacific, timedelta(0)) + timedelta(minutes=10)
    return max(0.0, (ready - now).total_seconds())


def await_base_clock(recipe: Path) -> None:
    facts = host.guest_facts() or {}
    if "finished_utc" not in facts:
        return
    bias = json.loads((recipe / "recipe.json").read_text(encoding="utf-8"))["config"].get("vmware_boot_clock_bias_minutes", 0)
    wait = base_clock_wait_seconds(facts["finished_utc"], int(bias), datetime.now(timezone.utc))
    if wait:
        log(f"waiting {wait / 60:.0f} minutes: the generation clock (UTC minus {bias} minutes) must start after "
            "the base build's last logged events")
        time.sleep(wait)


def completed(root: Path) -> Path | None:
    return next((manifest.parent for manifest in sorted(root.glob("**/manifest.json"))
                 if (manifest.parent / "full_scale.vmdk").is_file()), None)


def generate_image(image, lock: Path, folder: Path, attempts: int) -> Path:
    recipe = folder / "recipe"
    if not recipe.exists():
        if step("freeze", image=image.name, provider=host.provider(), lock=lock, recipe=recipe,
                **({} if image.paper else {"image_file": image.path})) != 0:
            raise SystemExit(f"{image.name}: freezing the recipe failed")
    await_base_clock(recipe)
    for attempt in range(1, attempts + 1):
        if (done := completed(folder / "generation")) is not None:
            return done
        log_path = folder / f"generate-{attempt}.log"
        code = step("generate", recipe=recipe, output_root=folder / "generation" / f"attempt-{attempt}",
                    vm_work_root=vm_work_root(), log_path=log_path)
        if code == 0 and (done := completed(folder / "generation" / f"attempt-{attempt}")) is not None:
            return done
        if code == INTERRUPTED:
            raise SystemExit(f"{image.name}: generation interrupted; its VM is removed")
        text = log_path.read_text(encoding="utf-8", errors="replace")
        if LOGFILE_WRAP.search(text):
            freed = discard_disks(folder / "generation" / f"attempt-{attempt}")
            log(f"{image.name}: attempt {attempt} lost a timestamp change from the $LogFile before export, which "
                f"Windows activity in the guest sometimes causes; removed its disk images ({freed:.0f} GiB) and "
                "retrying with the same recipe")
            continue
        if not RETRYABLE.search(text):
            break
        log(f"{image.name}: attempt {attempt} failed while booting or provisioning; retrying with the same recipe")
    raise SystemExit(f"{image.name}: generation failed, see {folder}")


def asked(recipe: Path) -> list[str] | None:
    from fmb.core.case_contract import QIDS
    from fmb.replication import image_files

    contract = json.loads((recipe / "recipe.json").read_text(encoding="utf-8"))["config"].get("population_contract")
    questions = None if contract is None else image_files.questions(contract)
    return None if questions is None or set(questions) == set(QIDS) else questions


def analyse(name: str, generation: Path, recipe: Path, folder: Path, llm: dict | None = None) -> dict:
    questions = asked(recipe)
    config = {"case_label": name, "generation": str(generation),
              "conditions": llm["conditions"] if llm else ["luna-high"],
              **({"questions": questions} if questions else {}),
              **({"dispatch": llm["dispatch"]} if llm else {}),
              **{key: llm[key] for key in ("user_conditions", "passes") if key in (llm or {})},
              "collect": {"windows_parsers": str(windows_parsers()), "host_toolchain_root": str(host.toolchain_root()),
                          **({"vm_work_root": str(host.cache() / "vm-work")} if host.MACOS else {})},
              "output": str(folder / "run")}
    (folder / "pipeline.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    step("analyse", config=folder / "pipeline.json", recipe=recipe, log_path=folder / "pipeline.log")
    return summary(name, folder / "run" / "gates" / "G5.json")


def summary(image: str, gate: Path) -> dict:
    if not gate.is_file():
        return {"image": image, "admission": "not reached"}
    g5 = json.loads(gate.read_text(encoding="utf-8"))
    rules, conditions = g5["comparison"]["rules"], g5["comparison"].get("conditions") or {}
    return {"image": image, "admission": g5["admission"]["status"], "f1": rules["f1"],
            "exact": sum(bool(q["exact"]) for q in rules["per_question"].values()), "questions": len(rules["per_question"]),
            "counts": rules["finding_counts"],
            "not_exact": sorted(name for name, q in rules["per_question"].items() if not q["exact"]),
            **({"llm": {name: {"exact": [c["spread"]["exact_min"], c["spread"]["exact_max"]],
                               "f1": [c["spread"]["f1_min"], c["spread"]["f1_max"]], "passes": len(c["passes"])}
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


def generate_images(paths: list[Path], attempts: int, root: Path = GENERATED) -> int:
    from fmb.replication import image_files

    images = [image_files.load(path) for path in paths]
    names = [image.name for image in images]
    if len(set(names)) != len(names):
        raise SystemExit("two images have the same name: " + ", ".join(names))
    implementation([image.name for image in images if image.paper])
    for image in images:
        log(image_files.check(image))
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    base = host.windows_base()
    if base and base["iso_pinned"] is False:
        log(f"the Windows base is build {base['build']} from an ISO that is not the pinned one "
            f"(SHA-256 {base['iso_sha256']}); every result records it")
    if not host.WINDOWS:
        remove_leftovers()
    lock = dependency_lock(root)
    failed = []
    for image in images:
        folder = root / image.name
        if (done := completed(folder / "generation")) is not None:
            log(f"{image.name}: already generated ({done}); delete {folder} to generate it again")
            continue
        definition = image.path.read_bytes()
        if (folder / "image.json").is_file() and (folder / "image.json").read_bytes() != definition:
            raise SystemExit(f"{image.path} changed since {folder} was started; delete {folder} to start again")
        folder.mkdir(exist_ok=True)
        (folder / "image.json").write_bytes(definition)
        try:
            done = generate_image(image, lock, folder, attempts)
            log(f"{image.name}: generated {done / 'full_scale.vmdk'}; analyse it with: fmb run {image.name}")
        except SystemExit as error:
            log(str(error))
            failed.append(image.name)
    return 1 if failed else 0


def generated(root: Path = GENERATED) -> list[str]:
    return sorted(folder.name for folder in root.glob("*") if completed(folder / "generation") is not None)


def run_images(names: list[str], llm: dict | None, root: Path = GENERATED, results: Path = RESULTS,
               delete_image: bool = False) -> int:
    from fmb.replication import report

    folders = {name: (root / name).resolve() for name in names}
    missing = [name for name, folder in folders.items() if completed(folder / "generation") is None]
    if missing:
        raise SystemExit(f"not generated yet: {', '.join(missing)}; run: fmb generate {' '.join(missing)}")
    paper = [name for name, folder in folders.items() if "population_contract" not in json.loads(
        (folder / "recipe" / "recipe.json").read_text(encoding="utf-8"))["config"]]
    provenance = implementation(paper)
    rows = []
    for name, folder in folders.items():
        generation = completed(folder / "generation")
        output = (results / name / datetime.now().strftime("%Y%m%d-%H%M%S")).resolve()
        output.mkdir(parents=True)
        row = analyse(name, generation, folder / "recipe", output, llm)
        row |= {"paper_image": name in paper, **({} if name in paper else provenance),
                "windows_base": host.windows_base(), "generation": str(generation)}
        report.complete(output, row, folder, generation)
        rows.append(row)
        print("\n".join(report.headline(row, output)), flush=True)
        if row["admission"] != "passed":
            continue
        size = host.allocated_gib(folder)
        if delete_image:
            shutil.rmtree(folder)
            log(f"{name}: deleted the generated image ({size:.0f} GiB); its result stays in {output}")
        else:
            log(f"{name}: the generated image ({size:.0f} GiB) stays in {folder} for further runs, such as an LLM "
                f"comparison; --delete-image removes it after a passing run")
    return 0 if all(row["admission"] == "passed" for row in rows) else 1
