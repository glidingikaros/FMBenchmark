from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fmb.replication import host
from fmb.replication.setup import log, windows_parsers

RETRYABLE = re.compile(r'"outcome": "error", "phase": "(qemu_boot|vagrant_boot|ansible_provisioning)"')


def step(name: str, *, log_path: Path | None = None, **arguments) -> int:
    encoded = json.dumps({key: str(value) if isinstance(value, Path) else value for key, value in arguments.items()})
    command = [sys.executable, "-m", "fmb.replication.steps", name, encoded]
    log(f"{name} {encoded}")
    if log_path is None:
        return subprocess.run(command, env=host.environment(), check=False).returncode
    with log_path.open("w", encoding="utf-8") as stream:
        process = subprocess.Popen(command, env=host.environment(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding="utf-8", errors="replace")
        for line in process.stdout:
            sys.stdout.write(line)
            stream.write(line)
        return process.wait()


def vm_work_root() -> Path | None:
    if not host.MACOS:
        return None
    root = host.cache() / "vm-work"
    root.mkdir(parents=True, exist_ok=True)
    return root


def dependency_lock(output: Path) -> Path:
    lock = output / "lock.json"
    if lock.is_file():
        return lock
    build = None
    if host.provider() == "qemu":
        facts = host.base_guest_facts()
        if facts is None:
            raise SystemExit("no Windows base yet: run `fmb replicate setup` first")
        build = facts["build"]
    if step("lock", path=lock, provider=host.provider(), windows_build=build) != 0:
        raise SystemExit("writing the dependency lock failed")
    return lock


def base_clock_wait_seconds(finished_utc: str, bias_minutes: int, now: datetime) -> float:
    finished = datetime.fromisoformat(finished_utc)
    pacific = finished.astimezone(ZoneInfo("America/Los_Angeles")).utcoffset() or timedelta(0)
    ready = finished + max(timedelta(minutes=bias_minutes) + pacific, timedelta(0)) + timedelta(minutes=10)
    return max(0.0, (ready - now).total_seconds())


def await_base_clock(recipe: Path) -> None:
    facts = host.base_guest_facts() or {}
    if host.provider() != "qemu" or "finished_utc" not in facts:
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


def generate(image: str, lock: Path, folder: Path, attempts: int) -> Path:
    recipe = folder / "recipe"
    if not recipe.exists():
        if step("freeze", image=image, provider=host.provider(), lock=lock, recipe=recipe) != 0:
            raise SystemExit(f"{image}: freezing the recipe failed")
    await_base_clock(recipe)
    for attempt in range(1, attempts + 1):
        if (done := completed(folder / "generation")) is not None:
            return done
        log_path = folder / f"generate-{attempt}.log"
        code = step("generate", recipe=recipe, output_root=folder / "generation" / f"attempt-{attempt}",
                    vm_work_root=vm_work_root(), log_path=log_path)
        if code == 0 and (done := completed(folder / "generation" / f"attempt-{attempt}")) is not None:
            return done
        if not RETRYABLE.search(log_path.read_text(encoding="utf-8", errors="replace")):
            break
        log(f"{image}: attempt {attempt} failed while booting or provisioning; retrying with the same recipe")
    raise SystemExit(f"{image}: generation failed, see {folder}")


def analyse(image: str, generation: Path, folder: Path) -> dict:
    config = {"case_label": image, "generation": str(generation), "conditions": ["luna-high"],
              "collect": {"windows_parsers": str(windows_parsers()), "host_toolchain_root": str(host.toolchain_root()),
                          **({"vm_work_root": str(host.cache() / "vm-work")} if host.MACOS else {})},
              "output": str(folder / "run")}
    (folder / "pipeline.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    step("analyse", config=folder / "pipeline.json", log_path=folder / "pipeline.log")
    return summary(image, folder / "run" / "gates" / "G5.json")


def summary(image: str, gate: Path) -> dict:
    if not gate.is_file():
        return {"image": image, "admission": "not reached"}
    g5 = json.loads(gate.read_text(encoding="utf-8"))
    rules = g5["comparison"]["rules"]
    return {"image": image, "admission": g5["admission"]["status"], "f1": rules["f1"],
            "exact": sum(bool(q["exact"]) for q in rules["per_question"].values()), "questions": len(rules["per_question"]),
            "counts": rules["finding_counts"],
            "not_exact": sorted(name for name, q in rules["per_question"].items() if not q["exact"])}


def write_summary(output: Path, results: list[dict]) -> None:
    base = host.windows_base()
    rows = [row | {"windows_base": base} for row in results] if base else results
    (output / "summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")


def images(names: list[str], output: Path, attempts: int) -> int:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    base = host.windows_base()
    if base and base["iso_pinned"] is False:
        log(f"the Windows base is build {base['build']} from an ISO that is not the pinned one "
            f"(SHA-256 {base['iso_sha256']}); summary.json records it with every image")
    results = []
    try:
        lock = dependency_lock(output)
    except SystemExit as error:
        results = [{"image": image, "admission": "not reached", "error": str(error)} for image in names]
        write_summary(output, results)
        raise
    for image in names:
        folder = output / image
        folder.mkdir(exist_ok=True)
        try:
            results.append(analyse(image, generate(image, lock, folder, attempts), folder))
        except SystemExit as error:
            results.append({"image": image, "admission": "not reached", "error": str(error)})
        write_summary(output, results)
    for row in results:
        log(f"{row['image']}: admission {row['admission']}"
            + (f", {row['exact']}/{row['questions']} exact, F1 {row['f1']}" if "exact" in row else f" ({row.get('error', '')})"))
    return 0 if all(row["admission"] == "passed" for row in results) else 1
