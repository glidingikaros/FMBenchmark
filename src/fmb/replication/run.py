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


def generate(image: str, lock: Path, folder: Path, attempts: int, image_file: Path | None = None) -> Path:
    recipe = folder / "recipe"
    if not recipe.exists():
        if step("freeze", image=image, provider=host.provider(), lock=lock, recipe=recipe,
                **({"image_file": image_file} if image_file else {})) != 0:
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


def analyse(image: str, generation: Path, folder: Path, llm: dict | None = None) -> dict:
    config = {"case_label": image, "generation": str(generation),
              "conditions": llm["conditions"] if llm else ["luna-high"],
              **({"dispatch": llm["dispatch"]} if llm else {}),
              "collect": {"windows_parsers": str(windows_parsers()), "host_toolchain_root": str(host.toolchain_root()),
                          **({"vm_work_root": str(host.cache() / "vm-work")} if host.MACOS else {})},
              "output": str(folder / "run")}
    (folder / "pipeline.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    step("analyse", config=folder / "pipeline.json", recipe=folder / "recipe", log_path=folder / "pipeline.log")
    return summary(image, folder / "run" / "gates" / "G5.json")


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


def write_summary(output: Path, results: list[dict]) -> None:
    base = host.windows_base()
    rows = [row | {"windows_base": base} for row in results] if base else results
    (output / "summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")


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


def images(names: list[str], output: Path, attempts: int, llm: dict | None = None) -> int:
    from fmb.replication import image_files

    output = output.resolve()
    own = {name: image_files.load(Path(name)) for name in names if name.endswith(".json")}
    labels = [own[name].name if name in own else name for name in names]
    if len(set(labels)) != len(labels):
        raise SystemExit("two images have the same name: " + ", ".join(labels))
    provenance = implementation([name for name in names if name not in own])
    for image in own.values():
        log(image_files.check(image))
    output.mkdir(parents=True, exist_ok=True)
    base = host.windows_base()
    if base and base["iso_pinned"] is False:
        log(f"the Windows base is build {base['build']} from an ISO that is not the pinned one "
            f"(SHA-256 {base['iso_sha256']}); summary.json records it with every image")
    results = []
    try:
        lock = dependency_lock(output)
    except SystemExit as error:
        results = [{"image": label, "admission": "not reached", "error": str(error)} for label in labels]
        write_summary(output, results)
        raise
    for name, label in zip(names, labels):
        folder = output / label
        folder.mkdir(exist_ok=True)
        image_file = own[name].path if name in own else None
        try:
            row = analyse(label, generate(label, lock, folder, attempts, image_file), folder, llm)
        except SystemExit as error:
            row = {"image": label, "admission": "not reached", "error": str(error)}
        results.append(({"image_file": str(image_file), **provenance} if image_file else {}) | row)
        write_summary(output, results)
    for row in results:
        log(f"{row['image']}: admission {row['admission']}"
            + (f", S3 {row['exact']}/{row['questions']} exact, F1 {row['f1']}" if "exact" in row else f" ({row.get('error', '')})")
            + "".join(f"; S3' {name} {llm['exact'][0]}-{llm['exact'][1]}/{row['questions']} exact over {llm['passes']} passes"
                      for name, llm in row.get("llm", {}).items()))
    return 0 if all(row["admission"] == "passed" for row in results) else 1
