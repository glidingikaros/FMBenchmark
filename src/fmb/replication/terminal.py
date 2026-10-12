from __future__ import annotations

import json
import re
import shutil
import sys
import time

from fmb.core.progress import PREFIX

GENERATION_PREFIX = "FMB_GENERATION_PHASE "
# The generation's own phases (FMB_GENERATION_PHASE), in plain words.
PHASES = {
    "source_recipe_verification": "check the recipe against this machine's locked tools",
    "preflight": "check the host",
    "population_media": "prepare the files and USB media to plant",
    "independent_apfs_clone": "clone the Windows box",
    "vagrant_boot": "boot the Windows guest",
    "qemu_boot": "boot the Windows guest",
    "ansible_provisioning": "user activity and manipulations in the guest",
    "host_record_validation": "check the ground-truth records",
    "soft_halt": "shut the guest down",
    "disk_discovery_export": "export the disk image and apply the post-export steps",
    "cleanup": "remove the VM",
}
# The pipeline's steps (pipeline/runner.py), in Figure 1's names; None keeps a quick check off the terminal.
STEPS = {
    "S1": "S1  resolve profile",
    "S2": "S2  collect and prepare (G3 evidence cards)",
    "check:presentation": None,
    "check:sources": None,
    "S3": "S3  deterministic assessment",
    "S3':freeze": "S3' freeze the LLM requests",
    "S4:admission": "S4  admission: the rules against ground truth",
    "S3':dispatch": "S3' send the LLM requests",
    "S3':publish": None,
    "S4:evaluation": "S4  compare and evaluate",
}
SCENARIO = re.compile(r"^included: .*/roles/manipulation/tasks/(?:pilot_)?(\w+?)\.yml for ")
SCENARIOS = re.compile(r'"msg": "Executing manipulation scenarios: ([\w,]+)')
TASK = re.compile(r"^TASK \[(?:[\w.-]+ : )?(.+?)\] \*")
INTERVENTION = re.compile(r"^\[\*\] Post-export intervention (\d+) (\S+) on ")


def duration(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m"


class Lines:
    """Turns a step's output into short lines; the full output goes to the step's log file."""

    def __init__(self, label: str, *, verbose: bool = False, stream=None, live: bool | None = None):
        self.label, self.verbose = label, verbose
        self.stream = stream or sys.stdout
        self.live = (not verbose and self.stream.isatty()) if live is None else live
        self.current = None
        self.title = ""
        self.started = time.monotonic()
        self.scenarios: list[str] = []
        self.shown = 0
        self.failed: str | None = None

    def write(self, text: str) -> None:
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError):
            pass

    def line(self, text: str) -> None:
        self.clear()
        self.write(f"[fmb] {self.label}  {text}\n")

    def status(self, text: str) -> None:
        if not self.live:
            return
        width = shutil.get_terminal_size((100, 20)).columns - 1
        status = f"[fmb] {self.label}  {text}"[:width]
        self.write("\r" + status + " " * max(self.shown - len(status), 0))
        self.shown = len(status)

    def clear(self) -> None:
        if self.shown:
            self.write("\r" + " " * self.shown + "\r")
            self.shown = 0

    def begin(self, name: str, title: str) -> None:
        self.current, self.title, self.started = name, title, time.monotonic()
        if self.live:
            self.status(title + " ...")
        else:
            self.line(title + " ...")

    def end(self, title: str, outcome: str, elapsed: float, extra: str = "") -> None:
        self.current = None
        if outcome in ("ok", "completed"):
            self.line(f"{title}: {duration(elapsed)}{extra}")
        else:
            self.failed = title
            self.line(f"{title}: failed after {duration(elapsed)}")

    def feed(self, raw: str) -> None:
        if self.verbose:
            self.write(raw)
            return
        text = raw.rstrip("\r\n")
        try:
            if text.startswith(GENERATION_PREFIX):
                return self.generation(json.loads(text[len(GENERATION_PREFIX):]))
            if text.startswith(PREFIX):
                return self.progress(json.loads(text[len(PREFIX):]))
        except (ValueError, KeyError, TypeError):
            return
        if text.startswith(("fmb: ", "[fmb] ", "[!] Warning")):
            self.clear()
            self.write(text + "\n")
        elif self.current is not None and self.live:
            self.detail(text)

    def detail(self, text: str) -> None:
        if found := SCENARIOS.search(text):
            self.scenarios = found.group(1).split(",")
        elif found := SCENARIO.match(text):
            if found.group(1) in self.scenarios:
                number = self.scenarios.index(found.group(1)) + 1
                self.status(f"{PHASES['ansible_provisioning']}: {number} of {len(self.scenarios)}, {found.group(1)}")
        elif found := INTERVENTION.match(text):
            self.status(f"{PHASES['disk_discovery_export']}: step {int(found.group(1))}, {found.group(2)}")
        elif (found := TASK.match(text)) and self.current == "ansible_provisioning" and not self.scenarios:
            self.status(f"{PHASES['ansible_provisioning']}: {found.group(1)}"[:200])

    def generation(self, record: dict) -> None:
        title = PHASES.get(record["phase"], record["phase"].replace("_", " "))
        if record["outcome"] == "start":
            self.begin(record["phase"], title)
        else:
            self.end(title, record["outcome"], record["elapsed_seconds"])

    def progress(self, record: dict) -> None:
        kind = record.get("kind")
        if kind == "stage":
            title = STEPS.get(record["step"], record["step"])
            if title is None and record["outcome"] in ("start", "completed"):
                return
            title = title or record["step"]
            if record["outcome"] == "start":
                self.begin(record["step"], title)
            else:
                extra = f" ({record['admission']})" if record.get("admission") else ""
                self.end(title, record["outcome"], record["elapsed_seconds"], extra)
        elif kind == "llm_plan":
            self.line(f"S3' {record['condition']}: {record['requests']} requests; at most ${record['worst_usd']} if "
                      f"each uses all its output tokens; ${record['cap_usd']} of the cap is left"
                      + ("" if record["covered"] >= record["requests"] else
                         f", which covers {record['covered']} of them for sure"))
        elif kind == "llm_call" and not self.live and (record["call"] % 10 == 0 or record["call"] == record["of"]):
            self.line(f"S3' {record['condition']}: {record['call']} of {record['of']} requests sent, "
                      f"${record['spent_usd']} so far")
        elif kind == "llm_call":
            self.status(f"S3' {record['condition']}: {record['call']} of {record['of']} requests sent, "
                        f"${record['spent_usd']} so far")

    def close(self, code: int) -> None:
        if self.current is not None and not self.verbose:
            self.line(f"{self.title}: stopped after {duration(time.monotonic() - self.started)}")
        self.clear()
