from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PureWindowsPath

DISTRO = os.environ.get("FMB_WSL_DISTRO", "Ubuntu-24.04")
HOME = os.environ.get("FMB_WSL_ANSIBLE_HOME", r"C:\fmb-ansible")
HOST_PATH_KEYS = ("fmb_factual_checkpoint_directory",)
DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
MOUNT_PATH = re.compile(r"/mnt/([a-z])(/[^\s'\",\]]*)?")


def to_wsl(value: str) -> str:
    if not DRIVE_PATH.match(value):
        return value
    path = PureWindowsPath(Path(value).resolve())
    return "/mnt/" + path.drive[0].lower() + "/" + "/".join(path.parts[1:])


def to_windows(text: str) -> str:
    return MOUNT_PATH.sub(lambda match: match.group(1).upper() + ":" + (match.group(2) or "/"), text)


def extra_vars_file(argument: str, scratch: Path) -> str:
    source = Path(argument[1:])
    data = json.loads(source.read_text(encoding="utf-8"))
    for key in HOST_PATH_KEYS:
        if isinstance(data.get(key), str):
            data[key] = to_wsl(data[key])
    copy = scratch / source.name
    copy.write_text(json.dumps(data), encoding="utf-8")
    return "@" + to_wsl(str(copy))


def run(tool: str) -> int:
    home = to_wsl(HOME)
    with tempfile.TemporaryDirectory(prefix="fmb-wsl-ansible-") as scratch:
        arguments = [extra_vars_file(argument, Path(scratch)) if argument.startswith("@") else to_wsl(argument)
                     for argument in sys.argv[1:]]
        command = ["wsl.exe", "-d", DISTRO, "--exec", "env", f"ANSIBLE_COLLECTIONS_PATH={home}/collections",
                   "ANSIBLE_HOST_KEY_CHECKING=False", "ANSIBLE_FORKS=1", f"{home}/bin/{tool}", *arguments]
        if tool == "ansible-galaxy" or "--version" in arguments:
            completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
            sys.stdout.write(to_windows(completed.stdout))
            sys.stderr.write(completed.stderr)
            return completed.returncode
        return subprocess.call(command)


def ansible() -> int:
    return run("ansible")


def ansible_playbook() -> int:
    return run("ansible-playbook")


def ansible_galaxy() -> int:
    return run("ansible-galaxy")
