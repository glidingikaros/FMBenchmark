from __future__ import annotations

import base64
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
NOISE_ROLE = PROJECT_ROOT / "src/fmb/generation/ansible/roles/noise/tasks/main.yml"
ANSIBLE_REQUIREMENTS = PROJECT_ROOT / "src/fmb/generation/ansible/requirements.yml"


def test_noise_role_uses_one_local_platform_independent_generator() -> None:
    source = NOISE_ROLE.read_text(encoding="utf-8")
    tasks = yaml.safe_load(source)

    assert isinstance(tasks, list)
    assert "http://" not in source.casefold()
    assert "https://" not in source.casefold()
    assert "win_get_url" not in source
    assert "win_unzip" not in source
    assert "download_ghosts" not in source
    assert "fmb_generation_host_is_macos" not in source
    assert "ignore_errors" not in source

    copy_tasks = [task for task in tasks if "ansible.windows.win_copy" in task]
    run_tasks = [task for task in tasks if "ansible.windows.win_shell" in task]
    assert len(copy_tasks) == 1
    assert len(run_tasks) == 1

    script_path = r"C:\ProgramData\LocalTasks\activity.ps1"
    assert copy_tasks[0]["ansible.windows.win_copy"]["dest"] == script_path
    assert script_path in run_tasks[0]["ansible.windows.win_shell"]
    removal = [task for task in tasks if task.get("ansible.windows.win_file", {}).get("state") == "absent"]
    assert removal and removal[0]["ansible.windows.win_file"]["path"] == r"C:\ProgramData\LocalTasks"
    assert "ForensicManipulation" not in NOISE_ROLE.read_text(encoding="utf-8")


def test_noise_generator_is_bounded_and_runs_in_the_ansible_session() -> None:
    tasks = yaml.safe_load(NOISE_ROLE.read_text(encoding="utf-8"))
    copy_task = next(task for task in tasks if "ansible.windows.win_copy" in task)
    run_task = next(task for task in tasks if "ansible.windows.win_shell" in task)
    script = copy_task["ansible.windows.win_copy"]["content"]
    command = run_task["ansible.windows.win_shell"]

    assert "$Iterations" in script
    assert "while($true)" not in script.replace(" ", "")
    assert "Start-Process" not in command
    assert "Start-Job" not in command


def test_noise_generator_powershell_parses_when_available() -> None:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell is not installed")

    tasks = yaml.safe_load(NOISE_ROLE.read_text(encoding="utf-8"))
    copy_task = next(task for task in tasks if "ansible.windows.win_copy" in task)
    script = copy_task["ansible.windows.win_copy"]["content"]
    encoded = base64.b64encode(script.encode()).decode()
    parser = (
        "$code=[Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String($args[0]));"
        "$tokens=$null;$errors=$null;"
        "[Management.Automation.Language.Parser]::ParseInput("
        "$code,[ref]$tokens,[ref]$errors)|Out-Null;"
        "if($errors.Count){$errors|ForEach-Object{Write-Error $_.Message};exit 1}"
    )

    result = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-CommandWithArgs", parser, encoded],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_generation_has_no_unused_windows_archive_collection() -> None:
    requirements = yaml.safe_load(ANSIBLE_REQUIREMENTS.read_text(encoding="utf-8"))
    collection_names = {
        collection["name"] for collection in requirements.get("collections", [])
    }

    assert collection_names == {"ansible.windows"}
