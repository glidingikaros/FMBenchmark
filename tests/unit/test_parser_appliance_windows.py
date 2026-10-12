import hashlib
import json
import os
import subprocess
import zipfile

import pytest

from fmb.collection.tools.host import parser_appliance as appliance


def test_windows_powershell_runs_with_its_own_module_path(monkeypatch):
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setenv("ProgramFiles", "C:\\Program Files")
    monkeypatch.setenv("PSModulePath", "C:\\Program Files\\PowerShell\\7\\Modules")
    powershell, env = appliance._windows_powershell()
    assert powershell == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert [key for key in env if key.upper() == "PSMODULEPATH"] == ["PSModulePath"]
    assert env["PSModulePath"] == ("C:\\Program Files\\WindowsPowerShell\\Modules;"
                                   "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules")


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell")
def test_get_file_hash_works_when_fmb_was_started_from_powershell_7(monkeypatch, tmp_path):
    seven = os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "PowerShell", "7", "Modules")
    monkeypatch.setenv("PSModulePath", seven + ";" + os.environ.get("PSModulePath", ""))
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"fmb")
    powershell, env = appliance._windows_powershell()
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command",
                             f"(Get-FileHash -Algorithm SHA256 -LiteralPath '{sample}').Hash"],
                            env=env, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().lower() == hashlib.sha256(b"fmb").hexdigest()


def test_a_failed_parser_script_shows_the_end_of_its_error_output(tmp_path):
    stderr = "\n".join(f"line {number}" for number in range(20)) + "\nThe term 'Get-FileHash' is not recognized\n"
    error = appliance._script_failed(subprocess.CompletedProcess([], 1, stdout="", stderr=stderr),
                                     tmp_path / "out.txt", tmp_path / "err.txt")
    message = str(error)
    assert message.startswith(f"parser script exited 1; see {tmp_path / 'err.txt'}\n")
    assert message.endswith("The term 'Get-FileHash' is not recognized")
    assert "line 8" not in message and "line 9" in message
    quiet = appliance._script_failed(subprocess.CompletedProcess([], 2, stdout="", stderr=""),
                                     tmp_path / "out.txt", tmp_path / "err.txt")
    assert str(quiet) == f"parser script exited 2; see {tmp_path / 'out.txt'}"


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell")
def test_the_parser_script_runs_the_parsers_together_and_lists_them_in_plan_order(tmp_path):
    # Two stand-ins for PECmd and SBECmd: the first one planned ends last, the second exits 3.
    tools = {"Slow": "@echo off\r\nping -n 4 127.0.0.1 > nul\r\necho Slow> \"%~2\\slow.csv\"\r\necho slow done\r\n"
                     "exit /b 0\r\n",
             "Fast": "@echo off\r\necho Fast> \"%~2\\fast.csv\"\r\necho fast done\r\nexit /b 3\r\n"}
    commands = [{"label": label, "category": label + "Output", "executable": label + ".cmd",
                 "arguments": ["%targets%", "%out%"]} for label in tools]
    root = tmp_path / "root"
    root.mkdir()
    with zipfile.ZipFile(root / "inputs.zip", "w") as package:
        for label, text in tools.items():
            package.writestr(f"bin/{label}.cmd", text)
        package.writestr("targets/C/input.txt", "input")
        package.writestr("plan.json", json.dumps({"commands": commands, "file_times": []}))
    script = root / "run_parsers.ps1"
    script.write_text(appliance.GUEST_SCRIPT, encoding="utf-8")
    powershell, env = appliance._windows_powershell()
    completed = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                "-File", str(script), "-Root", str(root)],
                               env=env, capture_output=True, text=True, timeout=300)
    assert completed.returncode == 0, completed.stderr
    with zipfile.ZipFile(root / "outputs.zip") as outputs:
        names = {name.replace("\\", "/") for name in outputs.namelist()}
        receipt = json.loads(outputs.read("receipt.json").decode("utf-8-sig"))
    slow, fast = receipt["results"]
    assert [slow["label"], fast["label"]] == ["Slow", "Fast"] and [slow["exit_code"], fast["exit_code"]] == [0, 3]
    assert fast["started_at"] < slow["ended_at"] and fast["ended_at"] < slow["ended_at"]
    assert {"modules/SlowOutput/slow.csv", "modules/FastOutput/fast.csv", "logs/Slow.stdout.txt",
            "logs/Fast.stdout.txt"} <= names
