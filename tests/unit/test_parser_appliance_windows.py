import hashlib
import os
import subprocess

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
