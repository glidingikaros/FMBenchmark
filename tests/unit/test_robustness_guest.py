from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from pwsh_helpers import PWSH, PWSH_TIMEOUT, requires_pwsh

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "src/fmb/generation/ansible/roles/manipulation/files"

# Renders the real Shellbag child for a target, in front of a fake Shell.Application whose window listing after the
# window's Quit() fails as given, and wraps it in the real watchdog. Arguments: helper, target, listing, close seconds,
# output path.
SHELLBAG_CHILD = r'''
. $args[0]
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
$assignment=$ast.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and $node.Left.VariablePath.UserPath -ceq 'childScript'},$true)
$expression=$assignment.Right.Find({param($node) $node -is [Management.Automation.Language.ExpandableStringExpressionAst]},$true)
$targetBase64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($args[1]))
$selectorSource='function Select-LocalCausalExactTargetShellWindows {'+[Environment]::NewLine+${function:Select-LocalCausalExactTargetShellWindows}.ToString()+[Environment]::NewLine+'}'
$matchSeconds=5;$closeSeconds=[int]$args[3]
$child=&([scriptblock]::Create($expression.Extent.Text))
$fake=@'
$script:fakeListing='__LISTING__';$script:fakeQuit=$false;$script:fakeExplored=$false;$script:fakeAfterQuit=0
function New-FakeWindow([bool]$Dying){
 $window=[PSCustomObject]@{Document=[PSCustomObject]@{Folder=[PSCustomObject]@{Self=[PSCustomObject]@{Path='__TARGET__'}}}}
 if($Dying){$window|Add-Member ScriptProperty HWND {throw 'RPC_E_DISCONNECTED'}}else{$window|Add-Member NoteProperty HWND 4242}
 $window|Add-Member ScriptMethod Quit {$script:fakeQuit=$true}
 $window
}
$script:fakeShell=[PSCustomObject]@{}
$script:fakeShell|Add-Member ScriptMethod Explore {param($path) $script:fakeExplored=$true}
$script:fakeShell|Add-Member ScriptMethod Windows {
 if(-not $script:fakeExplored){return ,@()}
 if(-not $script:fakeQuit){return ,@(New-FakeWindow $false)}
 $script:fakeAfterQuit+=1
 $first=$script:fakeAfterQuit -eq 1
 switch($script:fakeListing){
  'transient' {if($first){throw 'RPC_E_DISCONNECTED'};return ,@()}
  'dying' {if($first){return ,@(New-FakeWindow $true)};return ,@()}
  'persistent' {throw 'RPC_E_DISCONNECTED'}
  'open' {return ,@(New-FakeWindow $false)}
 }
}
function New-Object {$script:fakeShell}

'@
$fake=$fake.Replace('__LISTING__',$args[2]).Replace('__TARGET__',$args[1].Replace("'","''"))
$watchdog=New-LocalNativeShellbagWatchdogScript -ChildScript ($fake+$child) -TimeoutSeconds 60
[IO.File]::WriteAllText($args[4],$watchdog,[Text.UTF8Encoding]::new($false))
'''


@pytest.mark.pwsh
@requires_pwsh
@pytest.mark.parametrize(("listing", "expected"), [
    ("transient", 0),  # the listing throws once while Explorer destroys the closed window
    ("dying", 0),  # the closed window is still listed once, but its HWND throws
    ("persistent", 218),  # every listing fails until the close deadline
    ("open", 219),  # the listing works and the window never closes
])
def test_shellbag_close_wait_polls_through_a_failed_window_listing(tmp_path, listing, expected):
    watchdog = tmp_path / "watchdog.ps1"
    subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-CommandWithArgs", SHELLBAG_CHILD,
                    str(FILES / "native_shellbag.ps1"), str(tmp_path), listing, "2", str(watchdog)],
                   capture_output=True, text=True, check=True, timeout=PWSH_TIMEOUT)
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(watchdog)],
                            capture_output=True, text=True, check=False, timeout=PWSH_TIMEOUT)
    assert result.returncode == expected, result.stderr
    assert not result.stdout.strip() and not result.stderr.strip()


@pytest.mark.pwsh
@requires_pwsh
def test_shellbag_process_query_gives_a_slow_wmi_provider_time():
    audit = r'''
. $args[0]
$script:timeouts=@()
function Get-CimInstance {param($ClassName,$Filter,$OperationTimeoutSec,$ErrorAction) $script:timeouts+=$OperationTimeoutSec}
Get-LocalNativeShellbagOwnedProcesses -SupervisorCommand 'a' -WorkerCommand 'b' -ExpectedSessionId 1 | Out-Null
$script:timeouts -join ','
'''
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-CommandWithArgs", audit,
                             str(FILES / "native_shellbag.ps1")],
                            capture_output=True, text=True, check=True, timeout=PWSH_TIMEOUT)
    assert int(result.stdout) >= 30


# Runs the pilot's BQ-EXEC-01 step on a fake clock: the .pf appears after the given number of seconds.
PILOT_PREFETCH = r'''
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
$step=$ast.Find({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -ceq "`$q -eq 'BQ-EXEC-01'"},$true)
$body=$step.Clauses[0].Item2.Extent.Text
$script:start=[DateTime]'2026-01-01T00:00:00';$script:clock=$script:start;$script:appears=[int]$args[1];$script:pfFile=$args[2]
function Get-Date {$script:clock}
function Start-Sleep {param([int]$Seconds) $script:clock=$script:clock.AddSeconds($Seconds)}
function Start-Process {}
function Get-ChildItem {if(($script:clock-$script:start).TotalSeconds -ge $script:appears){Get-Item -LiteralPath $script:pfFile}}
function Get-Service {[PSCustomObject]@{Status='Running'}}
function Get-ItemProperty {[PSCustomObject]@{EnablePrefetcher=3}}
$p='C:\Pilot\f_PRIVATE_DO_NOT_EMIT.exe'
try {
 . ([scriptblock]::Create($body.Substring(1,$body.Length-2)))
 [ordered]@{ok=$true;waited=($script:clock-$script:start).TotalSeconds;witnesses=@($witnesses).Count}|ConvertTo-Json -Compress
} catch {
 [ordered]@{ok=$false;message=$_.Exception.Message}|ConvertTo-Json -Compress
}
'''


@pytest.mark.pwsh
@requires_pwsh
@pytest.mark.parametrize("appears", [100, 10_000])
def test_pilot_waits_like_prefetch_wipe_and_fails_with_counts_only(tmp_path, appears):
    pf = tmp_path / "F_PRIVATE_DO_NOT_EMIT.EXE-0123ABCD.pf"
    pf.write_bytes(b"MAM")
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-CommandWithArgs", PILOT_PREFETCH,
                             str(FILES / "pilot_challenge.ps1"), str(appears), str(pf)],
                            capture_output=True, text=True, check=True, timeout=PWSH_TIMEOUT)
    outcome = json.loads(result.stdout)
    if appears == 100:
        assert outcome == {"ok": True, "waited": 100, "witnesses": 1}
    else:
        assert outcome == {"ok": False, "message": "Pilot executable has no native Prefetch record: 0 of 1 .pf files "
                                                   "after 180 s (SysMain: Running, EnablePrefetcher: 3)"}


ANSIBLE = ROOT / "src/fmb/generation/ansible"
RESCUE = "{{ playbook_dir }}/hidden_task_failure.yml"
# These hidden tasks print their own path-free reason (failure stage, counts, or the helper's message).
SELF_REPORTING = {"ads_injection_01", "pilot_challenge", "pilot_ntfs_allocation_01", "prefetch_wipe_01",
                  "shellbag_path_residue_01", "timestomp_01"}


def _hidden_shell_tasks(tasks, rescue=None):
    for task in tasks or []:
        if "block" in task:
            yield from _hidden_shell_tasks(task["block"], task.get("rescue"))
        elif "ansible.windows.win_shell" in task and task.get("no_log") is True:
            yield task, rescue


def test_every_hidden_guest_task_reports_a_path_free_reason():
    yaml = pytest.importorskip("yaml")
    rescued = set()
    for path in sorted(ANSIBLE.rglob("*.yml")):
        for task, rescue in _hidden_shell_tasks(yaml.safe_load(path.read_text(encoding="utf-8"))):
            if rescue is None:
                assert path.stem in SELF_REPORTING, path
                continue
            [report] = rescue
            assert report["ansible.builtin.include_tasks"] == RESCUE, path
            assert report.get("vars", {}) == ({"fmb_failure_is_public": True} if path.stem == "recipe_environment" else {})
            rescued.add(path.stem)
    assert len(rescued) == 14


def _reporter():
    yaml = pytest.importorskip("yaml")
    [task] = yaml.safe_load((ANSIBLE / "hidden_task_failure.yml").read_text(encoding="utf-8"))
    return task


def test_the_rescue_prints_only_values_that_cannot_carry_private_inputs():
    import re

    task = _reporter()
    assert task["no_log"] is False and set(task) == {"name", "vars", "ansible.builtin.fail", "no_log"}
    variables = task["vars"]
    message = task["ansible.builtin.fail"]["msg"]
    assert variables["fmb_failure_stderr"] == "{{ ansible_failed_result.stderr | default('') | trim }}"
    for name in ("fmb_failure_lines", "fmb_failure_types"):
        assert re.fullmatch(r"\{\{ fmb_failure_stderr \| regex_findall\('[^']+'(?:, multiline=True)?\) "
                            r"\| unique \| join\(', '\) \}\}", variables[name].strip())
    # The result reaches the message only as these fields; its own message only for a task that declares it public.
    fields = set(re.findall(r"ansible_failed_\w+(?:\.\w+)?|fmb_\w+", message))
    assert fields == {"ansible_failed_task.name", "ansible_failed_result.rc", "fmb_failure_lines", "fmb_failure_types",
                      "fmb_failure_stderr", "fmb_failure_is_public"}
    assert re.search(r"\(': ' ~ \(fmb_failure_stderr\.splitlines\(\) \+ \[''\]\)\[0\]\) if fmb_failure_is_public",
                     message)
    assert message.count("fmb_failure_stderr") == 1


# Windows PowerShell 5.1 errors as win_shell returns them (CLIXML decoded), with private names in every free-text part.
DECODED_STDERR = "\r\n".join([
    "Exception calling \"WriteAllBytes\" with \"2\" argument(s): \"Could not find a part of the path "
    "'C:\\Users\\vagrant\\PRIVATE_DO_NOT_EMIT\\f.bmp'.\"",
    "At line:41 char:11",
    "+           [System.IO.File]::WriteAllBytes($path, $bmp)",
    "+           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
    "    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException",
    "    + FullyQualifiedErrorId : DirectoryNotFoundException",
    " ",
    "Copy-Item : Cannot find path 'C:\\PRIVATE_DO_NOT_EMIT\\PrivateException' because it does not exist.",
    "At C:\\ProgramData\\LocalTasks\\activity.ps1:25 char:11",
    "+           Copy-Item -LiteralPath $source -Destination $path -Force",
    "+           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
    "    + CategoryInfo          : ObjectNotFound: (C:\\PRIVATE_DO_N...PrivateException:String) [Copy-Item], "
    "ItemNotFoundException",
    "    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.CopyItemCommand",
    " ",
    "PRIVATE_DO_NOT_EMIT",
    "At line:12 char:9",
    "+         throw $name",
    "+         ~~~~~~~~~~~",
    "    + CategoryInfo          : OperationStopped: (PRIVATE_DO_NOT_EMIT:String) [], RuntimeException",
    "    + FullyQualifiedErrorId : PRIVATE_DO_NOT_EMIT",
])


@pytest.mark.parametrize("raw_clixml", [False, True])
def test_the_rescue_patterns_extract_lines_and_types_and_nothing_private(raw_clixml):
    import re

    variables = _reporter()["vars"]
    lines, types = (re.search(r"regex_findall\('([^']+)'", variables[name]).group(1)
                    for name in ("fmb_failure_lines", "fmb_failure_types"))
    stderr = DECODED_STDERR
    if raw_clixml:
        stderr = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\">" + "".join(
            f'<S S="Error">{line}_x000D__x000A_</S>' for line in stderr.split("\r\n")) + "</Objs>"
    found_lines = re.findall(lines, stderr)
    found_types = re.findall(types, stderr, re.MULTILINE)
    assert found_types == ["MethodInvocationException", "DirectoryNotFoundException", "ItemNotFoundException",
                           "RuntimeException"]
    assert found_lines == ["41", "25", "12"]
    assert "PRIVATE" not in "".join(found_lines + found_types)
