from __future__ import annotations

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

