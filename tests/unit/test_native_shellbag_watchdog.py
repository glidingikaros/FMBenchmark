from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from fmb.collection.run.lock import process_is_running

HELPER = Path(__file__).resolve().parents[2] / "src/fmb/generation/ansible/roles/manipulation/files/native_shellbag.ps1"
PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell is not installed")


def build_watchdog(tmp_path: Path, child: str, timeout: int = 10) -> Path:
    path = tmp_path / "watchdog.ps1"
    builder = (
        ". $args[0];$child=[Console]::In.ReadToEnd();"
        "$script=New-LocalNativeShellbagWatchdogScript -ChildScript $child -TimeoutSeconds ([int]$args[2]);"
        "[IO.File]::WriteAllText($args[1],$script,[Text.UTF8Encoding]::new($false))"
    )
    subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-CommandWithArgs", builder,
                    str(HELPER), str(path), str(timeout)],
                   input=child, text=True, capture_output=True, check=True, timeout=15)
    return path


@pytest.mark.parametrize(("child", "expected"), [
    ("[Console]::Out.WriteLine('FMB_STAGE:218');[Console]::Out.WriteLine('FMB_DONE:0');exit 0", 0),
    ("[Console]::Out.WriteLine('FMB_STAGE:213');exit 213", 213),
    ("[Console]::Out.WriteLine('FMB_STAGE:213');[Console]::Out.Flush();Start-Sleep 60", 213),
    ("[Console]::Out.WriteLine('FMB_STAGE:218');[Console]::Out.WriteLine('FMB_DONE:0');[Console]::Out.Flush();Start-Sleep 60", 222),
    ("Start-Sleep 60", 220),
    ("exit 0", 221),
    ("[Console]::Out.Write(('x'*65536));[Console]::Out.Flush();Start-Sleep 60", 221),
    ("[Console]::Out.Write('FMB_STAGE:213');[Console]::Out.Flush();exit 213", 221),
    ("[Console]::Out.WriteLine('PRIVATE_DO_NOT_EMIT');exit 0", 221),
    ("[Console]::Error.Write(('z'*262144));[Console]::Error.Flush();[Console]::Out.WriteLine('FMB_STAGE:218');[Console]::Out.WriteLine('FMB_DONE:0');exit 0", 0),
])
def test_watchdog_classifies_real_process_boundaries_without_relaying_output(tmp_path, child, expected):
    script = build_watchdog(tmp_path, child)
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)],
                            text=True, capture_output=True, check=False, timeout=30)
    assert result.returncode == expected, result.stderr
    assert not result.stdout.strip()
    assert not result.stderr.strip()


def test_watchdog_kills_only_its_owned_process(tmp_path):
    pid_file = tmp_path / "owned.pid"
    escaped = str(pid_file).replace("'", "''")
    child = (f"[IO.File]::WriteAllText('{escaped}',[string]$PID);"
             "[Console]::Out.WriteLine('FMB_STAGE:213');[Console]::Out.Flush();Start-Sleep 60")
    script = build_watchdog(tmp_path, child)
    unrelated = subprocess.Popen([PWSH, "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep 30"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 213
        assert unrelated.poll() is None
        owned_pid = int(pid_file.read_text())
        assert not process_is_running(owned_pid)
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_actual_child_and_watchdog_templates_parse_and_fit_windows_commands(tmp_path):
    audit = r'''
. $args[0]
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Helper AST invalid'}
function Assert-MonotonicWaits($tree){
 $wallClock=@($tree.FindAll({param($node)
  ($node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Get-Date') -or
  ($node -is [Management.Automation.Language.MemberExpressionAst] -and $node.Extent.Text -match '\[DateTime\]::(?:Now|UtcNow)')
 },$true))
 foreach($node in $wallClock){
  $owner=$node.Parent
  while($owner -and $owner -isnot [Management.Automation.Language.FunctionDefinitionAst]){$owner=$owner.Parent}
  if(-not $owner -or $owner.Name -cne 'Get-LocalNativeShellbagProcessDiagnostic'){throw 'Relative wait reads mutable wall clock'}
 }
}
Assert-MonotonicWaits $ast
$assignment=$ast.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and $node.Left.VariablePath.UserPath -ceq 'childScript'},$true)
$expression=$assignment.Right.Find({param($node) $node -is [Management.Automation.Language.ExpandableStringExpressionAst]},$true)
$nested=@($expression.NestedExpressions)
if($nested.Count -ne 4 -or @($nested|Where-Object{$_ -isnot [Management.Automation.Language.VariableExpressionAst] -or $_.VariablePath.UserPath -notin @('targetBase64','selectorSource','matchSeconds','closeSeconds')}).Count){throw 'Unexpected child interpolation'}
$matchSeconds=20;$closeSeconds=20
$selectorSource='function Select-LocalCausalExactTargetShellWindows {'+[Environment]::NewLine+${function:Select-LocalCausalExactTargetShellWindows}.ToString()+[Environment]::NewLine+'}'
$rows=@(foreach($length in @(90,260,1024)){
 $targetBase64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('C:\Records\Folders\'+('d'*$length)))
 $childScript=&([scriptblock]::Create($expression.Extent.Text))
 $childScript='# in-memory dispatch '+('0'*32)+[Environment]::NewLine+$childScript
 $watchdog=New-LocalNativeShellbagWatchdogScript -ChildScript $childScript
 foreach($name in @('child','watchdog')){
  $source=if($name -eq 'child'){$childScript}else{$watchdog}
  $tokens=$null;$errors=$null
  $renderedAst=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
  Assert-MonotonicWaits $renderedAst
  if($errors.Count){throw 'Rendered AST invalid'}
  $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($source))
  $command='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -STA -WindowStyle Hidden -OutputFormat Text -EncodedCommand '+$encoded
  if($command.Length+1 -gt 32767){throw 'Windows command limit'}
  [ordered]@{kind=$name;dummy_length=$length;command_characters=$command.Length+1}
 }
})
$rows|ConvertTo-Json -Compress
'''
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-CommandWithArgs", audit, str(HELPER)],
                            capture_output=True, text=True, check=True, timeout=20)
    rows = json.loads(result.stdout)
    assert len(rows) == 6
    assert {r["kind"] for r in rows} == {"child", "watchdog"}
    assert max(r["command_characters"] for r in rows) < 32767


def test_dispatch_diagnostic_reconstructs_only_fixed_typed_fields(tmp_path):
    audit = r'''
. $args[0]
$script:LocalNativeShellbagDispatchDiagnostic=@{
 task_state='PRIVATE_DO_NOT_EMIT';fresh_registration_verified='true';ran_this_dispatch='true';last_task_result='267009';
 elapsed_ms=[Int64]-1;supervisor_count=[Int32]999;worker_count='1';
 start_scheduled_task_elapsed_ms='100';cleanup_elapsed_ms=[Int64]4000000;
 supervisor_age_wall_ms=[Int64]-1;supervisor_cpu_cumulative_ms='PRIVATE_DO_NOT_EMIT';supervisor_thread_count=[Int32]-1;
 worker_age_wall_ms=[Int64]100;worker_cpu_cumulative_ms=[Int64]0;worker_thread_count=[Int32]1;
 cleanup_code='PRIVATE_DO_NOT_EMIT';process_query_succeeded='true';secret='PRIVATE_DO_NOT_EMIT'
}
$invalid=Get-LocalNativeShellbagDispatchDiagnostic
$script:LocalNativeShellbagDispatchDiagnostic=@{
 task_state='Running';fresh_registration_verified=$true;ran_this_dispatch=$true;last_task_result=[UInt32]267009;
 elapsed_ms=[Int64]240123;supervisor_count=[Int32]1;worker_count=[Int32]0;
 start_scheduled_task_elapsed_ms=[Int64]123;cleanup_elapsed_ms=[Int64]77;
 supervisor_age_wall_ms=[Int64]1000;supervisor_cpu_cumulative_ms=[Int64]250;supervisor_thread_count=[Int32]3;
 worker_age_wall_ms=[Int64]100;worker_cpu_cumulative_ms=[Int64]0;worker_thread_count=[Int32]1;
 cleanup_code='verified';process_query_succeeded=$true;secret='PRIVATE_DO_NOT_EMIT'
}
$valid=Get-LocalNativeShellbagDispatchDiagnostic
@($invalid,$valid)|ConvertTo-Json -Compress
'''
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-CommandWithArgs", audit, str(HELPER)],
                            capture_output=True, text=True, check=True, timeout=15)
    invalid, valid = json.loads(result.stdout)
    assert invalid == dict(task_state="unobserved", fresh_registration_verified=False, ran_this_dispatch=False,
                           last_task_result=None, start_scheduled_task_elapsed_ms=None, parent_elapsed_ms=None,
                           process_query_succeeded=False, supervisor_count=None,
                           worker_count=None, supervisor_age_wall_ms=None, supervisor_cpu_cumulative_ms=None,
                           supervisor_thread_count=None, worker_age_wall_ms=None, worker_cpu_cumulative_ms=None,
                           worker_thread_count=None, cleanup_code="unobserved", cleanup_elapsed_ms=None)
    assert valid == dict(task_state="Running", fresh_registration_verified=True, ran_this_dispatch=True,
                         last_task_result=267009, start_scheduled_task_elapsed_ms=123, parent_elapsed_ms=240123,
                         process_query_succeeded=True, supervisor_count=1,
                         worker_count=0, supervisor_age_wall_ms=1000, supervisor_cpu_cumulative_ms=250,
                         supervisor_thread_count=3, worker_age_wall_ms=None, worker_cpu_cumulative_ms=None,
                         worker_thread_count=None, cleanup_code="verified", cleanup_elapsed_ms=77)
    assert "PRIVATE_DO_NOT_EMIT" not in result.stdout + result.stderr


def test_cim_process_summary_requires_one_role_and_keeps_unknown_fields_null():
    audit = r'''
. $args[0]
$valid=[PSCustomObject]@{
 CreationDate=[DateTime]::UtcNow.AddSeconds(-10);KernelModeTime=[UInt64]20000;UserModeTime=[UInt64]30000;
 ThreadCount=[UInt32]7;ProcessId=98765;CommandLine='PRIVATE_DO_NOT_EMIT';ExecutablePath='PRIVATE_DO_NOT_EMIT'
}
$validEntry=[PSCustomObject]@{kind='worker';process=$valid}
$missing=[PSCustomObject]@{kind='worker';process=[PSCustomObject]@{}}
$malformed=[PSCustomObject]@{kind='worker';process=[PSCustomObject]@{
 CreationDate='PRIVATE_DO_NOT_EMIT';KernelModeTime='PRIVATE_DO_NOT_EMIT';UserModeTime=[UInt64]30000;ThreadCount='7'
}}
$future=[PSCustomObject]@{kind='worker';process=[PSCustomObject]@{
 CreationDate=[DateTime]::UtcNow.AddDays(1);KernelModeTime=[UInt64]0;UserModeTime=[UInt64]0;ThreadCount=[UInt32]0
}}
$partial=[PSCustomObject]@{kind='worker';process=[PSCustomObject]@{
 CreationDate=$valid.CreationDate;KernelModeTime=[UInt64]20000;ThreadCount=[UInt32]9
}}
$throwingNative=[PSCustomObject]@{ThreadCount=[Int32]2}
$throwingNative | Add-Member ScriptProperty CreationDate {throw 'PRIVATE_DO_NOT_EMIT'}
$throwingNative | Add-Member ScriptProperty KernelModeTime {throw 'PRIVATE_DO_NOT_EMIT'}
$throwing=[PSCustomObject]@{kind='worker';process=$throwingNative}
@(
 (Get-LocalNativeShellbagProcessDiagnostic -OwnedProcesses @($validEntry) -Kind worker),
 (Get-LocalNativeShellbagProcessDiagnostic -OwnedProcesses @() -Kind worker),
 (Get-LocalNativeShellbagProcessDiagnostic -OwnedProcesses @($validEntry,$validEntry) -Kind worker),
 (Get-LocalNativeShellbagProcessDiagnostic -OwnedProcesses @($validEntry) -Kind supervisor),
 (Get-LocalNativeShellbagProcessDiagnostic -OwnedProcesses @($missing) -Kind worker),
 (Get-LocalNativeShellbagProcessDiagnostic -OwnedProcesses @($malformed) -Kind worker),
 (Get-LocalNativeShellbagProcessDiagnostic -OwnedProcesses @($future) -Kind worker),
 (Get-LocalNativeShellbagProcessDiagnostic -OwnedProcesses @($partial) -Kind worker),
 (Get-LocalNativeShellbagProcessDiagnostic -OwnedProcesses @($throwing) -Kind worker)
) | ConvertTo-Json -Compress
'''
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-CommandWithArgs", audit, str(HELPER)],
                            capture_output=True, text=True, check=True, timeout=15)
    rows = json.loads(result.stdout)
    unknown = dict(age_wall_ms=None, cpu_cumulative_ms=None, thread_count=None)
    assert 9900 <= rows[0]["age_wall_ms"] < 15000
    assert rows[0]["cpu_cumulative_ms"] == 5
    assert rows[0]["thread_count"] == 7
    assert rows[1:6] == [unknown] * 5
    assert rows[6] == dict(age_wall_ms=None, cpu_cumulative_ms=0, thread_count=0)
    assert 9900 <= rows[7]["age_wall_ms"] < 15000
    assert rows[7]["cpu_cumulative_ms"] is None
    assert rows[7]["thread_count"] == 9
    assert rows[8] == dict(age_wall_ms=None, cpu_cumulative_ms=None, thread_count=2)
    assert "PRIVATE_DO_NOT_EMIT" not in result.stdout + result.stderr


@pytest.mark.parametrize("failure", ["timeout", "start", "poll", "summary"])
def test_failure_channel_keeps_primary_error_and_separate_phase_timings_without_extra_queries(failure):
    audit = r'''
. $args[0]
$source=${function:Invoke-LocalNativeShellbagScheduledWorker}.ToString()
$source=$source.Replace('[Security.Principal.WindowsIdentity]::GetCurrent().Name',"'PUBLIC\vagrant'")
$source=$source.Replace('$dispatchWatch.Elapsed.TotalSeconds -lt $dispatchSeconds','$dispatchWatch.Elapsed.TotalSeconds -lt 0')
Set-Item Function:Invoke-LocalNativeShellbagScheduledWorker ([scriptblock]::Create($source))
$script:failure=$args[1];$script:started=$false;$script:stopped=$false;$script:unregistered=$false;$script:queries=0
function Import-Module {}
function New-ScheduledTaskAction {}
function New-ScheduledTaskPrincipal {}
function New-ScheduledTaskSettingsSet {}
function Register-ScheduledTask {}
function Start-ScheduledTask {
 Start-Sleep -Milliseconds 50
 if($script:failure -ceq 'start'){throw [InvalidOperationException]::new('Native Shellbag scheduled task remained queued')}
 $script:started=$true
}
function Stop-ScheduledTask {$script:stopped=$true}
function Get-ScheduledTask {param($TaskName)
 if(-not $script:unregistered){[PSCustomObject]@{State=$(if($script:started -and -not $script:stopped){'Running'}else{'Ready'});TaskName=$TaskName}}
}
function Get-ScheduledTaskInfo {
 if($script:started -and $script:failure -ceq 'poll'){throw [InvalidOperationException]::new('Native Shellbag watchdog timed out before child completion')}
 [PSCustomObject]@{LastRunTime=[DateTime]$(if($script:started){'2026-01-01'}else{'1999-01-01'});LastTaskResult=[UInt32]$(if($script:started){267009}else{267011})}
}
function Get-CimInstance {
 $script:queries+=1
 if($script:queries -eq 1 -and $script:failure -notin @('start','poll')){
  foreach($kind in @('supervisor','worker')){
   $encoded=if($kind -ceq 'supervisor'){$SupervisorCommand}else{$WorkerCommand}
   [PSCustomObject]@{SessionId=1;CommandLine=('powershell.exe PRIVATE_DO_NOT_EMIT -EncodedCommand '+$encoded);
    CreationDate=[DateTime]::UtcNow.AddSeconds(-5);KernelModeTime=[UInt64]20000;UserModeTime=[UInt64]30000;
    ThreadCount=[UInt32]3;ProcessId=98765;ExecutablePath='PRIVATE_DO_NOT_EMIT'}
  }
 }
}
function Unregister-ScheduledTask {Start-Sleep -Milliseconds 20;$script:unregistered=$true}
if($script:failure -ceq 'summary'){function Get-LocalNativeShellbagProcessDiagnostic {throw 'PRIVATE_DO_NOT_EMIT'}}
try {
 Invoke-LocalNativeShellbagScheduledWorker -ChildScript 'exit 0' -ExpectedSessionId 1 | Out-Null
 throw 'Expected original failure'
} catch {
 $exception=$_.Exception
 while($exception.InnerException){$exception=$exception.InnerException}
 $code=Get-LocalNativeShellbagFailureCode -Message $exception.Message
 $type=$exception.GetType().FullName
}
[ordered]@{code=$code;error_type=$type;queries=$script:queries;unregistered=$script:unregistered;
 diagnostic=Get-LocalNativeShellbagDispatchDiagnostic}|ConvertTo-Json -Compress
'''
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-CommandWithArgs", audit,
                             str(HELPER), failure], capture_output=True, text=True, check=True, timeout=15)
    response = json.loads(result.stdout)
    diagnostic = response["diagnostic"]
    assert response["code"] == ("scheduled_task_queued_timeout" if failure == "start" else "child_watchdog_timeout")
    assert response["unregistered"] is True
    assert diagnostic["cleanup_code"] == "verified"
    assert diagnostic["start_scheduled_task_elapsed_ms"] >= 50
    assert diagnostic["cleanup_elapsed_ms"] >= 20
    assert response["queries"] == (2 if failure in {"start", "poll"} else 3)
    if failure == "start":
        assert diagnostic["parent_elapsed_ms"] is None
    else:
        assert diagnostic["parent_elapsed_ms"] >= 250
    if failure in {"start", "poll"}:
        assert response["error_type"] == "System.InvalidOperationException"
    if failure in {"timeout", "summary"}:
        assert diagnostic["process_query_succeeded"] is True
        assert diagnostic["supervisor_count"] == diagnostic["worker_count"] == 1
    for kind in ("supervisor", "worker"):
        if failure == "timeout":
            assert 4900 <= diagnostic[f"{kind}_age_wall_ms"] < 10000
            assert diagnostic[f"{kind}_cpu_cumulative_ms"] == 5
            assert diagnostic[f"{kind}_thread_count"] == 3
        else:
            assert diagnostic[f"{kind}_age_wall_ms"] is None
            assert diagnostic[f"{kind}_cpu_cumulative_ms"] is None
            assert diagnostic[f"{kind}_thread_count"] is None
    assert "PRIVATE_DO_NOT_EMIT" not in result.stdout + result.stderr


@pytest.mark.parametrize(("child_result", "cleanup_failure", "state", "changed", "baseline_result", "expected_code", "cleanup_code"), [
    (0, False, "Ready", True, 267011, "success", "verified"),
    (217, False, "Ready", True, 267011, "child_target_window_close_failed", "verified"),
    (217, True, "Ready", True, 267011, "child_target_window_close_failed", "unregister_failed"),
    (0, True, "Ready", True, 267011, "scheduled_task_cleanup_failed", "unregister_failed"),
    (0, False, "Ready", False, 267011, "scheduled_task_start_unobserved", "verified"),
    (0, False, "Ready", None, 267011, "scheduled_task_start_unobserved", "verified"),
    (267009, False, "Ready", True, 267011, "child_watchdog_timeout", "verified"),
    (267011, False, "Ready", True, 267011, "child_watchdog_timeout", "verified"),
    (267045, False, "Ready", True, 267011, "child_watchdog_timeout", "verified"),
    (0, False, "Running", True, 267011, "child_watchdog_timeout", "verified"),
    (267045, False, "Queued", True, 267011, "scheduled_task_queued_timeout", "verified"),
    (0, False, "Ready", True, 0, "scheduled_task_registration_not_fresh", "verified"),
])
def test_scheduler_uses_fresh_native_baseline_despite_backward_clock_and_keeps_cleanup_separate(
    tmp_path, child_result, cleanup_failure, state, changed, baseline_result, expected_code, cleanup_code
):
    audit = r'''
. $args[0]
$source=${function:Invoke-LocalNativeShellbagScheduledWorker}.ToString()
$identity='[Security.Principal.WindowsIdentity]::GetCurrent().Name'
if(($source.Split(@($identity),[StringSplitOptions]::None)).Count -ne 2){throw 'Identity mock boundary'}
$source=$source.Replace($identity,"'PUBLIC\vagrant'")
$deadline='$dispatchWatch.Elapsed.TotalSeconds -lt $dispatchSeconds'
if(($source.Split(@($deadline),[StringSplitOptions]::None)).Count -ne 2){throw 'Deadline mock boundary'}
$source=$source.Replace($deadline,'$dispatchWatch.Elapsed.TotalSeconds -lt 0')
Set-Item Function:Invoke-LocalNativeShellbagScheduledWorker ([scriptblock]::Create($source))
$script:unregistered=$false
$script:result=[UInt32]$args[1]
$script:cleanupFailure=$args[2] -ceq 'true'
$script:state=[string]$args[3]
$script:changed=$args[4] -ceq 'true'
$script:missingTime=$args[4] -ceq 'none'
$script:baselineResult=[UInt32]$args[5]
$script:started=$false
$script:stopped=$false
$script:baselineTime=[DateTime]'1999-11-30T00:00:00'
$script:nativeRunTime=(Get-Date).AddSeconds(-30)
$script:startCount=0
function Import-Module {}
function New-ScheduledTaskAction {}
function New-ScheduledTaskPrincipal {}
function New-ScheduledTaskSettingsSet {}
function Register-ScheduledTask {}
function Start-ScheduledTask {$script:started=$true;$script:startCount+=1}
function Stop-ScheduledTask {$script:stopped=$true}
function Get-ScheduledTask { param($TaskName)
 if(-not $script:unregistered){[PSCustomObject]@{State=$(if(-not $script:started -or $script:stopped){'Ready'}else{$script:state});TaskName=$TaskName}}
}
function Get-ScheduledTaskInfo {
 if(-not $script:started){return [PSCustomObject]@{LastRunTime=$script:baselineTime;LastTaskResult=$script:baselineResult}}
 [PSCustomObject]@{LastRunTime=$(if($script:missingTime){$null}elseif($script:changed){$script:nativeRunTime}else{$script:baselineTime});LastTaskResult=$script:result}
}
function Get-LocalNativeShellbagOwnedProcesses {}
function Unregister-ScheduledTask {
 if($script:cleanupFailure){throw 'PRIVATE_DO_NOT_EMIT'}
 $script:unregistered=$true
}
try {
 $value=Invoke-LocalNativeShellbagScheduledWorker -ChildScript 'exit 0' -ExpectedSessionId 1
 $code='success'
} catch {
 $exception=$_.Exception
 while($exception.InnerException){$exception=$exception.InnerException}
 $code=Get-LocalNativeShellbagFailureCode -Message $exception.Message
}
[ordered]@{code=$code;start_count=$script:startCount;old_wallclock_predicate=($script:nativeRunTime -ge (Get-Date).AddSeconds(-2));diagnostic=Get-LocalNativeShellbagDispatchDiagnostic}|ConvertTo-Json -Compress
'''
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-CommandWithArgs", audit, str(HELPER),
                             str(child_result), str(cleanup_failure).lower(), state, str(changed).lower(), str(baseline_result)],
                            capture_output=True, text=True, check=True, timeout=15)
    response = json.loads(result.stdout)
    assert response["code"] == expected_code, result.stderr
    diagnostic = response["diagnostic"]
    assert diagnostic["cleanup_code"] == cleanup_code
    fresh = baseline_result == 267011
    assert diagnostic["fresh_registration_verified"] is fresh
    assert response["start_count"] == int(fresh)
    assert response["old_wallclock_predicate"] is False
    assert diagnostic["last_task_result"] == (child_result if fresh else None)
    assert diagnostic["task_state"] == (state if fresh else "unobserved")
    assert diagnostic["ran_this_dispatch"] is (fresh and changed is True)
    if fresh:
        assert diagnostic["supervisor_count"] == diagnostic["worker_count"] == 0
    assert "PRIVATE_DO_NOT_EMIT" not in result.stdout + result.stderr


def test_supervisor_early_clock_and_normal_host_exit_follow_owned_child_cleanup(tmp_path):
    script = build_watchdog(tmp_path, "exit 0").read_text()
    assert script.startswith("$watch = [Diagnostics.Stopwatch]::StartNew()")
    assert script.count("$watch = [Diagnostics.Stopwatch]::StartNew()") == 1
    assert script.rstrip().endswith("exit $result")
    assert "[Environment]::Exit" not in script
    assert script.index("$worker.WaitForExit(2000)") < script.rindex("exit $result")


def test_new_visit_clears_previous_dispatch_before_any_native_operation(tmp_path):
    audit = r'''
. $args[0]
$script:LocalNativeShellbagDispatchDiagnostic=@{
 task_state='Ready';ran_this_dispatch=$true;last_task_result=[UInt32]0;
 cleanup_code='verified';elapsed_ms=[Int64]111;supervisor_count=[Int32]0;worker_count=[Int32]0
}
try { New-LocalNativeShellbagReceipt -Target $args[1] | Out-Null } catch {}
Get-LocalNativeShellbagDispatchDiagnostic | ConvertTo-Json -Compress
'''
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-CommandWithArgs", audit,
                             str(HELPER), str(tmp_path / "does-not-exist")],
                            capture_output=True, text=True, check=True, timeout=15)
    diagnostic = json.loads(result.stdout)
    assert diagnostic["task_state"] == "unobserved"
    assert diagnostic["last_task_result"] is None
    assert diagnostic["parent_elapsed_ms"] is None
    assert diagnostic["cleanup_code"] == "unobserved"
    assert diagnostic["ran_this_dispatch"] is False


def test_fallback_cleanup_pins_native_handle_before_identity_check_and_kill():
    source = HELPER.read_text()
    cleanup = source.split("$process = [Diagnostics.Process]::GetProcessById", 1)[1]
    pin = cleanup.index("$pinnedHandle = $process.Handle")
    identity = cleanup.index("$process.StartTime.ToUniversalTime()")
    kill = cleanup.index("$process.Kill()")
    dispose = cleanup.index("$process.Dispose()")
    assert pin < identity < kill < dispose


def test_packaged_shellbag_asset_matches_plain_helper():
    asset = HELPER.with_name(HELPER.name + ".gz.b64")
    assert gzip.decompress(base64.b64decode(asset.read_bytes().strip(), validate=True)) == HELPER.read_bytes()
