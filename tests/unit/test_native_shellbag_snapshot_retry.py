from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'src/fmb/generation/ansible/roles/manipulation/files/native_shellbag.ps1'
PWSH = shutil.which('pwsh')
pytestmark = pytest.mark.skipif(not PWSH, reason='PowerShell required')


def run(script: str, *args: str) -> object:
    result = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-CommandWithArgs',
                             '. $args[0]\n' + script, str(HELPER), *args],
                            text=True, capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert not result.stderr.strip(), result.stderr
    assert 'PRIVATE_DO_NOT_EMIT' not in result.stdout
    return json.loads(result.stdout)


DIAGNOSTIC = r'''
function New-PublicElapsedDiagnostic {
 return @{
  phase=$script:LocalNativeBagMruSnapshotPhase;exceeded_dimensions=[String[]]@('elapsed');
  elapsed_ms=[Int64]2228;node_count=[Int32]1;depth=[Int32]0;value_count=[Int32]2;
  value_bytes=[Int64]173;child_count=[Int32]0;projected_node_count=[Int32]1
 }
}
'''


def test_raw_classifier_rejects_mixed_unknown_invalid_stale_and_structural_metadata():
    rows = run(DIAGNOSTIC + r'''
$script:LocalNativeBagMruSnapshotPhase='pre_baseline'
$cases=[ordered]@{
 valid={};entry={$script:LocalNativeBagMruSnapshotDiagnostic.value_count=$null;$script:LocalNativeBagMruSnapshotDiagnostic.child_count=$null;$script:LocalNativeBagMruSnapshotDiagnostic.projected_node_count=$null};
 final_max_nodes={$script:LocalNativeBagMruSnapshotDiagnostic.node_count=[Int32]4096;$script:LocalNativeBagMruSnapshotDiagnostic.projected_node_count=[Int32]4096};
 missing={$script:LocalNativeBagMruSnapshotDiagnostic.Remove('depth')};
 extra={$script:LocalNativeBagMruSnapshotDiagnostic.secret='PRIVATE_DO_NOT_EMIT'};
 unknown_dimension={$script:LocalNativeBagMruSnapshotDiagnostic.exceeded_dimensions=[String[]]@('elapsed','PRIVATE_DO_NOT_EMIT')};
 mixed={$script:LocalNativeBagMruSnapshotDiagnostic.exceeded_dimensions=[String[]]@('elapsed','value_bytes')};
 duplicate={$script:LocalNativeBagMruSnapshotDiagnostic.exceeded_dimensions=[String[]]@('elapsed','elapsed')};
 empty={$script:LocalNativeBagMruSnapshotDiagnostic.exceeded_dimensions=[String[]]@()};
 scalar_dimension={$script:LocalNativeBagMruSnapshotDiagnostic.exceeded_dimensions='elapsed'};
 object_array={$script:LocalNativeBagMruSnapshotDiagnostic.exceeded_dimensions=[Object[]]@('elapsed')};
 case_dimension={$script:LocalNativeBagMruSnapshotDiagnostic.exceeded_dimensions=[String[]]@('Elapsed')};
 unobserved={$script:LocalNativeBagMruSnapshotDiagnostic.phase='unobserved'};
 stale={$script:LocalNativeBagMruSnapshotDiagnostic.phase='delta'};
 unknown_phase={$script:LocalNativeBagMruSnapshotDiagnostic.phase='PRIVATE_DO_NOT_EMIT'};
 unknown_key_case={$script:LocalNativeBagMruSnapshotDiagnostic.Remove('depth');$script:LocalNativeBagMruSnapshotDiagnostic['DEPTH']=[Int32]0};
 elapsed_string={$script:LocalNativeBagMruSnapshotDiagnostic.elapsed_ms='2228'};
 elapsed_int32={$script:LocalNativeBagMruSnapshotDiagnostic.elapsed_ms=[Int32]2228};
 elapsed_not_exceeded={$script:LocalNativeBagMruSnapshotDiagnostic.elapsed_ms=[Int64]2000};
 node_int64={$script:LocalNativeBagMruSnapshotDiagnostic.node_count=[Int64]1};
 node_negative={$script:LocalNativeBagMruSnapshotDiagnostic.node_count=[Int32]-1};
 node_exceeded={$script:LocalNativeBagMruSnapshotDiagnostic.node_count=[Int32]4097};
 entry_max_nodes={$script:LocalNativeBagMruSnapshotDiagnostic.node_count=[Int32]4096;$script:LocalNativeBagMruSnapshotDiagnostic.child_count=$null;$script:LocalNativeBagMruSnapshotDiagnostic.projected_node_count=$null};
 depth_exceeded={$script:LocalNativeBagMruSnapshotDiagnostic.depth=[Int32]65};
 bytes_exceeded={$script:LocalNativeBagMruSnapshotDiagnostic.value_bytes=[Int64]16777217};
 bytes_int32={$script:LocalNativeBagMruSnapshotDiagnostic.value_bytes=[Int32]173};
 value_exceeded={$script:LocalNativeBagMruSnapshotDiagnostic.value_count=[Int32]4097};
 child_exceeded={$script:LocalNativeBagMruSnapshotDiagnostic.child_count=[Int32]4097};
 projected_exceeded={$script:LocalNativeBagMruSnapshotDiagnostic.projected_node_count=[Int32]4097};
 projected_mismatch={$script:LocalNativeBagMruSnapshotDiagnostic.projected_node_count=[Int32]2};
 projected_missing={$script:LocalNativeBagMruSnapshotDiagnostic.projected_node_count=$null};
 child_missing={$script:LocalNativeBagMruSnapshotDiagnostic.child_count=$null};
 value_missing_at_children={$script:LocalNativeBagMruSnapshotDiagnostic.value_count=$null};
 value_string={$script:LocalNativeBagMruSnapshotDiagnostic.value_count='2'};
 child_negative={$script:LocalNativeBagMruSnapshotDiagnostic.child_count=[Int32]-1};
 raw_object={$script:LocalNativeBagMruSnapshotDiagnostic=[pscustomobject]$script:LocalNativeBagMruSnapshotDiagnostic};
 raw_null={$script:LocalNativeBagMruSnapshotDiagnostic=$null}
}
$rows=@(foreach($case in $cases.GetEnumerator()){
 $script:LocalNativeBagMruSnapshotDiagnostic=New-PublicElapsedDiagnostic
 & $case.Value
 $message='BagMRU snapshot resource boundary exceeded'
 [ordered]@{name=$case.Key;eligible=Test-LocalElapsedOnlyBagMruSnapshotFailure;
 permanent=Test-LocalPermanentBagMruSnapshotFailure -Message $message;
 transient=Test-LocalTransientBagMruSnapshotFailure -Message $message}
})
$rows|ConvertTo-Json -Compress
''')
    assert len(rows) == 37
    for row in rows:
        eligible = row['name'] in {'valid', 'entry', 'final_max_nodes'}
        assert row == {'name': row['name'], 'eligible': eligible,
                           'permanent': not eligible, 'transient': eligible}


@pytest.mark.parametrize(('events','expected_calls','expected_sleeps','code'), [
    ('A,A,A,A,A,A', 6, 5, 'success'),
    ('elapsed,A,A,A,A,A,A', 7, 6, 'success'),
    ('A,A,A,A,A,elapsed,A,A,A,A,A,A', 12, 11, 'success'),
    ('A,A,A,A,A,B,B,B,B,B,B', 11, 10, 'success'),
    ('A,A,A,A,A,transient,A,A,A,A,A,A', 12, 11, 'success'),
    ('elapsed', 20, 20, 'bagmru_quiescence_timeout'),
    ('A', 6, 5, 'success'),
    ('A,A,structural', 3, 2, 'bagmru_snapshot_resource_limit'),
    ('A,A,invalid', 3, 2, 'bagmru_snapshot_resource_limit'),
    ('unknown', 1, 0, 'unrecognized_native_failure'),
])
def test_actual_stability_requires_six_complete_consecutive_snapshots_and_twenty_attempt_cap(events, expected_calls, expected_sleeps, code):
    result = run(DIAGNOSTIC + r'''
$script:events=$args[1].Split(',');$script:calls=0;$script:sleeps=0
$script:LocalNativeBagMruSnapshotPhase='pre_baseline'
function Start-Sleep {$script:sleeps++}
function Get-LocalNativeBagMruSnapshot {
 $event=$script:events[[Math]::Min($script:calls,$script:events.Count-1)]
 $script:calls++;$script:LocalNativeBagMruSnapshotDiagnostic=$null
 if($event -in @('elapsed','structural','invalid')){
  $script:LocalNativeBagMruSnapshotDiagnostic=New-PublicElapsedDiagnostic
  if($event -eq 'structural'){$script:LocalNativeBagMruSnapshotDiagnostic.exceeded_dimensions=[String[]]@('elapsed','value_count')}
  if($event -eq 'invalid'){$script:LocalNativeBagMruSnapshotDiagnostic.elapsed_ms='2228'}
  throw 'BagMRU snapshot resource boundary exceeded'
 }
 if($event -eq 'transient'){throw 'Unable to open a BagMRU subkey'}
 if($event -eq 'unknown'){throw 'PRIVATE_DO_NOT_EMIT'}
 return [pscustomobject]@{canonical=$event;ordinal=$script:calls}
}
$snapshot=$null;$code='success'
try{$snapshot=Get-LocalStableNativeBagMruSnapshot -Target 'PRIVATE_DO_NOT_EMIT'}
catch{$code=Get-LocalNativeShellbagFailureCode -Message $_.Exception.Message}
[ordered]@{code=$code;calls=$script:calls;sleeps=$script:sleeps;snapshot=$snapshot}|ConvertTo-Json -Compress
''', events)
    assert result['code'] == code
    assert result['calls'] == expected_calls
    assert result['sleeps'] == expected_sleeps
    if code == 'success':
        assert result['snapshot']['ordinal'] == expected_calls
    else:
        assert result['snapshot'] is None


@pytest.mark.parametrize(('mode','code','snapshot_calls','delta_calls'), [
    ('elapsed_then_success','success',2,2),
    ('no_delta_elapsed_then_success','success',3,3),
    ('elapsed_until_deadline','bagmru_delta_missing',2,0),
    ('structural','bagmru_snapshot_resource_limit',1,0),
    ('invalid','bagmru_snapshot_resource_limit',1,0),
])
def test_actual_delta_loop_discards_failed_snapshot_and_never_reuses_prior_delta(mode, code, snapshot_calls, delta_calls):
    result = run(DIAGNOSTIC + r'''
Add-Type -TypeDefinition @'
public class PublicDeltaClock {
 public static int Reads;
 public System.TimeSpan Elapsed { get { Reads++; return System.TimeSpan.FromSeconds(Reads>1?20:0); } }
}
'@
$receiptBody=${function:New-LocalNativeShellbagReceipt}.ToString()
$receiptBody=$receiptBody.Replace('[Diagnostics.Stopwatch]::StartNew()','[PublicDeltaClock]::new()')
Set-Item Function:New-LocalNativeShellbagReceipt ([scriptblock]::Create($receiptBody))
$script:mode=$args[1];$script:snapshots=0;$script:deltas=0;$script:stableCalls=0;$script:afterOrdinals=@()
function Test-Path {return $true}
function Get-CimInstance {return @()}
function Test-LocalInteractiveVagrantExplorer {return $true}
function Get-LocalOwnedInteractiveExplorerSessionIds {return @(1)}
function Start-Sleep {}
function Get-LocalStableNativeBagMruSnapshot {
 $script:stableCalls++;return [pscustomobject]@{ordinal=100+$script:stableCalls}
}
function Invoke-LocalInteractiveShellExplore {
 [pscustomobject]@{scheduled_task_completed=$true;scheduled_task_unregistered=$true;exact_target_window_matched=$true;exact_target_window_closed=$true}
}
function Get-LocalNativeBagMruSnapshot {
 $script:snapshots++;$script:LocalNativeBagMruSnapshotDiagnostic=$null
 $fail=($script:mode -in @('structural','invalid','elapsed_until_deadline')) -or
  ($script:mode -eq 'elapsed_then_success' -and $script:snapshots -eq 1) -or
  ($script:mode -eq 'no_delta_elapsed_then_success' -and $script:snapshots -eq 2)
 if($fail){
  $script:LocalNativeBagMruSnapshotDiagnostic=New-PublicElapsedDiagnostic
  if($script:mode -eq 'structural'){$script:LocalNativeBagMruSnapshotDiagnostic.exceeded_dimensions=[String[]]@('elapsed','depth')}
  if($script:mode -eq 'invalid'){$script:LocalNativeBagMruSnapshotDiagnostic.extra='PRIVATE_DO_NOT_EMIT'}
  throw 'BagMRU snapshot resource boundary exceeded'
 }
 return [pscustomobject]@{ordinal=$script:snapshots}
}
function Get-LocalNativeBagMruDelta {
 param($Before,$After)
 $script:deltas++;$script:afterOrdinals+=@($After.ordinal)
 $qualifying=if($script:mode -eq 'no_delta_elapsed_then_success' -and $After.ordinal -eq 1){0}else{1}
 return [pscustomobject]@{qualifying_key_count=$qualifying;changed_numeric_value_count=1;changed_mrulistex_count=1}
}
if($script:mode -eq 'no_delta_elapsed_then_success'){
 $body=${function:New-LocalNativeShellbagReceipt}.ToString().Replace('[PublicDeltaClock]::new()','[Diagnostics.Stopwatch]::StartNew()')
 Set-Item Function:New-LocalNativeShellbagReceipt ([scriptblock]::Create($body))
}
$receipt=$null;$code='success'
try{$receipt=New-LocalNativeShellbagReceipt -Target 'PRIVATE_DO_NOT_EMIT'}
catch{$code=Get-LocalNativeShellbagFailureCode -Message $_.Exception.Message}
[ordered]@{code=$code;receipt=$receipt;snapshot_calls=$script:snapshots;delta_calls=$script:deltas;
 stable_calls=$script:stableCalls;after_ordinals=@($script:afterOrdinals)}|ConvertTo-Json -Depth 5 -Compress
''', mode)
    assert result['code'] == code
    assert result['snapshot_calls'] == snapshot_calls
    assert result['delta_calls'] == delta_calls
    if code == 'success':
        assert result['stable_calls'] == 2
        assert result['after_ordinals'] == ([1,3,102] if mode.startswith('no_delta') else [2,102])
        expected = {key:True for key in (
            'interactive_vagrant_explorer_verified','stable_pre_snapshots_verified',
            'native_bagmru_numeric_binary_verified','native_mrulistex_structure_verified',
            'custom_string_hint_absent','scheduled_task_completed','scheduled_task_unregistered',
            'exact_target_window_matched','exact_target_window_closed')}
        expected.update(changed_key_count=1,changed_numeric_value_count=1,changed_mrulistex_count=1)
        timing = {key: result['receipt'].pop(key) for key in ('visit_elapsed_ms', 'explore_elapsed_ms', 'dispatch_elapsed_ms', 'snapshot_count')}
        assert all(isinstance(value, int) and value >= 0 for value in timing.values())
        assert timing['explore_elapsed_ms'] <= timing['visit_elapsed_ms']
        assert result['receipt'] == expected
    else:
        assert result['receipt'] is None
        assert result['stable_calls'] == 1
        assert result['after_ordinals'] == []


def test_candidate_hex_output_retains_empty_single_lowercase_and_every_byte():
    result = run(r'''
$cases=@([byte[]]@(),[byte[]]@(0),[byte[]]@(255),[byte[]](0..255))
@(foreach($bytes in $cases){$actual=@(ConvertTo-LocalHex -Bytes $bytes);[ordered]@{count=$actual.Count;value=$actual[0]}})|ConvertTo-Json -Compress
''')
    assert result == [{'count': 1,'value': b.hex()} for b in (b'',b'\0',b'\xff',bytes(range(256)))]


def test_post_stability_exhaustion_withholds_success_after_verified_delta():
    result = run(DIAGNOSTIC + r'''
$script:snapshots=0;$script:deltas=0;$script:actions=0
function Test-Path {return $true}
function Get-CimInstance {return @()}
function Test-LocalInteractiveVagrantExplorer {return $true}
function Get-LocalOwnedInteractiveExplorerSessionIds {return @(1)}
function Start-Sleep {}
function Invoke-LocalInteractiveShellExplore {
 $script:actions++
 [pscustomobject]@{scheduled_task_completed=$true;scheduled_task_unregistered=$true;exact_target_window_matched=$true;exact_target_window_closed=$true}
}
function Get-LocalNativeBagMruSnapshot {
 $script:snapshots++;$script:LocalNativeBagMruSnapshotDiagnostic=$null
 if($script:LocalNativeBagMruSnapshotPhase -ceq 'post_stability'){
  $script:LocalNativeBagMruSnapshotDiagnostic=New-PublicElapsedDiagnostic
  throw 'BagMRU snapshot resource boundary exceeded'
 }
 return [pscustomobject]@{canonical=$script:LocalNativeBagMruSnapshotPhase}
}
function Get-LocalNativeBagMruDelta {
 $script:deltas++
 [pscustomobject]@{qualifying_key_count=1;changed_numeric_value_count=1;changed_mrulistex_count=1}
}
$receipt=$null;$code='success'
try{$receipt=New-LocalNativeShellbagReceipt -Target 'PRIVATE_DO_NOT_EMIT'}
catch{$code=Get-LocalNativeShellbagFailureCode -Message $_.Exception.Message}
[ordered]@{code=$code;receipt=$receipt;snapshots=$script:snapshots;deltas=$script:deltas;actions=$script:actions}|ConvertTo-Json -Compress
''')
    assert result == {'code': 'bagmru_quiescence_timeout','receipt': None,'snapshots': 27,'deltas': 1,'actions': 1}


def test_candidate_powershell_ast_and_unmodified_guard_caps():
    assert run(r'''
$tokens=$null;$errors=$null
$null=[Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
@($errors).Count|ConvertTo-Json -Compress
''') == 0
    text = HELPER.read_text()
    assert '$maxElapsedMilliseconds = [Int32](Get-LocalNativeShellbagVisitBudgets).snapshot_ms' in text
    assert '$maxNodeCount = 4096' in text
    assert '$maxDepth = 64' in text
    assert '$maxValueBytes = 16777216' in text
    assert 'foreach ($attempt in 1..20)' in text
    assert 'if ($stableIntervals -ge 5)' in text
    assert '$deltaWatch.Elapsed.TotalSeconds -lt 20' in text
