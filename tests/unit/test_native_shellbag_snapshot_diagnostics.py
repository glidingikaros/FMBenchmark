from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'src/fmb/generation/ansible/roles/manipulation/files/native_shellbag.ps1'
TASK = ROOT / 'src/fmb/generation/ansible/roles/manipulation/tasks/shellbag_path_residue_01.yml'
PWSH = shutil.which('pwsh')
pytestmark = pytest.mark.skipif(PWSH is None, reason='PowerShell is not installed')
LIMITS = {'max_elapsed_ms': 2000, 'max_node_count': 4096, 'max_depth': 64,
              'max_value_count': 4096, 'max_value_bytes': 16777216}


def run(script: str, *args: str) -> object:
    result = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-CommandWithArgs',
                             '. $args[0]\n' + script, str(HELPER), *args],
                            text=True, capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert not result.stderr.strip(), result.stderr
    assert 'PRIVATE_DO_NOT_EMIT' not in result.stdout
    return json.loads(result.stdout)


REGISTRY_DOUBLE = r'''
Add-Type -TypeDefinition @'
using System;
using System.Linq;
using Microsoft.Win32;
public class PublicClock {
 public static string Mode;
 public static int Calls;
 public long ElapsedMilliseconds { get {
  Calls++;
  return Mode=="entry_time" || ((Mode=="value_time" || Mode=="subkey_time") && Calls>=2) ? 2001 : 0;
 } }
}
public class PublicKey {
 public int Depth;
 public PublicKey(int depth) { Depth=depth; }
 public string[] GetValueNames() {
  if(PublicClock.Mode=="value_count") return Enumerable.Range(0,4097).Select(i=>i.ToString()).ToArray();
  if(PublicClock.Mode=="mru_bytes") return new[]{"MRUListEx"};
  if(PublicClock.Mode=="numeric_bytes" || PublicClock.Mode=="value_time") return new[]{"0"};
  return new string[0];
 }
 public RegistryValueKind GetValueKind(string name) { return RegistryValueKind.Binary; }
 public object GetValue(string name, object fallback, RegistryValueOptions options) {
  return new byte[16777217];
 }
 public string[] GetSubKeyNames() {
  if(PublicClock.Mode=="projected") return Enumerable.Repeat("PRIVATE_DO_NOT_EMIT",4097).ToArray();
  if(PublicClock.Mode=="depth" && Depth<65) return new[]{"PRIVATE_DO_NOT_EMIT"};
  return new string[0];
 }
 public PublicKey OpenSubKey(string name,bool write) { return new PublicKey(Depth+1); }
 public void Dispose() {}
}
'@
[PublicClock]::Mode=$args[1]
$source=${function:Get-LocalNativeBagMruSnapshot}.ToString()
$source=$source.Replace('[Microsoft.Win32.RegistryKey]','[Object]')
$source=$source.Replace('[Diagnostics.Stopwatch]::StartNew()','[PublicClock]::new()')
$pattern='\[Microsoft.Win32.Registry\]::CurrentUser.OpenSubKey\(\s*\$rootPath,\s*\$false\s*\)'
if([regex]::Matches($source,$pattern).Count -ne 1){throw 'Registry double boundary'}
$source=[regex]::Replace($source,$pattern,'[PublicKey]::new(0)')
if($args[1] -ceq 'nodes') {
 $needle='$nodes = [Collections.Generic.List[Object]]::new()'
 if($source.Split(@($needle),[StringSplitOptions]::None).Count -ne 2){throw 'Node double boundary'}
 $source=$source.Replace($needle,$needle+'; foreach($i in 1..4096){$nodes.Add($null)}')
}
Set-Item Function:Get-LocalNativeBagMruSnapshot ([scriptblock]::Create($source))
'''


@pytest.mark.parametrize(('mode', 'dimension', 'expected'), [
    ('entry_time', 'elapsed', {'elapsed_ms':2001, 'node_count':0, 'depth':0, 'value_count':None}),
    ('value_time', 'elapsed', {'elapsed_ms':2001, 'node_count':0, 'value_count':1}),
    ('subkey_time', 'elapsed', {'elapsed_ms':2001, 'node_count':1, 'child_count':0, 'projected_node_count':1}),
    ('nodes', 'node_count', {'node_count':4096, 'depth':0}),
    ('depth', 'depth', {'depth':65, 'node_count':65}),
    ('value_count', 'value_count', {'value_count':4097, 'node_count':0}),
    ('numeric_bytes', 'value_bytes', {'value_bytes':16777217, 'value_count':1}),
    ('mru_bytes', 'value_bytes', {'value_bytes':16777217, 'value_count':1}),
    ('projected', 'projected_node_count', {'child_count':4097, 'projected_node_count':4098, 'node_count':1}),
])
def test_actual_snapshot_resource_guards_emit_typed_dimension_without_private_names(mode, dimension, expected):
    result = run(REGISTRY_DOUBLE + r'''
$script:LocalNativeBagMruSnapshotPhase='pre_baseline'
$code='success'
try {Get-LocalNativeBagMruSnapshot -Target 'PRIVATE_DO_NOT_EMIT'|Out-Null}
catch {$code=Get-LocalNativeShellbagFailureCode -Message $_.Exception.Message}
[ordered]@{code=$code;diagnostic=Get-LocalNativeBagMruSnapshotDiagnostic}|ConvertTo-Json -Depth 5 -Compress
''', mode)
    assert result['code'] == 'bagmru_snapshot_resource_limit'
    diagnostic = result['diagnostic']
    assert diagnostic['phase'] == 'pre_baseline'
    assert diagnostic['exceeded_dimensions'] == [dimension]
    assert diagnostic['limits'] == LIMITS
    for key, value in expected.items():
        assert diagnostic[key] == value


def test_snapshot_success_resets_prior_failure_and_preserves_canonical_snapshot():
    result = run(REGISTRY_DOUBLE + r'''
$script:LocalNativeBagMruSnapshotDiagnostic=@{phase='delta';exceeded_dimensions=@('elapsed');elapsed_ms=[Int64]2001}
$snapshot=Get-LocalNativeBagMruSnapshot -Target 'PRIVATE_DO_NOT_EMIT'
[ordered]@{snapshot=$snapshot;diagnostic=Get-LocalNativeBagMruSnapshotDiagnostic}|ConvertTo-Json -Depth 7 -Compress
''', 'empty')
    nodes = [{'key_path':'BagMRU', 'numeric_values':[], 'mrulistex_hex':None}]
    assert result['snapshot'] == {'nodes':nodes, 'canonical':json.dumps(nodes, separators=(',',':'))}
    diagnostic = result['diagnostic']
    assert diagnostic['phase'] == 'unobserved'
    assert diagnostic['exceeded_dimensions'] == []
    assert diagnostic['elapsed_ms'] is None


def test_snapshot_getter_drops_unknown_names_keys_types_and_stale_receipt_data():
    result = run(r'''
$script:LocalNativeBagMruSnapshotDiagnostic=@{
 phase='PRIVATE_DO_NOT_EMIT';exceeded_dimensions=@('PRIVATE_DO_NOT_EMIT','elapsed','elapsed');
 elapsed_ms='2001';node_count=[Int64]9;depth=[Int32]-1;value_count='4';value_bytes=[Int64]17;
 child_count=[Int32]3;projected_node_count='1';secret='PRIVATE_DO_NOT_EMIT';limits='PRIVATE_DO_NOT_EMIT'
}
$invalid=Get-LocalNativeBagMruSnapshotDiagnostic
function Test-Path {return $false}
try {New-LocalNativeShellbagReceipt -Target 'PRIVATE_DO_NOT_EMIT'|Out-Null}catch{}
@($invalid,(Get-LocalNativeBagMruSnapshotDiagnostic))|ConvertTo-Json -Depth 5 -Compress
''')
    invalid, reset = result
    assert invalid == {'phase': 'unobserved', 'exceeded_dimensions': ['elapsed'], 'elapsed_ms': None,
                           'node_count': None, 'depth': None, 'value_count': None, 'value_bytes': 17,
                           'child_count': 3, 'projected_node_count': None, 'limits': LIMITS}
    assert reset == {'phase': 'unobserved', 'exceeded_dimensions': [], 'elapsed_ms': None,
                         'node_count': None, 'depth': None, 'value_count': None, 'value_bytes': None,
                         'child_count': None, 'projected_node_count': None, 'limits': LIMITS}


@pytest.mark.parametrize('phase', ['pre_baseline', 'delta', 'post_stability', 'success'])
def test_receipt_phases_and_success_contract_stay_separate(phase):
    result = run(r'''
$script:requestedPhase=$args[1]
function Test-Path {return $true}
function Get-CimInstance {return @()}
function Test-LocalInteractiveVagrantExplorer {return $true}
function Get-LocalOwnedInteractiveExplorerSessionIds {return @(1)}
function Start-Sleep {}
function PublicSnapshot {
 if($script:LocalNativeBagMruSnapshotPhase -ceq $script:requestedPhase){
  $script:LocalNativeBagMruSnapshotDiagnostic=@{phase=$script:LocalNativeBagMruSnapshotPhase;exceeded_dimensions=@('elapsed');elapsed_ms=[Int64]2001}
  throw 'BagMRU snapshot resource boundary exceeded'
 }
 return [pscustomobject]@{}
}
function Get-LocalStableNativeBagMruSnapshot {PublicSnapshot}
function Get-LocalNativeBagMruSnapshot {PublicSnapshot}
function Invoke-LocalInteractiveShellExplore {
 [pscustomobject]@{scheduled_task_completed=$true;scheduled_task_unregistered=$true;exact_target_window_matched=$true;exact_target_window_closed=$true}
}
function Get-LocalNativeBagMruDelta {
 [pscustomobject]@{qualifying_key_count=2;changed_numeric_value_count=3;changed_mrulistex_count=2}
}
$receipt=$null;$code='success'
try {$receipt=New-LocalNativeShellbagReceipt -Target 'PRIVATE_DO_NOT_EMIT'}
catch {$code=Get-LocalNativeShellbagFailureCode -Message $_.Exception.Message}
[ordered]@{code=$code;receipt=$receipt;diagnostic=Get-LocalNativeBagMruSnapshotDiagnostic}|ConvertTo-Json -Depth 6 -Compress
''', phase)
    if phase != 'success':
        assert result['code'] == 'bagmru_snapshot_resource_limit'
        assert result['receipt'] is None
        assert result['diagnostic']['phase'] == phase
    else:
        expected = {key:True for key in (
            'interactive_vagrant_explorer_verified','stable_pre_snapshots_verified',
            'native_bagmru_numeric_binary_verified','native_mrulistex_structure_verified',
            'custom_string_hint_absent','scheduled_task_completed','scheduled_task_unregistered',
            'exact_target_window_matched','exact_target_window_closed')}
        expected.update(changed_key_count=2,changed_numeric_value_count=3,changed_mrulistex_count=2)
        timing = {key: result['receipt'].pop(key) for key in ('visit_elapsed_ms', 'explore_elapsed_ms', 'dispatch_elapsed_ms', 'snapshot_count')}
        assert all(isinstance(value, int) and value >= 0 for value in timing.values())
        assert timing['explore_elapsed_ms'] <= timing['visit_elapsed_ms']
        assert result['receipt'] == expected
        assert result['code'] == 'success'


def test_public_snapshot_failure_field_uses_only_allowlisted_getter():
    tasks = yaml.safe_load(TASK.read_text())
    source = tasks[0]['ansible.windows.win_shell']
    assert tasks[0]['no_log'] is True
    assert '$snapshotDiagnostic = Get-LocalNativeBagMruSnapshotDiagnostic' in source
    assert 'snapshot_diagnostic = $snapshotDiagnostic' in source
    assert '$script:LocalNativeBagMruSnapshotDiagnostic' not in source
    assert 'snapshot_diagnostic' in tasks[1]['ansible.builtin.assert']['fail_msg']
