from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
TASK = ROOT / "src/fmb/generation/ansible/roles/manipulation/tasks/pilot_ntfs_allocation_01.yml"
PWSH = shutil.which("pwsh")
SENTINEL = "PRIVATE_DO_NOT_EMIT"


def task_body() -> str:
    return yaml.safe_load(TASK.read_text())[0]["ansible.windows.win_shell"]


def public_input(root: Path, case: str = "benign") -> dict:
    modes = ["ordinary"] * 2 + ["resident", "preallocation_request_then_close"]
    lengths = [4097, 4098] + [37, 4106]
    paths = [str(root / f"public-control-{index:02}.dat") for index in range(4)]
    return {
        "case": case,
        "expected_population_count": 4,
        "expected_operation_count": 1 if case == "positive" else 0,
        "population_paths": paths,
        "operation_refs": paths[:1] if case == "positive" else [],
        "storage_cases": [
            {"path": path, "storage_mode": mode, "logical_length": length}
            for path, mode, length in zip(paths, modes, lengths)
        ],
    }


def mock_prefix(payload: dict, failure: str = "none") -> str:
    config = base64.b64encode(json.dumps({"failure": failure, "path": payload["population_paths"][-1]}).encode()).decode()
    return r'''
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class LocalAllocationControl {
  public struct AllocationInfo { public long Size; }
  public struct StandardInfo {
    public long AllocationSize, EndOfFile;
    public uint NumberOfLinks;
    public bool DeletePending, Directory;
  }
  public static string Failure, Path;
  private static int reads;
  public static bool SetFileInformationByHandle(SafeFileHandle handle, int kind,
      ref AllocationInfo info, uint size) {
    if (Failure == "set_api_false") { Marshal.SetLastPInvokeError(5); return false; }
    return true;
  }
  public static bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind,
      out StandardInfo info, uint size) {
    reads++;
    info = new StandardInfo {AllocationSize=reads == 1 ? 65536 : 8192, EndOfFile=4106};
    if (Failure == "open_readback_size") info.AllocationSize=32768;
    if (Failure == "closed_open_throw" && reads == 1) File.Delete(Path);
    if (Failure == "closed_api_false" && reads == 2) {
      Marshal.SetLastPInvokeError(5); return false;
    }
    return true;
  }
}
'@
$config=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + "'" + config + "'" + r'''))|ConvertFrom-Json
[LocalAllocationControl]::Failure=$config.failure
[LocalAllocationControl]::Path=$config.path
$script:failure=$config.failure
function Add-Type {
  param([string]$TypeDefinition)
  if ($script:failure -eq 'compile_throw') { throw 'PRIVATE_DO_NOT_EMIT arbitrary compile details' }
}
function fsutil {
  if ($script:failure -eq 'sparse_range_throw' -and $args[1] -eq 'setrange') {
    throw 'PRIVATE_DO_NOT_EMIT arbitrary utility details'
  }
  $global:LASTEXITCODE=0
}
function compact { $global:LASTEXITCODE=0 }
function Get-Item {
  param([string]$LiteralPath, [switch]$Force)
  $actual=Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force
  $attributes=[IO.FileAttributes]::Normal
  if ($LiteralPath.EndsWith('public-control-10.dat')) { $attributes=[IO.FileAttributes]::SparseFile }
  if ($LiteralPath.EndsWith('public-control-11.dat')) { $attributes=[IO.FileAttributes]::Compressed }
  [pscustomobject]@{ Length=$actual.Length; Attributes=$attributes }
}
'''


def run_body(tmp_path: Path, payload: dict | str, *, failure: str = "none", body: str | None = None) -> dict:
    if not PWSH:
        pytest.skip("PowerShell is not installed")
    prefix = mock_prefix(payload, failure) if isinstance(payload, dict) else ""
    script = tmp_path / "execute.ps1"
    script.write_text(prefix + "\n" + (body or task_body()))
    result = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)],
        input=json.dumps(payload) if isinstance(payload, dict) else payload,
        text=True, capture_output=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert SENTINEL not in result.stdout + result.stderr
    assert not result.stderr.strip(), result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("case", ["benign", "positive"])
def test_allocation_success_keeps_exact_host_receipt_and_content(tmp_path, case):
    payload = public_input(tmp_path, case)
    for path in payload["population_paths"]:
        Path(path).write_text("Neutral generated record.")
    result = run_body(tmp_path, payload)
    refs = json.dumps(payload["operation_refs"], ensure_ascii=False, separators=(",", ":"))
    content = bytes((index * 37 + 19) % 251 for index in range(4106))
    assert result == {
        "scenario_id": "ntfs_allocation_01", "case": case,
        "operation_count": len(payload["operation_refs"]),
        "operation_refs_sha256": hashlib.sha256(("generation_operation_refs.v1\n" + refs).encode()).hexdigest(),
        "postcondition_verified": True, "population_count": 4,
        "prepared_modes": [item["storage_mode"] for item in payload["storage_cases"]],
        "preallocation_close_controls": [{
            "path": payload["population_paths"][-1], "requested_allocation_bytes": 65536,
            "open_allocation_bytes": 65536, "open_eof_bytes": 4106,
            "closed_allocation_bytes": 8192, "closed_eof_bytes": 4106,
            "content_sha256": hashlib.sha256(content).hexdigest(),
        }],
    }
    assert Path(payload["population_paths"][-1]).read_bytes() == content


@pytest.mark.parametrize(("failure", "stage", "code"), [
    ("compile_throw", "compile_native_interop", "unrecognized_native_failure"),
    ("set_api_false", "preallocation_set_api", "preallocation_api_failed"),
    ("open_readback_size", "preallocation_open_readback", "open_preallocation_readback_failed"),
    ("closed_api_false", "preallocation_closed_readback", "closed_preallocation_readback_failed"),
    pytest.param("closed_open_throw", "preallocation_closed_readback", "unrecognized_native_failure",
                 marks=pytest.mark.skipif(os.name == "nt", reason="the mock deletes an open file, which Windows forbids")),
])
def test_allocation_failure_is_single_safe_json_and_phase_values_are_current(tmp_path, failure, stage, code):
    payload = public_input(tmp_path)
    result = run_body(tmp_path, payload, failure=failure)
    assert set(result) == {"fmb_native_failure", "failure_stage", "error_type", "error_hresult",
                           "native_failure_code", "control_mode", "native_diagnostic"}
    assert result["fmb_native_failure"] is True
    assert result["failure_stage"] == stage
    assert result["native_failure_code"] == code
    assert isinstance(result["error_hresult"], int)
    assert str(tmp_path) not in json.dumps(result)
    diagnostic = result["native_diagnostic"]
    if failure in {"set_api_false", "closed_api_false"}:
        assert diagnostic["api_success"] is False
        assert diagnostic["last_win32_error"] == 5
        assert diagnostic["last_error_meaningful"] is True
        assert diagnostic["readback_valid"] is False
    elif failure == "open_readback_size":
        assert diagnostic["api_success"] is True
        assert diagnostic["readback_valid"] is True
        assert diagnostic["allocation_bytes"] == 32768
        assert diagnostic["end_of_file_bytes"] == 4106
        assert diagnostic["last_error_meaningful"] is False
    elif failure == "closed_open_throw":
        assert result["error_type"] == "System.IO.FileNotFoundException"
        assert diagnostic["last_api_stage"] == "not_called"
        assert diagnostic["api_success"] is None
        assert diagnostic["allocation_bytes"] is None
        assert diagnostic["end_of_file_bytes"] is None
        assert diagnostic["last_win32_error"] is None
        assert diagnostic["readback_valid"] is False
        assert diagnostic["open_allocation_bytes"] == 65536
    elif failure == "sparse_range_throw":
        assert result["control_mode"] == "sparse"
        assert diagnostic["command_exit_code"] is None
        assert diagnostic["api_success"] is None


def test_allocation_decode_and_file_errors_do_not_emit_input_or_paths(tmp_path):
    result = run_body(tmp_path, "{PRIVATE_DO_NOT_EMIT invalid JSON")
    assert result["failure_stage"] == "decode_input"
    assert result["native_failure_code"] == "unrecognized_native_failure"
    payload = public_input(tmp_path / SENTINEL)
    result = run_body(tmp_path, payload)
    assert result["failure_stage"] == "write_content"
    assert result["error_type"] == "System.IO.DirectoryNotFoundException"
    assert result["native_diagnostic"]["api_success"] is None


def test_allocation_failure_gate_precedes_truth_and_command_is_bounded():
    tasks = yaml.safe_load(TASK.read_text())
    assert tasks[0]["no_log"] is True
    assert "scenario_inputs.ntfs_allocation_01" in tasks[0]["args"]["stdin"]
    gate = tasks[1]["ansible.builtin.assert"]
    assert any("fmb_native_failure" in condition for condition in gate["that"])
    assert any("postcondition_verified | default(false) | bool" in condition for condition in gate["that"])
    assert tasks[2]["ansible.builtin.debug"]["msg"] == [
        "GROUND_TRUTH_BEGIN", "{{ allocation_receipt.stdout | trim }}", "GROUND_TRUTH_END",
    ]
    assert len(base64.b64encode(task_body().encode("utf-16le"))) + 2048 < 32767
