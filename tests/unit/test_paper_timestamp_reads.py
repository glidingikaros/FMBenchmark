import hashlib
import json
from pathlib import Path
import subprocess

import pytest

pytestmark = pytest.mark.pwsh

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "src/fmb/generation/ansible/roles/manipulation/files/pilot_challenge.ps1"


def run_powershell(tmp_path, source, target):
    script = tmp_path / "observer.ps1"
    script.write_text(source)
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), str(target)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not result.stderr.strip(), result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("legacy_order", [True, False])
def test_receipt_hash_read_cannot_shift_the_base_of_access_only_delta(
    tmp_path, legacy_order
):
    source = HELPER.read_text()
    observer = source[
        source.index("function Read-FactualState") : source.index(
            "function Write-FactualBmp"
        )
    ]
    if legacy_order:
        observer = observer.replace(
            "[FactualFileInfo]::Hash($Path)",
            "(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()",
        )
    target = tmp_path / "public-control.txt"
    target.write_text("Working document.")
    prefix = r"""$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
public static class FactualFileInfo {
  public struct Basic { public long Creation, Access, Write, Change; }
  public static long Access=134339040000000007;
  public static Basic Times(string p) { return new Basic {Creation=Access,Write=Access,Change=Access,Access=Access}; }
  public static string Identity(string p) { return "12345678:0001000000000042"; }
  public static string Hash(string p) { return new string('a',64); }
  public static void Set(string p,Basic t) { Access=t.Access; }
}
'@
function Get-FileHash {
  param([string]$LiteralPath,[string]$Algorithm)
  [FactualFileInfo]::Access += [long]6002014958
  return @{Hash=('a'*64)}
}
"""
    suffix = r"""
$before=Read-FactualState $args[0]
$t=[FactualFileInfo]::Times($args[0]); $t.Access += [long]-864000000000
[FactualFileInfo]::Set($args[0],$t)
$after=Read-FactualState $args[0]
@{delta=($after.access_filetime-$before.access_filetime);hash_unchanged=($before.sha256 -ceq $after.sha256)} | ConvertTo-Json -Compress
"""
    result = run_powershell(tmp_path, prefix + observer + suffix, target)
    assert result["hash_unchanged"] is True
    assert result["delta"] == (-857997985042 if legacy_order else -864000000000)


@pytest.mark.parametrize("reject_suppression", [False, True])
def test_actual_hash_method_sets_handle_scoped_suppression_before_reading(
    tmp_path, reject_suppression
):
    source = (
        HELPER.read_text()
        .split("Add-Type -TypeDefinition @'\n", 1)[1]
        .split("\n'@", 1)[0]
    )
    create = """[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFile(string p,uint access,uint share,IntPtr sec,uint disposition,uint flags,IntPtr template);"""
    replacement = """public static uint RequestedAccess, Share, Disposition, Flags;
  public static long AccessSentinel;
  public static bool Suppressed;
  public static System.IO.FileStream Backing;
  public static SafeFileHandle Opened;
  static SafeFileHandle CreateFile(string p,uint access,uint share,IntPtr sec,uint disposition,uint flags,IntPtr template) {
    RequestedAccess=access;Share=share;Disposition=disposition;Flags=flags;
    Backing=System.IO.File.OpenRead(p);Opened=Backing.SafeFileHandle;return Opened;
  }"""
    setter = '[DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileTime(SafeFileHandle h,IntPtr creation,ref long access,IntPtr write);'
    double = """static bool SetFileTime(SafeFileHandle h,IntPtr creation,ref long access,IntPtr write) {
    if(h!=Opened || Backing.Position!=0 || creation!=IntPtr.Zero || write!=IntPtr.Zero) throw new InvalidOperationException("Observer changed other times or read before suppression");
    AccessSentinel=access;Suppressed=true;return REPLY;
  }""".replace("REPLY", "false" if reject_suppression else "true")
    assert source.count(create) == source.count(setter) == 1
    source = source.replace(create, replacement).replace(setter, double)
    target = tmp_path / "public-bytes.bin"
    target.write_bytes(bytes(range(256)) * 64)
    script = (
        "$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n"
        + source
        + "\n'@\n"
        + r"""
$hash=$null;$failed=$false
try { $hash=[FactualFileInfo]::Hash($args[0]) } catch { $failed=$true }
finally { if($null -ne [FactualFileInfo]::Backing){[FactualFileInfo]::Backing.Dispose()} }
@{hash=$hash;failed=$failed;suppressed=[FactualFileInfo]::Suppressed;sentinel=[FactualFileInfo]::AccessSentinel;
  access=[FactualFileInfo]::RequestedAccess;share=[FactualFileInfo]::Share;disposition=[FactualFileInfo]::Disposition;flags=[FactualFileInfo]::Flags;
  handle_closed=[FactualFileInfo]::Opened.IsClosed} | ConvertTo-Json -Compress
"""
    )
    result = run_powershell(tmp_path, script, target)
    assert result["failed"] is reject_suppression
    assert result["suppressed"] and result["handle_closed"]
    assert (
        result["sentinel"],
        result["access"],
        result["share"],
        result["disposition"],
    ) == (-1, 0x80000100, 7, 3)
    assert result["flags"] == 0x02000000
    assert result["hash"] == (
        None if reject_suppression else hashlib.sha256(target.read_bytes()).hexdigest()
    )
