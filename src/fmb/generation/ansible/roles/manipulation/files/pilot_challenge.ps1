Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class FactualFileInfo {
  [StructLayout(LayoutKind.Sequential)] public struct Basic {
    public long Creation, Access, Write, Change; public uint Attributes;
  }
  [StructLayout(LayoutKind.Sequential)] public struct Info {
    public uint Attributes, C0,C1,A0,A1,W0,W1,Serial,SizeH,SizeL,Links,IndexH,IndexL;
  }
  [StructLayout(LayoutKind.Sequential)] public struct Standard {
    public long AllocationSize, EndOfFile; public uint Links;
    [MarshalAs(UnmanagedType.U1)] public bool DeletePending;
    [MarshalAs(UnmanagedType.U1)] public bool Directory;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFile(string p,uint access,uint share,IntPtr sec,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info v);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int kind,out Basic v,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int kind,ref Basic v,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileTime(SafeFileHandle h,IntPtr creation,ref long access,IntPtr write);
  [DllImport("kernel32.dll",EntryPoint="SetFileInformationByHandle",SetLastError=true)] static extern bool SetAllocation(SafeFileHandle h,int kind,ref long v,uint size);
  [DllImport("kernel32.dll",EntryPoint="GetFileInformationByHandleEx",SetLastError=true)] static extern bool GetStandard(SafeFileHandle h,int kind,out Standard v,uint size);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool CreateHardLink(string p,string existing,IntPtr reserved);
  static SafeFileHandle Open(string p) {
    var h=CreateFile(p,0x180,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero);
    if(h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error()); return h;
  }
  public static Basic Times(string p) { using(var h=Open(p)) { Basic v; if(!GetFileInformationByHandleEx(h,0,out v,(uint)Marshal.SizeOf(typeof(Basic)))) throw new Win32Exception(); return v; } }
  public static string Identity(string p) { using(var h=Open(p)) { Info v; if(!GetFileInformationByHandle(h,out v)) throw new Win32Exception(); return v.Serial.ToString("x8")+":"+(((ulong)v.IndexH<<32)|v.IndexL).ToString("x16"); } }
  public static string Hash(string p) {
    using(var h=CreateFile(p,0x80000100,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero)) {
      if(h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
      long noAccessUpdate=-1;
      if(!SetFileTime(h,IntPtr.Zero,ref noAccessUpdate,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
      using(var stream=new System.IO.FileStream(h,System.IO.FileAccess.Read))
      using(var hash=System.Security.Cryptography.SHA256.Create()) {
        return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
      }
    }
  }
  public static void Set(string p, Basic v) { using(var h=Open(p)) { if(!SetFileInformationByHandle(h,0,ref v,(uint)Marshal.SizeOf(typeof(Basic)))) throw new Win32Exception(Marshal.GetLastWin32Error()); } }
  public static long[] Allocate(string p,long bytes) { using(var h=CreateFile(p,0x40000180,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero)) {
    Standard v; if(h.IsInvalid || !SetAllocation(h,5,ref bytes,8) || !GetStandard(h,1,out v,24)) throw new Win32Exception(Marshal.GetLastWin32Error());
    if(v.AllocationSize<bytes) throw new InvalidOperationException("Preallocation not materialized");
    return new long[] {v.AllocationSize,v.EndOfFile};
  } }
}
'@
function Read-FactualState([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return @{exists=$false; path=$Path} }
  $t=[FactualFileInfo]::Times($Path)
  return @{exists=$true; path=$Path; file_reference=[FactualFileInfo]::Identity($Path);
    creation_filetime=$t.Creation; modified_filetime=$t.Write; change_filetime=$t.Change;
    sha256=$(if([IO.File]::Exists($Path)){[FactualFileInfo]::Hash($Path)}else{$null}); access_filetime=$t.Access; length=$(if([IO.File]::Exists($Path)){([IO.FileInfo]$Path).Length}else{$null})}
}
function Write-FactualBmp([string]$Path,[int]$Width,[int]$Height) {
  $stride=([int][Math]::Ceiling(($Width*3)/4.0))*4
  $size=54+$stride*$Height; $data=New-Object byte[] $size
  $data[0]=0x42; $data[1]=0x4d
  [BitConverter]::GetBytes([uint32]$size).CopyTo($data,2)
  [BitConverter]::GetBytes([uint32]54).CopyTo($data,10)
  [BitConverter]::GetBytes([uint32]40).CopyTo($data,14)
  [BitConverter]::GetBytes([int]$Width).CopyTo($data,18)
  [BitConverter]::GetBytes([int]$Height).CopyTo($data,22)
  [BitConverter]::GetBytes([uint16]1).CopyTo($data,26)
  [BitConverter]::GetBytes([uint16]24).CopyTo($data,28)
  [BitConverter]::GetBytes([uint32]($stride*$Height)).CopyTo($data,34)
  [IO.File]::WriteAllBytes($Path,$data)
}
function Write-FactualStream([string]$Path,[string]$Name,[byte[]]$Bytes) {
  Set-Content -LiteralPath $Path -Stream $Name -Encoding Byte -Value $Bytes
  [byte[]]$readback=Get-Content -LiteralPath $Path -Stream $Name -Encoding Byte -ReadCount 0
  $hasher=[Security.Cryptography.SHA256]::Create()
  try {
    $expected=[Convert]::ToBase64String($hasher.ComputeHash($Bytes))
    $hash=$hasher.ComputeHash($readback)
    if($readback.Length -ne $Bytes.Length -or [Convert]::ToBase64String($hash) -cne $expected){throw 'Native named-stream readback differs'}
    return @{stream_name=$Name; length=$readback.Length; sha256=([BitConverter]::ToString($hash)).Replace('-','').ToLowerInvariant()}
  } finally {$hasher.Dispose()}
}
$root=[string]$plan.public_manifest.root
if($plan.profile -cne 'pilot_min.v1'){throw 'Unsupported pilot profile'}
if($pilotStage -ceq 'materialize') {
  if(Test-Path -LiteralPath $root){throw 'Pilot population already exists'}
  New-Item -ItemType Directory -Path $root | Out-Null
  $initial=[Collections.Generic.List[object]]::new()
  foreach($m in $plan.members) {
    $p=[string]$m.path; $q=[string]$m.question_id; $source=$null
    if($q -in @('BQ-SHELLBAG-01','BQ-DIRECTORY-01')){New-Item -ItemType Directory -Path $p | Out-Null}
    elseif($m.operation_class -ceq 'old_copy') {
      $source=Read-FactualState ([string]$m.copy_source)
      if(-not $source.exists){throw 'Pilot old copy source is absent'}
      [IO.File]::Copy([string]$m.copy_source,$p,$false)
      $copied=Read-FactualState $p
      if($copied.sha256 -cne $source.sha256 -or $copied.modified_filetime -ne $source.modified_filetime){throw 'Initial copy did not preserve source content and write time'}
    }
    elseif($q -eq 'BQ-EXEC-01'){Copy-Item -LiteralPath 'C:\Windows\System32\where.exe' -Destination $p}
    elseif($q -eq 'BQ-FILE-01'){Write-FactualBmp $p 17 9}
    else{[IO.File]::WriteAllText($p,'Working document.')}
    $initial.Add(@{path=$p; state=(Read-FactualState $p); copy_source=$source})
  }
  @{schema_version='native_pilot_materialization.v1'; public_manifest_sha256=[string]$plan.public_manifest_sha256; members=@($initial)} | ConvertTo-Json -Compress -Depth 12
  return
}
if($pilotStage -cne 'operate' -or $materialization.public_manifest_sha256 -cne $plan.public_manifest_sha256){throw 'Pilot operations lack their bound materialization receipt'}
$receipts=[Collections.Generic.List[object]]::new()
$ordered=@($plan.members | Where-Object question_id -ne 'BQ-TIME-01') + @($plan.members | Where-Object question_id -eq 'BQ-TIME-01')
foreach($m in $ordered) {
  $p=[string]$m.path; $a=[string]$m.alternative_path; $kind=[string]$m.operation_class; $q=[string]$m.question_id
  $before=Read-FactualState $p; $witnesses=@(); $reuse=$null; $childTransition=$null
  $initial=@($materialization.members | Where-Object path -CEQ $p)
  if($initial.Count -ne 1 -or -not $before.exists -or $before.file_reference -cne $initial[0].state.file_reference){throw 'Pilot member changed since initial materialization'}
  if($q -eq 'BQ-SHELLBAG-01') {
    $visitPath=if($kind -ceq 'present_case'){$p.ToUpperInvariant()}else{$p}
    $witnesses=@(New-LocalNativeShellbagReceipt -Target $visitPath)
  }
  if($q -eq 'BQ-EXEC-01') {
    Start-Process -FilePath $p -ArgumentList 'cmd.exe' -WindowStyle Hidden -Wait
    $deadline=(Get-Date).AddSeconds(40); $name=[IO.Path]::GetFileName($p)
    do {
      $pf=@(Get-ChildItem -LiteralPath 'C:\Windows\Prefetch' -Filter "$name-*.pf" -ErrorAction SilentlyContinue)
      if($pf.Count -eq 0){Start-Sleep -Seconds 2}
    } while($pf.Count -eq 0 -and (Get-Date) -lt $deadline)
    if($pf.Count -eq 0){throw 'Pilot executable has no native Prefetch record'}
    $witnesses=@($pf | ForEach-Object {@{path=$_.FullName; length=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}})
  }
  if($q -in @('BQ-DELETE-01','BQ-SHELLBAG-01','BQ-EXEC-01')) {
    switch($kind) {
      'deleted' {Remove-Item -LiteralPath $p -Recurse -Force}
      'renamed' {Move-Item -LiteralPath $p -Destination $a}
      'recreated' {
        Remove-Item -LiteralPath $p -Recurse -Force
        if($q -eq 'BQ-SHELLBAG-01'){New-Item -ItemType Directory -Path $p | Out-Null}
        elseif($q -eq 'BQ-EXEC-01'){Copy-Item -LiteralPath 'C:\Windows\System32\where.exe' -Destination $p}
        else{[IO.File]::WriteAllText($p,'Replacement document.')}
      }
      'entry_reused' {
        $oldParts=$before.file_reference.Split(':')
        $oldEntry=[Convert]::ToUInt64($oldParts[1],16) -band 0x0000FFFFFFFFFFFFL
        Remove-Item -LiteralPath $p -Force
        for($attempt=1;$attempt -le [int]$m.reuse_attempt_limit;$attempt++) {
          $newPath=$a + '_r_' + $attempt.ToString('D3')
          [IO.File]::WriteAllText($newPath,'Working document.')
          $candidate=Read-FactualState $newPath
          $parts=$candidate.file_reference.Split(':')
          $entry=[Convert]::ToUInt64($parts[1],16) -band 0x0000FFFFFFFFFFFFL
          if($parts[0] -ceq $oldParts[0] -and $entry -eq $oldEntry -and $candidate.file_reference -cne $before.file_reference) {
            $reuse=$candidate; $reuse.attempt=$attempt; break
          }
        }
        if($null -eq $reuse){throw 'Frozen entry-reuse burst exhausted without native reuse'}
      }
      'present_case' {}
      default {throw 'Unregistered pilot path operation'}
    }
  } elseif($q -eq 'BQ-DIRECTORY-01') {
    $children=@()
    foreach($name in $m.child_names) {
      $child=Join-Path $p ([string]$name)
      [IO.File]::WriteAllText($child,'Directory history.')
      $children+=@(Read-FactualState $child)
    }
    $child=$children[[int]$m.child_operation_index]
    $destination=Join-Path $p ([IO.Path]::GetFileName($a) + '.txt')
    if($kind -ceq 'recreated_children') {
      Remove-Item -LiteralPath $child.path -Force
      [IO.File]::WriteAllText($child.path,'Replacement document.')
    } elseif($kind -ceq 'renamed_children') {Move-Item -LiteralPath $child.path -Destination $destination}
    elseif($kind -ceq 'moved_children') {
      New-Item -ItemType Directory -Path $a | Out-Null
      $destination=Join-Path $a ([IO.Path]::GetFileName($child.path))
      Move-Item -LiteralPath $child.path -Destination $destination
    } else {throw 'Unregistered pilot child operation'}
    $childTransition=@{before=$child; after=(Read-FactualState $child.path); alternative=(Read-FactualState $destination)}
    $witnesses=$children
  } elseif($q -eq 'BQ-STREAM-01') {
    $names=@($m.stream_names)
    if($kind -ceq 'second_pe') {
      $witnesses+=@(Write-FactualStream $p $names[0] ([Text.Encoding]::UTF8.GetBytes('{"revision":3}')))
      $witnesses+=@(Write-FactualStream $p $names[1] ([IO.File]::ReadAllBytes('C:\Windows\System32\where.exe')))
    } elseif($kind -ceq 'signature_decoy') {
      $witnesses+=@(Write-FactualStream $p $names[0] ([byte[]](0x4d,0x5a,0,1,2,3,4,5)))
    } elseif($kind -ceq 'empty_zip') {
      Add-Type -AssemblyName System.IO.Compression
      $ms=[IO.MemoryStream]::new()
      try {
        $zip=[IO.Compression.ZipArchive]::new($ms,[IO.Compression.ZipArchiveMode]::Create,$true)
        $zip.Dispose()
        $witnesses+=@(Write-FactualStream $p $names[0] $ms.ToArray())
      } finally {$ms.Dispose()}
    } else {throw 'Unregistered pilot stream operation'}
  } elseif($q -eq 'BQ-FILE-01') {
    if($kind -ceq 'append_four') {
      $stream=[IO.File]::Open($p,[IO.FileMode]::Append)
      try{$stream.Write(([byte[]](7,8,9,10)),0,4);$stream.Flush($true)}finally{$stream.Dispose()}
    } elseif($kind -cne 'valid_bmp'){throw 'Unregistered pilot bitmap operation'}
  } elseif($q -eq 'BQ-TIME-01') {
    $t=[FactualFileInfo]::Times($p)
    switch($kind) {
      'same_year' {
        $years=@([DateTime]::FromFileTimeUtc($t.Creation).Year,[DateTime]::FromFileTimeUtc($t.Write).Year)
        $t.Creation+=[long]$m.timestamp_deltas.creation_filetime
        $t.Write+=[long]$m.timestamp_deltas.modified_filetime
        if([DateTime]::FromFileTimeUtc($t.Creation).Year -ne $years[0] -or [DateTime]::FromFileTimeUtc($t.Write).Year -ne $years[1]){throw 'Pilot same-year target crossed its calendar year'}
        [FactualFileInfo]::Set($p,$t)
      }
      'forward' {$t.Write+=[long]$m.timestamp_deltas.modified_filetime;$t.Change=0;[FactualFileInfo]::Set($p,$t)}
      'access_only' {$t.Access+=[long]$m.timestamp_deltas.access_filetime;$t.Change=0;[FactualFileInfo]::Set($p,$t)}
      'old_copy' {
        if($before.sha256 -cne $initial[0].state.sha256 -or $before.modified_filetime -ne $initial[0].state.modified_filetime){throw 'Pilot preserved-copy metadata changed after initial creation'}
      }
      default {throw 'Unregistered pilot timestamp operation'}
    }
  } else {throw 'Unregistered pilot question'}
  $after=Read-FactualState $p; $alternative=Read-FactualState $a
  if($kind -ceq 'renamed' -and ($after.exists -or -not $alternative.exists -or $before.file_reference -cne $alternative.file_reference)){throw 'Native rename identity changed'}
  if($kind -ceq 'recreated' -and $before.file_reference -ceq $after.file_reference){throw 'Native replacement did not acquire a new identity'}
  $receipts.Add(@{question_id=$q; path=$p; operation_class=$kind; before=$before; after=$after; alternative=$alternative;
    witnesses=$witnesses; copy_source=$initial[0].copy_source; reuse=$reuse; child_transition=$childTransition; completed=$true})
}
@{schema_version='factual_challenge_receipt.v1'; public_manifest_sha256=[string]$plan.public_manifest_sha256; members=@($receipts)} | ConvertTo-Json -Compress -Depth 14
