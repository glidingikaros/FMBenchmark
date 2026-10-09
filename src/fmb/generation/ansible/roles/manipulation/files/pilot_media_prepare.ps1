$diskBytes = 67108864
$native = @(Get-CimInstance Win32_DiskDrive | Where-Object {
    if ($_.PNPDeviceID -notlike 'USBSTOR\*') { return $false }
    $candidateDisk = Get-Disk -Number ([int]$_.Index) -ErrorAction Stop
    [string]$candidateDisk.BusType -ceq 'USB' -and [UInt64]$candidateDisk.Size -eq $diskBytes
})
$native=@($native | Sort-Object PNPDeviceID)
if($native.Count -ne 3 -or @($native.PNPDeviceID | Select-Object -Unique).Count -ne 3 -or $pilotDiskIndex -notin @(0,1,2)){throw 'Pilot requires three unique native USBSTOR 64 MiB disks'}
$disk = Get-Disk -Number ([int]$native[$pilotDiskIndex].Index)
if ([string]$disk.BusType -cne 'USB' -or [UInt64]$disk.Size -ne $diskBytes -or
    $disk.IsBoot -or $disk.IsSystem -or $disk.IsOffline -or $disk.IsReadOnly) {
    throw 'Canary disk is not the dedicated writable virtual USB backing'
}
$startedUtc = [DateTime]::UtcNow.ToString('o')
$partitions = @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)
if ([string]$disk.PartitionStyle -ieq 'RAW') {
    $disk | Initialize-Disk -PartitionStyle MBR -PassThru | Out-Null
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
} else {
    $physical = [IO.File]::Open(('\\.\PhysicalDrive' + $disk.Number), [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        [byte[]]$boot = New-Object byte[] 512
        $read = $physical.Read($boot, 0, 512)
    } finally { $physical.Dispose() }
    if ($read -ne 512 -or @($boot | Where-Object { $_ -ne 0 }).Count -ne 0 -or
        $partitions.Count -ne 1 -or [UInt64]$partitions[0].Offset -ne 0 -or
        [UInt64]$partitions[0].Size -ne $diskBytes) {
        throw 'Canary existing partition is not proven empty offset-zero virtual media'
    }
    $partition = $partitions[0]
}
$volume = $partition | Format-Volume -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel 'RecordsMedia' -Force -Confirm:$false
$letter = [string]$volume.DriveLetter
$root = $letter + ':\'

if(-not ('LocalNativeMedia' -as [type])) { Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class LocalNativeMedia {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
      uint creation, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool DeviceIoControl(SafeFileHandle device, uint code, IntPtr input,
      uint inputLength, byte[] output, uint outputLength, out uint returned, IntPtr overlapped);
  [StructLayout(LayoutKind.Sequential)] public struct FileInfo {
    public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh,
      WriteLow, WriteHigh, VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
  }
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInfo info);
}
'@
}
& fsutil usn createjournal m=8388608 a=1048576 ($letter + ':') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Native removable-volume journal creation failed' }
$handle = [LocalNativeMedia]::CreateFile(('\\.\' + $letter + ':'), 2147483648, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
try {
    [byte[]]$journal = New-Object byte[] 80
    [uint32]$returned = 0
    if ($handle.IsInvalid -or -not [LocalNativeMedia]::DeviceIoControl($handle, 0x000900f4,
        [IntPtr]::Zero, 0, $journal, 80, [ref]$returned, [IntPtr]::Zero) -or $returned -lt 56) {
        throw 'Native USN journal identity readback failed'
    }
    $journalId = [BitConverter]::ToUInt64($journal, 0)
    $journalStartUsn = [BitConverter]::ToInt64($journal, 16)
} finally { $handle.Dispose() }
$records = Join-Path $root 'Records'
New-Item -Path $records -ItemType Directory -Force | Out-Null
$beforePath = Join-Path $records ([string]$scenarioInput.before_name)
$afterPath = Join-Path $records ([string]$scenarioInput.after_name)
[IO.File]::WriteAllText($beforePath, 'Local records index.', [Text.Encoding]::ASCII)
[IO.File]::WriteAllText($afterPath, 'Local records index.', [Text.Encoding]::ASCII)
$sourceDirectory = 'C:\Records\Files'
New-Item -Path $sourceDirectory -ItemType Directory -Force | Out-Null
$sourcePath = Join-Path $sourceDirectory ([string]$scenarioInput.file_name)
[byte[]]$content = New-Object byte[] 4097
for ($index = 0; $index -lt $content.Length; $index++) { $content[$index] = [byte](($index * 37 + 19) % 251) }
[IO.File]::WriteAllBytes($sourcePath, $content)
$mediaPath = Join-Path $records ([string]$scenarioInput.file_name)
[IO.File]::Copy($sourcePath, $mediaPath, $false)
$file = [IO.File]::Open($mediaPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
try {
    $fileInfo = [LocalNativeMedia+FileInfo]::new()
    if (-not [LocalNativeMedia]::GetFileInformationByHandle($file.SafeFileHandle, [ref]$fileInfo)) {
        throw 'Native removable-file identity readback failed'
    }
    [UInt64]$fileReference = ([UInt64]$fileInfo.IndexHigh -shl 32) -bor [UInt64]$fileInfo.IndexLow
} finally { $file.Dispose() }
$recent = 'C:\Users\vagrant\AppData\Roaming\Microsoft\Windows\Recent'
New-Item -Path $recent -ItemType Directory -Force | Out-Null
$linkPath = Join-Path $recent ([string]$scenarioInput.shortcut_name)
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($linkPath)
$link.TargetPath = $mediaPath
$link.WorkingDirectory = $records
$link.Save()
$readback = $shell.CreateShortcut($linkPath)
if (-not [String]::Equals($readback.TargetPath, $mediaPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Native ShellLink target readback failed'
}
[IO.File]::AppendAllText($afterPath, ' Updated index.', [Text.Encoding]::ASCII)
$volume = Get-Volume -DriveLetter $letter
$volumeState = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}:'" -f $letter)
$instance = [string]$native[$pilotDiskIndex].PNPDeviceID
$registryPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\' + $instance
$parents = @(); $current = $instance
foreach ($index in 1..5) {
    $property = Get-PnpDeviceProperty -InstanceId $current -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue
    if (-not $property -or -not $property.Data) { break }
    $current = [string]$property.Data
    $parents += $current
}
$setupText = Get-Content -LiteralPath 'C:\Windows\INF\setupapi.dev.log' -Raw
$encodedInstance = $instance.Replace('\', '#')
$setupMatches = @(
    foreach ($line in ($setupText -split "`n")) {
        if ($line -match '^\s*>>>\s+\[Device Install \(Hardware initiated\) - (?<identity>.+)\]\s*$') {
            $observed = [string]$Matches.identity
            if ([String]::Equals($observed, $instance, [StringComparison]::OrdinalIgnoreCase) -or
                $observed.IndexOf(($encodedInstance + '#{'), [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $observed
            }
        }
    }
)
if (-not (Test-Path -LiteralPath $registryPath) -or $setupMatches.Count -lt 1) {
    throw 'Native USB device ancestry lacks corroborating SetupAPI installation evidence'
}
[ordered]@{
    schema_version = 'native_media_binding.v1'
    device_instance_id = $instance
    parent_device_instance_ids = $parents
    setupapi_device_instance_id = [string]$setupMatches[0]
    disk_bus_type = [string]$disk.BusType
    attachment_kind = 'hypervisor_virtual_usb_mass_storage'
    physical_host_device = $false
    disk_size_bytes = [UInt64]$disk.Size
    disk_unique_id = [string]$disk.UniqueId
    volume_guid_path = [string]$volume.Path
    volume_serial_number = [string]$volumeState.VolumeSerialNumber
    partition_offset_bytes = [UInt64]$partition.Offset
    link_path = $linkPath
    target_path = $mediaPath
    target_file_reference_number = $fileReference
    observation_start_utc = $startedUtc
    observation_end_utc = [DateTime]::UtcNow.ToString('o')
    journal_start_usn = $journalStartUsn
    journal_id = $journalId
    companion_file = [string]$scenarioInput.companion_file
}
