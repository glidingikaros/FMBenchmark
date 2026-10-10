
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function ConvertTo-Number([string] $address) {
    $bytes = ([System.Net.IPAddress]::Parse($address)).GetAddressBytes()
    [int64]$bytes[0] * 16777216 + [int64]$bytes[1] * 65536 + [int64]$bytes[2] * 256 + [int64]$bytes[3]
}

function ConvertTo-Address([int64] $number) {
    '{0}.{1}.{2}.{3}' -f (($number -shr 24) -band 255), (($number -shr 16) -band 255), (($number -shr 8) -band 255), ($number -band 255)
}

function Get-OutsideRanges([string] $address, [int] $prefixLength) {
    if ($prefixLength -ne 24) { throw "expected a /24 NAT subnet, found $address/$prefixLength" }
    $value = ConvertTo-Number $address
    $network = $value - ($value % 256)
    $ranges = @()
    $found = $false
    foreach ($pair in @(@('1.0.0.0', '126.255.255.255'), @('128.0.0.0', '169.253.255.255'), @('169.255.0.0', '223.255.255.255'))) {
        $low = ConvertTo-Number $pair[0]
        $high = ConvertTo-Number $pair[1]
        if ($network -lt $low -or $network + 255 -gt $high) { $ranges += $pair[0] + '-' + $pair[1]; continue }
        if ($network -gt $low) { $ranges += $pair[0] + '-' + (ConvertTo-Address ($network - 1)) }
        if ($network + 255 -lt $high) { $ranges += (ConvertTo-Address ($network + 256)) + '-' + $pair[1] }
        $found = $true
    }
    if (-not $found) { throw "the NAT subnet $(ConvertTo-Address $network)/24 is not a unicast range" }
    $ranges
}

function Test-Outbound([string] $address, [int] $port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try { if ($client.ConnectAsync($address, $port).Wait(5000)) { 'connected' } else { 'timeout' } }
    catch { 'refused' }
    finally { $client.Dispose() }
}

if ($MyInvocation.InvocationName -eq '.') { return }

$route = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0')
if ($route.Count -ne 1) { throw "expected one IPv4 default route, found $($route.Count)" }
$nat = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route[0].InterfaceIndex |
    Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' })
if ($nat.Count -ne 1) {
    throw ('expected one IPv4 address on the default route''s interface, found: ' + (($nat | ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength }) -join ', '))
}
$ranges = Get-OutsideRanges $nat[0].IPAddress $nat[0].PrefixLength
if (@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count) { throw 'a firewall profile is disabled' }
Get-NetFirewallRule -Name 'FMB-Offline-Block-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name 'FMB-Offline-Block-IPv4' -DisplayName 'FMB offline base: block outbound IPv4 outside the NAT subnet' `
    -Direction Outbound -Action Block -Profile Any -RemoteAddress $ranges -Enabled True | Out-Null
New-NetFirewallRule -Name 'FMB-Offline-Block-IPv6' -DisplayName 'FMB offline base: block outbound IPv6 global unicast' `
    -Direction Outbound -Action Block -Profile Any -RemoteAddress '2000::/3' -Enabled True | Out-Null
$probe = Test-Outbound '1.1.1.1' 443
if ($probe -eq 'connected') { throw 'the guest still reaches 1.1.1.1:443' }
Write-Output ("offline-base.ps1: outbound blocked outside {0}/{1} ({2}); 1.1.1.1:443 {3}." -f $nat[0].IPAddress, $nat[0].PrefixLength, ($ranges -join ', '), $probe)

try { Delete-DeliveryOptimizationCache -Force } catch { Write-Output ('offline-base.ps1: Delivery Optimization cache not cleared: ' + $_.Exception.Message) }
foreach ($name in 'UsoSvc', 'wuauserv', 'BITS', 'DoSvc') {
    try { Stop-Service -Name $name -Force } catch { Write-Output ("offline-base.ps1: {0} did not stop: {1}" -f $name, $_.Exception.Message) }
}
$download = 'C:\Windows\SoftwareDistribution\Download'
Get-ChildItem $download -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction Continue
$left = @(Get-ChildItem $download -Recurse -Force -ErrorAction SilentlyContinue).Count
if ($left) { throw "SoftwareDistribution\Download still holds $left entries" }

$logs = 'C:\Windows\System32\winevt\Logs'
Stop-Service -Name EventLog -Force
& compact.exe /u $logs | Out-Null
& compact.exe /u /a /i /q /s:$logs '*' | Out-Null
Start-Service -Name EventLog
$compressed = @(Get-ChildItem $logs -File -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::Compressed }).Count
if ($compressed -or ((Get-Item $logs).Attributes -band [IO.FileAttributes]::Compressed)) {
    throw "winevt\Logs is still compressed ($compressed files)"
}

$journal = (& fsutil.exe usn queryjournal C: | Select-String 'First Usn|Next Usn') -join '; '
$version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Write-Output ("offline-base.ps1: download folder empty, event logs uncompressed, build {0}.{1}, journal {2}." -f $version.CurrentBuild, $version.UBR, $journal)
