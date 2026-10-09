
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$deadline = (Get-Date).AddSeconds(60)
do {
    $profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
    $pending  = @($profiles | Where-Object { $_.NetworkCategory -ne 'Private' })
    foreach ($p in $pending) {
        try {
            Set-NetConnectionProfile -InterfaceIndex $p.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
        } catch {
        }
    }
    if ($profiles.Count -gt 0 -and $pending.Count -eq 0) { break }
    Start-Sleep -Seconds 3
} while ((Get-Date) -lt $deadline)

$final = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty NetworkCategory)
Write-Output ("set-network-private.ps1: network categories = [{0}]" -f ($final -join ', '))
