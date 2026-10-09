
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
if (-not (Test-Path $au)) { New-Item -Path $au -Force | Out-Null }
Set-ItemProperty -Path $au -Name 'NoAutoRebootWithLoggedOnUsers' -Type DWord -Value 1

foreach ($task in @('\Microsoft\Windows\UpdateOrchestrator\Reboot',
                    '\Microsoft\Windows\UpdateOrchestrator\Reboot_AC',
                    '\Microsoft\Windows\UpdateOrchestrator\Reboot_Battery')) {
    try { Disable-ScheduledTask -TaskPath (Split-Path $task) -TaskName (Split-Path $task -Leaf) -ErrorAction Stop | Out-Null }
    catch { }
}

Write-Output 'disable-update-reboots.ps1: automatic update reboots disabled.'
