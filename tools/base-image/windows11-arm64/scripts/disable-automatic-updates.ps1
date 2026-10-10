
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
if (-not (Test-Path $au)) { New-Item -Path $au -Force | Out-Null }
Set-ItemProperty -Path $au -Name 'NoAutoUpdate' -Type DWord -Value 1

Write-Output 'disable-automatic-updates.ps1: Automatic Updates off (NoAutoUpdate=1).'
