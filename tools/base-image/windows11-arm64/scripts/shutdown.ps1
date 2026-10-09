
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Output 'shutdown.ps1: powering off for image export.'
& shutdown.exe /s /t 5 /f
