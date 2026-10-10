
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

& powercfg.exe /hibernate off

& powercfg.exe /change standby-timeout-ac 0
& powercfg.exe /change standby-timeout-dc 0
& powercfg.exe /change monitor-timeout-ac 0
& powercfg.exe /change monitor-timeout-dc 0
& powercfg.exe /change disk-timeout-ac 0
& powercfg.exe /change disk-timeout-dc 0
& powercfg.exe /change hibernate-timeout-ac 0
& powercfg.exe /change hibernate-timeout-dc 0

Write-Output 'disable-sleep-hibernate.ps1: hibernation and idle sleep disabled.'
