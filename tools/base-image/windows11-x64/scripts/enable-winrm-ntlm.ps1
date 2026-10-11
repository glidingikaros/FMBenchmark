

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Set-Service -Name WinRM -StartupType Automatic
if ((Get-Service -Name WinRM).Status -ne 'Running') {
    Start-Service -Name WinRM
}

if (-not @(Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTP' })) {
    New-Item -Path WSMan:\localhost\Listener -Transport HTTP -Address * -Force | Out-Null
}
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 1024
Set-Item WSMan:\localhost\MaxTimeoutms 1800000

# Windows starts a delayed-start service about two minutes after boot, and every boot waits for WinRM.
& sc.exe config WinRM start= auto | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe config WinRM start= auto failed (exit code $LASTEXITCODE)" }
if ((Get-CimInstance -ClassName Win32_Service -Filter "Name='WinRM'").DelayedAutoStart) {
    throw 'WinRM is still a delayed-start service'
}

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' -Type DWord -Value 1

if (-not (Get-NetFirewallRule -DisplayName 'FMB WinRM HTTP 5985' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'FMB WinRM HTTP 5985' -Name 'FMB-WinRM-HTTP-5985' `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 `
        -Profile Any -Enable True | Out-Null
}

Write-Output 'enable-winrm-ntlm.ps1: WinRM over HTTP/5985 with encrypted Negotiate/NTLM is configured.'
