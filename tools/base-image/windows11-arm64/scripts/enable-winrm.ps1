
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Set-Service -Name WinRM -StartupType Automatic
if ((Get-Service -Name WinRM).Status -ne 'Running') {
    Start-Service -Name WinRM
}

function Invoke-Winrm {
    & winrm @args | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "winrm $($args -join ' ') failed (exit code $LASTEXITCODE)" }
}

Invoke-Winrm quickconfig '-quiet' '-transport:http'
try {
    Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
} catch {
}

Invoke-Winrm set winrm/config/service '@{AllowUnencrypted="true"}'
Invoke-Winrm set winrm/config/service/auth '@{Basic="true"}'
Invoke-Winrm set winrm/config/client/auth '@{Basic="true"}'
Invoke-Winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'
Invoke-Winrm set winrm/config '@{MaxTimeoutms="1800000"}'

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' -Type DWord -Value 1

if (-not (Get-NetFirewallRule -DisplayName 'FMB WinRM HTTP 5985' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'FMB WinRM HTTP 5985' -Name 'FMB-WinRM-HTTP-5985' `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 `
        -Profile Any -Enable True | Out-Null
}

Write-Output 'enable-winrm.ps1: WinRM over HTTP/5985 (Basic, unencrypted) is configured.'
