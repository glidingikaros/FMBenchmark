
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty -Path $winlogon -Name 'AutoAdminLogon' -Type String -Value '1'
Set-ItemProperty -Path $winlogon -Name 'DefaultUserName' -Type String -Value 'vagrant'
Set-ItemProperty -Path $winlogon -Name 'DefaultPassword' -Type String -Value 'vagrant'
Set-ItemProperty -Path $winlogon -Name 'DefaultDomainName' -Type String -Value $env:COMPUTERNAME
Remove-ItemProperty -Path $winlogon -Name 'AutoLogonCount' -ErrorAction SilentlyContinue

Write-Output 'enable-autologon.ps1: vagrant logs on interactively at every boot.'
