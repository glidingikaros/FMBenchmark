
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$setup = Get-PSDrive -PSProvider FileSystem |
    ForEach-Object { Join-Path $_.Root 'setup.exe' } |
    Where-Object { (Test-Path $_) -and (Test-Path (Join-Path (Split-Path $_) 'vmxnet3')) } |
    Select-Object -First 1
if (-not $setup) {
    Write-Output 'install-vmware-tools.ps1: no VMware Tools media attached; nothing to do.'
    return
}

$process = Start-Process -FilePath $setup -ArgumentList '/S', '/v"/qn REBOOT=R"' -Wait -PassThru
if ($process.ExitCode -notin @(0, 3010)) {
    throw "VMware Tools setup exited with code $($process.ExitCode)"
}
Write-Output ("install-vmware-tools.ps1: VMware Tools installed from {0} (exit {1})." -f $setup, $process.ExitCode)
