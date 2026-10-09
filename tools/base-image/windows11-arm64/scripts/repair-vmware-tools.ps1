
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Get-Service -Name VMTools -ErrorAction SilentlyContinue)) {
    $product = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -eq 'VMware Tools' } |
        Select-Object -First 1
    if (-not $product) {
        Write-Output 'repair-vmware-tools.ps1: VMware Tools are not installed; nothing to repair.'
    } else {
        $repair = Start-Process -FilePath msiexec.exe -Wait -PassThru -ArgumentList @(
            '/fa', $product.PSChildName, '/qn', 'REBOOT=R', '/l*v', 'C:\fmb\tools-repair.log')
        if ($repair.ExitCode -notin @(0, 3010, 1641)) {
            throw "VMware Tools repair exited with code $($repair.ExitCode)"
        }
        Write-Output ('repair-vmware-tools.ps1: repaired {0} (exit {1}).' -f $product.PSChildName, $repair.ExitCode)
        if ($repair.ExitCode -eq 1641) { return }
    }
}
& shutdown.exe /r /t 5 /c 'FMB base build: restart after the VMware Tools check'
