param([string]$Source = $PSScriptRoot, [switch]$Stage)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path C:\fmb\scripts | Out-Null

function Say([string]$Text) {
    $line = '{0:HH:mm:ss} {1}' -f (Get-Date), $Text
    Add-Content -Path C:\fmb\first-logon.log -Value $line
    try {
        $port = New-Object System.IO.Ports.SerialPort 'COM1', 115200
        $port.Open()
        $port.WriteLine("FMB $line")
        $port.Close()
    } catch { }
}

Say "first-logon from $Source as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
if ((Resolve-Path $Source).Path -ne 'C:\fmb\scripts') {
    foreach ($file in Get-ChildItem -Path $Source -File) {
        $name = ($file.Name -replace ';\d+$', '').ToLowerInvariant().Replace('_', '-')
        Copy-Item -LiteralPath $file.FullName -Destination (Join-Path C:\fmb\scripts $name) -Force
    }
}
if ($Stage) {
    Say 'staged scripts'
    return
}
foreach ($name in 'disable-sleep-hibernate', 'set-network-private', 'disable-update-reboots',
                  'disable-automatic-updates', 'enable-autologon', 'enable-winrm-ntlm') {
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\fmb\scripts\$name.ps1" 2>&1
    Say ("{0}: exit {1}: {2}" -f $name, $LASTEXITCODE, ($output -join ' | '))
}
Set-Content -Path C:\fmb\first-logon-complete.txt -Value 'first-logon-provisioning-complete'
Say 'first-logon complete'
