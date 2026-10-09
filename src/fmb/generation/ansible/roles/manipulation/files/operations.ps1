function ConvertTo-OperationLiteral([string]$Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}
function Invoke-PaperOperation([string]$Text) {
    & ([ScriptBlock]::Create($Text))
}
function Get-OperationRefsSha256([object[]]$Refs) {
    [object[]]$strings = @($Refs | ForEach-Object { [string]$_ })
    $json = ConvertTo-Json -InputObject $strings -Compress
    $json = $json.Replace('\u0026', '&').Replace('\u0027', "'").Replace('\u003c', '<').Replace('\u003e', '>')
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes("generation_operation_refs.v1`n$json"))
        return ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}
