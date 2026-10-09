
$fmbNativeShellbagTemporaryNames = @(
    "LocalNativeShellbagPayloadBase64",
    "LocalNativeShellbagExpectedSha256",
    "fmbNativeShellbagPayloadBytes",
    "fmbNativeShellbagPayloadStream",
    "fmbNativeShellbagGzipStream",
    "fmbNativeShellbagExpandedStream",
    "fmbNativeShellbagHelperBytes",
    "fmbNativeShellbagSha256",
    "fmbNativeShellbagActualSha256",
    "fmbNativeShellbagUtf8",
    "fmbNativeShellbagSource",
    "LocalNativeShellbagScriptBlock"
)

try {
    if ([string]::IsNullOrWhiteSpace([string]$LocalNativeShellbagPayloadBase64)) {
        throw "Native Shellbag transport payload is missing"
    }
    if ([string]::IsNullOrWhiteSpace([string]$LocalNativeShellbagExpectedSha256)) {
        throw "Native Shellbag transport hash is missing"
    }

    $fmbNativeShellbagPayloadBytes = [Convert]::FromBase64String(
        [string]$LocalNativeShellbagPayloadBase64
    )
    $fmbNativeShellbagPayloadStream = [IO.MemoryStream]::new(
        [byte[]]$fmbNativeShellbagPayloadBytes,
        $false
    )
    $fmbNativeShellbagGzipStream = [IO.Compression.GZipStream]::new(
        $fmbNativeShellbagPayloadStream,
        [IO.Compression.CompressionMode]::Decompress,
        $false
    )
    $fmbNativeShellbagExpandedStream = [IO.MemoryStream]::new()
    $fmbNativeShellbagGzipStream.CopyTo($fmbNativeShellbagExpandedStream)
    $fmbNativeShellbagHelperBytes = $fmbNativeShellbagExpandedStream.ToArray()

    $fmbNativeShellbagSha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $fmbNativeShellbagActualSha256 = -join @(
            $fmbNativeShellbagSha256.ComputeHash(
                [byte[]]$fmbNativeShellbagHelperBytes
            ) | ForEach-Object { $_.ToString("x2") }
        )
    } finally {
        $fmbNativeShellbagSha256.Dispose()
    }
    if (-not [String]::Equals(
        $fmbNativeShellbagActualSha256,
        ([string]$LocalNativeShellbagExpectedSha256).Trim().ToLowerInvariant(),
        [StringComparison]::Ordinal
    )) {
        throw "Native Shellbag transport hash verification failed"
    }

    $fmbNativeShellbagUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $fmbNativeShellbagSource = $fmbNativeShellbagUtf8.GetString(
        [byte[]]$fmbNativeShellbagHelperBytes
    )
    $LocalNativeShellbagScriptBlock = [ScriptBlock]::Create(
        $fmbNativeShellbagSource
    )
    . $LocalNativeShellbagScriptBlock
} finally {
    if ($null -ne $fmbNativeShellbagGzipStream) {
        $fmbNativeShellbagGzipStream.Dispose()
    }
    if ($null -ne $fmbNativeShellbagPayloadStream) {
        $fmbNativeShellbagPayloadStream.Dispose()
    }
    if ($null -ne $fmbNativeShellbagExpandedStream) {
        $fmbNativeShellbagExpandedStream.Dispose()
    }
    foreach ($fmbNativeShellbagTemporaryName in $fmbNativeShellbagTemporaryNames) {
        Clear-Variable -Name $fmbNativeShellbagTemporaryName `
            -ErrorAction SilentlyContinue
        Remove-Variable -Name $fmbNativeShellbagTemporaryName `
            -ErrorAction SilentlyContinue
    }
    Clear-Variable -Name fmbNativeShellbagTemporaryNames `
        -ErrorAction SilentlyContinue
    Remove-Variable -Name fmbNativeShellbagTemporaryNames `
        -ErrorAction SilentlyContinue
    Clear-Variable -Name fmbNativeShellbagTemporaryName `
        -ErrorAction SilentlyContinue
    Remove-Variable -Name fmbNativeShellbagTemporaryName `
        -ErrorAction SilentlyContinue
}
