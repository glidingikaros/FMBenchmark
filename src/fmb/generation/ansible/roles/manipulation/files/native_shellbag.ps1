
function Get-LocalOwnedInteractiveExplorerSessionIds {
    [OutputType([Int32[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Object[]]$Processes
    )

    if (@($Processes).Count -eq 0) {
        return
    }

    try {
        $currentIdentity = (
            [Security.Principal.WindowsIdentity]::GetCurrent().Name
        )
    } catch {
        throw "Unable to establish the current WinRM identity"
    }
    $identityParts = $currentIdentity -split "\\", 2
    if (
        $identityParts.Count -ne 2 -or
        -not [String]::Equals(
            $identityParts[1],
            "vagrant",
            [StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "Native Shellbag action requires the local vagrant identity"
    }

    $sessionIds = @()
    foreach ($process in @($Processes)) {
        if ($null -eq $process) {
            throw "Explorer process enumeration returned a null entry"
        }
        $name = [string]$process.Name
        if (-not [String]::Equals(
            $name,
            "explorer.exe",
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Explorer process enumeration returned a non-Explorer process"
        }
        try {
            $owner = Invoke-CimMethod -InputObject $process `
                -MethodName GetOwner -ErrorAction Stop
        } catch {
            throw "Explorer GetOwner failed"
        }
        if (
            $null -eq $owner -or
            [UInt32]$owner.ReturnValue -ne 0 -or
            [String]::IsNullOrWhiteSpace([string]$owner.User) -or
            [String]::IsNullOrWhiteSpace([string]$owner.Domain)
        ) {
            throw "Explorer GetOwner did not return a verified owner"
        }
        $isCurrentOwner = (
            [String]::Equals(
                [string]$owner.User,
                $identityParts[1],
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            [String]::Equals(
                [string]$owner.Domain,
                $identityParts[0],
                [StringComparison]::OrdinalIgnoreCase
            )
        )
        if (-not $isCurrentOwner) {
            continue
        }
        $sessionId = [Int32]$process.SessionId
        if ($sessionId -le 0) {
            throw "The owned vagrant Explorer process is not interactive"
        }
        $sessionIds += $sessionId
    }
    return @($sessionIds | Sort-Object -Unique)
}

function Test-LocalInteractiveVagrantExplorer {
    [OutputType([Bool])]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [Object[]]$Processes = $null
    )

    try {
        if (-not $PSBoundParameters.ContainsKey("Processes")) {
            $Processes = @(
                Get-CimInstance -ClassName Win32_Process `
                    -Filter "Name = 'explorer.exe'" -ErrorAction Stop
            )
        }
        if (@($Processes).Count -eq 0) {
            return $false
        }
        $sessionIds = @(
            Get-LocalOwnedInteractiveExplorerSessionIds -Processes $Processes
        )
        return $sessionIds.Count -eq 1
    } catch {
        return $false
    }
}

function ConvertTo-LocalHex {
    [OutputType([String])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Byte[]]$Bytes
    )
    return [BitConverter]::ToString($Bytes).Replace('-', '').ToLowerInvariant()
}

function ConvertFrom-LocalMruListEx {
    [OutputType([UInt32[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Byte[]]$Bytes
    )

    if ($Bytes.Length -lt 4 -or ($Bytes.Length % 4) -ne 0) {
        throw "MRUListEx is not DWORD aligned"
    }
    $values = @()
    for ($offset = 0; $offset -lt $Bytes.Length; $offset += 4) {
        $values += [BitConverter]::ToUInt32($Bytes, $offset)
    }
    if ($values[-1] -ne [UInt32]::MaxValue) {
        throw "MRUListEx has no 0xffffffff terminator"
    }
    $linked = @($values[0..($values.Count - 2)])
    if ($values.Count -eq 1) {
        $linked = @()
    }
    if (@($linked | Where-Object { $_ -eq [UInt32]::MaxValue }).Count -gt 0) {
        throw "MRUListEx contains an early terminator"
    }
    if (@($linked | Sort-Object -Unique).Count -ne $linked.Count) {
        throw "MRUListEx contains duplicate links"
    }
    return [UInt32[]]$linked
}

function Get-LocalSha256Hex {
    [OutputType([String])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Byte[]]$Bytes
    )
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ConvertTo-LocalHex -Bytes ($sha256.ComputeHash($Bytes))
    } finally {
        $sha256.Dispose()
    }
}

function Set-LocalNativeShellbagVisitBudgets {
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Budgets
    )
    $keys = @('match_seconds', 'close_seconds', 'child_seconds', 'dispatch_seconds', 'snapshot_ms')
    if ($null -eq $Budgets) { throw 'Native Shellbag visit budgets are missing' }
    if ($Budgets -is [Collections.IDictionary]) {
        $names = @($Budgets.Keys | ForEach-Object { [string]$_ })
    } else {
        $names = @($Budgets.PSObject.Properties | ForEach-Object { [string]$_.Name })
    }
    if ($names.Count -ne $keys.Count -or @($keys | Where-Object { $names -cnotcontains $_ }).Count -ne 0) {
        throw 'Native Shellbag visit budgets are incomplete'
    }
    $resolved = [ordered]@{}
    foreach ($key in $keys) {
        $value = $Budgets.$key
        if ($value -isnot [Int32] -and $value -isnot [Int64]) {
            throw "Native Shellbag visit budget '$key' is not an integer"
        }
        $limit = if ($key -ceq 'snapshot_ms') { 600000 } else { 3600 }
        if ([Int64]$value -lt 1 -or [Int64]$value -gt $limit) {
            throw "Native Shellbag visit budget '$key' is outside its bounds"
        }
        $resolved[$key] = [Int32]$value
    }
    if ($resolved['child_seconds'] -lt ($resolved['match_seconds'] + $resolved['close_seconds'] + 2)) {
        throw 'Native Shellbag child budget cannot hold the match and close waits'
    }
    if ($resolved['dispatch_seconds'] -lt ($resolved['child_seconds'] + 8)) {
        throw 'Native Shellbag dispatch budget leaves no worker startup headroom'
    }
    $script:LocalNativeShellbagVisitBudgets = [PSCustomObject]$resolved
}

function Get-LocalNativeShellbagVisitBudgets {
    [OutputType([PSCustomObject])]
    param()
    if ($null -ne $script:LocalNativeShellbagVisitBudgets) {
        return $script:LocalNativeShellbagVisitBudgets
    }
    return [PSCustomObject][ordered]@{
        match_seconds = 20
        close_seconds = 20
        child_seconds = 42
        dispatch_seconds = 70
        snapshot_ms = 2000
    }
}

function Get-LocalNativeBagMruSnapshot {
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Target
    )

    $script:LocalNativeBagMruSnapshotDiagnostic = $null
    $script:LocalNativeBagMruSnapshotCount = [Int32]$script:LocalNativeBagMruSnapshotCount + 1
    $rootPath = (
        "Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
    )
    $nodes = [Collections.Generic.List[Object]]::new()
    $snapshotWatch = [Diagnostics.Stopwatch]::StartNew()
    $snapshotState = [PSCustomObject]@{
        value_bytes = [Int64]0
    }
    $maxNodeCount = 4096
    $maxDepth = 64
    $maxValueBytes = 16777216
    $maxElapsedMilliseconds = [Int32](Get-LocalNativeShellbagVisitBudgets).snapshot_ms

    function Set-LocalBagMruLimitDiagnostic {
        param(
            [String[]]$Dimensions,
            [Int32]$Depth,
            [Nullable[Int32]]$ValueCount,
            [Nullable[Int32]]$ChildCount
        )
        $script:LocalNativeBagMruSnapshotDiagnostic = @{
            phase = $script:LocalNativeBagMruSnapshotPhase
            exceeded_dimensions = $Dimensions
            elapsed_ms = [Int64]$snapshotWatch.ElapsedMilliseconds
            node_count = [Int32]$nodes.Count
            depth = [Int32]$Depth
            value_count = $ValueCount
            value_bytes = [Int64]$snapshotState.value_bytes
            child_count = $ChildCount
            projected_node_count = if ($null -eq $ChildCount) { $null } else { [Int32]($nodes.Count + $ChildCount) }
        }
    }

    function Read-LocalBagMruKey {
        param(
            [Parameter(Mandatory)]
            [Microsoft.Win32.RegistryKey]$Key,
            [Parameter(Mandatory)]
            [String]$RelativePath,
            [Parameter(Mandatory)]
            [Int32]$Depth
        )

        if (
            $Depth -gt $maxDepth -or
            $nodes.Count -ge $maxNodeCount -or
            $snapshotWatch.ElapsedMilliseconds -gt $maxElapsedMilliseconds
        ) {
            $dimensions = @(
                if ($Depth -gt $maxDepth) { 'depth' }
                if ($nodes.Count -ge $maxNodeCount) { 'node_count' }
                if ($snapshotWatch.ElapsedMilliseconds -gt $maxElapsedMilliseconds) { 'elapsed' }
            )
            Set-LocalBagMruLimitDiagnostic -Dimensions $dimensions -Depth $Depth
            throw "BagMRU snapshot resource boundary exceeded"
        }

        $numericValues = [Collections.Generic.List[Object]]::new()
        $mruListExHex = $null
        $mruLinks = @()
        $valueNames = @($Key.GetValueNames() | Sort-Object)
        if ($valueNames.Count -gt $maxNodeCount) {
            Set-LocalBagMruLimitDiagnostic -Dimensions @('value_count') -Depth $Depth -ValueCount $valueNames.Count
            throw "BagMRU snapshot resource boundary exceeded"
        }
        foreach ($valueName in $valueNames) {
            if ($snapshotWatch.ElapsedMilliseconds -gt $maxElapsedMilliseconds) {
                Set-LocalBagMruLimitDiagnostic -Dimensions @('elapsed') -Depth $Depth -ValueCount $valueNames.Count
                throw "BagMRU snapshot resource boundary exceeded"
            }
            if ([String]::Equals(
                $valueName,
                "FMB_Confidential_Path",
                [StringComparison]::OrdinalIgnoreCase
            )) {
                throw "Legacy FMB_Confidential_Path BagMRU hint is forbidden"
            }
            $kind = $Key.GetValueKind($valueName)
            $value = $Key.GetValue(
                $valueName,
                $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            if (
                $kind -in @(
                    [Microsoft.Win32.RegistryValueKind]::String,
                    [Microsoft.Win32.RegistryValueKind]::ExpandString
                ) -and
                [String]::Equals(
                    [string]$value,
                    $Target,
                    [StringComparison]::OrdinalIgnoreCase
                )
            ) {
                throw "A custom BagMRU string equal to the target is forbidden"
            }
            if ($valueName -match "^\d+$") {
                if ($kind -ne [Microsoft.Win32.RegistryValueKind]::Binary) {
                    throw "A numeric BagMRU value is not REG_BINARY"
                }
                $bytes = [Byte[]]$value
                $snapshotState.value_bytes += [Int64]$bytes.Length
                if ($snapshotState.value_bytes -gt $maxValueBytes) {
                    Set-LocalBagMruLimitDiagnostic -Dimensions @('value_bytes') -Depth $Depth -ValueCount $valueNames.Count
                    throw "BagMRU snapshot resource boundary exceeded"
                }
                $numericValues.Add([PSCustomObject][ordered]@{
                    name = $valueName
                    sha256 = Get-LocalSha256Hex -Bytes $bytes
                })
            } elseif ([String]::Equals(
                $valueName,
                "MRUListEx",
                [StringComparison]::Ordinal
            )) {
                if ($kind -ne [Microsoft.Win32.RegistryValueKind]::Binary) {
                    throw "MRUListEx is not REG_BINARY"
                }
                $mruBytes = [Byte[]]$value
                $snapshotState.value_bytes += [Int64]$mruBytes.Length
                if ($snapshotState.value_bytes -gt $maxValueBytes) {
                    Set-LocalBagMruLimitDiagnostic -Dimensions @('value_bytes') -Depth $Depth -ValueCount $valueNames.Count
                    throw "BagMRU snapshot resource boundary exceeded"
                }
                $mruLinks = @(ConvertFrom-LocalMruListEx -Bytes $mruBytes)
                $mruListExHex = ConvertTo-LocalHex -Bytes $mruBytes
            }
        }

        if ($numericValues.Count -gt 0 -and $null -eq $mruListExHex) {
            throw "Numeric BagMRU values exist without MRUListEx"
        }
        $numericNames = @($numericValues | ForEach-Object { $_.name })
        foreach ($link in $mruLinks) {
            if ([string]$link -notin $numericNames) {
                throw "MRUListEx references a missing numeric BagMRU value"
            }
        }
        $nodes.Add([PSCustomObject][ordered]@{
            key_path = $RelativePath
            numeric_values = @($numericValues)
            mrulistex_hex = $mruListExHex
        })

        $subkeyNames = @($Key.GetSubKeyNames() | Sort-Object)
        if (
            $nodes.Count + $subkeyNames.Count -gt $maxNodeCount -or
            $snapshotWatch.ElapsedMilliseconds -gt $maxElapsedMilliseconds
        ) {
            $dimensions = @(
                if ($nodes.Count + $subkeyNames.Count -gt $maxNodeCount) { 'projected_node_count' }
                if ($snapshotWatch.ElapsedMilliseconds -gt $maxElapsedMilliseconds) { 'elapsed' }
            )
            Set-LocalBagMruLimitDiagnostic -Dimensions $dimensions -Depth $Depth -ValueCount $valueNames.Count -ChildCount $subkeyNames.Count
            throw "BagMRU snapshot resource boundary exceeded"
        }
        foreach ($subkeyName in $subkeyNames) {
            $subkey = $Key.OpenSubKey($subkeyName, $false)
            if ($null -eq $subkey) {
                throw "Unable to open a BagMRU subkey"
            }
            try {
                Read-LocalBagMruKey -Key $subkey `
                    -RelativePath ($RelativePath + "\" + $subkeyName) `
                    -Depth ($Depth + 1)
            } finally {
                $subkey.Dispose()
            }
        }
    }

    $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        $rootPath,
        $false
    )
    if ($null -ne $root) {
        try {
            Read-LocalBagMruKey -Key $root -RelativePath "BagMRU" -Depth 0
        } finally {
            $root.Dispose()
        }
    }
    $nodeArray = @($nodes | Sort-Object key_path)
    $canonical = ConvertTo-Json -InputObject $nodeArray `
        -Depth 8 -Compress
    return [PSCustomObject][ordered]@{
        nodes = $nodeArray
        canonical = $canonical
    }
}

function Get-LocalNativeBagMruSnapshotDiagnostic {
    $raw = $script:LocalNativeBagMruSnapshotDiagnostic
    $phase = 'unobserved'
    if ($raw.phase -cin @('pre_baseline', 'delta', 'post_stability')) {
        $phase = [String]$raw.phase
    }
    $dimensions = @(
        foreach ($name in @('elapsed', 'node_count', 'depth', 'value_count', 'value_bytes', 'projected_node_count')) {
            if ($name -cin @($raw.exceeded_dimensions)) { $name }
        }
    )
    $result = [ordered]@{ phase = $phase; exceeded_dimensions = $dimensions }
    foreach ($name in @('elapsed_ms', 'node_count', 'depth', 'value_count', 'value_bytes', 'child_count', 'projected_node_count')) {
        $value = $raw.$name
        $expected = if ($name -in @('elapsed_ms', 'value_bytes')) { [Int64] } else { [Int32] }
        $result[$name] = if ($value -is $expected -and $value -ge 0) { $value } else { $null }
    }
    $result.limits = [ordered]@{
        max_elapsed_ms = 2000
        max_node_count = 4096
        max_depth = 64
        max_value_count = 4096
        max_value_bytes = 16777216
    }
    return [PSCustomObject]$result
}

function Test-LocalElapsedOnlyBagMruSnapshotFailure {
    [OutputType([Bool])]
    param()

    $raw = $script:LocalNativeBagMruSnapshotDiagnostic
    $names = @('phase', 'exceeded_dimensions', 'elapsed_ms', 'node_count',
        'depth', 'value_count', 'value_bytes', 'child_count', 'projected_node_count')
    if ($raw -isnot [Hashtable] -or $raw.Count -ne $names.Count) { return $false }
    foreach ($name in $raw.Keys) {
        if ($name -isnot [String] -or $name -cnotin $names) { return $false }
    }
    if (
        $raw.phase -isnot [String] -or
        $raw.phase -cnotin @('pre_baseline', 'delta', 'post_stability') -or
        $raw.phase -cne $script:LocalNativeBagMruSnapshotPhase -or
        $raw.exceeded_dimensions -isnot [String[]] -or
        $raw.exceeded_dimensions.Count -ne 1 -or
        $raw.exceeded_dimensions[0] -cne 'elapsed'
    ) { return $false }
    foreach ($name in @('elapsed_ms', 'node_count', 'depth', 'value_bytes')) {
        $expected = if ($name -in @('elapsed_ms', 'value_bytes')) { [Int64] } else { [Int32] }
        if ($raw[$name] -isnot $expected -or $raw[$name] -lt 0) { return $false }
    }
    foreach ($name in @('value_count', 'child_count', 'projected_node_count')) {
        if ($null -ne $raw[$name] -and ($raw[$name] -isnot [Int32] -or $raw[$name] -lt 0)) {
            return $false
        }
    }
    if (
        $raw.elapsed_ms -le 2000 -or $raw.node_count -gt 4096 -or
        $raw.depth -gt 64 -or $raw.value_bytes -gt 16777216 -or
        $raw.value_count -gt 4096 -or $raw.child_count -gt 4096 -or
        $raw.projected_node_count -gt 4096
    ) { return $false }
    if ($null -eq $raw.child_count) {
        if ($null -ne $raw.projected_node_count -or $raw.node_count -ge 4096) { return $false }
    } elseif (
        $null -eq $raw.value_count -or $null -eq $raw.projected_node_count -or
        $raw.projected_node_count -ne ($raw.node_count + $raw.child_count)
    ) { return $false }
    return $true
}

function Test-LocalPermanentBagMruSnapshotFailure {
    [OutputType([Bool])]
    param(
        [AllowNull()]
        [String]$Message
    )

    if ($Message -ceq "BagMRU snapshot resource boundary exceeded") {
        return -not (Test-LocalElapsedOnlyBagMruSnapshotFailure)
    }
    return [string]$Message -in @(
        "Legacy FMB_Confidential_Path BagMRU hint is forbidden",
        "A custom BagMRU string equal to the target is forbidden",
        "A numeric BagMRU value is not REG_BINARY",
        "MRUListEx is not REG_BINARY",
        "MRUListEx is not DWORD aligned",
        "MRUListEx has no 0xffffffff terminator",
        "MRUListEx contains an early terminator",
        "MRUListEx contains duplicate links"
    )
}

function Test-LocalTransientBagMruSnapshotFailure {
    [OutputType([Bool])]
    param(
        [AllowNull()]
        [String]$Message
    )

    if ($Message -ceq "BagMRU snapshot resource boundary exceeded") {
        return Test-LocalElapsedOnlyBagMruSnapshotFailure
    }
    return [string]$Message -in @(
        "Numeric BagMRU values exist without MRUListEx",
        "MRUListEx references a missing numeric BagMRU value",
        "Unable to open a BagMRU subkey"
    )
}

function Get-LocalStableNativeBagMruSnapshot {
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Target
    )

    $previous = $null
    $stableIntervals = 0
    foreach ($attempt in 1..20) {
        $current = $null
        try {
            $current = Get-LocalNativeBagMruSnapshot -Target $Target
        } catch {
            $snapshotFailure = [string]$_.Exception.Message
            if (
                (Test-LocalPermanentBagMruSnapshotFailure `
                    -Message $snapshotFailure) -or
                -not (Test-LocalTransientBagMruSnapshotFailure `
                    -Message $snapshotFailure)
            ) {
                throw
            }
            $current = $null
            $previous = $null
            $stableIntervals = 0
            Start-Sleep -Milliseconds 300
            continue
        }
        if (
            $null -ne $previous -and
            $previous.canonical -ceq $current.canonical
        ) {
            $stableIntervals += 1
            if ($stableIntervals -ge 5) {
                return $current
            }
        } else {
            $stableIntervals = 0
        }
        $previous = $current
        Start-Sleep -Milliseconds 300
    }
    throw "BagMRU did not remain stable for the required quiescence window"
}

function Get-LocalNativeBagMruDelta {
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Before,
        [Parameter(Mandatory)]
        [PSCustomObject]$After
    )

    $qualifyingKeys = 0
    $changedNumericValues = 0
    $changedMruListEx = 0
    foreach ($afterNode in @($After.nodes)) {
        $beforeNode = @(
            $Before.nodes | Where-Object {
                $_.key_path -ceq $afterNode.key_path
            }
        ) | Select-Object -First 1
        $beforeMru = if ($null -eq $beforeNode) {
            $null
        } else {
            $beforeNode.mrulistex_hex
        }
        $mruChanged = $afterNode.mrulistex_hex -and (
            $null -eq $beforeNode -or
            $afterNode.mrulistex_hex -cne $beforeMru
        )
        $numericChangesForKey = 0
        foreach ($afterValue in @($afterNode.numeric_values)) {
            $beforeValue = if ($null -eq $beforeNode) {
                $null
            } else {
                @(
                    $beforeNode.numeric_values | Where-Object {
                        $_.name -ceq $afterValue.name
                    }
                ) | Select-Object -First 1
            }
            if (
                $null -eq $beforeValue -or
                $beforeValue.sha256 -cne $afterValue.sha256
            ) {
                $numericChangesForKey += 1
            }
        }
        if ($mruChanged) {
            $changedMruListEx += 1
        }
        $changedNumericValues += $numericChangesForKey
        if ($mruChanged -and $numericChangesForKey -gt 0) {
            $qualifyingKeys += 1
        }
    }
    return [PSCustomObject][ordered]@{
        qualifying_key_count = $qualifyingKeys
        changed_numeric_value_count = $changedNumericValues
        changed_mrulistex_count = $changedMruListEx
    }
}

function Get-LocalNativeShellbagChildFailureMessage {
    [OutputType([String])]
    param(
        [Parameter(Mandatory)]
        [UInt32]$ExitCode
    )

    switch ($ExitCode) {
        211 { return "Native Shellbag child target normalization failed" }
        212 {
            return (
                "Native Shellbag child Shell COM or preexisting window " +
                "enumeration failed"
            )
        }
        213 { return "Native Shellbag child Explorer dispatch failed" }
        214 {
            return "Native Shellbag child exact-target window enumeration failed"
        }
        215 {
            return "Native Shellbag child found multiple exact-target windows"
        }
        216 {
            return (
                "Native Shellbag child did not match an exact-target window " +
                "before timeout"
            )
        }
        217 {
            return "Native Shellbag child exact-target window close request failed"
        }
        218 {
            return "Native Shellbag child exact-target close enumeration failed"
        }
        219 {
            return (
                "Native Shellbag child did not confirm exact-target window " +
                "closure before timeout"
            )
        }
        220 {
            return "Native Shellbag watchdog timed out before a child stage"
        }
        221 {
            return "Native Shellbag watchdog rejected the child execution boundary"
        }
        222 { return "Native Shellbag child reached success but did not terminate" }
        223 { return "Native Shellbag owned child termination failed" }
        default {
            return "Native Shellbag child failed without a recognized stage code"
        }
    }
}

function Select-LocalCausalExactTargetShellWindows {
    [OutputType([Object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Object[]]$BeforeWindows,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Object[]]$AfterWindows,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$NormalizedTarget
    )

    $beforePaths = @{}
    foreach ($window in @($BeforeWindows)) {
        $beforePaths[[Int64]$window.hwnd] = [string]$window.normalized_path
    }

    $matches = @()
    foreach ($window in @($AfterWindows)) {
        $afterPath = [string]$window.normalized_path
        if (-not [String]::Equals(
            $afterPath,
            $NormalizedTarget,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            continue
        }

        $hwnd = [Int64]$window.hwnd
        if (-not $beforePaths.ContainsKey($hwnd)) {
            $matches += $window
            continue
        }
        $beforePath = [string]$beforePaths[$hwnd]
        if (
            -not [String]::IsNullOrWhiteSpace($beforePath) -and
            -not [String]::Equals(
                $beforePath,
                $NormalizedTarget,
                [StringComparison]::OrdinalIgnoreCase
            )
        ) {
            $matches += $window
        }
    }
    return @($matches)
}

function Invoke-LocalInteractiveShellExplore {
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Target,
        [Parameter(Mandatory)]
        [ValidateRange(1, [Int32]::MaxValue)]
        [Int32]$ExpectedSessionId
    )

    $processes = @(
        Get-CimInstance -ClassName Win32_Process `
            -Filter "Name = 'explorer.exe'" -ErrorAction Stop
    )
    if (-not (Test-LocalInteractiveVagrantExplorer -Processes $processes)) {
        throw "Exactly one owned interactive vagrant Explorer is required"
    }
    $sessionIds = @(
        Get-LocalOwnedInteractiveExplorerSessionIds -Processes $processes
    )
    if (
        $sessionIds.Count -ne 1 -or
        $sessionIds[0] -ne $ExpectedSessionId
    ) {
        throw "The verified Explorer session changed before dispatch"
    }

        $visitBudgets = Get-LocalNativeShellbagVisitBudgets
        $matchSeconds = [Int32]$visitBudgets.match_seconds
        $closeSeconds = [Int32]$visitBudgets.close_seconds
        $targetBase64 = [Convert]::ToBase64String(
            [Text.Encoding]::UTF8.GetBytes($Target)
        )
        $selectorSource = (
            "function Select-LocalCausalExactTargetShellWindows {`r`n" +
            ${function:Select-LocalCausalExactTargetShellWindows}.ToString() +
            "`r`n}"
        )
        $childScript = @"
`$ErrorActionPreference = "Stop"
`$target = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String("$targetBase64")
)
$selectorSource
function ConvertTo-LocalNormalizedFilesystemPath {
    [OutputType([String])]
    param(
        [AllowNull()]
        [String]`$Path
    )

    if ([String]::IsNullOrWhiteSpace(`$Path)) {
        return `$null
    }
    try {
        `$item = Get-Item -LiteralPath `$Path -Force -ErrorAction Stop
        if (`$item -isnot [IO.DirectoryInfo]) {
            return `$null
        }
        `$normalized = [IO.Path]::GetFullPath([string]`$item.FullName)
        `$root = [IO.Path]::GetPathRoot(`$normalized)
        if (`$normalized.Length -gt `$root.Length) {
            `$normalized = `$normalized.TrimEnd([IO.Path]::DirectorySeparatorChar)
        }
        return `$normalized
    } catch {
        return `$null
    }
}

function Get-LocalShellWindowEntries {
    [OutputType([Object[]])]
    param(
        [Parameter(Mandatory)]
        [Object]`$Shell
    )

    `$entries = @()
    foreach (`$window in @(`$Shell.Windows())) {
        if (`$null -eq `$window) {
            throw "ShellWindows returned a null window"
        }
        try {
            `$hwnd = [Int64]`$window.HWND
        } catch {
            throw "ShellWindows window does not expose a HWND"
        }
        if (`$hwnd -eq 0) {
            throw "ShellWindows window exposed an invalid HWND"
        }
        `$entries += [PSCustomObject]@{
            hwnd = `$hwnd
            window = `$window
        }
    }
    if (@(`$entries | Select-Object -ExpandProperty hwnd -Unique).Count -ne `$entries.Count) {
        throw "ShellWindows returned duplicate HWND entries"
    }
    return @(`$entries)
}

function Get-LocalShellWindowFilesystemPath {
    [OutputType([String])]
    param(
        [Parameter(Mandatory)]
        [Object]`$Window
    )

    try {
        `$path = [string]`$Window.Document.Folder.Self.Path
    } catch {
        return `$null
    }
    return ConvertTo-LocalNormalizedFilesystemPath -Path `$path
}

function Exit-LocalNativeShellbagChild {
    param(
        [Parameter(Mandatory)]
        [Int32]`$Code
    )

    exit `$Code
}

function Write-LocalNativeShellbagStage {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(211, 212, 213, 214, 215, 216, 217, 218, 219)]
        [Int32]`$Code
    )

    [Console]::Out.WriteLine("FMB_STAGE:`$Code")
    [Console]::Out.Flush()
}

try {
    Write-LocalNativeShellbagStage -Code 211
    `$normalizedTarget = ConvertTo-LocalNormalizedFilesystemPath -Path `$target
    if ([String]::IsNullOrWhiteSpace(`$normalizedTarget)) {
        Exit-LocalNativeShellbagChild -Code 211
    }
} catch {
    Exit-LocalNativeShellbagChild -Code 211
}

try {
    Write-LocalNativeShellbagStage -Code 212
    `$shell = New-Object -ComObject Shell.Application
    `$preexistingWindows = @(
        foreach (`$entry in @(Get-LocalShellWindowEntries -Shell `$shell)) {
            [PSCustomObject]@{
                hwnd = [Int64]`$entry.hwnd
                normalized_path = Get-LocalShellWindowFilesystemPath -Window `$entry.window
                window = `$entry.window
            }
        }
    )
} catch {
    Exit-LocalNativeShellbagChild -Code 212
}

try {
    Write-LocalNativeShellbagStage -Code 213
    `$shell.Explore(`$target) | Out-Null
} catch {
    Exit-LocalNativeShellbagChild -Code 213
}
`$exact_target_window_matched = `$false
`$exact_target_window_closed = `$false
`$matchedHwnd = `$null
`$matchWatch = [Diagnostics.Stopwatch]::StartNew()
do {
    try {
        Write-LocalNativeShellbagStage -Code 214
        `$currentWindows = @(
            foreach (`$entry in @(Get-LocalShellWindowEntries -Shell `$shell)) {
                [PSCustomObject]@{
                    hwnd = [Int64]`$entry.hwnd
                    normalized_path = Get-LocalShellWindowFilesystemPath -Window `$entry.window
                    window = `$entry.window
                }
            }
        )
        `$matchingWindows = @(
            Select-LocalCausalExactTargetShellWindows -BeforeWindows `$preexistingWindows -AfterWindows `$currentWindows -NormalizedTarget `$normalizedTarget
        )
    } catch {
        Exit-LocalNativeShellbagChild -Code 214
    }
    if (`$matchingWindows.Count -gt 1) {
        Write-LocalNativeShellbagStage -Code 215
        Exit-LocalNativeShellbagChild -Code 215
    }
    if (`$matchingWindows.Count -eq 1) {
        `$matchedHwnd = [Int64]`$matchingWindows[0].hwnd
        try {
            Write-LocalNativeShellbagStage -Code 217
            `$matchingWindows[0].window.Quit()
        } catch {
            Exit-LocalNativeShellbagChild -Code 217
        }
        `$exact_target_window_matched = `$true
        break
    }
    Start-Sleep -Milliseconds 200
} while (`$matchWatch.Elapsed.TotalSeconds -lt $matchSeconds)
if (-not `$exact_target_window_matched -or `$null -eq `$matchedHwnd) {
    Write-LocalNativeShellbagStage -Code 216
    Exit-LocalNativeShellbagChild -Code 216
}

`$closeWatch = [Diagnostics.Stopwatch]::StartNew()
do {
    try {
        Write-LocalNativeShellbagStage -Code 218
        `$activeHwnds = @(
            Get-LocalShellWindowEntries -Shell `$shell |
                ForEach-Object { [Int64]`$_.hwnd }
        )
    } catch {
        Exit-LocalNativeShellbagChild -Code 218
    }
    if (`$activeHwnds -notcontains [Int64]`$matchedHwnd) {
        `$exact_target_window_closed = `$true
        break
    }
    Start-Sleep -Milliseconds 200
} while (`$closeWatch.Elapsed.TotalSeconds -lt $closeSeconds)
if (-not `$exact_target_window_closed) {
    Write-LocalNativeShellbagStage -Code 219
    Exit-LocalNativeShellbagChild -Code 219
}
[Console]::Out.WriteLine("FMB_DONE:0")
[Console]::Out.Flush()
Exit-LocalNativeShellbagChild -Code 0
"@
    $dispatch = Invoke-LocalNativeShellbagScheduledWorker -ChildScript $childScript `
        -ExpectedSessionId $ExpectedSessionId
    return [PSCustomObject][ordered]@{
        scheduled_task_completed = [Bool]$dispatch.scheduled_task_completed
        scheduled_task_unregistered = [Bool]$dispatch.scheduled_task_unregistered
        dispatch_elapsed_ms = [Int64]$dispatch.dispatch_elapsed_ms
        exact_target_window_matched = $true
        exact_target_window_closed = $true
    }
}


function New-LocalNativeShellbagReceipt {
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Target
    )

    $script:LocalNativeShellbagDispatchDiagnostic = $null
    $script:LocalNativeBagMruSnapshotDiagnostic = $null
    $script:LocalNativeBagMruSnapshotPhase = 'unobserved'
    $script:LocalNativeBagMruSnapshotCount = 0
    $visitWatch = [Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-Path -LiteralPath $Target -PathType Container)) {
        throw "Native Shellbag target directory does not exist"
    }
    $processes = @(
        Get-CimInstance -ClassName Win32_Process `
            -Filter "Name = 'explorer.exe'" -ErrorAction Stop
    )
    if (-not (Test-LocalInteractiveVagrantExplorer -Processes $processes)) {
        throw "Exactly one owned interactive vagrant Explorer is required"
    }
    $sessionIds = @(
        Get-LocalOwnedInteractiveExplorerSessionIds -Processes $processes
    )
    $script:LocalNativeBagMruSnapshotPhase = 'pre_baseline'
    $before = Get-LocalStableNativeBagMruSnapshot -Target $Target
    $exploreWatch = [Diagnostics.Stopwatch]::StartNew()
    $action = Invoke-LocalInteractiveShellExplore -Target $Target `
        -ExpectedSessionId $sessionIds[0]
    $exploreElapsedMs = [Int64]$exploreWatch.ElapsedMilliseconds

    $script:LocalNativeBagMruSnapshotPhase = 'delta'
    $deltaWatch = [Diagnostics.Stopwatch]::StartNew()
    $delta = $null
    do {
        Start-Sleep -Milliseconds 300
        $after = $null
        $delta = $null
        try {
            $after = Get-LocalNativeBagMruSnapshot -Target $Target
            $delta = Get-LocalNativeBagMruDelta -Before $before -After $after
        } catch {
            $snapshotFailure = [string]$_.Exception.Message
            if (
                (Test-LocalPermanentBagMruSnapshotFailure `
                    -Message $snapshotFailure) -or
                -not (Test-LocalTransientBagMruSnapshotFailure `
                    -Message $snapshotFailure)
            ) {
                throw
            }
            $after = $null
            $delta = $null
        }
    } while (
        (
            $null -eq $delta -or
            $delta.qualifying_key_count -lt 1
        ) -and
        $deltaWatch.Elapsed.TotalSeconds -lt 20
    )
    if ($null -eq $delta -or $delta.qualifying_key_count -lt 1) {
        throw (
            "Explorer navigation did not produce a linked native BagMRU " +
            "numeric/MRUListEx delta"
        )
    }

    $script:LocalNativeBagMruSnapshotPhase = 'post_stability'
    $stableAfter = Get-LocalStableNativeBagMruSnapshot -Target $Target
    $stableDelta = Get-LocalNativeBagMruDelta `
        -Before $before -After $stableAfter
    if ($stableDelta.qualifying_key_count -lt 1) {
        throw (
            "Stable Explorer state did not retain a linked native BagMRU " +
            "numeric/MRUListEx delta"
        )
    }
    $delta = $stableDelta

    return [PSCustomObject][ordered]@{
        interactive_vagrant_explorer_verified = $true
        stable_pre_snapshots_verified = $true
        native_bagmru_numeric_binary_verified = $true
        native_mrulistex_structure_verified = $true
        custom_string_hint_absent = $true
        changed_key_count = [Int32]$delta.qualifying_key_count
        changed_numeric_value_count = [Int32]$delta.changed_numeric_value_count
        changed_mrulistex_count = [Int32]$delta.changed_mrulistex_count
        scheduled_task_completed = [Bool]$action.scheduled_task_completed
        scheduled_task_unregistered = [Bool]$action.scheduled_task_unregistered
        exact_target_window_matched = [Bool]$action.exact_target_window_matched
        exact_target_window_closed = [Bool]$action.exact_target_window_closed
        visit_elapsed_ms = [Int64]$visitWatch.ElapsedMilliseconds
        explore_elapsed_ms = [Int64]$exploreElapsedMs
        dispatch_elapsed_ms = [Int64]$action.dispatch_elapsed_ms
        snapshot_count = [Int32]$script:LocalNativeBagMruSnapshotCount
    }
}

function Get-LocalNativeShellbagFailureCode {
    [OutputType([String])]
    param([AllowNull()][AllowEmptyString()][String]$Message)

    switch -CaseSensitive -Exact ($Message) {
        "Unable to establish the current WinRM identity" { return "winrm_identity_unavailable" }
        "Native Shellbag action requires the local vagrant identity" { return "winrm_identity_mismatch" }
        "Explorer process enumeration returned a null entry" { return "explorer_enumeration_null" }
        "Explorer process enumeration returned a non-Explorer process" { return "explorer_enumeration_mismatch" }
        "Explorer GetOwner failed" { return "explorer_owner_query_failed" }
        "Explorer GetOwner did not return a verified owner" { return "explorer_owner_unverified" }
        "The owned vagrant Explorer process is not interactive" { return "explorer_session_not_interactive" }
        "Exactly one owned interactive vagrant Explorer is required" { return "interactive_explorer_unverified" }
        "The verified Explorer session changed before dispatch" { return "explorer_session_changed" }
        "MRUListEx is not DWORD aligned" { return "mrulistex_alignment_invalid" }
        "MRUListEx has no 0xffffffff terminator" { return "mrulistex_terminator_missing" }
        "MRUListEx contains an early terminator" { return "mrulistex_terminator_early" }
        "MRUListEx contains duplicate links" { return "mrulistex_duplicate_links" }
        "BagMRU snapshot resource boundary exceeded" { return "bagmru_snapshot_resource_limit" }
        "Legacy FMB_Confidential_Path BagMRU hint is forbidden" { return "bagmru_legacy_hint_present" }
        "A custom BagMRU string equal to the target is forbidden" { return "bagmru_custom_hint_present" }
        "A numeric BagMRU value is not REG_BINARY" { return "bagmru_numeric_type_invalid" }
        "MRUListEx is not REG_BINARY" { return "mrulistex_type_invalid" }
        "Numeric BagMRU values exist without MRUListEx" { return "mrulistex_missing" }
        "MRUListEx references a missing numeric BagMRU value" { return "mrulistex_link_missing" }
        "Unable to open a BagMRU subkey" { return "bagmru_subkey_unavailable" }
        "BagMRU did not remain stable for the required quiescence window" { return "bagmru_quiescence_timeout" }
        "Native Shellbag watchdog timed out before child completion" { return "child_watchdog_timeout" }
        "Temporary interactive Explorer scheduled task was not removed" { return "scheduled_task_cleanup_failed" }
        "Interactive Explorer did not complete the exact target window lifecycle" { return "target_window_lifecycle_incomplete" }
        "Native Shellbag target directory does not exist" { return "target_directory_missing" }
        "Explorer navigation did not produce a linked native BagMRU numeric/MRUListEx delta" { return "bagmru_delta_missing" }
        "Stable Explorer state did not retain a linked native BagMRU numeric/MRUListEx delta" { return "bagmru_stable_delta_missing" }
        "Native Shellbag child target normalization failed" { return "child_target_normalization_failed" }
        "Native Shellbag child Shell COM or preexisting window enumeration failed" { return "child_initial_window_enumeration_failed" }
        "Native Shellbag child Explorer dispatch failed" { return "child_explorer_dispatch_failed" }
        "Native Shellbag child exact-target window enumeration failed" { return "child_target_window_enumeration_failed" }
        "Native Shellbag child found multiple exact-target windows" { return "child_target_window_ambiguous" }
        "Native Shellbag child did not match an exact-target window before timeout" { return "child_target_window_timeout" }
        "Native Shellbag child exact-target window close request failed" { return "child_target_window_close_failed" }
        "Native Shellbag child exact-target close enumeration failed" { return "child_close_window_enumeration_failed" }
        "Native Shellbag child did not confirm exact-target window closure before timeout" { return "child_target_close_timeout" }
        "Native Shellbag watchdog timed out before a child stage" { return "child_stage_watchdog_timeout" }
        "Native Shellbag watchdog rejected the child execution boundary" { return "child_execution_boundary_rejected" }
        "Native Shellbag child failed without a recognized stage code" { return "child_stage_unrecognized" }
        "Native Shellbag child reached success but did not terminate" { return "child_success_teardown_timeout" }
        "Native Shellbag owned child termination failed" { return "child_termination_failed" }
        "Native Shellbag scheduled task did not stop" { return "scheduled_task_stop_failed" }
        "Native Shellbag scheduled task remained queued" { return "scheduled_task_queued_timeout" }
        "Native Shellbag scheduled task start was not observed" { return "scheduled_task_start_unobserved" }
        "Native Shellbag child source exceeds its boundary" { return "child_source_boundary_exceeded" }
        "Native Shellbag watchdog command exceeds its boundary" { return "watchdog_command_boundary_exceeded" }
        "Native Shellbag scheduled task cleanup failed" { return "scheduled_task_cleanup_failed" }
        "Native Shellbag scheduled task was not freshly registered" { return "scheduled_task_registration_not_fresh" }
        default { return "unrecognized_native_failure" }
    }
}

function New-LocalNativeShellbagWatchdogScript {
    [OutputType([String])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][String]$ChildScript,
        [ValidateRange(1, 3600)][Int32]$TimeoutSeconds = 42
    )
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($ChildScript)
    if ($plainBytes.Length -gt 65536) { throw "Native Shellbag child source exceeds its boundary" }
    $buffer = [IO.MemoryStream]::new()
    try {
        $compressor = [IO.Compression.GZipStream]::new($buffer, [IO.Compression.CompressionMode]::Compress, $true)
        try { $compressor.Write($plainBytes, 0, $plainBytes.Length) } finally { $compressor.Dispose() }
        $payload = [Convert]::ToBase64String($buffer.ToArray())
    } finally { $buffer.Dispose() }
    $digest = Get-LocalSha256Hex -Bytes $plainBytes
    $watchdog = @'
$watch = [Diagnostics.Stopwatch]::StartNew()
$ErrorActionPreference = 'Stop'
$result = 221
$worker = $null
$lastStage = 220
$done = $false
$started = $false
try {
    $compressed = [IO.MemoryStream]::new([Convert]::FromBase64String('__FMB_PAYLOAD__'))
    $plain = [IO.MemoryStream]::new()
    try {
        $inflater = [IO.Compression.GZipStream]::new($compressed, [IO.Compression.CompressionMode]::Decompress)
        try { $inflater.CopyTo($plain) } finally { $inflater.Dispose() }
        $bytes = $plain.ToArray()
    } finally { $compressed.Dispose(); $plain.Dispose() }
    if ($bytes.Length -gt 65536) { throw 'Child source boundary' }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() } finally { $hash.Dispose() }
    if ($actual -cne '__FMB_SHA256__') { throw 'Child source hash' }
    $child = [Text.Encoding]::UTF8.GetString($bytes)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = (Get-Process -Id $PID).Path
    $info.Arguments = '-NoProfile -NonInteractive -OutputFormat Text '
    if ($env:OS -eq 'Windows_NT') { $info.Arguments += '-STA -WindowStyle Hidden ' }
    $info.Arguments += '-EncodedCommand ' + $encoded
    if (($info.FileName.Length + $info.Arguments.Length + 4) -gt 32767) { throw 'Child command boundary' }
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $worker = [Diagnostics.Process]::new()
    $worker.StartInfo = $info
    if (-not $worker.Start()) { throw 'Child process start' }
    $started = $true
    $stdoutBuffer = New-Object Char[] 64
    $lineBuffer = [Text.StringBuilder]::new(32)
    $stdout = $worker.StandardOutput.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
    $stderrBuffer = New-Object Char[] 4096
    $stderr = $worker.StandardError.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length)
    $stdoutEnded = $false
    $stderrEnded = $false
    $lineCount = 0
    while ($true) {
        while (-not $stdoutEnded -and $stdout.IsCompleted) {
            $count = $stdout.GetAwaiter().GetResult()
            if ($count -eq 0) {
                if ($lineBuffer.Length -ne 0) { throw 'Unterminated child stdout' }
                $stdoutEnded = $true
                break
            }
            for ($index = 0; $index -lt $count; $index += 1) {
                $character = $stdoutBuffer[$index]
                if ($character -eq "`n") {
                    $line = $lineBuffer.ToString()
                    $lineBuffer.Clear() | Out-Null
                    if ($line.EndsWith("`r")) { $line = $line.Substring(0, $line.Length - 1) }
                    $lineCount += 1
                    if ($lineCount -gt 512) { throw 'Child stdout line boundary' }
                    if ($line -cmatch '^FMB_STAGE:(21[1-9])$' -and -not $done) { $lastStage = [Int32]$Matches[1] }
                    elseif ($line -ceq 'FMB_DONE:0' -and -not $done -and $lastStage -eq 218) { $done = $true }
                    else { throw 'Child stdout protocol' }
                } else {
                    if ($lineBuffer.Length -ge 32) { throw 'Child stdout character boundary' }
                    $lineBuffer.Append($character) | Out-Null
                }
            }
            $stdout = $worker.StandardOutput.ReadAsync($stdoutBuffer, 0, $stdoutBuffer.Length)
        }
        if (-not $stderrEnded -and $stderr.IsCompleted) {
            $count = $stderr.GetAwaiter().GetResult()
            if ($count -eq 0) { $stderrEnded = $true }
            else { $stderr = $worker.StandardError.ReadAsync($stderrBuffer, 0, $stderrBuffer.Length) }
        }
        if ($worker.HasExited -and $stdoutEnded -and $stderrEnded) {
            $exitCode = [Int32]$worker.ExitCode
            if ($exitCode -eq 0 -and $done) { $result = 0 }
            elseif ($exitCode -in 211..221 -and -not $done) { $result = $exitCode }
            else { $result = 221 }
            break
        }
        if ($watch.Elapsed.TotalSeconds -ge __FMB_TIMEOUT__) {
            $result = if ($done) { 222 } else { $lastStage }
            break
        }
        Start-Sleep -Milliseconds 10
    }
} catch {
    $result = 221
} finally {
    if ($null -ne $worker) {
        if ($started -and -not $worker.HasExited) {
            try {
                $worker.Kill()
                if (-not $worker.WaitForExit(2000)) { $result = 223 }
            } catch { $result = 223 }
        }
        $worker.Dispose()
    }
}
exit $result
'@
    return $watchdog.Replace('__FMB_PAYLOAD__', $payload).Replace('__FMB_SHA256__', $digest).Replace('__FMB_TIMEOUT__', [string]$TimeoutSeconds)
}

function Get-LocalNativeShellbagProcessDiagnostic {
    param(
        [AllowEmptyCollection()][Object[]]$OwnedProcesses,
        [ValidateSet('supervisor', 'worker')][String]$Kind
    )
    $summary = [ordered]@{ age_wall_ms = $null; cpu_cumulative_ms = $null; thread_count = $null }
    try {
        $matches = @($OwnedProcesses | Where-Object { $_.kind -ceq $Kind })
        if ($matches.Count -ne 1) { return [PSCustomObject]$summary }
        $native = $matches[0].process
    } catch { return [PSCustomObject]$summary }
    try {
        $created = $native.CreationDate
        if ($created -is [DateTime]) {
            $age = [DateTime]::UtcNow - $created.ToUniversalTime()
            if ($age.Ticks -ge 0) { $summary.age_wall_ms = [Int64]([Decimal]::Floor([Decimal]$age.Ticks / 10000)) }
        }
    } catch {}
    try {
        $kernel = $native.KernelModeTime
        $user = $native.UserModeTime
        if ($kernel -is [UInt64] -and $user -is [UInt64]) {
            $summary.cpu_cumulative_ms = [Int64]([Decimal]::Floor(([Decimal]$kernel + [Decimal]$user) / 10000))
        }
    } catch {}
    try {
        $threads = $native.ThreadCount
        if (($threads -is [UInt32] -or $threads -is [Int32]) -and
            $threads -ge 0 -and $threads -le [Int32]::MaxValue) {
            $summary.thread_count = [Int32]$threads
        }
    } catch {}
    return [PSCustomObject]$summary
}

function Get-LocalNativeShellbagDispatchDiagnostic {
    $raw = $script:LocalNativeShellbagDispatchDiagnostic
    $state = 'unobserved'
    if ($raw.task_state -cin @('Unknown', 'Disabled', 'Queued', 'Ready', 'Running')) {
        $state = [string]$raw.task_state
    }
    $cleanup = 'unobserved'
    if ($raw.cleanup_code -cin @('not_registered', 'verified', 'stop_failed', 'unregister_failed', 'process_stop_failed', 'query_failed')) {
        $cleanup = [string]$raw.cleanup_code
    }
    $result = $null
    if ($raw.last_task_result -is [UInt32]) { $result = [UInt32]$raw.last_task_result }
    $elapsed = $null
    if ($raw.elapsed_ms -is [Int64] -and $raw.elapsed_ms -ge 0 -and $raw.elapsed_ms -le 3660000) {
        $elapsed = [Int64]$raw.elapsed_ms
    }
    $supervisors = $null
    $workers = $null
    if ($raw.supervisor_count -is [Int32] -and $raw.supervisor_count -ge 0 -and $raw.supervisor_count -le 4) {
        $supervisors = [Int32]$raw.supervisor_count
    }
    if ($raw.worker_count -is [Int32] -and $raw.worker_count -ge 0 -and $raw.worker_count -le 4) {
        $workers = [Int32]$raw.worker_count
    }
    $phases = @{}
    foreach ($key in @('start_scheduled_task_elapsed_ms', 'cleanup_elapsed_ms')) {
        $phases[$key] = $null
        if ($raw.$key -is [Int64] -and $raw.$key -ge 0 -and $raw.$key -le 3660000) {
            $phases[$key] = [Int64]$raw.$key
        }
    }
    $metrics = @{}
    foreach ($kind in @('supervisor', 'worker')) {
        $count = if ($kind -ceq 'supervisor') { $supervisors } else { $workers }
        foreach ($metric in @('age_wall_ms', 'cpu_cumulative_ms', 'thread_count')) {
            $key = $kind + '_' + $metric
            $metrics[$key] = $null
            if ($raw.process_query_succeeded -isnot [Bool] -or -not $raw.process_query_succeeded -or $count -ne 1) { continue }
            $value = $raw.$key
            if ($metric -ceq 'thread_count') {
                if ($value -is [Int32] -and $value -ge 0) { $metrics[$key] = [Int32]$value }
            } elseif ($value -is [Int64] -and $value -ge 0) {
                $metrics[$key] = [Int64]$value
            }
        }
    }
    return [PSCustomObject][ordered]@{
        task_state = $state
        fresh_registration_verified = $raw.fresh_registration_verified -is [Bool] -and $raw.fresh_registration_verified
        ran_this_dispatch = $raw.ran_this_dispatch -is [Bool] -and $raw.ran_this_dispatch
        last_task_result = $result
        start_scheduled_task_elapsed_ms = $phases.start_scheduled_task_elapsed_ms
        parent_elapsed_ms = $elapsed
        process_query_succeeded = $raw.process_query_succeeded -is [Bool] -and $raw.process_query_succeeded
        supervisor_count = $supervisors
        worker_count = $workers
        supervisor_age_wall_ms = $metrics.supervisor_age_wall_ms
        supervisor_cpu_cumulative_ms = $metrics.supervisor_cpu_cumulative_ms
        supervisor_thread_count = $metrics.supervisor_thread_count
        worker_age_wall_ms = $metrics.worker_age_wall_ms
        worker_cpu_cumulative_ms = $metrics.worker_cpu_cumulative_ms
        worker_thread_count = $metrics.worker_thread_count
        cleanup_code = $cleanup
        cleanup_elapsed_ms = $phases.cleanup_elapsed_ms
    }
}

function Get-LocalNativeShellbagOwnedProcesses {
    param(
        [Parameter(Mandatory)][String]$SupervisorCommand,
        [Parameter(Mandatory)][String]$WorkerCommand,
        [Parameter(Mandatory)][Int32]$ExpectedSessionId
    )
    $processes = @(Get-CimInstance -ClassName Win32_Process `
        -Filter "Name = 'powershell.exe'" -OperationTimeoutSec 2 -ErrorAction Stop)
    foreach ($process in $processes) {
        if ([Int32]$process.SessionId -ne $ExpectedSessionId) { continue }
        $command = [string]$process.CommandLine
        $kind = $null
        if ($command.EndsWith(' -EncodedCommand ' + $SupervisorCommand, [StringComparison]::Ordinal)) { $kind = 'supervisor' }
        elseif ($command.EndsWith(' -EncodedCommand ' + $WorkerCommand, [StringComparison]::Ordinal)) { $kind = 'worker' }
        if ($null -ne $kind) {
            [PSCustomObject]@{ kind = $kind; process = $process }
        }
    }
}

function Invoke-LocalNativeShellbagScheduledWorker {
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][String]$ChildScript,
        [Parameter(Mandatory)][ValidateRange(1, [Int32]::MaxValue)][Int32]$ExpectedSessionId
    )
    $script:LocalNativeShellbagDispatchDiagnostic = $null
    Import-Module ScheduledTasks -ErrorAction Stop
    $nonce = [Guid]::NewGuid().ToString('N')
    $taskName = 'UserSession_' + $nonce
    $registered = $false
    $unregistered = $false
    $primaryError = $null
    $dispatchWatch = $null
    $script:LocalNativeShellbagDispatchDiagnostic = @{
        cleanup_code = 'not_registered'
        fresh_registration_verified = $false
        ran_this_dispatch = $false
        process_query_succeeded = $false
    }
    $diagnostic = $script:LocalNativeShellbagDispatchDiagnostic
    $visitBudgets = Get-LocalNativeShellbagVisitBudgets
    $childSeconds = [Int32]$visitBudgets.child_seconds
    $dispatchSeconds = [Int32]$visitBudgets.dispatch_seconds
    try {
        $ChildScript = '# in-memory dispatch ' + $nonce + [Environment]::NewLine + $ChildScript
        $workerCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ChildScript))
        $watchdogScript = New-LocalNativeShellbagWatchdogScript -ChildScript $ChildScript -TimeoutSeconds $childSeconds
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($watchdogScript))
        if ($encodedCommand.Length + 256 -gt 32767) {
            throw 'Native Shellbag watchdog command exceeds its boundary'
        }
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument ('-NoProfile -NonInteractive -STA -WindowStyle Hidden -EncodedCommand ' + $encodedCommand)
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable:$false
        Register-ScheduledTask -TaskName $taskName -Action $action `
            -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        $registered = $true
        $baselineTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $baselineInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
        $baselineLastRunTime = $baselineInfo.LastRunTime
        if ([string]$baselineTask.State -cne 'Ready' -or
            [UInt32]$baselineInfo.LastTaskResult -ne 267011 -or
            $baselineLastRunTime -isnot [DateTime]) {
            throw 'Native Shellbag scheduled task was not freshly registered'
        }
        $diagnostic.fresh_registration_verified = $true
        $startWatch = $null
        try { $startWatch = [Diagnostics.Stopwatch]::StartNew() } catch {}
        try {
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $dispatchWatch = [Diagnostics.Stopwatch]::StartNew()
        } finally {
            try {
                if ($null -ne $startWatch) { $diagnostic.start_scheduled_task_elapsed_ms = [Int64]$startWatch.ElapsedMilliseconds }
            } catch {}
        }
        $completed = $false
        do {
            Start-Sleep -Milliseconds 250
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
            $ranThisDispatch = $info.LastRunTime -is [DateTime] -and
                $info.LastRunTime -ne $baselineLastRunTime
            $completed = $ranThisDispatch -and [string]$task.State -ceq 'Ready' -and
                [UInt32]$info.LastTaskResult -notin @(267009, 267011, 267045)
        } while (-not $completed -and $dispatchWatch.Elapsed.TotalSeconds -lt $dispatchSeconds)
        $diagnostic.task_state = [string]$task.State
        $diagnostic.ran_this_dispatch = [Bool]$ranThisDispatch
        $diagnostic.last_task_result = [UInt32]$info.LastTaskResult
        $diagnostic.elapsed_ms = [Int64]$dispatchWatch.ElapsedMilliseconds
        try {
            $owned = @(Get-LocalNativeShellbagOwnedProcesses -SupervisorCommand $encodedCommand `
                -WorkerCommand $workerCommand -ExpectedSessionId $ExpectedSessionId)
            $diagnostic.process_query_succeeded = $true
            $diagnostic.supervisor_count = [Int32]@($owned | Where-Object { $_.kind -ceq 'supervisor' }).Count
            $diagnostic.worker_count = [Int32]@($owned | Where-Object { $_.kind -ceq 'worker' }).Count
        } catch {
            $diagnostic.process_query_succeeded = $false
        }
        if ($diagnostic.process_query_succeeded) {
            foreach ($kind in @('supervisor', 'worker')) {
                try {
                    $summary = Get-LocalNativeShellbagProcessDiagnostic -OwnedProcesses $owned -Kind $kind
                    $diagnostic[$kind + '_age_wall_ms'] = $summary.age_wall_ms
                    $diagnostic[$kind + '_cpu_cumulative_ms'] = $summary.cpu_cumulative_ms
                    $diagnostic[$kind + '_thread_count'] = $summary.thread_count
                } catch {}
            }
        }
        if (-not $completed) {
            if ([string]$task.State -ceq 'Queued') { throw 'Native Shellbag scheduled task remained queued' }
            if (-not $ranThisDispatch) { throw 'Native Shellbag scheduled task start was not observed' }
            throw 'Native Shellbag watchdog timed out before child completion'
        }
        if ([UInt32]$info.LastTaskResult -ne 0) {
            throw (Get-LocalNativeShellbagChildFailureMessage -ExitCode ([UInt32]$info.LastTaskResult))
        }
    } catch {
        $primaryError = $_
        try {
            if ($null -ne $dispatchWatch -and $null -eq $diagnostic.elapsed_ms) {
                $diagnostic.elapsed_ms = [Int64]$dispatchWatch.ElapsedMilliseconds
            }
        } catch {}
    } finally {
        $cleanupWatch = $null
        try { if ($registered) { $cleanupWatch = [Diagnostics.Stopwatch]::StartNew() } } catch {}
        if ($registered) {
            $diagnostic.cleanup_code = 'verified'
            try {
                $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
                if ([string]$task.State -in @('Running', 'Queued')) {
                    Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
                    $stopWatch = [Diagnostics.Stopwatch]::StartNew()
                    do {
                        Start-Sleep -Milliseconds 100
                        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
                    } while ([string]$task.State -in @('Running', 'Queued') -and $stopWatch.Elapsed.TotalSeconds -lt 3)
                    if ([string]$task.State -in @('Running', 'Queued')) { $diagnostic.cleanup_code = 'stop_failed' }
                }
            } catch { $diagnostic.cleanup_code = 'stop_failed' }
            try {
                $owned = @(Get-LocalNativeShellbagOwnedProcesses -SupervisorCommand $encodedCommand `
                    -WorkerCommand $workerCommand -ExpectedSessionId $ExpectedSessionId)
                if (@($owned | Where-Object { $_.kind -ceq 'worker' }).Count -gt 1 -or
                    @($owned | Where-Object { $_.kind -ceq 'supervisor' }).Count -gt 1) {
                    $diagnostic.cleanup_code = 'process_stop_failed'
                } else {
                    foreach ($entry in @($owned | Sort-Object @{Expression = { if ($_.kind -ceq 'worker') { 0 } else { 1 } }})) {
                        $process = [Diagnostics.Process]::GetProcessById([Int32]$entry.process.ProcessId)
                        try {
                            $pinnedHandle = $process.Handle
                            if ($process.SessionId -ne $ExpectedSessionId -or
                                $process.StartTime.ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff') -cne $entry.process.CreationDate.ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff')) {
                                $diagnostic.cleanup_code = 'process_stop_failed'
                                continue
                            }
                            $process.Kill()
                            if (-not $process.WaitForExit(2000)) { $diagnostic.cleanup_code = 'process_stop_failed' }
                        } finally { $process.Dispose() }
                    }
                    $remaining = @(Get-LocalNativeShellbagOwnedProcesses -SupervisorCommand $encodedCommand `
                        -WorkerCommand $workerCommand -ExpectedSessionId $ExpectedSessionId)
                    if ($remaining.Count -ne 0) { $diagnostic.cleanup_code = 'process_stop_failed' }
                }
            } catch { $diagnostic.cleanup_code = 'query_failed' }
            try {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                $remainingTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { [String]$_.TaskName -ceq $taskName })
                $unregistered = $remainingTasks.Count -eq 0
                if (-not $unregistered) { $diagnostic.cleanup_code = 'unregister_failed' }
            } catch { $diagnostic.cleanup_code = 'unregister_failed' }
        }
        try {
            if ($null -ne $cleanupWatch) { $diagnostic.cleanup_elapsed_ms = [Int64]$cleanupWatch.ElapsedMilliseconds }
        } catch {}
    }
    if ($null -ne $primaryError) { throw $primaryError }
    if ($diagnostic.cleanup_code -ne 'verified') { throw 'Native Shellbag scheduled task cleanup failed' }
    return [PSCustomObject][ordered]@{
        scheduled_task_completed = $true
        scheduled_task_unregistered = [Bool]$unregistered
        dispatch_elapsed_ms = [Int64]$diagnostic.elapsed_ms
    }
}
