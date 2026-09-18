[CmdletBinding()]
param(
    [ValidateRange(60, 900)] [int] $StartupDeadlineSeconds = 300,
    [ValidateSet(30)] [int] $FailureDeadlineSeconds = 30,
    [ValidateRange(1, 7)] [int] $MinimumSealedSegmentsPerStream = 1,
    [ValidateSet("FAILURE_CONTAINMENT_TERMINAL")]
    [string] $FailureContainmentEvent = "FAILURE_CONTAINMENT_TERMINAL",
    [ValidateSet("RawQualificationFailureContainmentV2")]
    [string] $FailureContainmentSchema = "RawQualificationFailureContainmentV2",
    [string] $OutputBase = "artifacts/fg",
    [switch] $BootstrapValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:FaultGateZeroDigest = "0" * 64
$script:FaultGateEmptySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
$script:FaultGateTargetExitCode = [uint32]0xEE31
$script:FaultGateContainmentExitCode = [uint32]0xEE02
$script:FaultGateFallbackExitCode = [uint32]0xEE41
$script:FaultGateJournalSchema = "RawQualificationFaultGateEventV1"
# raw_campaign reserves min(30, max(1, overlap/10)) seconds so the
# predecessor seals before the successor root segment.  The fault profile is
# rotation=240, overlap=30, hence 240 + 30 - 3 = 267 seconds.
$script:FaultGateGenerationZeroDurationSeconds = [uint64]267
$script:FaultGateSpecRevision = "976cc580553890e92031b77306147c0ed1de5a46"
$script:FaultGateLegacyMaximumPathCharacters = 259
$script:FaultGateMaximumRunRelativePathCharacters = 131
$script:FaultGateMaximumTelemetryRecordBytes = [uint64](64 * 1024)
$script:FaultGateMaximumTelemetryPartialTailBytes = $script:FaultGateMaximumTelemetryRecordBytes - 1
$script:FaultGateMaximumProgressRecordBytes = [uint64](1024 * 1024)
$script:FaultGateMaximumProgressPartialTailBytes = $script:FaultGateMaximumProgressRecordBytes

function Assert-FaultGate {
    param([Parameter(Mandatory = $true)] [bool] $Condition, [Parameter(Mandatory = $true)] [string] $Message)
    if (-not $Condition) { throw $Message }
}

function Assert-FaultGateLegacyPathBudget {
    param([Parameter(Mandatory = $true)] [string] $OutputRoot)
    $canonicalOutputRoot = [IO.Path]::GetFullPath($OutputRoot).TrimEnd('\')
    $gateIdTemplate = "f-" + (("a" * 16) -join '')
    $runIdTemplate = (("2" * 16) -join '') + "-dual-" + (("a" * 12) -join '')
    $campaignIdTemplate = (("9" * 19) -join '') + "-ETHUSDT-raw-" + (("a" * 12) -join '')
    $sessionIdTemplate = (("9" * 19) -join '') + "-ETHUSDT-g000-" + (("a" * 12) -join '')
    $segmentRelativeTemplate = [IO.Path]::Combine(
        $campaignIdTemplate,
        "generations",
        $sessionIdTemplate,
        "trade",
        "segment-999999.bnraw")
    $transportJournalRelativeTemplate = [IO.Path]::Combine(
        $campaignIdTemplate,
        "generations",
        $sessionIdTemplate,
        "transport-depth-events.jsonl")
    $deepestRelativeTemplate = @($segmentRelativeTemplate, $transportJournalRelativeTemplate) |
        Sort-Object Length -Descending |
        Select-Object -First 1
    if ($segmentRelativeTemplate.Length -ne 129 -or
        $transportJournalRelativeTemplate.Length -ne 131 -or
        $deepestRelativeTemplate.Length -ne $script:FaultGateMaximumRunRelativePathCharacters) {
        throw "Fault-gate legacy path model drifted from the fixed raw artifact naming contract."
    }
    $projectedRunRoot = [IO.Path]::Combine(
        $canonicalOutputRoot,
        $gateIdTemplate,
        "qualification",
        $runIdTemplate)
    $projectedDeepestPath = [IO.Path]::Combine($projectedRunRoot, $deepestRelativeTemplate)
    if ($projectedDeepestPath.Length -gt $script:FaultGateLegacyMaximumPathCharacters) {
        throw ("OutputBase exceeds the fail-closed Windows PowerShell 5.1 path budget: projected deepest path is {0} characters, maximum is {1}. Use a shorter repository-relative OutputBase." -f `
            $projectedDeepestPath.Length, $script:FaultGateLegacyMaximumPathCharacters)
    }
    return [pscustomobject][ordered]@{
        projected_run_root_characters = [uint64]$projectedRunRoot.Length
        projected_deepest_path_characters = [uint64]$projectedDeepestPath.Length
        maximum_path_characters = [uint64]$script:FaultGateLegacyMaximumPathCharacters
        maximum_run_relative_path_characters = [uint64]$script:FaultGateMaximumRunRelativePathCharacters
    }
}

function Assert-FaultGateActualPathBudget {
    param(
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] [string] $Path
    )
    $canonicalRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
    $canonicalPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $rootPrefix = $canonicalRoot + '\'
    if (-not $canonicalPath.Equals($canonicalRoot, [StringComparison]::OrdinalIgnoreCase) -and
        -not $canonicalPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Fault-gate path-budget observation escaped RunRoot: $canonicalPath"
    }
    $relativeCharacters = if ($canonicalPath.Equals(
            $canonicalRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        [uint64]0
    }
    else {
        [uint64]($canonicalPath.Length - $rootPrefix.Length)
    }
    if ($canonicalPath.Length -gt $script:FaultGateLegacyMaximumPathCharacters -or
        $relativeCharacters -gt $script:FaultGateMaximumRunRelativePathCharacters) {
        throw ("Observed fault-gate artifact exceeds its fail-closed Windows PowerShell 5.1 path budget: full={0}/{1}, run_relative={2}/{3}, path={4}" -f `
            $canonicalPath.Length,
            $script:FaultGateLegacyMaximumPathCharacters,
            $relativeCharacters,
            $script:FaultGateMaximumRunRelativePathCharacters,
            $canonicalPath)
    }
    return [pscustomobject][ordered]@{
        path = $canonicalPath
        full_path_characters = [uint64]$canonicalPath.Length
        run_relative_path_characters = $relativeCharacters
    }
}

function Assert-FaultGateExactProperties {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)] [string[]] $Names,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $actual = @($Value.PSObject.Properties.Name)
    if (($actual -join "`n") -cne ($Names -join "`n")) {
        throw "$Label has missing, reordered, or unknown properties."
    }
}

function Get-FaultGateJsonUnsignedInteger {
    param([Parameter(Mandatory = $true)] $Value, [Parameter(Mandatory = $true)] [string] $Label, [uint64] $Maximum = [uint64]::MaxValue)
    if ($Value -is [bool] -or $null -eq $Value) { throw "$Label must be a JSON unsigned integer, not boolean/null." }
    $typeCode = [Type]::GetTypeCode($Value.GetType())
    if ($typeCode -eq [TypeCode]::Decimal) {
        [decimal]$decimalValue = $Value
        $decimalFlags = [decimal]::GetBits($decimalValue)[3]
        $decimalScale = ($decimalFlags -shr 16) -band 0xFF
        if ($decimalScale -ne 0 -or $decimalValue -lt [decimal]0 -or $decimalValue -gt [decimal][uint64]::MaxValue) {
            throw "$Label must be an unscaled unsigned integer in the UInt64 range."
        }
        [uint64]$convertedDecimal = $decimalValue
        if ($convertedDecimal -gt $Maximum) { throw "$Label exceeds its unsigned range." }
        return $convertedDecimal
    }
    if ($typeCode -notin @([TypeCode]::Byte, [TypeCode]::UInt16, [TypeCode]::UInt32, [TypeCode]::UInt64, [TypeCode]::SByte, [TypeCode]::Int16, [TypeCode]::Int32, [TypeCode]::Int64)) {
        throw "$Label must be an integral JSON number."
    }
    if ($typeCode -in @([TypeCode]::SByte, [TypeCode]::Int16, [TypeCode]::Int32, [TypeCode]::Int64) -and [int64]$Value -lt 0) {
        throw "$Label must be non-negative."
    }
    [uint64]$converted = $Value
    if ($converted -gt $Maximum) { throw "$Label exceeds its unsigned range." }
    return $converted
}

function Add-FaultGateCheckedUInt64 {
    param(
        [Parameter(Mandatory = $true)] [uint64] $Left,
        [Parameter(Mandatory = $true)] [uint64] $Right,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $remaining = [uint64]([decimal][uint64]::MaxValue - [decimal]$Left)
    if ($Right -gt $remaining) { throw "$Label overflows UInt64." }
    return [uint64]([decimal]$Left + [decimal]$Right)
}

function Get-FaultGateUInt64Successor {
    param([Parameter(Mandatory = $true)] [uint64] $Value, [Parameter(Mandatory = $true)] [string] $Label)
    return Add-FaultGateCheckedUInt64 -Left $Value -Right 1 -Label $Label
}

function Get-FaultGateInclusiveLastUInt64 {
    param(
        [Parameter(Mandatory = $true)] [uint64] $First,
        [Parameter(Mandatory = $true)] [uint64] $Count,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ($Count -eq 0) { throw "$Label has zero cardinality." }
    $countMinusOne = [uint64]([decimal]$Count - [decimal]1)
    return Add-FaultGateCheckedUInt64 -Left $First -Right $countMinusOne -Label $Label
}

function Get-FaultGateInclusiveCountUInt64 {
    param(
        [Parameter(Mandatory = $true)] [uint64] $First,
        [Parameter(Mandatory = $true)] [uint64] $Last,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ($Last -lt $First) { throw "$Label regresses before its first value." }
    $distance = [uint64]([decimal]$Last - [decimal]$First)
    return Add-FaultGateCheckedUInt64 -Left $distance -Right 1 -Label $Label
}

function Multiply-FaultGateCheckedUInt64 {
    param(
        [Parameter(Mandatory = $true)] [uint64] $Left,
        [Parameter(Mandatory = $true)] [uint64] $Right,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ($Left -ne 0) {
        $maximumRight = [uint64][decimal]::Floor(([decimal][uint64]::MaxValue) / [decimal]$Left)
        if ($Right -gt $maximumRight) { throw "$Label overflows UInt64." }
    }
    return [uint64]([decimal]$Left * [decimal]$Right)
}

function Subtract-FaultGateCheckedUInt64 {
    param(
        [Parameter(Mandatory = $true)] [uint64] $Left,
        [Parameter(Mandatory = $true)] [uint64] $Right,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ($Right -gt $Left) { throw "$Label underflows UInt64." }
    return [uint64]([decimal]$Left - [decimal]$Right)
}

function Get-FaultGateJsonSignedInteger {
    param([Parameter(Mandatory = $true)] $Value, [Parameter(Mandatory = $true)] [string] $Label)
    if ($Value -is [bool] -or $null -eq $Value) { throw "$Label must be a JSON signed integer, not boolean/null." }
    $typeCode = [Type]::GetTypeCode($Value.GetType())
    if ($typeCode -notin @([TypeCode]::Byte, [TypeCode]::UInt16, [TypeCode]::UInt32, [TypeCode]::SByte, [TypeCode]::Int16, [TypeCode]::Int32, [TypeCode]::Int64)) {
        throw "$Label must be an integral JSON number in the i64 range."
    }
    return [int64]$Value
}

function Get-FaultGateJsonNumber {
    param([Parameter(Mandatory = $true)] $Value, [Parameter(Mandatory = $true)] [string] $Label)
    if ($Value -is [bool] -or $null -eq $Value) { throw "$Label must be a JSON number, not boolean/null." }
    $typeCode = [Type]::GetTypeCode($Value.GetType())
    if ($typeCode -notin @(
        [TypeCode]::Byte, [TypeCode]::UInt16, [TypeCode]::UInt32, [TypeCode]::UInt64,
        [TypeCode]::SByte, [TypeCode]::Int16, [TypeCode]::Int32, [TypeCode]::Int64,
        [TypeCode]::Single, [TypeCode]::Double, [TypeCode]::Decimal
    )) { throw "$Label must be a JSON number." }
    [double]$converted = $Value
    if ([double]::IsNaN($converted) -or [double]::IsInfinity($converted)) { throw "$Label is not a finite JSON number." }
    return $converted
}

function Assert-FaultGateJsonStringArray {
    param([Parameter(Mandatory = $true)] $Value, [Parameter(Mandatory = $true)] [string] $Label, [switch] $AllowEmpty)
    Assert-FaultGateJsonArray -Value $Value -Label $Label
    $rows = @($Value)
    if (-not $AllowEmpty -and $rows.Count -eq 0) { throw "$Label must not be empty." }
    for ($index = 0; $index -lt $rows.Count; $index++) {
        $null = Get-FaultGateJsonNonEmptyString -Value $rows[$index] -Label "$Label[$index]"
    }
}

function Get-FaultGateJsonNonEmptyString {
    param([Parameter(Mandatory = $true)] $Value, [Parameter(Mandatory = $true)] [string] $Label)
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value)) { throw "$Label must be a non-empty JSON string." }
    return [string]$Value
}

function Get-FaultGateJsonString {
    param(
        [Parameter(Mandatory = $true)] [AllowEmptyString()] $Value,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ($Value -isnot [string]) { throw "$Label must be a JSON string." }
    return [string]$Value
}

function Get-FaultGateJsonBoolean {
    param([Parameter(Mandatory = $true)] $Value, [Parameter(Mandatory = $true)] [string] $Label)
    if ($Value -isnot [bool]) { throw "$Label must be a JSON boolean." }
    return [bool]$Value
}

function Assert-FaultGateJsonObject {
    param([Parameter(Mandatory = $true)] $Value, [Parameter(Mandatory = $true)] [string] $Label)
    if ($null -eq $Value -or $Value -isnot [Management.Automation.PSCustomObject]) { throw "$Label must be a JSON object." }
}

function Assert-FaultGateJsonArray {
    param([Parameter(Mandatory = $true)] $Value, [Parameter(Mandatory = $true)] [string] $Label)
    if ($Value -isnot [array]) { throw "$Label must be a JSON array." }
}

function ConvertTo-FaultGateCompactJsonBytes {
    param([Parameter(Mandatory = $true)] $Value)
    return [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 100 -Compress))
}

function ConvertTo-FaultGateSerdeJsonStringLiteral {
    param([Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Value)
    $builder = [Text.StringBuilder]::new()
    $null = $builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $code = [int][char]$character
        $escape = $null
        switch ($code) {
            8 { $escape = '\b'; break }
            9 { $escape = '\t'; break }
            10 { $escape = '\n'; break }
            12 { $escape = '\f'; break }
            13 { $escape = '\r'; break }
            34 { $escape = '\"'; break }
            92 { $escape = '\\'; break }
        }
        if ($null -ne $escape) { $null = $builder.Append($escape); continue }
        if ($code -lt 32) { $null = $builder.Append('\u').Append($code.ToString('x4')); continue }
        $null = $builder.Append($character)
    }
    $null = $builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-FaultGateSerdeCompactJsonText {
    param($Value)
    if ($null -eq $Value) { return "null" }
    if ($Value -is [string]) { return ConvertTo-FaultGateSerdeJsonStringLiteral -Value ([string]$Value) }
    if ($Value -is [bool]) { return $(if ([bool]$Value) { "true" } else { "false" }) }
    $typeCode = [Type]::GetTypeCode($Value.GetType())
    if ($typeCode -in @([TypeCode]::Byte, [TypeCode]::UInt16, [TypeCode]::UInt32, [TypeCode]::UInt64, [TypeCode]::SByte, [TypeCode]::Int16, [TypeCode]::Int32, [TypeCode]::Int64)) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($typeCode -eq [TypeCode]::Decimal) {
        [decimal]$decimalValue = $Value
        $decimalFlags = [decimal]::GetBits($decimalValue)[3]
        $decimalScale = ($decimalFlags -shr 16) -band 0xFF
        if ($decimalScale -ne 0 -or $decimalValue -lt [decimal]0 -or $decimalValue -gt [decimal][uint64]::MaxValue) {
            throw "Decimal cannot be serialized under the strict serde_json UInt64 integer contract."
        }
        return $decimalValue.ToString("0", [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [array]) {
        $parts = [Collections.Generic.List[string]]::new()
        foreach ($item in @($Value)) { $parts.Add((ConvertTo-FaultGateSerdeCompactJsonText -Value $item)) }
        return "[" + ($parts -join ',') + "]"
    }
    if ($Value -is [Collections.IDictionary]) {
        $parts = [Collections.Generic.List[string]]::new()
        foreach ($key in $Value.Keys) {
            if ($key -isnot [string]) { throw "Serde JSON object key is not a string." }
            $parts.Add((ConvertTo-FaultGateSerdeJsonStringLiteral -Value ([string]$key)) + ":" + (ConvertTo-FaultGateSerdeCompactJsonText -Value $Value[$key]))
        }
        return "{" + ($parts -join ',') + "}"
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $parts = [Collections.Generic.List[string]]::new()
        foreach ($property in $Value.PSObject.Properties) {
            $parts.Add((ConvertTo-FaultGateSerdeJsonStringLiteral -Value $property.Name) + ":" + (ConvertTo-FaultGateSerdeCompactJsonText -Value $property.Value))
        }
        return "{" + ($parts -join ',') + "}"
    }
    throw "Value cannot be serialized under the strict serde_json integer-only contract: $($Value.GetType().FullName)"
}

function ConvertTo-FaultGateSerdeCompactJsonBytes {
    param([Parameter(Mandatory = $true)] $Value)
    return [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-FaultGateSerdeCompactJsonText -Value $Value))
}

function Get-FaultGateSha256Bytes {
    param([Parameter(Mandatory = $true)] [AllowEmptyCollection()] [byte[]] $Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-FaultGateSha256File {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "").ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Assert-FaultGateExactDataStreamInventory {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [ValidateSet("file", "directory")] [string] $ExpectedType,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (($ExpectedType -ceq "directory") -ne [bool]$item.PSIsContainer) {
        throw "$Label changed filesystem type while its data-stream inventory was checked: $fullPath"
    }
    Initialize-FaultGateNative
    $streams = @([RawFaultGateNative]::GetDataStreamNames($fullPath, 1))
    if ($ExpectedType -ceq "file") {
        if ($streams.Count -ne 1 -or [string]$streams[0] -cne '::$DATA') {
            throw "$Label contains an alternate data stream: $fullPath"
        }
    }
    elseif ($streams.Count -gt 1 -or ($streams.Count -eq 1 -and [string]$streams[0] -cne '::$DATA')) {
        throw "$Label directory contains an alternate data stream: $fullPath"
    }
    return $item
}

function Get-FaultGateFileDigestSnapshot {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $fullPath
    $null = Assert-FaultGateExactDataStreamInventory -Path $fullPath -ExpectedType "file" -Label "Artifact tree file"
    $stream = [IO.FileStream]::new($fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        [uint64]$snapshotLength = $stream.Length
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $digest = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "").ToLowerInvariant() }
        finally { $sha.Dispose() }
        if ([uint64]$stream.Length -ne $snapshotLength -or [uint64]$stream.Position -ne $snapshotLength) {
            throw "File changed while its tree snapshot was hashed: $fullPath"
        }
        $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or [uint64]$item.Length -ne $snapshotLength) {
            throw "File identity/type/length changed while its tree snapshot was hashed: $fullPath"
        }
        $null = Assert-FaultGateExactDataStreamInventory -Path $fullPath -ExpectedType "file" -Label "Artifact tree file"
        return [pscustomobject][ordered]@{ bytes = $snapshotLength; sha256 = $digest }
    }
    finally { $stream.Dispose() }
}

function Test-FaultGateDigest {
    param($Value)
    return $Value -is [string] -and [string]$Value -cmatch '^[0-9a-f]{64}$'
}

function Read-FaultGateSnapshotBytes {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $length = [int64]$stream.Length
        if ($length -gt [int]::MaxValue) { throw "Snapshot file is too large: $Path" }
        $bytes = [byte[]]::new([int]$length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw "Snapshot file shortened while reading: $Path" }
            $offset += $read
        }
        return $bytes
    }
    finally { $stream.Dispose() }
}

function Read-FaultGateJson {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing JSON artifact: $Path" }
    [byte[]]$bytes = @(Read-FaultGateSnapshotBytes -Path $Path)
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) }
    catch { throw "Invalid UTF-8 JSON artifact: $Path" }
    try { return $text | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Invalid JSON artifact: $Path" }
}

function Read-FaultGateJsonSnapshot {
    param([Parameter(Mandatory = $true)] [string] $Path, [switch] $RequireCanonicalPrettyJson)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing JSON artifact: $Path" }
    [byte[]]$bytes = @(Read-FaultGateSnapshotBytes -Path $Path)
    if ($bytes.Length -eq 0) { throw "Empty JSON artifact: $Path" }
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) }
    catch { throw "Invalid UTF-8 JSON artifact: $Path" }
    try { $value = $text | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Invalid JSON artifact: $Path" }
    if ($RequireCanonicalPrettyJson) {
        [byte[]]$canonicalBytes = [Text.UTF8Encoding]::new($false).GetBytes((($value | ConvertTo-Json -Depth 100) + "`n"))
        if ($bytes.Length -ne $canonicalBytes.Length) { throw "JSON artifact is not exact writer-canonical pretty JSON: $Path" }
        for ($byteIndex = 0; $byteIndex -lt $bytes.Length; $byteIndex++) {
            if ($bytes[$byteIndex] -ne $canonicalBytes[$byteIndex]) { throw "JSON artifact is not exact writer-canonical pretty JSON: $Path" }
        }
    }
    return [pscustomobject][ordered]@{
        path = [IO.Path]::GetFullPath($Path)
        bytes = [uint64]$bytes.Length
        sha256 = Get-FaultGateSha256Bytes -Bytes $bytes
        value = $value
        raw_bytes = [byte[]]$bytes
    }
}

function Read-FaultGateJournal {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $ExpectedSchema,
        [switch] $RequireCleanTail,
        [switch] $RequireCanonicalCompactJson,
        [uint64] $MaximumRecordBytes = [uint64]::MaxValue,
        [uint64] $MaximumPartialTailBytes = [uint64]::MaxValue,
        [byte[]] $SnapshotBytes
    )
    if ($PSBoundParameters.ContainsKey("SnapshotBytes")) {
        [byte[]]$bytes = @($SnapshotBytes)
    }
    else {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing journal: $Path" }
        [byte[]]$bytes = @(Read-FaultGateSnapshotBytes -Path $Path)
    }
    if ($bytes.Length -eq 0) { throw "Empty journal: $Path" }
    $cleanTail = $bytes[$bytes.Length - 1] -eq 10
    if ($RequireCleanTail -and -not $cleanTail) { throw "Partial journal tail: $Path" }
    $lastJournalLf = if ($cleanTail) { $bytes.Length - 1 } else {
        $foundLf = -1
        for ($byteIndex = $bytes.Length - 1; $byteIndex -ge 0; $byteIndex--) {
            if ($bytes[$byteIndex] -eq 10) { $foundLf = $byteIndex; break }
        }
        $foundLf
    }
    [uint64]$preliminaryPartialTailBytes = if ($cleanTail) { 0 } elseif ($lastJournalLf -ge 0) { [uint64]$bytes.Length - [uint64]($lastJournalLf + 1) } else { [uint64]$bytes.Length }
    if ($preliminaryPartialTailBytes -gt $MaximumPartialTailBytes) {
        throw "Journal partial tail exceeds its exact writer-record byte limit: $Path"
    }
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) }
    catch { throw "Invalid UTF-8 journal: $Path" }
    $parts = $text.Split([char]10)
    $count = if ($cleanTail) { $parts.Length - 1 } else { $parts.Length - 1 }
    $records = [Collections.Generic.List[object]]::new()
    $previous = $script:FaultGateZeroDigest
    $previousCampaignMono = $null
    $previousPowerShellMono = $null
    $serdeJournal = $ExpectedSchema -cin @("RawCampaignJournalRecordV1", "RawDurabilityProgressV1")
    for ($index = 0; $index -lt $count; $index++) {
        $line = $parts[$index]
        if ($line.EndsWith("`r", [StringComparison]::Ordinal) -or [string]::IsNullOrEmpty($line)) {
            throw "Invalid journal line framing at record $index in $Path"
        }
        if ([uint64][Text.Encoding]::UTF8.GetByteCount($line) -gt $MaximumRecordBytes) {
            throw "Journal record exceeds its exact byte limit at record $index in $Path"
        }
        try { $envelope = $line | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "Invalid journal JSON at record $index in $Path" }
        if ($RequireCanonicalCompactJson) {
            $canonicalLineBytes = if ($serdeJournal) { ConvertTo-FaultGateSerdeCompactJsonBytes -Value $envelope } else { ConvertTo-FaultGateCompactJsonBytes -Value $envelope }
            $canonicalLine = [Text.UTF8Encoding]::new($false).GetString($canonicalLineBytes)
            if ($line -cne $canonicalLine) { throw "Non-canonical compact journal JSON at record $index in $Path" }
        }
        Assert-FaultGateJsonObject -Value $envelope -Label "journal envelope"
        Assert-FaultGateExactProperties -Value $envelope -Names @("body", "record_sha256") -Label "journal envelope"
        Assert-FaultGateJsonObject -Value $envelope.body -Label "journal body"
        if ($ExpectedSchema -ceq "RawCampaignJournalRecordV1") {
            Assert-FaultGateExactProperties -Value $envelope.body -Names @(
                "schema", "record_index", "wall_ns", "campaign_mono_ns", "generation_index", "channel", "payload", "previous_record_sha256"
            ) -Label "campaign journal body"
        }
        elseif ($ExpectedSchema -ceq "RawDurabilityProgressV1") {
            Assert-FaultGateExactProperties -Value $envelope.body -Names @("schema", "record_index", "raw_path", "ack", "previous_record_sha256") -Label "durability journal body"
        }
        elseif ($ExpectedSchema -cin @(
            "RawQualificationFaultGateEventV1", "RawQualificationLauncherEventV1", "RawQualificationGuardianPulseV1", "RawQualificationHostTelemetryRecordV1"
        )) {
            Assert-FaultGateExactProperties -Value $envelope.body -Names @("schema", "record_index", "wall_ns", "monotonic_tick", "channel", "payload", "previous_record_sha256") -Label "PowerShell qualification journal body"
        }
        $journalSchema = Get-FaultGateJsonNonEmptyString -Value $envelope.body.schema -Label "journal schema"
        $journalRecordIndex = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.record_index -Label "journal record_index"
        if ($null -ne $envelope.body.PSObject.Properties['channel']) { $null = Get-FaultGateJsonNonEmptyString -Value $envelope.body.channel -Label "journal channel" }
        if ($null -ne $envelope.body.PSObject.Properties['payload']) { Assert-FaultGateJsonObject -Value $envelope.body.payload -Label "journal payload" }
        foreach ($numericField in @("wall_ns", "monotonic_tick", "campaign_mono_ns")) {
            if ($null -ne $envelope.body.PSObject.Properties[$numericField]) { $null = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.$numericField -Label ("journal " + $numericField) }
        }
        if ($null -ne $envelope.body.PSObject.Properties['generation_index'] -and $null -ne $envelope.body.generation_index) {
            $null = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.generation_index -Label "journal generation_index"
        }
        if ($ExpectedSchema -ceq "RawCampaignJournalRecordV1") {
            $campaignWall = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.wall_ns -Label "campaign journal wall_ns"
            $campaignMono = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.campaign_mono_ns -Label "campaign journal campaign_mono_ns"
            $campaignChannel = Get-FaultGateJsonNonEmptyString -Value $envelope.body.channel -Label "campaign journal channel"
            $campaignEvent = Get-FaultGateJsonNonEmptyString -Value $envelope.body.payload.event -Label "campaign journal event"
            if ($campaignWall -eq 0 -or ($null -ne $previousCampaignMono -and $campaignMono -lt [uint64]$previousCampaignMono)) { throw "Campaign journal wall/monotonic chain is invalid at record $index in $Path" }
            $campaignScopeEvents = @("CAMPAIGN_STARTED", "CAMPAIGN_EVALUATION_PREPARED", "CAMPAIGN_COMMITTED", "CAMPAIGN_FAILED")
            $generationScopeEvents = @(
                "PROCESS_STARTED", "TRANSPORT_CONNECTED", "SNAPSHOT_DURABLE", "SEGMENT_DURABLE", "SERVER_SHUTDOWN_DURABLE", "HEARTBEAT_DURABLE", "PROCESS_TERMINAL",
                "GENERATION_LAUNCHED", "GENERATION_LAUNCHED_SERVER_SHUTDOWN", "GENERATION_EXITED", "HANDOVER_PROOF_STARTED", "INITIAL_ACTIVE_REGISTERED",
                "CANDIDATE_REGISTERED", "HANDOVER_PROVEN_AND_PROMOTED", "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE", "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING",
                "GENERATION_DISCONNECT_FAIL_CLOSED"
            )
            if (($campaignEvent -cin $campaignScopeEvents -and $null -ne $envelope.body.generation_index) -or
                ($campaignEvent -cin $generationScopeEvents -and $null -eq $envelope.body.generation_index) -or
                ($campaignEvent -cnotin ($campaignScopeEvents + $generationScopeEvents)) -or
                ($campaignChannel -ceq "CAMPAIGN" -and $campaignEvent -cnotin @("CAMPAIGN_STARTED", "GENERATION_LAUNCHED", "GENERATION_LAUNCHED_SERVER_SHUTDOWN", "GENERATION_EXITED", "HANDOVER_PROOF_STARTED", "CAMPAIGN_EVALUATION_PREPARED", "CAMPAIGN_COMMITTED", "CAMPAIGN_FAILED")) -or
                ($campaignChannel -ceq "SUPERVISOR" -and $campaignEvent -cnotin @("INITIAL_ACTIVE_REGISTERED", "CANDIDATE_REGISTERED", "HANDOVER_PROVEN_AND_PROMOTED", "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE", "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING", "GENERATION_DISCONNECT_FAIL_CLOSED")) -or
                ($campaignChannel -ceq "CHILD_STDOUT" -and $campaignEvent -cnotin @("PROCESS_STARTED", "TRANSPORT_CONNECTED", "SNAPSHOT_DURABLE", "SEGMENT_DURABLE", "SERVER_SHUTDOWN_DURABLE", "HEARTBEAT_DURABLE", "PROCESS_TERMINAL")) -or
                $campaignChannel -cnotin @("CAMPAIGN", "SUPERVISOR", "CHILD_STDOUT")) {
                throw "Campaign journal event/channel/generation scope is invalid at record $index in $Path"
            }
            $previousCampaignMono = $campaignMono
        }
        elseif ($ExpectedSchema -cin @(
            "RawQualificationFaultGateEventV1", "RawQualificationLauncherEventV1", "RawQualificationGuardianPulseV1", "RawQualificationHostTelemetryRecordV1"
        )) {
            $qualificationWall = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.wall_ns -Label "qualification journal wall_ns"
            $qualificationMono = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.monotonic_tick -Label "qualification journal monotonic_tick"
            if ($qualificationWall -eq 0 -or $qualificationMono -eq 0 -or
                ($null -ne $previousPowerShellMono -and $qualificationMono -lt [uint64]$previousPowerShellMono)) {
                throw "PowerShell qualification journal wall/monotonic chain is invalid at record $index in $Path"
            }
            $previousPowerShellMono = $qualificationMono
        }
        $bodyBytes = if ($serdeJournal) { ConvertTo-FaultGateSerdeCompactJsonBytes -Value $envelope.body } else { ConvertTo-FaultGateCompactJsonBytes -Value $envelope.body }
        $actual = Get-FaultGateSha256Bytes -Bytes $bodyBytes
        if ($journalSchema -cne $ExpectedSchema -or
            $journalRecordIndex -ne [uint64]$index -or
            [string]$envelope.body.previous_record_sha256 -cne $previous -or
            -not (Test-FaultGateDigest $envelope.body.previous_record_sha256) -or -not (Test-FaultGateDigest $envelope.record_sha256) -or
            [string]$envelope.record_sha256 -cne $actual) {
            throw "Journal hash-chain failure at record $index in $Path"
        }
        $records.Add($envelope)
        $previous = $actual
    }
    if ($records.Count -eq 0) { throw "Journal contains no complete records: $Path" }
    $verifiedThroughOffset = if ($cleanTail) {
        [uint64]$bytes.Length
    }
    else {
        if ($lastJournalLf -lt 0) { throw "Journal contains no complete line boundary: $Path" }
        [uint64]($lastJournalLf + 1)
    }
    $verifiedPrefixStream = [IO.MemoryStream]::new([byte[]]$bytes, $false)
    try { $verifiedPrefixSha256 = Get-FaultGateSha256StreamPrefix -Stream $verifiedPrefixStream -Length $verifiedThroughOffset }
    finally { $verifiedPrefixStream.Dispose() }
    $partialTailBytes = [uint64]$bytes.Length - $verifiedThroughOffset
    if ($partialTailBytes -gt $MaximumPartialTailBytes) {
        throw "Journal partial tail exceeds its exact writer-record byte limit: $Path"
    }
    return [pscustomobject][ordered]@{
        path = [IO.Path]::GetFullPath($Path)
        records = [uint64]$records.Count
        clean_tail = [bool]$cleanTail
        terminal_record_sha256 = $previous
        file_bytes = [uint64]$bytes.Length
        file_sha256 = Get-FaultGateSha256Bytes -Bytes $bytes
        verified_through_offset = $verifiedThroughOffset
        verified_prefix_sha256 = $verifiedPrefixSha256
        partial_tail_bytes = $partialTailBytes
        entries = @($records)
        raw_bytes = [byte[]]$bytes
    }
}

function Read-FaultGateEmbeddedCampaignJournal {
    param(
        [Parameter(Mandatory = $true)] [byte[]] $Bytes,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ($Bytes.Length -eq 0 -or $Bytes[$Bytes.Length - 1] -ne 10) { throw "$Label is empty or lacks its exact terminal LF." }
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) }
    catch { throw "$Label is not strict UTF-8." }
    $parts = $text.Split([char]10)
    if ($parts.Length -lt 2 -or $parts[$parts.Length - 1].Length -ne 0) { throw "$Label framing is invalid." }
    $entries = [Collections.Generic.List[object]]::new()
    $previous = $script:FaultGateZeroDigest
    $previousMono = $null
    for ($index = 0; $index -lt $parts.Length - 1; $index++) {
        $line = $parts[$index]
        if ([string]::IsNullOrEmpty($line) -or $line.EndsWith("`r", [StringComparison]::Ordinal)) { throw "$Label has invalid framing at record $index." }
        try { $envelope = $line | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "$Label has invalid JSON at record $index." }
        Assert-FaultGateJsonObject -Value $envelope -Label "$Label envelope $index"
        Assert-FaultGateExactProperties -Value $envelope -Names @("body", "record_sha256") -Label "$Label envelope $index"
        Assert-FaultGateJsonObject -Value $envelope.body -Label "$Label body $index"
        Assert-FaultGateExactProperties -Value $envelope.body -Names @(
            "schema", "record_index", "wall_ns", "campaign_mono_ns", "generation_index", "channel", "payload", "previous_record_sha256"
        ) -Label "$Label body $index"
        $canonicalLine = [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateSerdeCompactJsonBytes -Value $envelope))
        if ($line -cne $canonicalLine) { throw "$Label record $index is not exact writer-canonical JSON." }
        $schema = Get-FaultGateJsonNonEmptyString -Value $envelope.body.schema -Label "$Label schema $index"
        $recordIndex = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.record_index -Label "$Label record_index $index"
        $wall = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.wall_ns -Label "$Label wall_ns $index"
        $mono = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.campaign_mono_ns -Label "$Label campaign_mono_ns $index"
        $channel = Get-FaultGateJsonNonEmptyString -Value $envelope.body.channel -Label "$Label channel $index"
        Assert-FaultGateJsonObject -Value $envelope.body.payload -Label "$Label payload $index"
        $event = Get-FaultGateJsonNonEmptyString -Value $envelope.body.payload.event -Label "$Label event $index"
        if ($null -ne $envelope.body.generation_index) {
            $null = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.generation_index -Label "$Label generation_index $index"
        }
        Assert-FaultGateEvidenceDigest -Value $envelope.body.previous_record_sha256 -Label "$Label previous digest $index"
        Assert-FaultGateEvidenceDigest -Value $envelope.record_sha256 -Label "$Label record digest $index"
        $campaignScopeEvents = @("CAMPAIGN_STARTED", "CAMPAIGN_EVALUATION_PREPARED", "CAMPAIGN_COMMITTED", "CAMPAIGN_FAILED")
        $generationScopeEvents = @(
            "PROCESS_STARTED", "TRANSPORT_CONNECTED", "SNAPSHOT_DURABLE", "SEGMENT_DURABLE", "SERVER_SHUTDOWN_DURABLE", "HEARTBEAT_DURABLE", "PROCESS_TERMINAL",
            "GENERATION_LAUNCHED", "GENERATION_LAUNCHED_SERVER_SHUTDOWN", "GENERATION_EXITED", "HANDOVER_PROOF_STARTED", "INITIAL_ACTIVE_REGISTERED",
            "CANDIDATE_REGISTERED", "HANDOVER_PROVEN_AND_PROMOTED", "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE", "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING",
            "GENERATION_DISCONNECT_FAIL_CLOSED"
        )
        if ($schema -cne "RawCampaignJournalRecordV1" -or $recordIndex -ne [uint64]$index -or $wall -eq 0 -or
            ($null -ne $previousMono -and $mono -lt [uint64]$previousMono) -or
            ($event -cin $campaignScopeEvents -and $null -ne $envelope.body.generation_index) -or
            ($event -cin $generationScopeEvents -and $null -eq $envelope.body.generation_index) -or
            $event -cnotin ($campaignScopeEvents + $generationScopeEvents) -or
            ($channel -ceq "CAMPAIGN" -and $event -cnotin @("CAMPAIGN_STARTED", "GENERATION_LAUNCHED", "GENERATION_LAUNCHED_SERVER_SHUTDOWN", "GENERATION_EXITED", "HANDOVER_PROOF_STARTED", "CAMPAIGN_EVALUATION_PREPARED", "CAMPAIGN_COMMITTED", "CAMPAIGN_FAILED")) -or
            ($channel -ceq "SUPERVISOR" -and $event -cnotin @("INITIAL_ACTIVE_REGISTERED", "CANDIDATE_REGISTERED", "HANDOVER_PROVEN_AND_PROMOTED", "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE", "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING", "GENERATION_DISCONNECT_FAIL_CLOSED")) -or
            ($channel -ceq "CHILD_STDOUT" -and $event -cnotin @("PROCESS_STARTED", "TRANSPORT_CONNECTED", "SNAPSHOT_DURABLE", "SEGMENT_DURABLE", "SERVER_SHUTDOWN_DURABLE", "HEARTBEAT_DURABLE", "PROCESS_TERMINAL")) -or
            $channel -cnotin @("CAMPAIGN", "SUPERVISOR", "CHILD_STDOUT")) {
            throw "$Label event/channel/generation scope is invalid at record $index."
        }
        $bodySha = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $envelope.body)
        if ([string]$envelope.body.previous_record_sha256 -cne $previous -or [string]$envelope.record_sha256 -cne $bodySha) {
            throw "$Label hash chain is invalid at record $index."
        }
        $entries.Add($envelope)
        $previous = $bodySha
        $previousMono = $mono
    }
    if ($entries.Count -eq 0) { throw "$Label has no records." }
    return [pscustomobject][ordered]@{
        records = [uint64]$entries.Count; clean_tail = $true; terminal_record_sha256 = $previous
        file_bytes = [uint64]$Bytes.Length; file_sha256 = Get-FaultGateSha256Bytes -Bytes $Bytes; entries = @($entries)
    }
}

function Read-FaultGateEmbeddedFaultJournal {
    param(
        [Parameter(Mandatory = $true)] [byte[]] $Bytes,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ($Bytes.Length -eq 0 -or $Bytes[$Bytes.Length - 1] -ne 10) { throw "$Label is empty or lacks its exact terminal LF." }
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) }
    catch { throw "$Label is not strict UTF-8." }
    $parts = $text.Split([char]10)
    if ($parts.Length -lt 2 -or $parts[$parts.Length - 1].Length -ne 0) { throw "$Label framing is invalid." }
    $entries = [Collections.Generic.List[object]]::new()
    $previous = $script:FaultGateZeroDigest
    $previousMono = $null
    for ($index = 0; $index -lt $parts.Length - 1; $index++) {
        $line = $parts[$index]
        if ([string]::IsNullOrEmpty($line) -or $line.EndsWith("`r", [StringComparison]::Ordinal)) { throw "$Label has invalid framing at record $index." }
        try { $envelope = $line | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "$Label has invalid JSON at record $index." }
        Assert-FaultGateJsonObject -Value $envelope -Label "$Label envelope $index"
        Assert-FaultGateExactProperties -Value $envelope -Names @("body", "record_sha256") -Label "$Label envelope $index"
        Assert-FaultGateJsonObject -Value $envelope.body -Label "$Label body $index"
        Assert-FaultGateExactProperties -Value $envelope.body -Names @("schema", "record_index", "wall_ns", "monotonic_tick", "channel", "payload", "previous_record_sha256") -Label "$Label body $index"
        $canonicalLine = [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateCompactJsonBytes -Value $envelope))
        if ($line -cne $canonicalLine) { throw "$Label record $index is not exact writer-canonical JSON." }
        $schema = Get-FaultGateJsonNonEmptyString -Value $envelope.body.schema -Label "$Label schema $index"
        $recordIndex = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.record_index -Label "$Label record_index $index"
        $wall = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.wall_ns -Label "$Label wall_ns $index"
        $mono = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.monotonic_tick -Label "$Label monotonic_tick $index"
        $null = Get-FaultGateJsonNonEmptyString -Value $envelope.body.channel -Label "$Label channel $index"
        Assert-FaultGateJsonObject -Value $envelope.body.payload -Label "$Label payload $index"
        $null = Get-FaultGateJsonNonEmptyString -Value $envelope.body.payload.event -Label "$Label event $index"
        Assert-FaultGateEvidenceDigest -Value $envelope.body.previous_record_sha256 -Label "$Label previous digest $index"
        Assert-FaultGateEvidenceDigest -Value $envelope.record_sha256 -Label "$Label record digest $index"
        $bodySha = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $envelope.body)
        if ($schema -cne $script:FaultGateJournalSchema -or $recordIndex -ne [uint64]$index -or $wall -eq 0 -or $mono -eq 0 -or
            ($null -ne $previousMono -and $mono -lt [uint64]$previousMono) -or
            [string]$envelope.body.previous_record_sha256 -cne $previous -or [string]$envelope.record_sha256 -cne $bodySha) {
            throw "$Label identity/hash/monotonic chain is invalid at record $index."
        }
        $entries.Add($envelope); $previous = $bodySha; $previousMono = $mono
    }
    if ($entries.Count -eq 0) { throw "$Label has no records." }
    return [pscustomobject][ordered]@{
        records = [uint64]$entries.Count; clean_tail = $true; terminal_record_sha256 = $previous
        file_bytes = [uint64]$Bytes.Length; file_sha256 = Get-FaultGateSha256Bytes -Bytes $Bytes; entries = @($entries)
    }
}

function Get-FaultGateJournalEvents {
    param([Parameter(Mandatory = $true)] $Journal, [Parameter(Mandatory = $true)] [string] $Event)
    return @($Journal.entries | Where-Object {
        $null -ne $_.body.payload.PSObject.Properties['event'] -and [string]$_.body.payload.event -ceq $Event
    })
}

function Test-FaultGateCanonicalJsonValueEqual {
    param($Left, $Right)
    try {
        $leftText = [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateCompactJsonBytes -Value $Left))
        $rightText = [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateCompactJsonBytes -Value $Right))
        return $leftText -ceq $rightText
    }
    catch { return $false }
}

function Test-FaultGateFaultInjectionJournalSequence {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] [string] $ProposalSha256,
        [Parameter(Mandatory = $true)] [string] $InjectionRequestedSha256,
        [Parameter(Mandatory = $true)] [string] $InjectedSha256,
        [Parameter(Mandatory = $true)] [uint32] $TargetPid,
        [Parameter(Mandatory = $true)] [uint32] $RequestedExitCode,
        [Parameter(Mandatory = $true)] [uint64] $InjectionRequestedWallNs,
        [Parameter(Mandatory = $true)] [uint64] $InjectionRequestedMonotonicTick,
        [Parameter(Mandatory = $true)] [uint32] $ObservedExitCode,
        $EvidenceBody = $null
    )
    foreach ($digest in @($ProposalSha256, $InjectionRequestedSha256, $InjectedSha256)) {
        if (-not (Test-FaultGateDigest $digest)) { throw "External fault-journal sequence received an invalid record digest." }
    }
    if ($TargetPid -eq 0 -or $InjectionRequestedWallNs -eq 0 -or $InjectionRequestedMonotonicTick -eq 0) {
        throw "External fault-journal sequence received an invalid target/request identity."
    }
    Assert-FaultGateJsonArray -Value @($Journal.entries) -Label "external fault journal entries"
    $entries = @($Journal.entries)
    $expectedEvents = @("HARNESS_STARTED", "RUN_BOUND", "LIVE_HEALTHY", "FAULT_PROPOSED", "FAULT_INJECTION_REQUESTED", "FAULT_INJECTED", "LAUNCHER_EXITED", "EVIDENCE_PROPOSED")
    if ($entries.Count -ne $expectedEvents.Count) { throw "External fault journal event cardinality is invalid." }
    for ($index = 0; $index -lt $expectedEvents.Count; $index++) {
        if ($null -eq $entries[$index].body -or $null -eq $entries[$index].body.payload -or
            [string]$entries[$index].body.channel -cne "FAULT_GATE" -or
            [string]$entries[$index].body.payload.event -cne $expectedEvents[$index]) {
            throw "External fault journal event order is invalid at index $index."
        }
    }
    $harness = $entries[0].body.payload
    Assert-FaultGateExactProperties -Value $harness -Names @(
        "event", "gate_id", "repo", "qualification_base", "target_exit_code", "containment_exit_code", "source_bindings",
        "artifact_path_binding_scope", "artifact_path_binding_trust_boundary", "artifact_path_bindings", "launch_artifact_hashes"
    ) -Label "fault HARNESS_STARTED payload"
    $harnessGateId = Get-FaultGateJsonNonEmptyString -Value $harness.gate_id -Label "fault harness gate_id"
    $harnessRepo = Get-FaultGateJsonNonEmptyString -Value $harness.repo -Label "fault harness repo"
    $harnessQualificationBase = Get-FaultGateJsonNonEmptyString -Value $harness.qualification_base -Label "fault harness qualification_base"
    $harnessTargetExit = Get-FaultGateJsonUnsignedInteger -Value $harness.target_exit_code -Label "fault harness target_exit_code" -Maximum ([uint32]::MaxValue)
    $harnessContainmentExit = Get-FaultGateJsonUnsignedInteger -Value $harness.containment_exit_code -Label "fault harness containment_exit_code" -Maximum ([uint32]::MaxValue)
    Assert-FaultGateJsonArray -Value $harness.source_bindings -Label "fault harness source_bindings"
    Assert-FaultGateJsonArray -Value $harness.artifact_path_bindings -Label "fault harness artifact_path_bindings"
    Assert-FaultGateJsonObject -Value $harness.launch_artifact_hashes -Label "fault harness launch_artifact_hashes"
    if ($harnessTargetExit -ne $RequestedExitCode -or $harnessContainmentExit -ne [uint32]$script:FaultGateContainmentExitCode -or
        [string]$harness.artifact_path_binding_scope -cne "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE" -or
        [string]$harness.artifact_path_binding_trust_boundary -cne "Path-byte observation and retention do not assert absolute equivalence with bytes already interpreted or mapped by a runtime.") {
        throw "External fault journal HARNESS_STARTED contract is invalid."
    }

    $runBound = $entries[1].body.payload
    Assert-FaultGateExactProperties -Value $runBound -Names @(
        "event", "run_id", "run_root", "launcher_pid", "launcher_creation_filetime_utc", "launcher_command_line_sha256",
        "startup_sha256", "processes_sha256", "bindings_sha256"
    ) -Label "fault RUN_BOUND payload"
    $runBoundRunId = Get-FaultGateJsonNonEmptyString -Value $runBound.run_id -Label "fault run-bound run_id"
    $runBoundRoot = Get-FaultGateJsonNonEmptyString -Value $runBound.run_root -Label "fault run-bound run_root"
    $runBoundLauncherPid = Get-FaultGateJsonUnsignedInteger -Value $runBound.launcher_pid -Label "fault run-bound launcher_pid" -Maximum ([uint32]::MaxValue)
    $runBoundLauncherCreation = Get-FaultGateJsonSignedInteger -Value $runBound.launcher_creation_filetime_utc -Label "fault run-bound launcher creation"
    foreach ($digestName in @("launcher_command_line_sha256", "startup_sha256", "processes_sha256", "bindings_sha256")) {
        Assert-FaultGateEvidenceDigest -Value $runBound.$digestName -Label "fault run-bound $digestName"
    }
    if ($runBoundLauncherPid -eq 0 -or $runBoundLauncherCreation -le 0) { throw "External fault journal RUN_BOUND launcher identity is invalid." }

    $healthy = $entries[2].body.payload
    Assert-FaultGateExactProperties -Value $healthy -Names @("event", "monitor_attempt", "monitor_stdout_sha256", "status", "stage", "host_telemetry_records", "watchdog_ready_sha256") -Label "fault LIVE_HEALTHY payload"
    $healthyAttempt = Get-FaultGateJsonUnsignedInteger -Value $healthy.monitor_attempt -Label "fault healthy monitor_attempt"
    $healthyTelemetryRecords = Get-FaultGateJsonUnsignedInteger -Value $healthy.host_telemetry_records -Label "fault healthy telemetry records"
    foreach ($digestName in @("monitor_stdout_sha256", "watchdog_ready_sha256")) { Assert-FaultGateEvidenceDigest -Value $healthy.$digestName -Label "fault healthy $digestName" }
    if ($healthyAttempt -eq 0 -or $healthyTelemetryRecords -eq 0 -or [string]$healthy.status -cne "HEALTHY_RUNNING" -or [string]$healthy.stage -cne "CAPTURING") {
        throw "External fault journal LIVE_HEALTHY contract is invalid."
    }

    $proposal = $entries[3].body.payload
    Assert-FaultGateExactProperties -Value $proposal -Names @(
        "event", "run_id", "run_root", "symbol", "generation_index", "target_pid", "target_creation_filetime_utc", "target_parent_pid",
        "target_executable_sha256", "target_command_line_sha256", "requested_exit_code", "pre_fault_raw_prefixes_sha256",
        "pre_fault_campaign_prefixes_sha256", "pre_fault_campaign_prefixes"
    ) -Label "fault FAULT_PROPOSED payload"
    $proposalGeneration = Get-FaultGateJsonUnsignedInteger -Value $proposal.generation_index -Label "fault proposal generation_index"
    $proposalPid = Get-FaultGateJsonUnsignedInteger -Value $proposal.target_pid -Label "fault proposal target_pid" -Maximum ([uint32]::MaxValue)
    $proposalCreation = Get-FaultGateJsonSignedInteger -Value $proposal.target_creation_filetime_utc -Label "fault proposal target creation"
    $proposalParent = Get-FaultGateJsonUnsignedInteger -Value $proposal.target_parent_pid -Label "fault proposal target parent" -Maximum ([uint32]::MaxValue)
    $proposalExit = Get-FaultGateJsonUnsignedInteger -Value $proposal.requested_exit_code -Label "fault proposal requested exit" -Maximum ([uint32]::MaxValue)
    foreach ($digestName in @("target_executable_sha256", "target_command_line_sha256", "pre_fault_raw_prefixes_sha256", "pre_fault_campaign_prefixes_sha256")) {
        Assert-FaultGateEvidenceDigest -Value $proposal.$digestName -Label "fault proposal $digestName"
    }
    Assert-FaultGateJsonArray -Value $proposal.pre_fault_campaign_prefixes -Label "fault proposal campaign prefixes"
    if ([string]$entries[3].record_sha256 -cne $ProposalSha256 -or $proposalPid -ne $TargetPid -or $proposalPid -eq 0 -or $proposalCreation -le 0 -or
        $proposalParent -eq 0 -or $proposalGeneration -ne 0 -or [string]$proposal.symbol -cne "BTCUSDT" -or $proposalExit -ne $RequestedExitCode -or
        [string]$proposal.run_id -cne $runBoundRunId -or -not (Test-FaultGateFullPathEquals -PublishedPath $proposal.run_root -ExpectedPath $runBoundRoot)) {
        throw "External fault journal proposal identity is not exact."
    }
    $requestEntry = $entries[4]
    $request = $requestEntry.body.payload
    Assert-FaultGateExactProperties -Value $request -Names @("event", "proposal_record_sha256", "target_pid", "requested_exit_code", "request_wall_ns", "request_monotonic_tick") -Label "fault injection request payload"
    if ([string]$requestEntry.record_sha256 -cne $InjectionRequestedSha256 -or
        [string]$request.proposal_record_sha256 -cne $ProposalSha256 -or
        (Get-FaultGateJsonUnsignedInteger -Value $request.target_pid -Label "fault request target_pid" -Maximum ([uint32]::MaxValue)) -ne $TargetPid -or
        (Get-FaultGateJsonUnsignedInteger -Value $request.requested_exit_code -Label "fault request exit code" -Maximum ([uint32]::MaxValue)) -ne $RequestedExitCode -or
        (Get-FaultGateJsonUnsignedInteger -Value $request.request_wall_ns -Label "fault request wall_ns") -ne $InjectionRequestedWallNs -or
        (Get-FaultGateJsonUnsignedInteger -Value $request.request_monotonic_tick -Label "fault request monotonic tick") -ne $InjectionRequestedMonotonicTick) {
        throw "External fault journal does not preserve the exact requested-injection record/linkage."
    }
    $injectedEntry = $entries[5]
    $injected = $injectedEntry.body.payload
    Assert-FaultGateExactProperties -Value $injected -Names @("event", "proposal_record_sha256", "injection_requested_record_sha256", "target_pid", "observed_exit_code", "injection_method", "injected_wall_ns", "injected_monotonic_tick") -Label "fault injected payload"
    $injectedWallNs = Get-FaultGateJsonUnsignedInteger -Value $injected.injected_wall_ns -Label "fault injected wall_ns"
    $injectedMonotonicTick = Get-FaultGateJsonUnsignedInteger -Value $injected.injected_monotonic_tick -Label "fault injected monotonic tick"
    $proposalEnvelopeMonotonicTick = Get-FaultGateJsonUnsignedInteger -Value $entries[3].body.monotonic_tick -Label "fault proposal envelope monotonic tick"
    $requestEnvelopeMonotonicTick = Get-FaultGateJsonUnsignedInteger -Value $requestEntry.body.monotonic_tick -Label "fault request envelope monotonic tick"
    $injectedEnvelopeMonotonicTick = Get-FaultGateJsonUnsignedInteger -Value $injectedEntry.body.monotonic_tick -Label "fault injected envelope monotonic tick"
    if ([string]$injectedEntry.record_sha256 -cne $InjectedSha256 -or
        [string]$injected.proposal_record_sha256 -cne $ProposalSha256 -or
        [string]$injected.injection_requested_record_sha256 -cne $InjectionRequestedSha256 -or
        (Get-FaultGateJsonUnsignedInteger -Value $injected.target_pid -Label "fault injected target_pid" -Maximum ([uint32]::MaxValue)) -ne $TargetPid -or
        (Get-FaultGateJsonUnsignedInteger -Value $injected.observed_exit_code -Label "fault observed exit code" -Maximum ([uint32]::MaxValue)) -ne $ObservedExitCode -or
        [string]$injected.injection_method -cne "TerminateProcess_RETAINED_HANDLE" -or
        $injectedWallNs -eq 0 -or $proposalEnvelopeMonotonicTick -gt $InjectionRequestedMonotonicTick -or
        $InjectionRequestedMonotonicTick -gt $requestEnvelopeMonotonicTick -or $requestEnvelopeMonotonicTick -gt $injectedMonotonicTick -or
        $injectedMonotonicTick -gt $injectedEnvelopeMonotonicTick) {
        throw "External fault journal does not preserve the exact injected record/linkage."
    }

    $launcherExited = $entries[6].body.payload
    Assert-FaultGateExactProperties -Value $launcherExited -Names @(
        "event", "launcher_exit_code", "target_exit_code", "btc_coordinator_exit_code", "eth_capture_exit_code", "eth_coordinator_exit_code",
        "watchdog_exit_code", "outer_active_processes", "inner_job_exists", "inner_job_open_error", "workload_job_exists", "workload_job_open_error"
    ) -Label "fault LAUNCHER_EXITED payload"
    $launcherExit = Get-FaultGateJsonUnsignedInteger -Value $launcherExited.launcher_exit_code -Label "fault launcher exit" -Maximum ([uint32]::MaxValue)
    $launcherTargetExit = Get-FaultGateJsonUnsignedInteger -Value $launcherExited.target_exit_code -Label "fault launcher target exit" -Maximum ([uint32]::MaxValue)
    $btcCoordinatorExit = Get-FaultGateJsonUnsignedInteger -Value $launcherExited.btc_coordinator_exit_code -Label "fault BTC coordinator exit" -Maximum ([uint32]::MaxValue)
    $ethCaptureExit = Get-FaultGateJsonUnsignedInteger -Value $launcherExited.eth_capture_exit_code -Label "fault ETH capture exit" -Maximum ([uint32]::MaxValue)
    $ethCoordinatorExit = Get-FaultGateJsonUnsignedInteger -Value $launcherExited.eth_coordinator_exit_code -Label "fault ETH coordinator exit" -Maximum ([uint32]::MaxValue)
    $watchdogExit = Get-FaultGateJsonUnsignedInteger -Value $launcherExited.watchdog_exit_code -Label "fault watchdog exit" -Maximum ([uint32]::MaxValue)
    $launcherOuterActive = Get-FaultGateJsonUnsignedInteger -Value $launcherExited.outer_active_processes -Label "fault launcher outer active" -Maximum ([uint32]::MaxValue)
    $launcherInnerExists = Get-FaultGateJsonBoolean -Value $launcherExited.inner_job_exists -Label "fault launcher inner_job_exists"
    $launcherInnerError = Get-FaultGateJsonSignedInteger -Value $launcherExited.inner_job_open_error -Label "fault launcher inner_job_open_error"
    $launcherWorkloadExists = Get-FaultGateJsonBoolean -Value $launcherExited.workload_job_exists -Label "fault launcher workload_job_exists"
    $launcherWorkloadError = Get-FaultGateJsonSignedInteger -Value $launcherExited.workload_job_open_error -Label "fault launcher workload_job_open_error"
    $launcherExitedEnvelopeMonotonicTick = Get-FaultGateJsonUnsignedInteger -Value $entries[6].body.monotonic_tick -Label "fault launcher-exited envelope monotonic tick"
    if ($launcherExit -eq 0 -or $launcherTargetExit -ne $ObservedExitCode -or
        $btcCoordinatorExit -cnotin @([uint32]$script:FaultGateContainmentExitCode, [uint32]2) -or
        $ethCaptureExit -ne [uint32]$script:FaultGateContainmentExitCode -or $ethCoordinatorExit -ne [uint32]$script:FaultGateContainmentExitCode -or
        $watchdogExit -ne [uint32]$script:FaultGateContainmentExitCode -or $launcherOuterActive -ne 0 -or
        $launcherInnerExists -or $launcherInnerError -ne 2 -or $launcherWorkloadExists -or $launcherWorkloadError -ne 2) {
        throw "External fault journal LAUNCHER_EXITED containment result is invalid."
    }

    $evidenceProposed = $entries[7].body.payload
    Assert-FaultGateExactProperties -Value $evidenceProposed -Names @(
        "event", "run_id", "terminal_sha256", "containment_sha256", "launcher_journal_terminal_sha256", "process_observation",
        "outer_active_processes", "global_engine_processes", "run_bound_processes", "inner_job_exists", "inner_job_open_error",
        "workload_job_exists", "workload_job_open_error"
    ) -Label "fault EVIDENCE_PROPOSED payload"
    foreach ($digestName in @("terminal_sha256", "containment_sha256", "launcher_journal_terminal_sha256")) { Assert-FaultGateEvidenceDigest -Value $evidenceProposed.$digestName -Label "fault evidence-proposed $digestName" }
    $evidenceOuterActive = Get-FaultGateJsonUnsignedInteger -Value $evidenceProposed.outer_active_processes -Label "fault evidence-proposed outer active" -Maximum ([uint32]::MaxValue)
    $evidenceGlobal = Get-FaultGateJsonUnsignedInteger -Value $evidenceProposed.global_engine_processes -Label "fault evidence-proposed global engines"
    $evidenceRunBound = Get-FaultGateJsonUnsignedInteger -Value $evidenceProposed.run_bound_processes -Label "fault evidence-proposed run-bound"
    $evidenceInnerExists = Get-FaultGateJsonBoolean -Value $evidenceProposed.inner_job_exists -Label "fault evidence-proposed inner_job_exists"
    $evidenceInnerError = Get-FaultGateJsonSignedInteger -Value $evidenceProposed.inner_job_open_error -Label "fault evidence-proposed inner_job_open_error"
    $evidenceWorkloadExists = Get-FaultGateJsonBoolean -Value $evidenceProposed.workload_job_exists -Label "fault evidence-proposed workload_job_exists"
    $evidenceWorkloadError = Get-FaultGateJsonSignedInteger -Value $evidenceProposed.workload_job_open_error -Label "fault evidence-proposed workload_job_open_error"
    if ([string]$evidenceProposed.run_id -cne $runBoundRunId -or
        [string]$evidenceProposed.process_observation -cne "PRE_PROPOSAL_ONLY_POSTSCAN_REQUIRED_BEFORE_PUBLICATION" -or
        $evidenceOuterActive -ne 0 -or $evidenceGlobal -ne 0 -or $evidenceRunBound -ne 0 -or
        $evidenceInnerExists -or $evidenceInnerError -ne 2 -or $evidenceWorkloadExists -or $evidenceWorkloadError -ne 2) {
        throw "External fault journal EVIDENCE_PROPOSED process result is invalid."
    }

    if ($null -ne $EvidenceBody) {
        Assert-FaultGateJsonObject -Value $EvidenceBody -Label "fault journal evidence crosslink body"
        $expectedEvidenceBtcCoordinatorExit = [uint32]$EvidenceBody.containment.btc_coordinator_exit_code
        $expectedQualificationBase = Join-Path ([string]$EvidenceBody.evidence_root) "qualification"
        if ($harnessGateId -cne [string]$EvidenceBody.gate_id -or
            -not (Test-FaultGateFullPathEquals -PublishedPath $harnessRepo -ExpectedPath ([string]$EvidenceBody.repository_root)) -or
            -not (Test-FaultGateFullPathEquals -PublishedPath $harnessQualificationBase -ExpectedPath $expectedQualificationBase) -or
            -not (Test-FaultGateCanonicalJsonValueEqual $harness.source_bindings $EvidenceBody.harness.source_bindings_at_start) -or
            -not (Test-FaultGateCanonicalJsonValueEqual $harness.artifact_path_bindings $EvidenceBody.harness.direct_artifacts_retained_and_rehashed.bindings_at_start) -or
            -not (Test-FaultGateCanonicalJsonValueEqual $harness.launch_artifact_hashes $EvidenceBody.harness.direct_artifacts_retained_and_rehashed.hashes_at_start) -or
            $runBoundRunId -cne [string]$EvidenceBody.run_id -or -not (Test-FaultGateFullPathEquals -PublishedPath $runBoundRoot -ExpectedPath ([string]$EvidenceBody.run_root)) -or
            $runBoundLauncherPid -ne [uint64]$EvidenceBody.launcher.identity.pid -or $runBoundLauncherCreation -ne [int64]$EvidenceBody.launcher.identity.creation_filetime_utc -or
            [string]$runBound.launcher_command_line_sha256 -cne [string]$EvidenceBody.launcher.identity.command_line_sha256 -or
            [string]$runBound.startup_sha256 -cne [string]$EvidenceBody.launcher.startup_sha256 -or
            [string]$runBound.processes_sha256 -cne [string]$EvidenceBody.launcher.process_control_sha256 -or
            [string]$runBound.bindings_sha256 -cne [string]$EvidenceBody.launcher.campaign_bindings_sha256 -or
            $healthyAttempt -ne [uint64]$EvidenceBody.live_gate.monitor.attempt -or [string]$healthy.monitor_stdout_sha256 -cne [string]$EvidenceBody.live_gate.monitor.stdout_sha256 -or
            [string]$healthy.status -cne [string]$EvidenceBody.live_gate.monitor.report_status -or [string]$healthy.stage -cne [string]$EvidenceBody.live_gate.monitor.report_stage -or
            $healthyTelemetryRecords -ne [uint64]$EvidenceBody.live_gate.monitor.report_host_telemetry_records -or [string]$healthy.watchdog_ready_sha256 -cne [string]$EvidenceBody.live_gate.watchdog_ready.file_sha256 -or
            [string]$proposal.run_id -cne [string]$EvidenceBody.run_id -or -not (Test-FaultGateFullPathEquals -PublishedPath $proposal.run_root -ExpectedPath ([string]$EvidenceBody.run_root)) -or
            $proposalPid -ne [uint64]$EvidenceBody.fault.target.pid -or $proposalCreation -ne [int64]$EvidenceBody.fault.target.creation_filetime_utc -or $proposalParent -ne [uint64]$EvidenceBody.fault.target.parent_pid -or
            [string]$proposal.target_executable_sha256 -cne [string]$EvidenceBody.fault.target.executable_sha256 -or [string]$proposal.target_command_line_sha256 -cne [string]$EvidenceBody.fault.target.command_line_sha256 -or
            [string]$proposal.pre_fault_raw_prefixes_sha256 -cne [string]$EvidenceBody.raw_preservation.pre_fault_raw_prefixes_sha256 -or
            [string]$proposal.pre_fault_campaign_prefixes_sha256 -cne [string]$EvidenceBody.campaign_prefixes.pre_fault_campaign_prefixes_sha256 -or
            -not (Test-FaultGateCanonicalJsonValueEqual $proposal.pre_fault_campaign_prefixes $EvidenceBody.campaign_prefixes.pre_fault_campaign_prefixes) -or
            $launcherExit -ne [uint64]$EvidenceBody.launcher.exit_code -or $launcherTargetExit -ne [uint64]$EvidenceBody.fault.observed_exit_code -or
            $btcCoordinatorExit -ne [uint64]$expectedEvidenceBtcCoordinatorExit -or
            $btcCoordinatorExit -ne [uint64]$EvidenceBody.containment.btc_coordinator_exit_code -or $ethCaptureExit -ne [uint64]$EvidenceBody.containment.eth_capture_exit_code -or
            $ethCoordinatorExit -ne [uint64]$EvidenceBody.containment.eth_coordinator_exit_code -or $watchdogExit -ne [uint64]$EvidenceBody.containment.watchdog_exit_code -or
            $launcherOuterActive -ne [uint64]$EvidenceBody.containment.outer_active_processes -or $launcherInnerExists -ne [bool]$EvidenceBody.containment.inner_job_exists -or
            $launcherInnerError -ne [int64]$EvidenceBody.containment.inner_job_open_error -or
            $launcherWorkloadExists -ne [bool]$EvidenceBody.containment.workload_job_exists -or
            $launcherWorkloadError -ne [int64]$EvidenceBody.containment.workload_job_open_error -or
            [string]$evidenceProposed.terminal_sha256 -cne [string]$EvidenceBody.launcher.terminal_sha256 -or
            [string]$evidenceProposed.containment_sha256 -cne [string]$EvidenceBody.launcher.containment.sha256 -or
            [string]$evidenceProposed.launcher_journal_terminal_sha256 -cne [string]$EvidenceBody.launcher.launcher_journal.terminal_record_sha256 -or
            $evidenceOuterActive -ne [uint64]$EvidenceBody.containment.outer_active_processes -or $evidenceGlobal -ne [uint64]$EvidenceBody.containment.global_engine_processes -or
            $evidenceRunBound -ne [uint64]$EvidenceBody.containment.run_bound_processes -or
            $evidenceInnerExists -ne [bool]$EvidenceBody.containment.inner_job_exists -or
            $evidenceInnerError -ne [int64]$EvidenceBody.containment.inner_job_open_error -or
            $evidenceWorkloadExists -ne [bool]$EvidenceBody.containment.workload_job_exists -or
            $evidenceWorkloadError -ne [int64]$EvidenceBody.containment.workload_job_open_error) {
            throw "External fault journal event payloads do not crosslink exactly to fault evidence."
        }
    }
    return [pscustomobject][ordered]@{
        proposal_record_sha256 = $ProposalSha256
        injection_requested_record_sha256 = $InjectionRequestedSha256
        injected_record_sha256 = $InjectedSha256
        injected_envelope_monotonic_tick = [uint64]$injectedEnvelopeMonotonicTick
        launcher_exited_envelope_monotonic_tick = [uint64]$launcherExitedEnvelopeMonotonicTick
    }
}

function Read-FaultGateUInt32BigEndian {
    param([Parameter(Mandatory = $true)] [IO.Stream] $Stream)
    $buffer = Read-FaultGateExactBytes -Stream $Stream -Count 4
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($buffer) }
    return [BitConverter]::ToUInt32($buffer, 0)
}

function Read-FaultGateExactBytes {
    param([Parameter(Mandatory = $true)] [IO.Stream] $Stream, [Parameter(Mandatory = $true)] [int] $Count)
    $bytes = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($bytes, $offset, $Count - $offset)
        if ($read -le 0) { throw "Unexpected end of binary artifact." }
        $offset += $read
    }
    return $bytes
}

function Get-FaultGateSha256StreamPrefix {
    param(
        [Parameter(Mandatory = $true)] [IO.Stream] $Stream,
        [Parameter(Mandatory = $true)] [uint64] $Length
    )
    if (-not $Stream.CanRead -or -not $Stream.CanSeek -or $Length -gt [int64]::MaxValue) { throw "Stream cannot provide a bounded SHA-256 snapshot." }
    $Stream.Position = 0
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $buffer = [byte[]]::new(1MB)
        [uint64]$remaining = $Length
        while ($remaining -gt 0) {
            $wanted = [int][Math]::Min([uint64]$buffer.Length, $remaining)
            $read = $Stream.Read($buffer, 0, $wanted)
            if ($read -le 0) { throw "Stream shortened while hashing its bounded snapshot." }
            $null = $sha.TransformBlock($buffer, 0, $read, $null, 0)
            $remaining -= [uint64]$read
        }
        $null = $sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
        return ([BitConverter]::ToString($sha.Hash)).Replace("-", "").ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Get-FaultGatePathPrefixDigestSnapshot {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [uint64] $Length
    )
    $fullPath = [IO.Path]::GetFullPath($Path)
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $fullPath
    $stream = [IO.FileStream]::new($fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        if ($Length -eq 0 -or $Length -gt [uint64]$stream.Length) { throw "Requested prefix lies outside the file snapshot: $fullPath" }
        $first = Get-FaultGateSha256StreamPrefix -Stream $stream -Length $Length
        $second = Get-FaultGateSha256StreamPrefix -Stream $stream -Length $Length
        if ($first -cne $second) { throw "File prefix changed during bounded verification: $fullPath" }
        return $first
    }
    finally { $stream.Dispose() }
}

function Assert-FaultGatePreservedFilePrefix {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [uint64] $Length,
        [Parameter(Mandatory = $true)] [string] $ExpectedSha256,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if (-not (Test-FaultGateDigest $ExpectedSha256)) { throw "$Label expected prefix digest is invalid." }
    $observedSha256 = Get-FaultGatePathPrefixDigestSnapshot -Path $Path -Length $Length
    if ($observedSha256 -cne $ExpectedSha256) {
        throw "$Label exact prefix bytes were not preserved."
    }
    return $observedSha256
}

function Read-FaultGateProgress {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $ExpectedRawFile,
        [Parameter(Mandatory = $true)] [string] $ExpectedEpoch,
        [Parameter(Mandatory = $true)] [string] $ExpectedStream,
        [Parameter(Mandatory = $true)] [uint64] $FirstFrameIndex,
        [switch] $AllowPartialTail,
        [byte[]] $SnapshotBytes
    )
    $journalParameters = @{
        Path = $Path
        ExpectedSchema = "RawDurabilityProgressV1"
        RequireCanonicalCompactJson = $true
        MaximumRecordBytes = $script:FaultGateMaximumProgressRecordBytes
        MaximumPartialTailBytes = $script:FaultGateMaximumProgressPartialTailBytes
    }
    if (-not $AllowPartialTail) { $journalParameters["RequireCleanTail"] = $true }
    if ($PSBoundParameters.ContainsKey("SnapshotBytes")) { $journalParameters["SnapshotBytes"] = [byte[]]$SnapshotBytes }
    $journal = Read-FaultGateJournal @journalParameters
    $previousAck = $null
    foreach ($entry in $journal.entries) {
        Assert-FaultGateExactProperties -Value $entry.body -Names @("schema", "record_index", "raw_path", "ack", "previous_record_sha256") -Label "BNACK body"
        $rawPath = Get-FaultGateJsonNonEmptyString -Value $entry.body.raw_path -Label "BNACK raw_path"
        if ($rawPath -cne $ExpectedRawFile) { throw "BNACK raw_path drift: $Path" }
        $ack = $entry.body.ack
        Assert-FaultGateJsonObject -Value $ack -Label "BNACK ACK"
        Assert-FaultGateExactProperties -Value $ack -Names @("schema", "durable_record_count", "durable_through_offset", "last_record_sha256", "streams") -Label "BNACK ACK"
        $ackSchema = Get-FaultGateJsonNonEmptyString -Value $ack.schema -Label "BNACK schema"
        if ($ackSchema -cne "DurabilityAckV1" -or $ack.streams -isnot [array] -or @($ack.streams).Count -ne 1) { throw "Invalid BNACK ACK schema/cardinality: $Path" }
        $watermark = @($ack.streams)[0]
        Assert-FaultGateJsonObject -Value $watermark -Label "BNACK watermark"
        Assert-FaultGateExactProperties -Value $watermark -Names @("connection_epoch", "stream", "durable_through_frame_index") -Label "BNACK watermark"
        $count = Get-FaultGateJsonUnsignedInteger -Value $ack.durable_record_count -Label "BNACK durable_record_count"
        $durableThroughOffset = Get-FaultGateJsonUnsignedInteger -Value $ack.durable_through_offset -Label "BNACK durable_through_offset"
        $durableThroughFrameIndex = Get-FaultGateJsonUnsignedInteger -Value $watermark.durable_through_frame_index -Label "BNACK durable_through_frame_index"
        $watermarkEpoch = Get-FaultGateJsonNonEmptyString -Value $watermark.connection_epoch -Label "BNACK connection_epoch"
        $watermarkStream = Get-FaultGateJsonNonEmptyString -Value $watermark.stream -Label "BNACK stream"
        $expectedDurableThroughFrameIndex = Get-FaultGateInclusiveLastUInt64 -First $FirstFrameIndex -Count $count -Label "BNACK frame range"
        if ($count -eq 0 -or $durableThroughOffset -le 8 -or
            -not (Test-FaultGateDigest $ack.last_record_sha256) -or
            $watermarkEpoch -cne $ExpectedEpoch -or $watermarkStream -cne $ExpectedStream -or
            $durableThroughFrameIndex -ne $expectedDurableThroughFrameIndex) {
            throw "Invalid BNACK identity/range: $Path"
        }
        if ($null -ne $previousAck -and
            ($count -le [uint64]$previousAck.durable_record_count -or
             [uint64]$ack.durable_through_offset -le [uint64]$previousAck.durable_through_offset -or
             [uint64]$watermark.durable_through_frame_index -le [uint64]@($previousAck.streams)[0].durable_through_frame_index)) {
            throw "BNACK ACK regressed or did not advance: $Path"
        }
        $previousAck = $ack
    }
    return [pscustomobject][ordered]@{
        records = $journal.records
        raw_file = $ExpectedRawFile
        terminal_record_sha256 = $journal.terminal_record_sha256
        file_bytes = $journal.file_bytes
        file_sha256 = $journal.file_sha256
        verified_through_offset = $journal.verified_through_offset
        verified_prefix_sha256 = $journal.verified_prefix_sha256
        partial_tail_bytes = $journal.partial_tail_bytes
        partial_tail = -not [bool]$journal.clean_tail
        acknowledgements = @($journal.entries | ForEach-Object { $_.body.ack })
        latest_ack = $previousAck
    }
}

function Read-FaultGateRawPrefix {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [uint64] $Limit,
        [Parameter(Mandatory = $true)] [uint64] $ExpectedRecords,
        [Parameter(Mandatory = $true)] [uint64] $FirstFrameIndex,
        [Parameter(Mandatory = $true)] [string] $InitialPreviousSha256,
        [Parameter(Mandatory = $true)] [string] $ExpectedEpoch,
        [Parameter(Mandatory = $true)] [string] $ExpectedStream,
        [Parameter(Mandatory = $true)] [string] $ExpectedEndpoint,
        [Parameter(Mandatory = $true)] [string] $ExpectedSymbol,
        [Parameter(Mandatory = $true)] [string] $ExpectedSpecRevision,
        $Acknowledgements = @()
    )
    $expectedLastFrameIndex = Get-FaultGateInclusiveLastUInt64 -First $FirstFrameIndex -Count $ExpectedRecords -Label "BNRAW expected frame range"
    $file = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $snapshotLength = [uint64]$file.Length
        if ($Limit -gt $snapshotLength -or $Limit -gt [int64]::MaxValue) { throw "BNRAW durable limit exceeds the observed file: $Path" }
        $initialObservedSnapshotSha256 = Get-FaultGateSha256StreamPrefix -Stream $file -Length $snapshotLength
        $file.Position = 0
        $magic = Read-FaultGateExactBytes -Stream $file -Count 8
        if ([Text.Encoding]::ASCII.GetString($magic, 0, 5) -cne "BNRAW" -or $magic[5] -ne 0 -or $magic[6] -ne 1 -or $magic[7] -ne 10) {
            throw "Bad BNRAW magic: $Path"
        }
        $previous = $InitialPreviousSha256
        $records = [uint64]0
        $checkpoints = @{}
        foreach ($checkpoint in @($Acknowledgements)) {
            $checkpointCount = [uint64]$checkpoint.durable_record_count
            if ($checkpoints.ContainsKey([string]$checkpointCount) -or $checkpointCount -gt $ExpectedRecords) { throw "BNACK checkpoint count is duplicate/outside BNRAW prefix: $Path" }
            $checkpoints[[string]$checkpointCount] = $checkpoint
        }
        $matchedCheckpoints = [uint64]0
        while ([uint64]$file.Position -lt $Limit) {
            $remainingRawBytes = [uint64]($Limit - [uint64]$file.Position)
            if ($remainingRawBytes -lt 36) { throw "Partial BNRAW record in durable prefix: $Path" }
            $length = [uint32](Read-FaultGateUInt32BigEndian -Stream $file)
            $requiredRawRecordRemainder = Add-FaultGateCheckedUInt64 -Left ([uint64]$length) -Right 32 -Label "BNRAW body/digest framing"
            $remainingRawAfterLength = [uint64]($Limit - [uint64]$file.Position)
            if ($length -eq 0 -or $length -gt 4MB -or $requiredRawRecordRemainder -gt $remainingRawAfterLength) {
                throw "Invalid BNRAW record length in durable prefix: $Path"
            }
            $bodyBytes = Read-FaultGateExactBytes -Stream $file -Count ([int]$length)
            $digestBytes = Read-FaultGateExactBytes -Stream $file -Count 32
            $digest = ([BitConverter]::ToString($digestBytes)).Replace("-", "").ToLowerInvariant()
            if ((Get-FaultGateSha256Bytes -Bytes $bodyBytes) -cne $digest) { throw "BNRAW body digest mismatch: $Path" }
            try { $bodyText = [Text.UTF8Encoding]::new($false, $true).GetString($bodyBytes); $record = $bodyText | ConvertFrom-Json -ErrorAction Stop }
            catch { throw "Invalid UTF-8/JSON BNRAW record: $Path" }
            Assert-FaultGateJsonObject -Value $record -Label "BNRAW record"
            $canonicalBodyText = [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateSerdeCompactJsonBytes -Value $record))
            if ($bodyText -cne $canonicalBodyText) { throw "Non-canonical compact BNRAW JSON record: $Path" }
            Assert-FaultGateExactProperties -Value $record -Names @(
                "schema", "venue", "environment", "endpoint", "stream", "symbol", "connection_epoch", "frame_index",
                "receive_wall_ns", "receive_mono_ns", "clock_quality", "clock_source", "clock_offset_ns", "clock_uncertainty_ns",
                "payload_length", "payload_sha256", "payload_base64", "recorder_state", "spec_revision", "previous_record_sha256"
            ) -Label "BNRAW record"
            $rawSchema = Get-FaultGateJsonNonEmptyString -Value $record.schema -Label "BNRAW schema"
            $rawVenue = Get-FaultGateJsonNonEmptyString -Value $record.venue -Label "BNRAW venue"
            $rawEnvironment = Get-FaultGateJsonNonEmptyString -Value $record.environment -Label "BNRAW environment"
            $rawEndpoint = Get-FaultGateJsonNonEmptyString -Value $record.endpoint -Label "BNRAW endpoint"
            $rawStream = Get-FaultGateJsonNonEmptyString -Value $record.stream -Label "BNRAW stream"
            $rawSymbol = Get-FaultGateJsonNonEmptyString -Value $record.symbol -Label "BNRAW symbol"
            $rawEpoch = Get-FaultGateJsonNonEmptyString -Value $record.connection_epoch -Label "BNRAW connection_epoch"
            $rawFrameIndex = Get-FaultGateJsonUnsignedInteger -Value $record.frame_index -Label "BNRAW frame_index"
            $null = Get-FaultGateJsonUnsignedInteger -Value $record.receive_wall_ns -Label "BNRAW receive_wall_ns"
            $null = Get-FaultGateJsonUnsignedInteger -Value $record.receive_mono_ns -Label "BNRAW receive_mono_ns"
            $null = Get-FaultGateJsonNonEmptyString -Value $record.clock_quality -Label "BNRAW clock_quality"
            $null = Get-FaultGateJsonNonEmptyString -Value $record.clock_source -Label "BNRAW clock_source"
            if ($null -ne $record.clock_offset_ns) { $null = Get-FaultGateJsonSignedInteger -Value $record.clock_offset_ns -Label "BNRAW clock_offset_ns" }
            if ($null -ne $record.clock_uncertainty_ns) { $null = Get-FaultGateJsonUnsignedInteger -Value $record.clock_uncertainty_ns -Label "BNRAW clock_uncertainty_ns" }
            $rawPayloadLength = Get-FaultGateJsonUnsignedInteger -Value $record.payload_length -Label "BNRAW payload_length"
            $rawPayloadBase64 = Get-FaultGateJsonString -Value $record.payload_base64 -Label "BNRAW payload_base64"
            $rawRecorderState = Get-FaultGateJsonNonEmptyString -Value $record.recorder_state -Label "BNRAW recorder_state"
            $rawSpecRevision = Get-FaultGateJsonNonEmptyString -Value $record.spec_revision -Label "BNRAW spec_revision"
            $frame = Add-FaultGateCheckedUInt64 -Left $FirstFrameIndex -Right $records -Label "BNRAW current frame index"
            if ($rawSchema -cne "RawFrameV1" -or $rawVenue -cne "binance-spot" -or $rawEnvironment -cne "production-public-market-data" -or
                $rawStream -cne $ExpectedStream -or $rawEndpoint -cne $ExpectedEndpoint -or $rawSymbol -cne $ExpectedSymbol -or
                $rawEpoch -cne $ExpectedEpoch -or $rawFrameIndex -ne $frame -or -not (Test-FaultGateDigest $record.previous_record_sha256) -or
                [string]$record.previous_record_sha256 -cne $previous -or $rawRecorderState -cne "PENDING" -or $rawSpecRevision -cne $ExpectedSpecRevision -or
                -not (Test-FaultGateDigest $record.payload_sha256)) {
                throw "BNRAW identity/hash-chain/frame mismatch: $Path"
            }
            try { $payload = [Convert]::FromBase64String($rawPayloadBase64) }
            catch { throw "Invalid BNRAW payload base64: $Path" }
            if ([Convert]::ToBase64String($payload) -cne $rawPayloadBase64 -or [uint64]$payload.Length -ne $rawPayloadLength -or
                (Get-FaultGateSha256Bytes -Bytes $payload) -cne [string]$record.payload_sha256) {
                throw "BNRAW payload length/hash mismatch: $Path"
            }
            # RawFrameV1 ends at the WebSocket application-message byte boundary, before
            # JSON interpretation.  Keep the payload opaque here: canonical base64,
            # length and SHA-256 above prove the exact bytes, including binary frames and
            # case-sensitive JSON names such as Binance's simultaneous `e` and `E`.
            # Typed Rust/Python verification interprets those bytes only after this raw
            # durability boundary has been established.
            $previous = $digest
            $records++
            if ($checkpoints.ContainsKey([string]$records)) {
                $checkpoint = $checkpoints[[string]$records]
                $watermark = @($checkpoint.streams)[0]
                $expectedCheckpointFrameIndex = Get-FaultGateInclusiveLastUInt64 -First $FirstFrameIndex -Count $records -Label "BNACK checkpoint frame range"
                if ([uint64]$checkpoint.durable_through_offset -ne [uint64]$file.Position -or
                    [string]$checkpoint.last_record_sha256 -cne $previous -or
                    [uint64]$watermark.durable_through_frame_index -ne $expectedCheckpointFrameIndex) { throw "BNACK checkpoint does not match exact BNRAW boundary: $Path" }
                $matchedCheckpoints++
            }
        }
        if ([uint64]$file.Position -ne $Limit -or $records -ne $ExpectedRecords -or $matchedCheckpoints -ne [uint64]$checkpoints.Count) { throw "BNRAW durable boundary/count/checkpoint mismatch: $Path" }
        $verifiedPrefixSha256 = Get-FaultGateSha256StreamPrefix -Stream $file -Length $Limit
        $observedSnapshotSha256 = Get-FaultGateSha256StreamPrefix -Stream $file -Length $snapshotLength
        if ($observedSnapshotSha256 -cne $initialObservedSnapshotSha256) { throw "BNRAW bounded snapshot bytes changed during semantic validation: $Path" }
        return [pscustomobject][ordered]@{
            raw_file = [IO.Path]::GetFileName($Path)
            connection_epoch = $ExpectedEpoch
            stream = $ExpectedStream
            observed_file_bytes = $snapshotLength
            durable_through_offset = $Limit
            durable_records = $records
            first_frame_index = $FirstFrameIndex
            last_frame_index = $expectedLastFrameIndex
            terminal_record_sha256 = $previous
            verified_prefix_sha256 = $verifiedPrefixSha256
            unverified_suffix_bytes = $snapshotLength - $Limit
            full_file_sha256 = $observedSnapshotSha256
        }
    }
    finally { $file.Dispose() }
}

function Read-FaultGateSegmentManifest {
    param([Parameter(Mandatory = $true)] [string] $Path, [switch] $AllowPartialTail)
    $file = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $length = [uint64]$file.Length
        $initialManifestSnapshotSha256 = Get-FaultGateSha256StreamPrefix -Stream $file -Length $length
        $file.Position = 0
        $magic = Read-FaultGateExactBytes -Stream $file -Count 8
        if ([Text.Encoding]::ASCII.GetString($magic, 0, 5) -cne "BNSEG" -or $magic[5] -ne 0 -or $magic[6] -ne 1 -or $magic[7] -ne 10) {
            throw "Bad BNSEG magic: $Path"
        }
        $seals = [Collections.Generic.List[object]]::new()
        $verifiedRecords = [Collections.Generic.List[object]]::new()
        $previous = $script:FaultGateZeroDigest
        $verifiedThrough = [uint64]$file.Position
        $partialTailBytes = [uint64]0
        while ([uint64]$file.Position -lt $length) {
            $recordStart = [uint64]$file.Position
            $remainingManifestBytes = [uint64]($length - $recordStart)
            if ($remainingManifestBytes -lt 36) {
                if ($AllowPartialTail -and $seals.Count -ne 0) { $partialTailBytes = $length - $recordStart; break }
                throw "Partial BNSEG tail: $Path"
            }
            $bodyLength = [uint32](Read-FaultGateUInt32BigEndian -Stream $file)
            if ($bodyLength -eq 0 -or $bodyLength -gt 1MB) { throw "Invalid BNSEG record length: $Path" }
            $requiredManifestRecordRemainder = Add-FaultGateCheckedUInt64 -Left ([uint64]$bodyLength) -Right 32 -Label "BNSEG body/digest framing"
            $remainingManifestAfterLength = [uint64]($length - [uint64]$file.Position)
            if ($requiredManifestRecordRemainder -gt $remainingManifestAfterLength) {
                if ($AllowPartialTail -and $seals.Count -ne 0) { $partialTailBytes = $length - $recordStart; break }
                throw "Partial BNSEG record: $Path"
            }
            $bodyBytes = Read-FaultGateExactBytes -Stream $file -Count ([int]$bodyLength)
            $digestBytes = Read-FaultGateExactBytes -Stream $file -Count 32
            $digest = ([BitConverter]::ToString($digestBytes)).Replace("-", "").ToLowerInvariant()
            if ((Get-FaultGateSha256Bytes -Bytes $bodyBytes) -cne $digest) { throw "BNSEG record digest mismatch: $Path" }
            $bodyText = [Text.UTF8Encoding]::new($false, $true).GetString($bodyBytes)
            $body = $bodyText | ConvertFrom-Json -ErrorAction Stop
            Assert-FaultGateJsonObject -Value $body -Label "BNSEG body"
            if ([Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateSerdeCompactJsonBytes -Value $body)) -cne $bodyText) { throw "Non-canonical BNSEG JSON: $Path" }
            Assert-FaultGateExactProperties -Value $body -Names @("schema", "record_index", "previous_manifest_record_sha256", "seal") -Label "BNSEG body"
            $manifestSchema = Get-FaultGateJsonNonEmptyString -Value $body.schema -Label "BNSEG manifest schema"
            $manifestRecordIndex = Get-FaultGateJsonUnsignedInteger -Value $body.record_index -Label "BNSEG record_index"
            if ($manifestSchema -cne "RawSegmentManifestRecordV1" -or $manifestRecordIndex -ne [uint64]$seals.Count -or
                -not (Test-FaultGateDigest $body.previous_manifest_record_sha256) -or [string]$body.previous_manifest_record_sha256 -cne $previous) { throw "BNSEG manifest chain mismatch: $Path" }
            $seal = $body.seal
            Assert-FaultGateJsonObject -Value $seal -Label "BNSEG seal"
            Assert-FaultGateExactProperties -Value $seal -Names @(
                "schema", "segment_index", "raw_file", "connection_epoch", "stream", "first_frame_index", "last_frame_index",
                "records", "durable_through_offset", "previous_segment_terminal_sha256", "terminal_record_sha256"
            ) -Label "BNSEG seal"
            $sealSchema = Get-FaultGateJsonNonEmptyString -Value $seal.schema -Label "BNSEG seal schema"
            $segmentIndex = Get-FaultGateJsonUnsignedInteger -Value $seal.segment_index -Label "BNSEG segment_index"
            $sealRawFile = Get-FaultGateJsonNonEmptyString -Value $seal.raw_file -Label "BNSEG raw_file"
            $null = Get-FaultGateJsonNonEmptyString -Value $seal.connection_epoch -Label "BNSEG connection_epoch"
            $null = Get-FaultGateJsonNonEmptyString -Value $seal.stream -Label "BNSEG stream"
            $sealFirstFrame = Get-FaultGateJsonUnsignedInteger -Value $seal.first_frame_index -Label "BNSEG first_frame_index"
            $sealLastFrame = Get-FaultGateJsonUnsignedInteger -Value $seal.last_frame_index -Label "BNSEG last_frame_index"
            $sealRecords = Get-FaultGateJsonUnsignedInteger -Value $seal.records -Label "BNSEG records"
            $null = Get-FaultGateJsonUnsignedInteger -Value $seal.durable_through_offset -Label "BNSEG durable_through_offset"
            $expectedSealRecords = Get-FaultGateInclusiveCountUInt64 -First $sealFirstFrame -Last $sealLastFrame -Label "BNSEG frame range"
            if ($sealSchema -cne "RawSegmentSealV1" -or $segmentIndex -ne [uint64]$seals.Count -or
                $sealRawFile -cne ("segment-{0:D6}.bnraw" -f [uint64]$seals.Count) -or
                $sealRecords -eq 0 -or $sealRecords -ne $expectedSealRecords -or
                -not (Test-FaultGateDigest $seal.previous_segment_terminal_sha256) -or -not (Test-FaultGateDigest $seal.terminal_record_sha256)) {
                throw "Invalid BNSEG seal: $Path"
            }
            if ($seals.Count -eq 0) {
                if ([uint64]$seal.first_frame_index -ne 0 -or [string]$seal.previous_segment_terminal_sha256 -cne $script:FaultGateZeroDigest) { throw "BNSEG does not begin at genesis: $Path" }
            }
            else {
                $old = $seals[$seals.Count - 1]
                $expectedSuccessorFirstFrame = Get-FaultGateUInt64Successor -Value ([uint64]$old.last_frame_index) -Label "BNSEG successor first frame"
                if ([string]$seal.connection_epoch -cne [string]$old.connection_epoch -or [string]$seal.stream -cne [string]$old.stream -or
                    [uint64]$seal.first_frame_index -ne $expectedSuccessorFirstFrame -or
                    [string]$seal.previous_segment_terminal_sha256 -cne [string]$old.terminal_record_sha256) { throw "BNSEG transition is not contiguous: $Path" }
            }
            $seals.Add($seal)
            $previous = $digest
            $verifiedThrough = [uint64]$file.Position
            $verifiedRecords.Add([pscustomobject][ordered]@{
                record_index = [uint64]$manifestRecordIndex
                verified_through_offset = $verifiedThrough
                terminal_record_sha256 = $previous
                verified_prefix_sha256 = Get-FaultGateSha256StreamPrefix -Stream $file -Length $verifiedThrough
            })
        }
        $verifiedPrefixSha256 = Get-FaultGateSha256StreamPrefix -Stream $file -Length $verifiedThrough
        $manifestSnapshotSha256 = Get-FaultGateSha256StreamPrefix -Stream $file -Length $length
        if ($manifestSnapshotSha256 -cne $initialManifestSnapshotSha256) { throw "BNSEG bounded snapshot bytes changed during semantic validation: $Path" }
        return [pscustomobject][ordered]@{
            records = [uint64]$seals.Count
            terminal_record_sha256 = $previous
            file_bytes = $length
            file_sha256 = $manifestSnapshotSha256
            verified_through_offset = $verifiedThrough
            verified_prefix_sha256 = $verifiedPrefixSha256
            partial_tail_bytes = $partialTailBytes
            verified_records = @($verifiedRecords)
            seals = @($seals)
        }
    }
    finally { $file.Dispose() }
}

function Assert-FaultGateExactBytes {
    param(
        [Parameter(Mandatory = $true)] [byte[]] $Actual,
        [Parameter(Mandatory = $true)] [byte[]] $Expected,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ($Actual.Length -ne $Expected.Length) { throw "$Label byte length is not writer-canonical." }
    for ($index = 0; $index -lt $Actual.Length; $index++) {
        if ($Actual[$index] -ne $Expected[$index]) { throw "$Label bytes are not writer-canonical." }
    }
}

function Get-FaultGateExpectedInjectedCoordinatorStderr {
    param([Parameter(Mandatory = $true)] [string] $CampaignDirectory)
    if ([string]::IsNullOrWhiteSpace($CampaignDirectory) -or -not [IO.Path]::IsPathRooted($CampaignDirectory) -or
        $CampaignDirectory.IndexOf([char]0) -ge 0 -or $CampaignDirectory.IndexOf("`r", [StringComparison]::Ordinal) -ge 0 -or
        $CampaignDirectory.IndexOf("`n", [StringComparison]::Ordinal) -ge 0) {
        throw "Injected coordinator stderr campaign directory is not one exact absolute path."
    }
    $text = "raw-campaign: raw campaign failed: generation 0 exited without COMPLETE terminal evidence; evidence at " + $CampaignDirectory + "`n"
    [byte[]]$canonicalBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($text)
    return [pscustomobject][ordered]@{
        classification = "EXACT_INJECTED_GENERATION_ZERO_CAMPAIGN_FAILURE"
        file = "btcusdt.stderr.log"
        bytes = [uint64]$canonicalBytes.Length
        sha256 = Get-FaultGateSha256Bytes -Bytes $canonicalBytes
        terminal_failure = "BTCUSDT coordinator wrote unexpected stderr (" +
            ([uint64]$canonicalBytes.Length).ToString([Globalization.CultureInfo]::InvariantCulture) + " bytes)."
        canonical_bytes = $canonicalBytes
    }
}

function Test-FaultGateResponseHeaders {
    param([Parameter(Mandatory = $true)] $Headers, [Parameter(Mandatory = $true)] [string] $Label)
    Assert-FaultGateJsonObject -Value $Headers -Label $Label
    [string[]]$names = @($Headers.PSObject.Properties.Name)
    if ($names.Count -eq 0) { throw "$Label must not be empty." }
    [string[]]$sortedNames = @($names)
    [Array]::Sort($sortedNames, [StringComparer]::Ordinal)
    if (($names -join "`n") -cne ($sortedNames -join "`n")) { throw "$Label keys are not in the producer's ordinal order." }
    foreach ($name in $names) {
        if ([string]::IsNullOrWhiteSpace($name) -or $name.IndexOf("`r", [StringComparison]::Ordinal) -ge 0 -or $name.IndexOf("`n", [StringComparison]::Ordinal) -ge 0) {
            throw "$Label contains an invalid header name."
        }
        $values = $Headers.PSObject.Properties[$name].Value
        Assert-FaultGateJsonArray -Value $values -Label "$Label.$name"
        if (@($values).Count -eq 0) { throw "$Label.$name must not be empty." }
        foreach ($value in @($values)) {
            if ($value -isnot [string] -or [string]$value -cmatch "[`r`n]") { throw "$Label.$name contains a non-string or CR/LF header value." }
        }
    }
}

function Test-FaultGateSocketEndpoint {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)] [string] $Label,
        [uint16] $ExpectedPort = 0
    )
    $text = Get-FaultGateJsonNonEmptyString -Value $Value -Label $Label
    $endpointHost = $null
    $portText = $null
    if ($text.StartsWith("[", [StringComparison]::Ordinal)) {
        $close = $text.IndexOf(']')
        if ($close -le 1 -or $close + 2 -ge $text.Length -or $text[$close + 1] -cne ':') { throw "$Label is not a canonical bracketed IPv6 socket address." }
        $endpointHost = $text.Substring(1, $close - 1)
        $portText = $text.Substring($close + 2)
    }
    else {
        $colon = $text.LastIndexOf(':')
        if ($colon -le 0 -or $colon -eq $text.Length - 1 -or $text.IndexOf(':') -ne $colon) { throw "$Label is not a canonical IPv4 socket address." }
        $endpointHost = $text.Substring(0, $colon)
        $portText = $text.Substring($colon + 1)
    }
    if ($portText -cnotmatch '^(0|[1-9][0-9]*)$') { throw "$Label has a non-canonical port." }
    [uint16]$port = 0
    if (-not [uint16]::TryParse($portText, [ref]$port) -or $port -eq 0 -or ($ExpectedPort -ne 0 -and $port -ne $ExpectedPort)) { throw "$Label has an invalid port." }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($endpointHost, [ref]$address) -or $address.Equals([Net.IPAddress]::Any) -or $address.Equals([Net.IPAddress]::IPv6Any)) {
        throw "$Label has an invalid or unspecified IP address."
    }
    return [pscustomobject][ordered]@{ text = $text; address = $address.ToString(); port = $port }
}

function ConvertTo-FaultGateSerdeTransportBytes {
    param([Parameter(Mandatory = $true)] $Metadata)
    $connection = $Metadata.connection
    $builder = [Text.StringBuilder]::new()
    $appendProperty = {
        param([string]$Indent, [string]$Name, $Value, [bool]$Comma)
        $literal = if ($Value -is [string]) { ConvertTo-FaultGateSerdeJsonStringLiteral -Value ([string]$Value) } else { [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture).ToLowerInvariant() }
        $null = $builder.Append($Indent).Append((ConvertTo-FaultGateSerdeJsonStringLiteral -Value $Name)).Append(": ").Append($literal)
        if ($Comma) { $null = $builder.Append(',') }
        $null = $builder.Append("`n")
    }
    $null = $builder.Append("{`n")
    & $appendProperty "  " "schema" $Metadata.schema $true
    & $appendProperty "  " "session_id" $Metadata.session_id $true
    & $appendProperty "  " "generation_index" $Metadata.generation_index $true
    & $appendProperty "  " "symbol" $Metadata.symbol $true
    & $appendProperty "  " "spec_revision" $Metadata.spec_revision $true
    $null = $builder.Append("  `"connection`": {`n")
    & $appendProperty "    " "stream" $connection.stream $true
    & $appendProperty "    " "connection_epoch" $connection.connection_epoch $true
    & $appendProperty "    " "uri" $connection.uri $true
    & $appendProperty "    " "websocket_http_status" $connection.websocket_http_status $true
    & $appendProperty "    " "local_endpoint" $connection.local_endpoint $true
    & $appendProperty "    " "remote_endpoint" $connection.remote_endpoint $true
    $null = $builder.Append("    `"response_headers`": {`n")
    [string[]]$headerNames = @($connection.response_headers.PSObject.Properties.Name)
    for ($headerIndex = 0; $headerIndex -lt $headerNames.Count; $headerIndex++) {
        $headerName = $headerNames[$headerIndex]
        $null = $builder.Append("      ").Append((ConvertTo-FaultGateSerdeJsonStringLiteral -Value $headerName)).Append(": [`n")
        $headerValues = @($connection.response_headers.PSObject.Properties[$headerName].Value)
        for ($valueIndex = 0; $valueIndex -lt $headerValues.Count; $valueIndex++) {
            $null = $builder.Append("        ").Append((ConvertTo-FaultGateSerdeJsonStringLiteral -Value ([string]$headerValues[$valueIndex])))
            if ($valueIndex + 1 -lt $headerValues.Count) { $null = $builder.Append(',') }
            $null = $builder.Append("`n")
        }
        $null = $builder.Append("      ]")
        if ($headerIndex + 1 -lt $headerNames.Count) { $null = $builder.Append(',') }
        $null = $builder.Append("`n")
    }
    $null = $builder.Append("    }`n  }`n}`n")
    return [Text.UTF8Encoding]::new($false).GetBytes($builder.ToString())
}

function Test-FaultGateSnapshotHttpArtifact {
    param(
        [Parameter(Mandatory = $true)] [byte[]] $MetadataBytes,
        [Parameter(Mandatory = $true)] $SnapshotBody,
        [Parameter(Mandatory = $true)] [string] $RawRecordSha256,
        [Parameter(Mandatory = $true)] [string] $ExpectedEndpoint
    )
    try { $metadataText = [Text.UTF8Encoding]::new($false, $true).GetString($MetadataBytes); $metadata = $metadataText | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Snapshot HTTP metadata is not strict UTF-8 JSON." }
    Assert-FaultGateJsonObject -Value $metadata -Label "snapshot HTTP metadata"
    Assert-FaultGateExactProperties -Value $metadata -Names @(
        "schema", "endpoint", "http_status", "headers", "receive_wall_ns", "receive_mono_ns", "body_complete", "body_length", "body_sha256", "raw_file", "raw_record_sha256"
    ) -Label "snapshot HTTP metadata"
    Assert-FaultGateExactBytes -Actual $MetadataBytes -Expected (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $metadata) -Label "snapshot HTTP metadata"
    $metadataStatus = Get-FaultGateJsonUnsignedInteger -Value $metadata.http_status -Label "snapshot HTTP status" -Maximum ([uint16]::MaxValue)
    $metadataWall = Get-FaultGateJsonUnsignedInteger -Value $metadata.receive_wall_ns -Label "snapshot HTTP receive wall"
    $metadataMono = Get-FaultGateJsonUnsignedInteger -Value $metadata.receive_mono_ns -Label "snapshot HTTP receive monotonic"
    $metadataComplete = Get-FaultGateJsonBoolean -Value $metadata.body_complete -Label "snapshot HTTP body_complete"
    $metadataLength = Get-FaultGateJsonUnsignedInteger -Value $metadata.body_length -Label "snapshot HTTP body length"
    foreach ($field in @("schema", "endpoint", "body_sha256", "raw_file", "raw_record_sha256")) { $null = Get-FaultGateJsonNonEmptyString -Value $metadata.$field -Label "snapshot HTTP $field" }
    Assert-FaultGateEvidenceDigest -Value $metadata.body_sha256 -Label "snapshot HTTP body digest"
    Assert-FaultGateEvidenceDigest -Value $metadata.raw_record_sha256 -Label "snapshot HTTP raw record digest"
    Test-FaultGateResponseHeaders -Headers $metadata.headers -Label "snapshot HTTP headers"
    $payloadBase64 = Get-FaultGateJsonNonEmptyString -Value $SnapshotBody.payload_base64 -Label "snapshot frame payload_base64"
    try { [byte[]]$payloadBytes = [Convert]::FromBase64String($payloadBase64) }
    catch { throw "Snapshot frame payload base64 is invalid." }
    if ([Convert]::ToBase64String($payloadBytes) -cne $payloadBase64) { throw "Snapshot frame payload base64 is non-canonical." }
    try { $payloadText = [Text.UTF8Encoding]::new($false, $true).GetString($payloadBytes); $payload = $payloadText | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Snapshot body is not strict UTF-8 JSON." }
    Assert-FaultGateJsonObject -Value $payload -Label "snapshot body"
    foreach ($name in @("lastUpdateId", "bids", "asks")) {
        if ($payload.PSObject.Properties.Name -cnotcontains $name) { throw "Snapshot body lacks $name." }
    }
    $lastUpdateId = Get-FaultGateJsonUnsignedInteger -Value $payload.lastUpdateId -Label "snapshot lastUpdateId"
    Assert-FaultGateJsonArray -Value $payload.bids -Label "snapshot bids"
    Assert-FaultGateJsonArray -Value $payload.asks -Label "snapshot asks"
    foreach ($side in @("bids", "asks")) {
        foreach ($level in @($payload.$side)) {
            Assert-FaultGateJsonArray -Value $level -Label "snapshot $side level"
            if (@($level).Count -ne 2 -or @($level)[0] -isnot [string] -or @($level)[1] -isnot [string]) { throw "Snapshot $side level is not an exact price/quantity string pair." }
        }
    }
    $frameWall = Get-FaultGateJsonUnsignedInteger -Value $SnapshotBody.receive_wall_ns -Label "snapshot frame receive wall"
    $frameMono = Get-FaultGateJsonUnsignedInteger -Value $SnapshotBody.receive_mono_ns -Label "snapshot frame receive monotonic"
    $frameLength = Get-FaultGateJsonUnsignedInteger -Value $SnapshotBody.payload_length -Label "snapshot frame payload length"
    Assert-FaultGateEvidenceDigest -Value $SnapshotBody.payload_sha256 -Label "snapshot frame payload digest"
    if ([string]$metadata.schema -cne "SnapshotHttpMetadataV1" -or [string]$metadata.endpoint -cne $ExpectedEndpoint -or $metadataStatus -ne 200 -or
        -not $metadataComplete -or $metadataWall -ne $frameWall -or $metadataMono -ne $frameMono -or $metadataLength -ne $frameLength -or
        $metadataLength -ne [uint64]$payloadBytes.Length -or [string]$metadata.body_sha256 -cne [string]$SnapshotBody.payload_sha256 -or
        [string]$metadata.body_sha256 -cne (Get-FaultGateSha256Bytes -Bytes $payloadBytes) -or [string]$metadata.raw_file -cne "snapshot.bnraw" -or
        [string]$metadata.raw_record_sha256 -cne $RawRecordSha256 -or $frameWall -eq 0 -or $frameMono -eq 0) {
        throw "Snapshot HTTP metadata is not bound to the exact raw snapshot body."
    }
    return [pscustomobject][ordered]@{
        raw_frame_summary = [pscustomobject][ordered]@{
            endpoint = $ExpectedEndpoint; connection_epoch = [string]$SnapshotBody.connection_epoch
            receive_wall_ns = $frameWall; receive_mono_ns = $frameMono; payload_length = $frameLength
            payload_sha256 = [string]$SnapshotBody.payload_sha256; last_update_id = $lastUpdateId
            bid_levels = [uint64]@($payload.bids).Count; ask_levels = [uint64]@($payload.asks).Count
        }
        http_metadata = $metadata
    }
}

function Test-FaultGateTransportMetadataArtifact {
    param(
        [Parameter(Mandatory = $true)] [byte[]] $MetadataBytes,
        [Parameter(Mandatory = $true)] $CampaignEvent,
        [Parameter(Mandatory = $true)] [ValidateSet("depth", "trade")] [string] $ExpectedStream,
        [Parameter(Mandatory = $true)] [string] $ExpectedSessionId,
        [Parameter(Mandatory = $true)] [string] $ExpectedSymbol,
        [Parameter(Mandatory = $true)] [string] $ExpectedSpecRevision
    )
    try { $metadataText = [Text.UTF8Encoding]::new($false, $true).GetString($MetadataBytes); $metadata = $metadataText | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "$ExpectedSymbol/$ExpectedStream transport metadata is not strict UTF-8 JSON." }
    Assert-FaultGateJsonObject -Value $metadata -Label "$ExpectedSymbol/$ExpectedStream transport metadata"
    Assert-FaultGateExactProperties -Value $metadata -Names @("schema", "session_id", "generation_index", "symbol", "spec_revision", "connection") -Label "$ExpectedSymbol/$ExpectedStream transport metadata"
    Assert-FaultGateJsonObject -Value $metadata.connection -Label "$ExpectedSymbol/$ExpectedStream transport connection"
    Assert-FaultGateExactProperties -Value $metadata.connection -Names @("stream", "connection_epoch", "uri", "websocket_http_status", "local_endpoint", "remote_endpoint", "response_headers") -Label "$ExpectedSymbol/$ExpectedStream transport connection"
    Test-FaultGateResponseHeaders -Headers $metadata.connection.response_headers -Label "$ExpectedSymbol/$ExpectedStream transport headers"
    Assert-FaultGateExactBytes -Actual $MetadataBytes -Expected (ConvertTo-FaultGateSerdeTransportBytes -Metadata $metadata) -Label "$ExpectedSymbol/$ExpectedStream transport metadata"
    Assert-FaultGateJsonObject -Value $CampaignEvent -Label "$ExpectedSymbol/$ExpectedStream transport campaign event"
    Assert-FaultGateExactProperties -Value $CampaignEvent -Names @("body", "record_sha256") -Label "$ExpectedSymbol/$ExpectedStream transport campaign event"
    Assert-FaultGateJsonObject -Value $CampaignEvent.body -Label "$ExpectedSymbol/$ExpectedStream transport campaign body"
    Assert-FaultGateExactProperties -Value $CampaignEvent.body -Names @("schema", "record_index", "wall_ns", "campaign_mono_ns", "generation_index", "channel", "payload", "previous_record_sha256") -Label "$ExpectedSymbol/$ExpectedStream transport campaign body"
    $null = Get-FaultGateJsonUnsignedInteger -Value $CampaignEvent.body.record_index -Label "$ExpectedSymbol/$ExpectedStream transport record index"
    $null = Get-FaultGateJsonUnsignedInteger -Value $CampaignEvent.body.wall_ns -Label "$ExpectedSymbol/$ExpectedStream transport wall"
    $null = Get-FaultGateJsonUnsignedInteger -Value $CampaignEvent.body.campaign_mono_ns -Label "$ExpectedSymbol/$ExpectedStream transport monotonic"
    $eventGeneration = Get-FaultGateJsonUnsignedInteger -Value $CampaignEvent.body.generation_index -Label "$ExpectedSymbol/$ExpectedStream transport generation"
    Assert-FaultGateEvidenceDigest -Value $CampaignEvent.body.previous_record_sha256 -Label "$ExpectedSymbol/$ExpectedStream transport previous digest"
    Assert-FaultGateEvidenceDigest -Value $CampaignEvent.record_sha256 -Label "$ExpectedSymbol/$ExpectedStream transport record digest"
    if ([string]$CampaignEvent.record_sha256 -cne (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $CampaignEvent.body))) { throw "$ExpectedSymbol/$ExpectedStream transport journal record digest is invalid." }
    $payload = $CampaignEvent.body.payload
    Assert-FaultGateJsonObject -Value $payload -Label "$ExpectedSymbol/$ExpectedStream transport payload"
    Assert-FaultGateExactProperties -Value $payload -Names @("connection", "event", "metadata_file", "metadata_sha256", "schema", "session_id") -Label "$ExpectedSymbol/$ExpectedStream transport payload"
    Assert-FaultGateJsonObject -Value $payload.connection -Label "$ExpectedSymbol/$ExpectedStream transport event connection"
    Assert-FaultGateExactProperties -Value $payload.connection -Names @("connection_epoch", "local_endpoint", "remote_endpoint", "response_headers", "stream", "uri", "websocket_http_status") -Label "$ExpectedSymbol/$ExpectedStream transport event connection"
    Test-FaultGateResponseHeaders -Headers $payload.connection.response_headers -Label "$ExpectedSymbol/$ExpectedStream transport event headers"
    $metadataGeneration = Get-FaultGateJsonUnsignedInteger -Value $metadata.generation_index -Label "$ExpectedSymbol/$ExpectedStream metadata generation"
    $metadataStatus = Get-FaultGateJsonUnsignedInteger -Value $metadata.connection.websocket_http_status -Label "$ExpectedSymbol/$ExpectedStream metadata HTTP status" -Maximum ([uint16]::MaxValue)
    $eventStatus = Get-FaultGateJsonUnsignedInteger -Value $payload.connection.websocket_http_status -Label "$ExpectedSymbol/$ExpectedStream event HTTP status" -Maximum ([uint16]::MaxValue)
    $expectedPublicStream = if ($ExpectedStream -ceq "depth") { $ExpectedSymbol.ToLowerInvariant() + "@depth@100ms" } else { $ExpectedSymbol.ToLowerInvariant() + "@trade" }
    $expectedUri = "wss://data-stream.binance.vision:443/ws/" + $expectedPublicStream + "?timeUnit=MICROSECOND"
    $metadataEpoch = Get-FaultGateJsonNonEmptyString -Value $metadata.connection.connection_epoch -Label "$ExpectedSymbol/$ExpectedStream metadata epoch"
    foreach ($field in @("schema", "session_id", "symbol", "spec_revision")) { $null = Get-FaultGateJsonNonEmptyString -Value $metadata.$field -Label "$ExpectedSymbol/$ExpectedStream metadata $field" }
    foreach ($field in @("stream", "uri", "local_endpoint", "remote_endpoint")) { $null = Get-FaultGateJsonNonEmptyString -Value $metadata.connection.$field -Label "$ExpectedSymbol/$ExpectedStream metadata $field" }
    foreach ($field in @("event", "metadata_file", "metadata_sha256", "schema", "session_id")) { $null = Get-FaultGateJsonNonEmptyString -Value $payload.$field -Label "$ExpectedSymbol/$ExpectedStream event $field" }
    Assert-FaultGateEvidenceDigest -Value $payload.metadata_sha256 -Label "$ExpectedSymbol/$ExpectedStream event metadata digest"
    $null = Test-FaultGateSocketEndpoint -Value $metadata.connection.local_endpoint -Label "$ExpectedSymbol/$ExpectedStream local endpoint"
    $null = Test-FaultGateSocketEndpoint -Value $metadata.connection.remote_endpoint -Label "$ExpectedSymbol/$ExpectedStream remote endpoint" -ExpectedPort 443
    $metadataHeaders = [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateCompactJsonBytes -Value $metadata.connection.response_headers))
    $eventHeaders = [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateCompactJsonBytes -Value $payload.connection.response_headers))
    if ([string]$metadata.schema -cne "TransportMetadataV1" -or [string]$metadata.session_id -cne $ExpectedSessionId -or $metadataGeneration -ne 0 -or
        [string]$metadata.symbol -cne $ExpectedSymbol -or [string]$metadata.spec_revision -cne $ExpectedSpecRevision -or
        [string]$metadata.connection.stream -cne $ExpectedStream -or [string]$metadata.connection.uri -cne $expectedUri -or $metadataStatus -ne 101 -or
        [string]$CampaignEvent.body.schema -cne "RawCampaignJournalRecordV1" -or $eventGeneration -ne 0 -or [string]$CampaignEvent.body.channel -cne "CHILD_STDOUT" -or
        [string]$payload.event -cne "TRANSPORT_CONNECTED" -or [string]$payload.schema -cne "TransportConnectedProcessEventV1" -or [string]$payload.session_id -cne $ExpectedSessionId -or
        [string]$payload.metadata_file -cne ("transport-" + $ExpectedStream + ".json") -or (Get-FaultGateSha256Bytes -Bytes $MetadataBytes) -cne [string]$payload.metadata_sha256 -or
        [string]$payload.connection.connection_epoch -cne $metadataEpoch -or [string]$payload.connection.stream -cne $ExpectedStream -or
        [string]$payload.connection.uri -cne $expectedUri -or $eventStatus -ne 101 -or
        [string]$payload.connection.local_endpoint -cne [string]$metadata.connection.local_endpoint -or
        [string]$payload.connection.remote_endpoint -cne [string]$metadata.connection.remote_endpoint -or $eventHeaders -cne $metadataHeaders) {
        throw "$ExpectedSymbol/$ExpectedStream transport metadata/event handshake is inconsistent."
    }
    return [pscustomobject][ordered]@{
        stream = $ExpectedStream; connection_epoch = $metadataEpoch; uri = $expectedUri
        metadata_file = "transport-" + $ExpectedStream + ".json"; metadata_bytes = [uint64]$MetadataBytes.Length
        metadata_sha256 = Get-FaultGateSha256Bytes -Bytes $MetadataBytes; metadata = $metadata; campaign_event = $CampaignEvent
    }
}

function Assert-FaultGateExactSessionInventory {
    param(
        [Parameter(Mandatory = $true)] [string] $SessionDirectory,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $root = [IO.Path]::GetFullPath($SessionDirectory).TrimEnd('\')
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $root
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label is not an ordinary session directory."
    }
    $expectedTypes = [ordered]@{
        "startup.json" = "file"
        "snapshot.bnraw" = "file"
        "snapshot-http.json" = "file"
        "transport-depth.json" = "file"
        "transport-trade.json" = "file"
        "transport-depth-events.jsonl" = "file"
        "transport-trade-events.jsonl" = "file"
        "telemetry.jsonl" = "file"
        "depth" = "directory"
        "trade" = "directory"
    }
    $items = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    if ($items.Count -ne $expectedTypes.Count) { throw "$Label root inventory cardinality is not exact." }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($item in $items) {
        $full = [IO.Path]::GetFullPath($item.FullName)
        $leaf = [IO.Path]::GetFileName($full)
        if (-not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $expectedTypes.Contains($leaf) -or -not $seen.Add($leaf)) {
            throw "$Label contains an escaping, linked, unknown, or duplicate root entry: $leaf"
        }
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $full
        $expectedType = [string]$expectedTypes[$leaf]
        if (($expectedType -ceq "directory") -ne [bool]$item.PSIsContainer) { throw "$Label entry has the wrong type: $leaf" }
        $streams = @(Get-Item -LiteralPath $full -Stream * -Force -ErrorAction Stop)
        if ($expectedType -ceq "file") {
            if ($streams.Count -ne 1 -or [string]$streams[0].Stream -cne ':$DATA') { throw "$Label file contains an alternate data stream: $leaf" }
        }
        elseif ($streams.Count -ne 0) { throw "$Label directory contains an alternate data stream: $leaf" }
    }
    foreach ($name in $expectedTypes.Keys) {
        if (-not $seen.Contains([string]$name)) { throw "$Label omits required root entry: $name" }
    }
}

function Test-FaultGateTelemetryRecord {
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)] [uint64] $ExpectedIndex,
        $PreviousRecord,
        [Parameter(Mandatory = $true)] [uint64] $DurationRequestedSeconds,
        [Parameter(Mandatory = $true)] [uint64] $FreshnessStartupGraceSeconds,
        [Parameter(Mandatory = $true)] [uint64] $FreshnessDeadlineSeconds,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    Assert-FaultGateJsonObject -Value $Record -Label $Label
    $recordNames = @(
        "schema", "record_index", "wall_ns", "mono_ns", "clock",
        "depth_received", "depth_written", "depth_durable", "depth_segment",
        "depth_last_socket_activity_mono_ns", "depth_last_market_message_mono_ns", "depth_last_durable_mono_ns",
        "depth_queue_records", "depth_queue_bytes", "depth_max_queue_records", "depth_max_queue_bytes",
        "depth_max_queue_age_ns", "depth_last_sync_duration_ns", "depth_max_sync_duration_ns",
        "trade_received", "trade_written", "trade_durable", "trade_segment",
        "trade_last_socket_activity_mono_ns", "trade_last_market_message_mono_ns", "trade_last_durable_mono_ns",
        "trade_queue_records", "trade_queue_bytes", "trade_max_queue_records", "trade_max_queue_bytes",
        "trade_max_queue_age_ns", "trade_last_sync_duration_ns", "trade_max_sync_duration_ns"
    )
    Assert-FaultGateExactProperties -Value $Record -Names $recordNames -Label $Label
    $schema = Get-FaultGateJsonNonEmptyString -Value $Record.schema -Label "$Label schema"
    $index = Get-FaultGateJsonUnsignedInteger -Value $Record.record_index -Label "$Label record_index"
    $wall = Get-FaultGateJsonUnsignedInteger -Value $Record.wall_ns -Label "$Label wall_ns"
    $mono = Get-FaultGateJsonUnsignedInteger -Value $Record.mono_ns -Label "$Label mono_ns"
    Assert-FaultGateJsonObject -Value $Record.clock -Label "$Label clock"
    Assert-FaultGateExactProperties -Value $Record.clock -Names @("quality", "source", "leap_indicator", "stratum", "last_successful_sync") -Label "$Label clock"
    $quality = Get-FaultGateJsonNonEmptyString -Value $Record.clock.quality -Label "$Label clock quality"
    $null = Get-FaultGateJsonNonEmptyString -Value $Record.clock.source -Label "$Label clock source"
    $leap = if ($null -eq $Record.clock.leap_indicator) { $null } else { Get-FaultGateJsonUnsignedInteger -Value $Record.clock.leap_indicator -Label "$Label clock leap_indicator" -Maximum ([byte]::MaxValue) }
    $stratum = if ($null -eq $Record.clock.stratum) { $null } else { Get-FaultGateJsonUnsignedInteger -Value $Record.clock.stratum -Label "$Label clock stratum" -Maximum ([byte]::MaxValue) }
    if ($null -ne $Record.clock.last_successful_sync) { $null = Get-FaultGateJsonNonEmptyString -Value $Record.clock.last_successful_sync -Label "$Label clock last_successful_sync" }
    $values = [ordered]@{}
    foreach ($field in $recordNames[5..($recordNames.Count - 1)]) {
        $values[$field] = Get-FaultGateJsonUnsignedInteger -Value $Record.$field -Label "$Label $field"
    }
    if ($schema -cne "CaptureTelemetryV1" -or $index -ne $ExpectedIndex -or $wall -eq 0 -or
        $quality -cne "HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND" -or $leap -ne 0 -or
        $null -eq $stratum -or $stratum -lt 1 -or $stratum -gt 15 -or $null -eq $Record.clock.last_successful_sync -or
        $values.depth_written -gt $values.depth_received -or $values.depth_durable -gt $values.depth_written -or
        $values.trade_written -gt $values.trade_received -or $values.trade_durable -gt $values.trade_written -or
        $values.depth_last_socket_activity_mono_ns -gt $mono -or $values.depth_last_market_message_mono_ns -gt $mono -or $values.depth_last_durable_mono_ns -gt $mono -or
        $values.trade_last_socket_activity_mono_ns -gt $mono -or $values.trade_last_market_message_mono_ns -gt $mono -or $values.trade_last_durable_mono_ns -gt $mono -or
        $values.depth_last_market_message_mono_ns -gt $values.depth_last_socket_activity_mono_ns -or
        $values.trade_last_market_message_mono_ns -gt $values.trade_last_socket_activity_mono_ns -or
        $values.depth_queue_records -gt $values.depth_max_queue_records -or $values.depth_queue_bytes -gt $values.depth_max_queue_bytes -or
        $values.depth_last_sync_duration_ns -gt $values.depth_max_sync_duration_ns -or
        $values.trade_queue_records -gt $values.trade_max_queue_records -or $values.trade_queue_bytes -gt $values.trade_max_queue_bytes -or
        $values.trade_last_sync_duration_ns -gt $values.trade_max_sync_duration_ns) {
        throw "$Label shape/counters are invalid."
    }
    [uint64]$billion = 1000000000
    [uint64]$activeEnd = Multiply-FaultGateCheckedUInt64 -Left $DurationRequestedSeconds -Right $billion -Label "$Label duration nanoseconds"
    [uint64]$grace = Multiply-FaultGateCheckedUInt64 -Left $FreshnessStartupGraceSeconds -Right $billion -Label "$Label startup grace nanoseconds"
    [uint64]$deadline = Multiply-FaultGateCheckedUInt64 -Left $FreshnessDeadlineSeconds -Right $billion -Label "$Label freshness deadline nanoseconds"
    $depthMarketAge = Subtract-FaultGateCheckedUInt64 -Left $mono -Right ([uint64]$values.depth_last_market_message_mono_ns) -Label "$Label depth market age"
    $tradeMarketAge = Subtract-FaultGateCheckedUInt64 -Left $mono -Right ([uint64]$values.trade_last_market_message_mono_ns) -Label "$Label trade market age"
    if ($mono -ge $grace -and $mono -lt $activeEnd -and
        ($values.depth_last_market_message_mono_ns -eq 0 -or $values.trade_last_market_message_mono_ns -eq 0 -or
         $depthMarketAge -gt $deadline -or $tradeMarketAge -gt $deadline)) {
        throw "$Label reports stale market data during the active freshness window."
    }
    if ($null -ne $PreviousRecord) {
        $nonRegressing = @(
            "depth_received", "depth_written", "depth_durable", "depth_segment", "depth_last_socket_activity_mono_ns",
            "depth_last_market_message_mono_ns", "depth_max_queue_records", "depth_max_queue_bytes", "depth_max_queue_age_ns", "depth_max_sync_duration_ns",
            "trade_received", "trade_written", "trade_durable", "trade_segment", "trade_last_socket_activity_mono_ns",
            "trade_last_market_message_mono_ns", "trade_max_queue_records", "trade_max_queue_bytes", "trade_max_queue_age_ns", "trade_max_sync_duration_ns"
        )
        if ($mono -le [uint64]$PreviousRecord.mono_ns) { throw "$Label monotonic time did not advance strictly." }
        foreach ($field in $nonRegressing) {
            if ([uint64]$Record.$field -lt [uint64]$PreviousRecord.$field) { throw "$Label $field regressed." }
        }
    }
    return $Record
}

function Read-FaultGateTelemetryPrefix {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [uint64] $DurationRequestedSeconds,
        [Parameter(Mandatory = $true)] [uint64] $FreshnessStartupGraceSeconds,
        [Parameter(Mandatory = $true)] [uint64] $FreshnessDeadlineSeconds,
        [switch] $AllowPartialTail
    )
    $fullPath = [IO.Path]::GetFullPath($Path)
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $fullPath
    [byte[]]$bytes = @(Read-FaultGateSnapshotBytes -Path $fullPath)
    if ($bytes.Length -eq 0) { throw "Telemetry file is empty: $fullPath" }
    $lastLf = -1
    for ($scan = $bytes.Length - 1; $scan -ge 0; $scan--) { if ($bytes[$scan] -eq 10) { $lastLf = $scan; break } }
    if ($lastLf -lt 0) { throw "Telemetry has no complete durable record: $fullPath" }
    [uint64]$verifiedOffset = [uint64]($lastLf + 1)
    [uint64]$partialTail = [uint64]$bytes.Length - $verifiedOffset
    if (-not $AllowPartialTail -and $partialTail -ne 0) { throw "Telemetry has a partial tail: $fullPath" }
    if ($partialTail -gt $script:FaultGateMaximumTelemetryPartialTailBytes) { throw "Telemetry partial tail exceeds the exact writer-record byte limit: $fullPath" }
    $summaries = [Collections.Generic.List[object]]::new()
    [uint64]$cursor = 0
    $previousRecord = $null
    while ($cursor -lt $verifiedOffset) {
        [uint64]$newline = $cursor
        while ($newline -lt $verifiedOffset -and $bytes[$newline] -ne 10) { $newline++ }
        if ($newline -ge $verifiedOffset -or $newline -eq $cursor -or ($newline - $cursor + 1) -gt $script:FaultGateMaximumTelemetryRecordBytes) { throw "Telemetry contains an empty, partial, or oversized record." }
        [byte[]]$lineBytes = @($bytes[[int]$cursor..([int]$newline - 1)])
        try { $lineText = [Text.UTF8Encoding]::new($false, $true).GetString($lineBytes); $record = $lineText | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "Telemetry contains invalid strict UTF-8 JSON." }
        Assert-FaultGateExactBytes -Actual $lineBytes -Expected (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $record) -Label "telemetry record $($summaries.Count)"
        $null = Test-FaultGateTelemetryRecord -Record $record -ExpectedIndex ([uint64]$summaries.Count) -PreviousRecord $previousRecord -DurationRequestedSeconds $DurationRequestedSeconds -FreshnessStartupGraceSeconds $FreshnessStartupGraceSeconds -FreshnessDeadlineSeconds $FreshnessDeadlineSeconds -Label "telemetry record $($summaries.Count)"
        [byte[]]$recordBytes = @($bytes[[int]$cursor..[int]$newline])
        $cursor = $newline + 1
        $summaries.Add([pscustomobject][ordered]@{
            record_index = [uint64]$record.record_index
            durable_through_offset = $cursor
            record_sha256 = Get-FaultGateSha256Bytes -Bytes $recordBytes
            record = $record
        })
        $previousRecord = $record
    }
    if ($summaries.Count -eq 0 -or $cursor -ne $verifiedOffset) { throw "Telemetry verified prefix boundary is invalid." }
    [byte[]]$prefixBytes = @($bytes[0..([int]$verifiedOffset - 1)])
    return [pscustomobject][ordered]@{
        file = "telemetry.jsonl"
        duration_requested_s = $DurationRequestedSeconds
        market_freshness_startup_grace_s = $FreshnessStartupGraceSeconds
        market_freshness_deadline_s = $FreshnessDeadlineSeconds
        observed_file_bytes = [uint64]$bytes.Length
        full_file_sha256 = Get-FaultGateSha256Bytes -Bytes $bytes
        verified_through_offset = $verifiedOffset
        verified_prefix_sha256 = Get-FaultGateSha256Bytes -Bytes $prefixBytes
        partial_tail_bytes = $partialTail
        verified_records = @($summaries)
    }
}

function Test-FaultGateRawGeneration {
    param(
        [Parameter(Mandatory = $true)] [string] $SessionDirectory,
        [Parameter(Mandatory = $true)] [string] $Symbol,
        [Parameter(Mandatory = $true)] [string] $ExpectedSpecRevision,
        [Parameter(Mandatory = $true)] [string] $ExpectedCaptureExecutableSha256,
        [Parameter(Mandatory = $true)] [string] $ExpectedPublicConfigSha256,
        [Parameter(Mandatory = $true)] $CampaignJournal,
        [Parameter(Mandatory = $true)] [uint64] $MinimumSealedSegments,
        [Parameter(Mandatory = $true)] [string] $ExpectedCampaignDirectory,
        [Parameter(Mandatory = $true)] [uint64] $ExpectedSegmentDuration,
        [Parameter(Mandatory = $true)] [uint64] $ExpectedMarketFreshnessStartupGrace,
        [Parameter(Mandatory = $true)] [uint64] $ExpectedMarketFreshnessDeadline,
        [switch] $AllowRecoveryTails,
        [switch] $LivePrefixObservation
    )
    $allowBoundedPartialTail = [bool]($AllowRecoveryTails -or $LivePrefixObservation)
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path ([IO.Path]::GetFullPath($ExpectedCampaignDirectory))
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path ([IO.Path]::GetFullPath($SessionDirectory))
    $startupPath = Join-Path $SessionDirectory "startup.json"
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $startupPath
    $startupSnapshot = Read-FaultGateJsonSnapshot -Path $startupPath
    $startup = $startupSnapshot.value
    $startupSha256 = [string]$startupSnapshot.sha256
    Assert-FaultGateJsonObject -Value $startup -Label "$Symbol generation startup"
    $startupNames = @(
        "schema", "implementation", "session_id", "generation_index", "symbol", "duration_requested_s", "segment_duration_s", "started_wall_ns",
        "collector_executable_sha256", "public_config_sha256", "market_freshness_startup_grace_s", "market_freshness_deadline_s",
        "credentials", "order_entry", "raw_boundary", "spec_revision"
    )
    Assert-FaultGateExactProperties -Value $startup -Names $startupNames -Label "$Symbol generation startup"
    foreach ($name in @("schema", "implementation", "symbol", "credentials", "order_entry", "raw_boundary", "spec_revision")) {
        $null = Get-FaultGateJsonNonEmptyString -Value $startup.$name -Label "$Symbol generation startup $name"
    }
    $sessionId = Get-FaultGatePortableLeafComponent -Value $startup.session_id -Label "$Symbol generation startup session_id"
    $startupGenerationIndex = Get-FaultGateJsonUnsignedInteger -Value $startup.generation_index -Label "$Symbol generation startup generation_index"
    $startupDuration = Get-FaultGateJsonUnsignedInteger -Value $startup.duration_requested_s -Label "$Symbol generation startup duration_requested_s"
    $startupSegmentDuration = Get-FaultGateJsonUnsignedInteger -Value $startup.segment_duration_s -Label "$Symbol generation startup segment_duration_s"
    $startupWall = Get-FaultGateJsonUnsignedInteger -Value $startup.started_wall_ns -Label "$Symbol generation startup started_wall_ns"
    $startupGrace = Get-FaultGateJsonUnsignedInteger -Value $startup.market_freshness_startup_grace_s -Label "$Symbol generation startup market freshness grace"
    $startupFreshness = Get-FaultGateJsonUnsignedInteger -Value $startup.market_freshness_deadline_s -Label "$Symbol generation startup market freshness deadline"
    Assert-FaultGateEvidenceDigest -Value $startup.collector_executable_sha256 -Label "$Symbol generation startup collector digest"
    Assert-FaultGateEvidenceDigest -Value $startup.public_config_sha256 -Label "$Symbol generation startup config digest"
    $generationLaunches = @(Get-FaultGateJournalEvents -Journal $CampaignJournal -Event "GENERATION_LAUNCHED" | Where-Object { $null -ne $_.body.generation_index -and [uint64]$_.body.generation_index -eq 0 })
    if ($generationLaunches.Count -ne 1) { throw "$Symbol lacks exactly one generation-0 launch duration authority." }
    $launchPayload = $generationLaunches[0].body.payload
    Assert-FaultGateExactProperties -Value $launchPayload -Names @("duration_s", "event") -Label "$Symbol generation launch payload"
    $launchedDuration = Get-FaultGateJsonUnsignedInteger -Value $launchPayload.duration_s -Label "$Symbol generation launch duration"
    if ([string]$generationLaunches[0].body.channel -cne "CAMPAIGN" -or [string]$launchPayload.event -cne "GENERATION_LAUNCHED") { throw "$Symbol generation launch scope is invalid." }
    $expectedSessionDirectory = [IO.Path]::GetFullPath((Join-Path (Join-Path ([IO.Path]::GetFullPath($ExpectedCampaignDirectory)) "generations") $sessionId))
    if ([string]$startup.schema -cne "RawGenerationStartupV1" -or [string]$startup.implementation -cne "rust-segmented" -or [string]$startup.symbol -cne $Symbol -or
        $startupGenerationIndex -ne 0 -or $startupDuration -eq 0 -or $startupDuration -ne $launchedDuration -or
        $startupSegmentDuration -ne $ExpectedSegmentDuration -or $startupWall -eq 0 -or $startupGrace -ne $ExpectedMarketFreshnessStartupGrace -or
        $startupFreshness -ne $ExpectedMarketFreshnessDeadline -or [string]$startup.spec_revision -cne $ExpectedSpecRevision -or
        [string]$startup.collector_executable_sha256 -cne $ExpectedCaptureExecutableSha256 -or
        [string]$startup.public_config_sha256 -cne $ExpectedPublicConfigSha256 -or [string]$startup.credentials -cne "NONE" -or [string]$startup.order_entry -cne "ABSENT" -or
        [string]$startup.raw_boundary -cne "WebSocket application messages after TLS/framing and before JSON interpretation" -or
        [IO.Path]::GetFullPath($SessionDirectory) -cne $expectedSessionDirectory -or
        [IO.Path]::GetFileName([IO.Path]::GetFullPath($SessionDirectory)) -cne $sessionId) {
        throw "$Symbol generation startup identity is invalid."
    }
    $started = @(Get-FaultGateJournalEvents -Journal $CampaignJournal -Event "PROCESS_STARTED" | Where-Object {
        $null -ne $_.body.generation_index -and [uint64]$_.body.generation_index -eq 0
    })
    if ($started.Count -ne 1) { throw "$Symbol lacks one exact generation-0 PROCESS_STARTED record." }
    $startedPayload = $started[0].body.payload
    Assert-FaultGateExactProperties -Value $startedPayload -Names @("event", "generation_index", "process_id", "schema", "session_dir", "session_id", "spec_revision", "startup_manifest_sha256", "symbol") -Label "$Symbol PROCESS_STARTED payload"
    $startedGeneration = Get-FaultGateJsonUnsignedInteger -Value $startedPayload.generation_index -Label "$Symbol PROCESS_STARTED generation_index"
    $startedPid = Get-FaultGateJsonUnsignedInteger -Value $startedPayload.process_id -Label "$Symbol PROCESS_STARTED process_id" -Maximum ([uint32]::MaxValue)
    $startedSession = Get-FaultGatePortableLeafComponent -Value $startedPayload.session_id -Label "$Symbol PROCESS_STARTED session_id"
    foreach ($name in @("event", "schema", "session_dir", "spec_revision", "startup_manifest_sha256", "symbol")) { $null = Get-FaultGateJsonNonEmptyString -Value $startedPayload.$name -Label "$Symbol PROCESS_STARTED $name" }
    if ([string]$started[0].body.channel -cne "CHILD_STDOUT" -or [string]$startedPayload.event -cne "PROCESS_STARTED" -or
        [string]$startedPayload.schema -cne "CaptureProcessEventV1" -or $startedGeneration -ne 0 -or $startedPid -eq 0 -or
        $startedSession -cne $sessionId -or [string]$startedPayload.symbol -cne $Symbol -or [string]$startedPayload.spec_revision -cne $ExpectedSpecRevision -or
        [IO.Path]::GetFullPath([string]$startedPayload.session_dir) -cne $expectedSessionDirectory -or
        [string]$startedPayload.startup_manifest_sha256 -cne $startupSha256) {
        throw "$Symbol PROCESS_STARTED does not bind the exact generation startup."
    }
    $transportEvents = @(Get-FaultGateJournalEvents -Journal $CampaignJournal -Event "TRANSPORT_CONNECTED" | Where-Object {
        $null -ne $_.body.generation_index -and [uint64]$_.body.generation_index -eq 0
    })
    if ($transportEvents.Count -ne 2) { throw "$Symbol lacks exactly two generation-0 TRANSPORT_CONNECTED records." }
    $transportReports = [Collections.Generic.List[object]]::new()
    $transportEpochs = @{}
    foreach ($streamName in @("depth", "trade")) {
        $matchingTransport = @($transportEvents | Where-Object {
            $null -ne $_.body.payload -and $null -ne $_.body.payload.connection -and [string]$_.body.payload.connection.stream -ceq $streamName
        })
        if ($matchingTransport.Count -ne 1) { throw "$Symbol/$streamName transport campaign event is absent or ambiguous." }
        $metadataFile = "transport-" + $streamName + ".json"
        $metadataPath = Join-Path $SessionDirectory $metadataFile
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $metadataPath
        [byte[]]$metadataBytes = @(Read-FaultGateSnapshotBytes -Path $metadataPath)
        if ($metadataBytes.Length -eq 0) { throw "$Symbol/$streamName transport metadata is empty." }
        $transportReport = Test-FaultGateTransportMetadataArtifact -MetadataBytes $metadataBytes -CampaignEvent $matchingTransport[0] -ExpectedStream $streamName -ExpectedSessionId $sessionId -ExpectedSymbol $Symbol -ExpectedSpecRevision $ExpectedSpecRevision
        $transportEpochs[$streamName] = [string]$transportReport.connection_epoch
        $transportReports.Add($transportReport)
    }
    if ([string]$transportEpochs.depth -ceq [string]$transportEpochs.trade) { throw "$Symbol depth/trade transport epochs are not independent." }
    $snapshotEvents = @(Get-FaultGateJournalEvents -Journal $CampaignJournal -Event "SNAPSHOT_DURABLE" | Where-Object {
        $null -ne $_.body.generation_index -and [uint64]$_.body.generation_index -eq 0
    })
    if ($snapshotEvents.Count -ne 1) { throw "$Symbol lacks exactly one durable generation-0 snapshot." }
    $snapshotEvent = $snapshotEvents[0].body.payload
    Assert-FaultGateExactProperties -Value $snapshotEvent -Names @("durable_through_offset", "event", "http_metadata_file", "http_metadata_sha256", "last_record_sha256", "raw_file", "schema", "session_id") -Label "$Symbol SNAPSHOT_DURABLE payload"
    $snapshotOffset = Get-FaultGateJsonUnsignedInteger -Value $snapshotEvent.durable_through_offset -Label "$Symbol snapshot durable offset"
    $snapshotSessionId = Get-FaultGatePortableLeafComponent -Value $snapshotEvent.session_id -Label "$Symbol snapshot session_id"
    foreach ($name in @("event", "http_metadata_file", "raw_file", "schema")) { $null = Get-FaultGateJsonNonEmptyString -Value $snapshotEvent.$name -Label "$Symbol snapshot $name" }
    Assert-FaultGateEvidenceDigest -Value $snapshotEvent.http_metadata_sha256 -Label "$Symbol snapshot HTTP metadata digest"
    Assert-FaultGateEvidenceDigest -Value $snapshotEvent.last_record_sha256 -Label "$Symbol snapshot record digest"
    if ([string]$snapshotEvents[0].body.channel -cne "CHILD_STDOUT" -or [string]$snapshotEvent.event -cne "SNAPSHOT_DURABLE" -or
        [string]$snapshotEvent.schema -cne "SnapshotDurableProcessEventV1" -or $snapshotSessionId -cne $sessionId -or $snapshotOffset -le 44 -or
        [string]$snapshotEvent.raw_file -cne "snapshot.bnraw" -or [string]$snapshotEvent.http_metadata_file -cne "snapshot-http.json") { throw "$Symbol snapshot event uses an invalid identity or filename." }
    $snapshotPath = Join-Path $SessionDirectory ([string]$snapshotEvent.raw_file)
    $snapshotHttpPath = Join-Path $SessionDirectory ([string]$snapshotEvent.http_metadata_file)
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $snapshotPath
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $snapshotHttpPath
    [byte[]]$snapshotHttpArtifactBytes = @(Read-FaultGateSnapshotBytes -Path $snapshotHttpPath)
    $snapshotHttpBytes = [uint64]$snapshotHttpArtifactBytes.Length
    $snapshotHttpSha256 = Get-FaultGateSha256Bytes -Bytes $snapshotHttpArtifactBytes
    if ($snapshotHttpBytes -eq 0 -or $snapshotHttpSha256 -cne [string]$snapshotEvent.http_metadata_sha256) { throw "$Symbol snapshot HTTP metadata hash differs from its durable event." }
    [byte[]]$snapshotArtifactBytes = @(Read-FaultGateSnapshotBytes -Path $snapshotPath)
    $snapshotBytes = [uint64]$snapshotArtifactBytes.Length
    $snapshotArtifactSha256 = Get-FaultGateSha256Bytes -Bytes $snapshotArtifactBytes
    if ($snapshotBytes -ne $snapshotOffset) { throw "$Symbol snapshot has bytes beyond/before its durability event." }
    $snapshotFile = [IO.MemoryStream]::new($snapshotArtifactBytes, $false)
    try {
        $magic = Read-FaultGateExactBytes -Stream $snapshotFile -Count 8
        $bodyLength = [uint32](Read-FaultGateUInt32BigEndian -Stream $snapshotFile)
        $bodyBytes = Read-FaultGateExactBytes -Stream $snapshotFile -Count ([int]$bodyLength)
        $stored = Read-FaultGateExactBytes -Stream $snapshotFile -Count 32
        $storedSha = ([BitConverter]::ToString($stored)).Replace("-", "").ToLowerInvariant()
        $snapshotBody = ([Text.UTF8Encoding]::new($false, $true).GetString($bodyBytes) | ConvertFrom-Json -ErrorAction Stop)
        if ([Text.Encoding]::ASCII.GetString($magic, 0, 5) -cne "BNRAW" -or $magic[5] -ne 0 -or $magic[6] -ne 1 -or $magic[7] -ne 10 -or
            $snapshotFile.Position -ne $snapshotFile.Length -or (Get-FaultGateSha256Bytes -Bytes $bodyBytes) -cne $storedSha -or
            $storedSha -cne [string]$snapshotEvent.last_record_sha256 -or [string]$snapshotBody.schema -cne "RawFrameV1" -or
            [string]$snapshotBody.symbol -cne $Symbol -or [string]$snapshotBody.stream -cne ($Symbol.ToLowerInvariant() + "@rest-depth-snapshot") -or
            [uint64]$snapshotBody.frame_index -ne 0 -or [string]$snapshotBody.previous_record_sha256 -cne $script:FaultGateZeroDigest -or
            [string]$snapshotBody.spec_revision -cne $ExpectedSpecRevision) { throw "$Symbol snapshot BNRAW is not the exact durable single-record artifact." }
    }
    finally { $snapshotFile.Dispose() }
    $snapshotRaw = Read-FaultGateRawPrefix -Path $snapshotPath -Limit $snapshotBytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch ([string]$snapshotBody.connection_epoch) -ExpectedStream ($Symbol.ToLowerInvariant() + "@rest-depth-snapshot") -ExpectedEndpoint ("https://data-api.binance.vision/api/v3/depth?symbol=" + $Symbol + "&limit=5000") -ExpectedSymbol $Symbol -ExpectedSpecRevision $ExpectedSpecRevision
    if ([string]$snapshotRaw.terminal_record_sha256 -cne [string]$snapshotEvent.last_record_sha256 -or
        [uint64]$snapshotRaw.observed_file_bytes -ne $snapshotBytes -or [string]$snapshotRaw.full_file_sha256 -cne $snapshotArtifactSha256) {
        throw "$Symbol snapshot durable event/bytes differ from verified BNRAW."
    }
    $snapshotEndpoint = "https://data-api.binance.vision/api/v3/depth?symbol=" + $Symbol + "&limit=5000"
    $snapshotDetails = Test-FaultGateSnapshotHttpArtifact -MetadataBytes $snapshotHttpArtifactBytes -SnapshotBody $snapshotBody -RawRecordSha256 ([string]$snapshotEvent.last_record_sha256) -ExpectedEndpoint $snapshotEndpoint
    $telemetryPath = Join-Path $SessionDirectory "telemetry.jsonl"
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $telemetryPath
    $telemetryReport = Read-FaultGateTelemetryPrefix -Path $telemetryPath -DurationRequestedSeconds $startupDuration -FreshnessStartupGraceSeconds $startupGrace -FreshnessDeadlineSeconds $startupFreshness -AllowPartialTail:$allowBoundedPartialTail

    $streamReports = [Collections.Generic.List[object]]::new()
    foreach ($streamName in @("depth", "trade")) {
        $streamRoot = Join-Path $SessionDirectory $streamName
        $manifestPath = Join-Path $streamRoot "segments.bnseg"
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $streamRoot
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $manifestPath
        $manifest = Read-FaultGateSegmentManifest -Path $manifestPath -AllowPartialTail:$allowBoundedPartialTail
        if ([uint64]$manifest.records -lt $MinimumSealedSegments) { throw "$Symbol/$streamName has fewer than $MinimumSealedSegments sealed raw segments." }
        if ([uint64]$manifest.verified_through_offset -gt [uint64]$manifest.file_bytes -or
            [uint64]$manifest.partial_tail_bytes -ne ([uint64]$manifest.file_bytes - [uint64]$manifest.verified_through_offset) -or
            ((-not $allowBoundedPartialTail -or [uint64]$manifest.partial_tail_bytes -eq 0) -and [uint64]$manifest.verified_through_offset -ne [uint64]$manifest.file_bytes)) {
            throw "$Symbol/$streamName BNSEG verified prefix/tail boundary is inconsistent."
        }
        $expectedPublicStream = if ($streamName -ceq "depth") { $Symbol.ToLowerInvariant() + "@depth@100ms" } else { $Symbol.ToLowerInvariant() + "@trade" }
        $expectedEndpoint = "wss://data-stream.binance.vision:443/ws/" + $expectedPublicStream + "?timeUnit=MICROSECOND"
        $segments = [Collections.Generic.List[object]]::new()
        $expectedStreamFiles = [Collections.Generic.List[string]]::new()
        $expectedStreamFiles.Add("segments.bnseg")
        foreach ($seal in $manifest.seals) {
            $segmentIndex = [uint64]$seal.segment_index
            $rawFile = [string]$seal.raw_file
            if ([string]$seal.stream -cne $expectedPublicStream -or [string]$seal.connection_epoch -cne [string]$transportEpochs[$streamName]) { throw "$Symbol/$streamName BNSEG carries the wrong public stream/transport identity." }
            $ackFile = "segment-{0:D6}.bnack" -f $segmentIndex
            $expectedStreamFiles.Add($rawFile)
            $expectedStreamFiles.Add($ackFile)
            $rawPath = Join-Path $streamRoot $rawFile
            $ackPath = Join-Path $streamRoot $ackFile
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $rawPath
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $ackPath
            $progress = Read-FaultGateProgress -Path $ackPath -ExpectedRawFile $rawFile -ExpectedEpoch ([string]$seal.connection_epoch) -ExpectedStream ([string]$seal.stream) -FirstFrameIndex ([uint64]$seal.first_frame_index)
            $ack = $progress.latest_ack
            if ([uint64]$ack.durable_record_count -ne [uint64]$seal.records -or
                [uint64]$ack.durable_through_offset -ne [uint64]$seal.durable_through_offset -or
                [string]$ack.last_record_sha256 -cne [string]$seal.terminal_record_sha256) { throw "$Symbol/$streamName BNACK differs from BNSEG seal $segmentIndex." }
            $raw = Read-FaultGateRawPrefix -Path $rawPath -Limit ([uint64]$seal.durable_through_offset) -ExpectedRecords ([uint64]$seal.records) -FirstFrameIndex ([uint64]$seal.first_frame_index) -InitialPreviousSha256 ([string]$seal.previous_segment_terminal_sha256) -ExpectedEpoch ([string]$seal.connection_epoch) -ExpectedStream $expectedPublicStream -ExpectedEndpoint $expectedEndpoint -ExpectedSymbol $Symbol -ExpectedSpecRevision $ExpectedSpecRevision -Acknowledgements $progress.acknowledgements
            if ([uint64]$raw.observed_file_bytes -ne [uint64]$seal.durable_through_offset -or [uint64]$raw.unverified_suffix_bytes -ne 0 -or
                [bool]$progress.partial_tail -or [string]$raw.terminal_record_sha256 -cne [string]$seal.terminal_record_sha256) {
                throw "$Symbol/$streamName sealed BNRAW differs from BNSEG seal $segmentIndex."
            }
            $segments.Add([pscustomobject][ordered]@{ segment_index = $segmentIndex; sealed = $true; raw = $raw; progress = $progress })
        }
        $nextIndex = [uint64]$manifest.records
        $nextRawFile = "segment-{0:D6}.bnraw" -f $nextIndex
        $nextAckFile = "segment-{0:D6}.bnack" -f $nextIndex
        $nextRawPath = Join-Path $streamRoot $nextRawFile
        $nextAckPath = Join-Path $streamRoot $nextAckFile
        $nextRawExists = Test-Path -LiteralPath $nextRawPath -PathType Leaf
        $nextAckExists = Test-Path -LiteralPath $nextAckPath -PathType Leaf
        if ($nextAckExists -and -not $nextRawExists) {
            # BNRAW is created before BNACK. Recheck once for that legitimate
            # creation race; an ACK still lacking its raw predecessor is orphaned.
            $nextRawExists = Test-Path -LiteralPath $nextRawPath -PathType Leaf
            if (-not $nextRawExists) { throw "$Symbol/$streamName has an orphan active BNACK without its preceding BNRAW." }
        }
        if ($nextRawExists -and $nextAckExists) {
            $expectedStreamFiles.Add($nextRawFile)
            $expectedStreamFiles.Add($nextAckFile)
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $nextRawPath
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $nextAckPath
            $lastSeal = @($manifest.seals)[@($manifest.seals).Count - 1]
            $firstFrame = Get-FaultGateUInt64Successor -Value ([uint64]$lastSeal.last_frame_index) -Label "$Symbol/$streamName active segment first frame"
            [byte[]]$ackBytes = @(Read-FaultGateSnapshotBytes -Path $nextAckPath)
            if ([Array]::IndexOf([byte[]]$ackBytes, [byte]10) -ge 0) {
                $progress = Read-FaultGateProgress -Path $nextAckPath -ExpectedRawFile $nextRawFile -ExpectedEpoch ([string]$lastSeal.connection_epoch) -ExpectedStream ([string]$lastSeal.stream) -FirstFrameIndex $firstFrame -AllowPartialTail -SnapshotBytes $ackBytes
                $ack = $progress.latest_ack
                $raw = Read-FaultGateRawPrefix -Path $nextRawPath -Limit ([uint64]$ack.durable_through_offset) -ExpectedRecords ([uint64]$ack.durable_record_count) -FirstFrameIndex $firstFrame -InitialPreviousSha256 ([string]$lastSeal.terminal_record_sha256) -ExpectedEpoch ([string]$lastSeal.connection_epoch) -ExpectedStream $expectedPublicStream -ExpectedEndpoint $expectedEndpoint -ExpectedSymbol $Symbol -ExpectedSpecRevision $ExpectedSpecRevision -Acknowledgements $progress.acknowledgements
                if ([string]$raw.terminal_record_sha256 -cne [string]$ack.last_record_sha256) { throw "$Symbol/$streamName current BNRAW differs from its terminal durable ACK." }
                $segments.Add([pscustomobject][ordered]@{ segment_index = $nextIndex; sealed = $false; durable_prefix = $true; raw = $raw; progress = $progress })
            }
            else {
                if ([uint64]$ackBytes.Length -gt $script:FaultGateMaximumProgressPartialTailBytes) {
                    throw "$Symbol/$streamName active BNACK tail exceeds the Rust durability-follower bound."
                }
                [byte[]]$nextRawBytes = @(Read-FaultGateSnapshotBytes -Path $nextRawPath)
                $segments.Add([pscustomobject][ordered]@{
                    segment_index = $nextIndex; sealed = $false; durable_prefix = $false
                    raw_file_bytes = [uint64]$nextRawBytes.Length; raw_file_sha256 = Get-FaultGateSha256Bytes -Bytes $nextRawBytes
                    progress_file_bytes = [uint64]$ackBytes.Length; progress_file_sha256 = Get-FaultGateSha256Bytes -Bytes $ackBytes
                })
            }
        }
        elseif ($nextRawExists) {
            $remainingPath = $nextRawPath
            $expectedStreamFiles.Add([IO.Path]::GetFileName($remainingPath))
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $remainingPath
            [byte[]]$remainingBytes = @(Read-FaultGateSnapshotBytes -Path $remainingPath)
            $segments.Add([pscustomobject][ordered]@{
                segment_index = $nextIndex; sealed = $false; durable_prefix = $false
                sole_partial_file = [IO.Path]::GetFileName($remainingPath); sole_partial_file_bytes = [uint64]$remainingBytes.Length
                sole_partial_file_sha256 = Get-FaultGateSha256Bytes -Bytes $remainingBytes
            })
        }
        if ($LivePrefixObservation) {
            Assert-FaultGateLiveDirectoryFileInventory -Directory $streamRoot -ExpectedNames @($expectedStreamFiles) -Label "$Symbol/$streamName live raw stream"
        }
        else {
            Assert-FaultGateExactDirectoryFileInventory -Directory $streamRoot -ExpectedNames @($expectedStreamFiles) -Label "$Symbol/$streamName raw stream"
        }
        $streamReports.Add([pscustomobject][ordered]@{
            stream = $streamName
            manifest_records = [uint64]$manifest.records
            manifest_terminal_record_sha256 = $manifest.terminal_record_sha256
            manifest_file_bytes = [uint64]$manifest.file_bytes
            manifest_file_sha256 = $manifest.file_sha256
            manifest_verified_through_offset = [uint64]$manifest.verified_through_offset
            manifest_verified_prefix_sha256 = [string]$manifest.verified_prefix_sha256
            manifest_partial_tail_bytes = [uint64]$manifest.partial_tail_bytes
            manifest_verified_records = @($manifest.verified_records)
            verified_segments = @($segments)
        })
    }
    Assert-FaultGateExactSessionInventory -SessionDirectory $SessionDirectory -Label "$Symbol generation session"
    return [pscustomobject][ordered]@{
        symbol = $Symbol
        session_id = [string]$startup.session_id
        session_directory = [IO.Path]::GetFullPath($SessionDirectory)
        spec_revision = [string]$startup.spec_revision
        startup_bytes = [uint64]$startupSnapshot.bytes
        startup_sha256 = $startupSha256
        snapshot = [pscustomobject][ordered]@{
            bytes = $snapshotBytes
            terminal_record_sha256 = [string]$snapshotEvent.last_record_sha256
            file_sha256 = $snapshotArtifactSha256
            http_metadata_file = "snapshot-http.json"
            http_metadata_bytes = $snapshotHttpBytes
            http_metadata_sha256 = $snapshotHttpSha256
            raw_frame_summary = $snapshotDetails.raw_frame_summary
            http_metadata = $snapshotDetails.http_metadata
            campaign_event = $snapshotEvents[0]
        }
        transports = @($transportReports)
        telemetry = $telemetryReport
        streams = @($streamReports)
    }
}

function Get-FaultGateSafeTreeItems {
    param([Parameter(Mandatory = $true)] [string] $Root)
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $null = Assert-FaultGateActualPathBudget -RunRoot $rootPath -Path $rootPath
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $rootPath
    $rootItem = Get-Item -LiteralPath $rootPath -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Tree root is not an ordinary directory." }
    $null = Assert-FaultGateExactDataStreamInventory -Path $rootPath -ExpectedType "directory" -Label "Artifact tree root"
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($rootPath)
    $items = [Collections.Generic.List[object]]::new()
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        $directoryItem = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
        if (($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Artifact tree directory is a reparse point: $directory" }
        $null = Assert-FaultGateExactDataStreamInventory -Path $directory -ExpectedType "directory" -Label "Artifact tree directory"
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            $full = [IO.Path]::GetFullPath($item.FullName)
            $null = Assert-FaultGateActualPathBudget -RunRoot $rootPath -Path $full
            if (-not $full.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Artifact tree child escapes its root: $full" }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Artifact tree contains a reparse point: $full" }
            $itemType = if ($item.PSIsContainer) { "directory" } else { "file" }
            $null = Assert-FaultGateExactDataStreamInventory -Path $full -ExpectedType $itemType -Label "Artifact tree entry"
            $items.Add($item)
            if ($item.PSIsContainer) { $pending.Enqueue($full) }
        }
    }
    return @($items)
}

function Get-FaultGateTreeDigest {
    param([Parameter(Mandatory = $true)] [string] $Root)
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $rootPath
    $items = @(Get-FaultGateSafeTreeItems -Root $rootPath)
    $paths = [string[]]@($items | Where-Object { -not $_.PSIsContainer } | ForEach-Object { [IO.Path]::GetFullPath($_.FullName) })
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $inventory = [Collections.Generic.List[object]]::new()
    $builder = [Text.StringBuilder]::new()
    foreach ($path in $paths) {
        $relative = $path.Substring($rootPath.Length + 1).Replace('\', '/')
        $fileSnapshot = Get-FaultGateFileDigestSnapshot -Path $path
        $size = [uint64]$fileSnapshot.bytes
        $sha = [string]$fileSnapshot.sha256
        $inventory.Add([pscustomobject][ordered]@{ relative_path = $relative; bytes = $size; sha256 = $sha })
        $null = $builder.Append($relative).Append([char]0).Append($size.ToString([Globalization.CultureInfo]::InvariantCulture)).Append([char]0).Append($sha).Append([char]10)
    }
    if ($inventory.Count -eq 0) { throw "Artifact tree is empty." }
    $material = [Text.UTF8Encoding]::new($false).GetBytes($builder.ToString())
    return [pscustomobject][ordered]@{
        root = $rootPath
        files = [uint64]$inventory.Count
        total_bytes = [uint64](($inventory | Measure-Object -Property bytes -Sum).Sum)
        tree_sha256 = Get-FaultGateSha256Bytes -Bytes $material
        inventory = @($inventory)
    }
}

function Assert-FaultGateTreeStable {
    param([Parameter(Mandatory = $true)] [string] $Root)
    $first = Get-FaultGateTreeDigest -Root $Root
    $second = Get-FaultGateTreeDigest -Root $Root
    if ($first.tree_sha256 -cne $second.tree_sha256 -or $first.files -ne $second.files -or $first.total_bytes -ne $second.total_bytes) {
        throw "Artifact tree changed across consecutive exact scans."
    }
    return $second
}

function Get-FaultGateSupportNamespaceFiles {
    param(
        [Parameter(Mandatory = $true)] [string] $EvidenceRoot,
        [Parameter(Mandatory = $true)] [string] $QualificationRoot,
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] [Collections.IDictionary] $MaximumBytesByLeaf
    )
    $root = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\')
    $qualification = [IO.Path]::GetFullPath($QualificationRoot).TrimEnd('\')
    $run = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
    if (-not [IO.Path]::GetDirectoryName($qualification).Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetDirectoryName($run).Equals($qualification, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Support artifact evidence/qualification/run topology is not an exact two-level hierarchy."
    }
    foreach ($directoryContract in @(
        [pscustomobject]@{ path = $root; label = "Support artifact root" },
        [pscustomobject]@{ path = $qualification; label = "Support qualification root" },
        [pscustomobject]@{ path = $run; label = "Support run root" }
    )) {
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path ([string]$directoryContract.path)
        $null = Assert-FaultGateExactDataStreamInventory -Path ([string]$directoryContract.path) -ExpectedType "directory" -Label ([string]$directoryContract.label)
    }
    $expectedLeaves = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($leafValue in $MaximumBytesByLeaf.Keys) {
        $leaf = Get-FaultGatePortableLeafComponent -Value $leafValue -Label "support artifact bound filename"
        if (-not $expectedLeaves.Add($leaf)) { throw "Support artifact bounds contain a duplicate filename: $leaf" }
        try { $null = [uint64]$MaximumBytesByLeaf[$leafValue] }
        catch { throw "Support artifact byte bound is not UInt64: $leaf" }
    }
    if ($expectedLeaves.Count -eq 0) { throw "Support artifact bounds are empty." }
    $rootItems = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    if ($rootItems.Count -ne ($expectedLeaves.Count + 1)) { throw "Support artifact root namespace cardinality changed." }
    $files = [Collections.Generic.List[string]]::new()
    $qualificationSeen = $false
    foreach ($item in $rootItems) {
        $full = [IO.Path]::GetFullPath($item.FullName)
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Support artifact root contains a linked or escaping entry: $full"
        }
        if ($item.PSIsContainer) {
            if ($qualificationSeen -or -not $full.Equals($qualification, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Unexpected support-artifact subdirectory: $full"
            }
            $qualificationSeen = $true
            $null = Assert-FaultGateExactDataStreamInventory -Path $full -ExpectedType "directory" -Label "Support qualification root"
            continue
        }
        $leaf = [IO.Path]::GetFileName($full)
        if (-not $expectedLeaves.Contains($leaf) -or $leaf -ceq "fault-evidence.json") {
            throw "Unexpected or self-referential support artifact: $full"
        }
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $full
        $null = Assert-FaultGateExactDataStreamInventory -Path $full -ExpectedType "file" -Label "Support artifact file"
        $files.Add($full)
    }
    if (-not $qualificationSeen -or $files.Count -ne $expectedLeaves.Count) { throw "Support artifact root omits its exact qualification directory or file set." }
    $qualificationItems = @(Get-ChildItem -LiteralPath $qualification -Force -ErrorAction Stop)
    if ($qualificationItems.Count -ne 1 -or -not $qualificationItems[0].PSIsContainer -or
        -not [IO.Path]::GetFullPath($qualificationItems[0].FullName).Equals($run, [StringComparison]::OrdinalIgnoreCase) -or
        ($qualificationItems[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Support qualification root does not contain exactly the bound ordinary RunRoot."
    }
    $null = Assert-FaultGateExactDataStreamInventory -Path $run -ExpectedType "directory" -Label "Support run root"
    $orderedFiles = [string[]]@($files)
    [Array]::Sort($orderedFiles, [StringComparer]::Ordinal)
    return $orderedFiles
}

function Open-FaultGateSupportArtifactTree {
    param(
        [Parameter(Mandatory = $true)] [string] $EvidenceRoot,
        [Parameter(Mandatory = $true)] [string] $QualificationRoot,
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] [Collections.IDictionary] $MaximumBytesByLeaf
    )
    $root = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\')
    $qualification = [IO.Path]::GetFullPath($QualificationRoot).TrimEnd('\')
    $run = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
    $orderedFiles = Get-FaultGateSupportNamespaceFiles -EvidenceRoot $root -QualificationRoot $qualification -RunRoot $run -MaximumBytesByLeaf $MaximumBytesByLeaf
    $bindings = [Collections.Generic.List[object]]::new()
    $inventory = [Collections.Generic.List[object]]::new()
    $builder = [Text.StringBuilder]::new()
    try {
        foreach ($file in $orderedFiles) {
            $leaf = [IO.Path]::GetFileName($file)
            $binding = Open-FaultGateRetainedPathBinding -Path $file -Role ("support:" + $leaf) -MaximumBytes ([uint64]$MaximumBytesByLeaf[$leaf])
            $bindings.Add($binding)
            $row = [pscustomobject][ordered]@{ relative_path = $leaf; bytes = [uint64]$binding.length; sha256 = [string]$binding.sha256 }
            $inventory.Add($row)
            $null = $builder.Append($leaf).Append([char]0).Append(([uint64]$binding.length).ToString([Globalization.CultureInfo]::InvariantCulture)).Append([char]0).Append([string]$binding.sha256).Append([char]10)
        }
        if ($inventory.Count -ne $MaximumBytesByLeaf.Count) { throw "Support artifact inventory is unexpectedly incomplete." }
        $tree = [pscustomobject][ordered]@{
            root = $root; files = [uint64]$inventory.Count
            total_bytes = [uint64](($inventory | Measure-Object -Property bytes -Sum).Sum)
            tree_sha256 = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($builder.ToString()))
            inventory = @($inventory)
        }
        return [pscustomobject][ordered]@{ tree = $tree; bindings = @($bindings) }
    }
    catch {
        foreach ($binding in $bindings) { Close-FaultGateRetainedPathBinding -Binding $binding }
        throw
    }
}

function Test-FaultGateSupportArtifactBindings {
    param(
        [Parameter(Mandatory = $true)] $Bindings,
        [Parameter(Mandatory = $true)] $ExpectedTree,
        [Parameter(Mandatory = $true)] [string] $EvidenceRoot,
        [Parameter(Mandatory = $true)] [string] $QualificationRoot,
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] [Collections.IDictionary] $MaximumBytesByLeaf
    )
    $namespaceBefore = Get-FaultGateSupportNamespaceFiles -EvidenceRoot $EvidenceRoot -QualificationRoot $QualificationRoot -RunRoot $RunRoot -MaximumBytesByLeaf $MaximumBytesByLeaf
    $rows = @($Bindings | ForEach-Object {
        $binding = Test-FaultGateRetainedPathBinding -Binding $_
        $null = Assert-FaultGateExactDataStreamInventory -Path ([string]$binding.path) -ExpectedType "file" -Label "Retained support artifact"
        if ([uint64]$binding.length -gt [uint64]$MaximumBytesByLeaf[[IO.Path]::GetFileName([string]$binding.path)]) {
            throw "Retained support artifact exceeds its pre-hash byte bound."
        }
        [pscustomobject][ordered]@{ relative_path = [IO.Path]::GetFileName([string]$binding.path); bytes = [uint64]$binding.length; sha256 = [string]$binding.sha256 }
    })
    $namespaceAfter = Get-FaultGateSupportNamespaceFiles -EvidenceRoot $EvidenceRoot -QualificationRoot $QualificationRoot -RunRoot $RunRoot -MaximumBytesByLeaf $MaximumBytesByLeaf
    if ([string]::Join([char]0, $namespaceBefore) -cne [string]::Join([char]0, $namespaceAfter)) {
        throw "Support artifact namespace changed across retained-binding verification."
    }
    if ((Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $rows)) -cne
        (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($ExpectedTree.inventory)))) {
        throw "Retained support artifact inventory changed before publication."
    }
    return $rows
}

function Test-FaultGatePreservedDurablePrefixes {
    param([Parameter(Mandatory = $true)] $Before, [Parameter(Mandatory = $true)] $After)
    $preserved = [Collections.Generic.List[object]]::new()
    foreach ($beforeGeneration in @($Before)) {
        $afterGeneration = @($After | Where-Object { [string]$_.symbol -ceq [string]$beforeGeneration.symbol })
        if ($afterGeneration.Count -ne 1 -or [string]$afterGeneration[0].session_id -cne [string]$beforeGeneration.session_id -or
            [string]$afterGeneration[0].spec_revision -cne [string]$beforeGeneration.spec_revision -or
            [string]$afterGeneration[0].startup_sha256 -cne [string]$beforeGeneration.startup_sha256 -or
            [string]$afterGeneration[0].snapshot.file_sha256 -cne [string]$beforeGeneration.snapshot.file_sha256) {
            throw "$($beforeGeneration.symbol) startup/snapshot changed across injected failure."
        }
        for ($transportIndex = 0; $transportIndex -lt 2; $transportIndex++) {
            $beforeTransport = @($beforeGeneration.transports)[$transportIndex]
            $afterTransport = @($afterGeneration[0].transports)[$transportIndex]
            if ([string]$beforeTransport.stream -cne [string]$afterTransport.stream -or
                [string]$beforeTransport.connection_epoch -cne [string]$afterTransport.connection_epoch -or
                [string]$beforeTransport.metadata_sha256 -cne [string]$afterTransport.metadata_sha256 -or
                [string]$beforeTransport.campaign_event.record_sha256 -cne [string]$afterTransport.campaign_event.record_sha256) {
                throw "$($beforeGeneration.symbol) transport identity changed across injected failure."
            }
        }
        $beforeTelemetry = $beforeGeneration.telemetry
        $afterTelemetry = $afterGeneration[0].telemetry
        $telemetryPath = Join-Path ([string]$afterGeneration[0].session_directory) "telemetry.jsonl"
        if ([string]$beforeTelemetry.file -cne "telemetry.jsonl" -or [string]$afterTelemetry.file -cne "telemetry.jsonl" -or
            [uint64]$beforeTelemetry.verified_through_offset -gt [uint64]$afterTelemetry.verified_through_offset -or
            @($beforeTelemetry.verified_records).Count -gt @($afterTelemetry.verified_records).Count -or
            (Get-FaultGatePathPrefixDigestSnapshot -Path $telemetryPath -Length ([uint64]$beforeTelemetry.verified_through_offset)) -cne [string]$beforeTelemetry.verified_prefix_sha256) {
            throw "$($beforeGeneration.symbol) exact pre-fault telemetry prefix was not preserved."
        }
        for ($telemetryIndex = 0; $telemetryIndex -lt @($beforeTelemetry.verified_records).Count; $telemetryIndex++) {
            if ((Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($beforeTelemetry.verified_records)[$telemetryIndex])) -cne
                (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($afterTelemetry.verified_records)[$telemetryIndex]))) {
                throw "$($beforeGeneration.symbol) telemetry record $telemetryIndex changed after failure."
            }
        }
        foreach ($beforeStream in @($beforeGeneration.streams)) {
            $afterStream = @($afterGeneration[0].streams | Where-Object { [string]$_.stream -ceq [string]$beforeStream.stream })
            if ($afterStream.Count -ne 1) { throw "$($beforeGeneration.symbol)/$($beforeStream.stream) post-fault stream is absent/ambiguous." }
            $manifestPath = Join-Path (Join-Path ([string]$afterGeneration[0].session_directory) ([string]$beforeStream.stream)) "segments.bnseg"
            if ([uint64]$beforeStream.manifest_records -gt [uint64]$afterStream[0].manifest_records -or
                [uint64]$beforeStream.manifest_verified_through_offset -gt [uint64]$afterStream[0].manifest_verified_through_offset -or
                (Get-FaultGatePathPrefixDigestSnapshot -Path $manifestPath -Length ([uint64]$beforeStream.manifest_verified_through_offset)) -cne [string]$beforeStream.manifest_verified_prefix_sha256) {
                throw "$($beforeGeneration.symbol)/$($beforeStream.stream) exact pre-fault BNSEG verified prefix was not preserved."
            }
            for ($manifestIndex = 0; $manifestIndex -lt @($beforeStream.manifest_verified_records).Count; $manifestIndex++) {
                if ($manifestIndex -ge @($afterStream[0].manifest_verified_records).Count -or
                    (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($beforeStream.manifest_verified_records)[$manifestIndex])) -cne
                    (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($afterStream[0].manifest_verified_records)[$manifestIndex]))) {
                    throw "$($beforeGeneration.symbol)/$($beforeStream.stream) BNSEG verified record $manifestIndex changed after failure."
                }
            }
            foreach ($beforeSegment in @($beforeStream.verified_segments | Where-Object {
                [bool]$_.sealed -or ((-not [bool]$_.sealed) -and [bool]$_.durable_prefix)
            })) {
                $afterSegment = @($afterStream[0].verified_segments | Where-Object { [uint64]$_.segment_index -eq [uint64]$beforeSegment.segment_index })
                if ($afterSegment.Count -ne 1 -or
                    (-not ([bool]$afterSegment[0].sealed -or ((-not [bool]$afterSegment[0].sealed) -and [bool]$afterSegment[0].durable_prefix))) -or
                    [string]$afterSegment[0].raw.raw_file -cne [string]$beforeSegment.raw.raw_file -or
                    [string]$afterSegment[0].progress.raw_file -cne [string]$beforeSegment.progress.raw_file -or
                    [string]$afterSegment[0].raw.connection_epoch -cne [string]$beforeSegment.raw.connection_epoch -or
                    [string]$afterSegment[0].raw.stream -cne [string]$beforeSegment.raw.stream -or
                    [uint64]$afterSegment[0].raw.first_frame_index -ne [uint64]$beforeSegment.raw.first_frame_index -or
                    [uint64]$afterSegment[0].raw.durable_through_offset -lt [uint64]$beforeSegment.raw.durable_through_offset -or
                    [uint64]$afterSegment[0].raw.durable_records -lt [uint64]$beforeSegment.raw.durable_records -or
                    [uint64]$afterSegment[0].progress.verified_through_offset -lt [uint64]$beforeSegment.progress.verified_through_offset) {
                    throw "$($beforeGeneration.symbol)/$($beforeStream.stream) durable segment prefix $($beforeSegment.segment_index) changed or disappeared after failure."
                }
                $segmentRoot = Join-Path ([string]$afterGeneration[0].session_directory) ([string]$beforeStream.stream)
                $rawPath = Join-Path $segmentRoot ([string]$beforeSegment.raw.raw_file)
                $progressPath = Join-Path $segmentRoot ("segment-{0:D6}.bnack" -f [uint64]$beforeSegment.segment_index)
                $postRawPrefixSha256 = Assert-FaultGatePreservedFilePrefix -Path $rawPath -Length ([uint64]$beforeSegment.raw.durable_through_offset) -ExpectedSha256 ([string]$beforeSegment.raw.verified_prefix_sha256) -Label "$($beforeGeneration.symbol)/$($beforeStream.stream) BNRAW segment $($beforeSegment.segment_index)"
                $postProgressPrefixSha256 = Assert-FaultGatePreservedFilePrefix -Path $progressPath -Length ([uint64]$beforeSegment.progress.verified_through_offset) -ExpectedSha256 ([string]$beforeSegment.progress.verified_prefix_sha256) -Label "$($beforeGeneration.symbol)/$($beforeStream.stream) BNACK segment $($beforeSegment.segment_index)"
                $preserved.Add([pscustomobject][ordered]@{
                    symbol = [string]$beforeGeneration.symbol; stream = [string]$beforeStream.stream; segment_index = [uint64]$beforeSegment.segment_index
                    sealed_at_observation = [bool]$beforeSegment.sealed
                    raw_file = [string]$beforeSegment.raw.raw_file; raw_prefix_bytes = [uint64]$beforeSegment.raw.durable_through_offset
                    raw_prefix_sha256 = [string]$beforeSegment.raw.verified_prefix_sha256; post_rescan_raw_prefix_sha256 = [string]$postRawPrefixSha256
                    durable_records = [uint64]$beforeSegment.raw.durable_records
                    terminal_record_sha256 = [string]$beforeSegment.raw.terminal_record_sha256
                    progress_file = ("segment-{0:D6}.bnack" -f [uint64]$beforeSegment.segment_index)
                    progress_prefix_bytes = [uint64]$beforeSegment.progress.verified_through_offset
                    progress_prefix_sha256 = [string]$beforeSegment.progress.verified_prefix_sha256; post_rescan_progress_prefix_sha256 = [string]$postProgressPrefixSha256
                    progress_terminal_record_sha256 = [string]$beforeSegment.progress.terminal_record_sha256
                })
            }
        }
    }
    if ($preserved.Count -eq 0) { throw "No pre-request durable raw prefix was available for preservation proof." }
    return [pscustomobject][ordered]@{
        durable_segments = [uint64]$preserved.Count
        inventory_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($preserved))
        inventory = @($preserved)
    }
}

function Test-FaultGateFailureContainment {
    param(
        [Parameter(Mandatory = $true)] $Terminal,
        [Parameter(Mandatory = $true)] [string] $ExpectedSchema,
        [Parameter(Mandatory = $true)] [string] $ExpectedJobName
    )
    if ($null -eq $Terminal.PSObject.Properties['failure_containment'] -or $null -eq $Terminal.PSObject.Properties['failure_containment_sha256']) {
        throw "Terminal FAILED lacks direct failure_containment and its digest."
    }
    $value = $Terminal.failure_containment
    Assert-FaultGateExactProperties -Value $value -Names @(
        "schema", "job_name", "job_kill_on_close", "detected_wall_ns", "detected_monotonic_tick", "requested_exit_code",
        "initial_query_succeeded", "initial_active_processes", "initial_query_error", "terminate_attempted", "terminate_succeeded",
        "terminate_error", "termination_monotonic_tick", "monotonic_frequency", "drain_deadline_s", "drain_elapsed_qpc_ticks", "final_query_succeeded",
        "final_active_processes", "final_query_error", "result"
    ) -Label "failure_containment"
    $containmentSchema = Get-FaultGateJsonNonEmptyString -Value $value.schema -Label "containment schema"
    $containmentJobName = Get-FaultGateJsonNonEmptyString -Value $value.job_name -Label "containment job_name"
    $jobKillOnClose = Get-FaultGateJsonBoolean -Value $value.job_kill_on_close -Label "containment job_kill_on_close"
    $detectedWall = Get-FaultGateJsonUnsignedInteger -Value $value.detected_wall_ns -Label "containment detected_wall_ns"
    $detectedTick = Get-FaultGateJsonUnsignedInteger -Value $value.detected_monotonic_tick -Label "containment detected_monotonic_tick"
    $requestedExit = Get-FaultGateJsonUnsignedInteger -Value $value.requested_exit_code -Label "containment requested_exit_code" -Maximum ([uint32]::MaxValue)
    $initialQuerySucceeded = Get-FaultGateJsonBoolean -Value $value.initial_query_succeeded -Label "containment initial_query_succeeded"
    $initialActive = if ($initialQuerySucceeded) { Get-FaultGateJsonUnsignedInteger -Value $value.initial_active_processes -Label "containment initial_active_processes" -Maximum ([uint32]::MaxValue) } else { $null }
    if ($null -ne $value.initial_query_error) { $null = Get-FaultGateJsonUnsignedInteger -Value $value.initial_query_error -Label "containment initial_query_error" -Maximum ([uint32]::MaxValue) }
    $terminateAttempted = Get-FaultGateJsonBoolean -Value $value.terminate_attempted -Label "containment terminate_attempted"
    $terminateSucceeded = if ($terminateAttempted) { Get-FaultGateJsonBoolean -Value $value.terminate_succeeded -Label "containment terminate_succeeded" } else { $null }
    if ($null -ne $value.terminate_error) { $null = Get-FaultGateJsonUnsignedInteger -Value $value.terminate_error -Label "containment terminate_error" -Maximum ([uint32]::MaxValue) }
    $terminationTick = Get-FaultGateJsonUnsignedInteger -Value $value.termination_monotonic_tick -Label "containment termination_monotonic_tick"
    $monotonicFrequency = Get-FaultGateJsonUnsignedInteger -Value $value.monotonic_frequency -Label "containment monotonic_frequency"
    $drainDeadline = Get-FaultGateJsonUnsignedInteger -Value $value.drain_deadline_s -Label "containment drain_deadline_s"
    $drainElapsed = Get-FaultGateJsonUnsignedInteger -Value $value.drain_elapsed_qpc_ticks -Label "containment drain_elapsed_qpc_ticks"
    $finalQuerySucceeded = Get-FaultGateJsonBoolean -Value $value.final_query_succeeded -Label "containment final_query_succeeded"
    $finalActive = if ($finalQuerySucceeded) { Get-FaultGateJsonUnsignedInteger -Value $value.final_active_processes -Label "containment final_active_processes" -Maximum ([uint32]::MaxValue) } else { $null }
    if ($null -ne $value.final_query_error) { $null = Get-FaultGateJsonUnsignedInteger -Value $value.final_query_error -Label "containment final_query_error" -Maximum ([uint32]::MaxValue) }
    $containmentResult = Get-FaultGateJsonNonEmptyString -Value $value.result -Label "containment result"
    if ($containmentSchema -cne $ExpectedSchema -or $containmentJobName -cne $ExpectedJobName -or
        $requestedExit -ne $script:FaultGateContainmentExitCode -or
        $detectedWall -eq 0 -or $detectedTick -eq 0 -or $terminationTick -lt $detectedTick -or
        $monotonicFrequency -ne [uint64][Diagnostics.Stopwatch]::Frequency -or $drainDeadline -ne 30 -or
        $containmentResult -cnotin @("NO_JOB_HANDLE", "UNCONFIRMED_QUERY_ERROR", "UNCONFIRMED_TIMEOUT", "DRAINED_BY_ATTEMPT", "DRAINED_CONCURRENT_OR_PREEXISTING")) {
        throw "Terminal failure_containment does not prove bounded Job termination and drain."
    }
    if (($initialQuerySucceeded -and ($null -ne $value.initial_query_error -or $null -eq $value.initial_active_processes)) -or
        (-not $initialQuerySucceeded -and ($null -ne $value.initial_active_processes -or $null -eq $value.initial_query_error -or [uint64]$value.initial_query_error -eq 0))) {
        throw "Containment initial query result/error is inconsistent."
    }
    if (($finalQuerySucceeded -and $null -ne $value.final_query_error) -or
        (-not $finalQuerySucceeded -and ($null -ne $value.final_active_processes -or $null -eq $value.final_query_error -or [uint64]$value.final_query_error -eq 0))) {
        throw "Containment final query result/error is inconsistent."
    }
    if ((-not $terminateAttempted -and ($null -ne $value.terminate_succeeded -or $null -ne $value.terminate_error)) -or
        ($terminateAttempted -and $terminateSucceeded -and $null -ne $value.terminate_error) -or
        ($terminateAttempted -and -not $terminateSucceeded -and ($null -eq $value.terminate_error -or [uint64]$value.terminate_error -eq 0))) {
        throw "Containment TerminateJobObject result/error is inconsistent."
    }
    $drainWithinDeadline = [decimal]$drainElapsed -le ([decimal]$drainDeadline * [decimal]$monotonicFrequency)
    $expectedContainmentResult = if (-not $jobKillOnClose) {
        "NO_JOB_HANDLE"
    }
    elseif (-not $finalQuerySucceeded) {
        "UNCONFIRMED_QUERY_ERROR"
    }
    elseif (-not $drainWithinDeadline -or $finalActive -ne 0) {
        "UNCONFIRMED_TIMEOUT"
    }
    elseif ($initialQuerySucceeded -and $initialActive -eq 0) {
        "DRAINED_CONCURRENT_OR_PREEXISTING"
    }
    elseif ($terminateAttempted -and $terminateSucceeded) {
        "DRAINED_BY_ATTEMPT"
    }
    else {
        "DRAINED_CONCURRENT_OR_PREEXISTING"
    }
    if ($containmentResult -cne $expectedContainmentResult) { throw "Containment result contradicts the exact initial-query/TerminateJobObject/final-drain evidence." }
    $sha = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $value)
    if ([string]$Terminal.failure_containment_sha256 -cne $sha) { throw "Terminal failure_containment digest mismatch." }
    return [pscustomobject][ordered]@{
        schema = [string]$value.schema
        job_name = [string]$value.job_name
        job_kill_on_close = [bool]$value.job_kill_on_close
        detected_wall_ns = [uint64]$value.detected_wall_ns
        detected_monotonic_tick = [uint64]$value.detected_monotonic_tick
        requested_exit_code = [uint32]$value.requested_exit_code
        initial_query_succeeded = [bool]$value.initial_query_succeeded
        initial_active_processes = if ($initialQuerySucceeded) { [uint32]$initialActive } else { $null }
        initial_query_error = $value.initial_query_error
        terminate_attempted = [bool]$value.terminate_attempted
        terminate_succeeded = if ($terminateAttempted) { [bool]$terminateSucceeded } else { $null }
        terminate_error = $value.terminate_error
        termination_monotonic_tick = [uint64]$value.termination_monotonic_tick
        monotonic_frequency = [uint64]$value.monotonic_frequency
        drain_deadline_s = [uint64]$value.drain_deadline_s
        drain_elapsed_qpc_ticks = [uint64]$value.drain_elapsed_qpc_ticks
        final_query_succeeded = [bool]$value.final_query_succeeded
        final_active_processes = if ($finalQuerySucceeded) { [uint32]$finalActive } else { $null }
        final_query_error = $value.final_query_error
        result = [string]$value.result
        sha256 = $sha
    }
}

function Write-FaultGateEvidence {
    param([Parameter(Mandatory = $true)] [string] $Path, [Parameter(Mandatory = $true)] $Body)
    $bodyBytes = ConvertTo-FaultGateCompactJsonBytes -Value $Body
    $envelope = [ordered]@{ body = $Body; record_sha256 = Get-FaultGateSha256Bytes -Bytes $bodyBytes }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((($envelope | ConvertTo-Json -Depth 100) + "`n"))
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    return $envelope.record_sha256
}

function Test-FaultGateFailureReceiptEnvelope {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $snapshot = Read-FaultGateJsonSnapshot -Path $Path -RequireCanonicalPrettyJson
    $envelope = $snapshot.value
    Assert-FaultGateExactProperties -Value $envelope -Names @("body", "record_sha256") -Label "fault failure receipt envelope"
    Assert-FaultGateJsonObject -Value $envelope.body -Label "fault failure receipt body"
    Assert-FaultGateEvidenceDigest -Value $envelope.record_sha256 -Label "fault failure receipt record_sha256"
    $computed = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $envelope.body)
    if ([string]$envelope.record_sha256 -cne $computed) {
        throw "Fault failure receipt body digest is invalid."
    }
    $body = $envelope.body
    Assert-FaultGateExactProperties -Value $body -Names @(
        "schema", "status", "gate_id", "evidence_root", "repository_root", "run_root",
        "stage", "failure", "cleanup", "fault_journal", "pass_evidence_published"
    ) -Label "fault failure receipt body"
    Assert-FaultGateJsonObject -Value $body.failure -Label "fault failure receipt failure"
    Assert-FaultGateExactProperties -Value $body.failure -Names @(
        "exception_type", "fully_qualified_error_id", "message"
    ) -Label "fault failure receipt failure"
    Assert-FaultGateJsonObject -Value $body.cleanup -Label "fault failure receipt cleanup"
    Assert-FaultGateExactProperties -Value $body.cleanup -Names @(
        "resource_cleanup_succeeded", "resource_cleanup_error",
        "outer_job_created", "outer_job_cleanup_succeeded", "outer_job_cleanup_error",
        "outer_active_processes_after_cleanup"
    ) -Label "fault failure receipt cleanup"
    Assert-FaultGateJsonObject -Value $body.fault_journal -Label "fault failure receipt journal"
    Assert-FaultGateExactProperties -Value $body.fault_journal -Names @(
        "file", "records", "clean_tail", "terminal_record_sha256", "file_bytes", "file_sha256",
        "failure_event_appended", "failure_event_append_error"
    ) -Label "fault failure receipt journal"
    $resourceCleanupSucceeded = Get-FaultGateJsonBoolean -Value $body.cleanup.resource_cleanup_succeeded -Label "fault failure receipt resource cleanup succeeded"
    $outerCreated = Get-FaultGateJsonBoolean -Value $body.cleanup.outer_job_created -Label "fault failure receipt outer created"
    $outerCleanupSucceeded = Get-FaultGateJsonBoolean -Value $body.cleanup.outer_job_cleanup_succeeded -Label "fault failure receipt cleanup succeeded"
    $journalClean = Get-FaultGateJsonBoolean -Value $body.fault_journal.clean_tail -Label "fault failure receipt journal clean"
    $failureEventAppended = Get-FaultGateJsonBoolean -Value $body.fault_journal.failure_event_appended -Label "fault failure receipt event appended"
    $passPublished = Get-FaultGateJsonBoolean -Value $body.pass_evidence_published -Label "fault failure receipt pass publication"
    $records = Get-FaultGateJsonUnsignedInteger -Value $body.fault_journal.records -Label "fault failure receipt journal records"
    $fileBytes = Get-FaultGateJsonUnsignedInteger -Value $body.fault_journal.file_bytes -Label "fault failure receipt journal bytes"
    foreach ($requiredString in @(
        $body.schema, $body.status, $body.gate_id, $body.evidence_root, $body.repository_root,
        $body.stage, $body.failure.exception_type, $body.failure.fully_qualified_error_id,
        $body.failure.message, $body.fault_journal.file)) {
        $null = Get-FaultGateJsonNonEmptyString -Value $requiredString -Label "fault failure receipt required string"
    }
    if ([string]$body.schema -cne "RawQualificationFaultGateFailureReceiptV1" -or
        [string]$body.status -cne "FAILED_NO_PASS_EVIDENCE" -or $passPublished -or
        -not $journalClean -or $records -eq 0 -or $fileBytes -eq 0 -or
        -not (Test-FaultGateDigest $body.fault_journal.terminal_record_sha256) -or
        -not (Test-FaultGateDigest $body.fault_journal.file_sha256) -or
        ($failureEventAppended -and $null -ne $body.fault_journal.failure_event_append_error) -or
        (-not $failureEventAppended -and
            ($body.fault_journal.failure_event_append_error -isnot [string] -or
                [string]::IsNullOrWhiteSpace([string]$body.fault_journal.failure_event_append_error))) -or
        ($resourceCleanupSucceeded -and $null -ne $body.cleanup.resource_cleanup_error) -or
        (-not $resourceCleanupSucceeded -and
            ($body.cleanup.resource_cleanup_error -isnot [string] -or
                [string]::IsNullOrWhiteSpace([string]$body.cleanup.resource_cleanup_error))) -or
        ($outerCleanupSucceeded -and $null -ne $body.cleanup.outer_job_cleanup_error) -or
        (-not $outerCleanupSucceeded -and
            ($body.cleanup.outer_job_cleanup_error -isnot [string] -or
                [string]::IsNullOrWhiteSpace([string]$body.cleanup.outer_job_cleanup_error))) -or
        (-not $outerCreated -and $null -ne $body.cleanup.outer_active_processes_after_cleanup)) {
        throw "Fault failure receipt overclaims PASS, cleanup, journal terminality, or failure-event publication."
    }
    if ($null -ne $body.run_root) {
        $null = Get-FaultGateJsonNonEmptyString -Value $body.run_root -Label "fault failure receipt run_root"
    }
    if ($null -ne $body.cleanup.outer_active_processes_after_cleanup) {
        $null = Get-FaultGateJsonUnsignedInteger -Value $body.cleanup.outer_active_processes_after_cleanup -Label "fault failure receipt active processes" -Maximum ([uint32]::MaxValue)
    }
    $evidenceRoot = [IO.Path]::GetFullPath([string]$body.evidence_root).TrimEnd('\')
    $repositoryRoot = [IO.Path]::GetFullPath([string]$body.repository_root).TrimEnd('\')
    $expectedReceiptPath = [IO.Path]::GetFullPath((Join-Path $evidenceRoot "fault-gate-failure.json"))
    $canonicalPassPath = [IO.Path]::GetFullPath((Join-Path $evidenceRoot "fault-evidence.json"))
    $journalPath = [IO.Path]::GetFullPath((Join-Path $evidenceRoot ([string]$body.fault_journal.file)))
    if (-not [IO.Path]::GetFullPath($Path).Equals($expectedReceiptPath, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($evidenceRoot) -cne [string]$body.gate_id -or
        -not $evidenceRoot.StartsWith($repositoryRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($journalPath) -cne "fault-events.jsonl") {
        throw "Fault failure receipt path topology is invalid."
    }
    if ([IO.File]::Exists($canonicalPassPath)) {
        throw "Fault failure receipt cannot claim FAILED_NO_PASS_EVIDENCE while canonical PASS evidence exists."
    }
    $journal = Read-FaultGateJournal -Path $journalPath -ExpectedSchema $script:FaultGateJournalSchema -RequireCleanTail -RequireCanonicalCompactJson
    if ([uint64]$journal.records -ne $records -or [uint64]$journal.file_bytes -ne $fileBytes -or
        [string]$journal.terminal_record_sha256 -cne [string]$body.fault_journal.terminal_record_sha256 -or
        [string]$journal.file_sha256 -cne [string]$body.fault_journal.file_sha256) {
        throw "Fault failure receipt journal binding is invalid."
    }
    $failureEvents = @(Get-FaultGateJournalEvents -Journal $journal -Event "HARNESS_FAILED")
    if ($failureEventAppended) {
        if ($failureEvents.Count -ne 1) {
            throw "Fault failure receipt does not bind exactly one HARNESS_FAILED event."
        }
        $failureEntry = $failureEvents[0]
        $failurePayload = $failureEntry.body.payload
        Assert-FaultGateExactProperties -Value $failurePayload -Names @(
            "event", "stage", "exception_type", "fully_qualified_error_id", "message",
            "run_root", "pass_evidence_published", "resource_cleanup_succeeded",
            "outer_job_created", "outer_job_cleanup_succeeded", "outer_active_processes_after_cleanup"
        ) -Label "fault HARNESS_FAILED payload"
        $failureIndex = Get-FaultGateJsonUnsignedInteger -Value $failureEntry.body.record_index -Label "fault HARNESS_FAILED record index"
        $eventPassPublished = Get-FaultGateJsonBoolean -Value $failurePayload.pass_evidence_published -Label "fault HARNESS_FAILED pass publication"
        $eventResourceCleanup = Get-FaultGateJsonBoolean -Value $failurePayload.resource_cleanup_succeeded -Label "fault HARNESS_FAILED resource cleanup"
        $eventOuterCreated = Get-FaultGateJsonBoolean -Value $failurePayload.outer_job_created -Label "fault HARNESS_FAILED outer created"
        $eventOuterCleanup = Get-FaultGateJsonBoolean -Value $failurePayload.outer_job_cleanup_succeeded -Label "fault HARNESS_FAILED outer cleanup"
        $eventOuterActive = if ($null -eq $failurePayload.outer_active_processes_after_cleanup) {
            $null
        }
        else {
            Get-FaultGateJsonUnsignedInteger -Value $failurePayload.outer_active_processes_after_cleanup -Label "fault HARNESS_FAILED outer active" -Maximum ([uint32]::MaxValue)
        }
        $sameRunRoot = if ($null -eq $body.run_root) {
            $null -eq $failurePayload.run_root
        }
        else {
            Test-FaultGateFullPathEquals -PublishedPath $failurePayload.run_root -ExpectedPath ([string]$body.run_root)
        }
        if ([string]$failureEntry.body.channel -cne "FAULT_GATE" -or
            $failureIndex -ne ([uint64]$journal.records - 1) -or
            [string]$failureEntry.record_sha256 -cne [string]$journal.terminal_record_sha256 -or
            [string]$failurePayload.event -cne "HARNESS_FAILED" -or
            [string]$failurePayload.stage -cne [string]$body.stage -or
            [string]$failurePayload.exception_type -cne [string]$body.failure.exception_type -or
            [string]$failurePayload.fully_qualified_error_id -cne [string]$body.failure.fully_qualified_error_id -or
            [string]$failurePayload.message -cne [string]$body.failure.message -or
            -not $sameRunRoot -or $eventPassPublished -or
            $eventResourceCleanup -ne $resourceCleanupSucceeded -or
            $eventOuterCreated -ne $outerCreated -or
            $eventOuterCleanup -ne $outerCleanupSucceeded -or
            (($null -eq $eventOuterActive) -ne ($null -eq $body.cleanup.outer_active_processes_after_cleanup)) -or
            ($null -ne $eventOuterActive -and $eventOuterActive -ne [uint64]$body.cleanup.outer_active_processes_after_cleanup)) {
            throw "Fault failure receipt does not crosslink exactly to terminal HARNESS_FAILED payload/cleanup."
        }
    }
    elseif ($failureEvents.Count -ne 0) {
        throw "Fault failure receipt denies appending HARNESS_FAILED but its journal contains that event."
    }
    return [pscustomobject][ordered]@{
        body = $body
        record_sha256 = [string]$envelope.record_sha256
        file_bytes = [uint64]$snapshot.bytes
        file_sha256 = [string]$snapshot.sha256
    }
}

function Assert-FaultGateEvidenceDigest {
    param([Parameter(Mandatory = $true)] $Value, [Parameter(Mandatory = $true)] [string] $Label)
    if (-not (Test-FaultGateDigest $Value)) { throw "$Label must be a lowercase SHA-256 JSON string." }
}

function Get-FaultGateCanonicalContainedRelativePath {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [string] $FullPath,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $canonicalRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $canonicalPath = [IO.Path]::GetFullPath($FullPath)
    $rootPrefix = $canonicalRoot + '\'
    if (-not $canonicalPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "$Label escapes RunRoot." }
    $relative = $canonicalPath.Substring($rootPrefix.Length).Replace('\', '/')
    $null = Test-FaultGateCanonicalRelativePath -Root $canonicalRoot -RelativePath $relative -Label $Label
    return $relative
}

function Test-FaultGateCanonicalRelativePath {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] $RelativePath,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $relative = Get-FaultGateJsonNonEmptyString -Value $RelativePath -Label $Label
    if ($relative.IndexOf([char]0) -ge 0 -or $relative.Contains('\') -or $relative.Contains(':') -or
        $relative.StartsWith('/', [StringComparison]::Ordinal) -or [IO.Path]::IsPathRooted($relative)) {
        throw "$Label is not a canonical forward-slash relative path."
    }
    $segments = @($relative.Split('/'))
    if ($segments.Count -eq 0 -or @($segments | Where-Object { [string]::IsNullOrEmpty($_) -or $_ -ceq '.' -or $_ -ceq '..' }).Count -ne 0) {
        throw "$Label contains an empty, current, or parent segment."
    }
    $canonicalRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $resolved = [IO.Path]::GetFullPath((Join-Path $canonicalRoot $relative.Replace('/', '\')))
    if (-not $resolved.StartsWith($canonicalRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "$Label escapes RunRoot after resolution." }
    return $resolved
}

function Get-FaultGatePortableLeafComponent {
    param([Parameter(Mandatory = $true)] $Value, [Parameter(Mandatory = $true)] [string] $Label)
    $component = Get-FaultGateJsonNonEmptyString -Value $Value -Label $Label
    if ($component.IndexOf([char]0) -ge 0 -or $component.Contains('/') -or $component.Contains('\') -or
        $component.Contains(':') -or [IO.Path]::IsPathRooted($component) -or $component -ceq '.' -or $component -ceq '..' -or
        $component -cnotmatch '^[0-9A-Za-z][0-9A-Za-z._-]{0,255}$' -or $component.EndsWith('.', [StringComparison]::Ordinal) -or
        [IO.Path]::GetFileName($component) -cne $component) {
        throw "$Label is not a portable canonical leaf component."
    }
    return $component
}

function Assert-FaultGateExactDirectoryFileInventory {
    param(
        [Parameter(Mandatory = $true)] [string] $Directory,
        [Parameter(Mandatory = $true)] [string[]] $ExpectedNames,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $root = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $root
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label is not an ordinary directory."
    }
    $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($nameValue in $ExpectedNames) {
        $name = Get-FaultGatePortableLeafComponent -Value $nameValue -Label "$Label expected filename"
        if (-not $expected.Add($name)) { throw "$Label expected inventory contains a duplicate filename: $name" }
    }
    $items = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
    if ($items.Count -ne $expected.Count) { throw "$Label inventory cardinality differs from its exact manifest-derived set." }
    $actual = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($item in $items) {
        $full = [IO.Path]::GetFullPath($item.FullName)
        if (-not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a directory, link, junction, or escaping entry: $full"
        }
        $leaf = [IO.Path]::GetFileName($full)
        if (-not $expected.Contains($leaf) -or -not $actual.Add($leaf)) { throw "$Label contains an unknown, duplicate, or non-canonical entry: $leaf" }
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $full
        $streams = @(Get-Item -LiteralPath $full -Stream * -Force -ErrorAction Stop)
        if ($streams.Count -ne 1 -or [string]$streams[0].Stream -cne ':$DATA') {
            throw "$Label contains an alternate data stream: $leaf"
        }
    }
    foreach ($name in $expected) {
        if (-not $actual.Contains($name)) { throw "$Label omits manifest-derived entry: $name" }
    }
}

function Assert-FaultGateLiveDirectoryFileInventory {
    param(
        [Parameter(Mandatory = $true)] [string] $Directory,
        [Parameter(Mandatory = $true)] [string[]] $ExpectedNames,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $root = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $root
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label is not an ordinary directory."
    }
    $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($nameValue in $ExpectedNames) {
        $name = Get-FaultGatePortableLeafComponent -Value $nameValue -Label "$Label expected filename"
        if ($name -cne "segments.bnseg" -and $name -cnotmatch '^segment-[0-9]{6}\.(bnraw|bnack)$') {
            throw "$Label expected inventory contains a non-stream filename: $name"
        }
        if (-not $expected.Add($name)) { throw "$Label expected inventory contains a duplicate filename: $name" }
    }
    if (-not $expected.Contains("segments.bnseg")) { throw "$Label expected inventory omits segments.bnseg." }

    $actual = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $segmentKinds = @{}
    foreach ($item in @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)) {
        $full = [IO.Path]::GetFullPath($item.FullName)
        if (-not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a directory, link, junction, or escaping entry: $full"
        }
        $leaf = [IO.Path]::GetFileName($full)
        if (-not $actual.Add($leaf)) { throw "$Label contains a duplicate entry: $leaf" }
        if ($leaf -cne "segments.bnseg" -and $leaf -cnotmatch '^segment-([0-9]{6})\.(bnraw|bnack)$') {
            throw "$Label contains an unknown or non-canonical entry: $leaf"
        }
        if ($leaf -cne "segments.bnseg") {
            [uint64]$segmentIndex = [Convert]::ToUInt64($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
            $kind = [string]$Matches[2]
            if (-not $segmentKinds.ContainsKey($segmentIndex)) {
                $segmentKinds[$segmentIndex] = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            }
            if (-not $segmentKinds[$segmentIndex].Add($kind)) { throw "$Label repeats a segment artifact kind: $leaf" }
        }
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $full
        $streams = @(Get-Item -LiteralPath $full -Stream * -Force -ErrorAction Stop)
        if ($streams.Count -ne 1 -or [string]$streams[0].Stream -cne ':$DATA') {
            throw "$Label contains an alternate data stream: $leaf"
        }
    }
    foreach ($name in $expected) {
        if (-not $actual.Contains($name)) { throw "$Label lost an artifact from its verified manifest/prefix snapshot: $name" }
    }
    if (-not $actual.Contains("segments.bnseg") -or $segmentKinds.Count -eq 0) {
        throw "$Label lacks its manifest or any segment artifact."
    }
    [uint64[]]$indices = @($segmentKinds.Keys | ForEach-Object { [uint64]$_ } | Sort-Object)
    if ($indices[0] -ne 0) { throw "$Label live segment suffix does not begin at index zero." }
    for ($position = 0; $position -lt $indices.Count; $position++) {
        if ($indices[$position] -ne [uint64]$position) { throw "$Label live segment suffix contains an index gap." }
        $kindCount = [uint64]$segmentKinds[$indices[$position]].Count
        if ($kindCount -eq 0 -or $kindCount -gt 2 -or ($position -lt $indices.Count - 1 -and $kindCount -ne 2) -or
            ($position -eq $indices.Count - 1 -and $kindCount -eq 1 -and -not $segmentKinds[$indices[$position]].Contains("bnraw"))) {
            throw "$Label contains an incomplete non-terminal segment artifact pair."
        }
    }
}

function Add-FaultGateRequiredTreeDigest {
    param(
        [Parameter(Mandatory = $true)] $Map,
        [Parameter(Mandatory = $true)] [string] $RelativePath,
        [Parameter(Mandatory = $true)] [uint64] $Bytes,
        [Parameter(Mandatory = $true)] $Sha256,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    Assert-FaultGateEvidenceDigest -Value $Sha256 -Label "$Label digest"
    if ($Map.ContainsKey($RelativePath)) {
        if ([string]$Map[$RelativePath].sha256 -cne [string]$Sha256 -or [uint64]$Map[$RelativePath].bytes -ne $Bytes) { throw "$Label contradicts another required artifact bytes/digest." }
        return
    }
    $Map.Add($RelativePath, [pscustomobject][ordered]@{ bytes = $Bytes; sha256 = [string]$Sha256 })
}

function Test-FaultGateEvidenceAck {
    param([Parameter(Mandatory = $true)] $Ack, [Parameter(Mandatory = $true)] [string] $Label)
    Assert-FaultGateJsonObject -Value $Ack -Label $Label
    Assert-FaultGateExactProperties -Value $Ack -Names @("schema", "durable_record_count", "durable_through_offset", "last_record_sha256", "streams") -Label $Label
    $schema = Get-FaultGateJsonNonEmptyString -Value $Ack.schema -Label "$Label schema"
    $count = Get-FaultGateJsonUnsignedInteger -Value $Ack.durable_record_count -Label "$Label durable_record_count"
    $offset = Get-FaultGateJsonUnsignedInteger -Value $Ack.durable_through_offset -Label "$Label durable_through_offset"
    Assert-FaultGateEvidenceDigest -Value $Ack.last_record_sha256 -Label "$Label last_record_sha256"
    Assert-FaultGateJsonArray -Value $Ack.streams -Label "$Label streams"
    if ($schema -cne "DurabilityAckV1" -or $count -eq 0 -or $offset -le 8 -or @($Ack.streams).Count -ne 1) { throw "$Label has an invalid ACK identity/range." }
    $watermark = @($Ack.streams)[0]
    Assert-FaultGateJsonObject -Value $watermark -Label "$Label watermark"
    Assert-FaultGateExactProperties -Value $watermark -Names @("connection_epoch", "stream", "durable_through_frame_index") -Label "$Label watermark"
    $null = Get-FaultGateJsonNonEmptyString -Value $watermark.connection_epoch -Label "$Label watermark connection_epoch"
    $null = Get-FaultGateJsonNonEmptyString -Value $watermark.stream -Label "$Label watermark stream"
    $null = Get-FaultGateJsonUnsignedInteger -Value $watermark.durable_through_frame_index -Label "$Label watermark frame"
    return [pscustomobject][ordered]@{
        durable_record_count = $count; durable_through_offset = $offset; last_record_sha256 = [string]$Ack.last_record_sha256
        connection_epoch = [string]$watermark.connection_epoch; stream = [string]$watermark.stream
        durable_through_frame_index = [uint64]$watermark.durable_through_frame_index
    }
}

function Test-FaultGateEvidenceProgress {
    param([Parameter(Mandatory = $true)] $Progress, [Parameter(Mandatory = $true)] [string] $Label)
    Assert-FaultGateJsonObject -Value $Progress -Label $Label
    Assert-FaultGateExactProperties -Value $Progress -Names @(
        "records", "raw_file", "terminal_record_sha256", "file_bytes", "file_sha256", "verified_through_offset",
        "verified_prefix_sha256", "partial_tail_bytes", "partial_tail", "acknowledgements", "latest_ack"
    ) -Label $Label
    $records = Get-FaultGateJsonUnsignedInteger -Value $Progress.records -Label "$Label records"
    $rawFile = Get-FaultGateJsonNonEmptyString -Value $Progress.raw_file -Label "$Label raw_file"
    Assert-FaultGateEvidenceDigest -Value $Progress.terminal_record_sha256 -Label "$Label terminal_record_sha256"
    $fileBytes = Get-FaultGateJsonUnsignedInteger -Value $Progress.file_bytes -Label "$Label file_bytes"
    Assert-FaultGateEvidenceDigest -Value $Progress.file_sha256 -Label "$Label file_sha256"
    $verifiedThrough = Get-FaultGateJsonUnsignedInteger -Value $Progress.verified_through_offset -Label "$Label verified_through_offset"
    Assert-FaultGateEvidenceDigest -Value $Progress.verified_prefix_sha256 -Label "$Label verified_prefix_sha256"
    $partialTailBytes = Get-FaultGateJsonUnsignedInteger -Value $Progress.partial_tail_bytes -Label "$Label partial_tail_bytes"
    $partialTail = Get-FaultGateJsonBoolean -Value $Progress.partial_tail -Label "$Label partial_tail"
    Assert-FaultGateJsonArray -Value $Progress.acknowledgements -Label "$Label acknowledgements"
    $expectedProgressPartialTailBytes = Subtract-FaultGateCheckedUInt64 -Left $fileBytes -Right $verifiedThrough -Label "$Label ACK prefix boundary"
    if ($records -eq 0 -or $fileBytes -eq 0 -or $verifiedThrough -eq 0 -or
        $partialTailBytes -ne $expectedProgressPartialTailBytes -or $partialTailBytes -gt $script:FaultGateMaximumProgressPartialTailBytes -or
        $partialTail -ne ($partialTailBytes -ne 0) -or
        @($Progress.acknowledgements).Count -ne $records) { throw "$Label ACK record cardinality/prefix boundary is invalid." }
    $ackIndex = 0
    $previousAck = $null
    $previousProgressDigest = $script:FaultGateZeroDigest
    $progressPrefixBytes = [Collections.Generic.List[byte]]::new()
    foreach ($ack in @($Progress.acknowledgements)) {
        $ackSummary = Test-FaultGateEvidenceAck -Ack $ack -Label "$Label acknowledgement $ackIndex"
        if ($null -ne $previousAck -and
            ($ackSummary.durable_record_count -le $previousAck.durable_record_count -or
             $ackSummary.durable_through_offset -le $previousAck.durable_through_offset -or
             $ackSummary.durable_through_frame_index -le $previousAck.durable_through_frame_index -or
             $ackSummary.connection_epoch -cne $previousAck.connection_epoch -or $ackSummary.stream -cne $previousAck.stream)) {
            throw "$Label acknowledgements regress or change identity."
        }
        $progressBody = [pscustomobject][ordered]@{
            schema = "RawDurabilityProgressV1"
            record_index = [uint64]$ackIndex
            raw_path = $rawFile
            ack = $ack
            previous_record_sha256 = $previousProgressDigest
        }
        [byte[]]$progressBodyBytes = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $progressBody)
        $progressDigest = Get-FaultGateSha256Bytes -Bytes $progressBodyBytes
        $progressEnvelope = [pscustomobject][ordered]@{ body = $progressBody; record_sha256 = $progressDigest }
        [byte[]]$progressLineBytes = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $progressEnvelope)
        if ([uint64]$progressLineBytes.Length -gt $script:FaultGateMaximumProgressRecordBytes) {
            throw "$Label acknowledgement $ackIndex reconstructs an oversized BNACK record."
        }
        [byte[]]$progressLineWithLf = [byte[]]::new($progressLineBytes.Length + 1)
        [Array]::Copy($progressLineBytes, 0, $progressLineWithLf, 0, $progressLineBytes.Length)
        $progressLineWithLf[$progressLineBytes.Length] = 10
        $progressPrefixBytes.AddRange($progressLineWithLf)
        $previousProgressDigest = $progressDigest
        $previousAck = $ackSummary
        $ackIndex++
    }
    $latestAck = Test-FaultGateEvidenceAck -Ack $Progress.latest_ack -Label "$Label latest_ack"
    if ((Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($Progress.acknowledgements)[@($Progress.acknowledgements).Count - 1])) -cne
        (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $Progress.latest_ack))) { throw "$Label latest_ack differs from its last acknowledgement." }
    $progressPrefixSha256 = Get-FaultGateSha256Bytes -Bytes $progressPrefixBytes.ToArray()
    if ([uint64]$progressPrefixBytes.Count -ne $verifiedThrough -or
        $previousProgressDigest -cne [string]$Progress.terminal_record_sha256 -or
        $progressPrefixSha256 -cne [string]$Progress.verified_prefix_sha256 -or
        ($partialTailBytes -eq 0 -and [string]$Progress.file_sha256 -cne $progressPrefixSha256)) {
        throw "$Label reconstructed BNACK chain/prefix boundary is inconsistent."
    }
    return [pscustomobject][ordered]@{
        raw_file = $rawFile; durable_record_count = $latestAck.durable_record_count; durable_through_offset = $latestAck.durable_through_offset
        last_record_sha256 = $latestAck.last_record_sha256; connection_epoch = $latestAck.connection_epoch; stream = $latestAck.stream
        durable_through_frame_index = $latestAck.durable_through_frame_index; file_bytes = $fileBytes
        verified_through_offset = $verifiedThrough; verified_prefix_sha256 = [string]$Progress.verified_prefix_sha256
        partial_tail_bytes = $partialTailBytes; partial_tail = $partialTail
    }
}

function Test-FaultGateEvidenceRawPrefix {
    param([Parameter(Mandatory = $true)] $Raw, [Parameter(Mandatory = $true)] [string] $Label)
    Assert-FaultGateJsonObject -Value $Raw -Label $Label
    Assert-FaultGateExactProperties -Value $Raw -Names @(
        "raw_file", "connection_epoch", "stream", "observed_file_bytes", "durable_through_offset", "durable_records", "first_frame_index",
        "last_frame_index", "terminal_record_sha256", "verified_prefix_sha256", "unverified_suffix_bytes", "full_file_sha256"
    ) -Label $Label
    $rawFile = Get-FaultGateJsonNonEmptyString -Value $Raw.raw_file -Label "$Label raw_file"
    $epoch = Get-FaultGateJsonNonEmptyString -Value $Raw.connection_epoch -Label "$Label connection_epoch"
    $stream = Get-FaultGateJsonNonEmptyString -Value $Raw.stream -Label "$Label stream"
    $observed = Get-FaultGateJsonUnsignedInteger -Value $Raw.observed_file_bytes -Label "$Label observed_file_bytes"
    $durable = Get-FaultGateJsonUnsignedInteger -Value $Raw.durable_through_offset -Label "$Label durable_through_offset"
    $records = Get-FaultGateJsonUnsignedInteger -Value $Raw.durable_records -Label "$Label durable_records"
    $first = Get-FaultGateJsonUnsignedInteger -Value $Raw.first_frame_index -Label "$Label first_frame_index"
    $last = Get-FaultGateJsonUnsignedInteger -Value $Raw.last_frame_index -Label "$Label last_frame_index"
    $suffix = Get-FaultGateJsonUnsignedInteger -Value $Raw.unverified_suffix_bytes -Label "$Label unverified_suffix_bytes"
    Assert-FaultGateEvidenceDigest -Value $Raw.terminal_record_sha256 -Label "$Label terminal_record_sha256"
    Assert-FaultGateEvidenceDigest -Value $Raw.verified_prefix_sha256 -Label "$Label verified_prefix_sha256"
    Assert-FaultGateEvidenceDigest -Value $Raw.full_file_sha256 -Label "$Label full_file_sha256"
    $expectedLast = Get-FaultGateInclusiveLastUInt64 -First $first -Count $records -Label "$Label frame range"
    $expectedSuffix = Subtract-FaultGateCheckedUInt64 -Left $observed -Right $durable -Label "$Label raw suffix boundary"
    if ($last -ne $expectedLast -or $suffix -ne $expectedSuffix) { throw "$Label numeric boundary is inconsistent." }
    return [pscustomobject][ordered]@{
        raw_file = $rawFile; connection_epoch = $epoch; stream = $stream; observed_file_bytes = $observed; durable_through_offset = $durable
        durable_records = $records; first_frame_index = $first; last_frame_index = $last; terminal_record_sha256 = [string]$Raw.terminal_record_sha256
        verified_prefix_sha256 = [string]$Raw.verified_prefix_sha256; unverified_suffix_bytes = $suffix
    }
}

function Test-FaultGateEvidenceSegment {
    param([Parameter(Mandatory = $true)] $Segment, [Parameter(Mandatory = $true)] [string] $Label)
    Assert-FaultGateJsonObject -Value $Segment -Label $Label
    $names = @($Segment.PSObject.Properties.Name)
    $segmentIndex = Get-FaultGateJsonUnsignedInteger -Value $Segment.segment_index -Label "$Label segment_index"
    $expectedRawFile = "segment-{0:D6}.bnraw" -f $segmentIndex
    $expectedProgressFile = "segment-{0:D6}.bnack" -f $segmentIndex
    $sealed = Get-FaultGateJsonBoolean -Value $Segment.sealed -Label "$Label sealed"
    $durablePrefix = $false
    $rawSummary = $null
    $progressSummary = $null
    if ($sealed) {
        Assert-FaultGateExactProperties -Value $Segment -Names @("segment_index", "sealed", "raw", "progress") -Label $Label
        $rawSummary = Test-FaultGateEvidenceRawPrefix -Raw $Segment.raw -Label "$Label raw"
        $progressSummary = Test-FaultGateEvidenceProgress -Progress $Segment.progress -Label "$Label progress"
    }
    else {
        $durablePrefix = Get-FaultGateJsonBoolean -Value $Segment.durable_prefix -Label "$Label durable_prefix"
        if ($durablePrefix) {
            Assert-FaultGateExactProperties -Value $Segment -Names @("segment_index", "sealed", "durable_prefix", "raw", "progress") -Label $Label
            $rawSummary = Test-FaultGateEvidenceRawPrefix -Raw $Segment.raw -Label "$Label raw"
            $progressSummary = Test-FaultGateEvidenceProgress -Progress $Segment.progress -Label "$Label progress"
        }
        elseif (($names -join "`n") -ceq (@("segment_index", "sealed", "durable_prefix", "raw_file_bytes", "raw_file_sha256", "progress_file_bytes", "progress_file_sha256") -join "`n")) {
            $null = Get-FaultGateJsonUnsignedInteger -Value $Segment.raw_file_bytes -Label "$Label raw_file_bytes"
            $progressFileBytes = Get-FaultGateJsonUnsignedInteger -Value $Segment.progress_file_bytes -Label "$Label progress_file_bytes"
            Assert-FaultGateEvidenceDigest -Value $Segment.raw_file_sha256 -Label "$Label raw_file_sha256"
            Assert-FaultGateEvidenceDigest -Value $Segment.progress_file_sha256 -Label "$Label progress_file_sha256"
            if ($progressFileBytes -gt $script:FaultGateMaximumProgressPartialTailBytes) { throw "$Label contains an oversized non-authoritative BNACK tail." }
        }
        else {
            Assert-FaultGateExactProperties -Value $Segment -Names @("segment_index", "sealed", "durable_prefix", "sole_partial_file", "sole_partial_file_bytes", "sole_partial_file_sha256") -Label $Label
            $null = Get-FaultGateJsonNonEmptyString -Value $Segment.sole_partial_file -Label "$Label sole_partial_file"
            $null = Get-FaultGateJsonUnsignedInteger -Value $Segment.sole_partial_file_bytes -Label "$Label sole_partial_file_bytes"
            Assert-FaultGateEvidenceDigest -Value $Segment.sole_partial_file_sha256 -Label "$Label sole_partial_file_sha256"
            if ([string]$Segment.sole_partial_file -cne $expectedRawFile) { throw "$Label sole partial artifact is not the required BNRAW predecessor." }
        }
    }
    if ($sealed -or $durablePrefix) {
        if ($rawSummary.raw_file -cne $expectedRawFile -or $progressSummary.raw_file -cne $expectedRawFile -or
            $rawSummary.connection_epoch -cne $progressSummary.connection_epoch -or
            $rawSummary.stream -cne $progressSummary.stream -or $rawSummary.durable_records -ne $progressSummary.durable_record_count -or
            $rawSummary.durable_through_offset -ne $progressSummary.durable_through_offset -or
            $rawSummary.terminal_record_sha256 -cne $progressSummary.last_record_sha256 -or
            $rawSummary.last_frame_index -ne $progressSummary.durable_through_frame_index) {
            throw "$Label raw prefix and latest ACK contradict each other."
        }
        if ($sealed -and ($rawSummary.observed_file_bytes -ne $rawSummary.durable_through_offset -or
            $rawSummary.unverified_suffix_bytes -ne 0 -or $progressSummary.verified_through_offset -ne $progressSummary.file_bytes -or
            $progressSummary.partial_tail_bytes -ne 0 -or $progressSummary.partial_tail)) {
            throw "$Label sealed segment contains an unverified raw or ACK tail."
        }
    }
    return [pscustomobject][ordered]@{
        segment_index = $segmentIndex; sealed = $sealed; durable_prefix = if ($sealed) { $true } else { $durablePrefix }
        raw = if ($sealed -or $durablePrefix) { $rawSummary } else { $null }
    }
}

function Get-FaultGateVerifiedDepthConnectionEpoch {
    param(
        [Parameter(Mandatory = $true)] $Generation,
        [Parameter(Mandatory = $true)] [ValidateSet("BTCUSDT", "ETHUSDT")] [string] $Symbol
    )
    Assert-FaultGateJsonObject -Value $Generation -Label "$Symbol final raw generation"
    $depthStreams = @($Generation.streams | Where-Object { [string]$_.stream -ceq "depth" })
    $depthTransports = @($Generation.transports | Where-Object { [string]$_.stream -ceq "depth" })
    if ($depthStreams.Count -ne 1 -or $depthTransports.Count -ne 1) {
        throw "$Symbol final raw generation lacks one exact depth stream/transport authority."
    }
    $transportEpoch = Get-FaultGateJsonNonEmptyString -Value $depthTransports[0].connection_epoch -Label "$Symbol depth transport connection_epoch"
    $manifestRecords = Get-FaultGateJsonUnsignedInteger -Value $depthStreams[0].manifest_records -Label "$Symbol depth manifest_records"
    Assert-FaultGateJsonArray -Value $depthStreams[0].verified_segments -Label "$Symbol depth verified_segments"
    $segments = @($depthStreams[0].verified_segments)
    if ($manifestRecords -eq 0 -or $segments.Count -lt $manifestRecords -or
        [uint64]$segments.Count -gt (Get-FaultGateUInt64Successor -Value $manifestRecords -Label "$Symbol depth segment cardinality")) {
        throw "$Symbol depth verified segment cardinality cannot establish an authoritative epoch."
    }
    [uint64]$sealedSegments = 0
    [uint64]$authoritativeSegments = 0
    $authoritativeEpochs = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $authoritativeEpoch = $null
    for ($position = 0; $position -lt $segments.Count; $position++) {
        $summary = Test-FaultGateEvidenceSegment -Segment $segments[$position] -Label "$Symbol depth epoch segment $position"
        if ($summary.segment_index -ne [uint64]$position -or
            ($position -lt $manifestRecords -and -not $summary.sealed) -or
            ($position -eq $manifestRecords -and $summary.sealed)) {
            throw "$Symbol depth epoch segment ordering/seal authority is invalid."
        }
        if ($summary.sealed) {
            $sealedSegments++
        }
        if ($null -ne $summary.raw) {
            if (-not $summary.durable_prefix) { throw "$Symbol depth raw epoch lacks sealed/durable authority." }
            $rawEpoch = Get-FaultGateJsonNonEmptyString -Value $summary.raw.connection_epoch -Label "$Symbol authoritative depth raw connection_epoch"
            if ($null -eq $authoritativeEpoch) { $authoritativeEpoch = $rawEpoch }
            $null = $authoritativeEpochs.Add($rawEpoch)
            $authoritativeSegments++
        }
    }
    $maximumAuthoritativeSegments = Get-FaultGateUInt64Successor -Value $manifestRecords -Label "$Symbol depth authoritative segment cardinality"
    if ($sealedSegments -ne $manifestRecords -or $authoritativeSegments -lt $manifestRecords -or
        $authoritativeSegments -gt $maximumAuthoritativeSegments -or $authoritativeEpochs.Count -ne 1 -or
        $null -eq $authoritativeEpoch -or $authoritativeEpoch -cne $transportEpoch) {
        throw "$Symbol depth manifest/raw epochs do not establish one exact transport-bound authority."
    }
    return $authoritativeEpoch
}

function Test-FaultGateEvidenceTelemetry {
    param(
        [Parameter(Mandatory = $true)] $Telemetry,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    Assert-FaultGateJsonObject -Value $Telemetry -Label $Label
    Assert-FaultGateExactProperties -Value $Telemetry -Names @(
        "file", "duration_requested_s", "market_freshness_startup_grace_s", "market_freshness_deadline_s",
        "observed_file_bytes", "full_file_sha256", "verified_through_offset", "verified_prefix_sha256", "partial_tail_bytes", "verified_records"
    ) -Label $Label
    $file = Get-FaultGateJsonNonEmptyString -Value $Telemetry.file -Label "$Label file"
    $duration = Get-FaultGateJsonUnsignedInteger -Value $Telemetry.duration_requested_s -Label "$Label duration_requested_s"
    $grace = Get-FaultGateJsonUnsignedInteger -Value $Telemetry.market_freshness_startup_grace_s -Label "$Label market freshness grace"
    $deadline = Get-FaultGateJsonUnsignedInteger -Value $Telemetry.market_freshness_deadline_s -Label "$Label market freshness deadline"
    $observed = Get-FaultGateJsonUnsignedInteger -Value $Telemetry.observed_file_bytes -Label "$Label observed_file_bytes"
    $verified = Get-FaultGateJsonUnsignedInteger -Value $Telemetry.verified_through_offset -Label "$Label verified_through_offset"
    $partial = Get-FaultGateJsonUnsignedInteger -Value $Telemetry.partial_tail_bytes -Label "$Label partial_tail_bytes"
    Assert-FaultGateEvidenceDigest -Value $Telemetry.full_file_sha256 -Label "$Label full file digest"
    Assert-FaultGateEvidenceDigest -Value $Telemetry.verified_prefix_sha256 -Label "$Label verified prefix digest"
    Assert-FaultGateJsonArray -Value $Telemetry.verified_records -Label "$Label verified_records"
    $records = @($Telemetry.verified_records)
    $expectedTelemetryPartial = Subtract-FaultGateCheckedUInt64 -Left $observed -Right $verified -Label "$Label telemetry prefix boundary"
    if ($file -cne "telemetry.jsonl" -or $duration -ne $script:FaultGateGenerationZeroDurationSeconds -or $grace -ne 30 -or $deadline -ne 30 -or
        $records.Count -eq 0 -or $verified -eq 0 -or $partial -ne $expectedTelemetryPartial -or
        $partial -gt $script:FaultGateMaximumTelemetryPartialTailBytes) {
        throw "$Label identity/duration/prefix boundary is invalid."
    }
    $prefixBytes = [Collections.Generic.List[byte]]::new()
    $previousRecord = $null
    for ($recordPosition = 0; $recordPosition -lt $records.Count; $recordPosition++) {
        $summary = $records[$recordPosition]
        Assert-FaultGateJsonObject -Value $summary -Label "$Label record summary $recordPosition"
        Assert-FaultGateExactProperties -Value $summary -Names @("record_index", "durable_through_offset", "record_sha256", "record") -Label "$Label record summary $recordPosition"
        $index = Get-FaultGateJsonUnsignedInteger -Value $summary.record_index -Label "$Label record summary index"
        $offset = Get-FaultGateJsonUnsignedInteger -Value $summary.durable_through_offset -Label "$Label record summary offset"
        Assert-FaultGateEvidenceDigest -Value $summary.record_sha256 -Label "$Label record summary digest"
        $null = Test-FaultGateTelemetryRecord -Record $summary.record -ExpectedIndex ([uint64]$recordPosition) -PreviousRecord $previousRecord -DurationRequestedSeconds $duration -FreshnessStartupGraceSeconds $grace -FreshnessDeadlineSeconds $deadline -Label "$Label record $recordPosition"
        [byte[]]$line = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $summary.record)
        if ([uint64]$line.Length -ge $script:FaultGateMaximumTelemetryRecordBytes) {
            throw "$Label record $recordPosition exceeds the exact telemetry writer publication bound."
        }
        [byte[]]$lineWithLf = [byte[]]::new($line.Length + 1)
        [Array]::Copy($line, 0, $lineWithLf, 0, $line.Length)
        $lineWithLf[$line.Length] = 10
        $prefixBytes.AddRange($lineWithLf)
        if ($index -ne [uint64]$recordPosition -or $offset -ne [uint64]$prefixBytes.Count -or
            [string]$summary.record_sha256 -cne (Get-FaultGateSha256Bytes -Bytes $lineWithLf)) {
            throw "$Label record summary is not bound to one exact serde JSONL record."
        }
        $previousRecord = $summary.record
    }
    $prefixSha = Get-FaultGateSha256Bytes -Bytes $prefixBytes.ToArray()
    if ([uint64]$prefixBytes.Count -ne $verified -or $prefixSha -cne [string]$Telemetry.verified_prefix_sha256 -or
        ($partial -eq 0 -and ([string]$Telemetry.full_file_sha256 -cne $prefixSha -or $observed -ne $verified))) {
        throw "$Label terminal prefix digest/offset is inconsistent."
    }
    return [pscustomobject][ordered]@{
        file = $file; duration_requested_s = $duration; observed_file_bytes = $observed; full_file_sha256 = [string]$Telemetry.full_file_sha256
        verified_through_offset = $verified; verified_prefix_sha256 = $prefixSha; partial_tail_bytes = $partial; records = [uint64]$records.Count
    }
}

function Test-FaultGateEvidenceGeneration {
    param(
        [Parameter(Mandatory = $true)] $Generation,
        [Parameter(Mandatory = $true)] [string] $ExpectedSymbol,
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    Assert-FaultGateJsonObject -Value $Generation -Label $Label
    Assert-FaultGateExactProperties -Value $Generation -Names @("symbol", "session_id", "session_directory", "spec_revision", "startup_bytes", "startup_sha256", "snapshot", "transports", "telemetry", "streams") -Label $Label
    $symbol = Get-FaultGateJsonNonEmptyString -Value $Generation.symbol -Label "$Label symbol"
    $sessionId = Get-FaultGateJsonNonEmptyString -Value $Generation.session_id -Label "$Label session_id"
    $sessionDirectory = Get-FaultGateJsonNonEmptyString -Value $Generation.session_directory -Label "$Label session_directory"
    $specRevision = Get-FaultGateJsonNonEmptyString -Value $Generation.spec_revision -Label "$Label spec_revision"
    $null = Get-FaultGateCanonicalContainedRelativePath -Root $RunRoot -FullPath $sessionDirectory -Label "$Label session_directory"
    if ([IO.Path]::GetFileName([IO.Path]::GetFullPath($sessionDirectory)) -cne $sessionId -or $specRevision -cne $script:FaultGateSpecRevision) { throw "$Label session_directory/spec revision identity is invalid." }
    $startupBytes = Get-FaultGateJsonUnsignedInteger -Value $Generation.startup_bytes -Label "$Label startup_bytes"
    Assert-FaultGateEvidenceDigest -Value $Generation.startup_sha256 -Label "$Label startup_sha256"
    Assert-FaultGateJsonObject -Value $Generation.snapshot -Label "$Label snapshot"
    Assert-FaultGateExactProperties -Value $Generation.snapshot -Names @("bytes", "terminal_record_sha256", "file_sha256", "http_metadata_file", "http_metadata_bytes", "http_metadata_sha256", "raw_frame_summary", "http_metadata", "campaign_event") -Label "$Label snapshot"
    $snapshotBytes = Get-FaultGateJsonUnsignedInteger -Value $Generation.snapshot.bytes -Label "$Label snapshot bytes"
    Assert-FaultGateEvidenceDigest -Value $Generation.snapshot.terminal_record_sha256 -Label "$Label snapshot terminal digest"
    Assert-FaultGateEvidenceDigest -Value $Generation.snapshot.file_sha256 -Label "$Label snapshot file digest"
    $snapshotHttpFile = Get-FaultGateJsonNonEmptyString -Value $Generation.snapshot.http_metadata_file -Label "$Label snapshot HTTP metadata file"
    $snapshotHttpBytes = Get-FaultGateJsonUnsignedInteger -Value $Generation.snapshot.http_metadata_bytes -Label "$Label snapshot HTTP metadata bytes"
    Assert-FaultGateEvidenceDigest -Value $Generation.snapshot.http_metadata_sha256 -Label "$Label snapshot HTTP metadata digest"
    Assert-FaultGateJsonObject -Value $Generation.snapshot.raw_frame_summary -Label "$Label snapshot raw frame summary"
    Assert-FaultGateExactProperties -Value $Generation.snapshot.raw_frame_summary -Names @(
        "endpoint", "connection_epoch", "receive_wall_ns", "receive_mono_ns", "payload_length", "payload_sha256", "last_update_id", "bid_levels", "ask_levels"
    ) -Label "$Label snapshot raw frame summary"
    $snapshotEndpoint = Get-FaultGateJsonNonEmptyString -Value $Generation.snapshot.raw_frame_summary.endpoint -Label "$Label snapshot endpoint"
    $null = Get-FaultGateJsonNonEmptyString -Value $Generation.snapshot.raw_frame_summary.connection_epoch -Label "$Label snapshot epoch"
    $snapshotReceiveWall = Get-FaultGateJsonUnsignedInteger -Value $Generation.snapshot.raw_frame_summary.receive_wall_ns -Label "$Label snapshot receive wall"
    $snapshotReceiveMono = Get-FaultGateJsonUnsignedInteger -Value $Generation.snapshot.raw_frame_summary.receive_mono_ns -Label "$Label snapshot receive monotonic"
    $snapshotPayloadLength = Get-FaultGateJsonUnsignedInteger -Value $Generation.snapshot.raw_frame_summary.payload_length -Label "$Label snapshot payload length"
    Assert-FaultGateEvidenceDigest -Value $Generation.snapshot.raw_frame_summary.payload_sha256 -Label "$Label snapshot payload digest"
    $null = Get-FaultGateJsonUnsignedInteger -Value $Generation.snapshot.raw_frame_summary.last_update_id -Label "$Label snapshot last update id"
    $null = Get-FaultGateJsonUnsignedInteger -Value $Generation.snapshot.raw_frame_summary.bid_levels -Label "$Label snapshot bid levels"
    $null = Get-FaultGateJsonUnsignedInteger -Value $Generation.snapshot.raw_frame_summary.ask_levels -Label "$Label snapshot ask levels"
    Assert-FaultGateJsonObject -Value $Generation.snapshot.http_metadata -Label "$Label snapshot HTTP metadata"
    Assert-FaultGateExactProperties -Value $Generation.snapshot.http_metadata -Names @(
        "schema", "endpoint", "http_status", "headers", "receive_wall_ns", "receive_mono_ns", "body_complete", "body_length", "body_sha256", "raw_file", "raw_record_sha256"
    ) -Label "$Label snapshot HTTP metadata"
    $snapshotMetadata = $Generation.snapshot.http_metadata
    $snapshotMetadataStatus = Get-FaultGateJsonUnsignedInteger -Value $snapshotMetadata.http_status -Label "$Label snapshot metadata HTTP status" -Maximum ([uint16]::MaxValue)
    $snapshotMetadataWall = Get-FaultGateJsonUnsignedInteger -Value $snapshotMetadata.receive_wall_ns -Label "$Label snapshot metadata receive wall"
    $snapshotMetadataMono = Get-FaultGateJsonUnsignedInteger -Value $snapshotMetadata.receive_mono_ns -Label "$Label snapshot metadata receive monotonic"
    $snapshotMetadataComplete = Get-FaultGateJsonBoolean -Value $snapshotMetadata.body_complete -Label "$Label snapshot metadata complete"
    $snapshotMetadataLength = Get-FaultGateJsonUnsignedInteger -Value $snapshotMetadata.body_length -Label "$Label snapshot metadata length"
    foreach ($field in @("schema", "endpoint", "body_sha256", "raw_file", "raw_record_sha256")) { $null = Get-FaultGateJsonNonEmptyString -Value $snapshotMetadata.$field -Label "$Label snapshot metadata $field" }
    Assert-FaultGateEvidenceDigest -Value $snapshotMetadata.body_sha256 -Label "$Label snapshot metadata body digest"
    Assert-FaultGateEvidenceDigest -Value $snapshotMetadata.raw_record_sha256 -Label "$Label snapshot metadata raw digest"
    Test-FaultGateResponseHeaders -Headers $snapshotMetadata.headers -Label "$Label snapshot metadata headers"
    [byte[]]$canonicalSnapshotMetadataBytes = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $snapshotMetadata)
    $expectedSnapshotEndpoint = "https://data-api.binance.vision/api/v3/depth?symbol=" + $ExpectedSymbol + "&limit=5000"
    if ($snapshotEndpoint -cne $expectedSnapshotEndpoint -or $snapshotReceiveWall -eq 0 -or $snapshotReceiveMono -eq 0 -or $snapshotPayloadLength -eq 0 -or
        [string]$snapshotMetadata.schema -cne "SnapshotHttpMetadataV1" -or [string]$snapshotMetadata.endpoint -cne $snapshotEndpoint -or $snapshotMetadataStatus -ne 200 -or
        -not $snapshotMetadataComplete -or $snapshotMetadataWall -ne $snapshotReceiveWall -or $snapshotMetadataMono -ne $snapshotReceiveMono -or
        $snapshotMetadataLength -ne $snapshotPayloadLength -or [string]$snapshotMetadata.body_sha256 -cne [string]$Generation.snapshot.raw_frame_summary.payload_sha256 -or
        [string]$snapshotMetadata.raw_file -cne "snapshot.bnraw" -or [string]$snapshotMetadata.raw_record_sha256 -cne [string]$Generation.snapshot.terminal_record_sha256 -or
        [uint64]$canonicalSnapshotMetadataBytes.Length -ne $snapshotHttpBytes -or (Get-FaultGateSha256Bytes -Bytes $canonicalSnapshotMetadataBytes) -cne [string]$Generation.snapshot.http_metadata_sha256) {
        throw "$Label snapshot raw/HTTP metadata semantic crosslinks are invalid."
    }
    $snapshotCampaignEvent = $Generation.snapshot.campaign_event
    Assert-FaultGateJsonObject -Value $snapshotCampaignEvent -Label "$Label snapshot campaign event envelope"
    Assert-FaultGateExactProperties -Value $snapshotCampaignEvent -Names @("body", "record_sha256") -Label "$Label snapshot campaign event envelope"
    Assert-FaultGateJsonObject -Value $snapshotCampaignEvent.body -Label "$Label snapshot campaign event body"
    Assert-FaultGateExactProperties -Value $snapshotCampaignEvent.body -Names @("schema", "record_index", "wall_ns", "campaign_mono_ns", "generation_index", "channel", "payload", "previous_record_sha256") -Label "$Label snapshot campaign event body"
    $snapshotEventRecordIndex = Get-FaultGateJsonUnsignedInteger -Value $snapshotCampaignEvent.body.record_index -Label "$Label snapshot event record_index"
    $snapshotEventWall = Get-FaultGateJsonUnsignedInteger -Value $snapshotCampaignEvent.body.wall_ns -Label "$Label snapshot event wall_ns"
    $null = Get-FaultGateJsonUnsignedInteger -Value $snapshotCampaignEvent.body.campaign_mono_ns -Label "$Label snapshot event campaign_mono_ns"
    $snapshotEventGeneration = Get-FaultGateJsonUnsignedInteger -Value $snapshotCampaignEvent.body.generation_index -Label "$Label snapshot event generation_index"
    Assert-FaultGateEvidenceDigest -Value $snapshotCampaignEvent.body.previous_record_sha256 -Label "$Label snapshot event previous digest"
    Assert-FaultGateEvidenceDigest -Value $snapshotCampaignEvent.record_sha256 -Label "$Label snapshot event record digest"
    Assert-FaultGateJsonObject -Value $snapshotCampaignEvent.body.payload -Label "$Label snapshot event payload"
    Assert-FaultGateExactProperties -Value $snapshotCampaignEvent.body.payload -Names @("durable_through_offset", "event", "http_metadata_file", "http_metadata_sha256", "last_record_sha256", "raw_file", "schema", "session_id") -Label "$Label snapshot event payload"
    $snapshotEventOffset = Get-FaultGateJsonUnsignedInteger -Value $snapshotCampaignEvent.body.payload.durable_through_offset -Label "$Label snapshot event durable offset"
    $snapshotEventSession = Get-FaultGatePortableLeafComponent -Value $snapshotCampaignEvent.body.payload.session_id -Label "$Label snapshot event session_id"
    foreach ($digestName in @("http_metadata_sha256", "last_record_sha256")) { Assert-FaultGateEvidenceDigest -Value $snapshotCampaignEvent.body.payload.$digestName -Label "$Label snapshot event $digestName" }
    if ([string]$snapshotCampaignEvent.body.schema -cne "RawCampaignJournalRecordV1" -or $snapshotEventRecordIndex -eq 0 -or $snapshotEventWall -eq 0 -or
        $snapshotEventGeneration -ne 0 -or [string]$snapshotCampaignEvent.body.channel -cne "CHILD_STDOUT" -or
        [string]$snapshotCampaignEvent.body.payload.event -cne "SNAPSHOT_DURABLE" -or [string]$snapshotCampaignEvent.body.payload.schema -cne "SnapshotDurableProcessEventV1" -or
        $snapshotEventSession -cne $sessionId -or [string]$snapshotCampaignEvent.body.payload.raw_file -cne "snapshot.bnraw" -or
        [string]$snapshotCampaignEvent.body.payload.http_metadata_file -cne $snapshotHttpFile -or $snapshotEventOffset -ne $snapshotBytes -or
        [string]$snapshotCampaignEvent.body.payload.http_metadata_sha256 -cne [string]$Generation.snapshot.http_metadata_sha256 -or
        [string]$snapshotCampaignEvent.body.payload.last_record_sha256 -cne [string]$Generation.snapshot.terminal_record_sha256 -or
        [string]$snapshotCampaignEvent.record_sha256 -cne (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $snapshotCampaignEvent.body))) {
        throw "$Label snapshot evidence is not bound to the exact campaign journal SNAPSHOT_DURABLE record."
    }
    Assert-FaultGateJsonArray -Value $Generation.transports -Label "$Label transports"
    if (@($Generation.transports).Count -ne 2) { throw "$Label transport cardinality is invalid." }
    $transportEpochs = @{}
    for ($transportIndex = 0; $transportIndex -lt 2; $transportIndex++) {
        $expectedTransportStream = @("depth", "trade")[$transportIndex]
        $transport = @($Generation.transports)[$transportIndex]
        Assert-FaultGateJsonObject -Value $transport -Label "$Label transport $transportIndex"
        Assert-FaultGateExactProperties -Value $transport -Names @("stream", "connection_epoch", "uri", "metadata_file", "metadata_bytes", "metadata_sha256", "metadata", "campaign_event") -Label "$Label transport $transportIndex"
        $transportStream = Get-FaultGateJsonNonEmptyString -Value $transport.stream -Label "$Label transport stream"
        $transportEpoch = Get-FaultGateJsonNonEmptyString -Value $transport.connection_epoch -Label "$Label transport epoch"
        $transportUri = Get-FaultGateJsonNonEmptyString -Value $transport.uri -Label "$Label transport URI"
        $transportFile = Get-FaultGateJsonNonEmptyString -Value $transport.metadata_file -Label "$Label transport file"
        $transportBytes = Get-FaultGateJsonUnsignedInteger -Value $transport.metadata_bytes -Label "$Label transport bytes"
        Assert-FaultGateEvidenceDigest -Value $transport.metadata_sha256 -Label "$Label transport metadata digest"
        Assert-FaultGateJsonObject -Value $transport.metadata -Label "$Label transport metadata"
        [byte[]]$canonicalTransportBytes = @(ConvertTo-FaultGateSerdeTransportBytes -Metadata $transport.metadata)
        $validatedTransport = Test-FaultGateTransportMetadataArtifact -MetadataBytes $canonicalTransportBytes -CampaignEvent $transport.campaign_event -ExpectedStream $expectedTransportStream -ExpectedSessionId $sessionId -ExpectedSymbol $ExpectedSymbol -ExpectedSpecRevision $specRevision
        if ($transportStream -cne $expectedTransportStream -or $transportEpoch -cne [string]$validatedTransport.connection_epoch -or
            $transportUri -cne [string]$validatedTransport.uri -or $transportFile -cne [string]$validatedTransport.metadata_file -or
            $transportBytes -ne [uint64]$canonicalTransportBytes.Length -or [string]$transport.metadata_sha256 -cne (Get-FaultGateSha256Bytes -Bytes $canonicalTransportBytes)) {
            throw "$Label transport report is not bound to its canonical metadata/event."
        }
        $transportEpochs[$transportStream] = $transportEpoch
    }
    if ([string]$transportEpochs.depth -ceq [string]$transportEpochs.trade) { throw "$Label transport epochs are not independent." }
    $null = Test-FaultGateEvidenceTelemetry -Telemetry $Generation.telemetry -Label "$Label telemetry"
    Assert-FaultGateJsonArray -Value $Generation.streams -Label "$Label streams"
    if ($symbol -cne $ExpectedSymbol -or $startupBytes -eq 0 -or $snapshotBytes -le 44 -or $snapshotHttpFile -cne "snapshot-http.json" -or
        $snapshotHttpBytes -eq 0 -or @($Generation.streams).Count -ne 2) { throw "$Label symbol/startup/snapshot/stream cardinality is invalid." }
    $expectedStreams = @("depth", "trade")
    for ($streamIndex = 0; $streamIndex -lt 2; $streamIndex++) {
        $stream = @($Generation.streams)[$streamIndex]
        Assert-FaultGateJsonObject -Value $stream -Label "$Label stream $streamIndex"
        Assert-FaultGateExactProperties -Value $stream -Names @(
            "stream", "manifest_records", "manifest_terminal_record_sha256", "manifest_file_bytes", "manifest_file_sha256",
            "manifest_verified_through_offset", "manifest_verified_prefix_sha256", "manifest_partial_tail_bytes", "manifest_verified_records", "verified_segments"
        ) -Label "$Label stream $streamIndex"
        $streamName = Get-FaultGateJsonNonEmptyString -Value $stream.stream -Label "$Label stream name"
        $manifestRecords = Get-FaultGateJsonUnsignedInteger -Value $stream.manifest_records -Label "$Label manifest_records"
        Assert-FaultGateEvidenceDigest -Value $stream.manifest_terminal_record_sha256 -Label "$Label manifest terminal digest"
        $manifestBytes = Get-FaultGateJsonUnsignedInteger -Value $stream.manifest_file_bytes -Label "$Label manifest bytes"
        Assert-FaultGateEvidenceDigest -Value $stream.manifest_file_sha256 -Label "$Label manifest file digest"
        $manifestVerified = Get-FaultGateJsonUnsignedInteger -Value $stream.manifest_verified_through_offset -Label "$Label manifest verified offset"
        Assert-FaultGateEvidenceDigest -Value $stream.manifest_verified_prefix_sha256 -Label "$Label manifest verified prefix digest"
        $manifestPartial = Get-FaultGateJsonUnsignedInteger -Value $stream.manifest_partial_tail_bytes -Label "$Label manifest partial tail"
        Assert-FaultGateJsonArray -Value $stream.manifest_verified_records -Label "$Label manifest verified records"
        $manifestVerifiedRecords = @($stream.manifest_verified_records)
        Assert-FaultGateJsonArray -Value $stream.verified_segments -Label "$Label verified_segments"
        $segmentRows = @($stream.verified_segments)
        $maximumSegmentRows = Get-FaultGateUInt64Successor -Value $manifestRecords -Label "$Label stream segment cardinality"
        $expectedManifestPartial = Subtract-FaultGateCheckedUInt64 -Left $manifestBytes -Right $manifestVerified -Label "$Label stream manifest prefix boundary"
        if ($streamName -cne $expectedStreams[$streamIndex] -or $manifestRecords -eq 0 -or $manifestBytes -le 8 -or $manifestVerified -le 8 -or
            $manifestPartial -ne $expectedManifestPartial -or
            $manifestVerifiedRecords.Count -ne $manifestRecords -or $segmentRows.Count -lt $manifestRecords -or $segmentRows.Count -gt $maximumSegmentRows) { throw "$Label stream manifest/segment cardinality is invalid." }
        [uint64]$previousManifestOffset = 8
        for ($manifestIndex = 0; $manifestIndex -lt $manifestVerifiedRecords.Count; $manifestIndex++) {
            $manifestRecord = $manifestVerifiedRecords[$manifestIndex]
            Assert-FaultGateJsonObject -Value $manifestRecord -Label "$Label manifest record $manifestIndex"
            Assert-FaultGateExactProperties -Value $manifestRecord -Names @("record_index", "verified_through_offset", "terminal_record_sha256", "verified_prefix_sha256") -Label "$Label manifest record $manifestIndex"
            $recordIndex = Get-FaultGateJsonUnsignedInteger -Value $manifestRecord.record_index -Label "$Label manifest record index"
            $recordOffset = Get-FaultGateJsonUnsignedInteger -Value $manifestRecord.verified_through_offset -Label "$Label manifest record offset"
            Assert-FaultGateEvidenceDigest -Value $manifestRecord.terminal_record_sha256 -Label "$Label manifest record terminal digest"
            Assert-FaultGateEvidenceDigest -Value $manifestRecord.verified_prefix_sha256 -Label "$Label manifest record prefix digest"
            if ($recordIndex -ne [uint64]$manifestIndex -or $recordOffset -le $previousManifestOffset -or $recordOffset -gt $manifestVerified) {
                throw "$Label manifest verified-record boundary is invalid."
            }
            $previousManifestOffset = $recordOffset
        }
        $lastManifestRecord = $manifestVerifiedRecords[$manifestVerifiedRecords.Count - 1]
        if ([uint64]$lastManifestRecord.verified_through_offset -ne $manifestVerified -or
            [string]$lastManifestRecord.terminal_record_sha256 -cne [string]$stream.manifest_terminal_record_sha256 -or
            [string]$lastManifestRecord.verified_prefix_sha256 -cne [string]$stream.manifest_verified_prefix_sha256) {
            throw "$Label manifest terminal verified-record linkage is invalid."
        }
        $expectedPublicStream = if ($streamName -ceq "depth") { $ExpectedSymbol.ToLowerInvariant() + "@depth@100ms" } else { $ExpectedSymbol.ToLowerInvariant() + "@trade" }
        $streamEpoch = $null
        $previousLastFrame = $null
        for ($segmentPosition = 0; $segmentPosition -lt $segmentRows.Count; $segmentPosition++) {
            $summary = Test-FaultGateEvidenceSegment -Segment $segmentRows[$segmentPosition] -Label "$Label $streamName segment $segmentPosition"
            if ($summary.segment_index -ne [uint64]$segmentPosition -or
                ($segmentPosition -lt $manifestRecords -and -not $summary.sealed) -or
                ($segmentPosition -eq $manifestRecords -and $summary.sealed)) { throw "$Label $streamName sealed/tail segment ordering is invalid." }
            if ($null -ne $summary.raw) {
                $expectedFirstAfterPrevious = if ($null -ne $previousLastFrame) { Get-FaultGateUInt64Successor -Value ([uint64]$previousLastFrame) -Label "$Label $streamName raw frame continuity" } else { $null }
                if ($summary.raw.stream -cne $expectedPublicStream -or
                    $summary.raw.connection_epoch -cne [string]$transportEpochs[$streamName] -or
                    ($null -ne $streamEpoch -and $summary.raw.connection_epoch -cne $streamEpoch) -or
                    ($null -ne $previousLastFrame -and $summary.raw.first_frame_index -ne $expectedFirstAfterPrevious)) {
                    throw "$Label $streamName raw identity/frame continuity is invalid."
                }
                $streamEpoch = $summary.raw.connection_epoch
                $previousLastFrame = $summary.raw.last_frame_index
            }
        }
    }
}

function Test-FaultGateEvidenceJournalSummary {
    param([Parameter(Mandatory = $true)] $Summary, [Parameter(Mandatory = $true)] [string] $Label)
    Assert-FaultGateJsonObject -Value $Summary -Label $Label
    Assert-FaultGateExactProperties -Value $Summary -Names @("records", "terminal_record_sha256", "file_bytes", "file_sha256") -Label $Label
    $records = Get-FaultGateJsonUnsignedInteger -Value $Summary.records -Label "$Label records"
    $fileBytes = Get-FaultGateJsonUnsignedInteger -Value $Summary.file_bytes -Label "$Label file_bytes"
    Assert-FaultGateEvidenceDigest -Value $Summary.terminal_record_sha256 -Label "$Label terminal_record_sha256"
    Assert-FaultGateEvidenceDigest -Value $Summary.file_sha256 -Label "$Label file_sha256"
    if ($records -eq 0 -or $fileBytes -eq 0) { throw "$Label cannot be empty." }
}

function Test-FaultGateEvidenceCoreSchema {
    param([Parameter(Mandatory = $true)] $Body)
    Assert-FaultGateExactProperties -Value $Body.fault -Names @(
        "method", "symbol", "generation_index", "target", "requested_exit_code", "observed_exit_code", "proposed_record_sha256",
        "injection_requested_record_sha256", "injected_record_sha256", "injection_requested_wall_ns", "failure_deadline_seconds",
        "injection_requested_qpc_timestamp", "containment_observed_monotonic_tick"
    ) -Label "fault evidence fault"
    $faultMethod = Get-FaultGateJsonNonEmptyString -Value $Body.fault.method -Label "fault evidence method"
    $faultSymbol = Get-FaultGateJsonNonEmptyString -Value $Body.fault.symbol -Label "fault evidence symbol"
    $faultGeneration = Get-FaultGateJsonUnsignedInteger -Value $Body.fault.generation_index -Label "fault evidence generation_index"
    $faultRequestedExit = Get-FaultGateJsonUnsignedInteger -Value $Body.fault.requested_exit_code -Label "fault evidence requested_exit_code" -Maximum ([uint32]::MaxValue)
    $faultObservedExit = Get-FaultGateJsonUnsignedInteger -Value $Body.fault.observed_exit_code -Label "fault evidence observed_exit_code" -Maximum ([uint32]::MaxValue)
    $failureDeadlineSeconds = Get-FaultGateJsonUnsignedInteger -Value $Body.fault.failure_deadline_seconds -Label "fault evidence failure_deadline_seconds"
    $injectionRequestedWallNs = Get-FaultGateJsonUnsignedInteger -Value $Body.fault.injection_requested_wall_ns -Label "fault evidence injection_requested_wall_ns"
    $failureOriginTick = Get-FaultGateJsonUnsignedInteger -Value $Body.fault.injection_requested_qpc_timestamp -Label "fault evidence injection_requested_qpc_timestamp"
    $containmentObservedTick = Get-FaultGateJsonUnsignedInteger -Value $Body.fault.containment_observed_monotonic_tick -Label "fault evidence containment_observed_monotonic_tick"
    Assert-FaultGateJsonObject -Value $Body.fault.target -Label "fault evidence target"
    Assert-FaultGateExactProperties -Value $Body.fault.target -Names @("pid", "creation_filetime_utc", "parent_pid", "executable_sha256", "command_line_sha256") -Label "fault evidence target"
    $faultTargetPid = Get-FaultGateJsonUnsignedInteger -Value $Body.fault.target.pid -Label "fault evidence target pid" -Maximum ([uint32]::MaxValue)
    $faultTargetCreation = Get-FaultGateJsonSignedInteger -Value $Body.fault.target.creation_filetime_utc -Label "fault evidence target creation"
    $faultTargetParent = Get-FaultGateJsonUnsignedInteger -Value $Body.fault.target.parent_pid -Label "fault evidence target parent pid" -Maximum ([uint32]::MaxValue)
    Assert-FaultGateEvidenceDigest -Value $Body.fault.target.executable_sha256 -Label "fault evidence target executable digest"
    Assert-FaultGateEvidenceDigest -Value $Body.fault.target.command_line_sha256 -Label "fault evidence target command digest"
    Assert-FaultGateEvidenceDigest -Value $Body.fault.proposed_record_sha256 -Label "fault evidence proposed digest"
    Assert-FaultGateEvidenceDigest -Value $Body.fault.injection_requested_record_sha256 -Label "fault evidence injection request digest"
    Assert-FaultGateEvidenceDigest -Value $Body.fault.injected_record_sha256 -Label "fault evidence injected digest"
    if ($faultMethod -cne "TerminateProcess_RETAINED_HANDLE" -or $faultSymbol -cne "BTCUSDT" -or $faultGeneration -ne 0 -or
        $faultRequestedExit -ne $script:FaultGateTargetExitCode -or $faultObservedExit -ne $script:FaultGateTargetExitCode -or
        $faultTargetPid -eq 0 -or $faultTargetCreation -le 0 -or $faultTargetParent -eq 0 -or
        $injectionRequestedWallNs -eq 0 -or $failureDeadlineSeconds -ne 30 -or
        $failureOriginTick -eq 0 -or $containmentObservedTick -lt $failureOriginTick -or
        [decimal]($containmentObservedTick - $failureOriginTick) -gt ([decimal]$failureDeadlineSeconds * [decimal][Diagnostics.Stopwatch]::Frequency)) {
        throw "Fault evidence injection identity/deadline is invalid."
    }

    Assert-FaultGateExactProperties -Value $Body.launcher -Names @(
        "identity", "monotonic_origin_qpc_timestamp", "exit_code", "terminal_file", "terminal_bytes", "terminal_sha256", "terminal_status", "terminal_failure", "containment",
        "startup_file", "startup_bytes", "startup_sha256", "process_control_file", "process_control_bytes", "process_control_sha256",
        "campaign_bindings_file", "campaign_bindings_bytes", "campaign_bindings_sha256", "watchdog_ready_sha256",
        "launcher_journal", "guardian_journal", "telemetry_journal", "stdout_file", "stdout_bytes", "stdout_sha256", "stderr_file", "stderr_bytes", "stderr_sha256"
    ) -Label "fault evidence launcher"
    Assert-FaultGateJsonObject -Value $Body.launcher.identity -Label "fault evidence launcher identity"
    Assert-FaultGateExactProperties -Value $Body.launcher.identity -Names @("pid", "creation_filetime_utc", "executable_sha256", "command_line_sha256") -Label "fault evidence launcher identity"
    $launcherPid = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.identity.pid -Label "fault evidence launcher pid" -Maximum ([uint32]::MaxValue)
    $launcherCreation = Get-FaultGateJsonSignedInteger -Value $Body.launcher.identity.creation_filetime_utc -Label "fault evidence launcher creation"
    Assert-FaultGateEvidenceDigest -Value $Body.launcher.identity.executable_sha256 -Label "fault evidence launcher executable digest"
    Assert-FaultGateEvidenceDigest -Value $Body.launcher.identity.command_line_sha256 -Label "fault evidence launcher command digest"
    $launcherMonotonicOrigin = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.monotonic_origin_qpc_timestamp -Label "fault evidence launcher monotonic origin"
    $launcherExit = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.exit_code -Label "fault evidence launcher exit" -Maximum ([uint32]::MaxValue)
    $terminalFile = Get-FaultGateJsonNonEmptyString -Value $Body.launcher.terminal_file -Label "fault evidence terminal file"
    $terminalBytes = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.terminal_bytes -Label "fault evidence terminal bytes"
    Assert-FaultGateEvidenceDigest -Value $Body.launcher.terminal_sha256 -Label "fault evidence terminal digest"
    $terminalStatus = Get-FaultGateJsonNonEmptyString -Value $Body.launcher.terminal_status -Label "fault evidence terminal status"
    $terminalFailure = Get-FaultGateJsonNonEmptyString -Value $Body.launcher.terminal_failure -Label "fault evidence terminal failure"
    foreach ($controlFile in @("startup_file", "process_control_file", "campaign_bindings_file")) { $null = Get-FaultGateJsonNonEmptyString -Value $Body.launcher.$controlFile -Label "fault evidence launcher $controlFile" }
    foreach ($controlBytes in @("startup_bytes", "process_control_bytes", "campaign_bindings_bytes")) {
        if ((Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.$controlBytes -Label "fault evidence launcher $controlBytes") -eq 0) { throw "Fault evidence launcher control artifact is empty: $controlBytes" }
    }
    foreach ($controlDigest in @("startup_sha256", "process_control_sha256", "campaign_bindings_sha256", "watchdog_ready_sha256")) { Assert-FaultGateEvidenceDigest -Value $Body.launcher.$controlDigest -Label "fault evidence launcher $controlDigest" }
    $allowedTerminalFailures = @(
        "BTCUSDT campaign heartbeat reported failure.",
        "BTCUSDT campaign heartbeat regressed or has no active generation.",
        "BTCUSDT raw_campaign exited with code 2."
    )
    $provisionalCampaignRows = @($Body.campaign_journals)
    $provisionalBtcCampaignRows = @($provisionalCampaignRows | Where-Object { [string]$_.symbol -ceq "BTCUSDT" })
    if ($provisionalCampaignRows.Count -ne 2 -or $provisionalBtcCampaignRows.Count -ne 1) {
        throw "Fault evidence cannot derive one exact BTC coordinator stderr contract."
    }
    $expectedInjectedCoordinatorStderr = Get-FaultGateExpectedInjectedCoordinatorStderr `
        -CampaignDirectory ([string]$provisionalBtcCampaignRows[0].campaign_directory)
    $coordinatorStderrTerminalClass = $terminalFailure -ceq [string]$expectedInjectedCoordinatorStderr.terminal_failure
    $managedCoordinatorFailureTerminalClass = $terminalFailure -cmatch '^BTCUSDT campaign failed: generation 0 exited without COMPLETE terminal evidence \[journal [0-9a-f]{64}\]$'
    $allowedTerminalFailures += [string]$expectedInjectedCoordinatorStderr.terminal_failure
    if (-not $managedCoordinatorFailureTerminalClass -and $terminalFailure -cnotin $allowedTerminalFailures) {
        throw "Fault evidence launcher terminal failure is outside the exact allowlist."
    }
    Assert-FaultGateJsonObject -Value $Body.launcher.containment -Label "fault evidence launcher containment"
    Assert-FaultGateExactProperties -Value $Body.launcher.containment -Names @(
        "schema", "job_name", "job_kill_on_close", "detected_wall_ns", "detected_monotonic_tick", "requested_exit_code",
        "initial_query_succeeded", "initial_active_processes", "initial_query_error", "terminate_attempted", "terminate_succeeded",
        "terminate_error", "termination_monotonic_tick", "monotonic_frequency", "drain_deadline_s", "drain_elapsed_qpc_ticks", "final_query_succeeded",
        "final_active_processes", "final_query_error", "result", "sha256"
    ) -Label "fault evidence launcher containment"
    $launcherContainmentSchema = Get-FaultGateJsonNonEmptyString -Value $Body.launcher.containment.schema -Label "fault evidence launcher containment schema"
    $launcherContainmentJobName = Get-FaultGateJsonNonEmptyString -Value $Body.launcher.containment.job_name -Label "fault evidence launcher containment job"
    $launcherContainmentKillOnClose = Get-FaultGateJsonBoolean -Value $Body.launcher.containment.job_kill_on_close -Label "fault evidence launcher containment kill-on-close"
    $launcherContainmentDetectedWall = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.detected_wall_ns -Label "fault evidence launcher containment detected wall"
    $launcherContainmentDetectedTick = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.detected_monotonic_tick -Label "fault evidence launcher containment detected tick"
    Assert-FaultGateEvidenceDigest -Value $Body.launcher.containment.sha256 -Label "fault evidence launcher containment digest"
    $launcherContainmentRequestedExit = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.requested_exit_code -Label "fault evidence launcher containment requested exit" -Maximum ([uint32]::MaxValue)
    $launcherContainmentInitialQuery = Get-FaultGateJsonBoolean -Value $Body.launcher.containment.initial_query_succeeded -Label "fault evidence launcher containment initial query"
    $launcherContainmentInitialActive = $null
    if ($launcherContainmentInitialQuery) {
        $launcherContainmentInitialActive = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.initial_active_processes -Label "fault evidence launcher containment initial active" -Maximum ([uint32]::MaxValue)
        if ($null -ne $Body.launcher.containment.initial_query_error) { throw "Successful initial containment query must publish a null error." }
    }
    else {
        if ($null -ne $Body.launcher.containment.initial_active_processes) { throw "Failed initial containment query must publish a null active-process count." }
        $initialQueryError = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.initial_query_error -Label "fault evidence launcher containment initial error" -Maximum ([uint32]::MaxValue)
        if ($initialQueryError -eq 0) { throw "Failed initial containment query must publish a non-zero Win32 error." }
    }
    $launcherContainmentAttempted = Get-FaultGateJsonBoolean -Value $Body.launcher.containment.terminate_attempted -Label "fault evidence launcher containment attempted"
    $launcherContainmentSucceeded = Get-FaultGateJsonBoolean -Value $Body.launcher.containment.terminate_succeeded -Label "fault evidence launcher containment succeeded"
    if ($null -ne $Body.launcher.containment.terminate_error) { $null = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.terminate_error -Label "fault evidence launcher containment terminate error" -Maximum ([uint32]::MaxValue) }
    $launcherContainmentTerminationTick = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.termination_monotonic_tick -Label "fault evidence launcher containment termination tick"
    $launcherContainmentFrequency = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.monotonic_frequency -Label "fault evidence launcher containment monotonic frequency"
    $launcherContainmentDetectedAbsoluteTick = Add-FaultGateCheckedQpcTicks -Origin $launcherMonotonicOrigin -Relative $launcherContainmentDetectedTick -Label "fault evidence containment detected"
    $launcherContainmentTerminationAbsoluteTick = Add-FaultGateCheckedQpcTicks -Origin $launcherMonotonicOrigin -Relative $launcherContainmentTerminationTick -Label "fault evidence containment termination"
    $launcherContainmentDrainDeadline = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.drain_deadline_s -Label "fault evidence launcher containment drain deadline"
    $launcherContainmentDrainElapsed = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.drain_elapsed_qpc_ticks -Label "fault evidence launcher containment drain elapsed"
    $launcherContainmentFinalQuery = Get-FaultGateJsonBoolean -Value $Body.launcher.containment.final_query_succeeded -Label "fault evidence launcher containment final query"
    $launcherContainmentActive = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.final_active_processes -Label "fault evidence launcher containment active" -Maximum ([uint32]::MaxValue)
    if ($null -ne $Body.launcher.containment.final_query_error) { $null = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.containment.final_query_error -Label "fault evidence launcher containment final error" -Maximum ([uint32]::MaxValue) }
    $launcherContainmentResult = Get-FaultGateJsonNonEmptyString -Value $Body.launcher.containment.result -Label "fault evidence launcher containment result"
    $launcherContainmentHashBody = [ordered]@{}
    foreach ($containmentProperty in @(
        "schema", "job_name", "job_kill_on_close", "detected_wall_ns", "detected_monotonic_tick", "requested_exit_code",
        "initial_query_succeeded", "initial_active_processes", "initial_query_error", "terminate_attempted", "terminate_succeeded",
        "terminate_error", "termination_monotonic_tick", "monotonic_frequency", "drain_deadline_s", "drain_elapsed_qpc_ticks", "final_query_succeeded",
        "final_active_processes", "final_query_error", "result"
    )) { $launcherContainmentHashBody[$containmentProperty] = $Body.launcher.containment.$containmentProperty }
    $launcherContainmentRecomputedSha = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $launcherContainmentHashBody)
    foreach ($journalName in @("launcher_journal", "guardian_journal", "telemetry_journal")) { Test-FaultGateEvidenceJournalSummary -Summary $Body.launcher.$journalName -Label "fault evidence $journalName" }
    $launcherStdoutFile = Get-FaultGateJsonNonEmptyString -Value $Body.launcher.stdout_file -Label "fault evidence launcher stdout file"
    $launcherStdoutBytes = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.stdout_bytes -Label "fault evidence launcher stdout bytes"
    $launcherStderrFile = Get-FaultGateJsonNonEmptyString -Value $Body.launcher.stderr_file -Label "fault evidence launcher stderr file"
    $launcherStderrBytes = Get-FaultGateJsonUnsignedInteger -Value $Body.launcher.stderr_bytes -Label "fault evidence launcher stderr bytes"
    Assert-FaultGateEvidenceDigest -Value $Body.launcher.stdout_sha256 -Label "fault evidence launcher stdout digest"
    Assert-FaultGateEvidenceDigest -Value $Body.launcher.stderr_sha256 -Label "fault evidence launcher stderr digest"
    if ($launcherPid -eq 0 -or $launcherCreation -le 0 -or $launcherExit -eq 0 -or $terminalFile -cne "launcher-terminal.json" -or $terminalBytes -eq 0 -or $terminalStatus -cne "FAILED" -or
        [string]$Body.launcher.startup_file -cne "launcher-startup.json" -or [string]$Body.launcher.process_control_file -cne "processes.json" -or
        [string]$Body.launcher.campaign_bindings_file -cne "campaign-bindings.json" -or
        $launcherStdoutFile -cne "launcher.stdout.log" -or $launcherStderrFile -cne "launcher.stderr.log" -or $launcherStdoutBytes -gt 16777216 -or $launcherStderrBytes -gt 16777216 -or
        $launcherContainmentSchema -cne "RawQualificationFailureContainmentV2" -or $launcherContainmentRequestedExit -ne $script:FaultGateContainmentExitCode -or
        -not $launcherContainmentKillOnClose -or $launcherContainmentDetectedWall -eq 0 -or
        $launcherMonotonicOrigin -eq 0 -or $launcherContainmentDetectedAbsoluteTick -lt $failureOriginTick -or
        $launcherContainmentTerminationTick -lt $launcherContainmentDetectedTick -or
        $launcherContainmentTerminationAbsoluteTick -gt $containmentObservedTick -or
        $launcherContainmentFrequency -ne [uint64][Diagnostics.Stopwatch]::Frequency -or
        $launcherContainmentDrainDeadline -ne 30 -or
        [decimal]$launcherContainmentDrainElapsed -gt ([decimal]$launcherContainmentDrainDeadline * [decimal]$launcherContainmentFrequency) -or
        -not $launcherContainmentInitialQuery -or $null -eq $launcherContainmentInitialActive -or $launcherContainmentInitialActive -eq 0 -or
        -not $launcherContainmentAttempted -or -not $launcherContainmentSucceeded -or -not $launcherContainmentFinalQuery -or $launcherContainmentActive -ne 0 -or
        (-not $managedCoordinatorFailureTerminalClass -and $terminalFailure -cnotin $allowedTerminalFailures) -or
        $launcherContainmentResult -cne "DRAINED_BY_ATTEMPT" -or
        $null -ne $Body.launcher.containment.initial_query_error -or $null -ne $Body.launcher.containment.terminate_error -or
        $null -ne $Body.launcher.containment.final_query_error -or
        [string]$Body.launcher.containment.sha256 -cne $launcherContainmentRecomputedSha) { throw "Fault evidence launcher terminal/containment invariant is invalid." }
    if ([string]$Body.launcher.watchdog_ready_sha256 -cne [string]$Body.live_gate.watchdog_ready.file_sha256) { throw "Fault evidence launcher/READY digest crosslink is invalid." }

    Assert-FaultGateExactProperties -Value $Body.live_gate -Names @("watchdog_ready", "monitor") -Label "fault evidence live_gate"
    Assert-FaultGateJsonObject -Value $Body.live_gate.watchdog_ready -Label "fault evidence watchdog ready"
    Assert-FaultGateExactProperties -Value $Body.live_gate.watchdog_ready -Names @("schema", "pid", "job_name", "observed_qpc_timestamp", "file_bytes", "file_sha256") -Label "fault evidence watchdog ready"
    $readySchema = Get-FaultGateJsonNonEmptyString -Value $Body.live_gate.watchdog_ready.schema -Label "fault evidence ready schema"
    $readyPid = Get-FaultGateJsonUnsignedInteger -Value $Body.live_gate.watchdog_ready.pid -Label "fault evidence ready pid" -Maximum ([uint32]::MaxValue)
    $null = Get-FaultGateJsonNonEmptyString -Value $Body.live_gate.watchdog_ready.job_name -Label "fault evidence ready job"
    $readyQpc = Get-FaultGateJsonUnsignedInteger -Value $Body.live_gate.watchdog_ready.observed_qpc_timestamp -Label "fault evidence ready qpc"
    $readyBytes = Get-FaultGateJsonUnsignedInteger -Value $Body.live_gate.watchdog_ready.file_bytes -Label "fault evidence ready bytes"
    Assert-FaultGateEvidenceDigest -Value $Body.live_gate.watchdog_ready.file_sha256 -Label "fault evidence ready file digest"
    Assert-FaultGateJsonObject -Value $Body.live_gate.monitor -Label "fault evidence monitor"
    Assert-FaultGateExactProperties -Value $Body.live_gate.monitor -Names @(
        "attempt", "pid", "exact_command_line", "command_line_sha256", "creation_filetime_utc", "executable_path", "executable_sha256",
        "exit_code", "stdout_file", "stdout_bytes", "stdout_sha256", "stderr_file", "stderr_bytes", "stderr_sha256",
        "report_sha256", "report_schema", "report_status", "report_stage", "report_run_root", "report_host_telemetry_records"
    ) -Label "fault evidence monitor"
    $monitorAttempt = Get-FaultGateJsonUnsignedInteger -Value $Body.live_gate.monitor.attempt -Label "fault evidence monitor attempt"
    $monitorPid = Get-FaultGateJsonUnsignedInteger -Value $Body.live_gate.monitor.pid -Label "fault evidence monitor pid" -Maximum ([uint32]::MaxValue)
    $null = Get-FaultGateJsonNonEmptyString -Value $Body.live_gate.monitor.exact_command_line -Label "fault evidence monitor command"
    Assert-FaultGateEvidenceDigest -Value $Body.live_gate.monitor.command_line_sha256 -Label "fault evidence monitor command digest"
    $monitorCreation = Get-FaultGateJsonSignedInteger -Value $Body.live_gate.monitor.creation_filetime_utc -Label "fault evidence monitor creation"
    $monitorExecutablePath = Get-FaultGateJsonNonEmptyString -Value $Body.live_gate.monitor.executable_path -Label "fault evidence monitor executable path"
    Assert-FaultGateEvidenceDigest -Value $Body.live_gate.monitor.executable_sha256 -Label "fault evidence monitor executable digest"
    $monitorExit = Get-FaultGateJsonUnsignedInteger -Value $Body.live_gate.monitor.exit_code -Label "fault evidence monitor exit" -Maximum ([uint32]::MaxValue)
    $monitorStdoutBytes = Get-FaultGateJsonUnsignedInteger -Value $Body.live_gate.monitor.stdout_bytes -Label "fault evidence monitor stdout bytes"
    $monitorStderrBytes = Get-FaultGateJsonUnsignedInteger -Value $Body.live_gate.monitor.stderr_bytes -Label "fault evidence monitor stderr bytes"
    foreach ($monitorString in @("stdout_file", "stderr_file", "report_schema", "report_status", "report_stage", "report_run_root")) { $null = Get-FaultGateJsonNonEmptyString -Value $Body.live_gate.monitor.$monitorString -Label "fault evidence monitor $monitorString" }
    foreach ($monitorDigest in @("stdout_sha256", "stderr_sha256", "report_sha256")) { Assert-FaultGateEvidenceDigest -Value $Body.live_gate.monitor.$monitorDigest -Label "fault evidence monitor $monitorDigest" }
    $monitorTelemetryRecords = Get-FaultGateJsonUnsignedInteger -Value $Body.live_gate.monitor.report_host_telemetry_records -Label "fault evidence monitor telemetry records"
    $expectedMonitorStdout = "monitor-{0:D3}.stdout.json" -f $monitorAttempt
    $expectedMonitorStderr = "monitor-{0:D3}.stderr.log" -f $monitorAttempt
    $directBindingsForMonitor = @($Body.harness.direct_artifacts_retained_and_rehashed.bindings_at_start)
    $monitorPowerShellBinding = @($directBindingsForMonitor | Where-Object { [string]$_.role -ceq "powershell" })
    $monitorScriptBinding = @($directBindingsForMonitor | Where-Object { [string]$_.role -ceq "monitor" })
    if ($monitorPowerShellBinding.Count -ne 1 -or $monitorScriptBinding.Count -ne 1) { throw "Fault evidence lacks unique retained PowerShell/monitor bindings." }
    $expectedMonitorCommand = [RawQualificationNative]::BuildExactCommandLine(
        [string]$monitorPowerShellBinding[0].path,
        [string[]]@("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", [string]$monitorScriptBinding[0].path, "-RunRoot", [string]$Body.run_root)
    )
    $expectedMonitorCommandDigest = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($expectedMonitorCommand))
    if ($readySchema -cne "RawQualificationWatchdogReadyV1" -or $readyPid -eq 0 -or $readyQpc -eq 0 -or $readyBytes -eq 0 -or
        $monitorAttempt -eq 0 -or $monitorPid -eq 0 -or $monitorCreation -le 0 -or $monitorTelemetryRecords -eq 0 -or $monitorExit -ne 0 -or
        [string]$Body.live_gate.monitor.stdout_file -cne $expectedMonitorStdout -or [string]$Body.live_gate.monitor.stderr_file -cne $expectedMonitorStderr -or
        $monitorStdoutBytes -eq 0 -or $monitorStdoutBytes -gt 16777216 -or $monitorStderrBytes -ne 0 -or
        [string]$Body.live_gate.monitor.stdout_sha256 -cne [string]$Body.live_gate.monitor.report_sha256 -or
        [string]$Body.live_gate.monitor.exact_command_line -cne $expectedMonitorCommand -or
        [string]$Body.live_gate.monitor.command_line_sha256 -cne $expectedMonitorCommandDigest -or
        [string]$Body.live_gate.monitor.report_schema -cne "RawQualificationReadOnlyMonitorV1" -or
        [string]$Body.live_gate.monitor.report_status -cne "HEALTHY_RUNNING" -or [string]$Body.live_gate.monitor.report_stage -cne "CAPTURING" -or
        [string]$Body.live_gate.monitor.report_run_root -cne [string]$Body.run_root) { throw "Fault evidence live gate is not healthy/capturing or RunRoot-bound." }

    Assert-FaultGateJsonArray -Value $Body.retained_process_identities -Label "fault evidence retained process identities"
    $identityRows = @($Body.retained_process_identities)
    $expectedIdentityRoles = @("launcher", "BTCUSDT_coordinator", "BTCUSDT_generation_0", "ETHUSDT_coordinator", "ETHUSDT_generation_0", "watchdog")
    if ($identityRows.Count -ne $expectedIdentityRoles.Count) { throw "Fault evidence retained process identity set is incomplete or duplicated." }
    $seenIdentityPids = @{}
    for ($identityIndex = 0; $identityIndex -lt $identityRows.Count; $identityIndex++) {
        $identityRow = $identityRows[$identityIndex]
        Assert-FaultGateJsonObject -Value $identityRow -Label "fault evidence retained process identity row"
        Assert-FaultGateExactProperties -Value $identityRow -Names @("pid", "role", "parent_pid", "creation_filetime_utc", "executable_path", "executable_sha256", "command_line_sha256") -Label "fault evidence retained process identity row"
        $identityPid = Get-FaultGateJsonUnsignedInteger -Value $identityRow.pid -Label "fault evidence retained identity pid" -Maximum ([uint32]::MaxValue)
        $identityRole = Get-FaultGateJsonNonEmptyString -Value $identityRow.role -Label "fault evidence retained identity role"
        $identityParentPid = Get-FaultGateJsonUnsignedInteger -Value $identityRow.parent_pid -Label "fault evidence retained identity parent pid" -Maximum ([uint32]::MaxValue)
        $identityCreation = Get-FaultGateJsonSignedInteger -Value $identityRow.creation_filetime_utc -Label "fault evidence retained identity creation"
        $null = Get-FaultGateJsonNonEmptyString -Value $identityRow.executable_path -Label "fault evidence retained identity executable path"
        Assert-FaultGateEvidenceDigest -Value $identityRow.executable_sha256 -Label "fault evidence retained identity executable digest"
        Assert-FaultGateEvidenceDigest -Value $identityRow.command_line_sha256 -Label "fault evidence retained identity command digest"
        if ($identityPid -eq 0 -or $identityParentPid -eq 0 -or $identityCreation -le 0 -or $identityRole -cne $expectedIdentityRoles[$identityIndex] -or $seenIdentityPids.ContainsKey([string]$identityPid)) {
            throw "Fault evidence retained process identity order/uniqueness is invalid."
        }
        $seenIdentityPids[[string]$identityPid] = $true
    }
    if ([uint64]$identityRows[1].parent_pid -ne [uint64]$identityRows[0].pid -or
        [uint64]$identityRows[2].parent_pid -ne [uint64]$identityRows[1].pid -or
        [uint64]$identityRows[3].parent_pid -ne [uint64]$identityRows[0].pid -or
        [uint64]$identityRows[4].parent_pid -ne [uint64]$identityRows[3].pid -or
        [uint64]$identityRows[5].parent_pid -ne [uint64]$identityRows[0].pid -or
        [uint64]$identityRows[0].parent_pid -ne [uint64]$Body.harness.process_identity.pid) {
        throw "Fault evidence retained process parent graph is invalid."
    }

    Assert-FaultGateExactProperties -Value $Body.containment -Names @(
        "inner_job_name", "inner_job_exists", "inner_job_open_error", "workload_job_name", "workload_job_exists", "workload_job_open_error",
        "outer_job_name", "outer_job_kill_on_close", "outer_active_processes",
        "btc_coordinator_exit_code", "eth_capture_exit_code", "eth_coordinator_exit_code", "watchdog_exit_code", "retained_identity_absence", "global_engine_processes",
        "run_bound_processes", "verifier_processes"
    ) -Label "fault evidence containment"
    $innerJobName = Get-FaultGateJsonNonEmptyString -Value $Body.containment.inner_job_name -Label "fault evidence inner job"
    $innerExists = Get-FaultGateJsonBoolean -Value $Body.containment.inner_job_exists -Label "fault evidence inner job exists"
    $innerError = Get-FaultGateJsonSignedInteger -Value $Body.containment.inner_job_open_error -Label "fault evidence inner job error"
    $workloadJobName = Get-FaultGateJsonNonEmptyString -Value $Body.containment.workload_job_name -Label "fault evidence workload job"
    $workloadExists = Get-FaultGateJsonBoolean -Value $Body.containment.workload_job_exists -Label "fault evidence workload job exists"
    $workloadError = Get-FaultGateJsonSignedInteger -Value $Body.containment.workload_job_open_error -Label "fault evidence workload job error"
    $outerJobName = Get-FaultGateJsonNonEmptyString -Value $Body.containment.outer_job_name -Label "fault evidence outer job"
    $outerKill = Get-FaultGateJsonBoolean -Value $Body.containment.outer_job_kill_on_close -Label "fault evidence outer kill-on-close"
    $containedExitCodes = [Collections.Generic.List[uint64]]::new()
    foreach ($exitName in @("btc_coordinator_exit_code", "eth_capture_exit_code", "eth_coordinator_exit_code", "watchdog_exit_code")) {
        $exitCode = Get-FaultGateJsonUnsignedInteger -Value $Body.containment.$exitName -Label "fault evidence $exitName" -Maximum ([uint32]::MaxValue)
        if ($exitCode -in @([uint64]0, [uint64]259)) { throw "Fault evidence $exitName is not an abnormal contained exit." }
        $containedExitCodes.Add($exitCode)
    }
    if ($launcherContainmentResult -ceq "DRAINED_BY_ATTEMPT" -and
        @($containedExitCodes | Select-Object -Skip 1 | Where-Object { $_ -ne [uint64]$script:FaultGateContainmentExitCode }).Count -ne 0) {
        throw "Fault evidence DRAINED_BY_ATTEMPT ETH/watchdog peer exits differ from the Job termination code."
    }
    if ($innerJobName -cne ("Local\BinanceRawQualificationJob-" + [string]$Body.run_id) -or
        $workloadJobName -cne ("Local\BinanceRawQualificationWorkloadJob-" + [string]$Body.run_id) -or
        $innerJobName -ceq $workloadJobName -or
        $launcherContainmentJobName -cne $innerJobName -or
        $outerJobName -cne ("Local\BinanceRawFaultGateOuter-" + [string]$Body.gate_id)) {
        throw "Fault evidence Job names are not deterministically bound to run_id/gate_id."
    }
    if (($terminalFailure -ceq "BTCUSDT raw_campaign exited with code 2." -or $coordinatorStderrTerminalClass -or $managedCoordinatorFailureTerminalClass) -and
        [uint64]$Body.containment.btc_coordinator_exit_code -ne 2) {
        throw "Fault evidence coordinator-exit failure class is not bound to coordinator exit code 2."
    }
    Assert-FaultGateJsonArray -Value $Body.containment.retained_identity_absence -Label "fault evidence retained identity absence"
    $absenceRows = @($Body.containment.retained_identity_absence)
    $expectedAbsenceRoles = @("launcher", "BTCUSDT_coordinator", "BTCUSDT_generation_0", "ETHUSDT_coordinator", "ETHUSDT_generation_0", "watchdog")
    if ($absenceRows.Count -ne $expectedAbsenceRoles.Count) { throw "Fault evidence retained identity absence set is incomplete or duplicated." }
    $seenAbsencePids = @{}
    for ($absenceIndex = 0; $absenceIndex -lt $absenceRows.Count; $absenceIndex++) {
        $absence = $absenceRows[$absenceIndex]
        Assert-FaultGateJsonObject -Value $absence -Label "fault evidence retained identity absence row"
        Assert-FaultGateExactProperties -Value $absence -Names @("pid", "role", "creation_filetime_utc", "executable_path", "executable_sha256", "command_line_sha256", "absent", "pid_reused") -Label "fault evidence retained identity absence row"
        $absencePid = Get-FaultGateJsonUnsignedInteger -Value $absence.pid -Label "fault evidence absent pid" -Maximum ([uint32]::MaxValue)
        $absenceRole = Get-FaultGateJsonNonEmptyString -Value $absence.role -Label "fault evidence absent role"
        $absenceCreation = Get-FaultGateJsonSignedInteger -Value $absence.creation_filetime_utc -Label "fault evidence absent creation"
        $null = Get-FaultGateJsonNonEmptyString -Value $absence.executable_path -Label "fault evidence absent executable path"
        Assert-FaultGateEvidenceDigest -Value $absence.executable_sha256 -Label "fault evidence absent executable digest"
        Assert-FaultGateEvidenceDigest -Value $absence.command_line_sha256 -Label "fault evidence absent command digest"
        $absent = Get-FaultGateJsonBoolean -Value $absence.absent -Label "fault evidence absent flag"
        $pidReused = Get-FaultGateJsonBoolean -Value $absence.pid_reused -Label "fault evidence pid reused flag"
        $identityRow = $identityRows[$absenceIndex]
        if ($absenceRole -cne $expectedAbsenceRoles[$absenceIndex] -or $absencePid -eq 0 -or $absenceCreation -le 0 -or -not $absent -or $pidReused -or $seenAbsencePids.ContainsKey([string]$absencePid) -or
            $absencePid -ne [uint64]$identityRow.pid -or
            [int64]$absence.creation_filetime_utc -ne [int64]$identityRow.creation_filetime_utc -or
            [string]$absence.executable_path -cne [string]$identityRow.executable_path -or
            [string]$absence.executable_sha256 -cne [string]$identityRow.executable_sha256 -or
            [string]$absence.command_line_sha256 -cne [string]$identityRow.command_line_sha256) {
            throw "Fault evidence retained identity order/uniqueness/absence or start/terminal linkage is invalid."
        }
        $seenAbsencePids[[string]$absencePid] = $true
    }
    if ([uint64]$identityRows[0].pid -ne [uint64]$Body.launcher.identity.pid -or
        [int64]$identityRows[0].creation_filetime_utc -ne [int64]$Body.launcher.identity.creation_filetime_utc -or
        [string]$identityRows[0].executable_sha256 -cne [string]$Body.launcher.identity.executable_sha256 -or
        [string]$identityRows[0].command_line_sha256 -cne [string]$Body.launcher.identity.command_line_sha256 -or
        [uint64]$identityRows[2].pid -ne [uint64]$Body.fault.target.pid -or
        [int64]$identityRows[2].creation_filetime_utc -ne [int64]$Body.fault.target.creation_filetime_utc -or
        [uint64]$identityRows[2].parent_pid -ne [uint64]$Body.fault.target.parent_pid -or
        [string]$identityRows[2].executable_sha256 -cne [string]$Body.fault.target.executable_sha256 -or
        [string]$identityRows[2].command_line_sha256 -cne [string]$Body.fault.target.command_line_sha256 -or
        [uint64]$Body.fault.target.parent_pid -ne [uint64]$identityRows[1].pid -or
        [uint64]$Body.live_gate.watchdog_ready.pid -ne [uint64]$identityRows[5].pid -or
        [string]$Body.live_gate.watchdog_ready.job_name -cne $innerJobName) {
        throw "Fault evidence retained identities are not linked to launcher, target parent, watchdog READY, and inner Job."
    }
    if ($innerExists -or $innerError -ne 2 -or $workloadExists -or $workloadError -ne 2 -or -not $outerKill) { throw "Fault evidence Job containment invariant is invalid." }

    Assert-FaultGateExactProperties -Value $Body.promotion -Names @("launcher_complete", "campaign_or_generation_manifest_count", "independent_verification") -Label "fault evidence promotion"
    $manifestCount = Get-FaultGateJsonUnsignedInteger -Value $Body.promotion.campaign_or_generation_manifest_count -Label "fault evidence manifest count"
    if ($manifestCount -ne 0) { throw "Fault evidence contains a forbidden promoted manifest." }

    Assert-FaultGateJsonObject -Value $Body.campaign_prefixes -Label "fault evidence campaign prefixes"
    Assert-FaultGateExactProperties -Value $Body.campaign_prefixes -Names @("pre_fault_campaign_prefixes_sha256", "pre_fault_campaign_prefixes") -Label "fault evidence campaign prefixes"
    Assert-FaultGateEvidenceDigest -Value $Body.campaign_prefixes.pre_fault_campaign_prefixes_sha256 -Label "fault evidence campaign prefixes digest"
    Assert-FaultGateJsonArray -Value $Body.campaign_prefixes.pre_fault_campaign_prefixes -Label "fault evidence pre-fault campaign prefixes"
    $campaignPrefixes = @($Body.campaign_prefixes.pre_fault_campaign_prefixes)
    if ($campaignPrefixes.Count -ne 2 -or [string]$Body.campaign_prefixes.pre_fault_campaign_prefixes_sha256 -cne
        (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $campaignPrefixes))) { throw "Fault evidence pre-fault campaign prefixes cardinality/digest is invalid." }
    if (@($Body.campaign_journals).Count -ne 2) { throw "Fault evidence campaign journal cardinality is invalid." }
    $symbols = @("BTCUSDT", "ETHUSDT")
    $embeddedCampaignJournals = [Collections.Generic.List[object]]::new()
    for ($campaignIndex = 0; $campaignIndex -lt 2; $campaignIndex++) {
        $prefix = $campaignPrefixes[$campaignIndex]
        Assert-FaultGateJsonObject -Value $prefix -Label "fault evidence campaign prefix"
        Assert-FaultGateExactProperties -Value $prefix -Names @("symbol", "records", "clean_tail", "terminal_record_sha256", "file_sha256") -Label "fault evidence campaign prefix"
        $prefixSymbol = Get-FaultGateJsonNonEmptyString -Value $prefix.symbol -Label "fault evidence campaign prefix symbol"
        $prefixRecords = Get-FaultGateJsonUnsignedInteger -Value $prefix.records -Label "fault evidence campaign prefix records"
        $prefixClean = Get-FaultGateJsonBoolean -Value $prefix.clean_tail -Label "fault evidence campaign prefix clean_tail"
        Assert-FaultGateEvidenceDigest -Value $prefix.terminal_record_sha256 -Label "fault evidence campaign prefix terminal digest"
        Assert-FaultGateEvidenceDigest -Value $prefix.file_sha256 -Label "fault evidence campaign prefix file digest"
        $row = @($Body.campaign_journals)[$campaignIndex]
        Assert-FaultGateExactProperties -Value $row -Names @("symbol", "campaign_id", "campaign_directory", "campaign_startup_bytes", "campaign_startup_sha256", "campaign_started_event", "journal_bytes_base64", "records", "clean_tail", "terminal_record_sha256", "file_bytes", "file_sha256", "causality") -Label "fault evidence campaign journal"
        $symbol = Get-FaultGateJsonNonEmptyString -Value $row.symbol -Label "fault evidence campaign symbol"
        $campaignId = Get-FaultGateJsonNonEmptyString -Value $row.campaign_id -Label "fault evidence campaign id"
        $campaignDirectory = Get-FaultGateJsonNonEmptyString -Value $row.campaign_directory -Label "fault evidence campaign directory"
        $campaignStartupBytes = Get-FaultGateJsonUnsignedInteger -Value $row.campaign_startup_bytes -Label "fault evidence campaign startup bytes"
        Assert-FaultGateEvidenceDigest -Value $row.campaign_startup_sha256 -Label "fault evidence campaign startup digest"
        Assert-FaultGateJsonObject -Value $row.campaign_started_event -Label "fault evidence CAMPAIGN_STARTED envelope"
        Assert-FaultGateExactProperties -Value $row.campaign_started_event -Names @("body", "record_sha256") -Label "fault evidence CAMPAIGN_STARTED envelope"
        Assert-FaultGateJsonObject -Value $row.campaign_started_event.body -Label "fault evidence CAMPAIGN_STARTED body"
        Assert-FaultGateExactProperties -Value $row.campaign_started_event.body -Names @(
            "schema", "record_index", "wall_ns", "campaign_mono_ns", "generation_index", "channel", "payload", "previous_record_sha256"
        ) -Label "fault evidence CAMPAIGN_STARTED body"
        $campaignStartedBody = $row.campaign_started_event.body
        $campaignStartedSchema = Get-FaultGateJsonNonEmptyString -Value $campaignStartedBody.schema -Label "fault evidence CAMPAIGN_STARTED schema"
        $campaignStartedIndex = Get-FaultGateJsonUnsignedInteger -Value $campaignStartedBody.record_index -Label "fault evidence CAMPAIGN_STARTED index"
        $campaignStartedWall = Get-FaultGateJsonUnsignedInteger -Value $campaignStartedBody.wall_ns -Label "fault evidence CAMPAIGN_STARTED wall_ns"
        $null = Get-FaultGateJsonUnsignedInteger -Value $campaignStartedBody.campaign_mono_ns -Label "fault evidence CAMPAIGN_STARTED campaign_mono_ns"
        $campaignStartedChannel = Get-FaultGateJsonNonEmptyString -Value $campaignStartedBody.channel -Label "fault evidence CAMPAIGN_STARTED channel"
        Assert-FaultGateJsonObject -Value $campaignStartedBody.payload -Label "fault evidence CAMPAIGN_STARTED payload"
        Assert-FaultGateExactProperties -Value $campaignStartedBody.payload -Names @("campaign_id", "event", "startup_sha256") -Label "fault evidence CAMPAIGN_STARTED payload"
        $campaignStartedId = Get-FaultGateJsonNonEmptyString -Value $campaignStartedBody.payload.campaign_id -Label "fault evidence CAMPAIGN_STARTED campaign_id"
        $campaignStartedEvent = Get-FaultGateJsonNonEmptyString -Value $campaignStartedBody.payload.event -Label "fault evidence CAMPAIGN_STARTED event"
        Assert-FaultGateEvidenceDigest -Value $campaignStartedBody.payload.startup_sha256 -Label "fault evidence CAMPAIGN_STARTED startup digest"
        Assert-FaultGateEvidenceDigest -Value $campaignStartedBody.previous_record_sha256 -Label "fault evidence CAMPAIGN_STARTED previous digest"
        Assert-FaultGateEvidenceDigest -Value $row.campaign_started_event.record_sha256 -Label "fault evidence CAMPAIGN_STARTED record digest"
        $campaignStartedRecomputedSha = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $campaignStartedBody)
        $campaignJournalBase64 = Get-FaultGateJsonNonEmptyString -Value $row.journal_bytes_base64 -Label "fault evidence campaign journal base64"
        try { [byte[]]$campaignJournalBytes = [Convert]::FromBase64String($campaignJournalBase64) }
        catch { throw "Fault evidence campaign journal is not valid Base64." }
        if ([Convert]::ToBase64String($campaignJournalBytes) -cne $campaignJournalBase64) { throw "Fault evidence campaign journal Base64 is not canonical." }
        $embeddedCampaignJournal = Read-FaultGateEmbeddedCampaignJournal -Bytes $campaignJournalBytes -Label "fault evidence $symbol campaign journal"
        $records = Get-FaultGateJsonUnsignedInteger -Value $row.records -Label "fault evidence campaign records"
        $clean = Get-FaultGateJsonBoolean -Value $row.clean_tail -Label "fault evidence campaign clean tail"
        Assert-FaultGateEvidenceDigest -Value $row.terminal_record_sha256 -Label "fault evidence campaign terminal digest"
        $campaignFileBytes = Get-FaultGateJsonUnsignedInteger -Value $row.file_bytes -Label "fault evidence campaign file bytes"
        Assert-FaultGateEvidenceDigest -Value $row.file_sha256 -Label "fault evidence campaign file digest"
        Assert-FaultGateJsonObject -Value $row.causality -Label "fault evidence campaign causality"
        Assert-FaultGateExactProperties -Value $row.causality -Names @("symbol", "proof", "disconnects", "campaign_failures", "pre_fault_records", "pre_fault_terminal_record_sha256") -Label "fault evidence campaign causality"
        $causeSymbol = Get-FaultGateJsonNonEmptyString -Value $row.causality.symbol -Label "fault evidence causal symbol"
        $causalProof = Get-FaultGateJsonNonEmptyString -Value $row.causality.proof -Label "fault evidence causal proof"
        $causalDisconnects = Get-FaultGateJsonUnsignedInteger -Value $row.causality.disconnects -Label "fault evidence disconnects"
        $causalFailures = Get-FaultGateJsonUnsignedInteger -Value $row.causality.campaign_failures -Label "fault evidence campaign failures"
        $causalPrefixRecords = Get-FaultGateJsonUnsignedInteger -Value $row.causality.pre_fault_records -Label "fault evidence causal prefix records"
        Assert-FaultGateEvidenceDigest -Value $row.causality.pre_fault_terminal_record_sha256 -Label "fault evidence causal prefix terminal digest"
        $expectedCampaignDirectory = [IO.Path]::GetFullPath((Join-Path ([string]$Body.run_root) $campaignId))
        if ($symbol -cne $symbols[$campaignIndex] -or $causeSymbol -cne $symbol -or $prefixSymbol -cne $symbol -or
            $campaignId -cnotmatch ('^[0-9]+-' + $symbol + '-raw-[0-9a-f]{12}$') -or [IO.Path]::GetFileName($campaignId) -cne $campaignId -or
            -not [IO.Path]::GetFullPath($campaignDirectory).Equals($expectedCampaignDirectory, [StringComparison]::OrdinalIgnoreCase) -or $campaignStartupBytes -eq 0 -or
            $campaignStartedSchema -cne "RawCampaignJournalRecordV1" -or $campaignStartedIndex -ne 0 -or $campaignStartedWall -eq 0 -or
            $null -ne $campaignStartedBody.generation_index -or $campaignStartedChannel -cne "CAMPAIGN" -or
            $campaignStartedId -cne $campaignId -or $campaignStartedEvent -cne "CAMPAIGN_STARTED" -or
            [string]$campaignStartedBody.payload.startup_sha256 -cne [string]$row.campaign_startup_sha256 -or
            [string]$campaignStartedBody.previous_record_sha256 -cne $script:FaultGateZeroDigest -or
            [string]$row.campaign_started_event.record_sha256 -cne $campaignStartedRecomputedSha -or
            [uint64]$embeddedCampaignJournal.records -ne $records -or -not [bool]$embeddedCampaignJournal.clean_tail -or
            [string]$embeddedCampaignJournal.terminal_record_sha256 -cne [string]$row.terminal_record_sha256 -or
            [uint64]$embeddedCampaignJournal.file_bytes -ne $campaignFileBytes -or [string]$embeddedCampaignJournal.file_sha256 -cne [string]$row.file_sha256 -or
            [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateSerdeCompactJsonBytes -Value @($embeddedCampaignJournal.entries)[0])) -cne
                [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateSerdeCompactJsonBytes -Value $row.campaign_started_event)) -or
            $records -eq 0 -or $campaignFileBytes -eq 0 -or $records -lt $prefixRecords -or -not $clean -or -not $prefixClean -or $prefixRecords -eq 0 -or
            $causalPrefixRecords -ne $prefixRecords -or [string]$row.causality.pre_fault_terminal_record_sha256 -cne [string]$prefix.terminal_record_sha256) {
            throw "Fault evidence campaign journal/prefix identity is invalid."
        }
        if ($symbol -ceq "BTCUSDT") {
            $heartbeatRaceFailure = $terminalFailure -cin @(
                "BTCUSDT campaign heartbeat reported failure.",
                "BTCUSDT campaign heartbeat regressed or has no active generation."
            )
            if ($causalDisconnects -ne 1 -or $causalFailures -gt 1 -or
                ($causalFailures -eq 0 -and $causalProof -cne "TERMINAL_DISCONNECT_BEFORE_CAMPAIGN_FAILED") -or
                ($causalFailures -eq 1 -and $causalProof -cne "DISCONNECT_AND_CAMPAIGN_FAILED") -or
                (-not $heartbeatRaceFailure -and
                    ($causalFailures -ne 1 -or $causalProof -cne "DISCONNECT_AND_CAMPAIGN_FAILED"))) { throw "Fault evidence BTC causality proof/counts are inconsistent with launcher terminal failure class." }
        }
        elseif ($causalDisconnects -ne 0 -or $causalFailures -ne 0 -or $causalProof -cne "JOB_CONTAINED_PEER_WITHOUT_LOCAL_FAILURE") {
            throw "Fault evidence ETH peer-containment causality is inconsistent."
        }
        $embeddedCampaignJournals.Add($embeddedCampaignJournal)
    }

    Assert-FaultGateJsonObject -Value $Body.coordinator_stderr -Label "fault evidence coordinator stderr"
    Assert-FaultGateExactProperties -Value $Body.coordinator_stderr -Names @(
        "schema", "classification", "symbol", "generation_index", "coordinator_pid", "coordinator_exit_code",
        "campaign_id", "campaign_directory", "campaign_failure_record_sha256", "file", "bytes", "sha256",
        "peer_symbol", "peer_coordinator_pid", "peer_file", "peer_bytes", "peer_sha256"
    ) -Label "fault evidence coordinator stderr"
    $coordinatorStderrSchema = Get-FaultGateJsonNonEmptyString -Value $Body.coordinator_stderr.schema -Label "fault evidence coordinator stderr schema"
    $coordinatorStderrClassification = Get-FaultGateJsonNonEmptyString -Value $Body.coordinator_stderr.classification -Label "fault evidence coordinator stderr classification"
    $coordinatorStderrSymbol = Get-FaultGateJsonNonEmptyString -Value $Body.coordinator_stderr.symbol -Label "fault evidence coordinator stderr symbol"
    $coordinatorStderrGeneration = Get-FaultGateJsonUnsignedInteger -Value $Body.coordinator_stderr.generation_index -Label "fault evidence coordinator stderr generation"
    $coordinatorStderrPid = Get-FaultGateJsonUnsignedInteger -Value $Body.coordinator_stderr.coordinator_pid -Label "fault evidence coordinator stderr pid" -Maximum ([uint32]::MaxValue)
    $coordinatorStderrExit = Get-FaultGateJsonUnsignedInteger -Value $Body.coordinator_stderr.coordinator_exit_code -Label "fault evidence coordinator stderr exit" -Maximum ([uint32]::MaxValue)
    $coordinatorStderrCampaignId = Get-FaultGateJsonNonEmptyString -Value $Body.coordinator_stderr.campaign_id -Label "fault evidence coordinator stderr campaign id"
    $coordinatorStderrCampaignDirectory = Get-FaultGateJsonNonEmptyString -Value $Body.coordinator_stderr.campaign_directory -Label "fault evidence coordinator stderr campaign directory"
    $coordinatorStderrFile = Get-FaultGateJsonNonEmptyString -Value $Body.coordinator_stderr.file -Label "fault evidence coordinator stderr file"
    $coordinatorStderrBytes = Get-FaultGateJsonUnsignedInteger -Value $Body.coordinator_stderr.bytes -Label "fault evidence coordinator stderr bytes"
    Assert-FaultGateEvidenceDigest -Value $Body.coordinator_stderr.sha256 -Label "fault evidence coordinator stderr digest"
    $peerStderrSymbol = Get-FaultGateJsonNonEmptyString -Value $Body.coordinator_stderr.peer_symbol -Label "fault evidence peer stderr symbol"
    $peerStderrPid = Get-FaultGateJsonUnsignedInteger -Value $Body.coordinator_stderr.peer_coordinator_pid -Label "fault evidence peer stderr pid" -Maximum ([uint32]::MaxValue)
    $peerStderrFile = Get-FaultGateJsonNonEmptyString -Value $Body.coordinator_stderr.peer_file -Label "fault evidence peer stderr file"
    $peerStderrBytes = Get-FaultGateJsonUnsignedInteger -Value $Body.coordinator_stderr.peer_bytes -Label "fault evidence peer stderr bytes"
    Assert-FaultGateEvidenceDigest -Value $Body.coordinator_stderr.peer_sha256 -Label "fault evidence peer stderr digest"
    $btcFailureEvents = @(Get-FaultGateJournalEvents -Journal $embeddedCampaignJournals[0] -Event "CAMPAIGN_FAILED")
    $expectedCampaignFailureRecordSha256 = if ($btcFailureEvents.Count -eq 1) { [string]$btcFailureEvents[0].record_sha256 } else { $null }
    if ($managedCoordinatorFailureTerminalClass) {
        if ($btcFailureEvents.Count -ne 1) {
            throw "Managed coordinator terminal failure lacks one exact durable CAMPAIGN_FAILED record."
        }
        $expectedManagedTerminalFailure = "BTCUSDT campaign failed: " +
            [string]$btcFailureEvents[0].body.payload.error + " [journal " +
            [string]$btcFailureEvents[0].record_sha256 + "]"
        if ($terminalFailure -cne $expectedManagedTerminalFailure) {
            throw "Managed coordinator terminal failure is not bound to its exact durable CAMPAIGN_FAILED record."
        }
    }
    if ($null -ne $Body.coordinator_stderr.campaign_failure_record_sha256) {
        Assert-FaultGateEvidenceDigest -Value $Body.coordinator_stderr.campaign_failure_record_sha256 -Label "fault evidence coordinator stderr campaign failure record"
    }
    $publishedCampaignFailureRecordSha256 = if ($null -eq $Body.coordinator_stderr.campaign_failure_record_sha256) { $null } else { [string]$Body.coordinator_stderr.campaign_failure_record_sha256 }
    $coordinatorStderrIsEmpty = $coordinatorStderrBytes -eq 0
    $coordinatorStderrIsExactFailure = $coordinatorStderrBytes -ne 0
    if ($coordinatorStderrSchema -cne "RawQualificationCoordinatorStderrEvidenceV1" -or
        $coordinatorStderrSymbol -cne "BTCUSDT" -or $coordinatorStderrGeneration -ne 0 -or
        $coordinatorStderrPid -ne [uint64]$identityRows[1].pid -or $coordinatorStderrExit -ne [uint64]$Body.containment.btc_coordinator_exit_code -or
        $coordinatorStderrCampaignId -cne [string]@($Body.campaign_journals)[0].campaign_id -or
        $coordinatorStderrCampaignDirectory -cne [string]@($Body.campaign_journals)[0].campaign_directory -or
        $coordinatorStderrFile -cne "btcusdt.stderr.log" -or $coordinatorStderrBytes -gt 4096 -or
        $publishedCampaignFailureRecordSha256 -cne $expectedCampaignFailureRecordSha256 -or
        $peerStderrSymbol -cne "ETHUSDT" -or $peerStderrPid -ne [uint64]$identityRows[3].pid -or
        $peerStderrFile -cne "ethusdt.stderr.log" -or $peerStderrBytes -ne 0 -or
        [string]$Body.coordinator_stderr.peer_sha256 -cne $script:FaultGateEmptySha256) {
        throw "Fault evidence coordinator stderr receipt is not bound to exact processes, campaigns, journals, and peer-empty evidence."
    }
    if ($coordinatorStderrIsEmpty) {
        if ($coordinatorStderrClassification -cne "EMPTY" -or [string]$Body.coordinator_stderr.sha256 -cne $script:FaultGateEmptySha256 -or
            $coordinatorStderrExit -cnotin @([uint64]$script:FaultGateContainmentExitCode, [uint64]2) -or
            $coordinatorStderrTerminalClass -or
            ($coordinatorStderrExit -eq 2 -and -not ($managedCoordinatorFailureTerminalClass -or $terminalFailure -ceq "BTCUSDT raw_campaign exited with code 2."))) {
            throw "Fault evidence empty coordinator stderr contradicts its exact containment exit, terminal failure class, or digest."
        }
    }
    elseif ($coordinatorStderrClassification -cne [string]$expectedInjectedCoordinatorStderr.classification -or
        $coordinatorStderrBytes -ne [uint64]$expectedInjectedCoordinatorStderr.bytes -or
        [string]$Body.coordinator_stderr.sha256 -cne [string]$expectedInjectedCoordinatorStderr.sha256 -or
        $coordinatorStderrExit -ne 2 -or $btcFailureEvents.Count -ne 1) {
        throw "Fault evidence non-empty coordinator stderr is not the exact injected generation-0 failure receipt."
    }
    if (($coordinatorStderrTerminalClass -or $terminalFailure -ceq "BTCUSDT raw_campaign exited with code 2.") -and -not $coordinatorStderrIsExactFailure) {
        throw "Fault evidence terminal failure requires the exact causal coordinator stderr receipt."
    }

    if (@($Body.raw_durable_prefixes).Count -ne 2) { throw "Fault evidence raw durable prefix cardinality is invalid." }
    $finalGenerations = @($Body.raw_durable_prefixes)
    for ($generationIndex = 0; $generationIndex -lt 2; $generationIndex++) {
        Test-FaultGateEvidenceGeneration -Generation $finalGenerations[$generationIndex] -ExpectedSymbol $symbols[$generationIndex] -RunRoot ([string]$Body.run_root) -Label "fault evidence raw generation $generationIndex"
        if ([uint64]$finalGenerations[$generationIndex].snapshot.campaign_event.body.record_index -ge [uint64]@($Body.campaign_journals)[$generationIndex].records) {
            throw "Fault evidence snapshot journal record index lies outside its final campaign journal prefix."
        }
        foreach ($transport in @($finalGenerations[$generationIndex].transports)) {
            if ([uint64]$transport.campaign_event.body.record_index -ge [uint64]@($Body.campaign_journals)[$generationIndex].records) {
                throw "Fault evidence transport journal record index lies outside its final campaign journal prefix."
            }
        }
        $campaignRow = @($Body.campaign_journals)[$generationIndex]
        $campaignPrefix = $campaignPrefixes[$generationIndex]
        $embeddedJournal = $embeddedCampaignJournals[$generationIndex]
        $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $embeddedJournal -Records ([uint64]$campaignPrefix.records) -Symbol $symbols[$generationIndex] -FinalRawGeneration $finalGenerations[$generationIndex] -ExpectedCampaignStartupSha256 ([string]$campaignRow.campaign_startup_sha256) -Label "fault evidence $($symbols[$generationIndex]) embedded healthy prefix"
        $depthTransport = @($finalGenerations[$generationIndex].transports | Where-Object { [string]$_.stream -ceq "depth" })
        if ($depthTransport.Count -ne 1) { throw "Fault evidence embedded campaign journal lacks one exact depth transport authority." }
        $recomputedCausality = Test-FaultGateInjectedCampaignCausality -Journal $embeddedJournal -Symbol $symbols[$generationIndex] -LauncherFailure $terminalFailure -PreFaultPrefix $campaignPrefix -InjectionRequestedWallNs $injectionRequestedWallNs -ExpectedDepthEpoch ([string]$depthTransport[0].connection_epoch) -ExpectedCampaignStartupSha256 ([string]$campaignRow.campaign_startup_sha256) -FinalRawGeneration $finalGenerations[$generationIndex]
        if ([Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateCompactJsonBytes -Value $recomputedCausality)) -cne
            [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateCompactJsonBytes -Value $campaignRow.causality))) {
            throw "Fault evidence embedded campaign FSM/causality differs from its published summary."
        }
    }
    Assert-FaultGateExactProperties -Value $Body.raw_preservation -Names @("observation_scope", "completeness_claim", "pre_fault_raw_prefixes_sha256", "pre_fault_raw_prefixes", "durable_prefixes") -Label "fault evidence raw preservation"
    $rawObservationScope = Get-FaultGateJsonNonEmptyString -Value $Body.raw_preservation.observation_scope -Label "fault evidence raw observation scope"
    $rawCompletenessClaim = Get-FaultGateJsonNonEmptyString -Value $Body.raw_preservation.completeness_claim -Label "fault evidence raw completeness claim"
    if ($rawObservationScope -cne "MANIFEST_SNAPSHOT_BOUNDED_SEALED_SEGMENTS_AND_DURABLE_PREFIXES_OBSERVED_AFTER_FROZEN_PRE_FAULT_CAMPAIGN_PREFIX" -or
        $rawCompletenessClaim -cne "NO_ATOMIC_COMPLETE_STATE_CLAIM_AT_TERMINATEPROCESS_INSTANT_WITHOUT_A_COLLECTOR_BARRIER") {
        throw "Fault evidence raw preservation scope overclaims its non-quiescent observation boundary."
    }
    Assert-FaultGateEvidenceDigest -Value $Body.raw_preservation.pre_fault_raw_prefixes_sha256 -Label "fault evidence pre-fault prefix digest"
    if (@($Body.raw_preservation.pre_fault_raw_prefixes).Count -ne 2) { throw "Fault evidence pre-fault prefix cardinality is invalid." }
    $preGenerations = @($Body.raw_preservation.pre_fault_raw_prefixes)
    for ($generationIndex = 0; $generationIndex -lt 2; $generationIndex++) {
        Test-FaultGateEvidenceGeneration -Generation $preGenerations[$generationIndex] -ExpectedSymbol $symbols[$generationIndex] -RunRoot ([string]$Body.run_root) -Label "fault evidence pre-fault generation $generationIndex"
        if ([string]$preGenerations[$generationIndex].session_id -cne [string]$finalGenerations[$generationIndex].session_id -or
            [string]$preGenerations[$generationIndex].session_directory -cne [string]$finalGenerations[$generationIndex].session_directory -or
            [string]$preGenerations[$generationIndex].spec_revision -cne [string]$finalGenerations[$generationIndex].spec_revision -or
            [uint64]$preGenerations[$generationIndex].startup_bytes -ne [uint64]$finalGenerations[$generationIndex].startup_bytes -or
            [string]$preGenerations[$generationIndex].startup_sha256 -cne [string]$finalGenerations[$generationIndex].startup_sha256 -or
            [uint64]$preGenerations[$generationIndex].snapshot.bytes -ne [uint64]$finalGenerations[$generationIndex].snapshot.bytes -or
            [string]$preGenerations[$generationIndex].snapshot.file_sha256 -cne [string]$finalGenerations[$generationIndex].snapshot.file_sha256 -or
            [string]$preGenerations[$generationIndex].snapshot.terminal_record_sha256 -cne [string]$finalGenerations[$generationIndex].snapshot.terminal_record_sha256 -or
            [string]$preGenerations[$generationIndex].snapshot.http_metadata_file -cne [string]$finalGenerations[$generationIndex].snapshot.http_metadata_file -or
            [uint64]$preGenerations[$generationIndex].snapshot.http_metadata_bytes -ne [uint64]$finalGenerations[$generationIndex].snapshot.http_metadata_bytes -or
            [string]$preGenerations[$generationIndex].snapshot.http_metadata_sha256 -cne [string]$finalGenerations[$generationIndex].snapshot.http_metadata_sha256 -or
            [string]$preGenerations[$generationIndex].snapshot.campaign_event.record_sha256 -cne [string]$finalGenerations[$generationIndex].snapshot.campaign_event.record_sha256) {
            throw "Fault evidence pre/post generation identity changed across injection."
        }
        for ($transportIndex = 0; $transportIndex -lt 2; $transportIndex++) {
            $preTransport = @($preGenerations[$generationIndex].transports)[$transportIndex]
            $finalTransport = @($finalGenerations[$generationIndex].transports)[$transportIndex]
            if ([string]$preTransport.stream -cne [string]$finalTransport.stream -or
                [string]$preTransport.connection_epoch -cne [string]$finalTransport.connection_epoch -or
                [uint64]$preTransport.metadata_bytes -ne [uint64]$finalTransport.metadata_bytes -or
                [string]$preTransport.metadata_sha256 -cne [string]$finalTransport.metadata_sha256 -or
                [string]$preTransport.campaign_event.record_sha256 -cne [string]$finalTransport.campaign_event.record_sha256) {
                throw "Fault evidence pre/post transport identity changed across injection."
            }
        }
        $preTelemetry = $preGenerations[$generationIndex].telemetry
        $finalTelemetry = $finalGenerations[$generationIndex].telemetry
        if ([uint64]$preTelemetry.verified_through_offset -gt [uint64]$finalTelemetry.verified_through_offset -or
            @($preTelemetry.verified_records).Count -gt @($finalTelemetry.verified_records).Count) {
            throw "Fault evidence pre/post telemetry verified-prefix boundary is inconsistent."
        }
        for ($telemetryIndex = 0; $telemetryIndex -lt @($preTelemetry.verified_records).Count; $telemetryIndex++) {
            if ((Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($preTelemetry.verified_records)[$telemetryIndex])) -cne
                (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($finalTelemetry.verified_records)[$telemetryIndex]))) {
                throw "Fault evidence pre/post telemetry verified record prefix changed."
            }
        }
        for ($streamIndex = 0; $streamIndex -lt 2; $streamIndex++) {
            $preStream = @($preGenerations[$generationIndex].streams)[$streamIndex]
            $finalStream = @($finalGenerations[$generationIndex].streams)[$streamIndex]
            if ([string]$preStream.stream -cne [string]$finalStream.stream -or
                [uint64]$preStream.manifest_records -gt [uint64]$finalStream.manifest_records -or
                [uint64]$preStream.manifest_verified_through_offset -gt [uint64]$finalStream.manifest_verified_through_offset) {
                throw "Fault evidence pre/post BNSEG verified-prefix boundary is inconsistent."
            }
            for ($manifestIndex = 0; $manifestIndex -lt @($preStream.manifest_verified_records).Count; $manifestIndex++) {
                if ($manifestIndex -ge @($finalStream.manifest_verified_records).Count -or
                    (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($preStream.manifest_verified_records)[$manifestIndex])) -cne
                    (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($finalStream.manifest_verified_records)[$manifestIndex]))) {
                    throw "Fault evidence pre/post BNSEG verified record prefix changed."
                }
            }
        }
    }
    Assert-FaultGateJsonObject -Value $Body.raw_preservation.durable_prefixes -Label "fault evidence durable prefixes"
    Assert-FaultGateExactProperties -Value $Body.raw_preservation.durable_prefixes -Names @("durable_segments", "inventory_sha256", "inventory") -Label "fault evidence durable prefixes"
    $durableCount = Get-FaultGateJsonUnsignedInteger -Value $Body.raw_preservation.durable_prefixes.durable_segments -Label "fault evidence durable segment count"
    Assert-FaultGateEvidenceDigest -Value $Body.raw_preservation.durable_prefixes.inventory_sha256 -Label "fault evidence durable inventory digest"
    Assert-FaultGateJsonArray -Value $Body.raw_preservation.durable_prefixes.inventory -Label "fault evidence durable inventory"
    $durableInventory = @($Body.raw_preservation.durable_prefixes.inventory)
    $expectedDurableKeys = [Collections.Generic.List[string]]::new()
    foreach ($generation in $preGenerations) {
        foreach ($stream in @($generation.streams)) {
            foreach ($segment in @($stream.verified_segments)) {
                if ([bool]$segment.sealed -or ((-not [bool]$segment.sealed) -and [bool]$segment.durable_prefix)) {
                    $expectedDurableKeys.Add(([string]$generation.symbol + "|" + [string]$stream.stream + "|" + [uint64]$segment.segment_index))
                }
            }
        }
    }
    if ($durableCount -eq 0 -or $durableCount -ne [uint64]$expectedDurableKeys.Count -or $durableInventory.Count -ne $durableCount -or
        [string]$Body.raw_preservation.durable_prefixes.inventory_sha256 -cne (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $durableInventory))) {
        throw "Fault evidence durable inventory cardinality/digest is invalid."
    }
    $seenDurableKeys = @{}
    for ($durablePosition = 0; $durablePosition -lt $durableInventory.Count; $durablePosition++) {
        $durableRow = $durableInventory[$durablePosition]
        Assert-FaultGateJsonObject -Value $durableRow -Label "fault evidence durable inventory row"
        Assert-FaultGateExactProperties -Value $durableRow -Names @(
            "symbol", "stream", "segment_index", "sealed_at_observation", "raw_file", "raw_prefix_bytes", "raw_prefix_sha256", "post_rescan_raw_prefix_sha256",
            "durable_records", "terminal_record_sha256", "progress_file", "progress_prefix_bytes", "progress_prefix_sha256", "post_rescan_progress_prefix_sha256", "progress_terminal_record_sha256"
        ) -Label "fault evidence durable inventory row"
        $durableSymbol = Get-FaultGateJsonNonEmptyString -Value $durableRow.symbol -Label "fault evidence durable symbol"
        $durableStream = Get-FaultGateJsonNonEmptyString -Value $durableRow.stream -Label "fault evidence durable stream"
        $durableIndex = Get-FaultGateJsonUnsignedInteger -Value $durableRow.segment_index -Label "fault evidence durable segment index"
        $sealedAtObservation = Get-FaultGateJsonBoolean -Value $durableRow.sealed_at_observation -Label "fault evidence durable sealed_at_observation"
        $rawFile = Get-FaultGateJsonNonEmptyString -Value $durableRow.raw_file -Label "fault evidence durable raw_file"
        $progressFile = Get-FaultGateJsonNonEmptyString -Value $durableRow.progress_file -Label "fault evidence durable progress_file"
        $rawPrefixBytes = Get-FaultGateJsonUnsignedInteger -Value $durableRow.raw_prefix_bytes -Label "fault evidence durable raw_prefix_bytes"
        $progressPrefixBytes = Get-FaultGateJsonUnsignedInteger -Value $durableRow.progress_prefix_bytes -Label "fault evidence durable progress_prefix_bytes"
        $durableRecords = Get-FaultGateJsonUnsignedInteger -Value $durableRow.durable_records -Label "fault evidence durable records"
        foreach ($digestName in @("raw_prefix_sha256", "post_rescan_raw_prefix_sha256", "terminal_record_sha256", "progress_prefix_sha256", "post_rescan_progress_prefix_sha256", "progress_terminal_record_sha256")) {
            Assert-FaultGateEvidenceDigest -Value $durableRow.$digestName -Label "fault evidence durable $digestName"
        }
        $durableKey = $durableSymbol + "|" + $durableStream + "|" + $durableIndex
        if ($seenDurableKeys.ContainsKey($durableKey) -or $durableKey -cne $expectedDurableKeys[$durablePosition]) { throw "Fault evidence durable inventory identity/order is invalid." }
        $seenDurableKeys[$durableKey] = $true
        $symbolIndex = [Array]::IndexOf($symbols, $durableSymbol)
        if ($symbolIndex -lt 0) { throw "Fault evidence durable inventory has an unknown symbol." }
        $preStream = @($preGenerations[$symbolIndex].streams | Where-Object { [string]$_.stream -ceq $durableStream })
        $finalStream = @($finalGenerations[$symbolIndex].streams | Where-Object { [string]$_.stream -ceq $durableStream })
        if ($preStream.Count -ne 1 -or $finalStream.Count -ne 1) { throw "Fault evidence durable inventory stream is absent/ambiguous." }
        $preSegment = @($preStream[0].verified_segments | Where-Object { [uint64]$_.segment_index -eq $durableIndex })
        $finalSegment = @($finalStream[0].verified_segments | Where-Object { [uint64]$_.segment_index -eq $durableIndex })
        if ($preSegment.Count -ne 1 -or $finalSegment.Count -ne 1 -or
            -not ([bool]$preSegment[0].sealed -or ((-not [bool]$preSegment[0].sealed) -and [bool]$preSegment[0].durable_prefix)) -or
            -not ([bool]$finalSegment[0].sealed -or ((-not [bool]$finalSegment[0].sealed) -and [bool]$finalSegment[0].durable_prefix)) -or
            $sealedAtObservation -ne [bool]$preSegment[0].sealed -or
            $rawFile -cne ("segment-{0:D6}.bnraw" -f $durableIndex) -or $progressFile -cne ("segment-{0:D6}.bnack" -f $durableIndex) -or
            $rawFile -cne [string]$preSegment[0].raw.raw_file -or $rawFile -cne [string]$preSegment[0].progress.raw_file -or
            $rawPrefixBytes -ne [uint64]$preSegment[0].raw.durable_through_offset -or $progressPrefixBytes -ne [uint64]$preSegment[0].progress.verified_through_offset -or
            $durableRecords -ne [uint64]$preSegment[0].raw.durable_records -or
            [string]$durableRow.raw_prefix_sha256 -cne [string]$preSegment[0].raw.verified_prefix_sha256 -or
            [string]$durableRow.post_rescan_raw_prefix_sha256 -cne [string]$durableRow.raw_prefix_sha256 -or
            [string]$durableRow.terminal_record_sha256 -cne [string]$preSegment[0].raw.terminal_record_sha256 -or
            [string]$durableRow.progress_prefix_sha256 -cne [string]$preSegment[0].progress.verified_prefix_sha256 -or
            [string]$durableRow.post_rescan_progress_prefix_sha256 -cne [string]$durableRow.progress_prefix_sha256 -or
            [string]$durableRow.progress_terminal_record_sha256 -cne [string]$preSegment[0].progress.terminal_record_sha256 -or
            [uint64]$finalSegment[0].raw.durable_through_offset -lt $rawPrefixBytes -or
            [uint64]$finalSegment[0].raw.durable_records -lt $durableRecords -or
            [uint64]$finalSegment[0].progress.verified_through_offset -lt $progressPrefixBytes) {
            throw "Fault evidence durable inventory is not linked to an exact pre-request prefix and a non-regressing final segment."
        }
        if ($sealedAtObservation -and ((-not [bool]$finalSegment[0].sealed) -or
            (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $preSegment[0])) -cne
                (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $finalSegment[0])))) {
            throw "Fault evidence sealed durable segment changed after observation."
        }
        if ([uint64]$finalSegment[0].raw.durable_through_offset -eq $rawPrefixBytes -and
            [string]$finalSegment[0].raw.verified_prefix_sha256 -cne [string]$durableRow.raw_prefix_sha256) {
            throw "Fault evidence equal-length final BNRAW prefix digest changed."
        }
        if ([uint64]$finalSegment[0].progress.verified_through_offset -eq $progressPrefixBytes -and
            [string]$finalSegment[0].progress.verified_prefix_sha256 -cne [string]$durableRow.progress_prefix_sha256) {
            throw "Fault evidence equal-length final BNACK prefix digest changed."
        }
    }

    Assert-FaultGateJsonObject -Value $Body.fault_journal -Label "fault evidence fault journal"
    Assert-FaultGateExactProperties -Value $Body.fault_journal -Names @("journal_bytes_base64", "records", "terminal_record_sha256", "file_bytes", "file_sha256", "proposed_record_sha256", "injection_requested_record_sha256", "injected_record_sha256") -Label "fault evidence fault journal"
    $faultJournalBase64 = Get-FaultGateJsonNonEmptyString -Value $Body.fault_journal.journal_bytes_base64 -Label "fault evidence fault journal base64"
    try { [byte[]]$embeddedFaultJournalBytes = [Convert]::FromBase64String($faultJournalBase64) }
    catch { throw "Fault evidence fault journal is not valid Base64." }
    if ([Convert]::ToBase64String($embeddedFaultJournalBytes) -cne $faultJournalBase64) { throw "Fault evidence fault journal Base64 is not canonical." }
    $embeddedFaultJournal = Read-FaultGateEmbeddedFaultJournal -Bytes $embeddedFaultJournalBytes -Label "fault evidence embedded fault journal"
    $faultJournalRecords = Get-FaultGateJsonUnsignedInteger -Value $Body.fault_journal.records -Label "fault evidence fault journal records"
    $faultJournalBytes = Get-FaultGateJsonUnsignedInteger -Value $Body.fault_journal.file_bytes -Label "fault evidence fault journal bytes"
    foreach ($faultJournalDigest in @("terminal_record_sha256", "file_sha256", "proposed_record_sha256", "injection_requested_record_sha256", "injected_record_sha256")) {
        Assert-FaultGateEvidenceDigest -Value $Body.fault_journal.$faultJournalDigest -Label "fault evidence fault journal $faultJournalDigest"
    }
    if ($faultJournalRecords -ne 8 -or $faultJournalBytes -eq 0 -or [uint64]$embeddedFaultJournal.records -ne $faultJournalRecords -or
        [uint64]$embeddedFaultJournal.file_bytes -ne $faultJournalBytes -or [string]$embeddedFaultJournal.file_sha256 -cne [string]$Body.fault_journal.file_sha256 -or
        [string]$embeddedFaultJournal.terminal_record_sha256 -cne [string]$Body.fault_journal.terminal_record_sha256 -or
        [string]$Body.fault_journal.proposed_record_sha256 -cne [string]$Body.fault.proposed_record_sha256 -or
        [string]$Body.fault_journal.injection_requested_record_sha256 -cne [string]$Body.fault.injection_requested_record_sha256 -or
        [string]$Body.fault_journal.injected_record_sha256 -cne [string]$Body.fault.injected_record_sha256) {
        throw "Fault evidence journal does not bind the fixed eight-event proposal/request/injection sequence."
    }
    $faultJournalLinks = Test-FaultGateFaultInjectionJournalSequence -Journal $embeddedFaultJournal -ProposalSha256 ([string]$Body.fault.proposed_record_sha256) -InjectionRequestedSha256 ([string]$Body.fault.injection_requested_record_sha256) -InjectedSha256 ([string]$Body.fault.injected_record_sha256) -TargetPid ([uint32]$faultTargetPid) -RequestedExitCode ([uint32]$faultRequestedExit) -InjectionRequestedWallNs $injectionRequestedWallNs -InjectionRequestedMonotonicTick $failureOriginTick -ObservedExitCode ([uint32]$faultObservedExit) -EvidenceBody $Body
    if ([uint64]$faultJournalLinks.injected_envelope_monotonic_tick -gt $containmentObservedTick -or
        $containmentObservedTick -gt [uint64]$faultJournalLinks.launcher_exited_envelope_monotonic_tick) {
        throw "Fault evidence containment observation is not ordered between the authenticated injected and launcher-exited journal envelopes."
    }
    $requiredTreeDigests = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath "launcher-terminal.json" -Bytes ([uint64]$Body.launcher.terminal_bytes) -Sha256 $Body.launcher.terminal_sha256 -Label "launcher terminal tree binding"
    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath "launcher-startup.json" -Bytes ([uint64]$Body.launcher.startup_bytes) -Sha256 $Body.launcher.startup_sha256 -Label "launcher startup tree binding"
    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath "processes.json" -Bytes ([uint64]$Body.launcher.process_control_bytes) -Sha256 $Body.launcher.process_control_sha256 -Label "process control tree binding"
    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath "campaign-bindings.json" -Bytes ([uint64]$Body.launcher.campaign_bindings_bytes) -Sha256 $Body.launcher.campaign_bindings_sha256 -Label "campaign bindings tree binding"
    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath "launcher-events.jsonl" -Bytes ([uint64]$Body.launcher.launcher_journal.file_bytes) -Sha256 $Body.launcher.launcher_journal.file_sha256 -Label "launcher journal tree binding"
    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath "guardian-pulse.jsonl" -Bytes ([uint64]$Body.launcher.guardian_journal.file_bytes) -Sha256 $Body.launcher.guardian_journal.file_sha256 -Label "guardian journal tree binding"
    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath "host-telemetry.jsonl" -Bytes ([uint64]$Body.launcher.telemetry_journal.file_bytes) -Sha256 $Body.launcher.telemetry_journal.file_sha256 -Label "telemetry journal tree binding"
    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath "watchdog-ready.json" -Bytes ([uint64]$Body.live_gate.watchdog_ready.file_bytes) -Sha256 $Body.live_gate.watchdog_ready.file_sha256 -Label "watchdog READY tree binding"
    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath ([string]$Body.coordinator_stderr.file) -Bytes ([uint64]$Body.coordinator_stderr.bytes) -Sha256 $Body.coordinator_stderr.sha256 -Label "causal BTC coordinator stderr tree binding"
    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath ([string]$Body.coordinator_stderr.peer_file) -Bytes ([uint64]$Body.coordinator_stderr.peer_bytes) -Sha256 $Body.coordinator_stderr.peer_sha256 -Label "empty ETH coordinator stderr tree binding"
    $seenCampaignDirectories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $expectedStreamTreeFiles = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    for ($generationIndex = 0; $generationIndex -lt $finalGenerations.Count; $generationIndex++) {
        $generation = $finalGenerations[$generationIndex]
        $sessionFull = [IO.Path]::GetFullPath([string]$generation.session_directory)
        $sessionRelative = Get-FaultGateCanonicalContainedRelativePath -Root ([string]$Body.run_root) -FullPath $sessionFull -Label "fault evidence session tree path"
        $generationsDirectory = [IO.Directory]::GetParent($sessionFull)
        if ($null -eq $generationsDirectory -or $generationsDirectory.Name -cne "generations" -or $null -eq $generationsDirectory.Parent) {
            throw "Fault evidence session is not under an exact campaign generations directory."
        }
        $campaignDirectory = $generationsDirectory.Parent.FullName
        $campaignRelative = Get-FaultGateCanonicalContainedRelativePath -Root ([string]$Body.run_root) -FullPath $campaignDirectory -Label "fault evidence campaign tree path"
        if (-not $seenCampaignDirectories.Add($campaignDirectory)) { throw "Fault evidence symbols share an ambiguous campaign directory." }
        $campaignEvidenceRow = @($Body.campaign_journals)[$generationIndex]
        if (-not [IO.Path]::GetFullPath([string]$campaignEvidenceRow.campaign_directory).Equals([IO.Path]::GetFullPath($campaignDirectory), [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($campaignDirectory) -cne [string]$campaignEvidenceRow.campaign_id) {
            throw "Fault evidence raw session/campaign binding topology is inconsistent."
        }
        Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath ($campaignRelative + "/campaign-startup.json") -Bytes ([uint64]$campaignEvidenceRow.campaign_startup_bytes) -Sha256 $campaignEvidenceRow.campaign_startup_sha256 -Label "campaign startup tree binding"
        Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath ($campaignRelative + "/campaign-events.jsonl") -Bytes ([uint64]@($Body.campaign_journals)[$generationIndex].file_bytes) -Sha256 @($Body.campaign_journals)[$generationIndex].file_sha256 -Label "campaign journal tree binding"
        Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath ($sessionRelative + "/startup.json") -Bytes ([uint64]$generation.startup_bytes) -Sha256 $generation.startup_sha256 -Label "generation startup tree binding"
        Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath ($sessionRelative + "/snapshot.bnraw") -Bytes ([uint64]$generation.snapshot.bytes) -Sha256 $generation.snapshot.file_sha256 -Label "generation snapshot tree binding"
        Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath ($sessionRelative + "/snapshot-http.json") -Bytes ([uint64]$generation.snapshot.http_metadata_bytes) -Sha256 $generation.snapshot.http_metadata_sha256 -Label "generation snapshot HTTP metadata tree binding"
        foreach ($transport in @($generation.transports)) {
            Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath ($sessionRelative + "/" + [string]$transport.metadata_file) -Bytes ([uint64]$transport.metadata_bytes) -Sha256 $transport.metadata_sha256 -Label "generation transport metadata tree binding"
        }
        Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath ($sessionRelative + "/telemetry.jsonl") -Bytes ([uint64]$generation.telemetry.observed_file_bytes) -Sha256 $generation.telemetry.full_file_sha256 -Label "generation telemetry tree binding"
        foreach ($stream in @($generation.streams)) {
            $streamName = [string]$stream.stream
            $streamRelative = $sessionRelative + "/" + $streamName
            $streamExpected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            $null = $streamExpected.Add($streamRelative + "/segments.bnseg")
            Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath ($streamRelative + "/segments.bnseg") -Bytes ([uint64]$stream.manifest_file_bytes) -Sha256 $stream.manifest_file_sha256 -Label "stream manifest tree binding"
            foreach ($segment in @($stream.verified_segments)) {
                $segmentIndex = [uint64]$segment.segment_index
                $rawRelative = $streamRelative + ("/segment-{0:D6}.bnraw" -f $segmentIndex)
                $ackRelative = $streamRelative + ("/segment-{0:D6}.bnack" -f $segmentIndex)
                $segmentSealed = [bool]$segment.sealed
                $segmentDurable = $false
                if (-not $segmentSealed) { $segmentDurable = [bool]$segment.durable_prefix }
                if ($segmentSealed -or $segmentDurable) {
                    $null = $streamExpected.Add($rawRelative)
                    $null = $streamExpected.Add($ackRelative)
                    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath $rawRelative -Bytes ([uint64]$segment.raw.observed_file_bytes) -Sha256 $segment.raw.full_file_sha256 -Label "segment raw tree binding"
                    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath $ackRelative -Bytes ([uint64]$segment.progress.file_bytes) -Sha256 $segment.progress.file_sha256 -Label "segment ACK tree binding"
                }
                elseif ($null -ne $segment.PSObject.Properties['raw_file_sha256']) {
                    $null = $streamExpected.Add($rawRelative)
                    $null = $streamExpected.Add($ackRelative)
                    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath $rawRelative -Bytes ([uint64]$segment.raw_file_bytes) -Sha256 $segment.raw_file_sha256 -Label "opaque raw tail tree binding"
                    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath $ackRelative -Bytes ([uint64]$segment.progress_file_bytes) -Sha256 $segment.progress_file_sha256 -Label "opaque ACK tail tree binding"
                }
                else {
                    $partialRelative = if ([string]$segment.sole_partial_file -ceq [IO.Path]::GetFileName($rawRelative)) { $rawRelative } else { $ackRelative }
                    $null = $streamExpected.Add($partialRelative)
                    Add-FaultGateRequiredTreeDigest -Map $requiredTreeDigests -RelativePath $partialRelative -Bytes ([uint64]$segment.sole_partial_file_bytes) -Sha256 $segment.sole_partial_file_sha256 -Label "sole partial tail tree binding"
                }
            }
            if ($expectedStreamTreeFiles.ContainsKey($streamRelative)) { throw "Fault evidence repeats a raw stream directory identity." }
            $expectedStreamTreeFiles.Add($streamRelative, $streamExpected)
        }
    }
    Assert-FaultGateExactProperties -Value $Body.artifact_tree -Names @("root", "files", "total_bytes", "tree_sha256", "inventory") -Label "fault evidence artifact tree"
    $treeRoot = Get-FaultGateJsonNonEmptyString -Value $Body.artifact_tree.root -Label "fault evidence artifact tree root"
    $treeFiles = Get-FaultGateJsonUnsignedInteger -Value $Body.artifact_tree.files -Label "fault evidence artifact tree files"
    $treeTotalBytes = Get-FaultGateJsonUnsignedInteger -Value $Body.artifact_tree.total_bytes -Label "fault evidence artifact tree bytes"
    Assert-FaultGateEvidenceDigest -Value $Body.artifact_tree.tree_sha256 -Label "fault evidence artifact tree digest"
    Assert-FaultGateJsonArray -Value $Body.artifact_tree.inventory -Label "fault evidence artifact inventory"
    if ($treeFiles -eq 0 -or @($Body.artifact_tree.inventory).Count -ne $treeFiles) { throw "Fault evidence artifact tree inventory cardinality is invalid." }
    $treeBuilder = [Text.StringBuilder]::new()
    $treeInventoryByPath = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $computedTreeBytes = [uint64]0
    $previousTreePath = $null
    foreach ($treeRow in @($Body.artifact_tree.inventory)) {
        Assert-FaultGateJsonObject -Value $treeRow -Label "fault evidence artifact tree row"
        Assert-FaultGateExactProperties -Value $treeRow -Names @("relative_path", "bytes", "sha256") -Label "fault evidence artifact tree row"
        $treePath = Get-FaultGateJsonNonEmptyString -Value $treeRow.relative_path -Label "fault evidence artifact relative path"
        $null = Test-FaultGateCanonicalRelativePath -Root $treeRoot -RelativePath $treePath -Label "fault evidence artifact relative path"
        $treeLeaf = [IO.Path]::GetFileName($treePath)
        if ($treeLeaf -cin @("campaign.json", "generation.json", "qualification.json") -or @($treePath.Split('/')) -ccontains "independent-verification") {
            throw "Fault evidence artifact inventory contradicts the declared no-promotion state: $treePath"
        }
        $treeBytes = Get-FaultGateJsonUnsignedInteger -Value $treeRow.bytes -Label "fault evidence artifact bytes"
        Assert-FaultGateEvidenceDigest -Value $treeRow.sha256 -Label "fault evidence artifact digest"
        if ($treeInventoryByPath.ContainsKey($treePath) -or ($null -ne $previousTreePath -and [StringComparer]::Ordinal.Compare($previousTreePath, $treePath) -ge 0)) { throw "Fault evidence artifact inventory is not unique ordinal order." }
        $treeInventoryByPath.Add($treePath, [pscustomobject][ordered]@{ bytes = $treeBytes; sha256 = [string]$treeRow.sha256 })
        $previousTreePath = $treePath
        $computedTreeBytes += $treeBytes
        $null = $treeBuilder.Append($treePath).Append([char]0).Append($treeBytes.ToString([Globalization.CultureInfo]::InvariantCulture)).Append([char]0).Append([string]$treeRow.sha256).Append([char]10)
    }
    $computedTreeSha = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($treeBuilder.ToString()))
    if ($treeRoot -cne [string]$Body.run_root -or $computedTreeBytes -ne $treeTotalBytes -or $computedTreeSha -cne [string]$Body.artifact_tree.tree_sha256) { throw "Fault evidence artifact tree root/counters/digest do not match RunRoot and inventory." }
    foreach ($requiredTreePath in $requiredTreeDigests.Keys) {
        if (-not $treeInventoryByPath.ContainsKey($requiredTreePath) -or
            [uint64]$treeInventoryByPath[$requiredTreePath].bytes -ne [uint64]$requiredTreeDigests[$requiredTreePath].bytes -or
            [string]$treeInventoryByPath[$requiredTreePath].sha256 -cne [string]$requiredTreeDigests[$requiredTreePath].sha256) {
            throw "Fault evidence artifact tree omits or contradicts referenced artifact: $requiredTreePath"
        }
    }
    foreach ($streamRelative in $expectedStreamTreeFiles.Keys) {
        $actualStreamFiles = @($treeInventoryByPath.Keys | Where-Object { $_.StartsWith($streamRelative + '/', [StringComparison]::Ordinal) })
        $expectedFiles = $expectedStreamTreeFiles[$streamRelative]
        if ($actualStreamFiles.Count -ne $expectedFiles.Count) { throw "Fault evidence artifact tree contains an omitted or orphan raw stream file: $streamRelative" }
        foreach ($actualStreamFile in $actualStreamFiles) {
            if (-not $expectedFiles.Contains($actualStreamFile)) { throw "Fault evidence artifact tree contains an orphan raw stream file: $actualStreamFile" }
        }
    }
}

function Test-FaultGateEvidenceSupportTree {
    param([Parameter(Mandatory = $true)] $Body)
    $tree = $Body.support_artifact_tree
    Assert-FaultGateJsonObject -Value $tree -Label "fault evidence support artifact tree"
    Assert-FaultGateExactProperties -Value $tree -Names @("root", "files", "total_bytes", "tree_sha256", "inventory") -Label "fault evidence support artifact tree"
    $root = Get-FaultGateJsonNonEmptyString -Value $tree.root -Label "fault evidence support root"
    $files = Get-FaultGateJsonUnsignedInteger -Value $tree.files -Label "fault evidence support files"
    $totalBytes = Get-FaultGateJsonUnsignedInteger -Value $tree.total_bytes -Label "fault evidence support bytes"
    Assert-FaultGateEvidenceDigest -Value $tree.tree_sha256 -Label "fault evidence support tree digest"
    Assert-FaultGateJsonArray -Value $tree.inventory -Label "fault evidence support inventory"
    $monitorAttempt = Get-FaultGateJsonUnsignedInteger -Value $Body.live_gate.monitor.attempt -Label "fault evidence support monitor attempt"
    $expectedFiles = [Collections.Generic.List[string]]::new()
    foreach ($fixed in @("fault-events.jsonl", "launcher.stderr.log", "launcher.stdout.log")) { $expectedFiles.Add($fixed) }
    for ([uint64]$attempt = 1; $attempt -le $monitorAttempt; $attempt++) {
        $expectedFiles.Add(("monitor-{0:D3}.stderr.log" -f $attempt))
        $expectedFiles.Add(("monitor-{0:D3}.stdout.json" -f $attempt))
    }
    $expectedOrdered = [string[]]@($expectedFiles)
    [Array]::Sort($expectedOrdered, [StringComparer]::Ordinal)
    $rows = @($tree.inventory)
    if ($root -cne [string]$Body.evidence_root -or $files -ne [uint64]$expectedOrdered.Count -or $rows.Count -ne $expectedOrdered.Count) {
        throw "Fault evidence support artifact tree topology/cardinality is invalid."
    }
    $builder = [Text.StringBuilder]::new()
    [uint64]$computedBytes = 0
    $rowMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    for ($index = 0; $index -lt $rows.Count; $index++) {
        $row = $rows[$index]
        Assert-FaultGateJsonObject -Value $row -Label "fault evidence support artifact row"
        Assert-FaultGateExactProperties -Value $row -Names @("relative_path", "bytes", "sha256") -Label "fault evidence support artifact row"
        $relative = Get-FaultGateJsonNonEmptyString -Value $row.relative_path -Label "fault evidence support relative path"
        $null = Test-FaultGateCanonicalRelativePath -Root $root -RelativePath $relative -Label "fault evidence support relative path"
        $rowBytes = Get-FaultGateJsonUnsignedInteger -Value $row.bytes -Label "fault evidence support artifact bytes"
        Assert-FaultGateEvidenceDigest -Value $row.sha256 -Label "fault evidence support artifact digest"
        if ($relative.Contains('/') -or $relative -cne $expectedOrdered[$index] -or $rowMap.ContainsKey($relative)) { throw "Fault evidence support inventory path/order is invalid." }
        $rowMap.Add($relative, $row)
        $computedBytes += $rowBytes
        $null = $builder.Append($relative).Append([char]0).Append($rowBytes.ToString([Globalization.CultureInfo]::InvariantCulture)).Append([char]0).Append([string]$row.sha256).Append([char]10)
    }
    $computedSha = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($builder.ToString()))
    if ($computedBytes -ne $totalBytes -or $computedSha -cne [string]$tree.tree_sha256) { throw "Fault evidence support tree counters/digest are invalid." }
    $required = @(
        [pscustomobject]@{ path = "fault-events.jsonl"; bytes = [uint64]$Body.fault_journal.file_bytes; sha256 = [string]$Body.fault_journal.file_sha256 },
        [pscustomobject]@{ path = [string]$Body.launcher.stdout_file; bytes = [uint64]$Body.launcher.stdout_bytes; sha256 = [string]$Body.launcher.stdout_sha256 },
        [pscustomobject]@{ path = [string]$Body.launcher.stderr_file; bytes = [uint64]$Body.launcher.stderr_bytes; sha256 = [string]$Body.launcher.stderr_sha256 },
        [pscustomobject]@{ path = [string]$Body.live_gate.monitor.stdout_file; bytes = [uint64]$Body.live_gate.monitor.stdout_bytes; sha256 = [string]$Body.live_gate.monitor.stdout_sha256 },
        [pscustomobject]@{ path = [string]$Body.live_gate.monitor.stderr_file; bytes = [uint64]$Body.live_gate.monitor.stderr_bytes; sha256 = [string]$Body.live_gate.monitor.stderr_sha256 }
    )
    foreach ($reference in $required) {
        if (-not $rowMap.ContainsKey([string]$reference.path) -or [uint64]$rowMap[[string]$reference.path].bytes -ne [uint64]$reference.bytes -or
            [string]$rowMap[[string]$reference.path].sha256 -cne [string]$reference.sha256) {
            throw "Fault evidence support tree contradicts a referenced artifact: $($reference.path)"
        }
    }
}

function Test-FaultGateEvidenceEnvelope {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [string] $ExpectedPublishedPath
    )
    [byte[]]$evidenceBytes = [IO.File]::ReadAllBytes($Path)
    if ($evidenceBytes.Length -eq 0) { throw "Fault evidence file is empty." }
    $evidenceText = [Text.UTF8Encoding]::new($false, $true).GetString($evidenceBytes)
    $envelope = $evidenceText | ConvertFrom-Json -ErrorAction Stop
    Assert-FaultGateJsonObject -Value $envelope -Label "fault evidence envelope"
    Assert-FaultGateExactProperties -Value $envelope -Names @("body", "record_sha256") -Label "fault evidence envelope"
    [byte[]]$canonicalEvidenceBytes = [Text.UTF8Encoding]::new($false).GetBytes((($envelope | ConvertTo-Json -Depth 100) + "`n"))
    if ($evidenceBytes.Length -ne $canonicalEvidenceBytes.Length) { throw "Fault evidence bytes are not the exact writer-canonical envelope." }
    for ($evidenceByteIndex = 0; $evidenceByteIndex -lt $evidenceBytes.Length; $evidenceByteIndex++) {
        if ($evidenceBytes[$evidenceByteIndex] -ne $canonicalEvidenceBytes[$evidenceByteIndex]) { throw "Fault evidence bytes are not the exact writer-canonical envelope." }
    }
    Assert-FaultGateJsonObject -Value $envelope.body -Label "fault evidence body"
    Assert-FaultGateExactProperties -Value $envelope.body -Names @(
        "schema", "status", "gate_id", "run_id", "run_root", "evidence_root", "repository_root", "fault", "launcher", "live_gate", "retained_process_identities",
        "containment", "promotion", "campaign_journals", "campaign_prefixes", "coordinator_stderr", "raw_durable_prefixes", "raw_preservation", "fault_journal",
        "artifact_tree", "support_artifact_tree", "harness"
    ) -Label "fault evidence body"
    $evidenceSchema = Get-FaultGateJsonNonEmptyString -Value $envelope.body.schema -Label "fault evidence schema"
    $evidenceStatus = Get-FaultGateJsonNonEmptyString -Value $envelope.body.status -Label "fault evidence status"
    foreach ($stringField in @("gate_id", "run_id", "run_root", "evidence_root", "repository_root")) {
        $null = Get-FaultGateJsonNonEmptyString -Value $envelope.body.$stringField -Label ("fault evidence " + $stringField)
    }
    $evidenceRootPath = [IO.Path]::GetFullPath([string]$envelope.body.evidence_root).TrimEnd('\')
    $runRootPath = [IO.Path]::GetFullPath([string]$envelope.body.run_root).TrimEnd('\')
    $repositoryRootPath = [IO.Path]::GetFullPath([string]$envelope.body.repository_root).TrimEnd('\')
    $expectedRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..")).TrimEnd('\')
    $expectedEvidencePath = [IO.Path]::GetFullPath((Join-Path $evidenceRootPath "fault-evidence.json"))
    $publicationPath = if ([string]::IsNullOrWhiteSpace($ExpectedPublishedPath)) {
        [IO.Path]::GetFullPath($Path)
    }
    else {
        [IO.Path]::GetFullPath($ExpectedPublishedPath)
    }
    $physicalEvidencePath = [IO.Path]::GetFullPath($Path)
    $expectedRunRoot = [IO.Path]::GetFullPath((Join-Path (Join-Path $evidenceRootPath "qualification") ([string]$envelope.body.run_id))).TrimEnd('\')
    $repositoryPrefix = $repositoryRootPath + '\'
    if (-not $publicationPath.Equals($expectedEvidencePath, [StringComparison]::OrdinalIgnoreCase) -or
        (-not $physicalEvidencePath.Equals($publicationPath, [StringComparison]::OrdinalIgnoreCase) -and
            -not $physicalEvidencePath.StartsWith($evidenceRootPath + '\', [StringComparison]::OrdinalIgnoreCase)) -or
        [IO.Path]::GetFileName($evidenceRootPath) -cne [string]$envelope.body.gate_id -or
        -not $runRootPath.Equals($expectedRunRoot, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($runRootPath) -cne [string]$envelope.body.run_id -or
        -not $repositoryRootPath.Equals($expectedRepositoryRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not $evidenceRootPath.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetPathRoot($evidenceRootPath).Equals([IO.Path]::GetPathRoot($repositoryRootPath), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Fault evidence path/evidence_root/gate_id/qualification/run_id topology is invalid."
    }
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $repositoryRootPath
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $evidenceRootPath
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $runRootPath
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $physicalEvidencePath
    foreach ($objectField in @("fault", "launcher", "live_gate", "containment", "promotion", "campaign_prefixes", "coordinator_stderr", "raw_preservation", "fault_journal", "artifact_tree", "support_artifact_tree", "harness")) {
        Assert-FaultGateJsonObject -Value $envelope.body.$objectField -Label ("fault evidence " + $objectField)
    }
    Assert-FaultGateJsonArray -Value $envelope.body.campaign_journals -Label "fault evidence campaign_journals"
    Assert-FaultGateJsonArray -Value $envelope.body.retained_process_identities -Label "fault evidence retained_process_identities"
    Assert-FaultGateJsonArray -Value $envelope.body.raw_durable_prefixes -Label "fault evidence raw_durable_prefixes"
    Assert-FaultGateJsonArray -Value $envelope.body.raw_preservation.pre_fault_raw_prefixes -Label "fault evidence pre_fault_raw_prefixes"
    foreach ($journalRow in @($envelope.body.campaign_journals)) {
        Assert-FaultGateJsonObject -Value $journalRow -Label "fault evidence campaign journal row"
        $null = Get-FaultGateJsonNonEmptyString -Value $journalRow.symbol -Label "fault evidence campaign journal symbol"
    }
    foreach ($rawRow in @($envelope.body.raw_durable_prefixes)) {
        Assert-FaultGateJsonObject -Value $rawRow -Label "fault evidence raw prefix row"
        $null = Get-FaultGateJsonNonEmptyString -Value $rawRow.symbol -Label "fault evidence raw prefix symbol"
    }
    $outerActiveProcesses = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.containment.outer_active_processes -Label "fault evidence outer_active_processes" -Maximum ([uint32]::MaxValue)
    $globalEngineProcesses = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.containment.global_engine_processes -Label "fault evidence global_engine_processes"
    $runBoundProcesses = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.containment.run_bound_processes -Label "fault evidence run_bound_processes"
    $verifierProcesses = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.containment.verifier_processes -Label "fault evidence verifier_processes"
    $launcherComplete = Get-FaultGateJsonBoolean -Value $envelope.body.promotion.launcher_complete -Label "fault evidence launcher_complete"
    $independentVerification = Get-FaultGateJsonBoolean -Value $envelope.body.promotion.independent_verification -Label "fault evidence independent_verification"
    if (-not (Test-FaultGateDigest $envelope.body.fault.proposed_record_sha256) -or
        -not (Test-FaultGateDigest $envelope.body.fault.injected_record_sha256) -or
        -not (Test-FaultGateDigest $envelope.body.raw_preservation.pre_fault_raw_prefixes_sha256) -or
        -not (Test-FaultGateDigest $envelope.body.fault_journal.terminal_record_sha256) -or
        -not (Test-FaultGateDigest $envelope.body.artifact_tree.tree_sha256) -or
        -not (Test-FaultGateDigest $envelope.record_sha256)) { throw "Fault evidence contains an invalid critical digest type/value." }
    Assert-FaultGateJsonObject -Value $envelope.body.harness -Label "fault evidence harness"
    Assert-FaultGateExactProperties -Value $envelope.body.harness -Names @(
        "script_file", "process_identity", "source_binding_scope", "source_binding_trust_boundary", "source_bindings_at_start", "source_bindings_at_terminal",
        "direct_artifacts_retained_and_rehashed", "observed_digest_or_external_trust_boundary"
    ) -Label "fault evidence harness"
    Assert-FaultGateJsonObject -Value $envelope.body.harness.process_identity -Label "fault evidence harness process identity"
    Assert-FaultGateExactProperties -Value $envelope.body.harness.process_identity -Names @("pid", "creation_filetime_utc") -Label "fault evidence harness process identity"
    $harnessPid = Get-FaultGateJsonUnsignedInteger -Value $envelope.body.harness.process_identity.pid -Label "fault evidence harness pid" -Maximum ([uint32]::MaxValue)
    $harnessCreation = Get-FaultGateJsonSignedInteger -Value $envelope.body.harness.process_identity.creation_filetime_utc -Label "fault evidence harness creation"
    if ($harnessPid -eq 0 -or $harnessCreation -le 0) { throw "Fault evidence harness process identity is invalid." }
    Test-FaultGateEvidenceCoreSchema -Body $envelope.body
    Test-FaultGateEvidenceSupportTree -Body $envelope.body
    $directArtifacts = $envelope.body.harness.direct_artifacts_retained_and_rehashed
    Assert-FaultGateJsonObject -Value $directArtifacts -Label "fault evidence direct retained artifact scope"
    Assert-FaultGateExactProperties -Value $directArtifacts -Names @(
        "scope", "observation_scope", "trust_boundary", "unchanged", "hashes_at_start", "hashes_at_terminal", "bindings_at_start", "bindings_at_terminal"
    ) -Label "fault evidence direct retained artifact scope"
    Assert-FaultGateJsonObject -Value $directArtifacts.hashes_at_start -Label "fault evidence start artifact hashes"
    Assert-FaultGateJsonObject -Value $directArtifacts.hashes_at_terminal -Label "fault evidence terminal artifact hashes"
    $expectedSourceBindingProperties = @("role", "path", "observation_scope", "trust_boundary", "length", "sha256")
    $expectedSourceBindingTrustBoundary = "Path-byte observation and retention do not assert absolute equivalence with bytes already interpreted or mapped by a runtime."
    $expectedSourceRoles = @("harness", "helper")
    $expectedSourceFiles = @("run_raw_fault_gate.ps1", "RawQualification.Windows.ps1")
    $expectedPyvenvConfigPath = Join-Path $repositoryRootPath ".venv\pyvenv.cfg"
    $expectedPyvenvBinding = $null
    try {
        $expectedPyvenvBinding = Open-FaultGateRetainedPathBinding -Path $expectedPyvenvConfigPath -Role "evidence_validator_pyvenv_config"
        $expectedPythonRuntimePaths = Get-FaultGatePythonRuntimePathsFromRetainedConfig -Binding $expectedPyvenvBinding
    }
    finally { Close-FaultGateRetainedPathBinding -Binding $expectedPyvenvBinding }
    $expectedArtifactPaths = Get-FaultGateNominalDirectArtifactPaths -RepositoryRoot $repositoryRootPath -PythonBaseExecutable ([string]$expectedPythonRuntimePaths.base_executable)
    $expectedSourcePaths = @([string]$expectedArtifactPaths.harness, [string]$expectedArtifactPaths.helper)
    Assert-FaultGateJsonArray -Value $envelope.body.harness.source_bindings_at_start -Label "fault evidence source bindings at start"
    Assert-FaultGateJsonArray -Value $envelope.body.harness.source_bindings_at_terminal -Label "fault evidence source bindings at terminal"
    $sourceStart = @($envelope.body.harness.source_bindings_at_start)
    $sourceTerminal = @($envelope.body.harness.source_bindings_at_terminal)
    if ($sourceStart.Count -ne 2 -or $sourceTerminal.Count -ne 2) { throw "Fault evidence lacks two retained source bindings at both observations." }
    for ($sourceIndex = 0; $sourceIndex -lt 2; $sourceIndex++) {
        Assert-FaultGateExactProperties -Value $sourceStart[$sourceIndex] -Names $expectedSourceBindingProperties -Label "fault evidence source binding start"
        Assert-FaultGateExactProperties -Value $sourceTerminal[$sourceIndex] -Names $expectedSourceBindingProperties -Label "fault evidence source binding terminal"
        $sourceStartRole = Get-FaultGateJsonNonEmptyString -Value $sourceStart[$sourceIndex].role -Label "fault evidence source start role"
        $sourceTerminalRole = Get-FaultGateJsonNonEmptyString -Value $sourceTerminal[$sourceIndex].role -Label "fault evidence source terminal role"
        $sourceStartPath = Get-FaultGateJsonNonEmptyString -Value $sourceStart[$sourceIndex].path -Label "fault evidence source start path"
        $sourceTerminalPath = Get-FaultGateJsonNonEmptyString -Value $sourceTerminal[$sourceIndex].path -Label "fault evidence source terminal path"
        $sourceStartScope = Get-FaultGateJsonNonEmptyString -Value $sourceStart[$sourceIndex].observation_scope -Label "fault evidence source start scope"
        $sourceTerminalScope = Get-FaultGateJsonNonEmptyString -Value $sourceTerminal[$sourceIndex].observation_scope -Label "fault evidence source terminal scope"
        $sourceStartTrust = Get-FaultGateJsonNonEmptyString -Value $sourceStart[$sourceIndex].trust_boundary -Label "fault evidence source start trust boundary"
        $sourceTerminalTrust = Get-FaultGateJsonNonEmptyString -Value $sourceTerminal[$sourceIndex].trust_boundary -Label "fault evidence source terminal trust boundary"
        $sourceStartLength = Get-FaultGateJsonUnsignedInteger -Value $sourceStart[$sourceIndex].length -Label "fault evidence source start length"
        $sourceTerminalLength = Get-FaultGateJsonUnsignedInteger -Value $sourceTerminal[$sourceIndex].length -Label "fault evidence source terminal length"
        if ($sourceStartRole -cne $expectedSourceRoles[$sourceIndex] -or $sourceTerminalRole -cne $expectedSourceRoles[$sourceIndex] -or
            -not [IO.Path]::IsPathRooted($sourceStartPath) -or -not [IO.Path]::IsPathRooted($sourceTerminalPath) -or
            -not [IO.Path]::GetFullPath($sourceStartPath).Equals($expectedSourcePaths[$sourceIndex], [StringComparison]::OrdinalIgnoreCase) -or
            -not [IO.Path]::GetFullPath($sourceTerminalPath).Equals($expectedSourcePaths[$sourceIndex], [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($sourceStartPath) -cne $expectedSourceFiles[$sourceIndex] -or
            $sourceStartScope -cne "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE" -or $sourceTerminalScope -cne "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE" -or
            $sourceStartTrust -cne $expectedSourceBindingTrustBoundary -or $sourceTerminalTrust -cne $expectedSourceBindingTrustBoundary -or
            $sourceStartLength -ne $sourceTerminalLength -or $sourceStartLength -eq 0 -or
            [string]$sourceStart[$sourceIndex].sha256 -cne [string]$sourceTerminal[$sourceIndex].sha256 -or
            -not (Test-FaultGateDigest $sourceStart[$sourceIndex].sha256)) { throw "Fault evidence retained source binding drifted or is invalid." }
    }
    $expectedArtifactNames = @("harness", "selftest", "helper", "launcher", "monitor", "telemetry_probe", "watchdog", "python_runtime_fingerprint", "powershell", "campaign", "capture", "verifier", "public_config", "source_lock", "python", "pyproject", "requirements", "pyvenv_config", "python_base_executable")
    $expectedArtifactFiles = @("run_raw_fault_gate.ps1", "_raw_fault_gate_selftest.ps1", "RawQualification.Windows.ps1", "run_24h_raw_qualification.ps1", "monitor_24h_raw_qualification.ps1", "RawQualification.TelemetryProbe.ps1", "RawQualification.Watchdog.ps1", "RawQualification.PythonRuntimeFingerprint.ps1", "powershell.exe", "raw_campaign.exe", "segmented_capture.exe", "campaign_verify.exe", "public.json", "BINANCE_SOURCE_LOCK.md", "python.exe", "pyproject.toml", "requirements.lock", "pyvenv.cfg", "python.exe")
    Assert-FaultGateExactProperties -Value $directArtifacts.hashes_at_start -Names $expectedArtifactNames -Label "fault evidence start artifact hashes"
    Assert-FaultGateExactProperties -Value $directArtifacts.hashes_at_terminal -Names $expectedArtifactNames -Label "fault evidence terminal artifact hashes"
    foreach ($artifactName in $expectedArtifactNames) {
        if (-not (Test-FaultGateDigest $directArtifacts.hashes_at_start.$artifactName) -or
            -not (Test-FaultGateDigest $directArtifacts.hashes_at_terminal.$artifactName) -or
            [string]$directArtifacts.hashes_at_start.$artifactName -cne [string]$directArtifacts.hashes_at_terminal.$artifactName) {
            throw "Fault evidence artifact provenance is invalid or drifted: $artifactName"
        }
    }
    Assert-FaultGateJsonArray -Value $directArtifacts.bindings_at_start -Label "fault evidence artifact bindings at start"
    Assert-FaultGateJsonArray -Value $directArtifacts.bindings_at_terminal -Label "fault evidence artifact bindings at terminal"
    $artifactStart = @($directArtifacts.bindings_at_start)
    $artifactTerminal = @($directArtifacts.bindings_at_terminal)
    if ($artifactStart.Count -ne $expectedArtifactNames.Count -or $artifactTerminal.Count -ne $expectedArtifactNames.Count) {
        throw "Fault evidence lacks the exact retained critical-artifact binding set."
    }
    for ($artifactIndex = 0; $artifactIndex -lt $expectedArtifactNames.Count; $artifactIndex++) {
        $artifactName = $expectedArtifactNames[$artifactIndex]
        Assert-FaultGateExactProperties -Value $artifactStart[$artifactIndex] -Names $expectedSourceBindingProperties -Label "fault evidence artifact binding start"
        Assert-FaultGateExactProperties -Value $artifactTerminal[$artifactIndex] -Names $expectedSourceBindingProperties -Label "fault evidence artifact binding terminal"
        $artifactStartRole = Get-FaultGateJsonNonEmptyString -Value $artifactStart[$artifactIndex].role -Label "fault evidence artifact start role"
        $artifactTerminalRole = Get-FaultGateJsonNonEmptyString -Value $artifactTerminal[$artifactIndex].role -Label "fault evidence artifact terminal role"
        $artifactStartPath = Get-FaultGateJsonNonEmptyString -Value $artifactStart[$artifactIndex].path -Label "fault evidence artifact start path"
        $artifactTerminalPath = Get-FaultGateJsonNonEmptyString -Value $artifactTerminal[$artifactIndex].path -Label "fault evidence artifact terminal path"
        $artifactStartScope = Get-FaultGateJsonNonEmptyString -Value $artifactStart[$artifactIndex].observation_scope -Label "fault evidence artifact start scope"
        $artifactTerminalScope = Get-FaultGateJsonNonEmptyString -Value $artifactTerminal[$artifactIndex].observation_scope -Label "fault evidence artifact terminal scope"
        $artifactStartTrust = Get-FaultGateJsonNonEmptyString -Value $artifactStart[$artifactIndex].trust_boundary -Label "fault evidence artifact start trust boundary"
        $artifactTerminalTrust = Get-FaultGateJsonNonEmptyString -Value $artifactTerminal[$artifactIndex].trust_boundary -Label "fault evidence artifact terminal trust boundary"
        $artifactStartLength = Get-FaultGateJsonUnsignedInteger -Value $artifactStart[$artifactIndex].length -Label "fault evidence artifact start length"
        $artifactTerminalLength = Get-FaultGateJsonUnsignedInteger -Value $artifactTerminal[$artifactIndex].length -Label "fault evidence artifact terminal length"
        $expectedArtifactPath = [string]$expectedArtifactPaths[$artifactName]
        if ($artifactStartRole -cne $artifactName -or $artifactTerminalRole -cne $artifactName -or
            -not [IO.Path]::IsPathRooted($artifactStartPath) -or -not [IO.Path]::IsPathRooted($artifactTerminalPath) -or
            -not [IO.Path]::GetFullPath($artifactStartPath).Equals($expectedArtifactPath, [StringComparison]::OrdinalIgnoreCase) -or
            -not [IO.Path]::GetFullPath($artifactTerminalPath).Equals($expectedArtifactPath, [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($artifactStartPath) -cne $expectedArtifactFiles[$artifactIndex] -or
            $artifactStartScope -cne "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE" -or $artifactTerminalScope -cne "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE" -or
            $artifactStartTrust -cne $expectedSourceBindingTrustBoundary -or $artifactTerminalTrust -cne $expectedSourceBindingTrustBoundary -or
            $artifactStartLength -eq 0 -or $artifactStartLength -ne $artifactTerminalLength -or
            [string]$artifactStart[$artifactIndex].sha256 -cne [string]$artifactTerminal[$artifactIndex].sha256 -or
            [string]$artifactStart[$artifactIndex].sha256 -cne [string]$directArtifacts.hashes_at_start.$artifactName -or
            [string]$artifactTerminal[$artifactIndex].sha256 -cne [string]$directArtifacts.hashes_at_terminal.$artifactName) {
            throw "Fault evidence retained critical-artifact binding is invalid: $artifactName"
        }
    }
    $absenceArtifactRoles = @("powershell", "campaign", "capture", "campaign", "capture", "powershell")
    $expectedExecutionPathsByRole = @{
        powershell = [IO.Path]::GetFullPath([string]$expectedArtifactPaths.powershell)
        campaign = [IO.Path]::GetFullPath((Join-Path $runRootPath "sealed-runtime\bin\raw_campaign.exe"))
        capture = [IO.Path]::GetFullPath((Join-Path $runRootPath "sealed-runtime\bin\segmented_capture.exe"))
    }
    $retainedAbsenceRows = @($envelope.body.containment.retained_identity_absence)
    $retainedIdentityRows = @($envelope.body.retained_process_identities)
    for ($absenceIndex = 0; $absenceIndex -lt $absenceArtifactRoles.Count; $absenceIndex++) {
        $artifactRole = $absenceArtifactRoles[$absenceIndex]
        $artifactPosition = [Array]::IndexOf($expectedArtifactNames, $artifactRole)
        $expectedExecutionPath = [string]$expectedExecutionPathsByRole[$artifactRole]
        if ($artifactPosition -lt 0 -or
            [string]::IsNullOrWhiteSpace($expectedExecutionPath) -or
            -not [IO.Path]::GetFullPath([string]$retainedAbsenceRows[$absenceIndex].executable_path).Equals($expectedExecutionPath, [StringComparison]::OrdinalIgnoreCase) -or
            [string]$retainedAbsenceRows[$absenceIndex].executable_sha256 -cne [string]$artifactStart[$artifactPosition].sha256 -or
            -not [IO.Path]::GetFullPath([string]$retainedIdentityRows[$absenceIndex].executable_path).Equals($expectedExecutionPath, [StringComparison]::OrdinalIgnoreCase) -or
            [string]$retainedIdentityRows[$absenceIndex].executable_sha256 -cne [string]$artifactStart[$artifactPosition].sha256) {
            throw "Fault evidence retained/absent process path and digest are not bound to the sealed execution image and retained source role $artifactRole."
        }
    }
    $powerShellArtifactPosition = [Array]::IndexOf($expectedArtifactNames, "powershell")
    if ($powerShellArtifactPosition -lt 0 -or
        -not [IO.Path]::GetFullPath([string]$envelope.body.live_gate.monitor.executable_path).Equals([IO.Path]::GetFullPath([string]$artifactStart[$powerShellArtifactPosition].path), [StringComparison]::OrdinalIgnoreCase) -or
        [string]$envelope.body.live_gate.monitor.executable_sha256 -cne [string]$artifactStart[$powerShellArtifactPosition].sha256) {
        throw "Fault evidence monitor executable path/digest is not bound to retained PowerShell."
    }
    if ((Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $sourceStart[0])) -cne
            (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $artifactStart[0])) -or
        (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $sourceStart[1])) -cne
            (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $artifactStart[2])) -or
        (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $sourceTerminal[0])) -cne
            (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $artifactTerminal[0])) -or
        (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $sourceTerminal[1])) -cne
            (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $artifactTerminal[2]))) {
        throw "Fault evidence source bindings are not the exact harness/helper subset of critical-artifact bindings."
    }
    $observedBoundary = $envelope.body.harness.observed_digest_or_external_trust_boundary
    Assert-FaultGateJsonObject -Value $observedBoundary -Label "fault evidence observed/external trust boundary"
    Assert-FaultGateExactProperties -Value $observedBoundary -Names @(
        "scope", "retained_path_handles", "absolute_executed_byte_attestation", "observed_digests", "external_dependencies"
    ) -Label "fault evidence observed/external trust boundary"
    Assert-FaultGateJsonArray -Value $observedBoundary.observed_digests -Label "fault evidence observed digests"
    Assert-FaultGateJsonArray -Value $observedBoundary.external_dependencies -Label "fault evidence external dependencies"
    $observedRows = @($observedBoundary.observed_digests)
    $expectedObservedNames = @("python_verifier_source_tree", "python_runtime_tree")
    if ($observedRows.Count -ne 2) { throw "Fault evidence observed digest boundary is incomplete." }
    for ($observedIndex = 0; $observedIndex -lt 2; $observedIndex++) {
        Assert-FaultGateExactProperties -Value $observedRows[$observedIndex] -Names @(
            "name", "retained_path_handles", "executed_byte_attestation", "preflight_sha256", "launcher_terminal_preflight_sha256",
            "terminal_observation", "launcher_terminal_final_sha256"
        ) -Label "fault evidence observed digest"
        $expectedTerminalObservation = if ($observedIndex -eq 0) { "OBSERVED_AND_UNCHANGED" } else { "TERMINAL_NOT_OBSERVED_ON_FAILED_PATH" }
        $observedName = Get-FaultGateJsonNonEmptyString -Value $observedRows[$observedIndex].name -Label "fault evidence observed digest name"
        $observedRetainedHandles = Get-FaultGateJsonBoolean -Value $observedRows[$observedIndex].retained_path_handles -Label "fault evidence observed retained handles"
        $observedExecutedAttestation = Get-FaultGateJsonBoolean -Value $observedRows[$observedIndex].executed_byte_attestation -Label "fault evidence observed executed-byte attestation"
        $observedTerminalStatus = Get-FaultGateJsonNonEmptyString -Value $observedRows[$observedIndex].terminal_observation -Label "fault evidence observed terminal status"
        Assert-FaultGateEvidenceDigest -Value $observedRows[$observedIndex].preflight_sha256 -Label "fault evidence observed preflight digest"
        Assert-FaultGateEvidenceDigest -Value $observedRows[$observedIndex].launcher_terminal_preflight_sha256 -Label "fault evidence observed launcher preflight digest"
        if ($observedIndex -eq 0) { Assert-FaultGateEvidenceDigest -Value $observedRows[$observedIndex].launcher_terminal_final_sha256 -Label "fault evidence observed launcher final digest" }
        if ($observedName -cne $expectedObservedNames[$observedIndex] -or
            $observedRetainedHandles -or $observedExecutedAttestation -or
            [string]$observedRows[$observedIndex].preflight_sha256 -cne [string]$observedRows[$observedIndex].launcher_terminal_preflight_sha256 -or
            $observedTerminalStatus -cne $expectedTerminalObservation -or
            ($observedIndex -eq 0 -and [string]$observedRows[$observedIndex].preflight_sha256 -cne [string]$observedRows[$observedIndex].launcher_terminal_final_sha256) -or
            ($observedIndex -eq 1 -and $null -ne $observedRows[$observedIndex].launcher_terminal_final_sha256)) {
            throw "Fault evidence observed digest row is invalid or overclaims attestation."
        }
    }
    $expectedExternalDependencies = @(
        "WINDOWS_KERNEL_PROCESS_JOB_OBJECT_AND_FILESYSTEM_SEMANTICS",
        "WINDOWS_W32TIME_POWERCFG_CIM_AND_PERFORMANCE_PROVIDERS",
        "OS_LOADER_TLS_CERTIFICATE_STORE_NETWORK_STACK_AND_DEVICE_DRIVERS",
        "BINANCE_PUBLIC_MARKET_DATA_REST_AND_WEBSOCKET_SERVICES"
    )
    $actualExternalDependencies = @($observedBoundary.external_dependencies)
    for ($externalIndex = 0; $externalIndex -lt $actualExternalDependencies.Count; $externalIndex++) {
        $null = Get-FaultGateJsonNonEmptyString -Value $actualExternalDependencies[$externalIndex] -Label "fault evidence external dependency $externalIndex"
    }
    if (($expectedExternalDependencies -join "`n") -cne ($actualExternalDependencies -join "`n")) {
        throw "Fault evidence external trust boundary is missing, reordered, or unknown."
    }
    $directUnchanged = Get-FaultGateJsonBoolean -Value $directArtifacts.unchanged -Label "fault evidence direct artifacts unchanged"
    $observedRetainedHandles = Get-FaultGateJsonBoolean -Value $observedBoundary.retained_path_handles -Label "fault evidence boundary retained handles"
    $observedAbsoluteAttestation = Get-FaultGateJsonBoolean -Value $observedBoundary.absolute_executed_byte_attestation -Label "fault evidence boundary absolute executed-byte attestation"
    $directScope = Get-FaultGateJsonNonEmptyString -Value $directArtifacts.scope -Label "fault evidence direct artifact scope"
    $directObservationScope = Get-FaultGateJsonNonEmptyString -Value $directArtifacts.observation_scope -Label "fault evidence direct artifact observation scope"
    $directTrustBoundary = Get-FaultGateJsonNonEmptyString -Value $directArtifacts.trust_boundary -Label "fault evidence direct artifact trust boundary"
    $observedScope = Get-FaultGateJsonNonEmptyString -Value $observedBoundary.scope -Label "fault evidence observed boundary scope"
    $harnessScope = Get-FaultGateJsonNonEmptyString -Value $envelope.body.harness.source_binding_scope -Label "fault evidence harness binding scope"
    $harnessTrust = Get-FaultGateJsonNonEmptyString -Value $envelope.body.harness.source_binding_trust_boundary -Label "fault evidence harness trust boundary"
    $harnessScript = Get-FaultGateJsonNonEmptyString -Value $envelope.body.harness.script_file -Label "fault evidence harness script"
    $actual = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $envelope.body)
    $preFaultRawSha = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($envelope.body.raw_preservation.pre_fault_raw_prefixes))
    if ($evidenceSchema -cne "RawQualificationFaultEvidenceV3" -or $evidenceStatus -cne "PASS" -or
        [string]$envelope.record_sha256 -cne $actual -or -not (Test-FaultGateDigest $envelope.body.artifact_tree.tree_sha256) -or
        -not (Test-FaultGateDigest $envelope.body.fault_journal.terminal_record_sha256) -or
        -not (Test-FaultGateDigest $envelope.body.fault.proposed_record_sha256) -or -not (Test-FaultGateDigest $envelope.body.fault.injected_record_sha256) -or
        $outerActiveProcesses -ne 0 -or $globalEngineProcesses -ne 0 -or $runBoundProcesses -ne 0 -or $verifierProcesses -ne 0 -or
        $launcherComplete -or $independentVerification -or
        $directScope -cne "DIRECT_ARTIFACTS_RETAINED_AND_REHASHED" -or -not $directUnchanged -or
        $directObservationScope -cne "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE" -or
        $directTrustBoundary -cne $expectedSourceBindingTrustBoundary -or
        $observedScope -cne "OBSERVED_DIGEST_OR_EXTERNAL_TRUST_BOUNDARY" -or
        $observedRetainedHandles -or $observedAbsoluteAttestation -or
        $harnessScope -cne "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE" -or
        $harnessTrust -cne $expectedSourceBindingTrustBoundary -or
        $harnessScript -cne "run_raw_fault_gate.ps1" -or
        [string]$directArtifacts.hashes_at_start.harness -cne [string]$sourceStart[0].sha256 -or
        [string]$directArtifacts.hashes_at_start.helper -cne [string]$sourceStart[1].sha256 -or
        [string]$directArtifacts.hashes_at_terminal.harness -cne [string]$sourceTerminal[0].sha256 -or
        [string]$directArtifacts.hashes_at_terminal.helper -cne [string]$sourceTerminal[1].sha256 -or
        @($envelope.body.raw_durable_prefixes).Count -ne 2 -or
        @($envelope.body.campaign_journals).Count -ne 2) { throw "Fault evidence envelope/body invariant failure." }
    if ([string]$envelope.body.raw_preservation.pre_fault_raw_prefixes_sha256 -cne $preFaultRawSha) { throw "Fault evidence pre-fault raw material digest mismatch." }
    return $envelope
}

function Publish-FaultGateValidatedPassEvidence {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] $Body,
        [Parameter(Mandatory = $true)] [ref] $PublicationObserved
    )
    $publishedPath = [IO.Path]::GetFullPath($Path)
    if ([IO.Path]::GetFileName($publishedPath) -cne "fault-evidence.json") {
        throw "PASS evidence publication requires the canonical fault-evidence.json target."
    }
    if ([IO.File]::Exists($publishedPath)) {
        throw "PASS evidence publication target already exists."
    }
    $PublicationObserved.Value = $false
    $pendingPath = Join-Path `
        ([IO.Path]::GetDirectoryName($publishedPath)) `
        (".fault-evidence-" + [Guid]::NewGuid().ToString("N") + ".pending")
    $recordSha256 = $null
    try {
        $recordSha256 = Write-FaultGateEvidence -Path $pendingPath -Body $Body
        $verified = Test-FaultGateEvidenceEnvelope `
            -Path $pendingPath -ExpectedPublishedPath $publishedPath
        if ([string]$verified.record_sha256 -cne [string]$recordSha256) {
            throw "Staged fault PASS evidence did not rescan to its publication digest."
        }
        Initialize-FaultGateNative
        $moveSucceeded = $false
        try {
            [RawFaultGateNative]::MoveFileNoReplaceWriteThrough($pendingPath, $publishedPath)
            $moveSucceeded = $true
        }
        finally {
            # Once the validated same-directory rename becomes visible, the
            # canonical PASS artifact is the publication boundary even if a
            # later PowerShell statement fails.  The caller shares this ref so
            # its failure receipt can never claim that the file is absent.
            if ($moveSucceeded -and [IO.File]::Exists($publishedPath)) {
                $PublicationObserved.Value = $true
            }
        }
        if (-not [bool]$PublicationObserved.Value) {
            throw "Validated fault PASS evidence was not observed at its canonical target."
        }
        return [pscustomobject][ordered]@{
            path = $publishedPath
            record_sha256 = [string]$recordSha256
        }
    }
    finally {
        if ([IO.File]::Exists($pendingPath)) {
            try { [IO.File]::Delete($pendingPath) }
            catch { Write-Warning "Could not remove unpublished fault-evidence staging file: $($_.Exception.Message)" }
        }
    }
}

function Assert-FaultGateBootstrapNoReparsePointInExistingPath {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "Bootstrap path must not be empty." }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) { throw "Bootstrap path has no filesystem root: $Path" }
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Bootstrap path root is a reparse point: $root"
    }
    $current = $root
    $relative = $fullPath.Substring($root.Length)
    $components = @($relative.Split([char[]]@('\', '/'), [StringSplitOptions]::RemoveEmptyEntries))
    foreach ($component in $components) {
        if ($component -ceq "." -or $component -ceq ".." -or $component.IndexOf([char]0) -ge 0) {
            throw "Bootstrap path contains a non-canonical component: $Path"
        }
        $current = Join-Path $current $component
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Bootstrap path traverses a reparse point: $current"
        }
    }
    if (-not [IO.Path]::GetFullPath($current).Equals($fullPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Bootstrap path traversal did not resolve to its exact canonical path."
    }
    return $fullPath
}

function Open-FaultGateRetainedPathBinding {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Role,
        [uint64] $MaximumBytes = [uint64]::MaxValue
    )
    $fullPath = Assert-FaultGateBootstrapNoReparsePointInExistingPath -Path $Path
    Initialize-FaultGateNative
    $stream = [IO.FileStream]::new(
        $fullPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read,
        1048576,
        [IO.FileOptions]::SequentialScan)
    try {
        [uint64]$observedLength = $stream.Length
        if ($observedLength -gt $MaximumBytes) {
            throw "Retained path binding exceeds its open-time byte limit: $Role"
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = -join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString("x2") })
        }
        finally { $sha.Dispose() }
        $stream.Position = 0
        $fileIdentity = [RawFaultGateNative]::GetFileIdentity($stream.SafeFileHandle.DangerousGetHandle())
        return [pscustomobject][ordered]@{
            role = $Role
            path = $fullPath
            observation_scope = "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE"
            trust_boundary = "Path-byte observation and retention do not assert absolute equivalence with bytes already interpreted or mapped by a runtime."
            length = $observedLength
            sha256 = $digest
            volume_serial_number = [uint32]$fileIdentity.VolumeSerialNumber
            file_index = [uint64]$fileIdentity.FileIndex
            stream = $stream
        }
    }
    catch { $stream.Dispose(); throw }
}

function Test-FaultGateRetainedPathBinding {
    param([Parameter(Mandatory = $true)] $Binding)
    if ($null -eq $Binding.stream -or -not [bool]$Binding.stream.CanRead) { throw "Retained source binding is not readable: $($Binding.role)" }
    if ([uint64]$Binding.stream.Length -ne [uint64]$Binding.length) { throw "Retained source length drifted: $($Binding.role)" }
    $Binding.stream.Position = 0
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = -join ($sha.ComputeHash($Binding.stream) | ForEach-Object { $_.ToString("x2") }) }
    finally { $sha.Dispose(); $Binding.stream.Position = 0 }
    if ([string]$digest -cne [string]$Binding.sha256) { throw "Retained source bytes drifted: $($Binding.role)" }
    $boundPath = [IO.Path]::GetFullPath([string]$Binding.path)
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $boundPath
    $pathStream = [IO.FileStream]::new(
        $boundPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read,
        1048576,
        [IO.FileOptions]::SequentialScan)
    try {
        $pathIdentity = [RawFaultGateNative]::GetFileIdentity($pathStream.SafeFileHandle.DangerousGetHandle())
        if ([uint32]$pathIdentity.VolumeSerialNumber -ne [uint32]$Binding.volume_serial_number -or
            [uint64]$pathIdentity.FileIndex -ne [uint64]$Binding.file_index -or
            [uint64]$pathStream.Length -ne [uint64]$Binding.length) {
            throw "Nominal source path no longer resolves to the retained file identity: $($Binding.role)"
        }
        $pathSha = [Security.Cryptography.SHA256]::Create()
        try { $pathDigest = -join ($pathSha.ComputeHash($pathStream) | ForEach-Object { $_.ToString("x2") }) }
        finally { $pathSha.Dispose() }
        if ([string]$pathDigest -cne [string]$Binding.sha256) {
            throw "Nominal source path bytes differ from the retained file: $($Binding.role)"
        }
    }
    finally { $pathStream.Dispose() }
    return [pscustomobject][ordered]@{
        role = [string]$Binding.role
        path = [string]$Binding.path
        observation_scope = [string]$Binding.observation_scope
        trust_boundary = [string]$Binding.trust_boundary
        length = [uint64]$Binding.length
        sha256 = [string]$Binding.sha256
    }
}

function Read-FaultGateRetainedUtf8Text {
    param([Parameter(Mandatory = $true)] $Binding, [ValidateRange(1, 1048576)] [int] $MaximumBytes = 65536)
    if ([uint64]$Binding.length -gt [uint64]$MaximumBytes) { throw "Retained text binding exceeds its exact byte limit: $($Binding.role)" }
    $Binding.stream.Position = 0
    try {
        $bytes = Read-FaultGateExactBytes -Stream $Binding.stream -Count ([int][uint64]$Binding.length)
        if ($Binding.stream.Position -ne $Binding.stream.Length) { throw "Retained text binding was not read exactly." }
        return [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    finally { $Binding.stream.Position = 0 }
}

function Get-FaultGatePythonRuntimePathsFromRetainedConfig {
    param([Parameter(Mandatory = $true)] $Binding)
    $configText = Read-FaultGateRetainedUtf8Text -Binding $Binding
    $configValues = @{}
    foreach ($line in @($configText -split "`r?`n")) {
        if ($line -match '^\s*([^#=]+?)\s*=\s*(.*?)\s*$') {
            $key = $Matches[1].Trim().ToLowerInvariant()
            if ($configValues.ContainsKey($key)) { throw "Duplicate pyvenv.cfg key: $key" }
            $configValues[$key] = $Matches[2]
        }
    }
    if (-not $configValues.ContainsKey("home") -or -not $configValues.ContainsKey("executable")) {
        throw "pyvenv.cfg does not bind home and executable."
    }
    $baseRoot = [IO.Path]::GetFullPath([string]$configValues["home"]).TrimEnd('\')
    $baseExecutable = [IO.Path]::GetFullPath([string]$configValues["executable"])
    $basePrefix = $baseRoot + '\'
    if (-not $baseExecutable.StartsWith($basePrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $baseExecutable -PathType Leaf)) {
        throw "pyvenv.cfg base executable escaped or is absent."
    }
    return [pscustomobject][ordered]@{
        base_root = $baseRoot
        base_executable = $baseExecutable
    }
}

function Get-FaultGateNominalDirectArtifactPaths {
    param(
        [Parameter(Mandatory = $true)] [string] $RepositoryRoot,
        [Parameter(Mandatory = $true)] [string] $PythonBaseExecutable
    )
    $nominalRepo = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\')
    $nominalScripts = Join-Path $nominalRepo "scripts"
    return [ordered]@{
        harness = Join-Path $nominalScripts "run_raw_fault_gate.ps1"
        selftest = Join-Path $nominalScripts "_raw_fault_gate_selftest.ps1"
        helper = Join-Path $nominalScripts "RawQualification.Windows.ps1"
        launcher = Join-Path $nominalScripts "run_24h_raw_qualification.ps1"
        monitor = Join-Path $nominalScripts "monitor_24h_raw_qualification.ps1"
        telemetry_probe = Join-Path $nominalScripts "RawQualification.TelemetryProbe.ps1"
        watchdog = Join-Path $nominalScripts "RawQualification.Watchdog.ps1"
        python_runtime_fingerprint = Join-Path $nominalScripts "RawQualification.PythonRuntimeFingerprint.ps1"
        powershell = Join-Path $PSHOME "powershell.exe"
        campaign = Join-Path $nominalRepo "target\release\raw_campaign.exe"
        capture = Join-Path $nominalRepo "target\release\segmented_capture.exe"
        verifier = Join-Path $nominalRepo "target\release\campaign_verify.exe"
        public_config = Join-Path $nominalRepo "config\public.json"
        source_lock = Join-Path (Split-Path $nominalRepo -Parent) "BINANCE_SOURCE_LOCK.md"
        python = Join-Path $nominalRepo ".venv\Scripts\python.exe"
        pyproject = Join-Path $nominalRepo "pyproject.toml"
        requirements = Join-Path $nominalRepo "requirements.lock"
        pyvenv_config = Join-Path $nominalRepo ".venv\pyvenv.cfg"
        python_base_executable = [IO.Path]::GetFullPath($PythonBaseExecutable)
    }
}

function Close-FaultGateRetainedPathBinding {
    param($Binding)
    if ($null -ne $Binding -and $null -ne $Binding.stream) {
        $Binding.stream.Dispose()
        $Binding.stream = $null
    }
}

function Read-FaultGateRetainedPathBytes {
    param(
        [Parameter(Mandatory = $true)] $Binding,
        [Parameter(Mandatory = $true)] [uint64] $MaximumBytes
    )
    $null = Test-FaultGateRetainedPathBinding -Binding $Binding
    if ([uint64]$Binding.length -gt $MaximumBytes -or [uint64]$Binding.length -gt [uint64][int]::MaxValue) {
        throw "Retained path-byte artifact exceeds its exact read bound: $($Binding.role)"
    }
    [byte[]]$bytes = [byte[]]::new([int][uint64]$Binding.length)
    $Binding.stream.Position = 0
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $Binding.stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -le 0) { throw "Retained path-byte artifact shortened during exact read: $($Binding.role)" }
        $offset += $read
    }
    if ([uint64]$Binding.stream.Position -ne [uint64]$Binding.length) {
        throw "Retained path-byte artifact read did not stop at its frozen length: $($Binding.role)"
    }
    $Binding.stream.Position = 0
    return ,$bytes
}

function Initialize-FaultGateNative {
    if ("RawFaultGateNative" -as [type]) { return }
    Add-Type -Language CSharp -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public sealed class RawFaultGateJobQuery
{
    public bool Exists { get; internal set; }
    public int Error { get; internal set; }
    public uint ActiveProcesses { get; internal set; }
}

public sealed class RawFaultGateFileIdentity
{
    public uint VolumeSerialNumber { get; internal set; }
    public ulong FileIndex { get; internal set; }
}

public static class RawFaultGateNative
{
    private const uint PROCESS_TERMINATE = 0x0001;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint JOB_OBJECT_QUERY = 0x0004;
    private const uint MOVEFILE_WRITE_THROUGH = 0x00000008;
    private const int ERROR_HANDLE_EOF = 38;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteFileTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string StreamName;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder path, ref uint size);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenJobObjectW(uint desiredAccess, bool inheritHandle, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(IntPtr job, int informationClass, out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information, uint length, out uint returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(IntPtr file, out BY_HANDLE_FILE_INFORMATION information);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileExW(string existingPath, string newPath, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr FindFirstStreamW(string fileName, int informationLevel, out WIN32_FIND_STREAM_DATA findStreamData, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool FindNextStreamW(IntPtr findStream, out WIN32_FIND_STREAM_DATA findStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(IntPtr findFile);

    public static IntPtr OpenProcessRetained(uint processId)
    {
        IntPtr handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, processId);
        if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess retained failed");
        return handle;
    }

    public static long GetCreationFileTimeUtc(IntPtr process)
    {
        long creation, exit, kernel, user;
        if (!GetProcessTimes(process, out creation, out exit, out kernel, out user))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetProcessTimes failed");
        return creation;
    }

    public static string GetImagePath(IntPtr process)
    {
        uint size = 32768;
        StringBuilder path = new StringBuilder((int)size);
        if (!QueryFullProcessImageNameW(process, 0, path, ref size))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryFullProcessImageName failed");
        return path.ToString();
    }

    public static RawFaultGateFileIdentity GetFileIdentity(IntPtr file)
    {
        BY_HANDLE_FILE_INFORMATION information;
        if (!GetFileInformationByHandle(file, out information))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandle failed");
        RawFaultGateFileIdentity result = new RawFaultGateFileIdentity();
        result.VolumeSerialNumber = information.VolumeSerialNumber;
        result.FileIndex = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
        return result;
    }

    public static string[] GetDataStreamNames(string path, int maximumStreamCount)
    {
        if (maximumStreamCount < 1) throw new ArgumentOutOfRangeException("maximumStreamCount");
        WIN32_FIND_STREAM_DATA data;
        IntPtr find = FindFirstStreamW(path, 0, out data, 0);
        if (find == new IntPtr(-1))
        {
            int firstError = Marshal.GetLastWin32Error();
            if (firstError == ERROR_HANDLE_EOF) return new string[0];
            throw new Win32Exception(firstError, "FindFirstStreamW failed");
        }
        List<string> names = new List<string>();
        try
        {
            names.Add(data.StreamName);
            if (names.Count > maximumStreamCount)
                throw new InvalidOperationException("Data-stream inventory exceeds its exact bound");
            while (FindNextStreamW(find, out data))
            {
                names.Add(data.StreamName);
                if (names.Count > maximumStreamCount)
                    throw new InvalidOperationException("Data-stream inventory exceeds its exact bound");
            }
            int nextError = Marshal.GetLastWin32Error();
            if (nextError != ERROR_HANDLE_EOF)
                throw new Win32Exception(nextError, "FindNextStreamW failed");
        }
        finally
        {
            if (!FindClose(find))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "FindClose stream enumeration failed");
        }
        return names.ToArray();
    }

    public static void MoveFileNoReplaceWriteThrough(string existingPath, string newPath)
    {
        if (!MoveFileExW(existingPath, newPath, MOVEFILE_WRITE_THROUGH))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "MoveFileExW evidence publication failed");
    }

    public static RawFaultGateJobQuery QueryNamedJob(string name)
    {
        RawFaultGateJobQuery result = new RawFaultGateJobQuery();
        IntPtr handle = OpenJobObjectW(JOB_OBJECT_QUERY, false, name);
        if (handle == IntPtr.Zero)
        {
            result.Exists = false;
            result.Error = Marshal.GetLastWin32Error();
            return result;
        }
        try
        {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION information;
            uint returned;
            uint length = (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            if (!QueryInformationJobObject(handle, 1, out information, length, out returned))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryInformationJobObject failed");
            result.Exists = true;
            result.Error = 0;
            result.ActiveProcesses = information.ActiveProcesses;
            return result;
        }
        finally { CloseHandle(handle); }
    }
}
'@
}

function Get-FaultGateChildEnvironment {
    $entries = [Collections.Generic.List[string]]::new()
    foreach ($name in @("OS", "SystemDrive", "SystemRoot", "TEMP", "TMP", "WINDIR")) {
        $value = [Environment]::GetEnvironmentVariable($name, [EnvironmentVariableTarget]::Process)
        if ([string]::IsNullOrWhiteSpace($value) -or $value.IndexOf([char]0) -ge 0) { throw "Missing/invalid child environment variable: $name" }
        $entries.Add($name + "=" + $value)
    }
    $array = [string[]]$entries
    [Array]::Sort($array, [StringComparer]::OrdinalIgnoreCase)
    return $array
}

function Open-FaultGateExactProcess {
    param(
        [Parameter(Mandatory = $true)] [uint32] $ProcessId,
        [Parameter(Mandatory = $true)] [string] $ExpectedExecutable,
        [Parameter(Mandatory = $true)] [string] $ExpectedCommandLine,
        [Parameter(Mandatory = $true)] [uint32] $ExpectedParentProcessId,
        [Parameter(Mandatory = $true)] [string] $Role,
        [string] $ExpectedCreationTimeUtc
    )
    $handle = [RawFaultGateNative]::OpenProcessRetained($ProcessId)
    try {
        $image = [IO.Path]::GetFullPath([RawFaultGateNative]::GetImagePath($handle))
        $expectedImage = [IO.Path]::GetFullPath($ExpectedExecutable)
        $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -OperationTimeoutSec 5 -ErrorAction Stop
        $creationFileTime = [int64][RawFaultGateNative]::GetCreationFileTimeUtc($handle)
        if ([RawQualificationNative]::WaitForProcessExit($handle, 0) -or $null -eq $cim -or $creationFileTime -le 0 -or
            -not $image.Equals($expectedImage, [StringComparison]::OrdinalIgnoreCase) -or
            [string]$cim.CommandLine -cne $ExpectedCommandLine -or [uint32]$cim.ParentProcessId -ne $ExpectedParentProcessId -or
            (-not [string]::IsNullOrEmpty($ExpectedCreationTimeUtc) -and [DateTime]::Parse($ExpectedCreationTimeUtc).ToUniversalTime().ToFileTimeUtc() -ne $creationFileTime)) {
            throw "$Role process identity is not exact/alive."
        }
        if ([RawQualificationNative]::WaitForProcessExit($handle, 0)) { throw "$Role exited during retained identity validation." }
        return [pscustomobject][ordered]@{
            role = $Role
            pid = $ProcessId
            parent_pid = [uint32]$cim.ParentProcessId
            creation_filetime_utc = $creationFileTime
            creation_time_utc = [DateTime]::FromFileTimeUtc($creationFileTime).ToString("o")
            executable_path = $image
            executable_sha256 = Get-FaultGateSha256File -Path $image
            command_line = [string]$cim.CommandLine
            command_line_sha256 = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes([string]$cim.CommandLine))
            handle = $handle
        }
    }
    catch { $null = [RawQualificationNative]::CloseHandle($handle); throw }
}

function Close-FaultGateProcessIdentity {
    param($Identity)
    if ($null -ne $Identity -and $Identity.handle -ne [IntPtr]::Zero) {
        if (-not [RawQualificationNative]::CloseHandle($Identity.handle)) {
            throw "CloseHandle returned false for retained process identity: $($Identity.role) PID $($Identity.pid)"
        }
        $Identity.handle = [IntPtr]::Zero
    }
}

function Get-FaultGateProcessSnapshot {
    param([ValidateRange(1, 30)] [int] $OperationTimeoutSeconds = 5)
    return @(Get-CimInstance Win32_Process -OperationTimeoutSec $OperationTimeoutSeconds -ErrorAction Stop |
        Sort-Object -Property @{ Expression = { [uint64]$_.ProcessId }; Ascending = $true })
}

function Test-FaultGateRunRootCommandLine {
    param(
        [AllowNull()] [string] $CommandLine,
        [Parameter(Mandatory = $true)] [string] $RunRoot
    )
    if ([string]::IsNullOrWhiteSpace($RunRoot)) { throw "Run-root command-line predicate received an empty root." }
    if ([string]::IsNullOrEmpty($CommandLine)) { return $false }
    return $CommandLine.IndexOf($RunRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Get-FaultGateRunBoundProcesses {
    param(
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $ProcessSnapshot,
        [Parameter(Mandatory = $true)] [string] $RunRoot
    )
    return @($ProcessSnapshot | Where-Object {
        Test-FaultGateRunRootCommandLine -CommandLine ([string]$_.CommandLine) -RunRoot $RunRoot
    })
}

function Get-FaultGateProcessBlockerDiagnostic {
    param([Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $Processes)
    $maximumRows = 16
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($process in @($Processes | Select-Object -First $maximumRows)) {
        $commandLine = [string]$process.CommandLine
        $executablePath = [string]$process.ExecutablePath
        $creationFileTimeUtc = $null
        if ($null -ne $process.CreationDate) {
            try { $creationFileTimeUtc = [int64]([DateTime]$process.CreationDate).ToUniversalTime().ToFileTimeUtc() }
            catch { $creationFileTimeUtc = $null }
        }
        $rows.Add([pscustomobject][ordered]@{
            pid = [uint64]$process.ProcessId
            parent_pid = [uint64]$process.ParentProcessId
            name = [string]$process.Name
            creation_filetime_utc = $creationFileTimeUtc
            executable_path_sha256 = if ([string]::IsNullOrEmpty($executablePath)) { $null } else {
                Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($executablePath))
            }
            command_line_sha256 = if ([string]::IsNullOrEmpty($commandLine)) { $null } else {
                Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($commandLine))
            }
        })
    }
    $value = [pscustomobject][ordered]@{
        observed_processes = [uint64]$Processes.Count
        reported_processes = [uint64]$rows.Count
        truncated = [bool]($Processes.Count -gt $maximumRows)
        candidates = @($rows)
    }
    return [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateCompactJsonBytes -Value $value))
}

function Test-FaultGateRecordedProcessAbsent {
    param(
        [Parameter(Mandatory = $true)] $Identity,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $ProcessSnapshot
    )
    if (-not [RawQualificationNative]::WaitForProcessExit($Identity.handle, 0)) {
        throw "Recorded process survived containment: $($Identity.role) PID $($Identity.pid)"
    }
    $matchingRows = @($ProcessSnapshot | Where-Object { [uint64]$_.ProcessId -eq [uint64]$Identity.pid })
    if ($matchingRows.Count -gt 1) { throw "Terminal process snapshot repeats a PID: $($Identity.role) PID $($Identity.pid)" }
    $cim = if ($matchingRows.Count -eq 1) { $matchingRows[0] } else { $null }
    $evidence = [ordered]@{
        pid = [uint32]$Identity.pid; role = [string]$Identity.role; creation_filetime_utc = [int64]$Identity.creation_filetime_utc
        executable_path = [string]$Identity.executable_path; executable_sha256 = [string]$Identity.executable_sha256
        command_line_sha256 = [string]$Identity.command_line_sha256; absent = $true; pid_reused = $false
    }
    if ($null -eq $cim) { return [pscustomobject]$evidence }
    $diagnostic = Get-FaultGateProcessBlockerDiagnostic -Processes $matchingRows
    if ($null -eq $cim.CreationDate) {
        throw "Retained PID remains in the terminal process snapshot without CreationDate: $($Identity.role) PID $($Identity.pid); $diagnostic"
    }
    try { $currentCreationFileTimeUtc = [int64]([DateTime]$cim.CreationDate).ToUniversalTime().ToFileTimeUtc() }
    catch { throw "Cannot parse terminal Win32_Process CreationDate: $($Identity.role) PID $($Identity.pid); $diagnostic" }
    if ($currentCreationFileTimeUtc -eq [int64]$Identity.creation_filetime_utc) {
        throw "Recorded PID remains visible as its original identity after retained-handle termination: $($Identity.role) PID $($Identity.pid); $diagnostic"
    }
    throw "Retained-handle PID identity is inconsistent; PID reuse is impossible before handle close: $($Identity.role) PID $($Identity.pid); $diagnostic"
}

function Get-FaultGateRemainingDeadlineMilliseconds {
    param([Parameter(Mandatory = $true)] [int64] $DeadlineMonotonicTick)
    $now = [int64][Diagnostics.Stopwatch]::GetTimestamp()
    if ($DeadlineMonotonicTick -le $now) { return [int64]0 }
    $remainingTicks = [int64]($DeadlineMonotonicTick - $now)
    $milliseconds = [int64][Math]::Floor(([double]$remainingTicks * 1000.0) / [double][Diagnostics.Stopwatch]::Frequency)
    if ($milliseconds -lt 0) { return [int64]0 }
    return $milliseconds
}

function Assert-FaultGateObservationWithinDeadline {
    param(
        [Parameter(Mandatory = $true)] [int64] $ObservedMonotonicTick,
        [Parameter(Mandatory = $true)] [int64] $DeadlineMonotonicTick,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ($ObservedMonotonicTick -gt $DeadlineMonotonicTick) {
        throw "$Label was observed after its absolute deadline."
    }
}

function Add-FaultGateCheckedQpcTicks {
    param(
        [Parameter(Mandatory = $true)] [uint64] $Origin,
        [Parameter(Mandatory = $true)] [uint64] $Relative,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ($Origin -eq 0 -or $Origin -gt [uint64][int64]::MaxValue -or $Relative -gt ([uint64][int64]::MaxValue - $Origin)) {
        throw "$Label QPC origin/relative sum overflows the positive signed QPC range."
    }
    return [uint64]($Origin + $Relative)
}

function Assert-FaultGateCanonicalMonitorReportBytes {
    param(
        [Parameter(Mandatory = $true)] [byte[]] $Bytes,
        [Parameter(Mandatory = $true)] $Monitor
    )
    [byte[]]$canonicalBytes = [Text.UTF8Encoding]::new($false).GetBytes((($Monitor | ConvertTo-Json -Depth 100) + "`r`n"))
    Assert-FaultGateExactBytes -Actual $Bytes -Expected $canonicalBytes -Label "monitor stdout"
}

function Test-FaultGateHealthyMonitorReport {
    param(
        [Parameter(Mandatory = $true)] $Monitor,
        [Parameter(Mandatory = $true)] [string] $ExpectedRunRoot,
        [Parameter(Mandatory = $true)] [uint32] $ExpectedGuardianPid,
        [Parameter(Mandatory = $true)] [object[]] $ExpectedProcesses,
        [Parameter(Mandatory = $true)] [object[]] $ExpectedCampaigns,
        [Parameter(Mandatory = $true)] [uint64] $ExpectedMinimumDiskFreeGiB
    )
    Assert-FaultGateJsonObject -Value $Monitor -Label "healthy monitor report"
    Assert-FaultGateExactProperties -Value $Monitor -Names @(
        "schema", "status", "stage", "schedule_deviations", "observed_utc", "run_id", "run_root", "mode", "parameters",
        "launcher_journal_records", "launcher_journal_bytes", "host_telemetry_records", "host_telemetry_bytes", "host_telemetry_age_s",
        "guardian_pulse_records", "guardian_pulse_age_s", "guardian_stage", "disk_free_gib", "clock", "guardian", "processes", "campaigns",
        "current_terminal_reverification", "launcher_terminal_byte_authentication", "inference_boundary"
    ) -Label "healthy monitor report"

    $canonicalRunRoot = [IO.Path]::GetFullPath($ExpectedRunRoot)
    $observedUtc = Get-FaultGateJsonNonEmptyString -Value $Monitor.observed_utc -Label "healthy monitor observed_utc"
    try { $parsedObservedUtc = [DateTimeOffset]::ParseExact($observedUtc, "o", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    catch { throw "Healthy monitor observed_utc is not an exact round-trip timestamp." }
    if ($parsedObservedUtc.Offset -ne [TimeSpan]::Zero) { throw "Healthy monitor observed_utc is not UTC." }
    $unixEpochTicks = [int64]621355968000000000
    if ($parsedObservedUtc.UtcDateTime.Ticks -lt $unixEpochTicks) { throw "Healthy monitor observed_utc precedes the Unix epoch." }
    $observedTicksSinceUnixEpoch = [uint64]($parsedObservedUtc.UtcDateTime.Ticks - $unixEpochTicks)
    $observedUnixNs = Multiply-FaultGateCheckedUInt64 -Left $observedTicksSinceUnixEpoch -Right 100 -Label "healthy monitor observed_utc nanoseconds"
    if ([string]$Monitor.schema -cne "RawQualificationReadOnlyMonitorV1" -or
        [string]$Monitor.status -cne "HEALTHY_RUNNING" -or
        [string]$Monitor.stage -cne "CAPTURING" -or
        [string]$Monitor.run_root -cne $canonicalRunRoot -or
        [string]$Monitor.run_id -cne [IO.Path]::GetFileName($canonicalRunRoot) -or
        [string]$Monitor.mode -cne "Test" -or
        [string]$Monitor.guardian_stage -cne "CAPTURING" -or
        [string]$Monitor.launcher_terminal_byte_authentication -cne "NOT_TERMINAL") {
        throw "Healthy monitor top-level identity/stage contract is invalid."
    }
    $null = Get-FaultGateJsonNonEmptyString -Value $Monitor.inference_boundary -Label "healthy monitor inference boundary"
    Assert-FaultGateJsonArray -Value $Monitor.schedule_deviations -Label "healthy monitor schedule deviations"
    Assert-FaultGateJsonArray -Value $Monitor.current_terminal_reverification -Label "healthy monitor terminal reverification"
    if (@($Monitor.schedule_deviations).Count -ne 0 -or @($Monitor.current_terminal_reverification).Count -ne 0) {
        throw "HEALTHY_RUNNING monitor report contains a deviation or terminal reverification."
    }

    Assert-FaultGateJsonObject -Value $Monitor.parameters -Label "healthy monitor parameters"
    Assert-FaultGateExactProperties -Value $Monitor.parameters -Names @("total_s", "rotation_s", "overlap_s", "segment_s") -Label "healthy monitor parameters"
    $totalSeconds = Get-FaultGateJsonUnsignedInteger -Value $Monitor.parameters.total_s -Label "healthy monitor total_s"
    $rotationSeconds = Get-FaultGateJsonUnsignedInteger -Value $Monitor.parameters.rotation_s -Label "healthy monitor rotation_s"
    $overlapSeconds = Get-FaultGateJsonUnsignedInteger -Value $Monitor.parameters.overlap_s -Label "healthy monitor overlap_s"
    $segmentSeconds = Get-FaultGateJsonUnsignedInteger -Value $Monitor.parameters.segment_s -Label "healthy monitor segment_s"
    if ($totalSeconds -ne 300 -or $rotationSeconds -ne 240 -or $overlapSeconds -ne 30 -or $segmentSeconds -ne 30) {
        throw "Healthy monitor parameters differ from the exact generation-0 fault-gate campaign."
    }
    $launcherJournalRecords = Get-FaultGateJsonUnsignedInteger -Value $Monitor.launcher_journal_records -Label "healthy monitor launcher journal records"
    $launcherJournalBytes = Get-FaultGateJsonUnsignedInteger -Value $Monitor.launcher_journal_bytes -Label "healthy monitor launcher journal bytes"
    $hostTelemetryRecords = Get-FaultGateJsonUnsignedInteger -Value $Monitor.host_telemetry_records -Label "healthy monitor host telemetry records"
    $hostTelemetryBytes = Get-FaultGateJsonUnsignedInteger -Value $Monitor.host_telemetry_bytes -Label "healthy monitor host telemetry bytes"
    $guardianPulseRecords = Get-FaultGateJsonUnsignedInteger -Value $Monitor.guardian_pulse_records -Label "healthy monitor guardian pulse records"
    $diskFreeGiB = Get-FaultGateJsonUnsignedInteger -Value $Monitor.disk_free_gib -Label "healthy monitor disk free GiB"
    if ($launcherJournalRecords -ne 6 -or $launcherJournalBytes -eq 0 -or $hostTelemetryRecords -lt 2 -or
        $hostTelemetryBytes -eq 0 -or $guardianPulseRecords -eq 0 -or $ExpectedMinimumDiskFreeGiB -eq 0 -or
        $diskFreeGiB -lt $ExpectedMinimumDiskFreeGiB) {
        throw "Healthy monitor lacks the minimum durable journals or bound disk reserve."
    }
    $hostTelemetryAge = Get-FaultGateJsonNumber -Value $Monitor.host_telemetry_age_s -Label "healthy monitor host telemetry age"
    $guardianPulseAge = Get-FaultGateJsonNumber -Value $Monitor.guardian_pulse_age_s -Label "healthy monitor guardian pulse age"
    if ($hostTelemetryAge -lt -5 -or $hostTelemetryAge -gt 120 -or $guardianPulseAge -lt -5 -or $guardianPulseAge -gt 90) {
        throw "Healthy monitor host/guardian evidence is stale or future-dated."
    }

    Assert-FaultGateJsonObject -Value $Monitor.clock -Label "healthy monitor clock"
    Assert-FaultGateExactProperties -Value $Monitor.clock -Names @(
        "healthy", "leap_indicator", "stratum", "source", "last_successful_sync", "root_delay_s", "root_dispersion_s", "phase_offset_s",
        "seconds_since_last_good_sync", "maximum_last_good_sync_age_s", "state_machine", "last_sync_error", "poll_interval_s",
        "raw_status_sha256", "query_exit_code"
    ) -Label "healthy monitor clock"
    $clockHealthy = Get-FaultGateJsonBoolean -Value $Monitor.clock.healthy -Label "healthy monitor clock health"
    $clockLeap = Get-FaultGateJsonUnsignedInteger -Value $Monitor.clock.leap_indicator -Label "healthy monitor clock leap" -Maximum 3
    $clockStratum = Get-FaultGateJsonUnsignedInteger -Value $Monitor.clock.stratum -Label "healthy monitor clock stratum" -Maximum 255
    $clockSource = Get-FaultGateJsonNonEmptyString -Value $Monitor.clock.source -Label "healthy monitor clock source"
    $null = Get-FaultGateJsonNonEmptyString -Value $Monitor.clock.last_successful_sync -Label "healthy monitor last successful sync"
    $null = Get-FaultGateJsonNumber -Value $Monitor.clock.root_delay_s -Label "healthy monitor clock root delay"
    $clockDispersion = Get-FaultGateJsonNumber -Value $Monitor.clock.root_dispersion_s -Label "healthy monitor clock root dispersion"
    $null = Get-FaultGateJsonNumber -Value $Monitor.clock.phase_offset_s -Label "healthy monitor clock phase offset"
    $clockSinceGood = Get-FaultGateJsonNumber -Value $Monitor.clock.seconds_since_last_good_sync -Label "healthy monitor seconds since good sync"
    $clockMaximumAge = Get-FaultGateJsonNumber -Value $Monitor.clock.maximum_last_good_sync_age_s -Label "healthy monitor maximum sync age"
    $clockState = Get-FaultGateJsonUnsignedInteger -Value $Monitor.clock.state_machine -Label "healthy monitor clock state" -Maximum ([uint32]::MaxValue)
    $clockError = Get-FaultGateJsonUnsignedInteger -Value $Monitor.clock.last_sync_error -Label "healthy monitor clock error"
    $clockPoll = Get-FaultGateJsonUnsignedInteger -Value $Monitor.clock.poll_interval_s -Label "healthy monitor clock poll interval"
    Assert-FaultGateEvidenceDigest -Value $Monitor.clock.raw_status_sha256 -Label "healthy monitor clock status digest"
    $clockExit = Get-FaultGateJsonUnsignedInteger -Value $Monitor.clock.query_exit_code -Label "healthy monitor clock query exit" -Maximum ([int]::MaxValue)
    if (-not $clockHealthy -or $clockLeap -ne 0 -or $clockStratum -lt 1 -or $clockStratum -gt 15 -or
        $clockSource -match '(?i)Local CMOS|Free-running|VM IC Time Synchronization|unspecified' -or
        $clockDispersion -lt 0 -or $clockSinceGood -lt 0 -or $clockMaximumAge -ne 21600 -or $clockSinceGood -gt $clockMaximumAge -or
        $clockState -ne 2 -or $clockError -ne 0 -or $clockPoll -eq 0 -or $clockExit -ne 0) {
        throw "Healthy monitor clock proof is internally inconsistent or unhealthy."
    }
    Assert-FaultGateJsonObject -Value $Monitor.guardian -Label "healthy monitor guardian"
    Assert-FaultGateExactProperties -Value $Monitor.guardian -Names @("pid", "running", "exact_identity") -Label "healthy monitor guardian"
    $guardianPid = Get-FaultGateJsonUnsignedInteger -Value $Monitor.guardian.pid -Label "healthy monitor guardian pid" -Maximum ([uint32]::MaxValue)
    if ($ExpectedGuardianPid -eq 0 -or $guardianPid -ne $ExpectedGuardianPid -or
        -not (Get-FaultGateJsonBoolean -Value $Monitor.guardian.running -Label "healthy monitor guardian running") -or
        -not (Get-FaultGateJsonBoolean -Value $Monitor.guardian.exact_identity -Label "healthy monitor guardian identity")) {
        throw "Healthy monitor guardian process is not live under its exact identity."
    }

    Assert-FaultGateJsonArray -Value $Monitor.processes -Label "healthy monitor processes"
    $processRows = @($Monitor.processes)
    if ($processRows.Count -ne 2 -or $ExpectedProcesses.Count -ne 2 -or $ExpectedCampaigns.Count -ne 2) {
        throw "Healthy monitor and retained control artifacts must each report exactly two campaigns."
    }
    $expectedProcessMap = @{}
    foreach ($expectedProcess in $ExpectedProcesses) {
        $expectedSymbol = Get-FaultGateJsonNonEmptyString -Value $expectedProcess.symbol -Label "expected monitor process symbol"
        $expectedPid = Get-FaultGateJsonUnsignedInteger -Value $expectedProcess.pid -Label "$expectedSymbol expected monitor process pid" -Maximum ([uint32]::MaxValue)
        if ($expectedSymbol -cnotin @("BTCUSDT", "ETHUSDT") -or $expectedPid -eq 0 -or $expectedPid -eq $ExpectedGuardianPid -or
            $expectedProcessMap.ContainsKey($expectedSymbol) -or $expectedProcessMap.Values -contains $expectedPid) {
            throw "Expected monitor process identities are not a unique dual-symbol set distinct from the guardian."
        }
        $expectedProcessMap[$expectedSymbol] = $expectedPid
    }
    $expectedCampaignMap = @{}
    foreach ($expectedCampaign in $ExpectedCampaigns) {
        $expectedSymbol = Get-FaultGateJsonNonEmptyString -Value $expectedCampaign.symbol -Label "expected monitor campaign symbol"
        $expectedCampaignId = Get-FaultGateJsonNonEmptyString -Value $expectedCampaign.campaign_id -Label "$expectedSymbol expected monitor campaign id"
        if ($expectedSymbol -cnotin @("BTCUSDT", "ETHUSDT") -or $expectedCampaignMap.ContainsKey($expectedSymbol)) {
            throw "Expected monitor campaign bindings are not the unique BTCUSDT/ETHUSDT set."
        }
        if ($expectedCampaign.PSObject.Properties.Name -ccontains "pid") {
            $expectedCampaignPid = Get-FaultGateJsonUnsignedInteger -Value $expectedCampaign.pid -Label "$expectedSymbol expected campaign pid" -Maximum ([uint32]::MaxValue)
            if (-not $expectedProcessMap.ContainsKey($expectedSymbol) -or $expectedCampaignPid -ne [uint64]$expectedProcessMap[$expectedSymbol]) {
                throw "$expectedSymbol expected campaign binding PID differs from process control."
            }
        }
        $expectedCampaignMap[$expectedSymbol] = $expectedCampaignId
    }
    $processSymbols = @{}
    foreach ($processRow in $processRows) {
        Assert-FaultGateJsonObject -Value $processRow -Label "healthy monitor process"
        Assert-FaultGateExactProperties -Value $processRow -Names @(
            "symbol", "pid", "running", "exact_identity", "pid_occupied", "pid_reused_after_exit", "clean_capture_exit_proven"
        ) -Label "healthy monitor process"
        $symbol = Get-FaultGateJsonNonEmptyString -Value $processRow.symbol -Label "healthy monitor process symbol"
        if ($symbol -cnotin @("BTCUSDT", "ETHUSDT") -or $processSymbols.ContainsKey($symbol)) {
            throw "Healthy monitor process symbols are not the unique BTCUSDT/ETHUSDT set."
        }
        $processSymbols[$symbol] = $true
        $processPid = Get-FaultGateJsonUnsignedInteger -Value $processRow.pid -Label "$symbol monitor process pid" -Maximum ([uint32]::MaxValue)
        if ($processPid -eq 0 -or $processPid -eq $ExpectedGuardianPid -or
            -not $expectedProcessMap.ContainsKey($symbol) -or $processPid -ne [uint64]$expectedProcessMap[$symbol] -or
            -not (Get-FaultGateJsonBoolean -Value $processRow.running -Label "$symbol monitor process running") -or
            -not (Get-FaultGateJsonBoolean -Value $processRow.exact_identity -Label "$symbol monitor process identity") -or
            -not (Get-FaultGateJsonBoolean -Value $processRow.pid_occupied -Label "$symbol monitor process occupancy") -or
            (Get-FaultGateJsonBoolean -Value $processRow.pid_reused_after_exit -Label "$symbol monitor process PID reuse") -or
            (Get-FaultGateJsonBoolean -Value $processRow.clean_capture_exit_proven -Label "$symbol monitor process clean exit")) {
            throw "$symbol monitor process is not a live exact pre-terminal identity."
        }
    }

    Assert-FaultGateJsonArray -Value $Monitor.campaigns -Label "healthy monitor campaigns"
    $campaignRows = @($Monitor.campaigns)
    if ($campaignRows.Count -ne 2) { throw "Healthy monitor must report exactly two campaigns." }
    $campaignSymbols = @{}
    foreach ($campaignRow in $campaignRows) {
        Assert-FaultGateJsonObject -Value $campaignRow -Label "healthy monitor campaign"
        Assert-FaultGateExactProperties -Value $campaignRow -Names @(
            "symbol", "campaign_id", "journal_records", "journal_bytes", "durable_heartbeat_age_s", "depth_received", "depth_durable",
            "trade_received", "trade_durable", "generation_market_health", "planned_generation_launches", "server_shutdown_generation_launches",
            "server_shutdown_events", "campaign_elapsed_s", "campaign_heartbeat_age_s", "generations", "handovers_proven"
        ) -Label "healthy monitor campaign"
        $symbol = Get-FaultGateJsonNonEmptyString -Value $campaignRow.symbol -Label "healthy monitor campaign symbol"
        if ($symbol -cnotin @("BTCUSDT", "ETHUSDT") -or $campaignSymbols.ContainsKey($symbol)) {
            throw "Healthy monitor campaign symbols are not the unique BTCUSDT/ETHUSDT set."
        }
        $campaignSymbols[$symbol] = $true
        $campaignId = Get-FaultGateJsonNonEmptyString -Value $campaignRow.campaign_id -Label "$symbol monitor campaign id"
        if ($campaignId -cnotmatch ("^[0-9]{19}-" + $symbol + "-raw-[0-9a-f]{12}$") -or
            -not $expectedCampaignMap.ContainsKey($symbol) -or $campaignId -cne [string]$expectedCampaignMap[$symbol]) {
            throw "$symbol monitor campaign id is not canonical."
        }
        $journalRecords = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.journal_records -Label "$symbol monitor journal records"
        $journalBytes = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.journal_bytes -Label "$symbol monitor journal bytes"
        $depthReceived = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.depth_received -Label "$symbol monitor depth received"
        $depthDurable = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.depth_durable -Label "$symbol monitor depth durable"
        $tradeReceived = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.trade_received -Label "$symbol monitor trade received"
        $tradeDurable = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.trade_durable -Label "$symbol monitor trade durable"
        $durableHeartbeatAge = Get-FaultGateJsonNumber -Value $campaignRow.durable_heartbeat_age_s -Label "$symbol monitor durable heartbeat age"
        $campaignHeartbeatAge = Get-FaultGateJsonNumber -Value $campaignRow.campaign_heartbeat_age_s -Label "$symbol monitor campaign heartbeat age"
        $campaignElapsed = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.campaign_elapsed_s -Label "$symbol monitor campaign elapsed"
        $plannedLaunches = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.planned_generation_launches -Label "$symbol monitor planned launches"
        $shutdownLaunches = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.server_shutdown_generation_launches -Label "$symbol monitor shutdown launches"
        $shutdownEvents = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.server_shutdown_events -Label "$symbol monitor shutdown events"
        $generations = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.generations -Label "$symbol monitor generations"
        $handovers = Get-FaultGateJsonUnsignedInteger -Value $campaignRow.handovers_proven -Label "$symbol monitor handovers"
        if ($journalRecords -eq 0 -or $journalBytes -eq 0 -or $depthReceived -eq 0 -or $tradeReceived -eq 0 -or
            $depthDurable -gt $depthReceived -or $tradeDurable -gt $tradeReceived -or
            $durableHeartbeatAge -lt -5 -or $durableHeartbeatAge -gt 30 -or
            $campaignHeartbeatAge -lt -5 -or $campaignHeartbeatAge -gt 30 -or
            $campaignElapsed -eq 0 -or $campaignElapsed -ge $rotationSeconds -or $plannedLaunches -ne 1 -or $shutdownLaunches -ne 0 -or $shutdownEvents -ne 0 -or
            $generations -ne 1 -or $handovers -ne 0) {
            throw "$symbol monitor campaign is not a healthy generation-0 prefix."
        }

        Assert-FaultGateJsonArray -Value $campaignRow.generation_market_health -Label "$symbol monitor generation health"
        $generationRows = @($campaignRow.generation_market_health)
        if ($generationRows.Count -ne 1) { throw "$symbol monitor must report exactly generation zero before injection." }
        $generation = $generationRows[0]
        Assert-FaultGateJsonObject -Value $generation -Label "$symbol monitor generation health"
        Assert-FaultGateExactProperties -Value $generation -Names @(
            "generation_index", "duration_s", "launch_wall_ns", "last_heartbeat_wall_ns", "telemetry_mono_ns",
            "depth_last_socket_activity_mono_ns", "depth_last_market_message_mono_ns", "depth_market_message_age_ms",
            "trade_last_socket_activity_mono_ns", "trade_last_market_message_mono_ns", "trade_market_message_age_ms",
            "depth_received", "depth_durable", "trade_received", "trade_durable", "terminal", "terminal_wall_ns", "exited", "exited_wall_ns"
        ) -Label "$symbol monitor generation health"
        $generationIndex = Get-FaultGateJsonUnsignedInteger -Value $generation.generation_index -Label "$symbol monitor generation index"
        $duration = Get-FaultGateJsonUnsignedInteger -Value $generation.duration_s -Label "$symbol monitor generation duration"
        $launchWall = Get-FaultGateJsonUnsignedInteger -Value $generation.launch_wall_ns -Label "$symbol monitor launch wall"
        $heartbeatWall = Get-FaultGateJsonUnsignedInteger -Value $generation.last_heartbeat_wall_ns -Label "$symbol monitor heartbeat wall"
        $telemetryMono = Get-FaultGateJsonUnsignedInteger -Value $generation.telemetry_mono_ns -Label "$symbol monitor telemetry mono"
        $depthSocketMono = Get-FaultGateJsonUnsignedInteger -Value $generation.depth_last_socket_activity_mono_ns -Label "$symbol monitor depth socket mono"
        $depthMarketMono = Get-FaultGateJsonUnsignedInteger -Value $generation.depth_last_market_message_mono_ns -Label "$symbol monitor depth market mono"
        $tradeSocketMono = Get-FaultGateJsonUnsignedInteger -Value $generation.trade_last_socket_activity_mono_ns -Label "$symbol monitor trade socket mono"
        $tradeMarketMono = Get-FaultGateJsonUnsignedInteger -Value $generation.trade_last_market_message_mono_ns -Label "$symbol monitor trade market mono"
        $depthAgeMilliseconds = Get-FaultGateJsonNumber -Value $generation.depth_market_message_age_ms -Label "$symbol monitor depth market age"
        $tradeAgeMilliseconds = Get-FaultGateJsonNumber -Value $generation.trade_market_message_age_ms -Label "$symbol monitor trade market age"
        $generationDepthReceived = Get-FaultGateJsonUnsignedInteger -Value $generation.depth_received -Label "$symbol generation depth received"
        $generationDepthDurable = Get-FaultGateJsonUnsignedInteger -Value $generation.depth_durable -Label "$symbol generation depth durable"
        $generationTradeReceived = Get-FaultGateJsonUnsignedInteger -Value $generation.trade_received -Label "$symbol generation trade received"
        $generationTradeDurable = Get-FaultGateJsonUnsignedInteger -Value $generation.trade_durable -Label "$symbol generation trade durable"
        $terminalWall = Get-FaultGateJsonUnsignedInteger -Value $generation.terminal_wall_ns -Label "$symbol monitor terminal wall"
        $exitedWall = Get-FaultGateJsonUnsignedInteger -Value $generation.exited_wall_ns -Label "$symbol monitor exited wall"
        $terminal = Get-FaultGateJsonBoolean -Value $generation.terminal -Label "$symbol monitor terminal flag"
        $exited = Get-FaultGateJsonBoolean -Value $generation.exited -Label "$symbol monitor exited flag"
        $expectedDepthAgeMilliseconds = [math]::Round(([double]$telemetryMono - [double]$depthMarketMono) / 1000000.0, 3)
        $expectedTradeAgeMilliseconds = [math]::Round(([double]$telemetryMono - [double]$tradeMarketMono) / 1000000.0, 3)
        $generationDurationNs = Multiply-FaultGateCheckedUInt64 -Left $duration -Right 1000000000 -Label "$symbol monitor generation duration nanoseconds"
        $calculatedDurableHeartbeatAge = ([double]$observedUnixNs - [double]$heartbeatWall) / 1000000000.0
        if ($generationIndex -ne 0 -or $duration -ne $script:FaultGateGenerationZeroDurationSeconds -or
            $launchWall -eq 0 -or $heartbeatWall -lt $launchWall -or $telemetryMono -eq 0 -or
            $telemetryMono -ge $generationDurationNs -or $calculatedDurableHeartbeatAge -lt -5 -or
            [math]::Abs($calculatedDurableHeartbeatAge - $durableHeartbeatAge) -gt 1.0 -or
            $depthMarketMono -eq 0 -or $depthMarketMono -gt $depthSocketMono -or $depthSocketMono -gt $telemetryMono -or
            $tradeMarketMono -eq 0 -or $tradeMarketMono -gt $tradeSocketMono -or $tradeSocketMono -gt $telemetryMono -or
            $depthAgeMilliseconds -lt 0 -or $depthAgeMilliseconds -gt 30000 -or
            [math]::Abs($depthAgeMilliseconds - $expectedDepthAgeMilliseconds) -gt 0.001 -or
            $tradeAgeMilliseconds -lt 0 -or $tradeAgeMilliseconds -gt 30000 -or
            [math]::Abs($tradeAgeMilliseconds - $expectedTradeAgeMilliseconds) -gt 0.001 -or
            $generationDepthReceived -ne $depthReceived -or $generationDepthDurable -ne $depthDurable -or
            $generationTradeReceived -ne $tradeReceived -or $generationTradeDurable -ne $tradeDurable -or
            $terminal -or $terminalWall -ne 0 -or $exited -or $exitedWall -ne 0) {
            throw "$symbol monitor generation-zero market-health evidence is inconsistent."
        }
    }
    if ($processSymbols.Count -ne 2 -or $campaignSymbols.Count -ne 2 -or
        -not $processSymbols.ContainsKey("BTCUSDT") -or -not $processSymbols.ContainsKey("ETHUSDT") -or
        -not $campaignSymbols.ContainsKey("BTCUSDT") -or -not $campaignSymbols.ContainsKey("ETHUSDT")) {
        throw "Healthy monitor does not contain the exact dual-symbol process/campaign set."
    }
    return $true
}

function Invoke-FaultGateMonitorAttempt {
    param(
        [Parameter(Mandatory = $true)] [IntPtr] $OuterJob,
        [Parameter(Mandatory = $true)] [string] $PowerShellExecutable,
        [Parameter(Mandatory = $true)] [string] $ExpectedPowerShellSha256,
        [Parameter(Mandatory = $true)] [string] $MonitorScript,
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] [string] $GateRoot,
        [Parameter(Mandatory = $true)] [string[]] $EnvironmentEntries,
        [Parameter(Mandatory = $true)] [uint32] $ExpectedGuardianPid,
        [Parameter(Mandatory = $true)] [object[]] $ExpectedProcesses,
        [Parameter(Mandatory = $true)] [object[]] $ExpectedCampaigns,
        [Parameter(Mandatory = $true)] [uint64] $ExpectedMinimumDiskFreeGiB,
        [Parameter(Mandatory = $true)] [int] $Attempt,
        [Parameter(Mandatory = $true)] [int64] $DeadlineMonotonicTick,
        [ValidateRange(1, 120000)] [int] $PerAttemptCapMilliseconds = 120000,
        [ValidateRange(1, 10000)] [int] $DrainCapMilliseconds = 10000,
        [ValidateRange(1, 10000)] [int] $MinimumMonitorBudgetMilliseconds = 1000
    )
    $remainingBeforeLaunch = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $DeadlineMonotonicTick
    $requiredBeforeLaunch = [int64]$DrainCapMilliseconds + [int64]$MinimumMonitorBudgetMilliseconds
    if ($remainingBeforeLaunch -lt $requiredBeforeLaunch) { throw "Insufficient startup deadline budget to launch a bounded monitor attempt." }
    $stdout = Join-Path $GateRoot ("monitor-{0:D3}.stdout.json" -f $Attempt)
    $stderr = Join-Path $GateRoot ("monitor-{0:D3}.stderr.log" -f $Attempt)
    $canonicalGateRoot = [IO.Path]::GetFullPath($GateRoot).TrimEnd('\')
    if (-not [IO.Path]::GetFullPath($stdout).StartsWith($canonicalGateRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($stderr).StartsWith($canonicalGateRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($stdout) -cne ("monitor-{0:D3}.stdout.json" -f $Attempt) -or
        [IO.Path]::GetFileName($stderr) -cne ("monitor-{0:D3}.stderr.log" -f $Attempt)) {
        throw "Monitor evidence paths are not exact children of the fault gate root."
    }
    $arguments = [string[]]@("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $MonitorScript, "-RunRoot", $RunRoot)
    $launch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment($OuterJob, $PowerShellExecutable, $arguments, (Split-Path $PSScriptRoot -Parent), $stdout, $stderr, $EnvironmentEntries)
    try {
        $monitorActualExecutablePath = [IO.Path]::GetFullPath([RawFaultGateNative]::GetImagePath($launch.ProcessHandle))
        if (-not $monitorActualExecutablePath.Equals([IO.Path]::GetFullPath($PowerShellExecutable), [StringComparison]::OrdinalIgnoreCase) -or
            (Get-FaultGateSha256File -Path $monitorActualExecutablePath) -cne $ExpectedPowerShellSha256) {
            throw "Monitor retained process handle is not bound to the retained PowerShell path and digest."
        }
        $remainingForWait = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $DeadlineMonotonicTick
        $waitBudget = [Math]::Min([int64]$PerAttemptCapMilliseconds, $remainingForWait - [int64]$DrainCapMilliseconds)
        if ($waitBudget -lt $MinimumMonitorBudgetMilliseconds) { throw "Monitor attempt lost its bounded startup budget before observation." }
        if (-not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, [int]$waitBudget)) {
            [RawQualificationNative]::TerminateProcessHandle($launch.ProcessHandle, $script:FaultGateFallbackExitCode)
            $remainingForDrain = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $DeadlineMonotonicTick
            $drainBudget = [Math]::Min([int64]$DrainCapMilliseconds, $remainingForDrain)
            if ($drainBudget -le 0 -or -not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, [int]$drainBudget)) {
                throw "Timed-out monitor did not reach an exact terminal observation inside the startup deadline."
            }
            if ([uint32][RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle) -ne $script:FaultGateFallbackExitCode) {
                throw "Timed-out monitor terminal exit code differs from the retained-handle termination request."
            }
            return $null
        }
        if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $DeadlineMonotonicTick) -le 0) { throw "Monitor observation completed outside the startup deadline." }
        $exit = [uint32][RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle)
        $stdoutLength = [uint64](Get-Item -LiteralPath $stdout -ErrorAction Stop).Length
        $stderrLength = [uint64](Get-Item -LiteralPath $stderr -ErrorAction Stop).Length
        if ($exit -ne 0 -or $stderrLength -ne 0 -or $stdoutLength -eq 0 -or $stdoutLength -gt 16777216) { return $null }
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $stdout
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $stderr
        [byte[]]$monitorReportBytes = @(Read-FaultGateSnapshotBytes -Path $stdout)
        try { $monitorReportText = [Text.UTF8Encoding]::new($false, $true).GetString($monitorReportBytes) }
        catch { return $null }
        try { $monitor = $monitorReportText | ConvertFrom-Json -ErrorAction Stop }
        catch { return $null }
        try { Assert-FaultGateCanonicalMonitorReportBytes -Bytes $monitorReportBytes -Monitor $monitor }
        catch { return $null }
        try {
            $null = Test-FaultGateHealthyMonitorReport -Monitor $monitor -ExpectedRunRoot $RunRoot `
                -ExpectedGuardianPid $ExpectedGuardianPid -ExpectedProcesses $ExpectedProcesses -ExpectedCampaigns $ExpectedCampaigns `
                -ExpectedMinimumDiskFreeGiB $ExpectedMinimumDiskFreeGiB
        }
        catch { return $null }
        $evidence = [pscustomobject][ordered]@{
            attempt = $Attempt
            pid = [uint32]$launch.ProcessId
            exact_command_line = [string]$launch.ExactCommandLine
            command_line_sha256 = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes([string]$launch.ExactCommandLine))
            creation_filetime_utc = [int64]$launch.CreationFileTimeUtc
            executable_path = $monitorActualExecutablePath
            executable_sha256 = $ExpectedPowerShellSha256
            exit_code = $exit
            stdout_file = [IO.Path]::GetFileName($stdout)
            stdout_bytes = $stdoutLength
            stdout_sha256 = Get-FaultGateSha256Bytes -Bytes $monitorReportBytes
            stderr_file = [IO.Path]::GetFileName($stderr)
            stderr_bytes = $stderrLength
            stderr_sha256 = Get-FaultGateSha256File -Path $stderr
            report_sha256 = Get-FaultGateSha256Bytes -Bytes $monitorReportBytes
            report = $monitor
        }
        if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $DeadlineMonotonicTick) -le 0) { throw "Monitor evidence parsing exceeded the startup deadline." }
        return $evidence
    }
    finally {
        try {
            if (-not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 0)) {
                [RawQualificationNative]::TerminateProcessHandle($launch.ProcessHandle, $script:FaultGateFallbackExitCode)
                $remainingFinallyMilliseconds = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $DeadlineMonotonicTick
                $finallyDrainMilliseconds = [int][Math]::Min([int64]$DrainCapMilliseconds, $remainingFinallyMilliseconds)
                if ($finallyDrainMilliseconds -le 0 -or -not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, $finallyDrainMilliseconds) -or
                    [uint32][RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle) -ne $script:FaultGateFallbackExitCode) {
                    throw "Monitor attempt did not drain by retained handle inside the absolute startup deadline."
                }
            }
        }
        finally { $null = [RawQualificationNative]::CloseHandle($launch.ProcessHandle) }
    }
}

function Assert-FaultGateNoPromotion {
    param([Parameter(Mandatory = $true)] [string] $RunRoot, [Parameter(Mandatory = $true)] $LauncherJournal)
    $forbiddenEvents = @(
        "CAPTURE_DRAINING_STARTED", "CAMPAIGN_TERMINAL_EVALUATION_STARTED", "INDEPENDENT_VERIFICATION_STAGE_STARTED",
        "INDEPENDENT_CAMPAIGN_VERIFIED", "QUALIFICATION_COMMITTED"
    )
    foreach ($event in $forbiddenEvents) {
        if (@(Get-FaultGateJournalEvents -Journal $LauncherJournal -Event $event).Count -ne 0) { throw "Failure run reached forbidden promotion event: $event" }
    }
    $terminalEvents = @(Get-FaultGateJournalEvents -Journal $LauncherJournal -Event "LAUNCHER_TERMINAL")
    if ($terminalEvents.Count -ne 1 -or [string]$terminalEvents[0].body.payload.status -cne "FAILED") { throw "Failure run lacks one terminal FAILED launcher event." }
    $forbiddenNames = @("campaign.json", "generation.json", "qualification.json")
    $files = @(Get-FaultGateSafeTreeItems -Root $RunRoot | Where-Object { -not $_.PSIsContainer })
    if (@($files | Where-Object { $_.Name -cin $forbiddenNames }).Count -ne 0) { throw "Failure run contains a committed campaign/generation/qualification manifest." }
    if (Test-Path -LiteralPath (Join-Path $RunRoot "independent-verification")) { throw "Failure run entered independent verification." }
}

function Test-FaultGateHealthyPostPrefixEvent {
    param(
        [Parameter(Mandatory = $true)] $Entry,
        [Parameter(Mandatory = $true)] [string] $ExpectedSessionId,
        $FinalRawGeneration,
        [ref] $PreviousHeartbeat,
        [hashtable] $PreviousSegments,
        [switch] $AllowRawLinkageDeferral
    )
    $generation = Get-FaultGateJsonUnsignedInteger -Value $Entry.body.generation_index -Label "healthy suffix generation"
    $channel = Get-FaultGateJsonNonEmptyString -Value $Entry.body.channel -Label "healthy suffix channel"
    $event = Get-FaultGateJsonNonEmptyString -Value $Entry.body.payload.event -Label "healthy suffix event"
    if ($generation -ne 0 -or $channel -cne "CHILD_STDOUT" -or $event -cnotin @("HEARTBEAT_DURABLE", "SEGMENT_DURABLE")) {
        throw "Post-prefix event is not an allowed healthy generation-0 CHILD_STDOUT event."
    }
    $payload = $Entry.body.payload
    if ($event -ceq "HEARTBEAT_DURABLE") {
        $heartbeatNames = @(
            "depth_durable", "depth_last_durable_mono_ns", "depth_last_market_message_mono_ns", "depth_last_socket_activity_mono_ns", "depth_queue_records", "depth_received",
            "event", "schema", "session_id", "telemetry_durable_through_offset", "telemetry_mono_ns", "telemetry_record_index", "telemetry_record_sha256",
            "trade_durable", "trade_last_durable_mono_ns", "trade_last_market_message_mono_ns", "trade_last_socket_activity_mono_ns", "trade_queue_records", "trade_received"
        )
        Assert-FaultGateExactProperties -Value $payload -Names $heartbeatNames -Label "healthy suffix heartbeat"
        $schema = Get-FaultGateJsonNonEmptyString -Value $payload.schema -Label "healthy suffix heartbeat schema"
        $session = Get-FaultGateJsonNonEmptyString -Value $payload.session_id -Label "healthy suffix heartbeat session"
        Assert-FaultGateEvidenceDigest -Value $payload.telemetry_record_sha256 -Label "healthy suffix heartbeat telemetry digest"
        $values = [ordered]@{}
        foreach ($field in @(
            "telemetry_record_index", "telemetry_durable_through_offset", "telemetry_mono_ns", "depth_received", "depth_durable", "depth_queue_records",
            "depth_last_socket_activity_mono_ns", "depth_last_market_message_mono_ns", "depth_last_durable_mono_ns", "trade_received", "trade_durable",
            "trade_queue_records", "trade_last_socket_activity_mono_ns", "trade_last_market_message_mono_ns", "trade_last_durable_mono_ns"
        )) { $values[$field] = Get-FaultGateJsonUnsignedInteger -Value $payload.$field -Label "healthy suffix heartbeat $field" }
        if ($schema -cne "HeartbeatProcessEventV1" -or $session -cne $ExpectedSessionId -or
            $values.telemetry_durable_through_offset -eq 0 -or $values.telemetry_mono_ns -eq 0 -or
            $values.depth_durable -gt $values.depth_received -or $values.trade_durable -gt $values.trade_received -or
            $values.depth_last_market_message_mono_ns -gt $values.depth_last_socket_activity_mono_ns -or
            $values.trade_last_market_message_mono_ns -gt $values.trade_last_socket_activity_mono_ns -or
            $values.depth_last_socket_activity_mono_ns -gt $values.telemetry_mono_ns -or
            $values.trade_last_socket_activity_mono_ns -gt $values.telemetry_mono_ns) { throw "Healthy post-prefix heartbeat is semantically invalid." }
        if ($null -eq $FinalRawGeneration -or $null -eq $FinalRawGeneration.telemetry) {
            throw "Healthy post-prefix heartbeat lacks a final durable telemetry linkage."
        }
        $telemetryRows = @($FinalRawGeneration.telemetry.verified_records | Where-Object {
            [uint64]$_.record_index -eq [uint64]$values.telemetry_record_index
        })
        if ($telemetryRows.Count -eq 1) {
            $telemetryRow = $telemetryRows[0]
            $telemetryRecord = $telemetryRow.record
            if ([uint64]$telemetryRow.durable_through_offset -ne [uint64]$values.telemetry_durable_through_offset -or
                [string]$telemetryRow.record_sha256 -cne [string]$payload.telemetry_record_sha256 -or
                [uint64]$telemetryRecord.mono_ns -ne [uint64]$values.telemetry_mono_ns) {
                throw "Healthy post-prefix heartbeat identity differs from its exact durable telemetry record."
            }
            foreach ($field in @(
                "depth_received", "depth_durable", "depth_queue_records", "depth_last_socket_activity_mono_ns", "depth_last_market_message_mono_ns", "depth_last_durable_mono_ns",
                "trade_received", "trade_durable", "trade_queue_records", "trade_last_socket_activity_mono_ns", "trade_last_market_message_mono_ns", "trade_last_durable_mono_ns"
            )) {
                if ([uint64]$telemetryRecord.$field -ne [uint64]$values[$field]) { throw "Healthy post-prefix heartbeat field $field differs from durable telemetry." }
            }
        }
        elseif ($telemetryRows.Count -ne 0 -or -not $AllowRawLinkageDeferral -or
            $values.telemetry_record_index -lt [uint64]@($FinalRawGeneration.telemetry.verified_records).Count) {
            throw "Healthy post-prefix heartbeat telemetry record is absent or ambiguous."
        }
        if ($null -eq $PreviousHeartbeat.Value -and $values.telemetry_record_index -ne 0) {
            throw "First healthy heartbeat does not publish telemetry record zero."
        }
        $expectedHeartbeatIndex = if ($null -ne $PreviousHeartbeat.Value) {
            Get-FaultGateUInt64Successor -Value ([uint64]$PreviousHeartbeat.Value.telemetry_record_index) -Label "healthy heartbeat telemetry index"
        } else { [uint64]0 }
        if ($null -ne $PreviousHeartbeat.Value -and
            ($values.telemetry_record_index -ne $expectedHeartbeatIndex -or
             $values.telemetry_durable_through_offset -le [uint64]$PreviousHeartbeat.Value.telemetry_durable_through_offset -or
             $values.telemetry_mono_ns -le [uint64]$PreviousHeartbeat.Value.telemetry_mono_ns -or
             $values.depth_received -lt [uint64]$PreviousHeartbeat.Value.depth_received -or $values.depth_durable -lt [uint64]$PreviousHeartbeat.Value.depth_durable -or
             $values.trade_received -lt [uint64]$PreviousHeartbeat.Value.trade_received -or $values.trade_durable -lt [uint64]$PreviousHeartbeat.Value.trade_durable)) {
            throw "Healthy post-prefix heartbeat regressed."
        }
        $PreviousHeartbeat.Value = [pscustomobject]$values
        return
    }
    Assert-FaultGateExactProperties -Value $payload -Names @("event", "schema", "segment", "session_id") -Label "healthy suffix segment event"
    $schema = Get-FaultGateJsonNonEmptyString -Value $payload.schema -Label "healthy suffix segment schema"
    $session = Get-FaultGateJsonNonEmptyString -Value $payload.session_id -Label "healthy suffix segment session"
    Assert-FaultGateJsonObject -Value $payload.segment -Label "healthy suffix segment"
    Assert-FaultGateExactProperties -Value $payload.segment -Names @(
        "connection_epoch", "durable_through_offset", "first_frame_index", "last_frame_index", "manifest_durable_through_offset", "manifest_record_index",
        "manifest_record_sha256", "previous_segment_terminal_sha256", "raw_file", "records", "schema", "segment_index", "stream", "terminal_record_sha256"
    ) -Label "healthy suffix segment"
    $segment = $payload.segment
    $segmentSchema = Get-FaultGateJsonNonEmptyString -Value $segment.schema -Label "healthy suffix segment schema"
    $streamName = Get-FaultGateJsonNonEmptyString -Value $segment.stream -Label "healthy suffix segment stream"
    $epoch = Get-FaultGateJsonNonEmptyString -Value $segment.connection_epoch -Label "healthy suffix segment epoch"
    $segmentIndex = Get-FaultGateJsonUnsignedInteger -Value $segment.segment_index -Label "healthy suffix segment index"
    $rawFile = Get-FaultGateJsonNonEmptyString -Value $segment.raw_file -Label "healthy suffix segment raw file"
    $firstFrame = Get-FaultGateJsonUnsignedInteger -Value $segment.first_frame_index -Label "healthy suffix segment first frame"
    $lastFrame = Get-FaultGateJsonUnsignedInteger -Value $segment.last_frame_index -Label "healthy suffix segment last frame"
    $records = Get-FaultGateJsonUnsignedInteger -Value $segment.records -Label "healthy suffix segment records"
    $offset = Get-FaultGateJsonUnsignedInteger -Value $segment.durable_through_offset -Label "healthy suffix segment offset"
    $manifestIndex = Get-FaultGateJsonUnsignedInteger -Value $segment.manifest_record_index -Label "healthy suffix segment manifest index"
    $manifestOffset = Get-FaultGateJsonUnsignedInteger -Value $segment.manifest_durable_through_offset -Label "healthy suffix segment manifest offset"
    foreach ($digestField in @("previous_segment_terminal_sha256", "terminal_record_sha256", "manifest_record_sha256")) { Assert-FaultGateEvidenceDigest -Value $segment.$digestField -Label "healthy suffix segment $digestField" }
    $expectedSegmentRecords = Get-FaultGateInclusiveCountUInt64 -First $firstFrame -Last $lastFrame -Label "healthy suffix segment frame range"
    if ($schema -cne "SegmentDurableProcessEventV1" -or $session -cne $ExpectedSessionId -or $segmentSchema -cne "DurableSegmentEventV1" -or
        $streamName -cnotin @("depth", "trade") -or $rawFile -cne ("segment-{0:D6}.bnraw" -f $segmentIndex) -or
        $records -eq 0 -or $records -ne $expectedSegmentRecords -or $offset -eq 0 -or
        $manifestIndex -ne $segmentIndex -or $manifestOffset -eq 0) { throw "Healthy post-prefix segment event is semantically invalid." }
    if ($null -ne $PreviousSegments) {
        if ($PreviousSegments.ContainsKey($streamName)) {
            $previousSegment = $PreviousSegments[$streamName]
            $expectedSegmentIndex = Get-FaultGateUInt64Successor -Value ([uint64]$previousSegment.segment_index) -Label "healthy suffix segment index"
            $expectedFirstFrame = Get-FaultGateUInt64Successor -Value ([uint64]$previousSegment.last_frame_index) -Label "healthy suffix segment first frame"
            if ($segmentIndex -ne $expectedSegmentIndex -or
                $firstFrame -ne $expectedFirstFrame -or
                [string]$segment.previous_segment_terminal_sha256 -cne [string]$previousSegment.terminal_record_sha256) {
                throw "Healthy post-prefix segment publication replayed or broke its per-stream lineage."
            }
        }
        elseif ($segmentIndex -ne 0 -or $firstFrame -ne 0 -or [string]$segment.previous_segment_terminal_sha256 -cne $script:FaultGateZeroDigest) {
            throw "First healthy post-prefix segment publication is not a per-stream root."
        }
    }
    if ($null -eq $FinalRawGeneration) {
        throw "Healthy post-prefix segment lacks a final raw generation linkage."
    }
    $stream = @($FinalRawGeneration.streams | Where-Object { [string]$_.stream -ceq $streamName })
    if ($stream.Count -ne 1) {
        throw "Healthy post-prefix segment stream is absent from final raw evidence."
    }
    $transport = @($FinalRawGeneration.transports | Where-Object { [string]$_.stream -ceq $streamName })
    if ($transport.Count -ne 1 -or [string]$transport[0].connection_epoch -cne $epoch) { throw "Healthy post-prefix segment transport epoch is invalid." }
    $verified = @($stream[0].verified_segments | Where-Object { [uint64]$_.segment_index -eq $segmentIndex -and [bool]$_.sealed })
    if ($verified.Count -eq 0 -and $AllowRawLinkageDeferral) {
        if ($null -ne $PreviousSegments) {
            $PreviousSegments[$streamName] = [pscustomobject][ordered]@{
                segment_index = $segmentIndex; last_frame_index = $lastFrame; terminal_record_sha256 = [string]$segment.terminal_record_sha256
            }
        }
        return
    }
    $manifestRecords = @($stream[0].manifest_verified_records)
    $manifestRecord = if ($segmentIndex -lt [uint64]$manifestRecords.Count) { $manifestRecords[[int]$segmentIndex] } else { $null }
    $expectedPreviousSegmentSha = if ($segmentIndex -eq 0) { $script:FaultGateZeroDigest } else {
        $predecessor = @($stream[0].verified_segments | Where-Object { [uint64]$_.segment_index -eq ($segmentIndex - 1) -and [bool]$_.sealed })
        if ($predecessor.Count -ne 1) { throw "Healthy post-prefix segment predecessor is absent or ambiguous." }
        [string]$predecessor[0].raw.terminal_record_sha256
    }
    if ($null -eq $manifestRecord -or $verified.Count -ne 1 -or [string]$verified[0].raw.raw_file -cne $rawFile -or [string]$verified[0].raw.connection_epoch -cne $epoch -or
        [uint64]$verified[0].raw.first_frame_index -ne $firstFrame -or [uint64]$verified[0].raw.last_frame_index -ne $lastFrame -or
        [uint64]$verified[0].raw.durable_records -ne $records -or [uint64]$verified[0].raw.durable_through_offset -ne $offset -or
        [string]$verified[0].raw.terminal_record_sha256 -cne [string]$segment.terminal_record_sha256 -or
        [uint64]$manifestRecord.record_index -ne $manifestIndex -or [uint64]$manifestRecord.verified_through_offset -ne $manifestOffset -or
        [string]$manifestRecord.terminal_record_sha256 -cne [string]$segment.manifest_record_sha256 -or
        [string]$segment.previous_segment_terminal_sha256 -cne $expectedPreviousSegmentSha) {
        throw "Healthy post-prefix segment event is not linked to the final verified raw segment."
    }
    if ($null -ne $PreviousSegments) {
        $PreviousSegments[$streamName] = [pscustomobject][ordered]@{
            segment_index = $segmentIndex; last_frame_index = $lastFrame; terminal_record_sha256 = [string]$segment.terminal_record_sha256
        }
    }
}

function Test-FaultGateHealthyGenerationZeroPrefix {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] [uint64] $Records,
        [Parameter(Mandatory = $true)] [ValidateSet("BTCUSDT", "ETHUSDT")] [string] $Symbol,
        [Parameter(Mandatory = $true)] $FinalRawGeneration,
        [Parameter(Mandatory = $true)] [string] $ExpectedCampaignStartupSha256,
        [Parameter(Mandatory = $true)] [string] $Label,
        [switch] $AllowRawLinkageDeferral
    )
    $entries = @($Journal.entries)
    if ($Records -lt 8 -or $Records -gt [uint64]$entries.Count -or [string]$FinalRawGeneration.symbol -cne $Symbol) {
        throw "$Label lacks a complete healthy generation-0 setup and durable heartbeat."
    }
    $expectedSetup = @("CAMPAIGN_STARTED", "GENERATION_LAUNCHED", "PROCESS_STARTED", "TRANSPORT_CONNECTED", "TRANSPORT_CONNECTED")
    for ($setupIndex = 0; $setupIndex -lt $expectedSetup.Count; $setupIndex++) {
        $event = Get-FaultGateJsonNonEmptyString -Value $entries[$setupIndex].body.payload.event -Label "$Label setup event $setupIndex"
        if ($event -cne $expectedSetup[$setupIndex]) { throw "$Label setup FSM differs at record $setupIndex." }
    }
    $postTransportEvents = @(
        (Get-FaultGateJsonNonEmptyString -Value $entries[5].body.payload.event -Label "$Label post-transport event 5"),
        (Get-FaultGateJsonNonEmptyString -Value $entries[6].body.payload.event -Label "$Label post-transport event 6")
    )
    if (@($postTransportEvents | Where-Object { $_ -ceq "INITIAL_ACTIVE_REGISTERED" }).Count -ne 1 -or
        @($postTransportEvents | Where-Object { $_ -ceq "SNAPSHOT_DURABLE" }).Count -ne 1) {
        throw "$Label must contain one INITIAL_ACTIVE_REGISTERED and one SNAPSHOT_DURABLE after both transports."
    }
    $initialPosition = if ($postTransportEvents[0] -ceq "INITIAL_ACTIVE_REGISTERED") { 5 } else { 6 }
    $snapshotPosition = if ($initialPosition -eq 5) { 6 } else { 5 }
    $sessionId = Get-FaultGatePortableLeafComponent -Value $FinalRawGeneration.session_id -Label "$Label session_id"
    $sessionDirectory = [IO.Path]::GetFullPath([string]$FinalRawGeneration.session_directory)
    $generationsDirectory = Split-Path -Path $sessionDirectory -Parent
    $campaignDirectory = Split-Path -Path $generationsDirectory -Parent
    $campaignId = [IO.Path]::GetFileName($campaignDirectory)
    $campaignStart = $entries[0]
    Assert-FaultGateExactProperties -Value $campaignStart.body.payload -Names @("campaign_id", "event", "startup_sha256") -Label "$Label CAMPAIGN_STARTED payload"
    Assert-FaultGateEvidenceDigest -Value $campaignStart.body.payload.startup_sha256 -Label "$Label campaign startup digest"
    if ($null -ne $campaignStart.body.generation_index -or [string]$campaignStart.body.channel -cne "CAMPAIGN" -or
        [string]$campaignStart.body.payload.campaign_id -cne $campaignId -or $campaignId -cnotmatch ('^[0-9]+-' + $Symbol + '-raw-[0-9a-f]{12}$') -or
        [string]$campaignStart.body.payload.startup_sha256 -cne $ExpectedCampaignStartupSha256) {
        throw "$Label CAMPAIGN_STARTED identity is invalid."
    }
    $launch = $entries[1]
    Assert-FaultGateExactProperties -Value $launch.body.payload -Names @("duration_s", "event") -Label "$Label GENERATION_LAUNCHED payload"
    $launchDuration = Get-FaultGateJsonUnsignedInteger -Value $launch.body.payload.duration_s -Label "$Label launch duration"
    if ([uint64]$launch.body.generation_index -ne 0 -or [string]$launch.body.channel -cne "CAMPAIGN" -or
        $launchDuration -ne [uint64]$FinalRawGeneration.telemetry.duration_requested_s) { throw "$Label generation launch scope/duration is invalid." }
    $process = $entries[2]
    Assert-FaultGateExactProperties -Value $process.body.payload -Names @("event", "generation_index", "process_id", "schema", "session_dir", "session_id", "spec_revision", "startup_manifest_sha256", "symbol") -Label "$Label PROCESS_STARTED payload"
    $processGeneration = Get-FaultGateJsonUnsignedInteger -Value $process.body.payload.generation_index -Label "$Label PROCESS_STARTED generation"
    $processPid = Get-FaultGateJsonUnsignedInteger -Value $process.body.payload.process_id -Label "$Label PROCESS_STARTED pid" -Maximum ([uint32]::MaxValue)
    Assert-FaultGateEvidenceDigest -Value $process.body.payload.startup_manifest_sha256 -Label "$Label PROCESS_STARTED startup digest"
    if ([uint64]$process.body.generation_index -ne 0 -or [string]$process.body.channel -cne "CHILD_STDOUT" -or $processGeneration -ne 0 -or $processPid -eq 0 -or
        [string]$process.body.payload.schema -cne "CaptureProcessEventV1" -or [string]$process.body.payload.session_id -cne $sessionId -or
        -not [IO.Path]::GetFullPath([string]$process.body.payload.session_dir).Equals($sessionDirectory, [StringComparison]::OrdinalIgnoreCase) -or
        [string]$process.body.payload.spec_revision -cne [string]$FinalRawGeneration.spec_revision -or
        [string]$process.body.payload.startup_manifest_sha256 -cne [string]$FinalRawGeneration.startup_sha256 -or [string]$process.body.payload.symbol -cne $Symbol) {
        throw "$Label PROCESS_STARTED identity is invalid."
    }
    $expectedTransportShas = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($transport in @($FinalRawGeneration.transports)) { $null = $expectedTransportShas.Add([string]$transport.campaign_event.record_sha256) }
    for ($transportPosition = 3; $transportPosition -le 4; $transportPosition++) {
        if ([uint64]$entries[$transportPosition].body.generation_index -ne 0 -or [string]$entries[$transportPosition].body.channel -cne "CHILD_STDOUT" -or
            -not $expectedTransportShas.Remove([string]$entries[$transportPosition].record_sha256)) {
            throw "$Label TRANSPORT_CONNECTED records do not equal the verified depth/trade handshakes."
        }
    }
    if ($expectedTransportShas.Count -ne 0) { throw "$Label omits a verified transport handshake." }
    $initialActive = $entries[$initialPosition]
    Assert-FaultGateExactProperties -Value $initialActive.body.payload -Names @("event") -Label "$Label INITIAL_ACTIVE_REGISTERED payload"
    if ([uint64]$initialActive.body.generation_index -ne 0 -or [string]$initialActive.body.channel -cne "SUPERVISOR") { throw "$Label initial active registration scope is invalid." }
    if ([uint64]$entries[$snapshotPosition].body.generation_index -ne 0 -or [string]$entries[$snapshotPosition].body.channel -cne "CHILD_STDOUT" -or
        [string]$entries[$snapshotPosition].record_sha256 -cne [string]$FinalRawGeneration.snapshot.campaign_event.record_sha256) {
        throw "$Label SNAPSHOT_DURABLE record differs from the verified raw snapshot event."
    }
    $previousHeartbeat = $null
    $previousSegments = @{}
    for ([uint64]$recordIndex = 7; $recordIndex -lt $Records; $recordIndex++) {
        $event = Get-FaultGateJsonNonEmptyString -Value $entries[$recordIndex].body.payload.event -Label "$Label recurrent event $recordIndex"
        if ($event -cnotin @("HEARTBEAT_DURABLE", "SEGMENT_DURABLE")) {
            throw "$Label contains a non-healthy recurrent event before the injected fault: $event"
        }
        Test-FaultGateHealthyPostPrefixEvent -Entry $entries[$recordIndex] -ExpectedSessionId $sessionId -FinalRawGeneration $FinalRawGeneration -PreviousHeartbeat ([ref]$previousHeartbeat) -PreviousSegments $previousSegments -AllowRawLinkageDeferral:$AllowRawLinkageDeferral
    }
    if ($null -eq $previousHeartbeat -or -not $previousSegments.ContainsKey("depth") -or -not $previousSegments.ContainsKey("trade")) {
        throw "$Label lacks verified heartbeat/depth/trade durable recurrent evidence."
    }
    return [pscustomobject][ordered]@{ previous_heartbeat = $previousHeartbeat; previous_segments = $previousSegments }
}

function Get-FaultGateSerdeJournalPrefixSummary {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] [uint64] $Records,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $entries = @($Journal.entries)
    if ($Records -eq 0 -or $Records -gt [uint64]$entries.Count) { throw "$Label record boundary is outside the journal." }
    $prefixBytes = [Collections.Generic.List[byte]]::new()
    for ([uint64]$prefixIndex = 0; $prefixIndex -lt $Records; $prefixIndex++) {
        $prefixBytes.AddRange([byte[]](ConvertTo-FaultGateSerdeCompactJsonBytes -Value $entries[$prefixIndex]))
        $prefixBytes.Add([byte]10)
    }
    return [pscustomobject][ordered]@{
        records = $Records; terminal_record_sha256 = [string]$entries[$Records - 1].record_sha256
        file_bytes = [uint64]$prefixBytes.Count; file_sha256 = Get-FaultGateSha256Bytes -Bytes $prefixBytes.ToArray()
    }
}

function Test-FaultGatePreInjectionCampaignWindow {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] $PreFaultPrefix,
        [Parameter(Mandatory = $true)] [ValidateSet("BTCUSDT", "ETHUSDT")] [string] $Symbol,
        [Parameter(Mandatory = $true)] [string] $ExpectedSessionId,
        [string] $ExpectedCampaignStartupSha256 = "",
        $FinalRawGeneration = $null
    )
    Assert-FaultGateJsonObject -Value $PreFaultPrefix -Label "$Symbol pre-injection prefix"
    Assert-FaultGateExactProperties -Value $PreFaultPrefix -Names @("symbol", "records", "clean_tail", "terminal_record_sha256", "file_sha256") -Label "$Symbol pre-injection prefix"
    $prefixRecords = Get-FaultGateJsonUnsignedInteger -Value $PreFaultPrefix.records -Label "$Symbol pre-injection prefix records"
    $prefixClean = Get-FaultGateJsonBoolean -Value $PreFaultPrefix.clean_tail -Label "$Symbol pre-injection prefix clean_tail"
    Assert-FaultGateEvidenceDigest -Value $PreFaultPrefix.terminal_record_sha256 -Label "$Symbol pre-injection prefix terminal digest"
    Assert-FaultGateEvidenceDigest -Value $PreFaultPrefix.file_sha256 -Label "$Symbol pre-injection prefix file digest"
    $entries = @($Journal.entries)
    if ([string]$PreFaultPrefix.symbol -cne $Symbol -or -not $prefixClean -or $prefixRecords -eq 0 -or
        $prefixRecords -gt [uint64]$entries.Count -or [uint64]$Journal.records -ne [uint64]$entries.Count -or
        [string]$entries[$prefixRecords - 1].record_sha256 -cne [string]$PreFaultPrefix.terminal_record_sha256) {
        throw "$Symbol post-request journal does not extend the exact final pre-request prefix."
    }
    $prefixSummary = Get-FaultGateSerdeJournalPrefixSummary -Journal $Journal -Records $prefixRecords -Label "$Symbol retained pre-request journal prefix"
    if ([string]$prefixSummary.file_sha256 -cne [string]$PreFaultPrefix.file_sha256 -or
        [string]$prefixSummary.terminal_record_sha256 -cne [string]$PreFaultPrefix.terminal_record_sha256) {
        throw "$Symbol retained pre-request journal prefix bytes do not match its frozen file digest."
    }
    $launches = @(Get-FaultGateJournalEvents -Journal $Journal -Event "GENERATION_LAUNCHED")
    $starts = @(Get-FaultGateJournalEvents -Journal $Journal -Event "PROCESS_STARTED")
    if ($launches.Count -ne 1 -or $starts.Count -ne 1 -or
        (Get-FaultGateJsonUnsignedInteger -Value $launches[0].body.generation_index -Label "$Symbol pre-injection launch generation") -ne 0 -or
        (Get-FaultGateJsonUnsignedInteger -Value $starts[0].body.generation_index -Label "$Symbol pre-injection start generation") -ne 0) {
        throw "$Symbol post-request journal crossed the generation-0-only boundary."
    }
    $prefixState = if ($null -ne $FinalRawGeneration) {
        Test-FaultGateHealthyGenerationZeroPrefix -Journal $Journal -Records $prefixRecords -Symbol $Symbol -FinalRawGeneration $FinalRawGeneration -ExpectedCampaignStartupSha256 $ExpectedCampaignStartupSha256 -Label "$Symbol pre-request healthy prefix"
    } else { $null }
    $previousHeartbeat = if ($null -ne $prefixState) { $prefixState.previous_heartbeat } else { $null }
    $previousSegments = if ($null -ne $prefixState) { $prefixState.previous_segments } else { @{} }
    foreach ($entry in @($entries | Where-Object { [uint64]$_.body.record_index -ge $prefixRecords })) {
        Test-FaultGateHealthyPostPrefixEvent -Entry $entry -ExpectedSessionId $ExpectedSessionId -FinalRawGeneration $FinalRawGeneration -PreviousHeartbeat ([ref]$previousHeartbeat) -PreviousSegments $previousSegments -AllowRawLinkageDeferral
    }
    return [pscustomobject][ordered]@{
        symbol = $Symbol
        pre_request_records = $prefixRecords
        observed_records = [uint64]$entries.Count
        allowed_healthy_suffix_records = [uint64]($entries.Count - $prefixRecords)
        terminal_record_sha256 = [string]$Journal.terminal_record_sha256
    }
}

function Test-FaultGateInjectedCampaignCausality {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] [ValidateSet("BTCUSDT", "ETHUSDT")] [string] $Symbol,
        [Parameter(Mandatory = $true)] [string] $LauncherFailure,
        [Parameter(Mandatory = $true)] $PreFaultPrefix,
        [Parameter(Mandatory = $true)] [uint64] $InjectionRequestedWallNs,
        [string] $ExpectedDepthEpoch = "epoch-0",
        [string] $ExpectedCampaignStartupSha256 = "",
        $FinalRawGeneration = $null
    )
    Assert-FaultGateJsonObject -Value $PreFaultPrefix -Label "$Symbol pre-fault campaign prefix"
    Assert-FaultGateExactProperties -Value $PreFaultPrefix -Names @("symbol", "records", "clean_tail", "terminal_record_sha256", "file_sha256") -Label "$Symbol pre-fault campaign prefix"
    $prefixSymbol = Get-FaultGateJsonNonEmptyString -Value $PreFaultPrefix.symbol -Label "$Symbol pre-fault prefix symbol"
    $prefixRecords = Get-FaultGateJsonUnsignedInteger -Value $PreFaultPrefix.records -Label "$Symbol pre-fault prefix records"
    $prefixClean = Get-FaultGateJsonBoolean -Value $PreFaultPrefix.clean_tail -Label "$Symbol pre-fault prefix clean_tail"
    Assert-FaultGateEvidenceDigest -Value $PreFaultPrefix.terminal_record_sha256 -Label "$Symbol pre-fault prefix terminal digest"
    Assert-FaultGateEvidenceDigest -Value $PreFaultPrefix.file_sha256 -Label "$Symbol pre-fault prefix file digest"
    if ($InjectionRequestedWallNs -eq 0 -or $prefixSymbol -cne $Symbol -or -not $prefixClean -or $prefixRecords -eq 0 -or $prefixRecords -gt [uint64]$Journal.records -or
        [string]@($Journal.entries)[$prefixRecords - 1].record_sha256 -cne [string]$PreFaultPrefix.terminal_record_sha256) {
        throw "$Symbol final campaign journal does not extend the exact clean pre-fault prefix."
    }
    $prefixSummary = Get-FaultGateSerdeJournalPrefixSummary -Journal $Journal -Records $prefixRecords -Label "$Symbol causal pre-fault journal prefix"
    if ([string]$prefixSummary.file_sha256 -cne [string]$PreFaultPrefix.file_sha256 -or
        [string]$prefixSummary.terminal_record_sha256 -cne [string]$PreFaultPrefix.terminal_record_sha256) {
        throw "$Symbol causal journal does not retain the exact pre-fault prefix bytes."
    }
    $disconnects = @(Get-FaultGateJournalEvents -Journal $Journal -Event "GENERATION_DISCONNECT_FAIL_CLOSED")
    $failures = @(Get-FaultGateJournalEvents -Journal $Journal -Event "CAMPAIGN_FAILED")
    $generationExits = @(Get-FaultGateJournalEvents -Journal $Journal -Event "GENERATION_EXITED")
    $postPrefixEntries = @(@($Journal.entries) | Where-Object { [uint64]$_.body.record_index -ge $prefixRecords })
    $expectedSessionId = if ($null -ne $FinalRawGeneration) { [string]$FinalRawGeneration.session_id } else { "session-selftest" }
    $prefixState = if ($null -ne $FinalRawGeneration) {
        Test-FaultGateHealthyGenerationZeroPrefix -Journal $Journal -Records $prefixRecords -Symbol $Symbol -FinalRawGeneration $FinalRawGeneration -ExpectedCampaignStartupSha256 $ExpectedCampaignStartupSha256 -Label "$Symbol causal healthy prefix"
    } else { $null }
    $previousHeartbeat = if ($null -ne $prefixState) { $prefixState.previous_heartbeat } else { $null }
    $previousSegments = if ($null -ne $prefixState) { $prefixState.previous_segments } else { @{} }
    $causalPhase = $false
    $causalSuffixEvents = [Collections.Generic.List[string]]::new()
    foreach ($suffixEntry in $postPrefixEntries) {
        $suffixEvent = Get-FaultGateJsonNonEmptyString -Value $suffixEntry.body.payload.event -Label "$Symbol post-prefix event"
        if ($suffixEvent -cin @("HEARTBEAT_DURABLE", "SEGMENT_DURABLE")) {
            if ($causalPhase) { throw "$Symbol contains a healthy event after its causal failure phase began." }
            Test-FaultGateHealthyPostPrefixEvent -Entry $suffixEntry -ExpectedSessionId $expectedSessionId -FinalRawGeneration $FinalRawGeneration -PreviousHeartbeat ([ref]$previousHeartbeat) -PreviousSegments $previousSegments
        }
        else {
            $causalPhase = $true
            $causalSuffixEvents.Add($suffixEvent)
        }
    }
    foreach ($causalRecord in @($disconnects) + @($failures) + @($generationExits)) {
        $causalIndex = Get-FaultGateJsonUnsignedInteger -Value $causalRecord.body.record_index -Label "$Symbol causal record index"
        $null = Get-FaultGateJsonUnsignedInteger -Value $causalRecord.body.wall_ns -Label "$Symbol causal record wall_ns"
        if ($causalIndex -lt $prefixRecords) {
            throw "$Symbol contains a causal failure event inside its authenticated healthy pre-request journal prefix."
        }
    }
    if ($Symbol -ceq "ETHUSDT") {
        if ($causalSuffixEvents.Count -ne 0 -or $disconnects.Count -ne 0 -or $failures.Count -ne 0 -or $generationExits.Count -ne 0) {
            throw "ETHUSDT campaign journal falsely attributes the injected BTC failure to the Job-contained peer."
        }
        return [pscustomobject][ordered]@{
            symbol = $Symbol; proof = "JOB_CONTAINED_PEER_WITHOUT_LOCAL_FAILURE"; disconnects = [uint64]0; campaign_failures = [uint64]0
            pre_fault_records = $prefixRecords; pre_fault_terminal_record_sha256 = [string]$PreFaultPrefix.terminal_record_sha256
        }
    }
    if ($disconnects.Count -ne 1) { throw "BTCUSDT lacks one exact generation-0 fail-closed disconnect proof." }
    Assert-FaultGateExactProperties -Value $disconnects[0].body.payload -Names @("epoch", "event", "gap_count", "outcome") -Label "BTCUSDT disconnect payload"
    $disconnectGeneration = Get-FaultGateJsonUnsignedInteger -Value $disconnects[0].body.generation_index -Label "BTCUSDT disconnect generation"
    $disconnectChannel = Get-FaultGateJsonNonEmptyString -Value $disconnects[0].body.channel -Label "BTCUSDT disconnect channel"
    $disconnectEpoch = Get-FaultGateJsonNonEmptyString -Value $disconnects[0].body.payload.epoch -Label "BTCUSDT disconnect epoch"
    $disconnectEvent = Get-FaultGateJsonNonEmptyString -Value $disconnects[0].body.payload.event -Label "BTCUSDT disconnect event"
    $disconnectGap = Get-FaultGateJsonUnsignedInteger -Value $disconnects[0].body.payload.gap_count -Label "BTCUSDT disconnect gap count"
    $disconnectOutcome = Get-FaultGateJsonNonEmptyString -Value $disconnects[0].body.payload.outcome -Label "BTCUSDT disconnect outcome"
    if ($disconnectGeneration -ne 0 -or $disconnectChannel -cne "SUPERVISOR" -or $disconnectEvent -cne "GENERATION_DISCONNECT_FAIL_CLOSED" -or
        $disconnectGap -ne 1 -or $disconnectOutcome -cne "ActiveFailed" -or $disconnectEpoch -cne $ExpectedDepthEpoch) {
        throw "BTCUSDT lacks one exact generation-0 fail-closed disconnect proof."
    }
    $disconnectRecordIndex = [uint64]$disconnects[0].body.record_index
    if ($generationExits.Count -gt 1) { throw "BTCUSDT contains duplicate optional GENERATION_EXITED evidence." }
    if ($generationExits.Count -eq 1) {
        Assert-FaultGateExactProperties -Value $generationExits[0].body.payload -Names @("code", "event", "success") -Label "BTCUSDT optional generation exit payload"
        $exitGeneration = Get-FaultGateJsonUnsignedInteger -Value $generationExits[0].body.generation_index -Label "BTCUSDT optional exit generation"
        $exitChannel = Get-FaultGateJsonNonEmptyString -Value $generationExits[0].body.channel -Label "BTCUSDT optional exit channel"
        $exitCode = Get-FaultGateJsonUnsignedInteger -Value $generationExits[0].body.payload.code -Label "BTCUSDT optional exit code" -Maximum ([uint32]::MaxValue)
        $exitEvent = Get-FaultGateJsonNonEmptyString -Value $generationExits[0].body.payload.event -Label "BTCUSDT optional exit event"
        $exitSuccess = Get-FaultGateJsonBoolean -Value $generationExits[0].body.payload.success -Label "BTCUSDT optional exit success"
        $exitRecordIndex = Get-FaultGateJsonUnsignedInteger -Value $generationExits[0].body.record_index -Label "BTCUSDT optional exit record index"
        if ($exitGeneration -ne 0 -or $exitChannel -cne "CAMPAIGN" -or $exitCode -ne $script:FaultGateTargetExitCode -or
            $exitEvent -cne "GENERATION_EXITED" -or $exitSuccess -or $exitRecordIndex -ge $disconnectRecordIndex) {
            throw "BTCUSDT optional GENERATION_EXITED does not bind the injected retained-handle exit."
        }
    }
    foreach ($failure in $failures) {
        Assert-FaultGateExactProperties -Value $failure.body.payload -Names @("error", "event", "stage") -Label "BTCUSDT campaign failure payload"
        $failureChannel = Get-FaultGateJsonNonEmptyString -Value $failure.body.channel -Label "BTCUSDT failure channel"
        $failureError = Get-FaultGateJsonNonEmptyString -Value $failure.body.payload.error -Label "BTCUSDT failure error"
        $failureEvent = Get-FaultGateJsonNonEmptyString -Value $failure.body.payload.event -Label "BTCUSDT failure event"
        $failureStage = Get-FaultGateJsonNonEmptyString -Value $failure.body.payload.stage -Label "BTCUSDT failure stage"
        if ($null -ne $failure.body.generation_index -or $failureChannel -cne "CAMPAIGN" -or $failureEvent -cne "CAMPAIGN_FAILED" -or
            $failureStage -cne "RUNTIME" -or
            $failureError -cne "generation 0 exited without COMPLETE terminal evidence") {
            throw "BTCUSDT CAMPAIGN_FAILED is outside the exact injected generation-0 consequence."
        }
    }
    $earlyHeartbeatFailures = @(
        "BTCUSDT campaign heartbeat reported failure.",
        "BTCUSDT campaign heartbeat regressed or has no active generation."
    )
    $disconnectSuccessorIndex = Get-FaultGateUInt64Successor -Value $disconnectRecordIndex -Label "BTCUSDT disconnect terminal position"
    if ($LauncherFailure -cin $earlyHeartbeatFailures) {
        if ($failures.Count -gt 1) { throw "BTCUSDT early-heartbeat race contains duplicate CAMPAIGN_FAILED records." }
        if ($failures.Count -eq 0) {
            if ($disconnectSuccessorIndex -ne [uint64]$Journal.records) { throw "BTCUSDT early-heartbeat proof has unclassified journal events after its terminal disconnect." }
            $proof = "TERMINAL_DISCONNECT_BEFORE_CAMPAIGN_FAILED"
        }
        else { $proof = "DISCONNECT_AND_CAMPAIGN_FAILED" }
    }
    else {
        if ($failures.Count -ne 1) { throw "BTCUSDT launcher failure class requires one exact CAMPAIGN_FAILED record." }
        $proof = "DISCONNECT_AND_CAMPAIGN_FAILED"
    }
    $failureSuccessorIndex = if ($failures.Count -eq 1) {
        Get-FaultGateUInt64Successor -Value ([uint64]$failures[0].body.record_index) -Label "BTCUSDT campaign failure terminal position"
    } else { [uint64]0 }
    if ($failures.Count -eq 1 -and
        ([uint64]$failures[0].body.record_index -le $disconnectRecordIndex -or $failureSuccessorIndex -ne [uint64]$Journal.records)) {
        throw "BTCUSDT CAMPAIGN_FAILED is not a terminal record causally after the fail-closed disconnect."
    }
    $expectedSuffixEvents = [Collections.Generic.List[string]]::new()
    if ($generationExits.Count -eq 1) { $expectedSuffixEvents.Add("GENERATION_EXITED") }
    $expectedSuffixEvents.Add("GENERATION_DISCONNECT_FAIL_CLOSED")
    if ($failures.Count -eq 1) { $expectedSuffixEvents.Add("CAMPAIGN_FAILED") }
    if ((@($causalSuffixEvents) -join "`n") -cne (@($expectedSuffixEvents) -join "`n")) {
        throw "BTCUSDT post-fault journal suffix contains an unclassified or reordered event."
    }
    return [pscustomobject][ordered]@{
        symbol = $Symbol; proof = $proof; disconnects = [uint64]$disconnects.Count; campaign_failures = [uint64]$failures.Count
        pre_fault_records = $prefixRecords; pre_fault_terminal_record_sha256 = [string]$PreFaultPrefix.terminal_record_sha256
    }
}

function Get-FaultGateEngineProcesses {
    param([AllowEmptyCollection()] [object[]] $ProcessSnapshot)
    $names = @("raw_campaign.exe", "segmented_capture.exe", "campaign_verify.exe")
    $snapshot = if ($PSBoundParameters.ContainsKey("ProcessSnapshot")) { @($ProcessSnapshot) } else { @(Get-FaultGateProcessSnapshot) }
    return @($snapshot | Where-Object { [string]$_.Name -cin $names })
}

function Test-FaultGateQualificationPolicyShapes {
    param([Parameter(Mandatory = $true)] $Value, [Parameter(Mandatory = $true)] [string] $Label)
    foreach ($objectName in @("parameters", "verifier_policy", "coordinator_log_policy", "market_freshness_policy", "guardian_policy")) {
        Assert-FaultGateJsonObject -Value $Value.$objectName -Label "$Label $objectName"
    }
    Assert-FaultGateExactProperties -Value $Value.parameters -Names @("total_s", "rotation_s", "overlap_s", "segment_s") -Label "$Label parameters"
    foreach ($name in @("total_s", "rotation_s", "overlap_s", "segment_s")) { $null = Get-FaultGateJsonUnsignedInteger -Value $Value.parameters.$name -Label "$Label parameters.$name" }
    Assert-FaultGateExactProperties -Value $Value.verifier_policy -Names @("per_process_timeout_s", "total_post_capture_timeout_s", "maximum_artifact_bytes") -Label "$Label verifier policy"
    foreach ($name in @("per_process_timeout_s", "total_post_capture_timeout_s", "maximum_artifact_bytes")) { $null = Get-FaultGateJsonUnsignedInteger -Value $Value.verifier_policy.$name -Label "$Label verifier_policy.$name" }
    Assert-FaultGateExactProperties -Value $Value.coordinator_log_policy -Names @("maximum_stdout_bytes", "maximum_stderr_bytes", "child_stderr_events_allowed") -Label "$Label coordinator log policy"
    foreach ($name in @("maximum_stdout_bytes", "maximum_stderr_bytes", "child_stderr_events_allowed")) { $null = Get-FaultGateJsonUnsignedInteger -Value $Value.coordinator_log_policy.$name -Label "$Label coordinator_log_policy.$name" }
    Assert-FaultGateExactProperties -Value $Value.market_freshness_policy -Names @("startup_grace_s", "deadline_s") -Label "$Label market freshness policy"
    foreach ($name in @("startup_grace_s", "deadline_s")) { $null = Get-FaultGateJsonUnsignedInteger -Value $Value.market_freshness_policy.$name -Label "$Label market_freshness_policy.$name" }
    Assert-FaultGateExactProperties -Value $Value.guardian_policy -Names @(
        "pulse_file", "watchdog_ready_file", "watchdog_startup_deadline_s", "watchdog_deadline_s", "host_telemetry_gap_deadline_s",
        "maximum_dual_launch_skew_ms", "generation_terminal_deadline_s", "campaign_commit_deadline_s"
    ) -Label "$Label guardian policy"
    foreach ($name in @("pulse_file", "watchdog_ready_file")) { $null = Get-FaultGateJsonNonEmptyString -Value $Value.guardian_policy.$name -Label "$Label guardian_policy.$name" }
    foreach ($name in @("watchdog_startup_deadline_s", "watchdog_deadline_s", "host_telemetry_gap_deadline_s", "maximum_dual_launch_skew_ms", "generation_terminal_deadline_s", "campaign_commit_deadline_s")) {
        $null = Get-FaultGateJsonUnsignedInteger -Value $Value.guardian_policy.$name -Label "$Label guardian_policy.$name"
    }
}

function Test-FaultGateLauncherOutputPostCreateSchema {
    param(
        [Parameter(Mandatory = $true)] $Output,
        [Parameter(Mandatory = $true)] [uint64] $StartupMonotonicFrequency,
        [Parameter(Mandatory = $true)] [uint64] $StartupMonotonicOrigin
    )
    Assert-FaultGateJsonObject -Value $Output -Label "launcher startup output validation"
    Assert-FaultGateExactProperties -Value $Output -Names @(
        "reparse_points_rejected", "run_root_drive_device_id", "same_preflight_volume", "filesystem", "free_gib", "required_free_gib", "probe_pid",
        "probe_command_line_sha256", "probe_resume_qpc_timestamp", "probe_elapsed_qpc_ticks", "probe_monotonic_frequency", "probe_job_membership",
        "probe_parent_exit_observed_qpc_timestamp", "probe_descendant_drain_elapsed_qpc_ticks", "probe_descendant_drain_elapsed_ms",
        "probe_descendant_drain_active_processes", "probe_timeout_s", "probe_elapsed_ms", "probe_stdout_file", "probe_stdout_bytes", "probe_stdout_sha256",
        "probe_stderr_file", "probe_stderr_bytes", "probe_stderr_sha256"
    ) -Label "launcher startup output validation"
    $outputReparseRejected = Get-FaultGateJsonBoolean -Value $Output.reparse_points_rejected -Label "output reparse flag"
    $outputSameVolume = Get-FaultGateJsonBoolean -Value $Output.same_preflight_volume -Label "output same-volume flag"
    foreach ($name in @("run_root_drive_device_id", "filesystem", "probe_job_membership", "probe_stdout_file", "probe_stderr_file")) {
        $null = Get-FaultGateJsonNonEmptyString -Value $Output.$name -Label "output $name"
    }
    $freeGiB = Get-FaultGateJsonUnsignedInteger -Value $Output.free_gib -Label "output free_gib"
    $requiredFreeGiB = Get-FaultGateJsonUnsignedInteger -Value $Output.required_free_gib -Label "output required_free_gib"
    $probePid = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_pid -Label "output probe_pid" -Maximum ([uint32]::MaxValue)
    $probeResumeTick = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_resume_qpc_timestamp -Label "output probe_resume_qpc_timestamp" -Maximum ([int64]::MaxValue)
    $probeElapsedTicks = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_elapsed_qpc_ticks -Label "output probe_elapsed_qpc_ticks" -Maximum ([int64]::MaxValue)
    $probeFrequency = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_monotonic_frequency -Label "output probe_monotonic_frequency" -Maximum ([int64]::MaxValue)
    $probeParentExitTick = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_parent_exit_observed_qpc_timestamp -Label "output probe_parent_exit_observed_qpc_timestamp" -Maximum ([int64]::MaxValue)
    $probeDrainTicks = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_descendant_drain_elapsed_qpc_ticks -Label "output probe_descendant_drain_elapsed_qpc_ticks" -Maximum ([int64]::MaxValue)
    $probeDrainMilliseconds = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_descendant_drain_elapsed_ms -Label "output probe_descendant_drain_elapsed_ms"
    $probeDrainActive = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_descendant_drain_active_processes -Label "output probe_descendant_drain_active_processes" -Maximum ([uint32]::MaxValue)
    $probeTimeoutSeconds = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_timeout_s -Label "output probe_timeout_s"
    $probeElapsedMilliseconds = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_elapsed_ms -Label "output probe_elapsed_ms"
    $probeStdoutBytes = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_stdout_bytes -Label "output probe_stdout_bytes"
    $probeStderrBytes = Get-FaultGateJsonUnsignedInteger -Value $Output.probe_stderr_bytes -Label "output probe_stderr_bytes"
    foreach ($name in @("probe_command_line_sha256", "probe_stdout_sha256", "probe_stderr_sha256")) {
        Assert-FaultGateEvidenceDigest -Value $Output.$name -Label "output $name"
    }
    if ($StartupMonotonicFrequency -eq 0 -or $StartupMonotonicOrigin -eq 0 -or $probeFrequency -eq 0) {
        throw "Launcher/probe monotonic identity is invalid."
    }
    $hostFrequency = [uint64][Diagnostics.Stopwatch]::Frequency
    if ($probeParentExitTick -lt $probeResumeTick) { throw "Launcher post-create probe parent-exit chronology regressed." }
    $derivedElapsedTicks = [uint64]($probeParentExitTick - $probeResumeTick)
    $derivedElapsedMilliseconds = [uint64][decimal]::Floor(
        ([decimal]$probeElapsedTicks * [decimal]1000) / [decimal]$probeFrequency)
    $derivedDrainMilliseconds = [uint64][decimal]::Floor(
        ([decimal]$probeDrainTicks * [decimal]1000) / [decimal]$probeFrequency)
    if (-not $outputReparseRejected -or -not $outputSameVolume -or [string]$Output.filesystem -cne "NTFS" -or
        $freeGiB -lt $requiredFreeGiB -or $probePid -eq 0 -or
        $probeResumeTick -lt $StartupMonotonicOrigin -or $probeElapsedTicks -eq 0 -or
        $probeFrequency -ne $StartupMonotonicFrequency -or $probeFrequency -ne $hostFrequency -or
        $derivedElapsedTicks -ne $probeElapsedTicks -or $derivedElapsedMilliseconds -ne $probeElapsedMilliseconds -or
        [decimal]$probeElapsedTicks -gt ([decimal]20 * [decimal]$probeFrequency) -or
        $derivedDrainMilliseconds -ne $probeDrainMilliseconds -or
        [decimal]$probeDrainTicks -gt ([decimal]10 * [decimal]$probeFrequency) -or
        [string]$Output.probe_job_membership -cne "PRIMARY_AND_NESTED_BOUNDED" -or
        $probeDrainActive -ne 0 -or $probeTimeoutSeconds -ne 20 -or
        [string]$Output.probe_stdout_file -cne "post-create-volume.stdout.json" -or $probeStdoutBytes -eq 0 -or
        [string]$Output.probe_stderr_file -cne "post-create-volume.stderr.log" -or $probeStderrBytes -ne 0 -or
        [string]$Output.probe_stderr_sha256 -cne "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
        throw "Launcher post-create output/probe containment invariants are invalid."
    }
}

function Test-FaultGateLauncherStartupSchema {
    param([Parameter(Mandatory = $true)] $Startup)
    Assert-FaultGateJsonObject -Value $Startup -Label "launcher startup"
    Assert-FaultGateExactProperties -Value $Startup -Names @(
        "schema", "run_id", "mode", "run_root", "started_utc", "launcher_pid", "launcher_creation_time_utc", "launcher_executable_path",
        "launcher_executable_sha256", "launcher_command_line", "output_path_post_create", "monotonic_frequency", "monotonic_origin_qpc_timestamp",
        "parameters", "verifier_policy", "coordinator_log_policy", "market_freshness_policy", "guardian_policy", "preflight", "credentials", "order_entry"
    ) -Label "launcher startup"
    foreach ($name in @("schema", "run_id", "mode", "run_root", "started_utc", "launcher_creation_time_utc", "launcher_executable_path", "launcher_command_line", "credentials", "order_entry")) {
        $null = Get-FaultGateJsonNonEmptyString -Value $Startup.$name -Label "launcher startup $name"
    }
    if ([string]$Startup.schema -cne "RawQualificationLauncherStartupV1" -or [string]$Startup.mode -cne "Test" -or
        [string]$Startup.credentials -cne "NONE" -or [string]$Startup.order_entry -cne "ABSENT") { throw "Launcher startup schema/mode/non-trading boundary is invalid." }
    $startupMonotonicFrequency = Get-FaultGateJsonUnsignedInteger -Value $Startup.monotonic_frequency -Label "launcher startup monotonic frequency" -Maximum ([int64]::MaxValue)
    $startupMonotonicOrigin = Get-FaultGateJsonUnsignedInteger -Value $Startup.monotonic_origin_qpc_timestamp -Label "launcher startup monotonic origin" -Maximum ([int64]::MaxValue)
    if ((Get-FaultGateJsonUnsignedInteger -Value $Startup.launcher_pid -Label "launcher startup pid" -Maximum ([uint32]::MaxValue)) -eq 0 -or
        $startupMonotonicFrequency -eq 0 -or $startupMonotonicOrigin -eq 0) {
        throw "Launcher startup PID/monotonic identity is invalid."
    }
    Assert-FaultGateEvidenceDigest -Value $Startup.launcher_executable_sha256 -Label "launcher startup executable digest"
    Test-FaultGateQualificationPolicyShapes -Value $Startup -Label "launcher startup"
    if ([uint64]$Startup.parameters.total_s -ne 300 -or [uint64]$Startup.parameters.rotation_s -ne 240 -or
        [uint64]$Startup.parameters.overlap_s -ne 30 -or [uint64]$Startup.parameters.segment_s -ne 30 -or
        [uint64]$Startup.verifier_policy.per_process_timeout_s -ne 7200 -or [uint64]$Startup.verifier_policy.total_post_capture_timeout_s -ne 14400 -or
        [uint64]$Startup.verifier_policy.maximum_artifact_bytes -ne 33554432 -or [uint64]$Startup.coordinator_log_policy.maximum_stdout_bytes -ne 67108864 -or
        [uint64]$Startup.coordinator_log_policy.maximum_stderr_bytes -ne 0 -or [uint64]$Startup.coordinator_log_policy.child_stderr_events_allowed -ne 0 -or
        [uint64]$Startup.market_freshness_policy.startup_grace_s -ne 30 -or [uint64]$Startup.market_freshness_policy.deadline_s -ne 30 -or
        [string]$Startup.guardian_policy.pulse_file -cne "guardian-pulse.jsonl" -or [string]$Startup.guardian_policy.watchdog_ready_file -cne "watchdog-ready.json" -or
        [uint64]$Startup.guardian_policy.watchdog_startup_deadline_s -ne 90 -or [uint64]$Startup.guardian_policy.watchdog_deadline_s -ne 90 -or
        [uint64]$Startup.guardian_policy.host_telemetry_gap_deadline_s -ne 120 -or [uint64]$Startup.guardian_policy.maximum_dual_launch_skew_ms -ne 5000 -or
        [uint64]$Startup.guardian_policy.generation_terminal_deadline_s -ne 120 -or [uint64]$Startup.guardian_policy.campaign_commit_deadline_s -ne 1800) {
        throw "Launcher startup parameters/policies differ from the fixed fault-gate Test contract."
    }

    Test-FaultGateLauncherOutputPostCreateSchema -Output $Startup.output_path_post_create -StartupMonotonicFrequency $startupMonotonicFrequency -StartupMonotonicOrigin $startupMonotonicOrigin

    $preflight = $Startup.preflight
    Assert-FaultGateJsonObject -Value $preflight -Label "launcher startup preflight"
    Assert-FaultGateExactProperties -Value $preflight -Names @(
        "repo", "output_base", "drive_device_id", "free_gib", "projection_combined_raw_gib_per_hour", "projection_safety_multiplier",
        "projection_fixed_reserve_gib", "persistent_reserve_gib", "projected_remaining_gib_at_start", "required_free_gib", "disk_telemetry_preflight",
        "network_telemetry_preflight", "process_telemetry_preflight", "campaign_executable", "campaign_executable_sha256", "capture_executable",
        "capture_executable_sha256", "campaign_verifier_executable", "campaign_verifier_executable_sha256", "public_config", "public_config_sha256",
        "source_lock", "source_lock_sha256", "launcher_script", "launcher_script_sha256", "monitor_script", "monitor_script_sha256", "helper_script",
        "helper_script_sha256", "telemetry_probe_script", "telemetry_probe_script_sha256", "watchdog_script", "watchdog_script_sha256",
        "python_runtime_fingerprint_script", "python_runtime_fingerprint_script_sha256", "powershell_executable", "powershell_executable_sha256",
        "host_probe_timeout_s", "host_probe_maximum_artifact_bytes", "guardian_watchdog_deadline_s", "guardian_watchdog_startup_deadline_s",
        "python_runtime_fingerprint_timeout_s", "spec_revision", "clock", "python", "python_sha256", "python_verifier_source", "python_runtime",
        "python_project", "python_project_sha256", "python_requirements", "python_requirements_sha256", "cbs_reboot_pending",
        "windows_update_reboot_pending", "pending_file_rename_present", "child_environment"
    ) -Label "launcher startup preflight"
    foreach ($name in @("repo", "output_base", "drive_device_id", "campaign_executable", "capture_executable", "campaign_verifier_executable", "public_config", "source_lock", "launcher_script", "monitor_script", "helper_script", "telemetry_probe_script", "watchdog_script", "python_runtime_fingerprint_script", "powershell_executable", "spec_revision", "python", "python_project", "python_requirements")) {
        $null = Get-FaultGateJsonNonEmptyString -Value $preflight.$name -Label "preflight $name"
    }
    foreach ($name in @("campaign_executable_sha256", "capture_executable_sha256", "campaign_verifier_executable_sha256", "public_config_sha256", "source_lock_sha256", "launcher_script_sha256", "monitor_script_sha256", "helper_script_sha256", "telemetry_probe_script_sha256", "watchdog_script_sha256", "python_runtime_fingerprint_script_sha256", "powershell_executable_sha256", "python_sha256", "python_project_sha256", "python_requirements_sha256")) {
        Assert-FaultGateEvidenceDigest -Value $preflight.$name -Label "preflight $name"
    }
    foreach ($name in @("free_gib", "projection_fixed_reserve_gib", "persistent_reserve_gib", "projected_remaining_gib_at_start", "required_free_gib", "host_probe_timeout_s", "host_probe_maximum_artifact_bytes", "guardian_watchdog_deadline_s", "guardian_watchdog_startup_deadline_s", "python_runtime_fingerprint_timeout_s")) {
        $null = Get-FaultGateJsonUnsignedInteger -Value $preflight.$name -Label "preflight $name"
    }
    foreach ($name in @("projection_combined_raw_gib_per_hour", "projection_safety_multiplier")) { $null = Get-FaultGateJsonNumber -Value $preflight.$name -Label "preflight $name" }
    foreach ($name in @("cbs_reboot_pending", "windows_update_reboot_pending", "pending_file_rename_present")) { $null = Get-FaultGateJsonBoolean -Value $preflight.$name -Label "preflight $name" }
    if ([bool]$preflight.cbs_reboot_pending -or [bool]$preflight.windows_update_reboot_pending) { throw "Launcher preflight reports a servicing reboot requirement." }

    Assert-FaultGateJsonObject -Value $preflight.disk_telemetry_preflight -Label "preflight disk telemetry"
    Assert-FaultGateExactProperties -Value $preflight.disk_telemetry_preflight -Names @("device_id", "filesystem", "size_bytes", "free_bytes", "avg_read_latency_s", "avg_write_latency_s", "current_queue_length") -Label "preflight disk telemetry"
    foreach ($name in @("device_id", "filesystem")) { $null = Get-FaultGateJsonNonEmptyString -Value $preflight.disk_telemetry_preflight.$name -Label "preflight disk $name" }
    foreach ($name in @("size_bytes", "free_bytes")) { $null = Get-FaultGateJsonUnsignedInteger -Value $preflight.disk_telemetry_preflight.$name -Label "preflight disk $name" }
    foreach ($name in @("avg_read_latency_s", "avg_write_latency_s", "current_queue_length")) { $null = Get-FaultGateJsonNumber -Value $preflight.disk_telemetry_preflight.$name -Label "preflight disk $name" }
    Assert-FaultGateJsonObject -Value $preflight.network_telemetry_preflight -Label "preflight network telemetry"
    Assert-FaultGateExactProperties -Value $preflight.network_telemetry_preflight -Names @("received_bytes", "sent_bytes", "received_packets", "sent_packets", "received_discards", "outbound_discards", "received_errors", "outbound_errors") -Label "preflight network telemetry"
    foreach ($name in @("received_bytes", "sent_bytes", "received_packets", "sent_packets", "received_discards", "outbound_discards", "received_errors", "outbound_errors")) { $null = Get-FaultGateJsonUnsignedInteger -Value $preflight.network_telemetry_preflight.$name -Label "preflight network $name" }
    Assert-FaultGateJsonArray -Value $preflight.process_telemetry_preflight -Label "preflight process telemetry"
    if (@($preflight.process_telemetry_preflight).Count -eq 0) { throw "Preflight process telemetry is empty." }
    foreach ($processRow in @($preflight.process_telemetry_preflight)) {
        Assert-FaultGateJsonObject -Value $processRow -Label "preflight process row"
        Assert-FaultGateExactProperties -Value $processRow -Names @("pid", "parent_pid", "name", "creation_date", "executable_path", "cpu_kernel_100ns", "cpu_user_100ns", "working_set_bytes", "page_file_kib", "handles", "read_operations", "read_bytes", "write_operations", "write_bytes") -Label "preflight process row"
        foreach ($name in @("pid", "parent_pid", "cpu_kernel_100ns", "cpu_user_100ns", "working_set_bytes", "page_file_kib", "handles", "read_operations", "read_bytes", "write_operations", "write_bytes")) { $null = Get-FaultGateJsonUnsignedInteger -Value $processRow.$name -Label "preflight process $name" }
        foreach ($name in @("name", "creation_date", "executable_path")) { $null = Get-FaultGateJsonNonEmptyString -Value $processRow.$name -Label "preflight process $name" }
    }
    Assert-FaultGateJsonObject -Value $preflight.clock -Label "preflight clock"
    Assert-FaultGateExactProperties -Value $preflight.clock -Names @("healthy", "leap_indicator", "stratum", "source", "last_successful_sync", "root_delay_s", "root_dispersion_s", "phase_offset_s", "seconds_since_last_good_sync", "maximum_last_good_sync_age_s", "state_machine", "last_sync_error", "poll_interval_s", "raw_status_sha256", "query_exit_code") -Label "preflight clock"
    $null = Get-FaultGateJsonBoolean -Value $preflight.clock.healthy -Label "preflight clock healthy"
    foreach ($name in @("leap_indicator", "stratum", "state_machine", "last_sync_error", "poll_interval_s", "query_exit_code")) { $null = Get-FaultGateJsonUnsignedInteger -Value $preflight.clock.$name -Label "preflight clock $name" }
    foreach ($name in @("source", "last_successful_sync")) { $null = Get-FaultGateJsonNonEmptyString -Value $preflight.clock.$name -Label "preflight clock $name" }
    foreach ($name in @("root_delay_s", "root_dispersion_s", "phase_offset_s", "seconds_since_last_good_sync", "maximum_last_good_sync_age_s")) { $null = Get-FaultGateJsonNumber -Value $preflight.clock.$name -Label "preflight clock $name" }
    Assert-FaultGateEvidenceDigest -Value $preflight.clock.raw_status_sha256 -Label "preflight clock status digest"
    if (-not [bool]$preflight.clock.healthy -or [uint64]$preflight.clock.leap_indicator -ne 0 -or [uint64]$preflight.clock.stratum -eq 0 -or
        [uint64]$preflight.clock.stratum -gt 15 -or [uint64]$preflight.clock.state_machine -ne 2 -or [uint64]$preflight.clock.last_sync_error -ne 0 -or
        [uint64]$preflight.clock.query_exit_code -ne 0 -or [double]$preflight.clock.seconds_since_last_good_sync -gt [double]$preflight.clock.maximum_last_good_sync_age_s) {
        throw "Launcher preflight clock is not an exact healthy synchronized state."
    }

    Assert-FaultGateJsonObject -Value $preflight.python_verifier_source -Label "preflight Python source tree"
    Assert-FaultGateExactProperties -Value $preflight.python_verifier_source -Names @("root", "files", "tree_sha256", "inventory") -Label "preflight Python source tree"
    $null = Get-FaultGateJsonNonEmptyString -Value $preflight.python_verifier_source.root -Label "preflight Python source root"
    $sourceFiles = Get-FaultGateJsonUnsignedInteger -Value $preflight.python_verifier_source.files -Label "preflight Python source files"
    Assert-FaultGateEvidenceDigest -Value $preflight.python_verifier_source.tree_sha256 -Label "preflight Python source digest"
    Assert-FaultGateJsonArray -Value $preflight.python_verifier_source.inventory -Label "preflight Python source inventory"
    if (@($preflight.python_verifier_source.inventory).Count -ne $sourceFiles -or $sourceFiles -eq 0) { throw "Preflight Python source inventory cardinality is invalid." }
    foreach ($sourceRow in @($preflight.python_verifier_source.inventory)) {
        Assert-FaultGateJsonObject -Value $sourceRow -Label "preflight Python source row"
        Assert-FaultGateExactProperties -Value $sourceRow -Names @("path", "bytes", "sha256") -Label "preflight Python source row"
        $null = Get-FaultGateJsonNonEmptyString -Value $sourceRow.path -Label "preflight Python source path"
        $null = Get-FaultGateJsonUnsignedInteger -Value $sourceRow.bytes -Label "preflight Python source bytes"
        Assert-FaultGateEvidenceDigest -Value $sourceRow.sha256 -Label "preflight Python source row digest"
    }
    Assert-FaultGateJsonObject -Value $preflight.python_runtime -Label "preflight Python runtime"
    Assert-FaultGateExactProperties -Value $preflight.python_runtime -Names @("venv_root", "venv_python", "venv_python_sha256", "pyvenv_config", "pyvenv_config_sha256", "base_root", "base_executable", "base_executable_sha256", "file_count", "total_bytes", "tree_sha256", "included_extensions", "excluded_path_components") -Label "preflight Python runtime"
    foreach ($name in @("venv_root", "venv_python", "pyvenv_config", "base_root", "base_executable")) { $null = Get-FaultGateJsonNonEmptyString -Value $preflight.python_runtime.$name -Label "preflight Python runtime $name" }
    foreach ($name in @("venv_python_sha256", "pyvenv_config_sha256", "base_executable_sha256", "tree_sha256")) { Assert-FaultGateEvidenceDigest -Value $preflight.python_runtime.$name -Label "preflight Python runtime $name" }
    foreach ($name in @("file_count", "total_bytes")) { $null = Get-FaultGateJsonUnsignedInteger -Value $preflight.python_runtime.$name -Label "preflight Python runtime $name" }
    Assert-FaultGateJsonStringArray -Value $preflight.python_runtime.included_extensions -Label "preflight Python runtime extensions"
    Assert-FaultGateJsonStringArray -Value $preflight.python_runtime.excluded_path_components -Label "preflight Python runtime exclusions"
    Assert-FaultGateJsonObject -Value $preflight.child_environment -Label "preflight child environment"
    Assert-FaultGateExactProperties -Value $preflight.child_environment -Names @("mode", "names", "entries_sha256", "Entries") -Label "preflight child environment"
    $null = Get-FaultGateJsonNonEmptyString -Value $preflight.child_environment.mode -Label "preflight child environment mode"
    Assert-FaultGateJsonStringArray -Value $preflight.child_environment.names -Label "preflight child environment names"
    Assert-FaultGateEvidenceDigest -Value $preflight.child_environment.entries_sha256 -Label "preflight child environment digest"
    Assert-FaultGateJsonStringArray -Value $preflight.child_environment.Entries -Label "preflight child environment entries"
    $expectedEnvironmentNames = @("SystemDrive", "SystemRoot", "TEMP", "TMP", "WINDIR")
    $environmentNames = @($preflight.child_environment.names)
    $environmentEntries = @($preflight.child_environment.Entries)
    if ([string]$preflight.child_environment.mode -cne "EXPLICIT_ALLOWLIST_NO_INHERITANCE" -or
        ($environmentNames -join "`n") -cne ($expectedEnvironmentNames -join "`n") -or $environmentEntries.Count -ne $environmentNames.Count) {
        throw "Launcher child environment is not the exact fixed allowlist."
    }
    for ($environmentIndex = 0; $environmentIndex -lt $environmentNames.Count; $environmentIndex++) {
        if (-not [string]$environmentEntries[$environmentIndex].StartsWith(([string]$environmentNames[$environmentIndex] + '='), [StringComparison]::Ordinal) -or
            [string]$environmentEntries[$environmentIndex] -ceq ([string]$environmentNames[$environmentIndex] + '=')) { throw "Launcher child environment entry/name binding is invalid." }
    }
    $environmentMaterial = [string]::Join("`0", [string[]]$environmentEntries) + "`0`0"
    $environmentDigest = Get-FaultGateSha256Bytes -Bytes ([Text.UnicodeEncoding]::new($false, $false).GetBytes($environmentMaterial))
    if ([string]$preflight.child_environment.entries_sha256 -cne $environmentDigest) { throw "Launcher child environment digest is not derived from the exact ordered entries." }
}

function Test-FaultGateProcessControlSchema {
    param([Parameter(Mandatory = $true)] $ProcessControl)
    Assert-FaultGateJsonObject -Value $ProcessControl -Label "process control"
    Assert-FaultGateExactProperties -Value $ProcessControl -Names @(
        "schema", "run_id", "job_object_name", "job_kill_on_close",
        "workload_job_object_name", "workload_job_kill_on_close", "launch_method",
        "child_environment_mode", "child_environment_names", "child_environment_entries_sha256",
        "capture_origin_monotonic_tick", "launch_skew_ticks", "launch_skew_ms",
        "maximum_dual_launch_skew_ms", "watchdog", "processes") -Label "process control"
    foreach ($name in @("schema", "run_id", "job_object_name", "workload_job_object_name", "launch_method", "child_environment_mode")) { $null = Get-FaultGateJsonNonEmptyString -Value $ProcessControl.$name -Label "process control $name" }
    $jobKillOnClose = Get-FaultGateJsonBoolean -Value $ProcessControl.job_kill_on_close -Label "process control kill-on-close"
    $workloadKillOnClose = Get-FaultGateJsonBoolean -Value $ProcessControl.workload_job_kill_on_close -Label "process control workload kill-on-close"
    if ([string]$ProcessControl.schema -cne "RawQualificationProcessControlV2" -or
        -not $jobKillOnClose -or -not $workloadKillOnClose -or
        [string]$ProcessControl.job_object_name -ceq [string]$ProcessControl.workload_job_object_name -or
        [string]$ProcessControl.launch_method -cne "CREATE_SUSPENDED_ASSIGN_OUTER_AND_WORKLOAD_JOBS_RESUME" -or
        [string]$ProcessControl.child_environment_mode -cne "EXPLICIT_ALLOWLIST_NO_INHERITANCE") { throw "Process control schema/Job/launch/environment boundary is invalid." }
    Assert-FaultGateJsonStringArray -Value $ProcessControl.child_environment_names -Label "process control child environment names"
    Assert-FaultGateEvidenceDigest -Value $ProcessControl.child_environment_entries_sha256 -Label "process control environment digest"
    $captureOrigin = Get-FaultGateJsonUnsignedInteger -Value $ProcessControl.capture_origin_monotonic_tick -Label "process control capture origin"
    $launchSkewTicks = Get-FaultGateJsonUnsignedInteger -Value $ProcessControl.launch_skew_ticks -Label "process control launch skew ticks"
    $launchSkewMs = Get-FaultGateJsonUnsignedInteger -Value $ProcessControl.launch_skew_ms -Label "process control launch skew ms"
    $maximumLaunchSkewMs = Get-FaultGateJsonUnsignedInteger -Value $ProcessControl.maximum_dual_launch_skew_ms -Label "process control maximum launch skew ms"
    Assert-FaultGateJsonObject -Value $ProcessControl.watchdog -Label "process control watchdog"
    Assert-FaultGateExactProperties -Value $ProcessControl.watchdog -Names @("pid", "job_name", "creation_time_utc", "executable_path", "executable_sha256", "command_line", "script_path", "script_sha256", "launch_origin_qpc_timestamp", "resume_qpc_timestamp", "monotonic_frequency", "startup_deadline_s", "guardian_pulse_file", "maximum_guardian_pulse_age_s", "ready_file", "ready_file_sha256", "ready_observed_qpc_timestamp", "ready_pulse_length", "stdout_file", "stderr_file") -Label "process control watchdog"
    foreach ($name in @("pid", "launch_origin_qpc_timestamp", "resume_qpc_timestamp", "monotonic_frequency", "startup_deadline_s", "maximum_guardian_pulse_age_s", "ready_observed_qpc_timestamp", "ready_pulse_length")) { $null = Get-FaultGateJsonUnsignedInteger -Value $ProcessControl.watchdog.$name -Label "process control watchdog $name" }
    foreach ($name in @("job_name", "creation_time_utc", "executable_path", "command_line", "script_path", "guardian_pulse_file", "ready_file", "stdout_file", "stderr_file")) { $null = Get-FaultGateJsonNonEmptyString -Value $ProcessControl.watchdog.$name -Label "process control watchdog $name" }
    foreach ($name in @("executable_sha256", "script_sha256", "ready_file_sha256")) { Assert-FaultGateEvidenceDigest -Value $ProcessControl.watchdog.$name -Label "process control watchdog $name" }
    if ([uint64]$ProcessControl.watchdog.pid -eq 0 -or [string]$ProcessControl.watchdog.job_name -cne [string]$ProcessControl.job_object_name -or
        [uint64]$ProcessControl.watchdog.launch_origin_qpc_timestamp -eq 0 -or
        [uint64]$ProcessControl.watchdog.resume_qpc_timestamp -lt [uint64]$ProcessControl.watchdog.launch_origin_qpc_timestamp -or
        [uint64]$ProcessControl.watchdog.ready_observed_qpc_timestamp -lt [uint64]$ProcessControl.watchdog.resume_qpc_timestamp -or
        [uint64]$ProcessControl.watchdog.monotonic_frequency -eq 0 -or [uint64]$ProcessControl.watchdog.startup_deadline_s -eq 0 -or
        [uint64]$ProcessControl.watchdog.maximum_guardian_pulse_age_s -eq 0 -or [uint64]$ProcessControl.watchdog.ready_pulse_length -eq 0 -or
        [string]$ProcessControl.watchdog.guardian_pulse_file -cne "guardian-pulse.jsonl" -or [string]$ProcessControl.watchdog.ready_file -cne "watchdog-ready.json" -or
        [string]$ProcessControl.watchdog.stdout_file -cne "watchdog.stdout.log" -or [string]$ProcessControl.watchdog.stderr_file -cne "watchdog.stderr.log") {
        throw "Process-control watchdog chronology/support-file identity is invalid."
    }
    Assert-FaultGateJsonArray -Value $ProcessControl.processes -Label "process control processes"
    $processRows = @($ProcessControl.processes)
    if ($processRows.Count -ne 2) { throw "Process control must contain exactly two coordinator processes." }
    $symbols = @("BTCUSDT", "ETHUSDT")
    $launchTicks = [Collections.Generic.List[uint64]]::new()
    for ($index = 0; $index -lt 2; $index++) {
        $row = $processRows[$index]
        Assert-FaultGateJsonObject -Value $row -Label "process control coordinator"
        Assert-FaultGateExactProperties -Value $row -Names @("symbol", "pid", "creation_time_utc", "executable_path", "executable_sha256", "command_line", "launch_monotonic_tick", "stdout_file", "stderr_file") -Label "process control coordinator"
        foreach ($name in @("symbol", "creation_time_utc", "executable_path", "command_line", "stdout_file", "stderr_file")) { $null = Get-FaultGateJsonNonEmptyString -Value $row.$name -Label "process control coordinator $name" }
        $rowPid = Get-FaultGateJsonUnsignedInteger -Value $row.pid -Label "process control coordinator pid" -Maximum ([uint32]::MaxValue)
        $rowLaunchTick = Get-FaultGateJsonUnsignedInteger -Value $row.launch_monotonic_tick -Label "process control coordinator launch tick"
        if ([string]$row.symbol -cne $symbols[$index] -or $rowPid -eq 0 -or $rowLaunchTick -eq 0 -or
            [string]$row.stdout_file -cne ($symbols[$index].ToLowerInvariant() + ".stdout.log") -or
            [string]$row.stderr_file -cne ($symbols[$index].ToLowerInvariant() + ".stderr.log")) { throw "Process control coordinator identity/order/support files are invalid." }
        Assert-FaultGateEvidenceDigest -Value $row.executable_sha256 -Label "process control coordinator executable digest"
        $launchTicks.Add($rowLaunchTick)
    }
    $btcLaunchTick = [uint64]$launchTicks[0]
    $ethLaunchTick = [uint64]$launchTicks[1]
    if ($btcLaunchTick -gt $ethLaunchTick) { throw "Process control coordinator chronology requires BTCUSDT launch before or at ETHUSDT launch." }
    $expectedSkewTicks = $ethLaunchTick - $btcLaunchTick
    $expectedSkewMs = [uint64][Math]::Ceiling(([double]$expectedSkewTicks * 1000.0) / [double][Diagnostics.Stopwatch]::Frequency)
    if ($captureOrigin -ne $ethLaunchTick -or $launchSkewTicks -ne $expectedSkewTicks -or $launchSkewMs -ne $expectedSkewMs -or
        $maximumLaunchSkewMs -eq 0 -or $launchSkewMs -gt $maximumLaunchSkewMs) { throw "Process control capture origin/dual-launch skew arithmetic is invalid." }
}

function Test-FaultGateCampaignBindingsSchema {
    param([Parameter(Mandatory = $true)] $Bindings)
    Assert-FaultGateJsonObject -Value $Bindings -Label "campaign bindings"
    Assert-FaultGateExactProperties -Value $Bindings -Names @("schema", "run_id", "bound_utc", "campaigns") -Label "campaign bindings"
    foreach ($name in @("schema", "run_id", "bound_utc")) { $null = Get-FaultGateJsonNonEmptyString -Value $Bindings.$name -Label "campaign bindings $name" }
    if ([string]$Bindings.schema -cne "RawQualificationCampaignBindingsV1") { throw "Campaign bindings schema is invalid." }
    Assert-FaultGateJsonArray -Value $Bindings.campaigns -Label "campaign bindings campaigns"
    $rows = @($Bindings.campaigns)
    $symbols = @("BTCUSDT", "ETHUSDT")
    if ($rows.Count -ne 2) { throw "Campaign bindings must contain exactly BTCUSDT and ETHUSDT." }
    for ($index = 0; $index -lt 2; $index++) {
        $row = $rows[$index]
        Assert-FaultGateJsonObject -Value $row -Label "campaign binding"
        Assert-FaultGateExactProperties -Value $row -Names @("symbol", "pid", "campaign_id", "campaign_directory", "campaign_startup_sha256") -Label "campaign binding"
        foreach ($name in @("symbol", "campaign_id", "campaign_directory")) { $null = Get-FaultGateJsonNonEmptyString -Value $row.$name -Label "campaign binding $name" }
        if ([string]$row.symbol -cne $symbols[$index] -or (Get-FaultGateJsonUnsignedInteger -Value $row.pid -Label "campaign binding pid" -Maximum ([uint32]::MaxValue)) -eq 0) { throw "Campaign binding symbol/PID is invalid." }
        Assert-FaultGateEvidenceDigest -Value $row.campaign_startup_sha256 -Label "campaign binding startup digest"
    }
}

function Test-FaultGateWatchdogReadySchema {
    param([Parameter(Mandatory = $true)] $Ready)
    Assert-FaultGateJsonObject -Value $Ready -Label "watchdog READY"
    Assert-FaultGateExactProperties -Value $Ready -Names @("schema", "run_id", "job_name", "pid", "launch_origin_qpc_timestamp", "observed_qpc_timestamp", "monotonic_frequency", "startup_deadline_s", "pulse_length") -Label "watchdog READY"
    foreach ($name in @("schema", "run_id", "job_name")) { $null = Get-FaultGateJsonNonEmptyString -Value $Ready.$name -Label "watchdog READY $name" }
    if ([string]$Ready.schema -cne "RawQualificationWatchdogReadyV1") { throw "Watchdog READY schema is invalid." }
    foreach ($name in @("pid", "launch_origin_qpc_timestamp", "observed_qpc_timestamp", "monotonic_frequency", "startup_deadline_s", "pulse_length")) { $null = Get-FaultGateJsonUnsignedInteger -Value $Ready.$name -Label "watchdog READY $name" }
    $readyPid = Get-FaultGateJsonUnsignedInteger -Value $Ready.pid -Label "watchdog READY pid" -Maximum ([uint32]::MaxValue)
    $readyOrigin = [uint64]$Ready.launch_origin_qpc_timestamp
    $readyObserved = [uint64]$Ready.observed_qpc_timestamp
    $readyFrequency = [uint64]$Ready.monotonic_frequency
    $readyDeadlineSeconds = [uint64]$Ready.startup_deadline_s
    if ($readyPid -eq 0 -or $readyOrigin -eq 0 -or $readyObserved -lt $readyOrigin -or $readyFrequency -eq 0 -or $readyDeadlineSeconds -eq 0 -or [uint64]$Ready.pulse_length -eq 0) {
        throw "Watchdog READY PID/chronology/deadline is invalid."
    }
    $readyRelativeTicks = Multiply-FaultGateCheckedUInt64 -Left $readyDeadlineSeconds -Right $readyFrequency -Label "watchdog READY deadline interval"
    $readyDeadlineTick = Add-FaultGateCheckedQpcTicks -Origin $readyOrigin -Relative $readyRelativeTicks -Label "watchdog READY deadline"
    if ($readyObserved -gt $readyDeadlineTick) { throw "Watchdog READY observation exceeded its startup deadline." }
}

function Test-FaultGateControlCrosslinks {
    param(
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] $ProcessControl,
        [Parameter(Mandatory = $true)] $Bindings,
        [Parameter(Mandatory = $true)] $Ready,
        [Parameter(Mandatory = $true)] [string] $RepositoryRoot,
        [Parameter(Mandatory = $true)] [string] $QualificationBase,
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] [string] $ReadySha256
    )
    Assert-FaultGateEvidenceDigest -Value $ReadySha256 -Label "watchdog READY retained digest"
    $repoPath = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\')
    $qualificationPath = [IO.Path]::GetFullPath($QualificationBase).TrimEnd('\')
    $runPath = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
    $runId = [string]$Startup.run_id
    $expectedRunPath = [IO.Path]::GetFullPath((Join-Path $qualificationPath $runId)).TrimEnd('\')
    $expectedJobName = "Local\BinanceRawQualificationJob-" + $runId
    $expectedWorkloadJobName = "Local\BinanceRawQualificationWorkloadJob-" + $runId
    if ([string]::IsNullOrWhiteSpace($runId) -or [IO.Path]::GetFileName($runPath) -cne $runId -or
        -not $runPath.Equals($expectedRunPath, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-FaultGateFullPathEquals -PublishedPath $Startup.run_root -ExpectedPath $runPath) -or
        -not (Test-FaultGateFullPathEquals -PublishedPath $Startup.preflight.repo -ExpectedPath $repoPath) -or
        -not (Test-FaultGateFullPathEquals -PublishedPath $Startup.preflight.output_base -ExpectedPath $qualificationPath) -or
        [string]$ProcessControl.run_id -cne $runId -or [string]$Bindings.run_id -cne $runId -or [string]$Ready.run_id -cne $runId -or
        [string]$ProcessControl.job_object_name -cne $expectedJobName -or
        [string]$ProcessControl.workload_job_object_name -cne $expectedWorkloadJobName -or
        [string]$ProcessControl.job_object_name -ceq [string]$ProcessControl.workload_job_object_name -or
        [string]$ProcessControl.watchdog.job_name -cne $expectedJobName -or
        [string]$Ready.job_name -cne $expectedJobName) {
        throw "Startup/process/bindings/READY run-root and Job identity crosslinks are invalid."
    }
    $preflightDrive = [string]$Startup.preflight.drive_device_id
    if ($preflightDrive -cne [string]$Startup.preflight.disk_telemetry_preflight.device_id -or
        $preflightDrive -cne [string]$Startup.output_path_post_create.run_root_drive_device_id -or
        [string]$Startup.preflight.disk_telemetry_preflight.filesystem -cne [string]$Startup.output_path_post_create.filesystem -or
        [uint64]$Startup.preflight.required_free_gib -ne [uint64]$Startup.output_path_post_create.required_free_gib -or
        [uint64]$Startup.preflight.free_gib -lt [uint64]$Startup.preflight.required_free_gib -or
        [uint64]$Startup.output_path_post_create.free_gib -lt [uint64]$Startup.output_path_post_create.required_free_gib) {
        throw "Startup preflight/post-create device, filesystem, or capacity crosslinks are invalid."
    }
    $startupEnvironment = $Startup.preflight.child_environment
    if ([string]$ProcessControl.child_environment_mode -cne [string]$startupEnvironment.mode -or
        (@($ProcessControl.child_environment_names) -join "`n") -cne (@($startupEnvironment.names) -join "`n") -or
        [string]$ProcessControl.child_environment_entries_sha256 -cne [string]$startupEnvironment.entries_sha256 -or
        [uint64]$ProcessControl.maximum_dual_launch_skew_ms -ne [uint64]$Startup.guardian_policy.maximum_dual_launch_skew_ms) {
        throw "Process control child-environment or launch-skew policy is not exactly bound to startup."
    }
    $watchdog = $ProcessControl.watchdog
    if ([uint64]$watchdog.monotonic_frequency -ne [uint64]$Startup.monotonic_frequency -or
        [uint64]$watchdog.monotonic_frequency -ne [uint64][Diagnostics.Stopwatch]::Frequency -or
        [uint64]$watchdog.startup_deadline_s -ne [uint64]$Startup.guardian_policy.watchdog_startup_deadline_s -or
        [uint64]$watchdog.maximum_guardian_pulse_age_s -ne [uint64]$Startup.guardian_policy.watchdog_deadline_s -or
        [uint64]$Ready.pid -ne [uint64]$watchdog.pid -or
        [uint64]$Ready.launch_origin_qpc_timestamp -ne [uint64]$watchdog.launch_origin_qpc_timestamp -or
        [uint64]$Ready.observed_qpc_timestamp -ne [uint64]$watchdog.ready_observed_qpc_timestamp -or
        [uint64]$Ready.monotonic_frequency -ne [uint64]$watchdog.monotonic_frequency -or
        [uint64]$Ready.startup_deadline_s -ne [uint64]$watchdog.startup_deadline_s -or
        [uint64]$Ready.pulse_length -ne [uint64]$watchdog.ready_pulse_length -or
        [string]$watchdog.ready_file_sha256 -cne $ReadySha256) {
        throw "Watchdog READY/process-control/startup policy crosslinks are invalid."
    }
    $processRows = @($ProcessControl.processes)
    $bindingRows = @($Bindings.campaigns)
    if ($processRows.Count -ne 2 -or $bindingRows.Count -ne 2) { throw "Process/binding crosslink cardinality is invalid." }
    $seenPids = [Collections.Generic.HashSet[uint32]]::new()
    $seenCampaignIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenCampaignDirectories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($index in 0..1) {
        $symbol = @("BTCUSDT", "ETHUSDT")[$index]
        $processRow = $processRows[$index]
        $bindingRow = $bindingRows[$index]
        $campaignId = Get-FaultGatePortableLeafComponent -Value $bindingRow.campaign_id -Label "$symbol campaign id"
        $expectedCampaignDirectory = [IO.Path]::GetFullPath((Join-Path $runPath $campaignId))
        if ([string]$processRow.symbol -cne $symbol -or [string]$bindingRow.symbol -cne $symbol -or
            [uint32]$processRow.pid -ne [uint32]$bindingRow.pid -or -not $seenPids.Add([uint32]$processRow.pid) -or
            $campaignId -cnotmatch ('^[0-9]+-' + $symbol + '-raw-[0-9a-f]{12}$') -or -not $seenCampaignIds.Add($campaignId) -or
            -not (Test-FaultGateFullPathEquals -PublishedPath $bindingRow.campaign_directory -ExpectedPath $expectedCampaignDirectory) -or
            -not $seenCampaignDirectories.Add($expectedCampaignDirectory)) {
            throw "$symbol process/campaign binding is not the unique exact RunRoot child identity."
        }
    }
}

function Test-FaultGateLauncherTerminalV2Schema {
    param(
        [Parameter(Mandatory = $true)] $Terminal,
        [Parameter(Mandatory = $true)] $Startup
    )
    Assert-FaultGateJsonObject -Value $Terminal -Label "launcher terminal V2"
    Assert-FaultGateExactProperties -Value $Terminal -Names @(
        "schema", "status", "failure", "failure_containment", "failure_containment_sha256", "run_id", "mode", "run_root", "finished_utc",
        "launcher_elapsed_ms", "capture_elapsed_ms", "parameters", "verifier_policy", "coordinator_log_policy", "market_freshness_policy",
        "guardian_policy", "startup_sha256", "process_control_sha256", "campaign_bindings_sha256", "launcher_events", "host_telemetry",
        "guardian_pulse", "artifact_hashes_preflight", "artifact_hashes_terminal", "watchdog", "campaigns", "credentials", "order_entry"
    ) -Label "launcher terminal V2"
    foreach ($name in @("schema", "status", "failure", "run_id", "mode", "run_root", "finished_utc", "credentials", "order_entry")) {
        $null = Get-FaultGateJsonNonEmptyString -Value $Terminal.$name -Label "launcher terminal $name"
    }
    if ([string]$Terminal.schema -cne "RawQualificationLauncherTerminalV2" -or [string]$Terminal.status -cne "FAILED" -or
        [string]$Terminal.mode -cne "Test" -or [string]$Terminal.credentials -cne "NONE" -or [string]$Terminal.order_entry -cne "ABSENT" -or
        $null -eq $Terminal.failure_containment -or -not (Test-FaultGateDigest $Terminal.failure_containment_sha256) -or
        $null -ne $Terminal.watchdog) { throw "Launcher terminal V2 failure/non-trading boundary is invalid." }
    $launcherElapsed = Get-FaultGateJsonUnsignedInteger -Value $Terminal.launcher_elapsed_ms -Label "launcher terminal elapsed"
    if ($launcherElapsed -eq 0) { throw "Launcher terminal elapsed duration is invalid." }
    if ($null -ne $Terminal.capture_elapsed_ms) { $null = Get-FaultGateJsonUnsignedInteger -Value $Terminal.capture_elapsed_ms -Label "launcher terminal capture elapsed" }
    foreach ($name in @("startup_sha256", "process_control_sha256", "campaign_bindings_sha256")) { Assert-FaultGateEvidenceDigest -Value $Terminal.$name -Label "launcher terminal $name" }
    Test-FaultGateQualificationPolicyShapes -Value $Terminal -Label "launcher terminal"
    foreach ($policyName in @("parameters", "verifier_policy", "coordinator_log_policy", "market_freshness_policy", "guardian_policy")) {
        if ((Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $Terminal.$policyName)) -cne
            (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $Startup.$policyName))) {
            throw "Launcher terminal $policyName differs from startup."
        }
    }
    foreach ($journalName in @("launcher_events", "host_telemetry", "guardian_pulse")) {
        $journal = $Terminal.$journalName
        Assert-FaultGateJsonObject -Value $journal -Label "launcher terminal $journalName"
        $journalFields = if ($journalName -ceq "launcher_events") { @("file", "records", "terminal_record_sha256", "file_bytes", "file_sha256") } else { @("file", "records", "terminal_record_sha256", "file_sha256") }
        Assert-FaultGateExactProperties -Value $journal -Names $journalFields -Label "launcher terminal $journalName"
        $null = Get-FaultGateJsonNonEmptyString -Value $journal.file -Label "launcher terminal $journalName file"
        if ((Get-FaultGateJsonUnsignedInteger -Value $journal.records -Label "launcher terminal $journalName records") -eq 0) { throw "Launcher terminal $journalName is empty." }
        if ($journalName -ceq "launcher_events" -and (Get-FaultGateJsonUnsignedInteger -Value $journal.file_bytes -Label "launcher terminal launcher_events bytes") -eq 0) { throw "Launcher terminal launcher_events prefix bytes are empty." }
        Assert-FaultGateEvidenceDigest -Value $journal.terminal_record_sha256 -Label "launcher terminal $journalName terminal digest"
        Assert-FaultGateEvidenceDigest -Value $journal.file_sha256 -Label "launcher terminal $journalName file digest"
    }
    if ([string]$Terminal.launcher_events.file -cne "launcher-events.jsonl" -or [string]$Terminal.host_telemetry.file -cne "host-telemetry.jsonl" -or
        [string]$Terminal.guardian_pulse.file -cne "guardian-pulse.jsonl") { throw "Launcher terminal journal filenames are not exact." }
    $preflightArtifactFields = @(
        "campaign_executable_sha256", "capture_executable_sha256", "campaign_verifier_executable_sha256", "public_config_sha256", "source_lock_sha256",
        "launcher_script_sha256", "monitor_script_sha256", "helper_script_sha256", "telemetry_probe_script_sha256", "watchdog_script_sha256",
        "python_runtime_fingerprint_script_sha256", "powershell_executable_sha256", "python_executable_sha256",
        "python_verifier_source_tree_sha256", "python_runtime_tree_sha256", "python_pyvenv_config_sha256", "python_base_executable_sha256",
        "python_project_sha256", "python_requirements_sha256"
    )
    $terminalArtifactFields = @($preflightArtifactFields[0..9]) + @("watchdog_ready_file_sha256") + @($preflightArtifactFields[10..($preflightArtifactFields.Count - 1)])
    foreach ($hashSetName in @("artifact_hashes_preflight", "artifact_hashes_terminal")) {
        $hashSet = $Terminal.$hashSetName
        $artifactFields = if ($hashSetName -ceq "artifact_hashes_preflight") { $preflightArtifactFields } else { $terminalArtifactFields }
        Assert-FaultGateJsonObject -Value $hashSet -Label "launcher terminal $hashSetName"
        Assert-FaultGateExactProperties -Value $hashSet -Names $artifactFields -Label "launcher terminal $hashSetName"
        foreach ($field in $artifactFields) {
            $mayBeNull = $hashSetName -ceq "artifact_hashes_terminal" -and $field -cin @("python_runtime_tree_sha256", "python_pyvenv_config_sha256", "python_base_executable_sha256")
            if ($mayBeNull) {
                if ($null -ne $hashSet.$field) { throw "Launcher FAILED terminal unexpectedly published $field." }
            }
            else { Assert-FaultGateEvidenceDigest -Value $hashSet.$field -Label "launcher terminal $hashSetName $field" }
        }
    }
    Assert-FaultGateJsonArray -Value $Terminal.campaigns -Label "launcher terminal campaigns"
    if (@($Terminal.campaigns).Count -ne 0) { throw "Injected generation-0 failure terminal unexpectedly contains completed campaign results." }
    try { $null = [DateTimeOffset]::ParseExact([string]$Terminal.finished_utc, "o", [Globalization.CultureInfo]::InvariantCulture) }
    catch { throw "Launcher terminal finished_utc is not an exact round-trip timestamp." }
}

function Test-FaultGateLauncherTerminalPostLink {
    param(
        [Parameter(Mandatory = $true)] [string] $LauncherJournalPath,
        [Parameter(Mandatory = $true)] $LauncherJournal,
        [Parameter(Mandatory = $true)] $Terminal,
        [Parameter(Mandatory = $true)] [uint64] $TerminalBytes,
        [Parameter(Mandatory = $true)] [string] $TerminalSha256,
        [Parameter(Mandatory = $true)] [string] $ContainmentSha256
    )
    Assert-FaultGateEvidenceDigest -Value $TerminalSha256 -Label "launcher terminal file digest"
    Assert-FaultGateEvidenceDigest -Value $ContainmentSha256 -Label "launcher containment digest"
    $prefix = $Terminal.launcher_events
    $prefixRecords = Get-FaultGateJsonUnsignedInteger -Value $prefix.records -Label "launcher preterminal prefix records"
    $prefixBytes = Get-FaultGateJsonUnsignedInteger -Value $prefix.file_bytes -Label "launcher preterminal prefix bytes"
    $entries = @($LauncherJournal.entries)
    $expectedLauncherRecords = Get-FaultGateUInt64Successor -Value $prefixRecords -Label "launcher terminal post-link record count"
    if ($prefixRecords -eq 0 -or [uint64]$LauncherJournal.records -ne $expectedLauncherRecords -or [uint64]$entries.Count -ne $expectedLauncherRecords) {
        throw "Launcher terminal post-link is not the single record after its declared preterminal prefix."
    }
    $terminalEntry = $entries[$prefixRecords]
    $prefixTerminalEntry = $entries[$prefixRecords - 1]
    Assert-FaultGateExactProperties -Value $terminalEntry.body.payload -Names @("event", "status", "failure", "terminal_file", "terminal_bytes", "terminal_sha256", "failure_containment_sha256") -Label "launcher terminal post-link payload"
    if ([string]$prefix.file -cne "launcher-events.jsonl" -or
        [string]$prefix.terminal_record_sha256 -cne [string]$prefixTerminalEntry.record_sha256 -or
        [string]$terminalEntry.body.previous_record_sha256 -cne [string]$prefix.terminal_record_sha256 -or
        (Get-FaultGateJsonUnsignedInteger -Value $terminalEntry.body.record_index -Label "launcher terminal post-link index") -ne $prefixRecords -or
        [string]$terminalEntry.body.payload.event -cne "LAUNCHER_TERMINAL" -or [string]$terminalEntry.body.payload.status -cne "FAILED" -or
        [string]$terminalEntry.body.payload.failure -cne [string]$Terminal.failure -or [string]$terminalEntry.body.payload.terminal_file -cne "launcher-terminal.json" -or
        (Get-FaultGateJsonUnsignedInteger -Value $terminalEntry.body.payload.terminal_bytes -Label "launcher terminal post-link bytes") -ne $TerminalBytes -or
        [string]$terminalEntry.body.payload.terminal_sha256 -cne $TerminalSha256 -or
        [string]$terminalEntry.body.payload.failure_containment_sha256 -cne $ContainmentSha256) {
        throw "Launcher terminal post-link does not exactly bind terminal bytes, failure, containment, and preterminal prefix."
    }
    [byte[]]$journalBytes = [IO.File]::ReadAllBytes($LauncherJournalPath)
    if ([uint64]$journalBytes.Length -ne [uint64]$LauncherJournal.file_bytes -or
        (Get-FaultGateSha256Bytes -Bytes $journalBytes) -cne [string]$LauncherJournal.file_sha256 -or $prefixBytes -ge [uint64]$journalBytes.Length) {
        throw "Launcher journal bytes differ from its parsed stable snapshot."
    }
    [uint64]$newlines = 0
    [int64]$derivedPrefixLength = -1
    for ($byteIndex = 0; $byteIndex -lt $journalBytes.Length; $byteIndex++) {
        if ($journalBytes[$byteIndex] -eq 10) {
            $newlines++
            if ($newlines -eq $prefixRecords) { $derivedPrefixLength = [int64]$byteIndex + 1; break }
        }
    }
    if ($derivedPrefixLength -le 0 -or [uint64]$derivedPrefixLength -ne $prefixBytes) { throw "Launcher preterminal prefix byte boundary is invalid." }
    [byte[]]$exactPrefixBytes = @($journalBytes[0..($derivedPrefixLength - 1)])
    if ((Get-FaultGateSha256Bytes -Bytes $exactPrefixBytes) -cne [string]$prefix.file_sha256) { throw "Launcher preterminal prefix digest is not derived from exact file bytes." }
    return [pscustomobject][ordered]@{
        records = $prefixRecords; terminal_record_sha256 = [string]$prefix.terminal_record_sha256
        file_bytes = $prefixBytes; file_sha256 = [string]$prefix.file_sha256
        post_link_record_sha256 = [string]$terminalEntry.record_sha256
    }
}

function ConvertTo-FaultGateJsonStringLiteral {
    param([Parameter(Mandatory = $true)] [string] $Value)
    return ($Value | ConvertTo-Json -Compress)
}

function Read-FaultGateRawCampaignStartup {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $ExpectedCampaignId,
        [Parameter(Mandatory = $true)] [string] $ExpectedSymbol,
        [Parameter(Mandatory = $true)] [uint32] $ExpectedPid,
        [Parameter(Mandatory = $true)] $ExpectedParameters,
        [Parameter(Mandatory = $true)] [string] $ExpectedCampaignExecutableSha256,
        [Parameter(Mandatory = $true)] [string] $ExpectedCaptureExecutableSha256,
        [Parameter(Mandatory = $true)] [string] $ExpectedPublicConfigSha256,
        [Parameter(Mandatory = $true)] [string] $ExpectedSpecRevision
    )
    $snapshot = Read-FaultGateJsonSnapshot -Path $Path
    $value = $snapshot.value
    Assert-FaultGateJsonObject -Value $value -Label "raw campaign startup"
    $names = @("schema", "campaign_id", "symbol", "total_duration_s", "rotation_s", "overlap_s", "segment_s", "started_wall_ns", "process_id", "executable_sha256", "capture_executable_sha256", "public_config_sha256", "spec_revision", "credentials", "order_entry")
    Assert-FaultGateExactProperties -Value $value -Names $names -Label "raw campaign startup"
    foreach ($name in @("schema", "campaign_id", "symbol", "spec_revision", "credentials", "order_entry")) { $null = Get-FaultGateJsonNonEmptyString -Value $value.$name -Label "raw campaign startup $name" }
    foreach ($name in @("total_duration_s", "rotation_s", "overlap_s", "segment_s", "started_wall_ns", "process_id")) { $null = Get-FaultGateJsonUnsignedInteger -Value $value.$name -Label "raw campaign startup $name" }
    foreach ($name in @("executable_sha256", "capture_executable_sha256", "public_config_sha256")) { Assert-FaultGateEvidenceDigest -Value $value.$name -Label "raw campaign startup $name" }
    if ([string]$value.schema -cne "RawCampaignStartupV1" -or [string]$value.campaign_id -cne $ExpectedCampaignId -or
        [string]$value.symbol -cne $ExpectedSymbol -or [uint64]$value.total_duration_s -ne [uint64]$ExpectedParameters.total_s -or
        [uint64]$value.rotation_s -ne [uint64]$ExpectedParameters.rotation_s -or [uint64]$value.overlap_s -ne [uint64]$ExpectedParameters.overlap_s -or
        [uint64]$value.segment_s -ne [uint64]$ExpectedParameters.segment_s -or [uint64]$value.started_wall_ns -eq 0 -or
        [uint64]$value.process_id -ne [uint64]$ExpectedPid -or [string]$value.executable_sha256 -cne $ExpectedCampaignExecutableSha256 -or
        [string]$value.capture_executable_sha256 -cne $ExpectedCaptureExecutableSha256 -or [string]$value.public_config_sha256 -cne $ExpectedPublicConfigSha256 -or
        [string]$value.spec_revision -cne $ExpectedSpecRevision -or [string]$value.credentials -cne "NONE" -or [string]$value.order_entry -cne "ABSENT") {
        throw "Raw campaign startup identity/parameters/provenance are invalid."
    }
    $builder = [Text.StringBuilder]::new()
    $null = $builder.Append("{`n")
    for ($index = 0; $index -lt $names.Count; $index++) {
        $name = $names[$index]
        $property = $value.PSObject.Properties[$name].Value
        $encodedValue = if ($property -is [string]) { ConvertTo-FaultGateJsonStringLiteral -Value ([string]$property) } else { ([uint64]$property).ToString([Globalization.CultureInfo]::InvariantCulture) }
        $null = $builder.Append("  ").Append((ConvertTo-FaultGateJsonStringLiteral -Value $name)).Append(": ").Append($encodedValue)
        if ($index + 1 -lt $names.Count) { $null = $builder.Append(',') }
        $null = $builder.Append("`n")
    }
    $null = $builder.Append("}`n")
    [byte[]]$expectedBytes = [Text.UTF8Encoding]::new($false).GetBytes($builder.ToString())
    [byte[]]$actualBytes = $snapshot.raw_bytes
    if ($actualBytes.Length -ne $expectedBytes.Length) { throw "Raw campaign startup is not exact serde_json pretty writer output." }
    for ($byteIndex = 0; $byteIndex -lt $actualBytes.Length; $byteIndex++) {
        if ($actualBytes[$byteIndex] -ne $expectedBytes[$byteIndex]) { throw "Raw campaign startup is not exact serde_json pretty writer output." }
    }
    if ([uint64]$snapshot.bytes -ne [uint64]$actualBytes.Length -or [string]$snapshot.sha256 -cne (Get-FaultGateSha256Bytes -Bytes $actualBytes)) {
        throw "Raw campaign startup changed across exact canonical validation."
    }
    return $snapshot
}

function Add-FaultGateEvent {
    param([Parameter(Mandatory = $true)] $Journal, [Parameter(Mandatory = $true)] [string] $Event, [Parameter(Mandatory = $true)] $Payload)
    $orderedPayload = [ordered]@{ event = $Event }
    foreach ($property in $Payload.Keys) { $orderedPayload[$property] = $Payload[$property] }
    return Add-RawQualificationJournalRecord -Journal $Journal -Schema $script:FaultGateJournalSchema -Channel "FAULT_GATE" -WallNs (Get-RawQualificationWallNs) -MonotonicTick ([uint64][Diagnostics.Stopwatch]::GetTimestamp()) -Payload $orderedPayload
}

function Test-FaultGateLauncherStartupExecutableBinding {
    param(
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] [string] $ExpectedPath,
        [Parameter(Mandatory = $true)] [string] $ExpectedSha256
    )
    $publishedPath = Get-FaultGateJsonNonEmptyString -Value $Startup.launcher_executable_path -Label "launcher startup executable path"
    if (-not (Test-FaultGateDigest $Startup.launcher_executable_sha256) -or
        -not [IO.Path]::GetFullPath($publishedPath).Equals([IO.Path]::GetFullPath($ExpectedPath), [StringComparison]::OrdinalIgnoreCase) -or
        [string]$Startup.launcher_executable_sha256 -cne $ExpectedSha256) {
        throw "Launcher startup executable identity differs from the retained actual image binding."
    }
    return [pscustomobject][ordered]@{ path = [IO.Path]::GetFullPath($publishedPath); sha256 = [string]$Startup.launcher_executable_sha256 }
}

function Test-FaultGateFullPathEquals {
    param($PublishedPath, [Parameter(Mandatory = $true)] [string] $ExpectedPath)
    if ($PublishedPath -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$PublishedPath)) { return $false }
    try { return [IO.Path]::GetFullPath([string]$PublishedPath).Equals([IO.Path]::GetFullPath($ExpectedPath), [StringComparison]::OrdinalIgnoreCase) }
    catch { return $false }
}

function Test-FaultGateProcessExecutableBinding {
    param(
        [Parameter(Mandatory = $true)] $Identity,
        [Parameter(Mandatory = $true)] $PublishedExecutablePath,
        [Parameter(Mandatory = $true)] [string] $ExpectedExecutablePath,
        [Parameter(Mandatory = $true)] [string] $ExpectedExecutableSha256,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $publishedPath = Get-FaultGateJsonNonEmptyString -Value $PublishedExecutablePath -Label "$Label published executable path"
    $identityPath = Get-FaultGateJsonNonEmptyString -Value $Identity.executable_path -Label "$Label actual image path"
    if (-not (Test-FaultGateDigest $Identity.executable_sha256) -or
        -not [IO.Path]::GetFullPath($publishedPath).Equals([IO.Path]::GetFullPath($ExpectedExecutablePath), [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($identityPath).Equals([IO.Path]::GetFullPath($ExpectedExecutablePath), [StringComparison]::OrdinalIgnoreCase) -or
        [string]$Identity.executable_sha256 -cne $ExpectedExecutableSha256) {
        throw "$Label executable identity is not bound to the expected image path and digest."
    }
}

function Invoke-RawQualificationFaultGate {
    [CmdletBinding()]
    param(
        [int] $StartupDeadlineSeconds,
        [int] $FailureDeadlineSeconds,
        [int] $MinimumSealedSegmentsPerStream,
        [string] $FailureContainmentEvent,
        [string] $FailureContainmentSchema,
        [string] $OutputBase,
        [switch] $BootstrapValidateOnly
    )
    if ($MinimumSealedSegmentsPerStream -lt 1 -or $MinimumSealedSegmentsPerStream -gt 7) {
        throw "MinimumSealedSegmentsPerStream must remain within the generation-0-only pre-rotation window (1..7)."
    }
    if ($FailureDeadlineSeconds -ne 30) { throw "FailureDeadlineSeconds must remain exactly 30 seconds for the public fault gate." }
    $repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
    $helperScript = Join-Path $PSScriptRoot "RawQualification.Windows.ps1"
    $retainedArtifactBindings = [ordered]@{}
    $harnessSourceBinding = $null
    $helperSourceBinding = $null
    try {
    $harnessSourceBinding = Open-FaultGateRetainedPathBinding -Path $PSCommandPath -Role "harness"
    $retainedArtifactBindings["harness"] = $harnessSourceBinding
    $helperSourceBinding = Open-FaultGateRetainedPathBinding -Path $helperScript -Role "helper"
    $retainedArtifactBindings["helper"] = $helperSourceBinding
    if ($env:OS -cne "Windows_NT" -or -not [Environment]::Is64BitProcess) { throw "The real fault gate requires 64-bit Windows PowerShell." }
    . $helperScript
    Initialize-RawQualificationNative
    Initialize-FaultGateNative
    $harnessProcess = Get-Process -Id $PID -ErrorAction Stop
    $harnessProcessCreationFileTimeUtc = [int64]$harnessProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
    foreach ($bootstrapBinding in @($harnessSourceBinding, $helperSourceBinding)) {
        $localPath = Assert-FaultGateBootstrapNoReparsePointInExistingPath -Path ([string]$bootstrapBinding.path)
        $helperPath = Assert-RawQualificationNoReparsePointInExistingPath -Path ([string]$bootstrapBinding.path)
        if (-not [IO.Path]::GetFullPath($localPath).Equals([IO.Path]::GetFullPath([string]$helperPath), [StringComparison]::OrdinalIgnoreCase)) {
            throw "Bootstrap-local and helper anti-reparse barriers disagree: $($bootstrapBinding.role)"
        }
        $null = Test-FaultGateRetainedPathBinding -Binding $bootstrapBinding
    }
    if ($BootstrapValidateOnly) {
        $bootstrapRows = @(@($harnessSourceBinding, $helperSourceBinding) | ForEach-Object {
            [pscustomobject][ordered]@{
                role = [string]$_.role
                path = [string]$_.path
                length = [uint64]$_.length
                sha256 = [string]$_.sha256
                volume_serial_number = [uint32]$_.volume_serial_number
                file_index = [uint64]$_.file_index
            }
        })
        foreach ($bootstrapBinding in @($retainedArtifactBindings.Values)) { Close-FaultGateRetainedPathBinding -Binding $bootstrapBinding }
        foreach ($bootstrapBinding in @($retainedArtifactBindings.Values)) {
            if ($null -ne $bootstrapBinding.stream) { throw "Bootstrap retained binding did not close: $($bootstrapBinding.role)" }
        }
        $retainedArtifactBindings.Clear()
        Write-Output ([pscustomobject][ordered]@{
            schema = "RawQualificationFaultGateBootstrapValidationV1"
            status = "BOOTSTRAP_ONLY_NOT_FAULT_GATE"
            fault_gate_executed = $false
            network_started = $false
            evidence_published = $false
            retained_bindings_closed = $true
            bindings = $bootstrapRows
        } | ConvertTo-Json -Depth 10)
        return
    }
    $selftestScript = Join-Path $PSScriptRoot "_raw_fault_gate_selftest.ps1"
    $launcherScript = Join-Path $PSScriptRoot "run_24h_raw_qualification.ps1"
    $monitorScript = Join-Path $PSScriptRoot "monitor_24h_raw_qualification.ps1"
    $telemetryProbeScript = Join-Path $PSScriptRoot "RawQualification.TelemetryProbe.ps1"
    $watchdogScript = Join-Path $PSScriptRoot "RawQualification.Watchdog.ps1"
    $pythonRuntimeFingerprintScript = Join-Path $PSScriptRoot "RawQualification.PythonRuntimeFingerprint.ps1"
    $powerShellExecutable = Join-Path $PSHOME "powershell.exe"
    $campaignExecutable = Join-Path $repo "target\release\raw_campaign.exe"
    $captureExecutable = Join-Path $repo "target\release\segmented_capture.exe"
    $verifierExecutable = Join-Path $repo "target\release\campaign_verify.exe"
    $publicConfig = Join-Path $repo "config\public.json"
    $sourceLock = Join-Path (Split-Path $repo -Parent) "BINANCE_SOURCE_LOCK.md"
    $pythonExecutable = Join-Path $repo ".venv\Scripts\python.exe"
    $pythonProject = Join-Path $repo "pyproject.toml"
    $pythonRequirements = Join-Path $repo "requirements.lock"
    $pyvenvConfig = Join-Path $repo ".venv\pyvenv.cfg"
    $pyvenvBinding = Open-FaultGateRetainedPathBinding -Path $pyvenvConfig -Role "pyvenv_config"
    $retainedArtifactBindings["pyvenv_config"] = $pyvenvBinding
    $pythonRuntimePaths = Get-FaultGatePythonRuntimePathsFromRetainedConfig -Binding $pyvenvBinding
    $pythonBaseExecutable = [string]$pythonRuntimePaths.base_executable
    $artifactPaths = Get-FaultGateNominalDirectArtifactPaths -RepositoryRoot $repo -PythonBaseExecutable $pythonBaseExecutable
    if (-not [IO.Path]::GetFullPath($PSCommandPath).Equals([string]$artifactPaths.harness, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($helperScript).Equals([string]$artifactPaths.helper, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($selftestScript).Equals([string]$artifactPaths.selftest, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($launcherScript).Equals([string]$artifactPaths.launcher, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($monitorScript).Equals([string]$artifactPaths.monitor, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($telemetryProbeScript).Equals([string]$artifactPaths.telemetry_probe, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($watchdogScript).Equals([string]$artifactPaths.watchdog, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($pythonRuntimeFingerprintScript).Equals([string]$artifactPaths.python_runtime_fingerprint, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($powerShellExecutable).Equals([string]$artifactPaths.powershell, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($campaignExecutable).Equals([string]$artifactPaths.campaign, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($captureExecutable).Equals([string]$artifactPaths.capture, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($verifierExecutable).Equals([string]$artifactPaths.verifier, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($publicConfig).Equals([string]$artifactPaths.public_config, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($sourceLock).Equals([string]$artifactPaths.source_lock, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($pythonExecutable).Equals([string]$artifactPaths.python, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($pythonProject).Equals([string]$artifactPaths.pyproject, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($pythonRequirements).Equals([string]$artifactPaths.requirements, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFullPath($pyvenvConfig).Equals([string]$artifactPaths.pyvenv_config, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Fault gate direct-artifact construction diverged from the repository's nominal path contract."
    }
    foreach ($required in $artifactPaths.Values) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required executable/script is absent: $required" }
    }
    foreach ($artifactName in $artifactPaths.Keys) {
        if (-not $retainedArtifactBindings.Contains($artifactName)) {
            $retainedArtifactBindings[$artifactName] = Open-FaultGateRetainedPathBinding -Path ([string]$artifactPaths[$artifactName]) -Role $artifactName
        }
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path ([string]$retainedArtifactBindings[$artifactName].path)
    }
    $artifactBindingsAtStart = @($artifactPaths.Keys | ForEach-Object { Test-FaultGateRetainedPathBinding -Binding $retainedArtifactBindings[$_] })
    $sourceBindingsAtStart = @($artifactBindingsAtStart | Where-Object { [string]$_.role -cin @("harness", "helper") })
    $launchArtifactHashes = [ordered]@{}
    foreach ($artifactName in $artifactPaths.Keys) { $launchArtifactHashes[$artifactName] = [string]$retainedArtifactBindings[$artifactName].sha256 }
    $outputCandidate = [IO.Path]::GetFullPath((Join-Path $repo $OutputBase))
    $repoPrefix = $repo.TrimEnd('\') + '\'
    if ([IO.Path]::IsPathRooted($OutputBase) -or -not $outputCandidate.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "OutputBase must be relative and contained by the repository."
    }
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $outputCandidate
    $null = Assert-FaultGateLegacyPathBudget -OutputRoot $outputCandidate
    if (-not (Test-Path -LiteralPath $outputCandidate -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $outputCandidate -Force -ErrorAction Stop
    }
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $outputCandidate
    $preexistingProcessSnapshot = @(Get-FaultGateProcessSnapshot)
    $preexistingEngines = @(Get-FaultGateEngineProcesses -ProcessSnapshot $preexistingProcessSnapshot)
    if ($preexistingEngines.Count -ne 0) {
        throw "Fault gate requires global engine isolation; found: $(@($preexistingEngines | ForEach-Object { [string]$_.Name + ':' + [string]$_.ProcessId }) -join ',')"
    }

    $gateId = "f-" + [Guid]::NewGuid().ToString("N").Substring(0, 16)
    $gateRoot = Join-Path $outputCandidate $gateId
    $qualificationBase = Join-Path $gateRoot "qualification"
    $null = New-Item -ItemType Directory -Path $qualificationBase -ErrorAction Stop
    $gateRoot = [IO.Path]::GetFullPath($gateRoot)
    $qualificationBase = [IO.Path]::GetFullPath($qualificationBase)
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $gateRoot
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $qualificationBase
    $relativeQualificationBase = $qualificationBase.Substring($repo.Length + 1).Replace('\', '/')
    if (@(Get-ChildItem -LiteralPath $qualificationBase -Force).Count -ne 0) { throw "Unique qualification base was not empty at creation." }

    $faultJournalPath = Join-Path $gateRoot "fault-events.jsonl"
    $faultJournal = New-RawQualificationJournal -Path $faultJournalPath
    $outerJob = [IntPtr]::Zero
    $outerJobCreated = $false
    $launcherLaunch = $null
    $launcherIdentity = $null
    $identities = [Collections.Generic.List[object]]::new()
    $evidenceWritten = $false
    $runRoot = $null
    $supportArtifactBindings = @()
    $coordinatorStderrBindings = @()
    $gateFailure = $null
    $gateStage = "HARNESS_STARTING"
    try {
        $null = Add-FaultGateEvent -Journal $faultJournal -Event "HARNESS_STARTED" -Payload ([ordered]@{
            gate_id = $gateId
            repo = $repo
            qualification_base = $qualificationBase
            target_exit_code = $script:FaultGateTargetExitCode
            containment_exit_code = $script:FaultGateContainmentExitCode
            source_bindings = $sourceBindingsAtStart
            artifact_path_binding_scope = "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE"
            artifact_path_binding_trust_boundary = "Path-byte observation and retention do not assert absolute equivalence with bytes already interpreted or mapped by a runtime."
            artifact_path_bindings = $artifactBindingsAtStart
            launch_artifact_hashes = $launchArtifactHashes
        })
        $outerJobName = "Local\BinanceRawFaultGateOuter-" + $gateId
        $outerJob = [RawQualificationNative]::CreateKillOnCloseJob($outerJobName)
        $outerJobCreated = $true
        $gateStage = "WAITING_FOR_HEALTHY_MONITOR"
        $environmentEntries = Get-FaultGateChildEnvironment
        $launcherStdout = Join-Path $gateRoot "launcher.stdout.log"
        $launcherStderr = Join-Path $gateRoot "launcher.stderr.log"
        $launcherArguments = [string[]]@(
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $launcherScript,
            "-Mode", "Test", "-TotalSeconds", "300", "-RotationSeconds", "240", "-OverlapSeconds", "30", "-SegmentSeconds", "30",
            "-OutputBase", $relativeQualificationBase, "-StartupDeadlineSeconds", "180"
        )
        $launcherLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment($outerJob, $powerShellExecutable, $launcherArguments, $repo, $launcherStdout, $launcherStderr, $environmentEntries)
        $launcherActualExecutablePath = [IO.Path]::GetFullPath([RawFaultGateNative]::GetImagePath($launcherLaunch.ProcessHandle))
        if (-not $launcherActualExecutablePath.Equals([IO.Path]::GetFullPath([string]$retainedArtifactBindings["powershell"].path), [StringComparison]::OrdinalIgnoreCase)) {
            throw "Launcher retained process handle resolves to a different executable image path."
        }
        $startupOrigin = [int64][Diagnostics.Stopwatch]::GetTimestamp()
        $startupDeadlineTick = [int64]($startupOrigin + ([int64]$StartupDeadlineSeconds * [int64][Diagnostics.Stopwatch]::Frequency))
        $startup = $null
        $processControl = $null
        $bindings = $null
        $startupSnapshot = $null
        $processSnapshot = $null
        $bindingsSnapshot = $null
        $startupSha256 = $null
        $processSha256 = $null
        $bindingsSha256 = $null
        $monitorEvidence = $null
        $monitorAttempt = 0
        $lastStartupArtifactError = $null
        while ($null -eq $monitorEvidence) {
            if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick) -le 0) {
                throw "Startup/HEALTHY deadline expired before exact run binding. Last artifact error: $lastStartupArtifactError"
            }
            if ([RawQualificationNative]::WaitForProcessExit($launcherLaunch.ProcessHandle, 0)) {
                throw "Launcher exited before the fault gate reached HEALTHY_RUNNING."
            }
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $gateRoot
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $qualificationBase
            $baseEntries = @(Get-ChildItem -LiteralPath $qualificationBase -Force -ErrorAction Stop)
            if (@($baseEntries | Where-Object { -not $_.PSIsContainer }).Count -ne 0) { throw "Unique qualification base contains a non-directory entry." }
            $children = @($baseEntries | Where-Object { $_.PSIsContainer })
            if ($children.Count -gt 1) { throw "Unique qualification base contains multiple run directories." }
            if ($children.Count -eq 1) {
                if ($null -eq $runRoot) {
                    $runRoot = [IO.Path]::GetFullPath($children[0].FullName)
                    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $runRoot
                }
                elseif ($runRoot -cne [IO.Path]::GetFullPath($children[0].FullName)) { throw "Run root identity changed." }
                $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $runRoot
                $startupPath = Join-Path $runRoot "launcher-startup.json"
                $processPath = Join-Path $runRoot "processes.json"
                $bindingsPath = Join-Path $runRoot "campaign-bindings.json"
                if ((Test-Path -LiteralPath $startupPath -PathType Leaf) -and (Test-Path -LiteralPath $processPath -PathType Leaf) -and (Test-Path -LiteralPath $bindingsPath -PathType Leaf)) {
                    try {
                        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $startupPath
                        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $processPath
                        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $bindingsPath
                        $startupSnapshot = Read-FaultGateJsonSnapshot -Path $startupPath -RequireCanonicalPrettyJson
                        $processSnapshot = Read-FaultGateJsonSnapshot -Path $processPath -RequireCanonicalPrettyJson
                        $bindingsSnapshot = Read-FaultGateJsonSnapshot -Path $bindingsPath -RequireCanonicalPrettyJson
                        $startup = $startupSnapshot.value
                        $processControl = $processSnapshot.value
                        $bindings = $bindingsSnapshot.value
                        Test-FaultGateLauncherStartupSchema -Startup $startup
                        Test-FaultGateProcessControlSchema -ProcessControl $processControl
                        Test-FaultGateCampaignBindingsSchema -Bindings $bindings
                        $null = Test-FaultGateLauncherStartupExecutableBinding -Startup $startup -ExpectedPath $launcherActualExecutablePath -ExpectedSha256 ([string]$launchArtifactHashes.powershell)
                        $sealedRuntimeRoot = Join-Path $runRoot "sealed-runtime"
                        $expectedSealedCampaign = Join-Path $sealedRuntimeRoot "bin\raw_campaign.exe"
                        $expectedSealedCapture = Join-Path $sealedRuntimeRoot "bin\segmented_capture.exe"
                        $expectedSealedVerifier = Join-Path $sealedRuntimeRoot "bin\campaign_verify.exe"
                        $expectedSealedPublicConfig = Join-Path $sealedRuntimeRoot "config\public.json"
                        if ([string]$startup.schema -cne "RawQualificationLauncherStartupV1" -or [string]$startup.run_root -cne $runRoot -or
                            [string]$startup.run_id -cne [IO.Path]::GetFileName($runRoot) -or [string]$startup.mode -cne "Test" -or
                            [uint32]$startup.launcher_pid -ne [uint32]$launcherLaunch.ProcessId -or
                            [string]$startup.launcher_command_line -cne [string]$launcherLaunch.ExactCommandLine -or
                            [DateTime]::Parse([string]$startup.launcher_creation_time_utc).ToUniversalTime().ToFileTimeUtc() -ne [int64]$launcherLaunch.CreationFileTimeUtc -or
                            [string]$processControl.run_id -cne [string]$startup.run_id -or [string]$bindings.run_id -cne [string]$startup.run_id -or
                            [string]$startup.preflight.campaign_executable_sha256 -cne [string]$launchArtifactHashes.campaign -or
                            [string]$startup.preflight.capture_executable_sha256 -cne [string]$launchArtifactHashes.capture -or
                            [string]$startup.preflight.campaign_verifier_executable_sha256 -cne [string]$launchArtifactHashes.verifier -or
                            [string]$startup.preflight.public_config_sha256 -cne [string]$launchArtifactHashes.public_config -or
                            [string]$startup.preflight.launcher_script_sha256 -cne [string]$launchArtifactHashes.launcher -or
                            [string]$startup.preflight.monitor_script_sha256 -cne [string]$launchArtifactHashes.monitor -or
                            [string]$startup.preflight.helper_script_sha256 -cne [string]$launchArtifactHashes.helper -or
                            [string]$startup.preflight.telemetry_probe_script_sha256 -cne [string]$launchArtifactHashes.telemetry_probe -or
                            [string]$startup.preflight.watchdog_script_sha256 -cne [string]$launchArtifactHashes.watchdog -or
                            [string]$startup.preflight.python_runtime_fingerprint_script_sha256 -cne [string]$launchArtifactHashes.python_runtime_fingerprint -or
                            [string]$startup.preflight.powershell_executable_sha256 -cne [string]$launchArtifactHashes.powershell -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.campaign_executable -ExpectedPath $expectedSealedCampaign) -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.capture_executable -ExpectedPath $expectedSealedCapture) -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.campaign_verifier_executable -ExpectedPath $expectedSealedVerifier) -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.public_config -ExpectedPath $expectedSealedPublicConfig) -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.launcher_script -ExpectedPath ([string]$artifactPaths.launcher)) -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.monitor_script -ExpectedPath ([string]$artifactPaths.monitor)) -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.helper_script -ExpectedPath ([string]$artifactPaths.helper)) -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.telemetry_probe_script -ExpectedPath ([string]$artifactPaths.telemetry_probe)) -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.watchdog_script -ExpectedPath ([string]$artifactPaths.watchdog)) -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.python_runtime_fingerprint_script -ExpectedPath ([string]$artifactPaths.python_runtime_fingerprint)) -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.powershell_executable -ExpectedPath ([string]$artifactPaths.powershell)) -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.source_lock -ExpectedPath ([string]$artifactPaths.source_lock)) -or
                            [string]$startup.preflight.source_lock_sha256 -cne [string]$launchArtifactHashes.source_lock -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.python -ExpectedPath ([string]$artifactPaths.python)) -or
                            [string]$startup.preflight.python_sha256 -cne [string]$launchArtifactHashes.python -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.python_project -ExpectedPath ([string]$artifactPaths.pyproject)) -or
                            [string]$startup.preflight.python_project_sha256 -cne [string]$launchArtifactHashes.pyproject -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.python_requirements -ExpectedPath ([string]$artifactPaths.requirements)) -or
                            [string]$startup.preflight.python_requirements_sha256 -cne [string]$launchArtifactHashes.requirements -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.python_runtime.pyvenv_config -ExpectedPath ([string]$artifactPaths.pyvenv_config)) -or
                            [string]$startup.preflight.python_runtime.pyvenv_config_sha256 -cne [string]$launchArtifactHashes.pyvenv_config -or
                            -not (Test-FaultGateFullPathEquals -PublishedPath $startup.preflight.python_runtime.base_executable -ExpectedPath ([string]$artifactPaths.python_base_executable)) -or
                            [string]$startup.preflight.python_runtime.base_executable_sha256 -cne [string]$launchArtifactHashes.python_base_executable) {
                            throw "Launcher startup/run/process/binding identity is not exact."
                        }
                        $monitorAttempt++
                        $remainingBeforeMonitor = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick
                        if ($remainingBeforeMonitor -lt 11000) { throw "Insufficient remaining startup deadline for a monitor attempt and bounded drain." }
                        $monitorEvidence = Invoke-FaultGateMonitorAttempt -OuterJob $outerJob -PowerShellExecutable $powerShellExecutable `
                            -ExpectedPowerShellSha256 ([string]$launchArtifactHashes.powershell) -MonitorScript $monitorScript -RunRoot $runRoot `
                            -GateRoot $gateRoot -EnvironmentEntries $environmentEntries -ExpectedGuardianPid ([uint32]$startup.launcher_pid) `
                            -ExpectedProcesses @($processControl.processes) -ExpectedCampaigns @($bindings.campaigns) `
                            -ExpectedMinimumDiskFreeGiB ([uint64]$startup.preflight.required_free_gib) `
                            -Attempt $monitorAttempt -DeadlineMonotonicTick $startupDeadlineTick
                        if ($null -ne $monitorEvidence) {
                            foreach ($controlPath in @($startupPath, $processPath, $bindingsPath)) { $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $controlPath }
                            $freshStartupSnapshot = Read-FaultGateJsonSnapshot -Path $startupPath -RequireCanonicalPrettyJson
                            $freshProcessSnapshot = Read-FaultGateJsonSnapshot -Path $processPath -RequireCanonicalPrettyJson
                            $freshBindingsSnapshot = Read-FaultGateJsonSnapshot -Path $bindingsPath -RequireCanonicalPrettyJson
                            if ([string]$freshStartupSnapshot.sha256 -cne [string]$startupSnapshot.sha256 -or [uint64]$freshStartupSnapshot.bytes -ne [uint64]$startupSnapshot.bytes -or
                                [string]$freshProcessSnapshot.sha256 -cne [string]$processSnapshot.sha256 -or [uint64]$freshProcessSnapshot.bytes -ne [uint64]$processSnapshot.bytes -or
                                [string]$freshBindingsSnapshot.sha256 -cne [string]$bindingsSnapshot.sha256 -or [uint64]$freshBindingsSnapshot.bytes -ne [uint64]$bindingsSnapshot.bytes) {
                                throw "Launcher startup/process/binding bytes changed during the HEALTHY monitor observation."
                            }
                            $startupSnapshot = $freshStartupSnapshot; $processSnapshot = $freshProcessSnapshot; $bindingsSnapshot = $freshBindingsSnapshot
                            $startup = $freshStartupSnapshot.value; $processControl = $freshProcessSnapshot.value; $bindings = $freshBindingsSnapshot.value
                            $startupSha256 = [string]$freshStartupSnapshot.sha256; $processSha256 = [string]$freshProcessSnapshot.sha256; $bindingsSha256 = [string]$freshBindingsSnapshot.sha256
                        }
                    }
                    catch {
                        $lastStartupArtifactError = $_.Exception.Message
                        if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick) -le 0) { throw "Startup/HEALTHY deadline expired during bounded monitor observation. Last artifact error: $lastStartupArtifactError" }
                        $startup = $null; $processControl = $null; $bindings = $null; $monitorEvidence = $null
                    }
                }
            }
            if ($null -eq $monitorEvidence) {
                $remainingBeforeRetry = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick
                if ($remainingBeforeRetry -lt 11000) { throw "Insufficient remaining startup deadline for another bounded monitor attempt." }
                Start-Sleep -Milliseconds ([int][Math]::Min([int64]1000, $remainingBeforeRetry - 10000))
            }
        }
        $launcherIdentity = [pscustomobject][ordered]@{
            role = "launcher"; pid = [uint32]$launcherLaunch.ProcessId; parent_pid = [uint32]$PID
            creation_filetime_utc = [int64]$launcherLaunch.CreationFileTimeUtc
            creation_time_utc = [DateTime]::FromFileTimeUtc([int64]$launcherLaunch.CreationFileTimeUtc).ToString("o")
            executable_path = $launcherActualExecutablePath
            executable_sha256 = Get-FaultGateSha256File -Path $powerShellExecutable
            command_line = [string]$launcherLaunch.ExactCommandLine
            command_line_sha256 = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes([string]$launcherLaunch.ExactCommandLine))
            handle = $launcherLaunch.ProcessHandle
        }
        if ([string]$launcherIdentity.executable_sha256 -cne [string]$launchArtifactHashes.powershell) { throw "Retained launcher executable hash drifted from launch-time provenance." }
        $identities.Add($launcherIdentity)
        $readyPath = Join-Path $runRoot "watchdog-ready.json"
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $readyPath
        $readySnapshot = Read-FaultGateJsonSnapshot -Path $readyPath -RequireCanonicalPrettyJson
        $ready = $readySnapshot.value
        Test-FaultGateWatchdogReadySchema -Ready $ready
        $readySha256 = [string]$readySnapshot.sha256
        Test-FaultGateControlCrosslinks -Startup $startup -ProcessControl $processControl -Bindings $bindings -Ready $ready -RepositoryRoot $repo -QualificationBase $qualificationBase -RunRoot $runRoot -ReadySha256 $readySha256
        $readyEvidence = [pscustomobject][ordered]@{
            schema = [string]$ready.schema; pid = [uint32]$ready.pid; job_name = [string]$ready.job_name
            observed_qpc_timestamp = [uint64]$ready.observed_qpc_timestamp; file_bytes = [uint64]$readySnapshot.bytes; file_sha256 = $readySha256
        }
        $null = Add-FaultGateEvent -Journal $faultJournal -Event "RUN_BOUND" -Payload ([ordered]@{
            run_id = [string]$startup.run_id; run_root = $runRoot; launcher_pid = [uint32]$launcherLaunch.ProcessId
            launcher_creation_filetime_utc = [int64]$launcherLaunch.CreationFileTimeUtc
            launcher_command_line_sha256 = [string]$launcherIdentity.command_line_sha256
            startup_sha256 = $startupSha256
            processes_sha256 = $processSha256
            bindings_sha256 = $bindingsSha256
        })
        $processRows = @($processControl.processes)
        $bindingRows = @($bindings.campaigns)
        if ($processRows.Count -ne 2 -or $bindingRows.Count -ne 2) { throw "Process/binding files do not contain exactly BTCUSDT and ETHUSDT." }
        $campaignJournals = @{}
        $captureEvents = @{}
        $campaignDirectories = @{}
        $campaignStartupSnapshots = @{}
        foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
            $processRow = @($processRows | Where-Object { [string]$_.symbol -ceq $symbol })
            $bindingRow = @($bindingRows | Where-Object { [string]$_.symbol -ceq $symbol })
            if ($processRow.Count -ne 1 -or $bindingRow.Count -ne 1 -or [uint32]$processRow[0].pid -ne [uint32]$bindingRow[0].pid) { throw "$symbol process/binding identity is ambiguous." }
            # The launcher executes the byte-verified copy inside the immutable
            # per-run sealed runtime, not the mutable build-tree source path.
            # The startup artifact above binds this exact path to the retained
            # source digest before any coordinator identity is accepted.
            $sealedCampaignPath = [IO.Path]::GetFullPath([string]$startup.preflight.campaign_executable)
            if (-not $sealedCampaignPath.Equals([IO.Path]::GetFullPath($expectedSealedCampaign), [StringComparison]::OrdinalIgnoreCase)) {
                throw "$symbol sealed campaign executable path drifted after startup binding."
            }
            $coordinatorCommand = [RawQualificationNative]::BuildExactCommandLine(
                $sealedCampaignPath,
                [string[]]@(
                    $symbol,
                    ([uint64]$startup.parameters.total_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                    ([uint64]$startup.parameters.rotation_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                    ([uint64]$startup.parameters.overlap_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                    ([uint64]$startup.parameters.segment_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                    $runRoot,
                    "--event-stream"
                ))
            if ([string]$processRow[0].command_line -cne $coordinatorCommand) { throw "$symbol coordinator command line is not the nominal fault-gate launch contract." }
            $coordinator = Open-FaultGateExactProcess -ProcessId ([uint32]$processRow[0].pid) -ExpectedExecutable $sealedCampaignPath -ExpectedCommandLine $coordinatorCommand -ExpectedParentProcessId ([uint32]$launcherLaunch.ProcessId) -Role ($symbol + "_coordinator") -ExpectedCreationTimeUtc ([string]$processRow[0].creation_time_utc)
            Test-FaultGateProcessExecutableBinding -Identity $coordinator -PublishedExecutablePath $processRow[0].executable_path -ExpectedExecutablePath $sealedCampaignPath -ExpectedExecutableSha256 ([string]$launchArtifactHashes.campaign) -Label "$symbol coordinator"
            if ([string]$coordinator.executable_sha256 -cne [string]$processRow[0].executable_sha256) { throw "$symbol coordinator published executable digest drifted." }
            $identities.Add($coordinator)
            $campaignId = Get-FaultGateJsonNonEmptyString -Value $bindingRow[0].campaign_id -Label "$symbol campaign id"
            if ($campaignId -cnotmatch ('^[0-9]+-' + $symbol + '-raw-[0-9a-f]{12}$') -or [IO.Path]::GetFileName($campaignId) -cne $campaignId) { throw "$symbol campaign id is not canonical." }
            $expectedCampaignDir = [IO.Path]::GetFullPath((Join-Path $runRoot $campaignId))
            $campaignDir = [IO.Path]::GetFullPath([string]$bindingRow[0].campaign_directory)
            if (-not $campaignDir.Equals($expectedCampaignDir, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($campaignDir) -cne $campaignId) { throw "$symbol campaign directory is not the exact RunRoot/campaign_id child." }
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $campaignDir
            $campaignDirectories[$symbol] = $campaignDir
            $campaignStartupPath = Join-Path $campaignDir "campaign-startup.json"
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $campaignStartupPath
            $campaignStartupSnapshot = Read-FaultGateRawCampaignStartup -Path $campaignStartupPath -ExpectedCampaignId $campaignId -ExpectedSymbol $symbol -ExpectedPid ([uint32]$processRow[0].pid) -ExpectedParameters $startup.parameters -ExpectedCampaignExecutableSha256 ([string]$launchArtifactHashes.campaign) -ExpectedCaptureExecutableSha256 ([string]$launchArtifactHashes.capture) -ExpectedPublicConfigSha256 ([string]$launchArtifactHashes.public_config) -ExpectedSpecRevision ([string]$startup.preflight.spec_revision)
            if ([string]$campaignStartupSnapshot.sha256 -cne [string]$bindingRow[0].campaign_startup_sha256) { throw "$symbol campaign binding startup digest is invalid." }
            $campaignStartupSnapshots[$symbol] = $campaignStartupSnapshot
            $campaignJournalPath = Join-Path $campaignDir "campaign-events.jsonl"
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $campaignJournalPath
            $campaignJournal = Read-FaultGateJournal -Path $campaignJournalPath -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCanonicalCompactJson
            $campaignJournals[$symbol] = $campaignJournal
            $started = @(Get-FaultGateJournalEvents -Journal $campaignJournal -Event "PROCESS_STARTED" | Where-Object { [uint64]$_.body.payload.generation_index -eq 0 })
            if ($started.Count -ne 1 -or [string]$started[0].body.payload.symbol -cne $symbol) { throw "$symbol lacks one exact generation-0 PROCESS_STARTED." }
            $initialStartedPayload = $started[0].body.payload
            Assert-FaultGateExactProperties -Value $initialStartedPayload -Names @("event", "generation_index", "process_id", "schema", "session_dir", "session_id", "spec_revision", "startup_manifest_sha256", "symbol") -Label "$symbol initial PROCESS_STARTED payload"
            $initialSessionId = Get-FaultGatePortableLeafComponent -Value $initialStartedPayload.session_id -Label "$symbol initial session_id"
            $initialCapturePid = Get-FaultGateJsonUnsignedInteger -Value $initialStartedPayload.process_id -Label "$symbol initial capture pid" -Maximum ([uint32]::MaxValue)
            Assert-FaultGateEvidenceDigest -Value $initialStartedPayload.startup_manifest_sha256 -Label "$symbol initial generation startup digest"
            if ([string]$started[0].body.channel -cne "CHILD_STDOUT" -or [uint64]$started[0].body.generation_index -ne 0 -or
                (Get-FaultGateJsonUnsignedInteger -Value $initialStartedPayload.generation_index -Label "$symbol initial generation index") -ne 0 -or
                $initialCapturePid -eq 0 -or [string]$initialStartedPayload.event -cne "PROCESS_STARTED" -or
                [string]$initialStartedPayload.schema -cne "CaptureProcessEventV1" -or [string]$initialStartedPayload.symbol -cne $symbol -or
                [string]$initialStartedPayload.spec_revision -cne [string]$startup.preflight.spec_revision) {
                throw "$symbol initial PROCESS_STARTED identity is invalid."
            }
            $captureEvents[$symbol] = $started[0]
            $expectedSessionDirectory = [IO.Path]::GetFullPath((Join-Path (Join-Path $campaignDir "generations") $initialSessionId))
            if ([IO.Path]::GetFullPath([string]$initialStartedPayload.session_dir) -cne $expectedSessionDirectory) { throw "$symbol generation-0 session directory is outside its exact campaign generation path." }
            $firstDuration = [math]::Min(
                [int]$startup.parameters.total_s,
                [int]$script:FaultGateGenerationZeroDurationSeconds)
            $sealedCapturePath = [IO.Path]::GetFullPath([string]$startup.preflight.capture_executable)
            if (-not $sealedCapturePath.Equals([IO.Path]::GetFullPath($expectedSealedCapture), [StringComparison]::OrdinalIgnoreCase)) {
                throw "$symbol sealed capture executable path drifted after startup binding."
            }
            $captureCommand = [RawQualificationNative]::BuildExactCommandLine($sealedCapturePath, [string[]]@($symbol, "0", [string]$firstDuration, [string]$startup.parameters.segment_s, (Join-Path $campaignDir "generations")))
            $capture = Open-FaultGateExactProcess -ProcessId ([uint32]$initialCapturePid) -ExpectedExecutable $sealedCapturePath -ExpectedCommandLine $captureCommand -ExpectedParentProcessId ([uint32]$coordinator.pid) -Role ($symbol + "_generation_0")
            if ([string]$capture.executable_sha256 -cne [string]$launchArtifactHashes.capture) { throw "$symbol generation executable provenance drifted." }
            $identities.Add($capture)
        }
        $watchdogRow = $processControl.watchdog
        if (-not (Test-FaultGateFullPathEquals -PublishedPath $watchdogRow.script_path -ExpectedPath ([string]$retainedArtifactBindings["watchdog"].path)) -or
            [string]$watchdogRow.script_sha256 -cne [string]$launchArtifactHashes.watchdog -or
            [string]$watchdogRow.guardian_pulse_file -cne "guardian-pulse.jsonl" -or [string]$watchdogRow.ready_file -cne "watchdog-ready.json" -or
            [string]$watchdogRow.stdout_file -cne "watchdog.stdout.log" -or [string]$watchdogRow.stderr_file -cne "watchdog.stderr.log") {
            throw "Watchdog process control is not bound to the retained watchdog script and nominal support files."
        }
        $watchdogCommand = [RawQualificationNative]::BuildExactCommandLine(
            [string]$retainedArtifactBindings["powershell"].path,
            [string[]]@(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", [string]$retainedArtifactBindings["watchdog"].path,
                "-HelperPath", [string]$retainedArtifactBindings["helper"].path,
                "-JobName", [string]$processControl.job_object_name,
                "-RunId", [string]$startup.run_id,
                "-GuardianPulsePath", (Join-Path $runRoot "guardian-pulse.jsonl"),
                "-ReadyPath", (Join-Path $runRoot "watchdog-ready.json"),
                "-StopPath", (Join-Path $runRoot "watchdog-stop.json"),
                "-FailurePath", (Join-Path $runRoot "watchdog-failure.json"),
                "-LaunchOriginQpcTimestamp", ([uint64]$watchdogRow.launch_origin_qpc_timestamp).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-MonotonicFrequency", ([uint64]$watchdogRow.monotonic_frequency).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-StartupDeadlineSeconds", ([uint64]$watchdogRow.startup_deadline_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-MaximumGuardianPulseAgeSeconds", ([uint64]$watchdogRow.maximum_guardian_pulse_age_s).ToString([Globalization.CultureInfo]::InvariantCulture)
            ))
        if ([string]$watchdogRow.command_line -cne $watchdogCommand) { throw "Watchdog command line is not independently derived from the retained nominal launch contract." }
        $watchdog = Open-FaultGateExactProcess -ProcessId ([uint32]$watchdogRow.pid) -ExpectedExecutable ([string]$retainedArtifactBindings["powershell"].path) -ExpectedCommandLine $watchdogCommand -ExpectedParentProcessId ([uint32]$launcherLaunch.ProcessId) -Role "watchdog" -ExpectedCreationTimeUtc ([string]$watchdogRow.creation_time_utc)
        Test-FaultGateProcessExecutableBinding -Identity $watchdog -PublishedExecutablePath $watchdogRow.executable_path -ExpectedExecutablePath ([string]$retainedArtifactBindings["powershell"].path) -ExpectedExecutableSha256 ([string]$launchArtifactHashes.powershell) -Label "watchdog"
        $identities.Add($watchdog)

        $preFaultRaw = $null
        $preFaultCampaignPrefixes = $null
        while ($null -eq $preFaultRaw) {
            if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick) -le 0) { throw "Raw sealed-prefix deadline expired." }
            try {
                $reports = [Collections.Generic.List[object]]::new()
                $scanJournals = @{}
                foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
                    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path ([string]$campaignJournals[$symbol].path)
                    $freshJournal = Read-FaultGateJournal -Path $campaignJournals[$symbol].path -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCanonicalCompactJson
                    $scanJournals[$symbol] = $freshJournal
                    $sessionDir = [string]$captureEvents[$symbol].body.payload.session_dir
                    $reports.Add((Test-FaultGateRawGeneration -SessionDirectory $sessionDir -Symbol $symbol -ExpectedSpecRevision ([string]$startup.preflight.spec_revision) -ExpectedCaptureExecutableSha256 ([string]$launchArtifactHashes.capture) -ExpectedPublicConfigSha256 ([string]$launchArtifactHashes.public_config) -CampaignJournal $freshJournal -MinimumSealedSegments ([uint64]$MinimumSealedSegmentsPerStream) -ExpectedCampaignDirectory ([string]$campaignDirectories[$symbol]) -ExpectedSegmentDuration ([uint64]$startup.parameters.segment_s) -ExpectedMarketFreshnessStartupGrace ([uint64]$startup.market_freshness_policy.startup_grace_s) -ExpectedMarketFreshnessDeadline ([uint64]$startup.market_freshness_policy.deadline_s) -LivePrefixObservation))
                    if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick) -le 0) { throw "Raw sealed-prefix scan crossed the absolute startup deadline for $symbol." }
                }
                $postScanJournals = @{}
                $candidatePrefixes = [Collections.Generic.List[object]]::new()
                for ($symbolIndex = 0; $symbolIndex -lt 2; $symbolIndex++) {
                    $symbol = @("BTCUSDT", "ETHUSDT")[$symbolIndex]
                    $campaignJournalPath = [string]$campaignJournals[$symbol].path
                    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $campaignJournalPath
                    $postScanJournal = Read-FaultGateJournal -Path $campaignJournalPath -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCleanTail -RequireCanonicalCompactJson
                    $scanPrefix = [pscustomobject][ordered]@{
                        symbol = $symbol; records = [uint64]$scanJournals[$symbol].records; clean_tail = [bool]$scanJournals[$symbol].clean_tail
                        terminal_record_sha256 = [string]$scanJournals[$symbol].terminal_record_sha256; file_sha256 = [string]$scanJournals[$symbol].file_sha256
                    }
                    # The authenticated prefix existed before the raw scan, so every event
                    # inside it must link to the bounded raw/telemetry evidence just read.
                    # A journal append during that scan is normal live progress; only the
                    # narrowly defined healthy generation-0 suffix may follow it.
                    $null = Test-FaultGatePreInjectionCampaignWindow -Journal $postScanJournal -PreFaultPrefix $scanPrefix -Symbol $symbol -ExpectedSessionId ([string]$reports[$symbolIndex].session_id) -ExpectedCampaignStartupSha256 ([string]$campaignStartupSnapshots[$symbol].sha256) -FinalRawGeneration $reports[$symbolIndex]
                    $postScanJournals[$symbol] = $postScanJournal
                    $candidatePrefixes.Add($scanPrefix)
                }
                if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick) -le 0) { throw "Raw/campaign prefix materialization crossed the absolute startup deadline." }
                foreach ($symbol in @("BTCUSDT", "ETHUSDT")) { $campaignJournals[$symbol] = $postScanJournals[$symbol] }
                $preFaultCampaignPrefixes = @($candidatePrefixes)
                $preFaultRaw = @($reports)
            }
            catch {
                if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick) -le 0) { throw }
                $remainingRetry = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick
                Start-Sleep -Milliseconds ([int][Math]::Min([int64]1000, $remainingRetry))
            }
        }
        foreach ($identity in $identities) {
            if ([RawQualificationNative]::WaitForProcessExit($identity.handle, 0)) {
                throw "Qualification identity exited before the final pre-injection HEALTHY observation: $($identity.role)"
            }
        }
        $monitorAttempt++
        $remainingBeforeFinalMonitor = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick
        if ($remainingBeforeFinalMonitor -lt 11000) { throw "Insufficient startup budget for the final pre-injection HEALTHY monitor and bounded drain." }
        $finalMonitorEvidence = Invoke-FaultGateMonitorAttempt -OuterJob $outerJob -PowerShellExecutable $powerShellExecutable `
            -ExpectedPowerShellSha256 ([string]$launchArtifactHashes.powershell) -MonitorScript $monitorScript -RunRoot $runRoot `
            -GateRoot $gateRoot -EnvironmentEntries $environmentEntries -ExpectedGuardianPid ([uint32]$startup.launcher_pid) `
            -ExpectedProcesses @($processControl.processes) -ExpectedCampaigns @($bindings.campaigns) `
            -ExpectedMinimumDiskFreeGiB ([uint64]$startup.preflight.required_free_gib) `
            -Attempt $monitorAttempt -DeadlineMonotonicTick $startupDeadlineTick
        if ($null -eq $finalMonitorEvidence) { throw "Final pre-injection monitor did not prove HEALTHY_RUNNING/CAPTURING." }
        $monitorEvidence = $finalMonitorEvidence
        foreach ($controlPath in @($startupPath, $processPath, $bindingsPath, $readyPath)) { $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $controlPath }
        $preInjectionStartup = Read-FaultGateJsonSnapshot -Path $startupPath -RequireCanonicalPrettyJson
        $preInjectionProcesses = Read-FaultGateJsonSnapshot -Path $processPath -RequireCanonicalPrettyJson
        $preInjectionBindings = Read-FaultGateJsonSnapshot -Path $bindingsPath -RequireCanonicalPrettyJson
        $preInjectionReady = Read-FaultGateJsonSnapshot -Path $readyPath -RequireCanonicalPrettyJson
        if ([string]$preInjectionStartup.sha256 -cne $startupSha256 -or [uint64]$preInjectionStartup.bytes -ne [uint64]$startupSnapshot.bytes -or
            [string]$preInjectionProcesses.sha256 -cne $processSha256 -or [uint64]$preInjectionProcesses.bytes -ne [uint64]$processSnapshot.bytes -or
            [string]$preInjectionBindings.sha256 -cne $bindingsSha256 -or [uint64]$preInjectionBindings.bytes -ne [uint64]$bindingsSnapshot.bytes -or
            [string]$preInjectionReady.sha256 -cne $readySha256 -or [uint64]$preInjectionReady.bytes -ne [uint64]$readySnapshot.bytes) {
            throw "Control/READY bytes changed before the final pre-injection HEALTHY boundary."
        }
        for ($symbolIndex = 0; $symbolIndex -lt 2; $symbolIndex++) {
            $symbol = @("BTCUSDT", "ETHUSDT")[$symbolIndex]
            $journalPath = [string]$campaignJournals[$symbol].path
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $journalPath
            $finalPreFaultJournal = Read-FaultGateJournal -Path $journalPath -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCleanTail -RequireCanonicalCompactJson
            $frozenPrefix = @($preFaultCampaignPrefixes | Where-Object { [string]$_.symbol -ceq $symbol })
            if ($frozenPrefix.Count -ne 1) { throw "$symbol lacks one frozen pre-scan campaign prefix." }
            $null = Test-FaultGatePreInjectionCampaignWindow -Journal $finalPreFaultJournal -PreFaultPrefix $frozenPrefix[0] -Symbol $symbol -ExpectedSessionId ([string]$preFaultRaw[$symbolIndex].session_id) -ExpectedCampaignStartupSha256 ([string]$campaignStartupSnapshots[$symbol].sha256) -FinalRawGeneration $preFaultRaw[$symbolIndex]
            $campaignJournals[$symbol] = $finalPreFaultJournal
        }
        # The raw report is the bounded, authenticated snapshot taken after the frozen
        # campaign prefix.  Re-reading a non-quiescent generation from byte zero here
        # would create quadratic work and monitoring backpressure.  Subsequent journal
        # appends are admitted only through Test-FaultGatePreInjectionCampaignWindow's
        # exact healthy generation-0 suffix FSM, and terminal verification later links
        # every resulting durable artifact after containment.
        foreach ($identity in $identities) {
            if ([RawQualificationNative]::WaitForProcessExit($identity.handle, 0)) {
                throw "Qualification identity exited during the final pre-injection HEALTHY/journal revalidation: $($identity.role)"
            }
        }
        if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick) -le 0) { throw "Final pre-injection HEALTHY/journal revalidation crossed the startup deadline." }
        $null = Add-FaultGateEvent -Journal $faultJournal -Event "LIVE_HEALTHY" -Payload ([ordered]@{
            monitor_attempt = [uint64]$monitorEvidence.attempt; monitor_stdout_sha256 = [string]$monitorEvidence.stdout_sha256
            status = [string]$monitorEvidence.report.status; stage = [string]$monitorEvidence.report.stage
            host_telemetry_records = [uint64]$monitorEvidence.report.host_telemetry_records; watchdog_ready_sha256 = $readySha256
        })
        $gateStage = "PREPARING_FAULT_INJECTION"
        $target = @($identities | Where-Object { [string]$_.role -ceq "BTCUSDT_generation_0" })[0]
        if ([RawQualificationNative]::WaitForProcessExit($target.handle, 0)) { throw "BTC generation-0 target exited before durable proposal." }
        if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick) -le 0) { throw "Startup deadline expired immediately before sealing fault proposal." }
        $preFaultRawSha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($preFaultRaw))
        $preFaultCampaignPrefixesSha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($preFaultCampaignPrefixes))
        $proposalSha = Add-FaultGateEvent -Journal $faultJournal -Event "FAULT_PROPOSED" -Payload ([ordered]@{
            run_id = [string]$startup.run_id; run_root = $runRoot; symbol = "BTCUSDT"; generation_index = [uint64]0
            target_pid = [uint32]$target.pid; target_creation_filetime_utc = [int64]$target.creation_filetime_utc
            target_parent_pid = [uint32]$target.parent_pid; target_executable_sha256 = [string]$target.executable_sha256
            target_command_line_sha256 = [string]$target.command_line_sha256; requested_exit_code = $script:FaultGateTargetExitCode
            pre_fault_raw_prefixes_sha256 = $preFaultRawSha256
            pre_fault_campaign_prefixes_sha256 = $preFaultCampaignPrefixesSha256; pre_fault_campaign_prefixes = @($preFaultCampaignPrefixes)
        })
        foreach ($identity in $identities) {
            if ([RawQualificationNative]::WaitForProcessExit($identity.handle, 0)) { throw "Qualification peer died after proposal but before the injection request: $($identity.role)" }
        }
        for ($symbolIndex = 0; $symbolIndex -lt 2; $symbolIndex++) {
            $symbol = @("BTCUSDT", "ETHUSDT")[$symbolIndex]
            $immediateJournal = Read-FaultGateJournal -Path ([string]$campaignJournals[$symbol].path) -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCleanTail -RequireCanonicalCompactJson
            $frozenPrefix = @($preFaultCampaignPrefixes | Where-Object { [string]$_.symbol -ceq $symbol })
            if ($frozenPrefix.Count -ne 1) { throw "$symbol exact frozen campaign prefix is absent immediately before the injection request." }
            $null = Test-FaultGatePreInjectionCampaignWindow -Journal $immediateJournal -PreFaultPrefix $frozenPrefix[0] -Symbol $symbol -ExpectedSessionId ([string]$preFaultRaw[$symbolIndex].session_id) -ExpectedCampaignStartupSha256 ([string]$campaignStartupSnapshots[$symbol].sha256) -FinalRawGeneration $preFaultRaw[$symbolIndex]
        }
        if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $startupDeadlineTick) -le 0) { throw "Startup deadline expired immediately before retained-handle fault injection." }
        $injectionRequestedWallNs = [uint64](Get-RawQualificationWallNs)
        $failureOrigin = [int64][Diagnostics.Stopwatch]::GetTimestamp()
        if ($failureOrigin -le 0 -or [int64]$FailureDeadlineSeconds -gt ([int64]::MaxValue - $failureOrigin) / [int64][Diagnostics.Stopwatch]::Frequency) { throw "Failure deadline QPC arithmetic overflows." }
        $failureDeadlineTick = [int64]($failureOrigin + ([int64]$FailureDeadlineSeconds * [int64][Diagnostics.Stopwatch]::Frequency))
        $injectionRequestedSha = Add-FaultGateEvent -Journal $faultJournal -Event "FAULT_INJECTION_REQUESTED" -Payload ([ordered]@{
            proposal_record_sha256 = $proposalSha; target_pid = [uint32]$target.pid; requested_exit_code = $script:FaultGateTargetExitCode
            request_wall_ns = $injectionRequestedWallNs; request_monotonic_tick = [uint64]$failureOrigin
        })
        $gateStage = "FAULT_INJECTED_WAITING_FOR_CONTAINMENT"
        Assert-FaultGateObservationWithinDeadline -ObservedMonotonicTick ([int64][Diagnostics.Stopwatch]::GetTimestamp()) -DeadlineMonotonicTick $failureDeadlineTick -Label "Durable fault-injection request"
        foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
            if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $failureDeadlineTick) -le 0) { throw "Failure deadline expired during post-request campaign revalidation." }
            $postRequestJournal = Read-FaultGateJournal -Path ([string]$campaignJournals[$symbol].path) -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCleanTail -RequireCanonicalCompactJson
            $preRequestPrefix = @($preFaultCampaignPrefixes | Where-Object { [string]$_.symbol -ceq $symbol })
            $preRequestRaw = @($preFaultRaw | Where-Object { [string]$_.symbol -ceq $symbol })
            if ($preRequestPrefix.Count -ne 1 -or $preRequestRaw.Count -ne 1) { throw "$symbol exact final pre-request prefix/raw generation is absent or ambiguous." }
            $null = Test-FaultGatePreInjectionCampaignWindow -Journal $postRequestJournal -PreFaultPrefix $preRequestPrefix[0] -Symbol $symbol -ExpectedSessionId ([string]$preRequestRaw[0].session_id) -ExpectedCampaignStartupSha256 ([string]$campaignStartupSnapshots[$symbol].sha256) -FinalRawGeneration $preRequestRaw[0]
        }
        foreach ($identity in $identities) {
            if ([RawQualificationNative]::WaitForProcessExit($identity.handle, 0)) { throw "Qualification peer died after the durable injection request but before TerminateProcess: $($identity.role)" }
        }
        if ((Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $failureDeadlineTick) -le 0) { throw "Failure deadline expired immediately before TerminateProcess." }
        # The durable request boundary and these retained-handle/journal observations bound attribution.
        # They deliberately do not claim an atomic observation at the exact TerminateProcess syscall instant.
        if ([RawQualificationNative]::WaitForProcessExit($target.handle, 0)) { throw "BTC generation-0 target exited in the final pre-TerminateProcess observation." }
        [RawQualificationNative]::TerminateProcessHandle($target.handle, $script:FaultGateTargetExitCode)
        $remainingTargetMilliseconds = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $failureDeadlineTick
        $targetWaitMilliseconds = [int][Math]::Min([int64]30000, $remainingTargetMilliseconds)
        if ($targetWaitMilliseconds -le 0 -or -not [RawQualificationNative]::WaitForProcessExit($target.handle, $targetWaitMilliseconds)) { throw "BTC generation-0 target did not exit inside the absolute failure-containment deadline." }
        Assert-FaultGateObservationWithinDeadline -ObservedMonotonicTick ([int64][Diagnostics.Stopwatch]::GetTimestamp()) -DeadlineMonotonicTick $failureDeadlineTick -Label "Injected target terminal exit"
        $targetExit = [uint32][RawQualificationNative]::GetProcessExitCode($target.handle)
        if ($targetExit -ne $script:FaultGateTargetExitCode) { throw "BTC generation-0 target exit code differs from injected 0xEE31." }
        $injectedWallNs = [uint64](Get-RawQualificationWallNs)
        $injectedMonotonicTick = [uint64][Diagnostics.Stopwatch]::GetTimestamp()
        $injectedSha = Add-FaultGateEvent -Journal $faultJournal -Event "FAULT_INJECTED" -Payload ([ordered]@{
            proposal_record_sha256 = $proposalSha; injection_requested_record_sha256 = $injectionRequestedSha
            target_pid = [uint32]$target.pid; observed_exit_code = $targetExit
            injection_method = "TerminateProcess_RETAINED_HANDLE"; injected_wall_ns = $injectedWallNs
            injected_monotonic_tick = $injectedMonotonicTick
        })
        while ($true) {
            $remainingFailureMilliseconds = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $failureDeadlineTick
            if ($remainingFailureMilliseconds -le 0) { throw "Launcher did not reach terminal FAILED within containment deadline." }
            $failureWaitMilliseconds = [int][Math]::Min([int64]1000, $remainingFailureMilliseconds)
            $launcherObservedExited = [RawQualificationNative]::WaitForProcessExit($launcherLaunch.ProcessHandle, $failureWaitMilliseconds)
            $launcherExitObservationTick = [int64][Diagnostics.Stopwatch]::GetTimestamp()
            if ($launcherObservedExited) {
                Assert-FaultGateObservationWithinDeadline -ObservedMonotonicTick $launcherExitObservationTick -DeadlineMonotonicTick $failureDeadlineTick -Label "Launcher terminal exit"
                break
            }
            if ($launcherExitObservationTick -ge $failureDeadlineTick) { throw "Launcher did not reach terminal FAILED within containment deadline." }
        }
        $launcherExit = [uint32][RawQualificationNative]::GetProcessExitCode($launcherLaunch.ProcessHandle)
        if ($launcherExit -eq 0) { throw "Faulted launcher returned success." }
        foreach ($identity in @($identities | Where-Object { [string]$_.role -ne "launcher" })) {
            $remainingPeerMilliseconds = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $failureDeadlineTick
            $peerWaitMilliseconds = [int][Math]::Min([int64]10000, $remainingPeerMilliseconds)
            if ($peerWaitMilliseconds -le 0 -or -not [RawQualificationNative]::WaitForProcessExit($identity.handle, $peerWaitMilliseconds)) { throw "Retained process did not exit inside the absolute failure-containment deadline: $($identity.role)" }
            Assert-FaultGateObservationWithinDeadline -ObservedMonotonicTick ([int64][Diagnostics.Stopwatch]::GetTimestamp()) -DeadlineMonotonicTick $failureDeadlineTick -Label ("Retained process terminal exit: " + [string]$identity.role)
        }
        while ([RawQualificationNative]::GetActiveProcessCount($outerJob) -ne 0) {
            $remainingOuterMilliseconds = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $failureDeadlineTick
            if ($remainingOuterMilliseconds -le 0) { throw "Outer kill-on-close Job did not drain inside the absolute failure-containment deadline." }
            Start-Sleep -Milliseconds ([int][Math]::Min([int64]100, $remainingOuterMilliseconds))
        }
        $outerActive = [uint32][RawQualificationNative]::GetActiveProcessCount($outerJob)
        $innerQuery = [RawFaultGateNative]::QueryNamedJob([string]$processControl.job_object_name)
        if ($innerQuery.Exists -or $innerQuery.Error -ne 2) { throw "Inner qualification Job remains open or failed with an unexpected Win32 error." }
        $workloadQuery = [RawFaultGateNative]::QueryNamedJob([string]$processControl.workload_job_object_name)
        if ($workloadQuery.Exists -or $workloadQuery.Error -ne 2) { throw "Qualification workload Job remains open or failed with an unexpected Win32 error." }
        $containmentObservationTick = [int64][Diagnostics.Stopwatch]::GetTimestamp()
        Assert-FaultGateObservationWithinDeadline -ObservedMonotonicTick $containmentObservationTick -DeadlineMonotonicTick $failureDeadlineTick -Label "Final process and Job containment"
        $btcCoordinator = @($identities | Where-Object { [string]$_.role -ceq "BTCUSDT_coordinator" })[0]
        $ethCapture = @($identities | Where-Object { [string]$_.role -ceq "ETHUSDT_generation_0" })[0]
        $ethCoordinator = @($identities | Where-Object { [string]$_.role -ceq "ETHUSDT_coordinator" })[0]
        $btcCoordinatorExit = [uint32][RawQualificationNative]::GetProcessExitCode($btcCoordinator.handle)
        $watchdogExit = [uint32][RawQualificationNative]::GetProcessExitCode($watchdog.handle)
        $ethCaptureExit = [uint32][RawQualificationNative]::GetProcessExitCode($ethCapture.handle)
        $ethCoordinatorExit = [uint32][RawQualificationNative]::GetProcessExitCode($ethCoordinator.handle)
        if ($btcCoordinatorExit -in @([uint32]0, [uint32]259) -or $ethCaptureExit -in @([uint32]0, [uint32]259) -or $ethCoordinatorExit -in @([uint32]0, [uint32]259) -or $watchdogExit -in @([uint32]0, [uint32]259)) {
            throw "Coordinator/ETH/watchdog retained handles do not prove abnormal containment exit."
        }
        $expectedInjectedCoordinatorStderr = Get-FaultGateExpectedInjectedCoordinatorStderr -CampaignDirectory ([string]$campaignDirectories["BTCUSDT"])
        $coordinatorStderrSnapshots = @{}
        foreach ($stderrSymbol in @("BTCUSDT", "ETHUSDT")) {
            $stderrProcessRows = @($processRows | Where-Object { [string]$_.symbol -ceq $stderrSymbol })
            $stderrIdentityRows = @($identities | Where-Object { [string]$_.role -ceq ($stderrSymbol + "_coordinator") })
            $expectedStderrLeaf = $stderrSymbol.ToLowerInvariant() + ".stderr.log"
            if ($stderrProcessRows.Count -ne 1 -or $stderrIdentityRows.Count -ne 1 -or
                [string]$stderrProcessRows[0].stderr_file -cne $expectedStderrLeaf -or
                [uint64]$stderrProcessRows[0].pid -ne [uint64]$stderrIdentityRows[0].pid) {
                throw "$stderrSymbol coordinator stderr identity is not unique and process-bound."
            }
            $stderrPath = [IO.Path]::GetFullPath((Join-Path $runRoot $expectedStderrLeaf))
            if (-not [IO.Path]::GetDirectoryName($stderrPath).Equals($runRoot, [StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($stderrPath) -cne $expectedStderrLeaf) {
                throw "$stderrSymbol coordinator stderr is not one exact RunRoot child."
            }
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $stderrPath
            $null = Assert-FaultGateExactDataStreamInventory -Path $stderrPath -ExpectedType "file" -Label "$stderrSymbol coordinator stderr"
            $stderrBinding = Open-FaultGateRetainedPathBinding -Path $stderrPath -Role ($stderrSymbol.ToLowerInvariant() + "_coordinator_stderr") -MaximumBytes 4096
            $coordinatorStderrBindings += $stderrBinding
            [byte[]]$stderrBytes = Read-FaultGateRetainedPathBytes -Binding $stderrBinding -MaximumBytes 4096
            $coordinatorStderrSnapshots[$stderrSymbol] = [pscustomobject][ordered]@{
                binding = $stderrBinding
                raw_bytes = $stderrBytes
                bytes = [uint64]$stderrBytes.Length
                sha256 = Get-FaultGateSha256Bytes -Bytes $stderrBytes
            }
        }
        $btcStderrSnapshot = $coordinatorStderrSnapshots["BTCUSDT"]
        $ethStderrSnapshot = $coordinatorStderrSnapshots["ETHUSDT"]
        if ([uint64]$ethStderrSnapshot.bytes -ne 0 -or [string]$ethStderrSnapshot.sha256 -cne $script:FaultGateEmptySha256) {
            throw "ETHUSDT peer coordinator wrote stderr during Job containment."
        }
        $btcStderrClassification = if ([uint64]$btcStderrSnapshot.bytes -eq 0) {
            if ([string]$btcStderrSnapshot.sha256 -cne $script:FaultGateEmptySha256 -or
                $btcCoordinatorExit -ne 2) {
                throw "Managed BTCUSDT coordinator stderr contradicts its empty digest or exact durable-failure exit code."
            }
            "EMPTY"
        }
        else {
            Assert-FaultGateExactBytes -Actual ([byte[]]$btcStderrSnapshot.raw_bytes) -Expected ([byte[]]$expectedInjectedCoordinatorStderr.canonical_bytes) -Label "BTCUSDT injected coordinator stderr"
            if ([string]$btcStderrSnapshot.sha256 -cne [string]$expectedInjectedCoordinatorStderr.sha256 -or $btcCoordinatorExit -ne 2) {
                throw "BTCUSDT coordinator stderr/exit is not the exact injected generation-0 consequence."
            }
            [string]$expectedInjectedCoordinatorStderr.classification
        }
        $btcBindingRow = @($bindingRows | Where-Object { [string]$_.symbol -ceq "BTCUSDT" })[0]
        $coordinatorStderrEvidence = [ordered]@{
            schema = "RawQualificationCoordinatorStderrEvidenceV1"
            classification = $btcStderrClassification
            symbol = "BTCUSDT"
            generation_index = [uint64]0
            coordinator_pid = [uint32]$btcCoordinator.pid
            coordinator_exit_code = $btcCoordinatorExit
            campaign_id = [string]$btcBindingRow.campaign_id
            campaign_directory = [string]$btcBindingRow.campaign_directory
            campaign_failure_record_sha256 = $null
            file = "btcusdt.stderr.log"
            bytes = [uint64]$btcStderrSnapshot.bytes
            sha256 = [string]$btcStderrSnapshot.sha256
            peer_symbol = "ETHUSDT"
            peer_coordinator_pid = [uint32]$ethCoordinator.pid
            peer_file = "ethusdt.stderr.log"
            peer_bytes = [uint64]$ethStderrSnapshot.bytes
            peer_sha256 = [string]$ethStderrSnapshot.sha256
        }
        $null = Add-FaultGateEvent -Journal $faultJournal -Event "LAUNCHER_EXITED" -Payload ([ordered]@{
            launcher_exit_code = $launcherExit; target_exit_code = $targetExit; btc_coordinator_exit_code = $btcCoordinatorExit; eth_capture_exit_code = $ethCaptureExit
            eth_coordinator_exit_code = $ethCoordinatorExit; watchdog_exit_code = $watchdogExit
            outer_active_processes = $outerActive
            inner_job_exists = [bool]$innerQuery.Exists; inner_job_open_error = [int]$innerQuery.Error
            workload_job_exists = [bool]$workloadQuery.Exists; workload_job_open_error = [int]$workloadQuery.Error
        })
        $gateStage = "VALIDATING_FAILED_RUN_EVIDENCE"

        $terminalPath = Join-Path $runRoot "launcher-terminal.json"
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $terminalPath
        $terminalSnapshot = Read-FaultGateJsonSnapshot -Path $terminalPath -RequireCanonicalPrettyJson
        $terminal = $terminalSnapshot.value
        $terminalSha256 = [string]$terminalSnapshot.sha256
        Test-FaultGateLauncherTerminalV2Schema -Terminal $terminal -Startup $startup
        $allowedCausalFailures = @(
            "BTCUSDT campaign heartbeat reported failure.",
            "BTCUSDT campaign heartbeat regressed or has no active generation.",
            "BTCUSDT raw_campaign exited with code 2.",
            [string]$expectedInjectedCoordinatorStderr.terminal_failure
        )
        $managedCausalFailure = [string]$terminal.failure -cmatch '^BTCUSDT campaign failed: generation 0 exited without COMPLETE terminal evidence \[journal [0-9a-f]{64}\]$'
        if ([string]$terminal.schema -cne "RawQualificationLauncherTerminalV2" -or [string]$terminal.status -cne "FAILED" -or
            [string]$terminal.run_id -cne [string]$startup.run_id -or [string]$terminal.run_root -cne $runRoot -or
            (-not $managedCausalFailure -and [string]$terminal.failure -cnotin $allowedCausalFailures)) { throw "Terminal artifact is outside the exact causal failure class for the injected BTC generation." }
        $terminalRequiresExactCoordinatorStderr = [string]$terminal.failure -cin @(
            "BTCUSDT raw_campaign exited with code 2.",
            [string]$expectedInjectedCoordinatorStderr.terminal_failure
        )
        if (($terminalRequiresExactCoordinatorStderr -and [string]$coordinatorStderrEvidence.classification -cne [string]$expectedInjectedCoordinatorStderr.classification) -or
            ([string]$terminal.failure -ceq [string]$expectedInjectedCoordinatorStderr.terminal_failure -and
                [uint64]$coordinatorStderrEvidence.bytes -ne [uint64]$expectedInjectedCoordinatorStderr.bytes) -or
            ([string]$coordinatorStderrEvidence.classification -ceq [string]$expectedInjectedCoordinatorStderr.classification -and $btcCoordinatorExit -ne 2)) {
            throw "Launcher terminal failure is not conjunctively bound to exact causal coordinator stderr and exit code 2."
        }
        if ([string]$terminal.startup_sha256 -cne $startupSha256 -or [string]$terminal.process_control_sha256 -cne $processSha256 -or
            [string]$terminal.campaign_bindings_sha256 -cne $bindingsSha256 -or
            [string]$terminal.artifact_hashes_terminal.watchdog_ready_file_sha256 -cne $readySha256) {
            throw "Launcher terminal does not bind the exact startup/process/bindings/watchdog READY snapshots."
        }
        $launcherArtifactFields = [ordered]@{
            campaign = "campaign_executable_sha256"; capture = "capture_executable_sha256"; verifier = "campaign_verifier_executable_sha256"
            public_config = "public_config_sha256"; launcher = "launcher_script_sha256"; monitor = "monitor_script_sha256"; helper = "helper_script_sha256"
            telemetry_probe = "telemetry_probe_script_sha256"; watchdog = "watchdog_script_sha256"
            python_runtime_fingerprint = "python_runtime_fingerprint_script_sha256"; powershell = "powershell_executable_sha256"
            source_lock = "source_lock_sha256"; python = "python_executable_sha256"; pyproject = "python_project_sha256"
            requirements = "python_requirements_sha256"; pyvenv_config = "python_pyvenv_config_sha256"; python_base_executable = "python_base_executable_sha256"
        }
        foreach ($artifactName in $launcherArtifactFields.Keys) {
            $fieldName = [string]$launcherArtifactFields[$artifactName]
            $terminalFieldValue = $terminal.artifact_hashes_terminal.$fieldName
            $terminalMustBeNull = $artifactName -cin @("pyvenv_config", "python_base_executable")
            if ([string]$terminal.artifact_hashes_preflight.$fieldName -cne [string]$launchArtifactHashes[$artifactName] -or
                ($terminalMustBeNull -and $null -ne $terminalFieldValue) -or
                (-not $terminalMustBeNull -and [string]$terminalFieldValue -cne [string]$launchArtifactHashes[$artifactName])) {
                throw "Launcher terminal does not bind the retained critical artifact: $artifactName"
            }
        }
        $observedDigestRows = @(
            [pscustomobject][ordered]@{
                name = "python_verifier_source_tree"; retained_path_handles = $false; executed_byte_attestation = $false
                preflight_sha256 = [string]$startup.preflight.python_verifier_source.tree_sha256
                launcher_terminal_preflight_sha256 = [string]$terminal.artifact_hashes_preflight.python_verifier_source_tree_sha256
                terminal_observation = "OBSERVED_AND_UNCHANGED"
                launcher_terminal_final_sha256 = [string]$terminal.artifact_hashes_terminal.python_verifier_source_tree_sha256
            },
            [pscustomobject][ordered]@{
                name = "python_runtime_tree"; retained_path_handles = $false; executed_byte_attestation = $false
                preflight_sha256 = [string]$startup.preflight.python_runtime.tree_sha256
                launcher_terminal_preflight_sha256 = [string]$terminal.artifact_hashes_preflight.python_runtime_tree_sha256
                terminal_observation = "TERMINAL_NOT_OBSERVED_ON_FAILED_PATH"
                launcher_terminal_final_sha256 = $terminal.artifact_hashes_terminal.python_runtime_tree_sha256
            }
        )
        foreach ($observedRow in $observedDigestRows) {
            if (-not (Test-FaultGateDigest ([string]$observedRow.preflight_sha256)) -or
                [string]$observedRow.preflight_sha256 -cne [string]$observedRow.launcher_terminal_preflight_sha256 -or
                ([string]$observedRow.terminal_observation -ceq "OBSERVED_AND_UNCHANGED" -and [string]$observedRow.launcher_terminal_final_sha256 -cne [string]$observedRow.preflight_sha256) -or
                ([string]$observedRow.terminal_observation -ceq "TERMINAL_NOT_OBSERVED_ON_FAILED_PATH" -and $null -ne $observedRow.launcher_terminal_final_sha256)) {
                throw "Observed non-retained digest boundary drifted: $($observedRow.name)"
            }
        }
        $observedExternalBoundary = [ordered]@{
            scope = "OBSERVED_DIGEST_OR_EXTERNAL_TRUST_BOUNDARY"
            retained_path_handles = $false
            absolute_executed_byte_attestation = $false
            observed_digests = $observedDigestRows
            external_dependencies = @(
                "WINDOWS_KERNEL_PROCESS_JOB_OBJECT_AND_FILESYSTEM_SEMANTICS",
                "WINDOWS_W32TIME_POWERCFG_CIM_AND_PERFORMANCE_PROVIDERS",
                "OS_LOADER_TLS_CERTIFICATE_STORE_NETWORK_STACK_AND_DEVICE_DRIVERS",
                "BINANCE_PUBLIC_MARKET_DATA_REST_AND_WEBSOCKET_SERVICES"
            )
        }
        $containment = Test-FaultGateFailureContainment -Terminal $terminal -ExpectedSchema $FailureContainmentSchema -ExpectedJobName ([string]$processControl.job_object_name)
        $launcherMonotonicOrigin = Get-FaultGateJsonUnsignedInteger -Value $startup.monotonic_origin_qpc_timestamp -Label "launcher startup monotonic origin"
        $containmentDetectedAbsoluteTick = Add-FaultGateCheckedQpcTicks -Origin $launcherMonotonicOrigin -Relative ([uint64]$containment.detected_monotonic_tick) -Label "terminal containment detected"
        $containmentTerminationAbsoluteTick = Add-FaultGateCheckedQpcTicks -Origin $launcherMonotonicOrigin -Relative ([uint64]$containment.termination_monotonic_tick) -Label "terminal containment termination"
        if ($containmentDetectedAbsoluteTick -lt [uint64]$failureOrigin -or $containmentTerminationAbsoluteTick -lt $containmentDetectedAbsoluteTick -or
            $containmentTerminationAbsoluteTick -gt [uint64]$containmentObservationTick -or $containmentTerminationAbsoluteTick -gt [uint64]$failureDeadlineTick) {
            throw "Launcher-relative containment ticks do not fall inside the external retained-handle fault/deadline interval."
        }
        if ([string]$containment.result -cne "DRAINED_BY_ATTEMPT" -or -not [bool]$containment.initial_query_succeeded -or
            $null -eq $containment.initial_active_processes -or [uint32]$containment.initial_active_processes -eq 0 -or -not [bool]$containment.terminate_succeeded -or
            $ethCaptureExit -ne $script:FaultGateContainmentExitCode -or $ethCoordinatorExit -ne $script:FaultGateContainmentExitCode -or
            $watchdogExit -ne $script:FaultGateContainmentExitCode) {
            throw "The real gate requires a successful TerminateJobObject attempt and retained ETH/watchdog 0xEE02 exits."
        }
        $launcherJournalPath = Join-Path $runRoot "launcher-events.jsonl"
        $guardianJournalPath = Join-Path $runRoot "guardian-pulse.jsonl"
        $telemetryJournalPath = Join-Path $runRoot "host-telemetry.jsonl"
        foreach ($criticalJournalPath in @($launcherJournalPath, $guardianJournalPath, $telemetryJournalPath)) { $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $criticalJournalPath }
        $launcherJournal = Read-FaultGateJournal -Path $launcherJournalPath -ExpectedSchema "RawQualificationLauncherEventV1" -RequireCleanTail -RequireCanonicalCompactJson
        $guardianJournal = Read-FaultGateJournal -Path $guardianJournalPath -ExpectedSchema "RawQualificationGuardianPulseV1" -RequireCleanTail -RequireCanonicalCompactJson
        $telemetryJournal = Read-FaultGateJournal -Path $telemetryJournalPath -ExpectedSchema "RawQualificationHostTelemetryRecordV1" -RequireCleanTail -RequireCanonicalCompactJson
        $containmentEvents = @(Get-FaultGateJournalEvents -Journal $launcherJournal -Event $FailureContainmentEvent)
        $terminalEvents = @(Get-FaultGateJournalEvents -Journal $launcherJournal -Event "LAUNCHER_TERMINAL")
        $failureEvents = @(Get-FaultGateJournalEvents -Journal $launcherJournal -Event "LAUNCHER_FAILED")
        $failureEventTick = if ($failureEvents.Count -eq 1) { Get-FaultGateJsonUnsignedInteger -Value $failureEvents[0].body.monotonic_tick -Label "launcher failure event tick" } else { [uint64]0 }
        $containmentEventTick = if ($containmentEvents.Count -eq 1) { Get-FaultGateJsonUnsignedInteger -Value $containmentEvents[0].body.monotonic_tick -Label "launcher containment event tick" } else { [uint64]0 }
        $terminalEventTick = if ($terminalEvents.Count -eq 1) { Get-FaultGateJsonUnsignedInteger -Value $terminalEvents[0].body.monotonic_tick -Label "launcher terminal event tick" } else { [uint64]0 }
        $failureEventAbsoluteTick = if ($failureEventTick -ne 0) { Add-FaultGateCheckedQpcTicks -Origin $launcherMonotonicOrigin -Relative $failureEventTick -Label "launcher failure event" } else { [uint64]0 }
        $containmentEventAbsoluteTick = if ($containmentEventTick -ne 0) { Add-FaultGateCheckedQpcTicks -Origin $launcherMonotonicOrigin -Relative $containmentEventTick -Label "launcher containment event" } else { [uint64]0 }
        $terminalEventAbsoluteTick = if ($terminalEventTick -ne 0) { Add-FaultGateCheckedQpcTicks -Origin $launcherMonotonicOrigin -Relative $terminalEventTick -Label "launcher terminal event" } else { [uint64]0 }
        if ($failureEvents.Count -eq 1) { Assert-FaultGateExactProperties -Value $failureEvents[0].body.payload -Names @("event", "error") -Label "launcher failure payload" }
        if ($containmentEvents.Count -eq 1) { Assert-FaultGateExactProperties -Value $containmentEvents[0].body.payload -Names @("event", "failure_containment_sha256") -Label "launcher containment payload" }
        if ($failureEvents.Count -ne 1 -or $containmentEvents.Count -ne 1 -or $terminalEvents.Count -ne 1) {
            throw "Launcher journal lacks the exact failure/containment/terminal event cardinality."
        }
        $expectedContainmentRecordIndex = Get-FaultGateUInt64Successor -Value ([uint64]$failureEvents[0].body.record_index) -Label "launcher failure-to-containment record index"
        $expectedTerminalRecordIndex = Get-FaultGateUInt64Successor -Value ([uint64]$containmentEvents[0].body.record_index) -Label "launcher containment-to-terminal record index"
        if ($expectedContainmentRecordIndex -ne [uint64]$containmentEvents[0].body.record_index -or
            $expectedTerminalRecordIndex -ne [uint64]$terminalEvents[0].body.record_index -or
            [uint64]$terminalEvents[0].body.record_index -ne [uint64]$launcherJournal.records - 1 -or
            [string]$containmentEvents[0].body.payload.failure_containment_sha256 -cne [string]$containment.sha256 -or
            [string]$terminalEvents[0].body.payload.failure_containment_sha256 -cne [string]$containment.sha256 -or
            [string]$failureEvents[0].body.payload.error -cne [string]$terminal.failure -or
            [string]$terminalEvents[0].body.payload.failure -cne [string]$terminal.failure -or
            [string]$failureEvents[0].body.channel -cne "FAILURE" -or [string]$containmentEvents[0].body.channel -cne "FAILURE" -or
            [string]$terminalEvents[0].body.channel -cne "LAUNCHER" -or
            $failureEventAbsoluteTick -lt [uint64]$failureOrigin -or $containmentEventTick -lt $failureEventTick -or
            $terminalEventTick -lt $containmentEventTick -or $terminalEventAbsoluteTick -gt [uint64]$containmentObservationTick -or
            $containmentEventAbsoluteTick -lt $failureEventAbsoluteTick) {
            throw "Launcher journal does not bind containment immediately before terminal FAILED."
        }
        $null = Test-FaultGateLauncherTerminalPostLink -LauncherJournalPath $launcherJournalPath -LauncherJournal $launcherJournal -Terminal $terminal -TerminalBytes ([uint64]$terminalSnapshot.bytes) -TerminalSha256 $terminalSha256 -ContainmentSha256 ([string]$containment.sha256)
        if ([uint64]$terminal.guardian_pulse.records -ne [uint64]$guardianJournal.records -or
            [string]$terminal.guardian_pulse.terminal_record_sha256 -cne [string]$guardianJournal.terminal_record_sha256 -or
            [string]$terminal.guardian_pulse.file_sha256 -cne [string]$guardianJournal.file_sha256 -or
            [uint64]$terminal.host_telemetry.records -ne [uint64]$telemetryJournal.records -or
            [string]$terminal.host_telemetry.terminal_record_sha256 -cne [string]$telemetryJournal.terminal_record_sha256 -or
            [string]$terminal.host_telemetry.file_sha256 -cne [string]$telemetryJournal.file_sha256) { throw "Terminal does not bind launcher/guardian/telemetry journal hash chains." }
        Assert-FaultGateNoPromotion -RunRoot $runRoot -LauncherJournal $launcherJournal

        $finalCampaignJournals = @{}
        $campaignCausality = @{}
        $rawReports = [Collections.Generic.List[object]]::new()
        foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
            $null = Assert-RawQualificationNoReparsePointInExistingPath -Path ([string]$campaignJournals[$symbol].path)
            $journal = Read-FaultGateJournal -Path $campaignJournals[$symbol].path -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCleanTail -RequireCanonicalCompactJson
            $finalCampaignJournals[$symbol] = $journal
            if (@(Get-FaultGateJournalEvents -Journal $journal -Event "CAMPAIGN_COMMITTED").Count -ne 0 -or
                @(Get-FaultGateJournalEvents -Journal $journal -Event "PRECOMMIT_PREFIX").Count -ne 0 -or
                @(Get-FaultGateJournalEvents -Journal $journal -Event "HANDOVER_PROOF_STARTED").Count -ne 0 -or
                @(Get-FaultGateJournalEvents -Journal $journal -Event "HANDOVER_PROVEN_AND_PROMOTED").Count -ne 0 -or
                @(Get-FaultGateJournalEvents -Journal $journal -Event "GENERATION_LAUNCHED_SERVER_SHUTDOWN").Count -ne 0 -or
                @(Get-FaultGateJournalEvents -Journal $journal -Event "GENERATION_LAUNCHED" | Where-Object { [uint64]$_.body.generation_index -ne 0 }).Count -ne 0 -or
                @(Get-FaultGateJournalEvents -Journal $journal -Event "PROCESS_STARTED" | Where-Object { [uint64]$_.body.payload.generation_index -ne 0 }).Count -ne 0) { throw "$symbol campaign published a forbidden commit/handover/successor after fault." }
            $preFaultPrefix = @($preFaultCampaignPrefixes | Where-Object { [string]$_.symbol -ceq $symbol })
            if ($preFaultPrefix.Count -ne 1) { throw "$symbol pre-fault campaign prefix is absent or ambiguous." }
            $rawReport = Test-FaultGateRawGeneration -SessionDirectory ([string]$captureEvents[$symbol].body.payload.session_dir) -Symbol $symbol -ExpectedSpecRevision ([string]$startup.preflight.spec_revision) -ExpectedCaptureExecutableSha256 ([string]$launchArtifactHashes.capture) -ExpectedPublicConfigSha256 ([string]$launchArtifactHashes.public_config) -CampaignJournal $journal -MinimumSealedSegments ([uint64]$MinimumSealedSegmentsPerStream) -ExpectedCampaignDirectory ([string]$campaignDirectories[$symbol]) -ExpectedSegmentDuration ([uint64]$startup.parameters.segment_s) -ExpectedMarketFreshnessStartupGrace ([uint64]$startup.market_freshness_policy.startup_grace_s) -ExpectedMarketFreshnessDeadline ([uint64]$startup.market_freshness_policy.deadline_s) -AllowRecoveryTails
            $rawReports.Add($rawReport)
            $depthConnectionEpoch = Get-FaultGateVerifiedDepthConnectionEpoch -Generation $rawReport -Symbol $symbol
            $campaignCausality[$symbol] = Test-FaultGateInjectedCampaignCausality -Journal $journal -Symbol $symbol -LauncherFailure ([string]$terminal.failure) -PreFaultPrefix $preFaultPrefix[0] -InjectionRequestedWallNs $injectionRequestedWallNs -ExpectedDepthEpoch $depthConnectionEpoch -ExpectedCampaignStartupSha256 ([string]$campaignStartupSnapshots[$symbol].sha256) -FinalRawGeneration $rawReport
        }
        $btcCampaignFailureEvents = @(Get-FaultGateJournalEvents -Journal $finalCampaignJournals["BTCUSDT"] -Event "CAMPAIGN_FAILED")
        if ($btcCampaignFailureEvents.Count -gt 1 -or
            ([string]$coordinatorStderrEvidence.classification -ceq [string]$expectedInjectedCoordinatorStderr.classification -and $btcCampaignFailureEvents.Count -ne 1)) {
            throw "BTCUSDT coordinator stderr receipt is not linked to one exact CAMPAIGN_FAILED record."
        }
        if ($managedCausalFailure) {
            if ($btcCampaignFailureEvents.Count -ne 1) {
                throw "Managed BTCUSDT terminal failure lacks one exact CAMPAIGN_FAILED record."
            }
            $expectedManagedCausalFailure = "BTCUSDT campaign failed: " +
                [string]$btcCampaignFailureEvents[0].body.payload.error + " [journal " +
                [string]$btcCampaignFailureEvents[0].record_sha256 + "]"
            if ([string]$terminal.failure -cne $expectedManagedCausalFailure) {
                throw "Managed BTCUSDT terminal failure is not bound to its exact CAMPAIGN_FAILED record."
            }
        }
        $coordinatorStderrEvidence.campaign_failure_record_sha256 = if ($btcCampaignFailureEvents.Count -eq 1) {
            [string]$btcCampaignFailureEvents[0].record_sha256
        }
        else { $null }
        $rawPreservation = Test-FaultGatePreservedDurablePrefixes -Before @($preFaultRaw) -After @($rawReports)

        $terminalProcessSnapshot = @(Get-FaultGateProcessSnapshot)
        $absence = [Collections.Generic.List[object]]::new()
        foreach ($identity in $identities) {
            $absence.Add((Test-FaultGateRecordedProcessAbsent -Identity $identity -ProcessSnapshot $terminalProcessSnapshot))
        }
        $globalEngines = @(Get-FaultGateEngineProcesses -ProcessSnapshot $terminalProcessSnapshot)
        if ($globalEngines.Count -ne 0) {
            throw ("Engine process remains after containment; " + (Get-FaultGateProcessBlockerDiagnostic -Processes $globalEngines))
        }
        $runBoundProcesses = @(Get-FaultGateRunBoundProcesses -ProcessSnapshot $terminalProcessSnapshot -RunRoot $runRoot)
        if ($runBoundProcesses.Count -ne 0) {
            throw ("Run-bound command-line process remains after containment; " + (Get-FaultGateProcessBlockerDiagnostic -Processes $runBoundProcesses))
        }
        $verifiers = @($terminalProcessSnapshot | Where-Object { [string]$_.Name -ieq "campaign_verify.exe" })
        if ($verifiers.Count -ne 0) {
            throw ("Verifier process exists in a failure gate; " + (Get-FaultGateProcessBlockerDiagnostic -Processes $verifiers))
        }

        $artifactBindingsAtTerminal = @($artifactPaths.Keys | ForEach-Object { Test-FaultGateRetainedPathBinding -Binding $retainedArtifactBindings[$_] })
        $sourceBindingsAtTerminal = @($artifactBindingsAtTerminal | Where-Object { [string]$_.role -cin @("harness", "helper") })
        $terminalArtifactHashes = [ordered]@{}
        foreach ($artifactName in $artifactPaths.Keys) { $terminalArtifactHashes[$artifactName] = [string]$retainedArtifactBindings[$artifactName].sha256 }
        foreach ($artifactName in $launchArtifactHashes.Keys) {
            if ([string]$terminalArtifactHashes[$artifactName] -cne [string]$launchArtifactHashes[$artifactName]) { throw "Artifact provenance drifted during fault gate: $artifactName" }
        }

        $null = Add-FaultGateEvent -Journal $faultJournal -Event "EVIDENCE_PROPOSED" -Payload ([ordered]@{
            run_id = [string]$startup.run_id; terminal_sha256 = Get-FaultGateSha256File -Path $terminalPath
            containment_sha256 = [string]$containment.sha256; launcher_journal_terminal_sha256 = [string]$launcherJournal.terminal_record_sha256
            process_observation = "PRE_PROPOSAL_ONLY_POSTSCAN_REQUIRED_BEFORE_PUBLICATION"
            outer_active_processes = $outerActive
            global_engine_processes = [uint64]$globalEngines.Count; run_bound_processes = [uint64]$runBoundProcesses.Count
            inner_job_exists = [bool]$innerQuery.Exists; inner_job_open_error = [int]$innerQuery.Error
            workload_job_exists = [bool]$workloadQuery.Exists; workload_job_open_error = [int]$workloadQuery.Error
        })
        $gateStage = "PUBLISHING_PASS_EVIDENCE"
        Close-RawQualificationJournal -Journal $faultJournal
        $faultJournalSummary = Read-FaultGateJournal -Path $faultJournalPath -ExpectedSchema $script:FaultGateJournalSchema -RequireCleanTail -RequireCanonicalCompactJson
        $faultInjectionJournalLinks = Test-FaultGateFaultInjectionJournalSequence -Journal $faultJournalSummary -ProposalSha256 $proposalSha -InjectionRequestedSha256 $injectionRequestedSha -InjectedSha256 $injectedSha -TargetPid ([uint32]$target.pid) -RequestedExitCode $script:FaultGateTargetExitCode -InjectionRequestedWallNs $injectionRequestedWallNs -InjectionRequestedMonotonicTick ([uint64]$failureOrigin) -ObservedExitCode $targetExit
        $supportMaximumBytesByLeaf = [ordered]@{
            "fault-events.jsonl" = [uint64]$faultJournalSummary.file_bytes
            "launcher.stdout.log" = [uint64]16777216
            "launcher.stderr.log" = [uint64]16777216
        }
        for ([uint64]$supportMonitorAttempt = 1; $supportMonitorAttempt -le [uint64]$monitorEvidence.attempt; $supportMonitorAttempt++) {
            $supportMaximumBytesByLeaf[("monitor-{0:D3}.stdout.json" -f $supportMonitorAttempt)] = [uint64]16777216
            $supportMaximumBytesByLeaf[("monitor-{0:D3}.stderr.log" -f $supportMonitorAttempt)] = [uint64]16777216
        }
        $supportMaximumBytesByLeaf[[string]$monitorEvidence.stdout_file] = [uint64]$monitorEvidence.stdout_bytes
        $supportMaximumBytesByLeaf[[string]$monitorEvidence.stderr_file] = [uint64]$monitorEvidence.stderr_bytes
        $supportArtifacts = Open-FaultGateSupportArtifactTree -EvidenceRoot $gateRoot -QualificationRoot $qualificationBase `
            -RunRoot $runRoot -MaximumBytesByLeaf $supportMaximumBytesByLeaf
        $supportArtifactTree = $supportArtifacts.tree
        $supportArtifactBindings = @($supportArtifacts.bindings)
        $supportRowsByPath = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        foreach ($supportRow in @($supportArtifactTree.inventory)) { $supportRowsByPath.Add([string]$supportRow.relative_path, $supportRow) }
        if ([string]$supportRowsByPath["fault-events.jsonl"].sha256 -cne [string]$faultJournalSummary.file_sha256 -or
            [uint64]$supportRowsByPath["fault-events.jsonl"].bytes -ne [uint64]$faultJournalSummary.file_bytes -or
            [string]$supportRowsByPath[[string]$monitorEvidence.stdout_file].sha256 -cne [string]$monitorEvidence.stdout_sha256 -or
            [uint64]$supportRowsByPath[[string]$monitorEvidence.stdout_file].bytes -ne [uint64]$monitorEvidence.stdout_bytes -or
            [string]$supportRowsByPath[[string]$monitorEvidence.stderr_file].sha256 -cne [string]$monitorEvidence.stderr_sha256 -or
            [uint64]$supportRowsByPath[[string]$monitorEvidence.stderr_file].bytes -ne [uint64]$monitorEvidence.stderr_bytes) {
            throw "Retained support artifact tree differs from fault-journal or monitor evidence."
        }
        foreach ($stderrBinding in @($coordinatorStderrBindings)) {
            $null = Test-FaultGateRetainedPathBinding -Binding $stderrBinding
            $null = Assert-FaultGateExactDataStreamInventory -Path ([string]$stderrBinding.path) -ExpectedType "file" -Label "Retained coordinator stderr"
        }
        $tree = Assert-FaultGateTreeStable -Root $runRoot
        $evidencePath = Join-Path $gateRoot "fault-evidence.json"
        $body = [ordered]@{
            schema = "RawQualificationFaultEvidenceV3"
            status = "PASS"
            gate_id = $gateId
            run_id = [string]$startup.run_id
            run_root = $runRoot
            evidence_root = $gateRoot
            repository_root = $repo
            fault = [ordered]@{
                method = "TerminateProcess_RETAINED_HANDLE"; symbol = "BTCUSDT"; generation_index = [uint64]0
                target = [ordered]@{ pid = [uint32]$target.pid; creation_filetime_utc = [int64]$target.creation_filetime_utc; parent_pid = [uint32]$target.parent_pid; executable_sha256 = [string]$target.executable_sha256; command_line_sha256 = [string]$target.command_line_sha256 }
                requested_exit_code = $script:FaultGateTargetExitCode; observed_exit_code = $targetExit
                proposed_record_sha256 = [string]$faultInjectionJournalLinks.proposal_record_sha256
                injection_requested_record_sha256 = [string]$faultInjectionJournalLinks.injection_requested_record_sha256
                injected_record_sha256 = [string]$faultInjectionJournalLinks.injected_record_sha256
                injection_requested_wall_ns = $injectionRequestedWallNs
                failure_deadline_seconds = [uint64]$FailureDeadlineSeconds; injection_requested_qpc_timestamp = [uint64]$failureOrigin
                containment_observed_monotonic_tick = [uint64]$containmentObservationTick
            }
            launcher = [ordered]@{
                identity = [ordered]@{ pid = [uint32]$launcherIdentity.pid; creation_filetime_utc = [int64]$launcherIdentity.creation_filetime_utc; executable_sha256 = [string]$launcherIdentity.executable_sha256; command_line_sha256 = [string]$launcherIdentity.command_line_sha256 }
                monotonic_origin_qpc_timestamp = [uint64]$startup.monotonic_origin_qpc_timestamp
                exit_code = $launcherExit; terminal_file = "launcher-terminal.json"; terminal_bytes = [uint64]$terminalSnapshot.bytes; terminal_sha256 = $terminalSha256
                terminal_status = [string]$terminal.status; terminal_failure = [string]$terminal.failure; containment = $containment
                startup_file = "launcher-startup.json"; startup_bytes = [uint64]$startupSnapshot.bytes; startup_sha256 = $startupSha256
                process_control_file = "processes.json"; process_control_bytes = [uint64]$processSnapshot.bytes; process_control_sha256 = $processSha256
                campaign_bindings_file = "campaign-bindings.json"; campaign_bindings_bytes = [uint64]$bindingsSnapshot.bytes; campaign_bindings_sha256 = $bindingsSha256
                watchdog_ready_sha256 = $readySha256
                launcher_journal = [ordered]@{ records = $launcherJournal.records; terminal_record_sha256 = $launcherJournal.terminal_record_sha256; file_bytes = $launcherJournal.file_bytes; file_sha256 = $launcherJournal.file_sha256 }
                guardian_journal = [ordered]@{ records = $guardianJournal.records; terminal_record_sha256 = $guardianJournal.terminal_record_sha256; file_bytes = $guardianJournal.file_bytes; file_sha256 = $guardianJournal.file_sha256 }
                telemetry_journal = [ordered]@{ records = $telemetryJournal.records; terminal_record_sha256 = $telemetryJournal.terminal_record_sha256; file_bytes = $telemetryJournal.file_bytes; file_sha256 = $telemetryJournal.file_sha256 }
                stdout_file = "launcher.stdout.log"; stdout_bytes = [uint64]$supportRowsByPath["launcher.stdout.log"].bytes; stdout_sha256 = [string]$supportRowsByPath["launcher.stdout.log"].sha256
                stderr_file = "launcher.stderr.log"; stderr_bytes = [uint64]$supportRowsByPath["launcher.stderr.log"].bytes; stderr_sha256 = [string]$supportRowsByPath["launcher.stderr.log"].sha256
            }
            live_gate = [ordered]@{
                watchdog_ready = $readyEvidence
                monitor = [ordered]@{
                    attempt = [uint64]$monitorEvidence.attempt; pid = [uint32]$monitorEvidence.pid
                    exact_command_line = [string]$monitorEvidence.exact_command_line; command_line_sha256 = [string]$monitorEvidence.command_line_sha256
                    creation_filetime_utc = [int64]$monitorEvidence.creation_filetime_utc
                    executable_path = [string]$monitorEvidence.executable_path; executable_sha256 = [string]$monitorEvidence.executable_sha256
                    exit_code = [uint32]$monitorEvidence.exit_code; stdout_file = [string]$monitorEvidence.stdout_file
                    stdout_bytes = [uint64]$monitorEvidence.stdout_bytes; stdout_sha256 = [string]$monitorEvidence.stdout_sha256
                    stderr_file = [string]$monitorEvidence.stderr_file; stderr_bytes = [uint64]$monitorEvidence.stderr_bytes
                    stderr_sha256 = [string]$monitorEvidence.stderr_sha256; report_sha256 = [string]$monitorEvidence.report_sha256
                    report_schema = [string]$monitorEvidence.report.schema; report_status = [string]$monitorEvidence.report.status
                    report_stage = [string]$monitorEvidence.report.stage; report_run_root = [string]$monitorEvidence.report.run_root
                    report_host_telemetry_records = [uint64]$monitorEvidence.report.host_telemetry_records
                }
            }
            retained_process_identities = @($identities | ForEach-Object {
                [pscustomobject][ordered]@{
                    pid = [uint32]$_.pid; role = [string]$_.role; parent_pid = [uint32]$_.parent_pid
                    creation_filetime_utc = [int64]$_.creation_filetime_utc; executable_path = [string]$_.executable_path
                    executable_sha256 = [string]$_.executable_sha256; command_line_sha256 = [string]$_.command_line_sha256
                }
            })
            containment = [ordered]@{
                inner_job_name = [string]$processControl.job_object_name; inner_job_exists = [bool]$innerQuery.Exists; inner_job_open_error = [int]$innerQuery.Error
                workload_job_name = [string]$processControl.workload_job_object_name; workload_job_exists = [bool]$workloadQuery.Exists; workload_job_open_error = [int]$workloadQuery.Error
                outer_job_name = $outerJobName; outer_job_kill_on_close = $true; outer_active_processes = $outerActive
                btc_coordinator_exit_code = $btcCoordinatorExit; eth_capture_exit_code = $ethCaptureExit; eth_coordinator_exit_code = $ethCoordinatorExit; watchdog_exit_code = $watchdogExit
                retained_identity_absence = @($absence); global_engine_processes = [uint64]$globalEngines.Count
                run_bound_processes = [uint64]$runBoundProcesses.Count; verifier_processes = [uint64]$verifiers.Count
            }
            promotion = [ordered]@{ launcher_complete = $false; campaign_or_generation_manifest_count = [uint64]0; independent_verification = $false }
            campaign_journals = @(@("BTCUSDT", "ETHUSDT") | ForEach-Object {
                $campaignSymbol = [string]$_
                $campaignSummary = $finalCampaignJournals[$campaignSymbol]
                $campaignBinding = @($bindingRows | Where-Object { [string]$_.symbol -ceq $campaignSymbol })[0]
                $campaignStartupSnapshot = $campaignStartupSnapshots[$campaignSymbol]
                $campaignStartedEntries = @(Get-FaultGateJournalEvents -Journal $campaignSummary -Event "CAMPAIGN_STARTED")
                if ($campaignStartedEntries.Count -ne 1) { throw "$campaignSymbol final campaign journal lacks one exact CAMPAIGN_STARTED event." }
                [pscustomobject][ordered]@{
                    symbol = $campaignSymbol; campaign_id = [string]$campaignBinding.campaign_id; campaign_directory = [string]$campaignBinding.campaign_directory
                    campaign_startup_bytes = [uint64]$campaignStartupSnapshot.bytes; campaign_startup_sha256 = [string]$campaignStartupSnapshot.sha256
                    campaign_started_event = $campaignStartedEntries[0]
                    journal_bytes_base64 = [Convert]::ToBase64String([byte[]]$campaignSummary.raw_bytes)
                    records = [uint64]$campaignSummary.records; clean_tail = [bool]$campaignSummary.clean_tail
                    terminal_record_sha256 = [string]$campaignSummary.terminal_record_sha256; file_bytes = [uint64]$campaignSummary.file_bytes; file_sha256 = [string]$campaignSummary.file_sha256
                    causality = $campaignCausality[$_]
                }
            })
            campaign_prefixes = [ordered]@{
                pre_fault_campaign_prefixes_sha256 = $preFaultCampaignPrefixesSha256
                pre_fault_campaign_prefixes = @($preFaultCampaignPrefixes)
            }
            coordinator_stderr = $coordinatorStderrEvidence
            raw_durable_prefixes = @($rawReports)
            raw_preservation = [ordered]@{
                observation_scope = "MANIFEST_SNAPSHOT_BOUNDED_SEALED_SEGMENTS_AND_DURABLE_PREFIXES_OBSERVED_AFTER_FROZEN_PRE_FAULT_CAMPAIGN_PREFIX"
                completeness_claim = "NO_ATOMIC_COMPLETE_STATE_CLAIM_AT_TERMINATEPROCESS_INSTANT_WITHOUT_A_COLLECTOR_BARRIER"
                pre_fault_raw_prefixes_sha256 = $preFaultRawSha256
                pre_fault_raw_prefixes = @($preFaultRaw)
                durable_prefixes = $rawPreservation
            }
            fault_journal = [ordered]@{
                journal_bytes_base64 = [Convert]::ToBase64String([byte[]]$faultJournalSummary.raw_bytes)
                records = $faultJournalSummary.records; terminal_record_sha256 = $faultJournalSummary.terminal_record_sha256; file_bytes = $faultJournalSummary.file_bytes; file_sha256 = $faultJournalSummary.file_sha256
                proposed_record_sha256 = $proposalSha; injection_requested_record_sha256 = $injectionRequestedSha; injected_record_sha256 = $injectedSha
            }
            artifact_tree = $tree
            support_artifact_tree = $supportArtifactTree
            harness = [ordered]@{
                script_file = [IO.Path]::GetFileName($PSCommandPath)
                process_identity = [ordered]@{ pid = [uint32]$PID; creation_filetime_utc = $harnessProcessCreationFileTimeUtc }
                source_binding_scope = "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE"
                source_binding_trust_boundary = "Path-byte observation and retention do not assert absolute equivalence with bytes already interpreted or mapped by a runtime."
                source_bindings_at_start = $sourceBindingsAtStart; source_bindings_at_terminal = $sourceBindingsAtTerminal
                direct_artifacts_retained_and_rehashed = [ordered]@{
                    scope = "DIRECT_ARTIFACTS_RETAINED_AND_REHASHED"
                    observation_scope = "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE"
                    trust_boundary = "Path-byte observation and retention do not assert absolute equivalence with bytes already interpreted or mapped by a runtime."
                    unchanged = $true
                    hashes_at_start = $launchArtifactHashes; hashes_at_terminal = $terminalArtifactHashes
                    bindings_at_start = $artifactBindingsAtStart; bindings_at_terminal = $artifactBindingsAtTerminal
                }
                observed_digest_or_external_trust_boundary = $observedExternalBoundary
            }
        }
        $postProposalProcessSnapshot = @(Get-FaultGateProcessSnapshot)
        $postProposalAbsence = [Collections.Generic.List[object]]::new()
        foreach ($identity in $identities) {
            $postProposalAbsence.Add((Test-FaultGateRecordedProcessAbsent -Identity $identity -ProcessSnapshot $postProposalProcessSnapshot))
        }
        $postProposalOuterActive = [uint32][RawQualificationNative]::GetActiveProcessCount($outerJob)
        $postProposalInnerQuery = [RawFaultGateNative]::QueryNamedJob([string]$processControl.job_object_name)
        $postProposalWorkloadQuery = [RawFaultGateNative]::QueryNamedJob([string]$processControl.workload_job_object_name)
        $postProposalGlobalEngines = @(Get-FaultGateEngineProcesses -ProcessSnapshot $postProposalProcessSnapshot)
        $postProposalRunBoundProcesses = @(Get-FaultGateRunBoundProcesses -ProcessSnapshot $postProposalProcessSnapshot -RunRoot $runRoot)
        $postProposalVerifiers = @($postProposalProcessSnapshot | Where-Object { [string]$_.Name -ieq "campaign_verify.exe" })
        if ($postProposalAbsence.Count -ne 6 -or $postProposalOuterActive -ne 0 -or
            $postProposalInnerQuery.Exists -or $postProposalInnerQuery.Error -ne 2 -or
            $postProposalWorkloadQuery.Exists -or $postProposalWorkloadQuery.Error -ne 2 -or
            $postProposalGlobalEngines.Count -ne 0 -or $postProposalRunBoundProcesses.Count -ne 0 -or $postProposalVerifiers.Count -ne 0) {
            $postProposalBlockers = @($postProposalGlobalEngines) + @($postProposalRunBoundProcesses) + @($postProposalVerifiers)
            throw ("Post-EVIDENCE_PROPOSED containment rescan found a surviving, inconsistent, or newly appeared qualification process/Job; " +
                (Get-FaultGateProcessBlockerDiagnostic -Processes $postProposalBlockers))
        }
        $body.containment.inner_job_exists = [bool]$postProposalInnerQuery.Exists
        $body.containment.inner_job_open_error = [int]$postProposalInnerQuery.Error
        $body.containment.workload_job_exists = [bool]$postProposalWorkloadQuery.Exists
        $body.containment.workload_job_open_error = [int]$postProposalWorkloadQuery.Error
        $body.containment.outer_active_processes = $postProposalOuterActive
        $body.containment.retained_identity_absence = @($postProposalAbsence)
        $body.containment.global_engine_processes = [uint64]$postProposalGlobalEngines.Count
        $body.containment.run_bound_processes = [uint64]$postProposalRunBoundProcesses.Count
        $body.containment.verifier_processes = [uint64]$postProposalVerifiers.Count
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $terminalPath
        $terminalRescan = Read-FaultGateJsonSnapshot -Path $terminalPath -RequireCanonicalPrettyJson
        if ([string]$terminalRescan.sha256 -cne $terminalSha256 -or [uint64]$terminalRescan.bytes -ne [uint64]$terminalSnapshot.bytes) {
            throw "Launcher terminal bytes changed after their semantic validation and before evidence publication."
        }
        foreach ($controlPath in @($startupPath, $processPath, $bindingsPath, $readyPath)) { $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $controlPath }
        $startupRescan = Read-FaultGateJsonSnapshot -Path $startupPath -RequireCanonicalPrettyJson
        $processRescan = Read-FaultGateJsonSnapshot -Path $processPath -RequireCanonicalPrettyJson
        $bindingsRescan = Read-FaultGateJsonSnapshot -Path $bindingsPath -RequireCanonicalPrettyJson
        $readyRescan = Read-FaultGateJsonSnapshot -Path $readyPath -RequireCanonicalPrettyJson
        if ([string]$startupRescan.sha256 -cne $startupSha256 -or [uint64]$startupRescan.bytes -ne [uint64]$startupSnapshot.bytes -or
            [string]$processRescan.sha256 -cne $processSha256 -or [uint64]$processRescan.bytes -ne [uint64]$processSnapshot.bytes -or
            [string]$bindingsRescan.sha256 -cne $bindingsSha256 -or [uint64]$bindingsRescan.bytes -ne [uint64]$bindingsSnapshot.bytes -or
            [string]$readyRescan.sha256 -cne $readySha256 -or [uint64]$readyRescan.bytes -ne [uint64]$readySnapshot.bytes) {
            throw "Launcher control or watchdog READY bytes changed before evidence publication."
        }
        $null = Test-FaultGateSupportArtifactBindings -Bindings $supportArtifactBindings -ExpectedTree $supportArtifactTree `
            -EvidenceRoot $gateRoot -QualificationRoot $qualificationBase -RunRoot $runRoot -MaximumBytesByLeaf $supportMaximumBytesByLeaf
        foreach ($stderrBinding in @($coordinatorStderrBindings)) {
            $null = Test-FaultGateRetainedPathBinding -Binding $stderrBinding
            $null = Assert-FaultGateExactDataStreamInventory -Path ([string]$stderrBinding.path) -ExpectedType "file" -Label "Retained coordinator stderr"
        }
        $postProposalTree = Assert-FaultGateTreeStable -Root $runRoot
        if ((Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $postProposalTree)) -cne
            (Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $tree))) {
            throw "Qualification artifact tree changed after EVIDENCE_PROPOSED and before publication."
        }
        $body.artifact_tree = $postProposalTree
        $gateStage = "PREPUBLICATION_RESOURCE_CLEANUP"
        $prePublicationResourceFailures = [Collections.Generic.List[string]]::new()
        foreach ($supportBinding in @($supportArtifactBindings)) {
            try { Close-FaultGateRetainedPathBinding -Binding $supportBinding }
            catch { $prePublicationResourceFailures.Add("support binding: " + $_.Exception.Message) }
        }
        foreach ($stderrBinding in @($coordinatorStderrBindings)) {
            try { Close-FaultGateRetainedPathBinding -Binding $stderrBinding }
            catch { $prePublicationResourceFailures.Add("coordinator stderr binding: " + $_.Exception.Message) }
        }
        if ($prePublicationResourceFailures.Count -eq 0) { $coordinatorStderrBindings = @() }
        foreach ($identity in $identities) {
            try { Close-FaultGateProcessIdentity -Identity $identity }
            catch { $prePublicationResourceFailures.Add("process identity: " + $_.Exception.Message) }
        }
        if ($null -ne $launcherLaunch -and $null -eq $launcherIdentity -and
            $launcherLaunch.ProcessHandle -ne [IntPtr]::Zero) {
            try {
                if (-not [RawQualificationNative]::CloseHandle($launcherLaunch.ProcessHandle)) {
                    throw "CloseHandle returned false for the unowned launcher process handle."
                }
                $launcherLaunch = $null
            }
            catch { $prePublicationResourceFailures.Add("launcher handle: " + $_.Exception.Message) }
        }
        foreach ($retainedBinding in @($retainedArtifactBindings.Values)) {
            try { Close-FaultGateRetainedPathBinding -Binding $retainedBinding }
            catch { $prePublicationResourceFailures.Add("direct artifact binding: " + $_.Exception.Message) }
        }
        if ($prePublicationResourceFailures.Count -eq 0) {
            $retainedArtifactBindings.Clear()
        }
        if ($outerJob -ne [IntPtr]::Zero) {
            try {
                if ([RawQualificationNative]::GetActiveProcessCount($outerJob) -ne 0) {
                    throw "Outer Job became active during pre-publication cleanup."
                }
                if (-not [RawQualificationNative]::CloseHandle($outerJob)) {
                    throw "CloseHandle returned false for the drained outer Job."
                }
                $outerJob = [IntPtr]::Zero
            }
            catch { $prePublicationResourceFailures.Add("outer Job handle: " + $_.Exception.Message) }
        }
        if ($prePublicationResourceFailures.Count -ne 0) {
            throw ("Pre-publication retained-resource cleanup failed: " +
                ($prePublicationResourceFailures.ToArray() -join " | "))
        }

        $gateStage = "PUBLISHING_PASS_EVIDENCE"
        $publication = Publish-FaultGateValidatedPassEvidence `
            -Path $evidencePath -Body $body -PublicationObserved ([ref]$evidenceWritten)
        $evidenceSha = [string]$publication.record_sha256
        $gateStage = "PASS_EVIDENCE_PUBLISHED"
        Write-Output ([pscustomobject][ordered]@{ schema = "RawQualificationFaultGateResultV1"; status = "PASS"; evidence_file = $evidencePath; evidence_record_sha256 = $evidenceSha } | ConvertTo-Json -Depth 10)
    }
    catch {
        $gateFailure = $_
        throw
    }
    finally {
        $resourceCleanupFailures = [Collections.Generic.List[string]]::new()
        foreach ($supportBinding in @($supportArtifactBindings)) {
            try { Close-FaultGateRetainedPathBinding -Binding $supportBinding }
            catch { $resourceCleanupFailures.Add("support binding: " + $_.Exception.Message) }
        }
        foreach ($stderrBinding in @($coordinatorStderrBindings)) {
            try { Close-FaultGateRetainedPathBinding -Binding $stderrBinding }
            catch { $resourceCleanupFailures.Add("coordinator stderr binding: " + $_.Exception.Message) }
        }
        if ($resourceCleanupFailures.Count -eq 0) { $coordinatorStderrBindings = @() }
        foreach ($identity in $identities) {
            try { Close-FaultGateProcessIdentity -Identity $identity }
            catch { $resourceCleanupFailures.Add("process identity: " + $_.Exception.Message) }
        }
        if ($null -ne $launcherLaunch -and $null -eq $launcherIdentity -and $launcherLaunch.ProcessHandle -ne [IntPtr]::Zero) {
            try {
                if (-not [RawQualificationNative]::CloseHandle($launcherLaunch.ProcessHandle)) {
                    throw "CloseHandle returned false for the unowned launcher process handle."
                }
                $launcherLaunch = $null
            }
            catch { $resourceCleanupFailures.Add("launcher handle: " + $_.Exception.Message) }
        }
        foreach ($retainedBinding in @($retainedArtifactBindings.Values)) {
            try { Close-FaultGateRetainedPathBinding -Binding $retainedBinding }
            catch { $resourceCleanupFailures.Add("direct artifact binding: " + $_.Exception.Message) }
        }
        if ($resourceCleanupFailures.Count -eq 0) {
            $retainedArtifactBindings.Clear()
        }
        $resourceCleanupError = if ($resourceCleanupFailures.Count -eq 0) {
            $null
        }
        else {
            $resourceCleanupFailures.ToArray() -join " | "
        }
        $outerCleanupFailures = [Collections.Generic.List[string]]::new()
        $outerActiveAfterCleanup = $null
        if ($outerJob -ne [IntPtr]::Zero) {
            try {
                $currentOuterActive = [uint32][RawQualificationNative]::GetActiveProcessCount($outerJob)
                if ($currentOuterActive -ne 0) {
                    if (-not [RawQualificationNative]::TerminateJobObject($outerJob, $script:FaultGateFallbackExitCode)) { throw "Fallback TerminateJobObject returned false." }
                    $origin = [Diagnostics.Stopwatch]::GetTimestamp()
                    while ($true) {
                        $currentOuterActive = [uint32][RawQualificationNative]::GetActiveProcessCount($outerJob)
                        $outerDrainObservation = [Diagnostics.Stopwatch]::GetTimestamp()
                        $withinOuterDrainDeadline = Test-RawQualificationDeadlineTicks `
                            -ElapsedTicks ($outerDrainObservation - $origin) -TimeoutSeconds 30
                        if ($currentOuterActive -eq 0) {
                            if (-not $withinOuterDrainDeadline) {
                                throw "Outer fallback Job reached zero only after its 30-second deadline."
                            }
                            break
                        }
                        if (-not $withinOuterDrainDeadline) {
                            throw "Outer fallback Job did not drain to zero within 30 seconds."
                        }
                        Start-Sleep -Milliseconds 100
                    }
                }
                $outerActiveAfterCleanup = [uint32]$currentOuterActive
            }
            catch { $outerCleanupFailures.Add($_.Exception.Message) }
            finally {
                try {
                    if (-not [RawQualificationNative]::CloseHandle($outerJob)) {
                        throw "CloseHandle returned false for the outer Job."
                    }
                    $outerJob = [IntPtr]::Zero
                }
                catch { $outerCleanupFailures.Add($_.Exception.Message) }
            }
        }
        $outerCleanupFailure = if ($outerCleanupFailures.Count -eq 0) {
            $null
        }
        else {
            $outerCleanupFailures.ToArray() -join " | "
        }
        if (-not $evidenceWritten -and $null -ne $gateFailure) {
            $failureType = $gateFailure.Exception.GetType().FullName
            $failureId = [string]$gateFailure.FullyQualifiedErrorId
            if ([string]::IsNullOrWhiteSpace($failureId)) { $failureId = "UNSPECIFIED_FAILURE_ID" }
            $failureMessage = [string]$gateFailure.Exception.Message
            if ([string]::IsNullOrWhiteSpace($failureMessage)) { $failureMessage = "Unspecified fault-gate failure." }
            if ($failureMessage.Length -gt 4096) { $failureMessage = $failureMessage.Substring(0, 4096) }
            $failureEventAppended = $false
            $failureEventAppendError = $null
            if ($null -ne $faultJournal -and -not $faultJournal.Closed) {
                try {
                    $null = Add-FaultGateEvent -Journal $faultJournal -Event "HARNESS_FAILED" -Payload ([ordered]@{
                        stage = $gateStage
                        exception_type = $failureType
                        fully_qualified_error_id = $failureId
                        message = $failureMessage
                        run_root = $runRoot
                        pass_evidence_published = $false
                        resource_cleanup_succeeded = ($null -eq $resourceCleanupError)
                        outer_job_created = $outerJobCreated
                        outer_job_cleanup_succeeded = ($null -eq $outerCleanupFailure)
                        outer_active_processes_after_cleanup = $outerActiveAfterCleanup
                    })
                    $failureEventAppended = $true
                }
                catch { $failureEventAppendError = [string]$_.Exception.Message }
            }
            else {
                $failureEventAppendError = "Fault journal was already sealed before the harness failure."
            }
            if ($null -ne $faultJournal -and -not $faultJournal.Closed) {
                try { Close-RawQualificationJournal -Journal $faultJournal }
                catch {
                    if ($null -eq $failureEventAppendError) { $failureEventAppendError = [string]$_.Exception.Message }
                    $failureEventAppended = $false
                }
            }
            try {
                $failureJournal = Read-FaultGateJournal -Path $faultJournalPath `
                    -ExpectedSchema $script:FaultGateJournalSchema -RequireCleanTail -RequireCanonicalCompactJson
                $failureReceiptPath = Join-Path $gateRoot "fault-gate-failure.json"
                if ([IO.File]::Exists((Join-Path $gateRoot "fault-evidence.json"))) {
                    throw "Canonical PASS evidence exists; refusing to publish a contradictory FAILED_NO_PASS_EVIDENCE receipt."
                }
                $failureReceiptBody = [ordered]@{
                    schema = "RawQualificationFaultGateFailureReceiptV1"
                    status = "FAILED_NO_PASS_EVIDENCE"
                    gate_id = $gateId
                    evidence_root = $gateRoot
                    repository_root = $repo
                    run_root = $runRoot
                    stage = $gateStage
                    failure = [ordered]@{
                        exception_type = $failureType
                        fully_qualified_error_id = $failureId
                        message = $failureMessage
                    }
                    cleanup = [ordered]@{
                        resource_cleanup_succeeded = ($null -eq $resourceCleanupError)
                        resource_cleanup_error = $resourceCleanupError
                        outer_job_created = $outerJobCreated
                        outer_job_cleanup_succeeded = ($null -eq $outerCleanupFailure)
                        outer_job_cleanup_error = $outerCleanupFailure
                        outer_active_processes_after_cleanup = $outerActiveAfterCleanup
                    }
                    fault_journal = [ordered]@{
                        file = [IO.Path]::GetFileName($faultJournalPath)
                        records = [uint64]$failureJournal.records
                        clean_tail = [bool]$failureJournal.clean_tail
                        terminal_record_sha256 = [string]$failureJournal.terminal_record_sha256
                        file_bytes = [uint64]$failureJournal.file_bytes
                        file_sha256 = [string]$failureJournal.file_sha256
                        failure_event_appended = $failureEventAppended
                        failure_event_append_error = $failureEventAppendError
                    }
                    pass_evidence_published = $false
                }
                $failureReceiptSha = Write-FaultGateEvidence -Path $failureReceiptPath -Body $failureReceiptBody
                $failureReceipt = Test-FaultGateFailureReceiptEnvelope -Path $failureReceiptPath
                if ([string]$failureReceipt.record_sha256 -cne [string]$failureReceiptSha) {
                    throw "Fault failure receipt did not rescan to its publication digest."
                }
                Write-Warning "Fault gate failed closed; durable non-PASS receipt: $failureReceiptPath"
            }
            catch {
                Write-Warning "Fault gate failed closed and its non-PASS receipt could not be published: $($_.Exception.Message)"
            }
        }
        elseif ($null -ne $faultJournal -and -not $faultJournal.Closed) {
            try { Close-RawQualificationJournal -Journal $faultJournal } catch {}
        }
        if (-not $evidenceWritten -and $null -ne $runRoot) { Write-Warning "No RawQualificationFaultEvidenceV3 was published. RunRoot preserved: $runRoot" }
        if ($null -eq $gateFailure -and
            ($null -ne $resourceCleanupError -or $null -ne $outerCleanupFailure)) {
            throw ((@($resourceCleanupError, $outerCleanupFailure) | Where-Object {
                        -not [string]::IsNullOrWhiteSpace([string]$_)
                    }) -join " | ")
        }
    }
    }
    finally {
        foreach ($binding in @($retainedArtifactBindings.Values)) {
            try { Close-FaultGateRetainedPathBinding -Binding $binding }
            catch { Write-Warning "Final retained-binding cleanup failed closed: $($_.Exception.Message)" }
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-RawQualificationFaultGate -StartupDeadlineSeconds $StartupDeadlineSeconds -FailureDeadlineSeconds $FailureDeadlineSeconds -MinimumSealedSegmentsPerStream $MinimumSealedSegmentsPerStream -FailureContainmentEvent $FailureContainmentEvent -FailureContainmentSchema $FailureContainmentSchema -OutputBase $OutputBase -BootstrapValidateOnly:$BootstrapValidateOnly
}
