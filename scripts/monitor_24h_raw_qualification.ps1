[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $RunRoot,
    [ValidateRange(10, 30)] [int] $HeartbeatMaxAgeSeconds = 30,
    [ValidateRange(30, 120)] [int] $TelemetryMaxAgeSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")
$ExpectedMarketFreshnessStartupGraceSeconds = 30
$ExpectedMarketFreshnessDeadlineSeconds = 30
$ExpectedMarketFreshnessStartupGraceNs = [uint64]30000000000
$ExpectedMarketFreshnessDeadlineNs = [uint64]30000000000
$ExpectedHostProbeTimeoutSeconds = [uint64]20
$ExpectedHostProbeMaximumArtifactBytes = [uint64](8MB)
$ExpectedGuardianWatchdogDeadlineSeconds = [uint64]90
$ExpectedGuardianWatchdogStartupDeadlineSeconds = [uint64]90
$ExpectedHostTelemetryGapDeadlineSeconds = [uint64]120
$ExpectedMaximumDualLaunchSkewMilliseconds = [uint64]5000
$ExpectedPythonRuntimeFingerprintTimeoutSeconds = [uint64]300
$ExpectedGenerationTerminalDeadlineSeconds = [uint64]120
$ExpectedCampaignCommitDeadlineSeconds = [uint64]1800
$MaximumCurrentVerifierArtifactBytes = [uint64](32MB)

Initialize-RawQualificationNative

if (-not ("RawQualificationLengthLimitedStream" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;

public sealed class RawQualificationLengthLimitedStream : Stream
{
    private readonly Stream inner;
    private readonly bool leaveOpen;
    private long remaining;

    public RawQualificationLengthLimitedStream(Stream inner, long length, bool leaveOpen)
    {
        if (inner == null) throw new ArgumentNullException("inner");
        if (!inner.CanRead) throw new ArgumentException("The inner stream is not readable.", "inner");
        if (length < 0) throw new ArgumentOutOfRangeException("length");
        this.inner = inner;
        this.remaining = length;
        this.leaveOpen = leaveOpen;
    }

    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return false; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position
    {
        get { throw new NotSupportedException(); }
        set { throw new NotSupportedException(); }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (remaining == 0) return 0;
        int bounded = (int)Math.Min((long)count, remaining);
        int read = inner.Read(buffer, offset, bounded);
        if (read <= 0) throw new EndOfStreamException("The snapshotted journal prefix became unreadable.");
        remaining -= read;
        return read;
    }

    public override int ReadByte()
    {
        if (remaining == 0) return -1;
        int value = inner.ReadByte();
        if (value < 0) throw new EndOfStreamException("The snapshotted journal prefix became unreadable.");
        remaining--;
        return value;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
    public override void SetLength(long value) { throw new NotSupportedException(); }
    public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !leaveOpen) inner.Dispose();
        base.Dispose(disposing);
    }
}
'@ -Language CSharp -ErrorAction Stop
}

function Test-MonitorExactJsonProperties {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)] [string[]] $Expected
    )
    if ($null -eq $Value -or $null -eq $Value.PSObject) { return $false }
    $actualNames = @($Value.PSObject.Properties.Name | Sort-Object)
    $expectedNames = @($Expected | Sort-Object)
    return ($actualNames -join "`n") -ceq ($expectedNames -join "`n")
}

function Test-MonitorExactJsonPropertyOrder {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)] [string[]] $Expected
    )
    if ($null -eq $Value -or $null -eq $Value.PSObject) { return $false }
    $actualNames = [string[]]@($Value.PSObject.Properties.Name)
    if ($actualNames.Count -ne $Expected.Count) { return $false }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ($actualNames[$index] -cne $Expected[$index]) { return $false }
    }
    return $true
}

function Test-MonitorJsonFiniteNumber {
    param(
        [Parameter(Mandatory = $true)] [AllowNull()] $Value,
        [double] $Minimum = [double]::NegativeInfinity,
        [double] $Maximum = [double]::PositiveInfinity
    )
    if ($null -eq $Value) { return $false }
    $type = $Value.GetType()
    if ($type -notin @([single], [double], [decimal])) { return $false }
    $numeric = [double]$Value
    return -not [double]::IsNaN($numeric) -and
        -not [double]::IsInfinity($numeric) -and
        $numeric -ge $Minimum -and $numeric -le $Maximum
}

function Test-MonitorJsonRealNumber {
    param(
        [Parameter(Mandatory = $true)] [AllowNull()] $Value,
        [double] $Minimum = [double]::NegativeInfinity,
        [double] $Maximum = [double]::PositiveInfinity
    )
    if (Test-RawQualificationJsonInteger -Value $Value) {
        $numeric = [double][decimal]$Value
        return $numeric -ge $Minimum -and $numeric -le $Maximum
    }
    return Test-MonitorJsonFiniteNumber -Value $Value -Minimum $Minimum -Maximum $Maximum
}

function Test-MonitorJsonNullOrInteger {
    param(
        [AllowNull()] $Value,
        [decimal] $Minimum = 0,
        [decimal] $Maximum = [decimal][uint64]::MaxValue
    )
    return $null -eq $Value -or
        (Test-RawQualificationJsonInteger -Value $Value -Minimum $Minimum -Maximum $Maximum)
}

function Test-MonitorJsonNullOrString {
    param([AllowNull()] $Value)
    return $null -eq $Value -or (Test-RawQualificationJsonString -Value $Value)
}

function Assert-MonitorJsonStringArray {
    param([Parameter(Mandatory = $true)] [AllowEmptyCollection()] $Value)
    if ($Value -isnot [System.Array]) { throw "Contract list is not a JSON array." }
    foreach ($entry in @($Value)) {
        if (-not (Test-RawQualificationJsonString $entry)) {
            throw "Contract list contains a non-string JSON element."
        }
    }
    return $true
}

function Test-MonitorByteArraysEqual {
    param(
        [Parameter(Mandatory = $true)] [byte[]] $Left,
        [Parameter(Mandatory = $true)] [byte[]] $Right
    )
    if ($Left.Length -ne $Right.Length) { return $false }
    return [Linq.Enumerable]::SequenceEqual($Left, $Right)
}

function Test-MonitorTransientTreeSnapshotException {
    param([Parameter(Mandatory = $true)] [Exception] $Exception)
    $cause = $Exception
    while ($null -ne $cause.InnerException) { $cause = $cause.InnerException }
    if ($cause -is [IO.FileNotFoundException] -or
        $cause -is [IO.DirectoryNotFoundException]) { return $true }
    if ($cause -is [ComponentModel.Win32Exception] -and
        $cause.NativeErrorCode -in @(2, 3, 32, 33)) { return $true }
    return $false
}

function Get-MonitorEvidenceTreeStructureSnapshot {
    param(
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [ValidateRange(1, 16)] [int] $SnapshotAttempt = 1,
        [scriptblock] $BeforeDirectoryEnumeration
    )
    $resolvedRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $resolvedRoot
    $ioRoot = ConvertTo-RawQualificationExtendedLengthPath -Path $resolvedRoot
    $rootPrefix = $ioRoot.TrimEnd('\') + '\'
    $pending = [Collections.Generic.Queue[object]]::new()
    $retainedDirectories = [Collections.Generic.List[object]]::new()
    $rows = [Collections.Generic.List[string]]::new()
    try {
        $rootIdentity = [RawQualificationNative]::OpenPathIdentityNoFollow($ioRoot, $true, $true)
        $retainedDirectories.Add($rootIdentity)
        $rootAttributes = [IO.FileAttributes]$rootIdentity.Attributes
        if (($rootAttributes -band [IO.FileAttributes]::Directory) -eq 0 -or
            ($rootAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Qualification evidence root is not a normal directory: $resolvedRoot"
        }
        $rows.Add('D|' + ([uint64]$rootIdentity.Attributes).ToString(
                [Globalization.CultureInfo]::InvariantCulture) + '|' +
            ([uint64]$rootIdentity.VolumeSerialNumber).ToString(
                [Globalization.CultureInfo]::InvariantCulture) + '|' +
            ([uint64]$rootIdentity.FileIndex).ToString(
                [Globalization.CultureInfo]::InvariantCulture) + '|.')
        $pending.Enqueue([pscustomobject][ordered]@{ path = $ioRoot; identity = $rootIdentity })
        while ($pending.Count -ne 0) {
            $node = $pending.Dequeue()
            $directoryPath = [string]$node.path
            if ($null -ne $BeforeDirectoryEnumeration) {
                $publishedDirectoryPath = if ($directoryPath.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
                    '\\' + $directoryPath.Substring(8)
                }
                elseif ($directoryPath.StartsWith('\\?\', [StringComparison]::Ordinal)) {
                    $directoryPath.Substring(4)
                }
                else { $directoryPath }
                & $BeforeDirectoryEnumeration $publishedDirectoryPath $SnapshotAttempt
            }
            $directory = [IO.DirectoryInfo]::new($directoryPath)
            foreach ($child in $directory.EnumerateFileSystemInfos()) {
                $childPath = $child.FullName
                if (-not $childPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Qualification evidence child escaped RunRoot: $childPath"
                }
                $enumeratedAttributes = $child.Attributes
                if (($enumeratedAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Qualification evidence rejects child reparse points/junctions/symlinks: $childPath"
                }
                $enumeratedDirectory = ($enumeratedAttributes -band [IO.FileAttributes]::Directory) -ne 0
                $childIdentity = $null
                try {
                    $childIdentity = [RawQualificationNative]::OpenPathIdentityNoFollow(
                        $childPath,
                        $false,
                        $enumeratedDirectory)
                    $identityAttributes = [IO.FileAttributes]$childIdentity.Attributes
                    if (($identityAttributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                        throw "Qualification evidence rejects child reparse points/junctions/symlinks: $childPath"
                    }
                    $identityDirectory = ($identityAttributes -band [IO.FileAttributes]::Directory) -ne 0
                    if ($identityDirectory -ne $enumeratedDirectory) {
                        throw [IO.DirectoryNotFoundException]::new(
                            "Qualification evidence entry type changed during its structural snapshot: $childPath")
                    }
                    $relativePath = $childPath.Substring($rootPrefix.Length).Replace('\', '/')
                    $kind = if ($identityDirectory) { 'D' } else { 'F' }
                    $rows.Add($kind + '|' + ([uint64]$childIdentity.Attributes).ToString(
                            [Globalization.CultureInfo]::InvariantCulture) + '|' +
                        ([uint64]$childIdentity.VolumeSerialNumber).ToString(
                            [Globalization.CultureInfo]::InvariantCulture) + '|' +
                        ([uint64]$childIdentity.FileIndex).ToString(
                            [Globalization.CultureInfo]::InvariantCulture) + '|' + $relativePath)
                    if ($identityDirectory) {
                        $retainedDirectories.Add($childIdentity)
                        $pending.Enqueue([pscustomobject][ordered]@{ path = $childPath; identity = $childIdentity })
                        $childIdentity = $null
                    }
                }
                finally {
                    if ($null -ne $childIdentity -and $childIdentity.Handle -ne [IntPtr]::Zero) {
                        $null = [RawQualificationNative]::CloseHandle($childIdentity.Handle)
                    }
                }
            }
        }
    }
    finally {
        for ($handleIndex = $retainedDirectories.Count - 1; $handleIndex -ge 0; $handleIndex--) {
            $retained = $retainedDirectories[$handleIndex]
            if ($null -ne $retained -and $retained.Handle -ne [IntPtr]::Zero) {
                $null = [RawQualificationNative]::CloseHandle($retained.Handle)
            }
        }
    }
    $snapshot = $rows.ToArray()
    [Array]::Sort($snapshot, [StringComparer]::Ordinal)
    # Emit one pipeline object per structural row.  In Windows PowerShell 5.1,
    # returning the array as a single unary-comma object and then assigning it
    # to [string[]] coerces the entire array into one space-joined string.  That
    # destroys row boundaries and makes the convergence comparison non-injective.
    return $snapshot
}

function Assert-MonitorEvidenceTreeNoReparsePoints {
    param(
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [ValidateRange(2, 16)] [int] $MaximumSnapshotAttempts = 5,
        [scriptblock] $BeforeDirectoryEnumeration
    )
    $resolvedRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
    [string[]]$previous = $null
    $lastTransient = $null
    for ($attempt = 1; $attempt -le $MaximumSnapshotAttempts; $attempt++) {
        try {
            [string[]]$current = @(Get-MonitorEvidenceTreeStructureSnapshot `
                -RunRoot $resolvedRoot -SnapshotAttempt $attempt `
                -BeforeDirectoryEnumeration $BeforeDirectoryEnumeration)
        }
        catch {
            if (-not (Test-MonitorTransientTreeSnapshotException -Exception $_.Exception)) { throw }
            $lastTransient = $_.Exception
            $previous = $null
            if ($attempt -lt $MaximumSnapshotAttempts) {
                Start-Sleep -Milliseconds 10
                continue
            }
            throw "Qualification evidence tree did not yield a complete structural snapshot after $MaximumSnapshotAttempts attempts: $($lastTransient.Message)"
        }
        if ($null -ne $previous) {
            $same = $previous.Length -eq $current.Length
            if ($same) {
                for ($index = 0; $index -lt $current.Length; $index++) {
                    if ($previous[$index] -cne $current[$index]) { $same = $false; break }
                }
            }
            if ($same) { return $resolvedRoot }
        }
        $previous = $current
        if ($attempt -lt $MaximumSnapshotAttempts) { Start-Sleep -Milliseconds 10 }
    }
    throw "Qualification evidence tree changed across $MaximumSnapshotAttempts bounded structural snapshots."
}

function Resolve-MonitorContainedEvidencePath {
    param(
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] [string] $Path,
        [switch] $RequireLeaf,
        [switch] $RequireDirectory
    )
    $resolvedRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    if (-not $resolvedPath.StartsWith($resolvedRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Qualification evidence path escaped RunRoot: $resolvedPath"
    }
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $resolvedPath
    $ioPath = ConvertTo-RawQualificationExtendedLengthPath -Path $resolvedPath
    if ($RequireLeaf -and -not [IO.File]::Exists($ioPath)) {
        throw "Required qualification evidence file is absent: $resolvedPath"
    }
    if ($RequireDirectory -and -not [IO.Directory]::Exists($ioPath)) {
        throw "Required qualification evidence directory is absent: $resolvedPath"
    }
    return $resolvedPath
}

function ConvertTo-MonitorTwoSpacePrettyJsonBytes {
    param([Parameter(Mandatory = $true)] $Value)
    # serde_json::to_vec_pretty and Python json.dumps(indent=2) use the same
    # structural whitespace for the finite integer/string/bool/null evidence
    # accepted by this monitor.  ConvertTo-Json supplies the normalized compact
    # tokens; this formatter changes structural whitespace only.
    $compact = $Value | ConvertTo-Json -Depth 100 -Compress
    $builder = [Text.StringBuilder]::new()
    $indent = 0
    $inString = $false
    $escaped = $false
    for ($index = 0; $index -lt $compact.Length; $index++) {
        $character = $compact[$index]
        if ($inString) {
            $null = $builder.Append($character)
            if ($escaped) { $escaped = $false }
            elseif ($character -eq '\') { $escaped = $true }
            elseif ($character -eq '"') { $inString = $false }
            continue
        }
        switch ($character) {
            '"' {
                $inString = $true
                $null = $builder.Append($character)
            }
            '{' {
                $null = $builder.Append($character)
                if ($index + 1 -lt $compact.Length -and $compact[$index + 1] -ne '}') {
                    $indent++
                    $null = $builder.Append("`n").Append(' ' * (2 * $indent))
                }
            }
            '[' {
                $null = $builder.Append($character)
                if ($index + 1 -lt $compact.Length -and $compact[$index + 1] -ne ']') {
                    $indent++
                    $null = $builder.Append("`n").Append(' ' * (2 * $indent))
                }
            }
            '}' {
                if ($index -gt 0 -and $compact[$index - 1] -ne '{') {
                    $indent--
                    $null = $builder.Append("`n").Append(' ' * (2 * $indent))
                }
                $null = $builder.Append($character)
            }
            ']' {
                if ($index -gt 0 -and $compact[$index - 1] -ne '[') {
                    $indent--
                    $null = $builder.Append("`n").Append(' ' * (2 * $indent))
                }
                $null = $builder.Append($character)
            }
            ',' { $null = $builder.Append(",`n").Append(' ' * (2 * $indent)) }
            ':' { $null = $builder.Append(': ') }
            default { $null = $builder.Append($character) }
        }
    }
    return [Text.UTF8Encoding]::new($false).GetBytes($builder.ToString() + "`n")
}

function Read-MonitorCanonicalJsonSnapshot {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet("PowerShellPretty", "PowerShellCompactCrlf", "TwoSpacePretty")] [string] $WriterKind,
        [uint64] $MaximumBytes = [uint64](64MB),
        [string[]] $ExpectedTopLevelOrder
    )
    $stream = [IO.FileStream]::new(
        (ConvertTo-RawQualificationExtendedLengthPath -Path $Path),
        [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $length = [uint64]$stream.Length
        if ($length -eq 0 -or $length -gt $MaximumBytes -or $length -gt [uint64][int]::MaxValue) {
            throw "Canonical JSON singleton is empty or exceeds its bounded snapshot: $Path"
        }
        $bytes = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) { throw "Canonical JSON singleton ended before its frozen length: $Path" }
            $offset += $read
        }
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            throw "Canonical JSON singleton contains a forbidden UTF-8 BOM: $Path"
        }
        if ($WriterKind -eq "PowerShellCompactCrlf") {
            if ($bytes.Length -lt 3 -or $bytes[$bytes.Length - 2] -ne 13 -or
                $bytes[$bytes.Length - 1] -ne 10 -or
                @($bytes[0..($bytes.Length - 3)] | Where-Object { $_ -eq 10 -or $_ -eq 13 }).Count -ne 0) {
                throw "Canonical redirected PowerShell JSON must be one compact CRLF-terminated line: $Path"
            }
        }
        elseif ($bytes[$bytes.Length - 1] -ne 10 -or
            ($WriterKind -eq "TwoSpacePretty" -and $bytes -contains 13)) {
            throw "Canonical JSON singleton has invalid terminal/newline bytes for $WriterKind`: $Path"
        }
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $value = $text | ConvertFrom-Json -ErrorAction Stop
        if ($null -ne $ExpectedTopLevelOrder -and
            -not (Test-MonitorExactJsonPropertyOrder -Value $value -Expected $ExpectedTopLevelOrder)) {
            throw "Canonical JSON singleton has unexpected top-level property order: $Path"
        }
        $canonical = if ($WriterKind -eq "PowerShellPretty") {
            ConvertTo-RawQualificationJsonBytes -Value $value -Pretty
        }
        elseif ($WriterKind -eq "PowerShellCompactCrlf") {
            [Text.UTF8Encoding]::new($false).GetBytes(
                (($value | ConvertTo-Json -Depth 100 -Compress) + "`r`n"))
        }
        else { ConvertTo-MonitorTwoSpacePrettyJsonBytes -Value $value }
        if (-not (Test-MonitorByteArraysEqual -Left $bytes -Right $canonical)) {
            throw "Canonical JSON singleton differs from the exact $WriterKind writer representation: $Path"
        }
        return [pscustomobject][ordered]@{
            path = [IO.Path]::GetFullPath($Path)
            bytes = $bytes
            length = $length
            sha256 = Get-RawQualificationSha256Bytes -Bytes $bytes
            value = $value
            writer_kind = $WriterKind
        }
    }
    finally { $stream.Dispose() }
}

function Read-MonitorFrozenCanonicalJsonLines {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [uint64] $MaximumBytes = [uint64](512MB),
        [switch] $AllowEmpty,
        [AllowNull()] $ExpectedPrefixLength,
        [AllowNull()] $ExpectedPrefixSha256,
        [uint64] $ParseFromOffset = [uint64]0,
        [AllowNull()] $ParseFromOffsetSha256
    )
    $prefixLengthBound = $PSBoundParameters.ContainsKey('ExpectedPrefixLength')
    $prefixShaBound = $PSBoundParameters.ContainsKey('ExpectedPrefixSha256')
    if ($prefixLengthBound -ne $prefixShaBound) {
        throw "Frozen JSONL prefix identity requires both length and SHA-256."
    }
    $verifyPrefixIdentity = $prefixLengthBound -and $prefixShaBound
    if ($verifyPrefixIdentity -and
        ($ExpectedPrefixLength -isnot [uint64] -or
         $ExpectedPrefixSha256 -isnot [string] -or
         -not ([string]$ExpectedPrefixSha256 -cmatch '^[0-9a-f]{64}$'))) {
        throw "Frozen JSONL prefix identity has invalid types or digest."
    }
    $parseOffsetShaBound = $PSBoundParameters.ContainsKey('ParseFromOffsetSha256')
    if ($ParseFromOffset -ne 0 -and
        (-not $verifyPrefixIdentity -or
         -not $parseOffsetShaBound -or
         $ParseFromOffset -gt [uint64]$ExpectedPrefixLength -or
         $ParseFromOffsetSha256 -isnot [string] -or
         -not ([string]$ParseFromOffsetSha256 -cmatch '^[0-9a-f]{64}$'))) {
        throw "A nonzero JSONL parse offset requires its own authenticated complete-prefix identity."
    }
    if ($ParseFromOffset -eq 0 -and $parseOffsetShaBound) {
        throw "A zero JSONL parse offset must not carry a redundant parse-prefix digest."
    }
    $stream = [IO.FileStream]::new(
        (ConvertTo-RawQualificationExtendedLengthPath -Path $Path),
        [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $snapshotLength = [uint64]$stream.Length
        if (($snapshotLength -eq 0 -and -not $AllowEmpty) -or $snapshotLength -gt $MaximumBytes -or
            $snapshotLength -gt [uint64][int]::MaxValue) {
            throw "JSONL is empty or exceeds its bounded frozen prefix: $Path"
        }
        if ($snapshotLength -eq 0) {
            $emptySha = [Security.Cryptography.SHA256]::Create()
            try {
                $emptyDigest = -join ($emptySha.ComputeHash([byte[]]@()) | ForEach-Object { $_.ToString("x2") })
            }
            finally { $emptySha.Dispose() }
            if ($verifyPrefixIdentity -and
                ([uint64]$ExpectedPrefixLength -ne 0 -or
                 [string]$ExpectedPrefixSha256 -cne $emptyDigest)) {
                throw "Empty JSONL does not match the expected frozen byte prefix: $Path"
            }
            return [pscustomobject][ordered]@{
                lines = @()
                file_length = [uint64]0
                complete_length = [uint64]0
                partial_tail = $false
                file_sha256 = $emptyDigest
                complete_sha256 = $emptyDigest
            }
        }
        $bytes = New-Object byte[] ([int]$snapshotLength)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) { throw "JSONL ended before its frozen prefix length: $Path" }
            $offset += $read
        }
        # A continuation commonly asks for several identities at the same byte
        # boundary (observed file, complete LF prefix and parse cursor). Hash each
        # distinct prefix exactly once; equality still uses the same SHA-256 bytes.
        $prefixDigestCache = @{}
        $getPrefixDigest = {
            param([uint64] $Length)
            if ($Length -gt [uint64]$bytes.Length -or $Length -gt [uint64][int]::MaxValue) {
                throw "JSONL digest prefix exceeds its frozen bytes: $Path"
            }
            $key = [string]$Length
            if (-not $prefixDigestCache.ContainsKey($key)) {
                $hasher = [Security.Cryptography.SHA256]::Create()
                try {
                    $prefixDigestCache[$key] = -join ($hasher.ComputeHash(
                        $bytes, 0, [int]$Length) | ForEach-Object { $_.ToString("x2") })
                }
                finally { $hasher.Dispose() }
            }
            return [string]$prefixDigestCache[$key]
        }
        if ($verifyPrefixIdentity) {
            if ([uint64]$ExpectedPrefixLength -gt $snapshotLength -or
                [uint64]$ExpectedPrefixLength -gt [uint64][int]::MaxValue) {
                throw "JSONL no longer contains the expected frozen byte prefix: $Path"
            }
            $prefixDigest = & $getPrefixDigest ([uint64]$ExpectedPrefixLength)
            if ($prefixDigest -cne [string]$ExpectedPrefixSha256) {
                throw "JSONL frozen byte prefix changed between monitor observations: $Path"
            }
        }
        if ($ParseFromOffset -ne 0) {
            $parsePrefixDigest = & $getPrefixDigest $ParseFromOffset
            if ($parsePrefixDigest -cne [string]$ParseFromOffsetSha256) {
                throw "JSONL complete-record parse prefix changed between monitor observations: $Path"
            }
        }
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            throw "JSONL contains a forbidden UTF-8 BOM: $Path"
        }
        if ([Array]::IndexOf($bytes, [byte]13) -ge 0) {
            throw "JSONL contains a forbidden physical CR byte: $Path"
        }
        $lastLf = -1
        for ($scanIndex = $bytes.Length - 1; $scanIndex -ge 0; $scanIndex--) {
            if ($bytes[$scanIndex] -eq 10) { $lastLf = $scanIndex; break }
        }
        if ($lastLf -lt 0) { throw "JSONL has no complete LF-terminated record: $Path" }
        $completeLength = $lastLf + 1
        if ($ParseFromOffset -gt [uint64]$completeLength -or
            ($ParseFromOffset -ne 0 -and $bytes[[int]$ParseFromOffset - 1] -ne 10)) {
            throw "JSONL parse offset is not a complete LF-terminated prefix: $Path"
        }
        $parseLength = [int]([uint64]$completeLength - $ParseFromOffset)
        $text = [Text.UTF8Encoding]::new($false, $true).GetString(
            $bytes, [int]$ParseFromOffset, $parseLength)
        $parts = $text -split "`n", -1
        $lines = [Collections.Generic.List[string]]::new()
        for ($index = 0; $index -lt $parts.Count - 1; $index++) {
            if ([string]::IsNullOrEmpty($parts[$index])) {
                throw "JSONL contains an empty durable record: $Path"
            }
            $lines.Add($parts[$index])
        }
        $completeDigest = & $getPrefixDigest ([uint64]$completeLength)
        return [pscustomobject][ordered]@{
            lines = @($lines.ToArray())
            file_length = $snapshotLength
            complete_length = [uint64]$completeLength
            partial_tail = [bool]($completeLength -ne $bytes.Length)
            file_sha256 = & $getPrefixDigest $snapshotLength
            complete_sha256 = $completeDigest
        }
    }
    finally { $stream.Dispose() }
}

function ConvertFrom-MonitorCanonicalCompactJsonLine {
    param(
        [Parameter(Mandatory = $true)] [string] $Line,
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [uint64] $Ordinal
    )
    $value = $Line | ConvertFrom-Json -ErrorAction Stop
    $canonical = $value | ConvertTo-Json -Depth 100 -Compress
    if ($Line -cne $canonical) {
        throw "JSONL record $Ordinal differs from the exact compact writer representation: $Path"
    }
    return $value
}

function Test-MonitorJsonObjectKeysOrdinalSortedRecursive {
    param($Value)
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return $true }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [Management.Automation.PSCustomObject]) {
        foreach ($item in $Value) {
            if (-not (Test-MonitorJsonObjectKeysOrdinalSortedRecursive -Value $item)) { return $false }
        }
        return $true
    }
    $names = [string[]]@($Value.PSObject.Properties.Name)
    $sorted = [string[]]$names.Clone()
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    for ($index = 0; $index -lt $names.Count; $index++) {
        if ($names[$index] -cne $sorted[$index]) { return $false }
        if (-not (Test-MonitorJsonObjectKeysOrdinalSortedRecursive -Value $Value.PSObject.Properties[$names[$index]].Value)) {
            return $false
        }
    }
    return $true
}

function Assert-MonitorJournalRecordEnvelopeJsonTypes {
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)] [string] $ExpectedSchema
    )
    if (-not (Test-MonitorExactJsonPropertyOrder -Value $Record -Expected @("body", "record_sha256")) -or
        -not (Test-MonitorExactJsonPropertyOrder -Value $Record.body -Expected @(
                "schema", "record_index", "wall_ns", "monotonic_tick", "channel",
                "payload", "previous_record_sha256")) -or
        -not (Test-RawQualificationJsonString -Value $Record.body.schema) -or
        [string]$Record.body.schema -cne $ExpectedSchema -or
        -not (Test-RawQualificationJsonInteger -Value $Record.body.record_index -Minimum 0 -Maximum ([decimal][uint64]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger -Value $Record.body.wall_ns -Minimum 1 -Maximum ([decimal][uint64]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger -Value $Record.body.monotonic_tick -Minimum 0 -Maximum ([decimal][uint64]::MaxValue)) -or
        -not (Test-RawQualificationJsonString -Value $Record.body.channel) -or
        -not (Test-RawQualificationJsonSha256 -Value $Record.body.previous_record_sha256) -or
        -not (Test-RawQualificationJsonSha256 -Value $Record.record_sha256) -or
        $null -eq $Record.body.payload -or
        $null -eq $Record.body.payload.PSObject) {
        throw "Journal record JSON envelope is untyped, out of range, or has an unexpected property set."
    }
    if ($ExpectedSchema -eq "RawQualificationLauncherEventV1") {
        $null = Assert-MonitorLauncherRecordJsonContract -Record $Record
    }
    else {
        $null = Assert-MonitorQualificationJournalWriterOrder -Record $Record -ExpectedSchema $ExpectedSchema
    }
    return $true
}

function Assert-MonitorLauncherRecordJsonContract {
    param([Parameter(Mandatory = $true)] $Record)
    if ($null -eq $Record.PSObject.Properties['body'] -or
        $null -eq $Record.body.PSObject.Properties['record_index'] -or
        $null -eq $Record.body.PSObject.Properties['wall_ns'] -or
        $null -eq $Record.body.PSObject.Properties['monotonic_tick'] -or
        $null -eq $Record.body.PSObject.Properties['channel'] -or
        $null -eq $Record.body.PSObject.Properties['payload'] -or
        -not (Test-RawQualificationJsonInteger -Value $Record.body.record_index -Minimum 0 -Maximum ([decimal][uint64]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger -Value $Record.body.wall_ns -Minimum 1 -Maximum ([decimal][uint64]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger -Value $Record.body.monotonic_tick -Minimum 0 -Maximum ([decimal][uint64]::MaxValue)) -or
        -not (Test-RawQualificationJsonString -Value $Record.body.channel) -or
        $null -eq $Record.body.payload.PSObject.Properties['event'] -or
        -not (Test-RawQualificationJsonString -Value $Record.body.payload.event)) {
        throw "Launcher journal envelope contains an untyped or out-of-range record_index/wall_ns/monotonic_tick/channel/event."
    }
    $payload = $Record.body.payload
    $eventName = [string]$payload.event
    $channelByExactEvent = @{
        PREFLIGHT_PASSED = "LAUNCHER"
        JOB_OBJECT_ARMED = "CONTROL"
        GUARDIAN_WATCHDOG_STARTED = "CONTROL"
        DUAL_CAMPAIGN_STARTED = "CONTROL"
        DUAL_SEMANTIC_READINESS = "SEMANTIC"
        DUAL_READINESS_PUBLISHED = "SEMANTIC"
        CAPTURE_DRAINING_STARTED = "PROCESS"
        CAMPAIGN_PROCESS_EXITED = "PROCESS"
        CAMPAIGN_TERMINAL_EVALUATION_STARTED = "PROCESS"
        INDEPENDENT_VERIFICATION_STAGE_STARTED = "VERIFICATION"
        INDEPENDENT_VERIFIER_STARTED = "VERIFICATION"
        INDEPENDENT_VERIFIER_COMPLETED = "VERIFICATION"
        INDEPENDENT_CAMPAIGN_VERIFIED = "VERIFICATION"
        VERIFIER_DESCENDANTS_DRAINED = "CONTROL"
        GUARDIAN_WATCHDOG_STOPPED = "CONTROL"
        LAUNCHER_FAILED = "FAILURE"
        FAILURE_CONTAINMENT_TERMINAL = "FAILURE"
        LAUNCHER_TERMINAL = "LAUNCHER"
    }
    if (-not (@($channelByExactEvent.Keys) -ccontains $eventName) -or
        [string]$Record.body.channel -cne [string]$channelByExactEvent[$eventName]) {
        throw "Launcher journal contains a case-mismatched, unknown, or mischanneled event."
    }
    $uint32Maximum = [decimal][uint32]::MaxValue
    $uint64Maximum = [decimal][uint64]::MaxValue
    $int64Maximum = [decimal][long]::MaxValue
    switch -CaseSensitive ($eventName) {
        "PREFLIGHT_PASSED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @("event", "startup_sha256")) -or
                -not (Test-RawQualificationJsonSha256 $payload.startup_sha256)) { throw "PREFLIGHT_PASSED JSON contract is invalid." }
        }
        "JOB_OBJECT_ARMED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "name", "kill_on_close", "workload_name", "workload_kill_on_close")) -or
                -not (Test-RawQualificationJsonBoolean $payload.kill_on_close) -or
                -not (Test-RawQualificationJsonString $payload.name) -or
                -not (Test-RawQualificationJsonString $payload.workload_name) -or
                -not (Test-RawQualificationJsonBoolean $payload.workload_kill_on_close)) {
                throw "JOB_OBJECT_ARMED JSON contract is invalid."
            }
        }
        "GUARDIAN_WATCHDOG_STARTED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "pid", "ready_file_sha256", "launch_origin_qpc_timestamp",
                    "resume_qpc_timestamp", "ready_observed_qpc_timestamp", "ready_pulse_length",
                    "startup_deadline_s", "deadline_s")) -or
                -not (Test-RawQualificationJsonInteger $payload.pid 1 $uint32Maximum) -or
                -not (Test-RawQualificationJsonSha256 $payload.ready_file_sha256) -or
                -not (Test-RawQualificationJsonInteger $payload.launch_origin_qpc_timestamp 1 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.resume_qpc_timestamp 1 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.ready_observed_qpc_timestamp 1 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.ready_pulse_length 1 $uint64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.startup_deadline_s 1 604920) -or
                -not (Test-RawQualificationJsonInteger $payload.deadline_s 1 604920)) { throw "GUARDIAN_WATCHDOG_STARTED JSON contract is invalid." }
        }
        "DUAL_CAMPAIGN_STARTED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @("event", "process_control_sha256")) -or
                -not (Test-RawQualificationJsonSha256 $payload.process_control_sha256)) { throw "DUAL_CAMPAIGN_STARTED JSON contract is invalid." }
        }
        "DUAL_SEMANTIC_READINESS" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @("event", "bindings_sha256")) -or
                -not (Test-RawQualificationJsonSha256 $payload.bindings_sha256)) { throw "DUAL_SEMANTIC_READINESS JSON contract is invalid." }
        }
        "DUAL_READINESS_PUBLISHED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "bindings_sha256", "host_telemetry_record_index",
                    "host_telemetry_record_sha256", "host_telemetry_monotonic_tick")) -or
                -not (Test-RawQualificationJsonSha256 $payload.bindings_sha256) -or
                -not (Test-RawQualificationJsonInteger $payload.host_telemetry_monotonic_tick 0 $uint64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.host_telemetry_record_index 0 $uint64Maximum) -or
                -not (Test-RawQualificationJsonSha256 $payload.host_telemetry_record_sha256)) { throw "DUAL_READINESS_PUBLISHED JSON contract is invalid." }
        }
        "CAPTURE_DRAINING_STARTED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @("event", "generation_terminal_deadline_elapsed_s")) -or
                -not (Test-RawQualificationJsonInteger $payload.generation_terminal_deadline_elapsed_s 1 604920)) { throw "CAPTURE_DRAINING_STARTED JSON contract is invalid." }
        }
        "CAMPAIGN_PROCESS_EXITED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "symbol", "pid", "exit_observed_monotonic_tick", "exit_code",
                    "elapsed_s", "coordinator_elapsed_s")) -or
                -not (Test-RawQualificationJsonString $payload.symbol) -or
                -not (Test-RawQualificationJsonInteger $payload.pid 1 $uint32Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.exit_observed_monotonic_tick 1 $uint64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.exit_code 0 0) -or
                -not (Test-RawQualificationJsonInteger $payload.elapsed_s 0 $uint64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_elapsed_s 0 $uint64Maximum)) { throw "CAMPAIGN_PROCESS_EXITED JSON contract is invalid." }
        }
        "CAMPAIGN_TERMINAL_EVALUATION_STARTED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @("event", "commit_deadline_s")) -or
                -not (Test-RawQualificationJsonInteger $payload.commit_deadline_s 1 604920)) { throw "CAMPAIGN_TERMINAL_EVALUATION_STARTED JSON contract is invalid." }
        }
        "INDEPENDENT_VERIFICATION_STAGE_STARTED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "deadline_s", "coordinator_job_drain_contract",
                    "coordinator_job_scope", "coordinator_job_name",
                    "coordinator_job_drain_origin_kind", "coordinator_job_drain_deadline_s",
                    "coordinator_job_drain_origin_monotonic_tick",
                    "coordinator_job_initial_active_processes", "coordinator_job_final_active_processes",
                    "coordinator_job_observation_count", "coordinator_job_final_query_observed_monotonic_tick",
                    "coordinator_job_watchdog_liveness_observed_monotonic_tick",
                    "coordinator_job_drain_elapsed_ticks", "coordinator_job_drain_elapsed_ms",
                    "coordinator_job_monotonic_frequency", "coordinator_job_watchdog_pid",
                    "coordinator_job_watchdog_pre_query_signaled",
                    "coordinator_job_watchdog_post_query_signaled", "coordinator_job_drain_result")) -or
                -not (Test-RawQualificationJsonInteger $payload.deadline_s 1 604920) -or
                -not (Test-RawQualificationJsonString $payload.coordinator_job_drain_contract) -or
                -not (Test-RawQualificationJsonString $payload.coordinator_job_scope) -or
                -not (Test-RawQualificationJsonString $payload.coordinator_job_name) -or
                -not (Test-RawQualificationJsonString $payload.coordinator_job_drain_origin_kind) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_job_drain_deadline_s 1 10) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_job_drain_origin_monotonic_tick 1 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_job_initial_active_processes 0 $uint32Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_job_final_active_processes 0 $uint32Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_job_observation_count 1 $uint64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_job_final_query_observed_monotonic_tick 1 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_job_watchdog_liveness_observed_monotonic_tick 1 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_job_drain_elapsed_ticks 0 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_job_drain_elapsed_ms 0 $uint64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_job_monotonic_frequency 1 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.coordinator_job_watchdog_pid 1 $uint32Maximum) -or
                -not (Test-RawQualificationJsonBoolean $payload.coordinator_job_watchdog_pre_query_signaled) -or
                -not (Test-RawQualificationJsonBoolean $payload.coordinator_job_watchdog_post_query_signaled) -or
                -not (Test-RawQualificationJsonString $payload.coordinator_job_drain_result)) { throw "INDEPENDENT_VERIFICATION_STAGE_STARTED JSON contract is invalid." }
        }
        "INDEPENDENT_VERIFIER_STARTED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @("event", "name", "pid")) -or
                -not (Test-RawQualificationJsonString $payload.name) -or
                -not (Test-RawQualificationJsonInteger $payload.pid 1 $uint32Maximum)) { throw "INDEPENDENT_VERIFIER_STARTED JSON contract is invalid." }
        }
        "INDEPENDENT_VERIFIER_COMPLETED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "name", "pid", "exit_code", "stderr_bytes", "execution_sha256")) -or
                -not (Test-RawQualificationJsonString $payload.name) -or
                -not (Test-RawQualificationJsonInteger $payload.pid 1 $uint32Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.exit_code 0 0) -or
                -not (Test-RawQualificationJsonInteger $payload.stderr_bytes 0 0) -or
                -not (Test-RawQualificationJsonSha256 $payload.execution_sha256)) { throw "INDEPENDENT_VERIFIER_COMPLETED JSON contract is invalid." }
        }
        "INDEPENDENT_CAMPAIGN_VERIFIED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "symbol", "rust_report_sha256", "python_report_sha256")) -or
                -not (Test-RawQualificationJsonString $payload.symbol) -or
                -not (Test-RawQualificationJsonSha256 $payload.rust_report_sha256) -or
                -not (Test-RawQualificationJsonSha256 $payload.python_report_sha256)) { throw "INDEPENDENT_CAMPAIGN_VERIFIED JSON contract is invalid." }
        }
        "VERIFIER_DESCENDANTS_DRAINED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "active_processes", "job_scope", "job_name", "drain_origin_qpc_timestamp",
                    "elapsed_qpc_ticks", "monotonic_frequency", "elapsed_ms")) -or
                -not (Test-RawQualificationJsonInteger $payload.active_processes 0 0) -or
                -not (Test-RawQualificationJsonString $payload.job_scope) -or
                -not (Test-RawQualificationJsonString $payload.job_name) -or
                -not (Test-RawQualificationJsonInteger $payload.drain_origin_qpc_timestamp 1 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.elapsed_qpc_ticks 0 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.monotonic_frequency 1 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.elapsed_ms 0 $uint64Maximum)) { throw "VERIFIER_DESCENDANTS_DRAINED JSON contract is invalid." }
        }
        "GUARDIAN_WATCHDOG_STOPPED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "pid", "exit_code", "stop_file_sha256", "stop_request_qpc_timestamp",
                    "exit_elapsed_qpc_ticks", "final_job_drain_elapsed_qpc_ticks",
                    "monotonic_frequency", "final_job_active_processes")) -or
                -not (Test-RawQualificationJsonInteger $payload.pid 1 $uint32Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.exit_code 0 0) -or
                -not (Test-RawQualificationJsonSha256 $payload.stop_file_sha256) -or
                -not (Test-RawQualificationJsonInteger $payload.stop_request_qpc_timestamp 1 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.exit_elapsed_qpc_ticks 0 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.final_job_drain_elapsed_qpc_ticks 0 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.monotonic_frequency 1 $int64Maximum) -or
                -not (Test-RawQualificationJsonInteger $payload.final_job_active_processes 0 0)) { throw "GUARDIAN_WATCHDOG_STOPPED JSON contract is invalid." }
        }
        "LAUNCHER_FAILED" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @("event", "error")) -or
                -not (Test-RawQualificationJsonString $payload.error)) { throw "LAUNCHER_FAILED JSON contract is invalid." }
        }
        "FAILURE_CONTAINMENT_TERMINAL" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @("event", "failure_containment_sha256")) -or
                -not (Test-RawQualificationJsonSha256 $payload.failure_containment_sha256)) {
                throw "FAILURE_CONTAINMENT_TERMINAL JSON contract is invalid."
            }
        }
        "LAUNCHER_TERMINAL" {
            if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "status", "failure", "terminal_file", "terminal_bytes",
                    "terminal_sha256", "failure_containment_sha256")) -or
                -not (Test-RawQualificationJsonString $payload.status) -or
                @("COMPLETE", "FAILED") -cnotcontains [string]$payload.status -or
                ($null -ne $payload.failure -and -not (Test-RawQualificationJsonString $payload.failure)) -or
                -not (Test-RawQualificationJsonString $payload.terminal_file) -or
                [string]$payload.terminal_file -cne "launcher-terminal.json" -or
                -not (Test-RawQualificationJsonInteger $payload.terminal_bytes 1 $uint64Maximum) -or
                -not (Test-RawQualificationJsonSha256 $payload.terminal_sha256) -or
                ($null -ne $payload.failure_containment_sha256 -and
                    -not (Test-RawQualificationJsonSha256 $payload.failure_containment_sha256)) -or
                ([string]$payload.status -ceq "COMPLETE" -and
                    ($null -ne $payload.failure -or $null -ne $payload.failure_containment_sha256)) -or
                ([string]$payload.status -ceq "FAILED" -and
                    (-not (Test-RawQualificationJsonString $payload.failure) -or
                     -not (Test-RawQualificationJsonSha256 $payload.failure_containment_sha256)))) {
                throw "LAUNCHER_TERMINAL JSON contract is invalid."
            }
        }
        default { throw "Launcher journal contains an unknown future event: $eventName" }
    }
    return $true
}

function Assert-MonitorQualificationJournalWriterOrder {
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)] [string] $ExpectedSchema
    )
    $payload = $Record.body.payload
    if ($ExpectedSchema -eq "RawQualificationGuardianPulseV1") {
        if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "stage", "launcher_elapsed_ms", "capture_elapsed_ms"))) {
            throw "Guardian pulse differs from the exact ordered writer contract."
        }
        if (-not (Test-RawQualificationJsonString $payload.event) -or
            -not (Test-RawQualificationJsonString $payload.stage) -or
            -not (Test-RawQualificationJsonInteger $payload.launcher_elapsed_ms 0 ([decimal][uint64]::MaxValue)) -or
            -not (Test-MonitorJsonNullOrInteger $payload.capture_elapsed_ms 0 ([decimal][uint64]::MaxValue))) {
            throw "Guardian pulse contains an untyped/out-of-range recursive payload."
        }
        return $true
    }
    if ($ExpectedSchema -ne "RawQualificationHostTelemetryRecordV1") { return $true }
    if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                "monotonic_frequency", "launcher_elapsed_ms", "capture_elapsed_ms", "clock", "disk",
                "disk_persistent_reserve_gib", "disk_projected_remaining_gib", "disk_required_free_gib",
                "network", "collector_processes", "provider_execution", "campaigns")) -or
        -not (Test-MonitorExactJsonPropertyOrder $payload.clock @(
                "healthy", "leap_indicator", "stratum", "source", "last_successful_sync",
                "root_delay_s", "root_dispersion_s", "phase_offset_s", "seconds_since_last_good_sync",
                "maximum_last_good_sync_age_s", "state_machine", "last_sync_error", "poll_interval_s",
                "raw_status_sha256", "query_exit_code")) -or
        -not (Test-MonitorExactJsonPropertyOrder $payload.disk @(
                "device_id", "filesystem", "size_bytes", "free_bytes", "avg_read_latency_s",
                "avg_write_latency_s", "current_queue_length")) -or
        -not (Test-MonitorExactJsonPropertyOrder $payload.network @(
                "received_bytes", "sent_bytes", "received_packets", "sent_packets", "received_discards",
                "outbound_discards", "received_errors", "outbound_errors")) -or
        -not (Test-MonitorExactJsonPropertyOrder $payload.provider_execution @(
                "pid", "command_line_sha256", "resume_qpc_timestamp", "elapsed_qpc_ticks",
                "monotonic_frequency", "job_membership", "parent_exit_observed_qpc_timestamp",
                "descendant_drain_elapsed_qpc_ticks", "descendant_drain_elapsed_ms",
                "descendant_drain_active_processes", "timeout_s", "elapsed_ms", "stdout_bytes",
                "stdout_sha256", "stderr_bytes", "stderr_sha256"))) {
        throw "Host telemetry differs from the exact ordered writer contract."
    }
    foreach ($process in @($payload.collector_processes)) {
        if (-not (Test-MonitorExactJsonPropertyOrder $process @(
                    "pid", "parent_pid", "name", "creation_date", "executable_path", "cpu_kernel_100ns",
                    "cpu_user_100ns", "working_set_bytes", "page_file_kib", "handles", "read_operations",
                    "read_bytes", "write_operations", "write_bytes"))) {
            throw "Host telemetry collector process differs from the exact ordered writer contract."
        }
    }
    foreach ($campaign in @($payload.campaigns)) {
        if (-not (Test-MonitorExactJsonPropertyOrder $campaign @(
                    "symbol", "pid", "campaign_id", "campaign_elapsed_s", "generations", "active_processes",
                    "handovers_proven", "depth_received", "depth_durable", "trade_received", "trade_durable",
                    "latest_generation_index", "latest_telemetry_mono_ns",
                    "depth_last_socket_activity_mono_ns", "depth_last_market_message_mono_ns",
                    "depth_market_message_age_ms", "trade_last_socket_activity_mono_ns",
                    "trade_last_market_message_mono_ns", "trade_market_message_age_ms", "ready", "exited"))) {
            throw "Host telemetry campaign summary differs from the exact ordered writer contract."
        }
    }
    $null = Assert-MonitorHostTelemetryPayloadJsonTypes -Payload $payload
    return $true
}

function Assert-MonitorClockJsonTypes {
    param([Parameter(Mandatory = $true)] $Clock)
    $u64 = [decimal][uint64]::MaxValue
    if (-not (Test-MonitorExactJsonProperties $Clock @(
                "healthy", "leap_indicator", "stratum", "source", "last_successful_sync",
                "root_delay_s", "root_dispersion_s", "phase_offset_s", "seconds_since_last_good_sync",
                "maximum_last_good_sync_age_s", "state_machine", "last_sync_error", "poll_interval_s",
                "raw_status_sha256", "query_exit_code")) -or
        -not (Test-RawQualificationJsonBoolean $Clock.healthy) -or
        -not (Test-RawQualificationJsonInteger $Clock.leap_indicator 0 3) -or
        -not (Test-RawQualificationJsonInteger $Clock.stratum 0 255) -or
        -not (Test-RawQualificationJsonString $Clock.source) -or
        -not (Test-RawQualificationJsonString $Clock.last_successful_sync) -or
        -not (Test-MonitorJsonRealNumber $Clock.root_delay_s) -or
        -not (Test-MonitorJsonRealNumber $Clock.root_dispersion_s 0) -or
        -not (Test-MonitorJsonRealNumber $Clock.phase_offset_s) -or
        -not (Test-MonitorJsonRealNumber $Clock.seconds_since_last_good_sync 0) -or
        -not (Test-MonitorJsonRealNumber $Clock.maximum_last_good_sync_age_s 1) -or
        -not (Test-RawQualificationJsonInteger $Clock.state_machine 0 ([decimal][int]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $Clock.last_sync_error 0 $u64) -or
        -not (Test-RawQualificationJsonInteger $Clock.poll_interval_s 1 $u64) -or
        -not (Test-RawQualificationJsonSha256 $Clock.raw_status_sha256) -or
        -not (Test-RawQualificationJsonInteger $Clock.query_exit_code 0 ([decimal][int]::MaxValue))) {
        throw "Clock payload contains an unexpected property, coercible scalar, non-finite value, or invalid range."
    }
    return $true
}

function Assert-MonitorDiskJsonTypes {
    param([Parameter(Mandatory = $true)] $Disk)
    $u64 = [decimal][uint64]::MaxValue
    if (-not (Test-MonitorExactJsonProperties $Disk @(
                "device_id", "filesystem", "size_bytes", "free_bytes", "avg_read_latency_s",
                "avg_write_latency_s", "current_queue_length")) -or
        -not (Test-RawQualificationJsonString $Disk.device_id) -or
        -not (Test-RawQualificationJsonString $Disk.filesystem) -or
        -not (Test-RawQualificationJsonInteger $Disk.size_bytes 1 $u64) -or
        -not (Test-RawQualificationJsonInteger $Disk.free_bytes 0 $u64) -or
        -not (Test-MonitorJsonRealNumber $Disk.avg_read_latency_s 0) -or
        -not (Test-MonitorJsonRealNumber $Disk.avg_write_latency_s 0) -or
        -not (Test-MonitorJsonRealNumber $Disk.current_queue_length 0)) {
        throw "Disk payload contains an unexpected property, coercible scalar, non-finite value, or invalid range."
    }
    return $true
}

function Assert-MonitorNetworkJsonTypes {
    param([Parameter(Mandatory = $true)] $Network)
    $u64 = [decimal][uint64]::MaxValue
    $names = @("received_bytes", "sent_bytes", "received_packets", "sent_packets",
        "received_discards", "outbound_discards", "received_errors", "outbound_errors")
    if (-not (Test-MonitorExactJsonProperties $Network $names)) {
        throw "Network payload has an unexpected property set."
    }
    foreach ($name in $names) {
        if (-not (Test-RawQualificationJsonInteger $Network.PSObject.Properties[$name].Value 0 $u64)) {
            throw "Network payload contains an untyped/out-of-range counter: $name"
        }
    }
    return $true
}

function Assert-MonitorCollectorProcessJsonTypes {
    param([Parameter(Mandatory = $true)] $Process)
    $u64 = [decimal][uint64]::MaxValue
    if (-not (Test-MonitorExactJsonProperties $Process @(
                "pid", "parent_pid", "name", "creation_date", "executable_path", "cpu_kernel_100ns",
                "cpu_user_100ns", "working_set_bytes", "page_file_kib", "handles", "read_operations",
                "read_bytes", "write_operations", "write_bytes")) -or
        -not (Test-RawQualificationJsonInteger $Process.pid 1 ([decimal][uint32]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $Process.parent_pid 0 ([decimal][uint32]::MaxValue)) -or
        -not (Test-RawQualificationJsonString $Process.name) -or
        -not (Test-RawQualificationJsonString $Process.creation_date) -or
        -not (Test-RawQualificationJsonString $Process.executable_path)) {
        throw "Collector process identity contains an unexpected/coercible field."
    }
    foreach ($name in @("cpu_kernel_100ns", "cpu_user_100ns", "working_set_bytes", "page_file_kib",
            "handles", "read_operations", "read_bytes", "write_operations", "write_bytes")) {
        if (-not (Test-RawQualificationJsonInteger $Process.PSObject.Properties[$name].Value 0 $u64)) {
            throw "Collector process contains an untyped/out-of-range counter: $name"
        }
    }
    return $true
}

function Assert-MonitorCampaignSummaryJsonTypes {
    param([Parameter(Mandatory = $true)] $Campaign)
    $u64 = [decimal][uint64]::MaxValue
    $expected = @(
        "symbol", "pid", "campaign_id", "campaign_elapsed_s", "generations", "active_processes",
        "handovers_proven", "depth_received", "depth_durable", "trade_received", "trade_durable",
        "latest_generation_index", "latest_telemetry_mono_ns", "depth_last_socket_activity_mono_ns",
        "depth_last_market_message_mono_ns", "depth_market_message_age_ms",
        "trade_last_socket_activity_mono_ns", "trade_last_market_message_mono_ns",
        "trade_market_message_age_ms", "ready", "exited")
    if (-not (Test-MonitorExactJsonProperties $Campaign $expected) -or
        -not (Test-RawQualificationJsonString $Campaign.symbol) -or
        -not (Test-RawQualificationJsonInteger $Campaign.pid 1 ([decimal][uint32]::MaxValue)) -or
        -not (Test-MonitorJsonNullOrString $Campaign.campaign_id) -or
        -not (Test-RawQualificationJsonBoolean $Campaign.ready) -or
        -not (Test-RawQualificationJsonBoolean $Campaign.exited)) {
        throw "Campaign summary contains an unexpected/coercible identity or boolean."
    }
    foreach ($name in @("campaign_elapsed_s", "generations", "active_processes", "handovers_proven",
            "depth_received", "depth_durable", "trade_received", "trade_durable")) {
        if (-not (Test-RawQualificationJsonInteger $Campaign.PSObject.Properties[$name].Value 0 $u64)) {
            throw "Campaign summary contains an untyped/out-of-range counter: $name"
        }
    }
    foreach ($name in @("latest_generation_index", "latest_telemetry_mono_ns",
            "depth_last_socket_activity_mono_ns", "depth_last_market_message_mono_ns",
            "trade_last_socket_activity_mono_ns", "trade_last_market_message_mono_ns")) {
        if (-not (Test-MonitorJsonNullOrInteger $Campaign.PSObject.Properties[$name].Value 0 $u64)) {
            throw "Campaign summary contains an invalid nullable integer: $name"
        }
    }
    foreach ($name in @("depth_market_message_age_ms", "trade_market_message_age_ms")) {
        $value = $Campaign.PSObject.Properties[$name].Value
        if ($null -ne $value -and -not (Test-MonitorJsonRealNumber $value 0)) {
            throw "Campaign summary contains a non-finite/coercible age: $name"
        }
    }
    return $true
}

function Assert-MonitorHostTelemetryPayloadJsonTypes {
    param([Parameter(Mandatory = $true)] $Payload)
    $u64 = [decimal][uint64]::MaxValue
    foreach ($name in @("monotonic_frequency", "launcher_elapsed_ms", "capture_elapsed_ms",
            "disk_persistent_reserve_gib", "disk_projected_remaining_gib", "disk_required_free_gib")) {
        if (-not (Test-RawQualificationJsonInteger $Payload.PSObject.Properties[$name].Value 0 $u64)) {
            throw "Host telemetry contains an untyped/out-of-range scalar: $name"
        }
    }
    if ([decimal]$Payload.monotonic_frequency -lt 1 -or
        $Payload.collector_processes -isnot [System.Array] -or
        $Payload.campaigns -isnot [System.Array]) {
        throw "Host telemetry arrays/frequency do not have the exact JSON shape."
    }
    $null = Assert-MonitorClockJsonTypes $Payload.clock
    $null = Assert-MonitorDiskJsonTypes $Payload.disk
    $null = Assert-MonitorNetworkJsonTypes $Payload.network
    $null = Assert-MonitorProviderExecutionJsonTypes $Payload.provider_execution
    foreach ($process in @($Payload.collector_processes)) { $null = Assert-MonitorCollectorProcessJsonTypes $process }
    foreach ($campaign in @($Payload.campaigns)) { $null = Assert-MonitorCampaignSummaryJsonTypes $campaign }
    return $true
}

function Assert-MonitorStartupControlJsonTypes {
    param(
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] $Control,
        [switch] $RequireWriterContract
    )
    $unsigned = [decimal][uint64]::MaxValue
    $signed = [decimal][long]::MaxValue
    $u32 = [decimal][uint32]::MaxValue
    if ($RequireWriterContract) {
        if (-not (Test-MonitorExactJsonPropertyOrder $Startup @(
                "schema", "run_id", "mode", "run_root", "started_utc", "launcher_pid",
                "launcher_creation_time_utc", "launcher_executable_path", "launcher_executable_sha256",
                "launcher_command_line", "output_path_post_create", "monotonic_frequency",
                "monotonic_origin_qpc_timestamp", "parameters", "verifier_policy", "coordinator_log_policy",
                "market_freshness_policy", "guardian_policy", "preflight", "credentials", "order_entry")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.output_path_post_create @(
                "reparse_points_rejected", "run_root_drive_device_id", "same_preflight_volume", "filesystem",
                "free_gib", "required_free_gib", "probe_pid", "probe_command_line_sha256",
                "probe_resume_qpc_timestamp", "probe_elapsed_qpc_ticks", "probe_monotonic_frequency",
                "probe_job_membership", "probe_parent_exit_observed_qpc_timestamp",
                "probe_descendant_drain_elapsed_qpc_ticks", "probe_descendant_drain_elapsed_ms",
                "probe_descendant_drain_active_processes", "probe_timeout_s", "probe_elapsed_ms",
                "probe_stdout_file", "probe_stdout_bytes", "probe_stdout_sha256", "probe_stderr_file",
                "probe_stderr_bytes", "probe_stderr_sha256")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.parameters @("total_s", "rotation_s", "overlap_s", "segment_s")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.verifier_policy @(
                "per_process_timeout_s", "total_post_capture_timeout_s", "maximum_artifact_bytes")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.coordinator_log_policy @(
                "maximum_stdout_bytes", "maximum_stderr_bytes", "child_stderr_events_allowed")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.market_freshness_policy @("startup_grace_s", "deadline_s")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.guardian_policy @(
                "pulse_file", "watchdog_ready_file", "watchdog_startup_deadline_s", "watchdog_deadline_s",
                "host_telemetry_gap_deadline_s", "maximum_dual_launch_skew_ms",
                "generation_terminal_deadline_s", "campaign_commit_deadline_s")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.preflight @(
                "repo", "output_base", "drive_device_id", "free_gib", "projection_combined_raw_gib_per_hour",
                "projection_safety_multiplier", "projection_fixed_reserve_gib", "persistent_reserve_gib",
                "projected_remaining_gib_at_start", "required_free_gib", "disk_telemetry_preflight",
                "network_telemetry_preflight", "process_telemetry_preflight", "campaign_executable",
                "campaign_executable_sha256", "capture_executable", "capture_executable_sha256",
                "campaign_verifier_executable", "campaign_verifier_executable_sha256", "public_config",
                "public_config_sha256", "source_lock", "source_lock_sha256", "launcher_script",
                "launcher_script_sha256", "monitor_script", "monitor_script_sha256", "helper_script",
                "helper_script_sha256", "telemetry_probe_script", "telemetry_probe_script_sha256",
                "watchdog_script", "watchdog_script_sha256", "python_runtime_fingerprint_script",
                "python_runtime_fingerprint_script_sha256", "powershell_executable",
                "powershell_executable_sha256", "host_probe_timeout_s", "host_probe_maximum_artifact_bytes",
                "guardian_watchdog_deadline_s", "guardian_watchdog_startup_deadline_s",
                "python_runtime_fingerprint_timeout_s", "spec_revision", "clock", "python", "python_sha256",
                "python_verifier_source", "python_runtime", "python_project", "python_project_sha256",
                "python_requirements", "python_requirements_sha256", "cbs_reboot_pending",
                "windows_update_reboot_pending", "pending_file_rename_present", "child_environment")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.preflight.disk_telemetry_preflight @(
                "device_id", "filesystem", "size_bytes", "free_bytes", "avg_read_latency_s",
                "avg_write_latency_s", "current_queue_length")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.preflight.network_telemetry_preflight @(
                "received_bytes", "sent_bytes", "received_packets", "sent_packets", "received_discards",
                "outbound_discards", "received_errors", "outbound_errors")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.preflight.clock @(
                "healthy", "leap_indicator", "stratum", "source", "last_successful_sync", "root_delay_s",
                "root_dispersion_s", "phase_offset_s", "seconds_since_last_good_sync",
                "maximum_last_good_sync_age_s", "state_machine", "last_sync_error", "poll_interval_s",
                "raw_status_sha256", "query_exit_code")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.preflight.python_verifier_source @(
                "root", "files", "tree_sha256", "inventory")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.preflight.python_runtime @(
                "venv_root", "venv_python", "venv_python_sha256", "pyvenv_config", "pyvenv_config_sha256",
                "base_root", "base_executable", "base_executable_sha256", "file_count", "total_bytes",
                "tree_sha256", "included_extensions", "excluded_path_components")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Startup.preflight.child_environment @(
                "mode", "names", "entries_sha256", "Entries")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Control @(
                "schema", "run_id", "job_object_name", "job_kill_on_close",
                "workload_job_object_name", "workload_job_kill_on_close", "launch_method",
                "child_environment_mode", "child_environment_names", "child_environment_entries_sha256",
                "capture_origin_monotonic_tick", "launch_skew_ticks", "launch_skew_ms",
                "maximum_dual_launch_skew_ms", "watchdog", "processes")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Control.watchdog @(
                "pid", "job_name", "creation_time_utc", "executable_path", "executable_sha256", "command_line",
                "script_path", "script_sha256", "launch_origin_qpc_timestamp", "resume_qpc_timestamp",
                "monotonic_frequency", "startup_deadline_s", "guardian_pulse_file",
                "maximum_guardian_pulse_age_s", "ready_file", "ready_file_sha256",
                "ready_observed_qpc_timestamp", "ready_pulse_length", "stdout_file", "stderr_file"))) {
            throw "Startup/process-control differs from the exact ordered PowerShell writer contract."
        }
        foreach ($process in @($Control.processes)) {
            if (-not (Test-MonitorExactJsonPropertyOrder $process @(
                    "symbol", "pid", "creation_time_utc", "executable_path", "executable_sha256",
                    "command_line", "launch_monotonic_tick", "stdout_file", "stderr_file"))) {
                throw "Coordinator process record differs from the exact ordered PowerShell writer contract."
            }
        }
        foreach ($process in @($Startup.preflight.process_telemetry_preflight)) {
            if (-not (Test-MonitorExactJsonPropertyOrder $process @(
                    "pid", "parent_pid", "name", "creation_date", "executable_path", "cpu_kernel_100ns",
                    "cpu_user_100ns", "working_set_bytes", "page_file_kib", "handles", "read_operations",
                    "read_bytes", "write_operations", "write_bytes"))) {
                throw "Preflight process telemetry differs from the exact ordered PowerShell writer contract."
            }
        }
        foreach ($inventory in @($Startup.preflight.python_verifier_source.inventory)) {
            if (-not (Test-MonitorExactJsonPropertyOrder $inventory @("path", "bytes", "sha256"))) {
                throw "Python source inventory differs from the exact ordered PowerShell writer contract."
            }
        }
    }
    foreach ($entry in @(
        [pscustomobject]@{ value = $Startup.launcher_pid; min = 1; max = $u32; name = "startup.launcher_pid" },
        [pscustomobject]@{ value = $Startup.monotonic_frequency; min = 1; max = $signed; name = "startup.monotonic_frequency" },
        [pscustomobject]@{ value = $Startup.monotonic_origin_qpc_timestamp; min = 1; max = $signed; name = "startup.monotonic_origin_qpc_timestamp" },
        [pscustomobject]@{ value = $Startup.parameters.total_s; min = 1; max = 604800; name = "startup.parameters.total_s" },
        [pscustomobject]@{ value = $Startup.parameters.rotation_s; min = 1; max = 604800; name = "startup.parameters.rotation_s" },
        [pscustomobject]@{ value = $Startup.parameters.overlap_s; min = 1; max = 604800; name = "startup.parameters.overlap_s" },
        [pscustomobject]@{ value = $Startup.parameters.segment_s; min = 1; max = 604800; name = "startup.parameters.segment_s" },
        [pscustomobject]@{ value = $Startup.guardian_policy.watchdog_startup_deadline_s; min = 1; max = 604920; name = "startup.guardian.watchdog_startup" },
        [pscustomobject]@{ value = $Startup.guardian_policy.watchdog_deadline_s; min = 1; max = 604920; name = "startup.guardian.watchdog" },
        [pscustomobject]@{ value = $Startup.guardian_policy.host_telemetry_gap_deadline_s; min = 1; max = 604920; name = "startup.guardian.host_gap" },
        [pscustomobject]@{ value = $Startup.guardian_policy.maximum_dual_launch_skew_ms; min = 0; max = $unsigned; name = "startup.guardian.launch_skew" },
        [pscustomobject]@{ value = $Startup.guardian_policy.generation_terminal_deadline_s; min = 1; max = 120; name = "startup.guardian.generation_terminal" },
        [pscustomobject]@{ value = $Startup.guardian_policy.campaign_commit_deadline_s; min = 1; max = 604920; name = "startup.guardian.campaign_commit" },
        [pscustomobject]@{ value = $Startup.verifier_policy.total_post_capture_timeout_s; min = 1; max = 604920; name = "startup.verifier.total" },
        [pscustomobject]@{ value = $Startup.verifier_policy.per_process_timeout_s; min = 1; max = 604920; name = "startup.verifier.process" },
        [pscustomobject]@{ value = $Control.capture_origin_monotonic_tick; min = 1; max = $unsigned; name = "control.capture_origin" })) {
        if (-not (Test-RawQualificationJsonInteger $entry.value $entry.min $entry.max)) {
            throw "Startup/control JSON integer is untyped or out of range: $($entry.name)"
        }
    }
    if (-not (Test-RawQualificationJsonBoolean $Control.job_kill_on_close) -or
        -not (Test-RawQualificationJsonBoolean $Control.workload_job_kill_on_close)) {
        throw "Both process-control Job kill-on-close fields must be JSON booleans."
    }
    foreach ($process in @($Control.processes)) {
        if (-not (Test-RawQualificationJsonString $process.symbol) -or
            -not (Test-RawQualificationJsonInteger $process.pid 1 $u32) -or
            -not (Test-RawQualificationJsonInteger $process.launch_monotonic_tick 1 $unsigned)) {
            throw "A coordinator process identity contains an untyped JSON symbol/PID/launch tick."
        }
    }
    foreach ($entry in @(
        [pscustomobject]@{ value = $Control.watchdog.pid; min = 1; max = $u32 },
        [pscustomobject]@{ value = $Control.watchdog.launch_origin_qpc_timestamp; min = 1; max = $signed },
        [pscustomobject]@{ value = $Control.watchdog.resume_qpc_timestamp; min = 1; max = $signed },
        [pscustomobject]@{ value = $Control.watchdog.ready_observed_qpc_timestamp; min = 1; max = $signed },
        [pscustomobject]@{ value = $Control.watchdog.ready_pulse_length; min = 1; max = $unsigned })) {
        if (-not (Test-RawQualificationJsonInteger $entry.value $entry.min $entry.max)) {
            throw "Watchdog control JSON numeric identity is untyped or out of range."
        }
    }
    $null = Assert-MonitorStartupControlRecursiveJsonTypes -Startup $Startup -Control $Control
    return $true
}

function Assert-MonitorStartupControlRecursiveJsonTypes {
    param(
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] $Control
    )
    $u64 = [decimal][uint64]::MaxValue
    $i64 = [decimal][long]::MaxValue
    foreach ($value in @($Startup.schema, $Startup.run_id, $Startup.mode, $Startup.run_root,
            $Startup.started_utc, $Startup.launcher_creation_time_utc, $Startup.launcher_executable_path,
            $Startup.launcher_command_line, $Startup.credentials, $Startup.order_entry,
            $Control.schema, $Control.run_id, $Control.job_object_name,
            $Control.workload_job_object_name, $Control.launch_method,
            $Control.child_environment_mode)) {
        if (-not (Test-RawQualificationJsonString $value)) {
            throw "Startup/control contains a non-string JSON identity field."
        }
    }
    foreach ($digest in @($Startup.launcher_executable_sha256,
            $Startup.preflight.campaign_executable_sha256,
            $Startup.preflight.capture_executable_sha256,
            $Startup.preflight.campaign_verifier_executable_sha256,
            $Startup.preflight.public_config_sha256, $Startup.preflight.source_lock_sha256,
            $Startup.preflight.launcher_script_sha256, $Startup.preflight.monitor_script_sha256,
            $Startup.preflight.helper_script_sha256, $Startup.preflight.telemetry_probe_script_sha256,
            $Startup.preflight.watchdog_script_sha256,
            $Startup.preflight.python_runtime_fingerprint_script_sha256,
            $Startup.preflight.powershell_executable_sha256, $Startup.preflight.python_sha256,
            $Startup.preflight.python_project_sha256, $Startup.preflight.python_requirements_sha256,
            $Startup.preflight.python_verifier_source.tree_sha256,
            $Startup.preflight.python_runtime.venv_python_sha256,
            $Startup.preflight.python_runtime.pyvenv_config_sha256,
            $Startup.preflight.python_runtime.base_executable_sha256,
            $Startup.preflight.python_runtime.tree_sha256,
            $Startup.preflight.child_environment.entries_sha256,
            $Control.child_environment_entries_sha256, $Control.watchdog.executable_sha256,
            $Control.watchdog.script_sha256, $Control.watchdog.ready_file_sha256)) {
        if (-not (Test-RawQualificationJsonSha256 $digest)) {
            throw "Startup/control contains a malformed or non-string SHA-256 provenance field."
        }
    }
    foreach ($entry in @(
        [pscustomobject]@{ n="verifier.per_process";v=$Startup.verifier_policy.per_process_timeout_s;min=1;max=604920 },
        [pscustomobject]@{ n="verifier.total";v=$Startup.verifier_policy.total_post_capture_timeout_s;min=1;max=604920 },
        [pscustomobject]@{ n="verifier.bytes";v=$Startup.verifier_policy.maximum_artifact_bytes;min=1;max=$u64 },
        [pscustomobject]@{ n="logs.stdout";v=$Startup.coordinator_log_policy.maximum_stdout_bytes;min=1;max=$u64 },
        [pscustomobject]@{ n="logs.stderr";v=$Startup.coordinator_log_policy.maximum_stderr_bytes;min=0;max=$u64 },
        [pscustomobject]@{ n="logs.child_stderr";v=$Startup.coordinator_log_policy.child_stderr_events_allowed;min=0;max=$u64 },
        [pscustomobject]@{ n="freshness.startup";v=$Startup.market_freshness_policy.startup_grace_s;min=1;max=604920 },
        [pscustomobject]@{ n="freshness.deadline";v=$Startup.market_freshness_policy.deadline_s;min=1;max=604920 },
        [pscustomobject]@{ n="preflight.free";v=$Startup.preflight.free_gib;min=0;max=$u64 },
        [pscustomobject]@{ n="preflight.fixed";v=$Startup.preflight.projection_fixed_reserve_gib;min=0;max=$u64 },
        [pscustomobject]@{ n="preflight.reserve";v=$Startup.preflight.persistent_reserve_gib;min=0;max=$u64 },
        [pscustomobject]@{ n="preflight.projected";v=$Startup.preflight.projected_remaining_gib_at_start;min=0;max=$u64 },
        [pscustomobject]@{ n="preflight.required";v=$Startup.preflight.required_free_gib;min=0;max=$u64 },
        [pscustomobject]@{ n="preflight.host_timeout";v=$Startup.preflight.host_probe_timeout_s;min=1;max=604920 },
        [pscustomobject]@{ n="preflight.host_bytes";v=$Startup.preflight.host_probe_maximum_artifact_bytes;min=1;max=$u64 },
        [pscustomobject]@{ n="preflight.watchdog";v=$Startup.preflight.guardian_watchdog_deadline_s;min=1;max=604920 },
        [pscustomobject]@{ n="preflight.watchdog_start";v=$Startup.preflight.guardian_watchdog_startup_deadline_s;min=1;max=604920 },
        [pscustomobject]@{ n="preflight.python_timeout";v=$Startup.preflight.python_runtime_fingerprint_timeout_s;min=1;max=604920 },
        [pscustomobject]@{ n="python.files";v=$Startup.preflight.python_verifier_source.files;min=1;max=$u64 },
        [pscustomobject]@{ n="runtime.files";v=$Startup.preflight.python_runtime.file_count;min=1;max=$u64 },
        [pscustomobject]@{ n="runtime.bytes";v=$Startup.preflight.python_runtime.total_bytes;min=1;max=$u64 },
        [pscustomobject]@{ n="control.capture_origin";v=$Control.capture_origin_monotonic_tick;min=1;max=$u64 },
        [pscustomobject]@{ n="control.skew_ticks";v=$Control.launch_skew_ticks;min=0;max=$u64 },
        [pscustomobject]@{ n="control.skew_ms";v=$Control.launch_skew_ms;min=0;max=$u64 },
        [pscustomobject]@{ n="control.skew_max";v=$Control.maximum_dual_launch_skew_ms;min=0;max=$u64 },
        [pscustomobject]@{ n="watchdog.pid";v=$Control.watchdog.pid;min=1;max=([decimal][uint32]::MaxValue) },
        [pscustomobject]@{ n="watchdog.origin";v=$Control.watchdog.launch_origin_qpc_timestamp;min=1;max=$i64 },
        [pscustomobject]@{ n="watchdog.resume";v=$Control.watchdog.resume_qpc_timestamp;min=1;max=$i64 },
        [pscustomobject]@{ n="watchdog.frequency";v=$Control.watchdog.monotonic_frequency;min=1;max=$i64 },
        [pscustomobject]@{ n="watchdog.start_deadline";v=$Control.watchdog.startup_deadline_s;min=1;max=604920 },
        [pscustomobject]@{ n="watchdog.age";v=$Control.watchdog.maximum_guardian_pulse_age_s;min=1;max=604920 },
        [pscustomobject]@{ n="watchdog.observed";v=$Control.watchdog.ready_observed_qpc_timestamp;min=1;max=$i64 },
        [pscustomobject]@{ n="watchdog.pulse_length";v=$Control.watchdog.ready_pulse_length;min=1;max=$u64 })) {
        if (-not (Test-RawQualificationJsonInteger $entry.v $entry.min $entry.max)) {
            throw "Startup/control contains an untyped/out-of-range JSON integer: $($entry.n)"
        }
    }
    foreach ($entry in @(
            [pscustomobject]@{n="raw_rate";v=$Startup.preflight.projection_combined_raw_gib_per_hour;min=0},
            [pscustomobject]@{n="projection_multiplier";v=$Startup.preflight.projection_safety_multiplier;min=1})) {
        if (-not (Test-MonitorJsonRealNumber $entry.v $entry.min)) {
            throw "Startup preflight contains a non-finite/coercible projection scalar: $($entry.n)"
        }
    }
    foreach ($value in @($Startup.preflight.cbs_reboot_pending,
            $Startup.preflight.windows_update_reboot_pending,
            $Startup.preflight.pending_file_rename_present, $Control.job_kill_on_close,
            $Control.workload_job_kill_on_close)) {
        if (-not (Test-RawQualificationJsonBoolean $value)) {
            throw "Startup/control contains a non-boolean JSON policy field."
        }
    }
    $null = Assert-MonitorClockJsonTypes $Startup.preflight.clock
    $null = Assert-MonitorDiskJsonTypes $Startup.preflight.disk_telemetry_preflight
    $null = Assert-MonitorNetworkJsonTypes $Startup.preflight.network_telemetry_preflight
    foreach ($process in @($Startup.preflight.process_telemetry_preflight)) {
        $null = Assert-MonitorCollectorProcessJsonTypes $process
    }
    foreach ($inventory in @($Startup.preflight.python_verifier_source.inventory)) {
        if (-not (Test-MonitorExactJsonProperties $inventory @("path", "bytes", "sha256")) -or
            -not (Test-RawQualificationJsonString $inventory.path) -or
            -not (Test-RawQualificationJsonInteger $inventory.bytes 0 $u64) -or
            -not (Test-RawQualificationJsonSha256 $inventory.sha256)) {
            throw "Python source inventory contains an unexpected/coercible record."
        }
    }
    $null = Assert-MonitorJsonStringArray $Startup.preflight.python_runtime.included_extensions
    $null = Assert-MonitorJsonStringArray $Startup.preflight.python_runtime.excluded_path_components
    $null = Assert-MonitorJsonStringArray $Startup.preflight.child_environment.names
    $null = Assert-MonitorJsonStringArray $Startup.preflight.child_environment.Entries
    $null = Assert-MonitorJsonStringArray $Control.child_environment_names
    if ([string]$Startup.credentials -cne "NONE" -or [string]$Startup.order_entry -cne "ABSENT" -or
        [string]$Control.schema -cne "RawQualificationProcessControlV2" -or
        -not [bool]$Control.job_kill_on_close -or
        -not [bool]$Control.workload_job_kill_on_close -or
        [string]$Control.job_object_name -cne
            ("Local\BinanceRawQualificationJob-" + [string]$Startup.run_id) -or
        [string]$Control.workload_job_object_name -cne
            ("Local\BinanceRawQualificationWorkloadJob-" + [string]$Startup.run_id) -or
        [string]$Control.job_object_name -ceq [string]$Control.workload_job_object_name -or
        [string]$Control.launch_method -cne "CREATE_SUSPENDED_ASSIGN_OUTER_AND_WORKLOAD_JOBS_RESUME" -or
        [string]$Control.child_environment_mode -cne "EXPLICIT_ALLOWLIST_NO_INHERITANCE" -or
        [string]$Control.watchdog.job_name -cne [string]$Control.job_object_name -or
        [long]$Control.watchdog.monotonic_frequency -ne [Diagnostics.Stopwatch]::Frequency -or
        [uint64]$Control.launch_skew_ms -gt [uint64]$Control.maximum_dual_launch_skew_ms) {
        throw "Startup/control semantic policy or watchdog/launch-skew contract is invalid."
    }
    return $true
}

function Assert-MonitorStartupOnlyJsonTypes {
    param([Parameter(Mandatory = $true)] $Startup)
    # The existing validator intentionally couples startup and process-control.
    # A FAILED launcher can durably publish startup before processes.json exists,
    # so use a fully typed local sentinel only to exercise every startup branch.
    # No sentinel value is compared with evidence or returned as authority.
    $zeroDigest = "0" * 64
    $dummyJobName = "Local\BinanceRawQualificationJob-" + [string]$Startup.run_id
    $dummyWorkloadJobName = "Local\BinanceRawQualificationWorkloadJob-" + [string]$Startup.run_id
    $dummyControl = [pscustomobject][ordered]@{
        schema = "RawQualificationProcessControlV2"
        run_id = [string]$Startup.run_id
        job_object_name = $dummyJobName
        job_kill_on_close = $true
        workload_job_object_name = $dummyWorkloadJobName
        workload_job_kill_on_close = $true
        launch_method = "CREATE_SUSPENDED_ASSIGN_OUTER_AND_WORKLOAD_JOBS_RESUME"
        child_environment_mode = "EXPLICIT_ALLOWLIST_NO_INHERITANCE"
        child_environment_names = [object[]]@("SystemDrive", "SystemRoot", "TEMP", "TMP", "WINDIR")
        child_environment_entries_sha256 = $zeroDigest
        capture_origin_monotonic_tick = [uint64]1
        launch_skew_ticks = [uint64]0
        launch_skew_ms = [uint64]0
        maximum_dual_launch_skew_ms = [uint64]5000
        watchdog = [pscustomobject][ordered]@{
            pid = [uint32]1
            job_name = $dummyJobName
            creation_time_utc = "1970-01-01T00:00:00.0000000Z"
            executable_path = "validator.exe"
            executable_sha256 = $zeroDigest
            command_line = "validator.exe"
            script_path = "validator.ps1"
            script_sha256 = $zeroDigest
            launch_origin_qpc_timestamp = [long]1
            resume_qpc_timestamp = [long]1
            monotonic_frequency = [long][Diagnostics.Stopwatch]::Frequency
            startup_deadline_s = [uint64]90
            guardian_pulse_file = "guardian-pulse.jsonl"
            maximum_guardian_pulse_age_s = [uint64]90
            ready_file = "watchdog-ready.json"
            ready_file_sha256 = $zeroDigest
            ready_observed_qpc_timestamp = [long]1
            ready_pulse_length = [uint64]1
            stdout_file = "watchdog.stdout.log"
            stderr_file = "watchdog.stderr.log"
        }
        processes = [object[]]@()
    }
    return Assert-MonitorStartupControlJsonTypes `
        -Startup $Startup `
        -Control $dummyControl `
        -RequireWriterContract
}

function Test-MonitorBoundedExecutionCausality {
    param(
        [Parameter(Mandatory = $true)] $StartupOriginQpcTimestamp,
        [Parameter(Mandatory = $true)] $ContainerEventMonotonicTick,
        [Parameter(Mandatory = $true)] $ResumeQpcTimestamp,
        [Parameter(Mandatory = $true)] $ElapsedQpcTicks,
        [Parameter(Mandatory = $true)] $ParentExitObservedQpcTimestamp,
        [Parameter(Mandatory = $true)] $DescendantDrainElapsedQpcTicks
    )
    $signedMaximum = [decimal][long]::MaxValue
    $unsignedMaximum = [decimal][uint64]::MaxValue
    if (-not (Test-RawQualificationJsonInteger $StartupOriginQpcTimestamp 1 $signedMaximum) -or
        -not (Test-RawQualificationJsonInteger $ContainerEventMonotonicTick 0 $unsignedMaximum) -or
        -not (Test-RawQualificationJsonInteger $ResumeQpcTimestamp 1 $signedMaximum) -or
        -not (Test-RawQualificationJsonInteger $ElapsedQpcTicks 0 $signedMaximum) -or
        -not (Test-RawQualificationJsonInteger $ParentExitObservedQpcTimestamp 1 $signedMaximum) -or
        -not (Test-RawQualificationJsonInteger $DescendantDrainElapsedQpcTicks 0 $signedMaximum)) {
        return $false
    }
    $origin = [decimal]$StartupOriginQpcTimestamp
    $containerEnd = $origin + [decimal]$ContainerEventMonotonicTick
    $resume = [decimal]$ResumeQpcTimestamp
    $elapsed = [decimal]$ElapsedQpcTicks
    $parent = [decimal]$ParentExitObservedQpcTimestamp
    $drain = [decimal]$DescendantDrainElapsedQpcTicks
    return $resume -ge $origin -and $parent -ge $resume -and
        ($parent - $resume) -eq $elapsed -and
        ($parent + $drain) -le $containerEnd -and
        $containerEnd -le [decimal][long]::MaxValue
}

function Test-MonitorVerifierExecutionCausality {
    param(
        [Parameter(Mandatory = $true)] $StartupOriginQpcTimestamp,
        [Parameter(Mandatory = $true)] $BudgetComputedMonotonicTick,
        [Parameter(Mandatory = $true)] $StartEventMonotonicTick,
        [Parameter(Mandatory = $true)] $CompletedEventMonotonicTick,
        [Parameter(Mandatory = $true)] $ResumeQpcTimestamp,
        [Parameter(Mandatory = $true)] $ElapsedQpcTicks,
        [Parameter(Mandatory = $true)] $ParentExitObservedQpcTimestamp,
        [Parameter(Mandatory = $true)] $DescendantDrainElapsedQpcTicks,
        $PreviousCompletedAbsoluteQpcTimestamp = $null
    )
    $signed = [decimal][long]::MaxValue
    $unsigned = [decimal][uint64]::MaxValue
    foreach ($entry in @(
        [pscustomobject]@{ value = $StartupOriginQpcTimestamp; min = 1; max = $signed },
        [pscustomobject]@{ value = $BudgetComputedMonotonicTick; min = 0; max = $unsigned },
        [pscustomobject]@{ value = $StartEventMonotonicTick; min = 0; max = $unsigned },
        [pscustomobject]@{ value = $CompletedEventMonotonicTick; min = 0; max = $unsigned },
        [pscustomobject]@{ value = $ResumeQpcTimestamp; min = 1; max = $signed },
        [pscustomobject]@{ value = $ElapsedQpcTicks; min = 0; max = $signed },
        [pscustomobject]@{ value = $ParentExitObservedQpcTimestamp; min = 1; max = $signed },
        [pscustomobject]@{ value = $DescendantDrainElapsedQpcTicks; min = 0; max = $signed })) {
        if (-not (Test-RawQualificationJsonInteger $entry.value $entry.min $entry.max)) { return $false }
    }
    if ($null -ne $PreviousCompletedAbsoluteQpcTimestamp -and
        -not (Test-RawQualificationJsonInteger $PreviousCompletedAbsoluteQpcTimestamp 1 $signed)) {
        return $false
    }
    $origin = [decimal]$StartupOriginQpcTimestamp
    $budgetAbsolute = $origin + [decimal]$BudgetComputedMonotonicTick
    $startAbsolute = $origin + [decimal]$StartEventMonotonicTick
    $completeAbsolute = $origin + [decimal]$CompletedEventMonotonicTick
    $resume = [decimal]$ResumeQpcTimestamp
    $elapsed = [decimal]$ElapsedQpcTicks
    $parent = [decimal]$ParentExitObservedQpcTimestamp
    $drain = [decimal]$DescendantDrainElapsedQpcTicks
    if ($budgetAbsolute -gt $signed -or $startAbsolute -gt $signed -or $completeAbsolute -gt $signed) { return $false }
    if ($budgetAbsolute -gt $resume -or $resume -gt $startAbsolute -or $startAbsolute -gt $parent -or
        $parent -lt $resume -or ($parent - $resume) -ne $elapsed -or
        ($parent + $drain) -gt $completeAbsolute) {
        return $false
    }
    if ($null -ne $PreviousCompletedAbsoluteQpcTimestamp -and
        ($budgetAbsolute -lt [decimal]$PreviousCompletedAbsoluteQpcTimestamp -or
         $resume -lt [decimal]$PreviousCompletedAbsoluteQpcTimestamp)) {
        return $false
    }
    return $true
}

function Assert-MonitorProviderExecutionJsonTypes {
    param([Parameter(Mandatory = $true)] $Execution)
    $signed = [decimal][long]::MaxValue
    $unsigned = [decimal][uint64]::MaxValue
    $u32 = [decimal][uint32]::MaxValue
    if (-not (Test-MonitorExactJsonProperties -Value $Execution -Expected @(
                "command_line_sha256", "descendant_drain_active_processes",
                "descendant_drain_elapsed_ms", "descendant_drain_elapsed_qpc_ticks",
                "elapsed_ms", "elapsed_qpc_ticks", "job_membership", "monotonic_frequency",
                "parent_exit_observed_qpc_timestamp", "pid", "resume_qpc_timestamp",
                "stderr_bytes", "stderr_sha256", "stdout_bytes", "stdout_sha256", "timeout_s")) -or
        -not (Test-RawQualificationJsonInteger $Execution.pid 1 $u32) -or
        -not (Test-RawQualificationJsonSha256 $Execution.command_line_sha256) -or
        -not (Test-RawQualificationJsonInteger $Execution.resume_qpc_timestamp 1 $signed) -or
        -not (Test-RawQualificationJsonInteger $Execution.elapsed_qpc_ticks 0 $signed) -or
        -not (Test-RawQualificationJsonInteger $Execution.monotonic_frequency 1 $signed) -or
        -not (Test-RawQualificationJsonString $Execution.job_membership) -or
        -not (Test-RawQualificationJsonInteger $Execution.parent_exit_observed_qpc_timestamp 1 $signed) -or
        -not (Test-RawQualificationJsonInteger $Execution.descendant_drain_elapsed_qpc_ticks 0 $signed) -or
        -not (Test-RawQualificationJsonInteger $Execution.descendant_drain_elapsed_ms 0 $unsigned) -or
        -not (Test-RawQualificationJsonInteger $Execution.descendant_drain_active_processes 0 0) -or
        -not (Test-RawQualificationJsonInteger $Execution.timeout_s 1 604920) -or
        -not (Test-RawQualificationJsonInteger $Execution.elapsed_ms 0 $unsigned) -or
        -not (Test-RawQualificationJsonInteger $Execution.stdout_bytes 1 $unsigned) -or
        -not (Test-RawQualificationJsonSha256 $Execution.stdout_sha256) -or
        -not (Test-RawQualificationJsonInteger $Execution.stderr_bytes 0 0) -or
        -not (Test-RawQualificationJsonSha256 $Execution.stderr_sha256)) {
        throw "Host provider execution JSON contract is untyped, out of range, or has an unexpected property set."
    }
    return $true
}

function Assert-MonitorPostCreateProbeJsonTypes {
    param([Parameter(Mandatory = $true)] $Value)
    $signed = [decimal][long]::MaxValue
    $unsigned = [decimal][uint64]::MaxValue
    $u32 = [decimal][uint32]::MaxValue
    if (-not (Test-MonitorExactJsonProperties -Value $Value -Expected @(
                "filesystem", "free_gib", "probe_command_line_sha256",
                "probe_descendant_drain_active_processes", "probe_descendant_drain_elapsed_ms",
                "probe_descendant_drain_elapsed_qpc_ticks", "probe_elapsed_ms",
                "probe_elapsed_qpc_ticks", "probe_job_membership", "probe_monotonic_frequency",
                "probe_parent_exit_observed_qpc_timestamp", "probe_pid", "probe_resume_qpc_timestamp",
                "probe_stderr_bytes", "probe_stderr_file", "probe_stderr_sha256",
                "probe_stdout_bytes", "probe_stdout_file", "probe_stdout_sha256", "probe_timeout_s",
                "reparse_points_rejected", "required_free_gib", "run_root_drive_device_id",
                "same_preflight_volume")) -or
        -not (Test-RawQualificationJsonBoolean $Value.reparse_points_rejected) -or
        -not (Test-RawQualificationJsonString $Value.run_root_drive_device_id) -or
        -not (Test-RawQualificationJsonBoolean $Value.same_preflight_volume) -or
        -not (Test-RawQualificationJsonString $Value.filesystem) -or
        -not (Test-RawQualificationJsonInteger $Value.free_gib 0 $unsigned) -or
        -not (Test-RawQualificationJsonInteger $Value.required_free_gib 0 $unsigned) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_pid 1 $u32) -or
        -not (Test-RawQualificationJsonSha256 $Value.probe_command_line_sha256) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_resume_qpc_timestamp 1 $signed) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_elapsed_qpc_ticks 0 $signed) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_monotonic_frequency 1 $signed) -or
        -not (Test-RawQualificationJsonString $Value.probe_job_membership) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_parent_exit_observed_qpc_timestamp 1 $signed) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_descendant_drain_elapsed_qpc_ticks 0 $signed) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_descendant_drain_elapsed_ms 0 $unsigned) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_descendant_drain_active_processes 0 0) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_timeout_s 1 604920) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_elapsed_ms 0 $unsigned) -or
        -not (Test-RawQualificationJsonString $Value.probe_stdout_file) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_stdout_bytes 1 $unsigned) -or
        -not (Test-RawQualificationJsonSha256 $Value.probe_stdout_sha256) -or
        -not (Test-RawQualificationJsonString $Value.probe_stderr_file) -or
        -not (Test-RawQualificationJsonInteger $Value.probe_stderr_bytes 0 0) -or
        -not (Test-RawQualificationJsonSha256 $Value.probe_stderr_sha256)) {
        throw "Post-create probe JSON contract is untyped, out of range, or has an unexpected property set."
    }
    return $true
}

function Assert-MonitorTelemetryProbePayloadJsonTypes {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)] [uint32] $ExpectedRootProcessId,
        [switch] $ConflictScanExpected
    )
    if (-not (Test-MonitorExactJsonPropertyOrder $Value @(
                "schema", "clock", "disk", "network", "collector_processes",
                "conflicting_collectors", "power")) -or
        -not (Test-RawQualificationJsonString $Value.schema) -or
        [string]$Value.schema -cne "RawQualificationTelemetryProbeV1" -or
        $Value.collector_processes -isnot [System.Array] -or
        $Value.conflicting_collectors -isnot [System.Array] -or
        -not (Test-MonitorExactJsonPropertyOrder $Value.power @(
                "powercfg_exit_code", "ac_sleep_disabled"))) {
        throw "Telemetry probe has an unexpected top-level/nested writer contract."
    }
    $null = Assert-MonitorClockJsonTypes $Value.clock
    $null = Assert-MonitorDiskJsonTypes $Value.disk
    $null = Assert-MonitorNetworkJsonTypes $Value.network
    $observedRoot = $false
    foreach ($process in @($Value.collector_processes)) {
        $null = Assert-MonitorCollectorProcessJsonTypes $process
        if ([uint32]$process.pid -eq $ExpectedRootProcessId) { $observedRoot = $true }
    }
    if (-not $observedRoot) { throw "Telemetry probe did not bind the requested root process identity." }
    foreach ($conflict in @($Value.conflicting_collectors)) {
        if (-not (Test-MonitorExactJsonPropertyOrder $conflict @(
                    "pid", "name", "executable_path", "command_line")) -or
            -not (Test-RawQualificationJsonInteger $conflict.pid 1 ([decimal][uint32]::MaxValue)) -or
            -not (Test-RawQualificationJsonString $conflict.name) -or
            -not (Test-MonitorJsonNullOrString $conflict.executable_path) -or
            -not (Test-MonitorJsonNullOrString $conflict.command_line)) {
            throw "Telemetry probe conflicting collector record is untyped or structurally invalid."
        }
    }
    if ($ConflictScanExpected) {
        if (-not (Test-RawQualificationJsonInteger $Value.power.powercfg_exit_code 0 ([decimal][int]::MaxValue)) -or
            -not (Test-RawQualificationJsonBoolean $Value.power.ac_sleep_disabled)) {
            throw "Telemetry probe power proof is missing despite an explicit conflict/power scan."
        }
    }
    elseif ($null -ne $Value.power.powercfg_exit_code -or $null -ne $Value.power.ac_sleep_disabled) {
        throw "Post-create probe unexpectedly claims a powercfg result without the scan switch."
    }
    return $true
}

function Assert-MonitorSealedVerifierJsonTypes {
    param(
        [Parameter(Mandatory = $true)] $Verifier,
        [Parameter(Mandatory = $true)] $Execution
    )
    $signed = [decimal][long]::MaxValue
    $unsigned = [decimal][uint64]::MaxValue
    $u32 = [decimal][uint32]::MaxValue
    if (-not (Test-MonitorExactJsonProperties -Value $Verifier -Expected @(
                "command_line_sha256", "creation_time_utc", "descendant_drain_elapsed_ms",
                "descendant_drain_elapsed_qpc_ticks", "elapsed_ms", "elapsed_qpc_ticks", "execution_file",
                "execution_sha256", "exit_code", "global_budget_computed_monotonic_tick",
                "monotonic_frequency", "name", "parent_exit_observed_qpc_timestamp", "pid",
                "report_bytes", "report_file", "report_sha256", "resume_qpc_timestamp",
                "stderr_bytes", "stderr_file", "stderr_sha256", "stdout_bytes", "stdout_file",
                "stdout_sha256")) -or
        -not (Test-MonitorExactJsonProperties -Value $Execution -Expected @(
                "command_line", "creation_time_utc", "descendant_drain_elapsed_ms",
                "descendant_drain_elapsed_qpc_ticks", "elapsed_ms", "elapsed_qpc_ticks",
                "executable_path", "executable_sha256", "exit_code", "failure",
                "global_budget_computed_monotonic_tick", "monotonic_frequency", "name",
                "parent_exit_observed_qpc_timestamp", "pid", "report_bytes", "report_file",
                "report_present", "report_sha256", "resume_qpc_timestamp", "schema",
                "stderr_bytes", "stderr_file", "stderr_sha256", "stdout_bytes", "stdout_file",
                "stdout_sha256", "timed_out", "timeout_s"))) {
        throw "Sealed verifier object/execution has an unexpected property set."
    }
    foreach ($value in @($Verifier.name, $Verifier.creation_time_utc, $Verifier.execution_file,
            $Verifier.report_file, $Verifier.stdout_file, $Verifier.stderr_file,
            $Execution.schema, $Execution.name, $Execution.creation_time_utc,
            $Execution.executable_path, $Execution.command_line, $Execution.stdout_file,
            $Execution.stderr_file, $Execution.report_file)) {
        if (-not (Test-RawQualificationJsonString $value)) { throw "Sealed verifier contains a non-string JSON identity/path field." }
    }
    foreach ($digest in @($Verifier.command_line_sha256, $Verifier.execution_sha256,
            $Verifier.report_sha256, $Verifier.stdout_sha256, $Verifier.stderr_sha256,
            $Execution.executable_sha256, $Execution.stdout_sha256,
            $Execution.stderr_sha256, $Execution.report_sha256)) {
        if (-not (Test-RawQualificationJsonSha256 $digest)) { throw "Sealed verifier contains a malformed/non-string SHA-256." }
    }
    foreach ($entry in @(
        [pscustomobject]@{ value=$Verifier.pid; min=1; max=$u32 },
        [pscustomobject]@{ value=$Verifier.global_budget_computed_monotonic_tick; min=0; max=$unsigned },
        [pscustomobject]@{ value=$Verifier.resume_qpc_timestamp; min=1; max=$signed },
        [pscustomobject]@{ value=$Verifier.elapsed_qpc_ticks; min=0; max=$signed },
        [pscustomobject]@{ value=$Verifier.monotonic_frequency; min=1; max=$signed },
        [pscustomobject]@{ value=$Verifier.parent_exit_observed_qpc_timestamp; min=1; max=$signed },
        [pscustomobject]@{ value=$Verifier.descendant_drain_elapsed_qpc_ticks; min=0; max=$signed },
        [pscustomobject]@{ value=$Verifier.descendant_drain_elapsed_ms; min=0; max=$unsigned },
        [pscustomobject]@{ value=$Verifier.elapsed_ms; min=0; max=$unsigned },
        [pscustomobject]@{ value=$Verifier.report_bytes; min=1; max=$unsigned },
        [pscustomobject]@{ value=$Verifier.stdout_bytes; min=0; max=$unsigned },
        [pscustomobject]@{ value=$Verifier.stderr_bytes; min=0; max=0 },
        [pscustomobject]@{ value=$Verifier.exit_code; min=0; max=0 },
        [pscustomobject]@{ value=$Execution.pid; min=1; max=$u32 },
        [pscustomobject]@{ value=$Execution.global_budget_computed_monotonic_tick; min=0; max=$unsigned },
        [pscustomobject]@{ value=$Execution.resume_qpc_timestamp; min=1; max=$signed },
        [pscustomobject]@{ value=$Execution.elapsed_qpc_ticks; min=0; max=$signed },
        [pscustomobject]@{ value=$Execution.monotonic_frequency; min=1; max=$signed },
        [pscustomobject]@{ value=$Execution.parent_exit_observed_qpc_timestamp; min=1; max=$signed },
        [pscustomobject]@{ value=$Execution.descendant_drain_elapsed_qpc_ticks; min=0; max=$signed },
        [pscustomobject]@{ value=$Execution.descendant_drain_elapsed_ms; min=0; max=$unsigned },
        [pscustomobject]@{ value=$Execution.timeout_s; min=1; max=604920 },
        [pscustomobject]@{ value=$Execution.elapsed_ms; min=0; max=$unsigned },
        [pscustomobject]@{ value=$Execution.exit_code; min=0; max=0 },
        [pscustomobject]@{ value=$Execution.stdout_bytes; min=0; max=$unsigned },
        [pscustomobject]@{ value=$Execution.stderr_bytes; min=0; max=0 },
        [pscustomobject]@{ value=$Execution.report_bytes; min=1; max=$unsigned })) {
        if (-not (Test-RawQualificationJsonInteger $entry.value $entry.min $entry.max)) {
            throw "Sealed verifier contains an untyped or out-of-range JSON integer."
        }
    }
    if (-not (Test-RawQualificationJsonBoolean $Execution.timed_out) -or [bool]$Execution.timed_out -or
        -not (Test-RawQualificationJsonBoolean $Execution.report_present) -or -not [bool]$Execution.report_present -or
        $null -ne $Execution.failure) {
        throw "Sealed verifier boolean/failure terminal contract is invalid."
    }
    return $true
}

function Assert-MonitorTerminalWatchdogJsonTypes {
    param([Parameter(Mandatory = $true)] $Value)
    $signed = [decimal][long]::MaxValue
    $unsigned = [decimal][uint64]::MaxValue
    if (-not (Test-MonitorExactJsonPropertyOrder -Value $Value -Expected @(
                "pid", "exit_code", "stop_file", "stop_file_sha256", "stop_request_qpc_timestamp",
                "exit_elapsed_qpc_ticks", "final_job_drain_elapsed_qpc_ticks", "monotonic_frequency",
                "elapsed_ms", "final_job_drain_elapsed_ms", "stdout_file", "stdout_bytes", "stdout_sha256",
                "stderr_file", "stderr_bytes", "stderr_sha256", "final_job_active_processes")) -or
        -not (Test-RawQualificationJsonInteger $Value.pid 1 ([decimal][uint32]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $Value.exit_code 0 0) -or
        -not (Test-RawQualificationJsonString $Value.stop_file) -or
        -not (Test-RawQualificationJsonSha256 $Value.stop_file_sha256) -or
        -not (Test-RawQualificationJsonInteger $Value.stop_request_qpc_timestamp 1 $signed) -or
        -not (Test-RawQualificationJsonInteger $Value.exit_elapsed_qpc_ticks 0 $signed) -or
        -not (Test-RawQualificationJsonInteger $Value.final_job_drain_elapsed_qpc_ticks 0 $signed) -or
        -not (Test-RawQualificationJsonInteger $Value.monotonic_frequency 1 $signed) -or
        -not (Test-RawQualificationJsonInteger $Value.elapsed_ms 0 $unsigned) -or
        -not (Test-RawQualificationJsonInteger $Value.final_job_drain_elapsed_ms 0 $unsigned) -or
        -not (Test-RawQualificationJsonString $Value.stdout_file) -or
        -not (Test-RawQualificationJsonInteger $Value.stdout_bytes 0 0) -or
        -not (Test-RawQualificationJsonSha256 $Value.stdout_sha256) -or
        -not (Test-RawQualificationJsonString $Value.stderr_file) -or
        -not (Test-RawQualificationJsonInteger $Value.stderr_bytes 0 0) -or
        -not (Test-RawQualificationJsonSha256 $Value.stderr_sha256) -or
        -not (Test-RawQualificationJsonInteger $Value.final_job_active_processes 0 0)) {
        throw "Terminal watchdog JSON contract is untyped, out of range, or has an unexpected property set."
    }
    return $true
}

function Assert-MonitorTerminalCampaignJsonTypes {
    param([Parameter(Mandatory = $true)] $Campaign)
    $u64 = [decimal][uint64]::MaxValue
    $u32 = [decimal][uint32]::MaxValue
    foreach ($value in @($Campaign.symbol, $Campaign.campaign_id, $Campaign.campaign_directory,
            $Campaign.campaign_journal_boundary, $Campaign.generation_schedule_classification,
            $Campaign.stdout_file, $Campaign.stderr_file)) {
        if (-not (Test-RawQualificationJsonString $value)) {
            throw "Terminal campaign contains a non-string identity/path/classification field."
        }
    }
    foreach ($digest in @($Campaign.campaign_manifest_sha256,
            $Campaign.campaign_journal_precommit_sha256, $Campaign.campaign_journal_terminal_sha256,
            $Campaign.rust_verification_sha256, $Campaign.python_verification_sha256,
            $Campaign.stdout_file_sha256, $Campaign.stderr_file_sha256)) {
        if (-not (Test-RawQualificationJsonSha256 $digest)) {
            throw "Terminal campaign contains a malformed/non-string SHA-256."
        }
    }
    foreach ($entry in @(
            [pscustomobject]@{v=$Campaign.pid;min=1;max=$u32},
            [pscustomobject]@{v=$Campaign.exit_code;min=0;max=0},
            [pscustomobject]@{v=$Campaign.exit_elapsed_s;min=0;max=$u64},
            [pscustomobject]@{v=$Campaign.coordinator_exit_elapsed_s;min=0;max=$u64},
            [pscustomobject]@{v=$Campaign.campaign_journal_precommit_records;min=1;max=$u64},
            [pscustomobject]@{v=$Campaign.campaign_journal_committed_records;min=1;max=$u64},
            [pscustomobject]@{v=$Campaign.generations;min=1;max=$u64},
            [pscustomobject]@{v=$Campaign.handovers;min=0;max=$u64},
            [pscustomobject]@{v=$Campaign.unambiguous_clock_telemetry_records;min=1;max=$u64},
            [pscustomobject]@{v=$Campaign.planned_generation_launches;min=0;max=$u64},
            [pscustomobject]@{v=$Campaign.server_shutdown_generation_launches;min=0;max=$u64},
            [pscustomobject]@{v=$Campaign.server_shutdown_supervisor_events;min=0;max=$u64},
            [pscustomobject]@{v=$Campaign.server_shutdown_durable_events;min=0;max=$u64},
            [pscustomobject]@{v=$Campaign.child_stderr_events;min=0;max=0},
            [pscustomobject]@{v=$Campaign.stdout_file_bytes;min=0;max=$u64},
            [pscustomobject]@{v=$Campaign.stderr_file_bytes;min=0;max=0})) {
        if (-not (Test-RawQualificationJsonInteger $entry.v $entry.min $entry.max)) {
            throw "Terminal campaign contains an untyped/out-of-range integer."
        }
    }
    if ($Campaign.independent_verifiers -isnot [System.Array] -or
        @($Campaign.independent_verifiers).Count -ne 2 -or
        [string]$Campaign.campaign_journal_boundary -cne "PRECOMMIT_PREFIX" -or
        [uint64]$Campaign.campaign_journal_precommit_records + [uint64]1 -ne
            [uint64]$Campaign.campaign_journal_committed_records -or
        @("PLANNED_TWO_GENERATION", "PLANNED_CONTINUOUS_SEVEN_DAY", "DEVIATED", "NON_PRODUCTION_SCHEDULE") -cnotcontains
            [string]$Campaign.generation_schedule_classification) {
        throw "Terminal campaign array/boundary/schedule contract is invalid."
    }
    return $true
}

function Assert-MonitorTerminalRecursiveJsonTypes {
    param([Parameter(Mandatory = $true)] $Terminal)
    $u64 = [decimal][uint64]::MaxValue
    foreach ($name in @("watchdog_startup_deadline_s", "watchdog_deadline_s",
            "host_telemetry_gap_deadline_s", "maximum_dual_launch_skew_ms",
            "generation_terminal_deadline_s", "campaign_commit_deadline_s")) {
        if (-not (Test-RawQualificationJsonInteger $Terminal.guardian_policy.PSObject.Properties[$name].Value 0 $u64)) {
            throw "Terminal guardian policy contains an untyped/out-of-range integer: $name"
        }
    }
    foreach ($name in @("pulse_file", "watchdog_ready_file")) {
        if (-not (Test-RawQualificationJsonString $Terminal.guardian_policy.PSObject.Properties[$name].Value)) {
            throw "Terminal guardian policy contains a non-string path: $name"
        }
    }
    foreach ($container in @($Terminal.artifact_hashes_preflight, $Terminal.artifact_hashes_terminal)) {
        foreach ($property in $container.PSObject.Properties) {
            if ($null -ne $property.Value -and -not (Test-RawQualificationJsonSha256 $property.Value)) {
                throw "Terminal artifact provenance contains a malformed/non-string digest: $($property.Name)"
            }
        }
    }
    foreach ($campaign in @($Terminal.campaigns)) {
        $null = Assert-MonitorTerminalCampaignJsonTypes -Campaign $campaign
    }
    return $true
}

function Assert-MonitorBindingsWriterOrder {
    param([Parameter(Mandatory = $true)] $Bindings)
    if (-not (Test-MonitorExactJsonPropertyOrder $Bindings @("schema", "run_id", "bound_utc", "campaigns"))) {
        throw "Campaign bindings differ from the exact ordered PowerShell writer contract."
    }
    foreach ($campaign in @($Bindings.campaigns)) {
        if (-not (Test-MonitorExactJsonPropertyOrder $campaign @(
                    "symbol", "pid", "campaign_id", "campaign_directory", "campaign_startup_sha256"))) {
            throw "A campaign binding differs from the exact ordered PowerShell writer contract."
        }
        if (-not (Test-RawQualificationJsonString $campaign.symbol) -or
            -not (Test-RawQualificationJsonInteger $campaign.pid 1 ([decimal][uint32]::MaxValue)) -or
            -not (Test-RawQualificationJsonString $campaign.campaign_id) -or
            -not (Test-RawQualificationJsonString $campaign.campaign_directory) -or
            -not (Test-RawQualificationJsonSha256 $campaign.campaign_startup_sha256)) {
            throw "A campaign binding contains an untyped/coercible PID, identity, path, or digest."
        }
    }
    if (-not (Test-RawQualificationJsonString $Bindings.schema) -or
        [string]$Bindings.schema -cne "RawQualificationCampaignBindingsV1" -or
        -not (Test-RawQualificationJsonString $Bindings.run_id) -or
        -not (Test-RawQualificationJsonString $Bindings.bound_utc) -or
        $Bindings.campaigns -isnot [System.Array]) {
        throw "Campaign bindings top-level JSON contract is invalid."
    }
    return $true
}

function Assert-MonitorTerminalWriterOrder {
    param([Parameter(Mandatory = $true)] $Terminal)
    if (-not (Test-MonitorExactJsonPropertyOrder $Terminal @(
                "schema", "status", "failure", "failure_containment", "failure_containment_sha256",
                "run_id", "mode", "run_root", "finished_utc",
                "launcher_elapsed_ms", "capture_elapsed_ms", "parameters", "verifier_policy",
                "coordinator_log_policy", "market_freshness_policy", "guardian_policy", "startup_sha256",
                "process_control_sha256", "campaign_bindings_sha256", "launcher_events", "host_telemetry",
                "guardian_pulse", "artifact_hashes_preflight", "artifact_hashes_terminal", "watchdog",
                "campaigns", "credentials", "order_entry")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Terminal.parameters @("total_s", "rotation_s", "overlap_s", "segment_s")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Terminal.verifier_policy @(
                "per_process_timeout_s", "total_post_capture_timeout_s", "maximum_artifact_bytes")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Terminal.coordinator_log_policy @(
                "maximum_stdout_bytes", "maximum_stderr_bytes", "child_stderr_events_allowed")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Terminal.market_freshness_policy @("startup_grace_s", "deadline_s")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Terminal.guardian_policy @(
                "pulse_file", "watchdog_ready_file", "watchdog_startup_deadline_s", "watchdog_deadline_s",
                "host_telemetry_gap_deadline_s", "maximum_dual_launch_skew_ms",
                "generation_terminal_deadline_s", "campaign_commit_deadline_s"))) {
        throw "Terminal manifest differs from the exact ordered PowerShell writer contract."
    }
    if ($null -ne $Terminal.launcher_events -and -not (Test-MonitorExactJsonPropertyOrder $Terminal.launcher_events @(
                "file", "records", "terminal_record_sha256", "file_bytes", "file_sha256"))) {
        throw "Terminal launcher-journal prefix receipt differs from the exact ordered PowerShell writer contract."
    }
    foreach ($journal in @($Terminal.host_telemetry, $Terminal.guardian_pulse)) {
        if ($null -ne $journal -and -not (Test-MonitorExactJsonPropertyOrder $journal @(
                    "file", "records", "terminal_record_sha256", "file_sha256"))) {
            throw "Terminal journal receipt differs from the exact ordered PowerShell writer contract."
        }
    }
    $artifactOrder = @(
        "campaign_executable_sha256", "capture_executable_sha256", "campaign_verifier_executable_sha256",
        "public_config_sha256", "source_lock_sha256", "launcher_script_sha256", "monitor_script_sha256",
        "helper_script_sha256", "telemetry_probe_script_sha256", "watchdog_script_sha256",
        "python_runtime_fingerprint_script_sha256", "powershell_executable_sha256",
        "python_executable_sha256", "python_verifier_source_tree_sha256", "python_runtime_tree_sha256",
        "python_pyvenv_config_sha256", "python_base_executable_sha256", "python_project_sha256",
        "python_requirements_sha256")
    $terminalArtifactOrder = [Collections.Generic.List[string]]::new()
    foreach ($name in $artifactOrder) {
        $terminalArtifactOrder.Add($name)
        if ($name -ceq "watchdog_script_sha256") { $terminalArtifactOrder.Add("watchdog_ready_file_sha256") }
    }
    if (-not (Test-MonitorExactJsonPropertyOrder $Terminal.artifact_hashes_preflight $artifactOrder) -or
        -not (Test-MonitorExactJsonPropertyOrder $Terminal.artifact_hashes_terminal $terminalArtifactOrder.ToArray())) {
        throw "Terminal provenance digests differ from the exact ordered PowerShell writer contract."
    }
    foreach ($campaign in @($Terminal.campaigns)) {
        if (-not (Test-MonitorExactJsonPropertyOrder $campaign @(
                    "symbol", "pid", "exit_code", "exit_elapsed_s", "coordinator_exit_elapsed_s",
                    "campaign_id", "campaign_directory", "campaign_manifest_sha256",
                    "campaign_journal_boundary", "campaign_journal_precommit_records",
                    "campaign_journal_precommit_sha256", "campaign_journal_committed_records",
                    "campaign_journal_terminal_sha256", "generations", "handovers",
                    "unambiguous_clock_telemetry_records", "generation_schedule_classification",
                    "planned_generation_launches", "server_shutdown_generation_launches",
                    "server_shutdown_supervisor_events", "server_shutdown_durable_events", "child_stderr_events",
                    "rust_verification_sha256", "python_verification_sha256", "independent_verifiers",
                    "stdout_file", "stdout_file_bytes", "stdout_file_sha256", "stderr_file",
                    "stderr_file_bytes", "stderr_file_sha256"))) {
            throw "Terminal campaign differs from the exact ordered PowerShell writer contract."
        }
        foreach ($verifier in @($campaign.independent_verifiers)) {
            if (-not (Test-MonitorExactJsonPropertyOrder $verifier @(
                        "name", "pid", "creation_time_utc", "command_line_sha256",
                        "global_budget_computed_monotonic_tick", "resume_qpc_timestamp", "elapsed_qpc_ticks",
                        "monotonic_frequency", "parent_exit_observed_qpc_timestamp",
                        "descendant_drain_elapsed_qpc_ticks", "descendant_drain_elapsed_ms", "execution_file",
                        "execution_sha256", "report_file", "report_bytes", "report_sha256", "stdout_file",
                        "stdout_bytes", "stdout_sha256", "stderr_file", "stderr_bytes", "stderr_sha256",
                        "exit_code", "elapsed_ms"))) {
                throw "Terminal verifier receipt differs from the exact ordered PowerShell writer contract."
            }
        }
    }
    if ($null -ne $Terminal.watchdog) {
        $null = Assert-MonitorTerminalWatchdogJsonTypes -Value $Terminal.watchdog
    }
    return $true
}

function Assert-MonitorFailureContainmentJsonContract {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [AllowNull()] $ExpectedMonotonicFrequency = $null
    )
    $u32 = [decimal][uint32]::MaxValue
    $u64 = [decimal][uint64]::MaxValue
    if (-not (Test-MonitorExactJsonPropertyOrder $Value @(
                "schema", "job_name", "job_kill_on_close", "detected_wall_ns",
                "detected_monotonic_tick", "requested_exit_code", "initial_query_succeeded",
                "initial_active_processes", "initial_query_error", "terminate_attempted",
                "terminate_succeeded", "terminate_error", "termination_monotonic_tick",
                "monotonic_frequency", "drain_deadline_s", "drain_elapsed_qpc_ticks", "final_query_succeeded",
                "final_active_processes", "final_query_error", "result")) -or
        -not (Test-RawQualificationJsonString $Value.schema) -or
        [string]$Value.schema -cne "RawQualificationFailureContainmentV2" -or
        -not (Test-RawQualificationJsonString $Value.job_name) -or
        -not (Test-RawQualificationJsonBoolean $Value.job_kill_on_close) -or
        -not (Test-RawQualificationJsonInteger $Value.detected_wall_ns 1 $u64) -or
        -not (Test-RawQualificationJsonInteger $Value.detected_monotonic_tick 0 $u64) -or
        -not (Test-RawQualificationJsonInteger $Value.requested_exit_code 60930 60930) -or
        -not (Test-RawQualificationJsonBoolean $Value.initial_query_succeeded) -or
        -not (Test-MonitorJsonNullOrInteger $Value.initial_active_processes 0 $u32) -or
        -not (Test-MonitorJsonNullOrInteger $Value.initial_query_error 0 $u32) -or
        -not (Test-RawQualificationJsonBoolean $Value.terminate_attempted) -or
        ($null -ne $Value.terminate_succeeded -and -not (Test-RawQualificationJsonBoolean $Value.terminate_succeeded)) -or
        -not (Test-MonitorJsonNullOrInteger $Value.terminate_error 0 $u32) -or
        -not (Test-RawQualificationJsonInteger $Value.termination_monotonic_tick 0 $u64) -or
        -not (Test-RawQualificationJsonInteger $Value.monotonic_frequency 1 ([decimal][long]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $Value.drain_deadline_s 30 30) -or
        -not (Test-RawQualificationJsonInteger $Value.drain_elapsed_qpc_ticks 0 ([decimal][long]::MaxValue)) -or
        -not (Test-RawQualificationJsonBoolean $Value.final_query_succeeded) -or
        -not (Test-MonitorJsonNullOrInteger $Value.final_active_processes 0 $u32) -or
        -not (Test-MonitorJsonNullOrInteger $Value.final_query_error 0 $u32) -or
        -not (Test-RawQualificationJsonString $Value.result) -or
        @("DRAINED_BY_ATTEMPT", "DRAINED_CONCURRENT_OR_PREEXISTING",
          "UNCONFIRMED_QUERY_ERROR", "UNCONFIRMED_TIMEOUT", "NO_JOB_HANDLE") -cnotcontains [string]$Value.result) {
        throw "Failure containment JSON types/property order are invalid."
    }
    $monotonicFrequency = [long]$Value.monotonic_frequency
    if ($monotonicFrequency -ne [Diagnostics.Stopwatch]::Frequency -or
        ($null -ne $ExpectedMonotonicFrequency -and
            (-not (Test-RawQualificationJsonInteger $ExpectedMonotonicFrequency 1 ([decimal][long]::MaxValue)) -or
             [long]$ExpectedMonotonicFrequency -ne $monotonicFrequency)) -or
        [decimal]$Value.termination_monotonic_tick -lt [decimal]$Value.detected_monotonic_tick) {
        throw "Failure containment monotonic frequency/termination evidence is invalid."
    }
    $drainWithinDeadline = Test-RawQualificationDeadlineTicks `
        -ElapsedTicks ([long]$Value.drain_elapsed_qpc_ticks) `
        -TimeoutSeconds 30 `
        -Frequency $monotonicFrequency
    $initialSucceeded = [bool]$Value.initial_query_succeeded
    $attempted = [bool]$Value.terminate_attempted
    $finalSucceeded = [bool]$Value.final_query_succeeded
    if (($initialSucceeded -and ($null -eq $Value.initial_active_processes -or $null -ne $Value.initial_query_error)) -or
        (-not $initialSucceeded -and ($null -ne $Value.initial_active_processes -or $null -eq $Value.initial_query_error -or
            [uint32]$Value.initial_query_error -eq 0)) -or
        ($attempted -and $null -eq $Value.terminate_succeeded) -or
        (-not $attempted -and ($null -ne $Value.terminate_succeeded -or $null -ne $Value.terminate_error)) -or
        ($attempted -and [bool]$Value.terminate_succeeded -and $null -ne $Value.terminate_error) -or
        ($attempted -and -not [bool]$Value.terminate_succeeded -and
            ($null -eq $Value.terminate_error -or [uint32]$Value.terminate_error -eq 0)) -or
        ($finalSucceeded -and ($null -eq $Value.final_active_processes -or $null -ne $Value.final_query_error)) -or
        (-not $finalSucceeded -and ($null -ne $Value.final_active_processes -or $null -eq $Value.final_query_error -or
            [uint32]$Value.final_query_error -eq 0))) {
        throw "Failure containment nullable query/termination fields are incoherent."
    }
    switch -CaseSensitive ([string]$Value.result) {
        "NO_JOB_HANDLE" {
            if ([bool]$Value.job_kill_on_close -or $attempted -or $initialSucceeded -or $finalSucceeded -or
                [uint32]$Value.initial_query_error -ne 6 -or [uint32]$Value.final_query_error -ne 6) {
                throw "NO_JOB_HANDLE containment semantics are invalid."
            }
        }
        "DRAINED_BY_ATTEMPT" {
            if (-not [bool]$Value.job_kill_on_close -or -not $attempted -or
                -not [bool]$Value.terminate_succeeded -or -not $finalSucceeded -or
                [uint32]$Value.final_active_processes -ne 0 -or -not $drainWithinDeadline -or
                ($initialSucceeded -and [uint32]$Value.initial_active_processes -eq 0)) {
                throw "DRAINED_BY_ATTEMPT containment semantics are invalid."
            }
        }
        "DRAINED_CONCURRENT_OR_PREEXISTING" {
            if (-not [bool]$Value.job_kill_on_close -or -not $attempted -or
                -not $finalSucceeded -or [uint32]$Value.final_active_processes -ne 0 -or
                -not $drainWithinDeadline -or
                -not (($initialSucceeded -and [uint32]$Value.initial_active_processes -eq 0) -or
                      -not [bool]$Value.terminate_succeeded)) {
                throw "DRAINED_CONCURRENT_OR_PREEXISTING containment semantics are invalid."
            }
        }
        "UNCONFIRMED_QUERY_ERROR" {
            if (-not [bool]$Value.job_kill_on_close -or -not $attempted -or $finalSucceeded) {
                throw "UNCONFIRMED_QUERY_ERROR containment semantics are invalid."
            }
        }
        "UNCONFIRMED_TIMEOUT" {
            if (-not [bool]$Value.job_kill_on_close -or -not $attempted -or
                -not $finalSucceeded -or
                ($drainWithinDeadline -and [uint32]$Value.final_active_processes -eq 0)) {
                throw "UNCONFIRMED_TIMEOUT containment semantics are invalid."
            }
        }
    }
    return $true
}

function Assert-MonitorTerminalVerifierPolicyBinding {
    param(
        [Parameter(Mandatory = $true)] $Terminal,
        [Parameter(Mandatory = $true)] $Startup
    )
    if ([uint64]$Terminal.verifier_policy.per_process_timeout_s -ne
            [uint64]$Startup.verifier_policy.per_process_timeout_s -or
        [uint64]$Terminal.verifier_policy.total_post_capture_timeout_s -ne
            [uint64]$Startup.verifier_policy.total_post_capture_timeout_s -or
        [uint64]$Terminal.verifier_policy.maximum_artifact_bytes -ne
            [uint64]$Startup.verifier_policy.maximum_artifact_bytes) {
        throw "Terminal verifier policy does not bind the exact launcher startup policy."
    }
    return $true
}

function Assert-MonitorTerminalV2JsonContract {
    param(
        [Parameter(Mandatory = $true)] $Terminal,
        [AllowNull()] $ExpectedMonotonicFrequency = $null
    )
    $u64 = [decimal][uint64]::MaxValue
    foreach ($name in @("schema", "status", "run_id", "mode", "run_root", "finished_utc", "credentials", "order_entry")) {
        if (-not (Test-RawQualificationJsonString $Terminal.PSObject.Properties[$name].Value)) {
            throw "Terminal V2 has a non-string identity/policy field: $name"
        }
    }
    if ([string]$Terminal.schema -cne "RawQualificationLauncherTerminalV2" -or
        @("COMPLETE", "FAILED") -cnotcontains [string]$Terminal.status -or
        @("Production", "SevenDay", "Smoke", "Test") -cnotcontains [string]$Terminal.mode -or
        [string]::IsNullOrWhiteSpace([string]$Terminal.run_id) -or
        [string]::IsNullOrWhiteSpace([string]$Terminal.run_root) -or
        -not [IO.Path]::IsPathRooted([string]$Terminal.run_root) -or
        [string]::IsNullOrWhiteSpace([string]$Terminal.finished_utc) -or
        [string]$Terminal.credentials -cne "NONE" -or [string]$Terminal.order_entry -cne "ABSENT" -or
        -not (Test-RawQualificationJsonInteger $Terminal.launcher_elapsed_ms 0 $u64) -or
        -not (Test-MonitorJsonNullOrInteger $Terminal.capture_elapsed_ms 0 $u64) -or
        $Terminal.campaigns -isnot [System.Array]) {
        throw "Terminal V2 top-level JSON contract is invalid."
    }
    $finishedTimestamp = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            [string]$Terminal.finished_utc,
            "o",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$finishedTimestamp)) {
        throw "Terminal V2 finished_utc is not an exact round-trip timestamp."
    }
    foreach ($name in @("startup_sha256", "process_control_sha256", "campaign_bindings_sha256")) {
        $digest = $Terminal.PSObject.Properties[$name].Value
        if (([string]$Terminal.status -ceq "COMPLETE" -and -not (Test-RawQualificationJsonSha256 $digest)) -or
            ([string]$Terminal.status -ceq "FAILED" -and $null -ne $digest -and
                -not (Test-RawQualificationJsonSha256 $digest))) {
            throw "Terminal V2 has a malformed provenance digest: $name"
        }
    }
    foreach ($entry in @(
            [pscustomobject]@{v=$Terminal.parameters.total_s;min=1;max=604800},
            [pscustomobject]@{v=$Terminal.parameters.rotation_s;min=1;max=604800},
            [pscustomobject]@{v=$Terminal.parameters.overlap_s;min=1;max=604800},
            [pscustomobject]@{v=$Terminal.parameters.segment_s;min=1;max=604800},
            [pscustomobject]@{v=$Terminal.verifier_policy.per_process_timeout_s;min=1;max=604920},
            [pscustomobject]@{v=$Terminal.verifier_policy.total_post_capture_timeout_s;min=1;max=604920},
            [pscustomobject]@{v=$Terminal.verifier_policy.maximum_artifact_bytes;min=1;max=$u64},
            [pscustomobject]@{v=$Terminal.coordinator_log_policy.maximum_stdout_bytes;min=1;max=$u64},
            [pscustomobject]@{v=$Terminal.coordinator_log_policy.maximum_stderr_bytes;min=0;max=0},
            [pscustomobject]@{v=$Terminal.coordinator_log_policy.child_stderr_events_allowed;min=0;max=0},
            [pscustomobject]@{v=$Terminal.market_freshness_policy.startup_grace_s;min=1;max=604920},
            [pscustomobject]@{v=$Terminal.market_freshness_policy.deadline_s;min=1;max=604920})) {
        if (-not (Test-RawQualificationJsonInteger $entry.v $entry.min $entry.max)) {
            throw "Terminal V2 contains an untyped/out-of-range policy integer."
        }
    }
    if ([uint64]$Terminal.parameters.total_s -lt [uint64]$Terminal.parameters.overlap_s -or
        [uint64]$Terminal.parameters.overlap_s -ne [uint64]$Terminal.parameters.segment_s -or
        ([uint64]$Terminal.parameters.rotation_s % [uint64]$Terminal.parameters.segment_s) -ne 0 -or
        ([uint64]$Terminal.parameters.rotation_s + [uint64]$Terminal.parameters.overlap_s) -gt 86300 -or
        ([string]$Terminal.mode -ceq "Production" -and
            ([uint64]$Terminal.parameters.total_s -ne 86400 -or
             [uint64]$Terminal.parameters.rotation_s -ne 82800 -or
             [uint64]$Terminal.parameters.overlap_s -ne 900 -or
             [uint64]$Terminal.parameters.segment_s -ne 900 -or
             [uint64]$Terminal.verifier_policy.per_process_timeout_s -ne 43200 -or
             [uint64]$Terminal.verifier_policy.total_post_capture_timeout_s -ne 86400)) -or
        ([string]$Terminal.mode -ceq "SevenDay" -and
            ([uint64]$Terminal.parameters.total_s -ne 604800 -or
             [uint64]$Terminal.parameters.rotation_s -ne 82800 -or
             [uint64]$Terminal.parameters.overlap_s -ne 900 -or
             [uint64]$Terminal.parameters.segment_s -ne 900 -or
             [uint64]$Terminal.verifier_policy.per_process_timeout_s -ne 43200 -or
             [uint64]$Terminal.verifier_policy.total_post_capture_timeout_s -ne 86400)) -or
        [uint64]$Terminal.verifier_policy.per_process_timeout_s -lt 60 -or
        [uint64]$Terminal.verifier_policy.per_process_timeout_s -gt 43200 -or
        [uint64]$Terminal.verifier_policy.total_post_capture_timeout_s -lt 300 -or
        [uint64]$Terminal.verifier_policy.total_post_capture_timeout_s -gt 86400 -or
        [uint64]$Terminal.verifier_policy.maximum_artifact_bytes -ne [uint64](32MB) -or
        [uint64]$Terminal.coordinator_log_policy.maximum_stdout_bytes -ne [uint64](64MB) -or
        [uint64]$Terminal.coordinator_log_policy.maximum_stderr_bytes -ne 0 -or
        [uint64]$Terminal.coordinator_log_policy.child_stderr_events_allowed -ne 0 -or
        [uint64]$Terminal.market_freshness_policy.startup_grace_s -ne
            [uint64]$ExpectedMarketFreshnessStartupGraceSeconds -or
        [uint64]$Terminal.market_freshness_policy.deadline_s -ne
            [uint64]$ExpectedMarketFreshnessDeadlineSeconds -or
        [string]$Terminal.guardian_policy.pulse_file -cne "guardian-pulse.jsonl" -or
        [string]$Terminal.guardian_policy.watchdog_ready_file -cne "watchdog-ready.json" -or
        [uint64]$Terminal.guardian_policy.watchdog_startup_deadline_s -ne
            [uint64]$ExpectedGuardianWatchdogStartupDeadlineSeconds -or
        [uint64]$Terminal.guardian_policy.watchdog_deadline_s -ne
            [uint64]$ExpectedGuardianWatchdogDeadlineSeconds -or
        [uint64]$Terminal.guardian_policy.host_telemetry_gap_deadline_s -ne
            [uint64]$ExpectedHostTelemetryGapDeadlineSeconds -or
        [uint64]$Terminal.guardian_policy.maximum_dual_launch_skew_ms -ne
            [uint64]$ExpectedMaximumDualLaunchSkewMilliseconds -or
        [uint64]$Terminal.guardian_policy.generation_terminal_deadline_s -ne
            [uint64]$ExpectedGenerationTerminalDeadlineSeconds -or
        [uint64]$Terminal.guardian_policy.campaign_commit_deadline_s -ne
            [uint64]$ExpectedCampaignCommitDeadlineSeconds) {
        throw "Terminal V2 parameters/policies violate the exact launcher contract."
    }
    if ($null -eq $Terminal.launcher_events -or
        -not (Test-RawQualificationJsonString $Terminal.launcher_events.file) -or
        [string]$Terminal.launcher_events.file -cne "launcher-events.jsonl" -or
        -not (Test-RawQualificationJsonInteger $Terminal.launcher_events.records 2 $u64) -or
        -not (Test-RawQualificationJsonSha256 $Terminal.launcher_events.terminal_record_sha256) -or
        -not (Test-RawQualificationJsonInteger $Terminal.launcher_events.file_bytes 1 $u64) -or
        -not (Test-RawQualificationJsonSha256 $Terminal.launcher_events.file_sha256)) {
        throw "Terminal V2 launcher-journal prefix receipt is untyped or malformed."
    }
    foreach ($receipt in @($Terminal.host_telemetry, $Terminal.guardian_pulse)) {
        if ($null -ne $receipt -and
            (-not (Test-RawQualificationJsonString $receipt.file) -or
             -not (Test-RawQualificationJsonInteger $receipt.records 0 $u64) -or
             -not (Test-RawQualificationJsonSha256 $receipt.terminal_record_sha256) -or
             -not (Test-RawQualificationJsonSha256 $receipt.file_sha256))) {
            throw "Terminal V2 host/guardian journal receipt is untyped or malformed."
        }
    }
    if ([string]$Terminal.status -ceq "COMPLETE") {
        if ($null -ne $Terminal.failure -or $null -ne $Terminal.failure_containment -or
            $null -ne $Terminal.failure_containment_sha256) {
            throw "Terminal V2 COMPLETE contains failure containment evidence."
        }
    }
    else {
        if (-not (Test-RawQualificationJsonString $Terminal.failure) -or
            [string]::IsNullOrWhiteSpace([string]$Terminal.failure) -or
            -not (Test-RawQualificationJsonSha256 $Terminal.failure_containment_sha256) -or
            $null -eq $Terminal.failure_containment) {
            throw "Terminal V2 FAILED lacks typed containment evidence."
        }
        $null = Assert-MonitorFailureContainmentJsonContract `
            -Value $Terminal.failure_containment `
            -ExpectedMonotonicFrequency $ExpectedMonotonicFrequency
        $compact = [Text.UTF8Encoding]::new($false).GetBytes(
            ($Terminal.failure_containment | ConvertTo-Json -Depth 100 -Compress))
        if ((Get-RawQualificationSha256Bytes -Bytes $compact) -cne [string]$Terminal.failure_containment_sha256) {
            throw "Terminal V2 FAILED containment digest does not bind the exact ordered object."
        }
        if ([string]$Terminal.failure_containment.job_name -cne
            ("Local\BinanceRawQualificationJob-" + [string]$Terminal.run_id)) {
            throw "Terminal V2 FAILED containment Job name is not derived from its exact run identity."
        }
    }
    $null = Assert-MonitorTerminalRecursiveJsonTypes -Terminal $Terminal
    return $true
}

function Assert-MonitorRustCampaignSingletonWriterOrder {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)] [ValidateSet("Startup", "Manifest")] [string] $Kind
    )
    if ($Kind -eq "Startup") {
        if (-not (Test-MonitorExactJsonPropertyOrder $Value @(
                    "schema", "campaign_id", "symbol", "total_duration_s", "rotation_s", "overlap_s",
                    "segment_s", "started_wall_ns", "process_id", "executable_sha256",
                    "capture_executable_sha256", "public_config_sha256", "spec_revision", "credentials",
                    "order_entry"))) {
            throw "Rust campaign startup differs from its exact serde struct field order."
        }
        return $true
    }
    if (-not (Test-MonitorExactJsonPropertyOrder $Value @(
                "schema", "status", "campaign_id", "symbol", "total_duration_s", "rotation_s", "overlap_s",
                "segment_s", "started_wall_ns", "finished_wall_ns", "spec_revision", "credentials",
                "order_entry", "executable_sha256", "capture_executable_sha256", "public_config_sha256",
                "startup_file", "startup_sha256", "journal_file", "journal_boundary",
                "journal_precommit_records", "journal_precommit_sha256", "supervisor_gap_count",
                "generations", "handovers"))) {
        throw "Rust campaign manifest differs from its exact serde struct field order."
    }
    foreach ($generation in @($Value.generations)) {
        if (-not (Test-MonitorExactJsonPropertyOrder $generation @(
                    "generation_index", "session_id", "session_dir", "verification_sha256", "evaluation_file",
                    "evaluation_file_sha256", "generation_manifest_sha256", "depth_records", "trade_records"))) {
            throw "Rust campaign generation differs from its exact serde struct field order."
        }
    }
    foreach ($handover in @($Value.handovers)) {
        if (-not (Test-MonitorExactJsonPropertyOrder $handover @(
                    "predecessor_generation_index", "successor_generation_index", "proof_sha256", "proof_file",
                    "proof_file_sha256"))) {
            throw "Rust campaign handover differs from its exact serde struct field order."
        }
    }
    return $true
}

function Assert-MonitorRustCampaignSingletonJsonTypes {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)] [ValidateSet("Startup", "Manifest")] [string] $Kind
    )
    $u64 = [decimal][uint64]::MaxValue
    if ($Kind -eq "Startup") {
        foreach ($name in @("schema", "campaign_id", "symbol", "spec_revision", "credentials", "order_entry")) {
            if (-not (Test-RawQualificationJsonString $Value.PSObject.Properties[$name].Value)) {
                throw "Rust campaign startup contains a non-string identity/policy field: $name"
            }
        }
        foreach ($name in @("executable_sha256", "capture_executable_sha256", "public_config_sha256")) {
            if (-not (Test-RawQualificationJsonSha256 $Value.PSObject.Properties[$name].Value)) {
                throw "Rust campaign startup contains a malformed/non-string digest: $name"
            }
        }
        foreach ($entry in @(
                [pscustomobject]@{n="total_duration_s";v=$Value.total_duration_s;min=1;max=604800},
                [pscustomobject]@{n="rotation_s";v=$Value.rotation_s;min=1;max=604800},
                [pscustomobject]@{n="overlap_s";v=$Value.overlap_s;min=1;max=604800},
                [pscustomobject]@{n="segment_s";v=$Value.segment_s;min=1;max=604800},
                [pscustomobject]@{n="started_wall_ns";v=$Value.started_wall_ns;min=1;max=$u64},
                [pscustomobject]@{n="process_id";v=$Value.process_id;min=1;max=([decimal][uint32]::MaxValue)})) {
            if (-not (Test-RawQualificationJsonInteger $entry.v $entry.min $entry.max)) {
                throw "Rust campaign startup contains an untyped/out-of-range integer: $($entry.n)"
            }
        }
        if ([string]$Value.schema -cne "RawCampaignStartupV1" -or
            [string]$Value.credentials -cne "NONE" -or [string]$Value.order_entry -cne "ABSENT") {
            throw "Rust campaign startup schema/credential/order-entry contract is invalid."
        }
        return $true
    }
    foreach ($name in @("schema", "status", "campaign_id", "symbol", "spec_revision", "credentials",
            "order_entry", "startup_file", "journal_file", "journal_boundary")) {
        if (-not (Test-RawQualificationJsonString $Value.PSObject.Properties[$name].Value)) {
            throw "Rust campaign manifest contains a non-string identity/path/policy field: $name"
        }
    }
    foreach ($name in @("executable_sha256", "capture_executable_sha256", "public_config_sha256",
            "startup_sha256", "journal_precommit_sha256")) {
        if (-not (Test-RawQualificationJsonSha256 $Value.PSObject.Properties[$name].Value)) {
            throw "Rust campaign manifest contains a malformed/non-string digest: $name"
        }
    }
    foreach ($entry in @(
            [pscustomobject]@{n="total_duration_s";v=$Value.total_duration_s;min=1;max=604800},
            [pscustomobject]@{n="rotation_s";v=$Value.rotation_s;min=1;max=604800},
            [pscustomobject]@{n="overlap_s";v=$Value.overlap_s;min=1;max=604800},
            [pscustomobject]@{n="segment_s";v=$Value.segment_s;min=1;max=604800},
            [pscustomobject]@{n="started_wall_ns";v=$Value.started_wall_ns;min=1;max=$u64},
            [pscustomobject]@{n="finished_wall_ns";v=$Value.finished_wall_ns;min=1;max=$u64},
            [pscustomobject]@{n="journal_precommit_records";v=$Value.journal_precommit_records;min=1;max=$u64},
            [pscustomobject]@{n="supervisor_gap_count";v=$Value.supervisor_gap_count;min=0;max=$u64})) {
        if (-not (Test-RawQualificationJsonInteger $entry.v $entry.min $entry.max)) {
            throw "Rust campaign manifest contains an untyped/out-of-range integer: $($entry.n)"
        }
    }
    if ($Value.generations -isnot [System.Array] -or $Value.handovers -isnot [System.Array]) {
        throw "Rust campaign manifest generations/handovers are not JSON arrays."
    }
    foreach ($generation in @($Value.generations)) {
        foreach ($name in @("generation_index", "depth_records", "trade_records")) {
            if (-not (Test-RawQualificationJsonInteger $generation.PSObject.Properties[$name].Value 0 $u64)) {
                throw "Rust campaign generation contains an untyped/out-of-range integer: $name"
            }
        }
        foreach ($name in @("session_id", "session_dir", "evaluation_file")) {
            if (-not (Test-RawQualificationJsonString $generation.PSObject.Properties[$name].Value)) {
                throw "Rust campaign generation contains a non-string identity/path: $name"
            }
        }
        foreach ($name in @("verification_sha256", "evaluation_file_sha256", "generation_manifest_sha256")) {
            if (-not (Test-RawQualificationJsonSha256 $generation.PSObject.Properties[$name].Value)) {
                throw "Rust campaign generation contains a malformed/non-string digest: $name"
            }
        }
    }
    foreach ($handover in @($Value.handovers)) {
        foreach ($name in @("predecessor_generation_index", "successor_generation_index")) {
            if (-not (Test-RawQualificationJsonInteger $handover.PSObject.Properties[$name].Value 0 $u64)) {
                throw "Rust campaign handover contains an untyped/out-of-range generation index."
            }
        }
        if (-not (Test-RawQualificationJsonString $handover.proof_file) -or
            -not (Test-RawQualificationJsonSha256 $handover.proof_sha256) -or
            -not (Test-RawQualificationJsonSha256 $handover.proof_file_sha256)) {
            throw "Rust campaign handover contains an invalid path/digest."
        }
    }
    if ([string]$Value.schema -cne "RawCampaignManifestV1" -or
        [string]$Value.status -cne "COMPLETE" -or
        [string]$Value.credentials -cne "NONE" -or [string]$Value.order_entry -cne "ABSENT" -or
        [string]$Value.startup_file -cne "campaign-startup.json" -or
        [string]$Value.journal_file -cne "campaign-events.jsonl" -or
        [string]$Value.journal_boundary -cne "PRECOMMIT_PREFIX" -or
        [uint64]$Value.supervisor_gap_count -ne 0 -or
        [uint64]$Value.finished_wall_ns -lt [uint64]$Value.started_wall_ns) {
        throw "Rust campaign manifest terminal schema/status/gap/time contract is invalid."
    }
    return $true
}

function Assert-MonitorCampaignStartupBinding {
    param(
        [Parameter(Mandatory = $true)] $CampaignStartup,
        [Parameter(Mandatory = $true)] [string] $CampaignStartupSha256,
        [Parameter(Mandatory = $true)] $Binding,
        [Parameter(Mandatory = $true)] $LauncherStartup,
        [Parameter(Mandatory = $true)] $ControlProcess
    )
    $null = Assert-MonitorRustCampaignSingletonJsonTypes $CampaignStartup Startup
    if ([string]$CampaignStartup.campaign_id -cne [string]$Binding.campaign_id -or
        [string]$CampaignStartup.symbol -cne [string]$Binding.symbol -or
        [uint32]$CampaignStartup.process_id -ne [uint32]$Binding.pid -or
        [uint32]$CampaignStartup.process_id -ne [uint32]$ControlProcess.pid -or
        [string]$CampaignStartupSha256 -cne [string]$Binding.campaign_startup_sha256 -or
        [uint64]$CampaignStartup.total_duration_s -ne [uint64]$LauncherStartup.parameters.total_s -or
        [uint64]$CampaignStartup.rotation_s -ne [uint64]$LauncherStartup.parameters.rotation_s -or
        [uint64]$CampaignStartup.overlap_s -ne [uint64]$LauncherStartup.parameters.overlap_s -or
        [uint64]$CampaignStartup.segment_s -ne [uint64]$LauncherStartup.parameters.segment_s -or
        [string]$CampaignStartup.executable_sha256 -cne [string]$LauncherStartup.preflight.campaign_executable_sha256 -or
        [string]$CampaignStartup.capture_executable_sha256 -cne [string]$LauncherStartup.preflight.capture_executable_sha256 -or
        [string]$CampaignStartup.public_config_sha256 -cne [string]$LauncherStartup.preflight.public_config_sha256 -or
        [string]$CampaignStartup.spec_revision -cne [string]$LauncherStartup.preflight.spec_revision -or
        [string]$CampaignStartup.credentials -cne "NONE" -or
        [string]$CampaignStartup.order_entry -cne "ABSENT") {
        throw "Rust campaign startup is not causally/semantically bound to launcher control and campaign bindings."
    }
    return $true
}

function Assert-MonitorExecutionWriterOrder {
    param([Parameter(Mandatory = $true)] $Execution)
    if (-not (Test-MonitorExactJsonPropertyOrder $Execution @(
                "schema", "name", "pid", "creation_time_utc", "executable_path", "executable_sha256",
                "command_line", "global_budget_computed_monotonic_tick", "resume_qpc_timestamp",
                "elapsed_qpc_ticks", "monotonic_frequency", "parent_exit_observed_qpc_timestamp",
                "descendant_drain_elapsed_qpc_ticks", "descendant_drain_elapsed_ms", "timeout_s", "elapsed_ms",
                "timed_out", "exit_code", "failure", "stdout_file", "stdout_bytes", "stdout_sha256",
                "stderr_file", "stderr_bytes", "stderr_sha256", "report_file", "report_present",
                "report_bytes", "report_sha256"))) {
        throw "Verifier execution differs from the exact ordered PowerShell writer contract."
    }
    return $true
}

function Get-VerifiedJournalSummary {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $ExpectedSchema,
        [switch] $AllowEmpty
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing journal: $Path"
    }
    $snapshot = Read-MonitorFrozenCanonicalJsonLines -Path $Path -AllowEmpty:$AllowEmpty
    $snapshotLength = [uint64]$snapshot.file_length
    $endsWithNewline = -not [bool]$snapshot.partial_tail
    $sourceLines = [Collections.Generic.List[string]]::new()
    foreach ($snapshotLine in @($snapshot.lines)) { $sourceLines.Add($snapshotLine) }
    if ($snapshot.partial_tail) { $sourceLines.Add("__IGNORED_PARTIAL_TAIL_SENTINEL__") }
    try {
            $nextIndex = [uint64]0
            $previousDigest = "0" * 64
            $last = $null
            $penultimate = $null
            $pending = $null
            $startupBindingSha = $null
            $processControlBindingSha = $null
            $campaignBindingsSha = $null
            $campaignExitRecords = @{}
            $watchdogStopRecord = $null
            $captureDrainingRecord = $null
            $terminalEvaluationRecord = $null
            $independentVerificationRecord = $null
            $providerExecutions = [Collections.Generic.List[object]]::new()
            $allRecords = [Collections.Generic.List[object]]::new()
            foreach ($line in $sourceLines) {
                if ($null -ne $pending) {
                    $envelope = ConvertFrom-MonitorCanonicalCompactJsonLine `
                        -Line $pending -Path $Path -Ordinal $nextIndex
                    $null = Assert-MonitorJournalRecordEnvelopeJsonTypes -Record $envelope -ExpectedSchema $ExpectedSchema
                    $bodyJson = $envelope.body | ConvertTo-Json -Depth 100 -Compress
                    $actual = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($bodyJson))
                    if ([string]$envelope.body.schema -cne $ExpectedSchema -or
                        [uint64]$envelope.body.record_index -ne $nextIndex -or
                        [string]$envelope.body.previous_record_sha256 -ne $previousDigest -or
                        [string]$envelope.record_sha256 -ne $actual) {
                        throw "Hash-chain failure at record $nextIndex in $Path"
                    }
                    $nextIndex = [uint64]($nextIndex + 1)
                    $previousDigest = $actual
                    $penultimate = $last
                    $last = $envelope
                    $payload = $envelope.body.payload
                    if ($ExpectedSchema -in @(
                        "RawQualificationLauncherEventV1",
                        "RawQualificationHostTelemetryRecordV1",
                        "RawQualificationGuardianPulseV1")) {
                        $allRecords.Add($envelope)
                    }
                    if ($ExpectedSchema -eq "RawQualificationHostTelemetryRecordV1") {
                        if ($null -eq $payload.PSObject.Properties['provider_execution']) {
                            throw "Host telemetry record $($envelope.body.record_index) lacks provider execution evidence: $Path"
                        }
                        $providerExecutions.Add($payload.provider_execution)
                    }
                    if ($null -ne $payload.PSObject.Properties['event']) {
                        switch ([string]$payload.event) {
                            "PREFLIGHT_PASSED" {
                                if ($null -ne $startupBindingSha) { throw "Duplicate PREFLIGHT_PASSED in $Path" }
                                $startupBindingSha = [string]$payload.startup_sha256
                            }
                            "DUAL_CAMPAIGN_STARTED" {
                                if ($null -ne $processControlBindingSha) { throw "Duplicate DUAL_CAMPAIGN_STARTED in $Path" }
                                $processControlBindingSha = [string]$payload.process_control_sha256
                            }
                            "DUAL_SEMANTIC_READINESS" {
                                if ($null -ne $campaignBindingsSha) { throw "Duplicate DUAL_SEMANTIC_READINESS in $Path" }
                                $campaignBindingsSha = [string]$payload.bindings_sha256
                            }
                            "CAMPAIGN_PROCESS_EXITED" {
                                $symbol = [string]$payload.symbol
                                if ($campaignExitRecords.ContainsKey($symbol)) {
                                    throw "Duplicate campaign exit record for $symbol in $Path"
                                }
                                $campaignExitRecords[$symbol] = [pscustomobject]@{
                                    symbol = $symbol
                                    pid = [uint32]$payload.pid
                                    exit_code = [int]$payload.exit_code
                                    elapsed_s = [uint64]$payload.elapsed_s
                                    coordinator_elapsed_s = [uint64]$payload.coordinator_elapsed_s
                                }
                            }
                            "GUARDIAN_WATCHDOG_STOPPED" {
                                if ($null -ne $watchdogStopRecord) { throw "Duplicate watchdog stop record in $Path" }
                                $watchdogStopRecord = [pscustomobject]@{
                                    pid = [uint32]$payload.pid
                                     exit_code = [int]$payload.exit_code
                                     stop_file_sha256 = [string]$payload.stop_file_sha256
                                     stop_request_qpc_timestamp = [long]$payload.stop_request_qpc_timestamp
                                     exit_elapsed_qpc_ticks = [long]$payload.exit_elapsed_qpc_ticks
                                     final_job_drain_elapsed_qpc_ticks = [long]$payload.final_job_drain_elapsed_qpc_ticks
                                     monotonic_frequency = [long]$payload.monotonic_frequency
                                     final_job_active_processes = [uint32]$payload.final_job_active_processes
                                }
                            }
                            "CAPTURE_DRAINING_STARTED" {
                                if ($null -ne $captureDrainingRecord) { throw "Duplicate capture draining record in $Path" }
                                $captureDrainingRecord = $envelope
                            }
                            "CAMPAIGN_TERMINAL_EVALUATION_STARTED" {
                                if ($null -ne $terminalEvaluationRecord) { throw "Duplicate terminal evaluation record in $Path" }
                                $terminalEvaluationRecord = $envelope
                            }
                            "INDEPENDENT_VERIFICATION_STAGE_STARTED" {
                                if ($null -ne $independentVerificationRecord) { throw "Duplicate independent verification stage record in $Path" }
                                $independentVerificationRecord = $envelope
                            }
                        }
                    }
                }
                $pending = $line
            }
            if ($endsWithNewline -and $null -ne $pending) {
                $envelope = ConvertFrom-MonitorCanonicalCompactJsonLine `
                    -Line $pending -Path $Path -Ordinal $nextIndex
                $null = Assert-MonitorJournalRecordEnvelopeJsonTypes -Record $envelope -ExpectedSchema $ExpectedSchema
                $bodyJson = $envelope.body | ConvertTo-Json -Depth 100 -Compress
                $actual = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($bodyJson))
                if ([string]$envelope.body.schema -cne $ExpectedSchema -or
                    [uint64]$envelope.body.record_index -ne $nextIndex -or
                    [string]$envelope.body.previous_record_sha256 -ne $previousDigest -or
                    [string]$envelope.record_sha256 -ne $actual) {
                    throw "Hash-chain failure at record $nextIndex in $Path"
                }
                $nextIndex = [uint64]($nextIndex + 1)
                $previousDigest = $actual
                $penultimate = $last
                $last = $envelope
                $payload = $envelope.body.payload
                if ($ExpectedSchema -in @(
                    "RawQualificationLauncherEventV1",
                    "RawQualificationHostTelemetryRecordV1",
                    "RawQualificationGuardianPulseV1")) {
                    $allRecords.Add($envelope)
                }
                if ($ExpectedSchema -eq "RawQualificationHostTelemetryRecordV1") {
                    if ($null -eq $payload.PSObject.Properties['provider_execution']) {
                        throw "Host telemetry record $($envelope.body.record_index) lacks provider execution evidence: $Path"
                    }
                    $providerExecutions.Add($payload.provider_execution)
                }
                if ($null -ne $payload.PSObject.Properties['event']) {
                    switch ([string]$payload.event) {
                        "PREFLIGHT_PASSED" {
                            if ($null -ne $startupBindingSha) { throw "Duplicate PREFLIGHT_PASSED in $Path" }
                            $startupBindingSha = [string]$payload.startup_sha256
                        }
                        "DUAL_CAMPAIGN_STARTED" {
                            if ($null -ne $processControlBindingSha) { throw "Duplicate DUAL_CAMPAIGN_STARTED in $Path" }
                            $processControlBindingSha = [string]$payload.process_control_sha256
                        }
                        "DUAL_SEMANTIC_READINESS" {
                            if ($null -ne $campaignBindingsSha) { throw "Duplicate DUAL_SEMANTIC_READINESS in $Path" }
                            $campaignBindingsSha = [string]$payload.bindings_sha256
                        }
                        "CAMPAIGN_PROCESS_EXITED" {
                            $symbol = [string]$payload.symbol
                            if ($campaignExitRecords.ContainsKey($symbol)) {
                                throw "Duplicate campaign exit record for $symbol in $Path"
                            }
                            $campaignExitRecords[$symbol] = [pscustomobject]@{
                                symbol = $symbol
                                pid = [uint32]$payload.pid
                                exit_code = [int]$payload.exit_code
                                elapsed_s = [uint64]$payload.elapsed_s
                                coordinator_elapsed_s = [uint64]$payload.coordinator_elapsed_s
                            }
                        }
                        "GUARDIAN_WATCHDOG_STOPPED" {
                            if ($null -ne $watchdogStopRecord) { throw "Duplicate watchdog stop record in $Path" }
                            $watchdogStopRecord = [pscustomobject]@{
                                pid = [uint32]$payload.pid
                                     exit_code = [int]$payload.exit_code
                                     stop_file_sha256 = [string]$payload.stop_file_sha256
                                     stop_request_qpc_timestamp = [long]$payload.stop_request_qpc_timestamp
                                     exit_elapsed_qpc_ticks = [long]$payload.exit_elapsed_qpc_ticks
                                     final_job_drain_elapsed_qpc_ticks = [long]$payload.final_job_drain_elapsed_qpc_ticks
                                     monotonic_frequency = [long]$payload.monotonic_frequency
                                     final_job_active_processes = [uint32]$payload.final_job_active_processes
                                }
                            }
                        "CAPTURE_DRAINING_STARTED" {
                            if ($null -ne $captureDrainingRecord) { throw "Duplicate capture draining record in $Path" }
                            $captureDrainingRecord = $envelope
                        }
                        "CAMPAIGN_TERMINAL_EVALUATION_STARTED" {
                            if ($null -ne $terminalEvaluationRecord) { throw "Duplicate terminal evaluation record in $Path" }
                            $terminalEvaluationRecord = $envelope
                        }
                        "INDEPENDENT_VERIFICATION_STAGE_STARTED" {
                            if ($null -ne $independentVerificationRecord) { throw "Duplicate independent verification stage record in $Path" }
                            $independentVerificationRecord = $envelope
                        }
                    }
                }
            }
            if ($nextIndex -eq 0 -and -not $AllowEmpty) { throw "Journal has no complete durable record: $Path" }
            $preterminalPrefixBytes = $null
            $preterminalPrefixSha256 = $null
            if ($endsWithNewline -and $nextIndex -ge 2 -and
                $null -ne $last.body.payload.PSObject.Properties['event'] -and
                [string]$last.body.payload.event -ceq "LAUNCHER_TERMINAL") {
                $prefixText = (@($snapshot.lines[0..($snapshot.lines.Count - 2)]) -join "`n") + "`n"
                $prefixBytes = [Text.UTF8Encoding]::new($false).GetBytes($prefixText)
                $preterminalPrefixBytes = [uint64]$prefixBytes.Length
                $preterminalPrefixSha256 = Get-RawQualificationSha256Bytes -Bytes $prefixBytes
            }
            return [pscustomobject]@{
                records = $nextIndex
                terminal_record_sha256 = $previousDigest
                last = $last
                penultimate = $penultimate
                partial_tail = [bool](-not $endsWithNewline)
                file_length = [uint64]$snapshotLength
                file_sha256 = [string]$snapshot.file_sha256
                preterminal_prefix_bytes = $preterminalPrefixBytes
                preterminal_prefix_sha256 = $preterminalPrefixSha256
                startup_binding_sha256 = $startupBindingSha
                process_control_binding_sha256 = $processControlBindingSha
                campaign_bindings_sha256 = $campaignBindingsSha
                campaign_exit_records = $campaignExitRecords
                watchdog_stop_record = $watchdogStopRecord
                capture_draining_record = $captureDrainingRecord
                terminal_evaluation_record = $terminalEvaluationRecord
                independent_verification_record = $independentVerificationRecord
                provider_executions = @($providerExecutions.ToArray())
                all_records = @($allRecords.ToArray())
            }
    }
    finally { }
}

function Assert-HostProviderExecutionHistory {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] [uint64] $ExpectedTimeoutSeconds,
        [Parameter(Mandatory = $true)] [uint64] $MaximumArtifactBytes
    )
    $providerExecutions = @($Journal.provider_executions)
    $hostRecords = @($Journal.all_records)
    if ($providerExecutions.Count -ne [uint64]$Journal.records -or
        $hostRecords.Count -ne $providerExecutions.Count) {
        throw "Host telemetry does not bind exactly one provider execution per durable sample."
    }
    $expectedArguments = [string[]]@(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
        [string]$Startup.preflight.telemetry_probe_script,
        "-HelperPath", [string]$Startup.preflight.helper_script,
        "-DriveDeviceId", [string]$Startup.preflight.drive_device_id,
        "-RootProcessId", ([uint32]$Startup.launcher_pid).ToString([Globalization.CultureInfo]::InvariantCulture))
    $expectedCommandLine = [RawQualificationNative]::BuildExactCommandLine(
        [string]$Startup.preflight.powershell_executable,
        $expectedArguments)
    $expectedCommandLineSha256 = Get-RawQualificationSha256Bytes -Bytes (
        [Text.UTF8Encoding]::new($false).GetBytes($expectedCommandLine))
    $previousHostEventAbsoluteQpcTimestamp = $null
    for ($providerIndex = 0; $providerIndex -lt $providerExecutions.Count; $providerIndex++) {
        $providerExecution = $providerExecutions[$providerIndex]
        $hostRecord = $hostRecords[$providerIndex]
        $null = Assert-MonitorProviderExecutionJsonTypes -Execution $providerExecution
        if ([uint32]$providerExecution.pid -eq 0 -or
            [string]$providerExecution.job_membership -ne "PRIMARY_AND_NESTED_BOUNDED" -or
            [uint32]$providerExecution.descendant_drain_active_processes -ne 0 -or
            [uint64]$providerExecution.timeout_s -ne $ExpectedTimeoutSeconds -or
            -not (Test-MonitorQpcExecutionEvidence `
                -ResumeQpcTimestamp ([long]$providerExecution.resume_qpc_timestamp) `
                -ElapsedQpcTicks ([long]$providerExecution.elapsed_qpc_ticks) `
                -MonotonicFrequency ([long]$providerExecution.monotonic_frequency) `
                -ExpectedFrequency ([long]$Startup.monotonic_frequency) `
                -TimeoutSeconds $ExpectedTimeoutSeconds `
                -ElapsedMilliseconds ([uint64]$providerExecution.elapsed_ms)) -or
            -not (Test-MonitorQpcExecutionEvidence `
                -ResumeQpcTimestamp ([long]$providerExecution.parent_exit_observed_qpc_timestamp) `
                -ElapsedQpcTicks ([long]$providerExecution.descendant_drain_elapsed_qpc_ticks) `
                -MonotonicFrequency ([long]$providerExecution.monotonic_frequency) `
                -ExpectedFrequency ([long]$Startup.monotonic_frequency) `
                -TimeoutSeconds 10 `
                -ElapsedMilliseconds ([uint64]$providerExecution.descendant_drain_elapsed_ms)) -or
            [uint64]$providerExecution.stdout_bytes -eq 0 -or
            [uint64]$providerExecution.stdout_bytes -gt $MaximumArtifactBytes -or
            [string]$providerExecution.stdout_sha256 -notmatch '^[0-9a-f]{64}$' -or
            [uint64]$providerExecution.stderr_bytes -ne 0 -or
            [string]$providerExecution.stderr_sha256 -notmatch '^[0-9a-f]{64}$' -or
            [string]$providerExecution.command_line_sha256 -ne $expectedCommandLineSha256 -or
            ($null -ne $previousHostEventAbsoluteQpcTimestamp -and
                [decimal]$providerExecution.resume_qpc_timestamp -lt $previousHostEventAbsoluteQpcTimestamp) -or
            -not (Test-MonitorBoundedExecutionCausality `
                -StartupOriginQpcTimestamp $Startup.monotonic_origin_qpc_timestamp `
                -ContainerEventMonotonicTick $hostRecord.body.monotonic_tick `
                -ResumeQpcTimestamp $providerExecution.resume_qpc_timestamp `
                -ElapsedQpcTicks $providerExecution.elapsed_qpc_ticks `
                -ParentExitObservedQpcTimestamp $providerExecution.parent_exit_observed_qpc_timestamp `
                -DescendantDrainElapsedQpcTicks $providerExecution.descendant_drain_elapsed_qpc_ticks)) {
            throw "Host telemetry provider proof $providerIndex is invalid (resume=$($providerExecution.resume_qpc_timestamp), parent=$($providerExecution.parent_exit_observed_qpc_timestamp), elapsed=$($providerExecution.elapsed_qpc_ticks), drain=$($providerExecution.descendant_drain_elapsed_qpc_ticks), previous_host_absolute=$previousHostEventAbsoluteQpcTimestamp, host_tick=$($hostRecord.body.monotonic_tick))."
        }
        $previousHostEventAbsoluteQpcTimestamp =
            [decimal]$Startup.monotonic_origin_qpc_timestamp + [decimal]$hostRecord.body.monotonic_tick
        if ($previousHostEventAbsoluteQpcTimestamp -gt [decimal][long]::MaxValue) {
            throw "A host telemetry event absolute QPC timestamp overflowed its signed runtime domain."
        }
    }
    return $true
}

function Get-MonitorRemainingProjectionGiB {
    param(
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] [double] $ElapsedSeconds
    )
    $total = [double][uint64]$Startup.parameters.total_s
    $rotation = [double][uint64]$Startup.parameters.rotation_s
    $overlap = [double][uint64]$Startup.parameters.overlap_s
    $boundedElapsed = [math]::Min($total, [math]::Max(0.0, $ElapsedSeconds))
    $remainingEquivalentSeconds = [math]::Max(0.0, $total - $boundedElapsed)
    $handoverStart = $rotation
    while ($handoverStart -lt $total) {
        $handoverEnd = [math]::Min($total, $handoverStart + $overlap)
        if ($handoverEnd -gt $boundedElapsed) {
            $remainingEquivalentSeconds += [math]::Max(0.0, $handoverEnd - [math]::Max($boundedElapsed, $handoverStart))
        }
        $handoverStart += $rotation
    }
    return [uint64][math]::Ceiling(
        [double]$Startup.preflight.projection_combined_raw_gib_per_hour *
        ($remainingEquivalentSeconds / 3600.0) *
        [double]$Startup.preflight.projection_safety_multiplier)
}

function Test-MonitorVerifierExecutionBudget {
    param(
        [Parameter(Mandatory = $true)] [uint64] $ActualTimeoutSeconds,
        [Parameter(Mandatory = $true)] [uint64] $MaximumPerProcessTimeoutSeconds,
        [Parameter(Mandatory = $true)] [uint64] $ElapsedMilliseconds
    )
    return $ActualTimeoutSeconds -ge 60 -and
        $ActualTimeoutSeconds -le $MaximumPerProcessTimeoutSeconds -and
        $ElapsedMilliseconds -le ($ActualTimeoutSeconds * [uint64]1000)
}

function Test-MonitorQpcExecutionEvidence {
    param(
        [Parameter(Mandatory = $true)] [long] $ResumeQpcTimestamp,
        [Parameter(Mandatory = $true)] [long] $ElapsedQpcTicks,
        [Parameter(Mandatory = $true)] [long] $MonotonicFrequency,
        [Parameter(Mandatory = $true)] [long] $ExpectedFrequency,
        [Parameter(Mandatory = $true)] [uint64] $TimeoutSeconds,
        [Parameter(Mandatory = $true)] [uint64] $ElapsedMilliseconds
    )
    if ($ResumeQpcTimestamp -le 0 -or $ElapsedQpcTicks -lt 0 -or
        $MonotonicFrequency -le 0 -or $MonotonicFrequency -ne $ExpectedFrequency) {
        return $false
    }
    $expectedElapsedMilliseconds = Convert-RawQualificationQpcTicksToMilliseconds `
        -ElapsedTicks $ElapsedQpcTicks `
        -Frequency $MonotonicFrequency
    return $ElapsedMilliseconds -eq $expectedElapsedMilliseconds -and
        (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $ElapsedQpcTicks `
            -TimeoutSeconds $TimeoutSeconds `
            -Frequency $MonotonicFrequency)
}

function Add-MonitorSequentialProcessIdentity {
    param(
        [Parameter(Mandatory = $true)] [hashtable] $Seen,
        [Parameter(Mandatory = $true)] [uint32] $ProcessId,
        [Parameter(Mandatory = $true)] [string] $CreationTimeUtc
    )
    if ([string]::IsNullOrWhiteSpace($CreationTimeUtc)) { return $false }
    $pidKey = $ProcessId.ToString([Globalization.CultureInfo]::InvariantCulture)
    if ($Seen.ContainsKey($pidKey) -and @($Seen[$pidKey]) -contains $CreationTimeUtc) {
        return $false
    }
    if (-not $Seen.ContainsKey($pidKey)) { $Seen[$pidKey] = @() }
    $Seen[$pidKey] += $CreationTimeUtc
    return $true
}

function Test-MonitorCampaignVerifiedReportBinding {
    param(
        [Parameter(Mandatory = $true)] $VerifiedEvent,
        [Parameter(Mandatory = $true)] [object[]] $Verifiers
    )
    $rust = @($Verifiers | Where-Object { [string]$_.name -like "*-rust" })
    $python = @($Verifiers | Where-Object { [string]$_.name -like "*-python" })
    return $rust.Count -eq 1 -and $python.Count -eq 1 -and
        $null -ne $VerifiedEvent -and
        [string]$VerifiedEvent.body.payload.rust_report_sha256 -eq [string]$rust[0].report_sha256 -and
        [string]$VerifiedEvent.body.payload.python_report_sha256 -eq [string]$python[0].report_sha256
}

function Test-MonitorVerifierArtifactBounds {
    param(
        [Parameter(Mandatory = $true)] [uint64] $StdoutBytes,
        [Parameter(Mandatory = $true)] [uint64] $StderrBytes,
        [Parameter(Mandatory = $true)] [uint64] $ReportBytes,
        [Parameter(Mandatory = $true)] [uint64] $MaximumArtifactBytes
    )
    return $StdoutBytes -le $MaximumArtifactBytes -and
        $StderrBytes -eq 0 -and
        $ReportBytes -gt 0 -and
        $ReportBytes -le $MaximumArtifactBytes
}

function Get-MonitorExpectedVerifierTimeoutSeconds {
    param(
        [Parameter(Mandatory = $true)] [uint64] $BudgetComputedTick,
        [Parameter(Mandatory = $true)] [uint64] $VerificationStageTick,
        [Parameter(Mandatory = $true)] [uint64] $MonotonicFrequency,
        [Parameter(Mandatory = $true)] [uint64] $TotalPostCaptureTimeoutSeconds,
        [Parameter(Mandatory = $true)] [uint64] $MaximumPerProcessTimeoutSeconds
    )
    if ($BudgetComputedTick -lt $VerificationStageTick) { return [uint64]0 }
    $remainingSeconds = [int][math]::Floor(
        [double]$TotalPostCaptureTimeoutSeconds -
        ([double]($BudgetComputedTick - $VerificationStageTick) / [double]$MonotonicFrequency))
    if ($remainingSeconds -lt 60) { return [uint64]0 }
    return [uint64][math]::Min([double]$MaximumPerProcessTimeoutSeconds, [double]$remainingSeconds)
}

function Assert-PostCreateProbeEvidence {
    param(
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] $OutputPathValidation,
        [Parameter(Mandatory = $true)] [string] $ResolvedRunRoot
    )
    $null = Assert-MonitorPostCreateProbeJsonTypes -Value $OutputPathValidation
    if (-not (Test-RawQualificationJsonInteger -Value $Startup.monotonic_origin_qpc_timestamp -Minimum 1 -Maximum ([decimal][long]::MaxValue)) -or
        [decimal]$OutputPathValidation.probe_resume_qpc_timestamp -lt [decimal]$Startup.monotonic_origin_qpc_timestamp -or
        [decimal]$OutputPathValidation.probe_parent_exit_observed_qpc_timestamp -lt [decimal]$OutputPathValidation.probe_resume_qpc_timestamp -or
        ([decimal]$OutputPathValidation.probe_parent_exit_observed_qpc_timestamp -
            [decimal]$OutputPathValidation.probe_resume_qpc_timestamp) -ne
            [decimal]$OutputPathValidation.probe_elapsed_qpc_ticks) {
        throw "Post-creation probe has impossible parent/resume/elapsed QPC causality."
    }
    $probeRoot = Join-Path $ResolvedRunRoot "host-probes"
    $probeStdout = Join-Path $probeRoot ([string]$OutputPathValidation.probe_stdout_file)
    $probeStderr = Join-Path $probeRoot ([string]$OutputPathValidation.probe_stderr_file)
    $probeArguments = [string[]]@(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
        [string]$Startup.preflight.telemetry_probe_script,
        "-HelperPath", [string]$Startup.preflight.helper_script,
        "-DriveDeviceId", [string]$OutputPathValidation.run_root_drive_device_id,
        "-RootProcessId", ([uint32]$Startup.launcher_pid).ToString([Globalization.CultureInfo]::InvariantCulture))
    $probeCommandLine = [RawQualificationNative]::BuildExactCommandLine(
        [string]$Startup.preflight.powershell_executable,
        $probeArguments)
    $probeCommandLineSha256 = Get-RawQualificationSha256Bytes -Bytes (
        [Text.UTF8Encoding]::new($false).GetBytes($probeCommandLine))
    $probeSnapshot = Read-MonitorCanonicalJsonSnapshot `
        -Path $probeStdout `
        -WriterKind PowerShellCompactCrlf `
        -MaximumBytes $ExpectedHostProbeMaximumArtifactBytes
    if ($null -eq $OutputPathValidation.PSObject.Properties['probe_resume_qpc_timestamp'] -or
        $null -eq $OutputPathValidation.PSObject.Properties['probe_elapsed_qpc_ticks'] -or
        $null -eq $OutputPathValidation.PSObject.Properties['probe_monotonic_frequency'] -or
        $null -eq $OutputPathValidation.PSObject.Properties['probe_parent_exit_observed_qpc_timestamp'] -or
        $null -eq $OutputPathValidation.PSObject.Properties['probe_descendant_drain_elapsed_qpc_ticks'] -or
        $null -eq $OutputPathValidation.PSObject.Properties['probe_descendant_drain_elapsed_ms'] -or
        [string]$OutputPathValidation.probe_job_membership -ne "PRIMARY_AND_NESTED_BOUNDED" -or
        [uint32]$OutputPathValidation.probe_descendant_drain_active_processes -ne 0 -or
        [uint64]$OutputPathValidation.probe_timeout_s -ne $ExpectedHostProbeTimeoutSeconds -or
        -not (Test-MonitorQpcExecutionEvidence `
            -ResumeQpcTimestamp ([long]$OutputPathValidation.probe_resume_qpc_timestamp) `
            -ElapsedQpcTicks ([long]$OutputPathValidation.probe_elapsed_qpc_ticks) `
            -MonotonicFrequency ([long]$OutputPathValidation.probe_monotonic_frequency) `
            -ExpectedFrequency ([long]$Startup.monotonic_frequency) `
            -TimeoutSeconds $ExpectedHostProbeTimeoutSeconds `
            -ElapsedMilliseconds ([uint64]$OutputPathValidation.probe_elapsed_ms)) -or
        -not (Test-MonitorQpcExecutionEvidence `
            -ResumeQpcTimestamp ([long]$OutputPathValidation.probe_parent_exit_observed_qpc_timestamp) `
            -ElapsedQpcTicks ([long]$OutputPathValidation.probe_descendant_drain_elapsed_qpc_ticks) `
            -MonotonicFrequency ([long]$OutputPathValidation.probe_monotonic_frequency) `
            -ExpectedFrequency ([long]$Startup.monotonic_frequency) `
            -TimeoutSeconds 10 `
            -ElapsedMilliseconds ([uint64]$OutputPathValidation.probe_descendant_drain_elapsed_ms)) -or
        -not (Test-Path -LiteralPath $probeStdout -PathType Leaf) -or
        -not (Test-Path -LiteralPath $probeStderr -PathType Leaf) -or
        [uint64]$probeSnapshot.length -ne [uint64]$OutputPathValidation.probe_stdout_bytes -or
        [uint64]$probeSnapshot.length -eq 0 -or
        [uint64]$probeSnapshot.length -gt $ExpectedHostProbeMaximumArtifactBytes -or
        [string]$probeSnapshot.sha256 -cne [string]$OutputPathValidation.probe_stdout_sha256 -or
        (Get-RawQualificationSha256File -Path $probeStderr) -ne $OutputPathValidation.probe_stderr_sha256 -or
        [uint64](Get-Item -LiteralPath $probeStderr).Length -ne [uint64]$OutputPathValidation.probe_stderr_bytes -or
        [uint64](Get-Item -LiteralPath $probeStderr).Length -ne 0 -or
        [string]$OutputPathValidation.probe_command_line_sha256 -ne $probeCommandLineSha256) {
        throw "Post-creation run-root telemetry execution/artifacts violate their exact bounded startup proof."
    }
    $probeValue = $probeSnapshot.value
    $null = Assert-MonitorTelemetryProbePayloadJsonTypes `
        -Value $probeValue `
        -ExpectedRootProcessId ([uint32]$Startup.launcher_pid)
    if (-not (Test-MonitorExactJsonPropertyOrder -Value $probeValue -Expected @(
            "schema", "clock", "disk", "network", "collector_processes",
            "conflicting_collectors", "power")) -or
        -not (Test-MonitorExactJsonPropertyOrder -Value $probeValue.clock -Expected @(
            "healthy", "leap_indicator", "stratum", "source", "last_successful_sync",
            "root_delay_s", "root_dispersion_s", "phase_offset_s",
            "seconds_since_last_good_sync", "maximum_last_good_sync_age_s",
            "state_machine", "last_sync_error", "poll_interval_s", "raw_status_sha256",
            "query_exit_code")) -or
        -not (Test-MonitorExactJsonPropertyOrder -Value $probeValue.disk -Expected @(
            "device_id", "filesystem", "size_bytes", "free_bytes", "avg_read_latency_s",
            "avg_write_latency_s", "current_queue_length")) -or
        -not (Test-MonitorExactJsonPropertyOrder -Value $probeValue.network -Expected @(
            "received_bytes", "sent_bytes", "received_packets", "sent_packets",
            "received_discards", "outbound_discards", "received_errors", "outbound_errors")) -or
        -not (Test-MonitorExactJsonPropertyOrder -Value $probeValue.power -Expected @(
            "powercfg_exit_code", "ac_sleep_disabled")) -or
        [string]$probeValue.schema -cne "RawQualificationTelemetryProbeV1" -or
        -not [bool]$probeValue.clock.healthy -or
        [int]$probeValue.clock.query_exit_code -ne 0 -or
        [int]$probeValue.clock.leap_indicator -ne 0 -or
        [int]$probeValue.clock.stratum -lt 1 -or [int]$probeValue.clock.stratum -gt 15 -or
        [int]$probeValue.clock.state_machine -ne 2 -or
        [int]$probeValue.clock.last_sync_error -ne 0 -or
        [double]$probeValue.clock.seconds_since_last_good_sync -gt
            [double]$probeValue.clock.maximum_last_good_sync_age_s -or
        [string]$probeValue.disk.device_id -cne [string]$OutputPathValidation.run_root_drive_device_id -or
        [string]$probeValue.disk.filesystem -cne "NTFS" -or
        [uint64]$probeValue.disk.size_bytes -ne [uint64]$Startup.preflight.disk_telemetry_preflight.size_bytes -or
        [uint64][math]::Floor([double][uint64]$probeValue.disk.free_bytes / 1GB) -ne [uint64]$OutputPathValidation.free_gib -or
        @($probeValue.conflicting_collectors).Count -ne 0 -or
        @($probeValue.collector_processes | Where-Object { [uint32]$_.pid -eq [uint32]$Startup.launcher_pid }).Count -ne 1 -or
        @($probeValue.power.PSObject.Properties).Count -ne 2 -or
        $null -ne $probeValue.power.powercfg_exit_code -or
        $null -ne $probeValue.power.ac_sleep_disabled) {
        throw "Post-creation telemetry payload does not prove the exact bound NTFS volume/free-space state."
    }
    return $true
}

function Get-MonitorWatchdogReadyEvidence {
    param(
        [Parameter(Mandatory = $true)] [string] $ResolvedRunRoot,
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] $WatchdogControl
    )
    if ([string]$WatchdogControl.ready_file -cne "watchdog-ready.json") {
        throw "Process control names an unexpected watchdog READY file."
    }
    $readyPath = Join-Path $ResolvedRunRoot ([string]$WatchdogControl.ready_file)
    if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
        throw "Independent guardian watchdog READY evidence is absent."
    }
    $readySnapshot = Read-MonitorCanonicalJsonSnapshot `
        -Path $readyPath -WriterKind PowerShellPretty -MaximumBytes 65536
    $readyBytes = $readySnapshot.bytes
    $readySha256 = $readySnapshot.sha256
    $ready = $readySnapshot.value
    $expectedProperties = @(
        "schema", "run_id", "job_name", "pid", "launch_origin_qpc_timestamp",
        "observed_qpc_timestamp", "monotonic_frequency", "startup_deadline_s", "pulse_length")
    if (-not (Test-MonitorExactJsonPropertyOrder -Value $ready -Expected $expectedProperties) -or
        -not (Test-RawQualificationJsonString $ready.schema) -or
        -not (Test-RawQualificationJsonString $ready.run_id) -or
        -not (Test-RawQualificationJsonString $ready.job_name) -or
        -not (Test-RawQualificationJsonInteger $ready.pid 1 ([decimal][uint32]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $ready.launch_origin_qpc_timestamp 1 ([decimal][long]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $ready.observed_qpc_timestamp 1 ([decimal][long]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $ready.monotonic_frequency 1 ([decimal][long]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $ready.startup_deadline_s 1 604920) -or
        -not (Test-RawQualificationJsonInteger $ready.pulse_length 1 ([decimal][uint64]::MaxValue)) -or
        [string]$ready.schema -cne "RawQualificationWatchdogReadyV1" -or
        [string]$ready.run_id -cne [string]$Startup.run_id -or
        [string]$ready.job_name -cne [string]$WatchdogControl.job_name -or
        [uint32]$ready.pid -ne [uint32]$WatchdogControl.pid -or
        [long]$ready.launch_origin_qpc_timestamp -ne [long]$WatchdogControl.launch_origin_qpc_timestamp -or
        [long]$ready.observed_qpc_timestamp -ne [long]$WatchdogControl.ready_observed_qpc_timestamp -or
        [long]$ready.monotonic_frequency -ne [long]$Startup.monotonic_frequency -or
        [long]$WatchdogControl.monotonic_frequency -ne [long]$Startup.monotonic_frequency -or
        [uint64]$ready.startup_deadline_s -ne $ExpectedGuardianWatchdogStartupDeadlineSeconds -or
        [uint64]$WatchdogControl.startup_deadline_s -ne $ExpectedGuardianWatchdogStartupDeadlineSeconds -or
        [uint64]$ready.pulse_length -eq 0 -or
        [uint64]$ready.pulse_length -ne [uint64]$WatchdogControl.ready_pulse_length -or
        [string]$WatchdogControl.ready_file_sha256 -ne $readySha256 -or
        [long]$ready.launch_origin_qpc_timestamp -lt [long]$Startup.monotonic_origin_qpc_timestamp -or
        [long]$WatchdogControl.resume_qpc_timestamp -lt [long]$ready.launch_origin_qpc_timestamp -or
        [long]$ready.observed_qpc_timestamp -lt [long]$WatchdogControl.resume_qpc_timestamp -or
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks ([long]([long]$ready.observed_qpc_timestamp - [long]$ready.launch_origin_qpc_timestamp)) `
            -TimeoutSeconds $ExpectedGuardianWatchdogStartupDeadlineSeconds `
            -Frequency ([long]$Startup.monotonic_frequency))) {
        throw "Independent guardian watchdog READY payload/hash/QPC contract is invalid."
    }
    $pulsePath = Join-Path $ResolvedRunRoot ([string]$Startup.guardian_policy.pulse_file)
    if (-not (Test-Path -LiteralPath $pulsePath -PathType Leaf) -or
        [uint64](Get-Item -LiteralPath $pulsePath -ErrorAction Stop).Length -lt [uint64]$ready.pulse_length) {
        throw "Guardian pulse journal regressed below the READY-retained prefix."
    }
    return [pscustomobject][ordered]@{
        path = $readyPath
        sha256 = $readySha256
        value = $ready
    }
}

function Get-MonitorCoordinatorProcessDisposition {
    param(
        [Parameter(Mandatory = $true)] [string] $Symbol,
        [Parameter(Mandatory = $true)] $Identity,
        [Parameter(Mandatory = $true)] [bool] $CleanCaptureExit,
        [Parameter(Mandatory = $true)] [bool] $TerminalComplete
    )
    $originalRunning = [bool]($Identity.running -and $Identity.valid)
    $pidReusedAfterExit = [bool]($Identity.running -and -not $Identity.valid)
    if ($CleanCaptureExit -and $originalRunning) {
        throw "$Symbol original coordinator identity is still running despite its exact successful launcher exit proof."
    }
    if ($pidReusedAfterExit -and -not $CleanCaptureExit) {
        throw "$Symbol PID was reused without an exact successful launcher exit proof."
    }
    if (-not $originalRunning -and -not $TerminalComplete -and -not $CleanCaptureExit) {
        throw "$Symbol raw campaign is absent without its exact successful launcher exit proof."
    }
    if ($TerminalComplete -and -not $CleanCaptureExit) {
        throw "$Symbol terminal COMPLETE lacks its exact PID/exit-zero/duration launcher proof."
    }
    return [pscustomobject][ordered]@{
        original_running = $originalRunning
        pid_occupied = [bool]$Identity.running
        exact_identity = [bool]$Identity.valid
        pid_reused_after_exit = [bool]($pidReusedAfterExit -and $CleanCaptureExit)
    }
}

function Test-MonitorStartupMonotonicFrequency {
    param([Parameter(Mandatory = $true)] $Startup)
    $frequencyProperty = $Startup.PSObject.Properties['monotonic_frequency']
    if ($null -eq $frequencyProperty -or
        -not (Test-RawQualificationJsonInteger -Value $frequencyProperty.Value -Minimum 1 -Maximum ([decimal][long]::MaxValue))) {
        return $false
    }
    return [long]$frequencyProperty.Value -eq [long][Diagnostics.Stopwatch]::Frequency
}

function Assert-MonitorCaptureDrainingTiming {
    param(
        [Parameter(Mandatory = $true)] $DrainingRecord,
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] $Control
    )
    $null = Assert-MonitorLauncherRecordJsonContract -Record $DrainingRecord
    if (-not (Test-RawQualificationJsonInteger -Value $Startup.monotonic_frequency -Minimum 1 -Maximum ([decimal][long]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger -Value $Control.capture_origin_monotonic_tick -Minimum 1 -Maximum ([decimal][uint64]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger -Value $Startup.parameters.total_s -Minimum 1 -Maximum 604800) -or
        -not (Test-RawQualificationJsonInteger -Value $Startup.guardian_policy.generation_terminal_deadline_s -Minimum 1 -Maximum 120)) {
        throw "CAPTURE_DRAINING_STARTED dependencies contain untyped or out-of-range JSON integers."
    }
    $frequency = [long]$Startup.monotonic_frequency
    $origin = [uint64]$Control.capture_origin_monotonic_tick
    $observed = [uint64]$DrainingRecord.body.monotonic_tick
    $totalSeconds = [uint64]$Startup.parameters.total_s
    $terminalDeadlineSeconds = [uint64]$Startup.guardian_policy.generation_terminal_deadline_s
    if ($frequency -le 0 -or $origin -eq 0 -or $observed -lt $origin) {
        throw "CAPTURE_DRAINING_STARTED has an invalid monotonic origin/frequency/tick."
    }
    $elapsedTicksDecimal = [decimal]$observed - [decimal]$origin
    $minimumSeconds = if ($totalSeconds -gt 5) { [uint64]($totalSeconds - 5) } else { [uint64]0 }
    $minimumTicksDecimal = [decimal]$minimumSeconds * [decimal]$frequency
    $maximumSecondsDecimal = [decimal]$totalSeconds + [decimal]$terminalDeadlineSeconds
    if ($elapsedTicksDecimal -lt $minimumTicksDecimal -or
        $elapsedTicksDecimal -gt [decimal][long]::MaxValue -or
        $maximumSecondsDecimal -gt [decimal][uint64]::MaxValue -or
        [uint64]$DrainingRecord.body.payload.generation_terminal_deadline_elapsed_s -ne [uint64]$maximumSecondsDecimal -or
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks ([long]$elapsedTicksDecimal) `
            -TimeoutSeconds ([uint64]$maximumSecondsDecimal) `
            -Frequency $frequency)) {
        throw "CAPTURE_DRAINING_STARTED is outside its exact inclusive monotonic capture window."
    }
    return [pscustomobject][ordered]@{
        elapsed_ticks = [long]$elapsedTicksDecimal
        minimum_elapsed_ticks = [decimal]$minimumTicksDecimal
        maximum_elapsed_seconds = [uint64]$maximumSecondsDecimal
    }
}

function Test-MonitorCaptureRequiresLiveFreshness {
    param(
        [Parameter(Mandatory = $true)] $LauncherHistoryContract
    )
    $captureDrainingProperty = $LauncherHistoryContract.PSObject.Properties['capture_draining']
    if ($null -eq $captureDrainingProperty) {
        throw "Validated launcher history contract lacks capture_draining."
    }
    return $null -eq $captureDrainingProperty.Value
}

function Get-MonitorEventDrivenStage {
    param(
        [Parameter(Mandatory = $true)] [bool] $TerminalComplete,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $ScheduleDeviationReasons,
        [Parameter(Mandatory = $true)] $LauncherHistoryContract
    )
    if ($TerminalComplete) { return "COMPLETE" }
    if ($ScheduleDeviationReasons.Count -ne 0) { return "DEVIATED" }
    if ($null -ne $LauncherHistoryContract.independent_verification) { return "VERIFYING" }
    if ($null -ne $LauncherHistoryContract.capture_draining) { return "DRAINING" }
    return "CAPTURING"
}

function Assert-GuardianPulseHistory {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] $Control
    )
    $records = @($Journal.all_records)
    if ($records.Count -ne [uint64]$Journal.records) {
        throw "Guardian pulse scan did not retain every durable record."
    }
    $allowedStages = @(
        "STARTING", "CAPTURING", "DRAINING", "TERMINAL_EVALUATION",
        "HOST_TELEMETRY_PROVIDER", "PYTHON_RUNTIME_FINGERPRINT", "INDEPENDENT_VERIFICATION")
    $previousTick = $null
    $previousLauncherElapsedMs = [uint64]0
    $previousCaptureElapsedMs = [uint64]0
    $startingRecords = [uint64]0
    $lifecycleStageRank = -1
    $rankByStage = @{
        STARTING = 0
        CAPTURING = 1
        DRAINING = 2
        TERMINAL_EVALUATION = 3
        INDEPENDENT_VERIFICATION = 4
    }
    foreach ($record in $records) {
        $body = $record.body
        $payload = $body.payload
        if (-not (Test-MonitorExactJsonPropertyOrder $payload @(
                    "event", "stage", "launcher_elapsed_ms", "capture_elapsed_ms")) -or
            -not (Test-RawQualificationJsonString $payload.event) -or
            -not (Test-RawQualificationJsonString $payload.stage) -or
            -not (Test-RawQualificationJsonInteger $payload.launcher_elapsed_ms 0 ([decimal][uint64]::MaxValue)) -or
            -not (Test-MonitorJsonNullOrInteger $payload.capture_elapsed_ms 0 ([decimal][uint64]::MaxValue))) {
            throw "Guardian pulse history contains a coercible or structurally invalid payload."
        }
        $tick = [uint64]$body.monotonic_tick
        if ([string]$body.channel -cne "GUARDIAN" -or
            [string]$payload.event -cne "GUARDIAN_PULSE" -or
            -not ($allowedStages -ccontains [string]$payload.stage) -or
            $null -eq $payload.PSObject.Properties['launcher_elapsed_ms'] -or
            ($null -ne $previousTick -and $tick -le [uint64]$previousTick) -or
            ($null -ne $previousTick -and
                ($tick - [uint64]$previousTick) -gt
                    ($ExpectedGuardianWatchdogDeadlineSeconds * [uint64]$Startup.monotonic_frequency))) {
            throw "Guardian pulse history contains an invalid channel/event/stage or monotonic regression."
        }
        $launcherElapsedMs = [uint64]$payload.launcher_elapsed_ms
        $expectedLauncherElapsedMs = [double]$tick * 1000.0 /
            [double][uint64]$Startup.monotonic_frequency
        if ([math]::Abs($expectedLauncherElapsedMs - [double]$launcherElapsedMs) -gt 5000.0 -or
            $launcherElapsedMs -lt $previousLauncherElapsedMs) {
            throw "Guardian pulse history contains an invalid or regressing launcher elapsed value."
        }
        if ($payload.stage -eq "STARTING") { $startingRecords = [uint64]($startingRecords + 1) }
        if ($rankByStage.ContainsKey([string]$payload.stage)) {
            $rank = [int]$rankByStage[[string]$payload.stage]
            if ($rank -lt $lifecycleStageRank) {
                throw "Guardian lifecycle stage regressed from a terminal phase to an earlier phase."
            }
            if ($rank -gt $lifecycleStageRank) { $lifecycleStageRank = $rank }
        }
        $captureProperty = $payload.PSObject.Properties['capture_elapsed_ms']
        if ($null -eq $captureProperty -or $null -eq $captureProperty.Value) {
            if ($payload.stage -ne "STARTING" -or $tick -gt [uint64]$Control.capture_origin_monotonic_tick) {
                throw "Only a pre-origin STARTING pulse may omit capture_elapsed_ms."
            }
        }
        else {
            if ($tick -lt [uint64]$Control.capture_origin_monotonic_tick) {
                throw "Guardian pulse capture time precedes the common origin."
            }
            $captureElapsedMs = [uint64]$captureProperty.Value
            $expectedMs = [double]($tick - [uint64]$Control.capture_origin_monotonic_tick) * 1000.0 /
                [double][uint64]$Startup.monotonic_frequency
            if ([math]::Abs($expectedMs - [double]$captureElapsedMs) -gt 5000.0 -or
                $captureElapsedMs -lt $previousCaptureElapsedMs) {
                throw "Guardian pulse history contains an invalid or regressing capture elapsed value."
            }
            $previousCaptureElapsedMs = $captureElapsedMs
        }
        $previousTick = $tick
        $previousLauncherElapsedMs = $launcherElapsedMs
    }
    if ($startingRecords -ne 1 -or $records[0].body.payload.stage -ne "STARTING") {
        throw "Guardian pulse history must begin with exactly one STARTING record."
    }
    return $true
}

function Assert-HostTelemetryHistory {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] $Control,
        [Parameter(Mandatory = $true)] [uint64] $ExpectedProviderTimeoutSeconds,
        [Parameter(Mandatory = $true)] [uint64] $MaximumProviderArtifactBytes
    )
    $records = @($Journal.all_records)
    if ($records.Count -ne [uint64]$Journal.records) {
        throw "Host telemetry scan did not retain every durable record."
    }
    $null = Assert-HostProviderExecutionHistory `
        -Journal $Journal `
        -Startup $Startup `
        -ExpectedTimeoutSeconds $ExpectedProviderTimeoutSeconds `
        -MaximumArtifactBytes $MaximumProviderArtifactBytes
    $previousTick = $null
    $previousLauncherElapsedMs = [uint64]0
    $previousCaptureElapsedMs = [uint64]0
    $previousProjection = [uint64]$Startup.preflight.projected_remaining_gib_at_start
    $campaignPrevious = @{}
    $controlBySymbol = @{}
    foreach ($process in @($Control.processes)) { $controlBySymbol[[string]$process.symbol] = $process }
    foreach ($record in $records) {
        $body = $record.body
        $payload = $body.payload
        $null = Assert-MonitorHostTelemetryPayloadJsonTypes -Payload $payload
        $tick = [uint64]$body.monotonic_tick
        if ([string]$body.channel -cne "HOST" -or
            [uint64]$payload.monotonic_frequency -ne [uint64]$Startup.monotonic_frequency -or
            $tick -lt [uint64]$Control.capture_origin_monotonic_tick -or
            ($null -ne $previousTick -and $tick -le [uint64]$previousTick) -or
            ($null -ne $previousTick -and
                ($tick - [uint64]$previousTick) -gt
                    ($ExpectedHostTelemetryGapDeadlineSeconds * [uint64]$Startup.monotonic_frequency)) -or
            $null -eq $payload.PSObject.Properties['capture_elapsed_ms']) {
            throw "Host telemetry history contains an invalid channel/frequency/origin or monotonic regression."
        }
        $captureElapsedMs = [uint64]$payload.capture_elapsed_ms
        $launcherElapsedMs = [uint64]$payload.launcher_elapsed_ms
        $expectedLauncherElapsedMs = [double]$tick * 1000.0 /
            [double][uint64]$Startup.monotonic_frequency
        $expectedCaptureElapsedMs = [double]($tick - [uint64]$Control.capture_origin_monotonic_tick) * 1000.0 /
            [double][uint64]$Startup.monotonic_frequency
        if ([math]::Abs($expectedCaptureElapsedMs - [double]$captureElapsedMs) -gt 5000.0 -or
            [math]::Abs($expectedLauncherElapsedMs - [double]$launcherElapsedMs) -gt 5000.0 -or
            $captureElapsedMs -lt $previousCaptureElapsedMs -or
            $launcherElapsedMs -lt $previousLauncherElapsedMs) {
            throw "Host telemetry history contains an invalid or regressing launcher/capture elapsed value."
        }
        $clock = $payload.clock
        if (-not [bool]$clock.healthy -or
            [int]$clock.query_exit_code -ne 0 -or
            [int]$clock.leap_indicator -ne 0 -or
            [int]$clock.stratum -lt 1 -or [int]$clock.stratum -gt 15 -or
            [string]::IsNullOrWhiteSpace([string]$clock.source) -or
            [string]$clock.source -match '(?i)Local CMOS|Free-running|VM IC Time Synchronization|unspecified' -or
            [int]$clock.state_machine -ne 2 -or
            [int]$clock.last_sync_error -ne 0 -or
            [double]$clock.seconds_since_last_good_sync -lt 0 -or
            [double]$clock.seconds_since_last_good_sync -gt 21600 -or
            [uint64]$clock.maximum_last_good_sync_age_s -ne 21600 -or
            [string]::IsNullOrWhiteSpace([string]$clock.last_successful_sync) -or
            [string]$clock.raw_status_sha256 -notmatch '^[0-9a-f]{64}$') {
            throw "A historical host telemetry record contains an unhealthy or internally inconsistent clock proof."
        }
        $disk = $payload.disk
        $expectedProjection = Get-MonitorRemainingProjectionGiB `
            -Startup $Startup `
            -ElapsedSeconds ([double]$captureElapsedMs / 1000.0)
        $freeGiB = [uint64][math]::Floor([double][uint64]$disk.free_bytes / 1GB)
        if ($disk.device_id -ne $Startup.preflight.drive_device_id -or
            $disk.filesystem -ne "NTFS" -or
            [uint64]$disk.size_bytes -ne [uint64]$Startup.preflight.disk_telemetry_preflight.size_bytes -or
            [uint64]$payload.disk_persistent_reserve_gib -ne [uint64]$Startup.preflight.persistent_reserve_gib -or
            [uint64]$payload.disk_projected_remaining_gib -ne $expectedProjection -or
            [uint64]$payload.disk_projected_remaining_gib -gt $previousProjection -or
            [uint64]$payload.disk_required_free_gib -ne
                ([uint64]$payload.disk_persistent_reserve_gib + [uint64]$payload.disk_projected_remaining_gib) -or
            $freeGiB -lt [uint64]$payload.disk_required_free_gib) {
            throw "A historical host telemetry record violates the exact disk identity/reserve/projection/free-space contract."
        }
        $campaigns = @($payload.campaigns)
        $symbols = @($campaigns | ForEach-Object { [string]$_.symbol } | Sort-Object)
        if ($campaigns.Count -ne 2 -or ($symbols -join ',') -ne "BTCUSDT,ETHUSDT") {
            throw "Historical host telemetry lacks the exact dual campaign identity set."
        }
        foreach ($campaign in $campaigns) {
            $symbol = [string]$campaign.symbol
            if (-not $controlBySymbol.ContainsKey($symbol) -or
                [uint32]$campaign.pid -ne [uint32]$controlBySymbol[$symbol].pid -or
                [uint64]$campaign.active_processes -gt 2 -or
                [uint64]$campaign.depth_durable -gt [uint64]$campaign.depth_received -or
                [uint64]$campaign.trade_durable -gt [uint64]$campaign.trade_received) {
                throw "Historical host telemetry campaign identity/counters are invalid for $symbol."
            }
            $latestGenerationProperty = $campaign.PSObject.Properties['latest_generation_index']
            if ($null -ne $latestGenerationProperty -and $null -ne $latestGenerationProperty.Value) {
                $telemetryMonoNs = [uint64]$campaign.latest_telemetry_mono_ns
                $depthSocketMonoNs = [uint64]$campaign.depth_last_socket_activity_mono_ns
                $depthMarketMonoNs = [uint64]$campaign.depth_last_market_message_mono_ns
                $tradeSocketMonoNs = [uint64]$campaign.trade_last_socket_activity_mono_ns
                $tradeMarketMonoNs = [uint64]$campaign.trade_last_market_message_mono_ns
                if ([uint64]$campaign.generations -le [uint64]$latestGenerationProperty.Value -or
                    $depthMarketMonoNs -gt $depthSocketMonoNs -or
                    $depthSocketMonoNs -gt $telemetryMonoNs -or
                    $tradeMarketMonoNs -gt $tradeSocketMonoNs -or
                    $tradeSocketMonoNs -gt $telemetryMonoNs) {
                    throw "Historical host telemetry market/socket monotonic lineage is invalid for $symbol."
                }
                if (-not [bool]$campaign.exited -and
                    [uint64]$campaign.campaign_elapsed_s -ge $ExpectedMarketFreshnessStartupGraceSeconds -and
                    (($telemetryMonoNs - $depthMarketMonoNs) -gt $ExpectedMarketFreshnessDeadlineNs -or
                     ($telemetryMonoNs - $tradeMarketMonoNs) -gt $ExpectedMarketFreshnessDeadlineNs)) {
                    throw "Historical host telemetry proves stale market messages for an active $symbol campaign."
                }
            }
            elseif ([bool]$campaign.ready) {
                throw "A historically ready campaign lacks its latest generation telemetry identity for $symbol."
            }
            if ($campaignPrevious.ContainsKey($symbol)) {
                $prior = $campaignPrevious[$symbol]
                if ([uint64]$campaign.campaign_elapsed_s -lt [uint64]$prior.campaign_elapsed_s -or
                    [uint64]$campaign.generations -lt [uint64]$prior.generations -or
                    [uint64]$campaign.handovers_proven -lt [uint64]$prior.handovers_proven -or
                    [uint64]$campaign.depth_received -lt [uint64]$prior.depth_received -or
                    [uint64]$campaign.depth_durable -lt [uint64]$prior.depth_durable -or
                    [uint64]$campaign.trade_received -lt [uint64]$prior.trade_received -or
                    [uint64]$campaign.trade_durable -lt [uint64]$prior.trade_durable -or
                    ([bool]$prior.ready -and -not [bool]$campaign.ready) -or
                    ([bool]$prior.exited -and -not [bool]$campaign.exited)) {
                    throw "Historical host telemetry campaign state regressed for $symbol."
                }
            }
            $campaignPrevious[$symbol] = $campaign
        }
        $previousTick = $tick
        $previousLauncherElapsedMs = $launcherElapsedMs
        $previousCaptureElapsedMs = $captureElapsedMs
        $previousProjection = [uint64]$payload.disk_projected_remaining_gib
    }
    return $true
}

function Assert-LauncherCausalPrefix {
    param(
        [Parameter(Mandatory = $true)] [object[]] $Records,
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] $Control,
        [switch] $SkipSingletonValidation
    )
    if (-not $SkipSingletonValidation) {
        $null = Assert-MonitorStartupControlJsonTypes -Startup $Startup -Control $Control
    }
    $assertExactProperties = {
        param($Payload, [string[]] $Expected, [string] $EventName)
        $actual = @($Payload.PSObject.Properties.Name | Sort-Object)
        $expectedSorted = @($Expected | Sort-Object)
        if (($actual -join "`n") -cne ($expectedSorted -join "`n")) {
            throw "$EventName payload does not have its exact versioned property set."
        }
    }
    $baseEvents = @(
        "PREFLIGHT_PASSED",
        "JOB_OBJECT_ARMED",
        "GUARDIAN_WATCHDOG_STARTED",
        "DUAL_CAMPAIGN_STARTED")
    $verificationTail = @(
        [pscustomobject]@{ event = "INDEPENDENT_VERIFIER_STARTED"; identity = "btcusdt-rust" },
        [pscustomobject]@{ event = "INDEPENDENT_VERIFIER_COMPLETED"; identity = "btcusdt-rust" },
        [pscustomobject]@{ event = "INDEPENDENT_VERIFIER_STARTED"; identity = "btcusdt-python" },
        [pscustomobject]@{ event = "INDEPENDENT_VERIFIER_COMPLETED"; identity = "btcusdt-python" },
        [pscustomobject]@{ event = "INDEPENDENT_CAMPAIGN_VERIFIED"; identity = "BTCUSDT" },
        [pscustomobject]@{ event = "INDEPENDENT_VERIFIER_STARTED"; identity = "ethusdt-rust" },
        [pscustomobject]@{ event = "INDEPENDENT_VERIFIER_COMPLETED"; identity = "ethusdt-rust" },
        [pscustomobject]@{ event = "INDEPENDENT_VERIFIER_STARTED"; identity = "ethusdt-python" },
        [pscustomobject]@{ event = "INDEPENDENT_VERIFIER_COMPLETED"; identity = "ethusdt-python" },
        [pscustomobject]@{ event = "INDEPENDENT_CAMPAIGN_VERIFIED"; identity = "ETHUSDT" },
        [pscustomobject]@{ event = "VERIFIER_DESCENDANTS_DRAINED"; identity = $null },
        [pscustomobject]@{ event = "GUARDIAN_WATCHDOG_STOPPED"; identity = $null },
        [pscustomobject]@{ event = "LAUNCHER_TERMINAL"; identity = $null })
    $phase = "BASE"
    $basePosition = 0
    $verificationTailPosition = 0
    $captureDraining = $null
    $preflightRecord = $null
    $terminalEvaluation = $null
    $independentVerification = $null
    $semanticReadiness = $null
    $readinessPublished = $null
    $exitRecords = @{}
    $verifierStarted = @{}
    $verifierCompleted = @{}
    $campaignVerified = @{}
    $verifierDrained = $null
    $ordinal = [uint64]0
    foreach ($record in $Records) {
        $null = Assert-MonitorLauncherRecordJsonContract -Record $record
        $payload = $record.body.payload
        $eventName = [string]$payload.event
        if ([uint64]$record.body.record_index -ne $ordinal) {
            throw "Launcher journal causal prefix contains a non-contiguous record index."
        }
        if ($phase -eq "BASE") {
            if ($basePosition -ge $baseEvents.Count -or $eventName -cne $baseEvents[$basePosition]) {
                throw "Launcher journal violates the exact PREFLIGHT -> JOB -> WATCHDOG -> DUAL causal prefix."
            }
            switch ($eventName) {
                "PREFLIGHT_PASSED" {
                    & $assertExactProperties $payload @("event", "startup_sha256") $eventName
                    if ([uint64]$record.body.record_index -ne 0 -or
                        [string]$payload.startup_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                        [string]$payload.startup_sha256 -cne [string]$Journal.startup_binding_sha256) {
                        throw "PREFLIGHT_PASSED does not bind the exact startup manifest."
                    }
                    $preflightRecord = $record
                }
                "JOB_OBJECT_ARMED" {
                    & $assertExactProperties $payload @(
                        "event", "kill_on_close", "name", "workload_kill_on_close", "workload_name") $eventName
                    if (-not [bool]$payload.kill_on_close -or
                        -not [bool]$payload.workload_kill_on_close -or
                        [string]$payload.name -cne [string]$Control.job_object_name -or
                        [string]$payload.workload_name -cne [string]$Control.workload_job_object_name -or
                        [string]$payload.name -ceq [string]$payload.workload_name) {
                        throw "JOB_OBJECT_ARMED does not bind the exact outer/workload kill-on-close Jobs."
                    }
                }
                "GUARDIAN_WATCHDOG_STARTED" {
                    & $assertExactProperties $payload @(
                        "deadline_s", "event", "launch_origin_qpc_timestamp", "pid",
                        "ready_file_sha256", "ready_observed_qpc_timestamp", "ready_pulse_length",
                        "resume_qpc_timestamp", "startup_deadline_s") $eventName
                    $readyRelativeTick = [decimal][long]$payload.ready_observed_qpc_timestamp -
                        [decimal][long]$Startup.monotonic_origin_qpc_timestamp
                    if ([uint32]$payload.pid -ne [uint32]$Control.watchdog.pid -or
                        [string]$payload.ready_file_sha256 -cne [string]$Control.watchdog.ready_file_sha256 -or
                        [long]$payload.launch_origin_qpc_timestamp -ne [long]$Control.watchdog.launch_origin_qpc_timestamp -or
                        [long]$payload.resume_qpc_timestamp -ne [long]$Control.watchdog.resume_qpc_timestamp -or
                        [long]$payload.ready_observed_qpc_timestamp -ne [long]$Control.watchdog.ready_observed_qpc_timestamp -or
                        [uint64]$payload.ready_pulse_length -ne [uint64]$Control.watchdog.ready_pulse_length -or
                        [uint64]$payload.startup_deadline_s -ne [uint64]$Startup.guardian_policy.watchdog_startup_deadline_s -or
                        [uint64]$payload.deadline_s -ne [uint64]$Startup.guardian_policy.watchdog_deadline_s -or
                        $readyRelativeTick -lt [decimal]0 -or
                        $readyRelativeTick -gt [decimal][uint64]$record.body.monotonic_tick) {
                        throw "GUARDIAN_WATCHDOG_STARTED has invalid identity, READY, or QPC evidence."
                    }
                }
                "DUAL_CAMPAIGN_STARTED" {
                    & $assertExactProperties $payload @("event", "process_control_sha256") $eventName
                    if ([string]$payload.process_control_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                        [string]$payload.process_control_sha256 -cne [string]$Journal.process_control_binding_sha256) {
                        throw "DUAL_CAMPAIGN_STARTED does not bind the exact process control manifest."
                    }
                }
            }
            $basePosition++
            if ($basePosition -eq $baseEvents.Count) { $phase = "SEMANTIC" }
            $ordinal = [uint64]($ordinal + 1)
            continue
        }
        if ($phase -eq "SEMANTIC") {
            if ($eventName -cne "DUAL_SEMANTIC_READINESS") {
                throw "Launcher journal advanced beyond DUAL launch without semantic readiness."
            }
            & $assertExactProperties $payload @("bindings_sha256", "event") $eventName
            if ([string]$payload.bindings_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                [string]$payload.bindings_sha256 -cne [string]$Journal.campaign_bindings_sha256) {
                throw "DUAL_SEMANTIC_READINESS does not bind the exact campaign bindings manifest."
            }
            $semanticReadiness = $record
            $phase = "PUBLICATION"
            $ordinal = [uint64]($ordinal + 1)
            continue
        }
        if ($phase -eq "PUBLICATION") {
            if ($eventName -cne "DUAL_READINESS_PUBLISHED") {
                throw "Launcher journal advanced beyond semantic readiness without its cross-journal receipt."
            }
            $readinessPublished = $record
            $phase = "CAPTURING"
            $ordinal = [uint64]($ordinal + 1)
            continue
        }
        if ($phase -eq "CAPTURING") {
            if ($eventName -cne "CAPTURE_DRAINING_STARTED") {
                throw "Launcher journal advanced beyond capture without CAPTURE_DRAINING_STARTED."
            }
            & $assertExactProperties $payload @("event", "generation_terminal_deadline_elapsed_s") $eventName
            $null = Assert-MonitorCaptureDrainingTiming -DrainingRecord $record -Startup $Startup -Control $Control
            $captureDraining = $record
            $phase = "TERMINAL_EVIDENCE"
            $ordinal = [uint64]($ordinal + 1)
            continue
        }
        if ($phase -eq "TERMINAL_EVIDENCE") {
            if ($eventName -eq "CAMPAIGN_PROCESS_EXITED") {
                & $assertExactProperties $payload @(
                    "coordinator_elapsed_s", "elapsed_s", "event", "exit_code",
                    "exit_observed_monotonic_tick", "pid", "symbol") $eventName
                $symbol = [string]$payload.symbol
                $controlProcess = @($Control.processes | Where-Object { [string]$_.symbol -ceq $symbol })
                $minimumElapsed = [uint64][math]::Max(0, [int64]$Startup.parameters.total_s - 5)
                if ($symbol -notin @("BTCUSDT", "ETHUSDT") -or
                    $exitRecords.ContainsKey($symbol) -or
                    $controlProcess.Count -ne 1 -or
                    [uint32]$payload.pid -ne [uint32]$controlProcess[0].pid -or
                    [int]$payload.exit_code -ne 0) {
                    throw "CAMPAIGN_PROCESS_EXITED is duplicate, unknown, nonzero, premature, or mismatched."
                }
                $exitObservedTick = [uint64]$payload.exit_observed_monotonic_tick
                $exitPublishedTick = [uint64]$record.body.monotonic_tick
                $captureOriginTick = [uint64]$Control.capture_origin_monotonic_tick
                $coordinatorLaunchTick = [uint64]$controlProcess[0].launch_monotonic_tick
                if ($exitObservedTick -lt $captureOriginTick -or
                    $exitObservedTick -lt $coordinatorLaunchTick -or
                    $exitObservedTick -gt $exitPublishedTick) {
                    throw "CAMPAIGN_PROCESS_EXITED observation/publication timing is invalid."
                }
                $expectedElapsed = Convert-RawQualificationQpcTicksToWholeSeconds `
                    -ElapsedTicks ([long]($exitObservedTick - $captureOriginTick)) `
                    -Frequency ([long][uint64]$Startup.monotonic_frequency)
                $expectedCoordinatorElapsed = Convert-RawQualificationQpcTicksToWholeSeconds `
                    -ElapsedTicks ([long]($exitObservedTick - $coordinatorLaunchTick)) `
                    -Frequency ([long][uint64]$Startup.monotonic_frequency)
                if ([uint64]$payload.elapsed_s -ne $expectedElapsed -or
                    [uint64]$payload.coordinator_elapsed_s -ne $expectedCoordinatorElapsed -or
                    [uint64]$payload.elapsed_s -lt $minimumElapsed -or
                    [uint64]$payload.coordinator_elapsed_s -lt $minimumElapsed) {
                    throw "CAMPAIGN_PROCESS_EXITED elapsed fields do not derive exactly from the observed exit tick."
                }
                if ($null -ne $terminalEvaluation -and
                    $exitObservedTick -gt [uint64]$terminalEvaluation.body.monotonic_tick) {
                    $commitTicks = [long]($exitObservedTick - [uint64]$terminalEvaluation.body.monotonic_tick)
                    if (-not (Test-RawQualificationDeadlineTicks `
                        -ElapsedTicks $commitTicks `
                        -TimeoutSeconds ([uint64]$Startup.guardian_policy.campaign_commit_deadline_s) `
                        -Frequency ([long][uint64]$Startup.monotonic_frequency))) {
                        throw "A campaign coordinator exit is beyond the exact terminal-evaluation deadline."
                    }
                }
                $exitRecords[$symbol] = $record
                $ordinal = [uint64]($ordinal + 1)
                continue
            }
            if ($eventName -eq "CAMPAIGN_TERMINAL_EVALUATION_STARTED") {
                & $assertExactProperties $payload @("commit_deadline_s", "event") $eventName
                if ($null -ne $terminalEvaluation -or
                    [uint64]$payload.commit_deadline_s -ne [uint64]$Startup.guardian_policy.campaign_commit_deadline_s -or
                    [uint64]$record.body.monotonic_tick -lt [uint64]$Control.capture_origin_monotonic_tick) {
                    throw "CAMPAIGN_TERMINAL_EVALUATION_STARTED is duplicate or malformed."
                }
                $terminalEvidenceTicks = [long]([uint64]$record.body.monotonic_tick - [uint64]$Control.capture_origin_monotonic_tick)
                if (-not (Test-RawQualificationDeadlineTicks `
                    -ElapsedTicks $terminalEvidenceTicks `
                    -TimeoutSeconds ([uint64]([uint64]$Startup.parameters.total_s + [uint64]$Startup.guardian_policy.generation_terminal_deadline_s)) `
                    -Frequency ([long][uint64]$Startup.monotonic_frequency))) {
                    throw "Terminal generation evidence was observed after its exact monotonic deadline."
                }
                $terminalEvaluation = $record
                $ordinal = [uint64]($ordinal + 1)
                continue
            }
            if ($eventName -ne "INDEPENDENT_VERIFICATION_STAGE_STARTED" -or
                $null -eq $terminalEvaluation -or $exitRecords.Count -ne 2) {
                throw "Independent verification began without DRAINING, terminal evaluation, and two exact exits."
            }
            & $assertExactProperties $payload @(
                "coordinator_job_drain_contract", "coordinator_job_drain_deadline_s",
                "coordinator_job_drain_elapsed_ms", "coordinator_job_drain_elapsed_ticks",
                "coordinator_job_drain_origin_kind", "coordinator_job_drain_origin_monotonic_tick",
                "coordinator_job_drain_result", "coordinator_job_final_active_processes",
                "coordinator_job_final_query_observed_monotonic_tick",
                "coordinator_job_initial_active_processes", "coordinator_job_monotonic_frequency",
                "coordinator_job_name", "coordinator_job_scope",
                "coordinator_job_observation_count", "coordinator_job_watchdog_liveness_observed_monotonic_tick",
                "coordinator_job_watchdog_pid", "coordinator_job_watchdog_post_query_signaled",
                "coordinator_job_watchdog_pre_query_signaled", "deadline_s", "event") $eventName
            $orderedExitRecords = @($exitRecords.Values | Sort-Object {
                [uint64]$_.body.payload.exit_observed_monotonic_tick
            })
            $latestExitObservedTick = [decimal][uint64]$orderedExitRecords[-1].body.payload.exit_observed_monotonic_tick
            $latestExitPublicationTick = [decimal][uint64](($exitRecords.Values |
                ForEach-Object { [uint64]$_.body.monotonic_tick } |
                Measure-Object -Maximum).Maximum)
            $coordinatorDrainOrigin = [decimal][uint64]$payload.coordinator_job_drain_origin_monotonic_tick
            $coordinatorDrainElapsed = [decimal][long]$payload.coordinator_job_drain_elapsed_ticks
            $finalQueryTick = [decimal][uint64]$payload.coordinator_job_final_query_observed_monotonic_tick
            $watchdogLivenessTick = [decimal][uint64]$payload.coordinator_job_watchdog_liveness_observed_monotonic_tick
            $verificationStageTick = [decimal][uint64]$record.body.monotonic_tick
            $initialActiveProcesses = [uint32]$payload.coordinator_job_initial_active_processes
            $finalActiveProcesses = [uint32]$payload.coordinator_job_final_active_processes
            $observationCount = [uint64]$payload.coordinator_job_observation_count
            if ([uint64]$payload.deadline_s -ne [uint64]$Startup.verifier_policy.total_post_capture_timeout_s -or
                [string]$payload.coordinator_job_drain_contract -cne "RawQualificationCoordinatorWorkloadJobDrainV3" -or
                [string]$payload.coordinator_job_scope -cne "INNER_WORKLOAD_ONLY" -or
                [string]$payload.coordinator_job_name -cne [string]$Control.workload_job_object_name -or
                [string]$payload.coordinator_job_drain_origin_kind -cne "MAX_COORDINATOR_EXIT_OBSERVATION" -or
                [string]$payload.coordinator_job_drain_result -cne "WORKLOAD_EMPTY_WATCHDOG_ALIVE" -or
                [uint64]$payload.coordinator_job_drain_deadline_s -ne 10 -or
                [long]$payload.coordinator_job_monotonic_frequency -ne [long]$Startup.monotonic_frequency -or
                [uint32]$payload.coordinator_job_watchdog_pid -ne [uint32]$Control.watchdog.pid -or
                [bool]$payload.coordinator_job_watchdog_pre_query_signaled -or
                [bool]$payload.coordinator_job_watchdog_post_query_signaled -or
                $finalActiveProcesses -ne 0 -or
                $initialActiveProcesses -lt $finalActiveProcesses -or
                $observationCount -eq 0 -or
                ($initialActiveProcesses -eq 0 -and $observationCount -ne 1) -or
                ($initialActiveProcesses -gt 0 -and $observationCount -lt 2) -or
                $coordinatorDrainOrigin -ne $latestExitObservedTick -or
                $finalQueryTick -lt $latestExitPublicationTick -or
                $finalQueryTick -lt [decimal][uint64]$terminalEvaluation.body.monotonic_tick -or
                $watchdogLivenessTick -lt $finalQueryTick -or
                ($coordinatorDrainOrigin + $coordinatorDrainElapsed) -ne $watchdogLivenessTick -or
                $watchdogLivenessTick -gt $verificationStageTick -or
                -not (Test-MonitorQpcExecutionEvidence `
                    -ResumeQpcTimestamp ([long]$payload.coordinator_job_drain_origin_monotonic_tick) `
                    -ElapsedQpcTicks ([long]$payload.coordinator_job_drain_elapsed_ticks) `
                    -MonotonicFrequency ([long]$payload.coordinator_job_monotonic_frequency) `
                    -ExpectedFrequency ([long]$Startup.monotonic_frequency) `
                    -TimeoutSeconds ([uint64]$payload.coordinator_job_drain_deadline_s) `
                    -ElapsedMilliseconds ([uint64]$payload.coordinator_job_drain_elapsed_ms)) -or
                $verificationStageTick -gt [decimal][uint64]::MaxValue) {
                throw "INDEPENDENT_VERIFICATION_STAGE_STARTED has invalid deadline or coordinator Job-drain evidence."
            }
            $independentVerification = $record
            $phase = "VERIFICATION_TAIL"
            $ordinal = [uint64]($ordinal + 1)
            continue
        }
        if ($phase -ne "VERIFICATION_TAIL" -or $verificationTailPosition -ge $verificationTail.Count) {
            throw "Launcher journal contains an event after its exact terminal causal sequence."
        }
        $expectedTailRecord = $verificationTail[$verificationTailPosition]
        if ($eventName -cne [string]$expectedTailRecord.event) {
            throw "Launcher journal violates the exact sequential dual-verifier/control terminal FSM."
        }
        switch ($eventName) {
            "INDEPENDENT_VERIFIER_STARTED" {
                & $assertExactProperties $payload @("event", "name", "pid") $eventName
                $name = [string]$payload.name
                if ($name -cne [string]$expectedTailRecord.identity -or
                    [uint32]$payload.pid -eq 0 -or $verifierStarted.ContainsKey($name)) {
                    throw "Independent verifier start has an unexpected name, PID, or duplicate identity."
                }
                $verifierStarted[$name] = $record
            }
            "INDEPENDENT_VERIFIER_COMPLETED" {
                & $assertExactProperties $payload @(
                    "event", "execution_sha256", "exit_code", "name", "pid", "stderr_bytes") $eventName
                $name = [string]$payload.name
                if ($name -cne [string]$expectedTailRecord.identity -or
                    -not $verifierStarted.ContainsKey($name) -or $verifierCompleted.ContainsKey($name) -or
                    [uint32]$payload.pid -ne [uint32]$verifierStarted[$name].body.payload.pid -or
                    [int]$payload.exit_code -ne 0 -or [uint64]$payload.stderr_bytes -ne 0 -or
                    [string]$payload.execution_sha256 -cnotmatch '^[0-9a-f]{64}$') {
                    throw "Independent verifier completion does not match one exact successful stderr-free start."
                }
                $verifierCompleted[$name] = $record
            }
            "INDEPENDENT_CAMPAIGN_VERIFIED" {
                & $assertExactProperties $payload @(
                    "event", "python_report_sha256", "rust_report_sha256", "symbol") $eventName
                $symbol = [string]$payload.symbol
                if ($symbol -cne [string]$expectedTailRecord.identity -or $campaignVerified.ContainsKey($symbol) -or
                    [string]$payload.rust_report_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                    [string]$payload.python_report_sha256 -cnotmatch '^[0-9a-f]{64}$') {
                    throw "Independent campaign verification has an unexpected symbol or malformed report hashes."
                }
                $campaignVerified[$symbol] = $record
            }
            "VERIFIER_DESCENDANTS_DRAINED" {
                & $assertExactProperties $payload @(
                    "active_processes", "drain_origin_qpc_timestamp", "elapsed_ms",
                    "elapsed_qpc_ticks", "event", "job_name", "job_scope", "monotonic_frequency") $eventName
                $lastVerifiedRecord = $campaignVerified["ETHUSDT"]
                $drainOrigin = [decimal][long]$payload.drain_origin_qpc_timestamp
                $drainElapsed = [decimal][long]$payload.elapsed_qpc_ticks
                $startupOrigin = [decimal][long]$Startup.monotonic_origin_qpc_timestamp
                $lastVerifiedAbsolute = $startupOrigin + [decimal][uint64]$lastVerifiedRecord.body.monotonic_tick
                $drainEventAbsolute = $startupOrigin + [decimal][uint64]$record.body.monotonic_tick
                if ([uint32]$payload.active_processes -ne 0 -or
                    [string]$payload.job_scope -cne "INNER_WORKLOAD_ONLY" -or
                    [string]$payload.job_name -cne [string]$Control.workload_job_object_name -or
                    $null -eq $lastVerifiedRecord -or
                    $lastVerifiedAbsolute -gt [decimal][long]::MaxValue -or
                    $drainEventAbsolute -gt [decimal][long]::MaxValue -or
                    $drainOrigin -lt $lastVerifiedAbsolute -or
                    ($drainOrigin + $drainElapsed) -gt $drainEventAbsolute -or
                    -not (Test-MonitorQpcExecutionEvidence `
                        -ResumeQpcTimestamp ([long]$payload.drain_origin_qpc_timestamp) `
                        -ElapsedQpcTicks ([long]$payload.elapsed_qpc_ticks) `
                        -MonotonicFrequency ([long]$payload.monotonic_frequency) `
                        -ExpectedFrequency ([long]$Startup.monotonic_frequency) `
                        -TimeoutSeconds 10 `
                        -ElapsedMilliseconds ([uint64]$payload.elapsed_ms))) {
                    throw "VERIFIER_DESCENDANTS_DRAINED lacks exact empty-workload bounded drain evidence."
                }
                $verifierDrained = $record
            }
            "GUARDIAN_WATCHDOG_STOPPED" {
                & $assertExactProperties $payload @(
                    "event", "exit_code", "exit_elapsed_qpc_ticks", "final_job_active_processes",
                    "final_job_drain_elapsed_qpc_ticks", "monotonic_frequency", "pid",
                    "stop_file_sha256", "stop_request_qpc_timestamp") $eventName
                $stopRequest = [long]$payload.stop_request_qpc_timestamp
                $exitTicks = [long]$payload.exit_elapsed_qpc_ticks
                $finalDrainTicks = [long]$payload.final_job_drain_elapsed_qpc_ticks
                $latestStopTicks = [math]::Max($exitTicks, $finalDrainTicks)
                $startupOrigin = [decimal][long]$Startup.monotonic_origin_qpc_timestamp
                $watchdogEventAbsolute = $startupOrigin + [decimal][uint64]$record.body.monotonic_tick
                $verifierDrainAbsolute = $startupOrigin + [decimal][uint64]$verifierDrained.body.monotonic_tick
                if ([uint32]$payload.pid -ne [uint32]$Control.watchdog.pid -or
                    [int]$payload.exit_code -ne 0 -or [uint32]$payload.final_job_active_processes -ne 0 -or
                    [string]$payload.stop_file_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                    $null -eq $verifierDrained -or
                    [decimal]$stopRequest -lt $verifierDrainAbsolute -or
                    [long]$payload.monotonic_frequency -ne [long]$Startup.monotonic_frequency -or
                    $exitTicks -lt 0 -or $finalDrainTicks -lt 0 -or
                    -not (Test-RawQualificationDeadlineTicks -ElapsedTicks $exitTicks -TimeoutSeconds 10 -Frequency ([long]$Startup.monotonic_frequency)) -or
                    -not (Test-RawQualificationDeadlineTicks -ElapsedTicks $finalDrainTicks -TimeoutSeconds 10 -Frequency ([long]$Startup.monotonic_frequency)) -or
                    ([decimal]$stopRequest + [decimal]$exitTicks) -gt $watchdogEventAbsolute -or
                    ([decimal]$stopRequest + [decimal]$finalDrainTicks) -gt $watchdogEventAbsolute -or
                    $watchdogEventAbsolute -gt [decimal][long]::MaxValue) {
                    throw "GUARDIAN_WATCHDOG_STOPPED lacks exact clean bounded retained-watchdog evidence."
                }
            }
            "LAUNCHER_TERMINAL" {
                & $assertExactProperties $payload @(
                    "event", "failure", "failure_containment_sha256", "status", "terminal_bytes",
                    "terminal_file", "terminal_sha256") $eventName
                if ([string]$payload.status -cne "COMPLETE" -or $null -ne $payload.failure -or
                    $null -ne $payload.failure_containment_sha256 -or
                    [string]$payload.terminal_file -cne "launcher-terminal.json" -or
                    -not (Test-RawQualificationJsonInteger $payload.terminal_bytes 1 ([decimal][uint64]::MaxValue)) -or
                    -not (Test-RawQualificationJsonSha256 $payload.terminal_sha256)) {
                    throw "LAUNCHER_TERMINAL is not an exact successful terminal record."
                }
            }
        }
        $verificationTailPosition++
        $ordinal = [uint64]($ordinal + 1)
    }
    return [pscustomobject][ordered]@{
        phase = $phase
        preflight = $preflightRecord
        base_events_observed = [uint64]$basePosition
        verification_tail_position = [uint64]$verificationTailPosition
        semantic_readiness = $semanticReadiness
        readiness_published = $readinessPublished
        capture_draining = $captureDraining
        terminal_evaluation = $terminalEvaluation
        independent_verification = $independentVerification
        campaign_exits = $exitRecords
        verifier_started = $verifierStarted
        verifier_completed = $verifierCompleted
        campaign_verified = $campaignVerified
    }
}

function Assert-LauncherEventHistory {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] $Control,
        [Parameter(Mandatory = $true)] [bool] $TerminalComplete,
        [switch] $SkipSingletonValidation
    )
    if (-not $SkipSingletonValidation) {
        $null = Assert-MonitorStartupControlJsonTypes -Startup $Startup -Control $Control
    }
    $records = @($Journal.all_records)
    if ($records.Count -ne [uint64]$Journal.records) {
        throw "Launcher event scan did not retain every durable record."
    }
    $channelByEvent = @{
        PREFLIGHT_PASSED = "LAUNCHER"
        JOB_OBJECT_ARMED = "CONTROL"
        GUARDIAN_WATCHDOG_STARTED = "CONTROL"
        DUAL_CAMPAIGN_STARTED = "CONTROL"
        DUAL_SEMANTIC_READINESS = "SEMANTIC"
        DUAL_READINESS_PUBLISHED = "SEMANTIC"
        CAPTURE_DRAINING_STARTED = "PROCESS"
        CAMPAIGN_PROCESS_EXITED = "PROCESS"
        CAMPAIGN_TERMINAL_EVALUATION_STARTED = "PROCESS"
        INDEPENDENT_VERIFICATION_STAGE_STARTED = "VERIFICATION"
        INDEPENDENT_VERIFIER_STARTED = "VERIFICATION"
        INDEPENDENT_VERIFIER_COMPLETED = "VERIFICATION"
        INDEPENDENT_CAMPAIGN_VERIFIED = "VERIFICATION"
        VERIFIER_DESCENDANTS_DRAINED = "CONTROL"
        GUARDIAN_WATCHDOG_STOPPED = "CONTROL"
        LAUNCHER_FAILED = "FAILURE"
        FAILURE_CONTAINMENT_TERMINAL = "FAILURE"
        LAUNCHER_TERMINAL = "LAUNCHER"
    }
    $byEvent = @{}
    $previousTick = $null
    foreach ($record in $records) {
        $null = Assert-MonitorLauncherRecordJsonContract -Record $record
        $eventProperty = $record.body.payload.PSObject.Properties['event']
        if ($null -eq $eventProperty -or
            -not $channelByEvent.ContainsKey([string]$eventProperty.Value) -or
            [string]$record.body.channel -cne [string]$channelByEvent[[string]$eventProperty.Value] -or
            ($null -ne $previousTick -and [uint64]$record.body.monotonic_tick -le [uint64]$previousTick)) {
            throw "Launcher journal contains an unknown/mischanneled event or monotonic regression."
        }
        $eventName = [string]$eventProperty.Value
        if (-not $byEvent.ContainsKey($eventName)) { $byEvent[$eventName] = @() }
        $byEvent[$eventName] += $record
        $previousTick = [uint64]$record.body.monotonic_tick
    }
    $count = { param([string] $Name) if ($byEvent.ContainsKey($Name)) { return @($byEvent[$Name]).Count } return 0 }
    if ((& $count "PREFLIGHT_PASSED") -gt 1 -or
        (& $count "JOB_OBJECT_ARMED") -gt 1 -or
        (& $count "GUARDIAN_WATCHDOG_STARTED") -gt 1 -or
        (& $count "DUAL_CAMPAIGN_STARTED") -gt 1 -or
        (& $count "DUAL_SEMANTIC_READINESS") -gt 1 -or
        (& $count "DUAL_READINESS_PUBLISHED") -gt 1 -or
        (& $count "CAPTURE_DRAINING_STARTED") -gt 1 -or
        (& $count "CAMPAIGN_PROCESS_EXITED") -gt 2 -or
        (& $count "CAMPAIGN_TERMINAL_EVALUATION_STARTED") -gt 1 -or
        (& $count "INDEPENDENT_VERIFICATION_STAGE_STARTED") -gt 1 -or
        (& $count "INDEPENDENT_VERIFIER_STARTED") -gt 4 -or
        (& $count "INDEPENDENT_VERIFIER_COMPLETED") -gt 4 -or
        (& $count "INDEPENDENT_CAMPAIGN_VERIFIED") -gt 2 -or
        (& $count "VERIFIER_DESCENDANTS_DRAINED") -gt 1 -or
        (& $count "GUARDIAN_WATCHDOG_STOPPED") -gt 1 -or
        (& $count "LAUNCHER_TERMINAL") -gt 1 -or
        (& $count "LAUNCHER_FAILED") -ne 0) {
        throw "Launcher journal violates unique binding/stage/control cardinalities or contains LAUNCHER_FAILED."
    }
    $semanticReadyCount = & $count "DUAL_SEMANTIC_READINESS"
    $readinessPublishedCount = & $count "DUAL_READINESS_PUBLISHED"
    if ($readinessPublishedCount -gt $semanticReadyCount) {
        throw "Dual readiness publication precedes its unique semantic readiness event."
    }
    $semanticReadyEvent = if ($semanticReadyCount -eq 1) { @($byEvent.DUAL_SEMANTIC_READINESS)[0] } else { $null }
    $readinessPublishedEvent = if ($readinessPublishedCount -eq 1) { @($byEvent.DUAL_READINESS_PUBLISHED)[0] } else { $null }
    if ($null -ne $readinessPublishedEvent) {
        $expectedReceiptProperties = @(
            "bindings_sha256",
            "event",
            "host_telemetry_monotonic_tick",
            "host_telemetry_record_index",
            "host_telemetry_record_sha256") | Sort-Object
        $actualReceiptProperties = @($readinessPublishedEvent.body.payload.PSObject.Properties.Name | Sort-Object)
        if (($actualReceiptProperties -join "`n") -cne ($expectedReceiptProperties -join "`n") -or
            [string]$semanticReadyEvent.body.payload.event -cne "DUAL_SEMANTIC_READINESS" -or
            [string]$readinessPublishedEvent.body.payload.event -cne "DUAL_READINESS_PUBLISHED" -or
            [string]$semanticReadyEvent.body.payload.bindings_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$readinessPublishedEvent.body.payload.bindings_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$readinessPublishedEvent.body.payload.host_telemetry_record_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$readinessPublishedEvent.body.payload.bindings_sha256 -cne [string]$semanticReadyEvent.body.payload.bindings_sha256 -or
            [string]$readinessPublishedEvent.body.payload.bindings_sha256 -cne [string]$Journal.campaign_bindings_sha256 -or
            [uint64]$readinessPublishedEvent.body.record_index -le [uint64]$semanticReadyEvent.body.record_index -or
            [uint64]$readinessPublishedEvent.body.payload.host_telemetry_monotonic_tick -le [uint64]$semanticReadyEvent.body.monotonic_tick -or
            [uint64]$readinessPublishedEvent.body.payload.host_telemetry_monotonic_tick -ge [uint64]$readinessPublishedEvent.body.monotonic_tick) {
            throw "Dual readiness publication receipt has malformed fields, bindings, or cross-journal ordering."
        }
    }
    $causalPrefix = Assert-LauncherCausalPrefix `
        -Records $records `
        -Journal $Journal `
        -Startup $Startup `
        -Control $Control `
        -SkipSingletonValidation:$SkipSingletonValidation
    if ($TerminalComplete) {
        foreach ($expectation in @{
            DUAL_SEMANTIC_READINESS = 1
            DUAL_READINESS_PUBLISHED = 1
            CAPTURE_DRAINING_STARTED = 1
            CAMPAIGN_PROCESS_EXITED = 2
            CAMPAIGN_TERMINAL_EVALUATION_STARTED = 1
            INDEPENDENT_VERIFICATION_STAGE_STARTED = 1
            INDEPENDENT_VERIFIER_STARTED = 4
            INDEPENDENT_VERIFIER_COMPLETED = 4
            INDEPENDENT_CAMPAIGN_VERIFIED = 2
            VERIFIER_DESCENDANTS_DRAINED = 1
            GUARDIAN_WATCHDOG_STOPPED = 1
            LAUNCHER_TERMINAL = 1
        }.GetEnumerator()) {
            if ((& $count ([string]$expectation.Key)) -ne [int]$expectation.Value) {
                throw "Terminal launcher event cardinality is invalid for $($expectation.Key)."
            }
        }
        $terminalRecord = @($byEvent.LAUNCHER_TERMINAL)[0]
        if ([uint64]$terminalRecord.body.record_index -ne ([uint64]$Journal.records - 1) -or
            $terminalRecord.body.payload.status -ne "COMPLETE" -or
            $null -ne $terminalRecord.body.payload.failure -or
            [string]$terminalRecord.body.payload.terminal_file -cne "launcher-terminal.json" -or
            -not (Test-RawQualificationJsonInteger $terminalRecord.body.payload.terminal_bytes 1 ([decimal][uint64]::MaxValue)) -or
            -not (Test-RawQualificationJsonSha256 $terminalRecord.body.payload.terminal_sha256) -or
            $null -ne $terminalRecord.body.payload.failure_containment_sha256) {
            throw "Terminal launcher record is not the unique final COMPLETE event."
        }
        $independentStage = @($byEvent.INDEPENDENT_VERIFICATION_STAGE_STARTED)[0]
        $terminalEvaluation = @($byEvent.CAMPAIGN_TERMINAL_EVALUATION_STARTED)[0]
        $drainingStage = @($byEvent.CAPTURE_DRAINING_STARTED)[0]
        $preflightEvent = @($byEvent.PREFLIGHT_PASSED)[0]
        $jobArmedEvent = @($byEvent.JOB_OBJECT_ARMED)[0]
        $watchdogStartedEvent = @($byEvent.GUARDIAN_WATCHDOG_STARTED)[0]
        $dualStartedEvent = @($byEvent.DUAL_CAMPAIGN_STARTED)[0]
        $verifierDrainedEvent = @($byEvent.VERIFIER_DESCENDANTS_DRAINED)[0]
        $watchdogStoppedEvent = @($byEvent.GUARDIAN_WATCHDOG_STOPPED)[0]
        $terminalExitRecords = @($byEvent.CAMPAIGN_PROCESS_EXITED)
        $latestExitObservedTick = [uint64](($terminalExitRecords |
            ForEach-Object { [uint64]$_.body.payload.exit_observed_monotonic_tick } |
            Measure-Object -Maximum).Maximum)
        $latestExitPublicationTick = [uint64](($terminalExitRecords |
            ForEach-Object { [uint64]$_.body.monotonic_tick } |
            Measure-Object -Maximum).Maximum)
        $coordinatorDrainOriginTick = [uint64]$independentStage.body.payload.coordinator_job_drain_origin_monotonic_tick
        $coordinatorDrainElapsedTicks = [long]$independentStage.body.payload.coordinator_job_drain_elapsed_ticks
        $coordinatorFinalQueryTick = [uint64]$independentStage.body.payload.coordinator_job_final_query_observed_monotonic_tick
        $coordinatorWatchdogLivenessTick = [uint64]$independentStage.body.payload.coordinator_job_watchdog_liveness_observed_monotonic_tick
        $coordinatorInitialCount = [uint32]$independentStage.body.payload.coordinator_job_initial_active_processes
        $coordinatorFinalCount = [uint32]$independentStage.body.payload.coordinator_job_final_active_processes
        $coordinatorObservationCount = [uint64]$independentStage.body.payload.coordinator_job_observation_count
        if ([uint64]$preflightEvent.body.record_index -ne 0 -or
            [string]$preflightEvent.body.payload.startup_sha256 -ne [string]$Journal.startup_binding_sha256 -or
            [uint64]$jobArmedEvent.body.record_index -le [uint64]$preflightEvent.body.record_index -or
            -not [bool]$jobArmedEvent.body.payload.kill_on_close -or
            -not [bool]$jobArmedEvent.body.payload.workload_kill_on_close -or
            [string]$jobArmedEvent.body.payload.name -cne [string]$Control.job_object_name -or
            [string]$jobArmedEvent.body.payload.workload_name -cne [string]$Control.workload_job_object_name -or
            [string]$jobArmedEvent.body.payload.name -ceq [string]$jobArmedEvent.body.payload.workload_name -or
            [uint64]$watchdogStartedEvent.body.record_index -le [uint64]$jobArmedEvent.body.record_index -or
            [uint32]$watchdogStartedEvent.body.payload.pid -ne [uint32]$Control.watchdog.pid -or
            [string]$watchdogStartedEvent.body.payload.ready_file_sha256 -ne [string]$Control.watchdog.ready_file_sha256 -or
            [long]$watchdogStartedEvent.body.payload.launch_origin_qpc_timestamp -ne [long]$Control.watchdog.launch_origin_qpc_timestamp -or
            [long]$watchdogStartedEvent.body.payload.resume_qpc_timestamp -ne [long]$Control.watchdog.resume_qpc_timestamp -or
            [long]$watchdogStartedEvent.body.payload.ready_observed_qpc_timestamp -ne [long]$Control.watchdog.ready_observed_qpc_timestamp -or
            [uint64]$watchdogStartedEvent.body.payload.ready_pulse_length -ne [uint64]$Control.watchdog.ready_pulse_length -or
            [uint64]$watchdogStartedEvent.body.payload.startup_deadline_s -ne [uint64]$Startup.guardian_policy.watchdog_startup_deadline_s -or
            [uint64]$watchdogStartedEvent.body.payload.deadline_s -ne [uint64]$Startup.guardian_policy.watchdog_deadline_s -or
            [uint64]$watchdogStartedEvent.body.monotonic_tick -lt
                [uint64]([long]$Control.watchdog.ready_observed_qpc_timestamp - [long]$Startup.monotonic_origin_qpc_timestamp) -or
            [uint64]$dualStartedEvent.body.record_index -le [uint64]$watchdogStartedEvent.body.record_index -or
            [string]$dualStartedEvent.body.payload.process_control_sha256 -ne [string]$Journal.process_control_binding_sha256 -or
            [uint64]$semanticReadyEvent.body.record_index -le [uint64]$dualStartedEvent.body.record_index -or
            [string]$semanticReadyEvent.body.payload.bindings_sha256 -ne [string]$Journal.campaign_bindings_sha256 -or
            [uint64]$drainingStage.body.record_index -le [uint64]$readinessPublishedEvent.body.record_index -or
            [uint64]$drainingStage.body.payload.generation_terminal_deadline_elapsed_s -ne
                ([uint64]$Startup.parameters.total_s + [uint64]$Startup.guardian_policy.generation_terminal_deadline_s) -or
            [uint64]$terminalEvaluation.body.record_index -le [uint64]$drainingStage.body.record_index -or
            [uint64]$terminalEvaluation.body.payload.commit_deadline_s -ne
                [uint64]$Startup.guardian_policy.campaign_commit_deadline_s -or
            [uint64]$independentStage.body.record_index -le [uint64]$terminalEvaluation.body.record_index -or
            [uint64]$independentStage.body.payload.deadline_s -ne
                [uint64]$Startup.verifier_policy.total_post_capture_timeout_s -or
            [string]$independentStage.body.payload.coordinator_job_drain_contract -cne
                "RawQualificationCoordinatorWorkloadJobDrainV3" -or
            [string]$independentStage.body.payload.coordinator_job_scope -cne
                "INNER_WORKLOAD_ONLY" -or
            [string]$independentStage.body.payload.coordinator_job_name -cne
                [string]$Control.workload_job_object_name -or
            [string]$independentStage.body.payload.coordinator_job_drain_origin_kind -cne
                "MAX_COORDINATOR_EXIT_OBSERVATION" -or
            [string]$independentStage.body.payload.coordinator_job_drain_result -cne
                "WORKLOAD_EMPTY_WATCHDOG_ALIVE" -or
            [uint64]$independentStage.body.payload.coordinator_job_drain_deadline_s -ne 10 -or
            [long]$independentStage.body.payload.coordinator_job_monotonic_frequency -ne
                [long]$Startup.monotonic_frequency -or
            [uint32]$independentStage.body.payload.coordinator_job_watchdog_pid -ne
                [uint32]$Control.watchdog.pid -or
            [bool]$independentStage.body.payload.coordinator_job_watchdog_pre_query_signaled -or
            [bool]$independentStage.body.payload.coordinator_job_watchdog_post_query_signaled -or
            $coordinatorFinalCount -ne 0 -or
            $coordinatorInitialCount -lt $coordinatorFinalCount -or
            $coordinatorObservationCount -eq 0 -or
            ($coordinatorInitialCount -eq 0 -and $coordinatorObservationCount -ne 1) -or
            ($coordinatorInitialCount -gt 0 -and $coordinatorObservationCount -lt 2) -or
            $coordinatorDrainOriginTick -ne $latestExitObservedTick -or
            $coordinatorFinalQueryTick -lt $latestExitPublicationTick -or
            $coordinatorFinalQueryTick -lt [uint64]$terminalEvaluation.body.monotonic_tick -or
            $coordinatorWatchdogLivenessTick -lt $coordinatorFinalQueryTick -or
            ([decimal]$coordinatorDrainOriginTick + [decimal]$coordinatorDrainElapsedTicks) -ne
                [decimal]$coordinatorWatchdogLivenessTick -or
            $coordinatorWatchdogLivenessTick -gt [uint64]$independentStage.body.monotonic_tick -or
            -not (Test-MonitorQpcExecutionEvidence `
                -ResumeQpcTimestamp ([long]$coordinatorDrainOriginTick) `
                -ElapsedQpcTicks $coordinatorDrainElapsedTicks `
                -MonotonicFrequency ([long]$independentStage.body.payload.coordinator_job_monotonic_frequency) `
                -ExpectedFrequency ([long]$Startup.monotonic_frequency) `
                -TimeoutSeconds ([uint64]$independentStage.body.payload.coordinator_job_drain_deadline_s) `
                -ElapsedMilliseconds ([uint64]$independentStage.body.payload.coordinator_job_drain_elapsed_ms)) -or
            $null -eq $verifierDrainedEvent.body.payload.PSObject.Properties['drain_origin_qpc_timestamp'] -or
            $null -eq $verifierDrainedEvent.body.payload.PSObject.Properties['elapsed_qpc_ticks'] -or
            $null -eq $verifierDrainedEvent.body.payload.PSObject.Properties['monotonic_frequency'] -or
            [uint64]$verifierDrainedEvent.body.payload.active_processes -ne 0 -or
            [string]$verifierDrainedEvent.body.payload.job_scope -cne "INNER_WORKLOAD_ONLY" -or
            [string]$verifierDrainedEvent.body.payload.job_name -cne [string]$Control.workload_job_object_name -or
            -not (Test-MonitorQpcExecutionEvidence `
                -ResumeQpcTimestamp ([long]$verifierDrainedEvent.body.payload.drain_origin_qpc_timestamp) `
                -ElapsedQpcTicks ([long]$verifierDrainedEvent.body.payload.elapsed_qpc_ticks) `
                -MonotonicFrequency ([long]$verifierDrainedEvent.body.payload.monotonic_frequency) `
                -ExpectedFrequency ([long]$Startup.monotonic_frequency) `
                -TimeoutSeconds 10 `
                -ElapsedMilliseconds ([uint64]$verifierDrainedEvent.body.payload.elapsed_ms)) -or
            [uint64]$watchdogStoppedEvent.body.record_index -le [uint64]$verifierDrainedEvent.body.record_index -or
            [uint32]$watchdogStoppedEvent.body.payload.pid -ne [uint32]$Control.watchdog.pid -or
            [int]$watchdogStoppedEvent.body.payload.exit_code -ne 0 -or
            [uint32]$watchdogStoppedEvent.body.payload.final_job_active_processes -ne 0) {
            throw "Terminal launcher history violates its exact binding, payload, drain, or ordered control FSM."
        }
        foreach ($exitRecord in @($byEvent.CAMPAIGN_PROCESS_EXITED)) {
            $exitSymbol = [string]$exitRecord.body.payload.symbol
            $controlProcess = @($Control.processes | Where-Object { [string]$_.symbol -eq $exitSymbol })
            $exitObservedTick = [uint64]$exitRecord.body.payload.exit_observed_monotonic_tick
            $expectedElapsed = if ($exitObservedTick -ge [uint64]$Control.capture_origin_monotonic_tick) {
                Convert-RawQualificationQpcTicksToWholeSeconds `
                    -ElapsedTicks ([long]($exitObservedTick - [uint64]$Control.capture_origin_monotonic_tick)) `
                    -Frequency ([long][uint64]$Startup.monotonic_frequency)
            } else { [uint64]::MaxValue }
            $expectedCoordinatorElapsed = if ($controlProcess.Count -eq 1 -and
                $exitObservedTick -ge [uint64]$controlProcess[0].launch_monotonic_tick) {
                Convert-RawQualificationQpcTicksToWholeSeconds `
                    -ElapsedTicks ([long]($exitObservedTick - [uint64]$controlProcess[0].launch_monotonic_tick)) `
                    -Frequency ([long][uint64]$Startup.monotonic_frequency)
            } else { [uint64]::MaxValue }
            if ($controlProcess.Count -ne 1 -or
                [uint32]$exitRecord.body.payload.pid -ne [uint32]$controlProcess[0].pid -or
                [int]$exitRecord.body.payload.exit_code -ne 0 -or
                $exitObservedTick -lt [uint64]$Control.capture_origin_monotonic_tick -or
                $exitObservedTick -lt [uint64]$controlProcess[0].launch_monotonic_tick -or
                $exitObservedTick -gt [uint64]$exitRecord.body.monotonic_tick -or
                [uint64]$exitRecord.body.payload.elapsed_s -ne $expectedElapsed -or
                [uint64]$exitRecord.body.payload.coordinator_elapsed_s -ne $expectedCoordinatorElapsed -or
                [uint64]$exitRecord.body.record_index -le [uint64]$drainingStage.body.record_index -or
                [uint64]$exitRecord.body.record_index -ge [uint64]$independentStage.body.record_index) {
                throw "A terminal campaign exit record is not the exact successful bounded post-drain/pre-verification coordinator proof."
            }
        }
        $captureTicks = [long]([uint64]$terminalEvaluation.body.monotonic_tick - [uint64]$Control.capture_origin_monotonic_tick)
        if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $captureTicks `
            -TimeoutSeconds ([uint64]([uint64]$Startup.parameters.total_s + [uint64]$Startup.guardian_policy.generation_terminal_deadline_s)) `
            -Frequency ([long][uint64]$Startup.monotonic_frequency))) {
            throw "Terminal generation evidence was observed after its exact monotonic deadline."
        }
        $verificationTicks = [long]([uint64]$terminalRecord.body.monotonic_tick - [uint64]$independentStage.body.monotonic_tick)
        if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $verificationTicks `
            -TimeoutSeconds ([uint64]$Startup.verifier_policy.total_post_capture_timeout_s) `
            -Frequency ([long][uint64]$Startup.monotonic_frequency))) {
            throw "LAUNCHER_TERMINAL COMPLETE was published after the exact post-capture verification deadline."
        }
        foreach ($exitRecord in @($byEvent.CAMPAIGN_PROCESS_EXITED)) {
            $exitObservedTick = [uint64]$exitRecord.body.payload.exit_observed_monotonic_tick
            if ($exitObservedTick -gt [uint64]$terminalEvaluation.body.monotonic_tick) {
                $commitTicks = [long]($exitObservedTick - [uint64]$terminalEvaluation.body.monotonic_tick)
                if (-not (Test-RawQualificationDeadlineTicks `
                    -ElapsedTicks $commitTicks `
                    -TimeoutSeconds ([uint64]$Startup.guardian_policy.campaign_commit_deadline_s) `
                    -Frequency ([long][uint64]$Startup.monotonic_frequency))) {
                    throw "A campaign coordinator exited after the exact terminal-evaluation deadline."
                }
            }
        }
        $expectedVerifierNames = @("btcusdt-rust", "btcusdt-python", "ethusdt-rust", "ethusdt-python")
        $started = @{}
        $completed = @{}
        foreach ($start in @($byEvent.INDEPENDENT_VERIFIER_STARTED)) {
            $name = [string]$start.body.payload.name
        if ($expectedVerifierNames -cnotcontains $name -or $started.ContainsKey($name) -or [uint32]$start.body.payload.pid -eq 0) {
                throw "Independent verifier start FSM contains a duplicate/unknown name or invalid PID."
            }
            $started[$name] = $start
        }
        foreach ($complete in @($byEvent.INDEPENDENT_VERIFIER_COMPLETED)) {
            $name = [string]$complete.body.payload.name
            if (-not $started.ContainsKey($name) -or $completed.ContainsKey($name) -or
                [uint32]$complete.body.payload.pid -ne [uint32]$started[$name].body.payload.pid -or
                [uint64]$complete.body.record_index -le [uint64]$started[$name].body.record_index -or
                [int]$complete.body.payload.exit_code -ne 0 -or
                [uint64]$complete.body.payload.stderr_bytes -ne 0 -or
                [string]$complete.body.payload.execution_sha256 -notmatch '^[0-9a-f]{64}$') {
                throw "Independent verifier completion FSM does not match its exact successful start."
            }
            $completed[$name] = $complete
        }
        $campaignVerified = @{}
        foreach ($verified in @($byEvent.INDEPENDENT_CAMPAIGN_VERIFIED)) {
            $verifiedSymbol = [string]$verified.body.payload.symbol
            if ($campaignVerified.ContainsKey($verifiedSymbol) -or
                [string]$verified.body.payload.rust_report_sha256 -notmatch '^[0-9a-f]{64}$' -or
                [string]$verified.body.payload.python_report_sha256 -notmatch '^[0-9a-f]{64}$') {
                throw "Independent campaign verification FSM contains duplicate symbol or malformed report hashes."
            }
            $campaignVerified[$verifiedSymbol] = $verified
        }
        $campaignVerifiedSymbols = @($campaignVerified.Keys | Sort-Object)
        if (($campaignVerifiedSymbols -join ',') -ne "BTCUSDT,ETHUSDT") {
            throw "Independent campaign verification FSM lacks the exact dual symbol set."
        }
        $verificationSequence = @(
            $records |
                Where-Object {
                    [string]$_.body.payload.event -in @(
                        "INDEPENDENT_VERIFIER_STARTED",
                        "INDEPENDENT_VERIFIER_COMPLETED",
                        "INDEPENDENT_CAMPAIGN_VERIFIED")
                } |
                ForEach-Object {
                    if ($_.body.payload.event -eq "INDEPENDENT_CAMPAIGN_VERIFIED") {
                        "INDEPENDENT_CAMPAIGN_VERIFIED:" + [string]$_.body.payload.symbol
                    }
                    else {
                        [string]$_.body.payload.event + ":" + [string]$_.body.payload.name
                    }
                })
        $expectedVerificationSequence = @(
            "INDEPENDENT_VERIFIER_STARTED:btcusdt-rust",
            "INDEPENDENT_VERIFIER_COMPLETED:btcusdt-rust",
            "INDEPENDENT_VERIFIER_STARTED:btcusdt-python",
            "INDEPENDENT_VERIFIER_COMPLETED:btcusdt-python",
            "INDEPENDENT_CAMPAIGN_VERIFIED:BTCUSDT",
            "INDEPENDENT_VERIFIER_STARTED:ethusdt-rust",
            "INDEPENDENT_VERIFIER_COMPLETED:ethusdt-rust",
            "INDEPENDENT_VERIFIER_STARTED:ethusdt-python",
            "INDEPENDENT_VERIFIER_COMPLETED:ethusdt-python",
            "INDEPENDENT_CAMPAIGN_VERIFIED:ETHUSDT")
        if (($verificationSequence -join "`n") -ne ($expectedVerificationSequence -join "`n") -or
            [uint64]$started['btcusdt-rust'].body.record_index -le [uint64]$independentStage.body.record_index -or
            [uint64]$verifierDrainedEvent.body.record_index -le
                [uint64]@($byEvent.INDEPENDENT_CAMPAIGN_VERIFIED | Sort-Object { [uint64]$_.body.record_index })[-1].body.record_index) {
            throw "Independent verifier records violate the exact sequential Rust/Python dual-campaign FSM."
        }
        return [pscustomobject]@{
            preflight = $causalPrefix.preflight
            verifier_started = $started
            verifier_completed = $completed
            campaign_verified = $campaignVerified
            semantic_readiness = $semanticReadyEvent
            readiness_published = $readinessPublishedEvent
            capture_draining = $causalPrefix.capture_draining
            terminal_evaluation = $causalPrefix.terminal_evaluation
            independent_verification = $causalPrefix.independent_verification
        }
    }
    if ((& $count "LAUNCHER_TERMINAL") -ne 0) {
        throw "A nonterminal monitor state contains a hidden LAUNCHER_TERMINAL event."
    }
    return [pscustomobject]@{
        preflight = $causalPrefix.preflight
        verifier_started = $causalPrefix.verifier_started
        verifier_completed = $causalPrefix.verifier_completed
        campaign_verified = $causalPrefix.campaign_verified
        semantic_readiness = $semanticReadyEvent
        readiness_published = $readinessPublishedEvent
        capture_draining = $causalPrefix.capture_draining
        terminal_evaluation = $causalPrefix.terminal_evaluation
        independent_verification = $causalPrefix.independent_verification
    }
}

function Assert-MonitorFailedLauncherV2History {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] $Terminal,
        [Parameter(Mandatory = $true)] $TerminalSnapshot,
        [AllowNull()] $Startup,
        [AllowNull()] $Control
    )
    $records = @($Journal.all_records)
    if ([string]$Terminal.status -cne "FAILED" -or $records.Count -lt 3 -or
        $records.Count -ne [uint64]$Journal.records) {
        throw "FAILED terminal history is absent or incomplete."
    }
    $failedRecords = @($records | Where-Object { [string]$_.body.payload.event -ceq "LAUNCHER_FAILED" })
    $containmentRecords = @($records | Where-Object { [string]$_.body.payload.event -ceq "FAILURE_CONTAINMENT_TERMINAL" })
    $terminalRecords = @($records | Where-Object { [string]$_.body.payload.event -ceq "LAUNCHER_TERMINAL" })
    if ($failedRecords.Count -ne 1 -or $containmentRecords.Count -ne 1 -or $terminalRecords.Count -ne 1) {
        throw "FAILED terminal history does not contain exactly one failure, containment receipt, and post-link."
    }
    $failed = $failedRecords[0]
    $containmentReceipt = $containmentRecords[0]
    $postLink = $terminalRecords[0]
    $previousTick = $null
    $previousWall = $null
    foreach ($record in $records) {
        $null = Assert-MonitorLauncherRecordJsonContract -Record $record
        if (($null -ne $previousTick -and
                [decimal][uint64]$record.body.monotonic_tick -le [decimal][uint64]$previousTick) -or
            ($null -ne $previousWall -and
                [decimal][uint64]$record.body.wall_ns -lt [decimal][uint64]$previousWall)) {
            throw "FAILED launcher journal contains a monotonic or wall-clock regression."
        }
        $previousTick = [uint64]$record.body.monotonic_tick
        $previousWall = [uint64]$record.body.wall_ns
    }
    if ([uint64]$failed.body.record_index + [uint64]1 -ne [uint64]$containmentReceipt.body.record_index -or
        [uint64]$containmentReceipt.body.record_index + [uint64]1 -ne [uint64]$postLink.body.record_index -or
        [uint64]$postLink.body.record_index -ne ([uint64]$Journal.records - 1) -or
        [string]$failed.body.channel -cne "FAILURE" -or
        [string]$containmentReceipt.body.channel -cne "FAILURE" -or
        [string]$postLink.body.channel -cne "LAUNCHER" -or
        [string]$failed.body.payload.error -cne [string]$Terminal.failure -or
        [string]$containmentReceipt.body.payload.failure_containment_sha256 -cne
            [string]$Terminal.failure_containment_sha256 -or
        [string]$postLink.body.payload.status -cne "FAILED" -or
        [string]$postLink.body.payload.failure -cne [string]$Terminal.failure -or
        [string]$postLink.body.payload.failure_containment_sha256 -cne
            [string]$Terminal.failure_containment_sha256 -or
        [string]$postLink.body.payload.terminal_file -cne "launcher-terminal.json" -or
        [uint64]$postLink.body.payload.terminal_bytes -ne [uint64]$TerminalSnapshot.length -or
        [string]$postLink.body.payload.terminal_sha256 -cne [string]$TerminalSnapshot.sha256 -or
        [uint64]$Terminal.launcher_events.records + [uint64]1 -ne [uint64]$Journal.records -or
        [string]$Terminal.launcher_events.terminal_record_sha256 -cne [string]$Journal.penultimate.record_sha256 -or
        [uint64]$Terminal.launcher_events.file_bytes -ne [uint64]$Journal.preterminal_prefix_bytes -or
        [string]$Terminal.launcher_events.file_sha256 -cne [string]$Journal.preterminal_prefix_sha256) {
        throw "FAILED terminal V2 post-link/prefix/containment receipt is not exact."
    }
    $preFailureRecords = @(
        if ([uint64]$failed.body.record_index -ne 0) {
            $records[0..([int][uint64]$failed.body.record_index - 1)]
        }
    )
    $causalPrefixResult = $null
    $basePrefix = @("PREFLIGHT_PASSED", "JOB_OBJECT_ARMED", "GUARDIAN_WATCHDOG_STARTED")
    if ($preFailureRecords.Count -lt 4) {
        for ($index = 0; $index -lt $preFailureRecords.Count; $index++) {
            $record = $preFailureRecords[$index]
            if ([string]$record.body.payload.event -cne $basePrefix[$index]) {
                throw "FAILED launcher prefix is not the exact phase prefix before DUAL launch."
            }
        }
        if ($preFailureRecords.Count -ge 1) {
            if ($null -eq $Startup -or
                [string]$preFailureRecords[0].body.payload.startup_sha256 -cne
                    [string]$Terminal.startup_sha256) {
                throw "PREFLIGHT_PASSED lacks its exact durable startup singleton."
            }
        }
        if ($preFailureRecords.Count -ge 2 -and
            ([bool]$preFailureRecords[1].body.payload.kill_on_close -ne $true -or
             [bool]$preFailureRecords[1].body.payload.workload_kill_on_close -ne $true -or
             [string]$preFailureRecords[1].body.payload.name -cne
                [string]$Terminal.failure_containment.job_name -or
             [string]$preFailureRecords[1].body.payload.workload_name -cne
                ("Local\BinanceRawQualificationWorkloadJob-" + [string]$Startup.run_id) -or
             [string]$preFailureRecords[1].body.payload.name -ceq
                [string]$preFailureRecords[1].body.payload.workload_name)) {
            throw "JOB_OBJECT_ARMED does not bind the outer/workload containment identities."
        }
    }
    else {
        if ($null -eq $Startup -or $null -eq $Control) {
            throw "A DUAL-or-later FAILED prefix lacks startup/process-control singletons."
        }
        $prefixJournal = [pscustomobject]@{
            records = [uint64]$preFailureRecords.Count
            all_records = $preFailureRecords
            startup_binding_sha256 = $Journal.startup_binding_sha256
            process_control_binding_sha256 = $Journal.process_control_binding_sha256
            campaign_bindings_sha256 = $Journal.campaign_bindings_sha256
        }
        $causalPrefixResult = Assert-LauncherCausalPrefix `
            -Records $preFailureRecords `
            -Journal $prefixJournal `
            -Startup $Startup `
            -Control $Control `
            -SkipSingletonValidation
    }
    $phase = switch ($preFailureRecords.Count) {
        0 { "RECORD0"; break }
        1 { "POST_PREFLIGHT"; break }
        2 { "POST_JOB"; break }
        3 { "POST_WATCHDOG"; break }
        4 { "POST_DUAL"; break }
        5 { "SEMANTIC_READY"; break }
        default { "POST_READINESS_OR_LATER"; break }
    }
    $publishedReadiness = @($preFailureRecords | Where-Object {
        [string]$_.body.payload.event -ceq "DUAL_READINESS_PUBLISHED" }).Count -eq 1
    $jobArmed = @($preFailureRecords | Where-Object {
        [string]$_.body.payload.event -ceq "JOB_OBJECT_ARMED" })
    if ($jobArmed.Count -eq 1 -and
        (-not [bool]$Terminal.failure_containment.job_kill_on_close -or
         -not [bool]$Terminal.failure_containment.terminate_attempted -or
         [string]$Terminal.failure_containment.result -ceq "NO_JOB_HANDLE" -or
         [string]$Terminal.failure_containment.job_name -cne [string]$jobArmed[0].body.payload.name -or
         -not [bool]$jobArmed[0].body.payload.workload_kill_on_close -or
         [string]$jobArmed[0].body.payload.workload_name -cne
            ("Local\BinanceRawQualificationWorkloadJob-" + [string]$Startup.run_id) -or
         [string]$jobArmed[0].body.payload.name -ceq [string]$jobArmed[0].body.payload.workload_name)) {
        throw "A JOB_OBJECT_ARMED FAILED prefix is not bound to an attempted containment of that exact Job."
    }
    $prefixLastTick = if ($preFailureRecords.Count -eq 0) {
        [decimal]0
    }
    else { [decimal][uint64]$preFailureRecords[$preFailureRecords.Count - 1].body.monotonic_tick }
    $detectedTick = [decimal][uint64]$Terminal.failure_containment.detected_monotonic_tick
    $terminationTick = [decimal][uint64]$Terminal.failure_containment.termination_monotonic_tick
    $drainTicks = [decimal][uint64]$Terminal.failure_containment.drain_elapsed_qpc_ticks
    $failedTick = [decimal][uint64]$failed.body.monotonic_tick
    $containmentTick = [decimal][uint64]$containmentReceipt.body.monotonic_tick
    $postLinkTick = [decimal][uint64]$postLink.body.monotonic_tick
    if ($prefixLastTick -gt $detectedTick -or $detectedTick -gt $terminationTick -or
        ($terminationTick + $drainTicks) -gt $failedTick -or
        $failedTick -ge $containmentTick -or $containmentTick -ge $postLinkTick -or
        $postLinkTick -gt [decimal][uint64]::MaxValue) {
        throw "FAILED containment and durable suffix are not globally causal on the launcher monotonic clock."
    }
    return [pscustomobject][ordered]@{
        failure_record = $failed
        containment_record = $containmentReceipt
        terminal_record = $postLink
        phase = $phase
        post_readiness = [bool]$publishedReadiness
        containment_certainty = if (@("DRAINED_BY_ATTEMPT", "DRAINED_CONCURRENT_OR_PREEXISTING") -ccontains
            [string]$Terminal.failure_containment.result) { "DRAINED" }
            elseif ([string]$Terminal.failure_containment.result -ceq "NO_JOB_HANDLE") { "NO_JOB_EXISTED" }
            else { "UNCONFIRMED" }
        causal_prefix = $causalPrefixResult
    }
}

function Assert-DualReadinessReceipt {
    param(
        [Parameter(Mandatory = $true)] $Receipt,
        [Parameter(Mandatory = $true)] $TelemetryJournal,
        [Parameter(Mandatory = $true)] $Bindings,
        [Parameter(Mandatory = $true)] [string] $ExpectedBindingsSha256
    )
    if ($null -eq $Receipt -or
        [string]$Receipt.body.payload.event -cne "DUAL_READINESS_PUBLISHED" -or
        [string]$Receipt.body.payload.bindings_sha256 -cne $ExpectedBindingsSha256) {
        throw "Dual readiness publication receipt is absent or does not bind campaign-bindings.json."
    }
    $referencedIndex = [uint64]$Receipt.body.payload.host_telemetry_record_index
    $referencedRecords = @(
        $TelemetryJournal.all_records |
            Where-Object { [uint64]$_.body.record_index -eq $referencedIndex })
    if ($referencedRecords.Count -ne 1) {
        throw "Dual readiness publication does not reference exactly one verified host telemetry record."
    }
    $hostRecord = $referencedRecords[0]
    if ($hostRecord.body.schema -cne "RawQualificationHostTelemetryRecordV1" -or
        $hostRecord.body.channel -cne "HOST" -or
        [string]$hostRecord.record_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$hostRecord.record_sha256 -cne [string]$Receipt.body.payload.host_telemetry_record_sha256 -or
        [uint64]$hostRecord.body.monotonic_tick -ne [uint64]$Receipt.body.payload.host_telemetry_monotonic_tick) {
        throw "Dual readiness publication receipt does not match the exact verified host telemetry envelope."
    }
    $hostCampaignsProperty = $hostRecord.body.payload.PSObject.Properties['campaigns']
    if ($null -eq $hostCampaignsProperty -or @($hostCampaignsProperty.Value).Count -ne 2 -or @($Bindings.campaigns).Count -ne 2) {
        throw "Dual readiness host telemetry does not contain the exact two bound campaigns."
    }
    $hostBySymbol = @{}
    foreach ($campaign in @($hostCampaignsProperty.Value)) {
        $requiredProperties = @("symbol", "pid", "campaign_id", "ready", "exited", "generations", "active_processes")
        foreach ($property in $requiredProperties) {
            if ($null -eq $campaign.PSObject.Properties[$property]) {
                throw "Dual readiness host telemetry lacks required campaign field $property."
            }
        }
        $symbol = [string]$campaign.symbol
        if (($symbol -cne "BTCUSDT" -and $symbol -cne "ETHUSDT") -or $hostBySymbol.ContainsKey($symbol)) {
            throw "Dual readiness host telemetry has a duplicate or unexpected symbol."
        }
        $hostBySymbol[$symbol] = $campaign
    }
    foreach ($binding in @($Bindings.campaigns)) {
        $symbol = [string]$binding.symbol
        if (-not $hostBySymbol.ContainsKey($symbol)) {
            throw "Dual readiness host telemetry lacks bound symbol $symbol."
        }
        $campaign = $hostBySymbol[$symbol]
        if (($symbol -cne "BTCUSDT" -and $symbol -cne "ETHUSDT") -or
            $campaign.symbol -isnot [string] -or
            $campaign.pid -is [string] -or
            $campaign.pid -is [bool] -or
            $campaign.campaign_id -isnot [string] -or
            [uint32]$campaign.pid -ne [uint32]$binding.pid -or
            [string]$campaign.campaign_id -cne [string]$binding.campaign_id -or
            $campaign.ready -isnot [bool] -or
            $campaign.exited -isnot [bool] -or
            -not [bool]$campaign.ready -or
            [bool]$campaign.exited -or
            $campaign.generations -is [string] -or
            $campaign.generations -is [bool] -or
            $campaign.active_processes -is [string] -or
            $campaign.active_processes -is [bool] -or
            [uint64]$campaign.generations -lt 1 -or
            [uint64]$campaign.active_processes -lt 1) {
            throw "Dual readiness host telemetry is not the exact active ready state for $symbol."
        }
    }
    return $true
}

function Assert-MonitorRustCampaignJournalEnvelopeJsonTypes {
    param([Parameter(Mandatory = $true)] $Envelope)
    $u64 = [decimal][uint64]::MaxValue
    if (-not (Test-MonitorExactJsonPropertyOrder $Envelope @("body", "record_sha256")) -or
        -not (Test-MonitorExactJsonPropertyOrder $Envelope.body @(
                "schema", "record_index", "wall_ns", "campaign_mono_ns", "generation_index",
                "channel", "payload", "previous_record_sha256")) -or
        -not (Test-RawQualificationJsonString $Envelope.body.schema) -or
        [string]$Envelope.body.schema -cne "RawCampaignJournalRecordV1" -or
        -not (Test-RawQualificationJsonInteger $Envelope.body.record_index 0 $u64) -or
        -not (Test-RawQualificationJsonInteger $Envelope.body.wall_ns 1 $u64) -or
        -not (Test-RawQualificationJsonInteger $Envelope.body.campaign_mono_ns 0 $u64) -or
        -not (Test-MonitorJsonNullOrInteger $Envelope.body.generation_index 0 $u64) -or
        -not (Test-RawQualificationJsonString $Envelope.body.channel) -or
        -not (Test-RawQualificationJsonSha256 $Envelope.body.previous_record_sha256) -or
        -not (Test-RawQualificationJsonSha256 $Envelope.record_sha256) -or
        $null -eq $Envelope.body.payload -or
        $null -eq $Envelope.body.payload.PSObject) {
        throw "Rust campaign journal envelope contains a coercible/out-of-range field or an unexpected property set."
    }
    return $true
}

function Assert-MonitorRustCampaignPayloadJsonContract {
    param(
        [Parameter(Mandatory = $true)] $Payload,
        [Parameter(Mandatory = $true)] [string] $Channel,
        [AllowNull()] $GenerationIndex
    )
    $u64 = [decimal][uint64]::MaxValue
    $u32 = [decimal][uint32]::MaxValue
    $eventProperty = $Payload.PSObject.Properties['event']
    if ($null -eq $eventProperty -or -not (Test-RawQualificationJsonString $eventProperty.Value)) {
        throw "Rust campaign journal payload lacks an exact nonempty string event."
    }
    $event = [string]$eventProperty.Value
    $allowedByChannel = @{
        CAMPAIGN = @("CAMPAIGN_STARTED", "GENERATION_LAUNCHED", "GENERATION_LAUNCHED_SERVER_SHUTDOWN",
            "GENERATION_EXITED", "HANDOVER_PROOF_STARTED", "CAMPAIGN_EVALUATION_PREPARED",
            "CAMPAIGN_COMMITTED", "CAMPAIGN_FAILED")
        CHILD_STDOUT = @("PROCESS_STARTED", "TRANSPORT_CONNECTED", "SNAPSHOT_DURABLE",
            "SEGMENT_DURABLE", "SERVER_SHUTDOWN_DURABLE", "HEARTBEAT_DURABLE", "PROCESS_TERMINAL")
        CHILD_STDERR = @("CHILD_STDERR_TEXT")
        SUPERVISOR = @("INITIAL_ACTIVE_REGISTERED", "CANDIDATE_REGISTERED",
            "HANDOVER_PROVEN_AND_PROMOTED", "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE",
            "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING", "GENERATION_DISCONNECT_FAIL_CLOSED")
    }
    if (-not $allowedByChannel.ContainsKey($Channel)) {
        throw "Rust campaign journal channel is unknown or case-mismatched: $Channel"
    }
    if ($Channel -ceq "CHILD_STDERR") {
        if (-not (Test-MonitorExactJsonProperties $Payload @("text")) -or
            -not (Test-RawQualificationJsonString $Payload.text -AllowEmpty)) {
            throw "Rust child stderr record has an invalid payload."
        }
        return "CHILD_STDERR_TEXT"
    }
    if (-not ($allowedByChannel[$Channel] -ccontains $event)) {
        throw "Rust campaign event $event is unknown or invalid for channel $Channel."
    }
    $generationScoped = $event -notin @("CAMPAIGN_STARTED", "CAMPAIGN_EVALUATION_PREPARED",
        "CAMPAIGN_COMMITTED", "CAMPAIGN_FAILED")
    if (($generationScoped -and $null -eq $GenerationIndex) -or
        (-not $generationScoped -and $null -ne $GenerationIndex)) {
        throw "Rust campaign event $event has an invalid generation scope."
    }
    switch -CaseSensitive ($event) {
        "CAMPAIGN_STARTED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @("campaign_id", "event", "startup_sha256")) -or
                -not (Test-RawQualificationJsonString $Payload.campaign_id) -or
                -not (Test-RawQualificationJsonSha256 $Payload.startup_sha256)) { throw "$event payload is invalid." }
        }
        "GENERATION_LAUNCHED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @("duration_s", "event")) -or
                -not (Test-RawQualificationJsonInteger $Payload.duration_s 1 604800)) { throw "$event payload is invalid." }
        }
        "GENERATION_LAUNCHED_SERVER_SHUTDOWN" {
            if (-not (Test-MonitorExactJsonProperties $Payload @(
                        "duration_s", "event", "source_epoch", "source_generation")) -or
                -not (Test-RawQualificationJsonInteger $Payload.duration_s 1 604800) -or
                -not (Test-RawQualificationJsonString $Payload.source_epoch) -or
                -not (Test-RawQualificationJsonInteger $Payload.source_generation 0 $u64)) { throw "$event payload is invalid." }
        }
        "GENERATION_EXITED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @("code", "event", "success")) -or
                -not (Test-RawQualificationJsonInteger $Payload.code 0 $u32) -or
                -not (Test-RawQualificationJsonBoolean $Payload.success) -or
                (([bool]$Payload.success -and [uint64]$Payload.code -ne 0) -or
                 (-not [bool]$Payload.success -and [uint64]$Payload.code -eq 0))) {
                throw "$event payload is invalid."
            }
        }
        "HANDOVER_PROOF_STARTED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @("event", "predecessor")) -or
                -not (Test-RawQualificationJsonInteger $Payload.predecessor 0 $u64)) { throw "$event payload is invalid." }
        }
        "CAMPAIGN_EVALUATION_PREPARED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @("event"))) { throw "$event payload is invalid." }
        }
        "CAMPAIGN_COMMITTED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @("event", "manifest_file", "manifest_sha256")) -or
                [string]$Payload.manifest_file -cne "campaign.json" -or
                -not (Test-RawQualificationJsonSha256 $Payload.manifest_sha256)) { throw "$event payload is invalid." }
        }
        "CAMPAIGN_FAILED" {
            $validSet = (Test-MonitorExactJsonProperties $Payload @("error", "event")) -or
                (Test-MonitorExactJsonProperties $Payload @("error", "event", "stage"))
            if (-not $validSet -or -not (Test-RawQualificationJsonString $Payload.error) -or
                ($null -ne $Payload.PSObject.Properties['stage'] -and
                    [string]$Payload.stage -cnotin @("RUNTIME", "TERMINAL_EVALUATION"))) {
                throw "$event payload is invalid."
            }
        }
        "INITIAL_ACTIVE_REGISTERED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @("event"))) { throw "$event payload is invalid." }
        }
        "CANDIDATE_REGISTERED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @("event"))) { throw "$event payload is invalid." }
        }
        { $_ -ceq "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE" -or $_ -ceq "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING" } {
            if (-not (Test-MonitorExactJsonProperties $Payload @("event", "source_epoch")) -or
                -not (Test-RawQualificationJsonString $Payload.source_epoch)) { throw "$event payload is invalid." }
        }
        "GENERATION_DISCONNECT_FAIL_CLOSED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @("epoch", "event", "gap_count", "outcome")) -or
                -not (Test-RawQualificationJsonString $Payload.epoch) -or
                -not (Test-RawQualificationJsonInteger $Payload.gap_count 1 $u64) -or
                -not (Test-RawQualificationJsonString $Payload.outcome)) { throw "$event payload is invalid." }
        }
        "HANDOVER_PROVEN_AND_PROMOTED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @("event", "predecessor", "proof_sha256")) -or
                -not (Test-RawQualificationJsonInteger $Payload.predecessor 0 $u64) -or
                -not (Test-RawQualificationJsonSha256 $Payload.proof_sha256)) { throw "$event payload is invalid." }
        }
        "PROCESS_STARTED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @(
                        "event", "generation_index", "process_id", "schema", "session_dir", "session_id",
                        "spec_revision", "startup_manifest_sha256", "symbol")) -or
                [string]$Payload.schema -cne "CaptureProcessEventV1" -or
                -not (Test-RawQualificationJsonInteger $Payload.generation_index 0 $u64) -or
                -not (Test-RawQualificationJsonInteger $Payload.process_id 1 $u32) -or
                -not (Test-RawQualificationJsonString $Payload.session_dir) -or
                -not (Test-RawQualificationJsonString $Payload.session_id) -or
                -not (Test-RawQualificationJsonString $Payload.spec_revision) -or
                -not (Test-RawQualificationJsonSha256 $Payload.startup_manifest_sha256) -or
                -not (Test-RawQualificationJsonString $Payload.symbol)) { throw "$event payload is invalid." }
        }
        "TRANSPORT_CONNECTED" {
            if (-not (Test-MonitorExactJsonProperties $Payload @(
                        "connection", "event", "metadata_file", "metadata_sha256", "schema", "session_id")) -or
                [string]$Payload.schema -cne "TransportConnectedProcessEventV1" -or
                -not (Test-RawQualificationJsonString $Payload.session_id) -or
                -not (Test-RawQualificationJsonString $Payload.metadata_file) -or
                -not (Test-RawQualificationJsonSha256 $Payload.metadata_sha256) -or
                -not (Test-MonitorExactJsonProperties $Payload.connection @(
                        "connection_epoch", "local_endpoint", "remote_endpoint", "response_headers", "stream",
                        "uri", "websocket_http_status")) -or
                -not (Test-RawQualificationJsonString $Payload.connection.connection_epoch) -or
                -not (Test-RawQualificationJsonString $Payload.connection.local_endpoint) -or
                -not (Test-RawQualificationJsonString $Payload.connection.remote_endpoint) -or
                -not (Test-RawQualificationJsonString $Payload.connection.stream) -or
                -not (Test-RawQualificationJsonString $Payload.connection.uri) -or
                -not (Test-RawQualificationJsonInteger $Payload.connection.websocket_http_status 100 599)) {
                throw "$event payload is invalid."
            }
            foreach ($header in @($Payload.connection.response_headers.PSObject.Properties)) {
                if ($header.Value -isnot [System.Array]) { throw "$event response header is not a JSON string array." }
                foreach ($value in @($header.Value)) {
                    if (-not (Test-RawQualificationJsonString $value -AllowEmpty)) { throw "$event response header contains a non-string." }
                }
            }
        }
        "SNAPSHOT_DURABLE" {
            if (-not (Test-MonitorExactJsonProperties $Payload @(
                        "durable_through_offset", "event", "http_metadata_file", "http_metadata_sha256",
                        "last_record_sha256", "raw_file", "schema", "session_id")) -or
                [string]$Payload.schema -cne "SnapshotDurableProcessEventV1" -or
                -not (Test-RawQualificationJsonString $Payload.session_id) -or
                -not (Test-RawQualificationJsonString $Payload.raw_file) -or
                -not (Test-RawQualificationJsonInteger $Payload.durable_through_offset 1 $u64) -or
                -not (Test-RawQualificationJsonSha256 $Payload.last_record_sha256) -or
                -not (Test-RawQualificationJsonString $Payload.http_metadata_file) -or
                -not (Test-RawQualificationJsonSha256 $Payload.http_metadata_sha256)) { throw "$event payload is invalid." }
        }
        "SEGMENT_DURABLE" {
            $segment = $Payload.segment
            if (-not (Test-MonitorExactJsonProperties $Payload @("event", "schema", "segment", "session_id")) -or
                [string]$Payload.schema -cne "SegmentDurableProcessEventV1" -or
                -not (Test-RawQualificationJsonString $Payload.session_id) -or
                -not (Test-MonitorExactJsonProperties $segment @(
                        "connection_epoch", "durable_through_offset", "first_frame_index", "last_frame_index",
                        "manifest_durable_through_offset", "manifest_record_index", "manifest_record_sha256",
                        "previous_segment_terminal_sha256", "raw_file", "records", "schema", "segment_index",
                        "stream", "terminal_record_sha256")) -or
                [string]$segment.schema -cne "DurableSegmentEventV1" -or
                -not (Test-RawQualificationJsonString $segment.stream) -or
                -not (Test-RawQualificationJsonString $segment.connection_epoch) -or
                -not (Test-RawQualificationJsonString $segment.raw_file)) { throw "$event payload is invalid." }
            foreach ($name in @("segment_index", "first_frame_index", "last_frame_index", "records",
                    "durable_through_offset", "manifest_record_index", "manifest_durable_through_offset")) {
                if (-not (Test-RawQualificationJsonInteger $segment.PSObject.Properties[$name].Value 0 $u64)) {
                    throw "$event contains an untyped/out-of-range integer: $name"
                }
            }
            foreach ($name in @("previous_segment_terminal_sha256", "terminal_record_sha256", "manifest_record_sha256")) {
                if (-not (Test-RawQualificationJsonSha256 $segment.PSObject.Properties[$name].Value)) {
                    throw "$event contains a malformed digest: $name"
                }
            }
        }
        "SERVER_SHUTDOWN_DURABLE" {
            $shutdown = $Payload.shutdown
            if (-not (Test-MonitorExactJsonProperties $Payload @("event", "schema", "session_id", "shutdown")) -or
                [string]$Payload.schema -cne "ServerShutdownDurableProcessEventV1" -or
                -not (Test-RawQualificationJsonString $Payload.session_id) -or
                -not (Test-MonitorExactJsonProperties $shutdown @(
                        "connection_epoch", "durable_record_count", "durable_through_offset", "frame_index",
                        "last_record_sha256", "raw_file", "receive_mono_ns", "schema", "segment_index", "stream")) -or
                [string]$shutdown.schema -cne "DurableServerShutdownEventV1" -or
                -not (Test-RawQualificationJsonString $shutdown.stream) -or
                -not (Test-RawQualificationJsonString $shutdown.connection_epoch) -or
                -not (Test-RawQualificationJsonString $shutdown.raw_file) -or
                -not (Test-RawQualificationJsonSha256 $shutdown.last_record_sha256)) { throw "$event payload is invalid." }
            foreach ($name in @("segment_index", "frame_index", "receive_mono_ns", "durable_record_count", "durable_through_offset")) {
                if (-not (Test-RawQualificationJsonInteger $shutdown.PSObject.Properties[$name].Value 0 $u64)) {
                    throw "$event contains an untyped/out-of-range integer: $name"
                }
            }
        }
        "HEARTBEAT_DURABLE" {
            $names = @("depth_durable", "depth_last_durable_mono_ns", "depth_last_market_message_mono_ns",
                "depth_last_socket_activity_mono_ns", "depth_queue_records", "depth_received", "event", "schema",
                "session_id", "telemetry_durable_through_offset", "telemetry_mono_ns", "telemetry_record_index",
                "telemetry_record_sha256", "trade_durable", "trade_last_durable_mono_ns",
                "trade_last_market_message_mono_ns", "trade_last_socket_activity_mono_ns", "trade_queue_records",
                "trade_received")
            if (-not (Test-MonitorExactJsonProperties $Payload $names) -or
                [string]$Payload.schema -cne "HeartbeatProcessEventV1" -or
                -not (Test-RawQualificationJsonString $Payload.session_id) -or
                -not (Test-RawQualificationJsonSha256 $Payload.telemetry_record_sha256)) { throw "$event payload is invalid." }
            foreach ($name in @("telemetry_record_index", "telemetry_durable_through_offset", "telemetry_mono_ns",
                    "depth_received", "depth_durable", "depth_queue_records", "depth_last_socket_activity_mono_ns",
                    "depth_last_market_message_mono_ns", "depth_last_durable_mono_ns", "trade_received",
                    "trade_durable", "trade_queue_records", "trade_last_socket_activity_mono_ns",
                    "trade_last_market_message_mono_ns", "trade_last_durable_mono_ns")) {
                if (-not (Test-RawQualificationJsonInteger $Payload.PSObject.Properties[$name].Value 0 $u64)) {
                    throw "$event contains an untyped/out-of-range integer: $name"
                }
            }
        }
        "PROCESS_TERMINAL" {
            if (-not (Test-MonitorExactJsonProperties $Payload @(
                        "event", "generation_manifest", "schema", "session_id", "status")) -or
                [string]$Payload.schema -cne "CaptureTerminalProcessEventV1" -or
                -not (Test-RawQualificationJsonString $Payload.session_id) -or
                [string]$Payload.status -cnotin @("COMPLETE", "FAILED") -or
                [string]$Payload.generation_manifest -cne "generation.json") { throw "$event payload is invalid." }
        }
        default { throw "Rust campaign journal contains an unknown future event: $event" }
    }
    return $event
}

function Get-CampaignJournalHealth {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        $CampaignStartup,
        [string] $CampaignStartupSha256,
        [AllowNull()] $ExpectedPrefixRecords,
        [AllowNull()] $ExpectedPrefixTerminalRecordSha256,
        [AllowNull()] $ExpectedPrefixFileLength,
        [AllowNull()] $ExpectedPrefixFileSha256,
        [AllowNull()] $ContinuationState
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing campaign journal: $Path" }
    $prefixParameterNames = @(
        'ExpectedPrefixRecords', 'ExpectedPrefixTerminalRecordSha256',
        'ExpectedPrefixFileLength', 'ExpectedPrefixFileSha256')
    $boundPrefixParameterCount = @($prefixParameterNames | Where-Object {
        $PSBoundParameters.ContainsKey($_)
    }).Count
    if ($boundPrefixParameterCount -ne 0 -and $boundPrefixParameterCount -ne $prefixParameterNames.Count) {
        throw "Campaign journal prefix continuity requires all four exact prefix fields."
    }
    $verifyPrefixContinuity = $boundPrefixParameterCount -eq $prefixParameterNames.Count
    if ($verifyPrefixContinuity -and
        ($ExpectedPrefixRecords -isnot [uint64] -or [uint64]$ExpectedPrefixRecords -lt 1 -or
         $ExpectedPrefixTerminalRecordSha256 -isnot [string] -or
         -not ([string]$ExpectedPrefixTerminalRecordSha256 -cmatch '^[0-9a-f]{64}$') -or
         $ExpectedPrefixFileLength -isnot [uint64] -or [uint64]$ExpectedPrefixFileLength -lt 1 -or
         $ExpectedPrefixFileSha256 -isnot [string] -or
         -not ([string]$ExpectedPrefixFileSha256 -cmatch '^[0-9a-f]{64}$'))) {
        throw "Campaign journal prefix continuity fields have invalid types or values."
    }
    if ($null -ne $ContinuationState) {
        $continuationProperties = @(
            "schema", "path", "campaign_startup_sha256", "observed_file_length",
            "observed_file_sha256", "complete_length", "complete_sha256",
            "next_index", "previous_digest", "latest_heartbeat", "previous_heartbeat",
            "process_started", "snapshot_durable", "transports", "failed", "failure_reason",
            "failure_record_sha256", "terminal_status",
            "committed", "commit_manifest_file", "commit_manifest_sha256", "last_record_channel",
            "last_record_event", "generation_health", "planned_generation_launches",
            "server_shutdown_generation_launches", "server_shutdown_events",
            "server_shutdown_supervisor_events", "server_shutdown_durable_events",
            "child_stderr_events", "campaign_started_count", "campaign_prepared_count",
            "prepared_record_index", "prepared_record_sha256", "previous_wall_ns",
            "previous_campaign_mono_ns", "initial_active_registered", "active_generation",
            "pending_candidate", "warmed_generation", "candidate_registered", "proof_started",
            "promoted")
        if (-not $verifyPrefixContinuity -or
            -not (Test-MonitorExactJsonProperties $ContinuationState $continuationProperties) -or
            [string]$ContinuationState.schema -cne "MonitorCampaignJournalContinuationV1" -or
            [IO.Path]::GetFullPath([string]$ContinuationState.path) -cne [IO.Path]::GetFullPath($Path) -or
            [string]$ContinuationState.campaign_startup_sha256 -cne [string]$CampaignStartupSha256 -or
            $ContinuationState.observed_file_length -isnot [uint64] -or
            [uint64]$ContinuationState.observed_file_length -ne [uint64]$ExpectedPrefixFileLength -or
            [string]$ContinuationState.observed_file_sha256 -cne [string]$ExpectedPrefixFileSha256 -or
            $ContinuationState.complete_length -isnot [uint64] -or
            [uint64]$ContinuationState.complete_length -gt [uint64]$ContinuationState.observed_file_length -or
            $ContinuationState.complete_sha256 -isnot [string] -or
            -not ([string]$ContinuationState.complete_sha256 -cmatch '^[0-9a-f]{64}$') -or
            [uint64]$ContinuationState.next_index -ne [uint64]$ExpectedPrefixRecords -or
            [string]$ContinuationState.previous_digest -cne [string]$ExpectedPrefixTerminalRecordSha256) {
            throw "Campaign journal continuation is not exactly bound to its authenticated prefix."
        }
        if ($ContinuationState.next_index -isnot [uint64] -or
            $ContinuationState.previous_digest -isnot [string] -or
            $ContinuationState.process_started -isnot [bool] -or
            $ContinuationState.snapshot_durable -isnot [bool] -or
            $ContinuationState.failed -isnot [bool] -or
            $ContinuationState.committed -isnot [bool] -or
            $ContinuationState.initial_active_registered -isnot [bool] -or
            $ContinuationState.transports -isnot [Collections.Generic.HashSet[string]] -or
            $ContinuationState.candidate_registered -isnot [Collections.Generic.HashSet[string]] -or
            $ContinuationState.proof_started -isnot [Collections.Generic.HashSet[string]] -or
            $ContinuationState.promoted -isnot [Collections.Generic.HashSet[string]] -or
            $ContinuationState.generation_health -isnot [hashtable]) {
            throw "Campaign journal continuation contains an invalid in-memory parser state."
        }
    }
    $snapshotArguments = @{ Path = $Path }
    if ($verifyPrefixContinuity) {
        $snapshotArguments.ExpectedPrefixLength = [uint64]$ExpectedPrefixFileLength
        $snapshotArguments.ExpectedPrefixSha256 = [string]$ExpectedPrefixFileSha256
        if ($null -ne $ContinuationState) {
            $snapshotArguments.ParseFromOffset = [uint64]$ContinuationState.complete_length
            $snapshotArguments.ParseFromOffsetSha256 = [string]$ContinuationState.complete_sha256
        }
    }
    $snapshot = Read-MonitorFrozenCanonicalJsonLines @snapshotArguments
    $snapshotLength = [uint64]$snapshot.file_length
    $endsWithNewline = -not [bool]$snapshot.partial_tail
    $sourceLines = [Collections.Generic.List[string]]::new()
    foreach ($snapshotLine in @($snapshot.lines)) { $sourceLines.Add($snapshotLine) }
    if ($snapshot.partial_tail) { $sourceLines.Add("__IGNORED_PARTIAL_TAIL_SENTINEL__") }
    try {
        $pending = $null
        if ($null -ne $ContinuationState) {
            $nextIndex = [uint64]$ContinuationState.next_index
            $previousDigest = [string]$ContinuationState.previous_digest
            $latestHeartbeat = $ContinuationState.latest_heartbeat
            $previousHeartbeat = $ContinuationState.previous_heartbeat
            $processStarted = [bool]$ContinuationState.process_started
            $snapshotDurable = [bool]$ContinuationState.snapshot_durable
            $transports = $ContinuationState.transports
            $failed = [bool]$ContinuationState.failed
            $failureReason = $ContinuationState.failure_reason
            $failureRecordSha256 = $ContinuationState.failure_record_sha256
            $terminalStatus = $ContinuationState.terminal_status
            $committed = [bool]$ContinuationState.committed
            $commitManifestFile = $ContinuationState.commit_manifest_file
            $commitManifestSha256 = $ContinuationState.commit_manifest_sha256
            $lastRecordChannel = $ContinuationState.last_record_channel
            $lastRecordEvent = $ContinuationState.last_record_event
            $generationHealth = $ContinuationState.generation_health
            $plannedGenerationLaunches = [uint64]$ContinuationState.planned_generation_launches
            $serverShutdownGenerationLaunches = [uint64]$ContinuationState.server_shutdown_generation_launches
            $serverShutdownEvents = [uint64]$ContinuationState.server_shutdown_events
            $serverShutdownSupervisorEvents = [uint64]$ContinuationState.server_shutdown_supervisor_events
            $serverShutdownDurableEvents = [uint64]$ContinuationState.server_shutdown_durable_events
            $childStderrEvents = [uint64]$ContinuationState.child_stderr_events
            $campaignStartedCount = [uint64]$ContinuationState.campaign_started_count
            $campaignPreparedCount = [uint64]$ContinuationState.campaign_prepared_count
            $preparedRecordIndex = $ContinuationState.prepared_record_index
            $preparedRecordSha256 = $ContinuationState.prepared_record_sha256
            $previousWallNs = [uint64]$ContinuationState.previous_wall_ns
            $previousCampaignMonoNs = [uint64]$ContinuationState.previous_campaign_mono_ns
            $initialActiveRegistered = [bool]$ContinuationState.initial_active_registered
            $activeGeneration = $ContinuationState.active_generation
            $pendingCandidate = $ContinuationState.pending_candidate
            $warmedGeneration = $ContinuationState.warmed_generation
            $candidateRegistered = $ContinuationState.candidate_registered
            $proofStarted = $ContinuationState.proof_started
            $promoted = $ContinuationState.promoted
        }
        else {
            $nextIndex = [uint64]0
            $previousDigest = "0" * 64
            $latestHeartbeat = $null
            $previousHeartbeat = $null
            $processStarted = $false
            $snapshotDurable = $false
            $transports = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            $failed = $false
            $failureReason = $null
            $failureRecordSha256 = $null
            $terminalStatus = $null
            $committed = $false
            $commitManifestFile = $null
            $commitManifestSha256 = $null
            $lastRecordChannel = $null
            $lastRecordEvent = $null
            $generationHealth = @{}
            $plannedGenerationLaunches = [uint64]0
            $serverShutdownGenerationLaunches = [uint64]0
            $serverShutdownEvents = [uint64]0
            $serverShutdownSupervisorEvents = [uint64]0
            $serverShutdownDurableEvents = [uint64]0
            $childStderrEvents = [uint64]0
            $campaignStartedCount = [uint64]0
            $campaignPreparedCount = [uint64]0
            $preparedRecordIndex = $null
            $preparedRecordSha256 = $null
            $previousWallNs = [uint64]0
            $previousCampaignMonoNs = [uint64]0
            $initialActiveRegistered = $false
            $activeGeneration = $null
            $pendingCandidate = $null
            $warmedGeneration = $null
            $candidateRegistered = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            $proofStarted = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            $promoted = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        }
            $processLine = {
                param($Line)
                $envelope = ConvertFrom-MonitorCanonicalCompactJsonLine `
                    -Line $Line -Path $Path -Ordinal ([uint64]$script:journalNextIndex)
                $null = Assert-MonitorRustCampaignJournalEnvelopeJsonTypes -Envelope $envelope
                if (-not (Test-MonitorExactJsonPropertyOrder $envelope @("body", "record_sha256")) -or
                    -not (Test-MonitorExactJsonPropertyOrder $envelope.body @(
                            "schema", "record_index", "wall_ns", "campaign_mono_ns", "generation_index",
                            "channel", "payload", "previous_record_sha256")) -or
                    -not (Test-MonitorJsonObjectKeysOrdinalSortedRecursive $envelope.body.payload)) {
                    throw "Campaign journal record differs from the exact serde_json field/map order: $Path"
                }
                $bodyJson = $envelope.body | ConvertTo-Json -Depth 100 -Compress
                $actual = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($bodyJson))
                if ([decimal]$envelope.body.record_index -ne [decimal]$script:journalNextIndex -or
                    [string]$envelope.body.previous_record_sha256 -cne $script:journalPreviousDigest -or
                    [string]$envelope.record_sha256 -cne $actual -or
                    ([uint64]$script:journalNextIndex -ne 0 -and
                        ([uint64]$envelope.body.wall_ns -lt [uint64]$script:journalPreviousWallNs -or
                         [uint64]$envelope.body.campaign_mono_ns -lt [uint64]$script:journalPreviousCampaignMonoNs))) {
                    throw "Campaign hash-chain failure at record $($script:journalNextIndex) in $Path"
                }
                $script:journalPreviousWallNs = [uint64]$envelope.body.wall_ns
                $script:journalPreviousCampaignMonoNs = [uint64]$envelope.body.campaign_mono_ns
                $script:journalNextIndex = [uint64]($script:journalNextIndex + 1)
                $script:journalPreviousDigest = $actual
                if ($script:journalVerifyPrefixContinuity -and
                    $script:journalNextIndex -eq $script:journalExpectedPrefixRecords) {
                    if ($actual -cne $script:journalExpectedPrefixTerminalRecordSha256) {
                        throw "Campaign journal hash chain does not extend the previously observed prefix: $Path"
                    }
                    $script:journalExpectedPrefixObserved = $true
                }
                $payload = $envelope.body.payload
                $eventValue = Assert-MonitorRustCampaignPayloadJsonContract `
                    -Payload $payload `
                    -Channel ([string]$envelope.body.channel) `
                    -GenerationIndex $envelope.body.generation_index
                if ([uint64]$envelope.body.record_index -eq 0 -and $eventValue -cne "CAMPAIGN_STARTED") {
                    throw "Campaign journal must begin with CAMPAIGN_STARTED: $Path"
                }
                if ([uint64]$envelope.body.record_index -ne 0 -and $eventValue -ceq "CAMPAIGN_STARTED") {
                    throw "Campaign journal contains a non-initial CAMPAIGN_STARTED: $Path"
                }
                if ($script:journalCommitted) {
                    throw "Campaign journal contains evidence after CAMPAIGN_COMMITTED: $Path"
                }
                $script:journalLastRecordChannel = [string]$envelope.body.channel
                $script:journalLastRecordEvent = $eventValue
                if ($envelope.body.channel -eq "CHILD_STDERR") {
                    $script:journalChildStderrEvents = [uint64]($script:journalChildStderrEvents + 1)
                }
                if ($eventValue -ceq "CAMPAIGN_STARTED") {
                    $script:journalCampaignStartedCount = [uint64]($script:journalCampaignStartedCount + 1)
                    if ($script:journalCampaignStartedCount -ne 1 -or
                        ($null -ne $CampaignStartup -and
                            ([string]$payload.campaign_id -cne [string]$CampaignStartup.campaign_id -or
                             [string]$payload.startup_sha256 -cne [string]$CampaignStartupSha256))) {
                        throw "CAMPAIGN_STARTED does not bind the exact startup singleton: $Path"
                    }
                }
                if ($envelope.body.channel -ceq "CAMPAIGN" -and
                    @("GENERATION_LAUNCHED", "GENERATION_LAUNCHED_SERVER_SHUTDOWN") -ccontains $eventValue) {
                    $generationKey = [string][uint64]$envelope.body.generation_index
                    $generationIndex = [uint64]$envelope.body.generation_index
                    $immediateCandidate = ($generationIndex -gt 0 -and
                        $null -ne $script:journalActiveGeneration -and
                        [uint64]$script:journalActiveGeneration -eq ($generationIndex - 1) -and
                        $null -eq $script:journalPendingCandidate -and
                        $null -eq $script:journalWarmedGeneration)
                    $warmAhead = ($eventValue -ceq "GENERATION_LAUNCHED" -and
                        $generationIndex -ge 2 -and
                        $null -ne $script:journalActiveGeneration -and
                        [uint64]$script:journalActiveGeneration -eq ($generationIndex - 2) -and
                        $null -ne $script:journalPendingCandidate -and
                        [uint64]$script:journalPendingCandidate -eq ($generationIndex - 1) -and
                        $null -eq $script:journalWarmedGeneration)
                    if ($script:journalCampaignStartedCount -ne 1 -or
                        $script:journalGenerationHealth.ContainsKey($generationKey) -or
                        $generationIndex -ne [uint64]$script:journalGenerationHealth.Count -or
                        ($generationIndex -eq 0 -and
                            ($eventValue -cne "GENERATION_LAUNCHED" -or
                             $null -ne $script:journalActiveGeneration -or
                             $null -ne $script:journalPendingCandidate -or
                             $null -ne $script:journalWarmedGeneration)) -or
                        ($generationIndex -gt 0 -and -not $immediateCandidate -and -not $warmAhead) -or
                        ($eventValue -ceq "GENERATION_LAUNCHED_SERVER_SHUTDOWN" -and
                            ([uint64]$payload.source_generation + 1 -ne $generationIndex))) {
                        throw "Campaign journal has a duplicate/invalid generation launch: $Path"
                    }
                    $script:journalGenerationHealth[$generationKey] = [pscustomobject]@{
                        GenerationIndex = [uint64]$envelope.body.generation_index
                        DurationS = [uint64]$payload.duration_s
                        LaunchWallNs = [uint64]$envelope.body.wall_ns
                        LastHeartbeatWallNs = [uint64]0
                        TelemetryMonoNs = [uint64]0
                        DepthLastSocketActivityMonoNs = [uint64]0
                        DepthLastMarketMessageMonoNs = [uint64]0
                        TradeLastSocketActivityMonoNs = [uint64]0
                        TradeLastMarketMessageMonoNs = [uint64]0
                        DepthReceived = [uint64]0
                        DepthDurable = [uint64]0
                        TradeReceived = [uint64]0
                        TradeDurable = [uint64]0
                        Terminal = $false
                        TerminalWallNs = [uint64]0
                        Exited = $false
                        ExitedWallNs = [uint64]0
                        SessionId = $null
                        ProcessStartedRecord = $null
                        TerminalRecord = $null
                        ExitedRecord = $null
                        Snapshot = $false
                        Transports = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                    }
                    if ($generationIndex -gt 0) {
                        if ($warmAhead) { $script:journalWarmedGeneration = $generationIndex }
                        else { $script:journalPendingCandidate = $generationIndex }
                    }
                    if ($eventValue -ceq "GENERATION_LAUNCHED") {
                        $script:journalPlannedGenerationLaunches = [uint64]($script:journalPlannedGenerationLaunches + 1)
                    }
                    else {
                        $script:journalServerShutdownGenerationLaunches = [uint64]($script:journalServerShutdownGenerationLaunches + 1)
                    }
                }
                if ($envelope.body.channel -ceq "SUPERVISOR" -and $eventValue -clike "SERVER_SHUTDOWN_*") {
                    $script:journalServerShutdownSupervisorEvents = [uint64]($script:journalServerShutdownSupervisorEvents + 1)
                    $script:journalServerShutdownEvents = [uint64]($script:journalServerShutdownEvents + 1)
                }
                if ($envelope.body.channel -ceq "CHILD_STDOUT" -and $eventValue -ceq "SERVER_SHUTDOWN_DURABLE") {
                    $script:journalServerShutdownDurableEvents = [uint64]($script:journalServerShutdownDurableEvents + 1)
                    $script:journalServerShutdownEvents = [uint64]($script:journalServerShutdownEvents + 1)
                }
                if ($envelope.body.channel -ceq "CHILD_STDOUT") {
                    switch -CaseSensitive ($eventValue) {
                        "PROCESS_STARTED" {
                            $generationKey = [string][uint64]$envelope.body.generation_index
                            if (-not $script:journalGenerationHealth.ContainsKey($generationKey)) {
                                throw "Campaign PROCESS_STARTED preceded generation launch: $Path"
                            }
                            $generation = $script:journalGenerationHealth[$generationKey]
                            if ($null -ne $generation.SessionId -or
                                $null -ne $generation.ProcessStartedRecord -or
                                [string]$payload.schema -cne "CaptureProcessEventV1" -or
                                [uint64]$payload.generation_index -ne [uint64]$envelope.body.generation_index -or
                                ($null -ne $CampaignStartup -and
                                    ([string]$payload.symbol -cne [string]$CampaignStartup.symbol -or
                                     [string]$payload.spec_revision -cne [string]$CampaignStartup.spec_revision))) {
                                throw "Campaign PROCESS_STARTED identity is invalid/duplicate: $Path"
                            }
                            $generation.SessionId = [string]$payload.session_id
                            $generation.ProcessStartedRecord = [uint64]$envelope.body.record_index
                            $script:journalProcessStarted = $true
                        }
                        "TRANSPORT_CONNECTED" {
                            $generationKey = [string][uint64]$envelope.body.generation_index
                            if (-not $script:journalGenerationHealth.ContainsKey($generationKey)) {
                                throw "Campaign transport preceded generation launch: $Path"
                            }
                            $generation = $script:journalGenerationHealth[$generationKey]
                            $stream = [string]$payload.connection.stream
                            if ($null -eq $generation.ProcessStartedRecord -or $null -ne $generation.TerminalRecord -or
                                [string]$payload.session_id -cne [string]$generation.SessionId -or
                                -not (@("depth", "trade") -ccontains $stream) -or
                                -not $generation.Transports.Add($stream)) {
                                throw "Campaign TRANSPORT_CONNECTED identity/order/cardinality is invalid: $Path"
                            }
                            $null = $script:journalTransports.Add($stream)
                        }
                        "SNAPSHOT_DURABLE" {
                            $generationKey = [string][uint64]$envelope.body.generation_index
                            if (-not $script:journalGenerationHealth.ContainsKey($generationKey)) {
                                throw "Campaign snapshot preceded generation launch: $Path"
                            }
                            $generation = $script:journalGenerationHealth[$generationKey]
                            if ($null -eq $generation.ProcessStartedRecord -or $null -ne $generation.TerminalRecord -or
                                [string]$payload.session_id -cne [string]$generation.SessionId -or
                                [bool]$generation.Snapshot -or $generation.Transports.Count -ne 2) {
                                throw "Campaign SNAPSHOT_DURABLE identity/order/cardinality is invalid: $Path"
                            }
                            $generation.Snapshot = $true
                            $script:journalSnapshotDurable = $true
                        }
                        "SEGMENT_DURABLE" {
                            $generationKey = [string][uint64]$envelope.body.generation_index
                            if (-not $script:journalGenerationHealth.ContainsKey($generationKey)) {
                                throw "Campaign segment preceded generation launch: $Path"
                            }
                            $generation = $script:journalGenerationHealth[$generationKey]
                            if ($null -eq $generation.ProcessStartedRecord -or $null -ne $generation.TerminalRecord -or
                                [string]$payload.session_id -cne [string]$generation.SessionId -or
                                -not [bool]$generation.Snapshot -or
                                -not (@("depth", "trade") -ccontains [string]$payload.segment.stream) -or
                                [uint64]$payload.segment.first_frame_index -gt [uint64]$payload.segment.last_frame_index -or
                                [uint64]$payload.segment.records -eq 0 -or
                                [uint64]$payload.segment.durable_through_offset -eq 0 -or
                                [uint64]$payload.segment.manifest_durable_through_offset -eq 0) {
                                throw "Campaign SEGMENT_DURABLE identity/order/range is invalid: $Path"
                            }
                        }
                        "SERVER_SHUTDOWN_DURABLE" {
                            $generationKey = [string][uint64]$envelope.body.generation_index
                            if (-not $script:journalGenerationHealth.ContainsKey($generationKey)) {
                                throw "Campaign serverShutdown preceded generation launch: $Path"
                            }
                            $generation = $script:journalGenerationHealth[$generationKey]
                            if ($null -eq $generation.ProcessStartedRecord -or $null -ne $generation.TerminalRecord -or
                                [string]$payload.session_id -cne [string]$generation.SessionId -or
                                -not (@("depth", "trade") -ccontains [string]$payload.shutdown.stream) -or
                                [uint64]$payload.shutdown.receive_mono_ns -eq 0 -or
                                [uint64]$payload.shutdown.durable_record_count -eq 0 -or
                                [uint64]$payload.shutdown.durable_through_offset -eq 0) {
                                throw "Campaign SERVER_SHUTDOWN_DURABLE identity/order/range is invalid: $Path"
                            }
                        }
                        "HEARTBEAT_DURABLE" {
                            $generationKey = [string][uint64]$envelope.body.generation_index
                            if (-not $script:journalGenerationHealth.ContainsKey($generationKey)) {
                                throw "Campaign heartbeat preceded its generation launch: $Path"
                            }
                            $generation = $script:journalGenerationHealth[$generationKey]
                            if ($null -eq $generation.ProcessStartedRecord -or $null -ne $generation.TerminalRecord -or
                                [string]$payload.session_id -cne [string]$generation.SessionId -or
                                -not [bool]$generation.Snapshot -or
                                [uint64]$payload.telemetry_durable_through_offset -eq 0) {
                                throw "Campaign heartbeat identity/lifecycle is invalid: $Path"
                            }
                            $telemetryMonoNs = [uint64]$payload.telemetry_mono_ns
                            $depthSocketMonoNs = [uint64]$payload.depth_last_socket_activity_mono_ns
                            $depthMarketMonoNs = [uint64]$payload.depth_last_market_message_mono_ns
                            $tradeSocketMonoNs = [uint64]$payload.trade_last_socket_activity_mono_ns
                            $tradeMarketMonoNs = [uint64]$payload.trade_last_market_message_mono_ns
                            if (($generation.TelemetryMonoNs -ne 0 -and $telemetryMonoNs -le $generation.TelemetryMonoNs) -or
                                $depthSocketMonoNs -lt $generation.DepthLastSocketActivityMonoNs -or
                                $depthMarketMonoNs -lt $generation.DepthLastMarketMessageMonoNs -or
                                $tradeSocketMonoNs -lt $generation.TradeLastSocketActivityMonoNs -or
                                $tradeMarketMonoNs -lt $generation.TradeLastMarketMessageMonoNs -or
                                $depthMarketMonoNs -gt $depthSocketMonoNs -or
                                $depthSocketMonoNs -gt $telemetryMonoNs -or
                                $tradeMarketMonoNs -gt $tradeSocketMonoNs -or
                                $tradeSocketMonoNs -gt $telemetryMonoNs -or
                                [uint64]$payload.depth_received -lt $generation.DepthReceived -or
                                [uint64]$payload.depth_durable -lt $generation.DepthDurable -or
                                [uint64]$payload.trade_received -lt $generation.TradeReceived -or
                                [uint64]$payload.trade_durable -lt $generation.TradeDurable -or
                                [uint64]$payload.depth_durable -gt [uint64]$payload.depth_received -or
                                [uint64]$payload.trade_durable -gt [uint64]$payload.trade_received) {
                                throw "Campaign durable heartbeat freshness/counters regressed or became impossible: $Path"
                            }
                            $activeEndNs = [uint64]$generation.DurationS * [uint64]1000000000
                            if ($telemetryMonoNs -ge $ExpectedMarketFreshnessStartupGraceNs -and $telemetryMonoNs -lt $activeEndNs -and
                                ($depthMarketMonoNs -eq 0 -or
                                 $tradeMarketMonoNs -eq 0 -or
                                 ($telemetryMonoNs - $depthMarketMonoNs) -gt $ExpectedMarketFreshnessDeadlineNs -or
                                 ($telemetryMonoNs - $tradeMarketMonoNs) -gt $ExpectedMarketFreshnessDeadlineNs)) {
                                throw "Campaign heartbeat proves socket/ping activity without fresh market messages: $Path"
                            }
                            $generation.LastHeartbeatWallNs = [uint64]$envelope.body.wall_ns
                            $generation.TelemetryMonoNs = $telemetryMonoNs
                            $generation.DepthLastSocketActivityMonoNs = $depthSocketMonoNs
                            $generation.DepthLastMarketMessageMonoNs = $depthMarketMonoNs
                            $generation.TradeLastSocketActivityMonoNs = $tradeSocketMonoNs
                            $generation.TradeLastMarketMessageMonoNs = $tradeMarketMonoNs
                            $generation.DepthReceived = [uint64]$payload.depth_received
                            $generation.DepthDurable = [uint64]$payload.depth_durable
                            $generation.TradeReceived = [uint64]$payload.trade_received
                            $generation.TradeDurable = [uint64]$payload.trade_durable
                            $script:journalPreviousHeartbeat = $script:journalLatestHeartbeat
                            $script:journalLatestHeartbeat = $envelope
                        }
                        "PROCESS_TERMINAL" {
                            $generationKey = [string][uint64]$envelope.body.generation_index
                            if (-not $script:journalGenerationHealth.ContainsKey($generationKey)) {
                                throw "Campaign PROCESS_TERMINAL lacks a launched generation: $Path"
                            }
                            $generation = $script:journalGenerationHealth[$generationKey]
                            if ([bool]$generation.Terminal -or
                                $null -eq $generation.ProcessStartedRecord -or
                                [string]$payload.schema -cne "CaptureTerminalProcessEventV1" -or
                                [string]$payload.status -cnotin @("COMPLETE", "FAILED") -or
                                ([string]$payload.status -ceq "FAILED" -and -not $script:journalFailed) -or
                                ([string]$payload.status -ceq "COMPLETE" -and $script:journalFailed) -or
                                [string]$payload.generation_manifest -cne "generation.json" -or
                                [string]$payload.session_id -cne [string]$generation.SessionId) {
                                throw "Campaign PROCESS_TERMINAL identity is invalid/duplicate: $Path"
                            }
                            $script:journalTerminalStatus = [string]$payload.status
                            $generation.Terminal = $true
                            $generation.TerminalWallNs = [uint64]$envelope.body.wall_ns
                            $generation.TerminalRecord = [uint64]$envelope.body.record_index
                        }
                    }
                }
                if ($envelope.body.channel -ceq "SUPERVISOR") {
                    $generationKey = [string][uint64]$envelope.body.generation_index
                    if (-not $script:journalGenerationHealth.ContainsKey($generationKey)) {
                        throw "Campaign supervisor event references an unlaunched generation: $Path"
                    }
                    $generationIndex = [uint64]$envelope.body.generation_index
                    $generation = $script:journalGenerationHealth[$generationKey]
                    switch -CaseSensitive ($eventValue) {
                        "INITIAL_ACTIVE_REGISTERED" {
                            if ($generationIndex -ne 0 -or $script:journalInitialActiveRegistered -or
                                $null -eq $generation.ProcessStartedRecord -or
                                $null -ne $script:journalActiveGeneration) {
                                throw "INITIAL_ACTIVE_REGISTERED lifecycle is invalid: $Path"
                            }
                            $script:journalInitialActiveRegistered = $true
                            $script:journalActiveGeneration = [uint64]0
                        }
                        "CANDIDATE_REGISTERED" {
                            if ($script:journalWarmedGeneration -eq $generationIndex -and
                                $null -eq $script:journalPendingCandidate -and
                                $null -ne $script:journalActiveGeneration -and
                                [uint64]$script:journalActiveGeneration -eq ($generationIndex - 1)) {
                                $script:journalWarmedGeneration = $null
                                $script:journalPendingCandidate = $generationIndex
                            }
                            if ($generationIndex -eq 0 -or
                                $script:journalPendingCandidate -ne $generationIndex -or
                                $null -eq $generation.ProcessStartedRecord -or
                                $null -eq $script:journalActiveGeneration -or
                                [uint64]$script:journalActiveGeneration -ne ($generationIndex - 1) -or
                                -not $script:journalCandidateRegistered.Add($generationKey)) {
                                throw "CANDIDATE_REGISTERED lifecycle is invalid: $Path"
                            }
                        }
                        "HANDOVER_PROVEN_AND_PROMOTED" {
                            $predecessor = [uint64]$payload.predecessor
                            $pair = "$predecessor->$generationIndex"
                            if ($predecessor + 1 -ne $generationIndex -or
                                -not $script:journalCandidateRegistered.Contains($generationKey) -or
                                -not $script:journalProofStarted.Contains($pair) -or
                                $script:journalPendingCandidate -ne $generationIndex -or
                                $null -eq $script:journalActiveGeneration -or
                                [uint64]$script:journalActiveGeneration -ne $predecessor -or
                                -not $script:journalPromoted.Add($pair)) {
                                throw "HANDOVER_PROVEN_AND_PROMOTED lifecycle is invalid: $Path"
                            }
                            $script:journalActiveGeneration = $generationIndex
                            $script:journalPendingCandidate = $null
                        }
                        "GENERATION_DISCONNECT_FAIL_CLOSED" { $script:journalFailed = $true }
                    }
                }
                if ($eventValue -ceq "HANDOVER_PROOF_STARTED") {
                    $successor = [uint64]$envelope.body.generation_index
                    $predecessor = [uint64]$payload.predecessor
                    $pair = "$predecessor->$successor"
                    $predecessorKey = [string]$predecessor
                    $successorKey = [string]$successor
                    if ($predecessor + 1 -ne $successor -or
                        -not $script:journalGenerationHealth.ContainsKey($predecessorKey) -or
                        -not $script:journalGenerationHealth.ContainsKey($successorKey) -or
                        -not [bool]$script:journalGenerationHealth[$predecessorKey].Exited -or
                        $null -eq $script:journalGenerationHealth[$successorKey].ProcessStartedRecord -or
                        -not $script:journalCandidateRegistered.Contains($successorKey) -or
                        -not $script:journalProofStarted.Add($pair)) {
                        throw "HANDOVER_PROOF_STARTED lifecycle is invalid: $Path"
                    }
                }
                if ($eventValue -ceq "CAMPAIGN_FAILED") {
                    if ($null -ne $script:journalFailureReason) {
                        throw "Campaign journal contains duplicate CAMPAIGN_FAILED records: $Path"
                    }
                    $script:journalFailed = $true
                    $script:journalFailureReason = [string]$payload.error
                    $script:journalFailureRecordSha256 = [string]$envelope.record_sha256
                }
                if ($eventValue -ceq "CAMPAIGN_EVALUATION_PREPARED") {
                    $script:journalCampaignPreparedCount = [uint64]($script:journalCampaignPreparedCount + 1)
                    if ($script:journalCampaignPreparedCount -ne 1 -or
                        $script:journalGenerationHealth.Count -eq 0 -or
                        $null -ne $script:journalPendingCandidate -or
                        $null -ne $script:journalWarmedGeneration -or
                        $null -eq $script:journalActiveGeneration -or
                        [uint64]$script:journalActiveGeneration -ne ([uint64]$script:journalGenerationHealth.Count - 1) -or
                        @($script:journalGenerationHealth.Values | Where-Object {
                            -not [bool]$_.Terminal -or -not [bool]$_.Exited }).Count -ne 0) {
                        throw "CAMPAIGN_EVALUATION_PREPARED lifecycle/cardinality is invalid: $Path"
                    }
                    $script:journalPreparedRecordIndex = [uint64]$envelope.body.record_index
                    $script:journalPreparedRecordSha256 = [string]$envelope.record_sha256
                }
                if ($eventValue -ceq "CAMPAIGN_COMMITTED") {
                    if ($script:journalCommitted) {
                        throw "Campaign journal contains duplicate CAMPAIGN_COMMITTED records: $Path"
                    }
                    if ($script:journalCampaignPreparedCount -ne 1 -or $script:journalFailed) {
                        throw "CAMPAIGN_COMMITTED preceded its exact successful precommit boundary: $Path"
                    }
                    $script:journalCommitted = $true
                    $script:journalCommitManifestFile = [string]$payload.manifest_file
                    $script:journalCommitManifestSha256 = [string]$payload.manifest_sha256
                }
                if ($eventValue -ceq "GENERATION_EXITED") {
                    $generationKey = [string][uint64]$envelope.body.generation_index
                    if (-not $script:journalGenerationHealth.ContainsKey($generationKey) -or
                        [bool]$script:journalGenerationHealth[$generationKey].Exited -or
                        -not [bool]$script:journalGenerationHealth[$generationKey].Terminal -or
                        ([bool]$payload.success -and $script:journalFailed) -or
                        (-not [bool]$payload.success -and -not $script:journalFailed)) {
                        throw "Campaign GENERATION_EXITED is invalid/duplicate: $Path"
                    }
                    $script:journalGenerationHealth[$generationKey].Exited = $true
                    $script:journalGenerationHealth[$generationKey].ExitedWallNs = [uint64]$envelope.body.wall_ns
                    $script:journalGenerationHealth[$generationKey].ExitedRecord = [uint64]$envelope.body.record_index
                }
            }

            # Script-scope scratch variables let the validated callback mutate state under
            # Windows PowerShell 5.1 without trusting dynamic-scope copies.
            $script:journalNextIndex = $nextIndex
            $script:journalPreviousDigest = $previousDigest
            $script:journalLatestHeartbeat = $latestHeartbeat
            $script:journalPreviousHeartbeat = $previousHeartbeat
            $script:journalProcessStarted = $processStarted
            $script:journalSnapshotDurable = $snapshotDurable
            $script:journalTransports = $transports
            $script:journalFailed = $failed
            $script:journalFailureReason = $failureReason
            $script:journalFailureRecordSha256 = $failureRecordSha256
            $script:journalTerminalStatus = $terminalStatus
            $script:journalCommitted = $committed
            $script:journalCommitManifestFile = $commitManifestFile
            $script:journalCommitManifestSha256 = $commitManifestSha256
            $script:journalLastRecordChannel = $lastRecordChannel
            $script:journalLastRecordEvent = $lastRecordEvent
            $script:journalGenerationHealth = $generationHealth
            $script:journalPlannedGenerationLaunches = $plannedGenerationLaunches
            $script:journalServerShutdownGenerationLaunches = $serverShutdownGenerationLaunches
            $script:journalServerShutdownEvents = $serverShutdownEvents
            $script:journalServerShutdownSupervisorEvents = $serverShutdownSupervisorEvents
            $script:journalServerShutdownDurableEvents = $serverShutdownDurableEvents
            $script:journalChildStderrEvents = $childStderrEvents
            $script:journalCampaignStartedCount = $campaignStartedCount
            $script:journalCampaignPreparedCount = $campaignPreparedCount
            $script:journalPreparedRecordIndex = $preparedRecordIndex
            $script:journalPreparedRecordSha256 = $preparedRecordSha256
            $script:journalPreviousWallNs = $previousWallNs
            $script:journalPreviousCampaignMonoNs = $previousCampaignMonoNs
            $script:journalInitialActiveRegistered = $initialActiveRegistered
            $script:journalActiveGeneration = $activeGeneration
            $script:journalPendingCandidate = $pendingCandidate
            $script:journalWarmedGeneration = $warmedGeneration
            $script:journalCandidateRegistered = $candidateRegistered
            $script:journalProofStarted = $proofStarted
            $script:journalPromoted = $promoted
            # A replayed prefix proves record continuity while parsing from byte zero.
            # The incremental path has already authenticated the exact byte prefix and
            # starts at its next record/digest, so it must not wait to re-observe it.
            $script:journalVerifyPrefixContinuity = [bool](
                $verifyPrefixContinuity -and $null -eq $ContinuationState)
            $script:journalExpectedPrefixRecords = if ($script:journalVerifyPrefixContinuity) {
                [uint64]$ExpectedPrefixRecords
            } else { [uint64]0 }
            $script:journalExpectedPrefixTerminalRecordSha256 = if ($script:journalVerifyPrefixContinuity) {
                [string]$ExpectedPrefixTerminalRecordSha256
            } else { $null }
            $script:journalExpectedPrefixObserved = $false
            foreach ($line in $sourceLines) {
                if ($null -ne $pending) { & $processLine $pending }
                $pending = $line
            }
            if ($endsWithNewline -and $null -ne $pending) { & $processLine $pending }
            if ($script:journalNextIndex -eq 0) { throw "Campaign journal is empty: $Path" }
            if ($script:journalCampaignStartedCount -ne 1) {
                throw "Campaign journal lacks exactly one initial CAMPAIGN_STARTED: $Path"
            }
            if ($script:journalVerifyPrefixContinuity -and -not $script:journalExpectedPrefixObserved) {
                throw "Campaign journal no longer contains the complete previously observed record prefix: $Path"
            }
            return [pscustomobject]@{
                records = [uint64]$script:journalNextIndex
                terminal_record_sha256 = $script:journalPreviousDigest
                file_length = [uint64]$snapshotLength
                file_sha256 = [string]$snapshot.file_sha256
                complete_length = [uint64]$snapshot.complete_length
                complete_sha256 = [string]$snapshot.complete_sha256
                partial_tail = [bool](-not $endsWithNewline)
                process_started = [bool]$script:journalProcessStarted
                depth_connected = [bool]$script:journalTransports.Contains("depth")
                trade_connected = [bool]$script:journalTransports.Contains("trade")
                snapshot_durable = [bool]$script:journalSnapshotDurable
                latest_heartbeat = $script:journalLatestHeartbeat
                previous_heartbeat = $script:journalPreviousHeartbeat
                campaign_failed = [bool]$script:journalFailed
                campaign_failure_reason = $script:journalFailureReason
                campaign_failure_record_sha256 = $script:journalFailureRecordSha256
                terminal_status = $script:journalTerminalStatus
                campaign_committed = [bool]$script:journalCommitted
                commit_manifest_file = $script:journalCommitManifestFile
                commit_manifest_sha256 = $script:journalCommitManifestSha256
                prepared_record_index = $script:journalPreparedRecordIndex
                prepared_record_sha256 = $script:journalPreparedRecordSha256
                terminal_record_is_commit = [bool](
                    $script:journalLastRecordChannel -eq "CAMPAIGN" -and
                    $script:journalLastRecordEvent -eq "CAMPAIGN_COMMITTED")
                planned_generation_launches = [uint64]$script:journalPlannedGenerationLaunches
                server_shutdown_generation_launches = [uint64]$script:journalServerShutdownGenerationLaunches
                server_shutdown_events = [uint64]$script:journalServerShutdownEvents
                server_shutdown_supervisor_events = [uint64]$script:journalServerShutdownSupervisorEvents
                server_shutdown_durable_events = [uint64]$script:journalServerShutdownDurableEvents
                child_stderr_events = [uint64]$script:journalChildStderrEvents
                generation_health = @($script:journalGenerationHealth.Values | Sort-Object GenerationIndex | ForEach-Object {
                    [pscustomobject][ordered]@{
                        generation_index = [uint64]$_.GenerationIndex
                        duration_s = [uint64]$_.DurationS
                        launch_wall_ns = [uint64]$_.LaunchWallNs
                        last_heartbeat_wall_ns = [uint64]$_.LastHeartbeatWallNs
                        telemetry_mono_ns = [uint64]$_.TelemetryMonoNs
                        depth_last_socket_activity_mono_ns = [uint64]$_.DepthLastSocketActivityMonoNs
                        depth_last_market_message_mono_ns = [uint64]$_.DepthLastMarketMessageMonoNs
                        depth_market_message_age_ms = if ($_.DepthLastMarketMessageMonoNs -ne 0) { [math]::Round(([double]($_.TelemetryMonoNs - $_.DepthLastMarketMessageMonoNs) / 1e6), 3) } else { $null }
                        trade_last_socket_activity_mono_ns = [uint64]$_.TradeLastSocketActivityMonoNs
                        trade_last_market_message_mono_ns = [uint64]$_.TradeLastMarketMessageMonoNs
                        trade_market_message_age_ms = if ($_.TradeLastMarketMessageMonoNs -ne 0) { [math]::Round(([double]($_.TelemetryMonoNs - $_.TradeLastMarketMessageMonoNs) / 1e6), 3) } else { $null }
                        depth_received = [uint64]$_.DepthReceived
                        depth_durable = [uint64]$_.DepthDurable
                        trade_received = [uint64]$_.TradeReceived
                        trade_durable = [uint64]$_.TradeDurable
                        terminal = [bool]$_.Terminal
                        terminal_wall_ns = [uint64]$_.TerminalWallNs
                        exited = [bool]$_.Exited
                        exited_wall_ns = [uint64]$_.ExitedWallNs
                    }
                })
                continuation_state = [pscustomobject]@{
                    schema = "MonitorCampaignJournalContinuationV1"
                    path = [IO.Path]::GetFullPath($Path)
                    campaign_startup_sha256 = [string]$CampaignStartupSha256
                    observed_file_length = [uint64]$snapshot.file_length
                    observed_file_sha256 = [string]$snapshot.file_sha256
                    complete_length = [uint64]$snapshot.complete_length
                    complete_sha256 = [string]$snapshot.complete_sha256
                    next_index = [uint64]$script:journalNextIndex
                    previous_digest = [string]$script:journalPreviousDigest
                    latest_heartbeat = $script:journalLatestHeartbeat
                    previous_heartbeat = $script:journalPreviousHeartbeat
                    process_started = [bool]$script:journalProcessStarted
                    snapshot_durable = [bool]$script:journalSnapshotDurable
                    transports = $script:journalTransports
                    failed = [bool]$script:journalFailed
                    failure_reason = $script:journalFailureReason
                    failure_record_sha256 = $script:journalFailureRecordSha256
                    terminal_status = $script:journalTerminalStatus
                    committed = [bool]$script:journalCommitted
                    commit_manifest_file = $script:journalCommitManifestFile
                    commit_manifest_sha256 = $script:journalCommitManifestSha256
                    last_record_channel = $script:journalLastRecordChannel
                    last_record_event = $script:journalLastRecordEvent
                    generation_health = $script:journalGenerationHealth
                    planned_generation_launches = [uint64]$script:journalPlannedGenerationLaunches
                    server_shutdown_generation_launches = [uint64]$script:journalServerShutdownGenerationLaunches
                    server_shutdown_events = [uint64]$script:journalServerShutdownEvents
                    server_shutdown_supervisor_events = [uint64]$script:journalServerShutdownSupervisorEvents
                    server_shutdown_durable_events = [uint64]$script:journalServerShutdownDurableEvents
                    child_stderr_events = [uint64]$script:journalChildStderrEvents
                    campaign_started_count = [uint64]$script:journalCampaignStartedCount
                    campaign_prepared_count = [uint64]$script:journalCampaignPreparedCount
                    prepared_record_index = $script:journalPreparedRecordIndex
                    prepared_record_sha256 = $script:journalPreparedRecordSha256
                    previous_wall_ns = [uint64]$script:journalPreviousWallNs
                    previous_campaign_mono_ns = [uint64]$script:journalPreviousCampaignMonoNs
                    initial_active_registered = [bool]$script:journalInitialActiveRegistered
                    active_generation = $script:journalActiveGeneration
                    pending_candidate = $script:journalPendingCandidate
                    warmed_generation = $script:journalWarmedGeneration
                    candidate_registered = $script:journalCandidateRegistered
                    proof_started = $script:journalProofStarted
                    promoted = $script:journalPromoted
                }
            }
    }
    finally { }
}

function Get-LastCampaignHeartbeat {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $lines = @(Get-Content -LiteralPath $Path -Tail 200 -ErrorAction Stop)
    for ($index = $lines.Count - 1; $index -ge 0; $index--) {
        try { $value = $lines[$index] | ConvertFrom-Json -ErrorAction Stop }
        catch { continue }
        $canonical = $value | ConvertTo-Json -Depth 100 -Compress
        if ([string]$lines[$index] -cne $canonical) {
            throw "Coordinator stdout JSON differs from its exact compact writer representation: $Path"
        }
        if ($null -ne $value.PSObject.Properties['event'] -and $value.event -eq "CAMPAIGN_HEARTBEAT") {
            return $value
        }
    }
    return $null
}

function Assert-MonitorCampaignHeartbeatContract {
    param([Parameter(Mandatory = $true)] $Heartbeat)
    if (-not (Test-RawQualificationJsonBoolean $Heartbeat.failure)) {
        throw "Coordinator CAMPAIGN_HEARTBEAT failure is not an exact JSON boolean."
    }
    $failed = [bool]$Heartbeat.failure
    $expected = if ($failed) {
        @("event", "campaign_id", "elapsed_s", "generations", "active_processes",
            "handovers_proven", "failure", "failure_reason", "failure_record_sha256")
    }
    else {
        @("event", "campaign_id", "elapsed_s", "generations", "active_processes",
            "handovers_proven", "failure")
    }
    if (-not (Test-MonitorExactJsonPropertyOrder $Heartbeat $expected) -or
        [string]$Heartbeat.event -cne "CAMPAIGN_HEARTBEAT" -or
        -not (Test-RawQualificationJsonString $Heartbeat.campaign_id) -or
        -not (Test-RawQualificationJsonInteger $Heartbeat.elapsed_s 0 ([decimal][uint64]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $Heartbeat.generations 0 ([decimal][uint64]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $Heartbeat.active_processes 0 ([decimal][uint64]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $Heartbeat.handovers_proven 0 ([decimal][uint64]::MaxValue))) {
        throw "Coordinator CAMPAIGN_HEARTBEAT violates its exact JSON contract."
    }
    if ($failed -and
        (-not (Test-RawQualificationJsonString $Heartbeat.failure_reason) -or
         -not (Test-RawQualificationJsonSha256 $Heartbeat.failure_record_sha256))) {
        throw "Failed coordinator CAMPAIGN_HEARTBEAT lacks its exact durable cause binding."
    }
    return $true
}

function Invoke-CurrentCampaignVerifier {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [string] $Executable,
        [Parameter(Mandatory = $true)] [string[]] $ArgumentsBeforeReport,
        [Parameter(Mandatory = $true)] [string] $WorkingDirectory,
        [Parameter(Mandatory = $true)] [string[]] $EnvironmentEntries,
        [Parameter(Mandatory = $true)] [int] $TimeoutSeconds
    )
    $systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    $tempRoot = Join-Path $systemTemp ("BinanceRawQualificationCurrentVerify-" + [Guid]::NewGuid().ToString("N"))
    $job = [IntPtr]::Zero
    $processHandle = [IntPtr]::Zero
    try {
        $null = New-Item -ItemType Directory -Path $tempRoot -ErrorAction Stop
        $reportPath = Join-Path $tempRoot "report.json"
        $stdoutPath = Join-Path $tempRoot "stdout.log"
        $stderrPath = Join-Path $tempRoot "stderr.log"
        $arguments = [string[]]@($ArgumentsBeforeReport + @($reportPath))
        $job = [RawQualificationNative]::CreateKillOnCloseJob(
            "Local\BinanceRawQualificationMonitorVerify-" + [Guid]::NewGuid().ToString("N"))
        $launch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $job,
            $Executable,
            $arguments,
            $WorkingDirectory,
            $stdoutPath,
            $stderrPath,
            $EnvironmentEntries)
        $processHandle = $launch.ProcessHandle
        $resumeQpcTimestamp = [long]$launch.ResumeQpcTimestamp
        $finalElapsedTicks = [long]0
        while (-not [RawQualificationNative]::WaitForProcessExit($processHandle, 250)) {
            foreach ($path in @($stdoutPath, $stderrPath, $reportPath)) {
                if ((Test-Path -LiteralPath $path -PathType Leaf) -and
                    [uint64](Get-Item -LiteralPath $path -ErrorAction Stop).Length -gt $MaximumCurrentVerifierArtifactBytes) {
                    throw "Current $Name verifier exceeded its bounded artifact size."
                }
            }
            $elapsedTicks = Get-RawQualificationElapsedQpcTicks -ResumeQpcTimestamp $resumeQpcTimestamp
            if (-not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks $elapsedTicks `
                -TimeoutSeconds ([uint64]$TimeoutSeconds))) {
                throw "Current $Name verifier exceeded its ${TimeoutSeconds}-second deadline."
            }
        }
        $parentExitObservedQpcTimestamp = [long][Diagnostics.Stopwatch]::GetTimestamp()
        $finalElapsedTicks = Get-RawQualificationElapsedQpcTicks -ResumeQpcTimestamp $resumeQpcTimestamp
        if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $finalElapsedTicks `
            -TimeoutSeconds ([uint64]$TimeoutSeconds))) {
            throw "Current $Name verifier exceeded its ${TimeoutSeconds}-second deadline at exact process exit."
        }
        $exitCode = [int][RawQualificationNative]::GetProcessExitCode($processHandle)
        $descendantDrainElapsedTicks = [long]0
        while ([RawQualificationNative]::GetActiveProcessCount($job) -ne 0) {
            $descendantDrainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $parentExitObservedQpcTimestamp)
            if (-not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks $descendantDrainElapsedTicks `
                -TimeoutSeconds 10)) {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        $descendantDrainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $parentExitObservedQpcTimestamp)
        if ([RawQualificationNative]::GetActiveProcessCount($job) -ne 0 -or
            -not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks $descendantDrainElapsedTicks `
                -TimeoutSeconds 10)) {
            throw "Current $Name verifier retained a descendant after parent exit."
        }
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "Current $Name verifier omitted an expected artifact."
            }
        }
        $stdoutBytes = [uint64](Get-Item -LiteralPath $stdoutPath).Length
        $stderrBytes = [uint64](Get-Item -LiteralPath $stderrPath).Length
        $reportPresent = Test-Path -LiteralPath $reportPath -PathType Leaf
        $reportBytes = if ($reportPresent) { [uint64](Get-Item -LiteralPath $reportPath).Length } else { [uint64]0 }
        if ($exitCode -ne 0) {
            $stderrPreview = if ($stderrBytes -le 4096) {
                (Get-Content -LiteralPath $stderrPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue).Trim()
            }
            else { "<stderr omitted>" }
            throw "Current $Name verifier exited $exitCode without PASS: $stderrPreview"
        }
        if (-not $reportPresent -or $stderrBytes -ne 0 -or $reportBytes -eq 0 -or
            $stdoutBytes -gt $MaximumCurrentVerifierArtifactBytes -or
            $reportBytes -gt $MaximumCurrentVerifierArtifactBytes) {
            throw "Current $Name verifier failed exit/stderr/report bounds (exit=$exitCode stdout=$stdoutBytes stderr=$stderrBytes report=$reportBytes)."
        }
        $reportSnapshot = Read-MonitorCanonicalJsonSnapshot `
            -Path $reportPath -WriterKind TwoSpacePretty -MaximumBytes $MaximumCurrentVerifierArtifactBytes
        if ($reportSnapshot.length -ne $reportBytes) {
            throw "Current $Name verifier report changed after its bounded snapshot."
        }
        $report = $reportSnapshot.value
        return [pscustomobject][ordered]@{
            name = $Name
            pid = [uint32]$launch.ProcessId
            resume_qpc_timestamp = [long]$resumeQpcTimestamp
            elapsed_qpc_ticks = [long]$finalElapsedTicks
            monotonic_frequency = [long][Diagnostics.Stopwatch]::Frequency
            elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds -ElapsedTicks $finalElapsedTicks
            parent_exit_observed_qpc_timestamp = [long]$parentExitObservedQpcTimestamp
            descendant_drain_elapsed_qpc_ticks = [long]$descendantDrainElapsedTicks
            descendant_drain_elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds -ElapsedTicks $descendantDrainElapsedTicks
            executable_sha256 = Get-RawQualificationSha256File -Path $Executable
            command_line_sha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes([string]$launch.ExactCommandLine))
            stdout_bytes = $stdoutBytes
            stdout_sha256 = Get-RawQualificationSha256File -Path $stdoutPath
            stderr_bytes = $stderrBytes
            stderr_sha256 = Get-RawQualificationSha256File -Path $stderrPath
            report_bytes = $reportBytes
            report_sha256 = $reportSnapshot.sha256
            report = $report
        }
    }
    catch {
        if ($job -ne [IntPtr]::Zero) {
            try { $null = [RawQualificationNative]::TerminateJobObject($job, 0xEE31) } catch {}
        }
        if ($processHandle -ne [IntPtr]::Zero) {
            try { $null = [RawQualificationNative]::WaitForProcessExit($processHandle, 10000) } catch {}
        }
        throw
    }
    finally {
        if ($processHandle -ne [IntPtr]::Zero) { try { $null = [RawQualificationNative]::CloseHandle($processHandle) } catch {} }
        if ($job -ne [IntPtr]::Zero) { try { $null = [RawQualificationNative]::CloseHandle($job) } catch {} }
        if (Test-Path -LiteralPath $tempRoot -PathType Container) {
            $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
            if (-not $resolvedTemp.StartsWith($systemTemp + '\', [StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($resolvedTemp) -notlike "BinanceRawQualificationCurrentVerify-*") {
                throw "Current verifier cleanup target escaped its dedicated system-temporary directory."
            }
            Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction Stop
        }
    }
}

function Get-MonitorFailedSingletonEvidence {
    param(
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] [string] $FileName,
        [AllowNull()] $ExpectedSha256,
        [Parameter(Mandatory = $true)]
        [ValidateSet("PowerShellPretty", "PowerShellCompactCrlf", "TwoSpacePretty")] [string] $WriterKind
    )
    $path = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot -Path (Join-Path $RunRoot $FileName)
    if ($null -eq $ExpectedSha256) {
        if (Test-Path -LiteralPath $path) {
            throw "FAILED terminal left an unreceipted singleton: $FileName"
        }
        return $null
    }
    if (-not (Test-RawQualificationJsonSha256 $ExpectedSha256)) {
        throw "FAILED terminal contains a malformed singleton receipt for $FileName"
    }
    $null = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot -Path $path -RequireLeaf
    $snapshot = Read-MonitorCanonicalJsonSnapshot -Path $path -WriterKind $WriterKind
    if ([string]$snapshot.sha256 -cne [string]$ExpectedSha256) {
        throw "FAILED terminal singleton receipt mismatch: $FileName"
    }
    return $snapshot
}

function Get-MonitorFailedJournalReceiptEvidence {
    param(
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] [string] $ExpectedFileName,
        [Parameter(Mandatory = $true)] [string] $ExpectedSchema,
        [AllowNull()] $Receipt
    )
    $path = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot -Path (Join-Path $RunRoot $ExpectedFileName)
    if ($null -eq $Receipt) {
        if (Test-Path -LiteralPath $path) {
            throw "FAILED terminal left an unreceipted journal: $ExpectedFileName"
        }
        return $null
    }
    if (-not (Test-MonitorExactJsonPropertyOrder $Receipt @(
                "file", "records", "terminal_record_sha256", "file_sha256")) -or
        -not (Test-RawQualificationJsonString $Receipt.file) -or
        [string]$Receipt.file -cne $ExpectedFileName -or
        -not (Test-RawQualificationJsonInteger $Receipt.records 0 ([decimal][uint64]::MaxValue)) -or
        -not (Test-RawQualificationJsonSha256 $Receipt.terminal_record_sha256) -or
        -not (Test-RawQualificationJsonSha256 $Receipt.file_sha256)) {
        throw "FAILED terminal journal receipt is malformed: $ExpectedFileName"
    }
    $null = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot -Path $path -RequireLeaf
    $journal = Get-VerifiedJournalSummary -Path $path -ExpectedSchema $ExpectedSchema -AllowEmpty
    if ([bool]$journal.partial_tail -or
        [uint64]$journal.records -ne [uint64]$Receipt.records -or
        [string]$journal.terminal_record_sha256 -cne [string]$Receipt.terminal_record_sha256 -or
        [string]$journal.file_sha256 -cne [string]$Receipt.file_sha256 -or
        ([uint64]$journal.records -eq 0 -and
            [string]$journal.terminal_record_sha256 -cne ("0" * 64))) {
        throw "FAILED terminal does not byte-bind the exact closed journal: $ExpectedFileName"
    }
    return $journal
}

function Get-MonitorGenerationClockTelemetryCount {
    param(
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] [string] $GenerationDirectory
    )
    $directory = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
        -Path $GenerationDirectory -RequireDirectory
    $telemetryPath = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
        -Path (Join-Path $directory "telemetry.jsonl") -RequireLeaf
    $snapshot = Read-MonitorFrozenCanonicalJsonLines -Path $telemetryPath
    if ([bool]$snapshot.partial_tail) { throw "Generation clock telemetry has a partial tail: $telemetryPath" }
    $expectedIndex = [uint64]0
    foreach ($line in @($snapshot.lines)) {
        $record = ConvertFrom-MonitorCanonicalCompactJsonLine `
            -Line $line -Path $telemetryPath -Ordinal $expectedIndex
        if (-not (Test-MonitorExactJsonProperties $record @(
                "schema", "record_index", "wall_ns", "mono_ns", "clock",
                "depth_received", "depth_written", "depth_durable", "depth_segment",
                "depth_last_socket_activity_mono_ns", "depth_last_market_message_mono_ns",
                "depth_last_durable_mono_ns", "depth_queue_records", "depth_queue_bytes",
                "depth_max_queue_records", "depth_max_queue_bytes", "depth_max_queue_age_ns",
                "depth_last_sync_duration_ns", "depth_max_sync_duration_ns",
                "trade_received", "trade_written", "trade_durable", "trade_segment",
                "trade_last_socket_activity_mono_ns", "trade_last_market_message_mono_ns",
                "trade_last_durable_mono_ns", "trade_queue_records", "trade_queue_bytes",
                "trade_max_queue_records", "trade_max_queue_bytes", "trade_max_queue_age_ns",
                "trade_last_sync_duration_ns", "trade_max_sync_duration_ns")) -or
            -not (Test-RawQualificationJsonString $record.schema) -or
            [string]$record.schema -cne "CaptureTelemetryV1" -or
            -not (Test-RawQualificationJsonInteger $record.record_index 0 ([decimal][uint64]::MaxValue)) -or
            [uint64]$record.record_index -ne $expectedIndex -or
            -not (Test-MonitorExactJsonProperties $record.clock @(
                    "quality", "source", "leap_indicator", "stratum", "last_successful_sync")) -or
            -not (Test-RawQualificationJsonString $record.clock.quality) -or
            [string]$record.clock.quality -cne "HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND" -or
            -not (Test-RawQualificationJsonInteger $record.clock.leap_indicator 0 0) -or
            -not (Test-RawQualificationJsonInteger $record.clock.stratum 1 15) -or
            -not (Test-RawQualificationJsonString $record.clock.last_successful_sync) -or
            [string]::IsNullOrWhiteSpace([string]$record.clock.last_successful_sync)) {
            throw "Generation contains ambiguous or noncanonical clock telemetry at record $expectedIndex."
        }
        $expectedIndex = [uint64]($expectedIndex + 1)
    }
    if ($expectedIndex -eq 0) { throw "Generation clock telemetry is empty: $telemetryPath" }
    return $expectedIndex
}

function Assert-MonitorFailedArtifactEvidence {
    param(
        [Parameter(Mandatory = $true)] $Terminal,
        [AllowNull()] $Startup,
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [switch] $WatchdogEvidenceRequired
    )
    $preflightNames = @(
        "campaign_executable_sha256", "capture_executable_sha256", "campaign_verifier_executable_sha256",
        "public_config_sha256", "source_lock_sha256", "launcher_script_sha256", "monitor_script_sha256",
        "helper_script_sha256", "telemetry_probe_script_sha256", "watchdog_script_sha256",
        "python_runtime_fingerprint_script_sha256", "powershell_executable_sha256",
        "python_executable_sha256", "python_verifier_source_tree_sha256", "python_runtime_tree_sha256",
        "python_pyvenv_config_sha256", "python_base_executable_sha256", "python_project_sha256",
        "python_requirements_sha256")
    $observations = [Collections.Generic.List[object]]::new()
    if ($null -eq $Startup) {
        foreach ($name in $preflightNames) {
            if ($null -ne $Terminal.artifact_hashes_preflight.PSObject.Properties[$name].Value) {
                throw "Pre-startup FAILED terminal asserted a preflight receipt without durable startup authority: $name"
            }
            $terminalDigest = $Terminal.artifact_hashes_terminal.PSObject.Properties[$name].Value
            $observations.Add([pscustomobject][ordered]@{
                name = $name
                terminal_sha256 = $terminalDigest
                preflight_sha256 = $null
                current_sha256 = $null
                state = if ($null -eq $terminalDigest) { "TERMINAL_ABSENT_NO_PREFLIGHT" } else { "TERMINAL_UNBOUND_NO_PREFLIGHT" }
            })
        }
        $readyDigest = $Terminal.artifact_hashes_terminal.watchdog_ready_file_sha256
        $observations.Add([pscustomobject][ordered]@{
            name = "watchdog_ready_file_sha256"
            terminal_sha256 = $readyDigest
            preflight_sha256 = $null
            current_sha256 = $null
            state = if ($null -eq $readyDigest) { "TERMINAL_ABSENT_NO_PREFLIGHT" } else { "TERMINAL_UNBOUND_NO_PREFLIGHT" }
        })
        return [pscustomobject][ordered]@{
            preflight_bound = $false
            watchdog_event_observed = [bool]$WatchdogEvidenceRequired
            observations = @($observations.ToArray())
        }
    }

    $preflight = $Startup.preflight
    $expectedPreflight = [ordered]@{
        campaign_executable_sha256 = $preflight.campaign_executable_sha256
        capture_executable_sha256 = $preflight.capture_executable_sha256
        campaign_verifier_executable_sha256 = $preflight.campaign_verifier_executable_sha256
        public_config_sha256 = $preflight.public_config_sha256
        source_lock_sha256 = $preflight.source_lock_sha256
        launcher_script_sha256 = $preflight.launcher_script_sha256
        monitor_script_sha256 = $preflight.monitor_script_sha256
        helper_script_sha256 = $preflight.helper_script_sha256
        telemetry_probe_script_sha256 = $preflight.telemetry_probe_script_sha256
        watchdog_script_sha256 = $preflight.watchdog_script_sha256
        python_runtime_fingerprint_script_sha256 = $preflight.python_runtime_fingerprint_script_sha256
        powershell_executable_sha256 = $preflight.powershell_executable_sha256
        python_executable_sha256 = $preflight.python_sha256
        python_verifier_source_tree_sha256 = $preflight.python_verifier_source.tree_sha256
        python_runtime_tree_sha256 = $preflight.python_runtime.tree_sha256
        python_pyvenv_config_sha256 = $preflight.python_runtime.pyvenv_config_sha256
        python_base_executable_sha256 = $preflight.python_runtime.base_executable_sha256
        python_project_sha256 = $preflight.python_project_sha256
        python_requirements_sha256 = $preflight.python_requirements_sha256
    }
    foreach ($name in $preflightNames) {
        if ([string]$Terminal.artifact_hashes_preflight.PSObject.Properties[$name].Value -cne
            [string]$expectedPreflight[$name]) {
            throw "FAILED terminal changed a preflight artifact receipt: $name"
        }
    }
    $pathByTerminalName = [ordered]@{
        campaign_executable_sha256 = $preflight.campaign_executable
        capture_executable_sha256 = $preflight.capture_executable
        campaign_verifier_executable_sha256 = $preflight.campaign_verifier_executable
        public_config_sha256 = $preflight.public_config
        source_lock_sha256 = $preflight.source_lock
        launcher_script_sha256 = $preflight.launcher_script
        monitor_script_sha256 = $preflight.monitor_script
        helper_script_sha256 = $preflight.helper_script
        telemetry_probe_script_sha256 = $preflight.telemetry_probe_script
        watchdog_script_sha256 = $preflight.watchdog_script
        python_runtime_fingerprint_script_sha256 = $preflight.python_runtime_fingerprint_script
        powershell_executable_sha256 = $preflight.powershell_executable
        python_executable_sha256 = $preflight.python
        python_project_sha256 = $preflight.python_project
        python_requirements_sha256 = $preflight.python_requirements
    }
    $pathByTerminalName.watchdog_ready_file_sha256 = Join-Path $RunRoot "watchdog-ready.json"
    foreach ($name in $pathByTerminalName.Keys) {
        $path = [string]$pathByTerminalName[$name]
        $terminalDigest = $Terminal.artifact_hashes_terminal.PSObject.Properties[$name].Value
        $preflightDigest = if ($expectedPreflight.Contains($name)) { $expectedPreflight[$name] } else { $null }
        $currentDigest = $null
        $currentState = "CURRENT_ABSENT"
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            try {
                $currentDigest = Get-RawQualificationSha256File -Path $path
                $currentState = "CURRENT_HASHED"
            }
            catch { $currentState = "CURRENT_UNREADABLE" }
        }
        $terminalState = if ($null -eq $terminalDigest) {
            "TERMINAL_ABSENT"
        }
        elseif ($null -ne $preflightDigest -and [string]$terminalDigest -cne [string]$preflightDigest) {
            "TERMINAL_DRIFT_FROM_PREFLIGHT"
        }
        else { "TERMINAL_MATCHES_PREFLIGHT_OR_PHASE_ARTIFACT" }
        $currentRelation = if ($null -eq $currentDigest) {
            $currentState
        }
        elseif ($null -eq $terminalDigest) {
            "CURRENT_PRESENT_WITHOUT_TERMINAL_DIGEST"
        }
        elseif ([string]$currentDigest -ceq [string]$terminalDigest) {
            "CURRENT_MATCHES_TERMINAL"
        }
        else { "CURRENT_DRIFT_FROM_TERMINAL" }
        $observations.Add([pscustomobject][ordered]@{
            name = $name
            terminal_sha256 = $terminalDigest
            preflight_sha256 = $preflightDigest
            current_sha256 = $currentDigest
            state = $terminalState + ":" + $currentRelation
        })
    }

    foreach ($tree in @(
            [pscustomobject]@{
                name = "python_verifier_source_tree_sha256"
                terminal = $Terminal.artifact_hashes_terminal.python_verifier_source_tree_sha256
                preflight = $expectedPreflight.python_verifier_source_tree_sha256
                current = $(try { (Get-RawQualificationSourceTreeDigest -Root ([string]$preflight.python_verifier_source.root)).tree_sha256 } catch { $null })
            },
            [pscustomobject]@{
                name = "python_runtime_tree_sha256"
                terminal = $Terminal.artifact_hashes_terminal.python_runtime_tree_sha256
                preflight = $expectedPreflight.python_runtime_tree_sha256
                current = $null
            })) {
        $observations.Add([pscustomobject][ordered]@{
            name = [string]$tree.name
            terminal_sha256 = $tree.terminal
            preflight_sha256 = $tree.preflight
            current_sha256 = $tree.current
            state = if ($null -eq $tree.terminal) { "TERMINAL_ABSENT" }
                elseif ([string]$tree.terminal -cne [string]$tree.preflight) { "TERMINAL_DRIFT_FROM_PREFLIGHT" }
                elseif ($null -eq $tree.current) { "TERMINAL_MATCHES_PREFLIGHT:CURRENT_NOT_REHASHED_OR_UNAVAILABLE" }
                elseif ([string]$tree.current -ceq [string]$tree.terminal) { "CURRENT_MATCHES_TERMINAL" }
                else { "CURRENT_DRIFT_FROM_TERMINAL" }
        })
    }
    return [pscustomobject][ordered]@{
        preflight_bound = $true
        watchdog_event_observed = [bool]$WatchdogEvidenceRequired
        observations = @($observations.ToArray())
    }
}

function Assert-MonitorFailedWatchdogReadySnapshot {
    param(
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] $Startup,
        [Parameter(Mandatory = $true)] $FailureContainment,
        [Parameter(Mandatory = $true)] [string] $ExpectedSha256
    )
    $path = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
        -Path (Join-Path $RunRoot "watchdog-ready.json") -RequireLeaf
    $snapshot = Read-MonitorCanonicalJsonSnapshot -Path $path -WriterKind PowerShellPretty -MaximumBytes 65536
    $ready = $snapshot.value
    if ([string]$snapshot.sha256 -cne $ExpectedSha256 -or
        -not (Test-MonitorExactJsonPropertyOrder $ready @(
                "schema", "run_id", "job_name", "pid", "launch_origin_qpc_timestamp",
                "observed_qpc_timestamp", "monotonic_frequency", "startup_deadline_s", "pulse_length")) -or
        -not (Test-RawQualificationJsonString $ready.schema) -or
        [string]$ready.schema -cne "RawQualificationWatchdogReadyV1" -or
        -not (Test-RawQualificationJsonString $ready.run_id) -or
        [string]$ready.run_id -cne [string]$Startup.run_id -or
        -not (Test-RawQualificationJsonString $ready.job_name) -or
        [string]$ready.job_name -cne [string]$FailureContainment.job_name -or
        -not (Test-RawQualificationJsonInteger $ready.pid 1 ([decimal][uint32]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $ready.launch_origin_qpc_timestamp 1 ([decimal][long]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $ready.observed_qpc_timestamp 1 ([decimal][long]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger $ready.monotonic_frequency 1 ([decimal][long]::MaxValue)) -or
        [long]$ready.monotonic_frequency -ne [long]$Startup.monotonic_frequency -or
        -not (Test-RawQualificationJsonInteger $ready.startup_deadline_s 1 604920) -or
        [uint64]$ready.startup_deadline_s -ne [uint64]$ExpectedGuardianWatchdogStartupDeadlineSeconds -or
        -not (Test-RawQualificationJsonInteger $ready.pulse_length 1 ([decimal][uint64]::MaxValue)) -or
        [long]$ready.observed_qpc_timestamp -lt [long]$ready.launch_origin_qpc_timestamp -or
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks ([long]([long]$ready.observed_qpc_timestamp - [long]$ready.launch_origin_qpc_timestamp)) `
            -TimeoutSeconds ([uint64]$ExpectedGuardianWatchdogStartupDeadlineSeconds) `
            -Frequency ([long]$ready.monotonic_frequency))) {
        throw "FAILED terminal watchdog READY singleton is noncanonical or semantically unbound."
    }
    $pulsePath = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
        -Path (Join-Path $RunRoot ([string]$Startup.guardian_policy.pulse_file)) -RequireLeaf
    if ([uint64](Get-Item -LiteralPath $pulsePath).Length -lt [uint64]$ready.pulse_length) {
        throw "FAILED terminal guardian pulse journal regressed below watchdog READY."
    }
    return $snapshot
}

function Assert-MonitorFailedSingletonPolicyEvidence {
    param(
        [Parameter(Mandatory = $true)] [string] $RunRoot,
        [Parameter(Mandatory = $true)] $Terminal,
        [Parameter(Mandatory = $true)] $History,
        [AllowNull()] $StartupSnapshot,
        [AllowNull()] $ControlSnapshot,
        [AllowNull()] $BindingSnapshot
    )
    $startup = if ($null -ne $StartupSnapshot) { $StartupSnapshot.value } else { $null }
    $control = if ($null -ne $ControlSnapshot) { $ControlSnapshot.value } else { $null }
    $bindings = if ($null -ne $BindingSnapshot) { $BindingSnapshot.value } else { $null }
    if ([IO.Path]::GetFullPath([string]$Terminal.run_root).TrimEnd('\') -cne
            [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')) {
        throw "FAILED terminal run_root does not equal the monitored RunRoot."
    }
    if ($null -eq $startup) {
        if ($null -ne $Terminal.startup_sha256 -or $null -ne $control -or $null -ne $bindings -or
            @($Terminal.campaigns).Count -ne 0) {
            throw "Pre-startup FAILED terminal contains later-phase singleton or campaign evidence."
        }
        return [pscustomobject][ordered]@{ startup=$null; control=$null; bindings=$null }
    }
    $null = Assert-MonitorStartupOnlyJsonTypes -Startup $startup
    $null = Assert-MonitorTerminalVerifierPolicyBinding -Terminal $Terminal -Startup $startup
    if ([string]$StartupSnapshot.sha256 -cne [string]$Terminal.startup_sha256 -or
        [string]$startup.schema -cne "RawQualificationLauncherStartupV1" -or
        [string]$startup.run_id -cne [string]$Terminal.run_id -or
        [string]$startup.mode -cne [string]$Terminal.mode -or
        [IO.Path]::GetFullPath([string]$startup.run_root).TrimEnd('\') -cne
            [IO.Path]::GetFullPath($RunRoot).TrimEnd('\') -or
        [uint64]$startup.parameters.total_s -ne [uint64]$Terminal.parameters.total_s -or
        [uint64]$startup.parameters.rotation_s -ne [uint64]$Terminal.parameters.rotation_s -or
        [uint64]$startup.parameters.overlap_s -ne [uint64]$Terminal.parameters.overlap_s -or
        [uint64]$startup.parameters.segment_s -ne [uint64]$Terminal.parameters.segment_s -or
        [uint64]$startup.verifier_policy.per_process_timeout_s -ne [uint64]$Terminal.verifier_policy.per_process_timeout_s -or
        [uint64]$startup.verifier_policy.total_post_capture_timeout_s -ne [uint64]$Terminal.verifier_policy.total_post_capture_timeout_s -or
        [uint64]$startup.verifier_policy.maximum_artifact_bytes -ne [uint64]$Terminal.verifier_policy.maximum_artifact_bytes -or
        [uint64]$startup.coordinator_log_policy.maximum_stdout_bytes -ne [uint64]$Terminal.coordinator_log_policy.maximum_stdout_bytes -or
        [uint64]$startup.coordinator_log_policy.maximum_stderr_bytes -ne [uint64]$Terminal.coordinator_log_policy.maximum_stderr_bytes -or
        [uint64]$startup.coordinator_log_policy.child_stderr_events_allowed -ne [uint64]$Terminal.coordinator_log_policy.child_stderr_events_allowed -or
        [uint64]$startup.market_freshness_policy.startup_grace_s -ne [uint64]$Terminal.market_freshness_policy.startup_grace_s -or
        [uint64]$startup.market_freshness_policy.deadline_s -ne [uint64]$Terminal.market_freshness_policy.deadline_s -or
        ($startup.guardian_policy | ConvertTo-Json -Compress) -cne
            ($Terminal.guardian_policy | ConvertTo-Json -Compress)) {
        throw "FAILED terminal policy/identity does not exactly match launcher startup."
    }
    $outputValidation = $startup.output_path_post_create
    if (-not [bool]$outputValidation.reparse_points_rejected -or
        -not [bool]$outputValidation.same_preflight_volume -or
        [string]$outputValidation.run_root_drive_device_id -cne [string]$startup.preflight.drive_device_id -or
        [string]$outputValidation.filesystem -cne "NTFS" -or
        [uint64]$outputValidation.free_gib -lt [uint64]$outputValidation.required_free_gib -or
        [uint64]$outputValidation.required_free_gib -ne [uint64]$startup.preflight.required_free_gib -or
        [uint64]$startup.preflight.host_probe_timeout_s -ne [uint64]$ExpectedHostProbeTimeoutSeconds -or
        [uint64]$startup.preflight.host_probe_maximum_artifact_bytes -ne
            [uint64]$ExpectedHostProbeMaximumArtifactBytes -or
        [uint64]$startup.preflight.guardian_watchdog_deadline_s -ne
            [uint64]$ExpectedGuardianWatchdogDeadlineSeconds -or
        [uint64]$startup.preflight.guardian_watchdog_startup_deadline_s -ne
            [uint64]$ExpectedGuardianWatchdogStartupDeadlineSeconds -or
        [uint64]$startup.preflight.python_runtime_fingerprint_timeout_s -ne
            [uint64]$ExpectedPythonRuntimeFingerprintTimeoutSeconds -or
        [string]$startup.credentials -cne "NONE" -or [string]$startup.order_entry -cne "ABSENT") {
        throw "FAILED launcher startup preflight/policy proof is inconsistent."
    }
    $null = Assert-PostCreateProbeEvidence `
        -Startup $startup `
        -OutputPathValidation $outputValidation `
        -ResolvedRunRoot $RunRoot
    $environmentEntries = [string[]]@($startup.preflight.child_environment.Entries)
    $declaredEnvironmentNames = @($startup.preflight.child_environment.names)
    $environmentNames = @($environmentEntries | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_) -or $_.IndexOf('=') -le 0) {
            throw "FAILED launcher startup contains a malformed child-environment entry."
        }
        $_.Substring(0, $_.IndexOf('='))
    })
    $environmentMaterial = [string]::Join("`0", $environmentEntries) + "`0`0"
    $environmentDigest = Get-RawQualificationSha256Bytes -Bytes (
        [Text.UnicodeEncoding]::new($false, $false).GetBytes($environmentMaterial))
    if ([string]$startup.preflight.child_environment.mode -cne "EXPLICIT_ALLOWLIST_NO_INHERITANCE" -or
        ($declaredEnvironmentNames -join ',') -cne "SystemDrive,SystemRoot,TEMP,TMP,WINDIR" -or
        ($environmentNames -join ',') -cne "SystemDrive,SystemRoot,TEMP,TMP,WINDIR" -or
        ($declaredEnvironmentNames -join "`n") -cne ($environmentNames -join "`n") -or
        [string]$environmentDigest -cne [string]$startup.preflight.child_environment.entries_sha256) {
        throw "FAILED launcher startup child environment is not the exact no-inheritance allowlist."
    }
    if ($null -eq $control) {
        if ($null -ne $Terminal.process_control_sha256 -or $null -ne $bindings -or
            @($Terminal.campaigns).Count -ne 0 -or
            $History.phase -in @("POST_DUAL", "SEMANTIC_READY", "POST_READINESS_OR_LATER")) {
            throw "FAILED phase requires process control but its exact singleton is absent."
        }
    }
    else {
        $null = Assert-MonitorStartupControlJsonTypes -Startup $startup -Control $control -RequireWriterContract
        if ([string]$ControlSnapshot.sha256 -cne [string]$Terminal.process_control_sha256 -or
            [string]$control.run_id -cne [string]$startup.run_id -or
            [string]$control.job_object_name -cne [string]$Terminal.failure_containment.job_name -or
            -not [bool]$control.job_kill_on_close -or
            [string]$control.schema -cne "RawQualificationProcessControlV2" -or
            -not [bool]$control.workload_job_kill_on_close -or
            [string]$control.job_object_name -ceq [string]$control.workload_job_object_name -or
            [string]$control.launch_method -cne "CREATE_SUSPENDED_ASSIGN_OUTER_AND_WORKLOAD_JOBS_RESUME" -or
            [string]$control.child_environment_mode -cne "EXPLICIT_ALLOWLIST_NO_INHERITANCE" -or
            (@($control.child_environment_names) -join ',') -cne "SystemDrive,SystemRoot,TEMP,TMP,WINDIR" -or
            (@($control.child_environment_names) -join "`n") -cne ($declaredEnvironmentNames -join "`n") -or
            [string]$control.child_environment_entries_sha256 -cne [string]$environmentDigest -or
            @($control.processes).Count -ne 2 -or
            (@($control.processes | ForEach-Object { [string]$_.symbol } | Sort-Object) -join ',') -cne
                "BTCUSDT,ETHUSDT") {
            throw "FAILED terminal/process-control/containment identity binding is invalid."
        }
        $controlBySymbol = @{}
        foreach ($process in @($control.processes)) {
            $symbol = [string]$process.symbol
            if ($controlBySymbol.ContainsKey($symbol)) {
                throw "FAILED process control contains a duplicate coordinator symbol."
            }
            $controlBySymbol[$symbol] = $process
            $expectedCommandLine = [RawQualificationNative]::BuildExactCommandLine(
                [string]$startup.preflight.campaign_executable,
                [string[]]@(
                    $symbol,
                    ([uint64]$startup.parameters.total_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                    ([uint64]$startup.parameters.rotation_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                    ([uint64]$startup.parameters.overlap_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                    ([uint64]$startup.parameters.segment_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                    [string]$RunRoot))
            if ([IO.Path]::GetFullPath([string]$process.executable_path) -cne
                    [IO.Path]::GetFullPath([string]$startup.preflight.campaign_executable) -or
                [string]$process.executable_sha256 -cne
                    [string]$startup.preflight.campaign_executable_sha256 -or
                [string]$process.command_line -cne $expectedCommandLine -or
                [string]$process.stdout_file -cne ($symbol.ToLowerInvariant() + ".stdout.log") -or
                [string]$process.stderr_file -cne ($symbol.ToLowerInvariant() + ".stderr.log")) {
                throw "FAILED process control coordinator provenance/command/log binding is invalid for $symbol."
            }
        }
        if ([uint64]$control.capture_origin_monotonic_tick -ne
                [uint64]$controlBySymbol["ETHUSDT"].launch_monotonic_tick -or
            [uint64]$controlBySymbol["BTCUSDT"].launch_monotonic_tick -gt
                [uint64]$controlBySymbol["ETHUSDT"].launch_monotonic_tick -or
            [uint64]$control.launch_skew_ticks -ne
                ([uint64]$controlBySymbol["ETHUSDT"].launch_monotonic_tick -
                 [uint64]$controlBySymbol["BTCUSDT"].launch_monotonic_tick) -or
            [uint64]$control.maximum_dual_launch_skew_ms -ne
                [uint64]$ExpectedMaximumDualLaunchSkewMilliseconds -or
            [uint64]$control.launch_skew_ms -ne [uint64][math]::Ceiling(
                [decimal][uint64]$control.launch_skew_ticks * [decimal]1000 /
                [decimal][uint64]$startup.monotonic_frequency)) {
            throw "FAILED process control dual-launch monotonic origin/skew is invalid."
        }
    }
    if ($null -eq $bindings) {
        if ($null -ne $Terminal.campaign_bindings_sha256 -or
            $History.phase -in @("SEMANTIC_READY", "POST_READINESS_OR_LATER")) {
            throw "FAILED phase requires campaign bindings but their exact singleton is absent."
        }
    }
    else {
        if ($null -eq $control) { throw "Campaign bindings exist without process control." }
        $null = Assert-MonitorBindingsWriterOrder -Bindings $bindings
        if ([string]$BindingSnapshot.sha256 -cne [string]$Terminal.campaign_bindings_sha256 -or
            [string]$bindings.run_id -cne [string]$startup.run_id -or @($bindings.campaigns).Count -ne 2) {
            throw "FAILED terminal campaign-binding receipt/identity is invalid."
        }
        foreach ($binding in @($bindings.campaigns)) {
            $process = @($control.processes | Where-Object { [string]$_.symbol -ceq [string]$binding.symbol })
            if ($process.Count -ne 1 -or [uint32]$process[0].pid -ne [uint32]$binding.pid) {
                throw "FAILED campaign binding does not match exactly one process-control identity."
            }
            $campaignDirectory = Resolve-MonitorContainedEvidencePath `
                -RunRoot $RunRoot `
                -Path ([string]$binding.campaign_directory) `
                -RequireDirectory
            if (-not [IO.Path]::GetDirectoryName($campaignDirectory).Equals(
                    [IO.Path]::GetFullPath($RunRoot).TrimEnd('\'),
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "FAILED campaign binding directory is not an immediate contained RunRoot child."
            }
            $campaignStartupPath = Resolve-MonitorContainedEvidencePath `
                -RunRoot $RunRoot `
                -Path (Join-Path $campaignDirectory "campaign-startup.json") `
                -RequireLeaf
            $campaignStartupSnapshot = Read-MonitorCanonicalJsonSnapshot `
                -Path $campaignStartupPath `
                -WriterKind TwoSpacePretty
            $null = Assert-MonitorRustCampaignSingletonWriterOrder `
                -Value $campaignStartupSnapshot.value `
                -Kind Startup
            $null = Assert-MonitorCampaignStartupBinding `
                -CampaignStartup $campaignStartupSnapshot.value `
                -CampaignStartupSha256 $campaignStartupSnapshot.sha256 `
                -Binding $binding `
                -LauncherStartup $startup `
                -ControlProcess $process[0]
        }
    }
    return [pscustomobject][ordered]@{ startup=$startup; control=$control; bindings=$bindings }
}

function Assert-MonitorFailedCampaignResultEvidence {
    param(
        [Parameter(Mandatory = $true)] $Terminal,
        [Parameter(Mandatory = $true)] $History,
        [AllowNull()] $Startup,
        [AllowNull()] $Control,
        [AllowNull()] $Bindings,
        [Parameter(Mandatory = $true)] $LauncherJournal,
        [Parameter(Mandatory = $true)] [string] $RunRoot
    )
    $results = @($Terminal.campaigns)
    $verifiedRecords = @($LauncherJournal.all_records | Where-Object {
        [string]$_.body.payload.event -ceq "INDEPENDENT_CAMPAIGN_VERIFIED"
    } | Sort-Object { [uint64]$_.body.record_index })
    $verifiedSymbols = @($verifiedRecords | ForEach-Object { [string]$_.body.payload.symbol })
    $resultSymbols = @($results | ForEach-Object { [string]$_.symbol })
    if ($results.Count -gt $verifiedRecords.Count -or
        ($results.Count -gt 0 -and
            ($resultSymbols -join ',') -cne (@($verifiedSymbols[0..($results.Count - 1)]) -join ','))) {
        throw "FAILED terminal campaign results are not a prefix of durable INDEPENDENT_CAMPAIGN_VERIFIED events."
    }
    if ($results.Count -eq 0) {
        return [pscustomobject][ordered]@{
            durable_verified_events = [uint64]$verifiedRecords.Count
            sealed_campaign_results = [uint64]0
            unsealed_verified_events = [uint64]$verifiedRecords.Count
        }
    }
    if ($results.Count -gt 2 -or $null -eq $Startup -or $null -eq $Control -or
        $null -eq $Bindings -or $null -eq $History.causal_prefix) {
        throw "FAILED terminal campaign results exist without their complete control/causal authority."
    }
    $expectedResultSymbols = @("BTCUSDT", "ETHUSDT")[0..($results.Count - 1)]
    if ((@($results | ForEach-Object { [string]$_.symbol }) -join ',') -cne
        ($expectedResultSymbols -join ',')) {
        throw "FAILED terminal campaign results are not the exact ordered verifier-output prefix."
    }
    $seenSymbols = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $previousVerifierCompletedAbsolute = $null
    $verificationRoot = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
        -Path (Join-Path $RunRoot "independent-verification") -RequireDirectory
    foreach ($result in $results) {
        $symbol = [string]$result.symbol
        if ($symbol -notin @("BTCUSDT", "ETHUSDT") -or -not $seenSymbols.Add($symbol)) {
            throw "FAILED terminal contains duplicate or unknown campaign result identity."
        }
        $process = @($Control.processes | Where-Object { [string]$_.symbol -ceq $symbol })
        $binding = @($Bindings.campaigns | Where-Object { [string]$_.symbol -ceq $symbol })
        if ($process.Count -ne 1 -or $binding.Count -ne 1 -or
            [uint32]$result.pid -ne [uint32]$process[0].pid -or
            [uint32]$result.pid -ne [uint32]$binding[0].pid -or
            [string]$result.campaign_id -cne [string]$binding[0].campaign_id -or
            [string]$result.campaign_directory -cne [string]$binding[0].campaign_directory -or
            -not $LauncherJournal.campaign_exit_records.ContainsKey($symbol)) {
            throw "$symbol FAILED terminal result is not bound to one process, binding, and launcher exit."
        }
        $exit = $LauncherJournal.campaign_exit_records[$symbol]
        if ([uint32]$exit.pid -ne [uint32]$result.pid -or [int]$exit.exit_code -ne [int]$result.exit_code -or
            [uint64]$exit.elapsed_s -ne [uint64]$result.exit_elapsed_s -or
            [uint64]$exit.coordinator_elapsed_s -ne [uint64]$result.coordinator_exit_elapsed_s) {
            throw "$symbol FAILED terminal result does not match its exact launcher exit proof."
        }
        $campaignDirectory = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
            -Path ([string]$result.campaign_directory) -RequireDirectory
        if (-not [IO.Path]::GetDirectoryName($campaignDirectory).Equals(
                [IO.Path]::GetFullPath($RunRoot).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw "$symbol campaign result is not an immediate contained RunRoot child."
        }
        $campaignStartupSnapshot = Read-MonitorCanonicalJsonSnapshot `
            -Path (Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
                -Path (Join-Path $campaignDirectory "campaign-startup.json") -RequireLeaf) `
            -WriterKind TwoSpacePretty
        $null = Assert-MonitorRustCampaignSingletonWriterOrder -Value $campaignStartupSnapshot.value -Kind Startup
        $null = Assert-MonitorCampaignStartupBinding `
            -CampaignStartup $campaignStartupSnapshot.value `
            -CampaignStartupSha256 $campaignStartupSnapshot.sha256 `
            -Binding $binding[0] `
            -LauncherStartup $Startup `
            -ControlProcess $process[0]
        $campaignJournal = Get-CampaignJournalHealth `
            -Path (Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
                -Path (Join-Path $campaignDirectory "campaign-events.jsonl") -RequireLeaf) `
            -CampaignStartup $campaignStartupSnapshot.value `
            -CampaignStartupSha256 $campaignStartupSnapshot.sha256
        $campaignManifestSnapshot = Read-MonitorCanonicalJsonSnapshot `
            -Path (Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
                -Path (Join-Path $campaignDirectory "campaign.json") -RequireLeaf) `
            -WriterKind TwoSpacePretty
        $manifest = $campaignManifestSnapshot.value
        $null = Assert-MonitorRustCampaignSingletonWriterOrder -Value $manifest -Kind Manifest
        $null = Assert-MonitorRustCampaignSingletonJsonTypes -Value $manifest -Kind Manifest
        if ([string]$manifest.status -cne "COMPLETE" -or [uint64]$manifest.supervisor_gap_count -ne 0 -or
            [string]$manifest.campaign_id -cne [string]$result.campaign_id -or
            [string]$manifest.symbol -cne $symbol -or
            [uint64]$manifest.total_duration_s -ne [uint64]$Startup.parameters.total_s -or
            [uint64]$manifest.rotation_s -ne [uint64]$Startup.parameters.rotation_s -or
            [uint64]$manifest.overlap_s -ne [uint64]$Startup.parameters.overlap_s -or
            [uint64]$manifest.segment_s -ne [uint64]$Startup.parameters.segment_s -or
            [string]$manifest.startup_sha256 -cne [string]$campaignStartupSnapshot.sha256 -or
            [string]$campaignManifestSnapshot.sha256 -cne [string]$result.campaign_manifest_sha256 -or
            [string]$manifest.journal_boundary -cne [string]$result.campaign_journal_boundary -or
            [uint64]$manifest.journal_precommit_records -ne [uint64]$result.campaign_journal_precommit_records -or
            [string]$manifest.journal_precommit_sha256 -cne [string]$result.campaign_journal_precommit_sha256 -or
            [uint64]$campaignJournal.records -ne [uint64]$result.campaign_journal_committed_records -or
            [string]$campaignJournal.terminal_record_sha256 -cne [string]$result.campaign_journal_terminal_sha256 -or
            -not [bool]$campaignJournal.campaign_committed -or
            -not [bool]$campaignJournal.terminal_record_is_commit -or
            [string]$campaignJournal.commit_manifest_file -cne "campaign.json" -or
            [string]$campaignJournal.commit_manifest_sha256 -cne [string]$campaignManifestSnapshot.sha256 -or
            @($manifest.generations).Count -ne [uint64]$result.generations -or
            @($manifest.handovers).Count -ne [uint64]$result.handovers -or
            [uint64]$campaignJournal.planned_generation_launches -ne [uint64]$result.planned_generation_launches -or
            [uint64]$campaignJournal.server_shutdown_generation_launches -ne [uint64]$result.server_shutdown_generation_launches -or
            [uint64]$campaignJournal.server_shutdown_supervisor_events -ne [uint64]$result.server_shutdown_supervisor_events -or
            [uint64]$campaignJournal.server_shutdown_durable_events -ne [uint64]$result.server_shutdown_durable_events -or
            [uint64]$campaignJournal.child_stderr_events -ne [uint64]$result.child_stderr_events) {
            throw "$symbol FAILED terminal campaign result disagrees with manifest/journal/startup evidence."
        }
        $expectedSchedule = Get-RawQualificationGenerationScheduleClassification `
            -Mode ([string]$Startup.mode) `
            -Generations ([uint64]@($manifest.generations).Count) `
            -Handovers ([uint64]@($manifest.handovers).Count) `
            -PlannedGenerationLaunches ([uint64]$campaignJournal.planned_generation_launches) `
            -ServerShutdownGenerationLaunches ([uint64]$campaignJournal.server_shutdown_generation_launches) `
            -ServerShutdownSupervisorEvents ([uint64]$campaignJournal.server_shutdown_supervisor_events) `
            -ServerShutdownDurableEvents ([uint64]$campaignJournal.server_shutdown_durable_events)
        if ([string]$result.generation_schedule_classification -cne $expectedSchedule) {
            throw "$symbol FAILED terminal schedule classification is not derived from exact journal/manifest evidence."
        }
        $clockRecords = [uint64]0
        foreach ($generation in @($manifest.generations)) {
            $portable = [string]$generation.session_dir
            if ([IO.Path]::IsPathRooted($portable) -or $portable -match '(^|[\\/])\.\.([\\/]|$)') {
                throw "$symbol manifest contains an unsafe generation path."
            }
            $clockRecords = [uint64]($clockRecords + (Get-MonitorGenerationClockTelemetryCount `
                -RunRoot $RunRoot -GenerationDirectory (Join-Path $campaignDirectory $portable)))
        }
        if ($clockRecords -ne [uint64]$result.unambiguous_clock_telemetry_records) {
            throw "$symbol FAILED terminal clock telemetry count is not reproducible."
        }
        foreach ($log in @(
                [pscustomobject]@{file=$result.stdout_file;bytes=$result.stdout_file_bytes;sha=$result.stdout_file_sha256;maximum=$Startup.coordinator_log_policy.maximum_stdout_bytes},
                [pscustomobject]@{file=$result.stderr_file;bytes=$result.stderr_file_bytes;sha=$result.stderr_file_sha256;maximum=0})) {
            $logPath = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
                -Path (Join-Path $RunRoot ([string]$log.file)) -RequireLeaf
            if ([uint64](Get-Item -LiteralPath $logPath).Length -ne [uint64]$log.bytes -or
                [uint64]$log.bytes -gt [uint64]$log.maximum -or
                (Get-RawQualificationSha256File -Path $logPath) -cne [string]$log.sha) {
                throw "$symbol FAILED terminal coordinator log receipt is invalid."
            }
        }
        $verifiers = @($result.independent_verifiers)
        $expectedNames = [string[]]@(
            ($symbol.ToLowerInvariant() + "-rust")
            ($symbol.ToLowerInvariant() + "-python")
        )
        if ($verifiers.Count -ne 2 -or
            (@($verifiers | ForEach-Object { [string]$_.name }) -join ',') -cne
                ($expectedNames -join ',')) {
            throw "$symbol FAILED terminal lacks the exact Rust/Python verifier set."
        }
        foreach ($verifier in $verifiers) {
            $name = [string]$verifier.name
            $started = $History.causal_prefix.verifier_started[$name]
            $completed = $History.causal_prefix.verifier_completed[$name]
            if ($null -eq $started -or $null -eq $completed) {
                throw "$symbol verifier result lacks exact launcher start/completion events."
            }
            $executionPath = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
                -Path (Join-Path $verificationRoot ([string]$verifier.execution_file)) -RequireLeaf
            $reportPath = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
                -Path (Join-Path $verificationRoot ([string]$verifier.report_file)) -RequireLeaf
            $stdoutPath = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
                -Path (Join-Path $verificationRoot ([string]$verifier.stdout_file)) -RequireLeaf
            $stderrPath = Resolve-MonitorContainedEvidencePath -RunRoot $RunRoot `
                -Path (Join-Path $verificationRoot ([string]$verifier.stderr_file)) -RequireLeaf
            $executionSnapshot = Read-MonitorCanonicalJsonSnapshot -Path $executionPath -WriterKind PowerShellPretty
            $reportSnapshot = Read-MonitorCanonicalJsonSnapshot -Path $reportPath -WriterKind TwoSpacePretty
            $execution = $executionSnapshot.value
            $report = $reportSnapshot.value
            $null = Assert-MonitorExecutionWriterOrder -Execution $execution
            $null = Assert-MonitorSealedVerifierJsonTypes -Verifier $verifier -Execution $execution
            $expectedVerifierExecutable = if ($name -clike "*-rust") {
                [string]$Startup.preflight.campaign_verifier_executable
            }
            else { [string]$Startup.preflight.python }
            $expectedVerifierExecutableSha256 = if ($name -clike "*-rust") {
                [string]$Startup.preflight.campaign_verifier_executable_sha256
            }
            else { [string]$Startup.preflight.python_sha256 }
            $actualCommandLineSha256 = Get-RawQualificationSha256Bytes -Bytes (
                [Text.UTF8Encoding]::new($false).GetBytes([string]$execution.command_line))
            $verificationStageTick = [uint64]$History.causal_prefix.independent_verification.body.monotonic_tick
            $expectedTimeout = Get-MonitorExpectedVerifierTimeoutSeconds `
                -BudgetComputedTick ([uint64]$execution.global_budget_computed_monotonic_tick) `
                -VerificationStageTick $verificationStageTick `
                -MonotonicFrequency ([uint64]$Startup.monotonic_frequency) `
                -TotalPostCaptureTimeoutSeconds ([uint64]$Startup.verifier_policy.total_post_capture_timeout_s) `
                -MaximumPerProcessTimeoutSeconds ([uint64]$Startup.verifier_policy.per_process_timeout_s)
            if ([string]$executionSnapshot.sha256 -cne [string]$verifier.execution_sha256 -or
                [string]$verifier.execution_file -cne ($name + ".execution.json") -or
                [string]$reportSnapshot.sha256 -cne [string]$verifier.report_sha256 -or
                [uint64]$reportSnapshot.length -ne [uint64]$verifier.report_bytes -or
                (Get-RawQualificationSha256File -Path $stdoutPath) -cne [string]$verifier.stdout_sha256 -or
                [uint64](Get-Item -LiteralPath $stdoutPath).Length -ne [uint64]$verifier.stdout_bytes -or
                (Get-RawQualificationSha256File -Path $stderrPath) -cne [string]$verifier.stderr_sha256 -or
                [uint64](Get-Item -LiteralPath $stderrPath).Length -ne [uint64]$verifier.stderr_bytes -or
                [uint32]$execution.pid -ne [uint32]$verifier.pid -or
                [uint32]$execution.pid -ne [uint32]$started.body.payload.pid -or
                [uint32]$execution.pid -ne [uint32]$completed.body.payload.pid -or
                [string]$execution.name -cne $name -or
                [string]$execution.creation_time_utc -cne [string]$verifier.creation_time_utc -or
                [string]$execution.executable_path -cne $expectedVerifierExecutable -or
                [string]$execution.executable_sha256 -cne $expectedVerifierExecutableSha256 -or
                [string]$actualCommandLineSha256 -cne [string]$verifier.command_line_sha256 -or
                [uint64]$execution.global_budget_computed_monotonic_tick -ne [uint64]$verifier.global_budget_computed_monotonic_tick -or
                [long]$execution.resume_qpc_timestamp -ne [long]$verifier.resume_qpc_timestamp -or
                [long]$execution.elapsed_qpc_ticks -ne [long]$verifier.elapsed_qpc_ticks -or
                [long]$execution.monotonic_frequency -ne [long]$verifier.monotonic_frequency -or
                [long]$execution.parent_exit_observed_qpc_timestamp -ne [long]$verifier.parent_exit_observed_qpc_timestamp -or
                [long]$execution.descendant_drain_elapsed_qpc_ticks -ne [long]$verifier.descendant_drain_elapsed_qpc_ticks -or
                [uint64]$execution.descendant_drain_elapsed_ms -ne [uint64]$verifier.descendant_drain_elapsed_ms -or
                [uint64]$execution.elapsed_ms -ne [uint64]$verifier.elapsed_ms -or
                [string]$execution.report_file -cne [string]$verifier.report_file -or
                [uint64]$execution.report_bytes -ne [uint64]$verifier.report_bytes -or
                [string]$execution.stdout_file -cne [string]$verifier.stdout_file -or
                [uint64]$execution.stdout_bytes -ne [uint64]$verifier.stdout_bytes -or
                [string]$execution.stderr_file -cne [string]$verifier.stderr_file -or
                [uint64]$execution.stderr_bytes -ne [uint64]$verifier.stderr_bytes -or
                [int]$execution.exit_code -ne 0 -or [int]$verifier.exit_code -ne 0 -or
                [int]$completed.body.payload.exit_code -ne 0 -or [uint64]$completed.body.payload.stderr_bytes -ne 0 -or
                [string]$completed.body.payload.execution_sha256 -cne [string]$verifier.execution_sha256 -or
                [string]$execution.report_sha256 -cne [string]$verifier.report_sha256 -or
                [string]$execution.stdout_sha256 -cne [string]$verifier.stdout_sha256 -or
                [string]$execution.stderr_sha256 -cne [string]$verifier.stderr_sha256 -or
                [uint64]$expectedTimeout -eq 0 -or [uint64]$execution.timeout_s -ne [uint64]$expectedTimeout -or
                -not (Test-MonitorVerifierExecutionBudget `
                    -ActualTimeoutSeconds ([uint64]$execution.timeout_s) `
                    -MaximumPerProcessTimeoutSeconds ([uint64]$Startup.verifier_policy.per_process_timeout_s) `
                    -ElapsedMilliseconds ([uint64]$execution.elapsed_ms)) -or
                -not (Test-MonitorQpcExecutionEvidence `
                    -ResumeQpcTimestamp ([long]$execution.resume_qpc_timestamp) `
                    -ElapsedQpcTicks ([long]$execution.elapsed_qpc_ticks) `
                    -MonotonicFrequency ([long]$execution.monotonic_frequency) `
                    -ExpectedFrequency ([long]$Startup.monotonic_frequency) `
                    -TimeoutSeconds ([uint64]$execution.timeout_s) `
                    -ElapsedMilliseconds ([uint64]$execution.elapsed_ms)) -or
                -not (Test-MonitorQpcExecutionEvidence `
                    -ResumeQpcTimestamp ([long]$execution.parent_exit_observed_qpc_timestamp) `
                    -ElapsedQpcTicks ([long]$execution.descendant_drain_elapsed_qpc_ticks) `
                    -MonotonicFrequency ([long]$execution.monotonic_frequency) `
                    -ExpectedFrequency ([long]$Startup.monotonic_frequency) `
                    -TimeoutSeconds 10 `
                    -ElapsedMilliseconds ([uint64]$execution.descendant_drain_elapsed_ms)) -or
                -not (Test-MonitorVerifierExecutionCausality `
                    -StartupOriginQpcTimestamp ([long]$Startup.monotonic_origin_qpc_timestamp) `
                    -BudgetComputedMonotonicTick ([uint64]$execution.global_budget_computed_monotonic_tick) `
                    -StartEventMonotonicTick ([uint64]$started.body.monotonic_tick) `
                    -CompletedEventMonotonicTick ([uint64]$completed.body.monotonic_tick) `
                    -ResumeQpcTimestamp ([long]$execution.resume_qpc_timestamp) `
                    -ElapsedQpcTicks ([long]$execution.elapsed_qpc_ticks) `
                    -ParentExitObservedQpcTimestamp ([long]$execution.parent_exit_observed_qpc_timestamp) `
                    -DescendantDrainElapsedQpcTicks ([long]$execution.descendant_drain_elapsed_qpc_ticks) `
                    -PreviousCompletedAbsoluteQpcTimestamp $previousVerifierCompletedAbsolute) -or
                [bool]$execution.timed_out -or -not [bool]$execution.report_present -or $null -ne $execution.failure) {
                throw "$symbol FAILED terminal verifier receipt/execution/event/artifact binding is invalid."
            }
            if ($name -clike "*-rust") {
                if ([string]$report.schema -cne "VerifiedRawCampaignV1" -or [string]$report.status -cne "PASS" -or
                    [string]$report.campaign_id -cne [string]$result.campaign_id -or
                    [string]$report.symbol -cne $symbol -or
                    [string]$report.campaign_manifest_sha256 -cne [string]$result.campaign_manifest_sha256 -or
                    [uint64]$report.journal_records -ne [uint64]$result.campaign_journal_committed_records -or
                    [string]$report.journal_terminal_sha256 -cne [string]$result.campaign_journal_terminal_sha256 -or
                    [string]$report.verification_sha256 -cne [string]$result.rust_verification_sha256) {
                    throw "$symbol sealed Rust report is not bound to its FAILED terminal result."
                }
            }
            else {
                if ([string]$report.schema -cne "RawCampaignVerificationV1" -or [string]$report.status -cne "VERIFIED" -or
                    [string]$report.campaign_id -cne [string]$result.campaign_id -or
                    [string]$report.symbol -cne $symbol -or
                    [string]$report.campaign_manifest_file_sha256 -cne [string]$result.campaign_manifest_sha256 -or
                    [uint64]$report.journal.records -ne [uint64]$result.campaign_journal_committed_records -or
                    [string]$report.journal.terminal_record_sha256 -cne [string]$result.campaign_journal_terminal_sha256 -or
                    [string]$report.verification_sha256 -cne [string]$result.python_verification_sha256) {
                    throw "$symbol sealed Python report is not bound to its FAILED terminal result."
                }
            }
            $previousVerifierCompletedAbsolute =
                [decimal]$Startup.monotonic_origin_qpc_timestamp + [decimal][uint64]$completed.body.monotonic_tick
        }
        $verifiedEvent = $History.causal_prefix.campaign_verified[$symbol]
        if (-not (Test-MonitorCampaignVerifiedReportBinding -VerifiedEvent $verifiedEvent -Verifiers $verifiers)) {
            throw "$symbol FAILED terminal result lacks exact INDEPENDENT_CAMPAIGN_VERIFIED report hashes."
        }
    }
    return [pscustomobject][ordered]@{
        durable_verified_events = [uint64]$verifiedRecords.Count
        sealed_campaign_results = [uint64]$results.Count
        unsealed_verified_events = [uint64]($verifiedRecords.Count - $results.Count)
    }
}

$null = Assert-RawQualificationNoReparsePointInExistingPath -Path $RunRoot
$resolvedRunRoot = (Resolve-Path -LiteralPath $RunRoot -ErrorAction Stop).Path
$null = Assert-MonitorEvidenceTreeNoReparsePoints -RunRoot $resolvedRunRoot
$startupPath = Join-Path $resolvedRunRoot "launcher-startup.json"
$processPath = Join-Path $resolvedRunRoot "processes.json"
$bindingPath = Join-Path $resolvedRunRoot "campaign-bindings.json"
$terminalPath = Join-Path $resolvedRunRoot "launcher-terminal.json"
$launcherJournalPath = Join-Path $resolvedRunRoot "launcher-events.jsonl"
$telemetryJournalPath = Join-Path $resolvedRunRoot "host-telemetry.jsonl"
$guardianPulseJournalPath = Join-Path $resolvedRunRoot "guardian-pulse.jsonl"
$terminalSnapshot = if (Test-Path -LiteralPath $terminalPath -PathType Leaf) {
    $null = Resolve-MonitorContainedEvidencePath -RunRoot $resolvedRunRoot -Path $terminalPath -RequireLeaf
    Read-MonitorCanonicalJsonSnapshot -Path $terminalPath -WriterKind PowerShellPretty
}
else { $null }
$terminal = if ($null -ne $terminalSnapshot) { $terminalSnapshot.value } else { $null }

if ($null -ne $terminal -and [string]$terminal.status -ceq "FAILED") {
    $null = Assert-MonitorTerminalWriterOrder -Terminal $terminal
    $null = Assert-MonitorTerminalV2JsonContract -Terminal $terminal
    $startupSnapshot = Get-MonitorFailedSingletonEvidence `
        -RunRoot $resolvedRunRoot -FileName "launcher-startup.json" `
        -ExpectedSha256 $terminal.startup_sha256 -WriterKind PowerShellPretty
    $controlSnapshot = Get-MonitorFailedSingletonEvidence `
        -RunRoot $resolvedRunRoot -FileName "processes.json" `
        -ExpectedSha256 $terminal.process_control_sha256 -WriterKind PowerShellPretty
    $bindingSnapshot = Get-MonitorFailedSingletonEvidence `
        -RunRoot $resolvedRunRoot -FileName "campaign-bindings.json" `
        -ExpectedSha256 $terminal.campaign_bindings_sha256 -WriterKind PowerShellPretty
    if ($null -ne $startupSnapshot) {
        $null = Assert-MonitorFailureContainmentJsonContract `
            -Value $terminal.failure_containment `
            -ExpectedMonotonicFrequency $startupSnapshot.value.monotonic_frequency
    }
    $null = Resolve-MonitorContainedEvidencePath -RunRoot $resolvedRunRoot `
        -Path $launcherJournalPath -RequireLeaf
    $launcherJournal = Get-VerifiedJournalSummary `
        -Path $launcherJournalPath -ExpectedSchema "RawQualificationLauncherEventV1"
    $failureHistory = Assert-MonitorFailedLauncherV2History `
        -Journal $launcherJournal `
        -Terminal $terminal `
        -TerminalSnapshot $terminalSnapshot `
        -Startup $(if ($null -ne $startupSnapshot) { $startupSnapshot.value } else { $null }) `
        -Control $(if ($null -ne $controlSnapshot) { $controlSnapshot.value } else { $null })
    $phaseEvidence = Assert-MonitorFailedSingletonPolicyEvidence `
        -RunRoot $resolvedRunRoot `
        -Terminal $terminal `
        -History $failureHistory `
        -StartupSnapshot $startupSnapshot `
        -ControlSnapshot $controlSnapshot `
        -BindingSnapshot $bindingSnapshot
    $telemetryJournal = Get-MonitorFailedJournalReceiptEvidence `
        -RunRoot $resolvedRunRoot `
        -ExpectedFileName "host-telemetry.jsonl" `
        -ExpectedSchema "RawQualificationHostTelemetryRecordV1" `
        -Receipt $terminal.host_telemetry
    $guardianPulseJournal = Get-MonitorFailedJournalReceiptEvidence `
        -RunRoot $resolvedRunRoot `
        -ExpectedFileName "guardian-pulse.jsonl" `
        -ExpectedSchema "RawQualificationGuardianPulseV1" `
        -Receipt $terminal.guardian_pulse
    if ([string]$failureHistory.phase -cne "RECORD0" -and
        ($null -eq $terminal.host_telemetry -or $null -eq $terminal.guardian_pulse -or
         $null -eq $telemetryJournal -or $null -eq $guardianPulseJournal)) {
        throw "POST_PREFLIGHT-or-later FAILED evidence lacks exact host/guardian journal receipts."
    }
    $watchdogStartedRecord = @($launcherJournal.all_records | Where-Object {
        [string]$_.body.payload.event -ceq "GUARDIAN_WATCHDOG_STARTED" })
    $artifactEvidence = Assert-MonitorFailedArtifactEvidence `
        -Terminal $terminal `
        -Startup $phaseEvidence.startup `
        -RunRoot $resolvedRunRoot `
        -WatchdogEvidenceRequired:($watchdogStartedRecord.Count -eq 1)
    $readyEvidence = $null
    $readyEvidenceState = if ($watchdogStartedRecord.Count -eq 1) { "EVENT_PRESENT_ARTIFACT_UNCHECKED" } else { "EVENT_ABSENT" }
    if ($watchdogStartedRecord.Count -eq 1) {
        if ($null -eq $phaseEvidence.startup) {
            throw "Watchdog-started FAILED phase lacks launcher startup authority."
        }
        $watchdogPayload = $watchdogStartedRecord[0].body.payload
        $readyPath = Join-Path $resolvedRunRoot "watchdog-ready.json"
        if (Test-Path -LiteralPath $readyPath -PathType Leaf) {
            $readyCurrentSha256 = $null
            try {
                $readyCurrentSha256 = Get-RawQualificationSha256File -Path $readyPath
            }
            catch { $readyEvidenceState = "CURRENT_UNREADABLE_OR_NONCANONICAL" }
            if ($null -ne $readyCurrentSha256) {
                if ([string]$readyCurrentSha256 -ceq [string]$watchdogPayload.ready_file_sha256) {
                    $readyEvidence = Assert-MonitorFailedWatchdogReadySnapshot `
                        -RunRoot $resolvedRunRoot `
                        -Startup $phaseEvidence.startup `
                        -FailureContainment $terminal.failure_containment `
                        -ExpectedSha256 ([string]$watchdogPayload.ready_file_sha256)
                    $readyEvidenceState = "CURRENT_MATCHES_DURABLE_WATCHDOG_EVENT"
                }
                else { $readyEvidenceState = "CURRENT_DRIFT_FROM_DURABLE_WATCHDOG_EVENT" }
            }
        }
        else { $readyEvidenceState = "CURRENT_ABSENT" }
        $watchdogEvidenceControl = [pscustomobject]@{
            ready_file = "watchdog-ready.json"
            job_name = [string]$terminal.failure_containment.job_name
            pid = [uint32]$watchdogPayload.pid
            launch_origin_qpc_timestamp = [long]$watchdogPayload.launch_origin_qpc_timestamp
            resume_qpc_timestamp = [long]$watchdogPayload.resume_qpc_timestamp
            ready_observed_qpc_timestamp = [long]$watchdogPayload.ready_observed_qpc_timestamp
            monotonic_frequency = [long]$phaseEvidence.startup.monotonic_frequency
            startup_deadline_s = [uint64]$watchdogPayload.startup_deadline_s
            ready_pulse_length = [uint64]$watchdogPayload.ready_pulse_length
            ready_file_sha256 = [string]$watchdogPayload.ready_file_sha256
        }
        if ($null -ne $phaseEvidence.control) {
            $actualWatchdog = $phaseEvidence.control.watchdog
            if ([uint32]$actualWatchdog.pid -ne [uint32]$watchdogEvidenceControl.pid -or
                [string]$actualWatchdog.job_name -cne [string]$terminal.failure_containment.job_name -or
                [IO.Path]::GetFullPath([string]$actualWatchdog.executable_path) -cne
                    [IO.Path]::GetFullPath([string]$phaseEvidence.startup.preflight.powershell_executable) -or
                [string]$actualWatchdog.executable_sha256 -cne
                    [string]$phaseEvidence.startup.preflight.powershell_executable_sha256 -or
                [IO.Path]::GetFullPath([string]$actualWatchdog.script_path) -cne
                    [IO.Path]::GetFullPath([string]$phaseEvidence.startup.preflight.watchdog_script) -or
                [string]$actualWatchdog.script_sha256 -cne
                    [string]$phaseEvidence.startup.preflight.watchdog_script_sha256 -or
                [long]$actualWatchdog.launch_origin_qpc_timestamp -ne
                    [long]$watchdogEvidenceControl.launch_origin_qpc_timestamp -or
                [long]$actualWatchdog.resume_qpc_timestamp -ne
                    [long]$watchdogEvidenceControl.resume_qpc_timestamp -or
                [long]$actualWatchdog.ready_observed_qpc_timestamp -ne
                    [long]$watchdogEvidenceControl.ready_observed_qpc_timestamp -or
                [string]$actualWatchdog.ready_file_sha256 -cne [string]$watchdogPayload.ready_file_sha256 -or
                [uint64]$actualWatchdog.ready_pulse_length -ne [uint64]$watchdogEvidenceControl.ready_pulse_length -or
                [string]$actualWatchdog.guardian_pulse_file -cne "guardian-pulse.jsonl" -or
                [string]$actualWatchdog.ready_file -cne "watchdog-ready.json" -or
                [string]$actualWatchdog.stdout_file -cne "watchdog.stdout.log" -or
                [string]$actualWatchdog.stderr_file -cne "watchdog.stderr.log") {
                throw "FAILED terminal watchdog process control, READY, event, and preflight provenance disagree."
            }
        }
    }
    if ([bool]$failureHistory.post_readiness) {
        if ($null -eq $telemetryJournal -or $null -eq $phaseEvidence.bindings) {
            throw "Post-readiness FAILED terminal lacks bound telemetry/bindings evidence."
        }
        $readinessRecord = @($launcherJournal.all_records | Where-Object {
            [string]$_.body.payload.event -ceq "DUAL_READINESS_PUBLISHED" })
        if ($readinessRecord.Count -ne 1) { throw "Post-readiness FAILED terminal lacks one publication receipt." }
        $null = Assert-DualReadinessReceipt `
            -Receipt $readinessRecord[0] `
            -TelemetryJournal $telemetryJournal `
            -Bindings $phaseEvidence.bindings `
            -ExpectedBindingsSha256 ([string]$bindingSnapshot.sha256)
    }
    $campaignResultEvidence = Assert-MonitorFailedCampaignResultEvidence `
        -Terminal $terminal `
        -History $failureHistory `
        -Startup $phaseEvidence.startup `
        -Control $phaseEvidence.control `
        -Bindings $phaseEvidence.bindings `
        -LauncherJournal $launcherJournal `
        -RunRoot $resolvedRunRoot
    $null = Assert-MonitorEvidenceTreeNoReparsePoints -RunRoot $resolvedRunRoot
    [pscustomobject][ordered]@{
        schema = "RawQualificationReadOnlyMonitorV1"
        status = "FAILED"
        stage = "FAILED"
        observed_utc = [DateTimeOffset]::UtcNow.ToString("o")
        run_id = [string]$terminal.run_id
        run_root = $resolvedRunRoot
        mode = [string]$terminal.mode
        failure = [string]$terminal.failure
        failure_containment = $terminal.failure_containment
        failure_containment_sha256 = [string]$terminal.failure_containment_sha256
        containment_certainty = [string]$failureHistory.containment_certainty
        artifact_observations = $artifactEvidence
        watchdog_ready_observation = $readyEvidenceState
        campaign_result_publication = $campaignResultEvidence
        launcher_journal_records = [uint64]$launcherJournal.records
        terminal_sha256 = [string]$terminalSnapshot.sha256
        failure_phase = [string]$failureHistory.phase
        post_readiness = [bool]$failureHistory.post_readiness
        launcher_terminal_byte_authentication = "CANONICAL_FROZEN_SNAPSHOT_WITH_EXACT_DURABLE_LAUNCHER_TERMINAL_POST_LINK"
        local_writer_toctou_boundary = "REPARSE_FREE_SNAPSHOTS_AND_FINAL_TREE_BARRIER_DO_NOT_AUTHENTICATE_A_MALICIOUS_LOCAL_WRITER_BETWEEN_HANDLES"
    } | ConvertTo-Json -Depth 40
    exit 1
}

foreach ($path in @($startupPath, $processPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing launcher identity file: $path" }
}
$startupSnapshot = Read-MonitorCanonicalJsonSnapshot -Path $startupPath -WriterKind PowerShellPretty
$controlSnapshot = Read-MonitorCanonicalJsonSnapshot -Path $processPath -WriterKind PowerShellPretty
$startup = $startupSnapshot.value
$control = $controlSnapshot.value
    $null = Assert-MonitorStartupControlJsonTypes -Startup $startup -Control $control -RequireWriterContract
    if ($null -ne $terminal) {
    $null = Assert-MonitorTerminalWriterOrder -Terminal $terminal
    $null = Assert-MonitorTerminalV2JsonContract `
        -Terminal $terminal `
        -ExpectedMonotonicFrequency ([long]$startup.monotonic_frequency)
    $null = Assert-MonitorTerminalVerifierPolicyBinding -Terminal $terminal -Startup $startup
    if ([IO.Path]::GetFullPath([string]$terminal.run_root).TrimEnd('\') -cne
        [IO.Path]::GetFullPath($resolvedRunRoot).TrimEnd('\')) {
        throw "Terminal run_root does not exactly equal the monitored RunRoot."
    }
}

if ($startup.schema -ne "RawQualificationLauncherStartupV1" -or
    $control.schema -ne "RawQualificationProcessControlV2" -or
    @("Production", "SevenDay", "Smoke", "Test") -cnotcontains [string]$startup.mode -or
    [uint64]$startup.parameters.total_s -lt [uint64]$startup.parameters.overlap_s -or
    [uint64]$startup.parameters.overlap_s -ne [uint64]$startup.parameters.segment_s -or
    ([uint64]$startup.parameters.rotation_s % [uint64]$startup.parameters.segment_s) -ne 0 -or
    ([uint64]$startup.parameters.rotation_s + [uint64]$startup.parameters.overlap_s) -gt 86300 -or
    ($startup.mode -ceq "Production" -and
     ([uint64]$startup.parameters.total_s -ne 86400 -or
      [uint64]$startup.parameters.rotation_s -ne 82800 -or
      [uint64]$startup.parameters.overlap_s -ne 900 -or
      [uint64]$startup.parameters.segment_s -ne 900 -or
      [uint64]$startup.verifier_policy.per_process_timeout_s -ne 43200 -or
      [uint64]$startup.verifier_policy.total_post_capture_timeout_s -ne 86400)) -or
    ($startup.mode -ceq "SevenDay" -and
     ([uint64]$startup.parameters.total_s -ne 604800 -or
      [uint64]$startup.parameters.rotation_s -ne 82800 -or
      [uint64]$startup.parameters.overlap_s -ne 900 -or
      [uint64]$startup.parameters.segment_s -ne 900 -or
      [uint64]$startup.verifier_policy.per_process_timeout_s -ne 43200 -or
      [uint64]$startup.verifier_policy.total_post_capture_timeout_s -ne 86400)) -or
    ($startup.mode -ceq "Smoke" -and
     ([uint64]$startup.parameters.total_s -ne 120 -or
      [uint64]$startup.parameters.rotation_s -ne 60 -or
      [uint64]$startup.parameters.overlap_s -ne 10 -or
      [uint64]$startup.parameters.segment_s -ne 10)) -or
    $startup.run_id -ne $control.run_id -or
    [IO.Path]::GetFullPath([string]$startup.run_root) -ne $resolvedRunRoot -or
    $startup.credentials -ne "NONE" -or
    $startup.order_entry -ne "ABSENT" -or
    [uint64]$startup.market_freshness_policy.startup_grace_s -ne [uint64]$ExpectedMarketFreshnessStartupGraceSeconds -or
    [uint64]$startup.market_freshness_policy.deadline_s -ne [uint64]$ExpectedMarketFreshnessDeadlineSeconds -or
    [uint64]$startup.coordinator_log_policy.maximum_stdout_bytes -ne [uint64](64MB) -or
    [uint64]$startup.coordinator_log_policy.maximum_stderr_bytes -ne 0 -or
    [uint64]$startup.coordinator_log_policy.child_stderr_events_allowed -ne 0 -or
    [uint64]$startup.verifier_policy.maximum_artifact_bytes -ne $MaximumCurrentVerifierArtifactBytes -or
    [uint64]$startup.verifier_policy.per_process_timeout_s -lt 60 -or
    [uint64]$startup.verifier_policy.per_process_timeout_s -gt 43200 -or
    [uint64]$startup.verifier_policy.total_post_capture_timeout_s -lt 300 -or
    [uint64]$startup.verifier_policy.total_post_capture_timeout_s -gt 86400 -or
    [uint64]$startup.preflight.host_probe_timeout_s -ne $ExpectedHostProbeTimeoutSeconds -or
    [uint64]$startup.preflight.host_probe_maximum_artifact_bytes -ne $ExpectedHostProbeMaximumArtifactBytes -or
    [uint64]$startup.preflight.guardian_watchdog_deadline_s -ne $ExpectedGuardianWatchdogDeadlineSeconds -or
    [uint64]$startup.preflight.guardian_watchdog_startup_deadline_s -ne $ExpectedGuardianWatchdogStartupDeadlineSeconds -or
    [uint64]$startup.preflight.python_runtime_fingerprint_timeout_s -ne $ExpectedPythonRuntimeFingerprintTimeoutSeconds -or
    $startup.guardian_policy.pulse_file -ne "guardian-pulse.jsonl" -or
    $startup.guardian_policy.watchdog_ready_file -ne "watchdog-ready.json" -or
    [uint64]$startup.guardian_policy.watchdog_startup_deadline_s -ne $ExpectedGuardianWatchdogStartupDeadlineSeconds -or
    [uint64]$startup.guardian_policy.watchdog_deadline_s -ne $ExpectedGuardianWatchdogDeadlineSeconds -or
    [uint64]$startup.guardian_policy.host_telemetry_gap_deadline_s -ne $ExpectedHostTelemetryGapDeadlineSeconds -or
    [uint64]$startup.guardian_policy.maximum_dual_launch_skew_ms -ne $ExpectedMaximumDualLaunchSkewMilliseconds -or
    [uint64]$startup.guardian_policy.generation_terminal_deadline_s -ne $ExpectedGenerationTerminalDeadlineSeconds -or
    [uint64]$startup.guardian_policy.campaign_commit_deadline_s -ne $ExpectedCampaignCommitDeadlineSeconds -or
    [long]$startup.monotonic_origin_qpc_timestamp -le 0 -or
    -not (Test-MonitorStartupMonotonicFrequency -Startup $startup) -or
    -not [bool]$control.job_kill_on_close -or
    -not [bool]$control.workload_job_kill_on_close -or
    [string]$control.job_object_name -ceq [string]$control.workload_job_object_name -or
    $control.launch_method -ne "CREATE_SUSPENDED_ASSIGN_OUTER_AND_WORKLOAD_JOBS_RESUME" -or
    [uint64]$control.capture_origin_monotonic_tick -eq 0 -or
    @($control.processes).Count -ne 2) {
    throw "Launcher startup/process-control identity is inconsistent."
}
if ([uint64]$HeartbeatMaxAgeSeconds -gt [uint64]$startup.market_freshness_policy.deadline_s) {
    throw "Monitor heartbeat freshness cannot be weaker than the authenticated launcher policy."
}
$outputPathValidation = $startup.output_path_post_create
if ($null -eq $outputPathValidation) {
    throw "Post-creation run-root same-volume/NTFS/reserve proof is absent."
}
$null = Assert-MonitorPostCreateProbeJsonTypes -Value $outputPathValidation
if (
    -not [bool]$outputPathValidation.reparse_points_rejected -or
    -not [bool]$outputPathValidation.same_preflight_volume -or
    $outputPathValidation.run_root_drive_device_id -ne $startup.preflight.drive_device_id -or
    $outputPathValidation.filesystem -ne "NTFS" -or
    [uint64]$outputPathValidation.free_gib -lt [uint64]$outputPathValidation.required_free_gib -or
    [uint64]$outputPathValidation.required_free_gib -ne [uint64]$startup.preflight.required_free_gib -or
    [uint32]$outputPathValidation.probe_pid -eq 0 -or
    [uint64]$outputPathValidation.probe_timeout_s -ne $ExpectedHostProbeTimeoutSeconds -or
    [uint64]$outputPathValidation.probe_elapsed_ms -gt ($ExpectedHostProbeTimeoutSeconds * [uint64]1000) -or
    $outputPathValidation.probe_stdout_file -ne "post-create-volume.stdout.json" -or
    $outputPathValidation.probe_stderr_file -ne "post-create-volume.stderr.log" -or
    [uint64]$outputPathValidation.probe_stderr_bytes -ne 0) {
    throw "Post-creation run-root same-volume/NTFS/reserve proof is invalid."
}
$null = Assert-PostCreateProbeEvidence `
    -Startup $startup `
    -OutputPathValidation $outputPathValidation `
    -ResolvedRunRoot $resolvedRunRoot
$childEnvironmentEntries = [string[]]@($startup.preflight.child_environment.Entries)
$declaredChildEnvironmentNames = @($startup.preflight.child_environment.names)
$childEnvironmentNames = @($childEnvironmentEntries | ForEach-Object {
    if ([string]::IsNullOrWhiteSpace($_) -or $_.IndexOf('=') -le 0) { throw "Malformed explicit child environment entry." }
    $_.Substring(0, $_.IndexOf('='))
})
$childEnvironmentMaterial = [string]::Join("`0", $childEnvironmentEntries) + "`0`0"
$childEnvironmentSha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UnicodeEncoding]::new($false, $false).GetBytes($childEnvironmentMaterial))
if ([string]$startup.preflight.child_environment.mode -cne "EXPLICIT_ALLOWLIST_NO_INHERITANCE" -or
    ($declaredChildEnvironmentNames -join ',') -cne "SystemDrive,SystemRoot,TEMP,TMP,WINDIR" -or
    ($childEnvironmentNames -join ',') -cne "SystemDrive,SystemRoot,TEMP,TMP,WINDIR" -or
    ($declaredChildEnvironmentNames -join "`n") -cne ($childEnvironmentNames -join "`n") -or
    [string]$childEnvironmentSha256 -cne [string]$startup.preflight.child_environment.entries_sha256 -or
    [string]$control.child_environment_mode -cne "EXPLICIT_ALLOWLIST_NO_INHERITANCE" -or
    (@($control.child_environment_names) -join ',') -cne "SystemDrive,SystemRoot,TEMP,TMP,WINDIR" -or
    (@($control.child_environment_names) -join "`n") -cne ($declaredChildEnvironmentNames -join "`n") -or
    [string]$control.child_environment_entries_sha256 -cne [string]$childEnvironmentSha256) {
    throw "Coordinator/verifier environment is not the exact explicit no-inheritance allowlist."
}
$watchdogControl = $control.watchdog
if ($null -eq $watchdogControl -or
    [uint32]$watchdogControl.pid -eq 0 -or
    [IO.Path]::GetFullPath([string]$watchdogControl.executable_path) -ne [IO.Path]::GetFullPath([string]$startup.preflight.powershell_executable) -or
    $watchdogControl.executable_sha256 -ne $startup.preflight.powershell_executable_sha256 -or
    [IO.Path]::GetFullPath([string]$watchdogControl.script_path) -ne [IO.Path]::GetFullPath([string]$startup.preflight.watchdog_script) -or
    $watchdogControl.script_sha256 -ne $startup.preflight.watchdog_script_sha256 -or
    $watchdogControl.job_name -ne $control.job_object_name -or
    [long]$watchdogControl.launch_origin_qpc_timestamp -lt [long]$startup.monotonic_origin_qpc_timestamp -or
    [long]$watchdogControl.resume_qpc_timestamp -lt [long]$watchdogControl.launch_origin_qpc_timestamp -or
    [long]$watchdogControl.ready_observed_qpc_timestamp -lt [long]$watchdogControl.resume_qpc_timestamp -or
    [long]$watchdogControl.monotonic_frequency -ne [long]$startup.monotonic_frequency -or
    [uint64]$watchdogControl.startup_deadline_s -ne $ExpectedGuardianWatchdogStartupDeadlineSeconds -or
    $watchdogControl.guardian_pulse_file -ne "guardian-pulse.jsonl" -or
    [uint64]$watchdogControl.maximum_guardian_pulse_age_s -ne $ExpectedGuardianWatchdogDeadlineSeconds -or
    $watchdogControl.ready_file -ne "watchdog-ready.json" -or
    [string]$watchdogControl.ready_file_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [uint64]$watchdogControl.ready_pulse_length -eq 0 -or
    $watchdogControl.stdout_file -ne "watchdog.stdout.log" -or
    $watchdogControl.stderr_file -ne "watchdog.stderr.log") {
    throw "Process control lacks the exact independent guardian watchdog identity."
}
$null = Get-MonitorWatchdogReadyEvidence `
    -ResolvedRunRoot $resolvedRunRoot `
    -Startup $startup `
    -WatchdogControl $watchdogControl
$controlRecords = @($control.processes)
$controlSymbols = @($controlRecords | ForEach-Object { [string]$_.symbol } | Sort-Object)
$controlPids = @($controlRecords | ForEach-Object { [uint32]$_.pid })
$controlStdout = @($controlRecords | ForEach-Object { [string]$_.stdout_file })
$controlStderr = @($controlRecords | ForEach-Object { [string]$_.stderr_file })
$btcControl = @($controlRecords | Where-Object { [string]$_.symbol -eq "BTCUSDT" })
$ethControl = @($controlRecords | Where-Object { [string]$_.symbol -eq "ETHUSDT" })
if (($controlSymbols -join ',') -ne "BTCUSDT,ETHUSDT" -or
    @($controlPids | Select-Object -Unique).Count -ne 2 -or
    @($controlStdout | Select-Object -Unique).Count -ne 2 -or
    @($controlStderr | Select-Object -Unique).Count -ne 2 -or
    $btcControl.Count -ne 1 -or
    $ethControl.Count -ne 1 -or
    $null -eq $btcControl[0].PSObject.Properties['launch_monotonic_tick'] -or
    $null -eq $ethControl[0].PSObject.Properties['launch_monotonic_tick'] -or
    [uint64]$btcControl[0].launch_monotonic_tick -eq 0 -or
    [uint64]$ethControl[0].launch_monotonic_tick -ne [uint64]$control.capture_origin_monotonic_tick -or
    [uint64]$btcControl[0].launch_monotonic_tick -gt [uint64]$ethControl[0].launch_monotonic_tick -or
    [uint64]$control.maximum_dual_launch_skew_ms -ne $ExpectedMaximumDualLaunchSkewMilliseconds -or
    [uint64]$control.launch_skew_ticks -ne ([uint64]$ethControl[0].launch_monotonic_tick - [uint64]$btcControl[0].launch_monotonic_tick) -or
    [uint64]$control.launch_skew_ticks -gt ($ExpectedMaximumDualLaunchSkewMilliseconds * [uint64]$startup.monotonic_frequency / [uint64]1000) -or
    [uint64]$control.launch_skew_ms -ne [uint64][math]::Ceiling(
        [decimal][uint64]$control.launch_skew_ticks * [decimal]1000 / [decimal][uint64]$startup.monotonic_frequency) -or
    $controlStdout -notcontains "btcusdt.stdout.log" -or
    $controlStdout -notcontains "ethusdt.stdout.log" -or
    $controlStderr -notcontains "btcusdt.stderr.log" -or
    $controlStderr -notcontains "ethusdt.stderr.log") {
    throw "Process control does not contain the exact unique BTCUSDT/ETHUSDT PID/log set."
}
foreach ($artifact in @(
    [pscustomobject]@{ Path = [string]$startup.preflight.campaign_executable; Hash = [string]$startup.preflight.campaign_executable_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.capture_executable; Hash = [string]$startup.preflight.capture_executable_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.campaign_verifier_executable; Hash = [string]$startup.preflight.campaign_verifier_executable_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.public_config; Hash = [string]$startup.preflight.public_config_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.source_lock; Hash = [string]$startup.preflight.source_lock_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.launcher_script; Hash = [string]$startup.preflight.launcher_script_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.monitor_script; Hash = [string]$startup.preflight.monitor_script_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.helper_script; Hash = [string]$startup.preflight.helper_script_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.telemetry_probe_script; Hash = [string]$startup.preflight.telemetry_probe_script_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.watchdog_script; Hash = [string]$startup.preflight.watchdog_script_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.python_runtime_fingerprint_script; Hash = [string]$startup.preflight.python_runtime_fingerprint_script_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.powershell_executable; Hash = [string]$startup.preflight.powershell_executable_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.python; Hash = [string]$startup.preflight.python_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.python_project; Hash = [string]$startup.preflight.python_project_sha256 },
    [pscustomobject]@{ Path = [string]$startup.preflight.python_requirements; Hash = [string]$startup.preflight.python_requirements_sha256 }
)) {
    if (-not (Test-Path -LiteralPath $artifact.Path -PathType Leaf) -or
        (Get-RawQualificationSha256File -Path $artifact.Path) -ne $artifact.Hash) {
        throw "A preflight-bound executable/config/source/script artifact changed: $($artifact.Path)"
    }
}
$pythonSourceTreeNow = Get-RawQualificationSourceTreeDigest -Root ([string]$startup.preflight.python_verifier_source.root)
if ($pythonSourceTreeNow.tree_sha256 -ne $startup.preflight.python_verifier_source.tree_sha256) {
    throw "The preflight-bound independent Python verifier source tree changed."
}
$pythonRuntimeNow = Get-RawQualificationPythonRuntimeDigest -PythonExecutable ([string]$startup.preflight.python)
if ($pythonRuntimeNow.tree_sha256 -ne $startup.preflight.python_runtime.tree_sha256 -or
    [uint64]$pythonRuntimeNow.file_count -ne [uint64]$startup.preflight.python_runtime.file_count -or
    [uint64]$pythonRuntimeNow.total_bytes -ne [uint64]$startup.preflight.python_runtime.total_bytes -or
    $pythonRuntimeNow.pyvenv_config_sha256 -ne $startup.preflight.python_runtime.pyvenv_config_sha256 -or
    $pythonRuntimeNow.base_executable_sha256 -ne $startup.preflight.python_runtime.base_executable_sha256) {
    throw "The preflight-bound Python base runtime/stdlib inventory changed."
}

$terminalComplete = $null -ne $terminal -and $terminal.status -eq "COMPLETE"
$terminalSealed = $terminalComplete
$liveCampaignJournalSnapshots = @()
$liveCoordinatorStdoutSnapshots = @()
$captureFreshnessCutoff = [uint64][math]::Max(0, [int64]$startup.parameters.total_s - 5)
$launcherIdentity = [pscustomobject]@{
    pid = [uint32]$startup.launcher_pid
    creation_time_utc = [string]$startup.launcher_creation_time_utc
    executable_path = [string]$startup.launcher_executable_path
    executable_sha256 = [string]$startup.launcher_executable_sha256
    command_line = [string]$startup.launcher_command_line
}
$launcherProcessHealth = Test-RawQualificationProcessIdentity -Identity $launcherIdentity
if (-not $terminalSealed -and (-not $launcherProcessHealth.running -or -not $launcherProcessHealth.valid)) {
    throw "The 24-hour guardian PID is absent, reused, or changed identity."
}
if ((Get-RawQualificationSha256File -Path $launcherIdentity.executable_path) -ne $launcherIdentity.executable_sha256) {
    throw "The guardian PowerShell executable digest changed."
}
$watchdogProcessHealth = Test-RawQualificationProcessIdentity -Identity $watchdogControl
$watchdogStdoutPath = Join-Path $resolvedRunRoot ([string]$watchdogControl.stdout_file)
$watchdogStderrPath = Join-Path $resolvedRunRoot ([string]$watchdogControl.stderr_file)
$watchdogFailurePath = Join-Path $resolvedRunRoot "watchdog-failure.json"
if (Test-Path -LiteralPath $watchdogFailurePath -PathType Leaf) {
    throw "Independent guardian watchdog recorded a hard-fencing failure."
}
foreach ($path in @($watchdogStdoutPath, $watchdogStderrPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or [uint64](Get-Item -LiteralPath $path).Length -ne 0) {
        throw "Independent guardian watchdog log is absent or non-empty: $path"
    }
}
if (-not $terminalSealed -and (-not $watchdogProcessHealth.running -or -not $watchdogProcessHealth.valid)) {
    throw "Independent guardian watchdog is absent, reused, or changed identity."
}

$launcherJournalPath = Join-Path $resolvedRunRoot "launcher-events.jsonl"
$telemetryJournalPath = Join-Path $resolvedRunRoot "host-telemetry.jsonl"
$guardianPulseJournalPath = Join-Path $resolvedRunRoot "guardian-pulse.jsonl"
$launcherJournal = Get-VerifiedJournalSummary `
    -Path $launcherJournalPath `
    -ExpectedSchema "RawQualificationLauncherEventV1"
$telemetryJournal = Get-VerifiedJournalSummary `
    -Path $telemetryJournalPath `
    -ExpectedSchema "RawQualificationHostTelemetryRecordV1"
$guardianPulseJournal = Get-VerifiedJournalSummary `
    -Path $guardianPulseJournalPath `
    -ExpectedSchema "RawQualificationGuardianPulseV1"
$launcherHistoryContract = Assert-LauncherEventHistory `
    -Journal $launcherJournal `
    -Startup $startup `
    -Control $control `
    -TerminalComplete $terminalComplete
if (-not (Test-MonitorBoundedExecutionCausality `
    -StartupOriginQpcTimestamp $startup.monotonic_origin_qpc_timestamp `
    -ContainerEventMonotonicTick $launcherHistoryContract.preflight.body.monotonic_tick `
    -ResumeQpcTimestamp $outputPathValidation.probe_resume_qpc_timestamp `
    -ElapsedQpcTicks $outputPathValidation.probe_elapsed_qpc_ticks `
    -ParentExitObservedQpcTimestamp $outputPathValidation.probe_parent_exit_observed_qpc_timestamp `
    -DescendantDrainElapsedQpcTicks $outputPathValidation.probe_descendant_drain_elapsed_qpc_ticks)) {
    throw "Post-create provider execution is not causally contained by PREFLIGHT_PASSED."
}
$null = Assert-GuardianPulseHistory -Journal $guardianPulseJournal -Startup $startup -Control $control
$null = Assert-HostTelemetryHistory `
    -Journal $telemetryJournal `
    -Startup $startup `
    -Control $control `
    -ExpectedProviderTimeoutSeconds $ExpectedHostProbeTimeoutSeconds `
    -MaximumProviderArtifactBytes $ExpectedHostProbeMaximumArtifactBytes

if ($guardianPulseJournal.last.body.channel -ne "GUARDIAN" -or
    $guardianPulseJournal.last.body.payload.event -ne "GUARDIAN_PULSE" -or
    @("STARTING", "CAPTURING", "DRAINING", "TERMINAL_EVALUATION", "HOST_TELEMETRY_PROVIDER", "PYTHON_RUNTIME_FINGERPRINT", "INDEPENDENT_VERIFICATION") -notcontains [string]$guardianPulseJournal.last.body.payload.stage) {
    throw "Independent guardian pulse journal has an invalid terminal record."
}
$guardianPulseObservedNowNs = Get-RawQualificationWallNs
$guardianPulseAgeSeconds = [double]($guardianPulseObservedNowNs - [uint64]$guardianPulseJournal.last.body.wall_ns) / 1e9
if ($guardianPulseAgeSeconds -lt -5) {
    throw "Independent guardian pulse has a future wall timestamp."
}
if (-not $terminalComplete -and $guardianPulseAgeSeconds -gt $ExpectedGuardianWatchdogDeadlineSeconds) {
    throw "Independent guardian pulse is stale."
}
$latestPulseTick = [uint64]$guardianPulseJournal.last.body.monotonic_tick
if ($latestPulseTick -lt [uint64]$control.capture_origin_monotonic_tick -or
    $null -eq $guardianPulseJournal.last.body.payload.PSObject.Properties['capture_elapsed_ms']) {
    throw "Latest guardian pulse is not bound to the dual-campaign monotonic origin."
}
$expectedPulseCaptureElapsedMs = [double]($latestPulseTick - [uint64]$control.capture_origin_monotonic_tick) * 1000.0 / [double][uint64]$startup.monotonic_frequency
if ([math]::Abs($expectedPulseCaptureElapsedMs - [double][uint64]$guardianPulseJournal.last.body.payload.capture_elapsed_ms) -gt 5000.0) {
    throw "Guardian pulse capture elapsed time differs from its exact monotonic origin/tick."
}

if ($launcherJournal.startup_binding_sha256 -ne $startupSnapshot.sha256 -or
    $launcherJournal.process_control_binding_sha256 -ne $controlSnapshot.sha256) {
    throw "Launcher journal does not bind the exact startup/process-control files."
}

if ($null -ne $terminal) {
    $terminalCampaignSymbols = @($terminal.campaigns | ForEach-Object { [string]$_.symbol } | Sort-Object)
    if ($terminal.schema -ne "RawQualificationLauncherTerminalV2" -or
        $terminal.run_id -ne $startup.run_id -or
        $terminal.mode -ne $startup.mode -or
        [uint64]$terminal.parameters.total_s -ne [uint64]$startup.parameters.total_s -or
        [uint64]$terminal.parameters.rotation_s -ne [uint64]$startup.parameters.rotation_s -or
        [uint64]$terminal.parameters.overlap_s -ne [uint64]$startup.parameters.overlap_s -or
        [uint64]$terminal.parameters.segment_s -ne [uint64]$startup.parameters.segment_s -or
        [uint64]$terminal.verifier_policy.per_process_timeout_s -ne
            [uint64]$startup.verifier_policy.per_process_timeout_s -or
        [uint64]$terminal.verifier_policy.total_post_capture_timeout_s -ne
            [uint64]$startup.verifier_policy.total_post_capture_timeout_s -or
        [uint64]$terminal.verifier_policy.maximum_artifact_bytes -ne
            [uint64]$startup.verifier_policy.maximum_artifact_bytes -or
        [uint64]$terminal.market_freshness_policy.startup_grace_s -ne [uint64]$ExpectedMarketFreshnessStartupGraceSeconds -or
        [uint64]$terminal.market_freshness_policy.deadline_s -ne [uint64]$ExpectedMarketFreshnessDeadlineSeconds -or
        $terminal.guardian_policy.pulse_file -ne "guardian-pulse.jsonl" -or
        $terminal.guardian_policy.watchdog_ready_file -ne "watchdog-ready.json" -or
        [uint64]$terminal.guardian_policy.watchdog_startup_deadline_s -ne $ExpectedGuardianWatchdogStartupDeadlineSeconds -or
        [uint64]$terminal.guardian_policy.watchdog_deadline_s -ne $ExpectedGuardianWatchdogDeadlineSeconds -or
        [uint64]$terminal.guardian_policy.host_telemetry_gap_deadline_s -ne $ExpectedHostTelemetryGapDeadlineSeconds -or
        [uint64]$terminal.guardian_policy.maximum_dual_launch_skew_ms -ne $ExpectedMaximumDualLaunchSkewMilliseconds -or
        [uint64]$terminal.guardian_policy.generation_terminal_deadline_s -ne $ExpectedGenerationTerminalDeadlineSeconds -or
        [uint64]$terminal.guardian_policy.campaign_commit_deadline_s -ne $ExpectedCampaignCommitDeadlineSeconds -or
        [uint64]$terminal.coordinator_log_policy.maximum_stdout_bytes -ne [uint64]$startup.coordinator_log_policy.maximum_stdout_bytes -or
        [uint64]$terminal.coordinator_log_policy.maximum_stderr_bytes -ne 0 -or
        [uint64]$terminal.coordinator_log_policy.child_stderr_events_allowed -ne 0 -or
        @($terminal.campaigns).Count -ne 2 -or
        ($terminalCampaignSymbols -join ',') -ne "BTCUSDT,ETHUSDT" -or
        [uint64]$terminal.launcher_events.records + [uint64]1 -ne [uint64]$launcherJournal.records -or
        $terminal.launcher_events.terminal_record_sha256 -ne [string]$launcherJournal.penultimate.record_sha256 -or
        [uint64]$terminal.launcher_events.file_bytes -ne [uint64]$launcherJournal.preterminal_prefix_bytes -or
        $terminal.launcher_events.file_sha256 -ne [string]$launcherJournal.preterminal_prefix_sha256 -or
        [uint64]$terminal.host_telemetry.records -ne [uint64]$telemetryJournal.records -or
        $terminal.host_telemetry.terminal_record_sha256 -ne $telemetryJournal.terminal_record_sha256 -or
        $terminal.host_telemetry.file_sha256 -ne [string]$telemetryJournal.file_sha256 -or
        [uint64]$terminal.guardian_pulse.records -ne [uint64]$guardianPulseJournal.records -or
        $terminal.guardian_pulse.terminal_record_sha256 -ne $guardianPulseJournal.terminal_record_sha256 -or
        $terminal.guardian_pulse.file_sha256 -ne [string]$guardianPulseJournal.file_sha256) {
        throw "Terminal manifest does not bind the exact launcher/telemetry journals."
    }
    if ($launcherJournal.partial_tail -or $telemetryJournal.partial_tail -or $guardianPulseJournal.partial_tail) {
        throw "A terminal COMPLETE/FAILED manifest cannot bind a partial launcher journal tail."
    }
    if ($terminal.status -eq "COMPLETE" -and
        ($terminal.artifact_hashes_preflight.python_runtime_tree_sha256 -ne $startup.preflight.python_runtime.tree_sha256 -or
         $terminal.artifact_hashes_terminal.python_runtime_tree_sha256 -ne $startup.preflight.python_runtime.tree_sha256 -or
         $terminal.artifact_hashes_terminal.watchdog_ready_file_sha256 -ne $watchdogControl.ready_file_sha256 -or
         $terminal.artifact_hashes_terminal.python_pyvenv_config_sha256 -ne $startup.preflight.python_runtime.pyvenv_config_sha256 -or
         $terminal.artifact_hashes_terminal.python_base_executable_sha256 -ne $startup.preflight.python_runtime.base_executable_sha256)) {
        throw "Terminal COMPLETE does not bind the exact Python runtime provenance."
    }
    if ($terminal.status -eq "COMPLETE") {
        $terminalArtifactExpectations = [ordered]@{
            campaign_executable_sha256 = [string]$startup.preflight.campaign_executable_sha256
            capture_executable_sha256 = [string]$startup.preflight.capture_executable_sha256
            campaign_verifier_executable_sha256 = [string]$startup.preflight.campaign_verifier_executable_sha256
            public_config_sha256 = [string]$startup.preflight.public_config_sha256
            source_lock_sha256 = [string]$startup.preflight.source_lock_sha256
            launcher_script_sha256 = [string]$startup.preflight.launcher_script_sha256
            monitor_script_sha256 = [string]$startup.preflight.monitor_script_sha256
            helper_script_sha256 = [string]$startup.preflight.helper_script_sha256
            telemetry_probe_script_sha256 = [string]$startup.preflight.telemetry_probe_script_sha256
            watchdog_script_sha256 = [string]$startup.preflight.watchdog_script_sha256
            python_runtime_fingerprint_script_sha256 = [string]$startup.preflight.python_runtime_fingerprint_script_sha256
            powershell_executable_sha256 = [string]$startup.preflight.powershell_executable_sha256
            python_executable_sha256 = [string]$startup.preflight.python_sha256
            python_verifier_source_tree_sha256 = [string]$startup.preflight.python_verifier_source.tree_sha256
            python_runtime_tree_sha256 = [string]$startup.preflight.python_runtime.tree_sha256
            python_pyvenv_config_sha256 = [string]$startup.preflight.python_runtime.pyvenv_config_sha256
            python_base_executable_sha256 = [string]$startup.preflight.python_runtime.base_executable_sha256
            python_project_sha256 = [string]$startup.preflight.python_project_sha256
            python_requirements_sha256 = [string]$startup.preflight.python_requirements_sha256
        }
        foreach ($property in $terminalArtifactExpectations.Keys) {
            if ($null -eq $terminal.artifact_hashes_preflight.PSObject.Properties[$property] -or
                $null -eq $terminal.artifact_hashes_terminal.PSObject.Properties[$property] -or
                [string]$terminal.artifact_hashes_preflight.$property -ne [string]$terminalArtifactExpectations[$property] -or
                [string]$terminal.artifact_hashes_terminal.$property -ne [string]$terminalArtifactExpectations[$property]) {
                throw "Terminal COMPLETE artifact provenance mismatch: $property"
            }
        }
    }
    if ($terminal.status -eq "COMPLETE" -and
        ($launcherJournal.last.body.channel -ne "LAUNCHER" -or
         $launcherJournal.last.body.payload.event -ne "LAUNCHER_TERMINAL" -or
         $launcherJournal.last.body.payload.status -ne "COMPLETE" -or
         $null -ne $launcherJournal.last.body.payload.failure -or
         [string]$launcherJournal.last.body.payload.terminal_file -cne "launcher-terminal.json" -or
         [uint64]$launcherJournal.last.body.payload.terminal_bytes -ne [uint64]$terminalSnapshot.length -or
         [string]$launcherJournal.last.body.payload.terminal_sha256 -cne [string]$terminalSnapshot.sha256 -or
         $null -ne $launcherJournal.last.body.payload.failure_containment_sha256)) {
        throw "Terminal COMPLETE is not the last exact successful LAUNCHER_TERMINAL journal record."
    }
    if ($terminal.status -eq "COMPLETE") {
        $drainingStage = $launcherJournal.capture_draining_record
        $terminalEvaluationStage = $launcherJournal.terminal_evaluation_record
        $independentVerificationStage = $launcherJournal.independent_verification_record
        if ($null -eq $drainingStage -or
            $null -eq $terminalEvaluationStage -or
            $null -eq $independentVerificationStage -or
            $drainingStage.body.channel -ne "PROCESS" -or
            $drainingStage.body.payload.event -ne "CAPTURE_DRAINING_STARTED" -or
            [uint64]$drainingStage.body.payload.generation_terminal_deadline_elapsed_s -ne
                ([uint64]$startup.parameters.total_s + $ExpectedGenerationTerminalDeadlineSeconds) -or
            $terminalEvaluationStage.body.channel -ne "PROCESS" -or
            $terminalEvaluationStage.body.payload.event -ne "CAMPAIGN_TERMINAL_EVALUATION_STARTED" -or
            [uint64]$terminalEvaluationStage.body.payload.commit_deadline_s -ne $ExpectedCampaignCommitDeadlineSeconds -or
            $independentVerificationStage.body.channel -ne "VERIFICATION" -or
            $independentVerificationStage.body.payload.event -ne "INDEPENDENT_VERIFICATION_STAGE_STARTED" -or
            [uint64]$independentVerificationStage.body.payload.deadline_s -ne [uint64]$startup.verifier_policy.total_post_capture_timeout_s -or
            [uint64]$drainingStage.body.record_index -ge [uint64]$terminalEvaluationStage.body.record_index -or
            [uint64]$terminalEvaluationStage.body.record_index -ge [uint64]$independentVerificationStage.body.record_index -or
            [uint64]$drainingStage.body.monotonic_tick -gt [uint64]$terminalEvaluationStage.body.monotonic_tick -or
            [uint64]$terminalEvaluationStage.body.monotonic_tick -gt [uint64]$independentVerificationStage.body.monotonic_tick) {
            throw "Terminal COMPLETE lacks the exact unique ordered DRAINING -> TERMINAL_EVALUATION -> INDEPENDENT_VERIFICATION stage contract."
        }
    }
    if ($terminal.status -eq "COMPLETE") {
        $watchdogTerminal = $terminal.watchdog
        $null = Assert-MonitorTerminalWatchdogJsonTypes -Value $watchdogTerminal
        $watchdogStopPath = Join-Path $resolvedRunRoot ([string]$watchdogTerminal.stop_file)
        if ($null -eq $launcherJournal.watchdog_stop_record -or
            $null -eq $watchdogTerminal.PSObject.Properties['stop_request_qpc_timestamp'] -or
            $null -eq $watchdogTerminal.PSObject.Properties['exit_elapsed_qpc_ticks'] -or
            $null -eq $watchdogTerminal.PSObject.Properties['final_job_drain_elapsed_qpc_ticks'] -or
            $null -eq $watchdogTerminal.PSObject.Properties['monotonic_frequency'] -or
            $null -eq $watchdogTerminal.PSObject.Properties['final_job_drain_elapsed_ms'] -or
            $null -eq $launcherJournal.watchdog_stop_record.PSObject.Properties['stop_request_qpc_timestamp'] -or
            $null -eq $launcherJournal.watchdog_stop_record.PSObject.Properties['exit_elapsed_qpc_ticks'] -or
            $null -eq $launcherJournal.watchdog_stop_record.PSObject.Properties['final_job_drain_elapsed_qpc_ticks'] -or
            $null -eq $launcherJournal.watchdog_stop_record.PSObject.Properties['monotonic_frequency'] -or
            [uint32]$launcherJournal.watchdog_stop_record.pid -ne [uint32]$watchdogControl.pid -or
            [int]$launcherJournal.watchdog_stop_record.exit_code -ne 0 -or
            [uint32]$launcherJournal.watchdog_stop_record.final_job_active_processes -ne 0 -or
            $watchdogTerminal.stop_file -ne "watchdog-stop.json" -or
            -not (Test-Path -LiteralPath $watchdogStopPath -PathType Leaf) -or
            (Get-RawQualificationSha256File -Path $watchdogStopPath) -ne $watchdogTerminal.stop_file_sha256 -or
            $watchdogTerminal.stop_file_sha256 -ne $launcherJournal.watchdog_stop_record.stop_file_sha256 -or
            [uint32]$watchdogTerminal.pid -ne [uint32]$watchdogControl.pid -or
            [int]$watchdogTerminal.exit_code -ne 0 -or
            [long]$watchdogTerminal.stop_request_qpc_timestamp -ne [long]$launcherJournal.watchdog_stop_record.stop_request_qpc_timestamp -or
            [long]$watchdogTerminal.exit_elapsed_qpc_ticks -ne [long]$launcherJournal.watchdog_stop_record.exit_elapsed_qpc_ticks -or
            [long]$watchdogTerminal.final_job_drain_elapsed_qpc_ticks -ne [long]$launcherJournal.watchdog_stop_record.final_job_drain_elapsed_qpc_ticks -or
            [long]$watchdogTerminal.monotonic_frequency -ne [long]$launcherJournal.watchdog_stop_record.monotonic_frequency -or
            -not (Test-MonitorQpcExecutionEvidence `
                -ResumeQpcTimestamp ([long]$watchdogTerminal.stop_request_qpc_timestamp) `
                -ElapsedQpcTicks ([long]$watchdogTerminal.exit_elapsed_qpc_ticks) `
                -MonotonicFrequency ([long]$watchdogTerminal.monotonic_frequency) `
                -ExpectedFrequency ([long]$startup.monotonic_frequency) `
                -TimeoutSeconds 10 `
                -ElapsedMilliseconds ([uint64]$watchdogTerminal.elapsed_ms)) -or
            -not (Test-MonitorQpcExecutionEvidence `
                -ResumeQpcTimestamp ([long]$watchdogTerminal.stop_request_qpc_timestamp) `
                -ElapsedQpcTicks ([long]$watchdogTerminal.final_job_drain_elapsed_qpc_ticks) `
                -MonotonicFrequency ([long]$watchdogTerminal.monotonic_frequency) `
                -ExpectedFrequency ([long]$startup.monotonic_frequency) `
                -TimeoutSeconds 10 `
                -ElapsedMilliseconds ([uint64]$watchdogTerminal.final_job_drain_elapsed_ms)) -or
            [uint64]$watchdogTerminal.stdout_bytes -ne 0 -or
            [uint64]$watchdogTerminal.stderr_bytes -ne 0 -or
            [uint32]$watchdogTerminal.final_job_active_processes -ne 0 -or
            $watchdogTerminal.stdout_sha256 -ne (Get-RawQualificationSha256File -Path $watchdogStdoutPath) -or
            $watchdogTerminal.stderr_sha256 -ne (Get-RawQualificationSha256File -Path $watchdogStderrPath)) {
            throw "Terminal COMPLETE lacks exact watchdog clean-stop/job-drain evidence."
        }
    }
}

$telemetryObservedNowNs = Get-RawQualificationWallNs
$telemetryAgeSeconds = [double]($telemetryObservedNowNs - [uint64]$telemetryJournal.last.body.wall_ns) / 1e9
$captureOriginTick = [uint64]$control.capture_origin_monotonic_tick
$telemetryMonotonicTick = [uint64]$telemetryJournal.last.body.monotonic_tick
if ($telemetryMonotonicTick -lt $captureOriginTick -or
    $null -eq $telemetryJournal.last.body.payload.PSObject.Properties['capture_elapsed_ms']) {
    throw "Host telemetry lacks a monotonic duration measured from the dual-campaign origin."
}
$expectedCaptureElapsedMs = [double]($telemetryMonotonicTick - $captureOriginTick) * 1000.0 / [double][uint64]$startup.monotonic_frequency
$observedCaptureElapsedMs = [double][uint64]$telemetryJournal.last.body.payload.capture_elapsed_ms
if ([math]::Abs($expectedCaptureElapsedMs - $observedCaptureElapsedMs) -gt 5000.0) {
    throw "Host telemetry capture elapsed time differs from its exact monotonic origin/tick."
}
$captureRequiresLiveFreshness = Test-MonitorCaptureRequiresLiveFreshness `
    -LauncherHistoryContract $launcherHistoryContract
if ($telemetryAgeSeconds -lt -5) {
    throw "Latest host telemetry has a future wall timestamp; clock ordering is ambiguous."
}
if (-not $terminalComplete -and $telemetryAgeSeconds -gt $TelemetryMaxAgeSeconds) {
    throw "Host telemetry is stale by $([math]::Round($telemetryAgeSeconds, 3)) seconds."
}
if ($null -ne $telemetryJournal.penultimate -and
    [uint64]$telemetryJournal.last.body.monotonic_tick -le [uint64]$telemetryJournal.penultimate.body.monotonic_tick) {
    throw "Host telemetry monotonic sampling did not advance."
}
if (-not [bool]$telemetryJournal.last.body.payload.clock.healthy) {
    throw "Latest host telemetry records an unhealthy clock."
}
$latestDiskFreeGiB = [uint64][math]::Floor([double]$telemetryJournal.last.body.payload.disk.free_bytes / 1GB)
if ([uint64]$telemetryJournal.last.body.payload.disk_persistent_reserve_gib -ne [uint64]$startup.preflight.persistent_reserve_gib -or
    [uint64]$telemetryJournal.last.body.payload.disk_projected_remaining_gib -gt [uint64]$startup.preflight.projected_remaining_gib_at_start -or
    [uint64]$telemetryJournal.last.body.payload.disk_required_free_gib -ne
        ([uint64]$telemetryJournal.last.body.payload.disk_persistent_reserve_gib + [uint64]$telemetryJournal.last.body.payload.disk_projected_remaining_gib) -or
    $latestDiskFreeGiB -lt [uint64]$telemetryJournal.last.body.payload.disk_required_free_gib) {
    throw "Latest host telemetry violates persistent-reserve plus remaining-projection disk policy."
}
$bindingSnapshot = if (Test-Path -LiteralPath $bindingPath -PathType Leaf) {
    Read-MonitorCanonicalJsonSnapshot -Path $bindingPath -WriterKind PowerShellPretty
}
else { $null }
$bindings = if ($null -ne $bindingSnapshot) { $bindingSnapshot.value } else { $null }
if ($null -eq $bindings -and -not $terminalComplete) {
    throw "Dual semantic readiness has not been durably bound yet."
}
if ($null -ne $bindings -and ($bindings.schema -ne "RawQualificationCampaignBindingsV1" -or @($bindings.campaigns).Count -ne 2)) {
    throw "Campaign bindings are malformed."
}
if ($null -ne $bindings) {
    $null = Assert-MonitorBindingsWriterOrder -Bindings $bindings
    $bindingSymbols = @($bindings.campaigns | ForEach-Object { [string]$_.symbol } | Sort-Object)
    $bindingPids = @($bindings.campaigns | ForEach-Object { [uint32]$_.pid })
    $bindingIds = @($bindings.campaigns | ForEach-Object { [string]$_.campaign_id })
    if (($bindingSymbols -join ',') -ne "BTCUSDT,ETHUSDT" -or
        @($bindingPids | Select-Object -Unique).Count -ne 2 -or
        @($bindingIds | Select-Object -Unique).Count -ne 2) {
        throw "Campaign bindings do not contain exact unique BTCUSDT/ETHUSDT identities."
    }
}
if ($null -ne $bindings -and
    $launcherJournal.campaign_bindings_sha256 -ne $bindingSnapshot.sha256) {
    throw "Launcher journal does not bind the exact campaign-bindings file."
}
if ($null -ne $bindings) {
    $null = Assert-DualReadinessReceipt `
        -Receipt $launcherHistoryContract.readiness_published `
        -TelemetryJournal $telemetryJournal `
        -Bindings $bindings `
        -ExpectedBindingsSha256 ([string]$launcherJournal.campaign_bindings_sha256)
}
if ($null -ne $terminal -and
    ($terminal.startup_sha256 -ne $startupSnapshot.sha256 -or
     $terminal.process_control_sha256 -ne $controlSnapshot.sha256 -or
     $null -eq $bindingSnapshot -or $terminal.campaign_bindings_sha256 -ne $bindingSnapshot.sha256)) {
    throw "Terminal manifest does not bind its immutable control manifests."
}

$processHealth = @()
$campaignHealth = @()
$scheduleDeviationReasons = @()
$generationTerminalEvidence = @()
$currentReverificationEvidence = @()
$sealedVerifierPidCreationIdentities = @{}
$previousVerifierCompletionAbsoluteQpcTimestamp = $null
if ($terminalComplete -and $launcherJournal.campaign_exit_records.Count -ne 2) {
    throw "Terminal COMPLETE requires exactly two unique CAMPAIGN_PROCESS_EXITED proofs."
}
foreach ($record in @($control.processes | Sort-Object symbol)) {
    $coordinatorStdoutPath = Join-Path $resolvedRunRoot ([string]$record.stdout_file)
    $coordinatorStderrPath = Join-Path $resolvedRunRoot ([string]$record.stderr_file)
    if (-not (Test-Path -LiteralPath $coordinatorStdoutPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $coordinatorStderrPath -PathType Leaf) -or
        [uint64](Get-Item -LiteralPath $coordinatorStdoutPath).Length -gt [uint64]$startup.coordinator_log_policy.maximum_stdout_bytes -or
        [uint64](Get-Item -LiteralPath $coordinatorStderrPath).Length -ne 0) {
        throw "$($record.symbol) coordinator logs are absent, oversized, or contain forbidden stderr."
    }
    $identity = Test-RawQualificationProcessIdentity -Identity $record
    $campaignExit = if ($launcherJournal.campaign_exit_records.ContainsKey([string]$record.symbol)) {
        $launcherJournal.campaign_exit_records[[string]$record.symbol]
    }
    else { $null }
    $cleanCaptureExit = $null -ne $campaignExit -and
        [uint32]$campaignExit.pid -eq [uint32]$record.pid -and
        [int]$campaignExit.exit_code -eq 0 -and
        [uint64]$campaignExit.elapsed_s -ge $captureFreshnessCutoff
    $processDisposition = Get-MonitorCoordinatorProcessDisposition `
        -Symbol ([string]$record.symbol) `
        -Identity $identity `
        -CleanCaptureExit $cleanCaptureExit `
        -TerminalComplete $terminalComplete
    $originalRunning = [bool]$processDisposition.original_running
    if ((Get-RawQualificationSha256File -Path $record.executable_path) -ne $record.executable_sha256) {
        throw "$($record.symbol) release executable digest changed on disk."
    }
    $processHealth += [pscustomobject][ordered]@{
        symbol = $record.symbol
        pid = [uint32]$record.pid
        running = [bool]$originalRunning
        exact_identity = [bool]$processDisposition.exact_identity
        pid_occupied = [bool]$processDisposition.pid_occupied
        pid_reused_after_exit = [bool]$processDisposition.pid_reused_after_exit
        clean_capture_exit_proven = [bool]$cleanCaptureExit
    }

    if ($null -eq $bindings) { continue }
    $binding = @($bindings.campaigns | Where-Object { $_.symbol -eq $record.symbol })
    if ($binding.Count -ne 1 -or [uint32]$binding[0].pid -ne [uint32]$record.pid) {
        throw "$($record.symbol) campaign binding does not match process identity."
    }
    $campaignDirectory = [IO.Path]::GetFullPath([string]$binding[0].campaign_directory)
    if (-not [IO.Path]::GetDirectoryName($campaignDirectory).Equals($resolvedRunRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$($record.symbol) bound campaign directory escaped the run root."
    }
    $campaignStartupPath = Join-Path $campaignDirectory "campaign-startup.json"
    $campaignStartupSnapshot = Read-MonitorCanonicalJsonSnapshot `
        -Path $campaignStartupPath -WriterKind TwoSpacePretty
    $null = Assert-MonitorRustCampaignSingletonWriterOrder `
        -Value $campaignStartupSnapshot.value -Kind Startup
    $null = Assert-MonitorCampaignStartupBinding `
        -CampaignStartup $campaignStartupSnapshot.value `
        -CampaignStartupSha256 ([string]$campaignStartupSnapshot.sha256) `
        -Binding $binding[0] `
        -LauncherStartup $startup `
        -ControlProcess $record
    if ($campaignStartupSnapshot.sha256 -ne $binding[0].campaign_startup_sha256) {
        throw "$($record.symbol) campaign startup digest differs from its binding."
    }
    $campaignJournalPath = Join-Path $campaignDirectory "campaign-events.jsonl"
    $journal = Get-CampaignJournalHealth `
        -Path $campaignJournalPath `
        -CampaignStartup $campaignStartupSnapshot.value `
        -CampaignStartupSha256 ([string]$campaignStartupSnapshot.sha256)
    if (-not $terminalComplete) {
        # Historical replay is deliberately off the freshness edge. Authenticate it
        # once, then catch up from its exact byte/hash/lifecycle cursor before any
        # live-age decision. This preserves the 30-second market deadline without
        # letting replay time manufacture a false stale result.
        $journal = Get-CampaignJournalHealth `
            -Path $campaignJournalPath `
            -CampaignStartup $campaignStartupSnapshot.value `
            -CampaignStartupSha256 ([string]$campaignStartupSnapshot.sha256) `
            -ExpectedPrefixRecords ([uint64]$journal.records) `
            -ExpectedPrefixTerminalRecordSha256 ([string]$journal.terminal_record_sha256) `
            -ExpectedPrefixFileLength ([uint64]$journal.file_length) `
            -ExpectedPrefixFileSha256 ([string]$journal.file_sha256) `
            -ContinuationState $journal.continuation_state
        $liveCampaignJournalSnapshots += [pscustomobject]@{
            symbol = [string]$record.symbol
            path = $campaignJournalPath
            records = [uint64]$journal.records
            terminal_record_sha256 = [string]$journal.terminal_record_sha256
            file_length = [uint64]$journal.file_length
            file_sha256 = [string]$journal.file_sha256
            complete_length = [uint64]$journal.complete_length
            complete_sha256 = [string]$journal.complete_sha256
            continuation_state = $journal.continuation_state
            campaign_startup = $campaignStartupSnapshot.value
            campaign_startup_sha256 = [string]$campaignStartupSnapshot.sha256
        }
    }
    $campaignObservedNowNs = Get-RawQualificationWallNs
    $generationRows = @($journal.generation_health)
    $generationTerminalComplete = $generationRows.Count -gt 0 -and
        @($generationRows | Where-Object { -not [bool]$_.terminal -or -not [bool]$_.exited }).Count -eq 0
    $latestGenerationTerminalWallNs = [uint64]0
    foreach ($generationRow in $generationRows) {
        $latestGenerationTerminalWallNs = [uint64][math]::Max(
            [double]$latestGenerationTerminalWallNs,
            [math]::Max([double][uint64]$generationRow.terminal_wall_ns, [double][uint64]$generationRow.exited_wall_ns))
    }
    $generationTerminalEvidence += [pscustomobject]@{
        symbol = [string]$record.symbol
        complete = [bool]$generationTerminalComplete
        latest_wall_ns = $latestGenerationTerminalWallNs
    }
    if ($originalRunning -and -not $generationTerminalComplete -and
        [uint64]$telemetryJournal.last.body.payload.capture_elapsed_ms -gt
            (([uint64]$startup.parameters.total_s + $ExpectedGenerationTerminalDeadlineSeconds) * [uint64]1000)) {
        throw "$($record.symbol) exceeded the final per-generation terminal evidence deadline."
    }
    if ($journal.campaign_failed) {
        if (-not (Test-RawQualificationJsonString $journal.campaign_failure_reason) -or
            -not (Test-RawQualificationJsonSha256 $journal.campaign_failure_record_sha256)) {
            throw "$($record.symbol) campaign journal reports failure without an exact durable cause binding."
        }
        throw "$($record.symbol) campaign failed: $($journal.campaign_failure_reason) [journal $($journal.campaign_failure_record_sha256)]"
    }
    if (-not $journal.process_started -or
        -not $journal.depth_connected -or
        -not $journal.trade_connected -or
        -not $journal.snapshot_durable -or
        $null -eq $journal.latest_heartbeat -or
        [uint64]$journal.child_stderr_events -ne 0) {
        throw "$($record.symbol) campaign journal lacks current semantic health evidence."
    }
    foreach ($generation in @($journal.generation_health)) {
        $generationWallNs = if ([uint64]$generation.last_heartbeat_wall_ns -ne 0) {
            [uint64]$generation.last_heartbeat_wall_ns
        }
        else { [uint64]$generation.launch_wall_ns }
        $generationHeartbeatAgeSeconds = [double]($campaignObservedNowNs - $generationWallNs) / 1e9
        if ($generationHeartbeatAgeSeconds -lt -5) {
            throw "$($record.symbol) generation $($generation.generation_index) health has a future wall timestamp."
        }
        $generationStillActive = -not [bool]$generation.terminal -and
            ([uint64]$generation.telemetry_mono_ns -eq 0 -or
             [uint64]$generation.telemetry_mono_ns -lt ([uint64]$generation.duration_s * [uint64]1000000000))
        if ($generationStillActive -and $captureRequiresLiveFreshness -and
            $generationHeartbeatAgeSeconds -gt $HeartbeatMaxAgeSeconds) {
            throw "$($record.symbol) generation $($generation.generation_index) durable market-health heartbeat is stale."
        }
    }
    if ($startup.mode -in @("Production", "SevenDay") -and
        ([uint64]$journal.server_shutdown_generation_launches -ne 0 -or
         [uint64]$journal.server_shutdown_events -ne 0)) {
        $scheduleDeviationReasons += "$($record.symbol): official serverShutdown path observed"
    }
    $heartbeatAgeSeconds = [double]($campaignObservedNowNs - [uint64]$journal.latest_heartbeat.body.wall_ns) / 1e9
    if ($heartbeatAgeSeconds -lt -5) {
        throw "$($record.symbol) durable child heartbeat has a future wall timestamp."
    }
    $coordinatorStdoutPath = Join-Path $resolvedRunRoot ([string]$record.stdout_file)
    $coordinatorStdoutLengthBefore = [uint64](Get-Item -LiteralPath $coordinatorStdoutPath -ErrorAction Stop).Length
    $lastStdoutHeartbeat = Get-LastCampaignHeartbeat -Path $coordinatorStdoutPath
    $coordinatorStdoutLengthAfter = [uint64](Get-Item -LiteralPath $coordinatorStdoutPath -ErrorAction Stop).Length
    if ($coordinatorStdoutLengthAfter -ne $coordinatorStdoutLengthBefore) {
        throw "$($record.symbol) coordinator stdout changed during its bounded monitor observation; retry."
    }
    if (-not $terminalComplete) {
        $liveCoordinatorStdoutSnapshots += [pscustomobject]@{
            symbol = [string]$record.symbol
            path = $coordinatorStdoutPath
        }
    }
    if ($originalRunning -and $null -eq $lastStdoutHeartbeat) {
        throw "$($record.symbol) has no parseable campaign heartbeat."
    }
    if ($null -ne $lastStdoutHeartbeat) {
        $null = Assert-MonitorCampaignHeartbeatContract -Heartbeat $lastStdoutHeartbeat
    }
    if ($null -ne $lastStdoutHeartbeat -and [bool]$lastStdoutHeartbeat.failure) {
        throw "$($record.symbol) campaign failed: $($lastStdoutHeartbeat.failure_reason) [journal $($lastStdoutHeartbeat.failure_record_sha256)]"
    }
    $hostCampaign = @($telemetryJournal.last.body.payload.campaigns | Where-Object { $_.symbol -eq $record.symbol })
    if ($hostCampaign.Count -ne 1) {
        throw "$($record.symbol) lacks one exact guardian-parsed campaign summary in host telemetry."
    }
    $expectedCampaignElapsedAtTelemetry = [double][uint64]$telemetryJournal.last.body.payload.capture_elapsed_ms / 1000.0
    $campaignHeartbeatLagSeconds = $expectedCampaignElapsedAtTelemetry - [double][uint64]$hostCampaign[0].campaign_elapsed_s
    if ($campaignHeartbeatLagSeconds -lt -5) {
        throw "$($record.symbol) guardian-parsed campaign elapsed time is impossibly ahead of the dual-campaign monotonic clock."
    }
    if ($null -ne $lastStdoutHeartbeat -and
        ($lastStdoutHeartbeat.campaign_id -ne $binding[0].campaign_id -or
         [uint64]$lastStdoutHeartbeat.elapsed_s -lt [uint64]$hostCampaign[0].campaign_elapsed_s)) {
        throw "$($record.symbol) latest parseable CAMPAIGN_HEARTBEAT does not cover the hash-bound guardian summary."
    }
    if ($originalRunning -and
        $null -ne $lastStdoutHeartbeat -and
        $captureRequiresLiveFreshness -and
        ($campaignHeartbeatLagSeconds -gt $HeartbeatMaxAgeSeconds -or
         -not [bool]$hostCampaign[0].ready -or
         [uint64]$hostCampaign[0].generations -lt 1 -or
         [uint64]$hostCampaign[0].active_processes -lt 1)) {
        throw "$($record.symbol) CAMPAIGN_HEARTBEAT is stale or semantically inactive."
    }
    if ($originalRunning -and
        $null -ne $lastStdoutHeartbeat -and
        $captureRequiresLiveFreshness -and
        $heartbeatAgeSeconds -gt $HeartbeatMaxAgeSeconds) {
        throw "$($record.symbol) durable child heartbeat is stale."
    }
    if ($null -ne $journal.previous_heartbeat -and
        [uint64]$journal.previous_heartbeat.body.generation_index -eq [uint64]$journal.latest_heartbeat.body.generation_index) {
        $old = $journal.previous_heartbeat.body.payload
        $new = $journal.latest_heartbeat.body.payload
        if ([uint64]$new.depth_received -lt [uint64]$old.depth_received -or
            [uint64]$new.depth_durable -lt [uint64]$old.depth_durable -or
            [uint64]$new.trade_received -lt [uint64]$old.trade_received -or
            [uint64]$new.trade_durable -lt [uint64]$old.trade_durable) {
            throw "$($record.symbol) latest same-journal heartbeat counters regressed."
        }
    }
    $campaignManifestPath = Join-Path $campaignDirectory "campaign.json"
    $campaignManifestSnapshot = if (Test-Path -LiteralPath $campaignManifestPath -PathType Leaf) {
        Read-MonitorCanonicalJsonSnapshot -Path $campaignManifestPath -WriterKind TwoSpacePretty
    }
    else { $null }
    if ($null -ne $campaignManifestSnapshot) {
        $null = Assert-MonitorRustCampaignSingletonWriterOrder `
            -Value $campaignManifestSnapshot.value -Kind Manifest
        $null = Assert-MonitorRustCampaignSingletonJsonTypes `
            -Value $campaignManifestSnapshot.value -Kind Manifest
        $manifestValue = $campaignManifestSnapshot.value
        if ([string]$manifestValue.campaign_id -cne [string]$campaignStartupSnapshot.value.campaign_id -or
            [string]$manifestValue.symbol -cne [string]$campaignStartupSnapshot.value.symbol -or
            [uint64]$manifestValue.total_duration_s -ne [uint64]$campaignStartupSnapshot.value.total_duration_s -or
            [uint64]$manifestValue.rotation_s -ne [uint64]$campaignStartupSnapshot.value.rotation_s -or
            [uint64]$manifestValue.overlap_s -ne [uint64]$campaignStartupSnapshot.value.overlap_s -or
            [uint64]$manifestValue.segment_s -ne [uint64]$campaignStartupSnapshot.value.segment_s -or
            [uint64]$manifestValue.started_wall_ns -ne [uint64]$campaignStartupSnapshot.value.started_wall_ns -or
            [string]$manifestValue.executable_sha256 -cne [string]$campaignStartupSnapshot.value.executable_sha256 -or
            [string]$manifestValue.capture_executable_sha256 -cne [string]$campaignStartupSnapshot.value.capture_executable_sha256 -or
            [string]$manifestValue.public_config_sha256 -cne [string]$campaignStartupSnapshot.value.public_config_sha256 -or
            [string]$manifestValue.spec_revision -cne [string]$campaignStartupSnapshot.value.spec_revision -or
            [string]$manifestValue.startup_sha256 -cne [string]$campaignStartupSnapshot.sha256 -or
            [uint64]$manifestValue.journal_precommit_records -ne ([uint64]$journal.records - 1) -or
            [uint64]$manifestValue.journal_precommit_records -ne [uint64]$journal.prepared_record_index + 1 -or
            [string]$manifestValue.journal_precommit_sha256 -cne [string]$journal.prepared_record_sha256) {
            throw "$($record.symbol) campaign manifest is not exactly linked to startup and the precommit journal boundary."
        }
    }
    if ((-not $originalRunning -or $terminalComplete) -and
        ([bool]$journal.partial_tail -or
         -not [bool]$journal.campaign_committed -or
         -not [bool]$journal.terminal_record_is_commit -or
         $journal.commit_manifest_file -ne "campaign.json" -or
         [string]$journal.commit_manifest_sha256 -notmatch '^[0-9a-f]{64}$' -or
         $null -eq $campaignManifestSnapshot -or
         $campaignManifestSnapshot.sha256 -ne $journal.commit_manifest_sha256)) {
        throw "$($record.symbol) lacks one exact terminal CAMPAIGN_COMMITTED manifest binding."
    }
    if (-not $originalRunning -and -not $terminalComplete) {
        $captureManifest = $campaignManifestSnapshot.value
        if ($captureManifest.schema -ne "RawCampaignManifestV1" -or
            $captureManifest.status -ne "COMPLETE" -or
            $captureManifest.symbol -ne $record.symbol -or
            [uint64]$captureManifest.supervisor_gap_count -ne 0) {
            throw "$($record.symbol) capture exit proof does not bind a valid COMPLETE/gap-free campaign manifest."
        }
        $requiredExitTopology = Get-RawQualificationRequiredTerminalTopology `
            -Mode ([string]$startup.mode) `
            -TotalSeconds ([uint64]$startup.parameters.total_s) `
            -RotationSeconds ([uint64]$startup.parameters.rotation_s) `
            -OverlapSeconds ([uint64]$startup.parameters.overlap_s) `
            -SegmentSeconds ([uint64]$startup.parameters.segment_s)
        if ([bool]$requiredExitTopology.required -and -not (Test-RawQualificationRequiredTerminalTopology `
            -Topology $requiredExitTopology `
            -Generations ([uint64]@($captureManifest.generations).Count) `
            -Handovers ([uint64]@($captureManifest.handovers).Count) `
            -PlannedGenerationLaunches ([uint64]$journal.planned_generation_launches) `
            -ServerShutdownGenerationLaunches ([uint64]$journal.server_shutdown_generation_launches) `
            -ServerShutdownSupervisorEvents ([uint64]$journal.server_shutdown_supervisor_events) `
            -ServerShutdownDurableEvents ([uint64]$journal.server_shutdown_durable_events))) {
            $scheduleDeviationReasons += "$($record.symbol): terminal generation schedule violated $($requiredExitTopology.profile)"
        }
    }
    if ($terminalComplete) {
        if (-not (Test-Path -LiteralPath $campaignManifestPath -PathType Leaf)) {
            throw "$($record.symbol) COMPLETE launcher lacks campaign.json."
        }
        $campaignManifest = $campaignManifestSnapshot.value
        if ($campaignManifest.status -ne "COMPLETE" -or [uint64]$campaignManifest.supervisor_gap_count -ne 0) {
            throw "$($record.symbol) campaign terminal contract is not COMPLETE/gap-free."
        }
        $terminalCampaign = @($terminal.campaigns | Where-Object { $_.symbol -eq $record.symbol })
        $expectedSchedule = Get-RawQualificationGenerationScheduleClassification `
            -Mode ([string]$startup.mode) `
            -Generations ([uint64]@($campaignManifest.generations).Count) `
            -Handovers ([uint64]@($campaignManifest.handovers).Count) `
            -PlannedGenerationLaunches ([uint64]$journal.planned_generation_launches) `
            -ServerShutdownGenerationLaunches ([uint64]$journal.server_shutdown_generation_launches) `
            -ServerShutdownSupervisorEvents ([uint64]$journal.server_shutdown_supervisor_events) `
            -ServerShutdownDurableEvents ([uint64]$journal.server_shutdown_durable_events)
        if ($terminalCampaign.Count -ne 1 -or
            [uint32]$terminalCampaign[0].pid -ne [uint32]$record.pid -or
            [int]$terminalCampaign[0].exit_code -ne 0 -or
            [uint64]$terminalCampaign[0].exit_elapsed_s -ne [uint64]$campaignExit.elapsed_s -or
            [uint64]$terminalCampaign[0].exit_elapsed_s -lt $captureFreshnessCutoff -or
            [uint64]$terminalCampaign[0].coordinator_exit_elapsed_s -ne [uint64]$campaignExit.coordinator_elapsed_s -or
            [uint64]$terminalCampaign[0].coordinator_exit_elapsed_s -lt $captureFreshnessCutoff -or
            [uint64]$terminalCampaign[0].child_stderr_events -ne 0 -or
            $terminalCampaign[0].stdout_file -ne $record.stdout_file -or
            $terminalCampaign[0].stderr_file -ne $record.stderr_file -or
            [uint64]$terminalCampaign[0].stdout_file_bytes -gt [uint64]$startup.coordinator_log_policy.maximum_stdout_bytes -or
             [uint64]$terminalCampaign[0].stderr_file_bytes -ne 0 -or
             [uint64]$terminalCampaign[0].generations -ne [uint64]@($campaignManifest.generations).Count -or
             [uint64]$terminalCampaign[0].handovers -ne [uint64]@($campaignManifest.handovers).Count -or
             [uint64]$terminalCampaign[0].planned_generation_launches -ne [uint64]$journal.planned_generation_launches -or
             [uint64]$terminalCampaign[0].server_shutdown_generation_launches -ne [uint64]$journal.server_shutdown_generation_launches -or
             [uint64]$terminalCampaign[0].server_shutdown_supervisor_events -ne [uint64]$journal.server_shutdown_supervisor_events -or
             [uint64]$terminalCampaign[0].server_shutdown_durable_events -ne [uint64]$journal.server_shutdown_durable_events -or
             [string]$terminalCampaign[0].generation_schedule_classification -cne $expectedSchedule -or
             [uint64](Get-Item -LiteralPath (Join-Path $resolvedRunRoot ([string]$terminalCampaign[0].stdout_file))).Length -ne [uint64]$terminalCampaign[0].stdout_file_bytes -or
            [uint64](Get-Item -LiteralPath (Join-Path $resolvedRunRoot ([string]$terminalCampaign[0].stderr_file))).Length -ne 0 -or
            $terminalCampaign[0].campaign_manifest_sha256 -ne $campaignManifestSnapshot.sha256 -or
            $terminalCampaign[0].stdout_file_sha256 -ne (Get-RawQualificationSha256File -Path (Join-Path $resolvedRunRoot ([string]$terminalCampaign[0].stdout_file))) -or
            $terminalCampaign[0].stderr_file_sha256 -ne (Get-RawQualificationSha256File -Path (Join-Path $resolvedRunRoot ([string]$terminalCampaign[0].stderr_file)))) {
            throw "$($record.symbol) terminal manifest does not bind its campaign/stdout/stderr artifacts."
        }
        $requiredTerminalTopology = Get-RawQualificationRequiredTerminalTopology `
            -Mode ([string]$startup.mode) `
            -TotalSeconds ([uint64]$startup.parameters.total_s) `
            -RotationSeconds ([uint64]$startup.parameters.rotation_s) `
            -OverlapSeconds ([uint64]$startup.parameters.overlap_s) `
            -SegmentSeconds ([uint64]$startup.parameters.segment_s)
        if (-not (Test-RawQualificationRequiredTerminalTopology `
            -Topology $requiredTerminalTopology `
            -Generations ([uint64]@($campaignManifest.generations).Count) `
            -Handovers ([uint64]@($campaignManifest.handovers).Count) `
            -PlannedGenerationLaunches ([uint64]$journal.planned_generation_launches) `
            -ServerShutdownGenerationLaunches ([uint64]$journal.server_shutdown_generation_launches) `
            -ServerShutdownSupervisorEvents ([uint64]$journal.server_shutdown_supervisor_events) `
            -ServerShutdownDurableEvents ([uint64]$journal.server_shutdown_durable_events))) {
            throw "$($record.symbol) COMPLETE topology violates exact $($requiredTerminalTopology.profile) cardinality/shutdown requirements."
        }
        $verifiers = @($terminalCampaign[0].independent_verifiers | Sort-Object {
            [uint64]$launcherHistoryContract.verifier_started[[string]$_.name].body.record_index
        })
        $expectedVerifierNames = [string[]]@(
            (([string]$record.symbol).ToLowerInvariant() + "-rust")
            (([string]$record.symbol).ToLowerInvariant() + "-python")
        )
        if ($verifiers.Count -ne 2 -or
            @($verifiers | Select-Object -ExpandProperty name -Unique).Count -ne 2 -or
            @($verifiers | Where-Object { $expectedVerifierNames -cnotcontains $_.name }).Count -ne 0) {
            throw "$($record.symbol) lacks the exact Rust/Python independent verifier set."
        }
        $campaignVerifiedEvent = $launcherHistoryContract.campaign_verified[[string]$record.symbol]
        if (-not (Test-MonitorCampaignVerifiedReportBinding `
            -VerifiedEvent $campaignVerifiedEvent `
            -Verifiers $verifiers)) {
            throw "$($record.symbol) INDEPENDENT_CAMPAIGN_VERIFIED does not bind the exact sealed Rust/Python reports."
        }
        $verificationRoot = Join-Path $resolvedRunRoot "independent-verification"
        $rustVerifiedReport = $null
        $pythonVerifiedReport = $null
        foreach ($verifier in $verifiers) {
            $expectedExecutionFile = ([string]$verifier.name) + ".execution.json"
            $expectedReportFile = ([string]$verifier.name) + "-report.json"
            $expectedStdoutFile = ([string]$verifier.name) + ".stdout.log"
            $expectedStderrFile = ([string]$verifier.name) + ".stderr.log"
            if ([string]$verifier.execution_file -ne $expectedExecutionFile -or
                [string]$verifier.report_file -ne $expectedReportFile -or
                [string]$verifier.stdout_file -ne $expectedStdoutFile -or
                [string]$verifier.stderr_file -ne $expectedStderrFile) {
                throw "$($record.symbol) verifier evidence contains an unexpected or non-portable artifact name."
            }
            $executionPath = Join-Path $verificationRoot ([string]$verifier.execution_file)
            $reportPath = Join-Path $verificationRoot ([string]$verifier.report_file)
            $verifierStdoutPath = Join-Path $verificationRoot ([string]$verifier.stdout_file)
            $verifierStderrPath = Join-Path $verificationRoot ([string]$verifier.stderr_file)
            $executionSnapshot = Read-MonitorCanonicalJsonSnapshot `
                -Path $executionPath -WriterKind PowerShellPretty -MaximumBytes $MaximumCurrentVerifierArtifactBytes
            $reportSnapshot = Read-MonitorCanonicalJsonSnapshot `
                -Path $reportPath -WriterKind TwoSpacePretty -MaximumBytes $MaximumCurrentVerifierArtifactBytes
            $null = Assert-MonitorExecutionWriterOrder -Execution $executionSnapshot.value
            if ($executionSnapshot.sha256 -ne $verifier.execution_sha256 -or
                $reportSnapshot.sha256 -ne $verifier.report_sha256 -or
                (Get-RawQualificationSha256File -Path $verifierStdoutPath) -ne $verifier.stdout_sha256 -or
                (Get-RawQualificationSha256File -Path $verifierStderrPath) -ne $verifier.stderr_sha256 -or
                $reportSnapshot.length -ne [uint64]$verifier.report_bytes -or
                [uint64](Get-Item -LiteralPath $verifierStdoutPath).Length -ne [uint64]$verifier.stdout_bytes -or
                [uint64](Get-Item -LiteralPath $verifierStderrPath).Length -ne [uint64]$verifier.stderr_bytes -or
                [int]$verifier.exit_code -ne 0) {
                throw "$($record.symbol) independent verifier artifact hashes/exit status differ."
            }
            $execution = $executionSnapshot.value
            $report = $reportSnapshot.value
            $null = Assert-MonitorSealedVerifierJsonTypes -Verifier $verifier -Execution $execution
            $expectedVerifierExecutable = if ($verifier.name -like "*-rust") {
                [string]$startup.preflight.campaign_verifier_executable
            } else { [string]$startup.preflight.python }
            $expectedVerifierExecutableSha256 = if ($verifier.name -like "*-rust") {
                [string]$startup.preflight.campaign_verifier_executable_sha256
            } else { [string]$startup.preflight.python_sha256 }
            $isolatedPythonBootstrap = "import runpy,sys;sys.dont_write_bytecode=True;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('binance_lob.raw_verify_cli',run_name='__main__')"
            $expectedVerifierArguments = if ($verifier.name -like "*-rust") {
                [string[]]@($campaignDirectory, $reportPath)
            }
            else {
                [string[]]@(
                    "-I", "-P", "-S", "-B", "-c", $isolatedPythonBootstrap,
                    [string]$startup.preflight.python_verifier_source.root,
                    $campaignDirectory,
                    "--output", $reportPath)
            }
            $expectedCommandLine = [RawQualificationNative]::BuildExactCommandLine(
                $expectedVerifierExecutable,
                $expectedVerifierArguments)
            $expectedCommandLineSha256 = Get-RawQualificationSha256Bytes -Bytes (
                [Text.UTF8Encoding]::new($false).GetBytes($expectedCommandLine))
            $verifierStart = $launcherHistoryContract.verifier_started[[string]$verifier.name]
            $verifierCompleted = $launcherHistoryContract.verifier_completed[[string]$verifier.name]
            $creationTime = [DateTimeOffset]::MinValue
            $creationTimeValid = [DateTimeOffset]::TryParse(
                [string]$execution.creation_time_utc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$creationTime)
            $verifierCreationIdentity = [string]$execution.creation_time_utc
            if (-not (Add-MonitorSequentialProcessIdentity `
                -Seen $sealedVerifierPidCreationIdentities `
                -ProcessId ([uint32]$execution.pid) `
                -CreationTimeUtc $verifierCreationIdentity)) {
                throw "$($record.symbol) reuses one verifier PID with the same creation identity across sequential verifier executions."
            }
            $executionTimeoutSeconds = [uint64]$execution.timeout_s
            $budgetComputedTick = [uint64]$execution.global_budget_computed_monotonic_tick
            $budgetTickValid = $budgetComputedTick -ge [uint64]$launcherJournal.independent_verification_record.body.monotonic_tick -and
                $budgetComputedTick -le [uint64]$verifierStart.body.monotonic_tick
            $expectedExecutionTimeoutSeconds = Get-MonitorExpectedVerifierTimeoutSeconds `
                -BudgetComputedTick $budgetComputedTick `
                -VerificationStageTick ([uint64]$launcherJournal.independent_verification_record.body.monotonic_tick) `
                -MonotonicFrequency ([uint64]$startup.monotonic_frequency) `
                -TotalPostCaptureTimeoutSeconds ([uint64]$startup.verifier_policy.total_post_capture_timeout_s) `
                -MaximumPerProcessTimeoutSeconds ([uint64]$startup.verifier_policy.per_process_timeout_s)
            if (-not (Test-MonitorVerifierExecutionCausality `
                -StartupOriginQpcTimestamp $startup.monotonic_origin_qpc_timestamp `
                -BudgetComputedMonotonicTick $execution.global_budget_computed_monotonic_tick `
                -StartEventMonotonicTick $verifierStart.body.monotonic_tick `
                -CompletedEventMonotonicTick $verifierCompleted.body.monotonic_tick `
                -ResumeQpcTimestamp $execution.resume_qpc_timestamp `
                -ElapsedQpcTicks $execution.elapsed_qpc_ticks `
                -ParentExitObservedQpcTimestamp $execution.parent_exit_observed_qpc_timestamp `
                -DescendantDrainElapsedQpcTicks $execution.descendant_drain_elapsed_qpc_ticks `
                -PreviousCompletedAbsoluteQpcTimestamp $previousVerifierCompletionAbsoluteQpcTimestamp)) {
                throw "$($record.symbol) independent verifier QPC evidence violates its event/budget/previous-completion causal interval."
            }
            if ($execution.schema -ne "RawQualificationVerifierExecutionV1" -or
                $execution.name -ne $verifier.name -or
                $null -eq $verifierStart -or
                $null -eq $verifierCompleted -or
                [uint32]$execution.pid -eq 0 -or
                [uint32]$execution.pid -ne [uint32]$verifier.pid -or
                [uint32]$execution.pid -ne [uint32]$verifierStart.body.payload.pid -or
                [uint32]$execution.pid -ne [uint32]$verifierCompleted.body.payload.pid -or
                -not $creationTimeValid -or
                [string]$execution.creation_time_utc -ne [string]$verifier.creation_time_utc -or
                [IO.Path]::GetFullPath([string]$execution.executable_path) -ne [IO.Path]::GetFullPath($expectedVerifierExecutable) -or
                $execution.executable_sha256 -ne $expectedVerifierExecutableSha256 -or
                [string]$execution.command_line -ne $expectedCommandLine -or
                [string]$verifier.command_line_sha256 -ne $expectedCommandLineSha256 -or
                -not $budgetTickValid -or
                [uint64]$verifier.global_budget_computed_monotonic_tick -ne $budgetComputedTick -or
                $null -eq $execution.PSObject.Properties['resume_qpc_timestamp'] -or
                $null -eq $execution.PSObject.Properties['elapsed_qpc_ticks'] -or
                $null -eq $execution.PSObject.Properties['monotonic_frequency'] -or
                $null -eq $execution.PSObject.Properties['parent_exit_observed_qpc_timestamp'] -or
                $null -eq $execution.PSObject.Properties['descendant_drain_elapsed_qpc_ticks'] -or
                $null -eq $execution.PSObject.Properties['descendant_drain_elapsed_ms'] -or
                $null -eq $verifier.PSObject.Properties['resume_qpc_timestamp'] -or
                $null -eq $verifier.PSObject.Properties['elapsed_qpc_ticks'] -or
                $null -eq $verifier.PSObject.Properties['monotonic_frequency'] -or
                $null -eq $verifier.PSObject.Properties['parent_exit_observed_qpc_timestamp'] -or
                $null -eq $verifier.PSObject.Properties['descendant_drain_elapsed_qpc_ticks'] -or
                $null -eq $verifier.PSObject.Properties['descendant_drain_elapsed_ms'] -or
                [long]$verifier.resume_qpc_timestamp -ne [long]$execution.resume_qpc_timestamp -or
                [long]$verifier.elapsed_qpc_ticks -ne [long]$execution.elapsed_qpc_ticks -or
                [long]$verifier.monotonic_frequency -ne [long]$execution.monotonic_frequency -or
                [long]$verifier.parent_exit_observed_qpc_timestamp -ne [long]$execution.parent_exit_observed_qpc_timestamp -or
                [long]$verifier.descendant_drain_elapsed_qpc_ticks -ne [long]$execution.descendant_drain_elapsed_qpc_ticks -or
                [uint64]$verifier.descendant_drain_elapsed_ms -ne [uint64]$execution.descendant_drain_elapsed_ms -or
                $executionTimeoutSeconds -ne $expectedExecutionTimeoutSeconds -or
                -not (Test-MonitorQpcExecutionEvidence `
                    -ResumeQpcTimestamp ([long]$execution.resume_qpc_timestamp) `
                    -ElapsedQpcTicks ([long]$execution.elapsed_qpc_ticks) `
                    -MonotonicFrequency ([long]$execution.monotonic_frequency) `
                    -ExpectedFrequency ([long]$startup.monotonic_frequency) `
                    -TimeoutSeconds $executionTimeoutSeconds `
                    -ElapsedMilliseconds ([uint64]$execution.elapsed_ms)) -or
                -not (Test-MonitorQpcExecutionEvidence `
                    -ResumeQpcTimestamp ([long]$execution.parent_exit_observed_qpc_timestamp) `
                    -ElapsedQpcTicks ([long]$execution.descendant_drain_elapsed_qpc_ticks) `
                    -MonotonicFrequency ([long]$execution.monotonic_frequency) `
                    -ExpectedFrequency ([long]$startup.monotonic_frequency) `
                    -TimeoutSeconds 10 `
                    -ElapsedMilliseconds ([uint64]$execution.descendant_drain_elapsed_ms)) -or
                -not (Test-MonitorVerifierExecutionBudget `
                    -ActualTimeoutSeconds $executionTimeoutSeconds `
                    -MaximumPerProcessTimeoutSeconds ([uint64]$startup.verifier_policy.per_process_timeout_s) `
                    -ElapsedMilliseconds ([uint64]$execution.elapsed_ms)) -or
                [uint64]$execution.elapsed_ms -ne [uint64]$verifier.elapsed_ms -or
                [bool]$execution.timed_out -or
                [int]$execution.exit_code -ne 0 -or
                $null -ne $execution.failure -or
                [string]$execution.stdout_file -ne [string]$verifier.stdout_file -or
                [uint64]$execution.stdout_bytes -ne [uint64]$verifier.stdout_bytes -or
                [string]$execution.stdout_sha256 -ne [string]$verifier.stdout_sha256 -or
                [string]$execution.stderr_file -ne [string]$verifier.stderr_file -or
                [uint64]$execution.stderr_bytes -ne 0 -or
                [uint64]$execution.stderr_bytes -ne [uint64]$verifier.stderr_bytes -or
                [string]$execution.stderr_sha256 -ne [string]$verifier.stderr_sha256 -or
                (Get-Item -LiteralPath $verifierStderrPath).Length -ne 0 -or
                [string]$execution.report_file -ne [string]$verifier.report_file -or
                -not [bool]$execution.report_present -or
                [uint64]$execution.report_bytes -ne [uint64]$verifier.report_bytes -or
                -not (Test-MonitorVerifierArtifactBounds `
                    -StdoutBytes ([uint64]$execution.stdout_bytes) `
                    -StderrBytes ([uint64]$execution.stderr_bytes) `
                    -ReportBytes ([uint64]$execution.report_bytes) `
                    -MaximumArtifactBytes ([uint64]$startup.verifier_policy.maximum_artifact_bytes)) -or
                [string]$execution.report_sha256 -ne [string]$verifier.report_sha256 -or
                [string]$verifierCompleted.body.payload.execution_sha256 -ne [string]$verifier.execution_sha256 -or
                [int]$verifierCompleted.body.payload.exit_code -ne 0 -or
                [uint64]$verifierCompleted.body.payload.stderr_bytes -ne 0 -or
                [uint64]$verifierCompleted.body.record_index -le [uint64]$verifierStart.body.record_index -or
                (($verifier.name -like "*-rust") -and ($report.schema -ne "VerifiedRawCampaignV1" -or $report.status -ne "PASS")) -or
                (($verifier.name -like "*-python") -and ($report.schema -ne "RawCampaignVerificationV1" -or $report.status -ne "VERIFIED"))) {
                throw "$($record.symbol) independent verifier execution/report contract is invalid."
            }
            if ($verifier.name -like "*-rust") {
                if ($report.campaign_id -ne $binding[0].campaign_id -or
                    $report.symbol -ne $record.symbol -or
                    $report.campaign_manifest_sha256 -ne $campaignManifestSnapshot.sha256 -or
                    [uint64]$report.total_duration_s -ne [uint64]$startup.parameters.total_s -or
                    [uint64]$report.rotation_s -ne [uint64]$startup.parameters.rotation_s -or
                    [uint64]$report.overlap_s -ne [uint64]$startup.parameters.overlap_s -or
                    [uint64]$report.segment_s -ne [uint64]$startup.parameters.segment_s -or
                    [uint64]$report.journal_records -ne [uint64]$terminalCampaign[0].campaign_journal_committed_records -or
                    $report.journal_terminal_sha256 -ne $terminalCampaign[0].campaign_journal_terminal_sha256 -or
                    $report.verification_sha256 -ne $terminalCampaign[0].rust_verification_sha256) {
                    throw "$($record.symbol) Rust verifier report is not bound to this exact terminal campaign."
                }
                $rustVerifiedReport = $report
            }
            else {
                if ($report.campaign_id -ne $binding[0].campaign_id -or
                    $report.symbol -ne $record.symbol -or
                    $report.campaign_manifest_file_sha256 -ne $campaignManifestSnapshot.sha256 -or
                    [uint64]$report.total_duration_s -ne [uint64]$startup.parameters.total_s -or
                    [uint64]$report.rotation_s -ne [uint64]$startup.parameters.rotation_s -or
                    [uint64]$report.overlap_s -ne [uint64]$startup.parameters.overlap_s -or
                    [uint64]$report.segment_s -ne [uint64]$startup.parameters.segment_s -or
                    [uint64]$report.journal.records -ne [uint64]$terminalCampaign[0].campaign_journal_committed_records -or
                    $report.journal.terminal_record_sha256 -ne $terminalCampaign[0].campaign_journal_terminal_sha256 -or
                    $report.verification_sha256 -ne $terminalCampaign[0].python_verification_sha256) {
                    throw "$($record.symbol) Python verifier report is not bound to this exact terminal campaign."
                }
                $pythonVerifiedReport = $report
            }
            $previousVerifierCompletionAbsoluteQpcTimestamp = [long](
                [decimal][long]$startup.monotonic_origin_qpc_timestamp +
                [decimal][uint64]$verifierCompleted.body.monotonic_tick)
        }
        if ($null -eq $rustVerifiedReport -or $null -eq $pythonVerifiedReport) {
            throw "$($record.symbol) did not retain both independent verifier reports."
        }
        $rustGenerationHashes = @($rustVerifiedReport.generations | Sort-Object generation_index | ForEach-Object { [string]$_.verification_sha256 })
        $pythonGenerationHashes = @($pythonVerifiedReport.generations | Sort-Object generation_index | ForEach-Object { [string]$_.verification_sha256 })
        if (($rustGenerationHashes -join "`n") -ne ($pythonGenerationHashes -join "`n")) {
            throw "$($record.symbol) independent verifier generation identities disagree."
        }

        if ((Get-RawQualificationSha256File -Path ([string]$startup.preflight.campaign_verifier_executable)) -ne
            [string]$startup.preflight.campaign_verifier_executable_sha256) {
            throw "$($record.symbol) Rust verifier changed immediately before current re-verification."
        }
        $currentTimeout = [int][uint64]$startup.verifier_policy.per_process_timeout_s
        $currentRust = Invoke-CurrentCampaignVerifier `
            -Name (([string]$record.symbol).ToLowerInvariant() + "-current-rust") `
            -Executable ([string]$startup.preflight.campaign_verifier_executable) `
            -ArgumentsBeforeReport ([string[]]@($campaignDirectory)) `
            -WorkingDirectory ([string]$startup.preflight.repo) `
            -EnvironmentEntries $childEnvironmentEntries `
            -TimeoutSeconds $currentTimeout
        $currentSource = Get-RawQualificationSourceTreeDigest -Root ([string]$startup.preflight.python_verifier_source.root)
        $currentRuntime = Get-RawQualificationPythonRuntimeDigest -PythonExecutable ([string]$startup.preflight.python)
        if ($currentSource.tree_sha256 -ne $startup.preflight.python_verifier_source.tree_sha256 -or
            $currentRuntime.tree_sha256 -ne $startup.preflight.python_runtime.tree_sha256 -or
            [uint64]$currentRuntime.file_count -ne [uint64]$startup.preflight.python_runtime.file_count -or
            [uint64]$currentRuntime.total_bytes -ne [uint64]$startup.preflight.python_runtime.total_bytes -or
            $currentRuntime.pyvenv_config_sha256 -ne $startup.preflight.python_runtime.pyvenv_config_sha256 -or
            $currentRuntime.base_executable_sha256 -ne $startup.preflight.python_runtime.base_executable_sha256 -or
            (Get-RawQualificationSha256File -Path ([string]$startup.preflight.python)) -ne [string]$startup.preflight.python_sha256) {
            throw "$($record.symbol) Python oracle provenance changed immediately before current re-verification."
        }
        $isolatedPythonBootstrap = "import runpy,sys;sys.dont_write_bytecode=True;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('binance_lob.raw_verify_cli',run_name='__main__')"
        $currentPython = Invoke-CurrentCampaignVerifier `
            -Name (([string]$record.symbol).ToLowerInvariant() + "-current-python") `
            -Executable ([string]$startup.preflight.python) `
            -ArgumentsBeforeReport ([string[]]@(
                "-I", "-P", "-S", "-B", "-c", $isolatedPythonBootstrap,
                [string]$startup.preflight.python_verifier_source.root,
                $campaignDirectory,
                "--output"
            )) `
            -WorkingDirectory ([string]$startup.preflight.repo) `
            -EnvironmentEntries $childEnvironmentEntries `
            -TimeoutSeconds $currentTimeout
        $sealedRustVerifier = @($verifiers | Where-Object { [string]$_.name -like "*-rust" })
        $sealedPythonVerifier = @($verifiers | Where-Object { [string]$_.name -like "*-python" })
        if ($sealedRustVerifier.Count -ne 1 -or $sealedPythonVerifier.Count -ne 1 -or
            [string]$currentRust.report_sha256 -cne [string]$sealedRustVerifier[0].report_sha256 -or
            [string]$currentPython.report_sha256 -cne [string]$sealedPythonVerifier[0].report_sha256) {
            throw "$($record.symbol) sealed verifier report bytes differ from fresh exact writer output."
        }
        $currentRustReport = $currentRust.report
        $currentPythonReport = $currentPython.report
        if ($currentRustReport.schema -ne "VerifiedRawCampaignV1" -or
            $currentRustReport.status -ne "PASS" -or
            $currentRustReport.campaign_id -ne $binding[0].campaign_id -or
            $currentRustReport.symbol -ne $record.symbol -or
            $currentRustReport.campaign_manifest_sha256 -ne $campaignManifestSnapshot.sha256 -or
            [uint64]$currentRustReport.journal_records -ne [uint64]$terminalCampaign[0].campaign_journal_committed_records -or
            $currentRustReport.journal_terminal_sha256 -ne $terminalCampaign[0].campaign_journal_terminal_sha256 -or
            $currentRustReport.verification_sha256 -ne $terminalCampaign[0].rust_verification_sha256 -or
            $currentPythonReport.schema -ne "RawCampaignVerificationV1" -or
            $currentPythonReport.status -ne "VERIFIED" -or
            $currentPythonReport.campaign_id -ne $binding[0].campaign_id -or
            $currentPythonReport.symbol -ne $record.symbol -or
            $currentPythonReport.campaign_manifest_file_sha256 -ne $campaignManifestSnapshot.sha256 -or
            [uint64]$currentPythonReport.journal.records -ne [uint64]$terminalCampaign[0].campaign_journal_committed_records -or
            $currentPythonReport.journal.terminal_record_sha256 -ne $terminalCampaign[0].campaign_journal_terminal_sha256 -or
            $currentPythonReport.verification_sha256 -ne $terminalCampaign[0].python_verification_sha256) {
            throw "$($record.symbol) current dual-oracle re-verification differs from sealed terminal identity."
        }
        $currentRustGenerationHashes = @($currentRustReport.generations | Sort-Object generation_index | ForEach-Object { [string]$_.verification_sha256 })
        $currentPythonGenerationHashes = @($currentPythonReport.generations | Sort-Object generation_index | ForEach-Object { [string]$_.verification_sha256 })
        if (($currentRustGenerationHashes -join "`n") -ne ($currentPythonGenerationHashes -join "`n")) {
            throw "$($record.symbol) current Rust/Python generation identities disagree."
        }
        $currentReverificationEvidence += [pscustomobject][ordered]@{
            symbol = [string]$record.symbol
            rust_elapsed_ms = [uint64]$currentRust.elapsed_ms
            rust_report_sha256 = [string]$currentRust.report_sha256
            python_elapsed_ms = [uint64]$currentPython.elapsed_ms
            python_report_sha256 = [string]$currentPython.report_sha256
            campaign_verification_sha256 = [string]$currentRustReport.verification_sha256
            current_bytes_verified = $true
        }
    }
    $campaignHealth += [pscustomobject][ordered]@{
        symbol = $record.symbol
        campaign_id = $binding[0].campaign_id
        journal_records = [uint64]$journal.records
        journal_bytes = [uint64]$journal.file_length
        durable_heartbeat_age_s = [math]::Round($heartbeatAgeSeconds, 3)
        depth_received = [uint64]$journal.latest_heartbeat.body.payload.depth_received
        depth_durable = [uint64]$journal.latest_heartbeat.body.payload.depth_durable
        trade_received = [uint64]$journal.latest_heartbeat.body.payload.trade_received
        trade_durable = [uint64]$journal.latest_heartbeat.body.payload.trade_durable
        generation_market_health = @($journal.generation_health)
        planned_generation_launches = [uint64]$journal.planned_generation_launches
        server_shutdown_generation_launches = [uint64]$journal.server_shutdown_generation_launches
        server_shutdown_events = [uint64]$journal.server_shutdown_events
        campaign_elapsed_s = if ($null -ne $lastStdoutHeartbeat) { [uint64]$lastStdoutHeartbeat.elapsed_s } else { $null }
        campaign_heartbeat_age_s = [math]::Round($campaignHeartbeatLagSeconds, 3)
        generations = if ($null -ne $lastStdoutHeartbeat) { [uint64]$lastStdoutHeartbeat.generations } else { $null }
        handovers_proven = if ($null -ne $lastStdoutHeartbeat) { [uint64]$lastStdoutHeartbeat.handovers_proven } else { $null }
    }
}

$dualGenerationTerminalComplete = $generationTerminalEvidence.Count -eq 2 -and
    @($generationTerminalEvidence | Where-Object { -not $_.complete }).Count -eq 0
if ($dualGenerationTerminalComplete) {
    $latestDualTerminalWallNs = [uint64](($generationTerminalEvidence | Measure-Object -Property latest_wall_ns -Maximum).Maximum)
    $terminalEvidenceAgeSeconds = [double]((Get-RawQualificationWallNs) - $latestDualTerminalWallNs) / 1e9
    if ($terminalEvidenceAgeSeconds -lt -5) {
        throw "Dual generation terminal evidence has a future wall timestamp."
    }
    if ($null -eq $launcherJournal.terminal_evaluation_record -and $terminalEvidenceAgeSeconds -gt 5) {
        throw "Launcher did not durably enter terminal evaluation after both campaigns terminated their generations."
    }
    if ($null -ne $launcherJournal.terminal_evaluation_record) {
        $terminalEvaluationTick = [uint64]$launcherJournal.terminal_evaluation_record.body.monotonic_tick
        $latestGuardianTick = [uint64]$guardianPulseJournal.last.body.monotonic_tick
        if ($latestGuardianTick -lt $terminalEvaluationTick) {
            throw "Guardian pulse monotonic tick precedes terminal-evaluation stage."
        }
        $terminalEvaluationAgeSeconds = [double]($latestGuardianTick - $terminalEvaluationTick) / [uint64]$startup.monotonic_frequency
        if (@($processHealth | Where-Object { $_.running -and $_.exact_identity }).Count -gt 0 -and
            $terminalEvaluationAgeSeconds -gt $ExpectedCampaignCommitDeadlineSeconds) {
            throw "Campaign terminal evaluation exceeded its separate commit deadline."
        }
    }
}
if ($terminalComplete) {
    if ($currentReverificationEvidence.Count -ne 2 -or
        (@($currentReverificationEvidence | ForEach-Object { [string]$_.symbol } | Sort-Object) -join ',') -ne "BTCUSDT,ETHUSDT") {
        throw "Terminal COMPLETE lacks current dual-oracle re-verification of both campaigns."
    }
    $finalCurrentSource = Get-RawQualificationSourceTreeDigest -Root ([string]$startup.preflight.python_verifier_source.root)
    $finalCurrentRuntime = Get-RawQualificationPythonRuntimeDigest -PythonExecutable ([string]$startup.preflight.python)
    if ($finalCurrentSource.tree_sha256 -ne $startup.preflight.python_verifier_source.tree_sha256 -or
        $finalCurrentRuntime.tree_sha256 -ne $startup.preflight.python_runtime.tree_sha256 -or
        [uint64]$finalCurrentRuntime.file_count -ne [uint64]$startup.preflight.python_runtime.file_count -or
        [uint64]$finalCurrentRuntime.total_bytes -ne [uint64]$startup.preflight.python_runtime.total_bytes -or
        $finalCurrentRuntime.pyvenv_config_sha256 -ne $startup.preflight.python_runtime.pyvenv_config_sha256 -or
        $finalCurrentRuntime.base_executable_sha256 -ne $startup.preflight.python_runtime.base_executable_sha256 -or
        (Get-RawQualificationSha256File -Path ([string]$startup.preflight.python)) -ne [string]$startup.preflight.python_sha256 -or
        (Get-RawQualificationSha256File -Path ([string]$startup.preflight.campaign_verifier_executable)) -ne
            [string]$startup.preflight.campaign_verifier_executable_sha256) {
        throw "Verifier/runtime provenance changed during current terminal re-verification."
    }
}

if ($terminalComplete) {
    $null = Assert-MonitorEvidenceTreeNoReparsePoints -RunRoot $resolvedRunRoot
}
else {
    # Final linearization barrier. Append-only streams are intentionally allowed
    # to advance: each second pass freezes and validates a newer exact prefix.
    # Only the low-rate launcher FSM must remain unchanged so the reported stage
    # cannot cross a terminal transition during this invocation.
    if (Test-Path -LiteralPath $terminalPath -PathType Leaf) {
        throw "Launcher became terminal during the live monitor scan; retry against terminal evidence."
    }
    if (Test-Path -LiteralPath $watchdogFailurePath -PathType Leaf) {
        throw "Independent guardian watchdog failed during the live monitor scan."
    }
    $linearizedLauncherJournal = Get-VerifiedJournalSummary `
        -Path $launcherJournalPath `
        -ExpectedSchema "RawQualificationLauncherEventV1"
    if ([uint64]$linearizedLauncherJournal.records -ne [uint64]$launcherJournal.records -or
        [uint64]$linearizedLauncherJournal.file_length -ne [uint64]$launcherJournal.file_length -or
        [string]$linearizedLauncherJournal.terminal_record_sha256 -ne [string]$launcherJournal.terminal_record_sha256) {
        throw "Launcher FSM advanced during the monitor scan; retry against the new stage."
    }
    $linearizedLauncherHistoryContract = Assert-LauncherEventHistory `
        -Journal $linearizedLauncherJournal `
        -Startup $startup `
        -Control $control `
        -TerminalComplete $false
    $linearizedCaptureRequiresLiveFreshness = Test-MonitorCaptureRequiresLiveFreshness `
        -LauncherHistoryContract $linearizedLauncherHistoryContract
    if ($linearizedCaptureRequiresLiveFreshness -ne $captureRequiresLiveFreshness) {
        throw "Launcher capture phase changed without an advancing authenticated FSM prefix."
    }
    $telemetryJournal = Get-VerifiedJournalSummary `
        -Path $telemetryJournalPath `
        -ExpectedSchema "RawQualificationHostTelemetryRecordV1"
    $guardianPulseJournal = Get-VerifiedJournalSummary `
        -Path $guardianPulseJournalPath `
        -ExpectedSchema "RawQualificationGuardianPulseV1"
    $null = Assert-HostTelemetryHistory `
        -Journal $telemetryJournal `
        -Startup $startup `
        -Control $control `
        -ExpectedProviderTimeoutSeconds $ExpectedHostProbeTimeoutSeconds `
        -MaximumProviderArtifactBytes $ExpectedHostProbeMaximumArtifactBytes
    $null = Assert-GuardianPulseHistory -Journal $guardianPulseJournal -Startup $startup -Control $control
    $linearizedCampaignFreshness = @()
    foreach ($snapshot in $liveCampaignJournalSnapshots) {
        $current = Get-CampaignJournalHealth `
            -Path ([string]$snapshot.path) `
            -CampaignStartup $snapshot.campaign_startup `
            -CampaignStartupSha256 ([string]$snapshot.campaign_startup_sha256) `
            -ExpectedPrefixRecords ([uint64]$snapshot.records) `
            -ExpectedPrefixTerminalRecordSha256 ([string]$snapshot.terminal_record_sha256) `
            -ExpectedPrefixFileLength ([uint64]$snapshot.file_length) `
            -ExpectedPrefixFileSha256 ([string]$snapshot.file_sha256) `
            -ContinuationState $snapshot.continuation_state
        if ($current.campaign_failed -or -not $current.process_started -or
            -not $current.depth_connected -or -not $current.trade_connected -or
            -not $current.snapshot_durable -or $null -eq $current.latest_heartbeat -or
            [uint64]$current.child_stderr_events -ne 0) {
            throw "$($snapshot.symbol) final linearized campaign prefix is not semantically healthy."
        }
        $linearizedCampaignFreshness += [pscustomobject]@{
            symbol = [string]$snapshot.symbol
            latest_heartbeat_wall_ns = [uint64]$current.latest_heartbeat.body.wall_ns
            generations = @($current.generation_health)
        }
        $campaignRow = @($campaignHealth | Where-Object { [string]$_.symbol -eq [string]$snapshot.symbol })
        if ($campaignRow.Count -ne 1) { throw "$($snapshot.symbol) final campaign row is ambiguous." }
        $campaignRow[0].journal_records = [uint64]$current.records
        $campaignRow[0].journal_bytes = [uint64]$current.file_length
        $campaignRow[0].depth_received = [uint64]$current.latest_heartbeat.body.payload.depth_received
        $campaignRow[0].depth_durable = [uint64]$current.latest_heartbeat.body.payload.depth_durable
        $campaignRow[0].trade_received = [uint64]$current.latest_heartbeat.body.payload.trade_received
        $campaignRow[0].trade_durable = [uint64]$current.latest_heartbeat.body.payload.trade_durable
        $campaignRow[0].generation_market_health = @($current.generation_health)
        $campaignRow[0].planned_generation_launches = [uint64]$current.planned_generation_launches
        $campaignRow[0].server_shutdown_generation_launches = [uint64]$current.server_shutdown_generation_launches
        $campaignRow[0].server_shutdown_events = [uint64]$current.server_shutdown_events
        if ($startup.mode -in @("Production", "SevenDay") -and
            ([uint64]$current.server_shutdown_generation_launches -ne 0 -or
             [uint64]$current.server_shutdown_events -ne 0) -and
            $scheduleDeviationReasons -notcontains "$($snapshot.symbol): official serverShutdown path observed") {
            $scheduleDeviationReasons += "$($snapshot.symbol): official serverShutdown path observed"
        }
    }
    foreach ($snapshot in $liveCoordinatorStdoutSnapshots) {
        $stableHeartbeat = $null
        for ($attempt = 0; $attempt -lt 3; $attempt++) {
            $before = [uint64](Get-Item -LiteralPath $snapshot.path -ErrorAction Stop).Length
            $candidate = Get-LastCampaignHeartbeat -Path ([string]$snapshot.path)
            $after = [uint64](Get-Item -LiteralPath $snapshot.path -ErrorAction Stop).Length
            if ($before -eq $after) { $stableHeartbeat = $candidate; break }
        }
        if ($null -eq $stableHeartbeat -or [bool]$stableHeartbeat.failure) {
            throw "$($snapshot.symbol) lacks a stable healthy final coordinator heartbeat prefix."
        }
        $finalHostCampaign = @($telemetryJournal.last.body.payload.campaigns | Where-Object {
            [string]$_.symbol -eq [string]$snapshot.symbol })
        $finalBinding = @($bindings.campaigns | Where-Object { [string]$_.symbol -eq [string]$snapshot.symbol })
        if ($finalHostCampaign.Count -ne 1 -or $finalBinding.Count -ne 1 -or
            [string]$stableHeartbeat.campaign_id -ne [string]$finalBinding[0].campaign_id -or
            [uint64]$stableHeartbeat.elapsed_s -lt [uint64]$finalHostCampaign[0].campaign_elapsed_s) {
            throw "$($snapshot.symbol) final coordinator heartbeat does not cover the linearized host-telemetry campaign summary."
        }
        $finalCampaignLagSeconds =
            ([double][uint64]$telemetryJournal.last.body.payload.capture_elapsed_ms / 1000.0) -
            [double][uint64]$finalHostCampaign[0].campaign_elapsed_s
        if ($finalCampaignLagSeconds -lt -5 -or
            ($linearizedCaptureRequiresLiveFreshness -and
             ($finalCampaignLagSeconds -gt $HeartbeatMaxAgeSeconds -or
              -not [bool]$finalHostCampaign[0].ready -or
              [uint64]$finalHostCampaign[0].active_processes -lt 1))) {
            throw "$($snapshot.symbol) final host/coordinator campaign summary is stale or impossible."
        }
        $campaignRow = @($campaignHealth | Where-Object { [string]$_.symbol -eq [string]$snapshot.symbol })[0]
        $campaignRow.campaign_elapsed_s = [uint64]$stableHeartbeat.elapsed_s
        $campaignRow.campaign_heartbeat_age_s = [math]::Round($finalCampaignLagSeconds, 3)
        $campaignRow.generations = [uint64]$stableHeartbeat.generations
        $campaignRow.handovers_proven = [uint64]$stableHeartbeat.handovers_proven
    }
    $finalLauncherIdentity = Test-RawQualificationProcessIdentity -Identity $launcherIdentity
    $finalWatchdogIdentity = Test-RawQualificationProcessIdentity -Identity $watchdogControl
    if (-not $finalLauncherIdentity.running -or -not $finalLauncherIdentity.valid -or
        -not $finalWatchdogIdentity.running -or -not $finalWatchdogIdentity.valid) {
        throw "Guardian or watchdog identity changed before live monitor publication."
    }
    $launcherProcessHealth = $finalLauncherIdentity
    foreach ($record in $controlRecords) {
        $finalIdentity = Test-RawQualificationProcessIdentity -Identity $record
        $row = @($processHealth | Where-Object { [string]$_.symbol -eq [string]$record.symbol })
        $finalOriginalRunning = [bool]($finalIdentity.running -and $finalIdentity.valid)
        $finalPidReusedAfterExit = [bool]($finalIdentity.running -and -not $finalIdentity.valid)
        if ($row.Count -ne 1 -or
            $finalOriginalRunning -ne [bool]$row[0].running -or
            ($finalPidReusedAfterExit -and -not [bool]$row[0].clean_capture_exit_proven)) {
            throw "$($record.symbol) coordinator identity changed before live monitor publication; retry."
        }
        $row[0].running = $finalOriginalRunning
        $row[0].exact_identity = [bool]$finalIdentity.valid
        $row[0].pid_occupied = [bool]$finalIdentity.running
        $row[0].pid_reused_after_exit = [bool]($finalPidReusedAfterExit -and [bool]$row[0].clean_capture_exit_proven)
    }
    $null = Assert-MonitorEvidenceTreeNoReparsePoints -RunRoot $resolvedRunRoot
    if (Test-Path -LiteralPath $terminalPath -PathType Leaf) {
        throw "Launcher became terminal at the live monitor publication point; retry against terminal evidence."
    }
    if (Test-Path -LiteralPath $watchdogFailurePath -PathType Leaf) {
        throw "Independent guardian watchdog failed at the live monitor publication point."
    }
    $publicationLauncherJournal = Get-VerifiedJournalSummary `
        -Path $launcherJournalPath `
        -ExpectedSchema "RawQualificationLauncherEventV1"
    if ([uint64]$publicationLauncherJournal.records -ne [uint64]$linearizedLauncherJournal.records -or
        [uint64]$publicationLauncherJournal.file_length -ne [uint64]$linearizedLauncherJournal.file_length -or
        [string]$publicationLauncherJournal.terminal_record_sha256 -ne
            [string]$linearizedLauncherJournal.terminal_record_sha256) {
        throw "Launcher FSM advanced at the live monitor publication point; retry against the new stage."
    }
    $publicationObservedNowNs = Get-RawQualificationWallNs
    $guardianPulseAgeSeconds = [double]($publicationObservedNowNs - [uint64]$guardianPulseJournal.last.body.wall_ns) / 1e9
    $telemetryAgeSeconds = [double]($publicationObservedNowNs - [uint64]$telemetryJournal.last.body.wall_ns) / 1e9
    if ($guardianPulseAgeSeconds -lt -5 -or
        $guardianPulseAgeSeconds -gt $ExpectedGuardianWatchdogDeadlineSeconds -or
        $telemetryAgeSeconds -lt -5 -or
        $telemetryAgeSeconds -gt $TelemetryMaxAgeSeconds) {
        throw "Guardian/host telemetry freshness crossed its live bound at the monitor publication point."
    }
    if ($linearizedCaptureRequiresLiveFreshness) {
        foreach ($freshness in $linearizedCampaignFreshness) {
            $campaignAgeSeconds = [double]($publicationObservedNowNs - [uint64]$freshness.latest_heartbeat_wall_ns) / 1e9
            if ($campaignAgeSeconds -lt -5 -or $campaignAgeSeconds -gt $HeartbeatMaxAgeSeconds) {
                throw "$($freshness.symbol) campaign heartbeat crossed its live freshness bound at publication."
            }
            foreach ($generation in @($freshness.generations | Where-Object { -not [bool]$_.terminal })) {
                $generationWallNs = if ([uint64]$generation.last_heartbeat_wall_ns -ne 0) {
                    [uint64]$generation.last_heartbeat_wall_ns
                } else { [uint64]$generation.launch_wall_ns }
                $generationAgeSeconds = [double]($publicationObservedNowNs - $generationWallNs) / 1e9
                if ($generationAgeSeconds -lt -5 -or $generationAgeSeconds -gt $HeartbeatMaxAgeSeconds) {
                    throw "$($freshness.symbol) active generation heartbeat crossed its live freshness bound at publication."
                }
            }
        }
    }
    foreach ($campaignRow in $campaignHealth) {
        $freshness = @($linearizedCampaignFreshness | Where-Object { [string]$_.symbol -eq [string]$campaignRow.symbol })
        if ($freshness.Count -ne 1) { throw "$($campaignRow.symbol) final freshness row is ambiguous." }
        $campaignRow.durable_heartbeat_age_s = [math]::Round(
            [double]($publicationObservedNowNs - [uint64]$freshness[0].latest_heartbeat_wall_ns) / 1e9,
            3)
    }
}

$monitorStage = Get-MonitorEventDrivenStage `
    -TerminalComplete $terminalComplete `
    -ScheduleDeviationReasons @($scheduleDeviationReasons) `
    -LauncherHistoryContract $launcherHistoryContract
$result = [pscustomobject][ordered]@{
    schema = "RawQualificationReadOnlyMonitorV1"
    status = if ($terminalComplete) { "COMPLETE" } elseif ($monitorStage -eq "DEVIATED") { "DEVIATED" } elseif ($monitorStage -eq "DRAINING") { "DRAINING" } elseif ($monitorStage -eq "VERIFYING") { "VERIFYING" } else { "HEALTHY_RUNNING" }
    stage = $monitorStage
    schedule_deviations = @($scheduleDeviationReasons)
    observed_utc = [DateTimeOffset]::UtcNow.ToString("o")
    run_id = $startup.run_id
    run_root = $resolvedRunRoot
    mode = $startup.mode
    parameters = $startup.parameters
    launcher_journal_records = [uint64]$launcherJournal.records
    launcher_journal_bytes = [uint64]$launcherJournal.file_length
    host_telemetry_records = [uint64]$telemetryJournal.records
    host_telemetry_bytes = [uint64]$telemetryJournal.file_length
    host_telemetry_age_s = [math]::Round($telemetryAgeSeconds, 3)
    guardian_pulse_records = [uint64]$guardianPulseJournal.records
    guardian_pulse_age_s = [math]::Round($guardianPulseAgeSeconds, 3)
    guardian_stage = [string]$guardianPulseJournal.last.body.payload.stage
    disk_free_gib = [math]::Floor([double]$telemetryJournal.last.body.payload.disk.free_bytes / 1GB)
    clock = $telemetryJournal.last.body.payload.clock
    guardian = [ordered]@{
        pid = [uint32]$startup.launcher_pid
        running = [bool]$launcherProcessHealth.running
        exact_identity = [bool]$launcherProcessHealth.valid
    }
    processes = $processHealth
    campaigns = $campaignHealth
    current_terminal_reverification = @($currentReverificationEvidence)
    launcher_terminal_byte_authentication = if ($terminalComplete) {
        "CANONICAL_FROZEN_SNAPSHOT_WITH_EXACT_DURABLE_LAUNCHER_TERMINAL_POST_LINK"
    } else { "NOT_TERMINAL" }
    inference_boundary = "PID alone is not health; result requires exact identity, recent campaign heartbeat, hash-linked semantic events and host telemetry. Terminal bytes are authenticated by the final durable launcher-journal post-link. Reparse-free path barriers do not authenticate a malicious local writer that replaces ordinary bytes between separately opened handles; this proves bounded evidence consistency, not market profitability."
}
$result | ConvertTo-Json -Depth 30
