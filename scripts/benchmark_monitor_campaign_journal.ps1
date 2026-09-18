[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $CampaignDirectory,

    [ValidateRange(1, 100)]
    [int] $IncrementalIterations = 3,

    [AllowNull()]
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$campaignRoot = [IO.Path]::GetFullPath($CampaignDirectory)
if (-not (Test-Path -LiteralPath $campaignRoot -PathType Container)) {
    throw "Campaign directory does not exist: $campaignRoot"
}

. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")

# These are monitor contract constants consumed by the extracted lifecycle
# validator. Keeping them explicit makes the benchmark fail if its harness
# would otherwise exercise different freshness semantics.
$ExpectedMarketFreshnessStartupGraceNs = [uint64]30000000000
$ExpectedMarketFreshnessDeadlineNs = [uint64]30000000000

$monitorPath = Join-Path $PSScriptRoot "monitor_24h_raw_qualification.ps1"
$parseErrors = $null
$monitorAst = [Management.Automation.Language.Parser]::ParseFile(
    $monitorPath, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    throw "Monitor source does not parse: $($parseErrors[0].Message)"
}

$requiredFunctions = [string[]]@(
    "Test-MonitorExactJsonProperties",
    "Test-MonitorExactJsonPropertyOrder",
    "Test-MonitorJsonNullOrInteger",
    "Read-MonitorFrozenCanonicalJsonLines",
    "ConvertFrom-MonitorCanonicalCompactJsonLine",
    "Test-MonitorJsonObjectKeysOrdinalSortedRecursive",
    "Assert-MonitorRustCampaignJournalEnvelopeJsonTypes",
    "Assert-MonitorRustCampaignPayloadJsonContract",
    "Get-CampaignJournalHealth"
)
foreach ($functionName in $requiredFunctions) {
    $definition = @($monitorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $functionName
    }, $true))
    if ($definition.Count -ne 1) {
        throw "Monitor function extraction is ambiguous: $functionName"
    }
    Invoke-Expression $definition[0].Extent.Text
}

$startupPath = Join-Path $campaignRoot "campaign-startup.json"
$journalPath = Join-Path $campaignRoot "campaign-events.jsonl"
if (-not (Test-Path -LiteralPath $startupPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $journalPath -PathType Leaf)) {
    throw "Campaign directory lacks campaign-startup.json or campaign-events.jsonl."
}

$startupBytes = [IO.File]::ReadAllBytes($startupPath)
$startup = [Text.UTF8Encoding]::new($false, $true).GetString($startupBytes) |
    ConvertFrom-Json -ErrorAction Stop
$startupSha256 = Get-RawQualificationSha256Bytes -Bytes $startupBytes

$fullTimer = [Diagnostics.Stopwatch]::StartNew()
$full = Get-CampaignJournalHealth `
    -Path $journalPath `
    -CampaignStartup $startup `
    -CampaignStartupSha256 $startupSha256
$fullTimer.Stop()

$incrementalElapsed = [Collections.Generic.List[double]]::new()
$current = $full
for ($iteration = 0; $iteration -lt $IncrementalIterations; $iteration++) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $next = Get-CampaignJournalHealth `
        -Path $journalPath `
        -CampaignStartup $startup `
        -CampaignStartupSha256 $startupSha256 `
        -ExpectedPrefixRecords ([uint64]$current.records) `
        -ExpectedPrefixTerminalRecordSha256 ([string]$current.terminal_record_sha256) `
        -ExpectedPrefixFileLength ([uint64]$current.file_length) `
        -ExpectedPrefixFileSha256 ([string]$current.file_sha256) `
        -ContinuationState $current.continuation_state
    $timer.Stop()
    $incrementalElapsed.Add($timer.Elapsed.TotalMilliseconds)
    $current = $next
}

$fullGenerationJson = @($full.generation_health) | ConvertTo-Json -Depth 20 -Compress
$currentGenerationJson = @($current.generation_health) | ConvertTo-Json -Depth 20 -Compress
$stateEquivalent = (
    [uint64]$current.records -eq [uint64]$full.records -and
    [string]$current.terminal_record_sha256 -ceq [string]$full.terminal_record_sha256 -and
    [uint64]$current.complete_length -eq [uint64]$full.complete_length -and
    [string]$current.complete_sha256 -ceq [string]$full.complete_sha256 -and
    [bool]$current.process_started -eq [bool]$full.process_started -and
    [bool]$current.snapshot_durable -eq [bool]$full.snapshot_durable -and
    [bool]$current.campaign_failed -eq [bool]$full.campaign_failed -and
    [bool]$current.campaign_committed -eq [bool]$full.campaign_committed -and
    [uint64]$current.child_stderr_events -eq [uint64]$full.child_stderr_events -and
    $currentGenerationJson -ceq $fullGenerationJson)
if (-not $stateEquivalent) {
    throw "Incremental no-growth state differs from replay-from-zero."
}

$ordered = @($incrementalElapsed.ToArray() | Sort-Object)
$middle = [int][math]::Floor($ordered.Count / 2)
$incrementalMedianMs = if (($ordered.Count % 2) -eq 1) {
    [double]$ordered[$middle]
}
else {
    ([double]$ordered[$middle - 1] + [double]$ordered[$middle]) / 2.0
}
$fullMs = $fullTimer.Elapsed.TotalMilliseconds

$result = [pscustomobject][ordered]@{
    schema = "MonitorCampaignJournalIncrementalBenchmarkV1"
    status = "PASS"
    campaign_directory = $campaignRoot
    journal_path = [IO.Path]::GetFullPath($journalPath)
    journal_bytes = [uint64](Get-Item -LiteralPath $journalPath).Length
    records = [uint64]$full.records
    terminal_record_sha256 = [string]$full.terminal_record_sha256
    full_replay_ms = [math]::Round($fullMs, 3)
    incremental_iterations = [uint64]$IncrementalIterations
    incremental_samples_ms = @($incrementalElapsed.ToArray() | ForEach-Object { [math]::Round($_, 3) })
    incremental_median_ms = [math]::Round($incrementalMedianMs, 3)
    measured_speedup = if ($incrementalMedianMs -gt 0) {
        [math]::Round($fullMs / $incrementalMedianMs, 2)
    }
    else { $null }
    state_equivalent = $true
    monitor_sha256 = Get-RawQualificationSha256File -Path $monitorPath
    helper_sha256 = Get-RawQualificationSha256File -Path (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")
    measured_wall_ns = Get-RawQualificationWallNs
}
$json = $result | ConvertTo-Json -Depth 20
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
    $outputParent = Split-Path -Parent $resolvedOutput
    if (-not (Test-Path -LiteralPath $outputParent -PathType Container) -or
        $resolvedOutput.StartsWith($campaignRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Benchmark output must use an existing directory outside immutable campaign evidence."
    }
    $outputBytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
    $output = [IO.File]::Open(
        $resolvedOutput, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $output.Write($outputBytes, 0, $outputBytes.Length)
        $output.Flush($true)
    }
    finally { $output.Dispose() }
}
$json
