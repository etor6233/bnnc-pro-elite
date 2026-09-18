[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-ClockSelfTest {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
}

$helper = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "RawQualification.Windows.ps1") -ErrorAction Stop).Path
$probeScript = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "RawQualification.TelemetryProbe.ps1") -ErrorAction Stop).Path
$launcher = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "run_24h_raw_qualification.ps1") -ErrorAction Stop).Path
. $helper

function New-TestClock {
    return [pscustomobject][ordered]@{
        healthy = $true
        leap_indicator = 0
        stratum = 2
        source = "time.nist.gov,0x8"
        last_successful_sync = "2026-08-31T10:00:00Z"
        root_delay_s = [double]0.1
        root_dispersion_s = [double]0.01
        phase_offset_s = [double]0.001
        seconds_since_last_good_sync = [double]1
        maximum_last_good_sync_age_s = [double]21600
        state_machine = 2
        last_sync_error = 0
        poll_interval_s = [uint64]64
        raw_status_sha256 = "a" * 64
        query_exit_code = 0
    }
}

Assert-RawQualificationClockHealthy -Clock (New-TestClock)
$cases = [ordered]@{
    QUERY_EXIT_NONZERO = { param($clock) $clock.query_exit_code = 1 }
    LEAP_INDICATOR_NOT_ZERO = { param($clock) $clock.leap_indicator = 3 }
    STRATUM_OUT_OF_RANGE = { param($clock) $clock.stratum = 0 }
    SOURCE_LOCAL_OR_UNSPECIFIED = { param($clock) $clock.source = "Local CMOS Clock" }
    STATE_MACHINE_NOT_SYNC = { param($clock) $clock.state_machine = 1 }
    LAST_SYNC_ERROR_NONZERO = { param($clock) $clock.last_sync_error = 2 }
    LAST_GOOD_SYNC_ABSENT_STALE_OR_NEGATIVE = { param($clock) $clock.seconds_since_last_good_sync = 21601 }
    HEALTH_FLAG_CONTRADICTS_PARSED_FIELDS = { param($clock) $clock.healthy = $false }
}
$rejected = [uint32]0
foreach ($entry in $cases.GetEnumerator()) {
    $clock = New-TestClock
    $clock.healthy = $false
    if ($entry.Key -ceq "HEALTH_FLAG_CONTRADICTS_PARSED_FIELDS") { $clock.healthy = $true }
    & $entry.Value $clock
    if ($entry.Key -ceq "HEALTH_FLAG_CONTRADICTS_PARSED_FIELDS") { $clock.healthy = $false }
    $message = $null
    try { Assert-RawQualificationClockHealthy -Clock $clock }
    catch { $message = $_.Exception.Message }
    Assert-ClockSelfTest ($null -ne $message) "Clock mutant was accepted: $($entry.Key)"
    Assert-ClockSelfTest ($message.StartsWith("HOST_CLOCK_HEALTH_GATE_FAILED:", [StringComparison]::Ordinal)) `
        "Clock failure lacks its stable machine-readable prefix: $($entry.Key)"
    Assert-ClockSelfTest ($message.Contains("violations=$($entry.Key)")) `
        "Clock failure omitted its exact violated invariant: $($entry.Key)"
    foreach ($field in @("query_exit_code", "leap_indicator", "stratum", "source", "state_machine",
            "last_sync_error", "seconds_since_last_good_sync", "maximum_last_good_sync_age_s",
            "phase_offset_s", "root_delay_s", "root_dispersion_s", "poll_interval_s", "raw_status_sha256",
            "healthy", "last_successful_sync")) {
        Assert-ClockSelfTest ($message.Contains(('"' + $field + '"'))) `
            "Clock failure omitted forensic field $field for $($entry.Key)."
    }
    $rejected++
}

$probeText = Get-Content -LiteralPath $probeScript -Raw -Encoding UTF8
$launcherText = Get-Content -LiteralPath $launcher -Raw -Encoding UTF8
Assert-ClockSelfTest (-not $probeText.Contains("Assert-RawQualificationClockHealthy")) `
    "The child provider can still fail before publishing its JSON observation."
$schemaIndex = $launcherText.IndexOf('$invocation.value.schema', [StringComparison]::Ordinal)
$assertIndex = $launcherText.IndexOf('Assert-RawQualificationClockHealthy -Clock $invocation.value.clock', [StringComparison]::Ordinal)
$cleanupIndex = $launcherText.IndexOf('foreach ($path in @($invocation.stdout_path, $invocation.stderr_path))', $assertIndex, [StringComparison]::Ordinal)
Assert-ClockSelfTest ($schemaIndex -ge 0 -and $assertIndex -gt $schemaIndex -and $cleanupIndex -gt $assertIndex) `
    "Clock evidence is not validated after JSON publication and before success-path cleanup."
foreach ($binding in @("stdout_path", "stdout_bytes", "stdout_sha256", "stderr_path", "stderr_bytes", "stderr_sha256")) {
    Assert-ClockSelfTest ($launcherText.IndexOf($binding, $assertIndex, [StringComparison]::Ordinal) -gt $assertIndex) `
        "Clock terminal failure does not bind provider evidence field $binding."
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("binance-clock-evidence-" + [Guid]::NewGuid().ToString("N"))
$null = New-Item -ItemType Directory -Path $tempRoot -ErrorAction Stop
try {
    $syntheticHelper = Join-Path $tempRoot "SyntheticClockHelper.ps1"
    $syntheticStdout = Join-Path $tempRoot "host-synthetic.stdout.json"
    $syntheticStderr = Join-Path $tempRoot "host-synthetic.stderr.log"
    $syntheticSource = @'
function Get-RawQualificationClockStatus {
    [pscustomobject][ordered]@{
        healthy = $false; leap_indicator = 0; stratum = 2; source = "time.nist.gov,0x8"
        last_successful_sync = "2026-08-31T10:00:00Z"; root_delay_s = [double]0.1
        root_dispersion_s = [double]0.01; phase_offset_s = [double]0.001
        seconds_since_last_good_sync = [double]5; maximum_last_good_sync_age_s = [double]21600
        state_machine = 2; last_sync_error = 2; poll_interval_s = [uint64]64
        raw_status_sha256 = "b" * 64; query_exit_code = 0
    }
}
function Get-RawQualificationDiskCounters { param($DriveDeviceId); [pscustomobject]@{ device_id=$DriveDeviceId; filesystem="NTFS"; size_bytes=[uint64]1; free_bytes=[uint64]1; avg_read_latency_s=[double]0; avg_write_latency_s=[double]0; current_queue_length=[double]0 } }
function Get-RawQualificationNetworkCounters { [pscustomobject]@{ received_bytes=[uint64]0; sent_bytes=[uint64]0; received_packets=[uint64]0; sent_packets=[uint64]0; received_discards=[uint64]0; outbound_discards=[uint64]0; received_errors=[uint64]0; outbound_errors=[uint64]0 } }
function Get-RawQualificationCollectorProcesses { param($RootProcessIds); [pscustomobject]@{ pid=[uint32]$RootProcessIds[0]; parent_pid=[uint32]0; name="synthetic"; creation_date="2026-08-31T10:00:00Z"; executable_path="synthetic"; cpu_kernel_100ns=[uint64]0; cpu_user_100ns=[uint64]0; working_set_bytes=[uint64]0; page_file_kib=[uint64]0; handles=[uint32]1; read_operations=[uint64]0; read_bytes=[uint64]0; write_operations=[uint64]0; write_bytes=[uint64]0 } }
'@
    [IO.File]::WriteAllText($syntheticHelper, $syntheticSource, [Text.UTF8Encoding]::new($false))
    $powershell = Join-Path $PSHOME "powershell.exe"
    & $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $probeScript `
        -HelperPath $syntheticHelper -DriveDeviceId "C:" -RootProcessId $PID 1> $syntheticStdout 2> $syntheticStderr
    $providerExitCode = [int]$LASTEXITCODE
    Assert-ClockSelfTest ($providerExitCode -eq 0) "Synthetic unhealthy provider failed before JSON publication."
    Assert-ClockSelfTest ((Get-Item -LiteralPath $syntheticStdout).Length -gt 0) "Synthetic unhealthy provider emitted empty stdout."
    Assert-ClockSelfTest ((Get-Item -LiteralPath $syntheticStderr).Length -eq 0) "Synthetic unhealthy provider emitted stderr."
    $syntheticProbe = Get-Content -LiteralPath $syntheticStdout -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    Assert-ClockSelfTest (-not [bool]$syntheticProbe.clock.healthy -and [int]$syntheticProbe.clock.last_sync_error -eq 2) `
        "Synthetic unhealthy provider JSON did not retain the injected W32Time values."
    $syntheticFailure = $null
    try { Assert-RawQualificationClockHealthy -Clock $syntheticProbe.clock }
    catch { $syntheticFailure = $_.Exception.Message }
    Assert-ClockSelfTest ($syntheticFailure.Contains("violations=LAST_SYNC_ERROR_NONZERO")) `
        "The parent gate did not identify the persisted synthetic clock invariant."
}
finally {
    $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
    $expectedPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if ($resolvedTemp.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$parseErrors = [Collections.Generic.List[Management.Automation.Language.ParseError]]::new()
foreach ($path in @($helper, $probeScript, $launcher)) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    foreach ($error in @($errors)) { $parseErrors.Add($error) }
}
Assert-ClockSelfTest ($parseErrors.Count -eq 0) "A clock-evidence PowerShell source failed AST parsing."

[pscustomobject][ordered]@{
    schema = "ClockFailureEvidenceSelfTestV1"
    status = "PASS"
    healthy_case_accepted = $true
    unhealthy_mutants_rejected = $rejected
    child_publishes_before_parent_health_gate = $true
    failure_evidence_retained_before_cleanup = $true
    unhealthy_child_process_published_json = $true
} | ConvertTo-Json -Depth 5
