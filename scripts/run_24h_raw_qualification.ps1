[CmdletBinding()]
param(
    [ValidateSet("Production", "SevenDay", "Smoke", "Test")] [string] $Mode = "Production",
    [ValidateRange(1, 604800)] [int] $TotalSeconds = 86400,
    [ValidateRange(1, 86000)] [int] $RotationSeconds = 82800,
    [ValidateRange(1, 3600)] [int] $OverlapSeconds = 900,
    [ValidateRange(1, 3600)] [int] $SegmentSeconds = 900,
    [string] $OutputBase = "artifacts/qualification-24h-raw",
    [ValidateRange(100, 10000)] [int] $MinimumFreeGiB = 100,
    [ValidateRange(30, 600)] [int] $StartupDeadlineSeconds = 180,
    [ValidateRange(300, 86400)] [int] $PostVerificationDeadlineSeconds = 14400,
    [ValidateRange(60, 43200)] [int] $IndependentVerifierTimeoutSeconds = 7200,
    [switch] $ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")
$SuppliedScriptParameters = @{} + $PSBoundParameters
$Mode = ConvertTo-RawQualificationCanonicalMode -Mode $Mode

# SevenDay is a named, immutable qualification profile. Selecting it is enough
# to obtain its exact capture topology; explicit values are still accepted only
# when they equal this profile and are checked again by Assert-DurationContract.
if ($Mode -eq "SevenDay") {
    if (-not $SuppliedScriptParameters.ContainsKey("TotalSeconds")) { $TotalSeconds = 604800 }
    if (-not $SuppliedScriptParameters.ContainsKey("RotationSeconds")) { $RotationSeconds = 82800 }
    if (-not $SuppliedScriptParameters.ContainsKey("OverlapSeconds")) { $OverlapSeconds = 900 }
    if (-not $SuppliedScriptParameters.ContainsKey("SegmentSeconds")) { $SegmentSeconds = 900 }
    if (-not $SuppliedScriptParameters.ContainsKey("OutputBase")) {
        $OutputBase = "artifacts/qualification-7d-raw"
    }
}

# Test and Smoke retain their short explicit/default budgets. Production and
# SevenDay use
# fixed post-capture budget derived from measured full-scan verifier throughput:
# the four independent oracles are sequential and must not be forced to fail
# after an otherwise valid 24-hour capture merely because the test budget was
# inherited. Explicit Production overrides are checked below and cannot weaken
# this contract.
if ($Mode -in @("Production", "SevenDay")) {
    if (-not $SuppliedScriptParameters.ContainsKey("PostVerificationDeadlineSeconds")) {
        $PostVerificationDeadlineSeconds = 86400
    }
    if (-not $SuppliedScriptParameters.ContainsKey("IndependentVerifierTimeoutSeconds")) {
        $IndependentVerifierTimeoutSeconds = 43200
    }
}

$Production = [ordered]@{
    total_s = 86400
    rotation_s = 82800
    overlap_s = 900
    segment_s = 900
    post_verification_deadline_s = 86400
    independent_verifier_timeout_s = 43200
}
$SevenDay = [ordered]@{
    total_s = 604800
    rotation_s = 82800
    overlap_s = 900
    segment_s = 900
    post_verification_deadline_s = 86400
    independent_verifier_timeout_s = 43200
}
$HeartbeatDeadlineSeconds = 30
$SemanticDeadlineSeconds = 30
$TelemetryIntervalSeconds = 30
$GuardianGapDeadlineSeconds = 60
$GenerationTerminalDeadlineSeconds = 120
$CampaignCommitDeadlineSeconds = 1800
$MarketFreshnessStartupGraceSeconds = 30
$MarketFreshnessDeadlineSeconds = 30
$MarketFreshnessStartupGraceNs = [uint64]30000000000
$MarketFreshnessDeadlineNs = [uint64]30000000000
$ExpectedCombinedRawGiBPerHour = 2.0
$ProjectionSafetyMultiplier = 2.0
$ProjectionFixedReserveGiB = 20
$MaximumVerifierArtifactBytes = 32MB
$MaximumCampaignStdoutBytes = 64MB
$MaximumCampaignStderrBytes = 0
$MaximumHostProbeArtifactBytes = 8MB
$HostTelemetryProbeTimeoutSeconds = 20
$GuardianWatchdogDeadlineSeconds = 90
$GuardianWatchdogStartupDeadlineSeconds = 90
$HostTelemetryGapDeadlineSeconds = 120
$MaximumDualLaunchSkewMilliseconds = 5000
$PythonRuntimeFingerprintTimeoutSeconds = 300
$FailureContainmentExitCode = [uint32]0xEE02
$FailureContainmentDrainDeadlineSeconds = [uint64]30
$ExpectedSpecRevision = "976cc580553890e92031b77306147c0ed1de5a46"

function Get-ConservativeRemainingProjectionGiB {
    param([Parameter(Mandatory = $true)] [double] $ElapsedSeconds)
    $boundedElapsed = [math]::Min([double]$TotalSeconds, [math]::Max(0.0, $ElapsedSeconds))
    $remainingEquivalentSeconds = [math]::Max(0.0, [double]$TotalSeconds - $boundedElapsed)
    $handoverStart = [double]$RotationSeconds
    while ($handoverStart -lt [double]$TotalSeconds) {
        $handoverEnd = [math]::Min([double]$TotalSeconds, $handoverStart + [double]$OverlapSeconds)
        if ($handoverEnd -gt $boundedElapsed) {
            $remainingEquivalentSeconds += [math]::Max(0.0, $handoverEnd - [math]::Max($boundedElapsed, $handoverStart))
        }
        $handoverStart += [double]$RotationSeconds
    }
    return [uint64][math]::Ceiling(
        $ExpectedCombinedRawGiBPerHour * ($remainingEquivalentSeconds / 3600.0) * $ProjectionSafetyMultiplier)
}

function Get-ExplicitChildEnvironmentContract {
    $entries = @()
    foreach ($name in @("SystemDrive", "SystemRoot", "WINDIR", "TEMP", "TMP")) {
        $value = [Environment]::GetEnvironmentVariable($name, [EnvironmentVariableTarget]::Process)
        if ([string]::IsNullOrWhiteSpace($value) -or $value.IndexOf([char]0) -ge 0) {
            throw "Required child environment variable $name is absent or invalid."
        }
        $entries += ($name + "=" + $value)
    }
    $entries = [string[]]$entries
    [Array]::Sort($entries, [StringComparer]::OrdinalIgnoreCase)
    $material = [string]::Join("`0", $entries) + "`0`0"
    return [pscustomobject][ordered]@{
        mode = "EXPLICIT_ALLOWLIST_NO_INHERITANCE"
        names = @($entries | ForEach-Object { $_.Substring(0, $_.IndexOf('=')) })
        entries_sha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UnicodeEncoding]::new($false, $false).GetBytes($material))
        Entries = [string[]]$entries
    }
}

function Invoke-BoundedQualificationJsonProcess {
    param(
        [Parameter(Mandatory = $true)] [IntPtr] $JobHandle,
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [string] $Executable,
        [Parameter(Mandatory = $true)] [string[]] $Arguments,
        [Parameter(Mandatory = $true)] [string] $WorkingDirectory,
        [Parameter(Mandatory = $true)] [string] $OutputDirectory,
        [Parameter(Mandatory = $true)] [string[]] $EnvironmentEntries,
        [ValidateRange(1, 300)] [int] $TimeoutSeconds = 20,
        [scriptblock] $ProgressAction
    )
    $stdoutPath = Join-Path $OutputDirectory ($Name + ".stdout.json")
    $stderrPath = Join-Path $OutputDirectory ($Name + ".stderr.log")
    if ($JobHandle -eq [IntPtr]::Zero) { throw "Bounded host probe $Name lacks its guardian Job context." }
    $boundedJob = [IntPtr]::Zero
    $launch = $null
    $resumeQpcTimestamp = [long]0
    $finalElapsedTicks = [long]0
    $parentExitObservedQpcTimestamp = [long]0
    $descendantDrainElapsedTicks = [long]0
    $progressTimer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $boundedJob = [RawQualificationNative]::CreateKillOnCloseJob(
            "Local\BinanceRawQualificationBoundedProbe-" + [Guid]::NewGuid().ToString("N"))
        $launch = [RawQualificationNative]::StartSuspendedInJobsRetainedWithEnvironment(
            $JobHandle,
            $boundedJob,
            $Executable,
            $Arguments,
            $WorkingDirectory,
            $stdoutPath,
            $stderrPath,
            $EnvironmentEntries)
        $resumeQpcTimestamp = [long]$launch.ResumeQpcTimestamp
        while (-not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 250)) {
            foreach ($path in @($stdoutPath, $stderrPath)) {
                if ((Test-Path -LiteralPath $path -PathType Leaf) -and
                    [uint64](Get-Item -LiteralPath $path -ErrorAction Stop).Length -gt [uint64]$MaximumHostProbeArtifactBytes) {
                    $null = [RawQualificationNative]::TerminateJobObject($boundedJob, 0xEE21)
                    throw "Bounded host probe $Name exceeded its artifact limit."
                }
            }
            $elapsedTicks = Get-RawQualificationElapsedQpcTicks -ResumeQpcTimestamp $resumeQpcTimestamp
            if (-not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks $elapsedTicks `
                -TimeoutSeconds ([uint64]$TimeoutSeconds))) {
                $null = [RawQualificationNative]::TerminateJobObject($boundedJob, 0xEE22)
                throw "Bounded host probe $Name exceeded its ${TimeoutSeconds}-second deadline."
            }
            if ($null -ne $ProgressAction -and $progressTimer.Elapsed.TotalSeconds -ge 5) {
                & $ProgressAction
                $progressTimer.Restart()
            }
        }
        $parentExitObservedQpcTimestamp = [long][Diagnostics.Stopwatch]::GetTimestamp()
        $finalElapsedTicks = [long]($parentExitObservedQpcTimestamp - $resumeQpcTimestamp)
        if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $finalElapsedTicks `
            -TimeoutSeconds ([uint64]$TimeoutSeconds))) {
            $null = [RawQualificationNative]::TerminateJobObject($boundedJob, 0xEE22)
            throw "Bounded host probe $Name exceeded its ${TimeoutSeconds}-second deadline at exact process exit."
        }
        $exitCode = [int][RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle)
        while ([RawQualificationNative]::GetActiveProcessCount($boundedJob) -ne 0) {
            $descendantDrainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $parentExitObservedQpcTimestamp)
            if (-not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks $descendantDrainElapsedTicks `
                -TimeoutSeconds 10)) { break }
            Start-Sleep -Milliseconds 100
        }
        $descendantDrainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $parentExitObservedQpcTimestamp)
        if ([RawQualificationNative]::GetActiveProcessCount($boundedJob) -ne 0 -or
            -not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks $descendantDrainElapsedTicks `
                -TimeoutSeconds 10)) {
            $null = [RawQualificationNative]::TerminateJobObject($boundedJob, 0xEE23)
            throw "Bounded host probe $Name retained a descendant after parent exit."
        }
    }
    finally {
        if ($null -ne $launch -and $launch.ProcessHandle -ne [IntPtr]::Zero) {
            $null = [RawQualificationNative]::CloseHandle($launch.ProcessHandle)
        }
        if ($boundedJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($boundedJob) }
    }
    $stdoutLength = [uint64](Get-Item -LiteralPath $stdoutPath -ErrorAction Stop).Length
    $stderrLength = [uint64](Get-Item -LiteralPath $stderrPath -ErrorAction Stop).Length
    if ($exitCode -ne 0 -or $stderrLength -ne 0 -or $stdoutLength -eq 0 -or
        $stdoutLength -gt [uint64]$MaximumHostProbeArtifactBytes) {
        $stderrPreview = if ($stderrLength -gt 0 -and $stderrLength -le 4096) {
            (Get-Content -LiteralPath $stderrPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue).Trim()
        }
        else { "<stderr omitted>" }
        throw "Bounded host probe $Name failed its exit/stderr/size contract (exit=$exitCode, stdout=$stdoutLength, stderr=$stderrLength): $stderrPreview"
    }
    $raw = Get-Content -LiteralPath $stdoutPath -Raw -Encoding UTF8 -ErrorAction Stop
    $value = $raw | ConvertFrom-Json -ErrorAction Stop
    return [pscustomobject][ordered]@{
        value = $value
        pid = [uint32]$launch.ProcessId
        command_line = [string]$launch.ExactCommandLine
        resume_qpc_timestamp = [long]$resumeQpcTimestamp
        elapsed_qpc_ticks = [long]$finalElapsedTicks
        monotonic_frequency = [long][Diagnostics.Stopwatch]::Frequency
        job_membership = "PRIMARY_AND_NESTED_BOUNDED"
        parent_exit_observed_qpc_timestamp = [long]$parentExitObservedQpcTimestamp
        descendant_drain_elapsed_qpc_ticks = [long]$descendantDrainElapsedTicks
        descendant_drain_elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds -ElapsedTicks $descendantDrainElapsedTicks
        descendant_drain_active_processes = [uint32]0
        timeout_s = [uint64]$TimeoutSeconds
        elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds -ElapsedTicks $finalElapsedTicks
        stdout_path = $stdoutPath
        stdout_bytes = $stdoutLength
        stdout_sha256 = Get-RawQualificationSha256File -Path $stdoutPath
        stderr_path = $stderrPath
        stderr_bytes = $stderrLength
        stderr_sha256 = Get-RawQualificationSha256File -Path $stderrPath
    }
}

function Assert-DurationContract {
    if ($Mode -eq "Production") {
        if ($TotalSeconds -ne $Production.total_s -or
            $RotationSeconds -ne $Production.rotation_s -or
            $OverlapSeconds -ne $Production.overlap_s -or
            $SegmentSeconds -ne $Production.segment_s -or
            $PostVerificationDeadlineSeconds -ne $Production.post_verification_deadline_s -or
            $IndependentVerifierTimeoutSeconds -ne $Production.independent_verifier_timeout_s) {
            throw "Production mode is fixed at capture 86400/82800/900/900 seconds and verification 86400/43200 seconds."
        }
    }
    elseif ($Mode -eq "SevenDay") {
        if ($TotalSeconds -ne $SevenDay.total_s -or
            $RotationSeconds -ne $SevenDay.rotation_s -or
            $OverlapSeconds -ne $SevenDay.overlap_s -or
            $SegmentSeconds -ne $SevenDay.segment_s -or
            $PostVerificationDeadlineSeconds -ne $SevenDay.post_verification_deadline_s -or
            $IndependentVerifierTimeoutSeconds -ne $SevenDay.independent_verifier_timeout_s) {
            throw "SevenDay mode is fixed at capture 604800/82800/900/900 seconds and verification 86400/43200 seconds."
        }
    }
    else {
        foreach ($parameter in @("TotalSeconds", "RotationSeconds", "OverlapSeconds", "SegmentSeconds")) {
            if (-not $script:SuppliedScriptParameters.ContainsKey($parameter)) {
                throw "$Mode mode requires explicit -$parameter."
            }
        }
        if ($Mode -eq "Smoke" -and
            ($TotalSeconds -ne 120 -or $RotationSeconds -ne 60 -or
             $OverlapSeconds -ne 10 -or $SegmentSeconds -ne 10)) {
            throw "Smoke mode is fixed at 120/60/10/10 seconds."
        }
    }
    if ($OverlapSeconds -ne $SegmentSeconds -or
        ($RotationSeconds % $SegmentSeconds) -ne 0 -or
        ($RotationSeconds + $OverlapSeconds) -gt 86300 -or
        $TotalSeconds -lt $OverlapSeconds) {
        throw "Require overlap == segment, rotation divisible by segment, total >= overlap, and generation <= 86,300 seconds."
    }
    if ($PostVerificationDeadlineSeconds -le ($PythonRuntimeFingerprintTimeoutSeconds + 15)) {
        throw "PostVerificationDeadlineSeconds must exceed the bounded Python runtime fingerprint budget plus its 15-second publication reserve."
    }
}

function Get-PreflightState {
    param([Parameter(Mandatory = $true)] [string] $Repo)

    if ($env:OS -ne "Windows_NT" -or -not [Environment]::Is64BitProcess) {
        throw "The qualification guardian requires 64-bit Windows PowerShell."
    }
    $releaseRoot = Join-Path $Repo "target\release"
    $campaignExe = Join-Path $releaseRoot "raw_campaign.exe"
    $captureExe = Join-Path $releaseRoot "segmented_capture.exe"
    $campaignVerifierExe = Join-Path $releaseRoot "campaign_verify.exe"
    $publicConfig = Join-Path $Repo "config\public.json"
    $sourceLock = Join-Path (Split-Path $Repo -Parent) "BINANCE_SOURCE_LOCK.md"
    $launcherScript = Join-Path $PSScriptRoot "run_24h_raw_qualification.ps1"
    $monitorScript = Join-Path $PSScriptRoot "monitor_24h_raw_qualification.ps1"
    $helperScript = Join-Path $PSScriptRoot "RawQualification.Windows.ps1"
    $telemetryProbeScript = Join-Path $PSScriptRoot "RawQualification.TelemetryProbe.ps1"
    $watchdogScript = Join-Path $PSScriptRoot "RawQualification.Watchdog.ps1"
    $pythonRuntimeFingerprintScript = Join-Path $PSScriptRoot "RawQualification.PythonRuntimeFingerprint.ps1"
    $powerShellExecutable = Join-Path $PSHOME "powershell.exe"
    $pythonSourceRoot = Join-Path $Repo "src"
    $python = Join-Path $Repo ".venv\Scripts\python.exe"
    $pythonProject = Join-Path $Repo "pyproject.toml"
    $pythonRequirements = Join-Path $Repo "requirements.lock"
    foreach ($path in @($campaignExe, $captureExe, $campaignVerifierExe, $publicConfig, $sourceLock, $launcherScript, $monitorScript, $helperScript, $telemetryProbeScript, $watchdogScript, $pythonRuntimeFingerprintScript, $powerShellExecutable, $python, $pythonProject, $pythonRequirements)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required pre-existing artifact is absent: $path"
        }
    }

    $config = Get-Content -LiteralPath $publicConfig -Raw -Encoding UTF8 | ConvertFrom-Json
    $topLevelProperties = @($config.PSObject.Properties.Name | Sort-Object)
    $jsonProperties = @($config.json.PSObject.Properties.Name | Sort-Object)
    if (($topLevelProperties -join ',') -ne "credentials,environment,json,order_entry,schema_version,spec_revision,symbols,venue" -or
        ($jsonProperties -join ',') -ne "depth_interval,rest_base,streams,time_unit,websocket_base" -or
        $config.schema_version -ne "1" -or
        $config.environment -ne "production-public-market-data" -or
        $config.venue -ne "binance-spot" -or
        $config.credentials -ne "FORBIDDEN" -or
        $config.order_entry -ne "ABSENT" -or
        $config.spec_revision -ne $ExpectedSpecRevision -or
        $config.json.websocket_base -ne "wss://data-stream.binance.vision:443" -or
        $config.json.rest_base -ne "https://data-api.binance.vision" -or
        $config.json.depth_interval -ne "100ms" -or
        $config.json.time_unit -ne "MICROSECOND" -or
        (@($config.json.streams) -join ',') -ne "depth,trade" -or
        @($config.symbols).Count -ne 2 -or
        (@($config.symbols) -join ',') -ne "BTCUSDT,ETHUSDT") {
        throw "config/public.json differs from the fixed public raw-data scope."
    }

    $cbsReboot = Test-Path -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    $wuReboot = Test-Path -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    if ($cbsReboot -or $wuReboot) {
        throw "Windows reports a servicing reboot pending."
    }

    if (-not (Test-RawQualificationTcpPort -HostName "data-stream.binance.vision" -Port 443) -or
        -not (Test-RawQualificationTcpPort -HostName "data-api.binance.vision" -Port 443)) {
        throw "Binance public WebSocket/REST endpoints are not reachable on TCP 443."
    }

    $baseCandidate = [IO.Path]::GetFullPath((Join-Path $Repo $OutputBase))
    $repoPrefix = [IO.Path]::GetFullPath($Repo).TrimEnd('\') + '\'
    if ([IO.Path]::IsPathRooted($OutputBase) -or
        -not $baseCandidate.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "OutputBase must be a relative path contained by the repository."
    }
    # The sealed Python verifier on this host is not Win32-long-path enabled.
    # Project the longest fixed production evidence name before capture so a
    # 24-hour run can never fail only when the final independent scan opens it.
    $projectedLongestArtifact = Join-Path $baseCandidate `
        "00000000T000000Z-dual-000000000000\0000000000000000000-BTCUSDT-raw-000000000000\generations\0000000000000000000-BTCUSDT-g000-000000000000\transport-depth-events.jsonl"
    $maximumVerifierPathCharacters = 259
    if ($projectedLongestArtifact.Length -gt $maximumVerifierPathCharacters) {
        throw "OutputBase would create a $($projectedLongestArtifact.Length)-character verifier path; the measured host limit is $maximumVerifierPathCharacters. Select a shorter repository-relative OutputBase."
    }
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $baseCandidate
    $driveDeviceId = [IO.Path]::GetPathRoot($baseCandidate).TrimEnd('\')
    $childEnvironment = Get-ExplicitChildEnvironmentContract
    $probeTemp = Join-Path ([IO.Path]::GetTempPath()) ("BinanceRawQualificationPreflight-" + [Guid]::NewGuid().ToString("N"))
    $probeJob = [IntPtr]::Zero
    try {
        $null = New-Item -ItemType Directory -Path $probeTemp -ErrorAction Stop
        $probeJob = [RawQualificationNative]::CreateKillOnCloseJob("Local\BinanceRawQualificationPreflight-" + [Guid]::NewGuid().ToString("N"))
        $probeInvocation = Invoke-BoundedQualificationJsonProcess `
            -JobHandle $probeJob `
            -Name "preflight-host" `
            -Executable $powerShellExecutable `
            -Arguments ([string[]]@(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $telemetryProbeScript,
                "-HelperPath", $helperScript,
                "-DriveDeviceId", $driveDeviceId,
                "-RootProcessId", $PID.ToString([Globalization.CultureInfo]::InvariantCulture),
                "-IncludeCollectorConflictScan"
            )) `
            -WorkingDirectory $Repo `
            -OutputDirectory $probeTemp `
            -EnvironmentEntries ([string[]]$childEnvironment.Entries) `
            -TimeoutSeconds $HostTelemetryProbeTimeoutSeconds
        $hostPreflight = $probeInvocation.value
        $runtimeInvocation = Invoke-BoundedQualificationJsonProcess `
            -JobHandle $probeJob `
            -Name "preflight-python-runtime" `
            -Executable $powerShellExecutable `
            -Arguments ([string[]]@(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $pythonRuntimeFingerprintScript,
                "-HelperPath", $helperScript,
                "-PythonExecutable", $python
            )) `
            -WorkingDirectory $Repo `
            -OutputDirectory $probeTemp `
            -EnvironmentEntries ([string[]]$childEnvironment.Entries) `
            -TimeoutSeconds $PythonRuntimeFingerprintTimeoutSeconds
        if ($runtimeInvocation.value.schema -ne "RawQualificationPythonRuntimeFingerprintV1") {
            throw "Bounded Python runtime fingerprint returned an unexpected schema."
        }
        $pythonRuntime = $runtimeInvocation.value.runtime
    }
    finally {
        if ($probeJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($probeJob) }
        if (Test-Path -LiteralPath $probeTemp -PathType Container) {
            $resolvedProbeTemp = [IO.Path]::GetFullPath($probeTemp)
            $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
            if (-not $resolvedProbeTemp.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Preflight probe cleanup target escaped the system temporary directory."
            }
            Remove-Item -LiteralPath $resolvedProbeTemp -Recurse -Force -ErrorAction Stop
        }
    }
    if ($hostPreflight.schema -ne "RawQualificationTelemetryProbeV1") {
        throw "Bounded preflight telemetry returned an unexpected schema."
    }
    if (-not [bool]$hostPreflight.power.ac_sleep_disabled -or [int]$hostPreflight.power.powercfg_exit_code -ne 0) {
        throw "The active power plan does not have AC sleep disabled."
    }
    $conflicts = @($hostPreflight.conflicting_collectors)
    if ($conflicts.Count -gt 0) {
        throw "A known collector is already active (PID $($conflicts[0].pid), $($conflicts[0].name))."
    }
    $clock = $hostPreflight.clock
    Assert-RawQualificationClockHealthy -Clock $clock
    $diskTelemetryPreflight = $hostPreflight.disk
    if ($diskTelemetryPreflight.filesystem -ne "NTFS") {
        throw "The evidence root must reside on an available NTFS volume."
    }
    $persistentReserveGiB = [uint64][math]::Max($MinimumFreeGiB, $ProjectionFixedReserveGiB)
    $projectedGiB = Get-ConservativeRemainingProjectionGiB -ElapsedSeconds 0
    $requiredGiB = [uint64]($persistentReserveGiB + $projectedGiB)
    $freeGiB = [math]::Floor([double]$diskTelemetryPreflight.free_bytes / 1GB)
    if ($freeGiB -lt $requiredGiB) {
        throw "Only $freeGiB GiB are free; the conservative requirement is $requiredGiB GiB."
    }
    # The exact runtime providers ran in a bounded, kill-on-close subprocess.
    $networkTelemetryPreflight = $hostPreflight.network
    $processTelemetryPreflight = @($hostPreflight.collector_processes)
    if ($processTelemetryPreflight.Count -lt 1) {
        throw "Host process telemetry did not observe the launcher preflight process."
    }

    $pendingRename = $false
    try {
        $sessionManager = Get-ItemProperty -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Stop
        $pendingRename = $null -ne $sessionManager.PendingFileRenameOperations -and @($sessionManager.PendingFileRenameOperations).Count -gt 0
    }
    catch [Management.Automation.ItemNotFoundException] {}
    catch [Management.Automation.PSArgumentException] {}

    # The mutable worktree is inventoried but never executed. Bytecode caches
    # created by unrelated development are ignored here; an exact source-only
    # copy is durably sealed inside the run before startup publication.
    $pythonVerifierSource = Get-RawQualificationSourceTreeDigest `
        -Root $pythonSourceRoot `
        -AllowIgnoredBytecodeCaches
    return [pscustomobject][ordered]@{
        repo = $Repo
        output_base = $baseCandidate
        verifier_path_policy = [ordered]@{
            projected_longest_artifact = $projectedLongestArtifact
            projected_characters = [uint32]$projectedLongestArtifact.Length
            maximum_characters = [uint32]$maximumVerifierPathCharacters
            status = "PASS"
        }
        drive_device_id = $driveDeviceId
        free_gib = [uint64]$freeGiB
        projection_combined_raw_gib_per_hour = [double]$ExpectedCombinedRawGiBPerHour
        projection_safety_multiplier = [double]$ProjectionSafetyMultiplier
        projection_fixed_reserve_gib = [uint64]$ProjectionFixedReserveGiB
        persistent_reserve_gib = $persistentReserveGiB
        projected_remaining_gib_at_start = [uint64]$projectedGiB
        required_free_gib = [uint64]$requiredGiB
        disk_telemetry_preflight = $diskTelemetryPreflight
        network_telemetry_preflight = $networkTelemetryPreflight
        process_telemetry_preflight = $processTelemetryPreflight
        campaign_executable = $campaignExe
        campaign_executable_sha256 = Get-RawQualificationSha256File -Path $campaignExe
        capture_executable = $captureExe
        capture_executable_sha256 = Get-RawQualificationSha256File -Path $captureExe
        campaign_verifier_executable = $campaignVerifierExe
        campaign_verifier_executable_sha256 = Get-RawQualificationSha256File -Path $campaignVerifierExe
        public_config = $publicConfig
        public_config_sha256 = Get-RawQualificationSha256File -Path $publicConfig
        source_lock = $sourceLock
        source_lock_sha256 = Get-RawQualificationSha256File -Path $sourceLock
        launcher_script = $launcherScript
        launcher_script_sha256 = Get-RawQualificationSha256File -Path $launcherScript
        monitor_script = $monitorScript
        monitor_script_sha256 = Get-RawQualificationSha256File -Path $monitorScript
        helper_script = $helperScript
        helper_script_sha256 = Get-RawQualificationSha256File -Path $helperScript
        telemetry_probe_script = $telemetryProbeScript
        telemetry_probe_script_sha256 = Get-RawQualificationSha256File -Path $telemetryProbeScript
        watchdog_script = $watchdogScript
        watchdog_script_sha256 = Get-RawQualificationSha256File -Path $watchdogScript
        python_runtime_fingerprint_script = $pythonRuntimeFingerprintScript
        python_runtime_fingerprint_script_sha256 = Get-RawQualificationSha256File -Path $pythonRuntimeFingerprintScript
        powershell_executable = $powerShellExecutable
        powershell_executable_sha256 = Get-RawQualificationSha256File -Path $powerShellExecutable
        host_probe_timeout_s = [uint64]$HostTelemetryProbeTimeoutSeconds
        host_probe_maximum_artifact_bytes = [uint64]$MaximumHostProbeArtifactBytes
        guardian_watchdog_deadline_s = [uint64]$GuardianWatchdogDeadlineSeconds
        guardian_watchdog_startup_deadline_s = [uint64]$GuardianWatchdogStartupDeadlineSeconds
        python_runtime_fingerprint_timeout_s = [uint64]$PythonRuntimeFingerprintTimeoutSeconds
        spec_revision = $ExpectedSpecRevision
        clock = $clock
        python = $python
        python_sha256 = Get-RawQualificationSha256File -Path $python
        python_verifier_source = $pythonVerifierSource
        python_runtime = $pythonRuntime
        python_project = $pythonProject
        python_project_sha256 = Get-RawQualificationSha256File -Path $pythonProject
        python_requirements = $pythonRequirements
        python_requirements_sha256 = Get-RawQualificationSha256File -Path $pythonRequirements
        cbs_reboot_pending = [bool]$cbsReboot
        windows_update_reboot_pending = [bool]$wuReboot
        pending_file_rename_present = [bool]$pendingRename
        child_environment = $childEnvironment
    }
}

Assert-DurationContract
Initialize-RawQualificationNative
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$preflight = Get-PreflightState -Repo $repo
$childEnvironmentEntries = [string[]]$preflight.child_environment.Entries

if ($ValidateOnly) {
    [pscustomobject][ordered]@{
        schema = "RawQualificationPreflightV1"
        status = "PASS"
        mode = $Mode
        parameters = [ordered]@{
            total_s = $TotalSeconds
            rotation_s = $RotationSeconds
            overlap_s = $OverlapSeconds
            segment_s = $SegmentSeconds
        }
        verifier_policy = [ordered]@{
            per_process_timeout_s = $IndependentVerifierTimeoutSeconds
            total_post_capture_timeout_s = $PostVerificationDeadlineSeconds
            maximum_artifact_bytes = [uint64]$MaximumVerifierArtifactBytes
        }
        coordinator_log_policy = [ordered]@{
            maximum_stdout_bytes = [uint64]$MaximumCampaignStdoutBytes
            maximum_stderr_bytes = [uint64]$MaximumCampaignStderrBytes
            child_stderr_events_allowed = [uint64]0
        }
        market_freshness_policy = [ordered]@{
            startup_grace_s = $MarketFreshnessStartupGraceSeconds
            deadline_s = $MarketFreshnessDeadlineSeconds
        }
        guardian_policy = [ordered]@{
            watchdog_ready_file = "watchdog-ready.json"
            watchdog_startup_deadline_s = [uint64]$GuardianWatchdogStartupDeadlineSeconds
            watchdog_deadline_s = [uint64]$GuardianWatchdogDeadlineSeconds
            host_telemetry_gap_deadline_s = [uint64]$HostTelemetryGapDeadlineSeconds
            maximum_dual_launch_skew_ms = [uint64]$MaximumDualLaunchSkewMilliseconds
            generation_terminal_deadline_s = [uint64]$GenerationTerminalDeadlineSeconds
            campaign_commit_deadline_s = [uint64]$CampaignCommitDeadlineSeconds
        }
        preflight = $preflight
    } | ConvertTo-Json -Depth 20
    return
}

$runId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") + "-dual-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$runRoot = Join-Path $preflight.output_base $runId
$jobName = $null
$jobHandle = [IntPtr]::Zero
$workloadJobName = $null
$workloadJobHandle = [IntPtr]::Zero
$executionStateArmed = $false
$mutex = $null
$mutexOwned = $false
$eventJournal = $null
$telemetryJournal = $null
$guardianPulseJournal = $null
$startupSha256 = $null
$processControlSha256 = $null
$bindingsSha256 = $null
$processRecords = @()
$states = @{}
$coordinatorProcessHandleOwners = [Collections.Generic.List[object]]::new()
$coordinatorLaunchTicks = @{}
$campaignResults = @()
$qualificationDeviationReasons = @()
$terminalWritten = $false
$failureMessage = $null
$failureContainment = $null
$failureContainmentSha256 = $null
$hostProbeSequence = [uint64]0
$telemetryProbeDirectory = $null
$watchdogLaunch = $null
$watchdogIdentity = $null
$watchdogStopPath = $null
$watchdogFailurePath = $null
$watchdogReadyPath = $null
$watchdogReadyStream = $null
$watchdogStdoutPath = $null
$watchdogStderrPath = $null
$watchdogResult = $null
$postCreateOutputValidation = $null
$lastObservedFreeGiB = [uint64]0
$lastGuardianPulseTick = [uint64]0
$monotonicOrigin = [Diagnostics.Stopwatch]::GetTimestamp()
$monotonicFrequency = [Diagnostics.Stopwatch]::Frequency
$runStopwatch = [Diagnostics.Stopwatch]::StartNew()
$verificationStopwatch = $null
$captureOriginTick = [uint64]0
$launchSkewTicks = [uint64]0
$launchSkewMilliseconds = [uint64]0

function Get-MonotonicTick {
    return [uint64]([Diagnostics.Stopwatch]::GetTimestamp() - $script:monotonicOrigin)
}

function Get-CaptureElapsedSeconds {
    param([uint64] $ObservedTick = 0)
    if ($script:captureOriginTick -eq 0) { return [double]0 }
    $current = if ($ObservedTick -eq 0) { Get-MonotonicTick } else { $ObservedTick }
    if ($current -lt $script:captureOriginTick) {
        throw "Observed monotonic tick precedes the dual-campaign capture origin."
    }
    return [double]($current - $script:captureOriginTick) / [double]$script:monotonicFrequency
}

function Get-CoordinatorElapsedSeconds {
    param(
        [Parameter(Mandatory = $true)] $State,
        [uint64] $ObservedTick = 0
    )
    if ($null -eq $State.PSObject.Properties['LaunchTick'] -or [uint64]$State.LaunchTick -eq 0) {
        throw "Coordinator state lacks its exact monotonic launch tick."
    }
    $current = if ($ObservedTick -eq 0) { Get-MonotonicTick } else { $ObservedTick }
    if ($current -lt [uint64]$State.LaunchTick) {
        throw "Observed monotonic tick precedes the coordinator launch tick."
    }
    return [double]($current - [uint64]$State.LaunchTick) / [double]$script:monotonicFrequency
}

function Close-CoordinatorNativeProcessHandle {
    param([Parameter(Mandatory = $true)] $HandleOwner)
    if ([bool]$HandleOwner.Closed) {
        if ([IntPtr]$HandleOwner.ProcessHandle -ne [IntPtr]::Zero -or
            [uint32]$HandleOwner.CloseCount -ne 1) {
            throw "Coordinator native process-handle ownership is internally inconsistent."
        }
        return
    }
    if ([IntPtr]$HandleOwner.ProcessHandle -eq [IntPtr]::Zero -or
        [uint32]$HandleOwner.CloseCount -ne 0) {
        throw "Coordinator native process handle was lost before its unique close."
    }
    if (-not [RawQualificationNative]::CloseHandle([IntPtr]$HandleOwner.ProcessHandle)) {
        throw "CloseHandle failed for retained $($HandleOwner.Symbol) coordinator process handle."
    }
    $HandleOwner.ProcessHandle = [IntPtr]::Zero
    $HandleOwner.Closed = $true
    $HandleOwner.CloseCount = [uint32]1
    return $true
}

function Assert-CoordinatorNativeLivenessAfterTick {
    param(
        [Parameter(Mandatory = $true)] $State,
        [Parameter(Mandatory = $true)] [uint64] $CandidateTick,
        [Parameter(Mandatory = $true)] [string] $Context
    )
    $owner = $State.ProcessHandleOwner
    if ($null -eq $owner -or
        [uint32]$owner.ProcessId -ne [uint32]$State.ProcessId -or
        [bool]$owner.Closed -or
        [IntPtr]$owner.ProcessHandle -eq [IntPtr]::Zero -or
        [uint32]$owner.CloseCount -ne 0) {
        throw "$($State.Symbol) lacks its retained original coordinator process handle during $Context."
    }
    $livenessCheckTick = Get-MonotonicTick
    if ($livenessCheckTick -lt $CandidateTick) {
        throw "$($State.Symbol) native liveness check preceded the candidate publication tick."
    }
    if ([RawQualificationNative]::WaitForProcessExit([IntPtr]$owner.ProcessHandle, 0)) {
        $exitCode = [int][RawQualificationNative]::GetProcessExitCode([IntPtr]$owner.ProcessHandle)
        throw "$($State.Symbol) original coordinator exited with code $exitCode before $Context."
    }
    return [uint64]$livenessCheckTick
}

function Write-LauncherEvent {
    param(
        [string] $Channel,
        $Payload,
        [uint64] $MonotonicTick = [uint64]::MaxValue
    )
    if ($null -ne $script:eventJournal) {
        $recordTick = if ($MonotonicTick -eq [uint64]::MaxValue) { Get-MonotonicTick } else { $MonotonicTick }
        $null = Add-RawQualificationJournalRecord `
            -Journal $script:eventJournal `
            -Schema "RawQualificationLauncherEventV1" `
            -Channel $Channel `
            -WallNs (Get-RawQualificationWallNs) `
            -MonotonicTick $recordTick `
            -Payload $Payload
    }
}

function Add-IndependentCampaignVerifiedResult {
    param(
        [Parameter(Mandatory = $true)] $CampaignResult,
        [scriptblock] $DurableEventWriter = {
            param([string] $Channel, $Payload)
            Write-LauncherEvent -Channel $Channel -Payload $Payload
        }
    )
    $symbolProperty = $CampaignResult.PSObject.Properties['symbol']
    $verifiersProperty = $CampaignResult.PSObject.Properties['independent_verifiers']
    if ($null -eq $symbolProperty -or $null -eq $verifiersProperty -or
        @("BTCUSDT", "ETHUSDT") -cnotcontains [string]$symbolProperty.Value) {
        throw "A verified campaign result lacks its exact symbol/verifier identity."
    }
    $symbol = [string]$symbolProperty.Value
    $verifiers = @($verifiersProperty.Value)
    $rustName = $symbol.ToLowerInvariant() + "-rust"
    $pythonName = $symbol.ToLowerInvariant() + "-python"
    $rust = @($verifiers | Where-Object { [string]$_.name -ceq $rustName })
    $python = @($verifiers | Where-Object { [string]$_.name -ceq $pythonName })
    if ($verifiers.Count -ne 2 -or $rust.Count -ne 1 -or $python.Count -ne 1 -or
        [string]$rust[0].report_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$python[0].report_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "$symbol verified result lacks its exact Rust/Python report receipts."
    }

    # The durable event is authoritative.  Only after it is fsync-acknowledged
    # may the terminal in-memory result prefix advance.  If publication fails,
    # the catch path therefore cannot claim an unreceipted campaign result.
    $null = & $DurableEventWriter "VERIFICATION" ([ordered]@{
        event = "INDEPENDENT_CAMPAIGN_VERIFIED"
        symbol = $symbol
        rust_report_sha256 = [string]$rust[0].report_sha256
        python_report_sha256 = [string]$python[0].report_sha256
    })
    $script:campaignResults += $CampaignResult
}

function Write-GuardianPulse {
    param([Parameter(Mandatory = $true)] [string] $Stage)
    if ($null -eq $script:guardianPulseJournal -or $script:guardianPulseJournal.Closed) { return }
    $tick = Get-MonotonicTick
    $null = Add-RawQualificationJournalRecord `
        -Journal $script:guardianPulseJournal `
        -Schema "RawQualificationGuardianPulseV1" `
        -Channel "GUARDIAN" `
        -WallNs (Get-RawQualificationWallNs) `
        -MonotonicTick $tick `
        -Payload ([ordered]@{
            event = "GUARDIAN_PULSE"
            stage = $Stage
            launcher_elapsed_ms = [uint64]$script:runStopwatch.ElapsedMilliseconds
            capture_elapsed_ms = if ($script:captureOriginTick -ne 0) {
                [uint64]((Get-CaptureElapsedSeconds) * 1000.0)
            } else { $null }
        })
    $script:lastGuardianPulseTick = $tick
}

function Ensure-CaptureDraining {
    param([Parameter(Mandatory = $true)] [uint64] $ObservedTick)
    if ($script:captureDrainingEventWritten) { return }
    if ($script:captureOriginTick -eq 0 -or $ObservedTick -lt $script:captureOriginTick) {
        throw "CAPTURE_DRAINING cannot be established before the exact dual-campaign origin."
    }
    $captureElapsed = Get-CaptureElapsedSeconds -ObservedTick $ObservedTick
    if ($captureElapsed -lt ($TotalSeconds - 5)) {
        throw "A campaign coordinator exited before CAPTURE_DRAINING became eligible."
    }
    if (-not (Test-RawQualificationDeadlineTicks `
        -ElapsedTicks ([long]($ObservedTick - $script:captureOriginTick)) `
        -TimeoutSeconds ([uint64]($TotalSeconds + $GenerationTerminalDeadlineSeconds)) `
        -Frequency ([long]$script:monotonicFrequency))) {
        throw "CAPTURE_DRAINING was first observed after the exact generation-terminal deadline."
    }
    $script:captureDrainingStartedTick = $ObservedTick
    Write-LauncherEvent -Channel "PROCESS" -Payload ([ordered]@{
        event = "CAPTURE_DRAINING_STARTED"
        generation_terminal_deadline_elapsed_s = [uint64]($TotalSeconds + $GenerationTerminalDeadlineSeconds)
    }) -MonotonicTick $ObservedTick
    Write-GuardianPulse -Stage "DRAINING"
    $script:captureDrainingEventWritten = $true
}

function Open-WatchdogReadyRetained {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $stream = $null
    try {
        try {
            # FileShare.Read is intentionally symmetric and restrictive.  While
            # the durable writer still has WRITE access this open fails with a
            # sharing/lock violation; after it closes, this retained reader
            # permits other readers but fences delete/rename/replacement.
            $stream = [IO.FileStream]::new(
                $Path,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read,
                4096,
                [IO.FileOptions]::SequentialScan)
        }
        catch [IO.IOException] {
            $win32Code = $_.Exception.HResult -band 0xffff
            if ($win32Code -eq 32 -or $win32Code -eq 33) { return $null }
            throw
        }
        $length = [int64]$stream.Length
        if ($length -le 0 -or $length -gt 65536) {
            throw "Independent guardian watchdog READY is empty or exceeds 64 KiB."
        }
        $bytes = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) { throw "Independent guardian watchdog READY ended before its frozen length." }
            $offset += $read
        }
        if ($bytes[$bytes.Length - 1] -ne 10) {
            throw "Independent guardian watchdog READY is not newline complete."
        }
        $value = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json -ErrorAction Stop
        $result = [pscustomobject][ordered]@{
            Stream = $stream
            Bytes = $bytes
            Value = $value
        }
        $stream = $null
        return $result
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-StateSummary {
    $summaries = @()
    foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
        if (-not $script:states.ContainsKey($symbol)) { continue }
        $state = $script:states[$symbol]
        $latestGeneration = @($state.GenerationCounters.Values | Sort-Object GenerationIndex -Descending | Select-Object -First 1)
        $latest = if ($latestGeneration.Count -eq 1) { $latestGeneration[0] } else { $null }
        $summaries += [pscustomobject][ordered]@{
            symbol = $symbol
            pid = $state.ProcessId
            campaign_id = $state.CampaignId
            campaign_elapsed_s = $state.LastCampaignElapsedS
            generations = $state.Generations
            active_processes = $state.ActiveProcesses
            handovers_proven = $state.HandoversProven
            depth_received = $state.DepthReceived
            depth_durable = $state.DepthDurable
            trade_received = $state.TradeReceived
            trade_durable = $state.TradeDurable
            latest_generation_index = if ($null -ne $latest) { [uint64]$latest.GenerationIndex } else { $null }
            latest_telemetry_mono_ns = if ($null -ne $latest) { [uint64]$latest.TelemetryMonoNs } else { $null }
            depth_last_socket_activity_mono_ns = if ($null -ne $latest) { [uint64]$latest.DepthLastSocketActivityMonoNs } else { $null }
            depth_last_market_message_mono_ns = if ($null -ne $latest) { [uint64]$latest.DepthLastMarketMessageMonoNs } else { $null }
            depth_market_message_age_ms = if ($null -ne $latest -and $latest.DepthLastMarketMessageMonoNs -ne 0) {
                [math]::Round(([double]($latest.TelemetryMonoNs - $latest.DepthLastMarketMessageMonoNs) / 1e6), 3)
            } else { $null }
            trade_last_socket_activity_mono_ns = if ($null -ne $latest) { [uint64]$latest.TradeLastSocketActivityMonoNs } else { $null }
            trade_last_market_message_mono_ns = if ($null -ne $latest) { [uint64]$latest.TradeLastMarketMessageMonoNs } else { $null }
            trade_market_message_age_ms = if ($null -ne $latest -and $latest.TradeLastMarketMessageMonoNs -ne 0) {
                [math]::Round(([double]($latest.TelemetryMonoNs - $latest.TradeLastMarketMessageMonoNs) / 1e6), 3)
            } else { $null }
            ready = [bool]$state.Ready
            exited = [bool]$state.Exited
        }
    }
    return $summaries
}

function Test-AllGenerationTerminalEvidence {
    if ($script:states.Count -ne 2) { return $false }
    foreach ($state in $script:states.Values) {
        if ($state.GenerationDurations.Count -lt 1 -or
            $state.GenerationTerminals.Count -ne $state.GenerationDurations.Count -or
            $state.GenerationExited.Count -ne $state.GenerationDurations.Count) {
            return $false
        }
    }
    return $true
}

function Test-StateDurableFailureDrainage {
    param($State)
    if (-not $State.FailureValidated -or $State.GenerationDurations.Count -lt 1 -or
        $State.GenerationExited.Count -ne $State.GenerationDurations.Count) {
        return $false
    }
    foreach ($generationKey in @($State.GenerationDurations.Keys)) {
        if (-not $State.GenerationExited.Contains([string]$generationKey)) { return $false }
        if ($State.GenerationTerminals.Contains([string]$generationKey)) { continue }
        if (-not $State.GenerationFailedExits.Contains([string]$generationKey) -or
            -not $State.GenerationDisconnects.Contains([string]$generationKey)) {
            return $false
        }
    }
    return $true
}

function Invoke-BoundedHostTelemetryProbe {
    $script:hostProbeSequence = [uint64]($script:hostProbeSequence + 1)
    $probeName = "host-{0:D6}" -f $script:hostProbeSequence
    $invocation = Invoke-BoundedQualificationJsonProcess `
        -JobHandle $script:jobHandle `
        -Name $probeName `
        -Executable $preflight.powershell_executable `
        -Arguments ([string[]]@(
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $preflight.telemetry_probe_script,
            "-HelperPath", $preflight.helper_script,
            "-DriveDeviceId", $preflight.drive_device_id,
            "-RootProcessId", $PID.ToString([Globalization.CultureInfo]::InvariantCulture)
        )) `
        -WorkingDirectory $script:repo `
        -OutputDirectory $script:telemetryProbeDirectory `
        -EnvironmentEntries $script:childEnvironmentEntries `
        -TimeoutSeconds $HostTelemetryProbeTimeoutSeconds `
        -ProgressAction { Write-GuardianPulse -Stage "HOST_TELEMETRY_PROVIDER" }
    if ($invocation.value.schema -ne "RawQualificationTelemetryProbeV1" -or
        @($invocation.value.conflicting_collectors).Count -ne 0) {
        throw "Bounded runtime host telemetry returned an unexpected schema/payload."
    }
    $probePrefix = [IO.Path]::GetFullPath($script:telemetryProbeDirectory).TrimEnd('\') + '\'
    foreach ($path in @($invocation.stdout_path, $invocation.stderr_path)) {
        $resolved = [IO.Path]::GetFullPath([string]$path)
        if (-not $resolved.StartsWith($probePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Runtime probe evidence path escaped its dedicated directory."
        }
    }
    # The provider must publish its complete JSON observation before the
    # launcher evaluates health.  If this assertion fails, stdout remains as
    # create-only forensic evidence instead of being deleted by normal cleanup.
    try { Assert-RawQualificationClockHealthy -Clock $invocation.value.clock }
    catch {
        $providerEvidence = [ordered]@{
            stdout_path = [IO.Path]::GetRelativePath($script:runRoot, [string]$invocation.stdout_path).Replace('\', '/')
            stdout_bytes = [uint64]$invocation.stdout_bytes
            stdout_sha256 = [string]$invocation.stdout_sha256
            stderr_path = [IO.Path]::GetRelativePath($script:runRoot, [string]$invocation.stderr_path).Replace('\', '/')
            stderr_bytes = [uint64]$invocation.stderr_bytes
            stderr_sha256 = [string]$invocation.stderr_sha256
        } | ConvertTo-Json -Depth 5 -Compress
        throw "$($_.Exception.Message); provider_evidence=$providerEvidence"
    }
    $execution = [pscustomobject][ordered]@{
        pid = [uint32]$invocation.pid
        command_line_sha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes([string]$invocation.command_line))
        resume_qpc_timestamp = [long]$invocation.resume_qpc_timestamp
        elapsed_qpc_ticks = [long]$invocation.elapsed_qpc_ticks
        monotonic_frequency = [long]$invocation.monotonic_frequency
        job_membership = [string]$invocation.job_membership
        parent_exit_observed_qpc_timestamp = [long]$invocation.parent_exit_observed_qpc_timestamp
        descendant_drain_elapsed_qpc_ticks = [long]$invocation.descendant_drain_elapsed_qpc_ticks
        descendant_drain_elapsed_ms = [uint64]$invocation.descendant_drain_elapsed_ms
        descendant_drain_active_processes = [uint32]$invocation.descendant_drain_active_processes
        timeout_s = [uint64]$invocation.timeout_s
        elapsed_ms = [uint64]$invocation.elapsed_ms
        stdout_bytes = [uint64]$invocation.stdout_bytes
        stdout_sha256 = [string]$invocation.stdout_sha256
        stderr_bytes = [uint64]$invocation.stderr_bytes
        stderr_sha256 = [string]$invocation.stderr_sha256
    }
    foreach ($path in @($invocation.stdout_path, $invocation.stderr_path)) {
        $resolved = [IO.Path]::GetFullPath([string]$path)
        Remove-Item -LiteralPath $resolved -Force -ErrorAction Stop
    }
    return [pscustomobject][ordered]@{ telemetry = $invocation.value; execution = $execution }
}

function Get-BoundedPythonRuntimeFingerprint {
    Write-GuardianPulse -Stage "PYTHON_RUNTIME_FINGERPRINT"
    $script:hostProbeSequence = [uint64]($script:hostProbeSequence + 1)
    $probeName = "python-runtime-{0:D6}" -f $script:hostProbeSequence
    $invocation = Invoke-BoundedQualificationJsonProcess `
        -JobHandle $script:jobHandle `
        -Name $probeName `
        -Executable $preflight.powershell_executable `
        -Arguments ([string[]]@(
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $preflight.python_runtime_fingerprint_script,
            "-HelperPath", $preflight.helper_script,
            "-PythonExecutable", $preflight.python
        )) `
        -WorkingDirectory $script:repo `
        -OutputDirectory $script:telemetryProbeDirectory `
        -EnvironmentEntries $script:childEnvironmentEntries `
        -TimeoutSeconds $PythonRuntimeFingerprintTimeoutSeconds `
        -ProgressAction { Write-GuardianPulse -Stage "PYTHON_RUNTIME_FINGERPRINT" }
    if ($invocation.value.schema -ne "RawQualificationPythonRuntimeFingerprintV1") {
        throw "Bounded Python runtime fingerprint returned an unexpected schema."
    }
    foreach ($path in @($invocation.stdout_path, $invocation.stderr_path)) {
        $resolved = [IO.Path]::GetFullPath([string]$path)
        $prefix = [IO.Path]::GetFullPath($script:telemetryProbeDirectory).TrimEnd('\') + '\'
        if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Python runtime fingerprint cleanup target escaped its dedicated directory."
        }
        Remove-Item -LiteralPath $resolved -Force -ErrorAction Stop
    }
    return $invocation.value.runtime
}

function Write-HostTelemetrySample {
    param(
        $Probe,
        [scriptblock] $PreCommitAction
    )
    $probe = if ($PSBoundParameters.ContainsKey("Probe")) { $Probe } else { Invoke-BoundedHostTelemetryProbe }
    if ($null -eq $probe -or $null -eq $probe.telemetry -or $null -eq $probe.execution) {
        throw "Host telemetry publication requires one complete bounded provider result."
    }
    $clock = $probe.telemetry.clock
    Assert-RawQualificationClockHealthy -Clock $clock
    $disk = $probe.telemetry.disk
    $freeGiB = [math]::Floor([double]$disk.free_bytes / 1GB)
    $script:lastObservedFreeGiB = [uint64]$freeGiB
    $captureElapsedSeconds = Get-CaptureElapsedSeconds
    $projectedRemainingGiB = Get-ConservativeRemainingProjectionGiB -ElapsedSeconds $captureElapsedSeconds
    $runtimeRequiredGiB = [uint64]$preflight.persistent_reserve_gib + [uint64]$projectedRemainingGiB
    if ($freeGiB -lt $runtimeRequiredGiB) {
        throw "Free storage fell to $freeGiB GiB; persistent reserve plus conservative remaining projection requires $runtimeRequiredGiB GiB."
    }
    $collectorProcesses = @($probe.telemetry.collector_processes)
    if ($PSBoundParameters.ContainsKey("PreCommitAction")) {
        $null = & $PreCommitAction
    }
    $payload = [ordered]@{
        monotonic_frequency = [uint64]$script:monotonicFrequency
        launcher_elapsed_ms = [uint64]$script:runStopwatch.ElapsedMilliseconds
        capture_elapsed_ms = [uint64]($captureElapsedSeconds * 1000.0)
        clock = $clock
        disk = $disk
        disk_persistent_reserve_gib = [uint64]$preflight.persistent_reserve_gib
        disk_projected_remaining_gib = [uint64]$projectedRemainingGiB
        disk_required_free_gib = $runtimeRequiredGiB
        network = $probe.telemetry.network
        collector_processes = $collectorProcesses
        provider_execution = $probe.execution
        campaigns = @(Get-StateSummary)
    }
    $recordIndex = [uint64]$script:telemetryJournal.NextIndex
    $recordTick = Get-MonotonicTick
    $recordSha256 = Add-RawQualificationJournalRecord `
        -Journal $script:telemetryJournal `
        -Schema "RawQualificationHostTelemetryRecordV1" `
        -Channel "HOST" `
        -WallNs (Get-RawQualificationWallNs) `
        -MonotonicTick $recordTick `
        -Payload $payload
    if ([uint64]$script:telemetryJournal.NextIndex -ne ($recordIndex + 1) -or
        [string]$script:telemetryJournal.Previous -ne [string]$recordSha256) {
        throw "Host telemetry journal did not advance to the exact durable receipt."
    }
    return [pscustomobject][ordered]@{
        record_index = $recordIndex
        record_sha256 = [string]$recordSha256
        monotonic_tick = [uint64]$recordTick
    }
}

function Test-StateReady {
    param($State)
    return $State.ProcessStarted -and
        $State.TransportStreams.Contains("depth") -and
        $State.TransportStreams.Contains("trade") -and
        $State.SnapshotDurable -and
        $State.SemanticHeartbeatSeen -and
        $State.StartupValidated
}

function Assert-DualReadinessPublicationCurrent {
    if ([RawQualificationNative]::WaitForProcessExit($script:watchdogLaunch.ProcessHandle, 0)) {
        $watchdogExit = [int][RawQualificationNative]::GetProcessExitCode($script:watchdogLaunch.ProcessHandle)
        throw "Independent guardian watchdog exited with code $watchdogExit before readiness publication."
    }
    if (Test-Path -LiteralPath $script:watchdogFailurePath -PathType Leaf) {
        throw "Independent guardian watchdog fenced the Job before readiness publication."
    }
    if ([uint64](Get-Item -LiteralPath $script:watchdogStdoutPath -ErrorAction Stop).Length -ne 0 -or
        [uint64](Get-Item -LiteralPath $script:watchdogStderrPath -ErrorAction Stop).Length -ne 0) {
        throw "Independent guardian watchdog emitted unexpected output before readiness publication."
    }

    foreach ($state in $script:states.Values) {
        $null = Assert-StateCoordinatorLogsBounded -State $state
        Read-StateOutput -State $state
        Assert-CampaignStartup -State $state
        Read-StateCampaignEvents -State $state
        Assert-StateCampaignFailureContract -State $state
        $null = Assert-StateCoordinatorLogsBounded -State $state
        $state.Ready = Test-StateReady -State $state
    }

    $observedTick = Get-MonotonicTick
    foreach ($state in $script:states.Values) {
        $null = Assert-CoordinatorNativeLivenessAfterTick `
            -State $state `
            -CandidateTick $observedTick `
            -Context "readiness publication"
        if (-not $state.Ready -or [uint64]$state.Generations -lt 1 -or [uint64]$state.ActiveProcesses -lt 1) {
            throw "$($state.Symbol) lost semantic readiness during the readiness telemetry provider probe."
        }
        if ($state.LastHeartbeatTick -eq 0 -or
            ([double]($observedTick - $state.LastHeartbeatTick) / $script:monotonicFrequency) -gt $HeartbeatDeadlineSeconds) {
            throw "$($state.Symbol) campaign heartbeat was not current at readiness publication."
        }
        if ($state.LastSemanticTick -eq 0 -or
            ([double]($observedTick - $state.LastSemanticTick) / $script:monotonicFrequency) -gt $SemanticDeadlineSeconds) {
            throw "$($state.Symbol) durable child heartbeat was not current at readiness publication."
        }
    }
    if ([RawQualificationNative]::WaitForProcessExit($script:watchdogLaunch.ProcessHandle, 0) -or
        (Test-Path -LiteralPath $script:watchdogFailurePath -PathType Leaf)) {
        throw "Independent guardian watchdog lost authority during readiness revalidation."
    }
    return [uint64]$observedTick
}

function Assert-StateCoordinatorLogsBounded {
    param([Parameter(Mandatory = $true)] $State)
    $stdoutLength = [uint64](Get-Item -LiteralPath $State.StdoutState.Path -ErrorAction Stop).Length
    $stderrLength = [uint64](Get-Item -LiteralPath $State.StderrPath -ErrorAction Stop).Length
    if ($stdoutLength -gt [uint64]$MaximumCampaignStdoutBytes) {
        throw "$($State.Symbol) coordinator stdout exceeded the $MaximumCampaignStdoutBytes-byte hard limit."
    }
    if ($stderrLength -gt [uint64]$MaximumCampaignStderrBytes) {
        throw "$($State.Symbol) coordinator wrote unexpected stderr ($stderrLength bytes)."
    }
    return [pscustomobject]@{ stdout_bytes = $stdoutLength; stderr_bytes = $stderrLength }
}

function Assert-GenerationClockUnambiguous {
    param([Parameter(Mandatory = $true)] [string] $GenerationDirectory)
    $generationPath = [IO.Path]::GetFullPath($GenerationDirectory)
    $runPrefix = [IO.Path]::GetFullPath($script:runRoot).TrimEnd('\') + '\'
    if (-not $generationPath.StartsWith($runPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Generation telemetry escaped the qualification evidence root."
    }
    $telemetryPath = Join-Path $generationPath "telemetry.jsonl"
    if (-not (Test-Path -LiteralPath $telemetryPath -PathType Leaf)) {
        throw "Generation lacks telemetry.jsonl: $generationPath"
    }
    $stream = [IO.FileStream]::new($telemetryPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -eq 0) { throw "Generation clock telemetry is empty: $generationPath" }
        $null = $stream.Seek(-1, [IO.SeekOrigin]::End)
        if ($stream.ReadByte() -ne 10) { throw "Generation clock telemetry has a partial terminal record: $generationPath" }
        $null = $stream.Seek(0, [IO.SeekOrigin]::Begin)
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $true, 65536, $true)
        try {
            $expectedIndex = [uint64]0
            while ($null -ne ($line = $reader.ReadLine())) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $record = $line | ConvertFrom-Json -ErrorAction Stop
                if ($record.schema -ne "CaptureTelemetryV1" -or
                    [uint64]$record.record_index -ne $expectedIndex -or
                    $record.clock.quality -ne "HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND" -or
                    [int]$record.clock.leap_indicator -ne 0 -or
                    [int]$record.clock.stratum -lt 1 -or
                    [int]$record.clock.stratum -gt 15 -or
                    [string]::IsNullOrWhiteSpace([string]$record.clock.last_successful_sync)) {
                    throw "Generation contains ambiguous or invalid clock telemetry at record ${expectedIndex}: $generationPath"
                }
                $expectedIndex = [uint64]($expectedIndex + 1)
            }
            if ($expectedIndex -eq 0) { throw "Generation clock telemetry has no records: $generationPath" }
            return $expectedIndex
        }
        finally { $reader.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Sync-RawQualificationExistingFile {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::Read,
        4096,
        [IO.FileOptions]::WriteThrough)
    try { $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Invoke-BoundedRawCampaignVerifier {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [string] $Executable,
        [Parameter(Mandatory = $true)] [string[]] $Arguments,
        [Parameter(Mandatory = $true)] [string] $OutputDirectory,
        [Parameter(Mandatory = $true)] [string] $ReportPath,
        [Parameter(Mandatory = $true)] [int] $TimeoutSeconds,
        [Parameter(Mandatory = $true)] [uint64] $GlobalBudgetComputedMonotonicTick
    )
    if ($script:independentVerificationStartedTick -eq 0 -or
        $GlobalBudgetComputedMonotonicTick -lt $script:independentVerificationStartedTick) {
        throw "$Name lacks a valid independent-verification budget origin."
    }
    $globalElapsedAtBudgetSeconds = [double]($GlobalBudgetComputedMonotonicTick - $script:independentVerificationStartedTick) /
        [double]$script:monotonicFrequency
    $remainingAtBudgetSeconds = [int][math]::Floor(
        $PostVerificationDeadlineSeconds - $globalElapsedAtBudgetSeconds)
    $expectedTimeoutSeconds = if ($remainingAtBudgetSeconds -ge 60) {
        [int][math]::Min($IndependentVerifierTimeoutSeconds, $remainingAtBudgetSeconds)
    }
    else { 0 }
    if ($TimeoutSeconds -ne $expectedTimeoutSeconds) {
        throw "$Name timeout is not the exact min(per-process, remaining-global) budget."
    }
    $stdoutPath = Join-Path $OutputDirectory ($Name + ".stdout.log")
    $stderrPath = Join-Path $OutputDirectory ($Name + ".stderr.log")
    $executionPath = Join-Path $OutputDirectory ($Name + ".execution.json")
    if ($script:jobHandle -eq [IntPtr]::Zero -or
        $script:workloadJobHandle -eq [IntPtr]::Zero) {
        throw "$Name lacks its exact outer/workload Job containment context."
    }
    $launch = [RawQualificationNative]::StartSuspendedInJobsRetainedWithEnvironment(
        $script:jobHandle,
        $script:workloadJobHandle,
        $Executable,
        $Arguments,
        $script:repo,
        $stdoutPath,
        $stderrPath,
        $script:childEnvironmentEntries)
    $verifierPid = [uint32]$launch.ProcessId
    $identity = [pscustomobject][ordered]@{
        pid = $verifierPid
        creation_time_utc = [DateTime]::FromFileTimeUtc([int64]$launch.CreationFileTimeUtc).ToString("o")
        executable_path = [IO.Path]::GetFullPath($Executable)
        executable_sha256 = Get-RawQualificationSha256File -Path $Executable
        command_line = [string]$launch.ExactCommandLine
        identity_source = "CREATE_PROCESS_SUSPENDED_HANDLE"
    }
    $resumeQpcTimestamp = [long]$launch.ResumeQpcTimestamp
    $finalVerifierElapsedTicks = [long]0
    $parentExitObservedQpcTimestamp = [long]0
    $failure = $null
    $timedOut = $false
    $lastVerifierTelemetry = [Diagnostics.Stopwatch]::StartNew()
    $lastVerifierGuardianPulse = [Diagnostics.Stopwatch]::StartNew()
    Write-LauncherEvent -Channel "VERIFICATION" -Payload ([ordered]@{ event = "INDEPENDENT_VERIFIER_STARTED"; name = $Name; pid = $verifierPid })
    while (-not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 1000)) {
        foreach ($path in @($stdoutPath, $stderrPath, $ReportPath)) {
            if ((Test-Path -LiteralPath $path -PathType Leaf) -and
                (Get-Item -LiteralPath $path).Length -gt $MaximumVerifierArtifactBytes) {
                $failure = "Verifier artifact exceeded $MaximumVerifierArtifactBytes bytes: $path"
                break
            }
        }
        if ($null -ne $failure) { break }
        if ($lastVerifierTelemetry.Elapsed.TotalSeconds -ge $TelemetryIntervalSeconds) {
            $null = Write-HostTelemetrySample
            $lastVerifierTelemetry.Restart()
        }
        if ($lastVerifierGuardianPulse.Elapsed.TotalSeconds -ge 5) {
            Write-GuardianPulse -Stage "INDEPENDENT_VERIFICATION"
            $lastVerifierGuardianPulse.Restart()
        }
        $verifierElapsedTicks = Get-RawQualificationElapsedQpcTicks -ResumeQpcTimestamp $resumeQpcTimestamp
        if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $verifierElapsedTicks `
            -TimeoutSeconds ([uint64]$TimeoutSeconds))) {
            $timedOut = $true
            $failure = "Verifier exceeded its $TimeoutSeconds second deadline."
            break
        }
        if ($null -ne $script:verificationStopwatch -and
            $script:verificationStopwatch.Elapsed.TotalSeconds -gt $PostVerificationDeadlineSeconds) {
            $timedOut = $true
            $failure = "Global post-capture verification deadline expired."
            break
        }
    }
    if ($null -eq $failure) {
        $parentExitObservedQpcTimestamp = [long][Diagnostics.Stopwatch]::GetTimestamp()
        $finalVerifierElapsedTicks = [long]($parentExitObservedQpcTimestamp - $resumeQpcTimestamp)
        if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $finalVerifierElapsedTicks `
            -TimeoutSeconds ([uint64]$TimeoutSeconds))) {
            $timedOut = $true
            $failure = "Verifier exceeded its $TimeoutSeconds second deadline at exact process exit."
        }
        elseif ($null -ne $script:verificationStopwatch -and
            -not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks $script:verificationStopwatch.ElapsedTicks `
                -TimeoutSeconds ([uint64]$PostVerificationDeadlineSeconds))) {
            $timedOut = $true
            $failure = "Global post-capture verification deadline expired at exact process exit."
        }
    }
    if ($null -ne $failure) {
        $null = [RawQualificationNative]::TerminateJobObject($script:jobHandle, 0xEE03)
        $null = [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 10000)
    }
    $exited = [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 0)
    if ($finalVerifierElapsedTicks -eq 0) {
        $finalVerifierElapsedTicks = Get-RawQualificationElapsedQpcTicks -ResumeQpcTimestamp $resumeQpcTimestamp
    }
    $exitCode = if ($exited) { [int][RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle) } else { $null }
    if ($exited -and $parentExitObservedQpcTimestamp -eq 0) {
        $parentExitObservedQpcTimestamp = [long][Diagnostics.Stopwatch]::GetTimestamp()
    }
    $descendantDrainElapsedTicks = [long]0
    if ($null -eq $failure -and $exited) {
        $previousWorkloadActiveProcesses = $null
        while ($true) {
            if ([RawQualificationNative]::WaitForProcessExit($script:watchdogLaunch.ProcessHandle, 0)) {
                $failure = "The exact watchdog exited before verifier workload-drain observation."
                break
            }
            $workloadActiveProcesses =
                [uint32][RawQualificationNative]::GetActiveProcessCount($script:workloadJobHandle)
            $descendantDrainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $parentExitObservedQpcTimestamp)
            if ([RawQualificationNative]::WaitForProcessExit($script:watchdogLaunch.ProcessHandle, 0)) {
                $failure = "The exact watchdog exited during verifier workload-drain observation."
                break
            }
            if ($null -ne $previousWorkloadActiveProcesses -and
                $workloadActiveProcesses -gt [uint32]$previousWorkloadActiveProcesses) {
                $failure = "Verifier workload active-process count increased after its parent exited."
                break
            }
            $previousWorkloadActiveProcesses = [uint32]$workloadActiveProcesses
            if (-not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks $descendantDrainElapsedTicks `
                -TimeoutSeconds 10)) {
                break
            }
            if ($workloadActiveProcesses -eq 0) { break }
            Start-Sleep -Milliseconds 100
        }
        $descendantDrainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $parentExitObservedQpcTimestamp)
        if ($null -eq $failure -and
            ([RawQualificationNative]::GetActiveProcessCount($script:workloadJobHandle) -ne 0 -or
            -not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks $descendantDrainElapsedTicks `
                -TimeoutSeconds 10) -or
            [RawQualificationNative]::WaitForProcessExit($script:watchdogLaunch.ProcessHandle, 0))) {
            $failure = "Verifier descendants did not drain the exact workload Job before artifact sealing."
        }
        if ($null -ne $failure) {
            $null = [RawQualificationNative]::TerminateJobObject($script:jobHandle, 0xEE05)
        }
    }
    $null = [RawQualificationNative]::CloseHandle($launch.ProcessHandle)
    foreach ($path in @($stdoutPath, $stderrPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Verifier log is absent: $path" }
    }
    $stdoutLength = [uint64](Get-Item -LiteralPath $stdoutPath).Length
    $stderrLength = [uint64](Get-Item -LiteralPath $stderrPath).Length
    $reportPresent = [bool](Test-Path -LiteralPath $ReportPath -PathType Leaf)
    $reportLength = if ($reportPresent) { [uint64](Get-Item -LiteralPath $ReportPath).Length } else { [uint64]0 }
    if ($null -eq $failure -and -not $exited) {
        $failure = "Verifier did not reach a terminal process state."
    }
    if ($null -eq $failure -and $stdoutLength -gt $MaximumVerifierArtifactBytes) {
        $failure = "Verifier stdout exceeded the bounded artifact size after process exit."
    }
    if ($null -eq $failure -and $stderrLength -gt $MaximumVerifierArtifactBytes) {
        $failure = "Verifier stderr exceeded the bounded artifact size after process exit."
    }
    if ($null -eq $failure -and $reportLength -gt $MaximumVerifierArtifactBytes) {
        $failure = "Verifier report exceeded the bounded artifact size after process exit."
    }
    if ($null -eq $failure -and $exitCode -eq 0 -and $stderrLength -ne 0) {
        $failure = "Verifier wrote unexpected stderr despite a zero exit code."
    }
    if ($null -eq $failure -and $exitCode -eq 0 -and (-not $reportPresent -or $reportLength -eq 0)) {
        $failure = "Verifier exited zero without a non-empty new report."
    }
    if ($null -eq $failure -and $exitCode -eq 0) {
        try { Sync-RawQualificationExistingFile -Path $ReportPath }
        catch { $failure = "Verifier report could not be durably synchronized: $($_.Exception.Message)" }
    }
    $stdoutSha256 = if ($stdoutLength -le $MaximumVerifierArtifactBytes) { Get-RawQualificationSha256File -Path $stdoutPath } else { $null }
    $stderrSha256 = if ($stderrLength -le $MaximumVerifierArtifactBytes) { Get-RawQualificationSha256File -Path $stderrPath } else { $null }
    $reportSha256 = if ($reportPresent -and $reportLength -le $MaximumVerifierArtifactBytes) { Get-RawQualificationSha256File -Path $ReportPath } else { $null }
    $execution = [ordered]@{
        schema = "RawQualificationVerifierExecutionV1"
        name = $Name
        pid = [uint32]$verifierPid
        creation_time_utc = $identity.creation_time_utc
        executable_path = $identity.executable_path
        executable_sha256 = $identity.executable_sha256
        command_line = $identity.command_line
        global_budget_computed_monotonic_tick = $GlobalBudgetComputedMonotonicTick
        resume_qpc_timestamp = [long]$resumeQpcTimestamp
        elapsed_qpc_ticks = [long]$finalVerifierElapsedTicks
        monotonic_frequency = [long][Diagnostics.Stopwatch]::Frequency
        parent_exit_observed_qpc_timestamp = [long]$parentExitObservedQpcTimestamp
        descendant_drain_elapsed_qpc_ticks = [long]$descendantDrainElapsedTicks
        descendant_drain_elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds -ElapsedTicks $descendantDrainElapsedTicks
        timeout_s = [uint64]$TimeoutSeconds
        elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds -ElapsedTicks $finalVerifierElapsedTicks
        timed_out = [bool]$timedOut
        exit_code = $exitCode
        failure = $failure
        stdout_file = [IO.Path]::GetFileName($stdoutPath)
        stdout_bytes = $stdoutLength
        stdout_sha256 = $stdoutSha256
        stderr_file = [IO.Path]::GetFileName($stderrPath)
        stderr_bytes = $stderrLength
        stderr_sha256 = $stderrSha256
        report_file = [IO.Path]::GetFileName($ReportPath)
        report_present = $reportPresent
        report_bytes = $reportLength
        report_sha256 = $reportSha256
    }
    $executionSha256 = Write-RawQualificationDurableNewJson -Path $executionPath -Value $execution
    if ($null -ne $failure -or $exitCode -ne 0) {
        throw "$Name failed; exact execution evidence: $executionPath"
    }
    Write-LauncherEvent -Channel "VERIFICATION" -Payload ([ordered]@{
        event = "INDEPENDENT_VERIFIER_COMPLETED"
        name = $Name
        pid = $verifierPid
        exit_code = $exitCode
        stderr_bytes = $stderrLength
        execution_sha256 = $executionSha256
    })
    return [pscustomobject][ordered]@{
        name = $Name
        pid = [uint32]$verifierPid
        creation_time_utc = [string]$identity.creation_time_utc
        command_line_sha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes([string]$identity.command_line))
        global_budget_computed_monotonic_tick = $GlobalBudgetComputedMonotonicTick
        resume_qpc_timestamp = [long]$resumeQpcTimestamp
        elapsed_qpc_ticks = [long]$finalVerifierElapsedTicks
        monotonic_frequency = [long][Diagnostics.Stopwatch]::Frequency
        parent_exit_observed_qpc_timestamp = [long]$parentExitObservedQpcTimestamp
        descendant_drain_elapsed_qpc_ticks = [long]$descendantDrainElapsedTicks
        descendant_drain_elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds -ElapsedTicks $descendantDrainElapsedTicks
        execution_file = [IO.Path]::GetFileName($executionPath)
        execution_sha256 = $executionSha256
        report_file = [IO.Path]::GetFileName($ReportPath)
        report_bytes = [uint64](Get-Item -LiteralPath $ReportPath).Length
        report_sha256 = Get-RawQualificationSha256File -Path $ReportPath
        stdout_file = [IO.Path]::GetFileName($stdoutPath)
        stdout_bytes = $stdoutLength
        stdout_sha256 = $execution.stdout_sha256
        stderr_file = [IO.Path]::GetFileName($stderrPath)
        stderr_bytes = $stderrLength
        stderr_sha256 = $execution.stderr_sha256
        exit_code = $exitCode
        elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds -ElapsedTicks $finalVerifierElapsedTicks
    }
}

function Read-StateOutput {
    param($State)
    foreach ($line in @(Read-RawQualificationNewUtf8Lines -State $State.StdoutState)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $value = $line | ConvertFrom-Json -ErrorAction Stop }
        catch { continue }
        if ($value.event -ne "CAMPAIGN_HEARTBEAT") { continue }
        $heartbeatFailed = [bool]$value.failure
        $expectedProperties = if ($heartbeatFailed) {
            @("event", "campaign_id", "elapsed_s", "generations", "active_processes",
                "handovers_proven", "failure", "failure_reason", "failure_record_sha256")
        }
        else {
            @("event", "campaign_id", "elapsed_s", "generations", "active_processes",
                "handovers_proven", "failure")
        }
        $actualProperties = @($value.PSObject.Properties.Name)
        if ($actualProperties.Count -ne $expectedProperties.Count) {
            throw "$($State.Symbol) campaign heartbeat has an invalid property set."
        }
        for ($propertyIndex = 0; $propertyIndex -lt $expectedProperties.Count; $propertyIndex++) {
            if ([string]$actualProperties[$propertyIndex] -cne [string]$expectedProperties[$propertyIndex]) {
                throw "$($State.Symbol) campaign heartbeat has invalid canonical property order."
            }
        }
        $campaignId = [string]$value.campaign_id
        if ([string]::IsNullOrWhiteSpace($campaignId) -or
            ($null -ne $State.CampaignId -and $State.CampaignId -ne $campaignId)) {
            throw "$($State.Symbol) campaign identity changed or is empty."
        }
        if ([uint64]$value.elapsed_s -lt [uint64]$State.LastCampaignElapsedS -or
            [uint64]$value.generations -lt 1 -or
            ([uint64]$value.active_processes -lt 1 -and -not $heartbeatFailed -and
             (Get-CaptureElapsedSeconds) -lt ($TotalSeconds - 5))) {
            throw "$($State.Symbol) campaign heartbeat regressed or has no active generation."
        }
        $State.CampaignId = $campaignId
        $State.CampaignDirectory = Join-Path $script:runRoot $campaignId
        $campaignParent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($State.CampaignDirectory))
        if (-not $campaignParent.Equals([IO.Path]::GetFullPath($script:runRoot).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw "$($State.Symbol) campaign directory escaped the common evidence root."
        }
        $State.EventState.Path = Join-Path $State.CampaignDirectory "campaign-events.jsonl"
        $State.LastHeartbeatTick = Get-MonotonicTick
        $State.LastCampaignElapsedS = [uint64]$value.elapsed_s
        $State.Generations = [uint64]$value.generations
        $State.ActiveProcesses = [uint64]$value.active_processes
        $State.HandoversProven = [uint64]$value.handovers_proven
        if ($heartbeatFailed) {
            if (-not (Test-RawQualificationJsonString -Value $value.failure_reason) -or
                [string]::IsNullOrWhiteSpace([string]$value.failure_reason) -or
                -not (Test-RawQualificationJsonSha256 -Value $value.failure_record_sha256)) {
                throw "$($State.Symbol) failure heartbeat lacks an exact reason and durable record digest."
            }
            if (($null -ne $State.PendingFailureReason -and
                 [string]$State.PendingFailureReason -cne [string]$value.failure_reason) -or
                ($null -ne $State.PendingFailureRecordSha256 -and
                 [string]$State.PendingFailureRecordSha256 -cne [string]$value.failure_record_sha256)) {
                throw "$($State.Symbol) failure heartbeat changed its first durable cause."
            }
            $State.PendingFailureReason = [string]$value.failure_reason
            $State.PendingFailureRecordSha256 = [string]$value.failure_record_sha256
        }
    }
}

function Assert-StateCampaignFailureContract {
    param($State)
    if ($null -eq $State.PendingFailureReason -and $null -eq $State.JournalFailureReason) {
        return
    }
    if ($null -eq $State.PendingFailureReason -or $null -eq $State.JournalFailureReason) {
        return $false
    }
    if ([string]$State.PendingFailureReason -cne [string]$State.JournalFailureReason -or
        [string]$State.PendingFailureRecordSha256 -cne [string]$State.JournalFailureRecordSha256) {
        throw "$($State.Symbol) failure heartbeat is not bound to its exact durable CAMPAIGN_FAILED record."
    }
    $State.FailureValidated = $true
    if ([uint64]$State.FailureFirstObservedTick -eq 0) {
        $State.FailureFirstObservedTick = Get-MonotonicTick
    }
    return
}

function Assert-CampaignStartup {
    param($State)
    if ($State.StartupValidated -or $null -eq $State.CampaignDirectory) { return }
    $path = Join-Path $State.CampaignDirectory "campaign-startup.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
    $startup = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($startup.schema -ne "RawCampaignStartupV1" -or
        $startup.campaign_id -ne $State.CampaignId -or
        $startup.symbol -ne $State.Symbol -or
        [uint32]$startup.process_id -ne [uint32]$State.ProcessId -or
        [uint64]$startup.total_duration_s -ne [uint64]$TotalSeconds -or
        [uint64]$startup.rotation_s -ne [uint64]$RotationSeconds -or
        [uint64]$startup.overlap_s -ne [uint64]$OverlapSeconds -or
        [uint64]$startup.segment_s -ne [uint64]$SegmentSeconds -or
        $startup.executable_sha256 -ne $preflight.campaign_executable_sha256 -or
        $startup.capture_executable_sha256 -ne $preflight.capture_executable_sha256 -or
        $startup.public_config_sha256 -ne $preflight.public_config_sha256 -or
        $startup.spec_revision -ne $ExpectedSpecRevision -or
        $startup.credentials -ne "NONE" -or
        $startup.order_entry -ne "ABSENT") {
        throw "$($State.Symbol) campaign startup contract differs from the launcher preflight."
    }
    $State.StartupValidated = $true
    $State.CampaignStartupSha256 = Get-RawQualificationSha256File -Path $path
}

function Read-StateCampaignEvents {
    param($State)
    if ($null -eq $State.CampaignDirectory) { return }
    foreach ($line in @(Read-RawQualificationNewUtf8Lines -State $State.EventState)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $envelope = $line | ConvertFrom-Json -ErrorAction Stop
        $bodyJson = $envelope.body | ConvertTo-Json -Depth 100 -Compress
        $actualDigest = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($bodyJson))
        if ($envelope.body.schema -ne "RawCampaignJournalRecordV1" -or
            [uint64]$envelope.body.record_index -ne [uint64]$State.EventNextIndex -or
            [string]$envelope.body.previous_record_sha256 -ne [string]$State.EventPrevious -or
            [string]$envelope.record_sha256 -ne $actualDigest) {
            throw "$($State.Symbol) campaign event journal lost its exact hash chain."
        }
        $State.EventNextIndex = [uint64]($State.EventNextIndex + 1)
        $State.EventPrevious = $actualDigest
        $payload = $envelope.body.payload
        if ($envelope.body.channel -eq "CHILD_STDERR") {
            $State.ChildStderrEvents = [uint64]($State.ChildStderrEvents + 1)
            throw "$($State.Symbol) segmented_capture emitted a forbidden CHILD_STDERR journal record."
        }
        $eventProperty = $payload.PSObject.Properties['event']
        $eventValue = if ($null -ne $eventProperty) { [string]$eventProperty.Value } else { $null }
        if ($envelope.body.channel -eq "CHILD_STDOUT") {
            $allowedChildStdoutEvents = @(
                "PROCESS_STARTED",
                "TRANSPORT_CONNECTED",
                "SNAPSHOT_DURABLE",
                "SEGMENT_DURABLE",
                "SERVER_SHUTDOWN_DURABLE",
                "HEARTBEAT_DURABLE",
                "PROCESS_TERMINAL")
            if ($null -eq $eventProperty -or
                $eventProperty.Value -isnot [string] -or
                [string]::IsNullOrWhiteSpace($eventValue) -or
                $allowedChildStdoutEvents -notcontains $eventValue) {
                throw "$($State.Symbol) CHILD_STDOUT record lacks an exact allowlisted event string."
            }
        }
        if ($null -eq $eventValue) { continue }
        if ($envelope.body.channel -eq "CAMPAIGN") {
            switch ($eventValue) {
                "GENERATION_LAUNCHED" {
                    $State.PlannedGenerationLaunches = [uint64]($State.PlannedGenerationLaunches + 1)
                    $generationKey = [string][uint64]$envelope.body.generation_index
                    if ($State.GenerationDurations.ContainsKey($generationKey) -or [uint64]$payload.duration_s -eq 0) {
                        throw "$($State.Symbol) has a duplicate/invalid planned generation launch."
                    }
                    $State.GenerationDurations[$generationKey] = [uint64]$payload.duration_s
                }
                "GENERATION_LAUNCHED_SERVER_SHUTDOWN" {
                    $State.ServerShutdownGenerationLaunches = [uint64]($State.ServerShutdownGenerationLaunches + 1)
                    $generationKey = [string][uint64]$envelope.body.generation_index
                    if ($State.GenerationDurations.ContainsKey($generationKey) -or [uint64]$payload.duration_s -eq 0) {
                        throw "$($State.Symbol) has a duplicate/invalid serverShutdown generation launch."
                    }
                    $State.GenerationDurations[$generationKey] = [uint64]$payload.duration_s
                }
                "CAMPAIGN_COMMITTED" {
                    if ($State.CampaignCommitted) {
                        throw "$($State.Symbol) has duplicate CAMPAIGN_COMMITTED records."
                    }
                    if ($payload.manifest_file -ne "campaign.json" -or
                        [string]$payload.manifest_sha256 -notmatch '^[0-9a-f]{64}$') {
                        throw "$($State.Symbol) CAMPAIGN_COMMITTED record is malformed."
                    }
                    $State.CampaignCommitted = $true
                    $State.CommitManifestSha256 = [string]$payload.manifest_sha256
                }
                "GENERATION_EXITED" {
                    $generationKey = [string][uint64]$envelope.body.generation_index
                    $successfulExit = [bool]$payload.success -and [int]$payload.code -eq 0
                    $failedExit = -not [bool]$payload.success -and [int]$payload.code -ne 0
                    if (-not $State.GenerationDurations.ContainsKey($generationKey) -or
                        $State.GenerationExited.Contains($generationKey) -or
                        (-not $successfulExit -and -not $failedExit)) {
                        throw "$($State.Symbol) has an invalid/duplicate GENERATION_EXITED record."
                    }
                    $null = $State.GenerationExited.Add($generationKey)
                    if ($failedExit) { $null = $State.GenerationFailedExits.Add($generationKey) }
                }
                "CAMPAIGN_FAILED" {
                    if ($null -ne $State.JournalFailureReason -or
                        $null -ne $envelope.body.generation_index -or
                        -not (Test-RawQualificationJsonString -Value $payload.error) -or
                        [string]::IsNullOrWhiteSpace([string]$payload.error) -or
                        -not (Test-RawQualificationJsonString -Value $payload.stage) -or
                        [string]$payload.stage -cne "RUNTIME") {
                        throw "$($State.Symbol) has a malformed or duplicate runtime CAMPAIGN_FAILED record."
                    }
                    $payloadProperties = @($payload.PSObject.Properties.Name)
                    $expectedFailureProperties = @("error", "event", "stage")
                    if ($payloadProperties.Count -ne $expectedFailureProperties.Count) {
                        throw "$($State.Symbol) runtime CAMPAIGN_FAILED payload has an invalid property set."
                    }
                    for ($failurePropertyIndex = 0; $failurePropertyIndex -lt $expectedFailureProperties.Count; $failurePropertyIndex++) {
                        if ([string]$payloadProperties[$failurePropertyIndex] -cne [string]$expectedFailureProperties[$failurePropertyIndex]) {
                            throw "$($State.Symbol) runtime CAMPAIGN_FAILED payload has invalid canonical property order."
                        }
                    }
                    $State.JournalFailureReason = [string]$payload.error
                    $State.JournalFailureRecordSha256 = [string]$actualDigest
                }
            }
            continue
        }
        if ($envelope.body.channel -eq "SUPERVISOR") {
            if ($eventValue -like "SERVER_SHUTDOWN_*") {
                $State.ServerShutdownSupervisorEvents = [uint64]($State.ServerShutdownSupervisorEvents + 1)
            }
            elseif ($eventValue -eq "GENERATION_DISCONNECT_FAIL_CLOSED") {
                $generationKey = [string][uint64]$envelope.body.generation_index
                if (-not $State.GenerationDurations.ContainsKey($generationKey) -or
                    -not $State.GenerationDisconnects.Add($generationKey) -or
                    [uint64]$payload.gap_count -lt 1 -or
                    [string]::IsNullOrWhiteSpace([string]$payload.epoch) -or
                    [string]::IsNullOrWhiteSpace([string]$payload.outcome)) {
                    throw "$($State.Symbol) has an invalid/duplicate GENERATION_DISCONNECT_FAIL_CLOSED record."
                }
            }
            continue
        }
        if ($envelope.body.channel -ne "CHILD_STDOUT") { continue }
        switch ($eventValue) {
            "PROCESS_STARTED" {
                $generationKey = [string][uint64]$envelope.body.generation_index
                if (-not $State.GenerationDurations.ContainsKey($generationKey) -or
                    $State.GenerationSessionIds.ContainsKey($generationKey) -or
                    $payload.schema -ne "CaptureProcessEventV1" -or
                    [uint64]$payload.generation_index -ne [uint64]$envelope.body.generation_index -or
                    $payload.symbol -ne $State.Symbol -or
                    $payload.spec_revision -ne $ExpectedSpecRevision -or
                    [uint32]$payload.process_id -eq 0 -or
                    [string]::IsNullOrWhiteSpace([string]$payload.session_id) -or
                    [string]$payload.startup_manifest_sha256 -notmatch '^[0-9a-f]{64}$') {
                    throw "$($State.Symbol) has an invalid/duplicate PROCESS_STARTED record."
                }
                $State.GenerationSessionIds[$generationKey] = [string]$payload.session_id
                $State.ProcessStarted = $true
            }
            "TRANSPORT_CONNECTED" {
                $stream = [string]$payload.connection.stream
                if (@("depth", "trade") -notcontains $stream -or [uint64]$payload.connection.websocket_http_status -ne 101) {
                    throw "$($State.Symbol) recorded an invalid transport connection event."
                }
                $null = $State.TransportStreams.Add($stream)
            }
            "SNAPSHOT_DURABLE" { $State.SnapshotDurable = $true }
            "SERVER_SHUTDOWN_DURABLE" { $State.ServerShutdownDurableEvents = [uint64]($State.ServerShutdownDurableEvents + 1) }
            "PROCESS_TERMINAL" {
                $generationKey = [string][uint64]$envelope.body.generation_index
                if (-not $State.GenerationDurations.ContainsKey($generationKey) -or
                    -not $State.GenerationSessionIds.ContainsKey($generationKey) -or
                    $State.GenerationTerminals.Contains($generationKey) -or
                    $payload.schema -ne "CaptureTerminalProcessEventV1" -or
                    @("COMPLETE", "FAILED") -notcontains [string]$payload.status -or
                    ([string]$payload.status -eq "FAILED" -and $null -eq $State.JournalFailureReason) -or
                    ([string]$payload.status -eq "COMPLETE" -and $null -ne $State.JournalFailureReason) -or
                    $payload.generation_manifest -ne "generation.json" -or
                    [string]$payload.session_id -ne [string]$State.GenerationSessionIds[$generationKey]) {
                    throw "$($State.Symbol) has an invalid/duplicate PROCESS_TERMINAL record."
                }
                $null = $State.GenerationTerminals.Add($generationKey)
                $State.ProcessTerminal = $true
            }
            "HEARTBEAT_DURABLE" {
                $generationKey = [string][uint64]$envelope.body.generation_index
                if (-not $State.GenerationDurations.ContainsKey($generationKey)) {
                    throw "$($State.Symbol) heartbeat preceded its generation launch contract."
                }
                if (-not $State.GenerationCounters.ContainsKey($generationKey)) {
                    $State.GenerationCounters[$generationKey] = [pscustomobject]@{
                        GenerationIndex = [uint64]$envelope.body.generation_index
                        DurationS = [uint64]$State.GenerationDurations[$generationKey]
                        TelemetryMonoNs = [uint64]0
                        DepthLastSocketActivityMonoNs = [uint64]0
                        DepthLastMarketMessageMonoNs = [uint64]0
                        TradeLastSocketActivityMonoNs = [uint64]0
                        TradeLastMarketMessageMonoNs = [uint64]0
                        DepthReceived = [uint64]0
                        DepthDurable = [uint64]0
                        TradeReceived = [uint64]0
                        TradeDurable = [uint64]0
                    }
                }
                $counters = $State.GenerationCounters[$generationKey]
                $depthReceived = [uint64]$payload.depth_received
                $depthDurable = [uint64]$payload.depth_durable
                $tradeReceived = [uint64]$payload.trade_received
                $tradeDurable = [uint64]$payload.trade_durable
                $telemetryMonoNs = [uint64]$payload.telemetry_mono_ns
                $depthSocketMonoNs = [uint64]$payload.depth_last_socket_activity_mono_ns
                $depthMarketMonoNs = [uint64]$payload.depth_last_market_message_mono_ns
                $tradeSocketMonoNs = [uint64]$payload.trade_last_socket_activity_mono_ns
                $tradeMarketMonoNs = [uint64]$payload.trade_last_market_message_mono_ns
                if ($depthReceived -lt $counters.DepthReceived -or
                    $depthDurable -lt $counters.DepthDurable -or
                    $tradeReceived -lt $counters.TradeReceived -or
                    $tradeDurable -lt $counters.TradeDurable -or
                    $depthDurable -gt $depthReceived -or
                    $tradeDurable -gt $tradeReceived -or
                    ($counters.TelemetryMonoNs -ne 0 -and $telemetryMonoNs -le $counters.TelemetryMonoNs) -or
                    $depthSocketMonoNs -lt $counters.DepthLastSocketActivityMonoNs -or
                    $depthMarketMonoNs -lt $counters.DepthLastMarketMessageMonoNs -or
                    $tradeSocketMonoNs -lt $counters.TradeLastSocketActivityMonoNs -or
                    $tradeMarketMonoNs -lt $counters.TradeLastMarketMessageMonoNs -or
                    $depthMarketMonoNs -gt $depthSocketMonoNs -or
                    $depthSocketMonoNs -gt $telemetryMonoNs -or
                    $tradeMarketMonoNs -gt $tradeSocketMonoNs -or
                    $tradeSocketMonoNs -gt $telemetryMonoNs) {
                    throw "$($State.Symbol) durable child counters regressed or became impossible."
                }
                $generationActiveEndNs = [uint64]$counters.DurationS * [uint64]1000000000
                if ($telemetryMonoNs -ge $MarketFreshnessStartupGraceNs -and $telemetryMonoNs -lt $generationActiveEndNs -and
                    ($depthMarketMonoNs -eq 0 -or
                     $tradeMarketMonoNs -eq 0 -or
                     ($telemetryMonoNs - $depthMarketMonoNs) -gt $MarketFreshnessDeadlineNs -or
                     ($telemetryMonoNs - $tradeMarketMonoNs) -gt $MarketFreshnessDeadlineNs)) {
                    throw "$($State.Symbol) durable heartbeat proves ping/socket activity without fresh depth/trade market messages."
                }
                $counters.TelemetryMonoNs = $telemetryMonoNs
                $counters.DepthLastSocketActivityMonoNs = $depthSocketMonoNs
                $counters.DepthLastMarketMessageMonoNs = $depthMarketMonoNs
                $counters.TradeLastSocketActivityMonoNs = $tradeSocketMonoNs
                $counters.TradeLastMarketMessageMonoNs = $tradeMarketMonoNs
                $counters.DepthReceived = $depthReceived
                $counters.DepthDurable = $depthDurable
                $counters.TradeReceived = $tradeReceived
                $counters.TradeDurable = $tradeDurable
                $State.DepthReceived = [uint64](($State.GenerationCounters.Values | Measure-Object -Property DepthReceived -Sum).Sum)
                $State.DepthDurable = [uint64](($State.GenerationCounters.Values | Measure-Object -Property DepthDurable -Sum).Sum)
                $State.TradeReceived = [uint64](($State.GenerationCounters.Values | Measure-Object -Property TradeReceived -Sum).Sum)
                $State.TradeDurable = [uint64](($State.GenerationCounters.Values | Measure-Object -Property TradeDurable -Sum).Sum)
                $State.SemanticHeartbeatSeen = $true
                $State.LastSemanticTick = Get-MonotonicTick
            }
        }
    }
}

function Stop-GuardianWatchdogClean {
    if ($null -eq $script:watchdogLaunch -or $script:watchdogLaunch.ProcessHandle -eq [IntPtr]::Zero) {
        throw "Guardian watchdog retained handle is absent before COMPLETE."
    }
    if ($script:workloadJobHandle -eq [IntPtr]::Zero -or
        [RawQualificationNative]::GetActiveProcessCount($script:workloadJobHandle) -ne 0) {
        throw "The exact workload Job is not empty before the guardian watchdog clean stop."
    }
    if ([RawQualificationNative]::WaitForProcessExit($script:watchdogLaunch.ProcessHandle, 0)) {
        throw "Guardian watchdog was not alive before its durable clean-stop request."
    }
    $stopRequestQpcTimestamp = [long][Diagnostics.Stopwatch]::GetTimestamp()
    $stop = [ordered]@{
        schema = "RawQualificationWatchdogStopV1"
        run_id = $script:runId
        job_name = "Local\BinanceRawQualificationJob-" + $script:runId
        requested_utc = [DateTimeOffset]::UtcNow.ToString("o")
    }
    $stopSha256 = Write-RawQualificationDurableNewJson -Path $script:watchdogStopPath -Value $stop
    $watchdogExitElapsedTicks = [long]0
    while (-not [RawQualificationNative]::WaitForProcessExit($script:watchdogLaunch.ProcessHandle, 100)) {
        $watchdogExitElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $stopRequestQpcTimestamp)
        if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $watchdogExitElapsedTicks `
            -TimeoutSeconds 10)) {
            break
        }
    }
    $watchdogExitElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $stopRequestQpcTimestamp)
    if (-not [RawQualificationNative]::WaitForProcessExit($script:watchdogLaunch.ProcessHandle, 0) -or
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $watchdogExitElapsedTicks `
            -TimeoutSeconds 10)) {
        throw "Guardian watchdog did not stop within its clean 10-second deadline."
    }
    $exitCode = [int][RawQualificationNative]::GetProcessExitCode($script:watchdogLaunch.ProcessHandle)
    if (-not [RawQualificationNative]::CloseRetainedProcessHandle($script:watchdogLaunch)) {
        throw "Guardian watchdog retained process handle was not closed exactly once."
    }
    $stdoutBytes = [uint64](Get-Item -LiteralPath $script:watchdogStdoutPath -ErrorAction Stop).Length
    $stderrBytes = [uint64](Get-Item -LiteralPath $script:watchdogStderrPath -ErrorAction Stop).Length
    if ($exitCode -ne 0 -or $stdoutBytes -ne 0 -or $stderrBytes -ne 0 -or
        (Test-Path -LiteralPath $script:watchdogFailurePath -PathType Leaf)) {
        throw "Guardian watchdog clean-stop evidence is invalid (exit=$exitCode, stdout=$stdoutBytes, stderr=$stderrBytes)."
    }
    $finalJobDrainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $stopRequestQpcTimestamp)
    while ([RawQualificationNative]::GetActiveProcessCount($script:jobHandle) -ne 0) {
        $finalJobDrainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $stopRequestQpcTimestamp)
        if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $finalJobDrainElapsedTicks `
            -TimeoutSeconds 10)) {
            break
        }
        Start-Sleep -Milliseconds 100
    }
    $finalJobDrainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $stopRequestQpcTimestamp)
    if ([RawQualificationNative]::GetActiveProcessCount($script:jobHandle) -ne 0 -or
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $finalJobDrainElapsedTicks `
            -TimeoutSeconds 10)) {
        throw "Job Object retained descendants after the guardian watchdog clean stop."
    }
    $result = [pscustomobject][ordered]@{
        pid = [uint32]$script:watchdogIdentity.pid
        exit_code = $exitCode
        stop_file = [IO.Path]::GetFileName($script:watchdogStopPath)
        stop_file_sha256 = $stopSha256
        stop_request_qpc_timestamp = [long]$stopRequestQpcTimestamp
        exit_elapsed_qpc_ticks = [long]$watchdogExitElapsedTicks
        final_job_drain_elapsed_qpc_ticks = [long]$finalJobDrainElapsedTicks
        monotonic_frequency = [long][Diagnostics.Stopwatch]::Frequency
        elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds -ElapsedTicks $watchdogExitElapsedTicks
        final_job_drain_elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds -ElapsedTicks $finalJobDrainElapsedTicks
        stdout_file = [IO.Path]::GetFileName($script:watchdogStdoutPath)
        stdout_bytes = $stdoutBytes
        stdout_sha256 = Get-RawQualificationSha256File -Path $script:watchdogStdoutPath
        stderr_file = [IO.Path]::GetFileName($script:watchdogStderrPath)
        stderr_bytes = $stderrBytes
        stderr_sha256 = Get-RawQualificationSha256File -Path $script:watchdogStderrPath
        final_job_active_processes = [uint32]0
    }
    Write-LauncherEvent -Channel "CONTROL" -Payload ([ordered]@{
        event = "GUARDIAN_WATCHDOG_STOPPED"
        pid = [uint32]$result.pid
        exit_code = $result.exit_code
        stop_file_sha256 = $stopSha256
        stop_request_qpc_timestamp = [long]$result.stop_request_qpc_timestamp
        exit_elapsed_qpc_ticks = [long]$result.exit_elapsed_qpc_ticks
        final_job_drain_elapsed_qpc_ticks = [long]$result.final_job_drain_elapsed_qpc_ticks
        monotonic_frequency = [long]$result.monotonic_frequency
        final_job_active_processes = [uint32]0
    })
    return $result
}

function Invoke-LauncherFailureContainment {
    param([Parameter(Mandatory = $true)] [uint64] $DetectedWallNs,
          [Parameter(Mandatory = $true)] [uint64] $DetectedMonotonicTick)

    # This function intentionally performs the native query/termination before
    # any durable evidence write.  Both native helpers are no-throw and capture
    # GetLastError immediately, so even a damaged failure path produces an
    # explicit, fail-closed result instead of silently treating uncertainty as
    # an empty Job.
    $initial = [RawQualificationNative]::TryGetActiveProcessCountNoThrow($script:jobHandle)
    $termination = [RawQualificationNative]::TryTerminateJobObjectNoThrow(
        $script:jobHandle,
        [uint32]$FailureContainmentExitCode)
    $terminationTick = Get-MonotonicTick
    $drainOriginQpcTimestamp = [long][Diagnostics.Stopwatch]::GetTimestamp()
    $final = [RawQualificationNative]::TryGetActiveProcessCountNoThrow($script:jobHandle)
    $drainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $drainOriginQpcTimestamp)

    if ($script:jobHandle -ne [IntPtr]::Zero) {
        while ((-not [bool]$final.Succeeded -or [uint32]$final.ActiveProcesses -ne 0) -and
               (Test-RawQualificationDeadlineTicks `
                    -ElapsedTicks $drainElapsedTicks `
                    -TimeoutSeconds $FailureContainmentDrainDeadlineSeconds)) {
            Start-Sleep -Milliseconds 25
            $final = [RawQualificationNative]::TryGetActiveProcessCountNoThrow($script:jobHandle)
            $drainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $drainOriginQpcTimestamp)
        }
    }

    if ($drainElapsedTicks -lt 0) {
        throw "Failure containment produced a negative QPC drain interval."
    }
    $drainWithinDeadline = Test-RawQualificationDeadlineTicks `
        -ElapsedTicks $drainElapsedTicks `
        -TimeoutSeconds $FailureContainmentDrainDeadlineSeconds `
        -Frequency ([Diagnostics.Stopwatch]::Frequency)

    $result = if ($script:jobHandle -eq [IntPtr]::Zero) {
        "NO_JOB_HANDLE"
    }
    elseif (-not [bool]$final.Succeeded) {
        "UNCONFIRMED_QUERY_ERROR"
    }
    elseif (-not $drainWithinDeadline -or [uint32]$final.ActiveProcesses -ne 0) {
        "UNCONFIRMED_TIMEOUT"
    }
    elseif ([bool]$initial.Succeeded -and [uint32]$initial.ActiveProcesses -eq 0) {
        "DRAINED_CONCURRENT_OR_PREEXISTING"
    }
    elseif ([bool]$termination.Succeeded) {
        "DRAINED_BY_ATTEMPT"
    }
    else {
        "DRAINED_CONCURRENT_OR_PREEXISTING"
    }

    return [pscustomobject][ordered]@{
        schema = "RawQualificationFailureContainmentV2"
        job_name = if ($null -ne $script:jobName) { [string]$script:jobName } else { "Local\BinanceRawQualificationJob-" + [string]$script:runId }
        job_kill_on_close = [bool]($script:jobHandle -ne [IntPtr]::Zero)
        detected_wall_ns = [uint64]$DetectedWallNs
        detected_monotonic_tick = [uint64]$DetectedMonotonicTick
        requested_exit_code = [uint32]$FailureContainmentExitCode
        initial_query_succeeded = [bool]$initial.Succeeded
        initial_active_processes = if ([bool]$initial.Succeeded) { [uint32]$initial.ActiveProcesses } else { $null }
        initial_query_error = if ([bool]$initial.Succeeded) { $null } else { [uint32]$initial.Error }
        terminate_attempted = [bool]$termination.Attempted
        terminate_succeeded = if ([bool]$termination.Attempted) { [bool]$termination.Succeeded } else { $null }
        terminate_error = if (-not [bool]$termination.Attempted -or [bool]$termination.Succeeded) { $null } else { [uint32]$termination.Error }
        termination_monotonic_tick = [uint64]$terminationTick
        monotonic_frequency = [uint64][Diagnostics.Stopwatch]::Frequency
        drain_deadline_s = [uint64]$FailureContainmentDrainDeadlineSeconds
        drain_elapsed_qpc_ticks = [uint64]$drainElapsedTicks
        final_query_succeeded = [bool]$final.Succeeded
        final_active_processes = if ([bool]$final.Succeeded) { [uint32]$final.ActiveProcesses } else { $null }
        final_query_error = if ([bool]$final.Succeeded) { $null } else { [uint32]$final.Error }
        result = $result
    }
}

function Assert-LauncherFailureContainmentEvidence {
    param(
        [Parameter(Mandatory = $true)] $Value
    )
    if ($Value -isnot [pscustomobject]) {
        throw "Failure containment evidence must be an exact object."
    }
    $expectedProperties = @(
        "schema", "job_name", "job_kill_on_close", "detected_wall_ns",
        "detected_monotonic_tick", "requested_exit_code", "initial_query_succeeded",
        "initial_active_processes", "initial_query_error", "terminate_attempted",
        "terminate_succeeded", "terminate_error", "termination_monotonic_tick",
        "monotonic_frequency", "drain_deadline_s", "drain_elapsed_qpc_ticks",
        "final_query_succeeded", "final_active_processes", "final_query_error", "result")
    $actualProperties = @($Value.PSObject.Properties.Name)
    if ($actualProperties.Count -ne $expectedProperties.Count) {
        throw "Failure containment evidence has an invalid property set."
    }
    for ($propertyIndex = 0; $propertyIndex -lt $expectedProperties.Count; $propertyIndex++) {
        if ([string]$actualProperties[$propertyIndex] -cne [string]$expectedProperties[$propertyIndex]) {
            throw "Failure containment evidence has invalid canonical property order."
        }
    }
    $u32 = [decimal][uint32]::MaxValue
    $u64 = [decimal][uint64]::MaxValue
    $nullOrInteger = {
        param($Candidate, [decimal] $Minimum, [decimal] $Maximum)
        return $null -eq $Candidate -or
            (Test-RawQualificationJsonInteger -Value $Candidate -Minimum $Minimum -Maximum $Maximum)
    }
    if (-not (Test-RawQualificationJsonString -Value $Value.schema) -or
        [string]$Value.schema -cne "RawQualificationFailureContainmentV2" -or
        -not (Test-RawQualificationJsonString -Value $Value.job_name) -or
        -not (Test-RawQualificationJsonBoolean -Value $Value.job_kill_on_close) -or
        -not (Test-RawQualificationJsonInteger -Value $Value.detected_wall_ns -Minimum 1 -Maximum $u64) -or
        -not (Test-RawQualificationJsonInteger -Value $Value.detected_monotonic_tick -Minimum 0 -Maximum $u64) -or
        -not (Test-RawQualificationJsonInteger -Value $Value.requested_exit_code `
            -Minimum ([decimal]$FailureContainmentExitCode) -Maximum ([decimal]$FailureContainmentExitCode)) -or
        -not (Test-RawQualificationJsonBoolean -Value $Value.initial_query_succeeded) -or
        -not (& $nullOrInteger $Value.initial_active_processes 0 $u32) -or
        -not (& $nullOrInteger $Value.initial_query_error 0 $u32) -or
        -not (Test-RawQualificationJsonBoolean -Value $Value.terminate_attempted) -or
        ($null -ne $Value.terminate_succeeded -and
            -not (Test-RawQualificationJsonBoolean -Value $Value.terminate_succeeded)) -or
        -not (& $nullOrInteger $Value.terminate_error 0 $u32) -or
        -not (Test-RawQualificationJsonInteger -Value $Value.termination_monotonic_tick -Minimum 0 -Maximum $u64) -or
        -not (Test-RawQualificationJsonInteger -Value $Value.monotonic_frequency -Minimum 1 -Maximum ([decimal][long]::MaxValue)) -or
        -not (Test-RawQualificationJsonInteger -Value $Value.drain_deadline_s `
            -Minimum ([decimal]$FailureContainmentDrainDeadlineSeconds) `
            -Maximum ([decimal]$FailureContainmentDrainDeadlineSeconds)) -or
        -not (Test-RawQualificationJsonInteger -Value $Value.drain_elapsed_qpc_ticks -Minimum 0 -Maximum ([decimal][long]::MaxValue)) -or
        -not (Test-RawQualificationJsonBoolean -Value $Value.final_query_succeeded) -or
        -not (& $nullOrInteger $Value.final_active_processes 0 $u32) -or
        -not (& $nullOrInteger $Value.final_query_error 0 $u32) -or
        -not (Test-RawQualificationJsonString -Value $Value.result) -or
        @("DRAINED_BY_ATTEMPT", "DRAINED_CONCURRENT_OR_PREEXISTING",
          "UNCONFIRMED_QUERY_ERROR", "UNCONFIRMED_TIMEOUT", "NO_JOB_HANDLE") -cnotcontains
            [string]$Value.result) {
        throw "Failure containment evidence types or constants are invalid."
    }
    $frequency = [long]$Value.monotonic_frequency
    if ($frequency -ne [Diagnostics.Stopwatch]::Frequency -or
        [decimal]$Value.termination_monotonic_tick -lt [decimal]$Value.detected_monotonic_tick) {
        throw "Failure containment monotonic evidence is invalid."
    }
    $drainWithinDeadline = Test-RawQualificationDeadlineTicks `
        -ElapsedTicks ([long]$Value.drain_elapsed_qpc_ticks) `
        -TimeoutSeconds $FailureContainmentDrainDeadlineSeconds `
        -Frequency $frequency
    $initialSucceeded = [bool]$Value.initial_query_succeeded
    $attempted = [bool]$Value.terminate_attempted
    $finalSucceeded = [bool]$Value.final_query_succeeded
    if (($initialSucceeded -and ($null -eq $Value.initial_active_processes -or $null -ne $Value.initial_query_error)) -or
        (-not $initialSucceeded -and ($null -ne $Value.initial_active_processes -or
            $null -eq $Value.initial_query_error -or [uint32]$Value.initial_query_error -eq 0)) -or
        ($attempted -and $null -eq $Value.terminate_succeeded) -or
        (-not $attempted -and ($null -ne $Value.terminate_succeeded -or $null -ne $Value.terminate_error)) -or
        ($attempted -and [bool]$Value.terminate_succeeded -and $null -ne $Value.terminate_error) -or
        ($attempted -and -not [bool]$Value.terminate_succeeded -and
            ($null -eq $Value.terminate_error -or [uint32]$Value.terminate_error -eq 0)) -or
        ($finalSucceeded -and ($null -eq $Value.final_active_processes -or $null -ne $Value.final_query_error)) -or
        (-not $finalSucceeded -and ($null -ne $Value.final_active_processes -or
            $null -eq $Value.final_query_error -or [uint32]$Value.final_query_error -eq 0))) {
        throw "Failure containment nullable evidence is incoherent."
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

function Assert-TerminalEvidenceArguments {
    param(
        [Parameter(Mandatory = $true)] [ValidateSet("COMPLETE", "FAILED")] $Status,
        [AllowNull()] $Failure,
        [AllowNull()] $FailureContainment,
        [AllowNull()] $FailureContainmentSha256
    )
    if ($Status -isnot [string] -or ($Status -cne "COMPLETE" -and $Status -cne "FAILED")) {
        throw "Terminal status must use exact canonical casing."
    }
    if ($Status -eq "COMPLETE") {
        if ($null -ne $Failure -or $null -ne $FailureContainment -or $null -ne $FailureContainmentSha256) {
            throw "A COMPLETE terminal cannot contain failure evidence."
        }
    }
    else {
        if ($Failure -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Failure) -or
            $null -eq $FailureContainment -or $FailureContainmentSha256 -isnot [string] -or
            -not ([string]$FailureContainmentSha256 -cmatch '^[0-9a-f]{64}$')) {
            throw "A FAILED terminal requires exact failure containment evidence and its digest."
        }
        $null = Assert-LauncherFailureContainmentEvidence -Value $FailureContainment
    }
}

function Assert-TerminalPublicationAcknowledgement {
    param(
        [Parameter(Mandatory = $true)] [AllowNull()] $Actual,
        [Parameter(Mandatory = $true)] [ValidateSet("COMPLETE", "FAILED")] $Expected
    )
    if ($Expected -isnot [string] -or ($Expected -cne "COMPLETE" -and $Expected -cne "FAILED") -or
        $Actual -isnot [string] -or $Actual -cne $Expected) {
        throw "Terminal manifest did not return its exact typed publication acknowledgement."
    }
    return $true
}

function Write-TerminalManifest {
    param(
        [Parameter(Mandatory = $true)] [ValidateSet("COMPLETE", "FAILED")] $Status,
        [AllowNull()] $Failure,
        [AllowNull()] $FailureContainment,
        [AllowNull()] $FailureContainmentSha256
    )
    if ($script:terminalWritten) {
        throw "A terminal manifest has already been written for this launcher."
    }
    if (-not (Test-Path -LiteralPath $script:runRoot -PathType Container)) {
        throw "The launcher run root is unavailable for terminal publication."
    }
    $null = Assert-TerminalEvidenceArguments `
        -Status $Status `
        -Failure $Failure `
        -FailureContainment $FailureContainment `
        -FailureContainmentSha256 $FailureContainmentSha256
    if ($Status -eq "FAILED") {
        $containmentCompactBytes = [Text.UTF8Encoding]::new($false).GetBytes(
            ($FailureContainment | ConvertTo-Json -Depth 100 -Compress))
        if ((Get-RawQualificationSha256Bytes -Bytes $containmentCompactBytes) -cne $FailureContainmentSha256) {
            throw "Failure containment evidence digest mismatch before terminal publication."
        }
    }
    $hashOrNull = {
        param([string] $Path)
        try { return Get-RawQualificationSha256File -Path $Path }
        catch { return $null }
    }
    $pythonTreeTerminal = try {
        (Get-RawQualificationSourceTreeDigest -Root $preflight.python_verifier_source.root).tree_sha256
    }
    catch { $null }
    $pythonRuntimeTerminal = if ($Status -eq "COMPLETE") {
        Get-BoundedPythonRuntimeFingerprint
    }
    if ($Status -eq "COMPLETE" -and $null -ne $script:verificationStopwatch -and
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $script:verificationStopwatch.ElapsedTicks `
            -TimeoutSeconds ([uint64]$PostVerificationDeadlineSeconds))) {
        throw "The separate post-capture verification deadline expired during terminal provenance sealing."
    }
    $terminalHashes = [ordered]@{
        campaign_executable_sha256 = & $hashOrNull $preflight.campaign_executable
        capture_executable_sha256 = & $hashOrNull $preflight.capture_executable
        campaign_verifier_executable_sha256 = & $hashOrNull $preflight.campaign_verifier_executable
        public_config_sha256 = & $hashOrNull $preflight.public_config
        source_lock_sha256 = & $hashOrNull $preflight.source_lock
        launcher_script_sha256 = & $hashOrNull $preflight.launcher_script
        monitor_script_sha256 = & $hashOrNull $preflight.monitor_script
        helper_script_sha256 = & $hashOrNull $preflight.helper_script
        telemetry_probe_script_sha256 = & $hashOrNull $preflight.telemetry_probe_script
        watchdog_script_sha256 = & $hashOrNull $preflight.watchdog_script
        watchdog_ready_file_sha256 = & $hashOrNull $script:watchdogReadyPath
        python_runtime_fingerprint_script_sha256 = & $hashOrNull $preflight.python_runtime_fingerprint_script
        powershell_executable_sha256 = & $hashOrNull $preflight.powershell_executable
        python_executable_sha256 = & $hashOrNull $preflight.python
        python_verifier_source_tree_sha256 = $pythonTreeTerminal
        python_runtime_tree_sha256 = if ($null -ne $pythonRuntimeTerminal) { $pythonRuntimeTerminal.tree_sha256 } else { $null }
        python_pyvenv_config_sha256 = if ($null -ne $pythonRuntimeTerminal) { $pythonRuntimeTerminal.pyvenv_config_sha256 } else { $null }
        python_base_executable_sha256 = if ($null -ne $pythonRuntimeTerminal) { $pythonRuntimeTerminal.base_executable_sha256 } else { $null }
        python_project_sha256 = & $hashOrNull $preflight.python_project
        python_requirements_sha256 = & $hashOrNull $preflight.python_requirements
    }
    if ($Status -eq "FAILED" -and $null -eq $script:startupSha256) {
        foreach ($hashName in @($terminalHashes.Keys)) { $terminalHashes[$hashName] = $null }
    }
    if ($Status -eq "COMPLETE") {
        $expectedTerminalHashes = [ordered]@{
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
            watchdog_ready_file_sha256 = $script:watchdogIdentity.ready_file_sha256
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
        $provenanceMismatches = @($expectedTerminalHashes.Keys | Where-Object {
            [string]$terminalHashes[$_] -cne [string]$expectedTerminalHashes[$_]
        })
        if ($provenanceMismatches.Count -ne 0) {
            throw "Qualification provenance digest mismatch: $($provenanceMismatches -join ',')."
        }
    }
    if ($Status -eq "COMPLETE") {
        $script:watchdogResult = Stop-GuardianWatchdogClean
    }
    if ($null -ne $script:guardianPulseJournal -and -not $script:guardianPulseJournal.Closed) {
        Close-RawQualificationJournal -Journal $script:guardianPulseJournal
    }
    if ($null -ne $script:telemetryJournal -and -not $script:telemetryJournal.Closed) {
        Close-RawQualificationJournal -Journal $script:telemetryJournal
    }
    if ($Status -eq "COMPLETE" -and $null -ne $script:verificationStopwatch) {
        $preterminalTick = Get-MonotonicTick
        if (-not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks ([long]($preterminalTick - $script:independentVerificationStartedTick)) `
                -TimeoutSeconds ([uint64]$PostVerificationDeadlineSeconds))) {
            throw "The exact post-capture deadline expired before the terminal manifest could be published."
        }
    }
    $launcherEventsPrefix = $null
    if ($null -ne $script:eventJournal -and -not $script:eventJournal.Closed) {
        $launcherPrefixSnapshot = Get-RawQualificationJournalPrefixSnapshot -Journal $script:eventJournal
        $launcherEventsPrefix = [ordered]@{
            file = "launcher-events.jsonl"
            records = [uint64]$launcherPrefixSnapshot.records
            terminal_record_sha256 = [string]$launcherPrefixSnapshot.terminal_record_sha256
            file_bytes = [uint64]$launcherPrefixSnapshot.file_bytes
            file_sha256 = [string]$launcherPrefixSnapshot.file_sha256
        }
    }
    $preflightHashesForTerminal = [ordered]@{
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
    if ($Status -eq "FAILED" -and $null -eq $script:startupSha256) {
        foreach ($hashName in @($preflightHashesForTerminal.Keys)) { $preflightHashesForTerminal[$hashName] = $null }
    }
    $manifest = [ordered]@{
        schema = "RawQualificationLauncherTerminalV2"
        status = $Status
        failure = if ($Status -eq "FAILED") { $Failure } else { $null }
        failure_containment = if ($Status -eq "FAILED") { $FailureContainment } else { $null }
        failure_containment_sha256 = if ($Status -eq "FAILED") { $FailureContainmentSha256 } else { $null }
        run_id = $script:runId
        mode = $Mode
        run_root = $script:runRoot
        finished_utc = [DateTimeOffset]::UtcNow.ToString("o")
        launcher_elapsed_ms = [uint64]$script:runStopwatch.ElapsedMilliseconds
        capture_elapsed_ms = if ($script:captureOriginTick -ne 0) {
            [uint64]((Get-CaptureElapsedSeconds) * 1000.0)
        } else { $null }
        parameters = [ordered]@{
            total_s = $TotalSeconds
            rotation_s = $RotationSeconds
            overlap_s = $OverlapSeconds
            segment_s = $SegmentSeconds
        }
        verifier_policy = [ordered]@{
            per_process_timeout_s = $IndependentVerifierTimeoutSeconds
            total_post_capture_timeout_s = $PostVerificationDeadlineSeconds
            maximum_artifact_bytes = [uint64]$MaximumVerifierArtifactBytes
        }
        coordinator_log_policy = [ordered]@{
            maximum_stdout_bytes = [uint64]$MaximumCampaignStdoutBytes
            maximum_stderr_bytes = [uint64]$MaximumCampaignStderrBytes
            child_stderr_events_allowed = [uint64]0
        }
        market_freshness_policy = [ordered]@{
            startup_grace_s = $MarketFreshnessStartupGraceSeconds
            deadline_s = $MarketFreshnessDeadlineSeconds
        }
        guardian_policy = [ordered]@{
            pulse_file = "guardian-pulse.jsonl"
            watchdog_ready_file = "watchdog-ready.json"
            watchdog_startup_deadline_s = [uint64]$GuardianWatchdogStartupDeadlineSeconds
            watchdog_deadline_s = [uint64]$GuardianWatchdogDeadlineSeconds
            host_telemetry_gap_deadline_s = [uint64]$HostTelemetryGapDeadlineSeconds
            maximum_dual_launch_skew_ms = [uint64]$MaximumDualLaunchSkewMilliseconds
            generation_terminal_deadline_s = [uint64]$GenerationTerminalDeadlineSeconds
            campaign_commit_deadline_s = [uint64]$CampaignCommitDeadlineSeconds
        }
        startup_sha256 = $script:startupSha256
        process_control_sha256 = $script:processControlSha256
        campaign_bindings_sha256 = $script:bindingsSha256
        launcher_events = $launcherEventsPrefix
        host_telemetry = if ($null -ne $script:telemetryJournal) { [ordered]@{
            file = "host-telemetry.jsonl"
            records = [uint64]$script:telemetryJournal.NextIndex
            terminal_record_sha256 = $script:telemetryJournal.Previous
            file_sha256 = Get-RawQualificationSha256File -Path $script:telemetryJournal.Path
        }} else { $null }
        guardian_pulse = if ($null -ne $script:guardianPulseJournal) { [ordered]@{
            file = "guardian-pulse.jsonl"
            records = [uint64]$script:guardianPulseJournal.NextIndex
            terminal_record_sha256 = $script:guardianPulseJournal.Previous
            file_sha256 = Get-RawQualificationSha256File -Path $script:guardianPulseJournal.Path
        }} else { $null }
        artifact_hashes_preflight = $preflightHashesForTerminal
        artifact_hashes_terminal = $terminalHashes
        watchdog = $script:watchdogResult
        campaigns = @($script:campaignResults)
        credentials = "NONE"
        order_entry = "ABSENT"
    }
    $path = Join-Path $script:runRoot "launcher-terminal.json"
    $terminalSha256 = Write-RawQualificationDurableNewJson -Path $path -Value $manifest
    $terminalBytes = [uint64](Get-Item -LiteralPath $path -ErrorAction Stop).Length
    $script:terminalWritten = $true
    if ($null -eq $script:eventJournal -or $script:eventJournal.Closed) {
        throw "The terminal manifest was durable, but its launcher journal post-link could not be written."
    }
    Write-LauncherEvent -Channel "LAUNCHER" -Payload ([ordered]@{
        event = "LAUNCHER_TERMINAL"
        status = $Status
        failure = if ($Status -eq "FAILED") { $Failure } else { $null }
        terminal_file = "launcher-terminal.json"
        terminal_bytes = [uint64]$terminalBytes
        terminal_sha256 = [string]$terminalSha256
        failure_containment_sha256 = if ($Status -eq "FAILED") { $FailureContainmentSha256 } else { $null }
    })
    try { Close-RawQualificationJournal -Journal $script:eventJournal } catch {}
    return $Status
}

try {
    $mutexSeed = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($repo.ToLowerInvariant()))
    $mutexName = "Local\BinanceRawQualification-" + $mutexSeed.Substring(0, 24)
    $createdNew = $false
    $mutex = [Threading.Mutex]::new($true, $mutexName, [ref]$createdNew)
    if (-not $createdNew) { throw "Another qualification guardian owns the repository mutex." }
    $mutexOwned = $true

    $null = New-Item -ItemType Directory -Path $preflight.output_base -Force -ErrorAction Stop
    $null = New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop
    $telemetryProbeDirectory = Join-Path $runRoot "host-probes"
    $null = New-Item -ItemType Directory -Path $telemetryProbeDirectory -ErrorAction Stop
    $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $runRoot
    $runRootDriveDeviceId = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($runRoot)).TrimEnd('\')
    if (-not $runRootDriveDeviceId.Equals([string]$preflight.drive_device_id, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Created run root resolved to a volume different from the preflight volume."
    }
    $postCreateProbeJob = [IntPtr]::Zero
    try {
        $postCreateProbeJob = [RawQualificationNative]::CreateKillOnCloseJob(
            "Local\BinanceRawQualificationPostCreate-" + [Guid]::NewGuid().ToString("N"))
        $postCreateProbe = Invoke-BoundedQualificationJsonProcess `
            -JobHandle $postCreateProbeJob `
            -Name "post-create-volume" `
            -Executable $preflight.powershell_executable `
            -Arguments ([string[]]@(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $preflight.telemetry_probe_script,
                "-HelperPath", $preflight.helper_script,
                "-DriveDeviceId", $runRootDriveDeviceId,
                "-RootProcessId", $PID.ToString([Globalization.CultureInfo]::InvariantCulture)
            )) `
            -WorkingDirectory $repo `
            -OutputDirectory $telemetryProbeDirectory `
            -EnvironmentEntries $childEnvironmentEntries `
            -TimeoutSeconds $HostTelemetryProbeTimeoutSeconds
    }
    finally {
        if ($postCreateProbeJob -ne [IntPtr]::Zero) {
            $null = [RawQualificationNative]::CloseHandle($postCreateProbeJob)
        }
    }
    if ($postCreateProbe.value.schema -ne "RawQualificationTelemetryProbeV1" -or
        $postCreateProbe.value.disk.device_id -ne $preflight.drive_device_id -or
        $postCreateProbe.value.disk.filesystem -ne "NTFS") {
        throw "Created run root failed the same-volume NTFS telemetry contract."
    }
    $postCreateFreeGiB = [uint64][math]::Floor([double]$postCreateProbe.value.disk.free_bytes / 1GB)
    if ($postCreateFreeGiB -lt [uint64]$preflight.required_free_gib) {
        throw "Created run root has only $postCreateFreeGiB GiB free; start requires $($preflight.required_free_gib) GiB."
    }
    $lastObservedFreeGiB = $postCreateFreeGiB
    $postCreateOutputValidation = [ordered]@{
        reparse_points_rejected = $true
        run_root_drive_device_id = $runRootDriveDeviceId
        same_preflight_volume = $true
        filesystem = [string]$postCreateProbe.value.disk.filesystem
        free_gib = $postCreateFreeGiB
        required_free_gib = [uint64]$preflight.required_free_gib
        probe_pid = [uint32]$postCreateProbe.pid
        probe_command_line_sha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes([string]$postCreateProbe.command_line))
        probe_resume_qpc_timestamp = [long]$postCreateProbe.resume_qpc_timestamp
        probe_elapsed_qpc_ticks = [long]$postCreateProbe.elapsed_qpc_ticks
        probe_monotonic_frequency = [long]$postCreateProbe.monotonic_frequency
        probe_job_membership = [string]$postCreateProbe.job_membership
        probe_parent_exit_observed_qpc_timestamp = [long]$postCreateProbe.parent_exit_observed_qpc_timestamp
        probe_descendant_drain_elapsed_qpc_ticks = [long]$postCreateProbe.descendant_drain_elapsed_qpc_ticks
        probe_descendant_drain_elapsed_ms = [uint64]$postCreateProbe.descendant_drain_elapsed_ms
        probe_descendant_drain_active_processes = [uint32]$postCreateProbe.descendant_drain_active_processes
        probe_timeout_s = [uint64]$postCreateProbe.timeout_s
        probe_elapsed_ms = [uint64]$postCreateProbe.elapsed_ms
        probe_stdout_file = [IO.Path]::GetFileName([string]$postCreateProbe.stdout_path)
        probe_stdout_bytes = [uint64]$postCreateProbe.stdout_bytes
        probe_stdout_sha256 = [string]$postCreateProbe.stdout_sha256
        probe_stderr_file = [IO.Path]::GetFileName([string]$postCreateProbe.stderr_path)
        probe_stderr_bytes = [uint64]$postCreateProbe.stderr_bytes
        probe_stderr_sha256 = [string]$postCreateProbe.stderr_sha256
    }
    $sealedRuntimeRoot = Join-Path $runRoot "sealed-runtime"
    $sealedBinRoot = Join-Path $sealedRuntimeRoot "bin"
    $sealedConfigRoot = Join-Path $sealedRuntimeRoot "config"
    $preflight.campaign_executable = Copy-RawQualificationVerifiedFile `
        -Source $preflight.campaign_executable `
        -ExpectedSha256 $preflight.campaign_executable_sha256 `
        -Destination (Join-Path $sealedBinRoot "raw_campaign.exe")
    $preflight.capture_executable = Copy-RawQualificationVerifiedFile `
        -Source $preflight.capture_executable `
        -ExpectedSha256 $preflight.capture_executable_sha256 `
        -Destination (Join-Path $sealedBinRoot "segmented_capture.exe")
    $preflight.campaign_verifier_executable = Copy-RawQualificationVerifiedFile `
        -Source $preflight.campaign_verifier_executable `
        -ExpectedSha256 $preflight.campaign_verifier_executable_sha256 `
        -Destination (Join-Path $sealedBinRoot "campaign_verify.exe")
    $preflight.public_config = Copy-RawQualificationVerifiedFile `
        -Source $preflight.public_config `
        -ExpectedSha256 $preflight.public_config_sha256 `
        -Destination (Join-Path $sealedConfigRoot "public.json")
    $sealedVerifierRoot = Join-Path $sealedRuntimeRoot "python-verifier-source"
    $preflight.python_verifier_source = New-RawQualificationSealedSourceTree `
        -SourceTree $preflight.python_verifier_source `
        -Destination $sealedVerifierRoot
    $script:executionBundleRoot = $sealedRuntimeRoot
    $eventJournal = New-RawQualificationJournal -Path (Join-Path $runRoot "launcher-events.jsonl")
    $telemetryJournal = New-RawQualificationJournal -Path (Join-Path $runRoot "host-telemetry.jsonl")
    $guardianPulseJournal = New-RawQualificationJournal -Path (Join-Path $runRoot "guardian-pulse.jsonl")
    Write-GuardianPulse -Stage "STARTING"

    $launcherProcess = [Diagnostics.Process]::GetCurrentProcess()
    $launcherExecutablePath = [IO.Path]::GetFullPath($launcherProcess.MainModule.FileName)
    $startup = [ordered]@{
        schema = "RawQualificationLauncherStartupV1"
        run_id = $runId
        mode = $Mode
        run_root = $runRoot
        started_utc = [DateTimeOffset]::UtcNow.ToString("o")
        launcher_pid = [uint32]$PID
        launcher_creation_time_utc = (Get-Process -Id $PID).StartTime.ToUniversalTime().ToString("o")
        launcher_executable_path = $launcherExecutablePath
        launcher_executable_sha256 = Get-RawQualificationSha256File -Path $launcherExecutablePath
        launcher_command_line = [Environment]::CommandLine
        output_path_post_create = $postCreateOutputValidation
        monotonic_frequency = [uint64]$monotonicFrequency
        monotonic_origin_qpc_timestamp = [long]$monotonicOrigin
        parameters = [ordered]@{
            total_s = $TotalSeconds
            rotation_s = $RotationSeconds
            overlap_s = $OverlapSeconds
            segment_s = $SegmentSeconds
        }
        verifier_policy = [ordered]@{
            per_process_timeout_s = $IndependentVerifierTimeoutSeconds
            total_post_capture_timeout_s = $PostVerificationDeadlineSeconds
            maximum_artifact_bytes = [uint64]$MaximumVerifierArtifactBytes
        }
        coordinator_log_policy = [ordered]@{
            maximum_stdout_bytes = [uint64]$MaximumCampaignStdoutBytes
            maximum_stderr_bytes = [uint64]$MaximumCampaignStderrBytes
            child_stderr_events_allowed = [uint64]0
        }
        market_freshness_policy = [ordered]@{
            startup_grace_s = $MarketFreshnessStartupGraceSeconds
            deadline_s = $MarketFreshnessDeadlineSeconds
        }
        guardian_policy = [ordered]@{
            pulse_file = "guardian-pulse.jsonl"
            watchdog_ready_file = "watchdog-ready.json"
            watchdog_startup_deadline_s = [uint64]$GuardianWatchdogStartupDeadlineSeconds
            watchdog_deadline_s = [uint64]$GuardianWatchdogDeadlineSeconds
            host_telemetry_gap_deadline_s = [uint64]$HostTelemetryGapDeadlineSeconds
            maximum_dual_launch_skew_ms = [uint64]$MaximumDualLaunchSkewMilliseconds
            generation_terminal_deadline_s = [uint64]$GenerationTerminalDeadlineSeconds
            campaign_commit_deadline_s = [uint64]$CampaignCommitDeadlineSeconds
        }
        preflight = $preflight
        credentials = "NONE"
        order_entry = "ABSENT"
    }
    $startupSha256 = Write-RawQualificationDurableNewJson -Path (Join-Path $runRoot "launcher-startup.json") -Value $startup
    Write-LauncherEvent -Channel "LAUNCHER" -Payload ([ordered]@{ event = "PREFLIGHT_PASSED"; startup_sha256 = $startupSha256 })

    $powerState = [RawQualificationNative]::SetThreadExecutionState(
        [RawQualificationNative]::ES_CONTINUOUS -bor [RawQualificationNative]::ES_SYSTEM_REQUIRED)
    if ($powerState -eq 0) { throw "SetThreadExecutionState(ES_SYSTEM_REQUIRED) failed." }
    $executionStateArmed = $true

    $jobName = "Local\BinanceRawQualificationJob-" + $runId
    $jobHandle = [RawQualificationNative]::CreateKillOnCloseJob($jobName)
    $workloadJobName = "Local\BinanceRawQualificationWorkloadJob-" + $runId
    $workloadJobHandle = [RawQualificationNative]::CreateKillOnCloseJob($workloadJobName)
    Write-LauncherEvent -Channel "CONTROL" -Payload ([ordered]@{
        event = "JOB_OBJECT_ARMED"
        name = $jobName
        kill_on_close = $true
        workload_name = $workloadJobName
        workload_kill_on_close = $true
    })

    $watchdogStopPath = Join-Path $runRoot "watchdog-stop.json"
    $watchdogFailurePath = Join-Path $runRoot "watchdog-failure.json"
    $watchdogReadyPath = Join-Path $runRoot "watchdog-ready.json"
    $watchdogStdoutPath = Join-Path $runRoot "watchdog.stdout.log"
    $watchdogStderrPath = Join-Path $runRoot "watchdog.stderr.log"
    if (Test-Path -LiteralPath $watchdogReadyPath) {
        throw "Independent guardian watchdog READY path existed before launch."
    }
    # This QPC sample deliberately precedes CreateProcess.  Process creation,
    # assignment and scheduling are therefore all charged to the startup bound.
    $watchdogLaunchOriginQpcTimestamp = [Diagnostics.Stopwatch]::GetTimestamp()
    $watchdogArguments = [string[]]@(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $preflight.watchdog_script,
        "-HelperPath", $preflight.helper_script,
        "-JobName", $jobName,
        "-RunId", $runId,
        "-GuardianPulsePath", $guardianPulseJournal.Path,
        "-ReadyPath", $watchdogReadyPath,
        "-StopPath", $watchdogStopPath,
        "-FailurePath", $watchdogFailurePath,
        "-LaunchOriginQpcTimestamp", $watchdogLaunchOriginQpcTimestamp.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-MonotonicFrequency", $monotonicFrequency.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-StartupDeadlineSeconds", $GuardianWatchdogStartupDeadlineSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        "-MaximumGuardianPulseAgeSeconds", $GuardianWatchdogDeadlineSeconds.ToString([Globalization.CultureInfo]::InvariantCulture)
    )
    $watchdogLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
        $jobHandle,
        $preflight.powershell_executable,
        $watchdogArguments,
        $repo,
        $watchdogStdoutPath,
        $watchdogStderrPath,
        $childEnvironmentEntries)
    if ([long]$watchdogLaunch.ResumeQpcTimestamp -lt [long]$watchdogLaunchOriginQpcTimestamp) {
        throw "Independent guardian watchdog resume QPC precedes its conservative launch origin."
    }
    $watchdogIdentity = [pscustomobject][ordered]@{
        pid = [uint32]$watchdogLaunch.ProcessId
        job_name = $jobName
        creation_time_utc = [DateTime]::FromFileTimeUtc([int64]$watchdogLaunch.CreationFileTimeUtc).ToString("o")
        executable_path = [IO.Path]::GetFullPath($preflight.powershell_executable)
        executable_sha256 = [string]$preflight.powershell_executable_sha256
        command_line = [string]$watchdogLaunch.ExactCommandLine
        script_path = [string]$preflight.watchdog_script
        script_sha256 = [string]$preflight.watchdog_script_sha256
        launch_origin_qpc_timestamp = [long]$watchdogLaunchOriginQpcTimestamp
        resume_qpc_timestamp = [long]$watchdogLaunch.ResumeQpcTimestamp
        monotonic_frequency = [long]$monotonicFrequency
        startup_deadline_s = [uint64]$GuardianWatchdogStartupDeadlineSeconds
        guardian_pulse_file = [IO.Path]::GetFileName($guardianPulseJournal.Path)
        maximum_guardian_pulse_age_s = [uint64]$GuardianWatchdogDeadlineSeconds
        ready_file = [IO.Path]::GetFileName($watchdogReadyPath)
        ready_file_sha256 = $null
        ready_observed_qpc_timestamp = $null
        ready_pulse_length = $null
        stdout_file = [IO.Path]::GetFileName($watchdogStdoutPath)
        stderr_file = [IO.Path]::GetFileName($watchdogStderrPath)
    }
    $watchdogReady = $null
    $watchdogReadyBytes = $null
    while ($null -eq $watchdogReady) {
        $readyPollQpc = [Diagnostics.Stopwatch]::GetTimestamp()
        if ($readyPollQpc -lt $watchdogLaunchOriginQpcTimestamp -or
            -not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks ([long]($readyPollQpc - $watchdogLaunchOriginQpcTimestamp)) `
                -TimeoutSeconds ([uint64]$GuardianWatchdogStartupDeadlineSeconds) `
                -Frequency ([long]$monotonicFrequency))) {
            throw "Independent guardian watchdog did not publish READY within its exact startup deadline."
        }
        if ([RawQualificationNative]::WaitForProcessExit($watchdogLaunch.ProcessHandle, 0)) {
            $watchdogExit = [int][RawQualificationNative]::GetProcessExitCode($watchdogLaunch.ProcessHandle)
            throw "Independent guardian watchdog exited with code $watchdogExit before READY."
        }
        if (Test-Path -LiteralPath $watchdogFailurePath -PathType Leaf) {
            throw "Independent guardian watchdog fenced the Job before READY."
        }
        $candidateReady = Open-WatchdogReadyRetained -Path $watchdogReadyPath
        if ($null -ne $candidateReady) {
            $watchdogReadyStream = $candidateReady.Stream
            $watchdogReady = $candidateReady.Value
            $watchdogReadyBytes = $candidateReady.Bytes
        }
        if ($null -eq $watchdogReady) { Start-Sleep -Milliseconds 50 }
    }
    $readyValidatedQpc = [Diagnostics.Stopwatch]::GetTimestamp()
    $readyPropertyNames = @($watchdogReady.PSObject.Properties.Name | Sort-Object)
    $expectedReadyPropertyNames = @(
        "job_name", "launch_origin_qpc_timestamp", "monotonic_frequency", "observed_qpc_timestamp",
        "pid", "pulse_length", "run_id", "schema", "startup_deadline_s") | Sort-Object
    if (($readyPropertyNames -join ',') -ne ($expectedReadyPropertyNames -join ',') -or
        $watchdogReady.schema -ne "RawQualificationWatchdogReadyV1" -or
        $watchdogReady.run_id -ne $runId -or
        $watchdogReady.job_name -ne $jobName -or
        [uint32]$watchdogReady.pid -ne [uint32]$watchdogLaunch.ProcessId -or
        [long]$watchdogReady.launch_origin_qpc_timestamp -ne [long]$watchdogLaunchOriginQpcTimestamp -or
        [long]$watchdogReady.monotonic_frequency -ne [long]$monotonicFrequency -or
        [uint64]$watchdogReady.startup_deadline_s -ne [uint64]$GuardianWatchdogStartupDeadlineSeconds -or
        [long]$watchdogReady.observed_qpc_timestamp -lt [long]$watchdogLaunch.ResumeQpcTimestamp -or
        [long]$watchdogReady.observed_qpc_timestamp -gt [long]$readyValidatedQpc -or
        [uint64]$watchdogReady.pulse_length -eq 0 -or
        [uint64]$watchdogReady.pulse_length -ne [uint64]$guardianPulseJournal.Stream.Length -or
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks ([long]($readyValidatedQpc - $watchdogLaunchOriginQpcTimestamp)) `
            -TimeoutSeconds ([uint64]$GuardianWatchdogStartupDeadlineSeconds) `
            -Frequency ([long]$monotonicFrequency)) -or
        [RawQualificationNative]::WaitForProcessExit($watchdogLaunch.ProcessHandle, 0)) {
        throw "Independent guardian watchdog READY payload, QPC deadline, retained pulse, or live identity is invalid."
    }
    $watchdogIdentity.ready_file_sha256 = Get-RawQualificationSha256Bytes -Bytes $watchdogReadyBytes
    $watchdogIdentity.ready_observed_qpc_timestamp = [long]$watchdogReady.observed_qpc_timestamp
    $watchdogIdentity.ready_pulse_length = [uint64]$watchdogReady.pulse_length
    Write-LauncherEvent -Channel "CONTROL" -Payload ([ordered]@{
        event = "GUARDIAN_WATCHDOG_STARTED"
        pid = [uint32]$watchdogIdentity.pid
        ready_file_sha256 = [string]$watchdogIdentity.ready_file_sha256
        launch_origin_qpc_timestamp = [long]$watchdogIdentity.launch_origin_qpc_timestamp
        resume_qpc_timestamp = [long]$watchdogIdentity.resume_qpc_timestamp
        ready_observed_qpc_timestamp = [long]$watchdogIdentity.ready_observed_qpc_timestamp
        ready_pulse_length = [uint64]$watchdogIdentity.ready_pulse_length
        startup_deadline_s = [uint64]$GuardianWatchdogStartupDeadlineSeconds
        deadline_s = [uint64]$GuardianWatchdogDeadlineSeconds
    })

    foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
            $stdoutPath = Join-Path $runRoot ($symbol.ToLowerInvariant() + ".stdout.log")
            $stderrPath = Join-Path $runRoot ($symbol.ToLowerInvariant() + ".stderr.log")
            $arguments = [string[]]@(
                $symbol,
                $TotalSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
                $RotationSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
                $OverlapSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
                $SegmentSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
                $runRoot,
                "--event-stream"
            )
            $childLaunch = [RawQualificationNative]::StartSuspendedInJobsRetainedWithEnvironment(
                $jobHandle,
                $workloadJobHandle,
                $preflight.campaign_executable,
                $arguments,
                $executionBundleRoot,
                $stdoutPath,
                $stderrPath,
                $childEnvironmentEntries)
            $handleOwner = [pscustomobject]@{
                Symbol = $symbol
                ProcessId = [uint32]$childLaunch.ProcessId
                ProcessHandle = [IntPtr]$childLaunch.ProcessHandle
                Closed = $false
                CloseCount = [uint32]0
            }
            $coordinatorProcessHandleOwners.Add($handleOwner)
            # The native helper samples QPC immediately before ResumeThread.  A
            # launcher deschedule after resume therefore cannot hide launch skew.
            if ([int64]$childLaunch.ResumeQpcTimestamp -le [int64]$monotonicOrigin) {
                throw "$symbol coordinator launch produced an invalid monotonic tick."
            }
            $coordinatorLaunchTick = [uint64]([int64]$childLaunch.ResumeQpcTimestamp - [int64]$monotonicOrigin)
            $coordinatorLaunchTicks[$symbol] = [uint64]$coordinatorLaunchTick
            if ($symbol -eq "ETHUSDT") {
                $captureOriginTick = [uint64]$coordinatorLaunchTick
                if (-not $coordinatorLaunchTicks.ContainsKey("BTCUSDT")) {
                    $null = Close-CoordinatorNativeProcessHandle -HandleOwner $handleOwner
                    throw "Second coordinator launched without the exact first-coordinator tick."
                }
                $launchSkewTicks = [uint64]($captureOriginTick - [uint64]$coordinatorLaunchTicks["BTCUSDT"])
                $maximumLaunchSkewTicks = [uint64]$MaximumDualLaunchSkewMilliseconds * [uint64]$monotonicFrequency / [uint64]1000
                if ($launchSkewTicks -gt $maximumLaunchSkewTicks) {
                    $null = Close-CoordinatorNativeProcessHandle -HandleOwner $handleOwner
                    throw "Dual coordinator launch skew exceeded the fixed ${MaximumDualLaunchSkewMilliseconds}ms deadline."
                }
                $launchSkewMilliseconds = [uint64][math]::Ceiling(
                    [decimal]$launchSkewTicks * [decimal]1000 / [decimal]$monotonicFrequency)
            }
            $childPid = [uint32]$childLaunch.ProcessId
            $identity = [pscustomobject][ordered]@{
                pid = $childPid
                creation_time_utc = [DateTime]::FromFileTimeUtc([int64]$childLaunch.CreationFileTimeUtc).ToString("o")
                executable_path = [IO.Path]::GetFullPath($preflight.campaign_executable)
                executable_sha256 = Get-RawQualificationSha256File -Path $preflight.campaign_executable
                command_line = [string]$childLaunch.ExactCommandLine
                identity_source = "CREATE_PROCESS_SUSPENDED_HANDLE"
            }
            if ($identity.executable_sha256 -ne $preflight.campaign_executable_sha256) {
                $null = Close-CoordinatorNativeProcessHandle -HandleOwner $handleOwner
                throw "$symbol process executable hash changed between preflight and launch."
            }
            if ([RawQualificationNative]::WaitForProcessExit([IntPtr]$handleOwner.ProcessHandle, 0)) {
                $launchExitCode = [int][RawQualificationNative]::GetProcessExitCode([IntPtr]$handleOwner.ProcessHandle)
                $null = Close-CoordinatorNativeProcessHandle -HandleOwner $handleOwner
                throw "$symbol coordinator exited during launch with code $launchExitCode."
            }
            $record = [pscustomobject][ordered]@{
                symbol = $symbol
                pid = [uint32]$identity.pid
                creation_time_utc = $identity.creation_time_utc
                executable_path = $identity.executable_path
                executable_sha256 = $identity.executable_sha256
                command_line = $identity.command_line
                launch_monotonic_tick = [uint64]$coordinatorLaunchTick
                stdout_file = [IO.Path]::GetFileName($stdoutPath)
                stderr_file = [IO.Path]::GetFileName($stderrPath)
            }
            $processRecords += $record
            $states[$symbol] = [pscustomobject]@{
                Symbol = $symbol
                ProcessId = [uint32]$childPid
                LaunchTick = [uint64]$coordinatorLaunchTick
                ProcessHandleOwner = $handleOwner
                StdoutState = [pscustomobject]@{ Path = $stdoutPath; Offset = [int64]0; Partial = "" }
                StderrPath = $stderrPath
                EventState = [pscustomobject]@{ Path = ""; Offset = [int64]0; Partial = "" }
                CampaignId = $null
                CampaignDirectory = $null
                CampaignStartupSha256 = $null
                StartupValidated = $false
                LastHeartbeatTick = [uint64]0
                LastSemanticTick = [uint64]0
                LastCampaignElapsedS = [uint64]0
                Generations = [uint64]0
                ActiveProcesses = [uint64]0
                HandoversProven = [uint64]0
                PendingFailureReason = $null
                PendingFailureRecordSha256 = $null
                JournalFailureReason = $null
                JournalFailureRecordSha256 = $null
                FailureValidated = $false
                FailureFirstObservedTick = [uint64]0
                PlannedGenerationLaunches = [uint64]0
                ServerShutdownGenerationLaunches = [uint64]0
                ServerShutdownSupervisorEvents = [uint64]0
                ServerShutdownDurableEvents = [uint64]0
                ChildStderrEvents = [uint64]0
                EventNextIndex = [uint64]0
                EventPrevious = ("0" * 64)
                ProcessStarted = $false
                TransportStreams = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                SnapshotDurable = $false
                ProcessTerminal = $false
                CampaignCommitted = $false
                CommitManifestSha256 = $null
                SemanticHeartbeatSeen = $false
                GenerationCounters = @{}
                GenerationDurations = @{}
                GenerationSessionIds = @{}
                GenerationTerminals = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                GenerationExited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                GenerationFailedExits = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                GenerationDisconnects = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                DepthReceived = [uint64]0
                DepthDurable = [uint64]0
                TradeReceived = [uint64]0
                TradeDurable = [uint64]0
                Ready = $false
                Exited = $false
                ExitCode = $null
                ExitElapsedS = $null
                CoordinatorExitElapsedS = $null
                ExitObservedTick = [uint64]0
            }
    }

    if ($captureOriginTick -eq 0 -or
        $processRecords.Count -ne 2 -or
        $coordinatorLaunchTicks.Count -ne 2 -or
        [uint64]$coordinatorLaunchTicks["ETHUSDT"] -ne [uint64]$captureOriginTick -or
        [uint64]$coordinatorLaunchTicks["BTCUSDT"] -gt [uint64]$captureOriginTick -or
        [uint64]$launchSkewTicks -ne ([uint64]$captureOriginTick - [uint64]$coordinatorLaunchTicks["BTCUSDT"]) -or
        [uint64]$launchSkewTicks -gt ([uint64]$MaximumDualLaunchSkewMilliseconds * [uint64]$monotonicFrequency / [uint64]1000)) {
        throw "Dual-campaign monotonic capture origin could not be established after both launches."
    }
    Write-GuardianPulse -Stage "CAPTURING"

    $processControl = [ordered]@{
        schema = "RawQualificationProcessControlV2"
        run_id = $runId
        job_object_name = $jobName
        job_kill_on_close = $true
        workload_job_object_name = $workloadJobName
        workload_job_kill_on_close = $true
        launch_method = "CREATE_SUSPENDED_ASSIGN_OUTER_AND_WORKLOAD_JOBS_RESUME"
        child_environment_mode = [string]$preflight.child_environment.mode
        child_environment_names = @($preflight.child_environment.names)
        child_environment_entries_sha256 = [string]$preflight.child_environment.entries_sha256
        capture_origin_monotonic_tick = [uint64]$captureOriginTick
        launch_skew_ticks = [uint64]$launchSkewTicks
        launch_skew_ms = [uint64]$launchSkewMilliseconds
        maximum_dual_launch_skew_ms = [uint64]$MaximumDualLaunchSkewMilliseconds
        watchdog = $watchdogIdentity
        processes = @($processRecords)
    }
    $processControlSha256 = Write-RawQualificationDurableNewJson -Path (Join-Path $runRoot "processes.json") -Value $processControl
    Write-LauncherEvent -Channel "CONTROL" -Payload ([ordered]@{ event = "DUAL_CAMPAIGN_STARTED"; process_control_sha256 = $processControlSha256 })

    $lastLoopTick = Get-MonotonicTick
    $lastTelemetryTick = [uint64]0
    $lastConsoleTick = [uint64]0
    $bindingsWritten = $false
    $captureDrainingEventWritten = $false
    $captureDrainingStartedTick = [uint64]0
    $terminalEvaluationStartedTick = [uint64]0
    $independentVerificationStartedTick = [uint64]0
    $null = Write-HostTelemetrySample
    $lastTelemetryTick = Get-MonotonicTick

    while (@($states.Values | Where-Object { -not $_.Exited }).Count -gt 0) {
        Start-Sleep -Seconds 2
        if ([RawQualificationNative]::WaitForProcessExit($watchdogLaunch.ProcessHandle, 0)) {
            $watchdogExit = [int][RawQualificationNative]::GetProcessExitCode($watchdogLaunch.ProcessHandle)
            throw "Independent guardian watchdog exited unexpectedly with code $watchdogExit."
        }
        if ([uint64](Get-Item -LiteralPath $watchdogStdoutPath -ErrorAction Stop).Length -ne 0 -or
            [uint64](Get-Item -LiteralPath $watchdogStderrPath -ErrorAction Stop).Length -ne 0) {
            throw "Independent guardian watchdog emitted unexpected stdout/stderr."
        }
        $nowTick = Get-MonotonicTick
        $loopDeltaSeconds = [double]($nowTick - $lastLoopTick) / $monotonicFrequency
        if ($loopDeltaSeconds -gt $GuardianGapDeadlineSeconds) {
            throw "The launcher guardian itself was silent for $([math]::Round($loopDeltaSeconds, 3)) seconds."
        }
        $lastLoopTick = $nowTick
        if (([double]($nowTick - $lastGuardianPulseTick) / $monotonicFrequency) -ge 5) {
            $pulseStage = if ($terminalEvaluationStartedTick -ne 0) {
                "TERMINAL_EVALUATION"
            }
            elseif ((Get-CaptureElapsedSeconds -ObservedTick $nowTick) -ge ($TotalSeconds - 5)) {
                "DRAINING"
            }
            else { "CAPTURING" }
            Write-GuardianPulse -Stage $pulseStage
        }
        if (-not $captureDrainingEventWritten -and (Get-CaptureElapsedSeconds -ObservedTick $nowTick) -ge ($TotalSeconds - 5)) {
            Ensure-CaptureDraining -ObservedTick $nowTick
        }

        foreach ($state in $states.Values) {
            $null = Assert-StateCoordinatorLogsBounded -State $state
            Read-StateOutput -State $state
            Assert-CampaignStartup -State $state
            Read-StateCampaignEvents -State $state
            Assert-StateCampaignFailureContract -State $state
            $null = Assert-StateCoordinatorLogsBounded -State $state
            $state.Ready = Test-StateReady -State $state

            if (-not $state.Exited) {
                $handleOwner = $state.ProcessHandleOwner
                if ($null -eq $handleOwner -or
                    [bool]$handleOwner.Closed -or
                    [IntPtr]$handleOwner.ProcessHandle -eq [IntPtr]::Zero -or
                    [uint32]$handleOwner.CloseCount -ne 0) {
                    throw "$($state.Symbol) lost its retained original coordinator process handle before exit observation."
                }
                if ([RawQualificationNative]::WaitForProcessExit([IntPtr]$handleOwner.ProcessHandle, 0)) {
                    $exitObservedTick = Get-MonotonicTick
                    $nativeExitCode = [int][RawQualificationNative]::GetProcessExitCode([IntPtr]$handleOwner.ProcessHandle)
                    $null = Close-CoordinatorNativeProcessHandle -HandleOwner $handleOwner
                    $state.Exited = $true
                    $state.ExitObservedTick = [uint64]$exitObservedTick
                    $state.ExitCode = $nativeExitCode
                    $state.ExitElapsedS = Convert-RawQualificationQpcTicksToWholeSeconds `
                        -ElapsedTicks ([long]($exitObservedTick - $captureOriginTick)) `
                        -Frequency ([long]$monotonicFrequency)
                    $state.CoordinatorExitElapsedS = Convert-RawQualificationQpcTicksToWholeSeconds `
                        -ElapsedTicks ([long]($exitObservedTick - [uint64]$state.LaunchTick)) `
                        -Frequency ([long]$monotonicFrequency)
                    if ($state.ExitCode -eq 0 -and [double]$state.CoordinatorExitElapsedS -lt ($TotalSeconds - 5)) {
                        throw "$($state.Symbol) raw_campaign exited before the requested campaign duration."
                    }
                    # If this poll crossed Total-5 while reading final output,
                    # durably linearize DRAINING at the exact exit observation
                    # before publishing the corresponding exit record.
                    if ($state.ExitCode -eq 0) {
                        Ensure-CaptureDraining -ObservedTick $exitObservedTick
                    }
                    Write-LauncherEvent -Channel "PROCESS" -Payload ([ordered]@{
                        event = "CAMPAIGN_PROCESS_EXITED"
                        symbol = $state.Symbol
                        pid = $state.ProcessId
                        exit_observed_monotonic_tick = [uint64]$state.ExitObservedTick
                        exit_code = $state.ExitCode
                        elapsed_s = $state.ExitElapsedS
                        coordinator_elapsed_s = $state.CoordinatorExitElapsedS
                    })
                    # The coordinator may append its final journal records between
                    # the first read above and the exact process-exit observation.
                    # Re-read the now-stable coordinator output in this same poll.
                    $null = Assert-StateCoordinatorLogsBounded -State $state
                    Read-StateOutput -State $state
                    Assert-CampaignStartup -State $state
                    Read-StateCampaignEvents -State $state
                    Assert-StateCampaignFailureContract -State $state
                    $null = Assert-StateCoordinatorLogsBounded -State $state
                    $state.Ready = Test-StateReady -State $state
                    if ($state.ExitCode -ne 0) {
                        if (-not (Test-StateDurableFailureDrainage -State $state)) {
                            throw "$($state.Symbol) raw_campaign exited with code $($state.ExitCode) before complete durable failure drainage."
                        }
                        throw "$($state.Symbol) campaign failed: $($state.JournalFailureReason) [journal $($state.JournalFailureRecordSha256)]"
                    }
                    if ($state.FailureValidated) {
                        throw "$($state.Symbol) raw_campaign exited successfully after declaring failure."
                    }
                }
            }

            # Reads above may publish heartbeat/semantic observations later than
            # the loop-entry tick.  Sample after those reads so every freshness
            # subtraction is causally ordered and includes any read/deschedule
            # time instead of reusing a stale pre-read observation.
            $stateDeadlineObservedTick = Get-MonotonicTick
            if ($stateDeadlineObservedTick -lt [uint64]$state.LaunchTick -or
                ($state.LastHeartbeatTick -gt 0 -and $stateDeadlineObservedTick -lt [uint64]$state.LastHeartbeatTick) -or
                ($state.LastSemanticTick -gt 0 -and $stateDeadlineObservedTick -lt [uint64]$state.LastSemanticTick)) {
                throw "$($state.Symbol) state deadline observation regressed behind its monotonic origin."
            }
            $coordinatorElapsedSeconds = Get-CoordinatorElapsedSeconds -State $state -ObservedTick $stateDeadlineObservedTick
            if (-not $state.Exited -and -not $state.FailureValidated -and
                $coordinatorElapsedSeconds -lt ($TotalSeconds - 5)) {
                if ($state.LastHeartbeatTick -eq 0 -and $coordinatorElapsedSeconds -gt $StartupDeadlineSeconds) {
                    throw "$($state.Symbol) did not emit a campaign heartbeat before startup deadline."
                }
                if ($state.LastHeartbeatTick -gt 0 -and
                    ([double]($stateDeadlineObservedTick - $state.LastHeartbeatTick) / $monotonicFrequency) -gt $HeartbeatDeadlineSeconds) {
                    throw "$($state.Symbol) campaign heartbeat became stale."
                }
                if (-not $state.Ready -and $coordinatorElapsedSeconds -gt $StartupDeadlineSeconds) {
                    throw "$($state.Symbol) did not reach semantic readiness before startup deadline."
                }
                if ($state.LastSemanticTick -gt 0 -and
                    ([double]($stateDeadlineObservedTick - $state.LastSemanticTick) / $monotonicFrequency) -gt $SemanticDeadlineSeconds) {
                    throw "$($state.Symbol) durable child heartbeat became stale."
                }
            }
        }

        $postReadTick = Get-MonotonicTick
        if (-not $captureDrainingEventWritten -and
            (Get-CaptureElapsedSeconds -ObservedTick $postReadTick) -ge ($TotalSeconds - 5)) {
            Ensure-CaptureDraining -ObservedTick $postReadTick
        }

        # This value must be derived after both journals and any same-poll exit
        # tails were consumed.  A stale pre-read value can skip the stage or
        # trigger a false generation-terminal timeout.
        $allGenerationTerminalEvidence = Test-AllGenerationTerminalEvidence
        if ($allGenerationTerminalEvidence -and $terminalEvaluationStartedTick -eq 0) {
            $terminalEvaluationStartedTick = Get-MonotonicTick
            if (-not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks ([long]($terminalEvaluationStartedTick - $captureOriginTick)) `
                -TimeoutSeconds ([uint64]($TotalSeconds + $GenerationTerminalDeadlineSeconds)))) {
                throw "Final generation terminal evidence arrived after the exact ${GenerationTerminalDeadlineSeconds}-second post-capture deadline."
            }
            Write-LauncherEvent -Channel "PROCESS" -Payload ([ordered]@{
                event = "CAMPAIGN_TERMINAL_EVALUATION_STARTED"
                commit_deadline_s = [uint64]$CampaignCommitDeadlineSeconds
            }) -MonotonicTick $terminalEvaluationStartedTick
            Write-GuardianPulse -Stage "TERMINAL_EVALUATION"
        }

        if (-not $bindingsWritten -and @($states.Values | Where-Object { -not $_.Ready }).Count -eq 0) {
            $bindings = [ordered]@{
                schema = "RawQualificationCampaignBindingsV1"
                run_id = $runId
                bound_utc = [DateTimeOffset]::UtcNow.ToString("o")
                campaigns = @($states.Values | Sort-Object Symbol | ForEach-Object {
                    [ordered]@{
                        symbol = $_.Symbol
                        pid = $_.ProcessId
                        campaign_id = $_.CampaignId
                        campaign_directory = $_.CampaignDirectory
                        campaign_startup_sha256 = $_.CampaignStartupSha256
                    }
                })
            }
            $bindingsSha256 = Write-RawQualificationDurableNewJson -Path (Join-Path $runRoot "campaign-bindings.json") -Value $bindings
            Write-LauncherEvent -Channel "SEMANTIC" -Payload ([ordered]@{ event = "DUAL_SEMANTIC_READINESS"; bindings_sha256 = $bindingsSha256 })
            $bindingsWritten = $true
            # READY is an externally actionable publication boundary.  Run the
            # bounded provider first, drain/revalidate both live campaign states,
            # then seal that refreshed summary with the provider proof.  Thus an
            # immediate monitor cannot see only the earlier pre-readiness sample.
            # Advancing the cadence cursor prevents a duplicate in this loop.
            $readinessProbe = Invoke-BoundedHostTelemetryProbe
            $readinessHostReceipt = Write-HostTelemetrySample `
                -Probe $readinessProbe `
                -PreCommitAction { $null = Assert-DualReadinessPublicationCurrent }
            $readinessPublicationTick = Assert-DualReadinessPublicationCurrent
            if ([uint64]$readinessPublicationTick -le [uint64]$readinessHostReceipt.monotonic_tick) {
                throw "Post-telemetry readiness revalidation did not advance beyond its durable host sample."
            }
            Write-LauncherEvent -Channel "SEMANTIC" -Payload ([ordered]@{
                event = "DUAL_READINESS_PUBLISHED"
                bindings_sha256 = [string]$bindingsSha256
                host_telemetry_record_index = [uint64]$readinessHostReceipt.record_index
                host_telemetry_record_sha256 = [string]$readinessHostReceipt.record_sha256
                host_telemetry_monotonic_tick = [uint64]$readinessHostReceipt.monotonic_tick
            }) -MonotonicTick ([uint64]$readinessPublicationTick)
            $lastTelemetryTick = Get-MonotonicTick
            Write-Host "READY: BTCUSDT and ETHUSDT are connected, snapshotted and durably heartbeating. Evidence: $runRoot"
        }
        elseif (([double]($nowTick - $lastTelemetryTick) / $monotonicFrequency) -ge $TelemetryIntervalSeconds) {
            $null = Write-HostTelemetrySample
            $lastTelemetryTick = Get-MonotonicTick
        }
        if (([double]($nowTick - $lastConsoleTick) / $monotonicFrequency) -ge $TelemetryIntervalSeconds) {
            $freeGiB = [uint64]$lastObservedFreeGiB
            $consoleUtc = [DateTimeOffset]::UtcNow.ToString(
                "yyyy-MM-dd HH:mm:ss'Z'",
                [Globalization.CultureInfo]::InvariantCulture)
            Write-Host ("{0} elapsed={1}s ready={2}/2 running={3}/2 free_GiB={4}" -f `
                $consoleUtc,
                [uint64](Get-CaptureElapsedSeconds -ObservedTick $nowTick),
                @($states.Values | Where-Object { $_.Ready }).Count,
                @($states.Values | Where-Object { -not $_.Exited }).Count,
                $freeGiB)
            $lastConsoleTick = $nowTick
        }
        if (-not $allGenerationTerminalEvidence -and
            (Get-CaptureElapsedSeconds -ObservedTick $postReadTick) -gt ($TotalSeconds + $GenerationTerminalDeadlineSeconds)) {
            throw "Final generations did not publish exact PROCESS_TERMINAL/GENERATION_EXITED evidence within ${GenerationTerminalDeadlineSeconds} seconds."
        }
        if ($terminalEvaluationStartedTick -ne 0 -and
            @($states.Values | Where-Object { -not $_.Exited }).Count -gt 0) {
            $campaignCommitDeadlineObservedTick = Get-MonotonicTick
            if ($campaignCommitDeadlineObservedTick -lt $terminalEvaluationStartedTick) {
                throw "Campaign commit deadline observation regressed behind terminal evaluation start."
            }
            if (-not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks ([long]($campaignCommitDeadlineObservedTick - $terminalEvaluationStartedTick)) `
                -TimeoutSeconds ([uint64]$CampaignCommitDeadlineSeconds))) {
                throw "Campaign coordinator did not evaluate/commit/exit within its separate ${CampaignCommitDeadlineSeconds}-second deadline."
            }
        }
        foreach ($exitedState in @($states.Values | Where-Object { $_.Exited })) {
            if ($terminalEvaluationStartedTick -ne 0 -and
                [uint64]$exitedState.ExitObservedTick -gt $terminalEvaluationStartedTick -and
                -not (Test-RawQualificationDeadlineTicks `
                    -ElapsedTicks ([long]([uint64]$exitedState.ExitObservedTick - $terminalEvaluationStartedTick)) `
                    -TimeoutSeconds ([uint64]$CampaignCommitDeadlineSeconds))) {
                throw "$($exitedState.Symbol) coordinator exit was observed after the exact terminal-evaluation deadline."
            }
        }
    }

    if (-not $bindingsWritten) { throw "Dual semantic readiness was never durably bound." }
    if (-not (Test-AllGenerationTerminalEvidence) -or
        -not $captureDrainingEventWritten -or
        $captureDrainingStartedTick -eq 0 -or
        $terminalEvaluationStartedTick -eq 0 -or
        $captureDrainingStartedTick -gt $terminalEvaluationStartedTick) {
        throw "Independent verification cannot start without ordered CAPTURE_DRAINING and fresh terminal-evaluation evidence."
    }
    $dualCoordinatorDrainOriginTick = [uint64](($states.Values | Measure-Object -Property ExitObservedTick -Maximum).Maximum)
    if ($dualCoordinatorDrainOriginTick -eq 0) {
        throw "Dual coordinator drain lacks the exact latest process-exit observation origin."
    }
    if ($workloadJobHandle -eq [IntPtr]::Zero -or
        [string]::IsNullOrWhiteSpace($workloadJobName)) {
        throw "Dual coordinator drain lacks its exact retained workload Job."
    }
    $coordinatorJobDrainDeadlineSeconds = [uint64]10
    $jobDrainInitialActiveProcesses = $null
    $jobDrainFinalActiveProcesses = [uint32]0
    $jobDrainObservationCount = [uint64]0
    $jobDrainPreviousActiveProcesses = $null
    $jobDrainFinalQueryObservedTick = [uint64]0
    $jobDrainWatchdogLivenessObservedTick = [uint64]0
    $jobDrainElapsedTicks = [long]0
    $jobDrainWatchdogPreQuerySignaled = $false
    $jobDrainWatchdogPostQuerySignaled = $false
    while ($true) {
        $jobDrainWatchdogPreQuerySignaled =
            [RawQualificationNative]::WaitForProcessExit($watchdogLaunch.ProcessHandle, 0)
        if ($jobDrainWatchdogPreQuerySignaled) {
            throw "The exact retained watchdog exited before coordinator Job-drain observation."
        }

        $jobDrainFinalActiveProcesses =
            [uint32][RawQualificationNative]::GetActiveProcessCount($workloadJobHandle)
        $jobDrainFinalQueryObservedTick = Get-MonotonicTick
        $jobDrainWatchdogPostQuerySignaled =
            [RawQualificationNative]::WaitForProcessExit($watchdogLaunch.ProcessHandle, 0)
        $jobDrainWatchdogLivenessObservedTick = Get-MonotonicTick
        $jobDrainElapsedTicks = [long]($jobDrainWatchdogLivenessObservedTick - $dualCoordinatorDrainOriginTick)
        $jobDrainObservationCount = [uint64]($jobDrainObservationCount + 1)

        if ($null -eq $jobDrainInitialActiveProcesses) {
            $jobDrainInitialActiveProcesses = [uint32]$jobDrainFinalActiveProcesses
        }
        if ($jobDrainWatchdogPostQuerySignaled) {
            throw "The exact retained watchdog exited during coordinator Job-drain observation."
        }
        if ($null -ne $jobDrainPreviousActiveProcesses -and
            $jobDrainFinalActiveProcesses -gt [uint32]$jobDrainPreviousActiveProcesses) {
            throw "The coordinator workload Job active-process count increased after both coordinators exited."
        }
        $jobDrainPreviousActiveProcesses = [uint32]$jobDrainFinalActiveProcesses
        if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $jobDrainElapsedTicks `
            -TimeoutSeconds $coordinatorJobDrainDeadlineSeconds)) {
            throw "The coordinator workload Job did not drain to zero within the monotonic deadline."
        }
        if ($jobDrainFinalActiveProcesses -eq 0) { break }
        Start-Sleep -Milliseconds 100
    }
    $minimumJobDrainObservations = if ([uint32]$jobDrainInitialActiveProcesses -eq 0) {
        [uint64]1
    }
    else { [uint64]2 }
    if ($jobDrainFinalActiveProcesses -ne 0 -or
        [uint32]$jobDrainInitialActiveProcesses -lt [uint32]$jobDrainFinalActiveProcesses -or
        $jobDrainObservationCount -lt $minimumJobDrainObservations -or
        $jobDrainObservationCount -eq 0 -or
        $jobDrainFinalQueryObservedTick -lt $dualCoordinatorDrainOriginTick -or
        $jobDrainWatchdogLivenessObservedTick -lt $jobDrainFinalQueryObservedTick -or
        $jobDrainWatchdogPreQuerySignaled -or
        $jobDrainWatchdogPostQuerySignaled -or
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $jobDrainElapsedTicks `
            -TimeoutSeconds $coordinatorJobDrainDeadlineSeconds)) {
        throw "The workload Job lacks exact bounded empty-drain evidence with a live retained watchdog."
    }
    $verificationStopwatch = [Diagnostics.Stopwatch]::StartNew()
    $independentVerificationStartedTick = Get-MonotonicTick
    if ($independentVerificationStartedTick -lt $terminalEvaluationStartedTick -or
        $independentVerificationStartedTick -lt $jobDrainWatchdogLivenessObservedTick) {
        throw "Independent verification monotonic stage ordering regressed."
    }
    Write-LauncherEvent -Channel "VERIFICATION" -Payload ([ordered]@{
        event = "INDEPENDENT_VERIFICATION_STAGE_STARTED"
        deadline_s = [uint64]$PostVerificationDeadlineSeconds
        coordinator_job_drain_contract = "RawQualificationCoordinatorWorkloadJobDrainV3"
        coordinator_job_scope = "INNER_WORKLOAD_ONLY"
        coordinator_job_name = $workloadJobName
        coordinator_job_drain_origin_kind = "MAX_COORDINATOR_EXIT_OBSERVATION"
        coordinator_job_drain_deadline_s = [uint64]$coordinatorJobDrainDeadlineSeconds
        coordinator_job_drain_origin_monotonic_tick = [uint64]$dualCoordinatorDrainOriginTick
        coordinator_job_initial_active_processes = [uint32]$jobDrainInitialActiveProcesses
        coordinator_job_final_active_processes = [uint32]$jobDrainFinalActiveProcesses
        coordinator_job_observation_count = [uint64]$jobDrainObservationCount
        coordinator_job_final_query_observed_monotonic_tick = [uint64]$jobDrainFinalQueryObservedTick
        coordinator_job_watchdog_liveness_observed_monotonic_tick = [uint64]$jobDrainWatchdogLivenessObservedTick
        coordinator_job_drain_elapsed_ticks = [long]$jobDrainElapsedTicks
        coordinator_job_drain_elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds `
            -ElapsedTicks $jobDrainElapsedTicks `
            -Frequency ([long]$monotonicFrequency)
        coordinator_job_monotonic_frequency = [long]$monotonicFrequency
        coordinator_job_watchdog_pid = [uint32]$watchdogIdentity.pid
        coordinator_job_watchdog_pre_query_signaled = [bool]$jobDrainWatchdogPreQuerySignaled
        coordinator_job_watchdog_post_query_signaled = [bool]$jobDrainWatchdogPostQuerySignaled
        coordinator_job_drain_result = "WORKLOAD_EMPTY_WATCHDOG_ALIVE"
    }) -MonotonicTick $independentVerificationStartedTick
    Write-GuardianPulse -Stage "INDEPENDENT_VERIFICATION"
    $verificationRoot = Join-Path $runRoot "independent-verification"
    $null = New-Item -ItemType Directory -Path $verificationRoot -ErrorAction Stop
    foreach ($state in $states.Values | Sort-Object Symbol) {
            $processRecord = @($processRecords | Where-Object { $_.symbol -eq $state.Symbol })
            if ($processRecord.Count -ne 1) { throw "$($state.Symbol) lacks one exact process-control record." }
            $stderrPath = Join-Path $runRoot ([string]$processRecord[0].stderr_file)
            $finalCoordinatorLogs = Assert-StateCoordinatorLogsBounded -State $state
            Read-StateOutput -State $state
            Read-StateCampaignEvents -State $state
            Assert-StateCampaignFailureContract -State $state
            $finalCoordinatorLogs = Assert-StateCoordinatorLogsBounded -State $state
            if (-not $state.ProcessTerminal -or
                $state.GenerationTerminals.Count -ne $state.GenerationDurations.Count -or
                $state.GenerationExited.Count -ne $state.GenerationDurations.Count -or
                -not $state.CampaignCommitted) {
                throw "$($state.Symbol) exited without exact per-generation PROCESS_TERMINAL/GENERATION_EXITED and CAMPAIGN_COMMITTED evidence."
            }
            if ([uint64]$state.ChildStderrEvents -ne 0) {
                throw "$($state.Symbol) campaign journal contains forbidden CHILD_STDERR evidence."
            }
            $manifestPath = Join-Path $state.CampaignDirectory "campaign.json"
            if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
                throw "$($state.Symbol) exited successfully without campaign.json."
            }
            $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($manifest.schema -ne "RawCampaignManifestV1" -or
                $manifest.status -ne "COMPLETE" -or
                $manifest.symbol -ne $state.Symbol -or
                [uint64]$manifest.total_duration_s -ne [uint64]$TotalSeconds -or
                [uint64]$manifest.rotation_s -ne [uint64]$RotationSeconds -or
                [uint64]$manifest.overlap_s -ne [uint64]$OverlapSeconds -or
                [uint64]$manifest.segment_s -ne [uint64]$SegmentSeconds -or
                $manifest.journal_file -ne "campaign-events.jsonl" -or
                $manifest.journal_boundary -ne "PRECOMMIT_PREFIX" -or
                [uint64]$manifest.journal_precommit_records -lt 1 -or
                [string]$manifest.journal_precommit_sha256 -notmatch '^[0-9a-f]{64}$' -or
                [uint64]$manifest.supervisor_gap_count -ne 0 -or
                $manifest.credentials -ne "NONE" -or
                $manifest.order_entry -ne "ABSENT" -or
                @($manifest.generations).Count -lt 1 -or
                @($manifest.handovers).Count -ne (@($manifest.generations).Count - 1)) {
                throw "$($state.Symbol) terminal campaign manifest is incomplete or inconsistent."
            }
            $campaignManifestSha256 = Get-RawQualificationSha256File -Path $manifestPath
            if ($campaignManifestSha256 -ne $state.CommitManifestSha256) {
                throw "$($state.Symbol) campaign.json differs from its exact CAMPAIGN_COMMITTED record."
            }
            $generationScheduleClassification = Get-RawQualificationGenerationScheduleClassification `
                -Mode $Mode `
                -Generations ([uint64]@($manifest.generations).Count) `
                -Handovers ([uint64]@($manifest.handovers).Count) `
                -PlannedGenerationLaunches ([uint64]$state.PlannedGenerationLaunches) `
                -ServerShutdownGenerationLaunches ([uint64]$state.ServerShutdownGenerationLaunches) `
                -ServerShutdownSupervisorEvents ([uint64]$state.ServerShutdownSupervisorEvents) `
                -ServerShutdownDurableEvents ([uint64]$state.ServerShutdownDurableEvents)
            $requiredTerminalTopology = Get-RawQualificationRequiredTerminalTopology `
                -Mode $Mode -TotalSeconds ([uint64]$TotalSeconds) `
                -RotationSeconds ([uint64]$RotationSeconds) `
                -OverlapSeconds ([uint64]$OverlapSeconds) `
                -SegmentSeconds ([uint64]$SegmentSeconds)
            $terminalTopologyMatches = Test-RawQualificationRequiredTerminalTopology `
                -Topology $requiredTerminalTopology `
                -Generations ([uint64]@($manifest.generations).Count) `
                -Handovers ([uint64]@($manifest.handovers).Count) `
                -PlannedGenerationLaunches ([uint64]$state.PlannedGenerationLaunches) `
                -ServerShutdownGenerationLaunches ([uint64]$state.ServerShutdownGenerationLaunches) `
                -ServerShutdownSupervisorEvents ([uint64]$state.ServerShutdownSupervisorEvents) `
                -ServerShutdownDurableEvents ([uint64]$state.ServerShutdownDurableEvents)
            if (-not $terminalTopologyMatches) {
                $qualificationDeviationReasons += (
                    "$($state.Symbol)/$($requiredTerminalTopology.profile): generations=$(@($manifest.generations).Count), " +
                    "handovers=$(@($manifest.handovers).Count), planned_launches=$($state.PlannedGenerationLaunches), " +
                    "server_shutdown_launches=$($state.ServerShutdownGenerationLaunches), " +
                    "server_shutdown_supervisor_events=$($state.ServerShutdownSupervisorEvents), " +
                    "server_shutdown_durable_events=$($state.ServerShutdownDurableEvents)")
            }
            $clockTelemetryRecords = [uint64]0
            foreach ($generation in @($manifest.generations)) {
                $portableSession = [string]$generation.session_dir
                if ([string]::IsNullOrWhiteSpace($portableSession) -or
                    [IO.Path]::IsPathRooted($portableSession) -or
                    $portableSession -match '(^|[\\/])\.\.([\\/]|$)' -or
                    $portableSession -notmatch '^generations[\\/][^\\/]+$') {
                    throw "$($state.Symbol) generation session_dir is not one portable contained path."
                }
                $absoluteSession = [IO.Path]::GetFullPath((Join-Path $state.CampaignDirectory $portableSession))
                $campaignPrefix = [IO.Path]::GetFullPath($state.CampaignDirectory).TrimEnd('\') + '\'
                if (-not $absoluteSession.StartsWith($campaignPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "$($state.Symbol) generation session_dir escaped its campaign directory."
                }
                $clockTelemetryRecords = [uint64]($clockTelemetryRecords + (Assert-GenerationClockUnambiguous -GenerationDirectory $absoluteSession))
            }

            $pythonRuntimeBeforeRust = Get-BoundedPythonRuntimeFingerprint
            if ($pythonRuntimeBeforeRust.tree_sha256 -ne $preflight.python_runtime.tree_sha256 -or
                [uint64]$pythonRuntimeBeforeRust.file_count -ne [uint64]$preflight.python_runtime.file_count -or
                [uint64]$pythonRuntimeBeforeRust.total_bytes -ne [uint64]$preflight.python_runtime.total_bytes -or
                $pythonRuntimeBeforeRust.pyvenv_config_sha256 -ne $preflight.python_runtime.pyvenv_config_sha256 -or
                $pythonRuntimeBeforeRust.base_executable_sha256 -ne $preflight.python_runtime.base_executable_sha256) {
                throw "Python verifier base runtime drifted before independent oracle invocation."
            }

            if ((Get-RawQualificationSha256File -Path $preflight.campaign_verifier_executable) -ne $preflight.campaign_verifier_executable_sha256) {
                throw "Rust campaign verifier drifted before invocation."
            }
            $rustBudgetComputedTick = Get-MonotonicTick
            $rustGlobalElapsedSeconds = [double]($rustBudgetComputedTick - $independentVerificationStartedTick) /
                [double]$monotonicFrequency
            $remainingVerifierSeconds = [int][math]::Floor(
                $PostVerificationDeadlineSeconds - $rustGlobalElapsedSeconds)
            if ($remainingVerifierSeconds -lt 60) { throw "Independent campaign verification exhausted its total bounded deadline." }
            $rustTimeout = [math]::Min($IndependentVerifierTimeoutSeconds, $remainingVerifierSeconds)
            $prefix = $state.Symbol.ToLowerInvariant()
            $rustReportPath = Join-Path $verificationRoot ($prefix + "-rust-report.json")
            $rustExecution = Invoke-BoundedRawCampaignVerifier `
                -Name ($prefix + "-rust") `
                -Executable $preflight.campaign_verifier_executable `
                -Arguments ([string[]]@($state.CampaignDirectory, $rustReportPath)) `
                -OutputDirectory $verificationRoot `
                -ReportPath $rustReportPath `
                -TimeoutSeconds $rustTimeout `
                -GlobalBudgetComputedMonotonicTick $rustBudgetComputedTick
            $rustReport = Get-Content -LiteralPath $rustReportPath -Raw -Encoding UTF8 | ConvertFrom-Json

            $pythonTreeNow = Get-RawQualificationSourceTreeDigest -Root $preflight.python_verifier_source.root
            $pythonRuntimeNow = Get-BoundedPythonRuntimeFingerprint
            if ($pythonTreeNow.tree_sha256 -ne $preflight.python_verifier_source.tree_sha256 -or
                $pythonRuntimeNow.tree_sha256 -ne $preflight.python_runtime.tree_sha256 -or
                [uint64]$pythonRuntimeNow.file_count -ne [uint64]$preflight.python_runtime.file_count -or
                [uint64]$pythonRuntimeNow.total_bytes -ne [uint64]$preflight.python_runtime.total_bytes -or
                $pythonRuntimeNow.pyvenv_config_sha256 -ne $preflight.python_runtime.pyvenv_config_sha256 -or
                $pythonRuntimeNow.base_executable_sha256 -ne $preflight.python_runtime.base_executable_sha256 -or
                (Get-RawQualificationSha256File -Path $preflight.python) -ne $preflight.python_sha256 -or
                (Get-RawQualificationSha256File -Path $preflight.python_project) -ne $preflight.python_project_sha256 -or
                (Get-RawQualificationSha256File -Path $preflight.python_requirements) -ne $preflight.python_requirements_sha256) {
                throw "Python verifier executable/source/lock drifted before invocation."
            }
            $pythonBudgetComputedTick = Get-MonotonicTick
            $pythonGlobalElapsedSeconds = [double]($pythonBudgetComputedTick - $independentVerificationStartedTick) /
                [double]$monotonicFrequency
            $remainingVerifierSeconds = [int][math]::Floor(
                $PostVerificationDeadlineSeconds - $pythonGlobalElapsedSeconds)
            if ($remainingVerifierSeconds -lt 60) { throw "Independent campaign verification exhausted its total bounded deadline." }
            $pythonTimeout = [math]::Min($IndependentVerifierTimeoutSeconds, $remainingVerifierSeconds)
            $pythonReportPath = Join-Path $verificationRoot ($prefix + "-python-report.json")
            $isolatedPythonBootstrap = "import runpy,sys;sys.dont_write_bytecode=True;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('binance_lob.raw_verify_cli',run_name='__main__')"
            $pythonExecution = Invoke-BoundedRawCampaignVerifier `
                -Name ($prefix + "-python") `
                -Executable $preflight.python `
                -Arguments ([string[]]@(
                    "-I", "-P", "-S", "-B", "-c", $isolatedPythonBootstrap,
                    $preflight.python_verifier_source.root,
                    $state.CampaignDirectory,
                    "--output", $pythonReportPath
                )) `
                -OutputDirectory $verificationRoot `
                -ReportPath $pythonReportPath `
                -TimeoutSeconds $pythonTimeout `
                -GlobalBudgetComputedMonotonicTick $pythonBudgetComputedTick
            $pythonReport = Get-Content -LiteralPath $pythonReportPath -Raw -Encoding UTF8 | ConvertFrom-Json

            if ($rustReport.schema -ne "VerifiedRawCampaignV1" -or
                $rustReport.status -ne "PASS" -or
                $rustReport.campaign_id -ne $state.CampaignId -or
                $rustReport.symbol -ne $state.Symbol -or
                [uint64]$rustReport.total_duration_s -ne [uint64]$TotalSeconds -or
                [uint64]$rustReport.rotation_s -ne [uint64]$RotationSeconds -or
                [uint64]$rustReport.overlap_s -ne [uint64]$OverlapSeconds -or
                [uint64]$rustReport.segment_s -ne [uint64]$SegmentSeconds -or
                $rustReport.campaign_manifest_sha256 -ne $campaignManifestSha256 -or
                [uint64]$rustReport.journal_records -ne [uint64]$state.EventNextIndex -or
                $rustReport.journal_terminal_sha256 -ne $state.EventPrevious -or
                @($rustReport.generations).Count -ne @($manifest.generations).Count -or
                [uint64]$rustReport.handovers -ne [uint64](@($manifest.handovers).Count) -or
                [string]$rustReport.verification_sha256 -notmatch '^[0-9a-f]{64}$') {
                throw "$($state.Symbol) Rust independent campaign verifier report is inconsistent."
            }
            if ($pythonReport.schema -ne "RawCampaignVerificationV1" -or
                $pythonReport.status -ne "VERIFIED" -or
                $pythonReport.campaign_id -ne $state.CampaignId -or
                $pythonReport.symbol -ne $state.Symbol -or
                [uint64]$pythonReport.total_duration_s -ne [uint64]$TotalSeconds -or
                [uint64]$pythonReport.rotation_s -ne [uint64]$RotationSeconds -or
                [uint64]$pythonReport.overlap_s -ne [uint64]$OverlapSeconds -or
                [uint64]$pythonReport.segment_s -ne [uint64]$SegmentSeconds -or
                $pythonReport.campaign_manifest_file_sha256 -ne $campaignManifestSha256 -or
                [uint64]$pythonReport.journal.records -ne [uint64]$state.EventNextIndex -or
                $pythonReport.journal.terminal_record_sha256 -ne $state.EventPrevious -or
                @($pythonReport.generations).Count -ne @($manifest.generations).Count -or
                @($pythonReport.handovers).Count -ne @($manifest.handovers).Count -or
                [uint64]$pythonReport.supervisor_gap_count -ne 0 -or
                $pythonReport.credentials -ne "NONE" -or
                $pythonReport.order_entry -ne "ABSENT" -or
                [string]$pythonReport.verification_sha256 -notmatch '^[0-9a-f]{64}$') {
                throw "$($state.Symbol) Python independent campaign verifier report is inconsistent."
            }
            if ([uint64]$manifest.journal_precommit_records + 1 -ne [uint64]$rustReport.journal_records) {
                throw "$($state.Symbol) manifest precommit boundary does not precede exactly one commit record."
            }
            $rustGenerationHashes = @($rustReport.generations | Sort-Object generation_index | ForEach-Object { [string]$_.verification_sha256 })
            $pythonGenerationHashes = @($pythonReport.generations | Sort-Object generation_index | ForEach-Object { [string]$_.verification_sha256 })
            if (($rustGenerationHashes -join "`n") -ne ($pythonGenerationHashes -join "`n")) {
                throw "$($state.Symbol) Rust/Python generation verification identities disagree."
            }

            $campaignResult = [pscustomobject][ordered]@{
                symbol = $state.Symbol
                pid = $state.ProcessId
                exit_code = $state.ExitCode
                exit_elapsed_s = [uint64]$state.ExitElapsedS
                coordinator_exit_elapsed_s = [uint64]$state.CoordinatorExitElapsedS
                campaign_id = $state.CampaignId
                campaign_directory = $state.CampaignDirectory
                campaign_manifest_sha256 = $campaignManifestSha256
                campaign_journal_boundary = [string]$manifest.journal_boundary
                campaign_journal_precommit_records = [uint64]$manifest.journal_precommit_records
                campaign_journal_precommit_sha256 = [string]$manifest.journal_precommit_sha256
                campaign_journal_committed_records = [uint64]$rustReport.journal_records
                campaign_journal_terminal_sha256 = [string]$rustReport.journal_terminal_sha256
                generations = @($manifest.generations).Count
                handovers = @($manifest.handovers).Count
                unambiguous_clock_telemetry_records = $clockTelemetryRecords
                generation_schedule_classification = $generationScheduleClassification
                planned_generation_launches = [uint64]$state.PlannedGenerationLaunches
                server_shutdown_generation_launches = [uint64]$state.ServerShutdownGenerationLaunches
                server_shutdown_supervisor_events = [uint64]$state.ServerShutdownSupervisorEvents
                server_shutdown_durable_events = [uint64]$state.ServerShutdownDurableEvents
                child_stderr_events = [uint64]$state.ChildStderrEvents
                rust_verification_sha256 = [string]$rustReport.verification_sha256
                python_verification_sha256 = [string]$pythonReport.verification_sha256
                independent_verifiers = @($rustExecution, $pythonExecution)
                stdout_file = [IO.Path]::GetFileName($state.StdoutState.Path)
                stdout_file_bytes = [uint64]$finalCoordinatorLogs.stdout_bytes
                stdout_file_sha256 = Get-RawQualificationSha256File -Path $state.StdoutState.Path
                stderr_file = [IO.Path]::GetFileName($stderrPath)
                stderr_file_bytes = [uint64]$finalCoordinatorLogs.stderr_bytes
                stderr_file_sha256 = Get-RawQualificationSha256File -Path $stderrPath
            }
            Add-IndependentCampaignVerifiedResult -CampaignResult $campaignResult
    }
    $null = Write-HostTelemetrySample
    $finalVerifierDrainOriginQpcTimestamp = [long][Diagnostics.Stopwatch]::GetTimestamp()
    if ([RawQualificationNative]::WaitForProcessExit($watchdogLaunch.ProcessHandle, 0)) {
        throw "The exact watchdog exited before final workload Job observation."
    }
    $finalActiveProcesses = [uint32][RawQualificationNative]::GetActiveProcessCount($workloadJobHandle)
    $finalVerifierDrainElapsedTicks = [long]([Diagnostics.Stopwatch]::GetTimestamp() - $finalVerifierDrainOriginQpcTimestamp)
    if ($finalActiveProcesses -ne 0 -or
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $finalVerifierDrainElapsedTicks `
            -TimeoutSeconds 10) -or
        [RawQualificationNative]::WaitForProcessExit($watchdogLaunch.ProcessHandle, 0)) {
        throw "The exact workload Job did not remain empty after all independent verifiers."
    }
    Write-LauncherEvent -Channel "CONTROL" -Payload ([ordered]@{
        event = "VERIFIER_DESCENDANTS_DRAINED"
        active_processes = $finalActiveProcesses
        job_scope = "INNER_WORKLOAD_ONLY"
        job_name = $workloadJobName
        drain_origin_qpc_timestamp = [long]$finalVerifierDrainOriginQpcTimestamp
        elapsed_qpc_ticks = [long]$finalVerifierDrainElapsedTicks
        monotonic_frequency = [long][Diagnostics.Stopwatch]::Frequency
        elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds -ElapsedTicks $finalVerifierDrainElapsedTicks
    })
    $verificationRoot = Join-Path $runRoot "independent-verification"
    foreach ($campaignResult in $campaignResults) {
        $campaignManifestPath = Join-Path ([string]$campaignResult.campaign_directory) "campaign.json"
        $campaignStdoutPath = Join-Path $runRoot ([string]$campaignResult.stdout_file)
        $campaignStderrPath = Join-Path $runRoot ([string]$campaignResult.stderr_file)
        if ((Get-RawQualificationSha256File -Path $campaignManifestPath) -ne $campaignResult.campaign_manifest_sha256 -or
            [uint64](Get-Item -LiteralPath $campaignStdoutPath).Length -ne [uint64]$campaignResult.stdout_file_bytes -or
            (Get-RawQualificationSha256File -Path $campaignStdoutPath) -ne $campaignResult.stdout_file_sha256 -or
            [uint64](Get-Item -LiteralPath $campaignStderrPath).Length -ne 0 -or
            (Get-RawQualificationSha256File -Path $campaignStderrPath) -ne $campaignResult.stderr_file_sha256) {
            throw "$($campaignResult.symbol) sealed coordinator/campaign artifacts changed after verification."
        }
        foreach ($verifier in @($campaignResult.independent_verifiers)) {
            foreach ($artifact in @(
                [pscustomobject]@{ path = Join-Path $verificationRoot ([string]$verifier.execution_file); hash = [string]$verifier.execution_sha256; bytes = $null },
                [pscustomobject]@{ path = Join-Path $verificationRoot ([string]$verifier.report_file); hash = [string]$verifier.report_sha256; bytes = [uint64]$verifier.report_bytes },
                [pscustomobject]@{ path = Join-Path $verificationRoot ([string]$verifier.stdout_file); hash = [string]$verifier.stdout_sha256; bytes = [uint64]$verifier.stdout_bytes },
                [pscustomobject]@{ path = Join-Path $verificationRoot ([string]$verifier.stderr_file); hash = [string]$verifier.stderr_sha256; bytes = [uint64]$verifier.stderr_bytes }
            )) {
                if ((Get-RawQualificationSha256File -Path $artifact.path) -ne $artifact.hash -or
                    ($null -ne $artifact.bytes -and [uint64](Get-Item -LiteralPath $artifact.path).Length -ne [uint64]$artifact.bytes)) {
                    throw "$($campaignResult.symbol) verifier artifact changed after descendant drain: $($artifact.path)"
                }
            }
        }
    }
    if ($qualificationDeviationReasons.Count -ne 0) {
        throw "Required qualification topology deviated from its exact cardinality/shutdown contract: $($qualificationDeviationReasons -join '; ')"
    }
    if ($captureDrainingStartedTick -eq 0 -or
        $terminalEvaluationStartedTick -eq 0 -or
        $independentVerificationStartedTick -eq 0 -or
        $captureDrainingStartedTick -gt $terminalEvaluationStartedTick -or
        $terminalEvaluationStartedTick -gt $independentVerificationStartedTick) {
        throw "COMPLETE requires all three ordered monotonic terminal stages."
    }
    if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $verificationStopwatch.ElapsedTicks `
            -TimeoutSeconds ([uint64]$PostVerificationDeadlineSeconds)) -or
        ($PostVerificationDeadlineSeconds - $verificationStopwatch.Elapsed.TotalSeconds) -lt ($PythonRuntimeFingerprintTimeoutSeconds + 15)) {
        throw "The global post-capture deadline expired before COMPLETE could be published."
    }
    $captureFreshnessCutoff = [uint64][math]::Max(0, [int64]$TotalSeconds - 5)
    $cleanCaptureStates = @($states.Values | Where-Object {
        $_.Exited -and
        [int]$_.ExitCode -eq 0 -and
        $null -ne $_.ExitElapsedS -and
        [uint64]$_.ExitElapsedS -ge $captureFreshnessCutoff -and
        $null -ne $_.CoordinatorExitElapsedS -and
        [uint64]$_.CoordinatorExitElapsedS -ge $captureFreshnessCutoff
    })
    $cleanResultSymbols = @($campaignResults | ForEach-Object { [string]$_.symbol } | Sort-Object)
    if ($cleanCaptureStates.Count -ne 2 -or
        $campaignResults.Count -ne 2 -or
        ($cleanResultSymbols -join ',') -ne "BTCUSDT,ETHUSDT" -or
        @($campaignResults | Where-Object {
            [int]$_.exit_code -ne 0 -or
            [uint64]$_.exit_elapsed_s -lt $captureFreshnessCutoff -or
            [uint64]$_.coordinator_exit_elapsed_s -lt $captureFreshnessCutoff -or
            [uint64]$_.child_stderr_events -ne 0 -or
            [uint64]$_.stderr_file_bytes -ne 0 -or
            [uint64]$_.stdout_file_bytes -gt [uint64]$MaximumCampaignStdoutBytes
        }).Count -ne 0) {
        throw "COMPLETE requires two exact clean coordinator exit proofs and bounded zero-stderr campaign results."
    }
    $writtenStatus = Write-TerminalManifest `
        -Status "COMPLETE" `
        -Failure $null `
        -FailureContainment $null `
        -FailureContainmentSha256 $null
    $null = Assert-TerminalPublicationAcknowledgement -Actual $writtenStatus -Expected "COMPLETE"
}
catch {
    $originalFailure = $_
    $failureMessage = [string]$originalFailure.Exception.Message
    $failureDetectedWallNs = Get-RawQualificationWallNs
    $failureDetectedMonotonicTick = Get-MonotonicTick

    # First contain the process tree.  Durable publication is intentionally
    # later, so a slow or failing filesystem cannot delay TerminateJobObject.
    $failureContainment = Invoke-LauncherFailureContainment `
        -DetectedWallNs $failureDetectedWallNs `
        -DetectedMonotonicTick $failureDetectedMonotonicTick
    $failureContainmentCompactBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($failureContainment | ConvertTo-Json -Depth 100 -Compress))
    $failureContainmentSha256 = Get-RawQualificationSha256Bytes -Bytes $failureContainmentCompactBytes

    try {
        Write-LauncherEvent -Channel "FAILURE" -Payload ([ordered]@{
            event = "LAUNCHER_FAILED"
            error = $failureMessage
        })
        Write-LauncherEvent -Channel "FAILURE" -Payload ([ordered]@{
            event = "FAILURE_CONTAINMENT_TERMINAL"
            failure_containment_sha256 = [string]$failureContainmentSha256
        })
        $failedWrittenStatus = Write-TerminalManifest `
            -Status "FAILED" `
            -Failure $failureMessage `
            -FailureContainment $failureContainment `
            -FailureContainmentSha256 $failureContainmentSha256
        $null = Assert-TerminalPublicationAcknowledgement -Actual $failedWrittenStatus -Expected "FAILED"
    }
    catch {
        throw "Original launcher failure: $failureMessage Evidence publication failure after containment: $($_.Exception.Message)"
    }
    throw $originalFailure
}
finally {
    if ($null -ne $eventJournal -and -not $eventJournal.Closed) {
        try { Close-RawQualificationJournal -Journal $eventJournal } catch {}
    }
    if ($null -ne $telemetryJournal -and -not $telemetryJournal.Closed) {
        try { Close-RawQualificationJournal -Journal $telemetryJournal } catch {}
    }
    if ($null -ne $guardianPulseJournal -and -not $guardianPulseJournal.Closed) {
        try { Close-RawQualificationJournal -Journal $guardianPulseJournal } catch {}
    }
    if ($null -ne $watchdogReadyStream) {
        try { $watchdogReadyStream.Dispose() } catch {}
    }
    foreach ($handleOwner in @($coordinatorProcessHandleOwners)) {
        if ($null -ne $handleOwner -and -not [bool]$handleOwner.Closed) {
            try { $null = Close-CoordinatorNativeProcessHandle -HandleOwner $handleOwner } catch {}
        }
    }
    if ($null -ne $watchdogLaunch -and $watchdogLaunch.ProcessHandle -ne [IntPtr]::Zero) {
        try { $null = [RawQualificationNative]::CloseRetainedProcessHandle($watchdogLaunch) } catch {}
    }
    if ($workloadJobHandle -ne [IntPtr]::Zero) {
        try { $null = [RawQualificationNative]::CloseHandle($workloadJobHandle) } catch {}
    }
    if ($jobHandle -ne [IntPtr]::Zero) {
        try { $null = [RawQualificationNative]::CloseHandle($jobHandle) } catch {}
    }
    if ($executionStateArmed) {
        try { $null = [RawQualificationNative]::SetThreadExecutionState([RawQualificationNative]::ES_CONTINUOUS) } catch {}
    }
    if ($mutexOwned -and $null -ne $mutex) {
        try { $mutex.ReleaseMutex() } catch {}
    }
    if ($null -ne $mutex) {
        try { $mutex.Dispose() } catch {}
    }
}
try { Write-Host "PASS: $runRoot\launcher-terminal.json" } catch {}
