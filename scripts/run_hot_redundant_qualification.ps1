[CmdletBinding()]
param(
    [ValidateSet("Production", "ValidateOnly", "IntegrationTest", "Continuous")]
    [string] $Mode = "ValidateOnly",

    [ValidateRange(60, 604800)]
    [uint32] $TotalSeconds = 86400,

    [ValidateRange(10, 300)]
    [uint32] $TelemetryIntervalSeconds = 30,

    [ValidateRange(100, 1024)]
    [uint32] $KernelTraceMiB = 256,

    # Continuous mode: bounded duration of every supervisor epoch.  Each
    # epoch's artifact is sealed and verified while the next epoch captures
    # (planned overlap: the successor launches EpochWindowSeconds - overlapS
    # into the epoch, so the symbol's two lanes never stop before the
    # successor is ready).  Milestones (24 h / 7 d / 30 d) aggregate those
    # verified windows and never stop the capture.
    [ValidateRange(20, 604800)]
    [uint32] $EpochWindowSeconds = 14400,

    # TEST-ONLY virtual control clock for milestone scheduling: the
    # service's milestone clock advances TimeScale times faster than wall
    # time (24 h / 7 d / 30 d checks).  Never applied to wall clocks written
    # into evidence, never used outside explicit test invocations (which must
    # also pass -Continuous); the real soak is a separate gate.  TimeScale
    # also unlocks the reduced test topology (20 s epochs, 30/25 s lane
    # rotations) used by the scheduler/fault gates.
    [ValidateRange(1, 3600)]
    [uint32] $TimeScale = 1,

    # TEST-ONLY fault injection overrides (REJECTED in Production): replace
    # the arbitration sidecar or its auditor binary with a test double to
    # exercise crash/hang paths without touching real processes.
    [string] $ArbiterOverride = "",
    [string] $ArbiterVerifyOverride = "",

    # TEST-ONLY: run Continuous without the kernel ETW controller and the
    # network witness (both require elevation).  The terminal records the
    # observer state honestly as SKIPPED_NOT_ELEVATED; it never pretends the
    # elevated gate ran.  Rejected in Production.
    [switch] $SkipKernelObserver,

    # TEST-ONLY: take the release binaries from this directory instead of
    # building into Binance/target/release (the gate script builds the same
    # sources into an isolated CARGO_TARGET_DIR first and records hashes).
    # Rejected in Production.
    [string] $ReleaseBinRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Mode -ceq "Production" -and $TotalSeconds -lt 1800) {
    throw "Production duration must be at least 1800 seconds."
}
if ($Mode -ceq "Continuous" -and $TotalSeconds -ne 86400) {
    # Continuous mode has no global horizon; TotalSeconds keeps its default
    # and must not be used to schedule the end of the service.
    throw "Continuous mode must use the default TotalSeconds; epochs are bounded by EpochWindowSeconds."
}
if ($Mode -ceq "Production") {
    if ($ArbiterOverride -ne "" -or $ArbiterVerifyOverride -ne "" -or $SkipKernelObserver -or $ReleaseBinRoot -ne "") {
        throw "Fault-injection overrides, observer skips and binary-root overrides are rejected in Production."
    }
    if ($TimeScale -ne 1) {
        throw "TimeScale is a TEST-ONLY control clock; Production must use 1."
    }
}
if ($TimeScale -gt 1 -and $Mode -cne "Continuous") {
    # Explicitly test invocations pass -Mode Continuous -TimeScale N.
    throw "TimeScale > 1 requires -Mode Continuous (scheduler test)."
}
if ($Mode -ceq "Continuous" -and $TimeScale -le 1 -and $EpochWindowSeconds -lt 120) {
    throw "Continuous production epochs must be at least 120 seconds; smaller epochs require the test control clock (TimeScale > 1)."
}
$isContinuous = $Mode -ceq "Continuous"
$isTestClock = $TimeScale -gt 1
# Milestone scheduling clock: scaled only under the TEST-ONLY control clock.
$milestoneClockScale = if ($isTestClock) { [double]$TimeScale } else { 1.0 }
# Test topology (TimeScale > 1): the IntegrationTest-proven short windows.
$primaryRotationS = if ($Mode -ceq "IntegrationTest" -or $isTestClock) { [uint32]30 } else { [uint32]82800 }
$shadowRotationS = if ($Mode -ceq "IntegrationTest" -or $isTestClock) { [uint32]20 } else { [uint32]81900 }
$overlapS = if ($Mode -ceq "IntegrationTest" -or $isTestClock) { [uint32]10 } else { [uint32]900 }
$segmentS = $overlapS
# Endurance lane-window renewal (ADR-15 / DECISION_ENDURANCE_LANE_WINDOW_RENEWAL_V1):
# a bounded, distinct window per lane means one silent market black-hole can
# only cost the current window; the failed lane restarts a fresh verified
# campaign (fresh connections, snapshot bootstrap, new lineage) while the
# sibling lane keeps coverage.  The historical single 24h window lost the
# whole qualification to one stream death at 22.4h/24.0h because the
# generation contract forbids bridging an unproven interval inside a campaign.
$primaryWindowS = if ($Mode -ceq "IntegrationTest" -or $isTestClock) { [uint32]100 } else { [uint32]14400 }
$shadowWindowS = if ($Mode -ceq "IntegrationTest" -or $isTestClock) { [uint32]90 } else { [uint32]14040 }
if ($isContinuous) {
    if ($EpochWindowSeconds -le $overlapS) {
        throw "EpochWindowSeconds must exceed the overlap window."
    }
}

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")
Initialize-RawQualificationNative

# TEST-ONLY deterministic disk-sensor overrides (fixture injection, ADR-17
# B2 storage safe-stop): BINANCE_LOB_TEST_FREE_GIB_PREFLIGHT replaces the
# preflight free-space reading, BINANCE_LOB_TEST_FREE_GIB_TELEMETRY replaces
# the per-tick telemetry reading. Honored ONLY in test invocations that pass
# -ReleaseBinRoot (a TEST-ONLY marker already rejected in Production); the
# real disk is never filled and the host WMI reading is never altered.
$testFreeGiBPreflight = $null
$testFreeGiBTelemetry = $null
foreach ($pair in @(
    @{ Name = "BINANCE_LOB_TEST_FREE_GIB_PREFLIGHT"; Slot = "preflight" },
    @{ Name = "BINANCE_LOB_TEST_FREE_GIB_TELEMETRY"; Slot = "telemetry" }
)) {
    $raw = [string][Environment]::GetEnvironmentVariable($pair.Name)
    if ($raw -ne "") {
        if ($ReleaseBinRoot -eq "") {
            throw ("{0} is a TEST-ONLY disk-sensor override and requires -ReleaseBinRoot." -f $pair.Name)
        }
        if ($raw -notmatch '^\d{1,9}$') {
            throw ("{0} must be a non-negative integer (GiB)." -f $pair.Name)
        }
        if ($pair.Slot -ceq "preflight") { $testFreeGiBPreflight = [uint64]$raw }
        else { $testFreeGiBTelemetry = [uint64]$raw }
    }
}

$cargo = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
# TEST-ONLY binary-root override: gate runs build the same sources into an
# isolated CARGO_TARGET_DIR and point the service at those release binaries
# (never touching Binance/target outside the final frozen delivery build).
$releaseBinRoot = if ($ReleaseBinRoot -ne "") {
    [IO.Path]::GetFullPath($ReleaseBinRoot)
} else {
    Join-Path $repo "target\release"
}
$capture = Join-Path $releaseBinRoot "hot_redundant_capture.exe"
$rustVerifier = Join-Path $releaseBinRoot "hot_redundant_verify.exe"
$kernelTrace = Join-Path $releaseBinRoot "kernel_network_trace.exe"
$liveArbiter = Join-Path $releaseBinRoot "live_arbitration.exe"
$liveArbiterVerify = Join-Path $releaseBinRoot "live_arbitration_verify.exe"
$python = Join-Path $repo ".venv\Scripts\python.exe"
$publicConfig = Join-Path $repo "config\public.json"
$sourceLock = Join-Path $repo "..\BINANCE_SOURCE_LOCK.md"
$networkWitnessScript = Join-Path $PSScriptRoot "RawQualification.NetworkWitness.ps1"
$systemEvidenceScript = Join-Path $PSScriptRoot "RawQualification.SystemEvidence.ps1"
$tracerpt = Join-Path $env:SystemRoot "System32\tracerpt.exe"
$logman = Join-Path $env:SystemRoot "System32\logman.exe"

foreach ($path in @(
    $cargo, $python, $publicConfig, $sourceLock, $networkWitnessScript,
    $systemEvidenceScript, $tracerpt, $logman
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required hot-redundant qualification input is absent: $path"
    }
}
function Invoke-ExactProcess {
    param(
        [Parameter(Mandatory = $true)] [string] $Executable,
        [Parameter(Mandatory = $true)] [string[]] $Arguments,
        [switch] $AllowStderr
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.WorkingDirectory = $repo
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Arguments = [string]::Join(
        " ",
        [string[]]@($Arguments | ForEach-Object {
            [RawQualificationNative]::QuoteExactArgument([string]$_)
        })
    )
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw "Process.Start returned false: $Executable" }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0 -or (-not $AllowStderr -and $stderr.Length -ne 0)) {
            throw "Command failed ($($process.ExitCode)): $Executable $([string]::Join(' ', $Arguments)); stderr=$stderr; stdout=$stdout"
        }
        return $stdout
    }
    finally { $process.Dispose() }
}

function Get-ServicePythonSourceFingerprint {
    $sourceRoot = Join-Path $repo "src\binance_lob"
    $rows = [Collections.Generic.List[string]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Filter "*.py" -ErrorAction Stop | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($sourceRoot.Length + 1).Replace('\', '/')
        $rows.Add(("{0}`t{1}`t{2}" -f $relative, [uint64]$file.Length, (Get-RawQualificationSha256File -Path $file.FullName)))
    }
    if ($rows.Count -eq 0) { throw "Python verifier source inventory is empty." }
    $material = [Text.UTF8Encoding]::new($false).GetBytes(([string]::Join("`n", $rows) + "`n"))
    return [ordered]@{
        root = $sourceRoot; files = [uint32]$rows.Count
        tree_sha256 = Get-RawQualificationSha256Bytes -Bytes $material
    }
}

if ($ReleaseBinRoot -eq "") {
    # The service builds its own release binaries from the current sources
    # (same-binary guarantee).  TEST-ONLY runs with -ReleaseBinRoot skip
    # this step because the gate script already built the same sources into
    # the isolated target and recorded the hashes.
    $null = Invoke-ExactProcess -Executable $cargo -Arguments ([string[]]@(
        "build", "--release", "-p", "lob-replay", "--bin", "hot_redundant_capture",
        "--bin", "hot_redundant_verify", "--bin", "raw_campaign", "--bin",
        "segmented_capture", "--bin", "campaign_verify", "--bin", "kernel_network_trace",
        "--bin", "live_arbitration", "--bin", "live_arbitration_verify"
    )) -AllowStderr
}

foreach ($path in @($capture, $rustVerifier, $kernelTrace, $liveArbiter, $liveArbiterVerify)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required release binary was not produced: $path"
    }
}

$clock = Get-RawQualificationClockStatus
Assert-RawQualificationClockHealthy -Clock $clock
$drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
$freeGiB = if ($null -ne $testFreeGiBPreflight) {
    [uint64]$testFreeGiBPreflight
} else {
    [uint64][Math]::Floor([double]$drive.FreeSpace / 1GB)
}
# Previous measured dual-symbol single-lane production traffic was bounded at
# 2 GiB/hour.  Two independent lanes double it; the factor of two below is a
# qualification reserve, not a throughput claim.
$projectedGiB = [uint64][Math]::Ceiling((4.0 * ([double]$TotalSeconds / 3600.0)) * 2.0)
$persistentReserveGiB = [uint64]100
$requiredGiB = [uint64]($projectedGiB + $persistentReserveGiB)
if ($freeGiB -lt $requiredGiB) {
    throw "Insufficient disk for redundant qualification: free=${freeGiB}GiB required=${requiredGiB}GiB."
}

$preflight = [ordered]@{
    schema = "HotRedundantQualificationPreflightV1"
    status = "PASS"
    mode = $Mode
    total_seconds = $TotalSeconds
    continuous = $isContinuous
    epoch_window_seconds = $EpochWindowSeconds
    time_scale = $TimeScale
    skip_kernel_observer = [bool]$SkipKernelObserver
    symbols = @("BTCUSDT", "ETHUSDT")
    topology = [ordered]@{
        lanes_per_symbol = 2
        primary_rotation_s = $primaryRotationS
        shadow_rotation_s = $shadowRotationS
        overlap_s = $overlapS
        segment_s = $segmentS
        primary_window_s = $primaryWindowS
        shadow_window_s = $shadowWindowS
        online_cross_lane_merge = $false
    }
    disk = [ordered]@{
        free_gib = $freeGiB
        projected_capture_gib_with_safety = $projectedGiB
        persistent_reserve_gib = $persistentReserveGiB
        required_gib = $requiredGiB
    }
    clock = $clock
    implementation = [ordered]@{
        hot_redundant_capture_sha256 = Get-RawQualificationSha256File -Path $capture
        hot_redundant_verify_sha256 = Get-RawQualificationSha256File -Path $rustVerifier
        kernel_network_trace_sha256 = Get-RawQualificationSha256File -Path $kernelTrace
        live_arbitration_sha256 = Get-RawQualificationSha256File -Path $liveArbiter
        live_arbitration_verify_sha256 = Get-RawQualificationSha256File -Path $liveArbiterVerify
        tracerpt_sha256 = Get-RawQualificationSha256File -Path $tracerpt
        logman_sha256 = Get-RawQualificationSha256File -Path $logman
        python_sha256 = Get-RawQualificationSha256File -Path $python
        python_source = Get-ServicePythonSourceFingerprint
        network_witness_script_sha256 = Get-RawQualificationSha256File -Path $networkWitnessScript
        system_evidence_script_sha256 = Get-RawQualificationSha256File -Path $systemEvidenceScript
        windows_helper_script_sha256 = Get-RawQualificationSha256File -Path (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")
        powershell_sha256 = Get-RawQualificationSha256File -Path (Join-Path $PSHOME "powershell.exe")
        public_config_sha256 = Get-RawQualificationSha256File -Path $publicConfig
        source_lock_sha256 = Get-RawQualificationSha256File -Path $sourceLock
        launcher_sha256 = Get-RawQualificationSha256File -Path $PSCommandPath
    }
}

if ($Mode -ceq "ValidateOnly") {
    $preflight | ConvertTo-Json -Depth 12
    return
}

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($isContinuous -and $SkipKernelObserver) {
        # TEST-ONLY non-elevated continuous run: the kernel observer and the
        # network witness are skipped and recorded honestly as
        # SKIPPED_NOT_ELEVATED; the elevated observer gate stays OPEN.
        $null = $null
    } else {
        throw "Production hot-redundant qualification requires an elevated PowerShell for kernel ETW."
    }
}

$createdMutex = $false
$mutex = [Threading.Mutex]::new($false, "Global\BinanceHotRedundantQualificationV1", [ref]$createdMutex)
$mutexAcquired = $false
try {
    $mutexAcquired = $mutex.WaitOne(0)
}
catch [Threading.AbandonedMutexException] {
    # The prior owner terminated without releasing; Windows transfers
    # ownership to this thread while reporting the abandoned state.
    $mutexAcquired = $true
}
if (-not $mutexAcquired) {
    $mutex.Dispose()
    throw "Another hot-redundant qualification already owns the host mutex."
}

$nonce = [guid]::NewGuid().ToString("N").Substring(0, 12)
$runId = "hrs-$nonce"
# TEST-ONLY fault runs may redirect the run root to an isolated artifacts
# area; production runs keep the canonical artifacts/hrs root.
$runRootBase = if ($Mode -ceq "Continuous" -and $isTestClock) {
    Join-Path $repo "artifacts\hsc"
} else {
    Join-Path $repo "artifacts\hrs"
}
$runRoot = Join-Path $runRootBase $runId
$observerRoot = Join-Path $runRoot "obs"
$verificationRoot = Join-Path $runRoot "verification"
New-Item -ItemType Directory -Path $observerRoot | Out-Null
New-Item -ItemType Directory -Path $verificationRoot | Out-Null
$null = Assert-RawQualificationNoReparsePointInExistingPath -Path $runRoot
$preflight.run_id = $runId
$preflight.run_root = $runRoot
$preflightSha = Write-RawQualificationDurableNewJson -Path (Join-Path $runRoot "preflight.json") -Value $preflight
$journal = New-RawQualificationJournal -Path (Join-Path $runRoot "service-events.jsonl")
$origin = [Diagnostics.Stopwatch]::StartNew()
$startUtc = [DateTimeOffset]::UtcNow
$job = [IntPtr]::Zero
$etw = $null
$witness = $null
$states = @{}
$successors = @{}
$arbiterStates = @{}
$arbiterVerification = [ordered]@{}
$arbiterRoot = $null
$observerFailures = [Collections.Generic.List[string]]::new()
$outerGaps = [Collections.Generic.List[object]]::new()
$completedArtifacts = [Collections.Generic.List[object]]::new()
$processIntervals = [Collections.Generic.List[object]]::new()
$verifiedWindows = [Collections.Generic.List[object]]::new()
$pendingSegmentVerifications = [Collections.Generic.List[object]]::new()
$lastTelemetry = [Diagnostics.Stopwatch]::StartNew()
$lastMilestoneDays = 0
$arbiterAuditDeadlineSeconds = 240
$terminalWritten = $false
$serviceReady = $false
# Cooperative service stop (Continuous): create-only stop file, the same
# discipline as the kernel/witness observers.  Bounded modes keep the
# TotalSeconds horizon (test) and never read this file.
$serviceStopFile = Join-Path $runRoot "stop.request"
$serviceStopRequested = $false
$storageSafeStop = $false

function Add-ServiceEvent {
    param([Parameter(Mandatory = $true)] [string] $Channel, [Parameter(Mandatory = $true)] $Payload)
    return Add-RawQualificationJournalRecord -Journal $journal `
        -Schema "HotRedundantServiceJournalRecordV1" -Channel $Channel `
        -WallNs (Get-RawQualificationWallNs) `
        -MonotonicTick ([uint64][Diagnostics.Stopwatch]::GetTimestamp()) -Payload $Payload
}

function Get-ServiceRelativePath {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [string] $FullPath
    )
    $canonicalRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $canonicalFull = [IO.Path]::GetFullPath($FullPath)
    $prefix = $canonicalRoot + '\'
    if (-not $canonicalFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escaped the service root: $canonicalFull"
    }
    return $canonicalFull.Substring($prefix.Length).Replace('\', '/')
}

function Convert-ServiceWallNsToUtc {
    param([Parameter(Mandatory = $true)] [uint64] $WallNs)
    $milliseconds = [int64][Math]::Floor([decimal]$WallNs / 1000000)
    return [DateTimeOffset]::FromUnixTimeMilliseconds($milliseconds).ToUniversalTime()
}

function Add-CollectorProcessIntervals {
    param([Parameter(Mandatory = $true)] [DateTimeOffset] $ObservationEnd)
    foreach ($journalPath in @(Get-ChildItem -LiteralPath $runRoot -Recurse -Filter "campaign-events.jsonl" -File -ErrorAction Stop)) {
        $startedBySession = @{}
        foreach ($line in [IO.File]::ReadLines($journalPath.FullName)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $envelope = $line | ConvertFrom-Json -ErrorAction Stop
            $payload = $envelope.body.payload
            if ([string]$payload.event -ceq "PROCESS_STARTED") {
                $sessionId = [string]$payload.session_id
                if ($startedBySession.ContainsKey($sessionId)) {
                    throw "Duplicate collector PROCESS_STARTED session identity."
                }
                $startedBySession[$sessionId] = [pscustomobject]@{
                    role = "COLLECTOR"; symbol = [string]$payload.symbol; pid = [uint32]$payload.process_id
                    interval_start_utc = Convert-ServiceWallNsToUtc -WallNs ([uint64]$envelope.body.wall_ns)
                    interval_end_utc = $ObservationEnd
                }
            }
            elseif ([string]$payload.event -ceq "PROCESS_TERMINAL") {
                $sessionId = [string]$payload.session_id
                if (-not $startedBySession.ContainsKey($sessionId)) {
                    throw "Collector PROCESS_TERMINAL lacks its PROCESS_STARTED identity."
                }
                $startedBySession[$sessionId].interval_end_utc = Convert-ServiceWallNsToUtc -WallNs ([uint64]$envelope.body.wall_ns)
            }
        }
        foreach ($sessionId in @($startedBySession.Keys | Sort-Object)) {
            $processIntervals.Add($startedBySession[$sessionId])
        }
    }
}

function Invoke-JsonVerifier {
    param(
        [Parameter(Mandatory = $true)] [string] $Module,
        [Parameter(Mandatory = $true)] [string] $InputRoot,
        [Parameter(Mandatory = $true)] [string] $OutputPath
    )
    $oldPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = Join-Path $repo "src"
        $stdout = Invoke-ExactProcess -Executable $python -Arguments ([string[]]@(
            "-B", "-m", $Module, $InputRoot
        ))
    }
    finally { $env:PYTHONPATH = $oldPythonPath }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($stdout.TrimEnd() + "`n")
    Write-RawQualificationDurableNewFile -Path $OutputPath -Bytes $bytes
    $value = Get-Content -LiteralPath $OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if ($value.status -cne "PASS") { throw "Independent verifier $Module did not report PASS." }
    return $value
}

function Assert-ServiceImplementationUnchanged {
    $expected = $preflight.implementation
    $actual = [ordered]@{
        hot_redundant_capture_sha256 = Get-RawQualificationSha256File -Path $capture
        hot_redundant_verify_sha256 = Get-RawQualificationSha256File -Path $rustVerifier
        kernel_network_trace_sha256 = Get-RawQualificationSha256File -Path $kernelTrace
        live_arbitration_sha256 = Get-RawQualificationSha256File -Path $liveArbiter
        live_arbitration_verify_sha256 = Get-RawQualificationSha256File -Path $liveArbiterVerify
        tracerpt_sha256 = Get-RawQualificationSha256File -Path $tracerpt
        logman_sha256 = Get-RawQualificationSha256File -Path $logman
        python_sha256 = Get-RawQualificationSha256File -Path $python
        python_source = Get-ServicePythonSourceFingerprint
        network_witness_script_sha256 = Get-RawQualificationSha256File -Path $networkWitnessScript
        system_evidence_script_sha256 = Get-RawQualificationSha256File -Path $systemEvidenceScript
        windows_helper_script_sha256 = Get-RawQualificationSha256File -Path (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")
        powershell_sha256 = Get-RawQualificationSha256File -Path (Join-Path $PSHOME "powershell.exe")
        public_config_sha256 = Get-RawQualificationSha256File -Path $publicConfig
        source_lock_sha256 = Get-RawQualificationSha256File -Path $sourceLock
        launcher_sha256 = Get-RawQualificationSha256File -Path $PSCommandPath
    }
    $expectedJson = $expected | ConvertTo-Json -Depth 10 -Compress
    $actualJson = $actual | ConvertTo-Json -Depth 10 -Compress
    if ($expectedJson -cne $actualJson) {
        throw "An executable, verifier source, observer, configuration, source lock, or launcher changed during qualification."
    }
}

function New-SymbolState {
    param([string] $Symbol, [string] $Code)
    return [pscustomobject]@{
        Symbol = $Symbol; Code = $Code; Epoch = 0; Launch = $null
        OutputRoot = $null; Artifact = $null; RequestedSeconds = 0
        RestartAtSeconds = 0.0; ConsecutiveFailures = 0
        OuterGap = $null; EverReady = $false
        # Planned-renewal bookkeeping (Continuous): the successor epoch
        # launches EpochWindowSeconds - overlapS into the epoch while the
        # predecessor keeps both lanes capturing; the symbol's lanes never
        # stop before the successor is READY.
        SuccessorScheduled = $false
        EpochLaunchSeconds = 0.0
        PlannedRenewal = $false
        NeedsArbiterRebind = $false
        # Per-epoch canonical view segments (continuous operation).
        ArbiterEpoch = 0; ArbiterSegment = 0; ArbiterLaunch = $null
        ArbiterJournal = $null; ArbiterArtifact = $null
        ArbiterDuration = 0; EpochStartedSeconds = 0.0
    }
}

function Start-SymbolEpoch {
    param([Parameter(Mandatory = $true)] $State)
    if ($isContinuous) {
        # Continuous service: every epoch is a bounded, sealable window; the
        # successor epoch starts before this one ends (planned overlap), so
        # the symbol's two lanes never stop before a READY successor.  No
        # global horizon.
        $remaining = [uint64]$EpochWindowSeconds
    } else {
        $remaining = [uint64][Math]::Ceiling([Math]::Max(0.0, [double]$TotalSeconds - $origin.Elapsed.TotalSeconds))
    }
    if ($remaining -lt $overlapS) { return $false }
    $State.Epoch = [int]$State.Epoch + 1
    $State.RequestedSeconds = $remaining
    $State.EpochStartedSeconds = $origin.Elapsed.TotalSeconds
    $State.EpochLaunchSeconds = $origin.Elapsed.TotalSeconds
    $State.SuccessorScheduled = $false
    $State.PlannedRenewal = $false
    $State.Artifact = $null
    # Per-symbol epoch root: <run>/<code>/e<epoch>; the whole <code> root is
    # the oracle artifact root of the symbol across every epoch.
    $State.OutputRoot = Join-Path $runRoot ("{0}\e{1}" -f $State.Code, $State.Epoch)
    New-Item -ItemType Directory -Path $State.OutputRoot | Out-Null
    $stdout = Join-Path $runRoot ("{0}{1}.stdout.jsonl" -f $State.Code, $State.Epoch)
    $stderr = Join-Path $runRoot ("{0}{1}.stderr.txt" -f $State.Code, $State.Epoch)
    $arguments = [string[]]@(
        $State.Symbol, [string]$remaining, [string]$primaryRotationS,
        [string]$shadowRotationS, [string]$overlapS, [string]$segmentS,
        [string]$primaryWindowS, [string]$shadowWindowS,
        $State.OutputRoot, "--event-stream"
    )
    $environment = [string[]]@(
        "SystemDrive=$env:SystemDrive", "SystemRoot=$env:SystemRoot",
        "TEMP=$env:TEMP", "TMP=$env:TMP", "WINDIR=$env:WINDIR"
    )
    $State.Launch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
        $job, $capture, $arguments, $repo, $stdout, $stderr, $environment
    )
    $processIntervals.Add([pscustomobject]@{
        role = "CAMPAIGN"; symbol = $State.Symbol; pid = [uint32]$State.Launch.ProcessId
        interval_start_utc = [DateTimeOffset]::UtcNow; interval_end_utc = $null
    })
    $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
        event = "SYMBOL_EPOCH_LAUNCHED"; symbol = $State.Symbol; epoch = $State.Epoch
        pid = [uint32]$State.Launch.ProcessId; requested_s = $remaining
        output_root = Get-ServiceRelativePath -Root $runRoot -FullPath $State.OutputRoot
        arguments = @($arguments)
        exact_command_line_sha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($State.Launch.ExactCommandLine))
    })
    return $true
}

function Update-SymbolArtifactAndReadiness {
    param([Parameter(Mandatory = $true)] $State)
    if ($null -eq $State.Artifact) {
        $roots = @(Get-ChildItem -LiteralPath $State.OutputRoot -Directory -ErrorAction SilentlyContinue)
        if ($roots.Count -gt 1) { throw "$($State.Symbol) epoch created multiple artifacts." }
        if ($roots.Count -eq 1) { $State.Artifact = $roots[0].FullName }
    }
    if ($null -eq $State.Artifact) { return }
    $events = Join-Path $State.Artifact "supervisor-events.jsonl"
    $ready = (Test-Path -LiteralPath $events -PathType Leaf) -and
        (Select-String -LiteralPath $events -SimpleMatch '"event":"LANE_READY"' -Quiet -ErrorAction SilentlyContinue)
    if ($ready -and -not $State.EverReady) {
        $State.EverReady = $true
        $null = Add-ServiceEvent -Channel "COVERAGE" -Payload ([ordered]@{
            event = "SYMBOL_FIRST_READY"; symbol = $State.Symbol; epoch = $State.Epoch
            artifact = Get-ServiceRelativePath -Root $runRoot -FullPath $State.Artifact
        })
    }
    if ($ready -and $null -ne $State.OuterGap) {
        $closed = [uint64]$origin.ElapsedTicks
        $gap = [ordered]@{
            symbol = $State.Symbol; gap_id = [uint64]$State.OuterGap.gap_id
            opened_elapsed_ticks = [uint64]$State.OuterGap.opened_elapsed_ticks
            closed_elapsed_ticks = $closed
            unavailable_ticks = [uint64]($closed - [uint64]$State.OuterGap.opened_elapsed_ticks)
        }
        $outerGaps.Add($gap)
        $null = Add-ServiceEvent -Channel "COVERAGE" -Payload ([ordered]@{ event = "OUTER_GAP_CLOSED"; gap = $gap })
        $State.OuterGap = $null
        $State.ConsecutiveFailures = 0
    }
}

function Start-LiveArbiter {
    param(
        [Parameter(Mandatory = $true)] $State,
        [Parameter(Mandatory = $true)] [string] $ArtifactRoot,
        [switch] $ResumeFromDeath,
        # ADR-17 B3 LIVE rebind: prior epoch artifacts whose sealing tails
        # this generation must walk (the rebind must not wait for the old
        # capture's stop, and must never lose the prior's recoverable data).
        [string[]] $PriorArtifacts = @()
    )
    # ADR-17 B2/B3/B4: the arbitration sidecar writes ONE journal segment per
    # generation; a resumed instance chains the previous segment (hash) and
    # the durable trade identity log, so restarts and rebinds can never
    # duplicate, roll back or degrade a post-publish conflict to `unknown`.
    $symbolName = $State.Symbol
    $symbolDir = Join-Path $arbiterRoot $symbolName
    if (-not (Test-Path -LiteralPath $symbolDir -PathType Container)) {
        New-Item -ItemType Directory -Path $symbolDir | Out-Null
    }
    $existingSegments = @(Get-ChildItem -LiteralPath $symbolDir -Filter "*-seg-*.jsonl" -File -ErrorAction SilentlyContinue)
    $sequence = $existingSegments.Count
    $arbJournal = Join-Path $symbolDir ("{0}-seg-{1:0000}.jsonl" -f $symbolName, $sequence)
    $identity = Join-Path $symbolDir "trade-identity.bin"
    $stopFile = Join-Path $symbolDir "stop.request"
    $rebindFile = Join-Path $symbolDir "rebind.request"
    if (Test-Path -LiteralPath $stopFile) {
        # A leftover stop marker from a previous generation must not stop the
        # successor at once: it was consumed by the generation it stopped.
        Remove-Item -LiteralPath $stopFile -Force
    }
    if (Test-Path -LiteralPath $rebindFile) {
        # A leftover rebind marker is likewise consumed by its generation.
        Remove-Item -LiteralPath $rebindFile -Force
    }
    $arbStdout = Join-Path $symbolDir ("seg-{0:0000}.stdout.txt" -f $sequence)
    $arbStderr = Join-Path $symbolDir ("seg-{0:0000}.stderr.txt" -f $sequence)
    $arbiterExe = if ($ArbiterOverride -ne "") { $ArbiterOverride } else { $liveArbiter }
    if ($isContinuous) {
        $arguments = [string[]]@(
            $symbolName, $ArtifactRoot, $arbJournal, "--continuous",
            "--identity", $identity, "--stop-file", $stopFile,
            "--rebind-file", $rebindFile,
            "--resume-dir", $symbolDir
        )
        foreach ($prior in $PriorArtifacts) {
            $arguments += "--prior-artifact"
            $arguments += $prior
        }
    } else {
        $arguments = [string[]]@(
            $symbolName, $ArtifactRoot, $arbJournal, [string]$TotalSeconds,
            "--identity", $identity
        )
    }
    $arbiterLaunch = [RawQualificationNative]::StartSuspendedInJobRetained(
        $job, $arbiterExe, $arguments, $repo, $arbStdout, $arbStderr
    )
    $previous = $arbiterStates[$symbolName]
    if ($null -ne $previous -and $null -ne $previous.auditLaunch) {
        # ADR-17 B6 cleanup completeness: an in-flight prefix audit must not
        # outlive the arbiter generation it audits.  A relaunch that only
        # closed the LAUNCH handle orphaned the auditor (fault-gate defect:
        # the hung-auditor timeout could never fire because the tracking
        # state was replaced at every renewal).
        if (-not [RawQualificationNative]::WaitForProcessExit($previous.auditLaunch.ProcessHandle, 0)) {
            $null = [RawQualificationNative]::TerminateProcessHandle($previous.auditLaunch.ProcessHandle, 0xEE45)
            $null = [RawQualificationNative]::WaitForProcessExit($previous.auditLaunch.ProcessHandle, 10000)
        }
        $null = [RawQualificationNative]::CloseRetainedProcessHandle($previous.auditLaunch)
    }
    if ($null -ne $previous -and $null -ne $previous.launch) {
        $null = [RawQualificationNative]::CloseRetainedProcessHandle($previous.launch)
    }
    # Audit evidence files are create-only: the sequence continues from the
    # files already sealed by previous arbiter generations.
    $existingAudits = @(Get-ChildItem -LiteralPath $symbolDir -Filter "*-audit-*" -File -ErrorAction SilentlyContinue).Count
    $arbiterStates[$symbolName] = [pscustomobject]@{
        symbol = $symbolName; launch = $arbiterLaunch; journal = $arbJournal
        dir = $symbolDir; stderr = $arbStderr; stdout = $arbStdout
        pid = [uint32]$arbiterLaunch.ProcessId
        artifact = $ArtifactRoot; sequence = $sequence
        # Semantic health state (initialized up front: StrictMode rejects
        # reads of properties that were never created).
        lastAuditedSize = $null; lastPrefixAudit = $null
        lastPrefixAuditResult = "NOT_RUN"; stallTicks = 0
        auditLaunch = $null; auditStartedStopwatch = $null
        auditSequence = $existingAudits; auditStdout = $null; auditStderr = $null
        segmentSequence = $sequence
        consecutiveFailures = 0; restartAtSeconds = 0.0
        resumeFromDeath = [bool]$ResumeFromDeath
        # ADR-17 B6 (defect hrs-e4878b5f365f): a planned rebind legitimately
        # pauses the canonical journal while the successor drains+binds (up to
        # the 30 s drain deadline); the stall detector must not type that
        # transition as a stall.  Cleared on the first journal growth or after
        # the transition bound (60 s).
        rebindActive = (@($PriorArtifacts).Count -gt 0)
        rebindLaunchedAt = if (@($PriorArtifacts).Count -gt 0) { [DateTimeOffset]::UtcNow } else { $null }
    }
    $processIntervals.Add([pscustomobject]@{
        role = "LIVE_ARBITRATION"; symbol = $symbolName; pid = [uint32]$arbiterLaunch.ProcessId
        interval_start_utc = [DateTimeOffset]::UtcNow; interval_end_utc = $null
    })
    $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
        event = "LIVE_ARBITRATION_LAUNCHED"; symbol = $symbolName
        pid = [uint32]$arbiterLaunch.ProcessId; segment = $sequence
        artifact = Get-ServiceRelativePath -Root $runRoot -FullPath $ArtifactRoot
        resumed = ([bool]$ResumeFromDeath) -or ($sequence -gt 0)
        journal = Get-ServiceRelativePath -Root $runRoot -FullPath $arbJournal
    })
}

function Stop-LiveArbiter {
    param(
        [Parameter(Mandatory = $true)] $Arbiter,
        [uint32] $KillExitCode = 0xEE23,
        # ADR-17 B3 LIVE rebind: a rebind stop drains only what is already
        # durable (the successor owns the predecessor artifact's sealing
        # tails via --prior-artifact), so the canonical chain never stalls
        # for the old epoch's drain.
        [switch] $RebindStop
    )
    if ($null -eq $Arbiter -or $null -eq $Arbiter.launch) { return 0 }
    if (-not [RawQualificationNative]::WaitForProcessExit($Arbiter.launch.ProcessHandle, 0)) {
        $stopFile = Join-Path $Arbiter.dir $(if ($RebindStop) { "rebind.request" } else { "stop.request" })
        if (-not (Test-Path -LiteralPath $stopFile)) {
            $null = Write-RawQualificationDurableNewFile -Path $stopFile -Bytes ([byte[]]@())
        }
        if (-not [RawQualificationNative]::WaitForProcessExit($Arbiter.launch.ProcessHandle, 60000)) {
            $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                event = "OBSERVER_FAILED"; observer = "LIVE_ARBITRATION"; symbol = $Arbiter.symbol
                detail = "sidecar exceeded the cooperative stop deadline and was terminated"
            })
            $null = [RawQualificationNative]::TerminateProcessHandle($Arbiter.launch.ProcessHandle, $KillExitCode)
            $null = [RawQualificationNative]::WaitForProcessExit($Arbiter.launch.ProcessHandle, 30000)
        }
        if (Test-Path -LiteralPath $stopFile) { Remove-Item -LiteralPath $stopFile -Force }
    }
    $code = [uint32][RawQualificationNative]::GetProcessExitCode($Arbiter.launch.ProcessHandle)
    $interval = @($processIntervals | Where-Object {
        $_.role -ceq "LIVE_ARBITRATION" -and $_.symbol -ceq $Arbiter.symbol -and $null -eq $_.interval_end_utc
    })
    if ($interval.Count -eq 1) { $interval[0].interval_end_utc = [DateTimeOffset]::UtcNow }
    $null = [RawQualificationNative]::CloseRetainedProcessHandle($Arbiter.launch)
    $Arbiter.launch = $null
    return $code
}

function Rebind-LiveArbiter {
    param(
        [Parameter(Mandatory = $true)] $State,
        [Parameter(Mandatory = $true)] [string] $NewArtifactRoot
    )
    # ADR-17 B3 LIVE rebind: the canonical view crosses the epoch boundary
    # without waiting for the old capture's stop.  The old generation closes
    # with a FAST drain (only what is already durable — the successor owns
    # the sealing tails via --prior-artifact), its segment is queued for the
    # bounded closed verification, and the successor resumes the same
    # journal chain + durable identity while walking the prior artifact's
    # generations as they seal.  Raw capture never stops on either side.
    $arb = $arbiterStates[$State.Symbol]
    $priorArtifacts = @()
    if ($null -ne $arb) {
        $exit = Stop-LiveArbiter -Arbiter $arb -RebindStop
        $priorArtifacts += [string]$arb.artifact
        # One sealed segment produces exactly one bounded verification task
        # (a rebind can be triggered twice â€” promotion + readiness â€” while
        # the segment was already queued).  The oracle root is the SYMBOL
        # root (every epoch artifact): the segment's ARBITRATION_RESUMED
        # record declares its prior artifacts and the verifier scopes the
        # oracle to exactly those names.
        $symbolRoot = Join-Path $runRoot $State.Code
        $duplicate = @($pendingSegmentVerifications | Where-Object {
            $_.symbol -ceq $State.Symbol -and $_.sequence -eq $arb.sequence -and $_.journal -ceq $arb.journal
        })
        if ($duplicate.Count -eq 0) {
            $pendingSegmentVerifications.Add([pscustomobject]@{
                symbol = $State.Symbol; journal = $arb.journal; dir = $arb.dir
                artifact = $symbolRoot; sequence = $arb.sequence
            })
        }
        $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
            event = "LIVE_ARBITRATION_SEGMENT_SEALED"; symbol = $State.Symbol
            journal = Get-ServiceRelativePath -Root $runRoot -FullPath $arb.journal
            exit_code = $exit; rebind = $true
        })
    }
    $null = Start-LiveArbiter -State $State -ArtifactRoot $NewArtifactRoot -PriorArtifacts $priorArtifacts
}

# --- Sealed-window verification machinery (ADR-17 B2/B6) --------------------
# Every completed epoch artifact and every sealed canonical segment is
# verified with the Rust AND Python oracles as DETACHED processes with
# monotonic deadlines: a hung/slow evaluator never blocks the service loop,
# its stderr is preserved, and the milestones only count verified windows.
$verificationTasks = [Collections.Generic.List[object]]::new()

function Start-EpochVerificationTask {
    param([Parameter(Mandatory = $true)] $Artifact, [int] $Epoch)
    $symbolCode = ($Artifact.symbol.Substring(0, 1)).ToLowerInvariant()
    $base = "$symbolCode$Epoch"
    $rustReport = Join-Path $verificationRoot "$base-rust.json"
    $pythonReport = Join-Path $verificationRoot "$base-python.json"
    $stderr = Join-Path $verificationRoot "$base-rust.stderr.txt"
    $coverageSeconds = [uint64]$Artifact.coverage_seconds
    $launch = [RawQualificationNative]::StartSuspendedInJobRetained(
        $job, $rustVerifier,
        ([string[]]@($Artifact.root, $rustReport)),
        $repo, (Join-Path $verificationRoot "$base-rust.stdout.txt"), $stderr
    )
    $verificationTasks.Add([pscustomobject]@{
        kind = "epoch"; symbol = $Artifact.symbol; epoch = $Epoch; root = $Artifact.root
        stage = "rust"; launch = $launch; stopwatch = [Diagnostics.Stopwatch]::StartNew()
        rustReport = $rustReport; rustStdout = (Join-Path $verificationRoot "$base-rust.stdout.txt")
        pythonReport = $pythonReport; stderr = $stderr
        pyStderr = $null
        coverage_seconds = $coverageSeconds
    })
}

function Start-SegmentVerificationTask {
    param([Parameter(Mandatory = $true)] $Entry)
    $base = ("{0}-seg-{1:0000}" -f $Entry.symbol.Substring(0, 1).ToLowerInvariant(), $Entry.sequence)
    $rustReport = Join-Path $verificationRoot "$base-rust.json"
    $pythonReport = Join-Path $verificationRoot "$base-python.json"
    $stderr = Join-Path $verificationRoot "$base-rust.stderr.txt"
    # Bounded per-epoch verification (ADR-17 B2): ONE sealed resume segment
    # audited against the chain context declared in its own
    # ARBITRATION_RESUMED record and the epoch's own raw artifact â€” never
    # the whole service history (the full structural set audit runs once at
    # the service terminal).
    $launch = [RawQualificationNative]::StartSuspendedInJobRetained(
        $job, $liveArbiterVerify,
        ([string[]]@($Entry.journal, "--tail-segment-only", "--oracle-artifact", $Entry.artifact)),
        $repo, (Join-Path $verificationRoot "$base-rust.stdout.txt"), $stderr
    )
    $verificationTasks.Add([pscustomobject]@{
        kind = "segment"; symbol = $Entry.symbol; sequence = $Entry.sequence
        journal = $Entry.journal; artifact = $Entry.artifact
        stage = "rust"; launch = $launch; stopwatch = [Diagnostics.Stopwatch]::StartNew()
        rustReport = $rustReport; rustStdout = (Join-Path $verificationRoot "$base-rust.stdout.txt")
        pythonReport = $pythonReport; stderr = $stderr
        pyStderr = $null
        coverage_seconds = [uint64]0
    })
}

function Process-VerificationTasks {
    # Sealed canonical segments queue bounded per-epoch verification tasks.
    while ($pendingSegmentVerifications.Count -gt 0) {
        $entry = $pendingSegmentVerifications[0]
        $pendingSegmentVerifications.RemoveAt(0)
        $already = @($verificationTasks | Where-Object {
            $_.kind -ceq "segment" -and $_.journal -ceq $entry.journal
        })
        if ($already.Count -eq 0) {
            Start-SegmentVerificationTask -Entry $entry
        }
    }
    foreach ($task in @($verificationTasks)) {
        if ($null -eq $task.launch) { continue }
        if ($task.stage -cne "rust") { continue }
        if ([RawQualificationNative]::WaitForProcessExit($task.launch.ProcessHandle, 0)) {
            $exit = [uint32][RawQualificationNative]::GetProcessExitCode($task.launch.ProcessHandle)
            $null = [RawQualificationNative]::CloseRetainedProcessHandle($task.launch)
            $task.launch = $null
            if ($exit -ne 0) {
                $verificationTasks.Remove($task)
                if (-not $observerFailures.Contains("SEALED_WINDOW_VERIFICATION_REJECTED")) {
                    $observerFailures.Add("SEALED_WINDOW_VERIFICATION_REJECTED")
                    $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                        event = "OBSERVER_FAILED"; observer = "WINDOW_VERIFIER"
                        symbol = $task.symbol; kind = $task.kind
                        detail = "Rust verifier rejected a sealed window (exit $exit)"
                    })
                }
                continue
            }
            if (Test-Path -LiteralPath $task.rustReport -PathType Leaf) {
                $rustValue = Get-Content -LiteralPath $task.rustReport -Raw | ConvertFrom-Json -ErrorAction Stop
            } elseif (Test-Path -LiteralPath $task.rustStdout -PathType Leaf) {
                # live_arbitration_verify reports on stdout; capture it into
                # the immutable report artifact.
                $rustText = (Get-Content -LiteralPath $task.rustStdout -Raw).TrimEnd()
                $null = Write-RawQualificationDurableNewFile -Path $task.rustReport -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($rustText + "`n"))
                $rustValue = $rustText | ConvertFrom-Json -ErrorAction Stop
            } else {
                throw "Rust verifier produced no report artifact."
            }
            if ($rustValue.status -cne "PASS") {
                $verificationTasks.Remove($task)
                if (-not $observerFailures.Contains("SEALED_WINDOW_VERIFICATION_REJECTED")) {
                    $observerFailures.Add("SEALED_WINDOW_VERIFICATION_REJECTED")
                    $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                        event = "OBSERVER_FAILED"; observer = "WINDOW_VERIFIER"
                        symbol = $task.symbol; kind = $task.kind
                        detail = "Rust verifier status was not PASS"
                    })
                }
                continue
            }
            # Stage 2: the independent Python verifier.
            $oldPythonPath = $env:PYTHONPATH
            # Unique per-task evidence files (create-only discipline).
            $pyBase = $task.pythonReport.Substring(0, $task.pythonReport.Length - ".json".Length)
            $pyStdout = "$pyBase.stdout.txt"
            $pyStderr = "$pyBase.stderr.txt"
            $launch = $null
            try {
                $env:PYTHONPATH = Join-Path $repo "src"
                $pyArgs = if ($task.kind -ceq "epoch") {
                    [string[]]@("-B", "-m", "binance_lob.hot_redundant_verify_cli", $task.root, "--output", $task.pythonReport)
                } else {
                    [string[]]@("-B", "-m", "binance_lob.live_arbitration_verify_cli", $task.journal, "--tail-segment-only", "--oracle-artifact", $task.artifact, "--output", $task.pythonReport)
                }
                $launch = [RawQualificationNative]::StartSuspendedInJobRetained(
                    $job, $python, $pyArgs, $repo, $pyStdout, $pyStderr
                )
            }
            finally { $env:PYTHONPATH = $oldPythonPath }
            $task.launch = $launch
            $task.stopwatch = [Diagnostics.Stopwatch]::StartNew()
            $task.stage = "python"
            $task.pyStderr = $pyStderr
            continue
        }
        if ($task.stopwatch.Elapsed.TotalSeconds -ge $arbiterAuditDeadlineSeconds) {
            $null = [RawQualificationNative]::TerminateProcessHandle($task.launch.ProcessHandle, 0xEE46)
            $null = [RawQualificationNative]::WaitForProcessExit($task.launch.ProcessHandle, 10000)
            $null = [RawQualificationNative]::CloseRetainedProcessHandle($task.launch)
            $task.launch = $null
            $verificationTasks.Remove($task)
            if (-not $observerFailures.Contains("SEALED_WINDOW_VERIFICATION_TIMEOUT")) {
                $observerFailures.Add("SEALED_WINDOW_VERIFICATION_TIMEOUT")
                $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                    event = "OBSERVER_FAILED"; observer = "WINDOW_VERIFIER"
                    symbol = $task.symbol; kind = $task.kind; stage = $task.stage
                    detail = "sealed-window verification exceeded its monotonic deadline and was terminated"
                })
            }
            continue
        }
    }
    # Collect finished Python stages.
    foreach ($task in @($verificationTasks)) {
        if ($null -eq $task.launch -or $task.stage -cne "python") { continue }
        if (-not [RawQualificationNative]::WaitForProcessExit($task.launch.ProcessHandle, 0)) {
            if ($task.stopwatch.Elapsed.TotalSeconds -ge $arbiterAuditDeadlineSeconds) {
                $null = [RawQualificationNative]::TerminateProcessHandle($task.launch.ProcessHandle, 0xEE47)
                $null = [RawQualificationNative]::WaitForProcessExit($task.launch.ProcessHandle, 10000)
                $null = [RawQualificationNative]::CloseRetainedProcessHandle($task.launch)
                $task.launch = $null
                $verificationTasks.Remove($task)
                if (-not $observerFailures.Contains("SEALED_WINDOW_VERIFICATION_TIMEOUT")) {
                    $observerFailures.Add("SEALED_WINDOW_VERIFICATION_TIMEOUT")
                    $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                        event = "OBSERVER_FAILED"; observer = "WINDOW_VERIFIER"
                        symbol = $task.symbol; kind = $task.kind; stage = "python"
                        detail = "sealed-window Python verification exceeded its monotonic deadline and was terminated"
                    })
                }
            }
            continue
        }
        $exit = [uint32][RawQualificationNative]::GetProcessExitCode($task.launch.ProcessHandle)
        $null = [RawQualificationNative]::CloseRetainedProcessHandle($task.launch)
        $task.launch = $null
        $verificationTasks.Remove($task)
        if ($exit -ne 0) {
            if (-not $observerFailures.Contains("SEALED_WINDOW_VERIFICATION_REJECTED")) {
                $observerFailures.Add("SEALED_WINDOW_VERIFICATION_REJECTED")
                $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                    event = "OBSERVER_FAILED"; observer = "WINDOW_VERIFIER"
                    symbol = $task.symbol; kind = $task.kind
                    detail = "Python verifier rejected a sealed window (exit $exit)"
                })
            }
            continue
        }
        $pyValue = Get-Content -LiteralPath $task.pythonReport -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($pyValue.status -cne "PASS") {
            if (-not $observerFailures.Contains("SEALED_WINDOW_VERIFICATION_REJECTED")) {
                $observerFailures.Add("SEALED_WINDOW_VERIFICATION_REJECTED")
                $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                    event = "OBSERVER_FAILED"; observer = "WINDOW_VERIFIER"
                    symbol = $task.symbol; kind = $task.kind
                    detail = "Python verifier status was not PASS"
                })
            }
            continue
        }
        if ($task.kind -ceq "epoch") {
            $verifiedWindows.Add([pscustomobject]@{
                symbol = $task.symbol; epoch = $task.epoch; status = "PASS"
                coverage_seconds = $task.coverage_seconds
                rust_report = Get-ServiceRelativePath -Root $runRoot -FullPath $task.rustReport
                python_report = Get-ServiceRelativePath -Root $runRoot -FullPath $task.pythonReport
            })
            $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
                event = "SYMBOL_EPOCH_VERIFIED"; symbol = $task.symbol; epoch = $task.epoch
            })
        } else {
            $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
                event = "LIVE_ARBITRATION_SEGMENT_VERIFIED"; symbol = $task.symbol; sequence = $task.sequence
            })
        }
    }
}

# Failure propagation (ADR-17 B2/B3): a -File host must exit non-zero when
# the service failed; the failure evidence is committed to service-failure.json
# first, resource cleanup runs in `finally`, and ONLY THEN the script exits
# with the explicit failure code (deterministic, independent of host quirks).
$failureExitCode = 0
try {
    $job = [RawQualificationNative]::CreateKillOnCloseJob("BinanceHotService_$nonce")
    $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
        event = "SERVICE_STARTED"; run_id = $runId; preflight_sha256 = $preflightSha
    })

    $kernelRoot = Join-Path $observerRoot "kernel"
    New-Item -ItemType Directory -Path $kernelRoot | Out-Null
    $etl = Join-Path $kernelRoot "kernel-network.etl"
    $etwStop = Join-Path $kernelRoot "stop.request"
    $etwOut = Join-Path $kernelRoot "controller.stdout.jsonl"
    $etwErr = Join-Path $kernelRoot "controller.stderr.txt"
    # Continuous operation (ADR-17 B2): the observer deadline is bounded per
    # epoch (rotated with the epoch), never a global service horizon.
    $etwDeadline = if ($isContinuous) {
        [uint32][Math]::Min(691200, [uint64]$EpochWindowSeconds + 1800)
    } else {
        [uint32][Math]::Min(691200, [uint64]$TotalSeconds + 1800)
    }
    $observerRunId = "observed-$nonce"
    $sessionName = "BinanceProduction_$nonce"
    $etwStartedUtc = [DateTimeOffset]::UtcNow
    $processIntervals.Add([pscustomobject]@{
        role = "LAUNCHER"; symbol = $null; pid = [uint32]$PID
        interval_start_utc = $etwStartedUtc; interval_end_utc = $null
    })
    $observerSkipped = $isContinuous -and $SkipKernelObserver
    if ($observerSkipped) {
        # TEST-ONLY: no kernel controller, no network witness; recorded
        # honestly at the terminal as SKIPPED_NOT_ELEVATED.
        $etw = $null
        $witness = $null
    } else {
        $etw = [RawQualificationNative]::StartSuspendedInJobRetained(
            $job, $kernelTrace,
            ([string[]]@($sessionName, $etl, $etwStop, [string]$KernelTraceMiB, [string]$etwDeadline)),
            $repo, $etwOut, $etwErr
        )
        $readyDeadline = [Diagnostics.Stopwatch]::StartNew()
        $etwReady = $false
        while ($readyDeadline.Elapsed.TotalSeconds -lt 30 -and -not $etwReady) {
            if ([RawQualificationNative]::WaitForProcessExit($etw.ProcessHandle, 0)) { break }
            if (Test-Path -LiteralPath $etwOut -PathType Leaf) {
                $first = @(Get-Content -LiteralPath $etwOut -ErrorAction SilentlyContinue | Select-Object -First 1)
                if ($first.Count -eq 1) {
                    try {
                        $value = $first[0] | ConvertFrom-Json -ErrorAction Stop
                        $etwReady = $value.schema -ceq "KernelNetworkTraceReadyV1" -and $value.status -ceq "READY"
                    } catch {}
                }
            }
            if (-not $etwReady) { Start-Sleep -Milliseconds 100 }
        }
        if (-not $etwReady) { throw "Kernel ETW did not publish exact READY before market capture." }
    }

    $networkRoot = Join-Path $observerRoot "network"
    $networkStop = Join-Path $networkRoot "stop.request"
    $witnessOut = Join-Path $observerRoot "network.stdout.txt"
    $witnessErr = Join-Path $observerRoot "network.stderr.txt"
    $powershell = Join-Path $PSHOME "powershell.exe"
    if (-not $observerSkipped) {
        $witnessArguments = [string[]]@(
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $networkWitnessScript,
            "-EvidenceRoot", $networkRoot, "-ObservationId", $observerRunId,
            "-DurationSeconds", [string]$etwDeadline, "-IntervalSeconds", "30",
            "-ProbeTimeoutMilliseconds", "2000", "-StopFile", $networkStop
        )
        $witness = [RawQualificationNative]::StartSuspendedInJobRetained(
            $job, $powershell, $witnessArguments, $repo, $witnessOut, $witnessErr
        )
        $witnessDeadline = [Diagnostics.Stopwatch]::StartNew()
        while ($witnessDeadline.Elapsed.TotalSeconds -lt 30 -and
            -not (Test-Path -LiteralPath (Join-Path $networkRoot "network-witness-startup.json") -PathType Leaf)) {
            if ([RawQualificationNative]::WaitForProcessExit($witness.ProcessHandle, 0)) { break }
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath (Join-Path $networkRoot "network-witness-startup.json") -PathType Leaf)) {
            throw "Independent network witness did not publish startup evidence."
        }
    }

    $states["BTCUSDT"] = New-SymbolState -Symbol "BTCUSDT" -Code "b"
    $states["ETHUSDT"] = New-SymbolState -Symbol "ETHUSDT" -Code "e"
    $successors["BTCUSDT"] = $null
    $successors["ETHUSDT"] = $null
    foreach ($state in $states.Values) {
        if (-not (Start-SymbolEpoch -State $state)) { throw "Initial symbol epoch was not launchable." }
    }

    $serviceLoopActive = $true
    while ($serviceLoopActive) {
        # Loop termination (ADR-17 B2): Continuous ends only on the explicit
        # cooperative stop request (or a storage safe-stop); bounded modes end
        # on the TotalSeconds test horizon.  Never a hidden global deadline.
        if ($isContinuous) {
            if (Test-Path -LiteralPath $serviceStopFile) { $serviceLoopActive = $false; $serviceStopRequested = $true }
        } else {
            if ($origin.Elapsed.TotalSeconds -ge $TotalSeconds) { $serviceLoopActive = $false }
        }
        if (-not $serviceLoopActive) { break }
        foreach ($state in @($states.Values)) {
            # Planned epoch renewal (ADR-17 B3/R2): launch the successor while
            # the predecessor still keeps both lanes capturing.  The symbol's
            # lanes never stop before the successor is READY.  A dead epoch
            # (outer gap) never schedules: its restart/promotion path owns
            # the next epoch.
            if ($isContinuous -and $null -ne $state.Launch -and -not $state.SuccessorScheduled -and $null -eq $successors[$state.Symbol]) {
                $epochAge = $origin.Elapsed.TotalSeconds - $state.EpochLaunchSeconds
                if ($epochAge -ge ([double]$EpochWindowSeconds - [double]$overlapS)) {
                    $successor = New-SymbolState -Symbol $state.Symbol -Code $state.Code
                    $successor.Epoch = $state.Epoch
                    if (Start-SymbolEpoch -State $successor) {
                        $successors[$state.Symbol] = $successor
                        $state.SuccessorScheduled = $true
                        $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
                            event = "SYMBOL_EPOCH_SUCCESSOR_LAUNCHED"; symbol = $state.Symbol
                            predecessor_epoch = $state.Epoch; successor_epoch = $successor.Epoch
                            predecessor_still_capturing = $true
                        })
                    }
                }
            }
            if ($null -ne $state.Launch) {
                Update-SymbolArtifactAndReadiness -State $state
                if ($isContinuous -and $state.NeedsArbiterRebind -and $null -ne $state.Artifact) {
                    $state.NeedsArbiterRebind = $false
                    Rebind-LiveArbiter -State $state -NewArtifactRoot $state.Artifact
                }
                if ([RawQualificationNative]::WaitForProcessExit($state.Launch.ProcessHandle, 0)) {
                    $code = [uint32][RawQualificationNative]::GetProcessExitCode($state.Launch.ProcessHandle)
                    $interval = @($processIntervals | Where-Object {
                        [uint32]$_.pid -eq [uint32]$state.Launch.ProcessId -and $null -eq $_.interval_end_utc
                    })
                    if ($interval.Count -ne 1) { throw "Supervisor process interval identity is ambiguous." }
                    $interval[0].interval_end_utc = [DateTimeOffset]::UtcNow
                    $terminalExists = ($null -ne $state.Artifact) -and (Test-Path -LiteralPath (Join-Path $state.Artifact "supervisor-terminal.json") -PathType Leaf)
                    if ($null -ne $state.Artifact) {
                        $completedArtifacts.Add([pscustomobject]@{
                            symbol = $state.Symbol; epoch = $state.Epoch; root = $state.Artifact; exit_code = $code
                        })
                    }
                    $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
                        event = "SYMBOL_EPOCH_EXITED"; symbol = $state.Symbol; epoch = $state.Epoch
                        exit_code = $code; artifact = if ($null -eq $state.Artifact) { $null } else { Get-ServiceRelativePath -Root $runRoot -FullPath $state.Artifact }
                    })
                    $cleanExit = ($code -eq 0) -and $terminalExists
                    if ($isContinuous -and $cleanExit -and $null -ne $state.Artifact) {
                        # Seal and verify the completed epoch WHILE the next
                        # epoch captures (ADR-17 B2): the verification runs
                        # detached with a monotonic deadline.
                        Start-EpochVerificationTask -Artifact ([pscustomobject]@{
                            symbol = $state.Symbol; root = $state.Artifact
                            coverage_seconds = $state.RequestedSeconds
                        }) -Epoch $state.Epoch
                    }
                    $successor = $successors[$state.Symbol]
                    if ($isContinuous -and $null -ne $successor) {
                        # Planned renewal: promote the successor WITHOUT opening
                        # an outer gap and WITHOUT backoff â€” the lanes never
                        # stopped.  A dirty predecessor exit is typed but the
                        # successor still carries the capture.
                        $state.PlannedRenewal = $cleanExit
                        $successors[$state.Symbol] = $null
                        $states[$state.Symbol] = $successor
                        $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
                            event = "SYMBOL_EPOCH_RENEWED"; symbol = $state.Symbol
                            predecessor_epoch = $state.Epoch; successor_epoch = $successor.Epoch
                            predecessor_clean = $cleanExit; no_outer_gap = $true
                        })
                        if ($state.ConsecutiveFailures -gt 0) { $state.ConsecutiveFailures = 0 }
                        $null = [RawQualificationNative]::CloseRetainedProcessHandle($state.Launch)
                        $state.Launch = $null
                        # The canonical view rebinds to the successor artifact
                        # now that the predecessor's lanes sealed (ADR-17 B3):
                        # resume chains the journal segments and never
                        # duplicates or rolls back.  If the successor is not
                        # READY yet, the rebind fires as soon as it is.
                        if ($null -ne $successor.Artifact) {
                            Rebind-LiveArbiter -State $successor -NewArtifactRoot $successor.Artifact
                        } else {
                            $successor.NeedsArbiterRebind = $true
                        }
                        continue
                    }
                    $null = [RawQualificationNative]::CloseRetainedProcessHandle($state.Launch)
                    $state.Launch = $null
                    if ($null -eq $state.OuterGap) {
                        $state.OuterGap = [pscustomobject]@{
                            gap_id = [uint64]($outerGaps.Count + @($states.Values | Where-Object { $null -ne $_.OuterGap }).Count)
                            opened_elapsed_ticks = [uint64]$origin.ElapsedTicks
                        }
                        $null = Add-ServiceEvent -Channel "COVERAGE" -Payload ([ordered]@{
                            event = "OUTER_GAP_OPENED"; symbol = $state.Symbol; gap_id = $state.OuterGap.gap_id
                            opened_elapsed_ticks = $state.OuterGap.opened_elapsed_ticks
                            prior_exit_code = $code
                        })
                    }
                    $state.ConsecutiveFailures = [int]$state.ConsecutiveFailures + 1
                    $delay = [Math]::Min(60.0, [Math]::Pow(2.0, [Math]::Min(5, $state.ConsecutiveFailures - 1)))
                    $state.RestartAtSeconds = $origin.Elapsed.TotalSeconds + $delay
                }
            }
            elseif ($origin.Elapsed.TotalSeconds -ge $state.RestartAtSeconds) {
                $successor = $successors[$state.Symbol]
                if ($isContinuous -and $null -ne $successor) {
                    # The planned successor already covers this epoch: promote
                    # it (the outer gap closes when its lanes become READY)
                    # instead of launching a colliding epoch.
                    $successors[$state.Symbol] = $null
                    $states[$state.Symbol] = $successor
                    $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
                        event = "SYMBOL_EPOCH_RENEWED"; symbol = $state.Symbol
                        predecessor_epoch = $state.Epoch; successor_epoch = $successor.Epoch
                        predecessor_clean = $false; no_outer_gap = $true
                        recovery_promotion = $true
                    })
                    if ($null -ne $successor.Artifact) {
                        Rebind-LiveArbiter -State $successor -NewArtifactRoot $successor.Artifact
                    } else {
                        $successor.NeedsArbiterRebind = $true
                    }
                } else {
                    $null = Start-SymbolEpoch -State $state
                }
            }
        }

        if (-not $serviceReady -and @($states.Values | Where-Object { $_.EverReady }).Count -eq 2) {
            $serviceReady = $true
            $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
                event = "SERVICE_READY"; symbols = @("BTCUSDT", "ETHUSDT")
                elapsed_s = [uint64]$origin.Elapsed.TotalSeconds
            })
            Write-Output ("READY: BTCUSDT and ETHUSDT each have at least one independently durable raw lane. Evidence: {0}" -f $runRoot)
            # ADR-16/ADR-17: launch the live cross-lane arbitration sidecar per
            # symbol.  It publishes the canonical live journal from both lanes'
            # durable prefixes; its death degrades only the derived view, never
            # the raw; on any exit it is re-launched with --resume (durable
            # identity + journal chain, zero duplication, zero rollback).
            $arbiterRoot = Join-Path $runRoot "canonical-live"
            New-Item -ItemType Directory -Path $arbiterRoot | Out-Null
            foreach ($symbolName in @("BTCUSDT", "ETHUSDT")) {
                $state = $states[$symbolName]
                $null = Start-LiveArbiter -State $state -ArtifactRoot $state.Artifact
            }
        }
        # Arbiter recovery (ADR-17 B3): an unexpected sidecar exit is
        # relaunched with the resume chain and backoff; the raw lanes are
        # never touched by that recovery.
        foreach ($arbiter in @($arbiterStates.Values)) {
            if ($null -ne $arbiter.launch -and
                [RawQualificationNative]::WaitForProcessExit($arbiter.launch.ProcessHandle, 0)) {
                $arbExit = [uint32][RawQualificationNative]::GetProcessExitCode($arbiter.launch.ProcessHandle)
                $interval = @($processIntervals | Where-Object {
                    $_.role -ceq "LIVE_ARBITRATION" -and $_.symbol -ceq $arbiter.symbol -and $null -eq $_.interval_end_utc
                })
                if ($interval.Count -eq 1) { $interval[0].interval_end_utc = [DateTimeOffset]::UtcNow }
                $null = [RawQualificationNative]::CloseRetainedProcessHandle($arbiter.launch)
                $arbiter.launch = $null
                if ($isContinuous) {
                    $arbiter.consecutiveFailures = [int]$arbiter.consecutiveFailures + 1
                    $delay = [Math]::Min(60.0, [Math]::Pow(2.0, [Math]::Min(5, $arbiter.consecutiveFailures - 1)))
                    $arbiter.restartAtSeconds = $origin.Elapsed.TotalSeconds + $delay
                    if (-not $observerFailures.Contains("LIVE_ARBITRATION_EXITED_EARLY")) {
                        $observerFailures.Add("LIVE_ARBITRATION_EXITED_EARLY")
                        $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                            event = "OBSERVER_FAILED"; observer = "LIVE_ARBITRATION"; symbol = $arbiter.symbol
                            detail = "sidecar exited with code $arbExit; raw lanes continue; resume scheduled"
                        })
                    }
                } else {
                    if (-not $observerFailures.Contains("LIVE_ARBITRATION_EXITED_EARLY")) {
                        $observerFailures.Add("LIVE_ARBITRATION_EXITED_EARLY")
                        $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                            event = "OBSERVER_FAILED"; observer = "LIVE_ARBITRATION"; symbol = $arbiter.symbol
                        })
                    }
                }
            }
            if ($isContinuous -and $null -eq $arbiter.launch -and $origin.Elapsed.TotalSeconds -ge $arbiter.restartAtSeconds) {
                $state = $states[$arbiter.symbol]
                # ADR-17 B3 crash recovery: the resume must continue the
                # DEAD arbiter's own artifact, never the state's CURRENT one —
                # an epoch renewal between the crash and the relaunch would
                # otherwise abandon every un-published trade of the old
                # artifact (fault-gate defect: the resumed segment jumped
                # from trade 6669555498 to 6669564193).  The normal planned
                # renewal advances the arbiter afterwards.
                # (Bare switch: PowerShell 5.1 rejects `-ResumeFromDeath $true`
                # in this parameter set — the boolean becomes a positional
                # argument and the binding throws.)
                $null = Start-LiveArbiter -State $state -ArtifactRoot "$($arbiter.artifact)" -ResumeFromDeath
            }
        }
        if (-not $serviceReady -and $origin.Elapsed.TotalSeconds -ge 90) {
            throw "Dual-symbol hot service did not reach initial durable readiness within 90 seconds."
        }

        if ($lastTelemetry.Elapsed.TotalSeconds -ge $TelemetryIntervalSeconds) {
            $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
            $currentFreeGiB = if ($null -ne $testFreeGiBTelemetry) {
                [uint64]$testFreeGiBTelemetry
            } else {
                [uint64][Math]::Floor([double]$disk.FreeSpace / 1GB)
            }
            $currentClock = Get-RawQualificationClockStatus
            try {
                Assert-RawQualificationClockHealthy -Clock $currentClock
            }
            catch {
                if (-not $observerFailures.Contains("CLOCK_HEALTH_POLICY_FAILED")) {
                    $observerFailures.Add("CLOCK_HEALTH_POLICY_FAILED")
                    $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                        event = "OBSERVER_FAILED"; observer = "WINDOWS_CLOCK"; detail = [string]$_
                    })
                }
            }
            $null = Add-ServiceEvent -Channel "HOST" -Payload ([ordered]@{
                event = "HOST_TELEMETRY"; elapsed_s = [uint64]$origin.Elapsed.TotalSeconds
                free_gib = $currentFreeGiB; clock = $currentClock
                network = Get-RawQualificationNetworkCounters
                active_job_processes = [uint32][RawQualificationNative]::GetActiveProcessCount($job)
            })
            if ($currentFreeGiB -lt $persistentReserveGiB) {
                if ($isContinuous) {
                    # ADR-17 B2: an unsafe storage condition triggers a SAFE,
                    # evidenced stop of the service (never unlimited
                    # availability on finite storage, never an automatic raw
                    # deletion).  Bounded modes fail fast with evidence.
                    $storageSafeStop = $true
                    if (-not (Test-Path -LiteralPath $serviceStopFile)) {
                        $null = Write-RawQualificationDurableNewFile -Path $serviceStopFile -Bytes ([byte[]]@())
                    }
                    if (-not $observerFailures.Contains("STORAGE_RESERVE_CROSSED_SAFE_STOP")) {
                        $observerFailures.Add("STORAGE_RESERVE_CROSSED_SAFE_STOP")
                        $null = Add-ServiceEvent -Channel "HOST" -Payload ([ordered]@{
                            event = "STORAGE_SAFE_STOP_REQUESTED"; free_gib = $currentFreeGiB
                            reserve_gib = $persistentReserveGiB
                        })
                    }
                } else {
                    throw "Persistent disk reserve was crossed; capture stopped before storage exhaustion."
                }
            }
            # Semantic health of the canonical view, on the telemetry cadence
            # only (never per 250 ms iteration) and never blocking: audits run
            # as detached processes with MONOTONIC deadlines (wall-clock jumps
            # cannot trigger false timeouts) and their stderr is preserved as
            # evidence instead of discarded.
            foreach ($arbiter in @($arbiterStates.Values)) {
                $arbiterAlive = ($null -ne $arbiter.launch) -and
                    (-not [RawQualificationNative]::WaitForProcessExit($arbiter.launch.ProcessHandle, 0))
                # Cleanup (ADR-17 B6): an in-flight audit must not outlive its
                # arbiter; kill it with its stderr preserved.
                if (-not $arbiterAlive -and $null -ne $arbiter.auditLaunch) {
                    if (-not [RawQualificationNative]::WaitForProcessExit($arbiter.auditLaunch.ProcessHandle, 0)) {
                        $null = [RawQualificationNative]::TerminateProcessHandle($arbiter.auditLaunch.ProcessHandle, 0xEE45)
                        $null = [RawQualificationNative]::WaitForProcessExit($arbiter.auditLaunch.ProcessHandle, 10000)
                    }
                    $null = [RawQualificationNative]::CloseRetainedProcessHandle($arbiter.auditLaunch)
                    $arbiter.auditLaunch = $null
                    $arbiter.lastPrefixAuditResult = "ARBITER_DIED"
                }
                $journalSize = if (Test-Path -LiteralPath $arbiter.journal -PathType Leaf) {
                    (Get-Item -LiteralPath $arbiter.journal).Length
                } else { 0 }
                if ($arbiterAlive) {
                    if ($null -ne $arbiter.lastAuditedSize) {
                        if ($journalSize -le $arbiter.lastAuditedSize) {
                            # No growth across two telemetry ticks (>= 2 *
                            # TelemetryIntervalSeconds) while the arbiter is
                            # alive: a semantic stall deadline, not a 250 ms
                            # sampling artifact.  A planned rebind transition
                            # (rebindActive) is exempt up to its bound (60 s:
                            # the drain deadline is 30 s) — defect
                            # hrs-e4878b5f365f typed a legitimate 21.3 s rebind
                            # pause as a stall.
                            $transitionExempt = $arbiter.rebindActive -and
                                $null -ne $arbiter.rebindLaunchedAt -and
                                ([DateTimeOffset]::UtcNow - $arbiter.rebindLaunchedAt).TotalSeconds -lt 60
                            if (-not $transitionExempt) {
                                $arbiter.rebindActive = $false
                                $arbiter.stallTicks = [int]$arbiter.stallTicks + 1
                                if ($arbiter.stallTicks -ge 2 -and
                                    -not $observerFailures.Contains("LIVE_ARBITRATION_STALLED")) {
                                    $observerFailures.Add("LIVE_ARBITRATION_STALLED")
                                    $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                                        event = "OBSERVER_FAILED"; observer = "LIVE_ARBITRATION"
                                        symbol = $arbiter.symbol
                                        detail = "canonical journal did not grow across two telemetry ticks"
                                    })
                                }
                            }
                        } else {
                            $arbiter.stallTicks = 0
                            $arbiter.rebindActive = $false
                        }
                    }
                    $arbiter.lastAuditedSize = $journalSize
                }
                # Collect a previously launched detached audit.
                if ($null -ne $arbiter.auditLaunch) {
                    if ([RawQualificationNative]::WaitForProcessExit($arbiter.auditLaunch.ProcessHandle, 0)) {
                        $auditExit = [uint32][RawQualificationNative]::GetProcessExitCode($arbiter.auditLaunch.ProcessHandle)
                        $arbiter.lastPrefixAuditResult = if ($auditExit -eq 0) { "PASS" } else { "FAIL" }
                        if ($auditExit -ne 0) {
                            if (-not $observerFailures.Contains("LIVE_ARBITRATION_PREFIX_AUDIT")) {
                                $observerFailures.Add("LIVE_ARBITRATION_PREFIX_AUDIT")
                                $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                                    event = "OBSERVER_FAILED"; observer = "LIVE_ARBITRATION"
                                    symbol = $arbiter.symbol
                                    detail = "incremental prefix audit rejected the canonical journal (exit $auditExit)"
                                })
                            }
                        }
                        $null = [RawQualificationNative]::CloseRetainedProcessHandle($arbiter.auditLaunch)
                        $arbiter.auditLaunch = $null
                        $arbiter.lastPrefixAudit = [DateTimeOffset]::UtcNow
                    } elseif ($null -ne $arbiter.auditStartedStopwatch -and
                        $arbiter.auditStartedStopwatch.Elapsed.TotalSeconds -ge $arbiterAuditDeadlineSeconds) {
                        # A hung auditor must not outlive its budget: kill it
                        # and record the failure with its stderr preserved.
                        # The deadline is MONOTONIC: a wall-clock jump can
                        # neither cancel nor extend it.
                        $null = [RawQualificationNative]::TerminateProcessHandle($arbiter.auditLaunch.ProcessHandle, 0xEE44)
                        $null = [RawQualificationNative]::WaitForProcessExit($arbiter.auditLaunch.ProcessHandle, 10000)
                        $null = [RawQualificationNative]::CloseRetainedProcessHandle($arbiter.auditLaunch)
                        $arbiter.auditLaunch = $null
                        $arbiter.lastPrefixAudit = [DateTimeOffset]::UtcNow
                        $arbiter.lastPrefixAuditResult = "TIMEOUT"
                        if (-not $observerFailures.Contains("LIVE_ARBITRATION_AUDIT_TIMEOUT")) {
                            $observerFailures.Add("LIVE_ARBITRATION_AUDIT_TIMEOUT")
                            $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                                event = "OBSERVER_FAILED"; observer = "LIVE_ARBITRATION_AUDITOR"
                                symbol = $arbiter.symbol; detail = "prefix audit exceeded its deadline and was terminated"
                            })
                        }
                    }
                }
                # Launch the next detached audit on a coarse cadence (every 5
                # minutes) once the journal has content.  In accelerated tests
                # the cadence scales down so the audit path is exercised.
                $auditCadence = if ($isTestClock) { 20 } else { 300 }
                if ($arbiterAlive -and $null -eq $arbiter.auditLaunch -and $journalSize -gt 0 -and
                    ($null -eq $arbiter.lastPrefixAudit -or
                     ([DateTimeOffset]::UtcNow - $arbiter.lastPrefixAudit).TotalSeconds -ge $auditCadence)) {
                    $arbiter.auditStdout = Join-Path $arbiter.dir ("{0}-audit-{1}.stdout.txt" -f $arbiter.symbol, $arbiter.auditSequence)
                    $arbiter.auditStderr = Join-Path $arbiter.dir ("{0}-audit-{1}.stderr.txt" -f $arbiter.symbol, $arbiter.auditSequence)
                    $arbiter.auditSequence = [int]$arbiter.auditSequence + 1
                    $verifierExe = if ($ArbiterVerifyOverride -ne "") { $ArbiterVerifyOverride } else { $liveArbiterVerify }
                    $auditArgs = [string[]]@($arbiter.journal, "--incremental")
                    # Incremental prefix audits run the bounded raw oracle over
                    # the covered prefix (ADR-17 B5).  The oracle root is the
                    # SYMBOL root: the RESUMED segment declares the artifacts it
                    # covers (artifact_root + prior_artifacts) and the catch-up
                    # walk may publish prior-artifact tail trades that the
                    # CURRENT epoch artifact alone does not contain (defect
                    # hrs-f7e726a48da8: the audit rejected those catch-up trades
                    # as invented when bound to the epoch artifact only).
                    $auditSymbolRoot = Join-Path $runRoot ($states[$arbiter.symbol].Code)
                    $auditArgs += [string[]]@("--oracle-artifact", $auditSymbolRoot)
                    $arbiter.auditLaunch = [RawQualificationNative]::StartSuspendedInJobRetained(
                        $job, $verifierExe, $auditArgs, $repo, $arbiter.auditStdout, $arbiter.auditStderr
                    )
                    $arbiter.auditStartedStopwatch = [Diagnostics.Stopwatch]::StartNew()
                }
            }
            $lastTelemetry.Restart()
        }

        if (-not $observerSkipped -and $null -ne $etw -and [RawQualificationNative]::WaitForProcessExit($etw.ProcessHandle, 0)) {
            if (-not $observerFailures.Contains("KERNEL_ETW_EXITED_EARLY")) {
                $observerFailures.Add("KERNEL_ETW_EXITED_EARLY")
                $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{ event = "OBSERVER_FAILED"; observer = "KERNEL_ETW" })
            }
        }
        if (-not $observerSkipped -and $null -ne $witness -and [RawQualificationNative]::WaitForProcessExit($witness.ProcessHandle, 0)) {
            if (-not $observerFailures.Contains("NETWORK_WITNESS_EXITED_EARLY")) {
                $observerFailures.Add("NETWORK_WITNESS_EXITED_EARLY")
                $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{ event = "OBSERVER_FAILED"; observer = "NETWORK_WITNESS" })
            }
        }
        # Sealed-window verification (ADR-17 B2): every completed epoch and
        # every sealed canonical segment is verified with BOTH independent
        # oracles WHILE the next epoch captures â€” as detached processes with
        # monotonic deadlines, so a hung evaluator never blocks the service
        # loop and raw stays safe.
        Process-VerificationTasks
        # Window milestones (24 h / 7 d / 30 d): report from the RUNNING
        # capture instead of stopping it to evaluate; the milestone
        # aggregates the sealed windows already verified by both oracles plus
        # the current live prefix state â€” no synchronous journal scans here.
        # The milestone clock is the test control clock scaled by TimeScale;
        # in production TimeScale is 1 (wall time).
        $elapsedDays = [math]::Floor((($origin.Elapsed.TotalSeconds * $milestoneClockScale) / 86400.0))
        if ($elapsedDays -gt $lastMilestoneDays) {
            $lastMilestoneDays = $elapsedDays
            $milestone = [ordered]@{ day = $elapsedDays; symbols = [ordered]@{} }
            foreach ($state in @($states.Values)) {
                $symbolVerified = @($verifiedWindows | Where-Object { $_.symbol -ceq $state.Symbol })
                $verifiedEpochs = @($symbolVerified | Where-Object { $_.status -ceq "PASS" }).Count
                $sealedCoverageSeconds = if ($symbolVerified.Count -gt 0) {
                    [uint64](@($symbolVerified | Measure-Object -Property coverage_seconds -Sum).Sum)
                } else { [uint64]0 }
                $arbiter = $arbiterStates[$state.Symbol]
                $prefixAudit = if ($null -ne $arbiter -and $null -ne $arbiter.lastPrefixAuditResult) {
                    $arbiter.lastPrefixAuditResult
                } else { "NOT_RUN" }
                # NOTE: named `canonicalSegments` (never `$segments`): PowerShell
                # variables are case-insensitive and `$segments` would clobber
                # the topology variable `$segmentS` for every later epoch.
                $canonicalSegments = if ($null -ne $arbiter) { $arbiter.segmentSequence } else { 0 }
                $milestone.symbols[$state.Symbol] = [ordered]@{
                    verified_epochs = $verifiedEpochs
                    sealed_coverage_seconds = $sealedCoverageSeconds
                    canonical_segments = $canonicalSegments
                    canonical_prefix_audit = $prefixAudit
                }
            }
            $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
                event = "WINDOW_MILESTONE"; elapsed_s = [uint64]$origin.Elapsed.TotalSeconds
                milestone_day = $elapsedDays; milestone_clock_scale = $milestoneClockScale
                detail = $milestone
            })
        }
        Start-Sleep -Milliseconds 250
    }

    $drain = [Diagnostics.Stopwatch]::StartNew()
    $drainStates = @($states.Values) + @($successors.Values | Where-Object { $null -ne $_ })
    while (@($drainStates | Where-Object { $null -ne $_.Launch }).Count -ne 0) {
        foreach ($state in $drainStates) {
            if ($null -ne $state.Launch -and [RawQualificationNative]::WaitForProcessExit($state.Launch.ProcessHandle, 0)) {
                Update-SymbolArtifactAndReadiness -State $state
                $code = [uint32][RawQualificationNative]::GetProcessExitCode($state.Launch.ProcessHandle)
                $interval = @($processIntervals | Where-Object {
                    [uint32]$_.pid -eq [uint32]$state.Launch.ProcessId -and $null -eq $_.interval_end_utc
                })
                if ($interval.Count -ne 1) { throw "Final supervisor process interval identity is ambiguous." }
                $interval[0].interval_end_utc = [DateTimeOffset]::UtcNow
                if ($null -ne $state.Artifact) {
                    $completedArtifacts.Add([pscustomobject]@{
                        symbol = $state.Symbol; epoch = $state.Epoch; root = $state.Artifact; exit_code = $code
                    })
                }
                $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
                    event = "SYMBOL_FINAL_EPOCH_EXITED"; symbol = $state.Symbol; epoch = $state.Epoch; exit_code = $code
                })
                $null = [RawQualificationNative]::CloseRetainedProcessHandle($state.Launch)
                $state.Launch = $null
            }
        }
        if ($drain.Elapsed.TotalSeconds -gt 1800) { throw "Symbol supervisors exceeded terminal drain deadline." }
        Start-Sleep -Milliseconds 250
    }

    if (-not $observerSkipped) {
        foreach ($path in @($etwStop, $networkStop)) {
            if (-not (Test-Path -LiteralPath $path)) {
                # Both cooperative observers define stop by create-only existence;
                # NetworkWitnessV2 additionally requires the exact file to be empty.
                $null = Write-RawQualificationDurableNewFile -Path $path -Bytes ([byte[]]@())
            }
        }
        foreach ($observer in @($etw, $witness)) {
            if (-not [RawQualificationNative]::WaitForProcessExit($observer.ProcessHandle, 30000)) {
                $observerFailures.Add("OBSERVER_STOP_DEADLINE_EXCEEDED")
                [RawQualificationNative]::TerminateProcessHandle($observer.ProcessHandle, 0xEE21)
                $null = [RawQualificationNative]::WaitForProcessExit($observer.ProcessHandle, 30000)
            }
        }
        $etwExitCode = [uint32][RawQualificationNative]::GetProcessExitCode($etw.ProcessHandle)
        $witnessExitCode = [uint32][RawQualificationNative]::GetProcessExitCode($witness.ProcessHandle)
        $etwProcessId = [uint32]$etw.ProcessId
    }
    $observationEndUtc = [DateTimeOffset]::UtcNow
    # Live cross-lane arbitration (ADR-16/ADR-17): the sidecar stops on the
    # cooperative stop request (Continuous) or at the capture horizon
    # (bounded modes); its closed canonical journal set is independently
    # verified by the Rust and Python auditors against the symbol's whole raw
    # oracle root before the service terminal commits.
    if ($isContinuous) {
        # Complete any pending planned renewal before sealing the canonical
        # view (ADR-17 B3): the drained successor epoch's raw is canonicalized
        # through the normal rebind path, so the closed window covers every
        # epoch that captured.
        foreach ($symbolName in @("BTCUSDT", "ETHUSDT")) {
            $successor = $successors[$symbolName]
            if ($null -ne $successor) {
                $states[$symbolName] = $successor
                $successors[$symbolName] = $null
                $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
                    event = "SYMBOL_EPOCH_RENEWED"; symbol = $symbolName
                    predecessor_epoch = $successor.Epoch - 1; successor_epoch = $successor.Epoch
                    predecessor_clean = $true; no_outer_gap = $true
                    stop_transition = $true
                })
            }
            $state = $states[$symbolName]
            $arb = $arbiterStates[$symbolName]
            if ($null -ne $state.Artifact -and $null -ne $arb -and $arb.artifact -cne $state.Artifact) {
                Rebind-LiveArbiter -State $state -NewArtifactRoot $state.Artifact
            }
        }
    }
    # Drain any pending sealed-segment verification before the final
    # journal-set audit (bounded by the audit deadline).
    $taskDrain = [Diagnostics.Stopwatch]::StartNew()
    while ((@($pendingSegmentVerifications).Count -gt 0 -or
            @($verificationTasks | Where-Object { $null -ne $_.launch }).Count -gt 0) -and
            $taskDrain.Elapsed.TotalSeconds -lt $arbiterAuditDeadlineSeconds) {
        Process-VerificationTasks
        Start-Sleep -Milliseconds 250
    }
    foreach ($arbiter in @($arbiterStates.Values)) {
        $arbiterExit = if ($isContinuous) {
            Stop-LiveArbiter -Arbiter $arbiter
        } else {
            if ($null -ne $arbiter.launch) {
                if (-not [RawQualificationNative]::WaitForProcessExit($arbiter.launch.ProcessHandle, 30000)) {
                    $observerFailures.Add("LIVE_ARBITRATION_STOP_DEADLINE_EXCEEDED")
                    [RawQualificationNative]::TerminateProcessHandle($arbiter.launch.ProcessHandle, 0xEE22)
                    $null = [RawQualificationNative]::WaitForProcessExit($arbiter.launch.ProcessHandle, 30000)
                }
                $code = [uint32][RawQualificationNative]::GetProcessExitCode($arbiter.launch.ProcessHandle)
                $null = [RawQualificationNative]::CloseRetainedProcessHandle($arbiter.launch)
                $arbiter.launch = $null
                $code
            } else { 0 }
        }
        if ($arbiterExit -ne 0) {
            throw ("Live arbitration sidecar for {0} exited with code {1}." -f $arbiter.symbol, $arbiterExit)
        }
        if ((Get-Item -LiteralPath $arbiter.stderr).Length -ne 0) {
            throw ("Live arbitration sidecar for {0} wrote unexpected stderr." -f $arbiter.symbol)
        }
        $arbInterval = @($processIntervals | Where-Object {
            $_.role -ceq "LIVE_ARBITRATION" -and $_.symbol -ceq $arbiter.symbol -and $null -eq $_.interval_end_utc
        })
        if ($arbInterval.Count -gt 1) { throw "Live arbitration process interval identity is ambiguous." }
        if ($arbInterval.Count -eq 1) { $arbInterval[0].interval_end_utc = $observationEndUtc }
        # ADR-16 promotion gate (ADR-17 B5 oracles): the closed canonical
        # journal must pass the redundant-evidence oracle in BOTH independent
        # verifiers (trades = raw union above the trade floor with payload and
        # lineage per record; depth = trusted prefixes of the publishing
        # lane); SKIPPED is never a promotion.
        $symbolRoot = Join-Path $runRoot ($states[$arbiter.symbol].Code)
        $arbRustReport = Join-Path $arbiterRoot ("{0}-rust-verify.json" -f $arbiter.symbol)
        $arbRustArgs = if ($isContinuous) {
            [string[]]@("--journal-root", $arbiter.dir, "--oracle-artifact", $symbolRoot)
        } else {
            [string[]]@($arbiter.journal, "--oracle-artifact", $symbolRoot)
        }
        $arbRust = Invoke-ExactProcess -Executable $liveArbiterVerify -Arguments $arbRustArgs
        $null = Write-RawQualificationDurableNewFile -Path $arbRustReport -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($arbRust.TrimEnd() + "`n"))
        $arbRustValue = $arbRust | ConvertFrom-Json
        if ($arbRustValue.status -cne "PASS" -or $arbRustValue.oracle_identity -cne "PASS") {
            throw ("Live arbitration Rust oracle verification was not PASS for {0}." -f $arbiter.symbol)
        }
        $arbPythonReport = Join-Path $arbiterRoot ("{0}-python-verify.json" -f $arbiter.symbol)
        $oldPythonPath = $env:PYTHONPATH
        try {
            $env:PYTHONPATH = Join-Path $repo "src"
            $arbPythonArgs = if ($isContinuous) {
                [string[]]@("-B", "-m", "binance_lob.live_arbitration_verify_cli",
                    "--journal-root", $arbiter.dir, "--oracle-artifact", $symbolRoot, "--output", $arbPythonReport)
            } else {
                [string[]]@("-B", "-m", "binance_lob.live_arbitration_verify_cli",
                    $arbiter.journal, "--oracle-artifact", $symbolRoot, "--output", $arbPythonReport)
            }
            $null = Invoke-ExactProcess -Executable $python -Arguments $arbPythonArgs
        }
        finally { $env:PYTHONPATH = $oldPythonPath }
        $arbPythonValue = Get-Content -LiteralPath $arbPythonReport -Raw | ConvertFrom-Json
        if ($arbPythonValue.status -cne "PASS" -or $arbPythonValue.oracle_identity -cne "PASS") {
            throw ("Live arbitration Python oracle verification was not PASS for {0}." -f $arbiter.symbol)
        }
        $arbiterVerification[$arbiter.symbol] = [ordered]@{
            symbol = $arbiter.symbol
            journal = Get-ServiceRelativePath -Root $runRoot -FullPath $arbiter.journal
            journal_root = Get-ServiceRelativePath -Root $runRoot -FullPath $arbiter.dir
            journal_sha256 = Get-RawQualificationSha256File -Path $arbiter.journal
            rust_report = Get-ServiceRelativePath -Root $runRoot -FullPath $arbRustReport
            rust_report_sha256 = Get-RawQualificationSha256File -Path $arbRustReport
            python_report = Get-ServiceRelativePath -Root $runRoot -FullPath $arbPythonReport
            python_report_sha256 = Get-RawQualificationSha256File -Path $arbPythonReport
            oracle_identity = "PASS"
            canonical_trades = [int]$arbRustValue.trades
            canonical_depth_frames = [int]$arbRustValue.depth_frames
            canonical_gaps = [int]$arbRustValue.gaps
            canonical_segments = [int]$arbRustValue.segments
            exit_code = [int]$arbiterExit
        }
        $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
            event = "LIVE_ARBITRATION_VERIFIED"; symbol = $arbiter.symbol
        })
    }
    Add-CollectorProcessIntervals -ObservationEnd $observationEndUtc
    $launcherIntervals = @($processIntervals | Where-Object { $_.role -ceq "LAUNCHER" })
    if ($launcherIntervals.Count -ne 1 -or $null -ne $launcherIntervals[0].interval_end_utc) {
        throw "Kernel process inventory lacks one open launcher interval."
    }
    $launcherIntervals[0].interval_end_utc = $observationEndUtc
    if (@($processIntervals | Where-Object { $null -eq $_.interval_end_utc }).Count -ne 0) {
        throw "Kernel process inventory contains an unterminated process interval."
    }
    if (-not $observerSkipped) {
        $null = [RawQualificationNative]::CloseRetainedProcessHandle($etw)
        $null = [RawQualificationNative]::CloseRetainedProcessHandle($witness)
        $etw = $null; $witness = $null
    }

    if ($observerSkipped) {
        # TEST-ONLY non-elevated run: the kernel/network observers never ran;
        # the terminal records that honestly instead of fabricating evidence.
        $kernelCaptureReport = [ordered]@{
            schema = "KernelNetworkProductionCaptureV1"; status = "SKIPPED_NOT_ELEVATED"
            run_id = $observerRunId; skipped_reason = "explicit -SkipKernelObserver test invocation (no elevation)"
        }
        $null = Write-RawQualificationDurableNewJson -Path (Join-Path $kernelRoot "kernel-network-capture.json") -Value $kernelCaptureReport
    } else {
        if ($etwExitCode -ne 0 -or (Get-Item -LiteralPath $etwErr -ErrorAction Stop).Length -ne 0) {
            throw "Kernel-Network controller did not seal cleanly."
        }
        if ($witnessExitCode -ne 0 -or (Get-Item -LiteralPath $witnessErr -ErrorAction Stop).Length -ne 0) {
            throw "Independent network witness did not seal cleanly."
        }
        $decodedPath = Join-Path $kernelRoot "kernel-network.xml"
        $decodeOutput = [string[]]@(& $tracerpt $etl -o $decodedPath -of XML -lr -y 2>&1 | ForEach-Object { [string]$_ })
        $decodeExitCode = [int]$LASTEXITCODE
        if ($decodeExitCode -ne 0 -or -not (Test-Path -LiteralPath $decodedPath -PathType Leaf)) {
            throw "tracerpt could not decode Kernel-Network evidence."
        }
        $postQueryOutput = [string[]]@(& $logman query -ets $sessionName 2>&1 | ForEach-Object { [string]$_ })
        $postQueryExitCode = [int]$LASTEXITCODE
        if ($postQueryExitCode -eq 0) { throw "Kernel-Network session remained orphaned after seal." }
        $controllerRecords = [object[]]@(Get-Content -LiteralPath $etwOut -ErrorAction Stop | ForEach-Object {
            $_ | ConvertFrom-Json -ErrorAction Stop
        })
        if ($controllerRecords.Count -ne 2) { throw "Kernel-Network controller did not emit exactly READY then SEALED." }
        $processInventory = [object[]]@($processIntervals | ForEach-Object {
            [ordered]@{
                role = [string]$_.role; symbol = $_.symbol; pid = [uint32]$_.pid
                interval_start_utc = ([DateTimeOffset]$_.interval_start_utc).ToUniversalTime().ToString("o")
                interval_end_utc = ([DateTimeOffset]$_.interval_end_utc).ToUniversalTime().ToString("o")
            }
        })
        $etlItem = Get-Item -LiteralPath $etl -ErrorAction Stop
        $xmlItem = Get-Item -LiteralPath $decodedPath -ErrorAction Stop
        $captureReport = [ordered]@{
            schema = "KernelNetworkProductionCaptureV1"; run_id = $observerRunId; status = "CANDIDATE"
            started_utc = $etwStartedUtc.ToUniversalTime().ToString("o")
            completed_utc = $observationEndUtc.ToUniversalTime().ToString("o")
            controller_executable = $kernelTrace; controller_sha256 = Get-RawQualificationSha256File -Path $kernelTrace
            controller_pid = $etwProcessId; session_name = $sessionName
            controller_exit_code = [int]$etwExitCode; controller_records = $controllerRecords
            controller_stderr_file = "controller.stderr.txt"; controller_stderr_bytes = [uint64](Get-Item -LiteralPath $etwErr).Length
            controller_stderr_sha256 = Get-RawQualificationSha256File -Path $etwErr
            maximum_file_mib = [uint32]$KernelTraceMiB; deadline_s = [uint64]$etwDeadline
            etl_file = "kernel-network.etl"; etl_bytes = [uint64]$etlItem.Length; etl_sha256 = Get-RawQualificationSha256File -Path $etl
            decoded_file = "kernel-network.xml"; decoded_bytes = [uint64]$xmlItem.Length; decoded_sha256 = Get-RawQualificationSha256File -Path $decodedPath
            tracerpt_exit_code = $decodeExitCode; tracerpt_output = $decodeOutput
            orphan_query_exit_code = $postQueryExitCode; orphan_query_output = $postQueryOutput
            monitored_processes = $processInventory; selected_event_ids = [uint16[]]@(12,13,14,15,16,17,28,29,30,31,32)
            raw_packet_payload_capture = $false; diagnostic_only = $true; training_eligible = $false
            correlation_status = "OPEN_PENDING_INDEPENDENT_VERIFY"
        }
        $null = Write-RawQualificationDurableNewJson -Path (Join-Path $kernelRoot "kernel-network-capture.json") -Value $captureReport
    }

    $verification = [Collections.Generic.List[object]]::new()
    foreach ($artifact in $completedArtifacts) {
        $alreadyVerified = @($verifiedWindows | Where-Object {
            $_.symbol -ceq $artifact.symbol -and $_.epoch -eq $artifact.epoch -and $_.status -ceq "PASS"
        })
        if ($alreadyVerified.Count -gt 0) {
            # Already sealed and verified in-loop by both oracles (Continuous):
            # never re-verify the same immutable window twice.
            $verification.Add([ordered]@{
                symbol = $artifact.symbol; epoch = $artifact.epoch; status = "PASS"
                verified_in_loop = $true
                rust_report = $alreadyVerified[0].rust_report
                python_report = $alreadyVerified[0].python_report
                artifact = Get-ServiceRelativePath -Root $runRoot -FullPath $artifact.root
            })
            continue
        }
        if ([uint32]$artifact.exit_code -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $artifact.root "supervisor-terminal.json") -PathType Leaf)) {
            $verification.Add([ordered]@{
                symbol = $artifact.symbol; epoch = $artifact.epoch; status = "INCOMPLETE_PRESERVED"; exit_code = $artifact.exit_code
                artifact = Get-ServiceRelativePath -Root $runRoot -FullPath $artifact.root
            })
            continue
        }
        $base = "{0}{1}" -f $artifact.symbol.Substring(0,1).ToLowerInvariant(), $artifact.epoch
        $rustReport = Join-Path $verificationRoot ("$base-rust.json")
        $pythonReport = Join-Path $verificationRoot ("$base-python.json")
        $null = Invoke-ExactProcess -Executable $rustVerifier -Arguments ([string[]]@($artifact.root, $rustReport))
        $oldPythonPath = $env:PYTHONPATH
        try {
            $env:PYTHONPATH = Join-Path $repo "src"
            $null = Invoke-ExactProcess -Executable $python -Arguments ([string[]]@(
                "-B", "-m", "binance_lob.hot_redundant_verify_cli", $artifact.root, "--output", $pythonReport
            ))
        }
        finally { $env:PYTHONPATH = $oldPythonPath }
        $rustValue = Get-Content -LiteralPath $rustReport -Raw | ConvertFrom-Json -ErrorAction Stop
        $pythonValue = Get-Content -LiteralPath $pythonReport -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($rustValue.status -cne "PASS" -or $pythonValue.status -cne "PASS" -or
            $rustValue.supervisor_id -cne $pythonValue.supervisor_id -or
            $rustValue.terminal_file_sha256 -cne $pythonValue.terminal_file_sha256 -or
            $rustValue.journal_terminal_sha256 -cne $pythonValue.journal_terminal_sha256) {
            throw "Independent hot-redundant verifiers did not converge."
        }
        $verification.Add([ordered]@{
            symbol = $artifact.symbol; epoch = $artifact.epoch; status = "PASS"
            supervisor_id = $rustValue.supervisor_id
            terminal_sha256 = $rustValue.terminal_file_sha256
            journal_sha256 = $rustValue.journal_terminal_sha256
            artifact = Get-ServiceRelativePath -Root $runRoot -FullPath $artifact.root
            rust_report = Get-ServiceRelativePath -Root $runRoot -FullPath $rustReport
            rust_report_sha256 = Get-RawQualificationSha256File -Path $rustReport
            python_report = Get-ServiceRelativePath -Root $runRoot -FullPath $pythonReport
            python_report_sha256 = Get-RawQualificationSha256File -Path $pythonReport
        })
    }
    foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
        if (@($verification | Where-Object { $_.symbol -ceq $symbol -and $_.status -ceq "PASS" }).Count -eq 0) {
            throw "$symbol has no independently verified service epoch."
        }
    }

    $systemRoot = Join-Path $observerRoot "system"
    $null = Invoke-ExactProcess -Executable $powershell -Arguments ([string[]]@(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $systemEvidenceScript,
        "-Action", "Collect", "-EvidenceRoot", $systemRoot, "-RunId", $observerRunId,
        "-StartUtc", $startUtc.ToString("o"), "-EndUtc", $observationEndUtc.ToString("o")
    ))
    $kernelVerificationPath = Join-Path $verificationRoot "kernel-network.json"
    $networkVerificationPath = Join-Path $verificationRoot "network-witness.json"
    $systemVerificationPath = Join-Path $verificationRoot "system-evidence.json"
    if ($observerSkipped) {
        $kernelVerification = [ordered]@{ status = "SKIPPED_NOT_ELEVATED"; run_id = $observerRunId }
        $networkVerification = [ordered]@{ status = "SKIPPED_NOT_ELEVATED"; observation_id = $observerRunId }
    } else {
        $kernelVerification = Invoke-JsonVerifier -Module "binance_lob.kernel_network_production_verify_cli" -InputRoot $kernelRoot -OutputPath $kernelVerificationPath
        $networkVerification = Invoke-JsonVerifier -Module "binance_lob.network_witness_verify_cli" -InputRoot $networkRoot -OutputPath $networkVerificationPath
    }
    $systemVerification = Invoke-JsonVerifier -Module "binance_lob.system_evidence_verify_cli" -InputRoot $systemRoot -OutputPath $systemVerificationPath
    Assert-ServiceImplementationUnchanged

    $endUtc = [DateTimeOffset]::UtcNow

    $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{ event = "SERVICE_TERMINAL_PREPARED" })
    $prefix = Get-RawQualificationJournalPrefixSnapshot -Journal $journal
    $openOuterGapCount = @($states.Values | Where-Object { $null -ne $_.OuterGap }).Count
    $status = if ($observerFailures.Count -eq 0 -and $outerGaps.Count -eq 0 -and $openOuterGapCount -eq 0) {
        "PASS"
    } elseif ($observerFailures.Count -eq 0) {
        "CAPTURE_COMPLETE_WITH_EXPLICIT_GAPS"
    } else {
        "CAPTURE_COMPLETE_WITH_OBSERVABILITY_FAILURES"
    }
    $terminal = [ordered]@{
        schema = "HotRedundantQualificationTerminalV1"; status = $status; run_id = $runId
        started_utc = $startUtc.ToString("o"); finished_utc = $endUtc.ToString("o")
        mode = $Mode; continuous = $isContinuous; epoch_window_s = $EpochWindowSeconds
        time_scale = $TimeScale; stop_requested = $serviceStopRequested
        storage_safe_stop = $storageSafeStop; observers_skipped = $observerSkipped
        requested_duration_s = $TotalSeconds; observer_failures = @($observerFailures)
        outer_gaps = @($outerGaps); verification = @($verification)
        verified_windows = [object[]]@($verifiedWindows)
        open_outer_gaps = [object[]]@($states.Values | Where-Object { $null -ne $_.OuterGap } | ForEach-Object {
            [ordered]@{
                symbol = $_.Symbol; gap_id = [uint64]$_.OuterGap.gap_id
                opened_elapsed_ticks = [uint64]$_.OuterGap.opened_elapsed_ticks
            }
        })
        observer_verification = [ordered]@{
            kernel_network = if ($observerSkipped) {
                [ordered]@{ status = "SKIPPED_NOT_ELEVATED"; run_id = $observerRunId }
            } else {
                [ordered]@{ path = Get-ServiceRelativePath -Root $runRoot -FullPath $kernelVerificationPath; sha256 = Get-RawQualificationSha256File -Path $kernelVerificationPath; run_id = $kernelVerification.run_id }
            }
            network_witness = if ($observerSkipped) {
                [ordered]@{ status = "SKIPPED_NOT_ELEVATED"; observation_id = $observerRunId }
            } else {
                [ordered]@{ path = Get-ServiceRelativePath -Root $runRoot -FullPath $networkVerificationPath; sha256 = Get-RawQualificationSha256File -Path $networkVerificationPath; observation_id = $networkVerification.observation_id }
            }
            system_evidence = [ordered]@{ path = Get-ServiceRelativePath -Root $runRoot -FullPath $systemVerificationPath; sha256 = Get-RawQualificationSha256File -Path $systemVerificationPath; run_id = $systemVerification.run_id }
            live_arbitration = [ordered]@{ btcusdt = $arbiterVerification["BTCUSDT"]; ethusdt = $arbiterVerification["ETHUSDT"] }
        }
        journal_precommit = $prefix
    }
    $terminalSha = Write-RawQualificationDurableNewJson -Path (Join-Path $runRoot "service-terminal.json") -Value $terminal
    $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
        event = "SERVICE_COMMITTED"; terminal_file = "service-terminal.json"; terminal_sha256 = $terminalSha
    })
    $terminalWritten = $true
    Close-RawQualificationJournal -Journal $journal
    $serviceVerificationPath = Join-Path $verificationRoot "service.json"
    $serviceVerification = Invoke-JsonVerifier -Module "binance_lob.hot_service_verify_cli" -InputRoot $runRoot -OutputPath $serviceVerificationPath
    if ($serviceVerification.terminal_status -cne $status) {
        throw "Independent service verification disagreed with the terminal status."
    }
    Write-Output ("{0}: {1}" -f $status, (Join-Path $runRoot "service-terminal.json"))
}
catch {
    $caught = $_
    try {
        if ($null -ne $journal -and -not $journal.Closed) {
            $failureSummary = [ordered]@{
                exception_type = $caught.Exception.GetType().FullName
                hresult = [int]$caught.Exception.HResult
                fully_qualified_error_id = [string]$caught.FullyQualifiedErrorId
                category = [string]$caught.CategoryInfo.Category
                message = [string]$caught.Exception.Message
            }
            $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
                event = "SERVICE_FAILURE_PREPARED"; failure = $failureSummary
            })
            $failurePrefix = Get-RawQualificationJournalPrefixSnapshot -Journal $journal
            $failure = [ordered]@{
                schema = "HotRedundantQualificationFailureV1"; status = "FAILED"; run_id = $runId
                observed_utc = [DateTimeOffset]::UtcNow.ToString("o")
                elapsed_s = [decimal]$origin.Elapsed.TotalSeconds
                failure = $failureSummary
                script_stack_trace = [string]$caught.ScriptStackTrace
                observer_failures = @($observerFailures)
                active_processes = [object[]]@($states.Values | Where-Object { $null -ne $_.Launch } | ForEach-Object {
                    [ordered]@{ symbol = $_.Symbol; epoch = $_.Epoch; pid = [uint32]$_.Launch.ProcessId }
                })
                journal_precommit = $failurePrefix
            }
            $failurePath = Join-Path $runRoot "service-failure.json"
            $failureSha = Write-RawQualificationDurableNewJson -Path $failurePath -Value $failure
            $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
                event = "SERVICE_FAILED_COMMITTED"; failure_file = "service-failure.json"; failure_sha256 = $failureSha
            })
            Close-RawQualificationJournal -Journal $journal
        }
    }
    catch {
        [Console]::Error.WriteLine(("Primary service failure: {0}; failure-evidence persistence also failed: {1}" -f $caught.Exception.Message, $_.Exception.Message))
    }
    # Preserve the terminating error record on the error stream (the gate
    # captures it as evidence) and propagate a deterministic non-zero exit
    # code AFTER the finally block released every resource.
    [Console]::Error.WriteLine(([string]$caught | Out-String))
    $failureExitCode = 2
}
finally {
    if ($null -ne $states) {
        foreach ($state in $states.Values) {
            if ($null -ne $state.Launch -and $state.Launch.ProcessHandle -ne [IntPtr]::Zero) {
                $null = [RawQualificationNative]::TryTerminateJobObjectNoThrow($job, 0xEE31)
                $null = [RawQualificationNative]::WaitForProcessExit($state.Launch.ProcessHandle, 30000)
                $null = [RawQualificationNative]::CloseRetainedProcessHandle($state.Launch)
                $state.Launch = $null
            }
        }
    }
    foreach ($observer in @($etw, $witness)) {
        if ($null -ne $observer -and $observer.ProcessHandle -ne [IntPtr]::Zero) {
            $null = [RawQualificationNative]::TryTerminateJobObjectNoThrow($job, 0xEE32)
            $null = [RawQualificationNative]::WaitForProcessExit($observer.ProcessHandle, 30000)
            $null = [RawQualificationNative]::CloseRetainedProcessHandle($observer)
        }
    }
    if ($job -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($job) }
    if ($null -ne $journal -and -not $journal.Closed) { Close-RawQualificationJournal -Journal $journal }
    if ($null -ne $mutex) {
        if ($mutexAcquired) {
            $mutex.ReleaseMutex()
            $mutexAcquired = $false
        }
        $mutex.Dispose()
    }
}
if ($null -ne $runRoot -and $runRoot.Length -gt 0) {
    try {
        # Durable exit-code evidence for the supervisor harness: PowerShell's
        # Start-Process -RedirectStandard* wrapper reports ExitCode 0 even for
        # non-zero children, so the launcher persists its own terminal code.
        $exitMarker = Join-Path $runRoot "launcher-exit.json"
        [IO.File]::WriteAllText(
            $exitMarker,
            ('{"schema":"LauncherExitV1","run_id":"' + $runId + '","exit_code":' + [string]$failureExitCode + '}' + [Environment]::NewLine),
            [Text.UTF8Encoding]::new($false)
        )
    }
    catch {
        [Console]::Error.WriteLine(("launcher exit marker persistence failed: {0}" -f $_.Exception.Message))
    }
}
if ($failureExitCode -ne 0) {
    # The failure evidence is already committed (service-failure.json); the
    # finally block above released every retained process handle, the job
    # object, the journal and the host mutex before this deterministic exit.
    exit $failureExitCode
}
