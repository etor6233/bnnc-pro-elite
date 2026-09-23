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
function Get-ServiceMutexName {
    param([string] $Repository, [bool] $TestClock, [string] $BinaryRoot)
    if (-not $TestClock -or $BinaryRoot -eq "") { return "Global\BinanceHotRedundantQualificationV1" }
    $normalized = [IO.Path]::GetFullPath($Repository).TrimEnd('\', '/').ToLowerInvariant()
    if (@($normalized -split '[\\/]' | Where-Object { $_ -ceq '.local' }).Count -eq 0) {
        throw "Concurrent test isolation requires a repository inside an exact .local directory."
    }
    $digest = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($normalized))
    return "Global\BinanceHotRedundantQualificationTest_$digest"
}
$mutexName = Get-ServiceMutexName -Repository $repo -TestClock $isTestClock -BinaryRoot $ReleaseBinRoot
$mutex = [Threading.Mutex]::new($false, $mutexName, [ref]$createdMutex)
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
# Independent inventory of every raw artifact discovered by the service.
# It outlives State replacements and is never reconstructed from a canonical
# journal. A prior is not retired without an explicit durable drain proof.
$sourceArtifacts = @{}
$canonicalStreamHealth = @{}
$observerWindows = [Collections.Generic.List[object]]::new()
$kernelWindows = [Collections.Generic.List[object]]::new()
$networkWindows = [Collections.Generic.List[object]]::new()
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
        OuterGap = $null; EverReady = $false; EpochReady = $false
        LastExitCode = $null; LastExitClean = $null
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
    $State.EpochReady = $false
    $State.LastExitCode = $null; $State.LastExitClean = $null
    $State.NeedsArbiterRebind = $false
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
    if (-not $sourceArtifacts.ContainsKey($State.Symbol)) {
        $sourceArtifacts[$State.Symbol] = [Collections.Generic.List[string]]::new()
    }
    if (-not $sourceArtifacts[$State.Symbol].Contains([string]$State.Artifact)) {
        $sourceArtifacts[$State.Symbol].Add([string]$State.Artifact)
        $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
            event = "RAW_ARTIFACT_DISCOVERED"; symbol = $State.Symbol; epoch = $State.Epoch
            artifact = Get-ServiceRelativePath -Root $runRoot -FullPath $State.Artifact
        })
    }
    $events = Join-Path $State.Artifact "supervisor-events.jsonl"
    $ready = (Test-Path -LiteralPath $events -PathType Leaf) -and
        (Select-String -LiteralPath $events -SimpleMatch '"event":"LANE_READY"' -Quiet -ErrorAction SilentlyContinue)
    $State.EpochReady = [bool]$ready
    if ($isContinuous -and $serviceReady -and $ready -and
        ($null -eq $arbiterStates[$State.Symbol] -or
         $arbiterStates[$State.Symbol].artifact -cne $State.Artifact)) {
        $State.NeedsArbiterRebind = $true
    }
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

function Get-SymbolArtifactInventory {
    param([Parameter(Mandatory = $true)] [string] $Symbol)
    if (-not $sourceArtifacts.ContainsKey($Symbol)) { return @() }
    return @($sourceArtifacts[$Symbol].ToArray())
}

function Sync-ServiceSourceInventory {
    # Terminal discovery is bounded to the two owned supervisor hierarchies.
    # A supervisor that created raw and exited between polls still belongs to
    # the expected source set; it cannot disappear merely through lost state.
    foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
        $code = $symbol.Substring(0, 1).ToLowerInvariant()
        $symbolRoot = Join-Path $runRoot $code
        if (-not (Test-Path -LiteralPath $symbolRoot -PathType Container)) { continue }
        foreach ($epochRoot in @(Get-ChildItem -LiteralPath $symbolRoot -Directory)) {
            if ($epochRoot.Name -notmatch '^e([1-9][0-9]*)$') { throw "Unexpected epoch directory under the owned symbol root." }
            $epochNumber = [int]$Matches[1]
            $discovered = New-SymbolState -Symbol $symbol -Code $code
            $discovered.Epoch = $epochNumber
            $discovered.EverReady = $true # discovery must not fabricate a new first-readiness event
            $discovered.OutputRoot = $epochRoot.FullName
            Update-SymbolArtifactAndReadiness -State $discovered
        }
    }
}

function Open-SymbolOuterGap {
    param([Parameter(Mandatory = $true)] $State, [uint32] $ExitCode)
    if ($null -ne $State.OuterGap) { return }
    $State.OuterGap = [pscustomobject]@{
        gap_id = [uint64]($outerGaps.Count + @($states.Values | Where-Object { $null -ne $_.OuterGap }).Count)
        opened_elapsed_ticks = [uint64]$origin.ElapsedTicks
    }
    $null = Add-ServiceEvent -Channel "COVERAGE" -Payload ([ordered]@{
        event = "OUTER_GAP_OPENED"; symbol = $State.Symbol; gap_id = $State.OuterGap.gap_id
        opened_elapsed_ticks = $State.OuterGap.opened_elapsed_ticks; prior_exit_code = $ExitCode
    })
}

function Read-CanonicalPublicationTail {
    param([Parameter(Mandatory = $true)] [string] $Path)
    # Bounded telemetry, not a verifier: a busy depth stream or late correction
    # must not masquerade as progress of canonical trades (and vice versa).
    $result = @{ trades = [uint64]0; depth = [uint64]0; sampled_bytes = 0 }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $result }
    $file = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $count = [int][Math]::Min([int64]262144, $file.Length)
        if ($count -eq 0) { return $result }
        $start = $file.Length - $count
        $null = $file.Seek($start, [IO.SeekOrigin]::Begin)
        $bytes = [byte[]]::new($count)
        $read = 0
        while ($read -lt $count) {
            $n = $file.Read($bytes, $read, $count - $read)
            if ($n -eq 0) { break }
            $read += $n
        }
        $result.sampled_bytes = $read
        $left = 0
        if ($start -gt 0) { while ($left -lt $read -and $bytes[$left] -ne 10) { $left++ }; $left++ }
        $right = $read - 1
        while ($right -ge $left -and $bytes[$right] -ne 10) { $right-- }
        if ($right -lt $left) { return $result }
        $lines = [Text.UTF8Encoding]::new($false, $true).GetString($bytes, $left, $right - $left + 1) -split "`n"
        for ($i = $lines.Count - 1; $i -ge 0; $i--) {
            if ($lines[$i] -notmatch '"event"\s*:\s*"(TRADE_OBSERVATION|DEPTH_OBSERVATION)"') { continue }
            $record = $lines[$i] | ConvertFrom-Json -ErrorAction Stop
            $payload = $record.body.payload
            if ($payload.event -ceq "TRADE_OBSERVATION" -and $result.trades -eq 0) { $result.trades = [uint64]$payload.trade_id }
            if ($payload.event -ceq "DEPTH_OBSERVATION" -and $result.depth -eq 0) { $result.depth = [uint64]$payload.final_sequence }
            if ($result.trades -ne 0 -and $result.depth -ne 0) { break }
        }
        return $result
    } finally { $file.Dispose() }
}

function Update-CanonicalStreamHealth {
    param([Parameter(Mandatory = $true)] $Arbiter, [bool] $ProcessAlive)
    $sample = Read-CanonicalPublicationTail -Path $Arbiter.journal
    $now = [double]$origin.Elapsed.TotalSeconds
    foreach ($stream in @("trades", "depth")) {
        $key = "$($Arbiter.symbol):$stream"
        if (-not $canonicalStreamHealth.ContainsKey($key)) {
            $canonicalStreamHealth[$key] = @{ id = [uint64]0; lastProgress = $now; stalled = $false; incident = 0 }
        }
        $health = $canonicalStreamHealth[$key]
        $advanced = [uint64]$sample[$stream] -gt [uint64]$health.id
        if ($advanced) {
            $health.id = [uint64]$sample[$stream]; $health.lastProgress = $now; $health.stalled = $false
        }
        $stale = $now - [double]$health.lastProgress
        $limit = [Math]::Max(60, 2 * [double]$TelemetryIntervalSeconds)
        $status = if (-not $ProcessAlive) { "PROCESS_EXITED" }
            elseif ($stale -ge $limit) { "NO_RECENT_PUBLICATION" }
            elseif ($advanced) { "PUBLISHING" } else { "AWAITING_PROGRESS" }
        if ($status -ceq "NO_RECENT_PUBLICATION" -and -not $health.stalled) {
            $health.stalled = $true; $health.incident = [int]$health.incident + 1
            Add-ObserverFailure -Kind ("LIVE_ARBITRATION_{0}_{1}" -f $Arbiter.symbol, $stream) `
                -Epoch $Arbiter.sequence -Detail ("NO_RECENT_PUBLICATION_{0}" -f $health.incident)
        }
        $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
            event = "CANONICAL_STREAM_HEALTH"; symbol = $Arbiter.symbol; segment = $Arbiter.sequence
            stream = $stream; status = $status; last_publication_id = [uint64]$health.id
            published_since_previous_sample = $advanced; seconds_without_observed_progress = $stale
            sampled_tail_bytes = $sample.sampled_bytes; process_alive = $ProcessAlive
            scope = "BOUNDED_PUBLICATION_SAMPLE_NOT_RAW_COMPLETENESS_OR_REALTIME_FRESHNESS"
        })
    }
}

function Add-ObserverFailure {
    param([string] $Kind, [int] $Epoch, [string] $Detail)
    $key = "${Kind}:${Epoch}:${Detail}"
    if (-not $observerFailures.Contains($key)) {
        $observerFailures.Add($key)
        $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
            event = "OBSERVER_FAILED"; observer = $Kind; epoch = $Epoch; detail = $Detail; failure_id = $key
        })
    }
}

function Get-SuccessorTransitionEvidence {
    param([Parameter(Mandatory = $true)] $Predecessor, [Parameter(Mandatory = $true)] $Successor)
    return [ordered]@{
        predecessor_clean = ($Predecessor.LastExitClean -eq $true)
        no_outer_gap = ($Successor.EpochReady -and $null -eq $Predecessor.OuterGap -and $null -eq $Successor.OuterGap)
    }
}

function Test-ObserverKernelOwnership {
    param([Parameter(Mandatory = $true)] $Window)
    if (-not (Test-Path -LiteralPath $Window.kernelOut -PathType Leaf)) { return $false }
    try {
        $first = @(Get-Content -LiteralPath $Window.kernelOut -TotalCount 1 -ErrorAction Stop)
        if ($first.Count -ne 1) { return $false }
        $ready = $first[0] | ConvertFrom-Json -ErrorAction Stop
        return $ready.schema -ceq "KernelNetworkTraceReadyV1" -and $ready.status -ceq "READY" -and
            $ready.session_name -ceq $Window.session -and
            [IO.Path]::GetFullPath([string]$ready.etl_path).Equals([IO.Path]::GetFullPath($Window.etl), [StringComparison]::OrdinalIgnoreCase) -and
            [IO.Path]::GetFullPath([string]$ready.stop_file).Equals([IO.Path]::GetFullPath($Window.kernelStop), [StringComparison]::OrdinalIgnoreCase)
    } catch { return $false }
}

function Invoke-ServiceLogman {
    param([Parameter(Mandatory = $true)] [string[]] $Arguments)
    $output = [string[]]@(& $logman @Arguments 2>&1 | ForEach-Object { [string]$_ })
    return [ordered]@{ exit_code = [int]$LASTEXITCODE; output = $output }
}

function Stop-OwnedKernelSession {
    param([Parameter(Mandatory = $true)] $Window, [string] $Reason, [bool] $RecordServiceEvent = $true)
    if ($Window.cleanupStatus -ceq "ABSENT") { return }
    $Window.cleanupAttempts = [int]$Window.cleanupAttempts + 1
    $owned = Test-ObserverKernelOwnership -Window $Window
    $stopResult = $null; $queryResult = $null
    $status = "OWNERSHIP_UNPROVEN"
    if ($owned) {
        try {
            $stopResult = Invoke-ServiceLogman -Arguments ([string[]]@("stop", "-ets", $Window.session))
            $queryResult = Invoke-ServiceLogman -Arguments ([string[]]@("query", "-ets", $Window.session))
            # PLA_E_DCS_NOT_FOUND is the observed Windows logman not-found
            # HRESULT. Access denied or any other error does not prove absence.
            $notFound = [int]-2144337918
            $status = if (($stopResult.exit_code -eq 0 -or $stopResult.exit_code -eq $notFound) -and
                $queryResult.exit_code -eq $notFound) { "ABSENT" } else { "CONTROL_FAILED" }
        } catch {
            $status = "CONTROL_FAILED"
            $queryResult = [ordered]@{ exit_code = $null; output = @([string]$_) }
        }
    }
    $Window.cleanupStatus = $status
    $record = [ordered]@{
        schema = "OwnedKernelSessionCleanupV1"; epoch = $Window.epoch; reason = $Reason
        observed_wall_ns = [uint64](Get-RawQualificationWallNs); controller_pid = $Window.kernelPid
        session_name = $Window.session; etl_path = $Window.etl; stop_file = $Window.kernelStop
        exact_ready_ownership = $owned; stop = $stopResult; post_query = $queryResult; status = $status
    }
    # Kernel verifier requires its exact six files. Control-plane evidence
    # belongs to the surrounding observer window, not inside that artifact.
    $path = Join-Path $Window.root ("kernel-cleanup-{0:0000}.json" -f $Window.cleanupAttempts)
    $null = Write-RawQualificationDurableNewJson -Path $path -Value $record
    if ($status -cne "ABSENT" -and $RecordServiceEvent) {
        Add-ObserverFailure -Kind "KERNEL_SESSION_CLEANUP" -Epoch $Window.epoch -Detail $status
    }
}

function Start-ServiceObserverWindow {
    # Unique owned roots/sessions. Both processes start without blocking the
    # service; Update-ServiceObserverWindows observes readiness on later ticks.
    $epoch = $observerWindows.Count + 1
    $windowNonce = [Guid]::NewGuid().ToString("N").Substring(0, 12)
    $root = Join-Path $observerRoot ("epochs/{0:000000}" -f $epoch)
    $kernel = Join-Path $root "kernel"
    $network = Join-Path $root "network"
    New-Item -ItemType Directory -Path $kernel -Force | Out-Null
    $window = [pscustomobject]@{
        epoch = $epoch; root = $root; kernelRoot = $kernel; networkRoot = $network
        identity = "observed-$windowNonce"; session = "BinanceProduction_$windowNonce"
        started = [uint64](Get-RawQualificationWallNs); ready = [uint64]0
        stop = [uint64]0; kernelTerminal = [uint64]0; networkTerminal = [uint64]0
        clock = [Diagnostics.Stopwatch]::StartNew(); stopClock = $null
        kernel = $null; network = $null; kernelPid = [uint32]0
        kernelExit = $null; networkExit = $null
        kernelForced = $false; cleanupAttempts = 0; cleanupStatus = "NOT_ATTEMPTED"
        kernelStop = (Join-Path $kernel "stop.request"); networkStop = (Join-Path $network "stop.request")
        kernelOut = (Join-Path $kernel "controller.stdout.jsonl"); kernelErr = (Join-Path $kernel "controller.stderr.txt")
        networkOut = (Join-Path $root "network.stdout.txt"); networkErr = (Join-Path $root "network.stderr.txt")
        etl = (Join-Path $kernel "kernel-network.etl")
    }
    # Register before spawning so even a partially failed start is owned by
    # cleanup. Never query/stop a session not created by this invocation.
    $observerWindows.Add($window)
    $window.kernel = [RawQualificationNative]::StartSuspendedInJobRetained(
        $job, $kernelTrace, ([string[]]@($window.session, $window.etl, $window.kernelStop,
            [string]$KernelTraceMiB, [string]$etwDeadline)), $repo, $window.kernelOut, $window.kernelErr)
    $window.kernelPid = [uint32]$window.kernel.ProcessId
    $window.network = [RawQualificationNative]::StartSuspendedInJobRetained(
        $job, $powershell, ([string[]]@("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", $networkWitnessScript, "-EvidenceRoot", $network, "-ObservationId", $window.identity,
            "-DurationSeconds", [string]$etwDeadline, "-IntervalSeconds", "30",
            "-ProbeTimeoutMilliseconds", "2000", "-StopFile", $window.networkStop)),
        $repo, $window.networkOut, $window.networkErr)
}

function Stop-ServiceObserverWindow {
    param([Parameter(Mandatory = $true)] $Window)
    if ($Window.stop -ne 0) { return }
    $Window.stop = [uint64](Get-RawQualificationWallNs)
    $Window.stopClock = [Diagnostics.Stopwatch]::StartNew()
    foreach ($kind in @("kernel_network", "network_witness")) {
        $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
            event = "OBSERVER_WINDOW_STOP_REQUESTED"; kind = $kind; epoch = $Window.epoch
            stop_requested_wall_ns = $Window.stop
        })
    }
    foreach ($path in @($Window.kernelStop, $Window.networkStop)) {
        if (-not (Test-Path -LiteralPath $path)) {
            $null = Write-RawQualificationDurableNewFile -Path $path -Bytes ([byte[]]@())
        }
    }
}

function Update-ServiceObserverWindows {
    param([switch] $NoRotation)
    if ($observerSkipped) { return }
    foreach ($window in @($observerWindows)) {
        foreach ($kind in @("kernel", "network")) {
            $launch = $window.$kind
            if ($null -eq $launch) { continue }
            $exited = [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 0)
            if (-not $exited -and $window.stop -ne 0 -and $window.stopClock.Elapsed.TotalSeconds -ge 30) {
                Add-ObserverFailure -Kind $kind -Epoch $window.epoch -Detail "STOP_DEADLINE_EXCEEDED"
                if ($kind -ceq "kernel") { $window.kernelForced = $true }
                $null = [RawQualificationNative]::TerminateProcessHandle($launch.ProcessHandle, 0xEE21)
                $exited = [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 0)
            }
            if ($exited) {
                $window.("${kind}Terminal") = [uint64](Get-RawQualificationWallNs)
                $window.("${kind}Exit") = [uint32][RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle)
                if ($window.stop -eq 0) {
                    Add-ObserverFailure -Kind $kind -Epoch $window.epoch -Detail "EXITED_BEFORE_STOP_REQUEST"
                }
                $null = [RawQualificationNative]::CloseRetainedProcessHandle($launch)
                $window.$kind = $null
                if ($kind -ceq "kernel" -and ($window.stop -eq 0 -or $window.kernelForced)) {
                    Stop-OwnedKernelSession -Window $window -Reason "CONTROLLER_EXITED_WITHOUT_PROVEN_SEAL"
                }
            }
        }
        if ($window.ready -eq 0) {
            if ($window.kernelTerminal -ne 0 -or $window.networkTerminal -ne 0) {
                throw "Observer window $($window.epoch) exited before readiness; failed evidence preserved."
            }
            $kernelReady = $false; $networkReady = $false
            $kernelReady = Test-ObserverKernelOwnership -Window $window
            $startup = Join-Path $window.networkRoot "network-witness-startup.json"
            if (Test-Path -LiteralPath $startup -PathType Leaf) {
                try {
                    $value = Get-Content -LiteralPath $startup -Raw | ConvertFrom-Json -ErrorAction Stop
                    $networkReady = $value.schema -ceq "RawQualificationNetworkWitnessStartupV2" -and
                        $value.observation_id -ceq $window.identity
                } catch {}
            }
            if ($kernelReady -and $networkReady) {
                $window.ready = [uint64](Get-RawQualificationWallNs)
                foreach ($kind in @("kernel_network", "network_witness")) {
                    $artifact = if ($kind -ceq "kernel_network") { $window.kernelRoot } else { $window.networkRoot }
                    $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                        event = "OBSERVER_WINDOW_READY"; kind = $kind; epoch = $window.epoch
                        artifact_root = Get-ServiceRelativePath -Root $runRoot -FullPath $artifact
                        started_wall_ns = $window.started; ready_wall_ns = $window.ready
                    })
                }
                # The successor is ready on both planes before the predecessor
                # receives either stop file. Readiness is never inherited.
                foreach ($previous in @($observerWindows | Where-Object {
                    $_.epoch -lt $window.epoch -and $_.stop -eq 0
                })) { Stop-ServiceObserverWindow -Window $previous }
            } elseif ($window.clock.Elapsed.TotalSeconds -ge 60) {
                Add-ObserverFailure -Kind "PAIR" -Epoch $window.epoch -Detail "READINESS_DEADLINE_EXCEEDED"
                throw "Observer pair did not publish both readiness records within 60 seconds."
            }
        }
    }
    if ($NoRotation) { return }
    $active = @($observerWindows | Where-Object { $_.stop -eq 0 })
    $retiring = @($observerWindows | Where-Object {
        $_.stop -ne 0 -and ($null -ne $_.kernel -or $null -ne $_.network)
    })
    if ($active.Count -eq 1 -and $active[0].ready -ne 0 -and $retiring.Count -eq 0) {
        $current = $active[0]
        if (($isContinuous -and $current.clock.Elapsed.TotalSeconds -ge $EpochWindowSeconds) -or
            $current.kernelTerminal -ne 0 -or $current.networkTerminal -ne 0) {
            Start-ServiceObserverWindow
        }
    }
}

function Complete-ServiceObserverReports {
    # Decoding and hashing are deliberately outside the capture loop. All
    # retired process handles were already closed; no live windows accumulate.
    foreach ($window in $observerWindows) {
        if ($window.ready -eq 0 -or $window.stop -eq 0 -or
            $window.kernelTerminal -eq 0 -or $window.networkTerminal -eq 0 -or
            $window.kernelExit -ne 0 -or $window.networkExit -ne 0) {
            throw "Observer window $($window.epoch) did not finish a complete cooperative lifetime."
        }
        if ((Get-Item -LiteralPath $window.kernelErr).Length -ne 0 -or
            (Get-Item -LiteralPath $window.networkErr).Length -ne 0) { throw "Observer window wrote unexpected stderr." }
        Stop-OwnedKernelSession -Window $window -Reason "FINAL_SEAL_CONFIRMATION"
        if ($window.cleanupStatus -cne "ABSENT") { throw "Owned kernel session absence could not be confirmed." }
        $decoded = Join-Path $window.kernelRoot "kernel-network.xml"
        $decodeOutput = [string[]]@(& $tracerpt $window.etl -o $decoded -of XML -lr -y 2>&1 | ForEach-Object { [string]$_ })
        $decodeExit = [int]$LASTEXITCODE
        if ($decodeExit -ne 0) { throw "tracerpt rejected observer window $($window.epoch)." }
        $queryOutput = [string[]]@(& $logman query -ets $window.session 2>&1 | ForEach-Object { [string]$_ })
        $queryExit = [int]$LASTEXITCODE
        if ($queryExit -ne -2144337918) { throw "Owned kernel session absence was not confirmed after seal (query $queryExit)." }
        $records = [object[]]@(Get-Content -LiteralPath $window.kernelOut | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
        if ($records.Count -ne 2 -or $records[1].stop_reason -cne "STOP_FILE") {
            throw "Observer kernel window did not seal READY then STOP_FILE."
        }
        $windowStart = Convert-ServiceWallNsToUtc $window.started
        $windowEnd = Convert-ServiceWallNsToUtc $window.kernelTerminal
        $inventory = [object[]]@($processIntervals | Where-Object {
            $_.role -cne "LIVE_ARBITRATION" -and
            $_.interval_start_utc -lt $windowEnd -and $_.interval_end_utc -gt $windowStart
        } | ForEach-Object {
            $left = if ($_.interval_start_utc -gt $windowStart) { $_.interval_start_utc } else { $windowStart }
            $right = if ($_.interval_end_utc -lt $windowEnd) { $_.interval_end_utc } else { $windowEnd }
            [ordered]@{ role = [string]$_.role; symbol = $_.symbol; pid = [uint32]$_.pid
                interval_start_utc = ([DateTimeOffset]$left).ToUniversalTime().ToString("o")
                interval_end_utc = ([DateTimeOffset]$right).ToUniversalTime().ToString("o") }
        })
        $report = [ordered]@{
            schema = "KernelNetworkProductionCaptureV1"; run_id = $window.identity; status = "CANDIDATE"
            started_utc = $windowStart.ToString("o"); completed_utc = $windowEnd.ToString("o")
            controller_executable = $kernelTrace; controller_sha256 = Get-RawQualificationSha256File -Path $kernelTrace
            controller_pid = $window.kernelPid; session_name = $window.session
            controller_exit_code = [int]$window.kernelExit; controller_records = $records
            controller_stderr_file = "controller.stderr.txt"; controller_stderr_bytes = [uint64](Get-Item -LiteralPath $window.kernelErr).Length
            controller_stderr_sha256 = Get-RawQualificationSha256File -Path $window.kernelErr
            maximum_file_mib = [uint32]$KernelTraceMiB; deadline_s = [uint64]$etwDeadline
            etl_file = "kernel-network.etl"; etl_bytes = [uint64](Get-Item -LiteralPath $window.etl).Length
            etl_sha256 = Get-RawQualificationSha256File -Path $window.etl
            decoded_file = "kernel-network.xml"; decoded_bytes = [uint64](Get-Item -LiteralPath $decoded).Length
            decoded_sha256 = Get-RawQualificationSha256File -Path $decoded
            tracerpt_exit_code = $decodeExit; tracerpt_output = $decodeOutput
            orphan_query_exit_code = $queryExit; orphan_query_output = $queryOutput
            monitored_processes = $inventory; selected_event_ids = [uint16[]]@(12,13,14,15,16,17,28,29,30,31,32)
            raw_packet_payload_capture = $false; diagnostic_only = $true; training_eligible = $false
            correlation_status = "OPEN_PENDING_INDEPENDENT_VERIFY"
        }
        $null = Write-RawQualificationDurableNewJson -Path (Join-Path $window.kernelRoot "kernel-network-capture.json") -Value $report
        $reportRoot = Join-Path $verificationRoot ("observers/{0:000000}" -f $window.epoch)
        New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null
        foreach ($kind in @("kernel_network", "network_witness")) {
            $isKernel = $kind -ceq "kernel_network"
            $artifact = if ($isKernel) { $window.kernelRoot } else { $window.networkRoot }
            $reportPath = Join-Path $reportRoot $(if ($isKernel) { "kernel.json" } else { "network.json" })
            $module = if ($isKernel) { "binance_lob.kernel_network_production_verify_cli" } else { "binance_lob.network_witness_verify_cli" }
            $null = Invoke-JsonVerifier -Module $module -InputRoot $artifact -OutputPath $reportPath
            $entry = [ordered]@{
                epoch = $window.epoch; artifact_root = Get-ServiceRelativePath -Root $runRoot -FullPath $artifact
                started_wall_ns = $window.started; ready_wall_ns = $window.ready; stop_requested_wall_ns = $window.stop
                terminal_wall_ns = $(if ($isKernel) { $window.kernelTerminal } else { $window.networkTerminal })
                verification_path = Get-ServiceRelativePath -Root $runRoot -FullPath $reportPath
                verification_sha256 = Get-RawQualificationSha256File -Path $reportPath
            }
            if ($isKernel) { $entry.run_id = $window.identity; $kernelWindows.Add($entry) }
            else { $entry.observation_id = $window.identity; $networkWindows.Add($entry) }
            $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                event = "OBSERVER_WINDOW_SEALED"; kind = $kind; epoch = $window.epoch
                terminal_wall_ns = $entry.terminal_wall_ns; verification_path = $entry.verification_path
                verification_sha256 = $entry.verification_sha256
            })
        }
    }
}

function Write-ArbiterExpectedArtifactInventory {
    param(
        [Parameter(Mandatory = $true)] [string] $OutputPath,
        [Parameter(Mandatory = $true)] [string[]] $Artifacts,
        [Parameter(Mandatory = $true)] [string[]] $Journals
    )
    $value = [ordered]@{
        schema = "LiveArbitrationExpectedArtifactsV1"
        artifacts = [string[]]@($Artifacts | Select-Object -Unique)
        journals = [object[]]@($Journals | ForEach-Object {
            [ordered]@{ path = [string]$_; sha256 = Get-RawQualificationSha256File -Path $_ }
        })
    }
    $null = Write-RawQualificationDurableNewJson -Path $OutputPath -Value $value
    return $OutputPath
}

function Get-ArbiterClosedJournalPrefix {
    param([Parameter(Mandatory = $true)] $Arbiter)
    $paths = [string[]]@(Get-ChildItem -LiteralPath $Arbiter.dir -Filter "*.jsonl" -File |
        ForEach-Object { $_.FullName })
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $cut = [Array]::IndexOf($paths, [string]$Arbiter.journal)
    if ($cut -lt 0) { throw "Closed canonical segment is absent from its journal directory." }
    # Preserve STARTED and every resume predecessor as identity context.
    # Files after this immutable cut are deliberately not selected.
    return [string[]]@($paths[0..$cut])
}

function Get-LivePrefixAuditArguments {
    param(
        [Parameter(Mandatory = $true)] [string] $JournalRoot,
        [Parameter(Mandatory = $true)] [string] $ArtifactRoot,
        [string] $OracleCache = ""
    )
    # Live audits need STARTED and all resume predecessors for identity context.
    # The last journal is mutable, so it cannot be bound by a sealed manifest.
    $auditArgs = [System.Collections.Generic.List[string]]::new()
    $auditArgs.AddRange([string[]]@(
        "--journal-root", $JournalRoot, "--incremental", "--oracle-artifact", $ArtifactRoot
    ))
    if ($OracleCache -ne "") {
        $auditArgs.Add("--oracle-cache")
        $auditArgs.Add($OracleCache)
    }
    return [string[]]$auditArgs.ToArray()
}

function Get-LivePrefixAuditResult {
    param(
        [Parameter(Mandatory = $true)] [uint32] $ExitCode,
        [Parameter(Mandatory = $true)] [string] $ReportPath
    )
    if ($ExitCode -ne 0) { return "FAIL" }
    try {
        $report = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($report.schema -cne "LiveArbitrationVerificationV2" -or $report.status -cne "PASS" -or
            $report.audit_scope -cne "LIVE_PREFIX" -or $report.journal_prefix -isnot [bool] -or
            $report.journal_prefix -or $report.coverage_exhaustive -isnot [bool] -or
            $report.coverage_exhaustive) { return "FAIL" }
        if ($report.oracle_identity -ceq "PASS") { return "PASS" }
        if ($report.oracle_identity -ceq "SKIPPED") { return "UNPROVEN" }
    } catch {}
    return "FAIL"
}

function Test-ArbiterCompleteTerminal {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        if ($stream.Length -eq 0) { return $false }
        $start = [Math]::Max([int64]0, $stream.Length - 65536)
        $null = $stream.Seek($start, [IO.SeekOrigin]::Begin)
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false), $false, 4096, $true)
        try {
            $tail = $reader.ReadToEnd()
            if (-not $tail.EndsWith("`n")) { return $false }
            $lines = @($tail.TrimEnd("`r", "`n") -split "`n")
            $record = $lines[-1] | ConvertFrom-Json -ErrorAction Stop
            return $record.body.payload.event -ceq "ARBITRATION_TERMINAL" -and
                $record.body.payload.status -ceq "COMPLETE"
        } catch { return $false }
        finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function Get-NextLiveArbiterSequence {
    param([Parameter(Mandatory = $true)][string] $SymbolDir)
    # Count is not an index. A missing journal (0000 and 0002, no 0001)
    # makes Count collide with an existing create-only stdout and the
    # relaunch exception aborts raw capture. The next sequence is one past
    # every journal and log already preserved.
    $max = -1
    foreach ($file in @(Get-ChildItem -LiteralPath $SymbolDir -File -ErrorAction SilentlyContinue)) {
        if ($file.Name -match '^(?:.*-)?seg-(\d+)\.(?:jsonl|stdout\.txt|stderr\.txt)$') {
            $index = [int]$Matches[1]
            if ($index -gt $max) { $max = $index }
        }
    }
    return ($max + 1)
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
    # The service's independently discovered inventory survives both a dead
    # supervisor and a dead arbiter. Resume does not inherit prior-artifact
    # arguments from previous journal segments.
    # Collect the first operand before adding: a function with one emitted
    # source otherwise becomes string + array and concatenates whole paths.
    $requiredArtifacts = [string[]]@(@(Get-SymbolArtifactInventory -Symbol $symbolName) + @($ArtifactRoot) + @($PriorArtifacts) | Select-Object -Unique)
    $PriorArtifacts = [string[]]@($requiredArtifacts | Where-Object { $_ -cne $ArtifactRoot })
    $symbolDir = Join-Path $arbiterRoot $symbolName
    if (-not (Test-Path -LiteralPath $symbolDir -PathType Container)) {
        New-Item -ItemType Directory -Path $symbolDir | Out-Null
    }
    $sequence = Get-NextLiveArbiterSequence -SymbolDir $symbolDir
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
            try {
                $null = [RawQualificationNative]::TerminateProcessHandle($previous.auditLaunch.ProcessHandle, 0xEE45)
            } catch {
                # The auditor can exit between the zero-wait and TerminateProcess.
                # That race is not a dead auditor. A process that is still
                # alive after the failure is.
                if (-not [RawQualificationNative]::WaitForProcessExit($previous.auditLaunch.ProcessHandle, 0)) {
                    throw
                }
            }
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
        sourceArtifacts = [string[]]@($requiredArtifacts)
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
            Add-ObserverFailure -Kind ("LIVE_ARBITRATION_{0}" -f $Arbiter.symbol) `
                -Epoch $Arbiter.sequence -Detail "STOP_DEADLINE_EXCEEDED"
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
    $State.NeedsArbiterRebind = $false
    $priorArtifacts = @()
    if ($null -ne $arb) {
        $exit = Stop-LiveArbiter -Arbiter $arb -RebindStop
        $priorArtifacts += [string]$arb.artifact
        $complete = $exit -eq 0 -and (Test-ArbiterCompleteTerminal -Path $arb.journal)
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
        if ($complete -and $duplicate.Count -eq 0) {
            $expectedPath = Join-Path $verificationRoot ("{0}-seg-{1:0000}-expected.json" -f $State.Code, $arb.sequence)
            $expected = Write-ArbiterExpectedArtifactInventory -OutputPath $expectedPath -Artifacts $arb.sourceArtifacts `
                -Journals (Get-ArbiterClosedJournalPrefix -Arbiter $arb)
            $pendingSegmentVerifications.Add([pscustomobject]@{
                symbol = $State.Symbol; journal = $arb.journal; dir = $arb.dir
                artifact = $symbolRoot; sequence = $arb.sequence
                expectedInventory = $expected
            })
        }
        if (-not $complete) {
            $failureKey = "LIVE_ARBITRATION_SEGMENT_INTERRUPTED:$($State.Symbol):$($arb.sequence)"
            if (-not $observerFailures.Contains($failureKey)) {
                $observerFailures.Add($failureKey)
                $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                    event = "OBSERVER_FAILED"; observer = "LIVE_ARBITRATION"; symbol = $State.Symbol
                    detail = "segment interrupted before a complete terminal"; failure_id = $failureKey
                })
            }
        }
        $null = Add-ServiceEvent -Channel "SERVICE" -Payload ([ordered]@{
            event = $(if ($complete) { "LIVE_ARBITRATION_SEGMENT_SEALED" } else { "LIVE_ARBITRATION_SEGMENT_INTERRUPTED" }); symbol = $State.Symbol
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
$pendingEpochVerifications = [Collections.Generic.List[object]]::new()
$maximumConcurrentWindowVerifiers = 2

function Start-EpochVerificationTask {
    param([Parameter(Mandatory = $true)] $Artifact, [int] $Epoch)
    $pendingEpochVerifications.Add([pscustomobject]@{ artifact = $Artifact; epoch = $Epoch })
}

function Start-QueuedEpochVerificationTask {
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
    # Immutable prefix cut: include prior identity context for late duplicate
    # corrections, but never journals created after this segment closed.
    $launch = [RawQualificationNative]::StartSuspendedInJobRetained(
        $job, $liveArbiterVerify,
        ([string[]]@("--journal-root", $Entry.dir, "--journal-prefix", "--oracle-artifact", $Entry.artifact,
            "--expected-artifact-inventory", $Entry.expectedInventory,
            "--oracle-cache", (Join-Path $verificationRoot "oracle-cache\rust"))),
        $repo, (Join-Path $verificationRoot "$base-rust.stdout.txt"), $stderr
    )
    $verificationTasks.Add([pscustomobject]@{
        kind = "segment"; symbol = $Entry.symbol; sequence = $Entry.sequence
        journal = $Entry.journal; dir = $Entry.dir; artifact = $Entry.artifact
        expectedInventory = $Entry.expectedInventory
        stage = "rust"; launch = $launch; stopwatch = [Diagnostics.Stopwatch]::StartNew()
        rustReport = $rustReport; rustStdout = (Join-Path $verificationRoot "$base-rust.stdout.txt")
        pythonReport = $pythonReport; stderr = $stderr
        pyStderr = $null
        coverage_seconds = [uint64]0
    })
}

function Process-VerificationTasks {
    # A backlog is explicit; never fan out every expensive raw oracle at once.
    # Deadlines begin at actual process launch, not while waiting in the queue.
    while ($pendingEpochVerifications.Count -gt 0 -and
        @($verificationTasks | Where-Object { $null -ne $_.launch }).Count -lt $maximumConcurrentWindowVerifiers) {
        $entry = $pendingEpochVerifications[0]
        $pendingEpochVerifications.RemoveAt(0)
        Start-QueuedEpochVerificationTask -Artifact $entry.artifact -Epoch $entry.epoch
    }
    while ($pendingSegmentVerifications.Count -gt 0 -and
        @($verificationTasks | Where-Object { $null -ne $_.launch }).Count -lt $maximumConcurrentWindowVerifiers) {
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
                        event = "OBSERVER_FAILED"; failure_id = "SEALED_WINDOW_VERIFICATION_REJECTED"; observer = "WINDOW_VERIFIER"
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
            $rustQualified = $rustValue.status -ceq "PASS"
            if ($task.kind -ceq "segment") {
                $rustQualified = $rustQualified -and $rustValue.schema -ceq "LiveArbitrationVerificationV2" -and
                    $rustValue.oracle_identity -ceq "PASS" -and $rustValue.artifact_coverage -ceq "PASS" -and
                    $rustValue.terminal_complete -eq $true -and
                    $rustValue.journal_prefix -eq $true -and $rustValue.audit_scope -ceq "SEALED_JOURNAL_PREFIX" -and
                    $rustValue.coverage_exhaustive -eq $false -and
                    $rustValue.expected_artifact_inventory_sha256 -ceq (Get-RawQualificationSha256File $task.expectedInventory)
            }
            if (-not $rustQualified) {
                $verificationTasks.Remove($task)
                if (-not $observerFailures.Contains("SEALED_WINDOW_VERIFICATION_REJECTED")) {
                    $observerFailures.Add("SEALED_WINDOW_VERIFICATION_REJECTED")
                    $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                        event = "OBSERVER_FAILED"; failure_id = "SEALED_WINDOW_VERIFICATION_REJECTED"; observer = "WINDOW_VERIFIER"
                        symbol = $task.symbol; kind = $task.kind
                        detail = "Rust verifier did not establish the required complete bounded prefix and oracle identity"
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
                    [string[]]@("-B", "-m", "binance_lob.live_arbitration_verify_cli",
                        "--journal-root", $task.dir, "--journal-prefix", "--oracle-artifact", $task.artifact,
                        "--expected-artifact-inventory", $task.expectedInventory, "--output", $task.pythonReport,
                        "--oracle-cache", (Join-Path $verificationRoot "oracle-cache\python"))
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
                    event = "OBSERVER_FAILED"; failure_id = "SEALED_WINDOW_VERIFICATION_TIMEOUT"; observer = "WINDOW_VERIFIER"
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
                        event = "OBSERVER_FAILED"; failure_id = "SEALED_WINDOW_VERIFICATION_TIMEOUT"; observer = "WINDOW_VERIFIER"
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
                    event = "OBSERVER_FAILED"; failure_id = "SEALED_WINDOW_VERIFICATION_REJECTED"; observer = "WINDOW_VERIFIER"
                    symbol = $task.symbol; kind = $task.kind
                    detail = "Python verifier rejected a sealed window (exit $exit)"
                })
            }
            continue
        }
        $pyValue = Get-Content -LiteralPath $task.pythonReport -Raw | ConvertFrom-Json -ErrorAction Stop
        $pythonQualified = $pyValue.status -ceq "PASS"
        if ($task.kind -ceq "segment") {
            $pythonQualified = $pythonQualified -and $pyValue.schema -ceq "LiveArbitrationVerificationV2" -and
                $pyValue.oracle_identity -ceq "PASS" -and $pyValue.artifact_coverage -ceq "PASS" -and
                $pyValue.terminal_complete -eq $true -and
                $pyValue.journal_prefix -eq $true -and $pyValue.audit_scope -ceq "SEALED_JOURNAL_PREFIX" -and
                $pyValue.coverage_exhaustive -eq $false -and
                $pyValue.expected_artifact_inventory_sha256 -ceq (Get-RawQualificationSha256File $task.expectedInventory)
        }
        if (-not $pythonQualified) {
            if (-not $observerFailures.Contains("SEALED_WINDOW_VERIFICATION_REJECTED")) {
                $observerFailures.Add("SEALED_WINDOW_VERIFICATION_REJECTED")
                $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                    event = "OBSERVER_FAILED"; failure_id = "SEALED_WINDOW_VERIFICATION_REJECTED"; observer = "WINDOW_VERIFIER"
                    symbol = $task.symbol; kind = $task.kind
                    detail = "Python verifier did not establish the required complete bounded prefix and oracle identity"
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
                audit_scope = "SEALED_JOURNAL_PREFIX"; coverage_exhaustive = $false
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

    $etwDeadline = if ($isContinuous) {
        [uint32][Math]::Min(691200, [uint64]$EpochWindowSeconds + 1800)
    } else { [uint32][Math]::Min(691200, [uint64]$TotalSeconds + 1800) }
    $observerRunId = "observed-$nonce"
    $powershell = Join-Path $PSHOME "powershell.exe"
    $observerSkipped = $isContinuous -and $SkipKernelObserver
    $processIntervals.Add([pscustomobject]@{
        role = "LAUNCHER"; symbol = $null; pid = [uint32]$PID
        interval_start_utc = $startUtc; interval_end_utc = $null
    })
    if (-not $observerSkipped) {
        Start-ServiceObserverWindow
        while ($observerWindows[0].ready -eq 0) {
            Update-ServiceObserverWindows -NoRotation
            Start-Sleep -Milliseconds 100
        }
        $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
            event = "OBSERVER_CAPTURE_INTERVAL_STARTED"
        })
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
        foreach ($successorState in @($successors.Values | Where-Object { $null -ne $_ })) {
            Update-SymbolArtifactAndReadiness -State $successorState
        }
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
                if ($isContinuous -and $state.NeedsArbiterRebind -and $state.EpochReady -and $null -ne $state.Artifact) {
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
                    $state.LastExitCode = $code; $state.LastExitClean = $cleanExit
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
                        # A launched successor is not proof of overlap: its
                        # current epoch must independently be READY.
                        $state.PlannedRenewal = $cleanExit
                        $successors[$state.Symbol] = $null
                        $states[$state.Symbol] = $successor
                        if ($null -ne $state.OuterGap) { $successor.OuterGap = $state.OuterGap }
                        $coveredPromotion = $successor.EpochReady -and $null -eq $successor.OuterGap
                        if (-not $successor.EpochReady) { Open-SymbolOuterGap -State $successor -ExitCode $code }
                        $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
                            event = "SYMBOL_EPOCH_RENEWED"; symbol = $state.Symbol
                            predecessor_epoch = $state.Epoch; successor_epoch = $successor.Epoch
                            predecessor_clean = $cleanExit; no_outer_gap = [bool]$coveredPromotion
                        })
                        if ($state.ConsecutiveFailures -gt 0) { $state.ConsecutiveFailures = 0 }
                        $null = [RawQualificationNative]::CloseRetainedProcessHandle($state.Launch)
                        $state.Launch = $null
                        # The canonical view rebinds to the successor artifact
                        # now that the predecessor's lanes sealed (ADR-17 B3):
                        # resume chains the journal segments and never
                        # duplicates or rolls back.  If the successor is not
                        # READY yet, the rebind fires as soon as it is.
                        if ($successor.EpochReady -and $null -ne $successor.Artifact) {
                            Rebind-LiveArbiter -State $successor -NewArtifactRoot $successor.Artifact
                        } else {
                            $successor.NeedsArbiterRebind = $true
                        }
                        continue
                    }
                    $null = [RawQualificationNative]::CloseRetainedProcessHandle($state.Launch)
                    $state.Launch = $null
                    Open-SymbolOuterGap -State $state -ExitCode $code
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
                    if ($null -ne $state.OuterGap) { $successor.OuterGap = $state.OuterGap }
                    $coveredPromotion = $successor.EpochReady -and $null -eq $successor.OuterGap
                    if (-not $successor.EpochReady) { Open-SymbolOuterGap -State $successor -ExitCode 0 }
                    $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
                        event = "SYMBOL_EPOCH_RENEWED"; symbol = $state.Symbol
                        predecessor_epoch = $state.Epoch; successor_epoch = $successor.Epoch
                        predecessor_clean = $false; no_outer_gap = [bool]$coveredPromotion
                        recovery_promotion = $true
                    })
                    if ($successor.EpochReady -and $null -ne $successor.Artifact) {
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
                            event = "OBSERVER_FAILED"; failure_id = "LIVE_ARBITRATION_EXITED_EARLY"; observer = "LIVE_ARBITRATION"; symbol = $arbiter.symbol
                            detail = "sidecar exited with code $arbExit; raw lanes continue; resume scheduled"
                        })
                    }
                } else {
                    if (-not $observerFailures.Contains("LIVE_ARBITRATION_EXITED_EARLY")) {
                        $observerFailures.Add("LIVE_ARBITRATION_EXITED_EARLY")
                        $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                            event = "OBSERVER_FAILED"; failure_id = "LIVE_ARBITRATION_EXITED_EARLY"; observer = "LIVE_ARBITRATION"; symbol = $arbiter.symbol
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
                try {
                    $null = Start-LiveArbiter -State $state -ArtifactRoot "$($arbiter.artifact)" -ResumeFromDeath
                } catch {
                    $arbiter.consecutiveFailures = [int]$arbiter.consecutiveFailures + 1
                    $delay = [Math]::Min(60.0, [Math]::Pow(2.0, [Math]::Min(5, $arbiter.consecutiveFailures - 1)))
                    $arbiter.restartAtSeconds = $origin.Elapsed.TotalSeconds + $delay
                    if (-not $observerFailures.Contains("LIVE_ARBITRATION_RELAUNCH_FAILED")) {
                        $observerFailures.Add("LIVE_ARBITRATION_RELAUNCH_FAILED")
                        $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                            event = "OBSERVER_FAILED"; failure_id = "LIVE_ARBITRATION_RELAUNCH_FAILED"; observer = "LIVE_ARBITRATION"; symbol = $arbiter.symbol
                            detail = "sidecar relaunch failed; raw lanes continue; resume scheduled: $($_.Exception.Message)"
                        })
                    }
                }
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
                        event = "OBSERVER_FAILED"; failure_id = "CLOCK_HEALTH_POLICY_FAILED"; observer = "WINDOWS_CLOCK"; detail = [string]$_
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
                        $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                            event = "OBSERVER_FAILED"; observer = "STORAGE_RESERVE"
                            detail = "storage reserve crossed; cooperative safe stop requested"
                            failure_id = "STORAGE_RESERVE_CROSSED_SAFE_STOP"
                        })
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
                Update-CanonicalStreamHealth -Arbiter $arbiter -ProcessAlive $arbiterAlive
                # Collect a previously launched detached audit.
                if ($null -ne $arbiter.auditLaunch) {
                    if ([RawQualificationNative]::WaitForProcessExit($arbiter.auditLaunch.ProcessHandle, 0)) {
                        $auditExit = [uint32][RawQualificationNative]::GetProcessExitCode($arbiter.auditLaunch.ProcessHandle)
                        $arbiter.lastPrefixAuditResult = Get-LivePrefixAuditResult -ExitCode $auditExit -ReportPath $arbiter.auditStdout
                        if ($arbiter.lastPrefixAuditResult -ceq "FAIL") {
                            if (-not $observerFailures.Contains("LIVE_ARBITRATION_PREFIX_AUDIT")) {
                                $observerFailures.Add("LIVE_ARBITRATION_PREFIX_AUDIT")
                                $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
                                    event = "OBSERVER_FAILED"; failure_id = "LIVE_ARBITRATION_PREFIX_AUDIT"; observer = "LIVE_ARBITRATION"
                                    symbol = $arbiter.symbol
                                    detail = "incremental whole-chain prefix audit failed or returned an invalid scope (exit $auditExit)"
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
                                event = "OBSERVER_FAILED"; failure_id = "LIVE_ARBITRATION_AUDIT_TIMEOUT"; observer = "LIVE_ARBITRATION_AUDITOR"
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
                    # Incremental prefix audits run the bounded raw oracle over
                    # the covered prefix (ADR-17 B5).  The oracle root is the
                    # SYMBOL root: the RESUMED segment declares the artifacts it
                    # covers (artifact_root + prior_artifacts) and the catch-up
                    # walk may publish prior-artifact tail trades that the
                    # CURRENT epoch artifact alone does not contain (defect
                    # hrs-f7e726a48da8: the audit rejected those catch-up trades
                    # as invented when bound to the epoch artifact only).
                    $auditSymbolRoot = Join-Path $runRoot ($states[$arbiter.symbol].Code)
                    $auditArgs = Get-LivePrefixAuditArguments -JournalRoot $arbiter.dir -ArtifactRoot $auditSymbolRoot -OracleCache (Join-Path $verificationRoot "oracle-cache\rust")
                    $arbiter.auditLaunch = [RawQualificationNative]::StartSuspendedInJobRetained(
                        $job, $verifierExe, $auditArgs, $repo, $arbiter.auditStdout, $arbiter.auditStderr
                    )
                    $arbiter.auditStartedStopwatch = [Diagnostics.Stopwatch]::StartNew()
                }
            }
            $lastTelemetry.Restart()
        }

        Update-ServiceObserverWindows
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
    if ($serviceStopRequested) {
        # A capture epoch does not watch stop.request. One that still has
        # more than a minute left would sit in the 1800 s drain and the
        # fault gate's 600 s cleanup would kill the launcher first. End
        # only those. A short epoch, such as the 20 s observer windows,
        # must finish and seal: cutting it leaves pending work and the
        # arbiter rejects a stop that should close cleanly.
        foreach ($state in $drainStates) {
            if ($null -eq $state.Launch) { continue }
            if ([RawQualificationNative]::WaitForProcessExit($state.Launch.ProcessHandle, 0)) { continue }
            $epochRemaining = [double]$state.RequestedSeconds - ($origin.Elapsed.TotalSeconds - [double]$state.EpochLaunchSeconds)
            if ($epochRemaining -le 60) { continue }
            try {
                $null = [RawQualificationNative]::TerminateProcessHandle($state.Launch.ProcessHandle, 0xEE33)
            } catch {
                if (-not [RawQualificationNative]::WaitForProcessExit($state.Launch.ProcessHandle, 0)) { throw }
            }
            $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
                event = "SYMBOL_EPOCH_STOP_REQUESTED"; symbol = $state.Symbol; epoch = $state.Epoch
                pid = [uint32]$state.Launch.ProcessId; reason = "SERVICE_STOP"
            })
        }
    }
    while (@($drainStates | Where-Object { $null -ne $_.Launch }).Count -ne 0) {
        foreach ($state in $drainStates) {
            if ($null -ne $state.Launch -and [RawQualificationNative]::WaitForProcessExit($state.Launch.ProcessHandle, 0)) {
                Update-SymbolArtifactAndReadiness -State $state
                $code = [uint32][RawQualificationNative]::GetProcessExitCode($state.Launch.ProcessHandle)
                $state.LastExitCode = $code
                $state.LastExitClean = $code -eq 0 -and $null -ne $state.Artifact -and
                    (Test-Path -LiteralPath (Join-Path $state.Artifact "supervisor-terminal.json") -PathType Leaf)
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
        Update-ServiceObserverWindows
        if ($drain.Elapsed.TotalSeconds -gt 1800) { throw "Symbol supervisors exceeded terminal drain deadline." }
        Start-Sleep -Milliseconds 250
    }

    if (-not $observerSkipped) {
        while (@($observerWindows | Where-Object { $_.ready -eq 0 }).Count -gt 0) {
            Update-ServiceObserverWindows -NoRotation
            Start-Sleep -Milliseconds 100
        }
        # The required capture interval ends only after every supervisor has
        # exited, before either diagnostic plane receives its final stop.
        $null = Add-ServiceEvent -Channel "OBSERVER" -Payload ([ordered]@{
            event = "OBSERVER_CAPTURE_INTERVAL_ENDED"
        })
        foreach ($window in $observerWindows) { Stop-ServiceObserverWindow -Window $window }
        $observerDrain = [Diagnostics.Stopwatch]::StartNew()
        while (@($observerWindows | Where-Object { $null -ne $_.kernel -or $null -ne $_.network }).Count -gt 0) {
            Update-ServiceObserverWindows -NoRotation
            if ($observerDrain.Elapsed.TotalSeconds -ge 60) { throw "Observer handles did not drain within 60 seconds." }
            Start-Sleep -Milliseconds 100
        }
    }
    $observationEndUtc = [DateTimeOffset]::UtcNow
    Sync-ServiceSourceInventory
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
                $predecessor = $states[$symbolName]
                $transition = Get-SuccessorTransitionEvidence -Predecessor $predecessor -Successor $successor
                if ($null -ne $predecessor.OuterGap) { $successor.OuterGap = $predecessor.OuterGap }
                $states[$symbolName] = $successor
                $successors[$symbolName] = $null
                if (-not $successor.EpochReady) { Open-SymbolOuterGap -State $successor -ExitCode 0 }
                $null = Add-ServiceEvent -Channel "SUPERVISOR" -Payload ([ordered]@{
                    event = "SYMBOL_EPOCH_RENEWED"; symbol = $symbolName
                    predecessor_epoch = $successor.Epoch - 1; successor_epoch = $successor.Epoch
                    predecessor_clean = $transition.predecessor_clean; no_outer_gap = $transition.no_outer_gap
                    stop_transition = $true
                })
            }
            $state = $states[$symbolName]
            $arb = $arbiterStates[$symbolName]
            # An if-statement unwraps a one-element array before assignment.
            # Under StrictMode that scalar has no Count and aborts the stop
            # before the arbiter can reject the interrupted prior.
            $missingSources = @($(if ($null -ne $arb) {
                @(Get-SymbolArtifactInventory -Symbol $symbolName | Where-Object { $_ -notin $arb.sourceArtifacts })
            }))
            if ($null -ne $state.Artifact -and $null -ne $arb -and
                ($arb.artifact -cne $state.Artifact -or $missingSources.Count -gt 0)) {
                Rebind-LiveArbiter -State $state -NewArtifactRoot $state.Artifact
            }
        }
    }
    # Drain any pending sealed-segment verification before the final
    # journal-set audit (bounded by the audit deadline).
    $taskDrain = [Diagnostics.Stopwatch]::StartNew()
    while ((@($pendingEpochVerifications).Count -gt 0 -or @($pendingSegmentVerifications).Count -gt 0 -or
            @($verificationTasks | Where-Object { $null -ne $_.launch }).Count -gt 0) -and
            $taskDrain.Elapsed.TotalSeconds -lt $arbiterAuditDeadlineSeconds) {
        Process-VerificationTasks
        Start-Sleep -Milliseconds 250
    }
    if ($pendingEpochVerifications.Count -gt 0 -or $pendingSegmentVerifications.Count -gt 0 -or
        @($verificationTasks | Where-Object { $null -ne $_.launch }).Count -gt 0) {
        throw "Sealed-window verification queue did not drain; no full verification claim is allowed."
    }
    foreach ($arbiter in @($arbiterStates.Values)) {
        $arbiterExit = if ($isContinuous) {
            Stop-LiveArbiter -Arbiter $arbiter
        } else {
            if ($null -ne $arbiter.launch) {
                if (-not [RawQualificationNative]::WaitForProcessExit($arbiter.launch.ProcessHandle, 30000)) {
                    Add-ObserverFailure -Kind ("LIVE_ARBITRATION_{0}" -f $arbiter.symbol) `
                        -Epoch $arbiter.sequence -Detail "FINAL_STOP_DEADLINE_EXCEEDED"
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
        $expectedPath = Join-Path $arbiterRoot ("{0}-expected-artifacts.json" -f $arbiter.symbol)
        # One journal file must stay a one-element list. An if-statement
        # unwraps it to a string, and StrictMode then has no Count.
        $expectedJournals = @($(if ($isContinuous) {
            @(Get-ChildItem -LiteralPath $arbiter.dir -Filter "*-seg-*.jsonl" -File |
                Sort-Object Name | ForEach-Object { $_.FullName })
        } else { @($arbiter.journal) }))
        if ($expectedJournals.Count -eq 0) { throw "Canonical inventory has no journal files." }
        $null = Write-ArbiterExpectedArtifactInventory -OutputPath $expectedPath `
            -Artifacts (Get-SymbolArtifactInventory -Symbol $arbiter.symbol) -Journals $expectedJournals
        $expectedSha = Get-RawQualificationSha256File -Path $expectedPath
        $arbRustReport = Join-Path $arbiterRoot ("{0}-rust-verify.json" -f $arbiter.symbol)
        $arbRustArgs = if ($isContinuous) {
            [string[]]@("--journal-root", $arbiter.dir, "--oracle-artifact", $symbolRoot)
        } else {
            [string[]]@($arbiter.journal, "--oracle-artifact", $symbolRoot)
        }
        $arbRustArgs += [string[]]@("--expected-artifact-inventory", $expectedPath)
        $arbRust = Invoke-ExactProcess -Executable $liveArbiterVerify -Arguments $arbRustArgs
        $null = Write-RawQualificationDurableNewFile -Path $arbRustReport -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($arbRust.TrimEnd() + "`n"))
        $arbRustValue = $arbRust | ConvertFrom-Json
        if ($arbRustValue.schema -cne "LiveArbitrationVerificationV2" -or
            $arbRustValue.status -cne "PASS" -or $arbRustValue.oracle_identity -cne "PASS" -or
            $arbRustValue.artifact_coverage -cne "PASS" -or $arbRustValue.terminal_complete -ne $true -or
            $arbRustValue.coverage_exhaustive -ne $true -or
            $arbRustValue.expected_artifact_inventory_sha256 -cne $expectedSha) {
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
            $arbPythonArgs += [string[]]@("--expected-artifact-inventory", $expectedPath)
            $null = Invoke-ExactProcess -Executable $python -Arguments $arbPythonArgs
        }
        finally { $env:PYTHONPATH = $oldPythonPath }
        $arbPythonValue = Get-Content -LiteralPath $arbPythonReport -Raw | ConvertFrom-Json
        if ($arbPythonValue.schema -cne "LiveArbitrationVerificationV2" -or
            $arbPythonValue.status -cne "PASS" -or $arbPythonValue.oracle_identity -cne "PASS" -or
            $arbPythonValue.artifact_coverage -cne "PASS" -or $arbPythonValue.terminal_complete -ne $true -or
            $arbPythonValue.coverage_exhaustive -ne $true -or
            $arbPythonValue.expected_artifact_inventory_sha256 -cne $expectedSha) {
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
            expected_artifact_inventory = Get-ServiceRelativePath -Root $runRoot -FullPath $expectedPath
            expected_artifact_inventory_sha256 = $expectedSha
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
    if (-not $observerSkipped) { Complete-ServiceObserverReports }

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
    $systemVerificationPath = Join-Path $verificationRoot "system-evidence.json"
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
        schema = "HotRedundantQualificationTerminalV2"; status = $status; run_id = $runId
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
            kernel_network = [object[]]@($kernelWindows)
            network_witness = [object[]]@($networkWindows)
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
    foreach ($window in @($observerWindows)) {
        foreach ($path in @($window.kernelStop, $window.networkStop)) {
            if (-not (Test-Path -LiteralPath $path) -and (Test-Path -LiteralPath (Split-Path $path -Parent))) {
                try { $null = Write-RawQualificationDurableNewFile -Path $path -Bytes ([byte[]]@()) } catch {}
            }
        }
        foreach ($kind in @("kernel", "network")) {
            $launch = $window.$kind
            if ($null -ne $launch -and $launch.ProcessHandle -ne [IntPtr]::Zero) {
                if (-not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 10000)) {
                    $null = [RawQualificationNative]::TerminateProcessHandle($launch.ProcessHandle, 0xEE32)
                    $null = [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 5000)
                }
                $null = [RawQualificationNative]::CloseRetainedProcessHandle($launch)
                $window.$kind = $null
            }
        }
        # A nonce alone is not ownership proof: a collision can make startup
        # fail before READY. Stop only a session bound by our exact READY.
        if (-not $terminalWritten) {
            try {
                Stop-OwnedKernelSession -Window $window -Reason "SERVICE_FINALLY" `
                    -RecordServiceEvent ($null -ne $journal -and -not $journal.Closed)
            } catch { [Console]::Error.WriteLine(("Owned kernel cleanup evidence failed: {0}" -f $_)) }
        }
    }
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
