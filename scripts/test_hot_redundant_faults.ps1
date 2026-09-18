[CmdletBinding()]
param(
    [ValidateSet("SinglePrimary", "Dual", "SilentStall", "SequentialWindows", "ArbitrationFailover")]
    [string] $Scenario = "SinglePrimary",
    [ValidateSet("BTCUSDT", "ETHUSDT")]
    [string] $Symbol = "BTCUSDT",
    [int] $DeadlineSeconds = 300,
    # Build profile directory for the tested executables; defaults to the
    # release profile used by production.  A debug root lets the fault gates
    # run while another campaign still holds the release images.
    [string] $BinRoot = "target\release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$helper = Join-Path $PSScriptRoot "RawQualification.Windows.ps1"
. $helper
Initialize-RawQualificationNative

$capture = Join-Path $repo (Join-Path $BinRoot "hot_redundant_capture.exe")
$rustVerifier = Join-Path $repo (Join-Path $BinRoot "hot_redundant_verify.exe")
$python = Join-Path $repo ".venv\Scripts\python.exe"
$liveArbiter = Join-Path $repo (Join-Path $BinRoot "live_arbitration.exe")
$liveArbiterVerify = Join-Path $repo (Join-Path $BinRoot "live_arbitration_verify.exe")
foreach ($path in @($capture, $rustVerifier, $python)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required fault-gate executable is absent: $path"
    }
}

$nonce = [guid]::NewGuid().ToString("N").Substring(0, 12)
$scenarioCode = if ($Scenario -ceq "SinglePrimary") { "s" } else { "d" }
# The production verifiers still run on Windows builds without long-path
# awareness.  Keep fault evidence deliberately short and let the Rust
# preflight independently enforce the exact projected MAX_PATH budget.
$evidence = Join-Path $repo ("artifacts\hfg\{0}-{1}" -f $scenarioCode, $nonce)
$output = Join-Path $evidence "c"
$stdout = Join-Path $evidence "supervisor.stdout.jsonl"
$stderr = Join-Path $evidence "supervisor.stderr.txt"
New-Item -ItemType Directory -Path $output | Out-Null

$jobName = "BinanceHotFault_{0}" -f $nonce
$job = [IntPtr]::Zero
$launch = $null
$artifact = $null
$timer = [Diagnostics.Stopwatch]::StartNew()

function Read-SupervisorEvents {
    param([Parameter(Mandatory = $true)] [string] $Artifact)
    $path = Join-Path $Artifact "supervisor-events.jsonl"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return @() }
    $records = @()
    foreach ($line in @(Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $records += ,($line | ConvertFrom-Json -ErrorAction Stop) } catch {}
    }
    return $records
}

function Wait-Until {
    param(
        [Parameter(Mandatory = $true)] [scriptblock] $Predicate,
        [Parameter(Mandatory = $true)] [string] $Failure
    )
    while ($timer.Elapsed.TotalSeconds -lt $DeadlineSeconds) {
        if (& $Predicate) { return }
        if ($null -ne $launch -and [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 0)) {
            throw "$Failure Supervisor exited first with code $([RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle))."
        }
        Start-Sleep -Milliseconds 100
    }
    throw "$Failure Deadline exceeded."
}

function Get-ChildProcesses {
    param([Parameter(Mandatory = $true)] [uint32[]] $Parents)
    return @(
        Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object { [uint32]$_.ParentProcessId -in $Parents }
    )
}

try {
    $job = [RawQualificationNative]::CreateKillOnCloseJob($jobName)
    # Process-kill scenarios preserve the historical 70s topology.  The
    # silent-stall and sequential-window scenarios mirror the production
    # endurance topology: lane windows shorter than the total (a failed window
    # is replaced by a fresh, independently verified campaign window) and
    # generation rotations longer than the windows (each campaign is a single
    # generation, exactly as 14400/14040 s windows against 82800/81900 s
    # rotations).  The lane stagger (60/45) exceeds the restart-to-ready
    # latency so a renewal in one lane never overlaps the other lane's
    # not-ready interval (no self-inflicted coverage gap).
    $topology = switch ($Scenario) {
        "SinglePrimary" { [string[]]@("70", "30", "20", "10", "10", "100", "90") }
        "Dual" { [string[]]@("70", "30", "20", "10", "10", "100", "90") }
        "SilentStall" { [string[]]@("150", "90", "160", "10", "10", "60", "150") }
        "SequentialWindows" { [string[]]@("150", "90", "80", "10", "10", "60", "45") }
        # ArbitrationFailover: one generation per campaign, windows longer
        # than the total so the untouched PRIMARY lane covers the entire run
        # continuously and forms the exact zero-loss oracle.
        "ArbitrationFailover" { [string[]]@("150", "240", "300", "60", "60", "200", "190") }
        default { throw "Unsupported scenario: $Scenario" }
    }
    $arguments = [string[]]@(@($Symbol) + $topology + @($output, "--event-stream"))
    $environment = [string[]]@(
        "SystemDrive=$env:SystemDrive",
        "SystemRoot=$env:SystemRoot",
        "TEMP=$env:TEMP",
        "TMP=$env:TMP",
        "WINDIR=$env:WINDIR"
    )
    if ($Scenario -ceq "SilentStall") {
        # Injected silent market black-hole: the PRIMARY lane's trade stream
        # stops delivering at generation-monotonic second 8 while the process
        # stays alive.  The campaign must fail with the exact production
        # freshness error and the supervisor must replace the window.
        # Timing rationale: the SHADOW window equals the total (150 s), so
        # the shadow is READY for the whole run and never renews; the
        # primary's injected failure lands near 8+30+lag ≈ 40 s and its
        # restart-to-ready aftermath (~5 s) therefore can never collide with
        # a shadow renewal.  The gate then deterministically proves that a
        # single-lane stall alone never opens a coverage gap, and the
        # restarted primary still completes a verified window before the
        # horizon.  (Earlier attempts failed by construction: a 45 s shadow
        # window renews at ~47 s, exactly when the primary's failure
        # aftermath was still not-ready — a one-second dual-unreadiness the
        # supervisor correctly typed as a gap; and a 35 s stall outlived the
        # 60 s primary window: 35+30 > 60, so the campaign completed cleanly
        # before its freshness deadline.)
        $environment += "BINANCE_LOB_FAULT_SILENT_STALL=trade:8:p"
    }
    $launch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
        $job, $capture, $arguments, $repo, $stdout, $stderr, $environment
    )

    Wait-Until -Failure "Artifact was not created." -Predicate {
        $roots = @(Get-ChildItem -LiteralPath $output -Directory -ErrorAction SilentlyContinue)
        if ($roots.Count -gt 1) { throw "Supervisor created more than one artifact." }
        if ($roots.Count -eq 1) { $script:artifact = $roots[0].FullName; return $true }
        return $false
    }
    Wait-Until -Failure "Both lanes did not become READY." -Predicate {
        $ready = @(
            Read-SupervisorEvents -Artifact $artifact |
                Where-Object { $_.body.payload.event -ceq "LANE_READY" } |
                ForEach-Object { [string]$_.body.payload.lane } |
                Sort-Object -Unique
        )
        return $ready.Count -eq 2
    }

    $rawCampaigns = @(Get-ChildProcesses -Parents @([uint32]$launch.ProcessId) | Where-Object Name -CEQ "raw_campaign.exe")
    if ($rawCampaigns.Count -ne 2) { throw "Expected exactly two raw_campaign children after READY." }
    $primaryRoot = Join-Path $artifact "p"
    $shadowRoot = Join-Path $artifact "s"
    $primary = @($rawCampaigns | Where-Object { $_.CommandLine -like "*$primaryRoot*" })
    $shadow = @($rawCampaigns | Where-Object { $_.CommandLine -like "*$shadowRoot*" })
    if ($primary.Count -ne 1 -or $shadow.Count -ne 1) { throw "Could not bind exact raw_campaign PIDs to both lanes." }

    $victims = @()
    if ($Scenario -ceq "SinglePrimary" -or $Scenario -ceq "Dual") {
        [uint32[]] $targetRawPids = if ($Scenario -ceq "SinglePrimary") {
            @([uint32]$primary[0].ProcessId)
        } else {
            @([uint32]$primary[0].ProcessId, [uint32]$shadow[0].ProcessId)
        }
        $victims = @(Get-ChildProcesses -Parents $targetRawPids | Where-Object Name -CEQ "segmented_capture.exe")
        if ($victims.Count -lt $targetRawPids.Count) { throw "Each targeted lane lacks a segmented_capture victim." }
        foreach ($rawPid in $targetRawPids) {
            $victim = @($victims | Where-Object { [uint32]$_.ParentProcessId -eq $rawPid } | Select-Object -First 1)
            if ($victim.Count -ne 1) { throw "Target raw campaign lacks one exact fault victim." }
            Stop-Process -Id ([int]$victim[0].ProcessId) -Force -ErrorAction Stop
        }

        Wait-Until -Failure "Injected lane failures were not durably observed." -Predicate {
            $failed = @(Read-SupervisorEvents -Artifact $artifact | Where-Object { $_.body.payload.event -ceq "LANE_FAILED" })
            return $failed.Count -ge $targetRawPids.Count
        }
        Wait-Until -Failure "Failed lanes did not restart and become READY." -Predicate {
            $events = @(Read-SupervisorEvents -Artifact $artifact)
            $restarted = @($events | Where-Object { $_.body.payload.event -ceq "LANE_RESTARTED" })
            $newReady = @($events | Where-Object { $_.body.payload.event -ceq "LANE_READY" -and ([string]$_.body.payload.token -match "-2-") })
            return $restarted.Count -ge $targetRawPids.Count -and $newReady.Count -ge $targetRawPids.Count
        }
    }
    elseif ($Scenario -ceq "SilentStall") {
        # No process is killed: the injected silent market black-hole makes the
        # PRIMARY campaign fail with the exact production freshness error while
        # every PID stays alive.
        Wait-Until -Failure "Injected silent stall did not fail the primary lane with the exact freshness error." -Predicate {
            $failed = @(Read-SupervisorEvents -Artifact $artifact | Where-Object {
                $_.body.payload.event -ceq "LANE_FAILED" -and
                [string]$_.body.payload.lane -ceq "PRIMARY" -and
                ([string]$_.body.payload.reason) -like "*market-message freshness deadline exceeded*"
            })
            return $failed.Count -ge 1
        }
        Wait-Until -Failure "Silent-stall lanes did not replace the failed window with verified complete windows." -Predicate {
            $events = @(Read-SupervisorEvents -Artifact $artifact)
            $primaryComplete = @($events | Where-Object {
                $_.body.payload.event -ceq "LANE_WINDOW_COMPLETED" -and [string]$_.body.payload.lane -ceq "PRIMARY"
            }).Count
            $shadowComplete = @($events | Where-Object {
                $_.body.payload.event -ceq "LANE_WINDOW_COMPLETED" -and [string]$_.body.payload.lane -ceq "SHADOW"
            }).Count
            return $primaryComplete -ge 1 -and $shadowComplete -ge 1
        }
    }
    elseif ($Scenario -ceq "SequentialWindows") {
        # No fault at all: bounded lane windows must retire cleanly and renew
        # into independent verified campaigns, proving the endurance topology.
        Wait-Until -Failure "Lanes did not renew multiple clean verified windows." -Predicate {
            $events = @(Read-SupervisorEvents -Artifact $artifact)
            $primaryComplete = @($events | Where-Object {
                $_.body.payload.event -ceq "LANE_WINDOW_COMPLETED" -and [string]$_.body.payload.lane -ceq "PRIMARY"
            }).Count
            $shadowComplete = @($events | Where-Object {
                $_.body.payload.event -ceq "LANE_WINDOW_COMPLETED" -and [string]$_.body.payload.lane -ceq "SHADOW"
            }).Count
            return $primaryComplete -ge 2 -and $shadowComplete -ge 2
        }
    }
    elseif ($Scenario -ceq "ArbitrationFailover") {
        # ADR-16 zero-loss oracle: the live cross-lane arbitration sidecar
        # publishes the canonical live journal while the SHADOW lane's stream
        # is killed.  The untouched PRIMARY lane covers the whole run and is
        # the ground truth: the canonical journal must be event-identical.
        foreach ($path in @($liveArbiter, $liveArbiterVerify)) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "Required arbitration executable is absent: $path"
            }
        }
        $arbJournal = Join-Path $evidence "canonical-live.jsonl"
        $arbStdout = Join-Path $evidence "arbiter.stdout.txt"
        $arbStderr = Join-Path $evidence "arbiter.stderr.txt"
        $arbiterLaunch = [RawQualificationNative]::StartSuspendedInJobRetained(
            $job, $liveArbiter,
            ([string[]]@($Symbol, $artifact, $arbJournal, "150")),
            $repo, $arbStdout, $arbStderr
        )
        Start-Sleep -Milliseconds 1500
        $shadowVictim = @(Get-ChildProcesses -Parents @([uint32]$shadow[0].ProcessId) | Where-Object Name -CEQ "segmented_capture.exe")
        if ($shadowVictim.Count -lt 1) { throw "Shadow lane lacks a segmented_capture victim." }
        $victims = @($shadowVictim | Select-Object -First 1)
        Stop-Process -Id ([int]$victims[0].ProcessId) -Force -ErrorAction Stop

        Wait-Until -Failure "The killed shadow lane was not durably observed." -Predicate {
            $failed = @(Read-SupervisorEvents -Artifact $artifact | Where-Object {
                $_.body.payload.event -ceq "LANE_FAILED" -and [string]$_.body.payload.lane -ceq "SHADOW"
            })
            return $failed.Count -ge 1
        }
        Wait-Until -Failure "The shadow lane did not restart and become READY." -Predicate {
            $events = @(Read-SupervisorEvents -Artifact $artifact)
            $restarted = @($events | Where-Object {
                $_.body.payload.event -ceq "LANE_RESTARTED" -and [string]$_.body.payload.lane -ceq "SHADOW"
            })
            $newReady = @($events | Where-Object {
                $_.body.payload.event -ceq "LANE_READY" -and [string]$_.body.payload.lane -ceq "SHADOW" -and
                ([string]$_.body.payload.token -match "-2-")
            })
            return $restarted.Count -ge 1 -and $newReady.Count -ge 1
        }
        Wait-Until -Failure "Arbiter did not publish its started record." -Predicate {
            if (-not (Test-Path -LiteralPath $arbJournal -PathType Leaf)) { return $false }
            return (Select-String -LiteralPath $arbJournal -SimpleMatch '"event":"ARBITRATION_STARTED"' -Quiet)
        }
        $script:arbiterLaunch = $arbiterLaunch
        $script:arbJournal = $arbJournal
        $script:arbStderr = $arbStderr
    }

    while (-not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 100)) {
        if ($timer.Elapsed.TotalSeconds -ge $DeadlineSeconds) { throw "Supervisor terminal deadline exceeded." }
    }
    $exitCode = [RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle)
    if ($exitCode -ne 0) { throw "Supervisor failed with exit code $exitCode." }
    if ((Get-Item -LiteralPath $stderr).Length -ne 0) { throw "Supervisor wrote unexpected stderr." }

    $events = @(Read-SupervisorEvents -Artifact $artifact)
    $opened = @($events | Where-Object { $_.body.payload.event -ceq "GAP_OPENED" })
    $closed = @($events | Where-Object { $_.body.payload.event -ceq "GAP_CLOSED" })
    if ($Scenario -ceq "SinglePrimary" -and ($opened.Count -ne 0 -or $closed.Count -ne 0)) {
        throw "A single-lane failure incorrectly opened a coverage gap."
    }
    if ($Scenario -ceq "Dual" -and ($opened.Count -ne 1 -or $closed.Count -ne 1)) {
        throw "The dual failure did not open and close exactly one gap."
    }
    if ($Scenario -ceq "SilentStall" -and ($opened.Count -ne 0 -or $closed.Count -ne 0)) {
        throw "A silent-stall single-lane failure incorrectly opened a coverage gap."
    }
    if ($Scenario -ceq "SequentialWindows" -and ($opened.Count -ne 0 -or $closed.Count -ne 0)) {
        throw "Sequential clean window renewal incorrectly opened a coverage gap."
    }
    if ($Scenario -ceq "ArbitrationFailover" -and ($opened.Count -ne 0 -or $closed.Count -ne 0)) {
        throw "A single-lane kill with live arbitration incorrectly opened a coverage gap."
    }
    $laneFailures = @($events | Where-Object { $_.body.payload.event -ceq "LANE_FAILED" })
    if ($Scenario -ceq "SilentStall") {
        $stallFailure = @($laneFailures | Where-Object {
            [string]$_.body.payload.lane -ceq "PRIMARY" -and
            ([string]$_.body.payload.reason) -like "*market-message freshness deadline exceeded*"
        })
        if ($stallFailure.Count -lt 1) { throw "Silent-stall failure evidence lacks the exact freshness reason." }
        $unexpected = @($laneFailures | Where-Object { [string]$_.body.payload.lane -ceq "SHADOW" })
        if ($unexpected.Count -ne 0) { throw "The injected fault leaked into the healthy shadow lane." }
    }
    if ($Scenario -ceq "SequentialWindows" -and $laneFailures.Count -ne 0) {
        throw "The no-fault sequential scenario recorded an unexpected lane failure."
    }

    $rustOutput = & $rustVerifier $artifact 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Rust verifier rejected fault evidence: $($rustOutput -join ' ')" }
    $oldPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = Join-Path $repo "src"
        $pythonOutput = & $python -B -m binance_lob.hot_redundant_verify_cli $artifact 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Python verifier rejected fault evidence: $($pythonOutput -join ' ')" }
    }
    finally { $env:PYTHONPATH = $oldPythonPath }

    $arbiterVerification = $null
    if ($Scenario -ceq "ArbitrationFailover") {
        if (-not [RawQualificationNative]::WaitForProcessExit($script:arbiterLaunch.ProcessHandle, 60000)) {
            throw "Live arbitration sidecar exceeded its terminal deadline."
        }
        $arbiterExit = [uint32][RawQualificationNative]::GetProcessExitCode($script:arbiterLaunch.ProcessHandle)
        if ($arbiterExit -ne 0) { throw "Live arbitration sidecar failed with exit code $arbiterExit." }
        if ((Get-Item -LiteralPath $script:arbStderr).Length -ne 0) { throw "Live arbitration sidecar wrote unexpected stderr." }
        $null = [RawQualificationNative]::CloseRetainedProcessHandle($script:arbiterLaunch)
        # ADR-16 zero-loss oracle (artifact mode): trades must equal the union
        # of BOTH lanes' durable records and depth must equal the untouched
        # PRIMARY lane's trusted observations, within the canonical window.
        $arbRust = & $liveArbiterVerify $script:arbJournal --oracle-artifact $artifact 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Rust arbitration verifier rejected the canonical journal: $($arbRust -join ' ')" }
        $arbRustValue = $arbRust | Out-String | ConvertFrom-Json
        if ($arbRustValue.status -cne "PASS" -or $arbRustValue.oracle_identity -cne "PASS") {
            throw "Rust arbitration verifier did not prove oracle identity."
        }
        if ([int]$arbRustValue.gaps -ne 0) {
            throw "The canonical live journal contains a gap although the sibling lane covered the loss."
        }
        $oldPythonPath = $env:PYTHONPATH
        try {
            $env:PYTHONPATH = Join-Path $repo "src"
            $arbPython = & $python -B -m binance_lob.live_arbitration_verify_cli $script:arbJournal --oracle-artifact $artifact 2>&1
            if ($LASTEXITCODE -ne 0) { throw "Python arbitration verifier rejected the canonical journal: $($arbPython -join ' ')" }
        }
        finally { $env:PYTHONPATH = $oldPythonPath }
        $arbPythonValue = $arbPython | Out-String | ConvertFrom-Json
        if ($arbPythonValue.status -cne "PASS" -or $arbPythonValue.oracle_identity -cne "PASS") {
            throw "Python arbitration verifier did not prove oracle identity."
        }
        $arbiterVerification = [ordered]@{
            status = "PASS"
            journal = $script:arbJournal
            oracle_artifact = $artifact
            rust_oracle_identity = "PASS"
            python_oracle_identity = "PASS"
            canonical_trades = [int]$arbRustValue.trades
            canonical_depth_frames = [int]$arbRustValue.depth_frames
            canonical_gaps = [int]$arbRustValue.gaps
        }
    }

    [ordered]@{
        schema = "HotRedundantFaultGateV1"
        status = "PASS"
        scenario = $Scenario
        symbol = $Symbol
        artifact = $artifact
        injected_processes = @($victims | ForEach-Object { [uint32]$_.ProcessId })
        injected_fault = if ($Scenario -ceq "SilentStall") { "BINANCE_LOB_FAULT_SILENT_STALL=trade:8:p" } else { $null }
        lane_failures = $laneFailures.Count
        lane_windows_completed = @($events | Where-Object { $_.body.payload.event -ceq "LANE_WINDOW_COMPLETED" }).Count
        lane_restarts = @($events | Where-Object { $_.body.payload.event -ceq "LANE_RESTARTED" }).Count
        gaps_opened = $opened.Count
        gaps_closed = $closed.Count
        rust_verification = "PASS"
        python_verification = "PASS"
        live_arbitration = $arbiterVerification
    } | ConvertTo-Json -Depth 8
}
finally {
    if ($null -ne $launch -and $launch.ProcessHandle -ne [IntPtr]::Zero) {
        if (-not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 0)) {
            $null = [RawQualificationNative]::TryTerminateJobObjectNoThrow($job, 0xEE11)
            $null = [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 30000)
        }
        $null = [RawQualificationNative]::CloseRetainedProcessHandle($launch)
    }
    if ($job -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($job) }
}
