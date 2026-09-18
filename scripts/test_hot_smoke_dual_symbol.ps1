[CmdletBinding()]
param(
    [ValidateRange(60, 600)]
    [int] $TotalSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$helper = Join-Path $PSScriptRoot "RawQualification.Windows.ps1"
. $helper
Initialize-RawQualificationNative

# Production-mode smoke (ADR-16, non-elevated equivalent of the service
# IntegrationTest without the kernel ETW observer): the release supervisor
# runs BOTH symbols with two redundant lanes and a live arbitration sidecar
# per symbol; at terminal every artifact is dual-verified and every
# canonical journal is checked against the redundant evidence oracle
# (trades = union of both lanes, depth = untouched primary lane, zero gaps).
$capture = Join-Path $repo "target\release\hot_redundant_capture.exe"
$rustVerifier = Join-Path $repo "target\release\hot_redundant_verify.exe"
$liveArbiter = Join-Path $repo "target\release\live_arbitration.exe"
$liveArbiterVerify = Join-Path $repo "target\release\live_arbitration_verify.exe"
$python = Join-Path $repo ".venv\Scripts\python.exe"
foreach ($path in @($capture, $rustVerifier, $liveArbiter, $liveArbiterVerify, $python)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required release binary is absent: $path"
    }
}

$nonce = [guid]::NewGuid().ToString("N").Substring(0, 12)
$runRoot = Join-Path $repo ("artifacts\hsm\smoke-{0}" -f $nonce)
$outputRoot = Join-Path $runRoot "c"
$canonicalRoot = Join-Path $runRoot "canonical-live"
New-Item -ItemType Directory -Path $outputRoot | Out-Null
New-Item -ItemType Directory -Path $canonicalRoot | Out-Null

# Single generation per campaign and windows longer than the total: every
# lane covers the whole run continuously (the exact zero-loss topology).
$topology = [string[]]@("240", "300", "60", "60", "200", "190")
$jobName = "BinanceHotSmoke_{0}" -f $nonce
$job = [RawQualificationNative]::CreateKillOnCloseJob($jobName)

function Read-Events {
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

$launches = [ordered]@{}
$artifacts = [ordered]@{}
$arbiters = [ordered]@{}

try {
    foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
        $stdout = Join-Path $runRoot ("{0}.supervisor.stdout.jsonl" -f $symbol)
        $stderr = Join-Path $runRoot ("{0}.supervisor.stderr.txt" -f $symbol)
        $arguments = [string[]]@(@($symbol) + @([string]$TotalSeconds) + $topology + @($outputRoot, "--event-stream"))
        $launch = [RawQualificationNative]::StartSuspendedInJobRetained(
            $job, $capture, $arguments, $repo, $stdout, $stderr
        )
        $launches[$symbol] = $launch
    }

    # Wait for both lanes of every symbol to become READY, binding artifacts.
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while ($deadline.Elapsed.TotalSeconds -lt 120) {
        $allReady = $true
        foreach ($symbol in @($launches.Keys)) {
            if (-not $artifacts.Contains($symbol)) {
                $roots = @(Get-ChildItem -LiteralPath $outputRoot -Directory -ErrorAction SilentlyContinue)
                foreach ($root in $roots) {
                    $startup = Join-Path $root.FullName "supervisor-startup.json"
                    if (-not (Test-Path -LiteralPath $startup -PathType Leaf)) { continue }
                    $value = Get-Content -LiteralPath $startup -Raw | ConvertFrom-Json
                    if ([string]$value.symbol -ceq $symbol) { $artifacts[$symbol] = $root.FullName }
                }
            }
            if (-not $artifacts.Contains($symbol)) { $allReady = $false; continue }
            $ready = @(
                Read-Events -Artifact $artifacts[$symbol] |
                    Where-Object { $_.body.payload.event -ceq "LANE_READY" } |
                    ForEach-Object { [string]$_.body.payload.lane } |
                    Sort-Object -Unique
            )
            if ($ready.Count -lt 2) { $allReady = $false }
        }
        if ($allReady) { break }
        Start-Sleep -Milliseconds 200
    }
    foreach ($symbol in @($launches.Keys)) {
        if (-not $artifacts.Contains($symbol)) {
            throw "Smoke artifact for $symbol was not created in time."
        }
    }

    # Launch one arbitration sidecar per symbol at READY, exactly like the
    # production service.
    foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
        $journal = Join-Path $canonicalRoot ("{0}.jsonl" -f $symbol)
        $arbStdout = Join-Path $runRoot ("{0}.arbiter.stdout.txt" -f $symbol)
        $arbStderr = Join-Path $runRoot ("{0}.arbiter.stderr.txt" -f $symbol)
        $arbiterLaunch = [RawQualificationNative]::StartSuspendedInJobRetained(
            $job, $liveArbiter,
            ([string[]]@($symbol, $artifacts[$symbol], $journal, [string]$TotalSeconds)),
            $repo, $arbStdout, $arbStderr
        )
        $arbiters[$symbol] = [ordered]@{
            launch = $arbiterLaunch; journal = $journal; stderr = $arbStderr
        }
    }

    # Wait for both supervisors to exit cleanly.
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    foreach ($symbol in @($launches.Keys)) {
        $launch = $launches[$symbol]
        while (-not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 0)) {
            if ($deadline.Elapsed.TotalSeconds -gt ([int]$TotalSeconds + 120)) {
                throw "$symbol supervisor exceeded the terminal deadline."
            }
            Start-Sleep -Milliseconds 250
        }
        $code = [uint32][RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle)
        if ($code -ne 0) { throw "$symbol supervisor failed with exit code $code." }
        if ((Get-Item -LiteralPath (Join-Path $runRoot ("{0}.supervisor.stderr.txt" -f $symbol))).Length -ne 0) {
            throw "$symbol supervisor wrote unexpected stderr."
        }
        $null = [RawQualificationNative]::CloseRetainedProcessHandle($launch)
    }

    # Wait for both arbiters to exit cleanly and verify everything.
    $report = [ordered]@{}
    foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
        $arb = $arbiters[$symbol]
        if (-not [RawQualificationNative]::WaitForProcessExit($arb.launch.ProcessHandle, 60000)) {
            throw "$symbol live arbitration sidecar exceeded its terminal deadline."
        }
        $arbCode = [uint32][RawQualificationNative]::GetProcessExitCode($arb.launch.ProcessHandle)
        if ($arbCode -ne 0) { throw "$symbol live arbitration sidecar failed with exit code $arbCode." }
        if ((Get-Item -LiteralPath $arb.stderr).Length -ne 0) {
            throw "$symbol live arbitration sidecar wrote unexpected stderr."
        }
        $null = [RawQualificationNative]::CloseRetainedProcessHandle($arb.launch)

        $artifact = $artifacts[$symbol]
        $rustOut = Join-Path $runRoot ("{0}.rust-verify.json" -f $symbol)
        & $rustVerifier $artifact $rustOut 2> (Join-Path $runRoot ("{0}.rust-verify.stderr.txt" -f $symbol))
        if ($LASTEXITCODE -ne 0) { throw "$symbol Rust supervisor verifier failed." }
        $rustValue = Get-Content -LiteralPath $rustOut -Raw | ConvertFrom-Json
        if ($rustValue.status -cne "PASS") { throw "$symbol Rust supervisor verification was not PASS." }

        $oldPythonPath = $env:PYTHONPATH
        try {
            $env:PYTHONPATH = Join-Path $repo "src"
            $pyOut = Join-Path $runRoot ("{0}.python-verify.json" -f $symbol)
            & $python -B -m binance_lob.hot_redundant_verify_cli $artifact --output $pyOut
            if ($LASTEXITCODE -ne 0) { throw "$symbol Python supervisor verifier failed." }
        }
        finally { $env:PYTHONPATH = $oldPythonPath }
        $pyValue = Get-Content -LiteralPath $pyOut -Raw | ConvertFrom-Json
        if ($pyValue.status -cne "PASS") { throw "$symbol Python supervisor verification was not PASS." }

        $arbRust = & $liveArbiterVerify $arb.journal --oracle-artifact $artifact 2>&1
        if ($LASTEXITCODE -ne 0) { throw "$symbol Rust arbitration verifier rejected the canonical journal: $($arbRust -join ' ')" }
        $arbRustValue = $arbRust | Out-String | ConvertFrom-Json
        if ($arbRustValue.status -cne "PASS" -or $arbRustValue.oracle_identity -cne "PASS") {
            throw "$symbol Rust arbitration verifier did not prove oracle identity."
        }
        if ([int]$arbRustValue.gaps -ne 0) { throw "$symbol canonical journal contains a gap." }

        $oldPythonPath = $env:PYTHONPATH
        try {
            $env:PYTHONPATH = Join-Path $repo "src"
            $arbPython = & $python -B -m binance_lob.live_arbitration_verify_cli $arb.journal --oracle-artifact $artifact 2>&1
            if ($LASTEXITCODE -ne 0) { throw "$symbol Python arbitration verifier rejected the canonical journal: $($arbPython -join ' ')" }
        }
        finally { $env:PYTHONPATH = $oldPythonPath }
        $arbPythonValue = $arbPython | Out-String | ConvertFrom-Json
        if ($arbPythonValue.status -cne "PASS" -or $arbPythonValue.oracle_identity -cne "PASS") {
            throw "$symbol Python arbitration verifier did not prove oracle identity."
        }

        $report[$symbol] = [ordered]@{
            artifact = $artifact
            journal = $arb.journal
            canonical_trades = [int]$arbRustValue.trades
            canonical_depth_frames = [int]$arbRustValue.depth_frames
            canonical_gaps = [int]$arbRustValue.gaps
            rust_oracle_identity = "PASS"
            python_oracle_identity = "PASS"
        }
    }

    [ordered]@{
        schema = "HotRedundantSmokeV1"
        status = "PASS"
        run_root = $runRoot
        total_seconds = $TotalSeconds
        symbols = $report
    } | ConvertTo-Json -Depth 8
}
finally {
    foreach ($launch in @($launches.Values)) {
        if ($null -ne $launch -and $launch.ProcessHandle -ne [IntPtr]::Zero) {
            if (-not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 0)) {
                $null = [RawQualificationNative]::TryTerminateJobObjectNoThrow($job, 0xEE33)
                $null = [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 30000)
            }
            $null = [RawQualificationNative]::CloseRetainedProcessHandle($launch)
        }
    }
    if ($job -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($job) }
}
