[CmdletBinding()]
param([switch] $ValidateOnly)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
Set-Location -LiteralPath $repo
. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")

$controllerExecutable = Join-Path $repo "target\release\kernel_network_trace.exe"
$collectorExecutable = Join-Path $repo "target\release\segmented_capture.exe"
$generationVerifier = Join-Path $repo "target\release\generation_verify.exe"
$publicConfig = Join-Path $repo "config\public.json"
$tracerpt = Join-Path $env:SystemRoot "System32\tracerpt.exe"
$logman = Join-Path $env:SystemRoot "System32\logman.exe"
$python = Join-Path $repo ".venv\Scripts\python.exe"
foreach ($required in @(
    $controllerExecutable,
    $collectorExecutable,
    $generationVerifier,
    $publicConfig,
    $tracerpt,
    $logman,
    $python
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required WebSocket canary input is absent: $required"
    }
}

$config = Get-Content -LiteralPath $publicConfig -Raw -ErrorAction Stop |
    ConvertFrom-Json -ErrorAction Stop
if ($config.schema_version -cne "1" -or
    $config.environment -cne "production-public-market-data" -or
    $config.venue -cne "binance-spot" -or
    $config.json.websocket_base -cne "wss://data-stream.binance.vision:443" -or
    $config.credentials -cne "FORBIDDEN" -or
    $config.order_entry -cne "ABSENT") {
    throw "Public capture config is outside the exact no-credentials/no-order canary contract."
}

$dnsAddresses = [string[]]@(
    [Net.Dns]::GetHostAddresses("data-stream.binance.vision") |
        ForEach-Object { $_.ToString() } |
        Sort-Object -Unique -CaseSensitive
)
if ($dnsAddresses.Count -eq 0) {
    throw "The public WebSocket hostname did not resolve."
}

$controllerValidationOutput = [string[]]@(
    & $controllerExecutable validate 2>&1 | ForEach-Object { [string]$_ }
)
if ([int]$LASTEXITCODE -ne 0) { throw "Rust ETW ABI validation failed." }
$controllerValidation = ($controllerValidationOutput -join [Environment]::NewLine) |
    ConvertFrom-Json -ErrorAction Stop
if ($controllerValidation.status -cne "PASS" -or
    $controllerValidation.match_any_keyword -cne "0x0000000000000030" -or
    $controllerValidation.raw_packet_payload_capture -ne $false) {
    throw "Rust ETW controller validation policy drifted."
}

if ($ValidateOnly) {
    [ordered]@{
        schema = "KernelNetworkWebSocketCanaryPreflightV1"
        status = "PASS"
        diagnostic_only = $true
        training_eligible = $false
        symbol = "BTCUSDT"
        duration_s = [uint64]30
        segment_s = [uint64]10
        websocket_host = "data-stream.binance.vision"
        websocket_port = [uint16]443
        dns_addresses = $dnsAddresses
        controller_executable = $controllerExecutable
        controller_sha256 = Get-RawQualificationSha256File -Path $controllerExecutable
        controller_validation = $controllerValidation
        collector_executable = $collectorExecutable
        collector_sha256 = Get-RawQualificationSha256File -Path $collectorExecutable
        generation_verifier = $generationVerifier
        generation_verifier_sha256 = Get-RawQualificationSha256File -Path $generationVerifier
        public_config = $publicConfig
        public_config_sha256 = Get-RawQualificationSha256File -Path $publicConfig
        python_executable = $python
    } | ConvertTo-Json -Depth 8
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "The public WebSocket/ETW canary requires an Administrator PowerShell."
}

$conflictingProcesses = [object[]]@(
    Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
        Where-Object {
            $_.Name -in @("raw_campaign.exe", "segmented_capture.exe", "capture.exe") -and
            [string]$_.ExecutablePath -like ((Join-Path $repo "target\*") + "*")
        }
)
if ($conflictingProcesses.Count -ne 0) {
    throw "A project market-data collector is already active; the isolated canary refuses to overlap it."
}

$evidenceBase = Join-Path $repo "artifacts\kernel-network-websocket-canary"
$marketBase = Join-Path $repo "artifacts\kernel-network-websocket-canary-market"
$null = New-Item -ItemType Directory -Path $evidenceBase -Force -ErrorAction Stop
$null = New-Item -ItemType Directory -Path $marketBase -Force -ErrorAction Stop
$runId = "ws-canary-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$runRoot = Join-Path $evidenceBase $runId
$marketRunRoot = Join-Path $marketBase $runId
$null = New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop
$null = New-Item -ItemType Directory -Path $marketRunRoot -ErrorAction Stop

$sessionName = "BinanceKernelNetwork_" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$etlPath = Join-Path $runRoot "kernel-network.etl"
$stopPath = Join-Path $runRoot "stop.request"
$controllerStdoutPath = Join-Path $runRoot "controller.stdout.jsonl"
$controllerStderrPath = Join-Path $runRoot "controller.stderr.txt"
$collectorStdoutPath = Join-Path $runRoot "collector.stdout.jsonl"
$collectorStderrPath = Join-Path $runRoot "collector.stderr.txt"
$decodedPath = Join-Path $runRoot "kernel-network.xml"
$generationVerificationPath = Join-Path $runRoot "generation-verification.json"
$reportPath = Join-Path $runRoot "websocket-canary.json"

$controller = $null
$collector = $null
$ready = $false
$emergencyCleanup = $false
$cleanupOutput = @()
$cleanupExitCode = $null
$postCleanupQuery = @()
$postCleanupQueryExitCode = $null
$startedUtc = [DateTimeOffset]::UtcNow

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)] [string] $Value)
    if ($Value.Contains('"')) { throw "Process argument contains an unsupported quote." }
    return '"' + $Value + '"'
}

trap {
    $failurePath = Join-Path $runRoot "wrapper-failure.json"
    if (-not (Test-Path -LiteralPath $failurePath)) {
        $failure = [ordered]@{
            schema = "KernelNetworkWebSocketCanaryFailureV1"
            status = "FAILED"
            observed_utc = [DateTimeOffset]::UtcNow.ToString("o")
            message = [string]$_.Exception.Message
            exception_type = [string]$_.Exception.GetType().FullName
            fully_qualified_error_id = [string]$_.FullyQualifiedErrorId
            category = [string]$_.CategoryInfo
            position = [string]$_.InvocationInfo.PositionMessage
            script_stack_trace = [string]$_.ScriptStackTrace
        }
        try { $null = Write-RawQualificationDurableNewJson -Path $failurePath -Value $failure }
        catch { [Console]::Error.WriteLine("Could not persist canary failure: " + $_.Exception.Message) }
    }
    [Console]::Error.WriteLine([string]$_.Exception.Message)
    exit 1
}

$controllerArguments = @(
    (Quote-ProcessArgument -Value $sessionName),
    (Quote-ProcessArgument -Value $etlPath),
    (Quote-ProcessArgument -Value $stopPath),
    "64",
    "180"
)

try {
    $controller = Start-Process `
        -FilePath $controllerExecutable `
        -ArgumentList $controllerArguments `
        -RedirectStandardOutput $controllerStdoutPath `
        -RedirectStandardError $controllerStderrPath `
        -PassThru `
        -WindowStyle Hidden

    $readyDeadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
    while ([DateTimeOffset]::UtcNow -lt $readyDeadline) {
        $controller.Refresh()
        if ($controller.HasExited) { break }
        if (Test-Path -LiteralPath $controllerStdoutPath -PathType Leaf) {
            $readyLine = Get-Content -LiteralPath $controllerStdoutPath -ErrorAction Stop |
                Where-Object { $_ -match '"status":"READY"' } |
                Select-Object -First 1
            if ($null -ne $readyLine) {
                $readyRecord = $readyLine | ConvertFrom-Json -ErrorAction Stop
                if ($readyRecord.session_name -cne $sessionName -or
                    [IO.Path]::GetFullPath([string]$readyRecord.etl_path) -cne [IO.Path]::GetFullPath($etlPath)) {
                    throw "ETW READY identity disagrees with the launched controller."
                }
                $ready = $true
                break
            }
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw "ETW controller did not publish exact READY evidence." }

    $collectorDigest = Get-RawQualificationSha256File -Path $collectorExecutable
    $configDigest = Get-RawQualificationSha256File -Path $publicConfig
    $previousCollectorDigest = $env:BINANCE_LOB_EXPECTED_CAPTURE_SHA256
    $previousConfigDigest = $env:BINANCE_LOB_EXPECTED_PUBLIC_CONFIG_SHA256
    try {
        $env:BINANCE_LOB_EXPECTED_CAPTURE_SHA256 = $collectorDigest
        $env:BINANCE_LOB_EXPECTED_PUBLIC_CONFIG_SHA256 = $configDigest
        $collectorStartedUtc = [DateTimeOffset]::UtcNow
        $collector = Start-Process `
            -FilePath $collectorExecutable `
            -ArgumentList @(
                "BTCUSDT",
                "0",
                "30",
                "10",
                (Quote-ProcessArgument -Value $marketRunRoot)
            ) `
            -WorkingDirectory $repo `
            -RedirectStandardOutput $collectorStdoutPath `
            -RedirectStandardError $collectorStderrPath `
            -PassThru `
            -WindowStyle Hidden
    }
    finally {
        $env:BINANCE_LOB_EXPECTED_CAPTURE_SHA256 = $previousCollectorDigest
        $env:BINANCE_LOB_EXPECTED_PUBLIC_CONFIG_SHA256 = $previousConfigDigest
    }

    if (-not $collector.WaitForExit(120000)) {
        throw "Public WebSocket collector exceeded its bounded 120-second deadline."
    }
    $collector.WaitForExit()
    $collectorCompletedUtc = [DateTimeOffset]::UtcNow
    if ([int]$collector.ExitCode -ne 0) {
        throw "Public WebSocket collector exited unsuccessfully: $($collector.ExitCode)."
    }
    $collectorStderrBytes = [uint64](Get-Item -LiteralPath $collectorStderrPath -ErrorAction Stop).Length
    if ($collectorStderrBytes -ne 0) {
        throw "Public WebSocket collector wrote unexpected stderr."
    }

    $generationDirectories = [object[]]@(
        Get-ChildItem -LiteralPath $marketRunRoot -Directory -ErrorAction Stop
    )
    if ($generationDirectories.Count -ne 1) {
        throw "Public WebSocket collector did not create exactly one owned generation."
    }
    $generationRoot = [IO.Path]::GetFullPath($generationDirectories[0].FullName)
    $generationVerificationOutput = [string[]]@(
        & $generationVerifier $generationRoot $generationVerificationPath 2>&1 |
            ForEach-Object { [string]$_ }
    )
    $generationVerificationExitCode = [int]$LASTEXITCODE
    if ($generationVerificationExitCode -ne 0 -or
        -not (Test-Path -LiteralPath $generationVerificationPath -PathType Leaf)) {
        throw "Independent Rust generation verification failed: " + ($generationVerificationOutput -join " ")
    }
    $generationVerification = Get-Content -LiteralPath $generationVerificationPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ($generationVerification.schema -cne "VerifiedGenerationV1" -or
        $generationVerification.status -cne "PASS" -or
        $generationVerification.symbol -cne "BTCUSDT" -or
        [uint64]$generationVerification.generation_index -ne 0 -or
        [uint64]$generationVerification.duration_requested_s -ne 30 -or
        [uint64]$generationVerification.segment_duration_s -ne 10 -or
        $generationVerification.collector_executable_sha256 -cne $collectorDigest -or
        $generationVerification.public_config_sha256 -cne $configDigest) {
        throw "Independent Rust generation verification identity drifted."
    }
}
finally {
    if ($null -ne $collector) {
        $collector.Refresh()
        if (-not $collector.HasExited) {
            Stop-Process -Id $collector.Id -Force -ErrorAction Stop
            $collector.WaitForExit()
        }
    }
    if ($null -ne $controller) {
        $controller.Refresh()
        if (-not $controller.HasExited) {
            if (-not (Test-Path -LiteralPath $stopPath)) {
                $null = New-Item -ItemType File -Path $stopPath -ErrorAction Stop
            }
            if (-not $controller.WaitForExit(30000)) {
                $emergencyCleanup = $true
            }
        }
    }
    $queryOutput = [string[]]@(
        & $logman query -ets $sessionName 2>&1 | ForEach-Object { [string]$_ }
    )
    $queryExitCode = [int]$LASTEXITCODE
    if ($queryExitCode -eq 0) {
        $emergencyCleanup = $true
        $cleanupOutput = [string[]]@(
            & $logman stop -ets $sessionName 2>&1 | ForEach-Object { [string]$_ }
        )
        $cleanupExitCode = [int]$LASTEXITCODE
    }
    if ($null -ne $controller) {
        $controller.Refresh()
        if (-not $controller.HasExited -and -not $controller.WaitForExit(10000)) {
            Stop-Process -Id $controller.Id -Force -ErrorAction Stop
            $controller.WaitForExit()
        }
    }
    $postCleanupQuery = [string[]]@(
        & $logman query -ets $sessionName 2>&1 | ForEach-Object { [string]$_ }
    )
    $postCleanupQueryExitCode = [int]$LASTEXITCODE
}

if ($postCleanupQueryExitCode -eq 0) {
    throw "ETW session remained orphaned after bounded cleanup."
}
if ($emergencyCleanup) {
    $cleanupEvidence = [ordered]@{
        schema = "KernelNetworkWebSocketEmergencyCleanupV1"
        status = if ($cleanupExitCode -eq 0 -and $postCleanupQueryExitCode -ne 0) { "STOPPED" } else { "FAILED" }
        session_name = $sessionName
        cleanup_exit_code = $cleanupExitCode
        cleanup_output = $cleanupOutput
        post_cleanup_query_exit_code = $postCleanupQueryExitCode
        post_cleanup_query_output = $postCleanupQuery
    }
    $null = Write-RawQualificationDurableNewJson `
        -Path (Join-Path $runRoot "emergency-cleanup.json") `
        -Value $cleanupEvidence
    throw "WebSocket canary required emergency ETW cleanup; PASS is forbidden."
}

$controller.Refresh()
if (-not $controller.HasExited -or [int]$controller.ExitCode -ne 0) {
    throw "ETW controller did not exit successfully."
}
$controllerStderrBytes = [uint64](Get-Item -LiteralPath $controllerStderrPath -ErrorAction Stop).Length
if ($controllerStderrBytes -ne 0) { throw "ETW controller wrote unexpected stderr." }
$records = [object[]]@(
    Get-Content -LiteralPath $controllerStdoutPath -ErrorAction Stop |
        ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop }
)
if ($records.Count -ne 2 -or
    $records[0].schema -cne "KernelNetworkTraceReadyV1" -or
    $records[0].status -cne "READY" -or
    $records[1].schema -cne "KernelNetworkTraceSealV1" -or
    $records[1].status -cne "SEALED") {
    throw "ETW controller stdout is not the exact READY/SEALED sequence."
}
$statistics = $records[1].statistics
if ([uint32]$statistics.events_lost -ne 0 -or
    [uint32]$statistics.log_buffers_lost -ne 0 -or
    [uint32]$statistics.realtime_buffers_lost -ne 0) {
    throw "ETW controller reported event or buffer loss."
}

$etlItem = Get-Item -LiteralPath $etlPath -ErrorAction Stop
if ([uint64]$etlItem.Length -eq 0 -or [uint64]$etlItem.Length -gt 64MB) {
    throw "ETW artifact is empty or oversized."
}
$decodeOutput = [string[]]@(
    & $tracerpt $etlPath -o $decodedPath -of XML -lr -y 2>&1 |
        ForEach-Object { [string]$_ }
)
$decodeExitCode = [int]$LASTEXITCODE
if ($decodeExitCode -ne 0 -or -not (Test-Path -LiteralPath $decodedPath -PathType Leaf)) {
    throw "tracerpt could not decode the WebSocket ETW artifact."
}
$decodedItem = Get-Item -LiteralPath $decodedPath -ErrorAction Stop
if ([uint64]$decodedItem.Length -eq 0 -or [uint64]$decodedItem.Length -gt 64MB) {
    throw "Decoded ETW XML is empty or oversized."
}

$collectorStdoutItem = Get-Item -LiteralPath $collectorStdoutPath -ErrorAction Stop
$collectorStderrItem = Get-Item -LiteralPath $collectorStderrPath -ErrorAction Stop
$generationVerificationItem = Get-Item -LiteralPath $generationVerificationPath -ErrorAction Stop
$report = [ordered]@{
    schema = "KernelNetworkWebSocketCanaryV1"
    run_id = $runId
    status = "CANDIDATE"
    started_utc = $startedUtc.ToString("o")
    collector_started_utc = $collectorStartedUtc.ToString("o")
    collector_completed_utc = $collectorCompletedUtc.ToString("o")
    completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
    diagnostic_only = $true
    training_eligible = $false
    controller_executable = $controllerExecutable
    controller_sha256 = Get-RawQualificationSha256File -Path $controllerExecutable
    session_name = $sessionName
    controller_pid = [uint32]$controller.Id
    controller_exit_code = [int]$controller.ExitCode
    controller_records = $records
    controller_stderr_file = "controller.stderr.txt"
    controller_stderr_bytes = $controllerStderrBytes
    controller_stderr_sha256 = Get-RawQualificationSha256File -Path $controllerStderrPath
    collector_executable = $collectorExecutable
    collector_sha256 = $collectorDigest
    collector_pid = [uint32]$collector.Id
    collector_exit_code = [int]$collector.ExitCode
    collector_stdout_file = "collector.stdout.jsonl"
    collector_stdout_bytes = [uint64]$collectorStdoutItem.Length
    collector_stdout_sha256 = Get-RawQualificationSha256File -Path $collectorStdoutPath
    collector_stderr_file = "collector.stderr.txt"
    collector_stderr_bytes = [uint64]$collectorStderrItem.Length
    collector_stderr_sha256 = Get-RawQualificationSha256File -Path $collectorStderrPath
    public_config = $publicConfig
    public_config_sha256 = $configDigest
    generation_verifier_executable = $generationVerifier
    generation_verifier_sha256 = Get-RawQualificationSha256File -Path $generationVerifier
    generation_verifier_exit_code = $generationVerificationExitCode
    symbol = "BTCUSDT"
    generation_index = [uint64]0
    duration_s = [uint64]30
    segment_s = [uint64]10
    websocket_host = "data-stream.binance.vision"
    websocket_port = [uint16]443
    dns_addresses = $dnsAddresses
    generation_directory = $generationRoot
    generation_verification_file = "generation-verification.json"
    generation_verification_bytes = [uint64]$generationVerificationItem.Length
    generation_verification_sha256 = Get-RawQualificationSha256File -Path $generationVerificationPath
    etl_file = "kernel-network.etl"
    etl_bytes = [uint64]$etlItem.Length
    etl_sha256 = Get-RawQualificationSha256File -Path $etlPath
    decoded_file = "kernel-network.xml"
    decoded_bytes = [uint64]$decodedItem.Length
    decoded_sha256 = Get-RawQualificationSha256File -Path $decodedPath
    tracerpt_exit_code = $decodeExitCode
    tracerpt_output = $decodeOutput
    orphan_query_exit_code = $postCleanupQueryExitCode
    orphan_query_output = $postCleanupQuery
    selected_event_ids = [uint16[]](12, 13, 14, 15, 16, 17, 28, 29, 30, 31, 32)
    raw_packet_payload_capture = $false
    correlation_status = "OPEN_PENDING_INDEPENDENT_VERIFY"
}
$null = Write-RawQualificationDurableNewJson -Path $reportPath -Value $report

$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $repo "src"
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $verificationOutput = [string[]]@(
        & $python -B -m binance_lob.kernel_network_websocket_verify_cli $runRoot 2>&1 |
            ForEach-Object { [string]$_ }
    )
    $verificationExitCode = [int]$LASTEXITCODE
}
finally {
    $ErrorActionPreference = $previousErrorActionPreference
    $env:PYTHONPATH = $previousPythonPath
}
$verificationOutput | ForEach-Object { $_ | Out-Host }
if ($verificationExitCode -ne 0) {
    throw "Independent public WebSocket/ETW verification failed; evidence is preserved."
}
$report | ConvertTo-Json -Depth 12
Write-Output $runRoot
