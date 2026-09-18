[CmdletBinding()]
param(
    [switch] $ValidateOnly,
    [switch] $InjectControllerAbortAfterReady
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
Set-Location -LiteralPath $repo
. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")
Initialize-RawQualificationNative

$executable = Join-Path $repo "target\release\kernel_network_trace.exe"
$faultSmoke = Join-Path $PSScriptRoot "_network_trace_fault_smoke.ps1"
$tracerpt = Join-Path $env:SystemRoot "System32\tracerpt.exe"
$python = Join-Path $repo ".venv\Scripts\python.exe"
foreach ($required in @($executable, $faultSmoke, $tracerpt, $python)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required filtered-ETW gate input is absent: $required"
    }
}

if ($ValidateOnly) {
    $validationOutput = [string[]]@(& $executable validate 2>&1 | ForEach-Object { [string]$_ })
    if ([int]$LASTEXITCODE -ne 0) { throw "Rust ETW ABI validation failed." }
    $validation = ($validationOutput -join [Environment]::NewLine) |
        ConvertFrom-Json -ErrorAction Stop
    if ($validation.status -cne "PASS" -or
        $validation.match_any_keyword -cne "0x0000000000000030" -or
        $validation.raw_packet_payload_capture -ne $false) {
        throw "Rust ETW validation policy drifted."
    }
    $manifestLines = [string[]]@(
        & (Join-Path $env:SystemRoot "System32\wevtutil.exe") gp Microsoft-Windows-Kernel-Network /ge:true /gm:true /f:xml 2>&1 |
            ForEach-Object { [string]$_ }
    )
    if ([int]$LASTEXITCODE -ne 0) { throw "Installed Kernel-Network provider manifest is unavailable." }
    $manifestText = $manifestLines -join "`n"
    if ($manifestText -cnotmatch 'guid="7dd42a49-5329-4832-8dfd-43d979153a88"') {
        throw "Installed Kernel-Network provider GUID drifted."
    }
    foreach ($eventId in [uint16[]](12, 13, 14, 15, 16, 17, 28, 29, 30, 31, 32)) {
        if ($manifestText -cnotmatch ('<event value="' + $eventId + '"')) {
            throw "Installed Kernel-Network event inventory is missing event $eventId."
        }
    }
    $manifestBytes = [Text.Encoding]::UTF8.GetBytes($manifestText)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $manifestSha256 = ([BitConverter]::ToString($sha.ComputeHash($manifestBytes))).Replace("-", "").ToLowerInvariant() }
    finally { $sha.Dispose() }
    [ordered]@{
        schema = "KernelNetworkTraceFaultSmokePreflightV1"
        status = "PASS"
        controller_executable = $executable
        controller_sha256 = Get-RawQualificationSha256File -Path $executable
        controller_validation = $validation
        provider_manifest_utf8_sha256 = $manifestSha256
        tracerpt_executable = $tracerpt
        python_executable = $python
    } | ConvertTo-Json -Depth 8
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "The filtered ETW fault smoke requires an Administrator PowerShell."
}

$base = Join-Path $repo "artifacts\kernel-network-etw-fault-smoke"
$null = New-Item -ItemType Directory -Path $base -Force -ErrorAction Stop
$runId = "etw-fault-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$runRoot = Join-Path $base $runId
$null = New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop
trap {
    $failurePath = Join-Path $runRoot "wrapper-failure.json"
    if (-not (Test-Path -LiteralPath $failurePath)) {
        $failure = [ordered]@{
            schema = "KernelNetworkTraceWrapperFailureV1"
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
        catch { [Console]::Error.WriteLine("Could not persist filtered ETW wrapper failure: " + $_.Exception.Message) }
    }
    [Console]::Error.WriteLine([string]$_.Exception.Message)
    exit 1
}
$sessionName = "BinanceKernelNetwork_" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$etlPath = Join-Path $runRoot "kernel-network.etl"
$stopPath = Join-Path $runRoot "stop.request"
$stdoutPath = Join-Path $runRoot "controller.stdout.jsonl"
$stderrPath = Join-Path $runRoot "controller.stderr.txt"
$decodedPath = Join-Path $runRoot "kernel-network.xml"

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)] [string] $Value)
    if ($Value.Contains('"')) { throw "Process argument contains an unsupported quote." }
    return '"' + $Value + '"'
}

$argumentList = @(
    (Quote-ProcessArgument -Value $sessionName),
    (Quote-ProcessArgument -Value $etlPath),
    (Quote-ProcessArgument -Value $stopPath),
    "64",
    "180"
)
$controller = $null
$innerOutput = @()
$innerEvidenceRoot = $null
$innerReportPath = $null
$innerReport = $null
$ready = $false
$emergencyCleanupRequired = $false
$emergencyCleanupOutput = @()
$emergencyCleanupExitCode = $null
$injectedControllerAbort = $false
$injectedTerminationExitCode = [uint32]0xE701
$injectedObservedExitCode = $null
$startedUtc = [DateTimeOffset]::UtcNow
try {
    $controller = Start-Process `
        -FilePath $executable `
        -ArgumentList $argumentList `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -PassThru `
        -WindowStyle Hidden

    $readyDeadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
    while ([DateTimeOffset]::UtcNow -lt $readyDeadline) {
        if ($controller.HasExited) { break }
        if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
            $readyLine = Get-Content -LiteralPath $stdoutPath -ErrorAction Stop |
                Where-Object { $_ -match '"status":"READY"' } |
                Select-Object -First 1
            if ($null -ne $readyLine) {
                $readyRecord = $readyLine | ConvertFrom-Json -ErrorAction Stop
                if ($readyRecord.session_name -cne $sessionName -or
                    [IO.Path]::GetFullPath([string]$readyRecord.etl_path) -cne [IO.Path]::GetFullPath($etlPath)) {
                    throw "Filtered ETW READY identity disagrees with the launched process."
                }
                $ready = $true
                break
            }
        }
        Start-Sleep -Milliseconds 100
        $controller.Refresh()
    }
    if (-not $ready) {
        throw "Filtered ETW controller did not publish exact READY evidence."
    }

    if ($InjectControllerAbortAfterReady) {
        $injectedControllerAbort = $true
        $controller.Refresh()
        if ($controller.HasExited) {
            throw "Filtered ETW controller exited before the intentional abort was injected."
        }
        $controllerHandle = [IntPtr]$controller.Handle
        [RawQualificationNative]::TerminateProcessHandle($controllerHandle, $injectedTerminationExitCode)
        if (-not [RawQualificationNative]::WaitForProcessExit($controllerHandle, 10000)) {
            throw "Filtered ETW controller ignored the bounded intentional TerminateProcess request."
        }
        $injectedObservedExitCode = [uint32][RawQualificationNative]::GetProcessExitCode($controllerHandle)
        $controller.WaitForExit()
    }
    else {
        $innerBase = Join-Path $repo "artifacts\network-trace-fault-smoke"
        $innerBefore = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        if (Test-Path -LiteralPath $innerBase -PathType Container) {
            Get-ChildItem -LiteralPath $innerBase -Directory -ErrorAction Stop | ForEach-Object {
                $null = $innerBefore.Add([IO.Path]::GetFullPath($_.FullName))
            }
        }
        $innerOutput = [object[]]@(& $faultSmoke -WinsockAfdProfile ErrorOnly 2>&1)
        $innerOutput | ForEach-Object { $_ | Out-Host }
        $innerAfter = [string[]]@(
            Get-ChildItem -LiteralPath $innerBase -Directory -ErrorAction Stop |
                ForEach-Object { [IO.Path]::GetFullPath($_.FullName) } |
                Where-Object { -not $innerBefore.Contains($_) }
        )
        if ($innerAfter.Count -ne 1) {
            throw "The deterministic transport fault gate did not create exactly one owned evidence directory."
        }
        $innerEvidenceRoot = $innerAfter[0]
        $innerReportPath = Join-Path $innerEvidenceRoot "analysis\fault-smoke.json"
        if (-not (Test-Path -LiteralPath $innerReportPath -PathType Leaf)) {
            throw "The deterministic transport fault report is absent."
        }
        $innerReport = Get-Content -LiteralPath $innerReportPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ($innerReport.status -cne "PASS") {
            throw "The deterministic transport fault report is not PASS."
        }
    }
}
finally {
    if ($null -ne $controller -and -not $controller.HasExited) {
        if (-not (Test-Path -LiteralPath $stopPath)) {
            $null = New-Item -ItemType File -Path $stopPath -ErrorAction Stop
        }
        if (-not $controller.WaitForExit(30000)) {
            $emergencyCleanupRequired = $true
        }
    }
    $cleanupQuery = [string[]]@(
        & (Join-Path $env:SystemRoot "System32\logman.exe") query -ets $sessionName 2>&1 |
            ForEach-Object { [string]$_ }
    )
    $cleanupQueryExitCode = [int]$LASTEXITCODE
    if ($cleanupQueryExitCode -eq 0) {
        $emergencyCleanupRequired = $true
        $emergencyCleanupOutput = [string[]]@(
            & (Join-Path $env:SystemRoot "System32\logman.exe") stop -ets $sessionName 2>&1 |
                ForEach-Object { [string]$_ }
        )
        $emergencyCleanupExitCode = [int]$LASTEXITCODE
    }
    if ($null -ne $controller -and -not $controller.HasExited) {
        if (-not $controller.WaitForExit(10000)) {
            Stop-Process -Id $controller.Id -Force -ErrorAction Stop
            $controller.WaitForExit()
        }
    }
}

$postCleanupQuery = [string[]]@(
    & (Join-Path $env:SystemRoot "System32\logman.exe") query -ets $sessionName 2>&1 |
        ForEach-Object { [string]$_ }
)
$postCleanupQueryExitCode = [int]$LASTEXITCODE
if ($injectedControllerAbort) {
    $controller.Refresh()
    $abortControllerHasExited = [bool]$controller.HasExited
    $abortControllerExitCode = if ($abortControllerHasExited) { [int]$controller.ExitCode } else { $null }
    $abortStdoutBytes = [uint64](Get-Item -LiteralPath $stdoutPath -ErrorAction Stop).Length
    $abortStderrBytes = [uint64](Get-Item -LiteralPath $stderrPath -ErrorAction Stop).Length
    $abortEtlBytes = [uint64](Get-Item -LiteralPath $etlPath -ErrorAction Stop).Length
    $orphanObserved = $cleanupQueryExitCode -eq 0
    $cleanupSucceeded = (-not $orphanObserved) -or $emergencyCleanupExitCode -eq 0
    $absenceProved = $postCleanupQueryExitCode -ne 0
    $abortEvidence = [ordered]@{
        schema = "KernelNetworkTraceAbortCleanupV1"
        status = if ($abortControllerHasExited -and $injectedObservedExitCode -eq $injectedTerminationExitCode -and $cleanupSucceeded -and $absenceProved) { "PASS" } else { "FAILED" }
        trigger = "INJECTED_CONTROLLER_ABORT_AFTER_READY"
        outcome = if (-not $orphanObserved) { "ALREADY_ABSENT_AFTER_ABORT" } elseif ($cleanupSucceeded -and $absenceProved) { "STOPPED_BY_WRAPPER" } else { "CLEANUP_FAILED" }
        session_name = $sessionName
        controller_pid = [uint32]$controller.Id
        controller_has_exited = $abortControllerHasExited
        controller_exit_code = $abortControllerExitCode
        termination_requested_exit_code = [uint32]$injectedTerminationExitCode
        termination_observed_exit_code = [uint32]$injectedObservedExitCode
        controller_stdout_file = [IO.Path]::GetFileName($stdoutPath)
        controller_stdout_bytes = $abortStdoutBytes
        controller_stdout_sha256 = Get-RawQualificationSha256File -Path $stdoutPath
        controller_stderr_file = [IO.Path]::GetFileName($stderrPath)
        controller_stderr_bytes = $abortStderrBytes
        controller_stderr_sha256 = Get-RawQualificationSha256File -Path $stderrPath
        etl_file = [IO.Path]::GetFileName($etlPath)
        etl_bytes = $abortEtlBytes
        etl_sha256 = Get-RawQualificationSha256File -Path $etlPath
        orphan_observed_before_cleanup = $orphanObserved
        cleanup_attempted = $orphanObserved
        cleanup_exit_code = $emergencyCleanupExitCode
        cleanup_output = $emergencyCleanupOutput
        post_cleanup_query_exit_code = $postCleanupQueryExitCode
        post_cleanup_query_output = $postCleanupQuery
    }
    $null = Write-RawQualificationDurableNewJson -Path (Join-Path $runRoot "abort-cleanup.json") -Value $abortEvidence
    throw "Injected controller abort cleanup qualification completed; normal PASS is forbidden."
}
if ($postCleanupQueryExitCode -eq 0) {
    throw "Filtered ETW session remained orphaned after bounded emergency cleanup."
}
if ($emergencyCleanupRequired) {
    $cleanupRoot = Join-Path $runRoot "emergency-cleanup.json"
    $controller.Refresh()
    $cleanupControllerHasExited = [bool]$controller.HasExited
    $cleanupControllerExitCode = if ($cleanupControllerHasExited) { [int]$controller.ExitCode } else { $null }
    $cleanupStdoutBytes = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
        [uint64](Get-Item -LiteralPath $stdoutPath -ErrorAction Stop).Length
    } else { [uint64]0 }
    $cleanupStderrBytes = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
        [uint64](Get-Item -LiteralPath $stderrPath -ErrorAction Stop).Length
    } else { [uint64]0 }
    $cleanupEtlBytes = if (Test-Path -LiteralPath $etlPath -PathType Leaf) {
        [uint64](Get-Item -LiteralPath $etlPath -ErrorAction Stop).Length
    } else { [uint64]0 }
    $cleanupEvidence = [ordered]@{
        schema = "KernelNetworkTraceEmergencyCleanupV1"
        status = if ($emergencyCleanupExitCode -eq 0) { "STOPPED" } else { "FAILED" }
        trigger = "UNEXPECTED_CONTROLLER_OR_SESSION_FAILURE"
        session_name = $sessionName
        controller_pid = [uint32]$controller.Id
        controller_has_exited = $cleanupControllerHasExited
        controller_exit_code = $cleanupControllerExitCode
        controller_stdout_file = [IO.Path]::GetFileName($stdoutPath)
        controller_stdout_bytes = $cleanupStdoutBytes
        controller_stdout_sha256 = if ($cleanupStdoutBytes -gt 0) { Get-RawQualificationSha256File -Path $stdoutPath } else { $null }
        controller_stderr_file = [IO.Path]::GetFileName($stderrPath)
        controller_stderr_bytes = $cleanupStderrBytes
        controller_stderr_sha256 = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { Get-RawQualificationSha256File -Path $stderrPath } else { $null }
        etl_file = [IO.Path]::GetFileName($etlPath)
        etl_bytes = $cleanupEtlBytes
        etl_sha256 = if ($cleanupEtlBytes -gt 0) { Get-RawQualificationSha256File -Path $etlPath } else { $null }
        cleanup_exit_code = $emergencyCleanupExitCode
        cleanup_output = $emergencyCleanupOutput
        post_cleanup_query_exit_code = $postCleanupQueryExitCode
        post_cleanup_query_output = $postCleanupQuery
    }
    $null = Write-RawQualificationDurableNewJson -Path $cleanupRoot -Value $cleanupEvidence
    throw "Filtered ETW required emergency cleanup; no PASS is allowed."
}

$controller.Refresh()
$controllerHasExited = [bool]$controller.HasExited
$controllerExitCode = if ($controllerHasExited) { [int]$controller.ExitCode } else { $null }
if (-not $controllerHasExited -or $controllerExitCode -ne 0) {
    throw "Filtered ETW controller exited unsuccessfully: has_exited=$controllerHasExited exit_code=$controllerExitCode."
}
$stderrBytes = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
    [uint64](Get-Item -LiteralPath $stderrPath -ErrorAction Stop).Length
} else { [uint64]0 }
if ($stderrBytes -ne 0) { throw "Filtered ETW controller wrote unexpected stderr." }

$records = [object[]]@(Get-Content -LiteralPath $stdoutPath -ErrorAction Stop | ForEach-Object {
    $_ | ConvertFrom-Json -ErrorAction Stop
})
if ($records.Count -ne 2 -or
    $records[0].schema -cne "KernelNetworkTraceReadyV1" -or
    $records[1].schema -cne "KernelNetworkTraceSealV1" -or
    $records[1].status -cne "SEALED") {
    throw "Filtered ETW controller stdout is not the exact READY/SEALED sequence."
}
$statistics = $records[1].statistics
if ([uint32]$statistics.events_lost -ne 0 -or
    [uint32]$statistics.log_buffers_lost -ne 0 -or
    [uint32]$statistics.realtime_buffers_lost -ne 0) {
    throw "Filtered ETW reported event or buffer loss."
}
if (-not (Test-Path -LiteralPath $etlPath -PathType Leaf)) {
    throw "Filtered ETW did not publish its ETL."
}
$etlItem = Get-Item -LiteralPath $etlPath -ErrorAction Stop
if ([uint64]$etlItem.Length -eq 0 -or [uint64]$etlItem.Length -gt 64MB) {
    throw "Filtered ETW output is empty or exceeds its bound."
}

$decodeOutput = [string[]]@(& $tracerpt $etlPath -o $decodedPath -of XML -lr -y 2>&1 | ForEach-Object { [string]$_ })
$decodeExitCode = [int]$LASTEXITCODE
if ($decodeExitCode -ne 0 -or -not (Test-Path -LiteralPath $decodedPath -PathType Leaf)) {
    throw "tracerpt could not decode the filtered ETW artifact."
}
$decodedItem = Get-Item -LiteralPath $decodedPath -ErrorAction Stop
if ([uint64]$decodedItem.Length -eq 0 -or [uint64]$decodedItem.Length -gt 32MB) {
    throw "Decoded filtered ETW output is empty or exceeds its bound."
}

$queryOutput = $postCleanupQuery
$queryExitCode = $postCleanupQueryExitCode
if ($queryExitCode -eq 0) { throw "Filtered ETW session remained orphaned after seal." }

$report = [ordered]@{
    schema = "KernelNetworkTraceFaultSmokeV1"
    run_id = $runId
    status = "PASS"
    started_utc = $startedUtc.ToString("o")
    completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
    controller_executable = $executable
    controller_sha256 = Get-RawQualificationSha256File -Path $executable
    session_name = $sessionName
    controller_records = $records
    controller_stderr_bytes = $stderrBytes
    etl_file = "kernel-network.etl"
    etl_bytes = [uint64]$etlItem.Length
    etl_sha256 = Get-RawQualificationSha256File -Path $etlPath
    decoded_file = "kernel-network.xml"
    decoded_bytes = [uint64]$decodedItem.Length
    decoded_sha256 = Get-RawQualificationSha256File -Path $decodedPath
    tracerpt_exit_code = $decodeExitCode
    tracerpt_output = $decodeOutput
    orphan_query_exit_code = $queryExitCode
    orphan_query_output = $queryOutput
    deterministic_fault_evidence_root = $innerEvidenceRoot
    deterministic_fault_report = $innerReportPath
    deterministic_fault_report_sha256 = Get-RawQualificationSha256File -Path $innerReportPath
    deterministic_faults = $innerReport.faults
    selected_event_ids = [uint16[]](12, 13, 14, 15, 16, 17, 28, 29, 30, 31, 32)
    raw_packet_payload_capture = $false
    correlation_status = "OPEN_PENDING_SEMANTIC_DECODE"
}
$reportPath = Join-Path $runRoot "fault-smoke.json"
$null = Write-RawQualificationDurableNewJson -Path $reportPath -Value $report
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $repo "src"
    $verificationOutput = [string[]]@(
        & $python -m binance_lob.kernel_network_etw_verify_cli $runRoot 2>&1 |
            ForEach-Object { [string]$_ }
    )
    $verificationExitCode = [int]$LASTEXITCODE
}
finally { $env:PYTHONPATH = $previousPythonPath }
$verificationOutput | ForEach-Object { $_ | Out-Host }
if ($verificationExitCode -ne 0) {
    throw "Independent filtered ETW verification failed; exact evidence is preserved."
}
$report | ConvertTo-Json -Depth 12
Write-Output $runRoot
