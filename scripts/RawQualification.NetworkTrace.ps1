[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Validate", "Start", "Status", "Stop")]
    [string] $Action,

    [Parameter(Mandatory = $true)]
    [string] $EvidenceRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z-]{0,127}$')]
    [string] $RunId,

    [ValidateRange(64, 2048)]
    [uint32] $MaximumFileMiB = 512,

    [ValidateSet("ErrorOnly", "DiagnosticInfo")]
    [string] $WinsockAfdProfile = "ErrorOnly"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")

function Assert-NetworkTraceAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Raw qualification network tracing requires an elevated administrator process."
    }
}

function Invoke-NetworkTracePktMon {
    param(
        [Parameter(Mandatory = $true)] [string] $Executable,
        [Parameter(Mandatory = $true)] [string[]] $Arguments
    )
    $lines = @(& $Executable @Arguments 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = [int]$LASTEXITCODE
    $outputBytes = [Text.UTF8Encoding]::new($false).GetByteCount([string]::Join("`n", $lines))
    if ($lines.Count -gt 4096 -or $outputBytes -gt 1MB) {
        throw "PktMon control output exceeded its bounded allowance."
    }
    return [pscustomobject][ordered]@{
        exit_code = $exitCode
        output = [string[]]$lines
        output_bytes = [uint64]$outputBytes
    }
}

function Write-NetworkTraceEvidence {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] $Value
    )
    return Write-RawQualificationDurableNewJson -Path $Path -Value $Value
}

if ($env:OS -cne "Windows_NT") {
    throw "Raw qualification network tracing is Windows-only."
}
if ($Action -cne "Validate") { Assert-NetworkTraceAdministrator }

$resolvedRoot = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\')
$parent = [IO.Path]::GetDirectoryName($resolvedRoot)
if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw "Network trace evidence parent directory does not exist."
}
$null = Assert-RawQualificationNoReparsePointInExistingPath -Path $parent

$pktmon = Join-Path $env:SystemRoot "System32\pktmon.exe"
if (-not (Test-Path -LiteralPath $pktmon -PathType Leaf)) {
    throw "The official Windows pktmon.exe executable is unavailable."
}
$pktmonSha256 = Get-RawQualificationSha256File -Path $pktmon
$controlPath = Join-Path $resolvedRoot "network-trace-control.json"
$etlPath = Join-Path $resolvedRoot "network-trace.etl"
$eventProviders = [string[]]@(
    "Microsoft-Windows-TCPIP",
    "Microsoft-Windows-DNS-Client",
    "Microsoft-Windows-NDIS",
    "Microsoft-Windows-Winsock-AFD"
)
$winsockAfdKeywords = "0x800000000000000C"
$winsockAfdLevel = if ($WinsockAfdProfile -ceq "ErrorOnly") { 2 } else { 4 }
$kernelNetworkEnabled = ($WinsockAfdProfile -ceq "DiagnosticInfo")
$kernelNetworkKeywords = if ($kernelNetworkEnabled) { "0x8000000000000030" } else { "" }
$kernelNetworkLevel = if ($kernelNetworkEnabled) { 4 } else { 0 }
if ($kernelNetworkEnabled) {
    $eventProviders += "Microsoft-Windows-Kernel-Network"
}
$captureScope = if ($WinsockAfdProfile -ceq "ErrorOnly") {
    "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_ERROR_ETW"
} else {
    "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_AND_KERNEL_NETWORK_DIAGNOSTIC_ETW"
}

switch ($Action) {
    "Validate" {
        [ordered]@{
            schema = "RawQualificationNetworkTraceValidationV5"
            status = "PASS"
            run_id = $RunId
            evidence_root = $resolvedRoot
            administrator_required_for_collection = $true
            event_providers = $eventProviders
            winsock_afd_profile = $WinsockAfdProfile
            winsock_afd_keywords = $winsockAfdKeywords
            winsock_afd_level = [uint32]$winsockAfdLevel
            kernel_network_enabled = [bool]$kernelNetworkEnabled
            kernel_network_keywords = $kernelNetworkKeywords
            kernel_network_level = [uint32]$kernelNetworkLevel
            capture_scope = $captureScope
            raw_packet_payload_capture = $false
            log_mode = "CIRCULAR"
            maximum_file_mib = [uint32]$MaximumFileMiB
            pktmon_executable = $pktmon
            pktmon_executable_sha256 = $pktmonSha256
            script_sha256 = Get-RawQualificationSha256File -Path $PSCommandPath
            qpc_frequency = [uint64][Diagnostics.Stopwatch]::Frequency
        } | ConvertTo-Json -Depth 10
    }
    "Start" {
        if (Test-Path -LiteralPath $resolvedRoot) {
            throw "Network trace evidence root already exists; Start is create-only."
        }
        $null = New-Item -ItemType Directory -Path $resolvedRoot -ErrorAction Stop
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $resolvedRoot
        $arguments = [string[]]@(
            "start",
            "--capture", "--comp", "nics", "--type", "drop", "--flags", "0x00F",
            "--trace"
        )
        foreach ($provider in $eventProviders) {
            $arguments += [string[]]@("--provider", $provider)
            if ($provider -ceq "Microsoft-Windows-Winsock-AFD") {
                $arguments += [string[]]@("--keywords", $winsockAfdKeywords, "--level", ([string]$winsockAfdLevel))
            } elseif ($provider -ceq "Microsoft-Windows-Kernel-Network") {
                $arguments += [string[]]@("--keywords", $kernelNetworkKeywords, "--level", ([string]$kernelNetworkLevel))
            }
        }
        $arguments += [string[]]@(
            "--file-name", $etlPath,
            "--file-size", ([string]$MaximumFileMiB),
            "--log-mode", "circular"
        )
        $attempt = [ordered]@{
            schema = "RawQualificationNetworkTraceControlV5"
            run_id = $RunId
            status = "START_ATTEMPTED"
            requested_utc = [DateTimeOffset]::UtcNow.ToString("o")
            requested_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
            qpc_frequency = [uint64][Diagnostics.Stopwatch]::Frequency
            owner_pid = [uint32]$PID
            event_providers = $eventProviders
            winsock_afd_profile = $WinsockAfdProfile
            winsock_afd_keywords = $winsockAfdKeywords
            winsock_afd_level = [uint32]$winsockAfdLevel
            kernel_network_enabled = [bool]$kernelNetworkEnabled
            kernel_network_keywords = $kernelNetworkKeywords
            kernel_network_level = [uint32]$kernelNetworkLevel
            capture_scope = $captureScope
            raw_packet_flag = "DISABLED_FLAGS_0x00F"
            log_mode = "CIRCULAR"
            maximum_file_mib = [uint32]$MaximumFileMiB
            etl_file = "network-trace.etl"
            pktmon_executable = $pktmon
            pktmon_executable_sha256 = $pktmonSha256
            arguments = $arguments
        }
        $attemptSha256 = Write-NetworkTraceEvidence -Path $controlPath -Value $attempt
        $startedByThisInvocation = $false
        try {
            $result = Invoke-NetworkTracePktMon -Executable $pktmon -Arguments $arguments
            $startedByThisInvocation = ($result.exit_code -eq 0)
            $statusResult = if ($startedByThisInvocation) {
                Invoke-NetworkTracePktMon -Executable $pktmon -Arguments @("status")
            } else { $null }
            $ready = ($startedByThisInvocation -and $null -ne $statusResult -and $statusResult.exit_code -eq 0)
            $startResult = [ordered]@{
                schema = "RawQualificationNetworkTraceStartV5"
                run_id = $RunId
                status = if ($ready) { "STARTED" } else { "FAILED" }
                observed_utc = [DateTimeOffset]::UtcNow.ToString("o")
                observed_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
                control_file = "network-trace-control.json"
                control_sha256 = $attemptSha256
                pktmon_exit_code = [int]$result.exit_code
                pktmon_output = [string[]]$result.output
                pktmon_output_bytes = [uint64]$result.output_bytes
                status_exit_code = if ($null -ne $statusResult) { [int]$statusResult.exit_code } else { $null }
                status_output = if ($null -ne $statusResult) { [string[]]$statusResult.output } else { @() }
                status_output_bytes = if ($null -ne $statusResult) { [uint64]$statusResult.output_bytes } else { [uint64]0 }
            }
            $null = Write-NetworkTraceEvidence `
                -Path (Join-Path $resolvedRoot "network-trace-start.json") `
                -Value $startResult
            if (-not $ready) {
                throw "PktMon did not reach a confirmed running state; exact output is preserved in network-trace-start.json."
            }
            $startedByThisInvocation = $false
            $startResult | ConvertTo-Json -Depth 10
        }
        catch {
            $originalError = $_.Exception.Message
            $cleanup = $null
            if ($startedByThisInvocation) {
                try {
                    $cleanup = Invoke-NetworkTracePktMon -Executable $pktmon -Arguments @("stop")
                }
                catch {
                    $cleanup = [pscustomobject][ordered]@{
                        exit_code = -1
                        output = @($_.Exception.Message)
                        output_bytes = [uint64][Text.UTF8Encoding]::new($false).GetByteCount($_.Exception.Message)
                    }
                }
            }
            $failure = [ordered]@{
                schema = "RawQualificationNetworkTraceStartFailureV1"
                run_id = $RunId
                observed_utc = [DateTimeOffset]::UtcNow.ToString("o")
                error = $originalError
                cleanup_required = [bool]$startedByThisInvocation
                cleanup_exit_code = if ($null -ne $cleanup) { [int]$cleanup.exit_code } else { $null }
                cleanup_output = if ($null -ne $cleanup) { [string[]]$cleanup.output } else { @() }
                cleanup_output_bytes = if ($null -ne $cleanup) { [uint64]$cleanup.output_bytes } else { [uint64]0 }
            }
            try {
                $null = Write-NetworkTraceEvidence `
                    -Path (Join-Path $resolvedRoot "network-trace-start-failure.json") `
                    -Value $failure
            }
            catch {}
            if ($null -ne $cleanup -and $cleanup.exit_code -ne 0) {
                throw "$originalError PktMon cleanup also failed; exact bounded cleanup output was preserved when storage allowed."
            }
            throw $originalError
        }
    }
    "Status" {
        if (-not (Test-Path -LiteralPath $controlPath -PathType Leaf)) {
            throw "Network trace control evidence is absent."
        }
        $control = Get-Content -LiteralPath $controlPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $startPath = Join-Path $resolvedRoot "network-trace-start.json"
        if (-not (Test-Path -LiteralPath $startPath -PathType Leaf)) {
            throw "Network trace start evidence is absent."
        }
        $start = Get-Content -LiteralPath $startPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($control.schema -cne "RawQualificationNetworkTraceControlV5" -or
            $control.run_id -cne $RunId -or
            $control.pktmon_executable_sha256 -cne $pktmonSha256 -or
            @($control.event_providers).Count -ne $eventProviders.Count -or
            ([string]::Join("`n", @($control.event_providers))) -cne ([string]::Join("`n", $eventProviders)) -or
            $control.winsock_afd_profile -cne $WinsockAfdProfile -or
            $control.winsock_afd_keywords -cne $winsockAfdKeywords -or
            [int]$control.winsock_afd_level -ne $winsockAfdLevel -or
            [bool]$control.kernel_network_enabled -ne $kernelNetworkEnabled -or
            $control.kernel_network_keywords -cne $kernelNetworkKeywords -or
            [int]$control.kernel_network_level -ne $kernelNetworkLevel -or
            $control.capture_scope -cne $captureScope -or
            $start.schema -cne "RawQualificationNetworkTraceStartV5" -or
            $start.run_id -cne $RunId -or $start.status -cne "STARTED" -or
            [string]$start.control_sha256 -cne (Get-RawQualificationSha256File -Path $controlPath) -or
            [int]$start.pktmon_exit_code -ne 0 -or [int]$start.status_exit_code -ne 0) {
            throw "Network trace control identity or executable digest drifted."
        }
        $result = Invoke-NetworkTracePktMon -Executable $pktmon -Arguments @("status")
        [ordered]@{
            schema = "RawQualificationNetworkTraceStatusV5"
            run_id = $RunId
            observed_utc = [DateTimeOffset]::UtcNow.ToString("o")
            pktmon_exit_code = [int]$result.exit_code
            pktmon_output = [string[]]$result.output
            pktmon_output_bytes = [uint64]$result.output_bytes
            etl_exists = [bool](Test-Path -LiteralPath $etlPath -PathType Leaf)
            etl_bytes = if (Test-Path -LiteralPath $etlPath -PathType Leaf) {
                [uint64](Get-Item -LiteralPath $etlPath -ErrorAction Stop).Length
            } else { [uint64]0 }
        } | ConvertTo-Json -Depth 10
        if ($result.exit_code -ne 0) { exit $result.exit_code }
    }
    "Stop" {
        if (-not (Test-Path -LiteralPath $controlPath -PathType Leaf)) {
            throw "Network trace control evidence is absent; refusing to stop an unowned global session."
        }
        $controlBytes = [IO.File]::ReadAllBytes($controlPath)
        $control = [Text.UTF8Encoding]::new($false, $true).GetString($controlBytes) | ConvertFrom-Json
        $startPath = Join-Path $resolvedRoot "network-trace-start.json"
        if (-not (Test-Path -LiteralPath $startPath -PathType Leaf)) {
            throw "Network trace start evidence is absent."
        }
        $start = Get-Content -LiteralPath $startPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($control.schema -cne "RawQualificationNetworkTraceControlV5" -or
            $control.run_id -cne $RunId -or
            $control.status -cne "START_ATTEMPTED" -or
            $control.pktmon_executable_sha256 -cne $pktmonSha256 -or
            $control.etl_file -cne "network-trace.etl" -or
            @($control.event_providers).Count -ne $eventProviders.Count -or
            ([string]::Join("`n", @($control.event_providers))) -cne ([string]::Join("`n", $eventProviders)) -or
            $control.winsock_afd_profile -cne $WinsockAfdProfile -or
            $control.winsock_afd_keywords -cne $winsockAfdKeywords -or
            [int]$control.winsock_afd_level -ne $winsockAfdLevel -or
            [bool]$control.kernel_network_enabled -ne $kernelNetworkEnabled -or
            $control.kernel_network_keywords -cne $kernelNetworkKeywords -or
            [int]$control.kernel_network_level -ne $kernelNetworkLevel -or
            $control.capture_scope -cne $captureScope -or
            $start.schema -cne "RawQualificationNetworkTraceStartV5" -or
            $start.run_id -cne $RunId -or $start.status -cne "STARTED" -or
            [string]$start.control_sha256 -cne (Get-RawQualificationSha256File -Path $controlPath) -or
            [int]$start.pktmon_exit_code -ne 0 -or [int]$start.status_exit_code -ne 0) {
            throw "Network trace control identity or executable digest drifted."
        }
        $preStopStatus = Invoke-NetworkTracePktMon -Executable $pktmon -Arguments @("status")
        if ($preStopStatus.exit_code -ne 0) {
            throw "PktMon status failed before stop; refusing to stop an unconfirmed global session."
        }
        $result = Invoke-NetworkTracePktMon -Executable $pktmon -Arguments @("stop")
        if ($result.exit_code -ne 0) {
            $failure = [ordered]@{
                schema = "RawQualificationNetworkTraceStopFailureV1"
                run_id = $RunId
                observed_utc = [DateTimeOffset]::UtcNow.ToString("o")
                pktmon_exit_code = [int]$result.exit_code
                pktmon_output = [string[]]$result.output
                pktmon_output_bytes = [uint64]$result.output_bytes
            }
            $null = Write-NetworkTraceEvidence `
                -Path (Join-Path $resolvedRoot "network-trace-stop-failure.json") `
                -Value $failure
            throw "PktMon did not stop; the exact failure is preserved."
        }
        if (-not (Test-Path -LiteralPath $etlPath -PathType Leaf)) {
            throw "PktMon stopped without publishing its ETL evidence file."
        }
        $etl = Get-Item -LiteralPath $etlPath -ErrorAction Stop
        if ([uint64]$etl.Length -eq 0 -or [uint64]$etl.Length -gt ([uint64]$MaximumFileMiB * 1MB + 16MB)) {
            throw "PktMon ETL size is empty or exceeds its bounded circular allowance."
        }
        $seal = [ordered]@{
            schema = "RawQualificationNetworkTraceSealV5"
            run_id = $RunId
            status = "SEALED"
            stopped_utc = [DateTimeOffset]::UtcNow.ToString("o")
            control_file = "network-trace-control.json"
            control_sha256 = Get-RawQualificationSha256File -Path $controlPath
            start_file = "network-trace-start.json"
            start_sha256 = Get-RawQualificationSha256File -Path (Join-Path $resolvedRoot "network-trace-start.json")
            etl_file = "network-trace.etl"
            etl_bytes = [uint64]$etl.Length
            etl_sha256 = Get-RawQualificationSha256File -Path $etlPath
            pktmon_executable_sha256 = $pktmonSha256
            pktmon_exit_code = [int]$result.exit_code
            pktmon_output = [string[]]$result.output
            pktmon_output_bytes = [uint64]$result.output_bytes
            pre_stop_status_exit_code = [int]$preStopStatus.exit_code
            pre_stop_status_output = [string[]]$preStopStatus.output
            pre_stop_status_output_bytes = [uint64]$preStopStatus.output_bytes
            inference_boundary = "TCPIP/DNS/NDIS ETW, Winsock-AFD error ETW and NIC-drop metadata improve local attribution; they do not prove an unobserved upstream physical cause."
        }
        $null = Write-NetworkTraceEvidence `
            -Path (Join-Path $resolvedRoot "network-trace-seal.json") `
            -Value $seal
        $seal | ConvertTo-Json -Depth 10
    }
}
