[CmdletBinding()]
param(
    [string]$EvidenceRoot = "",
    [ValidateRange(300, 1800)]
    [int]$ConvergenceDeadlineSeconds = 900
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Utf8Json {
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] $Value
    )
    $json = $Value | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)] [string]$Executable,
        [Parameter(Mandatory = $true)] [string[]]$Arguments
    )
    $output = (& $Executable @Arguments 2>&1 | Out-String).Trim()
    return [pscustomobject][ordered]@{
        exit_code = [int]$LASTEXITCODE
        output = $output
    }
}

function Get-ClockObservation {
    param([Parameter(Mandatory = $true)] [string]$W32tm)
    $query = Invoke-NativeCapture -Executable $W32tm -Arguments @("/query", "/status", "/verbose")
    $text = [string]$query.output
    $leap = if ($text -match '(?m)^Leap Indicator:\s*(\d+)') { [int]$Matches[1] } else { $null }
    $stratum = if ($text -match '(?m)^Stratum:\s*(\d+)') { [int]$Matches[1] } else { $null }
    $source = if ($text -match '(?m)^Source:\s*(.+?)\s*$') { $Matches[1].Trim() } else { $null }
    $stateMachine = if ($text -match '(?m)^State Machine:\s*(\d+)') { [int]$Matches[1] } else { $null }
    $lastSyncError = if ($text -match '(?m)^Last Sync Error:\s*(\d+)') { [int]$Matches[1] } else { $null }
    $phaseOffset = if ($text -match '(?m)^Phase Offset:\s*([-+0-9.eE]+)s') {
        [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
    }
    else { $null }
    $pollSeconds = if ($text -match '(?m)^Poll Interval:\s*\d+\s*\((\d+)s\)') { [uint64]$Matches[1] } else { $null }
    $localSource = $null -eq $source -or $source -match '(?i)Local CMOS|Free-running|VM IC Time Synchronization|unspecified'
    $healthy = $query.exit_code -eq 0 -and
        $leap -eq 0 -and
        $stratum -ge 1 -and $stratum -le 15 -and
        -not $localSource -and
        $stateMachine -eq 2 -and
        $lastSyncError -eq 0
    return [pscustomobject][ordered]@{
        observed_utc = [DateTime]::UtcNow.ToString("o")
        healthy = [bool]$healthy
        leap_indicator = $leap
        stratum = $stratum
        source = $source
        state_machine = $stateMachine
        last_sync_error = $lastSyncError
        phase_offset_s = $phaseOffset
        poll_interval_s = $pollSeconds
        query_exit_code = [int]$query.exit_code
        raw_status = $text
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must run in an elevated PowerShell process."
}

$scriptPath = $MyInvocation.MyCommand.Path
$repo = (Resolve-Path -LiteralPath (Join-Path (Split-Path -Parent $scriptPath) "..")).Path
if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    $EvidenceRoot = Join-Path $repo "artifacts\clock-repair"
}
$EvidenceRoot = [IO.Path]::GetFullPath($EvidenceRoot)
$runId = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ") + "-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$evidence = Join-Path $EvidenceRoot $runId
$null = New-Item -ItemType Directory -Path $evidence -Force
$progressPath = Join-Path $evidence "observations.jsonl"
$resultPath = Join-Path $evidence "result.json"

$w32tm = Join-Path $env:SystemRoot "System32\w32tm.exe"
$regExe = Join-Path $env:SystemRoot "System32\reg.exe"
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time"
if ($computer.PartOfDomain) {
    throw "Refusing to overwrite domain-managed time configuration."
}
if (Test-Path -LiteralPath $policyPath) {
    throw "Refusing to overwrite W32Time policy-managed configuration at $policyPath."
}

$configPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config"
$ntpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient"
$parametersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
$beforeConfig = Get-ItemProperty -LiteralPath $configPath
$beforeNtp = Get-ItemProperty -LiteralPath $ntpPath
$beforeParameters = Get-ItemProperty -LiteralPath $parametersPath
$beforeStatus = Get-ClockObservation -W32tm $w32tm
$beforePeers = Invoke-NativeCapture -Executable $w32tm -Arguments @("/query", "/peers", "/verbose")
$backupPath = Join-Path $evidence "W32Time-before.reg"
$backup = Invoke-NativeCapture -Executable $regExe -Arguments @(
    "export",
    "HKLM\SYSTEM\CurrentControlSet\Services\W32Time",
    $backupPath,
    "/y"
)
if ($backup.exit_code -ne 0 -or -not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
    throw "W32Time registry backup failed: $($backup.output)"
}

$before = [pscustomobject][ordered]@{
    schema = "W32TimeRepairBeforeV1"
    run_id = $runId
    captured_utc = [DateTime]::UtcNow.ToString("o")
    computer = $env:COMPUTERNAME
    identity = $identity.Name
    part_of_domain = [bool]$computer.PartOfDomain
    policy_path_present = [bool](Test-Path -LiteralPath $policyPath)
    parameters = [ordered]@{
        type = [string]$beforeParameters.Type
        ntp_server = [string]$beforeParameters.NtpServer
    }
    config = [ordered]@{
        min_poll_interval = [int]$beforeConfig.MinPollInterval
        max_poll_interval = [int]$beforeConfig.MaxPollInterval
        update_interval = [int]$beforeConfig.UpdateInterval
        frequency_correct_rate = [int]$beforeConfig.FrequencyCorrectRate
        hold_period = [int]$beforeConfig.HoldPeriod
        phase_correct_rate = [int]$beforeConfig.PhaseCorrectRate
        max_allowed_phase_offset = [int]$beforeConfig.MaxAllowedPhaseOffset
    }
    ntp_client = [ordered]@{
        enabled = [int]$beforeNtp.Enabled
        special_poll_interval = [int]$beforeNtp.SpecialPollInterval
    }
    status = $beforeStatus
    peers_exit_code = [int]$beforePeers.exit_code
    peers = [string]$beforePeers.output
    registry_backup = $backupPath
    microsoft_profile = "https://learn.microsoft.com/windows-server/networking/windows-time-service/configuring-systems-for-high-accuracy"
}
Write-Utf8Json -Path (Join-Path $evidence "before.json") -Value $before

# Microsoft high-accuracy profile: fixed 64-second automatic poll cadence,
# faster clock-frequency correction, and the already-recommended update interval.
# HoldPeriod, phase limits, peers, provider flags and time source remain untouched.
Set-ItemProperty -LiteralPath $configPath -Name MinPollInterval -Type DWord -Value 6
Set-ItemProperty -LiteralPath $configPath -Name MaxPollInterval -Type DWord -Value 6
Set-ItemProperty -LiteralPath $configPath -Name UpdateInterval -Type DWord -Value 100
Set-ItemProperty -LiteralPath $configPath -Name FrequencyCorrectRate -Type DWord -Value 2

$apply = Invoke-NativeCapture -Executable $w32tm -Arguments @("/config", "/update")
if ($apply.exit_code -ne 0) { throw "w32tm /config /update failed: $($apply.output)" }
Restart-Service -Name W32Time -Force
$resync = Invoke-NativeCapture -Executable $w32tm -Arguments @("/resync", "/rediscover")
if ($resync.exit_code -ne 0) { throw "w32tm /resync /rediscover failed: $($resync.output)" }

$afterConfig = Get-ItemProperty -LiteralPath $configPath
$afterParameters = Get-ItemProperty -LiteralPath $parametersPath
if ([int]$afterConfig.MinPollInterval -ne 6 -or
    [int]$afterConfig.MaxPollInterval -ne 6 -or
    [int]$afterConfig.UpdateInterval -ne 100 -or
    [int]$afterConfig.FrequencyCorrectRate -ne 2) {
    throw "The effective high-accuracy registry values do not match the requested profile."
}
if ([int]$afterConfig.HoldPeriod -ne [int]$beforeConfig.HoldPeriod -or
    [int]$afterConfig.PhaseCorrectRate -ne [int]$beforeConfig.PhaseCorrectRate -or
    [int]$afterConfig.MaxAllowedPhaseOffset -ne [int]$beforeConfig.MaxAllowedPhaseOffset -or
    [string]$afterParameters.Type -ne [string]$beforeParameters.Type -or
    [string]$afterParameters.NtpServer -ne [string]$beforeParameters.NtpServer) {
    throw "A W32Time value outside the approved profile changed unexpectedly."
}

$deadline = [DateTime]::UtcNow.AddSeconds($ConvergenceDeadlineSeconds)
$consecutiveHealthy = 0
$observations = 0
$last = $null
while ([DateTime]::UtcNow -lt $deadline) {
    Start-Sleep -Seconds 15
    $last = Get-ClockObservation -W32tm $w32tm
    $observations += 1
    [IO.File]::AppendAllText(
        $progressPath,
        (($last | ConvertTo-Json -Compress -Depth 6) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
    if ($last.healthy) { $consecutiveHealthy += 1 } else { $consecutiveHealthy = 0 }
    if ($consecutiveHealthy -ge 3) { break }
}

$passed = $consecutiveHealthy -ge 3
$result = [pscustomobject][ordered]@{
    schema = "W32TimeRepairResultV1"
    status = if ($passed) { "PASS" } else { "FAIL" }
    run_id = $runId
    completed_utc = [DateTime]::UtcNow.ToString("o")
    evidence = $evidence
    applied_profile = [ordered]@{
        min_poll_interval = 6
        max_poll_interval = 6
        update_interval = 100
        frequency_correct_rate = 2
    }
    intentionally_unchanged = [ordered]@{
        hold_period = [int]$afterConfig.HoldPeriod
        phase_correct_rate = [int]$afterConfig.PhaseCorrectRate
        max_allowed_phase_offset = [int]$afterConfig.MaxAllowedPhaseOffset
        type = [string]$afterParameters.Type
        ntp_server = [string]$afterParameters.NtpServer
    }
    observations = $observations
    consecutive_healthy_observations = $consecutiveHealthy
    final_status = $last
    registry_backup = $backupPath
}
Write-Utf8Json -Path $resultPath -Value $result
Write-Output $resultPath
if (-not $passed) { exit 1 }

