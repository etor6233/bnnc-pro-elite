[CmdletBinding()]
param(
    [string] $OutputBase = "artifacts/fault-injection",
    [ValidateRange(5, 60)] [int] $DetectionDeadlineSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$campaignExe = Join-Path $repo "target\debug\live_overlap_campaign.exe"
if (-not (Test-Path -LiteralPath $campaignExe -PathType Leaf)) {
    throw "Missing debug campaign binary: $campaignExe"
}
$active = Get-Process -Name "live_overlap_campaign", "capture" -ErrorAction SilentlyContinue
if ($null -ne $active) {
    throw "A capture process is already active. Fault injection requires an isolated process tree."
}
if ([IO.Path]::IsPathRooted($OutputBase) -or $OutputBase -match '\s') {
    throw "OutputBase must be a relative path without spaces."
}

$runId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") + "-capture-kill"
$runRoot = Join-Path $repo (($OutputBase.TrimEnd("/", "\") + "/" + $runId).Replace("/", "\"))
New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop | Out-Null
$stdout = Join-Path $runRoot "campaign.stdout.log"
$stderr = Join-Path $runRoot "campaign.stderr.log"
$campaign = $null
$killedPid = $null
try {
    $campaign = Start-Process -FilePath $campaignExe `
        -ArgumentList @("BTCUSDT", 5, 120, 10, $runRoot) `
        -WorkingDirectory $repo -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr

    $discoveryDeadline = (Get-Date).ToUniversalTime().AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 100
        $children = @(Get-CimInstance Win32_Process | Where-Object {
            $_.ParentProcessId -eq $campaign.Id -and $_.Name -eq "capture.exe"
        })
    } while ($children.Count -lt 2 -and (Get-Date).ToUniversalTime() -lt $discoveryDeadline -and -not $campaign.HasExited)
    if ($children.Count -ne 2) {
        throw "Expected two capture children, found $($children.Count)."
    }

    $killedPid = [int]$children[0].ProcessId
    $faultAt = (Get-Date).ToUniversalTime()
    Stop-Process -Id $killedPid -Force -ErrorAction Stop
    if (-not $campaign.WaitForExit($DetectionDeadlineSeconds * 1000)) {
        throw "Coordinator remained alive beyond the $DetectionDeadlineSeconds-second detection deadline."
    }
    if ($campaign.ExitCode -eq 0) {
        throw "Coordinator incorrectly reported success after a capture kill."
    }
    $elapsedMs = [math]::Round(((Get-Date).ToUniversalTime() - $faultAt).TotalMilliseconds, 3)
    Start-Sleep -Milliseconds 250
    $survivors = @(Get-CimInstance Win32_Process | Where-Object {
        $_.ParentProcessId -eq $campaign.Id -and $_.Name -eq "capture.exe"
    })
    if ($survivors.Count -ne 0) {
        throw "Coordinator exited but left $($survivors.Count) capture child process(es)."
    }
    $report = [ordered]@{
        schema = "LiveFailurePropagationEvidenceV1"
        status = "PASS"
        fault = "FORCED_CAPTURE_PROCESS_TERMINATION"
        campaign_pid = $campaign.Id
        killed_capture_pid = $killedPid
        coordinator_exit_code = $campaign.ExitCode
        detection_ms = $elapsedMs
        detection_deadline_s = $DetectionDeadlineSeconds
        surviving_capture_children = 0
        credentials = "NONE"
        order_entry = "ABSENT"
    }
    $reportPath = Join-Path $runRoot "failure-propagation.json"
    $report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $reportPath -Encoding utf8
    Write-Host "PASS: $reportPath"
}
finally {
    if ($null -ne $campaign -and -not $campaign.HasExited) {
        & taskkill.exe /PID $campaign.Id /T /F | Out-Null
    }
}
