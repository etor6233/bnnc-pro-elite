[CmdletBinding()]
param(
    [ValidateRange(1, 86390)] [int] $QualificationSeconds = 60,
    [ValidateRange(1, 300)] [int] $WarmupSeconds = 5,
    [ValidateRange(1, 300)] [int] $TailSeconds = 10,
    [string] $OutputBase = "artifacts/qualification",
    [ValidateRange(1, 10000)] [int] $MinimumFreeGiB = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressStartupGraceSeconds = 120
$ProgressDeadAfterSeconds = 90

function Assert-ClockSynchronized {
    $status = (& w32tm /query /status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or
        $status -match "Leap Indicator:\s+3" -or
        $status -match "Local CMOS Clock" -or
        $status -match "Stratum:\s+0") {
        throw "Windows Time lost synchronization during qualification."
    }
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
$cargo = if ($null -ne $cargoCommand) {
    $cargoCommand.Source
}
else {
    Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
}
if (-not (Test-Path -LiteralPath $cargo -PathType Leaf)) {
    throw "Rust cargo executable was not found."
}
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Missing project Python: $python"
}
if (($WarmupSeconds + $QualificationSeconds + $TailSeconds) -gt 86400 -or
    ($QualificationSeconds + $TailSeconds) -gt 86400) {
    throw "Each Binance WebSocket capture must remain within 86400 seconds."
}
if ([IO.Path]::IsPathRooted($OutputBase) -or $OutputBase -match '\s') {
    throw "OutputBase must be a relative path without spaces."
}

$active = Get-Process -Name "live_overlap_campaign", "capture" -ErrorAction SilentlyContinue
if ($null -ne $active) {
    throw "A capture process is already active. Refusing to overlap campaigns."
}
$driveName = [IO.Path]::GetPathRoot($repo).TrimEnd("\").TrimEnd(":")
$drive = Get-PSDrive -Name $driveName
$freeGiB = [math]::Floor($drive.Free / 1GB)
if ($freeGiB -lt $MinimumFreeGiB) {
    throw "Only $freeGiB GiB free; at least $MinimumFreeGiB GiB is required."
}
if (-not (Test-NetConnection data-stream.binance.vision -Port 443 -InformationLevel Quiet)) {
    throw "Cannot reach Binance public market-data port 443."
}

$longRun = (($WarmupSeconds + $QualificationSeconds + $TailSeconds) -ge 3600)
if ($longRun) {
    $sleepStatus = (& powercfg /QUERY SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 2>&1 | Out-String)
    if ($sleepStatus -notmatch "Current AC Power Setting Index:\s+0x00000000") {
        throw "Windows AC sleep is not disabled; a 24 h campaign would be interrupted."
    }
    Assert-ClockSynchronized
}

Push-Location $repo
try {
    & $cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt check failed" }
    & $cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed" }
    & $cargo test --workspace --all-targets
    if ($LASTEXITCODE -ne 0) { throw "Rust tests failed" }
    $oldPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = (Join-Path $repo "src")
        & $python -m unittest discover -s tests -q
        if ($LASTEXITCODE -ne 0) { throw "Python tests failed" }
    }
    finally {
        $env:PYTHONPATH = $oldPythonPath
    }
    & $cargo build --release --bin capture --bin live_overlap_campaign --bin durability_scan
    if ($LASTEXITCODE -ne 0) { throw "release build failed" }

    $campaignExe = Join-Path $repo "target\release\live_overlap_campaign.exe"
    $durabilityExe = Join-Path $repo "target\release\durability_scan.exe"
    $runId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") + "-dual"
    $runRoot = ($OutputBase.TrimEnd("/", "\") + "/" + $runId).Replace("\", "/")
    New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop | Out-Null
    $processes = @()
    foreach ($symbol in @("BTCUSDT", "ETHUSDT")) {
        $stdout = Join-Path $runRoot ($symbol.ToLowerInvariant() + ".stdout.log")
        $stderr = Join-Path $runRoot ($symbol.ToLowerInvariant() + ".stderr.log")
        $processes += Start-Process -FilePath $campaignExe `
            -ArgumentList @($symbol, $WarmupSeconds, $QualificationSeconds, $TailSeconds, $runRoot) `
            -WorkingDirectory $repo -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    }
    Write-Host "Started BTCUSDT and ETHUSDT. Evidence root: $runRoot"
    $startedAt = (Get-Date).ToUniversalTime()
    $progressByPath = @{}
    while (@($processes | Where-Object { -not $_.HasExited }).Count -gt 0) {
        Start-Sleep -Seconds 30
        foreach ($process in $processes) { $process.Refresh() }
        $failed = @($processes | Where-Object { $_.HasExited -and $_.ExitCode -ne 0 })
        if ($failed.Count -gt 0) {
            throw "Campaign PID $($failed[0].Id) failed with exit code $($failed[0].ExitCode)."
        }
        $running = @($processes | Where-Object { -not $_.HasExited }).Count
        $freeNow = [math]::Floor((Get-PSDrive -Name $driveName).Free / 1GB)
        if ($freeNow -lt $MinimumFreeGiB) {
            throw "Free space fell to $freeNow GiB; qualification minimum is $MinimumFreeGiB GiB."
        }
        if ($longRun) {
            Assert-ClockSynchronized
        }

        $now = (Get-Date).ToUniversalTime()
        $progressFiles = @(Get-ChildItem -LiteralPath $runRoot -Filter "*.bnack" -File -Recurse)
        if ($progressFiles.Count -lt 8 -and ($now - $startedAt).TotalSeconds -ge $ProgressStartupGraceSeconds) {
            throw "Only $($progressFiles.Count)/8 durability journals appeared before startup deadline."
        }
        foreach ($file in $progressFiles) {
            $key = $file.FullName
            if (-not $progressByPath.ContainsKey($key)) {
                $progressByPath[$key] = @{
                    Length = $file.Length
                    ChangedAt = $now
                }
                continue
            }
            $state = $progressByPath[$key]
            if ($file.Length -lt $state.Length) {
                throw "Durability journal regressed: $key"
            }
            if ($file.Length -gt $state.Length) {
                $state.Length = $file.Length
                $state.ChangedAt = $now
            }
            elseif (($now - $state.ChangedAt).TotalSeconds -ge $ProgressDeadAfterSeconds) {
                throw "Durability journal made no progress for $ProgressDeadAfterSeconds seconds: $key"
            }
        }
        Write-Host ("{0:u} running={1} progress_journals={2}/8 free_GiB={3}" -f (Get-Date), $running, $progressFiles.Count, $freeNow)
    }
    foreach ($process in $processes) {
        $process.WaitForExit()
        if ($null -ne $process.ExitCode -and $process.ExitCode -ne 0) {
            throw "Campaign PID $($process.Id) failed with exit code $($process.ExitCode)."
        }
    }
    & $python scripts/verify_live_qualification.py $runRoot `
        --durability-scan $durabilityExe `
        --output (Join-Path $runRoot "qualification-verification.json")
    if ($LASTEXITCODE -ne 0) { throw "dual qualification verification failed" }
    Write-Host "PASS: $runRoot/qualification-verification.json"
}
catch {
    if (Get-Variable processes -ErrorAction SilentlyContinue) {
        foreach ($process in $processes) {
            if (-not $process.HasExited) {
                & taskkill.exe /PID $process.Id /T /F | Out-Null
            }
        }
    }
    throw
}
finally {
    Pop-Location
}
