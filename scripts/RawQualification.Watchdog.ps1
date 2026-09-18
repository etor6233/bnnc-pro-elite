[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $HelperPath,
    [Parameter(Mandatory = $true)] [string] $JobName,
    [Parameter(Mandatory = $true)] [string] $RunId,
    [Parameter(Mandatory = $true)] [string] $GuardianPulsePath,
    [Parameter(Mandatory = $true)] [string] $ReadyPath,
    [Parameter(Mandatory = $true)] [string] $StopPath,
    [Parameter(Mandatory = $true)] [string] $FailurePath,
    [Parameter(Mandatory = $true)] [ValidateRange(1, [long]::MaxValue)] [long] $LaunchOriginQpcTimestamp,
    [Parameter(Mandatory = $true)] [ValidateRange(1, [long]::MaxValue)] [long] $MonotonicFrequency,
    [ValidateRange(1, 300)] [int] $StartupDeadlineSeconds = 90,
    [ValidateRange(1, 300)] [int] $MaximumGuardianPulseAgeSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. $HelperPath
Initialize-RawQualificationNative

function Stop-QualificationJob {
    param([Parameter(Mandatory = $true)] [string] $Reason)
    try {
        $null = Write-RawQualificationDurableNewJson -Path $FailurePath -Value ([ordered]@{
            schema = "RawQualificationWatchdogFailureV1"
            run_id = $RunId
            job_name = $JobName
            observed_utc = [DateTimeOffset]::UtcNow.ToString("o")
            reason = $Reason
        })
    }
    catch {}
    $job = [IntPtr]::Zero
    try {
        $job = [RawQualificationNative]::OpenExistingJobForTerminate($JobName)
        $null = [RawQualificationNative]::TerminateJobObject($job, 0xEE20)
    }
    finally {
        if ($job -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($job) }
    }
    exit 32
}

$pulseStream = $null
try {
    if ([long][Diagnostics.Stopwatch]::Frequency -ne $MonotonicFrequency) {
        Stop-QualificationJob -Reason "Watchdog monotonic frequency differs from the launcher contract."
    }
    $startupObservedQpc = [Diagnostics.Stopwatch]::GetTimestamp()
    if ($startupObservedQpc -lt $LaunchOriginQpcTimestamp -or
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks ([long]($startupObservedQpc - $LaunchOriginQpcTimestamp)) `
            -TimeoutSeconds ([uint64]$StartupDeadlineSeconds) `
            -Frequency $MonotonicFrequency)) {
        Stop-QualificationJob -Reason "Watchdog first execution exceeded the hard ${StartupDeadlineSeconds}-second startup deadline."
    }
    if (-not (Test-Path -LiteralPath $GuardianPulsePath -PathType Leaf)) {
        Stop-QualificationJob -Reason "Independent guardian pulse journal was absent before watchdog identity retention."
    }
    # FileShare.Delete is intentionally absent: the retained handle fences normal
    # rename/delete/replacement while permitting only the launcher's append writes.
    $pulseStream = [IO.FileStream]::new(
        $GuardianPulsePath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite)
    $lastObservedLength = [int64]$pulseStream.Length
    if ($lastObservedLength -le 0) {
        Stop-QualificationJob -Reason "Independent guardian pulse journal was empty at watchdog identity retention."
    }
    $null = $pulseStream.Seek($lastObservedLength - 1, [IO.SeekOrigin]::Begin)
    if ($pulseStream.ReadByte() -ne 10) {
        Stop-QualificationJob -Reason "Independent guardian pulse journal initial prefix was not newline complete."
    }
    $readyObservedQpc = [Diagnostics.Stopwatch]::GetTimestamp()
    if ($readyObservedQpc -lt $LaunchOriginQpcTimestamp -or
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks ([long]($readyObservedQpc - $LaunchOriginQpcTimestamp)) `
            -TimeoutSeconds ([uint64]$StartupDeadlineSeconds) `
            -Frequency $MonotonicFrequency)) {
        Stop-QualificationJob -Reason "Watchdog pulse identity retention exceeded the hard ${StartupDeadlineSeconds}-second startup deadline."
    }
    $null = Write-RawQualificationDurableNewJson -Path $ReadyPath -Value ([ordered]@{
        schema = "RawQualificationWatchdogReadyV1"
        run_id = $RunId
        job_name = $JobName
        pid = [uint32]$PID
        launch_origin_qpc_timestamp = [long]$LaunchOriginQpcTimestamp
        observed_qpc_timestamp = [long]$readyObservedQpc
        monotonic_frequency = [long]$MonotonicFrequency
        startup_deadline_s = [uint64]$StartupDeadlineSeconds
        pulse_length = [uint64]$lastObservedLength
    })
    $completeGrowthTimer = [Diagnostics.Stopwatch]::StartNew()

    while ($true) {
        # Deadline is evaluated before STOP and before observing/resetting any
        # new growth.  A late stop or pulse can never erase an already-open gap.
        if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $completeGrowthTimer.ElapsedTicks `
            -TimeoutSeconds ([uint64]$MaximumGuardianPulseAgeSeconds))) {
            Stop-QualificationJob -Reason "Independent guardian pulse exceeded the hard ${MaximumGuardianPulseAgeSeconds}-second monotonic deadline before the next observation."
        }
        if (Test-Path -LiteralPath $StopPath -PathType Leaf) {
            $stop = $null
            $stopRead = [Diagnostics.Stopwatch]::StartNew()
            while ($null -eq $stop) {
                if (-not (Test-RawQualificationDeadlineTicks `
                    -ElapsedTicks $stopRead.ElapsedTicks `
                    -TimeoutSeconds 5)) {
                    break
                }
                try {
                    $bytes = [IO.File]::ReadAllBytes($StopPath)
                    if ($bytes.Length -gt 0 -and $bytes[$bytes.Length - 1] -eq 10) {
                        $stop = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json -ErrorAction Stop
                    }
                }
                catch { $stop = $null }
                if ($null -eq $stop) { Start-Sleep -Milliseconds 100 }
            }
            if ($null -eq $stop -or
                -not (Test-RawQualificationDeadlineTicks `
                    -ElapsedTicks $stopRead.ElapsedTicks `
                    -TimeoutSeconds 5)) {
                Stop-QualificationJob -Reason "Watchdog stop contract remained partial or unreadable for five seconds."
            }
            if ($stop.schema -ne "RawQualificationWatchdogStopV1" -or
                $stop.run_id -ne $RunId -or
                $stop.job_name -ne $JobName) {
                Stop-QualificationJob -Reason "Watchdog stop contract is malformed or belongs to another run."
            }
            if (-not (Test-RawQualificationDeadlineTicks `
                -ElapsedTicks $completeGrowthTimer.ElapsedTicks `
                -TimeoutSeconds ([uint64]$MaximumGuardianPulseAgeSeconds))) {
                Stop-QualificationJob -Reason "Watchdog stop arrived only after the guardian pulse deadline was already open."
            }
            exit 0
        }
        if (-not (Test-Path -LiteralPath $GuardianPulsePath -PathType Leaf)) {
            Stop-QualificationJob -Reason "Independent guardian pulse path diverged from its retained file identity."
        }

        # Lengths are sampled handle/path/handle.  For the same append-only file,
        # the path length must lie inside this monotonic interval even if an append
        # races the samples.  A replacement or truncation is terminal.
        $handleLengthBefore = [int64]$pulseStream.Length
        $pathLength = [int64](Get-Item -LiteralPath $GuardianPulsePath -ErrorAction Stop).Length
        $currentLength = [int64]$pulseStream.Length
        if ($handleLengthBefore -lt $lastObservedLength -or
            $currentLength -lt $handleLengthBefore -or
            $pathLength -lt $handleLengthBefore -or
            $pathLength -gt $currentLength) {
            Stop-QualificationJob -Reason "Independent guardian pulse journal regressed, was truncated, or changed retained identity."
        }
        if ($currentLength -gt $lastObservedLength) {
            $lastObservedLength = $currentLength
            $null = $pulseStream.Seek($currentLength - 1, [IO.SeekOrigin]::Begin)
            if ($pulseStream.ReadByte() -eq 10) {
                if (-not (Test-RawQualificationDeadlineTicks `
                    -ElapsedTicks $completeGrowthTimer.ElapsedTicks `
                    -TimeoutSeconds ([uint64]$MaximumGuardianPulseAgeSeconds))) {
                    Stop-QualificationJob -Reason "Newline-complete guardian growth arrived only after the monotonic deadline was already open."
                }
                $completeGrowthTimer.Restart()
            }
        }
        if (-not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $completeGrowthTimer.ElapsedTicks `
            -TimeoutSeconds ([uint64]$MaximumGuardianPulseAgeSeconds))) {
            Stop-QualificationJob -Reason "Independent guardian pulse had no newline-complete byte growth within the hard ${MaximumGuardianPulseAgeSeconds}-second monotonic deadline."
        }
        Start-Sleep -Seconds 1
    }
}
catch {
    Stop-QualificationJob -Reason ("Independent guardian watchdog failed closed: " + $_.Exception.Message)
}
finally {
    if ($null -ne $pulseStream) { $pulseStream.Dispose() }
}
