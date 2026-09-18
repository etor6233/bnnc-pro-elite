[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Selection,
    [Parameter(Mandatory = $true)] [string] $Output,
    [ValidateRange(3, 100)] [int] $Iterations = 5,
    [ValidateRange(1, 20)] [int] $WarmupIterations = 1,
    [ValidateSet("Idle", "BelowNormal", "Normal", "AboveNormal", "High")] [string] $PriorityClass = "BelowNormal",
    [string] $BackgroundActivity = "unspecified",
    [ValidateSet("Selection", "QualifiedReceipt", "QualifiedCache")] [string] $InputKind = "Selection",
    [string] $ReplayExecutable = "",
    [string] $ReplayAdditionalArgument = "",
    [ValidateSet("FULL_SOURCE_VERIFICATION_PLUS_NEUTRAL_REPLAY", "QUALIFIED_SOURCE_INTEGRITY_PLUS_NEUTRAL_REPLAY", "QUALIFIED_BINARY_CACHE_PLUS_NEUTRAL_REPLAY")]
    [string] $BenchmarkScope = "FULL_SOURCE_VERIFICATION_PLUS_NEUTRAL_REPLAY"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ExpectedScope = switch ($InputKind) {
    "Selection" { "FULL_SOURCE_VERIFICATION_PLUS_NEUTRAL_REPLAY" }
    "QualifiedReceipt" { "QUALIFIED_SOURCE_INTEGRITY_PLUS_NEUTRAL_REPLAY" }
    "QualifiedCache" { "QUALIFIED_BINARY_CACHE_PLUS_NEUTRAL_REPLAY" }
}
if ($BenchmarkScope -cne $ExpectedScope) {
    throw "InputKind and BenchmarkScope must describe the same replay authority path"
}

function Get-Sha256Bytes {
    param([Parameter(Mandatory = $true)] [byte[]] $Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-Distribution {
    param([Parameter(Mandatory = $true)] [double[]] $Samples)
    if ($Samples.Count -eq 0) {
        throw "distribution requires at least one sample"
    }
    $ordered = @($Samples | Sort-Object)
    function Select-NearestRank {
        param([double] $Quantile)
        $rank = [math]::Ceiling($ordered.Count * $Quantile)
        $index = [math]::Max(0, [math]::Min($ordered.Count - 1, $rank - 1))
        return [double]$ordered[$index]
    }
    return [ordered]@{
        count = $ordered.Count
        min = [double]$ordered[0]
        p50 = Select-NearestRank 0.50
        p95 = Select-NearestRank 0.95
        p99 = Select-NearestRank 0.99
        p99_9 = Select-NearestRank 0.999
        max = [double]$ordered[-1]
        mean = [double](($ordered | Measure-Object -Average).Average)
    }
}

function Invoke-ReplaySample {
    param(
        [Parameter(Mandatory = $true)] [string] $Executable,
        [Parameter(Mandatory = $true)] [string] $SelectionPath,
        [string] $AdditionalArgument = ""
    )
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.Arguments = '"' + $SelectionPath.Replace('"', '\"') + '"'
    if (-not [string]::IsNullOrWhiteSpace($AdditionalArgument)) {
        $startInfo.Arguments += ' "' + $AdditionalArgument.Replace('"', '\"') + '"'
    }
    $startInfo.WorkingDirectory = $Repo
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $clock = [Diagnostics.Stopwatch]::StartNew()
    if (-not $process.Start()) {
        throw "failed to start complete_replay"
    }
    $process.PriorityClass = [Diagnostics.ProcessPriorityClass]::$PriorityClass
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $peakWorkingSetBytes = [uint64]0
    while (-not $process.WaitForExit(50)) {
        $process.Refresh()
        $peakWorkingSetBytes = [math]::Max($peakWorkingSetBytes, [uint64]$process.WorkingSet64)
    }
    $clock.Stop()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0 -or $stderr.Length -ne 0) {
        throw "complete_replay failed: exit=$($process.ExitCode), stderr=$stderr"
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($stdout)
    $report = $stdout | ConvertFrom-Json
    if ($report.schema -cne "CompleteRunReplayReportV1" -or
        $report.usage -cne "COMPLETE_RUN_NEUTRAL_REPLAY" -or
        $report.qualification_claim -ne $false -or
        $report.source.run_status -cne "COMPLETE" -or
        $report.cross_stream_total_order_available -ne $false -or
        @($report.economic_features).Count -ne 0) {
        throw "complete_replay emitted a report outside the neutral COMPLETE contract"
    }
    return [pscustomobject][ordered]@{
        wall_time_ms = [double]$clock.Elapsed.TotalMilliseconds
        cpu_time_ms = [double]$process.TotalProcessorTime.TotalMilliseconds
        peak_working_set_bytes = $peakWorkingSetBytes
        stdout_bytes = [uint64]$bytes.Length
        stdout_sha256 = Get-Sha256Bytes -Bytes $bytes
        report_sha256 = [string]$report.report_sha256
        report = $report
    }
}

$Repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$SelectionPath = (Resolve-Path -LiteralPath $Selection).Path
$ExecutableCandidate = if ([string]::IsNullOrWhiteSpace($ReplayExecutable)) {
    Join-Path $Repo "target\release\complete_replay.exe"
}
else {
    $ReplayExecutable
}
$Executable = (Resolve-Path -LiteralPath $ExecutableCandidate).Path
$AdditionalArgumentPath = if ([string]::IsNullOrWhiteSpace($ReplayAdditionalArgument)) {
    ""
}
else {
    (Resolve-Path -LiteralPath $ReplayAdditionalArgument).Path
}
if ($InputKind -ceq "QualifiedCache" -and [string]::IsNullOrWhiteSpace($AdditionalArgumentPath)) {
    throw "QualifiedCache benchmark requires ReplayAdditionalArgument"
}
$RustBin = Join-Path $env:USERPROFILE ".cargo\bin"
$Rustc = (Resolve-Path -LiteralPath (Join-Path $RustBin "rustc.exe")).Path
$Cargo = (Resolve-Path -LiteralPath (Join-Path $RustBin "cargo.exe")).Path
$OutputPath = [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Output))
if (Test-Path -LiteralPath $OutputPath) {
    throw "benchmark output already exists: $OutputPath"
}
$selectionDocument = Get-Content -Raw -LiteralPath $SelectionPath | ConvertFrom-Json
$RunDirectoryValue = if ($InputKind -in @("QualifiedReceipt", "QualifiedCache")) {
    [string]$selectionDocument.selection.run_directory
}
else {
    [string]$selectionDocument.run_directory
}
$RunDirectory = (Resolve-Path -LiteralPath $RunDirectoryValue).Path
if ($OutputPath.StartsWith($RunDirectory + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "benchmark output must remain outside the immutable source run"
}

$warmups = @()
for ($index = 0; $index -lt $WarmupIterations; $index++) {
    $warmups += Invoke-ReplaySample -Executable $Executable -SelectionPath $SelectionPath -AdditionalArgument $AdditionalArgumentPath
}
$samples = @()
for ($index = 0; $index -lt $Iterations; $index++) {
    $samples += Invoke-ReplaySample -Executable $Executable -SelectionPath $SelectionPath -AdditionalArgument $AdditionalArgumentPath
}
$all = @($warmups) + @($samples)
$expectedReportSha256 = [string]$all[0].report_sha256
$expectedStdoutSha256 = [string]$all[0].stdout_sha256
foreach ($sample in $all) {
    if ($sample.report_sha256 -cne $expectedReportSha256 -or
        $sample.stdout_sha256 -cne $expectedStdoutSha256) {
        throw "replay output changed between benchmark invocations"
    }
}
$reference = $samples[0].report
$CampaignDirectory = (Resolve-Path -LiteralPath (Join-Path $RunDirectory ([string]$reference.source.campaign_id))).Path
if (-not $CampaignDirectory.StartsWith($RunDirectory + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "selected campaign directory escapes the immutable source run"
}
$selectedEvents = [uint64]$reference.depth.selected_market_records + [uint64]$reference.trades.selected_market_records
$sourceRawRecords = [uint64]$reference.depth.total_raw_records + [uint64]$reference.trades.total_raw_records
$wall = [double[]]@($samples | ForEach-Object { $_.wall_time_ms })
$cpu = [double[]]@($samples | ForEach-Object { $_.cpu_time_ms })
$rss = [double[]]@($samples | ForEach-Object { [double]$_.peak_working_set_bytes })
$goodput = [double[]]@($samples | ForEach-Object { $selectedEvents / ($_.wall_time_ms / 1000.0) })
$sourceRate = [double[]]@($samples | ForEach-Object { $sourceRawRecords / ($_.wall_time_ms / 1000.0) })

$cpuInventory = @(Get-CimInstance Win32_Processor | ForEach-Object {
    [ordered]@{
        device_id = [string]$_.DeviceID
        name = ([string]$_.Name).Trim()
        manufacturer = [string]$_.Manufacturer
        cores = [uint64]$_.NumberOfCores
        logical_processors = [uint64]$_.NumberOfLogicalProcessors
        max_clock_mhz = [uint64]$_.MaxClockSpeed
    }
})
$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem
$rawFiles = @(Get-ChildItem -LiteralPath $CampaignDirectory -Recurse -File -Filter "*.bnraw")
$rawBytes = [uint64](($rawFiles | Measure-Object -Property Length -Sum).Sum)
$sourceDrive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$([IO.Path]::GetPathRoot($RunDirectory).TrimEnd('\'))'"
$powerPlan = (& powercfg.exe /getactivescheme 2>&1 | Out-String).Trim()
$report = [ordered]@{
    schema = "CompleteReplayEndToEndBenchmarkV2"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    implementation = "rust-release-process-per-invocation"
    benchmark_scope = $BenchmarkScope
    correctness = "PASS"
    credentials = "NONE"
    order_entry = "ABSENT"
    artifact = [ordered]@{
        executable = $Executable
        executable_bytes = [uint64](Get-Item -LiteralPath $Executable).Length
        executable_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Executable).Hash.ToLowerInvariant()
        benchmark_script = $PSCommandPath
        benchmark_script_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
        selection = $SelectionPath
        selection_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $SelectionPath).Hash.ToLowerInvariant()
        input_kind = $InputKind
        additional_argument = $AdditionalArgumentPath
        source_run = $RunDirectory
        source_run_id = [string]$reference.source.run_id
        source_symbol = [string]$reference.source.symbol
        source_campaign_id = [string]$reference.source.campaign_id
        source_campaign_directory = $CampaignDirectory
        source_campaign_manifest_sha256 = [string]$reference.source.campaign_manifest_sha256
        replay_report_sha256 = $expectedReportSha256
        replay_stdout_sha256 = $expectedStdoutSha256
    }
    environment = [ordered]@{
        host = [Environment]::MachineName
        cpu = $cpuInventory
        physical_memory_bytes = [uint64]$computer.TotalPhysicalMemory
        os_caption = [string]$os.Caption
        os_version = [string]$os.Version
        os_build = [string]$os.BuildNumber
        os_architecture = [string]$os.OSArchitecture
        process_architecture = if ([Environment]::Is64BitProcess) { "x86_64" } else { "x86" }
        powershell = [string]$PSVersionTable.PSVersion
        rustc = (& $Rustc --version 2>&1 | Out-String).Trim()
        cargo = (& $Cargo --version 2>&1 | Out-String).Trim()
        background_activity = $BackgroundActivity
        process_priority_class = $PriorityClass
        affinity = "OS_DEFAULT"
        active_power_plan = $powerPlan
        source_volume = if ($null -eq $sourceDrive) { $null } else { [ordered]@{
            device_id = [string]$sourceDrive.DeviceID
            filesystem = [string]$sourceDrive.FileSystem
            size_bytes = [uint64]$sourceDrive.Size
            free_bytes_at_start = [uint64]$sourceDrive.FreeSpace
        } }
        page_cache = "UNCONTROLLED_WARM_AFTER_EXPLICIT_WARMUP"
    }
    workload = [ordered]@{
        generations = [uint64]$reference.source.generations
        handovers = [uint64]$reference.source.handovers
        source_raw_records = $sourceRawRecords
        selected_market_events = $selectedEvents
        source_bnraw_files = [uint64]$rawFiles.Count
        source_bnraw_bytes = $rawBytes
        warmup_iterations = $WarmupIterations
        measured_iterations = $Iterations
        concurrency = 1
    }
    distributions = [ordered]@{
        wall_time_ms = Get-Distribution -Samples $wall
        cpu_time_ms = Get-Distribution -Samples $cpu
        peak_working_set_bytes = Get-Distribution -Samples $rss
        selected_market_events_per_second = Get-Distribution -Samples $goodput
        source_raw_records_per_second_end_to_end = Get-Distribution -Samples $sourceRate
    }
    raw_samples = @($samples | ForEach-Object {
        [ordered]@{
            wall_time_ms = $_.wall_time_ms
            cpu_time_ms = $_.cpu_time_ms
            peak_working_set_bytes = $_.peak_working_set_bytes
            stdout_bytes = $_.stdout_bytes
            stdout_sha256 = $_.stdout_sha256
            report_sha256 = $_.report_sha256
        }
    })
    warmup_samples = @($warmups | ForEach-Object {
        [ordered]@{
            wall_time_ms = $_.wall_time_ms
            cpu_time_ms = $_.cpu_time_ms
            peak_working_set_bytes = $_.peak_working_set_bytes
            stdout_sha256 = $_.stdout_sha256
            report_sha256 = $_.report_sha256
        }
    })
    limitations = @(
        "Windows page cache is not flushed; measured samples are warm-cache end-to-end runs",
        "process startup, full source verification, JSON decoding, replay and report serialization are included",
        "CPU affinity, frequency, thermal state, Defender and unrelated host activity are not controlled",
        "source_raw_records_per_second is a source-workload rate, not a count of internal verifier passes",
        "this benchmark does not measure live capture latency or order-entry capability"
    )
}

$parent = Split-Path -Parent $OutputPath
if ($parent) {
    [IO.Directory]::CreateDirectory($parent) | Out-Null
}
$json = $report | ConvertTo-Json -Depth 12
$encoding = [Text.UTF8Encoding]::new($false)
$stream = [IO.FileStream]::new($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $writer = [IO.StreamWriter]::new($stream, $encoding)
    try {
        $writer.Write($json)
        $writer.Write("`n")
        $writer.Flush()
        $stream.Flush($true)
    }
    finally {
        $writer.Dispose()
    }
}
finally {
    $stream.Dispose()
}
Write-Output $OutputPath
