[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "run_raw_fault_gate.ps1")
. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")
Initialize-RawQualificationNative

$script:FaultSelfTestPassed = [uint64]0
$script:FaultSelfTestMutants = [uint64]0
$PSDefaultParameterValues["Test-FaultGateInjectedCampaignCausality:InjectionRequestedWallNs"] = [uint64]1

function Assert-SelfTest {
    param([Parameter(Mandatory = $true)] [bool] $Condition, [Parameter(Mandatory = $true)] [string] $Message)
    if (-not $Condition) { throw $Message }
    $script:FaultSelfTestPassed++
}

function Assert-SelfTestThrows {
    param([Parameter(Mandatory = $true)] [scriptblock] $Action, [Parameter(Mandatory = $true)] [string] $Label)
    $threw = $false
    try { & $Action }
    catch { $threw = $true }
    if (-not $threw) { throw "Mutant survived: $Label" }
    $script:FaultSelfTestPassed++
    $script:FaultSelfTestMutants++
}

function Write-SelfTestBytes {
    param([Parameter(Mandatory = $true)] [string] $Path, [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [byte[]] $Bytes)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Invoke-SelfTestBootstrapEntrypoint {
    param(
        [Parameter(Mandatory = $true)] [string] $ScriptPath,
        [Parameter(Mandatory = $true)] [string] $WorkingDirectory,
        [Parameter(Mandatory = $true)] [string] $ArtifactRoot,
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [string] $OutputBase
    )
    $stdoutPath = Join-Path $ArtifactRoot ($Name + ".stdout.json")
    $stderrPath = Join-Path $ArtifactRoot ($Name + ".stderr.log")
    $job = [IntPtr]::Zero
    $launch = $null
    $exitCode = $null
    try {
        $job = [RawQualificationNative]::CreateKillOnCloseJob("Local\BinanceRawFaultGateBootstrapSelfTest-" + [Guid]::NewGuid().ToString("N"))
        $powerShell = Join-Path $PSHOME "powershell.exe"
        $launch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $job,
            $powerShell,
            [string[]]@("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $ScriptPath, "-BootstrapValidateOnly", "-OutputBase", $OutputBase),
            $WorkingDirectory,
            $stdoutPath,
            $stderrPath,
            (Get-FaultGateChildEnvironment))
        if (-not [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 30000)) {
            $null = [RawQualificationNative]::TerminateJobObject($job, $script:FaultGateFallbackExitCode)
            $null = [RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 10000)
            throw "Bootstrap-only entrypoint subprocess exceeded 30 seconds: $Name"
        }
        $exitCode = [uint32][RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle)
        $drainOrigin = [Diagnostics.Stopwatch]::GetTimestamp()
        while ([RawQualificationNative]::GetActiveProcessCount($job) -ne 0 -and
            (Test-RawQualificationDeadlineTicks -ElapsedTicks ([Diagnostics.Stopwatch]::GetTimestamp() - $drainOrigin) -TimeoutSeconds 10)) {
            Start-Sleep -Milliseconds 25
        }
        if ([RawQualificationNative]::GetActiveProcessCount($job) -ne 0) {
            $null = [RawQualificationNative]::TerminateJobObject($job, $script:FaultGateFallbackExitCode)
            throw "Bootstrap-only entrypoint retained a child after terminal exit: $Name"
        }
    }
    finally {
        if ($null -ne $launch -and $launch.ProcessHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($launch.ProcessHandle) }
        if ($job -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($job) }
    }
    [byte[]]$stdoutBytes = [byte[]]::new(0)
    [byte[]]$stderrBytes = [byte[]]::new(0)
    if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { $stdoutBytes = [IO.File]::ReadAllBytes($stdoutPath) }
    if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { $stderrBytes = [IO.File]::ReadAllBytes($stderrPath) }
    if ($stdoutBytes.Length -gt 1048576 -or $stderrBytes.Length -gt 1048576) { throw "Bootstrap-only subprocess exceeded its self-test artifact bound: $Name" }
    return [pscustomobject][ordered]@{
        exit_code = [uint32]$exitCode
        stdout_bytes = [uint64]$stdoutBytes.Length
        stdout_text = [Text.UTF8Encoding]::new($false, $true).GetString($stdoutBytes)
        stderr_bytes = [uint64]$stderrBytes.Length
        stderr_text = [Text.UTF8Encoding]::new($false, $true).GetString($stderrBytes)
    }
}

function Assert-SelfTestBootstrapRejected {
    param([Parameter(Mandatory = $true)] $Result, [Parameter(Mandatory = $true)] [string] $Label)
    if ([uint32]$Result.exit_code -eq 0 -or [string]$Result.stdout_text -cmatch 'BOOTSTRAP_ONLY_NOT_FAULT_GATE') {
        throw "Bootstrap mutant survived: $Label"
    }
    $script:FaultSelfTestPassed++
    $script:FaultSelfTestMutants++
}

function Add-SelfTestUInt32BigEndian {
    param([Parameter(Mandatory = $true)] [Collections.Generic.List[byte]] $Bytes, [Parameter(Mandatory = $true)] [uint32] $Value)
    $encoded = [BitConverter]::GetBytes($Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($encoded) }
    $Bytes.AddRange([byte[]]$encoded)
}

function ConvertFrom-SelfTestHex {
    param([Parameter(Mandatory = $true)] [string] $Value)
    if ($Value.Length % 2 -ne 0 -or $Value -cnotmatch '^[0-9a-f]+$') { throw "Invalid self-test hex." }
    $bytes = [byte[]]::new($Value.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Value.Substring($index * 2, 2), 16)
    }
    return $bytes
}

function New-SelfTestRawFixture {
    param([Parameter(Mandatory = $true)] [string] $Root)
    $epoch = "depth-selftest-epoch"
    $stream = "btcusdt@depth@100ms"
    # Binance payloads legitimately contain case-distinct JSON names (`e` and `E`).
    # PowerShell 5.1 cannot represent both on a PSCustomObject, so the raw verifier
    # must prove these bytes without interpreting the application payload.
    $payload = [Text.UTF8Encoding]::new($false).GetBytes('{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":1,"u":1,"b":[],"a":[]}')
    $record = [ordered]@{
        schema = "RawFrameV1"; venue = "binance-spot"; environment = "production-public-market-data"
        endpoint = "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms"; stream = $stream; symbol = "BTCUSDT"
        connection_epoch = $epoch; frame_index = [uint64]0; receive_wall_ns = [uint64]1; receive_mono_ns = [uint64]1
        clock_quality = "SYNCED"; clock_source = "selftest"; clock_offset_ns = [int64]0; clock_uncertainty_ns = [uint64]1
        payload_length = [uint64]$payload.Length; payload_sha256 = Get-FaultGateSha256Bytes -Bytes $payload
        payload_base64 = [Convert]::ToBase64String($payload); recorder_state = "PENDING"
        spec_revision = "976cc580553890e92031b77306147c0ed1de5a46"; previous_record_sha256 = $script:FaultGateZeroDigest
    }
    [byte[]]$bodyBytes = @(ConvertTo-FaultGateCompactJsonBytes -Value $record)
    $recordSha = Get-FaultGateSha256Bytes -Bytes $bodyBytes
    $rawBytes = [Collections.Generic.List[byte]]::new()
    [byte[]]$rawMagic = [Text.Encoding]::ASCII.GetBytes("BNRAW")
    $rawBytes.AddRange($rawMagic); $rawBytes.Add(0); $rawBytes.Add(1); $rawBytes.Add(10)
    Add-SelfTestUInt32BigEndian -Bytes $rawBytes -Value ([uint32]$bodyBytes.Length)
    $rawBytes.AddRange($bodyBytes)
    [byte[]]$recordDigestBytes = @(ConvertFrom-SelfTestHex -Value $recordSha)
    $rawBytes.AddRange($recordDigestBytes)
    $rawPath = Join-Path $Root "segment-000000.bnraw"
    Write-SelfTestBytes -Path $rawPath -Bytes $rawBytes.ToArray()

    $ack = [ordered]@{
        schema = "DurabilityAckV1"; durable_record_count = [uint64]1; durable_through_offset = [uint64]$rawBytes.Count
        last_record_sha256 = $recordSha
        streams = @([ordered]@{ connection_epoch = $epoch; stream = $stream; durable_through_frame_index = [uint64]0 })
    }
    $progressBody = [ordered]@{ schema = "RawDurabilityProgressV1"; record_index = [uint64]0; raw_path = "segment-000000.bnraw"; ack = $ack; previous_record_sha256 = $script:FaultGateZeroDigest }
    $progressEnvelope = [ordered]@{ body = $progressBody; record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $progressBody) }
    $progressBytes = [Text.UTF8Encoding]::new($false).GetBytes((($progressEnvelope | ConvertTo-Json -Depth 100 -Compress) + "`n"))
    $progressPath = Join-Path $Root "segment-000000.bnack"
    Write-SelfTestBytes -Path $progressPath -Bytes $progressBytes

    $seal = [ordered]@{
        schema = "RawSegmentSealV1"; segment_index = [uint64]0; raw_file = "segment-000000.bnraw"; connection_epoch = $epoch
        stream = $stream; first_frame_index = [uint64]0; last_frame_index = [uint64]0; records = [uint64]1
        durable_through_offset = [uint64]$rawBytes.Count; previous_segment_terminal_sha256 = $script:FaultGateZeroDigest
        terminal_record_sha256 = $recordSha
    }
    $manifestBody = [ordered]@{ schema = "RawSegmentManifestRecordV1"; record_index = [uint64]0; previous_manifest_record_sha256 = $script:FaultGateZeroDigest; seal = $seal }
    [byte[]]$manifestBodyBytes = @(ConvertTo-FaultGateCompactJsonBytes -Value $manifestBody)
    $manifestBytes = [Collections.Generic.List[byte]]::new()
    [byte[]]$manifestMagic = [Text.Encoding]::ASCII.GetBytes("BNSEG")
    $manifestBytes.AddRange($manifestMagic); $manifestBytes.Add(0); $manifestBytes.Add(1); $manifestBytes.Add(10)
    Add-SelfTestUInt32BigEndian -Bytes $manifestBytes -Value ([uint32]$manifestBodyBytes.Length)
    $manifestBytes.AddRange($manifestBodyBytes)
    [byte[]]$manifestDigestBytes = @(ConvertFrom-SelfTestHex -Value (Get-FaultGateSha256Bytes -Bytes $manifestBodyBytes))
    $manifestBytes.AddRange($manifestDigestBytes)
    $manifestPath = Join-Path $Root "segments.bnseg"
    Write-SelfTestBytes -Path $manifestPath -Bytes $manifestBytes.ToArray()
    return [pscustomobject]@{ epoch = $epoch; stream = $stream; record_sha256 = $recordSha; raw = $rawPath; progress = $progressPath; manifest = $manifestPath; raw_bytes = [uint64]$rawBytes.Count }
}

function New-SelfTestRawSemanticMutant {
    param(
        [Parameter(Mandatory = $true)] [string] $Source,
        [Parameter(Mandatory = $true)] [string] $Destination,
        [Parameter(Mandatory = $true)] [scriptblock] $Mutation
    )
    $sourceBytes = [IO.File]::ReadAllBytes($Source)
    [byte[]]$lengthBytes = @($sourceBytes[8..11])
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lengthBytes) }
    $bodyLength = [BitConverter]::ToUInt32($lengthBytes, 0)
    $bodyText = [Text.UTF8Encoding]::new($false, $true).GetString($sourceBytes, 12, [int]$bodyLength)
    $body = $bodyText | ConvertFrom-Json -ErrorAction Stop
    & $Mutation $body
    [byte[]]$mutatedBody = @(ConvertTo-FaultGateCompactJsonBytes -Value $body)
    $output = [Collections.Generic.List[byte]]::new()
    $output.AddRange([byte[]]$sourceBytes[0..7])
    Add-SelfTestUInt32BigEndian -Bytes $output -Value ([uint32]$mutatedBody.Length)
    $output.AddRange($mutatedBody)
    [byte[]]$mutatedDigest = @(ConvertFrom-SelfTestHex -Value (Get-FaultGateSha256Bytes -Bytes $mutatedBody))
    $output.AddRange($mutatedDigest)
    Write-SelfTestBytes -Path $Destination -Bytes $output.ToArray()
    return [uint64]$output.Count
}

function New-SelfTestRawJsonTextMutant {
    param(
        [Parameter(Mandatory = $true)] [string] $Source,
        [Parameter(Mandatory = $true)] [string] $Destination,
        [Parameter(Mandatory = $true)] [scriptblock] $Mutation
    )
    $sourceBytes = [IO.File]::ReadAllBytes($Source)
    [byte[]]$lengthBytes = @($sourceBytes[8..11])
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lengthBytes) }
    $bodyLength = [BitConverter]::ToUInt32($lengthBytes, 0)
    $bodyText = [Text.UTF8Encoding]::new($false, $true).GetString($sourceBytes, 12, [int]$bodyLength)
    $mutatedText = [string](& $Mutation $bodyText)
    [byte[]]$mutatedBody = [Text.UTF8Encoding]::new($false).GetBytes($mutatedText)
    $output = [Collections.Generic.List[byte]]::new()
    $output.AddRange([byte[]]$sourceBytes[0..7])
    Add-SelfTestUInt32BigEndian -Bytes $output -Value ([uint32]$mutatedBody.Length)
    $output.AddRange($mutatedBody)
    [byte[]]$mutatedDigest = @(ConvertFrom-SelfTestHex -Value (Get-FaultGateSha256Bytes -Bytes $mutatedBody))
    $output.AddRange($mutatedDigest)
    Write-SelfTestBytes -Path $Destination -Bytes $output.ToArray()
    return [uint64]$output.Count
}

function New-SelfTestManifestSemanticMutant {
    param(
        [Parameter(Mandatory = $true)] [string] $Source,
        [Parameter(Mandatory = $true)] [string] $Destination,
        [Parameter(Mandatory = $true)] [scriptblock] $Mutation
    )
    $sourceBytes = [IO.File]::ReadAllBytes($Source)
    [byte[]]$lengthBytes = @($sourceBytes[8..11])
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lengthBytes) }
    $bodyLength = [BitConverter]::ToUInt32($lengthBytes, 0)
    $bodyText = [Text.UTF8Encoding]::new($false, $true).GetString($sourceBytes, 12, [int]$bodyLength)
    $body = $bodyText | ConvertFrom-Json -ErrorAction Stop
    & $Mutation $body
    [byte[]]$mutatedBody = @(ConvertTo-FaultGateCompactJsonBytes -Value $body)
    $output = [Collections.Generic.List[byte]]::new()
    $output.AddRange([byte[]]$sourceBytes[0..7])
    Add-SelfTestUInt32BigEndian -Bytes $output -Value ([uint32]$mutatedBody.Length)
    $output.AddRange($mutatedBody)
    [byte[]]$mutatedDigest = @(ConvertFrom-SelfTestHex -Value (Get-FaultGateSha256Bytes -Bytes $mutatedBody))
    $output.AddRange($mutatedDigest)
    Write-SelfTestBytes -Path $Destination -Bytes $output.ToArray()
}

function New-SelfTestEvidenceAck {
    param([Parameter(Mandatory = $true)] [string] $Symbol, [Parameter(Mandatory = $true)] [string] $Stream)
    $publicStream = if ($Stream -ceq "depth") { $Symbol.ToLowerInvariant() + "@depth@100ms" } else { $Symbol.ToLowerInvariant() + "@trade" }
    return [ordered]@{
        schema = "DurabilityAckV1"; durable_record_count = [uint64]1; durable_through_offset = [uint64]100; last_record_sha256 = "a" * 64
        streams = @([ordered]@{ connection_epoch = "epoch-$Symbol-$Stream"; stream = $publicStream; durable_through_frame_index = [uint64]0 })
    }
}

function New-SelfTestTelemetryReport {
    $records = [Collections.Generic.List[object]]::new()
    $prefix = [Collections.Generic.List[byte]]::new()
    for ($index = 0; $index -lt 2; $index++) {
        [uint64]$mono = if ($index -eq 0) { 50 } else { 100 }
        [uint64]$socket = if ($index -eq 0) { 45 } else { 90 }
        [uint64]$market = if ($index -eq 0) { 40 } else { 80 }
        [uint64]$durableMono = if ($index -eq 0) { 42 } else { 85 }
        $record = [ordered]@{
            schema = "CaptureTelemetryV1"; record_index = [uint64]$index; wall_ns = [uint64]($index + 1); mono_ns = $mono
            clock = [ordered]@{ quality = "HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND"; source = "Windows-w32time:selftest"; leap_indicator = [uint64]0; stratum = [uint64]2; last_successful_sync = "2026-08-24T00:00:00Z" }
            depth_received = [uint64]10; depth_written = [uint64]10; depth_durable = [uint64]10; depth_segment = [uint64]0
            depth_last_socket_activity_mono_ns = $socket; depth_last_market_message_mono_ns = $market; depth_last_durable_mono_ns = $durableMono
            depth_queue_records = [uint64]0; depth_queue_bytes = [uint64]0; depth_max_queue_records = [uint64]0; depth_max_queue_bytes = [uint64]0
            depth_max_queue_age_ns = [uint64]0; depth_last_sync_duration_ns = [uint64]0; depth_max_sync_duration_ns = [uint64]0
            trade_received = [uint64]10; trade_written = [uint64]10; trade_durable = [uint64]10; trade_segment = [uint64]0
            trade_last_socket_activity_mono_ns = $socket; trade_last_market_message_mono_ns = $market; trade_last_durable_mono_ns = $durableMono
            trade_queue_records = [uint64]0; trade_queue_bytes = [uint64]0; trade_max_queue_records = [uint64]0; trade_max_queue_bytes = [uint64]0
            trade_max_queue_age_ns = [uint64]0; trade_last_sync_duration_ns = [uint64]0; trade_max_sync_duration_ns = [uint64]0
        }
        [byte[]]$line = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $record)
        [byte[]]$lineWithLf = [byte[]]::new($line.Length + 1)
        [Array]::Copy($line, 0, $lineWithLf, 0, $line.Length)
        $lineWithLf[$line.Length] = 10
        $prefix.AddRange($lineWithLf)
        $records.Add([ordered]@{
            record_index = [uint64]$index; durable_through_offset = [uint64]$prefix.Count
            record_sha256 = Get-FaultGateSha256Bytes -Bytes $lineWithLf; record = $record
        })
    }
    $sha = Get-FaultGateSha256Bytes -Bytes $prefix.ToArray()
    return [ordered]@{
        file = "telemetry.jsonl"; duration_requested_s = [uint64]267
        market_freshness_startup_grace_s = [uint64]30; market_freshness_deadline_s = [uint64]30
        observed_file_bytes = [uint64]$prefix.Count; full_file_sha256 = $sha
        verified_through_offset = [uint64]$prefix.Count; verified_prefix_sha256 = $sha; partial_tail_bytes = [uint64]0
        verified_records = @($records)
    }
}

function New-SelfTestSizedTelemetryEvidence {
    param([Parameter(Mandatory = $true)] $Source, [Parameter(Mandatory = $true)] [uint64] $RecordBytesIncludingLf)
    $report = (($Source | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $report.verified_records = @($report.verified_records[0])
    $record = $report.verified_records[0].record
    [byte[]]$initialLine = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $record)
    [int64]$targetSourceLength = [int64]([string]$record.clock.source).Length + [int64]$RecordBytesIncludingLf - [int64]$initialLine.Length - 1
    if ($targetSourceLength -lt 1 -or $targetSourceLength -gt [int]::MaxValue) { throw "Self-test telemetry target size is not constructible." }
    $record.clock.source = "x" * [int]$targetSourceLength
    [byte[]]$line = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $record)
    [byte[]]$lineWithLf = [byte[]]::new($line.Length + 1)
    [Array]::Copy($line, 0, $lineWithLf, 0, $line.Length); $lineWithLf[$line.Length] = 10
    if ([uint64]$lineWithLf.Length -ne $RecordBytesIncludingLf) { throw "Self-test telemetry exact-size construction drifted." }
    $sha256 = Get-FaultGateSha256Bytes -Bytes $lineWithLf
    $report.verified_records[0].durable_through_offset = [uint64]$lineWithLf.Length
    $report.verified_records[0].record_sha256 = $sha256
    $report.observed_file_bytes = [uint64]$lineWithLf.Length
    $report.full_file_sha256 = $sha256
    $report.verified_through_offset = [uint64]$lineWithLf.Length
    $report.verified_prefix_sha256 = $sha256
    $report.partial_tail_bytes = [uint64]0
    return $report
}

function New-SelfTestSizedProgressEvidence {
    param([Parameter(Mandatory = $true)] $Source, [Parameter(Mandatory = $true)] [uint64] $RecordBytesExcludingLf)
    $report = (($Source | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $report.acknowledgements = @($report.acknowledgements[0])
    $ack = $report.acknowledgements[0]
    $ack.streams[0].connection_epoch = "x"
    $report.latest_ack.streams[0].connection_epoch = "x"
    $body = [ordered]@{
        schema = "RawDurabilityProgressV1"; record_index = [uint64]0; raw_path = [string]$report.raw_file
        ack = $ack; previous_record_sha256 = $script:FaultGateZeroDigest
    }
    $digest = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $body)
    $envelope = [ordered]@{ body = $body; record_sha256 = $digest }
    [byte[]]$initialLine = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $envelope)
    [int64]$targetEpochLength = 1 + [int64]$RecordBytesExcludingLf - [int64]$initialLine.Length
    if ($targetEpochLength -lt 1 -or $targetEpochLength -gt [int]::MaxValue) { throw "Self-test BNACK target size is not constructible." }
    $ack.streams[0].connection_epoch = "x" * [int]$targetEpochLength
    $report.latest_ack.streams[0].connection_epoch = [string]$ack.streams[0].connection_epoch
    $body.ack = $ack
    $digest = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $body)
    $envelope.record_sha256 = $digest
    [byte[]]$line = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $envelope)
    if ([uint64]$line.Length -ne $RecordBytesExcludingLf) { throw "Self-test BNACK exact-size construction drifted." }
    [byte[]]$lineWithLf = [byte[]]::new($line.Length + 1)
    [Array]::Copy($line, 0, $lineWithLf, 0, $line.Length); $lineWithLf[$line.Length] = 10
    $prefixSha256 = Get-FaultGateSha256Bytes -Bytes $lineWithLf
    $report.records = [uint64]1
    $report.terminal_record_sha256 = $digest
    $report.file_bytes = [uint64]$lineWithLf.Length
    $report.file_sha256 = $prefixSha256
    $report.verified_through_offset = [uint64]$lineWithLf.Length
    $report.verified_prefix_sha256 = $prefixSha256
    $report.partial_tail_bytes = [uint64]0
    $report.partial_tail = $false
    return $report
}

function New-SelfTestEvidenceGeneration {
    param([Parameter(Mandatory = $true)] [string] $Symbol, [Parameter(Mandatory = $true)] [string] $RunRoot)
    $campaignId = "1-" + $Symbol + "-raw-" + $(if ($Symbol -ceq "BTCUSDT") { "111111111111" } else { "222222222222" })
    $sessionId = "session-" + $Symbol
    $specRevision = "976cc580553890e92031b77306147c0ed1de5a46"
    $transports = @()
    $streams = @()
    for ($streamIndex = 0; $streamIndex -lt 2; $streamIndex++) {
        $streamName = @("depth", "trade")[$streamIndex]
        $ack = New-SelfTestEvidenceAck -Symbol $Symbol -Stream $streamName
        $progressBody = [ordered]@{
            schema = "RawDurabilityProgressV1"; record_index = [uint64]0; raw_path = "segment-000000.bnraw"
            ack = $ack; previous_record_sha256 = $script:FaultGateZeroDigest
        }
        $progressTerminalSha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $progressBody)
        $progressEnvelope = [ordered]@{ body = $progressBody; record_sha256 = $progressTerminalSha256 }
        [byte[]]$progressLine = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $progressEnvelope)
        [byte[]]$progressBytes = [byte[]]::new($progressLine.Length + 1)
        [Array]::Copy($progressLine, 0, $progressBytes, 0, $progressLine.Length); $progressBytes[$progressLine.Length] = 10
        $progressPrefixSha256 = Get-FaultGateSha256Bytes -Bytes $progressBytes
        $progress = [ordered]@{
            records = [uint64]1; raw_file = "segment-000000.bnraw"; terminal_record_sha256 = $progressTerminalSha256; file_bytes = [uint64]$progressBytes.Length; file_sha256 = $progressPrefixSha256
            verified_through_offset = [uint64]$progressBytes.Length; verified_prefix_sha256 = $progressPrefixSha256; partial_tail_bytes = [uint64]0; partial_tail = $false
            acknowledgements = @($ack); latest_ack = $ack
        }
        $publicStream = if ($streamName -ceq "depth") { $Symbol.ToLowerInvariant() + "@depth@100ms" } else { $Symbol.ToLowerInvariant() + "@trade" }
        $raw = [ordered]@{
            raw_file = "segment-000000.bnraw"; connection_epoch = "epoch-$Symbol-$streamName"; stream = $publicStream
            observed_file_bytes = [uint64]100; durable_through_offset = [uint64]100
            durable_records = [uint64]1; first_frame_index = [uint64]0; last_frame_index = [uint64]0
            terminal_record_sha256 = "a" * 64; verified_prefix_sha256 = "d" * 64; unverified_suffix_bytes = [uint64]0; full_file_sha256 = "d" * 64
        }
        $streams += [ordered]@{
            stream = $streamName; manifest_records = [uint64]1; manifest_terminal_record_sha256 = "e" * 64; manifest_file_bytes = [uint64]100; manifest_file_sha256 = "f" * 64
            manifest_verified_through_offset = [uint64]100; manifest_verified_prefix_sha256 = "f" * 64; manifest_partial_tail_bytes = [uint64]0
            manifest_verified_records = @([ordered]@{ record_index = [uint64]0; verified_through_offset = [uint64]100; terminal_record_sha256 = "e" * 64; verified_prefix_sha256 = "f" * 64 })
            verified_segments = @([ordered]@{ segment_index = [uint64]0; sealed = $true; raw = $raw; progress = $progress })
        }
        $uri = "wss://data-stream.binance.vision:443/ws/" + $publicStream + "?timeUnit=MICROSECOND"
        $headers = [ordered]@{ connection = @("upgrade") }
        $connection = [ordered]@{
            stream = $streamName; connection_epoch = "epoch-$Symbol-$streamName"; uri = $uri; websocket_http_status = [uint64]101
            local_endpoint = "192.0.2.10:" + (50000 + $streamIndex); remote_endpoint = "198.51.100.10:443"; response_headers = $headers
        }
        $metadata = [ordered]@{
            schema = "TransportMetadataV1"; session_id = $sessionId; generation_index = [uint64]0; symbol = $Symbol; spec_revision = $specRevision; connection = $connection
        }
        $metadata = $metadata | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $connection = $metadata.connection
        $headers = $connection.response_headers
        [byte[]]$metadataBytes = @(ConvertTo-FaultGateSerdeTransportBytes -Metadata $metadata)
        $eventConnection = [ordered]@{
            connection_epoch = $connection.connection_epoch; local_endpoint = $connection.local_endpoint; remote_endpoint = $connection.remote_endpoint
            response_headers = $headers; stream = $streamName; uri = $uri; websocket_http_status = [uint64]101
        }
        $transportPayload = [ordered]@{
            connection = $eventConnection; event = "TRANSPORT_CONNECTED"; metadata_file = "transport-$streamName.json"
            metadata_sha256 = Get-FaultGateSha256Bytes -Bytes $metadataBytes; schema = "TransportConnectedProcessEventV1"; session_id = $sessionId
        }
        $transportEventBody = [ordered]@{
            schema = "RawCampaignJournalRecordV1"; record_index = [uint64](3 + $streamIndex); wall_ns = [uint64](3 + $streamIndex); campaign_mono_ns = [uint64](3 + $streamIndex)
            generation_index = [uint64]0; channel = "CHILD_STDOUT"; payload = $transportPayload; previous_record_sha256 = $script:FaultGateZeroDigest
        }
        $transports += [ordered]@{
            stream = $streamName; connection_epoch = $connection.connection_epoch; uri = $uri; metadata_file = "transport-$streamName.json"
            metadata_bytes = [uint64]$metadataBytes.Length; metadata_sha256 = Get-FaultGateSha256Bytes -Bytes $metadataBytes; metadata = $metadata
            campaign_event = [ordered]@{ body = $transportEventBody; record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $transportEventBody) }
        }
    }
    $snapshotEndpoint = "https://data-api.binance.vision/api/v3/depth?symbol=" + $Symbol + "&limit=5000"
    $snapshotPayloadSha = "8" * 64
    $snapshotMetadata = [ordered]@{
        schema = "SnapshotHttpMetadataV1"; endpoint = $snapshotEndpoint; http_status = [uint64]200; headers = [ordered]@{ connection = @("keep-alive") }
        receive_wall_ns = [uint64]10; receive_mono_ns = [uint64]11; body_complete = $true; body_length = [uint64]10; body_sha256 = $snapshotPayloadSha
        raw_file = "snapshot.bnraw"; raw_record_sha256 = "2" * 64
    }
    [byte[]]$snapshotMetadataBytes = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $snapshotMetadata)
    $snapshotMetadataSha = Get-FaultGateSha256Bytes -Bytes $snapshotMetadataBytes
    $snapshotEventBody = [ordered]@{
        schema = "RawCampaignJournalRecordV1"; record_index = [uint64]6; wall_ns = [uint64]1; campaign_mono_ns = [uint64]1
        generation_index = [uint64]0; channel = "CHILD_STDOUT"
        payload = [ordered]@{
            durable_through_offset = [uint64]100; event = "SNAPSHOT_DURABLE"; http_metadata_file = "snapshot-http.json"
            http_metadata_sha256 = $snapshotMetadataSha; last_record_sha256 = "2" * 64; raw_file = "snapshot.bnraw"
            schema = "SnapshotDurableProcessEventV1"; session_id = $sessionId
        }
        previous_record_sha256 = $script:FaultGateZeroDigest
    }
    $snapshotCampaignEvent = [ordered]@{ body = $snapshotEventBody; record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $snapshotEventBody) }
    $telemetry = New-SelfTestTelemetryReport
    return [ordered]@{
        symbol = $Symbol; session_id = $sessionId; session_directory = Join-Path (Join-Path (Join-Path $RunRoot $campaignId) "generations") $sessionId; spec_revision = $specRevision; startup_bytes = [uint64]100; startup_sha256 = "1" * 64
        snapshot = [ordered]@{
            bytes = [uint64]100; terminal_record_sha256 = "2" * 64; file_sha256 = "3" * 64
            http_metadata_file = "snapshot-http.json"; http_metadata_bytes = [uint64]$snapshotMetadataBytes.Length; http_metadata_sha256 = $snapshotMetadataSha
            raw_frame_summary = [ordered]@{
                endpoint = $snapshotEndpoint; connection_epoch = "snapshot-epoch-$Symbol"; receive_wall_ns = [uint64]10; receive_mono_ns = [uint64]11
                payload_length = [uint64]10; payload_sha256 = $snapshotPayloadSha; last_update_id = [uint64]1; bid_levels = [uint64]1; ask_levels = [uint64]1
            }
            http_metadata = $snapshotMetadata
            campaign_event = $snapshotCampaignEvent
        }
        transports = $transports
        telemetry = $telemetry
        streams = $streams
    }
}

function New-SelfTestActiveDurableSegment {
    param(
        [Parameter(Mandatory = $true)] $SealedSegment,
        [Parameter(Mandatory = $true)] [uint64] $SegmentIndex,
        [Parameter(Mandatory = $true)] [string] $ConnectionEpoch
    )
    $source = $SealedSegment | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $rawFile = "segment-{0:D6}.bnraw" -f $SegmentIndex
    $raw = $source.raw
    $raw.raw_file = $rawFile
    $raw.connection_epoch = $ConnectionEpoch
    $raw.first_frame_index = $SegmentIndex
    $raw.last_frame_index = $SegmentIndex
    $ack = $source.progress.latest_ack
    $ack.streams[0].connection_epoch = $ConnectionEpoch
    $ack.streams[0].durable_through_frame_index = $SegmentIndex
    $progressBody = [pscustomobject][ordered]@{
        schema = "RawDurabilityProgressV1"; record_index = [uint64]0; raw_path = $rawFile
        ack = $ack; previous_record_sha256 = $script:FaultGateZeroDigest
    }
    $progressDigest = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $progressBody)
    $progressEnvelope = [pscustomobject][ordered]@{ body = $progressBody; record_sha256 = $progressDigest }
    [byte[]]$progressLine = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $progressEnvelope)
    [byte[]]$progressBytes = [byte[]]::new($progressLine.Length + 1)
    [Array]::Copy($progressLine, 0, $progressBytes, 0, $progressLine.Length)
    $progressBytes[$progressLine.Length] = 10
    $progressSha256 = Get-FaultGateSha256Bytes -Bytes $progressBytes
    $progress = [pscustomobject][ordered]@{
        records = [uint64]1; raw_file = $rawFile; terminal_record_sha256 = $progressDigest
        file_bytes = [uint64]$progressBytes.Length; file_sha256 = $progressSha256
        verified_through_offset = [uint64]$progressBytes.Length; verified_prefix_sha256 = $progressSha256
        partial_tail_bytes = [uint64]0; partial_tail = $false; acknowledgements = @($ack); latest_ack = $ack
    }
    return [pscustomobject][ordered]@{
        segment_index = $SegmentIndex; sealed = $false; durable_prefix = $true; raw = $raw; progress = $progress
    }
}

function Test-SelfTestEvidenceEnvelope {
    param([Parameter(Mandatory = $true)] [string] $Path)
    return Test-FaultGateEvidenceEnvelope -Path $Path
}

function Assert-SelfTestEvidenceMutantRejected {
    param(
        [Parameter(Mandatory = $true)] [string] $SourcePath,
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [scriptblock] $Mutation
    )
    [byte[]]$originalBytes = [IO.File]::ReadAllBytes($SourcePath)
    $mutant = Read-FaultGateJson -Path $SourcePath
    & $Mutation $mutant
    $mutant.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $mutant.body)
    try {
        Write-SelfTestBytes -Path $SourcePath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($mutant | ConvertTo-Json -Depth 100) + "`n")))
        Assert-SelfTestThrows { $null = Test-SelfTestEvidenceEnvelope -Path $SourcePath } ("evidence " + $Name)
    }
    finally { Write-SelfTestBytes -Path $SourcePath -Bytes $originalBytes }
}

function Update-SelfTestEvidenceTreeEnvelope {
    param([Parameter(Mandatory = $true)] $Envelope)
    $inventory = @($Envelope.body.artifact_tree.inventory)
    $builder = [Text.StringBuilder]::new()
    [uint64]$totalBytes = 0
    foreach ($row in $inventory) {
        $rowBytes = [uint64]$row.bytes
        $totalBytes += $rowBytes
        $null = $builder.Append([string]$row.relative_path).Append([char]0).Append($rowBytes.ToString([Globalization.CultureInfo]::InvariantCulture)).Append([char]0).Append([string]$row.sha256).Append([char]10)
    }
    $Envelope.body.artifact_tree.files = [uint64]$inventory.Count
    $Envelope.body.artifact_tree.total_bytes = $totalBytes
    [byte[]]$treeMaterial = [Text.UTF8Encoding]::new($false).GetBytes($builder.ToString())
    if ($treeMaterial.Length -eq 0) {
        $emptySha = [Security.Cryptography.SHA256]::Create()
        try { $Envelope.body.artifact_tree.tree_sha256 = -join ($emptySha.ComputeHash($treeMaterial) | ForEach-Object { $_.ToString("x2") }) }
        finally { $emptySha.Dispose() }
    }
    else { $Envelope.body.artifact_tree.tree_sha256 = Get-FaultGateSha256Bytes -Bytes $treeMaterial }
}

function Update-SelfTestSupportTreeEnvelope {
    param([Parameter(Mandatory = $true)] $Envelope)
    $inventory = @($Envelope.body.support_artifact_tree.inventory)
    $builder = [Text.StringBuilder]::new()
    [uint64]$totalBytes = 0
    foreach ($row in $inventory) {
        $rowBytes = [uint64]$row.bytes
        $totalBytes += $rowBytes
        $null = $builder.Append([string]$row.relative_path).Append([char]0).Append($rowBytes.ToString([Globalization.CultureInfo]::InvariantCulture)).Append([char]0).Append([string]$row.sha256).Append([char]10)
    }
    $Envelope.body.support_artifact_tree.files = [uint64]$inventory.Count
    $Envelope.body.support_artifact_tree.total_bytes = $totalBytes
    $Envelope.body.support_artifact_tree.tree_sha256 = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($builder.ToString()))
}

function Update-SelfTestEmbeddedFaultJournal {
    param(
        [Parameter(Mandatory = $true)] $Envelope,
        [Parameter(Mandatory = $true)] [scriptblock] $Mutation
    )
    [byte[]]$original = [Convert]::FromBase64String([string]$Envelope.body.fault_journal.journal_bytes_base64)
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($original)
    $lines = @($text.Split([char]10) | Where-Object { $_.Length -gt 0 })
    $entries = @($lines | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
    & $Mutation $entries
    $previous = $script:FaultGateZeroDigest
    $builder = [Text.StringBuilder]::new()
    for ($index = 0; $index -lt $entries.Count; $index++) {
        $entries[$index].body.previous_record_sha256 = $previous
        if ($index -eq 4) { $entries[$index].body.payload.proposal_record_sha256 = [string]$entries[3].record_sha256 }
        if ($index -eq 5) {
            $entries[$index].body.payload.proposal_record_sha256 = [string]$entries[3].record_sha256
            $entries[$index].body.payload.injection_requested_record_sha256 = [string]$entries[4].record_sha256
        }
        $entries[$index].record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $entries[$index].body)
        if ($index -eq 4) { $entries[5].body.payload.proposal_record_sha256 = [string]$entries[3].record_sha256 }
        $canonical = [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateCompactJsonBytes -Value $entries[$index]))
        $null = $builder.Append($canonical).Append([char]10)
        $previous = [string]$entries[$index].record_sha256
    }
    [byte[]]$journalBytes = [Text.UTF8Encoding]::new($false).GetBytes($builder.ToString())
    $journalSha = Get-FaultGateSha256Bytes -Bytes $journalBytes
    $Envelope.body.fault.proposed_record_sha256 = [string]$entries[3].record_sha256
    $Envelope.body.fault.injection_requested_record_sha256 = [string]$entries[4].record_sha256
    $Envelope.body.fault.injected_record_sha256 = [string]$entries[5].record_sha256
    $Envelope.body.fault_journal.journal_bytes_base64 = [Convert]::ToBase64String($journalBytes)
    $Envelope.body.fault_journal.records = [uint64]$entries.Count
    $Envelope.body.fault_journal.terminal_record_sha256 = [string]$entries[$entries.Count - 1].record_sha256
    $Envelope.body.fault_journal.file_bytes = [uint64]$journalBytes.Length
    $Envelope.body.fault_journal.file_sha256 = $journalSha
    $Envelope.body.fault_journal.proposed_record_sha256 = [string]$entries[3].record_sha256
    $Envelope.body.fault_journal.injection_requested_record_sha256 = [string]$entries[4].record_sha256
    $Envelope.body.fault_journal.injected_record_sha256 = [string]$entries[5].record_sha256
    $faultTreeRow = @($Envelope.body.support_artifact_tree.inventory | Where-Object { [string]$_.relative_path -ceq "fault-events.jsonl" })
    if ($faultTreeRow.Count -ne 1) { throw "Self-test support tree lacks its exact fault journal row." }
    $faultTreeRow[0].bytes = [uint64]$journalBytes.Length
    $faultTreeRow[0].sha256 = $journalSha
    Update-SelfTestSupportTreeEnvelope -Envelope $Envelope
}

function Update-SelfTestContainmentEvidenceSha {
    param([Parameter(Mandatory = $true)] $Envelope)
    $containmentBody = [ordered]@{}
    foreach ($name in @(
        "schema", "job_name", "job_kill_on_close", "detected_wall_ns", "detected_monotonic_tick", "requested_exit_code",
        "initial_query_succeeded", "initial_active_processes", "initial_query_error", "terminate_attempted", "terminate_succeeded",
        "terminate_error", "termination_monotonic_tick", "monotonic_frequency", "drain_deadline_s", "drain_elapsed_qpc_ticks", "final_query_succeeded",
        "final_active_processes", "final_query_error", "result"
    )) { $containmentBody[$name] = $Envelope.body.launcher.containment.$name }
    $Envelope.body.launcher.containment.sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $containmentBody)
}

function New-SelfTestCampaignJournal {
    param([int] $DisconnectCount = 0, [int] $FailureCount = 0, [string] $FailureChannel = "CAMPAIGN", [int] $ExitCount = 0, [uint32] $ExitCode = [uint32]0xEE31)
    $entries = [Collections.Generic.List[object]]::new()
    $entries.Add(([ordered]@{
        body = [ordered]@{ record_index = [uint64]0; wall_ns = [uint64]1; generation_index = $null; channel = "CAMPAIGN"; payload = [ordered]@{ event = "CAMPAIGN_STARTED" } }
        record_sha256 = "a" * 64
    } | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json))
    [uint64]$recordIndex = 1
    for ($index = 0; $index -lt $ExitCount; $index++) {
        $entries.Add(([ordered]@{
            body = [ordered]@{ record_index = $recordIndex; wall_ns = [uint64](10 + $recordIndex); generation_index = [uint64]0; channel = "CAMPAIGN"; payload = [ordered]@{ code = $ExitCode; event = "GENERATION_EXITED"; success = $false } }
            record_sha256 = (($recordIndex + 10).ToString("x2")) * 32
        } | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json))
        $recordIndex++
    }
    for ($index = 0; $index -lt $DisconnectCount; $index++) {
        $entries.Add(([ordered]@{
            body = [ordered]@{ record_index = $recordIndex; wall_ns = [uint64](10 + $recordIndex); generation_index = [uint64]0; channel = "SUPERVISOR"; payload = [ordered]@{ epoch = "epoch-0"; event = "GENERATION_DISCONNECT_FAIL_CLOSED"; gap_count = [uint64]1; outcome = "ActiveFailed" } }
            record_sha256 = (($recordIndex + 10).ToString("x2")) * 32
        } | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json))
        $recordIndex++
    }
    for ($index = 0; $index -lt $FailureCount; $index++) {
        $entries.Add(([ordered]@{
            body = [ordered]@{ record_index = $recordIndex; wall_ns = [uint64](10 + $recordIndex); generation_index = $null; channel = $FailureChannel; payload = [ordered]@{ error = "generation 0 exited without COMPLETE terminal evidence"; event = "CAMPAIGN_FAILED"; stage = "RUNTIME" } }
            record_sha256 = (($recordIndex + 10).ToString("x2")) * 32
        } | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json))
        $recordIndex++
    }
    return [pscustomobject]@{ records = $recordIndex; entries = @($entries) }
}

function New-SelfTestCampaignPrefix {
    param([Parameter(Mandatory = $true)] [string] $Symbol, [uint64] $Records = 1, [string] $TerminalRecordSha256 = "")
    $journal = if ($Records -eq 1) { New-SelfTestCampaignJournal } elseif ($Records -eq 3) { New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 1 } else { throw "Unsupported self-test campaign prefix length." }
    $summary = Get-FaultGateSerdeJournalPrefixSummary -Journal $journal -Records $Records -Label "self-test campaign prefix"
    $terminal = if ([string]::IsNullOrEmpty($TerminalRecordSha256)) { [string]$summary.terminal_record_sha256 } else { $TerminalRecordSha256 }
    return ([ordered]@{ symbol = $Symbol; records = $Records; clean_tail = $true; terminal_record_sha256 = $terminal; file_sha256 = [string]$summary.file_sha256 } | ConvertTo-Json -Compress | ConvertFrom-Json)
}

function New-SelfTestCampaignStartedEvent {
    param(
        [Parameter(Mandatory = $true)] [string] $CampaignId,
        [Parameter(Mandatory = $true)] [string] $StartupSha256
    )
    $body = [pscustomobject][ordered]@{
        schema = "RawCampaignJournalRecordV1"; record_index = [uint64]0; wall_ns = [uint64]1; campaign_mono_ns = [uint64]0
        generation_index = $null; channel = "CAMPAIGN"
        payload = [pscustomobject][ordered]@{ campaign_id = $CampaignId; event = "CAMPAIGN_STARTED"; startup_sha256 = $StartupSha256 }
        previous_record_sha256 = $script:FaultGateZeroDigest
    }
    return [pscustomobject][ordered]@{
        body = $body
        record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $body)
    }
}

function New-SelfTestFaultJournalEvidence {
    param(
        [Parameter(Mandatory = $true)] [uint32] $TargetPid,
        [Parameter(Mandatory = $true)] $Context,
        [uint64] $RequestWallNs = 10,
        [uint64] $RequestMonotonicTick = 1000
    )
    $events = @("HARNESS_STARTED", "RUN_BOUND", "LIVE_HEALTHY", "FAULT_PROPOSED", "FAULT_INJECTION_REQUESTED", "FAULT_INJECTED", "LAUNCHER_EXITED", "EVIDENCE_PROPOSED")
    $entries = [Collections.Generic.List[object]]::new(); $bytes = [Collections.Generic.List[byte]]::new(); $previous = $script:FaultGateZeroDigest
    $proposalSha = $null; $requestSha = $null; $injectedSha = $null
    for ($index = 0; $index -lt $events.Count; $index++) {
        $payload = if ($index -eq 0) {
            [pscustomobject][ordered]@{
                event = $events[$index]; gate_id = [string]$Context.gate_id; repo = [string]$Context.repository_root
                qualification_base = [string]$Context.qualification_base; target_exit_code = [uint32]$script:FaultGateTargetExitCode
                containment_exit_code = [uint32]$script:FaultGateContainmentExitCode; source_bindings = $Context.source_bindings
                artifact_path_binding_scope = "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE"
                artifact_path_binding_trust_boundary = "Path-byte observation and retention do not assert absolute equivalence with bytes already interpreted or mapped by a runtime."
                artifact_path_bindings = $Context.artifact_path_bindings; launch_artifact_hashes = $Context.launch_artifact_hashes
            }
        }
        elseif ($index -eq 1) {
            [pscustomobject][ordered]@{
                event = $events[$index]; run_id = [string]$Context.run_id; run_root = [string]$Context.run_root
                launcher_pid = [uint32]$Context.launcher_pid; launcher_creation_filetime_utc = [int64]$Context.launcher_creation_filetime_utc
                launcher_command_line_sha256 = [string]$Context.launcher_command_line_sha256; startup_sha256 = [string]$Context.startup_sha256
                processes_sha256 = [string]$Context.processes_sha256; bindings_sha256 = [string]$Context.bindings_sha256
            }
        }
        elseif ($index -eq 2) {
            [pscustomobject][ordered]@{
                event = $events[$index]; monitor_attempt = [uint64]1; monitor_stdout_sha256 = "f" * 64; status = "HEALTHY_RUNNING"; stage = "CAPTURING"
                host_telemetry_records = [uint64]1; watchdog_ready_sha256 = "e" * 64
            }
        }
        elseif ($index -eq 3) {
            [pscustomobject][ordered]@{
                event = $events[$index]; run_id = [string]$Context.run_id; run_root = [string]$Context.run_root; symbol = "BTCUSDT"; generation_index = [uint64]0
                target_pid = $TargetPid; target_creation_filetime_utc = [int64]$Context.target_creation_filetime_utc; target_parent_pid = [uint32]$Context.target_parent_pid
                target_executable_sha256 = [string]$Context.target_executable_sha256; target_command_line_sha256 = [string]$Context.target_command_line_sha256
                requested_exit_code = [uint32]$script:FaultGateTargetExitCode; pre_fault_raw_prefixes_sha256 = [string]$Context.pre_fault_raw_prefixes_sha256
                pre_fault_campaign_prefixes_sha256 = [string]$Context.pre_fault_campaign_prefixes_sha256; pre_fault_campaign_prefixes = $Context.pre_fault_campaign_prefixes
            }
        }
        elseif ($index -eq 4) {
            [pscustomobject][ordered]@{ event = $events[$index]; proposal_record_sha256 = $proposalSha; target_pid = $TargetPid; requested_exit_code = [uint32]$script:FaultGateTargetExitCode; request_wall_ns = $RequestWallNs; request_monotonic_tick = $RequestMonotonicTick }
        }
        elseif ($index -eq 5) {
            [pscustomobject][ordered]@{ event = $events[$index]; proposal_record_sha256 = $proposalSha; injection_requested_record_sha256 = $requestSha; target_pid = $TargetPid; observed_exit_code = [uint32]$script:FaultGateTargetExitCode; injection_method = "TerminateProcess_RETAINED_HANDLE"; injected_wall_ns = [uint64]($RequestWallNs + 1); injected_monotonic_tick = [uint64]($RequestMonotonicTick + 1) }
        }
        elseif ($index -eq 6) {
            [pscustomobject][ordered]@{
                event = $events[$index]; launcher_exit_code = [uint32]1; target_exit_code = [uint32]$script:FaultGateTargetExitCode
                btc_coordinator_exit_code = [uint32]$script:FaultGateContainmentExitCode; eth_capture_exit_code = [uint32]$script:FaultGateContainmentExitCode
                eth_coordinator_exit_code = [uint32]$script:FaultGateContainmentExitCode; watchdog_exit_code = [uint32]$script:FaultGateContainmentExitCode
                outer_active_processes = [uint32]0; inner_job_exists = $false; inner_job_open_error = [int]2
                workload_job_exists = $false; workload_job_open_error = [int]2
            }
        }
        else {
            [pscustomobject][ordered]@{
                event = $events[$index]; run_id = [string]$Context.run_id; terminal_sha256 = [string]$Context.terminal_sha256
                containment_sha256 = [string]$Context.containment_sha256; launcher_journal_terminal_sha256 = [string]$Context.launcher_journal_terminal_sha256
                process_observation = "PRE_PROPOSAL_ONLY_POSTSCAN_REQUIRED_BEFORE_PUBLICATION"
                outer_active_processes = [uint32]0; global_engine_processes = [uint64]0; run_bound_processes = [uint64]0
                inner_job_exists = $false; inner_job_open_error = [int]2
                workload_job_exists = $false; workload_job_open_error = [int]2
            }
        }
        $body = [pscustomobject][ordered]@{
            schema = "RawQualificationFaultGateEventV1"; record_index = [uint64]$index; wall_ns = [uint64]($index + 1)
            monotonic_tick = [uint64]($RequestMonotonicTick - 4 + $index); channel = "FAULT_GATE"; payload = $payload; previous_record_sha256 = $previous
        }
        if ($index -eq 4) { $body.wall_ns = $RequestWallNs; $body.monotonic_tick = $RequestMonotonicTick }
        elseif ($index -eq 5) { $body.wall_ns = [uint64]($RequestWallNs + 1); $body.monotonic_tick = [uint64]($RequestMonotonicTick + 1) }
        elseif ($index -eq 6) { $body.wall_ns = [uint64]($RequestWallNs + 2); $body.monotonic_tick = [uint64]($RequestMonotonicTick + 400) }
        elseif ($index -eq 7) { $body.wall_ns = [uint64]($RequestWallNs + 3); $body.monotonic_tick = [uint64]($RequestMonotonicTick + 401) }
        $envelope = [pscustomobject][ordered]@{ body = $body; record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $body) }
        [byte[]]$line = @(ConvertTo-FaultGateCompactJsonBytes -Value $envelope); $bytes.AddRange($line); $bytes.Add([byte]10); $entries.Add($envelope)
        $previous = [string]$envelope.record_sha256
        if ($index -eq 3) { $proposalSha = $previous } elseif ($index -eq 4) { $requestSha = $previous } elseif ($index -eq 5) { $injectedSha = $previous }
    }
    return [pscustomobject][ordered]@{
        records = [uint64]$entries.Count; terminal_record_sha256 = $previous; file_bytes = [uint64]$bytes.Count
        file_sha256 = Get-FaultGateSha256Bytes -Bytes $bytes.ToArray(); raw_bytes = [byte[]]$bytes.ToArray(); entries = @($entries)
        proposed_record_sha256 = $proposalSha; injection_requested_record_sha256 = $requestSha; injected_record_sha256 = $injectedSha
    }
}

function New-SelfTestHealthyHeartbeatEntry {
    param([string] $SessionId = "session-selftest", [uint64] $TelemetryRecordIndex = 1, [uint64] $TelemetryMonoNs = 100)
    $telemetry = New-SelfTestTelemetryReport
    $telemetryRow = @($telemetry.verified_records | Where-Object { [uint64]$_.record_index -eq $TelemetryRecordIndex })
    if ($telemetryRow.Count -ne 1) { throw "Self-test heartbeat telemetry index is absent." }
    $telemetryRecord = $telemetryRow[0].record
    $payload = [ordered]@{
        depth_durable = [uint64]$telemetryRecord.depth_durable; depth_last_durable_mono_ns = [uint64]$telemetryRecord.depth_last_durable_mono_ns; depth_last_market_message_mono_ns = [uint64]$telemetryRecord.depth_last_market_message_mono_ns
        depth_last_socket_activity_mono_ns = [uint64]$telemetryRecord.depth_last_socket_activity_mono_ns; depth_queue_records = [uint64]$telemetryRecord.depth_queue_records; depth_received = [uint64]$telemetryRecord.depth_received
        event = "HEARTBEAT_DURABLE"; schema = "HeartbeatProcessEventV1"; session_id = $SessionId
        telemetry_durable_through_offset = [uint64]$telemetryRow[0].durable_through_offset; telemetry_mono_ns = $TelemetryMonoNs
        telemetry_record_index = $TelemetryRecordIndex; telemetry_record_sha256 = [string]$telemetryRow[0].record_sha256
        trade_durable = [uint64]$telemetryRecord.trade_durable; trade_last_durable_mono_ns = [uint64]$telemetryRecord.trade_last_durable_mono_ns; trade_last_market_message_mono_ns = [uint64]$telemetryRecord.trade_last_market_message_mono_ns
        trade_last_socket_activity_mono_ns = [uint64]$telemetryRecord.trade_last_socket_activity_mono_ns; trade_queue_records = [uint64]$telemetryRecord.trade_queue_records; trade_received = [uint64]$telemetryRecord.trade_received
    }
    return ([ordered]@{ body = [ordered]@{ record_index = [uint64]0; generation_index = [uint64]0; channel = "CHILD_STDOUT"; payload = $payload }; record_sha256 = "7" * 64 } | ConvertTo-Json -Depth 30 -Compress | ConvertFrom-Json)
}

function New-SelfTestHealthySegmentEntry {
    param(
        [Parameter(Mandatory = $true)] [string] $SessionId,
        [Parameter(Mandatory = $true)] [string] $Symbol,
        [ValidateSet("depth", "trade")] [string] $Stream = "depth",
        [uint64] $SegmentIndex = 0,
        [uint64] $FirstFrameIndex = 0,
        [uint64] $LastFrameIndex = 0,
        [string] $PreviousSegmentTerminalSha256 = "",
        [string] $TerminalRecordSha256 = ""
    )
    if ([string]::IsNullOrEmpty($PreviousSegmentTerminalSha256)) { $PreviousSegmentTerminalSha256 = if ($SegmentIndex -eq 0) { $script:FaultGateZeroDigest } else { "a" * 64 } }
    if ([string]::IsNullOrEmpty($TerminalRecordSha256)) { $TerminalRecordSha256 = if ($SegmentIndex -eq 0) { "a" * 64 } else { "c" * 64 } }
    $payload = [ordered]@{
        event = "SEGMENT_DURABLE"; schema = "SegmentDurableProcessEventV1"
        segment = [ordered]@{
            connection_epoch = "epoch-$Symbol-$Stream"; durable_through_offset = [uint64]100; first_frame_index = $FirstFrameIndex; last_frame_index = $LastFrameIndex
            manifest_durable_through_offset = [uint64]100; manifest_record_index = $SegmentIndex; manifest_record_sha256 = "e" * 64
            previous_segment_terminal_sha256 = $PreviousSegmentTerminalSha256; raw_file = ("segment-{0:D6}.bnraw" -f $SegmentIndex); records = [uint64]($LastFrameIndex - $FirstFrameIndex + 1)
            schema = "DurableSegmentEventV1"; segment_index = $SegmentIndex; stream = $Stream; terminal_record_sha256 = $TerminalRecordSha256
        }
        session_id = $SessionId
    }
    return ([ordered]@{ body = [ordered]@{ record_index = [uint64]0; generation_index = [uint64]0; channel = "CHILD_STDOUT"; payload = $payload }; record_sha256 = "8" * 64 } | ConvertTo-Json -Depth 30 -Compress | ConvertFrom-Json)
}

function Add-SelfTestHealthyEntriesBeforeCausal {
    param([Parameter(Mandatory = $true)] $Journal, [Parameter(Mandatory = $true)] [object[]] $HealthyEntries)
    $combined = @(@($Journal.entries)[0]) + @($HealthyEntries) + @(@($Journal.entries) | Select-Object -Skip 1)
    for ($index = 0; $index -lt $combined.Count; $index++) { $combined[$index].body.record_index = [uint64]$index }
    $Journal.entries = $combined
    $Journal.records = [uint64]$combined.Count
    return $Journal
}

function New-SelfTestFullHealthyCampaignJournal {
    param(
        [Parameter(Mandatory = $true)] [ValidateSet("BTCUSDT", "ETHUSDT")] [string] $Symbol,
        [Parameter(Mandatory = $true)] $FinalRawGeneration,
        [string] $CampaignStartupSha256 = ("6" * 64),
        [object[]] $RecurrentEvents = @(),
        [int] $DisconnectCount = 0,
        [int] $FailureCount = 0
    )
    $campaignId = [IO.Path]::GetFileName((Split-Path -Path (Split-Path -Path ([string]$FinalRawGeneration.session_directory) -Parent) -Parent))
    $setupBodies = [Collections.Generic.List[object]]::new()
    $null = $setupBodies.Add([ordered]@{ record_index = [uint64]0; generation_index = $null; channel = "CAMPAIGN"; payload = [ordered]@{ campaign_id = $campaignId; event = "CAMPAIGN_STARTED"; startup_sha256 = $CampaignStartupSha256 } })
    $null = $setupBodies.Add([ordered]@{ record_index = [uint64]1; generation_index = [uint64]0; channel = "CAMPAIGN"; payload = [ordered]@{ duration_s = [uint64]$FinalRawGeneration.telemetry.duration_requested_s; event = "GENERATION_LAUNCHED" } })
    $null = $setupBodies.Add([ordered]@{
        record_index = [uint64]2; generation_index = [uint64]0; channel = "CHILD_STDOUT"
        payload = [ordered]@{
            event = "PROCESS_STARTED"; generation_index = [uint64]0; process_id = [uint64]42; schema = "CaptureProcessEventV1"
            session_dir = [string]$FinalRawGeneration.session_directory; session_id = [string]$FinalRawGeneration.session_id
            spec_revision = [string]$FinalRawGeneration.spec_revision; startup_manifest_sha256 = [string]$FinalRawGeneration.startup_sha256; symbol = $Symbol
        }
    })
    $entries = [Collections.Generic.List[object]]::new()
    foreach ($body in $setupBodies) {
        $normalizedBody = $body | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json
        $null = $entries.Add([pscustomobject][ordered]@{ body = $normalizedBody; record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $normalizedBody) })
    }
    foreach ($transport in @($FinalRawGeneration.transports)) { $null = $entries.Add($transport.campaign_event) }
    $initialBody = [ordered]@{ record_index = [uint64]5; generation_index = [uint64]0; channel = "SUPERVISOR"; payload = [ordered]@{ event = "INITIAL_ACTIVE_REGISTERED" } }
    $normalizedInitialBody = $initialBody | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json
    $null = $entries.Add([pscustomobject][ordered]@{ body = $normalizedInitialBody; record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $normalizedInitialBody) })
    $null = $entries.Add($FinalRawGeneration.snapshot.campaign_event)
    foreach ($recurrent in @($RecurrentEvents)) {
        $clone = $recurrent | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json
        $clone.body.record_index = [uint64]$entries.Count
        $clone.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $clone.body)
        $null = $entries.Add($clone)
    }
    $causal = New-SelfTestCampaignJournal -DisconnectCount $DisconnectCount -FailureCount $FailureCount
    foreach ($causalEntry in @($causal.entries | Select-Object -Skip 1)) {
        $clone = $causalEntry | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json
        $clone.body.record_index = [uint64]$entries.Count
        if ([string]$clone.body.payload.event -ceq "GENERATION_DISCONNECT_FAIL_CLOSED") { $clone.body.payload.epoch = "epoch-$Symbol-depth" }
        $clone.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $clone.body)
        $null = $entries.Add($clone)
    }
    $previousSha = $script:FaultGateZeroDigest
    $journalBytes = [Collections.Generic.List[byte]]::new()
    for ($entryIndex = 0; $entryIndex -lt $entries.Count; $entryIndex++) {
        $oldBody = $entries[$entryIndex].body
        $body = [pscustomobject][ordered]@{
            schema = "RawCampaignJournalRecordV1"; record_index = [uint64]$entryIndex; wall_ns = [uint64]($entryIndex + 1); campaign_mono_ns = [uint64]$entryIndex
            generation_index = $oldBody.generation_index; channel = [string]$oldBody.channel; payload = $oldBody.payload; previous_record_sha256 = $previousSha
        }
        $envelope = [pscustomobject][ordered]@{ body = $body; record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $body) }
        $entries[$entryIndex] = $envelope
        [byte[]]$lineBytes = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $envelope)
        $journalBytes.AddRange($lineBytes); $journalBytes.Add([byte]10)
        $previousSha = [string]$envelope.record_sha256
        $event = [string]$body.payload.event
        if ($event -ceq "TRANSPORT_CONNECTED") {
            $transportRow = @($FinalRawGeneration.transports | Where-Object { [string]$_.stream -ceq [string]$body.payload.connection.stream })
            if ($transportRow.Count -ne 1) { throw "Self-test transport event is absent or ambiguous." }
            $transportRow[0].campaign_event = $envelope
        }
        elseif ($event -ceq "SNAPSHOT_DURABLE") { $FinalRawGeneration.snapshot.campaign_event = $envelope }
    }
    $journal = [pscustomobject][ordered]@{ records = [uint64]$entries.Count; entries = @($entries) }
    $journal | Add-Member -NotePropertyName terminal_record_sha256 -NotePropertyValue ([string]$entries[$entries.Count - 1].record_sha256)
    $journal | Add-Member -NotePropertyName file_bytes -NotePropertyValue ([uint64]$journalBytes.Count)
    $journal | Add-Member -NotePropertyName file_sha256 -NotePropertyValue (Get-FaultGateSha256Bytes -Bytes $journalBytes.ToArray())
    $journal | Add-Member -NotePropertyName raw_bytes -NotePropertyValue ([byte[]]$journalBytes.ToArray())
    return $journal
}

function New-SelfTestCampaignPrefixFromJournal {
    param(
        [Parameter(Mandatory = $true)] $Journal,
        [Parameter(Mandatory = $true)] [ValidateSet("BTCUSDT", "ETHUSDT")] [string] $Symbol,
        [Parameter(Mandatory = $true)] [uint64] $Records
    )
    $summary = Get-FaultGateSerdeJournalPrefixSummary -Journal $Journal -Records $Records -Label "self-test full healthy prefix"
    return ([ordered]@{
        symbol = $Symbol; records = $Records; clean_tail = $true
        terminal_record_sha256 = [string]$summary.terminal_record_sha256; file_sha256 = [string]$summary.file_sha256
    } | ConvertTo-Json -Compress | ConvertFrom-Json)
}

function Write-SelfTestCampaignJournalFixture {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [scriptblock] $Mutation
    )
    $bodies = @(
        [pscustomobject][ordered]@{ schema = "RawCampaignJournalRecordV1"; record_index = [uint64]0; wall_ns = [uint64]1; campaign_mono_ns = [uint64]10; generation_index = $null; channel = "CAMPAIGN"; payload = [pscustomobject][ordered]@{ event = "CAMPAIGN_STARTED" }; previous_record_sha256 = $script:FaultGateZeroDigest },
        [pscustomobject][ordered]@{ schema = "RawCampaignJournalRecordV1"; record_index = [uint64]1; wall_ns = [uint64]2; campaign_mono_ns = [uint64]20; generation_index = [uint64]0; channel = "CAMPAIGN"; payload = [pscustomobject][ordered]@{ event = "GENERATION_LAUNCHED" }; previous_record_sha256 = $script:FaultGateZeroDigest },
        [pscustomobject][ordered]@{ schema = "RawCampaignJournalRecordV1"; record_index = [uint64]2; wall_ns = [uint64]3; campaign_mono_ns = [uint64]30; generation_index = [uint64]0; channel = "CHILD_STDOUT"; payload = [pscustomobject][ordered]@{ event = "PROCESS_STARTED" }; previous_record_sha256 = $script:FaultGateZeroDigest }
    )
    if ($null -ne $Mutation) { & $Mutation $bodies }
    $previous = $script:FaultGateZeroDigest
    $builder = [Text.StringBuilder]::new()
    for ($index = 0; $index -lt $bodies.Count; $index++) {
        $bodies[$index].record_index = [uint64]$index
        $bodies[$index].previous_record_sha256 = $previous
        $digest = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $bodies[$index])
        $envelope = [ordered]@{ body = $bodies[$index]; record_sha256 = $digest }
        $null = $builder.Append(($envelope | ConvertTo-Json -Depth 100 -Compress)).Append([char]10)
        $previous = $digest
    }
    Write-SelfTestBytes -Path $Path -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($builder.ToString()))
}

function New-SelfTestControlArtifacts {
    param([Parameter(Mandatory = $true)] [string] $RepositoryRoot)
    $runId = "20260824T000000Z-dual-123456789abc"
    $qualificationBase = Join-Path $RepositoryRoot "gate\qualification"
    $runRoot = Join-Path $qualificationBase $runId
    $frequency = [uint64][Diagnostics.Stopwatch]::Frequency
    $jobName = "Local\BinanceRawQualificationJob-" + $runId
    $workloadJobName = "Local\BinanceRawQualificationWorkloadJob-" + $runId
    $environmentNames = @("SystemDrive", "SystemRoot", "TEMP", "TMP", "WINDIR")
    $environmentDigest = "a" * 64
    $processControl = [ordered]@{
        schema = "RawQualificationProcessControlV2"; run_id = $runId; job_object_name = $jobName; job_kill_on_close = $true
        workload_job_object_name = $workloadJobName; workload_job_kill_on_close = $true
        launch_method = "CREATE_SUSPENDED_ASSIGN_OUTER_AND_WORKLOAD_JOBS_RESUME"; child_environment_mode = "EXPLICIT_ALLOWLIST_NO_INHERITANCE"
        child_environment_names = $environmentNames; child_environment_entries_sha256 = $environmentDigest
        capture_origin_monotonic_tick = [uint64]200; launch_skew_ticks = [uint64]100; launch_skew_ms = [uint64]1; maximum_dual_launch_skew_ms = [uint64]5000
        watchdog = [ordered]@{
            pid = [uint64]30; job_name = $jobName; creation_time_utc = "2026-08-24T00:00:00Z"; executable_path = "C:\Windows\powershell.exe"
            executable_sha256 = "b" * 64; command_line = "watchdog"; script_path = (Join-Path $RepositoryRoot "scripts\RawQualification.Watchdog.ps1")
            script_sha256 = "c" * 64; launch_origin_qpc_timestamp = [uint64]1000; resume_qpc_timestamp = [uint64]1001
            monotonic_frequency = $frequency; startup_deadline_s = [uint64]90; guardian_pulse_file = "guardian-pulse.jsonl"
            maximum_guardian_pulse_age_s = [uint64]90; ready_file = "watchdog-ready.json"; ready_file_sha256 = "d" * 64
            ready_observed_qpc_timestamp = [uint64]1002; ready_pulse_length = [uint64]10; stdout_file = "watchdog.stdout.log"; stderr_file = "watchdog.stderr.log"
        }
        processes = @(
            [ordered]@{ symbol = "BTCUSDT"; pid = [uint64]10; creation_time_utc = "2026-08-24T00:00:01Z"; executable_path = "raw_campaign.exe"; executable_sha256 = "e" * 64; command_line = "btc"; launch_monotonic_tick = [uint64]100; stdout_file = "btcusdt.stdout.log"; stderr_file = "btcusdt.stderr.log" },
            [ordered]@{ symbol = "ETHUSDT"; pid = [uint64]20; creation_time_utc = "2026-08-24T00:00:02Z"; executable_path = "raw_campaign.exe"; executable_sha256 = "e" * 64; command_line = "eth"; launch_monotonic_tick = [uint64]200; stdout_file = "ethusdt.stdout.log"; stderr_file = "ethusdt.stderr.log" }
        )
    }
    $startup = [ordered]@{
        run_id = $runId; run_root = $runRoot; monotonic_frequency = $frequency
        preflight = [ordered]@{
            repo = $RepositoryRoot; output_base = $qualificationBase; drive_device_id = "C:"; free_gib = [uint64]1000; required_free_gib = [uint64]101
            disk_telemetry_preflight = [ordered]@{ device_id = "C:"; filesystem = "NTFS" }
            child_environment = [ordered]@{ mode = "EXPLICIT_ALLOWLIST_NO_INHERITANCE"; names = $environmentNames; entries_sha256 = $environmentDigest }
        }
        output_path_post_create = [ordered]@{ run_root_drive_device_id = "C:"; filesystem = "NTFS"; free_gib = [uint64]1000; required_free_gib = [uint64]101 }
        guardian_policy = [ordered]@{ maximum_dual_launch_skew_ms = [uint64]5000; watchdog_startup_deadline_s = [uint64]90; watchdog_deadline_s = [uint64]90 }
    }
    $bindings = [ordered]@{
        schema = "RawQualificationCampaignBindingsV1"; run_id = $runId; bound_utc = "2026-08-24T00:00:03Z"
        campaigns = @(
            [ordered]@{ symbol = "BTCUSDT"; pid = [uint64]10; campaign_id = "1-BTCUSDT-raw-111111111111"; campaign_directory = (Join-Path $runRoot "1-BTCUSDT-raw-111111111111"); campaign_startup_sha256 = "f" * 64 },
            [ordered]@{ symbol = "ETHUSDT"; pid = [uint64]20; campaign_id = "2-ETHUSDT-raw-222222222222"; campaign_directory = (Join-Path $runRoot "2-ETHUSDT-raw-222222222222"); campaign_startup_sha256 = "0" * 64 }
        )
    }
    $ready = [ordered]@{
        schema = "RawQualificationWatchdogReadyV1"; run_id = $runId; job_name = $jobName; pid = [uint64]30
        launch_origin_qpc_timestamp = [uint64]1000; observed_qpc_timestamp = [uint64]1002; monotonic_frequency = $frequency
        startup_deadline_s = [uint64]90; pulse_length = [uint64]10
    }
    return (([ordered]@{ startup = $startup; process_control = $processControl; bindings = $bindings; ready = $ready; repo = $RepositoryRoot; qualification_base = $qualificationBase; run_root = $runRoot; ready_sha256 = "d" * 64 } | ConvertTo-Json -Depth 30 -Compress) | ConvertFrom-Json)
}

function New-SelfTestHealthyMonitorReport {
    param([Parameter(Mandatory = $true)] [string] $RunRoot)
    $generation = {
        param([uint64] $DepthReceived, [uint64] $DepthDurable, [uint64] $TradeReceived, [uint64] $TradeDurable)
        [ordered]@{
            generation_index = [uint64]0; duration_s = [uint64]267; launch_wall_ns = [uint64]1787595560000000000; last_heartbeat_wall_ns = [uint64]1787595588000000000
            telemetry_mono_ns = [uint64]1000000000; depth_last_socket_activity_mono_ns = [uint64]900000000; depth_last_market_message_mono_ns = [uint64]850000000
            depth_market_message_age_ms = [double]150; trade_last_socket_activity_mono_ns = [uint64]800000000; trade_last_market_message_mono_ns = [uint64]750000000
            trade_market_message_age_ms = [double]250; depth_received = $DepthReceived; depth_durable = $DepthDurable
            trade_received = $TradeReceived; trade_durable = $TradeDurable; terminal = $false; terminal_wall_ns = [uint64]0
            exited = $false; exited_wall_ns = [uint64]0
        }
    }
    $campaign = {
        param([string] $Symbol, [string] $CampaignId, [uint64] $DepthReceived, [uint64] $DepthDurable, [uint64] $TradeReceived, [uint64] $TradeDurable)
        [ordered]@{
            symbol = $Symbol; campaign_id = $CampaignId; journal_records = [uint64]11; journal_bytes = [uint64]9000
            durable_heartbeat_age_s = [double]1; depth_received = $DepthReceived; depth_durable = $DepthDurable
            trade_received = $TradeReceived; trade_durable = $TradeDurable
            generation_market_health = @(& $generation $DepthReceived $DepthDurable $TradeReceived $TradeDurable)
            planned_generation_launches = [uint64]1; server_shutdown_generation_launches = [uint64]0; server_shutdown_events = [uint64]0
            campaign_elapsed_s = [uint64]40; campaign_heartbeat_age_s = [double]1; generations = [uint64]1; handovers_proven = [uint64]0
        }
    }
    $canonicalRoot = [IO.Path]::GetFullPath($RunRoot)
    $value = [ordered]@{
        schema = "RawQualificationReadOnlyMonitorV1"; status = "HEALTHY_RUNNING"; stage = "CAPTURING"; schedule_deviations = @()
        observed_utc = "2026-08-24T18:19:49.1474113+00:00"; run_id = [IO.Path]::GetFileName($canonicalRoot); run_root = $canonicalRoot; mode = "Test"
        parameters = [ordered]@{ total_s = [uint64]300; rotation_s = [uint64]240; overlap_s = [uint64]30; segment_s = [uint64]30 }
        launcher_journal_records = [uint64]6; launcher_journal_bytes = [uint64]3000; host_telemetry_records = [uint64]2
        host_telemetry_bytes = [uint64]15000; host_telemetry_age_s = [double]1; guardian_pulse_records = [uint64]6
        guardian_pulse_age_s = [double]1; guardian_stage = "CAPTURING"; disk_free_gib = [uint64]200
        clock = [ordered]@{
            healthy = $true; leap_indicator = [uint64]0; stratum = [uint64]2; source = "time.nist.gov,0x8"
            last_successful_sync = "8/24/2026 2:55:54 PM"; root_delay_s = [double]0.2; root_dispersion_s = [double]0.3
            phase_offset_s = [double]0.1; seconds_since_last_good_sync = [double]10; maximum_last_good_sync_age_s = [uint64]21600
            state_machine = [uint64]2; last_sync_error = [uint64]0; poll_interval_s = [uint64]1024
            raw_status_sha256 = "a" * 64; query_exit_code = [uint64]0
        }
        guardian = [ordered]@{ pid = [uint64]30; running = $true; exact_identity = $true }
        processes = @(
            [ordered]@{ symbol = "BTCUSDT"; pid = [uint64]10; running = $true; exact_identity = $true; pid_occupied = $true; pid_reused_after_exit = $false; clean_capture_exit_proven = $false },
            [ordered]@{ symbol = "ETHUSDT"; pid = [uint64]20; running = $true; exact_identity = $true; pid_occupied = $true; pid_reused_after_exit = $false; clean_capture_exit_proven = $false }
        )
        campaigns = @(
            (& $campaign "BTCUSDT" "1787595563269123700-BTCUSDT-raw-5ecbe98c9374" 177 130 1971 1967),
            (& $campaign "ETHUSDT" "1787595563303700300-ETHUSDT-raw-80b82ae0f114" 177 120 661 654)
        )
        current_terminal_reverification = @(); launcher_terminal_byte_authentication = "NOT_TERMINAL"
        inference_boundary = "self-test bound monitor semantics"
    }
    return (($value | ConvertTo-Json -Depth 30 -Compress) | ConvertFrom-Json)
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("BinanceRawFaultGateSelfTest-" + [Guid]::NewGuid().ToString("N"))
$tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$evidenceSandboxRoot = $null
$pssa = "NOT_RUN"
try {
    $null = New-Item -ItemType Directory -Path $tempRoot -ErrorAction Stop
    $harnessPath = Join-Path $PSScriptRoot "run_raw_fault_gate.ps1"
    $selfPath = $PSCommandPath
    foreach ($path in @($harnessPath, $selfPath)) {
        $tokens = $null; $errors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        Assert-SelfTest ($errors.Count -eq 0) ("AST parse errors: " + $path)
    }
    $harnessText = Get-Content -LiteralPath $harnessPath -Raw -Encoding UTF8
    Assert-SelfTest ((Add-FaultGateCheckedUInt64 -Left ([uint64]18446744073709551614) -Right 1 -Label "self-test checked add") -eq [uint64]::MaxValue) "Checked UInt64 add rejected its exact maximum."
    Assert-SelfTestThrows { $null = Add-FaultGateCheckedUInt64 -Left ([uint64]::MaxValue) -Right 1 -Label "self-test checked add overflow" } "UInt64 checked add maximum plus one"
    Assert-SelfTest ((Get-FaultGateUInt64Successor -Value ([uint64]18446744073709551614) -Label "self-test successor") -eq [uint64]::MaxValue) "Checked UInt64 successor rejected its exact maximum."
    Assert-SelfTestThrows { $null = Get-FaultGateUInt64Successor -Value ([uint64]::MaxValue) -Label "self-test successor overflow" } "UInt64 successor maximum plus one"
    Assert-SelfTest ((Get-FaultGateInclusiveLastUInt64 -First ([uint64]::MaxValue) -Count 1 -Label "self-test inclusive last") -eq [uint64]::MaxValue) "Checked inclusive-last rejected a one-record maximum boundary."
    Assert-SelfTestThrows { $null = Get-FaultGateInclusiveLastUInt64 -First ([uint64]::MaxValue) -Count 2 -Label "self-test inclusive last overflow" } "UInt64 inclusive-last maximum plus one"
    Assert-SelfTest ((Get-FaultGateInclusiveCountUInt64 -First ([uint64]::MaxValue) -Last ([uint64]::MaxValue) -Label "self-test inclusive count") -eq 1) "Checked inclusive-count rejected its exact maximum singleton."
    Assert-SelfTestThrows { $null = Get-FaultGateInclusiveCountUInt64 -First 0 -Last ([uint64]::MaxValue) -Label "self-test inclusive count overflow" } "UInt64 inclusive-count unrepresentable maximum span"
    Assert-SelfTest ((Multiply-FaultGateCheckedUInt64 -Left ([uint64]::MaxValue) -Right 1 -Label "self-test checked multiply") -eq [uint64]::MaxValue) "Checked UInt64 multiply rejected its exact maximum."
    Assert-SelfTestThrows { $null = Multiply-FaultGateCheckedUInt64 -Left ([uint64]::MaxValue) -Right 2 -Label "self-test checked multiply overflow" } "UInt64 checked multiply maximum times two"
    Assert-SelfTest ((Subtract-FaultGateCheckedUInt64 -Left ([uint64]::MaxValue) -Right ([uint64]18446744073709551614) -Label "self-test checked subtract") -eq 1) "Checked UInt64 subtraction rejected its exact maximum boundary."
    Assert-SelfTestThrows { $null = Subtract-FaultGateCheckedUInt64 -Left 0 -Right 1 -Label "self-test checked subtract underflow" } "UInt64 checked subtraction zero minus one"
    $jsonAboveI64 = ('{"value":9223372036854775808}' | ConvertFrom-Json).value
    $jsonU64Maximum = ('{"value":18446744073709551615}' | ConvertFrom-Json).value
    Assert-SelfTest ($jsonAboveI64 -is [decimal] -and (Get-FaultGateJsonUnsignedInteger -Value $jsonAboveI64 -Label "self-test JSON u64 above i64") -eq [uint64]9223372036854775808) "PowerShell Decimal JSON u64 above Int64 was rejected or rounded."
    Assert-SelfTest ($jsonU64Maximum -is [decimal] -and (Get-FaultGateJsonUnsignedInteger -Value $jsonU64Maximum -Label "self-test JSON u64 maximum") -eq [uint64]::MaxValue) "PowerShell Decimal JSON UInt64 maximum was rejected or rounded."
    Assert-SelfTest ((ConvertTo-FaultGateSerdeCompactJsonText -Value ([pscustomobject][ordered]@{ value = $jsonU64Maximum })) -ceq '{"value":18446744073709551615}') "Serde JSON UInt64 maximum round-trip was not byte exact."
    $jsonU64Overflow = ('{"value":18446744073709551616}' | ConvertFrom-Json).value
    $jsonScaledInteger = ('{"value":9223372036854775808.0}' | ConvertFrom-Json).value
    $jsonFraction = ('{"value":1.5}' | ConvertFrom-Json).value
    $jsonExponent = ('{"value":1e0}' | ConvertFrom-Json).value
    Assert-SelfTestThrows { $null = Get-FaultGateJsonUnsignedInteger -Value $jsonU64Overflow -Label "self-test JSON u64 overflow" } "JSON UInt64 maximum plus one"
    Assert-SelfTestThrows { $null = Get-FaultGateJsonUnsignedInteger -Value $jsonScaledInteger -Label "self-test scaled JSON integer" } "JSON integer expressed with decimal scale"
    Assert-SelfTestThrows { $null = Get-FaultGateJsonUnsignedInteger -Value $jsonFraction -Label "self-test JSON fraction" } "JSON fractional Decimal as unsigned integer"
    Assert-SelfTestThrows { $null = Get-FaultGateJsonUnsignedInteger -Value $jsonExponent -Label "self-test JSON exponent" } "JSON exponent as unsigned integer"
    Assert-SelfTestThrows { $null = ConvertTo-FaultGateSerdeCompactJsonText -Value $jsonScaledInteger } "Serde scaled Decimal integer"
    Assert-SelfTestThrows { $null = ConvertTo-FaultGateSerdeCompactJsonText -Value $jsonU64Overflow } "Serde UInt64 overflow Decimal"
    Assert-SelfTest (-not $harnessText.Contains("LastWriteTime")) "Harness uses timestamp selection."
    Assert-SelfTest (-not $harnessText.Contains("Stop-Process") -and -not $harnessText.Contains("taskkill")) "Harness uses an unbound destructive process primitive."
    Assert-SelfTest (-not [regex]::IsMatch($harnessText, '\[string\]\$_\.CommandLine\.IndexOf') -and
        $harnessText.Contains('function Test-FaultGateRunRootCommandLine') -and
        $harnessText.Contains('Get-CimInstance Win32_Process -OperationTimeoutSec $OperationTimeoutSeconds') -and
        -not [regex]::IsMatch($harnessText, 'Get-CimInstance\s+Win32_Process(?![^\r\n]*-OperationTimeoutSec)') -and
        [regex]::Matches($harnessText, '\$terminalProcessSnapshot\s*=\s*@\(Get-FaultGateProcessSnapshot\)').Count -eq 1 -and
        [regex]::Matches($harnessText, '\$postProposalProcessSnapshot\s*=\s*@\(Get-FaultGateProcessSnapshot\)').Count -eq 1) "Process identity/census retains the cast-precedence bug, an unbounded CIM call, or reused pre/post snapshots."
    $predicateRunRoot = "C:\selftest\run-root"
    Assert-SelfTest (-not (Test-FaultGateRunRootCommandLine -CommandLine $null -RunRoot $predicateRunRoot) -and
        -not (Test-FaultGateRunRootCommandLine -CommandLine "" -RunRoot $predicateRunRoot) -and
        -not (Test-FaultGateRunRootCommandLine -CommandLine "powershell.exe -File unrelated.ps1" -RunRoot $predicateRunRoot)) "Run-root command-line predicate classified null/empty/unrelated input as a match."
    Assert-SelfTest ((Test-FaultGateRunRootCommandLine -CommandLine ("worker.exe --root `"" + $predicateRunRoot + "`"") -RunRoot $predicateRunRoot) -and
        (Test-FaultGateRunRootCommandLine -CommandLine ("worker.exe --root `"" + $predicateRunRoot.ToUpperInvariant() + "`"") -RunRoot $predicateRunRoot)) "Run-root command-line predicate rejected exact/case-insensitive matches."
    Assert-SelfTestThrows { $null = Test-FaultGateRunRootCommandLine -CommandLine $null -RunRoot " " } "empty run-root predicate authority"
    Assert-SelfTestThrows {
        $unrelatedIndex = "powershell.exe -File unrelated.ps1".IndexOf($predicateRunRoot, [StringComparison]::OrdinalIgnoreCase)
        if ([string]$unrelatedIndex -ge 0) { throw "Exact cast-precedence mutant reproduced." }
    } "PowerShell string-cast IndexOf mutant"
    $syntheticProcessSnapshot = @(
        [pscustomobject]@{ ProcessId = [uint32]101; ParentProcessId = [uint32]1; Name = "unrelated.exe"; CreationDate = [DateTime]::UtcNow; ExecutablePath = "C:\unrelated.exe"; CommandLine = "unrelated.exe --safe" },
        [pscustomobject]@{ ProcessId = [uint32]102; ParentProcessId = [uint32]1; Name = "powershell.exe"; CreationDate = [DateTime]::UtcNow; ExecutablePath = "C:\powershell.exe"; CommandLine = ("powershell.exe -RunRoot `"" + $predicateRunRoot + "`"") }
    )
    $syntheticRunBound = @(Get-FaultGateRunBoundProcesses -ProcessSnapshot $syntheticProcessSnapshot -RunRoot $predicateRunRoot)
    Assert-SelfTest ($syntheticRunBound.Count -eq 1 -and [uint64]$syntheticRunBound[0].ProcessId -eq 102) "Common process snapshot did not select exactly the run-bound synthetic identity."
    $syntheticDiagnostic = Get-FaultGateProcessBlockerDiagnostic -Processes $syntheticRunBound
    Assert-SelfTest ($syntheticDiagnostic.Contains('"pid":102') -and
        -not $syntheticDiagnostic.Contains($predicateRunRoot)) "Sanitized blocker diagnostic omitted identity or leaked the raw command line."
    Assert-SelfTest ($harnessText.Contains("FAILURE_CONTAINMENT_TERMINAL") -and $harnessText.Contains("RawQualificationFaultEvidenceV3")) "Harness lacks exact A/B or evidence schema."
    $evidenceProposedProducerStart = $harnessText.IndexOf('$null = Add-FaultGateEvent -Journal $faultJournal -Event "EVIDENCE_PROPOSED"', [StringComparison]::Ordinal)
    $evidenceProposedProducerEnd = if ($evidenceProposedProducerStart -ge 0) { $harnessText.IndexOf('$gateStage = "PUBLISHING_PASS_EVIDENCE"', $evidenceProposedProducerStart, [StringComparison]::Ordinal) } else { -1 }
    Assert-SelfTest ($evidenceProposedProducerStart -ge 0 -and $evidenceProposedProducerEnd -gt $evidenceProposedProducerStart) "Harness lacks one bounded EVIDENCE_PROPOSED producer block."
    $evidenceProposedProducerText = $harnessText.Substring($evidenceProposedProducerStart, $evidenceProposedProducerEnd - $evidenceProposedProducerStart)
    $evidenceProposedProducerFields = @(
        'run_id', 'terminal_sha256', 'containment_sha256', 'launcher_journal_terminal_sha256', 'process_observation',
        'outer_active_processes', 'global_engine_processes', 'run_bound_processes', 'inner_job_exists', 'inner_job_open_error',
        'workload_job_exists', 'workload_job_open_error'
    )
    $evidenceProposedPreviousIndex = -1
    foreach ($evidenceProposedField in $evidenceProposedProducerFields) {
        $evidenceProposedFieldMatches = [regex]::Matches($evidenceProposedProducerText, ('(?<![A-Za-z0-9_])' + [regex]::Escape($evidenceProposedField) + '\s*='))
        $evidenceProposedFieldIndex = if ($evidenceProposedFieldMatches.Count -eq 1) { $evidenceProposedFieldMatches[0].Index } else { -1 }
        Assert-SelfTest ($evidenceProposedFieldIndex -gt $evidenceProposedPreviousIndex -and $evidenceProposedFieldMatches.Count -eq 1) `
            ("EVIDENCE_PROPOSED producer field is missing, duplicated, or reordered: " + $evidenceProposedField)
        $evidenceProposedPreviousIndex = $evidenceProposedFieldIndex
    }
    Assert-SelfTest ($harnessText.Contains("TerminateProcess_RETAINED_HANDLE") -and $harnessText.Contains("0xEE31")) "Harness lacks exact retained-handle injection."
    Assert-SelfTest ($harnessText.Contains("CreateKillOnCloseJob") -and $harnessText.Contains("outer_active_processes")) "Harness lacks external Job containment."
    Assert-SelfTest (-not [regex]::IsMatch($harnessText, '(?im)^\s*&\s*\$python') -and -not [regex]::IsMatch($harnessText, '(?i)Start-Process[^\r\n]*python')) "Fault gate invokes the Python verifier instead of only retaining/fingerprinting its runtime."
    Assert-SelfTest ($harnessText.Contains('Invoke-RawQualificationFaultGate -StartupDeadlineSeconds $StartupDeadlineSeconds')) "Direct invocation drops script defaults."
    Assert-SelfTest ($harnessText.Contains('[ValidateRange(1, 7)]') -and $harnessText.Contains('-LivePrefixObservation') -and
        $harnessText.Contains('Test-FaultGatePreInjectionCampaignWindow -Journal $postScanJournal -PreFaultPrefix $scanPrefix')) "Harness does not enforce its bounded raw-prefix/live generation-0 suffix boundary."
    Assert-SelfTest ([regex]::Matches($harnessText, 'Read-FaultGateSnapshotBytes -Path \$nextAckPath').Count -eq 1 -and
        $harnessText.Contains('Read-FaultGateProgress -Path $nextAckPath') -and
        $harnessText.Contains('[byte[]]$ackBytes = @(Read-FaultGateSnapshotBytes -Path $nextAckPath)') -and
        $harnessText.Contains('-AllowPartialTail -SnapshotBytes $ackBytes')) "Live BNACK classification and validation do not share one immutable byte snapshot, including its valid empty state."
    Assert-SelfTest ($harnessText.Contains('$ackBytes.Length -gt $script:FaultGateMaximumProgressPartialTailBytes') -and
        $harnessText.Contains('orphan active BNACK without its preceding BNRAW') -and
        $harnessText.Contains('$Segment.sole_partial_file -cne $expectedRawFile')) "Live/terminal evidence does not bound BNACK tails or reject orphan ACK artifacts."
    Assert-SelfTest ($harnessText.Contains('function Get-FaultGateVerifiedDepthConnectionEpoch') -and
        $harnessText.Contains('$depthConnectionEpoch = Get-FaultGateVerifiedDepthConnectionEpoch -Generation $rawReport -Symbol $symbol') -and
        -not $harnessText.Contains('Where-Object { $null -ne $_.raw }')) "Final causality still reads an optional recovery-tail raw property or bypasses sealed depth epoch authority."
    $depthEpochFixture = New-SelfTestEvidenceGeneration -Symbol "BTCUSDT" -RunRoot $tempRoot
    $depthEpochFixture = $depthEpochFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $depthEpochStream = @($depthEpochFixture.streams | Where-Object { [string]$_.stream -ceq "depth" })[0]
    $depthEpochStream.verified_segments = @($depthEpochStream.verified_segments) + @([pscustomobject][ordered]@{
        segment_index = [uint64]1; sealed = $false; durable_prefix = $false
        sole_partial_file = "segment-000001.bnraw"; sole_partial_file_bytes = [uint64]17; sole_partial_file_sha256 = "9" * 64
    })
    Assert-SelfTest ((Get-FaultGateVerifiedDepthConnectionEpoch -Generation $depthEpochFixture -Symbol "BTCUSDT") -ceq "epoch-BTCUSDT-depth") "A valid sole-BNRAW recovery tail prevented deterministic sealed depth epoch derivation."
    $opaqueTailFixture = $depthEpochFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $opaqueTailFixture.streams[0].verified_segments[1] = [pscustomobject][ordered]@{
        segment_index = [uint64]1; sealed = $false; durable_prefix = $false
        raw_file_bytes = [uint64]17; raw_file_sha256 = "8" * 64
        progress_file_bytes = [uint64]0; progress_file_sha256 = "9" * 64
    }
    Assert-SelfTest ((Get-FaultGateVerifiedDepthConnectionEpoch -Generation $opaqueTailFixture -Symbol "BTCUSDT") -ceq "epoch-BTCUSDT-depth") "The observed BNRAW/empty-BNACK recovery-tail shape prevented sealed depth epoch derivation."
    $activeDurableFixture = New-SelfTestEvidenceGeneration -Symbol "BTCUSDT" -RunRoot $tempRoot
    $activeDurableFixture = $activeDurableFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $activeDurableDepth = @($activeDurableFixture.streams | Where-Object { [string]$_.stream -ceq "depth" })[0]
    $activeDurableDepth.verified_segments = @($activeDurableDepth.verified_segments) + @(
        New-SelfTestActiveDurableSegment -SealedSegment $activeDurableDepth.verified_segments[0] -SegmentIndex 1 -ConnectionEpoch "epoch-BTCUSDT-depth"
    )
    Assert-SelfTest ((Get-FaultGateVerifiedDepthConnectionEpoch -Generation $activeDurableFixture -Symbol "BTCUSDT") -ceq "epoch-BTCUSDT-depth") "A valid active durable depth prefix was not included in the common authoritative epoch."
    $activeDurableDivergence = New-SelfTestEvidenceGeneration -Symbol "BTCUSDT" -RunRoot $tempRoot
    $activeDurableDivergence = $activeDurableDivergence | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $activeDivergentDepth = @($activeDurableDivergence.streams | Where-Object { [string]$_.stream -ceq "depth" })[0]
    $activeDivergentDepth.verified_segments = @($activeDivergentDepth.verified_segments) + @(
        New-SelfTestActiveDurableSegment -SealedSegment $activeDivergentDepth.verified_segments[0] -SegmentIndex 1 -ConnectionEpoch "epoch-divergent"
    )
    Assert-SelfTestThrows { $null = Get-FaultGateVerifiedDepthConnectionEpoch -Generation $activeDurableDivergence -Symbol "BTCUSDT" } "active durable/sealed depth epoch divergence"
    $rawEpochMismatch = $depthEpochFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $rawEpochMismatch.streams[0].verified_segments[0].raw.connection_epoch = "epoch-divergent"
    Assert-SelfTestThrows { $null = Get-FaultGateVerifiedDepthConnectionEpoch -Generation $rawEpochMismatch -Symbol "BTCUSDT" } "sealed depth raw/transport epoch divergence"
    $ambiguousDepthTransport = $depthEpochFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $ambiguousDepthTransport.transports = @($ambiguousDepthTransport.transports) + @($ambiguousDepthTransport.transports[0])
    Assert-SelfTestThrows { $null = Get-FaultGateVerifiedDepthConnectionEpoch -Generation $ambiguousDepthTransport -Symbol "BTCUSDT" } "ambiguous depth transport authority"
    $noSealedDepth = $depthEpochFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $noSealedDepth.streams[0].verified_segments = @([pscustomobject][ordered]@{
        segment_index = [uint64]0; sealed = $false; durable_prefix = $false
        sole_partial_file = "segment-000000.bnraw"; sole_partial_file_bytes = [uint64]17; sole_partial_file_sha256 = "9" * 64
    })
    Assert-SelfTestThrows { $null = Get-FaultGateVerifiedDepthConnectionEpoch -Generation $noSealedDepth -Symbol "BTCUSDT" } "missing authoritative sealed depth segment"
    Assert-SelfTest (-not [regex]::IsMatch($harnessText, 'GetProcessExitCode\([^\r\n]+\)\s*-(?:eq|ne)\s*259')) "Harness treats ambiguous STILL_ACTIVE exit code 259 as process liveness."
    Assert-SelfTest ($harnessText.Contains('FAULT_INJECTION_REQUESTED') -and $harnessText.Contains('InjectionRequestedWallNs $injectionRequestedWallNs') -and
        $harnessText.Contains('MANIFEST_SNAPSHOT_BOUNDED_SEALED_SEGMENTS_AND_DURABLE_PREFIXES_OBSERVED_AFTER_FROZEN_PRE_FAULT_CAMPAIGN_PREFIX')) "Harness lacks the exact pre-request boundary and honest raw-observation scope."
    $bootstrapLocalBarrierText = '$fullPath = Assert-FaultGateBootstrapNoReparsePointInExistingPath -Path $Path'
    $bootstrapOpenIndex = $harnessText.IndexOf('$harnessSourceBinding = Open-FaultGateRetainedPathBinding -Path $PSCommandPath -Role "harness"', [StringComparison]::Ordinal)
    $bootstrapDotSourceIndex = $harnessText.IndexOf('. $helperScript', [StringComparison]::Ordinal)
    $bootstrapHelperCrossCheckIndex = $harnessText.IndexOf('$helperPath = Assert-RawQualificationNoReparsePointInExistingPath -Path ([string]$bootstrapBinding.path)', [StringComparison]::Ordinal)
    Assert-SelfTest ($harnessText.Contains($bootstrapLocalBarrierText) -and $bootstrapOpenIndex -ge 0 -and
        $bootstrapDotSourceIndex -gt $bootstrapOpenIndex -and $bootstrapHelperCrossCheckIndex -gt $bootstrapDotSourceIndex) "Bootstrap retained-binding/local-barrier/helper-cross-check order is invalid."
    Assert-SelfTest ($harnessText.Contains('status = "BOOTSTRAP_ONLY_NOT_FAULT_GATE"') -and
        $harnessText.Contains('retained_bindings_closed = $true') -and $harnessText.Contains('-BootstrapValidateOnly:$BootstrapValidateOnly')) "Harness lacks its explicit non-fault bootstrap-only entrypoint contract."
    $retainedOpenStart = $harnessText.IndexOf('function Open-FaultGateRetainedPathBinding {', [StringComparison]::Ordinal)
    $retainedOpenEnd = $harnessText.IndexOf('function Test-FaultGateRetainedPathBinding {', [StringComparison]::Ordinal)
    Assert-SelfTest ($retainedOpenStart -ge 0 -and $retainedOpenEnd -gt $retainedOpenStart) "Retained path-binding function boundaries are absent."
    $retainedOpenText = $harnessText.Substring($retainedOpenStart, $retainedOpenEnd - $retainedOpenStart)
    $retainedOpenLimitIndex = $retainedOpenText.IndexOf('$observedLength -gt $MaximumBytes', [StringComparison]::Ordinal)
    $retainedOpenHashIndex = $retainedOpenText.IndexOf('$sha.ComputeHash($stream)', [StringComparison]::Ordinal)
    Assert-SelfTest ($retainedOpenLimitIndex -ge 0 -and $retainedOpenHashIndex -gt $retainedOpenLimitIndex) "Retained path open-time byte bound is not enforced before full-file hashing."

    $healthyMonitor = New-SelfTestHealthyMonitorReport -RunRoot $tempRoot
    $expectedMonitorProcesses = @($healthyMonitor.processes)
    $expectedMonitorCampaigns = @($healthyMonitor.campaigns)
    Assert-SelfTest (-not ($healthyMonitor.campaigns[0].PSObject.Properties.Name -ccontains "ready") -and
        (Test-FaultGateHealthyMonitorReport -Monitor $healthyMonitor -ExpectedRunRoot $tempRoot `
            -ExpectedGuardianPid 30 -ExpectedProcesses $expectedMonitorProcesses -ExpectedCampaigns $expectedMonitorCampaigns `
            -ExpectedMinimumDiskFreeGiB 101)) `
        "Current HEALTHY monitor schema without the obsolete campaign.ready field was rejected."
    [byte[]]$canonicalMonitorBytes = [Text.UTF8Encoding]::new($false).GetBytes((($healthyMonitor | ConvertTo-Json -Depth 100) + "`r`n"))
    Assert-FaultGateCanonicalMonitorReportBytes -Bytes $canonicalMonitorBytes -Monitor $healthyMonitor
    $script:FaultSelfTestPassed++
    Assert-SelfTestThrows {
        $null = Assert-FaultGateCanonicalMonitorReportBytes `
            -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($healthyMonitor | ConvertTo-Json -Depth 100) + "`n"))) `
            -Monitor $healthyMonitor
    } "monitor stdout LF instead of exact redirected CRLF framing"
    Assert-SelfTestThrows {
        [byte[]]$prefixedMonitorBytes = [byte[]]::new($canonicalMonitorBytes.Length + 1)
        $prefixedMonitorBytes[0] = 32
        [Array]::Copy($canonicalMonitorBytes, 0, $prefixedMonitorBytes, 1, $canonicalMonitorBytes.Length)
        $null = Assert-FaultGateCanonicalMonitorReportBytes -Bytes $prefixedMonitorBytes -Monitor $healthyMonitor
    } "monitor stdout non-canonical leading byte"
    $ninetySecondGuardianMonitor = (($healthyMonitor | ConvertTo-Json -Depth 30 -Compress) | ConvertFrom-Json)
    $ninetySecondGuardianMonitor.guardian_pulse_age_s = [double]90
    Assert-SelfTest (Test-FaultGateHealthyMonitorReport -Monitor $ninetySecondGuardianMonitor -ExpectedRunRoot $tempRoot `
            -ExpectedGuardianPid 30 -ExpectedProcesses $expectedMonitorProcesses -ExpectedCampaigns $expectedMonitorCampaigns `
            -ExpectedMinimumDiskFreeGiB 101) `
        "Monitor-valid 90-second guardian watchdog boundary was rejected."
    foreach ($monitorMutation in @(
        "extra_ready", "extra_ready_string", "missing_campaign_field", "duplicate_symbol", "duplicate_pid", "guardian_pid", "process_identity",
        "campaign_id", "wrong_mode", "wrong_parameters", "launcher_records", "disk_below_reserve", "stale_host", "stale_guardian",
        "clock_shape", "clock_state", "numeric_coercion", "durable_ahead", "generation_count", "shutdown_event", "terminal_generation",
        "generation_counter_mismatch", "campaign_at_rotation", "generation_at_end", "wrong_duration", "market_age", "heartbeat_chronology",
        "observed_drift", "wrong_root", "wrong_status"
    )) {
        $monitorMutant = (($healthyMonitor | ConvertTo-Json -Depth 30 -Compress) | ConvertFrom-Json)
        switch ($monitorMutation) {
            "extra_ready" { $monitorMutant.campaigns[0] | Add-Member -NotePropertyName ready -NotePropertyValue $true }
            "extra_ready_string" { $monitorMutant.campaigns[0] | Add-Member -NotePropertyName ready -NotePropertyValue "false" }
            "missing_campaign_field" { $monitorMutant.campaigns[0].PSObject.Properties.Remove("campaign_heartbeat_age_s") }
            "duplicate_symbol" { $monitorMutant.campaigns[1].symbol = "BTCUSDT" }
            "duplicate_pid" { $monitorMutant.processes[1].pid = [uint64]10 }
            "guardian_pid" { $monitorMutant.guardian.pid = [uint64]31 }
            "process_identity" { $monitorMutant.processes[0].exact_identity = $false }
            "campaign_id" { $monitorMutant.campaigns[0].campaign_id = "1787595563269123700-BTCUSDT-raw-aaaaaaaaaaaa" }
            "wrong_mode" { $monitorMutant.mode = "Production" }
            "wrong_parameters" { $monitorMutant.parameters.rotation_s = [uint64]241 }
            "launcher_records" { $monitorMutant.launcher_journal_records = [uint64]5 }
            "disk_below_reserve" { $monitorMutant.disk_free_gib = [uint64]100 }
            "stale_host" { $monitorMutant.host_telemetry_age_s = [double]121 }
            "stale_guardian" { $monitorMutant.guardian_pulse_age_s = [double]90.001 }
            "clock_shape" { $monitorMutant.clock.PSObject.Properties.Remove("raw_status_sha256") }
            "clock_state" { $monitorMutant.clock.state_machine = [uint64]1 }
            "numeric_coercion" { $monitorMutant.campaigns[0].depth_received = "177" }
            "durable_ahead" { $monitorMutant.campaigns[0].depth_durable = [uint64]178 }
            "generation_count" { $monitorMutant.campaigns[0].generations = [uint64]2 }
            "shutdown_event" { $monitorMutant.campaigns[0].server_shutdown_events = [uint64]1 }
            "terminal_generation" { $monitorMutant.campaigns[0].generation_market_health[0].terminal = $true }
            "generation_counter_mismatch" { $monitorMutant.campaigns[0].generation_market_health[0].trade_received = [uint64]1970 }
            "campaign_at_rotation" { $monitorMutant.campaigns[0].campaign_elapsed_s = [uint64]240 }
            "generation_at_end" {
                $monitorMutant.campaigns[0].generation_market_health[0].telemetry_mono_ns = [uint64]267000000000
                $monitorMutant.campaigns[0].generation_market_health[0].depth_last_socket_activity_mono_ns = [uint64]266900000000
                $monitorMutant.campaigns[0].generation_market_health[0].depth_last_market_message_mono_ns = [uint64]266850000000
                $monitorMutant.campaigns[0].generation_market_health[0].trade_last_socket_activity_mono_ns = [uint64]266800000000
                $monitorMutant.campaigns[0].generation_market_health[0].trade_last_market_message_mono_ns = [uint64]266750000000
            }
            "wrong_duration" { $monitorMutant.campaigns[0].generation_market_health[0].duration_s = [uint64]266 }
            "market_age" { $monitorMutant.campaigns[0].generation_market_health[0].depth_market_message_age_ms = [double]149 }
            "heartbeat_chronology" { $monitorMutant.campaigns[0].generation_market_health[0].last_heartbeat_wall_ns = [uint64]1 }
            "observed_drift" { $monitorMutant.observed_utc = "2000-01-01T00:00:00.0000000+00:00" }
            "wrong_root" { $monitorMutant.run_root = Join-Path $tempRoot "drift" }
            "wrong_status" { $monitorMutant.status = "COMPLETE" }
        }
        Assert-SelfTestThrows {
            $null = Test-FaultGateHealthyMonitorReport -Monitor $monitorMutant -ExpectedRunRoot $tempRoot `
                -ExpectedGuardianPid 30 -ExpectedProcesses $expectedMonitorProcesses -ExpectedCampaigns $expectedMonitorCampaigns `
                -ExpectedMinimumDiskFreeGiB 101
        } ("healthy monitor contract " + $monitorMutation)
    }

    $bootstrapOutputBase = "artifacts/qualification-fault-gates/bootstrap-selftest-" + [Guid]::NewGuid().ToString("N")
    $bootstrapOutputPath = Join-Path (Split-Path $PSScriptRoot -Parent) $bootstrapOutputBase
    Assert-SelfTest (-not (Test-Path -LiteralPath $bootstrapOutputPath)) "Bootstrap self-test output path pre-existed."
    $bootstrapEnginesBefore = @(Get-FaultGateEngineProcesses)
    Assert-SelfTest ($bootstrapEnginesBefore.Count -eq 0) "Bootstrap self-test requires no pre-existing engine process."
    $bootstrapResult = Invoke-SelfTestBootstrapEntrypoint -ScriptPath $harnessPath -WorkingDirectory (Split-Path $PSScriptRoot -Parent) -ArtifactRoot $tempRoot -Name "bootstrap-real" -OutputBase $bootstrapOutputBase
    Assert-SelfTest ([uint32]$bootstrapResult.exit_code -eq 0 -and [uint64]$bootstrapResult.stdout_bytes -gt 0 -and [uint64]$bootstrapResult.stderr_bytes -eq 0) "Real bootstrap-only entrypoint failed its exit/stdout/stderr contract."
    $bootstrapValue = [string]$bootstrapResult.stdout_text | ConvertFrom-Json -ErrorAction Stop
    Assert-FaultGateExactProperties -Value $bootstrapValue -Names @("schema", "status", "fault_gate_executed", "network_started", "evidence_published", "retained_bindings_closed", "bindings") -Label "bootstrap-only result"
    $bootstrapFaultExecuted = Get-FaultGateJsonBoolean -Value $bootstrapValue.fault_gate_executed -Label "bootstrap-only fault gate flag"
    $bootstrapNetworkStarted = Get-FaultGateJsonBoolean -Value $bootstrapValue.network_started -Label "bootstrap-only network flag"
    $bootstrapEvidencePublished = Get-FaultGateJsonBoolean -Value $bootstrapValue.evidence_published -Label "bootstrap-only evidence flag"
    $bootstrapBindingsClosed = Get-FaultGateJsonBoolean -Value $bootstrapValue.retained_bindings_closed -Label "bootstrap-only closed flag"
    Assert-SelfTest ([string]$bootstrapValue.schema -ceq "RawQualificationFaultGateBootstrapValidationV1" -and
        [string]$bootstrapValue.status -ceq "BOOTSTRAP_ONLY_NOT_FAULT_GATE" -and [string]$bootstrapValue.status -cne "PASS" -and
        -not $bootstrapFaultExecuted -and -not $bootstrapNetworkStarted -and -not $bootstrapEvidencePublished -and $bootstrapBindingsClosed) "Bootstrap-only result overclaims execution, network, evidence, or PASS."
    Assert-FaultGateJsonArray -Value $bootstrapValue.bindings -Label "bootstrap-only bindings"
    $bootstrapRows = @($bootstrapValue.bindings)
    Assert-SelfTest ($bootstrapRows.Count -eq 2) "Bootstrap-only result did not publish exactly harness/helper bindings."
    $bootstrapExpectedPaths = @($harnessPath, (Join-Path $PSScriptRoot "RawQualification.Windows.ps1"))
    $bootstrapExpectedRoles = @("harness", "helper")
    Initialize-FaultGateNative
    for ($bootstrapIndex = 0; $bootstrapIndex -lt 2; $bootstrapIndex++) {
        $bootstrapRow = $bootstrapRows[$bootstrapIndex]
        Assert-FaultGateExactProperties -Value $bootstrapRow -Names @("role", "path", "length", "sha256", "volume_serial_number", "file_index") -Label "bootstrap-only binding"
        $bootstrapRowLength = Get-FaultGateJsonUnsignedInteger -Value $bootstrapRow.length -Label "bootstrap-only binding length"
        $bootstrapRowVolume = Get-FaultGateJsonUnsignedInteger -Value $bootstrapRow.volume_serial_number -Label "bootstrap-only binding volume" -Maximum ([uint32]::MaxValue)
        $bootstrapRowFileIndex = Get-FaultGateJsonUnsignedInteger -Value $bootstrapRow.file_index -Label "bootstrap-only binding file index"
        Assert-FaultGateEvidenceDigest -Value $bootstrapRow.sha256 -Label "bootstrap-only binding digest"
        $expectedBootstrapPath = [IO.Path]::GetFullPath($bootstrapExpectedPaths[$bootstrapIndex])
        $bootstrapIdentityStream = [IO.FileStream]::new($expectedBootstrapPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try { $bootstrapIndependentIdentity = [RawFaultGateNative]::GetFileIdentity($bootstrapIdentityStream.SafeFileHandle.DangerousGetHandle()) }
        finally { $bootstrapIdentityStream.Dispose() }
        Assert-SelfTest ([string]$bootstrapRow.role -ceq $bootstrapExpectedRoles[$bootstrapIndex] -and
            [IO.Path]::GetFullPath([string]$bootstrapRow.path).Equals($expectedBootstrapPath, [StringComparison]::OrdinalIgnoreCase) -and
            $bootstrapRowLength -eq [uint64](Get-Item -LiteralPath $expectedBootstrapPath -ErrorAction Stop).Length -and
            [string]$bootstrapRow.sha256 -ceq (Get-FaultGateSha256File -Path $expectedBootstrapPath) -and
            $bootstrapRowVolume -eq [uint64]$bootstrapIndependentIdentity.VolumeSerialNumber -and
            $bootstrapRowFileIndex -eq [uint64]$bootstrapIndependentIdentity.FileIndex) "Bootstrap-only retained hash/file identity is invalid."
    }
    Assert-SelfTest (-not (Test-Path -LiteralPath $bootstrapOutputPath) -and @(Get-FaultGateEngineProcesses).Count -eq 0) "Bootstrap-only entrypoint created a gate artifact or engine process."

    $missingRoot = Join-Path $tempRoot "bootstrap-missing-helper"
    $missingScripts = Join-Path $missingRoot "scripts"
    $null = New-Item -ItemType Directory -Path $missingScripts -Force -ErrorAction Stop
    $missingHarness = Join-Path $missingScripts "run_raw_fault_gate.ps1"
    Write-SelfTestBytes -Path $missingHarness -Bytes ([IO.File]::ReadAllBytes($harnessPath))
    $missingResult = Invoke-SelfTestBootstrapEntrypoint -ScriptPath $missingHarness -WorkingDirectory $missingRoot -ArtifactRoot $tempRoot -Name "bootstrap-missing-helper" -OutputBase "artifacts/bootstrap-missing"
    Assert-SelfTestBootstrapRejected -Result $missingResult -Label "missing helper"

    $orderRoot = Join-Path $tempRoot "bootstrap-order-mutant"
    $orderScripts = Join-Path $orderRoot "scripts"
    $null = New-Item -ItemType Directory -Path $orderScripts -Force -ErrorAction Stop
    $orderHarness = Join-Path $orderScripts "run_raw_fault_gate.ps1"
    $orderHelper = Join-Path $orderScripts "RawQualification.Windows.ps1"
    $bootstrapLocalBarrierMatches = [regex]::Matches($harnessText, [regex]::Escape($bootstrapLocalBarrierText)).Count
    Assert-SelfTest ($bootstrapLocalBarrierMatches -eq 1) "Bootstrap local-barrier call is absent or ambiguous for the order mutant."
    $orderMutantText = $harnessText.Replace($bootstrapLocalBarrierText, '$fullPath = Assert-RawQualificationNoReparsePointInExistingPath -Path $Path')
    Write-SelfTestBytes -Path $orderHarness -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($orderMutantText))
    Write-SelfTestBytes -Path $orderHelper -Bytes ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot "RawQualification.Windows.ps1")))
    $orderResult = Invoke-SelfTestBootstrapEntrypoint -ScriptPath $orderHarness -WorkingDirectory $orderRoot -ArtifactRoot $tempRoot -Name "bootstrap-order-mutant" -OutputBase "artifacts/bootstrap-order"
    Assert-SelfTestBootstrapRejected -Result $orderResult -Label "helper barrier invoked before dot-source"

    $reparseTarget = Join-Path $tempRoot "bootstrap-reparse-target"
    $reparseTargetScripts = Join-Path $reparseTarget "scripts"
    $null = New-Item -ItemType Directory -Path $reparseTargetScripts -Force -ErrorAction Stop
    Write-SelfTestBytes -Path (Join-Path $reparseTargetScripts "run_raw_fault_gate.ps1") -Bytes ([IO.File]::ReadAllBytes($harnessPath))
    Write-SelfTestBytes -Path (Join-Path $reparseTargetScripts "RawQualification.Windows.ps1") -Bytes ([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot "RawQualification.Windows.ps1")))
    $reparseLink = Join-Path $tempRoot "bootstrap-reparse-link"
    $null = New-Item -ItemType Junction -Path $reparseLink -Target $reparseTarget -ErrorAction Stop
    $reparseHarness = Join-Path (Join-Path $reparseLink "scripts") "run_raw_fault_gate.ps1"
    Assert-SelfTestThrows { $null = Assert-FaultGateBootstrapNoReparsePointInExistingPath -Path $reparseHarness } "bootstrap local reparse barrier"
    $reparseResult = Invoke-SelfTestBootstrapEntrypoint -ScriptPath $reparseHarness -WorkingDirectory $tempRoot -ArtifactRoot $tempRoot -Name "bootstrap-reparse-mutant" -OutputBase "artifacts/bootstrap-reparse"
    Assert-SelfTestBootstrapRejected -Result $reparseResult -Label "reparse entrypoint path"
    Assert-FaultGateObservationWithinDeadline -ObservedMonotonicTick ([int64]6000) -DeadlineMonotonicTick ([int64]6000) -Label "self-test exact deadline"
    $script:FaultSelfTestPassed++
    Assert-SelfTestThrows { Assert-FaultGateObservationWithinDeadline -ObservedMonotonicTick ([int64]6001) -DeadlineMonotonicTick ([int64]6000) -Label "self-test +1 deadline" } "terminal observation one QPC tick after deadline"
    Assert-SelfTest ($harnessText.Contains('$failureWaitMilliseconds = [int][Math]::Min([int64]1000, $remainingFailureMilliseconds)') -and
        $harnessText.Contains('Assert-FaultGateObservationWithinDeadline -ObservedMonotonicTick $launcherExitObservationTick')) "Failure deadline does not bound each wait and post-observe the exact exit tick."
    Assert-SelfTestThrows { Invoke-RawQualificationFaultGate -StartupDeadlineSeconds 300 -FailureDeadlineSeconds 30 -MinimumSealedSegmentsPerStream 8 -FailureContainmentEvent "FAILURE_CONTAINMENT_TERMINAL" -FailureContainmentSchema "RawQualificationFailureContainmentV2" -OutputBase "artifacts/qualification-fault-gates" } "generation-0 impossible segment count"
    $defaultFaultOutput = Join-Path (Split-Path $PSScriptRoot -Parent) "artifacts\fg"
    $defaultPathBudget = Assert-FaultGateLegacyPathBudget -OutputRoot $defaultFaultOutput
    Assert-SelfTest ([uint64]$defaultPathBudget.projected_deepest_path_characters -le 259 -and
        [uint64]$defaultPathBudget.maximum_run_relative_path_characters -eq 131 -and
        $harnessText.Contains('[string] $OutputBase = "artifacts/fg"') -and
        $harnessText.Contains('$gateId = "f-" + [Guid]::NewGuid().ToString("N").Substring(0, 16)')) `
        "Default real fault-gate topology does not stay inside its explicit legacy path budget."
    $tooLongFaultOutput = [IO.Path]::Combine($tempRoot, (("x" * 180) -join ''))
    Assert-SelfTestThrows { $null = Assert-FaultGateLegacyPathBudget -OutputRoot $tooLongFaultOutput } `
        "over-budget fault-gate output root"
    $exactBudgetRoot = "C:\" + ("r" * 124)
    $exactBudgetPath = $exactBudgetRoot + "\" + ("p" * 131)
    $exactActualBudget = Assert-FaultGateActualPathBudget `
        -RunRoot $exactBudgetRoot -Path $exactBudgetPath
    Assert-SelfTest ([uint64]$exactActualBudget.full_path_characters -eq 259 -and
        [uint64]$exactActualBudget.run_relative_path_characters -eq 131) `
        "Exact 259/full and 131/run-relative path boundary was rejected."
    Assert-SelfTestThrows {
        $null = Assert-FaultGateActualPathBudget `
            -RunRoot $exactBudgetRoot -Path ($exactBudgetRoot + "\" + ("p" * 132))
    } "actual path budget at 260 characters"
    $fullOnlyBudgetRoot = "C:\" + ("r" * 125)
    Assert-SelfTestThrows {
        $null = Assert-FaultGateActualPathBudget `
            -RunRoot $fullOnlyBudgetRoot -Path ($fullOnlyBudgetRoot + "\" + ("p" * 131))
    } "actual full path budget at 260 with an in-budget relative path"

    $faultSequenceContext = [ordered]@{
        gate_id = "sequence-selftest"; repository_root = $tempRoot; qualification_base = $tempRoot; source_bindings = @(); artifact_path_bindings = @()
        launch_artifact_hashes = [ordered]@{ selftest = "4" * 64 }; run_id = "sequence-run"; run_root = $tempRoot
        launcher_pid = [uint32]40; launcher_creation_filetime_utc = [int64]1; launcher_command_line_sha256 = "5" * 64
        startup_sha256 = "6" * 64; processes_sha256 = "7" * 64; bindings_sha256 = "8" * 64
        target_creation_filetime_utc = [int64]2; target_parent_pid = [uint32]41; target_executable_sha256 = "9" * 64; target_command_line_sha256 = "a" * 64
        pre_fault_raw_prefixes_sha256 = "b" * 64; pre_fault_campaign_prefixes_sha256 = "c" * 64; pre_fault_campaign_prefixes = @()
        terminal_sha256 = "d" * 64; containment_sha256 = "e" * 64; launcher_journal_terminal_sha256 = "f" * 64
    }
    $faultSequence = ((New-SelfTestFaultJournalEvidence -TargetPid 42 -Context $faultSequenceContext -RequestWallNs 100 -RequestMonotonicTick 200) | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json
    $faultProposalSha = [string]$faultSequence.proposed_record_sha256
    $faultRequestSha = [string]$faultSequence.injection_requested_record_sha256
    $faultInjectedSha = [string]$faultSequence.injected_record_sha256
    $faultSequenceLinks = Test-FaultGateFaultInjectionJournalSequence -Journal $faultSequence -ProposalSha256 $faultProposalSha -InjectionRequestedSha256 $faultRequestSha -InjectedSha256 $faultInjectedSha -TargetPid 42 -RequestedExitCode $script:FaultGateTargetExitCode -InjectionRequestedWallNs 100 -InjectionRequestedMonotonicTick 200 -ObservedExitCode $script:FaultGateTargetExitCode
    Assert-SelfTest ([string]$faultSequenceLinks.injection_requested_record_sha256 -ceq $faultRequestSha -and [string]$faultSequenceLinks.injected_record_sha256 -ceq $faultInjectedSha) "Exact fault request/injection journal mapping was rejected."

    $failureReceiptGateId = "failure-selftest"
    $failureReceiptRoot = Join-Path $tempRoot $failureReceiptGateId
    $null = New-Item -ItemType Directory -Path $failureReceiptRoot -ErrorAction Stop
    $failureReceiptJournalPath = Join-Path $failureReceiptRoot "fault-events.jsonl"
    $failureReceiptJournal = New-RawQualificationJournal -Path $failureReceiptJournalPath
    try {
        $null = Add-FaultGateEvent -Journal $failureReceiptJournal -Event "HARNESS_STARTED" -Payload ([ordered]@{ gate_id = $failureReceiptGateId })
        $null = Add-FaultGateEvent -Journal $failureReceiptJournal -Event "HARNESS_FAILED" -Payload ([ordered]@{
            stage = "WAITING_FOR_HEALTHY_MONITOR"
            exception_type = "System.InvalidOperationException"
            fully_qualified_error_id = "SELFTEST_FAILURE"
            message = "injected self-test failure"
            run_root = $null
            pass_evidence_published = $false
            resource_cleanup_succeeded = $true
            outer_job_created = $true
            outer_job_cleanup_succeeded = $true
            outer_active_processes_after_cleanup = [uint64]0
        })
    }
    finally { Close-RawQualificationJournal -Journal $failureReceiptJournal }
    $failureReceiptJournalSummary = Read-FaultGateJournal -Path $failureReceiptJournalPath `
        -ExpectedSchema $script:FaultGateJournalSchema -RequireCleanTail -RequireCanonicalCompactJson
    $failureReceiptBody = [ordered]@{
        schema = "RawQualificationFaultGateFailureReceiptV1"
        status = "FAILED_NO_PASS_EVIDENCE"
        gate_id = $failureReceiptGateId
        evidence_root = $failureReceiptRoot
        repository_root = $tempRoot
        run_root = $null
        stage = "WAITING_FOR_HEALTHY_MONITOR"
        failure = [ordered]@{
            exception_type = "System.InvalidOperationException"
            fully_qualified_error_id = "SELFTEST_FAILURE"
            message = "injected self-test failure"
        }
        cleanup = [ordered]@{
            resource_cleanup_succeeded = $true
            resource_cleanup_error = $null
            outer_job_created = $true
            outer_job_cleanup_succeeded = $true
            outer_job_cleanup_error = $null
            outer_active_processes_after_cleanup = [uint64]0
        }
        fault_journal = [ordered]@{
            file = "fault-events.jsonl"
            records = [uint64]$failureReceiptJournalSummary.records
            clean_tail = [bool]$failureReceiptJournalSummary.clean_tail
            terminal_record_sha256 = [string]$failureReceiptJournalSummary.terminal_record_sha256
            file_bytes = [uint64]$failureReceiptJournalSummary.file_bytes
            file_sha256 = [string]$failureReceiptJournalSummary.file_sha256
            failure_event_appended = $true
            failure_event_append_error = $null
        }
        pass_evidence_published = $false
    }
    $failureReceiptPath = Join-Path $failureReceiptRoot "fault-gate-failure.json"
    $failureReceiptSha = Write-FaultGateEvidence -Path $failureReceiptPath -Body $failureReceiptBody
    $verifiedFailureReceipt = Test-FaultGateFailureReceiptEnvelope -Path $failureReceiptPath
    Assert-SelfTest ([string]$verifiedFailureReceipt.record_sha256 -ceq [string]$failureReceiptSha -and
        [string]$verifiedFailureReceipt.body.status -ceq "FAILED_NO_PASS_EVIDENCE" -and
        -not [bool]$verifiedFailureReceipt.body.pass_evidence_published) `
        "Durable non-PASS fault-gate failure receipt was rejected."
    $validFailureReceiptBytes = [IO.File]::ReadAllBytes($failureReceiptPath)
    $failureReceiptPassMutantBody = (($failureReceiptBody | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $failureReceiptPassMutantBody.pass_evidence_published = $true
    $failureReceiptPassMutantEnvelope = [ordered]@{
        body = $failureReceiptPassMutantBody
        record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $failureReceiptPassMutantBody)
    }
    Write-SelfTestBytes -Path $failureReceiptPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(
            (($failureReceiptPassMutantEnvelope | ConvertTo-Json -Depth 100) + "`n")))
    Assert-SelfTestThrows { $null = Test-FaultGateFailureReceiptEnvelope -Path $failureReceiptPath } `
        "failure receipt that overclaims PASS evidence"
    Write-SelfTestBytes -Path $failureReceiptPath -Bytes $validFailureReceiptBytes
    $failureReceiptStageMutantBody = (($failureReceiptBody | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $failureReceiptStageMutantBody.stage = "MISMATCHED_STAGE"
    $failureReceiptStageMutantEnvelope = [ordered]@{
        body = $failureReceiptStageMutantBody
        record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $failureReceiptStageMutantBody)
    }
    Write-SelfTestBytes -Path $failureReceiptPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(
            (($failureReceiptStageMutantEnvelope | ConvertTo-Json -Depth 100) + "`n")))
    Assert-SelfTestThrows { $null = Test-FaultGateFailureReceiptEnvelope -Path $failureReceiptPath } `
        "failure receipt whose stage differs from terminal HARNESS_FAILED"
    Write-SelfTestBytes -Path $failureReceiptPath -Bytes $validFailureReceiptBytes
    $failureReceiptDeniedEventBody = (($failureReceiptBody | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $failureReceiptDeniedEventBody.fault_journal.failure_event_appended = $false
    $failureReceiptDeniedEventBody.fault_journal.failure_event_append_error = "injected append failure"
    $failureReceiptDeniedEventEnvelope = [ordered]@{
        body = $failureReceiptDeniedEventBody
        record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $failureReceiptDeniedEventBody)
    }
    Write-SelfTestBytes -Path $failureReceiptPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(
            (($failureReceiptDeniedEventEnvelope | ConvertTo-Json -Depth 100) + "`n")))
    Assert-SelfTestThrows { $null = Test-FaultGateFailureReceiptEnvelope -Path $failureReceiptPath } `
        "failure receipt denying the HARNESS_FAILED event present in its journal"
    Write-SelfTestBytes -Path $failureReceiptPath -Bytes $validFailureReceiptBytes
    $contradictoryPassPath = Join-Path $failureReceiptRoot "fault-evidence.json"
    Write-SelfTestBytes -Path $contradictoryPassPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes("{}`n"))
    try {
        Assert-SelfTestThrows { $null = Test-FaultGateFailureReceiptEnvelope -Path $failureReceiptPath } `
            "FAILED_NO_PASS_EVIDENCE receipt coexisting with canonical PASS path"
    }
    finally { Remove-Item -LiteralPath $contradictoryPassPath -Force -ErrorAction Stop }
    $failureReceiptJournalBytes = [IO.File]::ReadAllBytes($failureReceiptJournalPath)
    $failureReceiptJournalBytes[0] = $failureReceiptJournalBytes[0] -bxor 1
    Write-SelfTestBytes -Path $failureReceiptJournalPath -Bytes $failureReceiptJournalBytes
    Assert-SelfTestThrows { $null = Test-FaultGateFailureReceiptEnvelope -Path $failureReceiptPath } `
        "failure receipt with drifted journal"
    $faultSequenceSwapped = (($faultSequence | ConvertTo-Json -Depth 20) | ConvertFrom-Json)
    $faultSequenceSwapped.entries[4].record_sha256 = $faultInjectedSha
    Assert-SelfTestThrows { $null = Test-FaultGateFaultInjectionJournalSequence -Journal $faultSequenceSwapped -ProposalSha256 $faultProposalSha -InjectionRequestedSha256 $faultRequestSha -InjectedSha256 $faultInjectedSha -TargetPid 42 -RequestedExitCode $script:FaultGateTargetExitCode -InjectionRequestedWallNs 100 -InjectionRequestedMonotonicTick 200 -ObservedExitCode $script:FaultGateTargetExitCode } "fault journal request record mapped to injected SHA"
    $faultSequenceBrokenLink = (($faultSequence | ConvertTo-Json -Depth 20) | ConvertFrom-Json)
    $faultSequenceBrokenLink.entries[5].body.payload.injection_requested_record_sha256 = "6" * 64
    Assert-SelfTestThrows { $null = Test-FaultGateFaultInjectionJournalSequence -Journal $faultSequenceBrokenLink -ProposalSha256 $faultProposalSha -InjectionRequestedSha256 $faultRequestSha -InjectedSha256 $faultInjectedSha -TargetPid 42 -RequestedExitCode $script:FaultGateTargetExitCode -InjectionRequestedWallNs 100 -InjectionRequestedMonotonicTick 200 -ObservedExitCode $script:FaultGateTargetExitCode } "fault journal injected event broken request link"
    $faultSequenceBtcExitThree = (($faultSequence | ConvertTo-Json -Depth 20) | ConvertFrom-Json)
    $faultSequenceBtcExitThree.entries[6].body.payload.btc_coordinator_exit_code = [uint32]3
    Assert-SelfTestThrows { $null = Test-FaultGateFaultInjectionJournalSequence -Journal $faultSequenceBtcExitThree -ProposalSha256 $faultProposalSha -InjectionRequestedSha256 $faultRequestSha -InjectedSha256 $faultInjectedSha -TargetPid 42 -RequestedExitCode $script:FaultGateTargetExitCode -InjectionRequestedWallNs 100 -InjectionRequestedMonotonicTick 200 -ObservedExitCode $script:FaultGateTargetExitCode } "fault journal BTC coordinator exit outside exact containment-or-receipt set"
    $faultSequenceWorkloadSurvivor = (($faultSequence | ConvertTo-Json -Depth 20) | ConvertFrom-Json)
    $faultSequenceWorkloadSurvivor.entries[6].body.payload.workload_job_exists = $true
    Assert-SelfTestThrows { $null = Test-FaultGateFaultInjectionJournalSequence -Journal $faultSequenceWorkloadSurvivor -ProposalSha256 $faultProposalSha -InjectionRequestedSha256 $faultRequestSha -InjectedSha256 $faultInjectedSha -TargetPid 42 -RequestedExitCode $script:FaultGateTargetExitCode -InjectionRequestedWallNs 100 -InjectionRequestedMonotonicTick 200 -ObservedExitCode $script:FaultGateTargetExitCode } "fault journal launcher-exited surviving workload Job"
    $faultSequenceWorkloadOpenError = (($faultSequence | ConvertTo-Json -Depth 20) | ConvertFrom-Json)
    $faultSequenceWorkloadOpenError.entries[6].body.payload.workload_job_open_error = [int]0
    Assert-SelfTestThrows { $null = Test-FaultGateFaultInjectionJournalSequence -Journal $faultSequenceWorkloadOpenError -ProposalSha256 $faultProposalSha -InjectionRequestedSha256 $faultRequestSha -InjectedSha256 $faultInjectedSha -TargetPid 42 -RequestedExitCode $script:FaultGateTargetExitCode -InjectionRequestedWallNs 100 -InjectionRequestedMonotonicTick 200 -ObservedExitCode $script:FaultGateTargetExitCode } "fault journal launcher-exited workload Job absence error"
    $faultSequenceProposedWorkloadSurvivor = (($faultSequence | ConvertTo-Json -Depth 20) | ConvertFrom-Json)
    $faultSequenceProposedWorkloadSurvivor.entries[7].body.payload.workload_job_exists = $true
    Assert-SelfTestThrows { $null = Test-FaultGateFaultInjectionJournalSequence -Journal $faultSequenceProposedWorkloadSurvivor -ProposalSha256 $faultProposalSha -InjectionRequestedSha256 $faultRequestSha -InjectedSha256 $faultInjectedSha -TargetPid 42 -RequestedExitCode $script:FaultGateTargetExitCode -InjectionRequestedWallNs 100 -InjectionRequestedMonotonicTick 200 -ObservedExitCode $script:FaultGateTargetExitCode } "fault journal evidence-proposed surviving workload Job"

    $controlArtifacts = New-SelfTestControlArtifacts -RepositoryRoot $tempRoot
    Test-FaultGateProcessControlSchema -ProcessControl $controlArtifacts.process_control
    Test-FaultGateCampaignBindingsSchema -Bindings $controlArtifacts.bindings
    Test-FaultGateWatchdogReadySchema -Ready $controlArtifacts.ready
    Test-FaultGateControlCrosslinks -Startup $controlArtifacts.startup -ProcessControl $controlArtifacts.process_control -Bindings $controlArtifacts.bindings -Ready $controlArtifacts.ready -RepositoryRoot $controlArtifacts.repo -QualificationBase $controlArtifacts.qualification_base -RunRoot $controlArtifacts.run_root -ReadySha256 $controlArtifacts.ready_sha256
    $script:FaultSelfTestPassed++
    $reversedCoordinatorChronology = (($controlArtifacts.process_control | ConvertTo-Json -Depth 30 -Compress) | ConvertFrom-Json)
    $reversedCoordinatorChronology.processes[0].launch_monotonic_tick = [uint64]200
    $reversedCoordinatorChronology.processes[1].launch_monotonic_tick = [uint64]100
    $reversedCoordinatorChronology.capture_origin_monotonic_tick = [uint64]200
    Assert-SelfTestThrows { Test-FaultGateProcessControlSchema -ProcessControl $reversedCoordinatorChronology } "coordinated ETH-before-BTC launch chronology"
    foreach ($processControlMutation in @("old_schema", "old_launch_method", "workload_kill_false", "workload_alias", "workload_nondeterministic")) {
        $processControlMutant = (($controlArtifacts.process_control | ConvertTo-Json -Depth 30 -Compress) | ConvertFrom-Json)
        switch ($processControlMutation) {
            "old_schema" { $processControlMutant.schema = "RawQualificationProcessControlV1" }
            "old_launch_method" { $processControlMutant.launch_method = "CREATE_SUSPENDED_ASSIGN_JOB_RESUME" }
            "workload_kill_false" { $processControlMutant.workload_job_kill_on_close = $false }
            "workload_alias" { $processControlMutant.workload_job_object_name = [string]$processControlMutant.job_object_name }
            "workload_nondeterministic" { $processControlMutant.workload_job_object_name = "Local\BinanceRawQualificationWorkloadJob-relabelled" }
        }
        if ($processControlMutation -ceq "workload_nondeterministic") {
            Assert-SelfTestThrows { Test-FaultGateControlCrosslinks -Startup $controlArtifacts.startup -ProcessControl $processControlMutant -Bindings $controlArtifacts.bindings -Ready $controlArtifacts.ready -RepositoryRoot $controlArtifacts.repo -QualificationBase $controlArtifacts.qualification_base -RunRoot $controlArtifacts.run_root -ReadySha256 $controlArtifacts.ready_sha256 } ("process control " + $processControlMutation)
        }
        else {
            Assert-SelfTestThrows { Test-FaultGateProcessControlSchema -ProcessControl $processControlMutant } ("process control " + $processControlMutation)
        }
    }
    foreach ($controlMutation in @("maximum_skew", "ready_observed", "environment_digest", "repository", "output_base", "device", "preflight_capacity", "binding_pid", "campaign_path")) {
        $controlMutant = (($controlArtifacts | ConvertTo-Json -Depth 30 -Compress) | ConvertFrom-Json)
        switch ($controlMutation) {
            "maximum_skew" { $controlMutant.process_control.maximum_dual_launch_skew_ms = [uint64]4000 }
            "ready_observed" { $controlMutant.ready.observed_qpc_timestamp = [uint64]1003 }
            "environment_digest" { $controlMutant.process_control.child_environment_entries_sha256 = "9" * 64 }
            "repository" { $controlMutant.startup.preflight.repo = Join-Path $tempRoot "drift\repo" }
            "output_base" { $controlMutant.startup.preflight.output_base = Join-Path $tempRoot "drift\qualification" }
            "device" { $controlMutant.startup.output_path_post_create.run_root_drive_device_id = "D:" }
            "preflight_capacity" { $controlMutant.startup.preflight.free_gib = [uint64]100 }
            "binding_pid" { $controlMutant.bindings.campaigns[0].pid = [uint64]11 }
            "campaign_path" { $controlMutant.bindings.campaigns[0].campaign_directory = Join-Path $controlMutant.run_root "copy\1-BTCUSDT-raw-111111111111" }
        }
        Assert-SelfTestThrows { Test-FaultGateControlCrosslinks -Startup $controlMutant.startup -ProcessControl $controlMutant.process_control -Bindings $controlMutant.bindings -Ready $controlMutant.ready -RepositoryRoot $controlMutant.repo -QualificationBase $controlMutant.qualification_base -RunRoot $controlMutant.run_root -ReadySha256 $controlMutant.ready_sha256 } ("control crosslink " + $controlMutation)
    }
    $probeFrequency = [uint64][Diagnostics.Stopwatch]::Frequency
    $probeResume = [uint64]200
    $probeElapsed = [uint64]1000
    $probeDrain = [uint64]500
    $probeOutput = [pscustomobject][ordered]@{
        reparse_points_rejected = $true; run_root_drive_device_id = "C:"; same_preflight_volume = $true; filesystem = "NTFS"
        free_gib = [uint64]1000; required_free_gib = [uint64]101; probe_pid = [uint32]42
        probe_command_line_sha256 = "1" * 64; probe_resume_qpc_timestamp = $probeResume; probe_elapsed_qpc_ticks = $probeElapsed
        probe_monotonic_frequency = $probeFrequency; probe_job_membership = "PRIMARY_AND_NESTED_BOUNDED"
        probe_parent_exit_observed_qpc_timestamp = [uint64]($probeResume + $probeElapsed)
        probe_descendant_drain_elapsed_qpc_ticks = $probeDrain
        probe_descendant_drain_elapsed_ms = [uint64][decimal]::Floor(([decimal]$probeDrain * [decimal]1000) / [decimal]$probeFrequency)
        probe_descendant_drain_active_processes = [uint32]0; probe_timeout_s = [uint64]20
        probe_elapsed_ms = [uint64][decimal]::Floor(([decimal]$probeElapsed * [decimal]1000) / [decimal]$probeFrequency)
        probe_stdout_file = "post-create-volume.stdout.json"; probe_stdout_bytes = [uint64]10; probe_stdout_sha256 = "2" * 64
        probe_stderr_file = "post-create-volume.stderr.log"; probe_stderr_bytes = [uint64]0
        probe_stderr_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
    Test-FaultGateLauncherOutputPostCreateSchema -Output $probeOutput -StartupMonotonicFrequency $probeFrequency -StartupMonotonicOrigin ([uint64]100)
    Assert-SelfTest $true "Exact launcher post-create QPC/output probe contract was rejected."
    foreach ($probeMutation in @("frequency", "elapsed_relation", "elapsed_ms", "drain_ms", "elapsed_deadline", "drain_deadline", "resume_before_origin")) {
        $probeMutant = (($probeOutput | ConvertTo-Json -Depth 20 -Compress) | ConvertFrom-Json)
        switch ($probeMutation) {
            "frequency" { $probeMutant.probe_monotonic_frequency = [uint64]($probeFrequency + 1) }
            "elapsed_relation" { $probeMutant.probe_elapsed_qpc_ticks = [uint64]($probeElapsed + 1) }
            "elapsed_ms" { $probeMutant.probe_elapsed_ms = [uint64]($probeOutput.probe_elapsed_ms + 1) }
            "drain_ms" { $probeMutant.probe_descendant_drain_elapsed_ms = [uint64]($probeOutput.probe_descendant_drain_elapsed_ms + 1) }
            "elapsed_deadline" {
                $probeMutant.probe_elapsed_qpc_ticks = [uint64]([decimal]20 * [decimal]$probeFrequency + [decimal]1)
                $probeMutant.probe_parent_exit_observed_qpc_timestamp = [uint64]($probeResume + [uint64]$probeMutant.probe_elapsed_qpc_ticks)
                $probeMutant.probe_elapsed_ms = [uint64][decimal]::Floor(([decimal]$probeMutant.probe_elapsed_qpc_ticks * [decimal]1000) / [decimal]$probeFrequency)
            }
            "drain_deadline" {
                $probeMutant.probe_descendant_drain_elapsed_qpc_ticks = [uint64]([decimal]10 * [decimal]$probeFrequency + [decimal]1)
                $probeMutant.probe_descendant_drain_elapsed_ms = [uint64][decimal]::Floor(([decimal]$probeMutant.probe_descendant_drain_elapsed_qpc_ticks * [decimal]1000) / [decimal]$probeFrequency)
            }
            "resume_before_origin" {
                $probeMutant.probe_resume_qpc_timestamp = [uint64]99
                $probeMutant.probe_parent_exit_observed_qpc_timestamp = [uint64](99 + $probeElapsed)
            }
        }
        Assert-SelfTestThrows { Test-FaultGateLauncherOutputPostCreateSchema -Output $probeMutant -StartupMonotonicFrequency $probeFrequency -StartupMonotonicOrigin ([uint64]100) } ("launcher post-create probe " + $probeMutation)
    }
    $environmentNames = @((Get-FaultGateChildEnvironment) | ForEach-Object { ([string]$_).Split('=')[0] })
    Assert-SelfTest ("OS" -cin $environmentNames -and "SystemDrive" -cin $environmentNames -and
        "SystemRoot" -cin $environmentNames) "External launcher environment lacks Windows identity/bootstrap variables."

    Assert-SelfTest ((Get-FaultGatePortableLeafComponent -Value "1700000000-BTCUSDT-g000-aaaaaaaaaaaa" -Label "selftest session") -ceq "1700000000-BTCUSDT-g000-aaaaaaaaaaaa") "Valid portable session leaf was rejected."
    foreach ($badLeaf in @("..", ".", "../escape", "sub/leaf", "sub\leaf", "C:\escape", "leaf:stream", "leaf.")) {
        Assert-SelfTestThrows { $null = Get-FaultGatePortableLeafComponent -Value $badLeaf -Label "selftest bad session" } ("portable session leaf " + $badLeaf)
    }
    $exactInventoryRoot = Join-Path $tempRoot "exact-stream-inventory"
    $null = New-Item -ItemType Directory -Path $exactInventoryRoot -ErrorAction Stop
    foreach ($leaf in @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack")) { Write-SelfTestBytes -Path (Join-Path $exactInventoryRoot $leaf) -Bytes ([byte[]](1)) }
    Assert-FaultGateExactDirectoryFileInventory -Directory $exactInventoryRoot -ExpectedNames @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack") -Label "selftest exact stream"
    $script:FaultSelfTestPassed++
    Write-SelfTestBytes -Path (Join-Path $exactInventoryRoot "segment-999999.bnraw") -Bytes ([byte[]](1))
    Assert-SelfTestThrows { Assert-FaultGateExactDirectoryFileInventory -Directory $exactInventoryRoot -ExpectedNames @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack") -Label "selftest orphan stream" } "orphan raw segment outside manifest/tail inventory"
    $liveInventoryRoot = Join-Path $tempRoot "live-stream-inventory"
    $null = New-Item -ItemType Directory -Path $liveInventoryRoot -ErrorAction Stop
    foreach ($leaf in @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack")) { Write-SelfTestBytes -Path (Join-Path $liveInventoryRoot $leaf) -Bytes ([byte[]](1)) }
    Assert-FaultGateLiveDirectoryFileInventory -Directory $liveInventoryRoot -ExpectedNames @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack") -Label "selftest live base stream"
    $script:FaultSelfTestPassed++
    Write-SelfTestBytes -Path (Join-Path $liveInventoryRoot "segment-000001.bnraw") -Bytes ([byte[]](1))
    Assert-FaultGateLiveDirectoryFileInventory -Directory $liveInventoryRoot -ExpectedNames @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack") -Label "selftest live partial terminal stream"
    $script:FaultSelfTestPassed++
    Write-SelfTestBytes -Path (Join-Path $liveInventoryRoot "segment-000001.bnack") -Bytes ([byte[]](1))
    Write-SelfTestBytes -Path (Join-Path $liveInventoryRoot "segment-000002.bnraw") -Bytes ([byte[]](1))
    Assert-FaultGateLiveDirectoryFileInventory -Directory $liveInventoryRoot -ExpectedNames @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack") -Label "selftest live contiguous append stream"
    $script:FaultSelfTestPassed++
    Write-SelfTestBytes -Path (Join-Path $liveInventoryRoot "unknown.bin") -Bytes ([byte[]](1))
    Assert-SelfTestThrows { Assert-FaultGateLiveDirectoryFileInventory -Directory $liveInventoryRoot -ExpectedNames @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack") -Label "selftest live unknown stream" } "unknown artifact in live stream suffix"
    $liveGapRoot = Join-Path $tempRoot "live-gap-stream-inventory"
    $null = New-Item -ItemType Directory -Path $liveGapRoot -ErrorAction Stop
    foreach ($leaf in @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack", "segment-000002.bnraw")) { Write-SelfTestBytes -Path (Join-Path $liveGapRoot $leaf) -Bytes ([byte[]](1)) }
    Assert-SelfTestThrows { Assert-FaultGateLiveDirectoryFileInventory -Directory $liveGapRoot -ExpectedNames @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack") -Label "selftest live gap stream" } "gap in live stream suffix"
    $liveIncompleteRoot = Join-Path $tempRoot "live-incomplete-stream-inventory"
    $null = New-Item -ItemType Directory -Path $liveIncompleteRoot -ErrorAction Stop
    foreach ($leaf in @("segments.bnseg", "segment-000000.bnraw", "segment-000001.bnraw")) { Write-SelfTestBytes -Path (Join-Path $liveIncompleteRoot $leaf) -Bytes ([byte[]](1)) }
    Assert-SelfTestThrows { Assert-FaultGateLiveDirectoryFileInventory -Directory $liveIncompleteRoot -ExpectedNames @("segments.bnseg", "segment-000000.bnraw") -Label "selftest live incomplete stream" } "incomplete non-terminal live segment pair"
    Assert-SelfTestThrows { Assert-FaultGateLiveDirectoryFileInventory -Directory $liveIncompleteRoot -ExpectedNames @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack") -Label "selftest live lost prefix stream" } "missing expected live prefix artifact"
    $liveOrphanAckRoot = Join-Path $tempRoot "live-orphan-ack-inventory"
    $null = New-Item -ItemType Directory -Path $liveOrphanAckRoot -ErrorAction Stop
    foreach ($leaf in @("segments.bnseg", "segment-000000.bnack")) { Write-SelfTestBytes -Path (Join-Path $liveOrphanAckRoot $leaf) -Bytes ([byte[]](1)) }
    Assert-SelfTestThrows { Assert-FaultGateLiveDirectoryFileInventory -Directory $liveOrphanAckRoot -ExpectedNames @("segments.bnseg") -Label "selftest live orphan ACK stream" } "orphan terminal BNACK without BNRAW predecessor"
    $unknownDirectoryRoot = Join-Path $tempRoot "unknown-stream-directory"
    $null = New-Item -ItemType Directory -Path $unknownDirectoryRoot -ErrorAction Stop
    foreach ($leaf in @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack")) { Write-SelfTestBytes -Path (Join-Path $unknownDirectoryRoot $leaf) -Bytes ([byte[]](1)) }
    $null = New-Item -ItemType Directory -Path (Join-Path $unknownDirectoryRoot "unknown") -ErrorAction Stop
    Assert-SelfTestThrows { Assert-FaultGateExactDirectoryFileInventory -Directory $unknownDirectoryRoot -ExpectedNames @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack") -Label "selftest directory stream" } "unknown directory in raw stream inventory"
    $adsInventoryRoot = Join-Path $tempRoot "ads-stream-inventory"
    $null = New-Item -ItemType Directory -Path $adsInventoryRoot -ErrorAction Stop
    foreach ($leaf in @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack")) { Write-SelfTestBytes -Path (Join-Path $adsInventoryRoot $leaf) -Bytes ([byte[]](1)) }
    Set-Content -LiteralPath ((Join-Path $adsInventoryRoot "segment-000000.bnraw") + ":orphan") -Value "ads" -NoNewline -Encoding ASCII -ErrorAction Stop
    Assert-SelfTestThrows { Assert-FaultGateExactDirectoryFileInventory -Directory $adsInventoryRoot -ExpectedNames @("segments.bnseg", "segment-000000.bnraw", "segment-000000.bnack") -Label "selftest ADS stream" } "alternate data stream in raw inventory"

    $bindingPath = Join-Path $tempRoot "retained-source.ps1"
    Write-SelfTestBytes -Path $bindingPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes("'bound'`n"))
    $binding = Open-FaultGateRetainedPathBinding -Path $bindingPath -Role "selftest_source"
    try {
        $bindingEvidence = Test-FaultGateRetainedPathBinding -Binding $binding
        Assert-SelfTest ([string]$bindingEvidence.observation_scope -ceq "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE" -and [uint64]$bindingEvidence.length -gt 0 -and (Test-FaultGateDigest ([string]$bindingEvidence.sha256))) "Retained path-byte binding is invalid."
        Assert-SelfTestThrows { [IO.File]::WriteAllText($bindingPath, "mutated") } "retained source write sharing"
        $identicalCopyPath = Join-Path $tempRoot "retained-source-copy.ps1"
        Write-SelfTestBytes -Path $identicalCopyPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes("'bound'`n"))
        $originalBoundPath = [string]$binding.path
        try {
            $binding.path = $identicalCopyPath
            Assert-SelfTestThrows { $null = Test-FaultGateRetainedPathBinding -Binding $binding } "retained source identical-byte path rebind"
        }
        finally { $binding.path = $originalBoundPath }
    }
    finally { Close-FaultGateRetainedPathBinding -Binding $binding }
    $emptyBindingPath = Join-Path $tempRoot "retained-empty.bin"
    Write-SelfTestBytes -Path $emptyBindingPath -Bytes ([byte[]]::new(0))
    $emptyBinding = Open-FaultGateRetainedPathBinding -Path $emptyBindingPath -Role "selftest_empty_bytes"
    try {
        [byte[]]$emptyBindingBytes = Read-FaultGateRetainedPathBytes -Binding $emptyBinding -MaximumBytes 3
        Assert-SelfTest ($emptyBindingBytes -is [byte[]] -and $emptyBindingBytes.Length -eq 0) "Retained empty byte-array contract was not preserved."
    }
    finally { Close-FaultGateRetainedPathBinding -Binding $emptyBinding }
    $nonEmptyBindingPath = Join-Path $tempRoot "retained-nonempty.bin"
    [byte[]]$nonEmptyExpectedBytes = @(0, 1, 255)
    Write-SelfTestBytes -Path $nonEmptyBindingPath -Bytes $nonEmptyExpectedBytes
    $nonEmptyBinding = Open-FaultGateRetainedPathBinding -Path $nonEmptyBindingPath -Role "selftest_nonempty_bytes"
    try {
        [byte[]]$nonEmptyBindingBytes = Read-FaultGateRetainedPathBytes -Binding $nonEmptyBinding -MaximumBytes 3
        Assert-SelfTest ($nonEmptyBindingBytes -is [byte[]] -and $nonEmptyBindingBytes.Length -eq 3 -and
            $nonEmptyBindingBytes[0] -eq 0 -and $nonEmptyBindingBytes[1] -eq 1 -and $nonEmptyBindingBytes[2] -eq 255) `
            "Retained non-empty byte-array contract changed type, length, or content."
        Assert-SelfTestThrows { $null = Read-FaultGateRetainedPathBytes -Binding $nonEmptyBinding -MaximumBytes 2 } "retained byte-array maximum"
    }
    finally { Close-FaultGateRetainedPathBinding -Binding $nonEmptyBinding }
    $oversizedBindingPath = Join-Path $tempRoot "retained-oversized.bin"
    Write-SelfTestBytes -Path $oversizedBindingPath -Bytes ([byte[]]::new(4097))
    Assert-SelfTestThrows {
        $oversizedBinding = $null
        try { $oversizedBinding = Open-FaultGateRetainedPathBinding -Path $oversizedBindingPath -Role "selftest_oversized_bytes" -MaximumBytes 4096 }
        finally { Close-FaultGateRetainedPathBinding -Binding $oversizedBinding }
    } "retained open-time byte maximum before full hash"
    $lateAdsTreeRoot = Join-Path $tempRoot "retained-late-ads-tree"
    $null = New-Item -ItemType Directory -Path $lateAdsTreeRoot -ErrorAction Stop
    $lateAdsPath = Join-Path $lateAdsTreeRoot "stderr.log"
    Write-SelfTestBytes -Path $lateAdsPath -Bytes ([byte[]](1, 2, 3))
    $lateAdsBinding = Open-FaultGateRetainedPathBinding -Path $lateAdsPath -Role "selftest_late_ads" -MaximumBytes 4096
    try {
        Set-Content -LiteralPath ($lateAdsPath + ":late") -Value "named-stream" -NoNewline -Encoding ASCII -ErrorAction Stop
        $lateAdsDefaultBinding = Test-FaultGateRetainedPathBinding -Binding $lateAdsBinding
        Assert-SelfTest ([uint64]$lateAdsDefaultBinding.length -eq 3 -and [string]$lateAdsDefaultBinding.sha256 -ceq (Get-FaultGateSha256Bytes -Bytes ([byte[]](1, 2, 3)))) `
            "Late ADS fixture unexpectedly changed the retained default-stream binding."
        Assert-SelfTestThrows {
            $null = Assert-FaultGateExactDataStreamInventory -Path $lateAdsPath -ExpectedType "file" -Label "selftest retained late ADS"
        } "late ADS while default stream binding remains retained"
        Assert-SelfTestThrows { $null = Assert-FaultGateTreeStable -Root $lateAdsTreeRoot } "artifact tree with late file ADS"
    }
    finally { Close-FaultGateRetainedPathBinding -Binding $lateAdsBinding }
    $directoryAdsTreeRoot = Join-Path $tempRoot "directory-late-ads-tree"
    $directoryAdsChild = Join-Path $directoryAdsTreeRoot "child"
    $null = New-Item -ItemType Directory -Path $directoryAdsChild -Force -ErrorAction Stop
    Write-SelfTestBytes -Path (Join-Path $directoryAdsChild "payload.bin") -Bytes ([byte[]](1))
    Set-Content -LiteralPath ($directoryAdsChild + ":late") -Value "directory-stream" -NoNewline -Encoding ASCII -ErrorAction Stop
    Assert-SelfTestThrows { $null = Assert-FaultGateTreeStable -Root $directoryAdsTreeRoot } "artifact tree with late directory ADS"
    $newSupportFixture = {
        param([Parameter(Mandatory = $true)] [string] $Name, [Parameter(Mandatory = $true)] [int] $Length)
        $supportRoot = Join-Path $tempRoot $Name
        $supportQualification = Join-Path $supportRoot "qualification"
        $supportRun = Join-Path $supportQualification "run"
        $null = New-Item -ItemType Directory -Path $supportRun -Force -ErrorAction Stop
        $supportFile = Join-Path $supportRoot "support.log"
        Write-SelfTestBytes -Path $supportFile -Bytes ([byte[]]::new($Length))
        return [pscustomobject]@{ root = $supportRoot; qualification = $supportQualification; run = $supportRun; file = $supportFile }
    }
    $supportBounds = [ordered]@{ "support.log" = [uint64]4096 }
    $healthySupportFixture = & $newSupportFixture "support-healthy" 3
    $healthySupport = Open-FaultGateSupportArtifactTree -EvidenceRoot $healthySupportFixture.root -QualificationRoot $healthySupportFixture.qualification `
        -RunRoot $healthySupportFixture.run -MaximumBytesByLeaf $supportBounds
    try {
        $healthySupportRows = Test-FaultGateSupportArtifactBindings -Bindings $healthySupport.bindings -ExpectedTree $healthySupport.tree `
            -EvidenceRoot $healthySupportFixture.root -QualificationRoot $healthySupportFixture.qualification -RunRoot $healthySupportFixture.run -MaximumBytesByLeaf $supportBounds
        Assert-SelfTest (@($healthySupportRows).Count -eq 1 -and [string]@($healthySupportRows)[0].relative_path -ceq "support.log") `
            "Exact support namespace/binding fixture was rejected."
    }
    finally { foreach ($supportBinding in @($healthySupport.bindings)) { Close-FaultGateRetainedPathBinding -Binding $supportBinding } }
    $lateSupportFileFixture = & $newSupportFixture "support-late-file-ads" 3
    $lateSupportFile = Open-FaultGateSupportArtifactTree -EvidenceRoot $lateSupportFileFixture.root -QualificationRoot $lateSupportFileFixture.qualification `
        -RunRoot $lateSupportFileFixture.run -MaximumBytesByLeaf $supportBounds
    try {
        Set-Content -LiteralPath ($lateSupportFileFixture.file + ":late") -Value "support-stream" -NoNewline -Encoding ASCII -ErrorAction Stop
        Assert-SelfTestThrows {
            $null = Test-FaultGateSupportArtifactBindings -Bindings $lateSupportFile.bindings -ExpectedTree $lateSupportFile.tree `
                -EvidenceRoot $lateSupportFileFixture.root -QualificationRoot $lateSupportFileFixture.qualification -RunRoot $lateSupportFileFixture.run -MaximumBytesByLeaf $supportBounds
        } "late ADS on retained support file"
    }
    finally { foreach ($supportBinding in @($lateSupportFile.bindings)) { Close-FaultGateRetainedPathBinding -Binding $supportBinding } }
    $lateSupportRootFixture = & $newSupportFixture "support-late-root-ads" 3
    $lateSupportRoot = Open-FaultGateSupportArtifactTree -EvidenceRoot $lateSupportRootFixture.root -QualificationRoot $lateSupportRootFixture.qualification `
        -RunRoot $lateSupportRootFixture.run -MaximumBytesByLeaf $supportBounds
    try {
        Set-Content -LiteralPath ($lateSupportRootFixture.root + ":late") -Value "root-stream" -NoNewline -Encoding ASCII -ErrorAction Stop
        Assert-SelfTestThrows {
            $null = Test-FaultGateSupportArtifactBindings -Bindings $lateSupportRoot.bindings -ExpectedTree $lateSupportRoot.tree `
                -EvidenceRoot $lateSupportRootFixture.root -QualificationRoot $lateSupportRootFixture.qualification -RunRoot $lateSupportRootFixture.run -MaximumBytesByLeaf $supportBounds
        } "late ADS on support evidence root"
    }
    finally { foreach ($supportBinding in @($lateSupportRoot.bindings)) { Close-FaultGateRetainedPathBinding -Binding $supportBinding } }
    $lateSupportDirectoryFixture = & $newSupportFixture "support-late-directory-ads" 3
    $lateSupportDirectory = Open-FaultGateSupportArtifactTree -EvidenceRoot $lateSupportDirectoryFixture.root -QualificationRoot $lateSupportDirectoryFixture.qualification `
        -RunRoot $lateSupportDirectoryFixture.run -MaximumBytesByLeaf $supportBounds
    try {
        Set-Content -LiteralPath ($lateSupportDirectoryFixture.qualification + ":late") -Value "qualification-stream" -NoNewline -Encoding ASCII -ErrorAction Stop
        Assert-SelfTestThrows {
            $null = Test-FaultGateSupportArtifactBindings -Bindings $lateSupportDirectory.bindings -ExpectedTree $lateSupportDirectory.tree `
                -EvidenceRoot $lateSupportDirectoryFixture.root -QualificationRoot $lateSupportDirectoryFixture.qualification -RunRoot $lateSupportDirectoryFixture.run -MaximumBytesByLeaf $supportBounds
        } "late ADS on support qualification directory"
    }
    finally { foreach ($supportBinding in @($lateSupportDirectory.bindings)) { Close-FaultGateRetainedPathBinding -Binding $supportBinding } }
    $oversizedSupportFixture = & $newSupportFixture "support-oversized" 4097
    Assert-SelfTestThrows {
        $null = Open-FaultGateSupportArtifactTree -EvidenceRoot $oversizedSupportFixture.root -QualificationRoot $oversizedSupportFixture.qualification `
            -RunRoot $oversizedSupportFixture.run -MaximumBytesByLeaf $supportBounds
    } "oversized support artifact rejected at retained open"
    $literalCoordinatorStderrOracle = Get-FaultGateExpectedInjectedCoordinatorStderr -CampaignDirectory "C:\raw\1-BTCUSDT-raw-111111111111"
    Assert-SelfTest ([uint64]$literalCoordinatorStderrOracle.bytes -eq 137 -and
        [string]$literalCoordinatorStderrOracle.sha256 -ceq "05f3af10004a918f2593b00ef9566e9d4d702244b98db83395873758c7778dbd" -and
        [string]$literalCoordinatorStderrOracle.terminal_failure -ceq "BTCUSDT coordinator wrote unexpected stderr (137 bytes)." -and
        [Convert]::ToBase64String([byte[]]$literalCoordinatorStderrOracle.canonical_bytes) -ceq "cmF3LWNhbXBhaWduOiByYXcgY2FtcGFpZ24gZmFpbGVkOiBnZW5lcmF0aW9uIDAgZXhpdGVkIHdpdGhvdXQgQ09NUExFVEUgdGVybWluYWwgZXZpZGVuY2U7IGV2aWRlbmNlIGF0IEM6XHJhd1wxLUJUQ1VTRFQtcmF3LTExMTExMTExMTExMQo=") `
        "Independent literal UTF-8/LF coordinator stderr oracle drifted."
    $launcherStartupIdentity = ([ordered]@{ launcher_executable_path = (Join-Path $PSHOME "powershell.exe"); launcher_executable_sha256 = "a" * 64 } | ConvertTo-Json -Compress | ConvertFrom-Json)
    $null = Test-FaultGateLauncherStartupExecutableBinding -Startup $launcherStartupIdentity -ExpectedPath (Join-Path $PSHOME "powershell.exe") -ExpectedSha256 ("a" * 64)
    $script:FaultSelfTestPassed++
    $launcherPathMutant = ($launcherStartupIdentity | ConvertTo-Json -Compress | ConvertFrom-Json); $launcherPathMutant.launcher_executable_path = "C:\Windows\not-powershell.exe"
    Assert-SelfTestThrows { $null = Test-FaultGateLauncherStartupExecutableBinding -Startup $launcherPathMutant -ExpectedPath (Join-Path $PSHOME "powershell.exe") -ExpectedSha256 ("a" * 64) } "launcher startup executable path"
    $launcherHashMutant = ($launcherStartupIdentity | ConvertTo-Json -Compress | ConvertFrom-Json); $launcherHashMutant.launcher_executable_sha256 = "b" * 64
    Assert-SelfTestThrows { $null = Test-FaultGateLauncherStartupExecutableBinding -Startup $launcherHashMutant -ExpectedPath (Join-Path $PSHOME "powershell.exe") -ExpectedSha256 ("a" * 64) } "launcher startup executable hash"
    $retainedProcessPath = Join-Path $PSHOME "powershell.exe"
    $publishedProcessIdentity = ([ordered]@{ executable_path = $retainedProcessPath; executable_sha256 = "a" * 64 } | ConvertTo-Json -Compress | ConvertFrom-Json)
    Test-FaultGateProcessExecutableBinding -Identity $publishedProcessIdentity -PublishedExecutablePath $retainedProcessPath -ExpectedExecutablePath $retainedProcessPath -ExpectedExecutableSha256 ("a" * 64) -Label "selftest process"
    $script:FaultSelfTestPassed++
    $sealedProcessPath = "C:\selftest\run\sealed-runtime\bin\raw_campaign.exe"
    $sealedProcessIdentity = ([ordered]@{ executable_path = $sealedProcessPath; executable_sha256 = "a" * 64 } | ConvertTo-Json -Compress | ConvertFrom-Json)
    Test-FaultGateProcessExecutableBinding -Identity $sealedProcessIdentity -PublishedExecutablePath $sealedProcessPath -ExpectedExecutablePath $sealedProcessPath -ExpectedExecutableSha256 ("a" * 64) -Label "selftest sealed process"
    $script:FaultSelfTestPassed++
    $byteIdenticalDifferentPath = ($publishedProcessIdentity | ConvertTo-Json -Compress | ConvertFrom-Json)
    $byteIdenticalDifferentPath.executable_path = "C:\selftest\byte-identical-powershell.exe"
    Assert-SelfTestThrows { Test-FaultGateProcessExecutableBinding -Identity $byteIdenticalDifferentPath -PublishedExecutablePath $byteIdenticalDifferentPath.executable_path -ExpectedExecutablePath $retainedProcessPath -ExpectedExecutableSha256 ("a" * 64) -Label "selftest process" } "byte-identical executable at different path"
    Assert-SelfTestThrows { Test-FaultGateProcessExecutableBinding -Identity $publishedProcessIdentity -PublishedExecutablePath "C:\selftest\published-copy.exe" -ExpectedExecutablePath $retainedProcessPath -ExpectedExecutableSha256 ("a" * 64) -Label "selftest process" } "published executable path differs from expected path"

    $earlyFailure = "BTCUSDT campaign heartbeat regressed or has no active generation."
    $reportedFailure = "BTCUSDT campaign heartbeat reported failure."
    $btcPrefix = New-SelfTestCampaignPrefix -Symbol "BTCUSDT"
    $ethPrefix = New-SelfTestCampaignPrefix -Symbol "ETHUSDT"
    $earlyNoTerminal = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -DisconnectCount 1) -Symbol "BTCUSDT" -LauncherFailure $earlyFailure -PreFaultPrefix $btcPrefix
    Assert-SelfTest ([string]$earlyNoTerminal.proof -ceq "TERMINAL_DISCONNECT_BEFORE_CAMPAIGN_FAILED") "Early heartbeat without terminal campaign record was rejected."
    $earlyWithTerminal = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 1) -Symbol "BTCUSDT" -LauncherFailure $earlyFailure -PreFaultPrefix $btcPrefix
    Assert-SelfTest ([string]$earlyWithTerminal.proof -ceq "DISCONNECT_AND_CAMPAIGN_FAILED") "Early heartbeat with exact terminal campaign record was rejected."
    $reported = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 1) -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $btcPrefix
    Assert-SelfTest ([uint64]$reported.campaign_failures -eq 1) "Reported-failure path lacks exact terminal campaign proof."
    $wallAdjustedCausality = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 1) -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $btcPrefix -InjectionRequestedWallNs 99
    Assert-SelfTest ([uint64]$wallAdjustedCausality.campaign_failures -eq 1) "Wall-clock adjustment incorrectly governed monotonic fault causality."
    $peer = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal) -Symbol "ETHUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $ethPrefix
    Assert-SelfTest ([string]$peer.proof -ceq "JOB_CONTAINED_PEER_WITHOUT_LOCAL_FAILURE") "ETH Job-contained peer proof was rejected."
    $btcTelemetryFinal = New-SelfTestEvidenceGeneration -Symbol "BTCUSDT" -RunRoot $tempRoot
    $ethTelemetryFinal = New-SelfTestEvidenceGeneration -Symbol "ETHUSDT" -RunRoot $tempRoot
    $btcRootHealthy = @(
        (New-SelfTestHealthyHeartbeatEntry -SessionId "session-BTCUSDT" -TelemetryRecordIndex 0 -TelemetryMonoNs 50),
        (New-SelfTestHealthySegmentEntry -SessionId "session-BTCUSDT" -Symbol "BTCUSDT" -Stream depth),
        (New-SelfTestHealthySegmentEntry -SessionId "session-BTCUSDT" -Symbol "BTCUSDT" -Stream trade)
    )
    $ethRootHealthy = @(
        (New-SelfTestHealthyHeartbeatEntry -SessionId "session-ETHUSDT" -TelemetryRecordIndex 0 -TelemetryMonoNs 50),
        (New-SelfTestHealthySegmentEntry -SessionId "session-ETHUSDT" -Symbol "ETHUSDT" -Stream depth),
        (New-SelfTestHealthySegmentEntry -SessionId "session-ETHUSDT" -Symbol "ETHUSDT" -Stream trade)
    )
    $validBtcHeartbeatJournal = New-SelfTestFullHealthyCampaignJournal -Symbol "BTCUSDT" -FinalRawGeneration $btcTelemetryFinal -RecurrentEvents ($btcRootHealthy + @((New-SelfTestHealthyHeartbeatEntry -SessionId "session-BTCUSDT"))) -DisconnectCount 1 -FailureCount 1
    $btcHealthyPrefix = New-SelfTestCampaignPrefixFromJournal -Journal $validBtcHeartbeatJournal -Symbol "BTCUSDT" -Records 10
    $null = Test-FaultGateInjectedCampaignCausality -Journal $validBtcHeartbeatJournal -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $btcHealthyPrefix -ExpectedDepthEpoch "epoch-BTCUSDT-depth" -ExpectedCampaignStartupSha256 ("6" * 64) -FinalRawGeneration $btcTelemetryFinal
    $script:FaultSelfTestPassed++
    $validEthHeartbeatJournal = New-SelfTestFullHealthyCampaignJournal -Symbol "ETHUSDT" -FinalRawGeneration $ethTelemetryFinal -RecurrentEvents ($ethRootHealthy + @((New-SelfTestHealthyHeartbeatEntry -SessionId "session-ETHUSDT")))
    $ethHealthyPrefix = New-SelfTestCampaignPrefixFromJournal -Journal $validEthHeartbeatJournal -Symbol "ETHUSDT" -Records 10
    $null = Test-FaultGateInjectedCampaignCausality -Journal $validEthHeartbeatJournal -Symbol "ETHUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $ethHealthyPrefix -ExpectedDepthEpoch "epoch-ETHUSDT-depth" -ExpectedCampaignStartupSha256 ("6" * 64) -FinalRawGeneration $ethTelemetryFinal
    $script:FaultSelfTestPassed++
    $alternateRaw = (($btcTelemetryFinal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $alternateJournal = (($validBtcHeartbeatJournal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $alternateInitial = $alternateJournal.entries[5]
    $alternateSnapshot = $alternateJournal.entries[6]
    $alternateSnapshot.body.record_index = [uint64]5
    $alternateSnapshot.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $alternateSnapshot.body)
    $alternateInitial.body.record_index = [uint64]6
    $alternateInitial.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $alternateInitial.body)
    $alternateJournal.entries[5] = $alternateSnapshot; $alternateJournal.entries[6] = $alternateInitial
    $alternateRaw.snapshot.campaign_event = $alternateSnapshot
    $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $alternateJournal -Records 10 -Symbol "BTCUSDT" -FinalRawGeneration $alternateRaw -ExpectedCampaignStartupSha256 ("6" * 64) -Label "self-test alternate snapshot/active ordering"
    $script:FaultSelfTestPassed++
    $serverShutdownPrefix = (($validBtcHeartbeatJournal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $serverShutdownPrefix.entries[7].body.payload = [pscustomobject][ordered]@{ event = "SERVER_SHUTDOWN_DURABLE" }
    Assert-SelfTestThrows { $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $serverShutdownPrefix -Records 10 -Symbol "BTCUSDT" -FinalRawGeneration $btcTelemetryFinal -ExpectedCampaignStartupSha256 ("6" * 64) -Label "self-test hidden server shutdown" } "SERVER_SHUTDOWN_DURABLE hidden inside frozen healthy prefix"
    $duplicateSnapshotPrefix = (($validBtcHeartbeatJournal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $duplicateSnapshotPrefix.entries[5] = (($duplicateSnapshotPrefix.entries[6] | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    Assert-SelfTestThrows { $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $duplicateSnapshotPrefix -Records 10 -Symbol "BTCUSDT" -FinalRawGeneration $btcTelemetryFinal -ExpectedCampaignStartupSha256 ("6" * 64) -Label "self-test duplicate snapshot" } "duplicate SNAPSHOT_DURABLE replaces INITIAL_ACTIVE_REGISTERED"
    $firstHeartbeatOne = (($validBtcHeartbeatJournal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $firstHeartbeatOne.entries[7].body.payload = (New-SelfTestHealthyHeartbeatEntry -SessionId "session-BTCUSDT" -TelemetryRecordIndex 1 -TelemetryMonoNs 100).body.payload
    Assert-SelfTestThrows { $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $firstHeartbeatOne -Records 10 -Symbol "BTCUSDT" -FinalRawGeneration $btcTelemetryFinal -ExpectedCampaignStartupSha256 ("6" * 64) -Label "self-test heartbeat seed" } "first HEARTBEAT_DURABLE does not bind telemetry record zero"
    $heartbeatReplay = (($validBtcHeartbeatJournal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $heartbeatReplay.entries[10].body.payload = (New-SelfTestHealthyHeartbeatEntry -SessionId "session-BTCUSDT" -TelemetryRecordIndex 0 -TelemetryMonoNs 50).body.payload
    Assert-SelfTestThrows { $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $heartbeatReplay -Records 11 -Symbol "BTCUSDT" -FinalRawGeneration $btcTelemetryFinal -ExpectedCampaignStartupSha256 ("6" * 64) -Label "self-test heartbeat replay" } "HEARTBEAT_DURABLE telemetry index replay"
    foreach ($heartbeatMutation in @("digest", "offset", "counter")) {
        $heartbeatMutant = (($validBtcHeartbeatJournal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
        switch ($heartbeatMutation) {
            "digest" { $heartbeatMutant.entries[7].body.payload.telemetry_record_sha256 = "9" * 64 }
            "offset" { $heartbeatMutant.entries[7].body.payload.telemetry_durable_through_offset = [uint64]1 }
            "counter" { $heartbeatMutant.entries[7].body.payload.depth_received = [uint64]11 }
        }
        Assert-SelfTestThrows { $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $heartbeatMutant -Records 10 -Symbol "BTCUSDT" -FinalRawGeneration $btcTelemetryFinal -ExpectedCampaignStartupSha256 ("6" * 64) -Label "self-test heartbeat $heartbeatMutation" } ("HEARTBEAT_DURABLE telemetry linkage " + $heartbeatMutation)
    }
    $segmentReplay = (($validBtcHeartbeatJournal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $segmentReplay.entries[9].body.payload = (New-SelfTestHealthySegmentEntry -SessionId "session-BTCUSDT" -Symbol "BTCUSDT" -Stream depth).body.payload
    Assert-SelfTestThrows { $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $segmentReplay -Records 10 -Symbol "BTCUSDT" -FinalRawGeneration $btcTelemetryFinal -ExpectedCampaignStartupSha256 ("6" * 64) -Label "self-test segment replay" } "SEGMENT_DURABLE per-stream replay"
    Assert-SelfTestThrows { $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $validBtcHeartbeatJournal -Records 10 -Symbol "BTCUSDT" -FinalRawGeneration $btcTelemetryFinal -ExpectedCampaignStartupSha256 ("9" * 64) -Label "self-test startup digest mismatch" } "CAMPAIGN_STARTED startup digest crosslink"
    $equalMonoRecord = (($btcTelemetryFinal.telemetry.verified_records[0].record | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $equalMonoRecord.record_index = [uint64]1
    Assert-SelfTestThrows { $null = Test-FaultGateTelemetryRecord -Record $equalMonoRecord -ExpectedIndex 1 -PreviousRecord $btcTelemetryFinal.telemetry.verified_records[0].record -DurationRequestedSeconds 600 -FreshnessStartupGraceSeconds 30 -FreshnessDeadlineSeconds 30 -Label "self-test equal telemetry mono" } "telemetry mono equality"
    $telemetryTypeMutant = (($btcTelemetryFinal.telemetry.verified_records[0].record | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $telemetryTypeMutant.depth_received = "10"
    Assert-SelfTestThrows { $null = Test-FaultGateTelemetryRecord -Record $telemetryTypeMutant -ExpectedIndex 0 -PreviousRecord $null -DurationRequestedSeconds 600 -FreshnessStartupGraceSeconds 30 -FreshnessDeadlineSeconds 30 -Label "self-test telemetry numeric string" } "telemetry numeric string"
    $telemetryUnknownMutant = (($btcTelemetryFinal.telemetry.verified_records[0].record | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $telemetryUnknownMutant | Add-Member -NotePropertyName unknown_field -NotePropertyValue 1
    Assert-SelfTestThrows { $null = Test-FaultGateTelemetryRecord -Record $telemetryUnknownMutant -ExpectedIndex 0 -PreviousRecord $null -DurationRequestedSeconds 600 -FreshnessStartupGraceSeconds 30 -FreshnessDeadlineSeconds 30 -Label "self-test telemetry unknown" } "telemetry unknown field"
    $coherentUnknownTelemetry = (($btcTelemetryFinal.telemetry | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $coherentUnknownPrefix = [Collections.Generic.List[byte]]::new()
    foreach ($unknownRow in @($coherentUnknownTelemetry.verified_records)) {
        $unknownRow.record.clock.quality = "UNKNOWN"; $unknownRow.record.clock.source = "non-Windows-selftest"
        $unknownRow.record.clock.leap_indicator = $null; $unknownRow.record.clock.stratum = $null; $unknownRow.record.clock.last_successful_sync = $null
        [byte[]]$unknownLine = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $unknownRow.record)
        [byte[]]$unknownLineLf = [byte[]]::new($unknownLine.Length + 1); [Array]::Copy($unknownLine, $unknownLineLf, $unknownLine.Length); $unknownLineLf[$unknownLine.Length] = 10
        $coherentUnknownPrefix.AddRange($unknownLineLf)
        $unknownRow.durable_through_offset = [uint64]$coherentUnknownPrefix.Count
        $unknownRow.record_sha256 = Get-FaultGateSha256Bytes -Bytes $unknownLineLf
    }
    $coherentUnknownTelemetry.observed_file_bytes = [uint64]$coherentUnknownPrefix.Count
    $coherentUnknownTelemetry.verified_through_offset = [uint64]$coherentUnknownPrefix.Count
    $coherentUnknownTelemetry.partial_tail_bytes = [uint64]0
    $coherentUnknownTelemetry.verified_prefix_sha256 = Get-FaultGateSha256Bytes -Bytes $coherentUnknownPrefix.ToArray()
    $coherentUnknownTelemetry.full_file_sha256 = [string]$coherentUnknownTelemetry.verified_prefix_sha256
    Assert-SelfTestThrows { $null = Test-FaultGateEvidenceTelemetry -Telemetry $coherentUnknownTelemetry -Label "self-test coordinated UNKNOWN telemetry evidence" } "coordinated self-hashed Windows telemetry UNKNOWN quality"
    $telemetryFixtureReport = New-SelfTestTelemetryReport
    $telemetryFixtureBuilder = [Text.StringBuilder]::new()
    foreach ($telemetryFixtureRow in @($telemetryFixtureReport.verified_records)) {
        $null = $telemetryFixtureBuilder.Append([Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateSerdeCompactJsonBytes -Value $telemetryFixtureRow.record))).Append([char]10)
    }
    $telemetryFixturePath = Join-Path $tempRoot "telemetry-fixture.jsonl"
    Write-SelfTestBytes -Path $telemetryFixturePath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($telemetryFixtureBuilder.ToString()))
    $telemetryFixtureScan = Read-FaultGateTelemetryPrefix -Path $telemetryFixturePath -DurationRequestedSeconds 600 -FreshnessStartupGraceSeconds 30 -FreshnessDeadlineSeconds 30
    Assert-SelfTest (@($telemetryFixtureScan.verified_records).Count -eq 2 -and [uint64]$telemetryFixtureScan.partial_tail_bytes -eq 0) "Valid byte-exact telemetry fixture was rejected."
    $telemetryWhitespacePath = Join-Path $tempRoot "telemetry-whitespace.jsonl"
    Write-SelfTestBytes -Path $telemetryWhitespacePath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($telemetryFixtureBuilder.ToString().Insert(1, " ")))
    Assert-SelfTestThrows { $null = Read-FaultGateTelemetryPrefix -Path $telemetryWhitespacePath -DurationRequestedSeconds 600 -FreshnessStartupGraceSeconds 30 -FreshnessDeadlineSeconds 30 } "telemetry writer-canonical whitespace"
    $telemetryDuplicatePath = Join-Path $tempRoot "telemetry-duplicate.jsonl"
    Write-SelfTestBytes -Path $telemetryDuplicatePath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($telemetryFixtureBuilder.ToString().Insert(1, '"schema":"CaptureTelemetryV1",')))
    Assert-SelfTestThrows { $null = Read-FaultGateTelemetryPrefix -Path $telemetryDuplicatePath -DurationRequestedSeconds 600 -FreshnessStartupGraceSeconds 30 -FreshnessDeadlineSeconds 30 } "telemetry duplicate key"
    $telemetryEqualMonoPath = Join-Path $tempRoot "telemetry-equal-mono.jsonl"
    $telemetryFirst = (($telemetryFixtureReport.verified_records[0].record | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $telemetrySecond = (($telemetryFirst | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json); $telemetrySecond.record_index = [uint64]1
    $telemetryEqualBuilder = [Text.StringBuilder]::new()
    foreach ($telemetryEqualRecord in @($telemetryFirst, $telemetrySecond)) { $null = $telemetryEqualBuilder.Append([Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateSerdeCompactJsonBytes -Value $telemetryEqualRecord))).Append([char]10) }
    Write-SelfTestBytes -Path $telemetryEqualMonoPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($telemetryEqualBuilder.ToString()))
    Assert-SelfTestThrows { $null = Read-FaultGateTelemetryPrefix -Path $telemetryEqualMonoPath -DurationRequestedSeconds 600 -FreshnessStartupGraceSeconds 30 -FreshnessDeadlineSeconds 30 } "telemetry byte-exact monotonic equality"
    $telemetryPartialPath = Join-Path $tempRoot "telemetry-partial.jsonl"
    Write-SelfTestBytes -Path $telemetryPartialPath -Bytes (@([Text.UTF8Encoding]::new($false).GetBytes($telemetryFixtureBuilder.ToString())) + [byte[]](123))
    Assert-SelfTestThrows { $null = Read-FaultGateTelemetryPrefix -Path $telemetryPartialPath -DurationRequestedSeconds 600 -FreshnessStartupGraceSeconds 30 -FreshnessDeadlineSeconds 30 } "telemetry strict partial tail"
    $telemetryPartialScan = Read-FaultGateTelemetryPrefix -Path $telemetryPartialPath -DurationRequestedSeconds 600 -FreshnessStartupGraceSeconds 30 -FreshnessDeadlineSeconds 30 -AllowPartialTail
    Assert-SelfTest ([uint64]$telemetryPartialScan.partial_tail_bytes -eq 1 -and @($telemetryPartialScan.verified_records).Count -eq 2) "Telemetry bounded partial-tail recovery did not preserve its exact durable prefix."
    [byte[]]$telemetryFixtureBytes = [Text.UTF8Encoding]::new($false).GetBytes($telemetryFixtureBuilder.ToString())
    $telemetryMaximumTailPath = Join-Path $tempRoot "telemetry-maximum-partial.jsonl"
    [byte[]]$telemetryMaximumTailBytes = [byte[]]::new($telemetryFixtureBytes.Length + [int]$script:FaultGateMaximumTelemetryPartialTailBytes)
    [Array]::Copy($telemetryFixtureBytes, 0, $telemetryMaximumTailBytes, 0, $telemetryFixtureBytes.Length)
    for ($tailIndex = $telemetryFixtureBytes.Length; $tailIndex -lt $telemetryMaximumTailBytes.Length; $tailIndex++) { $telemetryMaximumTailBytes[$tailIndex] = 123 }
    Write-SelfTestBytes -Path $telemetryMaximumTailPath -Bytes $telemetryMaximumTailBytes
    $telemetryMaximumTailScan = Read-FaultGateTelemetryPrefix -Path $telemetryMaximumTailPath -DurationRequestedSeconds 600 -FreshnessStartupGraceSeconds 30 -FreshnessDeadlineSeconds 30 -AllowPartialTail
    Assert-SelfTest ([uint64]$telemetryMaximumTailScan.partial_tail_bytes -eq $script:FaultGateMaximumTelemetryPartialTailBytes -and
        @($telemetryMaximumTailScan.verified_records).Count -eq 2) "Telemetry rejected the exact maximum writer-valid partial tail."
    $telemetryOversizedTailPath = Join-Path $tempRoot "telemetry-oversized-partial.jsonl"
    [byte[]]$telemetryOversizedTailBytes = [byte[]]::new($telemetryMaximumTailBytes.Length + 1)
    [Array]::Copy($telemetryMaximumTailBytes, 0, $telemetryOversizedTailBytes, 0, $telemetryMaximumTailBytes.Length)
    $telemetryOversizedTailBytes[$telemetryOversizedTailBytes.Length - 1] = 123
    Write-SelfTestBytes -Path $telemetryOversizedTailPath -Bytes $telemetryOversizedTailBytes
    Assert-SelfTestThrows { $null = Read-FaultGateTelemetryPrefix -Path $telemetryOversizedTailPath -DurationRequestedSeconds 600 -FreshnessStartupGraceSeconds 30 -FreshnessDeadlineSeconds 30 -AllowPartialTail } "telemetry maximum partial tail plus one"
    $telemetryOversizedEvidence = (($btcTelemetryFinal.telemetry | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $telemetryOversizedEvidence.observed_file_bytes = [uint64]$telemetryOversizedEvidence.verified_through_offset + $script:FaultGateMaximumTelemetryRecordBytes
    $telemetryOversizedEvidence.partial_tail_bytes = $script:FaultGateMaximumTelemetryRecordBytes
    Assert-SelfTestThrows { $null = Test-FaultGateEvidenceTelemetry -Telemetry $telemetryOversizedEvidence -Label "self-test oversized telemetry evidence" } "re-sealed telemetry evidence maximum partial tail plus one"
    $telemetryMaximumRecordEvidence = New-SelfTestSizedTelemetryEvidence -Source $btcTelemetryFinal.telemetry -RecordBytesIncludingLf $script:FaultGateMaximumTelemetryRecordBytes
    $null = Test-FaultGateEvidenceTelemetry -Telemetry $telemetryMaximumRecordEvidence -Label "self-test maximum telemetry record evidence"
    Assert-SelfTest $true "Evidence verifier rejected the exact maximum telemetry record including LF."
    $telemetryOversizedRecordEvidence = New-SelfTestSizedTelemetryEvidence -Source $btcTelemetryFinal.telemetry -RecordBytesIncludingLf ($script:FaultGateMaximumTelemetryRecordBytes + 1)
    Assert-SelfTestThrows { $null = Test-FaultGateEvidenceTelemetry -Telemetry $telemetryOversizedRecordEvidence -Label "self-test oversized telemetry record evidence" } "re-sealed telemetry complete record maximum plus one"
    $staleTelemetryRaw = (($btcTelemetryFinal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $staleTelemetryRaw.telemetry.verified_records = @($staleTelemetryRaw.telemetry.verified_records[0])
    $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $validBtcHeartbeatJournal -Records 11 -Symbol "BTCUSDT" -FinalRawGeneration $staleTelemetryRaw -ExpectedCampaignStartupSha256 ("6" * 64) -Label "self-test deferred heartbeat" -AllowRawLinkageDeferral
    $script:FaultSelfTestPassed++
    Assert-SelfTestThrows { $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $validBtcHeartbeatJournal -Records 11 -Symbol "BTCUSDT" -FinalRawGeneration $staleTelemetryRaw -ExpectedCampaignStartupSha256 ("6" * 64) -Label "self-test unresolved heartbeat" } "deferred heartbeat remains absent from final telemetry"
    $deferredSegmentsJournal = (($validBtcHeartbeatJournal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $deferredSegmentOne = New-SelfTestHealthySegmentEntry -SessionId "session-BTCUSDT" -Symbol "BTCUSDT" -Stream depth -SegmentIndex 1 -FirstFrameIndex 1 -LastFrameIndex 1 -PreviousSegmentTerminalSha256 ("a" * 64) -TerminalRecordSha256 ("c" * 64)
    $deferredSegmentTwo = New-SelfTestHealthySegmentEntry -SessionId "session-BTCUSDT" -Symbol "BTCUSDT" -Stream depth -SegmentIndex 2 -FirstFrameIndex 2 -LastFrameIndex 2 -PreviousSegmentTerminalSha256 ("c" * 64) -TerminalRecordSha256 ("d" * 64)
    $deferredSegmentOne.body.record_index = [uint64]10; $deferredSegmentTwo.body.record_index = [uint64]11
    $deferredSegmentsJournal.entries = @($deferredSegmentsJournal.entries[0..9]) + @($deferredSegmentOne, $deferredSegmentTwo)
    $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $deferredSegmentsJournal -Records 12 -Symbol "BTCUSDT" -FinalRawGeneration $btcTelemetryFinal -ExpectedCampaignStartupSha256 ("6" * 64) -Label "self-test deferred segment lineage" -AllowRawLinkageDeferral
    $script:FaultSelfTestPassed++
    Assert-SelfTestThrows { $null = Test-FaultGateHealthyGenerationZeroPrefix -Journal $deferredSegmentsJournal -Records 12 -Symbol "BTCUSDT" -FinalRawGeneration $btcTelemetryFinal -ExpectedCampaignStartupSha256 ("6" * 64) -Label "self-test unresolved segments" } "deferred segments absent from final raw scan"
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 1 -FailureChannel "SUPERVISOR") -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $btcPrefix } "campaign failure channel"
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 2) -Symbol "BTCUSDT" -LauncherFailure $earlyFailure -PreFaultPrefix $btcPrefix } "early heartbeat duplicate campaign failure"
    $reportedWithoutTerminal = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -DisconnectCount 1) -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $btcPrefix
    Assert-SelfTest ([string]$reportedWithoutTerminal.proof -ceq "TERMINAL_DISCONNECT_BEFORE_CAMPAIGN_FAILED") "Reported-heartbeat catch race without CAMPAIGN_FAILED was rejected."
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -DisconnectCount 1) -Symbol "ETHUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $ethPrefix } "peer false local failure"
    $optionalExit = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -ExitCount 1 -DisconnectCount 1 -FailureCount 1) -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $btcPrefix
    Assert-SelfTest ([string]$optionalExit.proof -ceq "DISCONNECT_AND_CAMPAIGN_FAILED") "Exact optional injected GENERATION_EXITED was rejected."
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -ExitCount 1 -ExitCode 1 -DisconnectCount 1 -FailureCount 1) -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $btcPrefix } "optional generation exit wrong code"
    $prefixMismatch = New-SelfTestCampaignPrefix -Symbol "BTCUSDT" -TerminalRecordSha256 ("f" * 64)
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 1) -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $prefixMismatch } "campaign prefix terminal mismatch"
    $preexistingPrefix = New-SelfTestCampaignPrefix -Symbol "BTCUSDT" -Records 3 -TerminalRecordSha256 (([uint64]12).ToString("x2") * 32)
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal (New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 1) -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $preexistingPrefix } "preexisting causal failure inside prefix"
    $reverseOrderJournal = New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 1
    $reverseOrderJournal.entries[1].body.record_index = [uint64]2
    $reverseOrderJournal.entries[2].body.record_index = [uint64]1
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal $reverseOrderJournal -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $btcPrefix } "campaign failure before disconnect"
    $trailingEarlyJournal = New-SelfTestCampaignJournal -DisconnectCount 1
    $trailingEarlyJournal.entries = @($trailingEarlyJournal.entries) + @(([ordered]@{ body = [ordered]@{ record_index = [uint64]$trailingEarlyJournal.records; generation_index = [uint64]0; channel = "CAMPAIGN"; payload = [ordered]@{ event = "UNCLASSIFIED_AFTER_DISCONNECT" } }; record_sha256 = "f" * 64 } | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json))
    $trailingEarlyJournal.records = [uint64]($trailingEarlyJournal.records + 1)
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal $trailingEarlyJournal -Symbol "BTCUSDT" -LauncherFailure $earlyFailure -PreFaultPrefix $btcPrefix } "early heartbeat nonterminal disconnect"
    $btcHeartbeatSuffix = New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 1
    $btcHeartbeatSuffix.entries = @($btcHeartbeatSuffix.entries) + @(([ordered]@{ body = [ordered]@{ record_index = [uint64]$btcHeartbeatSuffix.records; generation_index = [uint64]0; channel = "CHILD_STDOUT"; payload = [ordered]@{ event = "HEARTBEAT_DURABLE" } }; record_sha256 = "f" * 64 } | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json))
    $btcHeartbeatSuffix.records = [uint64]($btcHeartbeatSuffix.records + 1)
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal $btcHeartbeatSuffix -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $btcPrefix } "BTC valid but unclassified post-prefix heartbeat"
    $validHeartbeatAfterCausal = New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 1
    $lateHeartbeat = New-SelfTestHealthyHeartbeatEntry
    $lateHeartbeat.body.record_index = [uint64]$validHeartbeatAfterCausal.records
    $validHeartbeatAfterCausal.entries = @($validHeartbeatAfterCausal.entries) + @($lateHeartbeat)
    $validHeartbeatAfterCausal.records = [uint64]($validHeartbeatAfterCausal.records + 1)
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal $validHeartbeatAfterCausal -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $btcPrefix } "valid heartbeat after causal failure"
    $wrongDisconnectEpoch = New-SelfTestCampaignJournal -DisconnectCount 1 -FailureCount 1
    $wrongDisconnectEpoch.entries[1].body.payload.epoch = "trade-epoch"
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal $wrongDisconnectEpoch -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $btcPrefix } "disconnect wrong depth epoch"
    $ethTerminalSuffix = New-SelfTestCampaignJournal
    $ethTerminalSuffix.entries = @($ethTerminalSuffix.entries) + @(([ordered]@{ body = [ordered]@{ record_index = [uint64]$ethTerminalSuffix.records; generation_index = [uint64]0; channel = "CHILD_STDOUT"; payload = [ordered]@{ event = "PROCESS_TERMINAL" } }; record_sha256 = "e" * 64 } | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json))
    $ethTerminalSuffix.records = [uint64]($ethTerminalSuffix.records + 1)
    Assert-SelfTestThrows { $null = Test-FaultGateInjectedCampaignCausality -Journal $ethTerminalSuffix -Symbol "ETHUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $ethPrefix } "ETH valid but nonempty post-prefix suffix"

    $journalPath = Join-Path $tempRoot "valid.jsonl"
    $journal = New-RawQualificationJournal -Path $journalPath
    $null = Add-RawQualificationJournalRecord -Journal $journal -Schema "RawQualificationFaultGateEventV1" -Channel "SELFTEST" -WallNs 1 -MonotonicTick 1 -Payload ([ordered]@{ event = "ONE" })
    $null = Add-RawQualificationJournalRecord -Journal $journal -Schema "RawQualificationFaultGateEventV1" -Channel "SELFTEST" -WallNs 2 -MonotonicTick 2 -Payload ([ordered]@{ event = "TWO" })
    Close-RawQualificationJournal -Journal $journal
    $validJournal = Read-FaultGateJournal -Path $journalPath -ExpectedSchema "RawQualificationFaultGateEventV1" -RequireCleanTail -RequireCanonicalCompactJson
    Assert-SelfTest ($validJournal.records -eq 2) "Valid journal was not accepted."

    $partialPath = Join-Path $tempRoot "partial.jsonl"
    $journalBytes = [IO.File]::ReadAllBytes($journalPath)
    Write-SelfTestBytes -Path $partialPath -Bytes ([byte[]]$journalBytes[0..($journalBytes.Length - 2)])
    Assert-SelfTestThrows { $null = Read-FaultGateJournal -Path $partialPath -ExpectedSchema "RawQualificationFaultGateEventV1" -RequireCleanTail } "partial journal tail"

    $chainPath = Join-Path $tempRoot "chain.jsonl"
    $lines = ([Text.UTF8Encoding]::new($false, $true).GetString($journalBytes)).Split([char]10)
    $second = $lines[1] | ConvertFrom-Json
    $second.body.previous_record_sha256 = $script:FaultGateZeroDigest
    $second.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $second.body)
    $chainText = $lines[0] + "`n" + ($second | ConvertTo-Json -Depth 100 -Compress) + "`n"
    Write-SelfTestBytes -Path $chainPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($chainText))
    Assert-SelfTestThrows { $null = Read-FaultGateJournal -Path $chainPath -ExpectedSchema "RawQualificationFaultGateEventV1" -RequireCleanTail } "journal previous digest"
    $journalTypePath = Join-Path $tempRoot "journal-type.jsonl"
    $firstType = $lines[0] | ConvertFrom-Json
    $secondType = $lines[1] | ConvertFrom-Json
    $firstType.body.record_index = "0"
    $firstType.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $firstType.body)
    $secondType.body.previous_record_sha256 = $firstType.record_sha256
    $secondType.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $secondType.body)
    $journalTypeText = ($firstType | ConvertTo-Json -Depth 100 -Compress) + "`n" + ($secondType | ConvertTo-Json -Depth 100 -Compress) + "`n"
    Write-SelfTestBytes -Path $journalTypePath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($journalTypeText))
    Assert-SelfTestThrows { $null = Read-FaultGateJournal -Path $journalTypePath -ExpectedSchema "RawQualificationFaultGateEventV1" -RequireCleanTail } "journal numeric string"
    $journalDuplicatePath = Join-Path $tempRoot "journal-duplicate-key.jsonl"
    Write-SelfTestBytes -Path $journalDuplicatePath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(($lines[0].Insert(1, '"body":null,') + "`n")))
    Assert-SelfTestThrows { $null = Read-FaultGateJournal -Path $journalDuplicatePath -ExpectedSchema "RawQualificationFaultGateEventV1" -RequireCleanTail -RequireCanonicalCompactJson } "PowerShell journal duplicate key without rehash"
    $journalWhitespacePath = Join-Path $tempRoot "journal-whitespace.jsonl"
    Write-SelfTestBytes -Path $journalWhitespacePath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(($lines[0].Insert(1, " ") + "`n")))
    Assert-SelfTestThrows { $null = Read-FaultGateJournal -Path $journalWhitespacePath -ExpectedSchema "RawQualificationFaultGateEventV1" -RequireCleanTail -RequireCanonicalCompactJson } "PowerShell journal whitespace without rehash"

    $campaignJournalPath = Join-Path $tempRoot "campaign-valid.jsonl"
    Write-SelfTestCampaignJournalFixture -Path $campaignJournalPath
    $campaignJournalFixture = Read-FaultGateJournal -Path $campaignJournalPath -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCleanTail -RequireCanonicalCompactJson
    Assert-SelfTest ($campaignJournalFixture.records -eq 3) "Strict valid campaign journal fixture was rejected."
    $preRequestBaseJournal = New-SelfTestFullHealthyCampaignJournal -Symbol "BTCUSDT" -FinalRawGeneration $btcTelemetryFinal -RecurrentEvents $btcRootHealthy
    $preRequestCampaignPrefix = New-SelfTestCampaignPrefixFromJournal -Journal $preRequestBaseJournal -Symbol "BTCUSDT" -Records 10
    $preRequestWindow = Test-FaultGatePreInjectionCampaignWindow -Journal $preRequestBaseJournal -PreFaultPrefix $preRequestCampaignPrefix -Symbol "BTCUSDT" -ExpectedSessionId "session-BTCUSDT" -ExpectedCampaignStartupSha256 ("6" * 64) -FinalRawGeneration $btcTelemetryFinal
    Assert-SelfTest ([uint64]$preRequestWindow.allowed_healthy_suffix_records -eq 0 -and [uint64]$preRequestWindow.observed_records -eq 10) "Unchanged post-request campaign window was rejected."
    $postRequestHealthyMutant = (($preRequestBaseJournal | ConvertTo-Json -Depth 50 -Compress) | ConvertFrom-Json)
    $postRequestHeartbeat = New-SelfTestHealthyHeartbeatEntry -SessionId "session-BTCUSDT"
    $postRequestHeartbeat.body.record_index = [uint64]10
    $postRequestHealthyMutant.entries = @($postRequestHealthyMutant.entries) + @($postRequestHeartbeat)
    $postRequestHealthyMutant.records = [uint64]11
    $postRequestHealthyMutant.terminal_record_sha256 = [string]$postRequestHeartbeat.record_sha256
    $postRequestHealthyMutant.file_sha256 = "8" * 64
    $postRequestHealthyWindow = Test-FaultGatePreInjectionCampaignWindow -Journal $postRequestHealthyMutant -PreFaultPrefix $preRequestCampaignPrefix -Symbol "BTCUSDT" -ExpectedSessionId "session-BTCUSDT" -ExpectedCampaignStartupSha256 ("6" * 64) -FinalRawGeneration $btcTelemetryFinal
    Assert-SelfTest ([uint64]$postRequestHealthyWindow.allowed_healthy_suffix_records -eq 1) "Legitimate healthy journal extension after durable request was falsely rejected."
    $postRequestFailureMutant = (($preRequestBaseJournal | ConvertTo-Json -Depth 50 -Compress) | ConvertFrom-Json)
    $postRequestFailureMutant.entries = @($postRequestFailureMutant.entries) + @(([ordered]@{
        body = [ordered]@{ record_index = [uint64]10; generation_index = [uint64]0; channel = "SUPERVISOR"; payload = [ordered]@{ event = "GENERATION_DISCONNECT_FAIL_CLOSED" } }
        record_sha256 = "9" * 64
    } | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json))
    $postRequestFailureMutant.records = [uint64]11
    $postRequestFailureMutant.terminal_record_sha256 = "9" * 64
    $postRequestFailureMutant.file_sha256 = "8" * 64
    Assert-SelfTestThrows { $null = Test-FaultGatePreInjectionCampaignWindow -Journal $postRequestFailureMutant -PreFaultPrefix $preRequestCampaignPrefix -Symbol "BTCUSDT" -ExpectedSessionId "session-selftest" } "campaign failed after durable fault request but before TerminateProcess"
    $campaignUnknownPath = Join-Path $tempRoot "campaign-unknown.jsonl"
    Write-SelfTestCampaignJournalFixture -Path $campaignUnknownPath -Mutation { param($bodies) $bodies[1] | Add-Member -NotePropertyName unknown_field -NotePropertyValue 1 }
    Assert-SelfTestThrows { $null = Read-FaultGateJournal -Path $campaignUnknownPath -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCleanTail } "campaign journal unknown field"
    $campaignMissingPath = Join-Path $tempRoot "campaign-missing.jsonl"
    Write-SelfTestCampaignJournalFixture -Path $campaignMissingPath -Mutation { param($bodies) $bodies[1].PSObject.Properties.Remove("channel") }
    Assert-SelfTestThrows { $null = Read-FaultGateJournal -Path $campaignMissingPath -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCleanTail } "campaign journal missing field"
    $campaignMonoPath = Join-Path $tempRoot "campaign-mono-regression.jsonl"
    Write-SelfTestCampaignJournalFixture -Path $campaignMonoPath -Mutation { param($bodies) $bodies[2].campaign_mono_ns = [uint64]5 }
    Assert-SelfTestThrows { $null = Read-FaultGateJournal -Path $campaignMonoPath -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCleanTail } "campaign journal monotonic regression"
    $campaignCanonicalLines = ([Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($campaignJournalPath))).Split([char]10)
    $campaignDuplicatePath = Join-Path $tempRoot "campaign-duplicate-key.jsonl"
    Write-SelfTestBytes -Path $campaignDuplicatePath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(($campaignCanonicalLines[0].Insert(1, '"body":null,') + "`n")))
    Assert-SelfTestThrows { $null = Read-FaultGateJournal -Path $campaignDuplicatePath -ExpectedSchema "RawCampaignJournalRecordV1" -RequireCleanTail -RequireCanonicalCompactJson } "campaign journal duplicate key without rehash"

    $containment = [ordered]@{
        schema = "RawQualificationFailureContainmentV2"; job_name = "Local\SelfTest"; job_kill_on_close = $true
        detected_wall_ns = [uint64]1; detected_monotonic_tick = [uint64]2; requested_exit_code = [uint32]0xEE02
        initial_query_succeeded = $true; initial_active_processes = [uint32]3; initial_query_error = $null
        terminate_attempted = $true; terminate_succeeded = $true; terminate_error = $null; termination_monotonic_tick = [uint64]3
        monotonic_frequency = [uint64][Diagnostics.Stopwatch]::Frequency
        drain_deadline_s = [uint64]30; drain_elapsed_qpc_ticks = [uint64]4; final_query_succeeded = $true
        final_active_processes = [uint32]0; final_query_error = $null; result = "DRAINED_BY_ATTEMPT"
    }
    $terminal = (([ordered]@{ failure_containment = $containment; failure_containment_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $containment) } | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $verifiedContainment = Test-FaultGateFailureContainment -Terminal $terminal -ExpectedSchema "RawQualificationFailureContainmentV2" -ExpectedJobName "Local\SelfTest"
    Assert-SelfTest ($verifiedContainment.final_active_processes -eq 0) "Valid containment receipt was rejected."
    $concurrentContainmentTerminal = (($terminal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $concurrentContainmentTerminal.failure_containment.terminate_attempted = $false
    $concurrentContainmentTerminal.failure_containment.terminate_succeeded = $null
    $concurrentContainmentTerminal.failure_containment.terminate_error = $null
    $concurrentContainmentTerminal.failure_containment.result = "DRAINED_CONCURRENT_OR_PREEXISTING"
    $concurrentContainmentTerminal.failure_containment_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $concurrentContainmentTerminal.failure_containment)
    $null = Test-FaultGateFailureContainment -Terminal $concurrentContainmentTerminal -ExpectedSchema "RawQualificationFailureContainmentV2" -ExpectedJobName "Local\SelfTest"
    $queryErrorContainmentTerminal = (($terminal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $queryErrorContainmentTerminal.failure_containment.final_query_succeeded = $false
    $queryErrorContainmentTerminal.failure_containment.final_active_processes = $null
    $queryErrorContainmentTerminal.failure_containment.final_query_error = [uint32]5
    $queryErrorContainmentTerminal.failure_containment.result = "UNCONFIRMED_QUERY_ERROR"
    $queryErrorContainmentTerminal.failure_containment_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $queryErrorContainmentTerminal.failure_containment)
    $null = Test-FaultGateFailureContainment -Terminal $queryErrorContainmentTerminal -ExpectedSchema "RawQualificationFailureContainmentV2" -ExpectedJobName "Local\SelfTest"
    $nullabilityMutant = (($concurrentContainmentTerminal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $nullabilityMutant.failure_containment.terminate_succeeded = $false
    $nullabilityMutant.failure_containment_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $nullabilityMutant.failure_containment)
    Assert-SelfTestThrows { $null = Test-FaultGateFailureContainment -Terminal $nullabilityMutant -ExpectedSchema "RawQualificationFailureContainmentV2" -ExpectedJobName "Local\SelfTest" } "containment non-attempted nullable result"
    $queryNullabilityMutant = (($queryErrorContainmentTerminal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $queryNullabilityMutant.failure_containment.final_active_processes = [uint32]0
    $queryNullabilityMutant.failure_containment_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $queryNullabilityMutant.failure_containment)
    Assert-SelfTestThrows { $null = Test-FaultGateFailureContainment -Terminal $queryNullabilityMutant -ExpectedSchema "RawQualificationFailureContainmentV2" -ExpectedJobName "Local\SelfTest" } "containment failed-query nullable active count"
    foreach ($mutation in @("attempt", "active", "code", "code_string", "frequency", "deadline", "hash", "missing")) {
        $mutant = (($terminal | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
        switch ($mutation) {
            "attempt" { $mutant.failure_containment.terminate_attempted = $false }
            "active" { $mutant.failure_containment.final_active_processes = 1 }
            "code" { $mutant.failure_containment.requested_exit_code = 1 }
            "code_string" { $mutant.failure_containment.requested_exit_code = "60930" }
            "frequency" { $mutant.failure_containment.monotonic_frequency = [uint64]([Diagnostics.Stopwatch]::Frequency + 1) }
            "deadline" { $mutant.failure_containment.drain_deadline_s = [uint64]31 }
            "hash" { $mutant.failure_containment_sha256 = "f" * 64 }
            "missing" { $mutant.failure_containment.PSObject.Properties.Remove("result") }
        }
        if ($mutation -notin @("hash", "missing")) { $mutant.failure_containment_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $mutant.failure_containment) }
        Assert-SelfTestThrows { $null = Test-FaultGateFailureContainment -Terminal $mutant -ExpectedSchema "RawQualificationFailureContainmentV2" -ExpectedJobName "Local\SelfTest" } ("containment " + $mutation)
    }

    $terminalStartupPolicies = [pscustomobject][ordered]@{
        parameters = [pscustomobject][ordered]@{ total_s = [uint64]300; rotation_s = [uint64]240; overlap_s = [uint64]30; segment_s = [uint64]30 }
        verifier_policy = [pscustomobject][ordered]@{ per_process_timeout_s = [uint64]7200; total_post_capture_timeout_s = [uint64]14400; maximum_artifact_bytes = [uint64]33554432 }
        coordinator_log_policy = [pscustomobject][ordered]@{ maximum_stdout_bytes = [uint64]67108864; maximum_stderr_bytes = [uint64]0; child_stderr_events_allowed = [uint64]0 }
        market_freshness_policy = [pscustomobject][ordered]@{ startup_grace_s = [uint64]30; deadline_s = [uint64]30 }
        guardian_policy = [pscustomobject][ordered]@{
            pulse_file = "guardian-pulse.jsonl"; watchdog_ready_file = "watchdog-ready.json"; watchdog_startup_deadline_s = [uint64]90
            watchdog_deadline_s = [uint64]90; host_telemetry_gap_deadline_s = [uint64]120; maximum_dual_launch_skew_ms = [uint64]5000
            generation_terminal_deadline_s = [uint64]120; campaign_commit_deadline_s = [uint64]1800
        }
    }
    $terminalArtifactFields = @(
        "campaign_executable_sha256", "capture_executable_sha256", "campaign_verifier_executable_sha256", "public_config_sha256", "source_lock_sha256",
        "launcher_script_sha256", "monitor_script_sha256", "helper_script_sha256", "telemetry_probe_script_sha256", "watchdog_script_sha256",
        "watchdog_ready_file_sha256", "python_runtime_fingerprint_script_sha256", "powershell_executable_sha256", "python_executable_sha256",
        "python_verifier_source_tree_sha256", "python_runtime_tree_sha256", "python_pyvenv_config_sha256", "python_base_executable_sha256",
        "python_project_sha256", "python_requirements_sha256"
    )
    $terminalPreflightHashes = [ordered]@{}
    $terminalFinalHashes = [ordered]@{}
    $terminalPreflightArtifactFields = @($terminalArtifactFields | Where-Object { $_ -cne "watchdog_ready_file_sha256" })
    foreach ($terminalArtifactField in $terminalPreflightArtifactFields) { $terminalPreflightHashes[$terminalArtifactField] = "a" * 64 }
    foreach ($terminalArtifactField in $terminalArtifactFields) {
        $terminalFinalHashes[$terminalArtifactField] = if ($terminalArtifactField -cin @("python_runtime_tree_sha256", "python_pyvenv_config_sha256", "python_base_executable_sha256")) { $null } else { "a" * 64 }
    }
    $terminalV2 = [pscustomobject][ordered]@{
        schema = "RawQualificationLauncherTerminalV2"; status = "FAILED"; failure = "BTCUSDT campaign heartbeat reported failure."
        failure_containment = $containment; failure_containment_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $containment)
        run_id = "run-selftest"; mode = "Test"; run_root = $tempRoot; finished_utc = [DateTimeOffset]::UtcNow.ToString("o")
        launcher_elapsed_ms = [uint64]100; capture_elapsed_ms = [uint64]50
        parameters = $terminalStartupPolicies.parameters; verifier_policy = $terminalStartupPolicies.verifier_policy
        coordinator_log_policy = $terminalStartupPolicies.coordinator_log_policy; market_freshness_policy = $terminalStartupPolicies.market_freshness_policy
        guardian_policy = $terminalStartupPolicies.guardian_policy; startup_sha256 = "b" * 64; process_control_sha256 = "c" * 64; campaign_bindings_sha256 = "d" * 64
        launcher_events = [pscustomobject][ordered]@{ file = "launcher-events.jsonl"; records = [uint64]2; terminal_record_sha256 = "e" * 64; file_bytes = [uint64]200; file_sha256 = "f" * 64 }
        host_telemetry = [pscustomobject][ordered]@{ file = "host-telemetry.jsonl"; records = [uint64]1; terminal_record_sha256 = "1" * 64; file_sha256 = "2" * 64 }
        guardian_pulse = [pscustomobject][ordered]@{ file = "guardian-pulse.jsonl"; records = [uint64]1; terminal_record_sha256 = "3" * 64; file_sha256 = "4" * 64 }
        artifact_hashes_preflight = [pscustomobject]$terminalPreflightHashes; artifact_hashes_terminal = [pscustomobject]$terminalFinalHashes
        watchdog = $null; campaigns = @(); credentials = "NONE"; order_entry = "ABSENT"
    }
    Test-FaultGateLauncherTerminalV2Schema -Terminal $terminalV2 -Startup $terminalStartupPolicies
    $script:FaultSelfTestPassed++
    foreach ($terminalMutation in @("v1", "unknown", "reordered", "elapsed_type", "missing_nested", "runtime_on_failed", "campaign_result", "policy")) {
        $terminalMutant = (($terminalV2 | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
        switch ($terminalMutation) {
            "v1" { $terminalMutant.schema = "RawQualificationLauncherTerminalV1" }
            "unknown" { $terminalMutant | Add-Member -NotePropertyName unknown -NotePropertyValue 1 }
            "reordered" { $savedStatus = $terminalMutant.status; $terminalMutant.PSObject.Properties.Remove("status"); $terminalMutant | Add-Member -NotePropertyName status -NotePropertyValue $savedStatus }
            "elapsed_type" { $terminalMutant.launcher_elapsed_ms = "100" }
            "missing_nested" { $terminalMutant.launcher_events.PSObject.Properties.Remove("file_bytes") }
            "runtime_on_failed" { $terminalMutant.artifact_hashes_terminal.python_runtime_tree_sha256 = "9" * 64 }
            "campaign_result" { $terminalMutant.campaigns = @([pscustomobject]@{ symbol = "BTCUSDT" }) }
            "policy" { $terminalMutant.guardian_policy.watchdog_deadline_s = [uint64]91 }
        }
        Assert-SelfTestThrows { Test-FaultGateLauncherTerminalV2Schema -Terminal $terminalMutant -Startup $terminalStartupPolicies } ("launcher terminal V2 " + $terminalMutation)
    }

    $postLinkJournalPath = Join-Path $tempRoot "launcher-post-link.jsonl"
    $postLinkJournalWriter = New-RawQualificationJournal -Path $postLinkJournalPath
    $null = Add-RawQualificationJournalRecord -Journal $postLinkJournalWriter -Schema "RawQualificationLauncherEventV1" -Channel "FAILURE" -WallNs 1 -MonotonicTick 1 -Payload ([ordered]@{ event = "LAUNCHER_FAILED"; error = [string]$terminalV2.failure })
    $null = Add-RawQualificationJournalRecord -Journal $postLinkJournalWriter -Schema "RawQualificationLauncherEventV1" -Channel "FAILURE" -WallNs 2 -MonotonicTick 2 -Payload ([ordered]@{ event = "FAILURE_CONTAINMENT_TERMINAL"; failure_containment_sha256 = [string]$terminalV2.failure_containment_sha256 })
    $postLinkJournalWriter.Stream.Flush($true)
    $terminalV2.launcher_events.records = [uint64]$postLinkJournalWriter.NextIndex
    $terminalV2.launcher_events.terminal_record_sha256 = [string]$postLinkJournalWriter.Previous
    $terminalV2.launcher_events.file_bytes = [uint64]$postLinkJournalWriter.Stream.Length
    $terminalV2.launcher_events.file_sha256 = Get-FaultGateSha256File -Path $postLinkJournalPath
    [byte[]]$terminalV2Bytes = [Text.UTF8Encoding]::new($false).GetBytes((($terminalV2 | ConvertTo-Json -Depth 100) + "`n"))
    $terminalV2Sha256 = Get-FaultGateSha256Bytes -Bytes $terminalV2Bytes
    $null = Add-RawQualificationJournalRecord -Journal $postLinkJournalWriter -Schema "RawQualificationLauncherEventV1" -Channel "LAUNCHER" -WallNs 3 -MonotonicTick 3 -Payload ([ordered]@{
        event = "LAUNCHER_TERMINAL"; status = "FAILED"; failure = [string]$terminalV2.failure; terminal_file = "launcher-terminal.json"
        terminal_bytes = [uint64]$terminalV2Bytes.Length; terminal_sha256 = $terminalV2Sha256; failure_containment_sha256 = [string]$terminalV2.failure_containment_sha256
    })
    Close-RawQualificationJournal -Journal $postLinkJournalWriter
    $postLinkJournal = Read-FaultGateJournal -Path $postLinkJournalPath -ExpectedSchema "RawQualificationLauncherEventV1" -RequireCleanTail -RequireCanonicalCompactJson
    $postLinkProof = Test-FaultGateLauncherTerminalPostLink -LauncherJournalPath $postLinkJournalPath -LauncherJournal $postLinkJournal -Terminal $terminalV2 -TerminalBytes ([uint64]$terminalV2Bytes.Length) -TerminalSha256 $terminalV2Sha256 -ContainmentSha256 ([string]$terminalV2.failure_containment_sha256)
    Assert-SelfTest ([uint64]$postLinkProof.records -eq 2 -and [string]$postLinkProof.post_link_record_sha256 -ceq [string]$postLinkJournal.terminal_record_sha256) "Exact terminal V2 preterminal-prefix/post-link proof was rejected."
    $postLinkPrefixMutant = (($terminalV2 | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $postLinkPrefixMutant.launcher_events.records = [uint64]3
    Assert-SelfTestThrows { $null = Test-FaultGateLauncherTerminalPostLink -LauncherJournalPath $postLinkJournalPath -LauncherJournal $postLinkJournal -Terminal $postLinkPrefixMutant -TerminalBytes ([uint64]$terminalV2Bytes.Length) -TerminalSha256 $terminalV2Sha256 -ContainmentSha256 ([string]$terminalV2.failure_containment_sha256) } "terminal V2 claims full journal instead of preterminal prefix"

    $pyvenvFixtureRoot = Join-Path $tempRoot "pyvenv-parser"
    $pyvenvBaseRoot = Join-Path $pyvenvFixtureRoot "base"
    $null = New-Item -ItemType Directory -Path $pyvenvBaseRoot -Force -ErrorAction Stop
    $fallbackBaseExecutable = Join-Path $pyvenvBaseRoot "python.exe"
    $explicitBaseExecutable = Join-Path $pyvenvBaseRoot "python-explicit.exe"
    $escapedBaseExecutable = Join-Path $pyvenvFixtureRoot "python-escaped.exe"
    foreach ($fixtureExecutable in @($fallbackBaseExecutable, $explicitBaseExecutable, $escapedBaseExecutable)) {
        Write-SelfTestBytes -Path $fixtureExecutable -Bytes ([byte[]](1))
    }
    $validPyvenvPath = Join-Path $pyvenvFixtureRoot "valid-pyvenv.cfg"
    Write-SelfTestBytes -Path $validPyvenvPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes("# ignored`nHoMe = $pyvenvBaseRoot`nExEcUtAbLe = $explicitBaseExecutable`n"))
    $validPyvenvBinding = $null
    try {
        $validPyvenvBinding = Open-FaultGateRetainedPathBinding -Path $validPyvenvPath -Role "selftest_pyvenv"
        $validRuntimePaths = Get-FaultGatePythonRuntimePathsFromRetainedConfig -Binding $validPyvenvBinding
        Assert-SelfTest ([string]$validRuntimePaths.base_root -ceq [IO.Path]::GetFullPath($pyvenvBaseRoot).TrimEnd('\')) "Case-normalized pyvenv home was rejected."
        Assert-SelfTest ([string]$validRuntimePaths.base_executable -ceq [IO.Path]::GetFullPath($explicitBaseExecutable)) "Explicit pyvenv executable was not selected exactly."
        Assert-SelfTest ([string]$validRuntimePaths.base_executable -cne [IO.Path]::GetFullPath($fallbackBaseExecutable)) "pyvenv parser incorrectly synthesized home\\python.exe."
    }
    finally { Close-FaultGateRetainedPathBinding -Binding $validPyvenvBinding }
    $duplicatePyvenvPath = Join-Path $pyvenvFixtureRoot "duplicate-pyvenv.cfg"
    Write-SelfTestBytes -Path $duplicatePyvenvPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes("home = $pyvenvBaseRoot`nHOME = $pyvenvBaseRoot`nexecutable = $explicitBaseExecutable`n"))
    Assert-SelfTestThrows {
        $binding = $null
        try { $binding = Open-FaultGateRetainedPathBinding -Path $duplicatePyvenvPath -Role "selftest_pyvenv_duplicate"; $null = Get-FaultGatePythonRuntimePathsFromRetainedConfig -Binding $binding }
        finally { Close-FaultGateRetainedPathBinding -Binding $binding }
    } "pyvenv case-insensitive duplicate"
    $missingExecutablePyvenvPath = Join-Path $pyvenvFixtureRoot "missing-executable-pyvenv.cfg"
    Write-SelfTestBytes -Path $missingExecutablePyvenvPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes("home = $pyvenvBaseRoot`n"))
    Assert-SelfTestThrows {
        $binding = $null
        try { $binding = Open-FaultGateRetainedPathBinding -Path $missingExecutablePyvenvPath -Role "selftest_pyvenv_missing"; $null = Get-FaultGatePythonRuntimePathsFromRetainedConfig -Binding $binding }
        finally { Close-FaultGateRetainedPathBinding -Binding $binding }
    } "pyvenv missing executable"
    $escapedPyvenvPath = Join-Path $pyvenvFixtureRoot "escaped-pyvenv.cfg"
    Write-SelfTestBytes -Path $escapedPyvenvPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes("home = $pyvenvBaseRoot`nexecutable = $escapedBaseExecutable`n"))
    Assert-SelfTestThrows {
        $binding = $null
        try { $binding = Open-FaultGateRetainedPathBinding -Path $escapedPyvenvPath -Role "selftest_pyvenv_escape"; $null = Get-FaultGatePythonRuntimePathsFromRetainedConfig -Binding $binding }
        finally { Close-FaultGateRetainedPathBinding -Binding $binding }
    } "pyvenv executable escape"

    $binaryRoot = Join-Path $tempRoot "binary"
    $null = New-Item -ItemType Directory -Path $binaryRoot -ErrorAction Stop
    $emptySnapshotPath = Join-Path $binaryRoot "empty-live.bnack"
    Write-SelfTestBytes -Path $emptySnapshotPath -Bytes ([byte[]]::new(0))
    [byte[]]$emptySnapshotBytes = @(Read-FaultGateSnapshotBytes -Path $emptySnapshotPath)
    Assert-SelfTest ($emptySnapshotBytes.Length -eq 0 -and [Array]::IndexOf($emptySnapshotBytes, [byte]10) -eq -1 -and
        (Get-FaultGateSha256Bytes -Bytes $emptySnapshotBytes) -ceq "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") "Valid newly-created empty BNACK snapshot could not be classified and hashed safely."
    $fixture = New-SelfTestRawFixture -Root $binaryRoot
    $manifest = Read-FaultGateSegmentManifest -Path $fixture.manifest
    $progress = Read-FaultGateProgress -Path $fixture.progress -ExpectedRawFile "segment-000000.bnraw" -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -FirstFrameIndex 0
    $raw = Read-FaultGateRawPrefix -Path $fixture.raw -Limit $fixture.raw_bytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46" -Acknowledgements $progress.acknowledgements
    Assert-SelfTest ($manifest.records -eq 1 -and $progress.latest_ack.last_record_sha256 -ceq $raw.terminal_record_sha256) "Valid BNSEG/BNACK/BNRAW fixture was rejected."
    [byte[]]$immutableProgressSnapshot = [IO.File]::ReadAllBytes($fixture.progress)
    $invalidProgressPath = Join-Path $tempRoot "progress-invalid-live-state.bnack"
    Write-SelfTestBytes -Path $invalidProgressPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes('{'))
    $progressFromSnapshot = Read-FaultGateProgress -Path $invalidProgressPath -ExpectedRawFile "segment-000000.bnraw" -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -FirstFrameIndex 0 -SnapshotBytes $immutableProgressSnapshot
    Assert-SelfTest ($progressFromSnapshot.records -eq 1 -and [string]$progressFromSnapshot.file_sha256 -ceq [string]$progress.file_sha256) "BNACK parser reopened a path instead of consuming its supplied immutable live snapshot."
    Assert-SelfTest ([uint64]$raw.durable_through_offset -eq [uint64]$fixture.raw_bytes -and [string]$raw.verified_prefix_sha256 -ceq [string]$raw.full_file_sha256) "BNRAW same-handle verified-prefix digest was not retained."
    $rawFrameOverflowEvidence = (($raw | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $rawFrameOverflowEvidence.first_frame_index = [uint64]::MaxValue
    $rawFrameOverflowEvidence.durable_records = [uint64]2
    $rawFrameOverflowEvidence.last_frame_index = [uint64]::MaxValue
    Assert-SelfTestThrows { $null = Test-FaultGateEvidenceRawPrefix -Raw $rawFrameOverflowEvidence -Label "self-test BNRAW frame overflow evidence" } "re-sealed BNRAW first plus records overflow"
    Assert-SelfTest ([uint64]$progress.verified_through_offset -eq [uint64]$progress.file_bytes -and [uint64]$progress.partial_tail_bytes -eq 0 -and [string]$progress.verified_prefix_sha256 -ceq [string]$progress.file_sha256) "BNACK exact verified-prefix boundary was not retained."
    $null = Assert-FaultGatePreservedFilePrefix -Path $fixture.raw -Length ([uint64]$raw.durable_through_offset) -ExpectedSha256 ([string]$raw.verified_prefix_sha256) -Label "self-test BNRAW prefix"
    Assert-SelfTest $true "Valid BNRAW exact-prefix preservation proof was rejected."
    $null = Assert-FaultGatePreservedFilePrefix -Path $fixture.progress -Length ([uint64]$progress.verified_through_offset) -ExpectedSha256 ([string]$progress.verified_prefix_sha256) -Label "self-test BNACK prefix"
    Assert-SelfTest $true "Valid BNACK exact-prefix preservation proof was rejected."
    [byte[]]$rawPrefixBytes = [IO.File]::ReadAllBytes($fixture.raw)
    $rawPrefixShrink = Join-Path $tempRoot "raw-prefix-shrink.bnraw"
    Write-SelfTestBytes -Path $rawPrefixShrink -Bytes ([byte[]]$rawPrefixBytes[0..($rawPrefixBytes.Length - 2)])
    Assert-SelfTestThrows { Assert-FaultGatePreservedFilePrefix -Path $rawPrefixShrink -Length ([uint64]$raw.durable_through_offset) -ExpectedSha256 ([string]$raw.verified_prefix_sha256) -Label "self-test BNRAW shrink" } "BNRAW preserved prefix shrink"
    $rawPrefixDrift = Join-Path $tempRoot "raw-prefix-drift.bnraw"
    [byte[]]$rawDriftBytes = @($rawPrefixBytes); $rawDriftBytes[0] = $rawDriftBytes[0] -bxor 1
    Write-SelfTestBytes -Path $rawPrefixDrift -Bytes $rawDriftBytes
    Assert-SelfTestThrows { Assert-FaultGatePreservedFilePrefix -Path $rawPrefixDrift -Length ([uint64]$raw.durable_through_offset) -ExpectedSha256 ([string]$raw.verified_prefix_sha256) -Label "self-test BNRAW drift" } "BNRAW preserved prefix byte drift"
    $rawPrefixExtension = Join-Path $tempRoot "raw-prefix-extension.bnraw"
    [byte[]]$rawExtendedBytes = @($rawPrefixBytes) + [byte[]](1, 2, 3)
    Write-SelfTestBytes -Path $rawPrefixExtension -Bytes $rawExtendedBytes
    $null = Assert-FaultGatePreservedFilePrefix -Path $rawPrefixExtension -Length ([uint64]$raw.durable_through_offset) -ExpectedSha256 ([string]$raw.verified_prefix_sha256) -Label "self-test BNRAW extension"
    Assert-SelfTest $true "Legitimate BNRAW append changed its fixed prefix proof."
    $rawPrefixExtensionDrift = Join-Path $tempRoot "raw-prefix-extension-drift.bnraw"
    [byte[]]$rawExtendedDriftBytes = @($rawDriftBytes) + [byte[]](1, 2, 3)
    Write-SelfTestBytes -Path $rawPrefixExtensionDrift -Bytes $rawExtendedDriftBytes
    Assert-SelfTestThrows { Assert-FaultGatePreservedFilePrefix -Path $rawPrefixExtensionDrift -Length ([uint64]$raw.durable_through_offset) -ExpectedSha256 ([string]$raw.verified_prefix_sha256) -Label "self-test BNRAW extension drift" } "BNRAW extension with historical-prefix drift"
    [byte[]]$ackPrefixBytes = [IO.File]::ReadAllBytes($fixture.progress)
    $ackPrefixShrink = Join-Path $tempRoot "ack-prefix-shrink.bnack"
    Write-SelfTestBytes -Path $ackPrefixShrink -Bytes ([byte[]]$ackPrefixBytes[0..($ackPrefixBytes.Length - 2)])
    Assert-SelfTestThrows { Assert-FaultGatePreservedFilePrefix -Path $ackPrefixShrink -Length ([uint64]$progress.verified_through_offset) -ExpectedSha256 ([string]$progress.verified_prefix_sha256) -Label "self-test BNACK shrink" } "BNACK preserved prefix shrink"
    $ackPrefixDrift = Join-Path $tempRoot "ack-prefix-drift.bnack"
    [byte[]]$ackDriftBytes = @($ackPrefixBytes); $ackDriftBytes[0] = $ackDriftBytes[0] -bxor 1
    Write-SelfTestBytes -Path $ackPrefixDrift -Bytes $ackDriftBytes
    Assert-SelfTestThrows { Assert-FaultGatePreservedFilePrefix -Path $ackPrefixDrift -Length ([uint64]$progress.verified_through_offset) -ExpectedSha256 ([string]$progress.verified_prefix_sha256) -Label "self-test BNACK drift" } "BNACK preserved prefix byte drift"
    $ackPrefixExtension = Join-Path $tempRoot "ack-prefix-extension.bnack"
    [byte[]]$ackExtendedBytes = @($ackPrefixBytes) + [Text.UTF8Encoding]::new($false).GetBytes("tail")
    Write-SelfTestBytes -Path $ackPrefixExtension -Bytes $ackExtendedBytes
    $null = Assert-FaultGatePreservedFilePrefix -Path $ackPrefixExtension -Length ([uint64]$progress.verified_through_offset) -ExpectedSha256 ([string]$progress.verified_prefix_sha256) -Label "self-test BNACK extension"
    Assert-SelfTest $true "Legitimate BNACK append changed its fixed prefix proof."
    $ackPrefixExtensionDrift = Join-Path $tempRoot "ack-prefix-extension-drift.bnack"
    [byte[]]$ackExtendedDriftBytes = @($ackDriftBytes) + [Text.UTF8Encoding]::new($false).GetBytes("tail")
    Write-SelfTestBytes -Path $ackPrefixExtensionDrift -Bytes $ackExtendedDriftBytes
    Assert-SelfTestThrows { Assert-FaultGatePreservedFilePrefix -Path $ackPrefixExtensionDrift -Length ([uint64]$progress.verified_through_offset) -ExpectedSha256 ([string]$progress.verified_prefix_sha256) -Label "self-test BNACK extension drift" } "BNACK extension with historical-prefix drift"
    Assert-SelfTestThrows { $null = Read-FaultGateRawPrefix -Path $fixture.raw -Limit $fixture.raw_bytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@trade" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46" } "BNRAW endpoint identity"
    $rawMutant = Join-Path $tempRoot "raw-mutant.bnraw"
    $rawBytes = [IO.File]::ReadAllBytes($fixture.raw); $rawBytes[$rawBytes.Length - 1] = $rawBytes[$rawBytes.Length - 1] -bxor 1
    Write-SelfTestBytes -Path $rawMutant -Bytes $rawBytes
    Assert-SelfTestThrows { $null = Read-FaultGateRawPrefix -Path $rawMutant -Limit $fixture.raw_bytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46" } "BNRAW digest"
    $rawWhitespacePath = Join-Path $tempRoot "raw-whitespace.bnraw"
    $rawWhitespaceBytes = New-SelfTestRawJsonTextMutant -Source $fixture.raw -Destination $rawWhitespacePath -Mutation { param($text) $text.Insert(1, " ") }
    Assert-SelfTestThrows { $null = Read-FaultGateRawPrefix -Path $rawWhitespacePath -Limit $rawWhitespaceBytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46" } "BNRAW compact canonical whitespace"
    $rawDuplicatePath = Join-Path $tempRoot "raw-duplicate.bnraw"
    $rawDuplicateBytes = New-SelfTestRawJsonTextMutant -Source $fixture.raw -Destination $rawDuplicatePath -Mutation { param($text) $text.Insert(1, '"schema":"RawFrameV1",') }
    Assert-SelfTestThrows { $null = Read-FaultGateRawPrefix -Path $rawDuplicatePath -Limit $rawDuplicateBytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46" } "BNRAW duplicate key"
    $rawNumericFormatPath = Join-Path $tempRoot "raw-numeric-format.bnraw"
    $rawNumericFormatBytes = New-SelfTestRawJsonTextMutant -Source $fixture.raw -Destination $rawNumericFormatPath -Mutation { param($text) $text.Replace('"receive_wall_ns":1,', '"receive_wall_ns":1.0,') }
    Assert-SelfTestThrows { $null = Read-FaultGateRawPrefix -Path $rawNumericFormatPath -Limit $rawNumericFormatBytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46" } "BNRAW noncanonical numeric formatting"
    $wallStringPath = Join-Path $tempRoot "raw-wall-string.bnraw"
    $wallStringBytes = New-SelfTestRawSemanticMutant -Source $fixture.raw -Destination $wallStringPath -Mutation { param($body) $body.receive_wall_ns = "1" }
    Assert-SelfTestThrows { $null = Read-FaultGateRawPrefix -Path $wallStringPath -Limit $wallStringBytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46" } "BNRAW receive_wall_ns numeric string"
    $frameStringPath = Join-Path $tempRoot "raw-frame-string.bnraw"
    $frameStringBytes = New-SelfTestRawSemanticMutant -Source $fixture.raw -Destination $frameStringPath -Mutation { param($body) $body.frame_index = "0" }
    Assert-SelfTestThrows { $null = Read-FaultGateRawPrefix -Path $frameStringPath -Limit $frameStringBytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46" } "BNRAW frame_index numeric string"
    $clockNullPath = Join-Path $tempRoot "raw-clock-null.bnraw"
    $clockNullBytes = New-SelfTestRawSemanticMutant -Source $fixture.raw -Destination $clockNullPath -Mutation { param($body) $body.clock_quality = $null }
    Assert-SelfTestThrows { $null = Read-FaultGateRawPrefix -Path $clockNullPath -Limit $clockNullBytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46" } "BNRAW null clock quality"
    $opaquePayloadPath = Join-Path $tempRoot "raw-payload-opaque.bnraw"
    $opaquePayloadBytes = New-SelfTestRawSemanticMutant -Source $fixture.raw -Destination $opaquePayloadPath -Mutation {
        param($body)
        [byte[]]$opaquePayload = [byte[]](0, 255, 1, 254, 2)
        $body.payload_base64 = [Convert]::ToBase64String($opaquePayload)
        $body.payload_length = [uint64]$opaquePayload.Length
        $body.payload_sha256 = Get-FaultGateSha256Bytes -Bytes $opaquePayload
    }
    $opaqueRaw = Read-FaultGateRawPrefix -Path $opaquePayloadPath -Limit $opaquePayloadBytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46"
    Assert-SelfTest ([uint64]$opaqueRaw.durable_records -eq 1 -and [uint64]$opaqueRaw.durable_through_offset -eq [uint64]$opaquePayloadBytes) "Valid opaque binary BNRAW payload was rejected."
    $emptyPayloadPath = Join-Path $tempRoot "raw-payload-empty.bnraw"
    $emptyPayloadBytes = New-SelfTestRawSemanticMutant -Source $fixture.raw -Destination $emptyPayloadPath -Mutation {
        param($body)
        [byte[]]$emptyPayload = [byte[]]@()
        $body.payload_base64 = ""
        $body.payload_length = [uint64]0
        $body.payload_sha256 = Get-FaultGateSha256Bytes -Bytes $emptyPayload
    }
    $emptyRaw = Read-FaultGateRawPrefix -Path $emptyPayloadPath -Limit $emptyPayloadBytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46"
    Assert-SelfTest ([uint64]$emptyRaw.durable_records -eq 1 -and [uint64]$emptyRaw.durable_through_offset -eq [uint64]$emptyPayloadBytes) "Valid empty opaque BNRAW payload was rejected."
    $maximumFramePath = Join-Path $tempRoot "raw-frame-u64-maximum.bnraw"
    $maximumFrameBytes = New-SelfTestRawSemanticMutant -Source $fixture.raw -Destination $maximumFramePath -Mutation { param($body) $body.frame_index = [uint64]::MaxValue }
    $maximumFrameRaw = Read-FaultGateRawPrefix -Path $maximumFramePath -Limit $maximumFrameBytes -ExpectedRecords 1 -FirstFrameIndex ([uint64]::MaxValue) -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46"
    Assert-SelfTest ([uint64]$maximumFrameRaw.first_frame_index -eq [uint64]::MaxValue -and [uint64]$maximumFrameRaw.last_frame_index -eq [uint64]::MaxValue) "Valid BNRAW UInt64 maximum frame index was rejected or rounded."
    $payloadBase64Path = Join-Path $tempRoot "raw-payload-base64-noncanonical.bnraw"
    $payloadBase64Bytes = New-SelfTestRawSemanticMutant -Source $fixture.raw -Destination $payloadBase64Path -Mutation { param($body) $body.payload_base64 = ([string]$body.payload_base64).Insert(2, "`n") }
    Assert-SelfTestThrows { $null = Read-FaultGateRawPrefix -Path $payloadBase64Path -Limit $payloadBase64Bytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46" } "BNRAW noncanonical base64"
    $manifestMutant = Join-Path $tempRoot "manifest-mutant.bnseg"
    $manifestBytes = [IO.File]::ReadAllBytes($fixture.manifest); $manifestBytes[$manifestBytes.Length - 1] = $manifestBytes[$manifestBytes.Length - 1] -bxor 1
    Write-SelfTestBytes -Path $manifestMutant -Bytes $manifestBytes
    Assert-SelfTestThrows { $null = Read-FaultGateSegmentManifest -Path $manifestMutant } "BNSEG digest"
    $manifestTypeMutant = Join-Path $tempRoot "manifest-type-mutant.bnseg"
    New-SelfTestManifestSemanticMutant -Source $fixture.manifest -Destination $manifestTypeMutant -Mutation { param($body) $body.seal.records = "1" }
    Assert-SelfTestThrows { $null = Read-FaultGateSegmentManifest -Path $manifestTypeMutant } "BNSEG numeric string"
    $manifestPartial = Join-Path $tempRoot "manifest-partial.bnseg"
    [byte[]]$manifestPartialBytes = @([IO.File]::ReadAllBytes($fixture.manifest)) + [byte[]](0, 0)
    Write-SelfTestBytes -Path $manifestPartial -Bytes $manifestPartialBytes
    Assert-SelfTestThrows { $null = Read-FaultGateSegmentManifest -Path $manifestPartial } "BNSEG partial tail strict"
    $recoveredManifest = Read-FaultGateSegmentManifest -Path $manifestPartial -AllowPartialTail
    Assert-SelfTest ($recoveredManifest.records -eq 1 -and $recoveredManifest.partial_tail_bytes -eq 2) "BNSEG complete prefix recovery rejected a bounded partial tail."
    $progressPartial = Join-Path $tempRoot "progress-partial.bnack"
    [byte[]]$progressPartialBytes = @([IO.File]::ReadAllBytes($fixture.progress)) + [Text.UTF8Encoding]::new($false).GetBytes('{')
    Write-SelfTestBytes -Path $progressPartial -Bytes $progressPartialBytes
    Assert-SelfTestThrows { $null = Read-FaultGateProgress -Path $progressPartial -ExpectedRawFile "segment-000000.bnraw" -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -FirstFrameIndex 0 } "BNACK partial tail strict"
    $recoveredProgress = Read-FaultGateProgress -Path $progressPartial -ExpectedRawFile "segment-000000.bnraw" -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -FirstFrameIndex 0 -AllowPartialTail
    Assert-SelfTest ($recoveredProgress.records -eq 1 -and $recoveredProgress.partial_tail -and
        [uint64]$recoveredProgress.verified_through_offset -eq [uint64]$progress.file_bytes -and
        [uint64]$recoveredProgress.partial_tail_bytes -eq 1 -and
        [string]$recoveredProgress.verified_prefix_sha256 -ceq [string]$progress.file_sha256) "BNACK complete prefix recovery rejected or misbound a bounded partial tail."
    [byte[]]$progressFixtureBytes = [IO.File]::ReadAllBytes($fixture.progress)
    $progressMaximumTailPath = Join-Path $tempRoot "progress-maximum-partial.bnack"
    [byte[]]$progressMaximumTailBytes = [byte[]]::new($progressFixtureBytes.Length + [int]$script:FaultGateMaximumProgressPartialTailBytes)
    [Array]::Copy($progressFixtureBytes, 0, $progressMaximumTailBytes, 0, $progressFixtureBytes.Length)
    for ($tailIndex = $progressFixtureBytes.Length; $tailIndex -lt $progressMaximumTailBytes.Length; $tailIndex++) { $progressMaximumTailBytes[$tailIndex] = 123 }
    Write-SelfTestBytes -Path $progressMaximumTailPath -Bytes $progressMaximumTailBytes
    $progressMaximumTailScan = Read-FaultGateProgress -Path $progressMaximumTailPath -ExpectedRawFile "segment-000000.bnraw" -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -FirstFrameIndex 0 -AllowPartialTail
    Assert-SelfTest ($progressMaximumTailScan.records -eq 1 -and $progressMaximumTailScan.partial_tail -and
        [uint64]$progressMaximumTailScan.partial_tail_bytes -eq $script:FaultGateMaximumProgressPartialTailBytes) "BNACK rejected the exact maximum writer-valid partial tail."
    $progressOversizedTailPath = Join-Path $tempRoot "progress-oversized-partial.bnack"
    [byte[]]$progressOversizedTailBytes = [byte[]]::new($progressMaximumTailBytes.Length + 1)
    [Array]::Copy($progressMaximumTailBytes, 0, $progressOversizedTailBytes, 0, $progressMaximumTailBytes.Length)
    $progressOversizedTailBytes[$progressOversizedTailBytes.Length - 1] = 123
    Write-SelfTestBytes -Path $progressOversizedTailPath -Bytes $progressOversizedTailBytes
    Assert-SelfTestThrows { $null = Read-FaultGateProgress -Path $progressOversizedTailPath -ExpectedRawFile "segment-000000.bnraw" -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -FirstFrameIndex 0 -AllowPartialTail } "BNACK maximum partial tail plus one"
    $progressOversizedEvidence = (($progress | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $progressOversizedEvidence.file_bytes = [uint64]$progressOversizedEvidence.verified_through_offset + $script:FaultGateMaximumProgressPartialTailBytes + 1
    $progressOversizedEvidence.partial_tail_bytes = $script:FaultGateMaximumProgressPartialTailBytes + 1
    $progressOversizedEvidence.partial_tail = $true
    Assert-SelfTestThrows { $null = Test-FaultGateEvidenceProgress -Progress $progressOversizedEvidence -Label "self-test oversized BNACK evidence" } "re-sealed BNACK evidence maximum partial tail plus one"
    $progressMaximumRecordEvidence = New-SelfTestSizedProgressEvidence -Source $progress -RecordBytesExcludingLf $script:FaultGateMaximumProgressRecordBytes
    $null = Test-FaultGateEvidenceProgress -Progress $progressMaximumRecordEvidence -Label "self-test maximum BNACK record evidence"
    Assert-SelfTest $true "Evidence verifier rejected the exact maximum BNACK record excluding LF."
    $progressOversizedRecordEvidence = New-SelfTestSizedProgressEvidence -Source $progress -RecordBytesExcludingLf ($script:FaultGateMaximumProgressRecordBytes + 1)
    Assert-SelfTestThrows { $null = Test-FaultGateEvidenceProgress -Progress $progressOversizedRecordEvidence -Label "self-test oversized BNACK record evidence" } "re-sealed BNACK complete record maximum plus one"
    $unverifiedPairAtMaximum = [pscustomobject][ordered]@{
        segment_index = [uint64]0; sealed = $false; durable_prefix = $false
        raw_file_bytes = [uint64]8; raw_file_sha256 = "1" * 64
        progress_file_bytes = $script:FaultGateMaximumProgressPartialTailBytes; progress_file_sha256 = "2" * 64
    }
    $null = Test-FaultGateEvidenceSegment -Segment $unverifiedPairAtMaximum -Label "self-test maximum unverified BNACK pair"
    Assert-SelfTest $true "Evidence verifier rejected the exact maximum non-authoritative BNACK tail."
    $unverifiedPairOversized = (($unverifiedPairAtMaximum | ConvertTo-Json -Depth 20 -Compress) | ConvertFrom-Json)
    $unverifiedPairOversized.progress_file_bytes = $script:FaultGateMaximumProgressPartialTailBytes + 1
    Assert-SelfTestThrows { $null = Test-FaultGateEvidenceSegment -Segment $unverifiedPairOversized -Label "self-test oversized unverified BNACK pair" } "re-sealed unverified BNACK tail maximum plus one"
    $orphanAckEvidence = [pscustomobject][ordered]@{
        segment_index = [uint64]0; sealed = $false; durable_prefix = $false
        sole_partial_file = "segment-000000.bnack"; sole_partial_file_bytes = [uint64]1; sole_partial_file_sha256 = "3" * 64
    }
    Assert-SelfTestThrows { $null = Test-FaultGateEvidenceSegment -Segment $orphanAckEvidence -Label "self-test orphan ACK evidence" } "re-sealed orphan BNACK without BNRAW predecessor"
    $soleRawEvidence = (($orphanAckEvidence | ConvertTo-Json -Depth 20 -Compress) | ConvertFrom-Json)
    $soleRawEvidence.sole_partial_file = "segment-000000.bnraw"
    $null = Test-FaultGateEvidenceSegment -Segment $soleRawEvidence -Label "self-test sole raw predecessor evidence"
    Assert-SelfTest $true "Evidence verifier rejected the legitimate raw-only creation transient."
    $activeDurableRaw = (($raw | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $activeDurableProgress = (($progress | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $activeDurableRaw.raw_file = "segment-000001.bnraw"
    $activeDurableProgress.raw_file = "segment-000001.bnraw"
    $activeProgressBody = [ordered]@{
        schema = "RawDurabilityProgressV1"; record_index = [uint64]0; raw_path = "segment-000001.bnraw"
        ack = $activeDurableProgress.acknowledgements[0]; previous_record_sha256 = $script:FaultGateZeroDigest
    }
    $activeProgressDigest = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $activeProgressBody)
    $activeProgressEnvelope = [ordered]@{ body = $activeProgressBody; record_sha256 = $activeProgressDigest }
    [byte[]]$activeProgressLine = @(ConvertTo-FaultGateSerdeCompactJsonBytes -Value $activeProgressEnvelope)
    [byte[]]$activeProgressBytes = [byte[]]::new($activeProgressLine.Length + 1)
    [Array]::Copy($activeProgressLine, 0, $activeProgressBytes, 0, $activeProgressLine.Length); $activeProgressBytes[$activeProgressLine.Length] = 10
    $activeProgressPrefixSha256 = Get-FaultGateSha256Bytes -Bytes $activeProgressBytes
    $activeDurableProgress.terminal_record_sha256 = $activeProgressDigest
    $activeDurableProgress.file_bytes = [uint64]$activeProgressBytes.Length
    $activeDurableProgress.file_sha256 = $activeProgressPrefixSha256
    $activeDurableProgress.verified_through_offset = [uint64]$activeProgressBytes.Length
    $activeDurableProgress.verified_prefix_sha256 = $activeProgressPrefixSha256
    $activeDurableSegment = [pscustomobject][ordered]@{
        segment_index = [uint64]1; sealed = $false; durable_prefix = $true; raw = $activeDurableRaw; progress = $activeDurableProgress
    }
    $activeDurableSummary = Test-FaultGateEvidenceSegment -Segment $activeDurableSegment -Label "self-test active durable segment"
    Assert-SelfTest ((-not [bool]$activeDurableSummary.sealed) -and [bool]$activeDurableSummary.durable_prefix) "Active unsealed durable segment evidence was rejected."
    $activeDurableMissingPrefix = (($activeDurableSegment | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $activeDurableMissingPrefix.raw.PSObject.Properties.Remove("verified_prefix_sha256")
    Assert-SelfTestThrows { $null = Test-FaultGateEvidenceSegment -Segment $activeDurableMissingPrefix -Label "self-test active durable missing prefix" } "active durable BNRAW prefix witness omission"
    $activeDurableAckBoundary = (($activeDurableSegment | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $activeDurableAckBoundary.progress.partial_tail_bytes = [uint64]1
    Assert-SelfTestThrows { $null = Test-FaultGateEvidenceSegment -Segment $activeDurableAckBoundary -Label "self-test active durable ACK boundary" } "active durable BNACK partial-tail boundary"
    $progressMutant = Join-Path $tempRoot "progress-mutant.bnack"
    $progressEnvelope = ([Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($fixture.progress))).TrimEnd("`n") | ConvertFrom-Json
    $progressEnvelope.body.raw_path = "wrong.bnraw"
    $progressEnvelope.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $progressEnvelope.body)
    Write-SelfTestBytes -Path $progressMutant -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($progressEnvelope | ConvertTo-Json -Depth 100 -Compress) + "`n")))
    Assert-SelfTestThrows { $null = Read-FaultGateProgress -Path $progressMutant -ExpectedRawFile "segment-000000.bnraw" -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -FirstFrameIndex 0 } "BNACK raw identity"
    $progressWhitespacePath = Join-Path $tempRoot "progress-whitespace.bnack"
    $progressCanonicalText = ([Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($fixture.progress))).TrimEnd("`n")
    Write-SelfTestBytes -Path $progressWhitespacePath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(($progressCanonicalText.Insert(1, " ") + "`n")))
    Assert-SelfTestThrows { $null = Read-FaultGateProgress -Path $progressWhitespacePath -ExpectedRawFile "segment-000000.bnraw" -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -FirstFrameIndex 0 } "BNACK compact canonical whitespace"
    $progressDuplicatePath = Join-Path $tempRoot "progress-duplicate.bnack"
    Write-SelfTestBytes -Path $progressDuplicatePath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(($progressCanonicalText.Insert(1, '"body":null,') + "`n")))
    Assert-SelfTestThrows { $null = Read-FaultGateProgress -Path $progressDuplicatePath -ExpectedRawFile "segment-000000.bnraw" -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -FirstFrameIndex 0 } "BNACK duplicate key"
    $progressTypeMutant = Join-Path $tempRoot "progress-type-mutant.bnack"
    $progressTypeEnvelope = ([Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($fixture.progress))).TrimEnd("`n") | ConvertFrom-Json
    $progressTypeEnvelope.body.ack.durable_record_count = "1"
    $progressTypeEnvelope.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $progressTypeEnvelope.body)
    Write-SelfTestBytes -Path $progressTypeMutant -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($progressTypeEnvelope | ConvertTo-Json -Depth 100 -Compress) + "`n")))
    Assert-SelfTestThrows { $null = Read-FaultGateProgress -Path $progressTypeMutant -ExpectedRawFile "segment-000000.bnraw" -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -FirstFrameIndex 0 } "BNACK numeric string"
    $checkpointMutant = (($progress.latest_ack | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $checkpointMutant.durable_through_offset = [uint64]$checkpointMutant.durable_through_offset - 1
    Assert-SelfTestThrows { $null = Read-FaultGateRawPrefix -Path $fixture.raw -Limit $fixture.raw_bytes -ExpectedRecords 1 -FirstFrameIndex 0 -InitialPreviousSha256 $script:FaultGateZeroDigest -ExpectedEpoch $fixture.epoch -ExpectedStream $fixture.stream -ExpectedEndpoint "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms" -ExpectedSymbol "BTCUSDT" -ExpectedSpecRevision "976cc580553890e92031b77306147c0ed1de5a46" -Acknowledgements @($checkpointMutant) } "BNACK exact BNRAW checkpoint"

    $selfTestRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..")).TrimEnd('\')
    $evidenceSandboxRoot = Join-Path (Join-Path $selfTestRepositoryRoot "artifacts") ("raw-fault-gate-selftest-" + [Guid]::NewGuid().ToString("N"))
    $evidenceRoot = Join-Path $evidenceSandboxRoot "selftest"
    $treeRoot = Join-Path (Join-Path $evidenceRoot "qualification") "selftest-run"
    $null = New-Item -ItemType Directory -Path $treeRoot -Force -ErrorAction Stop
    Write-SelfTestBytes -Path (Join-Path $treeRoot "a.bin") -Bytes ([byte[]](1, 2, 3))
    $treeOne = Assert-FaultGateTreeStable -Root $treeRoot
    Write-SelfTestBytes -Path (Join-Path $treeRoot "a.bin") -Bytes ([byte[]](1, 2, 4))
    $treeTwo = Assert-FaultGateTreeStable -Root $treeRoot
    Assert-SelfTest ($treeOne.tree_sha256 -cne $treeTwo.tree_sha256) "Artifact tree digest ignored a byte mutation."

    $evidencePath = Join-Path $evidenceRoot "fault-evidence.json"
    $preFaultMaterial = @((New-SelfTestEvidenceGeneration -Symbol "BTCUSDT" -RunRoot $treeRoot), (New-SelfTestEvidenceGeneration -Symbol "ETHUSDT" -RunRoot $treeRoot))
    $finalRawMaterial = @((New-SelfTestEvidenceGeneration -Symbol "BTCUSDT" -RunRoot $treeRoot), (New-SelfTestEvidenceGeneration -Symbol "ETHUSDT" -RunRoot $treeRoot))
    $durableInventory = @()
    foreach ($generation in $preFaultMaterial) {
        foreach ($stream in @($generation.streams)) {
            $segment = @($stream.verified_segments)[0]
            $durableInventory += [ordered]@{
                symbol = $generation.symbol; stream = $stream.stream; segment_index = [uint64]$segment.segment_index
                sealed_at_observation = [bool]$segment.sealed
                raw_file = [string]$segment.raw.raw_file; raw_prefix_bytes = [uint64]$segment.raw.durable_through_offset
                raw_prefix_sha256 = [string]$segment.raw.verified_prefix_sha256; post_rescan_raw_prefix_sha256 = [string]$segment.raw.verified_prefix_sha256
                durable_records = [uint64]$segment.raw.durable_records
                terminal_record_sha256 = [string]$segment.raw.terminal_record_sha256
                progress_file = ("segment-{0:D6}.bnack" -f [uint64]$segment.segment_index)
                progress_prefix_bytes = [uint64]$segment.progress.verified_through_offset
                progress_prefix_sha256 = [string]$segment.progress.verified_prefix_sha256; post_rescan_progress_prefix_sha256 = [string]$segment.progress.verified_prefix_sha256
                progress_terminal_record_sha256 = [string]$segment.progress.terminal_record_sha256
            }
        }
    }
    $artifactNames = @("harness", "selftest", "helper", "launcher", "monitor", "telemetry_probe", "watchdog", "python_runtime_fingerprint", "powershell", "campaign", "capture", "verifier", "public_config", "source_lock", "python", "pyproject", "requirements", "pyvenv_config", "python_base_executable")
    $artifactFiles = @("run_raw_fault_gate.ps1", "_raw_fault_gate_selftest.ps1", "RawQualification.Windows.ps1", "run_24h_raw_qualification.ps1", "monitor_24h_raw_qualification.ps1", "RawQualification.TelemetryProbe.ps1", "RawQualification.Watchdog.ps1", "RawQualification.PythonRuntimeFingerprint.ps1", "powershell.exe", "raw_campaign.exe", "segmented_capture.exe", "campaign_verify.exe", "public.json", "BINANCE_SOURCE_LOCK.md", "python.exe", "pyproject.toml", "requirements.lock", "pyvenv.cfg", "python.exe")
    $selfTestPyvenvBinding = $null
    try {
        $selfTestPyvenvBinding = Open-FaultGateRetainedPathBinding -Path (Join-Path $selfTestRepositoryRoot ".venv\pyvenv.cfg") -Role "selftest_pyvenv_config"
        $selfTestPythonRuntimePaths = Get-FaultGatePythonRuntimePathsFromRetainedConfig -Binding $selfTestPyvenvBinding
    }
    finally { Close-FaultGateRetainedPathBinding -Binding $selfTestPyvenvBinding }
    $artifactExpectedPaths = Get-FaultGateNominalDirectArtifactPaths -RepositoryRoot $selfTestRepositoryRoot -PythonBaseExecutable ([string]$selfTestPythonRuntimePaths.base_executable)
    $bindingTrustBoundary = "Path-byte observation and retention do not assert absolute equivalence with bytes already interpreted or mapped by a runtime."
    $artifactHashMaterial = [ordered]@{}
    $artifactBindingList = [Collections.Generic.List[object]]::new()
    for ($artifactIndex = 0; $artifactIndex -lt $artifactNames.Count; $artifactIndex++) {
        $artifactDigest = (($artifactIndex + 1).ToString("x2")) * 32
        $artifactHashMaterial[$artifactNames[$artifactIndex]] = $artifactDigest
        $artifactBindingList.Add([ordered]@{ role = $artifactNames[$artifactIndex]; path = [string]$artifactExpectedPaths[$artifactNames[$artifactIndex]]; observation_scope = "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE"; trust_boundary = $bindingTrustBoundary; length = [uint64]1; sha256 = $artifactDigest })
    }
    $artifactBindingMaterial = @($artifactBindingList)
    $sourceBindingMaterial = @($artifactBindingMaterial[0], $artifactBindingMaterial[2])
    $absenceRoles = @("launcher", "BTCUSDT_coordinator", "BTCUSDT_generation_0", "ETHUSDT_coordinator", "ETHUSDT_generation_0", "watchdog")
    $absenceArtifactRoles = @("powershell", "campaign", "capture", "campaign", "capture", "powershell")
    $absenceMaterial = @()
    for ($absenceIndex = 0; $absenceIndex -lt $absenceRoles.Count; $absenceIndex++) {
        $artifactRole = $absenceArtifactRoles[$absenceIndex]
        $artifactBinding = @($artifactBindingMaterial | Where-Object { [string]$_.role -ceq $artifactRole })
        if ($artifactBinding.Count -ne 1) { throw "Self-test retained artifact role is absent or ambiguous: $artifactRole" }
        $executionPath = switch ($artifactRole) {
            "campaign" { Join-Path $treeRoot "sealed-runtime\bin\raw_campaign.exe" }
            "capture" { Join-Path $treeRoot "sealed-runtime\bin\segmented_capture.exe" }
            default { [string]$artifactBinding[0].path }
        }
        $absenceMaterial += [ordered]@{
            pid = [uint32](10 + $absenceIndex); role = $absenceRoles[$absenceIndex]; creation_filetime_utc = [int64](100 + $absenceIndex)
            executable_path = [IO.Path]::GetFullPath($executionPath); executable_sha256 = [string]$artifactBinding[0].sha256
            command_line_sha256 = (($absenceIndex + 20).ToString("x2")) * 32; absent = $true; pid_reused = $false
        }
    }
    $identityParentPids = @([uint32]4, [uint32]10, [uint32]11, [uint32]10, [uint32]13, [uint32]10)
    $retainedIdentityMaterial = @()
    for ($identityIndex = 0; $identityIndex -lt $absenceMaterial.Count; $identityIndex++) {
        $absenceRow = $absenceMaterial[$identityIndex]
        $retainedIdentityMaterial += [ordered]@{
            pid = $absenceRow.pid; role = $absenceRow.role; parent_pid = $identityParentPids[$identityIndex]
            creation_filetime_utc = $absenceRow.creation_filetime_utc; executable_path = $absenceRow.executable_path
            executable_sha256 = $absenceRow.executable_sha256; command_line_sha256 = $absenceRow.command_line_sha256
        }
    }
    $evidenceBtcHealthyEvents = @(
        (New-SelfTestHealthyHeartbeatEntry -SessionId "session-BTCUSDT" -TelemetryRecordIndex 0 -TelemetryMonoNs 50),
        (New-SelfTestHealthySegmentEntry -SessionId "session-BTCUSDT" -Symbol "BTCUSDT" -Stream depth),
        (New-SelfTestHealthySegmentEntry -SessionId "session-BTCUSDT" -Symbol "BTCUSDT" -Stream trade)
    )
    $evidenceEthHealthyEvents = @(
        (New-SelfTestHealthyHeartbeatEntry -SessionId "session-ETHUSDT" -TelemetryRecordIndex 0 -TelemetryMonoNs 50),
        (New-SelfTestHealthySegmentEntry -SessionId "session-ETHUSDT" -Symbol "ETHUSDT" -Stream depth),
        (New-SelfTestHealthySegmentEntry -SessionId "session-ETHUSDT" -Symbol "ETHUSDT" -Stream trade)
    )
    $evidenceBtcJournal = New-SelfTestFullHealthyCampaignJournal -Symbol "BTCUSDT" -FinalRawGeneration $finalRawMaterial[0] -CampaignStartupSha256 ("6" * 64) -RecurrentEvents $evidenceBtcHealthyEvents -DisconnectCount 1 -FailureCount 1
    $evidenceEthJournal = New-SelfTestFullHealthyCampaignJournal -Symbol "ETHUSDT" -FinalRawGeneration $finalRawMaterial[1] -CampaignStartupSha256 ("7" * 64) -RecurrentEvents $evidenceEthHealthyEvents
    $preFaultMaterial = @(
        (($finalRawMaterial[0] | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json),
        (($finalRawMaterial[1] | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    )
    $campaignPrefixMaterial = @(
        (New-SelfTestCampaignPrefixFromJournal -Journal $evidenceBtcJournal -Symbol "BTCUSDT" -Records 10),
        (New-SelfTestCampaignPrefixFromJournal -Journal $evidenceEthJournal -Symbol "ETHUSDT" -Records 10)
    )
    $evidenceBtcCausality = Test-FaultGateInjectedCampaignCausality -Journal $evidenceBtcJournal -Symbol "BTCUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $campaignPrefixMaterial[0] -InjectionRequestedWallNs 10 -ExpectedDepthEpoch "epoch-BTCUSDT-depth" -ExpectedCampaignStartupSha256 ("6" * 64) -FinalRawGeneration $finalRawMaterial[0]
    $evidenceEthCausality = Test-FaultGateInjectedCampaignCausality -Journal $evidenceEthJournal -Symbol "ETHUSDT" -LauncherFailure $reportedFailure -PreFaultPrefix $campaignPrefixMaterial[1] -InjectionRequestedWallNs 10 -ExpectedDepthEpoch "epoch-ETHUSDT-depth" -ExpectedCampaignStartupSha256 ("7" * 64) -FinalRawGeneration $finalRawMaterial[1]
    $campaignJournalMaterial = @(
        [ordered]@{ symbol = "BTCUSDT"; campaign_id = "1-BTCUSDT-raw-111111111111"; campaign_directory = Join-Path $treeRoot "1-BTCUSDT-raw-111111111111"; campaign_startup_bytes = [uint64]100; campaign_startup_sha256 = "6" * 64; campaign_started_event = $evidenceBtcJournal.entries[0]; journal_bytes_base64 = [Convert]::ToBase64String([byte[]]$evidenceBtcJournal.raw_bytes); records = [uint64]$evidenceBtcJournal.records; clean_tail = $true; terminal_record_sha256 = [string]$evidenceBtcJournal.terminal_record_sha256; file_bytes = [uint64]$evidenceBtcJournal.file_bytes; file_sha256 = [string]$evidenceBtcJournal.file_sha256; causality = $evidenceBtcCausality },
        [ordered]@{ symbol = "ETHUSDT"; campaign_id = "1-ETHUSDT-raw-222222222222"; campaign_directory = Join-Path $treeRoot "1-ETHUSDT-raw-222222222222"; campaign_startup_bytes = [uint64]100; campaign_startup_sha256 = "7" * 64; campaign_started_event = $evidenceEthJournal.entries[0]; journal_bytes_base64 = [Convert]::ToBase64String([byte[]]$evidenceEthJournal.raw_bytes); records = [uint64]$evidenceEthJournal.records; clean_tail = $true; terminal_record_sha256 = [string]$evidenceEthJournal.terminal_record_sha256; file_bytes = [uint64]$evidenceEthJournal.file_bytes; file_sha256 = [string]$evidenceEthJournal.file_sha256; causality = $evidenceEthCausality }
    )
    $evidenceBtcFailureEvents = @(Get-FaultGateJournalEvents -Journal $evidenceBtcJournal -Event "CAMPAIGN_FAILED")
    if ($evidenceBtcFailureEvents.Count -ne 1) { throw "Self-test BTC journal lacks one exact CAMPAIGN_FAILED receipt source." }
    $coordinatorStderrMaterial = [ordered]@{
        schema = "RawQualificationCoordinatorStderrEvidenceV1"; classification = "EMPTY"; symbol = "BTCUSDT"; generation_index = [uint64]0
        coordinator_pid = [uint32]$retainedIdentityMaterial[1].pid; coordinator_exit_code = [uint32]0xEE02
        campaign_id = [string]$campaignJournalMaterial[0].campaign_id; campaign_directory = [string]$campaignJournalMaterial[0].campaign_directory
        campaign_failure_record_sha256 = [string]$evidenceBtcFailureEvents[0].record_sha256
        file = "btcusdt.stderr.log"; bytes = [uint64]0; sha256 = $script:FaultGateEmptySha256
        peer_symbol = "ETHUSDT"; peer_coordinator_pid = [uint32]$retainedIdentityMaterial[3].pid
        peer_file = "ethusdt.stderr.log"; peer_bytes = [uint64]0; peer_sha256 = $script:FaultGateEmptySha256
    }
    $treeDigestMap = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $treeByteMap = [Collections.Generic.Dictionary[string,uint64]]::new([StringComparer]::Ordinal)
    $treeDigestMap.Add("launcher-terminal.json", "4" * 64)
    $treeByteMap.Add("launcher-terminal.json", [uint64]100)
    $treeDigestMap.Add("launcher-startup.json", "a" * 64)
    $treeByteMap.Add("launcher-startup.json", [uint64]100)
    $treeDigestMap.Add("processes.json", "b" * 64)
    $treeByteMap.Add("processes.json", [uint64]100)
    $treeDigestMap.Add("campaign-bindings.json", "c" * 64)
    $treeByteMap.Add("campaign-bindings.json", [uint64]100)
    $treeDigestMap.Add("launcher-events.jsonl", "7" * 64)
    $treeByteMap.Add("launcher-events.jsonl", [uint64]300)
    $treeDigestMap.Add("guardian-pulse.jsonl", "9" * 64)
    $treeByteMap.Add("guardian-pulse.jsonl", [uint64]200)
    $treeDigestMap.Add("host-telemetry.jsonl", "b" * 64)
    $treeByteMap.Add("host-telemetry.jsonl", [uint64]200)
    $treeDigestMap.Add("watchdog-ready.json", "e" * 64)
    $treeByteMap.Add("watchdog-ready.json", [uint64]100)
    $treeDigestMap.Add("btcusdt.stderr.log", $script:FaultGateEmptySha256)
    $treeByteMap.Add("btcusdt.stderr.log", [uint64]0)
    $treeDigestMap.Add("ethusdt.stderr.log", $script:FaultGateEmptySha256)
    $treeByteMap.Add("ethusdt.stderr.log", [uint64]0)
    for ($generationIndex = 0; $generationIndex -lt $finalRawMaterial.Count; $generationIndex++) {
        $generation = $finalRawMaterial[$generationIndex]
        $campaignRelative = [string]$campaignJournalMaterial[$generationIndex].campaign_id
        $sessionRelative = $campaignRelative + "/generations/" + [string]$generation.session_id
        $treeDigestMap.Add($campaignRelative + "/campaign-startup.json", [string]$campaignJournalMaterial[$generationIndex].campaign_startup_sha256)
        $treeByteMap.Add($campaignRelative + "/campaign-startup.json", [uint64]$campaignJournalMaterial[$generationIndex].campaign_startup_bytes)
        $treeDigestMap.Add($campaignRelative + "/campaign-events.jsonl", [string]$campaignJournalMaterial[$generationIndex].file_sha256)
        $treeByteMap.Add($campaignRelative + "/campaign-events.jsonl", [uint64]$campaignJournalMaterial[$generationIndex].file_bytes)
        $treeDigestMap.Add($sessionRelative + "/startup.json", [string]$generation.startup_sha256)
        $treeByteMap.Add($sessionRelative + "/startup.json", [uint64]$generation.startup_bytes)
        $treeDigestMap.Add($sessionRelative + "/snapshot.bnraw", [string]$generation.snapshot.file_sha256)
        $treeByteMap.Add($sessionRelative + "/snapshot.bnraw", [uint64]$generation.snapshot.bytes)
        $treeDigestMap.Add($sessionRelative + "/snapshot-http.json", [string]$generation.snapshot.http_metadata_sha256)
        $treeByteMap.Add($sessionRelative + "/snapshot-http.json", [uint64]$generation.snapshot.http_metadata_bytes)
        foreach ($transport in @($generation.transports)) {
            $treeDigestMap.Add($sessionRelative + "/" + [string]$transport.metadata_file, [string]$transport.metadata_sha256)
            $treeByteMap.Add($sessionRelative + "/" + [string]$transport.metadata_file, [uint64]$transport.metadata_bytes)
        }
        $treeDigestMap.Add($sessionRelative + "/telemetry.jsonl", [string]$generation.telemetry.full_file_sha256)
        $treeByteMap.Add($sessionRelative + "/telemetry.jsonl", [uint64]$generation.telemetry.observed_file_bytes)
        foreach ($stream in @($generation.streams)) {
            $streamRelative = $sessionRelative + "/" + [string]$stream.stream
            $treeDigestMap.Add($streamRelative + "/segments.bnseg", [string]$stream.manifest_file_sha256)
            $treeByteMap.Add($streamRelative + "/segments.bnseg", [uint64]$stream.manifest_file_bytes)
            foreach ($segment in @($stream.verified_segments)) {
                $treeDigestMap.Add($streamRelative + ("/segment-{0:D6}.bnraw" -f [uint64]$segment.segment_index), [string]$segment.raw.full_file_sha256)
                $treeByteMap.Add($streamRelative + ("/segment-{0:D6}.bnraw" -f [uint64]$segment.segment_index), [uint64]$segment.raw.observed_file_bytes)
                $treeDigestMap.Add($streamRelative + ("/segment-{0:D6}.bnack" -f [uint64]$segment.segment_index), [string]$segment.progress.file_sha256)
                $treeByteMap.Add($streamRelative + ("/segment-{0:D6}.bnack" -f [uint64]$segment.segment_index), [uint64]$segment.progress.file_bytes)
            }
        }
    }
    [string[]]$treeDigestPaths = @($treeDigestMap.Keys)
    [Array]::Sort($treeDigestPaths, [StringComparer]::Ordinal)
    $evidenceTreeInventory = [Collections.Generic.List[object]]::new()
    $evidenceTreeBuilder = [Text.StringBuilder]::new()
    [uint64]$evidenceTreeTotalBytes = 0
    foreach ($treeDigestPath in $treeDigestPaths) {
        $treeDigest = [string]$treeDigestMap[$treeDigestPath]
        $treeBytes = [uint64]$treeByteMap[$treeDigestPath]
        $evidenceTreeTotalBytes += $treeBytes
        $evidenceTreeInventory.Add([ordered]@{ relative_path = $treeDigestPath; bytes = $treeBytes; sha256 = $treeDigest })
        $null = $evidenceTreeBuilder.Append($treeDigestPath).Append([char]0).Append($treeBytes.ToString([Globalization.CultureInfo]::InvariantCulture)).Append([char]0).Append($treeDigest).Append([char]10)
    }
    $evidenceTree = [ordered]@{
        root = $treeRoot; files = [uint64]$evidenceTreeInventory.Count; total_bytes = $evidenceTreeTotalBytes
        tree_sha256 = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($evidenceTreeBuilder.ToString()))
        inventory = @($evidenceTreeInventory)
    }
    $containmentEvidenceBody = [ordered]@{
        schema = "RawQualificationFailureContainmentV2"
        job_name = "Local\BinanceRawQualificationJob-selftest-run"
        job_kill_on_close = $true
        detected_wall_ns = [uint64]1
        detected_monotonic_tick = [uint64]1100
        requested_exit_code = [uint32]0xEE02
        initial_query_succeeded = $true
        initial_active_processes = [uint32]5
        initial_query_error = $null
        terminate_attempted = $true
        terminate_succeeded = $true
        terminate_error = $null
        termination_monotonic_tick = [uint64]1200
        monotonic_frequency = [uint64][Diagnostics.Stopwatch]::Frequency
        drain_deadline_s = [uint64]30
        drain_elapsed_qpc_ticks = [uint64]1
        final_query_succeeded = $true
        final_active_processes = [uint32]0
        final_query_error = $null
        result = "DRAINED_BY_ATTEMPT"
    }
    $containmentEvidence = [ordered]@{}
    foreach ($containmentProperty in $containmentEvidenceBody.Keys) { $containmentEvidence[$containmentProperty] = $containmentEvidenceBody[$containmentProperty] }
    $containmentEvidence.sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $containmentEvidenceBody)
    $selfTestPowerShellPath = [string](@($artifactBindingMaterial | Where-Object { [string]$_.role -ceq "powershell" })[0].path)
    $selfTestMonitorPath = [string](@($artifactBindingMaterial | Where-Object { [string]$_.role -ceq "monitor" })[0].path)
    $selfTestMonitorCommand = [RawQualificationNative]::BuildExactCommandLine(
        $selfTestPowerShellPath,
        [string[]]@("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $selfTestMonitorPath, "-RunRoot", $treeRoot)
    )
    $faultJournalContext = [ordered]@{
        gate_id = "selftest"; repository_root = $selfTestRepositoryRoot; qualification_base = Join-Path $evidenceRoot "qualification"
        source_bindings = $sourceBindingMaterial; artifact_path_bindings = $artifactBindingMaterial; launch_artifact_hashes = $artifactHashMaterial
        run_id = "selftest-run"; run_root = $treeRoot; launcher_pid = [uint32]$absenceMaterial[0].pid
        launcher_creation_filetime_utc = [int64]$absenceMaterial[0].creation_filetime_utc; launcher_command_line_sha256 = [string]$absenceMaterial[0].command_line_sha256
        startup_sha256 = "a" * 64; processes_sha256 = "b" * 64; bindings_sha256 = "c" * 64
        target_creation_filetime_utc = [int64]$absenceMaterial[2].creation_filetime_utc; target_parent_pid = [uint32]11
        target_executable_sha256 = [string]$absenceMaterial[2].executable_sha256; target_command_line_sha256 = [string]$absenceMaterial[2].command_line_sha256
        pre_fault_raw_prefixes_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $preFaultMaterial)
        pre_fault_campaign_prefixes_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $campaignPrefixMaterial)
        pre_fault_campaign_prefixes = $campaignPrefixMaterial; terminal_sha256 = "4" * 64
        containment_sha256 = [string]$containmentEvidence.sha256; launcher_journal_terminal_sha256 = "6" * 64
    }
    $faultJournalEvidence = New-SelfTestFaultJournalEvidence -TargetPid ([uint32]$absenceMaterial[2].pid) -Context $faultJournalContext -RequestWallNs 10 -RequestMonotonicTick 1000
    $supportInventory = @(
        [ordered]@{ relative_path = "fault-events.jsonl"; bytes = [uint64]$faultJournalEvidence.file_bytes; sha256 = [string]$faultJournalEvidence.file_sha256 },
        [ordered]@{ relative_path = "launcher.stderr.log"; bytes = [uint64]0; sha256 = "d" * 64 },
        [ordered]@{ relative_path = "launcher.stdout.log"; bytes = [uint64]10; sha256 = "c" * 64 },
        [ordered]@{ relative_path = "monitor-001.stderr.log"; bytes = [uint64]0; sha256 = "0" * 64 },
        [ordered]@{ relative_path = "monitor-001.stdout.json"; bytes = [uint64]100; sha256 = "f" * 64 }
    )
    $supportBuilder = [Text.StringBuilder]::new()
    [uint64]$supportBytes = 0
    foreach ($supportRow in $supportInventory) {
        $supportBytes += [uint64]$supportRow.bytes
        $null = $supportBuilder.Append([string]$supportRow.relative_path).Append([char]0).Append(([uint64]$supportRow.bytes).ToString([Globalization.CultureInfo]::InvariantCulture)).Append([char]0).Append([string]$supportRow.sha256).Append([char]10)
    }
    $supportTree = [ordered]@{
        root = $evidenceRoot; files = [uint64]$supportInventory.Count; total_bytes = $supportBytes
        tree_sha256 = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($supportBuilder.ToString()))
        inventory = $supportInventory
    }
    $body = [ordered]@{
        schema = "RawQualificationFaultEvidenceV3"; status = "PASS"; gate_id = "selftest"; run_id = "selftest-run"
        run_root = $treeRoot; evidence_root = $evidenceRoot; repository_root = $selfTestRepositoryRoot
        fault = [ordered]@{
            method = "TerminateProcess_RETAINED_HANDLE"; symbol = "BTCUSDT"; generation_index = [uint64]0
            target = [ordered]@{ pid = $absenceMaterial[2].pid; creation_filetime_utc = $absenceMaterial[2].creation_filetime_utc; parent_pid = [uint32]11; executable_sha256 = $absenceMaterial[2].executable_sha256; command_line_sha256 = $absenceMaterial[2].command_line_sha256 }
            requested_exit_code = [uint32]0xEE31; observed_exit_code = [uint32]0xEE31
            proposed_record_sha256 = [string]$faultJournalEvidence.proposed_record_sha256; injection_requested_record_sha256 = [string]$faultJournalEvidence.injection_requested_record_sha256; injected_record_sha256 = [string]$faultJournalEvidence.injected_record_sha256
            injection_requested_wall_ns = [uint64]10
            failure_deadline_seconds = [uint64]30; injection_requested_qpc_timestamp = [uint64]1000; containment_observed_monotonic_tick = [uint64]1300
        }
        launcher = [ordered]@{
            identity = [ordered]@{ pid = $absenceMaterial[0].pid; creation_filetime_utc = $absenceMaterial[0].creation_filetime_utc; executable_sha256 = $absenceMaterial[0].executable_sha256; command_line_sha256 = $absenceMaterial[0].command_line_sha256 }
            monotonic_origin_qpc_timestamp = [uint64]100
            exit_code = [uint32]1; terminal_file = "launcher-terminal.json"; terminal_bytes = [uint64]100; terminal_sha256 = "4" * 64
            terminal_status = "FAILED"; terminal_failure = "BTCUSDT campaign heartbeat reported failure."
            containment = $containmentEvidence
            startup_file = "launcher-startup.json"; startup_bytes = [uint64]100; startup_sha256 = "a" * 64
            process_control_file = "processes.json"; process_control_bytes = [uint64]100; process_control_sha256 = "b" * 64
            campaign_bindings_file = "campaign-bindings.json"; campaign_bindings_bytes = [uint64]100; campaign_bindings_sha256 = "c" * 64
            watchdog_ready_sha256 = "e" * 64
            launcher_journal = [ordered]@{ records = [uint64]3; terminal_record_sha256 = "6" * 64; file_bytes = [uint64]300; file_sha256 = "7" * 64 }
            guardian_journal = [ordered]@{ records = [uint64]2; terminal_record_sha256 = "8" * 64; file_bytes = [uint64]200; file_sha256 = "9" * 64 }
            telemetry_journal = [ordered]@{ records = [uint64]2; terminal_record_sha256 = "a" * 64; file_bytes = [uint64]200; file_sha256 = "b" * 64 }
            stdout_file = "launcher.stdout.log"; stdout_bytes = [uint64]10; stdout_sha256 = "c" * 64
            stderr_file = "launcher.stderr.log"; stderr_bytes = [uint64]0; stderr_sha256 = "d" * 64
        }
        live_gate = [ordered]@{
            watchdog_ready = [ordered]@{ schema = "RawQualificationWatchdogReadyV1"; pid = [uint32]15; job_name = "Local\BinanceRawQualificationJob-selftest-run"; observed_qpc_timestamp = [uint64]1; file_bytes = [uint64]100; file_sha256 = "e" * 64 }
            monitor = [ordered]@{
                attempt = [uint64]1; pid = [uint32]16; exact_command_line = $selfTestMonitorCommand
                command_line_sha256 = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($selfTestMonitorCommand))
                creation_filetime_utc = [int64]200
                executable_path = [string](@($artifactBindingMaterial | Where-Object { [string]$_.role -ceq "powershell" })[0].path)
                executable_sha256 = [string](@($artifactBindingMaterial | Where-Object { [string]$_.role -ceq "powershell" })[0].sha256)
                exit_code = [uint32]0
                stdout_file = "monitor-001.stdout.json"; stdout_bytes = [uint64]100; stdout_sha256 = "f" * 64
                stderr_file = "monitor-001.stderr.log"; stderr_bytes = [uint64]0; stderr_sha256 = "0" * 64
                report_sha256 = "f" * 64; report_schema = "RawQualificationReadOnlyMonitorV1"; report_status = "HEALTHY_RUNNING"
                report_stage = "CAPTURING"; report_run_root = $treeRoot; report_host_telemetry_records = [uint64]1
            }
        }
        retained_process_identities = $retainedIdentityMaterial
        containment = [ordered]@{
            inner_job_name = "Local\BinanceRawQualificationJob-selftest-run"; inner_job_exists = $false; inner_job_open_error = [int]2
            workload_job_name = "Local\BinanceRawQualificationWorkloadJob-selftest-run"; workload_job_exists = $false; workload_job_open_error = [int]2
            outer_job_name = "Local\BinanceRawFaultGateOuter-selftest"; outer_job_kill_on_close = $true; outer_active_processes = [uint32]0
            btc_coordinator_exit_code = [uint32]0xEE02; eth_capture_exit_code = [uint32]0xEE02; eth_coordinator_exit_code = [uint32]0xEE02; watchdog_exit_code = [uint32]0xEE02
            retained_identity_absence = $absenceMaterial; global_engine_processes = [uint64]0; run_bound_processes = [uint64]0; verifier_processes = [uint64]0
        }
        promotion = [ordered]@{ launcher_complete = $false; campaign_or_generation_manifest_count = [uint64]0; independent_verification = $false }
        campaign_journals = $campaignJournalMaterial
        campaign_prefixes = [ordered]@{
            pre_fault_campaign_prefixes_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $campaignPrefixMaterial)
            pre_fault_campaign_prefixes = $campaignPrefixMaterial
        }
        coordinator_stderr = $coordinatorStderrMaterial
        raw_durable_prefixes = $finalRawMaterial
        raw_preservation = [ordered]@{
            observation_scope = "MANIFEST_SNAPSHOT_BOUNDED_SEALED_SEGMENTS_AND_DURABLE_PREFIXES_OBSERVED_AFTER_FROZEN_PRE_FAULT_CAMPAIGN_PREFIX"
            completeness_claim = "NO_ATOMIC_COMPLETE_STATE_CLAIM_AT_TERMINATEPROCESS_INSTANT_WITHOUT_A_COLLECTOR_BARRIER"
            pre_fault_raw_prefixes_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $preFaultMaterial)
            pre_fault_raw_prefixes = $preFaultMaterial
            durable_prefixes = [ordered]@{
                durable_segments = [uint64]$durableInventory.Count
                inventory_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $durableInventory)
                inventory = $durableInventory
            }
        }
        fault_journal = [ordered]@{
            journal_bytes_base64 = [Convert]::ToBase64String([byte[]]$faultJournalEvidence.raw_bytes)
            records = [uint64]$faultJournalEvidence.records; terminal_record_sha256 = [string]$faultJournalEvidence.terminal_record_sha256; file_bytes = [uint64]$faultJournalEvidence.file_bytes; file_sha256 = [string]$faultJournalEvidence.file_sha256
            proposed_record_sha256 = [string]$faultJournalEvidence.proposed_record_sha256; injection_requested_record_sha256 = [string]$faultJournalEvidence.injection_requested_record_sha256; injected_record_sha256 = [string]$faultJournalEvidence.injected_record_sha256
        }
        artifact_tree = $evidenceTree
        support_artifact_tree = $supportTree
        harness = [ordered]@{
            script_file = "run_raw_fault_gate.ps1"
            process_identity = [ordered]@{ pid = [uint32]4; creation_filetime_utc = [int64]1 }
            source_binding_scope = "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE"
            source_binding_trust_boundary = $bindingTrustBoundary
            source_bindings_at_start = $sourceBindingMaterial
            source_bindings_at_terminal = $sourceBindingMaterial
            direct_artifacts_retained_and_rehashed = [ordered]@{
                scope = "DIRECT_ARTIFACTS_RETAINED_AND_REHASHED"
                observation_scope = "PATH_BYTES_OBSERVED_AND_RETAINED_DURING_GATE"
                trust_boundary = $bindingTrustBoundary
                unchanged = $true
                hashes_at_start = $artifactHashMaterial
                hashes_at_terminal = $artifactHashMaterial
                bindings_at_start = $artifactBindingMaterial
                bindings_at_terminal = $artifactBindingMaterial
            }
            observed_digest_or_external_trust_boundary = [ordered]@{
                scope = "OBSERVED_DIGEST_OR_EXTERNAL_TRUST_BOUNDARY"
                retained_path_handles = $false
                absolute_executed_byte_attestation = $false
                observed_digests = @(
                    [ordered]@{ name = "python_verifier_source_tree"; retained_path_handles = $false; executed_byte_attestation = $false; preflight_sha256 = "e" * 64; launcher_terminal_preflight_sha256 = "e" * 64; terminal_observation = "OBSERVED_AND_UNCHANGED"; launcher_terminal_final_sha256 = "e" * 64 },
                    [ordered]@{ name = "python_runtime_tree"; retained_path_handles = $false; executed_byte_attestation = $false; preflight_sha256 = "f" * 64; launcher_terminal_preflight_sha256 = "f" * 64; terminal_observation = "TERMINAL_NOT_OBSERVED_ON_FAILED_PATH"; launcher_terminal_final_sha256 = $null }
                )
                external_dependencies = @(
                    "WINDOWS_KERNEL_PROCESS_JOB_OBJECT_AND_FILESYSTEM_SEMANTICS",
                    "WINDOWS_W32TIME_POWERCFG_CIM_AND_PERFORMANCE_PROVIDERS",
                    "OS_LOADER_TLS_CERTIFICATE_STORE_NETWORK_STACK_AND_DEVICE_DRIVERS",
                    "BINANCE_PUBLIC_MARKET_DATA_REST_AND_WEBSOCKET_SERVICES"
                )
            }
        }
    }
    $invalidPublicationBody = (($body | ConvertTo-Json -Depth 100 -Compress) | ConvertFrom-Json)
    $invalidPublicationBody.status = "INVALID_PASS_STATUS"
    $invalidPublicationObserved = $false
    Assert-SelfTestThrows {
        $null = Publish-FaultGateValidatedPassEvidence `
            -Path $evidencePath -Body $invalidPublicationBody `
            -PublicationObserved ([ref]$invalidPublicationObserved)
    } "write-then-validate PASS publication mutant"
    Assert-SelfTest (-not $invalidPublicationObserved -and
        -not (Test-Path -LiteralPath $evidencePath) -and
        @(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($evidencePath)) `
            -Filter ".fault-evidence-*.pending" -File -Force).Count -eq 0) `
        "Rejected staged PASS evidence leaked a canonical or pending publication."
    $validPublicationObserved = $false
    $validPublication = Publish-FaultGateValidatedPassEvidence `
        -Path $evidencePath -Body $body `
        -PublicationObserved ([ref]$validPublicationObserved)
    Assert-SelfTest ($validPublicationObserved -and
        [string]$validPublication.path -ceq [IO.Path]::GetFullPath($evidencePath) -and
        (Test-FaultGateDigest $validPublication.record_sha256)) `
        "Validated PASS evidence did not cross its same-directory atomic publication boundary."
    $null = Test-SelfTestEvidenceEnvelope -Path $evidencePath
    $script:FaultSelfTestPassed++

    [byte[]]$baseEvidenceBytes = [IO.File]::ReadAllBytes($evidencePath)
    $stderrEvidencePath = $evidencePath
    $stderrEvidenceEnvelope = Read-FaultGateJson -Path $evidencePath
    $expectedCoordinatorStderr = Get-FaultGateExpectedInjectedCoordinatorStderr -CampaignDirectory ([string]$stderrEvidenceEnvelope.body.campaign_journals[0].campaign_directory)
    $stderrEvidenceEnvelope.body.launcher.terminal_failure = [string]$expectedCoordinatorStderr.terminal_failure
    $stderrEvidenceEnvelope.body.containment.btc_coordinator_exit_code = [uint32]2
    $stderrEvidenceEnvelope.body.coordinator_stderr.classification = [string]$expectedCoordinatorStderr.classification
    $stderrEvidenceEnvelope.body.coordinator_stderr.coordinator_exit_code = [uint32]2
    $stderrEvidenceEnvelope.body.coordinator_stderr.bytes = [uint64]$expectedCoordinatorStderr.bytes
    $stderrEvidenceEnvelope.body.coordinator_stderr.sha256 = [string]$expectedCoordinatorStderr.sha256
    $stderrTreeRow = @($stderrEvidenceEnvelope.body.artifact_tree.inventory | Where-Object { [string]$_.relative_path -ceq "btcusdt.stderr.log" })
    if ($stderrTreeRow.Count -ne 1) { throw "Self-test evidence tree lacks its unique BTC stderr row." }
    $stderrTreeRow[0].bytes = [uint64]$expectedCoordinatorStderr.bytes
    $stderrTreeRow[0].sha256 = [string]$expectedCoordinatorStderr.sha256
    Update-SelfTestEvidenceTreeEnvelope -Envelope $stderrEvidenceEnvelope
    Update-SelfTestEmbeddedFaultJournal -Envelope $stderrEvidenceEnvelope -Mutation {
        param($entries)
        $entries[6].body.payload.btc_coordinator_exit_code = [uint32]2
    }
    $stderrEvidenceEnvelope.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $stderrEvidenceEnvelope.body)
    Write-SelfTestBytes -Path $stderrEvidencePath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($stderrEvidenceEnvelope | ConvertTo-Json -Depth 100) + "`n")))
    $null = Test-SelfTestEvidenceEnvelope -Path $stderrEvidencePath
    $script:FaultSelfTestPassed++

    Assert-SelfTestEvidenceMutantRejected -SourcePath $stderrEvidencePath -Name "coordinator stderr terminal byte count plus one" -Mutation {
        param($mutant)
        $mutant.body.launcher.terminal_failure = "BTCUSDT coordinator wrote unexpected stderr (" +
            (([uint64]$mutant.body.coordinator_stderr.bytes + 1).ToString([Globalization.CultureInfo]::InvariantCulture)) + " bytes)."
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $stderrEvidencePath -Name "coordinator stderr terminal leading-zero byte count" -Mutation {
        param($mutant)
        $mutant.body.launcher.terminal_failure = "BTCUSDT coordinator wrote unexpected stderr (0" +
            ([uint64]$mutant.body.coordinator_stderr.bytes).ToString([Globalization.CultureInfo]::InvariantCulture) + " bytes)."
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $stderrEvidencePath -Name "coordinator stderr byte mutation with coordinated tree digest" -Mutation {
        param($mutant)
        [byte[]]$mutatedBytes = [byte[]]$expectedCoordinatorStderr.canonical_bytes.Clone()
        $mutatedBytes[0] = $mutatedBytes[0] -bxor 1
        $mutatedSha = Get-FaultGateSha256Bytes -Bytes $mutatedBytes
        $mutant.body.coordinator_stderr.sha256 = $mutatedSha
        $row = @($mutant.body.artifact_tree.inventory | Where-Object { [string]$_.relative_path -ceq "btcusdt.stderr.log" })[0]
        $row.sha256 = $mutatedSha
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $stderrEvidencePath -Name "coordinator stderr CRLF with coordinated length digest and tree" -Mutation {
        param($mutant)
        [byte[]]$canonical = [byte[]]$expectedCoordinatorStderr.canonical_bytes
        [byte[]]$crlf = [byte[]]::new($canonical.Length + 1)
        [Array]::Copy($canonical, 0, $crlf, 0, $canonical.Length - 1)
        $crlf[$canonical.Length - 1] = 13; $crlf[$canonical.Length] = 10
        $crlfSha = Get-FaultGateSha256Bytes -Bytes $crlf
        $mutant.body.coordinator_stderr.bytes = [uint64]$crlf.Length
        $mutant.body.coordinator_stderr.sha256 = $crlfSha
        $mutant.body.launcher.terminal_failure = "BTCUSDT coordinator wrote unexpected stderr (" +
            ([uint64]$crlf.Length).ToString([Globalization.CultureInfo]::InvariantCulture) + " bytes)."
        $row = @($mutant.body.artifact_tree.inventory | Where-Object { [string]$_.relative_path -ceq "btcusdt.stderr.log" })[0]
        $row.bytes = [uint64]$crlf.Length; $row.sha256 = $crlfSha
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $stderrEvidencePath -Name "coordinator stderr receipt campaign directory relabel" -Mutation {
        param($mutant)
        $mutant.body.coordinator_stderr.campaign_directory = [string]$mutant.body.campaign_journals[1].campaign_directory
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $stderrEvidencePath -Name "coordinator stderr receipt exit three coordinated with containment journal" -Mutation {
        param($mutant)
        $mutant.body.coordinator_stderr.coordinator_exit_code = [uint32]3
        $mutant.body.containment.btc_coordinator_exit_code = [uint32]3
        Update-SelfTestEmbeddedFaultJournal -Envelope $mutant -Mutation {
            param($entries)
            $entries[6].body.payload.btc_coordinator_exit_code = [uint32]3
        }
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $stderrEvidencePath -Name "coordinator stderr required tree row omitted" -Mutation {
        param($mutant)
        $mutant.body.artifact_tree.inventory = @($mutant.body.artifact_tree.inventory | Where-Object { [string]$_.relative_path -cne "btcusdt.stderr.log" })
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $stderrEvidencePath -Name "peer coordinator stderr non-empty with coordinated tree" -Mutation {
        param($mutant)
        $mutant.body.coordinator_stderr.peer_bytes = [uint64]1
        $mutant.body.coordinator_stderr.peer_sha256 = Get-FaultGateSha256Bytes -Bytes ([byte[]](1))
        $row = @($mutant.body.artifact_tree.inventory | Where-Object { [string]$_.relative_path -ceq "ethusdt.stderr.log" })[0]
        $row.bytes = [uint64]1; $row.sha256 = [string]$mutant.body.coordinator_stderr.peer_sha256
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $stderrEvidencePath -Name "coordinator stderr receipt omitted" -Mutation {
        param($mutant)
        $mutant.body.PSObject.Properties.Remove("coordinator_stderr")
    }
    Write-SelfTestBytes -Path $evidencePath -Bytes $baseEvidenceBytes
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "empty coordinator stderr with coordinated exit two" -Mutation {
        param($mutant)
        $mutant.body.coordinator_stderr.coordinator_exit_code = [uint32]2
        $mutant.body.containment.btc_coordinator_exit_code = [uint32]2
        Update-SelfTestEmbeddedFaultJournal -Envelope $mutant -Mutation {
            param($entries)
            $entries[6].body.payload.btc_coordinator_exit_code = [uint32]2
        }
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "empty coordinator stderr with coordinated exit three" -Mutation {
        param($mutant)
        $mutant.body.coordinator_stderr.coordinator_exit_code = [uint32]3
        $mutant.body.containment.btc_coordinator_exit_code = [uint32]3
        Update-SelfTestEmbeddedFaultJournal -Envelope $mutant -Mutation {
            param($entries)
            $entries[6].body.payload.btc_coordinator_exit_code = [uint32]3
        }
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "exact stderr terminal class with empty receipt" -Mutation {
        param($mutant)
        $expected = Get-FaultGateExpectedInjectedCoordinatorStderr -CampaignDirectory ([string]$mutant.body.campaign_journals[0].campaign_directory)
        $mutant.body.launcher.terminal_failure = [string]$expected.terminal_failure
    }
    $caseExpectedCoordinatorStderr = Get-FaultGateExpectedInjectedCoordinatorStderr -CampaignDirectory ([string]$body.campaign_journals[0].campaign_directory)
    $caseMutatedCoordinatorStderrFailure = ([string]$caseExpectedCoordinatorStderr.terminal_failure) -replace '^BTCUSDT', 'btcusdt'
    foreach ($caseMutatedFailure in @(
        "btcusdt campaign heartbeat reported failure.",
        "btcusdt campaign heartbeat regressed or has no active generation.",
        "btcusdt raw_campaign exited with code 2.",
        $caseMutatedCoordinatorStderrFailure
    )) {
        Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name ("case-mutated terminal failure: " + $caseMutatedFailure) -Mutation {
            param($mutant)
            $mutant.body.launcher.terminal_failure = $caseMutatedFailure
        }
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "same-basename direct artifact path drift" -Mutation {
        param($mutant)
        $driftPath = Join-Path $tempRoot "monitor_24h_raw_qualification.ps1"
        $mutant.body.harness.direct_artifacts_retained_and_rehashed.bindings_at_start[4].path = $driftPath
        $mutant.body.harness.direct_artifacts_retained_and_rehashed.bindings_at_terminal[4].path = $driftPath
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "source path drift with same basename" -Mutation {
        param($mutant)
        $driftPath = Join-Path $tempRoot "run_raw_fault_gate.ps1"
        $mutant.body.harness.source_bindings_at_start[0].path = $driftPath
        $mutant.body.harness.source_bindings_at_terminal[0].path = $driftPath
        $mutant.body.harness.direct_artifacts_retained_and_rehashed.bindings_at_start[0].path = $driftPath
        $mutant.body.harness.direct_artifacts_retained_and_rehashed.bindings_at_terminal[0].path = $driftPath
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "coordinated inner Job relabel" -Mutation {
        param($mutant)
        $mutant.body.containment.inner_job_name = "Local\BinanceRawQualificationJob-relabelled"
        $mutant.body.live_gate.watchdog_ready.job_name = "Local\BinanceRawQualificationJob-relabelled"
        $mutant.body.launcher.containment.job_name = "Local\BinanceRawQualificationJob-relabelled"
        Update-SelfTestContainmentEvidenceSha -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "coordinated outer Job relabel" -Mutation {
        param($mutant)
        $mutant.body.containment.outer_job_name = "Local\BinanceRawFaultGateOuter-relabelled"
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "workload Job relabel" -Mutation {
        param($mutant)
        $mutant.body.containment.workload_job_name = "Local\BinanceRawQualificationWorkloadJob-relabelled"
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "workload Job aliases launcher outer Job" -Mutation {
        param($mutant)
        $mutant.body.containment.workload_job_name = [string]$mutant.body.containment.inner_job_name
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "coordinated surviving workload Job" -Mutation {
        param($mutant)
        $mutant.body.containment.workload_job_exists = $true
        Update-SelfTestEmbeddedFaultJournal -Envelope $mutant -Mutation {
            param($entries)
            $entries[6].body.payload.workload_job_exists = $true
            $entries[7].body.payload.workload_job_exists = $true
        }
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "coordinated workload Job absence error drift" -Mutation {
        param($mutant)
        $mutant.body.containment.workload_job_open_error = [int]0
        Update-SelfTestEmbeddedFaultJournal -Envelope $mutant -Mutation {
            param($entries)
            $entries[6].body.payload.workload_job_open_error = [int]0
            $entries[7].body.payload.workload_job_open_error = [int]0
        }
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "coordinated target pid zero" -Mutation {
        param($mutant)
        $mutant.body.fault.target.pid = [uint32]0
        $mutant.body.retained_process_identities[2].pid = [uint32]0
        $mutant.body.containment.retained_identity_absence[2].pid = [uint32]0
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "coordinated target creation zero" -Mutation {
        param($mutant)
        $mutant.body.fault.target.creation_filetime_utc = [int64]0
        $mutant.body.retained_process_identities[2].creation_filetime_utc = [int64]0
        $mutant.body.containment.retained_identity_absence[2].creation_filetime_utc = [int64]0
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "numeric unchanged flag" -Mutation {
        param($mutant)
        $mutant.body.harness.direct_artifacts_retained_and_rehashed.unchanged = [int]1
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "numeric launcher_complete flag" -Mutation {
        param($mutant)
        $mutant.body.promotion.launcher_complete = [int]0
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "string outer active count" -Mutation {
        param($mutant)
        $mutant.body.containment.outer_active_processes = "0"
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "numeric attestation flag" -Mutation {
        param($mutant)
        $mutant.body.harness.observed_digest_or_external_trust_boundary.absolute_executed_byte_attestation = [int]0
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "unknown evidence body property" -Mutation {
        param($mutant)
        $mutant.body | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "old evidence schema" -Mutation {
        param($mutant)
        $mutant.body.schema = "RawQualificationFaultEvidenceV2"
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "case-mutated evidence schema key" -Mutation {
        param($mutant)
        $replacement = [ordered]@{}
        foreach ($property in @($mutant.body.PSObject.Properties)) {
            $name = if ($property.Name -ceq "schema") { "Schema" } else { [string]$property.Name }
            $replacement[$name] = $property.Value
        }
        $mutant.body = [pscustomobject]$replacement
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "containment false with null Win32 error" -Mutation {
        param($mutant)
        $mutant.body.launcher.containment.terminate_succeeded = $false
        $mutant.body.launcher.containment.terminate_error = $null
        $mutant.body.launcher.containment.result = "DRAINED_CONCURRENT_OR_PREEXISTING"
        Update-SelfTestContainmentEvidenceSha -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "containment result contradicts successful termination" -Mutation {
        param($mutant)
        $mutant.body.launcher.containment.result = "DRAINED_CONCURRENT_OR_PREEXISTING"
        Update-SelfTestContainmentEvidenceSha -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "containment drain exceeds deadline" -Mutation {
        param($mutant)
        $mutant.body.launcher.containment.drain_elapsed_qpc_ticks = [uint64]::MaxValue
        Update-SelfTestContainmentEvidenceSha -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "containment impossible producer drain deadline" -Mutation {
        param($mutant)
        $mutant.body.launcher.containment.drain_deadline_s = [uint64]31
        Update-SelfTestContainmentEvidenceSha -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "containment detected before injected fault interval" -Mutation {
        param($mutant)
        $mutant.body.launcher.containment.detected_monotonic_tick = [uint64]899
        Update-SelfTestContainmentEvidenceSha -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "authenticated request QPC after containment detection" -Mutation {
        param($mutant)
        $mutant.body.fault.injection_requested_qpc_timestamp = [uint64]1201
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "coordinated monitor command self-hash without exact argv" -Mutation {
        param($mutant)
        $mutant.body.live_gate.monitor.exact_command_line = "powershell monitor"
        $mutant.body.live_gate.monitor.command_line_sha256 = Get-FaultGateSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes("powershell monitor"))
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "launcher relative QPC origin overflow" -Mutation {
        param($mutant)
        $mutant.body.launcher.monotonic_origin_qpc_timestamp = [uint64][int64]::MaxValue
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "containment termination after external observation" -Mutation {
        param($mutant)
        $mutant.body.launcher.containment.termination_monotonic_tick = [uint64]2001
        Update-SelfTestContainmentEvidenceSha -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "containment observation after authenticated launcher-exited envelope" -Mutation {
        param($mutant)
        $mutant.body.fault.containment_observed_monotonic_tick = [uint64]1401
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "raw campaign failure class exit three" -Mutation {
        param($mutant)
        $mutant.body.launcher.terminal_failure = "BTCUSDT raw_campaign exited with code 2."
        $mutant.body.containment.btc_coordinator_exit_code = [uint32]3
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "promoted campaign manifest hidden in artifact tree" -Mutation {
        param($mutant)
        $rows = @($mutant.body.artifact_tree.inventory) + @([pscustomobject][ordered]@{ relative_path = "campaign.json"; bytes = [uint64]1; sha256 = "9" * 64 })
        $mutant.body.artifact_tree.inventory = @($rows | Sort-Object -Property relative_path)
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "empty artifact tree" -Mutation {
        param($mutant)
        $mutant.body.artifact_tree.inventory = @()
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "missing referenced launcher terminal tree row" -Mutation {
        param($mutant)
        $mutant.body.artifact_tree.inventory = @($mutant.body.artifact_tree.inventory | Where-Object { [string]$_.relative_path -cne "launcher-terminal.json" })
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "orphan raw stream file in artifact tree" -Mutation {
        param($mutant)
        $rows = @($mutant.body.artifact_tree.inventory) + @([pscustomobject][ordered]@{
            relative_path = "1-BTCUSDT-raw-111111111111/generations/session-BTCUSDT/depth/segment-999999.bnraw"
            bytes = [uint64]1; sha256 = "9" * 64
        })
        $mutant.body.artifact_tree.inventory = @($rows | Sort-Object -Property relative_path)
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "snapshot HTTP metadata swap without journal event" -Mutation {
        param($mutant)
        $mutant.body.raw_durable_prefixes[0].snapshot.http_metadata_sha256 = "9" * 64
        $mutant.body.raw_preservation.pre_fault_raw_prefixes[0].snapshot.http_metadata_sha256 = "9" * 64
        $mutant.body.raw_preservation.pre_fault_raw_prefixes_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($mutant.body.raw_preservation.pre_fault_raw_prefixes))
        $row = @($mutant.body.artifact_tree.inventory | Where-Object { [string]$_.relative_path -ceq "1-BTCUSDT-raw-111111111111/generations/session-BTCUSDT/snapshot-http.json" })[0]
        $row.sha256 = "9" * 64
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "raw preservation overclaim" -Mutation {
        param($mutant)
        $mutant.body.raw_preservation.completeness_claim = "ALL_DURABLE_BYTES_AT_TERMINATEPROCESS"
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "generation duration differs from fixed gate launch" -Mutation {
        param($mutant)
        $mutant.body.raw_durable_prefixes[0].telemetry.duration_requested_s = [uint64]600
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "generation spec revision differs from pinned capture" -Mutation {
        param($mutant)
        $mutant.body.raw_durable_prefixes[0].spec_revision = "1111111111111111111111111111111111111111"
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "durable BNRAW prefix offset shrink" -Mutation {
        param($mutant)
        $mutant.body.raw_preservation.durable_prefixes.inventory[0].raw_prefix_bytes = [uint64]99
        $mutant.body.raw_preservation.durable_prefixes.inventory_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($mutant.body.raw_preservation.durable_prefixes.inventory))
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "durable BNRAW prefix digest drift" -Mutation {
        param($mutant)
        $mutant.body.raw_preservation.durable_prefixes.inventory[0].raw_prefix_sha256 = "9" * 64
        $mutant.body.raw_preservation.durable_prefixes.inventory_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($mutant.body.raw_preservation.durable_prefixes.inventory))
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "durable BNRAW post-rescan extension prefix drift" -Mutation {
        param($mutant)
        $mutant.body.raw_preservation.durable_prefixes.inventory[0].post_rescan_raw_prefix_sha256 = "9" * 64
        $mutant.body.raw_preservation.durable_prefixes.inventory_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($mutant.body.raw_preservation.durable_prefixes.inventory))
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "durable BNACK prefix offset shrink" -Mutation {
        param($mutant)
        $mutant.body.raw_preservation.durable_prefixes.inventory[0].progress_prefix_bytes = [uint64]99
        $mutant.body.raw_preservation.durable_prefixes.inventory_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($mutant.body.raw_preservation.durable_prefixes.inventory))
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "durable BNACK prefix digest drift" -Mutation {
        param($mutant)
        $mutant.body.raw_preservation.durable_prefixes.inventory[0].progress_prefix_sha256 = "9" * 64
        $mutant.body.raw_preservation.durable_prefixes.inventory_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($mutant.body.raw_preservation.durable_prefixes.inventory))
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "durable BNACK post-rescan extension prefix drift" -Mutation {
        param($mutant)
        $mutant.body.raw_preservation.durable_prefixes.inventory[0].post_rescan_progress_prefix_sha256 = "9" * 64
        $mutant.body.raw_preservation.durable_prefixes.inventory_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($mutant.body.raw_preservation.durable_prefixes.inventory))
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "durable prefix inventory omission" -Mutation {
        param($mutant)
        $mutant.body.raw_preservation.durable_prefixes.inventory = @($mutant.body.raw_preservation.durable_prefixes.inventory | Select-Object -Skip 1)
        $mutant.body.raw_preservation.durable_prefixes.durable_segments = [uint64]$mutant.body.raw_preservation.durable_prefixes.inventory.Count
        $mutant.body.raw_preservation.durable_prefixes.inventory_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($mutant.body.raw_preservation.durable_prefixes.inventory))
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "fault request journal linkage" -Mutation {
        param($mutant)
        $mutant.body.fault_journal.injection_requested_record_sha256 = "9" * 64
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "reencoded fault proposal target identity drift" -Mutation {
        param($mutant)
        Update-SelfTestEmbeddedFaultJournal -Envelope $mutant -Mutation {
            param($entries)
            $entries[3].body.payload.target_creation_filetime_utc = [int64]999
        }
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "reencoded fault request QPC predates proposal envelope" -Mutation {
        param($mutant)
        $mutant.body.fault.injection_requested_qpc_timestamp = [uint64]1
        Update-SelfTestEmbeddedFaultJournal -Envelope $mutant -Mutation {
            param($entries)
            $entries[4].body.payload.request_monotonic_tick = [uint64]1
            $entries[5].body.payload.injected_monotonic_tick = [uint64]2
        }
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "fault journal embedded bytes drift" -Mutation {
        param($mutant)
        [byte[]]$faultBytes = [Convert]::FromBase64String([string]$mutant.body.fault_journal.journal_bytes_base64)
        $faultBytes[0] = $faultBytes[0] -bxor 1
        $mutant.body.fault_journal.journal_bytes_base64 = [Convert]::ToBase64String($faultBytes)
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "failure deadline below runtime contract" -Mutation {
        param($mutant)
        $mutant.body.fault.failure_deadline_seconds = [uint64]29
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "failure deadline above runtime contract" -Mutation {
        param($mutant)
        $mutant.body.fault.failure_deadline_seconds = [uint64]601
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "failure deadline differs from exact public gate" -Mutation {
        param($mutant)
        $mutant.body.fault.failure_deadline_seconds = [uint64]31
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "campaign started startup digest differs from artifact" -Mutation {
        param($mutant)
        $mutant.body.campaign_journals[0].campaign_started_event.body.payload.startup_sha256 = "9" * 64
        $mutant.body.campaign_journals[0].campaign_started_event.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $mutant.body.campaign_journals[0].campaign_started_event.body)
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "coordinated campaign-startup relabel differs from embedded journal bytes" -Mutation {
        param($mutant)
        $mutant.body.campaign_journals[0].campaign_startup_sha256 = "9" * 64
        $mutant.body.campaign_journals[0].campaign_started_event.body.payload.startup_sha256 = "9" * 64
        $mutant.body.campaign_journals[0].campaign_started_event.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $mutant.body.campaign_journals[0].campaign_started_event.body)
        $startupTreeRow = @($mutant.body.artifact_tree.inventory | Where-Object { [string]$_.relative_path -ceq "1-BTCUSDT-raw-111111111111/campaign-startup.json" })[0]
        $startupTreeRow.sha256 = "9" * 64
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "embedded campaign journal noncanonical Base64" -Mutation {
        param($mutant)
        $mutant.body.campaign_journals[0].journal_bytes_base64 = ([string]$mutant.body.campaign_journals[0].journal_bytes_base64).Insert(4, "`n")
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "embedded journal heartbeat differs from durable telemetry" -Mutation {
        param($mutant)
        [byte[]]$journalBytes = [Convert]::FromBase64String([string]$mutant.body.campaign_journals[0].journal_bytes_base64)
        $journalText = [Text.UTF8Encoding]::new($false, $true).GetString($journalBytes)
        $journalLines = @($journalText.Split([char]10) | Where-Object { $_.Length -gt 0 })
        $previous = $script:FaultGateZeroDigest
        $builder = [Text.StringBuilder]::new()
        $prefixBuilder = [Text.StringBuilder]::new()
        $prefixTerminal = $null
        for ($lineIndex = 0; $lineIndex -lt $journalLines.Count; $lineIndex++) {
            $entry = $journalLines[$lineIndex] | ConvertFrom-Json
            $entry.body.previous_record_sha256 = $previous
            if ([string]$entry.body.payload.event -ceq "HEARTBEAT_DURABLE") { $entry.body.payload.depth_received = [uint64]11 }
            $entry.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateSerdeCompactJsonBytes -Value $entry.body)
            $canonicalEntry = [Text.UTF8Encoding]::new($false).GetString((ConvertTo-FaultGateSerdeCompactJsonBytes -Value $entry))
            $null = $builder.Append($canonicalEntry).Append([char]10)
            if ($lineIndex -lt 10) { $null = $prefixBuilder.Append($canonicalEntry).Append([char]10); $prefixTerminal = [string]$entry.record_sha256 }
            $previous = [string]$entry.record_sha256
        }
        [byte[]]$mutatedJournalBytes = [Text.UTF8Encoding]::new($false).GetBytes($builder.ToString())
        $mutant.body.campaign_journals[0].journal_bytes_base64 = [Convert]::ToBase64String($mutatedJournalBytes)
        $mutant.body.campaign_journals[0].terminal_record_sha256 = $previous
        $mutant.body.campaign_journals[0].file_bytes = [uint64]$mutatedJournalBytes.Length
        $mutant.body.campaign_journals[0].file_sha256 = Get-FaultGateSha256Bytes -Bytes $mutatedJournalBytes
        [byte[]]$mutatedPrefixBytes = [Text.UTF8Encoding]::new($false).GetBytes($prefixBuilder.ToString())
        $mutant.body.campaign_prefixes.pre_fault_campaign_prefixes[0].terminal_record_sha256 = $prefixTerminal
        $mutant.body.campaign_prefixes.pre_fault_campaign_prefixes[0].file_sha256 = Get-FaultGateSha256Bytes -Bytes $mutatedPrefixBytes
        $mutant.body.campaign_journals[0].causality.pre_fault_terminal_record_sha256 = $prefixTerminal
        $mutant.body.campaign_prefixes.pre_fault_campaign_prefixes_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value @($mutant.body.campaign_prefixes.pre_fault_campaign_prefixes))
        $journalTreeRow = @($mutant.body.artifact_tree.inventory | Where-Object { [string]$_.relative_path -ceq "1-BTCUSDT-raw-111111111111/campaign-events.jsonl" })[0]
        $journalTreeRow.bytes = [uint64]$mutatedJournalBytes.Length; $journalTreeRow.sha256 = [string]$mutant.body.campaign_journals[0].file_sha256
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "PASS evidence accepts concurrent containment" -Mutation {
        param($mutant)
        $mutant.body.launcher.containment.terminate_attempted = $false
        $mutant.body.launcher.containment.terminate_succeeded = $null
        $mutant.body.launcher.containment.terminate_error = $null
        $mutant.body.launcher.containment.result = "DRAINED_CONCURRENT_OR_PREEXISTING"
        Update-SelfTestContainmentEvidenceSha -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "tree bytes contradict launcher terminal" -Mutation {
        param($mutant)
        $row = @($mutant.body.artifact_tree.inventory | Where-Object { [string]$_.relative_path -ceq "launcher-terminal.json" })[0]
        $row.bytes = [uint64]101
        Update-SelfTestEvidenceTreeEnvelope -Envelope $mutant
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "swapped campaign journal order" -Mutation {
        param($mutant)
        $mutant.body.campaign_journals = @($mutant.body.campaign_journals[1], $mutant.body.campaign_journals[0])
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "omitted retained absence identity" -Mutation {
        param($mutant)
        $mutant.body.containment.retained_identity_absence = @($mutant.body.containment.retained_identity_absence | Select-Object -First 5)
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "sealed coordinator path replaced by build source path" -Mutation {
        param($mutant)
        $buildCampaignPath = [string](@($mutant.body.harness.direct_artifacts_retained_and_rehashed.bindings_at_start | Where-Object { [string]$_.role -ceq "campaign" })[0].path)
        $mutant.body.retained_process_identities[1].executable_path = $buildCampaignPath
        $mutant.body.containment.retained_identity_absence[1].executable_path = $buildCampaignPath
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "retained identity absence false" -Mutation {
        param($mutant)
        $mutant.body.containment.retained_identity_absence[5].absent = $false
    }
    Assert-SelfTestEvidenceMutantRejected -SourcePath $evidencePath -Name "retained-handle PID reuse claim" -Mutation {
        param($mutant)
        $mutant.body.containment.retained_identity_absence[5].pid_reused = $true
    }
    $evidenceMutantPath = Join-Path $tempRoot "fault-evidence-mutant.json"
    $evidenceMutant = Read-FaultGateJson -Path $evidencePath; $evidenceMutant.body.status = "FAIL"
    Write-SelfTestBytes -Path $evidenceMutantPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($evidenceMutant | ConvertTo-Json -Depth 100) + "`n")))
    Assert-SelfTestThrows { $null = Test-SelfTestEvidenceEnvelope -Path $evidenceMutantPath } "evidence self-hash"
    $bindingMutantPath = Join-Path $tempRoot "fault-evidence-binding-mutant.json"
    $bindingMutant = Read-FaultGateJson -Path $evidencePath
    $bindingMutant.body.harness.source_bindings_at_terminal[0].sha256 = "6" * 64
    $bindingMutant.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $bindingMutant.body)
    Write-SelfTestBytes -Path $bindingMutantPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($bindingMutant | ConvertTo-Json -Depth 100) + "`n")))
    Assert-SelfTestThrows { $null = Test-SelfTestEvidenceEnvelope -Path $bindingMutantPath } "evidence retained source binding"
    $roleMutantPath = Join-Path $tempRoot "fault-evidence-role-mutant.json"
    $roleMutant = Read-FaultGateJson -Path $evidencePath
    $roleMutant.body.harness.source_bindings_at_start[0].role = "executed_harness"
    $roleMutant.body.harness.source_bindings_at_terminal[0].role = "executed_harness"
    $roleMutant.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $roleMutant.body)
    Write-SelfTestBytes -Path $roleMutantPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($roleMutant | ConvertTo-Json -Depth 100) + "`n")))
    Assert-SelfTestThrows { $null = Test-SelfTestEvidenceEnvelope -Path $roleMutantPath } "evidence source role claim"
    $trustMutantPath = Join-Path $tempRoot "fault-evidence-trust-mutant.json"
    $trustMutant = Read-FaultGateJson -Path $evidencePath
    $trustMutant.body.harness.source_binding_trust_boundary = "EXECUTED_BYTES_ATTESTED"
    $trustMutant.body.harness.source_bindings_at_start[0].trust_boundary = "EXECUTED_BYTES_ATTESTED"
    $trustMutant.body.harness.source_bindings_at_terminal[0].trust_boundary = "EXECUTED_BYTES_ATTESTED"
    $trustMutant.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $trustMutant.body)
    Write-SelfTestBytes -Path $trustMutantPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($trustMutant | ConvertTo-Json -Depth 100) + "`n")))
    Assert-SelfTestThrows { $null = Test-SelfTestEvidenceEnvelope -Path $trustMutantPath } "evidence false executed-byte claim"
    $artifactMutantPath = Join-Path $tempRoot "fault-evidence-artifact-mutant.json"
    $artifactMutant = Read-FaultGateJson -Path $evidencePath
    $artifactMutant.body.harness.direct_artifacts_retained_and_rehashed.hashes_at_terminal.capture = "c" * 64
    $artifactMutant.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $artifactMutant.body)
    Write-SelfTestBytes -Path $artifactMutantPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($artifactMutant | ConvertTo-Json -Depth 100) + "`n")))
    Assert-SelfTestThrows { $null = Test-SelfTestEvidenceEnvelope -Path $artifactMutantPath } "evidence non-source artifact drift"
    $omissionMutantPath = Join-Path $tempRoot "fault-evidence-operational-omission-mutant.json"
    $omissionMutant = Read-FaultGateJson -Path $evidencePath
    $omissionMutant.body.harness.direct_artifacts_retained_and_rehashed.bindings_at_start = @($omissionMutant.body.harness.direct_artifacts_retained_and_rehashed.bindings_at_start | Where-Object { [string]$_.role -cne "watchdog" })
    $omissionMutant.body.harness.direct_artifacts_retained_and_rehashed.bindings_at_terminal = @($omissionMutant.body.harness.direct_artifacts_retained_and_rehashed.bindings_at_terminal | Where-Object { [string]$_.role -cne "watchdog" })
    $omissionMutant.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $omissionMutant.body)
    Write-SelfTestBytes -Path $omissionMutantPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($omissionMutant | ConvertTo-Json -Depth 100) + "`n")))
    Assert-SelfTestThrows { $null = Test-SelfTestEvidenceEnvelope -Path $omissionMutantPath } "evidence operational artifact omission"
    $globalTrustMutantPath = Join-Path $tempRoot "fault-evidence-global-trust-mutant.json"
    $globalTrustMutant = Read-FaultGateJson -Path $evidencePath
    $globalTrustMutant.body.harness.direct_artifacts_retained_and_rehashed.trust_boundary = "EXECUTED_OR_MAPPED_BYTES_ATTESTED"
    foreach ($row in @($globalTrustMutant.body.harness.direct_artifacts_retained_and_rehashed.bindings_at_start) + @($globalTrustMutant.body.harness.direct_artifacts_retained_and_rehashed.bindings_at_terminal)) { $row.trust_boundary = "EXECUTED_OR_MAPPED_BYTES_ATTESTED" }
    $globalTrustMutant.record_sha256 = Get-FaultGateSha256Bytes -Bytes (ConvertTo-FaultGateCompactJsonBytes -Value $globalTrustMutant.body)
    Write-SelfTestBytes -Path $globalTrustMutantPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes((($globalTrustMutant | ConvertTo-Json -Depth 100) + "`n")))
    Assert-SelfTestThrows { $null = Test-SelfTestEvidenceEnvelope -Path $globalTrustMutantPath } "evidence false global executed-byte claim"

    $sourceRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "src"
    $mutableSource = Get-RawQualificationSourceTreeDigest `
        -Root $sourceRoot `
        -AllowIgnoredBytecodeCaches
    $sealedSource = New-RawQualificationSealedSourceTree `
        -SourceTree $mutableSource `
        -Destination (Join-Path $tempRoot "sealed-python-verifier-source")
    $cacheDirectories = @(Get-ChildItem -LiteralPath $sealedSource.root -Recurse -Directory -Force -ErrorAction Stop | Where-Object { $_.Name -ceq "__pycache__" })
    Assert-SelfTest ($cacheDirectories.Count -eq 0) "Sealed Python verifier source contains a bytecode cache."
    Assert-SelfTest ($sealedSource.tree_sha256 -ceq $mutableSource.tree_sha256 -and
        [uint64]$sealedSource.files -eq [uint64]$mutableSource.files) "Sealed Python verifier source differs from its mutable preflight inventory."

    Initialize-RawQualificationNative
    Initialize-FaultGateNative
    $jobName = "Local\BinanceRawFaultGateSelfTest-" + [Guid]::NewGuid().ToString("N")
    Write-SelfTestBytes -Path $bindingPath -Bytes ([Text.UTF8Encoding]::new($false).GetBytes("if (`$env:OS -cne 'Windows_NT' -or `$null -eq (Get-CimInstance Win32_Process -Filter 'ProcessId=4')) { exit 7 }`nStart-Sleep -Seconds 30`n"))
    $job = [IntPtr]::Zero; $launch = $null; $openedIdentity = $null; $jobScriptBinding = $null; $jobRuntimeBinding = $null
    try {
        $job = [RawQualificationNative]::CreateKillOnCloseJob($jobName)
        $localPowerShell = Join-Path $PSHOME "powershell.exe"
        $jobScriptBinding = Open-FaultGateRetainedPathBinding -Path $bindingPath -Role "selftest_interpreted_script"
        $jobRuntimeBinding = Open-FaultGateRetainedPathBinding -Path $localPowerShell -Role "selftest_mapped_runtime"
        $launch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $job, $localPowerShell, [string[]]@("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $bindingPath),
            $tempRoot, (Join-Path $tempRoot "job.stdout.log"), (Join-Path $tempRoot "job.stderr.log"), (Get-FaultGateChildEnvironment))
        $openedIdentity = Open-FaultGateExactProcess -ProcessId ([uint32]$launch.ProcessId) -ExpectedExecutable $localPowerShell -ExpectedCommandLine ([string]$launch.ExactCommandLine) -ExpectedParentProcessId ([uint32]$PID) -Role "selftest_child" -ExpectedCreationTimeUtc ([DateTime]::FromFileTimeUtc([int64]$launch.CreationFileTimeUtc).ToString("o"))
        Assert-SelfTest ([int64]$openedIdentity.creation_filetime_utc -eq [int64]$launch.CreationFileTimeUtc) "Retained OpenProcess identity changed creation time."
        Start-Sleep -Milliseconds 1000
        Assert-SelfTest ([RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle) -eq 259) "Explicit launcher environment could not initialize OS/CIM locally."
        $activeBefore = [uint32][RawQualificationNative]::GetActiveProcessCount($job)
        Assert-SelfTest ($activeBefore -ge 1) "Native self-test process was not assigned before resume."
        Assert-SelfTest ([RawFaultGateNative]::QueryNamedJob($jobName).ActiveProcesses -ge 1) "Named Job query did not observe an active assigned process."
        Assert-SelfTest ([RawQualificationNative]::TerminateJobObject($job, $script:FaultGateFallbackExitCode)) "Native TerminateJobObject returned false."
        Assert-SelfTest ([RawQualificationNative]::WaitForProcessExit($launch.ProcessHandle, 10000)) "Native Job child did not exit."
        Assert-SelfTest ([RawQualificationNative]::GetProcessExitCode($launch.ProcessHandle) -eq $script:FaultGateFallbackExitCode) "Native Job child exit code drifted."
        $drainOrigin = [Diagnostics.Stopwatch]::GetTimestamp()
        while ([RawQualificationNative]::GetActiveProcessCount($job) -ne 0 -and
            (Test-RawQualificationDeadlineTicks -ElapsedTicks ([Diagnostics.Stopwatch]::GetTimestamp() - $drainOrigin) -TimeoutSeconds 10)) { Start-Sleep -Milliseconds 50 }
        Assert-SelfTest ([RawQualificationNative]::GetActiveProcessCount($job) -eq 0) "Native Job did not drain to zero."
        $sameCreationRow = [pscustomobject]@{
            ProcessId = [uint32]$openedIdentity.pid; ParentProcessId = [uint32]$openedIdentity.parent_pid; Name = "powershell.exe"
            CreationDate = [DateTime]::FromFileTimeUtc([int64]$openedIdentity.creation_filetime_utc)
            ExecutablePath = [string]$openedIdentity.executable_path; CommandLine = [string]$openedIdentity.command_line
        }
        Assert-SelfTestThrows {
            $null = Test-FaultGateRecordedProcessAbsent -Identity $openedIdentity -ProcessSnapshot @($sameCreationRow)
        } "retained PID remains with original creation identity"
        $differentCreationRow = $sameCreationRow | Select-Object *
        $differentCreationRow.CreationDate = ([DateTime]$sameCreationRow.CreationDate).AddTicks(1)
        Assert-SelfTestThrows {
            $null = Test-FaultGateRecordedProcessAbsent -Identity $openedIdentity -ProcessSnapshot @($differentCreationRow)
        } "retained PID impossible reuse before handle close"
        Assert-SelfTestThrows {
            $null = Test-FaultGateRecordedProcessAbsent -Identity $openedIdentity -ProcessSnapshot @($sameCreationRow, $differentCreationRow)
        } "duplicate PID in one terminal process snapshot"
        $nativeTerminalSnapshot = @(Get-FaultGateProcessSnapshot)
        $nativeAbsence = Test-FaultGateRecordedProcessAbsent -Identity $openedIdentity -ProcessSnapshot $nativeTerminalSnapshot
        Assert-SelfTest ([bool]$nativeAbsence.absent -and -not [bool]$nativeAbsence.pid_reused) "Retained native process was not literally absent from the bounded terminal snapshot."
    }
    finally {
        if ($null -ne $openedIdentity) { Close-FaultGateProcessIdentity -Identity $openedIdentity }
        if ($null -ne $launch -and $launch.ProcessHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($launch.ProcessHandle) }
        if ($job -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($job) }
        Close-FaultGateRetainedPathBinding -Binding $jobRuntimeBinding
        Close-FaultGateRetainedPathBinding -Binding $jobScriptBinding
    }
    $closedJob = [RawFaultGateNative]::QueryNamedJob($jobName)
    Assert-SelfTest (-not $closedJob.Exists -and $closedJob.Error -eq 2) "Native self-test Job remained named after final handle close."

    $hungMonitorScript = Join-Path $tempRoot "hung-monitor.ps1"
    Write-SelfTestBytes -Path $hungMonitorScript -Bytes ([Text.UTF8Encoding]::new($false).GetBytes("Start-Sleep -Seconds 30`n"))
    $deadlineJobName = "Local\BinanceRawFaultGateDeadlineSelfTest-" + [Guid]::NewGuid().ToString("N")
    $deadlineJob = [IntPtr]::Zero
    try {
        $deadlineJob = [RawQualificationNative]::CreateKillOnCloseJob($deadlineJobName)
        $deadline60Origin = [int64]([Diagnostics.Stopwatch]::GetTimestamp() - ([int64]55 * [int64][Diagnostics.Stopwatch]::Frequency))
        $deadline60Tick = [int64]($deadline60Origin + ([int64]60 * [int64][Diagnostics.Stopwatch]::Frequency))
        $remainingUnderCap = Get-FaultGateRemainingDeadlineMilliseconds -DeadlineMonotonicTick $deadline60Tick
        Assert-SelfTest ($remainingUnderCap -gt 4000 -and $remainingUnderCap -lt 120000) "Synthetic 60-second startup deadline did not expose a remainder below the monitor cap."
        $boundedOrigin = [Diagnostics.Stopwatch]::GetTimestamp()
        $hungResult = Invoke-FaultGateMonitorAttempt -OuterJob $deadlineJob -PowerShellExecutable (Join-Path $PSHOME "powershell.exe") `
            -ExpectedPowerShellSha256 (Get-FaultGateSha256File -Path (Join-Path $PSHOME "powershell.exe")) `
            -MonitorScript $hungMonitorScript -RunRoot $tempRoot -GateRoot $tempRoot -EnvironmentEntries (Get-FaultGateChildEnvironment) `
            -ExpectedGuardianPid 30 -ExpectedProcesses $expectedMonitorProcesses -ExpectedCampaigns $expectedMonitorCampaigns `
            -ExpectedMinimumDiskFreeGiB 101 -Attempt 900 -DeadlineMonotonicTick $deadline60Tick `
            -PerAttemptCapMilliseconds 120000 -DrainCapMilliseconds 500 -MinimumMonitorBudgetMilliseconds 250
        $boundedElapsed = [Diagnostics.Stopwatch]::GetTimestamp() - $boundedOrigin
        Assert-SelfTest ($null -eq $hungResult) "Hung monitor did not return a bounded null observation after retained-handle termination."
        Assert-SelfTest (Test-RawQualificationDeadlineTicks -ElapsedTicks $boundedElapsed -TimeoutSeconds 6) "Hung monitor exceeded the synthetic 60-second absolute deadline remainder."
        $deadlineJobDrainOrigin = [Diagnostics.Stopwatch]::GetTimestamp()
        do {
            $deadlineJobActive = [uint32][RawQualificationNative]::GetActiveProcessCount($deadlineJob)
            $deadlineJobObservedTick = [int64][Diagnostics.Stopwatch]::GetTimestamp()
            if ($deadlineJobActive -eq 0 -or -not (Test-RawQualificationDeadlineTicks -ElapsedTicks ($deadlineJobObservedTick - $deadlineJobDrainOrigin) -TimeoutSeconds 2)) { break }
            Start-Sleep -Milliseconds 10
        } while ($true)
        Assert-SelfTest ($deadlineJobActive -eq 0 -and
            (Test-RawQualificationDeadlineTicks -ElapsedTicks ($deadlineJobObservedTick - $deadlineJobDrainOrigin) -TimeoutSeconds 2)) "Hung monitor was not terminally observed and drained from its Job inside the exact post-exit convergence bound."
    }
    finally {
        if ($deadlineJob -ne [IntPtr]::Zero) {
            if ([RawQualificationNative]::GetActiveProcessCount($deadlineJob) -ne 0) { $null = [RawQualificationNative]::TerminateJobObject($deadlineJob, $script:FaultGateFallbackExitCode) }
            $null = [RawQualificationNative]::CloseHandle($deadlineJob)
        }
    }
    $closedDeadlineJob = [RawFaultGateNative]::QueryNamedJob($deadlineJobName)
    Assert-SelfTest (-not $closedDeadlineJob.Exists -and $closedDeadlineJob.Error -eq 2) "Deadline self-test Job remained named after final handle close."

    $pssaModule = Join-Path (Split-Path $PSScriptRoot -Parent) "artifacts\tools\PSScriptAnalyzer-1.25.0\PSScriptAnalyzer.psd1"
    if (-not (Test-Path -LiteralPath $pssaModule -PathType Leaf)) { throw "Pinned local PSScriptAnalyzer module is absent." }
    Import-Module -Name $pssaModule -Force -ErrorAction Stop
    $diagnostics = @(@($harnessPath, $selfPath) | ForEach-Object { Invoke-ScriptAnalyzer -Path $_ -Severity Error })
    Assert-SelfTest ($diagnostics.Count -eq 0) "PSScriptAnalyzer reported Error diagnostics."
    $pssa = "PASS"
    [pscustomobject][ordered]@{
        schema = "RawQualificationFaultGateSelfTestV1"
        status = "PASS"
        assertions = $script:FaultSelfTestPassed
        rejected_mutants = $script:FaultSelfTestMutants
        ast = "PASS"
        pssa = $pssa
        python_source_cache_directories = [uint64]$cacheDirectories.Count
        harness_sha256 = Get-FaultGateSha256File -Path $harnessPath
        selftest_sha256 = Get-FaultGateSha256File -Path $selfPath
    } | ConvertTo-Json -Depth 10
}
finally {
    $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
    if ($resolvedTemp.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolvedTemp).StartsWith("BinanceRawFaultGateSelfTest-", [StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $evidenceSandboxRoot) {
        $resolvedEvidenceSandbox = [IO.Path]::GetFullPath($evidenceSandboxRoot)
        $allowedEvidencePrefix = [IO.Path]::GetFullPath((Join-Path (Join-Path $PSScriptRoot "..") "artifacts")).TrimEnd('\') + '\'
        if ($resolvedEvidenceSandbox.StartsWith($allowedEvidencePrefix, [StringComparison]::OrdinalIgnoreCase) -and
            [IO.Path]::GetFileName($resolvedEvidenceSandbox).StartsWith("raw-fault-gate-selftest-", [StringComparison]::Ordinal)) {
            Remove-Item -LiteralPath $resolvedEvidenceSandbox -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
