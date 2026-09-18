[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $EvidenceRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z-]{0,127}$')]
    [string] $ObservationId,

    [ValidateRange(1, 691200)]
    [uint32] $DurationSeconds = 86400,

    [ValidateRange(5, 300)]
    [uint32] $IntervalSeconds = 30,

    [ValidateRange(250, 10000)]
    [uint32] $ProbeTimeoutMilliseconds = 2000,

    [string] $StopFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")

$cooperativeStop = -not [string]::IsNullOrWhiteSpace($StopFile)
$schema = if ($cooperativeStop) { "RawQualificationNetworkWitnessRecordV2" } else { "RawQualificationNetworkWitnessRecordV1" }
$resolvedRoot = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\')
$parent = [IO.Path]::GetDirectoryName($resolvedRoot)
if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw "Network witness evidence parent does not exist."
}
$null = Assert-RawQualificationNoReparsePointInExistingPath -Path $parent
if (Test-Path -LiteralPath $resolvedRoot) {
    throw "Network witness evidence root already exists; collection is create-only."
}
$null = New-Item -ItemType Directory -Path $resolvedRoot -ErrorAction Stop
$null = Assert-RawQualificationNoReparsePointInExistingPath -Path $resolvedRoot

$resolvedStopFile = $null
if ($cooperativeStop) {
    $resolvedStopFile = [IO.Path]::GetFullPath($StopFile)
    $stopParent = [IO.Path]::GetDirectoryName($resolvedStopFile)
    if ([string]::IsNullOrWhiteSpace($stopParent) -or
        -not $stopParent.Equals($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Network witness stop file must be a direct child of its evidence root."
    }
    if (Test-Path -LiteralPath $resolvedStopFile) {
        throw "Network witness stop file already exists; collection is create-only."
    }
}

function Get-NetworkWitnessError {
    param([Parameter(Mandatory = $true)] [Exception] $Exception)
    $socketCode = $null
    $cursor = $Exception
    while ($null -ne $cursor) {
        if ($cursor -is [Net.Sockets.SocketException]) {
            $socketCode = [int]$cursor.SocketErrorCode
            break
        }
        $cursor = $cursor.InnerException
    }
    return [ordered]@{
        type = $Exception.GetType().FullName
        hresult = [int]$Exception.HResult
        socket_error_code = $socketCode
        message = [string]$Exception.Message
    }
}

function Invoke-NetworkWitnessDns {
    param([Parameter(Mandatory = $true)] [string] $HostName)
    $started = [Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $task = [Net.Dns]::GetHostAddressesAsync($HostName)
        if (-not $task.Wait([int]$ProbeTimeoutMilliseconds)) {
            return [ordered]@{
                host = $HostName; status = "TIMEOUT"; elapsed_ms = [uint64]$ProbeTimeoutMilliseconds
                addresses = @(); error = $null
            }
        }
        $addresses = @($task.Result | ForEach-Object { $_.ToString() } | Sort-Object -Unique)
        $elapsed = [uint64](([decimal]([Diagnostics.Stopwatch]::GetTimestamp() - $started) * 1000) / [Diagnostics.Stopwatch]::Frequency)
        return [ordered]@{
            host = $HostName; status = if ($addresses.Count -gt 0) { "RESOLVED" } else { "EMPTY" }
            elapsed_ms = $elapsed; addresses = $addresses; error = $null
        }
    }
    catch {
        $elapsed = [uint64](([decimal]([Diagnostics.Stopwatch]::GetTimestamp() - $started) * 1000) / [Diagnostics.Stopwatch]::Frequency)
        return [ordered]@{
            host = $HostName; status = "FAILED"; elapsed_ms = $elapsed; addresses = @()
            error = Get-NetworkWitnessError -Exception $_.Exception
        }
    }
}

function Invoke-NetworkWitnessTcp {
    param(
        [Parameter(Mandatory = $true)] [string] $Target,
        [Parameter(Mandatory = $true)] [Net.IPAddress] $Address,
        [Parameter(Mandatory = $true)] [uint16] $Port
    )
    $client = [Net.Sockets.TcpClient]::new($Address.AddressFamily)
    $started = [Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $async = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne([int]$ProbeTimeoutMilliseconds)) {
            return [ordered]@{
                target = $Target; address = $Address.ToString(); port = $Port; status = "TIMEOUT"
                elapsed_ms = [uint64]$ProbeTimeoutMilliseconds; local_endpoint = $null; remote_endpoint = $null; error = $null
            }
        }
        $client.EndConnect($async)
        $elapsed = [uint64](([decimal]([Diagnostics.Stopwatch]::GetTimestamp() - $started) * 1000) / [Diagnostics.Stopwatch]::Frequency)
        return [ordered]@{
            target = $Target; address = $Address.ToString(); port = $Port; status = "CONNECTED"; elapsed_ms = $elapsed
            local_endpoint = [string]$client.Client.LocalEndPoint; remote_endpoint = [string]$client.Client.RemoteEndPoint; error = $null
        }
    }
    catch {
        $elapsed = [uint64](([decimal]([Diagnostics.Stopwatch]::GetTimestamp() - $started) * 1000) / [Diagnostics.Stopwatch]::Frequency)
        return [ordered]@{
            target = $Target; address = $Address.ToString(); port = $Port; status = "FAILED"; elapsed_ms = $elapsed
            local_endpoint = $null; remote_endpoint = $null; error = Get-NetworkWitnessError -Exception $_.Exception
        }
    }
    finally {
        $client.Dispose()
    }
}

function Get-NetworkWitnessRoute {
    param(
        [Parameter(Mandatory = $true)] [string] $Target,
        [Parameter(Mandatory = $true)] [Net.IPAddress] $Address
    )
    $socket = [Net.Sockets.Socket]::new($Address.AddressFamily, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
    try {
        $socket.Connect([Net.IPEndPoint]::new($Address, 443))
        return [ordered]@{
            target = $Target; address = $Address.ToString(); status = "ROUTE_SELECTED"
            local_endpoint = [string]$socket.LocalEndPoint; error = $null
        }
    }
    catch {
        return [ordered]@{
            target = $Target; address = $Address.ToString(); status = "FAILED"; local_endpoint = $null
            error = Get-NetworkWitnessError -Exception $_.Exception
        }
    }
    finally {
        $socket.Dispose()
    }
}

function Get-NetworkWitnessInterfaces {
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($adapter in @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Sort-Object Id)) {
        $properties = $adapter.GetIPProperties()
        $gateways = @($properties.GatewayAddresses | ForEach-Object { $_.Address.ToString() } | Sort-Object -Unique)
        $unicast = @($properties.UnicastAddresses | ForEach-Object { $_.Address.ToString() } | Sort-Object -Unique)
        $rows.Add([ordered]@{
            id = [string]$adapter.Id
            name = [string]$adapter.Name
            type = [string]$adapter.NetworkInterfaceType
            status = [string]$adapter.OperationalStatus
            speed_bps = [uint64][Math]::Max([int64]0, [int64]$adapter.Speed)
            gateways = $gateways
            unicast_addresses = $unicast
        })
    }
    return @($rows)
}

function Select-NetworkWitnessAddress {
    param([Parameter(Mandatory = $true)] [object[]] $Addresses)
    foreach ($text in $Addresses) {
        $parsed = $null
        if ([Net.IPAddress]::TryParse([string]$text, [ref]$parsed) -and
            $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
            return $parsed
        }
    }
    foreach ($text in $Addresses) {
        $parsed = $null
        if ([Net.IPAddress]::TryParse([string]$text, [ref]$parsed)) { return $parsed }
    }
    return $null
}

$journalPath = Join-Path $resolvedRoot "network-witness-events.jsonl"
$startupPath = Join-Path $resolvedRoot "network-witness-startup.json"
$sealPath = Join-Path $resolvedRoot "network-witness-seal.json"
$journal = $null
$terminalStatus = "COMPLETE"
$terminalError = $null
$terminalStopReason = $null
$origin = [Diagnostics.Stopwatch]::GetTimestamp()
$frequency = [uint64][Diagnostics.Stopwatch]::Frequency
$deadline = [decimal]$DurationSeconds * [decimal]$frequency
$sequence = [uint64]0

try {
    $startup = [ordered]@{
        schema = if ($cooperativeStop) { "RawQualificationNetworkWitnessStartupV2" } else { "RawQualificationNetworkWitnessStartupV1" }
        observation_id = $ObservationId
        evidence_root = $resolvedRoot
        started_utc = [DateTimeOffset]::UtcNow.ToString("o")
        process_id = [uint32]$PID
        monotonic_origin_qpc_timestamp = [int64]$origin
        monotonic_frequency = $frequency
        duration_s = [uint64]$DurationSeconds
        interval_s = [uint64]$IntervalSeconds
        probe_timeout_ms = [uint64]$ProbeTimeoutMilliseconds
        stop_file = if ($cooperativeStop) { [IO.Path]::GetFileName($resolvedStopFile) } else { $null }
        binance_host = "data-stream.binance.vision"
        independent_ip = "1.1.1.1"
        credentials = "NONE"
        order_entry = "ABSENT"
    }
    if (-not $cooperativeStop) { $startup.Remove("stop_file") }
    $startupSha256 = Write-RawQualificationDurableNewJson -Path $startupPath -Value $startup
    $journal = New-RawQualificationJournal -Path $journalPath
    while ([decimal]([Diagnostics.Stopwatch]::GetTimestamp() - $origin) -le $deadline) {
        if ($cooperativeStop -and (Test-Path -LiteralPath $resolvedStopFile -PathType Leaf)) {
            $terminalStopReason = "STOP_FILE"
            break
        }
        $sampleStarted = [Diagnostics.Stopwatch]::GetTimestamp()
        $binanceDns = Invoke-NetworkWitnessDns -HostName "data-stream.binance.vision"
        $binanceAddress = Select-NetworkWitnessAddress -Addresses @($binanceDns.addresses)
        $independentAddress = [Net.IPAddress]::Parse("1.1.1.1")
        $tcp = [Collections.Generic.List[object]]::new()
        $routes = [Collections.Generic.List[object]]::new()
        if ($null -ne $binanceAddress) {
            $tcp.Add((Invoke-NetworkWitnessTcp -Target "BINANCE_PUBLIC_STREAM" -Address $binanceAddress -Port 443))
            $routes.Add((Get-NetworkWitnessRoute -Target "BINANCE_PUBLIC_STREAM" -Address $binanceAddress))
        }
        $tcp.Add((Invoke-NetworkWitnessTcp -Target "INDEPENDENT_INTERNET" -Address $independentAddress -Port 443))
        $routes.Add((Get-NetworkWitnessRoute -Target "INDEPENDENT_INTERNET" -Address $independentAddress))
        $observedTick = [Diagnostics.Stopwatch]::GetTimestamp()
        $payload = [ordered]@{
            event = "NETWORK_WITNESS_SAMPLE"
            observation_id = $ObservationId
            sequence = $sequence
            sample_elapsed_ms = [uint64](([decimal]($observedTick - $sampleStarted) * 1000) / $frequency)
            interfaces = @(Get-NetworkWitnessInterfaces)
            dns = @($binanceDns)
            routes = @($routes)
            tcp = @($tcp)
        }
        $null = Add-RawQualificationJournalRecord `
            -Journal $journal `
            -Schema $schema `
            -Channel "NETWORK_WITNESS" `
            -WallNs (Get-RawQualificationWallNs) `
            -MonotonicTick ([uint64]$observedTick) `
            -Payload $payload
        $sequence = [uint64]($sequence + 1)
        $remainingTicks = $deadline - [decimal]([Diagnostics.Stopwatch]::GetTimestamp() - $origin)
        if ($remainingTicks -le 0) { break }
        $sleepMilliseconds = [int][Math]::Min(
            [decimal]$IntervalSeconds * 1000,
            [Math]::Ceiling(($remainingTicks * 1000) / $frequency))
        while ($sleepMilliseconds -gt 0) {
            if ($cooperativeStop -and (Test-Path -LiteralPath $resolvedStopFile -PathType Leaf)) {
                $terminalStopReason = "STOP_FILE"
                break
            }
            $slice = [int][Math]::Min(100, $sleepMilliseconds)
            Start-Sleep -Milliseconds $slice
            $sleepMilliseconds -= $slice
        }
        if ($terminalStopReason -ceq "STOP_FILE") { break }
    }
    if ($null -eq $terminalStopReason) { $terminalStopReason = "DEADLINE" }
}
catch {
    $terminalStatus = "FAILED"
    $terminalError = [string]$_
    throw
}
finally {
    if ($null -ne $journal -and -not $journal.Closed) {
        try {
            $terminalTick = [Diagnostics.Stopwatch]::GetTimestamp()
            $terminalPayload = [ordered]@{
                event = "NETWORK_WITNESS_TERMINAL"
                observation_id = $ObservationId
                status = $terminalStatus
                error = $terminalError
                samples = $sequence
                stop_reason = if ($cooperativeStop) { $terminalStopReason } else { $null }
            }
            if (-not $cooperativeStop) { $terminalPayload.Remove("stop_reason") }
            $null = Add-RawQualificationJournalRecord `
                -Journal $journal `
                -Schema $schema `
                -Channel "NETWORK_WITNESS" `
                -WallNs (Get-RawQualificationWallNs) `
                -MonotonicTick ([uint64]$terminalTick) `
                -Payload $terminalPayload
            $prefix = Get-RawQualificationJournalPrefixSnapshot -Journal $journal
            Close-RawQualificationJournal -Journal $journal
            $seal = [ordered]@{
                schema = if ($cooperativeStop) { "RawQualificationNetworkWitnessSealV2" } else { "RawQualificationNetworkWitnessSealV1" }
                observation_id = $ObservationId
                status = $terminalStatus
                error = $terminalError
                startup_file = "network-witness-startup.json"
                startup_sha256 = $startupSha256
                journal_file = "network-witness-events.jsonl"
                journal_records = [uint64]$prefix.records
                journal_terminal_record_sha256 = [string]$prefix.terminal_record_sha256
                journal_bytes = [uint64]$prefix.file_bytes
                journal_sha256 = [string]$prefix.file_sha256
                samples = $sequence
                stop_reason = if ($cooperativeStop) { $terminalStopReason } else { $null }
                finished_utc = [DateTimeOffset]::UtcNow.ToString("o")
                attribution_boundary = "ONE_HOST_WITNESS_CANNOT_SEPARATE_ISP_FROM_REMOTE_OR_INTERMEDIATE_FAILURE_WITHOUT_AN_EXTERNAL_VANTAGE"
            }
            if (-not $cooperativeStop) { $seal.Remove("stop_reason") }
            $null = Write-RawQualificationDurableNewJson -Path $sealPath -Value $seal
        }
        finally {
            if (-not $journal.Closed) { Close-RawQualificationJournal -Journal $journal }
        }
    }
}

Get-Content -LiteralPath $sealPath -Raw -Encoding UTF8
