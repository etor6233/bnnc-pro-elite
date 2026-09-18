[CmdletBinding()]
param(
    [ValidateSet("ErrorOnly", "DiagnosticInfo")]
    [string] $WinsockAfdProfile = "DiagnosticInfo"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
Set-Location -LiteralPath $repo
. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")

$base = Join-Path $repo "artifacts\network-trace-fault-smoke"
$null = New-Item -ItemType Directory -Path $base -Force -ErrorAction Stop
$runId = "trace-fault-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$runRoot = Join-Path $base $runId
$traceRoot = Join-Path $runRoot "trace"
$analysisRoot = Join-Path $runRoot "analysis"
$null = New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop
$null = New-Item -ItemType Directory -Path $analysisRoot -ErrorAction Stop
$traceScript = Join-Path $PSScriptRoot "RawQualification.NetworkTrace.ps1"
$python = Join-Path $repo ".venv\Scripts\python.exe"
$pktmon = Join-Path $env:SystemRoot "System32\pktmon.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw "Repository Python is absent." }

function Get-FaultSocketError {
    param([Parameter(Mandatory = $true)] [Exception] $Exception)
    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [Net.Sockets.SocketException]) {
            return [ordered]@{
                native_error_code = [int]$current.NativeErrorCode
                socket_error_code = [string]$current.SocketErrorCode
                exception_type = $Exception.GetType().FullName
            }
        }
        $current = $current.InnerException
    }
    return [ordered]@{
        native_error_code = $null
        socket_error_code = $null
        exception_type = $Exception.GetType().FullName
    }
}

function Invoke-RefusedConnectFault {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = [uint16]([Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    $client = [Net.Sockets.Socket]::new(
        [Net.Sockets.AddressFamily]::InterNetwork,
        [Net.Sockets.SocketType]::Stream,
        [Net.Sockets.ProtocolType]::Tcp)
    $client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 0))
    $clientPort = [uint16]([Net.IPEndPoint]$client.LocalEndPoint).Port
    $startedUtc = [DateTimeOffset]::UtcNow
    $startedQpc = [int64][Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $client.Connect([Net.IPAddress]::Loopback, $port)
        return [ordered]@{
            name = "CONNECT_REFUSED"; status = "FAILED"; port = $port
            native_error_code = $null; socket_error_code = $null; exception_type = $null
            client_port = $clientPort; process_id = [uint32]$PID; address_family = "InterNetwork"
            started_utc = $startedUtc.ToString("o"); completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
            started_qpc_timestamp = $startedQpc; completed_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
        }
    }
    catch {
        $errorIdentity = Get-FaultSocketError -Exception $_.Exception
        return [ordered]@{
            name = "CONNECT_REFUSED"
            status = if ($errorIdentity.socket_error_code -ceq "ConnectionRefused") { "PASS" } else { "FAILED" }
            port = $port
            native_error_code = $errorIdentity.native_error_code
            socket_error_code = $errorIdentity.socket_error_code
            exception_type = $errorIdentity.exception_type
            client_port = $clientPort
            process_id = [uint32]$PID
            address_family = "InterNetwork"
            started_utc = $startedUtc.ToString("o")
            completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
            started_qpc_timestamp = $startedQpc
            completed_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
        }
    }
    finally { $client.Dispose() }
}

function Invoke-CleanFinFault {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $server = $null
    $client = $null
    $port = [uint16]0
    $clientPort = [uint16]0
    $startedUtc = [DateTimeOffset]::UtcNow
    $startedQpc = [int64][Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $listener.Start()
        $port = [uint16]([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $accept = $listener.AcceptTcpClientAsync()
        $client = [Net.Sockets.TcpClient]::new()
        $client.ReceiveTimeout = 2000
        $client.Connect([Net.IPAddress]::Loopback, $port)
        $clientPort = [uint16]([Net.IPEndPoint]$client.Client.LocalEndPoint).Port
        $server = $accept.GetAwaiter().GetResult()
        $server.Client.Shutdown([Net.Sockets.SocketShutdown]::Send)
        $server.Dispose()
        $server = $null
        $value = $client.GetStream().ReadByte()
        return [ordered]@{
            name = "CLEAN_FIN"
            status = if ($value -eq -1) { "PASS" } else { "FAILED" }
            port = $port
            read_result = [int]$value
            native_error_code = $null
            socket_error_code = $null
            exception_type = $null
            client_port = $clientPort
            process_id = [uint32]$PID
            address_family = "InterNetwork"
            started_utc = $startedUtc.ToString("o")
            completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
            started_qpc_timestamp = $startedQpc
            completed_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
        }
    }
    catch {
        $errorIdentity = Get-FaultSocketError -Exception $_.Exception
        return [ordered]@{
            name = "CLEAN_FIN"; status = "FAILED"; port = $port; read_result = $null
            native_error_code = $errorIdentity.native_error_code
            socket_error_code = $errorIdentity.socket_error_code
            exception_type = $errorIdentity.exception_type
            client_port = $clientPort; process_id = [uint32]$PID; address_family = "InterNetwork"
            started_utc = $startedUtc.ToString("o"); completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
            started_qpc_timestamp = $startedQpc; completed_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
        }
    }
    finally {
        if ($null -ne $server) { $server.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
        $listener.Stop()
    }
}

function Invoke-AbortiveResetFault {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $server = $null
    $client = $null
    $port = [uint16]0
    $clientPort = [uint16]0
    $clientBytesSent = [int]0
    $serverUnreadBytes = [int]0
    $lingerEnabled = $false
    $lingerTimeSeconds = [int]-1
    $startedUtc = [DateTimeOffset]::UtcNow
    $startedQpc = [int64][Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $listener.Start()
        $port = [uint16]([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $accept = $listener.AcceptSocketAsync()
        $client = [Net.Sockets.Socket]::new(
            [Net.Sockets.AddressFamily]::InterNetwork,
            [Net.Sockets.SocketType]::Stream,
            [Net.Sockets.ProtocolType]::Tcp)
        $client.ReceiveTimeout = 2000
        $client.Connect([Net.IPAddress]::Loopback, $port)
        $clientPort = [uint16]([Net.IPEndPoint]$client.LocalEndPoint).Port
        $server = $accept.GetAwaiter().GetResult()
        $clientBytesSent = [int]$client.Send([byte[]](0xA5))
        $unreadDeadline = [int64][Diagnostics.Stopwatch]::GetTimestamp() +
            ([int64][Diagnostics.Stopwatch]::Frequency * 2)
        while ($server.Available -lt 1 -and
            [int64][Diagnostics.Stopwatch]::GetTimestamp() -lt $unreadDeadline) {
            Start-Sleep -Milliseconds 10
        }
        $serverUnreadBytes = [int]$server.Available
        if ($clientBytesSent -ne 1 -or $serverUnreadBytes -lt 1) {
            throw "The abortive-close precondition was not established."
        }
        $server.LingerState = [Net.Sockets.LingerOption]::new($true, 0)
        $appliedLinger = $server.LingerState
        $lingerEnabled = [bool]$appliedLinger.Enabled
        $lingerTimeSeconds = [int]$appliedLinger.LingerTime
        if (-not $lingerEnabled -or $lingerTimeSeconds -ne 0) {
            throw "Winsock did not retain the requested abortive linger state."
        }
        $server.Close()
        $server = $null
        Start-Sleep -Milliseconds 100
        $buffer = [byte[]]::new(1)
        $value = $client.Receive($buffer)
        return [ordered]@{
            name = "ABORTIVE_RST"; status = "FAILED"; port = $port; read_result = [int]$value
            native_error_code = $null; socket_error_code = $null; exception_type = $null
            client_port = $clientPort
            process_id = [uint32]$PID
            address_family = "InterNetwork"
            client_bytes_sent = $clientBytesSent
            server_unread_bytes_before_abort = $serverUnreadBytes
            linger_enabled = $lingerEnabled
            linger_time_s = $lingerTimeSeconds
            started_utc = $startedUtc.ToString("o")
            completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
            started_qpc_timestamp = $startedQpc
            completed_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
        }
    }
    catch {
        $errorIdentity = Get-FaultSocketError -Exception $_.Exception
        return [ordered]@{
            name = "ABORTIVE_RST"
            status = if ($errorIdentity.socket_error_code -ceq "ConnectionReset") { "PASS" } else { "FAILED" }
            port = $port
            read_result = $null
            native_error_code = $errorIdentity.native_error_code
            socket_error_code = $errorIdentity.socket_error_code
            exception_type = $errorIdentity.exception_type
            client_port = $clientPort
            process_id = [uint32]$PID
            address_family = "InterNetwork"
            client_bytes_sent = $clientBytesSent
            server_unread_bytes_before_abort = $serverUnreadBytes
            linger_enabled = $lingerEnabled
            linger_time_s = $lingerTimeSeconds
            started_utc = $startedUtc.ToString("o")
            completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
            started_qpc_timestamp = $startedQpc
            completed_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
        }
    }
    finally {
        if ($null -ne $server) { $server.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
        $listener.Stop()
    }
}

function Invoke-SilentReadFault {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $server = $null
    $client = $null
    $port = [uint16]0
    $clientPort = [uint16]0
    $startedUtc = [DateTimeOffset]::UtcNow
    $startedQpc = [int64][Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $listener.Start()
        $port = [uint16]([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $accept = $listener.AcceptTcpClientAsync()
        $client = [Net.Sockets.TcpClient]::new()
        $client.ReceiveTimeout = 500
        $client.Connect([Net.IPAddress]::Loopback, $port)
        $clientPort = [uint16]([Net.IPEndPoint]$client.Client.LocalEndPoint).Port
        $server = $accept.GetAwaiter().GetResult()
        $value = $client.GetStream().ReadByte()
        return [ordered]@{
            name = "SILENT_READ_TIMEOUT"; status = "FAILED"; port = $port; read_result = [int]$value
            native_error_code = $null; socket_error_code = $null; exception_type = $null
            client_port = $clientPort; process_id = [uint32]$PID; address_family = "InterNetwork"
            started_utc = $startedUtc.ToString("o"); completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
            started_qpc_timestamp = $startedQpc; completed_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
        }
    }
    catch {
        $errorIdentity = Get-FaultSocketError -Exception $_.Exception
        return [ordered]@{
            name = "SILENT_READ_TIMEOUT"
            status = if ($errorIdentity.socket_error_code -ceq "TimedOut") { "PASS" } else { "FAILED" }
            port = $port
            read_result = $null
            native_error_code = $errorIdentity.native_error_code
            socket_error_code = $errorIdentity.socket_error_code
            exception_type = $errorIdentity.exception_type
            client_port = $clientPort; process_id = [uint32]$PID; address_family = "InterNetwork"
            started_utc = $startedUtc.ToString("o"); completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
            started_qpc_timestamp = $startedQpc; completed_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
        }
    }
    finally {
        if ($null -ne $server) { $server.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
        $listener.Stop()
    }
}

$started = $false
$faultResults = @()
$dnsAddresses = @()
$startedUtc = [DateTimeOffset]::UtcNow
$startedQpc = [int64][Diagnostics.Stopwatch]::GetTimestamp()
try {
    & $traceScript -Action Start -EvidenceRoot $traceRoot -RunId $runId -MaximumFileMiB 64 -WinsockAfdProfile $WinsockAfdProfile | Out-Host
    $started = $true
    # PktMon reports the ETW session as running before every provider has
    # necessarily emitted its first event. Keep this diagnostic-only warmup
    # explicit; the post-stop correlation gate decides whether it was enough.
    Start-Sleep -Seconds 10
    $dnsAddresses = [string[]]@([Net.Dns]::GetHostAddresses("stream.binance.com") | ForEach-Object { $_.ToString() } | Sort-Object -Unique)
    $faultResults = [object[]]@(
        Invoke-RefusedConnectFault
        Invoke-CleanFinFault
        Invoke-AbortiveResetFault
        Invoke-SilentReadFault
    )
    Start-Sleep -Seconds 2
}
finally {
    if ($started) {
        & $traceScript -Action Stop -EvidenceRoot $traceRoot -RunId $runId -MaximumFileMiB 64 -WinsockAfdProfile $WinsockAfdProfile | Out-Host
    }
}

$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $repo "src"
    $verificationLines = [string[]]@(& $python -m binance_lob.network_trace_verify_cli $traceRoot 2>&1)
    $verificationExitCode = [int]$LASTEXITCODE
}
finally { $env:PYTHONPATH = $previousPythonPath }

$etlPath = Join-Path $traceRoot "network-trace.etl"
$textPath = Join-Path $analysisRoot "network-trace.txt"
$statsLines = [string[]]@(& $pktmon etl2txt $etlPath --stats 2>&1 | ForEach-Object { [string]$_ })
$statsExitCode = [int]$LASTEXITCODE
$conversionLines = [string[]]@(& $pktmon etl2txt $etlPath --out $textPath --timestamp --metadata 2>&1 | ForEach-Object { [string]$_ })
$conversionExitCode = [int]$LASTEXITCODE
if (-not (Test-Path -LiteralPath $textPath -PathType Leaf)) { throw "PktMon did not publish decoded trace text." }
$textItem = Get-Item -LiteralPath $textPath -ErrorAction Stop
if ([uint64]$textItem.Length -eq 0 -or [uint64]$textItem.Length -gt 32MB) {
    throw "Decoded trace text is empty or exceeds its bounded allowance."
}
$allFaultsPassed = -not [bool](@($faultResults | Where-Object { $_.status -cne "PASS" }).Count)
$report = [ordered]@{
    schema = "RawQualificationNetworkTraceFaultSmokeV1"
    run_id = $runId
    status = if ($allFaultsPassed -and $verificationExitCode -eq 0 -and $statsExitCode -eq 0 -and $conversionExitCode -eq 0) { "PASS" } else { "FAILED" }
    started_utc = $startedUtc.ToString("o")
    completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
    started_qpc_timestamp = $startedQpc
    completed_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
    qpc_frequency = [uint64][Diagnostics.Stopwatch]::Frequency
    dns_name = "stream.binance.com"
    dns_addresses = $dnsAddresses
    winsock_afd_profile = $WinsockAfdProfile
    faults = $faultResults
    trace_root = $traceRoot
    trace_verification_exit_code = $verificationExitCode
    trace_verification_output = $verificationLines
    etl_stats_exit_code = $statsExitCode
    etl_stats_output = $statsLines
    etl_conversion_exit_code = $conversionExitCode
    etl_conversion_output = $conversionLines
    decoded_text_file = "network-trace.txt"
    decoded_text_bytes = [uint64]$textItem.Length
    decoded_text_sha256 = Get-RawQualificationSha256File -Path $textPath
    inference_boundary = "This gate proves local fault generation plus trace lifecycle/integrity/decodability; endpoint-specific ETW correlation is a separate extractor gate."
}
$reportPath = Join-Path $analysisRoot "fault-smoke.json"
$null = Write-RawQualificationDurableNewJson -Path $reportPath -Value $report
$report | ConvertTo-Json -Depth 12
Write-Output $runRoot
if ($report.status -cne "PASS") { throw "Network trace fault smoke did not pass every gate; exact evidence is preserved." }
