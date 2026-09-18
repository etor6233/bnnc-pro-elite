[CmdletBinding()]
param(
    [ValidateSet("Production", "SevenDay", "Smoke", "Test")] [string] $Mode = "Production",
    [ValidateRange(1, 604800)] [int] $TotalSeconds = 86400,
    [ValidateRange(1, 86000)] [int] $RotationSeconds = 82800,
    [ValidateRange(1, 3600)] [int] $OverlapSeconds = 900,
    [ValidateRange(1, 3600)] [int] $SegmentSeconds = 900,
    [string] $OutputBase = "artifacts/qualification-24h-raw",
    [string] $ObservabilityOutputBase = "artifacts/qualification-observability",
    [ValidateRange(100, 10000)] [int] $MinimumFreeGiB = 100,
    [ValidateRange(30, 600)] [int] $StartupDeadlineSeconds = 180,
    [ValidateRange(300, 86400)] [int] $PostVerificationDeadlineSeconds = 14400,
    [ValidateRange(60, 43200)] [int] $IndependentVerifierTimeoutSeconds = 7200,
    [ValidateRange(5, 60)] [int] $WitnessIntervalSeconds = 10,
    [switch] $InjectKernelObserverAbortAfterRawStartup,
    [switch] $InjectWitnessObserverAbortAfterRawStartup,
    [switch] $ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
Set-Location -LiteralPath $repo
. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")
Initialize-RawQualificationNative
$supplied = @{} + $PSBoundParameters
$runRoot = $null
$terminalPath = $null
$observedMutex = $null
$observedMutexOwned = $false

trap {
    $failureText = [string]$_.Exception.Message
    if ($null -ne $runRoot -and (Test-Path -LiteralPath $runRoot -PathType Container)) {
        $failurePath = Join-Path $runRoot "observed-wrapper-failure.json"
        if (-not (Test-Path -LiteralPath $failurePath)) {
            try {
                $null = Write-RawQualificationDurableNewJson -Path $failurePath -Value ([ordered]@{
                    schema = "ObservedRawQualificationWrapperFailureV1"
                    status = "FAILED"
                    observed_utc = [DateTimeOffset]::UtcNow.ToString("o")
                    error = $failureText
                    terminal_published = [bool]($null -ne $terminalPath -and (Test-Path -LiteralPath $terminalPath -PathType Leaf))
                    inference_boundary = "WRAPPER_FAILURE_IS_NOT_A_CAUSAL_NETWORK_CLASSIFICATION"
                })
            } catch {}
        }
    }
    if ($observedMutexOwned -and $null -ne $observedMutex) {
        try { $observedMutex.ReleaseMutex(); $observedMutexOwned = $false } catch {}
    }
    if ($null -ne $observedMutex) { try { $observedMutex.Dispose() } catch {} }
    [Console]::Error.WriteLine($failureText)
    exit 1
}

if ($Mode -ceq "SevenDay") {
    if (-not $supplied.ContainsKey("TotalSeconds")) { $TotalSeconds = 604800 }
    if (-not $supplied.ContainsKey("RotationSeconds")) { $RotationSeconds = 82800 }
    if (-not $supplied.ContainsKey("OverlapSeconds")) { $OverlapSeconds = 900 }
    if (-not $supplied.ContainsKey("SegmentSeconds")) { $SegmentSeconds = 900 }
    if (-not $supplied.ContainsKey("OutputBase")) { $OutputBase = "artifacts/qualification-7d-raw" }
}
if ($Mode -in @("Production", "SevenDay")) {
    if (-not $supplied.ContainsKey("PostVerificationDeadlineSeconds")) { $PostVerificationDeadlineSeconds = 86400 }
    if (-not $supplied.ContainsKey("IndependentVerifierTimeoutSeconds")) { $IndependentVerifierTimeoutSeconds = 43200 }
}
if (($InjectKernelObserverAbortAfterRawStartup -or $InjectWitnessObserverAbortAfterRawStartup) -and
    $Mode -cne "Test") {
    throw "Observer-abort injection is authorized only in explicit Test mode."
}
if ($InjectKernelObserverAbortAfterRawStartup -and $InjectWitnessObserverAbortAfterRawStartup) {
    throw "Inject exactly one observer failure per test run."
}

$launcher = Join-Path $PSScriptRoot "run_24h_raw_qualification.ps1"
$witnessScript = Join-Path $PSScriptRoot "RawQualification.NetworkWitness.ps1"
$systemEvidenceScript = Join-Path $PSScriptRoot "RawQualification.SystemEvidence.ps1"
$helperScript = Join-Path $PSScriptRoot "RawQualification.Windows.ps1"
$wrapperScript = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$controller = Join-Path $repo "target\release\kernel_network_trace.exe"
$transportDiagnose = Join-Path $repo "target\release\transport_diagnose.exe"
$python = Join-Path $repo ".venv\Scripts\python.exe"
$observerPythonSource = Join-Path $repo "src"
$powershell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$tracerpt = Join-Path $env:SystemRoot "System32\tracerpt.exe"
$logman = Join-Path $env:SystemRoot "System32\logman.exe"
$cargoCommand = Get-Command cargo.exe -ErrorAction SilentlyContinue
$cargo = if ($null -ne $cargoCommand) {
    [string]$cargoCommand.Source
} else {
    Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
}

foreach ($path in @($launcher, $witnessScript, $systemEvidenceScript, $helperScript, $wrapperScript, $python, $powershell, $tracerpt, $logman, $cargo)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required observed-qualification input is absent: $path" }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Join-ExactArguments {
    param([Parameter(Mandatory = $true)] [string[]] $Arguments)
    return [string]::Join(" ", [string[]]@($Arguments | ForEach-Object {
        [RawQualificationNative]::QuoteExactArgument([string]$_)
    }))
}

function Convert-WallNsToUtc {
    param([Parameter(Mandatory = $true)] [uint64] $WallNs)
    $milliseconds = [int64][Math]::Floor([decimal]$WallNs / 1000000)
    return [DateTimeOffset]::FromUnixTimeMilliseconds($milliseconds).ToUniversalTime()
}

function Get-ObservedArtifactInventory {
    param([Parameter(Mandatory = $true)] [string] $Root)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $byPath = @{}
    $paths = [Collections.Generic.List[string]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $rootFull -Recurse -File -ErrorAction Stop)) {
        $full = [IO.Path]::GetFullPath($file.FullName)
        $relative = $full.Substring($rootFull.Length + 1).Replace('\', '/')
        if ($relative -ceq "observed-qualification-terminal.json") { continue }
        $paths.Add($relative)
        $byPath[$relative] = [ordered]@{
            path = $relative
            bytes = [uint64]$file.Length
            sha256 = Get-RawQualificationSha256File -Path $full
        }
    }
    $orderedPaths = $paths.ToArray()
    [Array]::Sort($orderedPaths, [StringComparer]::Ordinal)
    return [object[]]@($orderedPaths | ForEach-Object { $byPath[$_] })
}

function Get-SealedImplementationInventory {
    param([Parameter(Mandatory = $true)] [string] $Root)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $byPath = @{}
    $paths = [Collections.Generic.List[string]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $rootFull -Recurse -File -ErrorAction Stop)) {
        $full = [IO.Path]::GetFullPath($file.FullName)
        $relative = $full.Substring($rootFull.Length + 1).Replace('\', '/')
        $paths.Add($relative)
        $byPath[$relative] = [ordered]@{
            path = $relative
            bytes = [uint64]$file.Length
            sha256 = Get-RawQualificationSha256File -Path $full
        }
    }
    $orderedPaths = $paths.ToArray()
    [Array]::Sort($orderedPaths, [StringComparer]::Ordinal)
    return [object[]]@($orderedPaths | ForEach-Object { $byPath[$_] })
}

function Get-ExternalRuntimeInventory {
    return [object[]]@(
        [ordered]@{ name = "LOGMAN"; path = $logman; bytes = [uint64](Get-Item -LiteralPath $logman).Length; sha256 = Get-RawQualificationSha256File -Path $logman },
        [ordered]@{ name = "POWERSHELL"; path = $powershell; bytes = [uint64](Get-Item -LiteralPath $powershell).Length; sha256 = Get-RawQualificationSha256File -Path $powershell },
        [ordered]@{ name = "PYTHON"; path = $python; bytes = [uint64](Get-Item -LiteralPath $python).Length; sha256 = Get-RawQualificationSha256File -Path $python },
        [ordered]@{ name = "TRACERPT"; path = $tracerpt; bytes = [uint64](Get-Item -LiteralPath $tracerpt).Length; sha256 = Get-RawQualificationSha256File -Path $tracerpt }
    )
}

function Assert-ImplementationLockUnchanged {
    param(
        [Parameter(Mandatory = $true)] [object] $Lock,
        [Parameter(Mandatory = $true)] [string] $RuntimeRoot
    )
    if ((Get-RawQualificationSha256File -Path $wrapperScript) -cne [string]$Lock.wrapper_sha256 -or
        [uint64](Get-Item -LiteralPath $wrapperScript).Length -ne [uint64]$Lock.wrapper_bytes) {
        throw "Observed wrapper changed after its implementation lock was published."
    }
    $expectedFiles = $Lock.files | ConvertTo-Json -Depth 8 -Compress
    $observedFiles = (Get-SealedImplementationInventory -Root $RuntimeRoot) | ConvertTo-Json -Depth 8 -Compress
    if ($expectedFiles -cne $observedFiles) {
        throw "Sealed observer runtime changed after its implementation lock was published."
    }
    $expectedExternal = $Lock.external_runtime | ConvertTo-Json -Depth 8 -Compress
    $observedExternal = (Get-ExternalRuntimeInventory) | ConvertTo-Json -Depth 8 -Compress
    if ($expectedExternal -cne $observedExternal) {
        throw "An external observer runtime changed during the qualification."
    }
}

function Get-ProcessInventory {
    param(
        [Parameter(Mandatory = $true)] [string] $RawRoot,
        [Parameter(Mandatory = $true)] [DateTimeOffset] $ObservationEnd
    )
    $rows = [Collections.Generic.List[object]]::new()
    $startup = Get-Content -LiteralPath (Join-Path $RawRoot "launcher-startup.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    $rows.Add([ordered]@{
        role = "LAUNCHER"; symbol = $null; pid = [uint32]$startup.launcher_pid
        interval_start_utc = ([DateTimeOffset]::Parse([string]$startup.launcher_creation_time_utc)).ToUniversalTime().ToString("o")
        interval_end_utc = $ObservationEnd.ToUniversalTime().ToString("o")
    })
    $processControlPath = Join-Path $RawRoot "processes.json"
    if (Test-Path -LiteralPath $processControlPath -PathType Leaf) {
        $control = Get-Content -LiteralPath $processControlPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($null -ne $control.watchdog) {
            $rows.Add([ordered]@{
                role = "WATCHDOG"; symbol = $null; pid = [uint32]$control.watchdog.pid
                interval_start_utc = ([DateTimeOffset]::Parse([string]$control.watchdog.creation_time_utc)).ToUniversalTime().ToString("o")
                interval_end_utc = $ObservationEnd.ToUniversalTime().ToString("o")
            })
        }
        foreach ($process in @($control.processes)) {
            $rows.Add([ordered]@{
                role = "CAMPAIGN"; symbol = [string]$process.symbol; pid = [uint32]$process.pid
                interval_start_utc = ([DateTimeOffset]::Parse([string]$process.creation_time_utc)).ToUniversalTime().ToString("o")
                interval_end_utc = $ObservationEnd.ToUniversalTime().ToString("o")
            })
        }
    }
    foreach ($journalPath in @(Get-ChildItem -LiteralPath $RawRoot -Recurse -Filter "campaign-events.jsonl" -File -ErrorAction SilentlyContinue)) {
        $startedBySession = @{}
        foreach ($line in [IO.File]::ReadLines($journalPath.FullName)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $envelope = $line | ConvertFrom-Json -ErrorAction Stop
            $payload = $envelope.body.payload
            if ([string]$payload.event -ceq "PROCESS_STARTED") {
                $startedBySession[[string]$payload.session_id] = [ordered]@{
                    role = "COLLECTOR"; symbol = [string]$payload.symbol; pid = [uint32]$payload.process_id
                    interval_start_utc = (Convert-WallNsToUtc -WallNs ([uint64]$envelope.body.wall_ns)).ToString("o")
                    interval_end_utc = $ObservationEnd.ToUniversalTime().ToString("o")
                }
            }
            elseif ([string]$payload.event -ceq "PROCESS_TERMINAL") {
                $sessionId = [string]$payload.session_id
                if ($startedBySession.ContainsKey($sessionId)) {
                    $startedBySession[$sessionId].interval_end_utc = (Convert-WallNsToUtc -WallNs ([uint64]$envelope.body.wall_ns)).ToString("o")
                }
            }
        }
        foreach ($key in @($startedBySession.Keys | Sort-Object)) { $rows.Add($startedBySession[$key]) }
    }
    return [object[]]@($rows | Sort-Object role, symbol, pid, interval_start_utc)
}

function Wait-JsonFile {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [Diagnostics.Process] $Process,
        [ValidateRange(1, 300)] [int] $DeadlineSeconds = 30
    )
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt $DeadlineSeconds) {
        $Process.Refresh()
        if ($Process.HasExited) { throw "Process $($Process.Id) exited before publishing $Path." }
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try { return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop } catch {}
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for $Path."
}

function Request-ObservationStop {
    param([string] $EtwStop, [string] $WitnessStop)
    foreach ($path in @($EtwStop, $WitnessStop)) {
        if (-not (Test-Path -LiteralPath $path)) { $null = New-Item -ItemType File -Path $path -ErrorAction Stop }
    }
}

function Invoke-JsonVerifier {
    param([string] $Module, [string] $InputRoot, [string] $OutputPath)
    $stderr = $OutputPath + ".stderr"
    $verifierArguments = [string[]]@(
        "-I", "-P", "-S", "-B", "-c",
        "import runpy,sys;sys.dont_write_bytecode=True;sys.path.insert(0,sys.argv.pop(1));runpy.run_module(sys.argv.pop(1),run_name='__main__')",
        $observerPythonSource, $Module, $InputRoot
    )
    $process = Start-Process -FilePath $python -ArgumentList (Join-ExactArguments $verifierArguments) `
        -WorkingDirectory $repo -NoNewWindow -Wait -PassThru -RedirectStandardOutput $OutputPath -RedirectStandardError $stderr
    if ([int]$process.ExitCode -ne 0 -or [uint64](Get-Item -LiteralPath $stderr).Length -ne 0) {
        throw "Independent verifier $Module rejected $InputRoot."
    }
    return Get-Content -LiteralPath $OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
}

function Invoke-NetworkIncidentBundle {
    param(
        [Parameter(Mandatory = $true)] [string[]] $GenerationRoots,
        [Parameter(Mandatory = $true)] [uint64] $IncidentWallNs,
        [Parameter(Mandatory = $true)] [string] $WitnessRoot,
        [Parameter(Mandatory = $true)] [string] $OutputPath
    )
    $stderr = $OutputPath + ".stderr"
    $stdout = $OutputPath + ".stdout"
    $arguments = [Collections.Generic.List[string]]::new()
    $arguments.AddRange([string[]]@(
        "-I", "-P", "-S", "-B", "-c",
        "import runpy,sys;sys.dont_write_bytecode=True;sys.path.insert(0,sys.argv.pop(1));runpy.run_module(sys.argv.pop(1),run_name='__main__')",
        $observerPythonSource, "binance_lob.network_incident_cli"
    ))
    foreach ($generation in $GenerationRoots) { $arguments.Add("--generation"); $arguments.Add($generation) }
    $arguments.Add("--transport-diagnose"); $arguments.Add($transportDiagnose)
    $arguments.Add("--incident-wall-ns"); $arguments.Add([string]$IncidentWallNs)
    $arguments.Add("--witness-root"); $arguments.Add($WitnessRoot)
    $arguments.Add("--output"); $arguments.Add($OutputPath)
    $process = Start-Process -FilePath $python -ArgumentList (Join-ExactArguments ([string[]]$arguments)) `
        -WorkingDirectory $repo -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $process.Refresh()
    if ([int]$process.ExitCode -ne 0 -or [uint64](Get-Item -LiteralPath $stderr).Length -ne 0 -or
        -not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) { return $null }
    return Get-Content -LiteralPath $OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
}

$rawOutputBase = [IO.Path]::GetFullPath((Join-Path $repo $OutputBase))
$observabilityBase = [IO.Path]::GetFullPath((Join-Path $repo $ObservabilityOutputBase))
$repoPrefix = $repo.TrimEnd('\') + '\'
if ([IO.Path]::IsPathRooted($OutputBase) -or [IO.Path]::IsPathRooted($ObservabilityOutputBase) -or
    -not $rawOutputBase.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not $observabilityBase.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Raw and observability output bases must be relative paths contained by the repository."
}
$innerArguments = [Collections.Generic.List[string]]::new()
$innerArguments.AddRange([string[]]@(
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $launcher,
    "-Mode", $Mode, "-TotalSeconds", [string]$TotalSeconds,
    "-RotationSeconds", [string]$RotationSeconds, "-OverlapSeconds", [string]$OverlapSeconds,
    "-SegmentSeconds", [string]$SegmentSeconds, "-OutputBase", $OutputBase,
    "-MinimumFreeGiB", [string]$MinimumFreeGiB, "-StartupDeadlineSeconds", [string]$StartupDeadlineSeconds,
    "-PostVerificationDeadlineSeconds", [string]$PostVerificationDeadlineSeconds,
    "-IndependentVerifierTimeoutSeconds", [string]$IndependentVerifierTimeoutSeconds
))

$buildArguments = [string[]]@(
    "build", "--release", "--manifest-path", (Join-Path $repo "rust\lob-replay\Cargo.toml"),
    "--bin", "kernel_network_trace", "--bin", "transport_diagnose"
)
$build = Start-Process -FilePath $cargo -ArgumentList (Join-ExactArguments $buildArguments) `
    -WorkingDirectory $repo -NoNewWindow -Wait -PassThru
if ([int]$build.ExitCode -ne 0) { throw "Observed-qualification Rust release build failed." }
foreach ($path in @($controller, $transportDiagnose)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Release artifact is absent after build: $path" }
}
$controllerValidation = & $controller validate | ConvertFrom-Json -ErrorAction Stop
if ($controllerValidation.status -cne "PASS") { throw "Kernel-Network controller ABI validation failed." }

if ($ValidateOnly) {
    $validationArguments = [string[]]@($innerArguments) + "-ValidateOnly"
    $innerValidation = & $powershell @validationArguments
    if ($LASTEXITCODE -ne 0) { throw "Inner raw qualification preflight failed." }
    [ordered]@{
        schema = "ObservedRawQualificationPreflightV1"
        status = "PASS"
        mode = $Mode
        administrator = Test-Administrator
        parameters = [ordered]@{
            total_s = $TotalSeconds; rotation_s = $RotationSeconds; overlap_s = $OverlapSeconds; segment_s = $SegmentSeconds
            witness_interval_s = $WitnessIntervalSeconds
        }
        controller = $controller
        controller_sha256 = Get-RawQualificationSha256File -Path $controller
        controller_validation = $controllerValidation
        launcher_sha256 = Get-RawQualificationSha256File -Path $launcher
        witness_script_sha256 = Get-RawQualificationSha256File -Path $witnessScript
        system_evidence_script_sha256 = Get-RawQualificationSha256File -Path $systemEvidenceScript
        inner_preflight = ($innerValidation -join "`n" | ConvertFrom-Json -ErrorAction Stop)
    } | ConvertTo-Json -Depth 100
    exit 0
}

if (-not (Test-Administrator)) { throw "Observed raw qualification requires an elevated PowerShell for Kernel-Network ETW." }
$mutexSeed = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($repo.ToLowerInvariant()))
$createdObservedMutex = $false
$observedMutex = [Threading.Mutex]::new($true, ("Local\BinanceObservedQualification-" + $mutexSeed.Substring(0, 24)), [ref]$createdObservedMutex)
if (-not $createdObservedMutex) { throw "Another observed raw qualification owns the repository observer mutex." }
$observedMutexOwned = $true
$null = New-Item -ItemType Directory -Path $observabilityBase -Force -ErrorAction Stop
$null = New-Item -ItemType Directory -Path $rawOutputBase -Force -ErrorAction Stop
$beforeRoots = [string[]]@(
    Get-ChildItem -LiteralPath $rawOutputBase -Directory -ErrorAction Stop |
        ForEach-Object { [IO.Path]::GetFullPath($_.FullName) }
)
$runId = "observed-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$runRoot = Join-Path $observabilityBase $runId
$traceRoot = Join-Path $runRoot "kernel-network"
$witnessRoot = Join-Path $runRoot "network-witness"
$systemRoot = Join-Path $runRoot "system-evidence"
$null = New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop
$null = New-Item -ItemType Directory -Path $traceRoot -ErrorAction Stop

# The observer runs only from this create-once snapshot. Repository edits made
# after READY therefore cannot change a long-running qualification, and the
# terminal verifier can recompute the complete implementation identity.
$sealedObserverRoot = Join-Path $runRoot "sealed-observer-runtime"
$sealedScripts = Join-Path $sealedObserverRoot "scripts"
$sealedPythonPackage = Join-Path $sealedObserverRoot "src\binance_lob"
$sealedBin = Join-Path $sealedObserverRoot "bin"
foreach ($directory in @($sealedObserverRoot, $sealedScripts, $sealedPythonPackage, $sealedBin)) {
    $null = New-Item -ItemType Directory -Path $directory -ErrorAction Stop
}
foreach ($source in @($helperScript, $witnessScript, $systemEvidenceScript)) {
    Copy-Item -LiteralPath $source -Destination (Join-Path $sealedScripts ([IO.Path]::GetFileName($source))) -ErrorAction Stop
}
foreach ($source in @(Get-ChildItem -LiteralPath (Join-Path $repo "src\binance_lob") -Filter "*.py" -File -ErrorAction Stop | Sort-Object Name)) {
    Copy-Item -LiteralPath $source.FullName -Destination (Join-Path $sealedPythonPackage $source.Name) -ErrorAction Stop
}
Copy-Item -LiteralPath $controller -Destination (Join-Path $sealedBin "kernel_network_trace.exe") -ErrorAction Stop
Copy-Item -LiteralPath $transportDiagnose -Destination (Join-Path $sealedBin "transport_diagnose.exe") -ErrorAction Stop
$controller = Join-Path $sealedBin "kernel_network_trace.exe"
$transportDiagnose = Join-Path $sealedBin "transport_diagnose.exe"
$witnessScript = Join-Path $sealedScripts "RawQualification.NetworkWitness.ps1"
$systemEvidenceScript = Join-Path $sealedScripts "RawQualification.SystemEvidence.ps1"
$observerPythonSource = Join-Path $sealedObserverRoot "src"
$implementationLockPath = Join-Path $runRoot "implementation-lock.json"
$implementationLock = [ordered]@{
    schema = "ObservedImplementationLockV1"
    status = "LOCKED"
    run_id = $runId
    created_utc = [DateTimeOffset]::UtcNow.ToString("o")
    wrapper_path = $wrapperScript
    wrapper_bytes = [uint64](Get-Item -LiteralPath $wrapperScript).Length
    wrapper_sha256 = Get-RawQualificationSha256File -Path $wrapperScript
    sealed_runtime = "sealed-observer-runtime"
    files = Get-SealedImplementationInventory -Root $sealedObserverRoot
    external_runtime = Get-ExternalRuntimeInventory
}
$null = Write-RawQualificationDurableNewJson -Path $implementationLockPath -Value $implementationLock

$startedUtc = [DateTimeOffset]::UtcNow
$sessionName = "BinanceProduction_" + $runId.Substring($runId.Length - 12)
$etlPath = Join-Path $traceRoot "kernel-network.etl"
$etwStop = Join-Path $traceRoot "stop.request"
$etwStdout = Join-Path $traceRoot "controller.stdout.jsonl"
$etwStderr = Join-Path $traceRoot "controller.stderr.txt"
$witnessStop = Join-Path $witnessRoot "stop.request"
$witnessStdout = Join-Path $runRoot "network-witness.stdout.json"
$witnessStderr = Join-Path $runRoot "network-witness.stderr.txt"
$innerStdout = Join-Path $runRoot "qualification.stdout.log"
$innerStderr = Join-Path $runRoot "qualification.stderr.log"
$maximumEtwMiB = 256
$observerDeadline = [Math]::Min(691200, $TotalSeconds + 1800)
$controllerProcess = $null
$witnessProcess = $null
$innerProcess = $null
$rawRoot = $null
$observationStopRequested = $false
$observerFailure = $null
$observationEndUtc = $null
$emergencyCleanup = $false
$observerInjectionFired = $false

try {
    $controllerArguments = [string[]]@(
        $sessionName, $etlPath, $etwStop, [string]$maximumEtwMiB, [string]$observerDeadline
    )
    $controllerProcess = Start-Process -FilePath $controller -ArgumentList (Join-ExactArguments $controllerArguments) `
        -WorkingDirectory $repo -NoNewWindow -PassThru -RedirectStandardOutput $etwStdout -RedirectStandardError $etwStderr
    $readyTimer = [Diagnostics.Stopwatch]::StartNew()
    $ready = $null
    while ($readyTimer.Elapsed.TotalSeconds -lt 30 -and $null -eq $ready) {
        $controllerProcess.Refresh()
        if ($controllerProcess.HasExited) { throw "Kernel-Network controller exited before READY." }
        if (Test-Path -LiteralPath $etwStdout -PathType Leaf) {
            $lines = @(Get-Content -LiteralPath $etwStdout -ErrorAction SilentlyContinue)
            if ($lines.Count -ge 1) {
                try { $ready = $lines[0] | ConvertFrom-Json -ErrorAction Stop } catch {}
            }
        }
        if ($null -eq $ready) { Start-Sleep -Milliseconds 100 }
    }
    if ($null -eq $ready -or $ready.schema -cne "KernelNetworkTraceReadyV1" -or $ready.status -cne "READY" -or
        $ready.session_name -cne $sessionName) { throw "Kernel-Network controller did not publish exact READY evidence." }

    $witnessDuration = [Math]::Min(691200, $TotalSeconds + 1800)
    $witnessArguments = [string[]]@(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $witnessScript,
        "-EvidenceRoot", $witnessRoot, "-ObservationId", $runId,
        "-DurationSeconds", [string]$witnessDuration, "-IntervalSeconds", [string]$WitnessIntervalSeconds,
        "-ProbeTimeoutMilliseconds", "2000", "-StopFile", $witnessStop
    )
    $witnessProcess = Start-Process -FilePath $powershell -ArgumentList (Join-ExactArguments $witnessArguments) `
        -WorkingDirectory $repo -NoNewWindow -PassThru -RedirectStandardOutput $witnessStdout -RedirectStandardError $witnessStderr
    $witnessStartup = Wait-JsonFile -Path (Join-Path $witnessRoot "network-witness-startup.json") -Process $witnessProcess -DeadlineSeconds 30
    if ($witnessStartup.schema -cne "RawQualificationNetworkWitnessStartupV2" -or
        [uint32]$witnessStartup.process_id -ne [uint32]$witnessProcess.Id) {
        throw "Network witness READY identity is invalid."
    }

    $innerProcess = Start-Process -FilePath $powershell -ArgumentList (Join-ExactArguments ([string[]]$innerArguments)) `
        -WorkingDirectory $repo -NoNewWindow -PassThru -RedirectStandardOutput $innerStdout -RedirectStandardError $innerStderr
    $outerDeadline = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $innerProcess.Refresh(); $controllerProcess.Refresh(); $witnessProcess.Refresh()
        if ($null -eq $rawRoot) {
            $newRoots = [string[]]@(
                Get-ChildItem -LiteralPath $rawOutputBase -Directory -ErrorAction Stop |
                    ForEach-Object { [IO.Path]::GetFullPath($_.FullName) } |
                    Where-Object { $_ -notin $beforeRoots }
            )
            if ($newRoots.Count -gt 1) { throw "Inner launcher created more than one raw qualification root." }
            if ($newRoots.Count -eq 1) { $rawRoot = [IO.Path]::GetFullPath($newRoots[0]) }
        }
        if (-not $observationStopRequested -and $null -ne $rawRoot) {
            $eventsPath = Join-Path $rawRoot "launcher-events.jsonl"
            if ((Test-Path -LiteralPath $eventsPath -PathType Leaf) -and
                (Select-String -LiteralPath $eventsPath -SimpleMatch '"event":"INDEPENDENT_VERIFICATION_STAGE_STARTED"' -Quiet)) {
                Request-ObservationStop -EtwStop $etwStop -WitnessStop $witnessStop
                $observationStopRequested = $true
                $observationEndUtc = [DateTimeOffset]::UtcNow
            }
        }
        if (-not $observerInjectionFired -and $null -ne $rawRoot -and
            (Test-Path -LiteralPath (Join-Path $rawRoot "processes.json") -PathType Leaf)) {
            if ($InjectKernelObserverAbortAfterRawStartup) {
                Stop-Process -Id $controllerProcess.Id -Force -ErrorAction Stop
                $controllerProcess.WaitForExit()
                $observerInjectionFired = $true
            }
            elseif ($InjectWitnessObserverAbortAfterRawStartup) {
                Stop-Process -Id $witnessProcess.Id -Force -ErrorAction Stop
                $witnessProcess.WaitForExit()
                $observerInjectionFired = $true
            }
        }
        if (-not $observationStopRequested -and ($controllerProcess.HasExited -or $witnessProcess.HasExited)) {
            $observerFailure = if ($controllerProcess.HasExited) { "KERNEL_NETWORK_CONTROLLER_EXITED_BEFORE_STOP" } else { "NETWORK_WITNESS_EXITED_BEFORE_STOP" }
            if (-not $innerProcess.HasExited) { Stop-Process -Id $innerProcess.Id -Force -ErrorAction Stop; $innerProcess.WaitForExit() }
            break
        }
        if ($innerProcess.HasExited) { break }
        if ($outerDeadline.Elapsed.TotalSeconds -gt ($TotalSeconds + $PostVerificationDeadlineSeconds + 3600)) {
            $observerFailure = "OBSERVED_QUALIFICATION_OUTER_DEADLINE_EXCEEDED"
            Stop-Process -Id $innerProcess.Id -Force -ErrorAction Stop; $innerProcess.WaitForExit()
            break
        }
        Start-Sleep -Seconds 1
    }
}
finally {
    if (-not $observationStopRequested) {
        try { Request-ObservationStop -EtwStop $etwStop -WitnessStop $witnessStop; $observationStopRequested = $true } catch {}
    }
    if ($null -eq $observationEndUtc) { $observationEndUtc = [DateTimeOffset]::UtcNow }
    if ($null -ne $controllerProcess) {
        $controllerProcess.Refresh()
        if (-not $controllerProcess.HasExited -and -not $controllerProcess.WaitForExit(60000)) { $emergencyCleanup = $true }
    }
    $queryOutput = [string[]]@(& $logman query -ets $sessionName 2>&1 | ForEach-Object { [string]$_ })
    $queryExitCode = [int]$LASTEXITCODE
    if ($queryExitCode -eq 0) {
        $emergencyCleanup = $true
        $null = & $logman stop -ets $sessionName 2>&1
    }
    if ($null -ne $controllerProcess) {
        $controllerProcess.Refresh()
        if (-not $controllerProcess.HasExited) { Stop-Process -Id $controllerProcess.Id -Force -ErrorAction SilentlyContinue; $controllerProcess.WaitForExit() }
    }
    if ($null -ne $witnessProcess) {
        $witnessProcess.Refresh()
        if (-not $witnessProcess.HasExited -and -not $witnessProcess.WaitForExit(60000)) {
            $observerFailure = if ($null -eq $observerFailure) { "NETWORK_WITNESS_FAILED_TO_SEAL" } else { $observerFailure }
            Stop-Process -Id $witnessProcess.Id -Force -ErrorAction SilentlyContinue; $witnessProcess.WaitForExit()
        }
    }
}

if ($null -eq $rawRoot) {
    $newRoots = [string[]]@(
        Get-ChildItem -LiteralPath $rawOutputBase -Directory -ErrorAction Stop |
            ForEach-Object { [IO.Path]::GetFullPath($_.FullName) } |
            Where-Object { $_ -notin $beforeRoots }
    )
    if ($newRoots.Count -eq 1) { $rawRoot = [IO.Path]::GetFullPath($newRoots[0]) }
}
if ($emergencyCleanup) { throw "Observed qualification required emergency ETW cleanup; evidence is not promotable. Root: $runRoot" }
if ($null -ne $observerFailure) {
    throw "Observed qualification observer failed before requested stop: $observerFailure. Root: $runRoot"
}
if ($null -eq $controllerProcess -or [int]$controllerProcess.ExitCode -ne 0 -or
    [uint64](Get-Item -LiteralPath $etwStderr -ErrorAction Stop).Length -ne 0) {
    throw "Kernel-Network controller did not seal cleanly. Root: $runRoot"
}
if ($null -eq $witnessProcess -or [int]$witnessProcess.ExitCode -ne 0 -or
    [uint64](Get-Item -LiteralPath $witnessStderr -ErrorAction Stop).Length -ne 0) {
    throw "Network witness did not seal cleanly. Root: $runRoot"
}

$decodedPath = Join-Path $traceRoot "kernel-network.xml"
$decodeOutput = [string[]]@(& $tracerpt $etlPath -o $decodedPath -of XML -lr -y 2>&1 | ForEach-Object { [string]$_ })
$decodeExitCode = [int]$LASTEXITCODE
if ($decodeExitCode -ne 0 -or -not (Test-Path -LiteralPath $decodedPath -PathType Leaf)) {
    throw "tracerpt could not decode production Kernel-Network evidence. Root: $runRoot"
}
$postQueryOutput = [string[]]@(& $logman query -ets $sessionName 2>&1 | ForEach-Object { [string]$_ })
$postQueryExitCode = [int]$LASTEXITCODE
if ($postQueryExitCode -eq 0) { throw "Production Kernel-Network session remained orphaned. Root: $runRoot" }

$processInventory = if ($null -ne $rawRoot -and (Test-Path -LiteralPath (Join-Path $rawRoot "launcher-startup.json"))) {
    Get-ProcessInventory -RawRoot $rawRoot -ObservationEnd $observationEndUtc
} else {
    [object[]]@([ordered]@{
        role = "LAUNCHER"; symbol = $null; pid = if ($null -ne $innerProcess) { [uint32]$innerProcess.Id } else { [uint32]$PID }
        interval_start_utc = $startedUtc.ToString("o"); interval_end_utc = $observationEndUtc.ToString("o")
    })
}
$controllerRecords = [object[]]@(Get-Content -LiteralPath $etwStdout | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
$etlItem = Get-Item -LiteralPath $etlPath -ErrorAction Stop
$xmlItem = Get-Item -LiteralPath $decodedPath -ErrorAction Stop
$captureReport = [ordered]@{
    schema = "KernelNetworkProductionCaptureV1"; run_id = $runId; status = "CANDIDATE"
    started_utc = $startedUtc.ToString("o"); completed_utc = $observationEndUtc.ToString("o")
    controller_executable = $controller; controller_sha256 = Get-RawQualificationSha256File -Path $controller
    controller_pid = [uint32]$controllerProcess.Id; session_name = $sessionName
    controller_exit_code = [int]$controllerProcess.ExitCode; controller_records = $controllerRecords
    controller_stderr_file = "controller.stderr.txt"; controller_stderr_bytes = [uint64](Get-Item $etwStderr).Length
    controller_stderr_sha256 = Get-RawQualificationSha256File -Path $etwStderr
    maximum_file_mib = [uint32]$maximumEtwMiB; deadline_s = [uint64]$observerDeadline
    etl_file = "kernel-network.etl"; etl_bytes = [uint64]$etlItem.Length; etl_sha256 = Get-RawQualificationSha256File -Path $etlPath
    decoded_file = "kernel-network.xml"; decoded_bytes = [uint64]$xmlItem.Length; decoded_sha256 = Get-RawQualificationSha256File -Path $decodedPath
    tracerpt_exit_code = $decodeExitCode; tracerpt_output = $decodeOutput
    orphan_query_exit_code = $postQueryExitCode; orphan_query_output = $postQueryOutput
    monitored_processes = $processInventory; selected_event_ids = [uint16[]]@(12,13,14,15,16,17,28,29,30,31,32)
    raw_packet_payload_capture = $false; diagnostic_only = $true; training_eligible = $false
    correlation_status = "OPEN_PENDING_INDEPENDENT_VERIFY"
}
$null = Write-RawQualificationDurableNewJson -Path (Join-Path $traceRoot "kernel-network-capture.json") -Value $captureReport

$systemCollect = & $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $systemEvidenceScript `
    -Action Collect -EvidenceRoot $systemRoot -RunId $runId -StartUtc $startedUtc -EndUtc $observationEndUtc
if ($LASTEXITCODE -ne 0) { throw "Windows system evidence collection failed. Root: $runRoot" }

$etwVerificationPath = Join-Path $runRoot "kernel-network-verification.json"
$witnessVerificationPath = Join-Path $runRoot "network-witness-verification.json"
$systemVerificationPath = Join-Path $runRoot "system-evidence-verification.json"
$etwVerification = Invoke-JsonVerifier -Module "binance_lob.kernel_network_production_verify_cli" -InputRoot $traceRoot -OutputPath $etwVerificationPath
$witnessVerification = Invoke-JsonVerifier -Module "binance_lob.network_witness_verify_cli" -InputRoot $witnessRoot -OutputPath $witnessVerificationPath
$systemVerification = Invoke-JsonVerifier -Module "binance_lob.system_evidence_verify_cli" -InputRoot $systemRoot -OutputPath $systemVerificationPath

$innerTerminalPath = if ($null -ne $rawRoot) { Join-Path $rawRoot "launcher-terminal.json" } else { $null }
$innerTerminal = if ($null -ne $innerTerminalPath -and (Test-Path -LiteralPath $innerTerminalPath -PathType Leaf)) {
    Get-Content -LiteralPath $innerTerminalPath -Raw -Encoding UTF8 | ConvertFrom-Json
} else { $null }
$networkIncidentPath = Join-Path $runRoot "network-incident.json"
$networkIncident = $null
if ($null -ne $innerTerminal -and $innerTerminal.status -ceq "FAILED" -and $null -ne $rawRoot) {
    $generationRoots = [string[]]@(
        Get-ChildItem -LiteralPath $rawRoot -Recurse -Filter "generation.json" -File -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Directory.FullName } | Sort-Object -Unique
    )
    if ($generationRoots.Count -gt 0) {
        $incidentWallNs = if ($null -ne $innerTerminal.failure_containment -and
            $null -ne $innerTerminal.failure_containment.detected_wall_ns) {
            [uint64]$innerTerminal.failure_containment.detected_wall_ns
        } else {
            [uint64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) * [uint64]1000000
        }
        $networkIncident = Invoke-NetworkIncidentBundle `
            -GenerationRoots $generationRoots `
            -IncidentWallNs $incidentWallNs `
            -WitnessRoot $witnessRoot `
            -OutputPath $networkIncidentPath
    }
}
Assert-ImplementationLockUnchanged -Lock $implementationLock -RuntimeRoot $sealedObserverRoot
$status = if ($null -ne $observerFailure) { "FAILED" } elseif ($null -ne $innerTerminal -and $innerTerminal.status -ceq "COMPLETE") { "COMPLETE" } else { "FAILED" }
$causeDomain = if ($null -ne $observerFailure) {
    "OBSERVABILITY_INTERNAL_FAILURE"
} elseif ($null -eq $innerTerminal) {
    "INNER_QUALIFICATION_TERMINAL_MISSING"
} elseif ($innerTerminal.status -ceq "COMPLETE") {
    "NONE"
} elseif ([string]$innerTerminal.failure -clike "HOST_CLOCK_HEALTH_GATE_FAILED:*") {
    "HOST_TIME_SYNCHRONIZATION_FAILURE"
} elseif ($null -eq $networkIncident) {
    "INDETERMINATE_BECAUSE_CROSS_PLANE_INCIDENT_EVIDENCE_DID_NOT_VERIFY"
} elseif ([string]$networkIncident.classification -in @(
    "CORRELATED_LOCAL_INTERFACE_OR_ROUTE_FAILURE_FROM_THIS_HOST",
    "CORRELATED_SHARED_PATH_FAILURE_FROM_THIS_HOST")) {
    "HOST_OR_LOCAL_ACCESS_NETWORK_OUTSIDE_CAPTURE_PROCESS"
} elseif ([string]$networkIncident.classification -in @(
    "CORRELATED_BINANCE_PATH_SPECIFIC_FAILURE_FROM_THIS_HOST",
    "CORRELATED_BINANCE_DNS_FAILURE_FROM_THIS_HOST",
    "SOCKET_SILENCE_WHILE_NEW_TCP_PROBES_WERE_REACHABLE",
    "WEBSOCKET_CLOSE_FRAME_AT_APPLICATION_BOUNDARY",
    "SOCKET_READ_ERROR_AT_APPLICATION_BOUNDARY",
    "CONNECT_FAILURE_AT_APPLICATION_BOUNDARY",
    "WEBSOCKET_UPGRADE_REJECTION_AT_APPLICATION_BOUNDARY",
    "TRANSPORT_SILENCE_CAUSE_UNRESOLVED_AT_OBSERVED_BOUNDARIES")) {
    "EXTERNAL_TO_CAPTURE_PROCESS_AT_OBSERVED_SOCKET_BOUNDARY"
} else {
    "CAPTURE_OR_SUPERVISOR_INTERNAL_OR_NON_NETWORK_FAILURE"
}
$terminal = [ordered]@{
    schema = "ObservedRawQualificationTerminalV1"; status = $status; run_id = $runId
    started_utc = $startedUtc.ToString("o"); finished_utc = [DateTimeOffset]::UtcNow.ToString("o")
    raw_qualification_root = $rawRoot
    raw_launcher_terminal = if ($null -ne $innerTerminalPath) { [IO.Path]::GetFileName($innerTerminalPath) } else { $null }
    raw_launcher_terminal_sha256 = if ($null -ne $innerTerminalPath -and (Test-Path $innerTerminalPath)) { Get-RawQualificationSha256File -Path $innerTerminalPath } else { $null }
    raw_launcher_status = if ($null -ne $innerTerminal) { [string]$innerTerminal.status } else { $null }
    raw_launcher_failure = if ($null -ne $innerTerminal) { $innerTerminal.failure } else { $null }
    observer_failure = $observerFailure; cause_domain = $causeDomain
    cause_domain_boundary = "INTERNAL_OR_EXTERNAL_IS_RELATIVE_TO_THE_CAPTURE_PROCESS;_SINGLE_HOST_EVIDENCE_DOES_NOT_SEPARATE_ROUTER_ISP_TRANSIT_OR_BINANCE_INTERNALS"
    kernel_network_root = $traceRoot; kernel_network_verification_file = [IO.Path]::GetFileName($etwVerificationPath)
    kernel_network_verification_sha256 = Get-RawQualificationSha256File -Path $etwVerificationPath
    network_witness_root = $witnessRoot; network_witness_verification_file = [IO.Path]::GetFileName($witnessVerificationPath)
    network_witness_verification_sha256 = Get-RawQualificationSha256File -Path $witnessVerificationPath
    system_evidence_root = $systemRoot; system_evidence_verification_file = [IO.Path]::GetFileName($systemVerificationPath)
    system_evidence_verification_sha256 = Get-RawQualificationSha256File -Path $systemVerificationPath
    network_incident_file = if ($null -ne $networkIncident) { [IO.Path]::GetFileName($networkIncidentPath) } else { $null }
    network_incident_sha256 = if ($null -ne $networkIncident) { Get-RawQualificationSha256File -Path $networkIncidentPath } else { $null }
    network_incident_classification = if ($null -ne $networkIncident) { [string]$networkIncident.classification } else { $null }
    etw_verification_status = [string]$etwVerification.status
    witness_verification_status = [string]$witnessVerification.status
    system_verification_status = [string]$systemVerification.status
    implementation_lock_file = [IO.Path]::GetFileName($implementationLockPath)
    implementation_lock_sha256 = Get-RawQualificationSha256File -Path $implementationLockPath
    implementation_lock_status = "VERIFIED_UNCHANGED_AT_TERMINAL"
    diagnostic_only = $true; raw_lineage_authority = "NONE"; credentials = "NONE"; order_entry = "ABSENT"
    artifact_inventory = Get-ObservedArtifactInventory -Root $runRoot
}
$terminalPath = Join-Path $runRoot "observed-qualification-terminal.json"
$null = Write-RawQualificationDurableNewJson -Path $terminalPath -Value $terminal
$verificationBase = Join-Path $observabilityBase "independent-verifications"
$null = New-Item -ItemType Directory -Path $verificationBase -Force -ErrorAction Stop
$observedVerificationPath = Join-Path $verificationBase ($runId + ".json")
try {
    $observedVerification = Invoke-JsonVerifier `
        -Module "binance_lob.observed_qualification_verify_cli" `
        -InputRoot $runRoot `
        -OutputPath $observedVerificationPath
    if ($observedVerification.status -cne "PASS" -or
        $observedVerification.qualification_status -cne $status -or
        $observedVerification.cause_domain -cne $causeDomain) {
        throw "Observed qualification independent verification identity disagrees."
    }
}
catch {
    [Console]::Error.WriteLine("Observed qualification terminal did not independently verify: $($_.Exception.Message) Root: $runRoot")
    if ($observedMutexOwned) { $observedMutex.ReleaseMutex(); $observedMutexOwned = $false }
    $observedMutex.Dispose()
    exit 2
}
if ($status -cne "COMPLETE") {
    [Console]::Error.WriteLine("Observed raw qualification failed with cause domain $causeDomain. Evidence: $terminalPath")
    if ($observedMutexOwned) { $observedMutex.ReleaseMutex(); $observedMutexOwned = $false }
    $observedMutex.Dispose()
    exit 1
}
if ($observedMutexOwned) { $observedMutex.ReleaseMutex(); $observedMutexOwned = $false }
$observedMutex.Dispose()
Write-Host "PASS: $terminalPath"
