[CmdletBinding()]
param(
    [switch] $ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
Set-Location -LiteralPath $repo
. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")
Initialize-RawQualificationNative

$wrapper = Join-Path $PSScriptRoot "run_observed_raw_qualification.ps1"
$powershell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$python = Join-Path $repo ".venv\Scripts\python.exe"
$logman = Join-Path $env:SystemRoot "System32\logman.exe"
foreach ($path in @($wrapper, $powershell, $python, $logman)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required observed integration-gate input is absent: $path"
    }
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

function Invoke-ObservedVerifier {
    param(
        [Parameter(Mandatory = $true)] [string] $InputRoot,
        [Parameter(Mandatory = $true)] [string] $OutputPath
    )
    $stderrPath = $OutputPath + ".stderr"
    $arguments = [string[]]@(
        "-I", "-P", "-S", "-B", "-c",
        "import runpy,sys;sys.dont_write_bytecode=True;sys.path.insert(0,sys.argv.pop(1));runpy.run_module(sys.argv.pop(1),run_name='__main__')",
        (Join-Path $repo "src"), "binance_lob.observed_qualification_verify_cli", $InputRoot
    )
    $process = Start-Process -FilePath $python -ArgumentList (Join-ExactArguments $arguments) `
        -WorkingDirectory $repo -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $OutputPath -RedirectStandardError $stderrPath
    $process.Refresh()
    return [pscustomobject][ordered]@{
        exit_code = [int]$process.ExitCode
        stdout = $OutputPath
        stderr = $stderrPath
        stdout_bytes = [uint64](Get-Item -LiteralPath $OutputPath -ErrorAction Stop).Length
        stderr_bytes = [uint64](Get-Item -LiteralPath $stderrPath -ErrorAction Stop).Length
    }
}

function Get-OnlyDirectory {
    param([Parameter(Mandatory = $true)] [string] $Base)
    $directories = [object[]]@(
        Get-ChildItem -LiteralPath $Base -Directory -ErrorAction Stop |
            Where-Object { $_.Name -cne "independent-verifications" }
    )
    if ($directories.Count -ne 1) {
        throw "Expected exactly one observed run under $Base; found $($directories.Count)."
    }
    return [IO.Path]::GetFullPath($directories[0].FullName)
}

function Assert-NoObservedResidue {
    param(
        [Parameter(Mandatory = $true)] [string] $ObservedRoot,
        [Parameter(Mandatory = $true)] [string] $RawBase
    )
    $runId = [IO.Path]::GetFileName($ObservedRoot)
    if (-not $runId.StartsWith("observed-", [StringComparison]::Ordinal)) {
        throw "Observed run id is not canonical: $runId"
    }
    $sessionName = "BinanceProduction_" + $runId.Substring($runId.Length - 12)
    $query = [string[]]@(& $logman query -ets $sessionName 2>&1 | ForEach-Object { [string]$_ })
    $queryExitCode = [int]$LASTEXITCODE
    if ($queryExitCode -eq 0) {
        throw "Named ETW session remained active after the integration case: $sessionName"
    }

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(120)
    $residual = [object[]]@()
    do {
        $escapedRaw = [Regex]::Escape([IO.Path]::GetFullPath($RawBase))
        $escapedObserved = [Regex]::Escape([IO.Path]::GetFullPath($ObservedRoot))
        $residual = [object[]]@(
            Get-CimInstance Win32_Process -ErrorAction Stop |
                Where-Object {
                    $command = [string]$_.CommandLine
                    $executable = [string]$_.ExecutablePath
                    ($command -match $escapedRaw) -or ($command -match $escapedObserved) -or
                    ($executable -match $escapedRaw) -or ($executable -match $escapedObserved)
                } |
                Select-Object ProcessId, ParentProcessId, Name, CreationDate, ExecutablePath, CommandLine
        )
        if ($residual.Count -eq 0) { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($residual.Count -ne 0) {
        throw "Observed integration case left $($residual.Count) owned process(es) alive."
    }
    return [pscustomobject][ordered]@{
        session_name = $sessionName
        post_case_query_exit_code = $queryExitCode
        residual_processes = 0
    }
}

function Invoke-ObservedCase {
    param(
        [Parameter(Mandatory = $true)] [ValidateSet("HEALTHY", "KERNEL_ABORT", "WITNESS_ABORT")] [string] $Case,
        [Parameter(Mandatory = $true)] [string] $GateRoot
    )
    $caseSlug = if ($Case -ceq "HEALTHY") { "h" } elseif ($Case -ceq "KERNEL_ABORT") { "k" } else { "w" }
    $rawRelative = "artifacts/oqg/" + [IO.Path]::GetFileName($GateRoot) + "/r/" + $caseSlug
    $observedRelative = "artifacts/oqg/" + [IO.Path]::GetFileName($GateRoot) + "/o/" + $caseSlug
    $rawBase = [IO.Path]::GetFullPath((Join-Path $repo $rawRelative))
    $observedBase = [IO.Path]::GetFullPath((Join-Path $repo $observedRelative))
    $caseRoot = Join-Path $GateRoot ("case-" + $caseSlug)
    $null = New-Item -ItemType Directory -Path $caseRoot -ErrorAction Stop
    $stdout = Join-Path $caseRoot "wrapper.stdout.log"
    $stderr = Join-Path $caseRoot "wrapper.stderr.log"
    $mode = if ($Case -ceq "HEALTHY") { "Smoke" } else { "Test" }
    $arguments = [Collections.Generic.List[string]]::new()
    $arguments.AddRange([string[]]@(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $wrapper,
        "-Mode", $mode, "-TotalSeconds", "120", "-RotationSeconds", "60",
        "-OverlapSeconds", "10", "-SegmentSeconds", "10",
        "-OutputBase", $rawRelative, "-ObservabilityOutputBase", $observedRelative,
        "-MinimumFreeGiB", "100", "-StartupDeadlineSeconds", "180",
        "-PostVerificationDeadlineSeconds", "900", "-IndependentVerifierTimeoutSeconds", "300",
        "-WitnessIntervalSeconds", "5"
    ))
    if ($Case -ceq "KERNEL_ABORT") { $arguments.Add("-InjectKernelObserverAbortAfterRawStartup") }
    if ($Case -ceq "WITNESS_ABORT") { $arguments.Add("-InjectWitnessObserverAbortAfterRawStartup") }

    $startedUtc = [DateTimeOffset]::UtcNow
    $process = Start-Process -FilePath $powershell -ArgumentList (Join-ExactArguments ([string[]]$arguments)) `
        -WorkingDirectory $repo -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $process.Refresh()
    $exitCode = [int]$process.ExitCode
    $observedRoot = Get-OnlyDirectory -Base $observedBase
    $residue = Assert-NoObservedResidue -ObservedRoot $observedRoot -RawBase $rawBase

    if ($Case -ceq "HEALTHY") {
        if ($exitCode -ne 0) { throw "Healthy observed smoke failed with exit code $exitCode." }
        $terminalPath = Join-Path $observedRoot "observed-qualification-terminal.json"
        if (-not (Test-Path -LiteralPath $terminalPath -PathType Leaf)) {
            throw "Healthy observed smoke omitted its terminal."
        }
        $terminal = Get-Content -LiteralPath $terminalPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        if ($terminal.schema -cne "ObservedRawQualificationTerminalV1" -or
            $terminal.status -cne "COMPLETE" -or $terminal.cause_domain -cne "NONE") {
            throw "Healthy observed smoke did not produce exact COMPLETE/NONE identity."
        }
        $verificationPath = Join-Path $caseRoot "independent-observed-verification.json"
        $verificationRun = Invoke-ObservedVerifier -InputRoot $observedRoot -OutputPath $verificationPath
        if ($verificationRun.exit_code -ne 0 -or $verificationRun.stderr_bytes -ne 0) {
            throw "Healthy observed smoke failed an additional independent envelope verification."
        }
        $verification = Get-Content -LiteralPath $verificationPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        if ($verification.status -cne "PASS" -or $verification.qualification_status -cne "COMPLETE" -or
            $verification.cause_domain -cne "NONE") {
            throw "Healthy independent verification identity drifted."
        }
        return [pscustomobject][ordered]@{
            case = $Case; expected = "COMPLETE"; observed_exit_code = $exitCode; status = "PASS"
            started_utc = $startedUtc.ToString("o"); finished_utc = [DateTimeOffset]::UtcNow.ToString("o")
            raw_base = $rawBase; observed_root = $observedRoot
            terminal_sha256 = Get-RawQualificationSha256File -Path $terminalPath
            independent_verification_sha256 = Get-RawQualificationSha256File -Path $verificationPath
            cleanup = $residue
        }
    }

    if ($exitCode -ne 1) { throw "$Case did not fail closed with exit code 1; observed $exitCode." }
    $failurePath = Join-Path $observedRoot "observed-wrapper-failure.json"
    if (-not (Test-Path -LiteralPath $failurePath -PathType Leaf)) {
        throw "$Case omitted durable wrapper-failure evidence."
    }
    $failure = Get-Content -LiteralPath $failurePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if ($failure.schema -cne "ObservedRawQualificationWrapperFailureV1" -or
        $failure.status -cne "FAILED" -or $failure.terminal_published -ne $false) {
        throw "$Case wrapper-failure identity is invalid."
    }
    $expectedText = if ($Case -ceq "KERNEL_ABORT") {
        "Observed qualification required emergency ETW cleanup"
    } else {
        "Observed qualification observer failed before requested stop: NETWORK_WITNESS_EXITED_BEFORE_STOP"
    }
    if ([string]$failure.error -cnotlike ("*" + $expectedText + "*")) {
        throw "$Case failed for an unexpected reason: $($failure.error)"
    }
    return [pscustomobject][ordered]@{
        case = $Case; expected = "FAIL_CLOSED"; observed_exit_code = $exitCode; status = "PASS"
        started_utc = $startedUtc.ToString("o"); finished_utc = [DateTimeOffset]::UtcNow.ToString("o")
        raw_base = $rawBase; observed_root = $observedRoot
        wrapper_failure_sha256 = Get-RawQualificationSha256File -Path $failurePath
        exact_failure = [string]$failure.error; cleanup = $residue
    }
}

function Invoke-MutationGate {
    param(
        [Parameter(Mandatory = $true)] [string] $HealthyRoot,
        [Parameter(Mandatory = $true)] [string] $GateRoot
    )
    $mutationBase = Join-Path $GateRoot "mutations"
    $null = New-Item -ItemType Directory -Path $mutationBase -ErrorAction Stop
    $results = [Collections.Generic.List[object]]::new()
    foreach ($kind in [string[]]@("ETL_BYTE", "CAUSE_DOMAIN", "MISSING_WITNESS_SEAL")) {
        $copy = Join-Path $mutationBase $kind.ToLowerInvariant().Replace("_", "-")
        Copy-Item -LiteralPath $HealthyRoot -Destination $copy -Recurse -ErrorAction Stop
        if ($kind -ceq "ETL_BYTE") {
            $target = Join-Path $copy "kernel-network\kernel-network.etl"
            $stream = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            try {
                if ($stream.Length -eq 0) { throw "Cannot mutate an empty ETL artifact." }
                $stream.Position = $stream.Length - 1
                $value = $stream.ReadByte()
                $stream.Position = $stream.Length - 1
                $stream.WriteByte([byte]($value -bxor 1))
                $stream.Flush($true)
            } finally { $stream.Dispose() }
        }
        elseif ($kind -ceq "CAUSE_DOMAIN") {
            $target = Join-Path $copy "observed-qualification-terminal.json"
            $terminal = Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            $terminal.cause_domain = "EXTERNAL_TO_CAPTURE_PROCESS_AT_OBSERVED_SOCKET_BOUNDARY"
            [IO.File]::WriteAllText($target, ($terminal | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
        }
        else {
            $target = Join-Path $copy "network-witness\network-witness-seal.json"
            if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
                throw "Healthy fixture omitted the witness seal selected for mutation."
            }
            Move-Item -LiteralPath $target -Destination (Join-Path $GateRoot ("removed-" + $kind.ToLowerInvariant() + ".json")) -ErrorAction Stop
        }
        $output = Join-Path $mutationBase ($kind.ToLowerInvariant() + ".verification.json")
        $verification = Invoke-ObservedVerifier -InputRoot $copy -OutputPath $output
        if ($verification.exit_code -eq 0) { throw "Mutation $kind was falsely accepted." }
        $results.Add([ordered]@{
            mutation = $kind; status = "REJECTED_AS_REQUIRED"; verifier_exit_code = $verification.exit_code
            verifier_stdout_bytes = $verification.stdout_bytes; verifier_stderr_bytes = $verification.stderr_bytes
        })
    }
    return [object[]]$results
}

if ($ValidateOnly) {
    $parserTokens = $null
    $parserErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($wrapper, [ref]$parserTokens, [ref]$parserErrors) | Out-Null
    if ($parserErrors.Count -ne 0) { throw "Observed wrapper has PowerShell parse errors." }
    [ordered]@{
        schema = "ObservedRawQualificationIntegrationGatePreflightV1"
        status = "PASS"
        administrator = Test-Administrator
        wrapper = $wrapper
        wrapper_sha256 = Get-RawQualificationSha256File -Path $wrapper
        cases = [string[]]@("HEALTHY", "KERNEL_ABORT", "WITNESS_ABORT")
        mutations = [string[]]@("ETL_BYTE", "CAUSE_DOMAIN", "MISSING_WITNESS_SEAL")
    } | ConvertTo-Json -Depth 8
    exit 0
}

if (-not (Test-Administrator)) {
    throw "The observed integration gate requires one Administrator PowerShell."
}

$base = Join-Path $repo "artifacts\oqg"
$null = New-Item -ItemType Directory -Path $base -Force -ErrorAction Stop
$gateId = "g-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$gateRoot = Join-Path $base $gateId
$null = New-Item -ItemType Directory -Path $gateRoot -ErrorAction Stop
$gateStarted = [DateTimeOffset]::UtcNow
$healthy = Invoke-ObservedCase -Case HEALTHY -GateRoot $gateRoot
$mutations = Invoke-MutationGate -HealthyRoot $healthy.observed_root -GateRoot $gateRoot
$kernelAbort = Invoke-ObservedCase -Case KERNEL_ABORT -GateRoot $gateRoot
$witnessAbort = Invoke-ObservedCase -Case WITNESS_ABORT -GateRoot $gateRoot
$report = [ordered]@{
    schema = "ObservedRawQualificationIntegrationGateV1"
    status = "PASS"
    gate_id = $gateId
    started_utc = $gateStarted.ToString("o")
    completed_utc = [DateTimeOffset]::UtcNow.ToString("o")
    wrapper = $wrapper
    wrapper_sha256 = Get-RawQualificationSha256File -Path $wrapper
    healthy = $healthy
    mutations = $mutations
    observer_abort_cases = [object[]]@($kernelAbort, $witnessAbort)
    proof_boundary = "HEALTHY_COMPLETE_PLUS_INDEPENDENT_REVERIFY_PLUS_THREE_MUTATION_REJECTIONS_PLUS_BOTH_OBSERVER_ABORTS_FAIL_CLOSED_WITH_NO_OWNED_PROCESS_OR_ETW_RESIDUE"
}
$reportPath = Join-Path $gateRoot "observed-integration-gate.json"
$null = Write-RawQualificationDurableNewJson -Path $reportPath -Value $report
$report | ConvertTo-Json -Depth 20
Write-Host "PASS: $reportPath"
