[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
Set-Location -LiteralPath $repo
$base = Join-Path $repo "artifacts\network-trace-smoke"
$null = New-Item -ItemType Directory -Path $base -Force -ErrorAction Stop
$runId = "trace-smoke-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$root = Join-Path $base $runId
$traceScript = Join-Path $PSScriptRoot "RawQualification.NetworkTrace.ps1"
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "The repository Python runtime is absent."
}
$started = $false
try {
    & $traceScript -Action Start -EvidenceRoot $root -RunId $runId -MaximumFileMiB 64 | Out-Host
    $started = $true
    Start-Sleep -Seconds 3
    & $traceScript -Action Status -EvidenceRoot $root -RunId $runId -MaximumFileMiB 64 | Out-Host
}
finally {
    if ($started) {
        & $traceScript -Action Stop -EvidenceRoot $root -RunId $runId -MaximumFileMiB 64 | Out-Host
    }
}
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $repo "src"
    & $python -m binance_lob.network_trace_verify_cli $root | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Independent network-trace verification failed with exit code $LASTEXITCODE."
    }
}
finally {
    $env:PYTHONPATH = $previousPythonPath
}
Write-Output $root
