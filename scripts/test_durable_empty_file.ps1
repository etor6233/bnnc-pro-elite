[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")

$nonce = [guid]::NewGuid().ToString("N").Substring(0, 12)
$root = Join-Path $repo "artifacts\durable-empty-smoke\empty-$nonce"
New-Item -ItemType Directory -Path $root | Out-Null
$path = Join-Path $root "stop.request"

Write-RawQualificationDurableNewFile -Path $path -Bytes ([byte[]]@())
$item = Get-Item -LiteralPath $path -ErrorAction Stop
$exclusiveCreateRejected = $false
try {
    Write-RawQualificationDurableNewFile -Path $path -Bytes ([byte[]]@())
}
catch [IO.IOException] {
    $exclusiveCreateRejected = $true
}
if ($item.Length -ne 0 -or -not $exclusiveCreateRejected) {
    throw "Durable empty-file create-only contract failed."
}

[ordered]@{
    schema = "RawQualificationDurableEmptyFileSmokeV1"
    status = "PASS"
    path = $path
    bytes = [uint64]$item.Length
    exclusive_create_rejected = $exclusiveCreateRejected
} | ConvertTo-Json -Depth 4
