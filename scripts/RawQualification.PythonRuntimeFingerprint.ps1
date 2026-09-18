[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $HelperPath,
    [Parameter(Mandatory = $true)] [string] $PythonExecutable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. $HelperPath

[pscustomobject][ordered]@{
    schema = "RawQualificationPythonRuntimeFingerprintV1"
    runtime = Get-RawQualificationPythonRuntimeDigest -PythonExecutable $PythonExecutable
} | ConvertTo-Json -Depth 20 -Compress
