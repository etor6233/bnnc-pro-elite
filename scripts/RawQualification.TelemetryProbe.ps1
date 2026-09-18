[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $HelperPath,
    [Parameter(Mandatory = $true)] [string] $DriveDeviceId,
    [Parameter(Mandatory = $true)] [uint32] $RootProcessId,
    [switch] $IncludeCollectorConflictScan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. $HelperPath

$clock = Get-RawQualificationClockStatus
$disk = Get-RawQualificationDiskCounters -DriveDeviceId $DriveDeviceId
$network = Get-RawQualificationNetworkCounters
$collectorProcesses = @(Get-RawQualificationCollectorProcesses -RootProcessIds ([uint32[]]@($RootProcessId)))
if ($collectorProcesses.Count -lt 1) {
    throw "The bounded telemetry probe did not observe its requested root process."
}
$conflicts = @()
$powerCfgExitCode = $null
$acSleepDisabled = $null
if ($IncludeCollectorConflictScan) {
    $powerCfg = Join-Path $env:SystemRoot "System32\powercfg.exe"
    if (-not (Test-Path -LiteralPath $powerCfg -PathType Leaf)) { throw "Explicit powercfg.exe path is absent: $powerCfg" }
    $powerQuery = Invoke-RawQualificationExplicitProcess -Executable $powerCfg -Arguments ([string[]]@("/QUERY", "SCHEME_CURRENT", "SUB_SLEEP", "STANDBYIDLE"))
    $sleepStatus = ([string]$powerQuery.stdout + [string]$powerQuery.stderr)
    $powerCfgExitCode = [int]$powerQuery.exit_code
    $acSleepDisabled = $powerCfgExitCode -eq 0 -and $sleepStatus -match 'Current AC Power Setting Index:\s+0x00000000'
}
if ($IncludeCollectorConflictScan) {
    $knownCollectorNames = @("raw_campaign.exe", "segmented_capture.exe", "live_overlap_campaign.exe", "capture.exe")
    $conflicts = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $knownCollectorNames -contains [string]$_.Name
    } | ForEach-Object {
        [pscustomobject][ordered]@{
            pid = [uint32]$_.ProcessId
            name = [string]$_.Name
            executable_path = [string]$_.ExecutablePath
            command_line = [string]$_.CommandLine
        }
    })
}

[pscustomobject][ordered]@{
    schema = "RawQualificationTelemetryProbeV1"
    clock = $clock
    disk = $disk
    network = $network
    collector_processes = $collectorProcesses
    conflicting_collectors = $conflicts
    power = [ordered]@{
        powercfg_exit_code = $powerCfgExitCode
        ac_sleep_disabled = $acSleepDisabled
    }
} | ConvertTo-Json -Depth 30 -Compress
