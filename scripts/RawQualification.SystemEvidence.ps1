[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Validate", "Collect")]
    [string] $Action,

    [Parameter(Mandatory = $true)]
    [string] $EvidenceRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z-]{0,127}$')]
    [string] $RunId,

    [Parameter(Mandatory = $true)]
    [DateTimeOffset] $StartUtc,

    [Parameter(Mandatory = $true)]
    [DateTimeOffset] $EndUtc,

    [ValidateRange(1, 4096)]
    [uint32] $MaximumEventsPerLog = 2048,

    [ValidateRange(1, 32)]
    [uint32] $MaximumArtifactMiB = 16
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")

$systemProviders = [string[]]@(
    "Microsoft-Windows-Kernel-Power",
    "Microsoft-Windows-Power-Troubleshooter",
    "Microsoft-Windows-NDIS",
    "Microsoft-Windows-TCPIP",
    "Tcpip",
    "Microsoft-Windows-WHEA-Logger",
    "Microsoft-Windows-Ntfs",
    "Ntfs",
    "disk",
    "stornvme",
    "storahci",
    "Microsoft-Windows-Eventlog",
    "Microsoft-Windows-Time-Service",
    "Service Control Manager"
)
$applicationProviders = [string[]]@(
    "Application Error",
    "Application Hang",
    "Windows Error Reporting"
)

function ConvertTo-SystemEvidenceBoundedText {
    param(
        [AllowNull()] $Value,
        [Parameter(Mandatory = $true)] [uint32] $MaximumBytes,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ($text.IndexOf([char]0) -ge 0) { throw "$Label contains a NUL character." }
    if ([Text.UTF8Encoding]::new($false).GetByteCount($text) -gt $MaximumBytes) {
        throw "$Label exceeded its bounded UTF-8 allowance."
    }
    return $text
}

function Get-SystemEvidenceLogCoverage {
    param([Parameter(Mandatory = $true)] [string] $LogName)
    try {
        $metadata = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        $oldest = @(Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue)
        $newest = @(Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction SilentlyContinue)
        $oldestUtc = if ($oldest.Count -eq 1 -and $null -ne $oldest[0].TimeCreated) {
            ([DateTimeOffset]$oldest[0].TimeCreated).ToUniversalTime().ToString("o")
        } else { $null }
        $newestUtc = if ($newest.Count -eq 1 -and $null -ne $newest[0].TimeCreated) {
            ([DateTimeOffset]$newest[0].TimeCreated).ToUniversalTime().ToString("o")
        } else { $null }
        return [ordered]@{
            log_name = $LogName
            query_status = "PASS"
            is_enabled = [bool]$metadata.IsEnabled
            log_mode = [string]$metadata.LogMode
            maximum_size_bytes = [uint64]$metadata.MaximumSizeInBytes
            record_count = if ($null -eq $metadata.RecordCount) { $null } else { [uint64]$metadata.RecordCount }
            oldest_available_utc = $oldestUtc
            newest_available_utc = $newestUtc
            requested_start_is_covered = [bool](
                $null -ne $oldestUtc -and
                ([DateTimeOffset]::Parse($oldestUtc) -le $StartUtc.ToUniversalTime())
            )
            error = $null
        }
    }
    catch {
        return [ordered]@{
            log_name = $LogName
            query_status = "FAILED"
            is_enabled = $null
            log_mode = $null
            maximum_size_bytes = $null
            record_count = $null
            oldest_available_utc = $null
            newest_available_utc = $null
            requested_start_is_covered = $false
            error = ConvertTo-SystemEvidenceBoundedText -Value $_.Exception.Message -MaximumBytes 4096 -Label "$LogName coverage error"
        }
    }
}

function Get-SystemEvidenceEvents {
    param(
        [Parameter(Mandatory = $true)] [string] $LogName,
        [Parameter(Mandatory = $true)] [string[]] $ProviderNames
    )
    $queryErrors = @()
    $filter = @{
        LogName = $LogName
        StartTime = $StartUtc.UtcDateTime
        EndTime = $EndUtc.UtcDateTime
        ProviderName = $ProviderNames
    }
    $records = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaximumEventsPerLog `
        -ErrorAction SilentlyContinue -ErrorVariable +queryErrors)
    $events = [Collections.Generic.List[object]]::new()
    $xmlBytes = [uint64]0
    foreach ($record in ($records | Sort-Object TimeCreated, RecordId)) {
        $xml = ConvertTo-SystemEvidenceBoundedText -Value $record.ToXml() -MaximumBytes 131072 -Label "$LogName event XML"
        $xmlBytes += [uint64][Text.UTF8Encoding]::new($false).GetByteCount($xml)
        if ($xmlBytes -gt ([uint64]$MaximumArtifactMiB * 1MB)) {
            throw "$LogName event XML exceeded the total bounded artifact allowance."
        }
        $events.Add([ordered]@{
            log_name = $LogName
            provider_name = [string]$record.ProviderName
            event_id = [uint32]$record.Id
            level = if ($null -eq $record.Level) { $null } else { [uint32]$record.Level }
            record_id = if ($null -eq $record.RecordId) { $null } else { [uint64]$record.RecordId }
            time_created_utc = if ($null -eq $record.TimeCreated) { $null } else {
                ([DateTimeOffset]$record.TimeCreated).ToUniversalTime().ToString("o")
            }
            process_id = if ($null -eq $record.ProcessId) { $null } else { [uint32]$record.ProcessId }
            thread_id = if ($null -eq $record.ThreadId) { $null } else { [uint32]$record.ThreadId }
            xml = $xml
        })
    }
    $fatalErrors = @($queryErrors | Where-Object {
        ([string]$_.FullyQualifiedErrorId) -notmatch "NoMatchingEventsFound"
    })
    return [ordered]@{
        log_name = $LogName
        query_status = if ($fatalErrors.Count -eq 0) { "PASS" } else { "FAILED" }
        requested_provider_names = $ProviderNames
        returned_events = [uint32]$events.Count
        maximum_events = [uint32]$MaximumEventsPerLog
        result_limit_reached = [bool]($events.Count -eq $MaximumEventsPerLog)
        xml_bytes = [uint64]$xmlBytes
        errors = [string[]]@($fatalErrors | ForEach-Object {
            ConvertTo-SystemEvidenceBoundedText -Value $_.Exception.Message -MaximumBytes 4096 -Label "$LogName query error"
        })
        events = [object[]]$events
    }
}

if ($env:OS -cne "Windows_NT") { throw "System evidence collection is Windows-only." }
if ($EndUtc.ToUniversalTime() -le $StartUtc.ToUniversalTime()) {
    throw "System evidence end must be strictly after start."
}
if (($EndUtc - $StartUtc).TotalDays -gt 8) {
    throw "System evidence interval exceeds its bounded eight-day allowance."
}

$resolvedRoot = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\')
$parent = [IO.Path]::GetDirectoryName($resolvedRoot)
if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw "System evidence parent directory does not exist."
}
$null = Assert-RawQualificationNoReparsePointInExistingPath -Path $parent

if ($Action -ceq "Validate") {
    [ordered]@{
        schema = "RawQualificationSystemEvidenceValidationV1"
        status = "PASS"
        run_id = $RunId
        evidence_root = $resolvedRoot
        start_utc = $StartUtc.ToUniversalTime().ToString("o")
        end_utc = $EndUtc.ToUniversalTime().ToString("o")
        maximum_events_per_log = [uint32]$MaximumEventsPerLog
        maximum_artifact_mib = [uint32]$MaximumArtifactMiB
        system_provider_names = $systemProviders
        application_provider_names = $applicationProviders
        mutates_windows_logging_policy = $false
        administrator_required = $false
        script_sha256 = Get-RawQualificationSha256File -Path $PSCommandPath
    } | ConvertTo-Json -Depth 10
    exit 0
}

if (Test-Path -LiteralPath $resolvedRoot) {
    throw "System evidence root already exists; collection is create-only."
}
$null = New-Item -ItemType Directory -Path $resolvedRoot -ErrorAction Stop
$null = Assert-RawQualificationNoReparsePointInExistingPath -Path $resolvedRoot

$adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object InterfaceGuid | ForEach-Object {
    [ordered]@{
        interface_guid = [string]$_.InterfaceGuid
        interface_index = [uint32]$_.InterfaceIndex
        name = ConvertTo-SystemEvidenceBoundedText -Value $_.Name -MaximumBytes 4096 -Label "adapter name"
        interface_description = ConvertTo-SystemEvidenceBoundedText -Value $_.InterfaceDescription -MaximumBytes 4096 -Label "adapter description"
        status = [string]$_.Status
        media_connection_state = [string]$_.MediaConnectionState
        link_speed = [string]$_.LinkSpeed
        driver_information = ConvertTo-SystemEvidenceBoundedText -Value $_.DriverInformation -MaximumBytes 8192 -Label "driver information"
        driver_file_name = [string]$_.DriverFileName
        driver_version = [string]$_.DriverVersion
        driver_date = if ($null -eq $_.DriverDate) { $null } else { ([DateTimeOffset]$_.DriverDate).ToUniversalTime().ToString("o") }
        ndis_version = [string]$_.NdisVersion
        connector_present = [bool]$_.ConnectorPresent
        virtual = [bool]$_.Virtual
    }
})
$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
$coverage = [object[]]@(
    Get-SystemEvidenceLogCoverage -LogName "System"
    Get-SystemEvidenceLogCoverage -LogName "Application"
)
$queries = [object[]]@(
    Get-SystemEvidenceEvents -LogName "System" -ProviderNames $systemProviders
    Get-SystemEvidenceEvents -LogName "Application" -ProviderNames $applicationProviders
)
$completeCoverage = -not [bool](@($coverage | Where-Object {
    $_.query_status -cne "PASS" -or -not $_.is_enabled -or -not $_.requested_start_is_covered
}).Count)
$completeQueries = -not [bool](@($queries | Where-Object {
    $_.query_status -cne "PASS" -or $_.result_limit_reached
}).Count)

$evidence = [ordered]@{
    schema = "RawQualificationSystemEvidenceV1"
    run_id = $RunId
    status = if ($completeCoverage -and $completeQueries) { "COMPLETE" } else { "INSUFFICIENT_COVERAGE" }
    collected_utc = [DateTimeOffset]::UtcNow.ToString("o")
    collected_qpc_timestamp = [int64][Diagnostics.Stopwatch]::GetTimestamp()
    qpc_frequency = [uint64][Diagnostics.Stopwatch]::Frequency
    requested_start_utc = $StartUtc.ToUniversalTime().ToString("o")
    requested_end_utc = $EndUtc.ToUniversalTime().ToString("o")
    maximum_events_per_log = [uint32]$MaximumEventsPerLog
    maximum_artifact_mib = [uint32]$MaximumArtifactMiB
    collector_pid = [uint32]$PID
    computer_name = [string]$env:COMPUTERNAME
    os_last_boot_utc = ([DateTimeOffset]$operatingSystem.LastBootUpTime).ToUniversalTime().ToString("o")
    os_version = [string]$operatingSystem.Version
    os_build_number = [string]$operatingSystem.BuildNumber
    system_manufacturer = [string]$computerSystem.Manufacturer
    system_model = [string]$computerSystem.Model
    adapters = [object[]]$adapters
    log_coverage = $coverage
    event_queries = $queries
    inference_boundary = "This artifact observes retained local Windows logs and current host inventory only; missing or overwritten records cannot prove that an upstream event did not occur."
}
$evidencePath = Join-Path $resolvedRoot "system-evidence.json"
$evidenceSha256 = Write-RawQualificationDurableNewJson -Path $evidencePath -Value $evidence
$evidenceBytes = [uint64](Get-Item -LiteralPath $evidencePath -ErrorAction Stop).Length
if ($evidenceBytes -gt ([uint64]$MaximumArtifactMiB * 1MB)) {
    throw "Serialized system evidence exceeds its bounded artifact allowance."
}
$seal = [ordered]@{
    schema = "RawQualificationSystemEvidenceSealV1"
    run_id = $RunId
    status = "SEALED"
    evidence_file = "system-evidence.json"
    evidence_bytes = $evidenceBytes
    evidence_sha256 = $evidenceSha256
    sealed_utc = [DateTimeOffset]::UtcNow.ToString("o")
}
$null = Write-RawQualificationDurableNewJson -Path (Join-Path $resolvedRoot "system-evidence-seal.json") -Value $seal
$seal | ConvertTo-Json -Depth 10
