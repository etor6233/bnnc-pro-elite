[CmdletBinding()]
param(
    [string] $CampaignDirectory,
    [switch] $TestRustVerifier
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$helper = (Resolve-Path (Join-Path $PSScriptRoot "RawQualification.Windows.ps1")).Path
. $helper
Initialize-RawQualificationNative

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

function New-CollectorProcessSelfTestRecord {
    param(
        [uint32] $ProcessId,
        [uint32] $ParentPid,
        [AllowNull()] [string] $ExecutablePath,
        [AllowNull()] $CreationDate = ([DateTime]::UtcNow)
    )
    return [pscustomobject]@{
        ProcessId = $ProcessId
        ParentProcessId = $ParentPid
        Name = if ($ProcessId -eq 1002) { "w32tm.exe" } else { "powershell.exe" }
        CreationDate = $CreationDate
        ExecutablePath = $ExecutablePath
        KernelModeTime = [uint64]1
        UserModeTime = [uint64]2
        WorkingSetSize = [uint64]3
        PageFileUsage = [uint64]4
        HandleCount = [uint32]5
        ReadOperationCount = [uint64]6
        ReadTransferCount = [uint64]7
        WriteOperationCount = [uint64]8
        WriteTransferCount = [uint64]9
    }
}

$collectorRootRecord = New-CollectorProcessSelfTestRecord `
    -ProcessId 1001 -ParentPid 1 -ExecutablePath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$collectorVanishedRecord = New-CollectorProcessSelfTestRecord `
    -ProcessId 1002 -ParentPid 1001 -ExecutablePath $null
$script:collectorProcessSelfTestMode = "VANISHED_DESCENDANT"
function Get-CimInstance {
    param($ClassName, $Filter, $ErrorAction)
    if ([string]$ClassName -cne "Win32_Process") { throw "Unexpected self-test CIM class." }
    if ([string]::IsNullOrWhiteSpace([string]$Filter)) {
        return @($collectorRootRecord, $collectorVanishedRecord)
    }
    if ($script:collectorProcessSelfTestMode -ceq "LIVE_UNIDENTIFIABLE") {
        return @($collectorVanishedRecord)
    }
    return @()
}
try {
    $collectorRaceResult = @(Get-RawQualificationCollectorProcesses -RootProcessIds ([uint32[]]@(1001)))
    Assert-True ($collectorRaceResult.Count -eq 1 -and [uint32]$collectorRaceResult[0].pid -eq 1001) `
        "A vanished transient descendant was serialized instead of being omitted from its telemetry sample."

    $script:collectorProcessSelfTestMode = "LIVE_UNIDENTIFIABLE"
    $liveUnidentifiableRejected = $false
    try {
        $null = Get-RawQualificationCollectorProcesses -RootProcessIds ([uint32[]]@(1001))
    }
    catch {
        $liveUnidentifiableRejected = $_.Exception.Message -like "Live collector descendant process*"
    }
    Assert-True $liveUnidentifiableRejected `
        "A still-live collector descendant without stable executable identity was not rejected."

    $collectorRootRecord.ExecutablePath = $null
    $script:collectorProcessSelfTestMode = "VANISHED_DESCENDANT"
    $vanishedRootRejected = $false
    try {
        $null = Get-RawQualificationCollectorProcesses -RootProcessIds ([uint32[]]@(1001))
    }
    catch {
        $vanishedRootRejected = $_.Exception.Message -like "Required collector root process*vanished*"
    }
    Assert-True $vanishedRootRejected `
        "A required collector root that vanished during sampling was silently omitted."
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath Function:\Get-CimInstance -Force
}

$wholeSecondExact = Convert-RawQualificationQpcTicksToWholeSeconds -ElapsedTicks 20000000 -Frequency 10000000
$wholeSecondFraction = Convert-RawQualificationQpcTicksToWholeSeconds -ElapsedTicks 17777853 -Frequency 10000000
$roundedCastMutant = [uint64]([double]17777853 / [double]10000000)
Assert-True ($wholeSecondExact -eq 2 -and $wholeSecondFraction -eq 1 -and $roundedCastMutant -eq 2) `
    "Exact QPC whole-second conversion did not reject PowerShell's rounding cast mutant."

$scheduleArguments = @{
    Generations = [uint64]2
    Handovers = [uint64]1
    PlannedGenerationLaunches = [uint64]2
    ServerShutdownGenerationLaunches = [uint64]0
    ServerShutdownSupervisorEvents = [uint64]0
    ServerShutdownDurableEvents = [uint64]0
}
Assert-True ((ConvertTo-RawQualificationCanonicalMode -Mode production) -ceq "Production") "Lowercase production mode was not canonicalized."
Assert-True ((ConvertTo-RawQualificationCanonicalMode -Mode sevenday) -ceq "SevenDay") "Lowercase seven-day mode was not canonicalized."
Assert-True ((ConvertTo-RawQualificationCanonicalMode -Mode smoke) -ceq "Smoke") "Lowercase smoke mode was not canonicalized."
Assert-True ((ConvertTo-RawQualificationCanonicalMode -Mode test) -ceq "Test") "Lowercase test mode was not canonicalized."
Assert-True ((Get-RawQualificationGenerationScheduleClassification -Mode Production @scheduleArguments) -ceq
    "PLANNED_TWO_GENERATION") "Exact Production topology lost its planned two-generation classification."
Assert-True ((Get-RawQualificationGenerationScheduleClassification -Mode Smoke @scheduleArguments) -ceq
    "PLANNED_TWO_GENERATION") "Exact Smoke topology is not classified identically to launcher terminal output."
$stressScheduleArguments = @{} + $scheduleArguments
$stressScheduleArguments.Generations = [uint64]8
$stressScheduleArguments.Handovers = [uint64]7
$stressScheduleArguments.PlannedGenerationLaunches = [uint64]8
Assert-True ((Get-RawQualificationGenerationScheduleClassification -Mode Test @stressScheduleArguments) -ceq
    "NON_PRODUCTION_SCHEDULE") "Accelerated stress topology was misclassified as the planned two-generation schedule."
Assert-True ((Get-RawQualificationGenerationScheduleClassification -Mode SevenDay @stressScheduleArguments) -ceq
    "PLANNED_CONTINUOUS_SEVEN_DAY") "Exact seven-day schedule lost its continuous classification."
Assert-True ((Get-RawQualificationGenerationScheduleClassification -Mode SevenDay @scheduleArguments) -ceq
    "DEVIATED") "A truncated seven-day schedule was misclassified as planned."
$deviatedScheduleArguments = @{} + $scheduleArguments
$deviatedScheduleArguments.ServerShutdownDurableEvents = [uint64]1
Assert-True ((Get-RawQualificationGenerationScheduleClassification -Mode Production @deviatedScheduleArguments) -ceq
    "DEVIATED") "Production serverShutdown evidence did not force a schedule deviation."
Assert-True ((Get-RawQualificationGenerationScheduleClassification -Mode Smoke @deviatedScheduleArguments) -ceq
    "NON_PRODUCTION_SCHEDULE") "Smoke serverShutdown evidence retained the planned schedule classification."
$productionTopology = Get-RawQualificationRequiredTerminalTopology -Mode Production `
    -TotalSeconds 86400 -RotationSeconds 82800 -OverlapSeconds 900 -SegmentSeconds 900
$sevenDayTopology = Get-RawQualificationRequiredTerminalTopology -Mode SevenDay `
    -TotalSeconds 604800 -RotationSeconds 82800 -OverlapSeconds 900 -SegmentSeconds 900
$smokeTopology = Get-RawQualificationRequiredTerminalTopology -Mode Smoke `
    -TotalSeconds 120 -RotationSeconds 60 -OverlapSeconds 10 -SegmentSeconds 10
$stressTopology = Get-RawQualificationRequiredTerminalTopology -Mode Test `
    -TotalSeconds 7200 -RotationSeconds 900 -OverlapSeconds 900 -SegmentSeconds 900
$faultTopology = Get-RawQualificationRequiredTerminalTopology -Mode Test `
    -TotalSeconds 300 -RotationSeconds 240 -OverlapSeconds 30 -SegmentSeconds 30
Assert-True ([bool]$productionTopology.required -and $productionTopology.profile -ceq "ENDURANCE_24H") "Production exact terminal topology is not mandatory."
Assert-True ([bool]$sevenDayTopology.required -and $sevenDayTopology.profile -ceq "CONTINUOUS_7D" -and
    [uint64]$sevenDayTopology.generations -eq 8 -and [uint64]$sevenDayTopology.handovers -eq 7) "Seven-day exact terminal topology is not mandatory."
Assert-True ([bool]$smokeTopology.required -and $smokeTopology.profile -ceq "PUBLIC_SMOKE_120S") "Smoke exact terminal topology is not mandatory."
Assert-True ([bool]$stressTopology.required -and $stressTopology.profile -ceq "ROTATION_STRESS_120M") "120-minute stress exact terminal topology is not mandatory."
Assert-True (-not [bool]$faultTopology.required -and $faultTopology.profile -ceq "AD_HOC_TEST") "Fault-injection Test topology was conflated with the rotation stress."
$lowercaseProductionTopology = Get-RawQualificationRequiredTerminalTopology -Mode production `
    -TotalSeconds 86400 -RotationSeconds 82800 -OverlapSeconds 900 -SegmentSeconds 900
$lowercaseSmokeTopology = Get-RawQualificationRequiredTerminalTopology -Mode smoke `
    -TotalSeconds 120 -RotationSeconds 60 -OverlapSeconds 10 -SegmentSeconds 10
$lowercaseStressTopology = Get-RawQualificationRequiredTerminalTopology -Mode test `
    -TotalSeconds 7200 -RotationSeconds 900 -OverlapSeconds 900 -SegmentSeconds 900
Assert-True ([bool]$lowercaseProductionTopology.required -and [bool]$lowercaseSmokeTopology.required -and
    [bool]$lowercaseStressTopology.required) "ValidateSet-compatible lowercase mode spelling bypassed a required terminal topology."
Assert-True ((Get-RawQualificationGenerationScheduleClassification -Mode production @deviatedScheduleArguments) -ceq
    "DEVIATED") "Lowercase Production spelling bypassed deviated-schedule classification."
Assert-True (Test-RawQualificationRequiredTerminalTopology -Topology $smokeTopology @scheduleArguments) "Exact Smoke cardinality was rejected."
$smokeWrongGenerationArguments = @{} + $scheduleArguments
$smokeWrongGenerationArguments.Generations = [uint64]3
Assert-True (-not (Test-RawQualificationRequiredTerminalTopology -Topology $smokeTopology @smokeWrongGenerationArguments)) "Smoke accepted a third generation."
Assert-True (Test-RawQualificationRequiredTerminalTopology -Topology $stressTopology @stressScheduleArguments) "Exact stress cardinality was rejected."
$stressWrongHandoverArguments = @{} + $stressScheduleArguments
$stressWrongHandoverArguments.Handovers = [uint64]6
Assert-True (-not (Test-RawQualificationRequiredTerminalTopology -Topology $stressTopology @stressWrongHandoverArguments)) "Stress accepted 8/6/8 cardinality."
$stressShutdownArguments = @{} + $stressScheduleArguments
$stressShutdownArguments.ServerShutdownDurableEvents = [uint64]1
Assert-True (-not (Test-RawQualificationRequiredTerminalTopology -Topology $stressTopology @stressShutdownArguments)) "Stress accepted serverShutdown evidence."
$terminalTopologyMutationValues = [ordered]@{
    Generations = [uint64]3
    Handovers = [uint64]0
    PlannedGenerationLaunches = [uint64]1
    ServerShutdownGenerationLaunches = [uint64]1
    ServerShutdownSupervisorEvents = [uint64]1
    ServerShutdownDurableEvents = [uint64]1
}
$terminalTopologyMutantsRejected = [uint64]0
foreach ($field in $terminalTopologyMutationValues.Keys) {
    $mutantArguments = @{} + $scheduleArguments
    $mutantArguments[$field] = $terminalTopologyMutationValues[$field]
    Assert-True (-not (Test-RawQualificationRequiredTerminalTopology `
        -Topology $smokeTopology @mutantArguments)) "Smoke topology mutant bypassed required field $field."
    $terminalTopologyMutantsRejected++
}
Assert-True ($terminalTopologyMutantsRejected -eq 6) "Required terminal topology mutation matrix is incomplete."

$launcherAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot "run_24h_raw_qualification.ps1"),
    [ref]$null,
    [ref]$null)
$monitorAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot "monitor_24h_raw_qualification.ps1"),
    [ref]$null,
    [ref]$null)
$frozenJsonlReaderDefinitions = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Read-MonitorFrozenCanonicalJsonLines'
}, $true))
$campaignJournalHealthDefinitions = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-CampaignJournalHealth'
}, $true))
Assert-True ($frozenJsonlReaderDefinitions.Count -eq 1 -and $campaignJournalHealthDefinitions.Count -eq 1) `
    "Monitor frozen-prefix function extraction was ambiguous."
$frozenJsonlReaderSource = $frozenJsonlReaderDefinitions[0].Extent.Text
$campaignJournalHealthSource = $campaignJournalHealthDefinitions[0].Extent.Text
    foreach ($untypedPrefixFragment in @(
            '[AllowNull()] $ExpectedPrefixLength',
            '[AllowNull()] $ExpectedPrefixSha256',
            '[AllowNull()] $ParseFromOffsetSha256')) {
    Assert-True ($frozenJsonlReaderSource.Contains($untypedPrefixFragment)) `
        "Frozen JSONL reader can coerce an optional null prefix argument: $untypedPrefixFragment"
}
foreach ($untypedPrefixFragment in @(
        '[AllowNull()] $ExpectedPrefixRecords',
        '[AllowNull()] $ExpectedPrefixTerminalRecordSha256',
        '[AllowNull()] $ExpectedPrefixFileLength',
        '[AllowNull()] $ExpectedPrefixFileSha256',
        '[AllowNull()] $ContinuationState')) {
    Assert-True ($campaignJournalHealthSource.Contains($untypedPrefixFragment)) `
        "Campaign journal continuity can coerce an optional null prefix argument: $untypedPrefixFragment"
}
$helperText = Get-Content -LiteralPath $helper -Raw -Encoding UTF8
$resumeSampleIndex = $helperText.IndexOf('Int64 resumeQpcTimestamp = Stopwatch.GetTimestamp();', [StringComparison]::Ordinal)
$resumeThreadIndex = $helperText.IndexOf('UInt32 resume = ResumeThread(process.hThread);', [StringComparison]::Ordinal)
Assert-True ($resumeSampleIndex -ge 0 -and $resumeThreadIndex -gt $resumeSampleIndex) "Native launch helper does not sample QPC immediately before ResumeThread."
$launcherText = $launcherAst.Extent.Text
foreach ($requiredProductionBudgetFragment in @(
        '$PostVerificationDeadlineSeconds = 86400',
        '$IndependentVerifierTimeoutSeconds = 43200',
        'post_verification_deadline_s = 86400',
        'independent_verifier_timeout_s = 43200')) {
    Assert-True ($launcherText.Contains($requiredProductionBudgetFragment)) `
        "Launcher lost the fixed Production verification budget: $requiredProductionBudgetFragment"
}
    $monitorText = $monitorAst.Extent.Text
    $liveCampaignCatchupFragments = @(
        'Historical replay is deliberately off the freshness edge.',
        '-ContinuationState $journal.continuation_state',
        '-ContinuationState $snapshot.continuation_state')
    foreach ($fragment in $liveCampaignCatchupFragments) {
        Assert-True ($monitorText.Contains($fragment)) `
            "Live campaign monitor lost its authenticated incremental catch-up barrier: $fragment"
    }
Assert-True ($monitorText.Contains('[uint64]$startup.verifier_policy.per_process_timeout_s -ne 43200') -and
    $monitorText.Contains('[uint64]$startup.verifier_policy.total_post_capture_timeout_s -ne 86400') -and
    $monitorText.Contains('[uint64]$Terminal.verifier_policy.per_process_timeout_s -ne 43200') -and
    $monitorText.Contains('[uint64]$Terminal.verifier_policy.total_post_capture_timeout_s -ne 86400')) `
    "Monitor does not enforce the fixed Production verification budget at startup and terminal."
Assert-True ($helperText.Contains('public static bool CloseRetainedProcessHandle(RawQualificationLaunchResult launch)') -and
    $helperText.Contains('launch.ProcessHandle = IntPtr.Zero;')) `
    "Native helper cannot atomically close and invalidate its read-only retained process handle."
$nativeRetainedCloseIndex = $helperText.IndexOf('if (!CloseHandle(handle))', [StringComparison]::Ordinal)
$nativeRetainedInvalidateIndex = $helperText.IndexOf('launch.ProcessHandle = IntPtr.Zero;', [StringComparison]::Ordinal)
Assert-True ($nativeRetainedCloseIndex -ge 0 -and
    $nativeRetainedInvalidateIndex -gt $nativeRetainedCloseIndex) `
    "Native retained-handle helper does not invalidate ownership strictly after a successful close."
$stopWatchdogDefinitions = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Stop-GuardianWatchdogClean'
}, $true))
Assert-True ($stopWatchdogDefinitions.Count -eq 1) "Guardian watchdog clean-stop function extraction was ambiguous."
$stopWatchdogSource = $stopWatchdogDefinitions[0].Extent.Text
Assert-True ($stopWatchdogSource.Contains('CloseRetainedProcessHandle($script:watchdogLaunch)') -and
    -not $stopWatchdogSource.Contains('$script:watchdogLaunch.ProcessHandle =') -and
    -not $stopWatchdogSource.Contains('CloseHandle($script:watchdogLaunch.ProcessHandle)')) `
    "Guardian watchdog clean stop can close a read-only handle without atomically invalidating its owner."
Assert-True ($launcherText.Contains('CloseRetainedProcessHandle($watchdogLaunch)') -and
    -not $launcherText.Contains('$watchdogLaunch.ProcessHandle =')) `
    "Guardian watchdog finally path can double-close a stale read-only process handle."
$explicitChildEnvironmentDefinitions = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-ExplicitChildEnvironmentContract'
}, $true))
Assert-True ($explicitChildEnvironmentDefinitions.Count -eq 1) `
    "Explicit child-environment contract extraction was ambiguous."
Invoke-Expression $explicitChildEnvironmentDefinitions[0].Extent.Text
$productionChildEnvironmentContract = Get-ExplicitChildEnvironmentContract
Assert-True ((@($productionChildEnvironmentContract.names) -join ',') -ceq
    'SystemDrive,SystemRoot,TEMP,TMP,WINDIR') `
    "Production child-environment allowlist omits or reorders a required Windows bootstrap variable."
$productionSystemDriveEntry = @($productionChildEnvironmentContract.Entries | Where-Object {
    ([string]$_).StartsWith('SystemDrive=', [StringComparison]::Ordinal)
})
Assert-True ($productionSystemDriveEntry.Count -eq 1 -and
    [string]$productionSystemDriveEntry[0] -ceq
        ('SystemDrive=' + [Environment]::GetEnvironmentVariable('SystemDrive', [EnvironmentVariableTarget]::Process))) `
    "Production child-environment contract does not bind the exact process SystemDrive."
Assert-True ($launcherText.Contains('$Mode = ConvertTo-RawQualificationCanonicalMode -Mode $Mode')) "Launcher does not canonicalize its accepted mode spelling before persistence."
Assert-True ($launcherText.Contains('Get-RawQualificationGenerationScheduleClassification') -and
    $monitorAst.Extent.Text.Contains('Get-RawQualificationGenerationScheduleClassification')) "Launcher and monitor do not share the exact schedule-classification derivation."
Assert-True ($launcherText.Contains('Test-RawQualificationRequiredTerminalTopology') -and
    $monitorAst.Extent.Text.Contains('Test-RawQualificationRequiredTerminalTopology')) "Launcher and monitor do not both enforce the exact required terminal topology."
Assert-True (-not $monitorAst.Extent.Text.Contains('} else { "NON_PRODUCTION_SCHEDULE" }')) "Monitor retained the mode-only schedule-classification branch."
Assert-True ($monitorAst.Extent.Text.Contains('[ValidateRange(10, 30)] [int] $HeartbeatMaxAgeSeconds = 30') -and
    $monitorAst.Extent.Text.Contains('[uint64]$HeartbeatMaxAgeSeconds -gt [uint64]$startup.market_freshness_policy.deadline_s')) `
    "Monitor caller can weaken the authenticated 30-second market-heartbeat deadline."
Assert-True ($monitorAst.Extent.Text.Contains('$declaredEnvironmentNames = @($startup.preflight.child_environment.names)') -and
    $monitorAst.Extent.Text.Contains('$declaredChildEnvironmentNames = @($startup.preflight.child_environment.names)') -and
    $monitorAst.Extent.Text.Contains('($declaredEnvironmentNames -join "`n") -cne ($environmentNames -join "`n")') -and
    $monitorAst.Extent.Text.Contains('($declaredChildEnvironmentNames -join "`n") -cne ($childEnvironmentNames -join "`n")') -and
    $monitorAst.Extent.Text.Contains('(@($control.child_environment_names) -join "`n") -cne ($declaredChildEnvironmentNames -join "`n")')) `
    "Monitor does not bind declared child-environment names exactly to Entries and process control."
$monitorCaptureFreshnessFunctions = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Test-MonitorCaptureRequiresLiveFreshness"
}, $true))
Assert-True ($monitorCaptureFreshnessFunctions.Count -eq 1) "Monitor capture-freshness FSM function extraction was ambiguous."
Invoke-Expression $monitorCaptureFreshnessFunctions[0].Extent.Text
$capturingHistoryContract = [pscustomobject]@{ capture_draining = $null }
$drainingHistoryContract = [pscustomobject]@{ capture_draining = [pscustomobject]@{ event = "CAPTURE_DRAINING_STARTED" } }
$capturingRequiresLiveFreshness = Test-MonitorCaptureRequiresLiveFreshness `
    -LauncherHistoryContract $capturingHistoryContract
$drainingRequiresLiveFreshness = Test-MonitorCaptureRequiresLiveFreshness `
    -LauncherHistoryContract $drainingHistoryContract
$missingCaptureStageRejected = $false
try {
    $null = Test-MonitorCaptureRequiresLiveFreshness `
        -LauncherHistoryContract ([pscustomobject]@{ terminal_evaluation = $null })
}
catch { $missingCaptureStageRejected = $true }
$legacyTelemetryCaptureElapsedMs = [uint64]111208
$legacyTelemetryFreshnessCutoffMs = [uint64]115000
$legacyDrainingRaceWouldRequireLiveFreshness =
    $legacyTelemetryCaptureElapsedMs -lt $legacyTelemetryFreshnessCutoffMs
$lateCapturingTelemetryElapsedMs = [uint64]166478
$lateCapturingTelemetryWouldPreviouslyDisableFreshness =
    $lateCapturingTelemetryElapsedMs -ge $legacyTelemetryFreshnessCutoffMs
Assert-True ($capturingRequiresLiveFreshness -and -not $drainingRequiresLiveFreshness -and
    $missingCaptureStageRejected) "Monitor live-freshness obligation is not bound fail-closed to the validated launcher FSM."
Assert-True ($legacyDrainingRaceWouldRequireLiveFreshness -and -not $drainingRequiresLiveFreshness) `
    "DRAINING with a pre-cutoff final telemetry sample did not reproduce and eliminate the legacy monitor race."
Assert-True ($lateCapturingTelemetryWouldPreviouslyDisableFreshness -and $capturingRequiresLiveFreshness) `
    "CAPTURING without a durable DRAINING event allowed elapsed telemetry to disable live freshness."
Assert-True (-not $monitorAst.Extent.Text.Contains('$captureStageComplete')) `
    "Monitor still derives capture-stage completion from telemetry elapsed time."
$monitorCaptureFreshnessSource = $monitorCaptureFreshnessFunctions[0].Extent.Text
Assert-True ($monitorCaptureFreshnessSource.Contains("PSObject.Properties['capture_draining']") -and
    -not $monitorCaptureFreshnessSource.Contains('telemetry') -and
    -not $monitorCaptureFreshnessSource.Contains('Elapsed')) `
    "Monitor capture-freshness helper grants elapsed telemetry authority over launcher phase."
Assert-True (-not $monitorCaptureFreshnessSource.Replace('capture_draining', 'capture_elapsed_ms').Contains(
        "PSObject.Properties['capture_draining']")) `
    "Monitor capture-phase authority mutant was not rejected."
$monitorCaptureFreshnessCalls = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq "Test-MonitorCaptureRequiresLiveFreshness"
}, $true))
Assert-True ($monitorCaptureFreshnessCalls.Count -eq 2) `
    "Monitor does not derive initial and final live-freshness obligations from validated launcher FSM prefixes."
$monitorText = $monitorAst.Extent.Text
$derivedVerifierNameAssignments = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -in @('$expectedNames', '$expectedVerifierNames') -and
        $node.Extent.Text.Contains('ToLowerInvariant')
}, $true))
Assert-True ($derivedVerifierNameAssignments.Count -eq 2) `
    "Monitor derived verifier-name array assignments were ambiguous."
foreach ($assignment in $derivedVerifierNameAssignments) {
    $convertedExpression = $assignment.Right.Expression
    $arrayExpression = $convertedExpression.Child
    Assert-True ($convertedExpression -is [Management.Automation.Language.ConvertExpressionAst] -and
        $convertedExpression.Type.TypeName.FullName -ceq 'string[]' -and
        $arrayExpression -is [Management.Automation.Language.ArrayExpressionAst] -and
        @($arrayExpression.SubExpression.Statements).Count -eq 2) `
        "Monitor collapsed the derived Rust/Python verifier names into one PowerShell comma expression."
}
$verifierNameContainmentExpressions = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.BinaryExpressionAst] -and
        $node.Left.Extent.Text -ceq '$expectedVerifierNames' -and
        $node.Operator.ToString() -in @('Inotcontains', 'Cnotcontains')
}, $true))
Assert-True ($verifierNameContainmentExpressions.Count -eq 2 -and
    @($verifierNameContainmentExpressions | Where-Object {
        $_.Operator.ToString() -cne 'Cnotcontains'
    }).Count -eq 0) `
    "Monitor accepts case-mismatched verifier identities in an exact set."
$verifierNameFixtureSymbol = 'BTCUSDT'
$collapsedVerifierNameMutant = @(
    $verifierNameFixtureSymbol.ToLowerInvariant() + '-rust',
    $verifierNameFixtureSymbol.ToLowerInvariant() + '-python'
)
$derivedVerifierNameFixture = [string[]]@(
    ($verifierNameFixtureSymbol.ToLowerInvariant() + '-rust')
    ($verifierNameFixtureSymbol.ToLowerInvariant() + '-python')
)
Assert-True ($collapsedVerifierNameMutant.Count -eq 1 -and
    $collapsedVerifierNameMutant[0] -ceq 'btcusdt-rust btcusdt-python' -and
    $derivedVerifierNameFixture.Count -eq 2 -and
    $derivedVerifierNameFixture[0] -ceq 'btcusdt-rust' -and
    $derivedVerifierNameFixture[1] -ceq 'btcusdt-python' -and
    $derivedVerifierNameFixture -cnotcontains 'BTCUSDT-RUST') `
    "PowerShell verifier-name collapse/case mutant was not reproduced and rejected."
$exactVerifierSetPredicate = {
    param([object[]] $Actual, [string[]] $Expected)
    $values = @($Actual)
    return $values.Count -eq 2 -and
        @($values | Select-Object -Unique).Count -eq 2 -and
        @($values | Where-Object { $Expected -cnotcontains $_ }).Count -eq 0
}
$verifierSetValidAccepted = [bool](& $exactVerifierSetPredicate `
    -Actual @('btcusdt-rust', 'btcusdt-python') -Expected $derivedVerifierNameFixture)
$verifierSetReversedAccepted = [bool](& $exactVerifierSetPredicate `
    -Actual @('btcusdt-python', 'btcusdt-rust') -Expected $derivedVerifierNameFixture)
$verifierSetDuplicateRejected = -not [bool](& $exactVerifierSetPredicate `
    -Actual @('btcusdt-rust', 'btcusdt-rust') -Expected $derivedVerifierNameFixture)
$verifierSetMissingRejected = -not [bool](& $exactVerifierSetPredicate `
    -Actual @('btcusdt-rust') -Expected $derivedVerifierNameFixture)
$verifierSetExtraRejected = -not [bool](& $exactVerifierSetPredicate `
    -Actual @('btcusdt-rust', 'btcusdt-python', 'btcusdt-extra') -Expected $derivedVerifierNameFixture)
$verifierSetCaseRejected = -not [bool](& $exactVerifierSetPredicate `
    -Actual @('BTCUSDT-RUST', 'btcusdt-python') -Expected $derivedVerifierNameFixture)
Assert-True ($verifierSetValidAccepted -and $verifierSetReversedAccepted -and
    $verifierSetDuplicateRejected -and $verifierSetMissingRejected -and
    $verifierSetExtraRejected -and $verifierSetCaseRejected) `
    "Monitor exact verifier-set predicate did not reject every cardinality/name/case mutant."
$linearizedLauncherReadIndex = $monitorText.IndexOf('$linearizedLauncherJournal = Get-VerifiedJournalSummary', [StringComparison]::Ordinal)
$linearizedHistoryIndex = $monitorText.IndexOf('$linearizedLauncherHistoryContract = Assert-LauncherEventHistory', [StringComparison]::Ordinal)
$linearizedFreshnessIndex = $monitorText.IndexOf('$linearizedCaptureRequiresLiveFreshness = Test-MonitorCaptureRequiresLiveFreshness', [StringComparison]::Ordinal)
$finalCampaignReadIndex = $monitorText.IndexOf('foreach ($snapshot in $liveCampaignJournalSnapshots)', $linearizedFreshnessIndex, [StringComparison]::Ordinal)
$publicationLauncherReadIndex = $monitorText.IndexOf('$publicationLauncherJournal = Get-VerifiedJournalSummary', [StringComparison]::Ordinal)
$publicationLauncherAssignments = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$publicationLauncherJournal'
}, $true))
Assert-True ($publicationLauncherAssignments.Count -eq 1) `
    "Final launcher publication census assignment extraction was ambiguous."
$publicationLauncherReadCommands = @($publicationLauncherAssignments[0].FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'Get-VerifiedJournalSummary'
}, $true))
Assert-True ($publicationLauncherReadCommands.Count -eq 1) `
    "Final launcher publication census command extraction was ambiguous."
$publicationLauncherReadEndOffset = $publicationLauncherReadCommands[0].Extent.EndOffset
$finalTreeBarrierIndex = $monitorText.LastIndexOf('$null = Assert-MonitorEvidenceTreeNoReparsePoints', [StringComparison]::Ordinal)
$publicationFreshnessSampleIndex = $monitorText.IndexOf('$publicationObservedNowNs = Get-RawQualificationWallNs', [StringComparison]::Ordinal)
$monitorStageIndex = $monitorText.IndexOf('$monitorStage = Get-MonitorEventDrivenStage', [StringComparison]::Ordinal)
$postPublicationCensusCommandNames = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
        $node.Extent.StartOffset -ge $publicationLauncherReadEndOffset
}, $true) | ForEach-Object { $_.GetCommandName() } | Sort-Object -Unique)
$postPublicationCensusMemberCalls = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and
        $node.Extent.StartOffset -ge $publicationLauncherReadEndOffset
}, $true))
$postPublicationCensusMemberSignatures = @($postPublicationCensusMemberCalls | ForEach-Object {
    $_.Expression.Extent.Text + '|' + $_.Member.Extent.Text + '|' + [string]$_.Static
} | Sort-Object -Unique)
Assert-True ($linearizedLauncherReadIndex -ge 0 -and
    $linearizedHistoryIndex -gt $linearizedLauncherReadIndex -and
    $linearizedFreshnessIndex -gt $linearizedHistoryIndex -and
    $finalCampaignReadIndex -gt $linearizedFreshnessIndex -and
    $finalTreeBarrierIndex -gt $linearizedFreshnessIndex -and
    $finalTreeBarrierIndex -lt $publicationLauncherReadIndex -and
    $publicationLauncherReadIndex -gt $finalCampaignReadIndex -and
    $publicationFreshnessSampleIndex -gt $publicationLauncherReadIndex -and
    $monitorStageIndex -gt $publicationLauncherReadIndex) `
    "Live monitor publication is not enclosed by authenticated launcher FSM relinearization and a final census."
Assert-True (($postPublicationCensusCommandNames -join ',') -ceq 'ConvertTo-Json,Get-MonitorEventDrivenStage,Get-RawQualificationWallNs,Where-Object') `
    "Monitor performs non-pure command I/O after its final launcher publication census."
Assert-True ($postPublicationCensusMemberCalls.Count -eq 5 -and
    ($postPublicationCensusMemberSignatures -join ',') -ceq
        '[DateTimeOffset]::UtcNow|ToString|False,[math]|Floor|True,[math]|Round|True') `
    "Monitor performs an unreviewed .NET member call after its final launcher publication census."
$preCensusHeartbeatAgeSeconds = [double]29.9
$postCensusHeartbeatAgeSeconds = [double]30.1
$legacyPreCensusFreshnessWouldPass = $preCensusHeartbeatAgeSeconds -le 30
$postCensusFreshnessRejectsCrossing = $postCensusHeartbeatAgeSeconds -gt 30
Assert-True ($legacyPreCensusFreshnessWouldPass -and $postCensusFreshnessRejectsCrossing -and
    $monitorText.IndexOf('$campaignAgeSeconds = [double]($publicationObservedNowNs', [StringComparison]::Ordinal) -gt
        $publicationLauncherReadIndex) `
    "Monitor does not reject a heartbeat that crosses 30 seconds during final evidence I/O."
$failedCampaignResultValidators = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Assert-MonitorFailedCampaignResultEvidence"
}, $true))
Assert-True ($failedCampaignResultValidators.Count -eq 1 -and
    -not $failedCampaignResultValidators[0].Extent.Text.Contains('Test-RawQualificationRequiredTerminalTopology')) "FAILED result inspection incorrectly requires a promotable topology."
$completeTopologyBranches = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text.Contains('if ($terminalComplete)') -and
        $node.Extent.Text.Contains('Test-RawQualificationRequiredTerminalTopology')
}, $true))
Assert-True ($completeTopologyBranches.Count -eq 1) "Monitor COMPLETE path lacks one exact required-topology gate."
$completeTopologyText = $completeTopologyBranches[0].Extent.Text
Assert-True ($completeTopologyText.IndexOf('$terminalCampaign = @(', [StringComparison]::Ordinal) -ge 0 -and
    $completeTopologyText.IndexOf('Test-RawQualificationRequiredTerminalTopology', [StringComparison]::Ordinal) -gt
        $completeTopologyText.IndexOf('$terminalCampaign = @(', [StringComparison]::Ordinal)) "Monitor COMPLETE topology is not checked after binding its exact terminal campaign result."
$completeTopologyCrossBindingFragments = @(
    '[uint64]$terminalCampaign[0].generations -ne [uint64]@($campaignManifest.generations).Count',
    '[uint64]$terminalCampaign[0].handovers -ne [uint64]@($campaignManifest.handovers).Count',
    '[uint64]$terminalCampaign[0].planned_generation_launches -ne [uint64]$journal.planned_generation_launches',
    '[uint64]$terminalCampaign[0].server_shutdown_generation_launches -ne [uint64]$journal.server_shutdown_generation_launches',
    '[uint64]$terminalCampaign[0].server_shutdown_supervisor_events -ne [uint64]$journal.server_shutdown_supervisor_events',
    '[uint64]$terminalCampaign[0].server_shutdown_durable_events -ne [uint64]$journal.server_shutdown_durable_events',
    '[string]$terminalCampaign[0].generation_schedule_classification -cne $expectedSchedule'
)
foreach ($fragment in $completeTopologyCrossBindingFragments) {
    Assert-True ($completeTopologyText.Contains($fragment)) "Monitor COMPLETE lost exact topology cross-binding: $fragment"
}
Assert-True ($launcherText.Contains('ResumeQpcTimestamp - [int64]$monotonicOrigin')) "Coordinator timing is not derived from the native pre-Resume QPC sample."
$readyOpenFunction = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Open-WatchdogReadyRetained"
}, $true))
Assert-True ($readyOpenFunction.Count -eq 1) "Retained watchdog READY reader extraction was ambiguous."
Invoke-Expression $readyOpenFunction[0].Extent.Text
Assert-True ($readyOpenFunction[0].Extent.Text.Contains('$win32Code -eq 32 -or $win32Code -eq 33')) "READY reader does not restrict retry to sharing/lock violations."
Assert-True ($launcherText.Contains('$watchdogReadyStream = $candidateReady.Stream') -and
    $launcherText.Contains('$watchdogReadyStream.Dispose()')) "Launcher does not retain and finally close the READY identity handle."
$readinessPublicationBlocks = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text.Contains('event = "DUAL_SEMANTIC_READINESS"') -and
        $node.Extent.Text.Contains('Write-Host "READY: BTCUSDT and ETHUSDT')
}, $true))
Assert-True ($readinessPublicationBlocks.Count -eq 1) "Dual-readiness publication block extraction was ambiguous."
$readinessPublicationText = $readinessPublicationBlocks[0].Extent.Text
$readinessProbeIndex = $readinessPublicationText.IndexOf('$readinessProbe = Invoke-BoundedHostTelemetryProbe', [StringComparison]::Ordinal)
$readinessTelemetryIndex = $readinessPublicationText.IndexOf('Write-HostTelemetrySample', [StringComparison]::Ordinal)
$readinessPreCommitRevalidationIndex = $readinessPublicationText.IndexOf('Assert-DualReadinessPublicationCurrent', $readinessTelemetryIndex, [StringComparison]::Ordinal)
$readinessPostCommitRevalidationIndex = $readinessPublicationText.IndexOf('Assert-DualReadinessPublicationCurrent', $readinessPreCommitRevalidationIndex + 1, [StringComparison]::Ordinal)
$readinessReceiptIndex = $readinessPublicationText.IndexOf('event = "DUAL_READINESS_PUBLISHED"', [StringComparison]::Ordinal)
$readinessCadenceIndex = $readinessPublicationText.IndexOf('$lastTelemetryTick = Get-MonotonicTick', [StringComparison]::Ordinal)
$readinessConsoleIndex = $readinessPublicationText.IndexOf('Write-Host "READY: BTCUSDT and ETHUSDT', [StringComparison]::Ordinal)
Assert-True ($readinessProbeIndex -ge 0 -and
    $readinessTelemetryIndex -gt $readinessProbeIndex -and
    $readinessPreCommitRevalidationIndex -gt $readinessTelemetryIndex -and
    $readinessPostCommitRevalidationIndex -gt $readinessPreCommitRevalidationIndex -and
    $readinessReceiptIndex -gt $readinessPostCommitRevalidationIndex -and
    $readinessCadenceIndex -gt $readinessReceiptIndex -and
    $readinessConsoleIndex -gt $readinessCadenceIndex) "Readiness is not ordered provider -> telemetry pre-commit revalidation -> durable telemetry -> post-commit revalidation -> receipt -> cadence -> console READY."
Assert-True ($readinessPublicationText.Contains('-MonotonicTick ([uint64]$readinessPublicationTick)') -and
    $readinessPublicationText.Contains('[uint64]$readinessPublicationTick -le [uint64]$readinessHostReceipt.monotonic_tick')) "DUAL_READINESS_PUBLISHED is not bound to an advancing post-host liveness candidate tick."
Assert-True ($readinessPublicationText.Contains('elseif (([double]($nowTick - $lastTelemetryTick)')) "Readiness telemetry can be duplicated by the normal cadence branch in the same loop."
$hostTelemetryFunctions = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Write-HostTelemetrySample"
}, $true))
Assert-True ($hostTelemetryFunctions.Count -eq 1) "Host telemetry writer extraction was ambiguous."
$hostTelemetryFunctionText = $hostTelemetryFunctions[0].Extent.Text
$hostTelemetrySummaryIndex = $hostTelemetryFunctionText.IndexOf('campaigns = @(Get-StateSummary)', [StringComparison]::Ordinal)
$hostTelemetryJournalIndex = $hostTelemetryFunctionText.IndexOf('Add-RawQualificationJournalRecord', [StringComparison]::Ordinal)
Assert-True ($hostTelemetrySummaryIndex -ge 0 -and $hostTelemetryJournalIndex -gt $hostTelemetrySummaryIndex) "Readiness publication is not linked to a durable host record written after Get-StateSummary."
Assert-True ($hostTelemetryFunctionText.IndexOf('& $PreCommitAction', [StringComparison]::Ordinal) -ge 0 -and
    $hostTelemetryFunctionText.IndexOf('& $PreCommitAction', [StringComparison]::Ordinal) -lt $hostTelemetrySummaryIndex) "Host telemetry does not execute readiness revalidation immediately before materializing its campaign summary."
foreach ($requiredReceiptFragment in @(
    '$recordIndex = [uint64]$script:telemetryJournal.NextIndex',
    'record_index = $recordIndex',
    'record_sha256 = [string]$recordSha256',
    'monotonic_tick = [uint64]$recordTick')) {
    Assert-True ($hostTelemetryFunctionText.Contains($requiredReceiptFragment)) "Host telemetry writer lost exact receipt fragment: $requiredReceiptFragment"
}
$readinessRevalidationFunctions = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Assert-DualReadinessPublicationCurrent"
}, $true))
Assert-True ($readinessRevalidationFunctions.Count -eq 1) "Readiness revalidation function extraction was ambiguous."
$readinessRevalidationText = $readinessRevalidationFunctions[0].Extent.Text
foreach ($requiredFragment in @(
    'Read-StateOutput -State $state',
    'Read-StateCampaignEvents -State $state',
    '$state.Ready = Test-StateReady -State $state',
    '$observedTick = Get-MonotonicTick',
    'Assert-CoordinatorNativeLivenessAfterTick',
    '$state.ActiveProcesses -lt 1',
    '$state.LastHeartbeatTick',
    '$state.LastSemanticTick')) {
    Assert-True ($readinessRevalidationText.Contains($requiredFragment)) "Readiness revalidation lost required production fragment: $requiredFragment"
}
$readinessCandidateTickIndex = $readinessRevalidationText.IndexOf('$observedTick = Get-MonotonicTick', [StringComparison]::Ordinal)
$readinessNativeLivenessIndex = $readinessRevalidationText.IndexOf('Assert-CoordinatorNativeLivenessAfterTick', [StringComparison]::Ordinal)
Assert-True ($readinessCandidateTickIndex -ge 0 -and $readinessNativeLivenessIndex -gt $readinessCandidateTickIndex) "Readiness does not prove original-handle liveness after its publication candidate tick."
Assert-True (-not $readinessRevalidationText.Contains('$state.Process.HasExited')) "Readiness still trusts PID-reusable Diagnostics.Process liveness."
foreach ($functionName in @(
    "Get-MonotonicTick",
    "Close-CoordinatorNativeProcessHandle",
    "Assert-CoordinatorNativeLivenessAfterTick")) {
    $definition = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
    }, $true))
    Assert-True ($definition.Count -eq 1) "Coordinator native-handle function extraction was ambiguous: $functionName"
    Invoke-Expression $definition[0].Extent.Text
}
$nativeLivenessFunctionText = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Assert-CoordinatorNativeLivenessAfterTick"
}, $true))[0].Extent.Text
$nativeLivenessTickIndex = $nativeLivenessFunctionText.IndexOf('$livenessCheckTick = Get-MonotonicTick', [StringComparison]::Ordinal)
$nativeLivenessWaitIndex = $nativeLivenessFunctionText.IndexOf('WaitForProcessExit([IntPtr]$owner.ProcessHandle, 0)', [StringComparison]::Ordinal)
Assert-True ($nativeLivenessTickIndex -ge 0 -and $nativeLivenessWaitIndex -gt $nativeLivenessTickIndex) "Original coordinator handle is not checked after the exact liveness observation tick."
Assert-True (-not $launcherText.Contains('CloseHandle($childLaunch.ProcessHandle)')) "Coordinator CreateProcess handle is still closed directly instead of transferred to exact ownership."
Assert-True ($launcherText.Contains('ProcessHandleOwner = $handleOwner') -and
    $launcherText.Contains('WaitForProcessExit([IntPtr]$handleOwner.ProcessHandle, 0)') -and
    $launcherText.Contains('GetProcessExitCode([IntPtr]$handleOwner.ProcessHandle)') -and
    $launcherText.Contains('foreach ($handleOwner in @($coordinatorProcessHandleOwners))')) "Coordinator native handles are not retained through lifecycle and uniquely disposed in finally."

$invokeReadinessPublicationCase = {
    param(
        [bool] $SimulateReadinessLoss,
        [bool] $SimulateTelemetryFailure,
        [bool] $SimulatePostTelemetryReadinessLoss
    )
    $readinessPublicationTrace = [Collections.Generic.List[string]]::new()
    function Write-RawQualificationDurableNewJson {
        param($Path, $Value)
        $null = $readinessPublicationTrace.Add("BINDINGS")
        return ('a' * 64)
    }
    function Write-LauncherEvent {
        param($Channel, $Payload, $MonotonicTick)
        $null = $readinessPublicationTrace.Add("EVENT:$($Payload.event)")
    }
    function Invoke-BoundedHostTelemetryProbe {
        $null = $readinessPublicationTrace.Add("PROBE")
        if ($SimulateReadinessLoss) { $states.BTCUSDT.Ready = $false }
        return [pscustomobject]@{ telemetry = [pscustomobject]@{ token = "probe" }; execution = [pscustomobject]@{ token = "execution" } }
    }
    function Assert-DualReadinessPublicationCurrent {
        $script:readinessRevalidationCount = [uint64]($script:readinessRevalidationCount + 1)
        $null = $readinessPublicationTrace.Add("REVALIDATE")
        if (@($states.Values | Where-Object { -not $_.Ready }).Count -ne 0) {
            throw "Synthetic campaign lost readiness during provider execution."
        }
        return [uint64](4220 + (10 * $script:readinessRevalidationCount))
    }
    function Write-HostTelemetrySample {
        param($Probe, [scriptblock] $PreCommitAction)
        if ($null -eq $Probe -or $Probe.telemetry.token -ne "probe" -or $Probe.execution.token -ne "execution") {
            throw "Dynamic readiness publication did not reuse its bounded provider result."
        }
        $null = & $PreCommitAction
        if ($SimulateTelemetryFailure) {
            $null = $readinessPublicationTrace.Add("TELEMETRY_THROW")
            throw "Synthetic durable host telemetry failure."
        }
        $readyCount = @($states.Values | Where-Object { $_.Ready }).Count
        $null = $readinessPublicationTrace.Add("TELEMETRY:$readyCount")
        if ($SimulatePostTelemetryReadinessLoss) { $states.ETHUSDT.Ready = $false }
        return [pscustomobject]@{
            record_index = [uint64]7
            record_sha256 = ('d' * 64)
            monotonic_tick = [uint64]4230
        }
    }
    function Get-MonotonicTick {
        $null = $readinessPublicationTrace.Add("TICK")
        return [uint64]4242
    }
    function Write-Host {
        param([Parameter(Position = 0)] $Object)
        if ($Object.ToString().StartsWith("READY: BTCUSDT", [StringComparison]::Ordinal)) {
            $null = $readinessPublicationTrace.Add("CONSOLE:READY")
        }
        else { throw "Dynamic readiness publication emitted an unexpected console message." }
    }
    $bindingsWritten = $false
    $script:readinessRevalidationCount = [uint64]0
    $bindingsSha256 = $null
    $runId = "readiness-publication-selftest"
    $runRoot = $repo
    $lastTelemetryTick = [uint64]1
    $nowTick = [uint64]100
    $monotonicFrequency = [long]10000000
    $TelemetryIntervalSeconds = 30
    $states = @{
        BTCUSDT = [pscustomobject]@{
            Symbol = "BTCUSDT"; Ready = $true; ProcessId = [uint32]1001
            CampaignId = "btc-ready"; CampaignDirectory = "btc"; CampaignStartupSha256 = ('b' * 64)
        }
        ETHUSDT = [pscustomobject]@{
            Symbol = "ETHUSDT"; Ready = $true; ProcessId = [uint32]1002
            CampaignId = "eth-ready"; CampaignDirectory = "eth"; CampaignStartupSha256 = ('c' * 64)
        }
    }
    $caseError = $null
    try { Invoke-Expression $readinessPublicationText }
    catch { $caseError = $_.Exception.Message }
    return [pscustomobject]@{
        trace = @($readinessPublicationTrace)
        error = $caseError
        bindings_written = [bool]$bindingsWritten
        last_telemetry_tick = [uint64]$lastTelemetryTick
    }
}
$readinessHealthyCase = & $invokeReadinessPublicationCase $false $false $false
$readinessTrace = @($readinessHealthyCase.trace)
Assert-True ([string]::IsNullOrWhiteSpace([string]$readinessHealthyCase.error)) "Dynamic healthy readiness publication failed."
Assert-True $readinessHealthyCase.bindings_written "Dynamic readiness publication did not commit its bindings state."
Assert-True ($readinessHealthyCase.last_telemetry_tick -eq 4242) "Dynamic readiness publication did not advance the telemetry cadence cursor from the post-sample tick."
Assert-True (@($readinessTrace | Where-Object { $_ -eq "TELEMETRY:2" }).Count -eq 1) "Dynamic readiness publication did not write exactly one dual-ready host sample."
$expectedReadinessTrace = @("BINDINGS", "EVENT:DUAL_SEMANTIC_READINESS", "PROBE", "REVALIDATE", "TELEMETRY:2", "REVALIDATE", "EVENT:DUAL_READINESS_PUBLISHED", "TICK", "CONSOLE:READY")
Assert-True (($readinessTrace -join '|') -eq ($expectedReadinessTrace -join '|')) "Dynamic readiness publication order is not BINDINGS -> EVENT -> provider -> revalidation -> dual-ready TELEMETRY -> cadence TICK -> console READY."
$dynamicTelemetryIndex = [array]::IndexOf($readinessTrace, "TELEMETRY:2")
$dynamicReceiptIndex = [array]::IndexOf($readinessTrace, "EVENT:DUAL_READINESS_PUBLISHED")
$dynamicConsoleIndex = [array]::IndexOf($readinessTrace, "CONSOLE:READY")
$readinessLossCase = & $invokeReadinessPublicationCase $true $false $false
$readinessLossTrace = @($readinessLossCase.trace)
Assert-True (-not [string]::IsNullOrWhiteSpace([string]$readinessLossCase.error)) "Readiness loss during the provider probe did not fail closed."
Assert-True (($readinessLossTrace -join '|') -eq "BINDINGS|EVENT:DUAL_SEMANTIC_READINESS|PROBE|REVALIDATE") "Readiness loss during provider execution reached telemetry or console publication."
$readinessTelemetryFailureCase = & $invokeReadinessPublicationCase $false $true $false
$readinessTelemetryFailureTrace = @($readinessTelemetryFailureCase.trace)
Assert-True (-not [string]::IsNullOrWhiteSpace([string]$readinessTelemetryFailureCase.error)) "Durable readiness telemetry failure did not fail closed."
Assert-True (($readinessTelemetryFailureTrace -join '|') -eq "BINDINGS|EVENT:DUAL_SEMANTIC_READINESS|PROBE|REVALIDATE|TELEMETRY_THROW") "Durable readiness telemetry failure reached cadence or console READY publication."
$readinessPostTelemetryLossCase = & $invokeReadinessPublicationCase $false $false $true
$readinessPostTelemetryLossTrace = @($readinessPostTelemetryLossCase.trace)
Assert-True (-not [string]::IsNullOrWhiteSpace([string]$readinessPostTelemetryLossCase.error)) "Readiness loss after durable host telemetry did not fail closed before receipt publication."
Assert-True (($readinessPostTelemetryLossTrace -join '|') -eq "BINDINGS|EVENT:DUAL_SEMANTIC_READINESS|PROBE|REVALIDATE|TELEMETRY:2|REVALIDATE") "Post-telemetry readiness loss reached receipt, cadence, or console READY publication."

$immediateMonitorGates = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text.Contains('CAMPAIGN_HEARTBEAT is stale or semantically inactive.')
}, $true))
Assert-True ($immediateMonitorGates.Count -eq 1) "Immediate monitor readiness gate extraction was ambiguous."
$record = [pscustomobject]@{ symbol = "BTCUSDT" }
$originalRunning = $true
$lastStdoutHeartbeat = [pscustomobject]@{ event = "CAMPAIGN_HEARTBEAT" }
$captureRequiresLiveFreshness = $true
$campaignHeartbeatLagSeconds = [double]0
$HeartbeatMaxAgeSeconds = 30
$hostCampaign = @([pscustomobject]@{ ready = $true; generations = [uint64]1; active_processes = [uint64]1 })
Invoke-Expression $immediateMonitorGates[0].Extent.Text
$immediateReadyHostAccepted = $true
$hostCampaign[0].ready = $false
$preReadinessHostRejected = $false
try { Invoke-Expression $immediateMonitorGates[0].Extent.Text }
catch { $preReadinessHostRejected = $true }
Assert-True $preReadinessHostRejected "Immediate monitor accepted a pre-readiness host sample."
$watchdogLaunchOriginIndex = $launcherText.IndexOf('$watchdogLaunchOriginQpcTimestamp = [Diagnostics.Stopwatch]::GetTimestamp()', [StringComparison]::Ordinal)
$watchdogCreateIndex = $launcherText.IndexOf('$watchdogLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(', [StringComparison]::Ordinal)
$watchdogReadyValidationIndex = $launcherText.IndexOf('$watchdogIdentity.ready_file_sha256 = Get-RawQualificationSha256Bytes', [StringComparison]::Ordinal)
$firstCoordinatorIndex = $launcherText.IndexOf(
    'foreach ($symbol in @("BTCUSDT", "ETHUSDT"))',
    $watchdogCreateIndex,
    [StringComparison]::Ordinal)
Assert-True ($watchdogLaunchOriginIndex -ge 0 -and $watchdogCreateIndex -gt $watchdogLaunchOriginIndex) "Watchdog startup origin is not sampled before CreateProcess."
Assert-True ($watchdogReadyValidationIndex -gt $watchdogCreateIndex -and $firstCoordinatorIndex -gt $watchdogReadyValidationIndex) "Dual coordinators can launch before the watchdog READY contract is validated."
$dispositionFunction = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Get-MonitorCoordinatorProcessDisposition"
}, $true))
Assert-True ($dispositionFunction.Count -eq 1) "Coordinator disposition function extraction was ambiguous."
Invoke-Expression $dispositionFunction[0].Extent.Text
$nonterminalReuse = Get-MonitorCoordinatorProcessDisposition `
    -Symbol "BTCUSDT" `
    -Identity ([pscustomobject]@{ running = $true; valid = $false }) `
    -CleanCaptureExit $true `
    -TerminalComplete $false
Assert-True (-not $nonterminalReuse.original_running -and $nonterminalReuse.pid_reused_after_exit) "DRAINING/VERIFYING rejected legitimate post-exit PID reuse."
$reuseWithoutExitRejected = $false
try {
    $null = Get-MonitorCoordinatorProcessDisposition `
        -Symbol "BTCUSDT" `
        -Identity ([pscustomobject]@{ running = $true; valid = $false }) `
        -CleanCaptureExit $false `
        -TerminalComplete $false
}
catch { $reuseWithoutExitRejected = $true }
Assert-True $reuseWithoutExitRejected "Nonterminal foreign PID reuse passed without clean exit proof."
$coordinatorDispositionCases = @(
    [pscustomobject]@{ name = "live_original_running"; running = $true; valid = $true; clean = $false; terminal = $false; reject = $false; original = $true; reused = $false },
    [pscustomobject]@{ name = "live_original_running_with_exit"; running = $true; valid = $true; clean = $true; terminal = $false; reject = $true; original = $false; reused = $false },
    [pscustomobject]@{ name = "terminal_original_running_with_exit"; running = $true; valid = $true; clean = $true; terminal = $true; reject = $true; original = $false; reused = $false },
    [pscustomobject]@{ name = "live_foreign_reuse_with_exit"; running = $true; valid = $false; clean = $true; terminal = $false; reject = $false; original = $false; reused = $true },
    [pscustomobject]@{ name = "terminal_foreign_reuse_with_exit"; running = $true; valid = $false; clean = $true; terminal = $true; reject = $false; original = $false; reused = $true },
    [pscustomobject]@{ name = "live_foreign_reuse_without_exit"; running = $true; valid = $false; clean = $false; terminal = $false; reject = $true; original = $false; reused = $false },
    [pscustomobject]@{ name = "live_absent_with_exit"; running = $false; valid = $false; clean = $true; terminal = $false; reject = $false; original = $false; reused = $false },
    [pscustomobject]@{ name = "terminal_absent_with_exit"; running = $false; valid = $false; clean = $true; terminal = $true; reject = $false; original = $false; reused = $false },
    [pscustomobject]@{ name = "live_absent_without_exit"; running = $false; valid = $false; clean = $false; terminal = $false; reject = $true; original = $false; reused = $false },
    [pscustomobject]@{ name = "terminal_absent_without_exit"; running = $false; valid = $false; clean = $false; terminal = $true; reject = $true; original = $false; reused = $false })
foreach ($case in $coordinatorDispositionCases) {
    $actualRejected = $false
    $actualDisposition = $null
    try {
        $actualDisposition = Get-MonitorCoordinatorProcessDisposition `
            -Symbol "BTCUSDT" `
            -Identity ([pscustomobject]@{ running = [bool]$case.running; valid = [bool]$case.valid }) `
            -CleanCaptureExit ([bool]$case.clean) `
            -TerminalComplete ([bool]$case.terminal)
    }
    catch { $actualRejected = $true }
    Assert-True ($actualRejected -eq [bool]$case.reject) "Coordinator disposition truth-table mismatch: $($case.name)"
    if (-not $actualRejected) {
        Assert-True ([bool]$actualDisposition.original_running -eq [bool]$case.original) "Coordinator original-running result mismatch: $($case.name)"
        Assert-True ([bool]$actualDisposition.pid_reused_after_exit -eq [bool]$case.reused) "Coordinator PID-reuse result mismatch: $($case.name)"
    }
}
$coordinatorDispositionTruthTablePassed = $true
$readyEvidenceFunction = @($monitorAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Get-MonitorWatchdogReadyEvidence"
}, $true))
Assert-True ($readyEvidenceFunction.Count -eq 1) "Watchdog READY verifier extraction was ambiguous."
foreach ($readyDependencyName in @(
    "Test-MonitorExactJsonProperties",
    "Test-MonitorExactJsonPropertyOrder",
    "Test-MonitorByteArraysEqual",
    "ConvertTo-MonitorTwoSpacePrettyJsonBytes",
    "Read-MonitorCanonicalJsonSnapshot")) {
    $readyDependency = @($monitorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $readyDependencyName
    }, $true))
    Assert-True ($readyDependency.Count -eq 1) "Watchdog READY dependency extraction was ambiguous: $readyDependencyName"
    Invoke-Expression $readyDependency[0].Extent.Text
}
Invoke-Expression $readyEvidenceFunction[0].Extent.Text
$ExpectedGuardianWatchdogStartupDeadlineSeconds = [uint64]90
$projectionFunction = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Get-ConservativeRemainingProjectionGiB"
}, $true))
Assert-True ($projectionFunction.Count -eq 1) "Projection function extraction was ambiguous."
Invoke-Expression $projectionFunction[0].Extent.Text
$captureClockFunction = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Get-CaptureElapsedSeconds"
}, $true))
Assert-True ($captureClockFunction.Count -eq 1) "Capture clock function extraction was ambiguous."
Invoke-Expression $captureClockFunction[0].Extent.Text
$terminalEvidenceFunction = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq "Test-AllGenerationTerminalEvidence"
}, $true))
Assert-True ($terminalEvidenceFunction.Count -eq 1) "Terminal-evidence function extraction was ambiguous."
Invoke-Expression $terminalEvidenceFunction[0].Extent.Text
$TotalSeconds = 86400
$RotationSeconds = 82800
$OverlapSeconds = 900
$ExpectedCombinedRawGiBPerHour = 2.0
$ProjectionSafetyMultiplier = 2.0
$startProjection = Get-ConservativeRemainingProjectionGiB -ElapsedSeconds 0
$endProjection = Get-ConservativeRemainingProjectionGiB -ElapsedSeconds 86400
Assert-True ($startProjection -eq 97) "Production start projection must be exactly 97 GiB."
Assert-True ($endProjection -eq 0) "Projection at terminal capture time must be zero."
$reserve = [uint64]100
Assert-True (($reserve + $startProjection) -eq 197) "Start disk requirement must be reserve plus full projection."
Assert-True ((196 -lt ($reserve + $startProjection)) -and (197 -ge ($reserve + $startProjection))) "Disk boundary must fail at 196 GiB and pass at 197 GiB."
$monotonicFrequency = [uint64]10000000
$deadlineTicks = [long]([uint64]20 * $monotonicFrequency)
Assert-True (Test-RawQualificationDeadlineTicks -ElapsedTicks $deadlineTicks -TimeoutSeconds 20 -Frequency $monotonicFrequency) "Exact bounded-process deadline must be accepted."
Assert-True (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks ($deadlineTicks + 1) -TimeoutSeconds 20 -Frequency $monotonicFrequency)) "Deadline-plus-one-tick mutant bypassed the exact post-exit gate."
$maximumLaunchSkewTicks = [long]([uint64]5 * $monotonicFrequency)
Assert-True (Test-RawQualificationDeadlineTicks -ElapsedTicks $maximumLaunchSkewTicks -TimeoutSeconds 5 -Frequency $monotonicFrequency) "Exact 5s dual-launch skew boundary must be accepted."
Assert-True (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks ($maximumLaunchSkewTicks + 1) -TimeoutSeconds 5 -Frequency $monotonicFrequency)) "Dual-launch skew above 5s bypassed its exact monotonic gate."
$btcResumeQpc = [uint64]100
$btcReturnAfterArtificialDescheduleQpc = [uint64]([uint64]6 * $monotonicFrequency + $btcResumeQpc)
$ethResumeQpc = [uint64]([uint64]6 * $monotonicFrequency + [uint64]200)
$oldReturnDerivedSkew = [uint64]($ethResumeQpc - $btcReturnAfterArtificialDescheduleQpc)
$preResumeQpcSkew = [uint64]($ethResumeQpc - $btcResumeQpc)
Assert-True ($oldReturnDerivedSkew -lt $maximumLaunchSkewTicks) "Launch-skew mutant did not model an after-resume deschedule hidden by return-time sampling."
Assert-True (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks ([long]$preResumeQpcSkew) -TimeoutSeconds 5 -Frequency $monotonicFrequency)) "QPC sampled before ResumeThread did not expose a >5s launch skew mutant."
$boundedProcessResumeQpc = [uint64]100
$boundedProcessActualExitQpc = [uint64]($boundedProcessResumeQpc + ([uint64]20 * $monotonicFrequency) + 1)
$oldPostReturnTimerTicks = [long]1
Assert-True (Test-RawQualificationDeadlineTicks -ElapsedTicks $oldPostReturnTimerTicks -TimeoutSeconds 20 -Frequency $monotonicFrequency) "Bounded-process preemption mutant did not model the old post-return timer false pass."
Assert-True (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks ([long]($boundedProcessActualExitQpc - $boundedProcessResumeQpc)) -TimeoutSeconds 20 -Frequency $monotonicFrequency)) "Native pre-Resume QPC accounting accepted a deadline-plus-one execution hidden by post-Resume descheduling."
$verifierExitObservedQpc = [uint64]100
$verifierDrainCheckAfterDescheduleQpc = [uint64]($verifierExitObservedQpc + ([uint64]10 * $monotonicFrequency) + 1)
Assert-True (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks ([long]($verifierDrainCheckAfterDescheduleQpc - $verifierExitObservedQpc)) -TimeoutSeconds 10 -Frequency $monotonicFrequency)) "Verifier descendant drain hid a post-exit descheduling gap."
$generationTerminalDeadlineTicks = [long]([uint64](86400 + 120) * $monotonicFrequency)
$campaignCommitDeadlineTicks = [long]([uint64]1800 * $monotonicFrequency)
$verificationDeadlineTicks = [long]([uint64]14400 * $monotonicFrequency)
Assert-True (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks ($generationTerminalDeadlineTicks + 1) -TimeoutSeconds (86400 + 120) -Frequency $monotonicFrequency)) "Generation evidence at deadline-plus-one tick was accepted."
Assert-True (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks ($campaignCommitDeadlineTicks + 1) -TimeoutSeconds 1800 -Frequency $monotonicFrequency)) "Coordinator commit/exit at deadline-plus-one tick was accepted."
Assert-True (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks ($verificationDeadlineTicks + 1) -TimeoutSeconds 14400 -Frequency $monotonicFrequency)) "Terminal publication at verification deadline-plus-one tick was accepted."
$extendedDeadlineBoundaryResults = [ordered]@{}
foreach ($totalSecondsBoundary in @([uint64]604680, [uint64]604681, [uint64]604800)) {
    $timeoutBoundary = [uint64]($totalSecondsBoundary + [uint64]120)
    $ticksBoundary = [long]([decimal]$timeoutBoundary * [decimal]$monotonicFrequency)
    Assert-True (Test-RawQualificationDeadlineTicks -ElapsedTicks ($ticksBoundary - 1) -TimeoutSeconds $timeoutBoundary -Frequency $monotonicFrequency) "Extended total deadline-minus-one was rejected: $totalSecondsBoundary"
    Assert-True (Test-RawQualificationDeadlineTicks -ElapsedTicks $ticksBoundary -TimeoutSeconds $timeoutBoundary -Frequency $monotonicFrequency) "Extended total exact deadline was rejected: $totalSecondsBoundary"
    Assert-True (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks ($ticksBoundary + 1) -TimeoutSeconds $timeoutBoundary -Frequency $monotonicFrequency)) "Extended total deadline-plus-one was accepted: $totalSecondsBoundary"
    $extendedDeadlineBoundaryResults[$totalSecondsBoundary.ToString([Globalization.CultureInfo]::InvariantCulture)] = $timeoutBoundary
}
$unboundedDeadlineRejected = $false
try { $null = Test-RawQualificationDeadlineTicks -ElapsedTicks 0 -TimeoutSeconds ([uint64]604921) -Frequency $monotonicFrequency }
catch { $unboundedDeadlineRejected = $true }
Assert-True $unboundedDeadlineRejected "Deadline helper accepted timeout 604921 beyond the exact 604800+120 contract."
Assert-True (Test-RawQualificationDeadlineTicks `
    -ElapsedTicks ([long]::MaxValue) `
    -TimeoutSeconds ([uint64]604920) `
    -Frequency ([long]::MaxValue)) "Decimal deadline arithmetic rejected a valid maximum-integral evidence tuple."
$lateGuardianGrowthTicks = [long]([uint64]90 * $monotonicFrequency + 1)
Assert-True (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks $lateGuardianGrowthTicks -TimeoutSeconds 90 -Frequency $monotonicFrequency)) "A >90s guardian silence could be erased by late growth/STOP."
$artificialPreflightDelaySeconds = [uint64]600
$artificialPostCreateDelaySeconds = [uint64]300
$captureOriginTick = [uint64](($artificialPreflightDelaySeconds + $artificialPostCreateDelaySeconds) * $monotonicFrequency)
$oneSecondAfterCaptureOrigin = [uint64]($captureOriginTick + $monotonicFrequency)
$captureElapsedAfterArtificialDelay = Get-CaptureElapsedSeconds -ObservedTick $oneSecondAfterCaptureOrigin
Assert-True ([math]::Abs($captureElapsedAfterArtificialDelay - 1.0) -lt 0.000001) "Artificial preflight/post-create delay stole capture duration."
Assert-True (($oneSecondAfterCaptureOrigin / $monotonicFrequency) -eq 901) "Launcher clock fixture did not include both artificial delays."
$terminalDeadlineTick = [uint64]($captureOriginTick + ([uint64](86400 + 120) * $monotonicFrequency))
$terminalDeadlineElapsed = Get-CaptureElapsedSeconds -ObservedTick $terminalDeadlineTick
Assert-True ([math]::Abs($terminalDeadlineElapsed - 86520.0) -lt 0.000001) "Terminal deadline was measured from launcher/preflight instead of capture origin."

$makeTerminalSet = {
    param([string[]] $Values)
    $set = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($value in $Values) { $null = $set.Add($value) }
    return ,$set
}
$states = @{
    BTCUSDT = [pscustomobject]@{
        GenerationDurations = @{ 'btc-generation' = [uint64]82800 }
        GenerationTerminals = & $makeTerminalSet @('btc-generation')
        GenerationExited = & $makeTerminalSet @('btc-generation')
        Exited = $false
    }
    ETHUSDT = [pscustomobject]@{
        GenerationDurations = @{ 'eth-generation' = [uint64]82800 }
        GenerationTerminals = & $makeTerminalSet @()
        GenerationExited = & $makeTerminalSet @()
        Exited = $false
    }
}
$staleTerminalEvidence = Test-AllGenerationTerminalEvidence
$null = $states.ETHUSDT.GenerationTerminals.Add('eth-generation')
$null = $states.ETHUSDT.GenerationExited.Add('eth-generation')
$states.BTCUSDT.Exited = $true
$states.ETHUSDT.Exited = $true
$freshTerminalEvidence = Test-AllGenerationTerminalEvidence
Assert-True (-not $staleTerminalEvidence -and $freshTerminalEvidence) "Same-poll terminal+exit evidence was not detected by a fresh recomputation."

$terminalLoop = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.WhileStatementAst] -and
        $node.Extent.Text.Contains('CAMPAIGN_TERMINAL_EVALUATION_STARTED')
}, $true))
Assert-True ($terminalLoop.Count -eq 1) "Terminal guardian loop extraction was ambiguous."
$terminalLoopText = $terminalLoop[0].Extent.Text
$lastCampaignReadIndex = $terminalLoopText.LastIndexOf('Read-StateCampaignEvents -State $state', [StringComparison]::Ordinal)
$postReadTickIndex = $terminalLoopText.IndexOf('$postReadTick = Get-MonotonicTick', [StringComparison]::Ordinal)
$postReadDrainingIndex = $terminalLoopText.LastIndexOf('Ensure-CaptureDraining -ObservedTick $postReadTick', [StringComparison]::Ordinal)
$freshEvidenceIndex = $terminalLoopText.IndexOf('$allGenerationTerminalEvidence = Test-AllGenerationTerminalEvidence', [StringComparison]::Ordinal)
$stageIndex = $terminalLoopText.IndexOf('event = "CAMPAIGN_TERMINAL_EVALUATION_STARTED"', [StringComparison]::Ordinal)
$stateDeadlineObservationIndex = $terminalLoopText.IndexOf('$stateDeadlineObservedTick = Get-MonotonicTick', [StringComparison]::Ordinal)
$stateDeadlineLaunchRegressionIndex = $terminalLoopText.IndexOf('$stateDeadlineObservedTick -lt [uint64]$state.LaunchTick', [StringComparison]::Ordinal)
$stateDeadlineRegressionIndex = $terminalLoopText.IndexOf('$stateDeadlineObservedTick -lt [uint64]$state.LastHeartbeatTick', [StringComparison]::Ordinal)
$stateDeadlineSemanticRegressionIndex = $terminalLoopText.IndexOf('$stateDeadlineObservedTick -lt [uint64]$state.LastSemanticTick', [StringComparison]::Ordinal)
$coordinatorFreshObservationIndex = $terminalLoopText.IndexOf('Get-CoordinatorElapsedSeconds -State $state -ObservedTick $stateDeadlineObservedTick', [StringComparison]::Ordinal)
$heartbeatFreshElapsedIndex = $terminalLoopText.IndexOf('$stateDeadlineObservedTick - $state.LastHeartbeatTick', [StringComparison]::Ordinal)
$semanticFreshElapsedIndex = $terminalLoopText.IndexOf('$stateDeadlineObservedTick - $state.LastSemanticTick', [StringComparison]::Ordinal)
$campaignCommitObservationIndex = $terminalLoopText.IndexOf('$campaignCommitDeadlineObservedTick = Get-MonotonicTick', [StringComparison]::Ordinal)
$campaignCommitRegressionIndex = $terminalLoopText.IndexOf('$campaignCommitDeadlineObservedTick -lt $terminalEvaluationStartedTick', [StringComparison]::Ordinal)
$campaignCommitElapsedIndex = $terminalLoopText.IndexOf('$campaignCommitDeadlineObservedTick - $terminalEvaluationStartedTick', [StringComparison]::Ordinal)
$exitDrainingIndex = $terminalLoopText.IndexOf('Ensure-CaptureDraining -ObservedTick $exitObservedTick', [StringComparison]::Ordinal)
$campaignExitEventIndex = $terminalLoopText.IndexOf('event = "CAMPAIGN_PROCESS_EXITED"', [StringComparison]::Ordinal)
$productionTerminalStageAfterFinalJournalRead = (
    $lastCampaignReadIndex -ge 0 -and
    $freshEvidenceIndex -gt $lastCampaignReadIndex -and
    $stageIndex -gt $freshEvidenceIndex)
Assert-True $productionTerminalStageAfterFinalJournalRead "Production guardian can evaluate/exit before consuming and staging same-poll terminal evidence."
Assert-True ($postReadTickIndex -gt $lastCampaignReadIndex -and $postReadDrainingIndex -gt $postReadTickIndex -and $freshEvidenceIndex -gt $postReadDrainingIndex) "Production guardian can skip DRAINING when a final poll crosses Total-5."
Assert-True ($exitDrainingIndex -ge 0 -and $campaignExitEventIndex -gt $exitDrainingIndex) "A same-poll coordinator exit can be published before CAPTURE_DRAINING."
Assert-True ($stateDeadlineObservationIndex -gt $lastCampaignReadIndex -and
    $stateDeadlineLaunchRegressionIndex -gt $stateDeadlineObservationIndex -and
    $stateDeadlineRegressionIndex -gt $stateDeadlineLaunchRegressionIndex -and
    $stateDeadlineSemanticRegressionIndex -gt $stateDeadlineRegressionIndex -and
    $coordinatorFreshObservationIndex -gt $stateDeadlineSemanticRegressionIndex -and
    $heartbeatFreshElapsedIndex -gt $coordinatorFreshObservationIndex -and
    $semanticFreshElapsedIndex -gt $heartbeatFreshElapsedIndex -and
    -not $terminalLoopText.Contains('$nowTick - $state.LastHeartbeatTick') -and
    -not $terminalLoopText.Contains('$nowTick - $state.LastSemanticTick') -and
    -not $terminalLoopText.Contains('Get-CoordinatorElapsedSeconds -State $state -ObservedTick $nowTick')) `
    "State freshness deadlines reuse a pre-read loop tick or lack a causal QPC regression guard."
$samePollPreReadTick = [uint64]2000
$samePollHeartbeatTick = [uint64]2001
$samePollSemanticTick = [uint64]2002
$samePollStateDeadlineTick = [uint64]2003
$samePollLegacyHeartbeatElapsed = [long]([decimal]$samePollPreReadTick - [decimal]$samePollHeartbeatTick)
$samePollLegacySemanticElapsed = [long]([decimal]$samePollPreReadTick - [decimal]$samePollSemanticTick)
Assert-True ($samePollLegacyHeartbeatElapsed -eq -1 -and $samePollLegacySemanticElapsed -eq -2 -and
    [long]($samePollStateDeadlineTick - $samePollHeartbeatTick) -eq 2 -and
    [long]($samePollStateDeadlineTick - $samePollSemanticTick) -eq 1) `
    "Same-poll state freshness fixture did not reproduce and eliminate the negative pre-read intervals."
$campaignCommitObservationAssignments = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -ceq "campaignCommitDeadlineObservedTick"
}, $true))
$stateDeadlineObservationAssignments = @($launcherAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -ceq "stateDeadlineObservedTick"
}, $true))
Assert-True ($campaignCommitObservationAssignments.Count -eq 1 -and
    $campaignCommitObservationAssignments[0].Right.Extent.Text.Trim() -ceq 'Get-MonotonicTick' -and
    $stateDeadlineObservationAssignments.Count -eq 1 -and
    $stateDeadlineObservationAssignments[0].Right.Extent.Text.Trim() -ceq 'Get-MonotonicTick') `
    "Fresh deadline observations are not uniquely sampled from the monotonic clock."
$negativeDeadlineRejected = $false
$negativeDeadlineExceptionType = $null
try {
    $null = Test-RawQualificationDeadlineTicks -ElapsedTicks $samePollLegacyHeartbeatElapsed -TimeoutSeconds 1800 -Frequency $monotonicFrequency
}
catch {
    $negativeDeadlineExceptionType = $_.Exception.GetType().FullName
    $negativeDeadlineRejected = ($negativeDeadlineExceptionType -ceq "System.Management.Automation.ParameterBindingValidationException" -and
        [string]$_.FullyQualifiedErrorId -clike "ParameterArgumentValidationError,Test-RawQualificationDeadlineTicks")
}
Assert-True $negativeDeadlineRejected "Deadline helper did not fail closed with the exact validation error on the reproduced negative same-poll interval."
Assert-True ($campaignCommitObservationIndex -gt $stageIndex -and
    $campaignCommitRegressionIndex -gt $campaignCommitObservationIndex -and
    $campaignCommitElapsedIndex -gt $campaignCommitRegressionIndex -and
    -not $terminalLoopText.Contains('$postReadTick - $terminalEvaluationStartedTick')) `
    "Campaign commit deadline reuses a pre-terminal same-poll observation or lacks an explicit QPC regression guard."
$samePollPreTerminalTick = [uint64]1000
$samePollTerminalStartTick = [uint64]1001
$samePollCommitObservedTick = [uint64]1002
$samePollLegacyElapsedTicks = [long]([decimal]$samePollPreTerminalTick - [decimal]$samePollTerminalStartTick)
$samePollCurrentElapsedTicks = [long]($samePollCommitObservedTick - $samePollTerminalStartTick)
Assert-True ($samePollLegacyElapsedTicks -eq -1 -and $samePollCurrentElapsedTicks -eq 1 -and
    (Test-RawQualificationDeadlineTicks -ElapsedTicks $samePollCurrentElapsedTicks -TimeoutSeconds 1800 -Frequency $monotonicFrequency)) `
    "Same-poll campaign commit QPC fixture did not reproduce and eliminate the negative legacy interval."
$captureThreshold = [double](86400 - 5)
$preReadElapsed = $captureThreshold - 0.25
$postReadElapsed = $captureThreshold + 0.25
$crossingPollDrainingWritten = $false
if ($preReadElapsed -ge $captureThreshold) { $crossingPollDrainingWritten = $true }
if (-not $crossingPollDrainingWritten -and $postReadElapsed -ge $captureThreshold) {
    $crossingPollOrder = [Collections.Generic.List[string]]::new()
    $crossingPollOrder.Add("CAPTURE_DRAINING_STARTED")
    $crossingPollDrainingWritten = $true
    $crossingPollOrder.Add("CAMPAIGN_PROCESS_EXITED")
}
Assert-True $crossingPollDrainingWritten "Crossing Total-5 during the final journal read omitted DRAINING."
Assert-True (($crossingPollOrder -join ',') -eq "CAPTURE_DRAINING_STARTED,CAMPAIGN_PROCESS_EXITED") "Crossing Total-5 and observing exit in one poll did not linearize DRAINING before EXIT."

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("BinanceRawQualificationOpsTest-" + [Guid]::NewGuid().ToString("N"))
$null = New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop
try {
    $collisionPrimaryHandle = [IntPtr]::Zero
    $collisionFreshHandle = [IntPtr]::Zero
    try {
        $collisionName = "Local\BinanceRawQualificationCollisionTest-" + [Guid]::NewGuid().ToString("N")
        $collisionPrimaryHandle = [RawQualificationNative]::CreateKillOnCloseJob($collisionName)
        $collisionRejected = $false
        try { $null = [RawQualificationNative]::CreateKillOnCloseJob($collisionName) }
        catch [ComponentModel.Win32Exception] {
            $collisionRejected = $_.Exception.NativeErrorCode -eq 183
        }
        Assert-True $collisionRejected "CreateKillOnCloseJob accepted an existing named Job."
        Assert-True ([RawQualificationNative]::GetActiveProcessCount($collisionPrimaryHandle) -eq 0) `
            "Existing-Job rejection invalidated the original Job handle."
        $collisionFreshHandle = [RawQualificationNative]::CreateKillOnCloseJob(
            "Local\BinanceRawQualificationPostCollisionFreshTest-" + [Guid]::NewGuid().ToString("N"))
        Assert-True ($collisionFreshHandle -ne [IntPtr]::Zero) `
            "A stale ERROR_ALREADY_EXISTS poisoned creation of a fresh named Job."
    }
    finally {
        if ($collisionFreshHandle -ne [IntPtr]::Zero) {
            $null = [RawQualificationNative]::CloseHandle($collisionFreshHandle)
        }
        if ($collisionPrimaryHandle -ne [IntPtr]::Zero) {
            $null = [RawQualificationNative]::CloseHandle($collisionPrimaryHandle)
        }
    }
    $readyPulsePath = Join-Path $testRoot "ready-pulse.jsonl"
    [IO.File]::WriteAllText($readyPulsePath, "{}`n", [Text.UTF8Encoding]::new($false))
    $readyPath = Join-Path $testRoot "watchdog-ready.json"
    $readyOriginQpc = [long]1000
    $readyResumeQpc = [long]1100
    $readyObservedQpc = [long]1200
    $readyRuntimeFrequency = [long]10000000
    $readyValue = [ordered]@{
        schema = "RawQualificationWatchdogReadyV1"
        run_id = "ready-run"
        job_name = "Local\ReadyTest"
        pid = [uint32]1234
        launch_origin_qpc_timestamp = $readyOriginQpc
        observed_qpc_timestamp = $readyObservedQpc
        monotonic_frequency = $readyRuntimeFrequency
        startup_deadline_s = [uint64]90
        pulse_length = [uint64](Get-Item -LiteralPath $readyPulsePath).Length
    }
    $readyBytes = ConvertTo-RawQualificationJsonBytes -Value $readyValue -Pretty
    [IO.File]::WriteAllBytes($readyPath, $readyBytes)
    $readyStartup = [pscustomobject]@{
        run_id = "ready-run"
        monotonic_origin_qpc_timestamp = [long]500
        monotonic_frequency = $readyRuntimeFrequency
        guardian_policy = [pscustomobject]@{ pulse_file = "ready-pulse.jsonl" }
    }
    $readyControl = [pscustomobject]@{
        ready_file = "watchdog-ready.json"
        ready_file_sha256 = Get-RawQualificationSha256Bytes -Bytes $readyBytes
        job_name = "Local\ReadyTest"
        pid = [uint32]1234
        launch_origin_qpc_timestamp = $readyOriginQpc
        resume_qpc_timestamp = $readyResumeQpc
        ready_observed_qpc_timestamp = $readyObservedQpc
        monotonic_frequency = $readyRuntimeFrequency
        startup_deadline_s = [uint64]90
        ready_pulse_length = [uint64](Get-Item -LiteralPath $readyPulsePath).Length
    }
    $validReady = Get-MonitorWatchdogReadyEvidence -ResolvedRunRoot $testRoot -Startup $readyStartup -WatchdogControl $readyControl
    Assert-True ($validReady.sha256 -eq $readyControl.ready_file_sha256) "Valid watchdog READY evidence did not verify."
    $caseReadyValue = ($readyValue | ConvertTo-Json -Depth 10 -Compress | ConvertFrom-Json)
    $caseReadyValue.PSObject.Properties.Remove("schema")
    $caseReadyValue | Add-Member -NotePropertyName "Schema" -NotePropertyValue "RawQualificationWatchdogReadyV1"
    $caseReadyBytes = ConvertTo-RawQualificationJsonBytes -Value $caseReadyValue -Pretty
    [IO.File]::WriteAllBytes($readyPath, $caseReadyBytes)
    $caseReadyControl = $readyControl.PSObject.Copy()
    $caseReadyControl.ready_file_sha256 = Get-RawQualificationSha256Bytes -Bytes $caseReadyBytes
    $caseReadyRejected = $false
    try { $null = Get-MonitorWatchdogReadyEvidence -ResolvedRunRoot $testRoot -Startup $readyStartup -WatchdogControl $caseReadyControl }
    catch { $caseReadyRejected = $true }
    Assert-True $caseReadyRejected "Watchdog READY accepted a case-mismatched JSON property name."
    [IO.File]::WriteAllBytes($readyPath, $readyBytes)
    $lateReadyValue = [ordered]@{} + $readyValue
    $lateReadyValue.observed_qpc_timestamp = [long]($readyOriginQpc + ([long]90 * $readyRuntimeFrequency) + 1)
    $lateReadyBytes = ConvertTo-RawQualificationJsonBytes -Value $lateReadyValue -Pretty
    [IO.File]::WriteAllBytes($readyPath, $lateReadyBytes)
    $lateReadyControl = $readyControl.PSObject.Copy()
    $lateReadyControl.ready_file_sha256 = Get-RawQualificationSha256Bytes -Bytes $lateReadyBytes
    $lateReadyControl.ready_observed_qpc_timestamp = [long]$lateReadyValue.observed_qpc_timestamp
    $lateReadyRejected = $false
    try { $null = Get-MonitorWatchdogReadyEvidence -ResolvedRunRoot $testRoot -Startup $readyStartup -WatchdogControl $lateReadyControl }
    catch { $lateReadyRejected = $true }
    Assert-True $lateReadyRejected "Watchdog READY after startup deadline was accepted after coherent re-hashing."
    [IO.File]::WriteAllBytes($readyPath, $readyBytes)
    $replacedReadyBytes = [byte[]]$readyBytes.Clone()
    $replacedReadyBytes[10] = [byte]($replacedReadyBytes[10] -bxor 1)
    [IO.File]::WriteAllBytes($readyPath, $replacedReadyBytes)
    $replacedReadyRejected = $false
    try { $null = Get-MonitorWatchdogReadyEvidence -ResolvedRunRoot $testRoot -Startup $readyStartup -WatchdogControl $readyControl }
    catch { $replacedReadyRejected = $true }
    Assert-True $replacedReadyRejected "Replaced watchdog READY bytes passed the sealed hash binding."

    $raceReadyPath = Join-Path $testRoot "watchdog-ready-race.json"
    $raceReadyValue = [ordered]@{
        schema = "RawQualificationWatchdogReadyV1"
        run_id = "ready-race"
        job_name = "Local\ReadyRace"
        pid = [uint32]1234
        launch_origin_qpc_timestamp = [long]100
        observed_qpc_timestamp = [long]300
        monotonic_frequency = [long]10000000
        startup_deadline_s = [uint64]90
        pulse_length = [uint64]1
    }
    $raceReadyBytes = ConvertTo-RawQualificationJsonBytes -Value $raceReadyValue -Pretty
    $raceWriter = $null
    $raceRetained = $null
    try {
        # This is the exact sharing state of Write-RawQualificationDurableNewFile:
        # WRITE access remains active while only other readers are shared.
        $raceWriter = [IO.FileStream]::new(
            $raceReadyPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read,
            4096,
            [IO.FileOptions]::WriteThrough)
        $raceWriter.Write($raceReadyBytes, 0, $raceReadyBytes.Length)
        $raceWriter.Flush($true)

        $lockedReadyAttempt = Open-WatchdogReadyRetained -Path $raceReadyPath
        Assert-True ($null -eq $lockedReadyAttempt) "READY reader did not retry the real active-writer sharing race."
        $raceWriter.Dispose()
        $raceWriter = $null

        $raceRetained = Open-WatchdogReadyRetained -Path $raceReadyPath
        Assert-True ($null -ne $raceRetained -and $null -ne $raceRetained.Stream) "READY reader did not succeed after the durable writer closed."
        Assert-True ((Get-RawQualificationSha256Bytes -Bytes $raceRetained.Bytes) -eq
            (Get-RawQualificationSha256Bytes -Bytes $raceReadyBytes)) "Retained READY bytes differ from the durable writer prefix."
        Assert-True ($raceRetained.Value.schema -eq "RawQualificationWatchdogReadyV1") "Retained READY strict JSON parse changed its schema."
        $parallelReadyRead = [IO.File]::ReadAllBytes($raceReadyPath)
        Assert-True ($parallelReadyRead.Length -eq $raceReadyBytes.Length) "Retained READY handle incorrectly blocks independent readers."

        $movedRaceReadyPath = Join-Path $testRoot "watchdog-ready-race-moved.json"
        $raceReplacementBlocked = $false
        try { [IO.File]::Move($raceReadyPath, $movedRaceReadyPath) }
        catch [IO.IOException] { $raceReplacementBlocked = $true }
        catch [UnauthorizedAccessException] { $raceReplacementBlocked = $true }
        Assert-True $raceReplacementBlocked "Retained READY handle permitted rename/replacement during the campaign."
        Assert-True (Test-Path -LiteralPath $raceReadyPath -PathType Leaf) "Blocked READY replacement changed the retained path."

        $raceRetained.Stream.Dispose()
        $raceRetained = $null
        [IO.File]::Move($raceReadyPath, $movedRaceReadyPath)
        Assert-True (Test-Path -LiteralPath $movedRaceReadyPath -PathType Leaf) "READY rename remained blocked after retained-handle disposal."

        $partialRaceReadyPath = Join-Path $testRoot "watchdog-ready-race-partial.json"
        [IO.File]::WriteAllText($partialRaceReadyPath, "{`"schema`":`"partial`"}", [Text.UTF8Encoding]::new($false))
        $partialRaceReadyRejected = $false
        try { $null = Open-WatchdogReadyRetained -Path $partialRaceReadyPath }
        catch { $partialRaceReadyRejected = $true }
        Assert-True $partialRaceReadyRejected "READY reader accepted a closed non-newline-complete file."
    }
    finally {
        if ($null -ne $raceWriter) { $raceWriter.Dispose() }
        if ($null -ne $raceRetained -and $null -ne $raceRetained.Stream) { $raceRetained.Stream.Dispose() }
    }

    $prefixPath = Join-Path $testRoot "prefix.txt"
    [IO.File]::WriteAllText($prefixPath, "one`n", [Text.UTF8Encoding]::new($false))
    $file = [IO.FileStream]::new($prefixPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $snapshotLength = $file.Length
        [IO.File]::AppendAllText($prefixPath, "two`n", [Text.UTF8Encoding]::new($false))
        $bounded = [RawQualificationLengthLimitedStream]::new($file, $snapshotLength, $true)
        $reader = [IO.StreamReader]::new($bounded, [Text.UTF8Encoding]::new($false, $true), $true, 1024, $true)
        try { $prefixText = $reader.ReadToEnd() }
        finally { $reader.Dispose(); $bounded.Dispose() }
    }
    finally { $file.Dispose() }
    Assert-True ($prefixText -eq "one`n") "Length-limited journal scan consumed a concurrent append."

    $environmentEntries = [string[]]@($productionChildEnvironmentContract.Entries)

    $retainedCoordinatorJob = [RawQualificationNative]::CreateKillOnCloseJob(
        "Local\BinanceRawQualificationRetainedCoordinatorTest-" + [Guid]::NewGuid().ToString("N"))
    $retainedCoordinatorOwner = $null
    try {
        $retainedCoordinatorLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $retainedCoordinatorJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@("-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 300")),
            $repo,
            (Join-Path $testRoot "retained-coordinator.stdout.log"),
            (Join-Path $testRoot "retained-coordinator.stderr.log"),
            $environmentEntries)
        $retainedCoordinatorOwner = [pscustomobject]@{
            Symbol = "BTCUSDT"
            ProcessId = [uint32]$retainedCoordinatorLaunch.ProcessId
            ProcessHandle = [IntPtr]$retainedCoordinatorLaunch.ProcessHandle
            Closed = $false
            CloseCount = [uint32]0
        }
        $retainedCoordinatorState = [pscustomobject]@{
            Symbol = "BTCUSDT"
            ProcessId = [uint32]$retainedCoordinatorLaunch.ProcessId
            ProcessHandleOwner = $retainedCoordinatorOwner
            # This deliberately models a stale PID-based observation.  The
            # production assertion must ignore it and trust only the retained
            # CreateProcess handle.
            Process = [pscustomobject]@{ HasExited = $false }
        }
        $script:monotonicOrigin = [Diagnostics.Stopwatch]::GetTimestamp()
        $liveCandidateTick = Get-MonotonicTick
        $liveCheckedTick = Assert-CoordinatorNativeLivenessAfterTick `
            -State $retainedCoordinatorState `
            -CandidateTick $liveCandidateTick `
            -Context "self-test live publication"
        Assert-True ($liveCheckedTick -ge $liveCandidateTick) "Original-handle liveness was not sampled after the candidate publication tick."

        $exitBetweenTickAndCheckCandidate = Get-MonotonicTick
        $null = [RawQualificationNative]::TerminateJobObject($retainedCoordinatorJob, 0xEEC1)
        Assert-True ([RawQualificationNative]::WaitForProcessExit([IntPtr]$retainedCoordinatorOwner.ProcessHandle, 10000)) "Retained coordinator fixture did not exit after Job fencing."
        $retainedOriginalExitCode = [int][RawQualificationNative]::GetProcessExitCode([IntPtr]$retainedCoordinatorOwner.ProcessHandle)
        $exitBetweenTickAndCheckRejected = $false
        try {
            $null = Assert-CoordinatorNativeLivenessAfterTick `
                -State $retainedCoordinatorState `
                -CandidateTick $exitBetweenTickAndCheckCandidate `
                -Context "self-test post-exit publication"
        }
        catch { $exitBetweenTickAndCheckRejected = $true }
        Assert-True $exitBetweenTickAndCheckRejected "An exit between candidate tick and original-handle liveness check was accepted despite a stale HasExited=false/PID view."
        Assert-True ([RawQualificationNative]::WaitForProcessExit([IntPtr]$retainedCoordinatorOwner.ProcessHandle, 0)) "Retained original process handle lost its terminal identity."
        Assert-True ([int][RawQualificationNative]::GetProcessExitCode([IntPtr]$retainedCoordinatorOwner.ProcessHandle) -eq $retainedOriginalExitCode) "Retained process handle resolved to a different process identity after exit."
        Assert-True (Close-CoordinatorNativeProcessHandle -HandleOwner $retainedCoordinatorOwner) "Known-exit coordinator handle was not closed exactly once."
        Assert-True (-not (Close-CoordinatorNativeProcessHandle -HandleOwner $retainedCoordinatorOwner)) "Second coordinator handle close was not an idempotent ownership no-op."
        Assert-True ($retainedCoordinatorOwner.Closed -and
            [uint32]$retainedCoordinatorOwner.CloseCount -eq 1 -and
            [IntPtr]$retainedCoordinatorOwner.ProcessHandle -eq [IntPtr]::Zero) "Coordinator handle owner did not seal one exact close."
    }
    finally {
        if ($null -ne $retainedCoordinatorOwner -and -not [bool]$retainedCoordinatorOwner.Closed) {
            $null = Close-CoordinatorNativeProcessHandle -HandleOwner $retainedCoordinatorOwner
        }
        if ($retainedCoordinatorJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($retainedCoordinatorJob) }
    }

    $retainedWatchdogJob = [RawQualificationNative]::CreateKillOnCloseJob(
        "Local\BinanceRawQualificationRetainedWatchdogTest-" + [Guid]::NewGuid().ToString("N"))
    $retainedWatchdogLaunch = $null
    $retainedWatchdogSecondCloseRejected = $false
    try {
        $retainedWatchdogLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $retainedWatchdogJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@("-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 300")),
            $repo,
            (Join-Path $testRoot "retained-watchdog.stdout.log"),
            (Join-Path $testRoot "retained-watchdog.stderr.log"),
            $environmentEntries)
        Assert-True (-not [bool]$retainedWatchdogLaunch.PSObject.Properties['ProcessHandle'].IsSettable) `
            "PowerShell 5.1 no longer reproduces the read-only native launch-result handle contract."
        $null = [RawQualificationNative]::TerminateJobObject($retainedWatchdogJob, 0xEEC2)
        Assert-True ([RawQualificationNative]::WaitForProcessExit($retainedWatchdogLaunch.ProcessHandle, 10000)) `
            "Retained watchdog fixture did not exit after Job fencing."
        Assert-True ([RawQualificationNative]::CloseRetainedProcessHandle($retainedWatchdogLaunch)) `
            "Native helper did not close the retained watchdog process handle."
        Assert-True ([IntPtr]$retainedWatchdogLaunch.ProcessHandle -eq [IntPtr]::Zero) `
            "Native helper closed the retained watchdog process handle without invalidating its owner."
        try { $null = [RawQualificationNative]::CloseRetainedProcessHandle($retainedWatchdogLaunch) }
        catch { $retainedWatchdogSecondCloseRejected = $true }
        Assert-True $retainedWatchdogSecondCloseRejected `
            "Native retained-handle helper accepted a second close."
    }
    finally {
        if ($null -ne $retainedWatchdogLaunch -and
            [IntPtr]$retainedWatchdogLaunch.ProcessHandle -ne [IntPtr]::Zero) {
            $null = [RawQualificationNative]::CloseRetainedProcessHandle($retainedWatchdogLaunch)
        }
        if ($retainedWatchdogJob -ne [IntPtr]::Zero) {
            $null = [RawQualificationNative]::CloseHandle($retainedWatchdogJob)
        }
    }

    $env:BINANCE_TEST_SECRET_SENTINEL = "MUST_NOT_INHERIT"
    $envJob = [RawQualificationNative]::CreateKillOnCloseJob("Local\BinanceRawQualificationEnvTest-" + [Guid]::NewGuid().ToString("N"))
    $envHandle = [IntPtr]::Zero
    try {
        $envStdout = Join-Path $testRoot "env.stdout.log"
        $envStderr = Join-Path $testRoot "env.stderr.log"
        $envCommand = "`$null=Get-CimInstance Win32_Process -Filter 'ProcessId=4' -ErrorAction Stop;[pscustomobject]@{sentinel=[Environment]::GetEnvironmentVariable('BINANCE_TEST_SECRET_SENTINEL');system_drive=[Environment]::GetEnvironmentVariable('SystemDrive');expanded_system_drive=[Environment]::ExpandEnvironmentVariables('%SystemDrive%');system_root=[Environment]::GetEnvironmentVariable('SystemRoot')}|ConvertTo-Json -Compress"
        $envLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $envJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@("-NoProfile", "-NonInteractive", "-Command", $envCommand)),
            $testRoot,
            $envStdout,
            $envStderr,
            $environmentEntries)
        $envHandle = $envLaunch.ProcessHandle
        Assert-True ([RawQualificationNative]::WaitForProcessExit($envHandle, 10000)) "Explicit-environment child did not exit."
        Assert-True ([RawQualificationNative]::GetProcessExitCode($envHandle) -eq 0) "Explicit-environment child failed."
        $envResult = Get-Content -LiteralPath $envStdout -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-True ($null -eq $envResult.sentinel) "A credential-like parent variable leaked into the child."
        Assert-True ([string]$envResult.system_drive -ceq $env:SystemDrive -and
            [string]$envResult.expanded_system_drive -ceq $env:SystemDrive) `
            "Required SystemDrive was absent or expanded literally in the explicit-environment child."
        Assert-True ($envResult.system_root -eq $env:SystemRoot) "Required SystemRoot was absent from child allowlist."
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $testRoot '%SystemDrive%'))) `
            "A CIM-enabled explicit-environment child created a literal %SystemDrive% tree."
        Assert-True ((Get-Item -LiteralPath $envStderr).Length -eq 0) "Explicit-environment child wrote stderr."
    }
    finally {
        Remove-Item Env:\BINANCE_TEST_SECRET_SENTINEL -ErrorAction SilentlyContinue
        if ($envHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($envHandle) }
        if ($envJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($envJob) }
    }

    $killOnCloseJob = [RawQualificationNative]::CreateKillOnCloseJob(
        "Local\BinanceRawQualificationKillOnCloseTest-" + [Guid]::NewGuid().ToString("N"))
    $killOnCloseParentHandle = [IntPtr]::Zero
    $killOnCloseGrandchildPid = [uint32]0
    try {
        $grandchildPidPath = Join-Path $testRoot "kill-on-close-grandchild.pid"
        $escapedGrandchildPidPath = $grandchildPidPath.Replace("'", "''")
        $killOnCloseCommand = @'
$child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-NonInteractive','-WindowStyle','Hidden','-Command','Start-Sleep -Seconds 300') -WindowStyle Hidden -PassThru
[IO.File]::WriteAllText('__PID_PATH__', $child.Id.ToString([Globalization.CultureInfo]::InvariantCulture), [Text.UTF8Encoding]::new($false))
Start-Sleep -Seconds 300
'@.Replace('__PID_PATH__', $escapedGrandchildPidPath)
        $killOnCloseLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $killOnCloseJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@("-NoProfile", "-NonInteractive", "-Command", $killOnCloseCommand)),
            $repo,
            (Join-Path $testRoot "kill-on-close.stdout.log"),
            (Join-Path $testRoot "kill-on-close.stderr.log"),
            $environmentEntries)
        $killOnCloseParentHandle = $killOnCloseLaunch.ProcessHandle
        $descendantReady = [Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $grandchildPidPath -PathType Leaf) -or
            [RawQualificationNative]::GetActiveProcessCount($killOnCloseJob) -lt 2) {
            if (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks $descendantReady.ElapsedTicks -TimeoutSeconds 10)) {
                throw "Kill-on-close fixture did not create its Job descendant."
            }
            Start-Sleep -Milliseconds 50
        }
        $killOnCloseGrandchildPid = [uint32](Get-Content -LiteralPath $grandchildPidPath -Raw -Encoding UTF8)
        Assert-True ($killOnCloseGrandchildPid -ne 0) "Kill-on-close fixture emitted an invalid grandchild PID."
        $null = [RawQualificationNative]::CloseHandle($killOnCloseJob)
        $killOnCloseJob = [IntPtr]::Zero
        Assert-True ([RawQualificationNative]::WaitForProcessExit($killOnCloseParentHandle, 10000)) "Closing the unique Job handle did not kill the parent."
        $grandchildExitWait = [Diagnostics.Stopwatch]::StartNew()
        while ($null -ne (Get-Process -Id $killOnCloseGrandchildPid -ErrorAction SilentlyContinue)) {
            if (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks $grandchildExitWait.ElapsedTicks -TimeoutSeconds 10)) {
                throw "Closing the unique Job handle did not kill the grandchild."
            }
            Start-Sleep -Milliseconds 50
        }
    }
    finally {
        if ($killOnCloseParentHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($killOnCloseParentHandle) }
        if ($killOnCloseJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($killOnCloseJob) }
    }

    $nestedMainJob = [RawQualificationNative]::CreateKillOnCloseJob(
        "Local\BinanceRawQualificationNestedMainTest-" + [Guid]::NewGuid().ToString("N"))
    $nestedProbeJob = [RawQualificationNative]::CreateKillOnCloseJob(
        "Local\BinanceRawQualificationNestedProbeTest-" + [Guid]::NewGuid().ToString("N"))
    $nestedParentHandle = [IntPtr]::Zero
    $nestedGrandchildPid = [uint32]0
    try {
        $nestedGrandchildPidPath = Join-Path $testRoot "nested-grandchild.pid"
        $escapedNestedPidPath = $nestedGrandchildPidPath.Replace("'", "''")
        $nestedCommand = $killOnCloseCommand.Replace($escapedGrandchildPidPath, $escapedNestedPidPath)
        $nestedLaunch = [RawQualificationNative]::StartSuspendedInJobsRetainedWithEnvironment(
            $nestedMainJob,
            $nestedProbeJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@("-NoProfile", "-NonInteractive", "-Command", $nestedCommand)),
            $repo,
            (Join-Path $testRoot "nested.stdout.log"),
            (Join-Path $testRoot "nested.stderr.log"),
            $environmentEntries)
        $nestedParentHandle = $nestedLaunch.ProcessHandle
        $nestedReady = [Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $nestedGrandchildPidPath -PathType Leaf) -or
            [RawQualificationNative]::GetActiveProcessCount($nestedMainJob) -lt 2 -or
            [RawQualificationNative]::GetActiveProcessCount($nestedProbeJob) -lt 2) {
            if (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks $nestedReady.ElapsedTicks -TimeoutSeconds 10)) {
                throw "Nested probe fixture did not enter both Job Objects with its grandchild."
            }
            Start-Sleep -Milliseconds 50
        }
        $nestedGrandchildPid = [uint32](Get-Content -LiteralPath $nestedGrandchildPidPath -Raw -Encoding UTF8)
        $null = [RawQualificationNative]::TerminateJobObject($nestedMainJob, 0xEE71)
        Assert-True ([RawQualificationNative]::WaitForProcessExit($nestedParentHandle, 10000)) "Main guardian Job termination did not kill nested probe parent."
        $nestedExitWait = [Diagnostics.Stopwatch]::StartNew()
        while ($null -ne (Get-Process -Id $nestedGrandchildPid -ErrorAction SilentlyContinue)) {
            if (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks $nestedExitWait.ElapsedTicks -TimeoutSeconds 10)) {
                throw "Main guardian Job termination did not kill nested probe grandchild while nested handle remained open."
            }
            Start-Sleep -Milliseconds 50
        }
        Assert-True ([RawQualificationNative]::GetActiveProcessCount($nestedProbeJob) -eq 0) "Nested per-probe Job did not drain after main guardian fencing."
    }
    finally {
        if ($nestedParentHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($nestedParentHandle) }
        if ($nestedProbeJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($nestedProbeJob) }
        if ($nestedMainJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($nestedMainJob) }
    }

    $topologyOuterJob = [RawQualificationNative]::CreateKillOnCloseJob(
        "Local\BinanceRawQualificationTopologyOuterTest-" + [Guid]::NewGuid().ToString("N"))
    $topologyWorkloadJob = [RawQualificationNative]::CreateKillOnCloseJob(
        "Local\BinanceRawQualificationTopologyWorkloadTest-" + [Guid]::NewGuid().ToString("N"))
    $topologyWatchdogHandle = [IntPtr]::Zero
    $topologyWorkerHandle = [IntPtr]::Zero
    try {
        $topologyWatchdog = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $topologyOuterJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@("-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30")),
            $repo,
            (Join-Path $testRoot "topology-watchdog.stdout.log"),
            (Join-Path $testRoot "topology-watchdog.stderr.log"),
            $environmentEntries)
        $topologyWatchdogHandle = $topologyWatchdog.ProcessHandle
        $topologyWorker = [RawQualificationNative]::StartSuspendedInJobsRetainedWithEnvironment(
            $topologyOuterJob,
            $topologyWorkloadJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@("-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Milliseconds 500")),
            $repo,
            (Join-Path $testRoot "topology-worker.stdout.log"),
            (Join-Path $testRoot "topology-worker.stderr.log"),
            $environmentEntries)
        $topologyWorkerHandle = $topologyWorker.ProcessHandle
        Assert-True ([RawQualificationNative]::WaitForProcessExit($topologyWorkerHandle, 10000)) `
            "Topology workload parent did not exit."
        $topologyDrain = [Diagnostics.Stopwatch]::StartNew()
        while ([RawQualificationNative]::GetActiveProcessCount($topologyWorkloadJob) -ne 0) {
            if (-not (Test-RawQualificationDeadlineTicks -ElapsedTicks $topologyDrain.ElapsedTicks -TimeoutSeconds 10)) {
                throw "Topology workload Job did not drain to zero."
            }
            Start-Sleep -Milliseconds 50
        }
        Assert-True (-not [RawQualificationNative]::WaitForProcessExit($topologyWatchdogHandle, 0)) `
            "Topology watchdog was not alive after workload drain."
        Assert-True ([RawQualificationNative]::GetActiveProcessCount($topologyOuterJob) -gt 0) `
            "Outer Job unexpectedly became empty while its exact watchdog was alive."
        $null = [RawQualificationNative]::TerminateJobObject($topologyOuterJob, 0xEE72)
        Assert-True ([RawQualificationNative]::WaitForProcessExit($topologyWatchdogHandle, 10000)) `
            "Outer containment did not fence its retained watchdog."
    }
    finally {
        if ($topologyWorkerHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($topologyWorkerHandle) }
        if ($topologyWatchdogHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($topologyWatchdogHandle) }
        if ($topologyWorkloadJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($topologyWorkloadJob) }
        if ($topologyOuterJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($topologyOuterJob) }
    }

    $watchdogScript = (Resolve-Path (Join-Path $PSScriptRoot "RawQualification.Watchdog.ps1")).Path
    $cleanRunId = "clean-" + [Guid]::NewGuid().ToString("N")
    $cleanJobName = "Local\BinanceRawQualificationWatchdogTest-" + [Guid]::NewGuid().ToString("N")
    $cleanJob = [RawQualificationNative]::CreateKillOnCloseJob($cleanJobName)
    $cleanHandle = [IntPtr]::Zero
    try {
        $cleanPulse = Join-Path $testRoot "clean-pulse.jsonl"
        [IO.File]::WriteAllText($cleanPulse, "{}`n", [Text.UTF8Encoding]::new($false))
        $cleanReady = Join-Path $testRoot "clean-ready.json"
        $cleanStop = Join-Path $testRoot "clean-stop.json"
        $cleanFailure = Join-Path $testRoot "clean-failure.json"
        $cleanLaunchOriginQpc = [Diagnostics.Stopwatch]::GetTimestamp()
        $cleanLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $cleanJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $watchdogScript,
                "-HelperPath", $helper,
                "-JobName", $cleanJobName,
                "-RunId", $cleanRunId,
                "-GuardianPulsePath", $cleanPulse,
                "-ReadyPath", $cleanReady,
                "-StopPath", $cleanStop,
                "-FailurePath", $cleanFailure,
                "-LaunchOriginQpcTimestamp", $cleanLaunchOriginQpc.ToString([Globalization.CultureInfo]::InvariantCulture),
                "-MonotonicFrequency", ([Diagnostics.Stopwatch]::Frequency).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-StartupDeadlineSeconds", "30",
                "-MaximumGuardianPulseAgeSeconds", "30"
            )),
            $repo,
            (Join-Path $testRoot "clean-watchdog.stdout.log"),
            (Join-Path $testRoot "clean-watchdog.stderr.log"),
            $environmentEntries)
        $cleanHandle = $cleanLaunch.ProcessHandle
        $null = Write-RawQualificationDurableNewJson -Path $cleanStop -Value ([ordered]@{
            schema = "RawQualificationWatchdogStopV1"
            run_id = $cleanRunId
            job_name = $cleanJobName
            requested_utc = [DateTimeOffset]::UtcNow.ToString("o")
        })
        Assert-True ([RawQualificationNative]::WaitForProcessExit($cleanHandle, 10000)) "Watchdog clean-stop timed out."
        Assert-True ([RawQualificationNative]::GetProcessExitCode($cleanHandle) -eq 0) "Watchdog clean-stop was nonzero."
        Assert-True (-not (Test-Path -LiteralPath $cleanFailure)) "Watchdog clean-stop created failure evidence."
        Assert-True (Test-Path -LiteralPath $cleanReady -PathType Leaf) "Watchdog clean path omitted durable READY evidence."
    }
    finally {
        if ($cleanHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($cleanHandle) }
        if ($cleanJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($cleanJob) }
    }

    $expiredRunId = "expired-startup-" + [Guid]::NewGuid().ToString("N")
    $expiredJobName = "Local\BinanceRawQualificationWatchdogTest-" + [Guid]::NewGuid().ToString("N")
    $expiredJob = [RawQualificationNative]::CreateKillOnCloseJob($expiredJobName)
    $expiredWatchdogHandle = [IntPtr]::Zero
    $expiredSleeperHandle = [IntPtr]::Zero
    try {
        $expiredPulse = Join-Path $testRoot "expired-startup-pulse.jsonl"
        [IO.File]::WriteAllText($expiredPulse, "{}`n", [Text.UTF8Encoding]::new($false))
        $expiredReady = Join-Path $testRoot "expired-startup-ready.json"
        $expiredFailure = Join-Path $testRoot "expired-startup-failure.json"
        $expiredSleeper = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $expiredJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@("-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 300")),
            $repo,
            (Join-Path $testRoot "expired-startup-sleeper.stdout.log"),
            (Join-Path $testRoot "expired-startup-sleeper.stderr.log"),
            $environmentEntries)
        $expiredSleeperHandle = $expiredSleeper.ProcessHandle
        $expiredLaunchOriginQpc = [long]([Diagnostics.Stopwatch]::GetTimestamp() - (2 * [Diagnostics.Stopwatch]::Frequency))
        $expiredWatchdog = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $expiredJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $watchdogScript,
                "-HelperPath", $helper,
                "-JobName", $expiredJobName,
                "-RunId", $expiredRunId,
                "-GuardianPulsePath", $expiredPulse,
                "-ReadyPath", $expiredReady,
                "-StopPath", (Join-Path $testRoot "expired-startup-stop.json"),
                "-FailurePath", $expiredFailure,
                "-LaunchOriginQpcTimestamp", $expiredLaunchOriginQpc.ToString([Globalization.CultureInfo]::InvariantCulture),
                "-MonotonicFrequency", ([Diagnostics.Stopwatch]::Frequency).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-StartupDeadlineSeconds", "1",
                "-MaximumGuardianPulseAgeSeconds", "30")),
            $repo,
            (Join-Path $testRoot "expired-startup-watchdog.stdout.log"),
            (Join-Path $testRoot "expired-startup-watchdog.stderr.log"),
            $environmentEntries)
        $expiredWatchdogHandle = $expiredWatchdog.ProcessHandle
        Assert-True ([RawQualificationNative]::WaitForProcessExit($expiredWatchdogHandle, 10000)) "Expired-origin watchdog did not fence itself."
        Assert-True ([RawQualificationNative]::WaitForProcessExit($expiredSleeperHandle, 10000)) "Expired-origin watchdog did not fence the main Job descendant."
        Assert-True (Test-Path -LiteralPath $expiredFailure -PathType Leaf) "Expired-origin watchdog omitted durable failure evidence."
        Assert-True (-not (Test-Path -LiteralPath $expiredReady)) "Expired-origin watchdog published READY after its startup deadline."
        Assert-True ([RawQualificationNative]::GetActiveProcessCount($expiredJob) -eq 0) "Expired-origin watchdog left the main Job active."
    }
    finally {
        if ($expiredWatchdogHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($expiredWatchdogHandle) }
        if ($expiredSleeperHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($expiredSleeperHandle) }
        if ($expiredJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($expiredJob) }
    }

    $fenceRunId = "fence-" + [Guid]::NewGuid().ToString("N")
    $fenceJobName = "Local\BinanceRawQualificationWatchdogTest-" + [Guid]::NewGuid().ToString("N")
    $fenceJob = [RawQualificationNative]::CreateKillOnCloseJob($fenceJobName)
    $fenceWatchdogHandle = [IntPtr]::Zero
    $fenceSleeperHandle = [IntPtr]::Zero
    try {
        $fencePulse = Join-Path $testRoot "fence-pulse.jsonl"
        [IO.File]::WriteAllText($fencePulse, "{}`n", [Text.UTF8Encoding]::new($false))
        $fenceReady = Join-Path $testRoot "fence-ready.json"
        $fenceStop = Join-Path $testRoot "fence-stop.json"
        $fenceFailure = Join-Path $testRoot "fence-failure.json"
        $fenceLaunchOriginQpc = [Diagnostics.Stopwatch]::GetTimestamp()
        $fenceWatchdogLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $fenceJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $watchdogScript,
                "-HelperPath", $helper,
                "-JobName", $fenceJobName,
                "-RunId", $fenceRunId,
                "-GuardianPulsePath", $fencePulse,
                "-ReadyPath", $fenceReady,
                "-StopPath", $fenceStop,
                "-FailurePath", $fenceFailure,
                "-LaunchOriginQpcTimestamp", $fenceLaunchOriginQpc.ToString([Globalization.CultureInfo]::InvariantCulture),
                "-MonotonicFrequency", ([Diagnostics.Stopwatch]::Frequency).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-StartupDeadlineSeconds", "30",
                "-MaximumGuardianPulseAgeSeconds", "1"
            )),
            $repo,
            (Join-Path $testRoot "fence-watchdog.stdout.log"),
            (Join-Path $testRoot "fence-watchdog.stderr.log"),
            $environmentEntries)
        $fenceWatchdogHandle = $fenceWatchdogLaunch.ProcessHandle
        $fenceSleeperLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $fenceJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@("-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 300")),
            $repo,
            (Join-Path $testRoot "fence-sleeper.stdout.log"),
            (Join-Path $testRoot "fence-sleeper.stderr.log"),
            $environmentEntries)
        $fenceSleeperHandle = $fenceSleeperLaunch.ProcessHandle
        $mtimeMutationObserved = $false
        foreach ($offsetMinutes in @(-120, 120, -60, 60, -30, 30)) {
            try {
                (Get-Item -LiteralPath $fencePulse).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes($offsetMinutes)
                $mtimeMutationObserved = $true
            }
            catch {
                # A filesystem that refuses metadata mutation is also immune to
                # the touch-only bypass; byte length remains unchanged either way.
            }
            Start-Sleep -Milliseconds 250
        }
        Assert-True ([RawQualificationNative]::WaitForProcessExit($fenceWatchdogHandle, 15000)) "Stale-pulse watchdog did not fence its Job."
        Assert-True ([RawQualificationNative]::WaitForProcessExit($fenceSleeperHandle, 10000)) "Stale-pulse watchdog left a descendant alive."
        Assert-True (Test-Path -LiteralPath $fenceFailure -PathType Leaf) "Stale-pulse watchdog omitted durable failure evidence."
    }
    finally {
        if ($fenceWatchdogHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($fenceWatchdogHandle) }
        if ($fenceSleeperHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($fenceSleeperHandle) }
        if ($fenceJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($fenceJob) }
    }

    $lateRunId = "late-growth-stop-" + [Guid]::NewGuid().ToString("N")
    $lateJobName = "Local\BinanceRawQualificationWatchdogTest-" + [Guid]::NewGuid().ToString("N")
    $lateJob = [RawQualificationNative]::CreateKillOnCloseJob($lateJobName)
    $lateWatchdogHandle = [IntPtr]::Zero
    $lateSleeperHandle = [IntPtr]::Zero
    try {
        $latePulse = Join-Path $testRoot "late-growth-stop-pulse.jsonl"
        [IO.File]::WriteAllText($latePulse, "{}`n", [Text.UTF8Encoding]::new($false))
        $lateReady = Join-Path $testRoot "late-growth-stop-ready.json"
        $lateStop = Join-Path $testRoot "late-growth-stop.json"
        $lateFailure = Join-Path $testRoot "late-growth-stop-failure.json"
        $lateLaunchOriginQpc = [Diagnostics.Stopwatch]::GetTimestamp()
        $lateWatchdogLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $lateJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $watchdogScript,
                "-HelperPath", $helper,
                "-JobName", $lateJobName,
                "-RunId", $lateRunId,
                "-GuardianPulsePath", $latePulse,
                "-ReadyPath", $lateReady,
                "-StopPath", $lateStop,
                "-FailurePath", $lateFailure,
                "-LaunchOriginQpcTimestamp", $lateLaunchOriginQpc.ToString([Globalization.CultureInfo]::InvariantCulture),
                "-MonotonicFrequency", ([Diagnostics.Stopwatch]::Frequency).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-StartupDeadlineSeconds", "30",
                "-MaximumGuardianPulseAgeSeconds", "1")),
            $repo,
            (Join-Path $testRoot "late-growth-stop-watchdog.stdout.log"),
            (Join-Path $testRoot "late-growth-stop-watchdog.stderr.log"),
            $environmentEntries)
        $lateWatchdogHandle = $lateWatchdogLaunch.ProcessHandle
        $lateSleeperLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $lateJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@("-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 300")),
            $repo,
            (Join-Path $testRoot "late-growth-stop-sleeper.stdout.log"),
            (Join-Path $testRoot "late-growth-stop-sleeper.stderr.log"),
            $environmentEntries)
        $lateSleeperHandle = $lateSleeperLaunch.ProcessHandle
        Start-Sleep -Milliseconds 1250
        [IO.File]::AppendAllText($latePulse, "{`"late`":true}`n", [Text.UTF8Encoding]::new($false))
        $null = Write-RawQualificationDurableNewJson -Path $lateStop -Value ([ordered]@{
            schema = "RawQualificationWatchdogStopV1"
            run_id = $lateRunId
            job_name = $lateJobName
        })
        Assert-True ([RawQualificationNative]::WaitForProcessExit($lateWatchdogHandle, 15000)) "Late-growth watchdog did not terminate."
        Assert-True ([RawQualificationNative]::GetProcessExitCode($lateWatchdogHandle) -ne 0) "Late growth/STOP erased an already-open watchdog gap."
        Assert-True ([RawQualificationNative]::WaitForProcessExit($lateSleeperHandle, 10000)) "Late growth/STOP watchdog failure left a descendant alive."
        Assert-True (Test-Path -LiteralPath $lateFailure -PathType Leaf) "Late growth/STOP watchdog omitted durable failure evidence."
    }
    finally {
        if ($lateWatchdogHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($lateWatchdogHandle) }
        if ($lateSleeperHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($lateSleeperHandle) }
        if ($lateJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($lateJob) }
    }

    $growthRunId = "growth-" + [Guid]::NewGuid().ToString("N")
    $growthJobName = "Local\BinanceRawQualificationWatchdogTest-" + [Guid]::NewGuid().ToString("N")
    $growthJob = [RawQualificationNative]::CreateKillOnCloseJob($growthJobName)
    $growthHandle = [IntPtr]::Zero
    try {
        $growthPulse = Join-Path $testRoot "growth-pulse.jsonl"
        [IO.File]::WriteAllText($growthPulse, "{}`n", [Text.UTF8Encoding]::new($false))
        $growthReady = Join-Path $testRoot "growth-ready.json"
        $growthStop = Join-Path $testRoot "growth-stop.json"
        $growthFailure = Join-Path $testRoot "growth-failure.json"
        $growthLaunchOriginQpc = [Diagnostics.Stopwatch]::GetTimestamp()
        $growthLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $growthJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $watchdogScript,
                "-HelperPath", $helper,
                "-JobName", $growthJobName,
                "-RunId", $growthRunId,
                "-GuardianPulsePath", $growthPulse,
                "-ReadyPath", $growthReady,
                "-StopPath", $growthStop,
                "-FailurePath", $growthFailure,
                "-LaunchOriginQpcTimestamp", $growthLaunchOriginQpc.ToString([Globalization.CultureInfo]::InvariantCulture),
                "-MonotonicFrequency", ([Diagnostics.Stopwatch]::Frequency).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-StartupDeadlineSeconds", "30",
                "-MaximumGuardianPulseAgeSeconds", "2"
            )),
            $repo,
            (Join-Path $testRoot "growth-watchdog.stdout.log"),
            (Join-Path $testRoot "growth-watchdog.stderr.log"),
            $environmentEntries)
        $growthHandle = $growthLaunch.ProcessHandle
        foreach ($sequence in 1..3) {
            Start-Sleep -Milliseconds 750
            [IO.File]::AppendAllText($growthPulse, "{`"sequence`":$sequence}`n", [Text.UTF8Encoding]::new($false))
        }
        $null = Write-RawQualificationDurableNewJson -Path $growthStop -Value ([ordered]@{
            schema = "RawQualificationWatchdogStopV1"
            run_id = $growthRunId
            job_name = $growthJobName
        })
        Assert-True ([RawQualificationNative]::WaitForProcessExit($growthHandle, 10000)) "Growing-pulse watchdog clean-stop timed out."
        Assert-True ([RawQualificationNative]::GetProcessExitCode($growthHandle) -eq 0) "Real newline-complete pulse growth did not retain watchdog health."
        Assert-True (-not (Test-Path -LiteralPath $growthFailure)) "Real pulse growth produced watchdog failure evidence."
    }
    finally {
        if ($growthHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($growthHandle) }
        if ($growthJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($growthJob) }
    }

    $truncateRunId = "truncate-" + [Guid]::NewGuid().ToString("N")
    $truncateJobName = "Local\BinanceRawQualificationWatchdogTest-" + [Guid]::NewGuid().ToString("N")
    $truncateJob = [RawQualificationNative]::CreateKillOnCloseJob($truncateJobName)
    $truncateWatchdogHandle = [IntPtr]::Zero
    $truncateSleeperHandle = [IntPtr]::Zero
    try {
        $truncatePulse = Join-Path $testRoot "truncate-pulse.jsonl"
        [IO.File]::WriteAllText($truncatePulse, "{}`n", [Text.UTF8Encoding]::new($false))
        $truncateReady = Join-Path $testRoot "truncate-ready.json"
        $truncateFailure = Join-Path $testRoot "truncate-failure.json"
        $truncateLaunchOriginQpc = [Diagnostics.Stopwatch]::GetTimestamp()
        $truncateLaunch = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $truncateJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $watchdogScript,
                "-HelperPath", $helper,
                "-JobName", $truncateJobName,
                "-RunId", $truncateRunId,
                "-GuardianPulsePath", $truncatePulse,
                "-ReadyPath", $truncateReady,
                "-StopPath", (Join-Path $testRoot "truncate-stop.json"),
                "-FailurePath", $truncateFailure,
                "-LaunchOriginQpcTimestamp", $truncateLaunchOriginQpc.ToString([Globalization.CultureInfo]::InvariantCulture),
                "-MonotonicFrequency", ([Diagnostics.Stopwatch]::Frequency).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-StartupDeadlineSeconds", "30",
                "-MaximumGuardianPulseAgeSeconds", "30"
            )),
            $repo,
            (Join-Path $testRoot "truncate-watchdog.stdout.log"),
            (Join-Path $testRoot "truncate-watchdog.stderr.log"),
            $environmentEntries)
        $truncateWatchdogHandle = $truncateLaunch.ProcessHandle
        $truncateSleeper = [RawQualificationNative]::StartSuspendedInJobRetainedWithEnvironment(
            $truncateJob,
            (Join-Path $PSHOME "powershell.exe"),
            ([string[]]@("-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 300")),
            $repo,
            (Join-Path $testRoot "truncate-sleeper.stdout.log"),
            (Join-Path $testRoot "truncate-sleeper.stderr.log"),
            $environmentEntries)
        $truncateSleeperHandle = $truncateSleeper.ProcessHandle
        Start-Sleep -Milliseconds 1500
        $truncateStream = [IO.FileStream]::new($truncatePulse, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        try { $truncateStream.SetLength(0) }
        finally { $truncateStream.Dispose() }
        Assert-True ([RawQualificationNative]::WaitForProcessExit($truncateWatchdogHandle, 10000)) "Watchdog did not fence a truncated retained pulse file."
        Assert-True ([RawQualificationNative]::WaitForProcessExit($truncateSleeperHandle, 10000)) "Truncation fence left a Job descendant alive."
        Assert-True (Test-Path -LiteralPath $truncateFailure -PathType Leaf) "Truncation fence omitted failure evidence."
    }
    finally {
        if ($truncateWatchdogHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($truncateWatchdogHandle) }
        if ($truncateSleeperHandle -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($truncateSleeperHandle) }
        if ($truncateJob -ne [IntPtr]::Zero) { $null = [RawQualificationNative]::CloseHandle($truncateJob) }
    }

    $identityTarget = Join-Path $testRoot "retained-identity.jsonl"
    $identityReplacement = Join-Path $testRoot "retained-identity-replacement.jsonl"
    $identityBackup = Join-Path $testRoot "retained-identity-backup.jsonl"
    [IO.File]::WriteAllText($identityTarget, "{}`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($identityReplacement, "replacement-different-length`n", [Text.UTF8Encoding]::new($false))
    $retainedIdentityStream = [IO.FileStream]::new($identityTarget, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $replacementBlocked = $false
        try { [IO.File]::Replace($identityReplacement, $identityTarget, $identityBackup) }
        catch [IO.IOException] { $replacementBlocked = $true }
        Assert-True $replacementBlocked "A retained no-Delete pulse handle allowed path replacement."
    }
    finally { $retainedIdentityStream.Dispose() }

    $monitorAst = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot "monitor_24h_raw_qualification.ps1"),
        [ref]$null,
        [ref]$null)
    $boundedWrapperNames = @(
        [pscustomobject]@{ Ast = $launcherAst; Name = "Invoke-BoundedQualificationJsonProcess" },
        [pscustomobject]@{ Ast = $launcherAst; Name = "Invoke-BoundedRawCampaignVerifier" },
        [pscustomobject]@{ Ast = $monitorAst; Name = "Invoke-CurrentCampaignVerifier" }
    )
    foreach ($wrapper in $boundedWrapperNames) {
        $definition = @($wrapper.Ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $wrapper.Name
        }, $true))
        Assert-True ($definition.Count -eq 1) "Bounded wrapper extraction was ambiguous: $($wrapper.Name)"
        Assert-True ($definition[0].Extent.Text.Contains('Test-RawQualificationDeadlineTicks')) "Bounded wrapper lacks an exact post-exit deadline gate: $($wrapper.Name)"
        Assert-True ($definition[0].Extent.Text.Contains('ResumeQpcTimestamp') -and
            $definition[0].Extent.Text.Contains('Get-RawQualificationElapsedQpcTicks') -and
            $definition[0].Extent.Text.Contains('Convert-RawQualificationQpcTicksToMilliseconds')) "Bounded wrapper is not timed/proven from the native pre-Resume QPC sample: $($wrapper.Name)"
        if ($wrapper.Name -eq "Invoke-BoundedQualificationJsonProcess") {
            Assert-True ($definition[0].Extent.Text.Contains('StartSuspendedInJobsRetainedWithEnvironment') -and
                $definition[0].Extent.Text.Contains('$boundedJob') -and
                $definition[0].Extent.Text.Contains('GetActiveProcessCount($boundedJob)')) "Generic bounded probe is not nested in the guardian Job and independently drained."
        }
        if ($wrapper.Name -eq "Invoke-BoundedRawCampaignVerifier") {
            Assert-True ($definition[0].Extent.Text.Contains('StartSuspendedInJobsRetainedWithEnvironment') -and
                $definition[0].Extent.Text.Contains('$script:jobHandle') -and
                $definition[0].Extent.Text.Contains('$script:workloadJobHandle') -and
                $definition[0].Extent.Text.Contains('GetActiveProcessCount($script:workloadJobHandle)') -and
                -not $definition[0].Extent.Text.Contains('GetActiveProcessCount($script:jobHandle)')) `
                "Independent verifier is not dual-assigned to outer/workload Jobs and drained only from workload."
        }
    }
    $watchdogStopFunction = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "Stop-GuardianWatchdogClean"
    }, $true))
    Assert-True ($watchdogStopFunction.Count -eq 1 -and
        $watchdogStopFunction[0].Extent.Text.Contains('Test-RawQualificationDeadlineTicks')) "Watchdog clean stop lacks exact post-exit/drain deadline gates."
    $launcherJobDrains = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.WhileStatementAst] -and
            $node.Extent.Text.Contains('GetActiveProcessCount')
    }, $true))
    $monitorJobDrains = @($monitorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.WhileStatementAst] -and
            $node.Extent.Text.Contains('GetActiveProcessCount')
    }, $true))
    Assert-True ($launcherJobDrains.Count -ge 5 -and
        @($launcherJobDrains | Where-Object { -not $_.Extent.Text.Contains('Test-RawQualificationDeadlineTicks') }).Count -eq 0) "A launcher Job drain lacks an exact in-loop deadline gate."
    Assert-True ($monitorJobDrains.Count -eq 1 -and
        $monitorJobDrains[0].Extent.Text.Contains('Test-RawQualificationDeadlineTicks')) "The monitor Job drain lacks an exact in-loop deadline gate."
    $coordinatorDrainElapsedExpressions = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.BinaryExpressionAst] -and
            $node.Operator -eq [Management.Automation.Language.TokenKind]::Minus -and
            $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -ceq "jobDrainWatchdogLivenessObservedTick" -and
            $node.Right -is [Management.Automation.Language.VariableExpressionAst] -and
            $node.Right.VariablePath.UserPath -ceq "dualCoordinatorDrainOriginTick"
    }, $true))
    Assert-True ($coordinatorDrainElapsedExpressions.Count -eq 1) `
        "Coordinator Job drain must derive one exact elapsed sample from the post-query watchdog-liveness observation."
    Assert-True (-not $launcherText.Contains(
            '[long](Get-MonotonicTick - $dualCoordinatorDrainOriginTick')) `
        "Coordinator Job drain regressed to PowerShell command-argument parsing instead of arithmetic subtraction."
    $coordinatorDrainLoops = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.WhileStatementAst] -and
            $node.Extent.Text.Contains('$jobDrainWatchdogPreQuerySignaled') -and
            $node.Extent.Text.Contains('$jobDrainFinalActiveProcesses')
    }, $true))
    Assert-True ($coordinatorDrainLoops.Count -eq 1) `
        "Coordinator Job-drain observation loop extraction was ambiguous."
    $coordinatorDrainLoopText = $coordinatorDrainLoops[0].Extent.Text
    $coordinatorPrecheckIndex = $coordinatorDrainLoopText.IndexOf(
        '$jobDrainWatchdogPreQuerySignaled =', [StringComparison]::Ordinal)
    $coordinatorQueryIndex = $coordinatorDrainLoopText.IndexOf(
        '[uint32][RawQualificationNative]::GetActiveProcessCount($workloadJobHandle)', [StringComparison]::Ordinal)
    $coordinatorQueryTickIndex = $coordinatorDrainLoopText.IndexOf(
        '$jobDrainFinalQueryObservedTick = Get-MonotonicTick', [StringComparison]::Ordinal)
    $coordinatorPostcheckIndex = $coordinatorDrainLoopText.IndexOf(
        '$jobDrainWatchdogPostQuerySignaled =', [StringComparison]::Ordinal)
    $coordinatorLivenessTickIndex = $coordinatorDrainLoopText.IndexOf(
        '$jobDrainWatchdogLivenessObservedTick = Get-MonotonicTick', [StringComparison]::Ordinal)
    $coordinatorElapsedIndex = $coordinatorDrainLoopText.IndexOf(
        '$jobDrainElapsedTicks = [long]($jobDrainWatchdogLivenessObservedTick - $dualCoordinatorDrainOriginTick)',
        [StringComparison]::Ordinal)
    Assert-True ($coordinatorPrecheckIndex -ge 0 -and
        $coordinatorQueryIndex -gt $coordinatorPrecheckIndex -and
        $coordinatorQueryTickIndex -gt $coordinatorQueryIndex -and
        $coordinatorPostcheckIndex -gt $coordinatorQueryTickIndex -and
        $coordinatorLivenessTickIndex -gt $coordinatorPostcheckIndex -and
        $coordinatorElapsedIndex -gt $coordinatorLivenessTickIndex) `
        "Coordinator Job-drain receipt is not ordered precheck -> query -> post-query tick -> postcheck -> liveness tick -> elapsed."
    Assert-True ($coordinatorQueryIndex -ge 0 -and
        -not $coordinatorDrainLoopText.Contains('GetActiveProcessCount($jobHandle)') -and
        $coordinatorDrainLoopText.Contains('$jobDrainFinalActiveProcesses -eq 0') -and
        $coordinatorDrainLoopText.Contains('$jobDrainFinalActiveProcesses -gt [uint32]$jobDrainPreviousActiveProcesses') -and
        $coordinatorDrainLoopText.Contains('Test-RawQualificationDeadlineTicks')) `
        "Coordinator workload drain is not scoped, monotonic, and deadline-bound."
    $coordinatorIncreaseContradictionIndex = $coordinatorDrainLoopText.IndexOf(
        '$jobDrainFinalActiveProcesses -gt [uint32]$jobDrainPreviousActiveProcesses',
        [StringComparison]::Ordinal)
    $coordinatorDeadlineIndex = $coordinatorDrainLoopText.LastIndexOf(
        'Test-RawQualificationDeadlineTicks', [StringComparison]::Ordinal)
    $coordinatorSuccessBreakIndex = $coordinatorDrainLoopText.IndexOf(
        'if ($jobDrainFinalActiveProcesses -eq 0) { break }', [StringComparison]::Ordinal)
    Assert-True ($coordinatorIncreaseContradictionIndex -gt $coordinatorElapsedIndex -and
        $coordinatorDeadlineIndex -gt $coordinatorIncreaseContradictionIndex -and
        $coordinatorSuccessBreakIndex -gt $coordinatorDeadlineIndex) `
        "Coordinator Job-drain success can break before sticky contradictions and the deadline gate."
    $coordinatorDrainOriginAssignments = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -ceq "dualCoordinatorDrainOriginTick"
    }, $true))
    Assert-True ($coordinatorDrainOriginAssignments.Count -eq 1 -and
        $coordinatorDrainOriginAssignments[0].Right.Extent.Text.Contains('ExitObservedTick') -and
        $coordinatorDrainOriginAssignments[0].Right.Extent.Text.Contains('-Maximum')) `
        "Coordinator Job-drain origin is not the unique MAX of both exact exit observations."
    Assert-True ($launcherText.Contains(
            'coordinator_job_final_active_processes = [uint32]$jobDrainFinalActiveProcesses') -and
        $launcherText.Contains('coordinator_job_drain_contract = "RawQualificationCoordinatorWorkloadJobDrainV3"') -and
        $launcherText.Contains('coordinator_job_scope = "INNER_WORKLOAD_ONLY"') -and
        $launcherText.Contains('coordinator_job_name = $workloadJobName') -and
        -not $launcherText.Contains('coordinator_job_active_processes = [uint32]1')) `
        "Coordinator workload-drain receipt does not persist the exact inner Job query."
    Assert-True ($launcherText.Contains('StartSuspendedInJobsRetainedWithEnvironment(') -and
        $launcherText.Contains('$workloadJobHandle,') -and
        $launcherText.Contains('CREATE_SUSPENDED_ASSIGN_OUTER_AND_WORKLOAD_JOBS_RESUME') -and
        $launcherText.Contains('Convert-RawQualificationQpcTicksToWholeSeconds') -and
        -not $launcherText.Contains('$state.ExitElapsedS = [uint64](Get-CaptureElapsedSeconds')) `
        "Coordinator launch containment or exact whole-second floor regressed."
    function Get-SyntheticCoordinatorDrainTick { return [uint64]1260000000 }
    $syntheticCoordinatorExitOriginTick = [uint64]1259900000
    $correctCoordinatorDrainElapsedTicks =
        [long]((Get-SyntheticCoordinatorDrainTick) - $syntheticCoordinatorExitOriginTick)
    $mutantCoordinatorDrainElapsedTicks =
        [long](Get-SyntheticCoordinatorDrainTick - $syntheticCoordinatorExitOriginTick)
    Assert-True ($correctCoordinatorDrainElapsedTicks -eq 100000) `
        "Coordinator Job drain elapsed time is not relative to the latest coordinator-exit observation."
    Assert-True ($mutantCoordinatorDrainElapsedTicks -eq 1260000000) `
        "PowerShell command-argument arithmetic mutant no longer reproduces the production parser hazard."
    Assert-True ((Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $correctCoordinatorDrainElapsedTicks `
            -TimeoutSeconds 10 `
            -Frequency 10000000) -and
        -not (Test-RawQualificationDeadlineTicks `
            -ElapsedTicks $mutantCoordinatorDrainElapsedTicks `
            -TimeoutSeconds 10 `
            -Frequency 10000000)) `
        "Coordinator drain deadline did not distinguish a recent exit origin from total run age."
    Assert-True ($watchdogStopFunction[0].Extent.Text.IndexOf('$stopRequestQpcTimestamp', [StringComparison]::Ordinal) -lt
        $watchdogStopFunction[0].Extent.Text.IndexOf('Write-RawQualificationDurableNewJson', [StringComparison]::Ordinal)) "Watchdog clean-stop timer does not start before durable STOP publication."
    Assert-True ($monitorAst.Extent.Text.Contains("-ElapsedQpcTicks ([long]`$watchdogTerminal.exit_elapsed_qpc_ticks)")) "Terminal monitor does not reject a late watchdog clean stop from its pre-request QPC origin."
    $failureContainmentFunctions = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "Invoke-LauncherFailureContainment"
    }, $true))
    Assert-True ($failureContainmentFunctions.Count -eq 1) "Failure-containment function extraction was ambiguous."
    $testFailureContainmentSourceContract = {
        param([string] $Source)
        $initialIndex = $Source.IndexOf('TryGetActiveProcessCountNoThrow', [StringComparison]::Ordinal)
        $terminateIndex = $Source.IndexOf('TryTerminateJobObjectNoThrow', [StringComparison]::Ordinal)
        $deadlineIndex = $Source.IndexOf('Test-RawQualificationDeadlineTicks', [StringComparison]::Ordinal)
        $deadlineValueIndex = $Source.IndexOf('$FailureContainmentDrainDeadlineSeconds', [StringComparison]::Ordinal)
        $writeIndex = $Source.IndexOf('Write-', [StringComparison]::Ordinal)
        return $initialIndex -ge 0 -and $terminateIndex -gt $initialIndex -and
            $deadlineIndex -gt $terminateIndex -and $deadlineValueIndex -gt $terminateIndex -and
            ($writeIndex -lt 0 -or $terminateIndex -lt $writeIndex) -and
            $Source.Contains('RawQualificationFailureContainmentV2') -and
            $Source.Contains('monotonic_frequency') -and
            $Source.Contains('drain_elapsed_qpc_ticks') -and
            $Source.Contains('final_query_succeeded')
    }
    $failureContainmentSource = $failureContainmentFunctions[0].Extent.Text
    Assert-True (& $testFailureContainmentSourceContract $failureContainmentSource) "Failure containment lost terminate-before-I/O or its exact 30-second QPC drain proof."
    Assert-True (-not (& $testFailureContainmentSourceContract ($failureContainmentSource.Replace(
        'Test-RawQualificationDeadlineTicks', 'DeadlineGateRemoved')))) "Failure containment deadline-removal mutant was accepted."
    Assert-True (-not (& $testFailureContainmentSourceContract ($failureContainmentSource.Replace(
        'TryTerminateJobObjectNoThrow', 'Write-LauncherEvent; TryTerminateJobObjectNoThrow')))) "Failure containment terminate-after-write mutant was accepted."

    $failureContainmentValidators = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "Assert-LauncherFailureContainmentEvidence"
    }, $true))
    Assert-True ($failureContainmentValidators.Count -eq 1) "Launcher failure-containment validator extraction was ambiguous."
    $failureContainmentValidatorSource = $failureContainmentValidators[0].Extent.Text
    Assert-True ($failureContainmentValidatorSource.Contains('RawQualificationFailureContainmentV2') -and
        $failureContainmentValidatorSource.Contains('switch -CaseSensitive') -and
        $failureContainmentValidatorSource.Contains('Test-RawQualificationDeadlineTicks')) `
        "Launcher failure-containment validator lacks exact schema, result, or deadline semantics."
    $FailureContainmentExitCode = [uint32]0xEE02
    $FailureContainmentDrainDeadlineSeconds = [uint64]30
    Invoke-Expression $failureContainmentValidatorSource
    $validFailureContainment = [pscustomobject][ordered]@{
        schema = "RawQualificationFailureContainmentV2"
        job_name = "Local\BinanceRawQualificationJob-selftest"
        job_kill_on_close = $false
        detected_wall_ns = [uint64]1
        detected_monotonic_tick = [uint64]10
        requested_exit_code = [uint32]60930
        initial_query_succeeded = $false
        initial_active_processes = $null
        initial_query_error = [uint32]6
        terminate_attempted = $false
        terminate_succeeded = $null
        terminate_error = $null
        termination_monotonic_tick = [uint64]11
        monotonic_frequency = [uint64][Diagnostics.Stopwatch]::Frequency
        drain_deadline_s = [uint64]30
        drain_elapsed_qpc_ticks = [uint64]0
        final_query_succeeded = $false
        final_active_processes = $null
        final_query_error = [uint32]6
        result = "NO_JOB_HANDLE"
    }
    $null = Assert-LauncherFailureContainmentEvidence -Value $validFailureContainment

    $terminalEvidenceArgumentFunctions = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "Assert-TerminalEvidenceArguments"
    }, $true))
    Assert-True ($terminalEvidenceArgumentFunctions.Count -eq 1) "Terminal evidence argument validator extraction was ambiguous."
    $terminalEvidenceArgumentSource = $terminalEvidenceArgumentFunctions[0].Extent.Text
    Assert-True ($terminalEvidenceArgumentSource.Contains('[AllowNull()] $Failure') -and
        $terminalEvidenceArgumentSource.Contains('[AllowNull()] $FailureContainmentSha256') -and
        $terminalEvidenceArgumentSource.Contains('[ValidateSet("COMPLETE", "FAILED")] $Status') -and
        -not $terminalEvidenceArgumentSource.Contains('[AllowNull()] [string] $Failure') -and
        -not $terminalEvidenceArgumentSource.Contains('[string] $Status') -and
        $terminalEvidenceArgumentSource.Contains('$Status -isnot [string]') -and
        $terminalEvidenceArgumentSource.Contains('$Failure -isnot [string]') -and
        $terminalEvidenceArgumentSource.Contains('$FailureContainmentSha256 -isnot [string]')) `
        "Terminal evidence arguments can coerce COMPLETE nulls or accept non-string FAILED evidence."
    Invoke-Expression $terminalEvidenceArgumentSource
    $completeNullEvidenceAccepted = $true
    try {
        $null = Assert-TerminalEvidenceArguments -Status COMPLETE -Failure $null -FailureContainment $null -FailureContainmentSha256 $null
    }
    catch { $completeNullEvidenceAccepted = $false }
    Assert-True $completeNullEvidenceAccepted "Exact null COMPLETE terminal evidence was rejected."
    $completeEmptyFailureRejected = $false
    try {
        $null = Assert-TerminalEvidenceArguments -Status COMPLETE -Failure '' -FailureContainment $null -FailureContainmentSha256 $null
    }
    catch { $completeEmptyFailureRejected = $true }
    Assert-True $completeEmptyFailureRejected "COMPLETE terminal accepted an empty-string failure mutant."
    $noncanonicalTerminalStatusRejected = $false
    try {
        $null = Assert-TerminalEvidenceArguments -Status complete -Failure $null -FailureContainment $null -FailureContainmentSha256 $null
    }
    catch { $noncanonicalTerminalStatusRejected = $true }
    Assert-True $noncanonicalTerminalStatusRejected "Terminal evidence validator accepted noncanonical status casing."
    $coercibleNonStringTerminalStatusRejected = $false
    try {
        $null = Assert-TerminalEvidenceArguments `
            -Status ([Text.StringBuilder]::new('COMPLETE')) `
            -Failure $null -FailureContainment $null -FailureContainmentSha256 $null
    }
    catch { $coercibleNonStringTerminalStatusRejected = $true }
    Assert-True $coercibleNonStringTerminalStatusRejected `
        "Terminal evidence validator accepted a non-string object coercible to COMPLETE."
    $failedNumericEvidenceRejected = $false
    try {
        $null = Assert-TerminalEvidenceArguments -Status FAILED -Failure ([uint64]1) -FailureContainment $validFailureContainment -FailureContainmentSha256 ('a' * 64)
    }
    catch { $failedNumericEvidenceRejected = $true }
    Assert-True $failedNumericEvidenceRejected "FAILED terminal accepted a non-string failure mutant."
    $failedNumericDigestRejected = $false
    try {
        $null = Assert-TerminalEvidenceArguments -Status FAILED -Failure 'failure' -FailureContainment $validFailureContainment -FailureContainmentSha256 ([uint64]1)
    }
    catch { $failedNumericDigestRejected = $true }
    Assert-True $failedNumericDigestRejected "FAILED terminal accepted a non-string containment digest mutant."
    $validFailedEvidenceAccepted = $true
    try {
        $null = Assert-TerminalEvidenceArguments -Status FAILED -Failure 'failure' -FailureContainment $validFailureContainment -FailureContainmentSha256 ('a' * 64)
    }
    catch { $validFailedEvidenceAccepted = $false }
    Assert-True $validFailedEvidenceAccepted "Exact typed FAILED terminal evidence was rejected."
    $invalidFailureContainmentRejected = $false
    try {
        $null = Assert-TerminalEvidenceArguments -Status FAILED -Failure 'failure' `
            -FailureContainment ([pscustomobject]@{ result = 'NO_JOB_HANDLE' }) `
            -FailureContainmentSha256 ('a' * 64)
    }
    catch { $invalidFailureContainmentRejected = $true }
    Assert-True $invalidFailureContainmentRejected "FAILED terminal accepted incomplete containment evidence."
    $typedStringNullMutant = & {
        param([AllowNull()] [string] $Failure, [AllowNull()] [string] $Digest)
        return ($null -ne $Failure -and $Failure.Length -eq 0 -and $null -ne $Digest -and $Digest.Length -eq 0)
    } -Failure $null -Digest $null
    Assert-True $typedStringNullMutant "PowerShell typed-string null coercion mutant was not reproduced."

    $terminalAcknowledgementFunctions = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Assert-TerminalPublicationAcknowledgement'
    }, $true))
    Assert-True ($terminalAcknowledgementFunctions.Count -eq 1) `
        "Terminal publication acknowledgement function extraction was ambiguous."
    $terminalAcknowledgementSource = $terminalAcknowledgementFunctions[0].Extent.Text
    Assert-True ($terminalAcknowledgementSource.Contains('[AllowNull()] $Actual') -and
        $terminalAcknowledgementSource.Contains('$Actual -isnot [string]') -and
        $terminalAcknowledgementSource.Contains('$Actual -cne $Expected')) `
        "Terminal publication acknowledgement helper is coercible or case-insensitive."
    Invoke-Expression $terminalAcknowledgementSource
    $null = Assert-TerminalPublicationAcknowledgement -Actual 'COMPLETE' -Expected 'COMPLETE'
    $null = Assert-TerminalPublicationAcknowledgement -Actual 'FAILED' -Expected 'FAILED'
    $completeAckMutants = [Collections.Generic.List[object]]::new()
    $completeAckMutants.Add($null)
    $completeAckMutants.Add('')
    $completeAckMutants.Add('complete')
    $completeAckMutants.Add('FAILED')
    $completeAckMutants.Add([uint64]1)
    $completeAckMutants.Add([object[]]@($null, 'COMPLETE'))
    $completeAckMutantsRejected = $true
    foreach ($mutant in $completeAckMutants) {
        try { $null = Assert-TerminalPublicationAcknowledgement -Actual $mutant -Expected 'COMPLETE'; $completeAckMutantsRejected = $false }
        catch {}
    }
    Assert-True $completeAckMutantsRejected `
        "COMPLETE terminal publication accepted a null, noncanonical, opposite, or non-string acknowledgement."
    $failedAckMutants = [Collections.Generic.List[object]]::new()
    $failedAckMutants.Add($null)
    $failedAckMutants.Add('')
    $failedAckMutants.Add('failed')
    $failedAckMutants.Add('COMPLETE')
    $failedAckMutants.Add([uint64]1)
    $failedAckMutants.Add([object[]]@($null, 'FAILED'))
    $failedAckMutantsRejected = $true
    foreach ($mutant in $failedAckMutants) {
        try { $null = Assert-TerminalPublicationAcknowledgement -Actual $mutant -Expected 'FAILED'; $failedAckMutantsRejected = $false }
        catch {}
    }
    Assert-True $failedAckMutantsRejected `
        "FAILED terminal publication accepted a null, noncanonical, opposite, or non-string acknowledgement."
    Assert-True ($launcherText.Contains('Assert-TerminalPublicationAcknowledgement -Actual $writtenStatus -Expected "COMPLETE"') -and
        $launcherText.Contains('$failedWrittenStatus = Write-TerminalManifest') -and
        $launcherText.Contains('Assert-TerminalPublicationAcknowledgement -Actual $failedWrittenStatus -Expected "FAILED"') -and
        -not $launcherText.Contains('$null = Write-TerminalManifest')) `
        "Launcher terminal paths do not require exact typed publication acknowledgements."

    $terminalWriterFunctions = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "Write-TerminalManifest"
    }, $true))
    Assert-True ($terminalWriterFunctions.Count -eq 1) "Terminal-writer function extraction was ambiguous."
    $testTerminalPostLinkSourceContract = {
        param([string] $Source)
        $contractTokens = $null
        $contractErrors = $null
        $contractAst = [Management.Automation.Language.Parser]::ParseInput(
            $Source, [ref]$contractTokens, [ref]$contractErrors)
        if (@($contractErrors).Count -ne 0) { return $false }
        $contractFunctions = @($contractAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Write-TerminalManifest'
        }, $true))
        if ($contractFunctions.Count -ne 1) { return $false }
        $contractFunction = $contractFunctions[0]
        $contractStatements = @($contractFunction.Body.EndBlock.Statements)
        if ($contractStatements.Count -lt 4) { return $false }
        $contractTail = @($contractStatements[($contractStatements.Count - 4)..($contractStatements.Count - 1)])
        $uncapturedNullOutputs = @($contractFunction.FindAll({
            param($node)
            $node -is [Management.Automation.Language.VariableExpressionAst] -and
                $node.VariablePath.UserPath -ceq 'null' -and
                $node.Parent -is [Management.Automation.Language.CommandExpressionAst]
        }, $true) | Where-Object {
            $ancestor = $_.Parent
            $captured = $false
            while ($null -ne $ancestor -and $ancestor -ne $contractFunction) {
                if ($ancestor -is [Management.Automation.Language.AssignmentStatementAst] -or
                    $ancestor -is [Management.Automation.Language.HashtableAst] -or
                    $ancestor -is [Management.Automation.Language.ReturnStatementAst] -or
                    $ancestor -is [Management.Automation.Language.ScriptBlockExpressionAst]) {
                    $captured = $true
                    break
                }
                $ancestor = $ancestor.Parent
            }
            -not $captured
        })
        $topLevelReturns = @($contractFunction.FindAll({
            param($node)
            $node -is [Management.Automation.Language.ReturnStatementAst]
        }, $true) | Where-Object {
            $ancestor = $_.Parent
            $nestedScriptBlock = $false
            while ($null -ne $ancestor -and $ancestor -ne $contractFunction) {
                if ($ancestor -is [Management.Automation.Language.ScriptBlockAst] -and
                    $ancestor -ne $contractFunction.Body) {
                    $nestedScriptBlock = $true
                    break
                }
                $ancestor = $ancestor.Parent
            }
            -not $nestedScriptBlock
        })
        $durableIndex = $Source.IndexOf('Write-RawQualificationDurableNewJson', [StringComparison]::Ordinal)
        $postLinkIndex = $Source.IndexOf('event = "LAUNCHER_TERMINAL"', [StringComparison]::Ordinal)
        $closeIndex = $Source.LastIndexOf('Close-RawQualificationJournal', [StringComparison]::Ordinal)
        $returnIndex = $Source.LastIndexOf('return $Status', [StringComparison]::Ordinal)
        return $Source.Contains('RawQualificationLauncherTerminalV2') -and
            $Source.Contains('failure_containment_sha256') -and
            $Source.Contains('file_bytes') -and $Source.Contains('file_sha256') -and
            $Source.Contains('terminal_bytes') -and $Source.Contains('terminal_sha256') -and
            $durableIndex -ge 0 -and $postLinkIndex -gt $durableIndex -and
            $closeIndex -gt $postLinkIndex -and $returnIndex -gt $closeIndex -and
            $Source.Contains('if ((Get-RawQualificationSha256Bytes -Bytes $containmentCompactBytes) -cne $FailureContainmentSha256)') -and
            $Source.Contains('try { Close-RawQualificationJournal -Journal $script:eventJournal } catch {}') -and
            $contractTail[0] -is [Management.Automation.Language.IfStatementAst] -and
            $contractTail[0].Extent.Text.Contains('$script:eventJournal.Closed') -and
            $contractTail[1] -is [Management.Automation.Language.PipelineAst] -and
            $contractTail[1].Extent.Text.StartsWith('Write-LauncherEvent -Channel "LAUNCHER"', [StringComparison]::Ordinal) -and
            $contractTail[1].Extent.Text.Contains('event = "LAUNCHER_TERMINAL"') -and
            $contractTail[2] -is [Management.Automation.Language.TryStatementAst] -and
            $contractTail[3] -is [Management.Automation.Language.ReturnStatementAst] -and
            $uncapturedNullOutputs.Count -eq 0 -and
            $topLevelReturns.Count -eq 1 -and
            $topLevelReturns[0].Extent.Text -ceq 'return $Status'
    }
    $terminalWriterSource = $terminalWriterFunctions[0].Extent.Text
    Assert-True ((& $testTerminalPostLinkSourceContract $terminalWriterSource) -and
        $terminalWriterSource.Contains('Assert-TerminalEvidenceArguments') -and
        $terminalWriterSource.Contains('[ValidateSet("COMPLETE", "FAILED")] $Status') -and
        -not $terminalWriterSource.Contains('[string] $Status') -and
        -not $terminalWriterSource.Contains('[AllowNull()] [string] $Failure')) "Terminal V2 lost type-preserving validation, its durable preterminal receipt, or post-terminal SHA-256 link."
    Assert-True (-not (& $testTerminalPostLinkSourceContract ($terminalWriterSource.Replace(
        'event = "LAUNCHER_TERMINAL"', 'event = "LAUNCHER_TERMINAL_REMOVED"')))) "Terminal post-link removal mutant was accepted."
    Assert-True (-not (& $testTerminalPostLinkSourceContract ($terminalWriterSource.Replace(
        '$terminalBytes = [uint64](Get-Item -LiteralPath $path -ErrorAction Stop).Length',
        '$terminalBytes = [uint64](Get-Item -LiteralPath $path -ErrorAction Stop).Length; return $Status')))) `
        "Terminal early-return-before-post-link mutant was accepted."
    Assert-True (-not (& $testTerminalPostLinkSourceContract ($terminalWriterSource.Replace(
        '$script:terminalWritten = $true', '$script:terminalWritten = $true; return "COMPLETE"')))) `
        "Terminal literal early-return-before-post-link mutant was accepted."
    $postLinkStatementText = $terminalWriterFunctions[0].Body.EndBlock.Statements[
        $terminalWriterFunctions[0].Body.EndBlock.Statements.Count - 3].Extent.Text
    $conditionalPostLinkMutant = $terminalWriterSource.Replace(
        $postLinkStatementText,
        ('if ($false) {' + [Environment]::NewLine + $postLinkStatementText + [Environment]::NewLine + '}'))
    Assert-True (-not (& $testTerminalPostLinkSourceContract $conditionalPostLinkMutant)) `
        "Terminal conditional-disabled post-link mutant was accepted."
    Assert-True (-not (& $testTerminalPostLinkSourceContract ($terminalWriterSource.Replace(
        '-cne $FailureContainmentSha256', '-ceq $FailureContainmentSha256')))) `
        "Terminal containment digest comparison inversion mutant was accepted."
    $terminalHashLineMarker = '    $terminalHashes = [ordered]@{'
    $terminalHashLineIndex = $terminalWriterSource.IndexOf(
        $terminalHashLineMarker, [StringComparison]::Ordinal)
    Assert-True ($terminalHashLineIndex -ge 0) `
        "Terminal null-output mutant insertion marker is absent."
    $terminalNullOutputMutant = $terminalWriterSource.Insert(
        $terminalHashLineIndex,
        '    if ($false) { "unreachable" } else { $null }' + [Environment]::NewLine)
    Assert-True (-not (& $testTerminalPostLinkSourceContract $terminalNullOutputMutant)) `
        "Terminal writer accepted an uncaptured null pipeline output before its typed acknowledgement."
    $powerShellNullPipelineOutput = @(& { $null; return 'FAILED' })
    $powerShellNullPipelineOutputReproduced = $powerShellNullPipelineOutput.Count -eq 2 -and
        $null -eq $powerShellNullPipelineOutput[0] -and
        $powerShellNullPipelineOutput[1] -is [string] -and
        [string]$powerShellNullPipelineOutput[1] -ceq 'FAILED'
    Assert-True $powerShellNullPipelineOutputReproduced `
        "PowerShell 5.1 standalone-null pipeline output was not reproduced."
    $terminalCommitIndex = $launcherText.LastIndexOf('Assert-TerminalPublicationAcknowledgement -Actual $writtenStatus -Expected "COMPLETE"', [StringComparison]::Ordinal)
    $launcherFinallyIndex = $launcherText.LastIndexOf('finally {', [StringComparison]::Ordinal)
    $successConsoleIndex = $launcherText.LastIndexOf('Write-Host "PASS:', [StringComparison]::Ordinal)
    Assert-True ($terminalCommitIndex -ge 0 -and $launcherFinallyIndex -gt $terminalCommitIndex -and
        $successConsoleIndex -gt $launcherFinallyIndex -and
        $launcherText.Contains('try { Write-Host "PASS: $runRoot\launcher-terminal.json" } catch {}') -and
        $launcherText.Contains('try { $mutex.Dispose() } catch {}')) `
        "Fallible success console output remains inside the terminal transaction catch boundary."

    $verifiedResultPublicationFunctions = @($launcherAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "Add-IndependentCampaignVerifiedResult"
    }, $true))
    Assert-True ($verifiedResultPublicationFunctions.Count -eq 1) "Verified-result publication function extraction was ambiguous."
    $verifiedResultPublicationSource = $verifiedResultPublicationFunctions[0].Extent.Text
    $durableVerifiedEventIndex = $verifiedResultPublicationSource.IndexOf(
        '$null = & $DurableEventWriter', [StringComparison]::Ordinal)
    $inMemoryResultIndex = $verifiedResultPublicationSource.IndexOf(
        '$script:campaignResults += $CampaignResult', [StringComparison]::Ordinal)
    Assert-True ($durableVerifiedEventIndex -ge 0 -and $inMemoryResultIndex -gt $durableVerifiedEventIndex) `
        "Campaign result advances before its durable INDEPENDENT_CAMPAIGN_VERIFIED receipt."
    Invoke-Expression $verifiedResultPublicationSource
    $syntheticVerifiedResult = [pscustomobject][ordered]@{
        symbol = "BTCUSDT"
        independent_verifiers = [object[]]@(
            [pscustomobject]@{ name="btcusdt-rust"; report_sha256=('a' * 64) },
            [pscustomobject]@{ name="btcusdt-python"; report_sha256=('b' * 64) })
    }
    $script:campaignResults = @()
    $verifiedEventAppendFailureRejected = $false
    try {
        Add-IndependentCampaignVerifiedResult `
            -CampaignResult $syntheticVerifiedResult `
            -DurableEventWriter { param($Channel, $Payload) throw "Synthetic durable append failure." }
    }
    catch { $verifiedEventAppendFailureRejected = $true }
    Assert-True ($verifiedEventAppendFailureRejected -and @($script:campaignResults).Count -eq 0) `
        "A failed INDEPENDENT_CAMPAIGN_VERIFIED append leaked an unreceipted terminal result."
    $verifiedPublicationTrace = [Collections.Generic.List[object]]::new()
    Add-IndependentCampaignVerifiedResult `
        -CampaignResult $syntheticVerifiedResult `
        -DurableEventWriter {
            param($Channel, $Payload)
            $verifiedPublicationTrace.Add([pscustomobject]@{channel=$Channel;payload=$Payload})
        }
    Assert-True ($verifiedPublicationTrace.Count -eq 1 -and
        [string]$verifiedPublicationTrace[0].channel -ceq "VERIFICATION" -and
        [string]$verifiedPublicationTrace[0].payload.event -ceq "INDEPENDENT_CAMPAIGN_VERIFIED" -and
        @($script:campaignResults).Count -eq 1) `
        "Durable verified-result publication did not advance exactly once after acknowledgement."

    $terminalVerifierPolicyFunctions = @($monitorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "Assert-MonitorTerminalVerifierPolicyBinding"
    }, $true))
    Assert-True ($terminalVerifierPolicyFunctions.Count -eq 1) "Terminal verifier-policy validator extraction was ambiguous."
    Invoke-Expression $terminalVerifierPolicyFunctions[0].Extent.Text
    $policyStartup = [pscustomobject]@{ verifier_policy = [pscustomobject]@{
        per_process_timeout_s = [uint64]7200
        total_post_capture_timeout_s = [uint64]14400
        maximum_artifact_bytes = [uint64](32MB)
    }}
    $policyTerminal = [pscustomobject]@{ verifier_policy = [pscustomobject]@{
        per_process_timeout_s = [uint64]7200
        total_post_capture_timeout_s = [uint64]14400
        maximum_artifact_bytes = [uint64](32MB)
    }}
    $null = Assert-MonitorTerminalVerifierPolicyBinding -Terminal $policyTerminal -Startup $policyStartup
    $terminalVerifierPolicyMutantsRejected = [uint64]0
    foreach ($policyName in @("per_process_timeout_s", "total_post_capture_timeout_s")) {
        $policyMutant = $policyTerminal | ConvertTo-Json -Depth 10 -Compress | ConvertFrom-Json
        $policyMutant.verifier_policy.$policyName = [uint64]([uint64]$policyMutant.verifier_policy.$policyName + 1)
        $rejected = $false
        try { $null = Assert-MonitorTerminalVerifierPolicyBinding -Terminal $policyMutant -Startup $policyStartup }
        catch { $rejected = $true }
        Assert-True $rejected "Terminal verifier-policy binding accepted a re-selled $policyName mutant."
        $terminalVerifierPolicyMutantsRejected++
    }
    foreach ($functionName in @(
        "Test-MonitorExactJsonProperties",
        "Test-MonitorBoundedExecutionCausality",
        "Assert-MonitorProviderExecutionJsonTypes",
        "Test-MonitorQpcExecutionEvidence")) {
        $definition = @($monitorAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $functionName
        }, $true))
        Assert-True ($definition.Count -eq 1) "Provider validator dependency extraction was ambiguous: $functionName"
        Invoke-Expression $definition[0].Extent.Text
    }
    $providerHistoryFunction = @($monitorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "Assert-HostProviderExecutionHistory"
    }, $true))
    Assert-True ($providerHistoryFunction.Count -eq 1) "Provider-history validator extraction was ambiguous."
    Invoke-Expression $providerHistoryFunction[0].Extent.Text
    $validDigest = 'a' * 64
    $providerStartup = [pscustomobject]@{
        launcher_pid = [uint32]$PID
        monotonic_frequency = [uint64]1000
        monotonic_origin_qpc_timestamp = [long]1
        preflight = [pscustomobject]@{
            powershell_executable = (Join-Path $PSHOME "powershell.exe")
            telemetry_probe_script = (Resolve-Path (Join-Path $PSScriptRoot "RawQualification.TelemetryProbe.ps1")).Path
            helper_script = $helper
            drive_device_id = "C:"
        }
    }
    $providerArguments = [string[]]@(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
        [string]$providerStartup.preflight.telemetry_probe_script,
        "-HelperPath", [string]$providerStartup.preflight.helper_script,
        "-DriveDeviceId", [string]$providerStartup.preflight.drive_device_id,
        "-RootProcessId", ([uint32]$PID).ToString([Globalization.CultureInfo]::InvariantCulture))
    $providerCommand = [RawQualificationNative]::BuildExactCommandLine(
        [string]$providerStartup.preflight.powershell_executable,
        $providerArguments)
    $providerCommandDigest = Get-RawQualificationSha256Bytes -Bytes (
        [Text.UTF8Encoding]::new($false).GetBytes($providerCommand))
    $earlierLateProvider = [pscustomobject]@{
        pid = [uint32]101
        timeout_s = [uint64]20
        resume_qpc_timestamp = [long]100
        elapsed_qpc_ticks = [long]20001
        monotonic_frequency = [long]1000
        job_membership = "PRIMARY_AND_NESTED_BOUNDED"
        parent_exit_observed_qpc_timestamp = [long]20101
        descendant_drain_elapsed_qpc_ticks = [long]1
        descendant_drain_elapsed_ms = [uint64]1
        descendant_drain_active_processes = [uint32]0
        elapsed_ms = [uint64]20001
        stdout_bytes = [uint64]1
        stdout_sha256 = $validDigest
        stderr_bytes = [uint64]0
        stderr_sha256 = $validDigest
        command_line_sha256 = $providerCommandDigest
    }
    $laterHealthyProvider = [pscustomobject]@{
        pid = [uint32]102
        timeout_s = [uint64]20
        resume_qpc_timestamp = [long]30001
        elapsed_qpc_ticks = [long]1
        monotonic_frequency = [long]1000
        job_membership = "PRIMARY_AND_NESTED_BOUNDED"
        parent_exit_observed_qpc_timestamp = [long]30002
        descendant_drain_elapsed_qpc_ticks = [long]1
        descendant_drain_elapsed_ms = [uint64]1
        descendant_drain_active_processes = [uint32]0
        elapsed_ms = [uint64]1
        stdout_bytes = [uint64]1
        stdout_sha256 = $validDigest
        stderr_bytes = [uint64]0
        stderr_sha256 = $validDigest
        command_line_sha256 = $providerCommandDigest
    }
    $historyWithHiddenLateProbe = [pscustomobject]@{
        records = [uint64]2
        provider_executions = @($earlierLateProvider, $laterHealthyProvider)
        all_records = @(
            [pscustomobject]@{ body = [pscustomobject]@{ monotonic_tick = [uint64]30000 } },
            [pscustomobject]@{ body = [pscustomobject]@{ monotonic_tick = [uint64]40000 } })
    }
    $hiddenLateProbeRejected = $false
    try {
        $null = Assert-HostProviderExecutionHistory `
            -Journal $historyWithHiddenLateProbe `
            -Startup $providerStartup `
            -ExpectedTimeoutSeconds 20 `
            -MaximumArtifactBytes 1024
    }
    catch { $hiddenLateProbeRejected = $true }
    Assert-True $hiddenLateProbeRejected "A later healthy provider hid an earlier deadline violation."
    $earlierLateProvider.elapsed_qpc_ticks = [long]20000
    $earlierLateProvider.elapsed_ms = [uint64]20000
    $earlierLateProvider.parent_exit_observed_qpc_timestamp = [long]20100
    Assert-True (Assert-HostProviderExecutionHistory `
        -Journal $historyWithHiddenLateProbe `
        -Startup $providerStartup `
        -ExpectedTimeoutSeconds 20 `
        -MaximumArtifactBytes 1024) "Exact-deadline provider history should pass."
    $providerQpcCausalityMutantsRejected = [uint64]0
    foreach ($providerCase in @(
        "resume-before-origin", "parent-elapsed-mismatch", "drain-after-host-event",
        "next-resume-before-previous-host-event")) {
        $providerMutantHistory = ($historyWithHiddenLateProbe | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
        $providerMutantStartup = ($providerStartup | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
        switch ($providerCase) {
            "resume-before-origin" { $providerMutantStartup.monotonic_origin_qpc_timestamp = [long]101 }
            "parent-elapsed-mismatch" { $providerMutantHistory.provider_executions[0].parent_exit_observed_qpc_timestamp = [long]20101 }
            "drain-after-host-event" {
                $providerMutantHistory.provider_executions[0].descendant_drain_elapsed_qpc_ticks = [long]10000
                $providerMutantHistory.provider_executions[0].descendant_drain_elapsed_ms = [uint64]10000
            }
            "next-resume-before-previous-host-event" {
                $providerMutantHistory.provider_executions[1].resume_qpc_timestamp = [long]30000
                $providerMutantHistory.provider_executions[1].parent_exit_observed_qpc_timestamp = [long]30001
            }
        }
        $rejected = $false
        try { $null = Assert-HostProviderExecutionHistory -Journal $providerMutantHistory -Startup $providerMutantStartup -ExpectedTimeoutSeconds 20 -MaximumArtifactBytes 1024 }
        catch { $rejected = $true }
        Assert-True $rejected "Provider QPC causality mutant was accepted: $providerCase"
        $providerQpcCausalityMutantsRejected++
    }
    foreach ($replacement in @("100", $false, [double]100)) {
        $providerMutantHistory = ($historyWithHiddenLateProbe | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
        $providerMutantHistory.provider_executions[0].resume_qpc_timestamp = $replacement
        $rejected = $false
        try { $null = Assert-HostProviderExecutionHistory -Journal $providerMutantHistory -Startup $providerStartup -ExpectedTimeoutSeconds 20 -MaximumArtifactBytes 1024 }
        catch { $rejected = $true }
        Assert-True $rejected "Provider untyped QPC mutant was accepted: $($replacement.GetType().Name)"
        $providerQpcCausalityMutantsRejected++
    }
    Assert-True ($providerQpcCausalityMutantsRejected -eq 7) "Provider QPC adversarial matrix is incomplete."

    foreach ($functionName in @(
        "Test-MonitorExactJsonProperties",
        "Test-MonitorExactJsonPropertyOrder",
        "Test-MonitorJsonFiniteNumber",
        "Test-MonitorJsonRealNumber",
        "Test-MonitorJsonNullOrInteger",
        "Test-MonitorJsonNullOrString",
        "Assert-MonitorJsonStringArray",
        "Test-MonitorByteArraysEqual",
        "Test-MonitorTransientTreeSnapshotException",
        "Get-MonitorEvidenceTreeStructureSnapshot",
        "Assert-MonitorEvidenceTreeNoReparsePoints",
        "Resolve-MonitorContainedEvidencePath",
        "ConvertTo-MonitorTwoSpacePrettyJsonBytes",
        "Read-MonitorCanonicalJsonSnapshot",
        "Read-MonitorFrozenCanonicalJsonLines",
        "ConvertFrom-MonitorCanonicalCompactJsonLine",
        "Test-MonitorJsonObjectKeysOrdinalSortedRecursive",
        "Assert-MonitorJournalRecordEnvelopeJsonTypes",
        "Assert-MonitorQualificationJournalWriterOrder",
        "Assert-MonitorClockJsonTypes",
        "Assert-MonitorDiskJsonTypes",
        "Assert-MonitorNetworkJsonTypes",
        "Assert-MonitorCollectorProcessJsonTypes",
        "Assert-MonitorCampaignSummaryJsonTypes",
        "Assert-MonitorHostTelemetryPayloadJsonTypes",
        "Assert-MonitorLauncherRecordJsonContract",
        "Assert-MonitorStartupControlJsonTypes",
        "Assert-MonitorStartupControlRecursiveJsonTypes",
        "Test-MonitorBoundedExecutionCausality",
        "Test-MonitorVerifierExecutionCausality",
        "Assert-MonitorPostCreateProbeJsonTypes",
        "Assert-MonitorTelemetryProbePayloadJsonTypes",
        "Assert-MonitorSealedVerifierJsonTypes",
        "Assert-MonitorTerminalWatchdogJsonTypes",
        "Assert-MonitorBindingsWriterOrder",
        "Assert-MonitorTerminalWriterOrder",
        "Assert-MonitorTerminalCampaignJsonTypes",
        "Assert-MonitorTerminalRecursiveJsonTypes",
        "Assert-MonitorFailureContainmentJsonContract",
        "Assert-MonitorTerminalV2JsonContract",
        "Assert-MonitorRustCampaignSingletonWriterOrder",
        "Assert-MonitorRustCampaignSingletonJsonTypes",
        "Assert-MonitorCampaignStartupBinding",
        "Assert-MonitorExecutionWriterOrder",
        "Get-VerifiedJournalSummary",
        "Assert-MonitorRustCampaignJournalEnvelopeJsonTypes",
        "Assert-MonitorRustCampaignPayloadJsonContract",
        "Get-CampaignJournalHealth",
        "Get-MonitorRemainingProjectionGiB",
        "Test-MonitorVerifierExecutionBudget",
        "Test-MonitorVerifierArtifactBounds",
        "Get-MonitorExpectedVerifierTimeoutSeconds",
        "Add-MonitorSequentialProcessIdentity",
        "Test-MonitorCampaignVerifiedReportBinding",
        "Assert-PostCreateProbeEvidence",
        "Assert-GuardianPulseHistory",
        "Assert-HostTelemetryHistory",
        "Test-MonitorStartupMonotonicFrequency",
        "Assert-MonitorCaptureDrainingTiming",
        "Get-MonitorEventDrivenStage",
        "Assert-LauncherCausalPrefix",
        "Assert-LauncherEventHistory",
        "Assert-MonitorFailedLauncherV2History",
        "Assert-DualReadinessReceipt")) {
        $definition = @($monitorAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $functionName
        }, $true))
        Assert-True ($definition.Count -eq 1) "Historical validator extraction was ambiguous: $functionName"
        Invoke-Expression $definition[0].Extent.Text
    }
    $emptyFrozenJournalPath = Join-Path $testRoot 'empty-frozen-prefix.jsonl'
    [IO.File]::WriteAllBytes($emptyFrozenJournalPath, [byte[]]@())
    $emptyFrozenDigest = Get-RawQualificationSha256File -Path $emptyFrozenJournalPath
    $emptyFrozenPrefixAccepted = $true
    try {
        $null = Read-MonitorFrozenCanonicalJsonLines `
            -Path $emptyFrozenJournalPath -AllowEmpty `
            -ExpectedPrefixLength ([uint64]0) -ExpectedPrefixSha256 $emptyFrozenDigest
    }
    catch { $emptyFrozenPrefixAccepted = $false }
    $emptyFrozenWrongDigestRejected = $false
    try {
        $null = Read-MonitorFrozenCanonicalJsonLines `
            -Path $emptyFrozenJournalPath -AllowEmpty `
            -ExpectedPrefixLength ([uint64]0) -ExpectedPrefixSha256 ('f' * 64)
    }
    catch { $emptyFrozenWrongDigestRejected = $true }
    $emptyFrozenPositiveLengthRejected = $false
    try {
        $null = Read-MonitorFrozenCanonicalJsonLines `
            -Path $emptyFrozenJournalPath -AllowEmpty `
            -ExpectedPrefixLength ([uint64]1) -ExpectedPrefixSha256 $emptyFrozenDigest
    }
    catch { $emptyFrozenPositiveLengthRejected = $true }
    Assert-True ($emptyFrozenPrefixAccepted -and $emptyFrozenWrongDigestRejected -and
        $emptyFrozenPositiveLengthRejected) "Empty frozen JSONL prefix identity is not exact."
    $ExpectedGuardianWatchdogDeadlineSeconds = [uint64]90
    $ExpectedGuardianWatchdogStartupDeadlineSeconds = [uint64]90
    $ExpectedHostTelemetryGapDeadlineSeconds = [uint64]120
    $ExpectedMaximumDualLaunchSkewMilliseconds = [uint64]5000
    $ExpectedPythonRuntimeFingerprintTimeoutSeconds = [uint64]300
    $ExpectedGenerationTerminalDeadlineSeconds = [uint64]120
    $ExpectedCampaignCommitDeadlineSeconds = [uint64]1800
    $ExpectedHostProbeTimeoutSeconds = [uint64]20
    $ExpectedHostProbeMaximumArtifactBytes = [uint64](8MB)
    $ExpectedMarketFreshnessStartupGraceSeconds = [uint64]30
    $ExpectedMarketFreshnessDeadlineSeconds = [uint64]30
    $ExpectedMarketFreshnessStartupGraceNs = [uint64]30000000000
    $ExpectedMarketFreshnessDeadlineNs = [uint64]30000000000

    $assertCanonicalRejected = {
        param([scriptblock] $Operation, [string] $Label)
        $rejected = $false
        try { $null = & $Operation }
        catch { $rejected = $true }
        Assert-True $rejected "Canonical evidence mutant was accepted: $Label"
        return $rejected
    }

    $reparseEvidenceRoot = Join-Path $testRoot "reparse-evidence"
    $reparseTargetRoot = Join-Path $testRoot "reparse-target"
    $null = New-Item -ItemType Directory -Path $reparseEvidenceRoot -ErrorAction Stop
    $null = New-Item -ItemType Directory -Path $reparseTargetRoot -ErrorAction Stop
    $directoryJunction = Join-Path $reparseEvidenceRoot "directory-junction"
    $null = New-Item -ItemType Junction -Path $directoryJunction -Target $reparseTargetRoot -ErrorAction Stop
    $directoryReparseRejected = $false
    try { $null = Assert-MonitorEvidenceTreeNoReparsePoints -RunRoot $reparseEvidenceRoot }
    catch { $directoryReparseRejected = $true }
    Assert-True $directoryReparseRejected "A real child directory junction was accepted as qualification evidence."
    Remove-Item -LiteralPath $directoryJunction -Force -ErrorAction Stop
    $fileTarget = Join-Path $reparseTargetRoot "target.json"
    [IO.File]::WriteAllBytes($fileTarget, [Text.UTF8Encoding]::new($false).GetBytes("{}`n"))
    $fileSymbolicLink = Join-Path $reparseEvidenceRoot "file-symlink.json"
    if (-not ("RawQualificationSelfTestSymlink" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class RawQualificationSelfTestSymlink
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.I1)]
    private static extern bool CreateSymbolicLinkW(string link, string target, int flags);

    public static void CreateFile(string link, string target)
    {
        const int SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE = 0x2;
        if (!CreateSymbolicLinkW(link, target, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@ -Language CSharp -ErrorAction Stop
    }
    try {
        [RawQualificationSelfTestSymlink]::CreateFile($fileSymbolicLink, $fileTarget)
    }
    catch {
        $nativeError = if ($null -ne $_.Exception.InnerException -and
            $null -ne $_.Exception.InnerException.PSObject.Properties['NativeErrorCode']) {
            [int]$_.Exception.InnerException.NativeErrorCode
        } else { 0 }
        if ($nativeError -ne 1314) { throw }
        $wsl = Join-Path $env:SystemRoot "System32\wsl.exe"
        if (-not (Test-Path -LiteralPath $wsl -PathType Leaf)) {
            throw "File-reparse self-test requires native symlink privilege or the installed WSL fallback."
        }
        $toWslPath = {
            param([string] $WindowsPath)
            $full = [IO.Path]::GetFullPath($WindowsPath)
            if ($full.Length -lt 3 -or $full[1] -ne ':') { throw "WSL fallback requires a local drive path." }
            return "/mnt/" + [char]::ToLowerInvariant($full[0]) + $full.Substring(2).Replace('\', '/')
        }
        $wslTarget = & $toWslPath $fileTarget
        $wslLink = & $toWslPath $fileSymbolicLink
        $null = & $wsl ln -s -- $wslTarget $wslLink
        if ($LASTEXITCODE -ne 0) { throw "WSL could not create the real file reparse-point fixture." }
    }
    $fileReparseRejected = $false
    try { $null = Assert-MonitorEvidenceTreeNoReparsePoints -RunRoot $reparseEvidenceRoot }
    catch { $fileReparseRejected = $true }
    $fileLinkItem = Get-Item -LiteralPath $fileSymbolicLink -Force -ErrorAction Stop
    Assert-True $fileReparseRejected ("A real child file symbolic link was accepted as qualification evidence (attributes={0}, link_type={1}, target={2})." -f `
        [string]$fileLinkItem.Attributes, [string]$fileLinkItem.LinkType, [string]$fileLinkItem.Target)
    Remove-Item -LiteralPath $fileSymbolicLink -Force -ErrorAction Stop
    $null = Assert-MonitorEvidenceTreeNoReparsePoints -RunRoot $reparseEvidenceRoot

    # Windows PowerShell 5.1/CLR4 applies legacy MAX_PATH semantics to ordinary
    # System.IO paths.  A real qualification tree can legitimately exceed 260
    # characters below a normal RunRoot, so every physical I/O boundary must use
    # the Win32 extended-length spelling while published evidence stays canonical.
    $longPathRoot = [IO.Path]::Combine($reparseEvidenceRoot, "long-path")
    $longPathDirectory = $longPathRoot
    for ($longIndex = 0; $longIndex -lt 12; $longIndex++) {
        $longPathDirectory = [IO.Path]::Combine(
            $longPathDirectory,
            ("component-{0:D2}-abcdefghijkl" -f $longIndex))
    }
    Assert-True ($longPathDirectory.Length -gt 260) "Long-path fixture did not cross the legacy MAX_PATH boundary."
    $null = [IO.Directory]::CreateDirectory(
        (ConvertTo-RawQualificationExtendedLengthPath -Path $longPathDirectory))
    $longCanonicalPath = [IO.Path]::Combine($longPathDirectory, "canonical.json")
    $longCanonicalValue = [pscustomobject][ordered]@{
        schema = "LongPathMonitorSelfTestV1"
        accepted = $true
    }
    [IO.File]::WriteAllBytes(
        (ConvertTo-RawQualificationExtendedLengthPath -Path $longCanonicalPath),
        (ConvertTo-RawQualificationJsonBytes -Value $longCanonicalValue -Pretty))
    try {
        $null = Assert-RawQualificationNoReparsePointInExistingPath -Path $longCanonicalPath
        $null = Assert-MonitorEvidenceTreeNoReparsePoints -RunRoot $reparseEvidenceRoot
        $resolvedLongCanonical = Resolve-MonitorContainedEvidencePath `
            -RunRoot $reparseEvidenceRoot -Path $longCanonicalPath -RequireLeaf
        $longCanonicalSnapshot = Read-MonitorCanonicalJsonSnapshot `
            -Path $resolvedLongCanonical -WriterKind PowerShellPretty `
            -ExpectedTopLevelOrder @("schema", "accepted")
        Assert-True ($longCanonicalSnapshot.value.schema -ceq "LongPathMonitorSelfTestV1" -and
            [bool]$longCanonicalSnapshot.value.accepted -and
            [string]$longCanonicalSnapshot.sha256 -ceq
                (Get-RawQualificationSha256File -Path $longCanonicalPath)) `
            "Monitor did not preserve canonical identity across a real >260-character evidence path."
    }
    finally {
        if ([IO.Directory]::Exists((ConvertTo-RawQualificationExtendedLengthPath -Path $longPathRoot))) {
            [IO.Directory]::Delete(
                (ConvertTo-RawQualificationExtendedLengthPath -Path $longPathRoot),
                $true)
        }
    }

    $treeRaceRoot = Join-Path $testRoot "tree-snapshot-races"
    $treeRaceVictim = Join-Path $treeRaceRoot "victim"
    $null = New-Item -ItemType Directory -Path $treeRaceVictim -Force -ErrorAction Stop
    [IO.File]::WriteAllBytes(
        (Join-Path $treeRaceVictim "evidence.bin"),
        [byte[]](1, 2, 3))
    $treeRaceSpacedPath = Join-Path $treeRaceRoot "identity with spaces.bin"
    [IO.File]::WriteAllBytes($treeRaceSpacedPath, [byte[]](10, 11, 12))

    [string[]]$treeRaceRows = @(Get-MonitorEvidenceTreeStructureSnapshot `
        -RunRoot $treeRaceRoot)
    Assert-True ($treeRaceRows.Count -eq 4) `
        "Structural snapshot rows were collapsed, nested, omitted, or duplicated."
    foreach ($treeRaceRow in $treeRaceRows) {
        Assert-True ($treeRaceRow -is [string] -and
            $treeRaceRow -cmatch '^[DF]\|[0-9]+\|[0-9]+\|[0-9]+\|') `
            "Structural snapshot did not preserve one typed identity row per pipeline object."
    }
    Assert-True (@($treeRaceRows | Where-Object {
                $_.EndsWith('|identity with spaces.bin', [StringComparison]::Ordinal)
            }).Count -eq 1) `
        "Structural snapshot lost the exact boundary of a path containing spaces."

    $singleTransientState = [pscustomobject]@{ injected = $false; attempts = [uint64]0 }
    $singleTransientCallback = {
        param([string] $DirectoryPath, [int] $Attempt)
        if ([IO.Path]::GetFullPath($DirectoryPath).Equals(
                [IO.Path]::GetFullPath($treeRaceRoot),
                [StringComparison]::OrdinalIgnoreCase)) {
            $singleTransientState.attempts = [uint64][Math]::Max(
                [uint64]$singleTransientState.attempts,
                [uint64]$Attempt)
            if (-not $singleTransientState.injected) {
                $singleTransientState.injected = $true
                throw [IO.DirectoryNotFoundException]::new(
                    "Injected whole-snapshot invalidation before enumeration.")
            }
        }
    }
    $null = Assert-MonitorEvidenceTreeNoReparsePoints `
        -RunRoot $treeRaceRoot -MaximumSnapshotAttempts 4 `
        -BeforeDirectoryEnumeration $singleTransientCallback
    Assert-True ($singleTransientState.injected -and $singleTransientState.attempts -ge 3) `
        "A transient tree mutation did not discard the entire attempt and require two later stable snapshots."

    $persistentTransientState = [pscustomobject]@{ root_attempts = [uint64]0 }
    $persistentTransientCallback = {
        param([string] $DirectoryPath, [int] $Attempt)
        if ([IO.Path]::GetFullPath($DirectoryPath).Equals(
                [IO.Path]::GetFullPath($treeRaceRoot),
                [StringComparison]::OrdinalIgnoreCase)) {
            $persistentTransientState.root_attempts++
            throw [IO.DirectoryNotFoundException]::new("Injected persistent tree instability.")
        }
    }
    $persistentTransientRejected = $false
    try {
        $null = Assert-MonitorEvidenceTreeNoReparsePoints `
            -RunRoot $treeRaceRoot -MaximumSnapshotAttempts 3 `
            -BeforeDirectoryEnumeration $persistentTransientCallback
    }
    catch { $persistentTransientRejected = $true }
    Assert-True ($persistentTransientRejected -and $persistentTransientState.root_attempts -eq 3) `
        "Persistent tree instability was accepted or did not exhaust the exact bounded retry count."

    $hardFailureState = [pscustomobject]@{ root_attempts = [uint64]0 }
    $hardFailureCallback = {
        param([string] $DirectoryPath, [int] $Attempt)
        if ([IO.Path]::GetFullPath($DirectoryPath).Equals(
                [IO.Path]::GetFullPath($treeRaceRoot),
                [StringComparison]::OrdinalIgnoreCase)) {
            $hardFailureState.root_attempts++
            throw [UnauthorizedAccessException]::new("Injected hard tree access failure.")
        }
    }
    $hardFailureRejected = $false
    try {
        $null = Assert-MonitorEvidenceTreeNoReparsePoints `
            -RunRoot $treeRaceRoot -MaximumSnapshotAttempts 5 `
            -BeforeDirectoryEnumeration $hardFailureCallback
    }
    catch { $hardFailureRejected = $true }
    Assert-True ($hardFailureRejected -and $hardFailureState.root_attempts -eq 1) `
        "A hard tree access failure was retried as benign instability."

    $deleteFenceState = [pscustomobject]@{ attempted = $false; blocked = $false; maximum_attempt = [uint64]0 }
    $deleteFenceCallback = {
        param([string] $DirectoryPath, [int] $Attempt)
        if ([IO.Path]::GetFullPath($DirectoryPath).Equals(
                [IO.Path]::GetFullPath($treeRaceRoot),
                [StringComparison]::OrdinalIgnoreCase)) {
            $deleteFenceState.maximum_attempt = [uint64][Math]::Max(
                [uint64]$deleteFenceState.maximum_attempt,
                [uint64]$Attempt)
        }
        if (-not $deleteFenceState.attempted -and
            [IO.Path]::GetFullPath($DirectoryPath).Equals(
                [IO.Path]::GetFullPath($treeRaceVictim),
                [StringComparison]::OrdinalIgnoreCase)) {
            $deleteFenceState.attempted = $true
            try { Remove-Item -LiteralPath $DirectoryPath -Recurse -Force -ErrorAction Stop }
            catch { $deleteFenceState.blocked = $true }
        }
    }
    $null = Assert-MonitorEvidenceTreeNoReparsePoints `
        -RunRoot $treeRaceRoot -MaximumSnapshotAttempts 3 `
        -BeforeDirectoryEnumeration $deleteFenceCallback
    $deleteWasFenced = $deleteFenceState.blocked -and
        (Test-Path -LiteralPath $treeRaceVictim -PathType Container)
    $deleteInvalidatedSnapshot = -not $deleteFenceState.blocked -and
        -not (Test-Path -LiteralPath $treeRaceVictim) -and
        $deleteFenceState.maximum_attempt -ge 3
    Assert-True ($deleteFenceState.attempted -and
        ($deleteWasFenced -or $deleteInvalidatedSnapshot)) `
        "Delete-after-enqueue was neither fenced nor handled by discarding the entire snapshot before convergence."

    $identityReplacementPath = Join-Path $treeRaceRoot "identity.bin"
    $identityReplacementBackup = Join-Path $treeRaceRoot "identity-old.bin"
    [IO.File]::WriteAllBytes($identityReplacementPath, [byte[]](4, 5, 6))
    $identityReplacementState = [pscustomobject]@{ replaced = $false; maximum_attempt = [uint64]0 }
    $identityReplacementCallback = {
        param([string] $DirectoryPath, [int] $Attempt)
        if ([IO.Path]::GetFullPath($DirectoryPath).Equals(
                [IO.Path]::GetFullPath($treeRaceRoot),
                [StringComparison]::OrdinalIgnoreCase)) {
            $identityReplacementState.maximum_attempt = [uint64][Math]::Max(
                [uint64]$identityReplacementState.maximum_attempt,
                [uint64]$Attempt)
            if ($Attempt -eq 2 -and -not $identityReplacementState.replaced) {
                Move-Item -LiteralPath $identityReplacementPath -Destination $identityReplacementBackup -ErrorAction Stop
                [IO.File]::WriteAllBytes($identityReplacementPath, [byte[]](7, 8, 9))
                $identityReplacementState.replaced = $true
            }
        }
    }
    $null = Assert-MonitorEvidenceTreeNoReparsePoints `
        -RunRoot $treeRaceRoot -MaximumSnapshotAttempts 4 `
        -BeforeDirectoryEnumeration $identityReplacementCallback
    Assert-True ($identityReplacementState.replaced -and
        $identityReplacementState.maximum_attempt -ge 3) `
        "An ordinary file-identity replacement between snapshots was not invalidated before convergence."
    Remove-Item -LiteralPath $identityReplacementBackup -Force -ErrorAction Stop
    Remove-Item -LiteralPath $treeRaceRoot -Recurse -Force -ErrorAction Stop

    # A PowerShell singleton is accepted only as the exact BOM-less pretty writer
    # bytes, including property order and one terminal LF.
    $canonicalSingletonPath = Join-Path $testRoot "canonical-powershell.json"
    $canonicalSingletonValue = [pscustomobject][ordered]@{
        schema = "CanonicalSelfTestV1"
        count = [uint64]1
        nested = [ordered]@{ enabled = $true; digest = $validDigest }
    }
    [IO.File]::WriteAllBytes(
        $canonicalSingletonPath,
        (ConvertTo-RawQualificationJsonBytes -Value $canonicalSingletonValue -Pretty))
    $canonicalSingletonSnapshot = Read-MonitorCanonicalJsonSnapshot `
        -Path $canonicalSingletonPath `
        -WriterKind PowerShellPretty `
        -ExpectedTopLevelOrder @("schema", "count", "nested")
    Assert-True ($canonicalSingletonSnapshot.value.schema -ceq "CanonicalSelfTestV1") "Exact PowerShell singleton snapshot was rejected."
    $canonicalSingletonBytes = [byte[]]$canonicalSingletonSnapshot.bytes
    $singletonMutationCases = [ordered]@{
        whitespace = {
            $text = [Text.UTF8Encoding]::new($false, $true).GetString($canonicalSingletonBytes)
            [Text.UTF8Encoding]::new($false).GetBytes($text.Insert(1, ' '))
        }
        duplicate_key = {
            $text = [Text.UTF8Encoding]::new($false, $true).GetString($canonicalSingletonBytes)
            $insertAt = if ($text.StartsWith("{`r`n", [StringComparison]::Ordinal)) { 3 } else { 2 }
            [Text.UTF8Encoding]::new($false).GetBytes(
                $text.Insert($insertAt, '    "schema": "CanonicalSelfTestV1",' + "`r`n"))
        }
        reordered = {
            ConvertTo-RawQualificationJsonBytes -Value ([pscustomobject][ordered]@{
                count = [uint64]1; schema = "CanonicalSelfTestV1"
                nested = [ordered]@{ enabled = $true; digest = $validDigest }
            }) -Pretty
        }
        crlf = {
            $text = [Text.UTF8Encoding]::new($false, $true).GetString($canonicalSingletonBytes)
            [Text.UTF8Encoding]::new($false).GetBytes($text.Substring(0, $text.Length - 1) + "`r`n")
        }
        bom = { [byte[]](@(0xEF, 0xBB, 0xBF) + $canonicalSingletonBytes) }
        missing_lf = { [byte[]]$canonicalSingletonBytes[0..($canonicalSingletonBytes.Length - 2)] }
    }
    $canonicalSingletonMutantsRejected = [uint64]0
    foreach ($mutationName in $singletonMutationCases.Keys) {
        $mutationPath = Join-Path $testRoot "canonical-powershell-$mutationName.json"
        [IO.File]::WriteAllBytes($mutationPath, [byte[]](& $singletonMutationCases[$mutationName]))
        $null = & $assertCanonicalRejected {
            Read-MonitorCanonicalJsonSnapshot -Path $mutationPath -WriterKind PowerShellPretty `
                -ExpectedTopLevelOrder @("schema", "count", "nested")
        } "PowerShell-singleton-$mutationName"
        $canonicalSingletonMutantsRejected++
    }
    $realPowerShellFixtureRoot = Join-Path $repo `
        "artifacts\qualification-fault-final-v2\20260824T091653Z-dual-4f593ca12bff"
    Assert-True (Test-Path -LiteralPath $realPowerShellFixtureRoot -PathType Container) "Real PowerShell evidence fixture is absent."
    $realStartupSnapshot = Read-MonitorCanonicalJsonSnapshot `
        -Path (Join-Path $realPowerShellFixtureRoot "launcher-startup.json") `
        -WriterKind PowerShellPretty
    $realControlSnapshot = Read-MonitorCanonicalJsonSnapshot `
        -Path (Join-Path $realPowerShellFixtureRoot "processes.json") `
        -WriterKind PowerShellPretty
    $legacyRealControl = $realControlSnapshot.value
    $realStartupSnapshot.value.preflight.child_environment = [pscustomobject][ordered]@{
        mode = [string]$productionChildEnvironmentContract.mode
        names = @($productionChildEnvironmentContract.names)
        entries_sha256 = [string]$productionChildEnvironmentContract.entries_sha256
        Entries = @($productionChildEnvironmentContract.Entries)
    }
    $realControlSnapshot.value = [pscustomobject][ordered]@{
        schema = "RawQualificationProcessControlV2"
        run_id = [string]$legacyRealControl.run_id
        job_object_name = [string]$legacyRealControl.job_object_name
        job_kill_on_close = [bool]$legacyRealControl.job_kill_on_close
        workload_job_object_name =
            "Local\BinanceRawQualificationWorkloadJob-" + [string]$legacyRealControl.run_id
        workload_job_kill_on_close = $true
        launch_method = "CREATE_SUSPENDED_ASSIGN_OUTER_AND_WORKLOAD_JOBS_RESUME"
        child_environment_mode = [string]$productionChildEnvironmentContract.mode
        child_environment_names = @($productionChildEnvironmentContract.names)
        child_environment_entries_sha256 = [string]$productionChildEnvironmentContract.entries_sha256
        capture_origin_monotonic_tick = [uint64]$legacyRealControl.capture_origin_monotonic_tick
        launch_skew_ticks = [uint64]$legacyRealControl.launch_skew_ticks
        launch_skew_ms = [uint64]$legacyRealControl.launch_skew_ms
        maximum_dual_launch_skew_ms = [uint64]$legacyRealControl.maximum_dual_launch_skew_ms
        watchdog = $legacyRealControl.watchdog
        processes = @($legacyRealControl.processes)
    }
    $null = Assert-MonitorStartupControlJsonTypes `
        -Startup $realStartupSnapshot.value `
        -Control $realControlSnapshot.value `
        -RequireWriterContract
    $processControlV2MutantsRejected = [uint64]0
    foreach ($case in @(
        [pscustomobject]@{ name="old-schema"; action={ param($c) $c.schema = "RawQualificationProcessControlV1" } },
        [pscustomobject]@{ name="old-launch-method"; action={ param($c) $c.launch_method = "CREATE_SUSPENDED_ASSIGN_JOB_RESUME" } },
        [pscustomobject]@{ name="workload-kill-disabled"; action={ param($c) $c.workload_job_kill_on_close = $false } },
        [pscustomobject]@{ name="workload-aliases-outer"; action={ param($c) $c.workload_job_object_name = [string]$c.job_object_name } },
        [pscustomobject]@{ name="workload-name-nondeterministic"; action={ param($c) $c.workload_job_object_name = "Local\unexpected" } })) {
        $controlMutant = $realControlSnapshot.value | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
        & $case.action $controlMutant
        $rejected = $false
        try {
            $null = Assert-MonitorStartupControlJsonTypes `
                -Startup $realStartupSnapshot.value `
                -Control $controlMutant `
                -RequireWriterContract
        }
        catch { $rejected = $true }
        Assert-True $rejected "ProcessControlV2 mutant was accepted: $($case.name)"
        $processControlV2MutantsRejected++
    }
    $realBindingsSnapshot = Read-MonitorCanonicalJsonSnapshot `
        -Path (Join-Path $realPowerShellFixtureRoot "campaign-bindings.json") `
        -WriterKind PowerShellPretty
    $null = Assert-MonitorBindingsWriterOrder -Bindings $realBindingsSnapshot.value
    $realReadySnapshot = Read-MonitorCanonicalJsonSnapshot `
        -Path (Join-Path $realPowerShellFixtureRoot "watchdog-ready.json") `
        -WriterKind PowerShellPretty `
        -ExpectedTopLevelOrder @(
            "schema", "run_id", "job_name", "pid", "launch_origin_qpc_timestamp",
            "observed_qpc_timestamp", "monotonic_frequency", "startup_deadline_s", "pulse_length")

    # Exercise the real monitor entry point against every durable FAILED phase.
    # These fixtures are rebuilt with the production singleton/journal writers,
    # current artifact hashes, exact preterminal receipts, and the V2 terminal
    # post-link.  They therefore prove reachability of the phase-aware branch;
    # a stale hash alone cannot make a semantic mutant pass this matrix.
    function Copy-SelfTestJsonValue {
        param([Parameter(Mandatory = $true)] $Value)
        return ($Value | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
    }

    function Get-SelfTestJournalReceipt {
        param(
            [Parameter(Mandatory = $true)] [string] $Path,
            [Parameter(Mandatory = $true)] [string] $FileName
        )
        $bytes = [IO.File]::ReadAllBytes($Path)
        $records = [uint64]0
        $terminalDigest = "0" * 64
        if ($bytes.Length -ne 0) {
            $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
            Assert-True $text.EndsWith("`n", [StringComparison]::Ordinal) "Self-test journal receipt lacks a terminal LF."
            $lines = @($text.TrimEnd("`n").Split("`n"))
            $records = [uint64]$lines.Count
            $terminalDigest = [string](($lines[$lines.Count - 1] | ConvertFrom-Json).record_sha256)
        }
        return [pscustomobject][ordered]@{
            file = $FileName
            records = $records
            terminal_record_sha256 = $terminalDigest
            file_sha256 = Get-RawQualificationSha256File -Path $Path
        }
    }

    function Get-SelfTestTerminalArtifactHashes {
        param(
            [AllowNull()] $Startup,
            [AllowNull()] $WatchdogReadySha256,
            [switch] $Preflight
        )
        $baseNames = @(
            "campaign_executable_sha256", "capture_executable_sha256",
            "campaign_verifier_executable_sha256", "public_config_sha256",
            "source_lock_sha256", "launcher_script_sha256", "monitor_script_sha256",
            "helper_script_sha256", "telemetry_probe_script_sha256", "watchdog_script_sha256",
            "python_runtime_fingerprint_script_sha256", "powershell_executable_sha256",
            "python_executable_sha256", "python_verifier_source_tree_sha256",
            "python_runtime_tree_sha256", "python_pyvenv_config_sha256",
            "python_base_executable_sha256", "python_project_sha256", "python_requirements_sha256")
        $result = [ordered]@{}
        foreach ($name in $baseNames) {
            $result[$name] = $null
            if (-not $Preflight -and $name -ceq "watchdog_script_sha256") {
                $result.watchdog_ready_file_sha256 = $null
            }
        }
        if ($null -eq $Startup) { return [pscustomobject]$result }
        $preflightEvidence = $Startup.preflight
        $result.campaign_executable_sha256 = [string]$preflightEvidence.campaign_executable_sha256
        $result.capture_executable_sha256 = [string]$preflightEvidence.capture_executable_sha256
        $result.campaign_verifier_executable_sha256 = [string]$preflightEvidence.campaign_verifier_executable_sha256
        $result.public_config_sha256 = [string]$preflightEvidence.public_config_sha256
        $result.source_lock_sha256 = [string]$preflightEvidence.source_lock_sha256
        $result.launcher_script_sha256 = [string]$preflightEvidence.launcher_script_sha256
        $result.monitor_script_sha256 = [string]$preflightEvidence.monitor_script_sha256
        $result.helper_script_sha256 = [string]$preflightEvidence.helper_script_sha256
        $result.telemetry_probe_script_sha256 = [string]$preflightEvidence.telemetry_probe_script_sha256
        $result.watchdog_script_sha256 = [string]$preflightEvidence.watchdog_script_sha256
        $result.python_runtime_fingerprint_script_sha256 = [string]$preflightEvidence.python_runtime_fingerprint_script_sha256
        $result.powershell_executable_sha256 = [string]$preflightEvidence.powershell_executable_sha256
        $result.python_executable_sha256 = [string]$preflightEvidence.python_sha256
        $result.python_verifier_source_tree_sha256 = [string]$preflightEvidence.python_verifier_source.tree_sha256
        $result.python_project_sha256 = [string]$preflightEvidence.python_project_sha256
        $result.python_requirements_sha256 = [string]$preflightEvidence.python_requirements_sha256
        if ($Preflight) {
            $result.python_runtime_tree_sha256 = [string]$preflightEvidence.python_runtime.tree_sha256
            $result.python_pyvenv_config_sha256 = [string]$preflightEvidence.python_runtime.pyvenv_config_sha256
            $result.python_base_executable_sha256 = [string]$preflightEvidence.python_runtime.base_executable_sha256
        }
        if (-not $Preflight) {
            $result.watchdog_ready_file_sha256 = if ([string]::IsNullOrWhiteSpace([string]$WatchdogReadySha256)) {
                $null
            }
            else { [string]$WatchdogReadySha256 }
        }
        return [pscustomobject]$result
    }

    $mutablePythonSource = Get-RawQualificationSourceTreeDigest `
        -Root ([string]$realStartupSnapshot.value.preflight.python_verifier_source.root) `
        -AllowIgnoredBytecodeCaches
    $currentPythonSource = New-RawQualificationSealedSourceTree `
        -SourceTree $mutablePythonSource `
        -Destination (Join-Path $testRoot "sealed-python-verifier-source")
    $currentPythonRuntime = Get-RawQualificationPythonRuntimeDigest -PythonExecutable ([string]$realStartupSnapshot.value.preflight.python)
    $realGuardianFirstLine = Get-Content -LiteralPath (Join-Path $realPowerShellFixtureRoot "guardian-pulse.jsonl") -First 1 -Encoding UTF8
    $realHostFirstTwoLines = @(Get-Content -LiteralPath (Join-Path $realPowerShellFixtureRoot "host-telemetry.jsonl") -First 2 -Encoding UTF8)

    function New-SelfTestFailedMonitorFixture {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateSet("RECORD0", "POST_PREFLIGHT", "POST_JOB", "POST_WATCHDOG", "POST_DUAL", "SEMANTIC_READY", "POST_READINESS_OR_LATER")]
            [string] $Phase,
            [string] $Suffix = "valid",
            [ValidateSet("AUTO", "QUERY_ERROR", "TIMEOUT", "NO_JOB")]
            [string] $ContainmentMode = "AUTO",
            [switch] $OmitHostReceipt,
            [switch] $OmitGuardianReceipt,
            [switch] $MutateDeclaredChildEnvironmentNames,
            [ValidateSet("NONE", "DRIFT", "ABSENT")]
            [string] $TerminalArtifactMode = "NONE"
        )
        $phaseCounts = @{
            RECORD0 = 0; POST_PREFLIGHT = 1; POST_JOB = 2; POST_WATCHDOG = 3
            POST_DUAL = 4; SEMANTIC_READY = 5; POST_READINESS_OR_LATER = 6
        }
        $prefixCount = [int]$phaseCounts[$Phase]
        $runId = "failed-$($Phase.ToLowerInvariant().Replace('_','-'))-$Suffix-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
        $runRoot = Join-Path $testRoot $runId
        $null = New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop
        Copy-Item -LiteralPath (Join-Path $realPowerShellFixtureRoot "host-probes") -Destination $runRoot -Recurse -ErrorAction Stop

        foreach ($logName in @("watchdog.stdout.log", "watchdog.stderr.log", "btcusdt.stdout.log", "btcusdt.stderr.log", "ethusdt.stdout.log", "ethusdt.stderr.log")) {
            [IO.File]::WriteAllBytes((Join-Path $runRoot $logName), [byte[]]@())
        }

        $guardianPath = Join-Path $runRoot "guardian-pulse.jsonl"
        [IO.File]::WriteAllBytes(
            $guardianPath,
            [Text.UTF8Encoding]::new($false).GetBytes($realGuardianFirstLine + "`n"))
        $guardianReceipt = Get-SelfTestJournalReceipt -Path $guardianPath -FileName "guardian-pulse.jsonl"

        $hostPath = Join-Path $runRoot "host-telemetry.jsonl"
        if ($Phase -ceq "POST_READINESS_OR_LATER") {
            [IO.File]::WriteAllBytes(
                $hostPath,
                [Text.UTF8Encoding]::new($false).GetBytes(($realHostFirstTwoLines -join "`n") + "`n"))
        }
        else { [IO.File]::WriteAllBytes($hostPath, [byte[]]@()) }
        $hostReceipt = Get-SelfTestJournalReceipt -Path $hostPath -FileName "host-telemetry.jsonl"

        $startup = $null
        $startupSha256 = $null
        if ($prefixCount -ge 1) {
            $startup = Copy-SelfTestJsonValue $realStartupSnapshot.value
            $startup.run_id = $runId
            $startup.run_root = $runRoot
            $startup.started_utc = [DateTimeOffset]::UtcNow.ToString("o")
            $startup.preflight.launcher_script_sha256 = Get-RawQualificationSha256File -Path ([string]$startup.preflight.launcher_script)
            $startup.preflight.monitor_script_sha256 = Get-RawQualificationSha256File -Path ([string]$startup.preflight.monitor_script)
            $startup.preflight.helper_script_sha256 = Get-RawQualificationSha256File -Path ([string]$startup.preflight.helper_script)
            $startup.preflight.python_verifier_source.root = [string]$currentPythonSource.root
            $startup.preflight.python_verifier_source.files = [uint64]$currentPythonSource.files
            $startup.preflight.python_verifier_source.tree_sha256 = [string]$currentPythonSource.tree_sha256
            $startup.preflight.python_verifier_source.inventory = @($currentPythonSource.inventory)
            $startup.preflight.python_runtime.venv_root = [string]$currentPythonRuntime.venv_root
            $startup.preflight.python_runtime.venv_python = [string]$currentPythonRuntime.venv_python
            $startup.preflight.python_runtime.venv_python_sha256 = [string]$currentPythonRuntime.venv_python_sha256
            $startup.preflight.python_runtime.pyvenv_config = [string]$currentPythonRuntime.pyvenv_config
            $startup.preflight.python_runtime.pyvenv_config_sha256 = [string]$currentPythonRuntime.pyvenv_config_sha256
            $startup.preflight.python_runtime.base_root = [string]$currentPythonRuntime.base_root
            $startup.preflight.python_runtime.base_executable = [string]$currentPythonRuntime.base_executable
            $startup.preflight.python_runtime.base_executable_sha256 = [string]$currentPythonRuntime.base_executable_sha256
            $startup.preflight.python_runtime.file_count = [uint64]$currentPythonRuntime.file_count
            $startup.preflight.python_runtime.total_bytes = [uint64]$currentPythonRuntime.total_bytes
            $startup.preflight.python_runtime.tree_sha256 = [string]$currentPythonRuntime.tree_sha256
            $startup.preflight.python_runtime.included_extensions = @($currentPythonRuntime.included_extensions)
            $startup.preflight.python_runtime.excluded_path_components = @($currentPythonRuntime.excluded_path_components)
            if ($MutateDeclaredChildEnvironmentNames) {
                $startup.preflight.child_environment.names[0] = 'systemdrive'
            }
            $startupSha256 = Write-RawQualificationDurableNewJson -Path (Join-Path $runRoot "launcher-startup.json") -Value $startup
        }

        $jobName = "Local\BinanceRawQualificationJob-$runId"
        $workloadJobName = "Local\BinanceRawQualificationWorkloadJob-$runId"
        $ready = $null
        $readySha256 = $null
        if ($prefixCount -ge 3) {
            $ready = Copy-SelfTestJsonValue $realReadySnapshot.value
            $ready.run_id = $runId
            $ready.job_name = $jobName
            $ready.pulse_length = [uint64](Get-Item -LiteralPath $guardianPath).Length
            $readySha256 = Write-RawQualificationDurableNewJson -Path (Join-Path $runRoot "watchdog-ready.json") -Value $ready
        }

        $control = $null
        $controlSha256 = $null
        if ($prefixCount -ge 4) {
            $control = Copy-SelfTestJsonValue $realControlSnapshot.value
            $control.run_id = $runId
            $control.job_object_name = $jobName
            $control.workload_job_object_name = $workloadJobName
            $control.watchdog.job_name = $jobName
            $control.watchdog.executable_sha256 = [string]$startup.preflight.powershell_executable_sha256
            $control.watchdog.script_sha256 = [string]$startup.preflight.watchdog_script_sha256
            $control.watchdog.ready_file_sha256 = $readySha256
            $control.watchdog.ready_pulse_length = [uint64]$ready.pulse_length
            $control.watchdog.ready_observed_qpc_timestamp = [long]$ready.observed_qpc_timestamp
            $watchdogArguments = [string[]]@(
                "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", [string]$startup.preflight.watchdog_script,
                "-HelperPath", [string]$startup.preflight.helper_script,
                "-JobName", $jobName,
                "-RunId", $runId,
                "-GuardianPulsePath", $guardianPath,
                "-ReadyPath", (Join-Path $runRoot "watchdog-ready.json"),
                "-StopPath", (Join-Path $runRoot "watchdog-stop.json"),
                "-FailurePath", (Join-Path $runRoot "watchdog-failure.json"),
                "-LaunchOriginQpcTimestamp", ([long]$control.watchdog.launch_origin_qpc_timestamp).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-MonotonicFrequency", ([long]$startup.monotonic_frequency).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-StartupDeadlineSeconds", ([uint64]$startup.guardian_policy.watchdog_startup_deadline_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                "-MaximumGuardianPulseAgeSeconds", ([uint64]$startup.guardian_policy.watchdog_deadline_s).ToString([Globalization.CultureInfo]::InvariantCulture))
            $control.watchdog.command_line = [RawQualificationNative]::BuildExactCommandLine(
                [string]$startup.preflight.powershell_executable, $watchdogArguments)
            foreach ($process in @($control.processes)) {
                $symbol = [string]$process.symbol
                $process.command_line = [RawQualificationNative]::BuildExactCommandLine(
                    [string]$startup.preflight.campaign_executable,
                    [string[]]@(
                        $symbol,
                        ([uint64]$startup.parameters.total_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                        ([uint64]$startup.parameters.rotation_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                        ([uint64]$startup.parameters.overlap_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                        ([uint64]$startup.parameters.segment_s).ToString([Globalization.CultureInfo]::InvariantCulture),
                        $runRoot))
            }
            $controlSha256 = Write-RawQualificationDurableNewJson -Path (Join-Path $runRoot "processes.json") -Value $control
        }

        $bindings = $null
        $bindingsSha256 = $null
        if ($prefixCount -ge 5) {
            $bindings = Copy-SelfTestJsonValue $realBindingsSnapshot.value
            $bindings.run_id = $runId
            $bindings.bound_utc = [DateTimeOffset]::UtcNow.ToString("o")
            foreach ($binding in @($bindings.campaigns)) {
                $sourceBinding = @($realBindingsSnapshot.value.campaigns | Where-Object {
                    [string]$_.symbol -ceq [string]$binding.symbol })[0]
                $campaignDirectory = Join-Path $runRoot ([IO.Path]::GetFileName([string]$sourceBinding.campaign_directory))
                $null = New-Item -ItemType Directory -Path $campaignDirectory -ErrorAction Stop
                [IO.File]::WriteAllBytes(
                    (Join-Path $campaignDirectory "campaign-startup.json"),
                    [IO.File]::ReadAllBytes((Join-Path ([string]$sourceBinding.campaign_directory) "campaign-startup.json")))
                $binding.campaign_directory = $campaignDirectory
                $binding.campaign_startup_sha256 = Get-RawQualificationSha256File -Path (Join-Path $campaignDirectory "campaign-startup.json")
            }
            $bindingsSha256 = Write-RawQualificationDurableNewJson -Path (Join-Path $runRoot "campaign-bindings.json") -Value $bindings
        }

        $launcherPath = Join-Path $runRoot "launcher-events.jsonl"
        $eventJournal = New-RawQualificationJournal -Path $launcherPath
        $eventTicks = [uint64[]]@(40000000, 41000000, 49000000, 52000000, 116000000, 450000000)
        $wallBase = [uint64]1800000000000000000
        try {
            if ($prefixCount -ge 1) {
                $null = Add-RawQualificationJournalRecord -Journal $eventJournal -Schema "RawQualificationLauncherEventV1" -Channel "LAUNCHER" -WallNs ($wallBase + 1) -MonotonicTick $eventTicks[0] -Payload ([ordered]@{ event="PREFLIGHT_PASSED"; startup_sha256=$startupSha256 })
            }
            if ($prefixCount -ge 2) {
                $null = Add-RawQualificationJournalRecord -Journal $eventJournal -Schema "RawQualificationLauncherEventV1" -Channel "CONTROL" -WallNs ($wallBase + 2) -MonotonicTick $eventTicks[1] -Payload ([ordered]@{
                    event="JOB_OBJECT_ARMED"; name=$jobName; kill_on_close=$true
                    workload_name=$workloadJobName; workload_kill_on_close=$true
                })
            }
            if ($prefixCount -ge 3) {
                $null = Add-RawQualificationJournalRecord -Journal $eventJournal -Schema "RawQualificationLauncherEventV1" -Channel "CONTROL" -WallNs ($wallBase + 3) -MonotonicTick $eventTicks[2] -Payload ([ordered]@{
                    event="GUARDIAN_WATCHDOG_STARTED"; pid=[uint32]$ready.pid; ready_file_sha256=$readySha256
                    launch_origin_qpc_timestamp=[long]$ready.launch_origin_qpc_timestamp
                    resume_qpc_timestamp=[long]$realControlSnapshot.value.watchdog.resume_qpc_timestamp
                    ready_observed_qpc_timestamp=[long]$ready.observed_qpc_timestamp
                    ready_pulse_length=[uint64]$ready.pulse_length; startup_deadline_s=[uint64]90; deadline_s=[uint64]90
                })
            }
            if ($prefixCount -ge 4) {
                $null = Add-RawQualificationJournalRecord -Journal $eventJournal -Schema "RawQualificationLauncherEventV1" -Channel "CONTROL" -WallNs ($wallBase + 4) -MonotonicTick $eventTicks[3] -Payload ([ordered]@{ event="DUAL_CAMPAIGN_STARTED"; process_control_sha256=$controlSha256 })
            }
            if ($prefixCount -ge 5) {
                $null = Add-RawQualificationJournalRecord -Journal $eventJournal -Schema "RawQualificationLauncherEventV1" -Channel "SEMANTIC" -WallNs ($wallBase + 5) -MonotonicTick $eventTicks[4] -Payload ([ordered]@{ event="DUAL_SEMANTIC_READINESS"; bindings_sha256=$bindingsSha256 })
            }
            if ($prefixCount -ge 6) {
                $hostSummary = Get-VerifiedJournalSummary -Path $hostPath -ExpectedSchema "RawQualificationHostTelemetryRecordV1"
                $readyHostRecord = $hostSummary.all_records[1]
                $null = Add-RawQualificationJournalRecord -Journal $eventJournal -Schema "RawQualificationLauncherEventV1" -Channel "SEMANTIC" -WallNs ($wallBase + 6) -MonotonicTick $eventTicks[5] -Payload ([ordered]@{
                    event="DUAL_READINESS_PUBLISHED"; bindings_sha256=$bindingsSha256
                    host_telemetry_record_index=[uint64]$readyHostRecord.body.record_index
                    host_telemetry_record_sha256=[string]$readyHostRecord.record_sha256
                    host_telemetry_monotonic_tick=[uint64]$readyHostRecord.body.monotonic_tick
                })
            }

            $lastPrefixTick = if ($prefixCount -eq 0) { [uint64]0 } else { [uint64]$eventTicks[$prefixCount - 1] }
            $detectedTick = [uint64]($lastPrefixTick + 1000000)
            $terminationTick = [uint64]($detectedTick + 1000)
            $jobExists = $prefixCount -ge 2
            if ($ContainmentMode -ne "AUTO" -and -not $jobExists) {
                throw "Synthetic containment mode $ContainmentMode requires a JOB_OBJECT_ARMED phase."
            }
            $noJob = -not $jobExists -or $ContainmentMode -ceq "NO_JOB"
            $queryError = $ContainmentMode -ceq "QUERY_ERROR"
            $timedOut = $ContainmentMode -ceq "TIMEOUT"
            $drainTicks = if ($queryError -or $timedOut) {
                [uint64](([uint64][Diagnostics.Stopwatch]::Frequency * [uint64]30) + [uint64]1)
            }
            else { [uint64]1000 }
            $containment = [pscustomobject][ordered]@{
                schema = "RawQualificationFailureContainmentV2"
                job_name = $jobName
                job_kill_on_close = [bool](-not $noJob)
                detected_wall_ns = [uint64]($wallBase + 7)
                detected_monotonic_tick = $detectedTick
                requested_exit_code = [uint32]60930
                initial_query_succeeded = [bool](-not $noJob)
                initial_active_processes = if (-not $noJob) { [uint32]2 } else { $null }
                initial_query_error = if (-not $noJob) { $null } else { [uint32]6 }
                terminate_attempted = [bool](-not $noJob)
                terminate_succeeded = if (-not $noJob) { $true } else { $null }
                terminate_error = $null
                termination_monotonic_tick = $terminationTick
                monotonic_frequency = [uint64][Diagnostics.Stopwatch]::Frequency
                drain_deadline_s = [uint64]30
                drain_elapsed_qpc_ticks = $drainTicks
                final_query_succeeded = [bool](-not $noJob -and -not $queryError)
                final_active_processes = if ($noJob -or $queryError) { $null }
                    elseif ($timedOut) { [uint32]1 } else { [uint32]0 }
                final_query_error = if ($noJob) { [uint32]6 }
                    elseif ($queryError) { [uint32]5 } else { $null }
                result = if ($noJob) { "NO_JOB_HANDLE" }
                    elseif ($queryError) { "UNCONFIRMED_QUERY_ERROR" }
                    elseif ($timedOut) { "UNCONFIRMED_TIMEOUT" }
                    else { "DRAINED_BY_ATTEMPT" }
            }
            $containmentSha256 = Get-RawQualificationSha256Bytes -Bytes (
                [Text.UTF8Encoding]::new($false).GetBytes(($containment | ConvertTo-Json -Depth 100 -Compress)))
            $failure = "Synthetic authenticated launcher failure at $Phase."
            $failedTick = [uint64]($terminationTick + $drainTicks)
            $null = Add-RawQualificationJournalRecord -Journal $eventJournal -Schema "RawQualificationLauncherEventV1" -Channel "FAILURE" -WallNs ($wallBase + 8) -MonotonicTick $failedTick -Payload ([ordered]@{ event="LAUNCHER_FAILED"; error=$failure })
            $null = Add-RawQualificationJournalRecord -Journal $eventJournal -Schema "RawQualificationLauncherEventV1" -Channel "FAILURE" -WallNs ($wallBase + 9) -MonotonicTick ([uint64]($failedTick + 1000)) -Payload ([ordered]@{ event="FAILURE_CONTAINMENT_TERMINAL"; failure_containment_sha256=$containmentSha256 })
            $openPrefixSnapshot = Get-RawQualificationJournalPrefixSnapshot -Journal $eventJournal
            $launcherPrefixReceipt = [pscustomobject][ordered]@{
                file = "launcher-events.jsonl"
                records = [uint64]$openPrefixSnapshot.records
                terminal_record_sha256 = [string]$openPrefixSnapshot.terminal_record_sha256
                file_bytes = [uint64]$openPrefixSnapshot.file_bytes
                file_sha256 = [string]$openPrefixSnapshot.file_sha256
            }

            $artifactPreflight = Get-SelfTestTerminalArtifactHashes -Startup $startup -WatchdogReadySha256 $readySha256 -Preflight
            $artifactTerminal = Get-SelfTestTerminalArtifactHashes -Startup $startup -WatchdogReadySha256 $readySha256
            if ($TerminalArtifactMode -ceq "DRIFT") {
                $artifactTerminal.public_config_sha256 = "f" * 64
            }
            elseif ($TerminalArtifactMode -ceq "ABSENT") {
                $artifactTerminal.capture_executable_sha256 = $null
            }
            $terminal = [pscustomobject][ordered]@{
                schema = "RawQualificationLauncherTerminalV2"
                status = "FAILED"
                failure = $failure
                failure_containment = $containment
                failure_containment_sha256 = $containmentSha256
                run_id = $runId
                mode = "Test"
                run_root = $runRoot
                finished_utc = [DateTimeOffset]::UtcNow.ToString("o")
                launcher_elapsed_ms = [uint64]2000
                capture_elapsed_ms = if ($prefixCount -ge 4) { [uint64]1000 } else { $null }
                parameters = Copy-SelfTestJsonValue $realStartupSnapshot.value.parameters
                verifier_policy = Copy-SelfTestJsonValue $realStartupSnapshot.value.verifier_policy
                coordinator_log_policy = Copy-SelfTestJsonValue $realStartupSnapshot.value.coordinator_log_policy
                market_freshness_policy = Copy-SelfTestJsonValue $realStartupSnapshot.value.market_freshness_policy
                guardian_policy = Copy-SelfTestJsonValue $realStartupSnapshot.value.guardian_policy
                startup_sha256 = $startupSha256
                process_control_sha256 = $controlSha256
                campaign_bindings_sha256 = $bindingsSha256
                launcher_events = $launcherPrefixReceipt
                host_telemetry = if ($OmitHostReceipt) { $null } else { $hostReceipt }
                guardian_pulse = if ($OmitGuardianReceipt) { $null } else { $guardianReceipt }
                artifact_hashes_preflight = $artifactPreflight
                artifact_hashes_terminal = $artifactTerminal
                watchdog = $null
                campaigns = [object[]]@()
                credentials = "NONE"
                order_entry = "ABSENT"
            }
            $terminalPath = Join-Path $runRoot "launcher-terminal.json"
            $terminalSha256 = Write-RawQualificationDurableNewJson -Path $terminalPath -Value $terminal
            $terminalBytes = [uint64](Get-Item -LiteralPath $terminalPath).Length
            $null = Add-RawQualificationJournalRecord -Journal $eventJournal -Schema "RawQualificationLauncherEventV1" -Channel "LAUNCHER" -WallNs ($wallBase + 10) -MonotonicTick ([uint64]($failedTick + 2000)) -Payload ([ordered]@{
                event="LAUNCHER_TERMINAL"; status="FAILED"; failure=$failure
                terminal_file="launcher-terminal.json"; terminal_bytes=$terminalBytes
                terminal_sha256=$terminalSha256; failure_containment_sha256=$containmentSha256
            })
        }
        finally { Close-RawQualificationJournal -Journal $eventJournal }
        if ($OmitHostReceipt) { Remove-Item -LiteralPath $hostPath -Force -ErrorAction Stop }
        if ($OmitGuardianReceipt) { Remove-Item -LiteralPath $guardianPath -Force -ErrorAction Stop }
        return [pscustomobject][ordered]@{ phase=$Phase; run_root=$runRoot }
    }

    function Invoke-SelfTestFailedMonitor {
        param(
            [Parameter(Mandatory = $true)] [string] $RunRoot,
            [Parameter(Mandatory = $true)] [string] $ExpectedPhase,
            [switch] $ExpectAuthenticatedFailure,
            [string] $ExpectedErrorFragment
        )
        $psi = [Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = Join-Path $PSHOME "powershell.exe"
        $escapedMonitor = (Join-Path $PSScriptRoot "monitor_24h_raw_qualification.ps1").Replace('"', '\"')
        $escapedRoot = $RunRoot.Replace('"', '\"')
        $psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$escapedMonitor`" -RunRoot `"$escapedRoot`""
        $psi.WorkingDirectory = $repo
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $psi
        if (-not $process.Start()) { throw "Could not launch the full monitor self-test." }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(600000)) {
            try { $process.Kill() } catch {}
            throw "Full monitor self-test exceeded 600 seconds for $ExpectedPhase."
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = [int]$process.ExitCode
        $process.Dispose()
        if ($ExpectAuthenticatedFailure) {
            Assert-True ($exitCode -eq 1) "Authenticated FAILED monitor fixture returned exit $exitCode for $ExpectedPhase. stderr=$stderr"
            $result = $stdout | ConvertFrom-Json
            $statusProperty = if ($null -ne $result) { $result.PSObject.Properties['status'] } else { $null }
            $phaseProperty = if ($null -ne $result) { $result.PSObject.Properties['failure_phase'] } else { $null }
            Assert-True ($null -ne $statusProperty -and $null -ne $phaseProperty -and
                [string]$statusProperty.Value -ceq "FAILED" -and
                [string]$phaseProperty.Value -ceq $ExpectedPhase) "Full monitor did not authenticate exact FAILED phase $ExpectedPhase. stdout=$stdout stderr=$stderr"
            return $result
        }
        Assert-True ($exitCode -ne 0 -and [string]::IsNullOrWhiteSpace($stdout)) "Adversarial full monitor fixture unexpectedly produced authenticated evidence for $ExpectedPhase. stdout=$stdout stderr=$stderr"
        if (-not [string]::IsNullOrWhiteSpace($ExpectedErrorFragment)) {
            Assert-True ($stderr.IndexOf($ExpectedErrorFragment, [StringComparison]::Ordinal) -ge 0) `
                "Full monitor rejected $ExpectedPhase for the wrong reason. expected=$ExpectedErrorFragment stderr=$stderr"
        }
        return [pscustomobject]@{ exit_code=$exitCode; stderr=$stderr }
    }

    $openJournalSnapshotPath = Join-Path $testRoot "open-journal-prefix-snapshot.jsonl"
    $openJournal = New-RawQualificationJournal -Path $openJournalSnapshotPath
    $openJournalCursorRejected = $false
    $closedJournalSnapshotRejected = $false
    try {
        $null = Add-RawQualificationJournalRecord -Journal $openJournal -Schema "RawQualificationGuardianPulseV1" -Channel "GUARDIAN" -WallNs ([uint64]1) -MonotonicTick ([uint64]1) -Payload ([ordered]@{
            event="GUARDIAN_PULSE"; stage="STARTING"; launcher_elapsed_ms=[uint64]0; capture_elapsed_ms=$null
        })
        Assert-True ($openJournal.Stream.CanRead -and $openJournal.Stream.CanWrite) "Journal retained handle is not exact ReadWrite authority."
        $firstOpenPrefix = Get-RawQualificationJournalPrefixSnapshot -Journal $openJournal
        Assert-True ($openJournal.Stream.Position -eq $openJournal.Stream.Length -and
            [uint64]$firstOpenPrefix.records -eq 1 -and
            [uint64]$firstOpenPrefix.file_bytes -eq [uint64]$openJournal.Stream.Length) "Retained-handle prefix snapshot did not restore the append cursor."
        $openJournal.Stream.Position = 0
        try { $null = Get-RawQualificationJournalPrefixSnapshot -Journal $openJournal }
        catch { $openJournalCursorRejected = $true }
        Assert-True $openJournalCursorRejected "Retained-handle prefix snapshot accepted a non-boundary cursor."
        $openJournal.Stream.Position = $openJournal.Stream.Length
        $null = Add-RawQualificationJournalRecord -Journal $openJournal -Schema "RawQualificationGuardianPulseV1" -Channel "GUARDIAN" -WallNs ([uint64]2) -MonotonicTick ([uint64]2) -Payload ([ordered]@{
            event="GUARDIAN_PULSE"; stage="CAPTURING"; launcher_elapsed_ms=[uint64]1; capture_elapsed_ms=[uint64]0
        })
    }
    finally { Close-RawQualificationJournal -Journal $openJournal }
    $openJournalBytes = [IO.File]::ReadAllBytes($openJournalSnapshotPath)
    $firstOpenPrefixBytes = [byte[]]$openJournalBytes[0..([int][uint64]$firstOpenPrefix.file_bytes - 1)]
    Assert-True ((Get-RawQualificationSha256Bytes -Bytes $firstOpenPrefixBytes) -ceq [string]$firstOpenPrefix.file_sha256) "Retained-handle prefix digest differs from the exact closed-file prefix."
    try { $null = Get-RawQualificationJournalPrefixSnapshot -Journal $openJournal }
    catch { $closedJournalSnapshotRejected = $true }
    Assert-True $closedJournalSnapshotRejected "Retained-handle prefix snapshot accepted a closed journal."

    $fullFailedMonitorFixtures = [ordered]@{}
    foreach ($phaseName in @("RECORD0", "POST_PREFLIGHT", "POST_JOB", "POST_WATCHDOG", "POST_DUAL", "SEMANTIC_READY", "POST_READINESS_OR_LATER")) {
        $fixture = New-SelfTestFailedMonitorFixture -Phase $phaseName
        $fullFailedMonitorFixtures[$phaseName] = $fixture
        $null = Invoke-SelfTestFailedMonitor -RunRoot $fixture.run_root -ExpectedPhase $phaseName -ExpectAuthenticatedFailure
    }

    $record0WithoutOperationalReceipts = New-SelfTestFailedMonitorFixture `
        -Phase "RECORD0" -Suffix "optional-no-journals" -OmitHostReceipt -OmitGuardianReceipt
    $null = Invoke-SelfTestFailedMonitor -RunRoot $record0WithoutOperationalReceipts.run_root `
        -ExpectedPhase "RECORD0" -ExpectAuthenticatedFailure

    $queryErrorFixture = New-SelfTestFailedMonitorFixture `
        -Phase "POST_JOB" -Suffix "unconfirmed-query" -ContainmentMode "QUERY_ERROR"
    $queryErrorResult = Invoke-SelfTestFailedMonitor -RunRoot $queryErrorFixture.run_root `
        -ExpectedPhase "POST_JOB" -ExpectAuthenticatedFailure
    Assert-True ([string]$queryErrorResult.containment_certainty -ceq "UNCONFIRMED" -and
        [string]$queryErrorResult.failure_containment.result -ceq "UNCONFIRMED_QUERY_ERROR") `
        "Authenticated query-error containment was falsely reported as drained."

    $timeoutFixture = New-SelfTestFailedMonitorFixture `
        -Phase "POST_JOB" -Suffix "unconfirmed-timeout" -ContainmentMode "TIMEOUT"
    $timeoutResult = Invoke-SelfTestFailedMonitor -RunRoot $timeoutFixture.run_root `
        -ExpectedPhase "POST_JOB" -ExpectAuthenticatedFailure
    Assert-True ([string]$timeoutResult.containment_certainty -ceq "UNCONFIRMED" -and
        [string]$timeoutResult.failure_containment.result -ceq "UNCONFIRMED_TIMEOUT") `
        "Authenticated timeout containment was falsely reported as drained."

    $artifactDriftFixture = New-SelfTestFailedMonitorFixture `
        -Phase "POST_PREFLIGHT" -Suffix "artifact-drift" -TerminalArtifactMode "DRIFT"
    $artifactDriftResult = Invoke-SelfTestFailedMonitor -RunRoot $artifactDriftFixture.run_root `
        -ExpectedPhase "POST_PREFLIGHT" -ExpectAuthenticatedFailure
    $artifactDriftObservation = @($artifactDriftResult.artifact_observations.observations | Where-Object {
        [string]$_.name -ceq "public_config_sha256"
    })
    Assert-True ($artifactDriftObservation.Count -eq 1 -and
        [string]$artifactDriftObservation[0].state -clike "TERMINAL_DRIFT_FROM_PREFLIGHT:*") `
        "FAILED terminal artifact drift was not explicitly reported."

    $artifactAbsentFixture = New-SelfTestFailedMonitorFixture `
        -Phase "POST_PREFLIGHT" -Suffix "artifact-absent" -TerminalArtifactMode "ABSENT"
    $artifactAbsentResult = Invoke-SelfTestFailedMonitor -RunRoot $artifactAbsentFixture.run_root `
        -ExpectedPhase "POST_PREFLIGHT" -ExpectAuthenticatedFailure
    $artifactAbsentObservation = @($artifactAbsentResult.artifact_observations.observations | Where-Object {
        [string]$_.name -ceq "capture_executable_sha256"
    })
    Assert-True ($artifactAbsentObservation.Count -eq 1 -and
        [string]$artifactAbsentObservation[0].state -clike "TERMINAL_ABSENT:*") `
        "FAILED terminal artifact absence was not explicitly reported."

    $fullFailedMonitorMutantsRejected = [uint64]0

    $postJobNoHandleMutant = (New-SelfTestFailedMonitorFixture `
        -Phase "POST_JOB" -Suffix "mutant-no-job" -ContainmentMode "NO_JOB").run_root
    $null = Invoke-SelfTestFailedMonitor -RunRoot $postJobNoHandleMutant -ExpectedPhase "POST_JOB"
    $fullFailedMonitorMutantsRejected++

    $missingHostReceiptMutant = (New-SelfTestFailedMonitorFixture `
        -Phase "POST_PREFLIGHT" -Suffix "mutant-no-host-receipt" -OmitHostReceipt).run_root
    $null = Invoke-SelfTestFailedMonitor -RunRoot $missingHostReceiptMutant -ExpectedPhase "POST_PREFLIGHT"
    $fullFailedMonitorMutantsRejected++

    $missingGuardianReceiptMutant = (New-SelfTestFailedMonitorFixture `
        -Phase "POST_PREFLIGHT" -Suffix "mutant-no-guardian-receipt" -OmitGuardianReceipt).run_root
    $null = Invoke-SelfTestFailedMonitor -RunRoot $missingGuardianReceiptMutant -ExpectedPhase "POST_PREFLIGHT"
    $fullFailedMonitorMutantsRejected++

    $fullCompleteVerifierPolicyMutantsRejected = [uint64]0
    foreach ($policyName in @("per_process_timeout_s", "total_post_capture_timeout_s")) {
        $policyRunRoot = (New-SelfTestFailedMonitorFixture `
            -Phase "SEMANTIC_READY" -Suffix ("mutant-complete-policy-" + $policyName)).run_root
        $policyTerminalPath = Join-Path $policyRunRoot "launcher-terminal.json"
        $policyLauncherPath = Join-Path $policyRunRoot "launcher-events.jsonl"
        $policyTerminal = Get-Content -LiteralPath $policyTerminalPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $policyTerminal.status = "COMPLETE"
        $policyTerminal.failure = $null
        $policyTerminal.failure_containment = $null
        $policyTerminal.failure_containment_sha256 = $null
        $policyTerminal.verifier_policy.$policyName = [uint64]([uint64]$policyTerminal.verifier_policy.$policyName + 1)
        $policyTerminalSha = Write-RawQualificationDurableNewJson `
            -Path ($policyTerminalPath + ".new") -Value $policyTerminal
        Move-Item -LiteralPath ($policyTerminalPath + ".new") -Destination $policyTerminalPath -Force

        $policyLines = [Collections.Generic.List[string]]::new()
        foreach ($line in @(Get-Content -LiteralPath $policyLauncherPath -Encoding UTF8)) {
            $policyLines.Add([string]$line)
        }
        $policyPostLink = $policyLines[$policyLines.Count - 1] | ConvertFrom-Json
        $policyPostLink.body.payload.status = "COMPLETE"
        $policyPostLink.body.payload.failure = $null
        $policyPostLink.body.payload.failure_containment_sha256 = $null
        $policyPostLink.body.payload.terminal_bytes = [uint64](Get-Item -LiteralPath $policyTerminalPath).Length
        $policyPostLink.body.payload.terminal_sha256 = $policyTerminalSha
        $policyPostLink.record_sha256 = Get-RawQualificationSha256Bytes -Bytes (
            [Text.UTF8Encoding]::new($false).GetBytes(($policyPostLink.body | ConvertTo-Json -Depth 100 -Compress)))
        $policyLines[$policyLines.Count - 1] = $policyPostLink | ConvertTo-Json -Depth 100 -Compress
        [IO.File]::WriteAllBytes($policyLauncherPath, [Text.UTF8Encoding]::new($false).GetBytes(
            ($policyLines -join "`n") + "`n"))
        $null = Invoke-SelfTestFailedMonitor `
            -RunRoot $policyRunRoot `
            -ExpectedPhase ("COMPLETE_POLICY_" + $policyName) `
            -ExpectedErrorFragment "Terminal verifier policy does not bind the exact launcher startup policy."
        $fullCompleteVerifierPolicyMutantsRejected++
    }

    $runRootMutant = (New-SelfTestFailedMonitorFixture -Phase "POST_PREFLIGHT" -Suffix "mutant-runroot").run_root
    $runRootTerminalPath = Join-Path $runRootMutant "launcher-terminal.json"
    $runRootTerminal = Get-Content -LiteralPath $runRootTerminalPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $runRootTerminal.run_root = $testRoot
    $runRootTerminalSha = Write-RawQualificationDurableNewJson -Path ($runRootTerminalPath + ".new") -Value $runRootTerminal
    Move-Item -LiteralPath ($runRootTerminalPath + ".new") -Destination $runRootTerminalPath -Force
    $launcherMutantPath = Join-Path $runRootMutant "launcher-events.jsonl"
    $launcherMutantLines = @(Get-Content -LiteralPath $launcherMutantPath -Encoding UTF8)
    $postLinkMutant = $launcherMutantLines[$launcherMutantLines.Count - 1] | ConvertFrom-Json
    $postLinkMutant.body.payload.terminal_sha256 = $runRootTerminalSha
    $postLinkMutant.body.payload.terminal_bytes = [uint64](Get-Item -LiteralPath $runRootTerminalPath).Length
    $postLinkMutant.record_sha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(($postLinkMutant.body | ConvertTo-Json -Depth 100 -Compress)))
    $launcherMutantLines[$launcherMutantLines.Count - 1] = $postLinkMutant | ConvertTo-Json -Depth 100 -Compress
    [IO.File]::WriteAllBytes($launcherMutantPath, [Text.UTF8Encoding]::new($false).GetBytes(($launcherMutantLines -join "`n") + "`n"))
    $null = Invoke-SelfTestFailedMonitor -RunRoot $runRootMutant -ExpectedPhase "POST_PREFLIGHT"
    $fullFailedMonitorMutantsRejected++

    $missingStartupMutant = (New-SelfTestFailedMonitorFixture -Phase "POST_PREFLIGHT" -Suffix "mutant-missing-startup").run_root
    Remove-Item -LiteralPath (Join-Path $missingStartupMutant "launcher-startup.json") -Force -ErrorAction Stop
    $null = Invoke-SelfTestFailedMonitor -RunRoot $missingStartupMutant -ExpectedPhase "POST_PREFLIGHT"
    $fullFailedMonitorMutantsRejected++

    $declaredEnvironmentNamesMutant = (New-SelfTestFailedMonitorFixture `
        -Phase "POST_PREFLIGHT" -Suffix "mutant-environment-names" `
        -MutateDeclaredChildEnvironmentNames).run_root
    $null = Invoke-SelfTestFailedMonitor -RunRoot $declaredEnvironmentNamesMutant `
        -ExpectedPhase "POST_PREFLIGHT" `
        -ExpectedErrorFragment "FAILED launcher startup child environment is not the exact no-inheritance allowlist."
    $fullFailedMonitorMutantsRejected++

    $lateContainmentMutant = (New-SelfTestFailedMonitorFixture -Phase "POST_JOB" -Suffix "mutant-late-drained").run_root
    $lateTerminalPath = Join-Path $lateContainmentMutant "launcher-terminal.json"
    $lateLauncherPath = Join-Path $lateContainmentMutant "launcher-events.jsonl"
    $lateTerminal = Get-Content -LiteralPath $lateTerminalPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $lateRecords = [Collections.Generic.List[object]]::new()
    foreach ($line in @(Get-Content -LiteralPath $lateLauncherPath -Encoding UTF8)) {
        $lateRecords.Add(($line | ConvertFrom-Json))
    }
    $latePostLink = $lateRecords[$lateRecords.Count - 1]
    $lateRecords.RemoveAt($lateRecords.Count - 1)
    $lateContainment = $lateTerminal.failure_containment
    $lateContainment.drain_elapsed_qpc_ticks = [uint64](([uint64]$lateContainment.monotonic_frequency * [uint64]30) + [uint64]1)
    $lateContainment.result = "DRAINED_BY_ATTEMPT"
    $lateContainmentSha = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(
        ($lateContainment | ConvertTo-Json -Depth 100 -Compress)))
    $lateTerminal.failure_containment_sha256 = $lateContainmentSha
    $lateFailureIndex = $lateRecords.Count - 2
    $lateReceiptIndex = $lateRecords.Count - 1
    $lateFailureTick = [uint64]([uint64]$lateContainment.termination_monotonic_tick + [uint64]$lateContainment.drain_elapsed_qpc_ticks)
    $lateRecords[$lateFailureIndex].body.monotonic_tick = $lateFailureTick
    $lateRecords[$lateReceiptIndex].body.monotonic_tick = [uint64]($lateFailureTick + 1)
    $lateRecords[$lateReceiptIndex].body.payload.failure_containment_sha256 = $lateContainmentSha
    $previousLateDigest = "0" * 64
    $latePrefixBuilder = [Text.StringBuilder]::new()
    for ($index = 0; $index -lt $lateRecords.Count; $index++) {
        $record = $lateRecords[$index]
        $record.body.record_index = [uint64]$index
        $record.body.previous_record_sha256 = $previousLateDigest
        $record.record_sha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(
            ($record.body | ConvertTo-Json -Depth 100 -Compress)))
        $previousLateDigest = [string]$record.record_sha256
        $null = $latePrefixBuilder.Append(($record | ConvertTo-Json -Depth 100 -Compress)).Append("`n")
    }
    $latePrefixBytes = [Text.UTF8Encoding]::new($false).GetBytes($latePrefixBuilder.ToString())
    [IO.File]::WriteAllBytes($lateLauncherPath, $latePrefixBytes)
    $lateTerminal.launcher_events.records = [uint64]$lateRecords.Count
    $lateTerminal.launcher_events.terminal_record_sha256 = $previousLateDigest
    $lateTerminal.launcher_events.file_bytes = [uint64]$latePrefixBytes.Length
    $lateTerminal.launcher_events.file_sha256 = Get-RawQualificationSha256Bytes -Bytes $latePrefixBytes
    $lateTerminalSha = Write-RawQualificationDurableNewJson -Path ($lateTerminalPath + ".new") -Value $lateTerminal
    Move-Item -LiteralPath ($lateTerminalPath + ".new") -Destination $lateTerminalPath -Force
    $latePostLink.body.record_index = [uint64]$lateRecords.Count
    $latePostLink.body.previous_record_sha256 = $previousLateDigest
    $latePostLink.body.monotonic_tick = [uint64]($lateFailureTick + 2)
    $latePostLink.body.payload.terminal_bytes = [uint64](Get-Item -LiteralPath $lateTerminalPath).Length
    $latePostLink.body.payload.terminal_sha256 = $lateTerminalSha
    $latePostLink.body.payload.failure_containment_sha256 = $lateContainmentSha
    $latePostLink.record_sha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes(
        ($latePostLink.body | ConvertTo-Json -Depth 100 -Compress)))
    [IO.File]::WriteAllBytes($lateLauncherPath, [Text.UTF8Encoding]::new($false).GetBytes(
        $latePrefixBuilder.ToString() + ($latePostLink | ConvertTo-Json -Depth 100 -Compress) + "`n"))
    $null = Invoke-SelfTestFailedMonitor -RunRoot $lateContainmentMutant -ExpectedPhase "POST_JOB"
    $fullFailedMonitorMutantsRejected++

    $reparseFullMonitorRoot = (New-SelfTestFailedMonitorFixture -Phase "RECORD0" -Suffix "mutant-reparse").run_root
    $fullMonitorJunctionTarget = Join-Path $testRoot "full-monitor-reparse-target"
    $null = New-Item -ItemType Directory -Path $fullMonitorJunctionTarget -ErrorAction Stop
    $fullMonitorJunction = Join-Path $reparseFullMonitorRoot "evidence-junction"
    $null = New-Item -ItemType Junction -Path $fullMonitorJunction -Target $fullMonitorJunctionTarget -ErrorAction Stop
    $null = Invoke-SelfTestFailedMonitor -RunRoot $reparseFullMonitorRoot -ExpectedPhase "RECORD0"
    $fullFailedMonitorMutantsRejected++
    Remove-Item -LiteralPath $fullMonitorJunction -Force -ErrorAction Stop

    # Exercise the actual PowerShell journal writer.  Its complete frozen prefix
    # must be exact compact JSON + LF before hash-chain or payload interpretation.
    $canonicalJournalPath = Join-Path $testRoot "canonical-guardian.jsonl"
    $canonicalJournalWriter = New-RawQualificationJournal -Path $canonicalJournalPath
    try {
        $null = Add-RawQualificationJournalRecord `
            -Journal $canonicalJournalWriter `
            -Schema "RawQualificationGuardianPulseV1" `
            -Channel "GUARDIAN" `
            -WallNs ([uint64]1) `
            -MonotonicTick ([uint64]1) `
            -Payload ([pscustomobject][ordered]@{
                event = "GUARDIAN_PULSE"; stage = "STARTING"
                launcher_elapsed_ms = [uint64]0; capture_elapsed_ms = $null
            })
    }
    finally { Close-RawQualificationJournal -Journal $canonicalJournalWriter }
    $canonicalJournalSummary = Get-VerifiedJournalSummary `
        -Path $canonicalJournalPath `
        -ExpectedSchema "RawQualificationGuardianPulseV1"
    Assert-True ($canonicalJournalSummary.records -eq 1 -and -not $canonicalJournalSummary.partial_tail) "Exact PowerShell JSONL writer record was rejected."
    $canonicalJournalBytes = [IO.File]::ReadAllBytes($canonicalJournalPath)
    $canonicalJournalText = [Text.UTF8Encoding]::new($false, $true).GetString($canonicalJournalBytes)
    $canonicalJournalLine = $canonicalJournalText.TrimEnd("`n")
    $canonicalJournalEnvelope = $canonicalJournalLine | ConvertFrom-Json
    $canonicalJournalDigest = [string]$canonicalJournalEnvelope.record_sha256
    $journalMutationCases = [ordered]@{
        whitespace = { [Text.UTF8Encoding]::new($false).GetBytes("{ " + $canonicalJournalLine.Substring(1) + "`n") }
        duplicate_key = {
            [Text.UTF8Encoding]::new($false).GetBytes(
                $canonicalJournalLine.Substring(0, $canonicalJournalLine.Length - 1) +
                ',"record_sha256":"' + $canonicalJournalDigest + '"}' + "`n")
        }
        reordered_outer = {
            ConvertTo-RawQualificationJsonBytes -Value ([pscustomobject][ordered]@{
                record_sha256 = $canonicalJournalDigest; body = $canonicalJournalEnvelope.body })
        }
        resealed_payload_order = {
            $body = [ordered]@{
                schema = "RawQualificationGuardianPulseV1"; record_index = [uint64]0
                wall_ns = [uint64]1; monotonic_tick = [uint64]1; channel = "GUARDIAN"
                payload = [ordered]@{ stage = "STARTING"; event = "GUARDIAN_PULSE"; launcher_elapsed_ms = [uint64]0; capture_elapsed_ms = $null }
                previous_record_sha256 = ('0' * 64)
            }
            $bodyDigest = Get-RawQualificationSha256Bytes -Bytes (
                [Text.UTF8Encoding]::new($false).GetBytes(($body | ConvertTo-Json -Depth 100 -Compress)))
            ConvertTo-RawQualificationJsonBytes -Value ([ordered]@{ body = $body; record_sha256 = $bodyDigest })
        }
        crlf = { [Text.UTF8Encoding]::new($false).GetBytes($canonicalJournalLine + "`r`n") }
        bom = { [byte[]](@(0xEF, 0xBB, 0xBF) + $canonicalJournalBytes) }
    }
    $canonicalJournalMutantsRejected = [uint64]0
    foreach ($mutationName in $journalMutationCases.Keys) {
        $mutationPath = Join-Path $testRoot "canonical-guardian-$mutationName.jsonl"
        [IO.File]::WriteAllBytes($mutationPath, [byte[]](& $journalMutationCases[$mutationName]))
        $null = & $assertCanonicalRejected {
            Get-VerifiedJournalSummary -Path $mutationPath -ExpectedSchema "RawQualificationGuardianPulseV1"
        } "PowerShell-JSONL-$mutationName"
        $canonicalJournalMutantsRejected++
    }
    $partialJournalPath = Join-Path $testRoot "canonical-guardian-partial-tail.jsonl"
    [IO.File]::WriteAllBytes(
        $partialJournalPath,
        [Text.UTF8Encoding]::new($false).GetBytes($canonicalJournalLine + "`n{"))
    $partialJournalSummary = Get-VerifiedJournalSummary `
        -Path $partialJournalPath `
        -ExpectedSchema "RawQualificationGuardianPulseV1"
    Assert-True ($partialJournalSummary.records -eq 1 -and $partialJournalSummary.partial_tail) "A valid frozen complete prefix with an uncommitted partial tail was rejected."

    # Real Rust evidence proves serde's exact two-space singleton and compact
    # BTreeMap JSONL representations rather than substituting PowerShell pretty.
    $rustFixtureCampaign = Join-Path $repo "artifacts\parity-final-20260824\1700000000000000000-BTCUSDT-raw-aaaaaaaaaaaa"
    Assert-True (Test-Path -LiteralPath $rustFixtureCampaign -PathType Container) "Deterministic Rust parity fixture is absent."
    $rustStartupPath = Join-Path $rustFixtureCampaign "campaign-startup.json"
    $rustManifestPath = Join-Path $rustFixtureCampaign "campaign.json"
    $rustJournalPath = Join-Path $rustFixtureCampaign "campaign-events.jsonl"
    $rustStartupSnapshot = Read-MonitorCanonicalJsonSnapshot -Path $rustStartupPath -WriterKind TwoSpacePretty
    $rustManifestSnapshot = Read-MonitorCanonicalJsonSnapshot -Path $rustManifestPath -WriterKind TwoSpacePretty
    $null = Assert-MonitorRustCampaignSingletonWriterOrder -Value $rustStartupSnapshot.value -Kind Startup
    $null = Assert-MonitorRustCampaignSingletonWriterOrder -Value $rustManifestSnapshot.value -Kind Manifest
    $null = Assert-MonitorRustCampaignSingletonJsonTypes -Value $rustStartupSnapshot.value -Kind Startup
    $null = Assert-MonitorRustCampaignSingletonJsonTypes -Value $rustManifestSnapshot.value -Kind Manifest
    $rustSingletonTypeMutantsRejected = [uint64]0
    foreach ($case in @(
            [pscustomobject]@{kind="Startup";property="process_id";value="10"},
            [pscustomobject]@{kind="Startup";property="total_duration_s";value=$true},
            [pscustomobject]@{kind="Startup";property="started_wall_ns";value=[double]1},
            [pscustomobject]@{kind="Manifest";property="supervisor_gap_count";value="0"},
            [pscustomobject]@{kind="Manifest";property="total_duration_s";value=[double]2},
            [pscustomobject]@{kind="Manifest";property="finished_wall_ns";value=$false})) {
        $source = if ($case.kind -eq "Startup") { $rustStartupSnapshot.value } else { $rustManifestSnapshot.value }
        $mutant = $source | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
        $mutant.PSObject.Properties[$case.property].Value = $case.value
        $rejected = $false
        try { $null = Assert-MonitorRustCampaignSingletonJsonTypes -Value $mutant -Kind $case.kind }
        catch { $rejected = $true }
        Assert-True $rejected "Rust singleton coercion mutant was accepted: $($case.kind).$($case.property)"
        $rustSingletonTypeMutantsRejected++
    }
    $rustBinding = [pscustomobject]@{
        symbol = [string]$rustStartupSnapshot.value.symbol
        pid = [uint32]$rustStartupSnapshot.value.process_id
        campaign_id = [string]$rustStartupSnapshot.value.campaign_id
        campaign_startup_sha256 = [string]$rustStartupSnapshot.sha256
    }
    $rustLauncherBinding = [pscustomobject]@{
        parameters = [pscustomobject]@{
            total_s = [uint64]$rustStartupSnapshot.value.total_duration_s
            rotation_s = [uint64]$rustStartupSnapshot.value.rotation_s
            overlap_s = [uint64]$rustStartupSnapshot.value.overlap_s
            segment_s = [uint64]$rustStartupSnapshot.value.segment_s
        }
        preflight = [pscustomobject]@{
            campaign_executable_sha256 = [string]$rustStartupSnapshot.value.executable_sha256
            capture_executable_sha256 = [string]$rustStartupSnapshot.value.capture_executable_sha256
            public_config_sha256 = [string]$rustStartupSnapshot.value.public_config_sha256
            spec_revision = [string]$rustStartupSnapshot.value.spec_revision
        }
    }
    $rustControlBinding = [pscustomobject]@{ pid = [uint32]$rustStartupSnapshot.value.process_id }
    $null = Assert-MonitorCampaignStartupBinding `
        -CampaignStartup $rustStartupSnapshot.value `
        -CampaignStartupSha256 $rustStartupSnapshot.sha256 `
        -Binding $rustBinding `
        -LauncherStartup $rustLauncherBinding `
        -ControlProcess $rustControlBinding
    $rustCrossBindingMutantsRejected = [uint64]0
    foreach ($property in @("pid", "campaign_startup_sha256", "campaign_id")) {
        $mutantBinding = $rustBinding | ConvertTo-Json -Compress | ConvertFrom-Json
        if ($property -eq "pid") { $mutantBinding.pid = [int64]([uint32]$rustBinding.pid + 1) }
        elseif ($property -eq "campaign_startup_sha256") { $mutantBinding.campaign_startup_sha256 = 'e' * 64 }
        else { $mutantBinding.campaign_id = "wrong-campaign" }
        $rejected = $false
        try {
            $null = Assert-MonitorCampaignStartupBinding `
                -CampaignStartup $rustStartupSnapshot.value `
                -CampaignStartupSha256 $rustStartupSnapshot.sha256 `
                -Binding $mutantBinding `
                -LauncherStartup $rustLauncherBinding `
                -ControlProcess $rustControlBinding
        }
        catch { $rejected = $true }
        Assert-True $rejected "Rust campaign startup cross-binding mutant was accepted: $property"
        $rustCrossBindingMutantsRejected++
    }
    $rustJournalHealth = Get-CampaignJournalHealth `
        -Path $rustJournalPath `
        -CampaignStartup $rustStartupSnapshot.value `
        -CampaignStartupSha256 $rustStartupSnapshot.sha256
    Assert-True ($rustJournalHealth.records -eq 16) "Real Rust campaign journal did not preserve all 16 canonical records."
    $rustJournalLines = @(Get-Content -LiteralPath $rustJournalPath -Encoding UTF8)
    $continuityPrefixRecordCount = [uint64]8
    $continuityPath = Join-Path $testRoot "campaign-prefix-continuity.jsonl"
    $continuityPrefixBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        (($rustJournalLines[0..([int]$continuityPrefixRecordCount - 1)] -join "`n") + "`n"))
    [IO.File]::WriteAllBytes($continuityPath, $continuityPrefixBytes)
    $continuityPrefixHealth = Get-CampaignJournalHealth `
        -Path $continuityPath `
        -CampaignStartup $rustStartupSnapshot.value `
        -CampaignStartupSha256 $rustStartupSnapshot.sha256
    $continuitySuffixBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        (($rustJournalLines[([int]$continuityPrefixRecordCount)..($rustJournalLines.Count - 1)] -join "`n") + "`n"))
    $continuityAppend = [IO.File]::Open(
        $continuityPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $continuityAppend.Write($continuitySuffixBytes, 0, $continuitySuffixBytes.Length)
        $continuityAppend.Flush($true)
    }
    finally { $continuityAppend.Dispose() }
    $continuityExtendedHealth = Get-CampaignJournalHealth `
        -Path $continuityPath `
        -CampaignStartup $rustStartupSnapshot.value `
        -CampaignStartupSha256 $rustStartupSnapshot.sha256 `
        -ExpectedPrefixRecords ([uint64]$continuityPrefixHealth.records) `
        -ExpectedPrefixTerminalRecordSha256 ([string]$continuityPrefixHealth.terminal_record_sha256) `
        -ExpectedPrefixFileLength ([uint64]$continuityPrefixHealth.file_length) `
        -ExpectedPrefixFileSha256 ([string]$continuityPrefixHealth.file_sha256) `
        -ContinuationState $continuityPrefixHealth.continuation_state
    $continuityDeltaSnapshot = Read-MonitorFrozenCanonicalJsonLines `
        -Path $continuityPath `
        -ExpectedPrefixLength ([uint64]$continuityPrefixHealth.file_length) `
        -ExpectedPrefixSha256 ([string]$continuityPrefixHealth.file_sha256) `
        -ParseFromOffset ([uint64]$continuityPrefixHealth.complete_length) `
        -ParseFromOffsetSha256 ([string]$continuityPrefixHealth.complete_sha256)
    $continuityEquivalent = (
        [uint64]$continuityExtendedHealth.records -eq [uint64]$rustJournalHealth.records -and
        [string]$continuityExtendedHealth.terminal_record_sha256 -ceq [string]$rustJournalHealth.terminal_record_sha256 -and
        [bool]$continuityExtendedHealth.process_started -eq [bool]$rustJournalHealth.process_started -and
        [bool]$continuityExtendedHealth.snapshot_durable -eq [bool]$rustJournalHealth.snapshot_durable -and
        [bool]$continuityExtendedHealth.campaign_failed -eq [bool]$rustJournalHealth.campaign_failed -and
        [bool]$continuityExtendedHealth.campaign_committed -eq [bool]$rustJournalHealth.campaign_committed -and
        [uint64]$continuityExtendedHealth.child_stderr_events -eq [uint64]$rustJournalHealth.child_stderr_events -and
        (@($continuityExtendedHealth.generation_health) | ConvertTo-Json -Depth 20 -Compress) -ceq
            (@($rustJournalHealth.generation_health) | ConvertTo-Json -Depth 20 -Compress))
    Assert-True ($continuityEquivalent -and
        @($continuityDeltaSnapshot.lines).Count -eq
            ([int][uint64]$rustJournalHealth.records - [int]$continuityPrefixRecordCount)) `
        "Incremental campaign parsing did not exactly match replay-from-zero while reading only its delta."
    $continuityDigestMutantRejected = $false
    try {
        $null = Get-CampaignJournalHealth `
            -Path $continuityPath `
            -CampaignStartup $rustStartupSnapshot.value `
            -CampaignStartupSha256 $rustStartupSnapshot.sha256 `
            -ExpectedPrefixRecords ([uint64]$continuityPrefixHealth.records) `
            -ExpectedPrefixTerminalRecordSha256 ('f' * 64) `
            -ExpectedPrefixFileLength ([uint64]$continuityPrefixHealth.file_length) `
            -ExpectedPrefixFileSha256 ([string]$continuityPrefixHealth.file_sha256) `
            -ContinuationState $continuityPrefixHealth.continuation_state
    }
    catch { $continuityDigestMutantRejected = $true }
    $continuityByteMutantRejected = $false
    try {
        $null = Get-CampaignJournalHealth `
            -Path $continuityPath `
            -CampaignStartup $rustStartupSnapshot.value `
            -CampaignStartupSha256 $rustStartupSnapshot.sha256 `
            -ExpectedPrefixRecords ([uint64]$continuityPrefixHealth.records) `
            -ExpectedPrefixTerminalRecordSha256 ([string]$continuityPrefixHealth.terminal_record_sha256) `
            -ExpectedPrefixFileLength ([uint64]$continuityPrefixHealth.file_length) `
            -ExpectedPrefixFileSha256 ('e' * 64) `
            -ContinuationState $continuityPrefixHealth.continuation_state
    }
    catch { $continuityByteMutantRejected = $true }
    Assert-True ($continuityDigestMutantRejected -and $continuityByteMutantRejected) `
        "Campaign journal continuity accepted a substituted logical or byte prefix."
    $partialRecordBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        [string]$rustJournalLines[[int]$continuityPrefixRecordCount])
    $partialRecordCut = [int][math]::Floor([double]$partialRecordBytes.Length / 2.0)
    $partialObservedBytes = [byte[]]::new($continuityPrefixBytes.Length + $partialRecordCut)
    [Array]::Copy($continuityPrefixBytes, 0, $partialObservedBytes, 0, $continuityPrefixBytes.Length)
    [Array]::Copy($partialRecordBytes, 0, $partialObservedBytes, $continuityPrefixBytes.Length, $partialRecordCut)
    $partialContinuityPath = Join-Path $testRoot "campaign-partial-prefix-continuity.jsonl"
    [IO.File]::WriteAllBytes($partialContinuityPath, $partialObservedBytes)
    $partialPrefixHealth = Get-CampaignJournalHealth `
        -Path $partialContinuityPath `
        -CampaignStartup $rustStartupSnapshot.value `
        -CampaignStartupSha256 $rustStartupSnapshot.sha256
    Assert-True ([bool]$partialPrefixHealth.partial_tail -and
        [uint64]$partialPrefixHealth.records -eq $continuityPrefixRecordCount -and
        [uint64]$partialPrefixHealth.complete_length -eq [uint64]$continuityPrefixBytes.Length -and
        [uint64]$partialPrefixHealth.file_length -gt [uint64]$partialPrefixHealth.complete_length) `
        "Campaign continuation fixture did not preserve an authenticated partial tail."
    $partialRemainderBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ([string]$rustJournalLines[[int]$continuityPrefixRecordCount]).Substring($partialRecordCut) + "`n" +
        (($rustJournalLines[([int]$continuityPrefixRecordCount + 1)..($rustJournalLines.Count - 1)] -join "`n") + "`n"))
    $partialAppend = [IO.File]::Open(
        $partialContinuityPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $partialAppend.Write($partialRemainderBytes, 0, $partialRemainderBytes.Length)
        $partialAppend.Flush($true)
    }
    finally { $partialAppend.Dispose() }
    $partialExtendedHealth = Get-CampaignJournalHealth `
        -Path $partialContinuityPath `
        -CampaignStartup $rustStartupSnapshot.value `
        -CampaignStartupSha256 $rustStartupSnapshot.sha256 `
        -ExpectedPrefixRecords ([uint64]$partialPrefixHealth.records) `
        -ExpectedPrefixTerminalRecordSha256 ([string]$partialPrefixHealth.terminal_record_sha256) `
        -ExpectedPrefixFileLength ([uint64]$partialPrefixHealth.file_length) `
        -ExpectedPrefixFileSha256 ([string]$partialPrefixHealth.file_sha256) `
        -ContinuationState $partialPrefixHealth.continuation_state
    $partialContinuationEquivalent = (
        [uint64]$partialExtendedHealth.records -eq [uint64]$rustJournalHealth.records -and
        [string]$partialExtendedHealth.terminal_record_sha256 -ceq [string]$rustJournalHealth.terminal_record_sha256 -and
        (@($partialExtendedHealth.generation_health) | ConvertTo-Json -Depth 20 -Compress) -ceq
            (@($rustJournalHealth.generation_health) | ConvertTo-Json -Depth 20 -Compress))
    Assert-True $partialContinuationEquivalent `
        "A completed partial-tail continuation diverged from exact replay-from-zero."
    $partialMutantPath = Join-Path $testRoot "campaign-partial-prefix-mutant.jsonl"
    [IO.File]::WriteAllBytes($partialMutantPath, $partialObservedBytes)
    $partialMutantBytes = [IO.File]::ReadAllBytes($partialMutantPath)
    $partialMutantBytes[$partialMutantBytes.Length - 1] = [byte]($partialMutantBytes[$partialMutantBytes.Length - 1] -bxor 1)
    [IO.File]::WriteAllBytes($partialMutantPath, $partialMutantBytes)
    $partialObservedMutationRejected = $false
    $originalContinuationPath = [string]$partialPrefixHealth.continuation_state.path
    try {
        $partialPrefixHealth.continuation_state.path = [IO.Path]::GetFullPath($partialMutantPath)
        $null = Get-CampaignJournalHealth `
            -Path $partialMutantPath `
            -CampaignStartup $rustStartupSnapshot.value `
            -CampaignStartupSha256 $rustStartupSnapshot.sha256 `
            -ExpectedPrefixRecords ([uint64]$partialPrefixHealth.records) `
            -ExpectedPrefixTerminalRecordSha256 ([string]$partialPrefixHealth.terminal_record_sha256) `
            -ExpectedPrefixFileLength ([uint64]$partialPrefixHealth.file_length) `
            -ExpectedPrefixFileSha256 ([string]$partialPrefixHealth.file_sha256) `
            -ContinuationState $partialPrefixHealth.continuation_state
    }
    catch { $partialObservedMutationRejected = $true }
    finally { $partialPrefixHealth.continuation_state.path = $originalContinuationPath }
    $parseCursorDigestMutationRejected = $false
    $originalCompleteDigest = [string]$continuityPrefixHealth.continuation_state.complete_sha256
    try {
        $continuityPrefixHealth.continuation_state.complete_sha256 = 'd' * 64
        $null = Get-CampaignJournalHealth `
            -Path $continuityPath `
            -CampaignStartup $rustStartupSnapshot.value `
            -CampaignStartupSha256 $rustStartupSnapshot.sha256 `
            -ExpectedPrefixRecords ([uint64]$continuityPrefixHealth.records) `
            -ExpectedPrefixTerminalRecordSha256 ([string]$continuityPrefixHealth.terminal_record_sha256) `
            -ExpectedPrefixFileLength ([uint64]$continuityPrefixHealth.file_length) `
            -ExpectedPrefixFileSha256 ([string]$continuityPrefixHealth.file_sha256) `
            -ContinuationState $continuityPrefixHealth.continuation_state
    }
    catch { $parseCursorDigestMutationRejected = $true }
    finally { $continuityPrefixHealth.continuation_state.complete_sha256 = $originalCompleteDigest }
    Assert-True ($partialObservedMutationRejected -and $parseCursorDigestMutationRejected) `
        "Incremental campaign parsing accepted a mutated observed tail or parse cursor."
    $rustSingletonText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$rustStartupSnapshot.bytes)
    $rustSingletonMutationCases = [ordered]@{
        whitespace = { [Text.UTF8Encoding]::new($false).GetBytes($rustSingletonText.Insert(1, ' ')) }
        duplicate_key = { [Text.UTF8Encoding]::new($false).GetBytes($rustSingletonText.Insert(2, '  "schema": "RawCampaignStartupV1",' + "`n")) }
        reordered = {
            $source = $rustStartupSnapshot.value
            $names = [string[]]@($source.PSObject.Properties.Name)
            $reorderedValue = [ordered]@{}
            for ($nameIndex = $names.Count - 1; $nameIndex -ge 0; $nameIndex--) {
                $reorderedValue[$names[$nameIndex]] = $source.PSObject.Properties[$names[$nameIndex]].Value
            }
            ConvertTo-MonitorTwoSpacePrettyJsonBytes -Value $reorderedValue
        }
        crlf = { [Text.UTF8Encoding]::new($false).GetBytes($rustSingletonText.Replace("`n", "`r`n")) }
        bom = { [byte[]](@(0xEF, 0xBB, 0xBF) + [byte[]]$rustStartupSnapshot.bytes) }
        missing_lf = { [byte[]]$rustStartupSnapshot.bytes[0..($rustStartupSnapshot.bytes.Length - 2)] }
    }
    $rustSingletonMutantsRejected = [uint64]0
    foreach ($mutationName in $rustSingletonMutationCases.Keys) {
        $mutationPath = Join-Path $testRoot "canonical-rust-startup-$mutationName.json"
        [IO.File]::WriteAllBytes($mutationPath, [byte[]](& $rustSingletonMutationCases[$mutationName]))
        $null = & $assertCanonicalRejected {
            $snapshot = Read-MonitorCanonicalJsonSnapshot -Path $mutationPath -WriterKind TwoSpacePretty
            Assert-MonitorRustCampaignSingletonWriterOrder -Value $snapshot.value -Kind Startup
        } "Rust-singleton-$mutationName"
        $rustSingletonMutantsRejected++
    }
    $rustJournalBytes = [IO.File]::ReadAllBytes($rustJournalPath)
    $rustJournalText = [Text.UTF8Encoding]::new($false, $true).GetString($rustJournalBytes)
    $rustJournalLines = $rustJournalText -split "`n", -1
    $rustFirstLine = $rustJournalLines[0]
    $rustFirstEnvelope = $rustFirstLine | ConvertFrom-Json
    $rustJournalRest = [string]::Join("`n", $rustJournalLines[1..($rustJournalLines.Count - 1)])
    $rustJournalMutationCases = [ordered]@{
        whitespace = { [Text.UTF8Encoding]::new($false).GetBytes("{ " + $rustFirstLine.Substring(1) + "`n" + $rustJournalRest) }
        duplicate_key = {
            [Text.UTF8Encoding]::new($false).GetBytes(
                $rustFirstLine.Substring(0, $rustFirstLine.Length - 1) +
                ',"record_sha256":"' + [string]$rustFirstEnvelope.record_sha256 + '"}' + "`n" + $rustJournalRest)
        }
        reordered_outer = {
            $first = ([pscustomobject][ordered]@{
                record_sha256 = $rustFirstEnvelope.record_sha256; body = $rustFirstEnvelope.body
            } | ConvertTo-Json -Depth 100 -Compress)
            [Text.UTF8Encoding]::new($false).GetBytes($first + "`n" + $rustJournalRest)
        }
        resealed_payload_order = {
            $originalBody = $rustFirstEnvelope.body
            $payloadNames = [string[]]@($originalBody.payload.PSObject.Properties.Name)
            $reversedPayload = [ordered]@{}
            for ($payloadIndex = $payloadNames.Count - 1; $payloadIndex -ge 0; $payloadIndex--) {
                $reversedPayload[$payloadNames[$payloadIndex]] = $originalBody.payload.PSObject.Properties[$payloadNames[$payloadIndex]].Value
            }
            $body = [ordered]@{
                schema = $originalBody.schema; record_index = $originalBody.record_index
                wall_ns = $originalBody.wall_ns; campaign_mono_ns = $originalBody.campaign_mono_ns
                generation_index = $originalBody.generation_index; channel = $originalBody.channel
                payload = $reversedPayload; previous_record_sha256 = $originalBody.previous_record_sha256
            }
            $bodyDigest = Get-RawQualificationSha256Bytes -Bytes (
                [Text.UTF8Encoding]::new($false).GetBytes(($body | ConvertTo-Json -Depth 100 -Compress)))
            $first = ([ordered]@{ body = $body; record_sha256 = $bodyDigest } | ConvertTo-Json -Depth 100 -Compress)
            [Text.UTF8Encoding]::new($false).GetBytes($first + "`n" + $rustJournalRest)
        }
        crlf = { [Text.UTF8Encoding]::new($false).GetBytes($rustJournalText.Replace("`n", "`r`n")) }
        bom = { [byte[]](@(0xEF, 0xBB, 0xBF) + $rustJournalBytes) }
    }
    $rustJournalMutantsRejected = [uint64]0
    foreach ($mutationName in $rustJournalMutationCases.Keys) {
        $mutationPath = Join-Path $testRoot "canonical-rust-journal-$mutationName.jsonl"
        [IO.File]::WriteAllBytes($mutationPath, [byte[]](& $rustJournalMutationCases[$mutationName]))
        $null = & $assertCanonicalRejected {
            Get-CampaignJournalHealth -Path $mutationPath
        } "Rust-JSONL-$mutationName"
        $rustJournalMutantsRejected++
    }
    $writeResealedRustJournalMutant = {
        param([string] $Name, [scriptblock] $Mutation)
        $envelopes = @(
            (Get-Content -LiteralPath $rustJournalPath -Encoding UTF8) |
                ForEach-Object { $_ | ConvertFrom-Json })
        & $Mutation $envelopes
        $previous = '0' * 64
        $lines = [Collections.Generic.List[string]]::new()
        for ($index = 0; $index -lt $envelopes.Count; $index++) {
            $envelope = $envelopes[$index]
            $envelope.body.previous_record_sha256 = $previous
            $bodyJson = $envelope.body | ConvertTo-Json -Depth 100 -Compress
            $digest = Get-RawQualificationSha256Bytes -Bytes (
                [Text.UTF8Encoding]::new($false).GetBytes($bodyJson))
            $line = [ordered]@{ body = $envelope.body; record_sha256 = $digest } |
                ConvertTo-Json -Depth 100 -Compress
            $lines.Add($line)
            $previous = $digest
        }
        $path = Join-Path $testRoot "semantic-rust-$Name.jsonl"
        [IO.File]::WriteAllBytes(
            $path,
            [Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n") + "`n"))
        return $path
    }
    $rustSemanticMutants = [ordered]@{
        first_event_unknown = { param($rows) $rows[0].body.payload.event = "CAMPAIGN_STARTED_FUTURE" }
        duplicate_started = { param($rows) $rows[1].body.payload.event = "CAMPAIGN_STARTED" }
        startup_sha_mismatch = { param($rows) $rows[0].body.payload.startup_sha256 = ('f' * 64) }
        record_index_string = { param($rows) $rows[3].body.record_index = "3" }
        wall_bool = { param($rows) $rows[3].body.wall_ns = $true }
        wall_double = { param($rows) $rows[3].body.wall_ns = [double]$rows[3].body.wall_ns }
        wall_regression = { param($rows) $rows[3].body.wall_ns = [uint64]1 }
        mono_string = { param($rows) $rows[4].body.campaign_mono_ns = "4" }
        mono_regression = { param($rows) $rows[5].body.campaign_mono_ns = [uint64]0 }
        generation_index_double = { param($rows) $rows[6].body.generation_index = [double]1.5 }
        process_id_string = { param($rows) $rows[2].body.payload.process_id = "123" }
        duration_string = { param($rows) $rows[1].body.payload.duration_s = "2" }
        success_string = { param($rows) $rows[9].body.payload.success = "true" }
        exit_code_bool = { param($rows) $rows[9].body.payload.code = $false }
        unknown_payload_property = { param($rows) $rows[3].body.payload | Add-Member -NotePropertyName future -NotePropertyValue 1 }
        commit_before_prepared = { param($rows) $rows[14].body.payload.event = "CAMPAIGN_COMMITTED" }
        missing_terminal = { param($rows) $rows[12].body.payload.event = "PROCESS_STARTED" }
    }
    $rustSemanticMutantsRejected = [uint64]0
    foreach ($mutationName in $rustSemanticMutants.Keys) {
        $mutationPath = & $writeResealedRustJournalMutant $mutationName $rustSemanticMutants[$mutationName]
        $rejected = $false
        try {
            $null = Get-CampaignJournalHealth `
                -Path $mutationPath `
                -CampaignStartup $rustStartupSnapshot.value `
                -CampaignStartupSha256 $rustStartupSnapshot.sha256
        }
        catch { $rejected = $true }
        Assert-True $rejected "A hash-valid Rust campaign lifecycle/type mutant was accepted: $mutationName"
        $rustSemanticMutantsRejected++
    }
    Assert-True ($rustSemanticMutantsRejected -eq [uint64]$rustSemanticMutants.Count) "Rust semantic/type mutant matrix is incomplete."
    $validFailureContainment = [pscustomobject][ordered]@{
        schema = "RawQualificationFailureContainmentV2"
        job_name = "Local\BinanceRawQualificationJob-selftest"
        job_kill_on_close = $true
        detected_wall_ns = [uint64]1
        detected_monotonic_tick = [uint64]10
        requested_exit_code = [uint32]60930
        initial_query_succeeded = $true
        initial_active_processes = [uint32]3
        initial_query_error = $null
        terminate_attempted = $true
        terminate_succeeded = $true
        terminate_error = $null
        termination_monotonic_tick = [uint64]11
        monotonic_frequency = [uint64][Diagnostics.Stopwatch]::Frequency
        drain_deadline_s = [uint64]30
        drain_elapsed_qpc_ticks = [uint64]([Diagnostics.Stopwatch]::Frequency)
        final_query_succeeded = $true
        final_active_processes = [uint32]0
        final_query_error = $null
        result = "DRAINED_BY_ATTEMPT"
    }
    $null = Assert-MonitorFailureContainmentJsonContract `
        -Value $validFailureContainment `
        -ExpectedMonotonicFrequency ([long][Diagnostics.Stopwatch]::Frequency)
    $noJobContainment = $validFailureContainment | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
    $noJobContainment.job_kill_on_close = $false
    $noJobContainment.initial_query_succeeded = $false
    $noJobContainment.initial_active_processes = $null
    $noJobContainment.initial_query_error = [int64]6
    $noJobContainment.terminate_attempted = $false
    $noJobContainment.terminate_succeeded = $null
    $noJobContainment.terminate_error = $null
    $noJobContainment.final_query_succeeded = $false
    $noJobContainment.final_active_processes = $null
    $noJobContainment.final_query_error = [int64]6
    $noJobContainment.result = "NO_JOB_HANDLE"
    $null = Assert-MonitorFailureContainmentJsonContract `
        -Value $noJobContainment `
        -ExpectedMonotonicFrequency ([long][Diagnostics.Stopwatch]::Frequency)
    $failureContainmentMutantsRejected = [uint64]0
    foreach ($case in @(
            [pscustomobject]@{property="job_kill_on_close";value="true"},
            [pscustomobject]@{property="detected_wall_ns";value=[double]1},
            [pscustomobject]@{property="requested_exit_code";value="60930"},
            [pscustomobject]@{property="terminate_attempted";value=1},
            [pscustomobject]@{property="terminate_succeeded";value=$false},
            [pscustomobject]@{property="termination_monotonic_tick";value=[int64]9},
            [pscustomobject]@{property="drain_elapsed_qpc_ticks";value=[int64]([Diagnostics.Stopwatch]::Frequency * 30 + 1)},
            [pscustomobject]@{property="final_active_processes";value=[int64]1},
            [pscustomobject]@{property="result";value="UNCONFIRMED_FUTURE"})) {
        $mutant = $validFailureContainment | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
        $mutant.PSObject.Properties[$case.property].Value = $case.value
        $rejected = $false
        try {
            $null = Assert-MonitorFailureContainmentJsonContract `
                -Value $mutant `
                -ExpectedMonotonicFrequency ([long][Diagnostics.Stopwatch]::Frequency)
        }
        catch { $rejected = $true }
        Assert-True $rejected "Failure containment type/semantic mutant was accepted: $($case.property)"
        $failureContainmentMutantsRejected++
    }
    $failureContainmentCompact = [Text.UTF8Encoding]::new($false).GetBytes(
        ($validFailureContainment | ConvertTo-Json -Depth 100 -Compress))
    $failureContainmentDigest = Get-RawQualificationSha256Bytes -Bytes $failureContainmentCompact
    $terminalArtifactNames = @(
        "campaign_executable_sha256", "capture_executable_sha256", "campaign_verifier_executable_sha256",
        "public_config_sha256", "source_lock_sha256", "launcher_script_sha256", "monitor_script_sha256",
        "helper_script_sha256", "telemetry_probe_script_sha256", "watchdog_script_sha256",
        "python_runtime_fingerprint_script_sha256", "powershell_executable_sha256",
        "python_executable_sha256", "python_verifier_source_tree_sha256", "python_runtime_tree_sha256",
        "python_pyvenv_config_sha256", "python_base_executable_sha256", "python_project_sha256",
        "python_requirements_sha256")
    $nullPreflightArtifacts = [ordered]@{}
    $nullTerminalArtifacts = [ordered]@{}
    foreach ($artifactName in $terminalArtifactNames) {
        $nullPreflightArtifacts[$artifactName] = $null
        $nullTerminalArtifacts[$artifactName] = $null
        if ($artifactName -ceq "watchdog_script_sha256") {
            $nullTerminalArtifacts["watchdog_ready_file_sha256"] = $null
        }
    }
    $failedTerminalV2Contract = [pscustomobject][ordered]@{
        schema = "RawQualificationLauncherTerminalV2"
        status = "FAILED"
        failure = "selftest failure"
        failure_containment = $validFailureContainment
        failure_containment_sha256 = $failureContainmentDigest
        run_id = "selftest"
        mode = "Test"
        run_root = "C:\selftest"
        finished_utc = "2026-08-24T00:00:00.0000000Z"
        launcher_elapsed_ms = [uint64]1
        capture_elapsed_ms = [uint64]1
        parameters = [pscustomobject]@{ total_s=[uint64]100; rotation_s=[uint64]90; overlap_s=[uint64]5; segment_s=[uint64]5 }
        verifier_policy = [pscustomobject]@{ per_process_timeout_s=[uint64]7200; total_post_capture_timeout_s=[uint64]14400; maximum_artifact_bytes=[uint64](32MB) }
        coordinator_log_policy = [pscustomobject]@{ maximum_stdout_bytes=[uint64](64MB); maximum_stderr_bytes=[uint64]0; child_stderr_events_allowed=[uint64]0 }
        market_freshness_policy = [pscustomobject]@{ startup_grace_s=[uint64]30; deadline_s=[uint64]30 }
        guardian_policy = [pscustomobject][ordered]@{
            pulse_file = "guardian-pulse.jsonl"
            watchdog_ready_file = "watchdog-ready.json"
            watchdog_startup_deadline_s = [uint64]90
            watchdog_deadline_s = [uint64]90
            host_telemetry_gap_deadline_s = [uint64]120
            maximum_dual_launch_skew_ms = [uint64]5000
            generation_terminal_deadline_s = [uint64]120
            campaign_commit_deadline_s = [uint64]1800
        }
        startup_sha256 = $validDigest
        process_control_sha256 = $validDigest
        campaign_bindings_sha256 = $validDigest
        launcher_events = [pscustomobject]@{ file="launcher-events.jsonl"; records=[uint64]8; terminal_record_sha256=('2' * 64); file_bytes=[uint64]100; file_sha256=$validDigest }
        host_telemetry = $null
        guardian_pulse = $null
        artifact_hashes_preflight = [pscustomobject]$nullPreflightArtifacts
        artifact_hashes_terminal = [pscustomobject]$nullTerminalArtifacts
        watchdog = $null
        campaigns = @()
        credentials = "NONE"
        order_entry = "ABSENT"
    }
    $null = Assert-MonitorTerminalV2JsonContract `
        -Terminal $failedTerminalV2Contract `
        -ExpectedMonotonicFrequency ([long][Diagnostics.Stopwatch]::Frequency)
    $terminalV2ContainmentMutantsRejected = [uint64]0
    foreach ($case in @("wrong_digest", "missing_object", "complete_with_containment")) {
        $mutant = $failedTerminalV2Contract | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
        if ($case -eq "wrong_digest") { $mutant.failure_containment_sha256 = 'f' * 64 }
        elseif ($case -eq "missing_object") { $mutant.failure_containment = $null }
        else { $mutant.status = "COMPLETE"; $mutant.failure = $null }
        $rejected = $false
        try {
            $null = Assert-MonitorTerminalV2JsonContract `
                -Terminal $mutant `
                -ExpectedMonotonicFrequency ([long][Diagnostics.Stopwatch]::Frequency)
        }
        catch { $rejected = $true }
        Assert-True $rejected "Terminal V2 containment mutant was accepted: $case"
        $terminalV2ContainmentMutantsRejected++
    }
    Assert-True ($monitorAst.Extent.Text.Contains('launcher_terminal_byte_authentication') -and
        $monitorAst.Extent.Text.Contains('EXACT_DURABLE_LAUNCHER_TERMINAL_POST_LINK') -and
        $monitorAst.Extent.Text.Contains('terminal_bytes') -and
        $monitorAst.Extent.Text.Contains('terminal_sha256')) "Monitor does not bind the exact durable terminal V2 post-link."
    Assert-True ($monitorAst.Extent.Text.Contains('sealed verifier report bytes differ from fresh exact writer output')) "Terminal report canonicality is not bound to fresh independent Rust/Python report bytes."
    $runtimeFrequencyFixture = [pscustomobject]@{
        monotonic_frequency = [long][Diagnostics.Stopwatch]::Frequency
    }
    Assert-True (Test-MonitorStartupMonotonicFrequency -Startup $runtimeFrequencyFixture) "Monitor rejected the exact host Stopwatch frequency."
    $runtimeFrequencyFixture.monotonic_frequency = [long]([Diagnostics.Stopwatch]::Frequency + 1)
    Assert-True (-not (Test-MonitorStartupMonotonicFrequency -Startup $runtimeFrequencyFixture)) "Monitor accepted a startup monotonic frequency different from this host runtime."
    $startupFrequencyTypeMutantsRejected = [uint64]0
    foreach ($replacement in @(
        [string][Diagnostics.Stopwatch]::Frequency,
        $false,
        [double][Diagnostics.Stopwatch]::Frequency)) {
        $runtimeFrequencyFixture.monotonic_frequency = $replacement
        Assert-True (-not (Test-MonitorStartupMonotonicFrequency -Startup $runtimeFrequencyFixture)) "Monitor accepted an untyped startup monotonic frequency: $($replacement.GetType().Name)"
        $startupFrequencyTypeMutantsRejected++
    }
    $runtimeFrequencyFixture.monotonic_frequency = [long][Diagnostics.Stopwatch]::Frequency
    $stageFixture = [pscustomobject]@{
        capture_draining = $null
        terminal_evaluation = $null
        independent_verification = $null
    }
    $noDeviations = [object[]]@()
    Assert-True ((Get-MonitorEventDrivenStage -TerminalComplete $false -ScheduleDeviationReasons $noDeviations -LauncherHistoryContract $stageFixture) -eq "CAPTURING") "Event-driven monitor stage did not begin at CAPTURING."
    $stageFixture.terminal_evaluation = [pscustomobject]@{ body = [pscustomobject]@{} }
    Assert-True ((Get-MonitorEventDrivenStage -TerminalComplete $false -ScheduleDeviationReasons $noDeviations -LauncherHistoryContract $stageFixture) -eq "CAPTURING") "Generation/terminal evidence advanced stage without durable DRAINING."
    $stageFixture.capture_draining = [pscustomobject]@{ body = [pscustomobject]@{} }
    Assert-True ((Get-MonitorEventDrivenStage -TerminalComplete $false -ScheduleDeviationReasons $noDeviations -LauncherHistoryContract $stageFixture) -eq "DRAINING") "Durable DRAINING did not drive the monitor stage."
    $stageFixture.independent_verification = [pscustomobject]@{ body = [pscustomobject]@{} }
    Assert-True ((Get-MonitorEventDrivenStage -TerminalComplete $false -ScheduleDeviationReasons $noDeviations -LauncherHistoryContract $stageFixture) -eq "VERIFYING") "Monitor advanced to VERIFYING from something other than its durable verification event."
    Assert-True ((Get-MonitorEventDrivenStage -TerminalComplete $false -ScheduleDeviationReasons ([object[]]@("schedule mutant")) -LauncherHistoryContract $stageFixture) -eq "DEVIATED") "Schedule deviation did not retain priority over nonterminal stages."
    Assert-True ((Get-MonitorEventDrivenStage -TerminalComplete $true -ScheduleDeviationReasons ([object[]]@("historical deviation")) -LauncherHistoryContract $stageFixture) -eq "COMPLETE") "A sealed terminal COMPLETE did not retain terminal-stage priority."
    $eventDrivenStageMatrixPassed = $true
    Assert-True (Test-MonitorVerifierExecutionBudget `
        -ActualTimeoutSeconds 3600 `
        -MaximumPerProcessTimeoutSeconds 7200 `
        -ElapsedMilliseconds 3600000) "A legitimate globally-reduced verifier timeout was rejected."
    Assert-True (-not (Test-MonitorVerifierExecutionBudget `
        -ActualTimeoutSeconds 3600 `
        -MaximumPerProcessTimeoutSeconds 7200 `
        -ElapsedMilliseconds 3600001)) "A reduced verifier execution beyond its own exact budget was accepted."
    Assert-True (Test-MonitorVerifierArtifactBounds -StdoutBytes (32MB) -StderrBytes 0 -ReportBytes (32MB) -MaximumArtifactBytes (32MB)) "Exact verifier artifact limit was rejected."
    Assert-True (-not (Test-MonitorVerifierArtifactBounds -StdoutBytes ((32MB) + 1) -StderrBytes 0 -ReportBytes 1 -MaximumArtifactBytes (32MB))) "Verifier stdout above the sealed policy was accepted."
    Assert-True (-not (Test-MonitorVerifierArtifactBounds -StdoutBytes 0 -StderrBytes 0 -ReportBytes ((32MB) + 1) -MaximumArtifactBytes (32MB))) "Verifier report above the sealed policy was accepted."
    $sequentialPidIdentities = @{}
    Assert-True (Add-MonitorSequentialProcessIdentity -Seen $sequentialPidIdentities -ProcessId 4242 -CreationTimeUtc "2026-08-24T00:00:00.0000000Z") "First verifier process identity was rejected."
    Assert-True (Add-MonitorSequentialProcessIdentity -Seen $sequentialPidIdentities -ProcessId 4242 -CreationTimeUtc "2026-08-24T00:00:01.0000000Z") "Legitimate sequential PID reuse with a distinct creation identity was rejected."
    Assert-True (-not (Add-MonitorSequentialProcessIdentity -Seen $sequentialPidIdentities -ProcessId 4242 -CreationTimeUtc "2026-08-24T00:00:01.0000000Z")) "Sequential PID reuse with the same creation identity was accepted."
    $pythonDigest = 'b' * 64
    $verifiedBindingEvent = [pscustomobject]@{ body = [pscustomobject]@{ payload = [pscustomobject]@{
        rust_report_sha256 = $validDigest
        python_report_sha256 = $pythonDigest
    } } }
    $verifiedBindingExecutions = @(
        [pscustomobject]@{ name = "btcusdt-rust"; report_sha256 = $validDigest },
        [pscustomobject]@{ name = "btcusdt-python"; report_sha256 = $pythonDigest })
    Assert-True (Test-MonitorCampaignVerifiedReportBinding -VerifiedEvent $verifiedBindingEvent -Verifiers $verifiedBindingExecutions) "Exact INDEPENDENT_CAMPAIGN_VERIFIED report binding was rejected."
    $verifiedBindingEvent.body.payload.rust_report_sha256 = $pythonDigest
    $verifiedBindingEvent.body.payload.python_report_sha256 = $validDigest
    Assert-True (-not (Test-MonitorCampaignVerifiedReportBinding -VerifiedEvent $verifiedBindingEvent -Verifiers $verifiedBindingExecutions)) "Swapped INDEPENDENT_CAMPAIGN_VERIFIED report hashes were accepted."
    $reusedPidHealth = @([pscustomobject]@{ running = $true; exact_identity = $false; clean_capture_exit_proven = $true })
    Assert-True (@($reusedPidHealth | Where-Object { $_.running -and $_.exact_identity }).Count -eq 0) "A foreign process reusing a cleanly exited coordinator PID extended the commit deadline."
    Assert-True ($monitorAst.Extent.Text.Contains('Where-Object { $_.running -and $_.exact_identity }')) "Terminal commit deadline still treats foreign PID reuse as the original coordinator."
    Assert-True ($monitorAst.Extent.Text.Contains('Final linearization barrier') -and
        $monitorAst.Extent.Text.Contains('$linearizedLauncherJournal = Get-VerifiedJournalSummary') -and
        $monitorAst.Extent.Text.Contains('-ExpectedPrefixRecords ([uint64]$snapshot.records)') -and
        $monitorAst.Extent.Text.Contains('-ExpectedPrefixTerminalRecordSha256 ([string]$snapshot.terminal_record_sha256)') -and
        $monitorAst.Extent.Text.Contains('-ExpectedPrefixFileSha256 ([string]$snapshot.file_sha256)') -and
        $monitorAst.Extent.Text.Contains('-CampaignStartup $snapshot.campaign_startup') -and
        $monitorAst.Extent.Text.Contains('coordinator identity changed before live monitor publication')) "Live monitor lacks its final journal/stdout/process TOCTOU publication barrier."
    Assert-True (-not $monitorAst.Extent.Text.Contains('campaign journal changed during the monitor scan; retry')) "Live monitor rejects normal campaign-journal append growth and can livelock."
    $reducedTimeoutFromExactBudgetTick = Get-MonitorExpectedVerifierTimeoutSeconds `
        -BudgetComputedTick ([uint64](1000 + 10800 * 1000)) `
        -VerificationStageTick 1000 `
        -MonotonicFrequency 1000 `
        -TotalPostCaptureTimeoutSeconds 14400 `
        -MaximumPerProcessTimeoutSeconds 7200
    Assert-True ($reducedTimeoutFromExactBudgetTick -eq 3600) "Exact global budget tick did not reconstruct the legitimate reduced oracle timeout."
    $validVerifierCausality = @{
        StartupOriginQpcTimestamp = [long]10000
        BudgetComputedMonotonicTick = [uint64]100
        StartEventMonotonicTick = [uint64]150
        CompletedEventMonotonicTick = [uint64]400
        ResumeQpcTimestamp = [long]10120
        ElapsedQpcTicks = [long]100
        ParentExitObservedQpcTimestamp = [long]10220
        DescendantDrainElapsedQpcTicks = [long]100
        PreviousCompletedAbsoluteQpcTimestamp = [long]10050
    }
    Assert-True (Test-MonitorVerifierExecutionCausality @validVerifierCausality) "Valid verifier budget/start/exit/drain QPC interval was rejected."
    $verifierQpcCausalityMutantsRejected = [uint64]0
    foreach ($verifierCase in @(
        [pscustomobject]@{ name="budget-after-resume"; property="BudgetComputedMonotonicTick"; value=[uint64]121 },
        [pscustomobject]@{ name="resume-after-start"; property="ResumeQpcTimestamp"; value=[long]10151 },
        [pscustomobject]@{ name="start-after-parent-exit"; property="StartEventMonotonicTick"; value=[uint64]221 },
        [pscustomobject]@{ name="parent-minus-resume-not-elapsed"; property="ElapsedQpcTicks"; value=[long]99 },
        [pscustomobject]@{ name="descendant-drain-after-complete"; property="DescendantDrainElapsedQpcTicks"; value=[long]181 },
        [pscustomobject]@{ name="next-budget-before-previous-complete"; property="PreviousCompletedAbsoluteQpcTimestamp"; value=[long]10101 },
        [pscustomobject]@{ name="next-resume-before-previous-complete"; property="PreviousCompletedAbsoluteQpcTimestamp"; value=[long]10121 },
        [pscustomobject]@{ name="resume-before-startup-origin"; property="ResumeQpcTimestamp"; value=[long]9999 },
        [pscustomobject]@{ name="absolute-event-overflow"; property="StartupOriginQpcTimestamp"; value=[long]::MaxValue })) {
        $arguments = @{} + $validVerifierCausality
        $arguments[$verifierCase.property] = $verifierCase.value
        Assert-True (-not (Test-MonitorVerifierExecutionCausality @arguments)) "Verifier QPC causality mutant was accepted: $($verifierCase.name)"
        $verifierQpcCausalityMutantsRejected++
    }
    foreach ($replacement in @("10120", $false, [double]10120)) {
        $arguments = @{} + $validVerifierCausality
        $arguments.ResumeQpcTimestamp = $replacement
        Assert-True (-not (Test-MonitorVerifierExecutionCausality @arguments)) "Verifier untyped QPC mutant was accepted: $($replacement.GetType().Name)"
        $verifierQpcCausalityMutantsRejected++
    }
    Assert-True ($verifierQpcCausalityMutantsRejected -eq 12) "Verifier QPC adversarial matrix is incomplete."

    $postCreateRunRoot = Join-Path $testRoot "post-create-proof"
    $postCreateProbeRoot = Join-Path $postCreateRunRoot "host-probes"
    $null = New-Item -ItemType Directory -Path $postCreateProbeRoot -Force -ErrorAction Stop
    $postCreateStdout = Join-Path $postCreateProbeRoot "post-create-volume.stdout.json"
    $postCreateStderr = Join-Path $postCreateProbeRoot "post-create-volume.stderr.log"
    $postCreatePayload = [ordered]@{
        schema = "RawQualificationTelemetryProbeV1"
        clock = [ordered]@{
            healthy = $true; leap_indicator = 0; stratum = 2; source = "time.nist.gov,0x8"
            last_successful_sync = "2026-08-24T00:00:00Z"; root_delay_s = [double]0.1
            root_dispersion_s = [double]0.2; phase_offset_s = [double]0.001
            seconds_since_last_good_sync = [double]1; maximum_last_good_sync_age_s = [uint64]21600
            state_machine = 2; last_sync_error = 0; poll_interval_s = [uint64]1024
            raw_status_sha256 = $validDigest; query_exit_code = 0
        }
        disk = [ordered]@{
            device_id = "C:"; filesystem = "NTFS"; size_bytes = [uint64](1TB)
            free_bytes = [uint64](200GB); avg_read_latency_s = [double]0.001
            avg_write_latency_s = [double]0.001; current_queue_length = [double]0
        }
        network = [ordered]@{
            received_bytes = [uint64]1; sent_bytes = [uint64]1
            received_packets = [uint64]1; sent_packets = [uint64]1
            received_discards = [uint64]0; outbound_discards = [uint64]0
            received_errors = [uint64]0; outbound_errors = [uint64]0
        }
        collector_processes = @([ordered]@{
            pid = [uint32]$PID; parent_pid = [uint32]0; name = "powershell.exe"
            creation_date = "20260824000000.000000-180"
            executable_path = (Join-Path $PSHOME "powershell.exe")
            cpu_kernel_100ns = [uint64]0; cpu_user_100ns = [uint64]0
            working_set_bytes = [uint64]1; page_file_kib = [uint64]0; handles = [uint64]1
            read_operations = [uint64]0; read_bytes = [uint64]0
            write_operations = [uint64]0; write_bytes = [uint64]0
        })
        conflicting_collectors = @()
        power = [ordered]@{ powercfg_exit_code = $null; ac_sleep_disabled = $null }
    }
    [IO.File]::WriteAllBytes(
        $postCreateStdout,
        [Text.UTF8Encoding]::new($false).GetBytes(
            (($postCreatePayload | ConvertTo-Json -Depth 100 -Compress) + "`r`n")))
    [IO.File]::WriteAllBytes($postCreateStderr, [byte[]]@())
    $postCreateStartup = [pscustomobject]@{
        launcher_pid = [uint32]$PID
        monotonic_frequency = [uint64]1000
        monotonic_origin_qpc_timestamp = [long]1
        preflight = [pscustomobject]@{
            powershell_executable = [string]$providerStartup.preflight.powershell_executable
            telemetry_probe_script = [string]$providerStartup.preflight.telemetry_probe_script
            helper_script = [string]$providerStartup.preflight.helper_script
            disk_telemetry_preflight = [pscustomobject]@{ size_bytes = [uint64](1TB) }
        }
    }
    $postCreateArguments = [string[]]@(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
        [string]$postCreateStartup.preflight.telemetry_probe_script,
        "-HelperPath", [string]$postCreateStartup.preflight.helper_script,
        "-DriveDeviceId", "C:",
        "-RootProcessId", ([uint32]$PID).ToString([Globalization.CultureInfo]::InvariantCulture))
    $postCreateCommandLine = [RawQualificationNative]::BuildExactCommandLine(
        [string]$postCreateStartup.preflight.powershell_executable,
        $postCreateArguments)
    $postCreateValidation = [pscustomobject]@{
        reparse_points_rejected = $true; same_preflight_volume = $true
        run_root_drive_device_id = "C:"; filesystem = "NTFS"
        free_gib = [uint64]200; required_free_gib = [uint64]100
        probe_timeout_s = [uint64]20; probe_elapsed_ms = [uint64]20000; probe_pid = [uint32]1201
        probe_resume_qpc_timestamp = [long]100
        probe_elapsed_qpc_ticks = [long]20000
        probe_monotonic_frequency = [long]1000
        probe_job_membership = "PRIMARY_AND_NESTED_BOUNDED"
        probe_parent_exit_observed_qpc_timestamp = [long]20100
        probe_descendant_drain_elapsed_qpc_ticks = [long]1
        probe_descendant_drain_elapsed_ms = [uint64]1
        probe_descendant_drain_active_processes = [uint32]0
        probe_command_line_sha256 = Get-RawQualificationSha256Bytes -Bytes ([Text.UTF8Encoding]::new($false).GetBytes($postCreateCommandLine))
        probe_stdout_file = "post-create-volume.stdout.json"
        probe_stdout_bytes = [uint64](Get-Item -LiteralPath $postCreateStdout).Length
        probe_stdout_sha256 = Get-RawQualificationSha256File -Path $postCreateStdout
        probe_stderr_file = "post-create-volume.stderr.log"
        probe_stderr_bytes = [uint64]0
        probe_stderr_sha256 = Get-RawQualificationSha256File -Path $postCreateStderr
    }
    Assert-True (Assert-PostCreateProbeEvidence -Startup $postCreateStartup -OutputPathValidation $postCreateValidation -ResolvedRunRoot $postCreateRunRoot) "Valid post-create probe proof was rejected."
    $postCreateValidation.probe_elapsed_qpc_ticks = [long]20001
    $postCreateValidation.probe_elapsed_ms = [uint64]20001
    $latePostCreateProbeRejected = $false
    try { $null = Assert-PostCreateProbeEvidence -Startup $postCreateStartup -OutputPathValidation $postCreateValidation -ResolvedRunRoot $postCreateRunRoot }
    catch { $latePostCreateProbeRejected = $true }
    Assert-True $latePostCreateProbeRejected "Post-create probe deadline-plus-one was accepted."
    $postCreateValidation.probe_elapsed_qpc_ticks = [long]20000
    $postCreateValidation.probe_elapsed_ms = [uint64]20000
    $savedProbeArtifactLimit = $ExpectedHostProbeMaximumArtifactBytes
    $ExpectedHostProbeMaximumArtifactBytes = [uint64]($postCreateValidation.probe_stdout_bytes - 1)
    $oversizePostCreateProbeRejected = $false
    try { $null = Assert-PostCreateProbeEvidence -Startup $postCreateStartup -OutputPathValidation $postCreateValidation -ResolvedRunRoot $postCreateRunRoot }
    catch { $oversizePostCreateProbeRejected = $true }
    finally { $ExpectedHostProbeMaximumArtifactBytes = $savedProbeArtifactLimit }
    Assert-True $oversizePostCreateProbeRejected "Post-create probe above its exact artifact limit was accepted."
    $postCreateQpcCausalityMutantsRejected = [uint64]0
    foreach ($postCreateCase in @("resume-before-origin", "parent-elapsed-mismatch")) {
        $postCreateMutant = ($postCreateValidation | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json)
        $postCreateStartupMutant = ($postCreateStartup | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json)
        if ($postCreateCase -eq "resume-before-origin") {
            $postCreateStartupMutant.monotonic_origin_qpc_timestamp = [long]101
        }
        else {
            $postCreateMutant.probe_parent_exit_observed_qpc_timestamp = [long]20101
        }
        $rejected = $false
        try { $null = Assert-PostCreateProbeEvidence -Startup $postCreateStartupMutant -OutputPathValidation $postCreateMutant -ResolvedRunRoot $postCreateRunRoot }
        catch { $rejected = $true }
        Assert-True $rejected "Post-create QPC causality mutant was accepted: $postCreateCase"
        $postCreateQpcCausalityMutantsRejected++
    }
    foreach ($replacement in @("20000", $false, [double]20000)) {
        $postCreateMutant = ($postCreateValidation | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json)
        $postCreateMutant.probe_elapsed_qpc_ticks = $replacement
        $rejected = $false
        try { $null = Assert-PostCreateProbeEvidence -Startup $postCreateStartup -OutputPathValidation $postCreateMutant -ResolvedRunRoot $postCreateRunRoot }
        catch { $rejected = $true }
        Assert-True $rejected "Post-create untyped QPC mutant was accepted: $($replacement.GetType().Name)"
        $postCreateQpcCausalityMutantsRejected++
    }
    Assert-True (Test-MonitorBoundedExecutionCausality 1 30000 100 20000 20100 1) "Valid post-create containing-event QPC interval was rejected."
    Assert-True (-not (Test-MonitorBoundedExecutionCausality 1 20099 100 20000 20100 1)) "Post-create execution ending after PREFLIGHT was accepted."
    $postCreateQpcCausalityMutantsRejected++
    Assert-True ($postCreateQpcCausalityMutantsRejected -eq 6) "Post-create QPC adversarial matrix is incomplete."
    $postCreatePayloadTyped = $postCreatePayload | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
    $null = Assert-MonitorTelemetryProbePayloadJsonTypes `
        -Value $postCreatePayloadTyped `
        -ExpectedRootProcessId ([uint32]$PID)
    $postCreateRecursiveMutantsRejected = [uint64]0
    foreach ($case in @(
            [pscustomobject]@{path="clock.healthy";value="true"},
            [pscustomobject]@{path="disk.queue";value=[double]::PositiveInfinity},
            [pscustomobject]@{path="network.errors";value="0"},
            [pscustomobject]@{path="collector.pid";value=$true},
            [pscustomobject]@{path="power.exit";value=0},
            [pscustomobject]@{path="conflict";value="unexpected.exe"})) {
        $mutant = $postCreatePayloadTyped | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
        switch ($case.path) {
            "clock.healthy" { $mutant.clock.healthy = $case.value }
            "disk.queue" { $mutant.disk.current_queue_length = $case.value }
            "network.errors" { $mutant.network.received_errors = $case.value }
            "collector.pid" { $mutant.collector_processes[0].pid = $case.value }
            "power.exit" { $mutant.power.powercfg_exit_code = $case.value }
            "conflict" { $mutant.conflicting_collectors = @($case.value) }
        }
        $rejected = $false
        try {
            $null = Assert-MonitorTelemetryProbePayloadJsonTypes `
                -Value $mutant `
                -ExpectedRootProcessId ([uint32]$PID)
        }
        catch { $rejected = $true }
        Assert-True $rejected "Post-create recursive type/semantic mutant was accepted: $($case.path)"
        $postCreateRecursiveMutantsRejected++
    }
    $postCreatePayload.disk.device_id = "Z:"
    [IO.File]::WriteAllBytes(
        $postCreateStdout,
        [Text.UTF8Encoding]::new($false).GetBytes(
            (($postCreatePayload | ConvertTo-Json -Depth 100 -Compress) + "`r`n")))
    $postCreateValidation.probe_stdout_bytes = [uint64](Get-Item -LiteralPath $postCreateStdout).Length
    $postCreateValidation.probe_stdout_sha256 = Get-RawQualificationSha256File -Path $postCreateStdout
    $payloadMismatchPostCreateProbeRejected = $false
    try { $null = Assert-PostCreateProbeEvidence -Startup $postCreateStartup -OutputPathValidation $postCreateValidation -ResolvedRunRoot $postCreateRunRoot }
    catch { $payloadMismatchPostCreateProbeRejected = $true }
    Assert-True $payloadMismatchPostCreateProbeRejected "A coherently re-sealed post-create payload for the wrong volume was accepted."

    $historyRunId = "history-run"
    $historyOuterJobName = "Local\BinanceRawQualificationJob-$historyRunId"
    $historyWorkloadJobName = "Local\BinanceRawQualificationWorkloadJob-$historyRunId"
    $historyStartup = [pscustomobject]@{
        run_id = $historyRunId
        launcher_pid = [uint32]$PID
        monotonic_frequency = [uint64]1000
        monotonic_origin_qpc_timestamp = [long]10000
        parameters = [pscustomobject]@{
            total_s = [uint64]100; rotation_s = [uint64]90; overlap_s = [uint64]5; segment_s = [uint64]5 }
        guardian_policy = [pscustomobject]@{
            watchdog_startup_deadline_s = [uint64]90
            watchdog_deadline_s = [uint64]90
            host_telemetry_gap_deadline_s = [uint64]120
            maximum_dual_launch_skew_ms = [uint64]5000
            generation_terminal_deadline_s = [uint64]120
            campaign_commit_deadline_s = [uint64]1800
        }
        verifier_policy = [pscustomobject]@{
            total_post_capture_timeout_s = [uint64]14400; per_process_timeout_s = [uint64]7200 }
        preflight = [pscustomobject]@{
            powershell_executable = [string]$providerStartup.preflight.powershell_executable
            telemetry_probe_script = [string]$providerStartup.preflight.telemetry_probe_script
            helper_script = [string]$providerStartup.preflight.helper_script
            drive_device_id = "C:"
            projection_combined_raw_gib_per_hour = [double]0
            projection_safety_multiplier = [double]2
            projected_remaining_gib_at_start = [uint64]0
            persistent_reserve_gib = [uint64]100
            disk_telemetry_preflight = [pscustomobject]@{ size_bytes = [uint64](1TB) }
        }
    }
    $historyControl = [pscustomobject]@{
        capture_origin_monotonic_tick = [uint64]1000
        job_kill_on_close = $true
        job_object_name = $historyOuterJobName
        workload_job_kill_on_close = $true
        workload_job_object_name = $historyWorkloadJobName
        watchdog = [pscustomobject]@{
            pid = [uint32]9001
            ready_file_sha256 = $validDigest
            launch_origin_qpc_timestamp = [long]10010
            resume_qpc_timestamp = [long]10020
            ready_observed_qpc_timestamp = [long]10030
            ready_pulse_length = [uint64]1
        }
        processes = @(
            [pscustomobject]@{ symbol = "BTCUSDT"; pid = [uint32]1001; launch_monotonic_tick = [uint64]1000 },
            [pscustomobject]@{ symbol = "ETHUSDT"; pid = [uint32]1002; launch_monotonic_tick = [uint64]1001 })
    }
    $newHistoryEnvelope = {
        param([uint64] $Index, [uint64] $Tick, [string] $Channel, $Payload)
        return [pscustomobject]@{
            body = [pscustomobject]@{
                record_index = $Index
                monotonic_tick = $Tick
                wall_ns = [uint64](1000000000 + $Index)
                channel = $Channel
                payload = $Payload
            }
        }
    }
    $guardianStarting = & $newHistoryEnvelope 0 100 "GUARDIAN" ([pscustomobject]@{
        event = "GUARDIAN_PULSE"; stage = "STARTING"; launcher_elapsed_ms = [uint64]100; capture_elapsed_ms = $null })
    $guardianHealthy = & $newHistoryEnvelope 1 2000 "GUARDIAN" ([pscustomobject]@{
        event = "GUARDIAN_PULSE"; stage = "CAPTURING"; launcher_elapsed_ms = [uint64]2000; capture_elapsed_ms = [uint64]1000 })
    $guardianHistory = [pscustomobject]@{ records = [uint64]2; all_records = @($guardianStarting, $guardianHealthy) }
    $guardianStarting.body.payload.stage = "UNKNOWN_OLD_STAGE"
    $oldGuardianFailureRejected = $false
    try { $null = Assert-GuardianPulseHistory -Journal $guardianHistory -Startup $historyStartup -Control $historyControl }
    catch { $oldGuardianFailureRejected = $true }
    Assert-True $oldGuardianFailureRejected "A later healthy guardian pulse hid an earlier invalid stage."
    $guardianStarting.body.payload.stage = "STARTING"
    Assert-True (Assert-GuardianPulseHistory -Journal $guardianHistory -Startup $historyStartup -Control $historyControl) "Valid complete guardian pulse history was rejected."
    $guardianDraining = & $newHistoryEnvelope 2 3000 "GUARDIAN" ([pscustomobject]@{
        event = "GUARDIAN_PULSE"; stage = "DRAINING"; launcher_elapsed_ms = [uint64]3000; capture_elapsed_ms = [uint64]2000 })
    $guardianRegressedCapture = & $newHistoryEnvelope 3 4000 "GUARDIAN" ([pscustomobject]@{
        event = "GUARDIAN_PULSE"; stage = "CAPTURING"; launcher_elapsed_ms = [uint64]4000; capture_elapsed_ms = [uint64]3000 })
    $guardianStageRegressionRejected = $false
    try {
        $null = Assert-GuardianPulseHistory `
            -Journal ([pscustomobject]@{ records = [uint64]4; all_records = @(
                $guardianStarting, $guardianHealthy, $guardianDraining, $guardianRegressedCapture) }) `
            -Startup $historyStartup `
            -Control $historyControl
    }
    catch { $guardianStageRegressionRejected = $true }
    Assert-True $guardianStageRegressionRejected "Guardian CAPTURING -> DRAINING -> CAPTURING stage regression was accepted."
    $guardianLateAfterGap = & $newHistoryEnvelope 2 93001 "GUARDIAN" ([pscustomobject]@{
        event = "GUARDIAN_PULSE"; stage = "CAPTURING"; launcher_elapsed_ms = [uint64]93001; capture_elapsed_ms = [uint64]92001 })
    $guardianHealthyAfterGap = & $newHistoryEnvelope 3 94001 "GUARDIAN" ([pscustomobject]@{
        event = "GUARDIAN_PULSE"; stage = "CAPTURING"; launcher_elapsed_ms = [uint64]94001; capture_elapsed_ms = [uint64]93001 })
    $guardianGapHistory = [pscustomobject]@{
        records = [uint64]4
        all_records = @($guardianStarting, $guardianHealthy, $guardianLateAfterGap, $guardianHealthyAfterGap)
    }
    $historicalGuardianGapRejected = $false
    try { $null = Assert-GuardianPulseHistory -Journal $guardianGapHistory -Startup $historyStartup -Control $historyControl }
    catch { $historicalGuardianGapRejected = $true }
    Assert-True $historicalGuardianGapRejected "A later healthy guardian pulse hid an earlier >90s monotonic gap."

    $healthyClock = [pscustomobject]@{
        healthy = $true
        leap_indicator = 0
        stratum = 2
        source = "time.nist.gov,0x8"
        last_successful_sync = "2026-08-24T00:00:00Z"
        root_delay_s = [double]0.1
        root_dispersion_s = [double]0.2
        phase_offset_s = [double]0.001
        seconds_since_last_good_sync = [double]30
        maximum_last_good_sync_age_s = [uint64]21600
        state_machine = 2
        last_sync_error = 0
        poll_interval_s = [uint64]1024
        raw_status_sha256 = $validDigest
        query_exit_code = 0
    }
    $newCampaignSummary = {
        param([string] $Symbol, [uint32] $ProcessId, [uint64] $Elapsed)
        return [pscustomobject]@{
            symbol = $Symbol; pid = $ProcessId; campaign_id = $null; campaign_elapsed_s = $Elapsed
            generations = [uint64]0; active_processes = [uint64]1; handovers_proven = [uint64]0
            depth_received = [uint64]0; depth_durable = [uint64]0
            trade_received = [uint64]0; trade_durable = [uint64]0
            latest_generation_index = $null; latest_telemetry_mono_ns = $null
            depth_last_socket_activity_mono_ns = $null; depth_last_market_message_mono_ns = $null
            depth_market_message_age_ms = $null
            trade_last_socket_activity_mono_ns = $null; trade_last_market_message_mono_ns = $null
            trade_market_message_age_ms = $null
            ready = $false; exited = $false
        }
    }
    $newProviderExecution = {
        param([uint32] $ProcessId, [long] $ResumeQpcTimestamp)
        return [pscustomobject]@{
            pid = $ProcessId; timeout_s = [uint64]20; elapsed_ms = [uint64]1
            resume_qpc_timestamp = $ResumeQpcTimestamp
            elapsed_qpc_ticks = [long]1
            monotonic_frequency = [long]1000
            job_membership = "PRIMARY_AND_NESTED_BOUNDED"
            parent_exit_observed_qpc_timestamp = [long]($ResumeQpcTimestamp + 1)
            descendant_drain_elapsed_qpc_ticks = [long]1
            descendant_drain_elapsed_ms = [uint64]1
            descendant_drain_active_processes = [uint32]0
            stdout_bytes = [uint64]1; stdout_sha256 = $validDigest
            stderr_bytes = [uint64]0; stderr_sha256 = $validDigest
            command_line_sha256 = $providerCommandDigest
        }
    }
    $newHostPayload = {
        param(
            [uint64] $CaptureElapsedMs, [uint64] $LauncherElapsedMs,
            [uint64] $CampaignElapsed, [uint32] $ProviderPid,
            [long] $ProviderResumeQpcTimestamp)
        return [pscustomobject]@{
            monotonic_frequency = [uint64]1000
            launcher_elapsed_ms = $LauncherElapsedMs
            capture_elapsed_ms = $CaptureElapsedMs
            clock = $healthyClock.PSObject.Copy()
            disk = [pscustomobject]@{
                device_id = "C:"; filesystem = "NTFS"; size_bytes = [uint64](1TB); free_bytes = [uint64](200GB)
                avg_read_latency_s = [double]0.001; avg_write_latency_s = [double]0.001
                current_queue_length = [double]0
            }
            disk_persistent_reserve_gib = [uint64]100
            disk_projected_remaining_gib = [uint64]0
            disk_required_free_gib = [uint64]100
            network = [pscustomobject]@{
                received_bytes = [uint64]1; sent_bytes = [uint64]1
                received_packets = [uint64]1; sent_packets = [uint64]1
                received_discards = [uint64]0; outbound_discards = [uint64]0
                received_errors = [uint64]0; outbound_errors = [uint64]0
            }
            collector_processes = @([pscustomobject]@{
                pid = [uint32]$PID; parent_pid = [uint32]0; name = "powershell.exe"
                creation_date = "20260824000000.000000-180"
                executable_path = (Join-Path $PSHOME "powershell.exe")
                cpu_kernel_100ns = [uint64]0; cpu_user_100ns = [uint64]0
                working_set_bytes = [uint64]1; page_file_kib = [uint64]0; handles = [uint64]1
                read_operations = [uint64]0; read_bytes = [uint64]0
                write_operations = [uint64]0; write_bytes = [uint64]0
            })
            provider_execution = & $newProviderExecution $ProviderPid $ProviderResumeQpcTimestamp
            campaigns = @(
                (& $newCampaignSummary "BTCUSDT" 1001 $CampaignElapsed),
                (& $newCampaignSummary "ETHUSDT" 1002 $CampaignElapsed))
        }
    }
    $validHostPayload = & $newHostPayload 1000 2000 1 1101 11000
    $null = Assert-MonitorHostTelemetryPayloadJsonTypes -Payload $validHostPayload
    $hostRecursiveMutantsRejected = [uint64]0
    foreach ($case in @(
            [pscustomobject]@{path="clock.healthy";value="true"},
            [pscustomobject]@{path="clock.root_delay_s";value=[double]::NaN},
            [pscustomobject]@{path="disk.free_bytes";value="1"},
            [pscustomobject]@{path="network.received_bytes";value=$false},
            [pscustomobject]@{path="collector.pid";value=[double]1},
            [pscustomobject]@{path="campaign.ready";value=1},
            [pscustomobject]@{path="campaign.age";value="0"},
            [pscustomobject]@{path="provider.timeout";value="20"})) {
        $mutant = $validHostPayload | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
        switch ($case.path) {
            "clock.healthy" { $mutant.clock.healthy = $case.value }
            "clock.root_delay_s" { $mutant.clock.root_delay_s = $case.value }
            "disk.free_bytes" { $mutant.disk.free_bytes = $case.value }
            "network.received_bytes" { $mutant.network.received_bytes = $case.value }
            "collector.pid" { $mutant.collector_processes[0].pid = $case.value }
            "campaign.ready" { $mutant.campaigns[0].ready = $case.value }
            "campaign.age" { $mutant.campaigns[0].depth_market_message_age_ms = $case.value }
            "provider.timeout" { $mutant.provider_execution.timeout_s = $case.value }
        }
        $rejected = $false
        try { $null = Assert-MonitorHostTelemetryPayloadJsonTypes -Payload $mutant }
        catch { $rejected = $true }
        Assert-True $rejected "Recursive host telemetry coercion/non-finite mutant was accepted: $($case.path)"
        $hostRecursiveMutantsRejected++
    }
    $hostOld = & $newHistoryEnvelope 0 2000 "HOST" (& $newHostPayload 1000 2000 1 1101 11000)
    $hostLatest = & $newHistoryEnvelope 1 3000 "HOST" (& $newHostPayload 2000 3000 2 1102 12000)
    $hostHistory = [pscustomobject]@{
        records = [uint64]2
        all_records = @($hostOld, $hostLatest)
        provider_executions = @($hostOld.body.payload.provider_execution, $hostLatest.body.payload.provider_execution)
    }
    $hostOld.body.payload.clock.healthy = $false
    $oldClockFailureRejected = $false
    try {
        $null = Assert-HostTelemetryHistory -Journal $hostHistory -Startup $historyStartup -Control $historyControl -ExpectedProviderTimeoutSeconds 20 -MaximumProviderArtifactBytes 1024
    }
    catch { $oldClockFailureRejected = $true }
    Assert-True $oldClockFailureRejected "A later healthy host record hid an earlier unhealthy clock."
    $hostOld.body.payload.clock.healthy = $true
    $hostOld.body.payload.disk.free_bytes = [uint64](99GB)
    $oldDiskFailureRejected = $false
    try {
        $null = Assert-HostTelemetryHistory -Journal $hostHistory -Startup $historyStartup -Control $historyControl -ExpectedProviderTimeoutSeconds 20 -MaximumProviderArtifactBytes 1024
    }
    catch { $oldDiskFailureRejected = $true }
    Assert-True $oldDiskFailureRejected "A later healthy host record hid an earlier disk-reserve violation."
    $hostOld.body.payload.disk.free_bytes = [uint64](200GB)
    Assert-True (Assert-HostTelemetryHistory -Journal $hostHistory -Startup $historyStartup -Control $historyControl -ExpectedProviderTimeoutSeconds 20 -MaximumProviderArtifactBytes 1024) "Valid complete host telemetry history was rejected."
    $hostLateAfterGap = & $newHistoryEnvelope 2 124001 "HOST" (& $newHostPayload 123001 124001 123 1103 13000)
    $hostHealthyAfterGap = & $newHistoryEnvelope 3 125001 "HOST" (& $newHostPayload 124001 125001 124 1104 134001)
    $hostGapHistory = [pscustomobject]@{
        records = [uint64]4
        all_records = @($hostOld, $hostLatest, $hostLateAfterGap, $hostHealthyAfterGap)
        provider_executions = @(
            $hostOld.body.payload.provider_execution,
            $hostLatest.body.payload.provider_execution,
            $hostLateAfterGap.body.payload.provider_execution,
            $hostHealthyAfterGap.body.payload.provider_execution)
    }
    $historicalHostGapRejected = $false
    try {
        $null = Assert-HostTelemetryHistory -Journal $hostGapHistory -Startup $historyStartup -Control $historyControl -ExpectedProviderTimeoutSeconds 20 -MaximumProviderArtifactBytes 1024
    }
    catch { $historicalHostGapRejected = $true }
    Assert-True $historicalHostGapRejected "A later healthy host sample hid an earlier >120s monotonic gap."

    $newReadinessReceiptFixture = {
        $bindings = [pscustomobject]@{
            schema = "RawQualificationCampaignBindingsV1"
            campaigns = @(
                [pscustomobject]@{ symbol = "BTCUSDT"; pid = [uint32]1001; campaign_id = "btc-ready" },
                [pscustomobject]@{ symbol = "ETHUSDT"; pid = [uint32]1002; campaign_id = "eth-ready" })
        }
        $hostRecord = [pscustomobject]@{
            body = [pscustomobject]@{
                schema = "RawQualificationHostTelemetryRecordV1"
                record_index = [uint64]0
                monotonic_tick = [uint64]1150
                channel = "HOST"
                payload = [pscustomobject]@{
                    campaigns = @(
                        [pscustomobject]@{
                            symbol = "BTCUSDT"; pid = [uint32]1001; campaign_id = "btc-ready"
                            ready = $true; exited = $false; generations = [uint64]1; active_processes = [uint64]1
                        },
                        [pscustomobject]@{
                            symbol = "ETHUSDT"; pid = [uint32]1002; campaign_id = "eth-ready"
                            ready = $true; exited = $false; generations = [uint64]1; active_processes = [uint64]1
                        })
                }
            }
            record_sha256 = $validDigest
        }
        $receipt = [pscustomobject]@{
            body = [pscustomobject]@{
                payload = [pscustomobject]@{
                    event = "DUAL_READINESS_PUBLISHED"
                    bindings_sha256 = $validDigest
                    host_telemetry_record_index = [uint64]0
                    host_telemetry_record_sha256 = $validDigest
                    host_telemetry_monotonic_tick = [uint64]1150
                }
            }
        }
        return [pscustomobject]@{
            receipt = $receipt
            telemetry = [pscustomobject]@{ records = [uint64]1; all_records = @($hostRecord) }
            bindings = $bindings
        }
    }
    $validReadinessReceipt = & $newReadinessReceiptFixture
    Assert-True (Assert-DualReadinessReceipt `
        -Receipt $validReadinessReceipt.receipt `
        -TelemetryJournal $validReadinessReceipt.telemetry `
        -Bindings $validReadinessReceipt.bindings `
        -ExpectedBindingsSha256 $validDigest) "Exact cross-journal dual-readiness receipt was rejected."

    $readinessReceiptMutantCases = [ordered]@{
        swapped_identity = {
            param($fixture)
            $fixture.telemetry.all_records[0].body.payload.campaigns[0].pid = [uint32]1002
        }
        wrong_hash = {
            param($fixture)
            $fixture.receipt.body.payload.host_telemetry_record_sha256 = ('e' * 64)
        }
        wrong_tick = {
            param($fixture)
            $fixture.receipt.body.payload.host_telemetry_monotonic_tick = [uint64]1151
        }
        wrong_record = {
            param($fixture)
            $fixture.receipt.body.payload.host_telemetry_record_index = [uint64]1
        }
        ready_false = {
            param($fixture)
            $fixture.telemetry.all_records[0].body.payload.campaigns[0].ready = $false
        }
        exited_true = {
            param($fixture)
            $fixture.telemetry.all_records[0].body.payload.campaigns[0].exited = $true
        }
        generations_zero = {
            param($fixture)
            $fixture.telemetry.all_records[0].body.payload.campaigns[0].generations = [uint64]0
        }
        active_zero = {
            param($fixture)
            $fixture.telemetry.all_records[0].body.payload.campaigns[0].active_processes = [uint64]0
        }
    }
    $readinessReceiptMutantsRejected = [ordered]@{}
    foreach ($mutantName in $readinessReceiptMutantCases.Keys) {
        $fixture = & $newReadinessReceiptFixture
        & $readinessReceiptMutantCases[$mutantName] $fixture
        $rejected = $false
        try {
            $null = Assert-DualReadinessReceipt `
                -Receipt $fixture.receipt `
                -TelemetryJournal $fixture.telemetry `
                -Bindings $fixture.bindings `
                -ExpectedBindingsSha256 $validDigest
        }
        catch { $rejected = $true }
        Assert-True $rejected "Dual-readiness cross-journal mutant was accepted: $mutantName"
        $readinessReceiptMutantsRejected[$mutantName] = $rejected
    }

    $launcherBaseRecords = @(
        (& $newHistoryEnvelope 0 10 "LAUNCHER" ([pscustomobject]@{ event = "PREFLIGHT_PASSED"; startup_sha256 = $validDigest })),
        (& $newHistoryEnvelope 1 20 "CONTROL" ([pscustomobject]@{
            event = "JOB_OBJECT_ARMED"; name = $historyOuterJobName; kill_on_close = $true
            workload_name = $historyWorkloadJobName; workload_kill_on_close = $true })),
        (& $newHistoryEnvelope 2 30 "CONTROL" ([pscustomobject]@{
            event = "GUARDIAN_WATCHDOG_STARTED"; pid = [uint32]9001; ready_file_sha256 = $validDigest
            launch_origin_qpc_timestamp = [long]10010; resume_qpc_timestamp = [long]10020
            ready_observed_qpc_timestamp = [long]10030; ready_pulse_length = [uint64]1
            startup_deadline_s = [uint64]90; deadline_s = [uint64]90 })),
        (& $newHistoryEnvelope 3 40 "CONTROL" ([pscustomobject]@{ event = "DUAL_CAMPAIGN_STARTED"; process_control_sha256 = $validDigest })))
    $launcherHistory = [pscustomobject]@{
        records = [uint64]4; all_records = $launcherBaseRecords
        startup_binding_sha256 = $validDigest; process_control_binding_sha256 = $validDigest; campaign_bindings_sha256 = $null
    }
    $liveLauncherContract = Assert-LauncherEventHistory -Journal $launcherHistory -Startup $historyStartup -Control $historyControl -TerminalComplete $false -SkipSingletonValidation
    Assert-True ($null -ne $liveLauncherContract.preflight -and
        [string]$liveLauncherContract.preflight.body.payload.event -ceq "PREFLIGHT_PASSED") `
        "Live launcher-history contract omitted its causal PREFLIGHT_PASSED record."
    $duplicatePreflight = & $newHistoryEnvelope 4 50 "LAUNCHER" ([pscustomobject]@{ event = "PREFLIGHT_PASSED"; startup_sha256 = $validDigest })
    $duplicateLauncherHistory = [pscustomobject]@{
        records = [uint64]5; all_records = @($launcherBaseRecords + @($duplicatePreflight))
        startup_binding_sha256 = $validDigest; process_control_binding_sha256 = $validDigest; campaign_bindings_sha256 = $null
    }
    $oldDuplicateBindingRejected = $false
    try { $null = Assert-LauncherEventHistory -Journal $duplicateLauncherHistory -Startup $historyStartup -Control $historyControl -TerminalComplete $false -SkipSingletonValidation }
    catch { $oldDuplicateBindingRejected = $true }
    Assert-True $oldDuplicateBindingRejected "A later launcher record hid a duplicate historical binding."
    $oldFailureRecord = & $newHistoryEnvelope 4 50 "FAILURE" ([pscustomobject]@{ event = "LAUNCHER_FAILED"; error = "mutant" })
    $failedLauncherHistory = [pscustomobject]@{
        records = [uint64]5; all_records = @($launcherBaseRecords + @($oldFailureRecord))
        startup_binding_sha256 = $validDigest; process_control_binding_sha256 = $validDigest; campaign_bindings_sha256 = $null
    }
    $oldLauncherFailureRejected = $false
    try { $null = Assert-LauncherEventHistory -Journal $failedLauncherHistory -Startup $historyStartup -Control $historyControl -TerminalComplete $false -SkipSingletonValidation }
    catch { $oldLauncherFailureRejected = $true }
    Assert-True $oldLauncherFailureRejected "A later launcher state hid a historical LAUNCHER_FAILED event."

    $newTerminalLauncherHistory = {
        param([ValidateSet(
            "PRE_EVALUATION", "PRE_EVALUATION_REVERSED",
            "INTERLEAVED", "INTERLEAVED_REVERSED",
            "POST_EVALUATION_EXACT", "POST_EVALUATION_EXACT_REVERSED",
            "POST_EVALUATION_LATE")] [string] $ExitOrder)
        $specs = [Collections.Generic.List[object]]::new()
        $addSpec = {
            param([uint64] $Tick, [string] $Channel, $Payload)
            $specs.Add([pscustomobject]@{ tick = $Tick; channel = $Channel; payload = $Payload })
        }
        & $addSpec 10 "LAUNCHER" ([pscustomobject]@{ event = "PREFLIGHT_PASSED"; startup_sha256 = $validDigest })
        & $addSpec 20 "CONTROL" ([pscustomobject]@{
            event = "JOB_OBJECT_ARMED"; name = $historyOuterJobName; kill_on_close = $true
            workload_name = $historyWorkloadJobName; workload_kill_on_close = $true })
        & $addSpec 30 "CONTROL" ([pscustomobject]@{
            event = "GUARDIAN_WATCHDOG_STARTED"; pid = [uint32]9001; ready_file_sha256 = $validDigest
            launch_origin_qpc_timestamp = [long]10010; resume_qpc_timestamp = [long]10020
            ready_observed_qpc_timestamp = [long]10030; ready_pulse_length = [uint64]1
            startup_deadline_s = [uint64]90; deadline_s = [uint64]90 })
        & $addSpec 40 "CONTROL" ([pscustomobject]@{ event = "DUAL_CAMPAIGN_STARTED"; process_control_sha256 = $validDigest })
        & $addSpec 1100 "SEMANTIC" ([pscustomobject]@{ event = "DUAL_SEMANTIC_READINESS"; bindings_sha256 = $validDigest })
        & $addSpec 1200 "SEMANTIC" ([pscustomobject]@{
            event = "DUAL_READINESS_PUBLISHED"
            bindings_sha256 = $validDigest
            host_telemetry_record_index = [uint64]7
            host_telemetry_record_sha256 = $validDigest
            host_telemetry_monotonic_tick = [uint64]1150
        })
        & $addSpec 96000 "PROCESS" ([pscustomobject]@{ event = "CAPTURE_DRAINING_STARTED"; generation_terminal_deadline_elapsed_s = [uint64]220 })
        $terminalEvaluationTick = [uint64]102000
        $newExitPayload = {
            param([string] $Symbol, [uint32] $ProcessId, [uint64] $ObservedTick)
            $launchTick = if ($Symbol -eq "BTCUSDT") { [uint64]1000 } else { [uint64]1001 }
            [pscustomobject]@{
                event = "CAMPAIGN_PROCESS_EXITED"
                symbol = $Symbol
                pid = $ProcessId
                exit_observed_monotonic_tick = $ObservedTick
                exit_code = 0
                elapsed_s = [uint64][math]::Floor([double]($ObservedTick - 1000) / 1000.0)
                coordinator_elapsed_s = [uint64][math]::Floor([double]($ObservedTick - $launchTick) / 1000.0)
            }
        }
        if ($ExitOrder -in @("PRE_EVALUATION", "PRE_EVALUATION_REVERSED")) {
            $firstPreSymbol = if ($ExitOrder -eq "PRE_EVALUATION") { "BTCUSDT" } else { "ETHUSDT" }
            $firstPrePid = if ($firstPreSymbol -eq "BTCUSDT") { [uint32]1001 } else { [uint32]1002 }
            $secondPreSymbol = if ($firstPreSymbol -eq "BTCUSDT") { "ETHUSDT" } else { "BTCUSDT" }
            $secondPrePid = if ($secondPreSymbol -eq "BTCUSDT") { [uint32]1001 } else { [uint32]1002 }
            & $addSpec 100000 "PROCESS" (& $newExitPayload $firstPreSymbol $firstPrePid 99900)
            & $addSpec 101000 "PROCESS" (& $newExitPayload $secondPreSymbol $secondPrePid 100900)
            & $addSpec $terminalEvaluationTick "PROCESS" ([pscustomobject]@{ event = "CAMPAIGN_TERMINAL_EVALUATION_STARTED"; commit_deadline_s = [uint64]1800 })
        }
        elseif ($ExitOrder -in @("INTERLEAVED", "INTERLEAVED_REVERSED")) {
            $firstInterleavedSymbol = if ($ExitOrder -eq "INTERLEAVED") { "BTCUSDT" } else { "ETHUSDT" }
            $firstInterleavedPid = if ($firstInterleavedSymbol -eq "BTCUSDT") { [uint32]1001 } else { [uint32]1002 }
            $secondInterleavedSymbol = if ($firstInterleavedSymbol -eq "BTCUSDT") { "ETHUSDT" } else { "BTCUSDT" }
            $secondInterleavedPid = if ($secondInterleavedSymbol -eq "BTCUSDT") { [uint32]1001 } else { [uint32]1002 }
            & $addSpec 100000 "PROCESS" (& $newExitPayload $firstInterleavedSymbol $firstInterleavedPid 99900)
            & $addSpec $terminalEvaluationTick "PROCESS" ([pscustomobject]@{ event = "CAMPAIGN_TERMINAL_EVALUATION_STARTED"; commit_deadline_s = [uint64]1800 })
            & $addSpec 103000 "PROCESS" (& $newExitPayload $secondInterleavedSymbol $secondInterleavedPid 102900)
        }
        else {
            & $addSpec $terminalEvaluationTick "PROCESS" ([pscustomobject]@{ event = "CAMPAIGN_TERMINAL_EVALUATION_STARTED"; commit_deadline_s = [uint64]1800 })
            $deadlineTick = [uint64]($terminalEvaluationTick + [uint64]1800 * [uint64]1000)
            $postReversed = $ExitOrder -eq "POST_EVALUATION_EXACT_REVERSED"
            $firstPostSymbol = if ($postReversed) { "ETHUSDT" } else { "BTCUSDT" }
            $firstPostPid = if ($firstPostSymbol -eq "BTCUSDT") { [uint32]1001 } else { [uint32]1002 }
            $secondPostSymbol = if ($firstPostSymbol -eq "BTCUSDT") { "ETHUSDT" } else { "BTCUSDT" }
            $secondPostPid = if ($secondPostSymbol -eq "BTCUSDT") { [uint32]1001 } else { [uint32]1002 }
            & $addSpec ($deadlineTick - 1) "PROCESS" (& $newExitPayload $firstPostSymbol $firstPostPid ($deadlineTick - 101))
            if ($ExitOrder -in @("POST_EVALUATION_EXACT", "POST_EVALUATION_EXACT_REVERSED")) {
                & $addSpec ($deadlineTick + 100) "PROCESS" (& $newExitPayload $secondPostSymbol $secondPostPid $deadlineTick)
            }
            else {
                & $addSpec ($deadlineTick + 101) "PROCESS" (& $newExitPayload $secondPostSymbol $secondPostPid ($deadlineTick + 1))
            }
        }
        $lastCaptureTick = [uint64](($specs | Measure-Object -Property tick -Maximum).Maximum)
        $coordinatorDrainOriginTick = [uint64](($specs | Where-Object {
            [string]$_.payload.event -eq "CAMPAIGN_PROCESS_EXITED"
        } | ForEach-Object { [uint64]$_.payload.exit_observed_monotonic_tick } |
            Measure-Object -Maximum).Maximum)
        $coordinatorFinalQueryTick = [uint64]($lastCaptureTick + 800)
        $coordinatorWatchdogLivenessTick = [uint64]($lastCaptureTick + 900)
        $verificationStageTick = [uint64]($lastCaptureTick + 1000)
        $coordinatorDrainElapsedTicks = [long]($coordinatorWatchdogLivenessTick - $coordinatorDrainOriginTick)
        & $addSpec $verificationStageTick "VERIFICATION" ([pscustomobject]@{
            event = "INDEPENDENT_VERIFICATION_STAGE_STARTED"
            deadline_s = [uint64]14400
            coordinator_job_drain_contract = "RawQualificationCoordinatorWorkloadJobDrainV3"
            coordinator_job_scope = "INNER_WORKLOAD_ONLY"
            coordinator_job_name = $historyWorkloadJobName
            coordinator_job_drain_origin_kind = "MAX_COORDINATOR_EXIT_OBSERVATION"
            coordinator_job_drain_deadline_s = [uint64]10
            coordinator_job_drain_origin_monotonic_tick = $coordinatorDrainOriginTick
            coordinator_job_initial_active_processes = [uint32]2
            coordinator_job_final_active_processes = [uint32]0
            coordinator_job_observation_count = [uint64]2
            coordinator_job_final_query_observed_monotonic_tick = $coordinatorFinalQueryTick
            coordinator_job_watchdog_liveness_observed_monotonic_tick = $coordinatorWatchdogLivenessTick
            coordinator_job_drain_elapsed_ticks = $coordinatorDrainElapsedTicks
            coordinator_job_drain_elapsed_ms = [uint64]$coordinatorDrainElapsedTicks
            coordinator_job_monotonic_frequency = [long]1000
            coordinator_job_watchdog_pid = [uint32]9001
            coordinator_job_watchdog_pre_query_signaled = $false
            coordinator_job_watchdog_post_query_signaled = $false
            coordinator_job_drain_result = "WORKLOAD_EMPTY_WATCHDOG_ALIVE"
        })
        $verificationNames = @("btcusdt-rust", "btcusdt-python", "ethusdt-rust", "ethusdt-python")
        $verificationTick = $verificationStageTick
        $verifierPid = [uint32]2000
        foreach ($name in $verificationNames) {
            $verificationTick = [uint64]($verificationTick + 100)
            $verifierPid = [uint32]($verifierPid + 1)
            & $addSpec $verificationTick "VERIFICATION" ([pscustomobject]@{ event = "INDEPENDENT_VERIFIER_STARTED"; name = $name; pid = $verifierPid })
            $verificationTick = [uint64]($verificationTick + 100)
            & $addSpec $verificationTick "VERIFICATION" ([pscustomobject]@{ event = "INDEPENDENT_VERIFIER_COMPLETED"; name = $name; pid = $verifierPid; exit_code = 0; stderr_bytes = [uint64]0; execution_sha256 = $validDigest })
            if ($name -like "*-python") {
                $verificationTick = [uint64]($verificationTick + 100)
                $verifiedSymbol = if ($name -like "btc*") { "BTCUSDT" } else { "ETHUSDT" }
                & $addSpec $verificationTick "VERIFICATION" ([pscustomobject]@{ event = "INDEPENDENT_CAMPAIGN_VERIFIED"; symbol = $verifiedSymbol; rust_report_sha256 = $validDigest; python_report_sha256 = $validDigest })
            }
        }
        $verificationTick = [uint64]($verificationTick + 100)
        $verifierDrainEventTick = $verificationTick
        & $addSpec $verificationTick "CONTROL" ([pscustomobject]@{
            event = "VERIFIER_DESCENDANTS_DRAINED"
            active_processes = [uint32]0
            job_scope = "INNER_WORKLOAD_ONLY"
            job_name = $historyWorkloadJobName
            drain_origin_qpc_timestamp = [long]([long]$historyStartup.monotonic_origin_qpc_timestamp + [long]($verificationTick - 100))
            elapsed_qpc_ticks = [long]100
            monotonic_frequency = [long]1000
            elapsed_ms = [uint64]100
        })
        $verificationTick = [uint64]($verificationTick + 100)
        $watchdogStopRequestTick = [long]([long]$historyStartup.monotonic_origin_qpc_timestamp + [long]$verifierDrainEventTick)
        & $addSpec $verificationTick "CONTROL" ([pscustomobject]@{
            event = "GUARDIAN_WATCHDOG_STOPPED"
            pid = [uint32]9001
            exit_code = 0
            stop_file_sha256 = $validDigest
            stop_request_qpc_timestamp = $watchdogStopRequestTick
            exit_elapsed_qpc_ticks = [long]100
            final_job_drain_elapsed_qpc_ticks = [long]100
            monotonic_frequency = [long]1000
            final_job_active_processes = [uint32]0
        })
        $verificationTick = [uint64]($verificationTick + 100)
        & $addSpec $verificationTick "LAUNCHER" ([pscustomobject][ordered]@{
            event = "LAUNCHER_TERMINAL"
            status = "COMPLETE"
            failure = $null
            terminal_file = "launcher-terminal.json"
            terminal_bytes = [uint64]1
            terminal_sha256 = $validDigest
            failure_containment_sha256 = $null
        })
        $records = @()
        for ($recordIndex = 0; $recordIndex -lt $specs.Count; $recordIndex++) {
            $spec = $specs[$recordIndex]
            $records += & $newHistoryEnvelope ([uint64]$recordIndex) ([uint64]$spec.tick) ([string]$spec.channel) $spec.payload
        }
        return [pscustomobject]@{
            records = [uint64]$records.Count
            all_records = $records
            startup_binding_sha256 = $validDigest
            process_control_binding_sha256 = $validDigest
            campaign_bindings_sha256 = $validDigest
        }
    }
    $newLauncherHistoryPrefix = {
        param($History, [int] $Count)
        $copied = ($History | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
        $copied.all_records = @($copied.all_records | Select-Object -First $Count)
        $copied.records = [uint64]$copied.all_records.Count
        $eventNames = @($copied.all_records | ForEach-Object { [string]$_.body.payload.event })
        $copied.startup_binding_sha256 = if ($eventNames -contains "PREFLIGHT_PASSED") { $validDigest } else { $null }
        $copied.process_control_binding_sha256 = if ($eventNames -contains "DUAL_CAMPAIGN_STARTED") { $validDigest } else { $null }
        $copied.campaign_bindings_sha256 = if ($eventNames -contains "DUAL_SEMANTIC_READINESS") { $validDigest } else { $null }
        return $copied
    }
    $assertLauncherHistoryRejected = {
        param($History, [bool] $TerminalComplete, [string] $Label)
        $rejected = $false
        try {
            $null = Assert-LauncherEventHistory `
                -Journal $History `
                -Startup $historyStartup `
                -Control $historyControl `
                -TerminalComplete $TerminalComplete `
                -SkipSingletonValidation
        }
        catch { $rejected = $true }
        Assert-True $rejected "Adversarial launcher causal-prefix mutant was accepted: $Label"
        return $rejected
    }

    $drainingBoundaryFixture = {
        param([uint64] $Tick)
        & $newHistoryEnvelope 6 $Tick "PROCESS" ([pscustomobject]@{
            event = "CAPTURE_DRAINING_STARTED"
            generation_terminal_deadline_elapsed_s = [uint64]220
        })
    }
    $drainingMinimumTick = [uint64](
        [uint64]$historyControl.capture_origin_monotonic_tick +
        ([uint64]$historyStartup.parameters.total_s - [uint64]5) * [uint64]$historyStartup.monotonic_frequency)
    $drainingMaximumTick = [uint64](
        [uint64]$historyControl.capture_origin_monotonic_tick +
        ([uint64]$historyStartup.parameters.total_s + [uint64]$historyStartup.guardian_policy.generation_terminal_deadline_s) *
            [uint64]$historyStartup.monotonic_frequency)
    $drainingMinMinusOneRejected = $false
    try { $null = Assert-MonitorCaptureDrainingTiming -DrainingRecord (& $drainingBoundaryFixture ($drainingMinimumTick - 1)) -Startup $historyStartup -Control $historyControl }
    catch { $drainingMinMinusOneRejected = $true }
    Assert-True $drainingMinMinusOneRejected "DRAINING at minimum-minus-one monotonic tick was accepted."
    $null = Assert-MonitorCaptureDrainingTiming -DrainingRecord (& $drainingBoundaryFixture $drainingMinimumTick) -Startup $historyStartup -Control $historyControl
    $null = Assert-MonitorCaptureDrainingTiming -DrainingRecord (& $drainingBoundaryFixture $drainingMaximumTick) -Startup $historyStartup -Control $historyControl
    $drainingMaxPlusOneRejected = $false
    try { $null = Assert-MonitorCaptureDrainingTiming -DrainingRecord (& $drainingBoundaryFixture ($drainingMaximumTick + 1)) -Startup $historyStartup -Control $historyControl }
    catch { $drainingMaxPlusOneRejected = $true }
    Assert-True $drainingMaxPlusOneRejected "DRAINING at maximum-plus-one monotonic tick was accepted."

    $canonicalPrefixCounts = [ordered]@{}
    foreach ($canonicalExitOrder in @(
        "PRE_EVALUATION", "PRE_EVALUATION_REVERSED",
        "INTERLEAVED", "INTERLEAVED_REVERSED",
        "POST_EVALUATION_EXACT", "POST_EVALUATION_EXACT_REVERSED")) {
        $canonicalHistory = & $newTerminalLauncherHistory $canonicalExitOrder
        $acceptedPrefixes = [uint64]0
        for ($prefixCount = 1; $prefixCount -le [int]$canonicalHistory.records; $prefixCount++) {
            $prefix = & $newLauncherHistoryPrefix $canonicalHistory $prefixCount
            $isTerminalPrefix = $prefixCount -eq [int]$canonicalHistory.records
            $null = Assert-LauncherEventHistory `
                -Journal $prefix `
                -Startup $historyStartup `
                -Control $historyControl `
                -TerminalComplete $isTerminalPrefix `
                -SkipSingletonValidation
            $acceptedPrefixes = [uint64]($acceptedPrefixes + 1)
        }
        Assert-True ($acceptedPrefixes -eq [uint64]$canonicalHistory.records) "A legitimate launcher transition prefix was rejected: $canonicalExitOrder"
        $canonicalPrefixCounts[$canonicalExitOrder] = $acceptedPrefixes
    }
    Assert-True ((($canonicalPrefixCounts.Values | Measure-Object -Sum).Sum) -eq 144) "Canonical launcher prefix matrix is not exactly 144 accepted causal prefixes."

    $singleObservationHistory = (& $newTerminalLauncherHistory "PRE_EVALUATION" |
        ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
    $singleObservationStage = @($singleObservationHistory.all_records | Where-Object {
        [string]$_.body.payload.event -eq "INDEPENDENT_VERIFICATION_STAGE_STARTED"
    })[0]
    $singleObservationStage.body.payload.coordinator_job_initial_active_processes = [uint32]0
    $singleObservationStage.body.payload.coordinator_job_final_active_processes = [uint32]0
    $singleObservationStage.body.payload.coordinator_job_observation_count = [uint64]1
    $null = Assert-LauncherEventHistory `
        -Journal $singleObservationHistory `
        -Startup $historyStartup `
        -Control $historyControl `
        -TerminalComplete $true `
        -SkipSingletonValidation
    $coordinatorSingleObservationAccepted = $true

    $setCoordinatorDrainBoundary = {
        param($History, [long] $ElapsedTicks)
        $stageIndex = [array]::FindIndex(
            [object[]]$History.all_records,
            [Predicate[object]]{ param($candidate)
                [string]$candidate.body.payload.event -eq "INDEPENDENT_VERIFICATION_STAGE_STARTED"
            })
        if ($stageIndex -lt 0) { throw "Synthetic coordinator drain stage is absent." }
        $stage = $History.all_records[$stageIndex]
        $origin = [uint64]$stage.body.payload.coordinator_job_drain_origin_monotonic_tick
        $livenessTick = [uint64]([decimal]$origin + [decimal]$ElapsedTicks)
        $queryTick = [uint64]($livenessTick - 1)
        $stageTick = [uint64]($livenessTick + 100)
        $stage.body.payload.coordinator_job_final_query_observed_monotonic_tick = $queryTick
        $stage.body.payload.coordinator_job_watchdog_liveness_observed_monotonic_tick = $livenessTick
        $stage.body.payload.coordinator_job_drain_elapsed_ticks = $ElapsedTicks
        $stage.body.payload.coordinator_job_drain_elapsed_ms =
            Convert-RawQualificationQpcTicksToMilliseconds `
                -ElapsedTicks $ElapsedTicks `
                -Frequency ([long]$historyStartup.monotonic_frequency)
        $stage.body.monotonic_tick = $stageTick
        for ($recordIndex = $stageIndex + 1; $recordIndex -lt [int]$History.records; $recordIndex++) {
            $History.all_records[$recordIndex].body.monotonic_tick =
                [uint64]($stageTick + [uint64](($recordIndex - $stageIndex) * 100))
        }
        $verifierDrain = @($History.all_records | Where-Object {
            [string]$_.body.payload.event -eq "VERIFIER_DESCENDANTS_DRAINED"
        })[0]
        $verifierDrainTick = [uint64]$verifierDrain.body.monotonic_tick
        $verifierDrain.body.payload.drain_origin_qpc_timestamp =
            [long]([long]$historyStartup.monotonic_origin_qpc_timestamp + [long]($verifierDrainTick - 100))
        $verifierDrain.body.payload.elapsed_qpc_ticks = [long]100
        $verifierDrain.body.payload.monotonic_frequency = [long]$historyStartup.monotonic_frequency
        $verifierDrain.body.payload.elapsed_ms = Convert-RawQualificationQpcTicksToMilliseconds `
            -ElapsedTicks 100 `
            -Frequency ([long]$historyStartup.monotonic_frequency)
        $watchdogStop = @($History.all_records | Where-Object {
            [string]$_.body.payload.event -eq "GUARDIAN_WATCHDOG_STOPPED"
        })[0]
        $watchdogStop.body.payload.stop_request_qpc_timestamp =
            [long]([long]$historyStartup.monotonic_origin_qpc_timestamp + [long]$verifierDrainTick)
        $watchdogStop.body.payload.exit_elapsed_qpc_ticks = [long]100
        $watchdogStop.body.payload.final_job_drain_elapsed_qpc_ticks = [long]100
        $watchdogStop.body.payload.monotonic_frequency = [long]$historyStartup.monotonic_frequency
        return $History
    }
    $coordinatorDrainDeadlineTicks = [long](10 * [long]$historyStartup.monotonic_frequency)
    $coordinatorExactDeadlineHistory = & $setCoordinatorDrainBoundary `
        ((& $newTerminalLauncherHistory "PRE_EVALUATION") |
            ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json) `
        $coordinatorDrainDeadlineTicks
    $null = Assert-LauncherEventHistory `
        -Journal $coordinatorExactDeadlineHistory `
        -Startup $historyStartup `
        -Control $historyControl `
        -TerminalComplete $true `
        -SkipSingletonValidation
    $coordinatorDrainExactDeadlineAccepted = $true
    $coordinatorPlusOneDeadlineHistory = & $setCoordinatorDrainBoundary `
        ((& $newTerminalLauncherHistory "PRE_EVALUATION") |
            ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json) `
        ($coordinatorDrainDeadlineTicks + 1)
    $coordinatorDrainDeadlinePlusOneRejected = $false
    try {
        $null = Assert-LauncherEventHistory `
            -Journal $coordinatorPlusOneDeadlineHistory `
            -Startup $historyStartup `
            -Control $historyControl `
            -TerminalComplete $true `
            -SkipSingletonValidation
    }
    catch { $coordinatorDrainDeadlinePlusOneRejected = $true }
    Assert-True $coordinatorDrainDeadlinePlusOneRejected `
        "Coordinator workload Job-drain V3 accepted its exact 10-second deadline plus one QPC tick."

    $coordinatorNontrivialFrequency = [long]10000
    $coordinatorNontrivialRemainderTicks = [long]1001
    $coordinatorNontrivialRemainderMs = Convert-RawQualificationQpcTicksToMilliseconds `
        -ElapsedTicks $coordinatorNontrivialRemainderTicks `
        -Frequency $coordinatorNontrivialFrequency
    Assert-True ($coordinatorNontrivialRemainderMs -eq 100 -and
        $coordinatorNontrivialRemainderMs -ne [uint64]$coordinatorNontrivialRemainderTicks) `
        "Coordinator Job-drain QPC-to-ms regression does not exercise non-identity floor conversion."
    $coordinatorScaledStartup = ($historyStartup | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
    $coordinatorScaledControl = ($historyControl | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
    $coordinatorScaledHistory = (& $newTerminalLauncherHistory "PRE_EVALUATION" |
        ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
    $coordinatorScale = [uint64]10
    $coordinatorScaledStartup.monotonic_frequency = [uint64]$coordinatorNontrivialFrequency
    $coordinatorScaledControl.capture_origin_monotonic_tick =
        [uint64]([uint64]$coordinatorScaledControl.capture_origin_monotonic_tick * $coordinatorScale)
    foreach ($process in @($coordinatorScaledControl.processes)) {
        $process.launch_monotonic_tick =
            [uint64]([uint64]$process.launch_monotonic_tick * $coordinatorScale)
    }
    foreach ($record in @($coordinatorScaledHistory.all_records)) {
        $record.body.monotonic_tick = [uint64]([uint64]$record.body.monotonic_tick * $coordinatorScale)
        $eventName = [string]$record.body.payload.event
        if ($eventName -eq "DUAL_READINESS_PUBLISHED") {
            $record.body.payload.host_telemetry_monotonic_tick =
                [uint64]([uint64]$record.body.payload.host_telemetry_monotonic_tick * $coordinatorScale)
        }
        elseif ($eventName -eq "CAMPAIGN_PROCESS_EXITED") {
            $observed = [uint64]([uint64]$record.body.payload.exit_observed_monotonic_tick * $coordinatorScale)
            $launchTick = [uint64](@($coordinatorScaledControl.processes | Where-Object {
                [string]$_.symbol -eq [string]$record.body.payload.symbol
            })[0].launch_monotonic_tick)
            $record.body.payload.exit_observed_monotonic_tick = $observed
            $record.body.payload.elapsed_s = [uint64][math]::Floor(
                [double]($observed - [uint64]$coordinatorScaledControl.capture_origin_monotonic_tick) /
                [double]$coordinatorNontrivialFrequency)
            $record.body.payload.coordinator_elapsed_s = [uint64][math]::Floor(
                [double]($observed - $launchTick) / [double]$coordinatorNontrivialFrequency)
        }
        elseif ($eventName -eq "INDEPENDENT_VERIFICATION_STAGE_STARTED") {
            foreach ($property in @(
                "coordinator_job_drain_origin_monotonic_tick",
                "coordinator_job_final_query_observed_monotonic_tick",
                "coordinator_job_watchdog_liveness_observed_monotonic_tick")) {
                $record.body.payload.PSObject.Properties[$property].Value =
                    [uint64]([uint64]$record.body.payload.PSObject.Properties[$property].Value * $coordinatorScale)
            }
            $record.body.payload.coordinator_job_drain_elapsed_ticks =
                [long]([long]$record.body.payload.coordinator_job_drain_elapsed_ticks * [long]$coordinatorScale)
            $record.body.payload.coordinator_job_monotonic_frequency = $coordinatorNontrivialFrequency
            $record.body.payload.coordinator_job_drain_elapsed_ms =
                Convert-RawQualificationQpcTicksToMilliseconds `
                    -ElapsedTicks ([long]$record.body.payload.coordinator_job_drain_elapsed_ticks) `
                    -Frequency $coordinatorNontrivialFrequency
        }
    }
    $coordinatorScaledVerifierDrain = @($coordinatorScaledHistory.all_records | Where-Object {
        [string]$_.body.payload.event -eq "VERIFIER_DESCENDANTS_DRAINED"
    })[0]
    $coordinatorScaledVerifierDrainTick = [uint64]$coordinatorScaledVerifierDrain.body.monotonic_tick
    $coordinatorScaledVerifierDrain.body.payload.drain_origin_qpc_timestamp =
        [long]([long]$coordinatorScaledStartup.monotonic_origin_qpc_timestamp +
            [long]($coordinatorScaledVerifierDrainTick - 1000))
    $coordinatorScaledVerifierDrain.body.payload.elapsed_qpc_ticks = [long]1000
    $coordinatorScaledVerifierDrain.body.payload.monotonic_frequency = $coordinatorNontrivialFrequency
    $coordinatorScaledVerifierDrain.body.payload.elapsed_ms = [uint64]100
    $coordinatorScaledWatchdogStop = @($coordinatorScaledHistory.all_records | Where-Object {
        [string]$_.body.payload.event -eq "GUARDIAN_WATCHDOG_STOPPED"
    })[0]
    $coordinatorScaledWatchdogStop.body.payload.stop_request_qpc_timestamp =
        [long]([long]$coordinatorScaledStartup.monotonic_origin_qpc_timestamp +
            [long]$coordinatorScaledVerifierDrainTick)
    $coordinatorScaledWatchdogStop.body.payload.exit_elapsed_qpc_ticks = [long]1000
    $coordinatorScaledWatchdogStop.body.payload.final_job_drain_elapsed_qpc_ticks = [long]1000
    $coordinatorScaledWatchdogStop.body.payload.monotonic_frequency = $coordinatorNontrivialFrequency
    $null = Assert-LauncherEventHistory `
        -Journal $coordinatorScaledHistory `
        -Startup $coordinatorScaledStartup `
        -Control $coordinatorScaledControl `
        -TerminalComplete $true `
        -SkipSingletonValidation
    $coordinatorNonidentityFrequencyHistoryAccepted = $true
    $scaledCoordinatorStage = @($coordinatorScaledHistory.all_records | Where-Object {
        [string]$_.body.payload.event -eq "INDEPENDENT_VERIFICATION_STAGE_STARTED"
    })[0]
    Assert-True ([uint64]$scaledCoordinatorStage.body.payload.coordinator_job_drain_elapsed_ticks -ne
        [uint64]$scaledCoordinatorStage.body.payload.coordinator_job_drain_elapsed_ms) `
        "Coordinator workload Job-drain V3 scaled fixture still degenerates ticks into milliseconds."

    $numericPayloadProperties = @{
        GUARDIAN_WATCHDOG_STARTED = @(
            "pid", "launch_origin_qpc_timestamp", "resume_qpc_timestamp",
            "ready_observed_qpc_timestamp", "ready_pulse_length", "startup_deadline_s", "deadline_s")
        DUAL_READINESS_PUBLISHED = @("host_telemetry_record_index", "host_telemetry_monotonic_tick")
        CAPTURE_DRAINING_STARTED = @("generation_terminal_deadline_elapsed_s")
        CAMPAIGN_PROCESS_EXITED = @(
            "pid", "exit_observed_monotonic_tick", "exit_code", "elapsed_s", "coordinator_elapsed_s")
        CAMPAIGN_TERMINAL_EVALUATION_STARTED = @("commit_deadline_s")
        INDEPENDENT_VERIFICATION_STAGE_STARTED = @(
            "deadline_s", "coordinator_job_drain_deadline_s", "coordinator_job_drain_origin_monotonic_tick",
            "coordinator_job_initial_active_processes", "coordinator_job_final_active_processes",
            "coordinator_job_observation_count", "coordinator_job_final_query_observed_monotonic_tick",
            "coordinator_job_watchdog_liveness_observed_monotonic_tick",
            "coordinator_job_drain_elapsed_ticks", "coordinator_job_drain_elapsed_ms",
            "coordinator_job_monotonic_frequency", "coordinator_job_watchdog_pid")
        INDEPENDENT_VERIFIER_STARTED = @("pid")
        INDEPENDENT_VERIFIER_COMPLETED = @("pid", "exit_code", "stderr_bytes")
        VERIFIER_DESCENDANTS_DRAINED = @(
            "active_processes", "drain_origin_qpc_timestamp", "elapsed_qpc_ticks",
            "monotonic_frequency", "elapsed_ms")
        GUARDIAN_WATCHDOG_STOPPED = @(
            "pid", "exit_code", "stop_request_qpc_timestamp", "exit_elapsed_qpc_ticks",
            "final_job_drain_elapsed_qpc_ticks", "monotonic_frequency", "final_job_active_processes")
    }
    $numericMutationHistory = & $newTerminalLauncherHistory "PRE_EVALUATION"
    $launcherPayloadNumericFields = [uint64]0
    $launcherPayloadExactZeroFields = [uint64]0
    $launcherPayloadNumericTypeMutantsRejected = [uint64]0
    foreach ($recordIndex in 0..([int]$numericMutationHistory.records - 1)) {
        $eventName = [string]$numericMutationHistory.all_records[$recordIndex].body.payload.event
        if (-not $numericPayloadProperties.ContainsKey($eventName)) { continue }
        foreach ($propertyName in @($numericPayloadProperties[$eventName])) {
            $originalValue = $numericMutationHistory.all_records[$recordIndex].body.payload.$propertyName
            Assert-True (Test-RawQualificationJsonInteger -Value $originalValue) "Canonical numeric launcher field is not an actual integral CLR type: $eventName.$propertyName"
            $launcherPayloadNumericFields++
            if ([decimal]$originalValue -eq 0) { $launcherPayloadExactZeroFields++ }
            foreach ($replacement in @([string]$originalValue, $false, [double]$originalValue)) {
                $mutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
                $mutant.all_records[$recordIndex].body.payload.PSObject.Properties[$propertyName].Value = $replacement
                $null = & $assertLauncherHistoryRejected $mutant $true "numeric-type-$eventName-$propertyName-$($replacement.GetType().Name)-$recordIndex"
                $launcherPayloadNumericTypeMutantsRejected++
            }
        }
    }
    Assert-True ($launcherPayloadNumericFields -eq 61) "Launcher payload numeric audit inventory changed from exactly 61 fields."
    Assert-True ($launcherPayloadExactZeroFields -eq 14) "Launcher payload exact-zero audit inventory changed from exactly 14 fields."
    Assert-True ($launcherPayloadNumericTypeMutantsRejected -eq 183) "Not all numeric string/bool/double launcher payload mutants were rejected."

    $launcherEnvelopeNumericTypeMutantsRejected = [uint64]0
    foreach ($recordIndex in 0..([int]$numericMutationHistory.records - 1)) {
        foreach ($propertyName in @("record_index", "wall_ns", "monotonic_tick")) {
            $originalValue = $numericMutationHistory.all_records[$recordIndex].body.$propertyName
            foreach ($replacement in @([string]$originalValue, $false, [double]$originalValue)) {
                $mutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
                $mutant.all_records[$recordIndex].body.PSObject.Properties[$propertyName].Value = $replacement
                $null = & $assertLauncherHistoryRejected $mutant $true "envelope-type-$propertyName-$recordIndex-$($replacement.GetType().Name)"
                $launcherEnvelopeNumericTypeMutantsRejected++
            }
        }
    }
    Assert-True ($launcherEnvelopeNumericTypeMutantsRejected -eq 216) "Not all record_index/wall_ns/monotonic_tick string/bool/double mutants were rejected."

    $launcherPayloadPropertySetMutantsRejected = [uint64]0
    foreach ($recordIndex in 0..([int]$numericMutationHistory.records - 1)) {
        $extraMutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
        $extraMutant.all_records[$recordIndex].body.payload | Add-Member -NotePropertyName unexpected_future_field -NotePropertyValue "forbidden"
        $null = & $assertLauncherHistoryRejected $extraMutant $true "extra-payload-property-$recordIndex"
        $launcherPayloadPropertySetMutantsRejected++
        $missingMutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
        $removableName = @($missingMutant.all_records[$recordIndex].body.payload.PSObject.Properties.Name | Where-Object { $_ -ne "event" })[0]
        $missingMutant.all_records[$recordIndex].body.payload.PSObject.Properties.Remove($removableName)
        $null = & $assertLauncherHistoryRejected $missingMutant $true "missing-payload-property-$recordIndex-$removableName"
        $launcherPayloadPropertySetMutantsRejected++
        $caseMutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
        $caseValue = $caseMutant.all_records[$recordIndex].body.payload.PSObject.Properties[$removableName].Value
        $caseMutant.all_records[$recordIndex].body.payload.PSObject.Properties.Remove($removableName)
        $caseMutant.all_records[$recordIndex].body.payload | Add-Member -NotePropertyName $removableName.ToUpperInvariant() -NotePropertyValue $caseValue
        $null = & $assertLauncherHistoryRejected $caseMutant $true "case-mismatched-payload-property-$recordIndex-$removableName"
        $launcherPayloadPropertySetMutantsRejected++
    }
    Assert-True ($launcherPayloadPropertySetMutantsRejected -eq 72) "Exact/case-sensitive launcher payload property-set mutation coverage is incomplete."
    $eventCaseMutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
    $eventCaseMutant.all_records[0].body.payload.event = "preflight_passed"
    $null = & $assertLauncherHistoryRejected $eventCaseMutant $true "case-mismatched-event-value"
    $channelCaseMutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
    $channelCaseMutant.all_records[0].body.channel = "launcher"
    $null = & $assertLauncherHistoryRejected $channelCaseMutant $true "case-mismatched-channel-value"
    $digestCaseMutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
    $digestCaseMutant.all_records[0].body.payload.startup_sha256 = $validDigest.ToUpperInvariant()
    $null = & $assertLauncherHistoryRejected $digestCaseMutant $true "uppercase-digest"

    $qpcCausalityMutantsRejected = [ordered]@{}
    $coordinatorStageIndex = [array]::FindIndex(
        [object[]]$numericMutationHistory.all_records,
        [Predicate[object]]{ param($candidate) [string]$candidate.body.payload.event -eq "INDEPENDENT_VERIFICATION_STAGE_STARTED" })
    $orderedExitRecords = @($numericMutationHistory.all_records | Where-Object {
        [string]$_.body.payload.event -eq "CAMPAIGN_PROCESS_EXITED"
    } | Sort-Object { [uint64]$_.body.payload.exit_observed_monotonic_tick })
    $firstExitObservedTick = [uint64]$orderedExitRecords[0].body.payload.exit_observed_monotonic_tick
    $secondExitObservedTick = [uint64]$orderedExitRecords[1].body.payload.exit_observed_monotonic_tick
    $latestExitPublicationTick = [uint64](($orderedExitRecords |
        ForEach-Object { [uint64]$_.body.monotonic_tick } | Measure-Object -Maximum).Maximum)
    $coordinatorStageTick = [uint64]$numericMutationHistory.all_records[$coordinatorStageIndex].body.monotonic_tick
    $coordinatorQueryTick = [uint64]$numericMutationHistory.all_records[$coordinatorStageIndex].body.payload.coordinator_job_final_query_observed_monotonic_tick
    $coordinatorLivenessTick = [uint64]$numericMutationHistory.all_records[$coordinatorStageIndex].body.payload.coordinator_job_watchdog_liveness_observed_monotonic_tick
    foreach ($case in @(
        [pscustomobject]@{ name="coordinator-origin-before-first-observation"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_drain_origin_monotonic_tick = [uint64]($firstExitObservedTick - 1) } },
        [pscustomobject]@{ name="coordinator-origin-equals-first-not-max-observation"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_drain_origin_monotonic_tick = $firstExitObservedTick; $h.all_records[$i].body.payload.coordinator_job_drain_elapsed_ticks = [long]($coordinatorLivenessTick - $firstExitObservedTick); $h.all_records[$i].body.payload.coordinator_job_drain_elapsed_ms = [uint64]($coordinatorLivenessTick - $firstExitObservedTick) } },
        [pscustomobject]@{ name="coordinator-origin-after-latest-observation"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_drain_origin_monotonic_tick = [uint64]($secondExitObservedTick + 1) } },
        [pscustomobject]@{ name="coordinator-publication-tick-used-as-origin"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_drain_origin_monotonic_tick = $latestExitPublicationTick; $h.all_records[$i].body.payload.coordinator_job_drain_elapsed_ticks = [long]($coordinatorLivenessTick - $latestExitPublicationTick); $h.all_records[$i].body.payload.coordinator_job_drain_elapsed_ms = [uint64]($coordinatorLivenessTick - $latestExitPublicationTick) } },
        [pscustomobject]@{ name="coordinator-query-before-latest-exit-publication"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_final_query_observed_monotonic_tick = [uint64]($latestExitPublicationTick - 1) } },
        [pscustomobject]@{ name="coordinator-liveness-before-query"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_watchdog_liveness_observed_monotonic_tick = [uint64]($coordinatorQueryTick - 1); $h.all_records[$i].body.payload.coordinator_job_drain_elapsed_ticks = [long]($coordinatorQueryTick - 1 - $secondExitObservedTick); $h.all_records[$i].body.payload.coordinator_job_drain_elapsed_ms = [uint64]($coordinatorQueryTick - 1 - $secondExitObservedTick) } },
        [pscustomobject]@{ name="coordinator-liveness-after-verification-stage"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_watchdog_liveness_observed_monotonic_tick = [uint64]($coordinatorStageTick + 1); $h.all_records[$i].body.payload.coordinator_job_drain_elapsed_ticks = [long]($coordinatorStageTick + 1 - $secondExitObservedTick); $h.all_records[$i].body.payload.coordinator_job_drain_elapsed_ms = [uint64]($coordinatorStageTick + 1 - $secondExitObservedTick) } },
        [pscustomobject]@{ name="coordinator-drain-ms-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_drain_elapsed_ms = [uint64]($h.all_records[$i].body.payload.coordinator_job_drain_elapsed_ms + 1) } },
        [pscustomobject]@{ name="coordinator-drain-deadline-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_drain_deadline_s = [uint64]9 } },
        [pscustomobject]@{ name="coordinator-drain-frequency-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_monotonic_frequency = [long]1001 } },
        [pscustomobject]@{ name="coordinator-final-count-not-zero"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_final_active_processes = [uint32]1 } },
        [pscustomobject]@{ name="coordinator-initial-less-than-final"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_initial_active_processes = [uint32]0; $h.all_records[$i].body.payload.coordinator_job_final_active_processes = [uint32]1 } },
        [pscustomobject]@{ name="coordinator-zero-initial-observation-count-incoherent"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_initial_active_processes = [uint32]0; $h.all_records[$i].body.payload.coordinator_job_observation_count = [uint64]2 } },
        [pscustomobject]@{ name="coordinator-multi-process-single-observation"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_initial_active_processes = [uint32]2; $h.all_records[$i].body.payload.coordinator_job_observation_count = [uint64]1 } },
        [pscustomobject]@{ name="coordinator-scope-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_scope = "OUTER" } },
        [pscustomobject]@{ name="coordinator-workload-name-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_name = "test" } },
        [pscustomobject]@{ name="coordinator-watchdog-pid-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_watchdog_pid = [uint32]9002 } },
        [pscustomobject]@{ name="coordinator-watchdog-pre-query-signaled"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_watchdog_pre_query_signaled = $true } },
        [pscustomobject]@{ name="coordinator-watchdog-post-query-signaled"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_watchdog_post_query_signaled = $true } },
        [pscustomobject]@{ name="coordinator-contract-version-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_drain_contract = "RawQualificationCoordinatorJobDrainV2" } },
        [pscustomobject]@{ name="coordinator-origin-kind-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_drain_origin_kind = "MAX_EXIT_PUBLICATION" } },
        [pscustomobject]@{ name="coordinator-result-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.coordinator_job_drain_result = "UNKNOWN" } })) {
        $mutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
        & $case.action $mutant $coordinatorStageIndex
        $null = & $assertLauncherHistoryRejected $mutant $true $case.name
        $qpcCausalityMutantsRejected[$case.name] = $true
    }
    $exitObservationMutants = @(
        [pscustomobject]@{ name="exit-observation-after-publication"; action={ param($r)
            $observed = [uint64]($r.body.monotonic_tick + 1)
            $launchTick = if ([string]$r.body.payload.symbol -eq "BTCUSDT") { [uint64]1000 } else { [uint64]1001 }
            $r.body.payload.exit_observed_monotonic_tick = $observed
            $r.body.payload.elapsed_s = [uint64][math]::Floor([double]($observed - 1000) / 1000.0)
            $r.body.payload.coordinator_elapsed_s = [uint64][math]::Floor([double]($observed - $launchTick) / 1000.0)
        } },
        [pscustomobject]@{ name="exit-observed-elapsed-mismatch"; action={ param($r) $r.body.payload.elapsed_s = [uint64]($r.body.payload.elapsed_s + 1) } },
        [pscustomobject]@{ name="exit-observed-coordinator-elapsed-mismatch"; action={ param($r) $r.body.payload.coordinator_elapsed_s = [uint64]($r.body.payload.coordinator_elapsed_s + 1) } })
    foreach ($case in $exitObservationMutants) {
        $mutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
        $mutantExit = @($mutant.all_records | Where-Object {
            [string]$_.body.payload.event -eq "CAMPAIGN_PROCESS_EXITED"
        })[0]
        & $case.action $mutantExit
        $null = & $assertLauncherHistoryRejected $mutant $true $case.name
        $qpcCausalityMutantsRejected[$case.name] = $true
    }

    $verifierDrainIndex = [array]::FindIndex(
        [object[]]$numericMutationHistory.all_records,
        [Predicate[object]]{ param($candidate) [string]$candidate.body.payload.event -eq "VERIFIER_DESCENDANTS_DRAINED" })
    $lastVerifiedRecord = @($numericMutationHistory.all_records | Where-Object {
        [string]$_.body.payload.event -eq "INDEPENDENT_CAMPAIGN_VERIFIED"
    } | Sort-Object { [uint64]$_.body.record_index })[-1]
    $lastVerifiedAbsolute = [long]([long]$historyStartup.monotonic_origin_qpc_timestamp + [long]$lastVerifiedRecord.body.monotonic_tick)
    $verifierDrainEventAbsolute = [long]([long]$historyStartup.monotonic_origin_qpc_timestamp + [long]$numericMutationHistory.all_records[$verifierDrainIndex].body.monotonic_tick)
    foreach ($case in @(
        [pscustomobject]@{ name="verifier-drain-before-last-campaign-proof"; action={ param($h,$i) $h.all_records[$i].body.payload.drain_origin_qpc_timestamp = [long]($lastVerifiedAbsolute - 1) } },
        [pscustomobject]@{ name="verifier-drain-after-container-event"; action={ param($h,$i) $h.all_records[$i].body.payload.elapsed_qpc_ticks = [long]($verifierDrainEventAbsolute - [long]$h.all_records[$i].body.payload.drain_origin_qpc_timestamp + 1); $h.all_records[$i].body.payload.elapsed_ms = [uint64]$h.all_records[$i].body.payload.elapsed_qpc_ticks } },
        [pscustomobject]@{ name="verifier-drain-ms-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.elapsed_ms = [uint64]($h.all_records[$i].body.payload.elapsed_ms + 1) } },
        [pscustomobject]@{ name="verifier-drain-frequency-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.monotonic_frequency = [long]($historyStartup.monotonic_frequency + 1) } },
        [pscustomobject]@{ name="verifier-drain-active-not-zero"; action={ param($h,$i) $h.all_records[$i].body.payload.active_processes = [uint32]1 } },
        [pscustomobject]@{ name="verifier-drain-scope-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.job_scope = "OUTER" } },
        [pscustomobject]@{ name="verifier-drain-name-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.job_name = "test" } })) {
        $mutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
        & $case.action $mutant $verifierDrainIndex
        $null = & $assertLauncherHistoryRejected $mutant $true $case.name
        $qpcCausalityMutantsRejected[$case.name] = $true
    }

    $watchdogStopIndex = [array]::FindIndex(
        [object[]]$numericMutationHistory.all_records,
        [Predicate[object]]{ param($candidate) [string]$candidate.body.payload.event -eq "GUARDIAN_WATCHDOG_STOPPED" })
    $watchdogEventAbsolute = [long]([long]$historyStartup.monotonic_origin_qpc_timestamp + [long]$numericMutationHistory.all_records[$watchdogStopIndex].body.monotonic_tick)
    $verifierDrainAbsolute = [long]([long]$historyStartup.monotonic_origin_qpc_timestamp + [long]$numericMutationHistory.all_records[$verifierDrainIndex].body.monotonic_tick)
    foreach ($case in @(
        [pscustomobject]@{ name="watchdog-stop-before-verifier-drain"; action={ param($h,$i) $h.all_records[$i].body.payload.stop_request_qpc_timestamp = [long]($verifierDrainAbsolute - 1) } },
        [pscustomobject]@{ name="watchdog-exit-after-container-event"; action={ param($h,$i) $h.all_records[$i].body.payload.exit_elapsed_qpc_ticks = [long]($watchdogEventAbsolute - [long]$h.all_records[$i].body.payload.stop_request_qpc_timestamp + 1) } },
        [pscustomobject]@{ name="watchdog-final-drain-after-container-event"; action={ param($h,$i) $h.all_records[$i].body.payload.final_job_drain_elapsed_qpc_ticks = [long]($watchdogEventAbsolute - [long]$h.all_records[$i].body.payload.stop_request_qpc_timestamp + 1) } },
        [pscustomobject]@{ name="watchdog-frequency-mismatch"; action={ param($h,$i) $h.all_records[$i].body.payload.monotonic_frequency = [long]($historyStartup.monotonic_frequency + 1) } })) {
        $mutant = ($numericMutationHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json)
        & $case.action $mutant $watchdogStopIndex
        $null = & $assertLauncherHistoryRejected $mutant $true $case.name
        $qpcCausalityMutantsRejected[$case.name] = $true
    }

    $launcherCausalMutantsRejected = [ordered]@{}
    $canonicalForMutation = & $newTerminalLauncherHistory "PRE_EVALUATION"
    $failedPrefix = & $newLauncherHistoryPrefix $canonicalForMutation 6
    $failedHistoryContainment = $validFailureContainment | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
    $failedHistoryContainment.job_name = [string]$failedPrefix.all_records[1].body.payload.name
    $failedHistoryContainment.detected_monotonic_tick = [uint64]1300
    $failedHistoryContainment.termination_monotonic_tick = [uint64]1400
    $failedHistoryContainment.drain_elapsed_qpc_ticks = [uint64]100
    $failedHistoryContainmentBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($failedHistoryContainment | ConvertTo-Json -Depth 100 -Compress))
    $failedHistoryContainmentDigest = Get-RawQualificationSha256Bytes -Bytes $failedHistoryContainmentBytes
    $failureRecord = & $newHistoryEnvelope 6 95000 "FAILURE" ([pscustomobject][ordered]@{
        event = "LAUNCHER_FAILED"; error = "selftest failure" })
    $failureRecord | Add-Member -NotePropertyName record_sha256 -NotePropertyValue ('1' * 64)
    $containmentRecord = & $newHistoryEnvelope 7 95001 "FAILURE" ([pscustomobject][ordered]@{
        event = "FAILURE_CONTAINMENT_TERMINAL"; failure_containment_sha256 = $failedHistoryContainmentDigest })
    $containmentRecord | Add-Member -NotePropertyName record_sha256 -NotePropertyValue ('2' * 64)
    $failedPostLink = & $newHistoryEnvelope 8 95002 "LAUNCHER" ([pscustomobject][ordered]@{
        event = "LAUNCHER_TERMINAL"; status = "FAILED"; failure = "selftest failure"
        terminal_file = "launcher-terminal.json"; terminal_bytes = [uint64]1
        terminal_sha256 = $validDigest; failure_containment_sha256 = $failedHistoryContainmentDigest })
    $failedPostLink | Add-Member -NotePropertyName record_sha256 -NotePropertyValue ('3' * 64)
    $failedHistory = [pscustomobject]@{
        records = [uint64]9
        all_records = @($failedPrefix.all_records) + @($failureRecord, $containmentRecord, $failedPostLink)
        startup_binding_sha256 = $validDigest
        process_control_binding_sha256 = $validDigest
        campaign_bindings_sha256 = $validDigest
        penultimate = $containmentRecord
        preterminal_prefix_bytes = [uint64]100
        preterminal_prefix_sha256 = $validDigest
    }
    $failedHistoryTerminal = $failedTerminalV2Contract | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
    $failedHistoryTerminal.failure_containment = $failedHistoryContainment
    $failedHistoryTerminal.failure_containment_sha256 = $failedHistoryContainmentDigest
    $failedHistoryTerminal.launcher_events = [pscustomobject]@{
        file = "launcher-events.jsonl"; records = [uint64]8
        terminal_record_sha256 = ('2' * 64); file_bytes = [uint64]100; file_sha256 = $validDigest
    }
    $failedHistoryTerminalSnapshot = [pscustomobject]@{ length = [uint64]1; sha256 = $validDigest }
    $failedHistoryProof = Assert-MonitorFailedLauncherV2History `
        -Journal $failedHistory `
        -Terminal $failedHistoryTerminal `
        -TerminalSnapshot $failedHistoryTerminalSnapshot `
        -Startup $historyStartup `
        -Control $historyControl
    Assert-True ([bool]$failedHistoryProof.post_readiness) "Valid post-readiness FAILED V2 containment/post-link history was rejected."
    $failedHistoryMutantsRejected = [uint64]0
    foreach ($case in @("wrong_containment_hash", "wrong_terminal_sha", "nonzero_descendants", "missing_postlink")) {
        $journalMutant = $failedHistory | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
        $terminalMutant = $failedHistoryTerminal | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
        if ($case -eq "wrong_containment_hash") {
            $journalMutant.all_records[7].body.payload.failure_containment_sha256 = ('f' * 64)
        }
        elseif ($case -eq "wrong_terminal_sha") {
            $journalMutant.all_records[8].body.payload.terminal_sha256 = ('f' * 64)
        }
        elseif ($case -eq "nonzero_descendants") {
            $terminalMutant.failure_containment.final_active_processes = [int64]1
        }
        else {
            $journalMutant.all_records = @($journalMutant.all_records | Select-Object -First 8)
            $journalMutant.records = [uint64]8
        }
        $rejected = $false
        try {
            $null = Assert-MonitorFailureContainmentJsonContract `
                -Value $terminalMutant.failure_containment `
                -ExpectedMonotonicFrequency ([long]$historyStartup.monotonic_frequency)
            $null = Assert-MonitorFailedLauncherV2History `
                -Journal $journalMutant `
                -Terminal $terminalMutant `
                -TerminalSnapshot $failedHistoryTerminalSnapshot `
                -Startup $historyStartup `
                -Control $historyControl
        }
        catch { $rejected = $true }
        Assert-True $rejected "FAILED V2 containment/post-link history mutant was accepted: $case"
        $failedHistoryMutantsRejected++
    }

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 4
    $savedPayload = $mutant.all_records[1].body.payload
    $savedChannel = $mutant.all_records[1].body.channel
    $mutant.all_records[1].body.payload = $mutant.all_records[2].body.payload
    $mutant.all_records[1].body.channel = $mutant.all_records[2].body.channel
    $mutant.all_records[2].body.payload = $savedPayload
    $mutant.all_records[2].body.channel = $savedChannel
    $launcherCausalMutantsRejected.reordered_base = & $assertLauncherHistoryRejected $mutant $false "reordered_base"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 5
    $mutant.all_records[4].body.payload.event = "FUTURE_LAUNCHER_EVENT"
    $launcherCausalMutantsRejected.unknown_future_event = & $assertLauncherHistoryRejected $mutant $false "unknown_future_event"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 6
    $savedPayload = $mutant.all_records[4].body.payload
    $mutant.all_records[4].body.payload = $mutant.all_records[5].body.payload
    $mutant.all_records[5].body.payload = $savedPayload
    $launcherCausalMutantsRejected.publication_before_semantic = & $assertLauncherHistoryRejected $mutant $false "publication_before_semantic"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 7
    $savedPayload = $mutant.all_records[5].body.payload
    $savedChannel = $mutant.all_records[5].body.channel
    $mutant.all_records[5].body.payload = $mutant.all_records[6].body.payload
    $mutant.all_records[5].body.channel = $mutant.all_records[6].body.channel
    $mutant.all_records[6].body.payload = $savedPayload
    $mutant.all_records[6].body.channel = $savedChannel
    $launcherCausalMutantsRejected.draining_before_publication = & $assertLauncherHistoryRejected $mutant $false "draining_before_publication"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 8
    $savedPayload = $mutant.all_records[6].body.payload
    $savedChannel = $mutant.all_records[6].body.channel
    $mutant.all_records[6].body.payload = $mutant.all_records[7].body.payload
    $mutant.all_records[6].body.channel = $mutant.all_records[7].body.channel
    $mutant.all_records[7].body.payload = $savedPayload
    $mutant.all_records[7].body.channel = $savedChannel
    $launcherCausalMutantsRejected.exit_before_draining = & $assertLauncherHistoryRejected $mutant $false "exit_before_draining"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 8
    $mutant.all_records[7].body.payload.exit_code = 7
    $launcherCausalMutantsRejected.nonzero_campaign_exit = & $assertLauncherHistoryRejected $mutant $false "nonzero_campaign_exit"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 9
    $mutant.all_records[8].body.payload.symbol = "BTCUSDT"
    $mutant.all_records[8].body.payload.pid = [uint32]1001
    $launcherCausalMutantsRejected.duplicate_campaign_exit = & $assertLauncherHistoryRejected $mutant $false "duplicate_campaign_exit"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 10
    $mutant.all_records[9].body.channel = "VERIFICATION"
    $mutant.all_records[9].body.payload = ($canonicalForMutation.all_records[10].body.payload | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json)
    $launcherCausalMutantsRejected.verification_without_terminal_evaluation = & $assertLauncherHistoryRejected $mutant $false "verification_without_terminal_evaluation"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 12
    $mutant.all_records[11].body.payload.name = "btcusdt-python"
    $launcherCausalMutantsRejected.wrong_verifier_order = & $assertLauncherHistoryRejected $mutant $false "wrong_verifier_order"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 12
    $mutant.all_records[11].body.payload = ($canonicalForMutation.all_records[12].body.payload | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json)
    $launcherCausalMutantsRejected.verifier_complete_without_start = & $assertLauncherHistoryRejected $mutant $false "verifier_complete_without_start"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 13
    $mutant.all_records[12].body.payload.stderr_bytes = [uint64]1
    $launcherCausalMutantsRejected.verifier_stderr_nonzero = & $assertLauncherHistoryRejected $mutant $false "verifier_stderr_nonzero"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 13
    $mutant.all_records[12].body.payload.execution_sha256 = "not-a-digest"
    $launcherCausalMutantsRejected.verifier_execution_digest_invalid = & $assertLauncherHistoryRejected $mutant $false "verifier_execution_digest_invalid"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 23
    $mutant.all_records[22].body.payload.exit_code = 1
    $launcherCausalMutantsRejected.watchdog_nonzero_exit = & $assertLauncherHistoryRejected $mutant $false "watchdog_nonzero_exit"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 6
    $mutant.all_records[5].body.payload | Add-Member -NotePropertyName future_field -NotePropertyValue "mutant"
    $launcherCausalMutantsRejected.future_payload_field = & $assertLauncherHistoryRejected $mutant $false "future_payload_field"

    $mutant = & $newLauncherHistoryPrefix $canonicalForMutation 24
    $mutant.all_records += & $newHistoryEnvelope 24 ([uint64]($mutant.all_records[23].body.monotonic_tick + 1)) "LAUNCHER" ([pscustomobject]@{ event = "PREFLIGHT_PASSED"; startup_sha256 = $validDigest })
    $mutant.records = [uint64]$mutant.all_records.Count
    $launcherCausalMutantsRejected.event_after_terminal = & $assertLauncherHistoryRejected $mutant $true "event_after_terminal"

    $preEvaluationExitHistory = & $newTerminalLauncherHistory "PRE_EVALUATION"
    $terminalLauncherContract = Assert-LauncherEventHistory -Journal $preEvaluationExitHistory -Startup $historyStartup -Control $historyControl -TerminalComplete $true -SkipSingletonValidation
    Assert-True ($null -ne $terminalLauncherContract.preflight -and
        [string]$terminalLauncherContract.preflight.body.payload.event -ceq "PREFLIGHT_PASSED") `
        "Terminal launcher-history contract omitted its causal PREFLIGHT_PASSED record."
    $interleavedExitHistory = & $newTerminalLauncherHistory "INTERLEAVED"
    $null = Assert-LauncherEventHistory -Journal $interleavedExitHistory -Startup $historyStartup -Control $historyControl -TerminalComplete $true -SkipSingletonValidation
    $postEvaluationExactHistory = & $newTerminalLauncherHistory "POST_EVALUATION_EXACT"
    $null = Assert-LauncherEventHistory -Journal $postEvaluationExactHistory -Startup $historyStartup -Control $historyControl -TerminalComplete $true -SkipSingletonValidation
    $postEvaluationLateHistory = & $newTerminalLauncherHistory "POST_EVALUATION_LATE"
    $lateCoordinatorExitRejected = $false
    try { $null = Assert-LauncherEventHistory -Journal $postEvaluationLateHistory -Startup $historyStartup -Control $historyControl -TerminalComplete $true -SkipSingletonValidation }
    catch { $lateCoordinatorExitRejected = $true }
    Assert-True $lateCoordinatorExitRejected "A post-evaluation coordinator exit at deadline-plus-one tick was accepted."

    $verifierFunction = @($monitorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "Invoke-CurrentCampaignVerifier"
    }, $true))
    Assert-True ($verifierFunction.Count -eq 1) "Current verifier function extraction was ambiguous."
    Invoke-Expression $verifierFunction[0].Extent.Text
    $MaximumCurrentVerifierArtifactBytes = [uint64](32MB)
    $fakeVerifierScript = Join-Path $testRoot "fake-verifier.ps1"
$fakeVerifierSource = @'
param([string] $ReportPath)
[IO.File]::WriteAllText($ReportPath, "{`n  `"status`": `"PASS`"`n}`n", [Text.UTF8Encoding]::new($false))
'@
    [IO.File]::WriteAllText(
        $fakeVerifierScript,
        $fakeVerifierSource,
        [Text.UTF8Encoding]::new($false))
    $fakeVerifier = Invoke-CurrentCampaignVerifier `
        -Name "selftest-fake" `
        -Executable (Join-Path $PSHOME "powershell.exe") `
        -ArgumentsBeforeReport ([string[]]@("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $fakeVerifierScript)) `
        -WorkingDirectory $repo `
        -EnvironmentEntries $environmentEntries `
        -TimeoutSeconds 60
    Assert-True ($fakeVerifier.report.status -eq "PASS") "Bounded current verifier wrapper did not return its exact report."

    if ($TestRustVerifier) {
        if ([string]::IsNullOrWhiteSpace($CampaignDirectory)) { throw "-CampaignDirectory is required with -TestRustVerifier." }
        $campaign = (Resolve-Path -LiteralPath $CampaignDirectory).Path
        $rust = Invoke-CurrentCampaignVerifier `
            -Name "selftest-rust" `
            -Executable (Resolve-Path (Join-Path $repo "target\release\campaign_verify.exe")).Path `
            -ArgumentsBeforeReport ([string[]]@($campaign)) `
            -WorkingDirectory $repo `
            -EnvironmentEntries $environmentEntries `
            -TimeoutSeconds 300
        Assert-True ($rust.report.status -eq "PASS") "Current bounded Rust verifier did not PASS."
    }

    [pscustomobject][ordered]@{
        schema = "RawQualificationOpsSecuritySelfTestV1"
        status = "PASS"
        projection_start_gib = $startProjection
        projection_end_gib = $endProjection
        artificial_preflight_delay_s = $artificialPreflightDelaySeconds
        artificial_post_create_delay_s = $artificialPostCreateDelaySeconds
        capture_elapsed_after_delay_s = $captureElapsedAfterArtificialDelay
        terminal_deadline_capture_elapsed_s = $terminalDeadlineElapsed
        deadline_plus_one_tick_rejected = $true
        extended_total_deadline_boundaries = $extendedDeadlineBoundaryResults
        deadline_604921_rejected = [bool]$unboundedDeadlineRejected
        bounded_wrappers_with_post_exit_gate = [uint64]3
        bounded_job_drains_with_post_observation_gate = [uint64]5
        process_control_v2_mutants_rejected = [uint64]$processControlV2MutantsRejected
        named_job_collision_rejected_without_stale_error = $true
        outer_workload_runtime_isolation_proven = $true
        qpc_whole_seconds_floor_exact = $true
        coordinator_job_drain_relative_origin_bound = $true
        coordinator_job_drain_single_observation_accepted = [bool]$coordinatorSingleObservationAccepted
        coordinator_job_drain_exact_10s_accepted = [bool]$coordinatorDrainExactDeadlineAccepted
        coordinator_job_drain_10s_plus_one_rejected = [bool]$coordinatorDrainDeadlinePlusOneRejected
        coordinator_job_drain_nonidentity_frequency_history_accepted = [bool]$coordinatorNonidentityFrequencyHistoryAccepted
        coordinator_job_drain_nontrivial_floor_ms = [uint64]$coordinatorNontrivialRemainderMs
        command_call_arithmetic_mutant_rejected = $true
        required_terminal_topology_mutants_rejected = [uint64]$terminalTopologyMutantsRejected
        complete_terminal_topology_cross_bindings_audited = [uint64]$completeTopologyCrossBindingFragments.Count
        lowercase_modes_canonicalized = $true
        watchdog_clean_stop_deadline_bound = $true
        dual_launch_skew_plus_one_tick_rejected = $true
        pre_resume_qpc_exposes_post_resume_deschedule = $true
        bounded_process_post_resume_preemption_rejected = $true
        verifier_drain_post_exit_preemption_rejected = $true
        generation_commit_verification_deadline_plus_one_rejected = $true
        earlier_late_probe_not_hidden_by_latest = [bool]$hiddenLateProbeRejected
        historical_guardian_failure_not_hidden = [bool]$oldGuardianFailureRejected
        historical_guardian_gap_not_hidden = [bool]$historicalGuardianGapRejected
        guardian_stage_regression_rejected = [bool]$guardianStageRegressionRejected
        historical_clock_failure_not_hidden = [bool]$oldClockFailureRejected
        historical_disk_failure_not_hidden = [bool]$oldDiskFailureRejected
        historical_host_gap_not_hidden = [bool]$historicalHostGapRejected
        historical_launcher_duplicate_not_hidden = [bool]$oldDuplicateBindingRejected
        historical_launcher_failure_not_hidden = [bool]$oldLauncherFailureRejected
        launcher_canonical_prefixes_accepted = $canonicalPrefixCounts
        launcher_canonical_prefix_total = [uint64](($canonicalPrefixCounts.Values | Measure-Object -Sum).Sum)
        launcher_payload_numeric_fields_audited = $launcherPayloadNumericFields
        launcher_payload_exact_zero_fields_audited = $launcherPayloadExactZeroFields
        launcher_payload_numeric_type_mutants_rejected = $launcherPayloadNumericTypeMutantsRejected
        launcher_envelope_numeric_type_mutants_rejected = $launcherEnvelopeNumericTypeMutantsRejected
        launcher_payload_property_set_mutants_rejected = $launcherPayloadPropertySetMutantsRejected
        launcher_case_sensitive_event_channel_digest = $true
        qpc_causality_mutants_rejected = $qpcCausalityMutantsRejected
        launcher_causal_mutants_rejected = $launcherCausalMutantsRejected
        launcher_interleaved_exit_evaluation_order_accepted = $true
        draining_minimum_minus_one_rejected = [bool]$drainingMinMinusOneRejected
        draining_minimum_boundary_accepted = $true
        draining_maximum_boundary_accepted = $true
        draining_maximum_plus_one_rejected = [bool]$drainingMaxPlusOneRejected
        runtime_monotonic_frequency_exact = $true
        startup_frequency_type_mutants_rejected = $startupFrequencyTypeMutantsRejected
        event_driven_stage_matrix = [bool]$eventDrivenStageMatrixPassed
        launcher_exit_pre_evaluation_order_accepted = $true
        launcher_exit_post_evaluation_exact_deadline_accepted = $true
        launcher_exit_post_evaluation_plus_one_rejected = [bool]$lateCoordinatorExitRejected
        reduced_verifier_budget_exact = $true
        sequential_verifier_pid_reuse_distinct_creation_accepted = $true
        sequential_verifier_pid_reuse_same_creation_rejected = $true
        campaign_verified_swapped_report_hashes_rejected = $true
        terminal_foreign_pid_reuse_does_not_extend_commit = $true
        live_publication_toctou_barrier_present = $true
        verifier_artifact_policy_oversize_rejected = $true
        post_create_probe_deadline_plus_one_rejected = [bool]$latePostCreateProbeRejected
        post_create_probe_oversize_rejected = [bool]$oversizePostCreateProbeRejected
        post_create_probe_payload_mismatch_rejected = [bool]$payloadMismatchPostCreateProbeRejected
        post_create_recursive_mutants_rejected = [uint64]$postCreateRecursiveMutantsRejected
        host_recursive_mutants_rejected = [uint64]$hostRecursiveMutantsRejected
        provider_qpc_causality_mutants_rejected = $providerQpcCausalityMutantsRejected
        post_create_qpc_causality_mutants_rejected = $postCreateQpcCausalityMutantsRejected
        verifier_qpc_causality_mutants_rejected = $verifierQpcCausalityMutantsRejected
        powershell_singleton_canonical_mutants_rejected = $canonicalSingletonMutantsRejected
        evidence_child_directory_junction_rejected = [bool]$directoryReparseRejected
        evidence_child_file_symlink_rejected = [bool]$fileReparseRejected
        local_writer_toctou_residual_explicit = $monitorAst.Extent.Text.Contains('do not authenticate a malicious local writer')
        powershell_real_startup_control_bindings_ready_writer_fixtures = $true
        powershell_jsonl_canonical_mutants_rejected = $canonicalJournalMutantsRejected
        powershell_jsonl_partial_tail_preserves_complete_prefix = [bool]$partialJournalSummary.partial_tail
        rust_singleton_canonical_mutants_rejected = $rustSingletonMutantsRejected
        rust_singleton_type_mutants_rejected = $rustSingletonTypeMutantsRejected
        rust_cross_binding_mutants_rejected = $rustCrossBindingMutantsRejected
        rust_jsonl_canonical_mutants_rejected = $rustJournalMutantsRejected
        rust_semantic_type_mutants_rejected = $rustSemanticMutantsRejected
        rust_fixture_campaign_journal_records = [uint64]$rustJournalHealth.records
        failure_containment_mutants_rejected = $failureContainmentMutantsRejected
        terminal_v2_containment_mutants_rejected = $terminalV2ContainmentMutantsRejected
        failed_terminal_v2_history_mutants_rejected = $failedHistoryMutantsRejected
        verified_campaign_event_append_failure_preserves_empty_result_prefix = [bool]$verifiedEventAppendFailureRejected
        terminal_verifier_policy_mutants_rejected = [uint64]$terminalVerifierPolicyMutantsRejected
        full_monitor_complete_verifier_policy_resold_mutants_rejected = [uint64]$fullCompleteVerifierPolicyMutantsRejected
        full_monitor_failed_phases_authenticated = @($fullFailedMonitorFixtures.Keys)
        full_monitor_failed_phase_count = [uint64]$fullFailedMonitorFixtures.Count
        full_monitor_record0_without_operational_receipts_authenticated = $true
        full_monitor_unconfirmed_query_error_authenticated = $true
        full_monitor_unconfirmed_timeout_authenticated = $true
        full_monitor_failed_artifact_drift_reported = $true
        full_monitor_failed_artifact_absence_reported = $true
        full_monitor_resold_semantic_and_reparse_mutants_rejected = [uint64]$fullFailedMonitorMutantsRejected
        retained_open_journal_prefix_hash_matches_closed_prefix = $true
        retained_open_journal_cursor_mutant_rejected = [bool]$openJournalCursorRejected
        retained_closed_journal_snapshot_rejected = [bool]$closedJournalSnapshotRejected
        launcher_terminal_post_link_dependency_explicit = $true
        complete_terminal_null_evidence_accepted = [bool]$completeNullEvidenceAccepted
        complete_terminal_empty_failure_rejected = [bool]$completeEmptyFailureRejected
        failed_terminal_numeric_evidence_rejected = [bool]($failedNumericEvidenceRejected -and $failedNumericDigestRejected)
        failed_terminal_incomplete_containment_rejected = [bool]$invalidFailureContainmentRejected
        terminal_noncanonical_status_rejected = [bool]$noncanonicalTerminalStatusRejected
        terminal_coercible_non_string_status_rejected = [bool]$coercibleNonStringTerminalStatusRejected
        powershell_typed_string_null_coercion_reproduced = [bool]$typedStringNullMutant
        complete_terminal_exact_publication_ack = $true
        failed_terminal_exact_publication_ack = $true
        terminal_null_early_return_rejected = [bool]($completeAckMutantsRejected -and $failedAckMutantsRejected)
        terminal_standalone_null_pipeline_reproduced = [bool]$powerShellNullPipelineOutputReproduced
        terminal_post_link_early_return_mutant_rejected = $true
        terminal_success_console_outside_transaction = $true
        same_poll_terminal_exit_fresh_recompute = [bool]$freshTerminalEvidence
        same_poll_commit_deadline_fresh_observation = $true
        same_poll_legacy_negative_interval_reproduced = $true
        same_poll_state_deadlines_fresh_observation = $true
        same_poll_state_legacy_negative_intervals_reproduced = $true
        same_poll_negative_deadline_rejected = [bool]$negativeDeadlineRejected
        production_terminal_stage_after_final_journal_read = [bool]$productionTerminalStageAfterFinalJournalRead
        crossing_threshold_same_poll_emits_draining_first = [bool]$crossingPollDrainingWritten
        crossing_threshold_exit_order_is_draining_then_exit = (($crossingPollOrder -join ',') -eq "CAPTURE_DRAINING_STARTED,CAMPAIGN_PROCESS_EXITED")
        watchdog_ready_precedes_dual_launch = $true
        watchdog_expired_startup_fenced_main_job = $true
        watchdog_late_ready_rejected = [bool]$lateReadyRejected
        watchdog_ready_case_mismatched_key_rejected = [bool]$caseReadyRejected
        watchdog_replaced_ready_rejected = [bool]$replacedReadyRejected
        watchdog_ready_active_writer_race_retried = $true
        watchdog_ready_retained_handle_blocks_replacement = [bool]$raceReplacementBlocked
        watchdog_ready_retained_handle_allows_readers = $true
        watchdog_ready_retained_handle_finally_disposed = $true
        watchdog_ready_partial_file_rejected = [bool]$partialRaceReadyRejected
        watchdog_ready_retry_win32_allowlist = @(32, 33)
        dual_ready_host_telemetry_precedes_console = ($dynamicConsoleIndex -gt $dynamicTelemetryIndex)
        dual_readiness_receipt_precedes_console = ($dynamicReceiptIndex -gt $dynamicTelemetryIndex -and $dynamicConsoleIndex -gt $dynamicReceiptIndex)
        dual_readiness_cross_journal_receipt_valid = $true
        dual_readiness_cross_journal_mutants_rejected = $readinessReceiptMutantsRejected
        dual_ready_host_telemetry_written_once = (@($readinessTrace | Where-Object { $_ -eq "TELEMETRY:2" }).Count -eq 1)
        dual_ready_telemetry_cadence_cursor_advanced = $true
        readiness_loss_during_provider_blocks_telemetry_and_console = (-not [string]::IsNullOrWhiteSpace([string]$readinessLossCase.error))
        readiness_telemetry_failure_blocks_console = (-not [string]::IsNullOrWhiteSpace([string]$readinessTelemetryFailureCase.error))
        readiness_loss_after_host_sample_blocks_receipt_and_console = (-not [string]::IsNullOrWhiteSpace([string]$readinessPostTelemetryLossCase.error))
        coordinator_original_handle_live_after_candidate_tick = ($liveCheckedTick -ge $liveCandidateTick)
        coordinator_exit_between_tick_and_check_rejected = [bool]$exitBetweenTickAndCheckRejected
        coordinator_stale_pid_view_cannot_mask_original_exit = [bool]$exitBetweenTickAndCheckRejected
        coordinator_retained_handle_preserved_terminal_identity = $true
        coordinator_handle_closed_exactly_once = ([uint32]$retainedCoordinatorOwner.CloseCount -eq 1)
        watchdog_readonly_process_handle_reproduced = $true
        watchdog_retained_handle_closed_and_invalidated = ([IntPtr]$retainedWatchdogLaunch.ProcessHandle -eq [IntPtr]::Zero)
        watchdog_retained_handle_second_close_rejected = [bool]$retainedWatchdogSecondCloseRejected
        immediate_monitor_accepts_dual_ready_host_sample = [bool]$immediateReadyHostAccepted
        immediate_monitor_rejects_pre_readiness_host_sample = [bool]$preReadinessHostRejected
        monitor_live_freshness_bound_to_launcher_fsm = [bool]($capturingRequiresLiveFreshness -and -not $drainingRequiresLiveFreshness)
        monitor_draining_stale_telemetry_race_reproduced = [bool]$legacyDrainingRaceWouldRequireLiveFreshness
        monitor_capturing_late_telemetry_keeps_live_gate = [bool]($lateCapturingTelemetryWouldPreviouslyDisableFreshness -and $capturingRequiresLiveFreshness)
        monitor_missing_capture_stage_contract_rejected = [bool]$missingCaptureStageRejected
        monitor_publication_has_final_launcher_census = $true
        monitor_post_census_commands_are_pure = (($postPublicationCensusCommandNames -join ',') -ceq 'ConvertTo-Json,Get-MonitorEventDrivenStage,Get-RawQualificationWallNs,Where-Object')
        monitor_post_census_member_calls_are_pure = ($postPublicationCensusMemberCalls.Count -eq 5)
        monitor_post_census_freshness_crossing_rejected = [bool]($legacyPreCensusFreshnessWouldPass -and $postCensusFreshnessRejectsCrossing)
        monitor_live_heartbeat_override_cannot_weaken_30s_policy = $true
        monitor_campaign_journal_append_prefix_continuity = [bool]$continuityEquivalent
        monitor_campaign_journal_incremental_delta_only = [bool](@($continuityDeltaSnapshot.lines).Count -eq
            ([int][uint64]$rustJournalHealth.records - [int]$continuityPrefixRecordCount))
        monitor_campaign_journal_partial_tail_continuation = [bool]$partialContinuationEquivalent
        monitor_campaign_journal_incremental_cursor_mutants_rejected = [bool]($partialObservedMutationRejected -and $parseCursorDigestMutationRejected)
        monitor_campaign_journal_prefix_mutants_rejected = [bool]($continuityDigestMutantRejected -and $continuityByteMutantRejected)
        monitor_empty_frozen_prefix_identity_exact = [bool]($emptyFrozenPrefixAccepted -and $emptyFrozenWrongDigestRejected -and $emptyFrozenPositiveLengthRejected)
        monitor_verifier_name_collapse_mutant_rejected = $true
        monitor_exact_verifier_set_mutants_rejected = ($verifierSetDuplicateRejected -and
            $verifierSetMissingRejected -and $verifierSetExtraRejected -and $verifierSetCaseRejected)
        nonterminal_pid_reuse_with_clean_exit_accepted = [bool]$nonterminalReuse.pid_reused_after_exit
        nonterminal_pid_reuse_without_exit_rejected = [bool]$reuseWithoutExitRejected
        coordinator_disposition_truth_table = [bool]$coordinatorDispositionTruthTablePassed
        length_limited_prefix = $prefixText
        explicit_environment_no_secret_inheritance = $true
        explicit_environment_system_drive_exact = ([string]$envResult.system_drive -ceq $env:SystemDrive -and
            [string]$envResult.expanded_system_drive -ceq $env:SystemDrive)
        explicit_environment_literal_systemdrive_tree_absent = (-not (Test-Path -LiteralPath (Join-Path $testRoot '%SystemDrive%')))
        kill_on_close_killed_parent_and_grandchild = $true
        main_job_fenced_nested_probe_and_grandchild = $true
        watchdog_clean_stop = $true
        watchdog_touch_only_and_wall_mtime_mutation_fenced = $true
        watchdog_late_growth_and_stop_fenced = $true
        watchdog_mtime_mutation_was_permitted_by_filesystem = [bool]$mtimeMutationObserved
        watchdog_real_growth_retained_health = $true
        watchdog_truncation_fenced_descendants = $true
        watchdog_replacement_blocked_by_retained_identity = [bool]$replacementBlocked
        bounded_current_verifier_wrapper = $true
        bounded_rust_verifier = [bool]$TestRustVerifier
    } | ConvertTo-Json -Depth 10
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
        $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if (-not $resolvedTestRoot.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($resolvedTestRoot) -notlike "BinanceRawQualificationOpsTest-*") {
            throw "Ops self-test cleanup escaped its dedicated temporary directory."
        }
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force -ErrorAction Stop
    }
}
