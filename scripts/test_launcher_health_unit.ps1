[CmdletBinding()]
param([string]$Launcher = '', [Parameter(Mandatory=$true)][string]$EvidenceRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($Launcher -eq ''){$Launcher=Join-Path $PSScriptRoot 'run_hot_redundant_qualification.ps1'}
$resolved=[IO.Path]::GetFullPath($EvidenceRoot)
if($resolved -notlike '*\.local\*'){throw 'Unit evidence must be isolated.'}
New-Item -ItemType Directory -Path $resolved -Force | Out-Null
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Launcher,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ($parseErrors|Out-String)}
$wanted=@('Read-CanonicalPublicationTail','Update-CanonicalStreamHealth','Add-ObserverFailure','Get-ServiceMutexName','Get-LivePrefixAuditArguments','Get-LivePrefixAuditResult')
foreach($node in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){
    if($node.Name -in $wanted){. ([scriptblock]::Create($node.Extent.Text))}
}
$hasNewHealth=$null -ne (Get-Command Update-CanonicalStreamHealth -ErrorAction SilentlyContinue)
if(-not $hasNewHealth){
    # Baseline comparison executes its ACTUAL byte-growth branch, not a
    # reimplementation of the defect in the test.
    $legacy=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and
        $n.Extent.Text.StartsWith('if ($arbiterAlive) {') -and $n.Extent.Text.Contains('$arbiter.lastAuditedSize')},$true))
    if($legacy.Count -ne 1){throw 'Expected one baseline byte-growth health branch.'}
    $legacyBranch=[scriptblock]::Create($legacy[0].Extent.Text)
}
$events=[Collections.Generic.List[object]]::new();$errors=[Collections.Generic.List[string]]::new()
function Add-ServiceEvent {param($Channel,$Payload)$events.Add($Payload)}
function Check([bool]$ok,[string]$why){if(-not $ok){$errors.Add($why);Write-Output "FAIL: $why"}}
function Get-RawQualificationSha256Bytes {param($Bytes)$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
$canonicalStreamHealth=@{};$observerFailures=[Collections.Generic.List[string]]::new();$TelemetryIntervalSeconds=10
$path=Join-Path $resolved ('sample-'+[guid]::NewGuid().ToString('N')+'.jsonl')
$arbiter=[pscustomobject]@{symbol='BTCUSDT';sequence=0;journal=$path;lastAuditedSize=$null;stallTicks=0;rebindActive=$false;rebindLaunchedAt=$null}
$origin=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=[double]0}}
function Sample([double]$Seconds,[string]$Event,[uint64]$Id){
    $origin.Elapsed.TotalSeconds=$Seconds
    $payload=if($Event -ceq 'TRADE_OBSERVATION'){@{event=$Event;trade_id=$Id}}else{@{event=$Event;final_sequence=$Id}}
    [IO.File]::AppendAllText($path,(@{body=@{payload=$payload}}|ConvertTo-Json -Depth 6 -Compress)+"`n")
    if($hasNewHealth){Update-CanonicalStreamHealth -Arbiter $arbiter -ProcessAlive $true}
    else{$arbiterAlive=$true;$journalSize=(Get-Item $path).Length;. $legacyBranch}
}
Sample 0 'TRADE_OBSERVATION' 1
Sample 0 'DEPTH_OBSERVATION' 100
Sample 30 'DEPTH_OBSERVATION' 101
Sample 70 'DEPTH_OBSERVATION' 102
Check (@($events|Where-Object{$_.event -ceq 'OBSERVER_FAILED' -and $_.observer -ceq 'LIVE_ARBITRATION_BTCUSDT_trades'}).Count -eq 1) 'Growing depth bytes must not conceal stalled canonical trades'
Check (@($events|Where-Object{$_.event -ceq 'OBSERVER_FAILED' -and $_.observer -ceq 'LIVE_ARBITRATION_BTCUSDT_depth'}).Count -eq 0) 'Publishing depth must not be labelled stalled merely because trades stopped'
Sample 80 'TRADE_OBSERVATION' 2
Sample 80 'DEPTH_OBSERVATION' 103
Sample 150 'DEPTH_OBSERVATION' 104
Check (@($events|Where-Object{$_.event -ceq 'OBSERVER_FAILED' -and $_.observer -ceq 'LIVE_ARBITRATION_BTCUSDT_trades'}).Count -eq 2) 'A second trade stall after recovery must retain a separate incident'
if($hasNewHealth){
    [IO.File]::AppendAllText($path,'{"body":{"payload":{"event":"TRADE_OBSERVATION","trade_id":999')
    $tail=Read-CanonicalPublicationTail $path
    Check ($tail.trades -eq 2 -and $tail.depth -eq 104) 'Incomplete appended JSON cannot advance telemetry cursors'
    $production='C:\workspace\Binance';$first='C:\workspace\.local\candidate-a\Binance';$second='C:\workspace\.local\candidate-b\Binance'
    $prod=Get-ServiceMutexName $production $false ''
    $test=Get-ServiceMutexName $first $true 'C:\candidate-bin'
    Check ($prod -ceq 'Global\BinanceHotRedundantQualificationV1') 'Default service must retain the operational mutex'
    Check ($test -ceq (Get-ServiceMutexName ($first.ToUpperInvariant()+'\') $true 'C:\candidate-bin')) 'Equivalent candidate roots must exclude each other'
    Check ($test -cne (Get-ServiceMutexName $second $true 'C:\candidate-bin')) 'Distinct isolated candidate roots must not share the operational lock'
    Check ((Get-ServiceMutexName $first $false 'C:\candidate-bin') -ceq $prod) 'Binary override alone cannot bypass the production mutex'
    $rejected=$false;try{$null=Get-ServiceMutexName 'C:\workspace\.local-not-isolated\Binance' $true 'C:\candidate-bin'}catch{$rejected=$true}
    Check $rejected 'Test mutex requires an exact .local path segment'
    $auditArgs=@(Get-LivePrefixAuditArguments -JournalRoot 'C:\candidate\arbitration\BTCUSDT' -ArtifactRoot 'C:\candidate\b')
    Check (($auditArgs -join '|') -ceq '--journal-root|C:\candidate\arbitration\BTCUSDT|--incremental|--oracle-artifact|C:\candidate\b') 'Live audit must include whole-chain identity context without mutable inventory or single-tail flags'
    $reportPath=Join-Path $resolved 'live-prefix-report.json'
    $liveReport=[ordered]@{schema='LiveArbitrationVerificationV2';status='PASS';audit_scope='LIVE_PREFIX';journal_prefix=$false;coverage_exhaustive=$false;oracle_identity='PASS'}
    function Save-LiveReport {$liveReport|ConvertTo-Json|Set-Content -LiteralPath $reportPath -Encoding UTF8}
    Save-LiveReport
    Check ((Get-LivePrefixAuditResult -ExitCode 0 -ReportPath $reportPath) -ceq 'PASS') 'Exact bounded LIVE_PREFIX oracle PASS must pass'
    Check ((Get-LivePrefixAuditResult -ExitCode 2 -ReportPath $reportPath) -ceq 'FAIL') 'Non-zero auditor exit cannot be rescued by a PASS-looking report'
    $liveReport.oracle_identity='SKIPPED';Save-LiveReport
    Check ((Get-LivePrefixAuditResult -ExitCode 0 -ReportPath $reportPath) -ceq 'UNPROVEN') 'Empty prefix oracle SKIPPED is unproven, never PASS'
    $liveReport.oracle_identity='PASS';$liveReport.coverage_exhaustive=$true;Save-LiveReport
    Check ((Get-LivePrefixAuditResult -ExitCode 0 -ReportPath $reportPath) -ceq 'FAIL') 'Live audit must reject a false exhaustive claim'
    $liveReport.coverage_exhaustive=$false;$liveReport.audit_scope='SEALED_DRAIN';Save-LiveReport
    Check ((Get-LivePrefixAuditResult -ExitCode 0 -ReportPath $reportPath) -ceq 'FAIL') 'Closed drain report cannot masquerade as live audit'
    $liveReport.audit_scope='LIVE_PREFIX';$liveReport.journal_prefix='false';Save-LiveReport
    Check ((Get-LivePrefixAuditResult -ExitCode 0 -ReportPath $reportPath) -ceq 'FAIL') 'String booleans cannot masquerade as scoped report flags'
    [IO.File]::WriteAllText($reportPath,'{"status":"PASS"')
    Check ((Get-LivePrefixAuditResult -ExitCode 0 -ReportPath $reportPath) -ceq 'FAIL') 'Truncated report cannot be promoted by successful process exit'
}
$result=[ordered]@{schema='LauncherHealthUnitGateV1';scope='Exact current health functions or exact baseline AST byte-growth branch; simulated monotonic time and generated journal';launcher_sha256=(Get-RawQualificationSha256Bytes ([IO.File]::ReadAllBytes($Launcher)));passed=($errors.Count -eq 0);errors=@($errors);events=@($events)}
$result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $resolved 'result.json') -Encoding UTF8
$result|ConvertTo-Json -Depth 8
if($errors.Count){exit 2}
