[CmdletBinding()]
param([string]$Launcher = '', [Parameter(Mandatory=$true)][string]$EvidenceRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($Launcher -eq '') { $Launcher = Join-Path $PSScriptRoot 'run_hot_redundant_qualification.ps1' }
# Unit gate: execute exact function ASTs from the production launcher. Only
# process creation/wait is fake; this is explicitly NOT the live integration gate.
$resolved=[IO.Path]::GetFullPath($EvidenceRoot)
if ($resolved -notlike '*\.local\*') { throw 'Unit evidence must be isolated.' }
New-Item -ItemType Directory -Path $resolved -Force | Out-Null
Add-Type -TypeDefinition @'
using System;
public static class RawQualificationNative {
 public static uint ExitCode=0;
 public static string[] LastArguments=new string[0];
 public static object StartSuspendedInJobRetainedWithEnvironment(object j,string e,string[] a,string r,string o,string x,string[] v){return new Launch();}
 public static object StartSuspendedInJobRetained(object j,string e,string[] a,string r,string o,string x){LastArguments=(string[])a.Clone();return new Launch();}
 public static bool WaitForProcessExit(object h,int n){return true;}
 public static uint GetProcessExitCode(object h){return ExitCode;}
 public static bool CloseRetainedProcessHandle(object h){return true;}
 public static bool TerminateProcessHandle(object h,uint c){return true;}
 public class Launch { public uint ProcessId=123; public IntPtr ProcessHandle=IntPtr.Zero; public string ExactCommandLine="unit-fake-process"; }
}
'@
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Launcher,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors|Out-String) }
$wanted=@('New-SymbolState','Start-SymbolEpoch','Update-SymbolArtifactAndReadiness','Get-NextLiveArbiterSequence','Start-LiveArbiter','Stop-LiveArbiter','Rebind-LiveArbiter','Get-ServiceRelativePath','Write-ArbiterExpectedArtifactInventory','Test-ArbiterCompleteTerminal','Get-SymbolArtifactInventory','Sync-ServiceSourceInventory','Get-SuccessorTransitionEvidence','Add-ObserverFailure','Get-ArbiterClosedJournalPrefix')
foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){
 if($node.Name -in $wanted){ . ([scriptblock]::Create($node.Extent.Text)) }
}
$events=[Collections.Generic.List[object]]::new()
function Add-ServiceEvent {param($Channel,$Payload) $script:events.Add($Payload); return @{body=@{wall_ns=1}}}
function Write-RawQualificationDurableNewFile {param($Path,$Bytes) [IO.File]::WriteAllBytes($Path,$Bytes)}
function Write-RawQualificationDurableNewJson {param($Path,$Value) [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 20)); return 'unit-hash'}
function Get-RawQualificationSha256Bytes {param($Bytes) return 'unit-hash'}
function Get-RawQualificationSha256File {param($Path) $h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
$script:errors=[Collections.Generic.List[string]]::new()
function Check([bool]$ok,[string]$why){if(-not $ok){$script:errors.Add($why);Write-Output "FAIL: $why"}}
$runRoot=Join-Path $resolved ([guid]::NewGuid().ToString('N'))
$repo=$runRoot;$job=[IntPtr]::Zero;$capture='fake-capture';$liveArbiter='fake-arbiter';$ArbiterOverride='';$isContinuous=$true
$EpochWindowSeconds=40;$TotalSeconds=100;$overlapS=10;$primaryRotationS=30;$shadowRotationS=20;$segmentS=10;$primaryWindowS=100;$shadowWindowS=90
$origin=[Diagnostics.Stopwatch]::StartNew();$processIntervals=[Collections.Generic.List[object]]::new();$outerGaps=[Collections.Generic.List[object]]::new();$serviceReady=$true
$arbiterRoot=Join-Path $runRoot 'canonical-live';$verificationRoot=Join-Path $runRoot 'verification';New-Item -ItemType Directory -Path $arbiterRoot,$verificationRoot -Force|Out-Null
$sourceArtifacts=@{};$sourceArtifacts['BTCUSDT']=[Collections.Generic.List[string]]::new()
$arbiterStates=@{};$pendingSegmentVerifications=[Collections.Generic.List[object]]::new();$observerFailures=[Collections.Generic.List[string]]::new()
# A PowerShell function enumerates returned arrays. With exactly one source,
# parentheses therefore yield a scalar string: string + array concatenates
# paths unless the FIRST operand is explicitly collected as an array.
# Execute the exact production assignment AST, not a rewritten imitation.
$inventoryAssignment=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and
    $n.Extent.Text.StartsWith('$requiredArtifacts =')},$true))
if($inventoryAssignment.Count -ne 1){throw 'Expected exactly one requiredArtifacts production assignment.'}
$inventoryCases=@(
    @{name='empty';sources=@();current='C:\run\b\e1\hr-one';priors=@();expected=@('C:\run\b\e1\hr-one')},
    @{name='singleton-same-current';sources=@('C:\run\b\e1\hr-one');current='C:\run\b\e1\hr-one';priors=@();expected=@('C:\run\b\e1\hr-one')},
    @{name='singleton-new-current';sources=@('C:\run\b\e1\hr-one');current='C:\run\b\e2\hr-two';priors=@();expected=@('C:\run\b\e1\hr-one','C:\run\b\e2\hr-two')},
    @{name='singleton-explicit-prior';sources=@('C:\run\b\e1\hr-one');current='C:\run\b\e2\hr-two';priors=@('C:\run\b\e0\hr-zero');expected=@('C:\run\b\e1\hr-one','C:\run\b\e2\hr-two','C:\run\b\e0\hr-zero')},
    @{name='multiple-deduplicated';sources=@('C:\run\b\e1\hr-one','C:\run\b\e2\hr-two');current='C:\run\b\e3\hr-three';priors=@('C:\run\b\e1\hr-one');expected=@('C:\run\b\e1\hr-one','C:\run\b\e2\hr-two','C:\run\b\e3\hr-three')}
)
$inventoryResults=@();$symbolName='BTCUSDT'
foreach($inventoryCase in $inventoryCases){
    $sourceArtifacts[$symbolName]=[Collections.Generic.List[string]]::new()
    foreach($item in $inventoryCase.sources){$sourceArtifacts[$symbolName].Add($item)}
    $ArtifactRoot=$inventoryCase.current;$PriorArtifacts=[string[]]@($inventoryCase.priors)
    . ([scriptblock]::Create($inventoryAssignment[0].Extent.Text))
    $actual=[string[]]@($requiredArtifacts)
    Check (($actual -join '|') -ceq ($inventoryCase.expected -join '|')) ('Artifact inventory must preserve separate exact paths: '+$inventoryCase.name)
    $inventoryResults += [ordered]@{case=$inventoryCase.name;expected=@($inventoryCase.expected);actual=@($actual)}
}
$sourceArtifacts[$symbolName]=[Collections.Generic.List[string]]::new()
$oneRoot=Join-Path $runRoot 'singleton bootstrap';New-Item -ItemType Directory -Path $oneRoot -Force|Out-Null
$sourceArtifacts[$symbolName].Add($oneRoot)
$singleState=New-SymbolState -Symbol 'BTCUSDT' -Code 'b'
$null=Start-LiveArbiter -State $singleState -ArtifactRoot $oneRoot
$singletonLaunchArguments=[string[]]@([RawQualificationNative]::LastArguments)
Check ($arbiterStates[$symbolName].sourceArtifacts.Count -eq 1 -and $arbiterStates[$symbolName].sourceArtifacts[0] -ceq $oneRoot) 'First real Start-LiveArbiter AST must preserve the single original source path'
Check ($singletonLaunchArguments -notcontains '--prior-artifact') 'First arbiter must not receive a fabricated concatenated prior path'
$arbiterStates.Remove($symbolName);$processIntervals.Clear();$events.Clear()
$gapSymbolDir = Join-Path $arbiterRoot 'ETHUSDT'
New-Item -ItemType Directory -Path $gapSymbolDir -Force | Out-Null
foreach ($name in @('ETHUSDT-seg-0000.jsonl','ETHUSDT-seg-0002.jsonl','seg-0001.stdout.txt','seg-0002.stdout.txt','seg-0002.stderr.txt','ETHUSDT-audit-9.stdout.txt')) {
    [IO.File]::WriteAllText((Join-Path $gapSymbolDir $name), '')
}
$gapState = New-SymbolState -Symbol 'ETHUSDT' -Code 'e'
$null = Start-LiveArbiter -State $gapState -ArtifactRoot $oneRoot
Check ($arbiterStates['ETHUSDT'].sequence -eq 3) 'A missing journal index must not reuse an existing arbiter log sequence'
Check ([string]$arbiterStates['ETHUSDT'].stdout -like '*seg-0003.stdout.txt') 'Relaunch stdout must be the next free create-only log'
$arbiterStates.Remove('ETHUSDT');$processIntervals.Clear();$events.Clear()
$sourceArtifacts[$symbolName]=[Collections.Generic.List[string]]::new()
$state=New-SymbolState -Symbol 'BTCUSDT' -Code 'b';$state.EverReady=$true;$state.Epoch=1
$oldRoot=Join-Path $runRoot 'b/e1/hr-old';New-Item -ItemType Directory -Path $oldRoot -Force|Out-Null
$sourceArtifacts['BTCUSDT'].Add($oldRoot)
$arbiterStates['BTCUSDT']=[pscustomobject]@{artifact=$oldRoot}
$null=Start-SymbolEpoch -State $state
Check ($state.PSObject.Properties.Name -contains 'EpochReady') 'New epoch must have independent EpochReady state'
if($state.PSObject.Properties.Name -contains 'EpochReady'){Check (-not $state.EpochReady) 'Historical EverReady cannot make restarted epoch ready'}
$middle=Join-Path $state.OutputRoot 'hr-middle';New-Item -ItemType Directory -Path $middle|Out-Null
$ready='{"body":{"payload":{"event":"LANE_READY"}}}'
[IO.File]::WriteAllText((Join-Path $middle 'supervisor-events.jsonl'),$ready+"`n")
Update-SymbolArtifactAndReadiness -State $state
Check ([bool]$state.NeedsArbiterRebind) 'Restarted ready e2 must request arbiter rebind immediately'
Check ($sourceArtifacts['BTCUSDT'].Contains($middle)) 'Independent service source inventory must retain middle epoch'
Update-SymbolArtifactAndReadiness -State $state
if($null -ne (Get-Command Sync-ServiceSourceInventory -ErrorAction SilentlyContinue)){
    Check (@($events|Where-Object{$_.event -ceq 'RAW_ARTIFACT_DISCOVERED'}).Count -eq 1) 'Source admission must be journalled exactly once, independent of repeated polls'
}

# Resume repeatedly must preserve the middle source even when old arbiter is
# still bound to e1. Ground truth here is the raw service artifact inventory.
if(-not $sourceArtifacts['BTCUSDT'].Contains($middle)){$sourceArtifacts['BTCUSDT'].Add($middle)}
$third=Join-Path $runRoot 'b/e3/hr-third';New-Item -ItemType Directory -Path $third -Force|Out-Null
$sourceArtifacts['BTCUSDT'].Add($third)
$dir=Join-Path $arbiterRoot 'BTCUSDT';New-Item -ItemType Directory -Path $dir -Force|Out-Null
$journal=Join-Path $dir 'BTCUSDT-seg-0000.jsonl'
[IO.File]::WriteAllText($journal,'{"body":{"payload":{"event":"ARBITRATION_STARTED"}}}'+"`n")
$old=[pscustomobject]@{symbol='BTCUSDT';artifact=$oldRoot;launch=[RawQualificationNative+Launch]::new();sequence=0;dir=$dir;journal=$journal;auditLaunch=$null}
$arbiterStates['BTCUSDT']=$old
[RawQualificationNative]::ExitCode=60963
Rebind-LiveArbiter -State $state -NewArtifactRoot $third
$new=$arbiterStates['BTCUSDT']
Check ($new.PSObject.Properties.Name -contains 'sourceArtifacts') 'Arbiter must retain its service source-inventory snapshot'
if($new.PSObject.Properties.Name -contains 'sourceArtifacts'){Check ($new.sourceArtifacts -contains $middle) 'e1-to-e3 recovery must include e2 as prior'}
Check ($pendingSegmentVerifications.Count -eq 0) 'Interrupted segment cannot enter complete-segment promotion queue'
Check (@($events|Where-Object{$_.event -eq 'LIVE_ARBITRATION_SEGMENT_INTERRUPTED'}).Count -eq 1) 'Interrupted segment must have explicit preserved-prefix event'
if($null -ne (Get-Command Get-SuccessorTransitionEvidence -ErrorAction SilentlyContinue)){
    $prior=New-SymbolState 'BTCUSDT' 'b';$next=New-SymbolState 'BTCUSDT' 'b'
    $prior.LastExitCode=9;$prior.LastExitClean=$false;$next.EpochReady=$false
    $transition=Get-SuccessorTransitionEvidence $prior $next
    Check (-not $transition.predecessor_clean -and -not $transition.no_outer_gap) 'Final promotion cannot fabricate a clean predecessor or ready successor'
    $prior.LastExitCode=0;$prior.LastExitClean=$true;$next.EpochReady=$true
    $transition=Get-SuccessorTransitionEvidence $prior $next
    Check ($transition.predecessor_clean -and $transition.no_outer_gap) 'Positive control: clean ready overlap remains representable'
    $prior.OuterGap=[pscustomobject]@{gap_id=1}
    Check (-not (Get-SuccessorTransitionEvidence $prior $next).no_outer_gap) 'Final promotion must preserve an already recorded outer gap'
    $failureMaps=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.HashtableAst] -and
        $n.Extent.Text -match 'event\s*=\s*"OBSERVER_FAILED"'},$true))
    Check ($failureMaps.Count -gt 0) 'Failure event source inventory must not be empty'
    Check (@($failureMaps|Where-Object{$_.Extent.Text -notmatch 'failure_id\s*='}).Count -eq 0) 'Every OBSERVER_FAILED source site must explicitly bind failure_id'
    $ids=@($events|Where-Object{$_.event -ceq 'OBSERVER_FAILED'}|ForEach-Object{$_.failure_id}|Sort-Object -Unique)
    Check ($ids.Count -eq $observerFailures.Count -and @($ids|Where-Object{$_ -notin $observerFailures}).Count -eq 0) 'Observed failure event IDs must match the preserved terminal inventory'
}

if($null -ne (Get-Command Test-ArbiterCompleteTerminal -ErrorAction SilentlyContinue)){
    $complete='{"body":{"payload":{"event":"ARBITRATION_TERMINAL","status":"COMPLETE"}}}'
    [IO.File]::WriteAllText($new.journal,$complete)
    Check (-not (Test-ArbiterCompleteTerminal $new.journal)) 'A torn terminal without newline is not a complete segment'
    [IO.File]::WriteAllText($new.journal,$complete+"`n")
    Check (Test-ArbiterCompleteTerminal $new.journal) 'Positive control: complete terminal must be recognized'
    [RawQualificationNative]::ExitCode=0
    Rebind-LiveArbiter -State $state -NewArtifactRoot $third
    Check ($pendingSegmentVerifications.Count -eq 1) 'A clean sealed segment should enter independent bounded verification'
    $expected=Get-Content -LiteralPath $pendingSegmentVerifications[0].expectedInventory -Raw|ConvertFrom-Json
    Check ($expected.artifacts -contains $middle -and $expected.artifacts.Count -eq 3) 'Expected manifest must preserve all prior sources, including middle epoch'
    Check ($expected.journals.Count -eq 2 -and $expected.journals[-1].sha256 -ceq (Get-RawQualificationSha256File $new.journal)) 'Prefix manifest must include prior identity context and bind the closing segment bytes'
    $future=Join-Path $new.dir 'BTCUSDT-seg-9999.jsonl';[IO.File]::WriteAllText($future,'future')
    $prefix=@(Get-ArbiterClosedJournalPrefix -Arbiter $new)
    Check ($prefix.Count -eq 2 -and $prefix -notcontains $future -and $prefix[0] -ceq $journal) 'Closed prefix must begin at STARTED and exclude every future journal'
    $orphan=Join-Path $runRoot 'b/e4/hr-between-polls';New-Item -ItemType Directory -Path $orphan -Force|Out-Null
    Sync-ServiceSourceInventory
    Check ($sourceArtifacts['BTCUSDT'].Contains($orphan)) 'Final owned-directory discovery must retain raw created between polls'
    Check ($new.sourceArtifacts -notcontains $orphan) 'A later discovery cannot rewrite an earlier segment inventory snapshot'
}

$result=[ordered]@{schema='LauncherRecoveryUnitGateV1';scope='Exact launcher function ASTs, fake process boundary only; live integration remains separate';launcher_sha256=(Get-RawQualificationSha256File $Launcher);errors=@($script:errors);passed=($script:errors.Count -eq 0);fixture=$runRoot;inventory_cases=$inventoryResults;singleton_native_arguments=$singletonLaunchArguments}
$result|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $resolved 'result.json') -Encoding UTF8
$result|ConvertTo-Json -Depth 5
if($script:errors.Count){exit 2}
