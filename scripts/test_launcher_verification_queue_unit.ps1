[CmdletBinding()]
param([string]$Launcher='', [Parameter(Mandatory=$true)][string]$EvidenceRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($Launcher -eq ''){$Launcher=Join-Path $PSScriptRoot 'run_hot_redundant_qualification.ps1'}
$resolved=[IO.Path]::GetFullPath($EvidenceRoot)
if($resolved -notlike '*\.local\*'){throw 'Unit evidence must be isolated.'}
New-Item -ItemType Directory -Path $resolved -Force|Out-Null
Add-Type -TypeDefinition @'
using System;
public static class RawQualificationNative {
 public static bool Exited=false;
 public static int Started=0;
 public static string[] LastArguments;
 public static object StartSuspendedInJobRetained(object j,string e,string[] a,string r,string o,string x){Started++;LastArguments=a;return new Launch();}
 public static bool WaitForProcessExit(object h,int n){return Exited;}
 public static uint GetProcessExitCode(object h){return 0;}
 public static bool CloseRetainedProcessHandle(object h){return true;}
 public static bool TerminateProcessHandle(object h,uint c){return true;}
 public class Launch { public uint ProcessId=123; public IntPtr ProcessHandle=IntPtr.Zero; }
}
'@
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Launcher,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ($parseErrors|Out-String)}
$wanted=@('Start-EpochVerificationTask','Start-QueuedEpochVerificationTask','Start-SegmentVerificationTask','Process-VerificationTasks')
foreach($node in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){
    if($node.Name -in $wanted){. ([scriptblock]::Create($node.Extent.Text))}
}
$script:events=[Collections.Generic.List[object]]::new();$errors=[Collections.Generic.List[string]]::new()
function Add-ServiceEvent {param($Channel,$Payload)$script:events.Add($Payload)}
function Check([bool]$ok,[string]$why){if(-not $ok){$errors.Add($why);Write-Output "FAIL: $why"}}
function Write-RawQualificationDurableNewFile {param($Path,$Bytes)[IO.File]::WriteAllBytes($Path,$Bytes)}
function Get-RawQualificationSha256File {param($Path)return 'unit-sha'}
$repo=$resolved;$verificationRoot=$resolved;$job=[IntPtr]::Zero;$rustVerifier='unit-verifier';$liveArbiterVerify='unit-arbiter-verifier';$arbiterAuditDeadlineSeconds=240
$pendingEpochVerifications=[Collections.Generic.List[object]]::new();$pendingSegmentVerifications=[Collections.Generic.List[object]]::new()
$verificationTasks=[Collections.Generic.List[object]]::new();$verifiedWindows=[Collections.Generic.List[object]]::new();$observerFailures=[Collections.Generic.List[string]]::new()
$maximumConcurrentWindowVerifiers=2
for($i=1;$i -le 10;$i++){Start-EpochVerificationTask -Artifact ([pscustomobject]@{symbol='BTCUSDT';root='unit-artifact';coverage_seconds=20}) -Epoch $i}
Check ([RawQualificationNative]::Started -eq 0 -and $pendingEpochVerifications.Count -eq 10) 'Enqueue must not spawn raw oracles synchronously'
Process-VerificationTasks
Check ($verificationTasks.Count -eq 2 -and $pendingEpochVerifications.Count -eq 8) 'Expensive window verifiers must respect the two-process bound'
Process-VerificationTasks
Check ([RawQualificationNative]::Started -eq 2) 'A queue backlog must not bypass concurrency limits on later ticks'
$verificationTasks.RemoveAt(0)
Process-VerificationTasks
Check ($verificationTasks.Count -eq 2 -and [RawQualificationNative]::Started -eq 3) 'A released slot must resume queued work'
# Semantic negative control: PASS of structure with SKIPPED oracle identity
# must never emit a segment-verification success or start Python promotion.
$verificationTasks.Clear();$pendingEpochVerifications.Clear()
Start-SegmentVerificationTask -Entry ([pscustomobject]@{symbol='BTCUSDT';sequence=77;journal='unit-journal';dir='unit-journal-root';artifact='unit-artifact';expectedInventory='unit-manifest'})
Check ([RawQualificationNative]::LastArguments -contains '--journal-prefix' -and [RawQualificationNative]::LastArguments -contains '--journal-root' -and [RawQualificationNative]::LastArguments -notcontains '--tail-segment-only') 'Segment audit must use an immutable full-context prefix instead of an isolated resume tail'
$task=$verificationTasks[0]
[IO.File]::WriteAllText($task.rustStdout,'{"schema":"LiveArbitrationVerificationV2","status":"PASS","oracle_identity":"SKIPPED","artifact_coverage":"PASS","terminal_complete":true,"expected_artifact_inventory_sha256":"unit-sha"}'+"`n")
$before=[RawQualificationNative]::Started
[RawQualificationNative]::Exited=$true
Process-VerificationTasks
Check ($verificationTasks.Count -eq 0 -and [RawQualificationNative]::Started -eq $before) 'SKIPPED oracle identity must reject the segment rather than start a promotion stage'
Check ($observerFailures.Contains('SEALED_WINDOW_VERIFICATION_REJECTED')) 'Incomplete oracle proof must remain visible as a rejection'
$hash=[Security.Cryptography.SHA256]::Create()
try{$sha=([BitConverter]::ToString($hash.ComputeHash([IO.File]::ReadAllBytes($Launcher)))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
$result=[ordered]@{schema='LauncherVerifierQueueUnitGateV1';scope='Exact launcher queue/state functions, fake process and verifier output boundaries; not real oracle integration';launcher_sha256=$sha;passed=($errors.Count -eq 0);errors=@($errors);events=@($events)}
$result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $resolved 'result.json') -Encoding UTF8
$result|ConvertTo-Json -Depth 8
if($errors.Count){exit 2}
