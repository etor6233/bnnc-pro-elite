[CmdletBinding()]
param([string]$Launcher = '', [Parameter(Mandatory=$true)][string]$EvidenceRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Launcher -eq '') { $Launcher = Join-Path $PSScriptRoot 'run_hot_redundant_qualification.ps1' }
$resolved = [IO.Path]::GetFullPath($EvidenceRoot)
if ($resolved -notlike '*\.local\*') { throw 'Unit evidence must be isolated.' }
New-Item -ItemType Directory -Path $resolved -Force | Out-Null
# Unit state-machine gate. Exact launcher ASTs run; native process creation is
# simulated. This does not qualify kernel ETW or the real elevated rotation.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
public static class RawQualificationNative {
 public static long Next=10;
 public static HashSet<long> Exited=new HashSet<long>();
 public static HashSet<long> Closed=new HashSet<long>();
 public static object StartSuspendedInJobRetained(object j,string e,string[] a,string r,string o,string x){return new Launch(++Next);}
 public static bool WaitForProcessExit(IntPtr h,int n){return Exited.Contains(h.ToInt64());}
 public static uint GetProcessExitCode(IntPtr h){return 0;}
 public static bool CloseRetainedProcessHandle(Launch l){Closed.Add(l.ProcessHandle.ToInt64());return true;}
 public static bool TerminateProcessHandle(IntPtr h,uint c){Exited.Add(h.ToInt64());return true;}
 public class Launch { public uint ProcessId; public IntPtr ProcessHandle; public Launch(long n){ProcessId=(uint)n;ProcessHandle=new IntPtr(n);} }
}
'@
$tokens=$null; $parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Launcher,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$wanted=@('Start-ServiceObserverWindow','Stop-ServiceObserverWindow','Update-ServiceObserverWindows','Add-ObserverFailure','Get-ServiceRelativePath','Test-ObserverKernelOwnership','Stop-OwnedKernelSession')
foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
    if($node.Name -in $wanted){ . ([scriptblock]::Create($node.Extent.Text)) }
}
$script:wall=[uint64]1900000000000000000
function Get-RawQualificationWallNs { $script:wall += 1000000; return $script:wall }
$events=[Collections.Generic.List[object]]::new()
function Add-ServiceEvent {param($Channel,$Payload) $script:events.Add($Payload)}
function Write-RawQualificationDurableNewFile {param($Path,$Bytes) [IO.File]::WriteAllBytes($Path,$Bytes)}
function Write-RawQualificationDurableNewJson {param($Path,$Value) [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 10));return 'unit-hash'}
$script:logmanCalls=[Collections.Generic.List[object]]::new()
$script:logmanStopExit=0;$script:logmanQueryExit=-2144337918
function Invoke-ServiceLogman {param([string[]]$Arguments)$script:logmanCalls.Add($Arguments);return [ordered]@{exit_code=$(if($Arguments[0] -ceq 'stop'){$script:logmanStopExit}else{$script:logmanQueryExit});output=@('unit-control-result')}}
$errors=[Collections.Generic.List[string]]::new()
function Check([bool]$ok,[string]$why) { if(-not $ok){$errors.Add($why);Write-Output "FAIL: $why"} }
function Publish-Ready($Window) {
    [IO.File]::WriteAllText($Window.kernelOut,([ordered]@{schema='KernelNetworkTraceReadyV1';status='READY';session_name=$Window.session;etl_path=$Window.etl;stop_file=$Window.kernelStop}|ConvertTo-Json -Compress)+"`n")
    New-Item -ItemType Directory -Path $Window.networkRoot -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $Window.networkRoot 'network-witness-startup.json'),
        ('{"schema":"RawQualificationNetworkWitnessStartupV2","observation_id":"'+$Window.identity+'"}'))
}
function Clock([double]$Seconds){return [pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=$Seconds}}}
$runRoot=Join-Path $resolved ([guid]::NewGuid().ToString('N'))
$observerRoot=Join-Path $runRoot 'obs';$repo=$runRoot;$job=[IntPtr]::Zero
$kernelTrace='unit-kernel';$powershell='unit-powershell';$networkWitnessScript='unit-witness';$KernelTraceMiB=100;$etwDeadline=1820
$observerWindows=[Collections.Generic.List[object]]::new();$observerFailures=[Collections.Generic.List[string]]::new()
$observerSkipped=$false;$isContinuous=$true;$EpochWindowSeconds=20
Start-ServiceObserverWindow
$one=$observerWindows[0]
Check ($one.ready -eq 0) 'New window cannot inherit READY'
Publish-Ready $one
Update-ServiceObserverWindows -NoRotation
Check ($one.ready -gt 0 -and $one.stop -eq 0) 'First pair must require two independent readiness files'
Check ($one.identity -match '^observed-[0-9a-f]{12}$') 'Observer nonce must satisfy actual kernel verifier identity contract'
$one.clock=Clock 20
Update-ServiceObserverWindows
Check ($observerWindows.Count -eq 2 -and $one.stop -eq 0) 'Rotation must overlap old capture until successor is ready'
$two=$observerWindows[1]
Check ($one.identity -cne $two.identity -and $one.kernelRoot -cne $two.kernelRoot) 'Each rotation requires unique identities and roots'
Update-ServiceObserverWindows
Check ($one.stop -eq 0 -and $observerWindows.Count -eq 2) 'Partial startup cannot stop predecessor or create a third pair'
Publish-Ready $two
Update-ServiceObserverWindows
Check ($two.ready -gt 0 -and $one.stop -ge $two.ready) 'Successor must be ready before predecessor stop request'
Check ((Test-Path $one.kernelStop) -and (Test-Path $one.networkStop)) 'Both owned stop files must be created'
$readyIndex=-1;$stopIndex=-1
for($i=0;$i -lt $events.Count;$i++){
    if($events[$i].event -ceq 'OBSERVER_WINDOW_READY' -and $events[$i].epoch -eq 2){$readyIndex=$i}
    if($events[$i].event -ceq 'OBSERVER_WINDOW_STOP_REQUESTED' -and $events[$i].epoch -eq 1 -and $stopIndex -eq -1){$stopIndex=$i}
}
Check ($readyIndex -ge 0 -and $stopIndex -gt $readyIndex) 'Both READY events must precede first predecessor STOP event'
$null=[RawQualificationNative]::Exited.Add($one.kernel.ProcessHandle.ToInt64())
$null=[RawQualificationNative]::Exited.Add($one.network.ProcessHandle.ToInt64())
Update-ServiceObserverWindows
Check ($null -eq $one.kernel -and $null -eq $one.network -and [RawQualificationNative]::Closed.Count -eq 2) 'Retired process handles must close during capture, not accumulate until terminal'
Check ($observerFailures.Count -eq 0) 'Cooperative overlap rotation must not introduce an observability failure'
$two.clock=Clock 20
Update-ServiceObserverWindows
Check ($observerWindows.Count -eq 3) 'Rotation must remain repeatable after retired handles close'
$three=$observerWindows[2];Publish-Ready $three;Update-ServiceObserverWindows
$two.stopClock=Clock 31
Update-ServiceObserverWindows
Check (@($observerFailures | Where-Object {$_ -like '*STOP_DEADLINE_EXCEEDED*'}).Count -eq 2) 'Both stop timeouts must remain explicit even after forced cleanup'
Check ($null -eq $two.kernel -and $null -eq $two.network) 'Timed-out owned processes must release handles'
$cleanupBefore=$script:logmanCalls.Count
$null=[RawQualificationNative]::Exited.Add($three.kernel.ProcessHandle.ToInt64())
Update-ServiceObserverWindows
Check (@($observerFailures | Where-Object {$_ -like '*EXITED_BEFORE_STOP_REQUEST*'}).Count -eq 1) 'Unexpected observer death cannot be hidden by a live sibling or READY history'
Check ($observerWindows.Count -eq 4) 'An unexpectedly dead active observer pair must initiate replacement'
Check ($script:logmanCalls.Count -eq $cleanupBefore + 2) 'An unexpectedly killed owned kernel controller must stop/query its orphan session immediately'
if($null -ne (Get-Command Stop-OwnedKernelSession -ErrorAction SilentlyContinue)){
    $four=$observerWindows[3]
    $before=$script:logmanCalls.Count
    Stop-OwnedKernelSession -Window $four -Reason 'unit-collision-no-ready'
    Check ($script:logmanCalls.Count -eq $before) 'A colliding startup without exact READY must never stop an existing foreign session'
    Publish-Ready $four
    $ready=Get-Content -LiteralPath $four.kernelOut -Raw|ConvertFrom-Json
    $ready.stop_file='C:\foreign\stop.request'
    [IO.File]::WriteAllText($four.kernelOut,($ready|ConvertTo-Json -Compress)+"`n")
    Stop-OwnedKernelSession -Window $four -Reason 'unit-mismatched-stop'
    Check ($script:logmanCalls.Count -eq $before) 'READY with another stop-file path does not establish ownership'
    Start-ServiceObserverWindow
    $five=$observerWindows[4];Publish-Ready $five
    $script:logmanQueryExit=5
    Stop-OwnedKernelSession -Window $five -Reason 'unit-query-error'
    Check ($five.cleanupStatus -cne 'ABSENT') 'A failed query is not evidence that an orphan session is gone'
    $script:logmanQueryExit=-2144337918;$script:logmanStopExit=5
    Stop-OwnedKernelSession -Window $five -Reason 'unit-stop-error'
    Check ($five.cleanupStatus -cne 'ABSENT') 'A failed stop must remain explicit even if a later query returns not-found'
    Check (@(Get-ChildItem -LiteralPath $five.root -Filter 'kernel-cleanup-*.json' -File).Count -eq 2) 'Control cleanup evidence must be retained outside the exact kernel artifact file set'
    Check (@($events|Where-Object{$_.event -ceq 'OBSERVER_FAILED' -and ($_.PSObject.Properties.Name -notcontains 'failure_id' -and -not $_.Contains('failure_id'))}).Count -eq 0) 'Every observer failure event needs an explicit terminal inventory identity'
}
$hash=[Security.Cryptography.SHA256]::Create()
try {$sha=([BitConverter]::ToString($hash.ComputeHash([IO.File]::ReadAllBytes($Launcher)))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
$result=[ordered]@{schema='LauncherObserverUnitGateV1';scope='Exact launcher ASTs with simulated process boundary; real elevated ETW gate remains OPEN';launcher_sha256=$sha;passed=($errors.Count -eq 0);errors=@($errors);events=@($events);fixture=$runRoot}
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $resolved 'result.json') -Encoding UTF8
Write-Output ($result | ConvertTo-Json -Depth 8)
if($errors.Count){exit 2}
