[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string] $ReleaseBinRoot,
    [Parameter(Mandatory=$true)][string] $EvidenceRoot,
    [ValidateRange(3,10)][int] $MinimumWindows = 3,
    [ValidateRange(180,1800)][int] $DeadlineSeconds = 900
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$bins=[IO.Path]::GetFullPath($ReleaseBinRoot)
$evidence=[IO.Path]::GetFullPath($EvidenceRoot)
foreach($path in @($repo,$bins,$evidence)){
    if(@($path -split '[\\/]'|Where-Object{$_ -ceq '.local'}).Count -eq 0){throw 'All elevated gate paths must be isolated inside an exact .local directory.'}
}
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'This real observer gate requires an elevated shell; no mock or skipped-observer PASS is accepted.'
}
. (Join-Path $PSScriptRoot 'RawQualification.Windows.ps1')
foreach($path in @($repo,$bins,$evidence)){$null=Assert-RawQualificationNoReparsePointInExistingPath -Path $path}
if(Test-Path -LiteralPath $evidence){throw 'EvidenceRoot must be new; previous gate evidence is preserved.'}
New-Item -ItemType Directory -Path $evidence | Out-Null
$launcher=Join-Path $PSScriptRoot 'run_hot_redundant_qualification.ps1'
$stdout=Join-Path $evidence 'launcher.stdout.txt';$stderr=Join-Path $evidence 'launcher.stderr.txt'
$python=Join-Path $repo '.venv/Scripts/python.exe'
$binaryHashes=[ordered]@{}
foreach($name in @('hot_redundant_capture.exe','hot_redundant_verify.exe','kernel_network_trace.exe','live_arbitration.exe','live_arbitration_verify.exe')){
    $binaryHashes[$name]=Get-RawQualificationSha256File -Path (Join-Path $bins $name)
}
$argsLine='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$launcher+'" -Mode Continuous -TimeScale 3600 -EpochWindowSeconds 20 -TelemetryIntervalSeconds 10 -ReleaseBinRoot "'+$bins+'"'
$command=[ordered]@{schema='ObserverRotationGateInvocationV1';started_utc=[DateTimeOffset]::UtcNow.ToString('o');cwd=$repo;executable=(Join-Path $PSHOME 'powershell.exe');arguments=$argsLine;launcher_sha256=(Get-RawQualificationSha256File $launcher);binaries=$binaryHashes;minimum_windows_per_plane=$MinimumWindows;scope='Real ETW/network witness, two or more overlap rotations, full service verifier; no injected process doubles'}
$null=Write-RawQualificationDurableNewJson -Path (Join-Path $evidence 'invocation.json') -Value $command
$process=$null;$runRoot=$null;$stopWritten=$false;$failure=$null;$service=$null
$clock=[Diagnostics.Stopwatch]::StartNew()
try{
    $process=Start-Process -WindowStyle Hidden -FilePath $command.executable -WorkingDirectory $repo -ArgumentList $argsLine -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    while($clock.Elapsed.TotalSeconds -lt $DeadlineSeconds){
        $process.Refresh()
        if($null -eq $runRoot -and (Test-Path -LiteralPath $stdout)){
            $ready=@(Select-String -LiteralPath $stdout -Pattern '^READY:.*Evidence: ')
            if($ready.Count -gt 0){
                $runRoot=[IO.Path]::GetFullPath(($ready[0].Line -split 'Evidence: ',2)[1].Trim())
                if(-not $runRoot.StartsWith(($repo.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Gate launcher returned a run outside its isolated candidate.'}
                $null=Assert-RawQualificationNoReparsePointInExistingPath -Path $runRoot
            }
        }
        if($null -ne $runRoot){
            if(Test-Path -LiteralPath (Join-Path $runRoot 'service-failure.json')){throw 'Candidate service recorded failure; evidence is preserved.'}
            if(-not $stopWritten){
                $counts=@{kernel_network=0;network_witness=0}
                # The service journal stays open with write access and only
                # shares reads. File.ReadLines asks for FileShare.Read, which
                # denies that writer, so the gate died at the first poll.
                # Share ReadWrite here, and ignore a trailing line without a
                # newline: it is not a committed record yet.
                $eventsPath=Join-Path $runRoot 'service-events.jsonl'
                $stream=[IO.FileStream]::new($eventsPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                try {
                    $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false),$false,4096,$true)
                    try { $text=$reader.ReadToEnd() } finally { $reader.Dispose() }
                } finally { $stream.Dispose() }
                $lastNewline=$text.LastIndexOf("`n")
                if ($lastNewline -ge 0) {
                    foreach($line in ($text.Substring(0,$lastNewline) -split "`n")){
                        if ($line.Length -eq 0) { continue }
                        try{$record=$line|ConvertFrom-Json -ErrorAction Stop}catch{continue}
                        if($record.body.payload.event -ceq 'OBSERVER_WINDOW_READY'){$counts[[string]$record.body.payload.kind]++}
                    }
                }
                if($counts.kernel_network -ge $MinimumWindows -and $counts.network_witness -ge $MinimumWindows){
                    $null=Write-RawQualificationDurableNewFile -Path (Join-Path $runRoot 'stop.request') -Bytes ([byte[]]@())
                    $stopWritten=$true
                }
            }
        }
        if($process.HasExited){break}
        Start-Sleep -Seconds 1
    }
    if($null -eq $runRoot -or -not $stopWritten -or -not $process.HasExited){throw 'Observer rotation gate exceeded its bounded lifetime without a cooperative complete service.'}
    $exitMarker=Get-Content -LiteralPath (Join-Path $runRoot 'launcher-exit.json') -Raw|ConvertFrom-Json
    if($exitMarker.exit_code -ne 0){throw 'Candidate launcher exited non-zero.'}
    $terminal=Get-Content -LiteralPath (Join-Path $runRoot 'service-terminal.json') -Raw|ConvertFrom-Json
    if($terminal.schema -cne 'HotRedundantQualificationTerminalV2' -or $terminal.observers_skipped -or
        $terminal.status -cne 'PASS' -or $terminal.observer_verification.kernel_network.Count -lt $MinimumWindows -or
        $terminal.observer_verification.network_witness.Count -lt $MinimumWindows){throw 'Terminal does not qualify complete observer rotations.'}
    $oldPythonPath=$env:PYTHONPATH
    try{
        $env:PYTHONPATH=Join-Path $repo 'src'
        # The verifier prints the report on stdout. It does not accept --output.
        $independentStdout=Join-Path $evidence 'independent.stdout.txt'
        $independentJson=Join-Path $evidence 'independent-service.json'
        & $python -B -m binance_lob.hot_service_verify_cli $runRoot 1> $independentStdout 2> (Join-Path $evidence 'independent.stderr.txt')
        if($LASTEXITCODE -ne 0){throw 'Independent real service replay rejected the candidate.'}
        Copy-Item -LiteralPath $independentStdout -Destination $independentJson
    }finally{$env:PYTHONPATH=$oldPythonPath}
    $service=Get-Content -LiteralPath (Join-Path $evidence 'independent-service.json') -Raw|ConvertFrom-Json
    if($service.status -cne 'PASS' -or $service.observer_coverage.status -cne 'COMPLETE'){throw 'Independent observer lifetime coverage is not COMPLETE.'}
}catch{$failure=[string]$_}
finally{
    if($null -ne $process){
        $process.Refresh()
        if(-not $process.HasExited){
            if($null -ne $runRoot -and -not (Test-Path -LiteralPath (Join-Path $runRoot 'stop.request'))){
                $null=Write-RawQualificationDurableNewFile -Path (Join-Path $runRoot 'stop.request') -Bytes ([byte[]]@())
            }
            # Only the process this gate created is eligible for forced cleanup.
            # Its own kill-on-close job owns its children; runtime is untouched.
            $cleanup=[Diagnostics.Stopwatch]::StartNew()
            while(-not $process.HasExited -and $cleanup.Elapsed.TotalSeconds -lt 60){Start-Sleep -Seconds 1;$process.Refresh()}
            if(-not $process.HasExited){
                Stop-Process -Id $process.Id -Force
                if($null -ne $runRoot){
                    $ownedEpochs=Join-Path $runRoot 'obs/epochs'
                    if(Test-Path -LiteralPath $ownedEpochs){
                        foreach($epoch in @(Get-ChildItem -LiteralPath $ownedEpochs -Directory)){
                            $recordPath=Join-Path $epoch.FullName 'kernel/controller.stdout.jsonl'
                            if(-not (Test-Path -LiteralPath $recordPath)){continue}
                            try{
                                $readyRecord=Get-Content -LiteralPath $recordPath -TotalCount 1|ConvertFrom-Json -ErrorAction Stop
                                $ownedEtl=[IO.Path]::GetFullPath((Join-Path $epoch.FullName 'kernel/kernel-network.etl'))
                                $ownedStop=[IO.Path]::GetFullPath((Join-Path $epoch.FullName 'kernel/stop.request'))
                                if($readyRecord.schema -ceq 'KernelNetworkTraceReadyV1' -and $readyRecord.status -ceq 'READY' -and
                                    $readyRecord.session_name -cmatch '^BinanceProduction_[0-9a-f]{12}$' -and
                                    [IO.Path]::GetFullPath([string]$readyRecord.etl_path) -ceq $ownedEtl -and
                                    [IO.Path]::GetFullPath([string]$readyRecord.stop_file) -ceq $ownedStop){
                                    & (Join-Path $env:SystemRoot 'System32/logman.exe') stop -ets $readyRecord.session_name 2>&1 |
                                        Out-File -LiteralPath (Join-Path $evidence ('owned-session-cleanup-'+$epoch.Name+'.txt')) -Encoding UTF8
                                    $stopExit=[int]$LASTEXITCODE
                                    & (Join-Path $env:SystemRoot 'System32/logman.exe') query -ets $readyRecord.session_name 2>&1 |
                                        Out-File -LiteralPath (Join-Path $evidence ('owned-session-post-query-'+$epoch.Name+'.txt')) -Encoding UTF8
                                    $queryExit=[int]$LASTEXITCODE
                                    $control=[ordered]@{session_name=$readyRecord.session_name;exact_ready_ownership=$true;stop_exit_code=$stopExit;post_query_exit_code=$queryExit;absence_confirmed=($queryExit -eq -2144337918 -and $stopExit -in @(0,-2144337918))}
                                    $null=Write-RawQualificationDurableNewJson -Path (Join-Path $evidence ('owned-session-control-'+$epoch.Name+'.json')) -Value $control
                                }
                            }catch{[IO.File]::AppendAllText((Join-Path $evidence 'cleanup-errors.txt'),([string]$_)+"`n")}
                        }
                    }
                }
            }
        }
        $process.Dispose()
    }
    $result=[ordered]@{schema='ObserverRotationGateV1';status=$(if($null -eq $failure){'PASS'}else{'FAIL'});finished_utc=[DateTimeOffset]::UtcNow.ToString('o');elapsed_s=$clock.Elapsed.TotalSeconds;run_root=$runRoot;cooperative_stop=$stopWritten;failure=$failure;observer_coverage=$(if($null -ne $service){$service.observer_coverage}else{$null})}
    $null=Write-RawQualificationDurableNewJson -Path (Join-Path $evidence 'result.json') -Value $result
}
$result|ConvertTo-Json -Depth 8
if($null -ne $failure){exit 2}
