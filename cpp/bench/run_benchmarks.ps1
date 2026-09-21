# run_benchmarks.ps1 — PHASE 5: builds and runs the measured benchmark suite
# in dev mode (fast) and final mode (held-out sizes). Every number lands in
# bench/benchmarks/*.json; nothing is estimated.
param(
    [string]$Mode = "both"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$CppRoot = Split-Path $Root -Parent
$VcVars = $null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $VcVars = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find "VC\Auxiliary\Build\vcvars64.bat" | Select-Object -First 1
}
if (-not $VcVars -or -not (Test-Path $VcVars)) {
    $VcVars = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
}
if (-not (Test-Path $VcVars)) {
    Write-Host "vcvars64.bat not found"; exit 3
}
$BinDir = Join-Path $CppRoot "build\bin"
$OutDir = Join-Path $Root "benchmarks"
New-Item -ItemType Directory -Force -Path $BinDir, $OutDir | Out-Null

function Invoke-ClBuild {
    param([string[]]$Sources, [string]$Output, [string[]]$IncludeDirs = @(), [string]$Libs = "")
    $inc = "/I`"$CppRoot`""
    foreach ($d in $IncludeDirs) { $inc += " /I`"$d`"" }
    $srcArgs = ($Sources | ForEach-Object { "`"$_`"" }) -join " "
    $log = Join-Path $BinDir "$(Split-Path $Output -Leaf).log"
    $cmd = "`"$VcVars`" >nul 2>&1 && cl /nologo /W4 /permissive- /EHsc /std:c++20 /O2 $inc $srcArgs /Fe:`"$Output`" $Libs /link /SUBSYSTEM:CONSOLE > `"$log`" 2>&1"
    cmd /c $cmd | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BUILD FAILED: $Output"
        Get-Content $log -Tail 30
        exit $LASTEXITCODE
    }
}

Invoke-ClBuild -Sources @("$Root\bench_itch.cpp", "$CppRoot\itch\src\itch_codec.cpp") -Output "$BinDir\bench_itch.exe" -IncludeDirs @("$CppRoot\itch\include", "$Root")
Invoke-ClBuild -Sources @("$Root\bench_sbe.cpp", "$CppRoot\sbe\src\binance_sbe.cpp") -Output "$BinDir\bench_sbe.exe" -IncludeDirs @("$CppRoot\sbe\include", "$Root")
Invoke-ClBuild -Sources @("$Root\bench_mcast.cpp", "$CppRoot\net\src\mcast_feed.cpp") -Output "$BinDir\bench_mcast.exe" -IncludeDirs @("$CppRoot\net\include", "$Root") -Libs "ws2_32.lib"
# PHASE 2 (latency elite): false sharing / cache-line and SPSC ring benches.
Invoke-ClBuild -Sources @("$Root\bench_false_sharing.cpp") -Output "$BinDir\bench_false_sharing.exe" -IncludeDirs @("$Root")
Invoke-ClBuild -Sources @("$Root\bench_spsc.cpp") -Output "$BinDir\bench_spsc.exe" -IncludeDirs @("$CppRoot\net\include", "$Root")

$modes = if ($Mode -eq "both") { @("dev", "final") } else { @($Mode) }

foreach ($m in $modes) {
    Write-Host "== mode: $m =="
    & "$BinDir\bench_itch.exe" $CppRoot $m "$OutDir\bench_itch_$m.json"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & "$BinDir\bench_sbe.exe" $CppRoot $m "$OutDir\bench_sbe_$m.json"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & "$BinDir\bench_mcast.exe" $m "$OutDir\bench_mcast_$m.json"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python "$Root\bench_json_decode.py" $m "$OutDir\bench_json_$m.json"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & "$BinDir\bench_false_sharing.exe" $m "$OutDir\bench_false_sharing_$m.json"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & "$BinDir\bench_spsc.exe" $m "$OutDir\bench_spsc_$m.json"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "== BENCHMARKS DONE =="
