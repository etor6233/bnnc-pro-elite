# build.ps1 — builds and runs the C++ venue-connectivity suites.
#
# Usage (from cpp/):
#   .\build.ps1 -Phase itch          build + run ITCH suite
#   .\build.ps1 -Phase all           build + run every suite
#   .\build.ps1 -Phase itch -Mode debug
#
# Toolchain: MSVC cl 14.50 (no cmake, per external-review/low-latency-reference/INDEX.md
# section 6). Golden/malformed vectors are (re)generated from the captured specs
# before each run, so the vectors and the code under test always trace to the
# same pinned spec bytes.
param(
    [string]$Phase = "all",
    [string]$Mode = "release"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
# Locate vcvars64.bat (works on dev machines and GitHub windows-latest runners).
$VcVars = $null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $VcVars = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find "VC\Auxiliary\Build\vcvars64.bat" | Select-Object -First 1
}
if (-not $VcVars -or -not (Test-Path $VcVars)) {
    $VcVars = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
}
if (-not (Test-Path $VcVars)) {
    Write-Host "vcvars64.bat not found (install MSVC Build Tools)"; exit 3
}
$BinDir = Join-Path $Root "build\bin"
$LogDir = Join-Path $Root "build\logs"
New-Item -ItemType Directory -Force -Path $BinDir, $LogDir | Out-Null

$Optimize = if ($Mode -eq "debug") { "/Od /Zi" } else { "/O2" }
$Warnings = "/W4 /permissive- /EHsc /std:c++20"
$Include = "/I`"$Root`""

function Invoke-ClBuild {
    param(
        [string[]]$Sources,
        [string]$Output,
        [string]$ExtraLibs = "",
        [string[]]$IncludeDirs = @()
    )
    $inc = "/I`"$Root`""
    foreach ($d in $IncludeDirs) { $inc += " /I`"$d`"" }
    $srcArgs = ($Sources | ForEach-Object { "`"$_`"" }) -join " "
    $log = Join-Path $LogDir "$(Split-Path $Output -Leaf).log"
    $cmd = "`"$VcVars`" >nul 2>&1 && cl /nologo $Warnings $Optimize $inc $srcArgs /Fe:`"$Output`" $ExtraLibs /link /SUBSYSTEM:CONSOLE > `"$log`" 2>&1"
    cmd /c $cmd | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BUILD FAILED: $Output (see $log)"
        Get-Content $log -Tail 40
        exit $LASTEXITCODE
    }
}

function Invoke-Test {
    param([string]$Exe, [string]$PhaseName)
    $outLog = Join-Path $LogDir "$PhaseName.test.log"
    & $Exe $Root > $outLog 2>&1
    $code = $LASTEXITCODE
    Write-Host ""
    Get-Content $outLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
    if ($code -ne 0) { exit $code }
}

# Golden/malformed vector regeneration from the captured specs.
function New-Goldens {
    param([string]$Tool, [string]$PhaseName)
    Write-Host "== regenerating $PhaseName vectors ($Tool) =="
    python $Tool
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$phases = @{
    itch = @{
        Tools = @("$Root\itch\tools\make_itch_golden.py", "$Root\itch\tools\make_itch_malformed.py");
        Sources = @("$Root\itch\tests\test_itch.cpp", "$Root\itch\src\itch_codec.cpp");
        Output = "$BinDir\test_itch.exe";
        IncludeDirs = @("$Root\itch\include");
    }
    sbe = @{
        Tools = @("$Root\sbe\tools\make_sbe_malformed.py");
        GoldenExe = @{
            Sources = @("$Root\sbe\tools\make_sbe_golden.cpp");
            Output = "$BinDir\make_sbe_golden.exe";
            IncludeDirs = @("$Root\tools\sbe-tool\gen");
        };
        Sources = @("$Root\sbe\tests\test_sbe.cpp", "$Root\sbe\src\binance_sbe.cpp");
        Output = "$BinDir\test_sbe.exe";
        IncludeDirs = @("$Root\sbe\include", "$Root\tools\sbe-tool\gen");
    }
    ouch = @{
        Tools = @("$Root\ouch\tools\make_ouch_golden.py");
        Sources = @("$Root\ouch\tests\test_ouch.cpp", "$Root\ouch\src\ouch_codec.cpp");
        Output = "$BinDir\test_ouch.exe";
        IncludeDirs = @("$Root\ouch\include");
    }
    net = @{
        Tools = @();
        Sources = @("$Root\net\tests\test_mcast.cpp", "$Root\net\src\mcast_feed.cpp");
        Output = "$BinDir\test_mcast.exe";
        Libs = "ws2_32.lib";
        IncludeDirs = @("$Root\net\include", "$Root\sbe\include");
    }
    recovery = @{
        Tools = @();
        Sources = @("$Root\recovery\tests\test_recovery.cpp", "$Root\recovery\src\feed_guard.cpp", "$Root\sbe\src\binance_sbe.cpp", "$Root\net\src\mcast_feed.cpp");
        Output = "$BinDir\test_recovery.exe";
        Libs = "ws2_32.lib";
        IncludeDirs = @("$Root\recovery\include", "$Root\sbe\include", "$Root\net\include", "$Root\tools\sbe-tool\gen");
    }
    resilience = @{
        Tools = @();
        Sources = @("$Root\resilience\tests\test_resilience.cpp", "$Root\resilience\src\layered_capture.cpp");
        Output = "$BinDir\test_resilience.exe";
        IncludeDirs = @("$Root\resilience\include", "$Root\recovery\include", "$Root\net\include");
    }
    fix = @{
        Tools = @("$Root\fix\tools\make_fix_golden.py");
        Sources = @("$Root\fix\tests\test_fix_session.cpp", "$Root\fix\src\fix_session.cpp");
        Output = "$BinDir\test_fix_session.exe";
        IncludeDirs = @("$Root\fix\include");
    }
}

if ($Phase -eq "all") { $names = @("itch", "sbe", "ouch", "net", "recovery", "resilience", "fix") }
else { $names = @($Phase) }

foreach ($n in $names) {
    if (-not $phases.ContainsKey($n)) {
        Write-Host "unknown phase: $n"; exit 2
    }
    $ph = $phases[$n]
    if ($ph.GoldenExe) {
        Invoke-ClBuild -Sources $ph.GoldenExe.Sources -Output $ph.GoldenExe.Output -IncludeDirs $ph.GoldenExe.IncludeDirs
        & $ph.GoldenExe.Output "$Root\$n\golden"
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    foreach ($t in $ph.Tools) { New-Goldens -Tool $t -PhaseName $n }
    if ($ph.Sources.Count -gt 0) {
        Invoke-ClBuild -Sources $ph.Sources -Output $ph.Output -ExtraLibs $ph.Libs -IncludeDirs $ph.IncludeDirs
        Invoke-Test -Exe $ph.Output -PhaseName $n
    }
}

Write-Host "== ALL PHASES GREEN =="
