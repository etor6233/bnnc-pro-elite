# Runs the Aeron IPC one-way latency demo end to end on a single Windows host.
#
# Steps: download official jars if missing, compile the adapted samples, start the
# media driver, start the subscriber, run the publisher, wait for the subscriber to
# finish, stop the media driver, then print the measured results JSON.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File run_aeron_ipc_demo.ps1 [-Messages 1000000]

param(
    [long]$Messages = 1000000
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$base = $PSScriptRoot
$srcDir = Join-Path $base 'src'
$classesDir = Join-Path $base 'classes'
$aeronDir = Join-Path $base 'aeron-driver'

# JDK 21 required (Aeron 1.53 needs Java 17+). Resolution order:
#   $env:JAVA_HOME -> java on PATH -> standard Adoptium location.
$jdkBin = $null
if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin\java.exe'))) {
    $jdkBin = Join-Path $env:JAVA_HOME 'bin'
} elseif (Get-Command java -ErrorAction SilentlyContinue) {
    $jdkBin = Split-Path (Get-Command java).Source -Parent
} else {
    $candidates = Get-ChildItem 'C:\Program Files\Eclipse Adoptium', "$env:LOCALAPPDATA\Programs\Eclipse Adoptium" -Directory -ErrorAction SilentlyContinue |
        Get-ChildItem -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
    foreach ($c in $candidates) {
        $probe = Join-Path $c.FullName 'bin\java.exe'
        if (Test-Path $probe) { $jdkBin = Join-Path $c.FullName 'bin'; break }
    }
}
if (-not $jdkBin) { throw 'JDK 21 not found: set JAVA_HOME or install Eclipse Adoptium JDK 21' }
$java = Join-Path $jdkBin 'java.exe'
$javac = Join-Path $jdkBin 'javac.exe'

# JVM module flags required by Aeron 1.53 on JDK 21 (taken from the pinned
# aeron-samples scripts/java-common.cmd, captured commit dad28d2).
$addOpens = @(
    '--add-opens', 'java.base/jdk.internal.misc=ALL-UNNAMED',
    '--add-opens', 'java.base/java.util.zip=ALL-UNNAMED'
)

$aeronVersion = '1.53.2'
$hdrVersion = '2.2.2'
$aeronJar = "aeron-all-$aeronVersion.jar"
$hdrJar = "HdrHistogram-$hdrVersion.jar"

$aeronUrl = "https://repo1.maven.org/maven2/io/aeron/aeron-all/$aeronVersion/$aeronJar"
$hdrUrl = "https://repo1.maven.org/maven2/org/hdrhistogram/HdrHistogram/$hdrVersion/$hdrJar"

function Quote-Arg {
    param([string]$Value)
    if ($Value -match '\s') {
        return '"' + $Value + '"'
    }
    return $Value
}

function Build-CmdLine {
    param([string[]]$Arguments)
    $parts = foreach ($a in $Arguments) { Quote-Arg $a }
    return ($parts -join ' ')
}

# ---------------------------------------------------------------------------
# 1. Download jars if missing and record SHA256 in jars_manifest.json.
# ---------------------------------------------------------------------------
Write-Host '=== Step 1/5: jars ==='
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not (Test-Path (Join-Path $base $aeronJar))) {
    Write-Host "Downloading $aeronUrl"
    Invoke-WebRequest -Uri $aeronUrl -OutFile (Join-Path $base $aeronJar) -UseBasicParsing -TimeoutSec 120
}
if (-not (Test-Path (Join-Path $base $hdrJar))) {
    Write-Host "Downloading $hdrUrl"
    Invoke-WebRequest -Uri $hdrUrl -OutFile (Join-Path $base $hdrJar) -UseBasicParsing -TimeoutSec 120
}

$aeronSha = (Get-FileHash -Algorithm SHA256 (Join-Path $base $aeronJar)).Hash
$hdrSha = (Get-FileHash -Algorithm SHA256 (Join-Path $base $hdrJar)).Hash

$manifest = @{
    jars = @(
        @{
            groupId = 'io.aeron'; artifactId = 'aeron-all'; version = $aeronVersion
            url = $aeronUrl; file = $aeronJar; sha256 = $aeronSha
        },
        @{
            groupId = 'org.hdrhistogram'; artifactId = 'HdrHistogram'; version = $hdrVersion
            url = $hdrUrl; file = $hdrJar; sha256 = $hdrSha
        }
    )
    notes = @(
        'The modern Aeron groupId is io.aeron; the historical uk.co.real-logic:aeron-all artifact ends at 0.9.4.',
        'Version 1.53.2 is the highest stable released aeron-all version that is <= 1.54.0 (the captured SNAPSHOT version in external-review/low-latency-reference/aeron/version.txt).',
        'HdrHistogram 2.2.2 is the latest stable release per repo1.maven.org metadata.'
    )
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $base 'jars_manifest.json') -Encoding UTF8
Write-Host "aeron-all $aeronVersion SHA256 = $aeronSha"
Write-Host "HdrHistogram $hdrVersion SHA256 = $hdrSha"

# ---------------------------------------------------------------------------
# 2. Compile the adapted samples.
# ---------------------------------------------------------------------------
Write-Host '=== Step 2/5: compile ==='
New-Item -ItemType Directory -Force -Path $classesDir | Out-Null
$cpClient = "$classesDir;$base\$aeronJar;$base\$hdrJar"
& $javac -cp $cpClient -d $classesDir `
    (Join-Path $srcDir 'IpcLatencyPublisher.java') `
    (Join-Path $srcDir 'IpcLatencySubscriber.java')
if ($LASTEXITCODE -ne 0) {
    throw "javac failed with exit code $LASTEXITCODE"
}
Write-Host 'Compilation succeeded.'

# ---------------------------------------------------------------------------
# 3. Start the media driver (background).
# ---------------------------------------------------------------------------
Write-Host '=== Step 3/5: media driver ==='
if (Test-Path $aeronDir) { Remove-Item -Recurse -Force $aeronDir -ErrorAction SilentlyContinue }

$driverArgs = @(
    '-cp', "$base\$aeronJar",
    '-Daeron.dir.delete.on.start=true',
    '-Daeron.dir.delete.on.shutdown=true',
    "-Daeron.dir=$aeronDir",
    'io.aeron.driver.MediaDriver'
)
$driverArgs = $addOpens + $driverArgs
$driverCmd = Build-CmdLine $driverArgs
$driverOut = Join-Path $base 'media_driver.stdout.log'
$driverErr = Join-Path $base 'media_driver.stderr.log'
$driver = Start-Process -FilePath $java -ArgumentList $driverCmd -WorkingDirectory $base `
    -RedirectStandardOutput $driverOut -RedirectStandardError $driverErr -PassThru -WindowStyle Hidden
Write-Host "MediaDriver started (PID $($driver.Id))."
Start-Sleep -Seconds 3

# ---------------------------------------------------------------------------
# 4. Start the subscriber (background).
# ---------------------------------------------------------------------------
Write-Host '=== Step 4/5: subscriber ==='
$subArgs = @(
    '-cp', $cpClient,
    "-Daeron.dir=$aeronDir",
    'IpcLatencySubscriber',
    "$Messages",
    (Join-Path $base 'aeron_ipc_results.json')
)
$subArgs = $addOpens + $subArgs
$subCmd = Build-CmdLine $subArgs
$subOut = Join-Path $base 'subscriber.stdout.log'
$subErr = Join-Path $base 'subscriber.stderr.log'
$subscriber = Start-Process -FilePath $java -ArgumentList $subCmd -WorkingDirectory $base `
    -RedirectStandardOutput $subOut -RedirectStandardError $subErr -PassThru -WindowStyle Hidden
Write-Host "Subscriber started (PID $($subscriber.Id))."
Start-Sleep -Seconds 2

# ---------------------------------------------------------------------------
# 5. Run the publisher (foreground), then wait for the subscriber.
# ---------------------------------------------------------------------------
Write-Host '=== Step 5/5: publisher ==='
$pubArgs = @(
    '-cp', $cpClient,
    "-Daeron.dir=$aeronDir",
    'IpcLatencyPublisher',
    "$Messages"
)
$pubArgs = $addOpens + $pubArgs
& $java @pubArgs *> (Join-Path $base 'publisher.log')
$publisherExit = $LASTEXITCODE
Write-Host "Publisher exited with code $publisherExit."

if (-not $subscriber.WaitForExit(120000)) {
    Write-Host 'WARNING: subscriber did not finish within 120 s.'
}

# ---------------------------------------------------------------------------
# Stop the media driver and merge stdout/stderr into single log files.
# ---------------------------------------------------------------------------
if (-not $driver.HasExited) {
    Stop-Process -Id $driver.Id -Force -ErrorAction SilentlyContinue
    $driver.WaitForExit(10000) | Out-Null
}
Write-Host "MediaDriver stopped."

foreach ($name in @('media_driver', 'subscriber')) {
    $out = Join-Path $base "$name.stdout.log"
    $err = Join-Path $base "$name.stderr.log"
    $log = Join-Path $base "$name.log"
    if (Test-Path $out) { Move-Item $out $log -Force } else { New-Item -ItemType File -Path $log -Force | Out-Null }
    if (Test-Path $err) {
        Add-Content -Path $log -Value "`r`n===== STDERR =====`r`n"
        Get-Content -Path $err | Add-Content -Path $log
        Remove-Item $err -Force
    }
}

Remove-Item -Recurse -Force $aeronDir -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Print the results JSON.
# ---------------------------------------------------------------------------
$resultsPath = Join-Path $base 'aeron_ipc_results.json'
Write-Host ''
Write-Host '=== RESULTS ==='
if (Test-Path $resultsPath) {
    Get-Content -Path $resultsPath
} else {
    Write-Host 'ERROR: aeron_ipc_results.json was not produced.'
    Write-Host 'See subscriber.log for diagnostics.'
}
Write-Host "Results file: $resultsPath"
Write-Host "Publisher exit code: $publisherExit"
