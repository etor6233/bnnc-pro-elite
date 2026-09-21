# scan_publication.ps1 — PHASE 6 final scan of the public repository clone.
# Checks (outputs only counts/paths, NEVER secret material):
#   1. the Binance API key (comparing literal lines of the external key file
#      against the repo; the key itself is never printed);
#   2. private-key / API-key patterns;
#   3. personal machine paths (Windows per-user profile directories);
#   4. language mixing in public docs (Spanish function words);
#   5. relative markdown links that do not resolve;
#   6. placeholder markers (TODO/FIXME/lorem) in public docs.
param(
    # Repo default: the clone that contains this script (4 levels up:
    # PHASE6 -> 10-latency-elite -> evidence -> cpp -> repo root).
    [string]$Repo = (Join-Path $PSScriptRoot '..\..\..\..'),
    # External key file (NOT in the repo). When omitted, the literal-key
    # comparison is skipped; the key content is never printed either way.
    [string]$KeyFile = "",
    [string]$Out = ""
)
$ErrorActionPreference = "SilentlyContinue"
$repo = (Resolve-Path $Repo).Path
$results = @()

function Add-Result($check, $detail) {
    $script:results += "$check | $detail"
}

# Text-file inventory, once (excludes VCS, build outputs and binary capture
# artifacts; big files are skipped for the literal-key comparison).
$textExt = '\.(md|json|rs|py|cpp|hpp|h|yml|yaml|html|log|toml|txt|sh|ps1|js|mjs|lock|xml|gradle|properties|java|ini|cfg|bat|csv)$'
$repoFiles = Get-ChildItem $repo -Recurse -File |
    Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\target\\' -and $_.FullName -notmatch '\\build\\' -and $_.Name -match $textExt -and $_.Length -gt 0 -and $_.Length -lt 5MB }

# ---- 1. Binance key literal comparison (no key content ever printed) ----
$keyHits = 0
if ($KeyFile -ne "" -and (Test-Path $KeyFile)) {
    # Only long lines can be credential material (short words like "API" or
    # "true" would false-positive against every text file).
    $keyLines = Get-Content $KeyFile | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -ge 12 }
    foreach ($line in $keyLines) {
        $hits = $repoFiles | Select-String -SimpleMatch -Pattern $line
        foreach ($h in $hits) { $keyHits++; Add-Result "key-literal" "HIT in $($h.Path.Substring($repo.Length))" }
    }
    if ($keyHits -eq 0) { Add-Result "key-literal" "0 hits (external key file lines not found anywhere in the repo)" }
} else {
    Add-Result "key-literal" "skipped (no external key file path provided to the scan)"
}

# ---- 2. Secret patterns ----
$patterns = @('-----BEGIN [A-Z ]*PRIVATE KEY-----', '(?i)api[_-]?key["''\s:=]+[A-Za-z0-9]{24,}', '(?i)secret["''\s:=]+[A-Za-z0-9]{24,}', '(?i)password["''\s:=]+[^"''\s]{8,}')
foreach ($p in $patterns) {
    $hits = $repoFiles | Select-String -Pattern $p | Select-Object -First 3
    if ($hits) { $hits | ForEach-Object { Add-Result "pattern" "HIT '$p' in $($_.Path.Substring($repo.Length)):$($_.LineNumber)" } }
    else { Add-Result "pattern" "0 hits: $p" }
}

# ---- 3. Personal machine paths ----
# (pattern written with a character class so the scan does not flag itself)
# Raw execution logs (*.log) are excluded: they are verbatim traces of real
# runs and may echo the local shell's absolute paths (the pre-existing
# evidence log has the same trait). Authored documents must be clean.
$userPathPattern = 'C:[\\/]Users[\\/]'
$pathHits = $repoFiles | Where-Object { $_.Extension -ne '.log' } | Select-String -Pattern $userPathPattern | Select-Object -First 5
if ($pathHits) { $pathHits | ForEach-Object { Add-Result "personal-path" "HIT in $($_.Path.Substring($repo.Length)):$($_.LineNumber)" } }
else { Add-Result "personal-path" "0 hits (no per-user Windows profile paths in the repo)" }

# ---- 4. Language mixing in public docs (Spanish function words) ----
$publicDocs = @(
    "$repo\README.md", "$repo\docs\*.md", "$repo\portfolio\*.md",
    "$repo\cpp\README.md", "$repo\cpp\evidence\*.md",
    "$repo\cpp\evidence\10-latency-elite\*.md",
    "$repo\cpp\evidence\10-latency-elite\FASE*\*.md",
    "$repo\cpp\bench\KERNEL_BYPASS_DESIGN.md", "$repo\bench-latency\*.html"
)
# The ACTAs are internal execution records, Spanish by established
# convention (see the previous acta); excluded from the public-docs check.
$spanish = '(?i)\b(que|para|como|está|están|además|después|antes|mientras|cuando|según|también|pero|este|esta|estos|estas|del|los|las|una|un|ser|hacer|ejecutar|archivo|fichero|evidencia|prueba|fase|fases|instrucción|instrucciones|clave|propietario|dueño|publicado|publicada|publicación|correr|corrida|medición|medir|sección)\b'
$langHits = Get-ChildItem -Path $publicDocs -File | Select-String -Pattern $spanish | Select-Object -First 10
if ($langHits) { $langHits | ForEach-Object { Add-Result "language" "HIT in $($_.Path.Substring($repo.Length)):$($_.LineNumber): $($_.Line.Trim().Substring(0, [Math]::Min(80, $_.Line.Trim().Length)))" } }
else { Add-Result "language" "0 hits (no Spanish function words in public docs)" }

# ---- 5. Relative links in the rewritten public docs ----
$linkFiles = @("$repo\README.md", "$repo\portfolio\README.md", "$repo\docs\EVIDENCE.md", "$repo\cpp\README.md")
foreach ($lf in $linkFiles) {
    $text = [IO.File]::ReadAllText($lf)
    $links = [regex]::Matches($text, '\]\(([^)#]+)(#[^)]*)?\)') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -notmatch '^https?://' -and $_ -notmatch '^mailto:' }
    foreach ($l in $links | Select-Object -Unique) {
        $decoded = [uri]::UnescapeDataString($l) -replace '^\./', ''
        $target = Join-Path (Split-Path $lf -Parent) $decoded
        if (-not (Test-Path $target)) { Add-Result "link" "BROKEN in $($lf.Substring($repo.Length)): $l" }
    }
}
Add-Result "link" "checked $($linkFiles.Count) files (README, portfolio, docs/EVIDENCE, cpp/README)"

# ---- 6. Placeholders ----
$phHits = Get-ChildItem -Path $publicDocs -File | Select-String -Pattern '(?i)\b(todo|fixme|lorem ipsum|placeholder|xxxx)\b' | Select-Object -First 5
if ($phHits) { $phHits | ForEach-Object { Add-Result "placeholder" "HIT in $($_.Path.Substring($repo.Length)):$($_.LineNumber)" } }
else { Add-Result "placeholder" "0 hits" }

$results | Out-String | ForEach-Object { Write-Host $_ }
if ($Out -ne "") {
    Set-Content -Path $Out -Value ($results -join "`n") -Encoding UTF8
    Write-Host "scan saved to $Out"
}
