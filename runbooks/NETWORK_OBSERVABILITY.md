# Network Observability Runbook

Run all commands from the repository root. These procedures collect evidence;
they do not start trading and require no Binance API key.

## Independent host witness (non-administrator)

Create a fresh evidence parent and run a bounded witness:

```powershell
Set-Location -LiteralPath "C:\Users\NL\Desktop\NEW BINANCE\Binance"
$id = "witness-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$base = Join-Path (Get-Location) "artifacts\network-witness"
New-Item -ItemType Directory -Path $base -Force | Out-Null
$root = Join-Path $base $id
& .\scripts\RawQualification.NetworkWitness.ps1 -EvidenceRoot $root -ObservationId $id -DurationSeconds 300 -IntervalSeconds 30
.\.venv\Scripts\python.exe -m binance_lob.network_witness_verify_cli $root
```

The verifier must report `PASS`. Its classification is only a direct
local-host reachability classification.

## Bounded Windows trace (administrator)

Open one PowerShell as Administrator, then run the smoke:

```powershell
Set-Location -LiteralPath "C:\Users\NL\Desktop\NEW BINANCE\Binance"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\_network_trace_smoke.ps1"
```

The script starts PktMon in circular metadata/drop mode, checks status and
stops it in `finally`. Do not close the elevated console during this smoke.

If the script reports a failure, preserve the printed evidence path. Do not
run an unconditional `pktmon stop`: the stop action deliberately requires
matching control evidence so it does not take ownership of an unrelated global
PktMon session.

## Exact socket diagnosis

For a sealed generation, use the release build of `transport_diagnose` with
the generation directory and expected identity arguments recorded by its
manifest. The command independently rescans both transport journals; a
diagnosis is rejected if the journal or seal changed.

## Incident rule

Preserve the failed campaign, transport journals, witness journal, host
telemetry and trace ETL. Report separately:

- directly observed facts;
- causes ruled out at an observed boundary;
- narrowest evidence-supported classification;
- unavailable evidence and the additional vantage required.

Never concatenate raw generations across an unproved gap and never infer an
upstream owner from a single-host observation.

