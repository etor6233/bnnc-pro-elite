# Runbook (operational summary)

Run from the repository root. Production requires an elevated console (kernel observers).

```powershell
# Preflight (validates binaries, sources, disk, clock — no capture)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_hot_redundant_qualification.ps1 -Mode ValidateOnly

# Production continuous service (defaults: EpochWindowSeconds 14400, TimeScale 1)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_hot_redundant_qualification.ps1 -Mode Continuous

# State
Get-Content artifacts\hrs\hrs-<nonce>\service-events.jsonl -Tail 50

# Cooperative stop (never hard-kill)
[IO.File]::WriteAllBytes("artifacts\hrs\hrs-<nonce>\stop.request", [byte[]]@())
```

Service guarantees:
- No global horizon; epoch renewals every 4 h with overlap (capture never stops).
- Every epoch window is sealed and verified (Rust + Python) while the next one captures.
- Arbiter crash → `LIVE_ARBITRATION_EXITED_EARLY` + relaunch with `--resume` (no duplication,
  no rollback); supervisor kill → `OUTER_GAP_OPENED/CLOSED` + backoff; hung verifier →
  monotonic-deadline kill, `LIVE_ARBITRATION_AUDIT_TIMEOUT`; low disk → typed safe stop.
- Restart = a new `-Mode Continuous` with a new `hrs-<nonce>` root; recovery is automatic.
