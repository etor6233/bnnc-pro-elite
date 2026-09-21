# Runbooks

Operations for the continuous hot-redundant BTCUSDT/ETHUSDT service (ADR-17):

- [CONTINUOUS_SERVICE.md](CONTINUOUS_SERVICE.md) — operational runbook for the
  continuous service: preflight, start (elevated console), status, safe stop,
  recovery, quarantine and limits. This is the CURRENT operational reference;
  production is not started until the independent Codex review.
- [QUALIFICATION_24H.md](QUALIFICATION_24H.md) — HISTORICAL 24-hour
  qualification campaign (single-window soak). It is not the continuous
  operating mode: it documents the campaign already executed, it does not
  direct the current service.

Specialized runbooks planned (not executed yet): `clock-unhealthy`,
`websocket-gap-resync`, `slow-full-disk` and `bad-release-rollback`. No order
execution or order runbook is enabled.

Launcher guards against test/operation confusion (verified 2026-09-16 in
`scripts/run_hot_redundant_qualification.ps1`):

- `-TimeScale > 1` is TEST-ONLY (virtual milestone clock + reduced 30/25 s
  topology, run root `artifacts\hsc`); it requires `-Mode Continuous` and is
  forbidden in `-Mode Production`.
- `-SkipKernelObserver` / `-ArbiterOverride` / `-ArbiterVerifyOverride` /
  `-ReleaseBinRoot` are rejected in `-Mode Production`.
- `-Mode ValidateOnly` rebuilds `--release` unless `-ReleaseBinRoot` points at
  the frozen path (do not assume it is read-only).