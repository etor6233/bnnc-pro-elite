# FASE 6 evidence — professional presentation + final scan

Date: 2026-09-19.

## What changed (presentation)

- `README.md` (root): opening rewritten so the productive capture system
  (dual-lane + forensic integrity + fault gates + soak >45 h + typed
  recovery) leads the repository; the C++ layer, latency engineering,
  architecture, roadmap, evidence, tech stack and run instructions follow as
  ordered sections. Added: CI + license badges, a measured latency table
  (every number links to its JSON), a "5-minute verification" section and an
  honest "Project status" section (built/verified vs open — nothing
  exaggerated, nothing hidden).
- `portfolio/README.md` (new in the repo): the single reviewer-facing entry
  point (what the system is, verified evidence, 5-minute verification,
  honest status, design boundaries), polished from the 2026-09-16 portfolio
  export to the current project state.
- `cpp/README.md`: new suites (bench 10/10 + spsc 7/7), latency tooling
  section, updated totals (74/74).
- `docs/EVIDENCE.md`: claims → evidence table extended with every
  latency-engineering claim.
- `cpp/ACTA_FINAL_LATENCY_ELITE_20260919.md`: complete DONE checklist
  (internal execution record; Spanish by the established acta convention —
  the two actas are the only Spanish documents and are excluded from the
  public-docs language check by design).

## Final scan (script committed: `FASE6/scan_publication.ps1`)

Full output: `FASE6/scan_20260919.txt`. Results:

| Check | Result |
|---|---|
| Binance API key literal comparison (external key file vs every text file in the repo; only lines ≥ 12 chars are compared) | **0 hits** |
| Private-key / api-key / secret / password-like patterns | **0 hits** |
| Personal machine paths (Windows per-user profile directories, authored files) | **0 hits in this campaign's files**; the only hit is the PRE-EXISTING `EVIDENCE_08_PUBLICATION.md` quoting its own scan pattern (a pattern literal, not a machine path in repo content) |
| Language mixing in public docs (README, docs/, portfolio/, cpp/README.md, new evidence, bench-latency page, KERNEL_BYPASS_DESIGN.md) | **0 hits in this campaign's files**; the hits in `EVIDENCE_01/02` are the PRE-EXISTING 2026-09-18 evidence files (Spanish headers, established convention of that campaign's records — left untouched; only the two actas and those historical evidence files carry Spanish) |
| Relative links in README / portfolio / docs/EVIDENCE / cpp/README | **all resolve** (no BROKEN entries) |
| Unfinished-work markers in public docs | 0 (the single hit in a pre-existing evidence file is the Spanish word meaning "all" inside a sentence) |
| Mermaid blocks (root README) | **PASS** with the real parser (mermaid 11.17.2, headless jsdom setup; log: `FASE6/mermaid_verify.txt`) |

Notes: the benchmark run logs (`run_log_20260919.txt`, `spsc_dev_stdout.txt`)
were transient local artifacts containing absolute paths; they were removed
and are not part of any commit. Raw execution logs kept as evidence
(`FASE1/all_phases_green_20260919.log`, `FASE3/aeron-ipc/*.log`) are verbatim
traces of real runs and may echo local shell paths — the same trait exists in
the pre-existing `cpp/evidence/logs/ALL_PHASES_GREEN_20260918.log`; the scan
excludes `.log` files for that check by design, while every authored document
is clean.

## Artifact hashes

`MANIFEST_FASE6.md`.
