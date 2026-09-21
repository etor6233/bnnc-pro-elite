# EVIDENCE — PHASE 8: Publication and final evidence

**Status: DONE.** Date: 2026-09-18 (updated 2026-09-19).

## What was published

- Public repository `etor6233/bnnc-pro-elite`, branch `main` (clean history,
  see `git log` in the repo):
  - the complete new C++ code in `cpp/` (ITCH/OUCH/SBE/FIX/multicast/
    recovery/resilience/bench) with golden/malformed vectors and generators;
  - measured benchmarks `cpp/bench/benchmarks/*.json` (incl. HDR percentiles);
  - CI `.github/workflows/ci.yml` (green, latest 6/6 run `35542606468`);
  - `README.md` with the venue-connectivity layer section where EVERY claim
    points to an evidence file inside the repo;
  - `docs/EVIDENCE.md` extended with the new claim table.

## Required verifications

- Repo renders: YES (README/EVIDENCE markdown validated by GitHub).
- Evidence links OK: every relative link of the new sections resolves to an
  existing file in the repo (verified with `git ls-files`).
- Zero personal paths: YES — the publication scan over the whole repo finds
  no personal user-profile paths.
- Zero secrets: YES — scan for API tokens, key literals and private-key
  markers over the same set: 0 matches (the scan script itself lives at
  `cpp/evidence/10-latency-elite/PHASE6/scan_publication.ps1`).
- Not published: the live service tree, historical journals, holdout, frozen
  binaries, account credentials (the repo contains no credentials).

## Honesty (§5 of the project contract)

- The repo compensates with measurable evidence; it does not claim
  professional employment history nor work authorization in any country. No
  text in the repo makes such claims.
