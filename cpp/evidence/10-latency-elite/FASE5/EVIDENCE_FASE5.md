# FASE 5 evidence — CI artifacts, static report, 5-minute verification

Date: 2026-09-19.

## CI: benchmark job with artifacts (`.github/workflows/ci.yml`)

New `cpp-bench` job (Linux + Windows matrix):

- Windows: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
  cpp\bench\run_benchmarks.ps1 -Mode dev`
- Linux: `bash cpp/bench/run_benchmarks.sh dev` (new Linux mirror of the
  runner, added in this phase)
- Artifacts: every `cpp/bench/benchmarks/*_dev.json` and `*_dev_hdr.json`
  uploaded with `actions/upload-artifact@v4` (`if-no-files-found: error`),
  so the measured dev percentiles (including p50/p99/p99.9/p99.99) are
  downloadable from every green run.

Why final mode stays local (declared in the workflow comments): final-mode
numbers are only meaningful on a quiet machine dedicated to the measurement;
a shared CI runner is not one. CI therefore proves the suite builds and runs
on both platforms and publishes the dev JSONs — the final-mode JSONs are
measured locally and committed (`cpp/bench/benchmarks/bench_*_final*.json`).

## Verified CI run

Branch `latency-elite`, run **35542606468** (2026-09-20): **6/6 jobs green**
— Rust + Python (Linux, Windows), C++ suites (Linux, Windows), C++ benchmarks
dev (Linux, Windows). The benchmark artifacts (`benchmark-jsons-*`) are
downloadable from that run.

## Static benchmark report for GitHub Pages

- Generator: `cpp/bench/tools/make_pages_report.py` (stdlib-only) — reads
  the committed JSONs and renders `bench-latency/index.html` (committed,
  regenerated before each publication).
- Deploy (manual, documented): in the repository's GitHub Pages settings,
  choose "Deploy from a branch" and select branch `latency-elite` with
  folder `/bench-latency`. The page is fully static (no build step); the
  committed file is the deployable artifact. No Pages workflow was added
  because manual deploy keeps the CI surface minimal and the page is
  regenerated deterministically from committed JSONs.

## Badges + 5-minute verification (README)

- CI badge: GitHub Actions workflow `ci` on branch `latency-elite`
  (shields.io `github/actions/workflow/status` + `github/license` badge for
  MIT).
- "5-minute verification" section in the root README and in
  `portfolio/README.md`: clone → `bash cpp/build.sh all` →
  `bash cpp/bench/run_benchmarks.sh dev` → open `bench-latency/index.html`
  (Windows equivalents included).

## Artifact hashes

See `MANIFEST_FASE5.md` (workflow, page generator, generated page).
