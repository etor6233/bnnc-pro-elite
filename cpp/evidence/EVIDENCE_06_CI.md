# EVIDENCE — PHASE 6: CI in the public repository (Linux + Windows)

**Status: DONE (green checkmark).** Date: 2026-09-18/19.

## Workflow

- `.github/workflows/ci.yml` in `etor6233/bnnc-pro-elite`: on every push/PR,
  Linux + Windows matrix:
  - **Rust**: `cargo fmt --check`, `cargo test --all-targets`,
    `cargo clippy --all-targets -- -D warnings`, and the explicit gate for
    the Windows-only modules (`windows_etw`/`windows_tcp` are `#[cfg(windows)]`
    in `rust/lob-replay/src/lib.rs`): building on Windows exercises their
    inclusion, on Linux their exclusion.
  - **Python**: `unittest discover` with `websockets==17.0.1` (Windows wheel
    hash-lock on CI-Windows; the same pinned version on Linux).
  - **C++**: `cpp/build.ps1 -Phase all` (MSVC, Windows) and `cpp/build.sh all`
    (g++, Linux) — all suites with golden-vector regeneration on every run.
  - **C++ benchmarks dev**: runs the dev-mode benchmark suite on both OSes
    and uploads the percentile JSONs as artifacts (2026-09-19).

## Real iterations until green (evidence of the runs)

1. Run `35385665414` (red): vcvars not located via vswhere on the runner;
   rustfmt/clippy missing with the minimal profile.
2. Run `35385923090` (red): Python missing `websockets`; 5 network-trace
   tests with a fixture that did not bind the resolved path.
3. Run `35386528141` (red): Windows-specific wheel hash-lock failing on
   Linux.
4. **Run `35387520776` (GREEN)** — green checkmark on GitHub:

| Job | Result | Duration |
|---|---|---|
| C++ suites (windows-latest) | ✓ | 1m25s |
| C++ suites (ubuntu-latest) | ✓ | 32s |
| Rust + Python (windows-latest) | ✓ | 5m32s |
| Rust + Python (ubuntu-latest) | ✓ | 2m27s |

Later GREEN runs on `main` and on `latency-elite` (same YAML, same gates):
`35388366114`, `35405115134`, and **`35542606468` (6/6 jobs, including the
benchmark job on both OSes)**.

## Evidence files

- `.github/workflows/ci.yml` (repo)
- Green run URL: `https://github.com/etor6233/bnnc-pro-elite/actions/runs/35542606468`
- Per-job logs downloadable from that run.
