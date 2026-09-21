# Fuzz — lob-replay (cargo-fuzz)

Mirror target of the tetsuo fuzz harnesses (`fuzz_ws_frame.c`,
`fuzz_ws_frames.c`): feeds arbitrary bytes to the deterministic transport
model (`PublicWsSession.handle` + `watchdog_tick`) and requires that it never
panics.

## Usage (ONLY when fuzzing is wanted; outside the frozen build)

Requires the nightly toolchain + cargo-fuzz installed. The project's frozen
toolchain is stable 1.98.0 MSVC — this crate does NOT build with normal
`cargo build`/`cargo test` and does not affect the production build.

```powershell
rustup toolchain install nightly
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run transport_ws   # from rust/lob-replay/fuzz
cargo +nightly fuzz cmin transport_ws  # minimize the corpus
```

## Sacred rule

Fuzzing is only a reinforcement: it never replaces the red→green tests or the
gates on the real path, and no fuzzing change may alter the historical
numbers (1,569,954/1,136,854 trades, 862,595/843,196 depth, 5 gaps + 5
rebootstrap per symbol, journal hashes).