# Fuzz — lob-replay (cargo-fuzz)

Target espejo de los fuzz harnesses de tetsuo (`fuzz_ws_frame.c`,
`fuzz_ws_frames.c`): alimenta bytes arbitrarios al modelo determinista de
transporte (`PublicWsSession.handle` + `watchdog_tick`) y exige que nunca
haya pánico.

## Uso (SOLO cuando se desee fuzzear; fuera del build congelado)

Requiere toolchain nightly + cargo-fuzz instalados. El toolchain congelado del
proyecto es 1.98.0 MSVC estable — este crate **no se compila** con
`cargo build`/`cargo test` normales y no afecta el build de producción.

```powershell
rustup toolchain install nightly
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run transport_ws   # desde rust/lob-replay/fuzz
cargo +nightly fuzz cmin transport_ws  # minimizar corpus
```

## Regla sagrada

Fuzzear es solo un refuerzo: nunca sustituye a los tests rojo→verde ni a los
gates sobre el camino real, y ningún cambio de fuzzing puede alterar los
números históricos (1.569.954/1.136.854 trades, 862.595/843.196 depth, 5 gaps
+ 5 rebootstrap por símbolo, hashes de journals).
