# EVIDENCIA — FASE 5: Benchmarks honestos (medidos)

**Estado: DONE.** Fecha: 2026-09-18. Directorio: `cpp/bench/benchmarks/`.

## Método (anti-trampa)

- Cada iteración decodifica/encoda en una salida FRESCA y alimenta un sink
  volátil (anti dead-code elimination); NO hay memoización del caso medido.
- Latencia por batches cronometrados (tamaño de batch declarado en cada JSON)
  para eliminar el sesgo de granularidad del reloj en operaciones sub-100 ns.
- Modo dev (rápido) y modo final (tamaños held-out) — ambos ejecutados y
  publicados. Percentiles nearest-rank p50/p99 sobre las muestras reales.
- Números solo MEDIDOS en este host (MSVC cl 14.50 /O2, Windows x64; CPython
  3.14 stdlib json para la comparación JSON).

## Resultados FINALES (cifras exactas de benchmarks/*.json)

| Benchmark | p50 | p99 | throughput (medido) |
|---|---|---|---|
| ITCH 5.0 decode (C++) | 16 ns | 20 ns | 59.916.500 msg/s |
| SBE Binance decode (C++) | 83 ns | 111 ns | 11.822.300 msg/s |
| Publicación multicast UDP (29 B) | 2.682 ns | 95.146 ns | 203.376 dgram/s |
| JSON depth decode (Python stdlib) | 1.500 ns | 4.900 ns | 615.889 msg/s |

Comparación honesta decode SBE vs JSON actual: 83 ns (SBE C++) vs 1.500 ns
(JSON Python stdlib) de p50 por mensaje. Límite declarado: el parse JSON mide
solo json.loads sobre la cadena fija; la conversión de strings a decimales y
la aplicación al libro (que el camino JSON actual también paga) no están
incluidas en ese número — por eso la comparación se reporta por separado y
nunca como un único ratio engañoso.

## Archivos de evidencia (medidos, nunca estimados)

- `cpp/bench/benchmarks/bench_itch_final.json`
- `cpp/bench/benchmarks/bench_sbe_final.json`
- `cpp/bench/benchmarks/bench_mcast_final.json`
- `cpp/bench/benchmarks/bench_json_final.json`
- (modo dev: `bench_*_dev.json` en la misma carpeta)

Reproducible con `cpp/bench/run_benchmarks.ps1 -Mode both`.
