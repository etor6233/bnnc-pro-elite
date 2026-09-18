# EVIDENCIA — FASE 3-B: Detección instantánea + recuperación élite (OBLIGATORIA)

**Estado: DONE (verde).** Fecha: 2026-09-18. Directorio: `cpp/recovery/`.

## Spec usada (nada inventado)

- `ELITE_LOSS_RECOVERY_20260918.md` §0-§4 (raíz del workspace) + fuentes que
  anota (MoldUDP64, CME MDP 3.0 arbitration/recovery, B3 UMDF snapshot/RptSeq).
- `HOT_REDUNDANT_CAPTURE_AUTHORITY_V1.md` (límite honesto de Binance: los feeds
  duales son lanes independientes; el algoritmo A/B de CME es contraste, no
  contrato de Binance — el arbiter implementa el patrón genérico con ese
  límite documentado).
- `BINANCE_SOURCE_LOCK.md` web-socket-streams.md + `MARKET_MICROSTRUCTURE`
  §5.1 (regla local de libro: set quantity, cero elimina nivel, gap de
  update-id → resync).

## Implementación (los DOS casos del mandato)

1. **SILENCIO TOTAL**: `CadenceGuard` (depth@20ms; sin mensajes en 3 ventanas
   [dentro del rango 2-5 de la spec] = muerto, tipado al instante),
   `Watchdog` (deadline 5 s ping/pong). Causas tipadas:
   `transport_dead` / `exchange_silent` / `serverShutdown`.
2. **PÉRDIDA DE PAQUETES (flujo vivo)**: `DualLaneArbiter` — A/B por secuencia;
   hueco en UNA lane tipado con rango exacto y cubierto por la otra; hueco en
   AMBAS = ConsumerGap + `apply_snapshot` (snapshot + sequence bridging).
3. **Continuidad del libro**: `DerivedBook` con regla Binance de diff-depth
   (first==last+1; gap → ResyncNeeded tipado, jamás silencioso).
4. **Señales de anticipación** (`SignalMonitor`): desviación de tasa, frecuencia
   de huecos, tendencia RTT, rotación preventiva a las 23 h de 24 h.

## Test rojo → verde

- **ROJO** (stub): `0 passed, 10 failed, 10 total`.
- **VERDE**: `10 passed, 0 failed, 10 total`.

## Verificación exigida por la instrucción

- (a) Silencio total → detección tipada EN EL PLAZO declarado y failover a la
  otra lane: `cadence_exchange_silent_within_declared_deadline` (no dispara a
  119 ms, dispara `exchange_silent` a 120 ms con 3 ventanas de 20 ms) +
  `total_silence_failover_typed_hole` (A muere tras seq 10, B retoma en 15,
  hueco [11..14] TIPADO y B entrega continuo).
- (b) Pérdida en feed A → estado derivado continuo vía B o snapshot con hueco
  raw declarado: `ab_arbitration_loss_on_a_covered_by_b` (A pierde 5 → gap
  tipado [5..5] en A, B cubre, cero ConsumerGap) +
  `dual_loss_consumer_gap_and_snapshot_bridge` (pérdida en ambas → gap [4..5]
  declarado + snapshot bridging en 9 → continuidad).
- Integración real SBE→libro: `sbe_depth_diff_to_book_integration` (frame SBE
  generado con el encoder oficial, decodificado por FASE 2, aplicado al libro).

Log verde: `cpp/build.ps1 -Phase recovery` (y `ALL_PHASES_GREEN.log`).
