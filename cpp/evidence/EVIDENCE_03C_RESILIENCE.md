# EVIDENCIA — FASE 3-C: Arquitectura anti-pérdida por capas (OBLIGATORIA)

**Estado: DONE (verde).** Fecha: 2026-09-18. Directorio: `cpp/resilience/`.

## Spec usada (nada inventado)

- `ELITE_LOSS_RECOVERY_20260918.md` §6 (LA SOLUCIÓN DEFINITIVA ANTI-PÉRDIDA):
  1. duplicación en la fuente (dos caminos independientes del mismo dato);
  2. failover por capas FCP (feed vivo → cache local → API del venue → REST);
  3. reconciliación de gaps contra la fuente autoritativa tras cada
     recuperación;
  4. backfill desde el registro histórico del venue (Binance REST
     aggTrades/depth, pineado en `BINANCE_SOURCE_LOCK.md` rest-api.md);
  5. procedencia en la cadena: `captured-live` | `backfilled` + hash, nunca
     mezcla silenciosa.

## Implementación (`cpp/resilience/`)

- `LayeredCapture`: journal por secuencia con procedencia declarada por
  registro + hash de contenido (FNV-1a 32); dedup entre caminos redundantes
  conservando la procedencia del primero; failover por capas con orden
  documentado (live → cache → backfill REST); backfill inyectable
  (`BackfillFn`), cuyo binding productivo es Binance REST aggTrades/depth
  (documentado; requiere acceso live y key — fuera del alcance de esta
  calificación, límite declarado en el header).
- `reconcile()`: reconciliación autoritativa — completo solo si TODA
  secuencia emitida por el venue (1..high) está presente como contenido
  recuperable; registros gap-typed hacen la reconciliación INCOMPLETA con el
  rango exacto faltante.

## Test rojo → verde

- **ROJO** (stub): `0 passed, 5 failed, 5 total`.
- **VERDE**: `5 passed, 0 failed, 5 total`.

## Verificación exigida por la instrucción

Test que mata un camino entero, recupera por el otro + backfill, y demuestra
que el dataset final contiene TODO lo emitido por el venue con procedencia
declarada:

- `kill_entire_live_path_rest_backfill_recovers_all`: venue emite 1..25; A
  muere tras 10; backfill REST recupera 11..24 (`backfilled`); nuevo feed live
  entrega 25 (`captured-live`); reconcile vs venue=25 → COMPLETO; cada rango
  con su procedencia exacta.
- `cache_layer_serves_first_then_rest_backfill`: orden FCP verificado (cache
  local antes que REST; contenido de cache conserva `captured-live`).
- `dual_path_source_duplication_no_loss`: dos caminos independientes, A muere
  en 15, B cubre; 25/25 live, cero pérdida.
- `unrecoverable_window_typed_gap_exact_range`: si ni el backfill del venue
  tiene la secuencia 11 → queda TIPADA [11..11] y reconcile = INCOMPLETO
  (honestidad: nunca fingir completitud).
- `journal_hashes_bind_every_record`: hash por registro + procedencia del
  primer camino conservada.

Log verde: `cpp/build.ps1 -Phase resilience` (y `ALL_PHASES_GREEN.log`).
