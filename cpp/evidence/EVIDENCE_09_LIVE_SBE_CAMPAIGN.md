# EVIDENCIA — Campaña SBE en vivo (candidata paralela, 2026-09-19)

**Estado: CORRIENDO y auditada en vivo.** Instancia arrancada 2026-09-19
12:54:44 local (PID 35468). Auditoría streaming ejecutada 2026-09-19 23:56Z
sobre la captura SIN detenerla (solo lectura). Key Ed25519 del usuario —
validada por el venue (`ACCEPTED_101`), nunca escrita en disco.

## Datos acumulados al momento de la auditoría

| Métrica | Valor MEDIDO |
|---|---|
| Duración de datos | ~11,0 h (4.524.293 frames) |
| Journal hash-chain (SHA-256) | **cadena VÁLIDA** (4.524.293 registros) |
| Eventos | LANE_START ×1, FRAME ×4.524.292 — **0 GAP_TYPED, 0 SERVER_SHUTDOWN, 0 TRANSPORT_DEAD** |
| Key en disco | **0 coincidencias** (scan de todos los archivos de salida) |
| Decode CLI (muestra de 20.000 frames) | **20.000/20.000 ok, exit 0** |
| Frames por tipo | trades 210.249 · bestBidAsk 1.238.489 · depth20 1.073.599 · depth-diff 2.084.550 |

## Cadencia medida (inter-arrival, dos símbolos combinados)

| Stream (template) | p50 | p99 |
|---|---|---|
| depth diff @20ms (10003) | 16 ms | 50 ms |
| depth20 @50ms (10002) | 40 ms | 62 ms |
| bestBidAsk (10001, on-change) | 2 ms | 292 ms |
| trade (10000, event-driven) | 42 ms | 1143 ms |

## Delay punta a punta medido (venue E → recepción local; offset via
`/api/v3/time`, incertidumbre declarada ±187,7 ms sin PTP)

| Stream | p50 | p99 | mean |
|---|---|---|---|
| depth diff @20ms | **125,5 ms** | 172,9 ms | 127,8 ms |
| depth20 @50ms | 125,5 ms | 161,6 ms | 127,6 ms |
| bestBidAsk | 126,7 ms | 418,1 ms | 133,5 ms |
| trade | 126,4 ms | 257,1 ms | 131,3 ms |

## Comparación honesta contra la campaña JSON anterior (sin SBE)

| Dimensión | JSON (anterior) | SBE (esta campaña) | Mejora real |
|---|---|---|---|
| Cadencia del libro | depth@100ms (10/s) | depth@20ms (50/s) | **5× densidad temporal** (medido: 52,6 diffs/s en vivo) |
| Tamaño de mensaje | ~600 B (JSON depth) | 82–114 B (SBE depth diff) | **~5–7× menos bytes** |
| Decode local | 1.500 ns p50 (json.loads) | **83 ns p50** (decoder FASE 2) | **~18×** |
| Delay de RED (venue→host) | p50 119,9–120,3 ms | p50 125,5–126,7 ms | **sin mejora** (misma red/venue; dentro de la incertidumbre ±188 ms) |
| Tipos de datos extra | — | bestBidAsk (auto-culling) + depth20 top-20 | **sí** |
| Telemetría por frame | no per-message | venue-E + recv por frame + cadena SHA-256 | **sí** |

Conclusión honesta: la red domina el delay en ambos caminos (~120–126 ms);
SBE no reduce la latencia de red — gana en **densidad, tamaño, costo de
decode y evidencia por frame**. Esa es exactamente la mejora declarable.

## Auditor reproducible

```powershell
python latency-probe-20260918\audit_sbe_lane.py <dir-captura> cpp\build\bin\sbe_decode_cli.exe
```

(streaming, no detiene la captura, no carga el journal completo en memoria).
