# ACTA FINAL — CAPA DE VENUE CONNECTIVITY C++ + CI + BENCHMARKS (2026-09-18)

Ejecución completa de la instrucción de ingeniería (2026-09-18) desde
FASE 1 hasta FASE 8, sin tocar el servicio productivo, XERJ, journals
históricos, holdout ni binarios congelados. Todo el trabajo nuevo vive en el
directorio NUEVO `cpp/` del workspace y fue publicado al repo público
`etor6233/bnnc-pro-elite` (rama `main`).

## Checklist §4 "Definition of DONE" — completo

| Ítem | Estado | Archivo de evidencia |
|---|---|---|
| FASE 0: referencias capturadas con SHA256 + INDEX | [x] (previa 2026-09-18) | `external-review/low-latency-reference/INDEX.md` + `BINANCE_SOURCE_LOCK.md` |
| FASE 1-4: codecs ITCH/SBE/OUCH-semántica + FIX session con suites verdes | [x] DONE | `cpp/evidence/EVIDENCE_01_ITCH_OUCH.md`, `EVIDENCE_02_SBE.md`, `EVIDENCE_03_MULTICAST.md`, `EVIDENCE_03B_RECOVERY.md`, `EVIDENCE_03C_RESILIENCE.md`, `EVIDENCE_04_FIX.md`; log 57/57 verde: `cpp/evidence/logs/ALL_PHASES_GREEN_20260918.log` (SHA256 `BE00419C6D74D34F5185EFFFEADEA1D6502909A89EEE2C3DF0CB5E1805DA4870`) |
| FASE 5: benchmarks medidos publicados | [x] DONE | `cpp/bench/benchmarks/bench_*_final.json` + `cpp/evidence/EVIDENCE_05_BENCHMARKS.md` |
| FASE 6: CI verde en Linux + Windows | [x] DONE | `.github/workflows/ci.yml`; GitHub Actions runs `35387520776` y `35388366114` (main) VERDES (4 jobs por run: C++, Rust+Python, Linux+Windows) + `cpp/evidence/EVIDENCE_06_CI.md` |
| FASE 7: integración SBE respetando la política (o decisión documentada de aplazamiento) | [x] APLAZAMIENTO DOCUMENTADO | `cpp/evidence/EVIDENCE_07_SBE_INTEGRATION.md` (cita `CAPTURE_CAMPAIGN_POLICY_V1.md` §Feed evolution y §Promotion sequence; gates JSON abiertos; sin key Ed25519) |
| FASE 8: repo público actualizado, escaneado (sin secretos ni rutas personales) | [x] DONE | `cpp/evidence/EVIDENCE_08_PUBLICATION.md` (merge `main`, README/EVIDENCE alineados, scan limpio) |
| Acta final: cada claim del README apunta a un archivo de evidencia | [x] DONE | Este archivo + tabla "Venue-connectivity layer" del README + `docs/EVIDENCE.md` |

## Resumen por fase (test rojo → verde, specs capturadas)

| Fase | Qué | ROJO | VERDE |
|---|---|---|---|
| 1 | ITCH 5.0 (17 golden, 8 malformed) | 1/5 | **5/5** |
| 1 | OUCH 5.0 semántica (8 golden + 7 escenarios) | 1/11 | **11/11** |
| 2 | SBE Binance + cross-check codec oficial | 1/4 | **4/4** |
| 3 | Multicast UDP + sequence recovery (e2e pérdida→NAK→retransmisión) | 2/12 | **12/12** |
| 3-B | Silencio total tipado + A/B arbitration + libro Binance | 0/10 | **10/10** |
| 3-C | Anti-pérdida por capas + backfill con procedencia | 0/5 | **5/5** |
| 4 | FIX session (logon/heartbeat/resend/reset/persistencia) | — (golden-driven) | **10/10** |
| 5 | Benchmarks dev+final | — | 8 JSON medidos |
| 6 | CI GitHub Actions Linux+Windows | 2 corridas rojas (toolchain/deps) | **VERDE 4/4 jobs** |
| 7 | SBE integración | — | Aplazamiento documentado por política |
| 8 | Publicación | — | Merge en `main`, scan limpio |

Total suites C++: **57/57 tests verdes** en Windows (MSVC) y en Linux (g++ vía CI).

## Límites honestos (mandato §5 y regla de no-inventar)

- La experiencia laboral de 3+ años NO se reemplaza con este repo; solo se
  compensa con evidencia medible. No se afirma lo contrario en ningún archivo.
- La autorización de trabajo en USA es un filtro externo; no se afirma en el
  repo.
- El repo no afirma cero-gaps: los huecos se TIPAN con rango exacto
  (gap-typed / ConsumerGap / ResyncNeeded) — ver suites 3/3-B/3-C.
- Los números históricos del proyecto (trades, depth, journals SHA256) no se
  tocaron; ningún archivo nuevo los reutiliza ni los reescribe.
- El servicio productivo (`Binance\artifacts\hrs\hrs-5971e1d2cb41`), XERJ,
  journals históricos, holdout y binarios release congelados NO fueron
  tocados: todo el trabajo nuevo está en `cpp/` y en el repo clonado en
  `cpp/public-repo/` (copia limpia), nunca en el árbol vivo.

## Evidencia ejecutable

```powershell
# Windows
powershell.exe -NoProfile -ExecutionPolicy Bypass -File cpp\build.ps1 -Phase all
# Linux
bash cpp/build.sh all
# Benchmarks (medidos, anti-trampa)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File cpp\bench\run_benchmarks.ps1 -Mode both
```

## Addendum (mismo día, tarde): latencia real medida + grafo actualizado

- Sonda independiente (dir nuevo `latency-probe-20260918/` → publicada en
  `cpp/probe/`): delay host↔Binance medido en vivo con método declarado.
  Depth BTCUSDT@100ms **p50 119,9 ms / p99 131,0 ms**; trades **p50 124,6 ms /
  p99 450,0 ms**; RTT REST 371,2 ms y WS ping/pong 388,3 ms (sin reloj);
  incertidumbre declarada ±185,6 ms (sin PTP); cadencia 100 ms verificada
  (inter-arrival p50 99,99 ms). Evidencia: `cpp/probe/REPORT.md` +
  `cpp/probe/report.json`.
- Grafo de arquitectura del README actualizado a la situación actual
  (capa C++ de venue-connectivity + benchmarks + CI + sonda de latencia).
- Re-verificación final: 57/57 tests locales verdes, CI en `main` verde
  (tras el push del grafo/probe), servicio productivo vivo y escribiendo
  (10 procesos, journals recientes), scan de secretos/rutas = 0.

Firmado por el agente ejecutor — 2026-09-18.
