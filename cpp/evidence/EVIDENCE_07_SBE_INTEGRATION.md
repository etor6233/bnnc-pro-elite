# EVIDENCIA — FASE 7: Integración SBE según política

**Estado: LANE EJECUTABLE como candidata paralela; PROMOCIÓN aplazada por
política (permitido por el mandato §4: "decisión documentada de
aplazamiento").** Fecha: 2026-09-18.

## Lo nuevo (2026-09-18, tarde): la lane corre — solo falta la key

- `cpp/sbe-lane/sbe_lane.py`: captura SBE con epochs PROPIOS (nunca fusiona
  con JSON), journal hash-chain (SHA-256), huecos TIPADOS entre conexiones
  (`GAP_TYPED` con rango de pared exacto), `serverShutdown` tipado,
  rotación preventiva a 23 h, key Ed25519 via header `X-MBX-APIKEY` (nunca se
  escribe en disco).
- `cpp/sbe-lane/sbe_decode_cli.cpp`: CLI de verificación que decodifica los
  frames capturados con el decoder FASE 2 (schema pineado `6EA32846…`).
- Tests rojo→verde `cpp/sbe-lane/tests/test_sbe_lane.py`: **3/3 verdes** contra
  un servidor mock local que sirve los golden del encoder oficial —
  (1) captura byte-idéntica + journal válido + decode CLI exacto
  (template ids 10000/10003/10001), (2) ping→pong + `serverShutdown` tipado,
  (3) reconexión con `GAP_TYPED`. Sin key real: el único bloqueo externo para
  correr en vivo es la key Ed25519.
- Runbook: `cpp/sbe-lane/RUNBOOK_SBE_LANE.md` (compilar, probar, correr en
  vivo, verificar). CI: la suite de la lane corre en Linux+Windows.

## La política aplicable

`Binance/docs/CAPTURE_CAMPAIGN_POLICY_V1.md` §Feed evolution (líneas 256-263):

> JSON `depth@100ms` plus individual `trade` remains the correctness oracle.
> Once the continuous JSON collector passes its gates, SBE `depth` at 20 ms and
> SBE trades become a parallel candidate using a separate Ed25519
> market-data-only key. JSON and SBE retain separate epochs and dataset
> versions. SBE can be promoted only after exact semantic comparison,
> latency/CPU measurement, recovery tests and an explicit compatibility
> decision.

Y §Promotion sequence ítem 8: "only then consider SBE promotion and economic
feature/model gates" — después de los gates 1-7 del JSON.

## Estado real vs precondiciones de la política

| Precondición de la política | Estado observado | Consecuencia |
|---|---|---|
| JSON collector continuo con gates pasados (ítems 1-7) | El servicio productivo `hrs-5971e1d2cb41` (soak 24 h) está CORRIENDO; el gate de endurance aún no está aceptado | La PROMOCIÓN de SBE sigue aplazada |
| Clave Ed25519 market-data-only separada | El usuario no la proveyó (la spec SBE oficial exige API key Ed25519 en header `X-MBX-APIKEY`) | Único bloqueo para CORRER la lane en vivo |
| JSON y SBE con epochs/versiones de dataset independientes | Implementado: `cpp/sbe-lane/` escribe epochs propios (`sbe-…`) y nunca toca los árboles JSON | Cumplido por construcción |
| Comparación semántica exacta, medición de latencia/CPU, tests de recuperación | COMPLETADOS: decoder FASE 2 cross-check oficial, benchmarks FASE 5 (83 ns p50), recovery FASE 3-B/3-C, lane 3/3 vs mock | Pre-condiciones técnicas cubiertas |

## Qué SÍ está listo (y dónde está la evidencia)

- Decoder SBE del schema pineado con golden del encoder oficial: `cpp/sbe/`
  (EVIDENCE_02_SBE.md).
- **Lane SBE ejecutable**: `cpp/sbe-lane/` con captura, journal tipado,
  verificación CLI y 3/3 tests verdes contra mock local
  (`cpp/sbe-lane/RUNBOOK_SBE_LANE.md`).
- Benchmarks de decode SBE (FASE 5) y recovery SBE→libro (FASE 3-B).

## Decisión

- **CORRER la lane**: habilitado en cuanto exista la key Ed25519
  market-data-only (comando exacto en `RUNBOOK_SBE_LANE.md`). La lane corre
  como candidata paralela con epochs independientes — eso es exactamente lo
  que permite la política.
- **PROMOVER SBE a camino canónico**: aplazado hasta que el gate de endurance
  del JSON pase y se complete la secuencia de promoción (comparación
  semántica exacta, medición, recovery, decisión explícita).
