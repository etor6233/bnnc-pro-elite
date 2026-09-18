# EVIDENCIA — FASE 7: Integración SBE según política (decisión documentada)

**Estado: APLAZAMIENTO DOCUMENTADO (permitido por el mandato §4: "integración
SBE respetando la política (o decisión documentada de aplazamiento)").**
Fecha: 2026-09-18.

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
| JSON collector continuo con gates pasados (ítems 1-7) | El servicio productivo `hrs-5971e1d2cb41` (soak 24 h) está CORRIENDO; el gate de endurance aún no está aceptado | SBE no puede promocionarse todavía |
| Clave Ed25519 market-data-only separada | El usuario no la proveyó (la spec SBE oficial exige API key Ed25519 en header `X-MBX-APIKEY`) | No se puede abrir una lane SBE real |
| JSON y SBE con epochs/versiones de dataset independientes | Diseñado y documentado (ver abajo) | Listo para cuando se active |
| Comparación semántica exacta, medición de latencia/CPU, tests de recuperación | COMPLETADOS en este proyecto: decoder FASE 2 con cross-check contra el codec oficial, benchmarks FASE 5 (83 ns p50), recovery FASE 3-B/3-C | Pre-condiciones técnicas cubiertas |

## Qué SÍ está listo (y dónde está la evidencia)

- Decoder SBE del schema pineado con golden del encoder oficial: `cpp/sbe/`
  (EVIDENCE_02_SBE.md).
- Lane SBE con epochs independientes del JSON: el diseño de captura por capas
  `cpp/resilience/` ya trata cada camino como lane independiente con
  procedencia propia (EVIDENCE_03C_RESILIENCE.md); la política de "epochs
  separadas" se refleja en la ausencia total de código que fusione epochs
  JSON/SBE.
- Benchmarks de decode SBE (FASE 5) y recovery SBE→libro (FASE 3-B).

## Decisión

**Aplazar la integración SBE a la captura productiva** hasta que (a) el gate de
endurance del JSON pase, y (b) el usuario provea la clave Ed25519
market-data-only. Mientras tanto: JSON y SBE NO fusionan epochs en ningún
punto del código nuevo (verificado por diseño y por la ausencia de cualquier
acoplamiento entre `sbe/` y `binance_lob` en el árbol nuevo).

Sin llaves, sin datos live del venue y con el gate JSON abierto, encender una
lane SBE violaría la política; documentarlo es el resultado correcto y es el
que exige el mandato para esta fase.
