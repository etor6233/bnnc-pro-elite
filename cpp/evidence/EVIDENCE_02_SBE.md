# EVIDENCIA — FASE 2: SBE decoder del schema oficial de Binance

**Estado: DONE (verde).** Fecha: 2026-09-18. Directorio: `cpp/sbe/`.

## Spec usada (nada inventado)

- Schema oficial PINEADO de Binance Spot:
  `external-review/low-latency-reference/binance-sbe-official/stream_1_0.xml`
  SHA256 `6EA328467E144311B1F1EFFF38E9FE613829997F041DD02A3B7077885D10A1F7`
  (vendido a `cpp/sbe/schema/stream_1_0.xml`, SHA256 idéntico verificado).
- `sbe-market-data-streams.md` capturado (SHA256 `3E945F52C279E0DCB894B25B4933CBB5165AB488A7014356DBE496EB5B54A41`):
  timestamps en microsegundos, depth@20ms, bestBidAsk con auto-culling, serverShutdown.
- Implementación canónica SBE (referencia, no copia): `external-review/low-latency-reference/simple-binary-encoding`.
- Codegen OFICIAL para golden vectors: `sbe-all-1.35.1.jar` (Maven Central,
  SHA256 `456384ED1DB090D018B4DC15BE152D371FA192E96AA4C98D362CC163BD18777E`)
  → headers generados en `cpp/tools/sbe-tool/gen/spot_stream/` (commitados).

## Método

1. Golden vectors producidos con el ENCODER oficial generado desde el MISMO
   schema pineado (`cpp/sbe/tools/make_sbe_golden.cpp`): TradesStreamEvent
   (id=10000), BestBidAskStreamEvent (10001), DepthSnapshotStreamEvent (10002),
   DepthDiffStreamEvent (10003).
2. Decoder propio defensivo `cpp/sbe/src/binance_sbe.cpp` (little-endian,
   messageHeader, groupSizeEncoding/groupSize16Encoding, varString8,
   mantissa64/exponent8, campo constante `isBestMatch` = True ausente del wire).
3. Cross-check: cada vector es decodificado por el decoder propio Y por el
   decoder generado oficial; TODOS los campos deben coincidir.

## Test rojo → verde

- **ROJO** (stub): `1 passed, 3 failed, 4 total`.
- **VERDE**: `4 passed, 0 failed, 4 total` — golden exacto + cross-check
  oficial campo a campo, 11 vectores malformed con estado tipado
  (Truncated/UnknownTemplate/SchemaMismatch/InvalidLayout), 100.000
  mutaciones sin crash, constante isBestMatch=1 verificada.

## Verificación exigida

- Mensajes golden decodificados con salida idéntica a la esperada por el
  schema: SÍ — incluye igualdad campo a campo contra el decoder OFICIAL.
- `cpp/sbe/golden/manifest.json` + `cpp/sbe/malformed/manifest.json`.
- Log verde: `cpp/build.ps1 -Phase sbe` (y `ALL_PHASES_GREEN.log`).
