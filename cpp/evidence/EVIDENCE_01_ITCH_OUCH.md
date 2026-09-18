# EVIDENCIA — FASE 1: Codec ITCH 5.0 + OUCH-semántica en C++

**Estado: DONE (verde).** Fecha: 2026-09-18. Directorio: `cpp/itch/`, `cpp/ouch/`.

## Specs usadas (nada inventado)

- Nasdaq TotalView-ITCH 5.0 oficial, capturada y pineada:
  `external-review/low-latency-reference/nasdaq-specs/NQTVITCHSpecification.pdf`
  SHA256 `45E0531D1B4B3BEB886E9618B2AB824A5AA9BDA3A99C0DFF03509306E68AACC3`
  (texto extraído a `cpp/tools/extracted/NQTVITCHSpecification.txt`, sin modificar el PDF).
- Nasdaq OUCH 5.0 oficial:
  `external-review/low-latency-reference/nasdaq-specs/OUCH5.0.pdf`
  SHA256 `770253DE8B257AB68700AB5DBF179F806D890890683BF695AB8257585D8C2C00`.
- Semántica anotada: `MARKET_MICROSTRUCTURE_EXCHANGE_SYSTEMS.md` §5.5 (OUCH UserRefNum /
  replace chain) y secciones 5.2/5.3 (ITCH lifecycle, codificación big-endian,
  precios fixed-point, timestamp ns).

## Test rojo → implementación → test verde

1. **ROJO** (suite ITCH contra stub): `1 passed, 4 failed, 5 total`
   (golden_vectors_decode_exactly, malformed_corpus_rejected_without_crash,
   explicit_endian_and_fixed_point, max_price_boundary en rojo).
2. Implementación `cpp/itch/src/itch_codec.cpp` (offsets/longitudes/validaciones
   tomados de las tablas de la spec: 1.1, 1.2.1, 1.2.2, 1.3.1, 1.3.2, 1.4.x,
   1.5.x; max price 0x77359400 de "Data Types" p.4).
3. **VERDE**: `5 passed, 0 failed, 5 total` — 17 golden vectors decodificados
   exactos (mensajes S/R/H/A/F/E/C/X/D/U/P/Q/B), 8 vectores malformed con
   estado tipado exacto (Truncated/UnknownType/PriceOutOfRange), 200.000
   mutaciones aleatorias sin crash.
4. **ROJO** (suite OUCH contra stub): `1 passed, 10 failed, 11 total`.
5. Implementación `cpp/ouch/src/ouch_codec.cpp` (tablas OUCH 2.1/2.2/2.3 y
   3.2/3.3/3.4/3.6/3.8 + motor de sesión: UserRefNum único/creciente 1.2,
   outcomes del replace 2.2, cancel superfluo 2.3, cadena acumulativa).
6. **VERDE**: `11 passed, 0 failed, 11 total` — 8 golden vectors + encoder
   byte-idéntico al vector independiente de Python + 7 escenarios de semántica.

## Verificación exigida por la instrucción

- Todos los mensajes decodificados contra golden de la spec oficial: SÍ
  (`itch/golden/*.bin` generados byte a byte por `itch/tools/make_itch_golden.py`
  con citas de sección por vector; manifest con SHA256 de la fuente).
- Malformed rechazado sin crash: SÍ (`itch/malformed/` + test de mutaciones).

## Archivos de evidencia

- `cpp/itch/golden/manifest.json`, `cpp/itch/malformed/manifest.json`
- `cpp/ouch/golden/manifest.json`
- Logs verdes reproducibles: `cpp/build.ps1 -Phase itch` / `-Phase ouch`
  (corrida completa en `cpp/build/logs/ALL_PHASES_GREEN.log`).
