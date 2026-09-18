# RUNBOOK — SBE lane (candidate parallel lane, separate epochs)

Estado: **ejecutable**. La lane SBE corre como CANDIDATA en paralelo con su
propio directorio, sus propios epochs y su propia clave — nunca fusiona epochs
con las lanes JSON (CAPTURE_CAMPAIGN_POLICY_V1.md §Feed evolution). La
promoción a camino canónico sigue los gates de la política (comparación
semántica exacta, medición, recovery, decisión explícita).

## Medición punta a punta (ya instrumentada)

Cada frame capturado escribe `sbe-telemetry.jsonl` con el **event time del
venue** (primer campo del schema SBE, `eventTime` µs en offset 8 — se lee del
propio frame, sin depender de nada externo) y el **instante de recepción
local**. La pata de red se mide así:

```powershell
python cpp\sbe-lane\measure_sbe_lane.py --dir <dir-de-la-lane> --out measure.json
```

`measure.json` trae, por tipo de mensaje: delay p50/p99/mean/max entre el
venue y nosotros, y el inter-arrival (cadencia). El offset de reloj se mide
contra `/api/v3/time` (incertidumbre declarada ±RTT/2, ~±190 ms en este host
sin PTP). Las patas LOCALES (recepción→almacenado→decodificado) son ns/µs y
están medidas en los benchmarks de FASE 5 (SBE decode 83 ns p50) — la red
domina por ~5 órdenes de magnitud.

## Cómo decidimos si la corrida es "perfecta" (criterios medibles)

| # | Criterio | Cómo se mide | Umbral esperado en este host |
|---|---|---|---|
| 1 | Cadencia real | `measure_sbe_lane.py` inter-arrival | depth@20ms → p50 ≈ 20 ms; sin ventanas vacías sin tipar |
| 2 | Cero corrupción | `sbe_decode_cli.exe <dir>\frames.sbe` | exit 0 sobre el 100% de los frames |
| 3 | Journal íntegro | re-verificación de la cadena SHA-256 | cadena válida; huecos entre conexiones = `GAP_TYPED`, cero silencio |
| 4 | Delay punta a punta | `measure_sbe_lane.py` | wire p50 ≈ 120 ms (medido hoy), p99 acotado, incertidumbre declarada |
| 5 | Igualdad semántica vs JSON | ventana solapada de ambas lanes | trades idénticos por trade id; libro converge (gate de promoción de la política) |
| 6 | Rotación | `--max-conn-s 82800` | 23 h sin pérdida, hueco de rotación TIPADO |

**"Perfecta" = criterios 1-4 sin una sola excepción en la corrida completa,
más el 5 en la ventana de comparación, más la aceptación formal del gate de
endurance JSON (política).** Hasta entonces la lane es candidata con evidencia
medida, no un claim.

## Requisito único para correr en vivo

Una **API key Ed25519 market-data-only** de Binance (spec:
`sbe-market-data-streams.md` capturada, SHA256 `3E945F52…`; la key va en el
header `X-MBX-APIKEY` del handshake WebSocket). Sin key, el endpoint rechaza
la conexión — es el único bloqueo externo.

## Compilar y probar (sin key, contra mock local)

```powershell
# Windows
powershell.exe -NoProfile -ExecutionPolicy Bypass -File cpp\build.ps1 -Phase all
python -m pip install "websockets==17.0.1"
$env:PYTHONPATH = "cpp\sbe-lane"
python -m unittest discover -s cpp\sbe-lane\tests -v    # 3/3 green

# Linux
bash cpp/build.sh all
PYTHONPATH=cpp/sbe-lane python3 -m unittest discover -s cpp/sbe-lane/tests -v
```

## Correr en vivo (con key)

```powershell
$env:BINANCE_SBE_API_KEY = "<ED25519_MARKET_DATA_ONLY>"
python cpp\sbe-lane\sbe_lane.py `
  --url "wss://stream-sbe.binance.com:9443/stream?streams=btcusdt@depth@20ms/btcusdt@depth/btcusdt@trade/btcusdt@bestBidAsk/ethusdt@depth@20ms/ethusdt@depth/ethusdt@trade/ethusdt@bestBidAsk" `
  --out "D:\captures\sbe-<fecha-hora>" `
  --duration 0 `
  --max-conn-s 82800
```

- `--duration 0` = corre hasta rotación/terminación; `--max-conn-s 82800` = 23 h
  (límite del venue: 24 h por conexión; rotación preventiva como la lane JSON).
- La key NO se escribe en ningún archivo de salida (solo viaja en el
  handshake; el journal registra `api_key_present: true` sin la key).

## Qué escribe (create-only, todo dentro de --out)

| Archivo | Contenido |
|---|---|
| `frames.sbe` | frames SBE crudos, prefijados por longitud u32-LE |
| `sbe-events.jsonl` | journal hash-chain (SHA-256): LANE_START, FRAME (sha256+template_id), SERVER_SHUTDOWN, CONN_CLOSED, TRANSPORT_DEAD, GAP_TYPED (rango de pared exacto entre conexiones), LANE_END |
| `sbe-terminal.json` | inventario terminal: archivos, bytes, SHA-256, conteo de frames |

## Verificar una corrida

```powershell
cpp\build\bin\sbe_decode_cli.exe <dir>\frames.sbe   # JSON por frame, exit 0 = todo decodificó
```

El decodificador es el mismo de FASE 2 (schema pineado `6EA32846…`,
cross-check contra el codec oficial de Simple Binary Encoding).

## Límites declarados

- La lane es CANDIDATA; el camino JSON sigue siendo el oráculo de corrección.
- Los huecos entre conexiones quedan TIPADOS con rango de pared; cero pérdida
  silenciosa.
- La reconciliación contra el backfill REST del venue (aggTrades/depth) para
  ventanas perdidas es la capa documentada en `cpp/resilience/`
  (EVIDENCE_03C) — integrarla a esta lane es el siguiente paso de política,
  no un reemplazo del gate actual.
