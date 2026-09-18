# RUNBOOK — SBE lane (candidate parallel lane, separate epochs)

Estado: **ejecutable**. La lane SBE corre como CANDIDATA en paralelo con su
propio directorio, sus propios epochs y su propia clave — nunca fusiona epochs
con las lanes JSON (CAPTURE_CAMPAIGN_POLICY_V1.md §Feed evolution). La
promoción a camino canónico sigue los gates de la política (comparación
semántica exacta, medición, recovery, decisión explícita).

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
