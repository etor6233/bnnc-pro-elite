# REPORT — Latencia medida host ↔ Binance Spot (2026-09-18 20:28Z)

Sonda INDEPENDIENTE (directorio nuevo `latency-probe-20260918/`): abre su
propia conexión pública y NO toca el servicio productivo de 24 h (verificado
vivo y escribiendo en el mismo período), XERJ, journals ni binarios
congelados.

## Método (declarado, nada estimado)

1. **Offset de reloj** local↔venue: `GET https://api.binance.com/api/v3/time`
   ×12 (endpoint pineado en `BINANCE_SOURCE_LOCK.md` rest-api.md, SHA256
   `49EA6809…`); offset = serverTime − (t_envío_local + RTT/2); mediana.
2. **Delay por mensaje**: stream público combinado
   `/stream?streams=btcusdt@depth@100ms/btcusdt@trade` en
   `stream.binance.com:9443` (pineado web-socket-streams.md, SHA256
   `32BF73A0…`); por mensaje:
   `delay = t_recepción_local − (E_event_time_ms + offset_mediano)`.
   `E` es el event time del venue (spec). Incertidumbre declarada:
   ±RTT_mediano/2 (asimetría de red no observable sin PTP).
3. **RTT sin reloj**: ping/pong WebSocket (3 respuestas) y RTT REST (12) —
   cifras que no dependen del offset.
4. La fase de datos es recepción PURA (sin stalls): los pings se hicieron
   después, para no contaminar la distribución (un primer intento con pings
   intercalados infló el p99 artificialmente a ~10 s por encolado propio —
   corregido y documentado).

## Resultados medidos (report.json)

| Métrica | Valor medido |
|---|---|
| Reloj local vs venue (offset mediano) | +30,6 ms (local adelantado) |
| RTT REST mediano (`/api/v3/time` ×12) | 371,2 ms |
| RTT WebSocket ping/pong | 388,3 ms (3 muestras: 396,8 / 400,2 / 368) |
| **Depth BTCUSDT@100ms: delay p50** | **119,9 ms** |
| Depth: delay p99 / mean / max | 131,0 / 121,3 / 386,2 ms |
| Depth: inter-arrival p50 / p99 | 99,99 / 110,2 ms (cadencia 100 ms verificada) |
| **Trade BTCUSDT: delay p50** | **124,6 ms** |
| Trade: delay p99 / mean / max | 450,0 / 131,8 / 451,0 ms |
| Trade: inter-arrival p50 / p99 | 4,3 µs / 1,05 s (ráfagas) |
| Muestras | 1785 depth + 3726 trades (180 s) |
| Incertidumbre del delay (reloj) | ±185,6 ms |

## Lectura honesta

- El componente de RED puro (sin relojes) es **RTT/2 ≈ 185–194 ms** un camino.
- El delay efectivo evento→recepción mide **p50 ≈ 120–125 ms** con
  incertidumbre ±186 ms; el p99 depth es ~131 ms y el p99 trade ~450 ms
  (ráfagas de trades entregadas juntas en la misma ventana de agregación).
- Los ~120 ms vs RTT/2 186 ms son compatibles dentro de la incertidumbre de
  reloj (±186 ms): no se afirma precisión mejor que ese rango SIN PTP/NTP
  verificado. Es exactamente el límite que declara el proyecto
  (timestamp ≠ exactitud sin clock domain documentado).
- La cadencia depth (100 ms) quedó verificada por medición: p50 99,99 ms.

Archivos: `probe.py` (reproducible), `report.json` (cifras exactas).
