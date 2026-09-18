# EVIDENCIA — FASE 3: Transporte multicast UDP + sequence recovery

**Estado: DONE (verde).** Fecha: 2026-09-18. Directorio: `cpp/net/`.

## Specs usadas (nada inventado)

- `NETWORKING_DISTRIBUTED_STREAMING.md` §4 (UDP): contrato mínimo
  `version | message_type | stream/session_id | sequence | timestamp_domain |
  payload_length | integrity/authentication | payload` + lista obligatoria de
  definiciones de protocolo (ventana de secuencia y wrap, gap detection y
  recovery, dedup y caducidad, heartbeat, replay protection, límites por peer,
  conducta ante mensaje desconocido/truncado). Todas implementadas y
  documentadas en `cpp/net/include/net/mcast_feed.hpp`.
- `ELITE_LOSS_RECOVERY_20260918.md` §1-§3: detección instantánea por secuencia
  (llega N+k, esperábamos N+1 → hueco [N+1..N+k-1]), retransmisión downstream
  (MoldUDP64) y snapshot bridging.
- Aeron (referencia de DISEÑO, no copia): publicación por secuencia,
  retransmisión NAK, patrón ring buffer del media driver.

## Implementación

- `MulticastReceiver`/`MulticastSender` (join/leave IGMP, TTL, loopback),
  portátiles Winsock2/POSIX (para el CI Linux de FASE 6).
- `UnicastSocket` (listener de reparación NAK).
- Framing con integridad FNV-1a 32 y version check.
- `SequencedFeed`: gap instantáneo con rango exacto, dedup, ventana de
  reorden acotada (overflow = gap TIPADO, nunca pérdida silenciosa),
  retransmisiones entregadas como contenido recuperado, snapshot bridging,
  wraparound de secuencia en ventana 2^31.
- `SpscRing` (opcional de la instrucción): SPSC lock-free acotado con overflow
  EXPLÍCITO (try_push=false) según MARKET_MICROSTRUCTURE §5.4 (drop silencioso
  prohibido).

## Test rojo → verde

- **ROJO** (stub): `2 passed, 10 failed, 12 total`.
- **VERDE**: `12 passed, 0 failed, 12 total` — incluye los dos tests de
  transporte con sockets multicast REALES en loopback:
  - `multicast_join_leave_receive` (join/leave + recepción);
  - `multicast_loss_retransmission_e2e`: el publisher omite el datagrama 5,
    el receptor detecta el gap [5..5] AL INSTANTE, envía NAK al endpoint de
    reparación, el publisher retransmite desde su store y el receptor
    reconcilia la secuencia 1..10 completa (10/10 entregados exactamente una
    vez, seq 5 marcado recovered).

## Verificación exigida

- Test de pérdida/retransmisión y reconciliación por sequence number: SÍ
  (`multicast_loss_retransmission_e2e`).
- Log verde: `cpp/build.ps1 -Phase net` (y `ALL_PHASES_GREEN.log`).
- Nota de entorno documentada: los puertos 54507-54606 están en el rango
  excluido de Windows (WinNAT) en este host; los tests usan 45678-45680
  (comentado en `cpp/net/tests/test_mcast.cpp`).
