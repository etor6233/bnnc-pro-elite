# EVIDENCIA — FASE 4: FIX Session Layer mínimo

**Estado: DONE (verde).** Fecha: 2026-09-18. Directorio: `cpp/fix/`.

## Specs usadas (nada inventado)

- `MARKET_MICROSTRUCTURE_EXCHANGE_SYSTEMS.md` §5.5 [SPEC] (anotada):
  MsgSeqNum(34) ordena mensajes de sesión y aplicación en un único espacio;
  NextNumIn/NextNumOut persisten a través de conexiones; un gap genera
  ResendRequest(35=2) y los mensajes nuevos se retienen hasta cerrar el hueco;
  la retransmisión conserva el sequence original y usa PossDupFlag(43)=Y;
  SequenceReset(35=4, GapFillFlag=Y) salta mensajes no retransmitidos;
  resetear la sesión no es una reparación inocua; retransmisión de sesión =
  mismo MsgSeqNum + PossDup=Y con deduplicación por sesión.
- QuickFIX (referencia canónica capturada en
  `external-review/low-latency-reference/quickfix`): layout estándar de
  mensaje (8=BeginString, 9=BodyLength, 35=MsgType, … 10=CheckSum = suma de
  bytes mod 256 incluyendo SOH) — usado como golden-vectors de layout, no
  copiado.

## Implementación

- Codec: parse con verificación estricta de BodyLength y CheckSum + rechazo
  tipado (Malformed/BadBodyLength/BadChecksum); build con 9/10 automáticos.
- `FixSession`: estados (Disconnected/AwaitingLogon/LoggedOn/Closed), logon
  bidireccional, heartbeat, TestRequest(35=1)+echo 112, gap → ResendRequest
  (7=begin/16=end) + retención hasta cierre, retransmisión PossDup=Y con
  secuencia original, SequenceReset-GapFill, persistencia NextNumIn/Out.

## Test rojo → verde

- Golden vectors: 6 mensajes FIX byte a byte (`fix/tools/make_fix_golden.py`,
  citas por vector).
- **VERDE**: `10 passed, 0 failed, 10 total` — golden exacto, malformed con
  estado tipado, roundtrip build→parse, handshake logon, heartbeat/test
  request, gap→ResendRequest→PossDup con cierre del hueco, gap-fill skip,
  persistencia entre reconexiones, malformed contado sin crash, dedup PossDup.

## Verificación exigida

- Sesión simulada con recuperación de secuencia: SÍ
  (`gap_detection_resend_request_possdup_retransmission` + `sequence_reset_gapfill_skips`).
- Log verde: `cpp/build.ps1 -Phase fix` (y `ALL_PHASES_GREEN.log`).
