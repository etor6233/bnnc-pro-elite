# EVIDENCE — PHASE 4: Minimal FIX Session Layer

**Status: DONE (green).** Date: 2026-09-18. Directory: `cpp/fix/`.

## Specs used (nothing invented)

- `MARKET_MICROSTRUCTURE_EXCHANGE_SYSTEMS.md` §5.5 [SPEC] (annotated):
  MsgSeqNum(34) orders session and application messages in ONE space;
  NextNumIn/NextNumOut persist across connections; a gap generates
  ResendRequest(35=2) and new messages are retained until the gap closes;
  retransmission preserves the original sequence and uses PossDupFlag(43)=Y;
  SequenceReset(35=4, GapFillFlag=Y) skips non-retransmitted messages;
  resetting the session is not an innocent repair; session retransmission =
  same MsgSeqNum + PossDup=Y with per-session deduplication.
- QuickFIX (canonical reference captured in
  `external-review/low-latency-reference/quickfix`): standard message layout
  (8=BeginString, 9=BodyLength, 35=MsgType, … 10=CheckSum = sum of bytes mod
  256 including SOH) — used as layout golden vectors, not copied.

## Implementation

- Codec: parse with strict BodyLength and CheckSum verification + typed
  rejection (Malformed/BadBodyLength/BadChecksum); build with automatic 9/10.
- `FixSession`: states (Disconnected/AwaitingLogon/LoggedOn/Closed),
  bidirectional logon, heartbeat, TestRequest(35=1)+112 echo, gap →
  ResendRequest (7=begin/16=end) + retention until closed, PossDup=Y
  retransmission with the original sequence, SequenceReset-GapFill,
  NextNumIn/Out persistence.

## Test red → green

- Golden vectors: 6 FIX messages byte-by-byte (`fix/tools/make_fix_golden.py`,
  per-vector citations).
- **GREEN**: `10 passed, 0 failed, 10 total` — exact golden, malformed with
  typed status, build→parse roundtrip, logon handshake, heartbeat/test
  request, gap→ResendRequest→PossDup with gap closure, gap-fill skip,
  persistence across reconnects, malformed counted without crash, PossDup
  dedup.

## Verification required

- Simulated session with sequence recovery: YES
  (`gap_detection_resend_request_possdup_retransmission` +
  `sequence_reset_gapfill_skips`).
- Green log: `cpp/build.ps1 -Phase fix` (and `ALL_PHASES_GREEN.log`).
