# EVIDENCE — PHASE 3: Multicast UDP transport + sequence recovery

**Status: DONE (green).** Date: 2026-09-18. Directory: `cpp/net/`.

## Specs used (nothing invented)

- `NETWORKING_DISTRIBUTED_STREAMING.md` §4 (UDP): the minimum contract
  `version | message_type | stream/session_id | sequence | timestamp_domain |
  payload_length | integrity/authentication | payload` plus the mandatory
  protocol definitions (sequence window + wraparound, gap detection +
  recovery policy, dedup + expiry, heartbeat, replay protection, per-peer
  limits, behavior on unknown/truncated messages). All implemented and
  documented in `cpp/net/include/net/mcast_feed.hpp`.
- `ELITE_LOSS_RECOVERY_20260918.md` §1-§3: instant per-sequence detection
  (expected N+1, arrives N+k → gap [N+1..N+k-1]), downstream retransmission
  (MoldUDP64) and snapshot bridging.
- Aeron (DESIGN reference, not copied): sequence-based publication, NAK
  retransmission, media-driver ring-buffer pattern.

## Implementation

- `MulticastReceiver`/`MulticastSender` (IGMP join/leave, TTL, loopback),
  portable Winsock2/POSIX (for the Linux CI leg).
- `UnicastSocket` (NAK repair listener).
- Framing with FNV-1a 32 integrity and version check.
- `SequencedFeed`: instant gap with exact range, dedup, bounded reorder
  window (overflow = typed gap, never silent loss), retransmissions delivered
  as recovered content, snapshot bridging, 2^31 sequence wraparound.
- `SpscRing` (optional item): bounded lock-free SPSC with EXPLICIT overflow
  (try_push=false) per MARKET_MICROSTRUCTURE §5.4 (silent drop forbidden).

## Test red → green

- **RED** (stub): `2 passed, 10 failed, 12 total`.
- **GREEN**: `12 passed, 0 failed, 12 total` — including two transport tests
  with REAL loopback multicast sockets:
  - `multicast_join_leave_receive` (join/leave + receive);
  - `multicast_loss_retransmission_e2e`: the publisher drops datagram 5, the
    receiver detects gap [5..5] INSTANTLY, sends a NAK to the repair
    endpoint, the publisher retransmits from its store and the receiver
    reconciles the full 1..10 sequence (10/10 delivered exactly once, seq 5
    flagged recovered).

## Verification required

- Loss/retransmission test with sequence-number reconciliation: YES
  (`multicast_loss_retransmission_e2e`).
- Green log: `cpp/build.ps1 -Phase net` (and `ALL_PHASES_GREEN.log`).
- Environment note documented: Windows excluded UDP ranges (WinNAT) on this
  host; tests use ports outside them (commented in `cpp/net/tests/test_mcast.cpp`).
