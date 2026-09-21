# EVIDENCE — PHASE 2: SBE decoder for the official Binance schema

**Status: DONE (green).** Date: 2026-09-18. Directory: `cpp/sbe/`.

## Spec used (nothing invented)

- Official PINNED Binance Spot schema:
  `external-review/low-latency-reference/binance-sbe-official/stream_1_0.xml`
  SHA256 `6EA328467E144311B1F1EFFF38E9FE613829997F041DD02A3B7077885D10A1F7`
  (vendored at `cpp/sbe/schema/stream_1_0.xml`, identical SHA256 verified).
- Captured `sbe-market-data-streams.md` (SHA256 `3E945F522C279E0DCB894B25B4933CBB5165AB488A7014356DBE496EB5B54A41`):
  timestamps in microseconds, depth@20ms, bestBidAsk with auto-culling,
  serverShutdown.
- Canonical SBE implementation (reference, not copied):
  `external-review/low-latency-reference/simple-binary-encoding`.
- OFFICIAL code generation for golden vectors: `sbe-all-1.35.1.jar` (Maven
  Central, SHA256 `456384ED1DB090D018B4DC15BE152D371FA192E96AA4C98D362CC163BD18777E`)
  → generated headers in `cpp/tools/sbe-tool/gen/spot_stream/` (committed).

## Method

1. Golden vectors produced with the OFFICIAL generated encoder from the SAME
   pinned schema (`cpp/sbe/tools/make_sbe_golden.cpp`): TradesStreamEvent
   (id=10000), BestBidAskStreamEvent (10001), DepthSnapshotStreamEvent
   (10002), DepthDiffStreamEvent (10003).
2. Own defensive decoder `cpp/sbe/src/binance_sbe.cpp` (little-endian,
   messageHeader, groupSizeEncoding/groupSize16Encoding, varString8,
   mantissa64/exponent8, constant field `isBestMatch` = True absent from the
   wire).
3. Cross-check: every vector is decoded by BOTH the own decoder and the
   official generated decoder; ALL fields must match.

## Test red → green

- **RED** (stub): `1 passed, 3 failed, 4 total`.
- **GREEN**: `4 passed, 0 failed, 4 total` — exact golden + official
  field-by-field cross-check, 11 malformed vectors with typed status
  (Truncated/UnknownTemplate/SchemaMismatch/InvalidLayout), 100,000 mutations
  without a crash, constant isBestMatch=1 verified.

## Verification required

- Golden messages decoded with output identical to what the schema expects:
  YES — including field-by-field equality against the OFFICIAL decoder.
- `cpp/sbe/golden/manifest.json` + `cpp/sbe/malformed/manifest.json`.
- Green log: `cpp/build.ps1 -Phase sbe` (and `ALL_PHASES_GREEN.log`).
