# EVIDENCE — PHASE 1: ITCH 5.0 codec + OUCH semantics in C++

**Status: DONE (green).** Date: 2026-09-18. Directories: `cpp/itch/`, `cpp/ouch/`.

## Specs used (nothing invented)

- Official Nasdaq TotalView-ITCH 5.0, captured and pinned:
  `external-review/low-latency-reference/nasdaq-specs/NQTVITCHSpecification.pdf`
  SHA256 `45E0531D1B4B3BEB886E9618B2AB824A5AA9BDA3A99C0DFF03509306E68AACC3`
  (text extracted to `cpp/tools/extracted/NQTVITCHSpecification.txt` without
  modifying the PDF).
- Official Nasdaq OUCH 5.0:
  `external-review/low-latency-reference/nasdaq-specs/OUCH5.0.pdf`
  SHA256 `770253DE8B257AB68700AB5DBF179F806D890890683BF695AB8257585D8C2C00`.
- Annotated semantics: `MARKET_MICROSTRUCTURE_EXCHANGE_SYSTEMS.md` §5.5 (OUCH
  UserRefNum / replace chain) and §5.2/5.3 (ITCH lifecycle, big-endian
  encoding, fixed-point prices, ns timestamps).

## Test red → implementation → test green

1. **RED** (ITCH suite against a stub): `1 passed, 4 failed, 5 total`
   (golden_vectors_decode_exactly, malformed_corpus_rejected_without_crash,
   explicit_endian_and_fixed_point, max_price_boundary in red).
2. Implementation `cpp/itch/src/itch_codec.cpp` (offsets/lengths/validations
   taken from the spec tables: 1.1, 1.2.1, 1.2.2, 1.3.1, 1.3.2, 1.4.x,
   1.5.x; max price 0x77359400 from "Data Types" p.4).
3. **GREEN**: `5 passed, 0 failed, 5 total` — 17 golden vectors decoded
   exactly (messages S/R/H/A/F/E/C/X/D/U/P/Q/B), 8 malformed vectors with the
   exact typed status (Truncated/UnknownType/PriceOutOfRange), 200,000 random
   mutations without a crash.
4. **RED** (OUCH suite against a stub): `1 passed, 10 failed, 11 total`.
5. Implementation `cpp/ouch/src/ouch_codec.cpp` (OUCH tables 2.1/2.2/2.3 and
   3.2/3.3/3.4/3.6/3.8 + session engine: unique/increasing UserRefNum 1.2,
   replace outcomes 2.2, superfluous cancel 2.3, cumulative chain).
6. **GREEN**: `11 passed, 0 failed, 11 total` — 8 golden vectors + encoder
   byte-identical to the independent Python vector + 7 semantics scenarios.

## Verification required by the instruction

- All messages decoded against golden vectors from the official spec: YES
  (`itch/golden/*.bin` built byte-by-byte by `itch/tools/make_itch_golden.py`
  with per-vector section citations; the manifest carries the source SHA256).
- Malformed rejected without crash: YES (`itch/malformed/` + mutation test).

## Evidence files

- `cpp/itch/golden/manifest.json`, `cpp/itch/malformed/manifest.json`
- `cpp/ouch/golden/manifest.json`
- Reproducible green logs: `cpp/build.ps1 -Phase itch` / `-Phase ouch`
  (full run in `cpp/build/logs/ALL_PHASES_GREEN.log`).
