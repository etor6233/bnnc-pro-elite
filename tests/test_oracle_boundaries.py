"""ADR-17 B5 closed-oracle boundary regressions (audit-review-20260908 R2).

The closed verification must derive its expectation from the SEALED RAW
evidence, never from the output being verified:

- an EMPTY canonical trade stream against a non-empty sealed raw union is a
  REJECTION (the external cut is the raw); a genuinely empty window passes
  only when the sealed evidence is empty too;
- the depth final boundary is enforced independently of the trade oracle: a
  canonical depth stream that ends mid-gap, is empty against non-empty
  sealed evidence, or stops short of a TRUSTED contiguous continuation of
  the publishing lane is a FINAL OMISSION and must be rejected.

The fixtures below build real sealed raw generations (snapshot + depth +
trade streams with manifests and BNACK progress) and run the closed oracle
through `_verify_with_oracle`, plus in-memory unit checks of the two rules.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
import unittest
from base64 import b64encode
from pathlib import Path
from unittest.mock import patch

from binance_lob.live_arbitration_verify_cli import (
    ZERO_DIGEST,
    ArbitrationVerificationError,
    _Canonical,
    _generation_terminal_complete,
    _stream_fully_sealed,
    _verify_depth,
    _verify_trades,
    _verify_with_oracle,
)
from binance_lob.segment_chain import MANIFEST_MAGIC, RAW_MAGIC

LENGTH = struct.Struct(">I")
SPEC_REVISION = "976cc580553890e92031b77306147c0ed1de5a46"
SNAPSHOT_PAYLOAD = (
    b'{"lastUpdateId":100,"bids":[["100","2"],["99","1"]],"asks":[["101","3"],["102","1"]]}'
)


def _digest_body(body: dict) -> str:
    encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_journal(directory: Path, payloads: list[dict]) -> Path:
    """Writes one hash-chained canonical journal file in the canonical form
    shared by both verifiers: the payload map serializes with SORTED keys
    (the Rust scanner canonicalizes serde_json Value/BTreeMap that way)."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "canonical-live.jsonl"
    previous = ZERO_DIGEST
    with path.open("w", encoding="utf-8") as handle:
        for index, payload in enumerate(payloads):
            canonical_payload = json.loads(
                json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            )
            body = {
                "schema": "LiveArbitrationJournalRecordV1",
                "record_index": index,
                "wall_ns": 1000 + index,
                "mono_ns": 500 + index,
                "channel": "LIVE",
                "payload": canonical_payload,
                "previous_record_sha256": previous,
            }
            record_sha256 = _digest_body(body)
            envelope = {"body": body, "record_sha256": record_sha256}
            handle.write(json.dumps(envelope, separators=(",", ":"), ensure_ascii=False) + "\n")
            previous = record_sha256
    return path


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _encoded_record(body: bytes) -> tuple[bytes, str]:
    digest = hashlib.sha256(body).digest()
    return LENGTH.pack(len(body)) + body + digest, digest.hex()


def _raw_body(*, symbol: str, stream: str, epoch: str, frame_index: int, payload: bytes, previous: str) -> dict:
    return {
        "schema": "RawFrameV1",
        "venue": "binance-spot",
        "environment": "production-public-market-data",
        "endpoint": "wss://data-stream.binance.vision:443/ws/fixture",
        "stream": stream,
        "symbol": symbol,
        "connection_epoch": epoch,
        "frame_index": frame_index,
        "receive_wall_ns": 1_700_000_000_000_000_000 + frame_index,
        "receive_mono_ns": 1_000_000 + frame_index,
        "clock_quality": "SYNCHRONIZED",
        "clock_source": "test-clock",
        "clock_offset_ns": None,
        "clock_uncertainty_ns": None,
        "payload_length": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_base64": b64encode(payload).decode("ascii"),
        "recorder_state": "PENDING",
        "spec_revision": SPEC_REVISION,
        "previous_record_sha256": previous,
    }


def _write_raw(path: Path, *, symbol: str, stream: str, epoch: str, payloads: list[bytes], previous: str = ZERO_DIGEST) -> tuple[str, int]:
    encoded = bytearray(RAW_MAGIC)
    digest = previous
    for offset, payload in enumerate(payloads):
        body = _canonical(
            _raw_body(
                symbol=symbol, stream=stream, epoch=epoch,
                frame_index=offset, payload=payload, previous=digest,
            )
        )
        record, digest = _encoded_record(body)
        encoded.extend(record)
    path.write_bytes(bytes(encoded))
    return digest, len(encoded)


def _seal(*, index: int, raw_file: str, epoch: str, stream: str, records: int, offset: int, previous: str, terminal: str) -> dict:
    return {
        "schema": "RawSegmentSealV1",
        "segment_index": index,
        "raw_file": raw_file,
        "connection_epoch": epoch,
        "stream": stream,
        "first_frame_index": 0,
        "last_frame_index": records - 1,
        "records": records,
        "durable_through_offset": offset,
        "previous_segment_terminal_sha256": previous,
        "terminal_record_sha256": terminal,
    }


def _write_manifest(path: Path, seals: list[dict]) -> None:
    encoded = bytearray(MANIFEST_MAGIC)
    previous = ZERO_DIGEST
    for record_index, seal in enumerate(seals):
        body = _canonical(
            {
                "schema": "RawSegmentManifestRecordV1",
                "record_index": record_index,
                "previous_manifest_record_sha256": previous,
                "seal": seal,
            }
        )
        record, previous = _encoded_record(body)
        encoded.extend(record)
    path.write_bytes(bytes(encoded))


def _write_progress(path: Path, raw_file: str, seal: dict) -> None:
    ack = {
        "schema": "DurabilityAckV1",
        "durable_record_count": seal["records"],
        "durable_through_offset": seal["durable_through_offset"],
        "last_record_sha256": seal["terminal_record_sha256"],
        "streams": [
            {
                "connection_epoch": seal["connection_epoch"],
                "stream": seal["stream"],
                "durable_through_frame_index": seal["last_frame_index"],
            }
        ],
    }
    body = {
        "schema": "RawDurabilityProgressV1",
        "record_index": 0,
        "raw_path": raw_file,
        "ack": ack,
        "previous_record_sha256": ZERO_DIGEST,
    }
    envelope = {"body": body, "record_sha256": hashlib.sha256(_canonical(body)).hexdigest()}
    path.write_bytes(_canonical(envelope) + b"\n")


DEPTH_FRAMES = [
    b'{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":101,"u":103,"b":[["100","1"]],"a":[]}',
    b'{"e":"depthUpdate","E":2,"s":"BTCUSDT","U":104,"u":107,"b":[["100","0"]],"a":[]}',
    b'{"e":"depthUpdate","E":3,"s":"BTCUSDT","U":108,"u":110,"b":[],"a":[["103","4"]]}',
]
TRADE_PAYLOADS = {
    10: b'{"e":"trade","E":1,"s":"BTCUSDT","t":10,"p":"100.00","q":"1.00","T":1,"m":true,"M":true}',
    11: b'{"e":"trade","E":1,"s":"BTCUSDT","t":11,"p":"101.00","q":"1.00","T":1,"m":true,"M":true}',
    12: b'{"e":"trade","E":1,"s":"BTCUSDT","t":12,"p":"102.00","q":"1.00","T":1,"m":true,"M":true}',
    13: b'{"e":"trade","E":1,"s":"BTCUSDT","t":13,"p":"103.00","q":"1.00","T":1,"m":true,"M":true}',
}


def _write_stream(generation: Path, name: str, epoch: str, payloads: list[bytes], symbol: str = "BTCUSDT") -> None:
    stream_name = f"btcusdt@depth@100ms" if name == "depth" else "btcusdt@trade"
    stream_dir = generation / name
    stream_dir.mkdir(parents=True, exist_ok=True)
    raw_file = "segment-000000.bnraw"
    terminal, offset = _write_raw(
        stream_dir / raw_file, symbol=symbol, stream=stream_name, epoch=epoch, payloads=payloads
    )
    if payloads:
        seal = _seal(
            index=0, raw_file=raw_file, epoch=epoch, stream=stream_name,
            records=len(payloads), offset=offset, previous=ZERO_DIGEST, terminal=terminal,
        )
        _write_manifest(stream_dir / "segments.bnseg", [seal])
        _write_progress(stream_dir / "segment-000000.bnack", raw_file, seal)
    else:
        _write_manifest(stream_dir / "segments.bnseg", [])


def _build_artifact(root: Path, *, with_depth: bool = True, with_trades: bool = True, depth_frames: list[bytes] | None = None) -> Path:
    """Builds a sealed raw artifact root with p/ and s/ lane roots, one
    campaign and one generation per lane.  PRIMARY carries trades
    {10,12,13} and SHADOW {11,12,13} (union {10,11,12,13}); both lanes carry
    the same depth frames (serving-lane trusted evidence)."""
    artifact = root / "artifact"
    depth_frames = DEPTH_FRAMES if depth_frames is None else depth_frames
    for lane, trade_ids in (("p", [10, 12, 13]), ("s", [11, 12, 13])):
        generation = artifact / lane / "hr-campaign" / "generations" / "fixture-g000"
        generation.mkdir(parents=True, exist_ok=True)
        snapshot_path = generation / "snapshot.bnraw"
        _write_raw(
            snapshot_path,
            symbol="BTCUSDT",
            stream="btcusdt@rest-depth-snapshot",
            epoch="snapshot-fixture",
            payloads=[SNAPSHOT_PAYLOAD],
        )
        if with_depth:
            _write_stream(generation, "depth", "depth-fixture", depth_frames)
        if with_trades:
            _write_stream(
                generation, "trade", "trade-fixture",
                [TRADE_PAYLOADS[trade_id] for trade_id in trade_ids],
            )
    return artifact


class UnsealedLaneToleranceTests(unittest.TestCase):
    """ADR-17 B5 (defect hrs-14572a22e336): frames published from evidence the
    SAME classification excluded (unsealed lane) are tolerated — the exclusion
    and the tolerance must come from one snapshot."""

    def test_frame_from_an_unsealed_lane_the_oracle_excluded_is_tolerated(self):
        canonical = _Canonical()
        canonical.depth.append({
            "lane": "PRIMARY",
            "first_sequence": 740743,
            "final_sequence": 740752,
            "digest": "d",
        })
        canonical.last_depth_event = "frame"
        _verify_depth(
            canonical,
            {"p": {103: [(100, "d100")]}, "s": {}},
            tolerant_lanes=True,
            enforce_final_boundary=False,
            unsealed_lanes={"p"},
        )

    def test_same_frame_without_the_unsealed_classification_rejects(self):
        canonical = _Canonical()
        canonical.depth.append({
            "lane": "PRIMARY",
            "first_sequence": 740743,
            "final_sequence": 740752,
            "digest": "d",
        })
        with self.assertRaises(ArbitrationVerificationError):
            _verify_depth(
                canonical,
                {"p": {103: [(100, "d100")]}, "s": {}},
                tolerant_lanes=True,
                enforce_final_boundary=False,
                unsealed_lanes=set(),
            )


class LiveRotationSealAuthorityTests(unittest.TestCase):
    """ADR-17 boundary authority (defect hrs-a8d39b6c0204): the durable
    terminal declaration (generation.json COMPLETE) is the ONLY authority for
    "the stream can never deliver again" — a live rotation window with the
    next segment file absent must never be misread as the definitive end."""

    def test_live_rotation_window_is_not_misread_as_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            generation = Path(directory) / "g000"
            (generation / "depth").mkdir(parents=True)
            _write_manifest(generation / "depth" / "segments.bnseg", [])
            # No COMPLETE declaration: not fully sealed (the old predicate
            # returned True here — the misclassification of hrs-a8d39b6c0204).
            self.assertFalse(_generation_terminal_complete(generation))
            self.assertFalse(_stream_fully_sealed(generation, "depth"))
            # Durable COMPLETE declaration: fully sealed.
            (generation / "generation.json").write_text(
                '{"schema":"RawGenerationManifestV1","status":"COMPLETE","failure":null}',
                encoding="utf-8",
            )
            self.assertTrue(_generation_terminal_complete(generation))
            self.assertTrue(_stream_fully_sealed(generation, "depth"))
            # A partial mid-write declaration is no proof of COMPLETE.
            (generation / "generation.json").write_text('{"status":"COMPLE', encoding="utf-8")
            self.assertFalse(_stream_fully_sealed(generation, "depth"))
            # A failed generation is never fully sealed as success.
            (generation / "generation.json").write_text(
                '{"status":"COMPLETE","failure":{"reason":"x"}}', encoding="utf-8"
            )
            self.assertFalse(_stream_fully_sealed(generation, "depth"))


class ClosedOracleBoundaryTests(unittest.TestCase):
    def test_empty_canonical_trades_against_non_empty_union_is_rejected(self):
        canonical = _Canonical()
        canonical.trade_floor = 0
        raw_union = {10: [{"record_sha256": "r", "observation_sha256": "o"}]}
        with self.assertRaises(ArbitrationVerificationError):
            _verify_trades(canonical, raw_union, bound_to_last=False)

    def test_genuinely_empty_trade_window_passes(self):
        canonical = _Canonical()
        canonical.trade_floor = 0
        _verify_trades(canonical, {}, bound_to_last=False)

    def test_incremental_empty_canonical_is_tolerated(self):
        canonical = _Canonical()
        canonical.trade_floor = 0
        _verify_trades(canonical, {10: [{"record_sha256": "r", "observation_sha256": "o"}]}, bound_to_last=True)

    def test_depth_final_omission_is_rejected(self):
        canonical = _Canonical()
        canonical.depth = [
            {"first_sequence": 101, "final_sequence": 103, "digest": "d101", "lane": "PRIMARY"},
            {"first_sequence": 104, "final_sequence": 107, "digest": "d104", "lane": "PRIMARY"},
        ]
        canonical.last_depth_event = "frame"
        raw = {
            "p": {103: [(101, "d101")], 107: [(104, "d104")], 110: [(108, "d108")]},
            "s": {},
        }
        with self.assertRaises(ArbitrationVerificationError) as caught:
            _verify_depth(canonical, raw, tolerant_lanes=False, enforce_final_boundary=True)
        self.assertIn("final omission", str(caught.exception))

    def test_depth_exact_trusted_boundary_passes(self):
        canonical = _Canonical()
        canonical.depth = [
            {"first_sequence": 101, "final_sequence": 103, "digest": "d101", "lane": "PRIMARY"},
            {"first_sequence": 104, "final_sequence": 107, "digest": "d104", "lane": "PRIMARY"},
            {"first_sequence": 108, "final_sequence": 110, "digest": "d108", "lane": "PRIMARY"},
        ]
        canonical.last_depth_event = "frame"
        raw = {
            "p": {103: [(101, "d101")], 107: [(104, "d104")], 110: [(108, "d108")]},
            "s": {},
        }
        _verify_depth(canonical, raw, tolerant_lanes=False, enforce_final_boundary=True)

    def test_depth_trailing_gap_is_rejected(self):
        canonical = _Canonical()
        canonical.depth = [
            {"first_sequence": 101, "final_sequence": 103, "digest": "d101", "lane": "PRIMARY"},
        ]
        canonical.last_depth_event = "gap"
        raw = {"p": {103: [(101, "d101")], 107: [(104, "d104")]}, "s": {}}
        with self.assertRaises(ArbitrationVerificationError) as caught:
            _verify_depth(canonical, raw, tolerant_lanes=False, enforce_final_boundary=True)
        self.assertIn("unresolved gap", str(caught.exception))

    def test_empty_canonical_depth_rules(self):
        canonical = _Canonical()
        with self.assertRaises(ArbitrationVerificationError) as caught:
            _verify_depth(
                canonical, {"p": {103: [(101, "d101")]}, "s": {}},
                tolerant_lanes=False, enforce_final_boundary=True,
            )
        self.assertIn("canonical depth stream is empty", str(caught.exception))
        _verify_depth(
            canonical, {"p": {}, "s": {}},
            tolerant_lanes=False, enforce_final_boundary=True,
        )


class SealedPrefixDepthPoolTests(unittest.TestCase):
    def test_several_sealed_generations_share_the_closed_audit_pool(self):
        root = Path(tempfile.mkdtemp(prefix="sealed-prefix-pool-"))
        artifact = _build_artifact(root)
        for generation in artifact.glob("*/*/generations/*"):
            (generation / "generation.json").write_text(
                '{"status":"COMPLETE","failure":null}', encoding="utf-8"
            )
        from binance_lob.live_arbitration_verify_cli import oracle_depth_by_lane

        closed = oracle_depth_by_lane(artifact, tolerate_missing_ack=False)
        entered: list[int] = []

        class _Pool:
            def __init__(self, size: int):
                entered.append(size)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def map(self, function, items):
                return [function(item) for item in items]

        class _Context:
            def Pool(self, size: int):
                return _Pool(size)

        with patch.object(os, "cpu_count", return_value=4), patch(
            "multiprocessing.get_context", return_value=_Context()
        ):
            prefix = oracle_depth_by_lane(artifact, tolerate_missing_ack=True)
        self.assertEqual(prefix, closed)
        self.assertGreaterEqual(len(entered), 1)


class SealedOracleCacheTests(unittest.TestCase):
    def test_a_second_read_does_not_reopen_sealed_trade_bytes(self):
        root = Path(tempfile.mkdtemp(prefix="sealed-oracle-cache-"))
        artifact = _build_artifact(root)
        for generation in artifact.glob("*/*/generations/*"):
            (generation / "generation.json").write_text(
                '{"status":"COMPLETE","failure":null}', encoding="utf-8"
            )
        cache = root / "cache"
        from binance_lob import live_arbitration_verify_cli as verifier

        first = verifier.oracle_trades_union(artifact, cache_dir=cache)
        calls: list[str] = []
        real = verifier._stream_records

        def counting(generation, stream, tolerate_missing_ack=False):
            calls.append(stream)
            return real(generation, stream, tolerate_missing_ack)

        with patch.object(verifier, "_stream_records", counting):
            second = verifier.oracle_trades_union(artifact, cache_dir=cache)
        self.assertEqual(first, second)
        self.assertEqual(calls, [])

        cache_file = next((cache / "trade").glob("*.json"))
        stored = json.loads(cache_file.read_text(encoding="utf-8"))
        self.assertEqual(stored["key"], cache_file.stem)
        stored["key"] = "0" * 64
        stored["rows"][0]["trade_id"] = 1
        cache_file.write_text(json.dumps(stored), encoding="utf-8")
        with patch.object(verifier, "_stream_records", counting):
            repaired = verifier.oracle_trades_union(artifact, cache_dir=cache)
        self.assertEqual(repaired, first)
        self.assertTrue(calls)
        calls.clear()

        trade_file = next(artifact.glob("*/*/generations/*/trade/segment-*.bnraw"))
        payload = bytearray(trade_file.read_bytes())
        payload[-1] ^= 0x01
        trade_file.write_bytes(payload)
        with patch.object(verifier, "_stream_records", counting):
            try:
                verifier.oracle_trades_union(artifact, cache_dir=cache)
            except Exception:
                calls.append("recomputed")
        self.assertTrue(calls)


class ClosedOracleEndToEndTests(unittest.TestCase):
    """Full raw -> journal -> closed oracle in Python (the same fixture tree
    is reused by the Rust CLI in the bilingual gate runner)."""

    def _materialized(self, root: Path):
        # Reuse the verifier's own materialization for the expected digests.
        from binance_lob.live_arbitration_verify_cli import (
            oracle_depth_by_lane,
            oracle_trades_union,
        )
        artifact = _build_artifact(root)
        union = oracle_trades_union(artifact)
        depth = oracle_depth_by_lane(artifact)
        return artifact, union, depth

    def _journal_payloads(self, union, depth, *, trades=None, depth_count=None, trailing_gap=False):
        if trades is None:
            trades = sorted(union)
        trade_payloads = []
        for trade_id in trades:
            evidence = union[trade_id]
            trade_payloads.append(
                {
                    "event": "TRADE_OBSERVATION",
                    "trade_id": trade_id,
                    "lane": "PRIMARY",
                    "record_sha256": evidence[0]["record_sha256"],
                    "observation_sha256": evidence[0]["observation_sha256"],
                }
            )
        depth_payloads = []
        frames = sorted(
            (
                (first, final_, digest)
                for final_, variants in depth["p"].items()
                for first, digest in variants
            ),
            key=lambda item: item[1],
        )
        for index, (first, final_, digest) in enumerate(frames):
            if depth_count is not None and index >= depth_count:
                break
            depth_payloads.append(
                {
                    "event": "DEPTH_OBSERVATION",
                    "first_sequence": first,
                    "final_sequence": final_,
                    "lane": "PRIMARY",
                    "record_sha256": "c" * 64,
                    "observation_sha256": digest,
                }
            )
        payloads = [
            {
                "event": "ARBITRATION_STARTED",
                "symbol": "BTCUSDT",
                "spec_revision": SPEC_REVISION,
                "trade_floor": 0,
                "artifact_root": "artifact",
            },
            *trade_payloads,
            *depth_payloads,
        ]
        if trailing_gap and depth_payloads:
            payloads.append(
                {
                    "event": "GAP",
                    "canonical_last_sequence": depth_payloads[-1]["final_sequence"],
                }
            )
        payloads.append(
            {
                "event": "ARBITRATION_TERMINAL",
                "status": "COMPLETE",
                "trades": len(trade_payloads),
                "depth_frames": len(depth_payloads),
                "gaps": 1 if trailing_gap else 0,
                "late_corrections": 0,
            }
        )
        return payloads

    def _verify(self, directory: Path, artifact: Path, payloads: list[dict]):
        journal = _write_journal(directory, payloads)
        _verify_with_oracle(
            [journal], artifact, None,
            tolerant_lanes=False, bound_to_last=False, enforce_final_boundary=True,
        )

    def test_full_window_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact, union, depth = self._materialized(root)
            self._verify(root / "j", artifact, self._journal_payloads(union, depth))

    def test_final_trade_omission_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact, union, depth = self._materialized(root)
            with self.assertRaises(ArbitrationVerificationError):
                self._verify(
                    root / "j", artifact,
                    self._journal_payloads(union, depth, trades=sorted(union)[:-1]),
                )

    def test_initial_trade_omission_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact, union, depth = self._materialized(root)
            with self.assertRaises(ArbitrationVerificationError):
                self._verify(
                    root / "j", artifact,
                    self._journal_payloads(union, depth, trades=sorted(union)[1:]),
                )

    def test_empty_canonical_against_non_empty_raw_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact, union, depth = self._materialized(root)
            payloads = [
                {
                    "event": "ARBITRATION_STARTED",
                    "symbol": "BTCUSDT",
                    "spec_revision": SPEC_REVISION,
                    "trade_floor": 0,
                    "artifact_root": "artifact",
                },
                {
                    "event": "ARBITRATION_TERMINAL",
                    "status": "COMPLETE",
                    "trades": 0, "depth_frames": 0, "gaps": 0, "late_corrections": 0,
                },
            ]
            with self.assertRaises(ArbitrationVerificationError):
                self._verify(root / "j", artifact, payloads)

    def test_final_depth_omission_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact, union, depth = self._materialized(root)
            frames = sorted(
                (final_, variants)
                for final_, variants in depth["p"].items()
            )
            count = len(frames) - 1
            with self.assertRaises(ArbitrationVerificationError) as caught:
                self._verify(
                    root / "j", artifact,
                    self._journal_payloads(union, depth, depth_count=count),
                )
            self.assertIn("final omission", str(caught.exception))

    def test_trailing_gap_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact, union, depth = self._materialized(root)
            with self.assertRaises(ArbitrationVerificationError) as caught:
                self._verify(
                    root / "j", artifact,
                    self._journal_payloads(union, depth, trailing_gap=True),
                )
            self.assertIn("unresolved gap", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
