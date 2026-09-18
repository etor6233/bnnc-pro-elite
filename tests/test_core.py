from __future__ import annotations

from dataclasses import replace
import unittest

from binance_lob import (
    BookState,
    ClockQuality,
    FixedDecimal,
    IllegalTransition,
    PublicMarketDataSpec,
    RawFrameV1,
    sample_clock,
    transition,
)


class FixedDecimalTests(unittest.TestCase):
    def test_round_trip_preserves_declared_scale(self) -> None:
        value = FixedDecimal.parse("60000.10000000")
        self.assertEqual(value.coefficient, 6000010000000)
        self.assertEqual(value.scale, 8)
        self.assertEqual(str(value), "60000.10000000")

    def test_rejects_float_exponent_and_precision_loss(self) -> None:
        with self.assertRaises(TypeError):
            FixedDecimal.parse(0.1)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            FixedDecimal.parse("1e-8")
        with self.assertRaises(ValueError):
            FixedDecimal.parse("1.001").rescale_exact(2)


class SpecTests(unittest.TestCase):
    def test_scope_and_public_uris_are_fail_closed(self) -> None:
        spec = PublicMarketDataSpec()
        self.assertEqual(
            spec.websocket_uri("BTCUSDT", "depth"),
            "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms?timeUnit=MICROSECOND",
        )
        self.assertIn("symbol=ETHUSDT&limit=5000", spec.snapshot_uri("ethusdt"))
        with self.assertRaises(ValueError):
            spec.websocket_uri("BNBUSDT", "depth")
        with self.assertRaises(ValueError):
            spec.websocket_uri("BTCUSDT", "kline")


class ClockAndRawTests(unittest.TestCase):
    def test_unknown_clock_cannot_support_one_way_claim(self) -> None:
        clock = sample_clock()
        self.assertEqual(clock.quality, ClockQuality.UNKNOWN)
        self.assertFalse(clock.permits_one_way_claim)

    def test_raw_frame_detects_payload_tampering(self) -> None:
        frame = RawFrameV1.capture(
            endpoint="wss://data-stream.binance.vision:443",
            stream="btcusdt@trade",
            symbol="BTCUSDT",
            connection_epoch="test-epoch-1",
            frame_index=0,
            clock=sample_clock(quality=ClockQuality.UNSYNCHRONIZED, source="test"),
            payload=b'{"e":"trade"}',
        )
        self.assertEqual(len(frame.payload_sha256), 64)
        with self.assertRaises(ValueError):
            replace(frame, payload=b"tampered")


class StateMachineTests(unittest.TestCase):
    def test_gap_requires_resync_before_live(self) -> None:
        self.assertEqual(transition(BookState.LIVE, BookState.GAP), BookState.GAP)
        with self.assertRaises(IllegalTransition):
            transition(BookState.GAP, BookState.LIVE)
        self.assertEqual(transition(BookState.GAP, BookState.RESYNCING), BookState.RESYNCING)
        self.assertEqual(transition(BookState.RESYNCING, BookState.LIVE), BookState.LIVE)

    def test_stopped_is_terminal(self) -> None:
        with self.assertRaises(IllegalTransition):
            transition(BookState.STOPPED, BookState.SYNCING)


if __name__ == "__main__":
    unittest.main()

