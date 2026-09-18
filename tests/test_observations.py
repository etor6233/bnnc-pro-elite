from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from binance_lob import ClockQuality, RawFrameV1, RawLogWriter, sample_clock
from binance_lob.observations import (
    ObservationMaterializationError,
    materialize_depth_observations,
    materialize_trade_observations,
)
from binance_lob.raw_log import iter_raw_records


FIXTURES = Path(__file__).parents[1] / "fixtures"


def _frame(stream: str, epoch: str, index: int, payload: bytes) -> RawFrameV1:
    return RawFrameV1.capture(
        endpoint=f"wss://data-stream.binance.vision/ws/{stream}",
        stream=stream,
        symbol="BTCUSDT",
        connection_epoch=epoch,
        frame_index=index,
        clock=sample_clock(quality=ClockQuality.UNSYNCHRONIZED, source="test"),
        payload=payload,
    )


def _write(path: Path, frames: list[RawFrameV1]) -> None:
    with RawLogWriter(path, sync_every=1) as writer:
        for frame in frames:
            writer.append(frame)


class ObservationTests(unittest.TestCase):
    def test_depth_materialization_links_applied_state_to_raw_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_path = root / "snapshot.bnraw"
            depth_path = root / "depth.bnraw"
            _write(
                snapshot_path,
                [_frame("btcusdt@rest-depth-snapshot", "snapshot-1", 0,
                        (FIXTURES / "depth_snapshot_btcusdt.json").read_bytes())],
            )
            old = json.dumps({
                "e": "depthUpdate", "E": 1, "s": "BTCUSDT",
                "U": 90, "u": 99, "b": [], "a": [],
            }, separators=(",", ":")).encode()
            _write(
                depth_path,
                [
                    _frame("btcusdt@depth", "epoch-a", 0, old),
                    _frame("btcusdt@depth", "epoch-a", 1,
                           (FIXTURES / "depth_update_btcusdt.json").read_bytes()),
                ],
            )
            result = materialize_depth_observations(snapshot_path, depth_path)
            records = list(iter_raw_records(depth_path))
            self.assertEqual(result.skipped_initial_old_records, 1)
            self.assertEqual(len(result.observations), 1)
            self.assertEqual(result.observations[0].frame_index, 1)
            self.assertEqual(result.observations[0].first_sequence, 100)
            self.assertEqual(result.observations[0].final_sequence, 102)
            self.assertEqual(result.observations[0].record_sha256, records[1].record_sha256)
            self.assertEqual(len(result.observations[0].observation_sha256), 64)
            self.assertEqual(len(result.materialization_sha256), 64)

    def test_trade_materialization_is_contiguous_and_canonicalizes_decimals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trades.bnraw"
            base = {
                "e": "trade", "E": 10, "s": "BTCUSDT", "t": 7,
                "p": "60000.20000000", "q": "0.01000000", "T": 11,
                "m": False, "M": True,
            }
            second = dict(base, t=8, E=12, T=13, p="60000.2", q="0.01")
            _write(path, [
                _frame("btcusdt@trade", "epoch-t", 0, json.dumps(base).encode()),
                _frame("btcusdt@trade", "epoch-t", 1, json.dumps(second).encode()),
            ])
            result = materialize_trade_observations(path)
            self.assertEqual((result.first_sequence, result.final_sequence), (7, 8))
            self.assertEqual(len(result.observations), 2)
            self.assertNotEqual(
                result.observations[0].observation_sha256,
                result.observations[1].observation_sha256,
            )

    def test_trade_id_jump_is_preserved_without_a_loss_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trades.bnraw"
            def payload(trade_id: int) -> bytes:
                return json.dumps({
                    "e": "trade", "E": 10, "s": "BTCUSDT", "t": trade_id,
                    "p": "1", "q": "1", "T": 11, "m": False, "M": True,
                }).encode()
            _write(path, [
                _frame("btcusdt@trade", "epoch-t", 0, payload(7)),
                _frame("btcusdt@trade", "epoch-t", 1, payload(9)),
            ])
            result = materialize_trade_observations(path)
            self.assertEqual((result.first_sequence, result.final_sequence), (7, 9))

    def test_duplicate_or_regressing_trade_id_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trades.bnraw"

            def payload(trade_id: int) -> bytes:
                return json.dumps({
                    "e": "trade", "E": 10, "s": "BTCUSDT", "t": trade_id,
                    "p": "1", "q": "1", "T": 11, "m": False, "M": True,
                }).encode()

            _write(path, [
                _frame("btcusdt@trade", "epoch-t", 0, payload(7)),
                _frame("btcusdt@trade", "epoch-t", 1, payload(7)),
            ])
            with self.assertRaisesRegex(ObservationMaterializationError, "duplicated or regressed"):
                materialize_trade_observations(path)

    def test_trade_dispatch_time_is_raw_evidence_not_logical_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_path = root / "first.bnraw"
            second_path = root / "second.bnraw"
            event = {
                "e": "trade", "E": 100, "s": "BTCUSDT", "t": 7,
                "p": "60000.2", "q": "0.01", "T": 99,
                "m": False, "M": True,
            }
            _write(first_path, [
                _frame("btcusdt@trade", "epoch-a", 0, json.dumps(event).encode())
            ])
            event["E"] = 125
            _write(second_path, [
                _frame("btcusdt@trade", "epoch-b", 0, json.dumps(event).encode())
            ])
            first = materialize_trade_observations(first_path).observations[0]
            second = materialize_trade_observations(second_path).observations[0]
            self.assertNotEqual(first.record_sha256, second.record_sha256)
            self.assertEqual(first.observation_sha256, second.observation_sha256)


if __name__ == "__main__":
    unittest.main()
