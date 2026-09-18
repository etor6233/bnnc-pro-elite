from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from binance_lob import (
    ClockQuality,
    RawFrameV1,
    RawLogCorruption,
    RawLogWriter,
    recover_raw_log_prefix,
    sample_clock,
    scan_raw_log,
)
from binance_lob.raw_log import iter_raw_frames, iter_raw_records


class _PartialWriteFile:
    def __init__(self, wrapped: object, remaining: int) -> None:
        self._wrapped = wrapped
        self._remaining = remaining

    def write(self, data: bytes | memoryview) -> int:
        if self._remaining <= 0:
            raise OSError("injected partial write")
        selected = data[: self._remaining]
        written = self._wrapped.write(selected)  # type: ignore[attr-defined]
        self._remaining -= written
        return written

    def flush(self) -> None:
        self._wrapped.flush()  # type: ignore[attr-defined]

    def fileno(self) -> int:
        return self._wrapped.fileno()  # type: ignore[attr-defined]

    def close(self) -> None:
        self._wrapped.close()  # type: ignore[attr-defined]


def frame(index: int, payload: bytes = b'{"e":"depthUpdate"}') -> RawFrameV1:
    return RawFrameV1.capture(
        endpoint="wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms",
        stream="btcusdt@depth",
        symbol="BTCUSDT",
        connection_epoch="epoch-1",
        frame_index=index,
        clock=sample_clock(quality=ClockQuality.UNSYNCHRONIZED, source="test"),
        payload=payload,
    )


class RawLogTests(unittest.TestCase):
    def test_reader_accepts_production_windows_clock_quality_without_one_way_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.bnraw"
            production_clock = sample_clock(
                quality=ClockQuality.HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND,
                source="Windows-w32time:time.nist.gov",
            )
            production_frame = RawFrameV1.capture(
                endpoint="wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms",
                stream="btcusdt@depth",
                symbol="BTCUSDT",
                connection_epoch="epoch-production-clock",
                frame_index=0,
                clock=production_clock,
                payload=b'{"e":"depthUpdate"}',
            )
            with RawLogWriter(path, sync_every=1) as writer:
                writer.append(production_frame)

            [replayed] = list(iter_raw_frames(path))
            self.assertEqual(
                replayed.clock.quality,
                ClockQuality.HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND,
            )
            self.assertFalse(replayed.clock.permits_one_way_claim)

    def test_round_trip_and_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.bnraw"
            with RawLogWriter(path, sync_every=2) as writer:
                first = writer.append(frame(0))
                second = writer.append(frame(1, b'{"e":"depthUpdate","u":2}'))
            self.assertNotEqual(first.record_sha256, second.record_sha256)
            self.assertIsNone(first.durability_ack)
            self.assertIsNotNone(second.durability_ack)
            assert second.durability_ack is not None
            self.assertEqual(second.durability_ack.durable_record_count, 2)
            self.assertEqual(second.durability_ack.durable_through_offset, second.end_offset)
            scan = scan_raw_log(path)
            self.assertTrue(scan.clean_eof)
            self.assertEqual(scan.records, 2)
            self.assertEqual(scan.last_record_sha256, second.record_sha256)
            replayed = list(iter_raw_frames(path))
            self.assertEqual([item.frame_index for item in replayed], [0, 1])
            self.assertEqual(replayed[1].payload, b'{"e":"depthUpdate","u":2}')

    def test_partial_tail_is_explicit_and_valid_prefix_survives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.bnraw"
            with RawLogWriter(path, sync_every=1) as writer:
                writer.append(frame(0))
                writer.append(frame(1))
            data = path.read_bytes()
            path.write_bytes(data[:-7])
            scan = scan_raw_log(path)
            self.assertFalse(scan.clean_eof)
            self.assertEqual(scan.records, 1)
            self.assertEqual(scan.reason, "partial record digest")
            self.assertLess(scan.last_good_offset, scan.file_size)

            recovered = Path(directory) / "recovered.bnraw"
            original_damaged_size = path.stat().st_size
            report = recover_raw_log_prefix(path, recovered)
            self.assertEqual(path.stat().st_size, original_damaged_size)
            self.assertEqual(report.recovered_records, 1)
            self.assertGreater(report.excluded_tail_bytes, 0)
            self.assertTrue(scan_raw_log(recovered).clean_eof)
            self.assertEqual(len(list(iter_raw_frames(recovered))), 1)

    def test_iterator_revalidates_if_file_changes_after_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.bnraw"
            with RawLogWriter(path, sync_every=1) as writer:
                writer.append(frame(0))
            accepted_scan = scan_raw_log(path)
            data = path.read_bytes()
            marker = b"binance-spot"
            self.assertIn(marker, data)
            path.write_bytes(data.replace(marker, b"Binance-spot", 1))
            with mock.patch("binance_lob.raw_log.scan_raw_log", return_value=accepted_scan):
                with self.assertRaisesRegex(RawLogCorruption, "changed during replay"):
                    list(iter_raw_records(path))

    def test_discontinuous_index_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.bnraw"
            with RawLogWriter(path) as writer:
                writer.append(frame(0))
                with self.assertRaises(ValueError):
                    writer.append(frame(2))

    def test_payload_digest_tamper_is_rejected_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.bnraw"
            with RawLogWriter(path) as writer:
                with self.assertRaises(ValueError):
                    writer.append(replace(frame(0), payload=b"tampered"))

    def test_partial_write_poisoning_prevents_false_ack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = RawLogWriter(Path(directory) / "capture.bnraw", sync_every=1)
            writer._file = _PartialWriteFile(writer._file, remaining=20)  # type: ignore[assignment]
            with self.assertRaisesRegex(RawLogCorruption, "writer poisoned"):
                writer.append(frame(0))
            self.assertTrue(writer.is_poisoned)
            self.assertIsNone(writer.last_durability_ack)
            with self.assertRaisesRegex(RawLogCorruption, "poisoned"):
                writer.append(frame(0))
            writer.close()

    def test_fsync_failure_poisoning_prevents_false_ack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = RawLogWriter(Path(directory) / "capture.bnraw", sync_every=1)
            with mock.patch("binance_lob.raw_log.os.fsync", side_effect=OSError("injected")):
                with self.assertRaisesRegex(RawLogCorruption, "sync raw log; writer poisoned"):
                    writer.append(frame(0))
            self.assertTrue(writer.is_poisoned)
            self.assertIsNone(writer.last_durability_ack)
            writer.close()


if __name__ == "__main__":
    unittest.main()
