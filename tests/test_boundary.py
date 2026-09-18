from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from binance_lob import (
    BoundaryDurabilityV1,
    BoundaryJournalError,
    BoundaryJournalWriter,
    CanonicalObservationV1,
    HandoverBoundaryV1,
    RawPositionV1,
    scan_boundary_journal,
    select_canonical,
)


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def position(epoch: str, index: int, digest: str) -> RawPositionV1:
    return RawPositionV1(epoch, "btcusdt@depth@100ms", index, digest)


def boundary() -> HandoverBoundaryV1:
    return HandoverBoundaryV1(
        schema="HandoverBoundaryV1",
        boundary_id="btc-depth-a-b-100",
        environment="production-public-market-data",
        symbol="BTCUSDT",
        stream_kind="DEPTH",
        stream="btcusdt@depth@100ms",
        predecessor_epoch="epoch-a",
        successor_epoch="epoch-b",
        boundary_sequence=100,
        boundary_sha256=DIGEST_A,
        predecessor_last_selected=position("epoch-a", 10, DIGEST_A),
        successor_boundary_observation=position("epoch-b", 7, DIGEST_A),
        successor_first_selected=position("epoch-b", 8, DIGEST_B),
        predecessor_durability=BoundaryDurabilityV1(10, 4_000, DIGEST_A),
        successor_durability=BoundaryDurabilityV1(8, 3_000, DIGEST_B),
        spec_revision="976cc580553890e92031b77306147c0ed1de5a46",
        selector_version="CanonicalMarketDataViewV1",
    )


def observation(
    epoch: str,
    frame_index: int,
    first_sequence: int,
    final_sequence: int,
    record_digest: str,
    observation_digest: str,
    *,
    kind: str = "DEPTH",
    stream: str = "btcusdt@depth@100ms",
) -> CanonicalObservationV1:
    return CanonicalObservationV1(
        "BTCUSDT",
        kind,
        stream,
        epoch,
        frame_index,
        first_sequence,
        final_sequence,
        record_digest,
        observation_digest,
    )


def trade_boundary() -> HandoverBoundaryV1:
    value = boundary()
    return replace(
        value,
        boundary_id="btc-trade-a-b-200",
        stream_kind="TRADE",
        stream="btcusdt@trade",
        boundary_sequence=200,
        predecessor_last_selected=RawPositionV1("epoch-a", "btcusdt@trade", 10, DIGEST_A),
        successor_boundary_observation=RawPositionV1(
            "epoch-b", "btcusdt@trade", 7, DIGEST_A
        ),
        successor_first_selected=RawPositionV1("epoch-b", "btcusdt@trade", 8, DIGEST_B),
    )


class BoundaryJournalTests(unittest.TestCase):
    def test_proposal_is_not_canonical_until_durable_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boundary.bnhandover"
            writer = BoundaryJournalWriter(path)
            proposal = writer.propose(boundary())
            self.assertEqual(proposal.durable_record_count, 1)
            self.assertIsNone(scan_boundary_journal(path).committed)
            commit = writer.commit("btc-depth-a-b-100")
            writer.close()
            self.assertEqual(commit.durable_record_count, 2)
            scan = scan_boundary_journal(path)
            self.assertTrue(scan.clean_eof)
            self.assertEqual(scan.committed, boundary())

    def test_partial_commit_keeps_only_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boundary.bnhandover"
            writer = BoundaryJournalWriter(path)
            writer.propose(boundary())
            writer.commit("btc-depth-a-b-100")
            writer.close()
            with path.open("r+b") as handle:
                handle.truncate(path.stat().st_size - 7)
            scan = scan_boundary_journal(path)
            self.assertFalse(scan.clean_eof)
            self.assertEqual(scan.records, 1)
            self.assertIsNotNone(scan.proposal)
            self.assertIsNone(scan.committed)
            self.assertEqual(scan.reason, "partial boundary record digest")

    def test_boundary_beyond_durable_watermark_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = boundary()
            invalid = HandoverBoundaryV1(
                **{
                    **{field: getattr(value, field) for field in value.__dataclass_fields__},
                    "successor_durability": BoundaryDurabilityV1(7, 3_000, DIGEST_B),
                }
            )
            writer = BoundaryJournalWriter(Path(directory) / "boundary.bnhandover")
            with self.assertRaisesRegex(BoundaryJournalError, "durable watermark"):
                writer.propose(invalid)
            writer.close()

    def test_failed_commit_fsync_poisoning_emits_no_ack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = BoundaryJournalWriter(Path(directory) / "boundary.bnhandover")
            writer.propose(boundary())
            with mock.patch("binance_lob.boundary.os.fsync", side_effect=OSError("injected")):
                with self.assertRaisesRegex(BoundaryJournalError, "journal poisoned"):
                    writer.commit("btc-depth-a-b-100")
            self.assertTrue(writer.is_poisoned)
            writer.close()

    def test_canonical_depth_splice_selects_each_side_once(self) -> None:
        predecessor = [
            observation("epoch-a", 8, 98, 98, DIGEST_B, DIGEST_B),
            observation("epoch-a", 9, 99, 99, DIGEST_B, DIGEST_B),
            observation("epoch-a", 10, 100, 100, DIGEST_A, DIGEST_A),
            observation("epoch-a", 11, 101, 101, DIGEST_B, DIGEST_B),
        ]
        successor = [
            observation("epoch-b", 6, 99, 99, DIGEST_B, DIGEST_B),
            observation("epoch-b", 7, 100, 100, DIGEST_A, DIGEST_A),
            observation("epoch-b", 8, 101, 101, DIGEST_B, DIGEST_B),
            observation("epoch-b", 9, 102, 102, DIGEST_A, DIGEST_A),
        ]
        selection = select_canonical(boundary(), predecessor, successor)
        self.assertEqual(len(selection.selected), 5)
        self.assertEqual(selection.excluded_overlap_records, 3)
        self.assertEqual(selection.first_sequence, 98)
        self.assertEqual(selection.final_sequence, 102)
        self.assertEqual(
            selection.selection_sha256,
            "61de54e63913d9d2317beb1434954807d6ba7311c6ee2f7fe72c588be6a3ec76",
        )

    def test_canonical_depth_rejects_gap_and_divergence(self) -> None:
        predecessor = [
            observation("epoch-a", 9, 99, 99, DIGEST_B, DIGEST_B),
            observation("epoch-a", 10, 100, 100, DIGEST_A, DIGEST_A),
        ]
        successor = [
            observation("epoch-b", 7, 100, 100, DIGEST_A, DIGEST_A),
            observation("epoch-b", 8, 102, 102, DIGEST_B, DIGEST_B),
        ]
        with self.assertRaisesRegex(BoundaryJournalError, "bridge K\\+1"):
            select_canonical(boundary(), predecessor, successor)
        successor[0] = observation("epoch-b", 7, 100, 100, DIGEST_A, DIGEST_B)
        successor[1] = observation("epoch-b", 8, 101, 101, DIGEST_B, DIGEST_B)
        with self.assertRaisesRegex(BoundaryJournalError, "convergence"):
            select_canonical(boundary(), predecessor, successor)

    def test_canonical_trade_splice_uses_t_then_t_plus_one(self) -> None:
        predecessor = [
            observation(
                "epoch-a", 9, 199, 199, DIGEST_B, DIGEST_B,
                kind="TRADE", stream="btcusdt@trade"
            ),
            observation(
                "epoch-a", 10, 200, 200, DIGEST_A, DIGEST_A,
                kind="TRADE", stream="btcusdt@trade"
            ),
            observation(
                "epoch-a", 11, 201, 201, DIGEST_B, DIGEST_B,
                kind="TRADE", stream="btcusdt@trade"
            ),
        ]
        successor = [
            observation(
                "epoch-b", 6, 199, 199, DIGEST_B, DIGEST_B,
                kind="TRADE", stream="btcusdt@trade"
            ),
            observation(
                "epoch-b", 7, 200, 200, DIGEST_A, DIGEST_A,
                kind="TRADE", stream="btcusdt@trade"
            ),
            observation(
                "epoch-b", 8, 201, 201, DIGEST_B, DIGEST_B,
                kind="TRADE", stream="btcusdt@trade"
            ),
            observation(
                "epoch-b", 9, 202, 202, DIGEST_A, DIGEST_A,
                kind="TRADE", stream="btcusdt@trade"
            ),
        ]
        selection = select_canonical(trade_boundary(), predecessor, successor)
        self.assertEqual(len(selection.selected), 4)
        self.assertEqual(selection.excluded_overlap_records, 3)
        self.assertEqual(selection.first_sequence, 199)
        self.assertEqual(selection.final_sequence, 202)


if __name__ == "__main__":
    unittest.main()
