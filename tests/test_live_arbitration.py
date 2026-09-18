import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from binance_lob.live_arbitration_verify_cli import (
    ZERO_DIGEST,
    ArbitrationVerificationError,
    audit_journal,
    verify_trade_identity,
)


def _digest(body: dict) -> str:
    encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_journal(directory: Path, payloads: list[dict]) -> Path:
    path = directory / "canonical-live.jsonl"
    previous = ZERO_DIGEST
    with path.open("w", encoding="utf-8") as handle:
        for index, payload in enumerate(payloads):
            body = {
                "schema": "LiveArbitrationJournalRecordV1",
                "record_index": index,
                "wall_ns": 1000 + index,
                "mono_ns": 500 + index,
                "channel": "LIVE",
                "payload": payload,
                "previous_record_sha256": previous,
            }
            record_sha256 = _digest(body)
            envelope = {"body": body, "record_sha256": record_sha256}
            handle.write(json.dumps(envelope, separators=(",", ":"), ensure_ascii=False) + "\n")
            previous = record_sha256
    return path


def _started(symbol: str = "BTCUSDT") -> dict:
    return {"event": "ARBITRATION_STARTED", "symbol": symbol, "spec_revision": "rev"}


def _terminal(trades: int = 0, depth_frames: int = 0, gaps: int = 0,
              late_corrections: int = 0) -> dict:
    # ADR-17 B5: the terminal declares the late-correction counter too; the
    # audit demands exact equality with the recalculated one.
    return {
        "event": "ARBITRATION_TERMINAL",
        "status": "COMPLETE",
        "trades": trades,
        "depth_frames": depth_frames,
        "gaps": gaps,
        "late_corrections": late_corrections,
    }


def _trade(trade_id: int) -> dict:
    return {
        "event": "TRADE_OBSERVATION",
        "trade_id": trade_id,
        "lane": "PRIMARY",
        "record_sha256": "a" * 64,
        "observation_sha256": "b" * 64,
    }


def _correction(trade_id: int, kind: str = "duplicate",
                observation_sha256: str = "b" * 64) -> dict:
    # ADR-17 B5: corrections carry their raw lineage digests; the audit
    # validates them against the retained published identity.
    return {
        "event": "TRADE_LATE_CORRECTION",
        "trade_id": trade_id,
        "kind": kind,
        "lane": "SHADOW",
        "record_sha256": "e" * 64,
        "observation_sha256": observation_sha256,
    }


def _depth(first: int, final: int) -> dict:
    return {
        "event": "DEPTH_OBSERVATION",
        "first_sequence": first,
        "final_sequence": final,
        "lane": "PRIMARY",
        "record_sha256": "c" * 64,
        "observation_sha256": "d" * 64,
    }


class LiveArbitrationJournalAuditTests(unittest.TestCase):
    def test_valid_journal_passes_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [
                    _started(),
                    _trade(10),
                    _trade(11),
                    _depth(5001, 5010),
                    _depth(5011, 5015),
                    _terminal(trades=2, depth_frames=2),
                ],
            )
            audit = audit_journal(path)
            self.assertEqual(audit["trades"], 2)
            self.assertEqual(audit["depth_frames"], 2)
            self.assertEqual(audit["observations"], 4)
            self.assertEqual(audit["gaps"], 0)
            self.assertEqual(audit["last_trade_id"], 11)
            self.assertEqual(audit["last_depth_sequence"], 5015)

    def test_duplicate_trade_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory), [_started(), _trade(10), _trade(10), _terminal()]
            )
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_depth_regression_outside_gap_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [_started(), _depth(5001, 5010), _depth(5005, 5012), _terminal()],
            )
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_depth_jump_is_legal_only_across_a_typed_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [
                    _started(),
                    _depth(5001, 5010),
                    {"event": "GAP", "canonical_last_sequence": 5010},
                    _depth(5050, 5060),
                    _terminal(depth_frames=2, gaps=1),
                ],
            )
            audit = audit_journal(path)
            self.assertEqual(audit["gaps"], 1)
            self.assertEqual(audit["last_depth_sequence"], 5060)
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [_started(), _depth(5001, 5010), _depth(5050, 5060), _terminal(depth_frames=2)],
            )
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_tampered_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(Path(directory), [_started(), _terminal()])
            lines = path.read_text(encoding="utf-8").splitlines()
            envelope = json.loads(lines[1])
            envelope["body"]["payload"] = {"event": "ARBITRATION_TERMINAL", "status": "TAMPERED"}
            lines[1] = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_missing_terminal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(Path(directory), [_started(), _trade(10)])
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_unknown_event_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(Path(directory), [_started(), {"event": "INVENTED"}, _terminal()])
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_trade_identity_demands_exact_equality_against_external_oracle(self):
        # ADR-17 B5: the expected interval is derived from external evidence;
        # the canonical stream must equal it exactly (no trimming to the
        # canonical extremes, so initial/final omissions are visible).
        verify_trade_identity([10, 11, 12], [10, 11, 12])
        with self.assertRaises(ArbitrationVerificationError):
            verify_trade_identity([10, 11, 12], [8, 9, 10, 11, 12, 13])
        with self.assertRaises(ArbitrationVerificationError):
            verify_trade_identity([10, 11, 12], [10, 12])
        with self.assertRaises(ArbitrationVerificationError):
            verify_trade_identity([10, 11, 12], [10, 12, 11])
        with self.assertRaises(ArbitrationVerificationError):
            verify_trade_identity([], [1, 2, 3])

    def test_terminal_without_started_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(Path(directory), [_terminal()])
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_records_after_terminal_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [_started(), _terminal(), _trade(10)],
            )
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_terminal_counter_forgery_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [_started(), _trade(10), _terminal(trades=999)],
            )
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_late_correction_counter_forgery_is_rejected(self):
        # ADR-17 B5: the terminal declares 999 corrections but the audit
        # recalculated exactly 1.
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [_started(), _trade(10), _correction(10), _terminal(trades=1, late_corrections=999)],
            )
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_correction_kind_forgery_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [_started(), _trade(10), _correction(10, kind="NONEXISTENT_KIND"),
                 _terminal(trades=1, late_corrections=1)],
            )
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_correction_contradicting_the_published_identity_is_rejected(self):
        # kind=duplicate whose digest differs from the published one.
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [_started(), _trade(10), _correction(10, observation_sha256="f" * 64),
                 _terminal(trades=1, late_corrections=1)],
            )
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)
        # kind=unknown for a trade the journal published.
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [_started(), _trade(10), _correction(10, kind="unknown", observation_sha256="f" * 64),
                 _terminal(trades=1, late_corrections=1)],
            )
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_repeated_identical_corrections_and_genuine_unknown_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [
                    _started(),
                    _trade(10),
                    _correction(10),
                    _correction(10),
                    # 9 was never published: unknown is the honest claim.
                    _correction(9, kind="unknown", observation_sha256="c" * 64),
                    _terminal(trades=1, late_corrections=3),
                ],
            )
            audit = audit_journal(path)
            self.assertEqual(audit["late_corrections"], 3)

    def test_false_gap_boundary_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [
                    _started(),
                    _depth(10, 10),
                    {"event": "GAP", "canonical_last_sequence": 999999},
                    _depth(12, 12),
                    _terminal(depth_frames=2, gaps=1),
                ],
            )
            with self.assertRaises(ArbitrationVerificationError):
                audit_journal(path)

    def test_incremental_audit_accepts_a_live_prefix_without_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(Path(directory), [_started(), _trade(10)])
            audit = audit_journal(path, incremental=True)
            self.assertEqual(audit["trades"], 1)
            self.assertFalse(audit["terminal_seen"])

    def test_late_correction_and_lag_records_are_typed_not_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = _write_journal(
                Path(directory),
                [
                    _started(),
                    _trade(10),
                    _trade(11),
                    _correction(10),
                    {"event": "TRADE_LAG", "buffered": 1, "excluded_lane": "SHADOW"},
                    _terminal(trades=2, late_corrections=1),
                ],
            )
            audit = audit_journal(path)
            self.assertEqual(audit["late_corrections"], 1)
            self.assertEqual(audit["status_records"], 1)


if __name__ == "__main__":
    unittest.main()
