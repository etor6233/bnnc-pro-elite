from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import unittest

from binance_lob.book import ApplyOutcome, DepthGap, LocalOrderBook
from binance_lob.state import BookState


FIXTURES = Path(__file__).parents[1] / "fixtures"


def _legacy_state_digest(book: LocalOrderBook) -> str:
    """The pre-optimization serializer: the frozen contract.  The optimized
    streaming digest must remain byte-identical to this."""
    value = {
        "symbol": book.symbol,
        "last_update_id": book.last_update_id,
        "bids": [[str(p), str(book._bids[p])] for p in sorted(book._bids, reverse=True)],
        "asks": [[str(p), str(book._asks[p])] for p in sorted(book._asks)],
    }
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class BookTests(unittest.TestCase):
    def test_snapshot_bridge_update_and_delete(self) -> None:
        book = LocalOrderBook("BTCUSDT")
        snapshot = (FIXTURES / "depth_snapshot_btcusdt.json").read_bytes()
        update = (FIXTURES / "depth_update_btcusdt.json").read_bytes()
        self.assertEqual(book.load_snapshot(snapshot), 99)
        self.assertEqual(book.state, BookState.SYNCING)
        self.assertEqual(book.apply_depth(update), ApplyOutcome.APPLIED)
        self.assertEqual(book.state, BookState.LIVE)
        self.assertEqual(book.last_update_id, 102)
        self.assertEqual(str(book.best_bid), "60000.1")
        self.assertEqual(str(book.best_ask), "60000.2")
        self.assertEqual(book.bid_levels, 1)
        self.assertEqual(len(book.state_digest()), 64)

    def test_old_event_is_ignored_and_gap_is_fatal(self) -> None:
        book = LocalOrderBook("BTCUSDT")
        book.load_snapshot((FIXTURES / "depth_snapshot_btcusdt.json").read_bytes())
        old = {"e": "depthUpdate", "E": 1, "s": "BTCUSDT", "U": 90, "u": 99, "b": [], "a": []}
        self.assertEqual(book.apply_depth(json.dumps(old).encode()), ApplyOutcome.OLD)
        gap = {"e": "depthUpdate", "E": 2, "s": "BTCUSDT", "U": 101, "u": 101, "b": [], "a": []}
        with self.assertRaises(DepthGap):
            book.apply_depth(json.dumps(gap).encode())
        self.assertEqual(book.state, BookState.GAP)

    def test_digest_is_deterministic_across_decimal_formatting(self) -> None:
        first = LocalOrderBook("BTCUSDT")
        second = LocalOrderBook("BTCUSDT")
        first.load_snapshot(b'{"lastUpdateId":1,"bids":[["1.00","2.0"]],"asks":[["2.00","3.0"]]}')
        second.load_snapshot(b'{"lastUpdateId":1,"bids":[["1","2"]],"asks":[["2","3"]]}')
        self.assertEqual(first.state_digest(), second.state_digest())

    def test_state_digest_is_byte_identical_to_legacy_serializer(self) -> None:
        """Contract lock (2026-09-17 optimization): the streaming digest with
        incrementally sorted sides and memoized strings must produce EXACTLY
        the legacy bytes on randomized books, after randomized updates."""
        for seed in range(40):
            rng = random.Random(seed)
            bids = [
                [
                    f"{90000 - i * 10 + rng.randint(0, 5)}.{rng.randint(0, 99):02d}",
                    f"{1 + rng.randint(1, 99) / 100:.2f}",
                ]
                for i in range(2 + rng.randint(0, 60))
            ]
            asks = [
                [
                    f"{100000 + i * 10 + rng.randint(0, 5)}.{rng.randint(0, 99):02d}",
                    f"{1 + rng.randint(1, 99) / 100:.2f}",
                ]
                for i in range(2 + rng.randint(0, 60))
            ]
            book = LocalOrderBook("BTCUSDT")
            book.load_snapshot(json.dumps({"lastUpdateId": 1, "bids": bids, "asks": asks}).encode())
            self.assertEqual(book.state_digest(), _legacy_state_digest(book))
            for update_id in range(2, 302):
                book.apply_depth(
                    json.dumps(
                        {
                            "e": "depthUpdate",
                            "E": update_id,
                            "s": "BTCUSDT",
                            "U": update_id,
                            "u": update_id,
                            "b": [
                                [
                                    f"{90000 - rng.randint(0, 100) * 10}.{rng.randint(0, 99):02d}",
                                    "0" if rng.random() < 0.3 else f"{1 + rng.randint(1, 99) / 100:.2f}",
                                ]
                                for _ in range(rng.randint(0, 4))
                            ],
                            "a": [
                                [
                                    f"{100000 + rng.randint(0, 100) * 10}.{rng.randint(0, 99):02d}",
                                    "0" if rng.random() < 0.3 else f"{1 + rng.randint(1, 99) / 100:.2f}",
                                ]
                                for _ in range(rng.randint(0, 4))
                            ],
                        }
                    ).encode()
                )
                self.assertEqual(book.state_digest(), _legacy_state_digest(book))


if __name__ == "__main__":
    unittest.main()
