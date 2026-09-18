from __future__ import annotations

from pathlib import Path
import unittest

from binance_lob.snapshot import validate_snapshot_payload


class SnapshotTests(unittest.TestCase):
    def test_fixture_shape(self) -> None:
        fixture = Path(__file__).parents[1] / "fixtures" / "depth_snapshot_btcusdt.json"
        last_update_id, bids, asks = validate_snapshot_payload(fixture.read_bytes())
        self.assertEqual(last_update_id, 99)
        self.assertEqual((bids, asks), (2, 2))

    def test_rejects_malformed_levels(self) -> None:
        with self.assertRaises(ValueError):
            validate_snapshot_payload(b'{"lastUpdateId":1,"bids":[[1,2]],"asks":[]}')


if __name__ == "__main__":
    unittest.main()
