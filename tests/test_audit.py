from __future__ import annotations

from dataclasses import dataclass
import unittest

from binance_lob.audit import _trade_identity


@dataclass
class Frame:
    symbol: str
    payload: bytes


def trade(trade_id: int) -> Frame:
    return Frame(
        symbol="BTCUSDT",
        payload=(
            '{"e":"trade","s":"BTCUSDT","t":%d,"q":"1","m":false}'
            % trade_id
        ).encode(),
    )


class DatasetAuditTests(unittest.TestCase):
    def test_trade_identity_reports_jumps_without_claiming_loss(self) -> None:
        result = _trade_identity(
            [trade(10), trade(12), trade(12), trade(11)], "BTCUSDT"
        )
        self.assertEqual(result["id_jumps_without_loss_claim"], 1)
        self.assertEqual(result["duplicate_trade_ids"], 1)
        self.assertEqual(result["out_of_order_trade_ids"], 1)
        self.assertEqual(result["official_id_contiguity_claim"], "NONE")


if __name__ == "__main__":
    unittest.main()
