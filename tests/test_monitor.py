from __future__ import annotations

import unittest

from binance_lob.fixed_decimal import FixedDecimal
from binance_lob.monitor import _imbalance_ppm, _ratio_ppm


class MonitorMathTests(unittest.TestCase):
    def test_signed_imbalance_truncates_toward_zero(self) -> None:
        self.assertEqual(
            _imbalance_ppm(FixedDecimal.parse("3"), FixedDecimal.parse("1")), 500_000
        )
        self.assertEqual(
            _imbalance_ppm(FixedDecimal.parse("1"), FixedDecimal.parse("3")), -500_000
        )

    def test_ratio_aligns_decimal_scales_exactly(self) -> None:
        self.assertEqual(
            _ratio_ppm(FixedDecimal.parse("0.1"), FixedDecimal.parse("0.3")), 333_333
        )

    def test_decimal_sum_and_subtraction_are_canonical(self) -> None:
        left = FixedDecimal.parse("1.20")
        right = FixedDecimal.parse("0.2")
        self.assertEqual(str(left.add(right)), "1.4")
        self.assertEqual(str(left.subtract(right)), "1")


if __name__ == "__main__":
    unittest.main()
