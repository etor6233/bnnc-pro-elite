from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from scripts.portfolio_demo import run_case, write_frames
from binance_lob.raw_log import iter_raw_frames


class PortfolioDemoTests(unittest.TestCase):
    def test_exact_payload_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trade.bnraw"
            payload = b'{ "t": 1, "p": "1.000" }\n'
            write_frames(path, "BTCUSDT", "trade", [payload])
            self.assertEqual(next(iter_raw_frames(path)).payload, payload)
            with self.assertRaises(FileExistsError):
                write_frames(path, "BTCUSDT", "trade", [payload])

    def test_negative_case_does_not_accept_rust_success(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("scripts.portfolio_demo.subprocess.run", return_value=
                       subprocess.CompletedProcess([], 0, "{}", "")):
                with self.assertRaisesRegex(RuntimeError, "both implementations must reject"):
                    run_case(Path("unused"), Path(directory), "BTCUSDT", "sequence_gap")

    def test_positive_case_does_not_accept_rust_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("scripts.portfolio_demo.subprocess.run", return_value=
                       subprocess.CompletedProcess([], 2, "", "injected failure")):
                with self.assertRaisesRegex(RuntimeError, "Rust replay failed"):
                    run_case(Path("unused"), Path(directory), "ETHUSDT", "valid")


if __name__ == "__main__":
    unittest.main()
