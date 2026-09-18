from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class MinimalRawVerifierCliTests(unittest.TestCase):
    def test_import_keeps_unrelated_modules_unloaded(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "src"
        probe = (
            "import json,sys; sys.path.insert(0,sys.argv[1]); "
            "import binance_lob.raw_verify_cli; "
            "prefix='binance_lob.'; "
            "loaded=sorted(name for name in sys.modules if name.startswith(prefix)); "
            "print(json.dumps(loaded))"
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-P",
                "-S",
                "-B",
                "-c",
                probe,
                str(source_root),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        loaded = json.loads(completed.stdout)
        for forbidden in (
            "binance_lob.capture",
            "binance_lob.observations",
            "binance_lob.boundary",
            "binance_lob.clock",
            "binance_lob.book",
        ):
            self.assertNotIn(forbidden, loaded)

    def test_help_exposes_only_campaign_and_required_output(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-B", "-m", "binance_lob.raw_verify_cli", "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("campaign", completed.stdout)
        self.assertIn("--output", completed.stdout)
        for forbidden in ("capture", "symbol", "order", "feature"):
            self.assertNotIn(forbidden, completed.stdout.lower())

    def test_rejects_output_inside_campaign_before_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign = Path(temporary) / "campaign"
            campaign.mkdir()
            output = campaign / "report.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "binance_lob.raw_verify_cli",
                    str(campaign),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertFalse(output.exists())
            failure = json.loads(completed.stderr)
            self.assertEqual(failure["status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
