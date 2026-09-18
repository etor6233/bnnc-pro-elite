from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from binance_lob.raw_campaign import verify_raw_campaign
from tools.market_replay_oracle.complete_replay import (
    COMPLETE_REPLAY_USAGE,
    replay_complete_run,
)
from tools.market_replay_oracle.market_replay import MarketReplayCorruption
from test_raw_campaign import _build_campaign, _pretty


class CompleteReplayTests(unittest.TestCase):
    def _fixture(self, parent: Path) -> tuple[Path, dict[str, object]]:
        run = parent / "fixture-complete-run"
        run.mkdir()
        campaign = _build_campaign(run)
        python_report = verify_raw_campaign(campaign)
        campaign_manifest_sha = sha256((campaign / "campaign.json").read_bytes()).hexdigest()
        rust_verification_sha = "a" * 64
        rust_report = {
            "schema": "VerifiedRawCampaignV1",
            "status": "PASS",
            "campaign_id": campaign.name,
            "symbol": "BTCUSDT",
            "campaign_manifest_sha256": campaign_manifest_sha,
            "verification_sha256": rust_verification_sha,
        }
        verification = run / "independent-verification"
        verification.mkdir()
        rust_bytes = _pretty(rust_report)
        python_bytes = _pretty(python_report)
        (verification / "btcusdt-rust-report.json").write_bytes(rust_bytes)
        (verification / "btcusdt-python-report.json").write_bytes(python_bytes)
        bindings = {
            "schema": "RawQualificationCampaignBindingsV1",
            "run_id": run.name,
            "campaigns": [
                {
                    "symbol": "BTCUSDT",
                    "campaign_id": campaign.name,
                    "campaign_directory": str(campaign.resolve()),
                }
            ],
        }
        bindings_bytes = _pretty(bindings)
        (run / "campaign-bindings.json").write_bytes(bindings_bytes)
        selected = {
            "symbol": "BTCUSDT",
            "exit_code": 0,
            "child_stderr_events": 0,
            "stderr_file_bytes": 0,
            "campaign_id": campaign.name,
            "campaign_directory": str(campaign.resolve()),
            "campaign_manifest_sha256": campaign_manifest_sha,
            "rust_verification_sha256": rust_verification_sha,
            "python_verification_sha256": python_report["verification_sha256"],
            "independent_verifiers": [
                {
                    "name": "btcusdt-rust",
                    "exit_code": 0,
                    "stderr_bytes": 0,
                    "report_file": "btcusdt-rust-report.json",
                    "report_bytes": len(rust_bytes),
                    "report_sha256": sha256(rust_bytes).hexdigest(),
                },
                {
                    "name": "btcusdt-python",
                    "exit_code": 0,
                    "stderr_bytes": 0,
                    "report_file": "btcusdt-python-report.json",
                    "report_bytes": len(python_bytes),
                    "report_sha256": sha256(python_bytes).hexdigest(),
                },
            ],
        }
        terminal = {
            "schema": "RawQualificationLauncherTerminalV2",
            "status": "COMPLETE",
            "run_id": run.name,
            "mode": "Test",
            "run_root": str(run.resolve()),
            "campaign_bindings_sha256": sha256(bindings_bytes).hexdigest(),
            "campaigns": [selected, {"symbol": "ETHUSDT"}],
            "credentials": "NONE",
            "order_entry": "ABSENT",
        }
        (run / "launcher-terminal.json").write_bytes(_pretty(terminal))
        selection: dict[str, object] = {
            "schema": "CompleteRunReplaySelectionV1",
            "usage": COMPLETE_REPLAY_USAGE,
            "run_directory": str(run),
            "symbol": "BTCUSDT",
        }
        return run, selection

    def test_complete_replay_is_deterministic_neutral_and_splices_once(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            _run, selection = self._fixture(Path(raw_temp))
            first = replay_complete_run(selection)
            repeated = replay_complete_run(selection)
            self.assertEqual(first, repeated)
            self.assertFalse(first["qualification_claim"])
            self.assertFalse(first["cross_stream_total_order_available"])
            self.assertEqual(first["economic_features"], [])
            self.assertEqual(first["source"]["generations"], 2)  # type: ignore[index]
            self.assertEqual(first["source"]["handovers"], 1)  # type: ignore[index]
            self.assertGreater(first["depth"]["overlap_records_excluded"], 0)  # type: ignore[index]
            self.assertGreater(first["trades"]["overlap_records_excluded"], 0)  # type: ignore[index]
            self.assertTrue(first["trades"]["trade_ids_strictly_increasing"])  # type: ignore[index]

    def test_complete_replay_refuses_noncomplete_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            run, selection = self._fixture(Path(raw_temp))
            terminal_path = run / "launcher-terminal.json"
            terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
            terminal["status"] = "FAILED"
            terminal_path.write_bytes(_pretty(terminal))
            with self.assertRaisesRegex(
                MarketReplayCorruption, "not an exact COMPLETE qualification run"
            ):
                replay_complete_run(selection)


if __name__ == "__main__":
    unittest.main()
