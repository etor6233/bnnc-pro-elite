from __future__ import annotations

from pathlib import Path
from hashlib import sha256
import json
import tempfile
import unittest

from tools.market_replay_oracle.market_replay import (
    DEVELOPMENT_USAGE,
    MarketReplayCorruption,
    replay_failed_generation_prefix,
)
from binance_lob.segment_chain import SegmentChainCorruption
from test_segment_chain import _build_generation


class MarketReplayTests(unittest.TestCase):
    def _fixture(self, parent: Path) -> tuple[Path, dict[str, object]]:
        run = parent / "fixture-run"
        campaign = run / "fixture-campaign"
        generation = campaign / "generations" / "fixture-BTCUSDT-g000"
        generation.mkdir(parents=True)
        _build_generation(generation)
        bindings = {
            "schema": "RawQualificationCampaignBindingsV1",
            "run_id": "fixture-run",
            "campaigns": [
                {
                    "symbol": "BTCUSDT",
                    "campaign_id": "fixture-campaign",
                    "campaign_directory": str(campaign.resolve()),
                }
            ],
        }
        bindings_bytes = json.dumps(bindings, ensure_ascii=False, indent=2).encode(
            "utf-8"
        )
        (run / "campaign-bindings.json").write_bytes(bindings_bytes)
        terminal = {
            "schema": "RawQualificationLauncherTerminalV2",
            "status": "FAILED",
            "run_id": "fixture-run",
            "mode": "Production",
            "run_root": str(run.resolve()),
            "campaign_bindings_sha256": sha256(bindings_bytes).hexdigest(),
            "credentials": "NONE",
            "order_entry": "ABSENT",
        }
        (run / "launcher-terminal.json").write_text(
            json.dumps(terminal, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        selection: dict[str, object] = {
            "schema": "ReplayPrefixSelectionV1",
            "usage": DEVELOPMENT_USAGE,
            "generation_directory": str(generation),
            "through_segment_index": 0,
            "exclusion_reason": "fixture failed-source prefix",
        }
        return generation, selection

    def test_replay_is_deterministic_neutral_and_manifest_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            _generation, selection = self._fixture(Path(raw_temp))
            first = replay_failed_generation_prefix(selection)
            repeated = replay_failed_generation_prefix(selection)
            self.assertEqual(first, repeated)
            self.assertFalse(first["qualification_claim"])
            self.assertFalse(first["cross_stream_total_order_available"])
            self.assertEqual(first["economic_features"], [])
            self.assertEqual(first["depth"]["selected_segments"], 1)  # type: ignore[index]
            self.assertEqual(first["depth"]["excluded_manifest_segments"], 1)  # type: ignore[index]
            self.assertEqual(first["depth"]["final_update_id"], 101)  # type: ignore[index]
            self.assertEqual(first["trades"]["first_trade_id"], 10)  # type: ignore[index]
            self.assertEqual(first["trades"]["last_trade_id"], 10)  # type: ignore[index]

            selection["through_segment_index"] = 1
            complete_prefix = replay_failed_generation_prefix(selection)
            self.assertEqual(complete_prefix["depth"]["final_update_id"], 102)  # type: ignore[index]
            self.assertEqual(complete_prefix["trades"]["last_trade_id"], 12)  # type: ignore[index]
            self.assertNotEqual(first["report_sha256"], complete_prefix["report_sha256"])

    def test_replay_refuses_unmanifested_range_and_selected_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            generation, selection = self._fixture(Path(raw_temp))
            selection["through_segment_index"] = 2
            with self.assertRaisesRegex(
                MarketReplayCorruption, "cannot select through segment 2"
            ):
                replay_failed_generation_prefix(selection)

            selection["through_segment_index"] = 0
            selected = generation / "depth" / "segment-000000.bnraw"
            body = bytearray(selected.read_bytes())
            body[-1] ^= 0x01
            selected.write_bytes(body)
            with self.assertRaises(SegmentChainCorruption):
                replay_failed_generation_prefix(selection)

    def test_replay_refuses_a_nonfailed_source_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            generation, selection = self._fixture(Path(raw_temp))
            terminal_path = generation.parents[2] / "launcher-terminal.json"
            terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
            terminal["status"] = "COMPLETE"
            terminal_path.write_text(
                json.dumps(terminal, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                MarketReplayCorruption, "not an exact failed production run"
            ):
                replay_failed_generation_prefix(selection)


if __name__ == "__main__":
    unittest.main()
