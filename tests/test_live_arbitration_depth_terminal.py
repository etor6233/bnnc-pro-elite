"""The final raw boundary includes trusted overlaps U <= next <= u."""

import json
import tempfile
import unittest
from pathlib import Path

import test_oracle_boundaries as oracle_fixtures
from test_oracle_boundaries import _build_artifact, _write_journal
from test_live_arbitration_coverage import inventory, run_verifier
from binance_lob.book import LocalOrderBook
from binance_lob.live_arbitration_verify_cli import (
    _stream_records, oracle_trades_union, _trusted_depth_observations,
)


def frame(first, final, *, quantity="1"):
    return json.dumps({"e": "depthUpdate", "E": 1, "s": "BTCUSDT", "U": first, "u": final,
                       "b": [["100", quantity]], "a": []}, separators=(",", ":")).encode()


class DepthTerminalTests(unittest.TestCase):
    rust = False

    def check(self, frames, *, rejected=False, incremental=False, depth_count=1,
              canonical_indices=None, error="final omission"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = _build_artifact(root / "raw", depth_frames=frames)
            depth = {}
            for lane in ("p", "s"):
                generation = next((artifact / lane / "hr-campaign" / "generations").iterdir())
                (generation / "generation.json").write_text('{"status":"COMPLETE","failure":null}', encoding="utf-8")
                lane_depth = {}
                if canonical_indices is None:
                    canonical = _trusted_depth_observations(generation)
                else:
                    # The fixture explicitly chooses the published frames. Do not
                    # invoke the oracle under test to construct malformed-raw cases.
                    book = LocalOrderBook("BTCUSDT")
                    book.load_snapshot(oracle_fixtures.SNAPSHOT_PAYLOAD)
                    canonical = []
                    for index in canonical_indices:
                        payload = json.loads(frames[index])
                        book.apply_depth(frames[index])
                        canonical.append((payload["U"], payload["u"], book.state_digest()))
                for first, final, digest in canonical:
                    lane_depth.setdefault(final, []).append((first, digest))
                depth[lane] = lane_depth
            payloads = oracle_fixtures.ClosedOracleEndToEndTests()._journal_payloads(oracle_trades_union(artifact), depth, depth_count=depth_count)
            primary = next((artifact / "p" / "hr-campaign" / "generations").iterdir())
            raw_records = list(_stream_records(primary, "depth"))
            records = iter(raw_records if canonical_indices is None
                           else [raw_records[index] for index in canonical_indices])
            for payload in payloads:
                if payload["event"] == "DEPTH_OBSERVATION":
                    payload["record_sha256"] = next(records).record_sha256
            payloads[-1]["completion_scope"] = "SEALED_DRAIN"
            path = _write_journal(root / "journal", payloads)
            manifest = inventory(root / "expected.json", [artifact], [path])
            args = [str(path), "--oracle-artifact", str(artifact), "--expected-artifact-inventory", str(manifest)]
            if incremental:
                args.append("--incremental")
            result, report = run_verifier(args, self.rust)
            if rejected:
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(error, result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(report["coverage_exhaustive"], not incremental)

    def test_trusted_overlap_after_canonical_end_is_omission(self):
        self.check([frame(101, 101), frame(101, 105, quantity="0")], rejected=True)

    def test_exact_terminal_without_successor_passes(self):
        self.check([frame(101, 101)])

    def test_fully_published_trusted_prefix_is_not_a_successor(self):
        self.check([frame(101, 103), frame(104, 105)], depth_count=2)

    def test_uint64_max_has_no_successor(self):
        self.check([frame(101, 2**64 - 1)])

    def test_live_prefix_does_not_claim_full_depth_boundary(self):
        self.check([frame(101, 101), frame(101, 105, quantity="0")], incremental=True)

    def test_repeated_depth_after_live_is_rejected(self):
        self.check([frame(101, 101), frame(101, 101)], canonical_indices=[0],
                   rejected=True, error="stale depth record")

    def test_regressed_depth_after_live_is_rejected(self):
        self.check([frame(101, 105), frame(101, 103)], canonical_indices=[0],
                   rejected=True, error="stale depth record")

    def test_old_depth_before_first_live_is_bootstrap_and_allowed(self):
        self.check([frame(91, 99), frame(101, 101)], canonical_indices=[1])


class RustDepthTerminalTests(DepthTerminalTests):
    rust = True


if __name__ == "__main__":
    unittest.main()
