"""Independent cut inventories and honest prefix/terminal claims (2026-09-22)."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_oracle_boundaries import (
    TRADE_PAYLOADS, _build_artifact, _write_journal, _write_stream,
)
from binance_lob.live_arbitration_verify_cli import oracle_trades_union


def make_artifact(root: Path, name: str, trade_ids: list[int]) -> Path:
    artifact = _build_artifact(root / name, depth_frames=[])
    artifact = artifact.rename(artifact.with_name(name))
    for lane in ("p", "s"):
        generation = next((artifact / lane / "hr-campaign" / "generations").iterdir())
        _write_stream(generation, "trade", "trade-fixture", [TRADE_PAYLOADS[i] for i in trade_ids])
        # Empty depth is genuinely sealed, not a missing/unreadable input.
        (generation / "depth" / "segment-000000.bnraw").unlink()
        (generation / "generation.json").write_text(
            json.dumps({"status": "COMPLETE", "failure": None}), encoding="utf-8"
        )
    return artifact


def journal(root: Path, artifacts: list[Path], trade_ids: list[int], *, terminal=True) -> Path:
    raw = {}
    for artifact in artifacts:
        raw.update(oracle_trades_union(artifact))
    started = {"event": "ARBITRATION_STARTED", "symbol": "BTCUSDT", "spec_revision": "rev",
               "artifact_root": artifacts[-1].name, "prior_artifacts": [p.name for p in artifacts[:-1]],
               "trade_floor": 0}
    payloads = [started]
    for trade_id in trade_ids:
        payloads.append({"event": "TRADE_OBSERVATION", "trade_id": trade_id,
                         "lane": "PRIMARY", **raw[trade_id][0]})
    if terminal:
        payloads.append({"event": "ARBITRATION_TERMINAL", "status": "COMPLETE",
                         "trades": len(trade_ids), "depth_frames": 0, "gaps": 0,
                         "late_corrections": 0, "completion_scope": "SEALED_DRAIN"})
    return _write_journal(root, payloads)


def inventory(path: Path, artifacts: list[Path], journals: list[Path]) -> Path:
    path.write_text(json.dumps({
        "schema": "LiveArbitrationExpectedArtifactsV1",
        "artifacts": [str(p) for p in artifacts],
        "journals": [{"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                     for p in journals],
    }), encoding="utf-8")
    return path


def run_verifier(arguments: list[str], rust: bool = False):
    if rust:
        executable = os.environ.get("ARBITRATION_VERIFY_RUST")
        if not executable:
            raise unittest.SkipTest("Rust cross-language gate runs when isolated binary is built")
        command = [executable, *map(str, arguments)]
    else:
        command = [sys.executable, "-m", "binance_lob.live_arbitration_verify_cli", *map(str, arguments)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    report = json.loads(result.stdout) if result.returncode == 0 else None
    return result, report


class CoverageClaimTests(unittest.TestCase):
    rust = False

    def run_cli(self, *args):
        return run_verifier(list(args), self.rust)

    def test_clean_eof_without_terminal_is_not_terminal_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = make_artifact(root, "a1", [10])
            path = journal(root / "journal", [artifact], [10], terminal=False)
            result, report = self.run_cli(path, "--incremental")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(report["terminal_complete"])
            self.assertTrue(report["clean_eof"])

    def test_empty_bounded_prefix_cannot_claim_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = make_artifact(root, "a1", [10])
            path = journal(root / "journal", [artifact], [], terminal=False)
            result, report = self.run_cli(path, "--oracle-artifact", artifact, "--incremental")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report["oracle_identity"], "SKIPPED")
            self.assertEqual(report["oracle_trade_identity"], "SKIPPED_EMPTY_PREFIX")
            self.assertFalse(report["coverage_exhaustive"])

    def test_legacy_self_declared_scope_is_explicitly_unproven(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_artifact(root / "raw", "a1", [10])
            make_artifact(root / "raw", "a2", [11])
            third = make_artifact(root / "raw", "a3", [12])
            path = journal(root / "journal", [first, third], [10, 12])
            result, report = self.run_cli(path, "--oracle-artifact", root / "raw")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report["artifact_coverage"], "UNPROVEN")
            self.assertFalse(report["coverage_exhaustive"])

    def test_independent_inventory_rejects_omitted_middle_epoch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifacts = [make_artifact(root / "raw", f"a{i}", [i + 9]) for i in (1, 2, 3)]
            path = journal(root / "journal", [artifacts[0], artifacts[2]], [10, 12])
            manifest = inventory(root / "expected.json", artifacts, [path])
            result, _ = self.run_cli(path, "--oracle-artifact", root / "raw",
                                     "--expected-artifact-inventory", manifest)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("artifact inventory differs", result.stderr)

    def test_old_cut_does_not_require_future_epoch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_artifact(root / "raw", "a1", [10])
            path = journal(root / "journal", [first], [10])
            manifest = inventory(root / "expected.json", [first], [path])
            make_artifact(root / "raw", "future-a2", [11])
            result, report = self.run_cli(path, "--oracle-artifact", root / "raw",
                                         "--expected-artifact-inventory", manifest)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report["artifact_coverage"], "PASS")
            self.assertTrue(report["coverage_exhaustive"])
            self.assertTrue(report["terminal_complete"])

    def test_changed_journal_after_inventory_cut_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_artifact(root, "a1", [10])
            path = journal(root / "journal", [first], [10])
            manifest = inventory(root / "expected.json", [first], [path])
            path.write_bytes(path.read_bytes() + b"\n")
            result, _ = self.run_cli(path, "--oracle-artifact", first,
                                     "--expected-artifact-inventory", manifest)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("inventory journal hash mismatch", result.stderr)

    def test_partial_live_tail_keeps_prefix_and_reports_actual_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_artifact(root, "a1", [10])
            path = journal(root / "journal", [first], [10], terminal=False)
            path.write_bytes(path.read_bytes() + b'{"torn":')
            result, report = self.run_cli(path, "--oracle-artifact", first, "--incremental")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(report["terminal_complete"])
            self.assertFalse(report["clean_eof"])
            self.assertEqual(report["tail_bytes"], 8)
            self.assertEqual(report["audit_scope"], "LIVE_PREFIX")

    def test_interrupted_resumed_tail_never_reports_terminal_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_artifact(root, "a1", [10])
            payload = {"event": "ARBITRATION_RESUMED", "symbol": "BTCUSDT",
                       "artifact_root": first.name, "trade_floor": 10,
                       "previous_journal_sha256": "a" * 64, "mode": "LIVE"}
            path = _write_journal(root / "journal", [payload])
            result, report = self.run_cli(path, "--oracle-artifact", first, "--tail-segment-only")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(report["terminal_complete"])
            self.assertTrue(report["tail_interrupted"])
            self.assertEqual(report["audit_scope"], "INTERRUPTED_SEGMENT_PREFIX")
            self.assertFalse(report["coverage_exhaustive"])

    def test_sealed_tail_is_not_exhaustive_even_with_exact_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_artifact(root, "a1", [10, 11])
            path = journal(root / "journal", [first], [10])
            manifest = inventory(root / "expected.json", [first], [path])
            result, report = self.run_cli(path, "--oracle-artifact", first,
                                         "--expected-artifact-inventory", manifest, "--tail-segment-only")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(report["terminal_complete"])
            self.assertEqual(report["artifact_coverage"], "PASS")
            self.assertFalse(report["coverage_exhaustive"])

    def test_omission_still_rejected_when_journal_declares_expected_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifacts = [make_artifact(root / "raw", f"a{i}", [i + 9]) for i in (1, 2, 3)]
            path = journal(root / "journal", artifacts, [10, 12])
            manifest = inventory(root / "expected.json", artifacts, [path])
            result, _ = self.run_cli(path, "--oracle-artifact", root / "raw",
                                     "--expected-artifact-inventory", manifest)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("differs from the raw union", result.stderr)

    def test_duplicate_or_wrong_inventory_journal_set_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_artifact(root, "a1", [10])
            path = journal(root / "journal", [first], [10])
            for suffix in ("duplicate", "wrong-journal"):
                manifest = inventory(root / f"{suffix}.json", [first], [path])
                value = json.loads(manifest.read_text())
                if suffix == "duplicate":
                    value["artifacts"].append(str(first))
                    reason = "duplicate identities"
                else:
                    copy = root / "different-cut.jsonl"
                    copy.write_bytes(path.read_bytes())
                    value["journals"][0]["path"] = str(copy)
                    reason = "journal set differs"
                manifest.write_text(json.dumps(value), encoding="utf-8")
                result, _ = self.run_cli(path, "--oracle-artifact", first,
                                         "--expected-artifact-inventory", manifest)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(reason, result.stderr)

    def test_inventory_relative_paths_and_utf8_bom_are_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_artifact(root, "a1", [10])
            path = journal(root / "journal", [first], [10])
            manifest = inventory(root / "expected.json", [first], [path])
            value = json.loads(manifest.read_text())
            value["artifacts"] = [str(first.relative_to(root))]
            value["journals"][0]["path"] = str(path.relative_to(root))
            manifest.write_text(json.dumps(value), encoding="utf-8-sig")
            result, report = self.run_cli(path, "--oracle-artifact", first,
                                         "--expected-artifact-inventory", manifest)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report["expected_artifact_inventory_sha256"],
                             hashlib.sha256(manifest.read_bytes()).hexdigest())

    def test_artifact_with_matching_name_outside_oracle_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_artifact(root / "raw", "a1", [10])
            outside = make_artifact(root / "outside", "a1", [10])
            path = journal(root / "journal", [first], [10])
            manifest = inventory(root / "expected.json", [outside], [path])
            result, _ = self.run_cli(path, "--oracle-artifact", root / "raw",
                                     "--expected-artifact-inventory", manifest)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("paths are missing or ambiguous", result.stderr)

    def test_handoff_or_legacy_terminal_cannot_claim_exhaustive_drain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = make_artifact(root, "a1", [10])
            for completion_scope in ("HANDOFF", None):
                path = journal(root / "journal", [first], [10])
                payloads = [json.loads(line)["body"]["payload"]
                            for line in path.read_text().splitlines()]
                if completion_scope is None:
                    payloads[-1].pop("completion_scope")
                else:
                    payloads[-1]["completion_scope"] = completion_scope
                path = _write_journal(path.parent, payloads)
                manifest = inventory(root / "expected.json", [first], [path])
                result, report = self.run_cli(path, "--oracle-artifact", first,
                                             "--expected-artifact-inventory", manifest)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(report["terminal_complete"])
                self.assertFalse(report["coverage_exhaustive"])
                self.assertEqual(report["terminal_completion_scope"], completion_scope)


class RustCoverageClaimTests(CoverageClaimTests):
    rust = True


if __name__ == "__main__":
    unittest.main()
