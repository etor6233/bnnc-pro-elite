"""ADR-17: exact reconstructed raw union, with adversarial late identities."""

import json
import tempfile
import unittest
from pathlib import Path

from test_live_arbitration_coverage import make_artifact, inventory, run_verifier
from test_oracle_boundaries import _write_journal, _write_stream, TRADE_PAYLOADS
from binance_lob.live_arbitration_verify_cli import oracle_trades_union


def late_fixture(root, *, observed=(10, 12), corrections=((11, "unknown"),), floor=0,
                 bad_digest=False, conflict=False):
    artifact = make_artifact(root / "raw", "a1", [10, 11, 12])
    raw = oracle_trades_union(artifact)
    if conflict:
        generation = next((artifact / "s" / "hr-campaign" / "generations").iterdir())
        changed = json.loads(TRADE_PAYLOADS[11])
        changed["p"] = "9999.00"
        _write_stream(generation, "trade", "trade-fixture", [
            TRADE_PAYLOADS[10], json.dumps(changed).encode(), TRADE_PAYLOADS[12],
        ])
    payloads = [{"event": "ARBITRATION_STARTED", "symbol": "BTCUSDT", "spec_revision": "rev",
                 "artifact_root": artifact.name, "trade_floor": floor}]
    payloads += [{"event": "TRADE_OBSERVATION", "trade_id": i, "lane": "PRIMARY", **raw[i][0]}
                 for i in observed]
    for i, kind in corrections:
        payload = {"event": "TRADE_LATE_CORRECTION", "trade_id": i, "kind": kind,
                   "lane": "SHADOW", **raw[i][0]}
        if bad_digest:
            payload["observation_sha256"] = "f" * 64
        payloads.append(payload)
    payloads.append({"event": "ARBITRATION_TERMINAL", "status": "COMPLETE",
                     "trades": len(observed), "depth_frames": 0, "gaps": 0,
                     "late_corrections": len(corrections), "completion_scope": "SEALED_DRAIN"})
    path = _write_journal(root / "journal", payloads)
    manifest = inventory(root / "expected.json", [artifact], [path])
    return [str(path), "--oracle-artifact", str(artifact), "--expected-artifact-inventory", str(manifest)]


class LateUnionTests(unittest.TestCase):
    rust = False

    def check(self, *, accept=False, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            args = late_fixture(Path(tmp), **kwargs)
            result, report = run_verifier(args, self.rust)
            if accept:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(report["canonical_view"], "OBSERVATIONS_PLUS_UNKNOWN_LATE_CORRECTIONS")
                self.assertEqual(report["reconstructed_trades"], 3)
                self.assertTrue(report["coverage_exhaustive"])
                self.assertEqual(report.get("trades", report.get("audit", {}).get("trades")), 2)
            else:
                self.assertNotEqual(result.returncode, 0, "mutant falsely accepted: " + result.stdout)

    def test_legitimate_unknown_reconstructs_exact_union(self):
        self.check(accept=True)

    def test_duplicate_after_unknown_is_identity_corroborated(self):
        self.check(accept=True, corrections=((11, "unknown"), (11, "duplicate")))

    def test_missing_late_rejected(self):
        self.check(corrections=())

    def test_repeated_unknown_rejected(self):
        self.check(corrections=((11, "unknown"), (11, "unknown")))

    def test_unknown_claiming_published_identity_rejected(self):
        self.check(observed=(10, 11, 12))

    def test_duplicate_without_prior_identity_rejected(self):
        self.check(corrections=((11, "duplicate"),))

    def test_altered_correction_digest_rejected(self):
        self.check(bad_digest=True)

    def test_unknown_at_or_below_initial_admission_floor_rejected(self):
        self.check(observed=(12,), corrections=((11, "unknown"),), floor=11)

    def test_conflicting_raw_identity_cannot_be_hidden_by_correction(self):
        self.check(conflict=True)

    def test_duplicate_after_unknown_across_resume_has_full_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = late_fixture(root)
            first = Path(args[0]).rename(root / "journal" / "0000.jsonl")
            payloads = [json.loads(line)["body"]["payload"] for line in first.read_text().splitlines()]
            payloads[-1]["completion_scope"] = "HANDOFF"
            first.unlink()
            first = _write_journal(first.parent, payloads).rename(first)
            chain = json.loads(first.read_text().splitlines()[-1])["record_sha256"]
            correction = dict(payloads[-2], kind="duplicate")
            resumed = [{"event": "ARBITRATION_RESUMED", "symbol": "BTCUSDT", "mode": "CONTINUOUS",
                        "artifact_root": Path(args[2]).name, "trade_floor": 12,
                        "previous_journal_sha256": chain}, correction,
                       dict(payloads[-1], late_corrections=2, completion_scope="SEALED_DRAIN")]
            second = _write_journal(first.parent, resumed).rename(first.parent / "0001.jsonl")
            manifest = inventory(root / "chain.json", [Path(args[2])], [first, second])
            result, report = run_verifier(["--journal-root", str(first.parent), "--oracle-artifact", args[2],
                                           "--expected-artifact-inventory", str(manifest)], self.rust)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report["reconstructed_trades"], 3)
            self.assertTrue(report["coverage_exhaustive"])
            # A later active writer is deliberately malformed: the frozen
            # context cut must neither require it nor accidentally parse it.
            (first.parent / "0002.jsonl").write_bytes(b'{"active":')
            result, report = run_verifier(["--journal-root", str(first.parent), "--journal-prefix",
                                           "--oracle-artifact", args[2],
                                           "--expected-artifact-inventory", str(manifest)], self.rust)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report["reconstructed_trades"], 3)
            self.assertEqual(report["audit_scope"], "SEALED_JOURNAL_PREFIX")
            self.assertTrue(report["journal_prefix"])
            self.assertTrue(report["terminal_complete"])
            self.assertFalse(report["coverage_exhaustive"])
            (first.parent / "0002.jsonl").unlink()
            active_start = dict(resumed[0], previous_journal_sha256=
                                json.loads(second.read_text().splitlines()[-1])["record_sha256"])
            active = _write_journal(first.parent, [active_start, correction]).rename(first.parent / "0002.jsonl")
            active.write_bytes(active.read_bytes() + b'{"torn":')
            result, report = run_verifier(["--journal-root", str(first.parent), "--incremental",
                                           "--oracle-artifact", args[2]], self.rust)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report["reconstructed_trades"], 3)
            self.assertEqual(report["audit_scope"], "LIVE_PREFIX")
            self.assertFalse(report["terminal_complete"])
            self.assertFalse(report["coverage_exhaustive"])
            self.assertEqual(report["tail_bytes"], 8)

    def test_resumed_tail_never_invents_prior_duplicate_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = late_fixture(root)
            original = Path(args[0])
            payloads = [json.loads(line)["body"]["payload"] for line in original.read_text().splitlines()]
            resumed = {"event": "ARBITRATION_RESUMED", "symbol": "BTCUSDT", "mode": "CONTINUOUS",
                       "artifact_root": Path(args[2]).name, "trade_floor": 12,
                       "previous_journal_sha256": "a" * 64}
            for kind in ("unknown", "duplicate"):
                tail = _write_journal(root / kind, [resumed, dict(payloads[-2], kind=kind)])
                result, report = run_verifier([str(tail), "--oracle-artifact", args[2], "--tail-segment-only"], self.rust)
                if kind == "unknown":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(report["coverage_exhaustive"])
                    self.assertEqual(report["reconstructed_trades"], 1)
                else:
                    self.assertNotEqual(result.returncode, 0)

    def test_prefix_cut_cannot_omit_middle_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = late_fixture(root)
            first = Path(args[0]).rename(root / "journal" / "0000.jsonl")
            middle = first.parent / "0001.jsonl"
            future = first.parent / "0002.jsonl"
            middle.write_bytes(b'{"middle":')
            future.write_bytes(first.read_bytes())
            manifest = inventory(root / "missing-middle.json", [Path(args[2])], [first, future])
            result, _ = run_verifier(["--journal-root", str(first.parent), "--journal-prefix",
                                      "--oracle-artifact", args[2],
                                      "--expected-artifact-inventory", str(manifest)], self.rust)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("contiguous prefix", result.stderr)

    def test_prefix_requires_external_inventory_and_sealed_cut(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = late_fixture(root)
            path = Path(args[0])
            result, _ = run_verifier(["--journal-root", str(path.parent), "--journal-prefix",
                                      "--oracle-artifact", args[2]], self.rust)
            self.assertNotEqual(result.returncode, 0)

            payloads = [json.loads(line)["body"]["payload"] for line in path.read_text().splitlines()]
            path = _write_journal(path.parent, payloads[:-1])
            manifest = inventory(root / "interrupted.json", [Path(args[2])], [path])
            result, _ = run_verifier(["--journal-root", str(path.parent), "--journal-prefix",
                                      "--oracle-artifact", args[2],
                                      "--expected-artifact-inventory", str(manifest)], self.rust)
            self.assertNotEqual(result.returncode, 0)

    def test_torn_predecessor_requires_exact_declared_bytes_with_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = late_fixture(root)
            path = Path(args[0])
            payloads = [json.loads(line)["body"]["payload"] for line in path.read_text().splitlines()]
            first = _write_journal(path.parent, payloads[:-1]).rename(path.parent / "0000.jsonl")
            chain = json.loads(first.read_text().splitlines()[-1])["record_sha256"]
            first.write_bytes(first.read_bytes() + b'{"torn":')
            resumed = {"event": "ARBITRATION_RESUMED", "symbol": "BTCUSDT", "mode": "CONTINUOUS",
                       "artifact_root": Path(args[2]).name, "trade_floor": 12,
                       "previous_journal_sha256": chain, "previous_tail_bytes": 8}
            for declared in (8, 0):
                resumed["previous_tail_bytes"] = declared
                second = _write_journal(path.parent, [resumed, dict(payloads[-2], kind="duplicate"),
                                                       dict(payloads[-1], late_corrections=2)])
                target = path.parent / "0001.jsonl"
                if target.exists():
                    target.unlink()
                second.rename(target)
                for mode in ([], ["--incremental"]):
                    result, report = run_verifier(["--journal-root", str(path.parent), "--oracle-artifact", args[2], *mode], self.rust)
                    if declared == 8:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(report["reconstructed_trades"], 3)
                    else:
                        self.assertNotEqual(result.returncode, 0)


class RustLateUnionTests(LateUnionTests):
    rust = True


if __name__ == "__main__":
    unittest.main()
