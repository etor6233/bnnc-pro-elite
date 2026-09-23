from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from binance_lob import hot_service as service

from binance_lob.hot_service import (
    BODY_KEYS,
    HotServiceCorruption,
    _compact,
    _json,
    _relative,
    _scan_journal,
    verify_hot_service,
)


class HotServiceVerifierTests(unittest.TestCase):
    def _complete_legacy_envelope(self, root, *, version=1, exhaustive=True,
                                  omitted_failure=False, omitted_consensus=False):
        root.mkdir()
        reports = {}
        def write(relative, value):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            data = _compact(value)
            path.write_bytes(data)
            return sha256(data).hexdigest()
        preflight = dict(zip(service.PREFLIGHT_KEYS, (
            "HotRedundantQualificationPreflightV1", "PASS", "Continuous", 60,
            True, 30, 1, True, ["BTCUSDT", "ETHUSDT"], {}, {}, {}, {}, root.name, str(root),
        )))
        preflight_sha = write("preflight.json", preflight)
        verification, live, admissions = [], {}, []
        for symbol in ("BTCUSDT", "ETHUSDT"):
            artifact_relative = f"{symbol[0].lower()}/e1/hr-{symbol}"
            artifact = root / artifact_relative
            artifact.mkdir(parents=True)
            actual = {"symbol": symbol, "supervisor_id": symbol,
                      "terminal_file_sha256": "a" * 64, "journal_terminal_sha256": "b" * 64}
            reports[str(artifact)] = actual
            rust = {"status": "PASS", "supervisor_id": symbol,
                    "terminal_file_sha256": "a" * 64, "journal_terminal_sha256": "b" * 64}
            write(f"{symbol}/python.json", actual)
            write(f"{symbol}/rust.json", rust)
            verification.append(dict(zip(service.PASS_VERIFIED_IN_LOOP_KEYS, (
                symbol, 1, "PASS", True, f"{symbol}/rust.json", f"{symbol}/python.json", artifact_relative,
            ))))
            journal = f"{symbol}/canonical.jsonl"
            canonical_sha = write(journal, {"fixture": "canonical report binding only"})
            oracle = {"status": "PASS", "oracle_identity": "PASS", "trades": 1,
                      "depth_frames": 1, "gaps": 0, "segments": 1,
                      "late_corrections": 0, "last_record_sha256": "c" * 64}
            if version == 2:
                inventory = {"schema": "LiveArbitrationExpectedArtifactsV1", "artifacts": [str(artifact)],
                             "journals": [{"path": str(root / journal), "sha256": canonical_sha}]}
                inventory_path = f"{symbol}/expected-artifacts.json"
                inventory_sha = write(inventory_path, inventory)
                oracle.update(schema="LiveArbitrationVerificationV2", artifact_coverage="PASS",
                              terminal_complete=True, coverage_exhaustive=exhaustive,
                              terminal_completion_scope="SEALED_DRAIN",
                              canonical_view="OBSERVATIONS_PLUS_UNKNOWN_LATE_CORRECTIONS", reconstructed_trades=1,
                              expected_artifact_inventory_sha256=inventory_sha)
                oracle["audit"] = {"trades": 1, "depth_frames": 1, "gaps": 0, "segments": 1,
                                   "late_corrections": 0, "last_record_sha256": "c" * 64}
                if omitted_consensus:
                    for key in ("late_corrections", "last_record_sha256"):
                        del oracle[key]
                        del oracle["audit"][key]
                admissions.append({"event": "RAW_ARTIFACT_DISCOVERED", "symbol": symbol, "epoch": 1, "artifact": artifact_relative})
            rust_path, python_path = f"{symbol}/oracle-rust.json", f"{symbol}/oracle-python.json"
            rust_sha, python_sha = write(rust_path, oracle), write(python_path, oracle)
            live[symbol.lower()] = dict(zip(service.LIVE_ARBITRATION_KEYS, (
                symbol.lower(), journal, symbol, canonical_sha, rust_path, rust_sha,
                python_path, python_sha, "PASS", 1, 1, 0, 1, 0,
            )))
            if version == 2:
                live[symbol.lower()].update(expected_artifact_inventory=inventory_path,
                                           expected_artifact_inventory_sha256=inventory_sha)
        (root / "obs/system").mkdir(parents=True)
        system = {"run_id": "observed-0123456789ab", "status": "PASS"}
        system_sha = write("verification/system-evidence.json", system)
        observer = {
            "kernel_network": {"status": "SKIPPED_NOT_ELEVATED", "run_id": "observed-0123456789ab"},
            "network_witness": {"status": "SKIPPED_NOT_ELEVATED", "observation_id": "observed-0123456789ab"},
            "system_evidence": {"path": "verification/system-evidence.json", "sha256": system_sha,
                                "run_id": "observed-0123456789ab"},
            "live_arbitration": live,
        }
        if version == 2:
            observer["kernel_network"] = []
            observer["network_witness"] = []
        first, first_sha = self._journal_record(0, "0" * 64, {
            "event": "SERVICE_STARTED", "run_id": root.name, "preflight_sha256": preflight_sha})
        prefix, previous, count = first, first_sha, 1
        if omitted_failure:
            admissions.append({"event": "OBSERVER_FAILED", "observer": "KERNEL_NETWORK",
                               "failure_id": "kernel:1:FAILED", "detail": "injected observer failure"})
        for payload in admissions + [{"event": "SERVICE_TERMINAL_PREPARED"}]:
            line, previous = self._journal_record(count, previous, payload)
            prefix += line
            count += 1
        terminal = dict(zip(service.TERMINAL_KEYS, (
            f"HotRedundantQualificationTerminalV{version}", "PASS", root.name,
            "2026-09-22T00:00:00+00:00", "2026-09-22T00:01:00+00:00", "Continuous",
            True, 30, 1, True, False, True, 60, [], [], verification, [], [], observer,
            {"file_bytes": len(prefix), "file_sha256": sha256(prefix).hexdigest(),
             "records": count, "terminal_record_sha256": previous},
        )))
        terminal_sha = write("service-terminal.json", terminal)
        commit, _ = self._journal_record(count, previous, {
            "event": "SERVICE_COMMITTED", "terminal_file": "service-terminal.json", "terminal_sha256": terminal_sha})
        journal = prefix + commit
        (root / "service-events.jsonl").write_bytes(journal)
        return reports, system, journal

    def test_complete_envelope_reports_service_journal_hash_not_canonical_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "hrs-012345abcdef"
            reports, system, journal = self._complete_legacy_envelope(root)
            with patch.object(service, "verify_hot_redundant_capture", side_effect=lambda path: reports[str(path)]), \
                    patch.object(service, "verify_system_evidence", return_value=system):
                verified = verify_hot_service(root)
            self.assertEqual(verified["journal_sha256"], sha256(journal).hexdigest())
            self.assertEqual(verified["observer_coverage"]["status"], "UNVERIFIED_LEGACY_V1")

    def test_v2_complete_envelope_keeps_skipped_observers_unqualified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "hrs-012345abcdef"
            reports, system, _ = self._complete_legacy_envelope(root, version=2)
            with patch.object(service, "verify_hot_redundant_capture", side_effect=lambda path: reports[str(path)]), \
                    patch.object(service, "verify_system_evidence", return_value=system):
                verified = verify_hot_service(root)
            self.assertEqual(verified["schema"], "HotRedundantServiceVerificationV2")
            self.assertEqual(verified["observer_coverage"]["status"], "SKIPPED_NOT_ELEVATED")

    def test_v2_prefix_pass_cannot_be_promoted_to_complete_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "hrs-012345abcdef"
            reports, system, _ = self._complete_legacy_envelope(root, version=2, exhaustive=False)
            with patch.object(service, "verify_hot_redundant_capture", side_effect=lambda path: reports[str(path)]), \
                    patch.object(service, "verify_system_evidence", return_value=system):
                with self.assertRaisesRegex(HotServiceCorruption, "complete expected coverage"):
                    verify_hot_service(root)

    def test_v2_cannot_erase_observer_failure_from_terminal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "hrs-012345abcdef"
            reports, system, _ = self._complete_legacy_envelope(root, version=2, omitted_failure=True)
            with patch.object(service, "verify_hot_redundant_capture", side_effect=lambda path: reports[str(path)]), \
                    patch.object(service, "verify_system_evidence", return_value=system):
                with self.assertRaisesRegex(HotServiceCorruption, "failure inventory"):
                    verify_hot_service(root)

    def test_v2_missing_fields_in_both_oracles_do_not_prove_agreement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "hrs-012345abcdef"
            reports, system, _ = self._complete_legacy_envelope(root, version=2, omitted_consensus=True)
            with patch.object(service, "verify_hot_redundant_capture", side_effect=lambda path: reports[str(path)]), \
                    patch.object(service, "verify_system_evidence", return_value=system):
                with self.assertRaises(HotServiceCorruption):
                    verify_hot_service(root)

    def test_v2_inventory_cannot_omit_independently_admitted_epoch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "hrs-012345abcdef"
            self._complete_legacy_envelope(root, version=2)
            terminal = json.loads((root / "service-terminal.json").read_bytes())
            records, _ = _scan_journal((root / "service-events.jsonl").read_bytes())
            (root / "BTCUSDT-e2").mkdir()
            records.insert(-1, {"body": {"payload": {"event": "RAW_ARTIFACT_DISCOVERED", "symbol": "BTCUSDT",
                                                    "epoch": 2, "artifact": "BTCUSDT-e2"}}})
            with self.assertRaisesRegex(HotServiceCorruption, "independently journalled admissions"):
                service._verify_expected_artifacts(root, terminal["observer_verification"]["live_arbitration"]["btcusdt"], records, "btcusdt")

    def test_v2_inventory_cannot_omit_a_canonical_segment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "hrs-012345abcdef"
            self._complete_legacy_envelope(root, version=2)
            terminal = json.loads((root / "service-terminal.json").read_bytes())
            records, _ = _scan_journal((root / "service-events.jsonl").read_bytes())
            (root / "BTCUSDT/second.jsonl").write_text("omitted")
            with self.assertRaisesRegex(HotServiceCorruption, "omitted a canonical journal"):
                service._verify_expected_artifacts(root, terminal["observer_verification"]["live_arbitration"]["btcusdt"], records, "btcusdt")

    def test_v2_manifest_and_admissions_omitting_same_epoch_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "hrs-012345abcdef"
            self._complete_legacy_envelope(root, version=2)
            terminal = json.loads((root / "service-terminal.json").read_bytes())
            records, _ = _scan_journal((root / "service-events.jsonl").read_bytes())
            (root / "b/e2/hr-unregistered").mkdir(parents=True)
            with self.assertRaisesRegex(HotServiceCorruption, "raw source directories"):
                service._verify_expected_artifacts(root, terminal["observer_verification"]["live_arbitration"]["btcusdt"], records, "btcusdt")

    def test_large_closed_canonical_journal_is_hashed_without_256mib_limit(self):
        # Real retained journals already exceed 400 MB. The envelope must hash
        # a sealed file incrementally; its size is not a corruption criterion.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "hrs-012345abcdef"
            reports, system, _ = self._complete_legacy_envelope(root)
            terminal_path = root / "service-terminal.json"
            terminal = json.loads(terminal_path.read_bytes())
            entry = terminal["observer_verification"]["live_arbitration"]["ethusdt"]
            canonical_path = root / entry["journal"]
            with canonical_path.open("wb") as handle:
                handle.truncate(256 * 1024 * 1024 + 1)
            digest = sha256()
            with canonical_path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            entry["journal_sha256"] = digest.hexdigest()
            terminal_data = _compact(terminal)
            terminal_path.write_bytes(terminal_data)
            journal_path = root / "service-events.jsonl"
            lines = journal_path.read_bytes().splitlines(keepends=True)
            last = json.loads(lines[-1])["body"]
            commit, _ = self._journal_record(last["record_index"], last["previous_record_sha256"], {
                "event": "SERVICE_COMMITTED", "terminal_file": "service-terminal.json",
                "terminal_sha256": sha256(terminal_data).hexdigest()})
            journal_path.write_bytes(b"".join(lines[:-1]) + commit)
            with patch.object(service, "verify_hot_redundant_capture", side_effect=lambda path: reports[str(path)]), \
                    patch.object(service, "verify_system_evidence", return_value=system):
                self.assertEqual(verify_hot_service(root)["status"], "PASS")

    @staticmethod
    def _journal_record(index: int, previous: str, payload: object) -> tuple[bytes, str]:
        body = dict(zip(BODY_KEYS, (
            "HotRedundantServiceJournalRecordV1", index, 10 + index,
            20 + index, "SERVICE", payload, previous,
        )))
        digest = sha256(_compact(body)).hexdigest()
        return _compact({"body": body, "record_sha256": digest}) + b"\n", digest

    def test_committed_failure_round_trip_and_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "hrs-012345abcdef"
            root.mkdir()
            preflight = {
                "schema": "HotRedundantQualificationPreflightV1", "status": "PASS",
                "mode": "IntegrationTest", "total_seconds": 60,
                "continuous": False, "epoch_window_seconds": 14400, "time_scale": 1,
                "skip_kernel_observer": False,
                "symbols": ["BTCUSDT", "ETHUSDT"], "topology": {}, "disk": {},
                "clock": {}, "implementation": {}, "run_id": root.name,
                "run_root": str(root.resolve()),
            }
            preflight_data = json.dumps(preflight, indent=2).encode() + b"\n"
            (root / "preflight.json").write_bytes(preflight_data)
            summary = {
                "exception_type": "System.Exception", "hresult": -1,
                "fully_qualified_error_id": "TEST", "category": "OperationStopped",
                "message": "deterministic fault",
            }
            first, first_sha = self._journal_record(0, "0" * 64, {
                "event": "SERVICE_STARTED", "run_id": root.name,
                "preflight_sha256": sha256(preflight_data).hexdigest(),
            })
            prepared, prepared_sha = self._journal_record(1, first_sha, {
                "event": "SERVICE_FAILURE_PREPARED", "failure": summary,
            })
            prefix_data = first + prepared
            failure = {
                "schema": "HotRedundantQualificationFailureV1", "status": "FAILED",
                "run_id": root.name, "observed_utc": "2026-09-01T00:00:00+00:00",
                "elapsed_s": 1.5, "failure": summary, "script_stack_trace": "test",
                "observer_failures": [], "active_processes": [],
                "journal_precommit": {
                    "file_bytes": len(prefix_data), "file_sha256": sha256(prefix_data).hexdigest(),
                    "records": 2, "terminal_record_sha256": prepared_sha,
                },
            }
            failure_data = json.dumps(failure, indent=2).encode() + b"\n"
            (root / "service-failure.json").write_bytes(failure_data)
            commit, _ = self._journal_record(2, prepared_sha, {
                "event": "SERVICE_FAILED_COMMITTED", "failure_file": "service-failure.json",
                "failure_sha256": sha256(failure_data).hexdigest(),
            })
            (root / "service-events.jsonl").write_bytes(prefix_data + commit)
            self.assertEqual(verify_hot_service(root)["terminal_status"], "FAILED")
            changed = failure_data.replace(b"deterministic fault", b"deterministic faulu", 1)
            (root / "service-failure.json").write_bytes(changed)
            with self.assertRaises(HotServiceCorruption):
                verify_hot_service(root)

    def test_journal_round_trip_then_one_byte_corruption_fails(self) -> None:
        body = dict(zip(BODY_KEYS, (
            "HotRedundantServiceJournalRecordV1", 0, 10, 20, "SERVICE",
            {"event": "TEST"}, "0" * 64,
        )))
        envelope = {"body": body, "record_sha256": sha256(_compact(body)).hexdigest()}
        data = _compact(envelope) + b"\n"
        records, lines = _scan_journal(data)
        self.assertEqual(len(records), 1)
        self.assertEqual(lines, [data])
        mutated = bytearray(data)
        mutated[mutated.index(b"TEST")] ^= 1
        with self.assertRaises(HotServiceCorruption):
            _scan_journal(bytes(mutated))

    def test_duplicate_property_and_path_escape_fail(self) -> None:
        with self.assertRaises(HotServiceCorruption):
            _json(b'{"status":"PASS","status":"FAILED"}', "duplicate")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "inside.txt").write_text("ok", encoding="utf-8")
            self.assertEqual(_relative(root, "inside.txt", "inside"), root / "inside.txt")
            with self.assertRaises(HotServiceCorruption):
                _relative(root, "../outside.txt", "escape")


if __name__ == "__main__":
    unittest.main()
