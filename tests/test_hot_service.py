from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

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
