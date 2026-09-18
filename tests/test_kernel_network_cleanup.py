from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from binance_lob.kernel_network_cleanup import verify_kernel_network_cleanup
from binance_lob.kernel_network_etw import KernelNetworkEtwCorruption, SELECTED_EVENT_IDS


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


class KernelNetworkCleanupTests(unittest.TestCase):
    def _fixture(self, root: Path) -> None:
        etl = b"aborted-but-flushed-etl"
        ready = {
            "schema": "KernelNetworkTraceReadyV1",
            "status": "READY",
            "session_name": "BinanceKernelNetwork_0123456789ab",
            "etl_path": str((root / "kernel-network.etl").resolve()),
            "stop_file": str((root / "stop.request").resolve()),
            "event_ids": list(SELECTED_EVENT_IDS),
            "match_any_keyword": "0x0000000000000030",
            "statistics": {"number_of_buffers": 4, "free_buffers": 3, "events_lost": 0, "buffers_written": 1, "log_buffers_lost": 0, "realtime_buffers_lost": 0},
        }
        stdout = _json_bytes(ready)
        stderr = b""
        cleanup = {
            "schema": "KernelNetworkTraceAbortCleanupV1",
            "status": "PASS",
            "trigger": "INJECTED_CONTROLLER_ABORT_AFTER_READY",
            "outcome": "STOPPED_BY_WRAPPER",
            "session_name": ready["session_name"],
            "controller_pid": 42,
            "controller_has_exited": True,
            "controller_exit_code": 0xE701,
            "termination_requested_exit_code": 0xE701,
            "termination_observed_exit_code": 0xE701,
            "controller_stdout_file": "controller.stdout.jsonl",
            "controller_stdout_bytes": len(stdout),
            "controller_stdout_sha256": sha256(stdout).hexdigest(),
            "controller_stderr_file": "controller.stderr.txt",
            "controller_stderr_bytes": 0,
            "controller_stderr_sha256": sha256(stderr).hexdigest(),
            "etl_file": "kernel-network.etl",
            "etl_bytes": len(etl),
            "etl_sha256": sha256(etl).hexdigest(),
            "orphan_observed_before_cleanup": True,
            "cleanup_attempted": True,
            "cleanup_exit_code": 0,
            "cleanup_output": ["stopped"],
            "post_cleanup_query_exit_code": 1,
            "post_cleanup_query_output": ["not found"],
        }
        failure = {
            "schema": "KernelNetworkTraceWrapperFailureV1",
            "status": "FAILED",
            "message": "Injected controller abort cleanup qualification completed; normal PASS is forbidden.",
        }
        (root / "controller.stdout.jsonl").write_bytes(stdout)
        (root / "controller.stderr.txt").write_bytes(stderr)
        (root / "kernel-network.etl").write_bytes(etl)
        (root / "abort-cleanup.json").write_bytes(_json_bytes(cleanup))
        (root / "wrapper-failure.json").write_bytes(_json_bytes(failure))

    def test_injected_abort_cleanup_passes_without_false_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            self._fixture(root)
            result = verify_kernel_network_cleanup(root)
            self.assertEqual(result["status"], "PASS")
            self.assertFalse(result["orphan_session_after_cleanup"])
            self.assertFalse(result["false_pass"])

    def test_etl_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            self._fixture(root)
            path = root / "kernel-network.etl"
            path.write_bytes(path.read_bytes() + b"x")
            with self.assertRaises(KernelNetworkEtwCorruption):
                verify_kernel_network_cleanup(root)

    def test_platform_already_absent_after_abort_is_safe_and_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            self._fixture(root)
            path = root / "abort-cleanup.json"
            cleanup = json.loads(path.read_text())
            cleanup["outcome"] = "ALREADY_ABSENT_AFTER_ABORT"
            cleanup["orphan_observed_before_cleanup"] = False
            cleanup["cleanup_attempted"] = False
            cleanup["cleanup_exit_code"] = None
            cleanup["cleanup_output"] = []
            path.write_bytes(_json_bytes(cleanup))
            result = verify_kernel_network_cleanup(root)
            self.assertEqual(result["cleanup_outcome"], "ALREADY_ABSENT_AFTER_ABORT")

    def test_false_pass_terminal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            self._fixture(root)
            path = root / "wrapper-failure.json"
            failure = json.loads(path.read_text())
            failure["status"] = "PASS"
            path.write_bytes(_json_bytes(failure))
            with self.assertRaises(KernelNetworkEtwCorruption):
                verify_kernel_network_cleanup(root)


if __name__ == "__main__":
    unittest.main()
