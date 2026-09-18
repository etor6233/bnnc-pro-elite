from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import unittest

from binance_lob.kernel_network_etw import SELECTED_EVENT_IDS
from binance_lob.kernel_network_production import (
    KernelNetworkProductionCorruption,
    verify_kernel_network_production,
)


def _line(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


class KernelNetworkProductionTests(unittest.TestCase):
    def _fixture(self, root: Path) -> None:
        session = "BinanceProduction_0123456789ab"
        etl = b"synthetic-etl"
        xml = b'''<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Network" Guid="{7dd42a49-5329-4832-8dfd-43d979153a88}"/><EventID>12</EventID><TimeCreated SystemTime="2026-08-30T20:00:00+00:00"/><Execution ProcessID="0"/></System><EventData><Data Name="PID">42</Data><Data Name="saddr">192.0.2.2</Data><Data Name="daddr">192.0.2.3</Data><Data Name="sport">40122</Data><Data Name="dport">443</Data></EventData></Event></Events>'''
        stats = {"number_of_buffers": 4, "free_buffers": 3, "events_lost": 0, "buffers_written": 1, "log_buffers_lost": 0, "realtime_buffers_lost": 0}
        ready = {
            "schema": "KernelNetworkTraceReadyV1", "status": "READY", "session_name": session,
            "etl_path": str((root / "kernel-network.etl").resolve()),
            "stop_file": str((root / "stop.request").resolve()),
            "event_ids": list(SELECTED_EVENT_IDS), "match_any_keyword": "0x0000000000000030",
            "statistics": stats,
        }
        seal = {
            "schema": "KernelNetworkTraceSealV1", "status": "SEALED", "session_name": session,
            "etl_path": str((root / "kernel-network.etl").resolve()), "stop_reason": "STOP_FILE",
            "elapsed_ms": 1000, "statistics": {**stats, "free_buffers": 4, "buffers_written": 2},
        }
        executable = Path(sys.executable).resolve()
        executable_bytes = executable.read_bytes()
        report = {
            "schema": "KernelNetworkProductionCaptureV1", "run_id": "observed-0123456789ab",
            "status": "CANDIDATE", "started_utc": "2026-08-30T19:59:58+00:00",
            "completed_utc": "2026-08-30T20:00:02+00:00",
            "controller_executable": str(executable), "controller_sha256": sha256(executable_bytes).hexdigest(),
            "controller_pid": 99, "session_name": session, "controller_exit_code": 0,
            "controller_records": [ready, seal], "controller_stderr_file": "controller.stderr.txt",
            "controller_stderr_bytes": 0, "controller_stderr_sha256": sha256(b"").hexdigest(),
            "maximum_file_mib": 16, "deadline_s": 60,
            "etl_file": "kernel-network.etl", "etl_bytes": len(etl), "etl_sha256": sha256(etl).hexdigest(),
            "decoded_file": "kernel-network.xml", "decoded_bytes": len(xml), "decoded_sha256": sha256(xml).hexdigest(),
            "tracerpt_exit_code": 0, "tracerpt_output": ["success"],
            "orphan_query_exit_code": 1, "orphan_query_output": ["not found"],
            "monitored_processes": [
                {"role": "LAUNCHER", "symbol": None, "pid": 41, "interval_start_utc": "2026-08-30T19:59:58+00:00", "interval_end_utc": "2026-08-30T20:00:02+00:00"},
                {"role": "COLLECTOR", "symbol": "BTCUSDT", "pid": 42, "interval_start_utc": "2026-08-30T19:59:59+00:00", "interval_end_utc": "2026-08-30T20:00:01+00:00"},
            ],
            "selected_event_ids": list(SELECTED_EVENT_IDS), "raw_packet_payload_capture": False,
            "diagnostic_only": True, "training_eligible": False,
            "correlation_status": "OPEN_PENDING_INDEPENDENT_VERIFY",
        }
        (root / "controller.stdout.jsonl").write_bytes(_line(ready) + _line(seal))
        (root / "controller.stderr.txt").write_bytes(b"")
        (root / "stop.request").write_bytes(b"")
        (root / "kernel-network.etl").write_bytes(etl)
        (root / "kernel-network.xml").write_bytes(xml)
        (root / "kernel-network-capture.json").write_bytes(_line(report))

    def test_exact_production_lifecycle_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "trace"
            root.mkdir()
            self._fixture(root)
            report = verify_kernel_network_production(root)
            self.assertEqual(report["status"], "PASS")
            collector = next(row for row in report["process_correlations"] if row["role"] == "COLLECTOR")
            self.assertEqual(collector["selected_event_counts"], {"12": 1})

    def test_manifest_defined_unattributable_event_17_does_not_poison_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "trace"
            root.mkdir()
            self._fixture(root)
            xml_path = root / "kernel-network.xml"
            event_17 = b'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Network" Guid="{7dd42a49-5329-4832-8dfd-43d979153a88}"/><EventID>17</EventID><TimeCreated SystemTime="2026-08-30T20:00:00+00:00"/><Execution ProcessID="58416"/></System><EventData><Data Name="Proto">6</Data><Data Name="FailureCode">3</Data></EventData></Event>'''
            data = xml_path.read_bytes().replace(b"</Events>", event_17 + b"</Events>")
            xml_path.write_bytes(data)
            report_path = root / "kernel-network-capture.json"
            report = json.loads(report_path.read_text())
            report["decoded_bytes"] = len(data)
            report["decoded_sha256"] = sha256(data).hexdigest()
            report_path.write_bytes(_line(report))
            verified = verify_kernel_network_production(root)
            self.assertEqual(verified["selected_event_counts"], {"12": 1, "17": 1})
            collector = next(row for row in verified["process_correlations"] if row["role"] == "COLLECTOR")
            self.assertEqual(collector["selected_event_counts"], {"12": 1})

    def test_loss_or_unbound_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "trace"
            root.mkdir()
            self._fixture(root)
            (root / "unexpected.txt").write_text("x")
            with self.assertRaises(KernelNetworkProductionCorruption):
                verify_kernel_network_production(root)

    def test_pid_outside_observed_interval_is_not_correlated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "trace"
            root.mkdir()
            self._fixture(root)
            report_path = root / "kernel-network-capture.json"
            report = json.loads(report_path.read_text())
            report["monitored_processes"][1]["interval_start_utc"] = "2026-08-30T20:01:00+00:00"
            report["monitored_processes"][1]["interval_end_utc"] = "2026-08-30T20:01:01+00:00"
            report_path.write_bytes(_line(report))
            with self.assertRaises(KernelNetworkProductionCorruption):
                verify_kernel_network_production(root)


if __name__ == "__main__":
    unittest.main()
