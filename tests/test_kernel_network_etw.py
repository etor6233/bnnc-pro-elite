from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from binance_lob.kernel_network_etw import (
    KernelNetworkEtwCorruption,
    SELECTED_EVENT_IDS,
    _parse_kernel_events,
    verify_kernel_network_etw,
)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


class KernelNetworkEtwTests(unittest.TestCase):
    def _fixture(self, root: Path) -> None:
        inner_root = root.parent / "inner"
        inner_root.mkdir()
        faults = [{
            "name": "ABORTIVE_RST",
            "status": "PASS",
            "port": 40123,
            "client_port": 40122,
            "process_id": 42,
            "started_utc": "2026-08-29T19:59:59.900000+00:00",
            "completed_utc": "2026-08-29T20:00:00.100000+00:00",
        }]
        inner = {"schema": "RawQualificationNetworkTraceFaultSmokeV1", "status": "PASS", "faults": faults}
        inner_path = inner_root / "fault-smoke.json"
        inner_bytes = _json_bytes(inner)
        inner_path.write_bytes(inner_bytes)

        etl = b"synthetic-etl"
        xml = b'''<Events xmlns:e="urn:unused"><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Network" Guid="{7dd42a49-5329-4832-8dfd-43d979153a88}"/><EventID>12</EventID><TimeCreated SystemTime="2026-08-29T20:00:00+00:00"/><Execution ProcessID="42"/></System><EventData><Data Name="PID">42</Data><Data Name="saddr">127.0.0.1</Data><Data Name="daddr">127.0.0.1</Data><Data Name="sport">40122</Data><Data Name="dport">40123</Data></EventData></Event></Events>'''
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
        seal = {
            "schema": "KernelNetworkTraceSealV1",
            "status": "SEALED",
            "session_name": "BinanceKernelNetwork_0123456789ab",
            "etl_path": str((root / "kernel-network.etl").resolve()),
            "stop_reason": "STOP_FILE",
            "elapsed_ms": 1000,
            "statistics": {"number_of_buffers": 4, "free_buffers": 4, "events_lost": 0, "buffers_written": 2, "log_buffers_lost": 0, "realtime_buffers_lost": 0},
        }
        stdout = _json_bytes(ready) + _json_bytes(seal)
        report = {
            "schema": "KernelNetworkTraceFaultSmokeV1",
            "run_id": "etw-fault-0123456789ab",
            "status": "PASS",
            "started_utc": "2026-08-29T19:59:59+00:00",
            "completed_utc": "2026-08-29T20:00:01+00:00",
            "controller_executable": "C:\\fixture\\kernel_network_trace.exe",
            "controller_sha256": "a" * 64,
            "session_name": "BinanceKernelNetwork_0123456789ab",
            "controller_records": [ready, seal],
            "controller_stderr_bytes": 0,
            "etl_file": "kernel-network.etl",
            "etl_bytes": len(etl),
            "etl_sha256": sha256(etl).hexdigest(),
            "decoded_file": "kernel-network.xml",
            "decoded_bytes": len(xml),
            "decoded_sha256": sha256(xml).hexdigest(),
            "tracerpt_exit_code": 0,
            "tracerpt_output": ["success"],
            "orphan_query_exit_code": 1,
            "orphan_query_output": ["not found"],
            "deterministic_fault_evidence_root": str(inner_root),
            "deterministic_fault_report": str(inner_path),
            "deterministic_fault_report_sha256": sha256(inner_bytes).hexdigest(),
            "deterministic_faults": faults,
            "selected_event_ids": list(SELECTED_EVENT_IDS),
            "raw_packet_payload_capture": False,
            "correlation_status": "OPEN_PENDING_SEMANTIC_DECODE",
        }
        (root / "controller.stdout.jsonl").write_bytes(stdout)
        (root / "controller.stderr.txt").write_bytes(b"")
        (root / "stop.request").write_bytes(b"")
        (root / "kernel-network.etl").write_bytes(etl)
        (root / "kernel-network.xml").write_bytes(xml)
        (root / "fault-smoke.json").write_bytes(_json_bytes(report))

    def test_exact_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            self._fixture(root)
            report = verify_kernel_network_etw(root)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["selected_event_counts"], {"12": 1})
            self.assertEqual(report["correlation_status"], "EXACT_PID_ENDPOINT_TIME_CORRELATION_PASS")

    def test_kernel_header_pid_zero_uses_manifest_payload_pid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            self._fixture(root)
            xml_path = root / "kernel-network.xml"
            data = xml_path.read_bytes().replace(b'ProcessID="42"', b'ProcessID="0"')
            xml_path.write_bytes(data)
            report_path = root / "fault-smoke.json"
            report = json.loads(report_path.read_text())
            report["decoded_bytes"] = len(data)
            report["decoded_sha256"] = sha256(data).hexdigest()
            report_path.write_bytes(_json_bytes(report))
            self.assertEqual(verify_kernel_network_etw(root)["status"], "PASS")

    def test_nonzero_header_pid_is_context_not_provider_payload_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            self._fixture(root)
            xml_path = root / "kernel-network.xml"
            data = xml_path.read_bytes().replace(b'ProcessID="42"', b'ProcessID="43"')
            xml_path.write_bytes(data)
            report_path = root / "fault-smoke.json"
            report = json.loads(report_path.read_text())
            report["decoded_bytes"] = len(data)
            report["decoded_sha256"] = sha256(data).hexdigest()
            report_path.write_bytes(_json_bytes(report))
            report = verify_kernel_network_etw(root)
            self.assertEqual(report["status"], "PASS")

    def test_missing_provider_payload_pid_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            self._fixture(root)
            xml_path = root / "kernel-network.xml"
            data = xml_path.read_bytes().replace(b'<Data Name="PID">42</Data>', b"")
            xml_path.write_bytes(data)
            report_path = root / "fault-smoke.json"
            report = json.loads(report_path.read_text())
            report["decoded_bytes"] = len(data)
            report["decoded_sha256"] = sha256(data).hexdigest()
            report_path.write_bytes(_json_bytes(report))
            with self.assertRaises(KernelNetworkEtwCorruption):
                verify_kernel_network_etw(root)

    def test_manifest_defined_event_17_without_pid_is_preserved_not_correlated(self) -> None:
        xml = b'''<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Network" Guid="{7dd42a49-5329-4832-8dfd-43d979153a88}"/><EventID>17</EventID><TimeCreated SystemTime="2026-08-31T21:22:27.4752898+00:00"/><Execution ProcessID="58416"/></System><EventData><Data Name="Proto">6</Data><Data Name="FailureCode">3</Data></EventData></Event></Events>'''
        events = _parse_kernel_events(xml)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], 17)
        self.assertEqual(events[0]["header_process_id"], 58416)
        self.assertIsNone(events[0]["payload_process_id"])
        self.assertIsNone(events[0]["process_id"])
        self.assertEqual(events[0]["fields"], {"Proto": "6", "FailureCode": "3"})

    def test_event_17_rejects_a_forged_or_malformed_payload_schema(self) -> None:
        xml = b'''<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Network" Guid="{7dd42a49-5329-4832-8dfd-43d979153a88}"/><EventID>17</EventID><TimeCreated SystemTime="2026-08-31T21:22:27.4752898+00:00"/><Execution ProcessID="58416"/></System><EventData><Data Name="Proto">6</Data><Data Name="FailureCode">not-a-number</Data></EventData></Event></Events>'''
        with self.assertRaises(KernelNetworkEtwCorruption):
            _parse_kernel_events(xml)

    def test_excluded_event_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            self._fixture(root)
            xml_path = root / "kernel-network.xml"
            data = xml_path.read_bytes().replace(b"<EventID>12</EventID>", b"<EventID>10</EventID>")
            xml_path.write_bytes(data)
            report_path = root / "fault-smoke.json"
            report = json.loads(report_path.read_text())
            report["decoded_bytes"] = len(data)
            report["decoded_sha256"] = sha256(data).hexdigest()
            report_path.write_bytes(_json_bytes(report))
            with self.assertRaises(KernelNetworkEtwCorruption):
                verify_kernel_network_etw(root)

    def test_one_byte_etl_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            self._fixture(root)
            etl = root / "kernel-network.etl"
            data = bytearray(etl.read_bytes())
            data[0] ^= 1
            etl.write_bytes(data)
            with self.assertRaises(KernelNetworkEtwCorruption):
                verify_kernel_network_etw(root)

    def test_nonzero_loss_is_rejected_even_if_outer_report_remains_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            self._fixture(root)
            stdout_path = root / "controller.stdout.jsonl"
            records = [json.loads(line) for line in stdout_path.read_text().splitlines()]
            records[1]["statistics"]["events_lost"] = 1
            stdout_path.write_bytes(_json_bytes(records[0]) + _json_bytes(records[1]))
            report_path = root / "fault-smoke.json"
            report = json.loads(report_path.read_text())
            report["controller_records"] = records
            report_path.write_bytes(_json_bytes(report))
            with self.assertRaises(KernelNetworkEtwCorruption):
                verify_kernel_network_etw(root)


if __name__ == "__main__":
    unittest.main()
