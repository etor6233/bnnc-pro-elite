from __future__ import annotations

from collections import OrderedDict
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from binance_lob.system_evidence import (
    APPLICATION_PROVIDERS,
    SYSTEM_PROVIDERS,
    SystemEvidenceCorruption,
    verify_system_evidence,
)


def _write(path: Path, value: OrderedDict[str, object]) -> bytes:
    data = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    path.write_bytes(data)
    return data


def _fixture(root: Path, *, complete: bool = True) -> None:
    run_id = "system-test-0001"
    event_xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="Microsoft-Windows-TCPIP"/><EventID>1001</EventID>'
        '<Level>4</Level><TimeCreated SystemTime="2026-08-29T00:05:00.0000000Z"/>'
        '<EventRecordID>42</EventRecordID><Execution ProcessID="123" ThreadID="456"/>'
        '</System><EventData/></Event>'
    )
    system_event = OrderedDict([
        ("log_name", "System"), ("provider_name", "Microsoft-Windows-TCPIP"),
        ("event_id", 1001), ("level", 4), ("record_id", 42),
        ("time_created_utc", "2026-08-29T00:05:00+00:00"),
        ("process_id", 123), ("thread_id", 456), ("xml", event_xml),
    ])

    def coverage(log_name: str) -> OrderedDict[str, object]:
        return OrderedDict([
            ("log_name", log_name), ("query_status", "PASS"), ("is_enabled", True),
            ("log_mode", "Circular"), ("maximum_size_bytes", 20 * 1024 * 1024),
            ("record_count", 100),
            ("oldest_available_utc", "2026-08-28T00:00:00+00:00" if complete else "2026-08-29T00:02:00+00:00"),
            ("newest_available_utc", "2026-08-29T00:09:00+00:00"),
            ("requested_start_is_covered", complete), ("error", None),
        ])

    def query(log_name: str, providers: list[str], events: list[object]) -> OrderedDict[str, object]:
        return OrderedDict([
            ("log_name", log_name), ("query_status", "PASS"),
            ("requested_provider_names", providers), ("returned_events", len(events)),
            ("maximum_events", 64), ("result_limit_reached", False),
            ("xml_bytes", sum(len(event["xml"].encode("utf-8")) for event in events)),
            ("errors", []), ("events", events),
        ])

    adapter = OrderedDict([
        ("interface_guid", "{00000000-0000-0000-0000-000000000001}"),
        ("interface_index", 7), ("name", "Ethernet"),
        ("interface_description", "Fixture NIC"), ("status", "Up"),
        ("media_connection_state", "Connected"), ("link_speed", "1 Gbps"),
        ("driver_information", "Driver Date 2026-01-01 Version 1.0 NDIS 6.89"),
        ("driver_file_name", "fixture.sys"), ("driver_version", "1.0"),
        ("driver_date", "2026-01-01T00:00:00+00:00"), ("ndis_version", "6.89"),
        ("connector_present", True), ("virtual", False),
    ])
    evidence = OrderedDict([
        ("schema", "RawQualificationSystemEvidenceV1"), ("run_id", run_id),
        ("status", "COMPLETE" if complete else "INSUFFICIENT_COVERAGE"),
        ("collected_utc", "2026-08-29T00:11:00+00:00"),
        ("collected_qpc_timestamp", 1000), ("qpc_frequency", 10_000_000),
        ("requested_start_utc", "2026-08-29T00:00:00+00:00"),
        ("requested_end_utc", "2026-08-29T00:10:00+00:00"),
        ("maximum_events_per_log", 64), ("maximum_artifact_mib", 4),
        ("collector_pid", 1234), ("computer_name", "fixture-host"),
        ("os_last_boot_utc", "2026-08-28T00:00:00+00:00"),
        ("os_version", "10.0"), ("os_build_number", "26100"),
        ("system_manufacturer", "fixture"), ("system_model", "fixture"),
        ("adapters", [adapter]),
        ("log_coverage", [coverage("System"), coverage("Application")]),
        ("event_queries", [
            query("System", SYSTEM_PROVIDERS, [system_event]),
            query("Application", APPLICATION_PROVIDERS, []),
        ]),
        ("inference_boundary", "retained local evidence only"),
    ])
    evidence_bytes = _write(root / "system-evidence.json", evidence)
    seal = OrderedDict([
        ("schema", "RawQualificationSystemEvidenceSealV1"), ("run_id", run_id),
        ("status", "SEALED"), ("evidence_file", "system-evidence.json"),
        ("evidence_bytes", len(evidence_bytes)),
        ("evidence_sha256", sha256(evidence_bytes).hexdigest()),
        ("sealed_utc", "2026-08-29T00:12:00+00:00"),
    ])
    _write(root / "system-evidence-seal.json", seal)


def _reseal(root: Path) -> None:
    evidence_bytes = (root / "system-evidence.json").read_bytes()
    seal = json.loads((root / "system-evidence-seal.json").read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
    seal["evidence_bytes"] = len(evidence_bytes)
    seal["evidence_sha256"] = sha256(evidence_bytes).hexdigest()
    _write(root / "system-evidence-seal.json", seal)


class SystemEvidenceTests(unittest.TestCase):
    def test_complete_evidence_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            report = verify_system_evidence(root)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["coverage_status"], "COMPLETE")
            self.assertEqual(report["event_count"], 1)

    def test_explicit_insufficient_coverage_passes_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root, complete=False)
            self.assertEqual(verify_system_evidence(root)["coverage_status"], "INSUFFICIENT_COVERAGE")

    def test_one_byte_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            path = root / "system-evidence.json"
            data = bytearray(path.read_bytes())
            data[-2] ^= 1
            path.write_bytes(data)
            with self.assertRaises(SystemEvidenceCorruption):
                verify_system_evidence(root)

    def test_xml_semantic_drift_with_fresh_seal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            path = root / "system-evidence.json"
            evidence = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            evidence["event_queries"][0]["events"][0]["event_id"] = 1002
            _write(path, evidence)
            _reseal(root)
            with self.assertRaises(SystemEvidenceCorruption):
                verify_system_evidence(root)

    def test_false_complete_claim_with_fresh_seal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root, complete=False)
            path = root / "system-evidence.json"
            evidence = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            evidence["status"] = "COMPLETE"
            _write(path, evidence)
            _reseal(root)
            with self.assertRaises(SystemEvidenceCorruption):
                verify_system_evidence(root)

    def test_unknown_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            (root / "unknown.bin").write_bytes(b"x")
            with self.assertRaises(SystemEvidenceCorruption):
                verify_system_evidence(root)


if __name__ == "__main__":
    unittest.main()
