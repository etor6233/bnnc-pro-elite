from __future__ import annotations

from collections import OrderedDict
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from binance_lob.network_trace import NetworkTraceCorruption, verify_network_trace


def _write_json(path: Path, value: OrderedDict[str, object]) -> bytes:
    data = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    path.write_bytes(data)
    return data


def _lines_bytes(lines: list[str]) -> int:
    return len("\n".join(lines).encode("utf-8"))


def _fixture(root: Path, *, version: int = 1, afd_profile: str = "ErrorOnly") -> None:
    run_id = "trace-test-0001"
    etl_path = root / "network-trace.etl"
    etl_bytes = b"synthetic-etl-fixture\x00\x01"
    etl_path.write_bytes(etl_bytes)
    providers = (
        ["Microsoft-Windows-TCPIP"]
        if version == 1
        else [
            "Microsoft-Windows-TCPIP",
            "Microsoft-Windows-DNS-Client",
            "Microsoft-Windows-NDIS",
        ] + (["Microsoft-Windows-Winsock-AFD"] if version >= 3 else [])
        + (["Microsoft-Windows-Kernel-Network"] if version == 5 and afd_profile == "DiagnosticInfo" else [])
    )
    arguments = [
        "start", "--capture", "--comp", "nics", "--type", "drop", "--flags", "0x00F",
        "--trace",
    ]
    for provider in providers:
        arguments.extend(["--provider", provider])
        if version >= 3 and provider == "Microsoft-Windows-Winsock-AFD":
            arguments.extend([
                "--keywords", "0x800000000000000C", "--level",
                "2" if afd_profile == "ErrorOnly" else "4",
            ])
        elif version == 5 and provider == "Microsoft-Windows-Kernel-Network":
            arguments.extend([
                "--keywords", "0x8000000000000030", "--level", "4",
            ])
    arguments.extend(["--file-name", str(etl_path.resolve()), "--file-size", "64", "--log-mode", "circular"])
    control_items: list[tuple[str, object]] = [
        ("schema", f"RawQualificationNetworkTraceControlV{version}"), ("run_id", run_id),
        ("status", "START_ATTEMPTED"), ("requested_utc", "2026-08-29T00:00:00Z"),
        ("requested_qpc_timestamp", 100), ("qpc_frequency", 10_000_000),
        ("owner_pid", 1234),
        (("provider" if version == 1 else "event_providers"),
         (providers[0] if version == 1 else providers)),
    ]
    if version >= 4:
        control_items.extend([
            ("winsock_afd_profile", afd_profile),
            ("winsock_afd_keywords", "0x800000000000000C"),
            ("winsock_afd_level", 2 if afd_profile == "ErrorOnly" else 4),
        ])
    if version == 5:
        kernel_enabled = afd_profile == "DiagnosticInfo"
        control_items.extend([
            ("kernel_network_enabled", kernel_enabled),
            ("kernel_network_keywords", "0x8000000000000030" if kernel_enabled else ""),
            ("kernel_network_level", 4 if kernel_enabled else 0),
        ])
    control_items.extend([
        ("capture_scope", {
            1: "NIC_DROP_METADATA_ONLY",
            2: "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_ETW",
            3: "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_ERROR_ETW",
            4: (
                "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_ERROR_ETW"
                if afd_profile == "ErrorOnly"
                else "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_DIAGNOSTIC_ETW"
            ),
            5: (
                "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_ERROR_ETW"
                if afd_profile == "ErrorOnly"
                else "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_AND_KERNEL_NETWORK_DIAGNOSTIC_ETW"
            ),
        }[version]),
        ("raw_packet_flag", "DISABLED_FLAGS_0x00F"), ("log_mode", "CIRCULAR"),
        ("maximum_file_mib", 64), ("etl_file", "network-trace.etl"),
        ("pktmon_executable", "C:\\Windows\\System32\\pktmon.exe"),
        ("pktmon_executable_sha256", "a" * 64), ("arguments", arguments),
    ])
    control = OrderedDict(control_items)
    control_bytes = _write_json(root / "network-trace-control.json", control)
    start_output = ["Logger Parameters:", "Session is running"]
    status_output = ["Packet Monitor is running"] + (
        [f"Provider: {provider}" for provider in providers] if version >= 2 else []
    )
    start = OrderedDict([
        ("schema", f"RawQualificationNetworkTraceStartV{version}"), ("run_id", run_id),
        ("status", "STARTED"), ("observed_utc", "2026-08-29T00:00:01Z"),
        ("observed_qpc_timestamp", 101), ("control_file", "network-trace-control.json"),
        ("control_sha256", sha256(control_bytes).hexdigest()), ("pktmon_exit_code", 0),
        ("pktmon_output", start_output), ("pktmon_output_bytes", _lines_bytes(start_output)),
        ("status_exit_code", 0), ("status_output", status_output),
        ("status_output_bytes", _lines_bytes(status_output)),
    ])
    start_bytes = _write_json(root / "network-trace-start.json", start)
    stop_output = ["Flushing logs...", "Log file: network-trace.etl"]
    pre_stop = ["Packet Monitor is running"] + (
        [f"Provider: {provider}" for provider in providers] if version >= 2 else []
    )
    seal = OrderedDict([
        ("schema", f"RawQualificationNetworkTraceSealV{version}"), ("run_id", run_id),
        ("status", "SEALED"), ("stopped_utc", "2026-08-29T00:00:05Z"),
        ("control_file", "network-trace-control.json"),
        ("control_sha256", sha256(control_bytes).hexdigest()),
        ("start_file", "network-trace-start.json"),
        ("start_sha256", sha256(start_bytes).hexdigest()), ("etl_file", "network-trace.etl"),
        ("etl_bytes", len(etl_bytes)), ("etl_sha256", sha256(etl_bytes).hexdigest()),
        ("pktmon_executable_sha256", "a" * 64), ("pktmon_exit_code", 0),
        ("pktmon_output", stop_output), ("pktmon_output_bytes", _lines_bytes(stop_output)),
        ("pre_stop_status_exit_code", 0), ("pre_stop_status_output", pre_stop),
        ("pre_stop_status_output_bytes", _lines_bytes(pre_stop)),
        ("inference_boundary", "local boundaries only"),
    ])
    _write_json(root / "network-trace-seal.json", seal)


class NetworkTraceTests(unittest.TestCase):
    def test_exact_sealed_trace_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            report = verify_network_trace(root)
            self.assertEqual(report["status"], "PASS")
            self.assertFalse(report["raw_packet_payload_capture"])

    def test_exact_v2_sealed_trace_passes_with_all_providers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root, version=2)
            report = verify_network_trace(root)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["event_providers"], [
                "Microsoft-Windows-TCPIP",
                "Microsoft-Windows-DNS-Client",
                "Microsoft-Windows-NDIS",
            ])

    def test_exact_v3_sealed_trace_passes_with_error_only_afd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root, version=3)
            report = verify_network_trace(root)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["schema"], "RawQualificationNetworkTraceVerificationV3")
            self.assertEqual(report["event_providers"], [
                "Microsoft-Windows-TCPIP",
                "Microsoft-Windows-DNS-Client",
                "Microsoft-Windows-NDIS",
                "Microsoft-Windows-Winsock-AFD",
            ])

    def test_v3_afd_level_drift_with_fresh_outer_hashes_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root, version=3)
            control_path = root / "network-trace-control.json"
            control = json.loads(control_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            level_index = control["arguments"].index("--level") + 1
            control["arguments"][level_index] = "4"
            control_bytes = _write_json(control_path, control)
            start_path = root / "network-trace-start.json"
            start = json.loads(start_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            start["control_sha256"] = sha256(control_bytes).hexdigest()
            start_bytes = _write_json(start_path, start)
            seal_path = root / "network-trace-seal.json"
            seal = json.loads(seal_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            seal["control_sha256"] = sha256(control_bytes).hexdigest()
            seal["start_sha256"] = sha256(start_bytes).hexdigest()
            _write_json(seal_path, seal)
            with self.assertRaises(NetworkTraceCorruption):
                verify_network_trace(root)

    def test_exact_v4_diagnostic_profile_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root, version=4, afd_profile="DiagnosticInfo")
            report = verify_network_trace(root)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["schema"], "RawQualificationNetworkTraceVerificationV4")
            self.assertIn("DIAGNOSTIC", report["attribution_scope"])

    def test_exact_v5_kernel_network_diagnostic_profile_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root, version=5, afd_profile="DiagnosticInfo")
            report = verify_network_trace(root)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["schema"], "RawQualificationNetworkTraceVerificationV5")
            self.assertIn("Microsoft-Windows-Kernel-Network", report["event_providers"])

    def test_v5_kernel_network_omission_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root, version=5, afd_profile="DiagnosticInfo")
            control_path = root / "network-trace-control.json"
            control = json.loads(control_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            control["event_providers"].pop()
            provider_index = control["arguments"].index("Microsoft-Windows-Kernel-Network") - 1
            del control["arguments"][provider_index:provider_index + 6]
            control_bytes = _write_json(control_path, control)
            start_path = root / "network-trace-start.json"
            start = json.loads(start_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            start["control_sha256"] = sha256(control_bytes).hexdigest()
            start_bytes = _write_json(start_path, start)
            seal_path = root / "network-trace-seal.json"
            seal = json.loads(seal_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            seal["control_sha256"] = sha256(control_bytes).hexdigest()
            seal["start_sha256"] = sha256(start_bytes).hexdigest()
            _write_json(seal_path, seal)
            with self.assertRaises(NetworkTraceCorruption):
                verify_network_trace(root)

    def test_v2_provider_omission_with_fresh_outer_hashes_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root, version=2)
            control_path = root / "network-trace-control.json"
            control = json.loads(control_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            control["event_providers"].pop()
            control["arguments"][13:15] = []
            control_bytes = _write_json(control_path, control)
            start_path = root / "network-trace-start.json"
            start = json.loads(start_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            start["control_sha256"] = sha256(control_bytes).hexdigest()
            start_bytes = _write_json(start_path, start)
            seal_path = root / "network-trace-seal.json"
            seal = json.loads(seal_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            seal["control_sha256"] = sha256(control_bytes).hexdigest()
            seal["start_sha256"] = sha256(start_bytes).hexdigest()
            _write_json(seal_path, seal)
            with self.assertRaises(NetworkTraceCorruption):
                verify_network_trace(root)

    def test_one_byte_etl_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            path = root / "network-trace.etl"
            data = bytearray(path.read_bytes())
            data[-1] ^= 1
            path.write_bytes(data)
            with self.assertRaises(NetworkTraceCorruption):
                verify_network_trace(root)

    def test_semantic_argument_change_with_fresh_outer_hashes_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            control_path = root / "network-trace-control.json"
            control = json.loads(control_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            control["arguments"][7] = "0x01F"
            control_bytes = _write_json(control_path, control)
            start_path = root / "network-trace-start.json"
            start = json.loads(start_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            start["control_sha256"] = sha256(control_bytes).hexdigest()
            start_bytes = _write_json(start_path, start)
            seal_path = root / "network-trace-seal.json"
            seal = json.loads(seal_path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
            seal["control_sha256"] = sha256(control_bytes).hexdigest()
            seal["start_sha256"] = sha256(start_bytes).hexdigest()
            _write_json(seal_path, seal)
            with self.assertRaises(NetworkTraceCorruption):
                verify_network_trace(root)

    def test_unknown_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _fixture(root)
            (root / "unexpected.txt").write_text("x", encoding="utf-8")
            with self.assertRaises(NetworkTraceCorruption):
                verify_network_trace(root)


if __name__ == "__main__":
    unittest.main()
