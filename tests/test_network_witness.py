from __future__ import annotations

from pathlib import Path
from hashlib import sha256
import json
import unittest

from binance_lob.network_witness import (
    NetworkWitnessCorruption,
    classify_network_witness_sample,
    verify_network_witness,
)


class NetworkWitnessTests(unittest.TestCase):
    def test_causal_matrix_never_overattributes_beyond_this_host(self) -> None:
        interface = {"status": "Up", "type": "Ethernet", "gateways": ["192.0.2.1"]}

        def sample(dns: str, binance: str | None, independent: str, *, route: str = "ROUTE_SELECTED", up: bool = True):
            tcp = [{"target": "INDEPENDENT_INTERNET", "status": independent}]
            routes = [{"target": "INDEPENDENT_INTERNET", "status": route}]
            if binance is not None:
                tcp.append({"target": "BINANCE_PUBLIC_STREAM", "status": binance})
                routes.append({"target": "BINANCE_PUBLIC_STREAM", "status": "ROUTE_SELECTED"})
            return {
                "dns": [{"status": dns}],
                "tcp": tcp,
                "routes": routes,
                "interfaces": [interface if up else {**interface, "status": "Down", "gateways": []}],
            }

        cases = (
            (sample("RESOLVED", "CONNECTED", "CONNECTED"), "BINANCE_AND_INDEPENDENT_TCP_REACHABLE"),
            (sample("FAILED", None, "CONNECTED"), "BINANCE_DNS_UNAVAILABLE_INTERNET_TCP_REACHABLE"),
            (sample("RESOLVED", "TIMEOUT", "CONNECTED"), "BINANCE_PATH_SPECIFIC_TCP_FAILURE_FROM_THIS_HOST"),
            (sample("RESOLVED", "CONNECTED", "FAILED"), "INDEPENDENT_WITNESS_FAILURE_BINANCE_TCP_REACHABLE"),
            (sample("RESOLVED", "FAILED", "FAILED", up=False), "LOCAL_INTERFACE_OR_ROUTE_UNAVAILABLE"),
            (sample("RESOLVED", "TIMEOUT", "TIMEOUT"), "SHARED_PATH_FAILURE_FROM_THIS_HOST"),
        )
        for evidence, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(classify_network_witness_sample(evidence), expected)

    def test_real_smoke_fixture_verifies_and_one_byte_mutation_fails(self) -> None:
        fixtures = sorted(
            (Path(__file__).parents[1] / "artifacts" / "witness-smoke").glob("witness-smoke-*/"),
            key=lambda path: path.stat().st_mtime_ns,
        )
        if not fixtures:
            self.skipTest("network witness smoke artifact is unavailable")
        source = fixtures[-1]
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "witness"
            target.mkdir()
            for path in source.iterdir():
                (target / path.name).write_bytes(path.read_bytes())

            startup_path = target / "network-witness-startup.json"
            startup = json.loads(startup_path.read_text(encoding="utf-8"))
            startup["evidence_root"] = str(target.resolve())
            startup_bytes = (json.dumps(startup, ensure_ascii=False, indent=4) + "\n").encode("utf-8")
            startup_path.write_bytes(startup_bytes)
            seal_path = target / "network-witness-seal.json"
            seal = json.loads(seal_path.read_text(encoding="utf-8"))
            seal["startup_sha256"] = sha256(startup_bytes).hexdigest()
            seal_path.write_text(json.dumps(seal, ensure_ascii=False, indent=4) + "\n", encoding="utf-8")

            report = verify_network_witness(target)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["samples"], 1)
            self.assertEqual(report["last_classification"], "BINANCE_AND_INDEPENDENT_TCP_REACHABLE")

            journal = target / "network-witness-events.jsonl"
            damaged = bytearray(journal.read_bytes())
            position = damaged.index(b"BINANCE_PUBLIC_STREAM")
            damaged[position] = ord("X")
            journal.write_bytes(damaged)
            with self.assertRaises(NetworkWitnessCorruption):
                verify_network_witness(target)
