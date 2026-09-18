from __future__ import annotations

from datetime import datetime, timezone
import unittest

from binance_lob.kernel_network_websocket import (
    KernelNetworkWebSocketCorruption,
    _correlate_websocket_attempts,
    _strict_ip_list,
)


def _event(event_id: int, pid: int, source_port: int, destination: str) -> dict[str, object]:
    return {
        "event_id": event_id,
        "process_id": pid,
        "system_time": "2026-08-30T17:00:01+00:00",
        "fields": {
            "saddr": "192.0.2.10" if ":" not in destination else "2001:db8::10",
            "sport": str(source_port),
            "daddr": destination,
            "dport": "443",
        },
    }


class KernelNetworkWebSocketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.started = datetime(2026, 8, 30, 17, 0, 0, tzinfo=timezone.utc)
        self.completed = datetime(2026, 8, 30, 17, 0, 30, tzinfo=timezone.utc)

    def test_two_distinct_ipv4_attempts_pass(self) -> None:
        events = [_event(12, 42, 50001, "198.51.100.20"), _event(12, 42, 50002, "198.51.100.20")]
        attempts, endpoints = _correlate_websocket_attempts(
            events, 42, ["198.51.100.20"], self.started, self.completed
        )
        self.assertEqual(len(attempts), 2)
        self.assertEqual(len(endpoints), 2)

    def test_ipv4_and_ipv6_attempts_are_supported(self) -> None:
        events = [_event(12, 42, 50001, "198.51.100.20"), _event(28, 42, 50002, "2001:db8::20")]
        attempts, _ = _correlate_websocket_attempts(
            events,
            42,
            ["198.51.100.20", "2001:db8::20"],
            self.started,
            self.completed,
        )
        self.assertEqual({event["event_id"] for event in attempts}, {12, 28})

    def test_server_side_accept_events_do_not_satisfy_client_contract(self) -> None:
        events = [_event(15, 42, 50001, "198.51.100.20"), _event(31, 42, 50002, "198.51.100.20")]
        with self.assertRaises(KernelNetworkWebSocketCorruption):
            _correlate_websocket_attempts(
                events, 42, ["198.51.100.20"], self.started, self.completed
            )

    def test_wrong_pid_or_dns_is_rejected(self) -> None:
        events = [_event(12, 43, 50001, "198.51.100.20"), _event(12, 43, 50002, "198.51.100.20")]
        with self.assertRaises(KernelNetworkWebSocketCorruption):
            _correlate_websocket_attempts(
                events, 42, ["198.51.100.20"], self.started, self.completed
            )

    def test_dns_inventory_must_be_canonical_sorted_and_unique(self) -> None:
        self.assertEqual(_strict_ip_list(["198.51.100.20", "2001:db8::20"]), ["198.51.100.20", "2001:db8::20"])
        with self.assertRaises(KernelNetworkWebSocketCorruption):
            _strict_ip_list(["2001:0db8::20"])


if __name__ == "__main__":
    unittest.main()
