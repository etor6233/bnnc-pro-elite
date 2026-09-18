from __future__ import annotations

import unittest

from binance_lob.network_incident import _classify


def _transport(*classifications: str):
    return [{"streams": [{"classification": value} for value in classifications]}]


def _witness(classification: str, within: bool = True):
    return {"classification": classification, "within_sampling_tolerance": within}


class NetworkIncidentClassificationTests(unittest.TestCase):
    def test_clean_input_claims_no_transport_failure_only(self) -> None:
        self.assertEqual(
            _classify(_transport("CLEAN_CLIENT_STOP", "CLEAN_CLIENT_STOP"), None),
            "NO_TRANSPORT_FAILURE_IN_SUPPLIED_GENERATIONS",
        )

    def test_direct_socket_events_take_precedence_over_probe_inference(self) -> None:
        self.assertEqual(
            _classify(_transport("WEBSOCKET_CLOSE_FRAME_OBSERVED"), _witness("SHARED_PATH_FAILURE_FROM_THIS_HOST")),
            "WEBSOCKET_CLOSE_FRAME_AT_APPLICATION_BOUNDARY",
        )
        self.assertEqual(
            _classify(_transport("SOCKET_READ_ERROR_OBSERVED"), _witness("SHARED_PATH_FAILURE_FROM_THIS_HOST")),
            "SOCKET_READ_ERROR_AT_APPLICATION_BOUNDARY",
        )

    def test_silence_correlation_matrix_remains_single_host_scoped(self) -> None:
        cases = {
            "LOCAL_INTERFACE_OR_ROUTE_UNAVAILABLE": "CORRELATED_LOCAL_INTERFACE_OR_ROUTE_FAILURE_FROM_THIS_HOST",
            "SHARED_PATH_FAILURE_FROM_THIS_HOST": "CORRELATED_SHARED_PATH_FAILURE_FROM_THIS_HOST",
            "BINANCE_PATH_SPECIFIC_TCP_FAILURE_FROM_THIS_HOST": "CORRELATED_BINANCE_PATH_SPECIFIC_FAILURE_FROM_THIS_HOST",
            "BINANCE_DNS_UNAVAILABLE_INTERNET_TCP_REACHABLE": "CORRELATED_BINANCE_DNS_FAILURE_FROM_THIS_HOST",
            "BINANCE_AND_INDEPENDENT_TCP_REACHABLE": "SOCKET_SILENCE_WHILE_NEW_TCP_PROBES_WERE_REACHABLE",
        }
        for witness, expected in cases.items():
            with self.subTest(witness=witness):
                self.assertEqual(
                    _classify(_transport("TRANSPORT_SILENCE_WITH_LOCAL_TCP_ESTABLISHED"), _witness(witness)),
                    expected,
                )

    def test_stale_or_absent_witness_cannot_narrow_silence(self) -> None:
        expected = "TRANSPORT_SILENCE_CAUSE_UNRESOLVED_AT_OBSERVED_BOUNDARIES"
        self.assertEqual(_classify(_transport("TRANSPORT_SILENCE_WITHOUT_LOCAL_ESTABLISHED_PROOF"), None), expected)
        self.assertEqual(
            _classify(
                _transport("TRANSPORT_SILENCE_WITH_LOCAL_TCP_ESTABLISHED"),
                _witness("LOCAL_INTERFACE_OR_ROUTE_UNAVAILABLE", within=False),
            ),
            expected,
        )


if __name__ == "__main__":
    unittest.main()

