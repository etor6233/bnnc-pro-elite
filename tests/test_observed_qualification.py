from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from binance_lob.observed_qualification import (
    ObservedQualificationCorruption,
    _verify_host_clock_failure_evidence,
    classify_cause_domain,
)


class ObservedQualificationCauseTests(unittest.TestCase):
    def test_observer_failure_has_precedence(self) -> None:
        self.assertEqual(
            classify_cause_domain(observer_failure="ETW_DIED", raw_status="FAILED", incident_classification="SOCKET_READ_ERROR_AT_APPLICATION_BOUNDARY"),
            "OBSERVABILITY_INTERNAL_FAILURE",
        )

    def test_socket_silence_is_external_only_to_capture_process(self) -> None:
        self.assertEqual(
            classify_cause_domain(observer_failure=None, raw_status="FAILED", incident_classification="SOCKET_SILENCE_WHILE_NEW_TCP_PROBES_WERE_REACHABLE"),
            "EXTERNAL_TO_CAPTURE_PROCESS_AT_OBSERVED_SOCKET_BOUNDARY",
        )

    def test_missing_cross_plane_evidence_remains_explicit(self) -> None:
        self.assertEqual(
            classify_cause_domain(observer_failure=None, raw_status="FAILED", incident_classification=None),
            "INDETERMINATE_BECAUSE_CROSS_PLANE_INCIDENT_EVIDENCE_DID_NOT_VERIFY",
        )

    def test_structured_host_clock_failure_is_not_misclassified_as_network(self) -> None:
        self.assertEqual(
            classify_cause_domain(
                observer_failure=None,
                raw_status="FAILED",
                raw_failure="HOST_CLOCK_HEALTH_GATE_FAILED: violations=LAST_SYNC_ERROR_NONZERO",
                incident_classification=None,
            ),
            "HOST_TIME_SYNCHRONIZATION_FAILURE",
        )

    def test_legacy_generic_clock_failure_is_not_reinterpreted(self) -> None:
        self.assertEqual(
            classify_cause_domain(
                observer_failure=None,
                raw_status="FAILED",
                raw_failure="Windows Time is not Leap0/stratum 1..15/non-local/StateMachine Sync/Error0/recent-last-good.",
                incident_classification=None,
            ),
            "INDETERMINATE_BECAUSE_CROSS_PLANE_INCIDENT_EVIDENCE_DID_NOT_VERIFY",
        )

    def test_clean_completion_has_no_failure_domain(self) -> None:
        self.assertEqual(
            classify_cause_domain(observer_failure=None, raw_status="COMPLETE", incident_classification=None),
            "NONE",
        )

    def test_clock_failure_evidence_is_bound_and_mutation_fails(self) -> None:
        clock = {
            "healthy": False,
            "leap_indicator": 0,
            "stratum": 2,
            "source": "time.nist.gov,0x8",
            "last_successful_sync": "2026-08-31T10:00:00Z",
            "root_delay_s": 0.1,
            "root_dispersion_s": 0.01,
            "phase_offset_s": 0.001,
            "seconds_since_last_good_sync": 5.0,
            "maximum_last_good_sync_age_s": 21600.0,
            "state_machine": 2,
            "last_sync_error": 2,
            "poll_interval_s": 64,
            "raw_status_sha256": "b" * 64,
            "query_exit_code": 0,
        }
        provider = json.dumps(
            {"schema": "RawQualificationTelemetryProbeV1", "clock": clock},
            separators=(",", ":"),
        ).encode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probes = root / "host-probes"
            probes.mkdir()
            stdout = probes / "host-000007.stdout.json"
            stderr = probes / "host-000007.stderr.log"
            stdout.write_bytes(provider)
            stderr.write_bytes(b"")
            evidence = {
                "stdout_path": "host-probes/host-000007.stdout.json",
                "stdout_bytes": len(provider),
                "stdout_sha256": sha256(provider).hexdigest(),
                "stderr_path": "host-probes/host-000007.stderr.log",
                "stderr_bytes": 0,
                "stderr_sha256": sha256(b"").hexdigest(),
            }
            failure = (
                "HOST_CLOCK_HEALTH_GATE_FAILED: violations=LAST_SYNC_ERROR_NONZERO; observation="
                + json.dumps(clock, separators=(",", ":"))
                + "; provider_evidence="
                + json.dumps(evidence, separators=(",", ":"))
            )
            _verify_host_clock_failure_evidence(root, failure)
            stdout.write_bytes(provider + b"\n")
            with self.assertRaises(ObservedQualificationCorruption):
                _verify_host_clock_failure_evidence(root, failure)


if __name__ == "__main__":
    unittest.main()
