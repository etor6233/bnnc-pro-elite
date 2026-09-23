"""Window-oracle tests. Fake nested replays isolate the service envelope;
real artifact replay remains covered by kernel/network tests and elevated gates.
"""
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from binance_lob import hot_service as service


ORIGIN = 1_788_120_000_000_000_000
SECOND = 1_000_000_000


def stamp(value):
    return datetime.fromtimestamp(value / SECOND, timezone.utc).isoformat()


class ObserverWindowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.observers = {"kernel_network": [], "network_witness": []}
        self.records = []
        self.replays = {}
        # Three windows, two handovers; no use of production selection logic.
        for epoch, (ready, stop) in enumerate(((5, 40), (35, 70), (65, 100)), 1):
            for kind, folder, identity in (("kernel_network", "kernel", "run_id"),
                                           ("network_witness", "network", "observation_id")):
                start = ORIGIN + (ready - 1) * SECOND
                ready_ns, stop_ns = ORIGIN + ready * SECOND, ORIGIN + stop * SECOND
                artifact = self.root / f"obs/epochs/{epoch:06d}/{folder}"
                artifact.mkdir(parents=True)
                observer_id = f"observed-{epoch:012x}"
                report = {"status": "PASS", identity: observer_id}
                self.replays[str(artifact)] = report
                report_path = self.root / f"verification/observers/{epoch:06d}/{folder}.json"
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_data = json.dumps(report).encode()
                report_path.write_bytes(report_data)
                item = dict(zip(service.OBSERVER_WINDOW_KEYS + (identity,), (
                    epoch, artifact.relative_to(self.root).as_posix(), start,
                    ready_ns, stop_ns, stop_ns + SECOND,
                    report_path.relative_to(self.root).as_posix(), sha256(report_data).hexdigest(), observer_id,
                )))
                self.observers[kind].append(item)
                if kind == "kernel_network":
                    capture = {"started_utc": stamp(start), "completed_utc": stamp(stop_ns + SECOND),
                               "controller_records": [{"stop_reason": "STOP_FILE"}]}
                    (artifact / "kernel-network-capture.json").write_text(json.dumps(capture))
                else:
                    (artifact / "network-witness-startup.json").write_text(json.dumps({"started_utc": stamp(start)}))
                    (artifact / "network-witness-seal.json").write_text(json.dumps({
                        "finished_utc": stamp(stop_ns + SECOND), "stop_reason": "STOP_FILE"}))
        self.rebuild_events()
        for name in ("verify_kernel_network_production", "verify_network_witness"):
            mocked = patch.object(service, name, side_effect=lambda root: self.replays[str(root)])
            mocked.start()
            self.addCleanup(mocked.stop)

    def rebuild_events(self):
        timed = [(ORIGIN + 10 * SECOND, {"event": "OBSERVER_CAPTURE_INTERVAL_STARTED"}),
                 (ORIGIN + 95 * SECOND, {"event": "OBSERVER_CAPTURE_INTERVAL_ENDED"}),
                 (ORIGIN + 12 * SECOND, {"event": "SYMBOL_EPOCH_LAUNCHED", "symbol": "BTCUSDT", "epoch": 1}),
                 (ORIGIN + 93 * SECOND, {"event": "SYMBOL_FINAL_EPOCH_EXITED", "symbol": "BTCUSDT", "epoch": 1})]
        for kind, items in self.observers.items():
            for item in items:
                for event, clock, fields in (
                    ("OBSERVER_WINDOW_READY", "ready_wall_ns", ("artifact_root", "started_wall_ns", "ready_wall_ns")),
                    ("OBSERVER_WINDOW_STOP_REQUESTED", "stop_requested_wall_ns", ("stop_requested_wall_ns",)),
                    ("OBSERVER_WINDOW_SEALED", "terminal_wall_ns", ("terminal_wall_ns", "verification_path", "verification_sha256")),
                ):
                    timed.append((item[clock], {"event": event, "kind": kind, "epoch": item["epoch"],
                                              **{key: item[key] for key in fields}}))
        self.records = [{"body": {"wall_ns": wall, "payload": payload}}
                        for wall, payload in sorted(timed, key=lambda item: item[0])]

    def verify(self):
        return service._verify_observer_windows(self.root, self.observers, self.records, skipped=False)

    def test_three_windows_cover_two_rotations(self):
        result = self.verify()
        self.assertEqual((result["status"], result["windows"]), ("COMPLETE", 3))
        self.assertEqual(result["required_end_wall_ns"], ORIGIN + 95 * SECOND)

    def test_deadline_before_capture_end_is_rejected(self):
        # Exact historical failure shape: observers end while capture continues.
        for items in self.observers.values():
            items[-1]["stop_requested_wall_ns"] = ORIGIN + 90 * SECOND
        self.rebuild_events()
        with self.assertRaisesRegex(service.HotServiceCorruption, "ends before capture"):
            self.verify()

    def test_declared_coverage_cannot_hide_capture_before_or_after_it(self):
        for record in self.records:
            event = record["body"]["payload"]["event"]
            if event == "SYMBOL_EPOCH_LAUNCHED":
                record["body"]["wall_ns"] = ORIGIN
            elif event == "SYMBOL_FINAL_EPOCH_EXITED":
                record["body"]["wall_ns"] = ORIGIN + 110 * SECOND
        self.records.sort(key=lambda row: row["body"]["wall_ns"])
        with self.assertRaisesRegex(service.HotServiceCorruption, "capture lifecycle"):
            self.verify()

    def test_missing_supervisor_exit_cannot_claim_complete_coverage(self):
        self.records = [record for record in self.records
                        if record["body"]["payload"]["event"] != "SYMBOL_FINAL_EPOCH_EXITED"]
        with self.assertRaisesRegex(service.HotServiceCorruption, "capture lifecycle"):
            self.verify()

    def test_one_nanosecond_gap_is_not_filled_by_timestamp_tolerance(self):
        for items in self.observers.values():
            items[1]["ready_wall_ns"] = items[0]["stop_requested_wall_ns"] + 1
        self.rebuild_events()
        with self.assertRaisesRegex(service.HotServiceCorruption, "coverage has a gap"):
            self.verify()

    def test_omitting_middle_window_from_terminal_is_rejected(self):
        for items in self.observers.values():
            items.pop(1)
        with self.assertRaises(service.HotServiceCorruption):
            self.verify()

    def test_omitting_last_window_and_its_events_still_checks_disk(self):
        for items in self.observers.values():
            items.pop()
        self.rebuild_events()
        with self.assertRaisesRegex(service.HotServiceCorruption, "on-disk"):
            self.verify()

    def test_journal_disagreement_or_missing_seal_is_rejected(self):
        for record in self.records:
            if record["body"]["payload"]["event"] == "OBSERVER_WINDOW_SEALED":
                record["body"]["payload"]["verification_sha256"] = "0" * 64
                break
        with self.assertRaisesRegex(service.HotServiceCorruption, "differs from the service journal"):
            self.verify()

    def test_report_mutation_is_rejected(self):
        report = self.root / self.observers["kernel_network"][0]["verification_path"]
        report.write_bytes(report.read_bytes().replace(b"PASS", b"FAIL"))
        with self.assertRaisesRegex(service.HotServiceCorruption, "digest disagrees"):
            self.verify()

    def test_replay_disagreement_is_rejected(self):
        self.replays[str(self.root / self.observers["network_witness"][0]["artifact_root"])]["status"] = "FAIL"
        with self.assertRaisesRegex(service.HotServiceCorruption, "independent replay"):
            self.verify()

    def test_observer_stopping_by_deadline_is_not_complete_coverage(self):
        target = self.root / self.observers["network_witness"][0]["artifact_root"] / "network-witness-seal.json"
        seal = json.loads(target.read_text())
        seal["stop_reason"] = "DEADLINE"
        target.write_text(json.dumps(seal))
        with self.assertRaisesRegex(service.HotServiceCorruption, "stopped before"):
            self.verify()

    def test_claimed_lifetime_after_independent_seal_is_rejected(self):
        target = self.root / self.observers["kernel_network"][-1]["artifact_root"] / "kernel-network-capture.json"
        capture = json.loads(target.read_text())
        capture["completed_utc"] = stamp(ORIGIN + 80 * SECOND)
        target.write_text(json.dumps(capture))
        with self.assertRaisesRegex(service.HotServiceCorruption, "sealed lifetime"):
            self.verify()

    def test_skip_cannot_promote_windows(self):
        with self.assertRaises(service.HotServiceCorruption):
            service._verify_observer_windows(self.root, self.observers, self.records, skipped=True)
        self.assertEqual(service._verify_observer_windows(self.root, {
            "kernel_network": [], "network_witness": []}, [], skipped=True)["status"], "SKIPPED_NOT_ELEVATED")

    def test_duplicate_event_and_unknown_timezone_rejected(self):
        self.records.append(deepcopy(self.records[0]))
        with self.assertRaisesRegex(service.HotServiceCorruption, "duplicated"):
            self.verify()
        with self.assertRaisesRegex(service.HotServiceCorruption, "timezone"):
            service._utc_ns("2026-09-22T00:00:00", "bad clock")


if __name__ == "__main__":
    unittest.main()
