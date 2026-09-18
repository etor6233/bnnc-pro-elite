from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from binance_lob.hot_redundant import (
    HotRedundantCorruption,
    _JOURNAL_BODY_KEYS,
    _decode,
    _safe_campaign,
    _scan_journal,
)


def _compact(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


class HotRedundantIndependentVerifierTests(unittest.TestCase):
    def test_duplicate_json_property_is_rejected(self) -> None:
        with self.assertRaises(HotRedundantCorruption):
            _decode(b'{"schema":"A","schema":"B"}', "duplicate")

    def test_supervisor_journal_round_trip_and_one_byte_mutation(self) -> None:
        body = {
            "schema": "HotRedundantJournalRecordV1",
            "record_index": 0,
            "wall_ns": 10,
            "supervisor_mono_ns": 5,
            "channel": "SUPERVISOR",
            "payload": {"event": "TEST"},
            "previous_record_sha256": "0" * 64,
        }
        envelope = {
            "body": body,
            "record_sha256": sha256(_compact(body)).hexdigest(),
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "supervisor-events.jsonl"
            path.write_bytes(_compact(envelope) + b"\n")
            records = _scan_journal(
                path, _JOURNAL_BODY_KEYS, "HotRedundantJournalRecordV1"
            )
            self.assertEqual(records[0]["record_sha256"], envelope["record_sha256"])
            mutated = bytearray(path.read_bytes())
            offset = mutated.index(b"TEST")
            mutated[offset] ^= 1
            path.write_bytes(mutated)
            with self.assertRaises(HotRedundantCorruption):
                _scan_journal(
                    path, _JOURNAL_BODY_KEYS, "HotRedundantJournalRecordV1"
                )

    def test_campaign_path_cannot_escape_or_use_windows_separator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            campaign_id = "1-BTCUSDT-raw-abcdef123456"
            (root / "p" / campaign_id).mkdir(parents=True)
            self.assertEqual(
                _safe_campaign(root, f"p/{campaign_id}", campaign_id, "PRIMARY"),
                (root / "p" / campaign_id).resolve(),
            )
            for relative in (f"p\\{campaign_id}", f"p/../{campaign_id}"):
                with self.subTest(relative=relative):
                    with self.assertRaises(HotRedundantCorruption):
                        _safe_campaign(root, relative, campaign_id, "PRIMARY")


if __name__ == "__main__":
    unittest.main()
