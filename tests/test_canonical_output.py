from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import struct
import tempfile
import unittest

from binance_lob.canonical_output import MAGIC, scan_canonical_output


HASH = "a" * 64


def _owner(generation: str, epoch: str, token: int, sequence: int) -> dict[str, object]:
    return {
        "generation_id": generation,
        "connection_epoch": epoch,
        "fencing_token": token,
        "last_sequence": sequence,
    }


def _observation(epoch: str, first: int, final: int) -> dict[str, object]:
    return {
        "symbol": "BTCUSDT",
        "stream_kind": "DEPTH",
        "stream": "btcusdt@depth@100ms",
        "connection_epoch": epoch,
        "frame_index": final,
        "first_sequence": first,
        "final_sequence": final,
        "record_sha256": HASH,
        "observation_sha256": HASH,
    }


def _encoded(records: list[dict[str, object]]) -> bytes:
    result = bytearray(MAGIC)
    previous = "0" * 64
    for index, source in enumerate(records):
        record = {
            "schema": "CanonicalOutputRecordV1",
            "record_index": index,
            "symbol": "BTCUSDT",
            "stream_kind": "DEPTH",
            "previous_record_sha256": previous,
            **source,
        }
        body = json.dumps(record, separators=(",", ":"), sort_keys=True).encode()
        digest = sha256(body).digest()
        result.extend(struct.pack(">I", len(body)))
        result.extend(body)
        result.extend(digest)
        previous = digest.hex()
    return bytes(result)


def _valid_records() -> list[dict[str, object]]:
    return [
        {
            "action": "INITIALIZED",
            "owner": _owner("generation-a", "epoch-a", 1, 99),
            "observation": None,
            "ownership_activation_record_sha256": None,
        },
        {
            "action": "OBSERVATION",
            "owner": _owner("generation-a", "epoch-a", 1, 102),
            "observation": _observation("epoch-a", 100, 102),
            "ownership_activation_record_sha256": None,
        },
        {
            "action": "OWNERSHIP_CHANGED",
            "owner": _owner("generation-b", "epoch-b", 2, 102),
            "observation": None,
            "ownership_activation_record_sha256": HASH,
        },
        {
            "action": "OBSERVATION",
            "owner": _owner("generation-b", "epoch-b", 2, 105),
            "observation": _observation("epoch-b", 103, 105),
            "ownership_activation_record_sha256": None,
        },
    ]


class CanonicalOutputOracleTests(unittest.TestCase):
    def test_recovers_owner_change_and_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "depth.bnpub"
            path.write_bytes(_encoded(_valid_records()))
            scan = scan_canonical_output(path)
        self.assertTrue(scan.clean_eof, scan.reason)
        self.assertEqual(scan.records, 4)
        self.assertEqual(scan.observations, 2)
        self.assertEqual(scan.ownership_changes, 1)
        self.assertEqual(scan.owner.last_sequence, 105)  # type: ignore[union-attr]
        self.assertEqual(scan.last_observation["connection_epoch"], "epoch-b")  # type: ignore[index]
        self.assertEqual(scan.last_observation["frame_index"], 105)  # type: ignore[index]

    def test_partial_tail_stops_at_complete_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "depth.bnpub"
            path.write_bytes(_encoded(_valid_records())[:-5])
            scan = scan_canonical_output(path)
        self.assertFalse(scan.clean_eof)
        self.assertEqual(scan.records, 3)
        self.assertEqual(scan.owner.last_sequence, 102)  # type: ignore[union-attr]

    def test_gap_is_rejected(self) -> None:
        records = _valid_records()
        records[-1]["observation"] = _observation("epoch-b", 104, 106)
        records[-1]["owner"] = _owner("generation-b", "epoch-b", 2, 106)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "depth.bnpub"
            path.write_bytes(_encoded(records))
            scan = scan_canonical_output(path)
        self.assertFalse(scan.clean_eof)
        self.assertEqual(scan.records, 3)
        self.assertEqual(scan.reason, "invalid canonical output observation")


if __name__ == "__main__":
    unittest.main()
