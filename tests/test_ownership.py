from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from binance_lob.ownership import (
    OwnershipError,
    load_committed_boundary_proof,
    recover_source_pointer,
    scan_ownership_ledger,
)


SPLICE = (
    Path(__file__).parents[1]
    / "artifacts"
    / "overlap-splices"
    / "2026-08-23-BTCUSDT-A-B-002"
)


class OwnershipOracleTests(unittest.TestCase):
    def _proofs(self):
        return (
            load_committed_boundary_proof(SPLICE / "depth.bnhandover"),
            load_committed_boundary_proof(SPLICE / "trade.bnhandover"),
        )

    def test_cross_reads_rust_activated_ledger(self) -> None:
        depth, trade = self._proofs()
        scan = scan_ownership_ledger(SPLICE / "ownership.bnledger")
        owner = recover_source_pointer(scan, depth, trade)
        self.assertEqual(scan.records, 3)
        self.assertEqual(owner.generation_id, "generation-b")
        self.assertEqual(owner.fencing_token, 2)
        self.assertEqual(
            owner.digest(),
            "8d589a6f6326fa6b6d23368dbd1a713f8743107bffe86522cdad5701d157030c",
        )

    def test_partial_activation_tail_is_not_authority(self) -> None:
        depth, trade = self._proofs()
        with tempfile.TemporaryDirectory() as directory:
            damaged = Path(directory) / "ownership.bnledger"
            data = (SPLICE / "ownership.bnledger").read_bytes()
            damaged.write_bytes(data[:-7])
            scan = scan_ownership_ledger(damaged)
            self.assertFalse(scan.clean_eof)
            self.assertEqual(scan.records, 2)
            self.assertEqual(scan.active_owner.generation_id, "generation-a")  # type: ignore[union-attr]
            with self.assertRaisesRegex(OwnershipError, "clean recoverable"):
                recover_source_pointer(scan, depth, trade)

    def test_changed_boundary_proof_cannot_recover_b(self) -> None:
        depth, trade = self._proofs()
        scan = scan_ownership_ledger(SPLICE / "ownership.bnledger")
        forged = replace(depth, commit_record_sha256="c" * 64)
        with self.assertRaisesRegex(OwnershipError, "boundary proofs"):
            recover_source_pointer(scan, forged, trade)


if __name__ == "__main__":
    unittest.main()
