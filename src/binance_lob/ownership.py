"""Independent ownership-ledger recovery and fencing oracle."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
import struct

from .boundary import HandoverBoundaryV1, scan_boundary_journal


MAGIC = b"BNOWN\x00\x01\n"
LENGTH = struct.Struct(">I")
MAX_RECORD_BYTES = 256 * 1024
ZERO_DIGEST = "0" * 64


class OwnershipError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SourcePointerSnapshotV1:
    schema: str
    symbol: str
    generation_id: str
    depth_epoch: str
    trade_epoch: str
    fencing_token: int
    depth_last_sequence: int
    trade_last_sequence: int

    def validate(self) -> None:
        if (
            self.schema != "SourcePointerSnapshotV1"
            or self.symbol not in {"BTCUSDT", "ETHUSDT"}
            or not self.generation_id
            or not self.depth_epoch
            or not self.trade_epoch
            or self.fencing_token <= 0
            or self.depth_last_sequence < 0
            or self.trade_last_sequence < 0
        ):
            raise OwnershipError("invalid source pointer snapshot")

    def digest(self) -> str:
        self.validate()
        encoded = json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        return sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class CommittedBoundaryProofV1:
    boundary: HandoverBoundaryV1
    commit_record_sha256: str


@dataclass(frozen=True, slots=True)
class OwnershipActivationV1:
    schema: str
    activation_id: str
    symbol: str
    predecessor_generation: str
    successor_generation: str
    predecessor_depth_epoch: str
    predecessor_trade_epoch: str
    successor_depth_epoch: str
    successor_trade_epoch: str
    depth_boundary_id: str
    trade_boundary_id: str
    depth_commit_record_sha256: str
    trade_commit_record_sha256: str
    depth_boundary_sequence: int
    trade_boundary_sequence: int
    fencing_token: int

    def validate(self) -> None:
        if (
            self.schema != "OwnershipActivationV1"
            or not self.activation_id
            or self.symbol not in {"BTCUSDT", "ETHUSDT"}
            or not self.predecessor_generation
            or not self.successor_generation
            or self.predecessor_generation == self.successor_generation
            or not self.predecessor_depth_epoch
            or not self.predecessor_trade_epoch
            or not self.successor_depth_epoch
            or not self.successor_trade_epoch
            or self.predecessor_depth_epoch == self.successor_depth_epoch
            or self.predecessor_trade_epoch == self.successor_trade_epoch
            or not self.depth_boundary_id
            or not self.trade_boundary_id
            or self.depth_boundary_id == self.trade_boundary_id
            or self.depth_boundary_sequence < 0
            or self.trade_boundary_sequence < 0
            or self.fencing_token <= 0
        ):
            raise OwnershipError("invalid ownership activation identity")
        _validate_digest(self.depth_commit_record_sha256)
        _validate_digest(self.trade_commit_record_sha256)

    def successor_snapshot(self) -> SourcePointerSnapshotV1:
        return SourcePointerSnapshotV1(
            schema="SourcePointerSnapshotV1",
            symbol=self.symbol,
            generation_id=self.successor_generation,
            depth_epoch=self.successor_depth_epoch,
            trade_epoch=self.successor_trade_epoch,
            fencing_token=self.fencing_token,
            depth_last_sequence=self.depth_boundary_sequence,
            trade_last_sequence=self.trade_boundary_sequence,
        )


@dataclass(frozen=True, slots=True)
class OwnershipLedgerScanV1:
    schema: str
    path: Path
    file_size: int
    records: int
    last_good_offset: int
    clean_eof: bool
    reason: str | None
    active_owner: SourcePointerSnapshotV1 | None
    pending_activation: OwnershipActivationV1 | None
    last_activation: OwnershipActivationV1 | None
    last_record_sha256: str


def _validate_digest(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise OwnershipError("digest must be 64 lowercase hexadecimal characters")


def load_committed_boundary_proof(path: Path) -> CommittedBoundaryProofV1:
    scan = scan_boundary_journal(path)
    if not scan.clean_eof or scan.records != 2 or scan.committed is None:
        raise OwnershipError("boundary journal lacks one complete committed boundary")
    _validate_digest(scan.last_record_sha256)
    return CommittedBoundaryProofV1(scan.committed, scan.last_record_sha256)


def _validate_predecessor(
    owner: SourcePointerSnapshotV1, activation: OwnershipActivationV1
) -> None:
    owner.validate()
    activation.validate()
    if (
        activation.symbol != owner.symbol
        or activation.predecessor_generation != owner.generation_id
        or activation.predecessor_depth_epoch != owner.depth_epoch
        or activation.predecessor_trade_epoch != owner.trade_epoch
        or activation.fencing_token != owner.fencing_token + 1
    ):
        raise OwnershipError("ownership activation does not exactly continue active owner")


def _validate_proofs(
    activation: OwnershipActivationV1,
    depth: CommittedBoundaryProofV1,
    trade: CommittedBoundaryProofV1,
) -> None:
    if (
        depth.boundary.stream_kind != "DEPTH"
        or trade.boundary.stream_kind != "TRADE"
        or activation.symbol != depth.boundary.symbol
        or activation.symbol != trade.boundary.symbol
        or activation.predecessor_depth_epoch != depth.boundary.predecessor_epoch
        or activation.predecessor_trade_epoch != trade.boundary.predecessor_epoch
        or activation.successor_depth_epoch != depth.boundary.successor_epoch
        or activation.successor_trade_epoch != trade.boundary.successor_epoch
        or activation.depth_boundary_id != depth.boundary.boundary_id
        or activation.trade_boundary_id != trade.boundary.boundary_id
        or activation.depth_boundary_sequence != depth.boundary.boundary_sequence
        or activation.trade_boundary_sequence != trade.boundary.boundary_sequence
        or activation.depth_commit_record_sha256 != depth.commit_record_sha256
        or activation.trade_commit_record_sha256 != trade.commit_record_sha256
    ):
        raise OwnershipError("ownership activation does not match committed boundary proofs")


def _activation(value: object) -> OwnershipActivationV1:
    if not isinstance(value, dict):
        raise OwnershipError("ownership prepare lacks activation")
    try:
        result = OwnershipActivationV1(**value)
    except TypeError as exc:
        raise OwnershipError(f"invalid ownership activation: {exc}") from exc
    result.validate()
    return result


def _owner(value: object) -> SourcePointerSnapshotV1:
    if not isinstance(value, dict):
        raise OwnershipError("ownership initialization lacks owner")
    try:
        result = SourcePointerSnapshotV1(**value)
    except TypeError as exc:
        raise OwnershipError(f"invalid ownership owner: {exc}") from exc
    result.validate()
    return result


def scan_ownership_ledger(path: Path) -> OwnershipLedgerScanV1:
    path = Path(path)
    file_size = path.stat().st_size
    records = 0
    last_good_offset = 0
    previous = ZERO_DIGEST
    owner = None
    pending: tuple[OwnershipActivationV1, str] | None = None
    last_activation = None
    reason = None
    with path.open("rb") as handle:
        if handle.read(len(MAGIC)) != MAGIC:
            return OwnershipLedgerScanV1(
                "OwnershipLedgerScanV1", path, file_size, 0, 0, False,
                "bad ownership ledger magic", None, None, None, ZERO_DIGEST
            )
        last_good_offset = len(MAGIC)
        while True:
            prefix = handle.read(LENGTH.size)
            if prefix == b"":
                break
            if len(prefix) != LENGTH.size:
                reason = "partial ownership length prefix"
                break
            (body_length,) = LENGTH.unpack(prefix)
            if body_length > MAX_RECORD_BYTES:
                reason = "ownership record length exceeds limit"
                break
            body = handle.read(body_length)
            if len(body) != body_length:
                reason = "partial ownership record body"
                break
            digest = handle.read(32)
            if len(digest) != 32:
                reason = "partial ownership record digest"
                break
            if sha256(body).digest() != digest:
                reason = "ownership record digest mismatch"
                break
            try:
                record = json.loads(body)
                if not isinstance(record, dict):
                    raise OwnershipError("ownership record is not an object")
                if (
                    record.get("schema") != "OwnershipRecordV1"
                    or record.get("record_index") != records
                    or record.get("previous_record_sha256") != previous
                ):
                    raise OwnershipError("ownership ledger chain/index mismatch")
                action = record.get("action")
                if action == "INITIALIZED":
                    if records != 0 or owner is not None or pending is not None:
                        raise OwnershipError("illegal ownership initialization")
                    if record.get("activation") is not None or record.get("prepared_record_sha256") is not None:
                        raise OwnershipError("ownership initialization has illegal fields")
                    owner = _owner(record.get("initial_owner"))
                elif action == "PREPARED":
                    if owner is None or pending is not None or record.get("initial_owner") is not None or record.get("prepared_record_sha256") is not None:
                        raise OwnershipError("illegal ownership prepare")
                    activation = _activation(record.get("activation"))
                    _validate_predecessor(owner, activation)
                    pending = (activation, digest.hex())
                elif action == "ACTIVATED":
                    if pending is None:
                        raise OwnershipError("ownership activation has no prepared record")
                    activation, prepared_digest = pending
                    if record.get("initial_owner") is not None or record.get("activation") is not None or record.get("prepared_record_sha256") != prepared_digest:
                        raise OwnershipError("ownership activation reference mismatch")
                    owner = activation.successor_snapshot()
                    last_activation = activation
                    pending = None
                else:
                    raise OwnershipError("unknown ownership action")
            except (json.JSONDecodeError, UnicodeDecodeError, OwnershipError) as exc:
                reason = str(exc)
                break
            records += 1
            last_good_offset = handle.tell()
            previous = digest.hex()
    return OwnershipLedgerScanV1(
        "OwnershipLedgerScanV1", path, file_size, records, last_good_offset,
        reason is None, reason, owner, None if pending is None else pending[0],
        last_activation, previous
    )


def recover_source_pointer(
    scan: OwnershipLedgerScanV1,
    depth: CommittedBoundaryProofV1 | None = None,
    trade: CommittedBoundaryProofV1 | None = None,
) -> SourcePointerSnapshotV1:
    if not scan.clean_eof or scan.records == 0 or scan.active_owner is None:
        raise OwnershipError("ownership ledger is not a clean recoverable authority")
    scan.active_owner.validate()
    if scan.last_activation is None:
        if depth is not None or trade is not None:
            raise OwnershipError("initial ownership received unexpected boundary proofs")
    else:
        if depth is None or trade is None:
            raise OwnershipError("activated recovery requires both boundary proofs")
        _validate_proofs(scan.last_activation, depth, trade)
        if scan.last_activation.successor_snapshot() != scan.active_owner:
            raise OwnershipError("active owner differs from last durable activation")
    return scan.active_owner


def verify_ownership(
    ledger: Path, depth_journal: Path, trade_journal: Path
) -> dict[str, object]:
    depth = load_committed_boundary_proof(depth_journal)
    trade = load_committed_boundary_proof(trade_journal)
    scan = scan_ownership_ledger(ledger)
    owner = recover_source_pointer(scan, depth, trade)
    return {
        "schema": "OwnershipVerificationV1",
        "status": "PASS",
        "ledger": str(ledger),
        "records": scan.records,
        "last_record_sha256": scan.last_record_sha256,
        "active_owner": asdict(owner),
        "active_owner_sha256": owner.digest(),
        "credentials": "NONE",
        "order_entry": "ABSENT",
    }
