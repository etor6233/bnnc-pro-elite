"""Independent recovery oracle for the durable canonical publication journal."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
import struct

from .ownership import (
    load_committed_boundary_proof,
    recover_source_pointer,
    scan_ownership_ledger,
)


MAGIC = b"BNPUB\x00\x01\n"
LENGTH = struct.Struct(">I")
MAX_RECORD_BYTES = 256 * 1024
ZERO_DIGEST = "0" * 64


class CanonicalOutputError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CanonicalOutputOwnerV1:
    generation_id: str
    connection_epoch: str
    fencing_token: int
    last_sequence: int

    def validate(self) -> None:
        if (
            not self.generation_id.strip()
            or not self.connection_epoch.strip()
            or self.fencing_token <= 0
            or self.last_sequence < 0
        ):
            raise CanonicalOutputError("invalid canonical output owner")


@dataclass(frozen=True, slots=True)
class CanonicalOutputScanV1:
    schema: str
    path: Path
    file_size: int
    records: int
    observations: int
    ownership_changes: int
    last_good_offset: int
    clean_eof: bool
    reason: str | None
    symbol: str | None
    stream_kind: str | None
    owner: CanonicalOutputOwnerV1 | None
    last_observation: dict[str, object] | None
    ownership_activation_record_sha256: str | None
    last_record_sha256: str


def _digest(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise CanonicalOutputError("invalid lowercase SHA-256 digest")
    return value


def _owner(value: object) -> CanonicalOutputOwnerV1:
    if not isinstance(value, dict):
        raise CanonicalOutputError("canonical output record lacks owner")
    try:
        result = CanonicalOutputOwnerV1(**value)
    except TypeError as exc:
        raise CanonicalOutputError(f"invalid canonical output owner: {exc}") from exc
    result.validate()
    return result


def _validate_observation(
    record: dict[str, object], old: CanonicalOutputOwnerV1
) -> CanonicalOutputOwnerV1:
    value = record.get("observation")
    if not isinstance(value, dict):
        raise CanonicalOutputError("observation record lacks observation")
    owner = _owner(record.get("owner"))
    kind = record.get("stream_kind")
    expected = old.last_sequence + 1
    first = value.get("first_sequence")
    final = value.get("final_sequence")
    continuous = (
        isinstance(first, int)
        and isinstance(final, int)
        and (
            (kind == "DEPTH" and first <= expected <= final)
            or (kind == "TRADE" and first == expected and final == expected)
        )
    )
    if (
        not continuous
        or value.get("symbol") != record.get("symbol")
        or value.get("stream_kind") != kind
        or value.get("connection_epoch") != old.connection_epoch
        or owner.generation_id != old.generation_id
        or owner.connection_epoch != old.connection_epoch
        or owner.fencing_token != old.fencing_token
        or owner.last_sequence != final
        or record.get("ownership_activation_record_sha256") is not None
    ):
        raise CanonicalOutputError("invalid canonical output observation")
    _digest(value.get("record_sha256"))
    _digest(value.get("observation_sha256"))
    return owner


def _validate_record(
    record: object,
    index: int,
    symbol: str | None,
    kind: str | None,
    old: CanonicalOutputOwnerV1 | None,
    previous: str,
) -> CanonicalOutputOwnerV1:
    if not isinstance(record, dict):
        raise CanonicalOutputError("canonical output record is not an object")
    if (
        record.get("schema") != "CanonicalOutputRecordV1"
        or record.get("record_index") != index
        or record.get("previous_record_sha256") != previous
        or record.get("symbol") not in {"BTCUSDT", "ETHUSDT"}
        or record.get("stream_kind") not in {"DEPTH", "TRADE"}
        or (symbol is not None and record.get("symbol") != symbol)
        or (kind is not None and record.get("stream_kind") != kind)
    ):
        raise CanonicalOutputError("canonical output record identity mismatch")
    action = record.get("action")
    owner = _owner(record.get("owner"))
    if action == "INITIALIZED":
        if (
            index != 0
            or old is not None
            or record.get("observation") is not None
            or record.get("ownership_activation_record_sha256") is not None
        ):
            raise CanonicalOutputError("illegal canonical output initialization")
        return owner
    if action == "OBSERVATION":
        if old is None:
            raise CanonicalOutputError("observation before initialization")
        return _validate_observation(record, old)
    if action == "OWNERSHIP_CHANGED":
        proof = _digest(record.get("ownership_activation_record_sha256"))
        if (
            old is None
            or record.get("observation") is not None
            or owner.generation_id == old.generation_id
            or owner.connection_epoch == old.connection_epoch
            or owner.fencing_token != old.fencing_token + 1
            or owner.last_sequence != old.last_sequence
            or not proof
        ):
            raise CanonicalOutputError("invalid canonical output ownership change")
        return owner
    raise CanonicalOutputError("unknown canonical output action")


def scan_canonical_output(path: Path) -> CanonicalOutputScanV1:
    path = Path(path)
    file_size = path.stat().st_size
    records = observations = ownership_changes = 0
    offset = 0
    previous = ZERO_DIGEST
    symbol = kind = None
    owner = None
    reason = None
    with path.open("rb") as handle:
        if handle.read(len(MAGIC)) != MAGIC:
            return CanonicalOutputScanV1(
                "CanonicalOutputScanV1", path, file_size, 0, 0, 0, 0, False,
                "bad canonical output magic", None, None, None, None, None, ZERO_DIGEST
            )
        activation_proof = None
        last_observation = None
        offset = len(MAGIC)
        while True:
            prefix = handle.read(LENGTH.size)
            if prefix == b"":
                break
            if len(prefix) != LENGTH.size:
                reason = "partial canonical output length"
                break
            (body_length,) = LENGTH.unpack(prefix)
            if body_length == 0 or body_length > MAX_RECORD_BYTES:
                reason = "invalid canonical output record length"
                break
            body = handle.read(body_length)
            digest = handle.read(32)
            if len(body) != body_length or len(digest) != 32:
                reason = "partial canonical output record"
                break
            if sha256(body).digest() != digest:
                reason = "canonical output digest mismatch"
                break
            try:
                record = json.loads(body)
                owner = _validate_record(record, records, symbol, kind, owner, previous)
            except (CanonicalOutputError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                reason = str(exc)
                break
            symbol = str(record["symbol"])
            kind = str(record["stream_kind"])
            action = record["action"]
            observations += action == "OBSERVATION"
            ownership_changes += action == "OWNERSHIP_CHANGED"
            if action == "OBSERVATION":
                last_observation = dict(record["observation"])
            if action == "OWNERSHIP_CHANGED":
                activation_proof = str(record["ownership_activation_record_sha256"])
            records += 1
            offset = handle.tell()
            previous = digest.hex()
    return CanonicalOutputScanV1(
        "CanonicalOutputScanV1", path, file_size, records, observations,
        ownership_changes, offset, reason is None and offset == file_size,
        reason, symbol, kind, owner, last_observation, activation_proof, previous
    )


def verify_canonical_outputs(
    ledger: Path,
    depth_journal: Path,
    trade_journal: Path,
    depth_output: Path,
    trade_output: Path,
) -> dict[str, object]:
    ownership_scan = scan_ownership_ledger(ledger)
    pointer = recover_source_pointer(
        ownership_scan,
        load_committed_boundary_proof(depth_journal),
        load_committed_boundary_proof(trade_journal),
    )
    depth = scan_canonical_output(depth_output)
    trade = scan_canonical_output(trade_output)
    if (
        not depth.clean_eof
        or not trade.clean_eof
        or depth.stream_kind != "DEPTH"
        or trade.stream_kind != "TRADE"
        or depth.symbol != pointer.symbol
        or trade.symbol != pointer.symbol
        or depth.ownership_changes != 1
        or trade.ownership_changes != 1
        or depth.owner is None
        or trade.owner is None
        or depth.owner.generation_id != pointer.generation_id
        or trade.owner.generation_id != pointer.generation_id
        or depth.owner.connection_epoch != pointer.depth_epoch
        or trade.owner.connection_epoch != pointer.trade_epoch
        or depth.owner.fencing_token != pointer.fencing_token
        or trade.owner.fencing_token != pointer.fencing_token
        or depth.ownership_activation_record_sha256
        != ownership_scan.last_record_sha256
        or trade.ownership_activation_record_sha256
        != ownership_scan.last_record_sha256
        or depth.owner.last_sequence < pointer.depth_last_sequence
        or trade.owner.last_sequence < pointer.trade_last_sequence
    ):
        raise CanonicalOutputError("canonical outputs differ from durable source pointer")
    return {
        "schema": "CanonicalOutputVerificationV1",
        "status": "PASS",
        "active_owner": asdict(pointer),
        "depth": {**asdict(depth), "path": str(depth.path)},
        "trade": {**asdict(trade), "path": str(trade.path)},
        "credentials": "NONE",
        "order_entry": "ABSENT",
    }
