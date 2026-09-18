"""Independent Python oracle for durable A-to-B handover boundaries."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
from typing import BinaryIO


MAGIC = b"BNHND\x00\x01\n"
LENGTH = struct.Struct(">I")
DIGEST_SIZE = 32
MAX_RECORD_BYTES = 256 * 1024
ZERO_DIGEST = "0" * 64


class BoundaryJournalError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RawPositionV1:
    connection_epoch: str
    stream: str
    frame_index: int
    record_sha256: str


@dataclass(frozen=True, slots=True)
class BoundaryDurabilityV1:
    durable_through_frame_index: int
    durable_through_offset: int
    last_record_sha256: str


@dataclass(frozen=True, slots=True)
class HandoverBoundaryV1:
    schema: str
    boundary_id: str
    environment: str
    symbol: str
    stream_kind: str
    stream: str
    predecessor_epoch: str
    successor_epoch: str
    boundary_sequence: int
    boundary_sha256: str
    predecessor_last_selected: RawPositionV1
    successor_boundary_observation: RawPositionV1
    successor_first_selected: RawPositionV1
    predecessor_durability: BoundaryDurabilityV1
    successor_durability: BoundaryDurabilityV1
    spec_revision: str
    selector_version: str

    def validate(self) -> None:
        if (
            self.schema != "HandoverBoundaryV1"
            or not self.boundary_id.strip()
            or self.environment != "production-public-market-data"
            or self.symbol not in {"BTCUSDT", "ETHUSDT"}
            or self.stream_kind not in {"DEPTH", "TRADE"}
            or not self.predecessor_epoch
            or not self.successor_epoch
            or self.predecessor_epoch == self.successor_epoch
            or not self.spec_revision
            or not self.selector_version
        ):
            raise BoundaryJournalError("invalid handover boundary identity/scope")
        for digest in (
            self.boundary_sha256,
            self.predecessor_last_selected.record_sha256,
            self.successor_boundary_observation.record_sha256,
            self.successor_first_selected.record_sha256,
            self.predecessor_durability.last_record_sha256,
            self.successor_durability.last_record_sha256,
        ):
            _validate_digest(digest)
        positions = (
            (self.predecessor_last_selected, self.predecessor_epoch),
            (self.successor_boundary_observation, self.successor_epoch),
            (self.successor_first_selected, self.successor_epoch),
        )
        if any(position.connection_epoch != epoch or position.stream != self.stream for position, epoch in positions):
            raise BoundaryJournalError("raw position does not match boundary epoch/stream")
        if self.successor_first_selected.frame_index <= self.successor_boundary_observation.frame_index:
            raise BoundaryJournalError(
                "successor first-selected position must follow overlap boundary"
            )
        if (
            self.predecessor_durability.durable_through_frame_index
            < self.predecessor_last_selected.frame_index
            or self.successor_durability.durable_through_frame_index
            < self.successor_first_selected.frame_index
        ):
            raise BoundaryJournalError(
                "boundary references a raw position beyond durable watermark"
            )


@dataclass(frozen=True, slots=True)
class CanonicalObservationV1:
    symbol: str
    stream_kind: str
    stream: str
    connection_epoch: str
    frame_index: int
    first_sequence: int
    final_sequence: int
    record_sha256: str
    observation_sha256: str


@dataclass(frozen=True, slots=True)
class SelectedObservationV1:
    connection_epoch: str
    frame_index: int
    first_sequence: int
    final_sequence: int
    record_sha256: str


@dataclass(frozen=True, slots=True)
class CanonicalSelectionV1:
    schema: str
    boundary_id: str
    symbol: str
    stream_kind: str
    boundary_sequence: int
    selected: tuple[SelectedObservationV1, ...]
    excluded_overlap_records: int
    excluded_duplicate_records: int
    first_sequence: int
    final_sequence: int
    selection_sha256: str


def select_canonical(
    boundary: HandoverBoundaryV1,
    predecessor: list[CanonicalObservationV1],
    successor: list[CanonicalObservationV1],
) -> CanonicalSelectionV1:
    boundary.validate()
    _validate_observations(boundary, predecessor, boundary.predecessor_epoch)
    _validate_observations(boundary, successor, boundary.successor_epoch)
    predecessor_boundary = _find_position(predecessor, boundary.predecessor_last_selected)
    successor_boundary = _find_position(successor, boundary.successor_boundary_observation)
    successor_first = _find_position(successor, boundary.successor_first_selected)
    _validate_boundary_observations(
        boundary, predecessor_boundary, successor_boundary, successor_first
    )
    candidates = [
        item
        for item in predecessor
        if item.frame_index <= boundary.predecessor_last_selected.frame_index
    ] + [
        item
        for item in successor
        if item.frame_index >= boundary.successor_first_selected.frame_index
    ]
    excluded_overlap = sum(
        item.frame_index > boundary.predecessor_last_selected.frame_index
        for item in predecessor
    ) + sum(
        item.frame_index < boundary.successor_first_selected.frame_index for item in successor
    )
    selected_observations, duplicates = _validate_and_select_sequence(
        boundary.stream_kind, candidates
    )
    if not selected_observations:
        raise BoundaryJournalError("canonical selection is empty")
    predecessor_selected = [
        item
        for item in selected_observations
        if item.connection_epoch == boundary.predecessor_epoch
    ]
    successor_selected = [
        item for item in selected_observations if item.connection_epoch == boundary.successor_epoch
    ]
    if not predecessor_selected or not successor_selected:
        raise BoundaryJournalError("canonical selection lacks predecessor/successor")
    if (
        predecessor_selected[-1].final_sequence != boundary.boundary_sequence
        or successor_selected[0].frame_index != boundary.successor_first_selected.frame_index
    ):
        raise BoundaryJournalError("canonical splice does not match committed boundary")
    selected = tuple(
        SelectedObservationV1(
            item.connection_epoch,
            item.frame_index,
            item.first_sequence,
            item.final_sequence,
            item.record_sha256,
        )
        for item in selected_observations
    )
    material = {
        "schema": "CanonicalSelectionDigestV1",
        "boundary_id": boundary.boundary_id,
        "symbol": boundary.symbol,
        "stream_kind": boundary.stream_kind,
        "boundary_sequence": boundary.boundary_sequence,
        "selected": [asdict(item) for item in selected],
    }
    canonical = json.dumps(
        material, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()
    return CanonicalSelectionV1(
        schema="CanonicalSelectionV1",
        boundary_id=boundary.boundary_id,
        symbol=boundary.symbol,
        stream_kind=boundary.stream_kind,
        boundary_sequence=boundary.boundary_sequence,
        selected=selected,
        excluded_overlap_records=excluded_overlap,
        excluded_duplicate_records=duplicates,
        first_sequence=selected[0].first_sequence,
        final_sequence=selected[-1].final_sequence,
        selection_sha256=sha256(canonical).hexdigest(),
    )


def _validate_observations(
    boundary: HandoverBoundaryV1,
    observations: list[CanonicalObservationV1],
    expected_epoch: str,
) -> None:
    if not observations:
        raise BoundaryJournalError("canonical source observations are empty")
    previous_frame = None
    for observation in observations:
        if (
            observation.symbol != boundary.symbol
            or observation.stream_kind != boundary.stream_kind
            or observation.stream != boundary.stream
            or observation.connection_epoch != expected_epoch
            or observation.first_sequence > observation.final_sequence
        ):
            raise BoundaryJournalError("observation identity/range does not match boundary")
        _validate_digest(observation.record_sha256)
        _validate_digest(observation.observation_sha256)
        if previous_frame is not None and observation.frame_index != previous_frame + 1:
            raise BoundaryJournalError("raw frame index gap/reorder in canonical source")
        previous_frame = observation.frame_index


def _find_position(
    observations: list[CanonicalObservationV1], position: RawPositionV1
) -> CanonicalObservationV1:
    found = next(
        (item for item in observations if item.frame_index == position.frame_index), None
    )
    if found is None:
        raise BoundaryJournalError("committed raw position is absent from observations")
    if (
        found.connection_epoch != position.connection_epoch
        or found.stream != position.stream
        or found.record_sha256 != position.record_sha256
    ):
        raise BoundaryJournalError("committed raw position digest/identity mismatch")
    return found


def _validate_boundary_observations(
    boundary: HandoverBoundaryV1,
    predecessor: CanonicalObservationV1,
    successor_boundary: CanonicalObservationV1,
    successor_first: CanonicalObservationV1,
) -> None:
    if (
        predecessor.final_sequence != boundary.boundary_sequence
        or successor_boundary.final_sequence != boundary.boundary_sequence
        or predecessor.observation_sha256 != boundary.boundary_sha256
        or successor_boundary.observation_sha256 != boundary.boundary_sha256
    ):
        raise BoundaryJournalError("A/B observations do not prove the committed convergence")
    next_sequence = boundary.boundary_sequence + 1
    if boundary.stream_kind == "DEPTH":
        if (
            successor_first.first_sequence > next_sequence
            or successor_first.final_sequence < next_sequence
        ):
            raise BoundaryJournalError("successor depth frame does not bridge K+1")
    elif (
        predecessor.first_sequence != boundary.boundary_sequence
        or successor_boundary.first_sequence != boundary.boundary_sequence
        or successor_first.first_sequence != next_sequence
        or successor_first.final_sequence != next_sequence
    ):
        raise BoundaryJournalError("successor trade does not continue at T+1")


def _validate_and_select_sequence(
    kind: str, candidates: list[CanonicalObservationV1]
) -> tuple[list[CanonicalObservationV1], int]:
    selected: list[CanonicalObservationV1] = []
    duplicates = 0
    for observation in candidates:
        if not selected:
            selected.append(observation)
            continue
        previous = selected[-1]
        next_sequence = previous.final_sequence + 1
        if observation.final_sequence < next_sequence:
            if (
                observation.final_sequence == previous.final_sequence
                and observation.observation_sha256 == previous.observation_sha256
            ):
                duplicates += 1
                continue
            raise BoundaryJournalError("stale/conflicting canonical observation")
        if observation.first_sequence > next_sequence:
            raise BoundaryJournalError("gap in canonical observation sequence")
        if kind == "TRADE" and (
            observation.first_sequence != next_sequence
            or observation.final_sequence != next_sequence
        ):
            raise BoundaryJournalError("trade sequence is not exactly contiguous")
        selected.append(observation)
    return selected, duplicates


@dataclass(frozen=True, slots=True)
class BoundaryJournalAckV1:
    schema: str
    action: str
    boundary_id: str
    durable_record_count: int
    durable_through_offset: int
    last_record_sha256: str


@dataclass(frozen=True, slots=True)
class BoundaryJournalScanV1:
    schema: str
    path: Path
    file_size: int
    records: int
    last_good_offset: int
    clean_eof: bool
    reason: str | None
    proposal: HandoverBoundaryV1 | None
    committed: HandoverBoundaryV1 | None
    last_record_sha256: str


def _validate_digest(digest: str) -> None:
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise BoundaryJournalError("digest must be 64 lowercase hexadecimal characters")


def _boundary_from_dict(value: dict[str, object]) -> HandoverBoundaryV1:
    try:
        boundary = HandoverBoundaryV1(
            schema=str(value["schema"]),
            boundary_id=str(value["boundary_id"]),
            environment=str(value["environment"]),
            symbol=str(value["symbol"]),
            stream_kind=str(value["stream_kind"]),
            stream=str(value["stream"]),
            predecessor_epoch=str(value["predecessor_epoch"]),
            successor_epoch=str(value["successor_epoch"]),
            boundary_sequence=int(value["boundary_sequence"]),
            boundary_sha256=str(value["boundary_sha256"]),
            predecessor_last_selected=RawPositionV1(**value["predecessor_last_selected"]),  # type: ignore[arg-type]
            successor_boundary_observation=RawPositionV1(**value["successor_boundary_observation"]),  # type: ignore[arg-type]
            successor_first_selected=RawPositionV1(**value["successor_first_selected"]),  # type: ignore[arg-type]
            predecessor_durability=BoundaryDurabilityV1(**value["predecessor_durability"]),  # type: ignore[arg-type]
            successor_durability=BoundaryDurabilityV1(**value["successor_durability"]),  # type: ignore[arg-type]
            spec_revision=str(value["spec_revision"]),
            selector_version=str(value["selector_version"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise BoundaryJournalError(f"invalid handover boundary: {exc}") from exc
    boundary.validate()
    return boundary


def _write_all(handle: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = handle.write(view)
        if written is None or written <= 0:
            raise OSError("boundary sink made no write progress")
        view = view[written:]


class BoundaryJournalWriter:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file: BinaryIO = self.path.open("xb", buffering=0)
        self._end_offset = len(MAGIC)
        self._previous_digest = ZERO_DIGEST
        self._proposal: tuple[HandoverBoundaryV1, str] | None = None
        self._committed = False
        self._poisoned = False
        try:
            _write_all(self._file, MAGIC)
            os.fsync(self._file.fileno())
        except Exception:
            self._poisoned = True
            self._file.close()
            raise

    @property
    def is_poisoned(self) -> bool:
        return self._poisoned

    def propose(self, boundary: HandoverBoundaryV1) -> BoundaryJournalAckV1:
        if self._proposal is not None or self._committed:
            raise BoundaryJournalError("boundary journal already has a proposal")
        boundary.validate()
        record = {
            "schema": "BoundaryJournalRecordV1",
            "record_index": 0,
            "action": "PROPOSED",
            "boundary_id": boundary.boundary_id,
            "boundary": asdict(boundary),
            "proposal_record_sha256": None,
            "previous_record_sha256": self._previous_digest,
        }
        ack = self._append_and_sync(record)
        self._proposal = (boundary, ack.last_record_sha256)
        return ack

    def commit(self, boundary_id: str) -> BoundaryJournalAckV1:
        if self._committed:
            raise BoundaryJournalError("boundary journal is already committed")
        if self._proposal is None:
            raise BoundaryJournalError("boundary cannot commit before durable proposal")
        boundary, proposal_digest = self._proposal
        if boundary.boundary_id != boundary_id:
            raise BoundaryJournalError("commit boundary ID does not match proposal")
        record = {
            "schema": "BoundaryJournalRecordV1",
            "record_index": 1,
            "action": "COMMITTED",
            "boundary_id": boundary_id,
            "boundary": None,
            "proposal_record_sha256": proposal_digest,
            "previous_record_sha256": self._previous_digest,
        }
        ack = self._append_and_sync(record)
        self._committed = True
        return ack

    def _append_and_sync(self, record: dict[str, object]) -> BoundaryJournalAckV1:
        if self._poisoned:
            raise BoundaryJournalError("boundary journal is poisoned")
        body = json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        if len(body) > MAX_RECORD_BYTES:
            raise BoundaryJournalError("boundary journal record exceeds maximum size")
        digest = sha256(body).digest()
        encoded = LENGTH.pack(len(body)) + body + digest
        try:
            _write_all(self._file, encoded)
            self._file.flush()
            os.fsync(self._file.fileno())
        except Exception as exc:
            self._poisoned = True
            raise BoundaryJournalError(f"sync boundary record; journal poisoned: {exc}") from exc
        self._end_offset += len(encoded)
        self._previous_digest = digest.hex()
        return BoundaryJournalAckV1(
            schema="BoundaryJournalAckV1",
            action=str(record["action"]),
            boundary_id=str(record["boundary_id"]),
            durable_record_count=int(record["record_index"]) + 1,
            durable_through_offset=self._end_offset,
            last_record_sha256=self._previous_digest,
        )

    def close(self) -> None:
        self._file.close()


def scan_boundary_journal(path: Path) -> BoundaryJournalScanV1:
    path = Path(path)
    file_size = path.stat().st_size
    records = 0
    last_good_offset = 0
    previous = ZERO_DIGEST
    proposal: tuple[HandoverBoundaryV1, str] | None = None
    committed = None
    reason = None
    with path.open("rb") as handle:
        if handle.read(len(MAGIC)) != MAGIC:
            return BoundaryJournalScanV1(
                "BoundaryJournalScanV1", path, file_size, 0, 0, False,
                "bad boundary journal magic", None, None, ZERO_DIGEST
            )
        last_good_offset = len(MAGIC)
        while True:
            prefix = handle.read(LENGTH.size)
            if prefix == b"":
                break
            if len(prefix) != LENGTH.size:
                reason = "partial boundary length prefix"
                break
            (body_length,) = LENGTH.unpack(prefix)
            if body_length > MAX_RECORD_BYTES:
                reason = "boundary record length exceeds limit"
                break
            body = handle.read(body_length)
            if len(body) != body_length:
                reason = "partial boundary record body"
                break
            digest = handle.read(DIGEST_SIZE)
            if len(digest) != DIGEST_SIZE:
                reason = "partial boundary record digest"
                break
            if sha256(body).digest() != digest:
                reason = "boundary record digest mismatch"
                break
            try:
                record = json.loads(body)
                if not isinstance(record, dict):
                    raise BoundaryJournalError("boundary record is not an object")
                if (
                    record.get("schema") != "BoundaryJournalRecordV1"
                    or record.get("record_index") != records
                    or record.get("previous_record_sha256") != previous
                ):
                    raise BoundaryJournalError("boundary journal chain/index mismatch")
                action = record.get("action")
                if action == "PROPOSED":
                    if records != 0 or proposal is not None or committed is not None:
                        raise BoundaryJournalError("illegal duplicate boundary proposal")
                    raw_boundary = record.get("boundary")
                    if not isinstance(raw_boundary, dict):
                        raise BoundaryJournalError("proposal missing boundary")
                    boundary = _boundary_from_dict(raw_boundary)
                    if (
                        boundary.boundary_id != record.get("boundary_id")
                        or record.get("proposal_record_sha256") is not None
                    ):
                        raise BoundaryJournalError("proposal identity/reference mismatch")
                    proposal = (boundary, digest.hex())
                elif action == "COMMITTED":
                    if proposal is None or records != 1 or committed is not None:
                        raise BoundaryJournalError("commit has no valid proposal")
                    boundary, proposal_digest = proposal
                    if (
                        record.get("boundary") is not None
                        or record.get("boundary_id") != boundary.boundary_id
                        or record.get("proposal_record_sha256") != proposal_digest
                    ):
                        raise BoundaryJournalError("commit identity/reference mismatch")
                    committed = boundary
                else:
                    raise BoundaryJournalError("unknown boundary journal action")
            except (BoundaryJournalError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                reason = str(exc)
                break
            records += 1
            last_good_offset = handle.tell()
            previous = digest.hex()
    return BoundaryJournalScanV1(
        schema="BoundaryJournalScanV1",
        path=path,
        file_size=file_size,
        records=records,
        last_good_offset=last_good_offset,
        clean_eof=reason is None,
        reason=reason,
        proposal=None if proposal is None else proposal[0],
        committed=committed,
        last_record_sha256=previous,
    )
