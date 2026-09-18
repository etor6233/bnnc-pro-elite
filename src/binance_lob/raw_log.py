"""Append-only, length-delimited and hash-chained raw capture format."""

from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
from typing import BinaryIO, Iterator

from .clock import ClockQuality, ClockSample
from .raw_frame import RawFrameV1


MAGIC = b"BNRAW\x00\x01\n"
LENGTH = struct.Struct(">I")
DIGEST_SIZE = 32
MAX_RECORD_BYTES = 4 * 1024 * 1024
ZERO_DIGEST = "0" * 64


class RawLogCorruption(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RawRecordEnvelopeV1:
    """A verified frame plus its immutable BNRAW record lineage."""

    schema: str
    record_index: int
    start_offset: int
    end_offset: int
    record_sha256: str
    frame: RawFrameV1


@dataclass(frozen=True, slots=True)
class StreamDurabilityWatermarkV1:
    connection_epoch: str
    stream: str
    durable_through_frame_index: int


@dataclass(frozen=True, slots=True)
class DurabilityAckV1:
    schema: str
    durable_record_count: int
    durable_through_offset: int
    last_record_sha256: str
    streams: tuple[StreamDurabilityWatermarkV1, ...]


@dataclass(frozen=True, slots=True)
class AppendReceiptV1:
    schema: str
    record_index: int
    end_offset: int
    record_sha256: str
    durability_ack: DurabilityAckV1 | None


@dataclass(frozen=True, slots=True)
class RawLogScan:
    path: Path
    file_size: int
    records: int
    last_good_offset: int
    clean_eof: bool
    reason: str | None
    last_record_sha256: str
    streams: tuple[StreamDurabilityWatermarkV1, ...]


@dataclass(frozen=True, slots=True)
class RawRecoveryV1:
    schema: str
    source: Path
    destination: Path
    source_file_size: int
    copied_valid_prefix_bytes: int
    excluded_tail_bytes: int
    recovered_records: int
    last_record_sha256: str


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _record_dict(frame: RawFrameV1, previous_digest: str) -> dict[str, object]:
    return {
        "schema": "RawFrameV1",
        "venue": frame.venue,
        "environment": frame.environment,
        "endpoint": frame.endpoint,
        "stream": frame.stream,
        "symbol": frame.symbol,
        "connection_epoch": frame.connection_epoch,
        "frame_index": frame.frame_index,
        "receive_wall_ns": frame.clock.wall_ns,
        "receive_mono_ns": frame.clock.mono_ns,
        "clock_quality": frame.clock.quality.value,
        "clock_source": frame.clock.source,
        "clock_offset_ns": frame.clock.offset_ns,
        "clock_uncertainty_ns": frame.clock.uncertainty_ns,
        "payload_length": len(frame.payload),
        "payload_sha256": frame.payload_sha256,
        "payload_base64": b64encode(frame.payload).decode("ascii"),
        # The immutable frame cannot prove its own fsync. DurabilityAckV1 does.
        "recorder_state": "PENDING",
        "spec_revision": frame.spec_revision,
        "previous_record_sha256": previous_digest,
    }


def _frame_from_record(record: dict[str, object]) -> RawFrameV1:
    if record.get("schema") != "RawFrameV1":
        raise RawLogCorruption("unknown raw record schema")
    try:
        payload = b64decode(str(record["payload_base64"]), validate=True)
        if len(payload) != int(record["payload_length"]):
            raise RawLogCorruption("payload length mismatch")
        clock = ClockSample(
            wall_ns=int(record["receive_wall_ns"]),
            mono_ns=int(record["receive_mono_ns"]),
            quality=ClockQuality(str(record["clock_quality"])),
            source=str(record["clock_source"]),
            offset_ns=None if record["clock_offset_ns"] is None else int(record["clock_offset_ns"]),
            uncertainty_ns=(
                None
                if record["clock_uncertainty_ns"] is None
                else int(record["clock_uncertainty_ns"])
            ),
        )
        return RawFrameV1(
            venue=str(record["venue"]),
            environment=str(record["environment"]),
            endpoint=str(record["endpoint"]),
            stream=str(record["stream"]),
            symbol=str(record["symbol"]),
            connection_epoch=str(record["connection_epoch"]),
            frame_index=int(record["frame_index"]),
            clock=clock,
            payload=payload,
            payload_sha256=str(record["payload_sha256"]),
            recorder_state=str(record["recorder_state"]),
            spec_revision=str(record["spec_revision"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, RawLogCorruption):
            raise
        raise RawLogCorruption(f"invalid raw record: {exc}") from exc


class RawLogWriter:
    """Creates a new log and refuses overwrite or discontinuous frame indices."""

    def __init__(self, path: Path, *, sync_every: int = 64) -> None:
        if sync_every < 1:
            raise ValueError("sync_every must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file: BinaryIO = self.path.open("xb", buffering=0)
        self._sync_every = sync_every
        self._since_sync = 0
        self._previous_digest = ZERO_DIGEST
        self._next_index: dict[tuple[str, str], int] = {}
        self._closed = False
        self._poisoned = False
        self._record_count = 0
        self._end_offset = len(MAGIC)
        self._last_ack: DurabilityAckV1 | None = None
        try:
            self._write_all(MAGIC)
            self._file.flush()
            os.fsync(self._file.fileno())
        except Exception:
            self._poisoned = True
            self._file.close()
            self._closed = True
            raise

    @property
    def last_record_sha256(self) -> str:
        return self._previous_digest

    @property
    def last_durability_ack(self) -> DurabilityAckV1 | None:
        return self._last_ack

    @property
    def is_poisoned(self) -> bool:
        return self._poisoned

    def _write_all(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = self._file.write(view)
            if written is None or written <= 0:
                raise OSError("raw sink made no write progress")
            view = view[written:]

    def _watermarks(self) -> tuple[StreamDurabilityWatermarkV1, ...]:
        return tuple(
            StreamDurabilityWatermarkV1(
                connection_epoch=connection_epoch,
                stream=stream,
                durable_through_frame_index=next_index - 1,
            )
            for (connection_epoch, stream), next_index in sorted(self._next_index.items())
            if next_index > 0
        )

    def append(self, frame: RawFrameV1) -> AppendReceiptV1:
        if self._closed:
            raise ValueError("raw log is closed")
        if self._poisoned:
            raise RawLogCorruption("raw writer is poisoned")
        key = (frame.connection_epoch, frame.stream)
        expected = self._next_index.get(key, 0)
        if frame.frame_index != expected:
            raise ValueError(
                f"non-contiguous frame index for {key}: expected {expected}, got {frame.frame_index}"
            )
        body = _canonical_json(_record_dict(frame, self._previous_digest))
        if len(body) > MAX_RECORD_BYTES:
            raise ValueError("raw record exceeds maximum size")
        digest = sha256(body).digest()
        encoded = LENGTH.pack(len(body)) + body + digest
        try:
            self._write_all(encoded)
        except Exception as exc:
            self._poisoned = True
            raise RawLogCorruption(f"write raw record; writer poisoned: {exc}") from exc
        self._previous_digest = digest.hex()
        self._next_index[key] = expected + 1
        record_index = self._record_count
        self._record_count += 1
        self._end_offset += len(encoded)
        self._since_sync += 1
        durability_ack = None
        if self._since_sync >= self._sync_every:
            durability_ack = self.sync()
        return AppendReceiptV1(
            schema="AppendReceiptV1",
            record_index=record_index,
            end_offset=self._end_offset,
            record_sha256=self._previous_digest,
            durability_ack=durability_ack,
        )

    def sync(self) -> DurabilityAckV1:
        if self._closed:
            raise ValueError("raw log is closed")
        if self._poisoned:
            raise RawLogCorruption("raw writer is poisoned")
        try:
            self._file.flush()
            os.fsync(self._file.fileno())
        except Exception as exc:
            self._poisoned = True
            raise RawLogCorruption(f"sync raw log; writer poisoned: {exc}") from exc
        self._since_sync = 0
        ack = DurabilityAckV1(
            schema="DurabilityAckV1",
            durable_record_count=self._record_count,
            durable_through_offset=self._end_offset,
            last_record_sha256=self._previous_digest,
            streams=self._watermarks(),
        )
        self._last_ack = ack
        return ack

    def close(self) -> DurabilityAckV1 | None:
        if not self._closed:
            try:
                if not self._poisoned:
                    self.sync()
            finally:
                self._file.close()
                self._closed = True
        return self._last_ack

    def __enter__(self) -> "RawLogWriter":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _read_exact_or_partial(handle: BinaryIO, size: int) -> bytes:
    return handle.read(size)


def scan_raw_log(path: Path) -> RawLogScan:
    path = Path(path)
    file_size = path.stat().st_size
    records = 0
    last_good_offset = 0
    previous = ZERO_DIGEST
    next_index: dict[tuple[str, str], int] = {}
    reason: str | None = None
    with path.open("rb") as handle:
        if handle.read(len(MAGIC)) != MAGIC:
            return RawLogScan(path, file_size, 0, 0, False, "bad magic", ZERO_DIGEST, ())
        last_good_offset = len(MAGIC)
        while True:
            prefix = handle.read(LENGTH.size)
            if prefix == b"":
                break
            if len(prefix) != LENGTH.size:
                reason = "partial length prefix"
                break
            (body_length,) = LENGTH.unpack(prefix)
            if body_length > MAX_RECORD_BYTES:
                reason = "record length exceeds limit"
                break
            body = _read_exact_or_partial(handle, body_length)
            if len(body) != body_length:
                reason = "partial record body"
                break
            digest = _read_exact_or_partial(handle, DIGEST_SIZE)
            if len(digest) != DIGEST_SIZE:
                reason = "partial record digest"
                break
            actual = sha256(body).digest()
            if actual != digest:
                reason = "record digest mismatch"
                break
            try:
                record = json.loads(body)
                if not isinstance(record, dict):
                    raise RawLogCorruption("record is not an object")
                if record.get("previous_record_sha256") != previous:
                    raise RawLogCorruption("record chain mismatch")
                frame = _frame_from_record(record)
                key = (frame.connection_epoch, frame.stream)
                expected = next_index.get(key, 0)
                if frame.frame_index != expected:
                    raise RawLogCorruption(
                        f"non-contiguous frame index: expected {expected}, got {frame.frame_index}"
                    )
                next_index[key] = expected + 1
            except (json.JSONDecodeError, RawLogCorruption, UnicodeDecodeError) as exc:
                reason = str(exc)
                break
            previous = digest.hex()
            records += 1
            last_good_offset = handle.tell()
    return RawLogScan(
        path=path,
        file_size=file_size,
        records=records,
        last_good_offset=last_good_offset,
        clean_eof=reason is None,
        reason=reason,
        last_record_sha256=previous,
        streams=tuple(
            StreamDurabilityWatermarkV1(epoch, stream, expected - 1)
            for (epoch, stream), expected in sorted(next_index.items())
            if expected > 0
        ),
    )


def recover_raw_log_prefix(source: Path, destination: Path) -> RawRecoveryV1:
    source = Path(source)
    destination = Path(destination)
    source_scan = scan_raw_log(source)
    if source_scan.clean_eof:
        raise ValueError("source raw log already has a clean EOF")
    if source_scan.last_good_offset < len(MAGIC):
        raise RawLogCorruption("source has no recoverable BNRAW prefix")
    destination.parent.mkdir(parents=True, exist_ok=True)
    copied = 0
    with source.open("rb") as input_handle, destination.open("xb", buffering=0) as output_handle:
        remaining = source_scan.last_good_offset
        while remaining:
            chunk = input_handle.read(min(1024 * 1024, remaining))
            if not chunk:
                raise RawLogCorruption("short recovery read")
            view = memoryview(chunk)
            while view:
                written = output_handle.write(view)
                if written is None or written <= 0:
                    raise RawLogCorruption("short recovery write")
                view = view[written:]
                copied += written
                remaining -= written
        output_handle.flush()
        os.fsync(output_handle.fileno())
    recovered_scan = scan_raw_log(destination)
    if (
        not recovered_scan.clean_eof
        or recovered_scan.records != source_scan.records
        or recovered_scan.last_record_sha256 != source_scan.last_record_sha256
    ):
        raise RawLogCorruption("recovered raw prefix failed verification")
    return RawRecoveryV1(
        schema="RawRecoveryV1",
        source=source,
        destination=destination,
        source_file_size=source_scan.file_size,
        copied_valid_prefix_bytes=copied,
        excluded_tail_bytes=source_scan.file_size - copied,
        recovered_records=recovered_scan.records,
        last_record_sha256=recovered_scan.last_record_sha256,
    )


def iter_raw_records(path: Path) -> Iterator[RawRecordEnvelopeV1]:
    scan = scan_raw_log(path)
    if not scan.clean_eof:
        raise RawLogCorruption(f"cannot replay corrupt/incomplete log: {scan.reason}")
    with Path(path).open("rb") as handle:
        handle.seek(len(MAGIC))
        record_index = 0
        previous = ZERO_DIGEST
        next_index: dict[tuple[str, str], int] = {}
        while handle.tell() < scan.last_good_offset:
            start_offset = handle.tell()
            prefix = handle.read(LENGTH.size)
            if len(prefix) != LENGTH.size:
                raise RawLogCorruption("raw log changed during replay: partial length prefix")
            (body_length,) = LENGTH.unpack(prefix)
            if body_length > MAX_RECORD_BYTES:
                raise RawLogCorruption("raw log changed during replay: record length exceeds limit")
            body = handle.read(body_length)
            if len(body) != body_length:
                raise RawLogCorruption("raw log changed during replay: partial record body")
            digest = handle.read(DIGEST_SIZE)
            if len(digest) != DIGEST_SIZE or sha256(body).digest() != digest:
                raise RawLogCorruption("raw log changed during replay: record digest mismatch")
            try:
                record = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise RawLogCorruption("raw log changed during replay: invalid record JSON") from exc
            if not isinstance(record, dict) or record.get("previous_record_sha256") != previous:
                raise RawLogCorruption("raw log changed during replay: record chain mismatch")
            frame = _frame_from_record(record)
            key = (frame.connection_epoch, frame.stream)
            expected = next_index.get(key, 0)
            if frame.frame_index != expected:
                raise RawLogCorruption(
                    f"raw log changed during replay: expected frame {expected}, "
                    f"got {frame.frame_index}"
                )
            next_index[key] = expected + 1
            yield RawRecordEnvelopeV1(
                schema="RawRecordEnvelopeV1",
                record_index=record_index,
                start_offset=start_offset,
                end_offset=handle.tell(),
                record_sha256=digest.hex(),
                frame=frame,
            )
            previous = digest.hex()
            record_index += 1


def iter_raw_frames(path: Path) -> Iterator[RawFrameV1]:
    for record in iter_raw_records(path):
        yield record.frame


def first_raw_segment_record(path: Path) -> RawRecordEnvelopeV1:
    """The first complete record of a root segment (ZERO_DIGEST predecessor,
    frame 0), whose frame carries the segment's own identity.  Used by the
    live-arbitration verifier to bind an interrupted root segment's BNACK
    boundary to the exact stream identity without inventing one."""
    with Path(path).open("rb") as handle:
        magic = handle.read(len(MAGIC))
        if magic != MAGIC:
            raise RawLogCorruption("bad raw segment magic")
        prefix = handle.read(LENGTH.size)
        if len(prefix) != LENGTH.size:
            raise RawLogCorruption("root segment has no complete first record")
        (body_length,) = LENGTH.unpack(prefix)
        if body_length > MAX_RECORD_BYTES:
            raise RawLogCorruption("root segment record length exceeds limit")
        body = handle.read(body_length)
        if len(body) != body_length:
            raise RawLogCorruption("root segment first record is partial")
        digest = handle.read(DIGEST_SIZE)
        if len(digest) != DIGEST_SIZE or sha256(body).digest() != digest:
            raise RawLogCorruption("root segment first record digest mismatch")
        try:
            record = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RawLogCorruption("root segment first record is not JSON") from exc
        if not isinstance(record, dict) or record.get("previous_record_sha256") != ZERO_DIGEST:
            raise RawLogCorruption("root segment first record chain mismatch")
        frame = _frame_from_record(record)
        if frame.frame_index != 0:
            raise RawLogCorruption("root segment first record frame index mismatch")
        return RawRecordEnvelopeV1(
            schema="RawRecordEnvelopeV1",
            record_index=0,
            start_offset=len(MAGIC),
            end_offset=handle.tell(),
            record_sha256=digest.hex(),
            frame=frame,
        )


def _scan_segment_boundary(
    path: Path,
    previous_digest: str,
    next_frame_index: int,
    connection_epoch: str,
    stream: str,
) -> int:
    """Byte offset just past the last complete record that verifies against
    THIS segment's genesis chain (mirrors the Rust `scan_raw_segment`).  A
    live in-flight segment may end with a partial tail; only the verified
    prefix is usable."""
    offset = len(MAGIC)
    previous = previous_digest
    next_index = {(connection_epoch, stream): next_frame_index}
    with Path(path).open("rb") as handle:
        magic = handle.read(len(MAGIC))
        if magic != MAGIC:
            raise RawLogCorruption("bad raw segment magic")
        while True:
            record_start = handle.tell()
            prefix = handle.read(LENGTH.size)
            if len(prefix) == 0:
                return record_start
            if len(prefix) != LENGTH.size:
                return record_start
            (body_length,) = LENGTH.unpack(prefix)
            if body_length > MAX_RECORD_BYTES:
                return record_start
            body = handle.read(body_length)
            if len(body) != body_length:
                return record_start
            digest = handle.read(DIGEST_SIZE)
            if len(digest) != DIGEST_SIZE or sha256(body).digest() != digest:
                return record_start
            try:
                record = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return record_start
            if not isinstance(record, dict) or record.get("previous_record_sha256") != previous:
                return record_start
            frame = _frame_from_record(record)
            if (frame.connection_epoch, frame.stream) != (connection_epoch, stream):
                return record_start
            expected = next_index[(connection_epoch, stream)]
            if frame.frame_index != expected:
                return record_start
            next_index[(connection_epoch, stream)] = expected + 1
            previous = digest.hex()
            offset = handle.tell()
    return offset


def iter_raw_segment_records(
    path: Path,
    previous_digest: str,
    next_frame_index: int,
    connection_epoch: str,
    stream: str,
) -> Iterator[RawRecordEnvelopeV1]:
    """Reads one raw segment whose chain starts at the predecessor's terminal
    digest, mirroring the Rust `read_raw_segment_records`.  Used by the
    independent live-arbitration verifier to materialize the untouched lane
    as the failover oracle without concatenating raw files."""
    if len(previous_digest) != 64 or next_frame_index < 0 or not connection_epoch or not stream:
        raise RawLogCorruption("segment genesis is invalid")
    boundary = _scan_segment_boundary(
        path, previous_digest, next_frame_index, connection_epoch, stream
    )
    with Path(path).open("rb") as handle:
        handle.seek(len(MAGIC))
        record_index = 0
        previous = previous_digest
        next_index = {(connection_epoch, stream): next_frame_index}
        while handle.tell() < boundary:
            start_offset = handle.tell()
            prefix = handle.read(LENGTH.size)
            if len(prefix) != LENGTH.size:
                raise RawLogCorruption("segment changed during replay: partial length prefix")
            (body_length,) = LENGTH.unpack(prefix)
            if body_length > MAX_RECORD_BYTES:
                raise RawLogCorruption("segment changed during replay: record length exceeds limit")
            body = handle.read(body_length)
            if len(body) != body_length:
                raise RawLogCorruption("segment changed during replay: partial record body")
            digest = handle.read(DIGEST_SIZE)
            if len(digest) != DIGEST_SIZE or sha256(body).digest() != digest:
                raise RawLogCorruption("segment changed during replay: record digest mismatch")
            try:
                record = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise RawLogCorruption(
                    "segment changed during replay: invalid record JSON"
                ) from exc
            if not isinstance(record, dict) or record.get("previous_record_sha256") != previous:
                raise RawLogCorruption("segment changed during replay: record chain mismatch")
            frame = _frame_from_record(record)
            if (frame.connection_epoch, frame.stream) != (connection_epoch, stream):
                raise RawLogCorruption("segment changed during replay: stream identity mismatch")
            expected = next_index[(connection_epoch, stream)]
            if frame.frame_index != expected:
                raise RawLogCorruption(
                    f"segment changed during replay: expected frame {expected}, "
                    f"got {frame.frame_index}"
                )
            next_index[(connection_epoch, stream)] = expected + 1
            yield RawRecordEnvelopeV1(
                schema="RawRecordEnvelopeV1",
                record_index=record_index,
                start_offset=start_offset,
                end_offset=handle.tell(),
                record_sha256=digest.hex(),
                frame=frame,
            )
            previous = digest.hex()
            record_index += 1


def iter_raw_segment_prefix(
    path: Path,
    previous_digest: str,
    next_frame_index: int,
    connection_epoch: str,
    stream: str,
    end_offset: int,
) -> Iterator[RawRecordEnvelopeV1]:
    """Reads one raw segment's BNACK-authorized durable prefix
    `[magic, end_offset)` against this segment's genesis chain, mirroring the
    Rust `read_raw_record_range`.  Used by the independent live-arbitration
    verifier to bound an interrupted root segment at its exact durability
    boundary instead of any complete-but-unacknowledged tail."""
    if len(previous_digest) != 64 or next_frame_index < 0 or not connection_epoch or not stream:
        raise RawLogCorruption("segment genesis is invalid")
    if end_offset <= len(MAGIC):
        return
    with Path(path).open("rb") as handle:
        handle.seek(len(MAGIC))
        record_index = 0
        previous = previous_digest
        next_index = {(connection_epoch, stream): next_frame_index}
        while handle.tell() < end_offset:
            start_offset = handle.tell()
            prefix = handle.read(LENGTH.size)
            if len(prefix) != LENGTH.size:
                raise RawLogCorruption("segment changed during replay: partial length prefix")
            (body_length,) = LENGTH.unpack(prefix)
            if body_length > MAX_RECORD_BYTES:
                raise RawLogCorruption("segment changed during replay: record length exceeds limit")
            body = handle.read(body_length)
            if len(body) != body_length:
                raise RawLogCorruption("segment changed during replay: partial record body")
            digest = handle.read(DIGEST_SIZE)
            if len(digest) != DIGEST_SIZE or sha256(body).digest() != digest:
                raise RawLogCorruption("segment changed during replay: record digest mismatch")
            try:
                record = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise RawLogCorruption(
                    "segment changed during replay: invalid record JSON"
                ) from exc
            if not isinstance(record, dict) or record.get("previous_record_sha256") != previous:
                raise RawLogCorruption("segment changed during replay: record chain mismatch")
            frame = _frame_from_record(record)
            if (frame.connection_epoch, frame.stream) != (connection_epoch, stream):
                raise RawLogCorruption("segment changed during replay: stream identity mismatch")
            expected = next_index[(connection_epoch, stream)]
            if frame.frame_index != expected:
                raise RawLogCorruption(
                    f"segment changed during replay: expected frame {expected}, "
                    f"got {frame.frame_index}"
                )
            next_index[(connection_epoch, stream)] = expected + 1
            yield RawRecordEnvelopeV1(
                schema="RawRecordEnvelopeV1",
                record_index=record_index,
                start_offset=start_offset,
                end_offset=handle.tell(),
                record_sha256=digest.hex(),
                frame=frame,
            )
            previous = digest.hex()
            record_index += 1
        if handle.tell() != end_offset:
            raise RawLogCorruption("durable prefix does not end on a record boundary")
