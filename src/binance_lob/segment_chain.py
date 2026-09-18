"""Independent verifier for Rust segmented raw-capture generations.

The manifest and raw logs are treated as immutable byte-level evidence.  This
module deliberately does not derive order-book state, trades, features, or
market metrics.
"""

from __future__ import annotations

from base64 import b64decode
from dataclasses import dataclass, field
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import struct
from typing import BinaryIO, NoReturn


RAW_MAGIC = b"BNRAW\x00\x01\n"
MANIFEST_MAGIC = b"BNSEG\x00\x01\n"
LENGTH = struct.Struct(">I")
DIGEST_BYTES = 32
MAX_RAW_RECORD_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_RECORD_BYTES = 1024 * 1024
MAX_GENERATION_JSON_BYTES = 1024 * 1024
MAX_TRANSPORT_JOURNAL_BYTES = 64 * 1024 * 1024
ZERO_DIGEST = "0" * 64
SPEC_REVISION = "976cc580553890e92031b77306147c0ed1de5a46"
MARKET_FRESHNESS_STARTUP_GRACE_S = 30
MARKET_FRESHNESS_DEADLINE_S = 30
U64_MAX = (1 << 64) - 1
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1

_RAW_KEYS = (
    "schema",
    "venue",
    "environment",
    "endpoint",
    "stream",
    "symbol",
    "connection_epoch",
    "frame_index",
    "receive_wall_ns",
    "receive_mono_ns",
    "clock_quality",
    "clock_source",
    "clock_offset_ns",
    "clock_uncertainty_ns",
    "payload_length",
    "payload_sha256",
    "payload_base64",
    "recorder_state",
    "spec_revision",
    "previous_record_sha256",
)
_MANIFEST_KEYS = (
    "schema",
    "record_index",
    "previous_manifest_record_sha256",
    "seal",
)
_SEAL_KEYS = (
    "schema",
    "segment_index",
    "raw_file",
    "connection_epoch",
    "stream",
    "first_frame_index",
    "last_frame_index",
    "records",
    "durable_through_offset",
    "previous_segment_terminal_sha256",
    "terminal_record_sha256",
)
_GENERATION_KEYS = (
    "schema",
    "implementation",
    "session_id",
    "generation_index",
    "status",
    "symbol",
    "duration_requested_s",
    "segment_duration_s",
    "started_wall_ns",
    "finished_wall_ns",
    "collector_executable_sha256",
    "public_config_sha256",
    "market_freshness_startup_grace_s",
    "market_freshness_deadline_s",
    "credentials",
    "order_entry",
    "raw_boundary",
    "spec_revision",
    "startup_file",
    "startup_sha256",
    "failure",
    "snapshot",
    "telemetry",
    "streams",
)
_SNAPSHOT_KEYS = (
    "endpoint",
    "http_status",
    "last_update_id",
    "bid_levels",
    "ask_levels",
    "raw_file",
    "durability_ack",
    "http_metadata_file",
    "http_metadata_sha256",
)
_STREAM_KEYS = (
    "name",
    "uri",
    "connection_epoch",
    "transport_metadata_file",
    "transport_metadata_sha256",
    "transport_journal",
    "received",
    "written",
    "durable_records",
    "segments",
    "last_socket_activity_mono_ns",
    "last_market_message_mono_ns",
    "server_shutdown_events",
    "segment_manifest",
    "segment_manifest_sha256",
    "terminal_raw_sha256",
    "error",
)
_TRANSPORT_JOURNAL_SEAL_KEYS = (
    "schema",
    "file",
    "records",
    "terminal_record_sha256",
    "file_bytes",
    "file_sha256",
)
_TRANSPORT_JOURNAL_ENVELOPE_KEYS = ("body", "record_sha256")
_TRANSPORT_JOURNAL_BODY_KEYS = (
    "schema",
    "record_index",
    "wall_ns",
    "mono_ns",
    "stream",
    "connection_epoch",
    "event",
    "payload",
    "previous_record_sha256",
)
_WINDOWS_TCP_INFO_KEYS = (
    "api",
    "api_version",
    "bytes_in",
    "bytes_in_flight",
    "bytes_out",
    "bytes_reordered",
    "bytes_retransmitted",
    "congestion_window_bytes",
    "connection_time_ms",
    "duplicate_acks_in",
    "fast_retransmits",
    "min_rtt_us",
    "mss",
    "receive_buffer_bytes",
    "receive_window_bytes",
    "rtt_us",
    "schema",
    "send_window_bytes",
    "state",
    "state_name",
    "syn_retransmits",
    "timeout_episodes",
    "timestamps_enabled",
)
_ACK_KEYS = (
    "schema",
    "durable_record_count",
    "durable_through_offset",
    "last_record_sha256",
    "streams",
)
_WATERMARK_KEYS = (
    "connection_epoch",
    "stream",
    "durable_through_frame_index",
)
_STARTUP_KEYS = (
    "schema",
    "implementation",
    "session_id",
    "generation_index",
    "symbol",
    "duration_requested_s",
    "segment_duration_s",
    "started_wall_ns",
    "collector_executable_sha256",
    "public_config_sha256",
    "market_freshness_startup_grace_s",
    "market_freshness_deadline_s",
    "credentials",
    "order_entry",
    "raw_boundary",
    "spec_revision",
)
_HTTP_METADATA_KEYS = (
    "schema",
    "endpoint",
    "http_status",
    "headers",
    "receive_wall_ns",
    "receive_mono_ns",
    "body_complete",
    "body_length",
    "body_sha256",
    "raw_file",
    "raw_record_sha256",
)
_TELEMETRY_ARTIFACT_KEYS = (
    "schema",
    "file",
    "records",
    "durable_through_offset",
    "terminal_record_sha256",
    "terminal_mono_ns",
    "file_sha256",
)
_TRANSPORT_METADATA_KEYS = (
    "schema",
    "session_id",
    "generation_index",
    "symbol",
    "spec_revision",
    "connection",
)
_TRANSPORT_CONNECTION_KEYS = (
    "stream",
    "connection_epoch",
    "uri",
    "websocket_http_status",
    "local_endpoint",
    "remote_endpoint",
    "response_headers",
)
_TELEMETRY_CLOCK_KEYS = (
    "quality",
    "source",
    "leap_indicator",
    "stratum",
    "last_successful_sync",
)
_TELEMETRY_RECORD_KEYS = (
    "schema",
    "record_index",
    "wall_ns",
    "mono_ns",
    "clock",
    "depth_received",
    "depth_written",
    "depth_durable",
    "depth_segment",
    "depth_last_socket_activity_mono_ns",
    "depth_last_market_message_mono_ns",
    "depth_last_durable_mono_ns",
    "depth_queue_records",
    "depth_queue_bytes",
    "depth_max_queue_records",
    "depth_max_queue_bytes",
    "depth_max_queue_age_ns",
    "depth_last_sync_duration_ns",
    "depth_max_sync_duration_ns",
    "trade_received",
    "trade_written",
    "trade_durable",
    "trade_segment",
    "trade_last_socket_activity_mono_ns",
    "trade_last_market_message_mono_ns",
    "trade_last_durable_mono_ns",
    "trade_queue_records",
    "trade_queue_bytes",
    "trade_max_queue_records",
    "trade_max_queue_bytes",
    "trade_max_queue_age_ns",
    "trade_last_sync_duration_ns",
    "trade_max_sync_duration_ns",
)
_PROGRESS_ENVELOPE_KEYS = ("body", "record_sha256")
_PROGRESS_BODY_KEYS = (
    "schema",
    "record_index",
    "raw_path",
    "ack",
    "previous_record_sha256",
)


class SegmentChainCorruption(ValueError):
    """The segmented generation is incomplete, ambiguous, or corrupt."""


@dataclass(frozen=True, slots=True)
class _RawExpectations:
    connection_epoch: str
    stream: str
    first_frame_index: int
    initial_previous_sha256: str
    symbol: str
    endpoint: str
    spec_revision: str


@dataclass(frozen=True, slots=True)
class _RawScan:
    file_size: int
    records: int
    last_good_offset: int
    first_frame_index: int | None
    last_frame_index: int | None
    last_record_sha256: str
    file_sha256: str
    captured_record: "_RawRecordInfo | None"
    captured_records: "tuple[_RawRecordInfo, ...] | None"


@dataclass(frozen=True, slots=True)
class _RawRecordInfo:
    payload: bytes
    record_sha256: str
    receive_wall_ns: int
    receive_mono_ns: int


@dataclass(slots=True)
class _SequenceState:
    started: bool = False
    first: int | None = None
    final: int | None = None
    previous_receive_mono_ns: int | None = None
    last_market_mono_ns: int = 0
    first_active_market_mono_ns: int | None = None
    last_active_market_mono_ns: int | None = None
    freshness_active_end_ns: int | None = None
    server_shutdown_events: int = 0
    server_shutdowns: list[dict[str, object]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _ProgressScan:
    file_size: int
    records: int
    last_record_sha256: str
    file_sha256: str
    acknowledgements: tuple[dict[str, object], ...]


@dataclass(frozen=True, slots=True)
class _ManifestScan:
    file_size: int
    records: int
    last_good_offset: int
    last_record_sha256: str
    file_sha256: str
    seals: tuple[dict[str, object], ...]


def _fail(reason: str) -> NoReturn:
    raise SegmentChainCorruption(reason)


def _object_from_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON field {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    _fail(f"non-finite JSON number {value}")


def _parse_json(body: bytes, label: str) -> object:
    try:
        text = body.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_json_constant,
        )
    except SegmentChainCorruption:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"invalid {label} JSON: {exc.msg if isinstance(exc, json.JSONDecodeError) else exc}")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _fail(f"cannot canonicalize JSON: {exc}")


def _pretty_json(value: object) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _fail(f"cannot encode pretty JSON: {exc}")


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value


def _ordered_keys(value: dict[str, object], expected: tuple[str, ...], label: str) -> None:
    actual = tuple(value)
    if actual != expected:
        _fail(f"{label} has unknown, missing, or reordered fields")


def _text(value: dict[str, object], field: str, label: str, *, nonempty: bool = True) -> str:
    item = value.get(field)
    if not isinstance(item, str) or (nonempty and not item.strip()):
        _fail(f"{label}.{field} must be a non-empty string")
    return item


def _u64(value: dict[str, object], field: str, label: str) -> int:
    item = value.get(field)
    if type(item) is not int or item < 0 or item > U64_MAX:
        _fail(f"{label}.{field} must be a u64")
    return item


def _usize(value: dict[str, object], field: str, label: str) -> int:
    # The capture binary is 64-bit; constrain host-sized counters to u64.
    return _u64(value, field, label)


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _nullable_i64(value: object, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < I64_MIN or value > I64_MAX:
        _fail(f"{label} must be null or an i64")
    return value


def _nullable_u64(value: object, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0 or value > U64_MAX:
        _fail(f"{label} must be null or a u64")
    return value


def _relative_parts(value: object, label: str, *, count: int | None = None) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or value != value.strip():
        _fail(f"{label} must be a relative path")
    if "\\" in value or "\x00" in value or ":" in value or value.startswith("/"):
        _fail(f"{label} is not a safe relative path")
    parts = tuple(value.split("/"))
    if any(not part or part in {".", ".."} for part in parts):
        _fail(f"{label} is not a safe relative path")
    if count is not None and len(parts) != count:
        _fail(f"{label} has an invalid path depth")
    return parts


def _is_linklike(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (is_junction is not None and bool(is_junction()))


def _safe_file(root: Path, relative: str, label: str) -> Path:
    parts = _relative_parts(relative, label)
    root_resolved = root.resolve(strict=True)
    candidate = root.joinpath(*parts)
    current = root
    for part in parts:
        current = current / part
        if _is_linklike(current):
            _fail(f"{label} must not traverse a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        _fail(f"{label} is missing or inaccessible: {exc.strerror or exc}")
    try:
        resolved.relative_to(root_resolved)
    except ValueError:
        _fail(f"{label} escapes the generation directory")
    if not resolved.is_file():
        _fail(f"{label} is not a regular file")
    return resolved


def _read_exact(handle: BinaryIO, size: int, reason: str) -> bytes:
    value = handle.read(size)
    if len(value) != size:
        _fail(reason)
    return value


def _validate_raw_record(
    record: dict[str, object],
    body: bytes,
    expected: _RawExpectations,
    frame_index: int,
    previous_digest: str,
    record_digest: str,
) -> _RawRecordInfo:
    _ordered_keys(record, _RAW_KEYS, "raw record")
    if _canonical_json(record) != body:
        _fail("raw record JSON is not the canonical Rust encoding")
    if _text(record, "schema", "raw record") != "RawFrameV1":
        _fail("unknown raw record schema")
    if _text(record, "previous_record_sha256", "raw record") != previous_digest:
        _fail("raw record hash-chain mismatch")
    _digest(record["previous_record_sha256"], "raw record.previous_record_sha256")
    if _text(record, "recorder_state", "raw record") != "PENDING":
        _fail("segmented capture raw record state is not PENDING")

    payload_text = _text(record, "payload_base64", "raw record", nonempty=False)
    try:
        payload = b64decode(payload_text, validate=True)
    except ValueError as exc:
        _fail(f"invalid raw payload base64: {exc}")
    if len(payload) != _u64(record, "payload_length", "raw record"):
        _fail("raw payload length mismatch")
    payload_digest = _digest(record.get("payload_sha256"), "raw record.payload_sha256")
    if sha256(payload).hexdigest() != payload_digest:
        _fail("raw payload digest mismatch")

    if _text(record, "connection_epoch", "raw record") != expected.connection_epoch:
        _fail("raw segment connection epoch mismatch")
    if _text(record, "stream", "raw record") != expected.stream:
        _fail("raw segment stream identity mismatch")
    if _u64(record, "frame_index", "raw record") != frame_index:
        _fail(f"non-contiguous raw frame index; expected {frame_index}")
    if _text(record, "symbol", "raw record") != expected.symbol:
        _fail("raw record symbol differs from generation")
    if _text(record, "endpoint", "raw record") != expected.endpoint:
        _fail("raw record endpoint differs from generation")
    if _text(record, "spec_revision", "raw record") != expected.spec_revision:
        _fail("raw record spec revision differs from generation")
    if _text(record, "venue", "raw record") != "binance-spot":
        _fail("raw record venue differs from segmented capture contract")
    if _text(record, "environment", "raw record") != "production-public-market-data":
        _fail("raw record environment differs from segmented capture contract")
    receive_wall_ns = _u64(record, "receive_wall_ns", "raw record")
    receive_mono_ns = _u64(record, "receive_mono_ns", "raw record")
    _text(record, "clock_quality", "raw record")
    _text(record, "clock_source", "raw record")
    _nullable_i64(record.get("clock_offset_ns"), "raw record.clock_offset_ns")
    _nullable_u64(record.get("clock_uncertainty_ns"), "raw record.clock_uncertainty_ns")
    return _RawRecordInfo(
        payload=payload,
        record_sha256=record_digest,
        receive_wall_ns=receive_wall_ns,
        receive_mono_ns=receive_mono_ns,
    )


def _levels(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        _fail(f"{label} is not an array")
    for level in value:
        if (
            not isinstance(level, list)
            or len(level) != 2
            or not isinstance(level[0], str)
            or not isinstance(level[1], str)
        ):
            _fail(f"{label} contains a non price/quantity pair")
    return value


def _validate_application_payload(
    record: _RawRecordInfo,
    stream_kind: str,
    symbol: str,
    snapshot_sequence: int,
    sequence: _SequenceState,
) -> bool:
    if (
        sequence.previous_receive_mono_ns is not None
        and record.receive_mono_ns < sequence.previous_receive_mono_ns
    ):
        _fail(f"{stream_kind} receive monotonic time regressed")
    sequence.previous_receive_mono_ns = record.receive_mono_ns
    value = _object(
        _parse_json(record.payload, f"{stream_kind} payload"),
        f"{stream_kind} payload",
    )
    if value.get("e") == "serverShutdown":
        _u64(value, "E", "serverShutdown payload")
        if sequence.server_shutdown_events == U64_MAX:
            _fail("serverShutdown event count overflow")
        sequence.server_shutdown_events += 1
        return True
    if value.get("e") != ("depthUpdate" if stream_kind == "depth" else "trade"):
        _fail(f"{stream_kind} event identity is invalid")
    if value.get("s") != symbol:
        _fail(f"{stream_kind} event symbol is invalid")
    _u64(value, "E", f"{stream_kind} payload")
    _observe_market_message(record, stream_kind, sequence)
    if stream_kind == "depth":
        first = _u64(value, "U", "depth payload")
        final = _u64(value, "u", "depth payload")
        if first > final:
            _fail("depth update range is inverted")
        _levels(value.get("b"), "depth bids")
        _levels(value.get("a"), "depth asks")
        if not sequence.started:
            if final <= snapshot_sequence:
                return False
            if snapshot_sequence == U64_MAX:
                _fail("snapshot sequence overflow")
            bridge = snapshot_sequence + 1
            if first > bridge or final < bridge:
                _fail("depth stream cannot bridge its durable snapshot")
            sequence.started = True
            sequence.first = first
            sequence.final = final
            return False
        assert sequence.final is not None
        if sequence.final == U64_MAX:
            _fail("depth sequence overflow")
        next_sequence = sequence.final + 1
        if first > next_sequence or final < next_sequence:
            _fail(
                "depth update discontinuity: "
                f"expected coverage of {next_sequence}, got {first}..{final}"
            )
        sequence.final = final
        return False

    trade_id = _u64(value, "t", "trade payload")
    _u64(value, "T", "trade payload")
    for field in ("p", "q"):
        if not isinstance(value.get(field), str):
            _fail(f"trade field {field} is not a decimal string")
    for field in ("m", "M"):
        if type(value.get(field)) is not bool:
            _fail(f"trade field {field} is not boolean")
    if sequence.final is not None and trade_id <= sequence.final:
        _fail(
            "trade ID duplicated or regressed: "
            f"previous {sequence.final}, got {trade_id}"
        )
    if not sequence.started:
        sequence.started = True
        sequence.first = trade_id
    # Binance does not promise t+1 delivery; only strict increase is valid.
    sequence.final = trade_id
    return False


def _observe_market_message(
    record: _RawRecordInfo,
    stream_kind: str,
    sequence: _SequenceState,
) -> None:
    """Track raw market-message freshness without treating controls as data."""

    sequence.last_market_mono_ns = record.receive_mono_ns
    active_end_ns = sequence.freshness_active_end_ns
    if active_end_ns is None or record.receive_mono_ns > active_end_ns:
        return
    previous = sequence.last_active_market_mono_ns
    deadline_ns = MARKET_FRESHNESS_DEADLINE_S * 1_000_000_000
    if previous is not None and record.receive_mono_ns - previous > deadline_ns:
        _fail(
            f"{stream_kind} raw market-message gap exceeds "
            f"{MARKET_FRESHNESS_DEADLINE_S}s"
        )
    if sequence.first_active_market_mono_ns is None:
        sequence.first_active_market_mono_ns = record.receive_mono_ns
    sequence.last_active_market_mono_ns = record.receive_mono_ns


def _validate_raw_market_freshness(
    sequence: _SequenceState,
    stream_kind: str,
    active_end_ns: int,
) -> None:
    """Prove startup and tail freshness from immutable BNRAW timestamps."""

    first = sequence.first_active_market_mono_ns
    last = sequence.last_active_market_mono_ns
    startup_limit_ns = min(
        active_end_ns,
        MARKET_FRESHNESS_STARTUP_GRACE_S * 1_000_000_000,
    )
    if first is None or last is None:
        _fail(f"{stream_kind} has no raw market message in its active window")
    if first > startup_limit_ns:
        _fail(
            f"{stream_kind} first raw market message exceeds "
            f"{MARKET_FRESHNESS_STARTUP_GRACE_S}s startup grace"
        )
    deadline_ns = MARKET_FRESHNESS_DEADLINE_S * 1_000_000_000
    if active_end_ns - last > deadline_ns:
        _fail(
            f"{stream_kind} raw market-message tail exceeds "
            f"{MARKET_FRESHNESS_DEADLINE_S}s"
        )


def _scan_raw_segment(
    path: Path,
    expected: _RawExpectations,
    *,
    capture_payload: bool = False,
    capture_records: bool = False,
    acknowledgements: tuple[dict[str, object], ...] = (),
    stream_kind: str | None = None,
    snapshot_sequence: int = 0,
    sequence: _SequenceState | None = None,
    segment_index: int | None = None,
    segment_duration_ns: int | None = None,
    require_server_shutdown_ack: bool = False,
) -> _RawScan:
    if (segment_index is None) != (segment_duration_ns is None):
        _fail("raw segment monotonic bounds are incomplete")
    if segment_index is not None and (
        segment_index < 0
        or segment_index > U64_MAX
        or segment_duration_ns is None
        or segment_duration_ns <= 0
        or segment_duration_ns > U64_MAX
    ):
        _fail("raw segment monotonic bounds are invalid")
    previous_digest = _digest(expected.initial_previous_sha256, "raw genesis digest")
    next_frame = expected.first_frame_index
    records = 0
    file_hasher = sha256()
    retained_record: _RawRecordInfo | None = None
    retained_records: list[_RawRecordInfo] | None = [] if capture_records else None
    checkpoints = {
        int(ack["durable_record_count"]): ack for ack in acknowledgements
    }
    if len(checkpoints) != len(acknowledgements):
        _fail("durability ACK record counts are duplicated")
    matched_checkpoints = 0
    try:
        with path.open("rb", buffering=0) as handle:
            initial_stat = os.fstat(handle.fileno())
            magic = _read_exact(handle, len(RAW_MAGIC), "bad raw log magic")
            if magic != RAW_MAGIC:
                _fail("bad raw log magic")
            file_hasher.update(magic)
            while True:
                prefix = handle.read(LENGTH.size)
                if prefix == b"":
                    break
                if len(prefix) != LENGTH.size:
                    _fail("partial raw length prefix")
                file_hasher.update(prefix)
                (body_length,) = LENGTH.unpack(prefix)
                if body_length > MAX_RAW_RECORD_BYTES:
                    _fail("raw record length exceeds limit")
                body = _read_exact(handle, body_length, "partial raw record body")
                stored_digest = _read_exact(handle, DIGEST_BYTES, "partial raw record digest")
                file_hasher.update(body)
                file_hasher.update(stored_digest)
                actual_digest = sha256(body).digest()
                if actual_digest != stored_digest:
                    _fail("raw record digest mismatch")
                record = _object(_parse_json(body, "raw record"), "raw record")
                record_info = _validate_raw_record(
                    record,
                    body,
                    expected,
                    next_frame,
                    previous_digest,
                    stored_digest.hex(),
                )
                if (
                    segment_index is not None
                    and segment_duration_ns is not None
                    and record_info.receive_mono_ns // segment_duration_ns
                    != segment_index
                ):
                    _fail(
                        f"{stream_kind or 'raw'} record is outside its declared "
                        "monotonic segment"
                    )
                if capture_payload and records == 0:
                    retained_record = record_info
                if retained_records is not None:
                    retained_records.append(record_info)
                previous_digest = stored_digest.hex()
                records += 1
                checkpoint = checkpoints.get(records)
                if checkpoint is not None:
                    streams = checkpoint["streams"]
                    if not isinstance(streams, list) or len(streams) != 1:
                        _fail("durability ACK watermark changed after validation")
                    watermark = _object(streams[0], "durability ACK watermark")
                    if (
                        checkpoint["durable_through_offset"] != handle.tell()
                        or checkpoint["last_record_sha256"] != previous_digest
                        or watermark["durable_through_frame_index"] != next_frame
                    ):
                        _fail("BNACK does not match the exact BNRAW record boundary")
                    matched_checkpoints += 1
                if stream_kind is not None:
                    if sequence is None:
                        _fail("stream payload validation lacks sequence state")
                    is_server_shutdown = _validate_application_payload(
                        record_info,
                        stream_kind,
                        expected.symbol,
                        snapshot_sequence,
                        sequence,
                    )
                    if is_server_shutdown:
                        if segment_index is None:
                            _fail("serverShutdown identity lacks a raw segment")
                        if require_server_shutdown_ack and checkpoint is None:
                            _fail(
                                "serverShutdown raw record lacks its exact durable "
                                "BNACK checkpoint"
                            )
                        sequence.server_shutdowns.append(
                            {
                                "stream": stream_kind,
                                "connection_epoch": expected.connection_epoch,
                                "segment_index": segment_index,
                                "raw_file": path.name,
                                "frame_index": next_frame,
                                "receive_mono_ns": record_info.receive_mono_ns,
                                "durable_record_count": records,
                                "durable_through_offset": handle.tell(),
                                "last_record_sha256": record_info.record_sha256,
                            }
                        )
                if next_frame == U64_MAX:
                    _fail("raw frame index overflow")
                next_frame += 1
            final_stat = os.fstat(handle.fileno())
            offset = handle.tell()
    except SegmentChainCorruption:
        raise
    except OSError as exc:
        _fail(f"cannot scan raw segment: {exc.strerror or exc}")
    if (
        initial_stat.st_size != final_stat.st_size
        or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
        or offset != final_stat.st_size
    ):
        _fail("raw segment changed while it was scanned")
    if matched_checkpoints != len(acknowledgements):
        _fail("BNACK references a BNRAW record count outside the segment")
    return _RawScan(
        file_size=final_stat.st_size,
        records=records,
        last_good_offset=offset,
        first_frame_index=expected.first_frame_index if records else None,
        last_frame_index=(next_frame - 1) if records else None,
        last_record_sha256=previous_digest,
        file_sha256=file_hasher.hexdigest(),
        captured_record=retained_record,
        captured_records=(
            None if retained_records is None else tuple(retained_records)
        ),
    )


def _validate_seal(seal: dict[str, object], record_index: int) -> None:
    _ordered_keys(seal, _SEAL_KEYS, "raw segment seal")
    if _text(seal, "schema", "raw segment seal") != "RawSegmentSealV1":
        _fail("invalid raw segment seal schema")
    segment_index = _u64(seal, "segment_index", "raw segment seal")
    if segment_index != record_index:
        _fail("segment index is out of order")
    raw_file = _text(seal, "raw_file", "raw segment seal")
    _relative_parts(raw_file, "raw segment seal.raw_file", count=1)
    first = _u64(seal, "first_frame_index", "raw segment seal")
    last = _u64(seal, "last_frame_index", "raw segment seal")
    records = _u64(seal, "records", "raw segment seal")
    offset = _u64(seal, "durable_through_offset", "raw segment seal")
    _text(seal, "connection_epoch", "raw segment seal")
    _text(seal, "stream", "raw segment seal")
    previous = _digest(
        seal.get("previous_segment_terminal_sha256"),
        "raw segment seal.previous_segment_terminal_sha256",
    )
    terminal = _digest(
        seal.get("terminal_record_sha256"),
        "raw segment seal.terminal_record_sha256",
    )
    if records == 0 or offset <= len(RAW_MAGIC) or last < first or records != last - first + 1:
        _fail("invalid raw segment seal range/count/offset")
    is_root = segment_index == 0 and first == 0 and previous == ZERO_DIGEST
    is_successor = segment_index > 0 and first > 0 and previous != ZERO_DIGEST
    if not (is_root or is_successor) or terminal == ZERO_DIGEST:
        _fail("raw segment seal is neither a valid root nor successor")


def _scan_segment_manifest(path: Path, require_seals: bool = True) -> _ManifestScan:
    seals: list[dict[str, object]] = []
    raw_files: set[str] = set()
    previous_digest = ZERO_DIGEST
    file_hasher = sha256()
    try:
        with path.open("rb", buffering=0) as handle:
            initial_stat = os.fstat(handle.fileno())
            magic = _read_exact(handle, len(MANIFEST_MAGIC), "bad segment manifest magic")
            if magic != MANIFEST_MAGIC:
                _fail("bad segment manifest magic")
            file_hasher.update(magic)
            while True:
                prefix = handle.read(LENGTH.size)
                if prefix == b"":
                    break
                if len(prefix) != LENGTH.size:
                    _fail("partial segment manifest length prefix")
                file_hasher.update(prefix)
                (body_length,) = LENGTH.unpack(prefix)
                if body_length == 0 or body_length > MAX_MANIFEST_RECORD_BYTES:
                    _fail("segment manifest record length exceeds limit")
                body = _read_exact(handle, body_length, "partial segment manifest body")
                stored_digest = _read_exact(
                    handle,
                    DIGEST_BYTES,
                    "partial segment manifest digest",
                )
                file_hasher.update(body)
                file_hasher.update(stored_digest)
                if sha256(body).digest() != stored_digest:
                    _fail("segment manifest record digest mismatch")
                value = _object(_parse_json(body, "segment manifest"), "segment manifest record")
                _ordered_keys(value, _MANIFEST_KEYS, "segment manifest record")
                if _canonical_json(value) != body:
                    _fail("segment manifest JSON is not the canonical Rust encoding")
                if (
                    _text(value, "schema", "segment manifest record")
                    != "RawSegmentManifestRecordV1"
                ):
                    _fail("unknown segment manifest record schema")
                record_index = _u64(value, "record_index", "segment manifest record")
                if record_index != len(seals):
                    _fail("segment manifest record index is out of order")
                if _text(
                    value,
                    "previous_manifest_record_sha256",
                    "segment manifest record",
                ) != previous_digest:
                    _fail("segment manifest hash-chain mismatch")
                _digest(
                    value["previous_manifest_record_sha256"],
                    "segment manifest previous digest",
                )
                seal = _object(value.get("seal"), "raw segment seal")
                _validate_seal(seal, record_index)
                raw_file = str(seal["raw_file"])
                if raw_file in raw_files:
                    _fail("duplicate raw segment file in manifest")
                if seals:
                    old = seals[-1]
                    if (
                        int(seal["segment_index"]) != int(old["segment_index"]) + 1
                        or seal["connection_epoch"] != old["connection_epoch"]
                        or seal["stream"] != old["stream"]
                        or int(seal["first_frame_index"]) != int(old["last_frame_index"]) + 1
                        or seal["previous_segment_terminal_sha256"]
                        != old["terminal_record_sha256"]
                    ):
                        _fail("segment manifest transition is not exactly contiguous")
                elif (
                    seal["segment_index"] != 0
                    or seal["first_frame_index"] != 0
                    or seal["previous_segment_terminal_sha256"] != ZERO_DIGEST
                ):
                    _fail("segment manifest does not begin at the exact root")
                raw_files.add(raw_file)
                seals.append(seal)
                previous_digest = stored_digest.hex()
            final_stat = os.fstat(handle.fileno())
            offset = handle.tell()
    except SegmentChainCorruption:
        raise
    except OSError as exc:
        _fail(f"cannot scan segment manifest: {exc.strerror or exc}")
    if (
        initial_stat.st_size != final_stat.st_size
        or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
        or offset != final_stat.st_size
    ):
        _fail("segment manifest changed while it was scanned")
    if require_seals and not seals:
        _fail("segment manifest contains no sealed segment")
    return _ManifestScan(
        file_size=final_stat.st_size,
        records=len(seals),
        last_good_offset=offset,
        last_record_sha256=previous_digest,
        file_sha256=file_hasher.hexdigest(),
        seals=tuple(seals),
    )


def _scan_segment_manifest_prefix(path: Path) -> _ManifestScan:
    """Prefix-tolerant manifest scan for the failover oracle (mirror of the
    Rust `scan_segment_manifest`): a record-level problem (partial length
    prefix, partial body/digest, digest mismatch, invalid JSON, chain or
    transition violation) stops the scan at the last verified seal instead
    of failing — a writer interrupted mid-append is indistinguishable from
    a torn prefix and the verified seals remain authoritative evidence.
    Terminal verifications keep the strict `_scan_segment_manifest` with
    its exact corruption reasons."""
    try:
        with path.open("rb") as handle:
            content = handle.read()
    except OSError as exc:
        _fail(f"cannot scan segment manifest: {exc.strerror or exc}")
    file_hasher = sha256(content)
    seals: list[dict[str, object]] = []
    raw_files: set[str] = set()
    previous_digest = ZERO_DIGEST
    if len(content) < len(MANIFEST_MAGIC) or content[: len(MANIFEST_MAGIC)] != MANIFEST_MAGIC:
        return _ManifestScan(
            file_size=len(content),
            records=0,
            last_good_offset=0,
            last_record_sha256=ZERO_DIGEST,
            file_sha256=file_hasher.hexdigest(),
            seals=(),
        )
    offset = len(MANIFEST_MAGIC)
    last_good_offset = offset
    while True:
        if offset + LENGTH.size > len(content):
            break
        (body_length,) = LENGTH.unpack(content[offset : offset + LENGTH.size])
        offset += LENGTH.size
        if body_length == 0 or body_length > MAX_MANIFEST_RECORD_BYTES:
            break
        if offset + body_length + DIGEST_BYTES > len(content):
            break
        body = content[offset : offset + body_length]
        stored_digest = content[offset + body_length : offset + body_length + DIGEST_BYTES]
        offset += body_length + DIGEST_BYTES
        if sha256(body).digest() != stored_digest:
            break
        try:
            value = _object(_parse_json(body, "segment manifest"), "segment manifest record")
            _ordered_keys(value, _MANIFEST_KEYS, "segment manifest record")
            if _canonical_json(value) != body:
                raise SegmentChainCorruption(
                    "segment manifest JSON is not the canonical Rust encoding"
                )
            if (
                _text(value, "schema", "segment manifest record")
                != "RawSegmentManifestRecordV1"
            ):
                raise SegmentChainCorruption("unknown segment manifest record schema")
            record_index = _u64(value, "record_index", "segment manifest record")
            if record_index != len(seals):
                raise SegmentChainCorruption("segment manifest record index is out of order")
            if _text(
                value,
                "previous_manifest_record_sha256",
                "segment manifest record",
            ) != previous_digest:
                raise SegmentChainCorruption("segment manifest hash-chain mismatch")
            _digest(
                value["previous_manifest_record_sha256"],
                "segment manifest previous digest",
            )
            seal = _object(value.get("seal"), "raw segment seal")
            _validate_seal(seal, record_index)
            raw_file = str(seal["raw_file"])
            if raw_file in raw_files:
                raise SegmentChainCorruption("duplicate raw segment file in manifest")
            if seals:
                old = seals[-1]
                if (
                    int(seal["segment_index"]) != int(old["segment_index"]) + 1
                    or seal["connection_epoch"] != old["connection_epoch"]
                    or seal["stream"] != old["stream"]
                    or int(seal["first_frame_index"]) != int(old["last_frame_index"]) + 1
                    or seal["previous_segment_terminal_sha256"]
                    != old["terminal_record_sha256"]
                ):
                    raise SegmentChainCorruption(
                        "segment manifest transition is not exactly contiguous"
                    )
            elif (
                seal["segment_index"] != 0
                or seal["first_frame_index"] != 0
                or seal["previous_segment_terminal_sha256"] != ZERO_DIGEST
            ):
                raise SegmentChainCorruption("segment manifest does not begin at the exact root")
        except SegmentChainCorruption:
            break
        raw_files.add(raw_file)
        seals.append(seal)
        previous_digest = stored_digest.hex()
        last_good_offset = offset
    return _ManifestScan(
        file_size=len(content),
        records=len(seals),
        last_good_offset=last_good_offset,
        last_record_sha256=previous_digest,
        file_sha256=file_hasher.hexdigest(),
        seals=tuple(seals),
    )


def iter_segment_manifest_seals(path: Path) -> Iterator[dict[str, object]]:
    """Public iterator over one segment manifest's validated seals, used by
    the independent live-arbitration verifier to read a lane's ordered raw
    segments as the failover oracle (mirrors the Rust `scan_segment_manifest`
    public API: prefix-tolerant, the verified seals are authoritative)."""
    yield from _scan_segment_manifest_prefix(Path(path)).seals


def scan_segment_manifest_seals(path: Path) -> tuple[dict[str, object], ...]:
    """Public manifest seal reader for the failover oracle that also accepts
    a valid manifest with no sealed segments yet: a stream interrupted before
    its first rotation has a valid manifest with zero seals, and its root
    segment's durability boundary comes from its own BNACK journal.
    Prefix-tolerant like the Rust mirror: a torn tail stops at the last
    verified seal and never fabricates a boundary."""
    return _scan_segment_manifest_prefix(Path(path)).seals


def scan_durability_progress(path: Path) -> dict[str, object]:
    """Public BNACK prefix scanner (ADR-16 oracle support): validates the
    durability journal's digest chain and ACK monotonicity over the VERIFIED
    PREFIX and returns the latest complete ACK (None when the journal holds
    no complete ACK yet — a writer interrupted before its first ACK or a
    just-created empty segment), without requiring the stream identity,
    which the caller cross-checks against the raw prefix itself.  Mirrors
    the Rust `scan_durability_progress` public API exactly: a record-level
    problem (partial tail, invalid JSON, chain or ordering violation) stops
    the scan at the last verified record and never fabricates a boundary."""
    try:
        with Path(path).open("rb") as handle:
            content = handle.read()
    except OSError as exc:
        _fail(f"cannot scan durability progress: {exc.strerror or exc}")
    acknowledgements: list[dict[str, object]] = []
    previous_progress_digest = ZERO_DIGEST
    reason: str | None = None
    start = 0
    while start < len(content):
        relative_end = content.find(b"\n", start)
        if relative_end < 0:
            reason = "partial durability progress tail"
            break
        if relative_end - start > MAX_MANIFEST_RECORD_BYTES:
            reason = "durability progress record exceeds maximum size"
            break
        line = content[start:relative_end]
        start = relative_end + 1
        if not line:
            reason = "empty durability progress record"
            break
        try:
            envelope = _object(
                _parse_json(line, "durability progress"),
                "durability progress envelope",
            )
            _ordered_keys(
                envelope,
                _PROGRESS_ENVELOPE_KEYS,
                "durability progress envelope",
            )
            if _canonical_json(envelope) != line:
                raise SegmentChainCorruption(
                    "durability progress JSON is not the canonical Rust encoding"
                )
            body = _object(envelope.get("body"), "durability progress body")
            _ordered_keys(body, _PROGRESS_BODY_KEYS, "durability progress body")
            body_bytes = _canonical_json(body)
            progress_digest = sha256(body_bytes).hexdigest()
            if _digest(
                envelope.get("record_sha256"),
                "durability progress record_sha256",
            ) != progress_digest:
                raise SegmentChainCorruption("durability progress body digest mismatch")
            if _text(body, "schema", "durability progress body") != "RawDurabilityProgressV1":
                raise SegmentChainCorruption("invalid durability progress schema")
            record_index = _u64(body, "record_index", "durability progress body")
            if record_index != len(acknowledgements):
                raise SegmentChainCorruption("durability progress record index is out of order")
            raw_reference = _text(body, "raw_path", "durability progress body")
            _relative_parts(raw_reference, "durability progress raw_path", count=1)
            if _digest(
                body.get("previous_record_sha256"),
                "durability progress previous digest",
            ) != previous_progress_digest:
                raise SegmentChainCorruption("durability progress hash-chain mismatch")
            ack = _parse_ack(body.get("ack"), "durability progress ACK")
            count = _u64(ack, "durable_record_count", "durability progress ACK")
            offset = _u64(ack, "durable_through_offset", "durability progress ACK")
            if count == 0 or offset <= len(RAW_MAGIC):
                raise SegmentChainCorruption("invalid durability progress ACK count/offset")
            if acknowledgements:
                previous_ack = acknowledgements[-1]
                if (
                    count <= int(previous_ack["durable_record_count"])
                    or offset <= int(previous_ack["durable_through_offset"])
                ):
                    raise SegmentChainCorruption(
                        "durability progress ACK regressed or did not advance"
                    )
        except SegmentChainCorruption as error:
            reason = str(error)
            break
        acknowledgements.append(ack)
        previous_progress_digest = progress_digest
    return {
        "schema": "DurabilityProgressScanV1",
        "path": str(Path(path)),
        "records": len(acknowledgements),
        "latest_ack": acknowledgements[-1] if acknowledgements else None,
        "last_record_sha256": previous_progress_digest,
        "clean_eof": reason is None,
        "reason": reason,
    }


def _parse_ack(value: object, label: str) -> dict[str, object]:
    ack = _object(value, label)
    _ordered_keys(ack, _ACK_KEYS, label)
    if _text(ack, "schema", label) != "DurabilityAckV1":
        _fail(f"{label} has an invalid schema")
    _u64(ack, "durable_record_count", label)
    _u64(ack, "durable_through_offset", label)
    _digest(ack.get("last_record_sha256"), f"{label}.last_record_sha256")
    streams = ack.get("streams")
    if not isinstance(streams, list) or len(streams) != 1:
        _fail(f"{label}.streams must contain exactly one watermark")
    watermark = _object(streams[0], f"{label}.streams[0]")
    _ordered_keys(watermark, _WATERMARK_KEYS, f"{label}.streams[0]")
    _text(watermark, "connection_epoch", f"{label}.streams[0]")
    _text(watermark, "stream", f"{label}.streams[0]")
    _u64(watermark, "durable_through_frame_index", f"{label}.streams[0]")
    return ack


def _scan_progress(
    path: Path,
    expected_raw_reference: str,
    expected: _RawExpectations,
) -> _ProgressScan:
    _relative_parts(expected_raw_reference, "BNACK raw reference", count=1)
    acknowledgements: list[dict[str, object]] = []
    previous_progress_digest = ZERO_DIGEST
    previous_ack: dict[str, object] | None = None
    file_hasher = sha256()
    try:
        with path.open("rb", buffering=0) as handle:
            initial_stat = os.fstat(handle.fileno())
            while True:
                line_with_newline = handle.readline(MAX_MANIFEST_RECORD_BYTES + 2)
                if line_with_newline == b"":
                    break
                file_hasher.update(line_with_newline)
                if len(line_with_newline) > MAX_MANIFEST_RECORD_BYTES + 1:
                    _fail("durability progress record exceeds maximum size")
                if not line_with_newline.endswith(b"\n"):
                    _fail("partial durability progress tail at final audit")
                line = line_with_newline[:-1]
                if not line:
                    _fail("empty durability progress record")
                envelope = _object(
                    _parse_json(line, "durability progress"),
                    "durability progress envelope",
                )
                _ordered_keys(
                    envelope,
                    _PROGRESS_ENVELOPE_KEYS,
                    "durability progress envelope",
                )
                if _canonical_json(envelope) != line:
                    _fail("durability progress JSON is not the canonical Rust encoding")
                body = _object(envelope.get("body"), "durability progress body")
                _ordered_keys(body, _PROGRESS_BODY_KEYS, "durability progress body")
                body_bytes = _canonical_json(body)
                progress_digest = sha256(body_bytes).hexdigest()
                if _digest(
                    envelope.get("record_sha256"),
                    "durability progress record_sha256",
                ) != progress_digest:
                    _fail("durability progress body digest mismatch")
                if _text(body, "schema", "durability progress body") != "RawDurabilityProgressV1":
                    _fail("invalid durability progress schema")
                record_index = _u64(body, "record_index", "durability progress body")
                if record_index != len(acknowledgements):
                    _fail("durability progress record index is out of order")
                raw_reference = _text(body, "raw_path", "durability progress body")
                _relative_parts(raw_reference, "durability progress raw_path", count=1)
                if raw_reference != expected_raw_reference:
                    _fail("durability progress raw_path drift")
                if _digest(
                    body.get("previous_record_sha256"),
                    "durability progress previous digest",
                ) != previous_progress_digest:
                    _fail("durability progress hash-chain mismatch")
                ack = _parse_ack(body.get("ack"), "durability progress ACK")
                count = _u64(ack, "durable_record_count", "durability progress ACK")
                offset = _u64(ack, "durable_through_offset", "durability progress ACK")
                if count == 0 or offset <= len(RAW_MAGIC):
                    _fail("invalid durability progress ACK count/offset")
                ack_streams = ack["streams"]
                if not isinstance(ack_streams, list):
                    _fail("durability progress ACK streams changed after validation")
                watermark = _object(ack_streams[0], "durability progress watermark")
                if (
                    watermark["connection_epoch"] != expected.connection_epoch
                    or watermark["stream"] != expected.stream
                ):
                    _fail("durability progress ACK identity drift")
                if expected.first_frame_index > U64_MAX - (count - 1):
                    _fail("durability progress ACK frame range overflow")
                expected_frame = expected.first_frame_index + count - 1
                if watermark["durable_through_frame_index"] != expected_frame:
                    _fail("durability progress ACK count/frame mismatch")
                if previous_ack is not None:
                    old_streams = previous_ack["streams"]
                    if not isinstance(old_streams, list):
                        _fail("prior durability ACK streams changed after validation")
                    old_watermark = _object(old_streams[0], "prior durability watermark")
                    if (
                        count <= int(previous_ack["durable_record_count"])
                        or offset <= int(previous_ack["durable_through_offset"])
                        or int(watermark["durable_through_frame_index"])
                        <= int(old_watermark["durable_through_frame_index"])
                    ):
                        _fail("durability progress ACK regressed or did not advance")
                acknowledgements.append(ack)
                previous_ack = ack
                previous_progress_digest = progress_digest
            final_stat = os.fstat(handle.fileno())
            offset = handle.tell()
    except SegmentChainCorruption:
        raise
    except OSError as exc:
        _fail(f"cannot scan durability progress: {exc.strerror or exc}")
    if (
        initial_stat.st_size != final_stat.st_size
        or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
        or offset != final_stat.st_size
    ):
        _fail("durability progress changed while it was scanned")
    if not acknowledgements:
        _fail("durability progress contains no complete ACK")
    return _ProgressScan(
        file_size=final_stat.st_size,
        records=len(acknowledgements),
        last_record_sha256=previous_progress_digest,
        file_sha256=file_hasher.hexdigest(),
        acknowledgements=tuple(acknowledgements),
    )


def _exact_entries(path: Path, expected: set[str], label: str) -> list[str]:
    if _is_linklike(path):
        _fail(f"{label} must not be a symbolic link")
    try:
        entries = list(path.iterdir())
    except OSError as exc:
        _fail(f"cannot inventory {label}: {exc.strerror or exc}")
    actual: set[str] = set()
    for entry in entries:
        if _is_linklike(entry):
            _fail(f"{label} contains symbolic-link entry {entry.name}")
        actual.add(entry.name)
    if actual != expected:
        _fail(
            f"{label} inventory mismatch; "
            f"missing={sorted(expected - actual)}; unreferenced={sorted(actual - expected)}"
        )
    return sorted(actual)


def _read_stable(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.stat()
        if before.st_size > maximum:
            _fail(f"{label} exceeds the size limit")
        body = path.read_bytes()
        after = path.stat()
    except SegmentChainCorruption:
        raise
    except OSError as exc:
        _fail(f"cannot read {label}: {exc.strerror or exc}")
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(body) != after.st_size
    ):
        _fail(f"{label} changed while it was read")
    return body


def _load_generation(root: Path) -> tuple[dict[str, object], str]:
    path = _safe_file(root, "generation.json", "generation.json")
    try:
        body = _read_stable(path, MAX_GENERATION_JSON_BYTES, "generation.json")
    except SegmentChainCorruption:
        raise
    value = _object(_parse_json(body, "generation manifest"), "generation manifest")
    _ordered_keys(value, _GENERATION_KEYS, "generation manifest")
    return value, sha256(body).hexdigest()


def _validate_startup(
    root: Path,
    generation: dict[str, object],
) -> tuple[str, str]:
    startup_file = _text(generation, "startup_file", "generation manifest")
    _relative_parts(startup_file, "generation startup_file", count=1)
    if startup_file != "startup.json":
        _fail("generation startup file differs from the capture contract")
    expected_digest = _digest(
        generation.get("startup_sha256"),
        "generation startup_sha256",
    )
    startup_bytes = _read_stable(
        _safe_file(root, startup_file, "startup manifest"),
        MAX_GENERATION_JSON_BYTES,
        "startup manifest",
    )
    actual_digest = sha256(startup_bytes).hexdigest()
    if actual_digest != expected_digest:
        _fail("startup manifest digest differs from terminal generation")
    startup = _object(_parse_json(startup_bytes, "startup manifest"), "startup manifest")
    _ordered_keys(startup, _STARTUP_KEYS, "startup manifest")
    comparisons = (
        ("implementation", "rust-segmented"),
        ("session_id", generation["session_id"]),
        ("generation_index", generation["generation_index"]),
        ("symbol", generation["symbol"]),
        ("duration_requested_s", generation["duration_requested_s"]),
        ("segment_duration_s", generation["segment_duration_s"]),
        ("started_wall_ns", generation["started_wall_ns"]),
        ("collector_executable_sha256", generation["collector_executable_sha256"]),
        ("public_config_sha256", generation["public_config_sha256"]),
        (
            "market_freshness_startup_grace_s",
            generation["market_freshness_startup_grace_s"],
        ),
        (
            "market_freshness_deadline_s",
            generation["market_freshness_deadline_s"],
        ),
        ("credentials", generation["credentials"]),
        ("order_entry", generation["order_entry"]),
        ("raw_boundary", generation["raw_boundary"]),
        ("spec_revision", generation["spec_revision"]),
    )
    if startup.get("schema") != "RawGenerationStartupV1" or any(
        startup.get(field) != expected for field, expected in comparisons
    ):
        _fail("startup manifest differs from terminal generation identity")
    return startup_file, actual_digest


def _optional_u8(value: object, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0 or value > 255:
        _fail(f"{label} must be null or a u8")
    return value


def _optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        _fail(f"{label} must be null or a string")
    return value


def _validate_snapshot_http(
    root: Path,
    snapshot: dict[str, object],
    raw_record: _RawRecordInfo,
) -> tuple[str, str]:
    metadata_file = _text(snapshot, "http_metadata_file", "generation snapshot")
    _relative_parts(metadata_file, "snapshot http_metadata_file", count=1)
    if metadata_file != "snapshot-http.json":
        _fail("snapshot HTTP metadata file differs from the capture contract")
    expected_digest = _digest(
        snapshot.get("http_metadata_sha256"),
        "snapshot http_metadata_sha256",
    )
    metadata_bytes = _read_stable(
        _safe_file(root, metadata_file, "snapshot HTTP metadata"),
        MAX_GENERATION_JSON_BYTES,
        "snapshot HTTP metadata",
    )
    if sha256(metadata_bytes).hexdigest() != expected_digest:
        _fail("snapshot HTTP metadata digest differs from generation")
    metadata = _object(
        _parse_json(metadata_bytes, "snapshot HTTP metadata"),
        "snapshot HTTP metadata",
    )
    _ordered_keys(metadata, _HTTP_METADATA_KEYS, "snapshot HTTP metadata")
    if _canonical_json(metadata) != metadata_bytes:
        _fail("snapshot HTTP metadata is not the canonical Rust encoding")
    headers = _object(metadata.get("headers"), "snapshot HTTP headers")
    if not headers or tuple(headers) != tuple(sorted(headers)):
        _fail("snapshot HTTP headers are empty or noncanonical")
    for name, values in headers.items():
        if not name or not isinstance(values, list) or any(
            not isinstance(value, str) for value in values
        ):
            _fail("snapshot HTTP headers have an invalid value list")
    if (
        metadata.get("schema") != "SnapshotHttpMetadataV1"
        or metadata.get("endpoint") != snapshot["endpoint"]
        or metadata.get("http_status") != snapshot["http_status"]
        or type(metadata.get("body_complete")) is not bool
        or metadata["body_complete"] is not True
        or _u64(metadata, "body_length", "snapshot HTTP metadata")
        != len(raw_record.payload)
        or _digest(metadata.get("body_sha256"), "snapshot HTTP body_sha256")
        != sha256(raw_record.payload).hexdigest()
        or metadata.get("raw_file") != snapshot["raw_file"]
        or _digest(metadata.get("raw_record_sha256"), "snapshot HTTP raw_record_sha256")
        != raw_record.record_sha256
        or _u64(metadata, "receive_wall_ns", "snapshot HTTP metadata")
        != raw_record.receive_wall_ns
        or _u64(metadata, "receive_mono_ns", "snapshot HTTP metadata")
        != raw_record.receive_mono_ns
    ):
        _fail("snapshot HTTP metadata is not bound to the exact raw body")
    return metadata_file, expected_digest


def _socket_endpoint(value: object, label: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a socket address")
    try:
        if value.startswith("["):
            closing = value.index("]")
            if closing + 1 >= len(value) or value[closing + 1] != ":":
                raise ValueError("missing IPv6 port")
            host = value[1:closing]
            port_text = value[closing + 2 :]
        else:
            host, port_text = value.rsplit(":", 1)
        address = ipaddress.ip_address(host)
        port = int(port_text, 10)
    except (ValueError, IndexError) as exc:
        _fail(f"{label} is not a numeric socket address: {exc}")
    if port < 0 or port > 65_535:
        _fail(f"{label} port is outside u16")
    return address, port


def _validate_transport_metadata(
    root: Path,
    stream: dict[str, object],
    *,
    session_id: str,
    generation_index: int,
    symbol: str,
    expected_uri: str,
) -> dict[str, object]:
    name = _text(stream, "name", "generation stream")
    expected_file = f"transport-{name}.json"
    metadata_file = _text(stream, "transport_metadata_file", f"generation {name} stream")
    _relative_parts(metadata_file, f"generation {name} transport metadata", count=1)
    if metadata_file != expected_file:
        _fail(f"generation {name} transport metadata path drift")
    expected_digest = _digest(
        stream.get("transport_metadata_sha256"),
        f"generation {name} transport metadata digest",
    )
    metadata_bytes = _read_stable(
        _safe_file(root, metadata_file, f"generation {name} transport metadata"),
        MAX_GENERATION_JSON_BYTES,
        f"generation {name} transport metadata",
    )
    actual_digest = sha256(metadata_bytes).hexdigest()
    if actual_digest != expected_digest:
        _fail(f"generation {name} transport metadata digest drift")
    metadata = _object(
        _parse_json(metadata_bytes, f"generation {name} transport metadata"),
        f"generation {name} transport metadata",
    )
    _ordered_keys(metadata, _TRANSPORT_METADATA_KEYS, f"generation {name} transport metadata")
    if _pretty_json(metadata) != metadata_bytes:
        _fail(f"generation {name} transport metadata is not exact Rust pretty JSON")
    connection = _object(
        metadata.get("connection"), f"generation {name} transport connection"
    )
    _ordered_keys(
        connection,
        _TRANSPORT_CONNECTION_KEYS,
        f"generation {name} transport connection",
    )
    local_address, local_port = _socket_endpoint(
        connection.get("local_endpoint"), f"generation {name} local endpoint"
    )
    remote_address, remote_port = _socket_endpoint(
        connection.get("remote_endpoint"), f"generation {name} remote endpoint"
    )
    headers = _object(
        connection.get("response_headers"), f"generation {name} response headers"
    )
    if not headers or tuple(headers) != tuple(sorted(headers)):
        _fail(f"generation {name} response headers are empty or noncanonical")
    for header_name, values in headers.items():
        if (
            not header_name.strip()
            or not isinstance(values, list)
            or not values
            or any(
                not isinstance(item, str) or "\r" in item or "\n" in item
                for item in values
            )
        ):
            _fail(f"generation {name} response header values are invalid")
    if (
        metadata.get("schema") != "TransportMetadataV1"
        or metadata.get("session_id") != session_id
        or metadata.get("generation_index") != generation_index
        or metadata.get("symbol") != symbol
        or metadata.get("spec_revision") != SPEC_REVISION
        or connection.get("stream") != name
        or connection.get("connection_epoch") != stream.get("connection_epoch")
        or connection.get("uri") != expected_uri
        or connection.get("uri") != stream.get("uri")
        or connection.get("websocket_http_status") != 101
        or local_port == 0
        or local_address.is_unspecified
        or remote_port != 443
        or remote_address.is_unspecified
    ):
        _fail(f"generation {name} transport identity/handshake drift")
    return {
        "file": metadata_file,
        "file_sha256": actual_digest,
        "local_endpoint": connection["local_endpoint"],
        "remote_endpoint": connection["remote_endpoint"],
        "websocket_http_status": 101,
    }


def _transport_tcp_observation(value: object, label: str) -> None:
    observation = _object(value, label)
    status = _text(observation, "status", label)
    if status == "AVAILABLE":
        _ordered_keys(observation, ("sample", "status"), label)
        sample = _object(observation.get("sample"), f"{label} sample")
        _ordered_keys(sample, _WINDOWS_TCP_INFO_KEYS, f"{label} sample")
        u32_fields = (
            "bytes_in_flight",
            "bytes_reordered",
            "bytes_retransmitted",
            "congestion_window_bytes",
            "duplicate_acks_in",
            "fast_retransmits",
            "min_rtt_us",
            "mss",
            "receive_buffer_bytes",
            "receive_window_bytes",
            "rtt_us",
            "send_window_bytes",
            "timeout_episodes",
        )
        state_names = {
            0: "CLOSED",
            1: "LISTEN",
            2: "SYN_SENT",
            3: "SYN_RECEIVED",
            4: "ESTABLISHED",
            5: "FIN_WAIT_1",
            6: "FIN_WAIT_2",
            7: "CLOSE_WAIT",
            8: "CLOSING",
            9: "LAST_ACK",
            10: "TIME_WAIT",
        }
        state = sample.get("state")
        if (
            sample.get("schema") != "WindowsTcpInfoV0"
            or sample.get("api") != "SIO_TCP_INFO"
            or _u64(sample, "api_version", f"{label} sample") != 0
            or any(_u64(sample, field, f"{label} sample") > (1 << 32) - 1 for field in u32_fields)
            or any(
                _u64(sample, field, f"{label} sample") > U64_MAX
                for field in ("bytes_in", "bytes_out", "connection_time_ms")
            )
            or _u64(sample, "syn_retransmits", f"{label} sample") > 255
            or type(state) is not int
            or state < I64_MIN
            or state > I64_MAX
            or sample.get("state_name") != state_names.get(state, "UNKNOWN")
            or type(sample.get("timestamps_enabled")) is not bool
        ):
            _fail(f"{label} Windows TCP_INFO sample is invalid")
    elif status == "UNAVAILABLE":
        _ordered_keys(observation, ("error", "status"), label)
        _text(observation, "error", label)
    elif status == "UNSUPPORTED_PLATFORM":
        _ordered_keys(observation, ("status",), label)
    else:
        _fail(f"{label} status is unknown")


def _transport_error(value: object, label: str) -> None:
    error = _object(value, label)
    category = _text(error, "category", label)
    if category == "IO":
        _ordered_keys(error, ("category", "io_kind", "message", "native_os_error"), label)
        _text(error, "io_kind", label)
        _text(error, "message", label)
        native = error.get("native_os_error")
        if native is not None and (type(native) is not int or native < I64_MIN or native > I64_MAX):
            _fail(f"{label} native_os_error must be null or i64")
    else:
        _ordered_keys(error, ("category", "message"), label)
        _text(error, "message", label)


def _validate_transport_payload(event: str, value: object, label: str) -> dict[str, object]:
    payload = _object(value, label)
    if event == "CONNECT_ATTEMPT":
        _ordered_keys(payload, ("uri",), label)
        if not _text(payload, "uri", label).startswith(
            "wss://data-stream.binance.vision:443/ws/"
        ):
            _fail(f"{label} URI is outside the locked public endpoint")
    elif event == "DNS_OBSERVED":
        _ordered_keys(payload, ("addresses", "host", "port", "role"), label)
        addresses = payload.get("addresses")
        if (
            not isinstance(addresses, list)
            or not addresses
            or any(not isinstance(item, str) or not item for item in addresses)
            or payload.get("host") != "data-stream.binance.vision"
            or _u64(payload, "port", label) != 443
            or payload.get("role") != "DIAGNOSTIC_OBSERVATION_NOT_CONNECT_SELECTION"
        ):
            _fail(f"{label} DNS observation is invalid")
        for index, endpoint in enumerate(addresses):
            _, port = _socket_endpoint(endpoint, f"{label} address[{index}]")
            if port != 443:
                _fail(f"{label} DNS endpoint port differs from 443")
    elif event == "DNS_FAILED":
        _ordered_keys(payload, ("error", "host", "port", "role"), label)
        if (
            not _text(payload, "error", label)
            or payload.get("host") != "data-stream.binance.vision"
            or _u64(payload, "port", label) != 443
            or payload.get("role") != "DIAGNOSTIC_OBSERVATION_NOT_CONNECT_SELECTION"
        ):
            _fail(f"{label} DNS failure is invalid")
    elif event == "CONNECT_FAILED":
        _ordered_keys(payload, ("error",), label)
        _transport_error(payload.get("error"), f"{label} error")
    elif event == "WEBSOCKET_UPGRADE_REJECTED":
        _ordered_keys(payload, ("http_status",), label)
        status = _u64(payload, "http_status", label)
        if status < 100 or status > 599 or status == 101:
            _fail(f"{label} HTTP status is invalid")
    elif event == "WEBSOCKET_CONNECTED":
        _ordered_keys(
            payload,
            ("local_endpoint", "remote_endpoint", "tcp_info", "websocket_http_status"),
            label,
        )
        local_address, local_port = _socket_endpoint(payload.get("local_endpoint"), label)
        remote_address, remote_port = _socket_endpoint(payload.get("remote_endpoint"), label)
        if (
            local_port == 0
            or local_address.is_unspecified
            or remote_port != 443
            or remote_address.is_unspecified
            or _u64(payload, "websocket_http_status", label) != 101
        ):
            _fail(f"{label} connected endpoints/status are invalid")
        _transport_tcp_observation(payload.get("tcp_info"), f"{label} tcp_info")
    elif event == "READ_TIMEOUT":
        _ordered_keys(payload, ("inactive_ms", "io_kind", "native_os_error", "tcp_info"), label)
        _u64(payload, "inactive_ms", label)
        _text(payload, "io_kind", label)
        native = payload.get("native_os_error")
        if native is not None and (type(native) is not int or native < I64_MIN or native > I64_MAX):
            _fail(f"{label} native_os_error must be null or i64")
        _transport_tcp_observation(payload.get("tcp_info"), f"{label} tcp_info")
    elif event == "TRANSPORT_DEADLINE":
        _ordered_keys(payload, ("deadline_ms", "inactive_ms", "tcp_info"), label)
        _u64(payload, "deadline_ms", label)
        _u64(payload, "inactive_ms", label)
        _transport_tcp_observation(payload.get("tcp_info"), f"{label} tcp_info")
    elif event == "SOCKET_READ_ERROR":
        _ordered_keys(payload, ("error", "tcp_info"), label)
        _transport_error(payload.get("error"), f"{label} error")
        _transport_tcp_observation(payload.get("tcp_info"), f"{label} tcp_info")
    elif event == "WEBSOCKET_CLOSE":
        _ordered_keys(payload, ("close", "tcp_info"), label)
        close = payload.get("close")
        if close is not None:
            close_object = _object(close, f"{label} close")
            _ordered_keys(close_object, ("code", "reason"), f"{label} close")
            if not isinstance(close_object.get("code"), str) or not isinstance(
                close_object.get("reason"), str
            ):
                _fail(f"{label} close frame is invalid")
        _transport_tcp_observation(payload.get("tcp_info"), f"{label} tcp_info")
    elif event == "WS_PING_PONG_FLUSHED":
        _ordered_keys(payload, ("payload_bytes", "payload_sha256"), label)
        _u64(payload, "payload_bytes", label)
        _digest(payload.get("payload_sha256"), f"{label} payload_sha256")
    elif event == "WS_PONG_RECEIVED":
        # `watchdog_rtt_ms` is optional: historical journals predate the
        # watchdog and carry only the two base keys.
        keys = tuple(payload)
        if keys == ("payload_bytes", "payload_sha256"):
            pass
        elif keys == ("payload_bytes", "payload_sha256", "watchdog_rtt_ms"):
            rtt = payload.get("watchdog_rtt_ms")
            if rtt is not None and (
                type(rtt) is not int or not (0 <= rtt <= 0xFFFFFFFFFFFFFFFF)
            ):
                _fail(f"{label} watchdog_rtt_ms must be null or u64")
        else:
            _fail(f"{label} has unknown, missing, or reordered fields")
        _u64(payload, "payload_bytes", label)
        _digest(payload.get("payload_sha256"), f"{label} payload_sha256")
    elif event == "WATCHDOG_PING_SENT":
        _ordered_keys(payload, ("deadline_ms", "interval_ms"), label)
        _u64(payload, "deadline_ms", label)
        _u64(payload, "interval_ms", label)
    elif event == "WATCHDOG_PONG_DEADLINE":
        _ordered_keys(payload, ("deadline_ms", "inactive_ms", "tcp_info"), label)
        _u64(payload, "deadline_ms", label)
        _u64(payload, "inactive_ms", label)
        _transport_tcp_observation(payload.get("tcp_info"), f"{label} tcp_info")
    elif event == "UNEXPECTED_RAW_FRAME":
        _ordered_keys(payload, (), label)
    elif event == "FAULT_INJECTED_SILENT_STALL":
        _ordered_keys(payload, ("after_mono_ns", "stream"), label)
        _u64(payload, "after_mono_ns", label)
        stream_name = _text(payload, "stream", label)
        if stream_name not in {"depth", "trade"}:
            _fail(f"{label} injected stall names an unknown stream")
    elif event == "CLIENT_STOP_OBSERVED":
        _ordered_keys(payload, ("tcp_info",), label)
        _transport_tcp_observation(payload.get("tcp_info"), f"{label} tcp_info")
    elif event == "SUPERVISOR_FAILURE_STOP":
        _ordered_keys(
            payload,
            ("campaign_failure_record_sha256", "reason", "source", "tcp_info"),
            label,
        )
        _text(payload, "reason", label)
        source = _text(payload, "source", label)
        digest = payload.get("campaign_failure_record_sha256")
        if source == "CAMPAIGN_STOP_REQUEST":
            _digest(digest, f"{label} campaign failure digest")
        elif source == "LOCAL_GENERATION_SUPERVISOR":
            if digest is not None:
                _fail(f"{label} local supervisor stop cannot claim a campaign digest")
        else:
            _fail(f"{label} supervisor failure source is unknown")
        _transport_tcp_observation(payload.get("tcp_info"), f"{label} tcp_info")
    elif event == "PRODUCER_FAILURE":
        _ordered_keys(payload, ("error", "stage"), label)
        _text(payload, "error", label)
        if payload.get("stage") != "PRODUCER_LOOP":
            _fail(f"{label} producer stage is invalid")
    elif event == "TRANSPORT_TERMINAL":
        _ordered_keys(payload, ("error", "received", "status"), label)
        _u64(payload, "received", label)
        status = _text(payload, "status", label)
        error = payload.get("error")
        if (status == "STOPPED" and error is not None) or (
            status == "FAILED" and (not isinstance(error, str) or not error)
        ) or status not in {"STOPPED", "FAILED"}:
            _fail(f"{label} terminal status/error is invalid")
    else:
        _fail(f"{label} event is unknown: {event}")
    return payload


def _validate_transport_journal(
    root: Path,
    stream: dict[str, object],
) -> dict[str, object]:
    name = _text(stream, "name", "generation stream")
    epoch = _text(stream, "connection_epoch", f"generation {name} stream")
    seal = _object(stream.get("transport_journal"), f"generation {name} transport journal seal")
    _ordered_keys(
        seal,
        _TRANSPORT_JOURNAL_SEAL_KEYS,
        f"generation {name} transport journal seal",
    )
    expected_file = f"transport-{name}-events.jsonl"
    if (
        _text(seal, "schema", f"generation {name} transport journal seal")
        != "TransportJournalSealV1"
        or _text(seal, "file", f"generation {name} transport journal seal")
        != expected_file
    ):
        _fail(f"generation {name} transport journal seal identity is invalid")
    records = _u64(seal, "records", f"generation {name} transport journal seal")
    file_bytes = _u64(seal, "file_bytes", f"generation {name} transport journal seal")
    terminal_digest = _digest(
        seal.get("terminal_record_sha256"),
        f"generation {name} transport journal terminal digest",
    )
    file_digest = _digest(
        seal.get("file_sha256"),
        f"generation {name} transport journal file digest",
    )
    if records == 0 or file_bytes == 0:
        _fail(f"generation {name} transport journal seal is empty")
    path = _safe_file(root, expected_file, f"generation {name} transport journal")
    data = _read_stable(path, MAX_TRANSPORT_JOURNAL_BYTES, f"generation {name} transport journal")
    if len(data) != file_bytes or sha256(data).hexdigest() != file_digest:
        _fail(f"generation {name} transport journal file binding drift")
    lines = data.splitlines(keepends=True)
    if len(lines) != records or any(not line.endswith(b"\n") for line in lines):
        _fail(f"generation {name} transport journal record boundary is invalid")
    previous = ZERO_DIGEST
    first_event: str | None = None
    last_event: str | None = None
    websocket_connected = False
    client_stop_observed = False
    failure_reason: str | None = None
    terminal_seen = False
    for index, line in enumerate(lines):
        if len(line) > MAX_MANIFEST_RECORD_BYTES:
            _fail(f"generation {name} transport journal record is oversized")
        envelope = _object(
            _parse_json(line[:-1], f"generation {name} transport journal record[{index}]"),
            f"generation {name} transport journal record[{index}]",
        )
        _ordered_keys(
            envelope,
            _TRANSPORT_JOURNAL_ENVELOPE_KEYS,
            f"generation {name} transport journal envelope[{index}]",
        )
        body = _object(
            envelope.get("body"), f"generation {name} transport journal body[{index}]"
        )
        _ordered_keys(
            body,
            _TRANSPORT_JOURNAL_BODY_KEYS,
            f"generation {name} transport journal body[{index}]",
        )
        digest = _digest(
            envelope.get("record_sha256"),
            f"generation {name} transport journal record digest[{index}]",
        )
        event = _text(body, "event", f"generation {name} transport journal body[{index}]")
        payload = _validate_transport_payload(
            event,
            body.get("payload"),
            f"generation {name} transport journal payload[{index}]",
        )
        if (
            _text(body, "schema", f"generation {name} transport journal body[{index}]")
            != "TransportJournalRecordV1"
            or _u64(body, "record_index", f"generation {name} transport journal body[{index}]")
            != index
            or _u64(body, "wall_ns", f"generation {name} transport journal body[{index}]") == 0
            or _u64(body, "mono_ns", f"generation {name} transport journal body[{index}]")
            > U64_MAX
            or _text(body, "stream", f"generation {name} transport journal body[{index}]")
            != name
            or _text(
                body,
                "connection_epoch",
                f"generation {name} transport journal body[{index}]",
            )
            != epoch
            or _digest(
                body.get("previous_record_sha256"),
                f"generation {name} transport journal previous digest[{index}]",
            )
            != previous
            or sha256(_canonical_json(body)).hexdigest() != digest
        ):
            _fail(f"generation {name} transport journal identity/hash chain is invalid")
        if index == 0 and payload.get("uri") != stream.get("uri"):
            _fail(f"generation {name} transport journal URI binding drift")
        if (
            terminal_seen
            or (index == 0 and event != "CONNECT_ATTEMPT")
            or (index == 1 and event not in {"DNS_OBSERVED", "DNS_FAILED"})
            or (
                index == 2
                and event
                not in {
                    "CONNECT_FAILED",
                    "WEBSOCKET_UPGRADE_REJECTED",
                    "WEBSOCKET_CONNECTED",
                    "SUPERVISOR_FAILURE_STOP",
                    "PRODUCER_FAILURE",
                }
            )
        ):
            _fail(f"generation {name} transport journal lifecycle sequence is invalid")
        if (
            index > 2
            and not websocket_connected
            and event != "PRODUCER_FAILURE"
            and not (event == "TRANSPORT_TERMINAL" and failure_reason is not None)
        ):
            _fail(f"generation {name} transport journal advanced without WebSocket connection")
        if client_stop_observed and event != "TRANSPORT_TERMINAL":
            _fail(f"generation {name} transport journal continued after client stop")
        if failure_reason is not None and event != "TRANSPORT_TERMINAL":
            _fail(f"generation {name} transport journal continued after producer failure")
        if event == "WEBSOCKET_CONNECTED":
            if websocket_connected:
                _fail(f"generation {name} transport journal duplicated WebSocket connection")
            websocket_connected = True
        elif event in {
            "READ_TIMEOUT",
            "TRANSPORT_DEADLINE",
            "SOCKET_READ_ERROR",
            "WEBSOCKET_CLOSE",
            "WS_PING_PONG_FLUSHED",
            "WS_PONG_RECEIVED",
            "WATCHDOG_PING_SENT",
            "WATCHDOG_PONG_DEADLINE",
            "UNEXPECTED_RAW_FRAME",
            "FAULT_INJECTED_SILENT_STALL",
            "CLIENT_STOP_OBSERVED",
        }:
            if not websocket_connected:
                _fail(f"generation {name} transport event precedes WebSocket connection")
            if event == "CLIENT_STOP_OBSERVED":
                client_stop_observed = True
        elif event == "SUPERVISOR_FAILURE_STOP":
            if index > 2 and not websocket_connected:
                _fail(
                    f"generation {name} supervisor failure stop has no observable socket boundary"
                )
        elif event == "PRODUCER_FAILURE":
            failure_reason = str(payload["error"])
        elif event == "TRANSPORT_TERMINAL":
            status = payload.get("status")
            error = payload.get("error")
            if (
                status == "STOPPED"
                and (not client_stop_observed or failure_reason is not None)
            ) or (
                status == "FAILED"
                and (failure_reason is None or error != failure_reason)
            ):
                _fail(f"generation {name} terminal contradicts observed lifecycle")
            terminal_seen = True
        if first_event is None:
            first_event = event
        last_event = event
        previous = digest
    if (
        first_event != "CONNECT_ATTEMPT"
        or last_event != "TRANSPORT_TERMINAL"
        or not terminal_seen
        or previous != terminal_digest
    ):
        _fail(f"generation {name} transport journal lifecycle boundary is invalid")
    terminal = _object(
        _object(
            _parse_json(lines[-1][:-1], f"generation {name} terminal transport record"),
            f"generation {name} terminal transport envelope",
        ).get("body"),
        f"generation {name} terminal transport body",
    )
    terminal_payload = _object(
        terminal.get("payload"), f"generation {name} terminal transport payload"
    )
    _ordered_keys(
        terminal_payload,
        ("error", "received", "status"),
        f"generation {name} terminal transport payload",
    )
    if (
        terminal_payload.get("error") is not None
        or _text(terminal_payload, "status", f"generation {name} terminal transport payload")
        != "STOPPED"
        or _u64(terminal_payload, "received", f"generation {name} terminal transport payload")
        != _u64(stream, "received", f"generation {name} stream")
    ):
        _fail(f"generation {name} terminal transport status is not clean")
    return {
        "file": expected_file,
        "records": records,
        "terminal_record_sha256": terminal_digest,
        "file_bytes": file_bytes,
        "file_sha256": file_digest,
    }


def _validate_telemetry(
    root: Path,
    manifest_value: object,
    stream_reports: list[dict[str, object]],
    duration_requested_s: int,
) -> dict[str, object]:
    manifest = _object(manifest_value, "telemetry artifact")
    _ordered_keys(manifest, _TELEMETRY_ARTIFACT_KEYS, "telemetry artifact")
    if manifest.get("schema") != "TelemetryArtifactV1":
        _fail("telemetry artifact schema is invalid")
    telemetry_file = _text(manifest, "file", "telemetry artifact")
    _relative_parts(telemetry_file, "telemetry artifact file", count=1)
    if telemetry_file != "telemetry.jsonl":
        _fail("telemetry file differs from the capture contract")
    expected_records = _u64(manifest, "records", "telemetry artifact")
    expected_offset = _u64(manifest, "durable_through_offset", "telemetry artifact")
    expected_terminal_record = _digest(
        manifest.get("terminal_record_sha256"),
        "telemetry terminal_record_sha256",
    )
    expected_terminal_mono = _u64(manifest, "terminal_mono_ns", "telemetry artifact")
    expected_digest = _digest(manifest.get("file_sha256"), "telemetry file_sha256")
    if expected_records == 0 or expected_offset == 0 or expected_terminal_mono == 0:
        _fail("telemetry artifact contains no records")
    telemetry_bytes = _read_stable(
        _safe_file(root, telemetry_file, "telemetry artifact"),
        256 * 1024 * 1024,
        "telemetry artifact",
    )
    actual_digest = sha256(telemetry_bytes).hexdigest()
    if (
        actual_digest != expected_digest
        or len(telemetry_bytes) != expected_offset
        or not telemetry_bytes.endswith(b"\n")
    ):
        _fail("telemetry hash differs or terminal record is partial")
    lines = telemetry_bytes[:-1].split(b"\n")
    if len(lines) != expected_records or any(not line for line in lines):
        _fail("telemetry record count or newline framing is invalid")
    previous: dict[str, object] | None = None
    monotonic_fields = (
        "depth_received",
        "depth_written",
        "depth_durable",
        "depth_segment",
        "depth_last_socket_activity_mono_ns",
        "depth_last_market_message_mono_ns",
        "depth_max_queue_records",
        "depth_max_queue_bytes",
        "depth_max_queue_age_ns",
        "depth_max_sync_duration_ns",
        "trade_received",
        "trade_written",
        "trade_durable",
        "trade_segment",
        "trade_last_socket_activity_mono_ns",
        "trade_last_market_message_mono_ns",
        "trade_max_queue_records",
        "trade_max_queue_bytes",
        "trade_max_queue_age_ns",
        "trade_max_sync_duration_ns",
    )
    for index, line in enumerate(lines):
        record = _object(_parse_json(line, "telemetry"), "telemetry record")
        _ordered_keys(record, _TELEMETRY_RECORD_KEYS, "telemetry record")
        if _canonical_json(record) != line:
            _fail("telemetry JSON is not the canonical Rust encoding")
        if record.get("schema") != "CaptureTelemetryV1":
            _fail("telemetry record schema is invalid")
        if _u64(record, "record_index", "telemetry record") != index:
            _fail("telemetry record index is not contiguous")
        wall = _u64(record, "wall_ns", "telemetry record")
        mono = _u64(record, "mono_ns", "telemetry record")
        if wall == 0:
            _fail("telemetry wall clock is zero")
        clock = _object(record.get("clock"), "telemetry clock")
        _ordered_keys(clock, _TELEMETRY_CLOCK_KEYS, "telemetry clock")
        quality = _text(clock, "quality", "telemetry clock")
        _text(clock, "source", "telemetry clock")
        leap = _optional_u8(clock.get("leap_indicator"), "telemetry leap_indicator")
        stratum = _optional_u8(clock.get("stratum"), "telemetry stratum")
        last_sync = _optional_text(
            clock.get("last_successful_sync"),
            "telemetry last_successful_sync",
        )
        if quality not in {"HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND", "UNKNOWN"}:
            _fail("telemetry clock quality is outside the verified contract")
        if quality == "HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND" and (
            leap != 0 or stratum is None or not 1 <= stratum <= 15 or last_sync is None
        ):
            _fail("telemetry synchronized-clock metadata is incomplete")
        counters = {
            field: _u64(record, field, "telemetry record")
            for field in _TELEMETRY_RECORD_KEYS[5:]
        }
        if (
            counters["depth_written"] > counters["depth_received"]
            or counters["depth_durable"] > counters["depth_written"]
            or counters["trade_written"] > counters["trade_received"]
            or counters["trade_durable"] > counters["trade_written"]
            or counters["depth_last_socket_activity_mono_ns"] > mono
            or counters["depth_last_market_message_mono_ns"] > mono
            or counters["depth_last_durable_mono_ns"] > mono
            or counters["trade_last_socket_activity_mono_ns"] > mono
            or counters["trade_last_market_message_mono_ns"] > mono
            or counters["trade_last_durable_mono_ns"] > mono
            or counters["depth_last_market_message_mono_ns"]
            > counters["depth_last_socket_activity_mono_ns"]
            or counters["trade_last_market_message_mono_ns"]
            > counters["trade_last_socket_activity_mono_ns"]
            or counters["depth_queue_records"] > counters["depth_max_queue_records"]
            or counters["depth_queue_bytes"] > counters["depth_max_queue_bytes"]
            or counters["depth_last_sync_duration_ns"]
            > counters["depth_max_sync_duration_ns"]
            or counters["trade_queue_records"] > counters["trade_max_queue_records"]
            or counters["trade_queue_bytes"] > counters["trade_max_queue_bytes"]
            or counters["trade_last_sync_duration_ns"]
            > counters["trade_max_sync_duration_ns"]
        ):
            _fail("telemetry record counters are invalid")
        active_end_ns = duration_requested_s * 1_000_000_000
        freshness_grace_ns = MARKET_FRESHNESS_STARTUP_GRACE_S * 1_000_000_000
        freshness_deadline_ns = MARKET_FRESHNESS_DEADLINE_S * 1_000_000_000
        if mono >= freshness_grace_ns and mono < active_end_ns and (
            counters["depth_last_market_message_mono_ns"] == 0
            or counters["trade_last_market_message_mono_ns"] == 0
            or mono - counters["depth_last_market_message_mono_ns"]
            > freshness_deadline_ns
            or mono - counters["trade_last_market_message_mono_ns"]
            > freshness_deadline_ns
        ):
            _fail(
                "telemetry records contain stale market data despite fresh "
                "socket/control activity"
            )
        if previous is not None:
            if mono < int(previous["mono_ns"]) or any(
                counters[field] < int(previous[field]) for field in monotonic_fields
            ):
                _fail("telemetry monotonic lineage regressed")
        previous = {"mono_ns": mono, **counters}
    assert previous is not None
    terminal_record_digest = sha256(lines[-1] + b"\n").hexdigest()
    by_name = {str(stream["name"]): stream for stream in stream_reports}
    depth = by_name.get("depth")
    trade = by_name.get("trade")
    if depth is None or trade is None:
        _fail("telemetry verification lacks depth/trade stream results")
    if (
        previous["depth_received"] != depth["records"]
        or previous["depth_written"] != depth["records"]
        or previous["depth_durable"] != depth["records"]
        or previous["depth_segment"] != int(depth["segments"]) - 1
        or previous["depth_queue_records"] != 0
        or previous["depth_queue_bytes"] != 0
        or previous["depth_last_socket_activity_mono_ns"]
        != depth["last_socket_activity_mono_ns"]
        or previous["depth_last_market_message_mono_ns"]
        != depth["last_market_message_mono_ns"]
        or previous["trade_received"] != trade["records"]
        or previous["trade_written"] != trade["records"]
        or previous["trade_durable"] != trade["records"]
        or previous["trade_segment"] != int(trade["segments"]) - 1
        or previous["trade_queue_records"] != 0
        or previous["trade_queue_bytes"] != 0
        or previous["trade_last_socket_activity_mono_ns"]
        != trade["last_socket_activity_mono_ns"]
        or previous["trade_last_market_message_mono_ns"]
        != trade["last_market_message_mono_ns"]
        or previous["depth_max_sync_duration_ns"] == 0
        or previous["trade_max_sync_duration_ns"] == 0
        or terminal_record_digest != expected_terminal_record
        or previous["mono_ns"] != expected_terminal_mono
        or previous["mono_ns"] < duration_requested_s * 1_000_000_000
    ):
        _fail("telemetry terminal counters differ from sealed raw streams")
    return {
        "file": telemetry_file,
        "records": expected_records,
        "durable_through_offset": expected_offset,
        "terminal_record_sha256": terminal_record_digest,
        "terminal_mono_ns": expected_terminal_mono,
        "file_sha256": actual_digest,
    }


def _verify_segmented_generation(root: Path) -> dict[str, object]:
    if not root.exists() or not root.is_dir():
        _fail("generation directory is missing or not a directory")
    if _is_linklike(root):
        _fail("generation directory must not be a symbolic link or junction")
    generation, generation_file_digest = _load_generation(root)
    if _text(generation, "schema", "generation manifest") != "RawGenerationManifestV1":
        _fail("invalid generation manifest schema")
    if _text(generation, "implementation", "generation manifest") != "rust-segmented":
        _fail("generation implementation is not rust-segmented")
    session_id = _text(generation, "session_id", "generation manifest")
    if root.name != session_id:
        _fail("generation directory name differs from session_id")
    generation_index = _u64(generation, "generation_index", "generation manifest")
    if _text(generation, "status", "generation manifest") != "COMPLETE":
        _fail("generation status is not COMPLETE")
    symbol = _text(generation, "symbol", "generation manifest")
    if symbol not in {"BTCUSDT", "ETHUSDT"}:
        _fail("generation symbol is outside the fixed scope")
    duration = _u64(generation, "duration_requested_s", "generation manifest")
    segment_duration = _u64(generation, "segment_duration_s", "generation manifest")
    if duration == 0 or segment_duration == 0 or segment_duration > duration:
        _fail("segment duration exceeds generation duration")
    if segment_duration > U64_MAX // 1_000_000_000:
        _fail("segment duration nanoseconds overflow")
    if duration > U64_MAX // 1_000_000_000:
        _fail("generation duration nanoseconds overflow")
    segment_duration_ns = segment_duration * 1_000_000_000
    active_end_ns = duration * 1_000_000_000
    started = _u64(generation, "started_wall_ns", "generation manifest")
    finished = _u64(generation, "finished_wall_ns", "generation manifest")
    if started == 0 or finished < started:
        _fail("generation wall-clock bounds are invalid")
    if _text(generation, "credentials", "generation manifest") != "NONE":
        _fail("generation unexpectedly used credentials")
    if _text(generation, "order_entry", "generation manifest") != "ABSENT":
        _fail("generation unexpectedly included order entry")
    if _text(generation, "raw_boundary", "generation manifest") != (
        "WebSocket application messages after TLS/framing and before JSON interpretation"
    ):
        _fail("generation raw boundary differs from the capture contract")
    spec_revision = _text(generation, "spec_revision", "generation manifest")
    if spec_revision != "976cc580553890e92031b77306147c0ed1de5a46":
        _fail("generation spec revision differs from the capture contract")
    if generation.get("failure") is not None:
        _fail("complete generation contains a failure")
    collector_executable_sha256 = _digest(
        generation.get("collector_executable_sha256"),
        "generation collector_executable_sha256",
    )
    public_config_sha256 = _digest(
        generation.get("public_config_sha256"),
        "generation public_config_sha256",
    )
    if (
        _u64(
            generation,
            "market_freshness_startup_grace_s",
            "generation manifest",
        )
        != MARKET_FRESHNESS_STARTUP_GRACE_S
        or _u64(
            generation,
            "market_freshness_deadline_s",
            "generation manifest",
        )
        != MARKET_FRESHNESS_DEADLINE_S
    ):
        _fail("generation market freshness contract differs from the verifier")
    startup_file, startup_digest = _validate_startup(root, generation)

    snapshot = _object(generation.get("snapshot"), "generation snapshot")
    _ordered_keys(snapshot, _SNAPSHOT_KEYS, "generation snapshot")
    snapshot_endpoint = _text(snapshot, "endpoint", "generation snapshot")
    expected_snapshot_endpoint = (
        f"https://data-api.binance.vision/api/v3/depth?symbol={symbol}&limit=5000"
    )
    if snapshot_endpoint != expected_snapshot_endpoint:
        _fail("snapshot endpoint differs from the capture contract")
    if _u64(snapshot, "http_status", "generation snapshot") != 200:
        _fail("snapshot HTTP status is not 200")
    last_update_id = _u64(snapshot, "last_update_id", "generation snapshot")
    bid_levels = _usize(snapshot, "bid_levels", "generation snapshot")
    ask_levels = _usize(snapshot, "ask_levels", "generation snapshot")
    snapshot_file = _text(snapshot, "raw_file", "generation snapshot")
    _relative_parts(snapshot_file, "generation snapshot.raw_file", count=1)
    if snapshot_file != "snapshot.bnraw":
        _fail("snapshot raw file name differs from the capture contract")
    snapshot_ack = _parse_ack(snapshot.get("durability_ack"), "snapshot durability ACK")
    snapshot_ack_streams = snapshot_ack["streams"]
    if not isinstance(snapshot_ack_streams, list):
        _fail("snapshot durability ACK streams changed after validation")
    snapshot_watermark = _object(snapshot_ack_streams[0], "snapshot watermark")
    snapshot_expected = _RawExpectations(
        connection_epoch=str(snapshot_watermark["connection_epoch"]),
        stream=str(snapshot_watermark["stream"]),
        first_frame_index=0,
        initial_previous_sha256=ZERO_DIGEST,
        symbol=symbol,
        endpoint=snapshot_endpoint,
        spec_revision=spec_revision,
    )
    if snapshot_expected.stream != f"{symbol.lower()}@rest-depth-snapshot":
        _fail("snapshot stream identity differs from the capture contract")
    snapshot_scan = _scan_raw_segment(
        _safe_file(root, snapshot_file, "snapshot raw file"),
        snapshot_expected,
        capture_payload=True,
    )
    if (
        snapshot_scan.records != 1
        or snapshot_scan.first_frame_index != 0
        or snapshot_scan.last_frame_index != 0
        or snapshot_ack["durable_record_count"] != 1
        or snapshot_ack["durable_through_offset"] != snapshot_scan.file_size
        or snapshot_ack["last_record_sha256"] != snapshot_scan.last_record_sha256
        or snapshot_watermark["durable_through_frame_index"] != 0
    ):
        _fail("snapshot durability ACK does not match the exact BNRAW file")
    snapshot_record = snapshot_scan.captured_record
    if snapshot_record is None:
        _fail("snapshot BNRAW payload is missing")
    snapshot_value = _object(
        _parse_json(snapshot_record.payload, "snapshot payload"),
        "snapshot payload",
    )
    if (
        type(snapshot_value.get("lastUpdateId")) is not int
        or snapshot_value["lastUpdateId"] != last_update_id
    ):
        _fail("snapshot lastUpdateId differs from its raw payload")
    bids = _levels(snapshot_value.get("bids"), "snapshot bids")
    asks = _levels(snapshot_value.get("asks"), "snapshot asks")
    if len(bids) != bid_levels:
        _fail("snapshot bid-level count differs from its raw payload")
    if len(asks) != ask_levels:
        _fail("snapshot ask-level count differs from its raw payload")
    http_metadata_file, http_metadata_digest = _validate_snapshot_http(
        root,
        snapshot,
        snapshot_record,
    )

    stream_values = generation.get("streams")
    if not isinstance(stream_values, list) or len(stream_values) != 2:
        _fail("generation must contain exactly depth and trade streams")
    stream_reports: list[dict[str, object]] = []
    names: set[str] = set()
    epochs: set[str] = set()
    for position, stream_value in enumerate(stream_values):
        stream = _object(stream_value, f"generation stream[{position}]")
        _ordered_keys(stream, _STREAM_KEYS, f"generation stream[{position}]")
        name = _text(stream, "name", f"generation stream[{position}]")
        if name not in {"depth", "trade"} or name in names:
            _fail("generation streams are missing or duplicated")
        names.add(name)
        uri = _text(stream, "uri", f"generation stream {name}")
        expected_stream_name = (
            f"{symbol.lower()}@depth@100ms" if name == "depth" else f"{symbol.lower()}@trade"
        )
        expected_uri = (
            f"wss://data-stream.binance.vision:443/ws/{expected_stream_name}?timeUnit=MICROSECOND"
        )
        if uri != expected_uri:
            _fail(f"generation {name} URI differs from the capture contract")
        epoch = _text(stream, "connection_epoch", f"generation stream {name}")
        if epoch in epochs:
            _fail("generation stream connection epochs are not unique")
        epochs.add(epoch)
        transport_report = _validate_transport_metadata(
            root,
            stream,
            session_id=session_id,
            generation_index=generation_index,
            symbol=symbol,
            expected_uri=expected_uri,
        )
        transport_journal_report = _validate_transport_journal(root, stream)
        received = _u64(stream, "received", f"generation stream {name}")
        written = _u64(stream, "written", f"generation stream {name}")
        durable = _u64(stream, "durable_records", f"generation stream {name}")
        segment_count = _u64(stream, "segments", f"generation stream {name}")
        last_socket_activity_mono_ns = _u64(
            stream,
            "last_socket_activity_mono_ns",
            f"generation stream {name}",
        )
        last_market_message_mono_ns = _u64(
            stream,
            "last_market_message_mono_ns",
            f"generation stream {name}",
        )
        server_shutdown_events = _u64(
            stream,
            "server_shutdown_events",
            f"generation stream {name}",
        )
        if received == 0 or received != written or written != durable or segment_count == 0:
            _fail(f"generation {name} terminal counts are inconsistent")
        manifest_relative = _text(stream, "segment_manifest", f"generation stream {name}")
        _relative_parts(manifest_relative, f"generation stream {name}.segment_manifest", count=2)
        if manifest_relative != f"{name}/segments.bnseg":
            _fail(f"generation {name} manifest path differs from the capture contract")
        expected_manifest_digest = _digest(
            stream.get("segment_manifest_sha256"),
            f"generation stream {name}.segment_manifest_sha256",
        )
        expected_terminal_digest = _digest(
            stream.get("terminal_raw_sha256"),
            f"generation stream {name}.terminal_raw_sha256",
        )
        if stream.get("error") is not None:
            _fail(f"generation {name} contains a stream error")

        manifest_path = _safe_file(root, manifest_relative, f"generation {name} manifest")
        manifest_scan = _scan_segment_manifest(manifest_path)
        if manifest_scan.records != segment_count:
            _fail(f"generation {name} segment count differs from its manifest")
        if manifest_scan.last_record_sha256 != expected_manifest_digest:
            _fail(f"generation {name} manifest digest mismatch")
        if manifest_scan.seals[-1]["terminal_record_sha256"] != expected_terminal_digest:
            _fail(f"generation {name} terminal raw digest mismatch")

        segment_reports: list[dict[str, object]] = []
        total_records = 0
        sequence = _SequenceState(freshness_active_end_ns=active_end_ns)
        expected_stream_entries = {"segments.bnseg"}
        for seal in manifest_scan.seals:
            segment_index = int(seal["segment_index"])
            raw_file = str(seal["raw_file"])
            if raw_file != f"segment-{segment_index:06}.bnraw":
                _fail(f"generation {name} raw segment name is not canonical")
            raw_relative = f"{name}/{raw_file}"
            if seal["connection_epoch"] != epoch or seal["stream"] != expected_stream_name:
                _fail(f"generation {name} identity differs from its segment manifest")
            raw_expected = _RawExpectations(
                connection_epoch=epoch,
                stream=expected_stream_name,
                first_frame_index=int(seal["first_frame_index"]),
                initial_previous_sha256=str(seal["previous_segment_terminal_sha256"]),
                symbol=symbol,
                endpoint=uri,
                spec_revision=spec_revision,
            )
            progress_file = f"segment-{segment_index:06}.bnack"
            progress_relative = f"{name}/{progress_file}"
            progress_scan = _scan_progress(
                _safe_file(root, progress_relative, f"generation {name} BNACK"),
                raw_file,
                raw_expected,
            )
            latest_ack = progress_scan.acknowledgements[-1]
            latest_streams = latest_ack["streams"]
            if not isinstance(latest_streams, list):
                _fail("terminal BNACK streams changed after validation")
            latest_watermark = _object(latest_streams[0], "terminal BNACK watermark")
            if (
                latest_ack["durable_record_count"] != seal["records"]
                or latest_ack["durable_through_offset"] != seal["durable_through_offset"]
                or latest_ack["last_record_sha256"] != seal["terminal_record_sha256"]
                or latest_watermark["durable_through_frame_index"]
                != seal["last_frame_index"]
            ):
                _fail(f"generation {name} terminal BNACK differs from its seal")
            raw_scan = _scan_raw_segment(
                _safe_file(root, raw_relative, f"generation {name} raw segment"),
                raw_expected,
                acknowledgements=progress_scan.acknowledgements,
                stream_kind=name,
                snapshot_sequence=last_update_id,
                sequence=sequence,
                segment_index=segment_index,
                segment_duration_ns=segment_duration_ns,
                require_server_shutdown_ack=True,
            )
            if (
                raw_scan.records != seal["records"]
                or raw_scan.file_size != seal["durable_through_offset"]
                or raw_scan.last_good_offset != seal["durable_through_offset"]
                or raw_scan.first_frame_index != seal["first_frame_index"]
                or raw_scan.last_frame_index != seal["last_frame_index"]
                or raw_scan.last_record_sha256 != seal["terminal_record_sha256"]
            ):
                _fail(f"generation {name} raw segment differs from its manifest seal")
            total_records += raw_scan.records
            expected_stream_entries.update({raw_file, progress_file})
            segment_reports.append(
                {
                    "segment_index": segment_index,
                    "raw_file": raw_file,
                    "records": raw_scan.records,
                    "durable_through_offset": raw_scan.last_good_offset,
                    "terminal_record_sha256": raw_scan.last_record_sha256,
                    "raw_file_sha256": raw_scan.file_sha256,
                    "durability_progress_file": progress_file,
                    "durability_progress_records": progress_scan.records,
                    "durability_progress_terminal_sha256": (
                        progress_scan.last_record_sha256
                    ),
                    "durability_progress_file_sha256": progress_scan.file_sha256,
                }
            )
        if (
            total_records != durable
            or manifest_scan.seals[0]["first_frame_index"] != 0
            or manifest_scan.seals[-1]["last_frame_index"] != received - 1
            or not sequence.started
            or sequence.first is None
            or sequence.final is None
            or sequence.last_market_mono_ns != last_market_message_mono_ns
            or last_socket_activity_mono_ns < last_market_message_mono_ns
            or sequence.server_shutdown_events != server_shutdown_events
        ):
            _fail(f"generation {name} durable count differs from sealed raw records")
        _validate_raw_market_freshness(sequence, name, active_end_ns)
        _exact_entries(root / name, expected_stream_entries, f"generation {name} directory")
        stream_reports.append(
            {
                "name": name,
                "connection_epoch": epoch,
                "transport": transport_report,
                "transport_journal": transport_journal_report,
                "records": total_records,
                "segments": len(segment_reports),
                "segment_manifest": manifest_relative,
                "segment_manifest_records_sha256": manifest_scan.last_record_sha256,
                "segment_manifest_file_sha256": manifest_scan.file_sha256,
                "terminal_raw_sha256": expected_terminal_digest,
                "first_sequence": sequence.first,
                "final_sequence": sequence.final,
                "last_socket_activity_mono_ns": last_socket_activity_mono_ns,
                "last_market_message_mono_ns": last_market_message_mono_ns,
                "server_shutdown_events": server_shutdown_events,
                "server_shutdowns": list(sequence.server_shutdowns),
                "sealed_segments": segment_reports,
            }
        )
    stream_reports.sort(key=lambda item: str(item["name"]))
    if [stream["name"] for stream in stream_reports] != ["depth", "trade"]:
        _fail("generation stream set differs from depth/trade")
    telemetry_report = _validate_telemetry(
        root,
        generation.get("telemetry"),
        stream_reports,
        duration,
    )
    root_inventory = _exact_entries(
        root,
        {
            "depth",
            "generation.json",
            "snapshot-http.json",
            "snapshot.bnraw",
            "startup.json",
            "telemetry.jsonl",
            "transport-depth.json",
            "transport-depth-events.jsonl",
            "transport-trade.json",
            "transport-trade-events.jsonl",
            "trade",
        },
        "generation directory",
    )

    report: dict[str, object] = {
        "schema": "SegmentedGenerationVerificationV1",
        "status": "VERIFIED",
        "session_id": session_id,
        "generation_index": generation_index,
        "symbol": symbol,
        "generation_manifest_file_sha256": generation_file_digest,
        "collector_executable_sha256": collector_executable_sha256,
        "public_config_sha256": public_config_sha256,
        "startup": {
            "file": startup_file,
            "file_sha256": startup_digest,
        },
        "snapshot": {
            "raw_file": snapshot_file,
            "records": snapshot_scan.records,
            "durable_through_offset": snapshot_scan.last_good_offset,
            "terminal_record_sha256": snapshot_scan.last_record_sha256,
            "raw_file_sha256": snapshot_scan.file_sha256,
            "http_metadata_file": http_metadata_file,
            "http_metadata_file_sha256": http_metadata_digest,
        },
        "telemetry": telemetry_report,
        "streams": stream_reports,
        "inventory": root_inventory,
    }
    report["verification_sha256"] = sha256(_canonical_json(report)).hexdigest()
    return report


def verify_segmented_generation(generation_directory: Path) -> dict[str, object]:
    """Verify one completed Rust segmented generation, or raise fail-closed."""

    try:
        return _verify_segmented_generation(Path(generation_directory))
    except SegmentChainCorruption:
        raise
    except (OSError, TypeError, ValueError, OverflowError) as exc:
        raise SegmentChainCorruption(f"segmented generation verification failed: {exc}") from exc
