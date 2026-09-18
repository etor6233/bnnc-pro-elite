"""Terminal, raw-only verifier for completed Rust capture campaigns.

This module verifies immutable transport evidence and campaign provenance.  It
temporarily reconstructs exact depth state and trade identity only to re-prove
an A/B handover; it emits no book, feature, label, signal, or inferred trade-ID
loss and never modifies the raw evidence.
"""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import struct
from typing import BinaryIO, NoReturn

from .segment_chain import (
    MANIFEST_MAGIC,
    SegmentChainCorruption,
    ZERO_DIGEST,
    _RawExpectations,
    _RawRecordInfo,
    _SequenceState,
    _scan_raw_segment,
    verify_segmented_generation,
)


SPEC_REVISION = "976cc580553890e92031b77306147c0ed1de5a46"
LENGTH = struct.Struct(">I")
DIGEST_BYTES = 32
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_JOURNAL_RECORD_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_RECORD_BYTES = 1024 * 1024
U64_MAX = (1 << 64) - 1

_STARTUP_KEYS = (
    "schema",
    "campaign_id",
    "symbol",
    "total_duration_s",
    "rotation_s",
    "overlap_s",
    "segment_s",
    "started_wall_ns",
    "process_id",
    "executable_sha256",
    "capture_executable_sha256",
    "public_config_sha256",
    "spec_revision",
    "credentials",
    "order_entry",
)
_CAMPAIGN_KEYS_V1 = (
    "schema",
    "status",
    "campaign_id",
    "symbol",
    "total_duration_s",
    "rotation_s",
    "overlap_s",
    "segment_s",
    "started_wall_ns",
    "finished_wall_ns",
    "spec_revision",
    "credentials",
    "order_entry",
    "executable_sha256",
    "capture_executable_sha256",
    "public_config_sha256",
    "startup_file",
    "startup_sha256",
    "journal_file",
    "journal_boundary",
    "journal_precommit_records",
    "journal_precommit_sha256",
    "supervisor_gap_count",
    "generations",
    "handovers",
)
_CAMPAIGN_GENERATION_KEYS = (
    "generation_index",
    "session_id",
    "session_dir",
    "verification_sha256",
    "evaluation_file",
    "evaluation_file_sha256",
    "generation_manifest_sha256",
    "depth_records",
    "trade_records",
)
_CAMPAIGN_HANDOVER_KEYS = (
    "predecessor_generation_index",
    "successor_generation_index",
    "proof_sha256",
    "proof_file",
    "proof_file_sha256",
)
_JOURNAL_ENVELOPE_KEYS = ("body", "record_sha256")
_JOURNAL_BODY_KEYS = (
    "schema",
    "record_index",
    "wall_ns",
    "campaign_mono_ns",
    "generation_index",
    "channel",
    "payload",
    "previous_record_sha256",
)
_GENERATION_MANIFEST_KEYS = (
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
_EVALUATION_KEYS = (
    "schema",
    "status",
    "session_id",
    "session_dir",
    "generation_index",
    "symbol",
    "duration_requested_s",
    "segment_duration_s",
    "started_wall_ns",
    "finished_wall_ns",
    "collector_executable_sha256",
    "public_config_sha256",
    "generation_manifest_sha256",
    "snapshot_sha256",
    "snapshot_record_sha256",
    "snapshot_last_update_id",
    "telemetry_sha256",
    "telemetry_records",
    "streams",
    "verification_sha256",
)
_EVALUATION_STREAM_KEYS = (
    "schema",
    "name",
    "connection_epoch",
    "records",
    "segments",
    "first_frame_index",
    "last_frame_index",
    "first_sequence",
    "final_sequence",
    "last_socket_activity_mono_ns",
    "last_market_message_mono_ns",
    "server_shutdown_events",
    "manifest_sha256",
    "terminal_raw_sha256",
    "entries",
)
_EVALUATION_ENTRY_KEYS = (
    "schema",
    "record_index",
    "previous_manifest_record_sha256",
    "manifest_record_sha256",
    "seal",
)
_MANIFEST_BODY_KEYS = (
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
_HANDOVER_KEYS = (
    "schema",
    "status",
    "predecessor_session_id",
    "successor_session_id",
    "predecessor_generation_index",
    "successor_generation_index",
    "symbol",
    "credentials",
    "order_entry",
    "predecessor_verification_sha256",
    "successor_startup_sha256",
    "successor_snapshot_record_sha256",
    "successor_snapshot_http_sha256",
    "depth",
    "trade",
    "proof_sha256",
)
_SEGMENT_REFERENCE_KEYS = (
    "stream",
    "connection_epoch",
    "segment_index",
    "manifest_record_sha256",
    "raw_file",
    "first_frame_index",
    "last_frame_index",
    "terminal_record_sha256",
)
_POSITION_KEYS = ("connection_epoch", "stream", "frame_index", "record_sha256")
_DEPTH_EVIDENCE_KEYS = (
    "schema",
    "predecessor_segment",
    "successor_segment",
    "boundary_sequence",
    "boundary_state_sha256",
    "predecessor_boundary",
    "successor_boundary",
    "successor_continuation",
    "successor_continuation_first_sequence",
    "successor_continuation_final_sequence",
)
_TRADE_EVIDENCE_KEYS = (
    "schema",
    "predecessor_segment",
    "successor_segment",
    "common_lower_trade_id",
    "common_upper_trade_id",
    "common_events",
    "first_shared_trade_id",
    "first_shared_event_sha256",
    "predecessor_first_shared",
    "successor_first_shared",
    "next_shared_trade_id",
    "next_shared_event_sha256",
    "predecessor_next_shared",
    "successor_next_shared",
    "trade_id_contiguity_claim",
)
_SERVER_SHUTDOWN_IDENTITY_KEYS = (
    "stream",
    "connection_epoch",
    "segment_index",
    "raw_file",
    "frame_index",
    "receive_mono_ns",
    "durable_record_count",
    "durable_through_offset",
    "last_record_sha256",
)
_SERVER_SHUTDOWN_EVENT_KEYS = tuple(
    sorted(("schema", *_SERVER_SHUTDOWN_IDENTITY_KEYS))
)
_JOURNAL_EVENT_ALLOWLISTS = {
    "CHILD_STDOUT": {
        "PROCESS_STARTED",
        "TRANSPORT_CONNECTED",
        "SNAPSHOT_DURABLE",
        "SEGMENT_DURABLE",
        "SERVER_SHUTDOWN_DURABLE",
        "HEARTBEAT_DURABLE",
        "PROCESS_TERMINAL",
    },
    "CAMPAIGN": {
        "CAMPAIGN_STARTED",
        "GENERATION_LAUNCHED",
        "GENERATION_LAUNCHED_SERVER_SHUTDOWN",
        "GENERATION_EXITED",
        "HANDOVER_PROOF_STARTED",
        "CAMPAIGN_EVALUATION_PREPARED",
        "CAMPAIGN_COMMITTED",
        "CAMPAIGN_FAILED",
    },
    "SUPERVISOR": {
        "INITIAL_ACTIVE_REGISTERED",
        "CANDIDATE_REGISTERED",
        "HANDOVER_PROVEN_AND_PROMOTED",
        "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE",
        "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING",
        "GENERATION_DISCONNECT_FAIL_CLOSED",
    },
}
_CHILD_EVENT_SCHEMAS = {
    "PROCESS_STARTED": "CaptureProcessEventV1",
    "TRANSPORT_CONNECTED": "TransportConnectedProcessEventV1",
    "SNAPSHOT_DURABLE": "SnapshotDurableProcessEventV1",
    "SEGMENT_DURABLE": "SegmentDurableProcessEventV1",
    "SERVER_SHUTDOWN_DURABLE": "ServerShutdownDurableProcessEventV1",
    "HEARTBEAT_DURABLE": "HeartbeatProcessEventV1",
    "PROCESS_TERMINAL": "CaptureTerminalProcessEventV1",
}


class RawCampaignCorruption(ValueError):
    """A terminal campaign is incomplete, ambiguous, or internally corrupt."""


def _fail(reason: str) -> NoReturn:
    raise RawCampaignCorruption(reason)


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
        return json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_json_constant,
        )
    except RawCampaignCorruption:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"invalid {label} JSON: {exc}")


def _compact_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _fail(f"cannot serialize JSON exactly: {exc}")


def _pretty_json(value: object) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        _fail(f"cannot serialize pretty JSON exactly: {exc}")


def _rust_value(value: object) -> object:
    """Reproduce serde_json::Value map ordering without preserve_order."""

    if isinstance(value, dict):
        return {key: _rust_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_rust_value(item) for item in value]
    return value


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        _fail(f"{label} must be a JSON array")
    return value


def _keys(value: dict[str, object], expected: tuple[str, ...], label: str) -> None:
    if tuple(value) != expected:
        _fail(f"{label} has unknown, missing, or reordered fields")


def _text(value: dict[str, object], field: str, label: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        _fail(f"{label}.{field} must be a non-empty string")
    return item


def _u64(value: dict[str, object], field: str, label: str) -> int:
    item = value.get(field)
    if type(item) is not int or item < 0 or item > U64_MAX:
        _fail(f"{label}.{field} must be a u64")
    return item


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _server_shutdown_identity(
    value: dict[str, object],
    label: str,
    *,
    event_payload: bool = False,
) -> tuple[object, ...]:
    expected_keys = (
        set(_SERVER_SHUTDOWN_EVENT_KEYS)
        if event_payload
        else set(_SERVER_SHUTDOWN_IDENTITY_KEYS)
    )
    if set(value) != expected_keys or len(value) != len(expected_keys):
        _fail(f"{label} has unknown or missing fields")
    if event_payload and value.get("schema") != "DurableServerShutdownEventV1":
        _fail(f"{label} schema is invalid")
    stream = _text(value, "stream", label)
    if stream not in {"depth", "trade"}:
        _fail(f"{label} stream is invalid")
    epoch = _text(value, "connection_epoch", label)
    segment_index = _u64(value, "segment_index", label)
    raw_file = _text(value, "raw_file", label)
    if raw_file != f"segment-{segment_index:06}.bnraw":
        _fail(f"{label} raw file is not canonical")
    frame_index = _u64(value, "frame_index", label)
    receive_mono_ns = _u64(value, "receive_mono_ns", label)
    durable_record_count = _u64(value, "durable_record_count", label)
    durable_through_offset = _u64(value, "durable_through_offset", label)
    last_record_sha256 = _digest(
        value.get("last_record_sha256"), f"{label}.last_record_sha256"
    )
    if (
        receive_mono_ns == 0
        or durable_record_count == 0
        or durable_through_offset == 0
    ):
        _fail(f"{label} contains a zero durable boundary")
    return (
        stream,
        epoch,
        segment_index,
        raw_file,
        frame_index,
        receive_mono_ns,
        durable_record_count,
        durable_through_offset,
        last_record_sha256,
    )


def _is_linklike(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (is_junction is not None and bool(is_junction()))


def _safe_component(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or value in {".", ".."}
        or any(character in value for character in ("/", "\\", ":", "\x00"))
    ):
        _fail(f"{label} must be one safe path component")
    return value


def _relative_path(value: object, label: str, *, parts: int | None = None) -> tuple[str, ...]:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or "\x00" in value
    ):
        _fail(f"{label} must be a portable relative path")
    result = tuple(value.split("/"))
    if any(not item or item in {".", ".."} for item in result):
        _fail(f"{label} is not safe")
    if parts is not None and len(result) != parts:
        _fail(f"{label} has an invalid path depth")
    return result


def _safe_file(root: Path, relative: str, label: str) -> Path:
    parts = _relative_path(relative, label)
    current = root
    for item in parts:
        current /= item
        if _is_linklike(current):
            _fail(f"{label} must not traverse a link or junction")
    try:
        resolved_root = root.resolve(strict=True)
        resolved = current.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        _fail(f"{label} is missing or escapes the campaign: {exc}")
    if not resolved.is_file():
        _fail(f"{label} is not a regular file")
    return resolved


def _stable_bytes(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> bytes:
    if _is_linklike(path):
        _fail(f"{label} must not be a link or junction")
    try:
        before = path.stat()
        if not path.is_file() or before.st_size <= 0 or before.st_size > maximum:
            _fail(f"{label} has an invalid type or size")
        data = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        _fail(f"cannot read {label}: {exc}")
    if (
        len(data) != before.st_size
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        _fail(f"{label} changed while it was read")
    return data


def _load_pretty(path: Path, keys: tuple[str, ...], label: str) -> tuple[dict[str, object], bytes]:
    data = _stable_bytes(path, label)
    value = _object(_parse_json(data, label), label)
    _keys(value, keys, label)
    if _pretty_json(value) != data:
        _fail(f"{label} is not the exact Rust pretty JSON encoding")
    return value, data


def _exact_entries(path: Path, expected: set[str], label: str) -> list[str]:
    if _is_linklike(path) or not path.is_dir():
        _fail(f"{label} must be a regular directory, not a link or junction")
    try:
        entries = list(path.iterdir())
    except OSError as exc:
        _fail(f"cannot enumerate {label}: {exc}")
    actual = {item.name for item in entries}
    if len(entries) != len(actual) or actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        _fail(f"{label} inventory mismatch; missing={missing}, extra={extra}")
    for item in entries:
        if _is_linklike(item):
            _fail(f"{label} contains a link or junction: {item.name}")
    return sorted(actual)


def _check_session_path(value: str, campaign_id: str, session_id: str, label: str) -> None:
    if "\x00" in value:
        _fail(f"{label} contains NUL")
    normalized = value.replace("\\", "/").rstrip("/")
    components = normalized.split("/")
    if components and components[0] == "":
        components = components[1:]
    if any(not component or component in {".", ".."} for component in components):
        _fail(f"{label} is malformed")
    expected = [campaign_id, "generations", session_id]
    if components[-3:] != expected:
        _fail(f"{label} does not identify the exact campaign generation")


def _read_exact(handle: BinaryIO, count: int, reason: str) -> bytes:
    value = handle.read(count)
    if len(value) != count:
        _fail(reason)
    return value


def _scan_manifest_entries(path: Path) -> tuple[list[dict[str, object]], str]:
    entries: list[dict[str, object]] = []
    previous = ZERO_DIGEST
    try:
        with path.open("rb", buffering=0) as handle:
            before = os.fstat(handle.fileno())
            if _read_exact(handle, len(MANIFEST_MAGIC), "bad BNSEG magic") != MANIFEST_MAGIC:
                _fail("bad BNSEG magic")
            while True:
                prefix = handle.read(LENGTH.size)
                if not prefix:
                    break
                if len(prefix) != LENGTH.size:
                    _fail("partial BNSEG length prefix")
                (size,) = LENGTH.unpack(prefix)
                if size == 0 or size > MAX_MANIFEST_RECORD_BYTES:
                    _fail("BNSEG record length is invalid")
                body = _read_exact(handle, size, "partial BNSEG body")
                stored = _read_exact(handle, DIGEST_BYTES, "partial BNSEG digest")
                if sha256(body).digest() != stored:
                    _fail("BNSEG record digest mismatch")
                manifest = _object(_parse_json(body, "BNSEG record"), "BNSEG record")
                _keys(manifest, _MANIFEST_BODY_KEYS, "BNSEG record")
                if _compact_json(manifest) != body:
                    _fail("BNSEG record is not exact canonical JSON")
                index = _u64(manifest, "record_index", "BNSEG record")
                if (
                    _text(manifest, "schema", "BNSEG record")
                    != "RawSegmentManifestRecordV1"
                    or index != len(entries)
                    or _digest(
                        manifest.get("previous_manifest_record_sha256"),
                        "BNSEG previous digest",
                    )
                    != previous
                ):
                    _fail("BNSEG record identity/hash-chain mismatch")
                seal = _object(manifest.get("seal"), "BNSEG seal")
                _keys(seal, _SEAL_KEYS, "BNSEG seal")
                entry = {
                    "schema": "RawSegmentManifestEntryV1",
                    "record_index": index,
                    "previous_manifest_record_sha256": previous,
                    "manifest_record_sha256": stored.hex(),
                    "seal": seal,
                }
                entries.append(entry)
                previous = stored.hex()
            after = os.fstat(handle.fileno())
            final_offset = handle.tell()
    except RawCampaignCorruption:
        raise
    except OSError as exc:
        _fail(f"cannot scan BNSEG: {exc}")
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or final_offset != after.st_size
        or not entries
    ):
        _fail("BNSEG is empty, changed, or has a partial tail")
    return entries, previous


def _expected_evaluation(
    generation_root: Path,
    oracle: dict[str, object],
    generation: dict[str, object],
    session_dir: str,
) -> dict[str, object]:
    stream_reports = {
        str(item["name"]): item for item in _array(oracle.get("streams"), "oracle streams")
        if isinstance(item, dict)
    }
    streams: list[dict[str, object]] = []
    for name in ("depth", "trade"):
        report = _object(stream_reports.get(name), f"oracle {name} stream")
        entries, manifest_digest = _scan_manifest_entries(
            generation_root / name / "segments.bnseg"
        )
        if manifest_digest != report.get("segment_manifest_records_sha256"):
            _fail(f"oracle/BNSEG {name} manifest digest mismatch")
        first = _object(entries[0]["seal"], f"{name} first seal")
        last = _object(entries[-1]["seal"], f"{name} last seal")
        streams.append(
            {
                "schema": "VerifiedGenerationStreamV1",
                "name": name,
                "connection_epoch": report["connection_epoch"],
                "records": report["records"],
                "segments": report["segments"],
                "first_frame_index": first["first_frame_index"],
                "last_frame_index": last["last_frame_index"],
                "first_sequence": report["first_sequence"],
                "final_sequence": report["final_sequence"],
                "last_socket_activity_mono_ns": report[
                    "last_socket_activity_mono_ns"
                ],
                "last_market_message_mono_ns": report[
                    "last_market_message_mono_ns"
                ],
                "server_shutdown_events": report["server_shutdown_events"],
                "manifest_sha256": manifest_digest,
                "terminal_raw_sha256": report["terminal_raw_sha256"],
                "entries": entries,
            }
        )
    snapshot = _object(generation.get("snapshot"), "generation snapshot")
    telemetry = _object(generation.get("telemetry"), "generation telemetry")
    oracle_snapshot = _object(oracle.get("snapshot"), "oracle snapshot")
    expected: dict[str, object] = {
        "schema": "VerifiedGenerationV1",
        "status": "PASS",
        "session_id": generation["session_id"],
        "session_dir": session_dir,
        "generation_index": generation["generation_index"],
        "symbol": generation["symbol"],
        "duration_requested_s": generation["duration_requested_s"],
        "segment_duration_s": generation["segment_duration_s"],
        "started_wall_ns": generation["started_wall_ns"],
        "finished_wall_ns": generation["finished_wall_ns"],
        "collector_executable_sha256": generation["collector_executable_sha256"],
        "public_config_sha256": generation["public_config_sha256"],
        "generation_manifest_sha256": oracle["generation_manifest_file_sha256"],
        "snapshot_sha256": oracle_snapshot["raw_file_sha256"],
        "snapshot_record_sha256": oracle_snapshot["terminal_record_sha256"],
        "snapshot_last_update_id": snapshot["last_update_id"],
        "telemetry_sha256": telemetry["file_sha256"],
        "telemetry_records": telemetry["records"],
        "streams": streams,
    }
    material = {
        "schema": "VerifiedGenerationDigestV1",
        "session_id": expected["session_id"],
        "generation_index": expected["generation_index"],
        "symbol": expected["symbol"],
        "duration_requested_s": expected["duration_requested_s"],
        "segment_duration_s": expected["segment_duration_s"],
        "collector_executable_sha256": expected["collector_executable_sha256"],
        "public_config_sha256": expected["public_config_sha256"],
        "generation_manifest_sha256": expected["generation_manifest_sha256"],
        "snapshot_sha256": expected["snapshot_sha256"],
        "snapshot_record_sha256": expected["snapshot_record_sha256"],
        "snapshot_last_update_id": expected["snapshot_last_update_id"],
        "telemetry_sha256": expected["telemetry_sha256"],
        "telemetry_records": expected["telemetry_records"],
        "streams": streams,
    }
    expected["verification_sha256"] = sha256(_compact_json(material)).hexdigest()
    return expected


def _validate_evaluation_shape(evaluation: dict[str, object], label: str) -> None:
    _keys(evaluation, _EVALUATION_KEYS, label)
    streams = _array(evaluation.get("streams"), f"{label}.streams")
    if len(streams) != 2:
        _fail(f"{label} must contain depth and trade")
    for stream_index, stream_value in enumerate(streams):
        stream = _object(stream_value, f"{label}.streams[{stream_index}]")
        _keys(stream, _EVALUATION_STREAM_KEYS, f"{label}.streams[{stream_index}]")
        entries = _array(stream.get("entries"), f"{label}.streams[{stream_index}].entries")
        if not entries:
            _fail(f"{label} stream has no BNSEG entries")
        for entry_index, entry_value in enumerate(entries):
            entry = _object(entry_value, f"{label} entry[{entry_index}]")
            _keys(entry, _EVALUATION_ENTRY_KEYS, f"{label} entry[{entry_index}]")
            seal = _object(entry.get("seal"), f"{label} entry[{entry_index}].seal")
            _keys(seal, _SEAL_KEYS, f"{label} entry[{entry_index}].seal")


def _validate_reference(
    value: object,
    expected_entry: dict[str, object],
    label: str,
) -> dict[str, object]:
    reference = _object(value, label)
    _keys(reference, _SEGMENT_REFERENCE_KEYS, label)
    seal = _object(expected_entry.get("seal"), f"{label} expected seal")
    expected = {
        "stream": seal["stream"],
        "connection_epoch": seal["connection_epoch"],
        "segment_index": seal["segment_index"],
        "manifest_record_sha256": expected_entry["manifest_record_sha256"],
        "raw_file": seal["raw_file"],
        "first_frame_index": seal["first_frame_index"],
        "last_frame_index": seal["last_frame_index"],
        "terminal_record_sha256": seal["terminal_record_sha256"],
    }
    if reference != expected:
        _fail(f"{label} differs from the exact BNSEG entry")
    return reference


def _validate_position(value: object, reference: dict[str, object], label: str) -> None:
    position = _object(value, label)
    _keys(position, _POSITION_KEYS, label)
    frame = _u64(position, "frame_index", label)
    if (
        position.get("connection_epoch") != reference["connection_epoch"]
        or position.get("stream") != reference["stream"]
        or frame < int(reference["first_frame_index"])
        or frame > int(reference["last_frame_index"])
    ):
        _fail(f"{label} is outside its referenced raw segment")
    _digest(position.get("record_sha256"), f"{label}.record_sha256")


def _evaluation_stream(
    evaluation: dict[str, object], name: str, label: str
) -> dict[str, object]:
    streams = _array(evaluation.get("streams"), f"{label}.streams")
    matches = [
        _object(stream, f"{label}.{name}")
        for stream in streams
        if isinstance(stream, dict) and stream.get("name") == name
    ]
    if len(matches) != 1:
        _fail(f"{label} must contain exactly one {name} stream")
    return matches[0]


def _entry_reference(entry: dict[str, object]) -> dict[str, object]:
    seal = _object(entry.get("seal"), "handover BNSEG seal")
    return {
        "stream": seal["stream"],
        "connection_epoch": seal["connection_epoch"],
        "segment_index": seal["segment_index"],
        "manifest_record_sha256": entry["manifest_record_sha256"],
        "raw_file": seal["raw_file"],
        "first_frame_index": seal["first_frame_index"],
        "last_frame_index": seal["last_frame_index"],
        "terminal_record_sha256": seal["terminal_record_sha256"],
    }


def _observation_position(observation: dict[str, object]) -> dict[str, object]:
    return {
        "connection_epoch": observation["connection_epoch"],
        "stream": observation["stream"],
        "frame_index": observation["frame_index"],
        "record_sha256": observation["record_sha256"],
    }


def _load_handover_snapshot(
    successor_root: Path,
    successor: dict[str, object],
) -> bytes:
    generation, _ = _load_pretty(
        successor_root / "generation.json",
        _GENERATION_MANIFEST_KEYS,
        "handover successor generation manifest",
    )
    snapshot = _object(generation.get("snapshot"), "handover successor snapshot")
    ack = _object(snapshot.get("durability_ack"), "handover successor snapshot ACK")
    streams = _array(ack.get("streams"), "handover successor snapshot ACK streams")
    if len(streams) != 1:
        _fail("handover successor snapshot ACK must contain one watermark")
    watermark = _object(streams[0], "handover successor snapshot watermark")
    symbol = _text(successor, "symbol", "handover successor")
    endpoint = (
        "https://data-api.binance.vision/api/v3/depth?"
        f"symbol={symbol}&limit=5000"
    )
    expected = _RawExpectations(
        connection_epoch=_text(
            watermark, "connection_epoch", "handover successor snapshot watermark"
        ),
        stream=_text(watermark, "stream", "handover successor snapshot watermark"),
        first_frame_index=0,
        initial_previous_sha256=ZERO_DIGEST,
        symbol=symbol,
        endpoint=endpoint,
        spec_revision=SPEC_REVISION,
    )
    if expected.stream != f"{symbol.lower()}@rest-depth-snapshot":
        _fail("handover successor snapshot stream identity is invalid")
    try:
        scan = _scan_raw_segment(
            _safe_file(successor_root, "snapshot.bnraw", "handover successor snapshot"),
            expected,
            capture_payload=True,
            capture_records=True,
        )
    except SegmentChainCorruption as exc:
        _fail(f"handover successor snapshot raw verification failed: {exc}")
    if (
        scan.records != 1
        or scan.captured_record is None
        or scan.captured_records is None
        or len(scan.captured_records) != 1
        or ack.get("durable_record_count") != 1
        or ack.get("durable_through_offset") != scan.file_size
        or ack.get("last_record_sha256") != scan.last_record_sha256
        or watermark.get("durable_through_frame_index") != 0
    ):
        _fail("handover successor snapshot differs from its exact durable raw record")
    return scan.captured_record.payload


def _capture_handover_segment(
    generation_root: Path,
    evaluation: dict[str, object],
    entry: dict[str, object],
    name: str,
    snapshot_sequence: int,
) -> tuple[_RawRecordInfo, ...]:
    seal = _object(entry.get("seal"), f"handover {name} seal")
    symbol = _text(evaluation, "symbol", "handover generation")
    stream = (
        f"{symbol.lower()}@depth@100ms"
        if name == "depth"
        else f"{symbol.lower()}@trade"
    )
    uri = (
        "wss://data-stream.binance.vision:443/ws/"
        f"{stream}?timeUnit=MICROSECOND"
    )
    segment_duration = _u64(
        evaluation, "segment_duration_s", "handover generation"
    )
    if segment_duration > U64_MAX // 1_000_000_000:
        _fail("handover segment duration nanoseconds overflow")
    expected = _RawExpectations(
        connection_epoch=_text(seal, "connection_epoch", f"handover {name} seal"),
        stream=_text(seal, "stream", f"handover {name} seal"),
        first_frame_index=_u64(
            seal, "first_frame_index", f"handover {name} seal"
        ),
        initial_previous_sha256=_digest(
            seal.get("previous_segment_terminal_sha256"),
            f"handover {name} predecessor digest",
        ),
        symbol=symbol,
        endpoint=uri,
        spec_revision=SPEC_REVISION,
    )
    if expected.stream != stream:
        _fail(f"handover {name} stream identity is invalid")
    raw_file = _text(seal, "raw_file", f"handover {name} seal")
    relative = f"{name}/{raw_file}"
    try:
        scan = _scan_raw_segment(
            _safe_file(generation_root, relative, f"handover {name} raw segment"),
            expected,
            capture_records=True,
            stream_kind=name,
            snapshot_sequence=snapshot_sequence,
            sequence=_SequenceState(),
            segment_index=_u64(seal, "segment_index", f"handover {name} seal"),
            segment_duration_ns=segment_duration * 1_000_000_000,
        )
    except SegmentChainCorruption as exc:
        _fail(f"handover {name} raw verification failed: {exc}")
    records = scan.captured_records
    if (
        records is None
        or scan.records != seal.get("records")
        or scan.file_size != seal.get("durable_through_offset")
        or scan.first_frame_index != seal.get("first_frame_index")
        or scan.last_frame_index != seal.get("last_frame_index")
        or scan.last_record_sha256 != seal.get("terminal_record_sha256")
    ):
        _fail(f"handover {name} scan differs from the exact BNSEG seal")
    return records


def _payload_object(record: _RawRecordInfo, label: str) -> dict[str, object]:
    return _object(_parse_json(record.payload, label), label)


def _materialize_depth_window(
    snapshot_payload: bytes,
    records: tuple[_RawRecordInfo, ...],
    entry: dict[str, object],
    symbol: str,
) -> list[dict[str, object]]:
    # This import is intentionally local: exact book reconstruction is used
    # only for the integrity proof and is never exposed as a dataset feature.
    from .book import ApplyOutcome, BookInvariantError, DepthGap, LocalOrderBook

    seal = _object(entry.get("seal"), "depth handover seal")
    first_frame = _u64(seal, "first_frame_index", "depth handover seal")
    book = LocalOrderBook(symbol)
    try:
        book.load_snapshot(snapshot_payload)
    except (ValueError, BookInvariantError) as exc:
        _fail(f"handover snapshot cannot initialize exact depth state: {exc}")
    observations: list[dict[str, object]] = []
    for offset, record in enumerate(records):
        value = _payload_object(record, "handover depth payload")
        if value.get("e") == "serverShutdown":
            continue
        first = _u64(value, "U", "handover depth payload")
        final = _u64(value, "u", "handover depth payload")
        try:
            outcome = book.apply_depth(record.payload)
        except (ValueError, BookInvariantError, DepthGap) as exc:
            _fail(f"handover depth replay failed: {exc}")
        if outcome is ApplyOutcome.OLD:
            if observations:
                _fail("stale depth record appeared after handover state became live")
            continue
        observations.append(
            {
                "connection_epoch": seal["connection_epoch"],
                "stream": seal["stream"],
                "frame_index": first_frame + offset,
                "first_sequence": first,
                "final_sequence": final,
                "record_sha256": record.record_sha256,
                "observation_sha256": book.state_digest(),
            }
        )
    if not observations:
        _fail("handover depth window produced no exact state observation")
    return observations


def _exact_bool(value: dict[str, object], field: str, label: str) -> bool:
    item = value.get(field)
    if type(item) is not bool:
        _fail(f"{label}.{field} must be boolean")
    return item


def _materialize_trade_window(
    records: tuple[_RawRecordInfo, ...],
    entry: dict[str, object],
    symbol: str,
) -> list[dict[str, object]]:
    from .fixed_decimal import FixedDecimal

    seal = _object(entry.get("seal"), "trade handover seal")
    first_frame = _u64(seal, "first_frame_index", "trade handover seal")
    observations: list[dict[str, object]] = []
    previous_trade_id: int | None = None
    for offset, record in enumerate(records):
        value = _payload_object(record, "handover trade payload")
        if value.get("e") == "serverShutdown":
            continue
        trade_id = _u64(value, "t", "handover trade payload")
        _u64(value, "E", "handover trade payload")
        trade_time = _u64(value, "T", "handover trade payload")
        if value.get("e") != "trade" or value.get("s") != symbol:
            _fail("handover trade event identity is invalid")
        raw_price = value.get("p")
        raw_quantity = value.get("q")
        if not isinstance(raw_price, str) or not isinstance(raw_quantity, str):
            _fail("handover trade price/quantity must be decimal strings")
        try:
            price = FixedDecimal.parse(raw_price).canonical()
            quantity = FixedDecimal.parse(raw_quantity).canonical()
        except ValueError as exc:
            _fail(f"handover trade decimal is invalid: {exc}")
        if price.coefficient <= 0 or quantity.coefficient <= 0:
            _fail("handover trade price/quantity must be positive")
        if previous_trade_id is not None and trade_id <= previous_trade_id:
            _fail("handover trade IDs duplicated or regressed")
        material = {
            "best_match": _exact_bool(value, "M", "handover trade payload"),
            "buyer_is_maker": _exact_bool(value, "m", "handover trade payload"),
            "price": str(price),
            "quantity": str(quantity),
            "schema": "CanonicalTradeEventV1",
            "symbol": symbol,
            "trade_id": trade_id,
            "trade_time": trade_time,
        }
        observations.append(
            {
                "connection_epoch": seal["connection_epoch"],
                "stream": seal["stream"],
                "frame_index": first_frame + offset,
                "first_sequence": trade_id,
                "final_sequence": trade_id,
                "record_sha256": record.record_sha256,
                "observation_sha256": sha256(_compact_json(material)).hexdigest(),
            }
        )
        previous_trade_id = trade_id
    if not observations:
        _fail("handover trade window produced no market observation")
    return observations


def _derive_depth_evidence(
    predecessor_entry: dict[str, object],
    successor_entry: dict[str, object],
    predecessor: list[dict[str, object]],
    successor: list[dict[str, object]],
) -> dict[str, object]:
    predecessor_by_sequence = {
        int(item["final_sequence"]): item for item in predecessor
    }
    selected: tuple[
        dict[str, object], dict[str, object], dict[str, object]
    ] | None = None
    for boundary, continuation in zip(successor, successor[1:]):
        predecessor_boundary = predecessor_by_sequence.get(
            int(boundary["final_sequence"])
        )
        if predecessor_boundary is None:
            continue
        sequence = int(boundary["final_sequence"])
        if sequence == U64_MAX:
            _fail("depth handover boundary sequence overflow")
        next_sequence = sequence + 1
        if (
            predecessor_boundary["observation_sha256"]
            == boundary["observation_sha256"]
            and int(continuation["first_sequence"]) <= next_sequence
            and int(continuation["final_sequence"]) >= next_sequence
        ):
            selected = predecessor_boundary, boundary, continuation
    if selected is None:
        _fail("no exact depth convergence with documented successor continuation")
    predecessor_boundary, successor_boundary, continuation = selected
    return {
        "schema": "DepthOverlapEvidenceV1",
        "predecessor_segment": _entry_reference(predecessor_entry),
        "successor_segment": _entry_reference(successor_entry),
        "boundary_sequence": predecessor_boundary["final_sequence"],
        "boundary_state_sha256": predecessor_boundary["observation_sha256"],
        "predecessor_boundary": _observation_position(predecessor_boundary),
        "successor_boundary": _observation_position(successor_boundary),
        "successor_continuation": _observation_position(continuation),
        "successor_continuation_first_sequence": continuation["first_sequence"],
        "successor_continuation_final_sequence": continuation["final_sequence"],
    }


def _derive_trade_evidence(
    predecessor_entry: dict[str, object],
    successor_entry: dict[str, object],
    predecessor: list[dict[str, object]],
    successor: list[dict[str, object]],
) -> dict[str, object]:
    lower = max(
        int(predecessor[0]["final_sequence"]),
        int(successor[0]["final_sequence"]),
    )
    predecessor_last = int(predecessor[-1]["final_sequence"])
    successor_last = int(successor[-1]["final_sequence"])
    if successor_last < predecessor_last:
        _fail("successor durable trade prefix does not cover predecessor terminal trade")
    upper = min(predecessor_last, successor_last)
    common_predecessor = [
        item for item in predecessor if lower <= int(item["final_sequence"]) <= upper
    ]
    common_successor = [
        item for item in successor if lower <= int(item["final_sequence"]) <= upper
    ]
    if (
        len(common_predecessor) < 2
        or len(common_predecessor) != len(common_successor)
        or any(
            left["final_sequence"] != right["final_sequence"]
            or left["observation_sha256"] != right["observation_sha256"]
            for left, right in zip(common_predecessor, common_successor)
        )
    ):
        _fail("complete ordered trade lists differ across their common durable ID range")
    first_predecessor, next_predecessor = common_predecessor[-2:]
    first_successor, next_successor = common_successor[-2:]
    return {
        "schema": "TradeOverlapEvidenceV1",
        "predecessor_segment": _entry_reference(predecessor_entry),
        "successor_segment": _entry_reference(successor_entry),
        "common_lower_trade_id": lower,
        "common_upper_trade_id": upper,
        "common_events": len(common_predecessor),
        "first_shared_trade_id": first_successor["final_sequence"],
        "first_shared_event_sha256": first_successor["observation_sha256"],
        "predecessor_first_shared": _observation_position(first_predecessor),
        "successor_first_shared": _observation_position(first_successor),
        "next_shared_trade_id": next_successor["final_sequence"],
        "next_shared_event_sha256": next_successor["observation_sha256"],
        "predecessor_next_shared": _observation_position(next_predecessor),
        "successor_next_shared": _observation_position(next_successor),
        "trade_id_contiguity_claim": (
            "NONE_OFFICIAL_CONTRACT_DOES_NOT_PROMISE_CONSECUTIVE_IDS"
        ),
    }


def _recompute_handover_evidence(
    predecessor_root: Path,
    successor_root: Path,
    predecessor: dict[str, object],
    successor: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    symbol = _text(predecessor, "symbol", "handover predecessor")
    if (
        successor.get("symbol") != symbol
        or predecessor.get("generation_index") is None
        or successor.get("generation_index")
        != int(predecessor["generation_index"]) + 1
    ):
        _fail("terminal A/B generation identity/order mismatch")
    predecessor_depth = _evaluation_stream(predecessor, "depth", "predecessor")
    predecessor_trade = _evaluation_stream(predecessor, "trade", "predecessor")
    successor_depth = _evaluation_stream(successor, "depth", "successor")
    successor_trade = _evaluation_stream(successor, "trade", "successor")
    predecessor_depth_entries = _array(
        predecessor_depth.get("entries"), "predecessor depth entries"
    )
    predecessor_trade_entries = _array(
        predecessor_trade.get("entries"), "predecessor trade entries"
    )
    successor_depth_entries = _array(
        successor_depth.get("entries"), "successor depth entries"
    )
    successor_trade_entries = _array(
        successor_trade.get("entries"), "successor trade entries"
    )
    predecessor_depth_entry = _object(
        predecessor_depth_entries[-1], "predecessor terminal depth entry"
    )
    predecessor_trade_entry = _object(
        predecessor_trade_entries[-1], "predecessor terminal trade entry"
    )
    successor_depth_entry = _object(
        successor_depth_entries[0], "successor root depth entry"
    )
    successor_trade_entry = _object(
        successor_trade_entries[0], "successor root trade entry"
    )
    if (
        predecessor_depth.get("connection_epoch")
        == successor_depth.get("connection_epoch")
        or predecessor_trade.get("connection_epoch")
        == successor_trade.get("connection_epoch")
    ):
        _fail("terminal A/B handover reused a connection epoch")
    snapshot_sequence = _u64(
        successor, "snapshot_last_update_id", "handover successor"
    )
    snapshot_payload = _load_handover_snapshot(successor_root, successor)
    predecessor_depth_records = _capture_handover_segment(
        predecessor_root,
        predecessor,
        predecessor_depth_entry,
        "depth",
        snapshot_sequence,
    )
    successor_depth_records = _capture_handover_segment(
        successor_root,
        successor,
        successor_depth_entry,
        "depth",
        snapshot_sequence,
    )
    predecessor_trade_records = _capture_handover_segment(
        predecessor_root,
        predecessor,
        predecessor_trade_entry,
        "trade",
        0,
    )
    successor_trade_records = _capture_handover_segment(
        successor_root,
        successor,
        successor_trade_entry,
        "trade",
        0,
    )
    predecessor_depth_observations = _materialize_depth_window(
        snapshot_payload,
        predecessor_depth_records,
        predecessor_depth_entry,
        symbol,
    )
    successor_depth_observations = _materialize_depth_window(
        snapshot_payload,
        successor_depth_records,
        successor_depth_entry,
        symbol,
    )
    predecessor_trade_observations = _materialize_trade_window(
        predecessor_trade_records,
        predecessor_trade_entry,
        symbol,
    )
    successor_trade_observations = _materialize_trade_window(
        successor_trade_records,
        successor_trade_entry,
        symbol,
    )
    return (
        _derive_depth_evidence(
            predecessor_depth_entry,
            successor_depth_entry,
            predecessor_depth_observations,
            successor_depth_observations,
        ),
        _derive_trade_evidence(
            predecessor_trade_entry,
            successor_trade_entry,
            predecessor_trade_observations,
            successor_trade_observations,
        ),
    )


def _proof_digest(proof: dict[str, object]) -> str:
    material = {
        "schema": "RawGenerationHandoverProofDigestV1",
        "predecessor_session_id": proof["predecessor_session_id"],
        "successor_session_id": proof["successor_session_id"],
        "predecessor_generation_index": proof["predecessor_generation_index"],
        "successor_generation_index": proof["successor_generation_index"],
        "symbol": proof["symbol"],
        "predecessor_verification_sha256": proof["predecessor_verification_sha256"],
        "successor_startup_sha256": proof["successor_startup_sha256"],
        "successor_snapshot_record_sha256": proof["successor_snapshot_record_sha256"],
        "successor_snapshot_http_sha256": proof["successor_snapshot_http_sha256"],
        "depth": proof["depth"],
        "trade": proof["trade"],
    }
    return sha256(_compact_json(material)).hexdigest()


def _validate_handover(
    proof: dict[str, object],
    predecessor: dict[str, object],
    successor: dict[str, object],
    predecessor_root: Path,
    successor_root: Path,
    symbol: str,
    label: str,
) -> None:
    _keys(proof, _HANDOVER_KEYS, label)
    if (
        _text(proof, "schema", label) != "RawGenerationHandoverProofV1"
        or _text(proof, "status", label) != "PROVEN"
        or proof.get("predecessor_session_id") != predecessor["session_id"]
        or proof.get("successor_session_id") != successor["session_id"]
        or proof.get("predecessor_generation_index") != predecessor["generation_index"]
        or proof.get("successor_generation_index") != successor["generation_index"]
        or proof.get("symbol") != symbol
        or proof.get("credentials") != "NONE"
        or proof.get("order_entry") != "ABSENT"
        or proof.get("predecessor_verification_sha256")
        != predecessor["verification_sha256"]
        or proof.get("successor_startup_sha256") != successor["startup_sha256"]
        or proof.get("successor_snapshot_record_sha256")
        != successor["snapshot_record_sha256"]
        or proof.get("successor_snapshot_http_sha256")
        != successor["snapshot_http_sha256"]
    ):
        _fail(f"{label} identity/source binding is invalid")
    expected_digest = _proof_digest(proof)
    if _digest(proof.get("proof_sha256"), f"{label}.proof_sha256") != expected_digest:
        _fail(f"{label} autodigest mismatch")

    predecessor_streams = {
        str(item["name"]): item
        for item in _array(predecessor.get("streams"), "predecessor streams")
        if isinstance(item, dict)
    }
    successor_streams = {
        str(item["name"]): item
        for item in _array(successor.get("streams"), "successor streams")
        if isinstance(item, dict)
    }
    depth = _object(proof.get("depth"), f"{label}.depth")
    _keys(depth, _DEPTH_EVIDENCE_KEYS, f"{label}.depth")
    if depth.get("schema") != "DepthOverlapEvidenceV1":
        _fail(f"{label} depth schema is invalid")
    predecessor_depth_entries = _array(
        _object(predecessor_streams.get("depth"), "predecessor depth").get("entries"),
        "predecessor depth entries",
    )
    successor_depth_entries = _array(
        _object(successor_streams.get("depth"), "successor depth").get("entries"),
        "successor depth entries",
    )
    predecessor_depth_ref = _validate_reference(
        depth.get("predecessor_segment"),
        _object(predecessor_depth_entries[-1], "predecessor terminal depth entry"),
        f"{label}.depth.predecessor_segment",
    )
    successor_depth_ref = _validate_reference(
        depth.get("successor_segment"),
        _object(successor_depth_entries[0], "successor root depth entry"),
        f"{label}.depth.successor_segment",
    )
    _digest(depth.get("boundary_state_sha256"), f"{label}.depth boundary state")
    boundary = _u64(depth, "boundary_sequence", f"{label}.depth")
    first = _u64(depth, "successor_continuation_first_sequence", f"{label}.depth")
    final = _u64(depth, "successor_continuation_final_sequence", f"{label}.depth")
    if boundary == U64_MAX or first > boundary + 1 or final < boundary + 1:
        _fail(f"{label} depth continuation does not cover boundary + 1")
    _validate_position(
        depth.get("predecessor_boundary"), predecessor_depth_ref, f"{label}.predecessor_boundary"
    )
    _validate_position(
        depth.get("successor_boundary"), successor_depth_ref, f"{label}.successor_boundary"
    )
    _validate_position(
        depth.get("successor_continuation"),
        successor_depth_ref,
        f"{label}.successor_continuation",
    )

    trade = _object(proof.get("trade"), f"{label}.trade")
    _keys(trade, _TRADE_EVIDENCE_KEYS, f"{label}.trade")
    if (
        trade.get("schema") != "TradeOverlapEvidenceV1"
        or trade.get("trade_id_contiguity_claim")
        != "NONE_OFFICIAL_CONTRACT_DOES_NOT_PROMISE_CONSECUTIVE_IDS"
    ):
        _fail(f"{label} trade schema/continuity disclaimer is invalid")
    predecessor_trade_entries = _array(
        _object(predecessor_streams.get("trade"), "predecessor trade").get("entries"),
        "predecessor trade entries",
    )
    successor_trade_entries = _array(
        _object(successor_streams.get("trade"), "successor trade").get("entries"),
        "successor trade entries",
    )
    predecessor_trade_ref = _validate_reference(
        trade.get("predecessor_segment"),
        _object(predecessor_trade_entries[-1], "predecessor terminal trade entry"),
        f"{label}.trade.predecessor_segment",
    )
    successor_trade_ref = _validate_reference(
        trade.get("successor_segment"),
        _object(successor_trade_entries[0], "successor root trade entry"),
        f"{label}.trade.successor_segment",
    )
    lower = _u64(trade, "common_lower_trade_id", f"{label}.trade")
    upper = _u64(trade, "common_upper_trade_id", f"{label}.trade")
    events = _u64(trade, "common_events", f"{label}.trade")
    first_id = _u64(trade, "first_shared_trade_id", f"{label}.trade")
    next_id = _u64(trade, "next_shared_trade_id", f"{label}.trade")
    if events < 2 or not (lower <= first_id < next_id <= upper):
        _fail(f"{label} trade overlap range/order is invalid")
    _digest(trade.get("first_shared_event_sha256"), f"{label} first trade event")
    _digest(trade.get("next_shared_event_sha256"), f"{label} next trade event")
    for field, reference in (
        ("predecessor_first_shared", predecessor_trade_ref),
        ("successor_first_shared", successor_trade_ref),
        ("predecessor_next_shared", predecessor_trade_ref),
        ("successor_next_shared", successor_trade_ref),
    ):
        _validate_position(trade.get(field), reference, f"{label}.{field}")

    recomputed_depth, recomputed_trade = _recompute_handover_evidence(
        predecessor_root,
        successor_root,
        predecessor,
        successor,
    )
    if depth != recomputed_depth or trade != recomputed_trade:
        _fail(f"{label} differs from independent terminal raw A/B replay")


def _scan_journal(path: Path, generation_count: int) -> tuple[list[dict[str, object]], str, str]:
    records: list[dict[str, object]] = []
    previous = ZERO_DIGEST
    file_hash = sha256()
    last_mono: int | None = None
    try:
        with path.open("rb", buffering=0) as handle:
            before = os.fstat(handle.fileno())
            while True:
                line_with_newline = handle.readline(MAX_JOURNAL_RECORD_BYTES + 2)
                if not line_with_newline:
                    break
                file_hash.update(line_with_newline)
                if len(line_with_newline) > MAX_JOURNAL_RECORD_BYTES + 1:
                    _fail("campaign journal record exceeds limit")
                if not line_with_newline.endswith(b"\n"):
                    _fail("campaign journal has a partial terminal record")
                line = line_with_newline[:-1]
                envelope = _object(_parse_json(line, "campaign journal"), "journal envelope")
                _keys(envelope, _JOURNAL_ENVELOPE_KEYS, "journal envelope")
                body = _object(envelope.get("body"), "journal body")
                _keys(body, _JOURNAL_BODY_KEYS, "journal body")
                normalized_body = {
                    "schema": body["schema"],
                    "record_index": body["record_index"],
                    "wall_ns": body["wall_ns"],
                    "campaign_mono_ns": body["campaign_mono_ns"],
                    "generation_index": body["generation_index"],
                    "channel": body["channel"],
                    "payload": _rust_value(body["payload"]),
                    "previous_record_sha256": body["previous_record_sha256"],
                }
                body_bytes = _compact_json(normalized_body)
                digest = sha256(body_bytes).hexdigest()
                normalized_envelope = {"body": normalized_body, "record_sha256": digest}
                index = _u64(body, "record_index", "journal body")
                mono = _u64(body, "campaign_mono_ns", "journal body")
                generation_index = body.get("generation_index")
                if generation_index is not None and (
                    type(generation_index) is not int
                    or generation_index < 0
                    or generation_index >= generation_count
                ):
                    _fail("journal generation index is outside the campaign")
                if (
                    line != _compact_json(normalized_envelope)
                    or body.get("schema") != "RawCampaignJournalRecordV1"
                    or index != len(records)
                    or body.get("previous_record_sha256") != previous
                    or envelope.get("record_sha256") != digest
                    or last_mono is not None
                    and mono < last_mono
                ):
                    _fail("campaign journal encoding/hash-chain/order is invalid")
                _u64(body, "wall_ns", "journal body")
                _object(body.get("payload"), "journal payload")
                channel = _text(body, "channel", "journal body")
                if channel not in {"CAMPAIGN", "CHILD_STDOUT", "CHILD_STDERR", "SUPERVISOR"}:
                    _fail("journal channel is outside the campaign contract")
                if channel == "CHILD_STDERR":
                    _fail("successful campaign journal contains child stderr")
                records.append(body)
                previous = digest
                last_mono = mono
            after = os.fstat(handle.fileno())
            final_offset = handle.tell()
    except RawCampaignCorruption:
        raise
    except OSError as exc:
        _fail(f"cannot scan campaign journal: {exc}")
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or final_offset != after.st_size
        or not records
    ):
        _fail("campaign journal is empty, changed, or truncated")
    return records, previous, file_hash.hexdigest()


def _journal_events(
    records: list[dict[str, object]],
    startup_digest: str,
    manifest_digest: str,
    campaign_id: str,
    total_duration_s: int,
    generations: list[dict[str, object]],
    handovers: list[dict[str, object]],
) -> None:
    if len(records) < 3:
        _fail("campaign journal is too short for a terminal commit")
    first_payload = _object(records[0].get("payload"), "first journal payload")
    prepared_payload = _object(records[-2].get("payload"), "precommit journal payload")
    last_payload = _object(records[-1].get("payload"), "last journal payload")
    if (
        records[0].get("channel") != "CAMPAIGN"
        or records[0].get("generation_index") is not None
        or first_payload
        != {
            "campaign_id": campaign_id,
            "event": "CAMPAIGN_STARTED",
            "startup_sha256": startup_digest,
        }
        or records[-2].get("channel") != "CAMPAIGN"
        or records[-2].get("generation_index") is not None
        or prepared_payload != {"event": "CAMPAIGN_EVALUATION_PREPARED"}
        or records[-1].get("channel") != "CAMPAIGN"
        or records[-1].get("generation_index") is not None
        or last_payload
        != {
            "event": "CAMPAIGN_COMMITTED",
            "manifest_file": "campaign.json",
            "manifest_sha256": manifest_digest,
        }
    ):
        _fail("campaign journal does not have exact STARTED/PREPARED/COMMITTED terminals")

    states: dict[int, dict[str, int | None]] = {
        index: {
            "launch": None,
            "launch_mono": None,
            "process_started": None,
            "process_started_mono": None,
            "process_terminal": None,
            "process_terminal_mono": None,
            "generation_exited": None,
            "generation_exited_mono": None,
        }
        for index in range(len(generations))
    }
    expected_epochs: dict[tuple[int, str], str] = {}
    expected_shutdowns: dict[tuple[int, str], int] = {}
    expected_shutdown_identities: set[tuple[int, tuple[object, ...]]] = set()
    expected_shutdown_identity_counts: dict[tuple[int, str], int] = {}
    identity_tokens: set[str] = set()
    for index, generation in enumerate(generations):
        session_id = _text(generation, "session_id", f"generation {index}")
        if session_id in identity_tokens:
            _fail("campaign generation/session epoch identity was reused")
        identity_tokens.add(session_id)
        stream_names: set[str] = set()
        for stream_value in _array(
            generation.get("streams"), f"generation {index} streams"
        ):
            stream = _object(stream_value, f"generation {index} stream")
            name = _text(stream, "name", f"generation {index} stream")
            epoch = _text(
                stream, "connection_epoch", f"generation {index} {name} stream"
            )
            if (
                name not in {"depth", "trade"}
                or name in stream_names
                or epoch in identity_tokens
            ):
                _fail("campaign generation/session epoch identity was reused")
            stream_names.add(name)
            identity_tokens.add(epoch)
            expected_epochs[(index, name)] = epoch
            expected_shutdowns[(index, name)] = _u64(
                stream,
                "server_shutdown_events",
                f"generation {index} {name} stream",
            )
        if stream_names != {"depth", "trade"}:
            _fail("campaign generation/session epoch identity was reused")
        for shutdown_value in _array(
            generation.get("_raw_server_shutdowns", []),
            f"generation {index} raw serverShutdown identities",
        ):
            shutdown = _object(
                shutdown_value,
                f"generation {index} raw serverShutdown identity",
            )
            identity = _server_shutdown_identity(
                shutdown,
                f"generation {index} raw serverShutdown identity",
            )
            stream = str(identity[0])
            epoch = str(identity[1])
            if expected_epochs.get((index, stream)) != epoch:
                _fail(
                    f"generation {index} raw serverShutdown epoch is not authoritative"
                )
            scoped = (index, identity)
            if scoped in expected_shutdown_identities:
                _fail(f"generation {index} duplicates a raw serverShutdown identity")
            expected_shutdown_identities.add(scoped)
            stream_key = (index, stream)
            expected_shutdown_identity_counts[stream_key] = (
                expected_shutdown_identity_counts.get(stream_key, 0) + 1
            )
    for stream_key, expected in expected_shutdowns.items():
        if expected_shutdown_identity_counts.get(stream_key, 0) != expected:
            _fail("raw serverShutdown identities/count differ")
    observed_shutdowns: dict[tuple[int, str], int] = {}
    available_shutdowns: dict[tuple[int, str], int] = {}
    observed_shutdown_identities: set[tuple[int, tuple[object, ...]]] = set()
    proof_started: set[tuple[int, int]] = set()
    promoted: dict[tuple[int, int], str] = {}
    campaign_started = 0
    prepared_count = 0
    committed_count = 0
    prepared_boundary: tuple[int, int] | None = None
    initial_active_registered = False
    candidate_registered: set[int] = set()
    active_generation: int | None = None
    pending_candidate: int | None = None
    # A planned connection may be warmed one generation ahead, but it has no
    # publication authority until CANDIDATE_REGISTERED transfers it into the
    # supervisor's single pending-candidate slot.
    warmed_generation: int | None = None
    for body in records:
        payload = _object(body.get("payload"), "journal payload")
        event = payload.get("event")
        if not isinstance(event, str):
            _fail("campaign journal payload lacks a string event")
        record_index = _u64(body, "record_index", "journal body")
        campaign_mono_ns = _u64(body, "campaign_mono_ns", "journal body")
        channel = _text(body, "channel", "journal body")
        generation = body.get("generation_index")
        if generation is not None and (
            type(generation) is not int
            or generation < 0
            or generation >= len(generations)
        ):
            _fail("campaign journal generation index is outside the campaign")
        if event not in _JOURNAL_EVENT_ALLOWLISTS.get(channel, set()):
            _fail(
                f"campaign journal event {event} is unknown or invalid for channel {channel}"
            )
        if channel == "CHILD_STDOUT" and payload.get("schema") != (
            _CHILD_EVENT_SCHEMAS[event]
        ):
            _fail(f"{event} uses the wrong child event schema")
        if channel == "CHILD_STDOUT":
            if type(generation) is not int:
                _fail(f"{event} is not generation-scoped")
            state = states[generation]
            if (
                payload.get("session_id") != generations[generation]["session_id"]
                or event != "PROCESS_STARTED"
                and (
                    state["process_started"] is None
                    or int(state["process_started"]) >= record_index
                    or state["process_terminal"] is not None
                )
            ):
                _fail(f"{event} child session/lifecycle is invalid")
        if event == "CAMPAIGN_FAILED":
            _fail("successful campaign journal contains CAMPAIGN_FAILED")
        if event == "GENERATION_DISCONNECT_FAIL_CLOSED":
            _fail("successful campaign journal contains a fail-closed disconnect")
        if event == "CAMPAIGN_STARTED":
            campaign_started += 1
            if (
                channel != "CAMPAIGN"
                or generation is not None
                or payload
                != {
                    "campaign_id": campaign_id,
                    "event": "CAMPAIGN_STARTED",
                    "startup_sha256": startup_digest,
                }
            ):
                _fail("CAMPAIGN_STARTED identity/scope is invalid")
        elif event == "CAMPAIGN_EVALUATION_PREPARED":
            prepared_count += 1
            if (
                channel != "CAMPAIGN"
                or generation is not None
                or payload != {"event": "CAMPAIGN_EVALUATION_PREPARED"}
            ):
                _fail("CAMPAIGN_EVALUATION_PREPARED scope is invalid")
            prepared_boundary = (record_index, campaign_mono_ns)
        elif event == "CAMPAIGN_COMMITTED":
            committed_count += 1
            if (
                channel != "CAMPAIGN"
                or generation is not None
                or payload
                != {
                    "event": "CAMPAIGN_COMMITTED",
                    "manifest_file": "campaign.json",
                    "manifest_sha256": manifest_digest,
                }
            ):
                _fail("CAMPAIGN_COMMITTED identity/scope is invalid")
        elif event == "SERVER_SHUTDOWN_DURABLE":
            if type(generation) is not int:
                _fail("SERVER_SHUTDOWN_DURABLE is unscoped")
            generation_report = generations[generation]
            shutdown = _object(
                payload.get("shutdown"), "SERVER_SHUTDOWN_DURABLE shutdown"
            )
            identity = _server_shutdown_identity(
                shutdown,
                "SERVER_SHUTDOWN_DURABLE shutdown",
                event_payload=True,
            )
            stream = str(identity[0])
            epoch = str(identity[1])
            if (
                channel != "CHILD_STDOUT"
                or set(payload) != {"event", "schema", "session_id", "shutdown"}
                or payload.get("session_id") != generation_report["session_id"]
                or expected_epochs.get((generation, stream)) != epoch
            ):
                _fail("SERVER_SHUTDOWN_DURABLE identity is invalid")
            process_started = states[generation]["process_started"]
            if (
                process_started is None
                or process_started >= record_index
                or states[generation]["process_terminal"] is not None
                or states[generation]["generation_exited"] is not None
            ):
                _fail(
                    "SERVER_SHUTDOWN_DURABLE is outside the active child lifecycle"
                )
            scoped_identity = (generation, identity)
            if (
                scoped_identity not in expected_shutdown_identities
                or scoped_identity in observed_shutdown_identities
            ):
                _fail(
                    "SERVER_SHUTDOWN_DURABLE does not bind one exact BNRAW record"
                )
            observed_shutdown_identities.add(scoped_identity)
            stream_key = (generation, stream)
            observed = observed_shutdowns.get(stream_key, 0)
            if observed == U64_MAX:
                _fail("serverShutdown journal count overflow")
            observed_shutdowns[stream_key] = observed + 1
            epoch_key = (generation, epoch)
            available = available_shutdowns.get(epoch_key, 0)
            if available == U64_MAX:
                _fail("available serverShutdown count overflow")
            available_shutdowns[epoch_key] = available + 1
        elif event in {
            "GENERATION_LAUNCHED",
            "GENERATION_LAUNCHED_SERVER_SHUTDOWN",
        }:
            if type(generation) is not int:
                _fail("unscoped generation launch")
            expected_duration = _u64(
                generations[generation],
                "duration_requested_s",
                f"generation {generation}",
            )
            immediate_candidate = (
                generation != 0
                and active_generation == generation - 1
                and pending_candidate is None
                and warmed_generation is None
            )
            warm_ahead = (
                event == "GENERATION_LAUNCHED"
                and generation >= 2
                and active_generation == generation - 2
                and pending_candidate == generation - 1
                and warmed_generation is None
            )
            if (
                channel != "CAMPAIGN"
                or states[generation]["launch"] is not None
                or _u64(payload, "duration_s", "generation launch")
                != expected_duration
                or generation == 0
                and (
                    event != "GENERATION_LAUNCHED"
                    or active_generation is not None
                    or pending_candidate is not None
                    or warmed_generation is not None
                )
                or generation > 0
                and not immediate_candidate
                and not warm_ahead
            ):
                _fail("duplicate or unscoped generation launch")
            if event == "GENERATION_LAUNCHED" and payload != {
                "event": "GENERATION_LAUNCHED",
                "duration_s": expected_duration,
            }:
                _fail(f"generation {generation} launch is invalid")
            if event == "GENERATION_LAUNCHED_SERVER_SHUTDOWN":
                source_generation = _u64(
                    payload,
                    "source_generation",
                    "GENERATION_LAUNCHED_SERVER_SHUTDOWN",
                )
                source_epoch = payload.get("source_epoch")
                if (
                    generation == 0
                    or source_generation + 1 != generation
                    or not isinstance(source_epoch, str)
                    or not source_epoch
                    or payload
                    != {
                        "event": "GENERATION_LAUNCHED_SERVER_SHUTDOWN",
                        "duration_s": expected_duration,
                        "source_generation": source_generation,
                        "source_epoch": source_epoch,
                    }
                ):
                    _fail("serverShutdown generation launch source is invalid")
                source_state = states[source_generation]
                if (
                    source_state["process_terminal"] is not None
                    or source_state["generation_exited"] is not None
                ):
                    _fail("serverShutdown launch source is no longer active")
                if active_generation != source_generation:
                    _fail("serverShutdown launch source is not the active generation")
                source_epochs = {
                    epoch
                    for (generation_index, _), epoch in expected_epochs.items()
                    if generation_index == source_generation
                }
                if source_epoch not in source_epochs:
                    _fail("serverShutdown launch source epoch is not authoritative")
                source_key = (source_generation, source_epoch)
                available = available_shutdowns.get(source_key, 0)
                if available == 0:
                    _fail("serverShutdown launch lacks a prior unused durable event")
                available_shutdowns[source_key] = available - 1
            states[generation]["launch"] = record_index
            states[generation]["launch_mono"] = campaign_mono_ns
            if generation != 0:
                if warm_ahead:
                    warmed_generation = generation
                else:
                    pending_candidate = generation
        elif event == "PROCESS_STARTED":
            if type(generation) is not int:
                _fail("unscoped PROCESS_STARTED")
            state = states[generation]
            launch = state["launch"]
            if (
                channel != "CHILD_STDOUT"
                or state["process_started"] is not None
                or launch is None
                or launch >= record_index
                or payload.get("schema") != "CaptureProcessEventV1"
                or payload.get("generation_index") != generation
                or payload.get("session_id") != generations[generation]["session_id"]
                or payload.get("symbol") != generations[generation]["symbol"]
                or payload.get("spec_revision") != SPEC_REVISION
                or payload.get("startup_manifest_sha256")
                != generations[generation]["startup_sha256"]
                or _u64(payload, "process_id", "PROCESS_STARTED") == 0
            ):
                _fail("duplicate or unscoped PROCESS_STARTED")
            session_dir = _text(payload, "session_dir", "PROCESS_STARTED")
            _check_session_path(
                session_dir,
                campaign_id,
                str(generations[generation]["session_id"]),
                "journal session_dir",
            )
            state["process_started"] = record_index
            state["process_started_mono"] = campaign_mono_ns
            if generation == 0 and campaign_mono_ns > 30_000_000_000:
                _fail("first generation PROCESS_STARTED exceeds 30s startup grace")
            if generation > 0 and states[generation - 1]["process_started"] is None:
                _fail("successor PROCESS_STARTED precedes predecessor startup")
        elif event == "PROCESS_TERMINAL":
            if type(generation) is not int:
                _fail("unscoped PROCESS_TERMINAL")
            state = states[generation]
            started_record = state["process_started"]
            required_pair = (generation - 1, generation)
            successor_started = (
                states[generation + 1]["process_started"]
                if generation + 1 < len(generations)
                else None
            )
            successor_started_mono = (
                states[generation + 1]["process_started_mono"]
                if generation + 1 < len(generations)
                else None
            )
            if (
                channel != "CHILD_STDOUT"
                or state["process_terminal"] is not None
                or started_record is None
                or started_record >= record_index
                or payload.get("schema") != "CaptureTerminalProcessEventV1"
                or payload.get("session_id") != generations[generation]["session_id"]
                or payload.get("status") != "COMPLETE"
                or payload.get("generation_manifest") != "generation.json"
                or generation > 0
                and required_pair not in promoted
                or generation + 1 < len(generations)
                and (
                    successor_started is None
                    or successor_started >= record_index
                    or successor_started_mono is None
                    or successor_started_mono > campaign_mono_ns
                )
            ):
                _fail("invalid PROCESS_TERMINAL")
            state["process_terminal"] = record_index
            state["process_terminal_mono"] = campaign_mono_ns
        elif event == "GENERATION_EXITED":
            if type(generation) is not int:
                _fail("unscoped GENERATION_EXITED")
            state = states[generation]
            terminal_record = state["process_terminal"]
            if (
                channel != "CAMPAIGN"
                or state["generation_exited"] is not None
                or terminal_record is None
                or terminal_record >= record_index
                or payload.get("success") is not True
                or payload.get("code") != 0
            ):
                _fail("invalid GENERATION_EXITED")
            state["generation_exited"] = record_index
            state["generation_exited_mono"] = campaign_mono_ns
        elif event == "HANDOVER_PROOF_STARTED":
            if type(generation) is not int:
                _fail("invalid HANDOVER_PROOF_STARTED")
            predecessor = _u64(payload, "predecessor", "HANDOVER_PROOF_STARTED")
            pair = (predecessor, generation)
            if (
                channel != "CAMPAIGN"
                or predecessor + 1 != generation
                or payload
                != {
                    "event": "HANDOVER_PROOF_STARTED",
                    "predecessor": predecessor,
                }
                or pair not in {
                    (index, index + 1) for index in range(len(generations) - 1)
                }
                or pair in proof_started
                or active_generation != predecessor
                or pending_candidate != generation
                or generation not in candidate_registered
                or states[predecessor]["generation_exited"] is None
                or states[predecessor]["generation_exited"] >= record_index
                or states[generation]["process_started"] is None
                or states[generation]["process_started"] >= record_index
            ):
                _fail("duplicate HANDOVER_PROOF_STARTED")
            proof_started.add(pair)
        elif event == "HANDOVER_PROVEN_AND_PROMOTED":
            if type(generation) is not int:
                _fail("invalid HANDOVER_PROVEN_AND_PROMOTED")
            predecessor = _u64(
                payload, "predecessor", "HANDOVER_PROVEN_AND_PROMOTED"
            )
            pair = (predecessor, generation)
            proof_digest = _digest(
                payload.get("proof_sha256"), "journal proof_sha256"
            )
            expected_proof = next(
                (
                    item["proof_sha256"]
                    for item in handovers
                    if item["predecessor_generation_index"] == predecessor
                    and item["successor_generation_index"] == generation
                ),
                None,
            )
            if (
                channel != "SUPERVISOR"
                or predecessor + 1 != generation
                or payload
                != {
                    "event": "HANDOVER_PROVEN_AND_PROMOTED",
                    "predecessor": predecessor,
                    "proof_sha256": proof_digest,
                }
                or pair not in proof_started
                or generation not in candidate_registered
                or active_generation != predecessor
                or pending_candidate != generation
                or pair in promoted
                or expected_proof != proof_digest
                or states[generation]["process_terminal"] is not None
            ):
                _fail("duplicate HANDOVER_PROVEN_AND_PROMOTED")
            promoted[pair] = proof_digest
            active_generation = generation
            pending_candidate = None
        elif event == "INITIAL_ACTIVE_REGISTERED":
            if (
                type(generation) is not int
                or generation != 0
                or initial_active_registered
                or states[0]["process_started"] is None
                or int(states[0]["process_started"]) >= record_index
                or payload != {"event": "INITIAL_ACTIVE_REGISTERED"}
            ):
                _fail("INITIAL_ACTIVE_REGISTERED lifecycle is invalid")
            initial_active_registered = True
            active_generation = 0
        elif event == "CANDIDATE_REGISTERED":
            if (
                type(generation) is int
                and warmed_generation == generation
                and pending_candidate is None
                and active_generation == generation - 1
            ):
                warmed_generation = None
                pending_candidate = generation
            if (
                type(generation) is not int
                or generation == 0
                or states[generation]["process_started"] is None
                or int(states[generation]["process_started"]) >= record_index
                or active_generation != generation - 1
                or pending_candidate != generation
                or generation in candidate_registered
                or payload != {"event": "CANDIDATE_REGISTERED"}
            ):
                _fail("CANDIDATE_REGISTERED lifecycle is invalid")
            candidate_registered.add(generation)
        elif event in {
            "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE",
            "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING",
        }:
            if type(generation) is not int:
                _fail(f"{event} is not generation-scoped")
            source_epoch = _text(payload, "source_epoch", event)
            source_epochs = {
                epoch
                for (generation_index, _), epoch in expected_epochs.items()
                if generation_index == generation
            }
            if (
                source_epoch not in source_epochs
                or payload
                != {
                    "event": event,
                    "source_epoch": source_epoch,
                }
                or event == "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE"
                and active_generation == generation
                or event == "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING"
                and (
                    active_generation != generation
                    or pending_candidate is None
                )
            ):
                _fail(f"{event} source/lifecycle is invalid")
            source_key = (generation, source_epoch)
            available = available_shutdowns.get(source_key, 0)
            if available == 0:
                _fail(f"{event} lacks a prior unused durable source event")
            available_shutdowns[source_key] = available - 1
        elif event in {
            "TRANSPORT_CONNECTED",
            "SNAPSHOT_DURABLE",
            "SEGMENT_DURABLE",
            "HEARTBEAT_DURABLE",
        }:
            pass

    indices = set(range(len(generations)))
    if any(
        any(value is None for value in states[index].values()) for index in indices
    ):
        _fail("journal omits a generation lifecycle boundary")
    if campaign_started != 1 or prepared_count != 1 or committed_count != 1:
        _fail("journal contains duplicate or omitted campaign commit boundaries")
    if (
        not initial_active_registered
        or active_generation != len(generations) - 1
        or pending_candidate is not None
        or warmed_generation is not None
    ):
        _fail("campaign active-generation lifecycle is incomplete")
    if any(available != 0 for available in available_shutdowns.values()):
        _fail("durable serverShutdown event lacks one terminal disposition")
    if observed_shutdown_identities != expected_shutdown_identities:
        _fail("journal/raw serverShutdown identities differ")
    for stream_key, expected in expected_shutdowns.items():
        if observed_shutdowns.get(stream_key, 0) != expected:
            _fail("journal/raw serverShutdown count differs")

    if total_duration_s > U64_MAX // 1_000_000_000:
        _fail("campaign duration nanoseconds overflow")
    required_end_ns = total_duration_s * 1_000_000_000
    first_state = states[0]
    first_start = first_state["process_started_mono"]
    assert first_start is not None
    if first_start > 30_000_000_000:
        _fail("first generation PROCESS_STARTED exceeds startup grace")
    for successor_index in range(1, len(generations)):
        predecessor_state = states[successor_index - 1]
        successor_state = states[successor_index]
        successor_start = successor_state["process_started_mono"]
        predecessor_terminal = predecessor_state["process_terminal_mono"]
        predecessor_exit = predecessor_state["generation_exited_mono"]
        assert successor_start is not None
        assert predecessor_terminal is not None
        assert predecessor_exit is not None
        if (
            successor_start >= predecessor_terminal
            or successor_start >= predecessor_exit
        ):
            _fail(
                f"generation {successor_index} did not start before its "
                "predecessor terminated"
            )

    first_duration = _u64(
        generations[0], "duration_requested_s", "generation 0 coverage"
    )
    if first_duration > U64_MAX // 1_000_000_000:
        _fail("generation 0 coverage interval overflow")
    first_duration_ns = first_duration * 1_000_000_000
    if first_start > U64_MAX - first_duration_ns:
        _fail("generation 0 coverage interval overflow")
    covered_through_ns = first_start + first_duration_ns
    previous_start_ns = first_start
    for index in range(1, len(generations)):
        started_ns = states[index]["process_started_mono"]
        assert started_ns is not None
        if started_ns <= previous_start_ns or started_ns > covered_through_ns:
            _fail(
                f"generation {index} declared coverage leaves a campaign gap "
                "or regresses"
            )
        duration_s = _u64(
            generations[index],
            "duration_requested_s",
            f"generation {index} coverage",
        )
        if duration_s > U64_MAX // 1_000_000_000:
            _fail(f"generation {index} coverage interval overflow")
        duration_ns = duration_s * 1_000_000_000
        if started_ns > U64_MAX - duration_ns:
            _fail(f"generation {index} coverage interval overflow")
        covered_through_ns = max(covered_through_ns, started_ns + duration_ns)
        previous_start_ns = started_ns
    if covered_through_ns < required_end_ns:
        _fail("declared generation windows do not cover the requested campaign")

    final_state = states[len(generations) - 1]
    if (
        final_state["process_terminal_mono"] is None
        or final_state["process_terminal_mono"] < required_end_ns
        or final_state["generation_exited_mono"] is None
        or final_state["generation_exited_mono"] < required_end_ns
    ):
        _fail("generation lifecycle does not cover the campaign terminal deadline")
    assert prepared_boundary is not None
    prepared_record, prepared_mono_ns = prepared_boundary
    final_terminal_record = final_state["process_terminal"]
    final_exit_record = final_state["generation_exited"]
    final_terminal_mono = final_state["process_terminal_mono"]
    final_exit_mono = final_state["generation_exited_mono"]
    assert final_terminal_record is not None
    assert final_exit_record is not None
    assert final_terminal_mono is not None
    assert final_exit_mono is not None
    if (
        prepared_record <= final_terminal_record
        or prepared_record <= final_exit_record
        or prepared_mono_ns < final_terminal_mono
        or prepared_mono_ns < final_exit_mono
    ):
        _fail("campaign prepared boundary predates the last generation end")
    expected_pairs = {(index, index + 1) for index in range(len(generations) - 1)}
    if proof_started != expected_pairs or set(promoted) != expected_pairs:
        _fail("journal handover lifecycle is incomplete or reordered")
    for handover in handovers:
        pair = (
            int(handover["predecessor_generation_index"]),
            int(handover["successor_generation_index"]),
        )
        if promoted.get(pair) != handover["proof_sha256"]:
            _fail("journal promotion digest differs from handover proof")


def _verify_raw_campaign(root: Path) -> dict[str, object]:
    if not root.is_dir() or _is_linklike(root):
        _fail("campaign directory is missing, not a directory, or link-like")
    manifest, manifest_bytes = _load_pretty(
        root / "campaign.json", _CAMPAIGN_KEYS_V1, "campaign manifest"
    )
    if manifest.get("schema") != "RawCampaignManifestV1" or manifest.get("status") != "COMPLETE":
        _fail("campaign is not a completed RawCampaignManifestV1")
    campaign_id = _safe_component(manifest.get("campaign_id"), "campaign_id")
    if root.name != campaign_id:
        _fail("campaign directory name differs from campaign_id")
    symbol = _text(manifest, "symbol", "campaign manifest")
    if symbol not in {"BTCUSDT", "ETHUSDT"}:
        _fail("campaign symbol is outside fixed scope")
    total = _u64(manifest, "total_duration_s", "campaign manifest")
    rotation = _u64(manifest, "rotation_s", "campaign manifest")
    overlap = _u64(manifest, "overlap_s", "campaign manifest")
    segment = _u64(manifest, "segment_s", "campaign manifest")
    if (
        total == 0
        or rotation == 0
        or overlap == 0
        or segment == 0
        or overlap != segment
        or rotation % segment != 0
        or rotation + overlap > 86_300
        or total < overlap
    ):
        _fail("campaign duration/rotation/overlap contract is invalid")
    started = _u64(manifest, "started_wall_ns", "campaign manifest")
    finished = _u64(manifest, "finished_wall_ns", "campaign manifest")
    if started == 0 or finished < started:
        _fail("campaign wall-clock bounds are invalid")
    if (
        manifest.get("spec_revision") != SPEC_REVISION
        or manifest.get("credentials") != "NONE"
        or manifest.get("order_entry") != "ABSENT"
        or manifest.get("supervisor_gap_count") != 0
    ):
        _fail("campaign spec/security/gap terminal contract is invalid")
    executable_sha = _digest(manifest.get("executable_sha256"), "campaign executable_sha256")
    capture_sha = _digest(
        manifest.get("capture_executable_sha256"), "campaign capture_executable_sha256"
    )
    config_sha = _digest(manifest.get("public_config_sha256"), "campaign public_config_sha256")

    startup, startup_bytes = _load_pretty(
        root / "campaign-startup.json", _STARTUP_KEYS, "campaign startup"
    )
    startup_digest = sha256(startup_bytes).hexdigest()
    if (
        startup.get("schema") != "RawCampaignStartupV1"
        or startup.get("campaign_id") != campaign_id
        or startup.get("symbol") != symbol
        or startup.get("total_duration_s") != total
        or startup.get("rotation_s") != rotation
        or startup.get("overlap_s") != overlap
        or startup.get("segment_s") != segment
        or startup.get("started_wall_ns") != started
        or startup.get("executable_sha256") != executable_sha
        or startup.get("capture_executable_sha256") != capture_sha
        or startup.get("public_config_sha256") != config_sha
        or startup.get("spec_revision") != SPEC_REVISION
        or startup.get("credentials") != "NONE"
        or startup.get("order_entry") != "ABSENT"
        or _u64(startup, "process_id", "campaign startup") == 0
        or manifest.get("startup_file") != "campaign-startup.json"
        or manifest.get("startup_sha256") != startup_digest
    ):
        _fail("campaign startup differs from the terminal campaign lock")

    generation_rows = _array(manifest.get("generations"), "campaign generations")
    if not generation_rows:
        _fail("campaign contains no generation")
    generation_names: set[str] = set()
    generations: list[dict[str, object]] = []
    seen_epochs: set[str] = set()
    for index, row_value in enumerate(generation_rows):
        row = _object(row_value, f"campaign generation[{index}]")
        _keys(row, _CAMPAIGN_GENERATION_KEYS, f"campaign generation[{index}]")
        if _u64(row, "generation_index", f"campaign generation[{index}]") != index:
            _fail("campaign generation indices are reordered or discontinuous")
        session_id = _safe_component(row.get("session_id"), f"generation[{index}].session_id")
        if session_id in generation_names:
            _fail("campaign reuses a generation session_id")
        generation_names.add(session_id)
        session_dir = _text(row, "session_dir", f"campaign generation[{index}]")
        expected_session_dir = f"generations/{session_id}"
        if session_dir != expected_session_dir:
            _fail("campaign session_dir is not the exact portable generation path")
        generation_root = root / "generations" / session_id
        try:
            oracle = verify_segmented_generation(generation_root)
        except SegmentChainCorruption as exc:
            _fail(f"generation {index} raw verification failed: {exc}")
        generation, _ = _load_pretty(
            generation_root / "generation.json",
            _GENERATION_MANIFEST_KEYS,
            f"generation {index} manifest",
        )
        if (
            oracle.get("generation_index") != index
            or oracle.get("session_id") != session_id
            or oracle.get("symbol") != symbol
            or oracle.get("collector_executable_sha256") != capture_sha
            or oracle.get("public_config_sha256") != config_sha
            or generation.get("segment_duration_s") != segment
            or generation.get("credentials") != "NONE"
            or generation.get("order_entry") != "ABSENT"
        ):
            _fail(f"generation {index} identity/source lock differs from campaign")
        duration = _u64(generation, "duration_requested_s", f"generation {index}")
        if duration == 0 or duration > rotation + overlap:
            _fail(f"generation {index} requested duration exceeds campaign policy")
        evaluation_relative = f"evaluations/generation-{index:03}-rust.json"
        if row.get("evaluation_file") != evaluation_relative:
            _fail(f"generation {index} evaluation path is not canonical")
        evaluation_path = _safe_file(root, evaluation_relative, "generation evaluation")
        evaluation, evaluation_bytes = _load_pretty(
            evaluation_path, _EVALUATION_KEYS, f"generation {index} evaluation"
        )
        _validate_evaluation_shape(evaluation, f"generation {index} evaluation")
        expected_evaluation = _expected_evaluation(
            generation_root, oracle, generation, session_dir
        )
        if evaluation != expected_evaluation:
            _fail(f"generation {index} evaluation differs from independently verified raw bytes")
        if (
            row.get("verification_sha256") != evaluation["verification_sha256"]
            or row.get("evaluation_file_sha256") != sha256(evaluation_bytes).hexdigest()
            or row.get("generation_manifest_sha256")
            != evaluation["generation_manifest_sha256"]
        ):
            _fail(f"generation {index} campaign/evaluation digest mismatch")
        streams = _array(evaluation.get("streams"), f"generation {index} streams")
        by_name = {
            str(item["name"]): item for item in streams if isinstance(item, dict)
        }
        if (
            row.get("depth_records") != _object(by_name.get("depth"), "depth stream").get("records")
            or row.get("trade_records")
            != _object(by_name.get("trade"), "trade stream").get("records")
        ):
            _fail(f"generation {index} campaign record count mismatch")
        for stream in streams:
            stream_object = _object(stream, "evaluated stream")
            epoch = _text(stream_object, "connection_epoch", "evaluated stream")
            if epoch in seen_epochs:
                _fail("campaign reuses a WebSocket connection epoch")
            seen_epochs.add(epoch)
        startup_report = _object(oracle.get("startup"), "generation startup report")
        snapshot_report = _object(oracle.get("snapshot"), "generation snapshot report")
        raw_server_shutdowns: list[dict[str, object]] = []
        raw_server_shutdown_keys: set[tuple[object, ...]] = set()
        for oracle_stream_value in _array(
            oracle.get("streams"), f"generation {index} oracle streams"
        ):
            oracle_stream = _object(
                oracle_stream_value, f"generation {index} oracle stream"
            )
            for shutdown_value in _array(
                oracle_stream.get("server_shutdowns"),
                f"generation {index} oracle serverShutdown identities",
            ):
                shutdown = _object(
                    shutdown_value,
                    f"generation {index} oracle serverShutdown identity",
                )
                identity = _server_shutdown_identity(
                    shutdown,
                    f"generation {index} oracle serverShutdown identity",
                )
                if identity in raw_server_shutdown_keys:
                    _fail(
                        f"generation {index} oracle duplicates a serverShutdown identity"
                    )
                raw_server_shutdown_keys.add(identity)
                raw_server_shutdowns.append(dict(shutdown))
        generations.append(
            {
                **evaluation,
                "startup_sha256": startup_report["file_sha256"],
                "snapshot_http_sha256": snapshot_report["http_metadata_file_sha256"],
                "evaluation_file": evaluation_relative,
                "evaluation_file_sha256": sha256(evaluation_bytes).hexdigest(),
                "raw_oracle_verification_sha256": oracle["verification_sha256"],
                "_raw_server_shutdowns": raw_server_shutdowns,
            }
        )

    handover_rows = _array(manifest.get("handovers"), "campaign handovers")
    if len(handover_rows) != len(generations) - 1:
        _fail("campaign must contain exactly N-1 handover proofs")
    handovers: list[dict[str, object]] = []
    for index, row_value in enumerate(handover_rows):
        row = _object(row_value, f"campaign handover[{index}]")
        _keys(row, _CAMPAIGN_HANDOVER_KEYS, f"campaign handover[{index}]")
        successor = index + 1
        expected_path = f"handovers/handover-{index:03}-to-{successor:03}/handover.json"
        if (
            row.get("predecessor_generation_index") != index
            or row.get("successor_generation_index") != successor
            or row.get("proof_file") != expected_path
        ):
            _fail("campaign handover list is omitted, reordered, or has a noncanonical path")
        proof_path = _safe_file(root, expected_path, "handover proof")
        proof, proof_bytes = _load_pretty(proof_path, _HANDOVER_KEYS, f"handover {index}->{successor}")
        _validate_handover(
            proof,
            generations[index],
            generations[successor],
            root / "generations" / str(generations[index]["session_id"]),
            root / "generations" / str(generations[successor]["session_id"]),
            symbol,
            f"handover {index}->{successor}",
        )
        if row.get("proof_sha256") != proof.get("proof_sha256"):
            _fail("campaign handover digest differs from proof autodigest")
        if row.get("proof_file_sha256") != sha256(proof_bytes).hexdigest():
            _fail("campaign handover file digest differs from exact proof bytes")
        handovers.append(
            {
                "predecessor_generation_index": index,
                "successor_generation_index": successor,
                "proof_file": expected_path,
                "proof_file_sha256": sha256(proof_bytes).hexdigest(),
                "proof_sha256": proof["proof_sha256"],
            }
        )

    journal_file = manifest.get("journal_file")
    if journal_file != "campaign-events.jsonl":
        _fail("campaign journal path is not canonical")
    journal_path = _safe_file(root, "campaign-events.jsonl", "campaign journal")
    journal_records, journal_terminal, journal_file_sha = _scan_journal(
        journal_path, len(generations)
    )
    precommit_records = _u64(
        manifest, "journal_precommit_records", "campaign manifest"
    )
    precommit_sha = _digest(
        manifest.get("journal_precommit_sha256"), "campaign journal precommit digest"
    )
    if (
        manifest.get("journal_boundary") != "PRECOMMIT_PREFIX"
        or precommit_records + 1 != len(journal_records)
        or journal_records[-1].get("previous_record_sha256") != precommit_sha
        or int(journal_records[-2]["campaign_mono_ns"]) < total * 1_000_000_000
    ):
        _fail("campaign precommit journal boundary/duration differs from the exact prefix")
    manifest_digest = sha256(manifest_bytes).hexdigest()
    _journal_events(
        journal_records,
        startup_digest,
        manifest_digest,
        campaign_id,
        total,
        generations,
        handovers,
    )

    root_inventory = _exact_entries(
        root,
        {
            "campaign-events.jsonl",
            "campaign-startup.json",
            "campaign.json",
            "control",
            "evaluations",
            "generations",
            "handovers",
        },
        "campaign directory",
    )
    _exact_entries(root / "control", set(), "campaign control directory")
    _exact_entries(
        root / "evaluations",
        {f"generation-{index:03}-rust.json" for index in range(len(generations))},
        "campaign evaluations directory",
    )
    _exact_entries(root / "generations", generation_names, "campaign generations directory")
    handover_directories = {
        f"handover-{index:03}-to-{index + 1:03}" for index in range(len(generations) - 1)
    }
    _exact_entries(root / "handovers", handover_directories, "campaign handovers directory")
    for directory in handover_directories:
        _exact_entries(root / "handovers" / directory, {"handover.json"}, directory)

    report_generations = [
        {
            "generation_index": item["generation_index"],
            "session_id": item["session_id"],
            "duration_requested_s": item["duration_requested_s"],
            "verification_sha256": item["verification_sha256"],
            "raw_oracle_verification_sha256": item["raw_oracle_verification_sha256"],
            "generation_manifest_sha256": item["generation_manifest_sha256"],
            "evaluation_file": item["evaluation_file"],
            "evaluation_file_sha256": item["evaluation_file_sha256"],
        }
        for item in generations
    ]
    report: dict[str, object] = {
        "schema": "RawCampaignVerificationV1",
        "status": "VERIFIED",
        "campaign_id": campaign_id,
        "symbol": symbol,
        "total_duration_s": total,
        "rotation_s": rotation,
        "overlap_s": overlap,
        "segment_s": segment,
        "campaign_manifest_file_sha256": sha256(manifest_bytes).hexdigest(),
        "campaign_startup_file_sha256": startup_digest,
        "capture_executable_sha256": capture_sha,
        "public_config_sha256": config_sha,
        "journal": {
            "file": "campaign-events.jsonl",
            "records": len(journal_records),
            "terminal_record_sha256": journal_terminal,
            "file_sha256": journal_file_sha,
            "boundary": "PRECOMMIT_PREFIX",
            "precommit_records": precommit_records,
            "precommit_record_sha256": precommit_sha,
        },
        "generations": report_generations,
        "handovers": handovers,
        "supervisor_gap_count": 0,
        "credentials": "NONE",
        "order_entry": "ABSENT",
        "inventory": root_inventory,
    }
    report["verification_sha256"] = sha256(_compact_json(report)).hexdigest()
    return report


def verify_raw_campaign(campaign_directory: Path) -> dict[str, object]:
    """Verify one completed raw campaign, or raise fail-closed."""

    try:
        return _verify_raw_campaign(Path(campaign_directory))
    except RawCampaignCorruption:
        raise
    except (OSError, TypeError, ValueError, OverflowError) as exc:
        raise RawCampaignCorruption(f"raw campaign verification failed: {exc}") from exc
