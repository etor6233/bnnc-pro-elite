from __future__ import annotations

from base64 import b64encode
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from binance_lob.cli import main
from binance_lob.segment_chain import (
    MANIFEST_MAGIC,
    RAW_MAGIC,
    SegmentChainCorruption,
    ZERO_DIGEST,
    _RawExpectations,
    _RawRecordInfo,
    _SequenceState,
    _scan_raw_segment,
    _validate_application_payload,
    _validate_raw_market_freshness,
    _validate_telemetry,
    verify_segmented_generation,
)


LENGTH = struct.Struct(">I")
SPEC_REVISION = "976cc580553890e92031b77306147c0ed1de5a46"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _encoded_record(body: bytes) -> tuple[bytes, str]:
    digest = sha256(body).digest()
    return LENGTH.pack(len(body)) + body + digest, digest.hex()


def _raw_body(
    *,
    symbol: str,
    endpoint: str,
    stream: str,
    epoch: str,
    frame_index: int,
    payload: bytes,
    previous: str,
    receive_mono_ns: int | None = None,
) -> dict[str, object]:
    return {
        "schema": "RawFrameV1",
        "venue": "binance-spot",
        "environment": "production-public-market-data",
        "endpoint": endpoint,
        "stream": stream,
        "symbol": symbol,
        "connection_epoch": epoch,
        "frame_index": frame_index,
        "receive_wall_ns": 1_700_000_000_000_000_000 + frame_index,
        "receive_mono_ns": (
            1_000_000 + frame_index
            if receive_mono_ns is None
            else receive_mono_ns
        ),
        "clock_quality": "SYNCHRONIZED",
        "clock_source": "test-clock",
        "clock_offset_ns": None,
        "clock_uncertainty_ns": None,
        "payload_length": len(payload),
        "payload_sha256": sha256(payload).hexdigest(),
        "payload_base64": b64encode(payload).decode("ascii"),
        "recorder_state": "PENDING",
        "spec_revision": SPEC_REVISION,
        "previous_record_sha256": previous,
    }


def _write_raw(
    path: Path,
    *,
    symbol: str,
    endpoint: str,
    stream: str,
    epoch: str,
    first_frame: int,
    previous: str,
    payloads: list[bytes],
    frame_delta: int = 0,
    receive_mono_start_ns: int | None = None,
) -> tuple[str, int]:
    encoded = bytearray(RAW_MAGIC)
    digest = previous
    for offset, payload in enumerate(payloads):
        body = _canonical(
            _raw_body(
                symbol=symbol,
                endpoint=endpoint,
                stream=stream,
                epoch=epoch,
                frame_index=first_frame + offset + frame_delta,
                payload=payload,
                previous=digest,
                receive_mono_ns=(
                    None
                    if receive_mono_start_ns is None
                    else receive_mono_start_ns + offset
                ),
            )
        )
        record, digest = _encoded_record(body)
        encoded.extend(record)
    path.write_bytes(bytes(encoded))
    return digest, len(encoded)


def _seal(
    *,
    index: int,
    raw_file: str,
    epoch: str,
    stream: str,
    first_frame: int,
    records: int,
    offset: int,
    previous: str,
    terminal: str,
) -> dict[str, object]:
    return {
        "schema": "RawSegmentSealV1",
        "segment_index": index,
        "raw_file": raw_file,
        "connection_epoch": epoch,
        "stream": stream,
        "first_frame_index": first_frame,
        "last_frame_index": first_frame + records - 1,
        "records": records,
        "durable_through_offset": offset,
        "previous_segment_terminal_sha256": previous,
        "terminal_record_sha256": terminal,
    }


def _write_manifest(path: Path, seals: list[dict[str, object]]) -> str:
    encoded = bytearray(MANIFEST_MAGIC)
    previous = ZERO_DIGEST
    for record_index, seal in enumerate(seals):
        body = _canonical(
            {
                "schema": "RawSegmentManifestRecordV1",
                "record_index": record_index,
                "previous_manifest_record_sha256": previous,
                "seal": seal,
            }
        )
        record, previous = _encoded_record(body)
        encoded.extend(record)
    path.write_bytes(bytes(encoded))
    return previous


def _stream_uri(symbol: str, name: str) -> tuple[str, str]:
    stream = f"{symbol.lower()}@depth@100ms" if name == "depth" else f"{symbol.lower()}@trade"
    return stream, f"wss://data-stream.binance.vision:443/ws/{stream}?timeUnit=MICROSECOND"


def _write_progress(path: Path, raw_file: str, seal: dict[str, object]) -> None:
    ack = {
        "schema": "DurabilityAckV1",
        "durable_record_count": seal["records"],
        "durable_through_offset": seal["durable_through_offset"],
        "last_record_sha256": seal["terminal_record_sha256"],
        "streams": [
            {
                "connection_epoch": seal["connection_epoch"],
                "stream": seal["stream"],
                "durable_through_frame_index": seal["last_frame_index"],
            }
        ],
    }
    body = {
        "schema": "RawDurabilityProgressV1",
        "record_index": 0,
        "raw_path": raw_file,
        "ack": ack,
        "previous_record_sha256": ZERO_DIGEST,
    }
    envelope = {"body": body, "record_sha256": sha256(_canonical(body)).hexdigest()}
    path.write_bytes(_canonical(envelope) + b"\n")


def _write_transport_journal(
    path: Path,
    *,
    stream: str,
    epoch: str,
    uri: str,
    received: int,
) -> dict[str, object]:
    previous = ZERO_DIGEST
    encoded = bytearray()
    events = [
        ("CONNECT_ATTEMPT", {"uri": uri}),
        (
            "DNS_OBSERVED",
            {
                "addresses": ["127.0.0.1:443"],
                "host": "data-stream.binance.vision",
                "port": 443,
                "role": "DIAGNOSTIC_OBSERVATION_NOT_CONNECT_SELECTION",
            },
        ),
        (
            "WEBSOCKET_CONNECTED",
            {
                "local_endpoint": "127.0.0.1:40000",
                "remote_endpoint": "127.0.0.1:443",
                "tcp_info": {"status": "UNSUPPORTED_PLATFORM"},
                "websocket_http_status": 101,
            },
        ),
        (
            "CLIENT_STOP_OBSERVED",
            {"tcp_info": {"status": "UNSUPPORTED_PLATFORM"}},
        ),
        (
            "TRANSPORT_TERMINAL",
            {"error": None, "received": received, "status": "STOPPED"},
        ),
    ]
    for index, (event, payload) in enumerate(events):
        body = {
            "schema": "TransportJournalRecordV1",
            "record_index": index,
            "wall_ns": 1_700_000_000_000_000_000 + index,
            "mono_ns": index,
            "stream": stream,
            "connection_epoch": epoch,
            "event": event,
            "payload": payload,
            "previous_record_sha256": previous,
        }
        previous = sha256(_canonical(body)).hexdigest()
        encoded.extend(_canonical({"body": body, "record_sha256": previous}) + b"\n")
    data = bytes(encoded)
    path.write_bytes(data)
    return {
        "schema": "TransportJournalSealV1",
        "file": path.name,
        "records": len(events),
        "terminal_record_sha256": previous,
        "file_bytes": len(data),
        "file_sha256": sha256(data).hexdigest(),
    }


def _telemetry_record(
    index: int,
    *,
    terminal: bool,
    duration_s: int = 1,
    terminal_segment: int = 1,
    last_market_mono_ns: int = 1_000_000_000,
) -> dict[str, object]:
    count = 2 if terminal else 0
    segment = terminal_segment if terminal else 0
    mono = duration_s * 1_000_000_000 if terminal else 0
    last_market = last_market_mono_ns if terminal else 0
    max_queue = 1 if terminal else 0
    max_age = 100 if terminal else 0
    last_sync = 500 if terminal else 0
    max_sync = 1_000 if terminal else 0
    return {
        "schema": "CaptureTelemetryV1",
        "record_index": index,
        "wall_ns": 1_700_000_000_000_000_000 + index,
        "mono_ns": mono,
        "clock": {
            "quality": "UNKNOWN",
            "source": "test-clock",
            "leap_indicator": None,
            "stratum": None,
            "last_successful_sync": None,
        },
        "depth_received": count,
        "depth_written": count,
        "depth_durable": count,
        "depth_segment": segment,
        "depth_last_socket_activity_mono_ns": last_market,
        "depth_last_market_message_mono_ns": last_market,
        "depth_last_durable_mono_ns": mono,
        "depth_queue_records": 0,
        "depth_queue_bytes": 0,
        "depth_max_queue_records": max_queue,
        "depth_max_queue_bytes": max_queue * 100,
        "depth_max_queue_age_ns": max_age,
        "depth_last_sync_duration_ns": last_sync,
        "depth_max_sync_duration_ns": max_sync,
        "trade_received": count,
        "trade_written": count,
        "trade_durable": count,
        "trade_segment": segment,
        "trade_last_socket_activity_mono_ns": last_market,
        "trade_last_market_message_mono_ns": last_market,
        "trade_last_durable_mono_ns": mono,
        "trade_queue_records": 0,
        "trade_queue_bytes": 0,
        "trade_max_queue_records": max_queue,
        "trade_max_queue_bytes": max_queue * 100,
        "trade_max_queue_age_ns": max_age,
        "trade_last_sync_duration_ns": last_sync,
        "trade_max_sync_duration_ns": max_sync,
    }


def _build_generation(
    root: Path,
    *,
    trade_ids: tuple[int, int] = (10, 12),
    generation_index: int = 0,
    duration_s: int = 1,
    started_wall_ns: int = 1_700_000_000_000_000_000,
    epoch_suffix: str = "",
    single_overlap_segment: bool = False,
    server_shutdown_stream: str | None = None,
) -> dict[str, object]:
    symbol = "BTCUSDT"
    session_id = root.name
    duration = duration_s
    segment_duration = 1
    startup: dict[str, object] = {
        "schema": "RawGenerationStartupV1",
        "implementation": "rust-segmented",
        "session_id": session_id,
        "generation_index": generation_index,
        "symbol": symbol,
        "duration_requested_s": duration,
        "segment_duration_s": segment_duration,
        "started_wall_ns": started_wall_ns,
        "collector_executable_sha256": "a" * 64,
        "public_config_sha256": "b" * 64,
        "market_freshness_startup_grace_s": 30,
        "market_freshness_deadline_s": 30,
        "credentials": "NONE",
        "order_entry": "ABSENT",
        "raw_boundary": (
            "WebSocket application messages after TLS/framing and before JSON interpretation"
        ),
        "spec_revision": SPEC_REVISION,
    }
    startup_bytes = json.dumps(startup, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    (root / "startup.json").write_bytes(startup_bytes)

    snapshot_endpoint = (
        "https://data-api.binance.vision/api/v3/depth?symbol=BTCUSDT&limit=5000"
    )
    snapshot_payload = _canonical(
        {"lastUpdateId": 100, "bids": [["1", "2"]], "asks": [["3", "4"]]}
    )
    snapshot_epoch = f"snapshot-epoch{epoch_suffix}"
    snapshot_stream = "btcusdt@rest-depth-snapshot"
    snapshot_digest, snapshot_offset = _write_raw(
        root / "snapshot.bnraw",
        symbol=symbol,
        endpoint=snapshot_endpoint,
        stream=snapshot_stream,
        epoch=snapshot_epoch,
        first_frame=0,
        previous=ZERO_DIGEST,
        payloads=[snapshot_payload],
    )
    snapshot_ack = {
        "schema": "DurabilityAckV1",
        "durable_record_count": 1,
        "durable_through_offset": snapshot_offset,
        "last_record_sha256": snapshot_digest,
        "streams": [
            {
                "connection_epoch": snapshot_epoch,
                "stream": snapshot_stream,
                "durable_through_frame_index": 0,
            }
        ],
    }
    snapshot_http = {
        "schema": "SnapshotHttpMetadataV1",
        "endpoint": snapshot_endpoint,
        "http_status": 200,
        "headers": {"content-type": ["application/json"]},
        "receive_wall_ns": 1_700_000_000_000_000_000,
        "receive_mono_ns": 1_000_000,
        "body_complete": True,
        "body_length": len(snapshot_payload),
        "body_sha256": sha256(snapshot_payload).hexdigest(),
        "raw_file": "snapshot.bnraw",
        "raw_record_sha256": snapshot_digest,
    }
    snapshot_http_bytes = _canonical(snapshot_http)
    (root / "snapshot-http.json").write_bytes(snapshot_http_bytes)

    streams: list[dict[str, object]] = []
    segment_count = 1 if single_overlap_segment else 2
    terminal_segment = segment_count - 1
    terminal_market_mono_ns = (
        1_000_001 if single_overlap_segment else 1_000_000_000
    )
    if server_shutdown_stream not in {None, "depth", "trade"}:
        raise ValueError("server_shutdown_stream must be depth, trade, or None")
    for name in ("depth", "trade"):
        directory = root / name
        directory.mkdir()
        stream, uri = _stream_uri(symbol, name)
        epoch = f"{name}-epoch{epoch_suffix}"
        transport_file = f"transport-{name}.json"
        transport_metadata = {
            "schema": "TransportMetadataV1",
            "session_id": session_id,
            "generation_index": generation_index,
            "symbol": symbol,
            "spec_revision": SPEC_REVISION,
            "connection": {
                "stream": name,
                "connection_epoch": epoch,
                "uri": uri,
                "websocket_http_status": 101,
                "local_endpoint": f"192.0.2.1:{10_000 + generation_index}",
                "remote_endpoint": "198.51.100.1:443",
                "response_headers": {
                    "connection": ["upgrade"],
                    "upgrade": ["websocket"],
                },
            },
        }
        transport_bytes = (
            json.dumps(transport_metadata, ensure_ascii=False, indent=2).encode("utf-8")
            + b"\n"
        )
        (root / transport_file).write_bytes(transport_bytes)
        seals: list[dict[str, object]] = []
        previous = ZERO_DIGEST
        frame_index = 0
        event_index = 0
        for index in range(segment_count):
            raw_file = f"segment-{index:06}.bnraw"
            payloads: list[bytes] = []
            events_in_segment = 2 if single_overlap_segment else 1
            for _ in range(events_in_segment):
                if name == "depth":
                    event_payload = _canonical(
                        {
                            "e": "depthUpdate",
                            "E": 1_000 + event_index,
                            "s": symbol,
                            "U": 101 + event_index,
                            "u": 101 + event_index,
                            "b": [["1", "2"]],
                            "a": [["3", "4"]],
                        }
                    )
                else:
                    event_payload = _canonical(
                        {
                            "e": "trade",
                            "E": 2_000 + event_index,
                            "s": symbol,
                            "t": trade_ids[event_index],
                            "p": "1",
                            "q": "2",
                            "T": 3_000 + event_index,
                            "m": False,
                            "M": True,
                        }
                    )
                payloads.append(event_payload)
                event_index += 1
            if name == server_shutdown_stream and index == 0:
                payloads.append(
                    _canonical({"e": "serverShutdown", "E": 9_000 + event_index})
                )
            terminal, raw_offset = _write_raw(
                directory / raw_file,
                symbol=symbol,
                endpoint=uri,
                stream=stream,
                epoch=epoch,
                first_frame=frame_index,
                previous=previous,
                payloads=payloads,
                receive_mono_start_ns=(
                    1_000_000 if index == 0 else index * 1_000_000_000
                ),
            )
            seal = _seal(
                index=index,
                raw_file=raw_file,
                epoch=epoch,
                stream=stream,
                first_frame=frame_index,
                records=len(payloads),
                offset=raw_offset,
                previous=previous,
                terminal=terminal,
            )
            seals.append(seal)
            _write_progress(directory / f"segment-{index:06}.bnack", raw_file, seal)
            previous = terminal
            frame_index += len(payloads)
        manifest_digest = _write_manifest(directory / "segments.bnseg", seals)
        stream_records = 2 + int(name == server_shutdown_stream)
        terminal_socket_mono_ns = terminal_market_mono_ns + int(
            name == server_shutdown_stream and single_overlap_segment
        )
        transport_journal = _write_transport_journal(
            root / f"transport-{name}-events.jsonl",
            stream=name,
            epoch=epoch,
            uri=uri,
            received=stream_records,
        )
        streams.append(
            {
                "name": name,
                "uri": uri,
                "connection_epoch": epoch,
                "transport_metadata_file": transport_file,
                "transport_metadata_sha256": sha256(transport_bytes).hexdigest(),
                "transport_journal": transport_journal,
                "received": stream_records,
                "written": stream_records,
                "durable_records": stream_records,
                "segments": segment_count,
                "last_socket_activity_mono_ns": terminal_socket_mono_ns,
                "last_market_message_mono_ns": terminal_market_mono_ns,
                "server_shutdown_events": int(name == server_shutdown_stream),
                "segment_manifest": f"{name}/segments.bnseg",
                "segment_manifest_sha256": manifest_digest,
                "terminal_raw_sha256": previous,
                "error": None,
            }
        )

    telemetry_records = [
        _telemetry_record(
            index,
            terminal=index == 1,
            duration_s=duration,
            terminal_segment=terminal_segment,
            last_market_mono_ns=terminal_market_mono_ns,
        )
        for index in range(2)
    ]
    if server_shutdown_stream is not None:
        terminal_telemetry = telemetry_records[-1]
        for suffix in ("received", "written", "durable"):
            terminal_telemetry[f"{server_shutdown_stream}_{suffix}"] = 3
        terminal_telemetry[f"{server_shutdown_stream}_last_socket_activity_mono_ns"] = (
            terminal_market_mono_ns
            + int(single_overlap_segment)
        )
    telemetry_bytes = b"".join(
        _canonical(record) + b"\n" for record in telemetry_records
    )
    (root / "telemetry.jsonl").write_bytes(telemetry_bytes)
    generation: dict[str, object] = {
        "schema": "RawGenerationManifestV1",
        "implementation": "rust-segmented",
        "session_id": session_id,
        "generation_index": generation_index,
        "status": "COMPLETE",
        "symbol": symbol,
        "duration_requested_s": duration,
        "segment_duration_s": segment_duration,
        "started_wall_ns": started_wall_ns,
        "finished_wall_ns": started_wall_ns + duration * 1_000_000_000,
        "collector_executable_sha256": "a" * 64,
        "public_config_sha256": "b" * 64,
        "market_freshness_startup_grace_s": 30,
        "market_freshness_deadline_s": 30,
        "credentials": "NONE",
        "order_entry": "ABSENT",
        "raw_boundary": (
            "WebSocket application messages after TLS/framing and before JSON interpretation"
        ),
        "spec_revision": SPEC_REVISION,
        "startup_file": "startup.json",
        "startup_sha256": sha256(startup_bytes).hexdigest(),
        "failure": None,
        "snapshot": {
            "endpoint": snapshot_endpoint,
            "http_status": 200,
            "last_update_id": 100,
            "bid_levels": 1,
            "ask_levels": 1,
            "raw_file": "snapshot.bnraw",
            "durability_ack": snapshot_ack,
            "http_metadata_file": "snapshot-http.json",
            "http_metadata_sha256": sha256(snapshot_http_bytes).hexdigest(),
        },
        "telemetry": {
            "schema": "TelemetryArtifactV1",
            "file": "telemetry.jsonl",
            "records": 2,
            "durable_through_offset": len(telemetry_bytes),
            "terminal_record_sha256": sha256(
                _canonical(telemetry_records[-1]) + b"\n"
            ).hexdigest(),
            "terminal_mono_ns": duration * 1_000_000_000,
            "file_sha256": sha256(telemetry_bytes).hexdigest(),
        },
        "streams": streams,
    }
    _write_generation(root, generation)
    return generation


def _write_generation(root: Path, generation: dict[str, object]) -> None:
    (root / "generation.json").write_text(
        json.dumps(generation, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _rewrite_progress(path: Path, mutation: object) -> None:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(envelope, dict)
    body = envelope["body"]
    assert isinstance(body, dict)
    mutation(body)  # type: ignore[operator]
    envelope["record_sha256"] = sha256(_canonical(body)).hexdigest()
    path.write_bytes(_canonical(envelope) + b"\n")


def _rewrite_telemetry(
    root: Path,
    generation: dict[str, object],
    records: list[dict[str, object]],
    *,
    terminal_newline: bool = True,
) -> None:
    body = b"\n".join(_canonical(record) for record in records)
    if terminal_newline:
        body += b"\n"
    (root / "telemetry.jsonl").write_bytes(body)
    telemetry = generation["telemetry"]
    assert isinstance(telemetry, dict)
    telemetry["records"] = len(records)
    telemetry["durable_through_offset"] = len(body)
    telemetry["terminal_record_sha256"] = sha256(
        _canonical(records[-1]) + b"\n"
    ).hexdigest()
    telemetry["terminal_mono_ns"] = records[-1]["mono_ns"]
    telemetry["file_sha256"] = sha256(body).hexdigest()
    _write_generation(root, generation)


class SegmentChainVerificationTests(unittest.TestCase):
    @staticmethod
    def _trade_record(receive_mono_ns: int, trade_id: int) -> _RawRecordInfo:
        return _RawRecordInfo(
            payload=_canonical(
                {
                    "e": "trade",
                    "E": trade_id,
                    "s": "BTCUSDT",
                    "t": trade_id,
                    "p": "1",
                    "q": "2",
                    "T": trade_id,
                    "m": False,
                    "M": True,
                }
            ),
            record_sha256=f"{trade_id:064x}",
            receive_wall_ns=receive_mono_ns + 1,
            receive_mono_ns=receive_mono_ns,
        )

    def test_raw_market_freshness_rejects_hidden_gap_then_recovery(self) -> None:
        sequence = _SequenceState(freshness_active_end_ns=60_000_000_000)
        _validate_application_payload(
            self._trade_record(1, 1), "trade", "BTCUSDT", 0, sequence
        )
        with self.assertRaisesRegex(SegmentChainCorruption, "gap exceeds 30s"):
            _validate_application_payload(
                self._trade_record(30_000_000_002, 2),
                "trade",
                "BTCUSDT",
                0,
                sequence,
            )

    def test_raw_market_freshness_rejects_start_and_tail_violations(self) -> None:
        late_start = _SequenceState(freshness_active_end_ns=60_000_000_000)
        _validate_application_payload(
            self._trade_record(30_000_000_001, 1),
            "trade",
            "BTCUSDT",
            0,
            late_start,
        )
        with self.assertRaisesRegex(SegmentChainCorruption, "startup grace"):
            _validate_raw_market_freshness(late_start, "trade", 60_000_000_000)

        stale_tail = _SequenceState(freshness_active_end_ns=60_000_000_000)
        _validate_application_payload(
            self._trade_record(1, 1), "trade", "BTCUSDT", 0, stale_tail
        )
        with self.assertRaisesRegex(SegmentChainCorruption, "tail exceeds 30s"):
            _validate_raw_market_freshness(stale_tail, "trade", 60_000_000_000)

    def test_post_deadline_market_message_does_not_create_false_gap(self) -> None:
        active_end = 10_000_000_000
        sequence = _SequenceState(freshness_active_end_ns=active_end)
        _validate_application_payload(
            self._trade_record(1, 1), "trade", "BTCUSDT", 0, sequence
        )
        _validate_application_payload(
            self._trade_record(50_000_000_000, 2),
            "trade",
            "BTCUSDT",
            0,
            sequence,
        )
        _validate_raw_market_freshness(sequence, "trade", active_end)
        self.assertEqual(sequence.last_market_mono_ns, 50_000_000_000)

    def test_raw_record_must_belong_to_its_declared_monotonic_segment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            symbol = "BTCUSDT"
            stream, uri = _stream_uri(symbol, "depth")
            epoch = "depth-epoch"
            payload = _canonical(
                {
                    "e": "depthUpdate",
                    "E": 1_000,
                    "s": symbol,
                    "U": 101,
                    "u": 101,
                    "b": [["1", "2"]],
                    "a": [["3", "4"]],
                }
            )
            raw_path = root / "segment-000001.bnraw"
            _write_raw(
                raw_path,
                symbol=symbol,
                endpoint=uri,
                stream=stream,
                epoch=epoch,
                first_frame=0,
                previous=ZERO_DIGEST,
                payloads=[payload],
                receive_mono_start_ns=999_999_999,
            )
            expected = _RawExpectations(
                connection_epoch=epoch,
                stream=stream,
                first_frame_index=0,
                initial_previous_sha256=ZERO_DIGEST,
                symbol=symbol,
                endpoint=uri,
                spec_revision=SPEC_REVISION,
            )
            with self.assertRaisesRegex(
                SegmentChainCorruption,
                "outside its declared monotonic segment",
            ):
                _scan_raw_segment(
                    raw_path,
                    expected,
                    stream_kind="depth",
                    snapshot_sequence=100,
                    sequence=_SequenceState(),
                    segment_index=1,
                    segment_duration_ns=1_000_000_000,
                )

    def test_control_activity_cannot_mask_stale_market_streams(self) -> None:
        def verify_middle(market_mono_ns: int) -> dict[str, object]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                initial = _telemetry_record(0, terminal=False, duration_s=60)
                middle = _telemetry_record(1, terminal=False, duration_s=60)
                middle["wall_ns"] = 1_700_000_000_040_000_000
                middle["mono_ns"] = 40_000_000_000
                terminal = _telemetry_record(2, terminal=True, duration_s=60)
                for record, socket_mono in (
                    (middle, 40_000_000_000),
                    (terminal, 60_000_000_000),
                ):
                    for name in ("depth", "trade"):
                        record[f"{name}_last_socket_activity_mono_ns"] = socket_mono
                        record[f"{name}_last_market_message_mono_ns"] = market_mono_ns
                records = [initial, middle, terminal]
                body = b"".join(_canonical(record) + b"\n" for record in records)
                (root / "telemetry.jsonl").write_bytes(body)
                manifest = {
                    "schema": "TelemetryArtifactV1",
                    "file": "telemetry.jsonl",
                    "records": len(records),
                    "durable_through_offset": len(body),
                    "terminal_record_sha256": sha256(
                        _canonical(terminal) + b"\n"
                    ).hexdigest(),
                    "terminal_mono_ns": terminal["mono_ns"],
                    "file_sha256": sha256(body).hexdigest(),
                }
                streams = [
                    {
                        "name": name,
                        "records": 2,
                        "segments": 2,
                        "last_socket_activity_mono_ns": 60_000_000_000,
                        "last_market_message_mono_ns": market_mono_ns,
                    }
                    for name in ("depth", "trade")
                ]
                return _validate_telemetry(root, manifest, streams, 60)

        with self.assertRaisesRegex(SegmentChainCorruption, "stale market data"):
            verify_middle(1_000_000_000)
        self.assertEqual(verify_middle(39_000_000_000)["records"], 3)

    def test_server_shutdown_is_control_only_and_terminally_counted(self) -> None:
        sequence = _SequenceState()
        trade = _RawRecordInfo(
            payload=_canonical(
                {
                    "e": "trade",
                    "E": 1,
                    "s": "BTCUSDT",
                    "t": 10,
                    "p": "1",
                    "q": "2",
                    "T": 1,
                    "m": False,
                    "M": True,
                }
            ),
            record_sha256="a" * 64,
            receive_wall_ns=1,
            receive_mono_ns=100,
        )
        shutdown = _RawRecordInfo(
            payload=_canonical({"e": "serverShutdown", "E": 2}),
            record_sha256="b" * 64,
            receive_wall_ns=2,
            receive_mono_ns=200,
        )
        _validate_application_payload(trade, "trade", "BTCUSDT", 0, sequence)
        _validate_application_payload(shutdown, "trade", "BTCUSDT", 0, sequence)
        self.assertEqual(sequence.final, 10)
        self.assertEqual(sequence.last_market_mono_ns, 100)
        self.assertEqual(sequence.server_shutdown_events, 1)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root, server_shutdown_stream="trade")
            report = verify_segmented_generation(root)
            trade_report = next(
                stream
                for stream in report["streams"]
                if stream["name"] == "trade"
            )
            shutdowns = trade_report["server_shutdowns"]
            self.assertEqual(len(shutdowns), 1)
            shutdown_identity = shutdowns[0]
            first_segment = trade_report["sealed_segments"][0]
            self.assertEqual(
                shutdown_identity,
                {
                    "stream": "trade",
                    "connection_epoch": trade_report["connection_epoch"],
                    "segment_index": 0,
                    "raw_file": "segment-000000.bnraw",
                    "frame_index": 1,
                    "receive_mono_ns": 1_000_001,
                    "durable_record_count": 2,
                    "durable_through_offset": first_segment[
                        "durable_through_offset"
                    ],
                    "last_record_sha256": first_segment[
                        "terminal_record_sha256"
                    ],
                },
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            stream = generation["streams"][0]
            assert isinstance(stream, dict)
            stream["server_shutdown_events"] = 1
            _write_generation(root, generation)
            with self.assertRaisesRegex(SegmentChainCorruption, "durable count"):
                verify_segmented_generation(root)

    def test_server_shutdown_requires_its_exact_intermediate_bnack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            symbol = "BTCUSDT"
            stream, uri = _stream_uri(symbol, "trade")
            epoch = "trade-epoch"

            def trade(trade_id: int) -> bytes:
                return _canonical(
                    {
                        "e": "trade",
                        "E": trade_id,
                        "s": symbol,
                        "t": trade_id,
                        "p": "1",
                        "q": "2",
                        "T": trade_id,
                        "m": False,
                        "M": True,
                    }
                )

            raw_path = root / "segment-000000.bnraw"
            terminal, raw_offset = _write_raw(
                raw_path,
                symbol=symbol,
                endpoint=uri,
                stream=stream,
                epoch=epoch,
                first_frame=0,
                previous=ZERO_DIGEST,
                payloads=[
                    trade(10),
                    _canonical({"e": "serverShutdown", "E": 11}),
                    trade(12),
                ],
                receive_mono_start_ns=1_000_000,
            )
            terminal_only_ack = {
                "schema": "DurabilityAckV1",
                "durable_record_count": 3,
                "durable_through_offset": raw_offset,
                "last_record_sha256": terminal,
                "streams": [
                    {
                        "connection_epoch": epoch,
                        "stream": stream,
                        "durable_through_frame_index": 2,
                    }
                ],
            }
            with self.assertRaisesRegex(
                SegmentChainCorruption,
                "exact durable BNACK checkpoint",
            ):
                _scan_raw_segment(
                    raw_path,
                    _RawExpectations(
                        connection_epoch=epoch,
                        stream=stream,
                        first_frame_index=0,
                        initial_previous_sha256=ZERO_DIGEST,
                        symbol=symbol,
                        endpoint=uri,
                        spec_revision=SPEC_REVISION,
                    ),
                    acknowledgements=(terminal_only_ack,),
                    stream_kind="trade",
                    sequence=_SequenceState(),
                    segment_index=0,
                    segment_duration_ns=1_000_000_000,
                    require_server_shutdown_ack=True,
                )

    def test_valid_generation_is_deterministic_and_raw_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            first = verify_segmented_generation(root)
            second = verify_segmented_generation(root)
            self.assertEqual(first, second)
            self.assertEqual(first["status"], "VERIFIED")
            self.assertEqual([item["name"] for item in first["streams"]], ["depth", "trade"])
            self.assertNotIn("imbalance", json.dumps(first))
            self.assertEqual(
                first["inventory"],
                [
                    "depth",
                    "generation.json",
                    "snapshot-http.json",
                    "snapshot.bnraw",
                    "startup.json",
                    "telemetry.jsonl",
                    "trade",
                    "transport-depth-events.jsonl",
                    "transport-depth.json",
                    "transport-trade-events.jsonl",
                    "transport-trade.json",
                ],
            )
            self.assertEqual(first["streams"][1]["first_sequence"], 10)
            self.assertEqual(first["streams"][1]["final_sequence"], 12)

    def test_cli_subcommand_writes_only_an_explicit_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "generation"
            root.mkdir()
            _build_generation(root)
            report = Path(directory) / "verification.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(["verify-segmented-generation", str(root), "--output", str(report)]),
                    0,
                )
            self.assertEqual(json.loads(report.read_text(encoding="utf-8"))["status"], "VERIFIED")

    def test_cli_refuses_to_pollute_exact_generation_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "generation"
            root.mkdir()
            _build_generation(root)
            report = root / "verification.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                status = main(
                    ["verify-segmented-generation", str(root), "--output", str(report)]
                )
            self.assertEqual(status, 2)
            self.assertFalse(report.exists())

    def test_raw_digest_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            path = root / "depth" / "segment-000000.bnraw"
            data = bytearray(path.read_bytes())
            data[-1] ^= 1
            path.write_bytes(data)
            with self.assertRaisesRegex(SegmentChainCorruption, "raw record digest mismatch"):
                verify_segmented_generation(root)

    def test_raw_truncation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            path = root / "trade" / "segment-000001.bnraw"
            path.write_bytes(path.read_bytes()[:-5])
            with self.assertRaisesRegex(SegmentChainCorruption, "partial raw record digest"):
                verify_segmented_generation(root)

    def test_manifest_digest_and_truncation_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            path = root / "depth" / "segments.bnseg"
            data = bytearray(path.read_bytes())
            data[-1] ^= 1
            path.write_bytes(data)
            with self.assertRaisesRegex(SegmentChainCorruption, "manifest record digest mismatch"):
                verify_segmented_generation(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            path = root / "depth" / "segments.bnseg"
            path.write_bytes(path.read_bytes()[:-7])
            with self.assertRaisesRegex(SegmentChainCorruption, "partial segment manifest digest"):
                verify_segmented_generation(root)

    def test_reordered_segments_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            manifest = root / "depth" / "segments.bnseg"
            # Recreate syntactically valid records while reversing the authoritative seals.
            from binance_lob.segment_chain import _scan_segment_manifest  # local test oracle access

            seals = list(_scan_segment_manifest(manifest).seals)
            _write_manifest(manifest, list(reversed(seals)))
            with self.assertRaisesRegex(SegmentChainCorruption, "segment index is out of order"):
                verify_segmented_generation(root)

    def test_duplicate_raw_file_authority_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            manifest = root / "depth" / "segments.bnseg"
            from binance_lob.segment_chain import _scan_segment_manifest

            seals = [dict(seal) for seal in _scan_segment_manifest(manifest).seals]
            seals[1]["raw_file"] = seals[0]["raw_file"]
            _write_manifest(manifest, seals)
            with self.assertRaisesRegex(SegmentChainCorruption, "duplicate raw segment file"):
                verify_segmented_generation(root)

    def test_unsafe_raw_file_authority_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            manifest = root / "trade" / "segments.bnseg"
            from binance_lob.segment_chain import _scan_segment_manifest

            seals = [dict(seal) for seal in _scan_segment_manifest(manifest).seals]
            seals[0]["raw_file"] = "../segment-000000.bnraw"
            _write_manifest(manifest, seals)
            with self.assertRaisesRegex(SegmentChainCorruption, "safe relative path"):
                verify_segmented_generation(root)

    def test_noncanonical_manifest_json_is_rejected_even_with_valid_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            manifest = root / "depth" / "segments.bnseg"
            from binance_lob.segment_chain import _scan_segment_manifest

            seal = dict(_scan_segment_manifest(manifest).seals[0])
            # The same fields in a different order remain valid JSON, but are
            # not the exact deterministic Rust record encoding.
            body = _canonical(
                {
                    "record_index": 0,
                    "schema": "RawSegmentManifestRecordV1",
                    "previous_manifest_record_sha256": ZERO_DIGEST,
                    "seal": seal,
                }
            )
            record, _ = _encoded_record(body)
            manifest.write_bytes(MANIFEST_MAGIC + record)
            with self.assertRaisesRegex(SegmentChainCorruption, "reordered fields"):
                verify_segmented_generation(root)

    def test_frame_discontinuity_is_rejected_even_with_fresh_record_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            depth = generation["streams"][0]
            assert isinstance(depth, dict)
            stream, uri = _stream_uri("BTCUSDT", "depth")
            _write_raw(
                root / "depth" / "segment-000000.bnraw",
                symbol="BTCUSDT",
                endpoint=uri,
                stream=stream,
                epoch=str(depth["connection_epoch"]),
                first_frame=0,
                previous=ZERO_DIGEST,
                payloads=[b"opaque"],
                frame_delta=1,
            )
            with self.assertRaisesRegex(SegmentChainCorruption, "non-contiguous raw frame index"):
                verify_segmented_generation(root)

    def test_unreferenced_raw_file_is_rejected_as_an_omission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            orphan = root / "depth" / "segment-999999.bnraw"
            orphan.write_bytes((root / "depth" / "segment-000000.bnraw").read_bytes())
            with self.assertRaisesRegex(SegmentChainCorruption, "unreferenced=.*999999"):
                verify_segmented_generation(root)

    def test_unsafe_manifest_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            depth = generation["streams"][0]
            assert isinstance(depth, dict)
            depth["segment_manifest"] = "../segments.bnseg"
            _write_generation(root, generation)
            with self.assertRaisesRegex(SegmentChainCorruption, "safe relative path"):
                verify_segmented_generation(root)

    def test_snapshot_claim_must_match_immutable_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            snapshot = generation["snapshot"]
            assert isinstance(snapshot, dict)
            snapshot["last_update_id"] = 43
            _write_generation(root, generation)
            with self.assertRaisesRegex(SegmentChainCorruption, "lastUpdateId differs"):
                verify_segmented_generation(root)

    def test_startup_hash_and_identity_are_terminally_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            startup_path = root / "startup.json"
            startup_path.write_bytes(startup_path.read_bytes() + b" ")
            with self.assertRaisesRegex(SegmentChainCorruption, "startup manifest digest"):
                verify_segmented_generation(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            startup_path = root / "startup.json"
            startup = json.loads(startup_path.read_text(encoding="utf-8"))
            startup["symbol"] = "ETHUSDT"
            startup_bytes = json.dumps(startup, ensure_ascii=False, indent=2).encode() + b"\n"
            startup_path.write_bytes(startup_bytes)
            generation["startup_sha256"] = sha256(startup_bytes).hexdigest()
            _write_generation(root, generation)
            with self.assertRaisesRegex(SegmentChainCorruption, "startup manifest differs"):
                verify_segmented_generation(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            generation["collector_executable_sha256"] = "not-a-sha256"
            _write_generation(root, generation)
            with self.assertRaisesRegex(SegmentChainCorruption, "collector_executable_sha256"):
                verify_segmented_generation(root)

    def test_snapshot_http_metadata_must_bind_exact_raw_body(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            metadata_path = root / "snapshot-http.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["body_length"] += 1
            metadata_bytes = _canonical(metadata)
            metadata_path.write_bytes(metadata_bytes)
            snapshot = generation["snapshot"]
            assert isinstance(snapshot, dict)
            snapshot["http_metadata_sha256"] = sha256(metadata_bytes).hexdigest()
            _write_generation(root, generation)
            with self.assertRaisesRegex(SegmentChainCorruption, "not bound to the exact raw body"):
                verify_segmented_generation(root)

    def test_bnack_portable_reference_hash_and_clean_eof_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            progress = root / "depth" / "segment-000000.bnack"
            _rewrite_progress(progress, lambda body: body.__setitem__("raw_path", "../escape.bnraw"))
            with self.assertRaisesRegex(SegmentChainCorruption, "safe relative path"):
                verify_segmented_generation(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            progress = root / "trade" / "segment-000001.bnack"
            progress.write_bytes(progress.read_bytes()[:-1])
            with self.assertRaisesRegex(SegmentChainCorruption, "partial durability progress tail"):
                verify_segmented_generation(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            progress = root / "trade" / "segment-000000.bnack"
            envelope = json.loads(progress.read_text(encoding="utf-8"))
            envelope["record_sha256"] = "0" * 64
            progress.write_bytes(_canonical(envelope) + b"\n")
            with self.assertRaisesRegex(SegmentChainCorruption, "body digest mismatch"):
                verify_segmented_generation(root)

    def test_bnack_survives_moving_complete_generation_without_path_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source_parent = base / "source"
            destination_parent = base / "destination"
            source_parent.mkdir()
            destination_parent.mkdir()
            root = source_parent / "portable-generation"
            root.mkdir()
            _build_generation(root)
            moved = destination_parent / root.name
            root.rename(moved)
            self.assertEqual(verify_segmented_generation(moved)["status"], "VERIFIED")

    def test_telemetry_hash_terminal_newline_and_monotonicity_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            records = [
                _telemetry_record(0, terminal=False),
                _telemetry_record(1, terminal=True),
            ]
            records[0]["depth_max_queue_age_ns"] = 200
            _rewrite_telemetry(root, generation, records)
            with self.assertRaisesRegex(SegmentChainCorruption, "telemetry monotonic lineage"):
                verify_segmented_generation(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            records = [
                _telemetry_record(0, terminal=False),
                _telemetry_record(1, terminal=True),
            ]
            _rewrite_telemetry(root, generation, records, terminal_newline=False)
            with self.assertRaisesRegex(SegmentChainCorruption, "terminal record is partial"):
                verify_segmented_generation(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            telemetry = generation["telemetry"]
            assert isinstance(telemetry, dict)
            telemetry["terminal_record_sha256"] = "f" * 64
            _write_generation(root, generation)
            with self.assertRaisesRegex(SegmentChainCorruption, "terminal counters"):
                verify_segmented_generation(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            telemetry = generation["telemetry"]
            assert isinstance(telemetry, dict)
            telemetry["durable_through_offset"] += 1
            _write_generation(root, generation)
            with self.assertRaisesRegex(SegmentChainCorruption, "telemetry hash differs"):
                verify_segmented_generation(root)

    def test_transport_metadata_hash_identity_and_inventory_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            path = root / "transport-depth.json"
            metadata = json.loads(path.read_text(encoding="utf-8"))
            metadata["connection"]["remote_endpoint"] = "198.51.100.1:80"
            metadata_bytes = (
                json.dumps(metadata, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
            )
            path.write_bytes(metadata_bytes)
            depth = generation["streams"][0]
            assert isinstance(depth, dict)
            depth["transport_metadata_sha256"] = sha256(metadata_bytes).hexdigest()
            _write_generation(root, generation)
            with self.assertRaisesRegex(SegmentChainCorruption, "transport identity/handshake"):
                verify_segmented_generation(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            (root / "transport-trade.json").unlink()
            with self.assertRaisesRegex(SegmentChainCorruption, "missing or inaccessible"):
                verify_segmented_generation(root)

    def test_transport_journal_rejects_semantic_tamper_with_fresh_hashes(self) -> None:
        def resign(root: Path, generation: dict[str, object], mutate) -> None:
            path = root / "transport-depth-events.jsonl"
            envelopes = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            mutate(envelopes)
            previous = ZERO_DIGEST
            encoded = bytearray()
            for envelope in envelopes:
                body = envelope["body"]
                body["previous_record_sha256"] = previous
                previous = sha256(_canonical(body)).hexdigest()
                envelope["record_sha256"] = previous
                encoded.extend(_canonical(envelope) + b"\n")
            data = bytes(encoded)
            path.write_bytes(data)
            depth = generation["streams"][0]
            assert isinstance(depth, dict)
            seal = depth["transport_journal"]
            assert isinstance(seal, dict)
            seal["terminal_record_sha256"] = previous
            seal["file_bytes"] = len(data)
            seal["file_sha256"] = sha256(data).hexdigest()
            _write_generation(root, generation)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            resign(
                root,
                generation,
                lambda envelopes: envelopes[3]["body"].update(
                    {
                        "event": "WS_PONG_RECEIVED",
                        "payload": {"payload_bytes": 0, "payload_sha256": sha256(b"").hexdigest()},
                    }
                ),
            )
            with self.assertRaisesRegex(SegmentChainCorruption, "contradicts observed lifecycle"):
                verify_segmented_generation(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            resign(
                root,
                generation,
                lambda envelopes: envelopes[3]["body"].update(
                    {"event": "FUTURE_UNKNOWN_EVENT", "payload": {}}
                ),
            )
            with self.assertRaisesRegex(SegmentChainCorruption, "event is unknown"):
                verify_segmented_generation(root)

    def test_trade_ids_may_skip_but_must_strictly_increase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root, trade_ids=(10, 12))
            report = verify_segmented_generation(root)
            trade = report["streams"][1]
            self.assertEqual((trade["first_sequence"], trade["final_sequence"]), (10, 12))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root, trade_ids=(10, 10))
            with self.assertRaisesRegex(SegmentChainCorruption, "duplicated or regressed"):
                verify_segmented_generation(root)

    def test_exact_inventory_rejects_non_evidence_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _build_generation(root)
            (root / "notes.txt").write_text("not authoritative", encoding="utf-8")
            with self.assertRaisesRegex(SegmentChainCorruption, "unreferenced=.*notes.txt"):
                verify_segmented_generation(root)

    def test_generation_digest_claim_must_match_bnseg(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = _build_generation(root)
            depth = generation["streams"][0]
            assert isinstance(depth, dict)
            depth["segment_manifest_sha256"] = "1" * 64
            _write_generation(root, generation)
            with self.assertRaisesRegex(SegmentChainCorruption, "manifest digest mismatch"):
                verify_segmented_generation(root)


if __name__ == "__main__":
    unittest.main()
