"""Bounded public market-data capture. No authenticated capability exists here."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json
from pathlib import Path
import random
import uuid

from websockets.asyncio.client import connect

from .clock import ClockQuality, sample_clock
from .raw_frame import RawFrameV1
from .raw_log import DurabilityAckV1, RawLogWriter, scan_raw_log
from .snapshot import fetch_snapshot
from .spec import PublicMarketDataSpec


class CaptureIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CaptureOptions:
    output_root: Path
    symbol: str
    duration_s: float = 15.0
    streams: tuple[str, ...] = ("depth", "trade")
    queue_capacity: int = 4096
    sync_every: int = 64
    max_reconnects: int = 5
    clock_quality: ClockQuality = ClockQuality.UNKNOWN
    clock_source: str = "unverified-local-clock"

    def __post_init__(self) -> None:
        PublicMarketDataSpec.require_symbol(self.symbol)
        if self.duration_s <= 0 or self.duration_s > 86_400:
            raise ValueError("duration_s must be within (0, 86400]")
        if not self.streams or any(stream not in {"depth", "trade"} for stream in self.streams):
            raise ValueError("only depth and trade streams are capturable")
        if len(set(self.streams)) != len(self.streams):
            raise ValueError("duplicate stream")
        if self.queue_capacity < 1 or self.sync_every < 1 or self.max_reconnects < 0:
            raise ValueError("invalid capture limits")


@dataclass(slots=True)
class _StreamRuntime:
    name: str
    uri: str
    writer: RawLogWriter
    queue: asyncio.Queue[RawFrameV1]
    connected: asyncio.Event = field(default_factory=asyncio.Event)
    producer_done: asyncio.Event = field(default_factory=asyncio.Event)
    connections: list[dict[str, object]] = field(default_factory=list)
    received: int = 0
    written: int = 0
    durability_ack: DurabilityAckV1 | None = None
    error: str | None = None


def _atomic_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    temporary.write_text(data, encoding="utf-8", newline="\n")
    temporary.replace(path)


async def _writer_loop(runtime: _StreamRuntime, stop: asyncio.Event) -> None:
    try:
        while not runtime.producer_done.is_set() or not runtime.queue.empty():
            try:
                frame = await asyncio.wait_for(runtime.queue.get(), timeout=0.25)
            except TimeoutError:
                continue
            await asyncio.to_thread(runtime.writer.append, frame)
            runtime.written += 1
            runtime.queue.task_done()
        runtime.durability_ack = await asyncio.to_thread(runtime.writer.sync)
    except Exception as exc:
        runtime.error = f"writer: {type(exc).__name__}: {exc}"
        stop.set()


async def _producer_loop(
    runtime: _StreamRuntime,
    symbol: str,
    options: CaptureOptions,
    stop: asyncio.Event,
) -> None:
    reconnects = 0
    try:
        while not stop.is_set():
            epoch = str(uuid.uuid4())
            connection: dict[str, object] = {
                "epoch": epoch,
                "opened_at": datetime.now(UTC).isoformat(),
                "closed_at": None,
                "frames": 0,
                "error": None,
            }
            runtime.connections.append(connection)
            frame_index = 0
            try:
                async with connect(
                    runtime.uri,
                    open_timeout=15,
                    close_timeout=5,
                    ping_interval=None,
                    ping_timeout=None,
                    compression=None,
                    max_size=2 * 1024 * 1024,
                    max_queue=16,
                    proxy=None,
                ) as websocket:
                    runtime.connected.set()
                    async for message in websocket:
                        if stop.is_set():
                            break
                        clock = sample_clock(
                            quality=options.clock_quality,
                            source=options.clock_source,
                        )
                        payload = message.encode("utf-8") if isinstance(message, str) else bytes(message)
                        frame = RawFrameV1.capture(
                            endpoint=runtime.uri,
                            stream=(
                                f"{symbol.lower()}@depth@100ms"
                                if runtime.name == "depth"
                                else f"{symbol.lower()}@trade"
                            ),
                            symbol=symbol,
                            connection_epoch=epoch,
                            frame_index=frame_index,
                            clock=clock,
                            payload=payload,
                        )
                        try:
                            runtime.queue.put_nowait(frame)
                        except asyncio.QueueFull as exc:
                            raise CaptureIntegrityError(
                                f"bounded queue overflow on {runtime.name}"
                            ) from exc
                        frame_index += 1
                        runtime.received += 1
                        connection["frames"] = frame_index
            except asyncio.CancelledError:
                raise
            except CaptureIntegrityError:
                raise
            except Exception as exc:
                connection["error"] = f"{type(exc).__name__}: {exc}"
                reconnects += 1
                if reconnects > options.max_reconnects:
                    raise CaptureIntegrityError(
                        f"reconnect budget exhausted on {runtime.name}"
                    ) from exc
                delay = min(8.0, float(2 ** (reconnects - 1))) + random.uniform(0.0, 0.25)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=delay)
                except TimeoutError:
                    pass
            finally:
                connection["closed_at"] = datetime.now(UTC).isoformat()
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        runtime.error = f"producer: {type(exc).__name__}: {exc}"
        stop.set()
    finally:
        runtime.producer_done.set()


def _session_manifest(
    *,
    session_id: str,
    started_at: str,
    ended_at: str | None,
    options: CaptureOptions,
    runtimes: list[_StreamRuntime],
    snapshot: dict[str, object] | None,
    status: str,
    error: str | None,
) -> dict[str, object]:
    return {
        "schema": "CaptureManifestV1",
        "session_id": session_id,
        "started_at": started_at,
        "ended_at": ended_at,
        "status": status,
        "error": error,
        "symbol": PublicMarketDataSpec.require_symbol(options.symbol),
        "duration_requested_s": options.duration_s,
        "clock_quality": options.clock_quality.value,
        "clock_source": options.clock_source,
        "credentials": "NONE",
        "order_entry": "ABSENT",
        "spec_revision": PublicMarketDataSpec().spec_revision,
        "snapshot": snapshot,
        "streams": [
            {
                "name": runtime.name,
                "uri": runtime.uri,
                "received": runtime.received,
                "written": runtime.written,
                "queue_capacity": options.queue_capacity,
                "error": runtime.error,
                "connections": runtime.connections,
                "raw_file": runtime.writer.path.name,
                "durability_ack": (
                    None if runtime.durability_ack is None else asdict(runtime.durability_ack)
                ),
            }
            for runtime in runtimes
        ],
    }


async def capture_public(options: CaptureOptions) -> Path:
    spec = PublicMarketDataSpec()
    symbol = spec.require_symbol(options.symbol)
    session_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%S.%fZ')}-{symbol}-{uuid.uuid4().hex[:12]}"
    session_dir = Path(options.output_root) / session_id
    session_dir.mkdir(parents=True, exist_ok=False)
    manifest_path = session_dir / "manifest.json"
    started_at = datetime.now(UTC).isoformat()
    stop = asyncio.Event()
    runtimes: list[_StreamRuntime] = []
    snapshot_metadata: dict[str, object] | None = None
    error: str | None = None

    for stream in options.streams:
        writer = RawLogWriter(session_dir / f"{stream}.bnraw", sync_every=options.sync_every)
        runtimes.append(
            _StreamRuntime(
                name=stream,
                uri=spec.websocket_uri(symbol, stream),
                writer=writer,
                queue=asyncio.Queue(maxsize=options.queue_capacity),
            )
        )

    _atomic_json(
        manifest_path,
        _session_manifest(
            session_id=session_id,
            started_at=started_at,
            ended_at=None,
            options=options,
            runtimes=runtimes,
            snapshot=None,
            status="RUNNING",
            error=None,
        ),
    )

    producers = [
        asyncio.create_task(_producer_loop(runtime, symbol, options, stop)) for runtime in runtimes
    ]
    consumers = [asyncio.create_task(_writer_loop(runtime, stop)) for runtime in runtimes]

    try:
        await asyncio.wait_for(
            asyncio.gather(*(runtime.connected.wait() for runtime in runtimes)),
            timeout=20,
        )
        snapshot = await asyncio.to_thread(fetch_snapshot, spec, symbol)
        snapshot_writer = RawLogWriter(session_dir / "snapshot.bnraw", sync_every=1)
        snapshot_epoch = f"snapshot-{uuid.uuid4()}"
        snapshot_frame = RawFrameV1.capture(
            endpoint=snapshot.endpoint,
            stream=f"{symbol.lower()}@rest-depth-snapshot",
            symbol=symbol,
            connection_epoch=snapshot_epoch,
            frame_index=0,
            clock=sample_clock(quality=options.clock_quality, source=options.clock_source),
            payload=snapshot.payload,
        )
        snapshot_writer.append(snapshot_frame)
        snapshot_ack = snapshot_writer.close()
        if snapshot_ack is None:
            raise CaptureIntegrityError("snapshot closed without durability acknowledgement")
        snapshot_metadata = {
            "raw_file": "snapshot.bnraw",
            "endpoint": snapshot.endpoint,
            "http_status": snapshot.status,
            "last_update_id": snapshot.last_update_id,
            "bid_levels": snapshot.bid_levels,
            "ask_levels": snapshot.ask_levels,
            "durability_ack": asdict(snapshot_ack),
        }
        try:
            await asyncio.wait_for(stop.wait(), timeout=options.duration_s)
        except TimeoutError:
            pass
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        stop.set()
        for producer in producers:
            producer.cancel()
        await asyncio.gather(*producers, return_exceptions=True)
        for runtime in runtimes:
            runtime.producer_done.set()
        await asyncio.gather(*consumers, return_exceptions=True)
        for runtime in runtimes:
            runtime.writer.close()

    runtime_errors = [runtime.error for runtime in runtimes if runtime.error]
    for runtime in runtimes:
        if (
            runtime.error is None
            and (
                runtime.durability_ack is None
                or runtime.durability_ack.durable_record_count != runtime.written
            )
        ):
            runtime.error = "writer: missing or incomplete durability acknowledgement"
            runtime_errors.append(runtime.error)
    if error is None and runtime_errors:
        error = "; ".join(runtime_errors)
    scans: dict[str, object] = {}
    for path in sorted(session_dir.glob("*.bnraw")):
        scan = scan_raw_log(path)
        scans[path.name] = asdict(scan) | {"path": path.name}
        if not scan.clean_eof and error is None:
            error = f"raw verification failed: {path.name}: {scan.reason}"
    status = "COMPLETE" if error is None else "FAILED"
    manifest = _session_manifest(
        session_id=session_id,
        started_at=started_at,
        ended_at=datetime.now(UTC).isoformat(),
        options=options,
        runtimes=runtimes,
        snapshot=snapshot_metadata,
        status=status,
        error=error,
    )
    manifest["raw_verification"] = scans
    _atomic_json(manifest_path, manifest)
    if error is not None:
        raise CaptureIntegrityError(f"capture failed; evidence preserved at {session_dir}: {error}")
    return session_dir
