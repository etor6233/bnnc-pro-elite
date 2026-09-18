"""Independent neutral replay of an explicitly selected sealed segment prefix."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from binance_lob.book import ApplyOutcome, LocalOrderBook
from binance_lob.fixed_decimal import FixedDecimal
from binance_lob.raw_log import iter_raw_records
from binance_lob.segment_chain import (
    SegmentChainCorruption,
    _RawExpectations,
    _parse_json,
    _scan_raw_segment,
    _scan_segment_manifest,
)


DEVELOPMENT_USAGE = "DEVELOPMENT_ONLY_FAILED_PREFIX_NOT_PROMOTABLE"
SPEC_REVISION = "976cc580553890e92031b77306147c0ed1de5a46"


class MarketReplayCorruption(ValueError):
    """The selected prefix cannot be replayed without ambiguity."""


def _fail(reason: str) -> None:
    raise MarketReplayCorruption(reason)


def _sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        _fail(f"hashed source is not a regular non-link file: {path}")
    digest = sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _load_object(path: Path, label: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label} is not a regular non-link file")
    try:
        value = _parse_json(path.read_bytes(), label)
    except OSError as exc:
        _fail(f"cannot read {label}: {exc.strerror or exc}")
    if not isinstance(value, dict):
        _fail(f"{label} root must be an object")
    return value


def _validate_failed_source(generation: Path, symbol: str) -> dict[str, str]:
    generations = generation.parent
    if generations.name != "generations":
        _fail("generation is not below an exact generations directory")
    campaign = generations.parent
    run = campaign.parent
    terminal_path = run / "launcher-terminal.json"
    terminal = _load_object(terminal_path, "launcher terminal")
    run_id = _text(terminal, "run_id", "launcher terminal")
    if (
        _text(terminal, "schema", "launcher terminal")
        != "RawQualificationLauncherTerminalV2"
        or _text(terminal, "status", "launcher terminal") != "FAILED"
        or _text(terminal, "mode", "launcher terminal") != "Production"
        or _text(terminal, "credentials", "launcher terminal") != "NONE"
        or _text(terminal, "order_entry", "launcher terminal") != "ABSENT"
        or run.name != run_id
        or Path(_text(terminal, "run_root", "launcher terminal")).resolve(strict=True)
        != run
    ):
        _fail("source qualification is not an exact failed production run")
    bindings_path = run / "campaign-bindings.json"
    bindings_sha = _sha256_file(bindings_path)
    if (
        _text(terminal, "campaign_bindings_sha256", "launcher terminal")
        != bindings_sha
    ):
        _fail("launcher terminal does not bind campaign-bindings.json")
    bindings = _load_object(bindings_path, "campaign bindings")
    rows = bindings.get("campaigns")
    if (
        _text(bindings, "schema", "campaign bindings")
        != "RawQualificationCampaignBindingsV1"
        or _text(bindings, "run_id", "campaign bindings") != run_id
        or not isinstance(rows, list)
    ):
        _fail("campaign bindings identity differs from failed run")
    matches = 0
    for row in rows:
        if not isinstance(row, dict):
            _fail("campaign binding must be an object")
        if (
            _text(row, "campaign_id", "campaign binding") == campaign.name
            and _text(row, "symbol", "campaign binding") == symbol
            and Path(
                _text(row, "campaign_directory", "campaign binding")
            ).resolve(strict=True)
            == campaign
        ):
            matches += 1
    if matches != 1:
        _fail("selected generation is not bound exactly once by the failed run")
    return {
        "run_id": run_id,
        "campaign_id": campaign.name,
        "launcher_terminal_sha256": _sha256_file(terminal_path),
        "campaign_bindings_sha256": bindings_sha,
    }


def _text(value: dict[str, object], field: str, label: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item:
        _fail(f"{label}.{field} must be non-empty text")
    return item


def _integer(value: dict[str, object], field: str, label: str) -> int:
    item = value.get(field)
    if type(item) is not int or item < 0 or item > (1 << 64) - 1:
        _fail(f"{label}.{field} must be a u64")
    return item


def _transport(
    generation: Path,
    kind: str,
    startup: dict[str, object],
) -> dict[str, str]:
    value = _load_object(generation / f"transport-{kind}.json", "transport metadata")
    connection = value.get("connection")
    if not isinstance(connection, dict):
        _fail("transport.connection must be an object")
    if (
        _text(value, "schema", "transport") != "TransportMetadataV1"
        or _text(value, "session_id", "transport")
        != _text(startup, "session_id", "startup")
        or _integer(value, "generation_index", "transport")
        != _integer(startup, "generation_index", "startup")
        or _text(value, "symbol", "transport")
        != _text(startup, "symbol", "startup")
        or _text(value, "spec_revision", "transport")
        != _text(startup, "spec_revision", "startup")
        or _text(connection, "stream", "transport.connection") != kind
        or _integer(connection, "websocket_http_status", "transport.connection") != 101
    ):
        _fail("transport metadata differs from startup identity")
    symbol = _text(value, "symbol", "transport")
    stream = (
        f"{symbol.lower()}@depth@100ms"
        if kind == "depth"
        else f"{symbol.lower()}@trade"
    )
    return {
        "symbol": symbol,
        "stream": stream,
        "connection_epoch": _text(
            connection, "connection_epoch", "transport.connection"
        ),
        "endpoint": _text(connection, "uri", "transport.connection"),
        "spec_revision": _text(value, "spec_revision", "transport"),
    }


def _selected_seals(
    manifest: Any, through_segment_index: int, label: str
) -> tuple[dict[str, object], ...]:
    count = through_segment_index + 1
    if count <= 0 or count > len(manifest.seals):
        _fail(
            f"{label} manifest has {len(manifest.seals)} records, cannot select "
            f"through segment {through_segment_index}"
        )
    return manifest.seals[:count]


def _expectations(seal: dict[str, object], identity: dict[str, str]) -> _RawExpectations:
    return _RawExpectations(
        connection_epoch=_text(seal, "connection_epoch", "seal"),
        stream=_text(seal, "stream", "seal"),
        first_frame_index=_integer(seal, "first_frame_index", "seal"),
        initial_previous_sha256=_text(
            seal, "previous_segment_terminal_sha256", "seal"
        ),
        symbol=identity["symbol"],
        endpoint=identity["endpoint"],
        spec_revision=identity["spec_revision"],
    )


def _verify_scan_against_seal(scan: Any, seal: dict[str, object], label: str) -> None:
    if (
        scan.records != _integer(seal, "records", "seal")
        or scan.last_good_offset != _integer(seal, "durable_through_offset", "seal")
        or scan.first_frame_index != _integer(seal, "first_frame_index", "seal")
        or scan.last_frame_index != _integer(seal, "last_frame_index", "seal")
        or scan.last_record_sha256
        != _text(seal, "terminal_record_sha256", "seal")
    ):
        _fail(f"{label} segment differs from its manifest seal")


def _payload_object(payload: bytes, label: str) -> dict[str, object]:
    value = _parse_json(payload, label)
    if not isinstance(value, dict):
        _fail(f"{label} root must be an object")
    return value


def _server_shutdown(value: dict[str, object]) -> bool:
    if value.get("e") != "serverShutdown":
        return False
    _integer(value, "E", "serverShutdown")
    return True


def _replay_depth(
    generation: Path,
    through: int,
    segment_duration_ns: int,
    snapshot_payload: bytes,
    identity: dict[str, str],
) -> tuple[dict[str, object], str, str]:
    directory = generation / "depth"
    manifest_path = directory / "segments.bnseg"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        _fail("depth segment manifest is not a regular non-link file")
    manifest = _scan_segment_manifest(manifest_path)
    seals = _selected_seals(manifest, through, "depth")
    book = LocalOrderBook(identity["symbol"])
    book.load_snapshot(snapshot_payload)
    raw_records = 0
    controls = 0
    old_records = 0
    applied_records = 0
    first_applied: int | None = None
    previous_mono: int | None = None
    checkpoints: list[dict[str, object]] = []
    for seal in seals:
        segment_index = _integer(seal, "segment_index", "seal")
        raw_file = _text(seal, "raw_file", "seal")
        if Path(raw_file).name != raw_file:
            _fail("depth manifest raw file is not a local filename")
        raw_path = directory / raw_file
        if raw_path.is_symlink() or not raw_path.is_file():
            _fail("selected depth segment is not a regular non-link file")
        scan = _scan_raw_segment(
            raw_path,
            _expectations(seal, identity),
            capture_records=True,
            segment_index=segment_index,
            segment_duration_ns=segment_duration_ns,
        )
        _verify_scan_against_seal(scan, seal, "depth")
        if scan.captured_records is None:
            _fail("depth scan did not retain replay records")
        frame_index = _integer(seal, "first_frame_index", "seal")
        for record in scan.captured_records:
            if previous_mono is not None and record.receive_mono_ns < previous_mono:
                _fail("depth receive monotonic time regressed")
            previous_mono = record.receive_mono_ns
            raw_records += 1
            value = _payload_object(record.payload, "depth payload")
            if _server_shutdown(value):
                controls += 1
            else:
                outcome = book.apply_depth(record.payload)
                if outcome is ApplyOutcome.OLD:
                    old_records += 1
                else:
                    if first_applied is None:
                        first_applied = frame_index
                    applied_records += 1
            frame_index += 1
        if frame_index - 1 != _integer(seal, "last_frame_index", "seal"):
            _fail("depth replay frame range differs from seal")
        if book.last_update_id is None:
            _fail("depth replay lost its update ID")
        checkpoints.append(
            {
                "segment_index": segment_index,
                "terminal_record_sha256": _text(
                    seal, "terminal_record_sha256", "seal"
                ),
                "last_frame_index": _integer(seal, "last_frame_index", "seal"),
                "last_update_id": book.last_update_id,
                "state_sha256": book.state_digest(),
            }
        )
    if book.state.value != "LIVE" or first_applied is None or book.last_update_id is None:
        _fail("selected depth prefix never reached LIVE")
    first, last = seals[0], seals[-1]
    return (
        {
            "connection_epoch": identity["connection_epoch"],
            "stream": identity["stream"],
            "selected_segments": len(seals),
            "excluded_manifest_segments": manifest.records - len(seals),
            "raw_records": raw_records,
            "control_records": controls,
            "old_records": old_records,
            "applied_records": applied_records,
            "first_frame_index": _integer(first, "first_frame_index", "seal"),
            "last_frame_index": _integer(last, "last_frame_index", "seal"),
            "first_applied_frame_index": first_applied,
            "final_update_id": book.last_update_id,
            "bid_levels": book.bid_levels,
            "ask_levels": book.ask_levels,
            "state_sha256": book.state_digest(),
            "checkpoints": checkpoints,
        },
        _sha256_file(manifest_path),
        _manifest_record_digest(manifest_path, through),
    )


def _replay_trades(
    generation: Path,
    through: int,
    segment_duration_ns: int,
    identity: dict[str, str],
) -> tuple[dict[str, object], str, str]:
    directory = generation / "trade"
    manifest_path = directory / "segments.bnseg"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        _fail("trade segment manifest is not a regular non-link file")
    manifest = _scan_segment_manifest(manifest_path)
    seals = _selected_seals(manifest, through, "trade")
    raw_records = 0
    controls = 0
    first_trade_id: int | None = None
    previous_trade_id: int | None = None
    previous_mono: int | None = None
    checkpoints: list[dict[str, object]] = []
    for seal in seals:
        segment_index = _integer(seal, "segment_index", "seal")
        raw_file = _text(seal, "raw_file", "seal")
        if Path(raw_file).name != raw_file:
            _fail("trade manifest raw file is not a local filename")
        raw_path = directory / raw_file
        if raw_path.is_symlink() or not raw_path.is_file():
            _fail("selected trade segment is not a regular non-link file")
        scan = _scan_raw_segment(
            raw_path,
            _expectations(seal, identity),
            capture_records=True,
            segment_index=segment_index,
            segment_duration_ns=segment_duration_ns,
        )
        _verify_scan_against_seal(scan, seal, "trade")
        if scan.captured_records is None:
            _fail("trade scan did not retain replay records")
        frame_index = _integer(seal, "first_frame_index", "seal")
        for record in scan.captured_records:
            if previous_mono is not None and record.receive_mono_ns < previous_mono:
                _fail("trade receive monotonic time regressed")
            previous_mono = record.receive_mono_ns
            raw_records += 1
            value = _payload_object(record.payload, "trade payload")
            if _server_shutdown(value):
                controls += 1
            else:
                if value.get("e") != "trade" or value.get("s") != identity["symbol"]:
                    _fail("unexpected trade event type or symbol")
                _integer(value, "E", "trade")
                _integer(value, "T", "trade")
                trade_id = _integer(value, "t", "trade")
                for field in ("p", "q"):
                    raw_decimal = value.get(field)
                    if not isinstance(raw_decimal, str):
                        _fail(f"trade.{field} must be a decimal string")
                    decimal = FixedDecimal.parse(raw_decimal)
                    if decimal.coefficient <= 0:
                        _fail(f"trade.{field} must be positive")
                for field in ("m", "M"):
                    if type(value.get(field)) is not bool:
                        _fail(f"trade.{field} must be boolean")
                if previous_trade_id is not None and trade_id <= previous_trade_id:
                    _fail(
                        "trade ID duplicated or regressed: "
                        f"previous {previous_trade_id}, got {trade_id}"
                    )
                if first_trade_id is None:
                    first_trade_id = trade_id
                previous_trade_id = trade_id
            frame_index += 1
        if frame_index - 1 != _integer(seal, "last_frame_index", "seal"):
            _fail("trade replay frame range differs from seal")
        if previous_trade_id is None:
            _fail("selected trade prefix contains no trade event")
        checkpoints.append(
            {
                "segment_index": segment_index,
                "terminal_record_sha256": _text(
                    seal, "terminal_record_sha256", "seal"
                ),
                "last_frame_index": _integer(seal, "last_frame_index", "seal"),
                "last_trade_id": previous_trade_id,
            }
        )
    if first_trade_id is None or previous_trade_id is None:
        _fail("selected trade prefix contains no trade event")
    first, last = seals[0], seals[-1]
    return (
        {
            "connection_epoch": identity["connection_epoch"],
            "stream": identity["stream"],
            "selected_segments": len(seals),
            "excluded_manifest_segments": manifest.records - len(seals),
            "raw_records": raw_records,
            "control_records": controls,
            "first_frame_index": _integer(first, "first_frame_index", "seal"),
            "last_frame_index": _integer(last, "last_frame_index", "seal"),
            "first_trade_id": first_trade_id,
            "last_trade_id": previous_trade_id,
            "trade_ids_strictly_increasing": True,
            "checkpoints": checkpoints,
        },
        _sha256_file(manifest_path),
        _manifest_record_digest(manifest_path, through),
    )


def _manifest_record_digest(path: Path, index: int) -> str:
    """Independently return the stored digest for one already-scanned record."""
    with path.open("rb") as handle:
        if handle.read(8) != b"BNSEG\0\x01\n":
            _fail("bad segment manifest magic")
        for current in range(index + 1):
            prefix = handle.read(4)
            if len(prefix) != 4:
                _fail("manifest ended before selected record")
            length = int.from_bytes(prefix, "big")
            body = handle.read(length)
            digest = handle.read(32)
            if len(body) != length or len(digest) != 32 or sha256(body).digest() != digest:
                _fail("selected manifest record is corrupt")
            if current == index:
                return digest.hex()
    raise AssertionError("unreachable")


def replay_failed_generation_prefix(selection: dict[str, object]) -> dict[str, object]:
    if set(selection) != {
        "schema",
        "usage",
        "generation_directory",
        "through_segment_index",
        "exclusion_reason",
    } or (
        selection.get("schema") != "ReplayPrefixSelectionV1"
        or selection.get("usage") != DEVELOPMENT_USAGE
        or not isinstance(selection.get("exclusion_reason"), str)
        or not str(selection["exclusion_reason"]).strip()
    ):
        _fail("invalid development-only replay prefix selection")
    raw_generation = selection.get("generation_directory")
    through = selection.get("through_segment_index")
    if not isinstance(raw_generation, str) or type(through) is not int or through < 0:
        _fail("invalid generation path or selected segment index")
    generation = Path(raw_generation).resolve(strict=True)
    if not generation.is_dir():
        _fail("generation path is not a directory")
    startup_path = generation / "startup.json"
    startup = _load_object(startup_path, "generation startup")
    if (
        _text(startup, "schema", "startup") != "RawGenerationStartupV1"
        or _text(startup, "implementation", "startup") != "rust-segmented"
        or _text(startup, "spec_revision", "startup") != SPEC_REVISION
        or _text(startup, "credentials", "startup") != "NONE"
        or _text(startup, "order_entry", "startup") != "ABSENT"
    ):
        _fail("generation startup is outside replay scope")
    symbol = _text(startup, "symbol", "startup")
    if symbol not in {"BTCUSDT", "ETHUSDT"}:
        _fail("generation symbol is outside replay scope")
    failed_source = _validate_failed_source(generation, symbol)
    segment_duration_ns = _integer(startup, "segment_duration_s", "startup") * 1_000_000_000
    depth_identity = _transport(generation, "depth", startup)
    trade_identity = _transport(generation, "trade", startup)

    snapshot_path = generation / "snapshot.bnraw"
    snapshots = list(iter_raw_records(snapshot_path))
    if len(snapshots) != 1:
        _fail("replay requires exactly one durable snapshot record")
    snapshot = snapshots[0]
    metadata = _load_object(generation / "snapshot-http.json", "snapshot HTTP metadata")
    snapshot_stream = f"{symbol.lower()}@rest-depth-snapshot"
    if (
        _text(metadata, "schema", "snapshot metadata") != "SnapshotHttpMetadataV1"
        or _integer(metadata, "http_status", "snapshot metadata") != 200
        or metadata.get("body_complete") is not True
        or _text(metadata, "raw_file", "snapshot metadata") != "snapshot.bnraw"
        or _text(metadata, "raw_record_sha256", "snapshot metadata")
        != snapshot.record_sha256
        or snapshot.frame.symbol != symbol
        or snapshot.frame.stream != snapshot_stream
        or snapshot.frame.endpoint != _text(metadata, "endpoint", "snapshot metadata")
        or snapshot.frame.spec_revision != SPEC_REVISION
        or len(snapshot.frame.payload) != _integer(metadata, "body_length", "snapshot metadata")
        or sha256(snapshot.frame.payload).hexdigest()
        != _text(metadata, "body_sha256", "snapshot metadata")
    ):
        _fail("snapshot evidence is not bound to the selected generation")
    snapshot_value = _payload_object(snapshot.frame.payload, "snapshot")
    snapshot_last_update_id = _integer(snapshot_value, "lastUpdateId", "snapshot")

    depth, depth_manifest_sha, depth_record_sha = _replay_depth(
        generation,
        through,
        segment_duration_ns,
        snapshot.frame.payload,
        depth_identity,
    )
    trades, trade_manifest_sha, trade_record_sha = _replay_trades(
        generation, through, segment_duration_ns, trade_identity
    )
    report: dict[str, object] = {
        "schema": "MarketReplayReportV1",
        "usage": DEVELOPMENT_USAGE,
        "qualification_claim": False,
        "exclusion_reason": str(selection["exclusion_reason"]),
        "selected_through_segment_index": through,
        "source": {
            "source_run_id": failed_source["run_id"],
            "source_run_status": "FAILED",
            "source_campaign_id": failed_source["campaign_id"],
            "session_id": _text(startup, "session_id", "startup"),
            "symbol": symbol,
            "spec_revision": SPEC_REVISION,
            "launcher_terminal_sha256": failed_source[
                "launcher_terminal_sha256"
            ],
            "campaign_bindings_sha256": failed_source[
                "campaign_bindings_sha256"
            ],
            "startup_sha256": _sha256_file(startup_path),
            "snapshot_raw_sha256": _sha256_file(snapshot_path),
            "snapshot_record_sha256": snapshot.record_sha256,
            "snapshot_last_update_id": snapshot_last_update_id,
            "depth_manifest_sha256": depth_manifest_sha,
            "depth_selected_manifest_record_sha256": depth_record_sha,
            "trade_manifest_sha256": trade_manifest_sha,
            "trade_selected_manifest_record_sha256": trade_record_sha,
        },
        "depth": depth,
        "trades": trades,
        "cross_stream_total_order_available": False,
        "economic_features": [],
        "report_sha256": "",
    }
    digest_material = json.dumps(
        report, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    report["report_sha256"] = sha256(digest_material).hexdigest()
    return report


__all__ = [
    "DEVELOPMENT_USAGE",
    "MarketReplayCorruption",
    "replay_failed_generation_prefix",
]
