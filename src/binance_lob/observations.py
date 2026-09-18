"""Neutral, replay-derived observations with exact BNRAW lineage."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path

from .book import ApplyOutcome, LocalOrderBook
from .boundary import CanonicalObservationV1
from .fixed_decimal import FixedDecimal
from .raw_log import RawRecordEnvelopeV1, iter_raw_records, scan_raw_log
from .spec import PublicMarketDataSpec


class ObservationMaterializationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ObservationMaterializationV1:
    schema: str
    symbol: str
    stream_kind: str
    stream: str
    connection_epoch: str
    raw_path: str
    raw_last_record_sha256: str
    snapshot_path: str | None
    snapshot_record_sha256: str | None
    snapshot_last_update_id: int | None
    raw_records: int
    skipped_initial_old_records: int
    observations: tuple[CanonicalObservationV1, ...]
    first_sequence: int
    final_sequence: int
    materialization_sha256: str


def _strict_object(payload: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ObservationMaterializationError(f"{label} payload is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ObservationMaterializationError(f"{label} payload root must be object")
    return value


def _exact_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ObservationMaterializationError(f"invalid non-negative integer field {field}")
    return value


def _exact_bool(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise ObservationMaterializationError(f"invalid boolean field {field}")
    return value


def _canonical_digest(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _identity(records: list[RawRecordEnvelopeV1]) -> tuple[str, str, str]:
    if not records:
        raise ObservationMaterializationError("raw source has no records")
    first = records[0].frame
    identity = (first.symbol, first.stream, first.connection_epoch)
    for record in records:
        frame = record.frame
        if (frame.symbol, frame.stream, frame.connection_epoch) != identity:
            raise ObservationMaterializationError("raw source mixes symbol/stream/epoch identity")
    return identity


def _depth_ids(payload: bytes) -> tuple[int, int]:
    value = _strict_object(payload, "depth")
    if value.get("e") != "depthUpdate":
        raise ObservationMaterializationError("unexpected depth event type")
    return _exact_int(value.get("U"), "U"), _exact_int(value.get("u"), "u")


def _trade_observation_digest(payload: bytes, symbol: str) -> tuple[int, str]:
    value = _strict_object(payload, "trade")
    if value.get("e") != "trade" or value.get("s") != symbol:
        raise ObservationMaterializationError("unexpected trade event type or symbol")
    trade_id = _exact_int(value.get("t"), "t")
    # E is validated and retained in raw evidence, but it is a stream dispatch
    # timestamp and was observed to differ for the same trade ID across two
    # simultaneous public connections. It cannot define logical trade identity.
    _exact_int(value.get("E"), "E")
    trade_time = _exact_int(value.get("T"), "T")
    price_value = value.get("p")
    quantity_value = value.get("q")
    if not isinstance(price_value, str) or not isinstance(quantity_value, str):
        raise ObservationMaterializationError("trade price/quantity must be strings")
    try:
        price = FixedDecimal.parse(price_value).canonical()
        quantity = FixedDecimal.parse(quantity_value).canonical()
    except ValueError as exc:
        raise ObservationMaterializationError(f"invalid trade decimal: {exc}") from exc
    if price.coefficient <= 0 or quantity.coefficient <= 0:
        raise ObservationMaterializationError("trade price/quantity must be positive")
    material = {
        "best_match": _exact_bool(value.get("M"), "M"),
        "buyer_is_maker": _exact_bool(value.get("m"), "m"),
        "price": str(price),
        "quantity": str(quantity),
        "schema": "CanonicalTradeEventV1",
        "symbol": symbol,
        "trade_id": trade_id,
        "trade_time": trade_time,
    }
    return trade_id, _canonical_digest(material)


def _finalize(
    *,
    raw_path: Path,
    stream_kind: str,
    records: list[RawRecordEnvelopeV1],
    observations: list[CanonicalObservationV1],
    skipped_initial_old_records: int,
    snapshot_path: Path | None = None,
    snapshot_record: RawRecordEnvelopeV1 | None = None,
    snapshot_last_update_id: int | None = None,
) -> ObservationMaterializationV1:
    if not observations:
        raise ObservationMaterializationError("materialization produced no observations")
    symbol, stream, epoch = _identity(records)
    raw_scan = scan_raw_log(raw_path)
    digest_material = {
        "observations": [asdict(item) for item in observations],
        "raw_last_record_sha256": raw_scan.last_record_sha256,
        "schema": "ObservationMaterializationDigestV1",
        "skipped_initial_old_records": skipped_initial_old_records,
        "snapshot_record_sha256": (
            None if snapshot_record is None else snapshot_record.record_sha256
        ),
        "snapshot_last_update_id": snapshot_last_update_id,
        "stream_kind": stream_kind,
    }
    return ObservationMaterializationV1(
        schema="ObservationMaterializationV1",
        symbol=symbol,
        stream_kind=stream_kind,
        stream=stream,
        connection_epoch=epoch,
        raw_path=str(raw_path),
        raw_last_record_sha256=raw_scan.last_record_sha256,
        snapshot_path=None if snapshot_path is None else str(snapshot_path),
        snapshot_record_sha256=(
            None if snapshot_record is None else snapshot_record.record_sha256
        ),
        snapshot_last_update_id=snapshot_last_update_id,
        raw_records=len(records),
        skipped_initial_old_records=skipped_initial_old_records,
        observations=tuple(observations),
        first_sequence=observations[0].first_sequence,
        final_sequence=observations[-1].final_sequence,
        materialization_sha256=_canonical_digest(digest_material),
    )


def materialize_depth_observations(
    snapshot_path: Path, depth_path: Path
) -> ObservationMaterializationV1:
    snapshot_path = Path(snapshot_path)
    depth_path = Path(depth_path)
    snapshots = list(iter_raw_records(snapshot_path))
    if len(snapshots) != 1:
        raise ObservationMaterializationError("depth materialization requires one snapshot")
    records = list(iter_raw_records(depth_path))
    symbol, stream, epoch = _identity(records)
    if "@depth" not in stream:
        raise ObservationMaterializationError("depth source stream is not a depth stream")
    snapshot = snapshots[0]
    if snapshot.frame.symbol != symbol:
        raise ObservationMaterializationError("snapshot/depth symbol mismatch")
    book = LocalOrderBook(symbol)
    snapshot_last_update_id = book.load_snapshot(snapshot.frame.payload)
    observations: list[CanonicalObservationV1] = []
    skipped = 0
    for record in records:
        first_id, final_id = _depth_ids(record.frame.payload)
        outcome = book.apply_depth(record.frame.payload)
        if outcome is ApplyOutcome.OLD:
            if observations:
                raise ObservationMaterializationError(
                    "stale depth record appeared after canonical LIVE observations"
                )
            skipped += 1
            continue
        observations.append(
            CanonicalObservationV1(
                symbol=symbol,
                stream_kind="DEPTH",
                stream=stream,
                connection_epoch=epoch,
                frame_index=record.frame.frame_index,
                first_sequence=first_id,
                final_sequence=final_id,
                record_sha256=record.record_sha256,
                observation_sha256=book.state_digest(),
            )
        )
    return _finalize(
        raw_path=depth_path,
        stream_kind="DEPTH",
        records=records,
        observations=observations,
        skipped_initial_old_records=skipped,
        snapshot_path=snapshot_path,
        snapshot_record=snapshot,
        snapshot_last_update_id=snapshot_last_update_id,
    )


def materialize_trade_observations(trade_path: Path) -> ObservationMaterializationV1:
    trade_path = Path(trade_path)
    records = list(iter_raw_records(trade_path))
    symbol, stream, epoch = _identity(records)
    PublicMarketDataSpec.require_symbol(symbol)
    if not stream.endswith("@trade"):
        raise ObservationMaterializationError("trade source stream is not an individual trade stream")
    observations: list[CanonicalObservationV1] = []
    previous_trade_id: int | None = None
    for record in records:
        trade_id, event_digest = _trade_observation_digest(record.frame.payload, symbol)
        if previous_trade_id is not None and trade_id <= previous_trade_id:
            raise ObservationMaterializationError(
                f"trade ID duplicated or regressed: previous {previous_trade_id}, got {trade_id}"
            )
        observations.append(
            CanonicalObservationV1(
                symbol=symbol,
                stream_kind="TRADE",
                stream=stream,
                connection_epoch=epoch,
                frame_index=record.frame.frame_index,
                first_sequence=trade_id,
                final_sequence=trade_id,
                record_sha256=record.record_sha256,
                observation_sha256=event_digest,
            )
        )
        previous_trade_id = trade_id
    return _finalize(
        raw_path=trade_path,
        stream_kind="TRADE",
        records=records,
        observations=observations,
        skipped_initial_old_records=0,
    )


def materialization_dict(result: ObservationMaterializationV1) -> dict[str, object]:
    return asdict(result)
