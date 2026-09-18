"""Neutral integrity/lineage audit for a captured Binance Spot dataset."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from .book import replay_result_dict, replay_session
from .raw_log import iter_raw_frames


SCHEMA = "DatasetAuditV2"


def _canonical_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _trade_identity(frames: list[object], symbol: str) -> dict[str, object]:
    first_id: int | None = None
    previous_id: int | None = None
    id_jumps_without_loss_claim = 0
    duplicate_ids = 0
    out_of_order_ids = 0
    for frame in frames:
        value = json.loads(frame.payload)
        if not isinstance(value, dict) or value.get("e") != "trade":
            raise ValueError("unexpected trade event")
        if frame.symbol != symbol or value.get("s") != symbol:
            raise ValueError("unexpected trade symbol")
        trade_id = value.get("t")
        if not isinstance(trade_id, int) or trade_id < 0:
            raise ValueError("invalid trade ID")
        if first_id is None:
            first_id = trade_id
        if previous_id is not None:
            if trade_id == previous_id:
                duplicate_ids += 1
            elif trade_id < previous_id:
                out_of_order_ids += 1
            elif trade_id - previous_id > 1:
                id_jumps_without_loss_claim += 1
        previous_id = trade_id
    if first_id is None:
        raise ValueError("trade log is empty")
    return {
        "records": len(frames),
        "first_trade_id": first_id,
        "last_trade_id": previous_id,
        "id_jumps_without_loss_claim": id_jumps_without_loss_claim,
        "duplicate_trade_ids": duplicate_ids,
        "out_of_order_trade_ids": out_of_order_ids,
        "official_id_contiguity_claim": "NONE",
    }


def audit_session(session_dir: Path) -> dict[str, object]:
    session_dir = Path(session_dir)
    snapshot_frames = list(iter_raw_frames(session_dir / "snapshot.bnraw"))
    depth_frames = list(iter_raw_frames(session_dir / "depth.bnraw"))
    trade_frames = list(iter_raw_frames(session_dir / "trade.bnraw"))
    if len(snapshot_frames) != 1:
        raise ValueError("session must contain exactly one snapshot")
    symbol = snapshot_frames[0].symbol
    replay = replay_result_dict(replay_session(session_dir))
    trades = _trade_identity(trade_frames, symbol)
    clocks = [
        snapshot_frames[0].clock,
        *(frame.clock for frame in depth_frames),
        *(frame.clock for frame in trade_frames),
    ]
    trade_ids_strictly_increasing = (
        trades["duplicate_trade_ids"] == 0
        and trades["out_of_order_trade_ids"] == 0
    )
    validity = ["RAW_INTEGRITY", "BOOK_LIVE"]
    if trade_ids_strictly_increasing:
        validity.append("TRADE_IDS_STRICTLY_INCREASING_NO_CONSECUTIVITY_CLAIM")
    report: dict[str, object] = {
        "schema": SCHEMA,
        "symbol": symbol,
        "dataset_policy": "RAW_IMMUTABLE_DERIVATIONS_SEPARATE",
        "lineage": {
            "snapshot_connection_epoch": snapshot_frames[0].connection_epoch,
            "depth_connection_epochs": sorted(
                {frame.connection_epoch for frame in depth_frames}
            ),
            "trade_connection_epochs": sorted(
                {frame.connection_epoch for frame in trade_frames}
            ),
            "cross_stream_total_order_available": False,
        },
        "clock": {
            "qualities": sorted({clock.quality.value for clock in clocks}),
            "sources": sorted({clock.source for clock in clocks}),
            "event_age_available": all(clock.permits_one_way_claim for clock in clocks),
        },
        "health": {
            "raw_integrity": "PASS",
            "book_state": replay["state"],
            "snapshot_last_update_id": replay["snapshot_last_update_id"],
            "final_update_id": replay["final_update_id"],
            "depth_records": replay["depth_records"],
            "applied_depth_records": replay["applied_records"],
            "old_depth_records": replay["old_records"],
            "first_applied_frame_index": replay["first_applied_frame_index"],
            "trade_ids_strictly_increasing": trade_ids_strictly_increasing,
            "validity": validity,
        },
        "book": {
            "bid_levels": replay["bid_levels"],
            "ask_levels": replay["ask_levels"],
            "best_bid": replay["best_bid"],
            "best_ask": replay["best_ask"],
            "spread": replay["spread"],
            "state_sha256": replay["state_sha256"],
        },
        "trades": trades,
        "excluded_from_audit": [
            "IMBALANCE",
            "MICROPRICE",
            "AGGRESSOR_AGGREGATES",
            "SIGNALS",
            "FILL_OR_PROFITABILITY_CLAIMS",
        ],
    }
    report["audit_sha256"] = sha256(_canonical_bytes(report)).hexdigest()
    return report
