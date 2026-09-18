"""Deterministic health and microstructure report over verified BNRAW sessions.

Depth and trade streams keep independent lineage.  This module does not infer a
total event order, queue position, hidden liquidity, fills, or profitability.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from .book import ApplyOutcome, LocalOrderBook
from .clock import ClockQuality
from .fixed_decimal import FixedDecimal
from .raw_log import iter_raw_frames
from .state import BookState


REPORT_SCHEMA = "MicrostructureReportV2"
PPM_SCALE = 1_000_000


def _canonical_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sum_decimals(values: list[FixedDecimal]) -> FixedDecimal:
    total = FixedDecimal(0, 0)
    for value in values:
        total = total.add(value)
    return total


def _ratio_ppm(numerator: FixedDecimal, denominator: FixedDecimal) -> int:
    if denominator.coefficient <= 0:
        raise ValueError("ratio denominator must be positive")
    scale = max(numerator.scale, denominator.scale)
    num = numerator.rescale_exact(scale).coefficient * PPM_SCALE
    den = denominator.rescale_exact(scale).coefficient
    # Explicit truncation toward zero, identical to signed integer division in Rust.
    return (1 if num >= 0 else -1) * (abs(num) // den)


def _imbalance_ppm(left: FixedDecimal, right: FixedDecimal) -> int:
    return _ratio_ppm(left.subtract(right), left.add(right))


def _trade_report(
    path: Path, expected_symbol: str
) -> tuple[dict[str, object], list[object], list[str]]:
    frames = list(iter_raw_frames(path))
    if not frames:
        raise ValueError("trade log is empty")
    first_id: int | None = None
    previous_id: int | None = None
    id_jumps_without_loss_claim = 0
    duplicate_ids = 0
    out_of_order_ids = 0
    buyer_count = 0
    seller_count = 0
    buyer_quantities: list[FixedDecimal] = []
    seller_quantities: list[FixedDecimal] = []
    clock_samples = []
    for frame in frames:
        value = json.loads(frame.payload)
        if not isinstance(value, dict) or value.get("e") != "trade":
            raise ValueError("unexpected trade event")
        if value.get("s") != expected_symbol or frame.symbol != expected_symbol:
            raise ValueError("unexpected trade symbol")
        trade_id = value.get("t")
        quantity_text = value.get("q")
        buyer_is_maker = value.get("m")
        if (
            not isinstance(trade_id, int)
            or trade_id < 0
            or not isinstance(quantity_text, str)
            or not isinstance(buyer_is_maker, bool)
        ):
            raise ValueError("invalid trade fields")
        quantity = FixedDecimal.parse(quantity_text).canonical()
        if quantity.coefficient <= 0:
            raise ValueError("trade quantity must be positive")
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
        # Binance field m=true means buyer is maker, hence seller is aggressor.
        if buyer_is_maker:
            seller_count += 1
            seller_quantities.append(quantity)
        else:
            buyer_count += 1
            buyer_quantities.append(quantity)
        clock_samples.append(frame.clock)
    buyer_qty = _sum_decimals(buyer_quantities)
    seller_qty = _sum_decimals(seller_quantities)
    report: dict[str, object] = {
        "records": len(frames),
        "first_trade_id": first_id,
        "last_trade_id": previous_id,
        "id_jumps_without_loss_claim": id_jumps_without_loss_claim,
        "duplicate_trade_ids": duplicate_ids,
        "out_of_order_trade_ids": out_of_order_ids,
        "official_id_contiguity_claim": "NONE",
        "buyer_aggressor_count": buyer_count,
        "seller_aggressor_count": seller_count,
        "buyer_aggressor_base_qty": str(buyer_qty),
        "seller_aggressor_base_qty": str(seller_qty),
        "aggressor_qty_imbalance_ppm": _imbalance_ppm(buyer_qty, seller_qty),
    }
    epochs = sorted({frame.connection_epoch for frame in frames})
    return report, clock_samples, epochs


def monitor_session(session_dir: Path) -> dict[str, object]:
    session_dir = Path(session_dir)
    snapshots = list(iter_raw_frames(session_dir / "snapshot.bnraw"))
    if len(snapshots) != 1:
        raise ValueError("session must contain exactly one snapshot")
    symbol = snapshots[0].symbol
    book = LocalOrderBook(symbol)
    snapshot_id = book.load_snapshot(snapshots[0].payload)
    depth_frames = list(iter_raw_frames(session_dir / "depth.bnraw"))
    applied = 0
    old = 0
    first_applied = -1
    for frame in depth_frames:
        if frame.symbol != symbol:
            raise ValueError("unexpected depth symbol")
        outcome = book.apply_depth(frame.payload)
        if outcome is ApplyOutcome.OLD:
            old += 1
        else:
            if first_applied < 0:
                first_applied = frame.frame_index
            applied += 1
    if book.state is not BookState.LIVE or book.last_update_id is None or first_applied < 0:
        raise ValueError("capture did not produce a LIVE book")

    bid_20 = book.top_levels("bid", 20)
    ask_20 = book.top_levels("ask", 20)
    if len(bid_20) < 20 or len(ask_20) < 20:
        raise ValueError("book has fewer than 20 levels on one side")
    best_bid, top_bid_qty = bid_20[0]
    best_ask, top_ask_qty = ask_20[0]
    bid_5_qty = _sum_decimals([quantity for _, quantity in bid_20[:5]])
    ask_5_qty = _sum_decimals([quantity for _, quantity in ask_20[:5]])
    bid_20_qty = _sum_decimals([quantity for _, quantity in bid_20])
    ask_20_qty = _sum_decimals([quantity for _, quantity in ask_20])
    trades, trade_clocks, trade_epochs = _trade_report(session_dir / "trade.bnraw", symbol)
    clocks = [snapshots[0].clock, *(frame.clock for frame in depth_frames), *trade_clocks]
    qualities = sorted({clock.quality.value for clock in clocks})
    sources = sorted({clock.source for clock in clocks})
    permits_event_age = all(clock.permits_one_way_claim for clock in clocks)
    trade_ids_strictly_increasing = (
        trades["duplicate_trade_ids"] == 0
        and trades["out_of_order_trade_ids"] == 0
    )
    validity = ["RAW_INTEGRITY", "BOOK_LIVE"]
    if trade_ids_strictly_increasing:
        validity.append("TRADE_IDS_STRICTLY_INCREASING_NO_CONSECUTIVITY_CLAIM")
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "symbol": symbol,
        "lineage_policy": "DEPTH_AND_TRADE_INDEPENDENT_NO_TOTAL_ORDER",
        "lineage": {
            "snapshot_connection_epoch": snapshots[0].connection_epoch,
            "depth_connection_epochs": sorted(
                {frame.connection_epoch for frame in depth_frames}
            ),
            "trade_connection_epochs": trade_epochs,
        },
        "clock": {
            "qualities": qualities,
            "sources": sources,
            "event_age_available": permits_event_age,
        },
        "health": {
            "raw_integrity": "PASS",
            "book_state": book.state.value,
            "snapshot_last_update_id": snapshot_id,
            "final_update_id": book.last_update_id,
            "depth_records": len(depth_frames),
            "applied_depth_records": applied,
            "old_depth_records": old,
            "first_applied_frame_index": first_applied,
            "trade_ids_strictly_increasing": trade_ids_strictly_increasing,
            "validity": validity,
        },
        "book": {
            "bid_levels": book.bid_levels,
            "ask_levels": book.ask_levels,
            "best_bid": str(best_bid),
            "best_ask": str(best_ask),
            "spread": str(best_ask.subtract(best_bid)),
            "top_bid_base_qty": str(top_bid_qty),
            "top_ask_base_qty": str(top_ask_qty),
            "top_imbalance_ppm": _imbalance_ppm(top_bid_qty, top_ask_qty),
            "microprice_position_ppm": _ratio_ppm(top_bid_qty, top_bid_qty.add(top_ask_qty)),
            "bid_5_base_qty": str(bid_5_qty),
            "ask_5_base_qty": str(ask_5_qty),
            "depth_5_imbalance_ppm": _imbalance_ppm(bid_5_qty, ask_5_qty),
            "bid_20_base_qty": str(bid_20_qty),
            "ask_20_base_qty": str(ask_20_qty),
            "depth_20_imbalance_ppm": _imbalance_ppm(bid_20_qty, ask_20_qty),
            "state_sha256": book.state_digest(),
        },
        "trades": trades,
        "limitations": [
            "NO_DEPTH_TRADE_TOTAL_ORDER",
            "NO_L3_QUEUE_POSITION",
            "NO_HIDDEN_LIQUIDITY_INFERENCE",
            "NO_FILL_OR_PROFITABILITY_CLAIM",
        ],
    }
    report["report_sha256"] = sha256(_canonical_bytes(report)).hexdigest()
    return report
