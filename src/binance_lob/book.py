"""Deterministic Binance Spot L2 snapshot + diff-depth oracle."""

from __future__ import annotations

from bisect import bisect_left, insort
from dataclasses import asdict, dataclass
from enum import StrEnum
from hashlib import sha256
import json
from pathlib import Path

from .fixed_decimal import FixedDecimal
from .raw_log import iter_raw_frames
from .spec import PublicMarketDataSpec
from .state import BookState, transition


class DepthGap(RuntimeError):
    pass


class BookInvariantError(RuntimeError):
    pass


class ApplyOutcome(StrEnum):
    APPLIED = "APPLIED"
    OLD = "OLD"


@dataclass(frozen=True, slots=True)
class BookReplayResult:
    symbol: str
    state: str
    snapshot_last_update_id: int
    final_update_id: int
    depth_records: int
    applied_records: int
    old_records: int
    first_applied_frame_index: int
    bid_levels: int
    ask_levels: int
    best_bid: str
    best_ask: str
    spread: str
    state_sha256: str


def _strict_object(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("payload is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("payload root must be object")
    return value


def _level(value: object, side: str) -> tuple[FixedDecimal, FixedDecimal]:
    if not (
        isinstance(value, list)
        and len(value) == 2
        and isinstance(value[0], str)
        and isinstance(value[1], str)
    ):
        raise ValueError(f"invalid {side} level")
    price = FixedDecimal.parse(value[0]).canonical()
    quantity = FixedDecimal.parse(value[1]).canonical()
    if price.coefficient <= 0 or quantity.coefficient < 0:
        raise ValueError(f"invalid {side} price/quantity")
    return price, quantity


class LocalOrderBook:
    def __init__(self, symbol: str) -> None:
        self.symbol = PublicMarketDataSpec.require_symbol(symbol)
        self.state = BookState.EMPTY
        self.last_update_id: int | None = None
        self._bids: dict[FixedDecimal, FixedDecimal] = {}
        self._asks: dict[FixedDecimal, FixedDecimal] = {}
        # Ascending price lists maintained incrementally: the digest walk
        # iterates them without the per-frame O(n log n) sort that used to
        # dominate Book.state_digest (measured: 46% of the verifier's wall
        # time).  The canonical output order is unchanged (bids reversed).
        self._bid_prices: list[FixedDecimal] = []
        self._ask_prices: list[FixedDecimal] = []

    @property
    def bid_levels(self) -> int:
        return len(self._bids)

    @property
    def ask_levels(self) -> int:
        return len(self._asks)

    @property
    def best_bid(self) -> FixedDecimal:
        if not self._bids:
            raise BookInvariantError("bid side is empty")
        return max(self._bids)

    @property
    def best_ask(self) -> FixedDecimal:
        if not self._asks:
            raise BookInvariantError("ask side is empty")
        return min(self._asks)

    def top_levels(
        self, side: str, limit: int
    ) -> tuple[tuple[FixedDecimal, FixedDecimal], ...]:
        if limit < 1:
            raise ValueError("limit must be positive")
        if side == "bid":
            prices = sorted(self._bids, reverse=True)[:limit]
            source = self._bids
        elif side == "ask":
            prices = sorted(self._asks)[:limit]
            source = self._asks
        else:
            raise ValueError("side must be bid or ask")
        return tuple((price, source[price]) for price in prices)

    def load_snapshot(self, payload: bytes) -> int:
        if self.state is not BookState.EMPTY:
            raise ValueError("snapshot may only initialize an empty book")
        value = _strict_object(payload)
        update_id = value.get("lastUpdateId")
        bids = value.get("bids")
        asks = value.get("asks")
        if not isinstance(update_id, int) or update_id < 0:
            raise ValueError("invalid snapshot update id")
        if not isinstance(bids, list) or not isinstance(asks, list):
            raise ValueError("invalid snapshot sides")
        self._bids = self._load_side(bids, "bid")
        self._asks = self._load_side(asks, "ask")
        self._bid_prices = sorted(self._bids)
        self._ask_prices = sorted(self._asks)
        self.last_update_id = update_id
        self.state = transition(self.state, BookState.SYNCING)
        self._check_invariants()
        return update_id

    @staticmethod
    def _load_side(levels: list[object], side: str) -> dict[FixedDecimal, FixedDecimal]:
        result: dict[FixedDecimal, FixedDecimal] = {}
        for raw_level in levels:
            price, quantity = _level(raw_level, side)
            if quantity.coefficient == 0:
                continue
            if price in result:
                raise ValueError(f"duplicate {side} price in snapshot")
            result[price] = quantity
        if not result:
            raise BookInvariantError(f"{side} snapshot side is empty")
        return result

    def apply_depth(self, payload: bytes) -> ApplyOutcome:
        if self.state not in {BookState.SYNCING, BookState.LIVE}:
            raise ValueError(f"cannot apply depth while {self.state}")
        if self.last_update_id is None:
            raise ValueError("snapshot not loaded")
        value = _strict_object(payload)
        if value.get("e") != "depthUpdate" or value.get("s") != self.symbol:
            raise ValueError("unexpected event type or symbol")
        first_id = value.get("U")
        final_id = value.get("u")
        bids = value.get("b")
        asks = value.get("a")
        if not isinstance(first_id, int) or not isinstance(final_id, int) or first_id > final_id:
            raise ValueError("invalid depth update IDs")
        if not isinstance(bids, list) or not isinstance(asks, list):
            raise ValueError("invalid depth sides")
        if final_id < self.last_update_id + 1:
            return ApplyOutcome.OLD
        expected = self.last_update_id + 1
        if first_id > expected or final_id < expected:
            self.state = transition(self.state, BookState.GAP)
            raise DepthGap(
                f"depth gap: expected bridge for {expected}, received U={first_id}, u={final_id}"
            )
        bid_updates = [_level(level, "bid") for level in bids]
        ask_updates = [_level(level, "ask") for level in asks]
        self._apply_side(self._bids, self._bid_prices, bid_updates)
        self._apply_side(self._asks, self._ask_prices, ask_updates)
        self.last_update_id = final_id
        if self.state is BookState.SYNCING:
            self.state = transition(self.state, BookState.LIVE)
        self._check_invariants()
        return ApplyOutcome.APPLIED

    @staticmethod
    def _apply_side(
        side: dict[FixedDecimal, FixedDecimal],
        prices: list[FixedDecimal],
        updates: list[tuple[FixedDecimal, FixedDecimal]],
    ) -> None:
        for price, quantity in updates:
            if quantity.coefficient == 0:
                if side.pop(price, None) is not None:
                    index = bisect_left(prices, price)
                    if index < len(prices) and prices[index] == price:
                        prices.pop(index)
            else:
                if price not in side:
                    side[price] = quantity
                    insort(prices, price)
                else:
                    side[price] = quantity

    def _check_invariants(self) -> None:
        try:
            best_bid = self.best_bid
            best_ask = self.best_ask
            if not best_bid < best_ask:
                raise BookInvariantError(f"crossed/locked book: bid={best_bid}, ask={best_ask}")
        except BookInvariantError:
            if self.state in {BookState.SYNCING, BookState.LIVE, BookState.RESYNCING}:
                self.state = transition(self.state, BookState.INVALID)
            raise

    def state_digest(self) -> str:
        # Streaming SHA-256 over the EXACT canonical bytes produced by the
        # legacy implementation:
        #   json.dumps({"symbol","last_update_id","bids","asks"},
        #              sort_keys=True, separators=(",", ":"))
        # Byte-identical by construction (property-tested against the legacy
        # serializer): symbols are ASCII, canonical price/quantity strings
        # contain only digits, '.' and '-', so no JSON escaping occurs.
        # Iterating the incrementally maintained price lists removes the
        # per-frame O(n log n) sorts; FixedDecimal.__str__ is memoized.
        digest = sha256()
        digest.update(b'{"asks":[')
        first = True
        for price in self._ask_prices:
            if not first:
                digest.update(b",")
            first = False
            digest.update(b'["')
            digest.update(str(price).encode("utf-8"))
            digest.update(b'","')
            digest.update(str(self._asks[price]).encode("utf-8"))
            digest.update(b'"]')
        digest.update(b'],"bids":[')
        first = True
        for price in reversed(self._bid_prices):
            if not first:
                digest.update(b",")
            first = False
            digest.update(b'["')
            digest.update(str(price).encode("utf-8"))
            digest.update(b'","')
            digest.update(str(self._bids[price]).encode("utf-8"))
            digest.update(b'"]')
        digest.update(b'],"last_update_id":')
        digest.update(str(self.last_update_id).encode("utf-8"))
        digest.update(b',"symbol":"')
        digest.update(self.symbol.encode("utf-8"))
        digest.update(b'"}')
        return digest.hexdigest()


def replay_session(session_dir: Path) -> BookReplayResult:
    session_dir = Path(session_dir)
    snapshots = list(iter_raw_frames(session_dir / "snapshot.bnraw"))
    if len(snapshots) != 1:
        raise ValueError("session must contain exactly one snapshot")
    snapshot_value = _strict_object(snapshots[0].payload)
    snapshot_id = snapshot_value.get("lastUpdateId")
    if not isinstance(snapshot_id, int):
        raise ValueError("snapshot id missing")
    book = LocalOrderBook(snapshots[0].symbol)
    book.load_snapshot(snapshots[0].payload)
    depth_frames = list(iter_raw_frames(session_dir / "depth.bnraw"))
    applied = 0
    old = 0
    first_applied = -1
    for frame in depth_frames:
        outcome = book.apply_depth(frame.payload)
        if outcome is ApplyOutcome.OLD:
            old += 1
        else:
            if first_applied < 0:
                first_applied = frame.frame_index
            applied += 1
    if book.state is not BookState.LIVE or first_applied < 0 or book.last_update_id is None:
        raise ValueError("capture did not produce a LIVE book")
    best_bid = book.best_bid
    best_ask = book.best_ask
    scale = max(best_bid.scale, best_ask.scale)
    spread = FixedDecimal(
        best_ask.rescale_exact(scale).coefficient - best_bid.rescale_exact(scale).coefficient,
        scale,
    ).canonical()
    return BookReplayResult(
        symbol=book.symbol,
        state=book.state.value,
        snapshot_last_update_id=snapshot_id,
        final_update_id=book.last_update_id,
        depth_records=len(depth_frames),
        applied_records=applied,
        old_records=old,
        first_applied_frame_index=first_applied,
        bid_levels=book.bid_levels,
        ask_levels=book.ask_levels,
        best_bid=str(best_bid),
        best_ask=str(best_ask),
        spread=str(spread),
        state_sha256=book.state_digest(),
    )


def replay_result_dict(result: BookReplayResult) -> dict[str, object]:
    return asdict(result)
