"""Public REST snapshot retrieval with strict size and shape checks."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Callable
from urllib.request import Request, urlopen

from .spec import PublicMarketDataSpec


MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SnapshotPayload:
    endpoint: str
    status: int
    payload: bytes
    last_update_id: int
    bid_levels: int
    ask_levels: int


def validate_snapshot_payload(payload: bytes) -> tuple[int, int, int]:
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise ValueError("snapshot exceeds maximum size")
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("snapshot is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("snapshot root must be an object")
    last_update_id = value.get("lastUpdateId")
    bids = value.get("bids")
    asks = value.get("asks")
    if not isinstance(last_update_id, int) or last_update_id < 0:
        raise ValueError("snapshot lastUpdateId is invalid")
    if not isinstance(bids, list) or not isinstance(asks, list):
        raise ValueError("snapshot sides must be arrays")
    for side_name, levels in (("bids", bids), ("asks", asks)):
        for level in levels:
            if not (
                isinstance(level, list)
                and len(level) == 2
                and all(isinstance(item, str) for item in level)
            ):
                raise ValueError(f"invalid {side_name} level")
    return last_update_id, len(bids), len(asks)


def fetch_snapshot(
    spec: PublicMarketDataSpec,
    symbol: str,
    *,
    limit: int = 5000,
    timeout_s: float = 15.0,
    opener: Callable[..., object] = urlopen,
) -> SnapshotPayload:
    endpoint = spec.snapshot_uri(symbol, limit=limit)
    request = Request(endpoint, headers={"User-Agent": "binance-lob-oracle/0.1"})
    with opener(request, timeout=timeout_s) as response:  # type: ignore[attr-defined]
        status = int(response.status)
        if status != 200:
            raise ValueError(f"snapshot HTTP status {status}")
        payload = response.read(MAX_SNAPSHOT_BYTES + 1)
    last_update_id, bids, asks = validate_snapshot_payload(payload)
    return SnapshotPayload(endpoint, status, payload, last_update_id, bids, asks)

