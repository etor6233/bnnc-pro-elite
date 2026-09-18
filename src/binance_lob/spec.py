"""Pinned, fail-closed public Binance Spot surface for phase 1/2."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PublicMarketDataSpec:
    spec_revision: str = "976cc580553890e92031b77306147c0ed1de5a46"
    websocket_base: str = "wss://data-stream.binance.vision:443"
    rest_base: str = "https://data-api.binance.vision"

    ALLOWED_SYMBOLS = frozenset({"BTCUSDT", "ETHUSDT"})

    @classmethod
    def require_symbol(cls, symbol: str) -> str:
        normalized = symbol.upper()
        if normalized not in cls.ALLOWED_SYMBOLS:
            raise ValueError(f"symbol outside fixed scope: {symbol!r}")
        return normalized

    def websocket_uri(self, symbol: str, stream: str) -> str:
        normalized = self.require_symbol(symbol).lower()
        stream_names = {
            "depth": f"{normalized}@depth@100ms",
            "trade": f"{normalized}@trade",
            "bookTicker": f"{normalized}@bookTicker",
        }
        try:
            stream_name = stream_names[stream]
        except KeyError as exc:
            raise ValueError(f"stream outside fixed scope: {stream!r}") from exc
        return f"{self.websocket_base}/ws/{stream_name}?timeUnit=MICROSECOND"

    def snapshot_uri(self, symbol: str, *, limit: int = 5000) -> str:
        normalized = self.require_symbol(symbol)
        if limit not in {5, 10, 20, 50, 100, 500, 1000, 5000}:
            raise ValueError("snapshot limit is not in the approved Binance set")
        return f"{self.rest_base}/api/v3/depth?symbol={normalized}&limit={limit}"

