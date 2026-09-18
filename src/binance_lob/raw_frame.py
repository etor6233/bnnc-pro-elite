"""Immutable raw evidence contract before decoding or book mutation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from .clock import ClockSample
from .spec import PublicMarketDataSpec


@dataclass(frozen=True, slots=True)
class RawFrameV1:
    venue: str
    environment: str
    endpoint: str
    stream: str
    symbol: str
    connection_epoch: str
    frame_index: int
    clock: ClockSample
    payload: bytes
    payload_sha256: str
    recorder_state: str
    spec_revision: str

    def __post_init__(self) -> None:
        PublicMarketDataSpec.require_symbol(self.symbol)
        if self.venue != "binance-spot":
            raise ValueError("unexpected venue")
        if self.environment != "production-public-market-data":
            raise ValueError("unexpected environment")
        if self.frame_index < 0:
            raise ValueError("frame_index must be non-negative")
        if not self.connection_epoch:
            raise ValueError("connection_epoch is required")
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be exact bytes")
        if sha256(self.payload).hexdigest() != self.payload_sha256:
            raise ValueError("payload digest mismatch")
        if self.recorder_state not in {"PENDING", "DURABLE", "FAILED"}:
            raise ValueError("invalid recorder_state")

    @classmethod
    def capture(
        cls,
        *,
        endpoint: str,
        stream: str,
        symbol: str,
        connection_epoch: str,
        frame_index: int,
        clock: ClockSample,
        payload: bytes,
        recorder_state: str = "PENDING",
        spec_revision: str = "976cc580553890e92031b77306147c0ed1de5a46",
    ) -> "RawFrameV1":
        return cls(
            venue="binance-spot",
            environment="production-public-market-data",
            endpoint=endpoint,
            stream=stream,
            symbol=PublicMarketDataSpec.require_symbol(symbol),
            connection_epoch=connection_epoch,
            frame_index=frame_index,
            clock=clock,
            payload=payload,
            payload_sha256=sha256(payload).hexdigest(),
            recorder_state=recorder_state,
            spec_revision=spec_revision,
        )

