"""Separate wall and monotonic clock domains and carry quality explicitly."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import time


class ClockQuality(StrEnum):
    UNKNOWN = "UNKNOWN"
    UNSYNCHRONIZED = "UNSYNCHRONIZED"
    SYNCHRONIZED = "SYNCHRONIZED"
    DEGRADED = "DEGRADED"
    # Windows w32time reports a synchronized host clock, but the capture does
    # not claim a bounded one-way network delay. Keep that distinction explicit
    # instead of misclassifying it as generic SYNCHRONIZED.
    HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND = (
        "HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND"
    )


@dataclass(frozen=True, slots=True)
class ClockSample:
    wall_ns: int
    mono_ns: int
    quality: ClockQuality
    source: str
    offset_ns: int | None = None
    uncertainty_ns: int | None = None

    @property
    def permits_one_way_claim(self) -> bool:
        return (
            self.quality is ClockQuality.SYNCHRONIZED
            and self.offset_ns is not None
            and self.uncertainty_ns is not None
            and self.uncertainty_ns >= 0
        )


def sample_clock(
    *,
    quality: ClockQuality = ClockQuality.UNKNOWN,
    source: str = "unverified-local-clock",
    offset_ns: int | None = None,
    uncertainty_ns: int | None = None,
) -> ClockSample:
    return ClockSample(
        wall_ns=time.time_ns(),
        mono_ns=time.perf_counter_ns(),
        quality=quality,
        source=source,
        offset_ns=offset_ns,
        uncertainty_ns=uncertainty_ns,
    )
