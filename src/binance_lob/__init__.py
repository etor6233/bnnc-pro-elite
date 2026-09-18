"""Offline correctness oracle for Binance Spot BTCUSDT/ETHUSDT.

Compatibility exports are resolved lazily so importing the isolated raw
campaign verifier cannot accidentally load capture, networking, feature, or
legacy materialization modules.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any


_EXPORTS: dict[str, tuple[str, str]] = {
    "ClockQuality": (".clock", "ClockQuality"),
    "ClockSample": (".clock", "ClockSample"),
    "sample_clock": (".clock", "sample_clock"),
    "BookInvariantError": (".book", "BookInvariantError"),
    "DepthGap": (".book", "DepthGap"),
    "LocalOrderBook": (".book", "LocalOrderBook"),
    "replay_session": (".book", "replay_session"),
    "BoundaryDurabilityV1": (".boundary", "BoundaryDurabilityV1"),
    "BoundaryJournalAckV1": (".boundary", "BoundaryJournalAckV1"),
    "BoundaryJournalError": (".boundary", "BoundaryJournalError"),
    "BoundaryJournalScanV1": (".boundary", "BoundaryJournalScanV1"),
    "BoundaryJournalWriter": (".boundary", "BoundaryJournalWriter"),
    "CanonicalObservationV1": (".boundary", "CanonicalObservationV1"),
    "CanonicalSelectionV1": (".boundary", "CanonicalSelectionV1"),
    "HandoverBoundaryV1": (".boundary", "HandoverBoundaryV1"),
    "RawPositionV1": (".boundary", "RawPositionV1"),
    "SelectedObservationV1": (".boundary", "SelectedObservationV1"),
    "select_canonical": (".boundary", "select_canonical"),
    "scan_boundary_journal": (".boundary", "scan_boundary_journal"),
    "FixedDecimal": (".fixed_decimal", "FixedDecimal"),
    "ObservationMaterializationError": (
        ".observations",
        "ObservationMaterializationError",
    ),
    "ObservationMaterializationV1": (
        ".observations",
        "ObservationMaterializationV1",
    ),
    "materialize_depth_observations": (
        ".observations",
        "materialize_depth_observations",
    ),
    "materialize_trade_observations": (
        ".observations",
        "materialize_trade_observations",
    ),
    "RawFrameV1": (".raw_frame", "RawFrameV1"),
    "AppendReceiptV1": (".raw_log", "AppendReceiptV1"),
    "DurabilityAckV1": (".raw_log", "DurabilityAckV1"),
    "RawLogCorruption": (".raw_log", "RawLogCorruption"),
    "RawLogScan": (".raw_log", "RawLogScan"),
    "RawLogWriter": (".raw_log", "RawLogWriter"),
    "RawRecordEnvelopeV1": (".raw_log", "RawRecordEnvelopeV1"),
    "RawRecoveryV1": (".raw_log", "RawRecoveryV1"),
    "StreamDurabilityWatermarkV1": (
        ".raw_log",
        "StreamDurabilityWatermarkV1",
    ),
    "recover_raw_log_prefix": (".raw_log", "recover_raw_log_prefix"),
    "iter_raw_records": (".raw_log", "iter_raw_records"),
    "scan_raw_log": (".raw_log", "scan_raw_log"),
    "PublicMarketDataSpec": (".spec", "PublicMarketDataSpec"),
    "BookState": (".state", "BookState"),
    "IllegalTransition": (".state", "IllegalTransition"),
    "transition": (".state", "transition"),
}

__all__ = [
    "BookState",
    "BoundaryDurabilityV1",
    "BoundaryJournalAckV1",
    "BoundaryJournalError",
    "BoundaryJournalScanV1",
    "BoundaryJournalWriter",
    "CanonicalObservationV1",
    "CanonicalSelectionV1",
    "BookInvariantError",
    "ClockQuality",
    "ClockSample",
    "FixedDecimal",
    "DepthGap",
    "IllegalTransition",
    "HandoverBoundaryV1",
    "LocalOrderBook",
    "ObservationMaterializationError",
    "ObservationMaterializationV1",
    "PublicMarketDataSpec",
    "AppendReceiptV1",
    "DurabilityAckV1",
    "RawFrameV1",
    "RawLogCorruption",
    "RawLogScan",
    "RawLogWriter",
    "RawRecordEnvelopeV1",
    "RawRecoveryV1",
    "RawPositionV1",
    "SelectedObservationV1",
    "StreamDurabilityWatermarkV1",
    "recover_raw_log_prefix",
    "iter_raw_records",
    "materialize_depth_observations",
    "materialize_trade_observations",
    "sample_clock",
    "replay_session",
    "scan_raw_log",
    "scan_boundary_journal",
    "select_canonical",
    "transition",
]


def __getattr__(name: str) -> Any:
    try:
        module_name, attribute = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
