"""Offline, synthetic evidence demo. Never connects to an exchange.

Uses the existing BNRAW writer and the independent Python/Rust replay cores.
All mutable data lives in a newly created temporary directory.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from binance_lob.book import DepthGap, replay_session  # noqa: E402
from binance_lob.clock import ClockQuality, ClockSample  # noqa: E402
from binance_lob.raw_frame import RawFrameV1  # noqa: E402
from binance_lob.raw_log import RawLogCorruption, RawLogWriter, iter_raw_frames  # noqa: E402


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def write_frames(path: Path, symbol: str, stream: str, payloads: list[bytes]) -> None:
    with RawLogWriter(path, sync_every=1) as writer:
        for index, payload in enumerate(payloads):
            writer.append(RawFrameV1.capture(
                endpoint="fixture://offline-not-a-network-capture",
                stream=stream, symbol=symbol, connection_epoch="synthetic-portfolio-v1",
                frame_index=index,
                clock=ClockSample(1_720_000_000_000_000_000 + index, index,
                                  ClockQuality.UNKNOWN, "synthetic-fixture-clock"),
                payload=payload,
            ))
    if [frame.payload for frame in iter_raw_frames(path)] != payloads:
        raise RuntimeError("raw round-trip changed payload bytes")


def run_case(rust: Path, root: Path, symbol: str, case: str) -> dict:
    session = root / f"{symbol}-{case}"
    session.mkdir()
    snapshot = (REPO / "fixtures/depth_snapshot_btcusdt.json").read_bytes()
    update = (REPO / "fixtures/depth_update_btcusdt.json").read_bytes()
    trade = (REPO / "fixtures/trade_btcusdt.json").read_bytes()
    # Explicitly synthetic: reuse fixture prices, changing only the symbol.
    update = update.replace(b"BTCUSDT", symbol.encode())
    trade = trade.replace(b"BTCUSDT", symbol.encode())
    updates = [update]
    if case == "sequence_gap":
        event = json.loads(update)
        event.update(U=104, u=104)
        updates.append(json.dumps(event, separators=(",", ":")).encode())
    elif case == "old_event":
        event = json.loads(update)
        event.update(U=90, u=99, b=[], a=[])
        updates.append(json.dumps(event, separators=(",", ":")).encode())
    write_frames(session / "snapshot.bnraw", symbol, "snapshot", [snapshot])
    write_frames(session / "depth.bnraw", symbol, "depth", updates)
    write_frames(session / "trade.bnraw", symbol, "trade", [trade])
    if case == "byte_corruption":
        # Damage only this test's temporary file, never retained evidence.
        path = session / "depth.bnraw"
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
    inputs = {name: digest(session / name) for name in
              ("snapshot.bnraw", "depth.bnraw", "trade.bnraw")}
    expected_error = {"sequence_gap": DepthGap,
                      "byte_corruption": RawLogCorruption}.get(case)
    python_value = None
    python_rejection = None
    try:
        python_value = asdict(replay_session(session))
    except (DepthGap, RawLogCorruption) as error:
        if expected_error is None or not isinstance(error, expected_error):
            raise
        python_rejection = type(error).__name__
    completed = subprocess.run([str(rust), str(session)], capture_output=True,
                               text=True, timeout=30, check=False)
    if {name: digest(session / name) for name in inputs} != inputs:
        raise RuntimeError("a verifier changed a raw input")
    if expected_error is not None:
        if python_rejection is None or completed.returncode != 2 or not completed.stderr.strip():
            raise RuntimeError(f"{symbol}/{case}: both implementations must reject")
        return {"symbol": symbol, "case": case, "expected": "REJECT",
                "python": python_rejection, "rust_exit": completed.returncode,
                "raw_unchanged": True, "passed": True}
    if completed.returncode != 0:
        raise RuntimeError(f"{symbol}/{case}: Rust replay failed: {completed.stderr[:500]}")
    rust_value = json.loads(completed.stdout)
    if python_value != rust_value:
        raise RuntimeError(f"{symbol}/{case}: Python and Rust disagree")
    expected_old = int(case == "old_event")
    if (python_value["state"] != "LIVE" or python_value["final_update_id"] != 102
            or python_value["old_records"] != expected_old
            or python_value["applied_records"] != 1
            or python_value["bid_levels"] != 1 or python_value["ask_levels"] != 2):
        raise RuntimeError("both implementations disagree with the fixture expectation")
    return {"symbol": symbol, "case": case, "expected": "ACCEPT",
            "rust_python_equal": True, "final_update_id": 102,
            "state_sha256": python_value["state_sha256"],
            "raw_unchanged": True, "trade_payload_round_trip": True, "passed": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-bin", required=True, type=Path,
                        help="locally built lob-replay executable; never downloaded")
    args = parser.parse_args()
    rust = args.rust_bin.resolve(strict=True)
    binary_hash = digest(rust)
    with tempfile.TemporaryDirectory(prefix="market-data-demo-") as directory:
        cases = [run_case(rust, Path(directory), symbol, case)
                 for symbol in ("BTCUSDT", "ETHUSDT")
                 for case in ("valid", "old_event", "sequence_gap", "byte_corruption")]
    if digest(rust) != binary_hash:
        raise RuntimeError("Rust binary changed during demonstration")
    print(json.dumps({"schema": "OfflinePortfolioDemoV1", "status": "PASS",
                      "synthetic": True, "network_used": False,
                      "scope": "BNRAW round-trip and L2 replay fixtures, not live qualification",
                      "rust_binary_sha256": binary_hash,
                      "demo_sha256": digest(Path(__file__)), "cases": cases}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"portfolio-demo: {error}", file=sys.stderr)
        raise SystemExit(2)
