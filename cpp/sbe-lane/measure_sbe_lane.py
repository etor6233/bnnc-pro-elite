#!/usr/bin/env python
"""End-to-end latency measurement for a captured SBE lane.

Punta a punta = venue event time (E, inside every SBE message) -> local
receive -> stored frame. This script computes the WIRE leg distribution:

    delay_ms = recv_wall_ms - (event_time_us / 1000 + clock_offset_ms)

with the clock offset measured against the venue REST /api/v3/time (median of
N samples, declared uncertainty = median_RTT/2), or passed explicitly with
--offset for reproducible offline analysis (the capture test uses this).

The local legs (receive -> store, store -> decode) are nanoseconds/microseconds
and are measured by the FASE 5 benchmarks (SBE decode 83 ns p50) — the wire
leg dominates by ~5 orders of magnitude.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import sys
import time
import urllib.request


def measure_offset(samples: int = 8) -> tuple[float, float]:
    offsets: list[float] = []
    rtts: list[float] = []
    url = "https://api.binance.com/api/v3/time"
    for _ in range(samples):
        t0_wall = time.time() * 1000.0
        t0_perf = time.perf_counter()
        with urllib.request.urlopen(url, timeout=10) as resp:
            server_ms = json.loads(resp.read())["serverTime"]
        t1_perf = time.perf_counter()
        rtt_ms = (t1_perf - t0_perf) * 1000.0
        offsets.append(server_ms - t0_wall - rtt_ms / 2.0)
        rtts.append(rtt_ms)
    return statistics.median(offsets), statistics.median(rtts)


def pct(xs: list[float], p: float) -> float:
    s = sorted(xs)
    return s[int(p * (len(s) - 1) + 0.5)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="SBE lane output directory")
    ap.add_argument("--offset", type=float, default=None,
                    help="clock offset ms (default: measure via /api/v3/time)")
    ap.add_argument("--out", default=None, help="optional JSON report path")
    args = ap.parse_args()

    tel_path = pathlib.Path(args.dir) / "sbe-telemetry.jsonl"
    if not tel_path.exists():
        print(f"error: {tel_path} not found", file=sys.stderr)
        return 2

    rows = []
    for line in tel_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))

    if args.offset is None:
        offset_ms, rtt_ms = measure_offset()
        uncertainty = rtt_ms / 2.0
    else:
        offset_ms = args.offset
        rtt_ms = None
        uncertainty = 0.0

    by_tpl: dict[int, list[float]] = {}
    gaps: dict[int, list[float]] = {}
    last_recv: dict[int, float] = {}
    for row in rows:
        tpl = row["template_id"]
        delay = row["recv_wall_ms"] - (row["event_time_us"] / 1000.0 + offset_ms)
        by_tpl.setdefault(tpl, []).append(delay)
        recv = row["recv_wall_ms"]
        if tpl in last_recv:
            gaps.setdefault(tpl, []).append(recv - last_recv[tpl])
        last_recv[tpl] = recv

    report: dict = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "clock_offset_ms": offset_ms,
        "uncertainty_ms": uncertainty,
        "frames": len(rows),
        "wire_leg": {},
    }
    for tpl in sorted(by_tpl):
        ds = by_tpl[tpl]
        gs = gaps.get(tpl, [])
        report["wire_leg"][str(tpl)] = {
            "samples": len(ds),
            "delay_ms_p50": pct(ds, 0.50),
            "delay_ms_p99": pct(ds, 0.99),
            "delay_ms_mean": statistics.mean(ds),
            "delay_ms_max": max(ds),
            "inter_arrival_ms_p50": pct(gs, 0.50) if gs else None,
            "inter_arrival_ms_p99": pct(gs, 0.99) if gs else None,
        }

    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
