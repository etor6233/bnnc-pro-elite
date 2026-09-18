"""FASE 5 measured benchmark: current JSON path (comparison baseline).

Parses a depth@100ms diff JSON message with the stdlib json parser (the same
payload shape the current capture lane consumes; field names per the pinned
web-socket-streams.md schema captured in BINANCE_SOURCE_LOCK.md:
e=event type, E=event time, s=symbol, U=first update id, u=final update id,
b=bids [price,qty], a=asks [price,qty]).

Numbers are MEASURED only; anti-cheat: a fresh parse + a mandatory field
extraction on every iteration (no memoization, no pre-parsed objects).
"""
from __future__ import annotations

import json
import statistics
import sys
import time

MSG = json.dumps({
    "e": "depthUpdate",
    "E": 1726700000123456,
    "s": "BTCUSDT",
    "U": 900000101,
    "u": 900000101,
    "b": [["59786.55000000", "1.50000000"], ["59785.00000000", "0.00000000"]],
    "a": [["59787.00000000", "0.80000000"], ["59789.00000000", "0.05000000"]],
}).encode("utf-8")


def run(n: int) -> tuple[list[int], int, float]:
    samples: list[int] = []
    sink = 0
    t_start = time.perf_counter()
    for _ in range(n):
        t0 = time.perf_counter_ns()
        doc = json.loads(MSG)          # fresh parse every iteration
        sink ^= doc["U"] ^ doc["u"]    # mandatory extraction (anti-DCE)
        t1 = time.perf_counter_ns()
        samples.append(t1 - t0)
    elapsed = time.perf_counter() - t_start
    return samples, sink, elapsed


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "dev"
    out = sys.argv[2] if len(sys.argv) > 2 else "benchmarks/bench_json_decode.json"
    n = 100_000 if mode == "dev" else 1_000_000
    reps = 3 if mode == "dev" else 5

    all_samples: list[int] = []
    best_tp = 0.0
    for r in range(reps):
        samples, sink, elapsed = run(n)
        all_samples.extend(samples)
        tp = n / elapsed if elapsed > 0 else 0.0
        best_tp = max(best_tp, tp)
        print(f"[{mode}] rep {r}: p50 {statistics.median(samples):.0f} ns, "
              f"n={len(samples)} (sink={sink})")

    ordered = sorted(all_samples)

    def pct(p: float) -> float:
        idx = int(p * (len(ordered) - 1) + 0.5)
        return float(ordered[idx])

    result = {
        "benchmark": "json_depth_decode",
        "mode": mode,
        "iterations_per_rep": n,
        "repetitions": reps,
        "p50_ns": pct(0.50),
        "p99_ns": pct(0.99),
        "mean_ns": statistics.mean(ordered),
        "min_ns": float(ordered[0]),
        "max_ns": float(ordered[-1]),
        "throughput_msg_per_s": best_tp,
        "anti_cheat": "fresh json.loads + mandatory field extraction per iteration; no memoization",
        "measured_on": "CPython 3.14 stdlib json",
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
