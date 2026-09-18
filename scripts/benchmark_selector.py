from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from time import perf_counter_ns, time_ns

from binance_lob import (
    BoundaryDurabilityV1,
    CanonicalObservationV1,
    HandoverBoundaryV1,
    RawPositionV1,
    select_canonical,
)

A = "a" * 64
B = "b" * 64
STREAM = "btcusdt@depth@100ms"


def observation(epoch: str, frame: int, sequence: int, digest: str) -> CanonicalObservationV1:
    return CanonicalObservationV1(
        "BTCUSDT", "DEPTH", STREAM, epoch, frame, sequence, sequence, digest, digest
    )


def percentile(samples: list[int], numerator: int, denominator: int) -> int:
    rank = (len(samples) * numerator + denominator - 1) // denominator
    return samples[max(1, min(rank, len(samples))) - 1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("records", type=int)
    parser.add_argument("iterations", type=int)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    if args.records < 1_000 or args.iterations < 10:
        raise SystemExit("records must be >=1000 and iterations >=10")
    overlap = 100
    boundary_sequence = args.records - overlap
    predecessor_boundary_frame = boundary_sequence - 1
    successor_boundary_frame = overlap - 1
    successor_first_frame = overlap
    predecessor = [
        observation("epoch-a", frame, frame + 1, A if frame + 1 == boundary_sequence else B)
        for frame in range(args.records)
    ]
    successor_start = boundary_sequence - successor_boundary_frame
    successor = [
        observation(
            "epoch-b",
            frame,
            successor_start + frame,
            A if successor_start + frame == boundary_sequence else B,
        )
        for frame in range(args.records)
    ]
    position = lambda epoch, frame, digest: RawPositionV1(epoch, STREAM, frame, digest)
    boundary = HandoverBoundaryV1(
        "HandoverBoundaryV1",
        "selector-benchmark",
        "production-public-market-data",
        "BTCUSDT",
        "DEPTH",
        STREAM,
        "epoch-a",
        "epoch-b",
        boundary_sequence,
        A,
        position("epoch-a", predecessor_boundary_frame, A),
        position("epoch-b", successor_boundary_frame, A),
        position("epoch-b", successor_first_frame, B),
        BoundaryDurabilityV1(args.records - 1, 1, A),
        BoundaryDurabilityV1(args.records - 1, 1, B),
        "976cc580553890e92031b77306147c0ed1de5a46",
        "CanonicalMarketDataViewV1",
    )
    expected_selected = args.records * 2 - overlap * 2
    expected_excluded = overlap * 2
    samples: list[int] = []
    digest = None
    wall_start = perf_counter_ns()
    for _ in range(args.iterations):
        started = perf_counter_ns()
        selection = select_canonical(boundary, predecessor, successor)
        samples.append(perf_counter_ns() - started)
        if (
            len(selection.selected) != expected_selected
            or selection.excluded_overlap_records != expected_excluded
            or (digest is not None and digest != selection.selection_sha256)
        ):
            raise RuntimeError("selector correctness/digest instability")
        digest = selection.selection_sha256
    wall_ns = perf_counter_ns() - wall_start
    samples.sort()
    report = {
        "schema": "CanonicalSelectorBenchmarkV1",
        "generated_at_unix_ns": time_ns(),
        "implementation": "python-oracle",
        "records_per_source": args.records,
        "overlap_records_per_source": overlap,
        "iterations": args.iterations,
        "input_observations": args.records * 2 * args.iterations,
        "selected_observations_per_iteration": expected_selected,
        "excluded_overlap_per_iteration": expected_excluded,
        "latency_ns": {
            "min": samples[0],
            "p50": percentile(samples, 50, 100),
            "p95": percentile(samples, 95, 100),
            "p99": percentile(samples, 99, 100),
            "p99_9": percentile(samples, 999, 1000),
            "max": samples[-1],
        },
        "input_observations_per_second": (args.records * 2 * args.iterations)
        / (wall_ns / 1_000_000_000),
        "wall_time_ns": wall_ns,
        "selection_sha256": digest,
        "correctness": "PASS",
        "credentials": "NONE",
        "order_entry": "ABSENT",
        "limitations": [
            "synthetic validated observations in memory",
            "not JSON decode, network capture, book application or disk materialization",
            "oracle performance is diagnostic, not hot-path candidacy",
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    print(args.report)


if __name__ == "__main__":
    main()
