"""CLI for the independent Python MarketReplayReportV1 oracle."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .market_replay import MarketReplayCorruption, replay_failed_generation_prefix


def main() -> int:
    parser = argparse.ArgumentParser(prog="binance-market-replay")
    parser.add_argument("selection", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        selection = json.loads(args.selection.read_text(encoding="utf-8"))
        if not isinstance(selection, dict):
            raise MarketReplayCorruption("selection root must be an object")
        report = replay_failed_generation_prefix(selection)
        encoded = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        if args.output is not None:
            generation = Path(str(selection.get("generation_directory", ""))).resolve(
                strict=True
            )
            output = args.output.resolve()
            try:
                output.relative_to(generation)
            except ValueError:
                pass
            else:
                raise MarketReplayCorruption(
                    "replay report must remain outside immutable source generation"
                )
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("xb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        sys.stdout.buffer.write(encoded)
        return 0
    except (MarketReplayCorruption, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"market-replay-python: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
