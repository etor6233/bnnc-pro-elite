"""CLI for the independent Python CompleteRunReplayReportV1 oracle."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .complete_replay import replay_complete_run
from .market_replay import MarketReplayCorruption


def main() -> int:
    parser = argparse.ArgumentParser(prog="binance-complete-market-replay")
    parser.add_argument("selection", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        selection = json.loads(args.selection.read_text(encoding="utf-8"))
        if not isinstance(selection, dict):
            raise MarketReplayCorruption("selection root must be an object")
        report = replay_complete_run(selection)
        encoded = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        if args.output is not None:
            run = Path(str(selection.get("run_directory", ""))).resolve(strict=True)
            output = args.output.resolve()
            try:
                output.relative_to(run)
            except ValueError:
                pass
            else:
                raise MarketReplayCorruption(
                    "replay report must remain outside immutable source run"
                )
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("xb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        sys.stdout.buffer.write(encoded)
        return 0
    except (MarketReplayCorruption, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"complete-replay-python: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
