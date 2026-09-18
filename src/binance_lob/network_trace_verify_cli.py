"""CLI for independent sealed network-trace verification."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from .network_trace import NetworkTraceCorruption, verify_network_trace


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m binance_lob.network_trace_verify_cli <trace-root>", file=sys.stderr)
        return 2
    try:
        report = verify_network_trace(Path(sys.argv[1]))
    except (OSError, NetworkTraceCorruption) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

