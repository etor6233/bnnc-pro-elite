"""CLI for independent filtered Kernel-Network ETW verification."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from .kernel_network_etw import KernelNetworkEtwCorruption, verify_kernel_network_etw


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m binance_lob.kernel_network_etw_verify_cli <root>", file=sys.stderr)
        return 2
    try:
        report = verify_kernel_network_etw(Path(sys.argv[1]))
    except (OSError, KernelNetworkEtwCorruption) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
