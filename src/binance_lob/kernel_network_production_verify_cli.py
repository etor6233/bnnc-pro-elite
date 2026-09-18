"""CLI for independent production-lifecycle Kernel-Network verification."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from .kernel_network_production import (
    KernelNetworkProductionCorruption,
    verify_kernel_network_production,
)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m binance_lob.kernel_network_production_verify_cli <root>", file=sys.stderr)
        return 2
    try:
        report = verify_kernel_network_production(Path(sys.argv[1]))
    except (OSError, KernelNetworkProductionCorruption) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
