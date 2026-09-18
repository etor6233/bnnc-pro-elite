"""CLI for independent network-witness verification."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from .network_witness import NetworkWitnessCorruption, verify_network_witness


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m binance_lob.network_witness_verify_cli <witness-root>", file=sys.stderr)
        return 2
    try:
        report = verify_network_witness(Path(sys.argv[1]))
    except (OSError, NetworkWitnessCorruption) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
