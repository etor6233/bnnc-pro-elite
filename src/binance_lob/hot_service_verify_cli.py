"""CLI for independent verification of a hot-redundant service run."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from .hot_service import HotServiceCorruption, verify_hot_service


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m binance_lob.hot_service_verify_cli <service-root>", file=sys.stderr)
        return 2
    try:
        report = verify_hot_service(Path(sys.argv[1]))
    except (OSError, HotServiceCorruption) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
