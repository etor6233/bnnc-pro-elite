from __future__ import annotations

import json
from pathlib import Path
import sys

from .observed_qualification import ObservedQualificationCorruption, verify_observed_qualification


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m binance_lob.observed_qualification_verify_cli <root>", file=sys.stderr)
        return 2
    try:
        report = verify_observed_qualification(Path(sys.argv[1]))
    except (OSError, ObservedQualificationCorruption) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
