from __future__ import annotations

import json
from pathlib import Path
import sys

from .kernel_network_cleanup import verify_kernel_network_cleanup


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m binance_lob.kernel_network_cleanup_verify_cli <evidence-root>", file=sys.stderr)
        return 2
    try:
        result = verify_kernel_network_cleanup(Path(sys.argv[1]))
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
