"""CLI for independent Windows system-evidence verification."""

from __future__ import annotations

import json
from pathlib import Path
import sys

from .system_evidence import SystemEvidenceCorruption, verify_system_evidence


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m binance_lob.system_evidence_verify_cli <evidence-root>", file=sys.stderr)
        return 2
    try:
        report = verify_system_evidence(Path(sys.argv[1]))
    except (OSError, SystemEvidenceCorruption) as error:
        print(f"system evidence verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
