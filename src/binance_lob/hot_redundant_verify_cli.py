"""Offline entry point for independent hot-redundant verification."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .hot_redundant import HotRedundantCorruption, verify_hot_redundant_capture


def _write_synced_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="binance-hot-redundant-verify")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    artifact = args.artifact.resolve(strict=True)
    if args.output is not None:
        output = args.output.resolve(strict=False)
        try:
            output.relative_to(artifact)
        except ValueError:
            pass
        else:
            print("verification output cannot contaminate the artifact", file=sys.stderr)
            return 2
    try:
        report = verify_hot_redundant_capture(artifact)
    except HotRedundantCorruption as exc:
        print(
            json.dumps(
                {"schema": "HotRedundantVerificationFailureV1", "status": "REJECTED", "reason": str(exc)},
                ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2
    payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if args.output is not None:
        _write_synced_new(output, payload)
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
