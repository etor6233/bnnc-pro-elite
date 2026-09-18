"""Minimal offline entry point for terminal RawCampaignV1 verification.

This module deliberately exposes no capture, account, network, feature or order
operation.  It exists so the Windows guardian does not load the general project
CLI (and its capture dependencies) into the independent verifier process.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .raw_campaign import RawCampaignCorruption, verify_raw_campaign


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="binance-raw-campaign-verify")
    parser.add_argument("campaign", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _write_synced_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    campaign = args.campaign.resolve(strict=True)
    output = args.output.resolve(strict=False)
    try:
        output.relative_to(campaign)
    except ValueError:
        pass
    else:
        print(
            json.dumps(
                {
                    "schema": "RawCampaignVerificationFailureV1",
                    "status": "REJECTED",
                    "reason": (
                        "verification output must remain outside the exact "
                        "campaign inventory"
                    ),
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2

    try:
        result = verify_raw_campaign(campaign)
    except RawCampaignCorruption as exc:
        print(
            json.dumps(
                {
                    "schema": "RawCampaignVerificationFailureV1",
                    "status": "REJECTED",
                    "reason": str(exc),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2

    payload = (
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    _write_synced_new(output, payload)
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
