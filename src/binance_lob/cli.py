"""Command line entry point for public capture and raw verification."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
import json
from pathlib import Path
import sys

from .capture import CaptureOptions, capture_public
from .book import replay_result_dict, replay_session
from .clock import ClockQuality
from .monitor import monitor_session
from .observations import (
    materialization_dict,
    materialize_depth_observations,
    materialize_trade_observations,
)
from .audit import audit_session
from .raw_log import scan_raw_log
from .splice_verify import verify_splice
from .ownership import verify_ownership
from .canonical_output import verify_canonical_outputs
from .segment_chain import SegmentChainCorruption, verify_segmented_generation
from .raw_campaign import RawCampaignCorruption, verify_raw_campaign


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="binance-lob")
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser("capture", help="capture public depth/trade and REST snapshot")
    capture.add_argument("--symbol", choices=("BTCUSDT", "ETHUSDT"), required=True)
    capture.add_argument("--duration", type=float, default=15.0)
    capture.add_argument("--output", type=Path, default=Path("artifacts/captures"))
    capture.add_argument("--queue-capacity", type=int, default=4096)
    capture.add_argument("--sync-every", type=int, default=64)
    capture.add_argument(
        "--clock-quality",
        choices=tuple(quality.value for quality in ClockQuality),
        default=ClockQuality.UNKNOWN.value,
    )
    capture.add_argument("--clock-source", default="unverified-local-clock")

    verify = subparsers.add_parser("verify", help="verify one or more .bnraw files")
    verify.add_argument("paths", nargs="+", type=Path)
    segmented = subparsers.add_parser(
        "verify-segmented-generation",
        help="independently verify a Rust segmented raw generation",
    )
    segmented.add_argument("generation", type=Path)
    segmented.add_argument("--output", type=Path)
    raw_campaign = subparsers.add_parser(
        "verify-raw-campaign",
        help="independently verify one terminal Rust raw capture campaign",
    )
    raw_campaign.add_argument("campaign", type=Path)
    raw_campaign.add_argument("--output", type=Path)
    replay = subparsers.add_parser("replay-book", help="rebuild a session L2 book")
    replay.add_argument("session", type=Path)
    replay.add_argument("--output", type=Path)
    audit = subparsers.add_parser(
        "audit-session", help="audit raw integrity, lineage and neutral book reconstruction"
    )
    audit.add_argument("session", type=Path)
    audit.add_argument("--output", type=Path)
    features = subparsers.add_parser(
        "derive-features", help="derive an experimental, non-authoritative feature sidecar"
    )
    features.add_argument("session", type=Path)
    features.add_argument("--output", type=Path)
    observations = subparsers.add_parser(
        "materialize-observations",
        help="derive neutral validated observations with exact BNRAW lineage",
    )
    observations.add_argument("--kind", choices=("depth", "trade"), required=True)
    observations.add_argument("--raw", type=Path, required=True)
    observations.add_argument("--snapshot", type=Path)
    observations.add_argument("--output", type=Path)
    splice = subparsers.add_parser(
        "verify-splice", help="independently replay and verify a committed A/B splice"
    )
    splice.add_argument("splice_dir", type=Path)
    splice.add_argument("--output", type=Path)
    ownership = subparsers.add_parser(
        "verify-ownership", help="verify ownership ledger against committed stream journals"
    )
    ownership.add_argument("ledger", type=Path)
    ownership.add_argument("--depth-journal", type=Path, required=True)
    ownership.add_argument("--trade-journal", type=Path, required=True)
    ownership.add_argument("--output", type=Path)
    canonical = subparsers.add_parser(
        "verify-canonical-output",
        help="independently recover canonical depth/trade output and compare ownership",
    )
    canonical.add_argument("--ledger", type=Path, required=True)
    canonical.add_argument("--depth-journal", type=Path, required=True)
    canonical.add_argument("--trade-journal", type=Path, required=True)
    canonical.add_argument("--depth-output", type=Path, required=True)
    canonical.add_argument("--trade-output", type=Path, required=True)
    canonical.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "capture":
        options = CaptureOptions(
            output_root=args.output,
            symbol=args.symbol,
            duration_s=args.duration,
            queue_capacity=args.queue_capacity,
            sync_every=args.sync_every,
            clock_quality=ClockQuality(args.clock_quality),
            clock_source=args.clock_source,
        )
        try:
            session_dir = asyncio.run(capture_public(options))
        except KeyboardInterrupt:
            return 130
        print(json.dumps({"status": "COMPLETE", "session_dir": str(session_dir)}))
        return 0

    if args.command == "replay-book":
        result = replay_result_dict(replay_session(args.session))
        if args.output is not None:
            destination = args.output
        else:
            destination = args.session / "book-replay.json"
        destination.write_text(
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "verify-segmented-generation":
        try:
            result = verify_segmented_generation(args.generation)
        except SegmentChainCorruption as exc:
            failure = {
                "schema": "SegmentedGenerationVerificationFailureV1",
                "status": "REJECTED",
                "reason": str(exc),
            }
            print(
                json.dumps(failure, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
            )
            return 2
        if args.output is not None:
            try:
                args.output.resolve().relative_to(args.generation.resolve())
            except ValueError:
                pass
            else:
                failure = {
                    "schema": "SegmentedGenerationVerificationFailureV1",
                    "status": "REJECTED",
                    "reason": (
                        "verification output must remain outside the exact generation inventory"
                    ),
                }
                print(
                    json.dumps(
                        failure,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    file=sys.stderr,
                )
                return 2
            args.output.write_text(
                json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if args.command == "verify-raw-campaign":
        try:
            result = verify_raw_campaign(args.campaign)
        except RawCampaignCorruption as exc:
            failure = {
                "schema": "RawCampaignVerificationFailureV1",
                "status": "REJECTED",
                "reason": str(exc),
            }
            print(
                json.dumps(failure, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
            )
            return 2
        if args.output is not None:
            try:
                args.output.resolve().relative_to(args.campaign.resolve())
            except ValueError:
                pass
            else:
                failure = {
                    "schema": "RawCampaignVerificationFailureV1",
                    "status": "REJECTED",
                    "reason": "verification output must remain outside the exact campaign inventory",
                }
                print(
                    json.dumps(
                        failure,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    file=sys.stderr,
                )
                return 2
            args.output.write_text(
                json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if args.command == "audit-session":
        result = audit_session(args.session)
        destination = args.output or args.session / "dataset-audit-python.json"
        destination.write_text(
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if args.command == "derive-features":
        result = monitor_session(args.session)
        destination = args.output or args.session / "experimental-features-python.json"
        destination.write_text(
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if args.command == "materialize-observations":
        if args.kind == "depth":
            if args.snapshot is None:
                raise SystemExit("--snapshot is required for depth observations")
            materialized = materialize_depth_observations(args.snapshot, args.raw)
        else:
            if args.snapshot is not None:
                raise SystemExit("--snapshot is not valid for trade observations")
            materialized = materialize_trade_observations(args.raw)
        result = materialization_dict(materialized)
        if args.output is not None:
            args.output.write_text(
                json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if args.command == "verify-splice":
        result = asdict(verify_splice(args.splice_dir))
        destination = args.output or args.splice_dir / "splice-verification-python.json"
        destination.write_text(
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if args.command == "verify-ownership":
        result = verify_ownership(args.ledger, args.depth_journal, args.trade_journal)
        if args.output is not None:
            args.output.write_text(
                json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if args.command == "verify-canonical-output":
        result = verify_canonical_outputs(
            args.ledger,
            args.depth_journal,
            args.trade_journal,
            args.depth_output,
            args.trade_output,
        )
        if args.output is not None:
            args.output.write_text(
                json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    scans = [asdict(scan_raw_log(path)) for path in args.paths]
    for scan in scans:
        scan["path"] = str(scan["path"])
    print(json.dumps(scans, ensure_ascii=False, indent=2))
    return 0 if all(scan["clean_eof"] for scan in scans) else 2


if __name__ == "__main__":
    raise SystemExit(main())
