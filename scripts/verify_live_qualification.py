"""Fail-closed verifier for completed dual-symbol live qualification campaigns."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from binance_lob.canonical_output import verify_canonical_outputs  # noqa: E402
from binance_lob.raw_log import scan_raw_log  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def resolve_report_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else REPO / path


def verify_source(session: Path, durability_scan: Path) -> dict[str, object]:
    manifest_path = session / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("schema") == "CaptureManifestV1", f"bad manifest: {manifest_path}")
    require(manifest.get("status") == "COMPLETE", f"capture incomplete: {session}")
    require(manifest.get("credentials") == "NONE", f"credentials present: {session}")
    require(manifest.get("order_entry") == "ABSENT", f"order entry present: {session}")
    reports: list[dict[str, object]] = []
    streams = manifest.get("streams")
    require(isinstance(streams, list) and len(streams) == 2, f"bad streams: {session}")
    for stream in streams:
        require(isinstance(stream, dict), f"bad stream entry: {session}")
        name = str(stream["name"])
        require(name in {"depth", "trade"}, f"unexpected stream: {name}")
        received = int(stream["received"])
        written = int(stream["written"])
        require(received == written and written > 0, f"loss in {session}/{name}")
        require(stream.get("error") is None, f"stream error in {session}/{name}")
        raw_path = session / str(stream["raw_file"])
        ack_path = session / str(stream["durability_progress_file"])
        raw = scan_raw_log(raw_path)
        require(raw.clean_eof, f"unclean raw {raw_path}: {raw.reason}")
        require(raw.records == written, f"raw count mismatch: {raw_path}")
        ack = stream["durability_ack"]
        require(isinstance(ack, dict), f"missing terminal ACK: {session}/{name}")
        require(int(ack["durable_record_count"]) == written, f"ACK count mismatch: {raw_path}")
        require(int(ack["durable_through_offset"]) == raw.last_good_offset, f"ACK offset mismatch: {raw_path}")
        require(str(ack["last_record_sha256"]) == raw.last_record_sha256, f"ACK hash mismatch: {raw_path}")
        command = subprocess.run(
            [str(durability_scan), str(ack_path), str(raw_path)],
            cwd=REPO,
            text=True,
            capture_output=True,
            check=False,
        )
        require(command.returncode == 0, f"Rust durability verification failed: {command.stderr}")
        rust = json.loads(command.stdout)
        require(rust["progress"]["clean_eof"] is True, f"unclean BNACK: {ack_path}")
        require(rust["verified_ack"] == ack, f"Rust ACK differs from manifest: {ack_path}")
        reports.append(
            {
                "stream": name,
                "records": written,
                "bytes": raw.file_size,
                "last_record_sha256": raw.last_record_sha256,
                "python_raw_scan": "PASS",
                "rust_durability_scan": "PASS",
            }
        )
    return {
        "session": str(session),
        "symbol": manifest["symbol"],
        "duration_requested_s": manifest["duration_requested_s"],
        "streams": reports,
    }


def verify_campaign(campaign_dir: Path, durability_scan: Path) -> dict[str, object]:
    report_path = campaign_dir / "live-campaign.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    symbol = report.get("symbol")
    require(report.get("schema") == "LiveCampaignReportV1", f"bad campaign: {report_path}")
    require(report.get("status") == "ACTIVATED_WHILE_RECEIVING", f"campaign failed: {report_path}")
    require(symbol in {"BTCUSDT", "ETHUSDT"}, f"bad symbol: {report_path}")
    require(report.get("credentials") == "NONE", f"credentials present: {report_path}")
    require(report.get("order_entry") == "ABSENT", f"order entry present: {report_path}")
    require(report.get("predecessor_alive_at_activation") is True, f"A dead at activation: {report_path}")
    require(report.get("successor_alive_at_activation") is True, f"B dead at activation: {report_path}")
    require(int(report.get("fenced_predecessor_rejections", 0)) >= 1, f"fencing unproved: {report_path}")
    require(int(report.get("depth_post_activation_accepted", 0)) > 0, f"no live depth after activation")
    require(int(report.get("trade_post_activation_accepted", 0)) > 0, f"no live trades after activation")

    predecessor = resolve_report_path(str(report["predecessor_session"]))
    successor = resolve_report_path(str(report["successor_session"]))
    sources = [verify_source(predecessor, durability_scan), verify_source(successor, durability_scan)]
    committed = campaign_dir / "committed"
    canonical = verify_canonical_outputs(
        committed / "ownership.bnledger",
        committed / "depth.bnhandover",
        committed / "trade.bnhandover",
        committed / "depth.bnpub",
        committed / "trade.bnpub",
    )
    require(canonical["status"] == "PASS", f"canonical verification failed: {campaign_dir}")
    for kind in ("depth", "trade"):
        output = canonical[kind]
        require(output["clean_eof"] is True, f"unclean canonical {kind}: {campaign_dir}")
        require(output["ownership_changes"] == 1, f"wrong ownership count: {campaign_dir}/{kind}")
        require(output["last_observation"] is not None, f"missing recovery lineage: {campaign_dir}/{kind}")
        require(
            output["last_observation"]["connection_epoch"] == output["owner"]["connection_epoch"],
            f"last observation is not owned by B: {campaign_dir}/{kind}",
        )
    oracle_path = campaign_dir / "canonical-output-verification-python.json"
    oracle_path.write_text(
        json.dumps(canonical, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        "symbol": symbol,
        "campaign": str(campaign_dir),
        "sources": sources,
        "canonical": {
            "status": "PASS",
            "depth_records": canonical["depth"]["records"],
            "trade_records": canonical["trade"]["records"],
            "ownership_changes": 1,
            "recovery_lineage": "PRESENT",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, help="run directory containing both campaign folders")
    parser.add_argument("--durability-scan", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    manifests = sorted(root.glob("*/live-campaign.json"))
    require(len(manifests) == 2, f"expected exactly two campaigns under {root}, found {len(manifests)}")
    campaigns = [verify_campaign(path.parent, args.durability_scan.resolve()) for path in manifests]
    require({item["symbol"] for item in campaigns} == {"BTCUSDT", "ETHUSDT"}, "symbol set mismatch")
    result = {
        "schema": "DualLiveQualificationVerificationV1",
        "status": "PASS",
        "root": str(root),
        "campaigns": campaigns,
        "credentials": "NONE",
        "order_entry": "ABSENT",
    }
    destination = args.output or root / "qualification-verification.json"
    destination.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(destination)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"qualification verification: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
