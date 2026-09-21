#!/usr/bin/env python
"""SBE lane capture — executable PHASE 7 lane for Binance Spot SBE streams.

Policy (CAPTURE_CAMPAIGN_POLICY_V1.md §Feed evolution): SBE runs as a SEPARATE
lane with its OWN epochs and dataset versions; it never merges with JSON
epochs. Live access requires an Ed25519 market-data-only key
(sbe-market-data-streams.md, captured SHA256 3E945F52…): the key travels in
the X-MBX-APIKEY header of the websocket handshake.

Spec-grounded behavior:
  - binary frames = SBE messages (schema stream_1_0.xml, pinned 6EA32846…);
  - server ping every 20 s -> pong echo (websockets library answers; we log);
  - serverShutdown arrives as a JSON TEXT frame {"e":"serverShutdown","E":…}
    -> typed record + clean reconnect;
  - 24 h connection lifetime -> rotation at 23 h (--max-conn-s 82800) like the
    JSON lane policy.

Outputs (all inside --out, create-only):
  - frames.sbe            : u32-LE-length-prefixed raw SBE frames
  - sbe-events.jsonl      : hash-chained journal (SHA-256) with provenance
                            and TYPED gaps between connections
  - sbe-terminal.json     : terminal inventory (files, SHA-256, frame counts)

Never touches the productive JSON service: independent directory, independent
connection, independent epoch ids.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import pathlib
import sys
import time

import websockets

JOURNAL_SCHEMA = "SbeLaneJournalRecordV1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Journal:
    def __init__(self, path: pathlib.Path):
        self.path = path
        self.index = 0
        self.prev = None

    def append(self, event: str, **payload) -> dict:
        wall_ns = time.time_ns()
        body = {
            "schema": JOURNAL_SCHEMA,
            "record_index": self.index,
            "wall_ns": wall_ns,
            "monotonic_tick": time.perf_counter_ns(),
            "channel": "SBE",
            "payload": {"event": event, **payload},
            "previous_record_sha256": self.prev,
        }
        record_sha256 = _sha256(
            json.dumps(body["payload"], sort_keys=True, separators=(",", ":")).encode()
        )
        row = {"body": body, "record_sha256": record_sha256}
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        self.prev = record_sha256
        self.index += 1
        return row


def template_id(frame: bytes) -> int:
    if len(frame) < 4:
        return 0
    return int.from_bytes(frame[2:4], "little")


class Lane:
    def __init__(self, out: pathlib.Path, urls: list[str], api_key: str,
                 max_conn_s: float):
        self.out = out
        self.urls = urls
        self.api_key = api_key
        self.max_conn_s = max_conn_s
        self.journal = Journal(out / "sbe-events.jsonl")
        self.frames_path = out / "frames.sbe"
        self.frame_count = 0

    def store(self, frame: bytes) -> str:
        with self.frames_path.open("ab") as fh:
            fh.write(len(frame).to_bytes(4, "little"))
            fh.write(frame)
        self.frame_count += 1
        # Per-frame end-to-end telemetry: venue event time is the first field
        # (eventTime, int64 microseconds at offset 8 of every message in the
        # pinned schema) -> wire leg measurable without a decoder.
        tpl = template_id(frame)
        event_us = 0
        if len(frame) >= 16:
            event_us = int.from_bytes(frame[8:16], "little")
        row = {
            "index": self.frame_count - 1,
            "template_id": tpl,
            "event_time_us": event_us,
            "recv_wall_ms": int(time.time() * 1000),
            "recv_monotonic_ns": time.perf_counter_ns(),
        }
        with (self.out / "sbe-telemetry.jsonl").open("a", encoding="utf-8",
                                                     newline="\n") as fh:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        return _sha256(frame)

    async def run_connection(self, url: str, duration_s: float) -> str | None:
        """Returns 'server_shutdown' or None; raises on transport error."""
        kwargs = {}
        if self.api_key:
            kwargs["additional_headers"] = {"X-MBX-APIKEY": self.api_key}
        started = time.monotonic()
        async with websockets.connect(url, ping_interval=None, max_size=2**24,
                                      **kwargs) as ws:
            while True:
                if duration_s and (time.monotonic() - started) >= duration_s:
                    return "duration"
                if self.max_conn_s and (time.monotonic() - started) >= self.max_conn_s:
                    return "rotation"
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=30)
                except asyncio.TimeoutError:
                    raise ConnectionError("no data for 30 s")
                if isinstance(raw, bytes):
                    h = self.store(raw)
                    self.journal.append(
                        "FRAME", template_id=template_id(raw), length=len(raw),
                        sha256=h, offset=self.frame_count - 1,
                    )
                else:
                    try:
                        doc = json.loads(raw)
                    except Exception:
                        continue
                    if doc.get("e") == "serverShutdown":
                        self.journal.append(
                            "SERVER_SHUTDOWN", event_time_ms=doc.get("E"),
                        )
                        return "server_shutdown"

    async def run(self, duration_s: float) -> int:
        self.out.mkdir(parents=True, exist_ok=False)
        epoch_id = "sbe-%s-%s" % (
            time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
            os.urandom(4).hex(),
        )
        self.journal.append(
            "LANE_START", epoch_id=epoch_id, urls=self.urls,
            api_key_present=bool(self.api_key), max_conn_s=self.max_conn_s,
        )
        exit_code = 0
        last_end_ns = None
        for i, url in enumerate(self.urls):
            start_ns = time.time_ns()
            if last_end_ns is not None:
                # Wall hole between connections: TYPED, never silent.
                self.journal.append(
                    "GAP_TYPED", from_wall_ns=last_end_ns, to_wall_ns=start_ns,
                    reason=prev_reason or "unknown",
                )
            try:
                reason = await self.run_connection(url, duration_s)
            except websockets.exceptions.ConnectionClosed as exc:
                self.journal.append(
                    "CONN_CLOSED", url=url, code=exc.code or 0,
                    reason=str(exc)[:200],
                )
                reason = "connection_closed"
            except Exception as exc:  # transport dead: typed, then next url
                self.journal.append(
                    "TRANSPORT_DEAD", url=url, reason=str(exc)[:200],
                )
                reason = "transport_dead"
            prev_reason = reason
            last_end_ns = time.time_ns()
            if reason in ("duration", "rotation"):
                break
        # Terminal inventory with content digests.
        files = []
        for p in sorted(self.out.iterdir()):
            if p.is_file():
                b = p.read_bytes()
                files.append({
                    "file": p.name, "bytes": len(b), "sha256": _sha256(b),
                    "frames": self.frame_count if p.name == "frames.sbe" else 0,
                })
        self.journal.append("LANE_END", inventory=files, frame_count=self.frame_count)
        (self.out / "sbe-terminal.json").write_text(
            json.dumps({
                "schema": "SbeLaneTerminalV1",
                "epoch_id": epoch_id,
                "inventory": files,
                "frame_count": self.frame_count,
                "journal_head_sha256": self.journal.prev,
            }, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return exit_code


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True,
                    help="ws(s):// URL; '|'-separated chain for reconnects")
    ap.add_argument("--out", required=True, help="new output directory")
    ap.add_argument("--duration", type=float, default=0.0,
                    help="seconds (0 = until rotation/termination)")
    ap.add_argument("--max-conn-s", type=float, default=82800.0,
                    help="connection lifetime (23 h default, venue limit 24 h)")
    args = ap.parse_args()
    urls = [u for u in args.url.split("|") if u]
    key = os.environ.get("BINANCE_SBE_API_KEY", "")
    out = pathlib.Path(args.out)
    if out.exists():
        print(f"error: --out must be a NEW directory: {out}", file=sys.stderr)
        return 2
    lane = Lane(out, urls, key, args.max_conn_s)
    try:
        return asyncio.run(lane.run(args.duration))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
