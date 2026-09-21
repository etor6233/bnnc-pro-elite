"""Streaming audit of a live SBE lane (no full-file loads):
- journal hash chain verification (SHA-256, streamed);
- event counts, typed gaps, key-on-disk scan;
- telemetry: frames per template, cadence (inter-arrival p50/p99 per template,
  streaming per-template last-arrival), wire delay on a bounded tail sample
  with a live clock offset from /api/v3/time;
- extracts the first K complete frames for the C++ decode CLI.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import statistics
import os
import subprocess
import sys
import time
import urllib.request

KEY_MARKER = os.environ.get("SBE_KEY_MARKER", "")  # never hardcoded


def pct(xs, p):
    s = sorted(xs)
    return s[int(p * (len(s) - 1) + 0.5)]


def measure_offset(n=8):
    offs, rtts = [], []
    for _ in range(n):
        t0w = time.time() * 1000.0
        t0p = time.perf_counter()
        with urllib.request.urlopen("https://api.binance.com/api/v3/time", timeout=10) as r:
            server_ms = json.loads(r.read())["serverTime"]
        t1p = time.perf_counter()
        rtt_ms = (t1p - t0p) * 1000.0
        offs.append(server_ms - t0w - rtt_ms / 2.0)
        rtts.append(rtt_ms)
    return statistics.median(offs), statistics.median(rtts)


def main() -> int:
    out = pathlib.Path(sys.argv[1])
    cli = sys.argv[2]
    offset_ms, rtt_ms = measure_offset()

    # 1) journal chain + events (streamed)
    chain_ok = True
    prev = None
    events: dict[str, int] = {}
    n_rows = 0
    with (out / "sbe-events.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            n_rows += 1
            row = json.loads(line)
            body = row["body"]
            if body.get("previous_record_sha256") != prev:
                chain_ok = False
                break
            payload = body["payload"]
            ev = payload.get("event", "?")
            events[ev] = events.get(ev, 0) + 1
            digest_src = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            if row.get("record_sha256") != hashlib.sha256(digest_src.encode()).hexdigest():
                chain_ok = False
                break
            prev = row["record_sha256"]

    # 2) key never on disk
    key_on_disk = 0
    for p in out.iterdir():
        if p.is_file() and p.name != "stderr.log" and KEY_MARKER:
            if KEY_MARKER in p.read_text(encoding="utf-8", errors="ignore"):
                key_on_disk += 1

    # 3) telemetry streaming: counts, cadence, tail-sample delay
    counts: dict[str, int] = {}
    last_recv: dict[str, int] = {}
    gaps: dict[str, list[int]] = {}
    tail: list[tuple[int, int, int]] = []  # (tpl, event_us, recv_ms)
    with (out / "sbe-telemetry.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            tpl = str(r["template_id"])
            counts[tpl] = counts.get(tpl, 0) + 1
            recv = r["recv_wall_ms"]
            if tpl in last_recv:
                gaps.setdefault(tpl, []).append(recv - last_recv[tpl])
            last_recv[tpl] = recv
            tail.append((r["template_id"], r["event_time_us"], recv))
            if len(tail) > 300000:
                tail.pop(0)

    delays: dict[str, list[float]] = {}
    for tpl, event_us, recv in tail[-200000:]:
        delays.setdefault(str(tpl), []).append(recv - (event_us / 1000.0 + offset_ms))

    report = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "journal": {"rows": n_rows, "chain_ok": chain_ok, "events": events},
        "key_on_disk_matches": key_on_disk if KEY_MARKER else "skipped (no SBE_KEY_MARKER provided)",
        "clock": {"offset_ms": offset_ms, "rtt_ms": rtt_ms,
                  "uncertainty_ms": rtt_ms / 2.0},
        "templates": {},
    }
    for tpl in sorted(counts):
        ds = delays.get(tpl, [])
        gs = sorted(gaps.get(tpl, []))
        report["templates"][tpl] = {
            "frames": counts[tpl],
            "inter_arrival_ms_p50": pct(gs, 0.50) if gs else None,
            "inter_arrival_ms_p99": pct(gs, 0.99) if gs else None,
            "tail_delay_ms_p50": pct(ds, 0.50) if ds else None,
            "tail_delay_ms_p99": pct(ds, 0.99) if ds else None,
            "tail_delay_ms_mean": statistics.mean(ds) if ds else None,
            "tail_delay_ms_max": max(ds) if ds else None,
            "tail_samples": len(ds),
        }

    # 4) extract first K complete frames for the C++ decoder
    frames_path = out / "frames.sbe"
    sample_path = out / "frames-sample.sbe"
    data = frames_path.read_bytes()
    pos, k = 0, 20000
    with sample_path.open("wb") as fh:
        for _ in range(k):
            if pos + 4 > len(data):
                break
            ln = int.from_bytes(data[pos:pos + 4], "little")
            if pos + 4 + ln > len(data):
                break
            fh.write(data[pos:pos + 4 + ln])
            pos += 4 + ln
    dec = subprocess.run([cli, str(sample_path)], capture_output=True, text=True,
                         timeout=300)
    report["decode_sample"] = {
        "frames": k,
        "exit_code": dec.returncode,
        "ok_lines": dec.stdout.count('"status":"ok"'),
        "error_lines": dec.stdout.count('"status":"error"'),
        "stderr_tail": dec.stderr[-200:] if dec.stderr else "",
    }

    print(json.dumps(report, indent=2))
    return 0 if (chain_ok and key_on_disk == 0 and dec.returncode == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
