"""SBE lane tests (FASE 7 executable): capture pipeline against a LOCAL mock
SBE server, journal integrity and decode verification via the C++ CLI.

Runs WITHOUT any Binance key: the mock serves the official-encoder golden
frames (cpp/sbe/golden/*.bin) over a local websocket. The live run only adds
the pinned endpoint + the Ed25519 key (see RUNBOOK_SBE_LANE.md).

Spec grounding (nothing invented): sbe-market-data-streams.md (captured,
SHA256 3E945F52…): binary SBE frames, ping every 20 s with pong echo,
serverShutdown JSON event, API key in X-MBX-APIKEY header. The lane journal
keeps its OWN epochs (never merged with JSON lanes) per
CAPTURE_CAMPAIGN_POLICY_V1.md §Feed evolution.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import pathlib
import statistics
import subprocess
import sys
import threading
import unittest

import websockets

HERE = pathlib.Path(__file__).resolve().parent
LANE_DIR = HERE.parent
ROOT = LANE_DIR.parent  # cpp/ root
sys.path.insert(0, str(LANE_DIR))

import sbe_lane  # noqa: E402

GOLDEN = ROOT / "sbe" / "golden"
CLI = ROOT / "build" / "bin" / ("sbe_decode_cli.exe" if os.name == "nt" else "sbe_decode_cli")

FRAME_FILES = ["trades_stream.bin", "depth_diff.bin", "best_bid_ask.bin"]


def _golden_bytes(name: str) -> bytes:
    return (GOLDEN / name).read_bytes()


def _lane_env(out: pathlib.Path) -> dict[str, str]:
    env = dict(os.environ)
    env["SBE_LANE_DECODE_CLI"] = str(CLI)
    return env


class MockSbeServer:
    """Local websocket server speaking the SBE stream protocol surface."""

    def __init__(self, frames: list[bytes], shutdown_json: bool = False):
        self.frames = frames
        self.shutdown_json = shutdown_json
        self.saw_pong = False
        self.port = 0
        self._ready = threading.Event()
        self._server = None

    async def _handler(self, ws):
        if self.frames is None:
            return
        # Spec: server pings; client must pong (echo handled by library).
        try:
            pong_waiter = await ws.ping()
            await asyncio.wait_for(pong_waiter, timeout=5)
            self.saw_pong = True
        except Exception:
            pass
        for frame in self.frames:
            await ws.send(frame)
        if self.shutdown_json:
            await ws.send(json.dumps({"e": "serverShutdown", "E": 1789769000000}))
        await asyncio.sleep(0.5)

    def start(self):
        # Own event loop on a daemon thread: no accept/close race on Windows
        # Proactor and no explicit stop needed.
        thread = threading.Thread(target=self._run_loop, daemon=True)
        thread.start()
        if not self._ready.wait(timeout=10):
            raise RuntimeError("mock server did not start")

    def _run_loop(self):
        asyncio.run(self._serve())

    async def _serve(self):
        self._loop = asyncio.get_running_loop()
        self._server = await websockets.serve(self._handler, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        await self._server.wait_closed()  # runs until process exit


def _run_lane(out: pathlib.Path, url: str, duration_s: float, env: dict) -> dict:
    result = {"ok": False, "code": None, "stdout": "", "stderr": ""}
    proc = subprocess.run(
        [sys.executable, str(LANE_DIR / "sbe_lane.py"),
         "--url", url, "--out", str(out), "--duration", str(duration_s)],
        capture_output=True, text=True, env=env, timeout=120,
    )
    result["code"] = proc.returncode
    result["stdout"] = proc.stdout
    result["stderr"] = proc.stderr
    result["ok"] = proc.returncode == 0
    return result


def _read_journal(out: pathlib.Path) -> list[dict]:
    rows = []
    path = out / "sbe-events.jsonl"
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _verify_chain(rows: list[dict]) -> bool:
    prev = None
    for row in rows:
        body = row.get("body", {})
        if body.get("previous_record_sha256") != (prev if prev is not None else None):
            return False
        payload = body.get("payload", {})
        digest_src = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if row.get("record_sha256") != hashlib.sha256(digest_src.encode()).hexdigest():
            return False
        prev = row["record_sha256"]
    return True


class SbeLaneTests(unittest.TestCase):

    def test_capture_roundtrip_and_decode_cli(self):
        frames = [_golden_bytes(n) for n in FRAME_FILES]
        with tempdir() as tmp:
            out = tmp / "lane"
            mock = MockSbeServer(frames)
            mock.start()
            res = _run_lane(out, f"ws://127.0.0.1:{mock.port}", 3.0, _lane_env(out))
            self.assertTrue(res["ok"], res["stderr"])
            rows = _read_journal(out)
            self.assertTrue(rows, "journal missing")
            self.assertTrue(_verify_chain(rows), "journal hash chain broken")
            # Every golden frame must be captured byte-identical.
            stored = (out / "frames.sbe").read_bytes()
            for frame in frames:
                self.assertIn(frame, stored)
            # Typed lifecycle: start and clean end.
            events = [r["body"]["payload"].get("event") for r in rows]
            self.assertIn("LANE_START", events)
            self.assertIn("LANE_END", events)
            # Decode verification via the C++ CLI.
            self.assertTrue(CLI.exists(), f"CLI missing: {CLI}")
            dec = subprocess.run(
                [str(CLI), str(out / "frames.sbe")], capture_output=True, text=True,
                timeout=60,
            )
            self.assertEqual(dec.returncode, 0, dec.stderr)
            lines = [json.loads(l) for l in dec.stdout.splitlines() if l.strip()]
            self.assertEqual(len(lines), 3)
            ids = [l["template_id"] for l in lines]
            self.assertEqual(ids, [10000, 10003, 10001])
            # Per-frame end-to-end telemetry: venue event_time_us extracted
            # from every frame (first schema field, offset 8) + local recv.
            tel = [
                json.loads(l)
                for l in (out / "sbe-telemetry.jsonl").read_text().splitlines()
                if l.strip()
            ]
            self.assertEqual(len(tel), 3)
            self.assertEqual(tel[0]["event_time_us"], 1726700000000000)
            self.assertEqual(tel[1]["event_time_us"], 1726700000300000)
            self.assertEqual(tel[2]["event_time_us"], 1726700000100000)

    def test_measure_script_math_deterministic(self):
        # Synthetic telemetry with a known clock offset: the wire-leg delays
        # must be computed exactly (recv - event - offset).
        with tempdir() as tmp:
            out = tmp / "lane"
            out.mkdir(parents=True)
            rows = [
                {"index": 0, "template_id": 10000,
                 "event_time_us": 1726700000000000,
                 "recv_wall_ms": 1726700000010, "recv_monotonic_ns": 0},
                {"index": 1, "template_id": 10000,
                 "event_time_us": 1726700000000000,
                 "recv_wall_ms": 1726700000015, "recv_monotonic_ns": 0},
            ]
            (out / "sbe-telemetry.jsonl").write_text(
                "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            # offset = 5 ms -> delays = 10-0-5=5 and 15-0-5=10; nearest-rank
            # p50 over two samples picks the upper median -> 10.0
            meas = subprocess.run(
                [sys.executable, str(LANE_DIR / "measure_sbe_lane.py"),
                 "--dir", str(out), "--offset", "5",
                 "--out", str(out / "measure.json")],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(meas.returncode, 0, meas.stderr)
            report = json.loads((out / "measure.json").read_text())
            self.assertEqual(report["frames"], 2)
            self.assertEqual(report["wire_leg"]["10000"]["delay_ms_p50"], 10.0)
            self.assertEqual(
                report["wire_leg"]["10000"]["delay_ms_mean"], 7.5)
            self.assertEqual(
                report["wire_leg"]["10000"]["inter_arrival_ms_p50"], 5.0)

    def test_ping_pong_and_server_shutdown_typed(self):
        frames = [_golden_bytes("depth_diff.bin")]
        with tempdir() as tmp:
            out = tmp / "lane"
            mock = MockSbeServer(frames, shutdown_json=True)
            mock.start()
            res = _run_lane(out, f"ws://127.0.0.1:{mock.port}", 5.0, _lane_env(out))
            self.assertTrue(res["ok"], res["stderr"])
            self.assertTrue(mock.saw_pong, "client did not answer the server ping")
            rows = _read_journal(out)
            events = [r["body"]["payload"].get("event") for r in rows]
            self.assertIn("SERVER_SHUTDOWN", events)
            self.assertTrue(_verify_chain(rows))

    def test_reconnect_types_the_gap(self):
        frames = [_golden_bytes("trades_stream.bin")]
        with tempdir() as tmp:
            out = tmp / "lane"
            m1 = MockSbeServer(frames, shutdown_json=True)
            m2 = MockSbeServer(frames, shutdown_json=False)
            m1.start()
            m2.start()
            # Lane reconnects to m2 after m1's serverShutdown; the wall
            # hole between the two connections must be TYPED.
            res = _run_lane(
                out, f"ws://127.0.0.1:{m1.port}|ws://127.0.0.1:{m2.port}", 8.0,
                _lane_env(out),
            )
            self.assertTrue(res["ok"], res["stderr"])
            rows = _read_journal(out)
            events = [r["body"]["payload"].get("event") for r in rows]
            self.assertIn("SERVER_SHUTDOWN", events)
            self.assertIn("GAP_TYPED", events)
            self.assertTrue(_verify_chain(rows))


class _TempDir:
    def __init__(self, path: pathlib.Path):
        self.path = path

    def __enter__(self):
        return self.path

    def __exit__(self, *exc):
        import shutil
        shutil.rmtree(self.path, ignore_errors=True)


def tempdir():
    import tempfile as _tempfile
    return _TempDir(pathlib.Path(_tempfile.mkdtemp(prefix="sbe-lane-test-")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
