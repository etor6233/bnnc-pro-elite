"""Live handshake check: proves whether a given key value is accepted by the
SBE endpoint. Without a key -> 400; with the right API Key -> 101.

Usage: set BINANCE_SBE_API_KEY (or pass as argv[1]) with the VALUE from the
portal's "API Key" field (whatever the variable is called).
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

import websockets


async def main() -> int:
    url = "wss://stream-sbe.binance.com:9443/ws/btcusdt@depth@20ms"
    key = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("BINANCE_SBE_API_KEY", "")
    extra = {"X-MBX-APIKEY": key} if key else {}
    try:
        async with websockets.connect(url, ping_interval=None, open_timeout=15,
                                      additional_headers=extra) as ws:
            print(json.dumps({
                "endpoint": url,
                "key_provided": bool(key),
                "key_value_length": len(key),
                "result": "ACCEPTED_101",
                "note": "the value works: it is the right API Key",
            }, indent=2))
            # Close right away; the real capture lane does the rest.
            await ws.close()
            return 0
    except websockets.exceptions.InvalidStatus as exc:
        print(json.dumps({
            "endpoint": url,
            "key_provided": bool(key),
            "key_value_length": len(key),
            "result": "REJECTED",
            "http_status": exc.response.status_code,
            "reason_phrase": exc.response.reason_phrase,
            "note": "this value is NOT the portal API Key (or key disabled/restricted)",
        }, indent=2))
        return 1
    except Exception as exc:
        print(json.dumps({"result": "other_error", "error": str(exc)[:300]}))
        return 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
