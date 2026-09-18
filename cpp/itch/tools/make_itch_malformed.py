"""Generate the ITCH malformed corpus (deterministic, spec-grounded).

Each malformed vector is a mutation class justified by the captured spec:
  - truncations: buffers shorter than the fixed length of the message type
    (spec tables define fixed lengths per type);
  - unknown message type: type byte not defined by the captured spec tables;
  - price overflow: Price(4) above the spec maximum 200,000.0000
    (0x77359400) (spec page 4 Data Types).

The decoder must return a typed error for each and must never crash. Expected
status codes are recorded per vector so the C++ suite can assert them exactly.
"""
from __future__ import annotations

import json
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
MALFORMED = HERE.parent / "malformed"


def head(msg_type: str, locate: int, tracking: int, ts: int) -> bytes:
    return (
        msg_type.encode("ascii")
        + struct.pack(">HH", locate, tracking)
        + struct.pack(">Q", ts)[2:]
    )


def emit(name: str, body: bytes, expect_status: str, why: str) -> None:
    MALFORMED.mkdir(parents=True, exist_ok=True)
    (MALFORMED / f"{name}.bin").write_bytes(body)
    with open(MALFORMED / f"{name}.expect", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# why={why}\nstatus={expect_status}\n")
    print(f"malformed {name}: {len(body)} bytes -> {expect_status} ({why})")


def main() -> int:
    TS = 34_200_000_000_000

    # A valid 36-byte Add Order as the mutation base.
    add = head("A", 3000, 7, TS + 123_456) + struct.pack(">Q", 100_000)
    add += b"B" + struct.pack(">I", 100) + b"AAPL    " + struct.pack(">I", 48_000_000)

    # Truncations: every shorter-than-fixed-length buffer must be rejected
    # with Truncated, without reading past the buffer.
    emit("truncated_empty", b"", "Truncated", "0 bytes, shorter than any message")
    emit("truncated_type_only", b"A", "Truncated", "type byte only")
    emit("truncated_add_35", add[:35], "Truncated", "Add Order is 36 bytes (spec 1.3.1)")
    emit("truncated_system_event_5", b"S" + b"\x00" * 4, "Truncated",
         "System Event is 12 bytes (spec 1.1)")

    # Unknown message type byte (not in any captured spec table).
    emit("unknown_type_z", head("Z", 3000, 1, TS) + b"\x00" * 24, "UnknownType",
         "type byte 'Z' is not defined by the captured spec tables")

    # Price above the spec maximum 200,000.0000 (0x77359400): 200,000.0001.
    over = head("A", 3000, 7, TS + 123_456) + struct.pack(">Q", 100_000)
    over += b"B" + struct.pack(">I", 100) + b"AAPL    " + struct.pack(">I", 0x77359401)
    emit("price_over_max_add", over, "PriceOutOfRange",
         "price 200,000.0001 > max 200,000.0000 (spec p.4)")

    # Same overflow inside a Trade (Non-Cross) price field.
    tp = head("P", 3000, 17, TS + 10_000) + struct.pack(">Q", 0)
    tp += b"B" + struct.pack(">I", 300) + b"TSLA    " + struct.pack(">I", 0x77359401)
    tp += struct.pack(">Q", 999_999)
    emit("price_over_max_trade", tp, "PriceOutOfRange",
         "price overflow in Trade (Non-Cross), spec max p.4")

    # Truncated Order Replace (35 bytes fixed, spec 1.4.5): 20 bytes.
    rp = head("U", 3000, 16, TS + 9_000) + struct.pack(">Q", 100_000)
    emit("truncated_replace_20", rp + b"\x00" * 1, "Truncated",
         "Order Replace is 35 bytes (spec 1.4.5)")

    manifest = {
        "note": "Malformed corpus generated from the captured spec constraints; "
                "each vector records its justification and expected typed status.",
    }
    (MALFORMED / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("manifest written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
