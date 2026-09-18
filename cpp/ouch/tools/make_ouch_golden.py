"""Generate OUCH 5.0 golden vectors byte-by-byte from the captured official spec.

Nothing is invented: field layouts follow the captured, SHA256-pinned spec
(OUCH5.0.pdf -> cpp/tools/extracted/OUCH5.0.txt). Section citations per vector.

Vectors:
  inbound_enter.bin    2.1 Type O - Enter Order (46-byte base, no appendage)
  inbound_replace.bin  2.2 Type U - Replace Order (40-byte base)
  inbound_cancel.bin   2.3 Type X - Cancel Order (11-byte base)
  outbound_accepted.bin  3.2 Type A - Order Accepted (64 bytes)
  outbound_replaced.bin  3.3 Type U - Order Replaced (68 bytes)
  outbound_canceled.bin  3.4 Type C - Order Canceled (20 bytes)
  outbound_executed.bin  3.6 Type E - Order Executed (36 bytes)
  outbound_rejected.bin  3.8 Type J - Rejected (31 bytes)

Data types per spec 1.2: alphas left-justified space-padded; numerics
big-endian (Long 8 / Integer 4 / Short 2 / Byte 1); prices unsigned fixed
point with implied 4 decimals; timestamps ns since midnight.
"""
from __future__ import annotations

import json
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
GOLDEN = HERE.parent / "golden"

TS = 34_200_000_000_000  # 9:30:00 in ns since midnight (spec 1.2)


def alpha(s: str, width: int) -> bytes:
    return s.encode("ascii") + b" " * (width - len(s))


def emit(name: str, body: bytes, expect: dict, sections: str) -> None:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    (GOLDEN / f"{name}.bin").write_bytes(body)
    lines = [f"# spec={sections}", f"# wire_len={len(body)}"]
    for k, v in expect.items():
        lines.append(f"{k}={v}")
    with open(GOLDEN / f"{name}.expect", "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"golden {name}: {len(body)} bytes ({sections})")


def main() -> int:
    # --- 2.1 Type O - Enter Order -------------------------------------------
    # O | UserRefNum(4) | Side(1) | Quantity(4) | Symbol(8) | Price(8)
    #   | TIF(1) | Display(1) | Capacity(1) | ISE(1) | CrossType(1)
    #   | ClOrdID(14) | AppendageLen(2) | Appendage(var)
    enter = b"O" + struct.pack(">I", 5) + b"B" + struct.pack(">I", 500)
    enter += alpha("NVDA", 8) + struct.pack(">Q", 9_505_000)  # 950.5000
    enter += b"0" + b"Y" + b"A" + b"N" + b"N"
    enter += alpha("clid-001", 14) + struct.pack(">H", 0)
    emit("inbound_enter", enter,
         {"type": "O", "user_ref_num": 5, "side": "B", "quantity": 500,
          "symbol": "NVDA", "price": 9_505_000, "time_in_force": "0",
          "display": "Y", "capacity": "A", "intermkt_sweep": "N",
          "cross_type": "N", "cl_ord_id": "clid-001", "appendage_len": 0},
         "OUCH 2.1")

    # --- 2.2 Type U - Replace Order ------------------------------------------
    # U | OrigUserRefNum(4) | UserRefNum(4) | Quantity(4) | Price(8)
    #   | TIF(1) | Display(1) | ISE(1) | ClOrdID(14) | AppendageLen(2)
    replace = b"U" + struct.pack(">I", 5) + struct.pack(">I", 6)
    replace += struct.pack(">I", 600) + struct.pack(">Q", 9_510_000)
    replace += b"0" + b"Y" + b"N" + alpha("clid-002", 14) + struct.pack(">H", 0)
    emit("inbound_replace", replace,
         {"type": "U", "orig_user_ref_num": 5, "user_ref_num": 6,
          "quantity": 600, "price": 9_510_000, "time_in_force": "0",
          "display": "Y", "intermkt_sweep": "N", "cl_ord_id": "clid-002",
          "appendage_len": 0},
         "OUCH 2.2")

    # --- 2.3 Type X - Cancel Order -------------------------------------------
    # X | UserRefNum(4) | Quantity(4) | AppendageLen(2) | Appendage(var)
    cancel = b"X" + struct.pack(">I", 6) + struct.pack(">I", 0)
    cancel += struct.pack(">H", 0)
    emit("inbound_cancel", cancel,
         {"type": "X", "user_ref_num": 6, "quantity": 0, "appendage_len": 0},
         "OUCH 2.3")

    # --- 3.2 Type A - Order Accepted -----------------------------------------
    # A | Timestamp(8) | UserRefNum(4) | Side(1) | Quantity(4) | Symbol(8)
    #   | Price(8) | TIF(1) | Display(1) | OrderRefNum(8) | Capacity(1)
    #   | ISE(1) | CrossType(1) | OrderState(1) | ClOrdID(14) | AppendageLen(2)
    acc = b"A" + struct.pack(">Q", TS) + struct.pack(">I", 5) + b"B"
    acc += struct.pack(">I", 500) + alpha("NVDA", 8) + struct.pack(">Q", 9_505_000)
    acc += b"0" + b"Y" + struct.pack(">Q", 1234) + b"A" + b"N" + b"N" + b"L"
    acc += alpha("clid-001", 14) + struct.pack(">H", 0)
    emit("outbound_accepted", acc,
         {"type": "A", "timestamp_ns": TS, "user_ref_num": 5, "side": "B",
          "quantity": 500, "symbol": "NVDA", "price": 9_505_000,
          "time_in_force": "0", "display": "Y", "order_ref_num": 1234,
          "capacity": "A", "intermkt_sweep": "N", "cross_type": "N",
          "order_state": "L", "cl_ord_id": "clid-001", "appendage_len": 0},
         "OUCH 3.2")

    # --- 3.3 Type U - Order Replaced ------------------------------------------
    # U | Timestamp(8) | OrigUserRefNum(4) | UserRefNum(4) | Side(1)
    #   | Quantity(4) | Symbol(8) | Price(8) | TIF(1) | Display(1)
    #   | OrderRefNum(8) | Capacity(1) | ISE(1) | CrossType(1) | OrderState(1)
    #   | ClOrdID(14) | AppendageLen(2)
    rep = b"U" + struct.pack(">Q", TS + 1000) + struct.pack(">I", 5)
    rep += struct.pack(">I", 6) + b"B" + struct.pack(">I", 400)
    rep += alpha("NVDA", 8) + struct.pack(">Q", 9_510_000) + b"0" + b"Y"
    rep += struct.pack(">Q", 1235) + b"A" + b"N" + b"N" + b"L"
    rep += alpha("clid-002", 14) + struct.pack(">H", 0)
    emit("outbound_replaced", rep,
         {"type": "U", "timestamp_ns": TS + 1000, "orig_user_ref": 5,
          "user_ref_num": 6, "side": "B", "quantity": 400, "symbol": "NVDA",
          "price": 9_510_000, "time_in_force": "0", "display": "Y",
          "order_ref_num": 1235, "capacity": "A", "intermkt_sweep": "N",
          "cross_type": "N", "order_state": "L", "cl_ord_id": "clid-002",
          "appendage_len": 0},
         "OUCH 3.3")

    # --- 3.4 Type C - Order Canceled -----------------------------------------
    # C | Timestamp(8) | UserRefNum(4) | Quantity(4) | Reason(1)
    #   | AppendageLen(2) | Appendage(var)
    cxl = b"C" + struct.pack(">Q", TS + 2000) + struct.pack(">I", 6)
    cxl += struct.pack(">I", 300) + b"U" + struct.pack(">H", 0)
    emit("outbound_canceled", cxl,
         {"type": "C", "timestamp_ns": TS + 2000, "user_ref_num": 6,
          "quantity": 300, "reason": "U", "appendage_len": 0},
         "OUCH 3.4")

    # --- 3.6 Type E - Order Executed ------------------------------------------
    # E | Timestamp(8) | UserRefNum(4) | Quantity(4) | Price(8)
    #   | LiquidityFlag(1) | MatchNumber(8) | AppendageLen(2)
    exe = b"E" + struct.pack(">Q", TS + 3000) + struct.pack(">I", 6)
    exe += struct.pack(">I", 100) + struct.pack(">Q", 9_510_000) + b"R"
    exe += struct.pack(">Q", 888) + struct.pack(">H", 0)
    emit("outbound_executed", exe,
         {"type": "E", "timestamp_ns": TS + 3000, "user_ref_num": 6,
          "quantity": 100, "price": 9_510_000, "liquidity_flag": "R",
          "match_number": 888, "appendage_len": 0},
         "OUCH 3.6")

    # --- 3.8 Type J - Rejected ------------------------------------------------
    # J | Timestamp(8) | UserRefNum(4) | Reason(2) | ClOrdID(14)
    #   | AppendageLen(2)
    rej = b"J" + struct.pack(">Q", TS + 4000) + struct.pack(">I", 7)
    rej += struct.pack(">H", 102) + alpha("clid-003", 14) + struct.pack(">H", 0)
    emit("outbound_rejected", rej,
         {"type": "J", "timestamp_ns": TS + 4000, "user_ref_num": 7,
          "reason": 102, "cl_ord_id": "clid-003", "appendage_len": 0},
         "OUCH 3.8 + Appendix D")

    manifest = {
        "source_pdf": "external-review/low-latency-reference/nasdaq-specs/OUCH5.0.pdf",
        "source_sha256": "770253DE8B257AB68700AB5DBF179F806D890890683BF695AB8257585D8C2C00",
        "note": "Golden vectors constructed byte-by-byte from the captured spec field tables; section citations per vector.",
    }
    (GOLDEN / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("manifest written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
