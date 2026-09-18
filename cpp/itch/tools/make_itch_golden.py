"""Generate ITCH 5.0 golden vectors BYTE-BY-BYTE from the captured official spec.

Nothing is invented: every byte of every vector is laid out per the field
tables of the captured, SHA256-pinned spec
(NQTVITCHSpecification.pdf -> cpp/tools/extracted/NQTVITCHSpecification.txt).
Each vector records the spec sections it instantiates.

Outputs, per vector <name>:
  itch/golden/<name>.bin      raw big-endian wire bytes
  itch/golden/<name>.expect   expected decoded field values (name=value lines)

The C++ test suite (itch/tests/test_itch.cpp) decodes every .bin and compares
every field against the .expect file. Any mismatch = RED.
"""
from __future__ import annotations

import json
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
GOLDEN = HERE.parent / "golden"

# Spec constants (all cited from the captured spec text):
# - Prices are fixed point Price(4): 4 implied decimals (spec page 4).
# - Max price(4) = 200,000.0000 -> 2_000_000_000 (0x77359400) (spec page 4).
PRICE_SCALE = 10_000
PRICE_MAX = 2_000_000_000

# Nanoseconds since midnight examples (spec page 4: "nanoseconds since
# midnight"). 9:30:00.000000000 = 34_200_000_000_000 ns.
TS_OPEN = 34_200_000_000_000


def alpha(s: str, width: int) -> bytes:
    """Alpha field: ASCII, left justified, right padded with spaces (page 4)."""
    assert len(s) <= width, (s, width)
    return s.encode("ascii") + b" " * (width - len(s))


def head(msg_type: str, locate: int, tracking: int, ts: int) -> bytes:
    """Common leading fields of every ITCH message table:
    type(1) | locate(2) | tracking(2) | timestamp(6, ns since midnight).
    """
    return (
        msg_type.encode("ascii")
        + struct.pack(">HH", locate, tracking)
        + struct.pack(">Q", ts)[2:]  # timestamp field is 6 bytes
    )


def price(v: float) -> int:
    iv = int(round(v * PRICE_SCALE))
    assert 0 <= iv <= PRICE_MAX, iv
    return iv


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
    # 1.1 System Event Message — 'O' start of messages (spec page 5 codes).
    emit("sys_event_O", head("S", 0, 42, TS_OPEN) + b"O",
         {"type": "S", "locate": 0, "tracking": 42, "timestamp_ns": TS_OPEN,
          "event_code": "O"},
         "ITCH 1.1 + event codes p.5")
    # 'C' end of messages.
    emit("sys_event_C", head("S", 0, 43, TS_OPEN + 23_400_000_000_000) + b"C",
         {"type": "S", "locate": 0, "tracking": 43,
          "timestamp_ns": TS_OPEN + 23_400_000_000_000, "event_code": "C"},
         "ITCH 1.1 + event codes p.5")

    # 1.3.1 Add Order – No MPID Attribution:
    # A | locate(2) | tracking(2) | ts(6) | ref(8) | side(1) | shares(4) | stock(8) | price(4)
    def add(name, msg, locate, tracking, ts, order_ref, side, shares, stock, px, sections):
        body = head(msg, locate, tracking, ts) + struct.pack(">Q", order_ref)
        body += side.encode("ascii") + struct.pack(">I", shares)
        body += alpha(stock, 8) + struct.pack(">I", price(px))
        emit(name, body, {"type": msg, "locate": locate, "tracking": tracking,
                          "timestamp_ns": ts, "order_ref": order_ref, "side": side,
                          "shares": shares, "stock": stock, "price": price(px)},
             sections)

    add("add_order_buy", "A", 3000, 7, TS_OPEN + 123_456, 100_000, "B", 100,
        "AAPL", 4800.00, "ITCH 1.3.1")
    add("add_order_sell", "A", 3000, 8, TS_OPEN + 999_999, 100_001, "S", 250,
        "MSFT", 410.25, "ITCH 1.3.1")
    # Max legal price: 200,000.0000 (0x77359400, spec p.4 Data Types).
    add("add_order_max_price", "A", 3000, 9, TS_OPEN + 2_000, 100_002, "B", 10,
        "BRKA", 200_000.00, "ITCH 1.3.1 + Data Types p.4")

    # 1.3.2 Add Order with MPID Attribution ('NSDQ' example per spec 1.3.1 note):
    # F | ... | attribution(4)
    body = head("F", 3000, 10, TS_OPEN + 3_000) + struct.pack(">Q", 100_003)
    body += b"B" + struct.pack(">I", 500) + alpha("NVDA", 8)
    body += struct.pack(">I", price(950.50)) + alpha("NSDQ", 4)
    emit("add_order_mpid", body,
         {"type": "F", "locate": 3000, "tracking": 10, "timestamp_ns": TS_OPEN + 3_000,
          "order_ref": 100_003, "side": "B", "shares": 500, "stock": "NVDA",
          "price": price(950.50), "attribution": "NSDQ"},
         "ITCH 1.3.2")

    # 1.4.1 Order Executed: E | locate(2) | tracking(2) | ts(6) | ref(8) | shares(4) | match(8)
    body = head("E", 3000, 11, TS_OPEN + 4_000) + struct.pack(">Q", 100_000)
    body += struct.pack(">I", 40) + struct.pack(">Q", 2_500)
    emit("executed", body,
         {"type": "E", "locate": 3000, "tracking": 11, "timestamp_ns": TS_OPEN + 4_000,
          "order_ref": 100_000, "executed_shares": 40, "match_number": 2_500},
         "ITCH 1.4.1")

    # 1.4.2 Order Executed With Price:
    # C | locate(2) | tracking(2) | ts(6) | ref(8) | shares(4) | match(8) | printable(1) | price(4)
    def exec_price(name, printable, px, ts_off, match, ref, shares, tracking, sections):
        body = head("C", 3000, tracking, TS_OPEN + ts_off) + struct.pack(">Q", ref)
        body += struct.pack(">I", shares) + struct.pack(">Q", match)
        body += printable.encode("ascii") + struct.pack(">I", price(px))
        emit(name, body,
             {"type": "C", "locate": 3000, "tracking": tracking,
              "timestamp_ns": TS_OPEN + ts_off, "order_ref": ref,
              "executed_shares": shares, "match_number": match,
              "printable": printable, "price": price(px)},
             sections)

    exec_price("executed_price_printable", "Y", 4795.00, 5_000, 2_501, 100_000, 25, 12,
               "ITCH 1.4.2")
    exec_price("executed_price_nonprintable", "N", 410.25, 6_000, 2_502, 100_001, 100, 13,
               "ITCH 1.4.2")

    # 1.4.3 Order Cancel: X | locate(2) | tracking(2) | ts(6) | ref(8) | shares(4)
    body = head("X", 3000, 14, TS_OPEN + 7_000) + struct.pack(">Q", 100_000)
    body += struct.pack(">I", 25)
    emit("cancel_partial", body,
         {"type": "X", "locate": 3000, "tracking": 14, "timestamp_ns": TS_OPEN + 7_000,
          "order_ref": 100_000, "cancelled_shares": 25},
         "ITCH 1.4.3")

    # 1.4.4 Order Delete: D | locate(2) | tracking(2) | ts(6) | ref(8)
    body = head("D", 3000, 15, TS_OPEN + 8_000) + struct.pack(">Q", 100_001)
    emit("delete_order", body,
         {"type": "D", "locate": 3000, "tracking": 15, "timestamp_ns": TS_OPEN + 8_000,
          "order_ref": 100_001},
         "ITCH 1.4.4")

    # 1.4.5 Order Replace:
    # U | locate(2) | tracking(2) | ts(6) | orig(8) | new(8) | shares(4) | price(4)
    body = head("U", 3000, 16, TS_OPEN + 9_000) + struct.pack(">Q", 100_000)
    body += struct.pack(">Q", 100_100) + struct.pack(">I", 75)
    body += struct.pack(">I", price(4801.00))
    emit("replace_order", body,
         {"type": "U", "locate": 3000, "tracking": 16, "timestamp_ns": TS_OPEN + 9_000,
          "original_order_ref": 100_000, "new_order_ref": 100_100, "shares": 75,
          "price": price(4801.00)},
         "ITCH 1.4.5")

    # 1.5.1 Trade Message (Non-Cross): order ref null-filled (0) per spec note;
    # side always 'B' per 07/14/2014 note.
    # P | locate(2) | tracking(2) | ts(6) | ref(8) | side(1) | shares(4) | stock(8) | price(4) | match(8)
    body = head("P", 3000, 17, TS_OPEN + 10_000) + struct.pack(">Q", 0)
    body += b"B" + struct.pack(">I", 300) + alpha("TSLA", 8)
    body += struct.pack(">I", price(21_050.50)) + struct.pack(">Q", 999_999)
    emit("trade_non_cross", body,
         {"type": "P", "locate": 3000, "tracking": 17, "timestamp_ns": TS_OPEN + 10_000,
          "order_ref": 0, "side": "B", "shares": 300, "stock": "TSLA",
          "price": price(21_050.50), "match_number": 999_999},
         "ITCH 1.5.1")

    # 1.5.2 Cross Trade: Q | locate(2) | tracking(2) | ts(6) | shares(8) | stock(8)
    #                     | price(4) | match(8) | type(1)
    body = head("Q", 3000, 18, TS_OPEN + 11_000) + struct.pack(">Q", 5_000)
    body += alpha("AAPL", 8) + struct.pack(">I", price(4802.25))
    body += struct.pack(">Q", 2_501) + b"O"
    emit("cross_trade_open", body,
         {"type": "Q", "locate": 3000, "tracking": 18, "timestamp_ns": TS_OPEN + 11_000,
          "shares": 5_000, "stock": "AAPL", "cross_price": price(4802.25),
          "match_number": 2_501, "cross_type": "O"},
         "ITCH 1.5.2")

    # 1.5.3 Broken Trade: B | locate(2) | tracking(2) | ts(6) | match(8)
    body = head("B", 3000, 19, TS_OPEN + 12_000) + struct.pack(">Q", 2_500)
    emit("broken_trade", body,
         {"type": "B", "locate": 3000, "tracking": 19, "timestamp_ns": TS_OPEN + 12_000,
          "match_number": 2_500},
         "ITCH 1.5.3")

    # 1.2.2 Stock Trading Action: H | locate(2) | tracking(2) | ts(6) | stock(8)
    #                             | state(1) | reserved(1) | reason(4)
    body = head("H", 3000, 20, TS_OPEN + 13_000) + alpha("AAPL", 8)
    body += b"T" + b" " + alpha("T12", 4)  # 'T' = Trading on Nasdaq; reason per Appendix C
    emit("trading_action_t", body,
         {"type": "H", "locate": 3000, "tracking": 20, "timestamp_ns": TS_OPEN + 13_000,
          "stock": "AAPL", "trading_state": "T", "reason": "T12"},
         "ITCH 1.2.2 + Appendix C")

    # 1.2.1 Stock Directory:
    # R | locate(2) | tracking(2) | ts(6) | stock(8) | cat(1) | fsi(1) | roundlot(4)
    #   | rlo(1) | iclass(1) | isub(2) | auth(1) | ssti(1) | ipo(1) | luld(1) | etp(1)
    #   | lev(4) | inv(1)
    body = head("R", 3000, 21, TS_OPEN + 14_000) + alpha("AAPL", 8)
    body += b"Q"      # Market Category: Nasdaq Global Select (spec p.5)
    body += b"N"      # Financial Status: Normal (spec p.6)
    body += struct.pack(">I", 100)  # Round Lot Size
    body += b"N"      # Round Lots Only: no size restrictions (spec p.6)
    body += b"C"      # Issue Classification: Common Stock (Appendix D)
    body += alpha("C", 2)  # Issue Sub-Type: Common Shares (Appendix E)
    body += b"P"      # Authenticity: Live/Production (spec p.6)
    body += b"N"      # Short Sale Threshold: not restricted (spec p.7)
    body += b"N"      # IPO Flag: not a new IPO security (spec p.7)
    body += b"1"      # LULD tier 1 NMS stocks (spec p.7)
    body += b"N"      # ETP Flag: not an ETP (spec p.7)
    body += struct.pack(">I", 0)  # ETP Leverage Factor
    body += b"N"      # Inverse Indicator: not inverse (spec p.8)
    emit("stock_directory", body,
         {"type": "R", "locate": 3000, "tracking": 21, "timestamp_ns": TS_OPEN + 14_000,
          "stock": "AAPL", "market_category": "Q", "financial_status": "N",
          "round_lot_size": 100, "round_lots_only": "N",
          "issue_classification": "C", "issue_sub_type": "C",
          "authenticity": "P", "short_sale_threshold": "N", "ipo_flag": "N",
          "luld_reference_price_tier": "1", "etp_flag": "N",
          "etp_leverage_factor": 0, "inverse_indicator": "N"},
         "ITCH 1.2.1 + Appendix D/E")

    manifest = {
        "source_pdf": "external-review/low-latency-reference/nasdaq-specs/NQTVITCHSpecification.pdf",
        "source_sha256": "45E0531D1B4B3BEB886E9618B2AB824A5AA9BDA3A99C0DFF03509306E68AACC3",
        "note": "Golden vectors constructed byte-by-byte from the captured spec field tables; section citations per vector.",
    }
    (GOLDEN / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("manifest written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
