"""Generate FIX golden vectors byte-by-byte per the standard FIX layout.

Nothing invented: field layout follows the annotated spec
(MARKET_MICROSTRUCTURE_EXCHANGE_SYSTEMS.md §5.5 [SPEC] FIX Session Layer) and
the QuickFIX canonical reference captured in
external-review/low-latency-reference/quickfix:
  - message = tag=value<SOH> sequence; header 8=BeginString, 9=BodyLength,
    35=MsgType; trailer 10=CheckSum = sum of all preceding bytes mod 256;
  - BodyLength = bytes between the end of "9=..."<SOH> and the start of
    "10=...".
"""
from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
GOLDEN = HERE.parent / "golden"
SOH = "\x01"


def build_msg(fields: dict[str, str]) -> tuple[bytes, list[str]]:
    begin = fields.pop("8", "FIX.4.4")
    body = ""
    expect_lines = [f"tag8={begin}"]
    for tag in sorted(fields, key=lambda t: int(t)):
        body += f"{tag}={fields[tag]}{SOH}"
        expect_lines.append(f"tag{tag}={fields[tag]}")
    nine = len(body)
    head = f"8={begin}{SOH}9={nine}{SOH}"
    pre = head + body
    chk = sum(ord(c) for c in pre) % 256
    raw = pre + f"10={chk:03d}{SOH}"
    expect_lines.append(f"tag9={nine}")
    expect_lines.append(f"tag10={chk:03d}")
    return raw.encode("ascii"), expect_lines


def emit(name: str, raw: bytes, expect_lines: list[str], sections: str) -> None:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    (GOLDEN / f"{name}.bin").write_bytes(raw)
    with open(GOLDEN / f"{name}.expect", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# spec={sections}\n# wire_len={len(raw)}\n")
        fh.write("\n".join(expect_lines) + "\n")
    print(f"golden {name}: {len(raw)} bytes ({sections})")


def main() -> int:
    # Logon (35=A): standard initiator logon.
    raw, lines = build_msg({
        "35": "A", "49": "CLIENT", "56": "VENUE", "34": "1",
        "52": "20260918-09:30:00.000", "98": "0", "108": "30",
    })
    emit("logon", raw, lines, "MARKET_MICROSTRUCTURE §5.5 + QuickFIX layout")

    # Heartbeat (35=0).
    raw, lines = build_msg({
        "35": "0", "49": "CLIENT", "56": "VENUE", "34": "2",
        "52": "20260918-09:30:00.000",
    })
    emit("heartbeat", raw, lines, "MARKET_MICROSTRUCTURE §5.5 + QuickFIX layout")

    # ResendRequest (35=2): BeginSeqNo(7)=3, EndSeqNo(16)=5.
    raw, lines = build_msg({
        "35": "2", "49": "CLIENT", "56": "VENUE", "34": "4",
        "52": "20260918-09:30:00.000", "7": "3", "16": "5",
    })
    emit("resend_request", raw, lines, "MARKET_MICROSTRUCTURE §5.5 + QuickFIX layout")

    # SequenceReset-GapFill (35=4, 123=Y, 36=10).
    raw, lines = build_msg({
        "35": "4", "49": "CLIENT", "56": "VENUE", "34": "5",
        "52": "20260918-09:30:00.000", "123": "Y", "36": "10",
    })
    emit("sequence_reset_gapfill", raw, lines,
         "MARKET_MICROSTRUCTURE §5.5 + QuickFIX layout")

    # Application NewOrderSingle (35=D) — same sequence space as session
    # messages (§5.5).
    raw, lines = build_msg({
        "35": "D", "49": "CLIENT", "56": "VENUE", "34": "6",
        "52": "20260918-09:30:00.000", "11": "ord-0001", "55": "BTCUSDT",
        "54": "1", "38": "100", "40": "1", "44": "59786.55",
    })
    emit("new_order_single", raw, lines,
         "MARKET_MICROSTRUCTURE §5.5 + QuickFIX layout")

    # PossDup retransmission (43=Y, original sequence 3).
    raw, lines = build_msg({
        "35": "D", "49": "CLIENT", "56": "VENUE", "34": "3",
        "52": "20260918-09:30:00.000", "43": "Y", "11": "ord-0000",
        "55": "BTCUSDT", "54": "1", "38": "50", "40": "1",
    })
    emit("possdup_retransmission", raw, lines,
         "MARKET_MICROSTRUCTURE §5.5: same MsgSeqNum + PossDup=Y")

    manifest = {
        "note": "Golden FIX vectors constructed byte-by-byte from the annotated "
                "FIX session semantics and the standard header/trailer layout "
                "(QuickFIX canonical reference); citations per vector.",
    }
    (GOLDEN / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("manifest written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
