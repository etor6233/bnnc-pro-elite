"""Generate the SBE malformed corpus (deterministic, schema-grounded).

Mutation classes justified by the pinned schema (stream_1_0.xml) and the SBE
wire format (messageHeader + group dimensions + varString8). The decoder must
return the exact typed status per vector and never crash.
"""
from __future__ import annotations

import json
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
MALFORMED = HERE.parent / "malformed"

SCHEMA_ID = 1
VERSION = 0
TPL_TRADES = 10000
TPL_BBA = 10001


def header(block: int, tpl: int, schema: int = SCHEMA_ID, ver: int = VERSION) -> bytes:
    return struct.pack("<HHHH", block, tpl, schema, ver)


def emit(name: str, body: bytes, expect_status: str, why: str) -> None:
    MALFORMED.mkdir(parents=True, exist_ok=True)
    (MALFORMED / f"{name}.bin").write_bytes(body)
    with open(MALFORMED / f"{name}.expect", "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# why={why}\nstatus={expect_status}\n")
    print(f"malformed {name}: {len(body)} bytes -> {expect_status} ({why})")


def main() -> int:
    # Valid TradesStreamEvent body as mutation base (schema layout):
    # eventTime(8) transactTime(8) priceExp(1) qtyExp(1) [block=18]
    # group: blockLen u16 =25, numInGroup u32, then entries of 25 bytes
    # varString8: len u8 + bytes
    base_body = struct.pack("<qqbb", 1_726_700_000_000_000, 1_726_700_000_012_345, -2, -5)
    base_group = struct.pack("<HI", 25, 1)  # 1 trade
    base_entry = struct.pack("<qqqB", 700_000_001, 5_978_655, 12_345, 1)
    base_var = b"\x07BTCUSDT"
    base = header(18, TPL_TRADES) + base_body + base_group + base_entry + base_var

    emit("empty", b"", "Truncated", "0 bytes: shorter than the 8-byte message header")
    emit("header_only", base[:8], "Truncated",
         "message header without any root field bytes")
    emit("truncated_root_fields", base[:20], "Truncated",
         "cut inside the root block (blockLength=18)")
    emit("truncated_group", base[:38], "Truncated",
         "cut inside the trades group entries")
    emit("truncated_var_string", base[:-3], "Truncated",
         "varString8 length byte claims more bytes than the buffer holds")
    emit("unknown_template", header(18, 9999) + base_body, "UnknownTemplate",
         "templateId 9999 is not in the pinned schema (ids 10000..10003)")
    emit("schema_mismatch", header(18, TPL_TRADES, schema=2), "SchemaMismatch",
         "schemaId 2 != pinned schemaId 1")
    emit("version_mismatch", header(18, TPL_TRADES, ver=1), "SchemaMismatch",
         "version 1 != pinned version 0")
    emit("huge_group_count", header(18, TPL_TRADES) + base_body +
         struct.pack("<HI", 25, 1_000_000) + base_entry + base_var, "Truncated",
         "numInGroup=1000000 cannot fit in the buffer")
    emit("bad_block_length", header(0, TPL_BBA) + b"\x00" * 60, "InvalidLayout",
         "blockLength 0 is smaller than the BestBidAskStreamEvent root fields")
    emit("bad_group_block_length", header(18, TPL_TRADES) + base_body +
         struct.pack("<HI", 10, 1) + base_entry + base_var, "InvalidLayout",
         "trades group blockLength 10 < 25 (schema layout)")

    manifest = {
        "note": "Malformed corpus generated from the pinned schema constraints; "
                "each vector records its justification and expected typed status.",
    }
    (MALFORMED / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("manifest written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
