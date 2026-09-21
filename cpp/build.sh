#!/usr/bin/env bash
# build.sh — builds and runs the C++ suites on Linux (PHASE 6 CI leg).
# Mirrors build.ps1 (Windows/MSVC) with g++.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PHASE="${1:-all}"
MODE="${2:-release}"
BIN="$ROOT/build/bin"
mkdir -p "$BIN"

CXX="${CXX:-g++}"
OPT="-O2"
WARN="-Wall -Wextra"
STD="-std=c++20"
INC="-I$ROOT"

compile() {
    local out="$1"; shift
    "$CXX" $WARN $STD $OPT $INC "$@" -o "$out" -pthread
}

gen_goldens() {
    local tool="$1"
    echo "== regenerating vectors ($tool) =="
    python3 "$tool"
}

build_itch() {
    gen_goldens "$ROOT/itch/tools/make_itch_golden.py"
    gen_goldens "$ROOT/itch/tools/make_itch_malformed.py"
    compile "$BIN/test_itch" -I"$ROOT/itch/include" \
        "$ROOT/itch/tests/test_itch.cpp" "$ROOT/itch/src/itch_codec.cpp"
    "$BIN/test_itch" "$ROOT"
}

build_sbe() {
    # The pinned schema is vendored at cpp/sbe/schema/stream_1_0.xml and the
    # official generated headers at cpp/tools/sbe-tool/gen (committed). If
    # java + the pinned sbe-all jar are present, golden vectors are
    # REGENERATED with the official tool; otherwise the committed goldens
    # remain valid (same pinned schema bytes).
    if command -v java >/dev/null 2>&1 && [ -f "$ROOT/tools/sbe-tool/sbe-all-1.35.1.jar" ]; then
        mkdir -p "$ROOT/tools/sbe-tool/gen"
        java -Dsbe.output.dir="$ROOT/tools/sbe-tool/gen" -Dsbe.target.language=Cpp \
            -jar "$ROOT/tools/sbe-tool/sbe-all-1.35.1.jar" \
            "$ROOT/sbe/schema/stream_1_0.xml" || true
    fi
    compile "$BIN/make_sbe_golden" -I"$ROOT/tools/sbe-tool/gen" \
        "$ROOT/sbe/tools/make_sbe_golden.cpp"
    "$BIN/make_sbe_golden" "$ROOT/sbe/golden"
    gen_goldens "$ROOT/sbe/tools/make_sbe_malformed.py"
    compile "$BIN/test_sbe" -I"$ROOT/sbe/include" -I"$ROOT/tools/sbe-tool/gen" \
        "$ROOT/sbe/tests/test_sbe.cpp" "$ROOT/sbe/src/binance_sbe.cpp"
    "$BIN/test_sbe" "$ROOT"
}

build_ouch() {
    gen_goldens "$ROOT/ouch/tools/make_ouch_golden.py"
    compile "$BIN/test_ouch" -I"$ROOT/ouch/include" \
        "$ROOT/ouch/tests/test_ouch.cpp" "$ROOT/ouch/src/ouch_codec.cpp"
    "$BIN/test_ouch" "$ROOT"
}

build_net() {
    compile "$BIN/test_mcast" -I"$ROOT/net/include" -I"$ROOT/sbe/include" \
        "$ROOT/net/tests/test_mcast.cpp" "$ROOT/net/src/mcast_feed.cpp"
    "$BIN/test_mcast" "$ROOT"
}

build_recovery() {
    compile "$BIN/test_recovery" -I"$ROOT/recovery/include" -I"$ROOT/sbe/include" \
        -I"$ROOT/net/include" -I"$ROOT/tools/sbe-tool/gen" \
        "$ROOT/recovery/tests/test_recovery.cpp" "$ROOT/recovery/src/feed_guard.cpp" \
        "$ROOT/sbe/src/binance_sbe.cpp" "$ROOT/net/src/mcast_feed.cpp"
    "$BIN/test_recovery" "$ROOT"
}

build_resilience() {
    compile "$BIN/test_resilience" -I"$ROOT/resilience/include" \
        -I"$ROOT/recovery/include" -I"$ROOT/net/include" \
        "$ROOT/resilience/tests/test_resilience.cpp" \
        "$ROOT/resilience/src/layered_capture.cpp"
    "$BIN/test_resilience" "$ROOT"
}

build_fix() {
    gen_goldens "$ROOT/fix/tools/make_fix_golden.py"
    compile "$BIN/test_fix" -I"$ROOT/fix/include" \
        "$ROOT/fix/tests/test_fix_session.cpp" "$ROOT/fix/src/fix_session.cpp"
    "$BIN/test_fix" "$ROOT"
}

build_sbelane() {
    compile "$BIN/sbe_decode_cli" -I"$ROOT/sbe/include" \
        "$ROOT/sbe-lane/sbe_decode_cli.cpp" "$ROOT/sbe/src/binance_sbe.cpp"
}

build_bench() {
    compile "$BIN/test_hdr" \
        "$ROOT/bench/tests/test_hdr.cpp"
    "$BIN/test_hdr" "$ROOT"
    compile "$BIN/hdr_cli" \
        "$ROOT/bench/tools/hdr_cli.cpp"
    python3 "$ROOT/bench/tools/crosscheck_hdr.py" \
        --exe "$BIN/hdr_cli" \
        --out "$ROOT/bench/tools/crosscheck_report.json" \
        --evidence "$ROOT/evidence/10-latency-elite/PHASE 1"
}

build_spsc() {
    compile "$BIN/test_spsc" -I"$ROOT/net/include" \
        "$ROOT/net/tests/test_spsc.cpp"
    "$BIN/test_spsc" "$ROOT"
}

case "$PHASE" in
    itch) build_itch ;;
    sbe) build_sbe ;;
    ouch) build_ouch ;;
    net) build_net ;;
    recovery) build_recovery ;;
    resilience) build_resilience ;;
    fix) build_fix ;;
    sbelane) build_sbelane ;;
    bench) build_bench ;;
    spsc) build_spsc ;;
    all)
        build_itch
        build_sbe
        build_ouch
        build_net
        build_recovery
        build_resilience
        build_fix
        build_sbelane
        build_bench
        build_spsc
        ;;
    *)
        echo "unknown phase: $PHASE" >&2
        exit 2
        ;;
esac

echo "== ALL PHASES GREEN =="
