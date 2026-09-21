#!/usr/bin/env bash
# run_benchmarks.sh — Linux mirror of run_benchmarks.ps1 (PHASE 5 CI leg).
# Builds and runs the measured benchmark suite in dev mode (fast) and final
# mode (held-out sizes). Every number lands in bench/benchmarks/*.json;
# nothing is estimated. PHASE 1 adds the HDR percentile reports (bench_*_hdr.json).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CPP_ROOT="$(dirname "$ROOT")"
MODE="${1:-both}"
BIN="$CPP_ROOT/build/bin"
OUT="$ROOT/benchmarks"
mkdir -p "$BIN" "$OUT"

CXX="${CXX:-g++}"
WARN="-Wall -Wextra"
STD="-std=c++20"
OPT="-O2"

compile() {
    local out="$1"; shift
    "$CXX" $WARN $STD $OPT -I"$CPP_ROOT" "$@" -o "$out" -pthread
}

compile "$BIN/bench_itch" -I"$CPP_ROOT/itch/include" \
    "$ROOT/bench_itch.cpp" "$CPP_ROOT/itch/src/itch_codec.cpp"
compile "$BIN/bench_sbe" -I"$CPP_ROOT/sbe/include" -I"$CPP_ROOT/tools/sbe-tool/gen" \
    "$ROOT/bench_sbe.cpp" "$CPP_ROOT/sbe/src/binance_sbe.cpp"
compile "$BIN/bench_mcast" -I"$CPP_ROOT/net/include" \
    "$ROOT/bench_mcast.cpp" "$CPP_ROOT/net/src/mcast_feed.cpp"
# PHASE 2 (latency elite): false sharing / cache-line and SPSC ring benches.
compile "$BIN/bench_false_sharing" "$ROOT/bench_false_sharing.cpp"
compile "$BIN/bench_spsc" -I"$CPP_ROOT/net/include" "$ROOT/bench_spsc.cpp"

modes=()
if [ "$MODE" = "both" ]; then
    modes=(dev final)
else
    modes=("$MODE")
fi

for m in "${modes[@]}"; do
    echo "== mode: $m =="
    "$BIN/bench_itch" "$CPP_ROOT" "$m" "$OUT/bench_itch_$m.json"
    "$BIN/bench_sbe" "$CPP_ROOT" "$m" "$OUT/bench_sbe_$m.json"
    "$BIN/bench_mcast" "$m" "$OUT/bench_mcast_$m.json"
    python3 "$ROOT/bench_json_decode.py" "$m" "$OUT/bench_json_$m.json"
    "$BIN/bench_false_sharing" "$m" "$OUT/bench_false_sharing_$m.json"
    "$BIN/bench_spsc" "$m" "$OUT/bench_spsc_$m.json"
done

echo "== BENCHMARKS DONE =="
