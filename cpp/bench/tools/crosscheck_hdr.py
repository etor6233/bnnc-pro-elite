"""crosscheck_hdr.py — PHASE 1 cross-validation of the C++ HDR histogram.

Runs the compiled C++ driver (cpp/bench/tools/hdr_cli.cpp) over synthetic
corpora and compares its percentile output against hdr_reference.py, the
independent Python re-derivation of the HdrHistogram_c semantics (captured
commit 1343a18908c6, BSD-2-Clause / CC0-1.0). Two implementations in two
languages cannot agree by accident: this is the equivalence gate.

Tolerance (documented): values must be EXACTLY equal, or land in the same
equivalent-value bucket (<= 1 ULP of the HDR representation: the histogram
cannot distinguish values inside one bucket). Expected result: 0 differences
outside tolerance on every corpus, because both sides use the same integer
arithmetic.
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hdr_reference  # noqa: E402

LOWEST = 1
HIGHEST = 3_600_000_000_000  # 1 hour in ns
SIGFIGS = 3
PERCENTILES = (0.0, 50.0, 90.0, 99.0, 99.9, 99.99, 100.0)
SEED = 20260919  # deterministic corpora (documented seed)


def make_corpora(tmp: Path) -> list[dict]:
    rng = random.Random(SEED)
    corpora = []

    def log_uniform(lo_exp: float, hi_exp: float, n: int) -> list[int]:
        out = []
        for _ in range(n):
            v = int(round(10 ** rng.uniform(lo_exp, hi_exp)))
            out.append(max(1, min(HIGHEST, v)))
        return out

    # 1. Log-uniform across the full trackable range (exercises every bucket).
    corpora.append({"name": "log_uniform",
                    "values": log_uniform(0.0, 12.0, 100_000)})
    # 2. Spikes: clustered latencies + jitter (the market-data histogram shape).
    spikes: list[int] = []
    centers = [100, 1_000, 10_000, 100_000, 1_000_000, 100_000_000]
    for _ in range(100_000):
        if rng.random() < 0.6:
            c = rng.choice(centers)
            spikes.append(max(1, c + rng.randint(-c // 10, c // 10)))
        else:
            spikes.append(max(1, int(round(10 ** rng.uniform(0.0, 6.0)))))
    corpora.append({"name": "spikes", "values": spikes})
    # 3. Heavy tail: common small values + rare multi-second stalls.
    tail: list[int] = []
    for _ in range(100_000):
        if rng.random() < 0.95:
            tail.append(rng.randint(1, 100_000))
        else:
            tail.append(max(1, min(HIGHEST,
                                   int(round(10 ** rng.uniform(6.0, 12.0))))))
    corpora.append({"name": "heavy_tail", "values": tail})
    # 4. Uniform small values: exercises sub-bucket transitions and the
    #    single-unit-resolution range.
    corpora.append({"name": "uniform_small",
                    "values": [rng.randint(1, 4096) for _ in range(50_000)]})

    for c in corpora:
        p = tmp / f"{c['name']}.values"
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(str(v) for v in c["values"]) + "\n")
        c["file"] = str(p)
    return corpora


def run_cpp(exe: str, values_file: str) -> dict:
    proc = subprocess.run(
        [exe, values_file, str(LOWEST), str(HIGHEST), str(SIGFIGS)],
        capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"hdr_cli failed: {proc.stderr}")
    return json.loads(proc.stdout)


def run_reference(corpus: dict) -> dict:
    ref = hdr_reference.HdrHistogram(LOWEST, HIGHEST, SIGFIGS)
    for v in corpus["values"]:
        ref.record(v)
    return {
        "total_count": ref.total_count,
        "min": ref.min(),
        "max": ref.max(),
        **{f"p{p:g}": ref.value_at_percentile(p) for p in PERCENTILES},
    }


def same_bucket(a: int, b: int, ref: hdr_reference.HdrHistogram) -> bool:
    if a == b:
        return True
    try:
        return ref.highest_equivalent_value(a) == ref.highest_equivalent_value(b)
    except (ValueError, AssertionError):
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True,
                    help="path to the compiled hdr_cli executable")
    ap.add_argument("--evidence", default=None,
                    help="optional evidence dir to receive the report")
    ap.add_argument("--out", default=None,
                    help="optional explicit report path "
                         "(default: crosscheck_report.json next to the values)")
    args = ap.parse_args()

    exe = Path(args.exe).resolve()
    if not exe.exists():
        print(f"crosscheck: exe not found: {exe}", file=sys.stderr)
        return 2

    report = {
        "tool": "crosscheck_hdr.py",
        "reference": ("hdr_reference.py (HdrHistogram_c semantics, commit "
                      "1343a18908c6, BSD-2-Clause/CC0-1.0)"),
        "implementation": "cpp/bench/hdr_histogram.hpp + tools/hdr_cli.cpp",
        "config": {"lowest_discernible_value": LOWEST,
                   "highest_trackable_value": HIGHEST,
                   "significant_figures": SIGFIGS,
                   "percentiles": list(PERCENTILES)},
        "tolerance": ("exact equality, or same equivalent-value bucket "
                      "(<= 1 ULP of the HDR representation)"),
        "seed": SEED,
        "corpora": [],
        "verdict": "PASS",
    }

    with tempfile.TemporaryDirectory(prefix="hdr_crosscheck_") as td:
        tmp = Path(td)
        corpora = make_corpora(tmp)
        ref_hist = hdr_reference.HdrHistogram(LOWEST, HIGHEST, SIGFIGS)
        for corpus in corpora:
            cpp = run_cpp(args.exe, corpus["file"])
            ref = run_reference(corpus)
            mismatches = []
            for key in ["total_count", "min", "max"]:
                if cpp[key] != ref[key]:
                    mismatches.append({"key": key, "cpp": cpp[key],
                                       "reference": ref[key]})
            for p in PERCENTILES:
                key = f"p{p:g}"
                if not same_bucket(cpp[key], ref[key], ref_hist):
                    mismatches.append({"key": key, "cpp": cpp[key],
                                       "reference": ref[key],
                                       "note": "outside bucket tolerance"})
            entry = {
                "name": corpus["name"],
                "values": len(corpus["values"]),
                "cpp": {k: cpp[k] for k in
                        ["total_count", "min", "max"]
                        + [f"p{p:g}" for p in PERCENTILES]},
                "reference": {k: ref[k] for k in
                              ["total_count", "min", "max"]
                              + [f"p{p:g}" for p in PERCENTILES]},
                "mismatches_outside_tolerance": mismatches,
                "verdict": "PASS" if not mismatches else "FAIL",
            }
            report["corpora"].append(entry)
            if mismatches:
                report["verdict"] = "FAIL"
            print(f"corpus {corpus['name']}: {len(corpus['values'])} values, "
                  f"{'PASS' if not mismatches else f'FAIL ({len(mismatches)} '
                  f'mismatches)'}")

    if args.out:
        out_path = Path(args.out)
    else:
        out_path = Path(__file__).resolve().parent / "crosscheck_report.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
    print(f"report: {out_path}")

    if args.evidence:
        ev = Path(args.evidence)
        ev.mkdir(parents=True, exist_ok=True)
        with open(ev / "crosscheck_report.json", "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
            fh.write("\n")
        print(f"evidence copy: {ev / 'crosscheck_report.json'}")

    print(f"verdict: {report['verdict']}")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
