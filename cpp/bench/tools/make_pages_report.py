"""make_pages_report.py — static latency report for GitHub Pages (PHASE 5).

Reads every measured benchmark JSON under cpp/bench/benchmarks/ (dev and
final modes, nearest-rank and HDR percentile files) and renders a single
self-contained bench-latency/index.html page: one table per benchmark with
p50/p99/p99.9/p99.99, min/max/mean, throughput and the anti-cheat/measured-on
notes. Stdlib only; the generated page carries no runtime dependencies.

Deploy (documented in cpp/evidence/10-latency-elite/PHASE 5/): the committed
page can be served via GitHub Pages by selecting this branch and the
/bench-latency folder in the Pages settings — no build step on the server.
"""
from __future__ import annotations

import json
import pathlib
import sys

BENCH_DIR = pathlib.Path(__file__).resolve().parents[1] / "benchmarks"
OUT_HTML = pathlib.Path(__file__).resolve().parents[3] / "bench-latency" / "index.html"

PERCENTILE_KEYS = [("p50_ns", "p50"), ("p99_ns", "p99"),
                   ("p99.9_ns", "p99.9"), ("p99.99_ns", "p99.99")]


def load_benchmarks() -> dict[str, list[dict]]:
    benches: dict[str, list[dict]] = {}
    for path in sorted(BENCH_DIR.glob("bench_*.json")):
        if path.name.endswith("_hdr.json"):
            continue  # HDR files are merged into their base benchmark below
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        hdr_path = BENCH_DIR / (path.name[:-5] + "_hdr.json")
        if hdr_path.exists():
            with open(hdr_path, encoding="utf-8") as fh:
                hdr = json.load(fh)
            data["hdr"] = hdr
        benches.setdefault(data["benchmark"], []).append(data)
    for entries in benches.values():
        entries.sort(key=lambda e: (e.get("mode", ""), str(e)))
    return benches


def pct_of(entry: dict, key: str) -> str:
    value = entry.get(key)
    if value is None:
        return "&mdash;"
    return f"{float(value):,.0f}"


def hdr_pct_of(entry: dict, key: str) -> str:
    hdr = entry.get("hdr", {})
    # The HDR file embeds per-layout sub-objects for false_sharing; the flat
    # percentiles of the other benchmarks live at the top level.
    for candidate in (hdr, hdr.get("e2e", {}), hdr.get("same_line", {}),
                      hdr.get("separate_lines", {})):
        value = candidate.get(key)
        if value is not None:
            return f"{float(value):,.0f}"
    return "&mdash;"


def esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def cell(value) -> str:
    """Render a table cell: raw em dash for missing values, escaped otherwise."""
    if value is None or value == "&mdash;":
        return "—"
    return esc(value)


def render() -> str:
    benches = load_benchmarks()
    if not benches:
        raise SystemExit("no benchmark JSONs found under cpp/bench/benchmarks/")

    parts: list[str] = []
    parts.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
    parts.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
    parts.append("<title>bnnc-pro-elite — measured latency benchmarks</title>\n")
    parts.append("<style>\n"
                 "body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:64rem;"
                 "padding:0 1rem;color:#1a1a1a;line-height:1.5}\n"
                 "h1,h2{font-weight:600}\n"
                 "table{border-collapse:collapse;width:100%;margin:1rem 0 2rem}\n"
                 "th,td{border:1px solid #d0d0d0;padding:.4rem .6rem;text-align:right;"
                 "font-variant-numeric:tabular-nums}\n"
                 "th:first-child,td:first-child{text-align:left}\n"
                 "th{background:#f4f4f4}\n"
                 "code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}\n"
                 ".note{color:#555;font-size:.9rem}\n"
                 "</style>\n</head>\n<body>\n")
    parts.append("<h1>Measured latency benchmarks</h1>\n")
    parts.append("<p class=\"note\">Generated from the committed JSON files under "
                 "<code>cpp/bench/benchmarks/</code> by "
                 "<code>cpp/bench/tools/make_pages_report.py</code>. Every number on this "
                 "page was produced by a real run of <code>cpp/bench/run_benchmarks.ps1</code> "
                 "or <code>run_benchmarks.sh</code> — nothing is estimated. HDR percentiles "
                 "(p50/p99/p99.9/p99.99) use the 3-significant-figure histogram in "
                 "<code>cpp/bench/hdr_histogram.hpp</code> (HdrHistogram_c semantics, commit "
                 "<code>1343a18908c6</code>). Final-mode numbers are measured on the quiet "
                 "local machine; CI publishes dev-mode runs as artifacts.</p>\n")

    for name, entries in benches.items():
        parts.append(f"<h2>{esc(name)}</h2>\n")
        parts.append("<table>\n<tr><th>mode</th><th>samples</th>")
        for _, label in PERCENTILE_KEYS:
            parts.append(f"<th>{label} (HDR, ns)</th>")
        parts.append("<th>mean (ns)</th><th>min (ns)</th><th>max (ns)</th>"
                     "<th>throughput</th><th>measured on</th></tr>\n")
        for entry in entries:
            hdr = entry.get("hdr", {})
            if hdr and "e2e" in hdr and entry["benchmark"] == "spsc_ring_1p1c":
                # SPSC: one row per aspect (e2e/push/pop).
                for aspect in ("e2e", "push", "pop"):
                    block = hdr[aspect]
                    parts.append(f"<tr><td>{esc(entry.get('mode',''))} — {esc(aspect)}</td>"
                                 f"<td>{cell(block.get('samples'))}</td>")
                    for key, _ in PERCENTILE_KEYS:
                        parts.append(f"<td>{cell(block.get(key))}</td>")
                    parts.append(f"<td>{cell(block.get('mean_ns'))}</td>"
                                 f"<td>{cell(block.get('min_ns'))}</td>"
                                 f"<td>{cell(block.get('max_ns'))}</td>"
                                 f"<td>—</td>"
                                 f"<td>{esc(entry.get('measured_on',''))}</td></tr>\n")
                continue
            if hdr and entry["benchmark"] == "false_sharing":
                # False sharing: one row per layout, each with its own
                # throughput and speedup context.
                for layout, tp_key in (("same_line", "same_line_best_ops_per_s"),
                                       ("separate_lines", "separate_lines_best_ops_per_s")):
                    block = hdr[layout]
                    parts.append(f"<tr><td>{esc(entry.get('mode',''))} — {esc(layout)}</td>"
                                 f"<td>{cell(block.get('samples'))}</td>")
                    for key, _ in PERCENTILE_KEYS:
                        parts.append(f"<td>{cell(block.get(key))}</td>")
                    tp = entry.get(tp_key)
                    parts.append(f"<td>{cell(block.get('mean_ns'))}</td>"
                                 f"<td>—</td><td>—</td>"
                                 f"<td>{cell(f'{float(tp):,.0f} ops/s' if tp is not None else None)}</td>"
                                 f"<td>{esc(entry.get('measured_on',''))}</td></tr>\n")
                continue
            samples = hdr.get("samples") if isinstance(hdr, dict) else None
            if samples is None:
                samples = entry.get("samples") if entry.get("samples") else ""
            parts.append(f"<tr><td>{esc(entry.get('mode',''))}</td><td>{cell(samples)}</td>")
            for key, _ in PERCENTILE_KEYS:
                parts.append(f"<td>{hdr_pct_of(entry, key)}</td>")
            parts.append(f"<td>{pct_of(entry, 'mean_ns')}</td>"
                         f"<td>{pct_of(entry, 'min_ns')}</td>"
                         f"<td>{pct_of(entry, 'max_ns')}</td>")
            throughput_key = ("throughput_msg_per_s" if "throughput_msg_per_s" in entry
                              else "throughput_dgram_per_s"
                              if "throughput_dgram_per_s" in entry
                              else "best_throughput_msg_per_s"
                              if "best_throughput_msg_per_s" in entry else None)
            tp = entry.get(throughput_key) if throughput_key else None
            parts.append(f"<td>{cell(f'{float(tp):,.0f}/s' if tp is not None else None)}</td>")
            parts.append(f"<td>{esc(entry.get('measured_on',''))}</td></tr>\n")
        parts.append("</table>\n")

    parts.append("<p class=\"note\">Anti-cheat rules applied to every case: fresh output per "
                 "iteration, volatile sink, no memoization; batch sizes are declared in each "
                 "JSON. See <code>cpp/evidence/</code> for the full evidence trail.</p>\n")
    parts.append("</body>\n</html>\n")
    return "".join(parts)


def main() -> int:
    html = render()
    OUT_HTML.parent.mkdir(parents=True, exist_ok=True)
    OUT_HTML.write_text(html, encoding="utf-8")
    print(f"wrote {OUT_HTML}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
