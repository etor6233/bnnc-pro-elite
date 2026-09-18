// bench/bench_util.hpp — honest benchmark helpers (FASE 5).
//
// Rules enforced (per instruction FASE 5):
//  - numbers are MEASURED only (p50/p99/throughput from real samples);
//  - anti-cheat: no memoization of the measured case — every iteration
//    decodes into a fresh output and the result feeds a volatile sink so the
//    optimizer cannot eliminate the work;
//  - dev mode (fast) and final mode (held-out sizes) are separate runs and
//    both are recorded in benchmarks/*.json.
#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace bench {

using Clock = std::chrono::steady_clock;

inline uint64_t now_ns() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
               Clock::now().time_since_epoch())
        .count();
}

// Volatile sink: prevents dead-code elimination without changing semantics.
inline volatile uint64_t g_sink = 0;
inline void touch(uint64_t v) { g_sink ^= v; }

struct Stats {
    uint64_t n = 0;
    double p50_ns = 0, p99_ns = 0, mean_ns = 0, min_ns = 0, max_ns = 0;
    double throughput_per_s = 0;
};

// Percentiles from the actual samples (linear interpolation not needed:
// nearest-rank is documented and deterministic).
inline Stats compute(std::vector<uint64_t>& samples, double elapsed_s) {
    std::sort(samples.begin(), samples.end());
    Stats s;
    s.n = samples.size();
    const auto pct = [&](double p) {
        const size_t idx = (size_t)(p * (double)(samples.size() - 1) + 0.5);
        return (double)samples[idx];
    };
    s.min_ns = (double)samples.front();
    s.max_ns = (double)samples.back();
    s.p50_ns = pct(0.50);
    s.p99_ns = pct(0.99);
    double sum = 0;
    for (uint64_t v : samples) sum += (double)v;
    s.mean_ns = sum / (double)samples.size();
    s.throughput_per_s =
        (elapsed_s > 0) ? (double)samples.size() / elapsed_s : 0.0;
    return s;
}

inline std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

inline void write_json(const std::string& path, const std::string& json) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << json;
}

// One measured case: `fn` is invoked N times in BATCHES of `batch`; each
// batch is timed as a whole and one per-message sample (batch_time/batch) is
// recorded. Batching removes clock-granularity bias for sub-100 ns operations
// (honest measured numbers, batch size declared in the output JSON).
template <typename Fn>
inline Stats measure_case(uint64_t n, uint64_t batch, Fn fn,
                          std::vector<uint64_t>& samples) {
    samples.clear();
    samples.reserve((size_t)(n / batch) + 1);
    const uint64_t t0 = now_ns();
    uint64_t done = 0;
    while (done + batch <= n) {
        const uint64_t a = now_ns();
        for (uint64_t j = 0; j < batch; ++j) fn(done + j);
        const uint64_t b = now_ns();
        samples.push_back((b - a) / batch);
        done += batch;
    }
    const uint64_t t1 = now_ns();
    Stats st = compute(samples, (double)(t1 - t0) / 1e9);
    st.throughput_per_s = (t1 > t0) ? (double)n / ((double)(t1 - t0) / 1e9) : 0.0;
    return st;
}

}  // namespace bench
