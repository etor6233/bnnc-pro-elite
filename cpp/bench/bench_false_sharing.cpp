// bench/bench_false_sharing.cpp — FASE 2 (latency elite): MEASURED evidence
// of the cost of false sharing on x86 cache lines.
//
// Two layouts of the same logical state (two uint64_t counters, incremented
// by two threads, one counter each):
//   (a) `close`: both counters inside ONE 64-byte cache line — every write
//       by one thread invalidates the other thread's line (false sharing);
//   (b) `far`:   each counter on its own 64-byte-aligned line (the pattern
//       used by net/spsc_ring.hpp and the LMAX Disruptor; reference capture
//       external-review/low-latency-reference/disruptor, commit c871ca49826a).
//
// Each thread increments ITS OWN shared counter in batches and records the
// per-operation latency (batch_time / batch); the samples feed the HDR
// histogram (bench/hdr_histogram.hpp) for p50/p99/p99.9/p99.99. The
// magnitude of the difference is whatever THIS machine measures — reported
// as-is, never promised in advance.
//
// Anti-cheat / correctness gate: both counters must equal
// increments_per_thread_per_rep at the end (printed); the sums are volatile-
// sunk. Nothing is memoized: every iteration is a real shared-memory
// increment.
#include <bench/bench_util.hpp>

#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

// Layout (a): two counters share one cache line.
struct CountersClose {
    volatile uint64_t a = 0;
    volatile uint64_t b = 0;
};

// Layout (b): each counter owns a full cache line.
struct CountersFar {
    alignas(64) volatile uint64_t a = 0;
    alignas(64) volatile uint64_t b = 0;
};

// One thread: increments *counter (its own shared counter) in batches of
// `batch`, recording the per-operation latency per batch. The counters are
// VOLATILE on purpose: the C++ abstract machine forbids coalescing volatile
// accesses, so every iteration is a real read-modify-write in shared memory
// (without volatile, the optimizer would legally fold a batch of increments
// into a single add and the experiment would measure nothing). Samples are
// collected thread-locally in PICOSECONDS (per-op values below 1 ns must
// survive integer truncation) and merged by the caller after join.
inline std::vector<uint64_t> hammer(volatile uint64_t* counter, uint64_t n,
                                    uint64_t batch) {
    std::vector<uint64_t> samples;
    samples.reserve((size_t)(n / batch) + 1);
    for (uint64_t done = 0; done < n; done += batch) {
        const uint64_t t0 = bench::now_ns();
        for (uint64_t j = 0; j < batch; ++j) ++(*counter);  // real memory op
        const uint64_t t1 = bench::now_ns();
        samples.push_back(((t1 - t0) * 1000) / batch);  // ps per op
    }
    return samples;
}

template <typename C>
void run_layout(const char* name, const std::string& mode, uint64_t n,
                uint64_t batch, std::vector<uint64_t>& agg_out,
                double& wall_s_out, double& ops_per_s_out) {
    C c;
    const uint64_t t0 = bench::now_ns();
    std::vector<uint64_t> sa, sb;
    {
        // NOTE: both threads write their OWN counter. In the 'close' layout
        // &c.a and &c.b are in the same cache line (false sharing); in the
        // 'far' layout each is alone on its line.
        std::thread ta([&] { sa = hammer(&c.a, n, batch); });
        std::thread tb([&] { sb = hammer(&c.b, n, batch); });
        ta.join();
        tb.join();
    }
    const uint64_t t1 = bench::now_ns();

    // Correctness gate: each thread incremented exactly n times.
    bench::touch(c.a ^ c.b);
    std::printf("[%s/%s] counters: a=%llu b=%llu (expect %llu each)\n", name,
                mode.c_str(), (unsigned long long)c.a, (unsigned long long)c.b,
                (unsigned long long)n);

    const double wall_s = (double)(t1 - t0) / 1e9;
    wall_s_out = wall_s;
    ops_per_s_out = (wall_s > 0) ? (double)(2 * n) / wall_s : 0.0;
    agg_out.insert(agg_out.end(), sa.begin(), sa.end());
    agg_out.insert(agg_out.end(), sb.begin(), sb.end());
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
                     "usage: bench_false_sharing <mode> <out-json> "
                     "[out-hdr-json]\n");
        return 2;
    }
    const std::string mode = argv[1];
    const std::string out_path = argv[2];
    const std::string out_hdr =
        (argc >= 4) ? argv[3]
                    : out_path.substr(0, out_path.size() - 5) + "_hdr.json";

    const uint64_t n = (mode == "dev") ? 50'000'000 : 200'000'000;
    const uint64_t batch = 10'000;  // batch-timed samples (documented)
    const int reps = (mode == "dev") ? 3 : 5;

    double close_wall = 0, close_ops = 0, far_wall = 0, far_ops = 0;
    std::vector<uint64_t> close_agg, far_agg;
    for (int r = 0; r < reps; ++r) {
        double w = 0, o = 0;
        run_layout<CountersClose>("same-line", mode, n, batch, close_agg, w, o);
        close_wall = (r == 0) ? w : std::min(close_wall, w);
        close_ops = std::max(close_ops, o);
        run_layout<CountersFar>("separate-lines", mode, n, batch, far_agg, w, o);
        far_wall = (r == 0) ? w : std::min(far_wall, w);
        far_ops = std::max(far_ops, o);
    }

    std::ostringstream json;
    json << "{\n"
         << "  \"benchmark\": \"false_sharing\",\n"
         << "  \"mode\": \"" << mode << "\",\n"
         << "  \"increments_per_thread_per_rep\": " << n << ",\n"
         << "  \"repetitions\": " << reps << ",\n"
         << "  \"batch_size\": " << batch << ",\n"
         << "  \"threads\": 2,\n"
         << "  \"same_line_best_ops_per_s\": " << close_ops << ",\n"
         << "  \"separate_lines_best_ops_per_s\": " << far_ops << ",\n"
         << "  \"same_line_best_ns_per_op\": " << (close_ops > 0 ? 1e9 / (close_ops / 2.0) : 0.0) << ",\n"
         << "  \"separate_lines_best_ns_per_op\": " << (far_ops > 0 ? 1e9 / (far_ops / 2.0) : 0.0) << ",\n"
         << "  \"separate_lines_speedup_vs_same_line\": " << (far_ops > 0 ? close_ops / far_ops : 0.0) << ",\n"
         << "  \"layout_close\": \"two uint64_t counters in one 64-byte cache line (false sharing)\",\n"
         << "  \"layout_far\": \"two uint64_t counters, each alignas(64) (disruptor-style padding)\",\n"
         << "  \"counters\": \"volatile uint64_t: per-access memory operations that the optimizer cannot coalesce; identical semantics in both layouts so the delta isolates the cache-line effect\",\n"
         << "  \"correctness_gate\": \"each counter must equal increments_per_thread_per_rep (printed above)\",\n"
         << "  \"reference\": \"LMAX Disruptor cache-line padding pattern, capture commit c871ca49826a\",\n"
         << "  \"measured_on\": \"MSVC cl 14.50 /O2, Windows x64\"\n"
         << "}\n";
    bench::write_json(out_path, json.str());
    std::printf("wrote %s\n", out_path.c_str());

    // HDR per-op latency percentiles for both layouts (FASE 2 requirement).
    // Samples are in picoseconds; the histogram covers [1 ps, 1 h] at 3
    // significant figures and the report converts back to nanoseconds.
    auto hdr_of = [&](const std::vector<uint64_t>& samples) {
        bench::HdrHistogram h(1, 3'600'000'000'000'000LL, 3);
        for (uint64_t s : samples) h.record((int64_t)s);
        return h;
    };
    const auto h_close = hdr_of(close_agg);
    const auto h_far = hdr_of(far_agg);
    const auto pct = [](const bench::HdrHistogram& h, double p) {
        return (double)h.value_at_percentile(p) / 1000.0;  // ps -> ns
    };
    std::ostringstream hjson;
    hjson << "{\n"
          << "  \"benchmark\": \"false_sharing\",\n"
          << "  \"mode\": \"" << mode << "\",\n"
          << "  \"histogram\": \"bench/hdr_histogram.hpp, HdrHistogram_c semantics (commit 1343a18908c6), 3 sig figs, [1 ps, 1 h], reported in ns\",\n"
          << "  \"same_line\": {\n"
          << "    \"samples\": " << close_agg.size() << ",\n"
          << "    \"p50_ns\": " << pct(h_close, 50.0) << ",\n"
          << "    \"p99_ns\": " << pct(h_close, 99.0) << ",\n"
          << "    \"p99.9_ns\": " << pct(h_close, 99.9) << ",\n"
          << "    \"p99.99_ns\": " << pct(h_close, 99.99) << ",\n"
          << "    \"mean_ns\": " << h_close.mean() / 1000.0 << "\n"
          << "  },\n"
          << "  \"separate_lines\": {\n"
          << "    \"samples\": " << far_agg.size() << ",\n"
          << "    \"p50_ns\": " << pct(h_far, 50.0) << ",\n"
          << "    \"p99_ns\": " << pct(h_far, 99.0) << ",\n"
          << "    \"p99.9_ns\": " << pct(h_far, 99.9) << ",\n"
          << "    \"p99.99_ns\": " << pct(h_far, 99.99) << ",\n"
          << "    \"mean_ns\": " << h_far.mean() / 1000.0 << "\n"
          << "  },\n"
          << "  \"speedup_separate_vs_same_p50\": " << (pct(h_close, 50.0) > 0 ? pct(h_close, 50.0) / pct(h_far, 50.0) : 0.0) << ",\n"
          << "  \"measured_on\": \"MSVC cl 14.50 /O2, Windows x64\"\n"
          << "}\n";
    bench::write_json(out_hdr, hjson.str());
    std::printf("wrote %s\n", out_hdr.c_str());
    return 0;
}
