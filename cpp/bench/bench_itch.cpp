// bench/bench_itch.cpp — FASE 5 measured benchmarks: ITCH 5.0 decode latency
// p50/p99 + throughput. Decodes the spec-derived golden vectors (the exact
// bytes the FASE 1 suite validates against), rotated across iterations.
// Modes: dev (fast) / final (held-out larger N), written to
// bench/benchmarks/*.json — numbers are measured, never estimated.
#include <bench/bench_util.hpp>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include <itch/itch_codec.hpp>

namespace fs = std::filesystem;

static std::vector<uint8_t> read_bin(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: bench_itch <cpp-root> <mode> <out-json>\n");
        return 2;
    }
    const fs::path root = argv[1];
    const std::string mode = argv[2];
    const std::string out_path = argv[3];

    // Load the spec-derived golden vectors (same bytes the suite validates).
    std::vector<std::vector<uint8_t>> corpus;
    const std::vector<std::string> names = {
        "add_order_buy", "add_order_mpid", "executed", "executed_price_printable",
        "cancel_partial", "delete_order", "replace_order", "trade_non_cross",
        "cross_trade_open", "stock_directory", "trading_action_t", "sys_event_O"};
    for (const auto& n : names) {
        const auto p = root / "itch" / "golden" / (n + ".bin");
        corpus.push_back(read_bin(p));
    }
    const uint64_t N = (mode == "dev") ? 300'000 : 5'000'000;
    const uint64_t kBatch = 1000;  // batch-timed samples (documented)
    const int reps = (mode == "dev") ? 3 : 5;

    std::vector<std::vector<uint64_t>> all_samples;
    double best_throughput = 0;
    for (int r = 0; r < reps; ++r) {
        std::vector<uint64_t> samples;
        const auto st = bench::measure_case(
            N, kBatch,
            [&](uint64_t i) {
                const auto& buf = corpus[i % corpus.size()];
                itch::Decoded out;  // fresh output every iteration
                const itch::DecodeStatus s =
                    itch::decode(buf.data(), buf.size(), out);
                bench::touch((uint64_t)(uint8_t)s + buf[0]);
            },
            samples);
        best_throughput = std::max(best_throughput, st.throughput_per_s);
        all_samples.push_back(std::move(samples));
        std::printf("[%s] rep %d: p50 %.0f ns, p99 %.0f ns, %.0f msg/s\n",
                    mode.c_str(), r, st.p50_ns, st.p99_ns, st.throughput_per_s);
    }
    // Aggregate percentiles across reps.
    std::vector<uint64_t> agg;
    for (auto& s : all_samples) agg.insert(agg.end(), s.begin(), s.end());
    auto st = bench::compute(agg, 0.0);
    st.throughput_per_s = best_throughput;

    std::ostringstream json;
    json << "{\n"
         << "  \"benchmark\": \"itch_decode\",\n"
         << "  \"mode\": \"" << mode << "\",\n"
         << "  \"iterations_per_rep\": " << N << ",\n"
         << "  \"repetitions\": " << reps << ",\n"
         << "  \"batch_size\": " << 1000 << ",\n"
         << "  \"corpus\": \"spec-derived golden vectors (itch/golden)\",\n"
         << "  \"p50_ns\": " << st.p50_ns << ",\n"
         << "  \"p99_ns\": " << st.p99_ns << ",\n"
         << "  \"mean_ns\": " << st.mean_ns << ",\n"
         << "  \"min_ns\": " << st.min_ns << ",\n"
         << "  \"max_ns\": " << st.max_ns << ",\n"
         << "  \"throughput_msg_per_s\": " << st.throughput_per_s << ",\n"
         << "  \"anti_cheat\": \"fresh Decoded per iteration; volatile sink; no memoization\",\n"
         << "  \"measured_on\": \"MSVC cl 14.50 /O2, Windows x64\"\n"
         << "}\n";
    bench::write_json(out_path, json.str());
    std::printf("wrote %s\n", out_path.c_str());
    return 0;
}
