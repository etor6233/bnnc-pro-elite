// bench/bench_sbe.cpp — PHASE 5 measured benchmarks: Binance SBE decode
// latency p50/p99 + throughput on the official-encoder golden vectors
// (same bytes the PHASE 2 suite cross-checks against the official decoder).
#include <bench/bench_util.hpp>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include <sbe/binance_sbe.hpp>

namespace fs = std::filesystem;

static std::vector<uint8_t> read_bin(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr,
                     "usage: bench_sbe <cpp-root> <mode> <out-json> "
                     "[out-hdr-json]\n");
        return 2;
    }
    const fs::path root = argv[1];
    const std::string mode = argv[2];
    const std::string out_path = argv[3];
    // HDR percentiles (p50/p99/p99.9/p99.99 via bench/hdr_histogram.hpp) go
    // to <out-hdr-json>, or to <out-json> with the "_hdr.json" suffix.
    std::string out_hdr =
        (argc >= 5) ? argv[4]
                    : out_path.substr(0, out_path.size() - 5) + "_hdr.json";

    std::vector<std::vector<uint8_t>> corpus;
    const std::vector<std::string> names = {
        "trades_stream", "best_bid_ask", "depth_snapshot", "depth_diff"};
    for (const auto& n : names) {
        corpus.push_back(read_bin(root / "sbe" / "golden" / (n + ".bin")));
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
                sbe::Decoded out;  // fresh output every iteration
                const sbe::DecodeStatus s = sbe::decode(buf.data(), buf.size(), out);
                bench::touch((uint64_t)(uint8_t)s + buf[0]);
            },
            samples);
        best_throughput = std::max(best_throughput, st.throughput_per_s);
        all_samples.push_back(std::move(samples));
        std::printf("[%s] rep %d: p50 %.0f ns, p99 %.0f ns, %.0f msg/s\n",
                    mode.c_str(), r, st.p50_ns, st.p99_ns, st.throughput_per_s);
    }
    std::vector<uint64_t> agg;
    for (auto& s : all_samples) agg.insert(agg.end(), s.begin(), s.end());
    auto st = bench::compute(agg, 0.0);
    st.throughput_per_s = best_throughput;

    std::ostringstream json;
    json << "{\n"
         << "  \"benchmark\": \"sbe_decode\",\n"
         << "  \"mode\": \"" << mode << "\",\n"
         << "  \"iterations_per_rep\": " << N << ",\n"
         << "  \"repetitions\": " << reps << ",\n"
         << "  \"batch_size\": " << 1000 << ",\n"
         << "  \"corpus\": \"official-encoder golden vectors (sbe/golden)\",\n"
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

    // HDR percentile report (PHASE 1 integration): p50/p99/p99.9/p99.99.
    const auto hs = bench::hdr_stats(agg);
    std::ostringstream hjson;
    hjson << "{\n"
          << "  \"benchmark\": \"sbe_decode\",\n"
          << "  \"mode\": \"" << mode << "\",\n"
          << "  \"histogram\": \"bench/hdr_histogram.hpp, HdrHistogram_c semantics (commit 1343a18908c6), 3 sig figs, [1 ns, 1 h]\",\n"
          << "  \"samples\": " << hs.count << ",\n"
          << "  \"batch_size\": " << 1000 << ",\n"
          << "  \"iterations_per_rep\": " << N << ",\n"
          << "  \"repetitions\": " << reps << ",\n"
          << "  \"p50_ns\": " << hs.p50_ns << ",\n"
          << "  \"p99_ns\": " << hs.p99_ns << ",\n"
          << "  \"p99.9_ns\": " << hs.p999_ns << ",\n"
          << "  \"p99.99_ns\": " << hs.p9999_ns << ",\n"
          << "  \"min_ns\": " << hs.min_ns << ",\n"
          << "  \"max_ns\": " << hs.max_ns << ",\n"
          << "  \"mean_ns\": " << hs.mean_ns << ",\n"
          << "  \"anti_cheat\": \"fresh Decoded per iteration; volatile sink; no memoization\",\n"
          << "  \"measured_on\": \"MSVC cl 14.50 /O2, Windows x64\"\n"
          << "}\n";
    bench::write_json(out_hdr, hjson.str());
    std::printf("wrote %s\n", out_hdr.c_str());
    return 0;
}
