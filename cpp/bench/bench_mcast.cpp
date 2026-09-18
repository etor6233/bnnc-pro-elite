// bench/bench_mcast.cpp — FASE 5 measured benchmarks: multicast publication
// (UDP sendto on a real loopback multicast socket) latency p50/p99 +
// throughput. The net framing of the FASE 3 transport is used.
#include <bench/bench_util.hpp>

#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include <net/mcast_feed.hpp>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: bench_mcast <mode> <out-json>\n");
        return 2;
    }
    const std::string mode = argv[1];
    const std::string out_path = argv[2];

    net::McastConfig cfg;
    cfg.group = "239.255.42.77";
    cfg.port = 45677;  // outside the host's excluded UDP ranges
    cfg.ttl = 1;
    cfg.loopback = true;

    net::MulticastSender tx;
    std::string err;
    if (!tx.open(cfg, err)) {
        std::fprintf(stderr, "open failed: %s\n", err.c_str());
        return 2;
    }

    net::FeedMessage m;
    m.type = net::MsgType::MarketPayload;
    m.session_id = 42;
    m.sequence = 1;
    m.timestamp_domain = net::TsDomain::HostMonotonic;
    m.timestamp_ns = 0;
    m.payload = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> wire;
    net::encode_frame(m, wire);  // 25-byte header + 4-byte payload

    const uint64_t N = (mode == "dev") ? 300'000 : 2'000'000;
    const uint64_t kBatch = 100;  // batch-timed samples (documented)
    const int reps = (mode == "dev") ? 3 : 5;

    std::vector<std::vector<uint64_t>> all_samples;
    double best_throughput = 0;
    for (int r = 0; r < reps; ++r) {
        std::vector<uint64_t> samples;
        const auto st = bench::measure_case(
            N, kBatch,
            [&](uint64_t i) {
                net::FeedMessage mm = m;
                mm.sequence = (uint32_t)i;
                std::vector<uint8_t> w;  // fresh encoding every iteration
                net::encode_frame(mm, w);
                const bool ok = tx.send(w.data(), w.size());
                bench::touch(ok ? 1u : 0u);
            },
            samples);
        best_throughput = (std::max)(best_throughput, st.throughput_per_s);
        all_samples.push_back(std::move(samples));
        std::printf("[%s] rep %d: p50 %.0f ns, p99 %.0f ns, %.0f dgram/s\n",
                    mode.c_str(), r, st.p50_ns, st.p99_ns, st.throughput_per_s);
    }
    std::vector<uint64_t> agg;
    for (auto& s : all_samples) agg.insert(agg.end(), s.begin(), s.end());
    auto st = bench::compute(agg, 0.0);
    st.throughput_per_s = best_throughput;

    std::ostringstream json;
    json << "{\n"
         << "  \"benchmark\": \"multicast_publish\",\n"
         << "  \"mode\": \"" << mode << "\",\n"
         << "  \"datagrams_per_rep\": " << N << ",\n"
         << "  \"repetitions\": " << reps << ",\n"
         << "  \"batch_size\": " << 100 << ",\n"
         << "  \"datagram_bytes\": " << wire.size() << ",\n"
         << "  \"p50_ns\": " << st.p50_ns << ",\n"
         << "  \"p99_ns\": " << st.p99_ns << ",\n"
         << "  \"mean_ns\": " << st.mean_ns << ",\n"
         << "  \"min_ns\": " << st.min_ns << ",\n"
         << "  \"max_ns\": " << st.max_ns << ",\n"
         << "  \"throughput_dgram_per_s\": " << st.throughput_per_s << ",\n"
         << "  \"anti_cheat\": \"fresh encode per iteration; volatile sink; no memoization\",\n"
         << "  \"measured_on\": \"MSVC cl 14.50 /O2, Windows x64, loopback multicast\"\n"
         << "}\n";
    bench::write_json(out_path, json.str());
    std::printf("wrote %s\n", out_path.c_str());
    tx.close();
    return 0;
}
