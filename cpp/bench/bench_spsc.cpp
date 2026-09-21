// bench/bench_spsc.cpp — PHASE 2 (latency elite): measured benchmark of the
// bounded lock-free SPSC ring (net/spsc_ring.hpp), 1 producer / 1 consumer.
//
// What is measured (all real, all on this host):
//  - push latency: producer-side batch-timed samples (includes one
//    steady_clock read per item — the enqueue timestamp);
//  - pop latency: consumer-side batch-timed samples;
//  - end-to-end latency: producer stamps now_ns() into the item, consumer
//    measures now_ns() - stamp per item and records inline into the HDR
//    histogram (per-item telemetry cost is part of the consumer loop —
//    documented, not hidden);
//  - throughput: items / wall time across both threads;
//  - overflow behavior: try_push returns false when full (the explicit
//    overflow policy of net/spsc_ring.hpp); the producer retries and the
//    retry count is reported.
//
// HDR percentiles come from bench/hdr_histogram.hpp (HdrHistogram_c
// semantics, commit 1343a18908c6). Ring pattern references: Aeron
// media-driver ring (design only) and LMAX Disruptor cache-line padding
// (captures c871ca49826a / aeron §2 of the low-latency INDEX).
#include <bench/bench_util.hpp>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <net/spsc_ring.hpp>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
                     "usage: bench_spsc <mode> <out-json> [out-hdr-json]\n");
        return 2;
    }
    const std::string mode = argv[1];
    const std::string out_path = argv[2];
    const std::string out_hdr =
        (argc >= 4) ? argv[3]
                    : out_path.substr(0, out_path.size() - 5) + "_hdr.json";

    const uint64_t N = (mode == "dev") ? 10'000'000 : 50'000'000;
    const size_t kCapacity = (size_t)1 << 20;  // ~1M slots (documented)
    const uint64_t kBatch = 1000;              // batch-timed samples
    const int reps = (mode == "dev") ? 3 : 5;

    std::vector<uint64_t> push_agg, pop_agg;
    bench::HdrHistogram e2e(1, 3'600'000'000'000LL, 3);
    double best_throughput = 0;
    uint64_t total_retries = 0;

    for (int r = 0; r < reps; ++r) {
        net::SpscRing<uint64_t> ring(kCapacity);
        std::atomic<bool> start{false};
        std::atomic<uint64_t> retries{0};
        std::vector<uint64_t> push_samples, pop_samples;
        push_samples.reserve((size_t)(N / kBatch) + 1);
        pop_samples.reserve((size_t)(N / kBatch) + 1);

        // Producer: stamps the enqueue time into the item; on explicit
        // overflow (try_push == false) retries, counting every retry.
        std::thread producer([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            uint64_t r = 0;
            for (uint64_t done = 0; done < N; done += kBatch) {
                const uint64_t t0 = bench::now_ns();
                for (uint64_t j = 0; j < kBatch; ++j) {
                    while (!ring.try_push(bench::now_ns())) ++r;
                }
                const uint64_t t1 = bench::now_ns();
                push_samples.push_back((t1 - t0) / kBatch);
            }
            retries.store(r, std::memory_order_relaxed);
        });

        // Consumer: pops every item and records the per-item end-to-end
        // latency inline (the record call is part of the consumer loop).
        std::thread consumer([&] {
            while (!start.load(std::memory_order_acquire)) {
            }
            uint64_t got = 0;
            while (got < N) {
                uint64_t v = 0;
                if (!ring.try_pop(v)) {
                    std::this_thread::yield();
                    continue;
                }
                e2e.record((int64_t)(bench::now_ns() - v));
                ++got;
            }
        });

        const uint64_t t0 = bench::now_ns();
        start.store(true, std::memory_order_release);
        producer.join();
        consumer.join();
        const uint64_t t1 = bench::now_ns();

        // Consumer-side batch pop latency, measured on a pre-filled ring
        // with a concurrent feeder thread. The feeder keeps the other side
        // of the ring alive, which (a) prevents any optimizer collapse of
        // the pop loop (the atomics are raced by a real second thread) and
        // (b) matches the conditions of the real 1P/1C run. The consumer
        // pops whole batches only: the target is a multiple of the batch
        // size, so the loop always terminates. Occasional empty-ring waits
        // are part of the measured samples (documented).
        {
            net::SpscRing<uint64_t> ring2(kCapacity);
            uint64_t filled = 0;
            while (filled < ring2.capacity() && filled < 4'000'000) {
                if (!ring2.try_push(filled)) break;
                ++filled;
            }
            std::atomic<bool> start2{false};
            std::atomic<bool> stop2{false};
            std::thread feeder([&] {
                while (!start2.load(std::memory_order_acquire)) {
                }
                while (!stop2.load(std::memory_order_acquire)) {
                    if (!ring2.try_push(0)) std::this_thread::yield();
                }
            });
            start2.store(true, std::memory_order_release);
            const uint64_t pop_target = filled - (filled % kBatch);
            uint64_t v = 0;
            for (uint64_t done = 0; done < pop_target; done += kBatch) {
                const uint64_t a = bench::now_ns();
                for (uint64_t j = 0; j < kBatch; ++j) {
                    while (!ring2.try_pop(v)) std::this_thread::yield();
                }
                const uint64_t b = bench::now_ns();
                pop_samples.push_back((b - a) / kBatch);
            }
            stop2.store(true, std::memory_order_release);
            feeder.join();
            bench::touch(v ^ filled);
        }

        const double wall_s = (double)(t1 - t0) / 1e9;
        const double throughput = (wall_s > 0) ? (double)N / wall_s : 0.0;
        best_throughput = std::max(best_throughput, throughput);
        total_retries += retries.load(std::memory_order_relaxed);
        std::printf("[%s] rep %d: %.0f msg/s, retries=%llu\n", mode.c_str(), r,
                    throughput, (unsigned long long)retries.load());
        push_agg.insert(push_agg.end(), push_samples.begin(),
                        push_samples.end());
        pop_agg.insert(pop_agg.end(), pop_samples.begin(), pop_samples.end());
    }

    const auto push_hs = bench::hdr_stats(push_agg);
    const auto pop_hs = bench::hdr_stats(pop_agg);

    std::ostringstream json;
    json << "{\n"
         << "  \"benchmark\": \"spsc_ring_1p1c\",\n"
         << "  \"mode\": \"" << mode << "\",\n"
         << "  \"messages_per_rep\": " << N << ",\n"
         << "  \"repetitions\": " << reps << ",\n"
         << "  \"capacity_slots\": " << kCapacity << ",\n"
         << "  \"batch_size\": " << kBatch << ",\n"
         << "  \"best_throughput_msg_per_s\": " << best_throughput << ",\n"
         << "  \"producer_retries_total\": " << total_retries << ",\n"
         << "  \"overflow_policy\": \"explicit try_push==false on full; producer retries; nothing silently dropped\",\n"
         << "  \"push_p50_ns\": " << push_hs.p50_ns << ",\n"
         << "  \"push_p99_ns\": " << push_hs.p99_ns << ",\n"
         << "  \"pop_p50_ns\": " << pop_hs.p50_ns << ",\n"
         << "  \"pop_p99_ns\": " << pop_hs.p99_ns << ",\n"
         << "  \"notes\": \"push samples include one steady_clock read (enqueue timestamp); pop latency measured on a pre-filled ring with a concurrent feeder thread (no per-item telemetry, occasional empty-ring waits included)\",\n"
         << "  \"ring\": \"net/spsc_ring.hpp (bounded lock-free SPSC, cache-line separated head_/tail_, static_assert-verified)\",\n"
         << "  \"measured_on\": \"MSVC cl 14.50 /O2, Windows x64\"\n"
         << "}\n";
    bench::write_json(out_path, json.str());
    std::printf("wrote %s\n", out_path.c_str());

    std::ostringstream hjson;
    hjson << "{\n"
          << "  \"benchmark\": \"spsc_ring_1p1c\",\n"
          << "  \"mode\": \"" << mode << "\",\n"
          << "  \"histogram\": \"bench/hdr_histogram.hpp, HdrHistogram_c semantics (commit 1343a18908c6), 3 sig figs, [1 ns, 1 h]\",\n"
          << "  \"e2e\": {\n"
          << "    \"samples\": " << e2e.total_count() << ",\n"
          << "    \"p50_ns\": " << (double)e2e.value_at_percentile(50.0) << ",\n"
          << "    \"p99_ns\": " << (double)e2e.value_at_percentile(99.0) << ",\n"
          << "    \"p99.9_ns\": " << (double)e2e.value_at_percentile(99.9) << ",\n"
          << "    \"p99.99_ns\": " << (double)e2e.value_at_percentile(99.99) << ",\n"
          << "    \"min_ns\": " << (double)e2e.min() << ",\n"
          << "    \"max_ns\": " << (double)e2e.max() << ",\n"
          << "    \"mean_ns\": " << e2e.mean() << ",\n"
          << "    \"definition\": \"consumer clock read - producer enqueue timestamp, per item, includes queueing\",\n"
          << "    \"consumer_bookkeeping\": \"per-item histogram record included in the consumer loop\"\n"
          << "  },\n"
          << "  \"push\": {\n"
          << "    \"samples\": " << push_hs.count << ",\n"
          << "    \"p50_ns\": " << push_hs.p50_ns << ",\n"
          << "    \"p99_ns\": " << push_hs.p99_ns << ",\n"
          << "    \"p99.9_ns\": " << push_hs.p999_ns << ",\n"
          << "    \"p99.99_ns\": " << push_hs.p9999_ns << ",\n"
          << "    \"mean_ns\": " << push_hs.mean_ns << "\n"
          << "  },\n"
          << "  \"pop\": {\n"
          << "    \"samples\": " << pop_hs.count << ",\n"
          << "    \"p50_ns\": " << pop_hs.p50_ns << ",\n"
          << "    \"p99_ns\": " << pop_hs.p99_ns << ",\n"
          << "    \"p99.9_ns\": " << pop_hs.p999_ns << ",\n"
          << "    \"p99.99_ns\": " << pop_hs.p9999_ns << ",\n"
          << "    \"mean_ns\": " << pop_hs.mean_ns << "\n"
          << "  },\n"
          << "  \"measured_on\": \"MSVC cl 14.50 /O2, Windows x64\"\n"
          << "}\n";
    bench::write_json(out_hdr, hjson.str());
    std::printf("wrote %s\n", out_hdr.c_str());
    return 0;
}
