// bench/tools/hdr_cli.cpp — command-line driver for the HDR histogram
// (FASE 1 cross-check). Reads one base-10 int64 per line from a values file,
// records it into bench::HdrHistogram and prints a small JSON result with
// count/min/max and the standard percentile set. Used by
// bench/tools/crosscheck_hdr.py to compare the C++ implementation against the
// independent Python reference (hdr_reference.py).
#include <bench/hdr_histogram.hpp>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 5) {
        std::fprintf(stderr,
                     "usage: hdr_cli <values-file> <lowest> <highest> <sigfigs>\n");
        return 2;
    }
    const int64_t lowest = std::stoll(argv[2]);
    const int64_t highest = std::stoll(argv[3]);
    const int sigfigs = std::stoi(argv[4]);

    bench::HdrHistogram h(lowest, highest, sigfigs);
    std::ifstream in(argv[1]);
    std::string line;
    uint64_t read = 0, recorded = 0;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        ++read;
        if (h.record(std::stoll(line))) ++recorded;
    }

    const double percs[] = {0.0, 50.0, 90.0, 99.0, 99.9, 99.99, 100.0};
    std::printf("{\n");
    std::printf("  \"values_read\": %llu,\n", (unsigned long long)read);
    std::printf("  \"values_recorded\": %llu,\n", (unsigned long long)recorded);
    std::printf("  \"total_count\": %lld,\n", (long long)h.total_count());
    std::printf("  \"min\": %lld,\n", (long long)h.min());
    std::printf("  \"max\": %lld,\n", (long long)h.max());
    for (double p : percs) {
        const char* comma = (p == 100.0) ? "\n" : ",\n";
        std::printf("  \"p%g\": %lld%s", p,
                    (long long)h.value_at_percentile(p), comma);
    }
    std::printf("}\n");
    return 0;
}
