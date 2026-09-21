// bench/tests/test_hdr.cpp — PHASE 1 (latency elite): unit tests for the
// header-only HDR latency histogram (bench/hdr_histogram.hpp).
//
// Semantics tested here are the HdrHistogram_c contract (BSD-2/CC0 dual
// license, captured commit 1343a18908c6 in
// external-review/low-latency-reference/HdrHistogram_c):
//  - record() accepts [0, highest_trackable_value] and rejects everything else;
//  - value_at_percentile() uses the canonical cumulative-count rule
//    (count_at = floor(p/100 * total + 0.5), clamped to >= 1);
//  - empty histogram reports 0 at every percentile;
//  - percentile values are monotonically non-decreasing in p.
#include <bench/hdr_histogram.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <afx/test_framework.hpp>

using bench::HdrHistogram;

namespace {

constexpr int64_t kHighestNs = 3'600'000'000'000LL;  // 1 hour in ns
constexpr int kSigfigs = 3;

}  // namespace

// Known values recorded once each produce exact percentile answers: with
// significant_figures=3 and lowest=1, values < 2048 live in single-unit
// buckets, so recording 1..100 must yield value_at_percentile(50)==50,
// (99)==99, (100)==100, (0)==1.
AFX_TEST(known_values_exact_percentiles) {
    HdrHistogram h(1, kHighestNs, kSigfigs);
    for (int64_t v = 1; v <= 100; ++v) AFX_EXPECT(h.record(v));
    AFX_EXPECT_EQ(h.total_count(), 100);
    AFX_EXPECT_EQ(h.value_at_percentile(0.0), 1);
    AFX_EXPECT_EQ(h.value_at_percentile(50.0), 50);
    AFX_EXPECT_EQ(h.value_at_percentile(99.0), 99);
    AFX_EXPECT_EQ(h.value_at_percentile(100.0), 100);
    AFX_EXPECT_EQ(h.min(), 1);
    AFX_EXPECT_EQ(h.max(), 100);
}

// A single recorded value is the answer at every percentile.
AFX_TEST(single_value_all_percentiles) {
    HdrHistogram h(1, kHighestNs, kSigfigs);
    AFX_EXPECT(h.record(1000));
    AFX_EXPECT_EQ(h.value_at_percentile(50.0), 1000);
    AFX_EXPECT_EQ(h.value_at_percentile(99.0), 1000);
    AFX_EXPECT_EQ(h.value_at_percentile(99.9), 1000);
    AFX_EXPECT_EQ(h.value_at_percentile(99.99), 1000);
    AFX_EXPECT_EQ(h.max(), 1000);
}

// Empty histogram: 0 at every percentile, max 0, count 0.
AFX_TEST(empty_histogram_returns_zero) {
    HdrHistogram h(1, kHighestNs, kSigfigs);
    AFX_EXPECT_EQ(h.total_count(), 0);
    AFX_EXPECT_EQ(h.value_at_percentile(0.0), 0);
    AFX_EXPECT_EQ(h.value_at_percentile(50.0), 0);
    AFX_EXPECT_EQ(h.value_at_percentile(99.99), 0);
    AFX_EXPECT_EQ(h.max(), 0);
}

// Percentiles must be monotonically non-decreasing across a fine grid.
AFX_TEST(percentile_monotonicity) {
    HdrHistogram h(1, kHighestNs, kSigfigs);
    // Mixed corpus: powers of two with multiplicities + some noise.
    for (int64_t v = 1; v <= (1LL << 24); v <<= 1) {
        for (int i = 0; i < 7; ++i) h.record(v + (i % 3));
    }
    for (int64_t v = 1; v <= 10'000; ++v) h.record(v * 997);
    int64_t prev = 0;
    for (double p = 0.0; p <= 100.0001; p += 1.0) {
        const double pp = p > 100.0 ? 100.0 : p;
        const int64_t cur = h.value_at_percentile(pp);
        AFX_EXPECT(cur >= prev);
        prev = cur;
    }
    AFX_EXPECT_EQ(h.value_at_percentile(100.0),
                  h.value_at_percentile(150.0));  // clamped to 100
}

// record() accepts [0, highest] and rejects everything outside; the count
// reflects only accepted values.
AFX_TEST(record_bounds) {
    HdrHistogram h(1, 1'000'000, kSigfigs);
    AFX_EXPECT(h.record(0));
    AFX_EXPECT(!h.record(-1));
    AFX_EXPECT(!h.record(-1'000'000));
    AFX_EXPECT(h.record(1'000'000));
    AFX_EXPECT(!h.record(1'000'001));
    AFX_EXPECT_EQ(h.total_count(), 2);
    AFX_EXPECT_EQ(h.min(), 0);  // 0 recorded -> min is 0
    // max() is the HIGHEST EQUIVALENT value of the largest observation
    // (HdrHistogram_c contract): with 3 significant figures the bucket that
    // holds 1'000'000 spans up to its highest equivalent value.
    AFX_EXPECT_EQ(h.max(), h.highest_equivalent_value(1'000'000));
}

// min/max follow the HdrHistogram_c contract: min is the lowest equivalent
// value of the smallest non-zero observation, max the highest equivalent
// value of the largest observation.
AFX_TEST(min_max_semantics) {
    HdrHistogram h(1, kHighestNs, kSigfigs);
    AFX_EXPECT(h.record(5));
    AFX_EXPECT(h.record(500));
    AFX_EXPECT_EQ(h.min(), 5);
    AFX_EXPECT_EQ(h.max(), 500);
}

// Constructor validation mirrors hdr_calculate_bucket_config's EINVAL paths.
AFX_TEST(constructor_validation) {
    bool threw = false;
    try { HdrHistogram bad(0, kHighestNs, kSigfigs); } catch (const std::invalid_argument&) { threw = true; }
    AFX_EXPECT(threw);
    threw = false;
    try { HdrHistogram bad(1, 1, kSigfigs); } catch (const std::invalid_argument&) { threw = true; }  // lowest > highest/2
    AFX_EXPECT(threw);
    threw = false;
    try { HdrHistogram bad(1, kHighestNs, 0); } catch (const std::invalid_argument&) { threw = true; }
    AFX_EXPECT(threw);
    threw = false;
    try { HdrHistogram bad(1, kHighestNs, 6); } catch (const std::invalid_argument&) { threw = true; }
    AFX_EXPECT(threw);
    HdrHistogram ok(1, kHighestNs, 1);
    AFX_EXPECT_EQ(ok.total_count(), 0);
}

// count_at_value counts recorded observations in the equivalent bucket.
AFX_TEST(count_at_value) {
    HdrHistogram h(1, kHighestNs, kSigfigs);
    for (int i = 0; i < 5; ++i) h.record(42);
    AFX_EXPECT_EQ(h.count_at_value(42), 5);
    AFX_EXPECT_EQ(h.count_at_value(43), 0);  // distinct bucket at 3 sigfigs
    AFX_EXPECT_EQ(h.count_at_value(-1), 0);
}

// reset() empties the histogram.
AFX_TEST(reset_clears) {
    HdrHistogram h(1, kHighestNs, kSigfigs);
    AFX_EXPECT(h.record(123));
    h.reset();
    AFX_EXPECT_EQ(h.total_count(), 0);
    AFX_EXPECT_EQ(h.value_at_percentile(99.99), 0);
    AFX_EXPECT_EQ(h.max(), 0);
}

// The largest trackable value records and reads back without overflow, and
// high percentiles stay finite and ordered.
AFX_TEST(large_values_do_not_overflow) {
    HdrHistogram h(1, kHighestNs, kSigfigs);
    for (int64_t v = 1; v < kHighestNs; v *= 10) h.record(v);
    h.record(kHighestNs);
    // max() is the highest equivalent value of the recorded maximum.
    AFX_EXPECT_EQ(h.max(), h.highest_equivalent_value(kHighestNs));
    const int64_t p50 = h.value_at_percentile(50.0);
    const int64_t p99 = h.value_at_percentile(99.0);
    const int64_t p999 = h.value_at_percentile(99.9);
    const int64_t p9999 = h.value_at_percentile(99.99);
    AFX_EXPECT(p50 > 0);
    AFX_EXPECT(p50 <= p99);
    AFX_EXPECT(p99 <= p999);
    AFX_EXPECT(p999 <= p9999);
    AFX_EXPECT(p9999 <= h.highest_equivalent_value(kHighestNs));
}

int main(int argc, char** argv) { return afx::run_all(argc, argv); }
