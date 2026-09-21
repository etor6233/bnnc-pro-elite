// bench/hdr_histogram.hpp — header-only HDR (High Dynamic Range) latency
// histogram with configurable precision, record() and value_at_percentile()
// (PHASE 1 latency-elite).
//
// Semantics adapted from HdrHistogram_c (the canonical C port of Gil Tene's
// HdrHistogram), captured 2026-09-19 at commit 1343a18908c6 under
// external-review/low-latency-reference/HdrHistogram_c. License: BSD-2-Clause
// / CC0-1.0 dual (see COPYING.txt / LICENSE.txt in that capture). The bucket
// configuration, index arithmetic, min/max handling and percentile rule
// (count_at = floor(p/100 * total + 0.5), clamped to >= 1, highest equivalent
// value of the crossing bucket) follow that reference exactly so our numbers
// are comparable with the industry-canonical implementation. The adaptation
// is C++20 header-only and self-contained (no malloc API, std::vector).
//
// Why HDR: a fixed-precision histogram cannot report p99.99 of sub-100 ns
// operations (the common case) and a nanosecond-period histogram cannot hold
// multi-second stalls; HDR covers both with 3 significant figures using
// ~270 KB for [1 ns, 1 hour] (see Gil Tene, "How NOT to measure latency").
#pragma once

#include <bit>
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace bench {

class HdrHistogram {
  public:
    // Mirrors hdr_init()'s validation (EINVAL -> std::invalid_argument):
    // lowest_discernible_value >= 1, 1 <= significant_figures <= 5, and
    // lowest <= highest / 2.
    HdrHistogram(int64_t lowest_discernible_value,
                 int64_t highest_trackable_value, int significant_figures) {
        if (lowest_discernible_value < 1 || significant_figures < 1 ||
            significant_figures > 5 ||
            lowest_discernible_value > highest_trackable_value / 2) {
            throw std::invalid_argument("hdr_histogram: invalid parameters");
        }

        lowest_discernible_value_ = lowest_discernible_value;
        highest_trackable_value_ = highest_trackable_value;
        significant_figures_ = significant_figures;

        // largest_value_with_single_unit_resolution = 2 * 10^sigfigs
        int64_t largest_single_unit = 2;
        for (int i = 0; i < significant_figures; ++i) largest_single_unit *= 10;

        // sub_bucket_count_magnitude = ceil(log2(largest_single_unit))
        const int32_t sub_bucket_count_magnitude = (int32_t)std::ceil(
            std::log((double)largest_single_unit) / std::log(2.0));
        sub_bucket_half_count_magnitude_ =
            (sub_bucket_count_magnitude > 1 ? sub_bucket_count_magnitude : 1) - 1;

        const double unit_mag =
            std::log((double)lowest_discernible_value) / std::log(2.0);
        if (unit_mag >= (double)std::numeric_limits<int32_t>::max()) {
            throw std::invalid_argument("hdr_histogram: unit magnitude too large");
        }
        unit_magnitude_ = (int32_t)unit_mag;  // truncation toward zero, as in C

        // Reject before shifting: the C reference guards the mask shift.
        if (unit_magnitude_ + sub_bucket_half_count_magnitude_ > 61) {
            throw std::invalid_argument("hdr_histogram: bucket config overflow");
        }

        sub_bucket_count_ = (int32_t)1 << (sub_bucket_half_count_magnitude_ + 1);
        sub_bucket_half_count_ = sub_bucket_count_ / 2;
        sub_bucket_mask_ = ((int64_t)sub_bucket_count_ - 1) << unit_magnitude_;

        bucket_count_ =
            buckets_needed_to_cover_value(highest_trackable_value);
        const int32_t counts_len =
            (bucket_count_ + 1) * (sub_bucket_count_ / 2);
        counts_.assign((size_t)counts_len, 0);

        reset();
    }

    // Records one value in [0, highest_trackable_value]; returns false when
    // the value is out of range (never throws on out-of-range data).
    bool record(int64_t value) { return record_values(value, 1); }

    bool record_values(int64_t value, int64_t count) {
        if (value < 0 || highest_trackable_value_ < value) return false;
        const int32_t idx = counts_index_for(value);
        if (idx < 0 || (size_t)idx >= counts_.size()) return false;
        counts_[(size_t)idx] += count;
        total_count_ += count;
        if (value > max_value_) max_value_ = value;
        if (value != 0 && value < min_value_) min_value_ = value;
        return true;
    }

    // Canonical percentile rule: cumulative count crossing
    // floor(p/100 * total + 0.5) (clamped to >= 1); returns the highest
    // equivalent value of the crossing bucket (lowest equivalent for p == 0).
    int64_t value_at_percentile(double percentile) const {
        const double requested = percentile < 100.0 ? percentile : 100.0;
        int64_t count_at =
            (int64_t)(((requested / 100.0) * (double)total_count_) + 0.5);
        if (count_at < 1) count_at = 1;
        int64_t running = 0;
        for (size_t i = 0; i < counts_.size(); ++i) {
            running += counts_[i];
            if (running >= count_at) {
                const int64_t v = value_at_index((int32_t)i);
                return percentile == 0.0 ? lowest_equivalent_value(v)
                                         : highest_equivalent_value(v);
            }
        }
        return 0;  // empty histogram (matches the C reference)
    }

    // Highest equivalent value of the largest observation; 0 when empty.
    int64_t max() const {
        if (max_value_ == 0) return 0;
        return highest_equivalent_value(max_value_);
    }

    // 0 if 0 was recorded; otherwise the lowest equivalent value of the
    // smallest non-zero observation; INT64_MAX when empty.
    int64_t min() const {
        if (counts_[0] > 0) return 0;
        if (min_value_ == std::numeric_limits<int64_t>::max()) {
            return std::numeric_limits<int64_t>::max();
        }
        return lowest_equivalent_value(min_value_);
    }

    int64_t total_count() const { return total_count_; }
    int64_t count_at_value(int64_t value) const {
        if (value < 0) return 0;
        const int32_t idx = counts_index_for(value);
        if (idx < 0 || (size_t)idx >= counts_.size()) return 0;
        return counts_[(size_t)idx];
    }

    // Mean over the equivalent-value medians, in double (as the C reference).
    double mean() const {
        if (total_count_ == 0) return 0.0;
        double total = 0.0;
        for (size_t i = 0; i < counts_.size(); ++i) {
            if (counts_[i] != 0) {
                const int64_t v = value_at_index((int32_t)i);
                total += (double)counts_[i] *
                         (double)(lowest_equivalent_value(v) +
                                  (size_of_equivalent_value_range(v) >> 1));
            }
        }
        return total / (double)total_count_;
    }

    double stddev() const {
        if (total_count_ == 0) return 0.0;
        const double m = mean();
        double total = 0.0;
        for (size_t i = 0; i < counts_.size(); ++i) {
            if (counts_[i] != 0) {
                const int64_t v = value_at_index((int32_t)i);
                const double median =
                    (double)(lowest_equivalent_value(v) +
                             (size_of_equivalent_value_range(v) >> 1));
                const double dev = median - m;
                total += dev * dev * (double)counts_[i];
            }
        }
        return std::sqrt(total / (double)total_count_);
    }

    void reset() {
        std::fill(counts_.begin(), counts_.end(), 0);
        total_count_ = 0;
        min_value_ = std::numeric_limits<int64_t>::max();
        max_value_ = 0;
    }

    // --- introspection (documented configuration, used by the cross-check) ---
    int64_t lowest_discernible_value() const { return lowest_discernible_value_; }
    int64_t highest_trackable_value() const { return highest_trackable_value_; }
    int significant_figures() const { return significant_figures_; }
    int32_t unit_magnitude() const { return unit_magnitude_; }
    int32_t sub_bucket_half_count_magnitude() const {
        return sub_bucket_half_count_magnitude_;
    }
    int32_t sub_bucket_count() const { return sub_bucket_count_; }
    size_t counts_len() const { return counts_.size(); }

    // Equivalent-value range helpers (same semantics as the C reference).
    int64_t lowest_equivalent_value(int64_t value) const {
        const int32_t bucket = get_bucket_index(value);
        const int32_t sub = get_sub_bucket_index(value, bucket);
        return value_from_index(bucket, sub);
    }

    int64_t size_of_equivalent_value_range(int64_t value) const {
        const int32_t bucket = get_bucket_index(value);
        const int32_t sub = get_sub_bucket_index(value, bucket);
        const int32_t adjusted =
            (sub >= sub_bucket_count_) ? bucket + 1 : bucket;
        return (int64_t)1 << (unit_magnitude_ + adjusted);
    }

    int64_t highest_equivalent_value(int64_t value) const {
        const int64_t low = lowest_equivalent_value(value);
        const int64_t size = size_of_equivalent_value_range(value);
        if (low > std::numeric_limits<int64_t>::max() - size) {
            return std::numeric_limits<int64_t>::max();
        }
        return low + size - 1;
    }

  private:
    static int32_t count_leading_zeros_64(int64_t v) {
        return std::countl_zero((uint64_t)v);
    }

    int32_t get_bucket_index(int64_t value) const {
        const int32_t pow2ceiling =
            64 - count_leading_zeros_64(value | sub_bucket_mask_);
        return pow2ceiling - unit_magnitude_ -
               (sub_bucket_half_count_magnitude_ + 1);
    }

    int32_t get_sub_bucket_index(int64_t value, int32_t bucket_index) const {
        return (int32_t)(value >> (bucket_index + unit_magnitude_));
    }

    int32_t counts_index(int32_t bucket_index, int32_t sub_bucket_index) const {
        const int32_t bucket_base =
            (bucket_index + 1) << sub_bucket_half_count_magnitude_;
        return bucket_base + (sub_bucket_index - sub_bucket_half_count_);
    }

    int32_t counts_index_for(int64_t value) const {
        const int32_t bucket = get_bucket_index(value);
        const int32_t sub = get_sub_bucket_index(value, bucket);
        return counts_index(bucket, sub);
    }

    int64_t value_from_index(int32_t bucket_index,
                             int32_t sub_bucket_index) const {
        return (int64_t)sub_bucket_index
               << (bucket_index + unit_magnitude_);
    }

    int64_t value_at_index(int32_t index) const {
        int32_t bucket_index =
            (index >> sub_bucket_half_count_magnitude_) - 1;
        int32_t sub_bucket_index =
            (index & (sub_bucket_half_count_ - 1)) + sub_bucket_half_count_;
        if (bucket_index < 0) {
            sub_bucket_index -= sub_bucket_half_count_;
            bucket_index = 0;
        }
        return value_from_index(bucket_index, sub_bucket_index);
    }

    int32_t buckets_needed_to_cover_value(int64_t value) const {
        int64_t smallest_untrackable =
            (int64_t)sub_bucket_count_ << unit_magnitude_;
        int32_t buckets_needed = 1;
        while (smallest_untrackable <= value) {
            if (smallest_untrackable >
                std::numeric_limits<int64_t>::max() / 2) {
                return buckets_needed + 1;
            }
            smallest_untrackable <<= 1;
            buckets_needed++;
        }
        return buckets_needed;
    }

    int64_t lowest_discernible_value_ = 1;
    int64_t highest_trackable_value_ = 0;
    int significant_figures_ = 3;
    int32_t unit_magnitude_ = 0;
    int32_t sub_bucket_half_count_magnitude_ = 0;
    int32_t sub_bucket_half_count_ = 0;
    int32_t sub_bucket_count_ = 0;
    int64_t sub_bucket_mask_ = 0;
    int32_t bucket_count_ = 0;
    int64_t min_value_ = std::numeric_limits<int64_t>::max();
    int64_t max_value_ = 0;
    int64_t total_count_ = 0;
    std::vector<int64_t> counts_;
};

}  // namespace bench
