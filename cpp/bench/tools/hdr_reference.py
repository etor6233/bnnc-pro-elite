"""hdr_reference.py — independent Python reference for the HDR histogram.

Direct re-derivation of the HdrHistogram_c bucket/percentile semantics
(captured 2026-09-19, commit 1343a18908c6, BSD-2-Clause / CC0-1.0 dual
license; capture path external-review/low-latency-reference/HdrHistogram_c).
Used by crosscheck_hdr.py to validate the C++ implementation in
cpp/bench/hdr_histogram.hpp with the same integer arithmetic, and by
bench_json_decode.py to report p50/p99/p99.9/p99.99 for the Python lane.

The two implementations are written in different languages on purpose: an
agreement between them cannot come from shared code.
"""
from __future__ import annotations

import math

INT64_MAX = (1 << 63) - 1


def _clz64(v: int) -> int:
    """Count leading zeros of a positive 64-bit integer (bit_length based)."""
    assert v > 0
    return 64 - v.bit_length()


class HdrHistogram:
    """Port of struct hdr_histogram semantics (hdr_histogram.c @1343a18908c6)."""

    def __init__(self, lowest_discernible_value: int,
                 highest_trackable_value: int, significant_figures: int) -> None:
        if (lowest_discernible_value < 1 or significant_figures < 1
                or significant_figures > 5
                or lowest_discernible_value > highest_trackable_value // 2):
            raise ValueError("hdr_histogram: invalid parameters")

        self.lowest_discernible_value = lowest_discernible_value
        self.highest_trackable_value = highest_trackable_value
        self.significant_figures = significant_figures

        # largest_value_with_single_unit_resolution = 2 * 10^sigfigs
        largest_single_unit = 2 * (10 ** significant_figures)

        sub_bucket_count_magnitude = int(
            math.ceil(math.log(largest_single_unit) / math.log(2.0)))
        self.sub_bucket_half_count_magnitude = (
            max(sub_bucket_count_magnitude, 1) - 1)

        unit_magnitude = math.log(lowest_discernible_value) / math.log(2.0)
        if unit_magnitude >= 1 << 31:
            raise ValueError("hdr_histogram: unit magnitude too large")
        self.unit_magnitude = int(unit_magnitude)  # truncation toward zero

        if self.unit_magnitude + self.sub_bucket_half_count_magnitude > 61:
            raise ValueError("hdr_histogram: bucket config overflow")

        self.sub_bucket_count = 1 << (self.sub_bucket_half_count_magnitude + 1)
        self.sub_bucket_half_count = self.sub_bucket_count // 2
        self.sub_bucket_mask = (
            (self.sub_bucket_count - 1) << self.unit_magnitude)

        self.bucket_count = self._buckets_needed_to_cover_value(
            highest_trackable_value)
        self.counts_len = (self.bucket_count + 1) * (
            self.sub_bucket_count // 2)
        self.counts = [0] * self.counts_len
        self.total_count = 0
        self.min_value = INT64_MAX
        self.max_value = 0

    # --- index arithmetic (mirrors hdr_histogram.c) ---

    def _get_bucket_index(self, value: int) -> int:
        pow2ceiling = 64 - _clz64(value | self.sub_bucket_mask)
        return (pow2ceiling - self.unit_magnitude
                - (self.sub_bucket_half_count_magnitude + 1))

    def _get_sub_bucket_index(self, value: int, bucket_index: int) -> int:
        return value >> (bucket_index + self.unit_magnitude)

    def _counts_index(self, bucket_index: int, sub_bucket_index: int) -> int:
        bucket_base = (bucket_index + 1) << self.sub_bucket_half_count_magnitude
        return bucket_base + (sub_bucket_index - self.sub_bucket_half_count)

    def counts_index_for(self, value: int) -> int:
        bucket = self._get_bucket_index(value)
        sub = self._get_sub_bucket_index(value, bucket)
        return self._counts_index(bucket, sub)

    def _value_from_index(self, bucket_index: int, sub_bucket_index: int) -> int:
        return sub_bucket_index << (bucket_index + self.unit_magnitude)

    def value_at_index(self, index: int) -> int:
        bucket_index = (index >> self.sub_bucket_half_count_magnitude) - 1
        sub_bucket_index = (
            (index & (self.sub_bucket_half_count - 1))
            + self.sub_bucket_half_count)
        if bucket_index < 0:
            sub_bucket_index -= self.sub_bucket_half_count
            bucket_index = 0
        return self._value_from_index(bucket_index, sub_bucket_index)

    def _buckets_needed_to_cover_value(self, value: int) -> int:
        smallest_untrackable = self.sub_bucket_count << self.unit_magnitude
        buckets_needed = 1
        while smallest_untrackable <= value:
            if smallest_untrackable > INT64_MAX // 2:
                return buckets_needed + 1
            smallest_untrackable <<= 1
            buckets_needed += 1
        return buckets_needed

    # --- equivalent values ---

    def lowest_equivalent_value(self, value: int) -> int:
        bucket = self._get_bucket_index(value)
        sub = self._get_sub_bucket_index(value, bucket)
        return self._value_from_index(bucket, sub)

    def size_of_equivalent_value_range(self, value: int) -> int:
        bucket = self._get_bucket_index(value)
        sub = self._get_sub_bucket_index(value, bucket)
        adjusted = bucket + 1 if sub >= self.sub_bucket_count else bucket
        return 1 << (self.unit_magnitude + adjusted)

    def highest_equivalent_value(self, value: int) -> int:
        low = self.lowest_equivalent_value(value)
        size = self.size_of_equivalent_value_range(value)
        if low > INT64_MAX - size:
            return INT64_MAX
        return low + size - 1

    # --- recording (mirrors hdr_record_values) ---

    def record(self, value: int, count: int = 1) -> bool:
        if value < 0 or self.highest_trackable_value < value:
            return False
        idx = self.counts_index_for(value)
        if idx < 0 or idx >= self.counts_len:
            return False
        self.counts[idx] += count
        self.total_count += count
        if value > self.max_value:
            self.max_value = value
        if value != 0 and value < self.min_value:
            self.min_value = value
        return True

    # --- queries (mirrors hdr_min/hdr_max/hdr_value_at_percentile) ---

    def max(self) -> int:
        if self.max_value == 0:
            return 0
        return self.highest_equivalent_value(self.max_value)

    def min(self) -> int:
        if self.counts[0] > 0:
            return 0
        if self.min_value == INT64_MAX:
            return INT64_MAX
        return self.lowest_equivalent_value(self.min_value)

    def value_at_percentile(self, percentile: float) -> int:
        requested = percentile if percentile < 100.0 else 100.0
        count_at = int(((requested / 100.0) * self.total_count) + 0.5)
        count_at = max(count_at, 1)
        running = 0
        for i, c in enumerate(self.counts):
            running += c
            if running >= count_at:
                v = self.value_at_index(i)
                if percentile == 0.0:
                    return self.lowest_equivalent_value(v)
                return self.highest_equivalent_value(v)
        return 0

    def count_at_value(self, value: int) -> int:
        if value < 0:
            return 0
        idx = self.counts_index_for(value)
        if idx < 0 or idx >= self.counts_len:
            return 0
        return self.counts[idx]

    def mean(self) -> float:
        if self.total_count == 0:
            return 0.0
        total = 0.0
        for i, c in enumerate(self.counts):
            if c != 0:
                v = self.value_at_index(i)
                median = (self.lowest_equivalent_value(v)
                          + (self.size_of_equivalent_value_range(v) >> 1))
                total += float(c) * float(median)
        return total / float(self.total_count)


# Percentile set used by every FASE 1 report (documented once, reused).
STANDARD_PERCENTILES = (0.0, 50.0, 90.0, 99.0, 99.9, 99.99, 100.0)


def percentiles_of(hist: HdrHistogram) -> dict[str, int]:
    """Map the standard percentile set to measured values."""
    return {f"p{p:g}": hist.value_at_percentile(p)
            for p in STANDARD_PERCENTILES}
