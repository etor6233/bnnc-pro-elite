// net/tests/test_spsc.cpp — FASE 2 (latency elite): functional + static
// tests for the bounded lock-free SPSC ring (net/spsc_ring.hpp).
//
// The cache-line guarantees (head_ and tail_ on distinct 64-byte lines) are
// enforced at COMPILE TIME by the static_asserts inside net/spsc_ring.hpp —
// building this TU (MSVC and g++, both CI legs) proves them. Here we pin the
// functional contract: FIFO order, capacity rounding, explicit overflow
// (try_push returns false when full — never a silent drop), and size/empty.
#include <net/spsc_ring.hpp>

#include <cstdint>

#include <afx/test_framework.hpp>

using net::SpscRing;

// The alignas(64) members must propagate to the type's alignment: if the
// header's own static_asserts were weakened, this one still fails the build.
static_assert(alignof(SpscRing<uint64_t>) >= 64,
              "SpscRing must be cache-line aligned (alignas(64) members)");

AFX_TEST(cache_line_separation_runtime_probe) {
    SpscRing<uint64_t> r(1024);
    // Runtime corroboration of the false-sharing-free layout: the producer's
    // tail_ and the consumer's head_ must be >= 64 bytes apart in the
    // actually-built object (compile-time guarantee lives in the header).
    AFX_EXPECT(r.index_separation_bytes() >= 64);
    SpscRing<uint8_t> r2(16);
    AFX_EXPECT(r2.index_separation_bytes() >= 64);
}

AFX_TEST(capacity_rounds_to_power_of_two) {
    SpscRing<uint64_t> r(1000);
    // capacity() reports the usable slot count (2^k - 1 slots).
    AFX_EXPECT(r.capacity() >= 1000);
    AFX_EXPECT_EQ(r.capacity() & (r.capacity() + 1), 0);  // capacity+1 == 2^k
    AFX_EXPECT(r.empty());
}

AFX_TEST(fifo_order) {
    SpscRing<uint64_t> r(1024);
    for (uint64_t i = 0; i < 100; ++i) AFX_EXPECT(r.try_push(i));
    AFX_EXPECT_EQ(r.size(), 100);
    for (uint64_t i = 0; i < 100; ++i) {
        uint64_t v = 0;
        AFX_EXPECT(r.try_pop(v));
        AFX_EXPECT_EQ(v, i);  // strict FIFO
    }
    AFX_EXPECT(r.empty());
}

AFX_TEST(explicit_overflow_no_silent_drop) {
    SpscRing<uint64_t> r(4);  // rounds up to 8 slots -> usable capacity 7
    AFX_EXPECT_EQ(r.capacity(), 7);
    for (uint64_t i = 0; i < 7; ++i) AFX_EXPECT(r.try_push(i));
    AFX_EXPECT(!r.try_push(999));  // full -> explicit false, nothing dropped
    AFX_EXPECT_EQ(r.size(), 7);
    uint64_t v = 0;
    AFX_EXPECT(r.try_pop(v));
    AFX_EXPECT_EQ(v, 0);
    AFX_EXPECT(r.try_push(999));  // slot freed -> accepted
    uint64_t w = 0;
    for (uint64_t i = 0; i < 7; ++i) AFX_EXPECT(r.try_pop(w));
    AFX_EXPECT_EQ(w, 999);  // the pushed value survived, nothing lost
    AFX_EXPECT(r.empty());
}

AFX_TEST(empty_pop_returns_false) {
    SpscRing<uint64_t> r(4);
    uint64_t v = 42;
    AFX_EXPECT(!r.try_pop(v));
    AFX_EXPECT_EQ(v, 42);  // output untouched on empty
}

AFX_TEST(size_wraparound) {
    SpscRing<uint64_t> r(4);  // rounds up to 8 slots -> usable capacity 7
    uint64_t v = 0;
    for (int round = 0; round < 100; ++round) {
        AFX_EXPECT(r.try_push(1));
        AFX_EXPECT(r.try_push(2));
        AFX_EXPECT(r.try_pop(v));
        AFX_EXPECT_EQ(v, 1);
        AFX_EXPECT(r.try_pop(v));
        AFX_EXPECT_EQ(v, 2);
        AFX_EXPECT(r.empty());
    }
}

AFX_TEST(single_slot_capacity) {
    SpscRing<uint64_t> r(1);  // usable capacity 1
    AFX_EXPECT(r.try_push(7));
    AFX_EXPECT(!r.try_push(8));  // full
    uint64_t v = 0;
    AFX_EXPECT(r.try_pop(v));
    AFX_EXPECT_EQ(v, 7);
    AFX_EXPECT(r.empty());
}

int main(int argc, char** argv) { return afx::run_all(argc, argv); }
