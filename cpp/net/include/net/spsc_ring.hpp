// net/spsc_ring.hpp — bounded lock-free single-producer/single-consumer ring
// buffer (FASE 3 optional item, shared-memory inter-process pattern).
//
// Design reference: Aeron media-driver ring-buffer pattern (captured in
// external-review/low-latency-reference/aeron; DESIGN ONLY, not copied).
// Per MARKET_MICROSTRUCTURE_EXCHANGE_SYSTEMS.md §5.4: every ring/queue must
// have slots, bytes, age and an overflow policy — for market data, silent
// drop is forbidden. This ring therefore makes overflow EXPLICIT: try_push
// returns false when full so the upstream applies its recovery policy
// (gap -> invalidate -> resync), never a silent drop.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>
#include <vector>

namespace net {

// Capacity is rounded up to a power of two internally; exposed capacity()
// reports the usable slot count (capacity_round - 1).
template <typename T>
class SpscRing {
  public:
    explicit SpscRing(size_t capacity) {
        size_t cap = 1;
        while (cap < capacity + 1) cap <<= 1;
        slots_ = cap;
        ring_.resize(cap);
        head_.store(0, std::memory_order_relaxed);
        tail_.store(0, std::memory_order_relaxed);
    }

    size_t capacity() const { return slots_ - 1; }

    // Producer side (single thread). Returns false when full: explicit
    // overflow, never a silent drop.
    bool try_push(const T& value) {
        const size_t head = head_.load(std::memory_order_acquire);
        const size_t tail = tail_.load(std::memory_order_relaxed);
        const size_t next = (tail + 1) & (slots_ - 1);
        if (next == head) return false;  // full
        ring_[tail] = value;
        tail_.store(next, std::memory_order_release);
        return true;
    }

    // Consumer side (single thread). Returns false when empty.
    bool try_pop(T& out) {
        const size_t tail = tail_.load(std::memory_order_acquire);
        const size_t head = head_.load(std::memory_order_relaxed);
        if (head == tail) return false;  // empty
        out = ring_[head];
        head_.store((head + 1) & (slots_ - 1), std::memory_order_release);
        return true;
    }

    size_t size() const {
        const size_t head = head_.load(std::memory_order_acquire);
        const size_t tail = tail_.load(std::memory_order_acquire);
        return (tail - head) & (slots_ - 1);
    }

    bool empty() const { return size() == 0; }

  private:
    std::vector<T> ring_;
    size_t slots_ = 0;
    alignas(64) std::atomic<size_t> head_;
    alignas(64) std::atomic<size_t> tail_;
};

}  // namespace net
