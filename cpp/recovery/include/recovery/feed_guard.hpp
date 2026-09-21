// recovery/feed_guard.hpp — instant loss detection + elite recovery
// (PHASE 3-B). Implements ELITE_LOSS_RECOVERY_20260918.md §0-§4.
//
// Two distinct problems (ELITE_LOSS_RECOVERY §0):
//  A) TOTAL SILENCE — the flow dies. Detection by FEED CADENCE (depth@20ms:
//     no messages in 2-5 windows = dead, typed instantly) and by watchdog
//     ping/pong (deadline 5 s). Causes typed: transport_dead /
//     exchange_silent / serverShutdown.
//  B) PACKET LOSS — the flow is ALIVE but messages are missing in the middle.
//     Detection by per-message sequence (arrives N+k, expected N+1 -> gap
//     [N+1..N+k-1] instantly, exact range); recovery via A/B dual-feed
//     arbitration + snapshot/sequence bridging; raw gaps stay TYPED.
//
// Anticipation signals (ELITE_LOSS_RECOVERY §4): rate deviation, gap
// frequency, RTT trend, transport counters, serverShutdown, preventive
// rotation.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <net/mcast_feed.hpp>

namespace recovery {

// --- typed silence causes (ELITE_LOSS_RECOVERY §0 A) ------------------------
enum class SilenceCause : uint8_t {
    None = 0,
    TransportDead,   // socket/transport error or watchdog deadline
    ExchangeSilent,  // venue stopped emitting everything (cadence death)
    ServerShutdown,  // venue announced serverShutdown
};
const char* to_string(SilenceCause c);

// --- cadence-based total-silence detection ----------------------------------
// depth@20ms cadence: dead when no message arrives within `windows` windows
// (2-5 per ELITE_LOSS_RECOVERY; default 3, configurable).
class CadenceGuard {
  public:
    // period_ms: feed cadence (e.g. 20). windows: silence windows before
    // declaring exchange_silent (2..5). clock_ms: monotonic virtual clock.
    CadenceGuard(uint64_t period_ms, uint32_t windows);

    // Call on every received market message with the current clock.
    void on_message(uint64_t clock_ms);

    // Call on an explicit transport failure (socket error/close).
    void on_transport_error();

    // Call when the venue announces serverShutdown.
    void on_server_shutdown();

    // Poll: returns the typed cause once detection fires (sticky), else None.
    // Also returns the silence duration so callers can verify the deadline.
    SilenceCause poll(uint64_t clock_ms);

    uint64_t deadline_ms() const { return period_ms_ * windows_; }
    uint64_t silence_ms(uint64_t clock_ms) const;

  private:
    uint64_t period_ms_;
    uint32_t windows_;
    uint64_t last_message_ms_ = 0;
    bool seen_ = false;
    SilenceCause fired_ = SilenceCause::None;
    uint64_t fired_at_ms_ = 0;
};

// --- watchdog ping/pong (deadline 5 s, ELITE_LOSS_RECOVERY §0 A) ------------
class Watchdog {
  public:
    explicit Watchdog(uint64_t deadline_ms = 5000);

    void on_ping_sent(uint64_t clock_ms);
    void on_pong(uint64_t clock_ms);
    // True when a ping went unanswered past the deadline.
    bool expired(uint64_t clock_ms) const;
    uint64_t last_rtt_ms() const { return last_rtt_ms_; }

  private:
    uint64_t deadline_ms_;
    bool ping_outstanding_ = false;
    uint64_t ping_sent_ms_ = 0;
    uint64_t last_rtt_ms_ = 0;
};

// --- A/B dual-feed arbitration ------------------------------------------------
// Per-lane sequenced feeds (net::SequencedFeed) arbitrated by sequence: a
// message missing on A is taken from B (CME MDP 3.0 Incremental Feed
// Arbitration pattern; HOT_REDUNDANT_CAPTURE_AUTHORITY_V1.md annotates the
// Binance boundary). Consumer-facing gaps are declared ONLY when a sequence
// is missing from BOTH lanes, and the raw per-lane gap stays typed.
struct ArbiterEvent {
    enum class Kind : uint8_t {
        Delivered,       // continuous derived message (union of lanes)
        LaneGapTyped,    // typed raw gap on one lane (exact range)
        ConsumerGap,     // missing from both lanes (exact range)
        SnapshotBridged, // state re-seeded from snapshot at sequence
    } kind = Kind::Delivered;
    net::FeedMessage message;
    uint32_t lane = 0;  // 0=A, 1=B (LaneGapTyped only)
    uint32_t first = 0, last = 0;   // gap range
    uint32_t snapshot_sequence = 0;
};

class DualLaneArbiter {
  public:
    DualLaneArbiter();

    // Feed a frame received on lane A or B.
    void on_packet(uint32_t lane, const net::FeedMessage& m,
                   std::vector<ArbiterEvent>& out);

    // Snapshot bridging: state re-seeded at `snapshot_sequence`.
    void apply_snapshot(uint32_t snapshot_sequence, std::vector<ArbiterEvent>& out);

    // Sequences delivered continuously to the consumer (explicitly delivered
    // plus everything covered by a snapshot bridge).
    bool is_delivered(uint32_t seq) const;
    size_t delivered_count() const { return delivered_.size(); }

  private:
    net::SequencedFeed lane_[2];
    std::set<uint32_t> delivered_;         // union sequences handed out
    std::set<uint32_t> pending_a_, pending_b_;  // per-lane typed gaps
    uint32_t covered_floor_ = 0;           // all seqs <= floor are covered
    bool seen_first_ = false;
};

// --- snapshot + sequence bridging for book continuity -------------------------
// Binance local-book rule (BINANCE_SOURCE_LOCK web-socket-streams.md,
// annotated in MARKET_MICROSTRUCTURE §5.1): applying a diff requires
// firstBookUpdateId == lastBookUpdateId+1 of the previous event; a gap
// invalidates the book (resync), never silent.
struct DepthDiff {
    int64_t first_update_id = 0;
    int64_t last_update_id = 0;
    int64_t event_time_us = 0;
    struct Change {
        int64_t price_mantissa = 0;
        int8_t price_exponent = 0;
        int64_t qty_mantissa = 0;
        int8_t qty_exponent = 0;
    };
    std::vector<Change> bids;
    std::vector<Change> asks;
};

struct BookEvent {
    enum class Kind : uint8_t {
        Applied,       // diff applied in sequence
        ResyncNeeded,  // update-id gap: drop the book, re-bootstrap
        SnapshotInstalled,
    } kind = Kind::Applied;
    int64_t book_update_id = 0;  // last applied
    int64_t gap_first = 0, gap_last = 0;  // ResyncNeeded only
};

class DerivedBook {
  public:
    // Fixed scale -8 normalization for int64 keys/quantities.
    bool apply_diff(const DepthDiff& d, BookEvent& out);
    // Install a snapshot (levels) anchored at `book_update_id`.
    void install_snapshot(int64_t book_update_id,
                          const std::vector<DepthDiff::Change>& bids,
                          const std::vector<DepthDiff::Change>& asks);
    size_t level_count() const { return bids_.size() + asks_.size(); }
    bool is_valid() const { return valid_; }
    int64_t last_update_id() const { return last_update_id_; }
    std::optional<int64_t> best_bid() const;
    std::optional<int64_t> best_ask() const;
    std::optional<uint64_t> qty_at(bool is_bid, int64_t price_key) const;

  private:
    static int64_t normalize_price(const DepthDiff::Change& c);
    static uint64_t normalize_qty(const DepthDiff::Change& c);
    std::map<int64_t, uint64_t> bids_;
    std::map<int64_t, uint64_t> asks_;
    bool valid_ = false;
    bool seen_first_ = false;
    int64_t last_update_id_ = 0;
};

// --- anticipation signals (ELITE_LOSS_RECOVERY §4) ---------------------------
struct AnticipationSignals {
    double rate_deviation_ratio = 0.0;  // observed/expected frame rate - 1
    uint64_t gaps_observed = 0;         // cumulative typed gaps
    double gaps_per_minute = 0.0;
    double rtt_trend_ms = 0.0;          // slope of recent RTT samples
    bool preventive_rotation_due = false;
};

class SignalMonitor {
  public:
    // expected_rate_hz: nominal feed rate (e.g. 50 for depth@20ms).
    explicit SignalMonitor(double expected_rate_hz);

    void on_message(uint64_t clock_ms);
    void on_gap();
    void on_rtt_sample(uint64_t rtt_ms, uint64_t clock_ms);
    // Rotation when the connection approaches its venue lifetime: 23 h of the
    // 24 h max (ELITE_LOSS_RECOVERY §4, already the production policy).
    void on_uptime(uint64_t uptime_ms);
    AnticipationSignals snapshot(uint64_t clock_ms) const;

  private:
    double expected_rate_hz_;
    std::deque<uint64_t> arrivals_;
    std::deque<std::pair<uint64_t, uint64_t>> rtt_;  // (clock, rtt)
    uint64_t gaps_ = 0;
    uint64_t window_start_ms_ = 0;
    bool preventive_rotation_due_ = false;
};

}  // namespace recovery
