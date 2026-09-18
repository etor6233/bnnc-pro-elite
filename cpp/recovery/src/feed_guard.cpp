// recovery/feed_guard.cpp — instant loss detection + elite recovery engine.
//
// Implements ELITE_LOSS_RECOVERY_20260918.md §0-§4 from the annotated specs:
// cadence-based total-silence detection (depth@20ms, 2-5 windows), watchdog
// ping/pong deadline 5 s, typed causes, A/B arbitration, snapshot bridging,
// Binance diff-depth book continuity, and anticipation signals.
#include <recovery/feed_guard.hpp>

#include <algorithm>
#include <cmath>

namespace recovery {

const char* to_string(SilenceCause c) {
    switch (c) {
        case SilenceCause::None: return "none";
        case SilenceCause::TransportDead: return "transport_dead";
        case SilenceCause::ExchangeSilent: return "exchange_silent";
        case SilenceCause::ServerShutdown: return "serverShutdown";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// CadenceGuard
// ---------------------------------------------------------------------------

CadenceGuard::CadenceGuard(uint64_t period_ms, uint32_t windows)
    : period_ms_(period_ms), windows_(windows) {}

void CadenceGuard::on_message(uint64_t clock_ms) {
    if (fired_ != SilenceCause::None) return;
    last_message_ms_ = clock_ms;
    seen_ = true;
}

void CadenceGuard::on_transport_error() {
    if (fired_ != SilenceCause::None) return;
    fired_ = SilenceCause::TransportDead;
    fired_at_ms_ = last_message_ms_;
}

void CadenceGuard::on_server_shutdown() {
    if (fired_ != SilenceCause::None) return;
    fired_ = SilenceCause::ServerShutdown;
    fired_at_ms_ = last_message_ms_;
}

SilenceCause CadenceGuard::poll(uint64_t clock_ms) {
    if (fired_ != SilenceCause::None) return fired_;
    if (!seen_) return SilenceCause::None;
    if (clock_ms - last_message_ms_ >= deadline_ms()) {
        fired_ = SilenceCause::ExchangeSilent;
        fired_at_ms_ = clock_ms;
    }
    return fired_;
}

uint64_t CadenceGuard::silence_ms(uint64_t clock_ms) const {
    if (!seen_) return 0;
    return clock_ms - last_message_ms_;
}

// ---------------------------------------------------------------------------
// Watchdog
// ---------------------------------------------------------------------------

Watchdog::Watchdog(uint64_t deadline_ms) : deadline_ms_(deadline_ms) {}

void Watchdog::on_ping_sent(uint64_t clock_ms) {
    ping_outstanding_ = true;
    ping_sent_ms_ = clock_ms;
}

void Watchdog::on_pong(uint64_t clock_ms) {
    if (!ping_outstanding_) return;
    last_rtt_ms_ = clock_ms - ping_sent_ms_;
    ping_outstanding_ = false;
}

bool Watchdog::expired(uint64_t clock_ms) const {
    return ping_outstanding_ && (clock_ms - ping_sent_ms_) > deadline_ms_;
}

// ---------------------------------------------------------------------------
// DualLaneArbiter
// ---------------------------------------------------------------------------

DualLaneArbiter::DualLaneArbiter() = default;

void DualLaneArbiter::on_packet(uint32_t lane, const net::FeedMessage& m,
                                std::vector<ArbiterEvent>& out) {
    if (lane > 1 || m.type != net::MsgType::MarketPayload) return;
    std::vector<net::FeedEvent> lane_events;
    lane_[lane].on_frame(m, lane_events);
    for (const auto& e : lane_events) {
        if (e.kind == net::FeedEvent::Kind::GapDetected) {
            ArbiterEvent ev;
            ev.kind = ArbiterEvent::Kind::LaneGapTyped;
            ev.lane = lane;
            ev.first = e.gap.first;
            ev.last = e.gap.last;
            out.push_back(std::move(ev));
            auto& pending = (lane == 0) ? pending_a_ : pending_b_;
            for (uint64_t s = e.gap.first;; ++s) {
                pending.insert((uint32_t)s);
                if (s == e.gap.last) break;
            }
            // A sequence missing on BOTH lanes becomes a consumer gap.
            const auto& other = (lane == 0) ? pending_b_ : pending_a_;
            std::vector<uint32_t> both;
            for (uint32_t s : pending) {
                if (other.count(s) != 0) both.push_back(s);
            }
            if (!both.empty()) {
                std::sort(both.begin(), both.end());
                ArbiterEvent cg;
                cg.kind = ArbiterEvent::Kind::ConsumerGap;
                cg.first = both.front();
                cg.last = both.back();
                out.push_back(std::move(cg));
            }
        } else if (e.kind == net::FeedEvent::Kind::Delivered) {
            const uint32_t seq = e.deliver.message.sequence;
            if (delivered_.count(seq) == 0) {
                delivered_.insert(seq);
                ArbiterEvent ev;
                ev.kind = ArbiterEvent::Kind::Delivered;
                ev.message = e.deliver.message;
                ev.lane = lane;
                out.push_back(std::move(ev));
            }
            // Clean the per-lane pending gaps the other lane already covers.
            auto& mine = (lane == 0) ? pending_a_ : pending_b_;
            auto& other = (lane == 0) ? pending_b_ : pending_a_;
            mine.erase(seq);
            other.erase(seq);
        }
    }
}

void DualLaneArbiter::apply_snapshot(uint32_t snapshot_sequence,
                                     std::vector<ArbiterEvent>& out) {
    std::vector<net::FeedEvent> l0, l1;
    lane_[0].apply_snapshot(snapshot_sequence, l0);
    lane_[1].apply_snapshot(snapshot_sequence, l1);
    pending_a_.clear();
    pending_b_.clear();
    if (snapshot_sequence >= covered_floor_) {
        covered_floor_ = snapshot_sequence;
    }
    ArbiterEvent ev;
    ev.kind = ArbiterEvent::Kind::SnapshotBridged;
    ev.snapshot_sequence = snapshot_sequence;
    out.push_back(std::move(ev));
}

bool DualLaneArbiter::is_delivered(uint32_t seq) const {
    if (seq <= covered_floor_) return true;
    return delivered_.count(seq) != 0;
}

// ---------------------------------------------------------------------------
// DerivedBook (Binance diff-depth continuity)
// ---------------------------------------------------------------------------

int64_t DerivedBook::normalize_price(const DepthDiff::Change& c) {
    // Normalize mantissa*10^exp to a fixed -8 scale: key = m * 10^(exp+8).
    const int shift = (int)c.price_exponent + 8;
    long double v = (long double)c.price_mantissa;
    if (shift >= 0) {
        for (int i = 0; i < shift; ++i) v *= 10.0L;
    } else {
        for (int i = 0; i < -shift; ++i) v /= 10.0L;
    }
    return (int64_t)std::llround(v);
}

uint64_t DerivedBook::normalize_qty(const DepthDiff::Change& c) {
    const int shift = (int)c.qty_exponent + 8;
    long double v = (long double)c.qty_mantissa;
    if (shift >= 0) {
        for (int i = 0; i < shift; ++i) v *= 10.0L;
    } else {
        for (int i = 0; i < -shift; ++i) v /= 10.0L;
    }
    return (uint64_t)std::llround(v);
}

bool DerivedBook::apply_diff(const DepthDiff& d, BookEvent& out) {
    // Binance local-book rule: firstBookUpdateId must bridge the previous
    // lastBookUpdateId (source-lock web-socket-streams.md, annotated in
    // MARKET_MICROSTRUCTURE §5.1). A gap invalidates the book -> resync.
    if (seen_first_ && d.first_update_id != last_update_id_ + 1) {
        valid_ = false;
        out.kind = BookEvent::Kind::ResyncNeeded;
        out.gap_first = last_update_id_ + 1;
        out.gap_last = d.first_update_id - 1;
        bids_.clear();
        asks_.clear();
        seen_first_ = false;
        return false;
    }
    for (const auto& b : d.bids) {
        const int64_t key = normalize_price(b);
        const uint64_t qty = normalize_qty(b);
        if (qty == 0) {
            bids_.erase(key);  // zero quantity removes the level
        } else {
            bids_[key] = qty;  // set quantity, never sum
        }
    }
    for (const auto& a : d.asks) {
        const int64_t key = normalize_price(a);
        const uint64_t qty = normalize_qty(a);
        if (qty == 0) {
            asks_.erase(key);
        } else {
            asks_[key] = qty;
        }
    }
    seen_first_ = true;
    valid_ = true;
    last_update_id_ = d.last_update_id;
    out.kind = BookEvent::Kind::Applied;
    out.book_update_id = d.last_update_id;
    return true;
}

void DerivedBook::install_snapshot(int64_t book_update_id,
                                   const std::vector<DepthDiff::Change>& bids,
                                   const std::vector<DepthDiff::Change>& asks) {
    bids_.clear();
    asks_.clear();
    for (const auto& b : bids) {
        const uint64_t qty = normalize_qty(b);
        if (qty == 0) continue;
        bids_[normalize_price(b)] = qty;
    }
    for (const auto& a : asks) {
        const uint64_t qty = normalize_qty(a);
        if (qty == 0) continue;
        asks_[normalize_price(a)] = qty;
    }
    seen_first_ = true;
    valid_ = true;
    last_update_id_ = book_update_id;
}

std::optional<int64_t> DerivedBook::best_bid() const {
    if (bids_.empty()) return std::nullopt;
    return bids_.rbegin()->first;
}

std::optional<int64_t> DerivedBook::best_ask() const {
    if (asks_.empty()) return std::nullopt;
    return asks_.begin()->first;
}

std::optional<uint64_t> DerivedBook::qty_at(bool is_bid, int64_t price_key) const {
    const auto& m = is_bid ? bids_ : asks_;
    auto it = m.find(price_key);
    if (it == m.end()) return std::nullopt;
    return it->second;
}

// ---------------------------------------------------------------------------
// SignalMonitor
// ---------------------------------------------------------------------------

SignalMonitor::SignalMonitor(double expected_rate_hz)
    : expected_rate_hz_(expected_rate_hz) {}

void SignalMonitor::on_message(uint64_t clock_ms) {
    arrivals_.push_back(clock_ms);
    while (!arrivals_.empty() && clock_ms - arrivals_.front() > 5000) {
        arrivals_.pop_front();
    }
    if (window_start_ms_ == 0) window_start_ms_ = clock_ms;
}

void SignalMonitor::on_gap() { ++gaps_; }

void SignalMonitor::on_rtt_sample(uint64_t rtt_ms, uint64_t clock_ms) {
    rtt_.emplace_back(clock_ms, rtt_ms);
    while (rtt_.size() > 32) rtt_.pop_front();
}

void SignalMonitor::on_uptime(uint64_t uptime_ms) {
    // Preventive rotation before the venue deadline: 23 h of the 24 h max.
    preventive_rotation_due_ = uptime_ms >= 23ull * 3600 * 1000;
}

AnticipationSignals SignalMonitor::snapshot(uint64_t clock_ms) const {
    AnticipationSignals s;
    uint64_t window = clock_ms - window_start_ms_;
    if (window > 0 && !arrivals_.empty()) {
        const double observed_hz = 1000.0 * (double)arrivals_.size() / (double)window;
        s.rate_deviation_ratio = observed_hz / expected_rate_hz_ - 1.0;
    }
    s.gaps_observed = gaps_;
    if (window > 0) {
        s.gaps_per_minute = 60000.0 * (double)gaps_ / (double)window;
    }
    if (rtt_.size() >= 2) {
        const auto& first = rtt_.front();
        const auto& last = rtt_.back();
        const uint64_t dt = last.first - first.first;
        if (dt > 0) {
            s.rtt_trend_ms = (double)((int64_t)last.second - (int64_t)first.second) /
                             ((double)dt / 1000.0);
        }
    }
    s.preventive_rotation_due = preventive_rotation_due_;
    return s;
}

}  // namespace recovery
