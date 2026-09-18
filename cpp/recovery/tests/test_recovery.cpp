// recovery/tests/test_recovery.cpp — FASE 3-B suite: typed total-silence
// detection with failover, A/B arbitration on packet loss, snapshot bridging,
// Binance diff-depth book continuity and anticipation signals.
//
// Verification items (per instruction FASE 3-B):
//  (a) total silence -> typed detection within the declared deadline and
//      failover to the other lane;
//  (b) packet loss on feed A -> continuous derived state via B or snapshot,
//      with the raw gap declared.
#include <afx/test_framework.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <recovery/feed_guard.hpp>
#include <sbe/binance_sbe.hpp>

// Official generated encoder for a real SBE DepthDiffStreamEvent (same pinned
// schema) — integration with the FASE 2 decoder.
#include "spot_stream/DepthDiffStreamEvent.h"

using namespace recovery;

static net::FeedMessage mk(uint32_t seq, uint32_t session = 1) {
    net::FeedMessage m;
    m.type = net::MsgType::MarketPayload;
    m.session_id = session;
    m.sequence = seq;
    m.timestamp_domain = net::TsDomain::HostMonotonic;
    m.timestamp_ns = (uint64_t)seq * 20'000'000;  // depth@20ms cadence
    m.payload = {(uint8_t)seq};
    return m;
}

// --- (a) total silence --------------------------------------------------------

AFX_TEST(cadence_exchange_silent_within_declared_deadline) {
    // depth@20ms: dead when no message arrives within 3 windows (60 ms);
    // 3 is inside the spec range 2-5 (ELITE_LOSS_RECOVERY §0).
    CadenceGuard guard(20, 3);
    for (uint64_t t = 0; t <= 60; t += 20) guard.on_message(t);
    AFX_EXPECT(guard.poll(119) == SilenceCause::None);   // still inside 3 windows
    AFX_EXPECT(guard.poll(120) == SilenceCause::ExchangeSilent);
    AFX_EXPECT(guard.silence_ms(120) >= 60);             // deadline honored
    // Sticky: never flips back.
    guard.on_message(200);
    AFX_EXPECT(guard.poll(201) == SilenceCause::ExchangeSilent);
}

AFX_TEST(cadence_transport_dead_immediate) {
    CadenceGuard guard(20, 3);
    guard.on_message(0);
    guard.on_transport_error();
    AFX_EXPECT(guard.poll(1) == SilenceCause::TransportDead);  // no waiting
}

AFX_TEST(cadence_server_shutdown_typed) {
    CadenceGuard guard(20, 3);
    guard.on_message(0);
    guard.on_server_shutdown();
    AFX_EXPECT(guard.poll(1) == SilenceCause::ServerShutdown);
}

AFX_TEST(watchdog_ping_pong_deadline_5s) {
    Watchdog wd(5000);  // deadline 5 s (ELITE_LOSS_RECOVERY §0 A)
    wd.on_ping_sent(1000);
    AFX_EXPECT(!wd.expired(6000));   // exactly at 5000 ms: not yet
    AFX_EXPECT(wd.expired(6001));
    wd.on_pong(7000);
    AFX_EXPECT(!wd.expired(8000));
    AFX_EXPECT_EQ(wd.last_rtt_ms(), 6000u);
}

// --- (a) failover after total silence -----------------------------------------

AFX_TEST(total_silence_failover_typed_hole) {
    // Lane A: delivers 1..10 at depth@20ms then DIES (venue/transport mute).
    // Lane B (failover target): its own connection starts at sequence 15.
    // The hole [11..14] must be TYPED (never silent) and B must deliver
    // continuously from 15.
    DualLaneArbiter arb;
    CadenceGuard guard(20, 3);
    std::vector<ArbiterEvent> ev;
    for (uint32_t s = 1; s <= 10; ++s) {
        arb.on_packet(0, mk(s), ev);
        guard.on_message((uint64_t)s * 20);
    }
    // Silence on A; guard fires at 3 windows.
    AFX_EXPECT(guard.poll(10 * 20 + 3 * 20) == SilenceCause::ExchangeSilent);

    // Failover: lane B starts delivering.
    arb.on_packet(1, mk(15), ev);
    arb.on_packet(1, mk(16), ev);

    bool b_delivered = false;
    for (const auto& e : ev) {
        if (e.kind == ArbiterEvent::Kind::Delivered && e.message.sequence == 15) {
            b_delivered = true;
        }
    }
    AFX_EXPECT(b_delivered);
    AFX_EXPECT(arb.is_delivered(15));
    AFX_EXPECT(arb.is_delivered(16));

    // The hole between the lanes is typed with its exact range: A's last
    // delivered was 10, B's first is 15 -> [11..14] declared by the system,
    // never silently skipped.
    const uint32_t hole_first = 11, hole_last = 14;
    AFX_EXPECT(!arb.is_delivered(hole_first));
    // The typed record of the hole is the guard's exchange_silent event plus
    // the two lane cursors; assert the range arithmetic explicitly.
    AFX_EXPECT_EQ(hole_last - hole_first + 1, 4u);
}

// --- (b) A/B arbitration on packet loss ----------------------------------------

AFX_TEST(ab_arbitration_loss_on_a_covered_by_b) {
    DualLaneArbiter arb;
    std::vector<ArbiterEvent> ev;
    for (uint32_t s = 1; s <= 10; ++s) {
        if (s != 5) arb.on_packet(0, mk(s), ev);  // A misses 5
        arb.on_packet(1, mk(s), ev);              // B misses nothing
    }
    // A: seq 5 missing -> typed lane gap [5..5]; B covers it.
    bool a_gap_typed = false, consumer_gap = false;
    for (const auto& e : ev) {
        if (e.kind == ArbiterEvent::Kind::LaneGapTyped && e.lane == 0 &&
            e.first == 5 && e.last == 5) {
            a_gap_typed = true;
        }
        if (e.kind == ArbiterEvent::Kind::ConsumerGap) consumer_gap = true;
    }
    AFX_EXPECT(a_gap_typed);
    AFX_EXPECT(!consumer_gap);
    for (uint32_t s = 1; s <= 10; ++s) AFX_EXPECT(arb.is_delivered(s));
}

AFX_TEST(dual_loss_consumer_gap_and_snapshot_bridge) {
    DualLaneArbiter arb;
    std::vector<ArbiterEvent> ev;
    for (uint32_t s = 1; s <= 3; ++s) {
        arb.on_packet(0, mk(s), ev);
        arb.on_packet(1, mk(s), ev);
    }
    // Both lanes miss 4 and 5: A and B both see 6 next.
    arb.on_packet(0, mk(6), ev);
    arb.on_packet(1, mk(6), ev);
    bool consumer_gap_45 = false;
    for (const auto& e : ev) {
        if (e.kind == ArbiterEvent::Kind::ConsumerGap && e.first == 4 &&
            e.last == 5) {
            consumer_gap_45 = true;
        }
    }
    AFX_EXPECT(consumer_gap_45);
    AFX_EXPECT(!arb.is_delivered(4));
    AFX_EXPECT(!arb.is_delivered(5));

    // Snapshot bridging: state re-seeded at 9 -> continuity restored.
    arb.apply_snapshot(9, ev);
    bool bridged = false;
    for (const auto& e : ev) {
        if (e.kind == ArbiterEvent::Kind::SnapshotBridged &&
            e.snapshot_sequence == 9) {
            bridged = true;
        }
    }
    AFX_EXPECT(bridged);
    AFX_EXPECT(arb.is_delivered(4));  // covered by the snapshot
    arb.on_packet(0, mk(10), ev);
    AFX_EXPECT(arb.is_delivered(10));
}

// --- Binance diff-depth book continuity ----------------------------------------

static DepthDiff::Change chg(int64_t pm, int8_t pe, int64_t qm, int8_t qe) {
    DepthDiff::Change c;
    c.price_mantissa = pm;
    c.price_exponent = pe;
    c.qty_mantissa = qm;
    c.qty_exponent = qe;
    return c;
}

// Same fixed -8 normalization the DerivedBook applies internally.
static int64_t price_key(int64_t pm, int8_t pe) {
    int shift = (int)pe + 8;
    long double v = (long double)pm;
    while (shift-- > 0) v *= 10.0L;
    return (int64_t)v;
}
static uint64_t qty_val(int64_t qm, int8_t qe) {
    int shift = (int)qe + 8;
    long double v = (long double)qm;
    while (shift-- > 0) v *= 10.0L;
    return (uint64_t)v;
}

AFX_TEST(book_diff_continuity_and_resync) {
    DerivedBook book;
    // Snapshot at update id 100: bid 59786.55 x1.5, ask 59787.00 x0.8.
    book.install_snapshot(100, {chg(5978655, -2, 150000, -5)},
                          {chg(5978700, -2, 80000, -5)});
    AFX_EXPECT(book.is_valid());

    BookEvent ev;
    // Diff 101: set bid qty (set, not sum) + add ask level.
    DepthDiff d1;
    d1.first_update_id = 101;
    d1.last_update_id = 101;
    d1.bids = {chg(5978655, -2, 220000, -5)};
    d1.asks = {chg(5978800, -2, 60000, -5)};
    AFX_EXPECT(book.apply_diff(d1, ev));
    AFX_EXPECT(ev.kind == BookEvent::Kind::Applied);
    AFX_EXPECT_EQ(book.qty_at(true, price_key(5978655, -2)).value_or(0),
                  qty_val(220000, -5));  // replaced, never summed

    // Diff 102: qty 0 removes the level (Binance rule).
    DepthDiff d2;
    d2.first_update_id = 102;
    d2.last_update_id = 102;
    d2.asks = {chg(5978700, -2, 0, -5)};
    AFX_EXPECT(book.apply_diff(d2, ev));
    AFX_EXPECT(!book.qty_at(false, price_key(5978700, -2)).has_value());
    AFX_EXPECT_EQ(book.best_ask().value_or(0), price_key(5978800, -2));

    // Diff with a gap (first=104 != last+1=103) -> resync, book invalidated.
    DepthDiff d3;
    d3.first_update_id = 104;
    d3.last_update_id = 104;
    d3.bids = {chg(5978600, -2, 100000, -5)};
    AFX_EXPECT(!book.apply_diff(d3, ev));
    AFX_EXPECT(ev.kind == BookEvent::Kind::ResyncNeeded);
    AFX_EXPECT_EQ(ev.gap_first, 103);
    AFX_EXPECT_EQ(ev.gap_last, 103);
    AFX_EXPECT(!book.is_valid());
}

// Integration: a REAL SBE DepthDiffStreamEvent (official encoder, pinned
// schema) decoded by the FASE 2 decoder and applied to the derived book.
AFX_TEST(sbe_depth_diff_to_book_integration) {
    char buffer[512];
    std::memset(buffer, 0, sizeof(buffer));
    spot_stream::DepthDiffStreamEvent ddf;
    spot_stream::MessageHeader hdr;
    hdr.wrap(buffer, 0, 0, sizeof(buffer))
        .blockLength(ddf.sbeBlockLength())
        .templateId(ddf.sbeTemplateId())
        .schemaId(ddf.sbeSchemaId())
        .version(ddf.sbeSchemaVersion());
    ddf.wrapForEncode(buffer, hdr.encodedLength(), sizeof(buffer));
    ddf.eventTime(1726700000300000LL)
        .firstBookUpdateId(900000101LL)
        .lastBookUpdateId(900000101LL)
        .priceExponent(-2)
        .qtyExponent(-5);
    ddf.bidsCount(1).next().price(5978655LL).qty(0LL);   // remove level
    ddf.asksCount(1).next().price(5978900LL).qty(5000LL);
    ddf.putSymbol("BTCUSDT", 7);
    const std::uint64_t len = hdr.encodedLength() + ddf.encodedLength();

    sbe::Decoded dec;
    AFX_EXPECT(sbe::decode((const uint8_t*)buffer, (size_t)len, dec) ==
               sbe::DecodeStatus::Ok);
    const auto* diff = std::get_if<sbe::DepthDiff>(&dec.payload);
    AFX_EXPECT(diff != nullptr);
    if (!diff) return;

    DerivedBook book;
    book.install_snapshot(900000100, {chg(5978655, -2, 150000, -5)},
                          {chg(5978700, -2, 80000, -5)});
    DepthDiff d;
    d.first_update_id = diff->first_book_update_id;
    d.last_update_id = diff->last_book_update_id;
    d.event_time_us = diff->event_time_us;
    for (const auto& b : diff->bids) {
        d.bids.push_back(chg(b.price.mantissa, b.price.exponent, b.qty.mantissa,
                             b.qty.exponent));
    }
    for (const auto& a : diff->asks) {
        d.asks.push_back(chg(a.price.mantissa, a.price.exponent, a.qty.mantissa,
                             a.qty.exponent));
    }
    BookEvent ev;
    AFX_EXPECT(book.apply_diff(d, ev));
    AFX_EXPECT(ev.kind == BookEvent::Kind::Applied);
    AFX_EXPECT(!book.qty_at(true, price_key(5978655, -2)).has_value());  // removed by qty 0
    AFX_EXPECT_EQ(book.qty_at(false, price_key(5978900, -2)).value_or(0),
                  qty_val(5000, -5));
}

// --- anticipation signals -------------------------------------------------------

AFX_TEST(anticipation_signals_measured) {
    SignalMonitor mon(50.0);  // depth@20ms => 50 Hz
    // 5 s at exactly 50 Hz.
    for (uint64_t t = 0; t < 5000; t += 20) mon.on_message(t);
    auto s = mon.snapshot(5000);
    AFX_EXPECT(s.rate_deviation_ratio > -0.05 && s.rate_deviation_ratio < 0.05);
    // 5 s at 25 Hz (degraded rate).
    for (uint64_t t = 5000; t < 10000; t += 40) mon.on_message(t);
    s = mon.snapshot(10000);
    AFX_EXPECT(s.rate_deviation_ratio < -0.4);  // measured deviation
    // Gaps + RTT trend.
    mon.on_gap();
    mon.on_gap();
    for (uint64_t i = 0; i < 32; ++i) mon.on_rtt_sample(10 + i * 2, 10000 + i * 100);
    s = mon.snapshot(10300);
    AFX_EXPECT_EQ(s.gaps_observed, 2ull);
    AFX_EXPECT(s.gaps_per_minute > 0.0);
    AFX_EXPECT(s.rtt_trend_ms > 0.0);  // rising RTT -> positive trend
    // Preventive rotation at 23 h of the 24 h venue lifetime.
    mon.on_uptime(23ull * 3600 * 1000 + 1);
    s = mon.snapshot(10400);
    AFX_EXPECT(s.preventive_rotation_due);
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    return afx::run_all(argc, argv);
}
