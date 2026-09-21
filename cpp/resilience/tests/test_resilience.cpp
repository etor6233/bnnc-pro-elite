// resilience/tests/test_resilience.cpp — PHASE 3-C suite: source duplication,
// layered failover (live -> cache -> REST backfill), provenance journal and
// authoritative reconciliation.
//
// Verification (per instruction PHASE 3-C): a test kills an entire path,
// recovers via the other path + backfill, and proves the final dataset
// contains EVERYTHING the venue emitted, with declared provenance.
#include <afx/test_framework.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include <resilience/layered_capture.hpp>

using namespace resilience;

static std::vector<uint8_t> pl(uint32_t seq) { return {(uint8_t)seq, 0xAA}; }

// Simulated venue: emits 1..25 and serves its own REST history for [from..to].
static constexpr uint32_t kVenueHigh = 25;

static std::vector<std::pair<uint32_t, std::vector<uint8_t>>> venue_rest(
    uint32_t from, uint32_t to) {
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> rows;
    for (uint32_t s = from; s <= to; ++s) rows.emplace_back(s, pl(s));
    return rows;
}

AFX_TEST(dual_path_source_duplication_no_loss) {
    // ELITE_LOSS_RECOVERY §6.1: the same datum by TWO independent paths
    // (multicast A + WS JSON). A dies at 15; B covers everything.
    std::vector<CaptureEvent> events;
    LayeredCapture cap([&](const CaptureEvent& e) { events.push_back(e); });

    for (uint32_t s = 1; s <= 25; ++s) {
        cap.on_live(0, s, pl(s));               // path A (multicast)
        cap.on_live(1, s, pl(s));               // path B (WS JSON, same datum)
        if (s == 15) {
            cap.on_path_dead(0, recovery::SilenceCause::TransportDead);
        }
    }
    auto rep = cap.reconcile(kVenueHigh);
    AFX_EXPECT(rep.complete);
    AFX_EXPECT_EQ(cap.journal().size(), (size_t)25);
    for (uint32_t s = 1; s <= 25; ++s) {
        auto it = cap.journal().find(s);
        AFX_EXPECT(it != cap.journal().end());
        if (it != cap.journal().end()) {
            AFX_EXPECT(it->second.provenance == Provenance::CapturedLive);
        }
    }
    // Dedup: 25 sequences journaled once despite 2 paths x 25 messages.
    size_t journaled = 0;
    for (const auto& e : events) {
        if (e.kind == CaptureEvent::Kind::Journaled) ++journaled;
    }
    AFX_EXPECT_EQ(journaled, (size_t)25);
}

static Provenance prov_at(const LayeredCapture& cap, uint32_t seq,
                          bool& present) {
    auto it = cap.journal().find(seq);
    present = it != cap.journal().end();
    return present ? it->second.provenance : Provenance::GapTyped;
}

AFX_TEST(kill_entire_live_path_rest_backfill_recovers_all) {
    // Only path A. Venue keeps emitting 1..25. A dies after 10. Cache is
    // empty -> REST backfill 11..24 -> new live path resumes at 25.
    std::vector<CaptureEvent> events;
    LayeredCapture cap([&](const CaptureEvent& e) { events.push_back(e); });

    for (uint32_t s = 1; s <= 10; ++s) cap.on_live(0, s, pl(s));
    cap.on_path_dead(0, recovery::SilenceCause::ExchangeSilent);

    // L3: REST backfill the lost live window [11..24].
    cap.on_backfill(venue_rest, 11, 24);

    // New live path (fresh connection) resumes at 25.
    cap.on_live(2, 25, pl(25));

    auto rep = cap.reconcile(kVenueHigh);
    AFX_EXPECT(rep.complete);
    AFX_EXPECT_EQ(cap.journal().size(), (size_t)25);
    for (uint32_t s = 1; s <= 10; ++s) {
        bool ok = false;
        AFX_EXPECT(prov_at(cap, s, ok) == Provenance::CapturedLive);
    }
    for (uint32_t s = 11; s <= 24; ++s) {
        bool ok = false;
        AFX_EXPECT(prov_at(cap, s, ok) == Provenance::Backfilled);
    }
    {
        bool ok = false;
        AFX_EXPECT(prov_at(cap, 25, ok) == Provenance::CapturedLive);
    }
    // Provenance is per-record and never silently mixed.
    bool backfilled_event = false;
    for (const auto& e : events) {
        if (e.kind == CaptureEvent::Kind::BackfillApplied &&
            e.range_first == 11 && e.range_last == 24) {
            backfilled_event = true;
            AFX_EXPECT_EQ(e.count, (size_t)14);
        }
    }
    AFX_EXPECT(backfilled_event);
}

AFX_TEST(cache_layer_serves_first_then_rest_backfill) {
    // FCP layer order (ELITE_LOSS_RECOVERY §6.2): live -> local cache ->
    // API -> REST. The cache holds 11..12 (captured live before the crash).
    std::vector<CaptureEvent> events;
    LayeredCapture cap([&](const CaptureEvent& e) { events.push_back(e); });

    for (uint32_t s = 1; s <= 10; ++s) cap.on_live(0, s, pl(s));
    cap.on_path_dead(0, recovery::SilenceCause::TransportDead);

    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> cache = {
        {11, pl(11)}, {12, pl(12)}};
    cap.on_cache_replay(cache);            // L2
    cap.on_backfill(venue_rest, 13, 24);   // L3 REST
    cap.on_live(2, 25, pl(25));            // new live path

    auto rep = cap.reconcile(kVenueHigh);
    AFX_EXPECT(rep.complete);
    // Cache-replayed entries keep captured-live provenance (they were
    // captured live); only the REST window is backfilled.
    {
        bool ok = false;
        AFX_EXPECT(prov_at(cap, 11, ok) == Provenance::CapturedLive);
        AFX_EXPECT(prov_at(cap, 12, ok) == Provenance::CapturedLive);
    }
    for (uint32_t s = 13; s <= 24; ++s) {
        bool ok = false;
        AFX_EXPECT(prov_at(cap, s, ok) == Provenance::Backfilled);
    }
}

AFX_TEST(unrecoverable_window_typed_gap_exact_range) {
    // Venue emitted 1..20. Live died at 10. The venue REST record itself is
    // missing 11 (venue-side gap): the dataset must TYPE it, never pretend.
    std::vector<CaptureEvent> events;
    LayeredCapture cap([&](const CaptureEvent& e) { events.push_back(e); });

    for (uint32_t s = 1; s <= 10; ++s) cap.on_live(0, s, pl(s));
    cap.on_path_dead(0, recovery::SilenceCause::ExchangeSilent);

    auto partial_rest = [](uint32_t from, uint32_t to) {
        std::vector<std::pair<uint32_t, std::vector<uint8_t>>> rows;
        for (uint32_t s = from; s <= to; ++s) {
            if (s == 11) continue;  // venue history gap
            rows.emplace_back(s, pl(s));
        }
        return rows;
    };
    cap.on_backfill(partial_rest, 11, 19);
    cap.on_live(2, 20, pl(20));

    bool gap_typed = false;
    for (const auto& e : events) {
        if (e.kind == CaptureEvent::Kind::GapTyped && e.seq == 11) {
            gap_typed = true;
        }
    }
    AFX_EXPECT(gap_typed);
    {
        bool ok = false;
        AFX_EXPECT(prov_at(cap, 11, ok) == Provenance::GapTyped);
    }

    auto rep = cap.reconcile(20);
    AFX_EXPECT(!rep.complete);
    AFX_EXPECT_EQ(rep.missing.size(), (size_t)1);
    if (!rep.missing.empty()) {
        AFX_EXPECT_EQ(rep.missing[0].first, 11u);
        AFX_EXPECT_EQ(rep.missing[0].second, 11u);
    }
    // Honest state: the record exists with gap provenance, so the dataset
    // shows the exact hole instead of silently skipping it.
    AFX_EXPECT_EQ(cap.journal().count(11), (size_t)1);
}

AFX_TEST(journal_hashes_bind_every_record) {
    // Every record carries a content hash; duplicated deliveries across
    // paths keep the FIRST provenance (no silent mixing).
    std::vector<CaptureEvent> events;
    LayeredCapture cap([&](const CaptureEvent& e) { events.push_back(e); });
    cap.on_live(0, 1, pl(1));
    cap.on_live(1, 1, pl(1));  // duplicate path delivery
    const auto& j = cap.journal();
    AFX_EXPECT_EQ(j.size(), (size_t)1);
    auto jit = j.find(1);
    AFX_EXPECT(jit != j.end());
    if (jit == j.end()) return;
    AFX_EXPECT_EQ(jit->second.path_id, 0u);  // first path's provenance stands
    // Hash = FNV-1a 32 over {0x01, 0xAA}.
    const uint8_t payload[] = {0x01, 0xAA};
    uint32_t h = 2166136261u;
    for (uint8_t b : payload) {
        h ^= b;
        h *= 16777619u;
    }
    AFX_EXPECT_EQ(jit->second.payload_hash, h);
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    return afx::run_all(argc, argv);
}
