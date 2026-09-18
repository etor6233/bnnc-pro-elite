// resilience/layered_capture.hpp — layered anti-loss capture architecture
// (FASE 3-C). Implements ELITE_LOSS_RECOVERY_20260918.md §6:
//   1. source duplication: dual multicast A/B + WS JSON as independent paths;
//   2. layered failover (FCP): live feed -> local cache -> venue API -> REST;
//   3. gap reconciliation against the authoritative source after recovery;
//   4. backfill from the venue's historical record (Binance REST
//      aggTrades/depth) for windows lost live;
//   5. provenance chain: every recovered datum enters the journal tagged
//      `captured-live` | `backfilled` + hash — never a silent mix.
//
// The REST fetch is injectable (BackfillFn); the production binding is
// Binance Spot REST (pinned in BINANCE_SOURCE_LOCK.md rest-api.md:
// GET /api/v3/aggTrades, GET /api/v3/depth).
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <recovery/feed_guard.hpp>

namespace resilience {

// Provenance tags (ELITE_LOSS_RECOVERY §6.5): never a silent mix.
enum class Provenance : uint8_t {
    CapturedLive = 0,
    Backfilled = 1,
    GapTyped = 2,  // venue emitted it but no path ever carried it here
};

const char* to_string(Provenance p);

// One journal record: sequence + provenance + content hash. The hash binds
// the record to its bytes (same FNV-1a 32 the net framing uses).
struct JournalEntry {
    uint32_t sequence = 0;
    Provenance provenance = Provenance::CapturedLive;
    uint32_t payload_hash = 0;
    uint32_t path_id = 0;  // which path delivered it (0 when backfilled)
};

// Events emitted by the engine (sink callback).
struct CaptureEvent {
    enum class Kind : uint8_t {
        Journaled,          // one entry appended
        Failover,           // a path died -> failover started
        CacheReplay,        // local cache layer served entries
        BackfillApplied,    // REST layer filled a range
        GapTyped,           // a range exists nowhere recoverable
        Reconciled,         // reconciliation finished
    } kind = Kind::Journaled;
    uint32_t path_id = 0;
    uint32_t seq = 0;
    Provenance provenance = Provenance::CapturedLive;
    uint32_t range_first = 0, range_last = 0;
    size_t count = 0;
    bool complete = false;
    std::vector<std::pair<uint32_t, uint32_t>> missing;  // Reconciled only
};

struct ReconcileReport {
    bool complete = false;
    std::vector<std::pair<uint32_t, uint32_t>> missing;  // [first,last] each
};

// Fetches the venue's historical record for [from..to] (inclusive). The
// production binding is Binance REST (aggTrades for trades, depth for book).
using BackfillFn =
    std::function<std::vector<std::pair<uint32_t, std::vector<uint8_t>>>(
        uint32_t from, uint32_t to)>;

class LayeredCapture {
  public:
    explicit LayeredCapture(std::function<void(const CaptureEvent&)> sink);

    // L1: a live message from an independent path (multicast A, B, or WS).
    void on_live(uint32_t path_id, uint32_t seq,
                 const std::vector<uint8_t>& payload);

    // L2: local-cache replay entries (durably cached live captures).
    void on_cache_replay(
        const std::vector<std::pair<uint32_t, std::vector<uint8_t>>>& entries);

    // L3: REST backfill for a lost live window.
    void on_backfill(const BackfillFn& fetch, uint32_t from, uint32_t to);

    // A whole path died (transport/venue) with its typed cause.
    void on_path_dead(uint32_t path_id, recovery::SilenceCause cause);

    // Reconcile against the authoritative venue: everything the venue
    // emitted up to `venue_high_seq` must be present with declared
    // provenance; anything missing is typed.
    ReconcileReport reconcile(uint32_t venue_high_seq);

    const std::map<uint32_t, JournalEntry>& journal() const { return journal_; }
    uint32_t next_expected() const { return next_expected_; }

  private:
    void journal(uint32_t seq, Provenance p, uint32_t path,
                 const std::vector<uint8_t>& payload);

    std::function<void(const CaptureEvent&)> sink_;
    std::map<uint32_t, JournalEntry> journal_;  // by venue sequence
    uint32_t next_expected_ = 1;
    std::vector<uint32_t> dead_paths_;
};

}  // namespace resilience
