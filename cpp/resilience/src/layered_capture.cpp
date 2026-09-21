// resilience/layered_capture.cpp — layered anti-loss engine (PHASE 3-C).
//
// Implements ELITE_LOSS_RECOVERY_20260918.md §6 with honest provenance: every
// journal record carries captured-live | backfilled | gap-typed plus a
// content hash; duplicates across redundant paths are deduplicated while the
// first path's provenance is preserved (no silent mixing).
#include <resilience/layered_capture.hpp>

#include <algorithm>

namespace resilience {

namespace {
inline uint32_t fnv1a32(const uint8_t* p, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}
}  // namespace

const char* to_string(Provenance p) {
    switch (p) {
        case Provenance::CapturedLive: return "captured-live";
        case Provenance::Backfilled: return "backfilled";
        case Provenance::GapTyped: return "gap-typed";
    }
    return "?";
}

LayeredCapture::LayeredCapture(std::function<void(const CaptureEvent&)> sink)
    : sink_(std::move(sink)) {}

void LayeredCapture::journal(uint32_t seq, Provenance p, uint32_t path,
                             const std::vector<uint8_t>& payload) {
    if (journal_.count(seq) != 0) {
        return;  // dedup across redundant paths; first provenance stands
    }
    JournalEntry e;
    e.sequence = seq;
    e.provenance = p;
    e.payload_hash = fnv1a32(payload.data(), payload.size());
    e.path_id = path;
    journal_[seq] = e;
    if (seq == next_expected_) {
        ++next_expected_;
        while (journal_.count(next_expected_) != 0) ++next_expected_;
    }
    CaptureEvent ev;
    ev.kind = CaptureEvent::Kind::Journaled;
    ev.path_id = path;
    ev.seq = seq;
    ev.provenance = p;
    if (sink_) sink_(ev);
}

void LayeredCapture::on_live(uint32_t path_id, uint32_t seq,
                             const std::vector<uint8_t>& payload) {
    journal(seq, Provenance::CapturedLive, path_id, payload);
}

void LayeredCapture::on_cache_replay(
    const std::vector<std::pair<uint32_t, std::vector<uint8_t>>>& entries) {
    // L2: the local cache carries content that WAS captured live; provenance
    // stays captured-live (it is not a venue backfill).
    size_t n = 0;
    for (const auto& [seq, payload] : entries) {
        if (journal_.count(seq) != 0) continue;
        journal(seq, Provenance::CapturedLive, 0xFF /* cache layer */, payload);
        ++n;
    }
    if (n > 0) {
        CaptureEvent ev;
        ev.kind = CaptureEvent::Kind::CacheReplay;
        ev.count = n;
        if (sink_) sink_(ev);
    }
}

void LayeredCapture::on_backfill(const BackfillFn& fetch, uint32_t from,
                                 uint32_t to) {
    // L3: venue REST record for the lost live window. Everything the venue
    // returned is journaled backfilled; anything the venue could not return
    // is typed as a gap (never silent).
    const auto rows = fetch ? fetch(from, to)
                            : std::vector<std::pair<uint32_t, std::vector<uint8_t>>>{};
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> by_seq = rows;
    std::sort(by_seq.begin(), by_seq.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    std::map<uint32_t, bool> got;
    for (const auto& [seq, payload] : by_seq) {
        if (seq < from || seq > to) continue;  // out of the requested window
        got[seq] = true;
        journal(seq, Provenance::Backfilled, 0, payload);
    }
    size_t backfilled = 0;
    for (uint32_t s = from; s <= to && s != 0xFFFFFFFFu; ++s) {
        if (got.count(s) != 0) {
            ++backfilled;
            continue;
        }
        // Typed gap: the venue emitted it (reconcile() knows) but no path
        // ever carried it to this host.
        if (journal_.count(s) == 0) {
            JournalEntry e;
            e.sequence = s;
            e.provenance = Provenance::GapTyped;
            e.payload_hash = 0;
            journal_[s] = e;
            CaptureEvent ev;
            ev.kind = CaptureEvent::Kind::GapTyped;
            ev.seq = s;
            ev.provenance = Provenance::GapTyped;
            if (sink_) sink_(ev);
        }
    }
    CaptureEvent ev;
    ev.kind = CaptureEvent::Kind::BackfillApplied;
    ev.range_first = from;
    ev.range_last = to;
    ev.count = backfilled;
    if (sink_) sink_(ev);
}

void LayeredCapture::on_path_dead(uint32_t path_id,
                                  recovery::SilenceCause cause) {
    // The typed cause is produced by the PHASE 3-B recovery::CadenceGuard /
    // watchdog layer that surrounds this engine; here it only marks the
    // failover event for the journal's evidence chain.
    CaptureEvent ev;
    ev.kind = CaptureEvent::Kind::Failover;
    ev.path_id = path_id;
    dead_paths_.push_back(path_id);
    (void)cause;
    if (sink_) sink_(ev);
}

ReconcileReport LayeredCapture::reconcile(uint32_t venue_high_seq) {
    // Authoritative reconciliation: the venue emitted 1..venue_high_seq.
    // Complete means every sequence is present as recoverable content
    // (captured-live or backfilled). Gap-typed records are NOT content: they
    // make the reconciliation incomplete with the exact missing ranges.
    ReconcileReport rep;
    rep.complete = true;
    for (uint32_t s = 1; s <= venue_high_seq && s != 0; ++s) {
        auto it = journal_.find(s);
        if (it == journal_.end() ||
            it->second.provenance == Provenance::GapTyped) {
            rep.complete = false;
            if (!rep.missing.empty() && rep.missing.back().second == s - 1) {
                rep.missing.back().second = s;
            } else {
                rep.missing.emplace_back(s, s);
            }
        }
    }
    CaptureEvent ev;
    ev.kind = CaptureEvent::Kind::Reconciled;
    ev.complete = rep.complete;
    ev.missing = rep.missing;
    if (sink_) sink_(ev);
    return rep;
}

}  // namespace resilience
