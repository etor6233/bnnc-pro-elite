// net/tests/test_mcast.cpp — PHASE 3 suite: framing, sequence recovery,
// real multicast join/leave/loss/retransmission, SPSC ring.
#include <afx/test_framework.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <net/mcast_feed.hpp>
#include <net/spsc_ring.hpp>

using namespace net;

static const std::string kGroup = "239.255.42.99";
// Ports chosen OUTSIDE the Windows excluded UDP ranges observed on this host
// (netsh int ipv4 show excludedportrange: 54507-54606 etc. -> WSAEACCES).
static const uint16_t kPortJoinLeave = 45678;
static const uint16_t kPortE2e = 45679;
static const uint16_t kPortRepair = 45680;

static FeedMessage mk(uint32_t seq, uint32_t session = 7,
                      std::vector<uint8_t> payload = {}) {
    FeedMessage m;
    m.type = MsgType::MarketPayload;
    m.session_id = session;
    m.sequence = seq;
    m.timestamp_domain = TsDomain::HostMonotonic;
    m.timestamp_ns = (uint64_t)seq * 1000;
    m.payload = std::move(payload);
    return m;
}

// --- framing ---------------------------------------------------------------

AFX_TEST(frame_roundtrip_and_integrity) {
    FeedMessage in = mk(42);
    in.payload = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> wire;
    encode_frame(in, wire);
    if (wire.size() != FRAME_HEADER_LEN + 4) {
        AFX_EXPECT_EQ(wire.size(), FRAME_HEADER_LEN + 4);
        return;  // nothing sensible to test on an undersized frame
    }

    FeedMessage out;
    AFX_EXPECT(parse_frame(wire.data(), wire.size(), out));
    AFX_EXPECT_EQ(out.version, (uint8_t)1);
    AFX_EXPECT_EQ(out.sequence, 42u);
    AFX_EXPECT_EQ(out.session_id, 7u);
    AFX_EXPECT(out.payload == in.payload);
    AFX_EXPECT_EQ(out.timestamp_ns, 42000ull);

    // Tampered payload must fail integrity (FNV-1a 32).
    std::vector<uint8_t> bad = wire;
    bad[FRAME_HEADER_LEN] ^= 0xFF;
    AFX_EXPECT(!parse_frame(bad.data(), bad.size(), out));

    // Truncations must fail without reading past the buffer.
    AFX_EXPECT(!parse_frame(wire.data(), 10, out));
    AFX_EXPECT(!parse_frame(wire.data(), FRAME_HEADER_LEN - 1, out));
    AFX_EXPECT(!parse_frame(nullptr, 10, out));

    // Unknown version is rejected.
    bad = wire;
    bad[0] = 99;
    AFX_EXPECT(!parse_frame(bad.data(), bad.size(), out));
}

// --- sequence assembler ------------------------------------------------------

AFX_TEST(assembler_in_order_delivery) {
    SequencedFeed f;
    std::vector<FeedEvent> ev;
    for (uint32_t s = 1; s <= 10; ++s) f.on_frame(mk(s), ev);
    int delivered = 0;
    for (const auto& e : ev) {
        if (e.kind == FeedEvent::Kind::Delivered) {
            AFX_EXPECT_EQ(e.deliver.message.sequence, (uint32_t)(++delivered));
        }
    }
    AFX_EXPECT_EQ(delivered, 10);
}

AFX_TEST(assembler_gap_detection_exact_range) {
    std::vector<GapEvent> naks;
    SequencedFeed f(64, [&](uint32_t session, const std::vector<GapEvent>& g) {
        AFX_EXPECT_EQ(session, 7u);
        naks.insert(naks.end(), g.begin(), g.end());
    });
    std::vector<FeedEvent> ev;
    f.on_frame(mk(1), ev);
    f.on_frame(mk(2), ev);
    f.on_frame(mk(6), ev);  // expected 3 -> gap [3..5]
    AFX_EXPECT_EQ(naks.size(), (size_t)1);
    if (!naks.empty()) {
        AFX_EXPECT_EQ(naks[0].first, 3u);
        AFX_EXPECT_EQ(naks[0].last, 5u);
    }
    bool gap_seen = false;
    for (const auto& e : ev) {
        if (e.kind == FeedEvent::Kind::GapDetected) {
            gap_seen = true;
            AFX_EXPECT_EQ(e.gap.first, 3u);
            AFX_EXPECT_EQ(e.gap.last, 5u);
        }
    }
    AFX_EXPECT(gap_seen);
}

AFX_TEST(assembler_retransmission_recovery) {
    SequencedFeed f;
    std::vector<FeedEvent> ev;
    f.on_frame(mk(1), ev);
    f.on_frame(mk(2), ev);
    f.on_frame(mk(4), ev);  // gap [3..3] declared instantly, 4 delivered
    f.on_frame(mk(3), ev);  // retransmission of 3: delivered as recovered
    f.on_frame(mk(5), ev);
    // Instant gap policy (ELITE_LOSS_RECOVERY §1): delivery order is
    // 1,2,4,3(recovered),5 — never silent loss, every byte accounted.
    std::vector<uint32_t> order;
    uint32_t recovered_count = 0;
    uint32_t recovered_seq = 0;
    for (const auto& e : ev) {
        if (e.kind == FeedEvent::Kind::Delivered) {
            order.push_back(e.deliver.message.sequence);
            if (e.deliver.recovered) {
                ++recovered_count;
                recovered_seq = e.deliver.message.sequence;
            }
        }
    }
    AFX_EXPECT_EQ(order.size(), (size_t)5);
    const uint32_t want[] = {1, 2, 4, 3, 5};
    for (size_t i = 0; i < order.size(); ++i) AFX_EXPECT_EQ(order[i], want[i]);
    AFX_EXPECT_EQ(recovered_count, 1u);
    AFX_EXPECT_EQ(recovered_seq, 3u);
}

AFX_TEST(assembler_duplicate_dropped) {
    SequencedFeed f;
    std::vector<FeedEvent> ev;
    f.on_frame(mk(1), ev);
    f.on_frame(mk(2), ev);
    f.on_frame(mk(2), ev);  // duplicate
    int dup = 0;
    for (const auto& e : ev) {
        if (e.kind == FeedEvent::Kind::DuplicateIgnored) ++dup;
    }
    AFX_EXPECT_EQ(dup, 1);
}

AFX_TEST(assembler_reorder_gap_then_recovery) {
    SequencedFeed f;
    std::vector<FeedEvent> ev;
    f.on_frame(mk(1), ev);
    f.on_frame(mk(2), ev);
    f.on_frame(mk(4), ev);  // instant gap [3..3] + deliver 4
    f.on_frame(mk(3), ev);  // late arrival inside the declared gap
    std::vector<uint32_t> order;
    uint32_t recovered_seq = 0;
    for (const auto& e : ev) {
        if (e.kind == FeedEvent::Kind::Delivered) {
            order.push_back(e.deliver.message.sequence);
            if (e.deliver.recovered) recovered_seq = e.deliver.message.sequence;
        }
    }
    AFX_EXPECT_EQ(order.size(), (size_t)4);
    const uint32_t want[] = {1, 2, 4, 3};
    for (size_t i = 0; i < order.size(); ++i) AFX_EXPECT_EQ(order[i], want[i]);
    AFX_EXPECT_EQ(recovered_seq, 3u);
}

AFX_TEST(assembler_snapshot_bridging) {
    SequencedFeed f;
    std::vector<FeedEvent> ev;
    f.on_frame(mk(1), ev);
    f.on_frame(mk(2), ev);
    f.on_frame(mk(5), ev);  // gap 3..4
    f.apply_snapshot(9, ev);  // snapshot covers up to 9
    f.on_frame(mk(10), ev);
    f.on_frame(mk(3), ev);  // now behind the snapshot: duplicate
    bool bridged = false;
    int dup = 0;
    uint32_t last_delivered = 0;
    for (const auto& e : ev) {
        if (e.kind == FeedEvent::Kind::SnapshotBridged) {
            bridged = true;
            AFX_EXPECT_EQ(e.snapshot_sequence, 9u);
        }
        if (e.kind == FeedEvent::Kind::DuplicateIgnored) ++dup;
        if (e.kind == FeedEvent::Kind::Delivered) {
            last_delivered = e.deliver.message.sequence;
        }
    }
    AFX_EXPECT(bridged);
    AFX_EXPECT_EQ(dup, 1);
    AFX_EXPECT_EQ(last_delivered, 10u);
    AFX_EXPECT_EQ(f.expected(), 11u);
}

AFX_TEST(assembler_sequence_wraparound) {
    SequencedFeed f;
    std::vector<FeedEvent> ev;
    f.on_frame(mk(0xFFFFFFFEu), ev);
    f.on_frame(mk(0xFFFFFFFFu), ev);
    f.on_frame(mk(0u), ev);  // wraps to 0
    f.on_frame(mk(1u), ev);
    std::vector<uint32_t> order;
    for (const auto& e : ev) {
        if (e.kind == FeedEvent::Kind::Delivered) {
            order.push_back(e.deliver.message.sequence);
        }
    }
    if (order.size() != 4) {
        AFX_EXPECT_EQ(order.size(), (size_t)4);
        return;
    }
    AFX_EXPECT_EQ(order[0], 0xFFFFFFFEu);
    AFX_EXPECT_EQ(order[1], 0xFFFFFFFFu);
    AFX_EXPECT_EQ(order[2], 0u);
    AFX_EXPECT_EQ(order[3], 1u);
}

// --- real multicast transport -----------------------------------------------

AFX_TEST(multicast_join_leave_receive) {
    McastConfig cfg;
    cfg.group = kGroup;
    cfg.port = kPortJoinLeave;
    cfg.ttl = 1;
    cfg.loopback = true;

    MulticastReceiver rx;
    std::string err;
    AFX_EXPECT(rx.join(cfg, err));
    if (!rx.is_open()) {
        AFX_EXPECT_STREQ(err, std::string("joined"));
        return;
    }

    MulticastSender tx;
    AFX_EXPECT(tx.open(cfg, err));

    std::vector<uint8_t> wire;
    encode_frame(mk(1, 99, {0x01}), wire);
    AFX_EXPECT(tx.send(wire.data(), wire.size()));
    encode_frame(mk(2, 99, {0x02}), wire);
    AFX_EXPECT(tx.send(wire.data(), wire.size()));

    int received = 0;
    for (int i = 0; i < 50; ++i) {
        std::vector<uint8_t> datagram;
        if (rx.receive(datagram, 100)) ++received;
        if (received >= 2) break;
    }
    AFX_EXPECT_EQ(received, 2);

    // Leave: no more datagrams must be received.
    rx.leave();
    encode_frame(mk(3, 99, {0x03}), wire);
    AFX_EXPECT(tx.send(wire.data(), wire.size()));
    bool extra = false;
    for (int i = 0; i < 5; ++i) {
        std::vector<uint8_t> datagram;
        if (rx.receive(datagram, 50)) extra = true;
    }
    AFX_EXPECT(!extra);
    tx.close();
}

// End-to-end: publisher drops one datagram on purpose, receiver detects the
// gap instantly, NAKs the repair endpoint, publisher retransmits, receiver
// reconciles the full sequence (PHASE 3 verification).
AFX_TEST(multicast_loss_retransmission_e2e) {
    McastConfig cfg;
    cfg.group = kGroup;
    cfg.port = kPortE2e;
    cfg.ttl = 1;
    cfg.loopback = true;

    MulticastReceiver rx;
    std::string err;
    AFX_EXPECT(rx.join(cfg, err));
    if (!rx.is_open()) {
        AFX_EXPECT_STREQ(err, std::string("joined"));
        return;
    }
    MulticastSender tx;
    AFX_EXPECT(tx.open(cfg, err));

    // Publisher retransmission cache: last 64 datagrams per session, keyed
    // by sequence (lookup by sequence, not by index).
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> cache;
    auto publish = [&](uint32_t seq) {
        std::vector<uint8_t> wire;
        encode_frame(mk(seq, 42, {(uint8_t)seq}), wire);
        cache.emplace_back(seq, wire);
        if (cache.size() > 64) cache.erase(cache.begin());
        return tx.send(wire.data(), wire.size());
    };

    // Receiver thread: feed frames into the assembler, NAK on gap.
    std::atomic<bool> done{false};
    std::mutex mutex;
    std::vector<std::pair<uint32_t, bool>> delivered;  // (seq, recovered)
    int gap_count = 0;

    std::thread receiver([&]() {
        SequencedFeed feed(64, [&](uint32_t, const std::vector<GapEvent>& gaps) {
            for (const auto& g : gaps) {
                // NAK to the repair endpoint (unicast loopback).
                std::vector<uint8_t> nak;
                encode_frame(
                    FeedMessage{FRAME_VERSION, MsgType::RetransmitRequest, 42,
                                g.first, TsDomain::Unspecified, 0,
                                {(uint8_t)g.first, (uint8_t)g.last}},
                    nak);
                tx.send_to(nak.data(), nak.size(), "127.0.0.1", kPortRepair);
            }
        });
        while (!done.load()) {
            std::vector<uint8_t> datagram;
            if (!rx.receive(datagram, 50)) continue;
            FeedMessage m;
            if (!parse_frame(datagram.data(), datagram.size(), m)) continue;
            std::vector<FeedEvent> ev;
            feed.on_frame(m, ev);
            for (const auto& e : ev) {
                if (e.kind == FeedEvent::Kind::GapDetected) {
                    std::lock_guard<std::mutex> lk(mutex);
                    ++gap_count;
                } else if (e.kind == FeedEvent::Kind::Delivered) {
                    std::lock_guard<std::mutex> lk(mutex);
                    delivered.emplace_back(e.deliver.message.sequence,
                                           e.deliver.recovered);
                }
            }
        }
    });

    // Repair listener on 127.0.0.1:kPortRepair (unicast UDP, portable).
    net::UnicastSocket repair;
    {
        std::string berr;
        AFX_EXPECT(repair.bind("127.0.0.1", kPortRepair, berr));
    }

    // Publish 1..10, deliberately dropping 5 on the wire: the publisher
    // keeps the dropped datagram in its retransmission store (MoldUDP64
    // downstream-retransmission pattern) but never sends it.
    for (uint32_t s = 1; s <= 10; ++s) {
        if (s == 5) {
            std::vector<uint8_t> wire;
            encode_frame(mk(s, 42, {(uint8_t)s}), wire);
            cache.emplace_back(s, wire);  // store only, not sent
            continue;
        }
        AFX_EXPECT(publish(s));
    }

    // Wait for the NAK and retransmit the missing datagrams from the cache.
    bool retransmitted = false;
    for (int i = 0; i < 100 && !retransmitted; ++i) {
        std::vector<uint8_t> nak_bytes;
        if (repair.recv(nak_bytes, 20)) {
            FeedMessage nak;
            if (parse_frame(nak_bytes.data(), nak_bytes.size(), nak) &&
                nak.type == MsgType::RetransmitRequest) {
                const uint32_t first = nak.payload.empty() ? 0 : nak.payload[0];
                const uint32_t last =
                    nak.payload.size() > 1 ? nak.payload[1] : first;
                for (const auto& [seq, wire] : cache) {
                    if (seq >= first && seq <= last) {
                        tx.send(wire.data(), wire.size());
                    }
                }
                retransmitted = true;
            }
        }
    }
    AFX_EXPECT(retransmitted);

    // Allow the retransmission to land, then stop.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    done.store(true);
    receiver.join();
    repair.close();
    tx.close();
    rx.leave();

    {
        std::lock_guard<std::mutex> lk(mutex);
        AFX_EXPECT_EQ(gap_count, 1);
        // Full reconciliation: every sequence 1..10 delivered exactly once,
        // with seq 5 flagged recovered.
        AFX_EXPECT_EQ(delivered.size(), (size_t)10);
        std::vector<uint32_t> seqs;
        bool five_recovered = false;
        for (const auto& [seq, recovered] : delivered) {
            seqs.push_back(seq);
            if (seq == 5) five_recovered = recovered;
        }
        std::sort(seqs.begin(), seqs.end());
        for (size_t i = 0; i < seqs.size(); ++i) {
            AFX_EXPECT_EQ(seqs[i], (uint32_t)(i + 1));
        }
        AFX_EXPECT(five_recovered);
    }
}

// --- SPSC ring ---------------------------------------------------------------

AFX_TEST(spsc_ring_basic_and_overflow_explicit) {
    SpscRing<int> ring(8);  // capacity 8 (16 slots rounded, 15 usable)
    AFX_EXPECT_EQ(ring.capacity(), (size_t)15);
    int v = 0;
    AFX_EXPECT(!ring.try_pop(v));  // empty
    for (int i = 0; i < 15; ++i) AFX_EXPECT(ring.try_push(i));
    AFX_EXPECT(!ring.try_push(999));  // full: explicit, not silent
    for (int i = 0; i < 15; ++i) {
        AFX_EXPECT(ring.try_pop(v));
        AFX_EXPECT_EQ(v, i);
    }
    AFX_EXPECT(ring.empty());
}

AFX_TEST(spsc_ring_concurrent_producer_consumer) {
    SpscRing<uint64_t> ring(1024);
    const uint64_t N = 200'000;
    std::atomic<bool> start{false};
    std::thread producer([&]() {
        while (!start.load()) std::this_thread::yield();
        uint64_t i = 0;
        while (i < N) {
            if (ring.try_push(i)) ++i;
        }
    });
    std::thread consumer([&]() {
        while (!start.load()) std::this_thread::yield();
        uint64_t i = 0;
        while (i < N) {
            uint64_t v;
            if (ring.try_pop(v)) {
                AFX_EXPECT_EQ(v, i);
                ++i;
            }
        }
    });
    start.store(true);
    producer.join();
    consumer.join();
}

int main(int argc, char** argv) {
    // Unbuffered stdout: crash diagnostics keep the last test visible.
    setvbuf(stdout, nullptr, _IONBF, 0);
    return afx::run_all(argc, argv);
}
