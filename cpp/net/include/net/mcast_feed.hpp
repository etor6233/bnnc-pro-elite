// net/mcast_feed.hpp — low-latency multicast UDP transport with sequence
// recovery (PHASE 3).
//
// SPEC SOURCES (nothing invented):
//  - NETWORKING_DISTRIBUTED_STREAMING.md §4 (UDP): minimum UDP contract
//    "version | message_type | stream/session_id | sequence | timestamp_domain
//    | payload_length | integrity/authentication | payload" and the mandatory
//    protocol definitions list (sequence window + wraparound, gap detection +
//    recovery policy, dedup + expiry, heartbeat/liveness, replay protection,
//    per-peer limits, behavior on unknown/truncated messages).
//  - Aeron (captured reference, DESIGN ONLY — not copied): sequence-based
//    publication, NAK-based retransmission and snapshot recovery patterns.
//  - ELITE_LOSS_RECOVERY_20260918.md §1: per-message sequence, "expected N+1,
//    arrives N+k -> gap [N+1..N+k-1] detected instantly with exact range".
//
// Concrete protocol choices defined here (required by the UDP contract):
//   version u8 (1) | message_type u8 | session_id u32 | sequence u32
//   timestamp_domain u8 | timestamp_ns u64 | payload_length u16
//   integrity u32 | payload
//   - all multi-byte integers in network byte order (big-endian);
//   - sequence is u32 with wraparound compared inside a 2^31 window;
//   - gap detection: expected N+1, received N+k -> typed gap [N+1..N+k-1];
//   - recovery policy: NAK (retransmission request) to the repair endpoint +
//     snapshot bridging for unrecoverable gaps;
//   - dedup by (session, sequence) with expiry = one wraparound window;
//   - bounded reorder window (64 slots); overflow of the reorder window is a
//     typed gap, never silent loss;
//   - integrity: FNV-1a 32 over the payload (0 = no integrity);
//   - unknown message_type / truncated datagrams are counted and dropped
//     without state corruption.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

// Portable socket handle: Winsock2 on Windows, POSIX sockets elsewhere.
// (Portability needed for the Linux CI leg of PHASE 6.)
#ifdef _WIN32
#include <winsock2.h>
namespace net {
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
}  // namespace net
#else
#include <sys/types.h>
namespace net {
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
}  // namespace net
#endif

namespace net {

// ---------------------------------------------------------------------------
// Framing (UDP contract of NETWORKING_DISTRIBUTED_STREAMING.md §4)
// ---------------------------------------------------------------------------

constexpr uint8_t FRAME_VERSION = 1;
constexpr size_t FRAME_HEADER_LEN = 25;  // fixed header length in bytes

enum class MsgType : uint8_t {
    MarketPayload = 1,
    RetransmitRequest = 2,  // NAK: gap ranges
    SnapshotRequest = 3,
    Snapshot = 4,
    Heartbeat = 5,
};

enum class TsDomain : uint8_t {
    Unspecified = 0,
    VenueEventTime = 1,
    HostMonotonic = 2,
};

struct FeedMessage {
    uint8_t version = FRAME_VERSION;
    MsgType type = MsgType::MarketPayload;
    uint32_t session_id = 0;
    uint32_t sequence = 0;
    TsDomain timestamp_domain = TsDomain::Unspecified;
    uint64_t timestamp_ns = 0;
    std::vector<uint8_t> payload;
};

// Parse one frame. Returns false (and out untouched) for truncated frames.
// Unknown message types still parse structurally; the caller decides policy.
bool parse_frame(const uint8_t* data, size_t len, FeedMessage& out);

// Encode one frame into `out`. Integrity is computed automatically (FNV-1a 32
// over the payload; 0 when payload is empty).
void encode_frame(const FeedMessage& in, std::vector<uint8_t>& out);

// ---------------------------------------------------------------------------
// Transport primitives (Winsock2). IPv4 multicast, loopback-safe for tests.
// ---------------------------------------------------------------------------

struct McastConfig {
    std::string group;      // e.g. 239.255.42.99
    uint16_t port = 0;
    int ttl = 1;            // IP_MULTICAST_TTL
    bool loopback = true;   // IP_MULTICAST_LOOP (needed for local tests)
};

class MulticastReceiver {
  public:
    MulticastReceiver();
    ~MulticastReceiver();
    MulticastReceiver(const MulticastReceiver&) = delete;
    MulticastReceiver& operator=(const MulticastReceiver&) = delete;

    // Join the group (IGMP/IP_ADD_MEMBERSHIP) and bind any:port.
    bool join(const McastConfig& cfg, std::string& err);
    // Leave the group and close the socket (idempotent).
    void leave();

    // Receive one datagram with a bounded wait. Returns true when a datagram
    // arrived (msg points at it), false on timeout/closed. Never throws.
    bool receive(std::vector<uint8_t>& msg, int timeout_ms);

    bool is_open() const { return socket_ != kInvalidSocket; }

  private:
    NativeSocket socket_ = kInvalidSocket;
    McastConfig cfg_;
};

class MulticastSender {
  public:
    MulticastSender();
    ~MulticastSender();
    MulticastSender(const MulticastSender&) = delete;
    MulticastSender& operator=(const MulticastSender&) = delete;

    bool open(const McastConfig& cfg, std::string& err);
    void close();
    // Send one datagram to the configured multicast group:port.
    bool send(const uint8_t* data, size_t len);
    // Send one datagram to an explicit unicast/multicast destination
    // (used for NAK repair requests to the publisher).
    bool send_to(const uint8_t* data, size_t len, const std::string& addr,
                 uint16_t port);
    bool is_open() const { return socket_ != kInvalidSocket; }

  private:
    NativeSocket socket_ = kInvalidSocket;
    McastConfig cfg_;
};

// Portable unicast UDP socket (used by the NAK repair listener and the
// transport tests on both Windows and Linux).
class UnicastSocket {
  public:
    UnicastSocket();
    ~UnicastSocket();
    UnicastSocket(const UnicastSocket&) = delete;
    UnicastSocket& operator=(const UnicastSocket&) = delete;

    // Bind to addr:port for receiving (addr may be "127.0.0.1" or "0.0.0.0").
    bool bind(const std::string& addr, uint16_t port, std::string& err);
    // Receive one datagram with a bounded wait (ms).
    bool recv(std::vector<uint8_t>& msg, int timeout_ms);
    // Send a datagram to addr:port.
    bool send_to(const uint8_t* data, size_t len, const std::string& addr,
                 uint16_t port);
    void close();
    bool is_open() const { return socket_ != kInvalidSocket; }

  private:
    NativeSocket socket_ = kInvalidSocket;
};

// ---------------------------------------------------------------------------
// Sequenced feed assembler: gap detection, dedup, bounded reordering,
// retransmission requests and snapshot bridging (sequence reconciliation).
// ---------------------------------------------------------------------------

struct GapEvent {
    uint32_t first;   // inclusive
    uint32_t last;    // inclusive
};

struct DeliverEvent {
    FeedMessage message;   // complete, in-order
    bool recovered = false;  // arrived via retransmission/snapshot bridge
};

struct FeedEvent {
    enum class Kind : uint8_t {
        Delivered,          // in-order message ready for the consumer
        GapDetected,        // typed gap with exact range [first..last]
        DuplicateIgnored,   // already seen (session, sequence)
        Reordered,          // buffered then delivered in order later
        UnknownTypeDropped, // counted, no state corruption
        TruncatedDropped,   // counted, no state corruption
        SnapshotBridged,    // state re-seeded from snapshot at `sequence`
    } kind = Kind::Delivered;
    DeliverEvent deliver;
    GapEvent gap;
    uint64_t dropped_count = 0;
    uint32_t snapshot_sequence = 0;
};

// Retransmission callback: the assembler calls it with the session id and a
// list of gap ranges (ascending, disjoint) so the caller can emit NAKs to the
// repair endpoint (MoldUDP64 downstream-retransmission pattern, documented in
// ELITE_LOSS_RECOVERY_20260918.md §2).
using NakCallback = std::function<void(uint32_t session_id,
                                       const std::vector<GapEvent>& gaps)>;

class SequencedFeed {
  public:
    // max_reorder_window: bounded out-of-order buffering (default 64). The
    // window overflow is a typed gap — never silent loss.
    explicit SequencedFeed(size_t max_reorder_window = 64,
                           NakCallback nak = nullptr);

    // Feed one parsed frame. Appends any resulting events to `out`.
    void on_frame(const FeedMessage& m, std::vector<FeedEvent>& out);

    // Re-seed state from a snapshot covering everything up to
    // `snapshot_sequence` (inclusive). Messages below/equal that sequence are
    // no longer expected. Emits a SnapshotBridged event with the sequence.
    void apply_snapshot(uint32_t snapshot_sequence, std::vector<FeedEvent>& out);

    // Expectation cursor (next in-order sequence to deliver).
    uint32_t expected() const { return expected_; }
    bool has_seen_first() const { return seen_first_; }

  private:
    bool deliver(uint32_t seq, FeedMessage msg, bool recovered,
                 std::vector<FeedEvent>& out);
    bool insert_reorder(uint32_t seq, FeedMessage msg,
                        std::vector<FeedEvent>& out);
    void declare_gap(uint32_t session, uint32_t first, uint32_t last,
                     std::vector<FeedEvent>& out);

    size_t max_reorder_;
    NakCallback nak_;
    std::map<uint32_t, FeedMessage> reorder_;  // seq -> message
    std::set<uint32_t> pending_gaps_;          // declared-but-recoverable seqs
    uint32_t expected_ = 0;
    bool seen_first_ = false;
    uint32_t last_delivered_ = 0;
    uint64_t unknown_dropped_ = 0;
    uint64_t truncated_dropped_ = 0;
};

}  // namespace net
