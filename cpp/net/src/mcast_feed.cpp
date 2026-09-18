// net/mcast_feed.cpp — multicast UDP transport + sequenced feed assembler.
//
// Sources: NETWORKING_DISTRIBUTED_STREAMING.md §4 (UDP contract),
// ELITE_LOSS_RECOVERY_20260918.md §1-§3 (instant gap detection, NAK
// retransmission, snapshot bridging), Aeron reference (design patterns only).
#include <net/mcast_feed.hpp>

#include <cstring>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace net {

namespace {

#ifdef _WIN32
// Winsock startup, process-wide.
struct WinsockInit {
    WinsockInit() {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
    }
    ~WinsockInit() { WSACleanup(); }
};
static WinsockInit g_winsock;

inline int close_socket(NativeSocket s) { return ::closesocket(s); }
inline std::string last_err() { return std::to_string(WSAGetLastError()); }
inline int wait_readable(NativeSocket s, int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    return ::select(0, &fds, nullptr, nullptr, &tv);
}
#else
inline int close_socket(NativeSocket s) { return ::close(s); }
inline std::string last_err() { return std::strerror(errno); }
inline int wait_readable(NativeSocket s, int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    return ::select(s + 1, &fds, nullptr, nullptr, &tv);
}
#endif

inline uint32_t addr_ipv4(const std::string& addr) {
#ifdef _WIN32
    return (uint32_t)::inet_addr(addr.c_str());
#else
    return (uint32_t)::inet_addr(addr.c_str());
#endif
}

// Sequence comparison inside a 2^31 window (wraparound-safe per the UDP
// contract's "sequence window and wraparound" definition).
inline int32_t seq_distance(uint32_t a, uint32_t b) {
    return (int32_t)(a - b);
}
inline bool seq_after(uint32_t a, uint32_t b) { return seq_distance(a, b) > 0; }
inline bool seq_before(uint32_t a, uint32_t b) { return seq_distance(a, b) < 0; }

inline uint16_t rd16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
inline uint32_t rd32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
inline uint64_t rd64(const uint8_t* p) {
    return ((uint64_t)rd32(p) << 32) | (uint64_t)rd32(p + 4);
}
inline void wr16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}
inline void wr32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}
inline void wr64(uint8_t* p, uint64_t v) {
    wr32(p, (uint32_t)(v >> 32));
    wr32(p + 4, (uint32_t)(v & 0xFFFFFFFFull));
}

// FNV-1a 32-bit integrity (documented protocol choice; 0 when no payload).
inline uint32_t fnv1a32(const uint8_t* p, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

}  // namespace

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

bool parse_frame(const uint8_t* data, size_t len, FeedMessage& out) {
    if (data == nullptr || len < FRAME_HEADER_LEN) return false;
    if (data[0] != FRAME_VERSION) return false;  // unknown version: reject
    FeedMessage m;
    m.version = data[0];
    m.type = (MsgType)data[1];
    m.session_id = rd32(data + 2);
    m.sequence = rd32(data + 6);
    m.timestamp_domain = (TsDomain)data[10];
    m.timestamp_ns = rd64(data + 11);
    const uint16_t plen = rd16(data + 19);
    if (FRAME_HEADER_LEN + plen > len) return false;  // truncated payload
    const uint32_t integrity = rd32(data + 21);
    if (plen > 0) {
        const uint32_t want = fnv1a32(data + FRAME_HEADER_LEN, plen);
        if (integrity != 0 && integrity != want) return false;  // integrity fail
    }
    m.payload.assign(data + FRAME_HEADER_LEN, data + FRAME_HEADER_LEN + plen);
    out = std::move(m);
    return true;
}

void encode_frame(const FeedMessage& in, std::vector<uint8_t>& out) {
    const size_t plen = in.payload.size();
    out.assign(FRAME_HEADER_LEN + plen, 0);
    uint8_t* p = out.data();
    p[0] = in.version;
    p[1] = (uint8_t)in.type;
    wr32(p + 2, in.session_id);
    wr32(p + 6, in.sequence);
    p[10] = (uint8_t)in.timestamp_domain;
    wr64(p + 11, in.timestamp_ns);
    wr16(p + 19, (uint16_t)plen);
    wr32(p + 21, plen > 0 ? fnv1a32(in.payload.data(), plen) : 0);
    if (plen > 0) {
        std::memcpy(p + FRAME_HEADER_LEN, in.payload.data(), plen);
    }
}

// ---------------------------------------------------------------------------
// Multicast transport (portable: Winsock2 / POSIX sockets)
// ---------------------------------------------------------------------------

MulticastReceiver::MulticastReceiver() = default;

MulticastReceiver::~MulticastReceiver() { leave(); }

bool MulticastReceiver::join(const McastConfig& cfg, std::string& err) {
    if (socket_ != kInvalidSocket) {
        err = "already joined";
        return false;
    }
    cfg_ = cfg;
    socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == kInvalidSocket) {
        err = "socket() failed: " + last_err();
        return false;
    }
    int reuse = 1;
    setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR,
#ifdef _WIN32
               (const char*)&reuse,
#else
               &reuse,
#endif
               sizeof(reuse));
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(cfg.port);
    if (::bind(socket_, (sockaddr*)&bind_addr, sizeof(bind_addr)) != 0) {
        err = "bind() failed: " + last_err();
        leave();
        return false;
    }
    ip_mreq mreq{};
    mreq.imr_multiaddr.s_addr = addr_ipv4(cfg.group);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(socket_, IPPROTO_IP, IP_ADD_MEMBERSHIP,
#ifdef _WIN32
                   (const char*)&mreq,
#else
                   &mreq,
#endif
                   sizeof(mreq)) != 0) {
        err = "IP_ADD_MEMBERSHIP failed: " + last_err();
        leave();
        return false;
    }
#ifdef _WIN32
    DWORD loop = cfg.loopback ? 1 : 0;
    setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_LOOP, (const char*)&loop,
               sizeof(loop));
#else
    unsigned char loop = cfg.loopback ? 1 : 0;
    setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
#endif
    return true;
}

void MulticastReceiver::leave() {
    if (socket_ == kInvalidSocket) return;
    if (!cfg_.group.empty()) {
        ip_mreq mreq{};
        mreq.imr_multiaddr.s_addr = addr_ipv4(cfg_.group);
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        setsockopt(socket_, IPPROTO_IP, IP_DROP_MEMBERSHIP,
#ifdef _WIN32
                   (const char*)&mreq,
#else
                   &mreq,
#endif
                   sizeof(mreq));
    }
    close_socket(socket_);
    socket_ = kInvalidSocket;
    cfg_ = McastConfig{};
}

bool MulticastReceiver::receive(std::vector<uint8_t>& msg, int timeout_ms) {
    if (socket_ == kInvalidSocket) return false;
    const int sel = wait_readable(socket_, timeout_ms);
    if (sel <= 0) return false;  // timeout or closed
    char buf[65536];
    const int n = (int)::recv(socket_, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    msg.assign((uint8_t*)buf, (uint8_t*)buf + n);
    return true;
}

MulticastSender::MulticastSender() = default;

MulticastSender::~MulticastSender() { close(); }

bool MulticastSender::open(const McastConfig& cfg, std::string& err) {
    if (socket_ != kInvalidSocket) {
        err = "already open";
        return false;
    }
    cfg_ = cfg;
    socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == kInvalidSocket) {
        err = "socket() failed: " + last_err();
        return false;
    }
#ifdef _WIN32
    DWORD ttl = (DWORD)cfg.ttl;
    setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&ttl,
               sizeof(ttl));
    DWORD loop = cfg.loopback ? 1 : 0;
    setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_LOOP, (const char*)&loop,
               sizeof(loop));
#else
    int ttl = cfg.ttl;
    setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    unsigned char loop = cfg.loopback ? 1 : 0;
    setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
#endif
    return true;
}

void MulticastSender::close() {
    if (socket_ == kInvalidSocket) return;
    close_socket(socket_);
    socket_ = kInvalidSocket;
    cfg_ = McastConfig{};
}

bool MulticastSender::send_to(const uint8_t* data, size_t len,
                              const std::string& addr, uint16_t port) {
    if (socket_ == kInvalidSocket) return false;
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = addr_ipv4(addr);
    dst.sin_port = htons(port);
    const int n = (int)::sendto(socket_, (const char*)data, (int)len, 0,
                                (sockaddr*)&dst, sizeof(dst));
    return n == (int)len;
}

bool MulticastSender::send(const uint8_t* data, size_t len) {
    return send_to(data, len, cfg_.group, cfg_.port);
}

UnicastSocket::UnicastSocket() = default;

UnicastSocket::~UnicastSocket() { close(); }

bool UnicastSocket::bind(const std::string& addr, uint16_t port,
                         std::string& err) {
    if (socket_ != kInvalidSocket) {
        err = "already bound";
        return false;
    }
    socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == kInvalidSocket) {
        err = "socket() failed: " + last_err();
        return false;
    }
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = addr.empty() ? htonl(INADDR_ANY) : addr_ipv4(addr);
    a.sin_port = htons(port);
    if (::bind(socket_, (sockaddr*)&a, sizeof(a)) != 0) {
        err = "bind() failed: " + last_err();
        close();
        return false;
    }
    return true;
}

bool UnicastSocket::recv(std::vector<uint8_t>& msg, int timeout_ms) {
    if (socket_ == kInvalidSocket) return false;
    if (wait_readable(socket_, timeout_ms) <= 0) return false;
    char buf[65536];
    const int n = (int)::recv(socket_, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    msg.assign((uint8_t*)buf, (uint8_t*)buf + n);
    return true;
}

bool UnicastSocket::send_to(const uint8_t* data, size_t len,
                            const std::string& addr, uint16_t port) {
    if (socket_ == kInvalidSocket) return false;
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = addr_ipv4(addr);
    dst.sin_port = htons(port);
    const int n = (int)::sendto(socket_, (const char*)data, (int)len, 0,
                                (sockaddr*)&dst, sizeof(dst));
    return n == (int)len;
}

void UnicastSocket::close() {
    if (socket_ == kInvalidSocket) return;
    close_socket(socket_);
    socket_ = kInvalidSocket;
}

// ---------------------------------------------------------------------------
// SequencedFeed
// ---------------------------------------------------------------------------

SequencedFeed::SequencedFeed(size_t max_reorder_window, NakCallback nak)
    : max_reorder_(max_reorder_window), nak_(std::move(nak)) {}

// Bound on recoverable-gap tracking: gaps larger than this are bridged via
// snapshot instead of tracked sequence-by-sequence (documented policy).
constexpr uint64_t kMaxTrackedGapSeqs = 4096;

void SequencedFeed::declare_gap(uint32_t session, uint32_t first,
                                uint32_t last, std::vector<FeedEvent>& out) {
    FeedEvent ev;
    ev.kind = FeedEvent::Kind::GapDetected;
    ev.gap = GapEvent{first, last};
    // Track the declared gap (bounded) so late retransmissions are delivered
    // as recovered content instead of being dropped as duplicates.
    if ((uint64_t)last - (uint64_t)first + 1 <= kMaxTrackedGapSeqs) {
        for (uint64_t s = first;; ++s) {
            pending_gaps_.insert((uint32_t)s);
            if (s == last) break;
        }
    }
    out.push_back(std::move(ev));
    if (nak_) {
        std::vector<GapEvent> ranges;
        ranges.push_back({first, last});
        nak_(session, ranges);
    }
}

bool SequencedFeed::deliver(uint32_t seq, FeedMessage msg, bool recovered,
                            std::vector<FeedEvent>& out) {
    FeedEvent ev;
    ev.kind = FeedEvent::Kind::Delivered;
    ev.deliver.message = std::move(msg);
    ev.deliver.recovered = recovered;
    last_delivered_ = seq;
    out.push_back(std::move(ev));
    return true;
}

bool SequencedFeed::insert_reorder(uint32_t seq, FeedMessage msg,
                                   std::vector<FeedEvent>& out) {
    reorder_[seq] = std::move(msg);
    return true;
}

void SequencedFeed::on_frame(const FeedMessage& m, std::vector<FeedEvent>& out) {
    // The assembler sequences market payloads only; control frames (NAK,
    // snapshot request/response, heartbeat) are handled by the caller.
    if (m.type != MsgType::MarketPayload) return;

    if (!seen_first_) {
        seen_first_ = true;
        expected_ = m.sequence;
        deliver(m.sequence, m, false, out);
        expected_++;
        return;
    }

    if (m.sequence == expected_) {
        deliver(m.sequence, m, false, out);
        expected_++;
        // Cascade any buffered reordered messages.
        for (;;) {
            auto it = reorder_.find(expected_);
            if (it == reorder_.end()) break;
            deliver(it->first, std::move(it->second), false, out);
            reorder_.erase(it);
            expected_++;
        }
        return;
    }

    if (seq_after(m.sequence, expected_)) {
        // Instant gap detection with exact range (ELITE_LOSS_RECOVERY §1):
        // expected N+1, arrived N+k -> gap [N+1..N+k-1].
        const uint32_t gap_first = expected_;
        const uint32_t gap_last = m.sequence - 1;
        // Bounded reorder window: a frame farther than the window ahead
        // declares the gap and bridges the cursor (never silent loss).
        if ((uint64_t)(m.sequence - expected_) > max_reorder_) {
            reorder_.clear();
        }
        declare_gap(m.session_id, gap_first, gap_last, out);
        deliver(m.sequence, m, false, out);
        expected_ = m.sequence + 1;
        return;
    }

    // m.sequence < expected_: retransmission of a declared gap, a duplicate,
    // or a late reordered frame.
    auto pg = pending_gaps_.find(m.sequence);
    if (pg != pending_gaps_.end()) {
        pending_gaps_.erase(pg);
        deliver(m.sequence, m, true, out);  // recovered content
        return;
    }
    FeedEvent ev;
    ev.kind = FeedEvent::Kind::DuplicateIgnored;
    out.push_back(std::move(ev));
}

void SequencedFeed::apply_snapshot(uint32_t snapshot_sequence,
                                   std::vector<FeedEvent>& out) {
    // Snapshot bridging (ELITE_LOSS_RECOVERY §3): re-seed state at the
    // snapshot's sequence; frames at or below it are no longer expected.
    if (seen_first_ && !seq_after(snapshot_sequence, last_delivered_)) {
        return;  // snapshot older than the derived state: ignore
    }
    seen_first_ = true;
    expected_ = snapshot_sequence + 1;
    last_delivered_ = snapshot_sequence;
    reorder_.clear();
    pending_gaps_.clear();
    FeedEvent ev;
    ev.kind = FeedEvent::Kind::SnapshotBridged;
    ev.snapshot_sequence = snapshot_sequence;
    out.push_back(std::move(ev));
}

}  // namespace net
