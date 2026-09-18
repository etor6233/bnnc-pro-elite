// fix/fix_session.cpp — FIX codec + minimal session layer (FASE 4).
//
// Semantics per MARKET_MICROSTRUCTURE_EXCHANGE_SYSTEMS.md §5.5 [SPEC] and the
// QuickFIX reference (captured). Standard header/trailer: 8=BeginString,
// 9=BodyLength, 35=MsgType ... 10=CheckSum (sum of bytes mod 256, including
// the SOH separators, up to but excluding the 10= field).
#include <fix/fix_session.hpp>

#include <cstdlib>
#include <sstream>

namespace fix {

namespace {
constexpr char SOH = '\x01';

inline uint32_t fnv1a32(const std::string& s) {
    uint32_t h = 2166136261u;
    for (unsigned char c : s) {
        h ^= c;
        h *= 16777619u;
    }
    return h;
}
}  // namespace

const char* to_string(ParseStatus s) {
    switch (s) {
        case ParseStatus::Ok: return "Ok";
        case ParseStatus::Malformed: return "Malformed";
        case ParseStatus::BadBodyLength: return "BadBodyLength";
        case ParseStatus::BadChecksum: return "BadChecksum";
    }
    return "?";
}

ParseStatus parse(const uint8_t* data, size_t len, FixMessage& out) {
    if (data == nullptr || len < 3) return ParseStatus::Malformed;
    const std::string raw((const char*)data, len);
    // Must end with SOH.
    if (raw.empty() || raw.back() != SOH) return ParseStatus::Malformed;

    // Split on SOH into tag=value fields.
    FixMessage m;
    m.raw = raw;
    size_t pos = 0;
    while (pos < raw.size()) {
        const size_t next = raw.find(SOH, pos);
        if (next == std::string::npos) return ParseStatus::Malformed;
        const std::string field = raw.substr(pos, next - pos);
        const size_t eq = field.find('=');
        if (eq == std::string::npos) return ParseStatus::Malformed;
        const std::string tag_s = field.substr(0, eq);
        if (tag_s.empty()) return ParseStatus::Malformed;
        int tag = 0;
        for (char c : tag_s) {
            if (c < '0' || c > '9') return ParseStatus::Malformed;
            tag = tag * 10 + (c - '0');
        }
        const std::string value = field.substr(eq + 1);
        if (m.fields.count(tag) != 0) return ParseStatus::Malformed;
        m.fields[tag] = value;
        pos = next + 1;
    }

    // Required structure: 8, 9, 35, 10.
    if (!m.fields.count(8) || !m.fields.count(9) || !m.fields.count(35) ||
        !m.fields.count(10)) {
        return ParseStatus::Malformed;
    }
    // Body length: bytes between the end of "9=..." SOH and the start of
    // "10=..." SOH.
    {
        const size_t nine = raw.find("9=");
        const size_t nine_end = raw.find(SOH, nine);
        const size_t ten = raw.find("10=");
        if (nine == std::string::npos || nine_end == std::string::npos ||
            ten == std::string::npos) {
            return ParseStatus::Malformed;
        }
        const size_t body_len = ten - (nine_end + 1);
        const uint64_t declared = std::strtoull(m.fields[9].c_str(), nullptr, 10);
        if (declared != body_len) return ParseStatus::BadBodyLength;
    }
    // Checksum: sum of every byte BEFORE "10=", mod 256.
    {
        const size_t ten = raw.find("10=");
        uint32_t sum = 0;
        for (size_t i = 0; i < ten; ++i) sum += (uint8_t)raw[i];
        const uint64_t declared = std::strtoull(m.fields[10].c_str(), nullptr, 10);
        if (declared != (sum % 256)) return ParseStatus::BadChecksum;
    }

    out = std::move(m);
    return ParseStatus::Ok;
}

void build(const FixMessage& in, std::string& out) {
    // Emit 8 and 35 first (standard order), then the rest, then 9? Standard
    // layout: 8=..., 9=..., 35=... — BodyLength counts from 35 through the
    // field before 10. Build body, then assemble.
    out.clear();
    std::string body;
    const std::string begin = in.fields.count(8) ? in.fields.at(8) : "FIX.4.4";
    for (const auto& [tag, value] : in.fields) {
        if (tag == 8 || tag == 9 || tag == 10) continue;
        body += std::to_string(tag) + "=" + value;
        body.push_back(SOH);
    }
    const std::string body_len = std::to_string(body.size());
    out = "8=" + begin + SOH + "9=" + body_len + SOH + body;
    uint32_t sum = 0;
    for (unsigned char c : out) sum += c;
    out += "10=" + std::to_string(sum % 256) + SOH;
}

bool has(int tag, const std::string& value, const FixMessage& m) {
    auto it = m.fields.find(tag);
    return it != m.fields.end() && it->second == value;
}

uint32_t seq_num(const FixMessage& m) {
    auto it = m.fields.find(34);
    if (it == m.fields.end()) return 0;
    return (uint32_t)std::strtoul(it->second.c_str(), nullptr, 10);
}

std::string msg_type(const FixMessage& m) {
    auto it = m.fields.find(35);
    return it == m.fields.end() ? std::string() : it->second;
}

// ---------------------------------------------------------------------------
// FixSession
// ---------------------------------------------------------------------------

FixSession::FixSession(SessionConfig cfg) : cfg_(std::move(cfg)) {}

std::string FixSession::build_with_seq(const std::string& msg_type_char,
                                       uint32_t seq,
                                       const std::map<int, std::string>& extra) {
    FixMessage m;
    m.fields[8] = cfg_.begin_string;
    m.fields[35] = msg_type_char;
    m.fields[49] = cfg_.sender_comp_id;
    m.fields[56] = cfg_.target_comp_id;
    m.fields[34] = std::to_string(seq);
    m.fields[52] = "20260918-00:00:00.000";
    for (const auto& [tag, value] : extra) m.fields[tag] = value;
    std::string out;
    build(m, out);
    return out;
}

std::string FixSession::initiate_logon() {
    std::map<int, std::string> extra;
    extra[98] = "0";
    extra[108] = std::to_string(cfg_.heartbeat_interval_s);
    std::string out = build_with_seq("A", next_out_++, extra);
    state_ = SessionState::AwaitingLogon;
    return out;
}

std::string FixSession::reply_logon(uint32_t their_seq) {
    next_in_ = their_seq + 1;  // accept the counterparty's sequence
    std::map<int, std::string> extra;
    extra[98] = "0";
    extra[108] = std::to_string(cfg_.heartbeat_interval_s);
    std::string out = build_with_seq("A", next_out_++, extra);
    state_ = SessionState::LoggedOn;
    return out;
}

std::string FixSession::create_heartbeat() {
    return build_with_seq("0", next_out_++, {});
}

void FixSession::send_application(const FixMessage& app,
                                  std::vector<std::string>& out) {
    // Application messages travel in the same sequence space as session
    // messages (§5.5) and are retained for gap-fill retransmission.
    FixMessage m = app;
    m.fields[34] = std::to_string(next_out_++);
    std::string wire;
    build(m, wire);
    outbound_store_[(uint32_t)std::strtoul(m.fields[34].c_str(), nullptr, 10)] = m;
    if (outbound_store_.size() > 256) outbound_store_.erase(outbound_store_.begin());
    out.push_back(std::move(wire));
}

void FixSession::process_inbound(const std::string& raw,
                                 std::vector<std::string>& out) {
    FixMessage m;
    const ParseStatus st =
        parse((const uint8_t*)raw.data(), raw.size(), m);
    if (st != ParseStatus::Ok) {
        ++malformed_;  // corrupted inbound is dropped and counted
        return;
    }
    dispatch(m, out);
}

bool FixSession::dispatch(const FixMessage& m, std::vector<std::string>& out) {
    const uint32_t seq = seq_num(m);
    const std::string type = msg_type(m);

    // Logon may arrive in any state; heartbeat/application only when logged.
    if (type == "A") {
        if (state_ == SessionState::Disconnected) {
            // Acceptor role: reply with our own logon (QuickFIX semantics).
            out.push_back(reply_logon(seq));
            return true;
        }
        // Initiator receiving the acceptor's logon reply.
        next_in_ = seq + 1;
        state_ = SessionState::LoggedOn;
        return true;
    }
    if (type == "5") {  // Logout
        state_ = SessionState::Closed;
        next_in_ = seq + 1;
        return true;
    }
    if (state_ != SessionState::LoggedOn) return false;

    if (seq == next_in_) {
        // In order: process now.
        ++next_in_;
        const bool ok = (type == "0" || type == "1" || type == "2" ||
                         type == "4" || type == "D" || type == "8" ||
                         type == "9" || type == "F" || type == "G");
        if (!ok) return false;
        if (type == "1") {  // TestRequest: echo TestReqID(112)
            std::map<int, std::string> extra;
            auto it = m.fields.find(112);
            if (it != m.fields.end()) extra[112] = it->second;
            out.push_back(build_with_seq("0", next_out_++, extra));
        } else if (type == "2") {  // ResendRequest: replay from the store
            const uint32_t begin =
                (uint32_t)std::strtoul(m.fields.count(7) ? m.fields.at(7).c_str()
                                                         : "1",
                                       nullptr, 10);
            const uint32_t end =
                (uint32_t)std::strtoul(m.fields.count(16) ? m.fields.at(16).c_str()
                                                          : "0",
                                       nullptr, 10);
            for (uint32_t s = begin; s <= end; ++s) {
                auto it = outbound_store_.find(s);
                if (it == outbound_store_.end()) continue;
                FixMessage dup = it->second;
                dup.fields[43] = "Y";  // PossDupFlag: same original sequence
                std::string wire;
                build(dup, wire);
                out.push_back(std::move(wire));
            }
        } else if (type == "4") {  // SequenceReset
            const bool gap_fill = has(123, "Y", m);
            if (gap_fill && m.fields.count(36)) {
                // Skip the messages that are not retransmitted (§5.5).
                next_in_ = (uint32_t)std::strtoul(m.fields.at(36).c_str(),
                                                  nullptr, 10);
            }
        }
        // Process anything pending now that the gap closed.
        for (;;) {
            auto pit = pending_.find(next_in_);
            if (pit == pending_.end()) break;
            dispatch(pit->second, out);
            pending_.erase(pit);
        }
        return true;
    }

    if (seq > next_in_) {
        // Gap detected instantly: request the missing range and retain the
        // current message until the gap closes (§5.5).
        FixMessage rr;
        rr.fields[8] = cfg_.begin_string;
        rr.fields[35] = "2";
        rr.fields[49] = cfg_.sender_comp_id;
        rr.fields[56] = cfg_.target_comp_id;
        rr.fields[34] = std::to_string(next_out_++);
        rr.fields[52] = "20260918-00:00:00.000";
        rr.fields[7] = std::to_string(next_in_);
        rr.fields[16] = std::to_string(seq - 1);
        std::string wire;
        build(rr, wire);
        out.push_back(std::move(wire));
        pending_[seq] = m;
        return true;
    }

    // seq < next_in_: retransmission with PossDupFlag or a duplicate.
    if (has(43, "Y", m)) {
        // Session retransmission: same MsgSeqNum + PossDup=Y -> recovered
        // delivery, deduplicated by session (§5.5). We have already consumed
        // that sequence: nothing to do.
        return true;
    }
    // Duplicate: ignore.
    return true;
}

SeqStore FixSession::persist() const {
    return SeqStore{next_in_, next_out_};
}

void FixSession::restore(const SeqStore& s) {
    next_in_ = s.next_in;
    next_out_ = s.next_out;
}

}  // namespace fix
