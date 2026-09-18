// fix/fix_session.hpp — minimal FIX Session Layer (FASE 4).
//
// SPEC SOURCES (nothing invented):
//  - MARKET_MICROSTRUCTURE_EXCHANGE_SYSTEMS.md §5.5 [SPEC] (annotated):
//    MsgSeqNum(34) orders session and application messages in ONE space;
//    NextNumIn/NextNumOut persist across connections; a gap generates
//    ResendRequest(35=2) and new messages are retained until the gap closes;
//    retransmission preserves the original sequence and uses
//    PossDupFlag(43)=Y; SequenceReset(35=4, GapFillFlag=Y) skips messages
//    that are not retransmitted; resetting the session is not an innocent
//    repair. Session retransmission: same MsgSeqNum + PossDup=Y -> recover
//    delivery, deduplicate by session.
//  - QuickFIX (captured reference external-review/low-latency-reference/
//    quickfix): standard message layout semantics (header 8/9/35, trailer 10
//    with checksum = sum of bytes mod 256), used as design reference.
//
// Implemented scope: logon (35=A), logout (35=5), heartbeat (35=0),
// TestRequest (35=1), ResendRequest (35=2), SequenceReset-GapFill (35=4),
// sequence persistence and retransmission with PossDupFlag.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace fix {

// --- message codec -----------------------------------------------------------
struct FixMessage {
    std::map<int, std::string> fields;  // tag -> value (order preserved via
                                        // map<int,...>; duplicates rejected)
    std::string raw;  // original bytes as parsed
};

enum class ParseStatus : uint8_t {
    Ok = 0,
    Malformed,      // missing SOH structure / bad tags
    BadBodyLength,  // tag 9 does not match the actual body
    BadChecksum,    // tag 10 mismatch (sum of bytes mod 256)
};

const char* to_string(ParseStatus s);

// Parse a raw FIX message ("8=FIX.4.4\x01...\x0110=nnn\x01"). Verifies
// BodyLength(9) and CheckSum(10); never throws on arbitrary input.
ParseStatus parse(const uint8_t* data, size_t len, FixMessage& out);

// Build a message from fields. Tags 8/9/10 are set automatically: caller
// supplies at least 35; 9 and 10 are computed (standard header/trailer).
void build(const FixMessage& in, std::string& out);

// Helpers for the session layer.
bool has(int tag, const std::string& value, const FixMessage& m);
uint32_t seq_num(const FixMessage& m);        // tag 34
std::string msg_type(const FixMessage& m);    // tag 35

// --- session layer ------------------------------------------------------------
struct SessionConfig {
    std::string begin_string = "FIX.4.4";
    std::string sender_comp_id = "CLIENT";
    std::string target_comp_id = "VENUE";
    uint32_t heartbeat_interval_s = 30;  // tag 108
};

enum class SessionState : uint8_t {
    Disconnected = 0,
    AwaitingLogon,  // initiator: logon sent, waiting for acceptor logon
    LoggedOn,
    Closed,
};

// Persisted sequence numbers (NextNumIn/NextNumOut across connections).
struct SeqStore {
    uint32_t next_in = 1;
    uint32_t next_out = 1;
};

class FixSession {
  public:
    explicit FixSession(SessionConfig cfg);

    // Initiator side: first outbound message of a connection.
    std::string initiate_logon();

    // Acceptor side: reply logon for the counterparty's logon.
    std::string reply_logon(uint32_t their_seq);

    // Process one inbound raw message; appends outbound messages to send.
    // Never throws; malformed inbound is dropped and counted.
    void process_inbound(const std::string& raw, std::vector<std::string>& out);

    // Periodic heartbeat producer.
    std::string create_heartbeat();

    SessionState state() const { return state_; }
    SeqStore persist() const;
    void restore(const SeqStore& s);
    uint64_t malformed_count() const { return malformed_; }
    size_t pending_count() const { return pending_.size(); }

  private:
    void send_application(const FixMessage& app, std::vector<std::string>& out);
    bool dispatch(const FixMessage& m, std::vector<std::string>& out);
    std::string build_with_seq(const std::string& msg_type_char, uint32_t seq,
                               const std::map<int, std::string>& extra);

    SessionConfig cfg_;
    SessionState state_ = SessionState::Disconnected;
    uint32_t next_in_ = 1;
    uint32_t next_out_ = 1;
    uint64_t malformed_ = 0;
    // Outbound message store for retransmission: last N application messages
    // keyed by their original sequence (session retransmission keeps the
    // original sequence and PossDupFlag=Y).
    std::map<uint32_t, FixMessage> outbound_store_;
    // Inbound messages received while a gap is open, processed in order once
    // the gap closes.
    std::map<uint32_t, FixMessage> pending_;
};

}  // namespace fix
