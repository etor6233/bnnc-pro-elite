// ouch/ouch_codec.hpp — NASDAQ OUCH 5.0 order-entry semantics module.
//
// SPEC SOURCES (nothing invented):
//  - Captured official OUCH 5.0 PDF, SHA256-pinned in
//    external-review/low-latency-reference/INDEX.md:
//    OUCH5.0.pdf SHA256 770253DE8B257AB68700AB5DBF179F806D890890683BF695AB8257585D8C2C00
//    Text extraction: cpp/tools/extracted/OUCH5.0.txt.
//  - Annotated semantics: MARKET_MICROSTRUCTURE_EXCHANGE_SYSTEMS.md §5.5
//    (order entry: UserRefNum day/account-scoped, unique and strictly
//    increasing for enter/replace; lower ref => duplicate, ignore; replace has
//    its own semantics incl. cumulative liability over the chain; only the
//    response confirms the outcome).
//
// Implemented scope (per instruction FASE 1-4 checklist "OUCH-semántica"):
//   inbound: Enter Order (O, spec 2.1), Replace Order (U, spec 2.2),
//            Cancel Order (X, spec 2.3);
//   outbound: Order Accepted (A, spec 3.2), Order Replaced (U, spec 3.3),
//             Order Canceled (C, spec 3.4), Order Executed (E, spec 3.6),
//             Rejected (J, spec 3.8);
//   session engine implementing the UserRefNum rules of spec 1.2 and the
//   replace outcomes of spec 2.2 (silently ignored / cancel-take-out /
//   rejected / replaced), the superfluous-cancel rule of spec 2.3, and the
//   cumulative chain share rule (spec 2.2: no chain may execute more than
//   999,999 shares cumulatively; quantity < 1,000,000 per spec 2.1/2.2).
//
// Data types (spec 1.2): alpha fields ASCII left-justified space-padded;
// numeric fields big-endian (Long 8 / Integer 4 / Short 2 / Byte 1); prices
// unsigned fixed point with implied 4 decimals; timestamps ns since midnight.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace ouch {

enum class DecodeStatus : uint8_t { Ok = 0, Truncated, UnknownType };
const char* to_string(DecodeStatus s);

// ---------------------------------------------------------------------------
// Inbound messages (client -> host). Spec: all inbound messages may be
// repeated benignly (1.3 Fault Redundancy); sequential processing per port.
// ---------------------------------------------------------------------------

// 2.1 Type O – Enter Order: base 46 bytes + optional appendage.
struct EnterOrder {
    uint32_t user_ref_num;  // @1, 4 bytes, day-unique strictly increasing
    char side;              // @5: B/S/T/E
    uint32_t quantity;      // @6: >0 and <1,000,000 (spec 2.1)
    std::string symbol;     // @10, 8 alpha
    uint64_t price;         // @18, 8 bytes fixed point 4 decimals
    char time_in_force;     // @26
    char display;           // @27: Y/N/A
    char capacity;          // @28: A/P/R/O
    char intermkt_sweep;    // @29: Y/N
    char cross_type;        // @30
    std::string cl_ord_id;  // @31, 14 alpha
    uint16_t appendage_len; // @45, 2 bytes
    std::string appendage;  // @47, var
};

// 2.2 Type U – Replace Order: base 40 bytes + optional appendage.
struct ReplaceOrder {
    uint32_t orig_user_ref_num;  // @1
    uint32_t user_ref_num;       // @5, new ref: unique, strictly increasing
    uint32_t quantity;           // @9: total shares liable for the chain
    uint64_t price;              // @13
    char time_in_force;          // @21
    char display;                // @22
    char intermkt_sweep;         // @23
    std::string cl_ord_id;       // @24, 14 alpha
    uint16_t appendage_len;      // @38
    std::string appendage;       // @40
};

// 2.3 Type X – Cancel Order: base 11 bytes + optional appendage.
struct CancelOrder {
    uint32_t user_ref_num;       // @1
    uint32_t quantity;           // @5: new intended order size; 0 cancels all
    uint16_t appendage_len;      // @9 (optional per spec 2.3)
    std::string appendage;       // @11
};

enum class InboundType : uint8_t { Enter, Replace, Cancel };
struct Inbound {
    InboundType type;
    EnterOrder enter;
    ReplaceOrder replace;
    CancelOrder cancel;
};

// Encode inbound messages (used by golden generation and tests). Returns
// false on invalid field constraints (quantity bounds per spec 2.1/2.2).
bool encode_enter(const EnterOrder& m, std::string& out);
bool encode_replace(const ReplaceOrder& m, std::string& out);
bool encode_cancel(const CancelOrder& m, std::string& out);
DecodeStatus decode_inbound(const uint8_t* data, size_t len, Inbound& out);

// ---------------------------------------------------------------------------
// Outbound messages (host -> client).
// ---------------------------------------------------------------------------

// 3.2 Type A – Order Accepted: base 64 bytes.
struct Accepted {
    uint64_t timestamp_ns;   // @1
    uint32_t user_ref_num;   // @9
    char side;               // @13
    uint32_t quantity;       // @14
    std::string symbol;      // @18, 8 alpha
    uint64_t price;          // @26
    char time_in_force;      // @34
    char display;            // @35
    uint64_t order_ref_num;  // @36
    char capacity;           // @44
    char intermkt_sweep;     // @45
    char cross_type;         // @46
    char order_state;        // @47: L/D
    std::string cl_ord_id;   // @48, 14 alpha
    uint16_t appendage_len;  // @62
    std::string appendage;   // @64
};

// 3.3 Type U – Order Replaced: base 68 bytes.
struct Replaced {
    uint64_t timestamp_ns;   // @1
    uint32_t orig_user_ref;  // @9
    uint32_t user_ref_num;   // @13
    char side;               // @17
    uint32_t quantity;       // @18: shares outstanding on the book
    std::string symbol;      // @22
    uint64_t price;          // @30
    char time_in_force;      // @38
    char display;            // @39
    uint64_t order_ref_num;  // @40
    char capacity;           // @48
    char intermkt_sweep;     // @49
    char cross_type;         // @50
    char order_state;        // @51: L/D
    std::string cl_ord_id;   // @52, 14 alpha
    uint16_t appendage_len;  // @66
    std::string appendage;   // @68
};

// 3.4 Type C – Order Canceled: base 20 bytes (appendage only when the
// inbound message carried a non-zero UserRefIdx, spec 3.4).
struct Canceled {
    uint64_t timestamp_ns;   // @1
    uint32_t user_ref_num;   // @9
    uint32_t quantity;       // @13: incremental decrement
    char reason;             // @17
    uint16_t appendage_len;  // @18
    std::string appendage;   // @20
};

// 3.6 Type E – Order Executed: base 36 bytes.
struct Executed {
    uint64_t timestamp_ns;   // @1
    uint32_t user_ref_num;   // @9
    uint32_t quantity;       // @13: incremental shares just executed
    uint64_t price;          // @17
    char liquidity_flag;     // @25
    uint64_t match_number;   // @26
    uint16_t appendage_len;  // @34
    std::string appendage;   // @36
};

// 3.8 Type J – Rejected: base 31 bytes.
struct Rejected {
    uint64_t timestamp_ns;   // @1
    uint32_t user_ref_num;   // @9: cannot be re-used (spec 3.8)
    uint16_t reason;         // @13: Appendix D
    std::string cl_ord_id;   // @15, 14 alpha
    uint16_t appendage_len;  // @29
    std::string appendage;   // @31
};

enum class OutboundType : uint8_t { Accepted, Replaced, Canceled, Executed, Rejected };
struct Outbound {
    OutboundType type;
    Accepted accepted;
    Replaced replaced;
    Canceled canceled;
    Executed executed;
    Rejected rejected;
};

DecodeStatus decode_outbound(const uint8_t* data, size_t len, Outbound& out);

// ---------------------------------------------------------------------------
// Order-entry session engine (spec 1.2 + 2.2 + 2.3 semantics).
// ---------------------------------------------------------------------------

enum class EnterOutcome : uint8_t {
    Accepted,
    Rejected,          // quantity out of the spec 2.1 bounds (>=1,000,000 or 0)
    DuplicateIgnored,  // UserRefNum <= last processed: retransmission (1.2)
};

enum class ReplaceOutcome : uint8_t {
    Replaced,          // spec 2.2 outcome 4
    SilentlyIgnored,   // spec 2.2 outcome 1: orig not live or new ref used
    CancelTakeOut,     // spec 2.2 outcome 2: invalid details -> cancel orig
    Rejected,          // spec 2.2 outcome 3: orig live but cannot be canceled
    DuplicateIgnored,  // UserRefNum <= last processed: retransmission (1.2)
};

enum class CancelOutcome : uint8_t {
    Canceled,
    SilentlyIgnored,  // superfluous cancel (spec 2.3)
};

const char* to_string(EnterOutcome o);
const char* to_string(ReplaceOutcome o);
const char* to_string(CancelOutcome o);

// Models one client's view of its OUCH order flow for a single port/account
// (spec 1.2: UserRefNum rules are per port, or per UserRefIdx channel when
// that optional tag is used — channels are out of scope here and the engine
// documents that boundary).
class OrderEntrySession {
  public:
    OrderEntrySession();

    // Inbound processing, in wire order (spec 1.2: processed sequentially).
    EnterOutcome on_enter(const EnterOrder& m);
    ReplaceOutcome on_replace(const ReplaceOrder& m);
    CancelOutcome on_cancel(const CancelOrder& m);

    // Host responses arrive in sequence; the session folds them into its
    // view. Executions accumulate over the order/replace chain (spec 2.2).
    void on_executed(const Executed& m);
    void on_canceled(const Canceled& m);

    // State queries (for tests/evidence only).
    struct OrderState {
        uint32_t ref;            // current (latest) UserRefNum of the chain
        uint64_t order_ref_num;  // day-unique venue order reference
        char side;
        uint64_t price;
        uint32_t total_liable;     // shares liable over the whole chain
        uint32_t executed_cumulative;
        uint32_t canceled_cumulative;
        bool live;
    };
    const OrderState* find_order(uint32_t current_ref) const;
    uint32_t last_processed_ref() const { return last_processed_; }
    size_t consumed_ref_count() const { return consumed_.size(); }

    // Spec 2.2 outcome 3 models "cross order in the late period": orders that
    // cannot be canceled. The session-level flag is the spec's "late period".
    void set_late_period(bool on) { late_period_ = on; }

  private:
    struct InternalOrder {
        OrderState st;
    };
    uint32_t last_processed_ = 0;
    std::map<uint32_t, InternalOrder> orders_;       // by current ref
    std::map<uint32_t, bool> consumed_;              // consumed UserRefNums
    std::map<uint32_t, uint32_t> chain_origin_;      // ref -> first ref of chain
    std::map<uint32_t, uint32_t> chain_current_;     // origin -> current ref
    bool late_period_ = false;

    void mark_consumed(uint32_t ref) { consumed_[ref] = true; }
    bool is_consumed(uint32_t ref) const;
};

}  // namespace ouch
