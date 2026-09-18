// itch/itch_codec.hpp — Nasdaq TotalView-ITCH 5.0 decoder (FASE 1).
//
// SPEC SOURCE (nothing invented): every field offset/length/type in this file
// comes from the captured official spec, SHA256-pinned in
// external-review/low-latency-reference/INDEX.md:
//   NQTVITCHSpecification.pdf  SHA256 45E0531D1B4B3BEB886E9618B2AB824A5AA9BDA3A99C0DFF03509306E68AACC3
// Text extraction (read-only, from the captured PDF) lives in
// cpp/tools/extracted/NQTVITCHSpecification.txt. Section references below use
// the spec's own numbering (e.g. "1.1 System Event Message").
//
// Spec "Data Types" (page 4):
//   - All integer fields are big endian (network byte order), unsigned unless
//     otherwise noted.
//   - All alpha fields are ASCII, left justified, right padded with spaces.
//   - Prices are fixed point with implied decimals (Price (4) => 4 decimals).
//     Max price(4) = 200,000.0000 (decimal, 0x77359400).
//   - Timestamps are nanoseconds since midnight.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>

namespace itch {

// Message type byte, per spec section headers (1.1, 1.2.x, 1.3.x, 1.4.x,
// 1.5.x). Not all TotalView-ITCH messages are implemented: this decoder covers
// the FASE 1 scope plus the book-relevant administrative messages whose tables
// are captured: S, R, H, A, F, E, C, X, D, U, P, Q, B.
enum class MessageType : char {
    SystemEvent = 'S',
    StockDirectory = 'R',
    StockTradingAction = 'H',
    AddOrder = 'A',
    AddOrderMpid = 'F',
    OrderExecuted = 'E',
    OrderExecutedWithPrice = 'C',
    OrderCancel = 'X',
    OrderDelete = 'D',
    OrderReplace = 'U',
    TradeNonCross = 'P',
    CrossTrade = 'Q',
    BrokenTrade = 'B',
};

enum class DecodeStatus : uint8_t {
    Ok = 0,
    // Buffer shorter than the fixed length of the message type (spec tables
    // define fixed lengths per type).
    Truncated,
    // Message type byte not defined by the captured spec tables.
    UnknownType,
    // Price(4) exceeds the spec maximum 200,000.0000 (0x77359400), per
    // spec page 4 "Data Types".
    PriceOutOfRange,
};

const char* to_string(MessageType t);
const char* to_string(DecodeStatus s);

// Common leading fields shared by every ITCH message table:
// Stock Locate (offset 1, 2 bytes), Tracking Number (offset 3, 2 bytes),
// Timestamp (offset 5, 6 bytes, nanoseconds since midnight).
struct CommonHeader {
    uint16_t stock_locate;
    uint16_t tracking_number;
    uint64_t timestamp_ns;
};

// 1.1 System Event Message — 12 bytes. Event codes (spec page 5):
// O/S/Q/M/E/C.
struct SystemEvent {
    CommonHeader hdr;
    char event_code;
};

// 1.2.1 Stock Directory — 39 bytes.
struct StockDirectory {
    CommonHeader hdr;
    std::string stock;             // 8 alpha, right-padded
    char market_category;          // Q/G/S/N/A/P/Z/V/<space>
    char financial_status;         // D/E/Q/S/G/H/J/K/C/N/<space>
    uint32_t round_lot_size;
    char round_lots_only;          // Y/N
    char issue_classification;     // Appendix D
    std::string issue_sub_type;    // 2 alpha, Appendix E
    char authenticity;             // P/T
    char short_sale_threshold;     // Y/N/<space>
    char ipo_flag;                 // Y/N/<space>
    char luld_reference_price_tier;// 1/2/<space>
    char etp_flag;                 // Y/N/<space>
    uint32_t etp_leverage_factor;
    char inverse_indicator;        // Y/N
};

// 1.2.2 Stock Trading Action — 25 bytes. Trading state H/P/Q/T; Reason is
// 4 alpha (Appendix C, not decoded further).
struct StockTradingAction {
    CommonHeader hdr;
    std::string stock;
    char trading_state;
    std::string reason;  // 4 alpha, right-padded
};

// 1.3.1 Add Order – No MPID Attribution ('A', 36 bytes) /
// 1.3.2 Add Order with MPID Attribution ('F', 40 bytes).
struct AddOrder {
    CommonHeader hdr;
    uint64_t order_ref;
    char side;           // B/S
    uint32_t shares;
    std::string stock;
    uint32_t price;      // Price (4)
    bool has_attribution = false;
    std::string attribution;  // 4 alpha, only for 'F'
};

// 1.4.1 Order Executed ('E', 31 bytes) / 1.4.2 Order Executed With Price
// ('C', 36 bytes). Modify messages are cumulative per spec 1.4.
struct OrderExecuted {
    CommonHeader hdr;
    uint64_t order_ref;
    uint32_t executed_shares;
    uint64_t match_number;
    bool has_price = false;
    char printable = '\0';  // 'C' variant: Y/N
    uint32_t price = 0;     // 'C' variant: Price (4)
};

// 1.4.3 Order Cancel — 23 bytes.
struct OrderCancel {
    CommonHeader hdr;
    uint64_t order_ref;
    uint32_t cancelled_shares;
};

// 1.4.4 Order Delete — 19 bytes.
struct OrderDelete {
    CommonHeader hdr;
    uint64_t order_ref;
};

// 1.4.5 Order Replace — 35 bytes. Side/stock/attribution are NOT in the
// message; consumers must retain them from the original Add (spec 1.4.5).
struct OrderReplace {
    CommonHeader hdr;
    uint64_t original_order_ref;
    uint64_t new_order_ref;
    uint32_t shares;
    uint32_t price;  // Price (4)
};

// 1.5.1 Trade Message (Non-Cross) — 44 bytes. Order Reference Number is
// null-filled (zero) since Dec 6 2010; Buy/Sell Indicator is always 'B'
// since 07/14/2014 (spec notes). Does not affect the book (spec 1.5.1).
struct TradeNonCross {
    CommonHeader hdr;
    uint64_t order_ref;
    char side;
    uint32_t shares;
    std::string stock;
    uint32_t price;  // Price (4)
    uint64_t match_number;
};

// 1.5.2 Cross Trade — 40 bytes. Cross type O/C/H.
struct CrossTrade {
    CommonHeader hdr;
    uint64_t shares;
    std::string stock;
    uint32_t cross_price;  // Price (4)
    uint64_t match_number;
    char cross_type;
};

// 1.5.3 Broken Trade / Order Execution — 19 bytes.
struct BrokenTrade {
    CommonHeader hdr;
    uint64_t match_number;
};

// Decoded message payload. The variant alternative identifies the message
// table that was used; 'type' repeats the raw byte.
struct Decoded {
    MessageType type = MessageType::SystemEvent;
    std::variant<SystemEvent, StockDirectory, StockTradingAction, AddOrder,
                 OrderExecuted, OrderCancel, OrderDelete, OrderReplace,
                 TradeNonCross, CrossTrade, BrokenTrade>
        payload;
};

// Decode exactly one ITCH message from `data[0..len)`.
// Returns Ok and fills `out` on success; otherwise returns the typed status
// and leaves `out` untouched. Never throws, never crashes on arbitrary input.
DecodeStatus decode(const uint8_t* data, size_t len, Decoded& out);

// Fixed wire length (bytes) of a message type, or 0 if not implemented.
size_t wire_length(MessageType t);

}  // namespace itch
