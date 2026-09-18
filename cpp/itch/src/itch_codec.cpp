// itch/itch_codec.cpp — Nasdaq TotalView-ITCH 5.0 decoder (FASE 1).
//
// Implementation follows the captured, SHA256-pinned official spec
// (NQTVITCHSpecification.pdf; text in cpp/tools/extracted/NQTVITCHSpecification.txt).
// Every offset/length below comes from that spec's field tables:
//   - "Data Types" (p.4): big-endian unsigned ints; ASCII left-justified
//     space-padded alphas; fixed-point prices (Price(4) => 4 decimals,
//     max 200,000.0000 = 0x77359400); timestamps in nanoseconds since midnight.
//   - Message tables: 1.1 (S), 1.2.1 (R), 1.2.2 (H), 1.3.1 (A), 1.3.2 (F),
//     1.4.1 (E), 1.4.2 (C), 1.4.3 (X), 1.4.4 (D), 1.4.5 (U), 1.5.1 (P),
//     1.5.2 (Q), 1.5.3 (B).
#include <itch/itch_codec.hpp>

#include <cstring>

namespace itch {

namespace {

// Fixed wire lengths per spec table.
constexpr size_t LEN_SYSTEM_EVENT = 12;        // 1.1
constexpr size_t LEN_STOCK_DIRECTORY = 39;     // 1.2.1
constexpr size_t LEN_TRADING_ACTION = 25;      // 1.2.2
constexpr size_t LEN_ADD_ORDER = 36;           // 1.3.1
constexpr size_t LEN_ADD_ORDER_MPID = 40;      // 1.3.2
constexpr size_t LEN_ORDER_EXECUTED = 31;      // 1.4.1
constexpr size_t LEN_EXECUTED_PRICE = 36;      // 1.4.2
constexpr size_t LEN_ORDER_CANCEL = 23;        // 1.4.3
constexpr size_t LEN_ORDER_DELETE = 19;        // 1.4.4
constexpr size_t LEN_ORDER_REPLACE = 35;       // 1.4.5
constexpr size_t LEN_TRADE_NON_CROSS = 44;     // 1.5.1
constexpr size_t LEN_CROSS_TRADE = 40;         // 1.5.2
constexpr size_t LEN_BROKEN_TRADE = 19;        // 1.5.3

// Spec p.4: maximum value of Price (4) is 200,000.0000 = 0x77359400.
constexpr uint32_t MAX_PRICE4 = 0x77359400u;

// Big-endian reads (spec p.4: "All integer fields are big endian").
inline uint16_t rd16(const uint8_t* p) {
    return (uint16_t)((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
inline uint32_t rd32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
inline uint64_t rd48(const uint8_t* p) {
    return ((uint64_t)p[0] << 40) | ((uint64_t)p[1] << 32) |
           ((uint64_t)p[2] << 24) | ((uint64_t)p[3] << 16) |
           ((uint64_t)p[4] << 8) | (uint64_t)p[5];
}
inline uint64_t rd64(const uint8_t* p) {
    return ((uint64_t)rd32(p) << 32) | (uint64_t)rd32(p + 4);
}

// Alpha fields are left justified, right padded with spaces (p.4): trim
// trailing spaces when exposing the value.
inline std::string alpha_trimmed(const uint8_t* p, size_t n) {
    size_t end = n;
    while (end > 0 && p[end - 1] == ' ') --end;
    return std::string(reinterpret_cast<const char*>(p), end);
}

inline CommonHeader read_common(const uint8_t* p) {
    // Stock Locate @1 (2), Tracking Number @3 (2), Timestamp @5 (6).
    return CommonHeader{rd16(p + 1), rd16(p + 3), rd48(p + 5)};
}

// Spec tables define the offsets verbatim; use the same offsets here.
inline uint32_t price4_at(const uint8_t* p, size_t off) { return rd32(p + off); }

}  // namespace

const char* to_string(MessageType t) {
    switch (t) {
        case MessageType::SystemEvent: return "S";
        case MessageType::StockDirectory: return "R";
        case MessageType::StockTradingAction: return "H";
        case MessageType::AddOrder: return "A";
        case MessageType::AddOrderMpid: return "F";
        case MessageType::OrderExecuted: return "E";
        case MessageType::OrderExecutedWithPrice: return "C";
        case MessageType::OrderCancel: return "X";
        case MessageType::OrderDelete: return "D";
        case MessageType::OrderReplace: return "U";
        case MessageType::TradeNonCross: return "P";
        case MessageType::CrossTrade: return "Q";
        case MessageType::BrokenTrade: return "B";
    }
    return "?";
}

const char* to_string(DecodeStatus s) {
    switch (s) {
        case DecodeStatus::Ok: return "Ok";
        case DecodeStatus::Truncated: return "Truncated";
        case DecodeStatus::UnknownType: return "UnknownType";
        case DecodeStatus::PriceOutOfRange: return "PriceOutOfRange";
    }
    return "?";
}

size_t wire_length(MessageType t) {
    switch (t) {
        case MessageType::SystemEvent: return LEN_SYSTEM_EVENT;
        case MessageType::StockDirectory: return LEN_STOCK_DIRECTORY;
        case MessageType::StockTradingAction: return LEN_TRADING_ACTION;
        case MessageType::AddOrder: return LEN_ADD_ORDER;
        case MessageType::AddOrderMpid: return LEN_ADD_ORDER_MPID;
        case MessageType::OrderExecuted: return LEN_ORDER_EXECUTED;
        case MessageType::OrderExecutedWithPrice: return LEN_EXECUTED_PRICE;
        case MessageType::OrderCancel: return LEN_ORDER_CANCEL;
        case MessageType::OrderDelete: return LEN_ORDER_DELETE;
        case MessageType::OrderReplace: return LEN_ORDER_REPLACE;
        case MessageType::TradeNonCross: return LEN_TRADE_NON_CROSS;
        case MessageType::CrossTrade: return LEN_CROSS_TRADE;
        case MessageType::BrokenTrade: return LEN_BROKEN_TRADE;
    }
    return 0;
}

DecodeStatus decode(const uint8_t* data, size_t len, Decoded& out) {
    if (data == nullptr || len == 0) return DecodeStatus::Truncated;
    const char type = static_cast<char>(data[0]);

    switch (type) {
        case 'S': {  // 1.1 System Event Message
            if (len < LEN_SYSTEM_EVENT) return DecodeStatus::Truncated;
            SystemEvent m;
            m.hdr = read_common(data);
            m.event_code = static_cast<char>(data[11]);
            out.type = MessageType::SystemEvent;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 'R': {  // 1.2.1 Stock Directory
            if (len < LEN_STOCK_DIRECTORY) return DecodeStatus::Truncated;
            StockDirectory m;
            m.hdr = read_common(data);
            m.stock = alpha_trimmed(data + 11, 8);
            m.market_category = static_cast<char>(data[19]);
            m.financial_status = static_cast<char>(data[20]);
            m.round_lot_size = rd32(data + 21);
            m.round_lots_only = static_cast<char>(data[25]);
            m.issue_classification = static_cast<char>(data[26]);
            m.issue_sub_type = alpha_trimmed(data + 27, 2);
            m.authenticity = static_cast<char>(data[29]);
            m.short_sale_threshold = static_cast<char>(data[30]);
            m.ipo_flag = static_cast<char>(data[31]);
            m.luld_reference_price_tier = static_cast<char>(data[32]);
            m.etp_flag = static_cast<char>(data[33]);
            m.etp_leverage_factor = rd32(data + 34);
            m.inverse_indicator = static_cast<char>(data[38]);
            out.type = MessageType::StockDirectory;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 'H': {  // 1.2.2 Stock Trading Action
            if (len < LEN_TRADING_ACTION) return DecodeStatus::Truncated;
            StockTradingAction m;
            m.hdr = read_common(data);
            m.stock = alpha_trimmed(data + 11, 8);
            m.trading_state = static_cast<char>(data[19]);
            m.reason = alpha_trimmed(data + 21, 4);
            out.type = MessageType::StockTradingAction;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 'A':  // 1.3.1 Add Order – No MPID Attribution
        case 'F': {  // 1.3.2 Add Order with MPID Attribution
            const bool mpid = (type == 'F');
            const size_t need = mpid ? LEN_ADD_ORDER_MPID : LEN_ADD_ORDER;
            if (len < need) return DecodeStatus::Truncated;
            AddOrder m;
            m.hdr = read_common(data);
            m.order_ref = rd64(data + 11);
            m.side = static_cast<char>(data[19]);
            m.shares = rd32(data + 20);
            m.stock = alpha_trimmed(data + 24, 8);
            m.price = price4_at(data, 32);
            if (m.price > MAX_PRICE4) return DecodeStatus::PriceOutOfRange;
            if (mpid) {
                m.has_attribution = true;
                m.attribution = alpha_trimmed(data + 36, 4);
                out.type = MessageType::AddOrderMpid;
            } else {
                out.type = MessageType::AddOrder;
            }
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 'E': {  // 1.4.1 Order Executed
            if (len < LEN_ORDER_EXECUTED) return DecodeStatus::Truncated;
            OrderExecuted m;
            m.hdr = read_common(data);
            m.order_ref = rd64(data + 11);
            m.executed_shares = rd32(data + 19);
            m.match_number = rd64(data + 23);
            out.type = MessageType::OrderExecuted;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 'C': {  // 1.4.2 Order Executed With Price
            if (len < LEN_EXECUTED_PRICE) return DecodeStatus::Truncated;
            OrderExecuted m;
            m.hdr = read_common(data);
            m.order_ref = rd64(data + 11);
            m.executed_shares = rd32(data + 19);
            m.match_number = rd64(data + 23);
            m.has_price = true;
            m.printable = static_cast<char>(data[31]);
            m.price = price4_at(data, 32);
            if (m.price > MAX_PRICE4) return DecodeStatus::PriceOutOfRange;
            out.type = MessageType::OrderExecutedWithPrice;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 'X': {  // 1.4.3 Order Cancel
            if (len < LEN_ORDER_CANCEL) return DecodeStatus::Truncated;
            OrderCancel m;
            m.hdr = read_common(data);
            m.order_ref = rd64(data + 11);
            m.cancelled_shares = rd32(data + 19);
            out.type = MessageType::OrderCancel;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 'D': {  // 1.4.4 Order Delete
            if (len < LEN_ORDER_DELETE) return DecodeStatus::Truncated;
            OrderDelete m;
            m.hdr = read_common(data);
            m.order_ref = rd64(data + 11);
            out.type = MessageType::OrderDelete;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 'U': {  // 1.4.5 Order Replace
            if (len < LEN_ORDER_REPLACE) return DecodeStatus::Truncated;
            OrderReplace m;
            m.hdr = read_common(data);
            m.original_order_ref = rd64(data + 11);
            m.new_order_ref = rd64(data + 19);
            m.shares = rd32(data + 27);
            m.price = price4_at(data, 31);
            if (m.price > MAX_PRICE4) return DecodeStatus::PriceOutOfRange;
            out.type = MessageType::OrderReplace;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 'P': {  // 1.5.1 Trade Message (Non-Cross)
            if (len < LEN_TRADE_NON_CROSS) return DecodeStatus::Truncated;
            TradeNonCross m;
            m.hdr = read_common(data);
            m.order_ref = rd64(data + 11);
            m.side = static_cast<char>(data[19]);
            m.shares = rd32(data + 20);
            m.stock = alpha_trimmed(data + 24, 8);
            m.price = price4_at(data, 32);
            if (m.price > MAX_PRICE4) return DecodeStatus::PriceOutOfRange;
            m.match_number = rd64(data + 36);
            out.type = MessageType::TradeNonCross;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 'Q': {  // 1.5.2 Cross Trade
            if (len < LEN_CROSS_TRADE) return DecodeStatus::Truncated;
            CrossTrade m;
            m.hdr = read_common(data);
            m.shares = rd64(data + 11);
            m.stock = alpha_trimmed(data + 19, 8);
            m.cross_price = price4_at(data, 27);
            if (m.cross_price > MAX_PRICE4) return DecodeStatus::PriceOutOfRange;
            m.match_number = rd64(data + 31);
            m.cross_type = static_cast<char>(data[39]);
            out.type = MessageType::CrossTrade;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 'B': {  // 1.5.3 Broken Trade / Order Execution
            if (len < LEN_BROKEN_TRADE) return DecodeStatus::Truncated;
            BrokenTrade m;
            m.hdr = read_common(data);
            m.match_number = rd64(data + 11);
            out.type = MessageType::BrokenTrade;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        default:
            return DecodeStatus::UnknownType;
    }
}

}  // namespace itch
