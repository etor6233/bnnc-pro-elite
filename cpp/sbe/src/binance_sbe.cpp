// sbe/binance_sbe.cpp — decoder implementation for the pinned Binance SBE
// schema (stream_1_0.xml, schemaId=1, version=0, littleEndian).
//
// Layout constants verified against the official SBE code generator output
// (cpp/tools/sbe-tool/gen/spot_stream/*.h generated from the SAME pinned
// schema bytes). Schema semantics:
//   - messageHeader: blockLength u16 | templateId u16 | schemaId u16 | version u16
//   - mantissa64 (int64) + exponent8 (int8): decimal = mantissa * 10^exp
//   - varString8: length u8 | UTF-8 bytes
//   - groupSizeEncoding: blockLength u16 | numInGroup u32
//   - groupSize16Encoding: blockLength u16 | numInGroup u16
//   - constant fields (isBestMatch, boolEnum.True) are NOT on the wire.
#include <sbe/binance_sbe.hpp>

#include <cmath>
#include <cstring>

namespace sbe {

namespace {

inline uint16_t rd16(const uint8_t* p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
inline uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
inline uint64_t rd64(const uint8_t* p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

constexpr uint16_t SCHEMA_ID = 1;
constexpr uint16_t SCHEMA_VERSION = 0;

// Root block lengths from the official codegen (sbeBlockLength()).
constexpr size_t BLK_TRADES = 18;
constexpr size_t BLK_BESTBIDASK = 50;
constexpr size_t BLK_SNAPSHOT = 18;
constexpr size_t BLK_DIFF = 26;
// Group entry lengths from the official codegen (Trades::sbeBlockLength=25;
// Bids/Asks::sbeBlockLength=16).
constexpr size_t GRP_TRADE = 25;
constexpr size_t GRP_LEVEL = 16;

inline Decimal make_decimal(int64_t mantissa, int8_t exponent) {
    return Decimal{mantissa, exponent};
}

// varString8 at offset `off`: length byte then bytes. Returns false on
// truncation.
inline bool read_var_string(const uint8_t* data, size_t len, size_t off,
                            std::string& out) {
    if (off >= len) return false;
    const size_t n = data[off];
    if (off + 1 + n > len) return false;
    out.assign(reinterpret_cast<const char*>(data + off + 1), n);
    return true;
}

}  // namespace

double Decimal::to_double() const {
    return static_cast<double>(mantissa) * std::pow(10.0, exponent);
}

std::string Decimal::to_string() const {
    const bool neg = mantissa < 0;
    std::string digits = std::to_string(neg ? -mantissa : mantissa);
    const int exp = exponent;
    std::string result;
    if (exp >= 0) {
        result = digits;
        result.append(static_cast<size_t>(exp), '0');
    } else {
        const int scale = -exp;
        if ((int)digits.size() > scale) {
            digits.insert(digits.size() - (size_t)scale, 1, '.');
            result = std::move(digits);
        } else {
            result = "0.";
            result.append((size_t)(scale - (int)digits.size()), '0');
            result += digits;
        }
    }
    if (neg) result.insert(result.begin(), '-');
    return result;
}

const char* to_string(MessageType t) {
    switch (t) {
        case MessageType::TradesStreamEvent: return "TradesStreamEvent";
        case MessageType::BestBidAskStreamEvent: return "BestBidAskStreamEvent";
        case MessageType::DepthSnapshotStreamEvent: return "DepthSnapshotStreamEvent";
        case MessageType::DepthDiffStreamEvent: return "DepthDiffStreamEvent";
        case MessageType::Unknown: return "Unknown";
    }
    return "?";
}

const char* to_string(DecodeStatus s) {
    switch (s) {
        case DecodeStatus::Ok: return "Ok";
        case DecodeStatus::Truncated: return "Truncated";
        case DecodeStatus::UnknownTemplate: return "UnknownTemplate";
        case DecodeStatus::SchemaMismatch: return "SchemaMismatch";
        case DecodeStatus::InvalidLayout: return "InvalidLayout";
    }
    return "?";
}

size_t known_wire_length(MessageType t) {
    switch (t) {
        case MessageType::TradesStreamEvent:
        case MessageType::BestBidAskStreamEvent:
        case MessageType::DepthSnapshotStreamEvent:
        case MessageType::DepthDiffStreamEvent:
            return 0;  // variable length (groups + var data)
        default:
            return 0;
    }
}

DecodeStatus decode(const uint8_t* data, size_t len, Decoded& out) {
    if (data == nullptr || len < 8) return DecodeStatus::Truncated;
    const uint16_t block_length = rd16(data + 0);
    const uint16_t template_id = rd16(data + 2);
    const uint16_t schema_id = rd16(data + 4);
    const uint16_t version = rd16(data + 6);
    if (schema_id != SCHEMA_ID || version != SCHEMA_VERSION) {
        return DecodeStatus::SchemaMismatch;
    }

    switch (template_id) {
        case 10000: {  // TradesStreamEvent
            if (block_length < BLK_TRADES) return DecodeStatus::InvalidLayout;
            if (len < 8 + BLK_TRADES + 6) return DecodeStatus::Truncated;
            TradesStream m;
            m.event_time_us = (int64_t)rd64(data + 8);
            m.transact_time_us = (int64_t)rd64(data + 16);
            m.price_exponent = (int8_t)data[24];
            m.qty_exponent = (int8_t)data[25];
            // groupSizeEncoding at 8+18=26
            const uint16_t grp_block = rd16(data + 26);
            const uint32_t num = rd32(data + 28);
            if (grp_block < GRP_TRADE) return DecodeStatus::InvalidLayout;
            size_t pos = 8 + BLK_TRADES + 6;  // start of entries
            if (num > (len - pos) / grp_block) return DecodeStatus::Truncated;
            m.trades.reserve(num);
            for (uint32_t i = 0; i < num; ++i) {
                const uint8_t* e = data + pos;
                Trade t;
                t.id = (int64_t)rd64(e + 0);
                t.price = make_decimal((int64_t)rd64(e + 8), m.price_exponent);
                t.qty = make_decimal((int64_t)rd64(e + 16), m.qty_exponent);
                t.is_buyer_maker = e[24];
                t.is_best_match = 1;  // constant per schema (not on wire)
                m.trades.push_back(t);
                pos += grp_block;
            }
            if (!read_var_string(data, len, pos, m.symbol)) {
                return DecodeStatus::Truncated;
            }
            out.type = MessageType::TradesStreamEvent;
            out.template_id = template_id;
            out.schema_id = schema_id;
            out.version = version;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 10001: {  // BestBidAskStreamEvent
            if (block_length < BLK_BESTBIDASK) return DecodeStatus::InvalidLayout;
            if (len < 8 + BLK_BESTBIDASK + 1) return DecodeStatus::Truncated;
            BestBidAsk m;
            m.event_time_us = (int64_t)rd64(data + 8);
            m.book_update_id = (int64_t)rd64(data + 16);
            m.price_exponent = (int8_t)data[24];
            m.qty_exponent = (int8_t)data[25];
            m.bid_price = make_decimal((int64_t)rd64(data + 26), m.price_exponent);
            m.bid_qty = make_decimal((int64_t)rd64(data + 34), m.qty_exponent);
            m.ask_price = make_decimal((int64_t)rd64(data + 42), m.price_exponent);
            m.ask_qty = make_decimal((int64_t)rd64(data + 50), m.qty_exponent);
            if (!read_var_string(data, len, 8 + BLK_BESTBIDASK, m.symbol)) {
                return DecodeStatus::Truncated;
            }
            out.type = MessageType::BestBidAskStreamEvent;
            out.template_id = template_id;
            out.schema_id = schema_id;
            out.version = version;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 10002: {  // DepthSnapshotStreamEvent
            if (block_length < BLK_SNAPSHOT) return DecodeStatus::InvalidLayout;
            if (len < 8 + BLK_SNAPSHOT + 4 + 4 + 1) return DecodeStatus::Truncated;
            DepthSnapshot m;
            m.event_time_us = (int64_t)rd64(data + 8);
            m.book_update_id = (int64_t)rd64(data + 16);
            m.price_exponent = (int8_t)data[24];
            m.qty_exponent = (int8_t)data[25];
            size_t pos = 8 + BLK_SNAPSHOT;
            // bids group (groupSize16Encoding: u16 block, u16 num)
            {
                const uint16_t grp_block = rd16(data + pos);
                const uint16_t num = rd16(data + pos + 2);
                if (grp_block < GRP_LEVEL) return DecodeStatus::InvalidLayout;
                pos += 4;
                if (num > (len - pos) / grp_block) return DecodeStatus::Truncated;
                for (uint16_t i = 0; i < num; ++i) {
                    const uint8_t* e = data + pos;
                    m.bids.push_back(Level{make_decimal((int64_t)rd64(e), m.price_exponent),
                                           make_decimal((int64_t)rd64(e + 8), m.qty_exponent)});
                    pos += grp_block;
                }
            }
            // asks group
            {
                if (pos + 4 > len) return DecodeStatus::Truncated;
                const uint16_t grp_block = rd16(data + pos);
                const uint16_t num = rd16(data + pos + 2);
                if (grp_block < GRP_LEVEL) return DecodeStatus::InvalidLayout;
                pos += 4;
                if (num > (len - pos) / grp_block) return DecodeStatus::Truncated;
                for (uint16_t i = 0; i < num; ++i) {
                    const uint8_t* e = data + pos;
                    m.asks.push_back(Level{make_decimal((int64_t)rd64(e), m.price_exponent),
                                           make_decimal((int64_t)rd64(e + 8), m.qty_exponent)});
                    pos += grp_block;
                }
            }
            if (!read_var_string(data, len, pos, m.symbol)) {
                return DecodeStatus::Truncated;
            }
            out.type = MessageType::DepthSnapshotStreamEvent;
            out.template_id = template_id;
            out.schema_id = schema_id;
            out.version = version;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        case 10003: {  // DepthDiffStreamEvent
            if (block_length < BLK_DIFF) return DecodeStatus::InvalidLayout;
            if (len < 8 + BLK_DIFF + 4 + 4 + 1) return DecodeStatus::Truncated;
            DepthDiff m;
            m.event_time_us = (int64_t)rd64(data + 8);
            m.first_book_update_id = (int64_t)rd64(data + 16);
            m.last_book_update_id = (int64_t)rd64(data + 24);
            m.price_exponent = (int8_t)data[32];
            m.qty_exponent = (int8_t)data[33];
            size_t pos = 8 + BLK_DIFF;
            {
                const uint16_t grp_block = rd16(data + pos);
                const uint16_t num = rd16(data + pos + 2);
                if (grp_block < GRP_LEVEL) return DecodeStatus::InvalidLayout;
                pos += 4;
                if (num > (len - pos) / grp_block) return DecodeStatus::Truncated;
                for (uint16_t i = 0; i < num; ++i) {
                    const uint8_t* e = data + pos;
                    m.bids.push_back(Level{make_decimal((int64_t)rd64(e), m.price_exponent),
                                           make_decimal((int64_t)rd64(e + 8), m.qty_exponent)});
                    pos += grp_block;
                }
            }
            {
                if (pos + 4 > len) return DecodeStatus::Truncated;
                const uint16_t grp_block = rd16(data + pos);
                const uint16_t num = rd16(data + pos + 2);
                if (grp_block < GRP_LEVEL) return DecodeStatus::InvalidLayout;
                pos += 4;
                if (num > (len - pos) / grp_block) return DecodeStatus::Truncated;
                for (uint16_t i = 0; i < num; ++i) {
                    const uint8_t* e = data + pos;
                    m.asks.push_back(Level{make_decimal((int64_t)rd64(e), m.price_exponent),
                                           make_decimal((int64_t)rd64(e + 8), m.qty_exponent)});
                    pos += grp_block;
                }
            }
            if (!read_var_string(data, len, pos, m.symbol)) {
                return DecodeStatus::Truncated;
            }
            out.type = MessageType::DepthDiffStreamEvent;
            out.template_id = template_id;
            out.schema_id = schema_id;
            out.version = version;
            out.payload = m;
            return DecodeStatus::Ok;
        }
        default:
            return DecodeStatus::UnknownTemplate;
    }
}

}  // namespace sbe
