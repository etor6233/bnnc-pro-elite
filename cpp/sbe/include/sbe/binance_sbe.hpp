// sbe/binance_sbe.hpp — hand-written decoder for the PINNED Binance Spot SBE
// schema (PHASE 2).
//
// SPEC SOURCE (nothing invented): the pinned official schema
//   external-review/low-latency-reference/binance-sbe-official/stream_1_0.xml
//   SHA256 6EA328467E144311B1F1EFF38E9FE613829997F041DD02A3B7077885D10A1F7
// (schemaId=1, version=0, byteOrder=littleEndian, package spot_stream) plus
// the captured stream docs sbe-market-data-streams.md (SHA256 3E945F52...):
// timestamps in microseconds; mantissa64/exponent8 decimals; varString8
// UTF-8 symbol; isBestMatch is a CONSTANT field (presence="constant",
// valueRef boolEnum.True) and therefore absent from the wire — the decoder
// supplies the constant value 1 (true) itself.
//
// Wire layout cross-checked against the OFFICIAL SBE code generator output
// (sbe-all-1.35.1.jar -> cpp/tools/sbe-tool/gen/spot_stream/*.h): the test
// suite decodes every golden vector with BOTH this decoder and the official
// generated decoder and requires identical field values.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace sbe {

enum class MessageType : uint16_t {
    Unknown = 0,
    TradesStreamEvent = 10000,
    BestBidAskStreamEvent = 10001,
    DepthSnapshotStreamEvent = 10002,
    DepthDiffStreamEvent = 10003,
};

enum class DecodeStatus : uint8_t {
    Ok = 0,
    Truncated,        // buffer ends inside a required field/group/var-data
    UnknownTemplate,  // templateId not in the pinned schema
    SchemaMismatch,   // schemaId != 1 or version != 0 (pinned schema)
    InvalidLayout,    // blockLength too small for the declared fields
};

const char* to_string(MessageType t);
const char* to_string(DecodeStatus s);

// mantissa64/exponent8 decimal (schema types section). value = mantissa*10^exp.
struct Decimal {
    int64_t mantissa = 0;
    int8_t exponent = 0;

    double to_double() const;
    std::string to_string() const;  // exact decimal rendering
};

struct Trade {
    int64_t id = 0;
    Decimal price;
    Decimal qty;
    uint8_t is_buyer_maker = 0;   // boolEnum: 0/1
    uint8_t is_best_match = 1;    // CONSTANT per schema (not on the wire)
};

struct Level {
    Decimal price;
    Decimal qty;
};

struct TradesStream {
    int64_t event_time_us = 0;
    int64_t transact_time_us = 0;
    int8_t price_exponent = 0;
    int8_t qty_exponent = 0;
    std::vector<Trade> trades;
    std::string symbol;
};

struct BestBidAsk {
    int64_t event_time_us = 0;
    int64_t book_update_id = 0;
    int8_t price_exponent = 0;
    int8_t qty_exponent = 0;
    Decimal bid_price;
    Decimal bid_qty;
    Decimal ask_price;
    Decimal ask_qty;
    std::string symbol;
};

struct DepthSnapshot {
    int64_t event_time_us = 0;
    int64_t book_update_id = 0;
    int8_t price_exponent = 0;
    int8_t qty_exponent = 0;
    std::vector<Level> bids;
    std::vector<Level> asks;
    std::string symbol;
};

struct DepthDiff {
    int64_t event_time_us = 0;
    int64_t first_book_update_id = 0;
    int64_t last_book_update_id = 0;
    int8_t price_exponent = 0;
    int8_t qty_exponent = 0;
    std::vector<Level> bids;
    std::vector<Level> asks;
    std::string symbol;
};

struct Decoded {
    MessageType type = MessageType::Unknown;
    uint16_t template_id = 0;  // message header (schema: messageHeader)
    uint16_t schema_id = 0;
    uint16_t version = 0;
    std::variant<TradesStream, BestBidAsk, DepthSnapshot, DepthDiff> payload;
};

// Decode one SBE message from data[0..len). Never throws, never crashes on
// arbitrary input; returns a typed status and leaves `out` untouched on
// failure.
DecodeStatus decode(const uint8_t* data, size_t len, Decoded& out);

// Expected wire lengths for a known message; 0 for unknown.
size_t known_wire_length(MessageType t);

}  // namespace sbe
