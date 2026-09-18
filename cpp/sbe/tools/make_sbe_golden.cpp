// sbe/tools/make_sbe_golden.cpp — golden SBE vectors produced with the
// OFFICIAL Simple Binary Encoding code generator output.
//
// Pipeline (nothing invented):
//   stream_1_0.xml (pinned, SHA256 6EA328467E144311B1F1EFF38E9FE613829997F041DD02A3B7077885D10A1F7)
//     -> sbe-all-1.35.1.jar (Maven Central, SHA256 456384ED1DB090D018B4DC15BE152D371FA192E96AA4C98D362CC163BD18777E)
//        -Dsbe.target.language=Cpp  ->  cpp/tools/sbe-tool/gen/spot_stream/*.h
//     -> this tool encodes sample events with the generated encoder and writes
//        golden .bin + .expect files.
//
// The hand-written decoder under test (sbe/src/binance_sbe.cpp) must decode
// these bytes to the same field values. Field semantics per
// sbe-market-data-streams.md (captured, SHA256 3E945F52...): timestamps are
// microseconds; mantissa/exponent decimals per the schema mbx:exponent
// attributes.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#include "spot_stream/DepthDiffStreamEvent.h"
#include "spot_stream/DepthSnapshotStreamEvent.h"
#include "spot_stream/BestBidAskStreamEvent.h"
#include "spot_stream/TradesStreamEvent.h"

namespace fs = std::filesystem;

static void write_expect(const fs::path& p, const std::string& content) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << content;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: make_sbe_golden <out-dir>\n");
        return 2;
    }
    fs::path dir = argv[1];
    fs::create_directories(dir);

    char buffer[4096];
    std::memset(buffer, 0, sizeof(buffer));

    // ---------------------------------------------------------------- trades
    {
        spot_stream::TradesStreamEvent tse;
        spot_stream::MessageHeader hdr;
        hdr.wrap(buffer, 0, 0, sizeof(buffer))
            .blockLength(tse.sbeBlockLength())
            .templateId(tse.sbeTemplateId())
            .schemaId(tse.sbeSchemaId())
            .version(tse.sbeSchemaVersion());
        tse.wrapForEncode(buffer, hdr.encodedLength(), sizeof(buffer));
        tse.eventTime(1726700000000000LL)
            .transactTime(1726700000012345LL)
            .priceExponent(-2)
            .qtyExponent(-5);
        auto& trades = tse.tradesCount(2);
        trades.next().id(700000001LL).price(5978655LL).qty(12345LL)
            .isBuyerMaker(spot_stream::BoolEnum::True);
        trades.next().id(700000002LL).price(5978700LL).qty(7000LL)
            .isBuyerMaker(spot_stream::BoolEnum::False);
        tse.putSymbol("BTCUSDT", 7);
        const std::uint64_t len = hdr.encodedLength() + tse.encodedLength();
        fs::path bin = dir / "trades_stream.bin";
        {
            std::ofstream out(bin, std::ios::binary | std::ios::trunc);
            out.write(buffer, (std::streamsize)len);
        }
        write_expect(
            dir / "trades_stream.expect",
            "# spec=stream_1_0.xml TradesStreamEvent id=10000 + "
            "sbe-market-data-streams.md\n"
            "template_id=10000\n"
            "schema_id=1\n"
            "version=0\n"
            "event_time_us=1726700000000000\n"
            "transact_time_us=1726700000012345\n"
            "price_exponent=-2\n"
            "qty_exponent=-5\n"
            "trade_count=2\n"
            "trade0_id=700000001\n"
            "trade0_price_mantissa=5978655\n"
            "trade0_price_decimal=59786.55\n"
            "trade0_qty_mantissa=12345\n"
            "trade0_qty_decimal=0.12345\n"
            "trade0_buyer_maker=1\n"
            "trade0_best_match=1\n"
            "trade1_id=700000002\n"
            "trade1_price_mantissa=5978700\n"
            "trade1_price_decimal=59787.00\n"
            "trade1_qty_mantissa=7000\n"
            "trade1_qty_decimal=0.07000\n"
            "trade1_buyer_maker=0\n"
            "trade1_best_match=1\n"
            "symbol=BTCUSDT\n");
        std::printf("golden %s: %llu bytes\n", bin.filename().string().c_str(),
                    (unsigned long long)len);
    }

    // ------------------------------------------------------- best bid / ask
    {
        std::memset(buffer, 0, sizeof(buffer));
        spot_stream::BestBidAskStreamEvent bba;
        spot_stream::MessageHeader hdr;
        hdr.wrap(buffer, 0, 0, sizeof(buffer))
            .blockLength(bba.sbeBlockLength())
            .templateId(bba.sbeTemplateId())
            .schemaId(bba.sbeSchemaId())
            .version(bba.sbeSchemaVersion());
        bba.wrapForEncode(buffer, hdr.encodedLength(), sizeof(buffer));
        bba.eventTime(1726700000100000LL)
            .bookUpdateId(900000001LL)
            .priceExponent(-2)
            .qtyExponent(-5)
            .bidPrice(5978655LL)
            .bidQty(150000LL)
            .askPrice(5978700LL)
            .askQty(80000LL);
        bba.putSymbol("ETHUSDT", 7);
        const std::uint64_t len = hdr.encodedLength() + bba.encodedLength();
        fs::path bin = dir / "best_bid_ask.bin";
        {
            std::ofstream out(bin, std::ios::binary | std::ios::trunc);
            out.write(buffer, (std::streamsize)len);
        }
        write_expect(
            dir / "best_bid_ask.expect",
            "# spec=stream_1_0.xml BestBidAskStreamEvent id=10001\n"
            "template_id=10001\n"
            "schema_id=1\n"
            "version=0\n"
            "event_time_us=1726700000100000\n"
            "book_update_id=900000001\n"
            "price_exponent=-2\n"
            "qty_exponent=-5\n"
            "bid_price_mantissa=5978655\n"
            "bid_price_decimal=59786.55\n"
            "bid_qty_mantissa=150000\n"
            "bid_qty_decimal=1.50000\n"
            "ask_price_mantissa=5978700\n"
            "ask_price_decimal=59787.00\n"
            "ask_qty_mantissa=80000\n"
            "ask_qty_decimal=0.80000\n"
            "symbol=ETHUSDT\n");
        std::printf("golden %s: %llu bytes\n", bin.filename().string().c_str(),
                    (unsigned long long)len);
    }

    // ------------------------------------------------------ depth snapshot
    {
        std::memset(buffer, 0, sizeof(buffer));
        spot_stream::DepthSnapshotStreamEvent dss;
        spot_stream::MessageHeader hdr;
        hdr.wrap(buffer, 0, 0, sizeof(buffer))
            .blockLength(dss.sbeBlockLength())
            .templateId(dss.sbeTemplateId())
            .schemaId(dss.sbeSchemaId())
            .version(dss.sbeSchemaVersion());
        dss.wrapForEncode(buffer, hdr.encodedLength(), sizeof(buffer));
        dss.eventTime(1726700000200000LL)
            .bookUpdateId(900000100LL)
            .priceExponent(-2)
            .qtyExponent(-5);
        {
            auto& bids = dss.bidsCount(2);
            bids.next().price(5978655LL).qty(150000LL);
            bids.next().price(5978600LL).qty(220000LL);
        }
        {
            auto& asks = dss.asksCount(2);
            asks.next().price(5978700LL).qty(80000LL);
            asks.next().price(5978800LL).qty(60000LL);
        }
        dss.putSymbol("BTCUSDT", 7);
        const std::uint64_t len = hdr.encodedLength() + dss.encodedLength();
        fs::path bin = dir / "depth_snapshot.bin";
        {
            std::ofstream out(bin, std::ios::binary | std::ios::trunc);
            out.write(buffer, (std::streamsize)len);
        }
        write_expect(
            dir / "depth_snapshot.expect",
            "# spec=stream_1_0.xml DepthSnapshotStreamEvent id=10002\n"
            "template_id=10002\n"
            "schema_id=1\n"
            "version=0\n"
            "event_time_us=1726700000200000\n"
            "book_update_id=900000100\n"
            "price_exponent=-2\n"
            "qty_exponent=-5\n"
            "bid_count=2\n"
            "bid0_price_mantissa=5978655\n"
            "bid0_qty_mantissa=150000\n"
            "bid1_price_mantissa=5978600\n"
            "bid1_qty_mantissa=220000\n"
            "ask_count=2\n"
            "ask0_price_mantissa=5978700\n"
            "ask0_qty_mantissa=80000\n"
            "ask1_price_mantissa=5978800\n"
            "ask1_qty_mantissa=60000\n"
            "symbol=BTCUSDT\n");
        std::printf("golden %s: %llu bytes\n", bin.filename().string().c_str(),
                    (unsigned long long)len);
    }

    // ---------------------------------------------------------- depth diff
    {
        std::memset(buffer, 0, sizeof(buffer));
        spot_stream::DepthDiffStreamEvent ddf;
        spot_stream::MessageHeader hdr;
        hdr.wrap(buffer, 0, 0, sizeof(buffer))
            .blockLength(ddf.sbeBlockLength())
            .templateId(ddf.sbeTemplateId())
            .schemaId(ddf.sbeSchemaId())
            .version(ddf.sbeSchemaVersion());
        ddf.wrapForEncode(buffer, hdr.encodedLength(), sizeof(buffer));
        ddf.eventTime(1726700000300000LL)
            .firstBookUpdateId(900000101LL)
            .lastBookUpdateId(900000101LL)
            .priceExponent(-2)
            .qtyExponent(-5);
        {
            auto& bids = ddf.bidsCount(1);
            bids.next().price(5978655LL).qty(0LL);  // qty 0 removes the level
        }
        {
            auto& asks = ddf.asksCount(1);
            asks.next().price(5978900LL).qty(5000LL);
        }
        ddf.putSymbol("BTCUSDT", 7);
        const std::uint64_t len = hdr.encodedLength() + ddf.encodedLength();
        fs::path bin = dir / "depth_diff.bin";
        {
            std::ofstream out(bin, std::ios::binary | std::ios::trunc);
            out.write(buffer, (std::streamsize)len);
        }
        write_expect(
            dir / "depth_diff.expect",
            "# spec=stream_1_0.xml DepthDiffStreamEvent id=10003\n"
            "template_id=10003\n"
            "schema_id=1\n"
            "version=0\n"
            "event_time_us=1726700000300000\n"
            "first_update_id=900000101\n"
            "last_update_id=900000101\n"
            "price_exponent=-2\n"
            "qty_exponent=-5\n"
            "bid_count=1\n"
            "bid0_price_mantissa=5978655\n"
            "bid0_qty_mantissa=0\n"
            "ask_count=1\n"
            "ask0_price_mantissa=5978900\n"
            "ask0_qty_mantissa=5000\n"
            "symbol=BTCUSDT\n");
        std::printf("golden %s: %llu bytes\n", bin.filename().string().c_str(),
                    (unsigned long long)len);
    }

    return 0;
}
