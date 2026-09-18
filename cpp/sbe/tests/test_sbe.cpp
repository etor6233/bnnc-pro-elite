// sbe/tests/test_sbe.cpp — golden-vector + cross-check + malformed suite for
// the hand-written Binance SBE decoder (FASE 2).
//
// Golden vectors are produced with the OFFICIAL SBE code generator's C++
// encoder (same pinned schema); every golden vector is decoded BOTH by the
// hand-written decoder and by the official generated decoder, and the field
// values must agree exactly.
#include <afx/test_framework.hpp>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <sbe/binance_sbe.hpp>

#include "spot_stream/BestBidAskStreamEvent.h"
#include "spot_stream/DepthDiffStreamEvent.h"
#include "spot_stream/DepthSnapshotStreamEvent.h"
#include "spot_stream/TradesStreamEvent.h"

namespace fs = std::filesystem;

static std::string g_root;

static std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static std::vector<uint8_t> read_bin(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

static std::map<std::string, std::string> parse_expect(const std::string& text) {
    std::map<std::string, std::string> out;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        out[line.substr(0, eq)] = line.substr(eq + 1);
    }
    return out;
}

// Render MY decoder output as a field map mirroring the .expect keys.
static std::map<std::string, std::string> to_field_map(const sbe::Decoded& d) {
    std::map<std::string, std::string> m;
    m["template_id"] = std::to_string(d.template_id);
    m["schema_id"] = std::to_string(d.schema_id);
    m["version"] = std::to_string(d.version);
    std::visit(
        [&](const auto& p) {
            using T = std::decay_t<decltype(p)>;
            if constexpr (std::is_same_v<T, sbe::TradesStream>) {
                m["event_time_us"] = std::to_string(p.event_time_us);
                m["transact_time_us"] = std::to_string(p.transact_time_us);
                m["price_exponent"] = std::to_string(p.price_exponent);
                m["qty_exponent"] = std::to_string(p.qty_exponent);
                m["trade_count"] = std::to_string(p.trades.size());
                for (size_t i = 0; i < p.trades.size(); ++i) {
                    const auto& t = p.trades[i];
                    const std::string pre = "trade" + std::to_string(i) + "_";
                    m[pre + "id"] = std::to_string(t.id);
                    m[pre + "price_mantissa"] = std::to_string(t.price.mantissa);
                    m[pre + "price_decimal"] = t.price.to_string();
                    m[pre + "qty_mantissa"] = std::to_string(t.qty.mantissa);
                    m[pre + "qty_decimal"] = t.qty.to_string();
                    m[pre + "buyer_maker"] = std::to_string(t.is_buyer_maker);
                    m[pre + "best_match"] = std::to_string(t.is_best_match);
                }
                m["symbol"] = p.symbol;
            } else if constexpr (std::is_same_v<T, sbe::BestBidAsk>) {
                m["event_time_us"] = std::to_string(p.event_time_us);
                m["book_update_id"] = std::to_string(p.book_update_id);
                m["price_exponent"] = std::to_string(p.price_exponent);
                m["qty_exponent"] = std::to_string(p.qty_exponent);
                m["bid_price_mantissa"] = std::to_string(p.bid_price.mantissa);
                m["bid_price_decimal"] = p.bid_price.to_string();
                m["bid_qty_mantissa"] = std::to_string(p.bid_qty.mantissa);
                m["bid_qty_decimal"] = p.bid_qty.to_string();
                m["ask_price_mantissa"] = std::to_string(p.ask_price.mantissa);
                m["ask_price_decimal"] = p.ask_price.to_string();
                m["ask_qty_mantissa"] = std::to_string(p.ask_qty.mantissa);
                m["ask_qty_decimal"] = p.ask_qty.to_string();
                m["symbol"] = p.symbol;
            } else if constexpr (std::is_same_v<T, sbe::DepthSnapshot>) {
                m["event_time_us"] = std::to_string(p.event_time_us);
                m["book_update_id"] = std::to_string(p.book_update_id);
                m["price_exponent"] = std::to_string(p.price_exponent);
                m["qty_exponent"] = std::to_string(p.qty_exponent);
                m["bid_count"] = std::to_string(p.bids.size());
                for (size_t i = 0; i < p.bids.size(); ++i) {
                    m["bid" + std::to_string(i) + "_price_mantissa"] =
                        std::to_string(p.bids[i].price.mantissa);
                    m["bid" + std::to_string(i) + "_qty_mantissa"] =
                        std::to_string(p.bids[i].qty.mantissa);
                }
                m["ask_count"] = std::to_string(p.asks.size());
                for (size_t i = 0; i < p.asks.size(); ++i) {
                    m["ask" + std::to_string(i) + "_price_mantissa"] =
                        std::to_string(p.asks[i].price.mantissa);
                    m["ask" + std::to_string(i) + "_qty_mantissa"] =
                        std::to_string(p.asks[i].qty.mantissa);
                }
                m["symbol"] = p.symbol;
            } else if constexpr (std::is_same_v<T, sbe::DepthDiff>) {
                m["event_time_us"] = std::to_string(p.event_time_us);
                m["first_update_id"] = std::to_string(p.first_book_update_id);
                m["last_update_id"] = std::to_string(p.last_book_update_id);
                m["price_exponent"] = std::to_string(p.price_exponent);
                m["qty_exponent"] = std::to_string(p.qty_exponent);
                m["bid_count"] = std::to_string(p.bids.size());
                for (size_t i = 0; i < p.bids.size(); ++i) {
                    m["bid" + std::to_string(i) + "_price_mantissa"] =
                        std::to_string(p.bids[i].price.mantissa);
                    m["bid" + std::to_string(i) + "_qty_mantissa"] =
                        std::to_string(p.bids[i].qty.mantissa);
                }
                m["ask_count"] = std::to_string(p.asks.size());
                for (size_t i = 0; i < p.asks.size(); ++i) {
                    m["ask" + std::to_string(i) + "_price_mantissa"] =
                        std::to_string(p.asks[i].price.mantissa);
                    m["ask" + std::to_string(i) + "_qty_mantissa"] =
                        std::to_string(p.asks[i].qty.mantissa);
                }
                m["symbol"] = p.symbol;
            }
        },
        d.payload);
    return m;
}

// Render the OFFICIAL generated decoder's output for the same buffer into a
// field map, so both decoders can be compared field by field.
static std::map<std::string, std::string> official_field_map(
    const std::vector<uint8_t>& bytes, uint16_t tpl) {
    std::map<std::string, std::string> m;
    char* buf = const_cast<char*>(reinterpret_cast<const char*>(bytes.data()));
    const std::uint64_t len = bytes.size();
    spot_stream::MessageHeader hdr;
    hdr.wrap(buf, 0, 0, len);
    m["template_id"] = std::to_string(hdr.templateId());
    m["schema_id"] = std::to_string(hdr.schemaId());
    m["version"] = std::to_string(hdr.version());
    switch (tpl) {
        case 10000: {
            spot_stream::TradesStreamEvent m_;
            m_.wrapForDecode(buf, hdr.encodedLength(), hdr.blockLength(),
                             hdr.version(), len);
            m["event_time_us"] = std::to_string(m_.eventTime());
            m["transact_time_us"] = std::to_string(m_.transactTime());
            m["price_exponent"] = std::to_string(m_.priceExponent());
            m["qty_exponent"] = std::to_string(m_.qtyExponent());
            auto& trades = m_.trades();
            m["trade_count"] = std::to_string(trades.count());
            size_t i = 0;
            while (trades.hasNext()) {
                trades.next();
                const std::string pre = "trade" + std::to_string(i) + "_";
                m[pre + "id"] = std::to_string(trades.id());
                m[pre + "price_mantissa"] = std::to_string(trades.price());
                m[pre + "qty_mantissa"] = std::to_string(trades.qty());
                m[pre + "buyer_maker"] =
                    std::to_string((int)trades.isBuyerMaker());
                m[pre + "best_match"] = "1";
                ++i;
            }
            m["symbol"] = m_.getSymbolAsString();
            break;
        }
        case 10001: {
            spot_stream::BestBidAskStreamEvent m_;
            m_.wrapForDecode(buf, hdr.encodedLength(), hdr.blockLength(),
                             hdr.version(), len);
            m["event_time_us"] = std::to_string(m_.eventTime());
            m["book_update_id"] = std::to_string(m_.bookUpdateId());
            m["price_exponent"] = std::to_string(m_.priceExponent());
            m["qty_exponent"] = std::to_string(m_.qtyExponent());
            m["bid_price_mantissa"] = std::to_string(m_.bidPrice());
            m["bid_qty_mantissa"] = std::to_string(m_.bidQty());
            m["ask_price_mantissa"] = std::to_string(m_.askPrice());
            m["ask_qty_mantissa"] = std::to_string(m_.askQty());
            m["symbol"] = m_.getSymbolAsString();
            break;
        }
        case 10002: {
            spot_stream::DepthSnapshotStreamEvent m_;
            m_.wrapForDecode(buf, hdr.encodedLength(), hdr.blockLength(),
                             hdr.version(), len);
            m["event_time_us"] = std::to_string(m_.eventTime());
            m["book_update_id"] = std::to_string(m_.bookUpdateId());
            m["price_exponent"] = std::to_string(m_.priceExponent());
            m["qty_exponent"] = std::to_string(m_.qtyExponent());
            {
                auto& bids = m_.bids();
                m["bid_count"] = std::to_string(bids.count());
                size_t i = 0;
                while (bids.hasNext()) {
                    bids.next();
                    m["bid" + std::to_string(i) + "_price_mantissa"] =
                        std::to_string(bids.price());
                    m["bid" + std::to_string(i) + "_qty_mantissa"] =
                        std::to_string(bids.qty());
                    ++i;
                }
            }
            {
                auto& asks = m_.asks();
                m["ask_count"] = std::to_string(asks.count());
                size_t i = 0;
                while (asks.hasNext()) {
                    asks.next();
                    m["ask" + std::to_string(i) + "_price_mantissa"] =
                        std::to_string(asks.price());
                    m["ask" + std::to_string(i) + "_qty_mantissa"] =
                        std::to_string(asks.qty());
                    ++i;
                }
            }
            m["symbol"] = m_.getSymbolAsString();
            break;
        }
        case 10003: {
            spot_stream::DepthDiffStreamEvent m_;
            m_.wrapForDecode(buf, hdr.encodedLength(), hdr.blockLength(),
                             hdr.version(), len);
            m["event_time_us"] = std::to_string(m_.eventTime());
            m["first_update_id"] = std::to_string(m_.firstBookUpdateId());
            m["last_update_id"] = std::to_string(m_.lastBookUpdateId());
            m["price_exponent"] = std::to_string(m_.priceExponent());
            m["qty_exponent"] = std::to_string(m_.qtyExponent());
            {
                auto& bids = m_.bids();
                m["bid_count"] = std::to_string(bids.count());
                size_t i = 0;
                while (bids.hasNext()) {
                    bids.next();
                    m["bid" + std::to_string(i) + "_price_mantissa"] =
                        std::to_string(bids.price());
                    m["bid" + std::to_string(i) + "_qty_mantissa"] =
                        std::to_string(bids.qty());
                    ++i;
                }
            }
            {
                auto& asks = m_.asks();
                m["ask_count"] = std::to_string(asks.count());
                size_t i = 0;
                while (asks.hasNext()) {
                    asks.next();
                    m["ask" + std::to_string(i) + "_price_mantissa"] =
                        std::to_string(asks.price());
                    m["ask" + std::to_string(i) + "_qty_mantissa"] =
                        std::to_string(asks.qty());
                    ++i;
                }
            }
            m["symbol"] = m_.getSymbolAsString();
            break;
        }
        default:
            break;
    }
    return m;
}

// Every golden vector decodes Ok with MY decoder, every field matches the
// official-encoder-generated .expect, and the OFFICIAL generated decoder
// agrees field by field.
AFX_TEST(golden_vectors_decode_and_match_official) {
    fs::path dir = fs::path(g_root) / "sbe" / "golden";
    int checked = 0;
    for (const auto& e : fs::directory_iterator(dir)) {
        if (e.path().extension() != ".bin") continue;
        fs::path expect_path = e.path();
        expect_path.replace_extension(".expect");
        auto bytes = read_bin(e.path());
        auto expect = parse_expect(read_file(expect_path));

        sbe::Decoded out;
        sbe::DecodeStatus st = sbe::decode(bytes.data(), bytes.size(), out);
        if (st != sbe::DecodeStatus::Ok) {
            std::string msg = e.path().filename().string() + ": " +
                              sbe::to_string(st);
            AFX_EXPECT(st == sbe::DecodeStatus::Ok);
            (void)msg;
            continue;
        }

        const uint16_t tpl = (uint16_t)std::stoi(expect["template_id"]);
        auto mine = to_field_map(out);
        for (const auto& [k, v] : expect) {
            if (k.empty() || k[0] == '#') continue;
            if (mine.find(k) == mine.end() || mine[k] != v) {
                std::string msg = e.path().filename().string() + " field " + k +
                                  ": got " + (mine.count(k) ? mine[k] : "<missing>") +
                                  " want " + v;
                AFX_EXPECT_STREQ(mine.count(k) ? mine[k] : std::string("<missing>"), v);
                (void)msg;
            }
        }

        // Official generated decoder must agree field by field.
        auto official = official_field_map(bytes, tpl);
        for (const auto& [k, v] : official) {
            if (mine.find(k) == mine.end() || mine[k] != v) {
                std::string msg = e.path().filename().string() + " cross-check " +
                                  k + ": mine=" +
                                  (mine.count(k) ? mine[k] : "<missing>") +
                                  " official=" + v;
                AFX_EXPECT_STREQ(mine.count(k) ? mine[k] : std::string("<missing>"), v);
                (void)msg;
            }
        }
        ++checked;
    }
    AFX_EXPECT_EQ(checked, 4);
}

// Every malformed vector is rejected with its exact typed status; no crash.
AFX_TEST(malformed_corpus_rejected_without_crash) {
    fs::path dir = fs::path(g_root) / "sbe" / "malformed";
    int checked = 0;
    for (const auto& e : fs::directory_iterator(dir)) {
        if (e.path().extension() != ".bin") continue;
        fs::path expect_path = e.path();
        expect_path.replace_extension(".expect");
        auto expect = parse_expect(read_file(expect_path));
        auto bytes = read_bin(e.path());

        sbe::Decoded out;
        sbe::DecodeStatus st = sbe::decode(bytes.data(), bytes.size(), out);
        std::string got = sbe::to_string(st);
        if (got != expect["status"]) {
            std::string msg = e.path().filename().string() + ": want " +
                              expect["status"] + " got " + got;
            AFX_EXPECT_STREQ(got, expect["status"]);
            (void)msg;
        }
        ++checked;
    }
    AFX_EXPECT(checked >= 10);
}

// Robustness: random mutations of a valid golden message never crash.
AFX_TEST(random_mutations_never_crash) {
    fs::path dir = fs::path(g_root) / "sbe" / "golden";
    auto base = read_bin(dir / "trades_stream.bin");
    uint32_t state = 0xDEADBEEFu;
    auto next = [&state]() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    };
    for (int i = 0; i < 100000; ++i) {
        auto buf = base;
        buf[next() % buf.size()] ^= (uint8_t)(1u << (next() % 8));
        sbe::Decoded out;
        (void)sbe::decode(buf.data(), buf.size(), out);
    }
}

// The pinned schema's only constant field: isBestMatch is always True (1)
// because presence="constant" valueRef="boolEnum.True".
AFX_TEST(constant_field_is_best_match) {
    fs::path dir = fs::path(g_root) / "sbe" / "golden";
    auto bytes = read_bin(dir / "trades_stream.bin");
    sbe::Decoded out;
    AFX_EXPECT(sbe::decode(bytes.data(), bytes.size(), out) == sbe::DecodeStatus::Ok);
    const auto* t = std::get_if<sbe::TradesStream>(&out.payload);
    AFX_EXPECT(t != nullptr);
    if (!t) return;
    for (const auto& tr : t->trades) {
        AFX_EXPECT_EQ(tr.is_best_match, 1u);
    }
}

int main(int argc, char** argv) {
    g_root = (argc > 1) ? argv[1] : ".";
    return afx::run_all(argc, argv);
}
