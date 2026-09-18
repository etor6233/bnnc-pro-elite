// ouch/tests/test_ouch.cpp — golden-vector and session-semantics suite for
// the OUCH 5.0 module. Expected outcomes follow the captured spec rules
// (sections cited per test).
#include <afx/test_framework.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <ouch/ouch_codec.hpp>

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

static std::string ch(char c) { return std::string(1, c); }

// Golden decode: every inbound/outbound vector decodes Ok and every field
// matches the spec-derived expectation.
AFX_TEST(golden_vectors_decode_exactly) {
    fs::path dir = fs::path(g_root) / "ouch" / "golden";
    int checked = 0;
    for (const auto& e : fs::directory_iterator(dir)) {
        if (e.path().extension() != ".bin") continue;
        fs::path expect_path = e.path();
        expect_path.replace_extension(".expect");
        auto bytes = read_bin(e.path());
        auto expect = parse_expect(read_file(expect_path));
        const std::string fname = e.path().stem().string();
        const bool is_inbound = fname.rfind("inbound_", 0) == 0;

        std::map<std::string, std::string> got;
        if (is_inbound) {
            ouch::Inbound in;
            AFX_EXPECT(ouch::decode_inbound(bytes.data(), bytes.size(), in) ==
                       ouch::DecodeStatus::Ok);
            if (in.type == ouch::InboundType::Enter) {
                const auto& m = in.enter;
                got["type"] = "O";
                got["user_ref_num"] = std::to_string(m.user_ref_num);
                got["side"] = ch(m.side);
                got["quantity"] = std::to_string(m.quantity);
                got["symbol"] = m.symbol;
                got["price"] = std::to_string(m.price);
                got["time_in_force"] = ch(m.time_in_force);
                got["display"] = ch(m.display);
                got["capacity"] = ch(m.capacity);
                got["intermkt_sweep"] = ch(m.intermkt_sweep);
                got["cross_type"] = ch(m.cross_type);
                got["cl_ord_id"] = m.cl_ord_id;
                got["appendage_len"] = std::to_string(m.appendage_len);
            } else if (in.type == ouch::InboundType::Replace) {
                const auto& m = in.replace;
                got["type"] = "U";
                got["orig_user_ref_num"] = std::to_string(m.orig_user_ref_num);
                got["user_ref_num"] = std::to_string(m.user_ref_num);
                got["quantity"] = std::to_string(m.quantity);
                got["price"] = std::to_string(m.price);
                got["time_in_force"] = ch(m.time_in_force);
                got["display"] = ch(m.display);
                got["intermkt_sweep"] = ch(m.intermkt_sweep);
                got["cl_ord_id"] = m.cl_ord_id;
                got["appendage_len"] = std::to_string(m.appendage_len);
            } else {
                const auto& m = in.cancel;
                got["type"] = "X";
                got["user_ref_num"] = std::to_string(m.user_ref_num);
                got["quantity"] = std::to_string(m.quantity);
                got["appendage_len"] = std::to_string(m.appendage_len);
            }
        } else {
            ouch::Outbound ob;
            AFX_EXPECT(ouch::decode_outbound(bytes.data(), bytes.size(), ob) ==
                       ouch::DecodeStatus::Ok);
            switch (ob.type) {
                case ouch::OutboundType::Accepted: {
                    const auto& m = ob.accepted;
                    got["type"] = "A";
                    got["timestamp_ns"] = std::to_string(m.timestamp_ns);
                    got["user_ref_num"] = std::to_string(m.user_ref_num);
                    got["side"] = ch(m.side);
                    got["quantity"] = std::to_string(m.quantity);
                    got["symbol"] = m.symbol;
                    got["price"] = std::to_string(m.price);
                    got["time_in_force"] = ch(m.time_in_force);
                    got["display"] = ch(m.display);
                    got["order_ref_num"] = std::to_string(m.order_ref_num);
                    got["capacity"] = ch(m.capacity);
                    got["intermkt_sweep"] = ch(m.intermkt_sweep);
                    got["cross_type"] = ch(m.cross_type);
                    got["order_state"] = ch(m.order_state);
                    got["cl_ord_id"] = m.cl_ord_id;
                    got["appendage_len"] = std::to_string(m.appendage_len);
                    break;
                }
                case ouch::OutboundType::Replaced: {
                    const auto& m = ob.replaced;
                    got["type"] = "U";
                    got["timestamp_ns"] = std::to_string(m.timestamp_ns);
                    got["orig_user_ref"] = std::to_string(m.orig_user_ref);
                    got["user_ref_num"] = std::to_string(m.user_ref_num);
                    got["side"] = ch(m.side);
                    got["quantity"] = std::to_string(m.quantity);
                    got["symbol"] = m.symbol;
                    got["price"] = std::to_string(m.price);
                    got["time_in_force"] = ch(m.time_in_force);
                    got["display"] = ch(m.display);
                    got["order_ref_num"] = std::to_string(m.order_ref_num);
                    got["capacity"] = ch(m.capacity);
                    got["intermkt_sweep"] = ch(m.intermkt_sweep);
                    got["cross_type"] = ch(m.cross_type);
                    got["order_state"] = ch(m.order_state);
                    got["cl_ord_id"] = m.cl_ord_id;
                    got["appendage_len"] = std::to_string(m.appendage_len);
                    break;
                }
                case ouch::OutboundType::Canceled: {
                    const auto& m = ob.canceled;
                    got["type"] = "C";
                    got["timestamp_ns"] = std::to_string(m.timestamp_ns);
                    got["user_ref_num"] = std::to_string(m.user_ref_num);
                    got["quantity"] = std::to_string(m.quantity);
                    got["reason"] = ch(m.reason);
                    got["appendage_len"] = std::to_string(m.appendage_len);
                    break;
                }
                case ouch::OutboundType::Executed: {
                    const auto& m = ob.executed;
                    got["type"] = "E";
                    got["timestamp_ns"] = std::to_string(m.timestamp_ns);
                    got["user_ref_num"] = std::to_string(m.user_ref_num);
                    got["quantity"] = std::to_string(m.quantity);
                    got["price"] = std::to_string(m.price);
                    got["liquidity_flag"] = ch(m.liquidity_flag);
                    got["match_number"] = std::to_string(m.match_number);
                    got["appendage_len"] = std::to_string(m.appendage_len);
                    break;
                }
                case ouch::OutboundType::Rejected: {
                    const auto& m = ob.rejected;
                    got["type"] = "J";
                    got["timestamp_ns"] = std::to_string(m.timestamp_ns);
                    got["user_ref_num"] = std::to_string(m.user_ref_num);
                    got["reason"] = std::to_string(m.reason);
                    got["cl_ord_id"] = m.cl_ord_id;
                    got["appendage_len"] = std::to_string(m.appendage_len);
                    break;
                }
            }
        }

        for (const auto& [k, v] : expect) {
            if (k.empty() || k[0] == '#') continue;
            if (got.find(k) == got.end()) {
                AFX_EXPECT_STREQ(std::string("<missing> ") + k, std::string("present"));
                continue;
            }
            if (got[k] != v) {
                AFX_EXPECT_STREQ(got[k], v);
            }
        }
        ++checked;
    }
    AFX_EXPECT_EQ(checked, 8);
}

static ouch::EnterOrder mk_enter(uint32_t ref, uint32_t qty, uint64_t price) {
    ouch::EnterOrder m{};
    m.user_ref_num = ref;
    m.side = 'B';
    m.quantity = qty;
    m.symbol = "NVDA";
    m.price = price;
    m.time_in_force = '0';
    m.display = 'Y';
    m.capacity = 'A';
    m.intermkt_sweep = 'N';
    m.cross_type = 'N';
    m.cl_ord_id = "c1";
    return m;
}

static ouch::ReplaceOrder mk_replace(uint32_t orig, uint32_t newr, uint32_t qty,
                                     uint64_t price) {
    ouch::ReplaceOrder m{};
    m.orig_user_ref_num = orig;
    m.user_ref_num = newr;
    m.quantity = qty;
    m.price = price;
    m.time_in_force = '0';
    m.display = 'Y';
    m.intermkt_sweep = 'N';
    m.cl_ord_id = "c2";
    return m;
}

static ouch::CancelOrder mk_cancel(uint32_t ref, uint32_t qty) {
    ouch::CancelOrder m{};
    m.user_ref_num = ref;
    m.quantity = qty;
    return m;
}

// Spec 1.2: UserRefNum must be unique and strictly increasing; requests with
// UserRefNums lower than the last one processed are ignored as
// retransmissions.
AFX_TEST(userref_strictly_increasing_duplicates_ignored) {
    ouch::OrderEntrySession s;
    AFX_EXPECT(s.on_enter(mk_enter(1, 500, 9'505'000)) == ouch::EnterOutcome::Accepted);
    // exact re-send (retransmission)
    AFX_EXPECT(s.on_enter(mk_enter(1, 500, 9'505'000)) ==
               ouch::EnterOutcome::DuplicateIgnored);
    // lower ref (stale retransmission)
    AFX_EXPECT(s.on_enter(mk_enter(2, 100, 9'505'000)) == ouch::EnterOutcome::Accepted);
    AFX_EXPECT(s.on_enter(mk_enter(1, 100, 9'505'000)) ==
               ouch::EnterOutcome::DuplicateIgnored);
    AFX_EXPECT_EQ(s.last_processed_ref(), 2u);
}

// Spec 2.1: quantity must be greater than zero and less than 1,000,000.
AFX_TEST(enter_quantity_bounds) {
    ouch::OrderEntrySession s;
    AFX_EXPECT(s.on_enter(mk_enter(1, 0, 1000)) == ouch::EnterOutcome::Rejected);
    AFX_EXPECT(s.on_enter(mk_enter(2, 1'000'000, 1000)) ==
               ouch::EnterOutcome::Rejected);
    AFX_EXPECT(s.on_enter(mk_enter(3, 999'999, 1000)) ==
               ouch::EnterOutcome::Accepted);
    // spec 3.8: the UserRefNum of a Rejected message cannot be re-used.
    AFX_EXPECT(s.on_enter(mk_enter(1, 500, 1000)) ==
               ouch::EnterOutcome::DuplicateIgnored);
}

// Spec 2.2 outcome 1: orig not live or replacement ref already used ->
// silently ignored, replacement UserRefNum NOT consumed and reusable.
AFX_TEST(replace_outcome_silently_ignored_ref_reusable) {
    ouch::OrderEntrySession s;
    s.on_enter(mk_enter(1, 500, 1000));
    // orig not live
    AFX_EXPECT(s.on_replace(mk_replace(99, 2, 600, 1000)) ==
               ouch::ReplaceOutcome::SilentlyIgnored);
    // replacement ref already used (1 was an enter ref)
    AFX_EXPECT(s.on_replace(mk_replace(1, 1, 600, 1000)) ==
               ouch::ReplaceOutcome::SilentlyIgnored);
    // ref 2 was not consumed: an enter may use it now
    AFX_EXPECT(s.on_enter(mk_enter(2, 600, 1000)) == ouch::EnterOutcome::Accepted);
}

// Spec 2.2 outcome 2: live order but invalid details (new Shares >= 1,000,000)
// -> cancel takes the existing order out of the book; replacement ref not
// consumed.
AFX_TEST(replace_outcome_cancel_takeout) {
    ouch::OrderEntrySession s;
    s.on_enter(mk_enter(1, 500, 1000));
    AFX_EXPECT(s.on_replace(mk_replace(1, 2, 1'000'000, 1000)) ==
               ouch::ReplaceOutcome::CancelTakeOut);
    const auto* o = s.find_order(1);
    AFX_EXPECT(o != nullptr);
    if (o) AFX_EXPECT(!o->live);  // existing order out of the book
    // ref 2 not consumed -> reusable
    AFX_EXPECT(s.on_enter(mk_enter(2, 300, 1000)) == ouch::EnterOutcome::Accepted);
}

// Spec 2.2 outcome 3: live order but cannot be canceled (cross order in the
// late period) -> Rejected; existing order fully intact; replacement ref
// CONSUMED (spec 2.2 + 3.8).
AFX_TEST(replace_outcome_rejected_ref_consumed) {
    ouch::OrderEntrySession s;
    s.on_enter(mk_enter(1, 500, 1000));
    s.set_late_period(true);
    AFX_EXPECT(s.on_replace(mk_replace(1, 2, 600, 1000)) ==
               ouch::ReplaceOutcome::Rejected);
    const auto* o = s.find_order(1);
    AFX_EXPECT(o != nullptr);
    if (o) {
        AFX_EXPECT(o->live);
        AFX_EXPECT_EQ(o->total_liable, 500u);  // intact original instructions
    }
    // ref 2 consumed: an enter with ref 2 is a duplicate now
    AFX_EXPECT(s.on_enter(mk_enter(2, 300, 1000)) ==
               ouch::EnterOutcome::DuplicateIgnored);
}

// Spec 3.3 example: enter 500 -> executed 100 -> replace(500) -> replaced
// exposes 400 (total liable includes previous executions over the chain).
AFX_TEST(replace_chain_liability_spec_33_examples) {
    ouch::OrderEntrySession s;
    s.on_enter(mk_enter(1, 500, 1000));
    ouch::Executed ex{};
    ex.user_ref_num = 1;
    ex.quantity = 100;
    ex.price = 1000;
    ex.match_number = 1;
    s.on_executed(ex);

    // Example A: replace with 500 -> exposed 400.
    AFX_EXPECT(s.on_replace(mk_replace(1, 2, 500, 1000)) ==
               ouch::ReplaceOutcome::Replaced);
    const auto* o = s.find_order(2);
    AFX_EXPECT(o != nullptr);
    if (o) {
        AFX_EXPECT_EQ(o->total_liable, 500u);
        AFX_EXPECT_EQ(o->executed_cumulative, 100u);
        AFX_EXPECT_EQ(o->total_liable - o->executed_cumulative, 400u);
    }

    // Example B: replace(600) after 100 executed -> exposed 500.
    AFX_EXPECT(s.on_replace(mk_replace(2, 3, 600, 1000)) ==
               ouch::ReplaceOutcome::Replaced);
    o = s.find_order(3);
    AFX_EXPECT(o != nullptr);
    if (o) {
        AFX_EXPECT_EQ(o->total_liable, 600u);
        AFX_EXPECT_EQ(o->executed_cumulative, 100u);
        AFX_EXPECT_EQ(o->total_liable - o->executed_cumulative, 500u);
    }
}

// Spec 3.3 second example: execution in flight on the ORIGINAL order arrives
// after the replace -> replaced order exposure reduced by the late execution.
AFX_TEST(execution_in_flight_on_original_ref) {
    ouch::OrderEntrySession s;
    s.on_enter(mk_enter(1, 500, 1000));
    s.on_replace(mk_replace(1, 2, 500, 1000));  // Replaced
    ouch::Executed ex{};
    ex.user_ref_num = 1;  // original ref: execution was in flight
    ex.quantity = 100;
    ex.match_number = 7;
    s.on_executed(ex);
    const auto* o = s.find_order(2);
    AFX_EXPECT(o != nullptr);
    if (o) {
        AFX_EXPECT_EQ(o->executed_cumulative, 100u);
        AFX_EXPECT_EQ(o->total_liable - o->executed_cumulative, 400u);
    }
}

// Spec 2.3: cancel with intended size; zero cancels the entire balance;
// superfluous cancels (unknown ref) are silently ignored.
AFX_TEST(cancel_semantics) {
    ouch::OrderEntrySession s;
    s.on_enter(mk_enter(1, 500, 1000));
    // unknown ref -> superfluous cancel silently ignored
    AFX_EXPECT(s.on_cancel(mk_cancel(99, 0)) == ouch::CancelOutcome::SilentlyIgnored);
    // intended size 300 -> 200 decremented
    AFX_EXPECT(s.on_cancel(mk_cancel(1, 300)) == ouch::CancelOutcome::Canceled);
    const auto* o = s.find_order(1);
    AFX_EXPECT(o != nullptr);
    if (o) {
        AFX_EXPECT_EQ(o->canceled_cumulative, 200u);
        AFX_EXPECT(o->live);
    }
    // zero -> entire remaining balance canceled, order dead
    AFX_EXPECT(s.on_cancel(mk_cancel(1, 0)) == ouch::CancelOutcome::Canceled);
    o = s.find_order(1);
    AFX_EXPECT(o != nullptr);
    if (o) {
        AFX_EXPECT_EQ(o->canceled_cumulative, 500u);
        AFX_EXPECT(!o->live);
    }
    // cancel on dead order -> superfluous
    AFX_EXPECT(s.on_cancel(mk_cancel(1, 0)) == ouch::CancelOutcome::SilentlyIgnored);
}

// Encoder round-trip: the C++ encoder must produce the exact golden bytes for
// the spec-layout vectors (independent construction in Python).
AFX_TEST(encoder_matches_golden_bytes) {
    fs::path dir = fs::path(g_root) / "ouch" / "golden";
    auto golden = read_bin(dir / "inbound_enter.bin");

    ouch::EnterOrder m{};
    m.user_ref_num = 5;
    m.side = 'B';
    m.quantity = 500;
    m.symbol = "NVDA";
    m.price = 9'505'000;
    m.time_in_force = '0';
    m.display = 'Y';
    m.capacity = 'A';
    m.intermkt_sweep = 'N';
    m.cross_type = 'N';
    m.cl_ord_id = "clid-001";
    m.appendage_len = 0;
    std::string enc;
    AFX_EXPECT(ouch::encode_enter(m, enc));
    AFX_EXPECT_EQ(enc.size(), golden.size());
    AFX_EXPECT(enc == std::string(golden.begin(), golden.end()));
}

// Robustness: random mutations of a valid inbound/outbound buffer never crash.
AFX_TEST(random_mutations_never_crash) {
    fs::path dir = fs::path(g_root) / "ouch" / "golden";
    auto base = read_bin(dir / "outbound_accepted.bin");
    uint32_t state = 0x9E3779B9u;
    auto next = [&state]() {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    };
    for (int i = 0; i < 100000; ++i) {
        auto buf = base;
        buf[next() % buf.size()] ^= (uint8_t)(1u << (next() % 8));
        ouch::Outbound ob;
        (void)ouch::decode_outbound(buf.data(), buf.size(), ob);
        ouch::Inbound in;
        (void)ouch::decode_inbound(buf.data(), buf.size(), in);
    }
}

int main(int argc, char** argv) {
    g_root = (argc > 1) ? argv[1] : ".";
    return afx::run_all(argc, argv);
}
