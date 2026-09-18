// fix/tests/test_fix_session.cpp — FASE 4 suite: FIX codec golden vectors,
// malformed rejection, logon/heartbeat, gap -> ResendRequest -> PossDup
// retransmission, SequenceReset-GapFill and sequence persistence.
#include <afx/test_framework.hpp>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <fix/fix_session.hpp>

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

static std::string type_of(const std::vector<uint8_t>& bytes) {
    fix::FixMessage m;
    if (fix::parse(bytes.data(), bytes.size(), m) != fix::ParseStatus::Ok) {
        return "";
    }
    return fix::msg_type(m);
}

// --- codec -------------------------------------------------------------------

AFX_TEST(golden_vectors_parse_exactly) {
    fs::path dir = fs::path(g_root) / "fix" / "golden";
    if (!fs::exists(dir)) {
        AFX_EXPECT(fs::exists(dir));
        return;
    }
    int checked = 0;
    for (const auto& e : fs::directory_iterator(dir)) {
        if (e.path().extension() != ".bin") continue;
        fs::path expect_path = e.path();
        expect_path.replace_extension(".expect");
        auto bytes = read_bin(e.path());
        auto expect = parse_expect(read_file(expect_path));

        fix::FixMessage m;
        AFX_EXPECT(fix::parse(bytes.data(), bytes.size(), m) ==
                   fix::ParseStatus::Ok);
        for (const auto& [k, v] : expect) {
            if (k.empty() || k[0] == '#') continue;
            if (k.rfind("tag", 0) != 0) continue;
            const int tag = std::stoi(k.substr(3));
            if (m.fields.find(tag) == m.fields.end() || m.fields.at(tag) != v) {
                std::string msg = e.path().filename().string() + " tag " +
                                  std::to_string(tag);
                AFX_EXPECT_STREQ(m.fields.count(tag) ? m.fields.at(tag)
                                                     : std::string("<missing>"),
                                 v);
                (void)msg;
            }
        }
        ++checked;
    }
    AFX_EXPECT_EQ(checked, 6);
}

AFX_TEST(malformed_rejected_with_typed_status) {
    fs::path dir = fs::path(g_root) / "fix" / "golden";
    auto base = read_bin(dir / "heartbeat.bin");

    // Bad checksum: corrupt a body byte that does NOT alter BodyLength.
    {
        auto bad = base;
        const std::string s((char*)bad.data(), bad.size());
        const size_t t34 = s.find("34=");
        bad[t34 + 3] = '9';  // seq 2 -> 9: checksum breaks, length intact
        fix::FixMessage m;
        AFX_EXPECT(fix::parse(bad.data(), bad.size(), m) ==
                   fix::ParseStatus::BadChecksum);
    }
    // Bad body length: rewrite the 9= value.
    {
        std::string s((char*)base.data(), base.size());
        const size_t nine = s.find("9=");
        s[nine + 2] = '9';
        s[nine + 3] = '9';
        fix::FixMessage m;
        AFX_EXPECT(fix::parse((const uint8_t*)s.data(), s.size(), m) ==
                   fix::ParseStatus::BadBodyLength);
    }
    // Missing trailing SOH.
    {
        std::string s((char*)base.data(), base.size());
        s.pop_back();
        fix::FixMessage m;
        AFX_EXPECT(fix::parse((const uint8_t*)s.data(), s.size(), m) ==
                   fix::ParseStatus::Malformed);
    }
    // Duplicate tag.
    {
        std::string s((char*)base.data(), base.size());
        const size_t t35 = s.find("35=");
        s.insert(t35, "35=0\x01");
        fix::FixMessage m;
        AFX_EXPECT(fix::parse((const uint8_t*)s.data(), s.size(), m) ==
                   fix::ParseStatus::Malformed);
    }
    // Empty input.
    {
        fix::FixMessage m;
        AFX_EXPECT(fix::parse(nullptr, 0, m) == fix::ParseStatus::Malformed);
    }
}

AFX_TEST(build_then_parse_roundtrip) {
    fix::FixMessage m;
    m.fields[35] = "D";
    m.fields[49] = "CLIENT";
    m.fields[56] = "VENUE";
    m.fields[34] = "1";
    m.fields[11] = "ord-0001";
    m.fields[55] = "BTCUSDT";
    std::string wire;
    fix::build(m, wire);
    fix::FixMessage back;
    AFX_EXPECT(fix::parse((const uint8_t*)wire.data(), wire.size(), back) ==
               fix::ParseStatus::Ok);
    AFX_EXPECT_STREQ(fix::msg_type(back), std::string("D"));
    AFX_EXPECT_STREQ(back.fields.at(11), std::string("ord-0001"));
    AFX_EXPECT_EQ(fix::seq_num(back), 1u);
    // 9 and 10 were computed and validated by parse.
    AFX_EXPECT(back.fields.count(9) == 1);
    AFX_EXPECT(back.fields.count(10) == 1);
}

// --- session layer -------------------------------------------------------------

AFX_TEST(logon_handshake_both_sides) {
    fix::SessionConfig cfg;
    fix::FixSession initiator(cfg);
    fix::FixSession acceptor(cfg);

    std::string logon = initiator.initiate_logon();
    AFX_EXPECT(initiator.state() == fix::SessionState::AwaitingLogon);

    std::vector<std::string> out;
    acceptor.process_inbound(logon, out);
    if (out.size() != 1) {
        AFX_EXPECT_EQ(out.size(), (size_t)1);
        return;
    }
    AFX_EXPECT_STREQ(type_of(std::vector<uint8_t>(out[0].begin(), out[0].end())),
                     std::string("A"));
    AFX_EXPECT(acceptor.state() == fix::SessionState::LoggedOn);

    std::vector<std::string> out2;
    initiator.process_inbound(out[0], out2);
    AFX_EXPECT(initiator.state() == fix::SessionState::LoggedOn);
}

AFX_TEST(heartbeat_and_test_request) {
    fix::SessionConfig cfg;
    fix::FixSession a(cfg);
    fix::FixSession b(cfg);
    std::vector<std::string> out;
    b.process_inbound(a.initiate_logon(), out);
    a.process_inbound(out[0], out);

    // Heartbeat a->b (seq 2).
    std::vector<std::string> hb;
    b.process_inbound(a.create_heartbeat(), hb);
    AFX_EXPECT_EQ(hb.size(), (size_t)0);  // no reply needed

    // TestRequest b->a (echo TestReqID 112).
    fix::FixMessage tr;
    tr.fields[35] = "1";
    tr.fields[112] = "T-77";
    std::string tr_wire;
    fix::build(tr, tr_wire);  // seq will be wrong; fix it via session path
    // Use the session's own message path: craft via heartbeat-like builder is
    // internal; instead send a raw TestRequest with the next expected seq.
    tr.fields[34] = std::to_string(b.persist().next_out);
    std::string wire;
    fix::build(tr, wire);
    std::vector<std::string> resp;
    a.process_inbound(wire, resp);
    if (resp.size() != 1) {
        AFX_EXPECT_EQ(resp.size(), (size_t)1);
        return;
    }
    fix::FixMessage parsed;
    AFX_EXPECT(fix::parse((const uint8_t*)resp[0].data(), resp[0].size(),
                          parsed) == fix::ParseStatus::Ok);
    AFX_EXPECT_STREQ(fix::msg_type(parsed), std::string("0"));
    AFX_EXPECT_STREQ(parsed.fields.at(112), std::string("T-77"));
}

AFX_TEST(gap_detection_resend_request_possdup_retransmission) {
    fix::SessionConfig cfg;
    fix::FixSession a(cfg);
    fix::FixSession b(cfg);
    std::vector<std::string> out;
    b.process_inbound(a.initiate_logon(), out);   // a -> b: logon seq 1
    a.process_inbound(out[0], out);               // b -> a: logon seq 1
    out.clear();

    // a sends application messages seq 2 and 3; b receives 2 but 3 is LOST.
    auto app = [](const std::string& id) {
        fix::FixMessage m;
        m.fields[35] = "D";
        m.fields[11] = id;
        m.fields[55] = "BTCUSDT";
        return m;
    };
    std::vector<std::string> sent;
    {
        // send_application is internal; emulate: build app with seq from a.
        fix::FixMessage m2 = app("o-2");
        m2.fields[34] = "2";
        std::string w2;
        fix::build(m2, w2);
        sent.push_back(w2);

        fix::FixMessage m3 = app("o-3");
        m3.fields[34] = "3";
        std::string w3;
        fix::build(m3, w3);
        sent.push_back(w3);

        fix::FixMessage m4 = app("o-4");
        m4.fields[34] = "4";
        std::string w4;
        fix::build(m4, w4);
        sent.push_back(w4);
    }
    std::vector<std::string> out_b;
    b.process_inbound(sent[0], out_b);   // seq 2 in order
    AFX_EXPECT_EQ(out_b.size(), (size_t)0);
    // seq 3 lost on the wire.
    b.process_inbound(sent[2], out_b);   // seq 4 -> gap [3..3]
    if (out_b.size() != 1) {
        AFX_EXPECT_EQ(out_b.size(), (size_t)1);
        return;
    }
    fix::FixMessage rr;
    AFX_EXPECT(fix::parse((const uint8_t*)out_b[0].data(), out_b[0].size(), rr) ==
               fix::ParseStatus::Ok);
    AFX_EXPECT_STREQ(fix::msg_type(rr), std::string("2"));
    AFX_EXPECT_STREQ(rr.fields.at(7), std::string("3"));
    AFX_EXPECT_STREQ(rr.fields.at(16), std::string("3"));
    AFX_EXPECT_EQ(b.pending_count(), (size_t)1);  // 4 retained until gap closes

    // a receives the ResendRequest and retransmits seq 3 with PossDup=Y
    // preserving the ORIGINAL sequence (§5.5).
    fix::FixMessage dup3 = app("o-3");
    dup3.fields[34] = "3";
    dup3.fields[43] = "Y";
    std::string w3dup;
    fix::build(dup3, w3dup);

    std::vector<std::string> out_b2;
    b.process_inbound(w3dup, out_b2);
    AFX_EXPECT_EQ(b.pending_count(), (size_t)0);  // gap closed, 4 processed
}

AFX_TEST(sequence_reset_gapfill_skips) {
    fix::SessionConfig cfg;
    fix::FixSession a(cfg);
    fix::FixSession b(cfg);
    std::vector<std::string> out;
    b.process_inbound(a.initiate_logon(), out);
    a.process_inbound(out[0], out);

    // b expects seq 2; a sends SequenceReset(35=4, 123=Y, 36=9) with seq 2:
    // messages 2..8 are skipped, next expected is 9.
    fix::FixMessage reset;
    reset.fields[35] = "4";
    reset.fields[123] = "Y";
    reset.fields[36] = "9";
    reset.fields[34] = "2";
    std::string wire;
    fix::build(reset, wire);
    std::vector<std::string> out_b;
    b.process_inbound(wire, out_b);
    AFX_EXPECT_EQ(b.persist().next_in, 9u);
}

AFX_TEST(sequence_persistence_across_reconnect) {
    fix::SessionConfig cfg;
    fix::FixSession a(cfg);
    std::vector<std::string> out;
    a.initiate_logon();
    // Advance outbound sequence by one heartbeat.
    a.create_heartbeat();
    const fix::SeqStore saved = a.persist();
    AFX_EXPECT_EQ(saved.next_out, 3u);

    fix::FixSession reconnected(cfg);
    reconnected.restore(saved);
    const fix::SeqStore restored = reconnected.persist();
    AFX_EXPECT_EQ(restored.next_out, saved.next_out);
    AFX_EXPECT_EQ(restored.next_in, saved.next_in);
}

AFX_TEST(malformed_inbound_dropped_and_counted) {
    fix::SessionConfig cfg;
    fix::FixSession s(cfg);
    std::vector<std::string> out;
    s.process_inbound("not-a-fix-message", out);
    AFX_EXPECT_EQ(s.malformed_count(), 1ull);
    AFX_EXPECT_EQ(out.size(), (size_t)0);
}

AFX_TEST(possdup_duplicate_ignored) {
    fix::SessionConfig cfg;
    fix::FixSession a(cfg);
    fix::FixSession b(cfg);
    std::vector<std::string> out;
    b.process_inbound(a.initiate_logon(), out);
    a.process_inbound(out[0], out);

    // b receives seq 2 twice with PossDup=Y: deduplicated by session.
    fix::FixMessage m;
    m.fields[35] = "0";
    m.fields[34] = "2";
    std::string w;
    fix::build(m, w);
    std::vector<std::string> o1, o2;
    b.process_inbound(w, o1);
    fix::FixMessage dup = m;
    dup.fields[43] = "Y";
    std::string wdup;
    fix::build(dup, wdup);
    b.process_inbound(wdup, o2);
    AFX_EXPECT_EQ(b.persist().next_in, 3u);  // processed once
}

int main(int argc, char** argv) {
    g_root = (argc > 1) ? argv[1] : ".";
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("fix-test-main-start argc=%d\n", argc);
    const int rc = afx::run_all(argc, argv);
    std::printf("fix-test-done rc=%d\n", rc);
    return rc;
}
