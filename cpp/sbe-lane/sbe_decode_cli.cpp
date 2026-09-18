// sbe-lane/sbe_decode_cli.cpp — decode verification CLI for the SBE lane.
//
// Reads a frames file (u32 little-endian length prefix + SBE payload, the
// framing written by sbe_lane.py) and decodes every frame with the pinned
// FASE 2 decoder (sbe/binance_sbe). Emits one JSON line per frame; exits
// non-zero on any malformed frame. Used by the lane verification step and the
// test suite — spec schema pinned in cpp/sbe/schema/stream_1_0.xml.
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <sbe/binance_sbe.hpp>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: sbe_decode_cli <frames.sbe>\n");
        return 2;
    }
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "cannot open %s\n", argv[1]);
        return 2;
    }
    std::vector<uint8_t> data{std::istreambuf_iterator<char>(in),
                              std::istreambuf_iterator<char>()};
    size_t pos = 0;
    uint64_t index = 0;
    int failures = 0;
    while (pos + 4 <= data.size()) {
        const uint32_t len = (uint32_t)data[pos] | ((uint32_t)data[pos + 1] << 8) |
                             ((uint32_t)data[pos + 2] << 16) |
                             ((uint32_t)data[pos + 3] << 24);
        pos += 4;
        if (len == 0 || pos + len > data.size()) {
            std::printf("{\"index\":%llu,\"status\":\"error\","
                        "\"reason\":\"truncated_frame\"}\n",
                        (unsigned long long)index);
            return 1;
        }
        sbe::Decoded out;
        const sbe::DecodeStatus st = sbe::decode(data.data() + pos, len, out);
        if (st != sbe::DecodeStatus::Ok) {
            std::printf("{\"index\":%llu,\"status\":\"error\",\"reason\":\"%s\"}\n",
                        (unsigned long long)index, sbe::to_string(st));
            ++failures;
        } else {
            std::printf(
                "{\"index\":%llu,\"status\":\"ok\",\"template_id\":%u,"
                "\"schema_id\":%u,\"version\":%u}\n",
                (unsigned long long)index, (unsigned)out.template_id,
                (unsigned)out.schema_id, (unsigned)out.version);
        }
        pos += len;
        ++index;
    }
    if (pos != data.size()) {
        std::printf("{\"status\":\"error\",\"reason\":\"trailing_bytes\"}\n");
        return 1;
    }
    return failures == 0 ? 0 : 1;
}
