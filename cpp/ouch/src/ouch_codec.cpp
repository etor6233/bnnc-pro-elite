// ouch/ouch_codec.cpp — OUCH 5.0 codec + order-entry session engine.
//
// Layouts and rules follow the captured, SHA256-pinned official spec
// (OUCH5.0.pdf; text in cpp/tools/extracted/OUCH5.0.txt) and the annotated
// semantics in MARKET_MICROSTRUCTURE_EXCHANGE_SYSTEMS.md §5.5.
#include <ouch/ouch_codec.hpp>

#include <cstring>

namespace ouch {

namespace {

// Spec 1.2: numeric fields are big-endian.
inline uint16_t rd16(const uint8_t* p) {
    return (uint16_t)((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
inline uint32_t rd32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
inline uint64_t rd64(const uint8_t* p) {
    return ((uint64_t)rd32(p) << 32) | (uint64_t)rd32(p + 4);
}
inline void wr16(std::string& out, uint16_t v) {
    out.push_back((char)(v >> 8));
    out.push_back((char)(v & 0xFF));
}
inline void wr32(std::string& out, uint32_t v) {
    out.push_back((char)(v >> 24));
    out.push_back((char)((v >> 16) & 0xFF));
    out.push_back((char)((v >> 8) & 0xFF));
    out.push_back((char)(v & 0xFF));
}
inline void wr64(std::string& out, uint64_t v) {
    wr32(out, (uint32_t)(v >> 32));
    wr32(out, (uint32_t)(v & 0xFFFFFFFFull));
}

// Spec 1.2: alphas are left justified, space padded on the right.
inline void alpha_pad(std::string& out, const std::string& s, size_t width) {
    const size_t start = out.size();
    out += s;
    while (out.size() - start < width) out.push_back(' ');
}
inline std::string alpha_trimmed(const uint8_t* p, size_t n) {
    size_t end = n;
    while (end > 0 && p[end - 1] == ' ') --end;
    return std::string(reinterpret_cast<const char*>(p), end);
}

}  // namespace

const char* to_string(DecodeStatus s) {
    switch (s) {
        case DecodeStatus::Ok: return "Ok";
        case DecodeStatus::Truncated: return "Truncated";
        case DecodeStatus::UnknownType: return "UnknownType";
    }
    return "?";
}

const char* to_string(EnterOutcome o) {
    switch (o) {
        case EnterOutcome::Accepted: return "Accepted";
        case EnterOutcome::Rejected: return "Rejected";
        case EnterOutcome::DuplicateIgnored: return "DuplicateIgnored";
    }
    return "?";
}
const char* to_string(ReplaceOutcome o) {
    switch (o) {
        case ReplaceOutcome::Replaced: return "Replaced";
        case ReplaceOutcome::SilentlyIgnored: return "SilentlyIgnored";
        case ReplaceOutcome::CancelTakeOut: return "CancelTakeOut";
        case ReplaceOutcome::Rejected: return "Rejected";
        case ReplaceOutcome::DuplicateIgnored: return "DuplicateIgnored";
    }
    return "?";
}
const char* to_string(CancelOutcome o) {
    switch (o) {
        case CancelOutcome::Canceled: return "Canceled";
        case CancelOutcome::SilentlyIgnored: return "SilentlyIgnored";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Encoding (spec tables 2.1 / 2.2 / 2.3).
// ---------------------------------------------------------------------------

bool encode_enter(const EnterOrder& m, std::string& out) {
    // spec 2.1: quantity must be greater than zero and less than 1,000,000.
    if (m.quantity == 0 || m.quantity >= 1'000'000) return false;
    out.clear();
    out.push_back('O');
    wr32(out, m.user_ref_num);
    out.push_back(m.side);
    wr32(out, m.quantity);
    alpha_pad(out, m.symbol, 8);
    wr64(out, m.price);
    out.push_back(m.time_in_force);
    out.push_back(m.display);
    out.push_back(m.capacity);
    out.push_back(m.intermkt_sweep);
    out.push_back(m.cross_type);
    alpha_pad(out, m.cl_ord_id, 14);
    wr16(out, m.appendage_len);
    out += m.appendage;
    return true;
}

bool encode_replace(const ReplaceOrder& m, std::string& out) {
    // spec 2.2: quantity must be greater than zero and less than 1,000,000.
    if (m.quantity == 0 || m.quantity >= 1'000'000) return false;
    out.clear();
    out.push_back('U');
    wr32(out, m.orig_user_ref_num);
    wr32(out, m.user_ref_num);
    wr32(out, m.quantity);
    wr64(out, m.price);
    out.push_back(m.time_in_force);
    out.push_back(m.display);
    out.push_back(m.intermkt_sweep);
    alpha_pad(out, m.cl_ord_id, 14);
    wr16(out, m.appendage_len);
    out += m.appendage;
    return true;
}

bool encode_cancel(const CancelOrder& m, std::string& out) {
    out.clear();
    out.push_back('X');
    wr32(out, m.user_ref_num);
    wr32(out, m.quantity);
    wr16(out, m.appendage_len);
    out += m.appendage;
    return true;
}

DecodeStatus decode_inbound(const uint8_t* data, size_t len, Inbound& out) {
    if (data == nullptr || len < 1) return DecodeStatus::Truncated;
    switch (data[0]) {
        case 'O': {  // 2.1: base 47 bytes (ClOrdID @31 len 14 ends @45;
                     // AppendageLength @45 len 2; Appendage @47)
            if (len < 47) return DecodeStatus::Truncated;
            EnterOrder m{};
            m.user_ref_num = rd32(data + 1);
            m.side = (char)data[5];
            m.quantity = rd32(data + 6);
            m.symbol = alpha_trimmed(data + 10, 8);
            m.price = rd64(data + 18);
            m.time_in_force = (char)data[26];
            m.display = (char)data[27];
            m.capacity = (char)data[28];
            m.intermkt_sweep = (char)data[29];
            m.cross_type = (char)data[30];
            m.cl_ord_id = alpha_trimmed(data + 31, 14);
            m.appendage_len = rd16(data + 45);
            m.appendage = std::string(reinterpret_cast<const char*>(data + 47),
                                      len - 47);
            out.type = InboundType::Enter;
            out.enter = m;
            return DecodeStatus::Ok;
        }
        case 'U': {  // 2.2: base 40 bytes
            if (len < 40) return DecodeStatus::Truncated;
            ReplaceOrder m{};
            m.orig_user_ref_num = rd32(data + 1);
            m.user_ref_num = rd32(data + 5);
            m.quantity = rd32(data + 9);
            m.price = rd64(data + 13);
            m.time_in_force = (char)data[21];
            m.display = (char)data[22];
            m.intermkt_sweep = (char)data[23];
            m.cl_ord_id = alpha_trimmed(data + 24, 14);
            m.appendage_len = rd16(data + 38);
            m.appendage = std::string(reinterpret_cast<const char*>(data + 40),
                                      len - 40);
            out.type = InboundType::Replace;
            out.replace = m;
            return DecodeStatus::Ok;
        }
        case 'X': {  // 2.3: appendage fields optional; base 11 bytes
            if (len < 11) return DecodeStatus::Truncated;
            if (len == 12) return DecodeStatus::Truncated;  // dangling byte
            CancelOrder m{};
            m.user_ref_num = rd32(data + 1);
            m.quantity = rd32(data + 5);
            if (len == 11) {
                m.appendage_len = 0;
            } else {
                m.appendage_len = rd16(data + 9);
                m.appendage =
                    std::string(reinterpret_cast<const char*>(data + 11), len - 11);
            }
            out.type = InboundType::Cancel;
            out.cancel = m;
            return DecodeStatus::Ok;
        }
        default:
            return DecodeStatus::UnknownType;
    }
}

DecodeStatus decode_outbound(const uint8_t* data, size_t len, Outbound& out) {
    if (data == nullptr || len < 1) return DecodeStatus::Truncated;
    switch (data[0]) {
        case 'A': {  // 3.2: 64 bytes
            if (len < 64) return DecodeStatus::Truncated;
            Accepted m{};
            m.timestamp_ns = rd64(data + 1);
            m.user_ref_num = rd32(data + 9);
            m.side = (char)data[13];
            m.quantity = rd32(data + 14);
            m.symbol = alpha_trimmed(data + 18, 8);
            m.price = rd64(data + 26);
            m.time_in_force = (char)data[34];
            m.display = (char)data[35];
            m.order_ref_num = rd64(data + 36);
            m.capacity = (char)data[44];
            m.intermkt_sweep = (char)data[45];
            m.cross_type = (char)data[46];
            m.order_state = (char)data[47];
            m.cl_ord_id = alpha_trimmed(data + 48, 14);
            m.appendage_len = rd16(data + 62);
            m.appendage = std::string(reinterpret_cast<const char*>(data + 64),
                                      len - 64);
            out.type = OutboundType::Accepted;
            out.accepted = m;
            return DecodeStatus::Ok;
        }
        case 'U': {  // 3.3: 68 bytes
            if (len < 68) return DecodeStatus::Truncated;
            Replaced m{};
            m.timestamp_ns = rd64(data + 1);
            m.orig_user_ref = rd32(data + 9);
            m.user_ref_num = rd32(data + 13);
            m.side = (char)data[17];
            m.quantity = rd32(data + 18);
            m.symbol = alpha_trimmed(data + 22, 8);
            m.price = rd64(data + 30);
            m.time_in_force = (char)data[38];
            m.display = (char)data[39];
            m.order_ref_num = rd64(data + 40);
            m.capacity = (char)data[48];
            m.intermkt_sweep = (char)data[49];
            m.cross_type = (char)data[50];
            m.order_state = (char)data[51];
            m.cl_ord_id = alpha_trimmed(data + 52, 14);
            m.appendage_len = rd16(data + 66);
            m.appendage = std::string(reinterpret_cast<const char*>(data + 68),
                                      len - 68);
            out.type = OutboundType::Replaced;
            out.replaced = m;
            return DecodeStatus::Ok;
        }
        case 'C': {  // 3.4: appendage optional; base 18 bytes
            if (len < 18) return DecodeStatus::Truncated;
            if (len == 19) return DecodeStatus::Truncated;
            Canceled m{};
            m.timestamp_ns = rd64(data + 1);
            m.user_ref_num = rd32(data + 9);
            m.quantity = rd32(data + 13);
            m.reason = (char)data[17];
            if (len == 18) {
                m.appendage_len = 0;
            } else {
                m.appendage_len = rd16(data + 18);
                m.appendage =
                    std::string(reinterpret_cast<const char*>(data + 20), len - 20);
            }
            out.type = OutboundType::Canceled;
            out.canceled = m;
            return DecodeStatus::Ok;
        }
        case 'E': {  // 3.6: base 36 bytes (appendage only with UserRefIdx)
            if (len < 34) return DecodeStatus::Truncated;
            if (len == 35) return DecodeStatus::Truncated;
            Executed m{};
            m.timestamp_ns = rd64(data + 1);
            m.user_ref_num = rd32(data + 9);
            m.quantity = rd32(data + 13);
            m.price = rd64(data + 17);
            m.liquidity_flag = (char)data[25];
            m.match_number = rd64(data + 26);
            if (len == 34) {
                m.appendage_len = 0;
            } else {
                m.appendage_len = rd16(data + 34);
                m.appendage =
                    std::string(reinterpret_cast<const char*>(data + 36), len - 36);
            }
            out.type = OutboundType::Executed;
            out.executed = m;
            return DecodeStatus::Ok;
        }
        case 'J': {  // 3.8: appendage optional; base 29 bytes
            if (len < 29) return DecodeStatus::Truncated;
            if (len == 30) return DecodeStatus::Truncated;
            Rejected m{};
            m.timestamp_ns = rd64(data + 1);
            m.user_ref_num = rd32(data + 9);
            m.reason = rd16(data + 13);
            m.cl_ord_id = alpha_trimmed(data + 15, 14);
            if (len == 29) {
                m.appendage_len = 0;
            } else {
                m.appendage_len = rd16(data + 29);
                m.appendage =
                    std::string(reinterpret_cast<const char*>(data + 31), len - 31);
            }
            out.type = OutboundType::Rejected;
            out.rejected = m;
            return DecodeStatus::Ok;
        }
        default:
            return DecodeStatus::UnknownType;
    }
}

// ---------------------------------------------------------------------------
// OrderEntrySession engine.
// ---------------------------------------------------------------------------

OrderEntrySession::OrderEntrySession() = default;

bool OrderEntrySession::is_consumed(uint32_t ref) const {
    auto it = consumed_.find(ref);
    return it != consumed_.end();
}

EnterOutcome OrderEntrySession::on_enter(const EnterOrder& m) {
    // spec 1.2: UserRefNums lower than the last one processed are ignored as
    // retransmissions (equal => the same message resent => duplicate too).
    // Rejected refs are consumed (spec 3.8) and therefore also fall here.
    if (is_consumed(m.user_ref_num) || m.user_ref_num <= last_processed_) {
        return EnterOutcome::DuplicateIgnored;
    }
    // spec 2.1: quantity must be greater than zero and less than 1,000,000.
    if (m.quantity == 0 || m.quantity >= 1'000'000) {
        // spec 3.8: the UserRefNum of a Rejected message cannot be re-used.
        mark_consumed(m.user_ref_num);
        last_processed_ = m.user_ref_num;
        return EnterOutcome::Rejected;
    }
    mark_consumed(m.user_ref_num);
    last_processed_ = m.user_ref_num;
    InternalOrder io{};
    io.st.ref = m.user_ref_num;
    io.st.side = m.side;
    io.st.price = m.price;
    io.st.total_liable = m.quantity;
    io.st.executed_cumulative = 0;
    io.st.canceled_cumulative = 0;
    io.st.live = true;
    orders_[m.user_ref_num] = io;
    chain_origin_[m.user_ref_num] = m.user_ref_num;
    chain_current_[m.user_ref_num] = m.user_ref_num;
    return EnterOutcome::Accepted;
}

ReplaceOutcome OrderEntrySession::on_replace(const ReplaceOrder& m) {
    // spec 2.2 case 1: a replacement UserRefNum that has already been used in
    // another Enter or Replace is ignored, and it was NOT consumed there.
    if (is_consumed(m.user_ref_num)) return ReplaceOutcome::SilentlyIgnored;
    // spec 1.2: refs lower than the last one processed are retransmissions.
    if (m.user_ref_num <= last_processed_) return ReplaceOutcome::DuplicateIgnored;

    auto orig_it = orders_.find(m.orig_user_ref_num);
    // spec 2.2 outcome 1: orig not live -> silently ignored; the replacement
    // UserRefNum is NOT consumed (reusable later).
    if (orig_it == orders_.end() || !orig_it->second.st.live) {
        return ReplaceOutcome::SilentlyIgnored;
    }
    InternalOrder& orig = orig_it->second;

    // spec 2.2 outcome 2: live but invalid details (e.g. new Shares >=
    // 1,000,000) -> a Cancel takes the existing order out of the book; the
    // replacement ref is NOT consumed. A total liable at or below the chain's
    // executed quantity is likewise incoherent (2.2: total liable includes
    // previous executions over the chain) and falls into the invalid-details
    // branch, never silently creating double liability.
    if (m.quantity == 0 || m.quantity >= 1'000'000 ||
        m.quantity <= orig.st.executed_cumulative) {
        orig.st.live = false;
        return ReplaceOutcome::CancelTakeOut;
    }

    // spec 2.2 outcome 3: live but cannot be canceled (cross order in the
    // late period) -> Rejected; existing order fully intact; the reject
    // CONSUMES the replacement ref (spec 2.2 + 3.8).
    if (late_period_) {
        mark_consumed(m.user_ref_num);
        last_processed_ = m.user_ref_num;
        return ReplaceOutcome::Rejected;
    }

    // spec 2.2 outcome 4: Replaced. The chain keeps its cumulative
    // executions (2.2: shares denote the total liable for the whole chain).
    uint32_t origin = chain_origin_[orig.st.ref];
    InternalOrder neo{};
    neo.st.ref = m.user_ref_num;
    neo.st.side = orig.st.side;
    neo.st.price = m.price;
    neo.st.total_liable = m.quantity;
    neo.st.executed_cumulative = orig.st.executed_cumulative;
    neo.st.canceled_cumulative = orig.st.canceled_cumulative;
    neo.st.live = true;
    orders_.erase(m.orig_user_ref_num);
    orders_[m.user_ref_num] = neo;
    mark_consumed(m.user_ref_num);
    chain_origin_[m.user_ref_num] = origin;
    chain_current_[origin] = m.user_ref_num;
    last_processed_ = m.user_ref_num;
    return ReplaceOutcome::Replaced;
}

CancelOutcome OrderEntrySession::on_cancel(const CancelOrder& m) {
    auto it = orders_.find(m.user_ref_num);
    // spec 2.3: superfluous Cancel Order Messages are silently ignored.
    if (it == orders_.end() || !it->second.st.live) {
        return CancelOutcome::SilentlyIgnored;
    }
    InternalOrder& o = it->second;
    // 2.3: quantity is the new intended order size (max shares executable in
    // total after the cancel); zero cancels any remaining open shares.
    uint32_t total = o.st.total_liable;
    uint32_t executed = o.st.executed_cumulative;
    uint32_t canceled = o.st.canceled_cumulative;
    uint32_t floor = (m.quantity > executed) ? m.quantity : executed;
    uint32_t decrement = total - floor - canceled;
    if (decrement <= 0) {
        return CancelOutcome::SilentlyIgnored;
    }
    o.st.canceled_cumulative = canceled + decrement;
    if (o.st.total_liable - o.st.executed_cumulative - o.st.canceled_cumulative == 0) {
        o.st.live = false;
    }
    return CancelOutcome::Canceled;
}

void OrderEntrySession::on_executed(const Executed& m) {
    // Executions may arrive for the ORIGINAL ref of a chain after a replace
    // (spec 3.3 example: execution was in flight while the replace traveled).
    auto origin_it = chain_origin_.find(m.user_ref_num);
    if (origin_it == chain_origin_.end()) return;  // unknown ref: no order
    auto cur_it = chain_current_.find(origin_it->second);
    if (cur_it == chain_current_.end()) return;
    auto o_it = orders_.find(cur_it->second);
    if (o_it == orders_.end()) return;
    InternalOrder& o = o_it->second;
    o.st.executed_cumulative += m.quantity;
    if (o.st.total_liable - o.st.executed_cumulative - o.st.canceled_cumulative == 0) {
        o.st.live = false;
    }
}

void OrderEntrySession::on_canceled(const Canceled& m) {
    // Venue-initiated cancellation (3.4: quantity is incremental).
    auto it = orders_.find(m.user_ref_num);
    if (it == orders_.end() || !it->second.st.live) return;
    InternalOrder& o = it->second;
    o.st.canceled_cumulative += m.quantity;
    if (o.st.total_liable - o.st.executed_cumulative - o.st.canceled_cumulative == 0) {
        o.st.live = false;
    }
}

const OrderEntrySession::OrderState* OrderEntrySession::find_order(
    uint32_t current_ref) const {
    auto it = orders_.find(current_ref);
    if (it == orders_.end()) return nullptr;
    return &it->second.st;
}

}  // namespace ouch
