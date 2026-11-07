// SPDX-License-Identifier: MIT
// Clang libFuzzer entrypoint: untrusted IPv4/CIDR inputs and aggregator invariants.
#include "xorcist/net.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <string_view>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace xorcist::net;
    if (size > 2048) return 0; // bound work per fuzz iteration
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    try {
        const auto parsed = parse_cidr(text);
        const auto reparsed = parse_cidr(parsed.cidr());
        if (parsed.address != reparsed.address || parsed.prefix != reparsed.prefix) std::abort();
        const auto subnet = enclosing_supernet({parsed});
        if (subnet.address != parsed.address || subnet.prefix != parsed.prefix) std::abort();
        const auto collapsed = collapse({parsed, parsed});
        if (collapsed.size() != 1 || collapsed[0].cidr() != parsed.cidr()) std::abort();
    } catch (const std::exception&) { /* malformed input: rejection is valid */ }
    try {
        const auto parsed = parse_network_list(text);
        if (!parsed.empty() && parsed.size() <= 128) {
            const auto exact = collapse(parsed);
            const auto repeat = collapse(exact);
            if (exact.size() != repeat.size()) std::abort();
            for (std::size_t i = 0; i < exact.size(); ++i) {
                if (exact[i].cidr() != repeat[i].cidr()) std::abort();
                if (i != 0 && exact[i - 1].broadcast() >= exact[i].address) std::abort();
            }
        }
    } catch (const std::exception&) { /* malformed input: rejection is valid */ }
    return 0;
}
