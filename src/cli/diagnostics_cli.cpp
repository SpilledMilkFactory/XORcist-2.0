// SPDX-License-Identifier: MIT
#include "diagnostics_cli.hpp"
#include "xorcist/diagnostics.hpp"
#include <charconv>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace xorcist::cli {
namespace {
unsigned parse_uint(std::string_view text, unsigned min, unsigned max) {
    if (text.empty() || (text.size() > 1 && text.front() == '0'))
        throw std::invalid_argument("invalid decimal number");
    unsigned n{};
    const auto [p, error] = std::from_chars(text.data(), text.data() + text.size(), n);
    if (error != std::errc{} || p != text.data() + text.size() || n < min || n > max)
        throw std::invalid_argument("decimal number outside permitted range");
    return n;
}
void require_size(const std::vector<std::string>& args, std::size_t size, std::string_view help) {
    if (args.size() != size) throw std::invalid_argument(std::string(help));
}
} // namespace
int run_diag(const std::vector<std::string>& args) {
    using namespace xorcist::diagnostics;
    if (args.size() < 2) throw std::invalid_argument("expected diag dns|reverse|interfaces|routes|probe|mask|wildcard|acl");
    const auto& action = args[1];
    if (action == "dns") {
        if (args.size() != 3 && args.size() != 5)
            throw std::invalid_argument("diag dns <hostname> [--family any|v4|v6]");
        AddressFamily family = AddressFamily::Any;
        if (args.size() == 5) {
            if (args[3] != "--family") throw std::invalid_argument("expected --family any|v4|v6");
            if (args[4] == "v4") family = AddressFamily::IPv4;
            else if (args[4] == "v6") family = AddressFamily::IPv6;
            else if (args[4] != "any") throw std::invalid_argument("invalid DNS address family");
        }
        std::cout << format(lookup(args[2], family));
    } else if (action == "reverse") {
        require_size(args, 3, "diag reverse <numeric-IP>");
        std::cout << format(reverse(args[2]));
    } else if (action == "interfaces") {
        require_size(args, 2, "diag interfaces");
        std::cout << format(interfaces());
    } else if (action == "routes") {
        require_size(args, 2, "diag routes");
        std::cout << format(routes());
    } else if (action == "mask") {
        require_size(args, 3, "diag mask <IPv4-netmask>");
        std::cout << format(mask_from_netmask(args[2]));
    } else if (action == "wildcard") {
        require_size(args, 3, "diag wildcard <IPv4-wildcard>");
        std::cout << format(mask_from_wildcard(args[2]));
    } else if (action == "acl") {
        require_size(args, 3, "diag acl <IPv4-or-IPv6-CIDR>");
        std::cout << "Cisco-like match fragment (not a complete ACL rule): " << acl_match(args[2]) << '\n';
    } else if (action == "probe") {
        if (args.size() < 4) throw std::invalid_argument("diag probe <numeric-IP> <TCP-port> [--count 1..5] [--timeout-ms 100..2000] [--interval-ms 200..2000]");
        ProbeOptions cfg{};
        cfg.port = static_cast<std::uint16_t>(parse_uint(args[3], 1, 65535));
        bool count = false, timeout = false, interval = false;
        for (std::size_t i = 4; i < args.size(); i += 2) {
            if (i + 1 >= args.size()) throw std::invalid_argument("missing probe option value");
            if (args[i] == "--count" && !count) {
                cfg.count = parse_uint(args[i + 1], 1, 5); count = true;
            } else if (args[i] == "--timeout-ms" && !timeout) {
                cfg.timeout_ms = parse_uint(args[i + 1], 100, 2000); timeout = true;
            } else if (args[i] == "--interval-ms" && !interval) {
                cfg.interval_ms = parse_uint(args[i + 1], 200, 2000); interval = true;
            } else throw std::invalid_argument("unknown or duplicate probe option: " + args[i]);
        }
        std::cout << format(probe_tcp_numeric(args[2], cfg));
    } else throw std::invalid_argument("unknown diag command: " + action);
    return 0;
}
} // namespace xorcist::cli
