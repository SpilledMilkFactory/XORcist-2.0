// SPDX-License-Identifier: MIT
#include "xorcist/diagnostics.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
int checked = 0;
void require(bool good, const char* label) {
    ++checked;
    if (!good) throw std::runtime_error(label);
}
template<typename F> void error(F run, const char* label) {
    try { run(); } catch (const std::exception&) { ++checked; return; }
    throw std::runtime_error(label);
}
}
int main() {
    try {
        using namespace xorcist::diagnostics;
        for (unsigned n = 0; n <= 32; ++n) {
            // Build netmasks independently rather than parsing CIDR through project code.
            std::string mask;
            for (unsigned octet = 0; octet < 4; ++octet) {
                const int remaining = static_cast<int>(n) - static_cast<int>(octet * 8);
                const unsigned bits = static_cast<unsigned>(std::clamp(remaining, 0, 8));
                const unsigned value = bits == 0 ? 0U : (255U << (8U - bits)) & 255U;
                if (octet) mask += '.';
                mask += std::to_string(value);
            }
            const auto a = mask_from_netmask(mask);
            const auto b = mask_from_wildcard(a.wildcard);
            require(a.prefix == n && b.prefix == n && a.mask == b.mask && a.wildcard == b.wildcard,
                    "all 33 valid contiguous masks must round-trip");
        }
        require(mask_from_netmask("0.0.0.0").wildcard == "255.255.255.255", "/0 wildcard");
        require(mask_from_netmask("255.255.255.255").wildcard == "0.0.0.0", "/32 wildcard");
        require(acl_match("192.0.2.45/24") == "ip 192.0.2.0 0.0.0.255", "IPv4 ACL network normalization");
        require(acl_match("0.0.0.0/0") == "ip 0.0.0.0 255.255.255.255", "IPv4 ACL /0");
        require(acl_match("2001:db8::1/64") == "ipv6 2001:db8::/64", "IPv6 ACL fragment");
        error([] { (void)mask_from_netmask("255.0.255.0"); }, "reject discontiguous mask");
        error([] { (void)mask_from_wildcard("0.0.255.0"); }, "reject discontiguous wildcard");
        error([] { (void)mask_from_netmask("255.255.255.256"); }, "reject out-of-range octet");
        error([] { (void)mask_from_netmask("255.255.255"); }, "reject short IPv4");
        error([] { (void)acl_match("192.0.2.1/33"); }, "reject invalid prefix");
        error([] { (void)reverse("example.org"); }, "reverse accepts numeric addresses only");
        error([] { (void)lookup("example.org/AAAA"); }, "reject slash hostname");
        error([] { (void)probe_tcp_numeric("localhost", ProbeOptions{80, 1, 200, 200}); }, "probe rejects hostnames");
        error([] { (void)probe_tcp_numeric("127.0.0.1", ProbeOptions{0, 1, 200, 200}); }, "reject port 0");
        error([] { (void)probe_tcp_numeric("127.0.0.1", ProbeOptions{80, 6, 200, 200}); }, "reject too many probes");
        error([] { (void)probe_tcp_numeric("127.0.0.1", ProbeOptions{80, 5, 2000, 2000}); }, "reject >10s budget");
        error([] { (void)probe_tcp_numeric("127.0.0.1", ProbeOptions{80, 1, 0, 200}); }, "reject timeout zero");
        // One TCP attempt to loopback: no Internet or listening server is necessary.
        const auto loop = probe_tcp_numeric("127.0.0.1", ProbeOptions{1, 1, 300, 200});
        require(loop.attempts.size() == 1 && !loop.attempts[0].outcome.empty(), "bounded loopback probe");
        require(format(loop).find("TCP probe: 127.0.0.1:1") != std::string::npos, "probe formatter");
        const auto local = lookup("localhost", AddressFamily::IPv4);
        require(!local.addresses.empty() && local.observed_utc.ends_with('Z'), "system localhost lookup and UTC stamp");
        const auto ifaces = interfaces();
        require(ifaces.size() < 256, "interface enumeration bounds");
#ifdef __linux__
        require(!ifaces.empty(), "Linux interface snapshot");
        const auto table = routes();
        require(table.size() < 4097, "Linux route enumeration bounds");
#endif
        std::cout << checked << " M2 checks passed\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "M2 test failed after " << checked << " checks: " << e.what() << '\n';
        return 1;
    }
}
