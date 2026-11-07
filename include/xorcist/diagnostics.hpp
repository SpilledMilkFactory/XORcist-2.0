// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace xorcist::diagnostics {

enum class AddressFamily { Any, IPv4, IPv6 };
struct DnsResult {
    std::string query;
    std::string observed_utc;
    std::vector<std::string> addresses;
};
struct ReverseResult {
    std::string address;
    std::string hostname;
    std::string observed_utc;
};
struct Interface {
    std::string name;
    std::uint32_t index{};
    bool up{};
    std::uint32_t mtu{};
    std::vector<std::string> addresses; // numeric host/prefix
    std::vector<std::string> gateways; // OS-provided where available
};
struct Route {
    std::string destination; // canonical CIDR
    std::string gateway; // '-' for on-link
    std::string interface_name;
    std::uint32_t metric{};
};
struct Ipv4Mask {
    std::uint8_t prefix{};
    std::string mask;
    std::string wildcard;
};
struct ProbeOptions {
    std::uint16_t port{};
    unsigned count{2};
    unsigned timeout_ms{500};
    unsigned interval_ms{250};
};
struct ProbeAttempt {
    std::string outcome; // connected, refused, timeout, error
    std::string detail;
    std::uint32_t elapsed_ms{};
};
struct ProbeResult {
    std::string address;
    std::string observed_utc;
    ProbeOptions options;
    std::vector<ProbeAttempt> attempts;
};

// Uses OS resolver; may block according to operating-system resolver policy.
[[nodiscard]] DnsResult lookup(std::string_view hostname, AddressFamily family = AddressFamily::Any);
[[nodiscard]] ReverseResult reverse(std::string_view numeric_ip);
// Read-only, no special privileges or system configuration changes.
[[nodiscard]] std::vector<Interface> interfaces();
[[nodiscard]] std::vector<Route> routes();
// Strict contiguous IPv4 masks only.
[[nodiscard]] Ipv4Mask mask_from_netmask(std::string_view dotted);
[[nodiscard]] Ipv4Mask mask_from_wildcard(std::string_view dotted);
// Explicit Cisco-like matching *fragment*, not a full device-specific ACL rule.
[[nodiscard]] std::string acl_match(std::string_view cidr);
// TCP connect to a NUMERIC IP and EXPLICIT port only. Max 5 attempts / 10s configured budget.
[[nodiscard]] ProbeResult probe_tcp_numeric(std::string_view numeric_ip, const ProbeOptions& options);
[[nodiscard]] std::string format(const DnsResult& result);
[[nodiscard]] std::string format(const ReverseResult& result);
[[nodiscard]] std::string format(const std::vector<Interface>& result);
[[nodiscard]] std::string format(const std::vector<Route>& result);
[[nodiscard]] std::string format(const Ipv4Mask& result);
[[nodiscard]] std::string format(const ProbeResult& result);

} // namespace xorcist::diagnostics
