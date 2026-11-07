// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace xorcist::net {

// IPv4 addresses use network byte order in a host uint32_t: 192.0.2.1 = 0xC0000201.
struct Network {
    std::uint32_t address{}; // Always the network base, not an arbitrary host address.
    std::uint8_t prefix{};

    [[nodiscard]] std::uint32_t mask() const noexcept;
    [[nodiscard]] std::uint32_t broadcast() const noexcept;
    [[nodiscard]] std::string cidr() const;
};

[[nodiscard]] std::string format_ipv4(std::uint32_t address);
[[nodiscard]] Network parse_cidr(std::string_view input);
[[nodiscard]] std::vector<Network> parse_network_list(std::string_view input);
// Smallest single CIDR that covers every address of every supplied subnet.
[[nodiscard]] Network enclosing_supernet(const std::vector<Network>& networks);
// Exact union, without including addresses outside the supplied networks.
[[nodiscard]] std::vector<Network> collapse(const std::vector<Network>& networks);
[[nodiscard]] std::string inspect(const Network& network);

} // namespace xorcist::net
