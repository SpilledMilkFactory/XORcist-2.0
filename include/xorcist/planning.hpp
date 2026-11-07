// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace xorcist::planning {

enum class Family : std::uint8_t { IPv4 = 4, IPv6 = 6 };
enum class ListFormat { Lines, Csv };

// Address bytes are in network order; IPv4 occupies bytes[0..3] and zeros the rest.
struct Address {
    Family family{Family::IPv4};
    std::array<std::uint8_t, 16> bytes{};
    [[nodiscard]] std::string str() const;
};
struct Cidr {
    Address network{};  // Canonical, host bits zeroed.
    std::uint8_t prefix{};
    [[nodiscard]] std::string str() const;
};
struct Range {
    Address first{};
    Address last{}; // Inclusive.
};
struct HostRequest {
    std::string name;
    std::uint64_t hosts{}; // Conventional IPv4 usable host requirement (network/broadcast reserved).
};
struct Allocation {
    HostRequest request;
    Cidr network;
};

[[nodiscard]] Address parse_address(std::string_view text);
[[nodiscard]] Cidr parse_cidr(std::string_view text);
[[nodiscard]] Range parse_range(std::string_view first, std::string_view last);
[[nodiscard]] std::vector<Cidr> parse_list(std::string_view contents, ListFormat format);
[[nodiscard]] std::string serialize_list(const std::vector<Cidr>& networks, ListFormat format);
[[nodiscard]] std::vector<Cidr> load_list(const std::filesystem::path& path, ListFormat format);
// Exclusive-create; never overwrites an existing file.
void save_list(const std::filesystem::path& path, const std::vector<Cidr>& networks, ListFormat format);

[[nodiscard]] bool contains(const Cidr& network, const Address& address);
[[nodiscard]] bool covers(const Cidr& outer, const Cidr& inner);
[[nodiscard]] bool overlaps(const Cidr& a, const Cidr& b);
[[nodiscard]] std::optional<Cidr> intersection(const Cidr& a, const Cidr& b);
[[nodiscard]] std::vector<std::pair<std::size_t, std::size_t>> conflicts(const std::vector<Cidr>& networks);
[[nodiscard]] Cidr enclosing(const std::vector<Cidr>& networks);
[[nodiscard]] std::vector<Cidr> collapse(const std::vector<Cidr>& networks);
[[nodiscard]] std::vector<Cidr> range_to_cidrs(const Range& range);
// IPv4 only; max_results bounds output size / allocation.
[[nodiscard]] std::vector<Cidr> split_ipv4(const Cidr& parent, std::uint8_t new_prefix,
                                           std::size_t max_results = 65536);
// IPv4 only, largest-first deterministic placement; requests must have unique labels.
[[nodiscard]] std::vector<Allocation> allocate_vlsm(const Cidr& parent,
                                                     const std::vector<HostRequest>& requests);
[[nodiscard]] std::string inspect(const Cidr& network);
} // namespace xorcist::planning
