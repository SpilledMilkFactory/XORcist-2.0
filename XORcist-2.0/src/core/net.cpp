// SPDX-License-Identifier: MIT
#include "xorcist/net.hpp"

#include <algorithm>
#include <bit>
#include <charconv>
#include <cctype>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace xorcist::net {
namespace {
std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())) != 0) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())) != 0) s.remove_suffix(1);
    return s;
}

unsigned parse_decimal(std::string_view s, unsigned ceiling) {
    if (s.empty() || (s.size() > 1 && s.front() == '0'))
        throw std::invalid_argument("invalid decimal number (leading zeros are not allowed)");
    unsigned value = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    if (ec != std::errc{} || ptr != s.data() + s.size() || value > ceiling)
        throw std::invalid_argument("decimal value out of range or malformed");
    return value;
}
} // namespace

std::uint32_t Network::mask() const noexcept {
    return prefix == 0 ? 0U : (0xFFFFFFFFU << (32U - prefix));
}
std::uint32_t Network::broadcast() const noexcept {
    return address | ~mask();
}
std::string Network::cidr() const {
    return format_ipv4(address) + "/" + std::to_string(prefix);
}
std::string format_ipv4(std::uint32_t address) {
    return std::to_string((address >> 24U) & 255U) + "." +
           std::to_string((address >> 16U) & 255U) + "." +
           std::to_string((address >> 8U) & 255U) + "." +
           std::to_string(address & 255U);
}
Network parse_cidr(std::string_view input) {
    input = trim(input);
    const auto slash = input.find('/');
    if (slash == std::string_view::npos || input.find('/', slash + 1) != std::string_view::npos)
        throw std::invalid_argument("expected IPv4 address with CIDR prefix (e.g. 192.0.2.1/24)");
    const auto dotted = input.substr(0, slash);
    const auto bits = input.substr(slash + 1);
    const auto p = parse_decimal(bits, 32);
    std::uint32_t address = 0;
    std::size_t begin = 0;
    for (int i = 0; i < 4; ++i) {
        const auto dot = dotted.find('.', begin);
        if ((i != 3 && dot == std::string_view::npos) ||
            (i == 3 && dot != std::string_view::npos))
            throw std::invalid_argument("IPv4 address must have exactly four octets");
        const auto end = dot == std::string_view::npos ? dotted.size() : dot;
        const auto octet = parse_decimal(dotted.substr(begin, end - begin), 255);
        address = (address << 8U) | octet;
        begin = end + 1;
    }
    Network n{address, static_cast<std::uint8_t>(p)};
    n.address &= n.mask();
    return n;
}
std::vector<Network> parse_network_list(std::string_view input) {
    std::vector<Network> networks;
    std::istringstream lines{std::string(input)};
    std::string line;
    std::size_t line_no = 0;
    while (std::getline(lines, line)) {
        ++line_no;
        if (const auto comment = line.find('#'); comment != std::string::npos)
            line.erase(comment);
        std::istringstream tokens(line);
        std::string token;
        while (tokens >> token) {
            try { networks.push_back(parse_cidr(token)); }
            catch (const std::exception& e) {
                throw std::invalid_argument("line " + std::to_string(line_no) + ", '" + token + "': " + e.what());
            }
        }
    }
    return networks;
}
Network enclosing_supernet(const std::vector<Network>& networks) {
    if (networks.empty()) throw std::invalid_argument("at least one IPv4/CIDR network is required");
    std::uint32_t lowest = std::numeric_limits<std::uint32_t>::max();
    std::uint32_t highest = 0;
    for (const auto& network : networks) {
        if (network.prefix > 32 || (network.address & ~network.mask()) != 0)
            throw std::invalid_argument("invalid or unnormalized network");
        lowest = std::min(lowest, network.address);
        highest = std::max(highest, network.broadcast());
    }
    const auto prefix = static_cast<std::uint8_t>(std::countl_zero(lowest ^ highest));
    Network result{lowest, prefix};
    result.address &= result.mask();
    return result;
}
std::vector<Network> collapse(const std::vector<Network>& networks) {
    if (networks.empty()) throw std::invalid_argument("at least one IPv4/CIDR network is required");
    using Range = std::pair<std::uint64_t, std::uint64_t>;
    std::vector<Range> ranges;
    ranges.reserve(networks.size());
    for (const auto& network : networks) {
        if (network.prefix > 32 || (network.address & ~network.mask()) != 0)
            throw std::invalid_argument("invalid or unnormalized network");
        ranges.emplace_back(network.address, network.broadcast());
    }
    std::sort(ranges.begin(), ranges.end());
    std::vector<Range> joined;
    for (const auto& [lo, hi] : ranges) {
        if (!joined.empty() && lo <= joined.back().second + 1U)
            joined.back().second = std::max(hi, joined.back().second);
        else
            joined.emplace_back(lo, hi);
    }

    std::vector<Network> result;
    for (const auto& [begin, end] : joined) {
        std::uint64_t pos = begin;
        while (pos <= end) {
            // Pick the largest block aligned at pos and fully within the range.
            for (unsigned prefix = 0; prefix <= 32; ++prefix) {
                const std::uint64_t block = std::uint64_t{1} << (32U - prefix);
                if ((pos % block) == 0 && block <= end - pos + 1U) {
                    result.push_back(Network{static_cast<std::uint32_t>(pos),
                                             static_cast<std::uint8_t>(prefix)});
                    pos += block;
                    break;
                }
            }
        }
    }
    return result;
}
std::string inspect(const Network& network) {
    if (network.prefix > 32 || (network.address & ~network.mask()) != 0)
        throw std::invalid_argument("invalid or unnormalized network");
    const auto total = std::uint64_t{1} << (32U - network.prefix);
    const auto usable = network.prefix >= 31 ? total : total - 2;
    std::ostringstream out;
    out << "Network:       " << network.cidr() << '\n'
        << "Subnet mask:   " << format_ipv4(network.mask()) << '\n'
        << "Broadcast:     " << format_ipv4(network.broadcast()) << '\n'
        << "Total addresses: " << total << '\n'
        << "Usable addresses: " << usable << '\n';
    if (network.prefix == 32) {
        out << "Host address:  " << format_ipv4(network.address) << '\n';
    } else if (network.prefix == 31) {
        out << "Point-to-point endpoints (RFC 3021): " << format_ipv4(network.address)
            << " - " << format_ipv4(network.broadcast()) << '\n';
    } else {
        out << "Usable range:  " << format_ipv4(network.address + 1U)
            << " - " << format_ipv4(network.broadcast() - 1U) << '\n';
    }
    return out.str();
}
} // namespace xorcist::net
