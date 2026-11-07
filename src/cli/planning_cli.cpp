// SPDX-License-Identifier: MIT
#include "planning_cli.hpp"
#include "xorcist/net.hpp" // Preserve original IPv4 inspect display contract.
#include "xorcist/planning.hpp"

#include <charconv>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace xorcist::cli {
namespace {
using namespace xorcist::planning;
void exact_count(const std::vector<std::string>& args, std::size_t count, std::string_view help) {
    if (args.size() != count) throw std::invalid_argument(std::string(help));
}
std::uint64_t number(std::string_view s, std::uint64_t cap) {
    if (s.empty() || (s.size() > 1 && s.front() == '0')) throw std::invalid_argument("invalid number");
    std::uint64_t value{};
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    if (ec != std::errc{} || ptr != s.data() + s.size() || value > cap)
        throw std::invalid_argument("invalid or out-of-range number");
    return value;
}
ListFormat fmt(std::string_view name) {
    if (name == "lines") return ListFormat::Lines;
    if (name == "csv") return ListFormat::Csv;
    throw std::invalid_argument("expected format 'lines' or 'csv'");
}
std::vector<Cidr> list_args(const std::vector<std::string>& args) {
    std::vector<Cidr> result;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--file") {
            if (++i >= args.size()) throw std::invalid_argument("--file requires an input path");
            const auto list = load_list(args[i], ListFormat::Lines);
            result.insert(result.end(), list.begin(), list.end());
        } else if (!args[i].empty() && args[i].starts_with("--")) {
            throw std::invalid_argument("unknown option: " + args[i]);
        } else result.push_back(parse_cidr(args[i]));
    }
    if (result.empty() || result.size() > 50000)
        throw std::invalid_argument("expected 1..50000 CIDR networks");
    return result;
}
void print_cidrs(const std::vector<Cidr>& list) {
    for (const auto& n : list) std::cout << n.str() << '\n';
}
} // namespace
int run_net(const std::vector<std::string>& args) {
    if (args.size() < 2) throw std::invalid_argument("expected net action and arguments (see --help)");
    const std::string& action = args[1];
    const std::vector<std::string> tail(args.begin() + 2, args.end());
    if (action == "inspect") {
        exact_count(tail, 1, "net inspect <CIDR>");
        const auto value = parse_cidr(tail[0]);
        if (value.network.family == Family::IPv4)
            std::cout << net::inspect(net::parse_cidr(tail[0]));
        else std::cout << inspect(value);
    } else if (action == "summarize") {
        const auto result = enclosing(list_args(tail));
        std::cout << "Supernet: " << result.str() << '\n';
        if (result.network.family == Family::IPv4)
            std::cout << "Mask:     " << net::format_ipv4(net::parse_cidr(result.str()).mask()) << '\n';
    } else if (action == "collapse") {
        print_cidrs(collapse(list_args(tail)));
    } else if (action == "contains") {
        exact_count(tail, 2, "net contains <CIDR> <IP>");
        std::cout << (contains(parse_cidr(tail[0]), parse_address(tail[1])) ? "yes" : "no") << '\n';
    } else if (action == "covers") {
        exact_count(tail, 2, "net covers <OUTER-CIDR> <INNER-CIDR>");
        std::cout << (covers(parse_cidr(tail[0]), parse_cidr(tail[1])) ? "yes" : "no") << '\n';
    } else if (action == "overlap") {
        exact_count(tail, 2, "net overlap <CIDR> <CIDR>");
        std::cout << (overlaps(parse_cidr(tail[0]), parse_cidr(tail[1])) ? "yes" : "no") << '\n';
    } else if (action == "intersect") {
        exact_count(tail, 2, "net intersect <CIDR> <CIDR>");
        const auto result = intersection(parse_cidr(tail[0]), parse_cidr(tail[1]));
        std::cout << (result ? result->str() : "none") << '\n';
    } else if (action == "range") {
        exact_count(tail, 2, "net range <FIRST-IP> <LAST-IP>");
        print_cidrs(range_to_cidrs(parse_range(tail[0], tail[1])));
    } else if (action == "split") {
        exact_count(tail, 2, "net split <IPv4-CIDR> <NEW-PREFIX>");
        print_cidrs(split_ipv4(parse_cidr(tail[0]),
            static_cast<std::uint8_t>(number(tail[1], 32))));
    } else if (action == "vlsm") {
        if (tail.size() < 2) throw std::invalid_argument("net vlsm <IPv4-CIDR> <LABEL=HOSTS>...");
        const auto parent = parse_cidr(tail[0]);
        std::vector<HostRequest> requests;
        for (std::size_t i = 1; i < tail.size(); ++i) {
            const auto sep = tail[i].find('=');
            if (sep == std::string::npos || sep == 0) throw std::invalid_argument("expected LABEL=HOSTS");
            requests.push_back({tail[i].substr(0, sep), number(tail[i].substr(sep + 1), 4294967294ULL)});
        }
        for (const auto& allocation : allocate_vlsm(parent, requests))
            std::cout << allocation.request.name << "," << allocation.request.hosts << ","
                      << allocation.network.str() << '\n';
    } else if (action == "conflicts") {
        const auto networks = list_args(tail);
        const auto found = conflicts(networks);
        if (found.empty()) std::cout << "none\n";
        for (const auto& [a, b] : found)
            std::cout << networks[a].str() << " overlaps " << networks[b].str() << '\n';
    } else if (action == "convert") {
        std::string input, output;
        ListFormat from = ListFormat::Lines, to = ListFormat::Csv;
        bool seen_in = false, seen_out = false, seen_from = false, seen_to = false;
        for (std::size_t i = 0; i < tail.size(); i += 2) {
            if (i + 1 >= tail.size()) throw std::invalid_argument("net convert expects option/value pairs");
            const auto& flag = tail[i];
            if (flag == "--in" && !seen_in) { input = tail[i + 1]; seen_in = true; }
            else if (flag == "--out" && !seen_out) { output = tail[i + 1]; seen_out = true; }
            else if (flag == "--from" && !seen_from) { from = fmt(tail[i + 1]); seen_from = true; }
            else if (flag == "--to" && !seen_to) { to = fmt(tail[i + 1]); seen_to = true; }
            else throw std::invalid_argument("unknown or duplicated conversion option: " + flag);
        }
        if (!seen_in || !seen_out || input.empty() || output.empty())
            throw std::invalid_argument("net convert --in FILE --out FILE [--from lines|csv] [--to lines|csv]");
        const auto networks = load_list(input, from);
        save_list(output, networks, to);
        std::cout << "Wrote " << networks.size() << " networks to " << output << '\n';
    } else throw std::invalid_argument("unknown net command: " + action);
    return 0;
}
} // namespace xorcist::cli
