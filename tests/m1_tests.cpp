// SPDX-License-Identifier: MIT
#include "xorcist/planning.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
std::uint64_t checks{};
void check(bool ok, std::string_view label) {
    ++checks;
    if (!ok) throw std::runtime_error(std::string(label));
}
template <typename F> void rejects(F&& f, std::string_view label) {
    bool threw = false;
    try { f(); } catch (const std::exception&) { threw = true; }
    check(threw, label);
}
} // namespace

int main() {
    using namespace xorcist::planning;
    try {
        check(parse_address("::").str() == "::", "IPv6 all-zero canonical form");
        check(parse_address("FFFF:0:0:0:0:0:0:1").str() == "ffff::1", "canonical lowercase/zero compression");
        check(parse_address("2001:db8:0:1:0:0:0:1").str() == "2001:db8:0:1::1", "longest zero run");
        check(parse_address("2001:0:0:1:0:0:1:1").str() == "2001::1:0:0:1:1", "leftmost equal length run");
        check(parse_address("::ffff:192.0.2.1").str() == "::ffff:192.0.2.1", "embedded IPv4 suffix");
        check(parse_cidr("2001:db8:1234::babe/32").str() == "2001:db8::/32", "IPv6 CIDR normalization");
        check(parse_cidr("::/0").str() == "::/0", "IPv6 /0");
        check(parse_cidr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").str() ==
              "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "IPv6 /128");
        check(parse_cidr("192.168.1.9/24").str() == "192.168.1.0/24", "IPv4 backward compatible parse");

        for (const auto* invalid : {"", ":", ":::1", "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9",
                                     "1:2:3:4:5:6:7:", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7::8", "1::2:3:4:5:6:7:8",
                                     "2001:dg8::1", "2001:12345::1", "fe80::1%eth0", "::ffff:256.2.3.4",
                                     "1.2.3.4.5", "01.2.3.4", "1.2.3", "1.2.3.256"}) {
            rejects([&] { (void)parse_address(invalid); }, invalid);
        }
        for (const auto* invalid : {"::/129", "::/-1", "::/00", "::/", "::", "1.2.3.4/33", "1.2.3.4/01", "1.2.3.4/24a"})
            rejects([&] { (void)parse_cidr(invalid); }, invalid);

        check(contains(parse_cidr("2001:db8::/32"), parse_address("2001:db8:ffff::1")), "v6 contains");
        check(!contains(parse_cidr("2001:db8::/32"), parse_address("2001:db9::1")), "v6 outside");
        check(!contains(parse_cidr("2001:db8::/32"), parse_address("10.0.0.1")), "mixed families do not contain");
        check(covers(parse_cidr("10.0.0.0/8"), parse_cidr("10.1.2.0/24")), "covers route");
        check(!covers(parse_cidr("10.1.0.0/16"), parse_cidr("10.0.0.0/8")), "narrow route not covering broad route");
        check(overlaps(parse_cidr("2001:db8::/32"), parse_cidr("2001:db8:1::/48")), "IPv6 overlap");
        check(!overlaps(parse_cidr("2001:db8::/32"), parse_cidr("2001:db9::/32")), "non-overlap");
        check(!overlaps(parse_cidr("::/0"), parse_cidr("0.0.0.0/0")), "IPv6/IPv4 not an overlap");
        check(intersection(parse_cidr("2001:db8::/32"), parse_cidr("2001:db8:1::/48"))->str()
              == "2001:db8:1::/48", "CIDR intersection");
        check(!intersection(parse_cidr("1.1.1.0/24"), parse_cidr("2.2.2.0/24")), "disjoint intersection");
        check(conflicts({parse_cidr("10.0.0.0/8"), parse_cidr("10.0.1.0/24"),
                         parse_cidr("192.168.1.0/24")}).size() == 1, "conflict pair counting");
        check(enclosing({parse_cidr("2001:db8::/32"), parse_cidr("2001:db9::/32")}).str()
              == "2001:db8::/31", "v6 enclosing supernet");
        auto v6 = collapse({parse_cidr("2001:db8::/127"), parse_cidr("2001:db8::2/127")});
        check(v6.size() == 1 && v6[0].str() == "2001:db8::/126", "IPv6 adjacent aggregate");
        v6 = range_to_cidrs(parse_range("2001:db8::", "2001:db8::f"));
        check(v6.size() == 1 && v6[0].str() == "2001:db8::/124", "IPv6 exact range cover");
        v6 = range_to_cidrs(parse_range("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
        check(v6.size() == 1 && v6[0].str() == "::/0", "full IPv6 range");
        check(range_to_cidrs(parse_range("255.255.255.255", "255.255.255.255"))[0].str()
              == "255.255.255.255/32", "max IPv4 endpoint");
        rejects([&] { (void)parse_range("1.1.1.2", "1.1.1.1"); }, "reversed range");
        rejects([&] { (void)parse_range("1.1.1.1", "::1"); }, "mixed-family range");
        rejects([&] { (void)collapse({parse_cidr("::/0"), parse_cidr("0.0.0.0/0")}); }, "mixed-family collapse");
        rejects([&] { (void)enclosing({parse_cidr("::/0"), parse_cidr("0.0.0.0/0")}); }, "mixed-family supernet");
        check(inspect(parse_cidr("2001:db8::/64")).find("2^64") != std::string::npos, "v6 inspect count");

        const auto split = split_ipv4(parse_cidr("10.0.0.0/24"), 26);
        check(split.size() == 4 && split[0].str() == "10.0.0.0/26" &&
              split[3].str() == "10.0.0.192/26", "split into four /26 blocks");
        check(split_ipv4(parse_cidr("0.0.0.0/0"), 0).size() == 1, "split /0 into itself");
        rejects([&] { (void)split_ipv4(parse_cidr("10.0.0.0/24"), 32, 128); }, "split result cap");
        rejects([&] { (void)split_ipv4(parse_cidr("::/0"), 2); }, "no IPv6 split in IPv4 tool");
        const auto allocations = allocate_vlsm(parse_cidr("10.0.0.0/24"),
            {{"iot", 5}, {"lan", 50}, {"wifi", 20}});
        check(allocations.size() == 3 && allocations[0].network.str() == "10.0.0.0/26" &&
              allocations[1].network.str() == "10.0.0.64/27" &&
              allocations[2].network.str() == "10.0.0.96/29", "VLSM largest-first allocation");
        check(conflicts({allocations[0].network, allocations[1].network, allocations[2].network}).empty(),
              "allocated VLSM blocks do not overlap");
        rejects([&] { (void)allocate_vlsm(parse_cidr("192.0.2.0/30"), {{"a", 2}, {"b", 2}}); },
                "VLSM cannot overallocate");
        rejects([&] { (void)allocate_vlsm(parse_cidr("192.0.2.0/24"), {{"a", 5}, {"a", 7}}); },
                "VLSM duplicate name");
        rejects([&] { (void)allocate_vlsm(parse_cidr("192.0.2.0/24"), {{"a", 0}}); },
                "VLSM zero-host request");
        rejects([&] { (void)allocate_vlsm(parse_cidr("::/0"), {{"a", 3}}); },
                "VLSM IPv4-only");
        // Independent small-domain coverage oracle, with 3,000 deterministic IPv4
        // and 3,000 IPv6 cases: no extra addresses, none missing, and each CIDR
        // exactly covers a non-overlapping part of the range.
        std::mt19937 gen(0xA11CE);
        for (unsigned family_index = 0; family_index < 2; ++family_index) {
            const auto addr = [family_index](unsigned x) {
                return family_index == 0 ? "198.51.100." + std::to_string(x) :
                    "2001:db8::" + ([](unsigned v) {
                        constexpr char hex[] = "0123456789abcdef";
                        std::string s;
                        do { s.insert(s.begin(), hex[v % 16]); v /= 16; } while (v != 0);
                        return s;
                    })(x);
            };
            for (unsigned trial = 0; trial < 3000; ++trial) {
                const unsigned lo = gen() % 256;
                const unsigned hi = lo + gen() % (256 - lo);
                const auto cidrs = range_to_cidrs(parse_range(addr(lo), addr(hi)));
                check(!cidrs.empty(), "nonempty range decomposition");
                // Independent oracle: expand each block mathematically within
                // its known /24 (IPv4) or /120 (IPv6) test domain. This does
                // not call the production contains(), overlaps(), or collapse().
                std::array<unsigned, 256> coverage{};
                const unsigned width = family_index == 0 ? 32U : 128U;
                const unsigned last_index = family_index == 0 ? 3U : 15U;
                for (const auto& c : cidrs) {
                    check(c.prefix >= width - 8, "range block remains within test domain");
                    const unsigned block_size = 1U << (width - c.prefix);
                    const unsigned start_octet = c.network.bytes[last_index];
                    check(start_octet + block_size <= 256, "range block does not escape test octet");
                    for (unsigned i = 0; i < block_size; ++i) ++coverage[start_octet + i];
                }
                for (unsigned x = 0; x < 256; ++x)
                    check(coverage[x] == static_cast<unsigned>(x >= lo && x <= hi),
                          "range independent coverage oracle");
                check(collapse(cidrs).size() == cidrs.size(), "already-minimal range decomposition");
            }
        }
        const auto lines = std::string("# comment\n10.0.0.1/24 2001:db8::/32\n");
        const auto imported = parse_list(lines, ListFormat::Lines);
        check(imported.size() == 2, "newline import");
        const auto csv = serialize_list(imported, ListFormat::Csv);
        check(csv == "cidr\n10.0.0.0/24\n2001:db8::/32\n", "canonical CSV export");
        check(parse_list(csv, ListFormat::Csv).size() == 2, "CSV round trip");
        rejects([&] { (void)parse_list("cidr,other\n10.0.0.0/8,example\n", ListFormat::Csv); },
                "reject incompatible multi-column CSV");
        rejects([&] { (void)parse_list("10.0.0.0/8,2001:db8::/32", ListFormat::Csv); },
                "reject invalid CSV content");
        const auto temp = std::filesystem::temp_directory_path() /
            ("xorcist-m1-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        check(std::filesystem::create_directory(temp), "exclusive test directory creation");
        try {
            const auto f = temp / "out.csv";
            save_list(f, imported, ListFormat::Csv);
            check(load_list(f, ListFormat::Csv).size() == 2, "CSV file persistence");
            rejects([&] { save_list(f, imported, ListFormat::Csv); }, "refuse output overwrite");
        } catch (...) { std::filesystem::remove_all(temp); throw; }
        std::filesystem::remove_all(temp);
        std::cout << checks << " M1 checks passed.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "M1 FAILED after " << checks << " checks: " << e.what() << '\n';
        return 1;
    }
}
