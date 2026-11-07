// SPDX-License-Identifier: MIT
// Deterministic, oracle-backed properties for IPv4 CIDR aggregation.
#include "xorcist/net.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void require(bool condition, const char* why) {
    if (!condition) throw std::runtime_error(why);
}

bool contains(const xorcist::net::Network& n, std::uint32_t ip) {
    return (ip & n.mask()) == n.address;
}
}

int main() {
    try {
        using namespace xorcist::net;
        std::mt19937_64 rng(0x584F526369737432ULL); // stable seed; reproducible
        constexpr std::uint32_t base = 0xC6336400U; // 198.51.100.0/24, RFC 5737 TEST-NET-2
        constexpr std::size_t trials = 6000;
        for (std::size_t trial = 0; trial < trials; ++trial) {
            std::vector<Network> inputs;
            std::array<bool, 256> expected{};
            const std::size_t count = 1 + (rng() % 14);
            for (std::size_t i = 0; i < count; ++i) {
                const unsigned prefix = static_cast<unsigned>(24 + (rng() % 9));
                Network n{base + static_cast<std::uint32_t>(rng() % 256), static_cast<std::uint8_t>(prefix)};
                n.address &= n.mask();
                inputs.push_back(n);
                for (std::uint32_t ip = 0; ip < 256; ++ip)
                    if (contains(n, base + ip)) expected[ip] = true;
                require(parse_cidr(n.cidr()).cidr() == n.cidr(), "CIDR stringify/parse property");
            }
            const auto actual = collapse(inputs);
            require(!actual.empty(), "non-empty input produced empty aggregation");
            const auto again = collapse(actual);
            require(actual.size() == again.size(), "aggregation is not idempotent (size)");
            for (std::size_t i = 0; i < actual.size(); ++i) {
                require(actual[i].cidr() == again[i].cidr(), "aggregation is not idempotent (items)");
                require(actual[i].prefix >= 24 && actual[i].address >= base &&
                        actual[i].broadcast() <= base + 255U, "aggregate exceeded controlled oracle range");
                if (i != 0) require(actual[i - 1].broadcast() < actual[i].address,
                                    "aggregate contains overlapping/unsorted blocks");
            }
            for (std::uint32_t ip = 0; ip < 256; ++ip) {
                unsigned actual_matches = 0;
                for (const auto& n : actual)
                    if (contains(n, base + ip)) ++actual_matches;
                require(actual_matches == static_cast<unsigned>(expected[ip]),
                        "aggregate union differs from the independent address-level oracle");
            }
            const auto enclosing = enclosing_supernet(inputs);
            for (const auto& n : inputs) {
                require(contains(enclosing, n.address) && contains(enclosing, n.broadcast()),
                        "enclosing supernet does not cover entire input subnet");
            }
        }
        // Entire address-space boundary / uint32 overflow tests.
        const auto all = collapse({parse_cidr("0.0.0.0/1"), parse_cidr("128.0.0.0/1")});
        require(all.size() == 1 && all[0].cidr() == "0.0.0.0/0", "whole IPv4 span");
        std::cout << "PASS: " << trials << " deterministic CIDR oracle trials (256 addresses each)\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "CIDR property failure: " << e.what() << '\n';
        return 1;
    }
}
