// SPDX-License-Identifier: MIT
#include "xorcist/legacy.hpp"
#include "xorcist/net.hpp"
#include "xorcist/xor.hpp"

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
int tests = 0;
void check(bool truth, const char* message) {
    ++tests;
    if (!truth) throw std::runtime_error(message);
}
template <typename Fn> void fails(Fn&& fn) {
    try { fn(); } catch (const std::exception&) { ++tests; return; }
    throw std::runtime_error("expected error, succeeded");
}
} // namespace

int main() {
    try {
        using namespace xorcist;
        using net::parse_cidr;
        check(parse_cidr("192.168.1.17/24").cidr() == "192.168.1.0/24", "network normalization");
        check(parse_cidr("0.0.0.0/0").mask() == 0U, "/0 mask");
        check(parse_cidr("255.255.255.255/32").broadcast() == 0xFFFFFFFFU, "/32 broadcast");
        check(parse_cidr("192.0.2.0/31").broadcast() == 0xC0000201U, "/31 broadcast");
        check(net::inspect(parse_cidr("192.0.2.0/31")).find("RFC 3021") != std::string::npos, "/31 semantics");
        check(net::enclosing_supernet({parse_cidr("192.168.1.1/24"), parse_cidr("192.168.2.1/24")}).cidr()
              == "192.168.0.0/22", "legacy supernet example");
        check(net::enclosing_supernet({parse_cidr("10.5.0.0/16"), parse_cidr("10.5.8.1/32")}).cidr()
              == "10.5.0.0/16", "full subnet ranges matter");
        check(net::enclosing_supernet({parse_cidr("0.0.0.0/1"), parse_cidr("128.0.0.0/1")}).cidr()
              == "0.0.0.0/0", "/0 supernet");
        check(net::enclosing_supernet({parse_cidr("203.0.113.9/32")}).cidr()
              == "203.0.113.9/32", "single /32");
        auto merged = net::collapse({parse_cidr("10.0.0.128/25"), parse_cidr("10.0.0.0/25")});
        check(merged.size() == 1 && merged[0].cidr() == "10.0.0.0/24", "siblings collapse");
        merged = net::collapse({parse_cidr("10.0.1.0/24"), parse_cidr("10.0.0.0/24"),
                                parse_cidr("10.0.1.128/25"), parse_cidr("10.0.2.0/24")});
        check(merged.size() == 2 && merged[0].cidr() == "10.0.0.0/23" &&
              merged[1].cidr() == "10.0.2.0/24", "exact aggregate without addresses outside range");
        merged = net::collapse({parse_cidr("0.0.0.0/1"), parse_cidr("128.0.0.0/1")});
        check(merged.size() == 1 && merged[0].cidr() == "0.0.0.0/0", "collapse whole IPv4");
        check(net::parse_network_list("# hi\n192.0.2.1/24 # comment\n198.51.100.1/25\n").size() == 2,
              "parse network lists");
        for (const auto bad : {"", "192.168.1.1", "256.2.3.4/24", "192.168.1.1/33", "-1.2.3.4/8",
                               "1.2.3/24", "1.2.3.4.5/24", "001.2.3.4/24", "1.2.3.4/-1", "1.2.3.4/24a",
                               "1.2.3.4//24", "1.2.3.4 /24", "1.2.3.4/00"})
            fails([&] { (void)parse_cidr(bad); });
        fails([&] { (void)net::enclosing_supernet({}); });
        fails([&] { (void)net::collapse({}); });
        fails([&] { (void)net::parse_network_list("good\nbad/33"); });

        const auto key = xor_tool::hex_decode("0010feff");
        const auto input = xor_tool::to_bytes("Hello, XORcist 2.0!\n");
        const auto enc = xor_tool::transform(input, key);
        check(xor_tool::transform(enc, key) == input, "binary xor involution");
        check(xor_tool::hex_decode(xor_tool::hex_encode(enc)) == enc, "hex round trip");
        check(xor_tool::hex_encode(xor_tool::to_bytes("Hi")) == "4869", "hex canonical encoding");
        check(xor_tool::escaped_text(xor_tool::to_bytes("Hi\n")) == "Hi\\n", "safe terminal escape");
        for (const auto bad : {"", "1", "xx", "123", "0G", " 01"})
            fails([&] { (void)xor_tool::hex_decode(bad); });
        fails([&] { (void)xor_tool::transform(input, {}); });

        // Include deterministic generated inputs across all non-empty key lengths.
        std::mt19937 rng(0xAC1D);
        for (std::size_t key_len = 1; key_len <= 47; ++key_len) {
            xor_tool::Bytes random_key(key_len), random_data(key_len * 27 + 3);
            for (auto& b : random_key) b = static_cast<std::byte>(rng() & 255U);
            for (auto& b : random_data) b = static_cast<std::byte>(rng() & 255U);
            check(xor_tool::transform(xor_tool::transform(random_data, random_key), random_key) == random_data,
                  "randomized XOR roundtrip");
        }
        // Actual original files are included only as a compatibility test fixture.
        const auto recovered = legacy::decrypt_java_2019(XORCIST_LEGACY_KEYS, XORCIST_LEGACY_CIPHER);
        check(!recovered.empty(), "recover original fixture");
        check(xor_tool::escaped_text(recovered) == "XORcist legacy fixture", "verify synthetic legacy fixture content");

        const auto temp = std::filesystem::temp_directory_path() /
            ("xorcist-2-tests-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        // Create only a directory owned by this test run. Never delete a preexisting path.
        check(std::filesystem::create_directory(temp), "create exclusive test directory");
        try {
            const auto a = temp / "a.bin", b = temp / "b.bin", c = temp / "c.bin";
            xor_tool::Bytes file_input(3 * 65536 + 5);
            for (std::size_t i = 0; i < file_input.size(); ++i)
                file_input[i] = static_cast<std::byte>(i & 255U);
            xor_tool::write_new_file(a, file_input);
            fails([&] { xor_tool::write_new_file(a, input); });
            xor_tool::transform_file(a, b, key);
            xor_tool::transform_file(b, c, key);
            std::ifstream source(c, std::ios::binary);
            const std::string file_back{std::istreambuf_iterator<char>(source), std::istreambuf_iterator<char>()};
            check(file_back == std::string(reinterpret_cast<const char*>(file_input.data()), file_input.size()),
                  "binary file streaming across chunk boundary");
            fails([&] { xor_tool::transform_file(a, a, key); });
            fails([&] { xor_tool::transform_file(a, b, key); });
        } catch (...) { std::filesystem::remove_all(temp); throw; }
        std::filesystem::remove_all(temp);
        std::cout << tests << " checks passed.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAILED after " << tests << " checks: " << e.what() << '\n';
        return 1;
    }
}
