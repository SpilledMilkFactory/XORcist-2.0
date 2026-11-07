// SPDX-License-Identifier: MIT
#include "xorcist/legacy.hpp"
#include "xorcist/net.hpp"
#include "xorcist/xor.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
void usage(std::ostream& out) {
    out << R"(XORcist 2.0 - networking and XOR utility (XOR IS NOT SECURE ENCRYPTION)

Usage:
  xorcist net inspect <IPv4/CIDR>
  xorcist net summarize <IPv4/CIDR>... [--file networks.txt]
  xorcist net collapse <IPv4/CIDR>... [--file networks.txt]
  xorcist xor text --text "Hello!" --key-hex 010203
  xorcist xor hex --hex 49666f --key-hex 010203
  xorcist xor file --in original.bin --out transformed.bin --key-hex 010203
  xorcist legacy-decrypt --keys old/keys.dat --cipher old/cipherText.dat [--out recovered.txt]
  xorcist --help

XOR text/hex print hexadecimal bytes; applying the same key twice recovers the input.
Never reuse repeating-key XOR for sensitive data; it provides no authentication.
Output files must not exist. Input files are never overwritten.
Networks must be IPv4 with explicit /0 through /32 prefixes; use # comments in files.
)";
}
std::string option(const std::vector<std::string>& args, std::string_view flag, bool required = true) {
    std::string result;
    bool seen = false;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == flag) {
            if (seen || i + 1 == args.size() || args[i + 1].starts_with("--"))
                throw std::invalid_argument("missing or repeated option: " + std::string(flag));
            seen = true;
            result = args[i + 1];
        }
    }
    if (required && !seen) throw std::invalid_argument("missing required option: " + std::string(flag));
    return result;
}
void validate_flags(const std::vector<std::string>& args,
                    const std::vector<std::string_view>& flags) {
    for (std::size_t i = 0; i < args.size(); ++i) {
        bool known = false;
        for (const auto flag : flags) if (args[i] == flag) known = true;
        if (!known || i + 1 == args.size() || args[i + 1].starts_with("--"))
            throw std::invalid_argument("unknown option or missing argument: " + args[i]);
        ++i;
    }
}
std::string load_file(const std::filesystem::path& path) {
    if (!std::filesystem::is_regular_file(path) || std::filesystem::file_size(path) > 1024U * 1024U)
        throw std::invalid_argument("network list must be a regular file no larger than 1 MiB");
    std::ifstream source(path, std::ios::binary);
    if (!source) throw std::runtime_error("cannot read network list: " + path.string());
    return {std::istreambuf_iterator<char>(source), std::istreambuf_iterator<char>()};
}
std::vector<xorcist::net::Network> read_network_args(const std::vector<std::string>& args) {
    std::vector<xorcist::net::Network> list;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--file") {
            if (i + 1 >= args.size() || args[i + 1].starts_with("--"))
                throw std::invalid_argument("--file requires a filename");
            const auto file = xorcist::net::parse_network_list(load_file(args[++i]));
            list.insert(list.end(), file.begin(), file.end());
        } else if (args[i].starts_with("--")) {
            throw std::invalid_argument("unknown option: " + args[i]);
        } else {
            list.push_back(xorcist::net::parse_cidr(args[i]));
        }
    }
    if (list.empty()) throw std::invalid_argument("at least one network is required");
    return list;
}
} // namespace

int main(int argc, char** argv) {
    try {
        std::vector<std::string> args(argv + 1, argv + argc);
        if (args.empty() || args[0] == "--help" || args[0] == "-h") { usage(std::cout); return 0; }
        const auto group = args[0];
        if (group == "net") {
            if (args.size() < 3) throw std::invalid_argument("expected net inspect|summarize|collapse and arguments");
            const auto action = args[1];
            std::vector<std::string> tail(args.begin() + 2, args.end());
            if (action == "inspect") {
                if (tail.size() != 1) throw std::invalid_argument("inspect expects exactly one IPv4/CIDR");
                std::cout << xorcist::net::inspect(xorcist::net::parse_cidr(tail[0]));
            } else if (action == "summarize") {
                const auto net = xorcist::net::enclosing_supernet(read_network_args(tail));
                std::cout << "Supernet: " << net.cidr() << "\nMask:     "
                          << xorcist::net::format_ipv4(net.mask()) << "\n";
            } else if (action == "collapse") {
                for (const auto& net : xorcist::net::collapse(read_network_args(tail)))
                    std::cout << net.cidr() << '\n';
            } else throw std::invalid_argument("unknown net command: " + action);
            return 0;
        }
        if (group == "xor") {
            if (args.size() < 3) throw std::invalid_argument("expected xor text|hex|file");
            const auto action = args[1];
            std::vector<std::string> tail(args.begin() + 2, args.end());
            if (action == "text") validate_flags(tail, {"--text", "--key-hex"});
            else if (action == "hex") validate_flags(tail, {"--hex", "--key-hex"});
            else if (action == "file") validate_flags(tail, {"--in", "--out", "--key-hex"});
            else throw std::invalid_argument("unknown XOR command: " + action);
            const auto key = xorcist::xor_tool::hex_decode(option(tail, "--key-hex"));
            if (action == "text") {
                const auto input = xorcist::xor_tool::to_bytes(option(tail, "--text"));
                std::cout << xorcist::xor_tool::hex_encode(xorcist::xor_tool::transform(input, key)) << '\n';
            } else if (action == "hex") {
                const auto input = xorcist::xor_tool::hex_decode(option(tail, "--hex"));
                const auto decoded = xorcist::xor_tool::transform(input, key);
                std::cout << "Hex:  " << xorcist::xor_tool::hex_encode(decoded) << '\n'
                          << "Text: " << xorcist::xor_tool::escaped_text(decoded) << '\n';
            } else {
                xorcist::xor_tool::transform_file(option(tail, "--in"), option(tail, "--out"), key);
                std::cout << "File transformed successfully.\n";
            }
            return 0;
        }
        if (group == "legacy-decrypt") {
            std::vector<std::string> tail(args.begin() + 1, args.end());
            validate_flags(tail, {"--keys", "--cipher", "--out"});
            const auto plain = xorcist::legacy::decrypt_java_2019(option(tail, "--keys"), option(tail, "--cipher"));
            const auto dest = option(tail, "--out", false);
            if (dest.empty()) {
                std::cout << "Recovered text (escaped): " << xorcist::xor_tool::escaped_text(plain) << '\n';
                std::cout << "Recovered hex: " << xorcist::xor_tool::hex_encode(plain) << '\n';
            } else {
                xorcist::xor_tool::write_new_file(dest, plain);
                std::cout << "Recovered legacy data written to " << dest << '\n';
            }
            return 0;
        }
        throw std::invalid_argument("unknown command: " + group);
    } catch (const std::exception& error) {
        std::cerr << "xorcist: " << error.what() << "\nTry 'xorcist --help'.\n";
        return 2;
    }
}
