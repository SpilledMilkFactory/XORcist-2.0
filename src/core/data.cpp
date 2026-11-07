// SPDX-License-Identifier: MIT
#include "xorcist/data.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace xorcist::data {
namespace {
int base64_digit(unsigned char c) noexcept {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
std::ifstream regular_input(const std::filesystem::path& input) {
    if (!std::filesystem::is_regular_file(input)) throw std::invalid_argument("input must be a regular file");
    std::ifstream file(input, std::ios::binary);
    if (!file) throw std::runtime_error("cannot open input file: " + input.string());
    return file;
}
} // namespace

std::string base64_encode(std::span<const std::byte> bytes) {
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (bytes.size() > (std::string{}.max_size() - 4) / 4 * 3)
        throw std::length_error("input too large for Base64");
    std::string result;
    result.reserve((bytes.size() / 3 + (bytes.size() % 3 != 0)) * 4);
    for (std::size_t i = 0; i < bytes.size(); i += 3) {
        const auto a = std::to_integer<unsigned>(bytes[i]);
        const auto b = i + 1 < bytes.size() ? std::to_integer<unsigned>(bytes[i + 1]) : 0U;
        const auto c = i + 2 < bytes.size() ? std::to_integer<unsigned>(bytes[i + 2]) : 0U;
        result.push_back(alphabet[a >> 2]);
        result.push_back(alphabet[((a & 3U) << 4) | (b >> 4)]);
        result.push_back(i + 1 < bytes.size() ? alphabet[((b & 15U) << 2) | (c >> 6)] : '=');
        result.push_back(i + 2 < bytes.size() ? alphabet[c & 63U] : '=');
    }
    return result;
}

Bytes base64_decode(std::string_view s) {
    if (s.size() % 4 != 0) throw std::invalid_argument("Base64 must contain complete quartets");
    Bytes result;
    if (s.size() / 4 > result.max_size() / 3) throw std::length_error("Base64 input too large");
    result.reserve(s.size() / 4 * 3);
    for (std::size_t i = 0; i < s.size(); i += 4) {
        const int a = base64_digit(static_cast<unsigned char>(s[i]));
        const int b = base64_digit(static_cast<unsigned char>(s[i + 1]));
        const bool pad_c = s[i + 2] == '=';
        const bool pad_d = s[i + 3] == '=';
        const int c = pad_c ? 0 : base64_digit(static_cast<unsigned char>(s[i + 2]));
        const int d = pad_d ? 0 : base64_digit(static_cast<unsigned char>(s[i + 3]));
        if (a < 0 || b < 0 || c < 0 || d < 0 || (pad_c && !pad_d) ||
            ((pad_c || pad_d) && i + 4 != s.size()) ||
            (pad_c && (b & 15) != 0) || (pad_d && !pad_c && (c & 3) != 0))
            throw std::invalid_argument("malformed or noncanonical Base64");
        result.push_back(static_cast<std::byte>((a << 2) | (b >> 4)));
        if (!pad_c) result.push_back(static_cast<std::byte>(((b & 15) << 4) | (c >> 2)));
        if (!pad_d) result.push_back(static_cast<std::byte>(((c & 3) << 6) | d));
    }
    return result;
}

Bytes mask_bytes(std::span<const std::byte> value, std::span<const std::byte> mask,
                 std::string_view operation) {
    if (value.empty() || value.size() != mask.size())
        throw std::invalid_argument("value and mask must be nonempty and the same length");
    if (operation != "and" && operation != "or" && operation != "xor" && operation != "not")
        throw std::invalid_argument("operation must be and, or, xor or not");
    Bytes result(value.begin(), value.end());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (operation == "and") result[i] &= mask[i];
        else if (operation == "or") result[i] |= mask[i];
        else if (operation == "xor") result[i] ^= mask[i];
        else result[i] = ~result[i];
    }
    return result;
}
std::string bit_string(std::span<const std::byte> input) {
    std::string s;
    if (input.size() > s.max_size() / 8) throw std::length_error("bit representation too large");
    s.reserve(input.size() * 8);
    for (const auto value : input) {
        const unsigned v = std::to_integer<unsigned>(value);
        for (int i = 7; i >= 0; --i) s.push_back(((v >> static_cast<unsigned>(i)) & 1U) ? '1' : '0');
    }
    return s;
}
Bytes read_small_file(const std::filesystem::path& input, std::size_t max_bytes) {
    if (!std::filesystem::is_regular_file(input)) throw std::invalid_argument("input must be a regular file");
    const auto size = std::filesystem::file_size(input);
    if (size > max_bytes) throw std::invalid_argument("input exceeds the bounded transform size");
    auto file = regular_input(input);
    Bytes result(static_cast<std::size_t>(size));
    if (!result.empty() && !file.read(reinterpret_cast<char*>(result.data()),
                                      static_cast<std::streamsize>(result.size())))
        throw std::runtime_error("input changed or became unreadable");
    if (file.peek() != std::char_traits<char>::eof())
        throw std::runtime_error("input changed while reading");
    if (file.bad()) throw std::runtime_error("input read failed");
    return result;
}
std::string hexdump_file(const std::filesystem::path& input, std::size_t max_bytes) {
    if (max_bytes == 0 || max_bytes > 4096) throw std::invalid_argument("inspection limit must be 1..4096");
    auto file = regular_input(input);
    std::array<unsigned char, 16> line{};
    std::ostringstream out;
    std::size_t offset = 0;
    while (offset < max_bytes) {
        const auto want = std::min(line.size(), max_bytes - offset);
        file.read(reinterpret_cast<char*>(line.data()), static_cast<std::streamsize>(want));
        const auto n = static_cast<std::size_t>(file.gcount());
        if (!n) break;
        out << std::hex << std::setw(8) << std::setfill('0') << offset << "  ";
        for (std::size_t i = 0; i < 16; ++i) {
            if (i < n) out << std::setw(2) << static_cast<unsigned>(line[i]) << ' ';
            else out << "   ";
        }
        out << " |";
        for (std::size_t i = 0; i < n; ++i)
            out << (line[i] >= 32 && line[i] <= 126 ? static_cast<char>(line[i]) : '.');
        out << "|\n";
        offset += n;
        if (n < want) break;
    }
    if (file.bad()) throw std::runtime_error("inspection read failed");
    return out.str();
}
std::string diff_files(const std::filesystem::path& left, const std::filesystem::path& right,
                       std::size_t max_differences) {
    if (max_differences == 0 || max_differences > 1024)
        throw std::invalid_argument("difference limit must be 1..1024");
    auto a = regular_input(left);
    auto b = regular_input(right);
    constexpr std::size_t size = 65536;
    std::array<char, size> x{}, y{};
    std::uint64_t offset = 0, differences = 0;
    std::ostringstream out;
    while (true) {
        a.read(x.data(), static_cast<std::streamsize>(size));
        b.read(y.data(), static_cast<std::streamsize>(size));
        const auto na = static_cast<std::size_t>(a.gcount()), nb = static_cast<std::size_t>(b.gcount());
        if (a.bad() || b.bad()) throw std::runtime_error("file comparison read failed");
        const auto n = std::max(na, nb);
        for (std::size_t i = 0; i < n; ++i) {
            if (i >= na || i >= nb || x[i] != y[i]) {
                if (++differences <= max_differences) {
                    out << "offset " << (offset + i) << ": ";
                    if (i < na) out << std::hex << std::setw(2) << std::setfill('0')
                                    << static_cast<unsigned>(static_cast<unsigned char>(x[i]));
                    else out << "EOF";
                    out << " vs ";
                    if (i < nb) out << std::hex << std::setw(2) << std::setfill('0')
                                    << static_cast<unsigned>(static_cast<unsigned char>(y[i]));
                    else out << "EOF";
                    out << "\n" << std::dec;
                }
            }
        }
        offset += n;
        if (na < size && nb < size) break;
    }
    if (differences == 0) return "Files identical.\n";
    out << "Total differing byte positions: " << differences << '\n';
    if (differences > max_differences) out << "Output limited to first " << max_differences << " differences.\n";
    return out.str();
}
} // namespace xorcist::data
