// SPDX-License-Identifier: MIT
#include "xorcist/legacy.hpp"

#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace xorcist::legacy {
namespace {
std::vector<unsigned char> read_small_file(const std::filesystem::path& path) {
    // Legacy records have 16-bit lengths; protect against unexpectedly large files.
    constexpr std::uintmax_t limit = 16U * 1024U * 1024U;
    if (!std::filesystem::is_regular_file(path)) throw std::invalid_argument("not a regular legacy file");
    if (std::filesystem::file_size(path) > limit) throw std::invalid_argument("legacy file exceeds 16 MiB limit");
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open legacy file: " + path.string());
    const auto size = std::filesystem::file_size(path);
    std::vector<unsigned char> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty() && !in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
        throw std::runtime_error("cannot read legacy file: " + path.string());
    return bytes;
}
std::string read_ascii_java_utf(const std::vector<unsigned char>& data, std::size_t& offset) {
    if (offset > data.size() || data.size() - offset < 2) throw std::invalid_argument("truncated Java UTF record length");
    const std::size_t length = (static_cast<unsigned>(data[offset]) << 8U) | data[offset + 1];
    offset += 2;
    if (length > data.size() - offset) throw std::invalid_argument("truncated Java UTF record");
    std::string out;
    out.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        const auto b = data[offset + i];
        if (b > 127 || b == 0) throw std::invalid_argument("legacy record not ASCII (unsupported Java modified UTF-8)");
        out.push_back(static_cast<char>(b));
    }
    offset += length;
    return out;
}
int b64(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
std::vector<unsigned char> decode_b64(const std::string& s) {
    if (s.size() % 4 != 0) throw std::invalid_argument("invalid legacy Base64 length");
    std::vector<unsigned char> decoded;
    decoded.reserve(s.size() / 4 * 3);
    for (std::size_t i = 0; i < s.size(); i += 4) {
        const int a = b64(s[i]), b = b64(s[i + 1]);
        const bool pad2 = s[i + 2] == '=';
        const bool pad3 = s[i + 3] == '=';
        if (a < 0 || b < 0 || (pad2 && !pad3) || ((pad2 || pad3) && i + 4 != s.size()))
            throw std::invalid_argument("invalid legacy Base64 padding/digits");
        const int c = pad2 ? 0 : b64(s[i + 2]);
        const int d = pad3 ? 0 : b64(s[i + 3]);
        if (c < 0 || d < 0 || (pad2 && (b & 15) != 0) || (pad3 && !pad2 && (c & 3) != 0))
            throw std::invalid_argument("invalid legacy Base64 padding/digits");
        decoded.push_back(static_cast<unsigned char>((a << 2) | (b >> 4)));
        if (!pad2) decoded.push_back(static_cast<unsigned char>(((b & 15) << 4) | (c >> 2)));
        if (!pad3) decoded.push_back(static_cast<unsigned char>(((c & 3) << 6) | d));
    }
    return decoded;
}
} // namespace

xor_tool::Bytes decrypt_java_2019(const std::filesystem::path& keys_file,
                                  const std::filesystem::path& ciphertext_file) {
    const auto keys = read_small_file(keys_file);
    const auto cipher = read_small_file(ciphertext_file);
    std::size_t ko = 0, co = 0;
    std::string first_key = read_ascii_java_utf(keys, ko);
    const std::string b64_encoded = read_ascii_java_utf(cipher, co);
    if (co != cipher.size()) throw std::invalid_argument("unexpected extra ciphertext data");
    if (!first_key.empty() && first_key.back() == '\n') first_key.pop_back();
    if (first_key.empty()) throw std::invalid_argument("legacy key was empty");
    for (const auto digit : first_key)
        if (digit != '0' && digit != '1') throw std::invalid_argument("legacy first key was not a binary string");
    const auto mixed = decode_b64(b64_encoded);
    if (mixed.empty() || mixed.size() > first_key.size())
        throw std::invalid_argument("legacy ciphertext/key lengths do not match");
    if (mixed.size() % 8 != 0)
        throw std::invalid_argument("legacy ciphertext has incomplete binary octets");
    xor_tool::Bytes plain;
    plain.reserve(mixed.size() / 8);
    for (std::size_t i = 0; i < mixed.size(); i += 8) {
        unsigned byte = 0;
        for (unsigned j = 0; j < 8; ++j) {
            const auto bit = mixed[i + j] ^ static_cast<unsigned char>(first_key[i + j]);
            if (bit != static_cast<unsigned>('0') && bit != static_cast<unsigned>('1'))
                throw std::invalid_argument("legacy XOR output was not a binary digit");
            byte = (byte << 1U) | (bit == static_cast<unsigned>('1') ? 1U : 0U);
        }
        plain.push_back(static_cast<std::byte>(byte));
    }
    return plain;
}
} // namespace xorcist::legacy
