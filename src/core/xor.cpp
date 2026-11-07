// SPDX-License-Identifier: MIT
#include "xorcist/xor.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <system_error>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace xorcist::xor_tool {
namespace {
int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
std::FILE* open_exclusive(const std::filesystem::path& output) {
#ifdef _WIN32
    int fd = -1;
    const errno_t result = _wsopen_s(&fd, output.c_str(), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                                    _SH_DENYWR, _S_IREAD | _S_IWRITE);
    if (result != 0) throw std::system_error(result, std::generic_category(), "create output");
    auto* file = _fdopen(fd, "wb");
    if (!file) { _close(fd); throw std::runtime_error("fdopen failed"); }
#else
    const int fd = ::open(output.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) throw std::system_error(errno, std::generic_category(), "create output");
    auto* file = ::fdopen(fd, "wb");
    if (!file) { ::close(fd); throw std::runtime_error("fdopen failed"); }
#endif
    return file;
}
void write_all(std::FILE* file, const std::byte* bytes, std::size_t size) {
    if (size != 0 && std::fwrite(bytes, 1, size, file) != size)
        throw std::runtime_error("failed to write output file");
}
} // namespace

Bytes hex_decode(std::string_view hex) {
    if (hex.empty() || hex.size() % 2 != 0)
        throw std::invalid_argument("hex input must contain a nonzero, even number of digits");
    Bytes result;
    result.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int a = hex_value(hex[i]);
        const int b = hex_value(hex[i + 1]);
        if (a < 0 || b < 0) throw std::invalid_argument("invalid hexadecimal digit");
        result.push_back(static_cast<std::byte>((a << 4) | b));
    }
    return result;
}
std::string hex_encode(std::span<const std::byte> data) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (const auto b : data) {
        const auto v = std::to_integer<unsigned>(b);
        result.push_back(digits[v >> 4]);
        result.push_back(digits[v & 15]);
    }
    return result;
}
Bytes to_bytes(std::string_view text) {
    Bytes bytes;
    bytes.reserve(text.size());
    for (char ch : text) bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
    return bytes;
}
std::string escaped_text(std::span<const std::byte> data) {
    constexpr char digits[] = "0123456789ABCDEF";
    std::string result;
    for (const auto b : data) {
        const auto c = std::to_integer<unsigned char>(b);
        if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else if (c == '\\') result += "\\\\";
        else if (c >= 0x20 && c <= 0x7E) result += static_cast<char>(c);
        else { result += "\\x"; result += digits[c >> 4]; result += digits[c & 15]; }
    }
    return result;
}
Bytes transform(std::span<const std::byte> data, std::span<const std::byte> key) {
    if (key.empty()) throw std::invalid_argument("XOR key cannot be empty");
    Bytes result(data.begin(), data.end());
    for (std::size_t i = 0; i < result.size(); ++i) result[i] ^= key[i % key.size()];
    return result;
}
void write_new_file(const std::filesystem::path& output, std::span<const std::byte> data) {
    auto* file = open_exclusive(output);
    bool closed = false;
    try {
        write_all(file, data.data(), data.size());
        const int status = std::fclose(file);
        closed = true;
        if (status != 0) throw std::runtime_error("failed to close output file");
    } catch (...) {
        if (!closed) std::fclose(file);
        std::error_code ec;
        std::filesystem::remove(output, ec);
        throw;
    }
}
void transform_file(const std::filesystem::path& input, const std::filesystem::path& output,
                    std::span<const std::byte> key) {
    if (key.empty()) throw std::invalid_argument("XOR key cannot be empty");
    std::ifstream source(input, std::ios::binary);
    if (!source) throw std::runtime_error("cannot open input file: " + input.string());
    if (!std::filesystem::is_regular_file(input))
        throw std::invalid_argument("input must be a regular file");
    auto* dest = open_exclusive(output);
    bool closed = false;
    try {
        std::array<char, 65536> chunk{};
        std::uint64_t offset = 0;
        while (source) {
            source.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
            const auto count = static_cast<std::size_t>(source.gcount());
            for (std::size_t i = 0; i < count; ++i) {
                const auto byte = static_cast<unsigned char>(chunk[i]);
                chunk[i] = static_cast<char>(byte ^ std::to_integer<unsigned char>(key[(offset + i) % key.size()]));
            }
            write_all(dest, reinterpret_cast<const std::byte*>(chunk.data()), count);
            offset += count;
        }
        if (source.bad()) throw std::runtime_error("failed to read input file");
        if (std::fclose(dest) != 0) { closed = true; throw std::runtime_error("failed to close output file"); }
        closed = true;
    } catch (...) {
        if (!closed) std::fclose(dest);
        std::error_code ec;
        std::filesystem::remove(output, ec);
        throw;
    }
}
} // namespace xorcist::xor_tool
