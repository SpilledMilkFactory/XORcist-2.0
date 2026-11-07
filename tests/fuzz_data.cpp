// SPDX-License-Identifier: MIT
#include "xorcist/data.hpp"
#include "xorcist/xor.hpp"
#include <cstddef>
#include <cstdint>
#include <exception>
#include <string_view>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > 4096) return 0;
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    try {
        const auto decoded = xorcist::data::base64_decode(text);
        if (xorcist::data::base64_encode(decoded) != text) __builtin_trap();
    } catch (const std::exception&) {}
    try {
        const auto decoded = xorcist::xor_tool::hex_decode(text);
        if (xorcist::xor_tool::hex_decode(xorcist::xor_tool::hex_encode(decoded)) != decoded) __builtin_trap();
    } catch (const std::exception&) {}
    return 0;
}
