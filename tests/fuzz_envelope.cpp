// SPDX-License-Identifier: MIT
#include "xorcist/secure.hpp"
#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Pure structural parse: no key derivation, disk access or decryption.
    if (size != 64) return 0;
    try {
        const auto header = std::span(reinterpret_cast<const std::byte*>(data), size);
        (void)xorcist::secure::validate_container_layout(header, 80);
    } catch (const std::exception&) {}
    return 0;
}
