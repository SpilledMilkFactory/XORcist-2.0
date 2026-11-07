// SPDX-License-Identifier: MIT
#pragma once
#include "xorcist/xor.hpp"
#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace xorcist::data {
using Bytes = xor_tool::Bytes;
[[nodiscard]] std::string base64_encode(std::span<const std::byte> bytes);
[[nodiscard]] Bytes base64_decode(std::string_view input);
[[nodiscard]] Bytes mask_bytes(std::span<const std::byte> value, std::span<const std::byte> mask,
                               std::string_view operation);
[[nodiscard]] std::string bit_string(std::span<const std::byte> input);
[[nodiscard]] Bytes read_small_file(const std::filesystem::path& input, std::size_t max_bytes = 16 * 1024 * 1024);
[[nodiscard]] std::string hexdump_file(const std::filesystem::path& input, std::size_t max_bytes = 256);
[[nodiscard]] std::string diff_files(const std::filesystem::path& left,
                                     const std::filesystem::path& right,
                                     std::size_t max_differences = 32);
} // namespace xorcist::data
