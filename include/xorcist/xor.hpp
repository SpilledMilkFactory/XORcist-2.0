// SPDX-License-Identifier: MIT
#pragma once
#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace xorcist::xor_tool {
using Bytes = std::vector<std::byte>;
[[nodiscard]] Bytes hex_decode(std::string_view hex);
[[nodiscard]] std::string hex_encode(std::span<const std::byte> data);
[[nodiscard]] Bytes to_bytes(std::string_view text);
[[nodiscard]] std::string escaped_text(std::span<const std::byte> data);
[[nodiscard]] Bytes transform(std::span<const std::byte> data, std::span<const std::byte> key);
// O_EXCL / _O_EXCL prevents overwriting existing paths. Partial outputs are removed on errors.
void write_new_file(const std::filesystem::path& output, std::span<const std::byte> data);
void transform_file(const std::filesystem::path& input, const std::filesystem::path& output,
                    std::span<const std::byte> key);
} // namespace xorcist::xor_tool
