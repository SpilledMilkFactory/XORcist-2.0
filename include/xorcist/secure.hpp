// SPDX-License-Identifier: MIT
#pragma once
#include <filesystem>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace xorcist::secure {
// Version 1: 64-byte authenticated header, scrypt(N=32768,r=8,p=1),
// AES-256-GCM with a random 96-bit nonce and 128-bit authentication tag.
// Header layout validator: DOES NOT AUTHENTICATE any bytes. Suitable for input
// structure checks and fuzzing; only decrypt_file verifies authenticity.
[[nodiscard]] std::uint64_t validate_container_layout(std::span<const std::byte> header,
                                                      std::uint64_t file_size);
// New outputs are published only after success; decryption never publishes
// unauthenticated plaintext. No passwords are logged or passed in CLI arguments.
void encrypt_file(const std::filesystem::path& input, const std::filesystem::path& output,
                  std::string_view passphrase);
void decrypt_file(const std::filesystem::path& input, const std::filesystem::path& output,
                  std::string_view passphrase);
} // namespace xorcist::secure
