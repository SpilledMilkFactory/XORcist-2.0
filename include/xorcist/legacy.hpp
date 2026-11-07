// SPDX-License-Identifier: MIT
#pragma once
#include "xorcist/xor.hpp"
#include <filesystem>

namespace xorcist::legacy {
// Decode the actual 2019 Java RandomAccessFile.writeUTF() ASCII-on-disk format.
// The original program generated many keys but only applied the FIRST one.
// This tool reads that first key and recovers the binary digits stored in Base64.
// This format is NOT a secure encryption scheme.
[[nodiscard]] xor_tool::Bytes decrypt_java_2019(const std::filesystem::path& keys_file,
                                                const std::filesystem::path& ciphertext_file);
} // namespace xorcist::legacy
