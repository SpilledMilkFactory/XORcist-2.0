// SPDX-License-Identifier: MIT
#include "xorcist/data.hpp"
#include "xorcist/secure.hpp"
#include "xorcist/xor.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
int count = 0;
void check(bool b, const char* msg) { ++count; if (!b) throw std::runtime_error(msg); }
template <typename Fn> void rejects(Fn&& fn) {
    try { fn(); } catch (const std::exception&) { ++count; return; }
    throw std::runtime_error("unexpected acceptance of invalid input");
}
std::vector<unsigned char> read(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("cannot read fixture");
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
void write(const std::filesystem::path& p, const std::vector<unsigned char>& bytes) {
    std::ofstream o(p, std::ios::binary);
    if (!o.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
        throw std::runtime_error("cannot write fixture");
}
} // namespace
int main() {
    namespace fs = std::filesystem;
    using namespace xorcist;
    try {
        // Published NIST AES-256-GCM one-block vector (zero key/nonce/plaintext).
        // Independent known-answer check of the OpenSSL EVP algorithm used by secure.cpp.
        {
            const std::array<unsigned char, 32> key{};
            const std::array<unsigned char, 12> nonce{};
            const std::array<unsigned char, 16> plain{};
            std::array<unsigned char, 32> cipher{};
            std::array<unsigned char, 16> tag{};
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("NIST test allocation");
            int len = 0, final = 0;
            const bool success =
                EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) == 1 &&
                EVP_EncryptUpdate(ctx, cipher.data(), &len, plain.data(), static_cast<int>(plain.size())) == 1 &&
                EVP_EncryptFinal_ex(ctx, cipher.data() + len, &final) == 1 &&
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) == 1;
            EVP_CIPHER_CTX_free(ctx);
            check(success, "NIST AES-256-GCM EVP interface");
            check(xor_tool::hex_encode(std::as_bytes(std::span(cipher.data(), plain.size()))) ==
                  "cea7403d4d606b6e074ec5d3baf39d18", "NIST AES-256-GCM ciphertext");
            check(xor_tool::hex_encode(std::as_bytes(std::span(tag))) ==
                  "d0d1c8a799996bf0265b98b5d48ab919", "NIST AES-256-GCM tag");
        }
        check(data::base64_encode(xor_tool::to_bytes("Man")) == "TWFu", "RFC4648 Man");
        check(data::base64_encode(xor_tool::to_bytes("Ma")) == "TWE=", "RFC4648 Ma");
        check(data::base64_encode(xor_tool::to_bytes("M")) == "TQ==", "RFC4648 M");
        check(data::base64_encode({}).empty(), "empty Base64 encoding");
        check(data::base64_decode("TWFu") == xor_tool::to_bytes("Man"), "RFC4648 decode");
        check(data::base64_decode("").empty(), "empty Base64 decode");
        for (std::string_view bad : {"TQ=", "TQ=A", "TQ==AAAA", "TR==", "TWF=", "T?Fu", "TQ==\n", "====", "TQ==TQ=="})
            rejects([&] { (void)data::base64_decode(bad); });
        std::mt19937 rng(7891);
        for (std::size_t len = 0; len < 512; ++len) {
            data::Bytes input(len);
            for (auto& b : input) b = static_cast<std::byte>(rng() & 255U);
            check(data::base64_decode(data::base64_encode(input)) == input, "Base64 randomized round trip");
        }
        const auto a = xor_tool::hex_decode("f00f");
        const auto b = xor_tool::hex_decode("0ff0");
        check(xor_tool::hex_encode(data::mask_bytes(a, b, "and")) == "0000", "bit AND");
        check(xor_tool::hex_encode(data::mask_bytes(a, b, "or")) == "ffff", "bit OR");
        check(xor_tool::hex_encode(data::mask_bytes(a, b, "xor")) == "ffff", "bit XOR");
        check(xor_tool::hex_encode(data::mask_bytes(a, b, "not")) == "0ff0", "bit NOT");
        check(data::bit_string(xor_tool::hex_decode("0180")) == "0000000110000000", "MSB-first bits");
        rejects([&] { (void)data::mask_bytes(a, xor_tool::hex_decode("ff"), "xor"); });
        rejects([&] { (void)data::mask_bytes(a, b, "invalid"); });

        const auto dir = fs::temp_directory_path() /
            ("xorcist-m3-tests-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        check(fs::create_directory(dir), "unique test directory");
        try {
            const auto plain = dir / "source.bin", encrypted = dir / "encrypted.xorc3",
                decoded = dir / "recovered.bin";
            std::vector<unsigned char> payload(2 * 65536 + 91);
            for (auto& byte : payload) byte = static_cast<unsigned char>(rng() & 255U);
            write(plain, payload);
            check(data::hexdump_file(plain, 16).find("00000000") != std::string::npos, "hexdump offset");
            check(data::diff_files(plain, plain) == "Files identical.\n", "equal file diff");
            rejects([&] { (void)data::hexdump_file(plain, 4097); });
            const std::string password = "strong-integration-passphrase";
            secure::encrypt_file(plain, encrypted, password);
            const auto original = read(encrypted);
            check(original.size() == payload.size() + 80, "header and tag length");
            check(secure::validate_container_layout(std::as_bytes(std::span(original.data(), 64)), original.size()) ==
                  payload.size(), "v1 layout validator");
            rejects([&] { (void)secure::validate_container_layout(std::as_bytes(std::span(original.data(), 63)),
                                                                   original.size()); });
            secure::decrypt_file(encrypted, decoded, password);
            check(read(decoded) == payload, "authenticated multi-chunk round trip");
            rejects([&] { secure::encrypt_file(plain, encrypted, password); });
            rejects([&] { secure::decrypt_file(encrypted, decoded, password); });
            rejects([&] { secure::encrypt_file(plain, dir / "short-key.bin", "short"); });
            check(!fs::exists(dir / "short-key.bin"), "reject short password without output");
            rejects([&] { secure::decrypt_file(encrypted, dir / "wrong.bin", "wrong-passphrase"); });
            check(!fs::exists(dir / "wrong.bin"), "authentication failure doesn't publish plaintext");
            const auto mutated = dir / "mutated.xorc3";
            std::vector<unsigned char> tampered = original;
            tampered[64 + 101] ^= 1U;
            write(mutated, tampered);
            rejects([&] { secure::decrypt_file(mutated, dir / "tampered.bin", password); });
            check(!fs::exists(dir / "tampered.bin"), "modified ciphertext doesn't publish plaintext");
            tampered = original;
            tampered.back() ^= 1U;
            write(mutated, tampered);
            rejects([&] { secure::decrypt_file(mutated, dir / "tag.bin", password); });
            check(!fs::exists(dir / "tag.bin"), "modified tag doesn't publish plaintext");
            tampered = original;
            tampered[24] ^= 1U; // salt is included in AAD and changes the derived key.
            write(mutated, tampered);
            rejects([&] { secure::decrypt_file(mutated, dir / "salt.bin", password); });
            check(!fs::exists(dir / "salt.bin"), "modified salt doesn't publish plaintext");
            tampered = original;
            tampered[8] = 7; // Unsupported version.
            write(mutated, tampered);
            rejects([&] { secure::decrypt_file(mutated, dir / "version.bin", password); });
            check(!fs::exists(dir / "version.bin"), "unsupported version doesn't publish plaintext");
            tampered = original;
            tampered.resize(tampered.size() - 1);
            write(mutated, tampered);
            rejects([&] { secure::decrypt_file(mutated, dir / "truncated.bin", password); });
            check(!fs::exists(dir / "truncated.bin"), "truncated input doesn't publish plaintext");
            tampered = original;
            tampered[12] = 0xff; // Malicious scrypt cost: MUST be rejected before key derivation.
            write(mutated, tampered);
            rejects([&] { secure::decrypt_file(mutated, dir / "cost.bin", password); });
            check(!fs::exists(dir / "cost.bin"), "oversized scrypt parameters are rejected");
            const auto smaller = dir / "smaller.bin";
            write(smaller, {1U, 2U, 3U});
            const auto diff = data::diff_files(smaller, plain, 2);
            check(diff.find("offset") != std::string::npos &&
                  diff.find("Output limited to first 2") != std::string::npos, "bounded streaming diff");
            const auto empty = dir / "empty.bin", empty_enc = dir / "empty.xorc3", empty_dec = dir / "empty-dec.bin";
            write(empty, {});
            secure::encrypt_file(empty, empty_enc, password);
            secure::decrypt_file(empty_enc, empty_dec, password);
            check(read(empty_dec).empty(), "empty encrypted file round trip");
            for (const auto& entry : fs::directory_iterator(dir))
                check(entry.path().filename().string().find("xorcist-tmp-") == std::string::npos,
                      "no uncleaned temporary plaintext files");
        } catch (...) { fs::remove_all(dir); throw; }
        fs::remove_all(dir);
        std::cout << count << " M3 checks passed.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "M3 FAILED after " << count << ": " << e.what() << '\n';
        return 1;
    }
}
