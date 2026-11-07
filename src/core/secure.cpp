// SPDX-License-Identifier: MIT
#include "xorcist/secure.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <array>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace xorcist::secure {
namespace {
constexpr std::size_t header_size = 64;
constexpr std::size_t tag_size = 16;
constexpr std::size_t chunk_size = 65536;
constexpr std::uint64_t max_plaintext = std::uint64_t{1} << 35; // 32 GiB cap per nonce.
constexpr std::uint32_t scrypt_n = 32768;
constexpr std::uint32_t scrypt_r = 8;
constexpr std::uint32_t scrypt_p = 1;
constexpr std::uint64_t scrypt_max_memory = 64ULL * 1024 * 1024;
constexpr std::array<unsigned char, 8> magic{{'X', 'O', 'R', 'C', '3', 'A', 'E', '1'}};
using Header = std::array<unsigned char, header_size>;
using Key = std::array<unsigned char, 32>;
using Context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
void require(bool valid, const char* message) {
    if (!valid) throw std::runtime_error(message);
}
void put_u32(Header& h, std::size_t pos, std::uint32_t value) {
    for (int i = 3; i >= 0; --i) { h[pos + static_cast<std::size_t>(i)] = static_cast<unsigned char>(value); value >>= 8; }
}
void put_u64(Header& h, std::size_t pos, std::uint64_t value) {
    for (int i = 7; i >= 0; --i) { h[pos + static_cast<std::size_t>(i)] = static_cast<unsigned char>(value); value >>= 8; }
}
std::uint32_t get_u32(const Header& h, std::size_t pos) {
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) value = (value << 8) | h[pos + i];
    return value;
}
std::uint64_t get_u64(const Header& h, std::size_t pos) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value = (value << 8) | h[pos + i];
    return value;
}
struct ProtectedKey {
    Key bytes{};
    ~ProtectedKey() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
    ProtectedKey() = default;
    ProtectedKey(const ProtectedKey&) = delete;
    ProtectedKey& operator=(const ProtectedKey&) = delete;
};
void derive(ProtectedKey& key, std::string_view password, const Header& h) {
    if (password.empty()) throw std::invalid_argument("passphrase is empty");
    require(EVP_PBE_scrypt(password.data(), password.size(), h.data() + 24, 16,
                          scrypt_n, scrypt_r, scrypt_p, scrypt_max_memory,
                          key.bytes.data(), key.bytes.size()) == 1, "scrypt key derivation failed");
}
std::uint64_t regular_size(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path))
        throw std::invalid_argument("input file does not exist: " + path.string());
    if (!std::filesystem::is_regular_file(path))
        throw std::invalid_argument("input must be a regular file: " + path.string());
    const auto size = std::filesystem::file_size(path);
    if (size > max_plaintext + header_size + tag_size)
        throw std::invalid_argument("input exceeds version-1 size limit");
    return size;
}
std::ifstream open_input(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("cannot open input file: " + path.string());
    return file;
}
void write_all(std::FILE* out, const unsigned char* data, std::size_t n) {
    if (n && std::fwrite(data, 1, n, out) != n) throw std::runtime_error("failed writing temporary file");
}
std::FILE* open_exclusive(const std::filesystem::path& path) {
#ifdef _WIN32
    int fd = -1;
    const errno_t rc = _wsopen_s(&fd, path.c_str(), _O_BINARY | _O_WRONLY | _O_CREAT | _O_EXCL,
                                _SH_DENYWR, _S_IREAD | _S_IWRITE);
    if (rc != 0) throw std::system_error(static_cast<int>(rc), std::generic_category(), "exclusive temp create");
    auto* f = _fdopen(fd, "wb");
    if (!f) { _close(fd); throw std::runtime_error("fdopen failed"); }
#else
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) throw std::system_error(errno, std::generic_category(), "exclusive temp create");
    auto* f = ::fdopen(fd, "wb");
    if (!f) { ::close(fd); throw std::runtime_error("fdopen failed"); }
#endif
    return f;
}
class Output {
public:
    explicit Output(const std::filesystem::path& dest) : destination_(dest) {
        // A randomized, exclusive file in the same directory allows atomic no-overwrite publication.
        if (dest.empty() || dest.filename().empty()) throw std::invalid_argument("output path is empty");
        for (int attempt = 0; attempt < 8; ++attempt) {
            std::array<unsigned char, 16> random{};
            require(RAND_bytes(random.data(), static_cast<int>(random.size())) == 1,
                    "random temporary filename generation failed");
            constexpr char hex[] = "0123456789abcdef";
            std::string suffix;
            for (const auto b : random) { suffix += hex[b >> 4]; suffix += hex[b & 15]; }
            std::filesystem::path temp_name = dest.filename();
            temp_name += std::filesystem::path(".xorcist-tmp-" + suffix);
            temporary_ = dest.parent_path() / temp_name;
            try { file_ = open_exclusive(temporary_); return; }
            catch (const std::system_error& e) {
                if (e.code().value() != EEXIST) throw;
            }
        }
        throw std::runtime_error("could not allocate an exclusive temporary output");
    }
    Output(const Output&) = delete;
    Output& operator=(const Output&) = delete;
    ~Output() {
        if (file_) std::fclose(file_);
        if (!temporary_.empty()) { std::error_code ec; std::filesystem::remove(temporary_, ec); }
    }
    void write(const unsigned char* buf, std::size_t n) { write_all(file_, buf, n); }
    void publish() {
        require(std::fflush(file_) == 0, "temporary output flush failed");
#ifdef _WIN32
        require(_commit(_fileno(file_)) == 0, "temporary output sync failed");
#else
        require(::fsync(fileno(file_)) == 0, "temporary output sync failed");
#endif
        const int status = std::fclose(file_);
        file_ = nullptr;
        require(status == 0, "temporary output close failed");
#ifdef _WIN32
        // MoveFileExW without MOVEFILE_REPLACE_EXISTING fails if destination exists.
        if (!MoveFileExW(temporary_.c_str(), destination_.c_str(), MOVEFILE_WRITE_THROUGH))
            throw std::runtime_error("cannot publish output (exists or permission denied)");
#else
        // link() is atomic and refuses an existing destination, unlike POSIX rename().
        if (::link(temporary_.c_str(), destination_.c_str()) != 0)
            throw std::system_error(errno, std::generic_category(), "cannot publish output");
        std::error_code ec;
        std::filesystem::remove(temporary_, ec);
#endif
        temporary_.clear();
    }
private:
    std::filesystem::path destination_;
    std::filesystem::path temporary_;
    std::FILE* file_ = nullptr;
};
Header new_header(std::uint64_t len) {
    Header h{};
    std::copy(magic.begin(), magic.end(), h.begin());
    h[8] = 1; // format version
    h[9] = 1; // AES-256-GCM
    h[10] = 1; // scrypt
    put_u32(h, 12, scrypt_n);
    put_u32(h, 16, scrypt_r);
    put_u32(h, 20, scrypt_p);
    require(RAND_bytes(h.data() + 24, 16) == 1, "salt generation failed");
    require(RAND_bytes(h.data() + 40, 12) == 1, "nonce generation failed");
    put_u64(h, 52, len);
    return h;
}
std::uint64_t verify_header(const Header& h, std::uint64_t total) {
    if (!std::equal(magic.begin(), magic.end(), h.begin()) || h[8] != 1 || h[9] != 1 || h[10] != 1 || h[11] != 0 ||
        get_u32(h, 12) != scrypt_n || get_u32(h, 16) != scrypt_r || get_u32(h, 20) != scrypt_p ||
        std::any_of(h.begin() + 60, h.end(), [](unsigned char x) { return x != 0; }))
        throw std::invalid_argument("invalid, unsupported or modified XORcist AEAD header");
    const std::uint64_t len = get_u64(h, 52);
    if (len > max_plaintext || total != len + header_size + tag_size)
        throw std::invalid_argument("encrypted file length does not match authenticated header");
    return len;
}
} // namespace

std::uint64_t validate_container_layout(std::span<const std::byte> bytes,
                                       std::uint64_t file_size) {
    if (bytes.size() != header_size) throw std::invalid_argument("encrypted header must be 64 bytes");
    Header header{};
    for (std::size_t i = 0; i < header.size(); ++i)
        header[i] = std::to_integer<unsigned char>(bytes[i]);
    return verify_header(header, file_size);
}

void encrypt_file(const std::filesystem::path& input, const std::filesystem::path& output,
                  std::string_view passphrase) {
    if (passphrase.size() < 12 || passphrase.size() > 4096)
        throw std::invalid_argument("new encryption requires a passphrase of 12..4096 bytes");
    const std::uint64_t length = regular_size(input);
    if (length > max_plaintext) throw std::invalid_argument("plaintext exceeds version-1 size limit");
    auto source = open_input(input);
    const Header h = new_header(length);
    ProtectedKey key;
    derive(key, passphrase, h);
    Context ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    require(bool(ctx), "cipher context allocation failed");
    require(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
            "AES-256-GCM unavailable");
    require(EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.bytes.data(), h.data() + 40) == 1,
            "AES-GCM key initialization failed");
    int bytes = 0;
    require(EVP_EncryptUpdate(ctx.get(), nullptr, &bytes, h.data(), static_cast<int>(h.size())) == 1,
            "AES-GCM metadata authentication failed");
    Output dest(output);
    dest.write(h.data(), h.size());
    std::array<unsigned char, chunk_size> block{};
    std::array<unsigned char, chunk_size + 16> encrypted{};
    std::uint64_t processed = 0;
    while (processed < length) {
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(length - processed, chunk_size));
        if (!source.read(reinterpret_cast<char*>(block.data()), static_cast<std::streamsize>(count)))
            throw std::runtime_error("plaintext changed or became unreadable");
        require(EVP_EncryptUpdate(ctx.get(), encrypted.data(), &bytes, block.data(),
                                  static_cast<int>(count)) == 1, "encryption failed");
        dest.write(encrypted.data(), static_cast<std::size_t>(bytes));
        processed += count;
    }
    if (source.peek() != std::char_traits<char>::eof() || source.bad())
        throw std::runtime_error("plaintext changed during encryption");
    require(EVP_EncryptFinal_ex(ctx.get(), encrypted.data(), &bytes) == 1, "encryption finalization failed");
    dest.write(encrypted.data(), static_cast<std::size_t>(bytes));
    std::array<unsigned char, tag_size> tag{};
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1,
            "authentication tag retrieval failed");
    dest.write(tag.data(), tag.size());
    dest.publish();
}

void decrypt_file(const std::filesystem::path& input, const std::filesystem::path& output,
                  std::string_view passphrase) {
    if (passphrase.empty() || passphrase.size() > 4096)
        throw std::invalid_argument("passphrase is empty or too long");
    const std::uint64_t total = regular_size(input);
    if (total < header_size + tag_size) throw std::invalid_argument("truncated encrypted file");
    auto source = open_input(input);
    Header h{};
    if (!source.read(reinterpret_cast<char*>(h.data()), static_cast<std::streamsize>(h.size())))
        throw std::runtime_error("cannot read encryption header");
    const auto length = validate_container_layout(std::as_bytes(std::span(h)), total);
    ProtectedKey key;
    derive(key, passphrase, h);
    Context ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    require(bool(ctx), "cipher context allocation failed");
    require(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
            "AES-256-GCM unavailable");
    require(EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.bytes.data(), h.data() + 40) == 1,
            "AES-GCM key initialization failed");
    int count = 0;
    require(EVP_DecryptUpdate(ctx.get(), nullptr, &count, h.data(), static_cast<int>(h.size())) == 1,
            "AES-GCM metadata authentication failed");
    Output dest(output); // Temporary plaintext is private, not published until tag passes.
    std::array<unsigned char, chunk_size> block{};
    std::array<unsigned char, chunk_size + 16> plain{};
    std::uint64_t processed = 0;
    while (processed < length) {
        const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(length - processed, chunk_size));
        if (!source.read(reinterpret_cast<char*>(block.data()), static_cast<std::streamsize>(n)))
            throw std::runtime_error("truncated encrypted payload");
        require(EVP_DecryptUpdate(ctx.get(), plain.data(), &count, block.data(), static_cast<int>(n)) == 1,
                "AES-GCM decryption failed");
        dest.write(plain.data(), static_cast<std::size_t>(count));
        processed += n;
    }
    std::array<unsigned char, tag_size> tag{};
    if (!source.read(reinterpret_cast<char*>(tag.data()), static_cast<std::streamsize>(tag.size())))
        throw std::runtime_error("missing authentication tag");
    if (source.peek() != std::char_traits<char>::eof() || source.bad())
        throw std::runtime_error("encrypted file changed during reading");
    require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data()) == 1,
            "cannot configure authentication tag");
    if (EVP_DecryptFinal_ex(ctx.get(), plain.data(), &count) != 1)
        throw std::runtime_error("authentication failed: wrong passphrase or modified file");
    dest.write(plain.data(), static_cast<std::size_t>(count));
    dest.publish();
}
} // namespace xorcist::secure
