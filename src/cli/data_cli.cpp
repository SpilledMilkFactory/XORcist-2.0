// SPDX-License-Identifier: MIT
#include "data_cli.hpp"
#include "xorcist/data.hpp"
#include "xorcist/secure.hpp"
#include "xorcist/xor.hpp"
#include <openssl/crypto.h>
#include <algorithm>
#include <charconv>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string_view>
#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#include <cstdio>
#endif

namespace xorcist::cli {
namespace {
std::string_view value(const std::vector<std::string>& args, std::string_view flag, bool required = true) {
    bool found = false;
    std::string_view result;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] != flag) continue;
        if (found || i + 1 == args.size() || args[i + 1].starts_with("--"))
            throw std::invalid_argument("missing or duplicate option: " + std::string(flag));
        result = args[i + 1];
        found = true;
    }
    if (required && !found) throw std::invalid_argument("required option missing: " + std::string(flag));
    return result;
}
void validate(const std::vector<std::string>& args,
              std::initializer_list<std::string_view> allowed,
              std::initializer_list<std::string_view> switches = {}) {
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto arg = std::string_view(args[i]);
        bool switch_arg = false;
        for (auto s : switches) if (arg == s) switch_arg = true;
        if (switch_arg) continue;
        bool known = false;
        for (auto name : allowed) if (arg == name) known = true;
        if (!known || ++i == args.size() || args[i].starts_with("--"))
            throw std::invalid_argument("invalid option or missing option value: " + std::string(arg));
    }
}
std::size_t bounded_number(std::string_view s, std::size_t min, std::size_t max) {
    std::size_t n = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), n);
    if (s.empty() || ec != std::errc{} || ptr != s.data() + s.size() || n < min || n > max)
        throw std::invalid_argument("numeric argument out of range");
    return n;
}
std::string password_from_stdin() {
    std::string result;
    if (!std::getline(std::cin, result) || result.empty())
        throw std::invalid_argument("no password line received from stdin");
    if (!result.empty() && result.back() == '\r') result.pop_back();
    if (result.size() > 4096) throw std::invalid_argument("passphrase is too long");
    return result;
}
std::string interactive_password() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode))
        throw std::runtime_error("no interactive console; use --password-stdin");
    std::cerr << "Passphrase: ";
    const DWORD hidden = mode & ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(h, hidden)) throw std::runtime_error("cannot disable terminal echo");
    std::string pass;
    try { pass = password_from_stdin(); }
    catch (...) { SetConsoleMode(h, mode); std::cerr << '\n'; throw; }
    SetConsoleMode(h, mode);
    std::cerr << '\n';
    return pass;
#else
    std::FILE* tty = std::fopen("/dev/tty", "r+");
    if (!tty) throw std::runtime_error("no interactive terminal; use --password-stdin");
    const int fd = fileno(tty);
    termios old{};
    if (tcgetattr(fd, &old) != 0) { std::fclose(tty); throw std::runtime_error("cannot inspect terminal settings"); }
    termios hidden = old;
    hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    if (tcsetattr(fd, TCSANOW, &hidden) != 0) { std::fclose(tty); throw std::runtime_error("cannot hide terminal input"); }
    std::fprintf(tty, "Passphrase: ");
    std::fflush(tty);
    std::string pass;
    int ch = 0;
    while ((ch = std::fgetc(tty)) != EOF && ch != '\n') {
        if (pass.size() >= 4096) break;
        pass.push_back(static_cast<char>(ch));
    }
    tcsetattr(fd, TCSANOW, &old);
    std::fprintf(tty, "\n");
    std::fclose(tty);
    if (ch != '\n' || pass.empty()) throw std::invalid_argument("passphrase missing or too long");
    return pass;
#endif
}
struct Secret {
    std::string value;
    explicit Secret(bool from_stdin) : value(from_stdin ? password_from_stdin() : interactive_password()) {}
    ~Secret() { if (!value.empty()) OPENSSL_cleanse(value.data(), value.size()); }
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
};
std::string from_bytes(const data::Bytes& bytes) {
    if (bytes.empty()) return {};
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}
} // namespace

int run_data(const std::vector<std::string>& args) {
    if (args.size() < 3) throw std::invalid_argument("expected data base64|hex|mask|bits|inspect|diff");
    const std::string& cmd = args[1];
    const std::vector<std::string> tail(args.begin() + 2, args.end());
    if (cmd == "base64" || cmd == "hex") {
        if (tail.empty() || (tail.front() != "encode" && tail.front() != "decode"))
            throw std::invalid_argument("expected data base64|hex encode|decode");
        const std::string mode = tail.front();
        const std::vector<std::string> opts(tail.begin() + 1, tail.end());
        validate(opts, {"--in", "--out"});
        auto bytes = data::read_small_file(std::filesystem::path(value(opts, "--in")));
        if (mode == "encode") {
            std::string result = cmd == "base64" ? data::base64_encode(bytes) : xor_tool::hex_encode(bytes);
            const auto encoded = xor_tool::to_bytes(result);
            xor_tool::write_new_file(std::filesystem::path(value(opts, "--out")), encoded);
        } else {
            const auto contents = from_bytes(bytes);
            const auto decoded = cmd == "base64" ? data::base64_decode(contents) :
                                 (contents.empty() ? data::Bytes{} : xor_tool::hex_decode(contents));
            xor_tool::write_new_file(std::filesystem::path(value(opts, "--out")), decoded);
        }
        std::cout << "Binary-safe " << cmd << " transformation complete.\n";
        return 0;
    }
    if (cmd == "mask") {
        validate(tail, {"--hex", "--mask-hex", "--op"});
        const auto b = xor_tool::hex_decode(value(tail, "--hex"));
        const auto mask = xor_tool::hex_decode(value(tail, "--mask-hex"));
        std::cout << xor_tool::hex_encode(data::mask_bytes(b, mask, value(tail, "--op"))) << '\n';
        return 0;
    }
    if (cmd == "bits") {
        validate(tail, {"--hex"});
        std::cout << data::bit_string(xor_tool::hex_decode(value(tail, "--hex"))) << '\n';
        return 0;
    }
    if (cmd == "inspect") {
        validate(tail, {"--in", "--limit"});
        const auto lim = value(tail, "--limit", false);
        const auto max = lim.empty() ? 256 : bounded_number(lim, 1, 4096);
        std::cout << data::hexdump_file(std::filesystem::path(value(tail, "--in")), max);
        return 0;
    }
    if (cmd == "diff") {
        validate(tail, {"--left", "--right", "--limit"});
        const auto lim = value(tail, "--limit", false);
        const auto max = lim.empty() ? 32 : bounded_number(lim, 1, 1024);
        std::cout << data::diff_files(std::filesystem::path(value(tail, "--left")),
                                      std::filesystem::path(value(tail, "--right")), max);
        return 0;
    }
    throw std::invalid_argument("unknown data command: " + cmd);
}
int run_secure(const std::vector<std::string>& args) {
    if (args.size() < 2 || (args[1] != "encrypt" && args[1] != "decrypt"))
        throw std::invalid_argument("expected secure encrypt|decrypt");
    const std::vector<std::string> opts(args.begin() + 2, args.end());
    validate(opts, {"--in", "--out"}, {"--password-stdin"});
    const bool from_stdin = std::find(opts.begin(), opts.end(), "--password-stdin") != opts.end();
    const auto in = std::filesystem::path(value(opts, "--in"));
    const auto out = std::filesystem::path(value(opts, "--out"));
    if (!std::filesystem::exists(in))
        throw std::invalid_argument("input file does not exist: " + in.string());
    if (!std::filesystem::is_regular_file(in))
        throw std::invalid_argument("input must be a regular file: " + in.string());
    if (!from_stdin && args[1] == "encrypt")
        std::cerr << "Encryption requires a passphrase of 12 to 4096 bytes (input hidden).\n";
    Secret password(from_stdin);
    if (args[1] == "encrypt") secure::encrypt_file(in, out, password.value);
    else secure::decrypt_file(in, out, password.value);
    std::cout << "Authenticated " << args[1] << " complete.\n";
    return 0;
}
} // namespace xorcist::cli
