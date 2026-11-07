// SPDX-License-Identifier: MIT
#include "xorcist/diagnostics.hpp"
#include "xorcist/planning.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <ctime>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <fstream>
#endif

namespace xorcist::diagnostics {
namespace {
std::string utc_now() {
    const auto now = std::chrono::system_clock::now();
    const auto tm_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tm_t);
#else
    gmtime_r(&tm_t, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}
void check_numeric_ip(std::string_view ip) {
    if (ip.empty() || ip.size() > 64) throw std::invalid_argument("expected an IPv4 or IPv6 numeric address");
    (void)planning::parse_address(ip);
}
std::string ascii_host(std::string_view name) {
    if (name.empty() || name.size() > 253) throw std::invalid_argument("hostname length must be 1..253");
    std::size_t label_length = 0;
    for (std::size_t i = 0; i < name.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(name[i]);
        const bool alnum = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (!(alnum || c == '-' || c == '.'))
            throw std::invalid_argument("DNS name must use ASCII letters, digits, hyphens or dots");
        if (c == '.') {
            if (label_length == 0 || label_length > 63 || name[i - 1] == '-')
                throw std::invalid_argument("invalid DNS label");
            label_length = 0;
        } else {
            if (label_length == 0 && c == '-') throw std::invalid_argument("DNS label cannot start with '-'");
            ++label_length;
            if (label_length > 63) throw std::invalid_argument("DNS label exceeds 63 characters");
        }
    }
    if (label_length == 0 && name.back() != '.') throw std::invalid_argument("invalid DNS name");
    if (name.back() == '-' ) throw std::invalid_argument("DNS label cannot end with '-'");
    return std::string(name);
}
#ifdef _WIN32
struct SocketRuntime {
    SocketRuntime() {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) throw std::runtime_error("WSAStartup failed");
    }
    ~SocketRuntime() { WSACleanup(); }
};
using Socket = SOCKET;
using SocketLength = int;
constexpr Socket invalid_socket = INVALID_SOCKET;
void close_socket(Socket s) { closesocket(s); }
int last_error() { return WSAGetLastError(); }
int refused_error() { return WSAECONNREFUSED; }
int inprogress_error() { return WSAEWOULDBLOCK; }
void set_nonblocking(Socket s) {
    u_long flag = 1;
    if (ioctlsocket(s, FIONBIO, &flag) != 0) throw std::runtime_error("ioctlsocket(FIONBIO) failed");
}
std::string friendly_name(const wchar_t* name) {
    if (!name) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string output(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, name, -1, output.data(), n, nullptr, nullptr);
    output.pop_back();
    return output;
}
#else
using Socket = int;
using SocketLength = socklen_t;
constexpr Socket invalid_socket = -1;
void close_socket(Socket s) { ::close(s); }
int last_error() { return errno; }
int refused_error() { return ECONNREFUSED; }
int inprogress_error() { return EINPROGRESS; }
void set_nonblocking(Socket s) {
    const int flags = ::fcntl(s, F_GETFL, 0);
    if (flags < 0 || ::fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0)
        throw std::system_error(errno, std::generic_category(), "nonblocking socket");
}
#endif
struct SocketGuard {
    Socket s{invalid_socket};
    explicit SocketGuard(Socket value) : s(value) {}
    ~SocketGuard() { if (s != invalid_socket) close_socket(s); }
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;
};
int family_id(AddressFamily f) {
    if (f == AddressFamily::IPv4) return AF_INET;
    if (f == AddressFamily::IPv6) return AF_INET6;
    return AF_UNSPEC;
}
std::string numeric_sockaddr(const sockaddr* sa, SocketLength size) {
    if (!sa || (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)) return {};
    char buffer[NI_MAXHOST]{};
    if (getnameinfo(sa, size, buffer, sizeof(buffer), nullptr, 0, NI_NUMERICHOST) != 0) return {};
    return buffer;
}
std::string gai_failure(int code) {
#ifdef _WIN32
    return "system resolver error " + std::to_string(code);
#else
    return gai_strerror(code);
#endif
}
std::uint8_t prefix_from_mask(const sockaddr* sa) {
    if (!sa) return 0;
    const std::uint8_t* bytes = nullptr;
    unsigned length = 0;
    if (sa->sa_family == AF_INET) {
        bytes = reinterpret_cast<const std::uint8_t*>(&reinterpret_cast<const sockaddr_in*>(sa)->sin_addr);
        length = 4;
    } else if (sa->sa_family == AF_INET6) {
        bytes = reinterpret_cast<const std::uint8_t*>(&reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr);
        length = 16;
    } else return 0;
    bool zeros = false;
    std::uint8_t count = 0;
    for (unsigned j = 0; j < length; ++j)
        for (int bit = 7; bit >= 0; --bit) {
            const bool one = (bytes[j] & (1U << bit)) != 0;
            if (!one) zeros = true;
            else if (zeros) throw std::runtime_error("non-contiguous interface netmask");
            else ++count;
        }
    return count;
}

#ifndef _WIN32
// Hex values in /proc/net/route are printed in little-endian byte order.
std::string proc_v4(std::string_view value) {
    if (value.size() != 8) throw std::runtime_error("malformed /proc/net/route IPv4 value");
    std::array<unsigned, 4> bytes{};
    for (unsigned j = 0; j < 4; ++j) {
        const auto two = value.substr((3U - j) * 2U, 2);
        const auto v = std::stoul(std::string(two), nullptr, 16);
        if (v > 255) throw std::runtime_error("invalid /proc/net/route IPv4 byte");
        bytes[j] = static_cast<unsigned>(v);
    }
    return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." +
        std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
}
std::uint32_t checked_hex(std::string_view s) {
    if (s.empty() || s.size() > 8) throw std::runtime_error("invalid /proc hex number");
    std::size_t pos = 0;
    const auto n = std::stoul(std::string(s), &pos, 16);
    if (pos != s.size() || n > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("invalid /proc hex number");
    return static_cast<std::uint32_t>(n);
}
std::string proc_v6(std::string_view hex) {
    if (hex.size() != 32) throw std::runtime_error("malformed /proc/net/ipv6_route value");
    std::array<unsigned char, 16> addr{};
    for (std::size_t i = 0; i < addr.size(); ++i) addr[i] = static_cast<unsigned char>(checked_hex(hex.substr(i * 2, 2)));
    char buffer[INET6_ADDRSTRLEN]{};
    if (!inet_ntop(AF_INET6, addr.data(), buffer, sizeof(buffer)))
        throw std::runtime_error("invalid IPv6 route address");
    return buffer;
}
#endif
std::string host_prefix(std::string address, unsigned prefix) {
    return address + "/" + std::to_string(prefix);
}
} // namespace

DnsResult lookup(std::string_view hostname, AddressFamily family) {
#ifdef _WIN32
    SocketRuntime runtime;
#endif
    const auto host = ascii_host(hostname);
    addrinfo hints{};
    hints.ai_family = family_id(family);
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* raw = nullptr;
    const int rc = getaddrinfo(host.c_str(), nullptr, &hints, &raw);
    if (rc != 0) throw std::runtime_error("DNS lookup failed: " + gai_failure(rc));
    struct Guard { addrinfo* p; ~Guard() { if (p) freeaddrinfo(p); } } guard{raw};
    DnsResult result{host, utc_now(), {}};
    std::set<std::string> unique;
    for (auto* cur = raw; cur; cur = cur->ai_next) {
        auto ip = numeric_sockaddr(cur->ai_addr, static_cast<SocketLength>(cur->ai_addrlen));
        if (!ip.empty()) unique.insert(std::move(ip));
        if (unique.size() > 128) throw std::runtime_error("DNS resolver returned too many addresses");
    }
    result.addresses.assign(unique.begin(), unique.end());
    return result;
}
ReverseResult reverse(std::string_view numeric_ip) {
#ifdef _WIN32
    SocketRuntime runtime;
#endif
    check_numeric_ip(numeric_ip);
    const auto ip = std::string(numeric_ip);
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    addrinfo* raw = nullptr;
    const int rc = getaddrinfo(ip.c_str(), nullptr, &hints, &raw);
    if (rc != 0) throw std::runtime_error("invalid numeric IP: " + gai_failure(rc));
    struct Guard { addrinfo* p; ~Guard() { if (p) freeaddrinfo(p); } } guard{raw};
    char host[NI_MAXHOST]{};
    const auto err = getnameinfo(raw->ai_addr, static_cast<SocketLength>(raw->ai_addrlen), host, sizeof(host),
                                 nullptr, 0, NI_NAMEREQD);
    if (err != 0) throw std::runtime_error("reverse DNS/PTR unavailable: " + gai_failure(err));
    return {ip, host, utc_now()};
}

std::vector<Interface> interfaces() {
#ifdef _WIN32
    SocketRuntime runtime;
    ULONG size = 16 * 1024;
    std::vector<unsigned char> buffer(size);
    ULONG status = ERROR_BUFFER_OVERFLOW;
    for (int i = 0; i < 3 && status == ERROR_BUFFER_OVERFLOW; ++i) {
        status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
                                      nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
        if (status == ERROR_BUFFER_OVERFLOW) {
            if (size > 4U * 1024U * 1024U) throw std::runtime_error("adapter buffer limit exceeded");
            buffer.resize(size);
        }
    }
    if (status != NO_ERROR) throw std::runtime_error("GetAdaptersAddresses failed: " + std::to_string(status));
    std::vector<Interface> output;
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); a && output.size() < 256; a = a->Next) {
        Interface item;
        item.name = friendly_name(a->FriendlyName);
        item.index = a->IfIndex ? a->IfIndex : a->Ipv6IfIndex;
        item.up = a->OperStatus == IfOperStatusUp;
        item.mtu = a->Mtu;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            auto address = numeric_sockaddr(u->Address.lpSockaddr, static_cast<SocketLength>(u->Address.iSockaddrLength));
            if (!address.empty() && item.addresses.size() < 128)
                item.addresses.push_back(host_prefix(address, u->OnLinkPrefixLength));
        }
        for (auto* g = a->FirstGatewayAddress; g; g = g->Next) {
            auto ip = numeric_sockaddr(g->Address.lpSockaddr, static_cast<SocketLength>(g->Address.iSockaddrLength));
            if (!ip.empty() && item.gateways.size() < 16) item.gateways.push_back(ip);
        }
        output.push_back(std::move(item));
    }
    return output;
#else
    ifaddrs* raw = nullptr;
    if (getifaddrs(&raw) != 0) throw std::system_error(errno, std::generic_category(), "getifaddrs");
    struct Guard { ifaddrs* ptr; ~Guard() { freeifaddrs(ptr); } } guard{raw};
    std::vector<Interface> result;
    for (auto* p = raw; p; p = p->ifa_next) {
        if (!p->ifa_name) continue;
        std::string name(p->ifa_name);
        auto iter = std::find_if(result.begin(), result.end(), [&](const Interface& x) { return x.name == name; });
        if (iter == result.end()) {
            if (result.size() >= 256) throw std::runtime_error("too many network interfaces");
            result.push_back(Interface{name, if_nametoindex(p->ifa_name), (p->ifa_flags & IFF_UP) != 0, 0, {}, {}});
            iter = std::prev(result.end());
        }
        if (p->ifa_addr) {
            SocketLength len = 0;
            if (p->ifa_addr->sa_family == AF_INET) len = sizeof(sockaddr_in);
            else if (p->ifa_addr->sa_family == AF_INET6) len = sizeof(sockaddr_in6);
            if (len) {
                const auto addr = numeric_sockaddr(p->ifa_addr, len);
                if (!addr.empty() && iter->addresses.size() < 128) {
                    const auto prefix = p->ifa_netmask ? prefix_from_mask(p->ifa_netmask) : static_cast<std::uint8_t>(0);
                    iter->addresses.push_back(host_prefix(addr, prefix));
                }
            }
        }
    }
    SocketGuard fd(::socket(AF_INET, SOCK_DGRAM, 0));
    if (fd.s != invalid_socket) {
        for (auto& item : result) {
            ifreq request{};
            if (item.name.size() >= sizeof(request.ifr_name)) continue;
            std::memcpy(request.ifr_name, item.name.data(), item.name.size());
            if (::ioctl(fd.s, SIOCGIFMTU, &request) == 0 && request.ifr_mtu > 0)
                item.mtu = static_cast<std::uint32_t>(request.ifr_mtu);
        }
    }
    // Populate default gateways from the same read-only route source; interface
    // metadata itself is supplied by getifaddrs and SIOCGIFMTU.
    try {
        for (const auto& route : routes()) {
            if (route.gateway == "-" ||
                (route.destination != "0.0.0.0/0" && route.destination != "::/0")) continue;
            for (auto& iface : result) {
                if (iface.name != route.interface_name) continue;
                if (std::find(iface.gateways.begin(), iface.gateways.end(), route.gateway) == iface.gateways.end())
                    iface.gateways.push_back(route.gateway);
            }
        }
    } catch (const std::exception&) {
        // Missing optional route visibility must not prevent interface inspection.
    }
    return result;
#endif
}

std::vector<Route> routes() {
#ifdef _WIN32
    SocketRuntime runtime;
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    const auto status = GetIpForwardTable2(AF_UNSPEC, &table);
    if (status != NO_ERROR) throw std::runtime_error("GetIpForwardTable2 failed: " + std::to_string(status));
    struct Guard { PMIB_IPFORWARD_TABLE2 p; ~Guard() { if (p) FreeMibTable(p); } } guard{table};
    std::vector<Route> out;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        if (out.size() >= 4096) throw std::runtime_error("too many routes");
        const auto& r = table->Table[i];
        const auto& dst = r.DestinationPrefix;
        const auto* dst_sa = reinterpret_cast<const sockaddr*>(&dst.Prefix);
        const auto* next_sa = reinterpret_cast<const sockaddr*>(&r.NextHop);
        const auto dst_len = dst_sa->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
        const auto next_len = next_sa->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
        const auto base = numeric_sockaddr(dst_sa, static_cast<SocketLength>(dst_len));
        const auto next = numeric_sockaddr(next_sa, static_cast<SocketLength>(next_len));
        if (base.empty()) continue;
        char ifname[IF_MAX_STRING_SIZE + 1]{};
        const auto name_rc = ConvertInterfaceLuidToNameA(&r.InterfaceLuid, ifname, sizeof(ifname));
        out.push_back({host_prefix(base, dst.PrefixLength), next.empty() || next == "0.0.0.0" || next == "::" ? "-" : next,
                       name_rc == NO_ERROR ? ifname : std::to_string(r.InterfaceIndex), r.Metric});
    }
    return out;
#else
    std::vector<Route> out;
    std::ifstream ipv4("/proc/net/route");
    if (!ipv4) throw std::runtime_error("Linux route inventory unavailable: /proc/net/route");
    std::string line;
    (void)std::getline(ipv4, line); // header
    while (std::getline(ipv4, line)) {
        if (out.size() >= 4096) throw std::runtime_error("too many routes");
        std::istringstream row(line);
        std::string dev, dest, via, flags, ref, use, metric, mask;
        if (!(row >> dev >> dest >> via >> flags >> ref >> use >> metric >> mask)) continue;
        if ((checked_hex(flags) & 1U) == 0) continue; // ignore down routes
        const auto address = proc_v4(dest);
        const auto mask_bytes = proc_v4(mask);
        const auto prefix = mask_from_netmask(mask_bytes).prefix;
        // Parsing via planning canonicalizes any stray host bits.
        const auto cidr = planning::parse_cidr(host_prefix(address, prefix)).str();
        const auto gw = proc_v4(via);
        out.push_back({cidr, gw == "0.0.0.0" ? "-" : gw, dev, static_cast<std::uint32_t>(std::stoul(metric))});
    }
    std::ifstream ipv6("/proc/net/ipv6_route");
    if (ipv6) while (std::getline(ipv6, line)) {
        if (out.size() >= 4096) throw std::runtime_error("too many routes");
        std::istringstream row(line);
        std::string dst, plen, src, splen, gw, metric, ref, use, flags, dev;
        if (!(row >> dst >> plen >> src >> splen >> gw >> metric >> ref >> use >> flags >> dev)) continue;
        if ((checked_hex(flags) & 1U) == 0) continue;
        const auto pfx = checked_hex(plen);
        if (pfx > 128) continue;
        const auto base = proc_v6(dst);
        const auto next = proc_v6(gw);
        out.push_back({planning::parse_cidr(host_prefix(base, pfx)).str(),
                       next == "::" ? "-" : next, dev, checked_hex(metric)});
    }
    return out;
#endif
}

Ipv4Mask mask_from_netmask(std::string_view dotted) {
    const auto ip = planning::parse_address(dotted);
    if (ip.family != planning::Family::IPv4) throw std::invalid_argument("IPv4 mask required");
    std::uint8_t prefix = 0;
    bool zero_seen = false;
    for (unsigned j = 0; j < 4; ++j)
        for (int bit = 7; bit >= 0; --bit) {
            const bool one = (ip.bytes[j] & (1U << bit)) != 0;
            if (!one) zero_seen = true;
            else if (zero_seen) throw std::invalid_argument("IPv4 mask must have contiguous one bits");
            else ++prefix;
        }
    std::string wildcard;
    for (unsigned j = 0; j < 4; ++j) {
        if (j) wildcard.push_back('.');
        wildcard += std::to_string(255U - ip.bytes[j]);
    }
    return {prefix, std::string(dotted), wildcard};
}
Ipv4Mask mask_from_wildcard(std::string_view dotted) {
    const auto ip = planning::parse_address(dotted);
    if (ip.family != planning::Family::IPv4) throw std::invalid_argument("IPv4 wildcard required");
    std::string mask;
    for (unsigned j = 0; j < 4; ++j) {
        if (j) mask.push_back('.');
        mask += std::to_string(255U - ip.bytes[j]);
    }
    return mask_from_netmask(mask);
}
std::string acl_match(std::string_view cidr) {
    const auto item = planning::parse_cidr(cidr);
    if (item.network.family == planning::Family::IPv6) return "ipv6 " + item.str();
    // Wildcard of network prefix: construct directly from bit positions.
    std::uint32_t wildcard = item.prefix == 0 ? 0xFFFFFFFFU : ~(0xFFFFFFFFU << (32U - item.prefix));
    std::string bits;
    for (unsigned j = 0; j < 4; ++j) {
        if (j) bits.push_back('.');
        bits += std::to_string((wildcard >> (24U - 8U * j)) & 255U);
    }
    return "ip " + item.network.str() + " " + bits;
}

ProbeResult probe_tcp_numeric(std::string_view numeric_ip, const ProbeOptions& options) {
    check_numeric_ip(numeric_ip);
    if (options.port == 0 || options.count < 1 || options.count > 5 ||
        options.timeout_ms < 100 || options.timeout_ms > 2000 ||
        options.interval_ms < 200 || options.interval_ms > 2000 ||
        static_cast<std::uint64_t>(options.count) * options.timeout_ms +
        static_cast<std::uint64_t>(options.count - 1U) * options.interval_ms > 10000)
        throw std::invalid_argument("probe limits: port 1..65535, count 1..5, timeout 100..2000ms, interval 200..2000ms, total <= 10000ms");
#ifdef _WIN32
    SocketRuntime runtime;
#endif
    const auto target = std::string(numeric_ip);
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo* raw = nullptr;
    const auto service = std::to_string(options.port);
    const auto status = getaddrinfo(target.c_str(), service.c_str(), &hints, &raw);
    if (status != 0) throw std::runtime_error("invalid numeric probe target: " + gai_failure(status));
    struct Guard { addrinfo* p; ~Guard() { if (p) freeaddrinfo(p); } } guard{raw};
    if (!raw || (raw->ai_family != AF_INET && raw->ai_family != AF_INET6))
        throw std::runtime_error("unsupported probe target family");
    ProbeResult result{target, utc_now(), options, {}};
    for (unsigned attempt = 0; attempt < options.count; ++attempt) {
        const auto start = std::chrono::steady_clock::now();
        ProbeAttempt observation{};
        SocketGuard fd(::socket(raw->ai_family, SOCK_STREAM, IPPROTO_TCP));
        if (fd.s == invalid_socket) {
            observation.outcome = "error";
            observation.detail = "socket creation failed (code " + std::to_string(last_error()) + ")";
        } else {
            set_nonblocking(fd.s);
            const int connect_rc = ::connect(fd.s, raw->ai_addr, static_cast<SocketLength>(raw->ai_addrlen));
            if (connect_rc == 0) observation.outcome = "connected";
            else {
                const int err = last_error();
                if (err == refused_error()) observation.outcome = "refused";
                else if (err != inprogress_error()
#ifdef _WIN32
                         && err != WSAEINPROGRESS
#else
                         && err != EALREADY
#endif
                ) { observation.outcome = "error"; observation.detail = "connect failed (code " + std::to_string(err) + ")"; }
                else {
#ifdef _WIN32
                    fd_set writefds, exceptfds;
                    FD_ZERO(&writefds); FD_ZERO(&exceptfds);
                    FD_SET(fd.s, &writefds); FD_SET(fd.s, &exceptfds);
                    timeval timeout{static_cast<long>(options.timeout_ms / 1000U),
                                    static_cast<long>((options.timeout_ms % 1000U) * 1000U)};
                    const int ready = select(0, nullptr, &writefds, &exceptfds, &timeout);
#else
                    pollfd watch{fd.s, POLLOUT, 0};
                    const int ready = poll(&watch, 1, static_cast<int>(options.timeout_ms));
#endif
                    if (ready == 0) observation.outcome = "timeout";
                    else if (ready < 0) { observation.outcome = "error"; observation.detail = "socket wait failed"; }
                    else {
                        int so_error = 0;
#ifdef _WIN32
                        int len = static_cast<int>(sizeof(so_error));
#else
                        SocketLength len = sizeof(so_error);
#endif
                        if (getsockopt(fd.s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len) != 0) {
                            observation.outcome = "error"; observation.detail = "SO_ERROR query failed";
                        } else if (so_error == 0) observation.outcome = "connected";
                        else if (so_error == refused_error()) observation.outcome = "refused";
                        else { observation.outcome = "error"; observation.detail = "connect error " + std::to_string(so_error); }
                    }
                }
            }
        }
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        observation.elapsed_ms = static_cast<std::uint32_t>(std::max<std::int64_t>(0, elapsed));
        result.attempts.push_back(std::move(observation));
        if (attempt + 1 < options.count) std::this_thread::sleep_for(std::chrono::milliseconds(options.interval_ms));
    }
    return result;
}

std::string format(const DnsResult& r) {
    std::ostringstream out;
    out << "DNS lookup: " << r.query << "\nObserved UTC: " << r.observed_utc << '\n';
    if (r.addresses.empty()) out << "No addresses returned\n";
    for (const auto& ip : r.addresses) out << ip << '\n';
    return out.str();
}
std::string format(const ReverseResult& r) {
    return "Reverse DNS: " + r.address + "\nObserved UTC: " + r.observed_utc + "\nPTR: " + r.hostname + "\n";
}
std::string format(const std::vector<Interface>& result) {
    std::ostringstream out;
    out << "Local interfaces (read-only)\n";
    for (const auto& entry : result) {
        out << entry.name << " [index " << entry.index << ", " << (entry.up ? "UP" : "DOWN") << ", MTU " << entry.mtu << "]\n";
        for (const auto& ip : entry.addresses) out << "  address: " << ip << '\n';
        for (const auto& gw : entry.gateways) out << "  gateway: " << gw << '\n';
    }
    return out.str();
}
std::string format(const std::vector<Route>& result) {
    std::ostringstream out;
    out << "Local routing table (read-only)\n";
    for (const auto& route : result)
        out << route.destination << " via " << route.gateway << " dev " << route.interface_name << " metric " << route.metric << '\n';
    return out.str();
}
std::string format(const Ipv4Mask& r) {
    return "Prefix: /" + std::to_string(r.prefix) + "\nMask: " + r.mask + "\nWildcard: " + r.wildcard + "\n";
}
std::string format(const ProbeResult& r) {
    std::ostringstream out;
    out << "TCP probe: " << r.address << ':' << r.options.port << "\nObserved UTC: " << r.observed_utc << '\n';
    for (std::size_t i = 0; i < r.attempts.size(); ++i) {
        const auto& a = r.attempts[i];
        out << "Attempt " << (i + 1) << ": " << a.outcome << " (" << a.elapsed_ms << "ms)";
        if (!a.detail.empty()) out << " - " << a.detail;
        out << '\n';
    }
    out << "NOTE: TCP port check, not ICMP ping; refused means the host responded but the port rejected the connection.\n";
    return out.str();
}
} // namespace xorcist::diagnostics
