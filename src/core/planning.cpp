// SPDX-License-Identifier: MIT
#include "xorcist/planning.hpp"
#include "xorcist/xor.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <fstream>
#include <iterator>
#include <limits>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>

namespace xorcist::planning {
namespace {
std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())) != 0) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())) != 0) s.remove_suffix(1);
    return s;
}
unsigned parse_number(std::string_view s, unsigned max, int base = 10, bool allow_leading_zero = false) {
    if (s.empty() || (!allow_leading_zero && s.size() > 1 && s[0] == '0'))
        throw std::invalid_argument("empty or noncanonical numeric component");
    unsigned value = 0;
    const auto [p, error] = std::from_chars(s.data(), s.data() + s.size(), value, base);
    if (error != std::errc{} || p != s.data() + s.size() || value > max)
        throw std::invalid_argument("invalid numeric component");
    return value;
}
unsigned bits(Family family) { return family == Family::IPv4 ? 32U : 128U; }
unsigned length(Family family) { return family == Family::IPv4 ? 4U : 16U; }
void validate_family(const Address& a) {
    if (a.family != Family::IPv4 && a.family != Family::IPv6)
        throw std::invalid_argument("invalid address family");
    if (a.family == Family::IPv4 &&
        std::any_of(a.bytes.begin() + 4, a.bytes.end(), [](std::uint8_t b) { return b != 0; }))
        throw std::invalid_argument("IPv4 address contains unexpected trailing bytes");
}
int compare(const Address& a, const Address& b) {
    validate_family(a); validate_family(b);
    if (a.family != b.family) throw std::invalid_argument("IPv4 and IPv6 address families cannot be mixed");
    for (unsigned i = 0; i < length(a.family); ++i) {
        if (a.bytes[i] < b.bytes[i]) return -1;
        if (a.bytes[i] > b.bytes[i]) return 1;
    }
    return 0;
}
bool bit(const Address& a, unsigned index) { return (a.bytes[index / 8U] & (0x80U >> (index % 8U))) != 0; }
Address base(Address a, unsigned prefix) {
    validate_family(a);
    if (prefix > bits(a.family)) throw std::invalid_argument("CIDR prefix exceeds address width");
    for (unsigned i = prefix; i < bits(a.family); ++i)
        a.bytes[i / 8U] &= static_cast<std::uint8_t>(~(0x80U >> (i % 8U)));
    return a;
}
Address end_address(Address a, unsigned prefix) {
    a = base(a, prefix);
    for (unsigned i = prefix; i < bits(a.family); ++i)
        a.bytes[i / 8U] |= static_cast<std::uint8_t>(0x80U >> (i % 8U));
    return a;
}
bool increment(Address& a) {
    for (unsigned i = length(a.family); i > 0; --i) {
        if (++a.bytes[i - 1] != 0) return true;
    }
    return false;
}
void validate(const Cidr& c) {
    validate_family(c.network);
    if (c.prefix > bits(c.network.family) || compare(base(c.network, c.prefix), c.network) != 0)
        throw std::invalid_argument("invalid or unnormalized CIDR");
}
Address parse_ipv4(std::string_view s) {
    Address result{};
    unsigned start = 0;
    for (unsigned i = 0; i < 4; ++i) {
        const auto dot = s.find('.', start);
        if ((i == 3 && dot != std::string_view::npos) || (i != 3 && dot == std::string_view::npos))
            throw std::invalid_argument("IPv4 address requires exactly four octets");
        const auto end = dot == std::string_view::npos ? s.size() : dot;
        result.bytes[i] = static_cast<std::uint8_t>(parse_number(s.substr(start, end - start), 255U));
        start = static_cast<unsigned>(end) + 1U;
    }
    return result;
}
std::vector<std::uint16_t> ipv6_fields(std::string_view text, bool allow_ipv4) {
    std::vector<std::uint16_t> out;
    if (text.empty()) return out;
    std::size_t begin = 0;
    while (begin < text.size()) {
        const auto colon = text.find(':', begin);
        const auto end = colon == std::string_view::npos ? text.size() : colon;
        const auto part = text.substr(begin, end - begin);
        if (part.empty()) throw std::invalid_argument("empty IPv6 hextet");
        if (part.find('.') != std::string_view::npos) {
            if (!allow_ipv4 || end != text.size()) throw std::invalid_argument("IPv4 suffix must terminate IPv6 address");
            const auto ipv4 = parse_ipv4(part);
            out.push_back(static_cast<std::uint16_t>((ipv4.bytes[0] << 8) | ipv4.bytes[1]));
            out.push_back(static_cast<std::uint16_t>((ipv4.bytes[2] << 8) | ipv4.bytes[3]));
        } else {
            if (part.size() > 4) throw std::invalid_argument("IPv6 hextet exceeds four digits");
            out.push_back(static_cast<std::uint16_t>(parse_number(part, 0xFFFF, 16, true)));
        }
        if (colon == std::string_view::npos) break;
        begin = colon + 1;
        if (begin == text.size()) throw std::invalid_argument("trailing single ':' in IPv6 address");
    }
    return out;
}
Address parse_ipv6(std::string_view text) {
    if (text.find('%') != std::string_view::npos) throw std::invalid_argument("IPv6 zone identifiers are not supported");
    Address a{Family::IPv6, {}};
    const auto double_colon = text.find("::");
    std::vector<std::uint16_t> left, right;
    if (double_colon == std::string_view::npos) {
        left = ipv6_fields(text, true);
        if (left.size() != 8) throw std::invalid_argument("IPv6 address needs 8 hextets or :: compression");
    } else {
        if (text.find("::", double_colon + 2) != std::string_view::npos)
            throw std::invalid_argument("multiple :: sequences in IPv6 address");
        left = ipv6_fields(text.substr(0, double_colon), false);
        right = ipv6_fields(text.substr(double_colon + 2), true);
        if (left.size() + right.size() >= 8)
            throw std::invalid_argument("IPv6 :: must omit at least one hextet");
    }
    std::array<std::uint16_t, 8> fields{};
    for (std::size_t i = 0; i < left.size(); ++i) fields[i] = left[i];
    for (std::size_t i = 0; i < right.size(); ++i) fields[8 - right.size() + i] = right[i];
    for (std::size_t i = 0; i < 8; ++i) {
        a.bytes[2 * i] = static_cast<std::uint8_t>(fields[i] >> 8);
        a.bytes[2 * i + 1] = static_cast<std::uint8_t>(fields[i] & 0xFF);
    }
    return a;
}
unsigned common_prefix(const Address& a, const Address& b) {
    (void)compare(a, b);
    unsigned common = 0;
    while (common < bits(a.family) && bit(a, common) == bit(b, common)) ++common;
    return common;
}
unsigned trailing_zero_bits(const Address& a) {
    unsigned count = 0;
    for (unsigned i = bits(a.family); i > 0 && !bit(a, i - 1); --i) ++count;
    return count;
}
} // namespace

std::string Address::str() const {
    validate_family(*this);
    if (family == Family::IPv4) {
        return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." +
               std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
    }
    // Preserve the standard dotted-decimal presentation of IPv4-mapped IPv6.
    if (std::all_of(bytes.begin(), bytes.begin() + 10, [](std::uint8_t b) { return b == 0; }) &&
        bytes[10] == 0xFF && bytes[11] == 0xFF) {
        return "::ffff:" + std::to_string(bytes[12]) + "." + std::to_string(bytes[13]) + "." +
               std::to_string(bytes[14]) + "." + std::to_string(bytes[15]);
    }
    std::array<unsigned, 8> word{};
    for (unsigned i = 0; i < 8; ++i) word[i] = (static_cast<unsigned>(bytes[i * 2]) << 8) | bytes[i * 2 + 1];
    unsigned best_start = 8, best_length = 0;
    for (unsigned i = 0; i < 8;) {
        if (word[i] != 0) { ++i; continue; }
        unsigned end = i;
        while (end < 8 && word[end] == 0) ++end;
        if (end - i > best_length && end - i >= 2) { best_start = i; best_length = end - i; }
        i = end;
    }
    std::string s;
    constexpr char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 8;) {
        if (i == best_start) {
            s += "::";
            i += best_length;
            if (i == 8) break;
        } else {
            if (!s.empty() && s.back() != ':') s += ':';
            unsigned x = word[i++];
            char buf[4]; unsigned count = 0;
            do { buf[count++] = digits[x & 0xFU]; x >>= 4U; } while (x != 0);
            while (count != 0) s += buf[--count];
        }
    }
    return s;
}
std::string Cidr::str() const { validate(*this); return network.str() + "/" + std::to_string(prefix); }
Address parse_address(std::string_view text) {
    text = trim(text);
    if (text.empty()) throw std::invalid_argument("address is empty");
    return text.find(':') == std::string_view::npos ? parse_ipv4(text) : parse_ipv6(text);
}
Cidr parse_cidr(std::string_view text) {
    text = trim(text);
    const auto slash = text.find('/');
    if (slash == std::string_view::npos || text.find('/', slash + 1) != std::string_view::npos)
        throw std::invalid_argument("expected an explicit IPv4/IPv6 CIDR prefix");
    Address addr = parse_address(text.substr(0, slash));
    const auto prefix = parse_number(text.substr(slash + 1), bits(addr.family));
    return Cidr{base(addr, prefix), static_cast<std::uint8_t>(prefix)};
}
Range parse_range(std::string_view first, std::string_view last) {
    Range range{parse_address(first), parse_address(last)};
    if (compare(range.first, range.last) > 0) throw std::invalid_argument("range start exceeds end");
    return range;
}
bool contains(const Cidr& net, const Address& addr) {
    validate(net);
    return net.network.family == addr.family && compare(base(addr, net.prefix), net.network) == 0;
}
bool covers(const Cidr& outer, const Cidr& inner) {
    validate(outer); validate(inner);
    return outer.network.family == inner.network.family && outer.prefix <= inner.prefix &&
           contains(outer, inner.network);
}
bool overlaps(const Cidr& a, const Cidr& b) {
    validate(a); validate(b);
    return a.network.family == b.network.family && (covers(a, b) || covers(b, a));
}
std::optional<Cidr> intersection(const Cidr& a, const Cidr& b) {
    if (!overlaps(a, b)) return std::nullopt;
    return a.prefix > b.prefix ? a : b;
}
std::vector<std::pair<std::size_t, std::size_t>> conflicts(const std::vector<Cidr>& networks) {
    if (networks.size() > 1024) throw std::invalid_argument("conflict analysis supports at most 1024 networks");
    std::vector<std::pair<std::size_t, std::size_t>> result;
    for (std::size_t i = 0; i < networks.size(); ++i)
        for (std::size_t j = i + 1; j < networks.size(); ++j)
            if (overlaps(networks[i], networks[j])) {
                if (result.size() >= 100000) throw std::invalid_argument("too many overlapping pairs to display");
                result.emplace_back(i, j);
            }
    return result;
}
std::vector<Cidr> range_to_cidrs(const Range& range) {
    if (compare(range.first, range.last) > 0) throw std::invalid_argument("range start exceeds end");
    std::vector<Cidr> result;
    Address cursor = range.first;
    for (;;) {
        unsigned prefix = bits(cursor.family) - trailing_zero_bits(cursor);
        while (compare(end_address(cursor, prefix), range.last) > 0) ++prefix;
        result.push_back(Cidr{cursor, static_cast<std::uint8_t>(prefix)});
        Address last = end_address(cursor, prefix);
        if (compare(last, range.last) == 0) break;
        if (!increment(last)) throw std::logic_error("address overflow while converting range");
        cursor = last;
        if (result.size() > 256) throw std::logic_error("range conversion exceeded expected bound");
    }
    return result;
}
Cidr enclosing(const std::vector<Cidr>& networks) {
    if (networks.empty()) throw std::invalid_argument("at least one CIDR network is required");
    Address low = networks.front().network;
    Address high = end_address(networks.front().network, networks.front().prefix);
    for (const auto& network : networks) {
        validate(network);
        if (compare(network.network, low) < 0) low = network.network;
        const auto end = end_address(network.network, network.prefix);
        if (compare(end, high) > 0) high = end;
    }
    const auto p = common_prefix(low, high);
    return Cidr{base(low, p), static_cast<std::uint8_t>(p)};
}
std::vector<Cidr> collapse(const std::vector<Cidr>& networks) {
    if (networks.empty()) throw std::invalid_argument("at least one CIDR network is required");
    struct Span { Address first, last; };
    std::vector<Span> spans;
    spans.reserve(networks.size());
    for (const auto& network : networks) {
        validate(network);
        if (network.network.family != networks.front().network.family)
            throw std::invalid_argument("cannot collapse mixed IPv4 and IPv6 families");
        spans.push_back({network.network, end_address(network.network, network.prefix)});
    }
    std::sort(spans.begin(), spans.end(), [](const Span& a, const Span& b) {
        return compare(a.first, b.first) < 0;
    });
    std::vector<Span> joined;
    for (const auto& span : spans) {
        bool merge = false;
        if (!joined.empty()) {
            if (compare(span.first, joined.back().last) <= 0) merge = true;
            else {
                Address next = joined.back().last;
                merge = increment(next) && compare(span.first, next) <= 0;
            }
        }
        if (merge) {
            if (compare(span.last, joined.back().last) > 0) joined.back().last = span.last;
        } else joined.push_back(span);
    }
    std::vector<Cidr> result;
    for (const auto& span : joined) {
        auto cidrs = range_to_cidrs(Range{span.first, span.last});
        result.insert(result.end(), cidrs.begin(), cidrs.end());
    }
    return result;
}
std::vector<Cidr> split_ipv4(const Cidr& parent, std::uint8_t new_prefix, std::size_t max_results) {
    validate(parent);
    if (parent.network.family != Family::IPv4) throw std::invalid_argument("subnet splitting is IPv4-only");
    if (new_prefix < parent.prefix || new_prefix > 32)
        throw std::invalid_argument("new prefix must be between parent prefix and /32");
    const auto delta = static_cast<unsigned>(new_prefix - parent.prefix);
    if (max_results == 0 || delta >= 64 || (std::uint64_t{1} << delta) > max_results)
        throw std::invalid_argument("split would exceed the configured subnet count limit");
    const auto count = std::uint64_t{1} << delta;
    std::vector<Cidr> result;
    result.reserve(static_cast<std::size_t>(count));
    Address addr = parent.network;
    for (std::uint64_t i = 0; i < count; ++i) {
        result.push_back(Cidr{addr, new_prefix});
        if (i + 1 != count) {
            addr = end_address(addr, new_prefix);
            if (!increment(addr)) throw std::logic_error("subnet split overflow");
        }
    }
    return result;
}
std::vector<Allocation> allocate_vlsm(const Cidr& parent, const std::vector<HostRequest>& requests) {
    validate(parent);
    if (parent.network.family != Family::IPv4) throw std::invalid_argument("VLSM currently supports IPv4 only");
    if (requests.empty() || requests.size() > 4096) throw std::invalid_argument("provide 1..4096 host requests");
    std::set<std::string> labels;
    struct Job { HostRequest request; std::uint8_t prefix; std::uint64_t size; std::size_t index; };
    std::vector<Job> jobs;
    for (std::size_t i = 0; i < requests.size(); ++i) {
        const auto& r = requests[i];
        if (r.name.empty() || r.name.size() > 64 || !labels.insert(r.name).second)
            throw std::invalid_argument("host request labels must be unique, nonempty and at most 64 characters");
        for (char c : r.name) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-'))
                throw std::invalid_argument("VLSM labels must contain ASCII letters, digits, '_' or '-'");
        }
        if (r.hosts == 0 || r.hosts > 4294967294ULL)
            throw std::invalid_argument("host count must be in 1..4294967294");
        std::uint64_t size = 4;
        unsigned prefix = 30;
        while (size - 2 < r.hosts) { size *= 2; --prefix; }
        jobs.push_back({r, static_cast<std::uint8_t>(prefix), size, i});
    }
    std::stable_sort(jobs.begin(), jobs.end(), [](const Job& a, const Job& b) {
        return a.size > b.size;
    });
    const auto to_number = [](const Address& a) {
        return (std::uint64_t{a.bytes[0]} << 24) | (std::uint64_t{a.bytes[1]} << 16) |
               (std::uint64_t{a.bytes[2]} << 8) | a.bytes[3];
    };
    const auto from_number = [](std::uint64_t n) {
        Address a{};
        for (unsigned i = 0; i < 4; ++i) a.bytes[3 - i] = static_cast<std::uint8_t>(n >> (i * 8));
        return a;
    };
    std::uint64_t cursor = to_number(parent.network);
    const auto parent_end = to_number(end_address(parent.network, parent.prefix));
    std::vector<Allocation> allocations;
    for (const auto& job : jobs) {
        const auto aligned = (cursor + job.size - 1) / job.size * job.size;
        if (aligned > parent_end || job.size > parent_end - aligned + 1)
            throw std::invalid_argument("host requests do not fit within parent subnet");
        allocations.push_back({job.request, Cidr{from_number(aligned), job.prefix}});
        cursor = aligned + job.size;
    }
    return allocations;
}
std::vector<Cidr> parse_list(std::string_view contents, ListFormat format) {
    if (contents.size() > 1024 * 1024) throw std::invalid_argument("network list exceeds 1 MiB limit");
    std::vector<Cidr> result;
    std::istringstream stream{std::string(contents)};
    std::string line;
    unsigned line_no = 0;
    bool header_allowed = true;
    while (std::getline(stream, line)) {
        ++line_no;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string_view view = trim(line);
        if (view.empty()) continue;
        if (format == ListFormat::Lines) {
            if (const auto comment = view.find('#'); comment != std::string_view::npos)
                view = trim(view.substr(0, comment));
            std::istringstream items{std::string(view)};
            std::string item;
            while (items >> item) {
                try { result.push_back(parse_cidr(item)); }
                catch (const std::exception& e) {
                    throw std::invalid_argument("line " + std::to_string(line_no) + ": " + e.what());
                }
            }
        } else {
            if (header_allowed && view == "cidr") { header_allowed = false; continue; }
            header_allowed = false;
            // Deliberately strict one-column CSV schema. IPv4/IPv6 CIDR strings never require quoting.
            if (view.find_first_of(",\"#") != std::string_view::npos)
                throw std::invalid_argument("line " + std::to_string(line_no) + ": expected one unquoted cidr column");
            try { result.push_back(parse_cidr(view)); }
            catch (const std::exception& e) {
                throw std::invalid_argument("line " + std::to_string(line_no) + ": " + e.what());
            }
        }
        if (result.size() > 50000) throw std::invalid_argument("network list exceeds 50000 entries");
    }
    return result;
}
std::string serialize_list(const std::vector<Cidr>& networks, ListFormat format) {
    std::string result = format == ListFormat::Csv ? "cidr\n" : "";
    for (const auto& c : networks) result += c.str() + "\n";
    if (result.size() > 1024 * 1024) throw std::invalid_argument("serialized network list exceeds 1 MiB");
    return result;
}
std::vector<Cidr> load_list(const std::filesystem::path& path, ListFormat format) {
    if (!std::filesystem::is_regular_file(path) || std::filesystem::file_size(path) > 1024 * 1024)
        throw std::invalid_argument("network list must be a regular file of at most 1 MiB");
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot read network list");
    constexpr std::size_t limit = 1024U * 1024U;
    std::string content(limit + 1, '\0');
    in.read(content.data(), static_cast<std::streamsize>(content.size()));
    const auto read_count = static_cast<std::size_t>(in.gcount());
    if (in.bad()) throw std::runtime_error("failed reading network list");
    if (read_count > limit) throw std::invalid_argument("network list exceeds 1 MiB limit");
    content.resize(read_count);
    return parse_list(content, format);
}
void save_list(const std::filesystem::path& path, const std::vector<Cidr>& networks, ListFormat format) {
    const auto str = serialize_list(networks, format);
    const auto bytes = xor_tool::to_bytes(str);
    xor_tool::write_new_file(path, bytes);
}
std::string inspect(const Cidr& c) {
    validate(c);
    std::ostringstream out;
    out << "Network: " << c.str() << "\nFamily: " << (c.network.family == Family::IPv4 ? "IPv4" : "IPv6") << '\n';
    const auto last = end_address(c.network, c.prefix);
    out << "First:   " << c.network.str() << "\nLast:    " << last.str() << '\n';
    if (c.network.family == Family::IPv4) {
        const auto addresses = std::uint64_t{1} << (32 - c.prefix);
        out << "Addresses: " << addresses << "\nUsable (traditional): "
            << (c.prefix <= 30 ? addresses - 2 : addresses) << '\n';
    } else {
        out << "Addresses: 2^" << (128 - c.prefix) << '\n';
    }
    return out.str();
}
} // namespace xorcist::planning
