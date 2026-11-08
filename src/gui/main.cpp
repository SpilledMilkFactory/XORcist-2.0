// SPDX-License-Identifier: MIT
// Dear ImGui + GLFW + OpenGL3 frontend: ALL domain logic remains in xorcist_core.
#include "xorcist/legacy.hpp"
#include "xorcist/net.hpp"
#include "xorcist/planning.hpp"
#include "xorcist/diagnostics.hpp"
#include "xorcist/data.hpp"
#include "xorcist/secure.hpp"
#include "xorcist/xor.hpp"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <openssl/crypto.h>
#include <algorithm>
#include <array>
#include <cfloat>
#include <cmath>
#include <cstring>

#include <charconv>
#include <cstdint>
#include <exception>
#include <future>
#include <chrono>
#include <functional>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
struct XorcistUI {
    char networks[8192] = "192.168.1.1/24\n192.168.2.1/24\n192.168.3.1/24";
    char relation_a[128] = "2001:db8::/32";
    char relation_b[128] = "2001:db8:100::/40";
    char relation_ip[128] = "2001:db8::1";
    char range_first[128] = "2001:db8::";
    char range_last[128] = "2001:db8::f";
    char vlsm_parent[128] = "10.0.0.0/24";
    char split_prefix[8] = "26";
    char vlsm_requests[4096] = "lan=50\nwifi=20\niot=5";
    char list_input[1024] = "networks.txt";
    char list_output[1024] = "networks.csv";
    int list_from = 0, list_to = 1;
    char text[8192] = "Hello, XORcist 2.0!";
    char hex[16384] = "";
    char key[4096] = "010203";
    char file_in[1024] = "";
    char file_out[1024] = "";
    char legacy_keys[1024] = "keys.dat";
    char legacy_cipher[1024] = "cipherText.dat";
    std::string network_result;
    std::string relation_result;
    std::string allocation_result;
    std::string import_result;
    std::string xor_result;
    std::string file_result;
    std::string legacy_result;
    char m2_host[256] = "localhost";
    char m2_ip[128] = "127.0.0.1";
    char m2_mask[64] = "255.255.255.0";
    char m2_wildcard[64] = "0.0.0.255";
    char m2_acl[128] = "192.0.2.5/24";
    int m2_port = 443;
    int m2_count = 2;
    int m2_timeout = 500;
    int m2_interval = 250;
    std::future<std::string> m2_future;
    std::string m2_result;
    char m3_input[1024] = "";
    char m3_output[1024] = "";
    char m3_left[1024] = "";
    char m3_right[1024] = "";
    char m3_hex[8192] = "a5ff";
    char m3_mask[8192] = "0f0f";
    int m3_mask_op = 0;
    int m3_encoding = 0;
    int m3_limit = 256;
    char m3_password[1024] = "";
    char m3_secure_input[1024] = "";
    char m3_secure_output[1024] = "";
    std::future<std::string> m3_future;
    std::string m3_result;
    std::string m3_secure_result;
    int active_tool = -1; // -1: dashboard, otherwise a tool page (0..11).
    bool closing_tool = false;
    float page_slide = 0.0f; // 0: off-screen below dashboard, 1: fully open.
};

template <typename Action> void safe_run(std::string& result, Action&& action) {
    try { result = action(); }
    catch (const std::exception& e) { result = std::string("Error: ") + e.what(); }
}
template <typename Fn> void launch_diagnostic(XorcistUI& ui, Fn action) {
    if (ui.m2_future.valid()) return;
    ui.m2_result = "Query running...";
    ui.m2_future = std::async(std::launch::async, [action = std::move(action)]() mutable {
        try { return action(); }
        catch (const std::exception& error) { return std::string("Error: ") + error.what(); }
    });
}
struct ToolInfo {
    const char* title;
    const char* description;
};

// Navigation metadata only; the corresponding core operations are unchanged.
constexpr std::array<ToolInfo, 12> tools{{
    {"CIDR & IPv6 Networks", "Supernets, exact aggregation, inspection and overlaps"},
    {"Network Relations & IP Ranges", "Containment, intersection and range-to-CIDR"},
    {"IPv4 Subnet Splitting & VLSM", "Split subnets and allocate usable hosts"},
    {"Network List Import & Export", "Convert newline lists and strict CSV files"},
    {"DNS & System Information", "Forward/reverse DNS, interfaces and routes"},
    {"Subnet Masks & ACL Helpers", "Netmasks, wildcard masks and ACL fragments"},
    {"TCP Reachability", "Bounded connection checks to one numeric endpoint"},
    {"Binary Data Tools", "Base64, hex, hexdumps, comparison and bitmasks"},
    {"Authenticated File Encryption", "AES-256-GCM file encryption and verification"},
    {"XOR Text & Hexadecimal", "Educational byte-wise XOR conversions"},
    {"XOR Binary Files", "Reversible XOR transformations on binary files"},
    {"Legacy Java File Recovery", "Recover original 2019 XORcist data files"},
}};

// Consume the remaining page height with a scrollable result area. There is
// intentionally no fixed 160/185px output box and no change to result data.
void result_panel(const char* label, const std::string& result) {
    ImGui::Spacing();
    ImGui::TextDisabled("%s", label);
    const float remaining = ImGui::GetContentRegionAvail().y;
    const float height = std::max(120.0f, remaining - 4.0f);
    ImGui::BeginChild(label, ImVec2(0.0f, height), ImGuiChildFlags_Borders);
    if (result.empty()) ImGui::TextDisabled("Results will appear here.");
    else ImGui::TextUnformatted(result.c_str());
    ImGui::EndChild();
}

void diagnostics_result(XorcistUI& ui) {
    if (ui.m2_future.valid()) ImGui::TextUnformatted("Working... (OS DNS queries may take time)");
    if (!ui.m2_result.empty() && ImGui::Button("Copy diagnostics result"))
        ImGui::SetClipboardText(ui.m2_result.c_str());
    result_panel("Diagnostic output", ui.m2_result);
}

// Tiles use custom foreground text drawing so titles wrap instead of being
// clipped by the default ImGui::Button label renderer.
void tool_tile(int index, float width, float height, bool enabled, XorcistUI& ui) {
    ImGui::PushID(index);
    ImGui::InvisibleButton("tile", ImVec2(width, height));
    const bool hovered = ImGui::IsItemHovered();
    const bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    const ImVec2 lo = ImGui::GetItemRectMin();
    const ImVec2 hi = ImGui::GetItemRectMax();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const ImU32 bg = IM_COL32(25, 42, 63, 255);
    const ImU32 active = IM_COL32(39, 67, 98, 255);
    const ImU32 border = IM_COL32(67, 98, 127, 255);
    const ImU32 accent = IM_COL32(100, 178, 230, 255);
    const float radius = 9.0f;
    draw->AddRectFilled(lo, hi, hovered && enabled ? active : bg, radius);
    draw->AddRect(lo, hi, hovered && enabled ? accent : border, radius, 0, 1.2f);
    draw->AddRectFilled(ImVec2(lo.x + 12.0f, lo.y + 16.0f),
        ImVec2(lo.x + 15.0f, hi.y - 16.0f), accent, 2.0f);
    const float text_x = lo.x + 26.0f;
    const float wrap_width = std::max(90.0f, width - 46.0f);
    const float title_size = ImGui::GetFontSize() * 1.11f;
    const auto title = tools[static_cast<std::size_t>(index)].title;
    const float title_height = ImGui::GetFont()->CalcTextSizeA(title_size, FLT_MAX, wrap_width, title).y;
    draw->AddText(ImGui::GetFont(), title_size, ImVec2(text_x, lo.y + 18.0f),
        IM_COL32(236, 246, 255, 255), title, nullptr, wrap_width);
    const auto subtitle = tools[static_cast<std::size_t>(index)].description;
    draw->AddText(ImGui::GetFont(), ImGui::GetFontSize() * 0.88f,
        ImVec2(text_x, lo.y + 21.0f + title_height + 9.0f),
        IM_COL32(172, 198, 222, 255), subtitle, nullptr, wrap_width);
    if (clicked && enabled) {
        ui.active_tool = index;
        ui.closing_tool = false;
        ui.page_slide = 0.0f;
    }
    if (hovered) ImGui::SetTooltip("Open %s", title);
    ImGui::PopID();
}

void dashboard(XorcistUI& ui, ImVec2 area) {
    ImGui::BeginChild("Tools dashboard", area, ImGuiChildFlags_None);
    ImGui::TextUnformatted("Select a tool");
    ImGui::TextDisabled("Choose a category to open its dedicated workspace.");
    ImGui::Spacing();
    const float gap = 12.0f;
    const float width = ImGui::GetContentRegionAvail().x;
    const int columns = width >= 820.0f ? 3 : (width >= 540.0f ? 2 : 1);
    const int rows = static_cast<int>((tools.size() + static_cast<std::size_t>(columns) - 1) /
        static_cast<std::size_t>(columns));
    const float tile_width = std::max(160.0f, (width - static_cast<float>(columns - 1) * gap) /
        static_cast<float>(columns));
    const float tile_height = std::clamp(
        (ImGui::GetContentRegionAvail().y - gap * static_cast<float>(rows - 1) - 6.0f) /
            static_cast<float>(rows), 116.0f, 152.0f);
    const bool enabled = ui.active_tool == -1;
    ImGui::BeginDisabled(!enabled);
    for (std::size_t i = 0; i < tools.size(); ++i) {
        if (i % static_cast<std::size_t>(columns) != 0) ImGui::SameLine(0.0f, gap);
        tool_tile(static_cast<int>(i), tile_width, tile_height, enabled, ui);
    }
    ImGui::EndDisabled();
    ImGui::EndChild();
}

void tool_contents(XorcistUI& ui, int tool) {
    switch (tool) {
        case 0: {

            ImGui::TextWrapped("IPv4 and IPv6 networks: one per line or separated by whitespace. # starts a comment. Aggregation requires a single address family.");
            ImGui::InputTextMultiline("Networks", ui.networks, sizeof(ui.networks), ImVec2(-1, 170));
            if (ImGui::Button("Smallest enclosing supernet")) {
                safe_run(ui.network_result, [&] {
                    const auto nets = xorcist::planning::parse_list(ui.networks, xorcist::planning::ListFormat::Lines);
                    const auto n = xorcist::planning::enclosing(nets);
                    return "Supernet: " + n.str() + "\nNote: a supernet may include extra addresses.";
                });
            }
            ImGui::SameLine();
            if (ImGui::Button("Exact aggregation")) {
                safe_run(ui.network_result, [&] {
                    const auto nets = xorcist::planning::collapse(
                        xorcist::planning::parse_list(ui.networks, xorcist::planning::ListFormat::Lines));
                    return xorcist::planning::serialize_list(nets, xorcist::planning::ListFormat::Lines);
                });
            }
            ImGui::SameLine();
            if (ImGui::Button("Inspect first")) {
                safe_run(ui.network_result, [&] {
                    const auto nets = xorcist::planning::parse_list(ui.networks, xorcist::planning::ListFormat::Lines);
                    if (nets.empty()) throw std::invalid_argument("provide a network");
                    return xorcist::planning::inspect(nets.front());
                });
            }
            if (ImGui::Button("Check overlaps")) {
                safe_run(ui.network_result, [&] {
                    const auto nets = xorcist::planning::parse_list(ui.networks, xorcist::planning::ListFormat::Lines);
                    const auto pairs = xorcist::planning::conflicts(nets);
                    if (pairs.empty()) return std::string("No overlapping networks found.");
                    std::string result;
                    for (const auto& [a, b] : pairs)
                        result += nets[a].str() + " overlaps " + nets[b].str() + "\n";
                    return result;
                });
            }
            ImGui::Separator();
            if (!ui.network_result.empty() && ImGui::Button("Copy network result"))
                ImGui::SetClipboardText(ui.network_result.c_str());
            result_panel("Network results", ui.network_result);
            break;
        }
        case 1: {

            ImGui::TextWrapped("Use CIDR blocks for overlap, intersection and route coverage. Ranges use inclusive host IP endpoints.");
            ImGui::InputText("CIDR A", ui.relation_a, sizeof(ui.relation_a));
            ImGui::InputText("CIDR B", ui.relation_b, sizeof(ui.relation_b));
            ImGui::InputText("IP address", ui.relation_ip, sizeof(ui.relation_ip));
            if (ImGui::Button("A overlaps B")) {
                safe_run(ui.relation_result, [&] {
                    return xorcist::planning::overlaps(xorcist::planning::parse_cidr(ui.relation_a),
                        xorcist::planning::parse_cidr(ui.relation_b)) ? std::string("yes") : std::string("no");
                });
            }
            ImGui::SameLine();
            if (ImGui::Button("Intersection")) {
                safe_run(ui.relation_result, [&] {
                    const auto x = xorcist::planning::intersection(xorcist::planning::parse_cidr(ui.relation_a),
                        xorcist::planning::parse_cidr(ui.relation_b));
                    return x ? x->str() : std::string("none");
                });
            }
            ImGui::SameLine();
            if (ImGui::Button("A covers B")) {
                safe_run(ui.relation_result, [&] {
                    return xorcist::planning::covers(xorcist::planning::parse_cidr(ui.relation_a),
                        xorcist::planning::parse_cidr(ui.relation_b)) ? std::string("yes") : std::string("no");
                });
            }
            ImGui::SameLine();
            if (ImGui::Button("A contains IP")) {
                safe_run(ui.relation_result, [&] {
                    return xorcist::planning::contains(xorcist::planning::parse_cidr(ui.relation_a),
                        xorcist::planning::parse_address(ui.relation_ip)) ? std::string("yes") : std::string("no");
                });
            }
            ImGui::Separator();
            ImGui::InputText("Range first IP", ui.range_first, sizeof(ui.range_first));
            ImGui::InputText("Range last IP", ui.range_last, sizeof(ui.range_last));
            if (ImGui::Button("Range to exact CIDRs")) {
                safe_run(ui.relation_result, [&] {
                    return xorcist::planning::serialize_list(
                        xorcist::planning::range_to_cidrs(xorcist::planning::parse_range(
                            ui.range_first, ui.range_last)), xorcist::planning::ListFormat::Lines);
                });
            }
            ImGui::Separator();
            if (!ui.relation_result.empty() && ImGui::Button("Copy relation result"))
                ImGui::SetClipboardText(ui.relation_result.c_str());
            result_panel("Network relationship results", ui.relation_result);
            break;
        }
        case 2: {

            ImGui::TextWrapped("Split a parent subnet, or allocate IPv4 blocks for conventional usable host counts (network/broadcast reserved). Largest request is placed first.");
            ImGui::InputText("Parent CIDR", ui.vlsm_parent, sizeof(ui.vlsm_parent));
            ImGui::InputText("New prefix", ui.split_prefix, sizeof(ui.split_prefix));
            if (ImGui::Button("Split parent")) {
                safe_run(ui.allocation_result, [&] {
                    const std::string_view s(ui.split_prefix);
                    unsigned value = 0;
                    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
                    if (ec != std::errc{} || p != s.data() + s.size() || value > 32)
                        throw std::invalid_argument("new prefix must be 0..32");
                    return xorcist::planning::serialize_list(
                        xorcist::planning::split_ipv4(xorcist::planning::parse_cidr(ui.vlsm_parent),
                            static_cast<std::uint8_t>(value), 1024), xorcist::planning::ListFormat::Lines);
                });
            }
            ImGui::InputTextMultiline("VLSM requests: name=hosts", ui.vlsm_requests, sizeof(ui.vlsm_requests), ImVec2(-1, 95));
            if (ImGui::Button("Allocate VLSM")) {
                safe_run(ui.allocation_result, [&] {
                    std::vector<xorcist::planning::HostRequest> requests;
                    std::istringstream lines(ui.vlsm_requests);
                    std::string line;
                    while (std::getline(lines, line)) {
                        if (line.empty()) continue;
                        const auto pos = line.find('=');
                        if (pos == std::string::npos) throw std::invalid_argument("expected name=hosts per line");
                        const std::string_view number(line.data() + pos + 1, line.size() - pos - 1);
                        std::uint64_t hosts = 0;
                        const auto [ptr, ec] = std::from_chars(number.data(), number.data() + number.size(), hosts);
                        if (ec != std::errc{} || ptr != number.data() + number.size())
                            throw std::invalid_argument("invalid host count");
                        requests.push_back({line.substr(0, pos), hosts});
                    }
                    const auto allocations = xorcist::planning::allocate_vlsm(
                        xorcist::planning::parse_cidr(ui.vlsm_parent), requests);
                    std::string result = "name,hosts,cidr\n";
                    for (const auto& a : allocations)
                        result += a.request.name + "," + std::to_string(a.request.hosts) + "," + a.network.str() + "\n";
                    return result;
                });
            }
            ImGui::Separator();
            if (!ui.allocation_result.empty() && ImGui::Button("Copy allocation result"))
                ImGui::SetClipboardText(ui.allocation_result.c_str());
            result_panel("Subnet planning results", ui.allocation_result);
            break;
        }
        case 3: {

            ImGui::TextWrapped("Convert network lists between plain text and strict one-column CSV (cidr header). Output files must not already exist.");
            ImGui::InputText("Input file", ui.list_input, sizeof(ui.list_input));
            ImGui::InputText("Output file", ui.list_output, sizeof(ui.list_output));
            ImGui::Combo("Input format", &ui.list_from, "lines\0csv\0");
            ImGui::Combo("Output format", &ui.list_to, "lines\0csv\0");
            if (ImGui::Button("Convert file")) {
                safe_run(ui.import_result, [&] {
                    const auto items = xorcist::planning::load_list(ui.list_input,
                        ui.list_from == 0 ? xorcist::planning::ListFormat::Lines : xorcist::planning::ListFormat::Csv);
                    xorcist::planning::save_list(ui.list_output, items,
                        ui.list_to == 0 ? xorcist::planning::ListFormat::Lines : xorcist::planning::ListFormat::Csv);
                    return "Wrote " + std::to_string(items.size()) + " networks to " + ui.list_output;
                });
            }
            ImGui::Separator();
            result_panel("Import / export results", ui.import_result);
            break;
        }
        case 4: {

            ImGui::TextWrapped("System DNS resolver; responses are timestamped, not authoritative DNS diagnostics. Read-only OS interface and route snapshots.");
            ImGui::InputText("DNS name", ui.m2_host, sizeof(ui.m2_host));
            if (ImGui::Button("Resolve A + AAAA") && !ui.m2_future.valid()) {
                const std::string host(ui.m2_host);
                launch_diagnostic(ui, [host] { return xorcist::diagnostics::format(xorcist::diagnostics::lookup(host)); });
            }
            ImGui::SameLine();
            if (ImGui::Button("IPv4 only") && !ui.m2_future.valid()) {
                const std::string host(ui.m2_host);
                launch_diagnostic(ui, [host] { return xorcist::diagnostics::format(xorcist::diagnostics::lookup(host, xorcist::diagnostics::AddressFamily::IPv4)); });
            }
            ImGui::SameLine();
            if (ImGui::Button("IPv6 only") && !ui.m2_future.valid()) {
                const std::string host(ui.m2_host);
                launch_diagnostic(ui, [host] { return xorcist::diagnostics::format(xorcist::diagnostics::lookup(host, xorcist::diagnostics::AddressFamily::IPv6)); });
            }
            ImGui::InputText("Reverse IP", ui.m2_ip, sizeof(ui.m2_ip));
            if (ImGui::Button("Reverse PTR") && !ui.m2_future.valid()) {
                const std::string ip(ui.m2_ip);
                launch_diagnostic(ui, [ip] { return xorcist::diagnostics::format(xorcist::diagnostics::reverse(ip)); });
            }
            ImGui::SameLine();
            if (ImGui::Button("List interfaces") && !ui.m2_future.valid())
                launch_diagnostic(ui, [] { return xorcist::diagnostics::format(xorcist::diagnostics::interfaces()); });
            ImGui::SameLine();
            if (ImGui::Button("List routes") && !ui.m2_future.valid())
                launch_diagnostic(ui, [] { return xorcist::diagnostics::format(xorcist::diagnostics::routes()); });
            diagnostics_result(ui);
            break;
        }
        case 5: {

            ImGui::TextWrapped("Contiguous IPv4 netmask/wildcard conversion. ACL output is a Cisco-like match fragment, NOT a complete policy rule.");
            ImGui::InputText("Netmask", ui.m2_mask, sizeof(ui.m2_mask));
            if (ImGui::Button("Convert netmask") && !ui.m2_future.valid()) safe_run(ui.m2_result, [&] {
                return xorcist::diagnostics::format(xorcist::diagnostics::mask_from_netmask(ui.m2_mask));
            });
            ImGui::InputText("Wildcard", ui.m2_wildcard, sizeof(ui.m2_wildcard));
            if (ImGui::Button("Convert wildcard") && !ui.m2_future.valid()) safe_run(ui.m2_result, [&] {
                return xorcist::diagnostics::format(xorcist::diagnostics::mask_from_wildcard(ui.m2_wildcard));
            });
            ImGui::InputText("CIDR for ACL match", ui.m2_acl, sizeof(ui.m2_acl));
            if (ImGui::Button("Generate ACL match") && !ui.m2_future.valid()) safe_run(ui.m2_result, [&] {
                return std::string("Cisco-like match fragment: ") + xorcist::diagnostics::acl_match(ui.m2_acl);
            });
            diagnostics_result(ui);
            break;
        }
        case 6: {

            ImGui::TextWrapped("Explicit TCP connect to ONE numeric address and port; not ICMP ping. No host discovery or subnet scanning. Maximum 5 connections and 10s configured budget.");
            ImGui::InputText("Numeric IPv4/IPv6", ui.m2_ip, sizeof(ui.m2_ip));
            ImGui::InputInt("TCP port", &ui.m2_port);
            ImGui::InputInt("Attempts (1..5)", &ui.m2_count);
            ImGui::InputInt("Timeout ms (100..2000)", &ui.m2_timeout);
            ImGui::InputInt("Interval ms (200..2000)", &ui.m2_interval);
            if (ImGui::Button("Probe explicitly selected endpoint") && !ui.m2_future.valid()) {
                const std::string ip(ui.m2_ip);
                const int port = ui.m2_port, count = ui.m2_count;
                const int timeout = ui.m2_timeout, interval = ui.m2_interval;
                launch_diagnostic(ui, [ip, port, count, timeout, interval] {
                    if (port < 1 || port > 65535 || count < 1 || count > 5 ||
                        timeout < 100 || timeout > 2000 || interval < 200 || interval > 2000)
                        throw std::invalid_argument("port/count/timeout/interval outside permitted range");
                    const xorcist::diagnostics::ProbeOptions config{
                        static_cast<std::uint16_t>(port), static_cast<unsigned>(count),
                        static_cast<unsigned>(timeout), static_cast<unsigned>(interval)};
                    return xorcist::diagnostics::format(xorcist::diagnostics::probe_tcp_numeric(ip, config));
                });
            }
            diagnostics_result(ui);
            break;
        }
        case 7: {

            ImGui::TextWrapped("Offline binary inspection, comparison and encoding. Base64/hex conversion files are limited to 16 MiB; existing outputs are never overwritten.");
            ImGui::InputText("Input file##m3", ui.m3_input, sizeof(ui.m3_input));
            ImGui::InputText("Output file##m3", ui.m3_output, sizeof(ui.m3_output));
            const char* encodings[] = {"Base64", "Hexadecimal"};
            ImGui::Combo("Encoding", &ui.m3_encoding, encodings, 2);
            if (ImGui::Button("Encode file")) {
                safe_run(ui.m3_result, [&] {
                    const auto input = xorcist::data::read_small_file(ui.m3_input);
                    const auto coded = ui.m3_encoding == 0 ? xorcist::data::base64_encode(input) :
                        xorcist::xor_tool::hex_encode(input);
                    xorcist::xor_tool::write_new_file(ui.m3_output, xorcist::xor_tool::to_bytes(coded));
                    return std::string("Encoded file created without overwrite.");
                });
            }
            ImGui::SameLine();
            if (ImGui::Button("Decode file")) {
                safe_run(ui.m3_result, [&] {
                    const auto input = xorcist::data::read_small_file(ui.m3_input);
                    std::string coded;
                    if (!input.empty()) coded.assign(reinterpret_cast<const char*>(input.data()), input.size());
                    const auto decoded = ui.m3_encoding == 0 ? xorcist::data::base64_decode(coded) :
                        (coded.empty() ? xorcist::data::Bytes{} : xorcist::xor_tool::hex_decode(coded));
                    xorcist::xor_tool::write_new_file(ui.m3_output, decoded);
                    return std::string("Decoded file created without overwrite.");
                });
            }
            ImGui::InputInt("Hexdump limit (1..4096)", &ui.m3_limit);
            if (ImGui::Button("Inspect input")) {
                safe_run(ui.m3_result, [&] {
                    if (ui.m3_limit < 1 || ui.m3_limit > 4096)
                        throw std::invalid_argument("inspection limit must be 1..4096");
                    return xorcist::data::hexdump_file(ui.m3_input, static_cast<std::size_t>(ui.m3_limit));
                });
            }
            ImGui::Separator();
            ImGui::InputText("Left file", ui.m3_left, sizeof(ui.m3_left));
            ImGui::InputText("Right file", ui.m3_right, sizeof(ui.m3_right));
            if (ImGui::Button("Compare files")) {
                safe_run(ui.m3_result, [&] { return xorcist::data::diff_files(ui.m3_left, ui.m3_right); });
            }
            ImGui::Separator();
            ImGui::InputText("Bytes (hex)##m3", ui.m3_hex, sizeof(ui.m3_hex));
            ImGui::InputText("Bitmask (hex)", ui.m3_mask, sizeof(ui.m3_mask));
            const char* operations[] = {"and", "or", "xor", "not"};
            ImGui::Combo("Bit operation", &ui.m3_mask_op, operations, 4);
            if (ImGui::Button("Apply bitmask")) {
                safe_run(ui.m3_result, [&] {
                    return xorcist::xor_tool::hex_encode(xorcist::data::mask_bytes(
                        xorcist::xor_tool::hex_decode(ui.m3_hex),
                        xorcist::xor_tool::hex_decode(ui.m3_mask), operations[ui.m3_mask_op]));
                });
            }
            ImGui::SameLine();
            if (ImGui::Button("Show bits")) {
                safe_run(ui.m3_result, [&] {
                    return xorcist::data::bit_string(xorcist::xor_tool::hex_decode(ui.m3_hex));
                });
            }
            if (!ui.m3_result.empty() && ImGui::Button("Copy data result"))
                ImGui::SetClipboardText(ui.m3_result.c_str());
            result_panel("Data output", ui.m3_result);
            break;
        }
        case 8: {

            ImGui::TextWrapped("AES-256-GCM, scrypt, randomized salt/nonce and authenticated versioned header. Passwords are never logged. Incorrect passwords and tampering never publish plaintext.");
            ImGui::InputText("Input file##secure", ui.m3_secure_input, sizeof(ui.m3_secure_input));
            ImGui::InputText("Output file##secure", ui.m3_secure_output, sizeof(ui.m3_secure_output));
            ImGui::InputText("Passphrase", ui.m3_password, sizeof(ui.m3_password), ImGuiInputTextFlags_Password);
            if (ui.m3_future.valid()) ImGui::TextUnformatted("Encryption/decryption running...");
            if (ImGui::Button("Encrypt authenticated file") && !ui.m3_future.valid()) {
                auto password = std::string(ui.m3_password);
                const std::string input(ui.m3_secure_input), output(ui.m3_secure_output);
                OPENSSL_cleanse(ui.m3_password, sizeof(ui.m3_password));
                ui.m3_secure_result = "Working...";
                ui.m3_future = std::async(std::launch::async,
                    [input, output, password = std::move(password)]() mutable {
                        std::string result;
                        try {
                            xorcist::secure::encrypt_file(input, output, password);
                            result = "Authenticated file encryption complete.";
                        } catch (const std::exception& e) { result = std::string("Error: ") + e.what(); }
                        if (!password.empty()) OPENSSL_cleanse(password.data(), password.size());
                        return result;
                    });
            }
            ImGui::SameLine();
            if (ImGui::Button("Decrypt + verify file") && !ui.m3_future.valid()) {
                auto password = std::string(ui.m3_password);
                const std::string input(ui.m3_secure_input), output(ui.m3_secure_output);
                OPENSSL_cleanse(ui.m3_password, sizeof(ui.m3_password));
                ui.m3_secure_result = "Working...";
                ui.m3_future = std::async(std::launch::async,
                    [input, output, password = std::move(password)]() mutable {
                        std::string result;
                        try {
                            xorcist::secure::decrypt_file(input, output, password);
                            result = "Authentication passed. Verified plaintext file published.";
                        } catch (const std::exception& e) { result = std::string("Error: ") + e.what(); }
                        if (!password.empty()) OPENSSL_cleanse(password.data(), password.size());
                        return result;
                    });
            }
            ImGui::Separator();
            ImGui::TextWrapped("Use a strong unique passphrase (12+ bytes). The passphrase is not recoverable. Do not place secrets in file paths. Output files must not already exist.");
            result_panel("Authenticated file results", ui.m3_secure_result);
            break;
        }
        case 9: {

            ImGui::TextWrapped("Binary XOR demonstration ONLY. Repeating-key XOR provides NO modern cryptographic security or integrity.");
            ImGui::InputText("Key (hexadecimal)", ui.key, sizeof(ui.key));
            ImGui::InputTextMultiline("Text (UTF-8 bytes)", ui.text, sizeof(ui.text), ImVec2(-1, 100));
            ImGui::InputTextMultiline("Hex input", ui.hex, sizeof(ui.hex), ImVec2(-1, 80));
            if (ImGui::Button("Transform text -> hex")) {
                safe_run(ui.xor_result, [&] {
                    const auto key = xorcist::xor_tool::hex_decode(ui.key);
                    const auto data = xorcist::xor_tool::to_bytes(ui.text);
                    return xorcist::xor_tool::hex_encode(xorcist::xor_tool::transform(data, key));
                });
            }
            ImGui::SameLine();
            if (ImGui::Button("Transform hex -> bytes")) {
                safe_run(ui.xor_result, [&] {
                    const auto key = xorcist::xor_tool::hex_decode(ui.key);
                    const auto data = xorcist::xor_tool::hex_decode(ui.hex);
                    const auto out = xorcist::xor_tool::transform(data, key);
                    return "Hex: " + xorcist::xor_tool::hex_encode(out) +
                           "\nEscaped bytes: " + xorcist::xor_tool::escaped_text(out);
                });
            }
            ImGui::Separator();
            result_panel("XOR text / hex results", ui.xor_result);
            break;
        }
        case 10: {

            ImGui::TextWrapped("XOR any binary file. The same key reverses the transform. Existing output files are never overwritten.");
            ImGui::InputText("Input file path", ui.file_in, sizeof(ui.file_in));
            ImGui::InputText("Output file path", ui.file_out, sizeof(ui.file_out));
            ImGui::InputText("Key (hex)##file", ui.key, sizeof(ui.key));
            if (ImGui::Button("Transform file")) {
                safe_run(ui.file_result, [&] {
                    const auto key = xorcist::xor_tool::hex_decode(ui.key);
                    xorcist::xor_tool::transform_file(ui.file_in, ui.file_out, key);
                    return std::string("Transformation complete. Output: ") + ui.file_out;
                });
            }
            ImGui::Separator();
            result_panel("XOR file results", ui.file_result);
            break;
        }
        case 11: {

            ImGui::TextWrapped("Reads original Java RandomAccessFile.writeUTF() keys.dat + cipherText.dat. Never treats XOR as secure encryption.");
            ImGui::InputText("Original keys.dat", ui.legacy_keys, sizeof(ui.legacy_keys));
            ImGui::InputText("Original cipherText.dat", ui.legacy_cipher, sizeof(ui.legacy_cipher));
            if (ImGui::Button("Recover legacy plaintext")) {
                safe_run(ui.legacy_result, [&] {
                    const auto bytes = xorcist::legacy::decrypt_java_2019(ui.legacy_keys, ui.legacy_cipher);
                    return "Recovered text (escaped): " + xorcist::xor_tool::escaped_text(bytes) +
                           "\nHex: " + xorcist::xor_tool::hex_encode(bytes);
                });
            }
            ImGui::Separator();
            result_panel("Legacy recovery results", ui.legacy_result);
            break;
        }
        default: break;
    }
}


void draw(XorcistUI& ui) {
    if (ui.m2_future.valid() &&
        ui.m2_future.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready)
        ui.m2_result = ui.m2_future.get();
    if (ui.m3_future.valid() &&
        ui.m3_future.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready)
        ui.m3_secure_result = ui.m3_future.get();

    // State advances once per rendered frame; no timers, threads or OS hooks.
    if (ui.active_tool >= 0) {
        const float delta = std::clamp(ImGui::GetIO().DeltaTime / 0.28f, 0.0f, 1.0f);
        ui.page_slide = std::clamp(ui.page_slide + (ui.closing_tool ? -delta : delta), 0.0f, 1.0f);
        if (ui.closing_tool && ui.page_slide <= 0.0f) {
            ui.active_tool = -1;
            ui.closing_tool = false;
        }
    }

    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize, ImGuiCond_Always);
    constexpr ImGuiWindowFlags flags = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    ImGui::Begin("XORcist 2.0", nullptr, flags);
    ImGui::TextUnformatted("XORcist 2.0");
    ImGui::SameLine();
    ImGui::TextDisabled("  Network planning  /  diagnostics  /  binary tools");
    ImGui::Separator();
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const ImVec2 available = ImGui::GetContentRegionAvail();
    dashboard(ui, available);

    if (ui.active_tool >= 0) {
        if (ImGui::IsKeyPressed(ImGuiKey_Escape) && ui.page_slide >= 1.0f)
            ui.closing_tool = true;
        // The page is full-sized and moves upward from below the dashboard.
        // The parent window clips its off-screen portion during the transition.
        const float eased = 1.0f - std::pow(1.0f - ui.page_slide, 3.0f);
        ImGui::SetCursorScreenPos(ImVec2(origin.x, origin.y + available.y * (1.0f - eased)));
        ImGui::PushStyleColor(ImGuiCol_ChildBg, IM_COL32(17, 26, 39, 255));
        ImGui::PushStyleColor(ImGuiCol_Border, IM_COL32(65, 100, 130, 255));
        if (ImGui::BeginChild("Tool page", available, ImGuiChildFlags_Borders,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
            const auto& info = tools[static_cast<std::size_t>(ui.active_tool)];
            ImGui::TextUnformatted(info.title);
            ImGui::SameLine();
            const float close_width = 36.0f;
            ImGui::SetCursorPosX(std::max(ImGui::GetCursorPosX(),
                ImGui::GetWindowContentRegionMax().x - close_width));
            if (ImGui::Button("X##close page", ImVec2(close_width, 27.0f)) &&
                !ui.closing_tool && ui.page_slide >= 1.0f)
                ui.closing_tool = true;
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Close tool and return to tiles");
            ImGui::TextDisabled("%s", info.description);
            ImGui::Separator();
            ImGui::BeginChild("Tool controls", ImVec2(0, 0), ImGuiChildFlags_None);
            // Keep page contents visible while sliding, but prevent operations
            // until the transition has finished.
            ImGui::BeginDisabled(ui.page_slide < 1.0f || ui.closing_tool);
            tool_contents(ui, ui.active_tool);
            ImGui::EndDisabled();
            ImGui::EndChild();
        }
        ImGui::EndChild();
        ImGui::PopStyleColor(2);
    }
    ImGui::End();
}

} // namespace

int main(int argc, char** argv) {
    const bool smoke = argc == 2 && std::string_view(argv[1]) == "--smoke-test";
    if (argc > 1 && !smoke) {
        std::cerr << "Usage: xorcist-gui [--smoke-test]\n";
        return 2;
    }
    glfwSetErrorCallback([](int code, const char* description) {
        std::cerr << "GLFW (" << code << "): " << description << '\n';
    });
    if (!glfwInit()) return 1;
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    if (smoke) glfwWindowHint(GLFW_VISIBLE, GLFW_FALSE);
    GLFWwindow* window = glfwCreateWindow(1050, 720, "XORcist 2.0", nullptr, nullptr);
    if (!window) { glfwTerminate(); return 1; }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    auto& style = ImGui::GetStyle();
    style.WindowPadding = ImVec2(12.0f, 10.0f);
    style.FramePadding = ImVec2(9.0f, 5.0f);
    style.ItemSpacing = ImVec2(9.0f, 7.0f);
    style.FrameRounding = 5.0f;
    style.ChildRounding = 7.0f;
    style.ScrollbarRounding = 5.0f;
    if (!ImGui_ImplGlfw_InitForOpenGL(window, true)) {
        ImGui::DestroyContext(); glfwDestroyWindow(window); glfwTerminate(); return 1;
    }
    if (!ImGui_ImplOpenGL3_Init("#version 330")) {
        ImGui_ImplGlfw_Shutdown(); ImGui::DestroyContext(); glfwDestroyWindow(window); glfwTerminate(); return 1;
    }
    XorcistUI ui;
    unsigned frames = 0;
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        draw(ui);
        ImGui::Render();
        int width = 0, height = 0;
        glfwGetFramebufferSize(window, &width, &height);
        glViewport(0, 0, width, height);
        glClearColor(0.09F, 0.10F, 0.12F, 1.0F);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
        if (smoke && ++frames >= 2) break;
    }
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    if (smoke) std::cout << "PASS: GUI initialized, rendered two frames and shut down\n";
    return 0;
}
