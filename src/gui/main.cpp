// SPDX-License-Identifier: MIT
// Dear ImGui + GLFW + OpenGL3 frontend: ALL domain logic remains in xorcist_core.
#include "xorcist/legacy.hpp"
#include "xorcist/net.hpp"
#include "xorcist/planning.hpp"
#include "xorcist/diagnostics.hpp"
#include "xorcist/xor.hpp"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

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
struct UI {
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
};

template <typename Action> void safe_run(std::string& result, Action&& action) {
    try { result = action(); }
    catch (const std::exception& e) { result = std::string("Error: ") + e.what(); }
}
void show_text(const std::string& text) {
    if (!text.empty()) ImGui::TextWrapped("%s", text.c_str());
}
template <typename Fn> void launch_diagnostic(UI& ui, Fn action) {
    if (ui.m2_future.valid()) return;
    ui.m2_result = "Query running...";
    ui.m2_future = std::async(std::launch::async, [action = std::move(action)]() mutable {
        try { return action(); }
        catch (const std::exception& error) { return std::string("Error: ") + error.what(); }
    });
}
void diagnostics_result(UI& ui) {
    if (ui.m2_future.valid()) ImGui::TextUnformatted("Working... (OS DNS queries may take time)");
    if (!ui.m2_result.empty() && ImGui::Button("Copy diagnostics result"))
        ImGui::SetClipboardText(ui.m2_result.c_str());
    ImGui::BeginChild("Diagnostic output", ImVec2(0, 185), true);
    ImGui::TextUnformatted(ui.m2_result.c_str());
    ImGui::EndChild();
}
void draw(UI& ui) {
    if (ui.m2_future.valid() &&
        ui.m2_future.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready)
        ui.m2_result = ui.m2_future.get();
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize, ImGuiCond_Always);
    constexpr ImGuiWindowFlags flags = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar;
    ImGui::Begin("XORcist 2.0", nullptr, flags);
    ImGui::TextUnformatted("XORcist 2.0 | Network planning + binary transformations");
    ImGui::Separator();
    if (ImGui::BeginTabBar("tools")) {
        if (ImGui::BeginTabItem("CIDR / IPv6")) {
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
            show_text(ui.network_result);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Relations / Ranges")) {
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
            show_text(ui.relation_result);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("IPv4 Split / VLSM")) {
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
            show_text(ui.allocation_result);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("List Import / Export")) {
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
            show_text(ui.import_result);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("M2 DNS / System")) {
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
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("M2 Masks / ACL")) {
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
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("M2 TCP Reachability")) {
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
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("XOR Text / Hex")) {
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
            show_text(ui.xor_result);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("XOR File")) {
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
            show_text(ui.file_result);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Import 2019 Java Data")) {
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
            show_text(ui.legacy_result);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
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
    if (!ImGui_ImplGlfw_InitForOpenGL(window, true)) {
        ImGui::DestroyContext(); glfwDestroyWindow(window); glfwTerminate(); return 1;
    }
    if (!ImGui_ImplOpenGL3_Init("#version 330")) {
        ImGui_ImplGlfw_Shutdown(); ImGui::DestroyContext(); glfwDestroyWindow(window); glfwTerminate(); return 1;
    }
    UI ui;
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
