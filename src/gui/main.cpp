// SPDX-License-Identifier: MIT
// Dear ImGui + GLFW + OpenGL3 frontend: ALL domain logic remains in xorcist_core.
#include "xorcist/legacy.hpp"
#include "xorcist/net.hpp"
#include "xorcist/xor.hpp"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
struct UI {
    char networks[8192] = "192.168.1.1/24\n192.168.2.1/24\n192.168.3.1/24";
    char text[8192] = "Hello, XORcist 2.0!";
    char hex[16384] = "";
    char key[4096] = "010203";
    char file_in[1024] = "";
    char file_out[1024] = "";
    char legacy_keys[1024] = "keys.dat";
    char legacy_cipher[1024] = "cipherText.dat";
    std::string network_result;
    std::string xor_result;
    std::string file_result;
    std::string legacy_result;
};

template <typename Action> void safe_run(std::string& result, Action&& action) {
    try { result = action(); }
    catch (const std::exception& e) { result = std::string("Error: ") + e.what(); }
}
void show_text(const std::string& text) {
    if (!text.empty()) ImGui::TextWrapped("%s", text.c_str());
}
void draw(UI& ui) {
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize, ImGuiCond_Always);
    constexpr ImGuiWindowFlags flags = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar;
    ImGui::Begin("XORcist 2.0", nullptr, flags);
    ImGui::TextUnformatted("XORcist 2.0 | Network planning + binary transformations");
    ImGui::Separator();
    if (ImGui::BeginTabBar("tools")) {
        if (ImGui::BeginTabItem("IPv4 / CIDR")) {
            ImGui::TextWrapped("Enter CIDR networks, one per line or whitespace separated. # starts a comment.");
            ImGui::InputTextMultiline("Networks", ui.networks, sizeof(ui.networks), ImVec2(-1, 170));
            if (ImGui::Button("Smallest enclosing supernet")) {
                safe_run(ui.network_result, [&] {
                    const auto nets = xorcist::net::parse_network_list(ui.networks);
                    const auto n = xorcist::net::enclosing_supernet(nets);
                    return "Supernet: " + n.cidr() + "\nMask: " + xorcist::net::format_ipv4(n.mask()) +
                           "\nNote: one supernet may include addresses outside the inputs.";
                });
            }
            ImGui::SameLine();
            if (ImGui::Button("Exact CIDR aggregation")) {
                safe_run(ui.network_result, [&] {
                    const auto nets = xorcist::net::collapse(xorcist::net::parse_network_list(ui.networks));
                    std::string result = "Exact union (no extra IPs):\n";
                    for (const auto& net : nets) result += net.cidr() + "\n";
                    return result;
                });
            }
            ImGui::SameLine();
            if (ImGui::Button("Inspect first network")) {
                safe_run(ui.network_result, [&] {
                    const auto nets = xorcist::net::parse_network_list(ui.networks);
                    if (nets.empty()) throw std::invalid_argument("provide at least one network");
                    return xorcist::net::inspect(nets.front());
                });
            }
            ImGui::Separator();
            show_text(ui.network_result);
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
