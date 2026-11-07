cmake_minimum_required(VERSION 3.20)
project(XORcist VERSION 2.0.0 LANGUAGES CXX)

option(XORCIST_BUILD_CLI "Build terminal application" ON)
option(XORCIST_BUILD_GUI "Build Dear ImGui desktop application (fetches ImGui source)" OFF)
option(XORCIST_BUILD_TESTS "Build automated core regression tests" ON)
option(XORCIST_FETCH_GLFW "Fetch GLFW 3.4 if no system GLFW is available" ON)
set(XORCIST_IMGUI_SOURCE_DIR "" CACHE PATH "Use predownloaded Dear ImGui 1.91.9b source instead of fetching")

add_library(xorcist_core STATIC
    src/core/net.cpp
    src/core/xor.cpp
    src/core/legacy.cpp)
target_include_directories(xorcist_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(xorcist_core PUBLIC cxx_std_20)
set_target_properties(xorcist_core PROPERTIES CXX_EXTENSIONS OFF)
if(MSVC)
    target_compile_options(xorcist_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(xorcist_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

if(XORCIST_BUILD_CLI)
    add_executable(xorcist src/cli/main.cpp)
    target_link_libraries(xorcist PRIVATE xorcist_core)
    install(TARGETS xorcist RUNTIME DESTINATION bin)
endif()

if(XORCIST_BUILD_GUI)
    include(FetchContent)
    find_package(OpenGL REQUIRED)
    find_package(glfw3 CONFIG QUIET)
    if(NOT TARGET glfw AND NOT TARGET glfw3)
        if(NOT XORCIST_FETCH_GLFW)
            message(FATAL_ERROR "GLFW3 not installed (or enable XORCIST_FETCH_GLFW)")
        endif()
        set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
        set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)
        FetchContent_Declare(glfw GIT_REPOSITORY https://github.com/glfw/glfw.git
            GIT_TAG 7b6aead9fb88b3623e3b3725ebb42670cbe4c579 GIT_SHALLOW FALSE)
        FetchContent_MakeAvailable(glfw)
    endif()
    if(NOT XORCIST_IMGUI_SOURCE_DIR)
        FetchContent_Declare(imgui GIT_REPOSITORY https://github.com/ocornut/imgui.git
            GIT_TAG f5befd2d29e66809cd1110a152e375a7f1981f06 GIT_SHALLOW FALSE)
        FetchContent_MakeAvailable(imgui)
        set(XORCIST_IMGUI_SOURCE_DIR "${imgui_SOURCE_DIR}")
    endif()
    foreach(required imgui.cpp imgui_draw.cpp imgui_widgets.cpp imgui_tables.cpp
                     backends/imgui_impl_glfw.cpp backends/imgui_impl_opengl3.cpp)
        if(NOT EXISTS "${XORCIST_IMGUI_SOURCE_DIR}/${required}")
            message(FATAL_ERROR "Dear ImGui source incomplete: ${required}")
        endif()
    endforeach()
    add_library(xorcist_imgui STATIC
        ${XORCIST_IMGUI_SOURCE_DIR}/imgui.cpp
        ${XORCIST_IMGUI_SOURCE_DIR}/imgui_draw.cpp
        ${XORCIST_IMGUI_SOURCE_DIR}/imgui_widgets.cpp
        ${XORCIST_IMGUI_SOURCE_DIR}/imgui_tables.cpp
        ${XORCIST_IMGUI_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
        ${XORCIST_IMGUI_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp)
    target_include_directories(xorcist_imgui PUBLIC
        ${XORCIST_IMGUI_SOURCE_DIR} ${XORCIST_IMGUI_SOURCE_DIR}/backends)
    if(TARGET glfw)
        target_link_libraries(xorcist_imgui PUBLIC glfw)
    else()
        target_link_libraries(xorcist_imgui PUBLIC glfw3)
    endif()
    target_link_libraries(xorcist_imgui PUBLIC OpenGL::GL)
    add_executable(xorcist-gui src/gui/main.cpp)
    target_link_libraries(xorcist-gui PRIVATE xorcist_core xorcist_imgui)
    install(TARGETS xorcist-gui RUNTIME DESTINATION bin)
endif()

if(XORCIST_BUILD_TESTS)
    include(CTest)
    add_executable(xorcist_tests tests/core_tests.cpp)
    target_link_libraries(xorcist_tests PRIVATE xorcist_core)
    target_compile_definitions(xorcist_tests PRIVATE
        XORCIST_LEGACY_KEYS="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/keys.dat"
        XORCIST_LEGACY_CIPHER="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/cipherText.dat")
    add_test(NAME xorcist_core_tests COMMAND xorcist_tests)
endif()

install(TARGETS xorcist_core ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
install(FILES README.md LICENSE THIRD_PARTY_NOTICES.md SECURITY.md DESTINATION share/doc/xorcist)
install(DIRECTORY docs/licenses/ DESTINATION share/doc/xorcist/third-party-licenses)
