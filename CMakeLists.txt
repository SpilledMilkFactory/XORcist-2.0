cmake_minimum_required(VERSION 3.20)
project(XORcist VERSION 2.0.0 LANGUAGES CXX)
include(cmake/dependencies.lock.cmake)

# Normalize permissions of implicitly created directories even when the
# developer or CI runner has a permissive umask (e.g. 0002).
set(XORCIST_INSTALL_DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
set(CMAKE_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
    ${XORCIST_INSTALL_DIRECTORY_PERMISSIONS})
set(CPACK_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
    ${XORCIST_INSTALL_DIRECTORY_PERMISSIONS})

option(XORCIST_BUILD_CLI "Build terminal application" ON)
option(XORCIST_BUILD_GUI "Build Dear ImGui desktop application (fetches ImGui source)" OFF)
option(XORCIST_BUILD_TESTS "Build automated core regression tests" ON)
option(XORCIST_BUILD_FUZZER "Build Clang libFuzzer harness (requires instrumented build)" OFF)
option(XORCIST_INSTALL_DEV_FILES "Install developer headers and static core library" ON)
option(XORCIST_PACKAGE_DEB "Enable native DEB packaging with detected runtime dependencies" OFF)
if(XORCIST_BUILD_TESTS)
    include(CTest)
endif()
option(XORCIST_FETCH_GLFW "Fetch pinned GLFW if system GLFW is disabled or unavailable" ON)
option(XORCIST_USE_SYSTEM_GLFW "Prefer distribution GLFW rather than pinned upstream GLFW" ON)
set(XORCIST_IMGUI_SOURCE_DIR "" CACHE PATH "Use predownloaded pinned Dear ImGui source instead of fetching")

add_library(xorcist_core STATIC
    src/core/net.cpp
    src/core/planning.cpp
    src/core/diagnostics.cpp
    src/core/data.cpp
    src/core/secure.cpp
    src/core/xor.cpp
    src/core/legacy.cpp)
target_include_directories(xorcist_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(xorcist_core PUBLIC cxx_std_20)
find_package(Threads REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
target_link_libraries(xorcist_core PUBLIC Threads::Threads OpenSSL::Crypto)
set_target_properties(xorcist_core PROPERTIES CXX_EXTENSIONS OFF)
if(WIN32)
    target_link_libraries(xorcist_core PUBLIC ws2_32 iphlpapi)
endif()
if(MSVC)
    target_compile_options(xorcist_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(xorcist_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

if(XORCIST_BUILD_CLI)
    add_executable(xorcist src/cli/main.cpp src/cli/planning_cli.cpp src/cli/diagnostics_cli.cpp src/cli/data_cli.cpp)
    target_link_libraries(xorcist PRIVATE xorcist_core)
    install(TARGETS xorcist RUNTIME DESTINATION bin)
    install(FILES docs/man/xorcist.1 DESTINATION share/man/man1)
endif()

if(XORCIST_BUILD_GUI)
    include(FetchContent)
    find_package(OpenGL REQUIRED)
    if(XORCIST_USE_SYSTEM_GLFW)
        find_package(glfw3 CONFIG QUIET)
    endif()
    if(NOT TARGET glfw AND NOT TARGET glfw3)
        if(NOT XORCIST_FETCH_GLFW)
            message(FATAL_ERROR "GLFW3 not installed (or enable XORCIST_FETCH_GLFW)")
        endif()
        set(GLFW_BUILD_WAYLAND OFF CACHE BOOL "" FORCE)
        set(GLFW_BUILD_X11 ON CACHE BOOL "" FORCE)
        set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
        set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)
        FetchContent_Declare(glfw GIT_REPOSITORY https://github.com/glfw/glfw.git
            GIT_TAG ${XORCIST_GLFW_COMMIT} GIT_SHALLOW FALSE)
        FetchContent_MakeAvailable(glfw)
    endif()
    if(NOT XORCIST_IMGUI_SOURCE_DIR)
        FetchContent_Declare(imgui GIT_REPOSITORY https://github.com/ocornut/imgui.git
            GIT_TAG ${XORCIST_IMGUI_COMMIT} GIT_SHALLOW FALSE)
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
    if(UNIX AND NOT APPLE)
        install(FILES packaging/linux/xorcist.desktop DESTINATION share/applications)
    endif()
    if(XORCIST_BUILD_TESTS)
        add_test(NAME xorcist_gui_smoke COMMAND xorcist-gui --smoke-test)
        set_tests_properties(xorcist_gui_smoke PROPERTIES TIMEOUT 30)
    endif()
endif()

if(XORCIST_BUILD_TESTS)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME xorcist_m4_metadata_tests COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/m4_metadata_tests.py")
        add_test(NAME xorcist_release_asset_tests COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/m4_release_assets_tests.py")
    endif()
    add_executable(xorcist_tests tests/core_tests.cpp)
    target_link_libraries(xorcist_tests PRIVATE xorcist_core)
    target_compile_definitions(xorcist_tests PRIVATE
        XORCIST_LEGACY_KEYS="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/keys.dat"
        XORCIST_LEGACY_CIPHER="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/cipherText.dat")
    add_test(NAME xorcist_core_tests COMMAND xorcist_tests)
    add_executable(xorcist_net_properties tests/net_properties.cpp)
    target_link_libraries(xorcist_net_properties PRIVATE xorcist_core)
    add_test(NAME xorcist_net_properties COMMAND xorcist_net_properties)
    set_tests_properties(xorcist_net_properties PROPERTIES TIMEOUT 120)

    add_executable(xorcist_m3_tests tests/m3_tests.cpp)
    target_link_libraries(xorcist_m3_tests PRIVATE xorcist_core)
    add_test(NAME xorcist_m3_tests COMMAND xorcist_m3_tests)
    set_tests_properties(xorcist_m3_tests PROPERTIES TIMEOUT 120)

    add_executable(xorcist_m2_tests tests/m2_tests.cpp)
    target_link_libraries(xorcist_m2_tests PRIVATE xorcist_core)
    add_test(NAME xorcist_m2_tests COMMAND xorcist_m2_tests)
    set_tests_properties(xorcist_m2_tests PROPERTIES TIMEOUT 30)

    add_executable(xorcist_m1_tests tests/m1_tests.cpp)
    target_link_libraries(xorcist_m1_tests PRIVATE xorcist_core)
    add_test(NAME xorcist_m1_tests COMMAND xorcist_m1_tests)
    set_tests_properties(xorcist_m1_tests PROPERTIES TIMEOUT 120)
    if(XORCIST_BUILD_CLI)
        find_package(Python3 COMPONENTS Interpreter QUIET)
        if(Python3_Interpreter_FOUND)
            add_test(NAME xorcist_m3_cli_tests
                COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/m3_cli_tests.py" "$<TARGET_FILE:xorcist>")
            set_tests_properties(xorcist_m3_cli_tests PROPERTIES TIMEOUT 120)
            add_test(NAME xorcist_m2_cli_tests
                COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/m2_cli_tests.py" "$<TARGET_FILE:xorcist>")
            set_tests_properties(xorcist_m2_cli_tests PROPERTIES TIMEOUT 30)
            add_test(NAME xorcist_m1_cli_tests
                COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/m1_cli_tests.py" "$<TARGET_FILE:xorcist>")
        else()
            message(WARNING "Python3 interpreter not found: M1 CLI integration tests unavailable")
        endif()
    endif()
endif()

if(XORCIST_INSTALL_DEV_FILES)
    install(TARGETS xorcist_core ARCHIVE DESTINATION lib)
    install(DIRECTORY include/ DESTINATION include)
endif()
install(FILES README.md LICENSE THIRD_PARTY_NOTICES.md SECURITY.md docs/M3_FILE_FORMAT.md DESTINATION share/doc/xorcist)
install(DIRECTORY docs/licenses/ DESTINATION share/doc/xorcist/third-party-licenses)

if(XORCIST_PACKAGE_DEB)
    if(NOT UNIX OR APPLE)
        message(FATAL_ERROR "XORCIST_PACKAGE_DEB requires a Debian-family Linux build host")
    endif()
    if(NOT XORCIST_BUILD_CLI)
        message(FATAL_ERROR "DEB packaging requires the CLI executable")
    endif()
    # Keep packaging installation paths and Debian dependency detection local
    # to the distro build. Do not hard-code libssl3 vs libssl3t64.
    set(CPACK_GENERATOR "DEB")
    set(CPACK_PACKAGE_NAME "xorcist")
    set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
    set(CPACK_PACKAGE_CONTACT "SpilledMilkFactory (GitHub issues)")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Offline-first networking and binary-data toolkit")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "SpilledMilkFactory")
    set(CPACK_DEBIAN_PACKAGE_SECTION "net")
    set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/SpilledMilkFactory/XORcist-2.0")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    # Explicitly normalize directories in the staged archive. A permissive
    # build umask or inherited setgid bit must not leak into /usr paths.
    set(CPACK_PRE_BUILD_SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/m4_normalize_deb_permissions.cmake")
    set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
    # No Debian revision suffix: package Version remains PROJECT_VERSION (e.g. 2.0.1).
    set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
    include(CPack)
endif()

if(XORCIST_BUILD_FUZZER)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "The libFuzzer target requires Clang; use -DCMAKE_CXX_COMPILER=clang++")
    endif()
    # Separate instrumented core avoids leaking libFuzzer coverage requirements
    # into the ordinary CLI and test executables.
    add_library(xorcist_fuzz_core STATIC
        src/core/net.cpp src/core/planning.cpp src/core/diagnostics.cpp src/core/data.cpp src/core/secure.cpp src/core/xor.cpp src/core/legacy.cpp)
    target_include_directories(xorcist_fuzz_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(xorcist_fuzz_core PUBLIC OpenSSL::Crypto)
    target_compile_features(xorcist_fuzz_core PUBLIC cxx_std_20)
    target_compile_options(xorcist_fuzz_core PRIVATE -fsanitize=fuzzer-no-link)
    add_executable(xorcist_fuzz_net tests/fuzz_net.cpp)
    target_link_libraries(xorcist_fuzz_net PRIVATE xorcist_fuzz_core)
    target_compile_options(xorcist_fuzz_net PRIVATE -fsanitize=fuzzer)
    target_link_options(xorcist_fuzz_net PRIVATE -fsanitize=fuzzer)
    add_executable(xorcist_fuzz_data tests/fuzz_data.cpp)
    target_link_libraries(xorcist_fuzz_data PRIVATE xorcist_fuzz_core)
    target_compile_options(xorcist_fuzz_data PRIVATE -fsanitize=fuzzer)
    target_link_options(xorcist_fuzz_data PRIVATE -fsanitize=fuzzer)
    add_executable(xorcist_fuzz_envelope tests/fuzz_envelope.cpp)
    target_link_libraries(xorcist_fuzz_envelope PRIVATE xorcist_fuzz_core)
    target_compile_options(xorcist_fuzz_envelope PRIVATE -fsanitize=fuzzer)
    target_link_options(xorcist_fuzz_envelope PRIVATE -fsanitize=fuzzer)
endif()
