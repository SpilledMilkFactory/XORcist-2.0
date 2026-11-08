# XORcist M0 source-dependency lock. Full binary reproducibility also requires
# pinned toolchains, distro snapshots, and GPU/system runtime dependencies.
set(XORCIST_IMGUI_VERSION "1.91.9b")
set(XORCIST_IMGUI_COMMIT "f5befd2d29e66809cd1110a152e375a7f1981f06")
set(XORCIST_GLFW_VERSION "3.4")
set(XORCIST_GLFW_COMMIT "7b6aead9fb88b3623e3b3725ebb42670cbe4c579")

# OpenSSL 3.x is an OS/vcpkg-supplied binary dependency, NOT source-pinned.
# The minimum version is an API compatibility floor, not a reproducible binary lock.
set(XORCIST_OPENSSL_MIN_VERSION "3.0")

# M4 Windows release candidate: pinned immutable vcpkg registry tag.
# Record git rev-parse HEAD and exact OpenSSL port/patches in stage metadata.
set(XORCIST_WINDOWS_VCPKG_TAG "2026.10.16")
set(XORCIST_WINDOWS_VCPKG_TRIPLET "x64-windows-static")
