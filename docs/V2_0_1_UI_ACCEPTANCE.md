# XORcist 2.0.1 — Tile navigation / UI-only acceptance

## Scope

The Dear ImGui frontend replaces the horizontal tab bar with 12 dashboard
cards and an in-window sliding tool workspace. Core, CLI, cryptography,
network operations and file formats must not change. Version/package bump is
**not** included in this UI patch; handle that separately after UI acceptance.

## Ubuntu 26.04 manual visual checks

1. Launch `xorcist-gui` at its default **1050×720** size. Confirm **12 tiles** in
   **three columns/four rows**, with all category names fully visible. No
   leftover milestone-prefixed titles and no horizontal clipped tab labels.
2. Left-click every tile. Its workspace rises from the bottom and overlays the
   dashboard. Verify the title and all original controls appear and the upper
   right **X** returns to the tiles (descending animation). **Escape** also closes.
3. Confirm reopening a tool retains its input values and last results.
4. On **CIDR & IPv6 Networks**, calculate the sample supernet and confirm the
   output panel fills unused height rather than hugging the controls.
5. On **Binary Data Tools**, verify the output panel expands to the remaining
   available height; test hexdump and bitmask output, including scrolling.
6. On **DNS & System Information** and **TCP Reachability**, run a loopback-only
   operation; close the page while it is running, then reopen and check the
   completed result still appears. No implicit network operation on navigation.
7. On **Authenticated File Encryption**, confirm passphrase masking and the
   original encrypt/decrypt controls. Do not use private passwords in screenshots.
8. Resize the window to narrower widths. Dashboard switches to two and then
   one column; vertical scrolling replaces horizontal clipping. Workspaces can
   scroll when content exceeds the available height.
9. Launch on Windows 10/11 and each supported Debian/Ubuntu platform before
   promoting the patch to v2.0.1. Check different DPI/scaling settings.

## Regression commands

```bash
cmake -S . -B build-ui -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DXORCIST_BUILD_CLI=ON -DXORCIST_BUILD_GUI=ON \
  -DXORCIST_BUILD_TESTS=ON -DXORCIST_FETCH_GLFW=OFF
cmake --build build-ui --parallel
ctest --test-dir build-ui --output-on-failure
./build-ui/xorcist-gui --smoke-test
./build-ui/xorcist-gui
```

For GUI-enabled builds, **10/10 CTest suites** are expected with Python 3.
The existing GUI smoke test initializes and renders two frames; it does not
exercise tile selection or animated transitions. Those remain manual checks.

## Release hygiene

Build and test the UI patch first. After acceptance, increment the project and
candidate-package version metadata to 2.0.1, run the M4 candidate matrix on the
exact release commit, verify Sigstore bundles and installation tests, then
publish v2.0.1. Do not reuse v2.0.0 binaries or signatures.
