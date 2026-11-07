# Milestone M2 — Passive Diagnostics / Administration: Acceptance

## Scope and decision

M2 introduces read-only OS network inventory, system DNS resolution, IPv4 mask/wildcard
and Cisco-like ACL match helpers, and explicitly bounded single-target TCP probes. All
behavior uses the shared `xorcist_core`, invoked by CLI and Dear ImGui.

**Acceptance status: implementation proposed, pending Ubuntu 26.04 local GUI validation.**
M1 is accepted for the user's local development scope based on GCC 15.2.0 and 4/4 CLI,
5/5 GUI tests and successful hidden-window smoke. Debian 12/13, Ubuntu 24.04 and Windows
qualification remain deferred to the release phase, not blockers for local M2 work.

## Apply patch safely

The ZIP is a **delta patch against the exact uploaded `Post_M1.zip` source**. It excludes
`.git/`, all build directories, `imgui.ini`, third-party dependencies and binary fixtures.

1. Ensure `git status --short` is clean, then create a branch (`git switch -c m2-passive-diagnostics`).
2. Extract the contents into your repository root, allowing replacement of matching files.
3. Check `git status --short` and `git diff --check` before building. Do not overwrite your own
   newer changes without reviewing the diff.
4. If you have already applied another post-M1 patch, reconcile it instead of blindly extracting.

## Ubuntu 26.04 CLI verification

```bash
cmake -S . -B build-m2 -G Ninja -DCMAKE_BUILD_TYPE=Debug \
    -DXORCIST_BUILD_CLI=ON -DXORCIST_BUILD_GUI=OFF -DXORCIST_BUILD_TESTS=ON
cmake --build build-m2 --parallel
ctest --test-dir build-m2 --output-on-failure
./build-m2/xorcist --help
./build-m2/xorcist diag dns localhost --family v4
./build-m2/xorcist diag reverse 127.0.0.1
./build-m2/xorcist diag interfaces
./build-m2/xorcist diag routes
./build-m2/xorcist diag mask 255.255.255.0
./build-m2/xorcist diag wildcard 0.0.0.255
./build-m2/xorcist diag acl 192.0.2.9/24
./build-m2/xorcist diag acl 2001:db8::1/64
./build-m2/xorcist diag probe 127.0.0.1 1 --count 1 --timeout-ms 200
```

**Expected:** 6/6 CTest suites (assuming Python 3 is installed). DNS may depend on local
`/etc/hosts` and resolver configuration; `localhost` should normally return loopback.
Reverse PTR may legitimately fail if no PTR is configured; record the error and environment.
Interfaces and routes are environment-specific; inspect that entries and gateways make sense.
`mask` and `wildcard` return `/24`, `255.255.255.0` and `0.0.0.255`; ACL returns normalized
IPv4/IPv6 match fragments. TCP 127.0.0.1:1 may say `refused` or `connected` depending on
whether the port has a listener. It must not probe a subnet or repeat beyond the explicit count.

Negative cases (must exit with code 2, no network request):

```bash
./build-m2/xorcist diag probe localhost 80
./build-m2/xorcist diag probe 127.0.0.1 80 --count 100
./build-m2/xorcist diag mask 255.0.255.0
./build-m2/xorcist diag acl 192.0.2.1/99
```

## GUI verification

```bash
cmake -S . -B build-m2-gui -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DXORCIST_BUILD_CLI=ON -DXORCIST_BUILD_GUI=ON \
    -DXORCIST_BUILD_TESTS=ON -DXORCIST_FETCH_GLFW=OFF
cmake --build build-m2-gui --parallel
ctest --test-dir build-m2-gui --output-on-failure
./build-m2-gui/xorcist-gui --smoke-test
./build-m2-gui/xorcist-gui
```

**Expected:** 7/7 CTest suites (including the existing GUI smoke). Inspect the three new
M2 tabs. Run the same localhost DNS, read-only interface/route snapshot, mask/wildcard,
ACL fragment and single-endpoint TCP probe in the GUI; check errors display without crashing.
Verify the UI remains interactive during the short TCP probe and that previous M0/M1 tabs
continue to operate. DNS can outlive the GUI's immediate work, depending on OS resolver policy.

## Sanitizers / supply-chain regression

```bash
cmake -S . -B build-m2-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_COMPILER=clang++ -DXORCIST_BUILD_GUI=OFF -DXORCIST_BUILD_TESTS=ON \
    '-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer -O1' \
    '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined'
cmake --build build-m2-asan --parallel
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
    ctest --test-dir build-m2-asan --output-on-failure
```

M0 candidate packaging, SPDX, GitHub Actions and cross-platform release testing remain in
place. New M2 code is exercised by CI's existing Linux CTest runner. Windows testing is
**not claimed**; the existing CI file has Windows jobs disabled pending release qualification.

## Gate

Accept M2 for **Ubuntu 26.04 local development** only after CLI 6/6, GUI 7/7, hidden
smoke, and functional GUI checks are confirmed. Do not promote to a release, even if all
local tests pass, until deferred cross-platform release requirements are addressed.
