# XORcist 2.0

**Portable IPv4/IPv6 network planning, diagnostics, binary tools and authenticated file encryption, written in C++20.**

A modern rewrite of the original 2019 Java class project. The core has no GUI dependencies; terminal and optional Dear ImGui frontends share the same tested implementations. This is a **development baseline**, not a hardened production release.

> **Security warning:** XOR mode is for binary analysis and education. Repeating-key XOR is **not cryptographic encryption** and must not be used to protect sensitive files.

## Features implemented

| Tool | CLI | GUI | Behavior |
|---|:---:|:---:|---|
| IPv4/CIDR parsing and subnet inspection | Yes | Yes | Strict 4-octet parsing, masks, broadcast, `/31` and `/32` handling |
| Smallest enclosing IPv4/IPv6 supernet | Yes | Yes | Includes complete input CIDR ranges; may cover extra addresses |
| Exact IPv4/IPv6 aggregation | Yes | Yes | Minimal CIDR set without adding addresses |
| IPv6 parsing, normalization and range inspection | Yes | Yes | Compressed text, uppercase, IPv4-mapped addresses, `/0` through `/128` |
| CIDR overlap/intersection and route coverage | Yes | Yes | Same-family overlap and containment analysis |
| Inclusive range -> minimal CIDRs | Yes | Yes | Exact IPv4/IPv6 interval decomposition |
| Network list conversion | Yes | Yes | Newline-delimited text and strict single-column CSV (`cidr`) |
| IPv4 subnet splitting | Yes | Yes | Bounded output; custom target prefix |
| IPv4 VLSM allocation | Yes | Yes | Deterministic largest-first, traditional reserved network/broadcast slots |
| XOR raw UTF-8 text bytes -> hexadecimal | Yes | Yes | Key supplied as hex; no implicit charset conversion |
| XOR hexadecimal bytes -> hex / escaped text | Yes | Yes | No control-sequence printing |
| XOR binary file streaming | Yes | Yes | 64 KiB chunks, existing outputs never overwritten |
| Recovery of 2019 Java `.dat` files | Yes | Yes | Java `writeUTF`, Base64, original first-key logic |
| Base64/hex file encoders and decoders | Yes | Yes | Bounded binary-safe input, strict Base64 |
| Binary file inspection, diff and bit masks | Yes | Yes | Hex/ASCII inspection, bounded diff output, byte operations |
| Authenticated file encryption | Yes | Yes | OpenSSL 3.x AES-256-GCM, scrypt, versioned metadata, verified output |

No Java, NetBeans, Qt, or elevated privileges are required. M3 requires OpenSSL 3.x `libcrypto` for authenticated encryption.

## Build on Debian 12/13 or Ubuntu 26.04

CLI-only build and tests (does **not** fetch dependencies):

```bash
sudo apt install build-essential cmake ninja-build libssl-dev
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DXORCIST_BUILD_GUI=OFF
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/xorcist --help
```

GUI build (first configuration fetches **Dear ImGui v1.91.9b** at pinned commit `f5befd2d29e66809cd1110a152e375a7f1981f06` if a source directory is not specified):

```bash
sudo apt install build-essential cmake ninja-build libssl-dev git libglfw3-dev libgl1-mesa-dev
cmake -S . -B build-gui -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DXORCIST_BUILD_GUI=ON -DXORCIST_FETCH_GLFW=OFF
cmake --build build-gui --parallel
./build-gui/xorcist-gui
```

If the GUI build cannot find a system GLFW installation, install the GLFW development package or allow the `XORCIST_FETCH_GLFW=ON` fallback (GLFW **3.4** at pinned commit `7b6aead9fb88b3623e3b3725ebb42670cbe4c579`). To avoid fetching Dear ImGui on your build machine, download its tagged source independently and set `-DXORCIST_IMGUI_SOURCE_DIR=/path/to/imgui`. No GUI framework is needed for the CLI.

The **CMake default deliberately leaves GUI off** so a headless server can build the CLI with no graphics dependencies and without network access. Enable GUI explicitly as shown above.

### Windows build

Use Visual Studio 2022 / CMake 3.20+ / Git, a supported C++20 MSVC toolchain, OpenSSL 3.x (`OpenSSL::Crypto`, e.g. via vcpkg), and either GLFW via vcpkg or the FetchContent fallback. The following commands assume CMake can find the installed OpenSSL development package:

```powershell
cmake -S . -B build-win -DCMAKE_BUILD_TYPE=Release -DXORCIST_BUILD_GUI=ON
cmake --build build-win --config Release --parallel
ctest --test-dir build-win -C Release --output-on-failure
.\build-win\Release\xorcist.exe --help
.\build-win\Release\xorcist-gui.exe
```

Actual binary paths can differ by generator. GUI build needs an OpenGL-capable graphics environment. The source has not yet been release-validated on Windows; CI and a real Windows 10/11 smoke test are still required.

## CLI examples

```bash
# Smallest enclosing supernet (the 2019 example)
xorcist net summarize 192.168.1.1/24 192.168.2.1/24 192.168.3.1/24
# Supernet: 192.168.0.0/22
# Mask:     255.255.252.0

# Exact union without adding extra addresses
xorcist net collapse 10.0.0.0/25 10.0.0.128/25 10.0.1.0/24
# 10.0.0.0/23

xorcist net inspect 192.0.2.1/31
xorcist net inspect 2001:db8::1/64
xorcist net summarize --file networks.txt

# IPv6 minimal supernet and exact aggregation
xorcist net summarize 2001:db8::/32 2001:db9::/32
# Supernet: 2001:db8::/31
xorcist net collapse 2001:db8::/127 2001:db8::2/127
# 2001:db8::/126

# Relationships and exact inclusive range conversion
xorcist net contains 10.0.0.0/8 10.4.3.2
xorcist net covers 10.0.0.0/8 10.2.0.0/16
xorcist net overlap 2001:db8::/32 2001:db8:1::/48
xorcist net intersect 2001:db8::/32 2001:db8:1::/48
xorcist net conflicts 10.0.0.0/8 10.1.0.0/16 192.168.0.0/16
xorcist net range 192.0.2.7 192.0.2.20
xorcist net range 2001:db8:: 2001:db8::f

# Subnet planning (largest VLSM requests are allocated first)
xorcist net split 10.0.0.0/24 26
xorcist net vlsm 10.0.0.0/24 lan=50 wifi=20 iot=5
# lan,50,10.0.0.0/26
# wifi,20,10.0.0.64/27
# iot,5,10.0.0.96/29

# Convert between text and one-column CSV. Existing output is never replaced.
xorcist net convert --in networks.txt --out networks.csv --from lines --to csv
xorcist net convert --in networks.csv --out normalized.txt --from csv --to lines

# XOR bytes; reapply the same key to reverse. Hexadecimal output is safe for terminals.
xorcist xor text --text 'Hello!' --key-hex 010203
xorcist xor hex --hex 49676f6d6d22 --key-hex 010203

# Streaming binary files, output must not exist
xorcist xor file --in payload.bin --out payload.xor --key-hex 010203
xorcist xor file --in payload.xor --out recovered.bin --key-hex 010203

# Actual legacy Java format (original 2019 keys.dat and cipherText.dat)
xorcist legacy-decrypt --keys ./keys.dat --cipher ./cipherText.dat
xorcist legacy-decrypt --keys ./keys.dat --cipher ./cipherText.dat --out recovered.txt
```

## M2 — Passive diagnostics and administrative helpers (development patch)

M2 adds read-only network inventory, **system-resolver** A/AAAA resolution and reverse PTR lookup,
IPv4 mask/wildcard conversions, and Cisco-like ACL match fragments. Local network observation
is not a packet capture or a remote scan. The timestamp is UTC observation time rather than
DNS answer TTL, server provenance or a guaranteed DNS query timeout.

```bash
./build/xorcist diag dns localhost --family v4
./build/xorcist diag reverse 127.0.0.1
./build/xorcist diag interfaces
./build/xorcist diag routes
./build/xorcist diag mask 255.255.255.0
./build/xorcist diag wildcard 0.0.0.255
./build/xorcist diag acl 192.0.2.42/24
./build/xorcist diag probe 127.0.0.1 443 --count 2 --timeout-ms 500 --interval-ms 250
```

**TCP reachability is NOT ICMP ping.** A refused connection is reported separately from
connected, timeout and error, and does not imply application availability. The tool only
accepts a **numeric IPv4/IPv6 address** and an **explicit TCP port** for probes; resolve names
separately to select the target. Each invocation targets one endpoint, permits at most five
attempts, enforces a 100–2000 ms per-attempt timeout and 200–2000 ms inter-attempt interval,
and rejects a combined configured probe budget over 10 seconds. Scheduler delays may make
wall time slightly longer. No privileged network operations, discovery sweeps or packet capture.

The GUI gains three **M2** tabs. DNS, reverse DNS, system inventory and TCP probes run on
an asynchronous worker to keep the GUI responsive; a pending system DNS lookup may still
delay application shutdown because the platform resolver provides no portable hard deadline.

Linux uses `getifaddrs`, `SIOCGIFMTU` and read-only `/proc/net/{route,ipv6_route}` to collect
addresses, MTUs, route prefixes, gateways and metrics. Windows code paths use
`GetAdaptersAddresses` and `GetIpForwardTable2` (not yet Windows-build verified). Routes
reflect a snapshot of the host namespace and may omit policy-routing tables, VPN overlays,
or other platform-specific routing metadata; they are not authoritative for a given flow.

See [`docs/M2_ACCEPTANCE.md`](docs/M2_ACCEPTANCE.md) for local verification and limitations.

## Source tree

```text
include/xorcist/     Public cross-platform C++ core APIs
src/core/           IPv4/IPv6 planning, OS diagnostics, XOR, file streaming, legacy importer
src/cli/            Scriptable terminal frontend (planning_cli.cpp, diagnostics_cli.cpp)
src/gui/            Optional Dear ImGui + GLFW + OpenGL3 frontend
tests/              M0/M1 regression, M2 diagnostics and subprocess integration tests
docs/               Java audit, roadmap, third-party licenses
.github/workflows/  Debian/Ubuntu, Windows and GUI compile CI
```

## Security and compatibility policy

* Strict input validation, no output overwrite, bounded legacy inputs, escaped console output.
* The same key reverses XOR; there is **no** AEAD, salt, integrity check, or secure key lifecycle.
* The original format's Java-only details are preserved in **decode-only** compatibility tooling.
* IPv4/IPv6 address-family distinction is explicit. Mixed-family supernet/collapse/range operations are rejected. IPv6 zone IDs are not supported.
* CSV import/export uses one unquoted `cidr` column; it is intentionally not a general-purpose CSV parser. Newline lists permit whitespace and `#` comments.
* VLSM is IPv4 only, reserves network and broadcast addresses when estimating usable host capacity, places largest subnets first, and refuses requests that do not fit. It does not configure live routes or interfaces.
* `net split` is bounded to at most 65,536 networks in the CLI (1,024 in the GUI); overlap warnings are bounded to 1,024 input networks. Files are limited to 1 MiB / 50,000 entries.
* No promise that a GUI binary built on a modern distro runs on Debian 12. Build and package for your **oldest supported target** when selecting a portable baseline, or release per-distro packages.
* M1 passed the user's Ubuntu 26.04 / GCC 15.2.0 CLI (4/4) and GUI (5/5) tests, including the hidden-window smoke; M2 local GUI validation remains pending.
* M0/M1 are accepted for the local Ubuntu 26.04 development scope. Debian/Windows hardware, distribution verification, signed release artifacts and third-party dependency qualification remain deferred release gates. A GitHub commit is not release sign-off.

See [`SECURITY.md`](SECURITY.md), [`docs/2019_AUDIT.md`](docs/2019_AUDIT.md), [`docs/M1_ACCEPTANCE.md`](docs/M1_ACCEPTANCE.md), [`docs/M2_ACCEPTANCE.md`](docs/M2_ACCEPTANCE.md), and [`docs/ROADMAP.md`](docs/ROADMAP.md).

## License

XORcist 2.0's original source code: MIT License, copyright 2026 Christopher Sutton. Dear ImGui and GLFW remain separately licensed; see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and `docs/licenses/`.

## M0 development qualification and candidate packages

**M0 local development baseline accepted on Ubuntu 26.04 (November 7, 2026).**
Cross-platform testing and signed release qualification remain deferred and unverified.
Do not interpret candidate builds as a production release. See
[`docs/M0_ACCEPTANCE.md`](docs/M0_ACCEPTANCE.md) for the pass/fail matrix, platform-specific
verification steps, and outstanding hardware requirements.

The CI build matrix tests Linux CLI + Dear ImGui GUI on Debian 12, Debian 13, and Ubuntu 26.04;
builds a Windows x64 GUI/CLI candidate with MSVC; and runs Clang AddressSanitizer,
UndefinedBehaviorSanitizer, deterministic CIDR property tests, and libFuzzer. The GUI has a
hidden 2-frame smoke mode:

```bash
./build-gui/xorcist-gui --smoke-test
```

This must run with an OpenGL-capable display; use `xvfb-run -a` on headless Linux.

For **pinned upstream GLFW** rather than the optional system package, build with:

```bash
cmake -S . -B build-m0 -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DXORCIST_BUILD_GUI=ON -DXORCIST_BUILD_TESTS=ON \
  -DXORCIST_USE_SYSTEM_GLFW=OFF -DXORCIST_FETCH_GLFW=ON
cmake --build build-m0 --parallel
ctest --test-dir build-m0 --output-on-failure
cmake --install build-m0 --prefix stage-m0
python3 scripts/package_candidate.py --stage stage-m0 --output-dir dist \
  --platform local-linux-amd64 --format tar.gz
python3 scripts/check_candidate.py dist/*.tar.gz
```

**Source dependency locks** reside in `cmake/dependencies.lock.cmake`.
`package_candidate.py` emits a reproducible archive given identical staged bytes and
`SOURCE_DATE_EPOCH`, embeds an SPDX 2.3 file inventory and dependency manifest, and generates
an archive SHA-256 checksum file. This does **not** make runtime libraries fully statically
linked or guarantee byte-identical cross-distro compilations.

`workflow_dispatch` on `main` runs a gated CI signing job to produce Sigstore keyless bundles
for all four candidates; the workflow does not publish a GitHub Release. Independent
verification instructions are in the M0 acceptance document.


## M3 — Robust data tools (development candidate)

The original XOR commands remain educational and are **not secure encryption**.
M3 introduces separate authenticated encryption using OpenSSL 3 (`libcrypto`).
Install `libssl-dev` on Debian/Ubuntu before building the M3 source, even
for CLI-only builds:

```bash
sudo apt install libssl-dev
cmake -S . -B build-m3 -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DXORCIST_BUILD_GUI=OFF -DXORCIST_BUILD_TESTS=ON
cmake --build build-m3 --parallel
ctest --test-dir build-m3 --output-on-failure
```

M3 adds `data` commands:

```bash
xorcist data base64 encode --in input.bin --out encoded.txt
xorcist data base64 decode --in encoded.txt --out restored.bin
xorcist data hex encode --in input.bin --out encoded.hex
xorcist data hex decode --in encoded.hex --out restored.bin
xorcist data inspect --in input.bin --limit 256
xorcist data diff --left input.bin --right restored.bin --limit 32
xorcist data mask --hex f0a5 --mask-hex 0ff0 --op and
xorcist data bits --hex a5
```

Base64/hex file transforms are currently bounded to 16 MiB input size;
`diff` streams the entire files in fixed-size buffers. Encodings do not
provide confidentiality. Existing output paths are never overwritten.

Secure file encryption (requires a strong passphrase of at least 12 bytes):

```bash
xorcist secure encrypt --in input.bin --out protected.xorc3
xorcist secure decrypt --in protected.xorc3 --out restored.bin
```

When attached to a terminal, XORcist prompts with echo disabled. For a
**trusted scripted input source** only, supply `--password-stdin` and pipe a
passphrase securely without placing it into the process argument list.
Avoid storing secrets in shell history or world-readable files.

The container uses 64-byte authenticated metadata + ciphertext + 16-byte
AES-256-GCM authentication tag, OpenSSL RNG, and scrypt key derivation.
Decryption refuses wrong passwords and tampering before publishing a result.
M3 fuzzers exercise strict encoded-data parsers and unauthenticated container-header layout validation.
Intermediate plaintext is stored in a private temp file, which can remain
after process crashes; see `SECURITY.md` for significant limitations.

GUI adds **Data / Binary Tools** and **Authenticated Files** tabs. OpenSSL
3 is an additional runtime dependency; on Windows the final portable ZIP
will require explicit DLL/provider packaging and license review in M4.

See [`docs/M3_ACCEPTANCE.md`](docs/M3_ACCEPTANCE.md) for local gates and
[`docs/M3_FILE_FORMAT.md`](docs/M3_FILE_FORMAT.md) for the experimental envelope layout.


## M4 — Candidate packaging and distribution (not yet release-qualified)

`XORCIST_PACKAGE_DEB=ON` enables native Debian-family CPack packaging. Build
on the **target distribution**. CPack detects OS-level runtime dependencies,
including the distro-specific OpenSSL library; never reuse a package built on
Debian 13 as the Debian 12 release. Set `XORCIST_INSTALL_DEV_FILES=OFF` for
runtime-only packages. `xorcist` manpage and GUI `.desktop` entry are installed.

For Ubuntu 26.04 (with system GLFW development files):

```bash
cmake -S . -B build-m4 -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DXORCIST_BUILD_GUI=ON -DXORCIST_BUILD_TESTS=ON \
  -DXORCIST_PACKAGE_DEB=ON -DXORCIST_INSTALL_DEV_FILES=OFF \
  -DXORCIST_FETCH_GLFW=OFF
cmake --build build-m4 --parallel
ctest --test-dir build-m4 --output-on-failure
(cd build-m4 && cpack -G DEB)
```

Windows x64 candidates are built with MSVC `/MT`, static OpenSSL (vcpkg
`x64-windows-static`, pinned registry tag 2026.10.16), and pinned Dear ImGui
and GLFW. Its portable ZIP includes a DLL-import audit and full copyright
notices. No third-party DLLs should need redistributing; system DLL imports
and graphics drivers still require real Windows 10/11 launch checks. The
manual workflow `.github/workflows/m4-candidates.yml` builds candidate assets
and signs them keylessly **only if all platform jobs pass**. It never
publishes a GitHub Release automatically.

Follow [`docs/M4_ACCEPTANCE.md`](docs/M4_ACCEPTANCE.md),
[`docs/M4_HARDWARE_CHECKLIST.md`](docs/M4_HARDWARE_CHECKLIST.md),
[`docs/M4_UI_REVIEW.md`](docs/M4_UI_REVIEW.md), and
[`docs/M4_RELEASE_GUIDE.md`](docs/M4_RELEASE_GUIDE.md).
