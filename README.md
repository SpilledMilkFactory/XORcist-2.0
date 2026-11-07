# XORcist 2.0

**Portable IPv4/IPv6 network planning and binary XOR transformations, written in C++20.**

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

No Java, NetBeans, Qt, encryption dependencies, or elevated privileges are required.

## Build on Debian 12/13 or Ubuntu 26.04

CLI-only build and tests (does **not** fetch dependencies):

```bash
sudo apt install build-essential cmake ninja-build
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DXORCIST_BUILD_GUI=OFF
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/xorcist --help
```

GUI build (first configuration fetches **Dear ImGui v1.91.9b** at pinned commit `f5befd2d29e66809cd1110a152e375a7f1981f06` if a source directory is not specified):

```bash
sudo apt install build-essential cmake ninja-build git libglfw3-dev libgl1-mesa-dev
cmake -S . -B build-gui -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DXORCIST_BUILD_GUI=ON -DXORCIST_FETCH_GLFW=OFF
cmake --build build-gui --parallel
./build-gui/xorcist-gui
```

If the GUI build cannot find a system GLFW installation, install the GLFW development package or allow the `XORCIST_FETCH_GLFW=ON` fallback (GLFW **3.4** at pinned commit `7b6aead9fb88b3623e3b3725ebb42670cbe4c579`). To avoid fetching Dear ImGui on your build machine, download its tagged source independently and set `-DXORCIST_IMGUI_SOURCE_DIR=/path/to/imgui`. No GUI framework is needed for the CLI.

The **CMake default deliberately leaves GUI off** so a headless server can build the CLI with no graphics dependencies and without network access. Enable GUI explicitly as shown above.

### Windows build

Use Visual Studio 2022 / CMake 3.20+ / Git, a supported C++20 MSVC toolchain, and either GLFW via vcpkg or the FetchContent fallback:

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

## Source tree

```text
include/xorcist/     Public cross-platform C++ core APIs
src/core/           IPv4/IPv6 planning, binary XOR, file streaming, legacy Java importer
src/cli/            Scriptable terminal frontend (planning_cli.cpp)
src/gui/            Optional Dear ImGui + GLFW + OpenGL3 frontend
tests/              Baseline regression + M1 deterministic property tests and CLI integration
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
* M1 C++ core and CLI have been verified locally on Debian 13 / GCC 14.2.0, including the existing tests, a new IPv4/IPv6 planning suite, and subprocess CLI tests. The M1 GUI source passed a translation-unit syntax check using Dear ImGui headers and stub GLFW declarations; full GUI linking and runtime tests remain outstanding.
* The uploaded post-M0 project still lacks documented evidence of the M0 fuzzing, SBOM/signature, reproducibility, Debian/Windows CI and hardware gates. A GitHub commit is not release sign-off.

See [`SECURITY.md`](SECURITY.md), [`docs/2019_AUDIT.md`](docs/2019_AUDIT.md), [`docs/M1_ACCEPTANCE.md`](docs/M1_ACCEPTANCE.md), and [`docs/ROADMAP.md`](docs/ROADMAP.md).

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
