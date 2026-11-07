# XORcist 2.0 — M1 IP Planning acceptance checklist

**Status: patch delivered; local application and release validation outstanding.**

This rebased M1 patch is based on `Post_M0_Proper.zip` with the separate M0 local-acceptance documentation closeout applied. No generated build trees, nested Git repositories, or third-party source trees are included. Apply it to a clean local checkout, inspect `git diff`, and do not merge until locally verified.

## 1. Linux CLI configure, build and regression checks

```bash
cmake -S . -B build-m1 -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DXORCIST_BUILD_CLI=ON \
  -DXORCIST_BUILD_GUI=OFF \
  -DXORCIST_BUILD_TESTS=ON
cmake --build build-m1 --parallel
ctest --test-dir build-m1 --output-on-failure
./build-m1/xorcist --help
```

Expected **4/4 tests** on machines with Python 3 available:

- `xorcist_core_tests` — original regressions.
- `xorcist_net_properties` — 6,000 deterministic M0 CIDR property cases.
- `xorcist_m1_tests` — C++ M1 tests with 6,000 deterministic independent range-coverage cases.
- `xorcist_m1_cli_tests` — subprocess CLI integration and negative-input checks.

If Python is not installed, only the first three tests are registered. Treat that as partial coverage, not 4/4.

## 2. Key manual CLI checks

```bash
./build-m1/xorcist net inspect 2001:db8::1/64
./build-m1/xorcist net summarize 2001:db8::/32 2001:db9::/32
# Supernet: 2001:db8::/31
./build-m1/xorcist net collapse 2001:db8::/127 2001:db8::2/127
# 2001:db8::/126
./build-m1/xorcist net contains 2001:db8::/32 2001:db8::1
# yes
./build-m1/xorcist net intersect 2001:db8::/32 2001:db8:1::/48
# 2001:db8:1::/48
./build-m1/xorcist net range 192.0.2.0 192.0.2.15
# 192.0.2.0/28
./build-m1/xorcist net range 2001:db8:: 2001:db8::f
# 2001:db8::/124
./build-m1/xorcist net split 10.0.0.0/24 26
# four /26 networks
./build-m1/xorcist net vlsm 10.0.0.0/24 lan=50 wifi=20 iot=5
# lan,50,10.0.0.0/26
# wifi,20,10.0.0.64/27
# iot,5,10.0.0.96/29
./build-m1/xorcist net conflicts 10.0.0.0/8 10.1.0.0/16
# 10.0.0.0/8 overlaps 10.1.0.0/16
```

For CSV conversion, create a newline-list file in a temporary directory and run:

```bash
printf '192.0.2.1/24\n2001:db8::/32\n' > /tmp/xorcist-m1-networks.txt
./build-m1/xorcist net convert --in /tmp/xorcist-m1-networks.txt \
    --out /tmp/xorcist-m1-networks.csv --from lines --to csv
cat /tmp/xorcist-m1-networks.csv
# cidr
# 192.0.2.0/24
# 2001:db8::/32
# Running the same command a second time must refuse to overwrite the CSV.
```

Use a unique temporary output filename or delete previous test outputs **only when you know they are test files**; the program intentionally refuses to overwrite existing files.

## 3. Linux GUI build and manual acceptance

```bash
cmake -S . -B build-m1-gui -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DXORCIST_BUILD_GUI=ON \
  -DXORCIST_BUILD_CLI=ON \
  -DXORCIST_BUILD_TESTS=ON \
  -DXORCIST_FETCH_GLFW=OFF
cmake --build build-m1-gui --parallel
ctest --test-dir build-m1-gui --output-on-failure
# Expected 5/5 with Python3 (includes M0 GUI smoke).
./build-m1-gui/xorcist-gui --smoke-test
./build-m1-gui/xorcist-gui
```

Check that the `CIDR / IPv6`, `Relations / Ranges`, `IPv4 Split / VLSM`, and `List Import / Export` tabs operate, and that the legacy XOR and Java importer tabs still work. Test invalid addresses, same-family and mixed-family comparisons, non-fitting VLSM allocations, export to an existing path, and error messages. A syntax check is **not** equivalent to this runtime test.

## 4. Sanitizers (GCC or Clang, Linux)

```bash
cmake -S . -B build-m1-asan -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug -DXORCIST_BUILD_GUI=OFF \
  -DXORCIST_BUILD_TESTS=ON \
  -DCMAKE_CXX_FLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-m1-asan --parallel
ASAN_OPTIONS=detect_leaks=1 ctest --test-dir build-m1-asan --output-on-failure
```

## 5. Gate conditions

M1 development may be committed after local build, all applicable tests and GUI manual checks pass. **M1 is not accepted as a cross-platform release feature until** the CI matrix passes and the feature is exercised on intended Windows and Linux platforms. M0 local development is accepted (see `docs/M0_ACCEPTANCE.md`); full cross-platform and signed release qualification remains deferred. Retain and run the M0 properties, fuzzing, SBOM and GUI smoke infrastructure alongside M1 tests.

### API contracts and limits

- IPv4 and IPv6 are separate families; mixed-family enclosing/aggregation/range operations are errors. IPv4-mapped IPv6 stays IPv6.
- IPv6 zone identifiers (like `%eth0`) and multiple `::` compression sequences are rejected.
- Overlaps include network containment; IPv4 `/31` and `/32` inspection semantics remain in the legacy IPv4 display path.
- Range endpoints are inclusive. CIDR range conversion is exact and does not include addresses outside the interval.
- `net convert` imports/exports *one-column* CSV (`cidr`) or newline-delimited lists with `#` comments, not arbitrary multi-column CSV. File inputs are capped at 1 MiB; outputs are exclusive-create.
- Split limits: CLI 65,536 output blocks; GUI 1,024. VLSM: IPv4 only, largest-first deterministic, conventional usable host capacity (reserve network+broadcast), no live network changes.
- Pairwise conflicts: max 1,024 input networks and 100,000 result pairs; this prevents unbounded GUI/CLI output work.
