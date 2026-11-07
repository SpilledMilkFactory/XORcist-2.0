# Verification Report — XORcist 2.0 development baseline

Date: November 6, 2026 (local task environment)

| Evidence | Observed result | Scope |
|---|---|---|
| CMake configure | PASS | Debian 13, CMake/Ninja, GCC 14.2.0 |
| C++20 core build | PASS | `xorcist_core` |
| CLI build | PASS | `xorcist` |
| Core CTest suite | PASS | IPv4 parsing, supernet/collapse, invalid input, byte/file XOR, legacy import |
| ASan+UBSan compile and CTest | PASS | GCC 14.2.0 Debug; core/CLI/test target |
| CLI supernet smoke test | PASS | 3 networks -> `192.168.0.0/22` |
| XOR text/hex smoke test | PASS | `Hello!` -> `49676f6d6d22` -> `Hello!` |
| Legacy decoding of original 2019 `.dat` files | PASS | Recovers `here is some text I will encrypt` |
| Dear ImGui GUI compile or launch | NOT RUN | Original dependencies unavailable in this execution environment |
| Debian 12 and Ubuntu 26.04 CI | NOT RUN | Workflow supplied, awaiting repository Actions execution |
| Windows 10/11 core and GUI | NOT RUN | GUI compilation workflow supplied but not yet run; manual launch test required |
| Debian/Windows release packaging | NOT IMPLEMENTED | Future release milestone |

## Reproduce core checks

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DXORCIST_BUILD_GUI=OFF
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/xorcist net summarize 192.168.1.1/24 192.168.2.1/24 192.168.3.1/24
./build/xorcist xor text --text 'Hello!' --key-hex 010203
./build/xorcist xor hex --hex 49676f6d6d22 --key-hex 010203
```

## Reproduce sanitizer checks (GCC/Clang Linux)

```bash
cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
    -DXORCIST_BUILD_GUI=OFF -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -O1' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-asan --parallel
ASAN_OPTIONS=detect_leaks=1 ctest --test-dir build-asan --output-on-failure
```

This is a development-stage verification report, not a cross-platform release certification. The bundled GUI is source code whose compilation still requires follow-up validation.
