# M3 local-development acceptance — Robust data tools

**Status: implementation prepared; owner verification pending.**

## Scope and security boundary

M3 introduces a new OpenSSL 3.x `libcrypto` dependency for **AES-256-GCM + scrypt** authenticated-file encryption; it is separate from the unchanged educational XOR operations. This is a development candidate, **not** a third-party cryptographic audit or cross-platform release. Debian 12/13, Ubuntu 24.04/26.04 matrix, native Windows 10/11 and signed installer qualification remain under M4.

## Required local Ubuntu 26.04 verification

Install `libssl-dev` (in addition to existing CMake/Ninja/GLFW/OpenGL packages).

```bash
cmake -S . -B build-m3 -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DXORCIST_BUILD_CLI=ON -DXORCIST_BUILD_GUI=OFF -DXORCIST_BUILD_TESTS=ON
cmake --build build-m3 --parallel
ctest --test-dir build-m3 --output-on-failure
# Expected: 8/8 CTest suites when Python3 is available.

cmake -S . -B build-m3-gui -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DXORCIST_BUILD_CLI=ON -DXORCIST_BUILD_GUI=ON \
  -DXORCIST_BUILD_TESTS=ON -DXORCIST_FETCH_GLFW=OFF
cmake --build build-m3-gui --parallel
ctest --test-dir build-m3-gui --output-on-failure
# Expected: 9/9 including GUI smoke.
./build-m3-gui/xorcist-gui --smoke-test
./build-m3-gui/xorcist-gui
```

### Manual file-integrity smoke

```bash
mkdir -p /tmp/xorcist-m3-demo
printf 'private\000file\377data\n' > /tmp/xorcist-m3-demo/plain.bin
./build-m3/xorcist data inspect --in /tmp/xorcist-m3-demo/plain.bin
./build-m3/xorcist data base64 encode --in /tmp/xorcist-m3-demo/plain.bin --out /tmp/xorcist-m3-demo/base64.txt
./build-m3/xorcist data base64 decode --in /tmp/xorcist-m3-demo/base64.txt --out /tmp/xorcist-m3-demo/decoded.bin
cmp /tmp/xorcist-m3-demo/plain.bin /tmp/xorcist-m3-demo/decoded.bin
./build-m3/xorcist data bits --hex a5
./build-m3/xorcist data mask --hex f0 --mask-hex 0f --op or
```

Secure mode prompts for a hidden passphrase without putting secrets on the command line:

```bash
./build-m3/xorcist secure encrypt --in /tmp/xorcist-m3-demo/plain.bin --out /tmp/xorcist-m3-demo/encrypted.xorc3
./build-m3/xorcist secure decrypt --in /tmp/xorcist-m3-demo/encrypted.xorc3 --out /tmp/xorcist-m3-demo/verified.bin
cmp /tmp/xorcist-m3-demo/plain.bin /tmp/xorcist-m3-demo/verified.bin
```

Enter the same strong passphrase for both commands. Verify a wrong passphrase rejects and **does not create an output**. Use unique output filenames and don't paste passwords into shell commands. Manually exercise both new GUI tabs, including a deliberately incorrect decryption password. Verify there are no leftover `*.xorcist-tmp-*` files after *caught errors*. Abnormal termination can leave temporary plaintext; see `SECURITY.md`.

### Sanitizer + fuzz (Clang)

```bash
cmake -S . -B build-m3-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++ -DXORCIST_BUILD_GUI=OFF \
  -DXORCIST_BUILD_TESTS=ON -DXORCIST_BUILD_FUZZER=ON \
  '-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer -O1' \
  '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined'
cmake --build build-m3-asan --parallel
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-m3-asan --output-on-failure
mkdir -p /tmp/xorcist-m3-fuzz
printf 'TWFu' > /tmp/xorcist-m3-fuzz/base64.txt
./build-m3-asan/xorcist_fuzz_data /tmp/xorcist-m3-fuzz -runs=3000 -max_len=512
# A separate bounded structural header fuzzer is built as xorcist_fuzz_envelope.
```

### Acceptance evidence

Capture GCC compiler, CTest 8/8 + 9/9 results, GUI two-frame smoke, GUI manual behavior (both tabs), OpenSSL version from `openssl version`, the wrong-password rejection behavior, and any warnings. **Do not commit** until any test/UX problems are reviewed. M0/M4 deferred release qualification remains tracked separately.
