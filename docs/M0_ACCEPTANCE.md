# M0 — Local development acceptance and deferred release qualification

**Decision (November 7, 2026): LOCAL DEVELOPMENT ACCEPTED.** M0 has been closed
for ongoing development against the user's Ubuntu 26.04 / GCC 15.2.0 workstation.
The original multi-platform and signed release qualification gates below are
**deferred**, not passed or waived, and must be completed before a public release.
This is a deliberate change to M0's *development* acceptance scope, not a claim
that every criterion in the original roadmap has been satisfied.

## Development evidence supplied by project owner

- Ubuntu 26.04 GCC 15.2.0 Debug CLI configure/build: PASS.
- `xorcist_core_tests` + `xorcist_net_properties`: 2/2 CTest PASS.
- Ubuntu 26.04 GCC 15.2.0 Release GUI configure/build: PASS (19/19 steps).
- `xorcist_gui_smoke`, core, properties: 3/3 CTest PASS.
- `xorcist-gui --smoke-test`: `PASS: GUI initialized, rendered two frames and shut down`.
- Interactive GUI launched. Detailed per-widget/manual file-operation results were
  not separately supplied.
- Owner reports completing the other M0 checks; raw local sanitizer, fuzz,
  candidate archive and signature logs were not included in this review.

**Carry-forward release checklist:** Complete Gates A–E below at release time
and record CI run URLs, device/OS evidence, artifact digests, SBOM verification
and provenance. Local development acceptance does not authorize publication.

## Gate A — Fresh source checkouts and Linux CLI/GUI

Run `.github/workflows/ci.yml` after applying the patch. Required green jobs:

| Platform | CLI, core/property tests | GUI compile, hidden 2-frame smoke | Fresh install archive |
|---|---|---|---|
| Debian 12 | pending CI | pending CI | pending CI |
| Debian 13 | pending CI | pending CI | pending CI |
| Ubuntu 26.04 | pending CI | pending CI | pending CI |

The GUI smoke test uses Xvfb with Mesa software rendering in Linux CI. It is **not** an interactive desktop usability test, nor a guarantee that every GPU driver works.

Record CI run URL, commit SHA, package checksum and any failure logs. The Linux archives are **portable install trees**, not `.deb` packages; Debian-native packaging remains M4.

## Gate B — Windows 10 AND Windows 11 real hardware

CI additionally compiles the GUI with MSVC on a Windows hosted runner and runs `xorcist-gui --smoke-test`. This hosted environment is **not** a substitute for either physical Windows test.

On each of Windows 10 x64 and Windows 11 x64:

1. Unpack the `windows-x64.zip` candidate artifact from a successful CI run on a clean test machine (not the developer build tree).
2. Confirm the OS build with `winver`, architecture with `systeminfo`, GPU/driver and runtime dependencies using `dumpbin /DEPENDENTS` or a comparable dependency inspector.
3. Run `bin\xorcist.exe --help` and `bin\xorcist.exe net summarize 192.168.1.1/24 192.168.2.1/24`.
4. Run `bin\xorcist-gui.exe --smoke-test`, then `bin\xorcist-gui.exe` without flags; verify every tab, CIDR calculations, XOR text/file round trips with NON-SENSITIVE test fixtures, and legacy test fixture recovery.
5. Close normally; check Event Viewer for process faults and record the exit code of the `--smoke-test` run, screenshots, OS build, and whether extra redistributables were installed.
6. Inspect Windows C++ runtime availability: MSVC builds may need the corresponding VC++ runtime. The ZIP is **not promised truly standalone** until validated without developer toolchains installed.

Evidence: retain paths to reports/screenshots outside the source tree until reviewed; don't commit sensitive local paths or real secrets.

## Gate C — sanitizer / property-based / fuzz

The `sanitizers-fuzz` CI job must be green. It uses Clang ASan+UBSan, 6,000 seeded property cases with an independent /24 address oracle, a source-instrumented libFuzzer target, and 3,000 bounded fuzz iterations. This provides **initial exercise**, not exhaustive fuzz assurance. Preserve any discovered crashes or interesting minimized inputs as regression cases.

Local commands:

```bash
cmake -S . -B build-m0-asan -G Ninja -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug -DXORCIST_BUILD_GUI=OFF -DXORCIST_BUILD_FUZZER=ON \
  '-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer -O1' \
  '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined'
cmake --build build-m0-asan --parallel
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-m0-asan --output-on-failure
mkdir -p build-m0-corpus
cp tests/corpus/net/* build-m0-corpus/
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  ./build-m0-asan/xorcist_fuzz_net build-m0-corpus -runs=3000 -max_len=512 -timeout=10
```

`build-m0-corpus/` should stay untracked; move reproducing crash cases to `tests/corpus/net/` only after review.

## Gate D — supply-chain inventory, source locks, signing

- `cmake/dependencies.lock.cmake` locks the downloaded Dear ImGui and GLFW source commit IDs.
- System toolchains, OpenGL drivers and glibc are **not pinned**. Full bit-for-bit reproducible Linux builds across distribution dates are not claimed.
- `scripts/package_candidate.py` creates deterministic `.zip`/`.tar.gz` from an identical staged filesystem with stable timestamps, metadata and ordering. It embeds SPDX 2.3 **file inventory** and declared direct dependencies, plus a source/dependency manifest.
- `scripts/check_candidate.py` verifies archive digest, embedded SPDX file digests, and inventory completeness. These inventories do **not** enumerate all transitive ELF/PE OS libraries.
- The manually dispatched `signed-candidates` job signs each CI archive with keyless Sigstore/Cosign. It verifies the certificate identity before uploading `.sigstore.json` bundles. GitHub Actions runs have no release-publishing permissions; no release is created automatically.

From a manually triggered workflow on `main`, download `xorcist-m0-signed-candidates` and verify each bundle independently:

```bash
cosign verify-blob XORcist-2.0.0-m0-candidate-debian12-amd64.tar.gz \
  --bundle XORcist-2.0.0-m0-candidate-debian12-amd64.tar.gz.sigstore.json \
  --certificate-identity "https://github.com/SpilledMilkFactory/XORcist-2.0/.github/workflows/ci.yml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

This verifies signing identity and archive integrity; it does not mean the archive has passed a security audit. Checksum files are not signatures.

## Gate E — documentation and release review

- Review `README.md`, `SECURITY.md`, `THIRD_PARTY_NOTICES.md` and the exact packaged third-party license texts.
- Make an explicit decision for Windows runtime redistribution and OS/GPU library licenses.
- Inspect release archive contents and startup behavior; keep signing scoped to release candidates until acceptance.
- After all gates pass, create a separate release PR with platform evidence, artifact digests, and reviewer signoff. M0 complete status should be recorded only at that point.

### Status for this patch

**M0 IN PROGRESS — NOT RELEASE APPROVED.** Automated qualification jobs and candidate production are implemented, local CLI/core/fuzz verification completed in the development environment, with all external-platform and Windows hardware evidence still pending.
