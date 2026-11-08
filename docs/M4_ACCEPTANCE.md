# M4 — Distribution Acceptance and Release Authorization

**State:** implementation candidate; public release **NOT APPROVED**.
Previous M0–M3 *local* milestones remain complete. M4's criteria are additive.

## Required acceptance gates

1. **Build:** four clean source checkouts in Debian 12, Debian 13, Ubuntu 24.04,
   and Ubuntu 26.04 (amd64) build CLI and GUI against pinned Dear ImGui/GLFW.
   CTest and `xorcist-gui --smoke-test` under Xvfb pass in each image. Record
   compiler, OpenSSL, GLFW and exact build workflow commit hashes.
2. **Linux packaging:** each image produces its own installable `xorcist`
   `.deb` with both executables, GUI desktop entry, CLI man page and licenses.
   `dpkg-deb`, `ldd`, and `readelf` confirm runtime imports and GLIBC symbol ceilings. Confirm `Depends`
   contains distro-appropriate OpenSSL, libc/libstdc++ and GUI dependencies.
   Install/upgrade/remove via apt **inside each target distro** before release.
   Verify every installed `/usr` directory has mode `0755` (not `0775` or
   setgid), independent of the build runner's umask; the M4 package audit
   enforces this before creating its SPDX and dependency sidecars.
3. **Windows:** Windows MSVC x64 builds two executables with pinned vcpkg
   static OpenSSL and GLFW. Run all CLI regression tests and dependency import
   audit. A Win10 and Win11 **physical/independent VM** install-free GUI launch
   and CLI/secure-file roundtrip is mandatory. Hosted Windows runner success
   alone is NOT this evidence.
4. **Supply chain:** preserve pinned source revisions, OpenSSL attribution,
   SPDX 2.3 installed-file inventories and exact binary dependency import
   reports. Verify each candidate SHA-256 and the Sigstore bundle identity,
   issuer and transparency evidence. Ensure candidate metadata matches the
   pushed Git commit and package contents. Compare repeated builds only when
   toolchain/source/runtime inputs are identical; do not assert universal
   binary reproducibility.
5. **Documentation and UX:** installation/CLI/GUI instructions, `man xorcist`,
   screenshots, keyboard navigation, DPI scaling, font legibility, error-message
   review, accessibility limitations, and no-overwrite behavior reviewed.
6. **Secure-file tests:** verify valid/wrong passphrase, ciphertext tamper and
   legacy `.dat` migration. Do not publish private passphrases or plaintext
   test evidence. Keep negative tests deterministic and local-only.
7. **Release gate:** owner manually reviews all artifacts and acceptance records,
   signs off release checklist, THEN separately creates tagged GitHub release.
   Workflow `m4-candidates.yml` never publishes a GitHub Release itself.

## Local candidate build on Ubuntu 26.04

```bash
sudo apt install build-essential cmake ninja-build git python3 \
  libssl-dev libglfw3-dev libgl1-mesa-dev dpkg-dev binutils xvfb xauth
cmake -S . -B build-m4 -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DXORCIST_BUILD_CLI=ON -DXORCIST_BUILD_GUI=ON \
  -DXORCIST_BUILD_TESTS=ON -DXORCIST_PACKAGE_DEB=ON \
  -DXORCIST_INSTALL_DEV_FILES=OFF -DXORCIST_FETCH_GLFW=OFF
cmake --build build-m4 --parallel
xvfb-run -a ctest --test-dir build-m4 --output-on-failure
(cd build-m4 && cpack -G DEB)
mkdir -p dist
python3 scripts/m4_audit_deb.py --deb build-m4/xorcist_2.0.0-1_amd64.deb \
  --platform ubuntu2604-amd64 --outdir dist --require-gui
cmake --install build-m4 --prefix stage-m4
python3 scripts/package_candidate.py --stage stage-m4 --output-dir dist \
  --platform ubuntu2604-amd64 --git-sha "$(git rev-parse HEAD)" --format tar.gz
python3 scripts/check_candidate.py dist/*.tar.gz
```

Run `dpkg-deb -f build-m4/*.deb` and inspect the `Depends:` line. When
manually installing the candidate, use `sudo apt install ./build-m4/*.deb`,
run `xorcist --help`, `man xorcist`, open `xorcist-gui` from desktop and test,
then `sudo apt remove xorcist`. Perform these steps in a disposable host/VM
if the package is not yet approved.

## GitHub candidate matrix

Actions > `M4 platform packages and signed candidates` > Run workflow from
`main`. It builds DEBs for 4 distros, a Windows MSVC ZIP, and (on `main`)
keylessly signs candidate artifacts through Sigstore. Verify that all 3 jobs
pass before treating candidate provenance as established. A successful run is
**not** final release approval.

See `docs/M4_HARDWARE_CHECKLIST.md` for real-machine requirements and
`docs/M4_RELEASE_GUIDE.md` for artifact verification and manual promotion.
