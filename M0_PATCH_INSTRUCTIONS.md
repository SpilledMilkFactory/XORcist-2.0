# XORcist 2.0 — M0 quality-gates patch

Apply to the repository baseline supplied as `XORcist02.0-M0.zip`. This is a **changed-files-only** patch; do not delete files not included here. The patch does not include compiled binaries, downloaded GUI dependencies, or `.git` metadata.

1. Ensure `git status --short` is clean, then create a separate branch: `git switch -c m0-quality-gates`.
2. Extract this archive **into your repository root**, preserving relative directory paths and permitting overwrite of the listed files.
3. Review changes with `git diff --check` and `git diff` / `git status --short`.
4. Run the CLI and sanitizer test instructions in `docs/M0_ACCEPTANCE.md`.
5. On Ubuntu 26.04, build GUI, run `ctest` and manually verify each tab.
6. **Hold the commit** and send the local build/test logs and GUI results back for review; the commit title/description comes after this review, per the established RationalStudio cadence.
7. Once approved, commit/push a branch, review Linux+Windows Actions logs, and carry out Windows 10 and 11 real-hardware tests per `docs/M0_ACCEPTANCE.md`. Only dispatch the signed-candidate workflow after normal CI passes. Do not merge or mark M0 complete while gates remain outstanding.

The GitHub Actions workflow creates candidate ZIP/TAR.GZ archives with embedded SPDX and checksum files. Manual signing is **not a GitHub Release**; final promotion requires subsequent approval.

### Fast local Ubuntu verification
```bash
cmake -S . -B build-m0-cli -G Ninja -DCMAKE_BUILD_TYPE=Debug -DXORCIST_BUILD_GUI=OFF -DXORCIST_BUILD_TESTS=ON
cmake --build build-m0-cli --parallel
ctest --test-dir build-m0-cli --output-on-failure
./build-m0-cli/xorcist net summarize 192.168.1.1/24 192.168.2.1/24
cmake -S . -B build-m0-gui -G Ninja -DCMAKE_BUILD_TYPE=Release -DXORCIST_BUILD_GUI=ON -DXORCIST_BUILD_TESTS=ON -DXORCIST_FETCH_GLFW=OFF
cmake --build build-m0-gui --parallel
ctest --test-dir build-m0-gui --output-on-failure
./build-m0-gui/xorcist-gui
```

Run `docs/M0_ACCEPTANCE.md` for full sanitizer/fuzz, packaging and real-Windows gates. Report local CMake/CTest and GUI launch results **before committing**; provide the CI run link after the reviewed commit has been pushed.
