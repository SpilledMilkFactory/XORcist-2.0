# Verification and release qualification

This document summarizes the **scope of completed verification** and its limitations. It is not a claim of independent security certification. Historical milestone acceptance checklists are recoverable in Git history; current release procedures remain in [`docs/M4_RELEASE_GUIDE.md`](docs/M4_RELEASE_GUIDE.md).

## Published v2.0.0 — qualification summary

The maintainer reports publication of **XORcist 2.0.0** after a successful signed-candidate workflow and functional testing on fresh virtual machines for all distribution targets.

| Target or gate | Evidence | Status |
| --- | --- | --- |
| Debian 12 AMD64 | Separate native DEB job, build, tests, dependency/GLIBC and payload audit | Passed in GitHub Actions |
| Debian 13 AMD64 | Separate native DEB job and package audits | Passed in GitHub Actions |
| Ubuntu 24.04 AMD64 | Separate native DEB job and package audits | Passed in GitHub Actions |
| Ubuntu 26.04 AMD64 | Separate native DEB job and package audits | Passed in GitHub Actions |
| Windows x64 | MSVC portable ZIP, core/CLI tests, imported-DLL/dependency audit | Passed in GitHub Actions |
| Provenance | SHA-256, SPDX inventories, signed candidate artifacts, Sigstore verification job | Passed in GitHub Actions |
| Manual acceptance | Maintainer reports successful installation and operation in fresh VMs for all target platforms | Maintainer-reported; individual VM logs not committed |
| Independent cryptographic security audit | Third-party assessment of application algorithms/integration | **Not performed** |

The successful workflow was **M4 platform packages and signed candidates #2**. The release was assembled from that workflow's signed artifacts. Release assets and verification bundles should be checked against their own signed hashes and the exact release commit. See the [published releases](https://github.com/SpilledMilkFactory/XORcist-2.0/releases).

### Local development verification

The maintainer reported Ubuntu 26.04 / GCC 15.2.0 builds with **10/10 CTest suites passing** for the M4 GUI-enabled configuration, including the two-frame hidden GUI smoke test. Automated tests cover core CIDR/IPv6 logic, deterministic network properties, M1/M2/M3 CLI integration, authenticated-file round trips, incorrect-password and tamper rejection, and M4 packaging metadata.

Clang AddressSanitizer/UndefinedBehaviorSanitizer and bounded libFuzzer runs were also included in the development workflow. Fuzzing remains bounded and cannot establish exhaustive absence of defects.

### Limitations of the evidence

- GitHub-hosted Windows test runners do not substitute for every physical graphics driver, DPI arrangement, or accessibility setting. The maintainer's VM testing is separate, and should be repeated for changed GUI releases.
- The hidden GUI smoke test only initializes/render frames; it does **not** click through every tool, exercise transition animations, or establish screen-reader accessibility.
- Artifacts built for distinct Linux distributions are **not interchangeable**, even though their package names share a version.
- Package signatures validate byte integrity and CI signing identity; they do **not** make the software independently audited or immune to future dependency vulnerabilities.

## Current main — tile dashboard planned for v2.0.1

The 12-tile Dear ImGui dashboard is a **post-v2.0.0 source change**. The maintainer has visually reviewed the dashboard and Binary Data Tools workspace and reported smooth operation. It does **not** change the core, CLI, or `.xorc3` format.

Before tagging v2.0.1, rerun a GUI-enabled CTest suite (expected **10/10** with Python 3), the GUI smoke test, targeted interactive checks from [`docs/V2_0_1_UI_ACCEPTANCE.md`](docs/V2_0_1_UI_ACCEPTANCE.md), and the full signed release-candidate workflow on the **exact v2.0.1 release commit**. Previous v2.0.0 binaries and signatures cannot be reused for a new version.

## Reproducing local checks

```bash
cmake -S . -B build-verify -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DXORCIST_BUILD_CLI=ON -DXORCIST_BUILD_GUI=ON \
  -DXORCIST_BUILD_TESTS=ON -DXORCIST_FETCH_GLFW=OFF
cmake --build build-verify --parallel
ctest --test-dir build-verify --output-on-failure
./build-verify/xorcist-gui --smoke-test
```

On a headless Linux CI worker, run the GUI smoke test through an available display server (for example `xvfb-run`). The live build and packaging commands are also documented in the [README](README.md) and [release guide](docs/M4_RELEASE_GUIDE.md).
