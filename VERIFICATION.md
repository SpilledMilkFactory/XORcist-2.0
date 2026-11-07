# XORcist verification — M0 qualification patch (development evidence)

**M0 local development scope: ACCEPTED (November 7, 2026).**
Cross-platform and signed release gates: **DEFERRED; NOT CERTIFIED**.

## Owner-side Ubuntu 26.04 local verification (GCC 15.2.0)

| Check | Owner's reported outcome |
|---|---|
| CLI Debug configure/build | PASS |
| Core + property CTest | 2/2 PASS |
| GUI Release configure/build | PASS (19/19) |
| GUI smoke + core + properties CTest | 3/3 PASS |
| GUI hidden 2-frame smoke | PASS; printed expected success message |
| Interactive GUI | Launched; full widget-by-widget inspection not recorded |
| Local sanitizer/fuzzer/candidate tooling | Owner reports checks passed; raw logs not supplied |
| Debian 12/13, Ubuntu 24.04, Windows 10/11, signing | Deferred to release qualification |

This scope decision is documented in `docs/M0_ACCEPTANCE.md`.


## Verified in the assistant's execution environment (not your local machine)

| Check | Result | Context |
|---|---|---|
| C++ core + CLI + unit tests | PASS | Debian 13, GCC 14.2.0, CMake 3.31.6, Ninja |
| Deterministic CIDR property test | PASS | 6,000 seeded cases, 256-address independent oracle per case |
| Core regression CTest | PASS | Existing compatibility and XOR suite |
| AddressSanitizer + UndefinedBehaviorSanitizer | PASS | Clang 17.0.0 instrumented core/tests |
| Source-instrumented libFuzzer | PASS | 3,000 corpus-seeded runs of CIDR parser/aggregation |
| Candidate archive + SPDX verifier | PASS | Debian 13 CLI staged install; all listed file hashes matched |
| Identical-stage packaging determinism | PASS | Two `.tar.gz` files had identical SHA-256 |
| Dear ImGui GUI compile / hidden frame smoke | NOT RUN | GLFW/OpenGL development dependencies unavailable in this sandbox |
| Debian 12, Debian 13, Ubuntu 26.04 GitHub Actions | PENDING | Source workflows added; must run on user's repository |
| Windows MSVC GUI build and candidate ZIP | PENDING | GitHub Actions run required |
| Windows 10 AND 11 real hardware verification | PENDING | Manual evidence required |
| Signed candidate archives | PENDING | Explicit manual `workflow_dispatch` on main required |
| Final release signing and promotion | BLOCKED | Must pass M0 acceptance gates first |

### Core test evidence

`ctest --test-dir ... --output-on-failure` (GCC 14.2): 2/2 passed.
`ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 ctest ...` (Clang 17): 2/2 passed.
Fuzz harness: 3,000 seeded iterations; no sanitizer findings in this bounded exercise.

### Candidate evidence

An unchanged staged CLI install was packaged twice with the same environment and
`SOURCE_DATE_EPOCH` default of `0`; archives produced identical SHA-256 digests.
`check_candidate.py` validated SHA-256 digests, both JSON structures, and 12 staged file hashes.

These tests cannot substitute for user-side clean checkout, CI platform matrix, actual GUI
interaction or real Windows 10/11 hardware testing. Follow `docs/M0_ACCEPTANCE.md`.
