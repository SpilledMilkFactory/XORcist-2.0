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

## M1 engineering verification — November 7, 2026

The results below pertain to the **proposed M1 patch**, not to an accepted release. Keep the prior historical baseline section above for provenance.

| Evidence | Observed result | Qualification |
|---|---|---|
| GCC 14.2.0, Debian 13 C++20 CLI and core | PASS | Build from patched source with Ninja |
| Original `xorcist_core_tests` | PASS | Original suite retained |
| `xorcist_m1_tests` | PASS | Strict IPv4/IPv6 parsing, relationships, edge prefixes, range decomposition, split/VLSM, CSV import/export, invalid inputs |
| 6,000 deterministic range cases | PASS | Independent per-address mathematical coverage oracle on IPv4 `/24` and IPv6 `/120` domains |
| `xorcist_m1_cli_tests` | PASS | End-to-end subprocess commands, error exit codes, CSV output and overwrite refusal |
| CTest aggregate on rebased M0+M1 source | PASS | 4/4 suites on Debian 13 GCC 14.2.0; includes retained M0 property test |
| GUI source translation-unit syntax | PASS (limited) | Dear ImGui headers + GLFW declaration stubs, with retained M0 smoke option; not a full GUI build |
| Full GUI compile, link, launch and manual feature checks | NOT VERIFIED FOR M1 | Must be performed on user's Ubuntu 26.04 system |
| Windows 10/11, Debian 12, Debian 13, Ubuntu 26.04 CI matrix | NOT VERIFIED FOR M1 | CI output and physical hardware remain necessary |
| ASan/UBSan for merged M0+M1 | PASS | Clang 17 instrumented build; 4/4 CTest suites |
| Bounded fuzz of retained M0 network harness | PASS | 300 iterations; not exhaustive |
| M0 candidate packaging and verification after M1 | PASS | SHA-256 + 13 staged SPDX file hashes |
| M0 development quality gates | IMPLEMENTED; locally accepted | Release qualification remains deferred per `docs/M0_ACCEPTANCE.md` |

See [`docs/M1_ACCEPTANCE.md`](docs/M1_ACCEPTANCE.md) for precise manual checks and the M0/M1 separation.
