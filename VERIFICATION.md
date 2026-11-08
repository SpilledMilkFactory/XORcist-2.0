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

## M2 proposed implementation verification — November 7, 2026

M1 was reported passing on Ubuntu 26.04 GCC 15.2.0: CLI 4/4 CTest, GUI 5/5 CTest,
and the hidden-window GUI smoke test. This closes **M1 local development scope** only.

The following M2 evidence comes from the assistant's Linux execution environment and is
not a substitute for the user's Ubuntu GUI and end-to-end tests:

| Check | Result | Context |
|---|---|---|
| Core + M2 CLI compilation | PASS | GCC C++20, Ninja, Debug |
| M0/M1/M2 CTest suites | PASS | 6/6 (existing tests retained) |
| Mask/wildcard round-trip and invalid inputs | PASS | 33 prefix values + negative tests |
| Host validation, loopback TCP probe limits | PASS | No external network target required |
| Local OS interface/route inventory | PASS | Linux `/proc` and socket APIs |
| Clang ASan/UBSan | PASS | Instrumented 6/6 CTest suites |
| Dear ImGui GUI translation-unit syntax | PASS (limited) | Pinned ImGui headers + GLFW declaration stub; not full link |
| Full GUI build, CTest smoke, manual diagnostics tabs | PENDING | User Ubuntu 26.04 test needed |
| Windows API build and native behavior | NOT VERIFIED | Deferred release gate |
| Debian 12/13 and other Linux distributions | NOT VERIFIED | Deferred release gate |

Run the commands in [`docs/M2_ACCEPTANCE.md`](docs/M2_ACCEPTANCE.md) to qualify M2 locally.
No claim of full public release qualification is made here.


## M3 development patch evidence — November 7, 2026

Owner-side acceptance pending. This source adds OpenSSL 3.x libcrypto as a
**new third-party runtime dependency**, and M3 development acceptance is
separate from deferred M0/M4 cross-platform release qualification.

M3 includes a versioned AES-256-GCM/scrypt file container, strict Base64,
hexadecimal transforms, byte masks, binary/ASCII inspection and streamed
file comparison. New tests cover RFC 4648 vectors, randomized round trips,
wrong passwords, ciphertext/header/tag mutation, truncation, and absence of
recovered output on failed authentication. It preserves M0–M2 tests and
adds separate Base64/hex and envelope-layout libFuzzer harnesses.

Assistant-side GCC 14.2.0 Debug CTest: **8/8 PASS**.
Clang 17 ASan/UBSan Debug CTest: **8/8 PASS**.
Bounded M3 data libFuzzer exercise: **300 runs, no findings**.
GUI translation unit syntax with pinned ImGui headers and GLFW declaration stub:
**PASS**; **full GUI link, launch and manual operations NOT tested here**.
The M3 C++ regression suite includes a published AES-256-GCM NIST known-answer
vector and scrypt-backed file round trips with tag/header/payload tampering.

Local verification details and owner acceptance commands are described in
`docs/M3_ACCEPTANCE.md`; do not mark the GUI or user Ubuntu environment as
verified from assistant-side builds alone.


## M4 distribution infrastructure (local preparation)

M3 accepted by owner on Ubuntu 26.04: 8/8 CLI, 9/9 GUI tests;
AES-256-GCM/scrypt encrypt/decrypt byte-for-byte match and wrong-password
rejection. The subsequent M4 Linux CLI-only Release build on Debian 13 with
GCC completed, 8/8 pre-M4 CTests passed, and CPack emitted a `xorcist_2.0.0-1_amd64.deb`.
`dpkg-deb --field` reported version 2.0.0-1, architecture amd64, and runtime
`Depends: libc6, libgcc-s1, libssl3t64, libstdc++6` with version constraints.
The package payload and executable imports passed the new local auditing
script. This **does not** establish M4 release qualification: Debian 12,
Ubuntu 24.04/26.04, full GUI/DEB matrix, Windows MSVC build, actual Windows
10/11 launch, Cosign transparency verification, and third-party audit remain
pending GitHub Actions and hardware verification.
The M4 DEB audit additionally enforces the target GLIBC symbol-version ceilings
(2.36 / 2.41 / 2.39 / 2.43 for Debian 12 / Debian 13 / Ubuntu 24.04 /
Ubuntu 26.04, respectively) when given the matching target identifier.
