# XORcist — Development roadmap

XORcist's goal is a small, cross-platform toolbox for **network planning, bounded diagnostics, binary inspection, and file transformations**—not a Wireshark replacement or a broad network scanner.

## Shipped in v2.0.0

| Milestone | Delivered scope |
| --- | --- |
| **M0 — C++20 foundation** | Shared core, CLI and Dear ImGui frontends, CMake, property/regression tests, dependency locks, fuzzing/sanitizer infrastructure, candidate signing. |
| **M1 — IP planning** | IPv4/IPv6 CIDR and range operations, containment and overlap, exact aggregation, subnet splitting, VLSM, line/CSV conversion. |
| **M2 — Diagnostics** | System DNS and reverse DNS, read-only interfaces/routes, mask/wildcard/ACL helpers, bounded single-endpoint TCP probes. |
| **M3 — Data tools** | Binary comparison/inspection, Base64/hex, bit masks, AES-256-GCM authenticated-file format and scrypt passphrases. |
| **M4 — Distribution** | Debian 12/13 and Ubuntu 24.04/26.04 packages, Windows x64 ZIP, runtime audits, SPDX/checksums, Sigstore-signed candidates, CLI manpage, desktop launcher. |

The v2.0.0 packages were published after the maintainer's cross-platform VM validation. Test evidence and limitations are summarized in [`../VERIFICATION.md`](../VERIFICATION.md).

## v2.0.1 — GUI presentation (release qualification pending)

The v2.0.1 release-preparation source includes a **12-tile Dear ImGui dashboard** with animated workspaces, unclipped labels, responsive tile columns, and expandable result areas. This update is intentionally limited to the presentation layer. The project/package version is set to **2.0.1**; complete UI acceptance, rerun the platform matrix and signing on the exact release commit, and publish only newly qualified artifacts.

Checklist: [`V2_0_1_UI_ACCEPTANCE.md`](V2_0_1_UI_ACCEPTANCE.md).

## Future maintenance and enhancements

Potential work after v2.0.1 includes accessibility and keyboard-navigation review, targeted platform regression coverage, better diagnostic portability, performance baselines, tighter handling of interrupted encrypted-file operations, and automated dependency/security maintenance. These are **ideas, not promises or completed features**.

## Engineering constraints

- Keep domain logic in the shared C++ core; CLI/GUI must reuse it.
- Preserve existing CLI contracts and encrypted-container compatibility unless a versioned migration is explicitly designed.
- Prefer offline, non-privileged tools with deterministic outputs; network probes require explicit user intent.
- Maintain cross-platform builds, regression tests, security documentation, dependency notices, package auditing, and release provenance.
