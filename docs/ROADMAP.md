# Suggested post-baseline roadmap

The point of XORcist is utility, not replacing Wireshark. Avoid packet capture and invasive scanning as a core focus.

## M0 — Baseline completion and quality gates

**Development status: COMPLETE (Ubuntu 26.04 local baseline, November 7, 2026).**
The multi-platform and signed-release gates below are **deferred to release qualification**;
see [`M0_ACCEPTANCE.md`](M0_ACCEPTANCE.md). Do not mark these gates as verified.


- Rebuild current CLI and GUI from a fresh checkout on Debian 12, Debian 13, and Ubuntu 26.04.
- Add Windows 10/11 package and GUI launch verification on real hardware.
- Add sanitizer, fuzz, and property-based tests for CIDR parser and aggregation.
- Generate SBOMs, reproducible dependency locks, third-party notices and signed release artifacts.
- Address remaining baseline limitations in `SECURITY.md` and README before promoting a release candidate.

## M1 — IP planning

**Development status: COMPLETE for Ubuntu 26.04 local verification (November 7, 2026).** Retain M0 quality gates,
with full cross-platform verification deferred to release qualification.
See [`M1_ACCEPTANCE.md`](M1_ACCEPTANCE.md).


- IPv6 CIDR and range handling; fully distinguish IPv4 and IPv6.
- CIDR overlap and intersection, address containment, and route covering checks.
- Address-range -> minimum exact CIDR blocks; import/export CSV and newline formats.
- IPv4 subnet splitting, VLSM planning and allocation, overlap warnings.

## M2 — Passive diagnostics / administration

**Development status: COMPLETE for Ubuntu 26.04 local verification (owner-reported, November 7, 2026); release-platform checks deferred.**
See [`M2_ACCEPTANCE.md`](M2_ACCEPTANCE.md). System inventory is read-only; bounded TCP probes are opt-in.


- DNS lookup / reverse lookup using system resolvers, timestamped result inspection.
- Local interface, addresses, routes, MTU and gateway inventory using OS APIs.
- Network mask/wildcard mask conversions and ACL expression helpers.
- Safe reachability probes on user-specified hosts with explicit rate and duration limits.

## M3 — Robust data tools

**Development status: COMPLETE for Ubuntu 26.04 local verification (owner-reported, November 7, 2026).**
See [`M3_ACCEPTANCE.md`](M3_ACCEPTANCE.md).


- Dedicated Base64, hex, bit-mask, binary/ASCII comparison and file diff tools.
- Authenticated encryption **only** via a mature, independently reviewed crypto library.
- Versioned file containers and authentication, controlled key handling, and fuzz tests.

## M4 — Distribution

**Implementation status: Candidate packaging and audit infrastructure prepared;**
**release qualification NOT complete**. CI, Windows hardware, signed-candidate
verification and UI evidence must be supplied before the public release.
See [`M4_ACCEPTANCE.md`](M4_ACCEPTANCE.md).


- Debian release matrix with older glibc/runtime gates; dependency inventory per target.
- Windows portable x64 release, DLL inventory, license notices and provenance.
- User documentation, screenshot evidence, CLI manpage, accessibility and UX review.

## Design constraints

- Domain logic must not depend on CLI or GUI libraries.
- No OS networking changes without explicit user intent and a dry-run preview.
- No packet capture or privileged actions as a default operating mode.
- Prefer offline, non-privileged utilities with deterministic output and stable CLI contracts.
