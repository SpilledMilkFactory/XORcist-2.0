# Security policy

XORcist is a network-planning and binary-data utility that includes both **educational repeating-key XOR** and a **separate authenticated file-encryption mode**. These have different security properties.

## Reporting vulnerabilities

Please avoid disclosing an exploitable issue in a public GitHub issue. Use the repository's **GitHub private vulnerability reporting** feature if it is enabled, or contact the maintainer privately through an established contact channel. Do not attach sensitive plaintext, passphrases, or private network inventories to public reports.

Provide the affected version/commit, platform, reproducible steps, expected/observed behavior, and a minimal non-sensitive reproducer. No response-time SLA or security certification is implied.

## Supported versions and scope

The latest publicly supported release is listed on [GitHub Releases](https://github.com/SpilledMilkFactory/XORcist-2.0/releases); the `main` branch may contain unreleased changes. Security fixes, if needed, will be evaluated for the current release and development branch. Older versions are not guaranteed ongoing backports. Check the release page for version and security announcements.

XORcist is **not independently security-audited**, penetration-tested to a certification standard, or a replacement for a dedicated secret-management system. Automated tests, SBOMs, and signed builds do not constitute such a review.

## Encryption versus XOR

**Repeating-key XOR is not secure encryption.** It has no authentication, leaks plaintext structure, and can expose content through key reuse or known plaintext. The `xor` commands are intended only for demonstrations and binary transformations. Keys supplied using `--key-hex` can be visible in shell history, process arguments, and logs.

For authenticated files, the separate `secure` commands use **OpenSSL 3.x AES-256-GCM** with a key derived by **scrypt**. Version 1 of `.xorc3` includes a 64-byte authenticated header, randomly generated 16-byte salt and 12-byte nonce, and a 16-byte authentication tag. The header records KDF settings (N=32768, r=8, p=1), and the current implementation limits plaintext size to 32 GiB per generated nonce. The format is specified in [docs/M3_FILE_FORMAT.md](docs/M3_FILE_FORMAT.md).

New encryption requires a passphrase of **12–4096 bytes**. Minimum length is **not** a guarantee of entropy; use an unpredictable passphrase. XORcist cannot recover lost passphrases. Interactive CLI entry hides terminal echo; `--password-stdin` is intended only for trusted automation. Do not place real passwords in command-line arguments, environment dumps, shell history, or shared scripts. GUI password entry is masked, but process-memory and OS-level exposure are not eliminated.

### Important file-handling limitations

- Authentication is checked before a successfully decrypted output is published. Wrong passwords and modified container contents are rejected; output paths are not silently overwritten.
- Decryption writes intermediate plaintext to a private temporary file in the destination directory. A process crash, forced termination, or power failure **may leave temporary plaintext**; encryption does not provide secure deletion of swap, backups, journals, or other plaintext copies. Use a trusted directory on an encrypted disk for sensitive work.
- The implementation is not designed to defend against hostile processes racing changes to directory entries or files in an adversarial directory.
- Container metadata can reveal length, algorithm, and KDF settings. Filenames, filesystem metadata, and surrounding operating-system records are not hidden by encryption.
- Files are not encrypted in place. Output creation is exclusive, and caught failures attempt cleanup. This is not a guarantee of crash-safe durability.

The educational Java `.dat` importer is **decode-only** and bounded to 16 MiB; it is not a secure-cryptography compatibility format.

## Networking and local data

- CIDR calculations, subnet splitting, VLSM, and network-list conversions operate on input data and **do not modify live network configuration**. IPv4/IPv6 parsing and output counts are bounded; unsupported IPv6 scope identifiers and noncanonical IPv4 forms are rejected.
- Local interface and route inventory is **read-only**, but its output may reveal private addresses, host interface names, gateways, and topology. Do not publish sensitive diagnostic output or unredacted screenshots.
- DNS/reverse DNS queries use the operating system resolver. Results may be cached, observed upstream, or altered and are **not independently authenticated** by XORcist. Resolver operations have no portable hard timeout; slow DNS can delay GUI task completion or shutdown.
- TCP reachability is **active** and opt-in: a single numeric endpoint and explicit port, 1–5 attempts, 100–2000 ms timeout, 200–2000 ms interval, and at most a 10-second configured budget. It is not ICMP ping or a general scanner. Only probe systems you are authorized to contact.
- ACL helpers emit address-match fragments, **not** complete validated firewall rules. Verify protocol, action, direction, address ordering, and device syntax before deployment.
- Text and binary conversions have bounded input/output limits. Base64/hex are **encodings**, not confidentiality measures.

## Dependency and release security

Linux builds dynamically link distribution-managed libraries, including OpenSSL. Windows x64 release candidates statically link OpenSSL and other selected dependencies; **security updates to a statically linked library require rebuilding and redistributing the Windows package**. The exact direct dependencies and notices are documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Release workflows generate package audits, SPDX inventories, SHA-256 checksums, and Sigstore provenance bundles. Verify downloaded assets against the matching release evidence using [docs/M4_RELEASE_GUIDE.md](docs/M4_RELEASE_GUIDE.md). These attest to artifact identity and integrity, not vulnerability freedom, runtime safety on every machine, or a formal cryptographic audit.
