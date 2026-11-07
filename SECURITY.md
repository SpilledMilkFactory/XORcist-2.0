# Security policy and threat model

## Scope of this baseline

XORcist 2.0 includes network planning, a binary XOR demonstration, and M3 authenticated-file encryption.
The XOR functionality is not a confidential or integrity-protecting file encryption solution.
Repeating-key XOR is inappropriate for credentials, production secrets, backups, or sensitive data; use M3 authenticated mode rather than XOR for confidential files.

* Repeating-key XOR leaks structure and enables plaintext recovery if an attacker knows or guesses data; it is not authenticated.
* Keys passed via `--key-hex` can appear in shell history, process arguments and logs. GUI key fields are also not secret-management tools.
* The program never generates or claims to generate strong random encryption keys.
* Legacy Java files are treated as untrusted input and size-limited to 16 MiB. The new network-list import reads only explicitly selected paths and limits inputs to 1 MiB. File conversion exclusively creates a new output and refuses overwrite.
* XOR file outputs are exclusively created (never overwritten), opened mode 0600 on POSIX; incomplete outputs are deleted on detected read/write errors. The operating system still controls directory permissions and backups.
* The CLI escapes control bytes when printing recovered legacy plaintext, to reduce terminal escape/injection risk.
* IPv4 octets, IPv6 hextets/compression and prefix lengths (/0..32 and /0..128) are validated. IPv6 scope/zone identifiers, noncanonical IPv4 leading-zero octets and multi-column/quoted CSV are rejected.
* Network lists are limited to 1 MiB and 50,000 entries; GUI text buffers have explicit limits. `net split` limits output to 65,536 networks (GUI 1,024), VLSM accepts at most 4,096 named host requirements, and pairwise overlap reporting accepts at most 1,024 networks and 100,000 conflict pairs.
* VLSM allocations are local calculations only. They do not create routes or manipulate network interfaces. Traditional usable-host counts reserve network and broadcast addresses, even for host counts that might otherwise be served by explicit /31 point-to-point links.

## Not in scope yet

No OS-managed secret vault, hardware-backed key custody, IPv6 zone-aware interface routing, packet capture, privilege elevation, broad network discovery or scanning is included. M2 introduces opt-in single-endpoint TCP connection checks, which are active traffic but are not ICMP ping or a scan engine.
M3 implements a versioned AEAD container through OpenSSL 3 EVP and scrypt. This has not undergone independent security review; do not characterize it as formally audited or certified.

## Reporting vulnerabilities

Please report issues privately to the repository owner using GitHub's private vulnerability reporting feature (if enabled). Avoid posting secret-bearing files in public issues.

## M0 qualification and supply-chain boundaries

The M0 candidate packaging process provides a SHA-256-verified artifact inventory and optional
Sigstore keyless signatures for archives produced by GitHub Actions. A signed archive proves
integrity and a verified CI identity, **not** that the code is secure or independently reviewed.

The packaged SPDX 2.3 manifest lists staged files and declared direct dependencies; it does
not resolve every distro-supplied system library, transitive dependency, OpenGL implementation,
or GPU driver. The CMake lock pins fetched Dear ImGui/GLFW Git commits, not distro versions,
compiler packages or operating-system images.

Output files are created exclusively and ordinary write failures are cleaned up, but these
operations are not transactional or durable against abrupt process termination or power loss.
The tool does not defend against hostile processes changing directory entries concurrently;
use a trusted working directory. It has not received a third-party security audit.

GUI smoke tests create a hidden OpenGL context and render two frames. They do not test a
human-usable display or every GPU implementation. Windows runtimes, driver compatibility and
portable packaging require separate evidence under `docs/M0_ACCEPTANCE.md`.

## M2 DNS / inventory / TCP probe security boundaries

* DNS A/AAAA lookups use the operating system resolver (`getaddrinfo`), and PTR uses
  `getnameinfo`. Requests require explicit user action. DNS queries may be observable by
  configured resolvers and upstream providers, subject to OS privacy policies. Results are
  timestamped, not authenticated, and may be cached or changed; DNSSEC is not verified here.
* System DNS APIs do **not** expose a portable deadline. OS resolver stalls may exceed
  requested UI interaction times. The GUI dispatches queries off the rendering thread,
  but shutdown while an async resolver is still running can wait for that operation.
* Read-only local interfaces/routes can reveal private IP addresses, interface names,
  default gateways, and routing configuration. Copying/saving or sharing CLI output may
  expose sensitive network topology. Interface enumeration is not an authenticated
  inventory and routing snapshots can omit policy rules and non-main tables.
* TCP reachability requires a single **numeric** address and explicit destination port.
  It cannot take hostname lists, CIDRs or broad ranges. Count 1..5, timeout 100..2000 ms,
  interval 200..2000 ms, and a maximum configured budget of 10 seconds are validated.
  Probe attempts make ordinary outbound TCP connections, which may be logged or trigger
  monitoring on the selected host; only test hosts/ports you are authorized to access.
  A `refused` connection indicates a refusal, not a successful application-level probe;
  firewalls or OS/network behavior can make all outcomes ambiguous.
* ACL output is a **Cisco-like address-match fragment only**, not a deployable firewall
  command, a vetted device-specific ACL, or a policy correctness guarantee. Confirm
  address order, protocol, action, direction, and target platform syntax independently.
* Linux route inventory reads `/proc/net/route` and `/proc/net/ipv6_route`; systems without
  these interfaces or with restricted visibility may report errors. Windows adapters/routes
  use native OS APIs, but must be compiled and checked during deferred release qualification.


## M3 authenticated-file encryption threat model

* The `secure` command uses OpenSSL 3.x `EVP_aes_256_gcm` authenticated encryption,
  random 16-byte scrypt salt, random 12-byte GCM nonce and 16-byte tag.
  Format version 1 has an exactly 64-byte authenticated header (`XORC3AE1`,
  version/algorithm/KDF IDs, scrypt N=32768/r=8/p=1, salt, nonce, plaintext
  length, reserved zeros), followed by ciphertext and tag. Header bytes are
  AEAD associated data. Unknown versions, unsupported KDF values, excessive
  sizes and unexpected lengths are rejected before costly derivation.
* New encryptions require a passphrase of 12..4096 bytes. Length alone does not
  guarantee sufficient entropy: choose a genuinely unpredictable passphrase.
  The passphrase is **not** recoverable; a lost passphrase means lost plaintext.
  scrypt slows offline guessing but cannot compensate for weak choices.
* The interactive CLI disables terminal echo and does not accept passwords in
  argv. `--password-stdin` is intended for controlled scripts; supplying
  secrets from shell literals, environment variables, logs or world-readable
  files can leak passwords. The GUI has a masked passphrase field, cleared on
  submission. Copies may remain in OS process memory; no memory-lock guarantee.
* The CLI and GUI never publish a decrypted output until the OpenSSL GCM
  authentication final check succeeds. Intermediate plaintext is written into
  an exclusive temporary file with POSIX mode 0600 in the destination directory
  and removed on caught errors. POSIX publication uses `link()` so it cannot
  overwrite an existing path; Windows uses a move without replace. The
  destination is never overwritten. Do not operate in adversarial directories:
  file permissions and concurrent filesystem interference are OS-dependent.
* Crash, SIGKILL, power failure or malware can leave a **temporary plaintext
  file** in the chosen directory. Encryption does not provide secure deletion
  of plaintext, swap, crash dumps, backups, or filesystem journals. Prefer
  encrypted disks for sensitive working directories. File metadata, filename,
  plaintext length (and KDF parameters) are **not hidden** by the container.
* GCM version 1 deliberately limits plaintext to 32 GiB per independently
  generated nonce. The code does not support append, resume, partial decryption,
  external associated data, recipient public keys, or a password recovery agent.
  A filename extension does not imply trusted format.
* Data Base64/hex tools are reversible **encodings**, not cryptography; the
  in-memory file conversions are limited to 16 MiB. `data diff` streams 64 KiB
  blocks and prints bounded offsets but counts all differing byte positions.
* OpenSSL is a runtime security dependency; track security advisories, versions
  and provider availability before M4 release qualification. No third-party
  security assessment or independent formal verification is claimed.
