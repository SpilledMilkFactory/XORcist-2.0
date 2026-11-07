# Security policy and threat model

## Scope of this baseline

XORcist 2.0 is a **network-address planning** tool and a **binary XOR demonstration**.
The XOR functionality is not a confidential or integrity-protecting file encryption solution.
It is inappropriate for credentials, production secrets, backups, or sensitive data.

* Repeating-key XOR leaks structure and enables plaintext recovery if an attacker knows or guesses data; it is not authenticated.
* Keys passed via `--key-hex` can appear in shell history, process arguments and logs. GUI key fields are also not secret-management tools.
* The program never generates or claims to generate strong random encryption keys.
* The only data files read without an explicit output path are the legacy Java files, which are treated as untrusted input and size-limited to 16 MiB.
* XOR file outputs are exclusively created (never overwritten), opened mode 0600 on POSIX; incomplete outputs are deleted on detected read/write errors. The operating system still controls directory permissions and backups.
* The CLI escapes control bytes when printing recovered legacy plaintext, to reduce terminal escape/injection risk.
* Inputs are parsed with bounded CIDR prefixes and IPv4 octets. Network list files have a 1 MiB limit; GUI text buffers have explicit limits.

## Not in scope yet

No secure encryption mode, file authentication, key custody, IPv6, network discovery, packet capture, privilege elevation, or active traffic interrogation is included in this baseline.
Before shipping a secure encryption feature, use a reviewed AEAD library such as OpenSSL EVP, libsodium, or platform cryptography; define key derivation, salt/nonce construction, metadata authentication, versioned file formats, error behavior, memory handling, and independent test vectors.

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
