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
