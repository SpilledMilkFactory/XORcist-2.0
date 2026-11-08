# Third-party components and redistribution notices

XORcist's original source is MIT-licensed. Its external dependencies retain their own licenses; see the full texts in [`docs/licenses/`](docs/licenses/). The licensed dependencies are included in the installed documentation and relevant release archives.

| Component | Role | Source and version policy | License |
| --- | --- | --- | --- |
| **Dear ImGui** | Desktop widgets | Pinned v1.91.9b source revision in `cmake/dependencies.lock.cmake` | MIT |
| **GLFW** | Windowing and input | Pinned 3.4 source revision for CI/release; optionally system-provided for local builds | zlib/libpng |
| **OpenGL** | GPU rendering backend | Platform/graphics-driver implementation | Platform-provided terms |
| **OpenSSL 3.x (`libcrypto`)** | AES-256-GCM, scrypt, random bytes | Minimum API version 3.0; exact linked binary depends on target distribution/package | Apache-2.0 |

## Platform-specific redistribution

**Linux:** Debian-family packages are built on their respective target distributions. Runtime dependencies (including the applicable OpenSSL runtime and GLFW/OpenGL library versions) are determined from the actual ELF binaries through `dpkg-shlibdeps`. The installed package includes third-party license notices in `/usr/share/doc/xorcist/third-party-licenses/`.

**Windows x64:** The MSVC portable build uses a pinned vcpkg registry, the `x64-windows-static` triplet, statically linked OpenSSL and GLFW, and a static MSVC runtime. Its workflow audits DLL imports and rejects unreviewed dependencies. The ZIP includes the relevant OpenSSL copyright text, `WINDOWS_IMPORTS.json`, a vcpkg installed-package inventory, the source dependency lock, and an SPDX inventory. Windows system DLLs and OpenGL drivers remain platform-provided.

The exact version and license inventory for any distributed artifact must be checked against that **artifact's** contents; source locks do not cover system-provided shared libraries or every transitive dependency. Static linking also means that OpenSSL security fixes require rebuilding the Windows distribution.

## Provenance and compliance boundary

Release workflows emit SHA-256 digests, SPDX 2.3 file inventories, and Sigstore bundles for candidate artifacts. These help establish software provenance and file integrity but do **not** certify absence of vulnerabilities, prove complete transitive dependency coverage, or replace an independent security review.

OpenSSL's Apache-2.0 license and additional upstream notices are reproduced alongside the relevant distribution as required; the full Apache License Version 2.0 text is tracked in `docs/licenses/OPENSSL_APACHE-2.0.txt`. The MIT `LICENSE` in the repository applies only to original XORcist source, not to these third-party components.
