# Third-Party Notices — XORcist 2.0

The M3 core and CLI now require **OpenSSL 3.x libcrypto**, linked via `OpenSSL::Crypto`. Earlier M0–M2 builds did not require this dependency. OpenSSL must be installed as a runtime package (or bundled for a later platform release).
The optional GUI uses:

| Library | Pinned baseline | Role | License |
|---|---|---|---|
| Dear ImGui | v1.91.9b | UI rendering and widget behavior | MIT |
| GLFW | 3.4 when fetched, or an OS-provided GLFW3 | Window / input / OpenGL context | zlib/libpng |
| OpenGL | Platform implementation | GPU rendering | OS / driver supplied |
| OpenSSL libcrypto | >= 3.0, system or package-manager provided | AES-256-GCM, scrypt, secure random bytes | Apache-2.0 |

The corresponding license text for Dear ImGui and GLFW is under `docs/licenses/`. When publishing a GUI installer/package, include these files or the equivalent notices from the **exact** bundled versions. If dynamically linking system GLFW, its distribution package may already provide the required notice; still retain credits in this project.

If GLFW is supplied by the OS, its version and transitive dependencies may differ from the fetched fallback. A release must review the final dependency inventory and any platform-specific redistribution requirements. This notice file does **not** certify the compliance of any future release artifact.

The MIT license in `LICENSE` applies to original XORcist 2.0 source code, not to third-party components.

## M0 source lock / shipped artifact inventory

The exact fetched source Git hashes are kept in `cmake/dependencies.lock.cmake`. CI enables
`XORCIST_USE_SYSTEM_GLFW=OFF` for GLFW source-build reproducibility and uses a pinned Dear ImGui
revision. A developer can opt into a distribution-provided GLFW by setting
`XORCIST_USE_SYSTEM_GLFW=ON`; that version is *not* the pinned upstream revision.

Each candidate archive embeds `share/doc/xorcist/DEPENDENCIES.lock.json` and
`share/doc/xorcist/SBOM.spdx.json`. The latter is an SPDX 2.3 installed-file inventory with
**declared direct components**, not a comprehensive transitive dependency analysis. Retain
these files and the license notices in redistributed archives. OpenGL/system platform licenses
and runtime DLL/ELF dependencies require separate release-time review.


## M3 OpenSSL notice

OpenSSL 3.x uses Apache License 2.0: https://openssl-library.org/source/license/
Development builds use the system OpenSSL 3 library (`libcrypto`); it is **not**
vendored or pinned by hash in this repository. The minimum API version is 3.0,
while the exact binary version must be recorded during M4 packaging. If a future
Windows portable ZIP bundles OpenSSL DLLs, include the matching upstream license,
provider modules when required, and an inventory of DLLs with versions and hashes.
The package-candidate SBOM declares OpenSSL as a direct system dependency, but is
not a guarantee of complete runtime closure or security certification.

## M4 package-specific notices

Linux `.deb` files are built **inside their target distribution**. CPack
`dpkg-shlibdeps` derives `Depends` from the linked ELF binaries (including the
correct distribution OpenSSL runtime package name); do not manually claim a
Debian 12 build will run on Ubuntu 26.04 or vice versa. The third-party
licenses are installed under `/usr/share/doc/xorcist/third-party-licenses/`.

The Windows x64 candidate uses MSVC `/MT` with pinned vcpkg registry tag
`2026.10.16`, static OpenSSL (`x64-windows-static`) and pinned Dear ImGui / GLFW
source. This is intended to avoid shipping third-party DLLs; the candidate
build **fails** if an imported DLL outside its reviewed Windows system
allowlist is found. The exact vcpkg OpenSSL copyright is copied into the
portable ZIP, alongside the Apache License 2.0 text. System DLLs and Windows
OpenGL remain OS-provided. License and binary inventories require fresh review
whenever dependencies change.

`docs/licenses/OPENSSL_APACHE-2.0.txt` is the complete Apache License Version
2.0 text; the OpenSSL source distribution and installed vcpkg port may also
contain specific attribution notices that are copied to the Windows package.
Sigstore bundles are *candidate provenance metadata*, not proof of product
security or a substitute for native Windows code signing / SmartScreen review.
