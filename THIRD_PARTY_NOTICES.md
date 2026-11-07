# Third-Party Notices — XORcist 2.0

The core library and CLI have **no third-party runtime library dependencies** beyond the C++ runtime and operating system.
The optional GUI uses:

| Library | Pinned baseline | Role | License |
|---|---|---|---|
| Dear ImGui | v1.91.9b | UI rendering and widget behavior | MIT |
| GLFW | 3.4 when fetched, or an OS-provided GLFW3 | Window / input / OpenGL context | zlib/libpng |
| OpenGL | Platform implementation | GPU rendering | OS / driver supplied |

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
