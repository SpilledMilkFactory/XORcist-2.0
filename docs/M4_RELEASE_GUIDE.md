# M4 — Candidate Signing and Promotion Guide

**Candidate artifacts are not a public release.** There is no automated GitHub
release publishing in this workflow.

## Produced artifacts

- Four `xorcist_2.0.0-1_amd64.deb` files, each in a **separate named CI artifact**
  for Debian 12, Debian 13, Ubuntu 24.04, Ubuntu 26.04. Do not exchange them.
- One MSVC x64 `.zip` candidate with CLI, GUI, bundled third-party notices,
  `WINDOWS_IMPORTS.json`, vcpkg revision and installed-package inventory, and SPDX manifest.
- SHA-256 checksums and SPDX file-inventory sidecars for native `.deb` files.
- Extracted-tree `tar.gz` candidates with embedded SPDX and lock manifests.
- Keyless Sigstore `.sigstore.json` bundles for signed candidate files.

## Verify bundles independently

For each file and its matching bundle, verify with a current `cosign`:

```bash
cosign verify-blob xorcist_2.0.0-1_amd64.deb \
  --bundle xorcist_2.0.0-1_amd64.deb.sigstore.json \
  --certificate-identity \
  'https://github.com/SpilledMilkFactory/XORcist-2.0/.github/workflows/m4-candidates.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

The identity must match the *actual* workflow and branch; a valid signature
from a different identity is insufficient. The transparency bundle records a
signature event, not a claim of safe or reproducible software. Verify SBOM
and archive SHA-256 checks against the actual payloads as well.

## Promotion gate

1. Confirm zero failures across the Linux and Windows GitHub candidate matrix.
2. Confirm real Windows 10 AND Windows 11 test evidence (hardware checklist).
3. Confirm install/upgrade/remove on each Linux target, signed candidate bundles,
   linked runtime inventories and third-party notice review.
4. Record GUI screenshots and usability review as specified in `M4_UI_REVIEW.md`.
5. Freeze the commit, repeat deterministic tests on the frozen source, and
   obtain explicit owner approval.
6. Create the annotated version tag and GitHub Release manually. Check that
   every asset matches the approved, signed candidate SHA-256. If an asset
   changes, requalify and re-sign. Never sign an unchecked arbitrary artifact.
