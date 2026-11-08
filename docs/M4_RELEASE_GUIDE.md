# Release engineering guide

XORcist **v2.0.0 was published** using the M4 cross-platform candidate and signing pipeline. This guide describes the process for future patch releases, including v2.0.1. Candidate artifacts are **not** published automatically.

## Release sequence

1. Freeze the source changes and update project/package version identifiers. Do not reuse binaries or signatures from an older release.
2. Verify PR CI and local CTest/GUI checks; use [`V2_0_1_UI_ACCEPTANCE.md`](V2_0_1_UI_ACCEPTANCE.md) for the tile-navigation change.
3. On the exact chosen commit, manually dispatch `.github/workflows/m4-candidates.yml`. Confirm all four Linux native DEB jobs, Windows x64 portable ZIP, and signing verification pass.
4. Download the **signed aggregate artifact** and its matching hashes, SPDX files, runtime inventories and Sigstore bundles. The four distributions' internal `.deb` filenames may be identical; keep them separated by platform and rename only release asset filenames, not package contents.
5. Independently verify SHA-256 and signature bundles against the expected workflow identity and commit. Confirm file content, dependency notices, and release tag align with the signed candidates.
6. Perform installation, upgrade/removal and GUI checks on each supported distribution/Windows version. Keep redacted notes; see [`M4_HARDWARE_CHECKLIST.md`](M4_HARDWARE_CHECKLIST.md) and [`M4_UI_REVIEW.md`](M4_UI_REVIEW.md).
7. Create an annotated tag for the qualified commit and a **draft GitHub Release**; attach the verified platform-specific packages and verification evidence, then publish after explicit maintainer approval.

## Verify a Sigstore bundle

Install a current `cosign`, then substitute the **actual** artifact filename and bundle:

```bash
cosign verify-blob <artifact-file> \
  --bundle <artifact-file>.sigstore.json \
  --certificate-identity \
  'https://github.com/SpilledMilkFactory/XORcist-2.0/.github/workflows/m4-candidates.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Signatures demonstrate artifact byte integrity and workflow provenance, **not** that the software has had an independent security audit. Archive checks and signed artifacts are tied to the original file bytes; renaming alone does not change them. Do not sign or publish an altered artifact without requalification.

## Source and package hygiene

`cmake/` holds required dependency locks and DEB permission normalization; `packaging/linux/` holds the installed desktop launcher; `docs/licenses/` and `docs/man/` contain redistributable notices and CLI documentation. All are tracked release inputs. Local `build-*`, `dist/`, `_CPack_Packages/`, `XORcist-2.0-Release/`, `.deb`, and downloaded dependency trees are **not** source files and should remain untracked.
