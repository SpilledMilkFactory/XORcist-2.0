# Release engineering guide

XORcist **v2.0.0 was published** using the M4 cross-platform candidate and signing pipeline. This guide describes the process for future patch releases, including v2.0.1. Candidate artifacts are **not** published automatically.

## Release sequence

1. Freeze the source changes and update project/package version identifiers. Do not reuse binaries or signatures from an older release.
2. Verify PR CI and local CTest/GUI checks; use [`V2_0_1_UI_ACCEPTANCE.md`](V2_0_1_UI_ACCEPTANCE.md) for the tile-navigation change.
3. On the exact chosen commit, manually dispatch `.github/workflows/m4-candidates.yml`. Confirm all four Linux native DEB jobs, Windows x64 portable ZIP, and signing verification pass.
4. Download the **`xorcist-release-ready`** workflow artifact. It contains exactly five platform archives and `SHA256SUMS`. The Linux tarballs contain their distribution-specific `.deb`, SPDX and runtime JSON, original signed-component bundles, and an additional signed release manifest. The Windows ZIP directly contains the executables and documentation—no nested ZIP.
5. Independently verify `SHA256SUMS` and the **embedded** `RELEASE_MANIFEST.json` and `RELEASE_MANIFEST.json.sigstore.json` for each archive against the expected workflow identity and source commit. The signed manifest covers every included payload file; `SHA256SUMS` covers the compressed archives.
6. Perform installation, upgrade/removal and GUI checks on each supported distribution/Windows version. Keep redacted notes; see [`M4_HARDWARE_CHECKLIST.md`](M4_HARDWARE_CHECKLIST.md) and [`M4_UI_REVIEW.md`](M4_UI_REVIEW.md).
7. Create an annotated tag for the qualified commit and a **draft GitHub Release**; attach **only the five platform archives and `SHA256SUMS`**. GitHub automatically displays its own source-code ZIP and tarball. Publish after explicit maintainer approval. Do not upload the per-platform CI artifacts or the aggregate signed-candidates workspace.

## Version-driven package naming

`CMakeLists.txt` is the authoritative project version and now declares **2.0.1**. Both `scripts/package_candidate.py` and `scripts/assemble_release.py` derive filenames and metadata from that declaration. The local README release badge is intentionally **version-neutral**: it links to the latest published GitHub release without claiming the release candidate is already public. Rerun the full candidate workflow on the exact approved release commit; never reuse a previous version's binaries or signatures.

Debian CPack uses **no** forced release revision, yielding a package version of `2.0.1` and a native package filename `xorcist_2.0.1_amd64.deb`. The five top-level GitHub release files will be:

```text
XORcist-2.0.1-debian12-amd64.tar.gz
XORcist-2.0.1-debian13-amd64.tar.gz
XORcist-2.0.1-ubuntu2404-amd64.tar.gz
XORcist-2.0.1-ubuntu2604-amd64.tar.gz
XORcist-2.0.1-windows-x64.zip
SHA256SUMS
```

The `v2.0.0` release remains unchanged, including any existing `-1` Debian revision.

### How the signed contents work

Each downloadable archive contains `RELEASE_MANIFEST.json` and `RELEASE_MANIFEST.json.sigstore.json`. The manifest lists the source revision, target platform, version, and SHA-256 digest of **every other included file**. Its signed bundle verifies the manifest itself. Signing this *internal* manifest rather than the outer archive avoids the impossible task of including a file's own signature inside its signed bytes.

Linux archives additionally contain the signed `.deb`, signed SPDX file, runtime dependencies, and per-DEB checksum. The Windows ZIP directly contains `bin/` and `share/` plus the signed manifest and the source-candidate provenance record. The outer archive digest is verified against `SHA256SUMS` (which is not separately signed). This arrangement proves payload integrity and workflow origin after successful signature verification; it does not constitute an independent application security audit.

Confirm the release workflow was triggered from `main` at the **same full Git commit** you intend to tag. In particular, do not tag a later commit just because its version is also `2.0.1`. To independently verify the six downloaded assets, use a checkout with the matching `CMakeLists.txt`:

```bash
python3 scripts/release_version.py      # 2.0.1
```

To download assets from the successful workflow:

```bash
RUN_ID=<successful-M4-workflow-run-ID>
mkdir -p release-ready
gh run download "$RUN_ID" --name xorcist-release-ready --dir release-ready
cd release-ready
sha256sum -c SHA256SUMS
```

You can perform strict archive checks from a checkout of the **same source revision**:

```bash
python3 scripts/assemble_release.py verify --assets /path/to/release-ready --cosign \
  --source-commit "$(git rev-parse HEAD)"
```

### Verify a Sigstore bundle

Install a current `cosign`, extract the relevant platform archive, and verify its **internal** manifest and associated bundle:

```bash
cosign verify-blob RELEASE_MANIFEST.json \
  --bundle RELEASE_MANIFEST.json.sigstore.json \
  --certificate-identity \
  'https://github.com/SpilledMilkFactory/XORcist-2.0/.github/workflows/m4-candidates.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

The signature authenticates the **manifest**, which lists payload hashes. The outer download bytes are checked with `SHA256SUMS`. Signatures establish workflow provenance, **not** independent security assurance. Repacking an archive changes its outer checksum; verify a new release build rather than reusing old assets.

## Source and package hygiene

`cmake/` holds required dependency locks and DEB permission normalization; `packaging/linux/` holds the installed desktop launcher; `docs/licenses/` and `docs/man/` contain redistributable notices and CLI documentation. All are tracked release inputs. Local `build-*`, `dist/`, `_CPack_Packages/`, `XORcist-2.0-Release/`, `.deb`, and downloaded dependency trees are **not** source files and should remain untracked.
