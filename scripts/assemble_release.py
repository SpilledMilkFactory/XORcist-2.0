#!/usr/bin/env python3
"""Create five auditable, single-download release bundles from SIGNED M4 candidates.

`prepare` stages payloads and SHA-256 inventories for signing.
`finalize` requires a valid Sigstore bundle for each staged release manifest;
`verify` independently checks archive contents, hashes, and optionally signatures.

The manifest (not the outer compressed archive) is signed so its Sigstore
verification material can live INSIDE that single archive without circularity.
The public SHA256SUMS covers the exact outer archive bytes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

from release_version import project_version

LINUX = ('debian12', 'debian13', 'ubuntu2404', 'ubuntu2604')
PLATFORMS = (*LINUX, 'windows-x64')
ISSUER = 'https://token.actions.githubusercontent.com'
WORKFLOW = 'https://github.com/SpilledMilkFactory/XORcist-2.0/.github/workflows/m4-candidates.yml@refs/heads/main'
MANIFEST = 'RELEASE_MANIFEST.json'
SIGNATURE = MANIFEST + '.sigstore.json'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as inp:
        for chunk in iter(lambda: inp.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def candidates_folder(root: Path, platform: str) -> Path:
    directory = root / ('xorcist-m4-' + platform)
    if not directory.is_dir():
        raise ValueError(f'missing signed candidate directory: {directory}')
    return directory


def version_check(provided: str | None) -> str:
    actual = project_version()
    if provided is not None and provided != actual:
        raise ValueError(f'requested version {provided} differs from CMake project version {actual}')
    return actual


def read_single(directory: Path, glob: str) -> Path:
    found = sorted(p for p in directory.glob(glob) if p.is_file())
    if len(found) != 1:
        raise ValueError(f'expected exactly one {glob} in {directory}, found {len(found)}')
    return found[0]


def copy_required(source: Path, directory: Path) -> None:
    if not source.is_file():
        raise ValueError(f'missing required signed release input: {source}')
    shutil.copyfile(source, directory / source.name)


def check_checksum_sidecar(source: Path) -> None:
    checksum = source.with_name(source.name + '.sha256')
    if not checksum.is_file():
        raise ValueError(f'missing input checksum: {checksum}')
    parts = checksum.read_text(encoding='ascii').strip().split()
    if len(parts) != 2 or parts[1] != source.name or parts[0] != hash_file(source):
        raise ValueError(f'input checksum mismatch: {source}')


def check_archive_member(name: str, prefix: str) -> str:
    parts = PurePosixPath(name).parts
    if not name.startswith(prefix + '/') or len(parts) < 2:
        raise ValueError(f'unexpected path in Windows signed candidate: {name!r}')
    if name.startswith('/') or any(p in ('..', '.', '') for p in parts) or '\\' in name:
        raise ValueError(f'unsafe path in Windows signed candidate: {name!r}')
    return PurePosixPath(*parts[1:]).as_posix()


def windows_payload(zip_path: Path, stage: Path, version: str, commit: str) -> None:
    check_checksum_sidecar(zip_path)
    if not zip_path.with_name(zip_path.name + '.sigstore.json').is_file():
        raise ValueError('Windows signed source candidate is missing its Sigstore bundle')
    # The original ZIP is verified in the signing job. The new signed release
    # manifest covers the extracted portable files. No nested ZIP is shipped.
    (stage / 'SIGNED_SOURCE_CANDIDATE.json').write_text(json.dumps({
        'schema': 'xorcist.release.signed-candidate.v1',
        'source_candidate': zip_path.name,
        'source_candidate_sha256': hash_file(zip_path),
        'source_candidate_verified_by_signing_workflow': True,
        'source_commit': commit,
    }, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    with zipfile.ZipFile(zip_path) as archive:
        entries = archive.infolist()
        roots = {i.filename.split('/')[0] for i in entries if not i.is_dir()}
        if len(roots) != 1:
            raise ValueError('Windows candidate ZIP has multiple roots')
        root = roots.pop()
        if root != f'XORcist-{version}-m4-candidate-windows-x64':
            raise ValueError(f'Windows candidate version/root mismatch: {root}')
        names = set()
        for entry in entries:
            if entry.is_dir():
                continue
            rel = check_archive_member(entry.filename, root)
            if rel in names or rel in (MANIFEST, SIGNATURE, 'SIGNED_SOURCE_CANDIDATE.json'):
                raise ValueError(f'duplicate/reserved Windows candidate entry: {rel}')
            names.add(rel)
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('symlink not allowed in Windows candidate ZIP')
            dest = stage / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(archive.read(entry))
            if rel.startswith('bin/') and rel.endswith('.exe'):
                dest.chmod(0o755)
    for required in ['bin/xorcist.exe', 'bin/xorcist-gui.exe',
                     'share/doc/xorcist/SBOM.spdx.json',
                     'share/doc/xorcist/DEPENDENCIES.lock.json',
                     'share/doc/xorcist/WINDOWS_IMPORTS.json']:
        if not (stage / required).is_file():
            raise ValueError(f'Windows candidate lacks required file: {required}')
    manifest = json.loads((stage / 'share/doc/xorcist/DEPENDENCIES.lock.json').read_text(encoding='utf-8'))
    if manifest.get('source_commit') != commit or manifest.get('platform') != 'windows-x64':
        raise ValueError('Windows candidate source/platform identity mismatch')


def linux_payload(candidate: Path, stage: Path, version: str, platform: str) -> None:
    deb = read_single(candidate, '*.deb')
    if deb.name != f'xorcist_{version}_amd64.deb':
        raise ValueError(f'Linux DEB filename must not contain a Debian -1 revision: {deb.name}')
    check_checksum_sidecar(deb)
    for suffix in ('', '.sha256', '.spdx.json', '.runtime.json', '.sigstore.json',
                   '.spdx.json.sigstore.json'):
        copy_required(deb.with_name(deb.name + suffix), stage)
    runtime = json.loads((stage / (deb.name + '.runtime.json')).read_text(encoding='utf-8'))
    if runtime.get('target') != platform + '-amd64' or runtime.get('deb_sha256') != hash_file(deb):
        raise ValueError(f'Linux candidate runtime inventory mismatch: {platform}')
    # Debian control Version is checked by the existing m4_audit_deb.py on each
    # native build host before upload; only sign-verified artifacts are accepted.


def prepare(root: Path, stage_root: Path, version: str, commit: str) -> None:
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('source commit must be the full 40-character Git SHA')
    if stage_root.exists():
        raise ValueError(f'refusing to overwrite existing release staging directory: {stage_root}')
    stage_root.mkdir(parents=True)
    for platform in PLATFORMS:
        candidate = candidates_folder(root, platform)
        stage = stage_root / platform
        stage.mkdir()
        if platform in LINUX:
            linux_payload(candidate, stage, version, platform)
            (stage / 'INSTALL.txt').write_text(
                f'XORcist {version} for {platform} amd64\n\n'
                f'Extract this archive; from this directory run:\n'
                f'  sudo apt install ./xorcist_{version}_amd64.deb\n'
                f'  xorcist --help\n  xorcist-gui\n\n'
                'Use only the package matching your distribution.\n'
                'Verify RELEASE_MANIFEST.json with its Sigstore bundle first.\n', encoding='utf-8')
        else:
            source = read_single(candidate, '*.zip')
            windows_payload(source, stage, version, commit)
            (stage / 'INSTALL.txt').write_text(
                f'XORcist {version} for Windows 10/11 x64\n\n'
                'Extract this ZIP and launch bin/xorcist-gui.exe or bin/xorcist.exe.\n'
                'Verify RELEASE_MANIFEST.json with its Sigstore bundle first.\n', encoding='utf-8')
        files = sorted(p for p in stage.rglob('*') if p.is_file())
        inventory = {p.relative_to(stage).as_posix(): hash_file(p) for p in files}
        (stage / MANIFEST).write_text(json.dumps({
            'schema': 'xorcist.release.v1',
            'version': version, 'platform': platform,
            'source_commit': commit,
            'workflow_identity': WORKFLOW,
            'files': inventory,
        }, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        print(f'Staged {platform} with {len(files)} files for manifest signing')


def stage_files(stage: Path, version: str, platform: str, commit: str | None = None) -> list[Path]:
    manifest_file = stage / MANIFEST
    bundle = stage / SIGNATURE
    if not manifest_file.is_file() or not bundle.is_file():
        raise ValueError(f'missing manifest or Sigstore bundle in {stage}')
    manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
    if manifest.get('schema') != 'xorcist.release.v1' or manifest.get('version') != version \
            or manifest.get('platform') != platform or manifest.get('workflow_identity') != WORKFLOW:
        raise ValueError(f'invalid release manifest identity: {stage}')
    if commit is not None and manifest.get('source_commit') != commit:
        raise ValueError('source commit mismatch')
    files = {p.relative_to(stage).as_posix(): p for p in stage.rglob('*') if p.is_file()}
    if set(files) != set(manifest['files']) | {MANIFEST, SIGNATURE}:
        raise ValueError(f'file inventory mismatch in stage {stage}')
    for rel, expected_hash in manifest['files'].items():
        if len(expected_hash) != 64 or hash_file(files[rel]) != expected_hash:
            raise ValueError(f'payload changed since manifest signing: {rel}')
    return [files[n] for n in sorted(files)]


def canonical_archive(root: Path, files: list[Path], output: Path, epoch: int) -> None:
    folder = output.name.removesuffix('.tar.gz').removesuffix('.zip')
    with output.open('wb') as f:
        if output.name.endswith('.tar.gz'):
            with gzip.GzipFile(fileobj=f, filename='', mtime=0, mode='wb', compresslevel=9) as gz:
                with tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
                    for path in files:
                        rel = path.relative_to(root).as_posix()
                        data = path.read_bytes()
                        ti = tarfile.TarInfo(folder + '/' + rel)
                        ti.size = len(data)
                        ti.mode = 0o755 if rel.startswith('bin/') and rel.endswith('.exe') else 0o644
                        ti.uid = ti.gid = 0
                        ti.mtime = epoch
                        tar.addfile(ti, io.BytesIO(data))
        else:
            with zipfile.ZipFile(f, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
                for path in files:
                    rel = path.relative_to(root).as_posix()
                    item = zipfile.ZipInfo(folder + '/' + rel)
                    stamp = datetime.fromtimestamp(epoch, timezone.utc)
                    item.date_time = (1980, 1, 1, 0, 0, 0) if epoch < 315532800 else (stamp.year, stamp.month, stamp.day, stamp.hour, stamp.minute, stamp.second)
                    item.create_system = 3
                    item.external_attr = (0o100755 if rel.startswith('bin/') and rel.endswith('.exe') else 0o100644) << 16
                    item.compress_type = zipfile.ZIP_DEFLATED
                    z.writestr(item, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def filename_for(version: str, platform: str) -> str:
    return f'XORcist-{version}-{platform if platform == "windows-x64" else platform + "-amd64"}' + ('.zip' if platform == 'windows-x64' else '.tar.gz')


def finalize(staging: Path, out: Path, version: str, epoch: int) -> None:
    if out.exists() and any(out.iterdir()):
        raise ValueError('refusing to replace existing release assets: ' + str(out))
    out.mkdir(parents=True, exist_ok=True)
    for platform in PLATFORMS:
        folder = staging / platform
        files = stage_files(folder, version, platform)
        archive = out / filename_for(version, platform)
        canonical_archive(folder, files, archive, epoch)
        print(f'Created {archive.name} SHA256={hash_file(archive)}')
    (out / 'SHA256SUMS').write_text(''.join(
        f'{hash_file(out / filename_for(version, platform))}  {filename_for(version, platform)}\n'
        for platform in PLATFORMS), encoding='ascii')
    verify(out, version, cosign=False)


def archive_contents(path: Path) -> dict[str, bytes]:
    if path.name.endswith('.tar.gz'):
        with tarfile.open(path, 'r:gz') as tar:
            members = tar.getmembers()
            if any(not member.isfile() for member in members):
                raise ValueError('non-regular object in release tarball')
            items = [(member.name, tar.extractfile(member).read()) for member in members]
    elif path.suffix == '.zip':
        with zipfile.ZipFile(path) as z:
            entries = z.infolist()
            if any(entry.is_dir() or ((entry.external_attr >> 16) & 0o170000) == 0o120000
                   for entry in entries):
                raise ValueError('directory or symlink entries not allowed in release ZIP')
            items = [(entry.filename, z.read(entry)) for entry in entries]
    else:
        raise ValueError('unsupported release archive')
    if len(items) != len({name for name, _ in items}):
        raise ValueError('duplicate member names in release archive')
    prefix = path.name.removesuffix('.tar.gz').removesuffix('.zip')
    data = {}
    for name, value in items:
        parts = PurePosixPath(name).parts
        if not name.startswith(prefix + '/') or len(parts) < 2 or '..' in parts or '\\' in name:
            raise ValueError(f'unsafe or unexpected archive member: {name!r}')
        data['/'.join(parts[1:])] = value
    return data


def verify(out: Path, version: str, cosign: bool = False, commit: str | None = None) -> None:
    checksum_file = out / 'SHA256SUMS'
    checksum_lines = checksum_file.read_text(encoding='ascii').splitlines()
    if len(checksum_lines) != 5:
        raise ValueError('SHA256SUMS must list exactly five release archives')
    if set(p.name for p in out.iterdir()) != {filename_for(version, p) for p in PLATFORMS} | {'SHA256SUMS'}:
        raise ValueError('release directory must contain exactly five archives plus SHA256SUMS')
    for platform, line in zip(PLATFORMS, checksum_lines):
        name = filename_for(version, platform)
        expected = f'{hash_file(out / name)}  {name}'
        if line != expected:
            raise ValueError(f'archive checksum mismatch: {name}')
        data = archive_contents(out / name)
        if MANIFEST not in data or SIGNATURE not in data:
            raise ValueError(f'missing signed manifest: {name}')
        manifest = json.loads(data[MANIFEST])
        if manifest.get('schema') != 'xorcist.release.v1' or manifest.get('version') != version \
                or manifest.get('platform') != platform or manifest.get('workflow_identity') != WORKFLOW:
            raise ValueError(f'invalid release identity in {name}')
        if commit is not None and manifest.get('source_commit') != commit:
            raise ValueError(f'source SHA mismatch in {name}')
        names = set(data) - {MANIFEST, SIGNATURE}
        if set(manifest['files']) != names:
            raise ValueError(f'missing/extra payload file in {name}')
        for member, sha in manifest['files'].items():
            if digest(data[member]) != sha:
                raise ValueError(f'manifest SHA mismatch for {member}')
        if cosign:
            with tempfile.TemporaryDirectory() as temp:
                m, b = Path(temp) / MANIFEST, Path(temp) / SIGNATURE
                m.write_bytes(data[MANIFEST]); b.write_bytes(data[SIGNATURE])
                subprocess.run(['cosign', 'verify-blob', '--bundle', str(b),
                                '--certificate-identity', WORKFLOW,
                                '--certificate-oidc-issuer', ISSUER,
                                str(m)], check=True)
        print(f'PASS: {name} (signed manifest present, {len(names)} payload hashes match)')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('--candidates', type=Path, required=True)
    p.add_argument('--staging', type=Path, required=True)
    p.add_argument('--source-commit', required=True)
    p = sub.add_parser('finalize')
    p.add_argument('--staging', type=Path, required=True)
    p.add_argument('--output-dir', type=Path, required=True)
    p = sub.add_parser('verify')
    p.add_argument('--assets', type=Path, required=True)
    p.add_argument('--cosign', action='store_true')
    p.add_argument('--source-commit')
    parser.add_argument('--version')
    args = parser.parse_args()
    version = version_check(args.version)
    if args.command == 'prepare':
        prepare(args.candidates, args.staging, version, args.source_commit)
    elif args.command == 'finalize':
        epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
        finalize(args.staging, args.output_dir, version, epoch)
    else:
        verify(args.assets, version, args.cosign, args.source_commit)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as e:
        print(f'RELEASE ERROR: {e}', file=sys.stderr)
        sys.exit(1)
