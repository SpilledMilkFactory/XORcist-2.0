#!/usr/bin/env python3
"""Offline M4 release-assembly tests with deliberately synthetic signed sidecars.

Real Sigstore cryptographic verification is performed in the CI signing job;
fixtures here are not trusted signatures and never leave the test directory.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import assemble_release as release


def put_checksum(file: Path) -> None:
    (file.parent / (file.name + '.sha256')).write_text(
        f'{release.hash_file(file)}  {file.name}\n', encoding='ascii')


def prepare_candidates(root: Path, version: str, commit: str) -> None:
    for platform in release.LINUX:
        folder = root / ('xorcist-m4-' + platform)
        folder.mkdir(parents=True)
        deb = folder / f'xorcist_{version}_amd64.deb'
        deb.write_bytes(b'test only DEB bytes ' + platform.encode())
        put_checksum(deb)
        (folder / (deb.name + '.spdx.json')).write_text('{}', encoding='utf-8')
        (folder / (deb.name + '.runtime.json')).write_text(json.dumps({
            'target': platform + '-amd64', 'deb_sha256': release.hash_file(deb)}), encoding='utf-8')
        for sig in ('.sigstore.json', '.spdx.json.sigstore.json'):
            (folder / (deb.name + sig)).write_text('{}', encoding='utf-8')
    folder = root / 'xorcist-m4-windows-x64'
    folder.mkdir()
    name = f'XORcist-{version}-m4-candidate-windows-x64'
    archive = folder / (name + '.zip')
    with zipfile.ZipFile(archive, 'w') as z:
        for rel, data in {
            'bin/xorcist.exe': b'CLI',
            'bin/xorcist-gui.exe': b'GUI',
            'share/doc/xorcist/SBOM.spdx.json': b'{}',
            'share/doc/xorcist/WINDOWS_IMPORTS.json': b'{}',
            'share/doc/xorcist/DEPENDENCIES.lock.json': json.dumps({
                'platform': 'windows-x64', 'source_commit': commit}).encode(),
        }.items():
            z.writestr(name + '/' + rel, data)
    put_checksum(archive)
    (folder / (archive.name + '.sigstore.json')).write_text('{}', encoding='utf-8')


def expect_failure(func, message: str) -> None:
    try:
        func()
    except (ValueError, KeyError, OSError):
        return
    raise AssertionError('expected failure: ' + message)


def main() -> None:
    version = release.project_version()
    commit = 'f' * 40
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        candidates = root / 'candidates'
        prepare_candidates(candidates, version, commit)
        stage = root / 'stage'
        release.prepare(candidates, stage, version, commit)
        assert len(list(stage.glob('*/RELEASE_MANIFEST.json'))) == 5
        for directory in stage.iterdir():
            (directory / release.SIGNATURE).write_text('{"test-only":"not-a-signature"}', encoding='utf-8')
        artifacts = root / 'release-assets'
        release.finalize(stage, artifacts, version, 0)
        release.verify(artifacts, version, commit=commit)
        assert len(list(artifacts.iterdir())) == 6
        windows = release.archive_contents(artifacts / release.filename_for(version, 'windows-x64'))
        assert 'bin/xorcist.exe' in windows and not any(n.endswith('.zip') for n in windows)
        assert release.MANIFEST in windows and release.SIGNATURE in windows
        for platform in release.LINUX:
            assert f'xorcist_{version}_amd64.deb' in release.archive_contents(
                artifacts / release.filename_for(version, platform))
        expect_failure(lambda: release.verify(artifacts, version, commit='a' * 40), 'wrong source commit')
        expect_failure(lambda: release.finalize(stage, artifacts, version, 0), 'cannot overwrite archives')
        damaged = artifacts / release.filename_for(version, 'debian12')
        damaged.write_bytes(damaged.read_bytes() + b'corrupted')
        expect_failure(lambda: release.verify(artifacts, version), 'corrupt archive')
    print('PASS: release assembly, five archives, six assets, manifests, and negative tests')


if __name__ == '__main__':
    main()
