#!/usr/bin/env python3
"""Create deterministic candidate archives + SPDX 2.3 file/dependency inventory.

This is an M4 release CANDIDATE, not a certification of binaries.
The SBOM covers installed files and declared direct source/system dependencies;
it is not a recursive OS-wide vulnerability/component inventory.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'cmake' / 'dependencies.lock.cmake'
from release_version import project_version


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def deps() -> dict[str, str]:
    content = LOCK.read_text(encoding='utf-8')
    return dict(re.findall(r'set\((XORCIST_\w+) "([^"]+)"\)', content))


def manifest(stage: Path, platform: str, commit: str) -> dict:
    return {
        'schema': 'xorcist.m4.candidate.v1',
        'platform': platform,
        'source_commit': commit,
        'source_dependency_lock': deps(),
        'scope': 'Installed XORcist files and declared direct libraries only; OS runtime closure NOT exhaustively inventoried.',
        'runtime_note': 'See *.runtime.json for distro DEB ELF imports, WINDOWS_IMPORTS.json for Windows candidate, and third-party notices.',
    }


def sbom(stage: Path, platform: str, epoch: int) -> dict:
    files = sorted(p for p in stage.rglob('*') if p.is_file() and p.name != 'SBOM.spdx.json')
    namespace_hash = hashlib.sha256((''.join(f'{p.relative_to(stage)}:{sha256(p)}\n' for p in files) + platform).encode()).hexdigest()
    file_entries = []
    relationships = []
    for i, path in enumerate(files, 1):
        file_id = f'SPDXRef-File-{i}'
        file_entries.append({
            'SPDXID': file_id, 'fileName': './' + path.relative_to(stage).as_posix(),
            'checksums': [{'algorithm': 'SHA256', 'checksumValue': sha256(path)}],
            'licenseConcluded': 'NOASSERTION', 'copyrightText': 'NOASSERTION',
        })
        relationships.append({'spdxElementId': 'SPDXRef-XORcist', 'relatedSpdxElement': file_id,
                              'relationshipType': 'CONTAINS'})
    pkg_verification = hashlib.sha1(''.join(sorted(hashlib.sha1(p.read_bytes()).hexdigest() for p in files)).encode()).hexdigest()
    installed_pkg = {
        'SPDXID': 'SPDXRef-XORcist', 'name': 'XORcist', 'versionInfo': project_version() + '-m4-candidate',
        'downloadLocation': 'NOASSERTION', 'filesAnalyzed': True,
        'packageVerificationCode': {
            'packageVerificationCodeValue': pkg_verification,
            'packageVerificationCodeExcludedFiles': ['./share/doc/xorcist/SBOM.spdx.json'],
        },
        'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'MIT',
        'copyrightText': 'Copyright (c) 2026 Christopher Sutton',
    }
    components = [
        ('Dear-ImGui', deps()['XORCIST_IMGUI_VERSION'], deps()['XORCIST_IMGUI_COMMIT'], 'MIT'),
        ('GLFW', deps()['XORCIST_GLFW_VERSION'], deps()['XORCIST_GLFW_COMMIT'], 'Zlib'),
        ('OpenGL-system-runtime', 'OS-supplied', 'NOASSERTION', 'NOASSERTION'),
        ('OpenSSL-static-vcpkg' if platform.startswith('windows') else 'OpenSSL-libcrypto-system',
         deps().get('XORCIST_OPENSSL_MIN_VERSION', '>=3.0'), 'NOASSERTION', 'Apache-2.0'),
    ]
    packages = [installed_pkg]
    for i, (name, ver, commit, license_id) in enumerate(components):
        if name in ('Dear-ImGui', 'GLFW') and not any(p.name.startswith('xorcist-gui') for p in files):
            continue
        component_id = f'SPDXRef-Dependency-{i}'
        packages.append({
            'SPDXID': component_id, 'name': name, 'versionInfo': ver,
            'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False,
            'licenseConcluded': 'NOASSERTION', 'licenseDeclared': license_id,
            'copyrightText': 'NOASSERTION',
            'externalRefs': [] if commit == 'NOASSERTION' else [{
                'referenceCategory': 'PERSISTENT-ID', 'referenceType': 'swh',
                'referenceLocator': f'swh:1:rev:{commit}',
            }],
        })
        relationships.append({'spdxElementId': 'SPDXRef-XORcist',
                              'relatedSpdxElement': component_id, 'relationshipType': 'DEPENDS_ON'})
    return {
        'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
        'name': 'XORcist-M4-' + platform,
        'documentNamespace': 'https://spdx.org/spdxdocs/xorcist-' + namespace_hash,
        'creationInfo': {
            'created': datetime.fromtimestamp(epoch, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'creators': ['Tool: XORcist-package_candidate.py-2.0'],
            'comment': 'SBOM of staged installed files and declared direct dependencies. OS runtime dependency closure not resolved.',
        },
        'documentDescribes': ['SPDXRef-XORcist'],
        'packages': packages, 'files': file_entries, 'relationships': relationships,
    }


def package(source_stage: Path, output_dir: Path, platform: str, commit: str, epoch: int, fmt: str) -> Path:
    if not source_stage.is_dir():
        raise ValueError(f'missing stage directory: {source_stage}')
    output_dir.mkdir(parents=True, exist_ok=True)
    basename = f'XORcist-{project_version()}-m4-candidate-{platform}'
    archive = output_dir / f'{basename}.{fmt}'
    with tempfile.TemporaryDirectory(prefix='xorcist-m4-') as tmp:
        stage = Path(tmp) / basename
        shutil.copytree(source_stage, stage, symlinks=False)
        docs = stage / 'share/doc/xorcist'
        docs.mkdir(parents=True, exist_ok=True)
        (docs / 'DEPENDENCIES.lock.json').write_text(json.dumps(manifest(stage, platform, commit), indent=2, sort_keys=True) + '\n', encoding='utf-8')
        (docs / 'SBOM.spdx.json').write_text(json.dumps(sbom(stage, platform, epoch), indent=2, sort_keys=True) + '\n', encoding='utf-8')
        files = sorted(p for p in stage.rglob('*') if p.is_file())
        if not files or not any(p.name.startswith('xorcist') for p in files):
            raise ValueError('stage has no executables; check cmake --install prefix')
        if fmt == 'zip':
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
                for file in files:
                    name = f'{basename}/{file.relative_to(stage).as_posix()}'
                    entry = zipfile.ZipInfo(name)
                    entry.date_time = (1980, 1, 1, 0, 0, 0) if epoch < 315532800 else datetime.fromtimestamp(epoch, timezone.utc).timetuple()[:6]
                    entry.create_system = 3
                    entry.external_attr = (0o100755 if os.access(file, os.X_OK) else 0o100644) << 16
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    z.writestr(entry, file.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        else:
            with archive.open('wb') as stream:
                with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0, compresslevel=9) as gz:
                    with tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
                        for file in files:
                            name = f'{basename}/{file.relative_to(stage).as_posix()}'
                            info = tar.gettarinfo(str(file), arcname=name)
                            info.uid = info.gid = 0
                            info.uname = info.gname = ''
                            info.mtime = max(0, epoch)
                            with file.open('rb') as f:
                                tar.addfile(info, f)
        digest = sha256(archive)
        (output_dir / f'{archive.name}.sha256').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
        print(f'Created {archive.name} ({archive.stat().st_size} bytes, SHA256 {digest})')
        return archive


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage', type=Path, required=True)
    p.add_argument('--output-dir', type=Path, required=True)
    p.add_argument('--platform', required=True)
    p.add_argument('--git-sha', default='unverified-local-tree')
    p.add_argument('--format', choices=['zip', 'tar.gz'], required=True)
    a = p.parse_args()
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
    package(a.stage.resolve(), a.output_dir.resolve(), a.platform, a.git_sha, epoch, a.format)
