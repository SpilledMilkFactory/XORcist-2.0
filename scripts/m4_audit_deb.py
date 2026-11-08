#!/usr/bin/env python3
"""Audit a locally-built CPack Debian artifact and produce sidecar inventories.

This is a candidate-quality integrity/runtime audit, not a reproducibility or
security certification. No executables are run during extraction except a
trusted, newly built XORcist binary's --help command in CI.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import pathlib
import re
import subprocess
import stat
import tarfile
import tempfile
from package_candidate import sbom
from release_version import project_version


def cmd(*argv: str) -> str:
    return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT)


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def validate_payload_modes(deb: pathlib.Path) -> None:
    """Reject writable/special-mode package paths before extracting the DEB.

    Directory permissions must not depend on the build runner's umask.
    The package's /usr hierarchy is expected to have regular 0755 dirs.
    """
    archive = subprocess.run(
        ['dpkg-deb', '--fsys-tarfile', str(deb)],
        check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tar:
        seen = set()
        for entry in tar:
            parts = pathlib.PurePosixPath(entry.name).parts
            if not parts or parts[0] != 'usr' or '..' in parts:
                raise ValueError(f'unexpected DEB payload path: {entry.name!r}')
            if entry.name in seen:
                raise ValueError(f'duplicate DEB payload entry: {entry.name!r}')
            seen.add(entry.name)
            if not (entry.isdir() or entry.isfile() or entry.issym()):
                raise ValueError(f'unsupported DEB payload object: {entry.name!r}')
            if entry.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError(
                    f'unsafe DEB payload mode {entry.mode:04o}: {entry.name!r}; '
                    'group/world writable or special mode bits are forbidden')
            if entry.isdir() and (entry.mode & 0o777) != 0o755:
                raise ValueError(f'nonstandard DEB directory mode {entry.mode:04o}: {entry.name!r}')


def audit(deb: pathlib.Path, platform: str, dest: pathlib.Path, require_gui: bool = False) -> None:
    if not deb.is_file() or deb.suffix != '.deb':
        raise ValueError('expected a built .deb file')
    validate_payload_modes(deb)
    dest.mkdir(parents=True, exist_ok=True)
    control = cmd('dpkg-deb', '--field', str(deb))
    fields = dict(re.findall(r'^([A-Za-z-]+):\s*(.*)$', control, flags=re.MULTILINE))
    if fields.get('Package') != 'xorcist' or fields.get('Architecture') != 'amd64':
        raise ValueError('unexpected package identity or architecture')
    if fields.get('Version') != project_version():
        raise ValueError(f'DEB version {fields.get("Version")!r} must equal CMake version {project_version()!r} without revision')
    if 'libc6' not in fields.get('Depends', '') or not re.search(r'libssl3|libcrypto', fields.get('Depends', '')):
        raise ValueError('missing libc or OpenSSL package dependencies')
    # Enforce the glibc symbol floor of each declared target, not only the
    # package's deb dependency line. This still requires runtime testing.
    ceilings = {
        'debian12': (2, 36), 'debian13': (2, 41),
        'ubuntu2404': (2, 39), 'ubuntu2604': (2, 43),
    }
    target_key = platform.split('-')[0]
    ceiling = ceilings.get(target_key)
    with tempfile.TemporaryDirectory(prefix='xorcist-deb-audit-') as tmp:
        root = pathlib.Path(tmp) / 'root'
        root.mkdir()
        subprocess.run(['dpkg-deb', '--extract', str(deb), str(root)], check=True)
        bin_dir = root / 'usr/bin'
        executables = ['xorcist', 'xorcist-gui'] if require_gui else ['xorcist']
        for exe in executables:
            path = bin_dir / exe
            if not path.exists():
                raise ValueError(f'package missing {exe}')
        if not (root / 'usr/share/man/man1/xorcist.1').is_file():
            raise ValueError('missing CLI manpage')
        if require_gui and not (root / 'usr/share/applications/xorcist.desktop').is_file():
            raise ValueError('missing desktop entry')
        dependencies = {}
        versions = {}
        for exe in executables:
            output = cmd('ldd', str(bin_dir / exe))
            if re.search(r'\bnot found\b', output):
                raise ValueError(f'unresolved runtime libraries for {exe}:\n{output}')
            dependencies[exe] = output.splitlines()
            version_info = cmd('readelf', '--wide', '--version-info', str(bin_dir / exe))
            glibc = [tuple(map(int, m)) for m in re.findall(r'GLIBC_(\d+)\.(\d+)', version_info)]
            if not glibc:
                raise ValueError(f'no GLIBC version requirements detected for {exe}')
            max_glibc = max(glibc)
            if ceiling and max_glibc > ceiling:
                raise ValueError(f'{exe} requires GLIBC_{max_glibc[0]}.{max_glibc[1]} above {target_key} ceiling {ceiling}')
            glibcxx = set(re.findall(r'GLIBCXX_\d+\.\d+(?:\.\d+)?', version_info))
            versions[exe] = {'max_glibc': f'{max_glibc[0]}.{max_glibc[1]}',
                             'glibcxx_versions': sorted(glibcxx)}
        doc = sbom(root, platform, epoch=0)
        doc['name'] = 'XORcist-DEB-' + platform
        sidecar = dest / (deb.name + '.spdx.json')
        sidecar.write_text(json.dumps(doc, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        inventory = {
            'schema': 'xorcist.m4.deb-runtime.v1', 'target': platform,
            'deb': deb.name, 'deb_sha256': sha256(deb),
            'package_control': fields, 'linked_libraries': dependencies,
            'symbol_version_requirements': versions,
            'note': 'An ldd snapshot from the build container, not a full supply-chain vulnerability audit.',
        }
        (dest / (deb.name + '.runtime.json')).write_text(
            json.dumps(inventory, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    (dest / (deb.name + '.sha256')).write_text(f'{sha256(deb)}  {deb.name}\n', encoding='ascii')
    print(f'PASS: {deb.name} payload permissions, control, ELF dependencies & glibc gates, man page, SPDX inventory' + (', desktop entry' if require_gui else ''))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--deb', required=True, type=pathlib.Path)
    parser.add_argument('--platform', required=True)
    parser.add_argument('--outdir', required=True, type=pathlib.Path)
    parser.add_argument('--require-gui', action='store_true')
    args = parser.parse_args()
    audit(args.deb.resolve(), args.platform, args.outdir.resolve(), args.require_gui)
