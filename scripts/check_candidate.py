#!/usr/bin/env python3
"""Verify M4 candidate checksum, embedded SPDX file hashes, and metadata.

Does not establish trust in the signer: independently verify Sigstore bundles.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile


def check(archive: Path) -> None:
    checksum = archive.with_name(archive.name + '.sha256')
    expected = checksum.read_text(encoding='ascii').split()[0]
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if expected != actual:
        raise ValueError(f'archive digest mismatch {actual} != {expected}')
    if archive.suffix == '.zip':
        with zipfile.ZipFile(archive) as z:
            contents = {i.filename: z.read(i.filename) for i in z.infolist() if not i.is_dir()}
    elif archive.name.endswith('.tar.gz'):
        with tarfile.open(archive, 'r:gz') as t:
            contents = {i.name: t.extractfile(i).read() for i in t.getmembers() if i.isfile()}
    else:
        raise ValueError(f'unsupported archive: {archive}')
    if not contents:
        raise ValueError('archive is empty')
    prefixes = {name.split('/')[0] for name in contents}
    if len(prefixes) != 1:
        raise ValueError('more than one archive root directory')
    root = prefixes.pop()
    if '..' in root or any(n.startswith('/') or '..' in n.split('/') for n in contents):
        raise ValueError('unsafe archive paths')
    sbom_path = root + '/share/doc/xorcist/SBOM.spdx.json'
    dep_path = root + '/share/doc/xorcist/DEPENDENCIES.lock.json'
    sbom = json.loads(contents[sbom_path])
    manifest = json.loads(contents[dep_path])
    if sbom['spdxVersion'] != 'SPDX-2.3' or manifest['schema'] != 'xorcist.m4.candidate.v1':
        raise ValueError('unrecognized SBOM/manifest schema')
    ids = set()
    for entry in sbom['files']:
        relative = entry['fileName'].removeprefix('./')
        actual_bytes = contents[root + '/' + relative]
        expected_hash = next(x['checksumValue'] for x in entry['checksums'] if x['algorithm'] == 'SHA256')
        if hashlib.sha256(actual_bytes).hexdigest() != expected_hash:
            raise ValueError(f'SBOM hash mismatch for {relative}')
        ids.add(relative)
    listed_files = {p.removeprefix(root + '/') for p in contents if p != sbom_path}
    if ids != listed_files:
        raise ValueError(f'SBOM inventory mismatch: missing={listed_files-ids}, extra={ids-listed_files}')
    print(f'PASS: {archive.name}; verified archive SHA-256 and {len(ids)} SPDX file hashes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archives', nargs='+', type=Path)
    args = parser.parse_args()
    for archive in args.archives:
        check(archive)
