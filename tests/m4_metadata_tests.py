#!/usr/bin/env python3
"""Offline M4 release-metadata regression checks; no network or native packages."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]

def text(name): return (ROOT/name).read_text(encoding='utf-8')

def check(condition, message):
    if not condition: raise AssertionError(message)

def main():
    desktop = text('packaging/linux/xorcist.desktop')
    check('Type=Application' in desktop and 'Exec=xorcist-gui' in desktop, 'desktop exec mismatch')
    check('Terminal=false' in desktop, 'GUI desktop launcher must not launch terminal')
    man = text('docs/man/xorcist.1')
    for command in ['net', 'diag', 'xor', 'data', 'secure', 'legacy-decrypt']:
        check(command in man, f'missing command in manual: {command}')
    lock = text('cmake/dependencies.lock.cmake')
    for key in ['XORCIST_IMGUI_COMMIT', 'XORCIST_GLFW_COMMIT', 'XORCIST_WINDOWS_VCPKG_TAG']:
        check(key in lock, f'missing source lock: {key}')
    notices = text('THIRD_PARTY_NOTICES.md')
    check('OpenSSL' in notices and 'Apache' in notices, 'missing OpenSSL notice')
    check('Apache License' in text('docs/licenses/OPENSSL_APACHE-2.0.txt'), 'missing Apache license')
    workflow = text('.github/workflows/m4-candidates.yml')
    for target in ['debian:12', 'debian:13', 'ubuntu:24.04', 'ubuntu:26.04', 'windows-2022']:
        check(target in workflow, f'missing matrix target: {target}')
    check('workflow_dispatch:' in workflow, 'candidate process must be manual opt-in')
    check('assemble_release.py prepare' in workflow and 'assemble_release.py finalize' in workflow,
          'release bundle preparation/finalization missing')
    check('assemble_release.py verify' in workflow and '--cosign' in workflow,
          'release manifest independent signature verification missing')
    check('name: xorcist-release-ready' in workflow, 'missing six-asset release upload')
    sys.path.insert(0, str(ROOT / 'scripts'))
    from release_version import project_version
    version = project_version()
    check(re.fullmatch(r'\d+\.\d+\.\d+', version) is not None, 'invalid project version')
    from assemble_release import filename_for, PLATFORMS
    names = [filename_for(version, platform) for platform in PLATFORMS]
    check(len(names) == 5 and len(set(names)) == 5, 'release asset names not unique')
    check(all(name.startswith(f'XORcist-{version}-') for name in names), 'release asset naming mismatch')
    check(version in text(f'docs/releases/v{version}.md'), 'missing current-version release notes')
    check('CPACK_DEBIAN_PACKAGE_RELEASE "1"' not in text('CMakeLists.txt'),
          'Debian package must not force a -1 version suffix')
    candidate = text('scripts/package_candidate.py')
    check('project_version()' in candidate, 'candidate builder must derive project version from CMake')
    check('docs/images/latest-release.svg' in text('README.md') and (ROOT/'docs/images/latest-release.svg').is_file(), 'missing local GitHub release badge')
    check('XORCIST_PACKAGE_DEB=ON' in workflow and 'cosign verify-blob' in workflow, 'missing packaging/signature checks')
    check('XORCIST_PACKAGE_DEB' in text('CMakeLists.txt'), 'missing CMake packaging switch')
    check('CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON' in text('CMakeLists.txt'), 'missing runtime dependency resolver')
    check('CPACK_PRE_BUILD_SCRIPTS' in text('CMakeLists.txt'), 'missing DEB staged-permission normalization')
    check('m4_normalize_deb_permissions.cmake' in text('CMakeLists.txt'), 'missing staged-permission script')
    check('file(CHMOD' in text('cmake/m4_normalize_deb_permissions.cmake'), 'missing staged mode enforcement')
    check('validate_payload_modes(deb)' in text('scripts/m4_audit_deb.py'), 'missing payload-permission audit')
    print('PASS: M4 packaging metadata, target matrix, signing checks, and licenses')

if __name__ == '__main__': main()
