#!/usr/bin/env python3
"""Return the single authoritative project version from the CMake project()."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def project_version() -> str:
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(r"^project\(XORcist\s+VERSION\s+(\d+\.\d+\.\d+)\s+LANGUAGES\s+CXX\)", cmake, re.M)
    if not match:
        raise ValueError("CMakeLists.txt must declare project(XORcist VERSION X.Y.Z LANGUAGES CXX)")
    return match.group(1)

if __name__ == "__main__":
    print(project_version())
