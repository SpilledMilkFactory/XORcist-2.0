#!/usr/bin/env python3
"""Reproduce synthetic 2019 Java ASCII/writeUTF fixtures without real user data.

Not needed for C++ builds. Generated fixtures are intentionally small and public.
"""
from pathlib import Path
from base64 import b64encode

HERE = Path(__file__).resolve().parent
MESSAGE = b"XORcist legacy fixture"
BITS = "".join(f"{byte:08b}" for byte in MESSAGE)
KEY = "".join("1" if (i * 7 + 3) % 11 < 5 else "0" for i in range(len(BITS)))
MIXED = bytes(ord(x) ^ ord(y) for x, y in zip(BITS, KEY))


def write_utf(s: str) -> bytes:
    b = s.encode("ascii")
    if len(b) > 65535:
        raise ValueError("Java writeUTF record too large")
    return len(b).to_bytes(2, "big") + b


# The old implementation writes many keys, but ignores all except the first.
(HERE / "keys.dat").write_bytes(write_utf(KEY + "\n") + write_utf("0" * len(KEY) + "\n"))
(HERE / "cipherText.dat").write_bytes(write_utf(b64encode(MIXED).decode("ascii")))
print("Synthetic fixtures generated")
