# XORcist authenticated file envelope — experimental format v1

This is a **development file format, not yet a stable public interchange specification**.
M3 files use the `.xorc3` extension by convention. The extension is not part of
integrity verification and the implementation does not derive output filenames
from input metadata. No file names, owners, modification times or permissions
are included in the container.

## Wire layout

All multibyte integers use **unsigned big-endian** encoding; no host C++
struct packing or host-endian serialization is used.

| Byte offsets | Length | Field | Valid value in v1 |
|---|---:|---|---|
| 0..7 | 8 | Format magic | ASCII `XORC3AE1` |
| 8 | 1 | Version | `0x01` |
| 9 | 1 | Cipher ID | `0x01` = AES-256-GCM |
| 10 | 1 | KDF ID | `0x01` = scrypt |
| 11 | 1 | Reserved | `0x00` |
| 12..15 | 4 | scrypt N | `32768` |
| 16..19 | 4 | scrypt r | `8` |
| 20..23 | 4 | scrypt p | `1` |
| 24..39 | 16 | Per-file salt | CSPRNG bytes |
| 40..51 | 12 | Per-file GCM nonce | CSPRNG bytes |
| 52..59 | 8 | Plaintext byte count | `0` to `2^35` |
| 60..63 | 4 | Reserved | all zero |
| 64..64+L-1 | L | Ciphertext | AES-256-GCM ciphertext |
| 64+L..79+L | 16 | Authentication tag | GCM tag |

For version 1, the exact size of the file must be `64 + L + 16` bytes.
No trailing data are permitted. An empty plaintext results in an 80-byte
container. The complete 64-byte header is passed to the GCM cipher as
**additional authenticated data (AAD)**. The ciphertext and associated data
are authenticated together, so a successful decryption verifies the header.

## Key derivation and cryptography

The user passphrase is interpreted as a sequence of bytes (no Unicode
normalization); v1 encrypt operations require 12..4096 bytes. Decryption
requires a nonempty passphrase, allowing future recovery policies without
weakening new encryption. OpenSSL `EVP_PBE_scrypt` derives 32 key bytes using
N=32768, r=8, p=1, a 16-byte salt, and an explicit 64 MiB memory ceiling.
The cipher is `EVP_aes_256_gcm` with a random 12-byte nonce and a full
16-byte tag. No deterministic IV, passphrase hashing shortcut, repeating-key
XOR, unauthenticated CBC or homegrown encryption primitive is used.

The runtime imposes a 32 GiB maximum plaintext limit per nonce. Out-of-policy
KDF values, unknown version IDs, wrong lengths and reserved bits are rejected
before running an expensive key derivation. **Layout validation alone is not
authentication**: only successful GCM tag verification proves the bytes
are intact and the key was correct.

## Output and failure semantics

For encryption and decryption, output is prepared in a randomly named exclusive
file in the destination directory. No-existing-output publication uses
`link(2)` on POSIX and a no-replace move on Windows. On normal exceptions,
partial temporary files are removed. Decryption publishes plaintext **only
after the tag is verified**. Abrupt process termination can leave private
temporary plaintext files; `SECURITY.md` documents that risk.

There is no password recovery function, resume/append operation, chunk-wise
authentication or metadata concealment. File byte length and the format/KDF
parameters are visible without a password. The format is not intended as a
replacement for a professional secret-management or encrypted storage system.

## Forward-compatibility rules

New algorithms/KDFs must use new identifiers or a new major format version.
Do not reinterpret existing IDs or silently ignore reserved bytes. A future
v2 can introduce new fields or recipient modes, but v1 remains fixed once
released. Any such revision requires negative and interoperability tests,
format documentation, and a migration strategy before release.
