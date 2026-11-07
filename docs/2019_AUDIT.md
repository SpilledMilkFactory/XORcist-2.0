# 2019 Java XORcist → C++20 audit

Source reviewed: uploaded 2019 Java `src/main/XORcist.java`, `src/cryptoTools/CryptographyTool.java`, and `src/netTools/NetworkingTool.java`.

## What 2019 implemented

* Interactive terminal: choose cryptography or networking, and encrypt/decrypt.
* Convert input Java `String` characters to textual bit digits (`'0'`, `'1'`).
* Generate 0–99 pseudo-random bit strings and serialize all keys to `keys.dat` via Java `RandomAccessFile.writeUTF`.
* XOR textual bit digits with the FIRST generated bit-string key only (the loop always breaks), Base64 the resulting bytes, save via Java `writeUTF` to `cipherText.dat`.
* Decrypt using the first serialized key: Base64 decode, XOR, parse recovered groups of 8 bits to text.
* Enter IPv4 addresses with CIDR suffixes and attempt to determine a common-prefix supernet and subnet mask.

## Important bugs / behavioral constraints

* `Math.random()` is not a CSPRNG. Zero keys can be generated, in which case the plaintext bit representation is saved unchanged. These behaviors must **not** be carried forward.
* Generated extra keys are unused, despite reporting many keys used.
* `.dat` is a Java `writeUTF` container, not necessarily raw `.dat` content from arbitrary user files. The 2019 implementation does not implement general binary file encryption.
* `inputTextToBinary()` appends to an instance StringBuilder; the interactive caller invokes it twice and the code later truncates the buffer to work around duplicated data.
* The network comparison breaks on its first matching pair without checking every input network. Input CIDR suffixes do not influence the actual network-range comparison.
* Parsers did not enforce octet bounds, CIDR range, or four-octet grammar.
* Handling of non-ASCII Java strings was not byte-aligned because Java `char` is UTF-16 and the format prints a minimum width of 8 bits (not exactly 8); legacy importer intentionally supports ASCII-only bitstreams.

## Compatibility decision

**We keep old-data recovery, not old broken encryption semantics.**

`legacy-decrypt` understands the actual 2019 ASCII `writeUTF` + Base64 + first-key format, and has been checked against the provided Java project artifacts. The new XOR tool operates on bytes with an explicit user-supplied hexadecimal key. It does not write old Java formats or generate weak keys.

The new networking tool defines two distinct operations:

* **Supernet**: one smallest CIDR that encloses all **entire** input networks; this may include addresses not otherwise present.
* **Collapse**: the minimal set of CIDR blocks that describes exactly the input address union, without introducing addresses outside it.
