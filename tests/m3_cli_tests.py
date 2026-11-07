#!/usr/bin/env python3
"""M3 external CLI tests. No network, user secrets or external fixtures."""
import pathlib
import subprocess
import sys
import tempfile

BIN = pathlib.Path(sys.argv[1]).resolve()

def invoke(*args, password=None, ok=True):
    proc = subprocess.run([str(BIN), *args], input=password, text=True,
                          capture_output=True, timeout=30)
    if (proc.returncode == 0) != ok:
        raise AssertionError(f'{args}: code={proc.returncode}, stderr={proc.stderr}')
    return proc.stdout

with tempfile.TemporaryDirectory(prefix='xorcist-m3-cli-') as tmp:
    p = pathlib.Path(tmp)
    source = p / 'source.bin'
    source.write_bytes(bytes(range(256)) * 3 + b'\x00M3 data\n')
    b64 = p / 'base64.txt'
    binary = p / 'decoded.bin'
    invoke('data', 'base64', 'encode', '--in', str(source), '--out', str(b64))
    invoke('data', 'base64', 'decode', '--in', str(b64), '--out', str(binary))
    assert source.read_bytes() == binary.read_bytes()
    empty = p / 'empty.bin'
    empty.write_bytes(b'')
    empty_b64 = p / 'empty.b64'
    empty_recovered = p / 'empty-recovered.bin'
    invoke('data', 'base64', 'encode', '--in', str(empty), '--out', str(empty_b64))
    invoke('data', 'base64', 'decode', '--in', str(empty_b64), '--out', str(empty_recovered))
    assert empty_recovered.read_bytes() == b''
    empty_hex = p / 'empty.hex'
    empty_from_hex = p / 'empty-hex-recovered.bin'
    invoke('data', 'hex', 'encode', '--in', str(empty), '--out', str(empty_hex))
    invoke('data', 'hex', 'decode', '--in', str(empty_hex), '--out', str(empty_from_hex))
    assert empty_from_hex.read_bytes() == b''
    hexfile = p / 'hex.txt'
    hexback = p / 'hex-back.bin'
    invoke('data', 'hex', 'encode', '--in', str(source), '--out', str(hexfile))
    invoke('data', 'hex', 'decode', '--in', str(hexfile), '--out', str(hexback))
    assert source.read_bytes() == hexback.read_bytes()
    assert invoke('data', 'mask', '--hex', 'f0', '--mask-hex', '0f', '--op', 'or').strip() == 'ff'
    assert invoke('data', 'bits', '--hex', 'a5').strip() == '10100101'
    assert '00000000' in invoke('data', 'inspect', '--in', str(source), '--limit', '16')
    assert 'Files identical.' in invoke('data', 'diff', '--left', str(source), '--right', str(binary))
    secret = 'secure-M3-passphrase-only-from-stdin\n'
    # A short passphrase must not create encrypted output.
    short_output = p / 'short-password.xorc3'
    invoke('secure', 'encrypt', '--in', str(source), '--out', str(short_output),
           '--password-stdin', password='short\n', ok=False)
    assert not short_output.exists()

    # Missing encrypted input should fail before prompting.
    missing_output = p / 'missing-output.bin'
    missing = subprocess.run(
        [str(BIN), 'secure', 'decrypt',
         '--in', str(p / 'absent.xorc3'),
         '--out', str(missing_output)],
        input='', text=True, capture_output=True, timeout=10)
    assert missing.returncode != 0
    assert 'input file does not exist:' in missing.stderr
    assert 'Passphrase:' not in missing.stderr
    assert not missing_output.exists()

    encrypted = p / 'encrypted.xorc3'
    recovered = p / 'recovered.bin'
    invoke('secure', 'encrypt', '--in', str(source), '--out', str(encrypted), '--password-stdin', password=secret)
    invoke('secure', 'decrypt', '--in', str(encrypted), '--out', str(recovered), '--password-stdin', password=secret)
    assert recovered.read_bytes() == source.read_bytes()
    invoke('secure', 'decrypt', '--in', str(encrypted), '--out', str(p / 'wrong.bin'),
           '--password-stdin', password='wrong-password\n', ok=False)
    assert not (p / 'wrong.bin').exists()
    invoke('secure', 'encrypt', '--in', str(source), '--out', str(encrypted), '--password-stdin', password=secret, ok=False)
    invoke('secure', 'encrypt', '--in', str(source), '--out', str(p / 'bad.bin'),
           '--password', 'SHOULD_NOT_BE_ACCEPTED', ok=False)
    invoke('data', 'hex', 'decode', '--in', str(b64), '--out', str(p / 'bad-hex.bin'), ok=False)
    assert not (p / 'bad-hex.bin').exists()
print('M3 CLI integration PASS')
