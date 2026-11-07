#!/usr/bin/env python3
"""Deterministic CLI smoke tests for M2. No Internet or external targets."""
import subprocess
import sys
import socket

exe = sys.argv[1]
def invoke(*args, expected=0):
    p = subprocess.run([exe, *args], capture_output=True, text=True, timeout=12)
    if p.returncode != expected:
        raise AssertionError(f"{args}: expected exit {expected}, got {p.returncode}: {p.stdout} {p.stderr}")
    return p.stdout + p.stderr

assert "Prefix: /24" in invoke('diag', 'mask', '255.255.255.0')
assert "Mask: 255.255.255.0" in invoke('diag', 'wildcard', '0.0.0.255')
assert 'ip 192.0.2.0 0.0.0.255' in invoke('diag', 'acl', '192.0.2.4/24')
assert 'ipv6 2001:db8::/64' in invoke('diag', 'acl', '2001:db8::1/64')
assert 'DNS lookup: localhost' in invoke('diag', 'dns', 'localhost', '--family', 'v4')
assert 'Local interfaces' in invoke('diag', 'interfaces')
assert 'Local routing table' in invoke('diag', 'routes')
assert 'Attempt 1:' in invoke('diag', 'probe', '127.0.0.1', '1', '--count', '1', '--timeout-ms', '200')
# Self-contained positive case: ephemeral local TCP listener, no external traffic.
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    port = server.getsockname()[1]
    output = invoke('diag', 'probe', '127.0.0.1', str(port), '--count', '1', '--timeout-ms', '500')
    assert 'Attempt 1: connected' in output, output
for command in [
    ('diag', 'mask', '255.0.255.0'),
    ('diag', 'wildcard', '0.0.255.0'),
    ('diag', 'acl', '192.0.2.1/99'),
    ('diag', 'dns', 'host/injection'),
    ('diag', 'reverse', 'hostname.example'),
    ('diag', 'probe', 'localhost', '80'),
    ('diag', 'probe', '127.0.0.1', '0'),
    ('diag', 'probe', '127.0.0.1', '80', '--count', '100'),
    ('diag', 'probe', '127.0.0.1', '80', '--count', '2', '--count', '2'),
    ('diag', 'probe', '127.0.0.1', '80', '--count', '5', '--timeout-ms', '2000', '--interval-ms', '2000'),
]:
    invoke(*command, expected=2)
print('M2 CLI tests passed')
