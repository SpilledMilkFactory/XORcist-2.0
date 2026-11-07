#!/usr/bin/env python3
"""Integration checks of the actual CLI, including exit codes and file behavior."""
import pathlib
import subprocess
import sys
import tempfile

binary = pathlib.Path(sys.argv[1]).resolve()
checks = 0


def run(args, expected=None, fail=False):
    global checks
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, timeout=12)
    if fail and result.returncode == 0:
        raise AssertionError(f"expected rejection for {args}: {result.stdout}")
    if not fail and result.returncode != 0:
        raise AssertionError(f"command failed {args}: {result.stderr}")
    if expected is not None and expected not in result.stdout:
        raise AssertionError(f"expected {expected!r} in {result.stdout!r} from {args}")
    checks += 1
    return result.stdout


run(["net", "inspect", "2001:db8::1/64"], "Network: 2001:db8::/64")
run(["net", "summarize", "2001:db8::/32", "2001:db9::/32"], "2001:db8::/31")
run(["net", "collapse", "2001:db8::/127", "2001:db8::2/127"], "2001:db8::/126")
run(["net", "overlap", "10.0.0.0/24", "10.0.1.0/24"], "no")
run(["net", "intersect", "2001:db8::/32", "2001:db8:1::/48"], "2001:db8:1::/48")
run(["net", "contains", "10.0.0.0/8", "10.5.6.7"], "yes")
run(["net", "covers", "10.0.0.0/8", "10.5.0.0/16"], "yes")
run(["net", "range", "192.0.2.0", "192.0.2.15"], "192.0.2.0/28")
run(["net", "range", "::", "::f"], "::/124")
run(["net", "split", "192.0.2.0/24", "26"], "192.0.2.192/26")
run(["net", "vlsm", "10.0.0.0/24", "lan=50", "wifi=20", "iot=5"], "iot,5,10.0.0.96/29")
run(["net", "conflicts", "10.0.0.0/8", "10.1.0.0/16"], "overlaps")
run(["net", "summarize", "192.168.1.1/24", "192.168.2.1/24"], "255.255.252.0")
run(["xor", "text", "--text", "Hello!", "--key-hex", "010203"], "49676f6d6d22")
run(["net", "split", "192.0.2.0/24", "12"], fail=True)
run(["net", "range", "::1", "192.0.2.1"], fail=True)
run(["net", "vlsm", "10.0.0.0/30", "lan=3"], fail=True)
run(["net", "collapse", "10.0.0.0/8", "2001:db8::/32"], fail=True)
with tempfile.TemporaryDirectory(prefix="xorcist-m1-cli-") as temp:
    root = pathlib.Path(temp)
    lines = root / "networks.txt"
    csv = root / "export.csv"
    lines.write_text("192.0.2.1/24\n2001:db8::/32\n", encoding="ascii")
    run(["net", "convert", "--in", lines, "--out", csv, "--from", "lines", "--to", "csv"], "Wrote 2 networks")
    if csv.read_text(encoding="ascii") != "cidr\n192.0.2.0/24\n2001:db8::/32\n":
        raise AssertionError("wrong CSV contents")
    run(["net", "convert", "--in", lines, "--out", csv], fail=True)
    run(["net", "summarize", "--file", lines], fail=True)  # mixed-family is rejected
print(f"{checks} CLI integration checks passed")
