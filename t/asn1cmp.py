#!/usr/bin/env python3
"""Compare certlint --asn1 against openssl asn1parse, TLV by TLV.

The comparison is on the tuple (offset, depth, header length, value length,
constructed, tag name), parsed out of both printers. Never on the text: the
two formats share nothing but the facts.

Prints one line per input and a summary. Exit status is the number of
certificates that disagreed, capped at 125.
"""
import re
import subprocess
import sys

OURS = re.compile(r"^\s*(\d+) d=(\d+) hl=(\d+) l=(\d+) (cons|prim) (.*)$")
OSSL = re.compile(r"^\s*(\d+):d=(\d+)\s+hl=(\d+) l=\s*(\d+)\s+(cons|prim):\s*(.*?)\s*$")


def norm_tag(name):
    """One spelling for a tag name, since the two printers differ."""
    m = re.match(r"^(cont|appl|priv)\s*\[\s*(\d+)\s*\]$", name)
    if m:
        return "%s%s" % (m.group(1), m.group(2))
    m = re.match(r"^\[(cont|appl|priv) (\d+)\]$", name)
    if m:
        return "%s%s" % (m.group(1), m.group(2))
    # openssl annotates a value it cannot print as text with [HEX DUMP] and
    # writes the value after a colon. --asn1 prints neither, so both come
    # off before the names are compared.
    name = re.sub(r"\s*\[HEX DUMP\].*$", "", name)
    name = name.split(":")[0].strip()
    return name.strip()


def parse(text, rx):
    out = []
    for line in text.splitlines():
        m = rx.match(line)
        if not m:
            continue
        out.append(
            (
                int(m.group(1)),
                int(m.group(2)),
                int(m.group(3)),
                int(m.group(4)),
                m.group(5),
                norm_tag(m.group(6)),
            )
        )
    return out


def main(argv):
    binary, files = argv[1], argv[2:]
    bad = 0
    tlvs = 0
    for f in files:
        ours = subprocess.run(
            [binary, "--asn1", f], capture_output=True, text=True
        )
        theirs = subprocess.run(
            ["openssl", "asn1parse", "-in", f], capture_output=True, text=True
        )
        if ours.returncode != 0:
            print("    %s: certlint exited %d: %s"
                  % (f, ours.returncode, ours.stderr.strip()))
            bad += 1
            continue
        if theirs.returncode != 0:
            print("    %s: openssl asn1parse exited %d, nothing to compare"
                  % (f, theirs.returncode))
            bad += 1
            continue
        a = parse(ours.stdout, OURS)
        b = parse(theirs.stdout, OSSL)
        if not b:
            print("    %s: openssl printed no TLV lines" % f)
            bad += 1
            continue
        if a != b:
            bad += 1
            print("    %s: %d TLVs ours, %d theirs" % (f, len(a), len(b)))
            for i in range(max(len(a), len(b))):
                x = a[i] if i < len(a) else None
                y = b[i] if i < len(b) else None
                if x != y:
                    print("      first difference at index %d" % i)
                    print("        ours:   %r" % (x,))
                    print("        openssl:%r" % (y,))
                    break
        tlvs += len(b)
    print("    %d TLVs over %d files, %d files disagreed" % (tlvs, len(files), bad))
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
