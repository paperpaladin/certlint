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


def split_value(field):
    """Split a trailing printed value off a tag-name field.

    openssl annotates a value it cannot print as text with [HEX DUMP] and
    writes the value after a colon. We print the hex after a colon with no
    annotation, and print nothing at all for a type whose value we do not
    decode yet. None means "no value printed", which is not the same as an
    empty value.
    """
    field = field.strip()
    field = field.replace("[HEX DUMP]", "")
    if ":" not in field:
        return field.strip(), None
    name, value = field.split(":", 1)
    return name.strip(), value.strip()


def norm_tag(name):
    """One spelling for a tag name, since the two printers differ."""
    m = re.match(r"^(cont|appl|priv)\s*\[\s*(\d+)\s*\]$", name)
    if m:
        return "%s%s" % (m.group(1), m.group(2))
    m = re.match(r"^\[(cont|appl|priv) (\d+)\]$", name)
    if m:
        return "%s%s" % (m.group(1), m.group(2))
    return name.strip()


_oid_cache = {}


def openssl_renders_oid_as(dotted):
    """What openssl prints for this OID, asked of openssl itself.

    --asn1 prints dotted decimal, asn1parse prints openssl's own name for an
    OID it knows. Rather than copying openssl's name table into certlint,
    the dotted value we printed is handed back to openssl and the rendering
    it chooses is what gets compared. A wrong OID therefore fails here even
    when both printers would agree on the shape of the line.
    """
    if dotted in _oid_cache:
        return _oid_cache[dotted]
    r = subprocess.run(
        ["openssl", "asn1parse", "-genstr", "OID:" + dotted],
        capture_output=True, text=True,
    )
    out = dotted
    if r.returncode == 0 and ":" in r.stdout:
        out = r.stdout.split(":", 2)[-1].strip()
        # The line is "0:d=0  hl=2 l=9 prim: OBJECT  :name"; take the text
        # after the last colon on the first line.
        out = r.stdout.splitlines()[0].rsplit(":", 1)[-1].strip()
    _oid_cache[dotted] = out
    return out


def parse(text, rx):
    out = []
    for line in text.splitlines():
        m = rx.match(line)
        if not m:
            continue
        name, value = split_value(m.group(6))
        out.append(
            (
                int(m.group(1)),
                int(m.group(2)),
                int(m.group(3)),
                int(m.group(4)),
                m.group(5),
                norm_tag(name),
                value,
            )
        )
    return out


def main(argv):
    binary, files = argv[1], argv[2:]
    bad = 0
    tlvs = 0
    compared = [0]
    oids = [0]
    skipped = {}
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
        a = [list(x) for x in a]
        a = [tuple(x) for x in a]
        b = parse(theirs.stdout, OSSL)
        if not b:
            print("    %s: openssl printed no TLV lines" % f)
            bad += 1
            continue
        # Compare the value only where both printers printed one. A type we
        # do not decode yet is counted, not silently skipped.
        for i in range(min(len(a), len(b))):
            if a[i][6] is None and b[i][6] is not None:
                skipped[a[i][5]] = skipped.get(a[i][5], 0) + 1
                a[i] = a[i][:6] + (b[i][6],)
            elif a[i][6] is not None and b[i][6] is not None:
                if a[i][5] == "OBJECT":
                    a[i] = a[i][:6] + (openssl_renders_oid_as(a[i][6]),)
                    oids[0] += 1
                compared[0] += 1
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
    print("    %d of them OBJECT values, each resolved by asking openssl what"
          " it renders that dotted OID as" % oids[0])
    print("    %d printed values compared; %s"
          % (compared[0],
             ", ".join("%d %s not decoded by us" % (n, t)
                       for t, n in sorted(skipped.items())) or "none skipped"))
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
