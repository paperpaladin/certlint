#!/usr/bin/env python3
"""Check the curve constants against openssl ecparam.

A mistyped digit in a curve parameter gives a verifier that rejects
every signature, which looks exactly like strictness. openssl prints the
parameters of each named curve with -param_enc explicit, so each of ours
is compared against its own.

The three facts after the parameters come from certlint's arithmetic
rather than from openssl: the generator is on the curve, and n*G is the
point at infinity. They are not an outside authority, they are an
internal consistency check, and they are here because they catch a wrong
doubling formula that the parameter comparison cannot see.
"""
import re
import subprocess
import sys


def openssl_params(name):
    r = subprocess.run(
        ["openssl", "ecparam", "-name", name, "-param_enc", "explicit",
         "-text", "-noout"], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    flat = re.sub(r"[ \n:]", "", r.stdout)
    out = {}
    for key, tag in (("p", "Prime"), ("b", "B"), ("n", "Order")):
        m = re.search(tag + r"([0-9a-f]+)", flat)
        if m:
            out[key] = m.group(1).lstrip("0")
    m = re.search(r"Generator\(uncompressed\)04([0-9a-f]+)", flat)
    if m:
        half = len(m.group(1)) // 2
        out["gx"] = m.group(1)[:half].lstrip("0")
        out["gy"] = m.group(1)[half:].lstrip("0")
    return out


def main(argv):
    binary = argv[1]
    out = subprocess.run([binary, "--ec-check"], capture_output=True,
                         text=True, check=True).stdout
    curves = {}
    cur = None
    for line in out.splitlines():
        m = re.match(r"^curve (\S+) (\S+) (\d+) bits", line)
        if m:
            cur = m.group(1)
            curves[cur] = {"oid": m.group(2), "bits": int(m.group(3))}
            continue
        m = re.match(r"^  (\S+(?: \S+)*) (\S+)$", line)
        if m and cur:
            curves[cur][m.group(1)] = m.group(2)
    bad = 0
    n = 0
    for name, ours in sorted(curves.items()):
        theirs = openssl_params(name)
        if theirs is None:
            print("    openssl does not know %s" % name)
            bad += 1
            continue
        for k in ("p", "b", "gx", "gy", "n"):
            n += 1
            if ours.get(k) != theirs.get(k):
                bad += 1
                print("    %s %s: ours %s, openssl %s"
                      % (name, k, ours.get(k), theirs.get(k)))
        for fact, want in (("generator on curve", "true"),
                           ("nG x", "infinity")):
            n += 1
            if ours.get(fact) != want:
                bad += 1
                print("    %s: %s is %s, wanted %s"
                      % (name, fact, ours.get(fact), want))
    print("    %d curve facts over %d curves, %d wrong" % (n, len(curves), bad))
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
