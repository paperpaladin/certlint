#!/usr/bin/env python3
"""Check --lint against the same rules written over a different parser.

There is no Baseline Requirements linter on this machine: zlint is not
installed, the Ruby certlint is not installed, and nothing may be
downloaded. So this is not an oracle for the rules. What it is, is a
second implementation of each rule reading python cryptography's parse
of the same bytes, which catches the failure that matters most: a rule
firing on a value certlint got wrong, or not firing because certlint
read the field as something else.

Two further checks keep the first one from going vacuous. Every field a
finding names has to exist in --dump, and every --dump field is already
compared against openssl, certtool and cryptography. And the number of
corpus certificates that reach each rule is printed, so a rule nothing
reaches is visible rather than being a line in a passing suite.

Certificates cryptography will not parse are refusals, counted on their
own line and never folded into the agreement figure.
"""
import os
import subprocess
import sys
import warnings

from cryptography import x509
from cryptography.x509.oid import ExtensionOID


def serial_octets(s):
    """How many octets DER needs for this INTEGER."""
    if s == 0:
        return 1
    if s > 0:
        return (s.bit_length() // 8) + 1
    k = 1
    while s < -(1 << (8 * k - 1)):
        k += 1
    return k


def time_encodings(path):
    """How the two validity times were encoded, from openssl asn1parse.

    cryptography hands back a datetime and throws the encoding away, and
    RFC 5280 4.1.2.5 is a rule about the encoding. asn1parse is the
    third oracle here and the only one that can see it.
    """
    r = subprocess.run(["openssl", "asn1parse", "-in", path],
                       capture_output=True)
    out = []
    for line in r.stdout.decode("utf-8", "surrogateescape").splitlines():
        for tag in ("UTCTIME", "GENERALIZEDTIME"):
            if " " + tag + " " in line or line.rstrip().endswith(tag):
                out.append(tag)
    return out[:2]


def expected(c, path):
    """The findings these rules produce, read off cryptography's parse."""
    out = set()
    s = c.serial_number
    if s < 0:
        out.add("serial_negative")
    elif s == 0:
        out.add("serial_zero")
    if serial_octets(s) > 20:
        out.add("serial_too_long")
    if s >= 0 and s.bit_length() < 64:
        out.add("serial_short")

    nb = c.not_valid_before_utc
    na = c.not_valid_after_utc
    span = int((na - nb).total_seconds())
    try:
        bc = c.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value
        ca = bc.ca
    except x509.ExtensionNotFound:
        ca = False
    if span < 0:
        out.add("validity_inverted")
    elif not ca and span > 398 * 86400:
        out.add("validity_too_long")
    enc = time_encodings(path)
    want = ["UTCTIME" if t.year < 2050 else "GENERALIZEDTIME"
            for t in (nb, na)]
    if len(enc) == 2 and enc != want:
        out.add("validity_encoding")
    return out


def ours(binary, path):
    r = subprocess.run([binary, "--all", path], capture_output=True)
    out = r.stdout.decode("utf-8", "surrogateescape")
    codes = set()
    fields = {}
    dumped = set()
    for line in out.splitlines():
        if line.startswith("finding = "):
            parts = line[len("finding = "):].split(" ", 3)
            codes.add(parts[1])
            fields[parts[1]] = parts[2]
        elif " = " in line:
            dumped.add(line.split(" = ", 1)[0])
    return codes, fields, dumped, r.returncode


def main(argv):
    binary = argv[1]
    files = argv[2:]
    bad = 0
    n = 0
    refused = 0
    warned = 0
    reached = {}
    for path in sorted(files):
        try:
            # cryptography warns rather than refuses on some of these and
            # says it will refuse in a later release. A warning from an
            # oracle is a result: it is printed, not filtered out.
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                with open(path, "rb") as fh:
                    der = fh.read()
                c = x509.load_pem_x509_certificate(der)
                want = expected(c, path)
            for w in caught:
                if issubclass(w.category, ResourceWarning):
                    continue
                print("    ORACLE WARNED %s: %s"
                      % (os.path.basename(path), str(w.message)[:70]))
                warned += 1
        except Exception as e:
            refused += 1
            print("    ORACLE REFUSED %s: %s" % (os.path.basename(path),
                                                 str(e)[:70]))
            continue
        got, fields, dumped, rc = ours(binary, path)
        n += 1
        for code in got:
            reached[code] = reached.get(code, 0) + 1
        if got != want:
            bad += 1
            print("    %s: certlint %s, the rules over cryptography %s"
                  % (os.path.basename(path),
                     sorted(got) or ["nothing"], sorted(want) or ["nothing"]))
        for code, field in sorted(fields.items()):
            if field not in dumped:
                bad += 1
                print("    %s: finding %s names field %s, which --dump does "
                      "not print" % (os.path.basename(path), code, field))
        if rc not in (0, 4):
            bad += 1
            print("    %s: --all exited %d" % (os.path.basename(path), rc))
    print("    %d certificates linted, %d disagreed, %d refused by "
          "cryptography, %d warnings from it" % (n, bad, refused, warned))
    print("    rules reached by the corpus: %d (%s)"
          % (len(reached),
             " ".join("%s=%d" % kv for kv in sorted(reached.items()))))
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
