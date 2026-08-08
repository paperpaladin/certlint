#!/usr/bin/env python3
"""Truncate and corrupt certificates, and require a diagnostic each time.

A certificate is attacker-controlled input in every program that reads
one, so the property here is not that certlint gets the right answer, it
is that it always gives an answer. For every mutated file: exit status 0
or 1 and nothing else, no panic message on stderr, and a one-line
diagnostic whenever the status is 1.

The accept-or-refuse decision is compared against openssl x509 -text on
the same bytes. That comparison is reported and not asserted, because
the two are entitled to differ on a BER-ish input: openssl is lenient
where certlint is strict, and the counts say by how much rather than
hiding it. What is asserted is the crash-freedom, and that the sweep
actually moved something, since a corruption sweep whose mutations all
land in the signature bytes proves nothing about the parser.
"""
import os
import random
import subprocess
import sys


def run(cmd, data):
    r = subprocess.run(cmd, input=data, capture_output=True)
    return r.returncode, r.stderr.decode("utf-8", "replace")


def main(argv):
    binary, work = argv[1], argv[2]
    files = argv[3:]
    tmp = os.path.join(work, "corrupt.der")
    panics = 0
    badstatus = 0
    silent = 0
    n = 0
    refused = 0
    accepted = 0
    split = 0
    for path in sorted(files):
        der = subprocess.run(["openssl", "x509", "-in", path, "-outform",
                              "DER"], capture_output=True).stdout
        if not der:
            continue
        rnd = random.Random(20261020 ^ len(der))
        cases = []
        # Every truncation in the header region, where the length octets
        # and the outer structure live, then a sample of the rest.
        cases += [der[:i] for i in range(0, min(len(der), 64))]
        cases += [der[:i] for i in range(64, len(der), 17)]
        # Single bit flips, spread over the whole file.
        for _ in range(100):
            i = rnd.randrange(len(der))
            b = bytearray(der)
            b[i] ^= 1 << rnd.randrange(8)
            cases.append(bytes(b))
        # A length octet set to something enormous, which is the shape
        # that turns a reader into an out-of-bounds read.
        for i in range(1, min(len(der), 24)):
            b = bytearray(der)
            b[i] = 0x7F
            cases.append(bytes(b))
        for case in cases:
            with open(tmp, "wb") as f:
                f.write(case)
            n += 1
            dumprc = None
            # --lint exits 4 for an error-level finding, which is a
            # verdict and not a failure to cope.
            for mode, allowed in (("--asn1", (0, 1)), ("--dump", (0, 1)),
                                  ("--lint", (0, 1, 4))):
                rc, err = run([binary, mode, tmp], b"")
                if mode == "--dump":
                    dumprc = rc
                if "panicked" in err or rc < 0 or rc > 128:
                    panics += 1
                    print("    PANIC %s %s on a %d byte case: %s"
                          % (os.path.basename(path), mode, len(case),
                             err.strip().splitlines()[:1]))
                    break
                if rc not in allowed:
                    badstatus += 1
                    print("    %s %s exited %d on a %d byte case"
                          % (os.path.basename(path), mode, rc, len(case)))
                    break
                if rc == 1 and not err.strip():
                    silent += 1
                    print("    %s %s refused a %d byte case and said nothing"
                          % (os.path.basename(path), mode, len(case)))
                    break
            ok = dumprc == 0
            orc = subprocess.run(["openssl", "x509", "-inform", "DER", "-in",
                                  tmp, "-noout", "-text"],
                                 capture_output=True).returncode
            if ok:
                accepted += 1
            else:
                refused += 1
            if ok != (orc == 0):
                split += 1
    bad = panics + badstatus + silent
    print("    %d mutated certificates, %d accepted, %d refused with a "
          "diagnostic" % (n, accepted, refused))
    print("    %d of them where openssl x509 -text and certlint differ on "
          "accept or refuse" % split)
    if accepted == 0 or refused == 0:
        print("    the sweep only ever got one answer, so it is not "
              "exercising the parser")
        bad += 1
    print("    %d panics, %d exit statuses the mode cannot produce, %d "
          "silent refusals" % (panics, badstatus, silent))
    try:
        os.unlink(tmp)
    except OSError:
        pass
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
