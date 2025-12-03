#!/usr/bin/env python3
"""Check the dotted OIDs certlint knows by name are well formed.

Nothing here checks the names: those are the RFC spellings and no oracle on
this machine holds them. What two outside parsers can say is whether each
dotted string is an object identifier at all and whether it encodes the way
we think, so each one is handed to openssl and to python cryptography.
"""
import subprocess
import sys

from cryptography.x509.oid import ObjectIdentifier


def main(argv):
    binary = argv[1]
    dotted = subprocess.run(
        [binary, "--oid-table"], capture_output=True, text=True, check=True
    ).stdout.split()
    bad = 0
    seen = {}
    for d in dotted:
        if d in seen:
            print("    duplicate entry %s" % d)
            bad += 1
        seen[d] = 1
        try:
            if ObjectIdentifier(d).dotted_string != d:
                print("    cryptography normalises %s differently" % d)
                bad += 1
        except Exception as e:
            print("    cryptography rejects %s: %s" % (d, e))
            bad += 1
        r = subprocess.run(
            ["openssl", "asn1parse", "-genstr", "OID:" + d],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            print("    openssl will not encode %s" % d)
            bad += 1
    print("    %d OIDs in the table, %d rejected by openssl or cryptography"
          % (len(dotted), bad))
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
