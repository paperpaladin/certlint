#!/usr/bin/env python3
"""Compare certlint's signature verdicts against openssl dgst -verify.

For each corpus certificate, every other corpus certificate whose subject
matches its issuer is tried as the signer. The oracle is openssl: the
bytes under the signature and the signature itself are cut out of the DER
using the offsets openssl asn1parse prints, the signer's public key comes
from openssl x509 -pubkey, and openssl dgst -verify answers the same
question certlint was asked.

Every pair is then run again with the last byte of the certificate
flipped, which is always inside the signature value. A verifier that
accepts everything passes a suite made only of valid signatures, so the
flipped run is the half that can fail.
"""
import os
import re
import subprocess
import sys

ALG = {
    "sha1WithRSAEncryption": "sha1",
    "sha256WithRSAEncryption": "sha256",
    "sha384WithRSAEncryption": "sha384",
    "sha512WithRSAEncryption": "sha512",
    "ecdsa-with-SHA1": "sha1",
    "ecdsa-with-SHA256": "sha256",
    "ecdsa-with-SHA384": "sha384",
    "ecdsa-with-SHA512": "sha512",
}


def run(cmd, stdin=None):
    return subprocess.run(cmd, input=stdin, capture_output=True)


def der_of(path):
    r = run(["openssl", "x509", "-in", path, "-outform", "DER"])
    return r.stdout if r.returncode == 0 else None


def pieces(der, work):
    """(tbs, signature), cut out at the offsets openssl asn1parse prints."""
    p = os.path.join(work, "piece.der")
    with open(p, "wb") as f:
        f.write(der)
    r = run(["openssl", "asn1parse", "-inform", "DER", "-in", p])
    if r.returncode != 0:
        return None, None
    lines = r.stdout.decode("utf-8", "surrogateescape").splitlines()
    rx = re.compile(r"^\s*(\d+):d=(\d+)\s+hl=(\d+) l=\s*(\d+)\s+(cons|prim)")
    tbs = sig = None
    for line in lines:
        m = rx.match(line)
        if not m:
            continue
        off, depth, hl, length = (int(m.group(i)) for i in (1, 2, 3, 4))
        if depth == 1 and tbs is None:
            tbs = der[off:off + hl + length]
        if depth == 1 and "BIT STRING" in line:
            sig = der[off + hl + 1:off + hl + length]
    return tbs, sig


def subject_issuer(path):
    out = {}
    for opt in ("-subject", "-issuer"):
        r = run(["openssl", "x509", "-in", path, "-noout", opt,
                 "-nameopt", "RFC2253"])
        if r.returncode != 0:
            return None
        out[opt] = r.stdout.decode("utf-8", "surrogateescape").split("=", 1)[1].strip()
    return out


def sig_alg(path):
    r = run(["openssl", "x509", "-in", path, "-noout", "-text"])
    if r.returncode != 0:
        return None
    m = re.search(r"^\s*Signature Algorithm: (\S+)", r.stdout.decode("utf-8", "surrogateescape"), re.M)
    return ALG.get(m.group(1)) if m else None


def openssl_verify(issuer, tbs, sig, alg, work):
    pub = os.path.join(work, "pub.pem")
    r = run(["openssl", "x509", "-in", issuer, "-pubkey", "-noout"])
    if r.returncode != 0:
        return None
    with open(pub, "wb") as f:
        f.write(r.stdout)
    tf = os.path.join(work, "tbs.bin")
    sf = os.path.join(work, "sig.bin")
    with open(tf, "wb") as f:
        f.write(tbs)
    with open(sf, "wb") as f:
        f.write(sig)
    r = run(["openssl", "dgst", "-" + alg, "-verify", pub, "-signature", sf, tf])
    return r.returncode == 0


def ours(binary, cert, issuer):
    """True, False, None for unsupported, or "refused" for a parse error."""
    r = run([binary, "--sig", cert, "--ca", issuer])
    out = r.stdout.decode("utf-8", "surrogateescape")
    if "signature = valid" in out:
        return True
    if "unsupported" in out:
        return None
    if "signature = invalid" in out:
        return False
    return "refused"


def main(argv):
    binary, work, files = argv[1], argv[2], argv[3:]
    names = {}
    for f in files:
        si = subject_issuer(f)
        if si:
            names[f] = si
    pairs = 0
    bad = 0
    unsupported = 0
    refused = 0
    flipped_ok = 0
    for f in sorted(names):
        for g in sorted(names):
            if names[g]["-subject"] != names[f]["-issuer"]:
                continue
            alg = sig_alg(f)
            if alg is None:
                continue
            der = der_of(f)
            if der is None:
                continue
            tbs, sig = pieces(der, work)
            if tbs is None or sig is None:
                continue
            want = openssl_verify(g, tbs, sig, alg, work)
            if want is None:
                continue
            got = ours(binary, f, g)
            pairs += 1
            if got is None:
                unsupported += 1
                continue
            if got == "refused":
                refused += 1
                continue
            if got != want:
                bad += 1
                print("    %s signed by %s: ours %s, openssl %s"
                      % (os.path.basename(f), os.path.basename(g), got, want))
            # Now with the last byte of the certificate flipped, which is
            # always inside the signature value.
            broken = bytearray(der)
            broken[-1] ^= 0x01
            bf = os.path.join(work, "broken.der")
            with open(bf, "wb") as fh:
                fh.write(bytes(broken))
            tbs2, sig2 = pieces(bytes(broken), work)
            want2 = openssl_verify(g, tbs2, sig2, alg, work)
            got2 = ours(binary, bf, g)
            pairs += 1
            if want2 is not False:
                print("    openssl accepted a flipped signature on %s"
                      % os.path.basename(f))
                bad += 1
            elif got2 is not False:
                print("    certlint accepted a flipped signature on %s"
                      % os.path.basename(f))
                bad += 1
            else:
                flipped_ok += 1
    print("    %d verdicts against openssl dgst -verify, %d disagreed, %d"
          " unsupported by certlint" % (pairs, bad, unsupported))
    print("    %d of them signatures with one bit flipped, rejected by both"
          % flipped_ok)
    if refused:
        print("    %d certificates refused by certlint before any signature"
              " was checked" % refused)
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
