#!/usr/bin/env python3
"""Forge PKCS#1 v1.5 blocks and check that they are refused.

The corpus holds the private keys, so the harness can sign any block it
likes with openssl pkeyutl in raw mode and splice the result into a
certificate in place of its signature. That is the only way to test the
padding check: a bit flipped in a signature changes the whole recovered
block, so it exercises nothing more than "these two strings differ".

Each variant is one deliberate change to the block the signer should have
produced. certlint must refuse every one of them except the control, and
openssl dgst -verify is asked the same question, so a variant openssl
accepts is recorded rather than assumed wrong.
"""
import base64
import hashlib
import os
import re
import subprocess
import sys

SHA256_DI_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
# The same DigestInfo with the NULL parameters left out, which some
# signers emit and which RFC 4055 discourages rather than forbids.
SHA256_DI_NO_NULL = bytes.fromhex("302f300b0609608648016503040201 0420".replace(" ", ""))


def run(cmd, stdin=None):
    return subprocess.run(cmd, input=stdin, capture_output=True)


def der_of(path):
    return run(["openssl", "x509", "-in", path, "-outform", "DER"]).stdout


def pieces(der, work):
    p = os.path.join(work, "f.der")
    open(p, "wb").write(der)
    out = run(["openssl", "asn1parse", "-inform", "DER", "-in", p]).stdout
    rx = re.compile(r"^\s*(\d+):d=(\d+)\s+hl=(\d+) l=\s*(\d+)\s+(cons|prim)")
    tbs = sigoff = siglen = sighl = None
    for line in out.decode("utf-8", "surrogateescape").splitlines():
        m = rx.match(line)
        if not m:
            continue
        off, depth, hl, length = (int(m.group(i)) for i in (1, 2, 3, 4))
        if depth == 1 and tbs is None:
            tbs = der[off:off + hl + length]
        if depth == 1 and "BIT STRING" in line:
            sigoff, sighl, siglen = off, hl, length
    return tbs, sigoff, sighl, siglen


def pem(der):
    b = base64.b64encode(der)
    return (b"-----BEGIN CERTIFICATE-----\n"
            + b"\n".join(b[i:i + 64] for i in range(0, len(b), 64))
            + b"\n-----END CERTIFICATE-----\n")


def raw_sign(key, block, work):
    """The textbook RSA operation on a block of our choosing.

    openssl will not do this any more: pkeyutl with
    rsa_padding_mode:none refuses an input longer than a digest, and
    rsautl -raw is deprecated. python has arbitrary-precision integers
    and cryptography will hand over the private exponent, so the
    exponentiation is done here.
    """
    from cryptography.hazmat.primitives import serialization
    k = serialization.load_pem_private_key(open(key, "rb").read(), None)
    n = k.private_numbers().public_numbers.n
    d = k.private_numbers().d
    m = int.from_bytes(block, "big")
    size = (n.bit_length() + 7) // 8
    return pow(m, d, n).to_bytes(size, "big")


def variants(tbs, k):
    """(name, block, should_be_valid)."""
    digest = hashlib.sha256(tbs).digest()
    di = SHA256_DI_PREFIX + digest

    def block(di_bytes, ps_byte=0xFF, first=b"\x00\x01", pslen=None):
        n = k - len(di_bytes) - len(first) - 1 if pslen is None else pslen
        return first + bytes([ps_byte]) * n + b"\x00" + di_bytes

    out = [("control", block(di), True)]
    bad = bytearray(di)
    bad[-1] ^= 0x01
    out.append(("last byte of the digest changed", block(bytes(bad)), False))
    b = bytearray(block(di))
    b[10] = 0xFE
    out.append(("one padding octet is 0xfe", bytes(b), False))
    b = bytearray(block(di))
    b[1] = 0x02
    out.append(("block type 2 rather than 1", bytes(b), False))
    out.append(("DigestInfo without the NULL parameters",
                block(SHA256_DI_NO_NULL + digest), False))
    out.append(("a trailing octet after the DigestInfo",
                block(di + b"\x00", pslen=k - len(di) - 4) + b"",
                False))
    short = b"\x00\x01" + b"\xff" * 7 + b"\x00" * (k - len(di) - 10) + b"\x00" + di
    out.append(("only seven padding octets", short[:k], False))
    return out


def main(argv):
    binary, work, cert, issuer, key = argv[1:6]
    der = der_of(cert)
    tbs, sigoff, sighl, siglen = pieces(der, work)
    k = siglen - 1
    bad = 0
    n = 0
    for name, block, want_valid in variants(tbs, k):
        if len(block) != k:
            print("    harness error: %s block is %d octets, wanted %d"
                  % (name, len(block), k))
            bad += 1
            continue
        sig = raw_sign(key, block, work)
        forged = der[:sigoff + sighl + 1] + sig + der[sigoff + sighl + siglen:]
        path = os.path.join(work, "forged.pem")
        open(path, "wb").write(pem(forged))
        r = run([binary, "--sig", path, "--ca", issuer])
        got = b"signature = valid" in r.stdout
        # Ask openssl the same question.
        open(os.path.join(work, "tbs.bin"), "wb").write(tbs)
        open(os.path.join(work, "sig.bin"), "wb").write(sig)
        pub = run(["openssl", "x509", "-in", issuer, "-pubkey", "-noout"]).stdout
        open(os.path.join(work, "pub.pem"), "wb").write(pub)
        ossl = run(["openssl", "dgst", "-sha256", "-verify",
                    os.path.join(work, "pub.pem"), "-signature",
                    os.path.join(work, "sig.bin"),
                    os.path.join(work, "tbs.bin")]).returncode == 0
        n += 1
        tag = "accepts" if ossl else "refuses"
        if got != want_valid:
            bad += 1
            print("    %s: certlint %s, wanted %s (openssl %s)"
                  % (name, "accepts" if got else "refuses",
                     "accept" if want_valid else "refuse", tag))
        elif got != ossl:
            print("    noted: %s: certlint %s and openssl %s"
                  % (name, "accepts" if got else "refuses", tag))
    print("    %d forged PKCS#1 v1.5 blocks, %d handled wrongly" % (n, bad))
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
