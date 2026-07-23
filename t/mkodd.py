#!/usr/bin/env python3
"""Build the certificates openssl will not emit.

openssl 3.5 adds a subjectKeyIdentifier to anything it signs, so there is
no way to ask it for a version 1 certificate; it will not encode a
PrintableString outside the alphabet, a T61String of our choosing, or an
RDN whose SET is out of DER order. Those are exactly the encodings a
decoder gets wrong, so they are written here, byte by byte, and signed
with openssl so that the result is a real certificate rather than a blob
that only the parser under test will look at.

Standard library only. The DER written here is deliberately independent of
certlint's decoder: a generator that shares code with the thing it tests
proves nothing.

Files named refuse-* are expected to be refused by certlint. The suite
checks that they are, and records what each oracle does with them.
"""
import os
import subprocess
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def tlv(tag, body):
    return bytes([tag]) + enc_len(len(body)) + body


def long_len_tlv(tag, body):
    """A TLV whose length carries one more octet than it needs.

    DER says the length is the shortest form that fits, so a leading zero
    octet in the length is an encoding error even though the value it
    encodes is the same.
    """
    n = len(body)
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    b.insert(0, 0)
    return bytes([tag, 0x80 | len(b)]) + bytes(b) + body


def seq(*xs):
    return tlv(0x30, b"".join(xs))


def setof(*xs):
    return tlv(0x31, b"".join(xs))


def ctx(n, body, constructed=True):
    return tlv((0xA0 if constructed else 0x80) | n, body)


def oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.insert(0, 0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(chunk)
    return tlv(0x06, body)


def integer(n):
    if n == 0:
        return tlv(0x02, b"\x00")
    neg = n < 0
    if neg:
        n = -n
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    if neg:
        v = int.from_bytes(bytes(b), "big")
        size = len(b) + (1 if b[0] & 0x80 else 0)
        v = (1 << (8 * size)) - v
        b = list(v.to_bytes(size, "big"))
    elif b[0] & 0x80:
        b.insert(0, 0)
    return tlv(0x02, bytes(b))


def raw_integer(body):
    return tlv(0x02, body)


def utf8(s):
    return tlv(0x0C, s.encode())


def printable(s):
    return tlv(0x13, s.encode())


def t61(raw):
    return tlv(0x14, raw)


def bmp(s):
    return tlv(0x1E, s.encode("utf-16-be"))


def universal(s):
    return tlv(0x1C, s.encode("utf-32-be"))


def utc(s):
    return tlv(0x17, s.encode())


def octets(b):
    return tlv(0x04, b)


def bitstring(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)


def boolean(v, raw=None):
    return tlv(0x01, bytes([raw if raw is not None else (0xFF if v else 0x00)]))


def atv(type_oid, value):
    return seq(oid(type_oid), value)


def rdn(*atvs):
    return setof(*atvs)


CN = "2.5.4.3"
O = "2.5.4.10"
OU = "2.5.4.11"
C = "2.5.4.6"
SHA256_RSA = "1.2.840.113549.1.1.11"


def name(*rdns):
    return seq(*rdns)


def simple_name(cn):
    return name(rdn(atv(C, printable("GB"))),
                rdn(atv(O, utf8("certlint"))),
                rdn(atv(CN, utf8(cn))))


def extension(dotted, value_der, critical=None):
    parts = [oid(dotted)]
    if critical is not None:
        parts.append(critical)
    parts.append(octets(value_der))
    return seq(*parts)


def run(cmd, stdin=None):
    r = subprocess.run(cmd, input=stdin, capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode("utf-8", "replace"))
        raise SystemExit("mkodd: %s failed" % " ".join(cmd))
    return r.stdout


def spki_of(keyfile):
    return run(["openssl", "pkey", "-in", keyfile, "-pubout", "-outform", "DER"])


def sign(tbs, cakey):
    return run(["openssl", "dgst", "-sha256", "-sign", cakey], stdin=tbs)


def build(path, subject, keyfile, cakey, caname,
          version=None, serial=None, exts=None, not_before=b"250101000000Z",
          not_after=b"350101000000Z", outer_long_len=False, time_tag=0x17):
    parts = []
    if version is not None:
        parts.append(ctx(0, integer(version)))
    parts.append(serial if serial is not None else integer(0x3039))
    alg = seq(oid(SHA256_RSA), tlv(0x05, b""))
    parts.append(alg)
    parts.append(caname)
    parts.append(seq(tlv(time_tag, not_before), tlv(time_tag, not_after)))
    parts.append(subject)
    parts.append(spki_of(keyfile))
    if exts:
        parts.append(ctx(3, seq(*exts)))
    tbs = seq(*parts)
    sig = sign(tbs, cakey)
    body = tbs + alg + bitstring(sig)
    der = long_len_tlv(0x30, body) if outer_long_len else tlv(0x30, body)
    with open(os.path.join(OUT, path), "wb") as f:
        f.write(b"-----BEGIN CERTIFICATE-----\n")
        import base64
        b = base64.b64encode(der)
        for i in range(0, len(b), 64):
            f.write(b[i:i + 64] + b"\n")
        f.write(b"-----END CERTIFICATE-----\n")
    return der


def main():
    cakey = os.path.join(OUT, "inter-rsa.key")
    cacert = os.path.join(OUT, "inter-rsa.pem")
    keyfile = os.path.join(OUT, "leaf-rsa.key")
    # The issuer name has to be the CA's subject byte for byte or nothing
    # will chain, so it is taken from the CA certificate.
    caname = subject_der_of(cacert)

    bc_leaf = extension("2.5.29.19", seq(), critical=boolean(True))
    san = extension("2.5.29.17", seq(ctx(2, b"odd.example.com", False)))

    made = []
    # A version 1 certificate: no version field at all, no extensions.
    build("v1.pem", simple_name("version one"), keyfile, cakey, caname)
    made.append("v1.pem")

    # The version field present and spelled v1, which DER forbids because
    # v1 is the DEFAULT.
    build("version-redundant.pem", simple_name("redundant version"),
          keyfile, cakey, caname, version=0)
    made.append("version-redundant.pem")

    # Three DirectoryString encodings openssl will not choose on request.
    build("dn-t61.pem",
          name(rdn(atv(C, printable("GB"))),
               rdn(atv(CN, t61(b"Caf\xe9 Ltd")))),
          keyfile, cakey, caname, version=2, exts=[bc_leaf, san])
    made.append("dn-t61.pem")
    build("dn-bmp.pem",
          name(rdn(atv(C, printable("GB"))),
               rdn(atv(CN, bmp("Café Ltd")))),
          keyfile, cakey, caname, version=2, exts=[bc_leaf, san])
    made.append("dn-bmp.pem")
    build("dn-universal.pem",
          name(rdn(atv(C, printable("GB"))),
               rdn(atv(CN, universal("Café Ltd")))),
          keyfile, cakey, caname, version=2, exts=[bc_leaf, san])
    made.append("dn-universal.pem")

    # A multi-valued RDN, in DER order and out of it. The two attributes
    # are in one SET, so the certificate means the same thing either way
    # and only the encoding differs.
    a = atv(CN, utf8("multi value"))
    b = atv(OU, utf8("Testing"))
    lo, hi = (a, b) if a < b else (b, a)
    build("dn-multivalue.pem",
          name(rdn(atv(C, printable("GB"))), rdn(lo, hi)),
          keyfile, cakey, caname, version=2, exts=[bc_leaf, san])
    made.append("dn-multivalue.pem")
    build("dn-set-unordered.pem",
          name(rdn(atv(C, printable("GB"))), rdn(hi, lo)),
          keyfile, cakey, caname, version=2, exts=[bc_leaf, san])
    made.append("dn-set-unordered.pem")

    # Encodings certlint refuses. Each is one byte away from a certificate
    # it accepts.
    build("refuse-serial-nonminimal.pem", simple_name("non-minimal serial"),
          keyfile, cakey, caname, version=2,
          serial=raw_integer(b"\x00\x30\x39"), exts=[bc_leaf, san])
    made.append("refuse-serial-nonminimal.pem")
    build("refuse-critical-one.pem", simple_name("critical is one"),
          keyfile, cakey, caname, version=2,
          exts=[extension("2.5.29.19", seq(), critical=boolean(True, raw=0x01)),
                san])
    made.append("refuse-critical-one.pem")
    # A GeneralizedTime for a date before 2050. RFC 5280 4.1.2.5 says
    # dates through 2049 are UTCTime and openssl will not write anything
    # else, so this one has to be built by hand. Both oracles parse it.
    build("time-generalized-early.pem", simple_name("generalized before 2050"),
          keyfile, cakey, caname, version=2, exts=[bc_leaf, san],
          time_tag=0x18, not_before=b"20250101000000Z",
          not_after=b"20350101000000Z")
    made.append("time-generalized-early.pem")

    # notBefore after notAfter. openssl x509 -req will not emit one.
    build("time-inverted.pem", simple_name("inverted validity"),
          keyfile, cakey, caname, version=2, exts=[bc_leaf, san],
          not_before=b"350101000000Z", not_after=b"250101000000Z")
    made.append("time-inverted.pem")

    # Extensions in a certificate with no version field, which makes it
    # version 1. RFC 5280 4.1.2.9 allows extensions in version 3 only, and
    # certlint refuses it at the parser. So does certtool; openssl and
    # python cryptography both parse it and report version 1.
    build("refuse-v1-extensions.pem", simple_name("version one with extensions"),
          keyfile, cakey, caname, exts=[bc_leaf, san])
    made.append("refuse-v1-extensions.pem")

    # An attribute whose value is the empty string. openssl drops an
    # empty component from -subj rather than encoding one.
    build("subject-empty-value.pem",
          name(rdn(atv(C, printable("GB"))),
               rdn(atv(O, printable(""))),
               rdn(atv(CN, printable("empty.example.com")))),
          keyfile, cakey, caname, version=2,
          exts=[bc_leaf,
                extension("2.5.29.17",
                          seq(ctx(2, b"empty.example.com", False)))])
    made.append("subject-empty-value.pem")

    # An iPAddress that is neither four nor sixteen octets. openssl will
    # not encode one: it parses the text as an address first.
    build("ip-bad-length.pem", simple_name("five octet address"),
          keyfile, cakey, caname, version=2,
          exts=[bc_leaf,
                extension("2.5.29.17", seq(ctx(7, b"\x01\x02\x03\x04\x05",
                                               False)))])
    made.append("ip-bad-length.pem")

    # The same extension twice, which RFC 5280 4.2 forbids.
    build("ext-duplicate.pem", simple_name("duplicate extension"),
          keyfile, cakey, caname, version=2, exts=[bc_leaf, san, san])
    made.append("ext-duplicate.pem")

    build("refuse-length-nonminimal.pem", simple_name("long form length"),
          keyfile, cakey, caname, version=2, exts=[bc_leaf, san],
          outer_long_len=True)
    made.append("refuse-length-nonminimal.pem")

    print("mkodd: %d hand-built certificates" % len(made))


def subject_der_of(path):
    """The subject Name of a certificate, as the bytes it was encoded in."""
    der = run(["openssl", "x509", "-in", path, "-outform", "DER"])
    # Walk the TBS to the sixth field. Minimal reader, enough for a
    # certificate openssl wrote.
    def read(buf, i):
        tag = buf[i]
        i += 1
        n = buf[i]
        i += 1
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(buf[i:i + k], "big")
            i += k
        return tag, buf[i:i + n], i + n
    _, cert, _ = read(der, 0)
    _, tbs, _ = read(cert, 0)
    i = 0
    tag, _, j = read(tbs, i)
    if tag == 0xA0:            # version
        i = j
    _, _, i = read(tbs, i)     # serial
    _, _, i = read(tbs, i)     # signature
    start = i
    _, _, i = read(tbs, i)     # issuer
    _, _, i = read(tbs, i)     # validity
    start = i
    _, _, end = read(tbs, i)   # subject
    return tbs[start:end]


if __name__ == "__main__":
    main()
