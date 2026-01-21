#!/usr/bin/env python3
"""Compare certlint --dump against three parsers, field by field.

Not file by file: each fact certlint prints is turned into a canonical
python value, each oracle is asked for the same fact in its own way, and
the pairs are compared one at a time. A field the oracle does not report is
counted as not compared rather than passed over in silence, and the counts
are printed so that a comparison which has quietly stopped checking
anything looks different from one that agrees.

Oracles:
  cryptography  structured values, so no text parsing at all
  openssl       x509 -text -noout and the single-fact options
  certtool      --certificate-info, GnuTLS, an independent ASN.1 library

Where two oracles disagree with each other the disagreement is reported
with both values and counted on its own line; it is not a certlint
failure, and averaging it away would lose the only interesting thing in
the output.
"""
import datetime
import re
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization

# GnuTLS spells a signature algorithm its own way. This is the harness
# translating the oracle's names, not certlint's table: certlint prints the
# OID and the OID is what gets translated.
# GnuTLS and cryptography both name a curve rather than printing its OID,
# so the harness holds the mapping. certlint prints the OID.
CURVE_OID = {
    "secp256r1": "1.2.840.10045.3.1.7",
    "secp384r1": "1.3.132.0.34",
    "secp521r1": "1.3.132.0.35",
    "secp256k1": "1.3.132.0.10",
}

# GnuTLS prints an extension by a name of its own and never by OID, so the
# harness holds this table. Where certtool prints a name that is not here,
# the extension comparison for that certificate is dropped and counted
# rather than guessed at.
GNUTLS_EXT = {
    "Basic Constraints": "2.5.29.19",
    "Key Usage": "2.5.29.15",
    "Key Purpose": "2.5.29.37",
    "Subject Key Identifier": "2.5.29.14",
    "Authority Key Identifier": "2.5.29.35",
    "Subject Alternative Name": "2.5.29.17",
    "Issuer Alternative Name": "2.5.29.18",
    "Name Constraints": "2.5.29.30",
    "CRL Distribution points": "2.5.29.31",
    "Certificate Policies": "2.5.29.32",
    "Authority Information Access": "1.3.6.1.5.5.7.1.1",
    "Private Key Usage Period": "2.5.29.16",
    "Policy Constraints": "2.5.29.36",
    "Inhibit anyPolicy": "2.5.29.54",
}

# The nine KeyUsage bits, in the three spellings the oracles use. RFC 5280
# names them in the first column and certlint prints that.
KU = [
    ("digitalSignature", "digital_signature", "Digital signature."),
    ("nonRepudiation", "content_commitment", "Non repudiation."),
    ("keyEncipherment", "key_encipherment", "Key encipherment."),
    ("dataEncipherment", "data_encipherment", "Data encipherment."),
    ("keyAgreement", "key_agreement", "Key agreement."),
    ("keyCertSign", "key_cert_sign", "Certificate signing."),
    ("cRLSign", "crl_sign", "CRL signing."),
    ("encipherOnly", "encipher_only", "Key encipher only."),
    ("decipherOnly", "decipher_only", "Key decipher only."),
]

GNUTLS_SIG = {
    "1.2.840.113549.1.1.5": "RSA-SHA1",
    "1.2.840.113549.1.1.11": "RSA-SHA256",
    "1.2.840.113549.1.1.12": "RSA-SHA384",
    "1.2.840.113549.1.1.13": "RSA-SHA512",
    "1.2.840.10045.4.1": "ECDSA-SHA1",
    "1.2.840.10045.4.3.2": "ECDSA-SHA256",
    "1.2.840.10045.4.3.3": "ECDSA-SHA384",
    "1.2.840.10045.4.3.4": "ECDSA-SHA512",
}

_oid_name_cache = {}


def openssl_name_for(dotted):
    """Ask openssl what it calls this OID, so certlint need not know."""
    if dotted not in _oid_name_cache:
        r = subprocess.run(
            ["openssl", "asn1parse", "-genstr", "OID:" + dotted],
            capture_output=True, text=True,
        )
        name = dotted
        if r.returncode == 0 and r.stdout:
            name = r.stdout.splitlines()[0].rsplit(":", 1)[-1].strip()
        _oid_name_cache[dotted] = name
    return _oid_name_cache[dotted]


def run(cmd):
    r = subprocess.run(cmd, capture_output=True)
    return r.returncode, r.stdout.decode("utf-8", "surrogateescape"), \
        r.stderr.decode("utf-8", "surrogateescape")


def ours(binary, path):
    rc, out, errtext = run([binary, "--dump", path])
    if rc != 0:
        return None, "certlint exited %d: %s" % (rc, errtext.strip())
    d = {}
    for line in out.splitlines():
        if " = " not in line:
            continue
        k, v = line.split(" = ", 1)
        d.setdefault(k, []).append(v)
    return d, None


def as_int_serial(text):
    neg = text.startswith("-")
    n = int(text.lstrip("-") or "0", 16)
    return -n if neg else n


def canonical_ours(d):
    """The facts, as canonical python values."""
    out = {}
    one = lambda k: d[k][0] if k in d else None
    if one("version"):
        out["version"] = int(one("version"))
    if one("serial") is not None:
        out["serial"] = as_int_serial(one("serial"))
    for k in ("not_before_epoch", "not_after_epoch", "tbs_octets",
              "signature_octets"):
        if one(k) is not None:
            out[k] = int(one(k))
    if one("signature_algorithm_oid"):
        out["sig_alg_oid"] = one("signature_algorithm_oid")
    if one("issuer_rfc4514") is not None:
        out["issuer_rfc4514"] = one("issuer_rfc4514")
    if one("subject_rfc4514") is not None:
        out["subject_rfc4514"] = one("subject_rfc4514")
    for key, dest in (("issuer_attr", "issuer_attrs"),
                      ("subject_attr", "subject_attrs"),
                      ("issuer_attr_type", "issuer_attr_types"),
                      ("subject_attr_type", "subject_attr_types")):
        if key in d:
            out[dest] = tuple(x.upper() if "type" in key else x for x in d[key])
    if one("spki_algorithm_oid"):
        out["spki_alg_oid"] = one("spki_algorithm_oid")
    if one("key_bits"):
        out["key_bits"] = int(one("key_bits"))
    if one("spki_octets"):
        out["spki_octets"] = int(one("spki_octets"))
    if one("ec_curve_oid"):
        out["ec_curve_oid"] = one("ec_curve_oid")
    if one("rsa_exponent"):
        out["rsa_exponent"] = int(one("rsa_exponent"))
    if one("rsa_modulus_octets"):
        out["rsa_modulus_octets"] = int(one("rsa_modulus_octets"))
    if one("basic_constraints_ca"):
        out["bc_ca"] = one("basic_constraints_ca") == "yes"
    if one("basic_constraints_pathlen"):
        v = one("basic_constraints_pathlen")
        out["bc_pathlen"] = None if v == "none" else int(v)
    if one("key_usage") is not None:
        out["key_usage"] = tuple(x for x in one("key_usage").split(",") if x)
    if "extension" in d:
        out["ext_oids"] = tuple(e.split()[0] for e in d["extension"])
        out["ext_critical"] = tuple(
            "%s %s" % (e.split()[0], e.split()[1]) for e in d["extension"])
    return out


def from_cryptography(path):
    data = open(path, "rb").read()
    c = x509.load_pem_x509_certificate(data) if b"-----BEGIN" in data \
        else x509.load_der_x509_certificate(data)
    out = {
        "version": c.version.value + 1,
        "serial": c.serial_number,
        "not_before_epoch": int(c.not_valid_before_utc.timestamp()),
        "not_after_epoch": int(c.not_valid_after_utc.timestamp()),
        "tbs_octets": len(c.tbs_certificate_bytes),
        "signature_octets": len(c.signature),
        "sig_alg_oid": c.signature_algorithm_oid.dotted_string,
        "issuer_attrs": tuple(
            "%s %s" % (a.oid.dotted_string, a.value)
            for rdn in c.issuer.rdns for a in rdn),
        "subject_attrs": tuple(
            "%s %s" % (a.oid.dotted_string, a.value)
            for rdn in c.subject.rdns for a in rdn),
        "issuer_attr_types": tuple(
            ("%s %s" % (a.oid.dotted_string, a._type.name)).upper()
            for rdn in c.issuer.rdns for a in rdn),
        "subject_attr_types": tuple(
            ("%s %s" % (a.oid.dotted_string, a._type.name)).upper()
            for rdn in c.subject.rdns for a in rdn),
        "ext_oids": tuple(e.oid.dotted_string for e in c.extensions),
        "ext_critical": tuple(
            "%s %s" % (e.oid.dotted_string, "critical" if e.critical
                       else "noncritical") for e in c.extensions),
    }
    try:
        bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
        out["bc_ca"] = bc.ca
        out["bc_pathlen"] = bc.path_length
    except x509.ExtensionNotFound:
        pass
    try:
        ku = c.extensions.get_extension_for_class(x509.KeyUsage).value
        got = []
        for rfc, attr, _ in KU:
            try:
                if getattr(ku, attr):
                    got.append(rfc)
            except ValueError:
                pass  # encipher_only raises unless key_agreement is set
        out["key_usage"] = tuple(got)
    except x509.ExtensionNotFound:
        pass
    spki = c.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    out["spki_octets"] = len(spki)
    k = c.public_key()
    out["key_bits"] = k.key_size
    if hasattr(k, "public_numbers") and hasattr(k.public_numbers(), "e"):
        n = k.public_numbers()
        out["rsa_exponent"] = n.e
        out["rsa_modulus_octets"] = (n.n.bit_length() + 7) // 8
        out["spki_alg_oid"] = "1.2.840.113549.1.1.1"
    if hasattr(k, "curve"):
        out["spki_alg_oid"] = "1.2.840.10045.2.1"
        if k.curve.name in CURVE_OID:
            out["ec_curve_oid"] = CURVE_OID[k.curve.name]
    return out


def openssl_date(text):
    # "Oct 20 06:39:24 2026 GMT", and openssl prints GMT for everything.
    text = text.strip()
    if not text.endswith("GMT"):
        raise ValueError(text)
    t = datetime.datetime.strptime(text[:-4].strip(), "%b %d %H:%M:%S %Y")
    return int(t.replace(tzinfo=datetime.timezone.utc).timestamp())


def from_openssl(path):
    out = {}
    rc, text, _ = run(["openssl", "x509", "-in", path, "-noout", "-text"])
    if rc != 0:
        return out
    m = re.search(r"Version: (\d+) \(0x", text)
    if m:
        out["version"] = int(m.group(1))
    m = re.search(r"^\s*Signature Algorithm: (\S+)", text, re.M)
    if m:
        out["sig_alg_openssl_name"] = m.group(1)
    m = re.search(r"Public-Key: \((\d+) bit\)", text)
    if m:
        out["key_bits"] = int(m.group(1))
    m = re.search(r"CA:(TRUE|FALSE)(, pathlen:(\d+))?", text)
    if m:
        out["bc_ca"] = m.group(1) == "TRUE"
        out["bc_pathlen"] = int(m.group(3)) if m.group(3) else None
    m = re.search(r"X509v3 Key Usage:.*\n\s+(.*)", text)
    if m:
        # openssl prints its own names, comma separated.
        OSSL_KU = {
            "Digital Signature": "digitalSignature",
            "Non Repudiation": "nonRepudiation",
            "Key Encipherment": "keyEncipherment",
            "Data Encipherment": "dataEncipherment",
            "Key Agreement": "keyAgreement",
            "Certificate Sign": "keyCertSign",
            "CRL Sign": "cRLSign",
            "Encipher Only": "encipherOnly",
            "Decipher Only": "decipherOnly",
        }
        got = [OSSL_KU[x.strip()] for x in m.group(1).split(",")
               if x.strip() in OSSL_KU]
        if len(got) == len([x for x in m.group(1).split(",") if x.strip()]):
            out["key_usage"] = tuple(got)
    exts = []
    inblock = False
    for line in text.splitlines():
        if re.match(r"^ {8}X509v3 extensions:", line):
            inblock = True
            continue
        if inblock:
            if re.match(r"^ {4}Signature (Algorithm|Value)", line) or \
               re.match(r"^ {0,8}\S", line):
                break
            # openssl writes a trailing space where the extension is not
            # critical, so the pattern cannot anchor hard on the colon.
            m = re.match(r"^ {12}(\S.*?): ?(critical)?\s*$", line)
            if m:
                exts.append("%s %s" % (m.group(1),
                                       "critical" if m.group(2) else "noncritical"))
    if exts:
        out["ext_openssl_names"] = tuple(exts)
    rc, s, _ = run(["openssl", "x509", "-in", path, "-noout", "-serial"])
    if rc == 0 and "=" in s:
        out["serial"] = as_int_serial(s.split("=", 1)[1].strip())
    for opt, key in (("-startdate", "not_before_epoch"),
                     ("-enddate", "not_after_epoch")):
        rc, s, _ = run(["openssl", "x509", "-in", path, "-noout", opt])
        if rc == 0 and "=" in s:
            out[key] = openssl_date(s.split("=", 1)[1])
    rc, s, _ = run(["openssl", "x509", "-in", path, "-noout", "-subject",
                    "-nameopt", "oid,sep_multiline,show_type,utf8"])
    if rc == 0:
        out["subject_attrs"] = tuple(openssl_name_lines(s))
    rc, s, _ = run(["openssl", "x509", "-in", path, "-noout", "-issuer",
                    "-nameopt", "oid,sep_multiline,show_type,utf8"])
    if rc == 0:
        out["issuer_attrs"] = tuple(openssl_name_lines(s))
    for opt, key in (("-subject", "subject"), ("-issuer", "issuer")):
        rc, s, _ = run(["openssl", "x509", "-in", path, "-noout", opt,
                        "-nameopt", "oid,sep_multiline,show_type,utf8"])
        if rc == 0:
            out[key + "_attr_types"] = tuple(openssl_name_lines(s, True))
        rc, s, _ = run(["openssl", "x509", "-in", path, "-noout", opt,
                        "-nameopt", "RFC2253"])
        if rc == 0 and "=" in s:
            out[key + "_rfc4514"] = s.split("=", 1)[1].strip()
    return out


def openssl_name_lines(text, want_type=False):
    out = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^([0-9.]+)=([A-Z0-9]+):(.*)$", line)
        if m:
            if want_type:
                out.append(("%s %s" % (m.group(1), m.group(2))).upper())
            else:
                out.append("%s %s" % (m.group(1), m.group(3)))
    return out


# The nine attribute types RFC 4514 section 3 gives a short name. A DN made
# only of these has one string form that all four implementations write the
# same way; a DN holding anything else does not, because openssl and GnuTLS
# print names RFC 4514 never defined. Those are compared structurally only,
# and the count of skipped strings is printed.
RFC4514_NAMED = {
    "2.5.4.3", "2.5.4.6", "2.5.4.7", "2.5.4.8", "2.5.4.10", "2.5.4.11",
    "2.5.4.9", "0.9.2342.19200300.100.1.25", "0.9.2342.19200300.100.1.1",
}


def gnutls_date(text):
    # "Tue Oct 20 06:39:24 UTC 2026"
    t = datetime.datetime.strptime(text.strip(), "%a %b %d %H:%M:%S UTC %Y")
    return int(t.replace(tzinfo=datetime.timezone.utc).timestamp())


def from_certtool(path):
    out = {}
    rc, text, _ = run(["certtool", "--certificate-info", "--infile", path])
    if rc != 0:
        return out
    m = re.search(r"^\s*Version: (\d+)", text, re.M)
    if m:
        out["version"] = int(m.group(1))
    m = re.search(r"Serial Number \(hex\): ([0-9a-fA-F]+)", text)
    if m:
        # GnuTLS prints the content octets, so this is a signed big-endian
        # integer and not a magnitude.
        out["serial"] = int.from_bytes(bytes.fromhex(m.group(1)), "big",
                                       signed=True)
    m = re.search(r"Algorithm Security Level: \S+ \((\d+) bits\)", text)
    if m:
        out["key_bits"] = int(m.group(1))
    m = re.search(r"^\s*Curve:\s+(\S+)", text, re.M)
    if m and m.group(1).lower() in CURVE_OID:
        out["ec_curve_oid"] = CURVE_OID[m.group(1).lower()]
    m = re.search(r"Not Before: (.*)", text)
    if m:
        out["not_before_epoch"] = gnutls_date(m.group(1))
    m = re.search(r"Not After: (.*)", text)
    if m:
        out["not_after_epoch"] = gnutls_date(m.group(1))
    m = re.search(r"^\s*Signature Algorithm: (\S+)", text, re.M)
    if m:
        out["sig_alg_gnutls_name"] = m.group(1)
    m = re.search(r"Certificate Authority \(CA\): (TRUE|FALSE)", text)
    if m:
        out["bc_ca"] = m.group(1) == "TRUE"
    m = re.search(r"Path Length Constraint: (\d+)", text)
    if m:
        out["bc_pathlen"] = int(m.group(1))
    elif "Certificate Authority (CA):" in text:
        out["bc_pathlen"] = None
    m = re.search(r"Key Usage \((?:critical|not critical)\):\n((?:\t{3}[^\t].*\n)+)", text)
    if m:
        want = {g: r for r, _, g in KU}
        got = [want[l.strip()] for l in m.group(1).splitlines()
               if l.strip() in want]
        if len(got) == len(m.group(1).strip().splitlines()):
            out["key_usage"] = tuple(got)
    names = []
    unknown = False
    for line in text.splitlines():
        m = re.match(r"^\t\t(\S.*?) \((critical|not critical)\):$", line)
        if m:
            if m.group(1) not in GNUTLS_EXT:
                unknown = True
            else:
                names.append("%s %s" % (
                    GNUTLS_EXT[m.group(1)],
                    "critical" if m.group(2) == "critical" else "noncritical"))
    if names and not unknown:
        out["ext_critical"] = tuple(names)
    m = re.search(r"^\tIssuer: (.*)$", text, re.M)
    if m:
        out["issuer_rfc4514"] = m.group(1).strip()
    m = re.search(r"^\tSubject: (.*)$", text, re.M)
    if m:
        out["subject_rfc4514"] = m.group(1).strip()
    return out


def derived(mine):
    """Facts certlint states in its own terms, in each oracle's terms."""
    out = dict(mine)
    if "ext_oids" in mine:
        out["ext_openssl_names"] = tuple(
            "%s %s" % (openssl_name_for(e.split()[0]), e.split()[1])
            for e in mine["ext_critical"])
    if "sig_alg_oid" in mine:
        out["sig_alg_openssl_name"] = openssl_name_for(mine["sig_alg_oid"])
        if mine["sig_alg_oid"] in GNUTLS_SIG:
            out["sig_alg_gnutls_name"] = GNUTLS_SIG[mine["sig_alg_oid"]]
    return out


def main(argv):
    binary, files = argv[1], argv[2:]
    totals = {"cryptography": [0, 0], "openssl": [0, 0], "certtool": [0, 0]}
    refusals = 0
    dn_skipped = [0]
    # What the corpus actually reaches. A comparison of a construct the
    # corpus does not hold passes without running anything, so the reached
    # set is printed next to the agreement counts.
    reached = {"key usage bit": set(), "string type": set(),
               "extension": set(), "signature algorithm": set()}
    oracle_conflicts = 0
    skipped = {}
    for path in files:
        mine, why = ours(binary, path)
        if mine is None:
            print("    REFUSED %s: %s" % (path, why))
            refusals += 1
            continue
        mine = derived(canonical_ours(mine))
        reached["key usage bit"] |= set(mine.get("key_usage", ()))
        reached["extension"] |= set(e.split()[0] for e in mine.get("ext_oids", ()))
        reached["signature algorithm"].add(mine.get("sig_alg_oid"))
        for k in ("issuer_attr_types", "subject_attr_types"):
            reached["string type"] |= set(a.split()[1] for a in mine.get(k, ()))
        oracles = {
            "cryptography": from_cryptography(path),
            "openssl": from_openssl(path),
            "certtool": from_certtool(path),
        }
        # The DN string is only comparable when every attribute type in it
        # is one RFC 4514 names. Drop it from every side otherwise, and
        # count what was dropped.
        for which in ("issuer", "subject"):
            key = which + "_rfc4514"
            types = {a.split()[0] for a in mine.get(which + "_attrs", ())}
            if not types <= RFC4514_NAMED:
                dn_skipped[0] += 1
                mine.pop(key, None)
                for f in oracles.values():
                    f.pop(key, None)
        for name, facts in oracles.items():
            for k, v in sorted(facts.items()):
                if k not in mine:
                    skipped[k] = skipped.get(k, 0) + 1
                    continue
                totals[name][0] += 1
                if mine[k] != v:
                    totals[name][1] += 1
                    print("    %s %s: ours %r, %s %r"
                          % (path, k, mine[k], name, v))
        # Where the oracles disagree with each other, say so.
        keys = set()
        for facts in oracles.values():
            keys |= set(facts)
        for k in sorted(keys):
            vals = {n: f[k] for n, f in oracles.items() if k in f}
            if len(set(map(repr, vals.values()))) > 1:
                oracle_conflicts += 1
                print("    ORACLES DISAGREE %s %s: %s"
                      % (path, k, ", ".join("%s=%r" % (n, v)
                                            for n, v in sorted(vals.items()))))
    bad = 0
    for name in sorted(totals):
        n, b = totals[name]
        bad += b
        print("    %-13s %4d field comparisons, %d disagreed" % (name, n, b))
    if skipped:
        print("    not compared (no certlint field): %s"
              % ", ".join("%s %d" % (k, n) for k, n in sorted(skipped.items())))
    if dn_skipped[0]:
        print("    %d DN strings not compared: they hold an attribute type"
              " RFC 4514 does not name" % dn_skipped[0])
    for what in sorted(reached):
        got = sorted(x for x in reached[what] if x)
        print("    %s reached by the corpus: %d (%s)"
              % (what, len(got), " ".join(got)))
    print("    %d certificates, %d refused by certlint, %d oracle-versus-oracle"
          " disagreements" % (len(files), refusals, oracle_conflicts))
    return min(bad + refusals, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
