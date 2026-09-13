#!/usr/bin/env python3
"""Compare chain decisions against certtool --verify, and against openssl.

GnuTLS has its own ASN.1 library and its own path builder, neither
sharing a line with OpenSSL, so it is the oracle that can contradict the
other one. Two things are measured here and reported apart:

  certlint against GnuTLS, decision by decision;
  OpenSSL against GnuTLS, which is a finding about the two of them and
  not about certlint.

Where the two oracles disagree the scenario is listed with what each one
said. Nothing is averaged and nothing is dropped: a scenario where
OpenSSL and GnuTLS differ is still compared against both, and certlint
siding with one of them is recorded rather than scored.

certtool has no equivalent of openssl verify -attime, so the scenarios
that name an instant cannot be put to it. They are counted and named
rather than quietly left out.
"""
import os
import subprocess
import sys

import chaincmp


def certtool_verdict(leaf, anchors, untrusted, purpose, work):
    chain = os.path.join(work, "chain.pem")
    with open(chain, "wb") as f:
        f.write(open(chaincmp.p(leaf), "rb").read())
        for u in untrusted:
            f.write(open(chaincmp.p(u), "rb").read())
    ca = os.path.join(work, "gnutls-anchors.pem")
    with open(ca, "wb") as f:
        for a in anchors:
            f.write(open(chaincmp.p(a), "rb").read())
    cmd = ["certtool", "--verify", "--load-ca-certificate", ca,
           "--infile", chain]
    if purpose:
        cmd += ["--verify-purpose", OID[purpose]]
    r = subprocess.run(cmd, capture_output=True)
    out = (r.stdout + r.stderr).decode("utf-8", "surrogateescape")
    line = ""
    for l in out.splitlines():
        if l.startswith("Chain verification output:"):
            line = l.split(":", 1)[1].strip()
    ok = line.startswith("Verified")
    if not ok:
        # Drop the two sentences every failure repeats and keep the reason.
        line = line.replace("Not verified. The certificate is NOT trusted.",
                            "").strip()
    return ok, line


# The scenarios where the two oracles contradict each other, with the
# cause of each and the side certlint takes. The set is asserted, both
# ways: a new disagreement fails the suite and so does one that has
# stopped happening, because this list is the record and a record that
# drifts is worse than none.
RECORDED = {
    "sha1 leaf": (
        "openssl", "GnuTLS refuses SHA-1 signatures under its default "
        "verification profile; openssl has no such rule and certlint has "
        "no policy on digest strength in --verify"),
    "four long, through a key rollover certificate": (
        "openssl", "RFC 5280 6.1.4 (l) excludes self-issued certificates "
        "from the pathlen count. openssl excludes them, GnuTLS counts "
        "them, so GnuTLS sees two intermediates under a pathlen:1 root"),
    "an intermediate in breach, with a leaf that is not": (
        "openssl", "GnuTLS applies name constraints to the end "
        "certificate and openssl applies them to every certificate below "
        "the constraining CA"),
    "a subject DN outside it": (
        "openssl", "GnuTLS does not check the subject DN against a "
        "permitted directoryName subtree; openssl does"),
    "codeSigning on a certificate that offers six purposes": (
        "certtool", "openssl's codesign purpose refuses a keyUsage "
        "holding anything beyond digitalSignature and nonRepudiation. "
        "GnuTLS checks the purpose OID alone, which is what certlint "
        "does"),
}

OID = {
    "serverAuth": "1.3.6.1.5.5.7.3.1",
    "clientAuth": "1.3.6.1.5.5.7.3.2",
    "codeSigning": "1.3.6.1.5.5.7.3.3",
    "emailProtection": "1.3.6.1.5.5.7.3.4",
}


def main(argv):
    binary, work, chaincmp.C = argv[1], argv[2], argv[3]
    bad = 0
    n = 0
    skipped = []
    splits = []
    unsupported = 0
    for (name, leaf, anchors, untrusted, attime, extra, purpose,
         known) in chaincmp.scenarios():
        if attime is not None:
            skipped.append(name)
            continue
        gnutls, gwhy = certtool_verdict(leaf, anchors, untrusted, purpose,
                                        work)
        ossl, owhy, _ = chaincmp.openssl_verdict(leaf, anchors, untrusted,
                                                 None, work, extra, purpose)
        got, ourwhy, rc, plen = chaincmp.ours(binary, leaf, anchors,
                                              untrusted, None, purpose)
        n += 1
        if ossl != gnutls:
            splits.append((name, ossl, gnutls, owhy, gwhy, got))
            continue
        if not got and gnutls and "unsupported" in ourwhy:
            # Same refusal as in chaincmp: an algorithm with no verifier
            # here. Counted apart from a wrong answer.
            unsupported += 1
            continue
        if got != gnutls:
            bad += 1
            print("    %s: certlint %s, certtool %s"
                  % (name, "accepts" if got else "refuses",
                     "accepts" if gnutls else "refuses"))
            print("        certlint: %s" % (ourwhy or "-"))
            print("        certtool: %s" % (gwhy or "-"))
    if splits:
        print("    OpenSSL and GnuTLS disagree about %d of them:" % len(splits))
        for name, ossl, gnutls, owhy, gwhy, got in splits:
            side = "openssl" if got == ossl else "certtool"
            print("      %s" % name)
            print("        openssl  %s: %s"
                  % ("accepts" if ossl else "refuses", owhy or "-"))
            print("        certtool %s: %s"
                  % ("accepts" if gnutls else "refuses", gwhy or "-"))
            print("        certlint %s, siding with %s"
                  % ("accepts" if got else "refuses", side))
            rec = RECORDED.get(name)
            if rec is None:
                print("        NOT RECORDED: a new oracle disagreement")
                bad += 1
            else:
                print("        cause: %s" % rec[1])
                if rec[0] != side:
                    print("        the record says certlint sides with %s"
                          % rec[0])
                    bad += 1
    gone = sorted(set(RECORDED) - {s[0] for s in splits})
    for name in gone:
        print("    recorded oracle disagreement no longer happens: %s" % name)
        bad += 1
    if skipped:
        print("    %d scenarios not put to certtool, which has no -attime: %s"
              % (len(skipped), "; ".join(skipped)))
    print("    %d chain decisions against certtool --verify, %d disagreed, "
          "%d refused by certlint for want of a verifier, %d where the two "
          "oracles disagree with each other"
          % (n, bad, unsupported, len(splits)))
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
