#!/usr/bin/env python3
"""Compare certlint's chain decisions against openssl verify.

One scenario is a leaf, a set of trust anchors, a set of untrusted
intermediates and an instant. The comparison is on the decision, not on
the path: openssl prints one error and we print every candidate path we
tried, and those are not the same kind of output. Where both refuse, the
reason each gave is printed so that a pair of refusals for different
reasons is visible rather than counted as agreement.
"""
import os
import re
import subprocess
import sys

C = None  # corpus directory, set in main


def p(name):
    return os.path.join(C, name + ".pem")


def scenarios():
    """(name, leaf, anchors, untrusted, attime or None, openssl flags).

    The extra flags exist for one difference of policy rather than of
    fact. certlint treats any certificate in the --ca set as a trust
    anchor, so a chain that ends at an intermediate is accepted;
    openssl requires the chain to reach a self-signed certificate unless
    it is given -partial_chain. Both behaviours are defensible and the
    flag makes the comparison ask the same question.
    """
    s = [
        ("rsa chain", "leaf-rsa", ["root-rsa"], ["inter-rsa"], None, []),
        ("rsa chain, no intermediate", "leaf-rsa", ["root-rsa"], [], None, []),
        ("rsa chain, wrong root", "leaf-rsa", ["root-ec"], ["inter-rsa"], None, []),
        ("rsa chain, intermediate as anchor", "leaf-rsa", ["inter-rsa"], [],
         None, ["-partial_chain"]),
        ("ec chain", "leaf-ec", ["root-ec"], ["inter-ec"], None, []),
        ("p-521 chain", "leaf-ec521", ["root-ec521"], [], None, []),
        ("sha512 leaf", "leaf-sha512", ["root-rsa"], ["inter-rsa"], None, []),
        ("sha1 leaf", "leaf-sha1", ["root-rsa"], ["inter-rsa"], None, []),
        ("version 1 leaf", "v1", ["root-rsa"], ["inter-rsa"], None, []),
        ("root verifies against itself", "root-rsa", ["root-rsa"], [], None, []),
        ("every intermediate offered at once", "leaf-rsa",
         ["root-rsa", "root-ec", "root-nc"],
         ["inter-rsa", "inter-ec", "root-ec521"], None, []),
        ("name constrained, inside", "leaf-nc-ok", ["root-nc"], [], None, []),
        ("a dNSName in an excluded subtree", "leaf-nc-bad", ["root-nc"], [],
         None, []),
        ("an iPAddress outside every permitted subtree", "leaf-nc-ip",
         ["root-nc"], [], None, []),
        ("an rfc822Name outside every permitted subtree", "leaf-nc-mail",
         ["root-nc"], [], None, []),
        ("a uniformResourceIdentifier in an excluded subtree", "leaf-nc-uri",
         ["root-nc"], [], None, []),
        ("a dNSName that only ends with the permitted base",
         "leaf-nc-suffix", ["root-nc"], [], None, []),
        ("an intermediate in breach, with a leaf that is not",
         "leaf-nc-sub", ["root-nc"], ["inter-nc"], None, []),
        ("a subject DN inside the permitted directoryName", "leaf-ncdn-ok",
         ["root-ncdn"], [], None, []),
        ("a subject DN outside it", "leaf-ncdn-bad", ["root-ncdn"], [],
         None, []),
        ("before notBefore", "leaf-rsa", ["root-rsa"], ["inter-rsa"],
         1000000000, []),
        ("after notAfter", "leaf-rsa", ["root-rsa"], ["inter-rsa"],
         4000000000, []),
        ("intermediate expired at that instant", "time-utc2049",
         ["root-rsa"], ["inter-rsa"], 820454400, []),
        ("one level below a pathlen:0 intermediate", "leaf-deep",
         ["root-rsa"], ["inter-rsa", "subca-rsa"], None, []),
        ("the same chain with the sub-CA as the anchor", "leaf-deep",
         ["subca-rsa"], [], None, ["-partial_chain"]),
        ("issued by a leaf", "leaf-under-leaf", ["root-rsa"],
         ["inter-rsa", "leaf-rsa"], None, []),
        # The same certificate against a two-long path. The scenario
        # above reaches the CA flag and the pathlen rule at once, so
        # deleting the CA flag check leaves the decision unchanged and
        # only the reason moves; here nothing else can refuse it.
        ("issued by a leaf, with that leaf as the anchor", "leaf-under-leaf",
         ["leaf-rsa"], [], None, ["-partial_chain"]),
        ("four long, through a key rollover certificate", "leaf-roll",
         ["root-rsa"], ["inter2-rsa", "roll-rsa"], None, []),
        # The issuer here has keyCertSign and says CA:FALSE, so only the
        # basicConstraints rule can refuse it. leaf-rsa, which the two
        # scenarios above use, is refused by the keyUsage rule first.
        ("issued by something with keyCertSign that is not a CA",
         "leaf-under-notca", ["leaf-notca"], [], None, ["-partial_chain"]),
        ("an intermediate with no basicConstraints", "leaf-nobc",
         ["root-rsa"], ["inter-nobc"], None, []),
        ("a CA whose keyUsage has no keyCertSign", "leaf-nokcs",
         ["root-rsa"], ["inter-nokcs"], None, []),
        ("a critical extension nobody processes", "ext-unknown-critical",
         ["root-rsa"], ["inter-rsa"], None, []),
        ("a critical subjectAltName on an empty subject", "subject-empty",
         ["root-rsa"], ["inter-rsa"], None, []),
        ("cross-signed, the short path", "leaf-cross", ["root-cross"], [],
         None, []),
        ("cross-signed, the long path", "leaf-cross", ["root-rsa"],
         ["cross-rsa"], None, []),
        ("cross-signed, both paths available", "leaf-cross",
         ["root-rsa", "root-cross"], ["cross-rsa"], None, []),
        # --purpose. openssl spells the same four purposes differently and
        # its -purpose also applies the key usage rules that go with each,
        # so these are the scenarios most likely to produce a real
        # difference rather than an agreement.
        ("serverAuth on a server certificate", "leaf-rsa", ["root-rsa"],
         ["inter-rsa"], None, [], "serverAuth"),
        ("clientAuth on a certificate that does not offer it", "leaf-ec",
         ["root-ec"], ["inter-ec"], None, [], "clientAuth"),
        # A recorded difference, not an agreement. leaf-full carries all
        # nine key usage bits, and openssl's codesign purpose refuses a
        # certificate whose keyUsage has anything beyond digitalSignature
        # and nonRepudiation. certlint's --purpose is an extendedKeyUsage
        # check and nothing else, so it accepts. Listed here so that the
        # suite fails if the two ever start agreeing without the record
        # being updated.
        ("codeSigning on a certificate that offers six purposes",
         "leaf-full", ["root-rsa"], ["inter-rsa"], None, [], "codeSigning",
         "openssl applies its own keyUsage rule for codesign; "
         "certlint's --purpose reads extendedKeyUsage only"),
        ("emailProtection on a server certificate", "leaf-rsa",
         ["root-rsa"], ["inter-rsa"], None, [], "emailProtection"),
        ("clientAuth under a CA restricted to serverAuth", "leaf-eku",
         ["root-rsa"], ["inter-eku"], None, [], "clientAuth"),
        ("serverAuth under the same CA", "leaf-eku", ["root-rsa"],
         ["inter-eku"], None, [], "serverAuth"),
    ]
    s = [x + (None,) * (8 - len(x)) for x in s]
    return [x for x in s if os.path.exists(p(x[1]))]


# Scenarios where both accept and the two build different paths, with
# the reason. Asserted both ways, like the verdict differences: a new
# length difference fails, and one of these agreeing fails too.
LENGTH_DIFFS = {
    "root verifies against itself":
        "the subject certificate is itself a trust anchor. openssl stops "
        "there and reports a chain of one; certlint still builds a path to "
        "the anchor copy in the store and checks the self-signature, so it "
        "reports two",
}


# openssl verify names the same purposes differently.
OSSL_PURPOSE = {
    "serverAuth": "sslserver",
    "clientAuth": "sslclient",
    "codeSigning": "codesign",
    "emailProtection": "smimesign",
}


def run(cmd):
    r = subprocess.run(cmd, capture_output=True)
    return (r.returncode,
            r.stdout.decode("utf-8", "surrogateescape"),
            r.stderr.decode("utf-8", "surrogateescape"))


def openssl_verdict(leaf, anchors, untrusted, attime, work, extra, purpose):
    cmd = ["openssl", "verify", "-show_chain"] + list(extra)
    if purpose:
        cmd += ["-purpose", OSSL_PURPOSE[purpose]]
    ca = os.path.join(work, "anchors.pem")
    with open(ca, "wb") as f:
        for a in anchors:
            f.write(open(p(a), "rb").read())
    cmd += ["-CAfile", ca]
    if untrusted:
        un = os.path.join(work, "untrusted.pem")
        with open(un, "wb") as f:
            for u in untrusted:
                f.write(open(p(u), "rb").read())
        cmd += ["-untrusted", un]
    if attime is not None:
        cmd += ["-attime", str(attime)]
    cmd.append(p(leaf))
    rc, out, err = run(cmd)
    reason = ""
    m = re.search(r"error \d+ at \d+ depth lookup: *(.*)", out + err)
    if m:
        reason = m.group(1).strip()
    elif rc != 0:
        reason = (out + err).strip().splitlines()[-1] if (out + err).strip() else ""
    # The chain openssl actually built, so that two implementations
    # agreeing on the verdict can still be compared on the path. A
    # cross-signed root gives two valid answers and the verdict alone
    # cannot tell which one was found.
    depth = len([l for l in (out + err).splitlines()
                 if l.startswith("depth=")])
    return rc == 0, reason, depth


def ours(binary, leaf, anchors, untrusted, attime, purpose):
    cmd = [binary, "--verify", p(leaf)]
    if purpose:
        cmd += ["--purpose", purpose]
    for a in anchors:
        cmd += ["--ca", p(a)]
    for u in untrusted:
        cmd += ["--untrusted", p(u)]
    if attime is not None:
        import datetime
        t = datetime.datetime.fromtimestamp(attime, datetime.timezone.utc)
        cmd += ["--at", t.strftime("%Y%m%d%H%M%SZ")]
    rc, out, err = run(cmd)
    ok = "verdict = ok" in out
    reasons = [l.split(" ", 2)[-1] for l in out.splitlines()
               if l.startswith("attempt = ")]
    plen = 0
    for l in out.splitlines():
        if l.startswith("path_length = "):
            plen = int(l.split("=")[1])
    return ok, "; ".join(reasons[:2]), rc, plen


def counts():
    """What the corpus actually holds, per construct the scenarios reach.

    A pathlen test over a corpus with no pathLenConstraint passes while
    checking nothing, and so does a cross-signing test over a corpus
    where every subject is unique. These are the numbers that say
    whether the scenarios above can fail.
    """
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID
    ca = 0
    plen = 0
    refused = 0
    subjects = {}
    nctypes = set()
    for f in sorted(os.listdir(C)):
        if not f.endswith(".pem"):
            continue
        try:
            c = x509.load_pem_x509_certificate(
                open(os.path.join(C, f), "rb").read())
            s = c.subject.rfc4514_string()
            exts = c.extensions
        except Exception:
            # The oracle refusing to parse a corpus file is a refusal and
            # not a zero. Counted and printed, never folded into the
            # construct counts.
            refused += 1
            continue
        subjects[s] = subjects.get(s, 0) + 1
        try:
            nc = exts.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS).value
            for st in list(nc.permitted_subtrees or []) + \
                    list(nc.excluded_subtrees or []):
                nctypes.add(type(st).__name__)
        except x509.ExtensionNotFound:
            pass
        try:
            bc = exts.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        except x509.ExtensionNotFound:
            continue
        if bc.ca:
            ca += 1
            if bc.path_length is not None:
                plen += 1
    shared = sum(1 for v in subjects.values() if v > 1)
    return ca, plen, shared, refused, sorted(nctypes)


def main(argv):
    global C
    binary, work, C = argv[1], argv[2], argv[3]
    bad = 0
    n = 0
    lengths = {}
    for (name, leaf, anchors, untrusted, attime, extra, purpose,
         known) in scenarios():
        want, why, wantlen = openssl_verdict(leaf, anchors, untrusted,
                                             attime, work, extra, purpose)
        got, ourwhy, rc, plen = ours(binary, leaf, anchors, untrusted, attime,
                                     purpose)
        n += 1
        if got:
            lengths[name] = plen
        if want and got and wantlen:
            rec = LENGTH_DIFFS.get(name)
            if plen != wantlen and rec is None:
                bad += 1
                print("    %s: both accept, certlint built a path of %d and "
                      "openssl one of %d" % (name, plen, wantlen))
            elif rec is not None:
                print("    recorded path difference %s: certlint %d, "
                      "openssl %d" % (name, plen, wantlen))
                print("        %s" % rec)
                if plen == wantlen:
                    print("        they agree now; the record is stale")
                    bad += 1
        if known is not None:
            # An inverted check: this pair is recorded as differing, so
            # agreement is the failure. A recorded difference that has
            # quietly gone away is a record that is now wrong.
            print("    recorded difference %s: certlint %s, openssl %s"
                  % (name, "accepts" if got else "refuses",
                     "accepts" if want else "refuses"))
            print("        %s" % known)
            if got == want:
                print("        they agree now; the record is stale")
                bad += 1
            continue
        if got != want:
            bad += 1
            print("    %s: certlint %s, openssl %s"
                  % (name, "accepts" if got else "refuses",
                     "accepts" if want else "refuses"))
            print("        certlint: %s" % (ourwhy or "-"))
            print("        openssl:  %s" % (why or "-"))
        elif not want:
            print("    both refuse %s" % name)
            print("        certlint: %s" % (ourwhy or "-"))
            print("        openssl:  %s" % (why or "-"))
        if got and rc != 0:
            print("    %s: accepted but exit status %d" % (name, rc))
            bad += 1
        if not got and rc != 3:
            print("    %s: refused but exit status %d, wanted 3" % (name, rc))
            bad += 1
    ca, plen, shared, refused, nctypes = counts()
    print("    the corpus holds %d CA certificates, %d of them with a "
          "pathLenConstraint, and %d subjects held by more than one "
          "certificate (%d files cryptography would not parse, counted "
          "here and nowhere else)" % (ca, plen, shared, refused))
    print("    name constraint base types in the corpus: %d (%s)"
          % (len(nctypes), " ".join(nctypes)))
    if len(nctypes) < 4:
        print("    fewer than four constrained name types; the per-type "
              "matchers are not all reached")
        bad += 1
    if plen == 0 or shared == 0:
        print("    the pathlen and cross-signing scenarios cannot fail on "
              "this corpus")
        bad += 1
    # The two cross-signed scenarios must find paths of different lengths,
    # or the second one is the first one again under another name.
    short = lengths.get("cross-signed, the short path")
    long_ = lengths.get("cross-signed, the long path")
    print("    cross-signed leaf: path of %s certificates to the self-signed "
          "root, %s through the cross certificate" % (short, long_))
    if short != 2 or long_ != 3:
        print("    wanted 2 and 3; one of the two paths was not built")
        bad += 1
    print("    %d chain decisions against openssl verify, %d disagreed"
          % (n, bad))
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
