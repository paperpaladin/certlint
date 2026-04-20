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
        ("before notBefore", "leaf-rsa", ["root-rsa"], ["inter-rsa"],
         1000000000, []),
        ("after notAfter", "leaf-rsa", ["root-rsa"], ["inter-rsa"],
         4000000000, []),
        ("intermediate expired at that instant", "time-utc2049",
         ["root-rsa"], ["inter-rsa"], 820454400, []),
    ]
    return [x for x in s if os.path.exists(p(x[1]))]


def run(cmd):
    r = subprocess.run(cmd, capture_output=True)
    return (r.returncode,
            r.stdout.decode("utf-8", "surrogateescape"),
            r.stderr.decode("utf-8", "surrogateescape"))


def openssl_verdict(leaf, anchors, untrusted, attime, work, extra):
    cmd = ["openssl", "verify"] + list(extra)
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
    return rc == 0, reason


def ours(binary, leaf, anchors, untrusted, attime):
    cmd = [binary, "--verify", p(leaf)]
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
    return ok, "; ".join(reasons[:2]), rc


def main(argv):
    global C
    binary, work, C = argv[1], argv[2], argv[3]
    bad = 0
    n = 0
    for name, leaf, anchors, untrusted, attime, extra in scenarios():
        want, why = openssl_verdict(leaf, anchors, untrusted, attime, work,
                                    extra)
        got, ourwhy, rc = ours(binary, leaf, anchors, untrusted, attime)
        n += 1
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
    print("    %d chain decisions against openssl verify, %d disagreed"
          % (n, bad))
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
