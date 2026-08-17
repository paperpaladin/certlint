#!/usr/bin/env python3
"""Mutate the source, rebuild, and require the suite to notice.

Run it with `make mutants`, not as part of `make test`: each mutant is a
full rebuild plus the comparison scripts, so the run takes minutes.

Each entry is one edit to one file. The edit has to match exactly once,
which is checked, because a mutation that silently applies nowhere
reports a kill it did not earn. A mutant is killed when one of the
comparison scripts exits non-zero. Survivors are printed with the
reason, and an entry marked expect="survives" that dies is reported too:
the table is a record of what is and is not tested, and a record that
has stopped being true is worse than none.

Every mutant here was watched going red before it was written down. All
25 are killed as of this writing, and four of them only after the
corpus or the comparison grew to reach them: the table records which
comparison kills each one.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BIN = os.path.join(ROOT, "target", "release", "certlint")

# (name, file, from, to, which comparisons to run, expect)
#
# The comparison list per mutant is the point of the exercise: a
# path-building mutant that is only checked by the DER comparison would
# report a survivor it has not earned.
MUTANTS = [
    ("der: a long-form length that fits in short form is accepted",
     "src/der.rs",
     "        if len < 0x80 {\n            return err(\n                at,\n"
     "                format!(\"length {} must use the short form\", len),\n"
     "            );\n        }",
     "", ["asn1", "dump"], "killed"),
    ("der: a length with a leading zero octet is accepted", "src/der.rs",
     "        if octets[0] == 0 {\n            return err(at, \"length has a "
     "redundant leading zero octet\");\n        }",
     "", ["asn1", "dump"], "killed"),
    ("der: BOOLEAN accepts any non-zero octet", "src/der.rs",
     "            0xff => Ok(true),", "            _ => Ok(true),",
     ["dump"], "killed"),
    ("der: an OID subidentifier may start with 0x80", "src/der.rs",
     "            if first && *b == 0x80 {", "            if false {",
     ["asn1", "oid"], "killed"),
    ("ext: the KeyUsage ninth bit is dropped", "src/ext.rs",
     "if bs.bits > 9 {", "if bs.bits > 8 {", ["dump"], "killed"),
    ("path: the CA flag is not checked", "src/path.rs",
     "if !bc.ca {", "if false {", ["chain", "gnutls"], "killed"),
    ("path: pathlen off by one", "src/path.rs",
     "if intermediates > n {", "if intermediates > n + 1 {",
     ["chain", "gnutls"], "killed"),
    ("path: self-issued counted as an intermediate", "src/path.rs",
     "            if !is_self_issued(&c.cert) {\n"
     "                intermediates += 1;\n            }",
     "            intermediates += 1;", ["chain"], "killed"),
    ("path: keyCertSign is not checked", "src/path.rs",
     "Some(Ok(ku)) if !ku.has(KU_KEY_CERT_SIGN)",
     "Some(Ok(ku)) if false && !ku.has(KU_KEY_CERT_SIGN)",
     ["chain", "gnutls"], "killed"),
    ("path: the purpose is checked on the leaf only", "src/path.rs",
     "for (depth, idx) in chain.iter().enumerate() {\n"
     "                let c = &self.certs[*idx];\n"
     "                if let Some(ps) = purposes(&c.cert) {",
     "for (depth, idx) in chain.iter().enumerate().take(1) {\n"
     "                let c = &self.certs[*idx];\n"
     "                if let Some(ps) = purposes(&c.cert) {",
     ["chain"], "killed"),
    ("path: an unknown critical extension is waved through", "src/path.rs",
     "if e.critical && !PROCESSED.contains(&d.as_str()) {",
     "if false && !PROCESSED.contains(&d.as_str()) {",
     ["chain", "gnutls"], "killed"),
    ("path: excluded subtrees ignored", "src/path.rs",
     "for st in &nc.excluded {", "for st in nc.excluded.iter().take(0) {",
     ["chain"], "killed"),
    ("path: permitted subtrees ignored", "src/path.rs",
     "if !same.is_empty() && !same.iter().any",
     "if false && !same.iter().any", ["chain"], "killed"),
    ("path: the dNSName label boundary dropped", "src/path.rs",
     "if n.len() > b.len() && !b.starts_with('.') "
     "&& !n[..n.len() - b.len()].ends_with('.') {",
     "if false {", ["chain"], "killed"),
    ("path: the iPAddress mask ignored", "src/path.rs",
     "        .all(|((x, a), m)| x & m == a & m)",
     "        .all(|((x, a), m)| { let _ = m; x == a })", ["chain"], "killed"),
    ("path: the subject DN is not checked as a name", "src/path.rs",
     "        names.push(GeneralName::Directory(c.subject_der));",
     "        let _ = &c.subject_der;", ["chain"], "killed"),
    ("path: name constraints applied to the leaf only", "src/path.rs",
     "if !active.is_empty() && (depth == 0 || !is_self_issued(&c.cert)) {",
     "if !active.is_empty() && depth == 0 {", ["chain"], "killed"),
    # This one survived until the chain comparison started asking
    # openssl verify -show_chain which path it built. Reversing the
    # order still finds a valid path by backtracking, so no verdict
    # moves; what moves is which of the cross-signed root's two paths
    # comes back.
    ("path: candidate ordering reversed", "src/path.rs",
     "v.sort_by_key(|i| (score(child, &self.certs[*i], at), *i));",
     "v.sort_by_key(|i| (-score(child, &self.certs[*i], at), *i));",
     ["chain"], "killed"),
    ("lint: the 398 day cap moved by one", "src/lint.rs",
     "MAX_SUBSCRIBER_DAYS: i64 = 398", "MAX_SUBSCRIBER_DAYS: i64 = 399",
     ["lint"], "killed"),
    ("lint: the serial entropy floor moved by one", "src/lint.rs",
     "if !negative && bits < 64 {", "if !negative && bits < 63 {",
     ["lint"], "killed"),
    ("lint: the twenty octet serial cap moved by one", "src/lint.rs",
     "if octets > 20 {", "if octets > 21 {", ["lint"], "killed"),
    ("lint: the commonName matched case-sensitively", "src/lint.rs",
     ".map(|h| h.eq_ignore_ascii_case(cn))", ".map(|h| h == cn)",
     ["lint"], "killed"),
    ("lint: an iPAddress is not a commonName match", "src/lint.rs",
     "|| n.strip_prefix(\"IP:\").map(|h| h == cn).unwrap_or(false)",
     "|| false", ["lint"], "killed"),
    ("lint: a wildcard allowed in any label", "src/lint.rs",
     "        if i == 0 && *l == \"*\" {", "        if *l == \"*\" {",
     ["lint"], "killed"),
    ("sig: the PKCS#1 padding is not compared, only its tail", "src/sig.rs",
     "    if want == got {", "    if want[want.len() - 8..] == got[got.len() - 8..] {",
     ["sig", "forge"], "killed"),
]


def comparisons(which, corpus, work):
    pem = sorted(os.path.join(corpus, f) for f in os.listdir(corpus)
                 if f.endswith(".pem"))
    table = {
        "asn1": [sys.executable, os.path.join(HERE, "asn1cmp.py"), BIN] + pem,
        "dump": [sys.executable, os.path.join(HERE, "dumpcmp.py"), BIN] + pem,
        "lint": [sys.executable, os.path.join(HERE, "lintcmp.py"), BIN] + pem,
        "chain": [sys.executable, os.path.join(HERE, "chaincmp.py"), BIN,
                  work, corpus],
        "gnutls": [sys.executable, os.path.join(HERE, "gnutlscmp.py"), BIN,
                   work, corpus],
        "sig": [sys.executable, os.path.join(HERE, "sigcmp.py"), BIN, work]
               + pem,
        "oid": [sys.executable, os.path.join(HERE, "oidtable.py"), BIN],
        "forge": [sys.executable, os.path.join(HERE, "forge.py"), BIN, work,
                  os.path.join(corpus, "leaf-rsa.pem"),
                  os.path.join(corpus, "inter-rsa.pem"),
                  os.path.join(corpus, "inter-rsa.key")],
    }
    return [table[w] for w in which]


def build():
    r = subprocess.run(["cargo", "build", "--release", "--offline"],
                       cwd=ROOT, capture_output=True)
    return r.returncode == 0, r.stderr.decode("utf-8", "replace")


def main(argv):
    corpus = os.path.join(ROOT, "t", "corpus")
    work = tempfile.mkdtemp(prefix="certlint-mutants-")
    killed = []
    survived = []
    broken = []
    unexpected = []
    originals = {}
    for name, path, a, b, which, expect in MUTANTS:
        if expect == "skip":
            continue
        full = os.path.join(ROOT, path)
        if full not in originals:
            originals[full] = open(full).read()
        src = originals[full]
        if src.count(a) != 1:
            broken.append((name, "the text to replace appears %d times"
                           % src.count(a)))
            continue
        try:
            open(full, "w").write(src.replace(a, b))
            ok, err = build()
            if not ok:
                broken.append((name, "does not compile: %s"
                               % err.strip().splitlines()[-1:]))
                continue
            dead = None
            for cmd in comparisons(which, corpus, work):
                r = subprocess.run(cmd, cwd=ROOT, capture_output=True)
                if r.returncode != 0:
                    dead = os.path.basename(cmd[1])
                    break
        finally:
            open(full, "w").write(src)
        if dead:
            killed.append((name, dead))
            if expect == "survives":
                unexpected.append((name, "recorded as surviving, it died"))
        else:
            survived.append(name)
            if expect == "killed":
                unexpected.append((name, "recorded as killed, it survived"))
    build()
    shutil.rmtree(work, ignore_errors=True)
    for name, d in killed:
        print("    killed   %-55s by %s" % (name, d))
    for name in survived:
        print("    SURVIVED %s" % name)
    for name, why in broken:
        print("    BROKEN   %-55s %s" % (name, why))
    for name, why in unexpected:
        print("    CHANGED  %-55s %s" % (name, why))
    print("    %d mutants: %d killed, %d survived, %d did not apply"
          % (len(killed) + len(survived) + len(broken), len(killed),
             len(survived), len(broken)))
    return min(len(broken) + len(unexpected), 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
