# certlint

An X.509 certificate parser, chain validator and CA/Browser Forum Baseline
Requirements linter, in Rust 2021 with no dependencies. No ASN.1 crate, no
crypto crate, no bignum crate: the DER decoder, SHA-1 and the SHA-2 family,
the Montgomery arithmetic, RSA PKCS#1 v1.5, ECDSA over P-256, P-384 and
P-521, the path builder and the linter are all in `src/`. `std` only, and
the suite counts the occurrences in `src` of the keyword that would let an
index skip its bounds check, which has to be zero.

```
certlint [MODE] [OPTIONS] FILE...

  -a, --asn1        print the DER structure, one line per TLV
      --der         write the first certificate out as DER
  -d, --dump        print the parsed certificate as key = value lines
  -v, --verify      build a path to a trust anchor and validate it
  -l, --lint        check against the Baseline Requirements
  -A, --all         --dump then --lint

  --ca FILE         add a trust anchor (repeatable)
  --untrusted FILE  add candidate intermediates (repeatable)
  --at TIME         validate at this instant, as YYYYMMDDHHMMSSZ
  --purpose NAME    serverAuth, clientAuth, codeSigning, emailProtection
  --max-paths N     stop after N candidate paths have been tried
```

Exit status: 0 when every requested check passed, 1 when the input is
malformed or unreadable, 2 on a usage error, 3 when a chain could not be
built or validated, 4 when the linter found an error-level finding. The
numbers are distinct because the suite asserts on the difference, and
because "cannot parse" and "parsed fine, chain is bad" are not the same
answer.

`make test` runs the suite, `make mutants` the mutation run, `make
overread` the bounds-check gate.

## The oracles

Nothing here is checked against a number worked out by hand. Every field
and every chain decision is compared against software this repository does
not control.

- `openssl asn1parse`, `openssl x509 -text -noout`, `openssl verify
  -show_chain` and `openssl dgst -verify`, from OpenSSL 3.5.7.
- `certtool --certificate-info` and `certtool --verify` from GnuTLS 3.8.9.
  libtasn1 shares no code with OpenSSL, so this is the oracle that can
  contradict the other one, and it does: five times, listed below.
- python `cryptography` 43.0.0, a Rust ASN.1 parser behind a Python API,
  which returns structured values rather than printed text.
- python's `pow` for the modular exponentiation, and `openssl ecparam` for
  the curve parameters.
- `openssl req`, `openssl x509 -req` and a 400-line `t/mkodd.py` generate
  the corpus. Generators, not oracles.

Comparison is per field and per decision, never per file. The three
printers disagree about radix, date format, DN order and separator, so
every value is compared as a value.

## What is measured

77 certificates in the corpus, and the suite reports 24 checks. The
figures below are from one run on 20 October 2026.

Structure, against `openssl asn1parse`: 4706 TLVs over 75 files, every one
agreeing on offset, depth, header length, length and tag. 2219 of the
printed values are compared as well, 1011 of them OBJECT IDENTIFIERs each
resolved by asking openssl what it renders that dotted form as.

Fields, against all three parsers: 1564 comparisons against cryptography,
1305 against openssl, 1010 against certtool, none disagreeing.

Chains, against `openssl verify`: 42 scenarios, every verdict agreeing,
and the length of the path built compared too where both accept.

Chains, against `certtool --verify`: 39 of those scenarios, every verdict
agreeing wherever OpenSSL and GnuTLS agree with each other.

Signatures, against `openssl dgst -verify`: 172 verdicts, 85 of them with
a bit flipped in the signature and rejected by both. 7 forged PKCS#1 v1.5
padding blocks, all refused.

Digests, against `openssl dgst`: 116 over 29 input lengths. Modular
exponentiation, against python `pow`: 53. Curve parameters, against
`openssl ecparam`: 21 facts over three curves, including that n*G is the
point at infinity on each.

Lint, against the same rules written a second time over cryptography's
parse: 66 certificates, 24 rules, no disagreement.

Hostile input: 727 truncated and corrupted files, no panic, no exit status
the mode cannot produce, no silent refusal.

### Refusals, counted separately

A refusal is not a disagreement and the suite never adds the two together.

certlint refuses 6 corpus certificates outright, every one of them
deliberately malformed and named `refuse-*`: a non-minimal INTEGER, a
non-minimal length, a length in long form that fits in short form, a
BOOLEAN whose content octet is 0x01, an OID arc beginning 0x80, and a
version 1 certificate carrying extensions. openssl parses four of those
six, refusing the non-minimal serial and the non-minimal OID arc. It
also refuses 7 hand-built malformed strings that openssl parses without
complaint, and 2 certificates before any signature is checked.

The oracles refuse things too. python cryptography refuses 10 of the 77
and certtool refuses 3, each named in the output with the reason. It also
warns rather than refusing on a negative serial, and says it will refuse
one outright in its next release; the warning is printed, not filtered.

Some comparisons are dropped with a reason rather than fudged: 6
alternative-name lists against openssl (4 where it prints a name type the
harness cannot convert back, 2 where the extension appears twice and
openssl runs the two bodies together), 2 against certtool (it writes an
iPAddress of the wrong width as `(error)`), and 4 DN strings (openssl
sorts a multi-valued RDN, certtool writes two values as hexstrings).

### Where the oracles contradict each other

Seven, recorded rather than averaged. The five chain ones are asserted in
both directions: a sixth fails the suite, and so does one of these five
going away.

1. **SHA-1.** GnuTLS refuses a SHA-1 signature under its default
   verification profile; openssl accepts one. certlint accepts: `--verify`
   has no policy on digest strength.
2. **The pathlen count and self-issued certificates.** RFC 5280 6.1.4 (l)
   says the count excludes self-issued certificates. openssl excludes
   them; GnuTLS counts them, and so refuses a four-long chain through a
   key rollover certificate under a `pathlen:1` root. certlint sides with
   openssl, because the RFC text is explicit.
3. **Where name constraints apply.** GnuTLS checks them against the end
   certificate. openssl checks every certificate below the constraining
   CA, and refuses an intermediate whose own SubjectAltName is in an
   excluded subtree even though the leaf under it is clean. certlint sides
   with openssl, which is also what 6.1.4 (g) describes.
4. **Name constraints and the subject DN.** GnuTLS accepts a subject of
   `C=FR` under a CA permitting only `dirName:C=GB,O=certlint`. openssl
   refuses it. Same choice, same reason.
5. **The codesign purpose.** openssl refuses a certificate whose keyUsage
   holds anything beyond digitalSignature and nonRepudiation. GnuTLS
   checks the purpose OID alone. certlint sides with GnuTLS here, because
   openssl's rule is its reading of RFC 5280 4.2.1.3 rather than a line in
   it, and `--purpose` is documented as an extendedKeyUsage check.
6. **A version 1 certificate carrying extensions.** certtool refuses it
   with an import error. openssl prints it as version 1 with a
   SubjectAltName, and cryptography parses it and reports version 1.
   certlint refuses it at the parser.
7. **The bit length of a P-521 key.** certtool says 528 and both openssl
   and cryptography say 521. certlint says 521.

Four of the five chain differences favour openssl and one favours GnuTLS,
which is worth saying plainly: certlint is not tracking either
implementation, it is choosing per rule.

There is also one place where the two agree on the verdict and build
different paths. Given a self-signed root as the subject certificate,
openssl reports a chain of one and stops; certlint builds a path to the
anchor copy in its store and checks the self-signature, so it reports two.

## Mutation testing

`make mutants` applies 25 edits to the parser, the path builder, the
linter and the signature code, rebuilds, and runs the comparisons each one
should be caught by. All 25 are killed. Each entry names the comparisons
to run, because a path-building mutant checked only by the DER comparison
would report a survivor it has not earned, and each edit must match its
source text exactly once, because a mutation that applies nowhere reports
a kill it has not earned either.

Four of the 25 needed something built before they would die, and those are
the useful ones:

- The short-form length rule had no corpus case at all. The non-minimal
  length certificate already there has a redundant leading zero octet,
  which is a different rule.
- The OID minimal-arc rule had none either.
- **The basicConstraints CA flag had stopped being tested.** It was killed
  when it was written, by a certificate issued by `leaf-rsa`. Then the
  keyCertSign rule arrived, and `leaf-rsa` has no keyCertSign, so that
  chain started being refused one rule earlier and the CA flag mutant
  quietly began surviving. A rule can lose its test to a rule added later
  and nothing says so.
- Candidate ordering survived everything, because reversing it still finds
  a valid path by backtracking and no verdict moves. What moves is which
  of a cross-signed root's two paths comes back, and the chain comparison
  now asks `openssl verify -show_chain` which path it built.

Separately, the rules in `src/lint.rs` are all required to be reached by
some corpus certificate; that check was watched going red with a rule
planted behind an `if false`. Two lint mutants die on it rather than on a
disagreement, which is a weaker kill and is counted as one anyway: a rule
nothing reaches is a rule that is not running.

Several earlier survivors were fixed by adding certificates either side of
a constant: 398 and 399 days to the second, a serial of exactly 21 octets,
serials of exactly 63 and 64 bits, a commonName differing from its SAN
only in case. Every one of those constants could be moved by one without
any corpus certificate noticing.

## The overread gate

`make overread` builds a second binary with the `plant_overread` feature,
which reads one byte past the end of the file buffer, and fails unless the
process dies at exactly that index with a message naming it.

The point is the failure this collection has found eighteen times in its C
repositories: a buffer allocated larger than the data in it, which leaves
a sanitizer blind to everything between the end of the data and the end of
the allocation. Rust has no equivalent as long as every read goes through
a slice whose length is the length of the data, and that is a claim about
this program rather than about the language, since a `Vec` carries a
capacity as well as a length. `read_file` calls `shrink_to_fit`.

The gate requires the ordinary binary to succeed on the same file first,
requires exit 134, which is SIGABRT under the release profile's `panic =
abort` and is a status this program cannot reach any other way, and
requires the panic text to name the index. It was watched both ways: with
the plant it reports the read of index 1350 caught at index 1350, and with
the same directory rebuilt without the feature it reports exit 0 where it
wanted 134.

What it does not cover: a read of the wrong byte that is still inside the
buffer. Nothing about bounds checking can see that, and the differential
comparisons are what stand in its place.

## What does not work

**No revocation checking.** No CRL, no OCSP, no CRLSets. `--dump` prints
the CRL distribution points and the AIA OCSP URL and nothing reads them. A
revoked certificate verifies here.

**No policy processing.** The certificate policies extension is parsed and
printed and the RFC 5280 6.1.3 policy tree is not implemented: no policy
mapping, no policy constraints, no inhibitAnyPolicy. A certificate marking
`certificatePolicies` critical is refused rather than waved through, which
is the honest answer to a feature that is not there, and the three
policy-processing extensions are all absent from the list of critical
extensions path validation will accept.

**No DSA, no Ed25519, no Ed448, no RSASSA-PSS.** The PLAN lists PSS and it
is not written. A certificate signed with any of them is reported as
unsupported rather than valid, and the signature comparison counts those
separately from disagreements; the count is currently 0 because the corpus
holds none.

**No Baseline Requirements oracle.** zlint is not installed, the Ruby
certlint is not installed and nothing may be downloaded here, so nothing
outside this tree can say whether a lint rule is the right rule. What
`t/lintcmp.py` does instead is implement each rule a second time over
python cryptography's parse of the same bytes and require the two sets of
findings to be equal. That cannot catch a misreading of the Baseline
Requirements. It catches a rule firing on a value certlint got wrong,
which is the failure the rest of the suite is built to catch. Two things
keep it from going vacuous: every rule reads a field out of `--dump`
rather than re-deriving it from the DER, and the comparison asserts that
each finding's named field is one `--dump` prints and that every rule is
reached by something.

**One lint rule has no mirror at all.** cryptography refuses to parse the
certificate with a five-octet iPAddress, so the only thing holding
`ip_bad_length` up is the coverage assertion.

**The 24 lint rules are a sample, not the Baseline Requirements.** They
cover the serial number, the validity period and its encoding, the
required and forbidden extensions per certificate type, dNSName labels and
wildcards, iPAddress width, and the subject DN including the
commonName-in-SAN rule. There is no CAA check, no public suffix list, so
no check that a wildcard sits above a registry-controlled label, no key
size floor, no check of the certificate policies against the BR policy
identifiers, and no SCT requirement.

**`--purpose` is an extendedKeyUsage check and nothing else.** It does not
apply the keyUsage rules that openssl attaches to each purpose. That is
one of the recorded oracle differences above rather than an oversight, but
it means `--purpose serverAuth` will accept a certificate whose keyUsage
makes no sense for a server.

**Three chain scenarios cannot be put to GnuTLS.** certtool has no
equivalent of `openssl verify -attime`, so the scenarios that name an
instant are compared against openssl only. They are named in the output
rather than dropped quietly.

**The corruption sweep is a sample.** 727 files from three certificates,
with a fixed seed. It is not a fuzzer and it does not run long.

**No TLS and no network.** Nothing here opens a socket.
