# PLAN

## Contract

```
certlint [MODE] [OPTIONS] FILE...

  -a, --asn1        print the DER structure, one line per TLV
  -d, --dump        print the parsed certificate as key = value lines
  -v, --verify      build a path to a trust anchor and validate it
  -l, --lint        check the certificate against the CA/Browser Forum
                    Baseline Requirements
  -A, --all         --dump then --lint

  --ca FILE         add a trust anchor (repeatable, file may hold several)
  --untrusted FILE  add candidate intermediates (repeatable)
  --at TIME         validate at this instant, as YYYYMMDDHHMMSSZ
  --purpose NAME    serverAuth, clientAuth, codeSigning, emailProtection
  --max-paths N     stop after N candidate paths have been tried
```

`FILE` is a certificate in DER or PEM. PEM is detected by the `-----BEGIN`
line, and a file may hold several, in which case the first is the subject of
the command and the rest are candidate intermediates.

Exit status: 0 when every requested check passed, 1 when the input is
malformed or unreadable, 2 on a usage error, 3 when a chain could not be
built or validated, 4 when the linter found an error-level finding. The
numbers are distinct because the harness asserts on the difference, and
because "cannot parse" and "parsed fine, chain is bad" are not the same
answer.

Pure Rust 2021 with no dependencies: no ASN.1 crate, no crypto crate, no
bignum crate. `std` only. Zero `unsafe` in the tree, asserted by the suite.

## Hard invariant

**Every field certlint prints and every chain decision it makes agrees with
an implementation it does not control, compared field by field and decision
by decision, and anything certlint will not parse is counted as a refusal
separately from a wrong answer.**

Concretely:

- For every certificate in the corpus, the (field, value) pairs from
  `--dump` equal the pairs extracted from python `cryptography`, from
  `openssl x509 -text -noout`, and from `certtool --certificate-info`.
  Compared as values, per field, never as text: the three printers disagree
  about radix, date format, DN order and separator.
- For every TLV in every corpus file, the (offset, depth, tag, length) tuple
  from `--asn1` equals the tuple `openssl asn1parse` prints.
- For every (leaf, anchor set, intermediate set, time) scenario, the verdict
  from `--verify` equals the verdict from `openssl verify` and from
  `certtool --verify-chain`, with the three-way disagreements recorded rather
  than averaged.
- Where OpenSSL and GnuTLS disagree with each other, the suite records the
  disagreement and certlint is allowed to side with either, but the choice
  is written down in the README with the reason.

## Oracle

Ranked by how little we control them.

1. `openssl asn1parse`, `openssl x509 -text -noout`, `openssl verify`.
   OpenSSL's ASN.1 decoder and path builder are the de facto reference for
   the whole ecosystem.
2. `certtool --certificate-info` and `certtool --verify` from GnuTLS. An
   independent implementation with an independent ASN.1 library
   (libtasn1), so it is the one that can contradict OpenSSL. It does:
   seven times, every one recorded in the README with the side certlint
   took. `--verify` rather than `--verify-chain`, which this said at
   first: `--verify-chain` treats the last certificate in the file as
   the anchor, where `--verify --load-ca-certificate` asks the same
   question openssl verify is being asked.
3. python `cryptography` 43.0.0, which is a Rust ASN.1 parser under a Python
   API. A third opinion, and the easiest one to compare against because it
   returns structured values rather than printed text.
4. `openssl req` and `openssl x509 -req` as corpus generators, plus
   `t/mkodd.py` for the encodings openssl will not emit. Not oracles for
   correctness, but the source of certificates nobody here hand-wrote.
   `openssl ca` is not used; the two above cover everything the corpus
   needs.

No oracle exists for the Baseline Requirements lint on this machine: zlint
and certlint (the Ruby one) are not installed and nothing may be downloaded.
The lint is therefore measured differently, and the README says so: every
lint finding names the field it fired on, and the suite asserts the field
value against the three parsers above, so a lint cannot fire on a value
certlint invented. `t/lintcmp.py` goes further and implements each rule a
second time over cryptography's parse, which does not check the rule but
does check the value it reads.

## Non-goals

- CRL and OCSP. No revocation checking at all.
- TLS. Nothing on this machine opens a socket.
- Certificate issuance, key generation, signing.
- DSA, Ed25519 and Ed448 signatures. RSASSA-PSS is still planned rather
  than a non-goal.
- Policy mapping, policy constraints, inhibitAnyPolicy. The policy tree of
  RFC 5280 section 6.1 is not implemented; certificatePolicies is parsed and
  printed but not processed.
- BER. Only DER is accepted, and an indefinite length is a refusal.

## Commit sequence

- [x] scaffolding: Cargo.toml, Makefile, LICENSE, suite skeleton
      why: the gate runs `make test` from the first commit, so the harness
      has to exist before the code does.
- [x] der: identifier and length octets, with the DER minimal-length rule
      why: every later parser is a caller of this, and the minimal-length
      rule is the first place a BER-tolerant decoder goes wrong.
- [x] der: a reader over a slice, with nesting and a sticky error
      why: one chokepoint for every read means a hostile file produces a
      diagnostic rather than a panic, and it is the thing to mutate later.
- [x] der: INTEGER, with the no-redundant-leading-octet rule and negatives
      why: serial numbers are the one field where a sign bug is invisible,
      and openssl and certtool already disagree about printing one.
- [x] der: BOOLEAN, NULL, OBJECT IDENTIFIER
      why: BOOLEAN under DER is 0x00 or 0xFF and nothing else; an OID arc
      needs the minimal-base-128 rule for the same reason as a length.
- [x] der: BIT STRING and OCTET STRING
      why: the unused-bits octet is load-bearing for KeyUsage.
- [x] der: the string types and their character set rules
      why: PrintableString has a 74-character alphabet that nobody checks,
      and a T61String is not UTF-8 however much it looks like it.
- [x] oid: the name table and the dotted-decimal fallback
      why: an unknown OID must print as numbers, never as a guess.
- [x] cli: --asn1, printing offset, depth, tag, length, header length
      why: the first output that an oracle can read, so the first commit
      that can be checked against something outside.
- [x] t: corpus generator, the ordinary certificates
      why: nothing can be compared until there are files nobody here wrote
      by hand.
- [x] t: --asn1 against openssl asn1parse, TLV by TLV
      why: proves the decoder agrees on structure before any field means
      anything.
- [x] time: UTCTime and GeneralizedTime, including the 2050 rule
      why: RFC 5280 makes the encoding depend on the year, and the boundary
      is exactly where a parser that handles one format well breaks.
- [x] name: RDNSequence, AttributeTypeAndValue, RFC 4514 output
      why: the DN is compared by three oracles that print it three ways, so
      it has to be a value and not a string.
- [x] cert: TBSCertificate, version, serial, signature algorithm
      why: the spine everything else hangs from.
- [x] cert: SubjectPublicKeyInfo, RSA and EC parameters, key size
      why: key size is a lint input and a field all three oracles print.
- [x] cert: the extension list, criticality, unknown extensions
      why: an unrecognised critical extension changes the verdict, so it
      cannot be skipped quietly.
- [x] ext: BasicConstraints
      why: the extension path building is built on.
- [x] ext: KeyUsage, with the unused-bits trap
      why: a nine-bit KeyUsage is two octets and decipherOnly is the bit
      that gets dropped.
- [x] ext: ExtendedKeyUsage
      why: purpose checking needs it, and anyExtendedKeyUsage is a special
      case.
- [x] ext: GeneralName, all nine alternatives
      why: SAN and NameConstraints both decode it, and the context tags are
      primitive where the type is a string and constructed where it is not.
- [x] ext: SubjectAltName and IssuerAltName
      why: the field browsers actually match on.
- [x] ext: NameConstraints
      why: the permitted and excluded subtree trees that path validation
      intersects.
- [x] ext: AKI, SKI, CRLDistributionPoints, AIA, certificatePolicies
      why: AKI is the hint path building orders candidates by, and the rest
      are lint inputs.
- [x] cli: --dump
      why: the output the field-by-field comparison reads.
- [x] t: --dump against python cryptography, field by field
      why: structured values, so the comparison is on the value and not on
      a format.
- [x] t: --dump against openssl x509 -text
      why: a second parser, and the one whose output everybody else copies.
- [x] t: --dump against certtool --certificate-info
      why: libtasn1 is genuinely independent of OpenSSL, so this is the
      comparison that can find a shared assumption.
- [x] t: corpus of awkward certificates
      why: a name-constraints test on a corpus with no name constraints
      passes vacuously, so the constructs have to be counted and the counts
      printed.
- [x] t: record where OpenSSL and GnuTLS disagree
      why: a disagreement between two oracles is a finding, not noise to be
      averaged away.
- [x] hash: SHA-1, SHA-256, SHA-384, SHA-512
      why: signature verification needs a digest and there is no crate.
- [x] bignum: the modular arithmetic signature verification needs
      why: RSA is a modexp and ECDSA is a scalar multiplication; both need
      a bignum nobody wrote for us.
- [x] sig: RSA PKCS#1 v1.5 verification
      why: most of the corpus is signed this way, and the padding check is
      where the forgeries live.
- [x] sig: ECDSA over P-256 and P-384
      why: the other half of the real world, and the signature encoding is
      a DER SEQUENCE of two INTEGERs that must itself be strict.
- [ ] sig: RSASSA-PSS
      why: MGF1 and the salt length, and because openssl will sign with it
      on request. Still not written. A certificate signed this way is
      reported as unsupported, which the signature comparison counts
      apart from a disagreement, and the count is 0 only because the
      corpus holds none: the corpus has to grow a PSS certificate in the
      same commit or the feature will look tested when it is not.
- [x] t: every signature in the corpus against openssl dgst -verify
      why: a verifier that accepts everything passes any test made only of
      valid signatures, so the suite flips bits and requires a rejection.
- [x] path: the candidate issuer index, by subject
      why: several certificates can share a subject, which is the case the
      naive implementation gets wrong.
- [x] path: depth-first search with backtracking and loop detection
      why: taking the first matching issuer is the bug this project exists
      to not have.
- [x] path: candidate ordering by AKI, validity and key identifier
      why: ordering changes which valid path is found first, and a
      cross-signed root makes two valid answers.
- [x] path: validity windows at a given instant
      why: --at is what makes an expired intermediate testable without
      waiting.
- [x] path: basic constraints, CA flag and pathlen
      why: a pathlen that is exceeded must fail, and the count excludes
      self-issued certificates.
- [x] path: keyCertSign and the purpose check
      why: an issuer without keyCertSign is not an issuer.
- [x] path: name constraints, permitted and excluded, per name type
      why: the state has to be carried down the chain and intersected, not
      checked once.
- [x] t: chain decisions against openssl verify
      why: the decision, not the path: openssl prints one error, we print
      the path we tried.
- [x] t: chain decisions against certtool --verify-chain
      why: GnuTLS builds paths differently and will not always agree.
- [x] t: the cross-signed and multiple-candidate scenarios
      why: the whole point of the path builder, and the place a vacuous
      pass is most likely.
- [x] lint: serial number, positive, not zero, 64 bits of entropy
      why: the BR rule with a measurable input.
- [x] lint: validity period caps
      why: 398 days for a server certificate, and the arithmetic is on the
      dates the oracles already agree about.
- [x] lint: required and forbidden extensions, per certificate type
      why: a CA certificate without basicConstraints is a different defect
      from a leaf with it.
- [x] lint: name encoding, SAN presence, wildcards, IP address length
      why: the encoding rules are per name type and each has its own trap.
- [x] lint: subject DN rules and the commonName-in-SAN requirement
      why: a commonName that is not in the SAN is the classic finding.
- [x] t: mutation run over the parser and the path builder
      why: a test that cannot fail is the defect this collection keeps
      finding; survivors get written down, including the equivalent ones.
- [x] t: truncation and corruption sweep
      why: a certificate is attacker-controlled input in every program that
      reads one.
- [x] overread: the planted one-past-the-end read, as a gate
      why: Rust bounds-checks a slice, so the claim is that nothing here
      carries a length beside a buffer; the gate is what makes it a measured
      claim rather than a language slogan.
- [x] README with the measured numbers and what does not work
      why: a README that only lists successes is not finished.
- [ ] lint: a key size floor, and the BR policy identifiers
      why: two of the easiest Baseline Requirements rules to check are
      missing, and the README says so. key_bits is already a --dump field
      all three parsers agree on, and certificatePolicies is already
      parsed, so both are rules over values that have an oracle.
- [ ] lint: the wildcard-above-a-public-suffix rule, or a note saying why not
      why: BR 7.1.4.2.1 forbids a wildcard directly left of a
      registry-controlled label, and there is no public suffix list on this
      machine and nothing may be downloaded. Either it gets a list from
      somewhere defensible or the README stops implying it is a gap that
      will close.
- [x] t: a PSS and an Ed25519 certificate in the corpus, as refusals
      why: the unsupported-algorithm path is currently reached by nothing,
      which is the same vacuity the lint coverage check exists to catch.
      openssl can sign with both, so the certificates are cheap, and the
      suite would then measure a refusal against an oracle that accepts
      rather than assuming one.
