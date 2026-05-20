// Path building and path validation.
//
// Two different jobs, and the reason most implementations get this wrong
// is that they run them together. Building is a search: a certificate's
// issuer field names a subject, several certificates can have that
// subject, and the one that happens to be first is not always the one
// that leads to a trust anchor. Validation is a set of rules applied to a
// finished path. Taking the first matching issuer and then validating is
// not path building, it is one guess at it, and it fails on exactly the
// cases that matter: a cross-signed root, an expired intermediate beside
// a valid one, two CAs with the same name.
//
// So this does a depth-first search with backtracking. Every candidate
// issuer is tried, in an order that puts the likely ones first, and a
// candidate that fails validation does not end the search.

use crate::cert::Cert;
use crate::ext::{AuthorityKeyId, BasicConstraints, ExtKeyUsage, Exts, KeyUsage, KU_KEY_CERT_SIGN};
use crate::key::Spki;
use crate::oid;
use crate::sig::{self, Verdict};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    Input,
    Untrusted,
    Anchor,
}

impl Source {
    pub fn name(&self) -> &'static str {
        match self {
            Source::Input => "input",
            Source::Untrusted => "untrusted",
            Source::Anchor => "anchor",
        }
    }
}

pub struct Candidate<'a> {
    pub cert: Cert<'a>,
    pub source: Source,
    pub label: String,
}

pub struct Store<'a> {
    pub certs: Vec<Candidate<'a>>,
}

pub struct Options {
    pub at: i64,
    pub purpose: Option<String>,
    pub max_paths: usize,
    pub max_depth: usize,
}

pub struct Failure {
    pub depth: usize,
    pub at_cert: String,
    pub reason: String,
}

pub struct Built {
    pub ok: bool,
    // The indices into the store of the path that validated, leaf first.
    pub path: Vec<usize>,
    pub failures: Vec<Failure>,
    pub paths_tried: usize,
}

fn subject_of<'a>(c: &Cert<'a>) -> &'a [u8] {
    c.subject_der
}

fn is_self_issued(c: &Cert) -> bool {
    c.subject_der == c.issuer_der
}

// The order candidates are tried in. RFC 4158 calls these "sorting
// heuristics" and is clear that none of them may remove a candidate: an
// AKI that matches nothing still has to fall through to the certificates
// that do not carry one.
fn score(child: &Cert, cand: &Candidate, at: i64) -> i32 {
    let mut s = 0;
    // A key identifier match first.
    if let (Some(kid), Some(skid)) = (aki_keyid(child), ski(&cand.cert)) {
        if kid == skid {
            s -= 8;
        }
    }
    // Then a certificate that is valid at the instant being asked about.
    if cand.cert.not_before.epoch <= at && at <= cand.cert.not_after.epoch {
        s -= 4;
    }
    // Then an anchor over an intermediate, because a shorter path is the
    // one a relying party wants when both work.
    if cand.source == Source::Anchor {
        s -= 2;
    }
    s
}

fn exts<'a>(c: &Cert<'a>) -> Option<Exts<'a>> {
    Exts::parse(c.extensions_tlv.as_ref()?).ok()
}

fn ski(c: &Cert) -> Option<Vec<u8>> {
    let x = exts(c)?;
    let ext = x.get(oid::EXT_SUBJECT_KEY_ID)?;
    crate::ext::subject_key_id(ext).ok().map(|v| v.to_vec())
}

fn aki_keyid(c: &Cert) -> Option<Vec<u8>> {
    let x = exts(c)?;
    let ext = x.get(oid::EXT_AUTHORITY_KEY_ID)?;
    AuthorityKeyId::parse(ext).ok()?.key_id.map(|v| v.to_vec())
}

fn key_usage(c: &Cert) -> Option<std::result::Result<KeyUsage, String>> {
    let x = exts(c)?;
    let e = x.get(oid::EXT_KEY_USAGE)?;
    Some(KeyUsage::parse(e).map_err(|e| e.msg))
}

// The purposes the certificate declares, or None when it declares none,
// which RFC 5280 reads as no restriction rather than as no purpose.
fn purposes(c: &Cert) -> Option<Vec<String>> {
    let x = exts(c)?;
    let e = x.get(oid::EXT_EXT_KEY_USAGE)?;
    let eku = ExtKeyUsage::parse(e).ok()?;
    Some(eku.purposes.iter().map(|p| p.dotted()).collect())
}

// The names --purpose takes, and the OID each one means.
pub fn purpose_oid(name: &str) -> Option<&'static str> {
    match name {
        "serverAuth" => Some(oid::KP_SERVER_AUTH),
        "clientAuth" => Some(oid::KP_CLIENT_AUTH),
        "codeSigning" => Some(oid::KP_CODE_SIGNING),
        "emailProtection" => Some(oid::KP_EMAIL_PROTECTION),
        "timeStamping" => Some(oid::KP_TIME_STAMPING),
        "OCSPSigning" => Some(oid::KP_OCSP_SIGNING),
        _ => None,
    }
}

// None when there is no basicConstraints at all, which for an issuer is
// its own failure and not a missing value to be defaulted.
fn basic_constraints(c: &Cert) -> Option<std::result::Result<BasicConstraints, String>> {
    let x = exts(c)?;
    let e = x.get(oid::EXT_BASIC_CONSTRAINTS)?;
    Some(BasicConstraints::parse(e).map_err(|e| e.msg))
}

impl<'a> Store<'a> {
    // Every certificate whose subject is this certificate's issuer, in the
    // order they should be tried.
    pub fn candidates(&self, child: &Cert, at: i64) -> Vec<usize> {
        let mut v: Vec<usize> = (0..self.certs.len())
            .filter(|i| {
                self.certs[*i].source != Source::Input
                    && subject_of(&self.certs[*i].cert) == child.issuer_der
            })
            .collect();
        v.sort_by_key(|i| (score(child, &self.certs[*i], at), *i));
        v
    }

    pub fn build(&self, leaf: usize, opt: &Options) -> Built {
        let mut out = Built {
            ok: false,
            path: Vec::new(),
            failures: Vec::new(),
            paths_tried: 0,
        };
        let mut chain = vec![leaf];
        self.search(&mut chain, opt, &mut out);
        out
    }

    fn search(&self, chain: &mut Vec<usize>, opt: &Options, out: &mut Built) {
        if out.ok || out.paths_tried >= opt.max_paths {
            return;
        }
        let tip = *chain.last().unwrap();
        let tipc = &self.certs[tip];
        // A trust anchor ends the path. An anchor given as input is still
        // an anchor: a self-signed certificate that is in the store is one
        // we were told to trust.
        if tipc.source == Source::Anchor && chain.len() > 1 {
            out.paths_tried += 1;
            match self.validate(chain, opt) {
                Ok(()) => {
                    out.ok = true;
                    out.path = chain.clone();
                }
                Err(f) => out.failures.push(f),
            }
            return;
        }
        if chain.len() > opt.max_depth {
            out.failures.push(Failure {
                depth: chain.len(),
                at_cert: self.certs[tip].label.clone(),
                reason: format!("the path is longer than {} certificates", opt.max_depth),
            });
            return;
        }
        let cands = self.candidates(&tipc.cert, opt.at);
        if cands.is_empty() {
            out.paths_tried += 1;
            out.failures.push(Failure {
                depth: chain.len() - 1,
                at_cert: tipc.label.clone(),
                reason: "no candidate issuer has this subject".to_string(),
            });
            return;
        }
        for c in cands {
            // A certificate may not appear twice in one path. Without this
            // a pair of cross-signed CAs is an infinite loop.
            if chain.contains(&c) {
                continue;
            }
            chain.push(c);
            self.search(chain, opt, out);
            chain.pop();
            if out.ok {
                return;
            }
        }
    }

    // RFC 5280 6.1, over a finished path. Leaf first, anchor last.
    fn validate(&self, chain: &[usize], opt: &Options) -> Result<(), Failure> {
        let fail = |depth: usize, label: &str, reason: String| Failure {
            depth,
            at_cert: label.to_string(),
            reason,
        };
        for (depth, idx) in chain.iter().enumerate() {
            let c = &self.certs[*idx];
            if opt.at < c.cert.not_before.epoch {
                return Err(fail(
                    depth,
                    &c.label,
                    format!("not valid until {}", c.cert.not_before.iso()),
                ));
            }
            if opt.at > c.cert.not_after.epoch {
                return Err(fail(
                    depth,
                    &c.label,
                    format!("expired at {}", c.cert.not_after.iso()),
                ));
            }
        }
        // Each certificate is signed by the one above it.
        for w in chain.windows(2) {
            let (child, issuer) = (&self.certs[w[0]], &self.certs[w[1]]);
            let spki = match Spki::parse(issuer.cert.spki_der) {
                Ok(s) => s,
                Err(e) => return Err(fail(0, &issuer.label, e.msg)),
            };
            match sig::verify(
                &spki,
                &child.cert.sig_alg,
                child.cert.tbs_der,
                child.cert.signature,
            ) {
                Verdict::Valid => {}
                Verdict::Invalid(w2) => {
                    return Err(fail(
                        0,
                        &child.label,
                        format!("the signature does not verify: {}", w2),
                    ))
                }
                Verdict::Unsupported(w2) => {
                    return Err(fail(0, &child.label, format!("unsupported: {}", w2)))
                }
            }
        }
        // RFC 5280 6.1.4 (k) and (l). Every certificate that issues
        // another one in this path has to say it is a CA, and each one's
        // pathLenConstraint bounds the number of non-self-issued
        // intermediates below it. The count excludes self-issued
        // certificates, which is what makes a key rollover certificate
        // free, and it excludes the leaf, which is not an intermediate.
        //
        // The anchor is included. RFC 5280 leaves the anchor's own
        // constraints to the implementation, and both oracles apply
        // them: openssl refuses leaf-deep at depth 3 as well as at
        // depth 2.
        let mut intermediates: u64 = 0;
        for (depth, idx) in chain.iter().enumerate().skip(1) {
            let c = &self.certs[*idx];
            match basic_constraints(&c.cert) {
                None => {
                    return Err(fail(
                        depth,
                        &c.label,
                        "issues a certificate and has no basicConstraints".to_string(),
                    ))
                }
                Some(Err(m)) => {
                    return Err(fail(
                        depth,
                        &c.label,
                        format!("basicConstraints does not decode: {}", m),
                    ))
                }
                Some(Ok(bc)) => {
                    if !bc.ca {
                        return Err(fail(
                            depth,
                            &c.label,
                            "issues a certificate and is not a CA".to_string(),
                        ));
                    }
                    if let Some(n) = bc.path_len {
                        if intermediates > n {
                            return Err(fail(
                                depth,
                                &c.label,
                                format!(
                                    "pathLenConstraint is {} and {} intermediate \
                                     certificates are below it",
                                    n, intermediates
                                ),
                            ));
                        }
                    }
                }
            }
            // RFC 5280 6.1.4 (n). An issuer that says what its key is for
            // has to say certificate signing is one of them. An issuer
            // with no keyUsage at all is unrestricted, which is the
            // reading every implementation takes.
            match key_usage(&c.cert) {
                Some(Err(m)) => {
                    return Err(fail(
                        depth,
                        &c.label,
                        format!("keyUsage does not decode: {}", m),
                    ))
                }
                Some(Ok(ku)) if !ku.has(KU_KEY_CERT_SIGN) => {
                    return Err(fail(
                        depth,
                        &c.label,
                        "issues a certificate and its keyUsage has no keyCertSign"
                            .to_string(),
                    ))
                }
                _ => {}
            }
            if !is_self_issued(&c.cert) {
                intermediates += 1;
            }
        }
        // The purpose, over every certificate in the path. An EKU on a CA
        // restricts what that CA may issue, so the check is not only on
        // the leaf; a certificate with no EKU is unrestricted, and
        // anyExtendedKeyUsage is the same thing written down.
        if let Some(name) = &opt.purpose {
            let want = match purpose_oid(name) {
                Some(o) => o,
                None => {
                    return Err(fail(
                        0,
                        &self.certs[chain[0]].label,
                        format!("{} is not a purpose certlint knows", name),
                    ))
                }
            };
            for (depth, idx) in chain.iter().enumerate() {
                let c = &self.certs[*idx];
                if let Some(ps) = purposes(&c.cert) {
                    if !ps.iter().any(|p| p == want || p == oid::KP_ANY) {
                        return Err(fail(
                            depth,
                            &c.label,
                            format!("its extendedKeyUsage does not include {}", name),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}
