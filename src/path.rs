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
use crate::ext::{AuthorityKeyId, Exts};
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

fn ski(c: &Cert) -> Option<Vec<u8>> {
    let e = c.extensions_tlv.as_ref()?;
    let x = Exts::parse(e).ok()?;
    let ext = x.get(oid::EXT_SUBJECT_KEY_ID)?;
    crate::ext::subject_key_id(ext).ok().map(|v| v.to_vec())
}

fn aki_keyid(c: &Cert) -> Option<Vec<u8>> {
    let e = c.extensions_tlv.as_ref()?;
    let x = Exts::parse(e).ok()?;
    let ext = x.get(oid::EXT_AUTHORITY_KEY_ID)?;
    AuthorityKeyId::parse(ext).ok()?.key_id.map(|v| v.to_vec())
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
        let _ = is_self_issued;
        Ok(())
    }
}
