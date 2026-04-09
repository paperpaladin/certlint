// Signature verification.
//
// Two families: RSA PKCS#1 v1.5, and ECDSA over a prime curve. Both are
// written out here because there is no crate.
//
// The PKCS#1 v1.5 check is by re-encoding, not by parsing. The verifier
// builds the exact octet string the signer should have produced and
// compares it with what came out of the modular exponentiation. Parsing
// the recovered block instead is how a verifier ends up accepting padding
// with the wrong number of 0xff octets, or a DigestInfo with trailing
// rubbish after the digest, which is the shape of every Bleichenbacher
// signature forgery.

use crate::bignum::{self, Mont};
use crate::cert::AlgId;
use crate::hash::{self, Alg};
use crate::key::{Key, Spki};
use crate::oid;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    Invalid(String),
    // The algorithm is one certlint does not implement. Counted apart from
    // a bad signature everywhere, because "we cannot check this" and "this
    // is forged" are not the same answer.
    Unsupported(String),
}

impl Verdict {
    pub fn text(&self) -> String {
        match self {
            Verdict::Valid => "valid".to_string(),
            Verdict::Invalid(w) => format!("invalid ({})", w),
            Verdict::Unsupported(w) => format!("unsupported ({})", w),
        }
    }
}

// The digest a signature algorithm OID implies, and the family it belongs
// to.
pub fn digest_of(alg: &AlgId) -> Option<(Alg, bool)> {
    let d = alg.oid.dotted();
    let rsa = |a| Some((a, true));
    let ec = |a| Some((a, false));
    if d == oid::SHA1_RSA {
        rsa(Alg::Sha1)
    } else if d == oid::SHA256_RSA {
        rsa(Alg::Sha256)
    } else if d == oid::SHA384_RSA {
        rsa(Alg::Sha384)
    } else if d == oid::SHA512_RSA {
        rsa(Alg::Sha512)
    } else if d == oid::ECDSA_SHA1 {
        ec(Alg::Sha1)
    } else if d == oid::ECDSA_SHA256 {
        ec(Alg::Sha256)
    } else if d == oid::ECDSA_SHA384 {
        ec(Alg::Sha384)
    } else if d == oid::ECDSA_SHA512 {
        ec(Alg::Sha512)
    } else {
        None
    }
}

// The DER of DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING },
// built by hand because it is the thing being compared against.
fn digest_info(alg: Alg, digest: &[u8]) -> Vec<u8> {
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if body.len() < 0x80 {
            v.push(body.len() as u8);
        } else {
            v.push(0x81);
            v.push(body.len() as u8);
        }
        v.extend_from_slice(body);
        v
    }
    fn oid_der(dotted: &str) -> Vec<u8> {
        let parts: Vec<u64> = dotted.split('.').map(|p| p.parse().unwrap_or(0)).collect();
        let mut body = vec![(parts[0] * 40 + parts[1]) as u8];
        for p in &parts[2..] {
            let mut chunk = vec![(p & 0x7f) as u8];
            let mut v = p >> 7;
            while v > 0 {
                chunk.insert(0, 0x80 | (v & 0x7f) as u8);
                v >>= 7;
            }
            body.extend_from_slice(&chunk);
        }
        tlv(0x06, &body)
    }
    let digest_oid = match alg {
        Alg::Sha1 => oid::SHA1,
        Alg::Sha256 => oid::SHA256,
        Alg::Sha384 => oid::SHA384,
        Alg::Sha512 => oid::SHA512,
    };
    let mut inner = oid_der(digest_oid);
    inner.extend_from_slice(&tlv(0x05, &[]));
    let mut body = tlv(0x30, &inner);
    body.extend_from_slice(&tlv(0x04, digest));
    tlv(0x30, &body)
}

fn rsa_verify(
    modulus: &[u8],
    exponent: &[u8],
    alg: Alg,
    message: &[u8],
    signature: &[u8],
) -> Verdict {
    let k = modulus.len();
    if signature.len() != k {
        return Verdict::Invalid(format!(
            "the signature is {} octets and the modulus is {}",
            signature.len(),
            k
        ));
    }
    let n = bignum::from_be(modulus);
    let mont = match Mont::new(&n) {
        Some(m) => m,
        None => return Verdict::Invalid("the modulus is even".to_string()),
    };
    let s = bignum::from_be(signature);
    if bignum::cmp(&s, &n) != std::cmp::Ordering::Less {
        return Verdict::Invalid("the signature is not less than the modulus".to_string());
    }
    let m = mont.pow(&s, exponent);
    let got = bignum::to_be(&m, k);

    let di = digest_info(alg, &hash::digest(alg, message));
    if k < di.len() + 11 {
        return Verdict::Invalid("the modulus is too small for this digest".to_string());
    }
    let mut want = Vec::with_capacity(k);
    want.push(0x00);
    want.push(0x01);
    want.resize(k - di.len() - 1, 0xff);
    want.push(0x00);
    want.extend_from_slice(&di);
    if want == got {
        Verdict::Valid
    } else {
        Verdict::Invalid("the recovered block is not the expected encoding".to_string())
    }
}

pub fn verify(spki: &Spki, alg: &AlgId, message: &[u8], signature: &[u8]) -> Verdict {
    let (digest, is_rsa) = match digest_of(alg) {
        Some(x) => x,
        None => {
            return Verdict::Unsupported(format!(
                "signature algorithm {}",
                oid::name_or_dotted(&alg.oid)
            ))
        }
    };
    match (&spki.key, is_rsa) {
        (Key::Rsa { modulus, exponent }, true) => {
            // RFC 4055: the parameters of an RSA signature algorithm are
            // NULL, and an absent parameters field is a different encoding
            // that some signers emit. Both are accepted; anything else is
            // not, because it would mean a different algorithm.
            if let Some(p) = &alg.params {
                if p.null().is_err() {
                    return Verdict::Invalid(
                        "the signature algorithm parameters are not NULL".to_string(),
                    );
                }
            }
            rsa_verify(modulus, exponent, digest, message, signature)
        }
        (Key::Ec { .. }, false) => {
            Verdict::Unsupported("ECDSA is not implemented yet".to_string())
        }
        (Key::Rsa { .. }, false) | (Key::Ec { .. }, true) => Verdict::Invalid(
            "the signature algorithm does not match the key".to_string(),
        ),
        (Key::Opaque { .. }, _) => {
            Verdict::Unsupported(format!("public key algorithm {}", spki.algorithm_name()))
        }
    }
}
