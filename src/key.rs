// SubjectPublicKeyInfo.
//
//   SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
//                                       subjectPublicKey BIT STRING }
//
// The BIT STRING holds another encoding for RSA and raw point octets for
// EC, which is the one place in a certificate where a structure hides
// inside an unparsed field and a decoder can get away with never looking.
// Here it is decoded far enough to state the key size and to hand the
// verifier the numbers it needs.

use crate::cert::AlgId;
use crate::der::{err, Oid, Reader, Result, CLASS_UNIVERSAL, T_BIT_STRING, T_SEQUENCE};
use crate::oid;

pub enum Key<'a> {
    Rsa {
        // Both as magnitudes, leading zero removed, which is the form the
        // modular arithmetic wants.
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    },
    Ec {
        curve: Oid,
        // The uncompressed point, 0x04 || X || Y, as encoded.
        point: &'a [u8],
    },
    // A key whose algorithm we know by OID and do not decode. Named rather
    // than guessed at, and counted as a refusal wherever it matters.
    Opaque {
        bits: &'a [u8],
    },
}

pub struct Spki<'a> {
    pub alg: AlgId<'a>,
    pub key: Key<'a>,
}

fn curve_bits(curve: &Oid) -> Option<usize> {
    let d = curve.dotted();
    if d == oid::SECP256R1 || d == oid::SECP256K1 {
        Some(256)
    } else if d == oid::SECP384R1 {
        Some(384)
    } else if d == oid::SECP521R1 {
        Some(521)
    } else {
        None
    }
}

impl<'a> Spki<'a> {
    pub fn parse(der: &'a [u8]) -> Result<Spki<'a>> {
        let outer = Reader::new(der).read_only_tlv()?;
        outer.expect(CLASS_UNIVERSAL, T_SEQUENCE, "SubjectPublicKeyInfo")?;
        let mut r = outer.reader();
        let alg = AlgId::parse(&r.read_tlv()?)?;
        let bs = r.read_tlv()?;
        bs.expect(CLASS_UNIVERSAL, T_BIT_STRING, "subjectPublicKey")?;
        r.expect_empty("SubjectPublicKeyInfo")?;
        if bs.value.is_empty() {
            return err(bs.start, "subjectPublicKey has no octets at all");
        }
        if bs.value[0] != 0 {
            return err(
                bs.start,
                format!("subjectPublicKey has {} unused bits", bs.value[0]),
            );
        }
        let bits = &bs.value[1..];
        let d = alg.oid.dotted();
        let key = if d == oid::RSA_ENCRYPTION {
            // RFC 3279: the parameters field MUST be NULL for rsaEncryption.
            match &alg.params {
                Some(p) => p.null()?,
                None => return err(outer.start, "rsaEncryption with no parameters field"),
            }
            let seq = Reader::with_origin(bits, bs.start + bs.hlen + 1).read_only_tlv()?;
            seq.expect(CLASS_UNIVERSAL, T_SEQUENCE, "RSAPublicKey")?;
            let mut kr = seq.reader();
            let m = kr.read_tlv()?;
            let e = kr.read_tlv()?;
            kr.expect_empty("RSAPublicKey")?;
            if m.integer_is_negative()? {
                return err(m.start, "the RSA modulus is negative");
            }
            if e.integer_is_negative()? {
                return err(e.start, "the RSA public exponent is negative");
            }
            Key::Rsa {
                modulus: m.integer_magnitude()?,
                exponent: e.integer_magnitude()?,
            }
        } else if d == oid::EC_PUBLIC_KEY {
            let p = match &alg.params {
                Some(p) => p,
                None => return err(outer.start, "an EC key with no parameters"),
            };
            // RFC 5480 says the parameters are a named curve for anything
            // that belongs in a certificate. An implicit or specified curve
            // is refused by name rather than decoded.
            let curve = p.oid().map_err(|_| crate::der::Error {
                at: p.start,
                msg: "EC parameters are not a named curve OID".to_string(),
            })?;
            if bits.is_empty() {
                return err(bs.start, "an EC key with no point octets");
            }
            if bits[0] != 0x04 {
                return err(
                    bs.start,
                    format!(
                        "EC point format 0x{:02x}; only the uncompressed form is decoded",
                        bits[0]
                    ),
                );
            }
            if let Some(b) = curve_bits(&curve) {
                let want = 1 + 2 * ((b + 7) / 8);
                if bits.len() != want {
                    return err(
                        bs.start,
                        format!(
                            "an uncompressed point on this curve is {} octets, this is {}",
                            want,
                            bits.len()
                        ),
                    );
                }
            }
            Key::Ec {
                curve,
                point: bits,
            }
        } else {
            Key::Opaque { bits }
        };
        Ok(Spki {
            alg,
            key,
        })
    }

    // The size everybody prints: the modulus length for RSA, the field size
    // for EC. Both in bits, and both are the number cryptography's key_size
    // returns, which is what the comparison is against.
    pub fn key_bits(&self) -> Option<usize> {
        match &self.key {
            Key::Rsa { modulus, .. } => match modulus.iter().position(|b| *b != 0) {
                Some(i) => Some((modulus.len() - i) * 8 - modulus[i].leading_zeros() as usize),
                None => Some(0),
            },
            Key::Ec { curve, .. } => curve_bits(curve),
            Key::Opaque { .. } => None,
        }
    }

    pub fn algorithm_name(&self) -> String {
        oid::name_or_dotted(&self.alg.oid)
    }
}
