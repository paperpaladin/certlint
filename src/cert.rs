// The certificate itself.
//
//   Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
//                              signatureValue BIT STRING }
//
// Everything that is not decoded yet is kept as the slice it occupies, so a
// later pass can decode it and so the signature can be checked over exactly
// the bytes that were signed. Re-encoding the TBS and hoping it comes out
// the same is how a verifier ends up checking a signature over something
// the issuer never saw.

use crate::der::{err, Oid, Reader, Result, Tag, Tlv, CLASS_CONTEXT, CLASS_UNIVERSAL};
use crate::der::{T_BIT_STRING, T_INTEGER, T_SEQUENCE};
use crate::time::Time;

#[derive(Debug, Clone)]
pub struct AlgId<'a> {
    pub oid: Oid,
    pub params: Option<Tlv<'a>>,
}

impl<'a> AlgId<'a> {
    pub fn parse(tlv: &Tlv<'a>) -> Result<AlgId<'a>> {
        tlv.expect(CLASS_UNIVERSAL, T_SEQUENCE, "AlgorithmIdentifier")?;
        let mut r = tlv.reader();
        let oid = r.read_tlv()?.oid()?;
        let params = if r.is_empty() {
            None
        } else {
            Some(r.read_tlv()?)
        };
        r.expect_empty("AlgorithmIdentifier")?;
        Ok(AlgId { oid, params })
    }
}

pub struct Cert<'a> {
    pub der: &'a [u8],
    // The exact bytes the signature covers, tag and length included.
    pub tbs_der: &'a [u8],
    pub version: u8,
    // True when the version field is present and says v1, which DER forbids
    // because v1 is the DEFAULT.
    pub version_redundant: bool,
    pub serial: Tlv<'a>,
    pub tbs_sig_alg: AlgId<'a>,
    pub sig_alg: AlgId<'a>,
    pub issuer_der: &'a [u8],
    pub subject_der: &'a [u8],
    pub not_before: Time,
    pub not_after: Time,
    pub spki_der: &'a [u8],
    pub issuer_unique_id: Option<Tlv<'a>>,
    pub subject_unique_id: Option<Tlv<'a>>,
    pub extensions_tlv: Option<Tlv<'a>>,
    // The signature value, with the BIT STRING's unused-bits octet removed.
    pub signature: &'a [u8],
}

fn whole<'a>(tlv: &Tlv<'a>, der: &'a [u8]) -> &'a [u8] {
    &der[tlv.start..tlv.end()]
}

impl<'a> Cert<'a> {
    pub fn parse(der: &'a [u8]) -> Result<Cert<'a>> {
        let outer = Reader::new(der).read_only_tlv()?;
        outer.expect(CLASS_UNIVERSAL, T_SEQUENCE, "Certificate")?;
        let mut c = outer.reader();

        let tbs = c.read_tlv()?;
        tbs.expect(CLASS_UNIVERSAL, T_SEQUENCE, "TBSCertificate")?;
        let tbs_der = whole(&tbs, der);
        let mut t = tbs.reader();

        // version [0] EXPLICIT Version DEFAULT v1
        let mut next = t.read_tlv()?;
        let mut version = 1u8;
        let mut version_redundant = false;
        if next.tag == Tag::context(0, true) {
            let mut vr = next.reader();
            let v = vr.read_tlv()?;
            vr.expect_empty("the version field")?;
            let n = v.integer_u64()?;
            if n > 2 {
                return err(v.start, format!("version {} is not 1, 2 or 3", n + 1));
            }
            version = n as u8 + 1;
            version_redundant = n == 0;
            next = t.read_tlv()?;
        }

        let serial = next;
        serial.expect(CLASS_UNIVERSAL, T_INTEGER, "the serial number")?;
        serial.integer()?;

        let tbs_sig_alg = AlgId::parse(&t.read_tlv()?)?;

        let issuer = t.read_tlv()?;
        issuer.expect(CLASS_UNIVERSAL, T_SEQUENCE, "the issuer Name")?;
        let issuer_der = whole(&issuer, der);

        let validity = t.read_tlv()?;
        validity.expect(CLASS_UNIVERSAL, T_SEQUENCE, "Validity")?;
        let mut vr = validity.reader();
        let not_before = Time::parse(&vr.read_tlv()?)?;
        let not_after = Time::parse(&vr.read_tlv()?)?;
        vr.expect_empty("Validity")?;

        let subject = t.read_tlv()?;
        subject.expect(CLASS_UNIVERSAL, T_SEQUENCE, "the subject Name")?;
        let subject_der = whole(&subject, der);

        let spki = t.read_tlv()?;
        spki.expect(CLASS_UNIVERSAL, T_SEQUENCE, "SubjectPublicKeyInfo")?;
        let spki_der = whole(&spki, der);

        let mut issuer_unique_id = None;
        let mut subject_unique_id = None;
        let mut extensions_tlv = None;
        while !t.is_empty() {
            let x = t.read_tlv()?;
            match (x.tag.class, x.tag.number) {
                (CLASS_CONTEXT, 1) => issuer_unique_id = Some(x),
                (CLASS_CONTEXT, 2) => subject_unique_id = Some(x),
                (CLASS_CONTEXT, 3) => {
                    let mut er = x.reader();
                    let inner = er.read_tlv()?;
                    inner.expect(CLASS_UNIVERSAL, T_SEQUENCE, "Extensions")?;
                    er.expect_empty("the extensions field")?;
                    extensions_tlv = Some(inner);
                }
                _ => {
                    return err(
                        x.start,
                        format!("unexpected {} in TBSCertificate", x.tag.name()),
                    )
                }
            }
        }
        if version < 3 && extensions_tlv.is_some() {
            return err(tbs.start, "extensions in a certificate below version 3");
        }
        if version < 2 && (issuer_unique_id.is_some() || subject_unique_id.is_some()) {
            return err(tbs.start, "a unique identifier in a version 1 certificate");
        }

        let sig_alg = AlgId::parse(&c.read_tlv()?)?;
        let sig = c.read_tlv()?;
        sig.expect(CLASS_UNIVERSAL, T_BIT_STRING, "the signature value")?;
        c.expect_empty("Certificate")?;
        if sig.value.is_empty() {
            return err(sig.start, "the signature BIT STRING has no octets at all");
        }
        if sig.value[0] != 0 {
            return err(
                sig.start,
                format!("the signature BIT STRING has {} unused bits", sig.value[0]),
            );
        }
        let signature = &sig.value[1..];

        Ok(Cert {
            der,
            tbs_der,
            version,
            version_redundant,
            serial,
            tbs_sig_alg,
            sig_alg,
            issuer_der,
            subject_der,
            not_before,
            not_after,
            spki_der,
            issuer_unique_id,
            subject_unique_id,
            extensions_tlv,
            signature,
        })
    }

    // RFC 5280 4.1.1.2: the two algorithm identifiers must match. They are
    // compared as encodings, parameters included, because that is what
    // "contain the same algorithm identifier" means.
    pub fn algorithms_match(&self) -> bool {
        self.tbs_sig_alg.oid == self.sig_alg.oid
            && match (&self.tbs_sig_alg.params, &self.sig_alg.params) {
                (None, None) => true,
                (Some(a), Some(b)) => {
                    a.tag == b.tag && a.value == b.value
                }
                _ => false,
            }
    }
}
