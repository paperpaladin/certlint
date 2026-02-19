// Extensions.
//
//   Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER,
//                            critical BOOLEAN DEFAULT FALSE,
//                            extnValue OCTET STRING }
//
// The container first. Each extension's own structure is decoded on
// demand, because an extension certlint does not understand must still be
// listed, and a critical one it does not understand must still change the
// verdict. RFC 5280 6.1.4 is explicit about that, and it is the rule a
// linter is most tempted to drop.

use crate::der::{err, Oid, Reader, Result, Tlv, CLASS_UNIVERSAL};
use crate::der::{T_BOOLEAN, T_OCTET_STRING, T_SEQUENCE};

pub struct Ext<'a> {
    pub oid: Oid,
    pub critical: bool,
    // The contents of the extnValue OCTET STRING: the extension's own DER.
    pub value: &'a [u8],
    // The offset of the OCTET STRING's contents in the file, so that an
    // error inside an extension can name where it is.
    pub value_at: usize,
    // DER forbids encoding a DEFAULT at its default value, so a critical
    // field spelled FALSE is an encoding error. Recorded, not refused.
    pub critical_explicit_false: bool,
}

pub struct Exts<'a> {
    pub list: Vec<Ext<'a>>,
}

impl<'a> Exts<'a> {
    pub fn parse(tlv: &Tlv<'a>) -> Result<Exts<'a>> {
        tlv.expect(CLASS_UNIVERSAL, T_SEQUENCE, "Extensions")?;
        let mut r = tlv.reader();
        let mut list = Vec::new();
        if r.is_empty() {
            return err(tlv.start, "the extensions field is present and empty");
        }
        while !r.is_empty() {
            let e = r.read_tlv()?;
            e.expect(CLASS_UNIVERSAL, T_SEQUENCE, "an Extension")?;
            let mut er = e.reader();
            let oid = er.read_tlv()?.oid()?;
            let mut critical = false;
            let mut critical_explicit_false = false;
            let mut next = er.read_tlv()?;
            if next.tag.is(CLASS_UNIVERSAL, T_BOOLEAN) {
                critical = next.boolean()?;
                critical_explicit_false = !critical;
                next = er.read_tlv()?;
            }
            next.expect(CLASS_UNIVERSAL, T_OCTET_STRING, "extnValue")?;
            if next.tag.constructed {
                return err(next.start, "a constructed extnValue is BER, not DER");
            }
            er.expect_empty("an Extension")?;
            list.push(Ext {
                oid,
                critical,
                value: next.value,
                value_at: next.start + next.hlen,
                critical_explicit_false,
            });
        }
        Ok(Exts { list })
    }

    pub fn get(&self, dotted: &str) -> Option<&Ext<'a>> {
        self.list.iter().find(|e| e.oid.dotted() == dotted)
    }

    pub fn count(&self, dotted: &str) -> usize {
        self.list.iter().filter(|e| e.oid.dotted() == dotted).count()
    }

    // RFC 5280 4.2: a certificate must not include more than one instance
    // of an extension. Returned as a list so the linter can name them.
    pub fn duplicates(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        let mut dup: Vec<String> = Vec::new();
        for e in &self.list {
            let d = e.oid.dotted();
            if seen.contains(&d) {
                if !dup.contains(&d) {
                    dup.push(d.clone());
                }
            } else {
                seen.push(d);
            }
        }
        dup
    }
}

impl<'a> Ext<'a> {
    // A reader over the extension's own DER, with offsets that still point
    // into the file.
    pub fn reader(&self) -> Reader<'a> {
        Reader::with_origin(self.value, self.value_at)
    }

    // Every extension's value is a single DER value filling the OCTET
    // STRING. Trailing bytes after it are a defect, not padding.
    pub fn only_tlv(&self) -> Result<Tlv<'a>> {
        self.reader().read_only_tlv()
    }
}

// ---------------------------------------------------------------------------
// BasicConstraints
//
//   BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
//                                   pathLenConstraint INTEGER (0..MAX) OPTIONAL }

pub struct BasicConstraints {
    pub ca: bool,
    pub path_len: Option<u64>,
    // cA is a DEFAULT, so encoding it as FALSE is a DER error. Every
    // implementation accepts it and openssl itself emits it for a leaf, so
    // it is recorded for the linter.
    pub ca_explicit_false: bool,
}

impl BasicConstraints {
    pub fn parse(e: &Ext) -> Result<BasicConstraints> {
        let tlv = e.only_tlv()?;
        tlv.expect(CLASS_UNIVERSAL, T_SEQUENCE, "BasicConstraints")?;
        let mut r = tlv.reader();
        let mut ca = false;
        let mut ca_explicit_false = false;
        let mut path_len = None;
        if !r.is_empty() {
            let first = r.read_tlv()?;
            let next = if first.tag.is(CLASS_UNIVERSAL, T_BOOLEAN) {
                ca = first.boolean()?;
                ca_explicit_false = !ca;
                if r.is_empty() {
                    None
                } else {
                    Some(r.read_tlv()?)
                }
            } else {
                Some(first)
            };
            if let Some(n) = next {
                n.expect(CLASS_UNIVERSAL, crate::der::T_INTEGER, "pathLenConstraint")?;
                if n.integer_is_negative()? {
                    return err(n.start, "a negative pathLenConstraint");
                }
                path_len = Some(n.integer_u64()?);
            }
        }
        r.expect_empty("BasicConstraints")?;
        Ok(BasicConstraints {
            ca,
            path_len,
            ca_explicit_false,
        })
    }
}

// ---------------------------------------------------------------------------
// KeyUsage
//
//   KeyUsage ::= BIT STRING { digitalSignature (0), ... decipherOnly (8) }
//
// Nine bits, so a certificate that uses decipherOnly needs two octets and
// one that does not needs one. The bit that gets dropped is therefore the
// last one, by a decoder that reads a single octet and stops.

pub const KEY_USAGE_NAMES: [&str; 9] = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
];

pub struct KeyUsage {
    pub bits: [bool; 9],
    pub declared_bits: usize,
    // DER wants the trailing zero bits of a named-bit BIT STRING removed.
    pub not_minimal: bool,
}

impl KeyUsage {
    pub fn parse(e: &Ext) -> Result<KeyUsage> {
        let tlv = e.only_tlv()?;
        let bs = tlv.bit_string()?;
        if bs.bits > 9 {
            return err(tlv.start, format!("KeyUsage has {} bits, the type has 9", bs.bits));
        }
        let mut bits = [false; 9];
        for (i, b) in bits.iter_mut().enumerate() {
            *b = bs.get(i);
        }
        Ok(KeyUsage {
            bits,
            declared_bits: bs.bits,
            not_minimal: bs.trailing_zero_bit,
        })
    }

    pub fn names(&self) -> Vec<&'static str> {
        KEY_USAGE_NAMES
            .iter()
            .enumerate()
            .filter(|(i, _)| self.bits[*i])
            .map(|(_, n)| *n)
            .collect()
    }

    pub fn has(&self, i: usize) -> bool {
        self.bits[i]
    }
}

pub const KU_DIGITAL_SIGNATURE: usize = 0;
pub const KU_KEY_ENCIPHERMENT: usize = 2;
pub const KU_KEY_AGREEMENT: usize = 4;
pub const KU_KEY_CERT_SIGN: usize = 5;
pub const KU_CRL_SIGN: usize = 6;

// ---------------------------------------------------------------------------
// ExtendedKeyUsage
//
//   ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
//
// anyExtendedKeyUsage is an OID like any other here. RFC 5280 says a
// certificate with it should be treated as having no EKU restriction at
// all, which is a decision for the purpose check and not for the decoder.

pub struct ExtKeyUsage {
    pub purposes: Vec<Oid>,
}

impl ExtKeyUsage {
    pub fn parse(e: &Ext) -> Result<ExtKeyUsage> {
        let tlv = e.only_tlv()?;
        tlv.expect(CLASS_UNIVERSAL, T_SEQUENCE, "ExtKeyUsageSyntax")?;
        let mut r = tlv.reader();
        let mut purposes = Vec::new();
        while !r.is_empty() {
            purposes.push(r.read_tlv()?.oid()?);
        }
        if purposes.is_empty() {
            return err(tlv.start, "an empty ExtendedKeyUsage");
        }
        Ok(ExtKeyUsage { purposes })
    }

    pub fn has(&self, dotted: &str) -> bool {
        self.purposes.iter().any(|p| p.dotted() == dotted)
    }
}

// ---------------------------------------------------------------------------
// NameConstraints
//
//   NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees
//                                                        OPTIONAL,
//                                  excludedSubtrees  [1] GeneralSubtrees
//                                                        OPTIONAL }
//   GeneralSubtree ::= SEQUENCE { base GeneralName,
//                                 minimum [0] BaseDistance DEFAULT 0,
//                                 maximum [1] BaseDistance OPTIONAL }
//
// RFC 5280 4.2.1.10 requires minimum to be absent and maximum to be absent.
// They are parsed anyway, because a certificate that carries them is one
// the linter should report, and a decoder that refuses them cannot report
// anything.

use crate::gname::GeneralName;

pub struct Subtree<'a> {
    pub base: GeneralName<'a>,
    pub minimum: Option<u64>,
    pub maximum: Option<u64>,
}

pub struct NameConstraints<'a> {
    pub permitted: Vec<Subtree<'a>>,
    pub excluded: Vec<Subtree<'a>>,
}

fn parse_subtrees<'a>(tlv: &Tlv<'a>) -> Result<Vec<Subtree<'a>>> {
    let mut r = tlv.reader();
    let mut out = Vec::new();
    while !r.is_empty() {
        let st = r.read_tlv()?;
        st.expect(CLASS_UNIVERSAL, T_SEQUENCE, "a GeneralSubtree")?;
        let mut sr = st.reader();
        let base = GeneralName::parse(&sr.read_tlv()?)?;
        let mut minimum = None;
        let mut maximum = None;
        while !sr.is_empty() {
            let x = sr.read_tlv()?;
            match (x.tag.class, x.tag.number, x.tag.constructed) {
                (crate::der::CLASS_CONTEXT, 0, false) => {
                    minimum = Some(int_from_implicit(&x)?)
                }
                (crate::der::CLASS_CONTEXT, 1, false) => {
                    maximum = Some(int_from_implicit(&x)?)
                }
                _ => {
                    return err(
                        x.start,
                        format!("unexpected {} in a GeneralSubtree", x.tag.name()),
                    )
                }
            }
        }
        out.push(Subtree {
            base,
            minimum,
            maximum,
        });
    }
    if out.is_empty() {
        return err(tlv.start, "an empty GeneralSubtrees");
    }
    Ok(out)
}

// A BaseDistance carries an implicit context tag, so its content octets
// are an INTEGER's without the INTEGER tag in front of them.
fn int_from_implicit(tlv: &Tlv) -> Result<u64> {
    let v = tlv.value;
    if v.is_empty() {
        return err(tlv.start, "an empty BaseDistance");
    }
    if v[0] & 0x80 != 0 {
        return err(tlv.start, "a negative BaseDistance");
    }
    if v.len() > 8 {
        return err(tlv.start, "a BaseDistance that does not fit in 64 bits");
    }
    let mut n = 0u64;
    for b in v {
        n = (n << 8) | u64::from(*b);
    }
    Ok(n)
}

impl<'a> NameConstraints<'a> {
    pub fn parse(e: &Ext<'a>) -> Result<NameConstraints<'a>> {
        let tlv = e.only_tlv()?;
        tlv.expect(CLASS_UNIVERSAL, T_SEQUENCE, "NameConstraints")?;
        let mut r = tlv.reader();
        let mut permitted = Vec::new();
        let mut excluded = Vec::new();
        while !r.is_empty() {
            let x = r.read_tlv()?;
            match (x.tag.class, x.tag.number) {
                (crate::der::CLASS_CONTEXT, 0) => permitted = parse_subtrees(&x)?,
                (crate::der::CLASS_CONTEXT, 1) => excluded = parse_subtrees(&x)?,
                _ => {
                    return err(
                        x.start,
                        format!("unexpected {} in NameConstraints", x.tag.name()),
                    )
                }
            }
        }
        if permitted.is_empty() && excluded.is_empty() {
            return err(tlv.start, "a NameConstraints with neither subtree");
        }
        Ok(NameConstraints {
            permitted,
            excluded,
        })
    }
}
