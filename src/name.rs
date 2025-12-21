// Distinguished names.
//
//   Name ::= RDNSequence
//   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//   RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
//   AttributeTypeAndValue ::= SEQUENCE { type AttributeType, value ANY }
//
// Three things make a DN harder than it looks. The value is ANY, so its
// type is per attribute and a decoder cannot assume a string. The SET is a
// SET OF, so DER fixes its order by encoding and an out-of-order one is
// malformed even though every reader will accept it. And the printed form
// is in the reverse of the encoded order, so the string a person reads and
// the bytes a verifier compares run in opposite directions.

use crate::der::{err, is_string_tag, Oid, Reader, Result, Tlv, CLASS_UNIVERSAL};
use crate::der::{T_SEQUENCE, T_SET};
use crate::oid;

pub struct Atv<'a> {
    pub oid: Oid,
    pub value: Tlv<'a>,
    // The decoded text, where the value is a string type at all.
    pub text: Option<String>,
}

pub struct Name<'a> {
    pub der: &'a [u8],
    // In encoded order, each entry being one RDN's attributes.
    pub rdns: Vec<Vec<Atv<'a>>>,
    // DER wants the members of a SET OF sorted by their encodings. Recorded
    // rather than refused: it is a finding about the certificate, and every
    // implementation in the world reads one of these anyway.
    pub set_ordered: bool,
}

impl<'a> Name<'a> {
    pub fn parse(der: &'a [u8]) -> Result<Name<'a>> {
        let outer = Reader::new(der).read_only_tlv()?;
        outer.expect(CLASS_UNIVERSAL, T_SEQUENCE, "a Name")?;
        let mut r = outer.reader();
        let mut rdns = Vec::new();
        let mut set_ordered = true;
        while !r.is_empty() {
            let set = r.read_tlv()?;
            set.expect(CLASS_UNIVERSAL, T_SET, "a RelativeDistinguishedName")?;
            let mut sr = set.reader();
            let mut atvs = Vec::new();
            let mut prev: Option<&[u8]> = None;
            while !sr.is_empty() {
                let atv = sr.read_tlv()?;
                atv.expect(CLASS_UNIVERSAL, T_SEQUENCE, "an AttributeTypeAndValue")?;
                let whole = &der[atv.start..atv.end()];
                if let Some(p) = prev {
                    if p > whole {
                        set_ordered = false;
                    }
                }
                prev = Some(whole);
                let mut ar = atv.reader();
                let oid = ar.read_tlv()?.oid()?;
                let value = ar.read_tlv()?;
                ar.expect_empty("an AttributeTypeAndValue")?;
                let text = if is_string_tag(value.tag.number)
                    && value.tag.class == CLASS_UNIVERSAL
                {
                    Some(value.string_text()?)
                } else {
                    None
                };
                atvs.push(Atv { oid, value, text });
            }
            if atvs.is_empty() {
                return err(set.start, "an empty RelativeDistinguishedName");
            }
            rdns.push(atvs);
        }
        Ok(Name {
            der,
            rdns,
            set_ordered,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }

    pub fn attribute_count(&self) -> usize {
        self.rdns.iter().map(|r| r.len()).sum()
    }

    // Every attribute with this type, in encoded order.
    pub fn values_of(&self, dotted: &str) -> Vec<String> {
        let mut out = Vec::new();
        for rdn in &self.rdns {
            for a in rdn {
                if a.oid.dotted() == dotted {
                    out.push(a.text.clone().unwrap_or_else(|| hexstring(&a.value)));
                }
            }
        }
        out
    }

    // RFC 4514. The RDNs come out in the reverse of their encoded order,
    // the attributes within one RDN are joined with +, and a value that is
    // not a string type is written as # followed by the hex of its whole
    // encoding, which is what section 2.4 says to do with an ANY.
    pub fn rfc4514(&self) -> String {
        let mut parts = Vec::new();
        for rdn in self.rdns.iter().rev() {
            let mut bits = Vec::new();
            for a in rdn {
                let v = match &a.text {
                    Some(t) => escape_4514(t),
                    None => hexstring(&a.value),
                };
                bits.push(format!("{}={}", oid::dn_short(&a.oid), v));
            }
            parts.push(bits.join("+"));
        }
        parts.join(",")
    }
}

pub fn hexstring(tlv: &Tlv) -> String {
    let mut s = String::from("#");
    // The whole encoding, tag and length included: a hexstring in RFC 4514
    // is the BER of the value, not its content octets.
    let mut hdr = Vec::new();
    hdr.push(if tlv.tag.class == CLASS_UNIVERSAL {
        tlv.tag.number as u8 | if tlv.tag.constructed { 0x20 } else { 0 }
    } else {
        (tlv.tag.class << 6) | if tlv.tag.constructed { 0x20 } else { 0 } | tlv.tag.number as u8
    });
    let n = tlv.value.len();
    if n < 0x80 {
        hdr.push(n as u8);
    } else {
        let mut be = n.to_be_bytes().to_vec();
        while be.len() > 1 && be[0] == 0 {
            be.remove(0);
        }
        hdr.push(0x80 | be.len() as u8);
        hdr.extend_from_slice(&be);
    }
    for b in hdr.iter().chain(tlv.value.iter()) {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn escape_4514(s: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        let first = i == 0;
        let last = i + 1 == chars.len();
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                out.push('\\');
                out.push(*c);
            }
            '#' if first => out.push_str("\\#"),
            ' ' if first || last => out.push_str("\\ "),
            '\0' => out.push_str("\\00"),
            _ => out.push(*c),
        }
    }
    out
}
