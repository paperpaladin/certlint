// GeneralName, the CHOICE that SubjectAltName and NameConstraints are both
// made of.
//
//   GeneralName ::= CHOICE {
//     otherName                 [0] OtherName,
//     rfc822Name                [1] IA5String,
//     dNSName                   [2] IA5String,
//     x400Address               [3] ORAddress,
//     directoryName             [4] Name,
//     ediPartyName              [5] EDIPartyName,
//     uniformResourceIdentifier [6] IA5String,
//     iPAddress                 [7] OCTET STRING,
//     registeredID              [8] OBJECT IDENTIFIER }
//
// The tags are IMPLICIT, so the alternatives that hold a string are
// primitive and the ones that hold a structure are constructed. The
// exception is directoryName: Name is itself a CHOICE, an implicit tag
// cannot be applied to one, so [4] is constructed and holds the whole
// RDNSequence. A decoder that treats [4] as implicit reads the first RDN
// as the whole name.

use crate::der::{err, Oid, Reader, Result, Tlv, CLASS_CONTEXT};
use crate::name::Name;

pub enum GeneralName<'a> {
    Other { type_id: Oid, value: Tlv<'a> },
    Rfc822(&'a [u8]),
    Dns(&'a [u8]),
    X400(&'a [u8]),
    Directory(&'a [u8]),
    EdiParty(&'a [u8]),
    Uri(&'a [u8]),
    Ip(&'a [u8]),
    RegisteredId(Oid),
}

pub fn ipv4(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

// RFC 5952: lowercase, the leftmost longest run of two or more zero groups
// written as ::. This is also what python's ipaddress module prints, which
// is what the comparison is against.
pub fn ipv6(b: &[u8]) -> String {
    let g: Vec<u16> = b
        .chunks(2)
        .map(|c| (u16::from(c[0]) << 8) | u16::from(c[1]))
        .collect();
    let (mut best_at, mut best_len) = (usize::MAX, 0usize);
    let mut i = 0;
    while i < g.len() {
        if g[i] == 0 {
            let mut j = i;
            while j < g.len() && g[j] == 0 {
                j += 1;
            }
            if j - i > best_len {
                best_len = j - i;
                best_at = i;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    if best_len < 2 {
        best_at = usize::MAX;
    }
    let mut out = String::new();
    let mut i = 0;
    while i < g.len() {
        if i == best_at {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", g[i]));
        i += 1;
    }
    if out.is_empty() {
        out.push_str("::");
    }
    out
}

fn ascii(b: &[u8]) -> String {
    b.iter().map(|c| char::from(*c)).collect()
}

impl<'a> GeneralName<'a> {
    pub fn parse(tlv: &Tlv<'a>) -> Result<GeneralName<'a>> {
        if tlv.tag.class != CLASS_CONTEXT {
            return err(
                tlv.start,
                format!("{} is not a GeneralName alternative", tlv.tag.name()),
            );
        }
        let want_constructed = matches!(tlv.tag.number, 0 | 3 | 4 | 5);
        if tlv.tag.constructed != want_constructed {
            return err(
                tlv.start,
                format!(
                    "GeneralName [{}] is {} and should be {}",
                    tlv.tag.number,
                    if tlv.tag.constructed { "constructed" } else { "primitive" },
                    if want_constructed { "constructed" } else { "primitive" }
                ),
            );
        }
        // The three IA5String alternatives are the ones that reach a
        // matcher, so their character set is checked here rather than left
        // to whatever reads them.
        let ia5 = |v: &'a [u8]| -> Result<&'a [u8]> {
            if let Some(p) = v.iter().position(|c| *c > 0x7f) {
                return err(
                    tlv.start,
                    format!("IA5String holds 0x{:02x} at offset {}", v[p], p),
                );
            }
            Ok(v)
        };
        Ok(match tlv.tag.number {
            0 => {
                let mut r = tlv.reader();
                let type_id = r.read_tlv()?.oid()?;
                let v = r.read_tlv()?;
                r.expect_empty("an otherName")?;
                GeneralName::Other { type_id, value: v }
            }
            1 => GeneralName::Rfc822(ia5(tlv.value)?),
            2 => GeneralName::Dns(ia5(tlv.value)?),
            3 => GeneralName::X400(tlv.value),
            4 => GeneralName::Directory(tlv.value),
            5 => GeneralName::EdiParty(tlv.value),
            6 => GeneralName::Uri(ia5(tlv.value)?),
            7 => GeneralName::Ip(tlv.value),
            8 => GeneralName::RegisteredId(Oid::decode(tlv.value, tlv.start)?),
            n => {
                return err(
                    tlv.start,
                    format!("GeneralName alternative [{}] does not exist", n),
                )
            }
        })
    }

    // The form --dump prints and the harness compares. One line per name,
    // the type first so that a name holding a colon cannot be mistaken for
    // a different type.
    pub fn text(&self) -> String {
        match self {
            GeneralName::Other { type_id, value } => {
                format!("otherName:{}:{}", type_id.dotted(), value.value.len())
            }
            GeneralName::Rfc822(v) => format!("email:{}", ascii(v)),
            GeneralName::Dns(v) => format!("DNS:{}", ascii(v)),
            GeneralName::X400(v) => format!("x400Address:{}", v.len()),
            GeneralName::Directory(v) => match Name::parse(v) {
                Ok(n) => format!("DirName:{}", n.rfc4514()),
                Err(e) => format!("DirName:<{}>", e.msg),
            },
            GeneralName::EdiParty(v) => format!("ediPartyName:{}", v.len()),
            GeneralName::Uri(v) => format!("URI:{}", ascii(v)),
            GeneralName::Ip(v) => match v.len() {
                4 => format!("IP:{}", ipv4(v)),
                16 => format!("IP:{}", ipv6(v)),
                // The 8 and 32 octet forms are address plus mask, and they
                // are legal only inside NameConstraints.
                8 => format!("IP:{}/{}", ipv4(&v[0..4]), ipv4(&v[4..8])),
                32 => format!("IP:{}/{}", ipv6(&v[0..16]), ipv6(&v[16..32])),
                n => format!("IP:<{} octets>", n),
            },
            GeneralName::RegisteredId(o) => format!("RID:{}", o.dotted()),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            GeneralName::Other { .. } => "otherName",
            GeneralName::Rfc822(_) => "rfc822Name",
            GeneralName::Dns(_) => "dNSName",
            GeneralName::X400(_) => "x400Address",
            GeneralName::Directory(_) => "directoryName",
            GeneralName::EdiParty(_) => "ediPartyName",
            GeneralName::Uri(_) => "uniformResourceIdentifier",
            GeneralName::Ip(_) => "iPAddress",
            GeneralName::RegisteredId(_) => "registeredID",
        }
    }
}

// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
pub fn parse_general_names<'a>(tlv: &Tlv<'a>) -> Result<Vec<GeneralName<'a>>> {
    tlv.expect(crate::der::CLASS_UNIVERSAL, crate::der::T_SEQUENCE, "GeneralNames")?;
    let mut r = tlv.reader();
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(GeneralName::parse(&r.read_tlv()?)?);
    }
    if out.is_empty() {
        return err(tlv.start, "an empty GeneralNames");
    }
    Ok(out)
}

pub fn parse_general_names_der<'a>(der: &'a [u8], at: usize) -> Result<Vec<GeneralName<'a>>> {
    let tlv = Reader::with_origin(der, at).read_only_tlv()?;
    parse_general_names(&tlv)
}
