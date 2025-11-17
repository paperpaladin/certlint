// A DER decoder.
//
// DER is BER with the ambiguity removed, and every one of the removals is a
// rule a tolerant decoder quietly skips: the length must be the shortest
// form that fits, an indefinite length does not exist, a BOOLEAN is 0x00 or
// 0xFF and nothing between. X.509 says DER, so this decoder refuses the rest
// rather than accepting it and printing something plausible.
//
// Every read of the input goes through Reader. Nothing else indexes the
// buffer, and the only way to obtain bytes from it is take(), which checks
// the length first and returns a slice. A slice carries its own length, so a
// read past the end is a bounds check rather than a quiet read of whatever
// is next in the allocation. See the overread section of the README for the
// gate that makes that a measured claim.

use std::fmt;

#[derive(Debug, Clone)]
pub struct Error {
    pub at: usize,
    pub msg: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "offset {}: {}", self.at, self.msg)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn err<T>(at: usize, msg: impl Into<String>) -> Result<T> {
    Err(Error {
        at,
        msg: msg.into(),
    })
}

// Tag classes, in the order the two high bits of the identifier octet give
// them.
pub const CLASS_UNIVERSAL: u8 = 0;
pub const CLASS_APPLICATION: u8 = 1;
pub const CLASS_CONTEXT: u8 = 2;
pub const CLASS_PRIVATE: u8 = 3;

// Universal tag numbers that appear in a certificate.
pub const T_BOOLEAN: u32 = 1;
pub const T_INTEGER: u32 = 2;
pub const T_BIT_STRING: u32 = 3;
pub const T_OCTET_STRING: u32 = 4;
pub const T_NULL: u32 = 5;
pub const T_OID: u32 = 6;
pub const T_UTF8_STRING: u32 = 12;
pub const T_SEQUENCE: u32 = 16;
pub const T_SET: u32 = 17;
pub const T_NUMERIC_STRING: u32 = 18;
pub const T_PRINTABLE_STRING: u32 = 19;
pub const T_T61_STRING: u32 = 20;
pub const T_IA5_STRING: u32 = 22;
pub const T_UTC_TIME: u32 = 23;
pub const T_GENERALIZED_TIME: u32 = 24;
pub const T_VISIBLE_STRING: u32 = 26;
pub const T_UNIVERSAL_STRING: u32 = 28;
pub const T_BMP_STRING: u32 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    pub class: u8,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    pub fn universal(number: u32) -> Tag {
        Tag {
            class: CLASS_UNIVERSAL,
            constructed: number == T_SEQUENCE || number == T_SET,
            number,
        }
    }

    pub fn context(number: u32, constructed: bool) -> Tag {
        Tag {
            class: CLASS_CONTEXT,
            constructed,
            number,
        }
    }

    pub fn is(&self, class: u8, number: u32) -> bool {
        self.class == class && self.number == number
    }

    pub fn is_universal(&self, number: u32) -> bool {
        self.is(CLASS_UNIVERSAL, number)
    }

    // The name openssl asn1parse prints, so the comparison can be on a name
    // rather than on a number. Unnamed universal tags and every non-universal
    // tag print the way asn1parse prints them.
    pub fn name(&self) -> String {
        if self.class != CLASS_UNIVERSAL {
            let k = match self.class {
                CLASS_APPLICATION => "appl",
                CLASS_CONTEXT => "cont",
                _ => "priv",
            };
            return format!("[{} {}]", k, self.number);
        }
        let s = match self.number {
            0 => "EOC",
            T_BOOLEAN => "BOOLEAN",
            T_INTEGER => "INTEGER",
            T_BIT_STRING => "BIT STRING",
            T_OCTET_STRING => "OCTET STRING",
            T_NULL => "NULL",
            T_OID => "OBJECT",
            7 => "OBJECT DESCRIPTOR",
            9 => "REAL",
            10 => "ENUMERATED",
            11 => "EMBEDDED PDV",
            T_UTF8_STRING => "UTF8STRING",
            13 => "RELATIVE-OID",
            T_SEQUENCE => "SEQUENCE",
            T_SET => "SET",
            T_NUMERIC_STRING => "NUMERICSTRING",
            T_PRINTABLE_STRING => "PRINTABLESTRING",
            T_T61_STRING => "T61STRING",
            21 => "VIDEOTEXSTRING",
            T_IA5_STRING => "IA5STRING",
            T_UTC_TIME => "UTCTIME",
            T_GENERALIZED_TIME => "GENERALIZEDTIME",
            25 => "GRAPHICSTRING",
            T_VISIBLE_STRING => "VISIBLESTRING",
            27 => "GENERALSTRING",
            T_UNIVERSAL_STRING => "UNIVERSALSTRING",
            T_BMP_STRING => "BMPSTRING",
            _ => return format!("<ASN1 {}>", self.number),
        };
        s.to_string()
    }
}

// One tag-length-value. `start` and the offsets derived from it are absolute
// in the file, so they can be compared against what asn1parse prints.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: Tag,
    pub start: usize,
    pub hlen: usize,
    pub value: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn end(&self) -> usize {
        self.start + self.hlen + self.value.len()
    }

    pub fn reader(&self) -> Reader<'a> {
        Reader::with_origin(self.value, self.start + self.hlen)
    }

    pub fn is(&self, class: u8, number: u32) -> bool {
        self.tag.is(class, number)
    }

    pub fn expect(&self, class: u8, number: u32, what: &str) -> Result<()> {
        if self.is(class, number) {
            Ok(())
        } else {
            err(
                self.start,
                format!("expected {} here, found {}", what, self.tag.name()),
            )
        }
    }
}

#[derive(Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    origin: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader {
            buf,
            pos: 0,
            origin: 0,
        }
    }

    pub fn with_origin(buf: &'a [u8], origin: usize) -> Reader<'a> {
        Reader {
            buf,
            pos: 0,
            origin,
        }
    }

    pub fn offset(&self) -> usize {
        self.origin + self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn byte(&mut self) -> Result<u8> {
        match self.buf.get(self.pos) {
            Some(b) => {
                self.pos += 1;
                Ok(*b)
            }
            None => err(self.offset(), "ran off the end of the input"),
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        // The one place a length becomes bytes. A slice, never a pointer and
        // a count, so the end of the input is the end of the slice.
        match self.buf.get(self.pos..self.pos + n) {
            Some(s) => {
                self.pos += n;
                Ok(s)
            }
            None => err(
                self.offset(),
                format!("wanted {} bytes, {} left", n, self.remaining()),
            ),
        }
    }

    fn read_tag(&mut self) -> Result<Tag> {
        let at = self.offset();
        let b = self.byte()?;
        let class = b >> 6;
        let constructed = b & 0x20 != 0;
        let low = u32::from(b & 0x1f);
        if low != 0x1f {
            return Ok(Tag {
                class,
                constructed,
                number: low,
            });
        }
        // High tag number form: base-128, most significant first, minimal.
        let mut number: u32 = 0;
        let mut first = true;
        loop {
            let b = self.byte()?;
            if first && b == 0x80 {
                return err(at, "tag number has a redundant leading octet");
            }
            first = false;
            if number > (u32::MAX >> 7) {
                return err(at, "tag number does not fit in 32 bits");
            }
            number = (number << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
        if number < 0x1f {
            return err(
                at,
                format!("tag number {} must use the short form", number),
            );
        }
        Ok(Tag {
            class,
            constructed,
            number,
        })
    }

    fn read_length(&mut self) -> Result<usize> {
        let at = self.offset();
        let b = self.byte()?;
        if b < 0x80 {
            return Ok(usize::from(b));
        }
        if b == 0x80 {
            return err(at, "indefinite length: BER, not DER");
        }
        if b == 0xff {
            return err(at, "length octet 0xff is reserved");
        }
        let n = usize::from(b & 0x7f);
        if n > std::mem::size_of::<usize>() {
            return err(at, format!("length of {} octets is too large", n));
        }
        let octets = self.take(n)?;
        if octets[0] == 0 {
            return err(at, "length has a redundant leading zero octet");
        }
        let mut len: usize = 0;
        for o in octets {
            len = (len << 8) | usize::from(*o);
        }
        if len < 0x80 {
            return err(
                at,
                format!("length {} must use the short form", len),
            );
        }
        Ok(len)
    }

    pub fn read_tlv(&mut self) -> Result<Tlv<'a>> {
        let start = self.offset();
        let tag = self.read_tag()?;
        let len = self.read_length()?;
        let hlen = self.offset() - start;
        let value = self.take(len)?;
        Ok(Tlv {
            tag,
            start,
            hlen,
            value,
        })
    }

    // Read a TLV and require it to be the whole of what is left. The outer
    // structure of a certificate is exactly one SEQUENCE, and trailing bytes
    // after it are a defect worth naming rather than ignoring.
    pub fn read_only_tlv(&mut self) -> Result<Tlv<'a>> {
        let tlv = self.read_tlv()?;
        if !self.is_empty() {
            return err(
                self.offset(),
                format!("{} trailing bytes after the outermost value", self.remaining()),
            );
        }
        Ok(tlv)
    }

    pub fn expect_empty(&self, what: &str) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            err(
                self.offset(),
                format!("{} bytes left over in {}", self.remaining(), what),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Primitive values.
//
// Each of these takes the TLV rather than the bytes, so the tag is checked in
// the same place the value is decoded and a caller cannot read an INTEGER out
// of something that was not one.

impl<'a> Tlv<'a> {
    fn primitive(&self, number: u32, what: &str) -> Result<&'a [u8]> {
        self.expect(CLASS_UNIVERSAL, number, what)?;
        if self.tag.constructed {
            return err(self.start, format!("{} must be primitive under DER", what));
        }
        Ok(self.value)
    }

    // The content octets of an INTEGER, with DER's minimality rule checked:
    // the first nine bits may not be all zero or all one, which is to say a
    // redundant leading 0x00 or 0xff octet is an encoding error rather than
    // padding to be skipped.
    pub fn integer(&self) -> Result<&'a [u8]> {
        let v = self.primitive(T_INTEGER, "INTEGER")?;
        if v.is_empty() {
            return err(self.start, "INTEGER has no content octets");
        }
        if v.len() > 1 {
            let (a, b) = (v[0], v[1]);
            if a == 0x00 && b & 0x80 == 0 {
                return err(self.start, "INTEGER has a redundant leading 0x00 octet");
            }
            if a == 0xff && b & 0x80 != 0 {
                return err(self.start, "INTEGER has a redundant leading 0xff octet");
            }
        }
        Ok(v)
    }

    pub fn integer_is_negative(&self) -> Result<bool> {
        Ok(self.integer()?[0] & 0x80 != 0)
    }

    // The magnitude, most significant octet first, with no leading zero. This
    // is what openssl asn1parse prints after the sign, so it is the form the
    // comparison is made in.
    pub fn integer_magnitude(&self) -> Result<Vec<u8>> {
        let v = self.integer()?;
        let mut m: Vec<u8> = if v[0] & 0x80 == 0 {
            v.to_vec()
        } else {
            // Two's complement negation, most significant octet first.
            let mut out = vec![0u8; v.len()];
            let mut carry = 1u16;
            for i in (0..v.len()).rev() {
                let t = u16::from(!v[i]) + carry;
                out[i] = t as u8;
                carry = t >> 8;
            }
            out
        };
        while m.len() > 1 && m[0] == 0 {
            m.remove(0);
        }
        Ok(m)
    }

    // Uppercase hex of the magnitude with a leading minus for a negative
    // value, which is how BN_bn2hex and therefore asn1parse writes one.
    pub fn integer_hex(&self) -> Result<String> {
        let neg = self.integer_is_negative()?;
        let m = self.integer_magnitude()?;
        let mut s = String::new();
        if neg {
            s.push('-');
        }
        for b in &m {
            s.push_str(&format!("{:02X}", b));
        }
        Ok(s)
    }

    pub fn integer_u64(&self) -> Result<u64> {
        let v = self.integer()?;
        if v[0] & 0x80 != 0 {
            return err(self.start, "INTEGER is negative where a count was wanted");
        }
        let d: &[u8] = if v[0] == 0 { &v[1..] } else { v };
        if d.len() > 8 {
            return err(self.start, "INTEGER does not fit in 64 bits");
        }
        let mut n = 0u64;
        for b in d {
            n = (n << 8) | u64::from(*b);
        }
        Ok(n)
    }

    // DER allows exactly two encodings of a BOOLEAN, and FALSE is the only
    // one of them that is not 0xff. A decoder that accepts 0x01 as TRUE will
    // disagree with one that does not about whether an extension is critical.
    pub fn boolean(&self) -> Result<bool> {
        let v = self.primitive(T_BOOLEAN, "BOOLEAN")?;
        if v.len() != 1 {
            return err(self.start, "BOOLEAN must have exactly one content octet");
        }
        match v[0] {
            0x00 => Ok(false),
            0xff => Ok(true),
            n => err(
                self.start,
                format!("BOOLEAN content octet is 0x{:02x}, not 0x00 or 0xff", n),
            ),
        }
    }

    pub fn null(&self) -> Result<()> {
        let v = self.primitive(T_NULL, "NULL")?;
        if !v.is_empty() {
            return err(self.start, "NULL has content octets");
        }
        Ok(())
    }

    pub fn oid(&self) -> Result<Oid> {
        let v = self.primitive(T_OID, "OBJECT IDENTIFIER")?;
        Oid::decode(v, self.start)
    }
}

// An object identifier, kept as its content octets. Comparison is on the
// bytes: two OIDs are equal when their encodings are, and under DER an
// encoding is unique.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Oid(pub Vec<u8>);

impl Oid {
    pub fn decode(v: &[u8], at: usize) -> Result<Oid> {
        if v.is_empty() {
            return err(at, "OBJECT IDENTIFIER has no content octets");
        }
        if v[v.len() - 1] & 0x80 != 0 {
            return err(at, "OBJECT IDENTIFIER ends mid-subidentifier");
        }
        let mut first = true;
        for (i, b) in v.iter().enumerate() {
            if first && *b == 0x80 {
                return err(at, "OBJECT IDENTIFIER subidentifier has a leading 0x80");
            }
            first = *b & 0x80 == 0;
            let _ = i;
        }
        Ok(Oid(v.to_vec()))
    }

    // Dotted decimal. The first octet carries two arcs: 40*x + y, with x
    // capped at 2 and y unbounded above 2.39 for x == 2.
    pub fn dotted(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut acc: u128 = 0;
        let mut started = false;
        for b in &self.0 {
            acc = (acc << 7) | u128::from(b & 0x7f);
            if b & 0x80 != 0 {
                continue;
            }
            if !started {
                started = true;
                let (x, y) = if acc < 40 {
                    (0, acc)
                } else if acc < 80 {
                    (1, acc - 40)
                } else {
                    (2, acc - 80)
                };
                parts.push(x.to_string());
                parts.push(y.to_string());
            } else {
                parts.push(acc.to_string());
            }
            acc = 0;
        }
        parts.join(".")
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.dotted())
    }
}
