// UTCTime and GeneralizedTime.
//
// RFC 5280 section 4.1.2.5 makes the encoding depend on the year: a time
// before 2050 is a UTCTime, 2050 and after is a GeneralizedTime. So the
// boundary is the one place a parser that handles each format perfectly
// well can still be wrong, and the corpus has a certificate either side of
// it.
//
// Both forms are required to be in Z, to carry seconds, and to carry no
// fractional part. DER says so and RFC 5280 says so again, and a decoder
// that accepts a local-time offset has to guess at what it means.

use crate::der::{err, Result, Tlv, T_GENERALIZED_TIME, T_UTC_TIME};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Utc,
    Generalized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    pub kind: Kind,
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
    pub epoch: i64,
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

// Days since 1970-01-01 from a proleptic Gregorian date. Howard Hinnant's
// days_from_civil, which is exact over the whole range and has no table.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn digits(s: &[u8], at: usize, what: &str) -> Result<i64> {
    let mut n = 0i64;
    for c in s {
        if !c.is_ascii_digit() {
            return err(at, format!("{} is not all digits", what));
        }
        n = n * 10 + i64::from(c - b'0');
    }
    Ok(n)
}

impl Time {
    pub fn parse(tlv: &Tlv) -> Result<Time> {
        let at = tlv.start;
        let v = tlv.value;
        if tlv.tag.constructed {
            return err(at, "a constructed time is BER, not DER");
        }
        let (kind, ylen) = match tlv.tag.number {
            T_UTC_TIME => (Kind::Utc, 2),
            T_GENERALIZED_TIME => (Kind::Generalized, 4),
            _ => return err(at, format!("{} is not a time", tlv.tag.name())),
        };
        let want = ylen + 11;
        if v.len() != want {
            return err(
                at,
                format!(
                    "{} is {} octets, DER wants exactly {} (YYMMDDHHMMSSZ form)",
                    tlv.tag.name(),
                    v.len(),
                    want
                ),
            );
        }
        if v[v.len() - 1] != b'Z' {
            return err(at, "a time must end in Z; DER has no local time");
        }
        let year = match kind {
            // The two-digit year rule from RFC 5280 4.1.2.5.1: 50 and above
            // is 19xx, below 50 is 20xx. Nothing else interprets it, which
            // is why the format is retired above 2049.
            Kind::Utc => {
                let yy = digits(&v[0..2], at, "year")?;
                if yy >= 50 {
                    1900 + yy
                } else {
                    2000 + yy
                }
            }
            Kind::Generalized => digits(&v[0..4], at, "year")?,
        };
        let p = ylen;
        let month = digits(&v[p..p + 2], at, "month")?;
        let day = digits(&v[p + 2..p + 4], at, "day")?;
        let hour = digits(&v[p + 4..p + 6], at, "hour")?;
        let minute = digits(&v[p + 6..p + 8], at, "minute")?;
        let second = digits(&v[p + 8..p + 10], at, "second")?;
        if !(1..=12).contains(&month) {
            return err(at, format!("month {} is out of range", month));
        }
        if day < 1 || day > days_in_month(year, month) {
            return err(
                at,
                format!("day {} is out of range for month {} of {}", day, month, year),
            );
        }
        if hour > 23 || minute > 59 {
            return err(at, format!("{}:{} is not a time of day", hour, minute));
        }
        // 60 would be a leap second. X.509 does not have them and neither do
        // the oracles, so it is a refusal rather than a silent rounding.
        if second > 59 {
            return err(at, format!("second {} is a leap second", second));
        }
        let epoch = days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
        Ok(Time {
            kind,
            year,
            month,
            day,
            hour,
            minute,
            second,
            epoch,
        })
    }

    pub fn iso(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            Kind::Utc => "UTCTime",
            Kind::Generalized => "GeneralizedTime",
        }
    }

    // RFC 5280 4.1.2.5: before 2050 is a UTCTime, 2050 and after is a
    // GeneralizedTime. Returned rather than refused, because a certificate
    // that breaks it is a certificate the linter should report and the path
    // builder should still be able to reason about.
    pub fn encoding_is_correct(&self) -> bool {
        match self.kind {
            Kind::Utc => self.year < 2050,
            Kind::Generalized => self.year >= 2050,
        }
    }

    // Parse a time string of the form the --at option takes.
    pub fn parse_stamp(s: &str) -> std::result::Result<Time, String> {
        let b = s.as_bytes();
        if b.len() != 15 || b[14] != b'Z' {
            return Err(format!("{}: want YYYYMMDDHHMMSSZ", s));
        }
        let mut der = Vec::with_capacity(17);
        der.push(0x18u8);
        der.push(15);
        der.extend_from_slice(b);
        let tlv = crate::der::Reader::new(&der)
            .read_tlv()
            .map_err(|e| e.msg)?;
        Time::parse(&tlv).map_err(|e| e.msg)
    }
}
