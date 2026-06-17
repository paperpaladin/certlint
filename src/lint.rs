// The CA/Browser Forum Baseline Requirements linter.
//
// Every rule here reads a field out of the --dump output rather than
// re-deriving it from the DER. That is deliberate and it is the only
// thing holding the linter honest: no Baseline Requirements linter is
// installed on this machine, so there is no outside authority for the
// rules, but every value a rule fires on is one the suite has already
// compared against openssl, certtool and python cryptography. A finding
// can be wrong about the rule. It cannot be wrong about the number.
//
// Each finding names the field it read, and the suite checks that the
// named field exists in the dump, so a rule cannot quietly fire on a
// field nobody compares.

use crate::cert::Cert;
use crate::dump::Dump;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    // The Baseline Requirements say must or must not.
    Error,
    // They say should, or RFC 5280 does and the BRs are silent.
    Warning,
}

impl Level {
    pub fn name(&self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warning => "warning",
        }
    }
}

pub struct Finding {
    pub level: Level,
    pub code: &'static str,
    pub field: String,
    pub text: String,
}

pub struct Report {
    pub findings: Vec<Finding>,
    // Which profile the rules were applied under. A CA certificate and a
    // subscriber certificate are judged by different sections of the BRs
    // and saying which one was used is part of the answer.
    pub profile: &'static str,
}

impl Report {
    pub fn errors(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.level == Level::Error)
            .count()
    }

    pub fn print(&self) {
        println!("lint_profile = {}", self.profile);
        for f in &self.findings {
            println!(
                "finding = {} {} {} {}",
                f.level.name(),
                f.code,
                f.field,
                f.text
            );
        }
        println!("finding_count = {}", self.findings.len());
        println!("error_count = {}", self.errors());
    }
}

struct Ctx<'a> {
    d: &'a Dump,
    out: Vec<Finding>,
}

impl<'a> Ctx<'a> {
    fn get(&self, k: &str) -> Option<&str> {
        self.d
            .lines
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    }

    fn num(&self, k: &str) -> Option<i64> {
        self.get(k).and_then(|v| v.parse().ok())
    }

    fn say(&mut self, level: Level, code: &'static str, field: &str, text: String) {
        self.out.push(Finding {
            level,
            code,
            field: field.to_string(),
            text,
        });
    }
}

// A CA certificate and a subscriber certificate are different documents
// under the Baseline Requirements, and basicConstraints is what says
// which one this is.
fn is_ca(c: &Ctx) -> bool {
    c.get("basic_constraints_ca") == Some("yes")
}

pub fn lint(_cert: &Cert, d: &Dump) -> Report {
    let mut c = Ctx {
        d,
        out: Vec::new(),
    };
    serial(&mut c);
    let profile = if is_ca(&c) { "ca" } else { "subscriber" };
    Report {
        findings: c.out,
        profile,
    }
}

// BR 7.1 and RFC 5280 4.1.2.2. The serial is a positive integer of at
// most twenty octets, and the BRs want at least 64 bits of it to come
// from a CSPRNG.
fn serial(c: &mut Ctx) {
    let negative = c.get("serial_negative") == Some("yes");
    let bits = c.num("serial_bits").unwrap_or(0);
    let octets = c.num("serial_octets").unwrap_or(0);
    if negative {
        c.say(
            Level::Error,
            "serial_negative",
            "serial_negative",
            "the serial number is negative, and RFC 5280 4.1.2.2 says \
             positive"
                .to_string(),
        );
    } else if bits == 0 {
        c.say(
            Level::Error,
            "serial_zero",
            "serial_bits",
            "the serial number is zero, and RFC 5280 4.1.2.2 says positive"
                .to_string(),
        );
    }
    if octets > 20 {
        c.say(
            Level::Error,
            "serial_too_long",
            "serial_octets",
            format!(
                "the serial number is {} octets, and RFC 5280 4.1.2.2 allows \
                 at most 20",
                octets
            ),
        );
    }
    // The bit length of the magnitude is an upper bound on the entropy
    // and not a measurement of it: a serial of 2^63 has 64 bits and no
    // entropy at all. It is what can be checked from one certificate,
    // and saying so is better than calling it entropy.
    if !negative && bits < 64 {
        c.say(
            Level::Error,
            "serial_short",
            "serial_bits",
            format!(
                "the serial number has {} bits, and BR 7.1 wants 64 bits of \
                 CSPRNG output, of which this is an upper bound",
                bits
            ),
        );
    }
}
