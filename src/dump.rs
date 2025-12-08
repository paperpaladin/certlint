// --dump: the parsed certificate as key = value lines.
//
// The format exists to be compared, not to be read aloud. One fact per
// line, no nesting, values in a form that survives being parsed back: a
// time as both an ISO string and an epoch second, an algorithm as both a
// name and the OID the name came from, a serial as the hex of its
// magnitude with the sign in front. Where a field can repeat, the key
// repeats.

use crate::cert::Cert;
use crate::oid;

pub struct Dump {
    pub lines: Vec<(String, String)>,
}

impl Dump {
    fn new() -> Dump {
        Dump { lines: Vec::new() }
    }

    fn put(&mut self, k: &str, v: impl Into<String>) {
        self.lines.push((k.to_string(), v.into()));
    }

    pub fn print(&self) {
        for (k, v) in &self.lines {
            println!("{} = {}", k, v);
        }
    }
}

fn yesno(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

pub fn dump(c: &Cert) -> Dump {
    let mut d = Dump::new();
    d.put("version", c.version.to_string());
    if c.version_redundant {
        d.put("version_redundant", "yes");
    }
    let serial_hex = c.serial.integer_hex().unwrap_or_default();
    d.put("serial", &serial_hex[..]);
    d.put(
        "serial_negative",
        yesno(c.serial.integer_is_negative().unwrap_or(false)),
    );
    // The bit length of the magnitude, which is what the Baseline
    // Requirements mean by entropy even though it is only an upper bound on
    // it: a serial of 2^63 has 64 bits and no entropy at all.
    let mag = c.serial.integer_magnitude().unwrap_or_default();
    let bits = match mag.iter().position(|b| *b != 0) {
        Some(i) => (mag.len() - i) * 8 - usize::from(mag[i].leading_zeros() as u8),
        None => 0,
    };
    d.put("serial_bits", bits.to_string());
    d.put("serial_octets", c.serial.value.len().to_string());

    d.put("signature_algorithm", oid::name_or_dotted(&c.sig_alg.oid));
    d.put("signature_algorithm_oid", c.sig_alg.oid.dotted());
    d.put("tbs_signature_algorithm_oid", c.tbs_sig_alg.oid.dotted());
    d.put("algorithms_match", yesno(c.algorithms_match()));
    d.put("signature_octets", c.signature.len().to_string());
    d.put("tbs_octets", c.tbs_der.len().to_string());

    d.put("not_before", c.not_before.iso());
    d.put("not_after", c.not_after.iso());
    d.put("not_before_epoch", c.not_before.epoch.to_string());
    d.put("not_after_epoch", c.not_after.epoch.to_string());
    d.put("not_before_encoding", c.not_before.kind_name());
    d.put("not_after_encoding", c.not_after.kind_name());
    d.put(
        "validity_encoding_per_rfc5280",
        yesno(c.not_before.encoding_is_correct() && c.not_after.encoding_is_correct()),
    );
    let span = c.not_after.epoch - c.not_before.epoch;
    d.put("validity_seconds", span.to_string());

    d.put("has_extensions", yesno(c.extensions_tlv.is_some()));
    d.put("issuer_unique_id", yesno(c.issuer_unique_id.is_some()));
    d.put("subject_unique_id", yesno(c.subject_unique_id.is_some()));
    d
}
