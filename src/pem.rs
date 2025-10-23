// PEM, and the base64 under it.
//
// A certificate file is either DER or PEM, and PEM is detected by the
// "-----BEGIN " line rather than by the file extension. A file may hold
// several objects: openssl's own convention for a chain file, and the thing
// the path builder needs, so the decoder returns all of them with their
// labels.
//
// The base64 here is strict. Whitespace between characters is ignored
// because every PEM producer wraps at 64 columns, but a character outside
// the alphabet, a misplaced pad or a final group with one character left is
// an error. A lenient decoder turns a corrupt file into a certificate that
// parses, which is the failure mode worth avoiding.

pub struct Block {
    pub label: String,
    pub der: Vec<u8>,
}

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub fn base64_decode(s: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut quad = [0u8; 4];
    let mut n = 0;
    let mut pad = 0;
    for (i, c) in s.iter().enumerate() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if *c == b'=' {
            pad += 1;
            if pad > 2 {
                return Err(format!("more than two pad characters at byte {}", i));
            }
            quad[n] = 0;
            n += 1;
        } else {
            if pad > 0 {
                return Err(format!("base64 data after a pad character at byte {}", i));
            }
            match b64_value(*c) {
                Some(v) => {
                    quad[n] = v;
                    n += 1;
                }
                None => {
                    return Err(format!(
                        "byte {} is 0x{:02x}, not a base64 character",
                        i, c
                    ))
                }
            }
        }
        if n == 4 {
            let bits = (u32::from(quad[0]) << 18)
                | (u32::from(quad[1]) << 12)
                | (u32::from(quad[2]) << 6)
                | u32::from(quad[3]);
            out.push((bits >> 16) as u8);
            if pad < 2 {
                out.push((bits >> 8) as u8);
            }
            if pad < 1 {
                out.push(bits as u8);
            }
            n = 0;
        }
    }
    if n != 0 {
        return Err(format!("base64 ends with {} leftover characters", n));
    }
    out.shrink_to_fit();
    Ok(out)
}

fn line_label(line: &[u8], marker: &[u8]) -> Option<String> {
    // "-----BEGIN CERTIFICATE-----" with the marker being BEGIN or END.
    let dashes = b"-----";
    if !line.starts_with(dashes) || !line.ends_with(dashes) || line.len() < 11 {
        return None;
    }
    let inner = &line[5..line.len() - 5];
    if !inner.starts_with(marker) {
        return None;
    }
    let rest = &inner[marker.len()..];
    if !rest.starts_with(b" ") {
        return None;
    }
    String::from_utf8(rest[1..].to_vec()).ok()
}

pub fn looks_like_pem(data: &[u8]) -> bool {
    data.windows(11).any(|w| w == b"-----BEGIN ")
}

// Every PEM block in the buffer, in file order. A file that is not PEM at
// all is one block labelled DER holding the whole file, so the caller does
// not need two paths.
pub fn blocks(data: &[u8]) -> Result<Vec<Block>, String> {
    if !looks_like_pem(data) {
        return Ok(vec![Block {
            label: "DER".to_string(),
            der: data.to_vec(),
        }]);
    }
    let mut out = Vec::new();
    let mut open: Option<(String, Vec<u8>)> = None;
    for line in data.split(|c| *c == b'\n') {
        let line = match line.strip_suffix(b"\r") {
            Some(l) => l,
            None => line,
        };
        if let Some(label) = line_label(line, b"BEGIN") {
            if open.is_some() {
                return Err(format!("BEGIN {} inside an unclosed block", label));
            }
            open = Some((label, Vec::new()));
            continue;
        }
        if let Some(label) = line_label(line, b"END") {
            match open.take() {
                Some((want, body)) if want == label => {
                    out.push(Block {
                        label,
                        der: base64_decode(&body)?,
                    });
                }
                Some((want, _)) => {
                    return Err(format!("END {} closes a block that opened {}", label, want))
                }
                None => return Err(format!("END {} with no BEGIN", label)),
            }
            continue;
        }
        if let Some((_, body)) = open.as_mut() {
            body.extend_from_slice(line);
        }
    }
    if let Some((label, _)) = open {
        return Err(format!("BEGIN {} is never closed", label));
    }
    if out.is_empty() {
        return Err("no PEM block in a file that contains a BEGIN line".to_string());
    }
    Ok(out)
}

// Only the certificates, which is what every caller here wants.
pub fn certificates(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let bs = blocks(data)?;
    let mut out = Vec::new();
    for b in bs {
        if b.label == "CERTIFICATE" || b.label == "TRUSTED CERTIFICATE" || b.label == "DER" {
            out.push(b.der);
        }
    }
    if out.is_empty() {
        return Err("no CERTIFICATE block in this file".to_string());
    }
    Ok(out)
}
