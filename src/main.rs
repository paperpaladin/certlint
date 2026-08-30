// certlint: an X.509 certificate and chain validator with a policy linter.
//
// Nothing here is a wrapper around a library. The DER decoder, the digests,
// the bignum, the path builder and the linter are all in this tree, because
// the point of the exercise is the bytes.

mod bignum;
mod cert;
mod der;
mod dump;
mod ec;
mod ext;
mod gname;
mod hash;
mod key;
mod lint;
mod name;
mod oid;
mod path;
mod pem;
mod sig;
mod time;

use std::io::Write;
use std::process::ExitCode;

// Exit codes. The suite asserts on the difference between them, so a new one
// goes here and nowhere else.
const EXIT_OK: u8 = 0;
const EXIT_MALFORMED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_CHAIN: u8 = 3;
const EXIT_LINT: u8 = 4;

const USAGE: &str = "\
usage: certlint [MODE] [OPTIONS] FILE...

  -a, --asn1        print the DER structure, one line per TLV
      --der         write the first certificate out as DER
  -d, --dump        print the parsed certificate as key = value lines
  -v, --verify      build a path to a trust anchor and validate it
  -l, --lint        check against the CA/Browser Forum Baseline Requirements
  -A, --all         --dump then --lint

  --ca FILE         add a trust anchor (repeatable)
  --untrusted FILE  add candidate intermediates (repeatable)
  --at TIME         validate at this instant, as YYYYMMDDHHMMSSZ
  --purpose NAME    serverAuth, clientAuth, codeSigning, emailProtection
  --max-paths N     stop after N candidate paths have been tried
  -h, --help        this text
";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Asn1,
    Sig,
    Hash,
    Der,
    Dump,
    Verify,
    Lint,
    All,
}

struct Args {
    mode: Option<Mode>,
    files: Vec<String>,
    cas: Vec<String>,
    untrusted: Vec<String>,
    at: Option<String>,
    purpose: Option<String>,
    max_paths: usize,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        mode: None,
        files: Vec::new(),
        cas: Vec::new(),
        untrusted: Vec::new(),
        at: None,
        purpose: None,
        max_paths: 64,
    };
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        let mut need = |what: &str| -> Result<String, String> {
            i += 1;
            match argv.get(i) {
                Some(v) => Ok(v.clone()),
                None => Err(format!("{} needs an argument", what)),
            }
        };
        match arg {
            "-a" | "--asn1" => a.mode = Some(Mode::Asn1),
            "--der" => a.mode = Some(Mode::Der),
            "-d" | "--dump" => a.mode = Some(Mode::Dump),
            "-v" | "--verify" => a.mode = Some(Mode::Verify),
            "-l" | "--lint" => a.mode = Some(Mode::Lint),
            "-A" | "--all" => a.mode = Some(Mode::All),
            "--ca" => {
                let v = need("--ca")?;
                a.cas.push(v);
            }
            "--untrusted" => {
                let v = need("--untrusted")?;
                a.untrusted.push(v);
            }
            "--at" => a.at = Some(need("--at")?),
            "--purpose" => a.purpose = Some(need("--purpose")?),
            "--max-paths" => {
                let v = need("--max-paths")?;
                a.max_paths = v
                    .parse()
                    .map_err(|_| format!("--max-paths wants a number, got {}", v))?;
            }
            // Undocumented on purpose: it prints the OID table for the
            // suite to check against openssl and python cryptography, and
            // it is not a mode anybody would run by hand.
            // Undocumented, for the suite: print the four digests of the
            // file so openssl dgst can be asked the same question.
            "--hash" => a.mode = Some(Mode::Hash),
            // Undocumented, for the suite: check one certificate's
            // signature against the key in the first --ca file, or its
            // own key when there is none.
            "--sig" => a.mode = Some(Mode::Sig),
            // Undocumented, for the suite: base, exponent and modulus in
            // hex, so python's pow can be asked the same question.
            "--modexp" => {
                let b = need("--modexp")?;
                let e = need("--modexp")?;
                let m = need("--modexp")?;
                let hx = |s: &str| -> Vec<u8> {
                    let s = if s.len() % 2 == 1 {
                        format!("0{}", s)
                    } else {
                        s.to_string()
                    };
                    (0..s.len() / 2)
                        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0))
                        .collect()
                };
                let mont = match bignum::Mont::new(&bignum::from_be(&hx(&m))) {
                    Some(x) => x,
                    None => {
                        eprintln!("certlint: the modulus must be odd and non-zero");
                        std::process::exit(1);
                    }
                };
                let r = mont.pow(&bignum::from_be(&hx(&b)), &hx(&e));
                let bytes = bignum::to_be(&r, mont.k * 4);
                let mut out = String::new();
                for byte in bytes.iter().skip_while(|b| **b == 0) {
                    out.push_str(&format!("{:02x}", byte));
                }
                println!("{}", if out.is_empty() { "0".to_string() } else { out });
                std::process::exit(0);
            }
            // Undocumented, for the suite: curve parameters and a few
            // facts the arithmetic must produce.
            "--ec-check" => {
                for c in ec::CURVES {
                    println!("curve {} {} {} bits", c.name, c.oid, c.bits);
                    for (k, v) in [("p", c.p), ("b", c.b), ("gx", c.gx),
                                   ("gy", c.gy), ("n", c.n)] {
                        let h: String = v.chars().filter(|x| x.is_ascii_hexdigit()).collect();
                        println!("  {} {}", k, h.trim_start_matches('0'));
                    }
                    for (k, v) in ec::self_facts(c) {
                        println!("  {} {}", k, v);
                    }
                }
                std::process::exit(0);
            }
            "--oid-table" => {
                for d in oid::all_dotted() {
                    println!("{}", d);
                }
                std::process::exit(0);
            }
            "-h" | "--help" => return Err(String::new()),
            _ if arg.starts_with('-') && arg.len() > 1 => {
                return Err(format!("unknown option {}", arg))
            }
            _ => a.files.push(arg.to_string()),
        }
        i += 1;
    }
    Ok(a)
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    // Read into an exactly sized buffer. A Vec with spare capacity behind a
    // separately tracked length is the shape that hides an over-read; see the
    // README. Nothing here indexes by anything but the slice's own length,
    // and `make overread` is the gate on that.
    let mut v = std::fs::read(path).map_err(|e| format!("{}: {}", path, e))?;
    v.shrink_to_fit();
    planted_overread(&v);
    Ok(v)
}

// The gate behind `make overread`, compiled only under the plant_overread feature.
//
// Rust bounds-checks a slice, so the C failure mode this collection
// keeps finding -- a buffer rounded up past its data, which turns the
// sanitizer off for everything between the end of the data and the end
// of the allocation -- has no equivalent here as long as every read
// goes through a slice whose length is the length of the data. That is
// a claim about this program and not about the language: a Vec carries
// a capacity as well as a length, and code that passed a capacity
// around would have the same hole.
//
// So the claim is measured rather than asserted. The planted read is
// one past the end of the file buffer, the gate requires the process to
// die at that index with a message naming it, and the suite separately
// counts the occurrences in src of the keyword that would let an index
// skip its check, which has to be zero for the gate to mean anything.
#[cfg(feature = "plant_overread")]
fn planted_overread(v: &[u8]) {
    eprintln!("certlint: planted read at index {} of {}", v.len(), v.len());
    let b = v[v.len()];
    eprintln!("certlint: read {} past the end, which should not happen", b);
}

#[cfg(not(feature = "plant_overread"))]
fn planted_overread(_v: &[u8]) {}

// The value an --asn1 line carries, where there is one worth printing. A
// type whose value is not printed here is a type the comparison against
// asn1parse cannot check the value of, and the comparator counts those
// separately so the gap stays visible.
fn asn1_value(tlv: &der::Tlv) -> Vec<u8> {
    if tlv.tag.class != der::CLASS_UNIVERSAL || tlv.tag.constructed {
        return Vec::new();
    }
    match tlv.tag.number {
        der::T_INTEGER => match tlv.integer_hex() {
            Ok(h) => format!(" :{}", h).into_bytes(),
            Err(e) => format!(" :<{}>", e.msg).into_bytes(),
        },
        der::T_BOOLEAN => match tlv.boolean() {
            Ok(b) => format!(" :{}", if b { 255 } else { 0 }).into_bytes(),
            Err(e) => format!(" :<{}>", e.msg).into_bytes(),
        },
        der::T_OID => match tlv.oid() {
            Ok(o) => format!(" :{}", o.dotted()).into_bytes(),
            Err(e) => format!(" :<{}>", e.msg).into_bytes(),
        },
        // The narrow string types and the two times print as the bytes
        // they were encoded as, which is what asn1parse prints. BMPString
        // and UniversalString print nothing, because asn1parse prints
        // nothing for them and inventing a rendering would be comparing
        // our transcoding against no one.
        n if (der::is_string_tag(n) && n != der::T_BMP_STRING && n != der::T_UNIVERSAL_STRING)
            || n == der::T_UTC_TIME
            || n == der::T_GENERALIZED_TIME =>
        {
            let bytes = if n == der::T_UTC_TIME || n == der::T_GENERALIZED_TIME {
                Ok(tlv.value)
            } else {
                tlv.string_bytes()
            };
            // The octets as they were encoded, not transcoded. asn1parse
            // writes the bytes straight out and a T61String holds bytes
            // that are not UTF-8, so anything else here would be comparing
            // our idea of the character set against openssl's.
            match bytes {
                Ok(b) => {
                    let mut v = b" :".to_vec();
                    v.extend_from_slice(b);
                    v
                }
                Err(e) => format!(" :<{}>", e.msg).into_bytes(),
            }
        }
        // The wide types print nothing when they are well formed, and the
        // reason when they are not, so a malformed one is still visible.
        der::T_BMP_STRING | der::T_UNIVERSAL_STRING => match tlv.string_text() {
            Ok(_) => Vec::new(),
            Err(e) => format!(" :<{}>", e.msg).into_bytes(),
        },
        der::T_OCTET_STRING => {
            let mut s = String::from(" :");
            for b in tlv.value {
                s.push_str(&format!("{:02X}", b));
            }
            s.into_bytes()
        }
        _ => Vec::new(),
    }
}

// Walk the whole tree, printing one line per TLV, descending into every
// constructed value. The walk is iterative: the depth of a certificate is
// attacker-controlled, and a recursive walker is a stack overflow waiting
// for a file with ten thousand nested SEQUENCEs.
fn print_asn1(der: &[u8]) -> der::Result<usize> {
    let mut stack: Vec<(der::Reader, usize)> = vec![(der::Reader::new(der), 0)];
    let mut count = 0;
    while let Some((mut r, depth)) = stack.pop() {
        if r.is_empty() {
            continue;
        }
        let tlv = r.read_tlv()?;
        count += 1;
        let mut line = format!(
            "{:6} d={} hl={} l={} {} {}",
            tlv.start,
            depth,
            tlv.hlen,
            tlv.value.len(),
            if tlv.tag.constructed { "cons" } else { "prim" },
            tlv.tag.name()
        )
        .into_bytes();
        line.extend_from_slice(&asn1_value(&tlv));
        line.push(b'\n');
        let _ = std::io::stdout().write_all(&line);
        stack.push((r, depth));
        if tlv.tag.constructed {
            stack.push((tlv.reader(), depth + 1));
        }
    }
    Ok(count)
}

// Load every certificate from a list of files, labelled by file and
// position so a report can name which one it means.
fn load_all(paths: &[String]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut out = Vec::new();
    for p in paths {
        let bytes = read_file(p)?;
        let certs = pem::certificates(&bytes).map_err(|e| format!("{}: {}", p, e))?;
        for (i, c) in certs.into_iter().enumerate() {
            let label = if i == 0 {
                p.clone()
            } else {
                format!("{}#{}", p, i)
            };
            out.push((label, c));
        }
    }
    Ok(out)
}

fn cmd_verify(f: &str, certs: &[Vec<u8>], a: &Args) -> Result<u8, String> {
    let anchors = load_all(&a.cas)?;
    let untrusted = load_all(&a.untrusted)?;
    let at = match &a.at {
        Some(s) => time::Time::parse_stamp(s).map_err(|e| e)?.epoch,
        None => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    };
    // Everything after the first certificate in the subject file is a
    // candidate intermediate, which is the convention every chain file
    // follows.
    let mut owned: Vec<(String, Vec<u8>, path::Source)> = Vec::new();
    owned.push((f.to_string(), certs[0].clone(), path::Source::Input));
    for (i, c) in certs.iter().enumerate().skip(1) {
        owned.push((format!("{}#{}", f, i), c.clone(), path::Source::Untrusted));
    }
    for (l, c) in untrusted {
        owned.push((l, c, path::Source::Untrusted));
    }
    for (l, c) in anchors {
        owned.push((l, c, path::Source::Anchor));
    }
    let mut store = path::Store { certs: Vec::new() };
    for (label, der, source) in &owned {
        match cert::Cert::parse(der) {
            Ok(c) => store.certs.push(path::Candidate {
                cert: c,
                source: *source,
                label: label.clone(),
            }),
            Err(e) => return Err(format!("{}: {}", label, e)),
        }
    }
    let opt = path::Options {
        at,
        purpose: a.purpose.clone(),
        max_paths: a.max_paths,
        max_depth: 16,
    };
    let built = store.build(0, &opt);
    println!("at = {}", at);
    println!("candidates = {}", store.certs.len() - 1);
    println!("paths_tried = {}", built.paths_tried);
    if built.ok {
        println!("path_length = {}", built.path.len());
        for (i, idx) in built.path.iter().enumerate() {
            let c = &store.certs[*idx];
            println!(
                "path_cert = {} {} {}",
                i,
                c.source.name(),
                c.label
            );
        }
        println!("verdict = ok");
        Ok(EXIT_OK)
    } else {
        for f2 in &built.failures {
            println!("attempt = depth {} {} {}", f2.depth, f2.at_cert, f2.reason);
        }
        println!("verdict = failed");
        Ok(EXIT_CHAIN)
    }
}

fn run(a: &Args) -> Result<u8, String> {
    let mut worst = EXIT_OK;
    let mut verdict;
    for f in &a.files {
        let bytes = read_file(f)?;
        if a.mode == Some(Mode::Hash) {
            for alg in [hash::Alg::Sha1, hash::Alg::Sha256, hash::Alg::Sha384,
                        hash::Alg::Sha512] {
                let d = hash::digest(alg, &bytes);
                let mut s = String::new();
                for b in &d {
                    s.push_str(&format!("{:02x}", b));
                }
                println!("{} {}", alg.name(), s);
            }
            continue;
        }
        let certs = pem::certificates(&bytes).map_err(|e| format!("{}: {}", f, e))?;
        match a.mode {
            Some(Mode::Der) => {
                // Check the framing before writing anything out: a file that
                // is not one complete TLV is a malformed certificate, not a
                // certificate we have not looked at yet.
                der::Reader::new(&certs[0])
                    .read_only_tlv()
                    .map_err(|e| format!("{}: {}", f, e))?;
                let mut out = std::io::stdout();
                out.write_all(&certs[0]).map_err(|e| e.to_string())?;
                out.flush().map_err(|e| e.to_string())?;
            }
            Some(Mode::Asn1) => {
                for c in certs.iter() {
                    print_asn1(c).map_err(|e| format!("{}: {}", f, e))?;
                }
            }
            Some(Mode::Verify) => {
                verdict = cmd_verify(f, &certs, a)?;
                if verdict != EXIT_OK {
                    worst = verdict;
                }
                continue;
            }
            Some(Mode::Sig) => {
                let parsed = cert::Cert::parse(&certs[0]).map_err(|e| format!("{}: {}", f, e))?;
                let issuer_bytes = match a.cas.first() {
                    Some(p) => {
                        let b = read_file(p)?;
                        pem::certificates(&b).map_err(|e| format!("{}: {}", p, e))?[0].clone()
                    }
                    None => certs[0].clone(),
                };
                let issuer = cert::Cert::parse(&issuer_bytes).map_err(|e| e.to_string())?;
                let spki = key::Spki::parse(issuer.spki_der).map_err(|e| e.to_string())?;
                let v = sig::verify(&spki, &parsed.sig_alg, parsed.tbs_der, parsed.signature);
                println!("signature = {}", v.text());
                if v != sig::Verdict::Valid {
                    worst = EXIT_CHAIN;
                }
            }
            Some(Mode::Lint) | Some(Mode::All) => {
                let parsed = cert::Cert::parse(&certs[0]).map_err(|e| format!("{}: {}", f, e))?;
                let d = dump::dump(&parsed);
                if a.mode == Some(Mode::All) {
                    d.print();
                }
                let r = lint::lint(&parsed, &d);
                r.print();
                if r.errors() > 0 {
                    worst = EXIT_LINT;
                }
            }
            Some(Mode::Dump) => {
                let parsed = cert::Cert::parse(&certs[0]).map_err(|e| format!("{}: {}", f, e))?;
                let d = dump::dump(&parsed);
                d.print();
                if d.errors() > 0 {
                    eprintln!(
                        "certlint: {}: {} field(s) did not decode",
                        f,
                        d.errors()
                    );
                    worst = EXIT_MALFORMED;
                }
            }
            _ => {
                for (i, c) in certs.iter().enumerate() {
                    println!("{}: certificate {} is {} DER bytes", f, i, c.len());
                }
            }
        }
    }
    let _ = (&a.cas, &a.untrusted, &a.at, &a.purpose, a.max_paths);
    Ok(worst)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(msg) => {
            if msg.is_empty() {
                print!("{}", USAGE);
                return ExitCode::from(EXIT_OK);
            }
            eprintln!("certlint: {}", msg);
            eprint!("{}", USAGE);
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if args.files.is_empty() {
        eprintln!("certlint: no input file");
        eprint!("{}", USAGE);
        return ExitCode::from(EXIT_USAGE);
    }
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("certlint: {}", msg);
            ExitCode::from(EXIT_MALFORMED)
        }
    }
}
