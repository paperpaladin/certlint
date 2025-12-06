// certlint: an X.509 certificate and chain validator with a policy linter.
//
// Nothing here is a wrapper around a library. The DER decoder, the digests,
// the bignum, the path builder and the linter are all in this tree, because
// the point of the exercise is the bytes.

mod der;
mod oid;
mod pem;

use std::io::Write;
use std::process::ExitCode;

// Exit codes. The suite asserts on the difference between them, so a new one
// goes here and nowhere else.
const EXIT_OK: u8 = 0;
const EXIT_MALFORMED: u8 = 1;
const EXIT_USAGE: u8 = 2;

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
    Ok(v)
}

// The value an --asn1 line carries, where there is one worth printing. A
// type whose value is not printed here is a type the comparison against
// asn1parse cannot check the value of, and the comparator counts those
// separately so the gap stays visible.
fn asn1_value(tlv: &der::Tlv) -> String {
    if tlv.tag.class != der::CLASS_UNIVERSAL || tlv.tag.constructed {
        return String::new();
    }
    match tlv.tag.number {
        der::T_INTEGER => match tlv.integer_hex() {
            Ok(h) => format!(" :{}", h),
            Err(e) => format!(" :<{}>", e.msg),
        },
        der::T_BOOLEAN => match tlv.boolean() {
            Ok(b) => format!(" :{}", if b { 255 } else { 0 }),
            Err(e) => format!(" :<{}>", e.msg),
        },
        der::T_OID => match tlv.oid() {
            Ok(o) => format!(" :{}", o.dotted()),
            Err(e) => format!(" :<{}>", e.msg),
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
            match bytes {
                Ok(b) => {
                    let mut s = String::from(" :");
                    for c in b {
                        s.push(char::from(*c));
                    }
                    s
                }
                Err(e) => format!(" :<{}>", e.msg),
            }
        }
        // The wide types print nothing when they are well formed, and the
        // reason when they are not, so a malformed one is still visible.
        der::T_BMP_STRING | der::T_UNIVERSAL_STRING => match tlv.string_text() {
            Ok(_) => String::new(),
            Err(e) => format!(" :<{}>", e.msg),
        },
        der::T_OCTET_STRING => {
            let mut s = String::from(" :");
            for b in tlv.value {
                s.push_str(&format!("{:02X}", b));
            }
            s
        }
        _ => String::new(),
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
        println!(
            "{:6} d={} hl={} l={} {} {}{}",
            tlv.start,
            depth,
            tlv.hlen,
            tlv.value.len(),
            if tlv.tag.constructed { "cons" } else { "prim" },
            tlv.tag.name(),
            asn1_value(&tlv)
        );
        stack.push((r, depth));
        if tlv.tag.constructed {
            stack.push((tlv.reader(), depth + 1));
        }
    }
    Ok(count)
}

fn run(a: &Args) -> Result<u8, String> {
    for f in &a.files {
        let bytes = read_file(f)?;
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
            _ => {
                for (i, c) in certs.iter().enumerate() {
                    println!("{}: certificate {} is {} DER bytes", f, i, c.len());
                }
            }
        }
    }
    let _ = (&a.cas, &a.untrusted, &a.at, &a.purpose, a.max_paths);
    Ok(EXIT_OK)
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
