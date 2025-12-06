#!/bin/sh
# certlint test suite.
#
# Run it as `make test`, never directly: the Makefile's test target depends on
# `all`, and a harness that does not build the thing it tests reports passes
# for whatever binary was lying around. The staleness guard below is the
# second line of defence for when it is invoked directly anyway.
#
# The final line is exactly "N passed, M failed"; the collection's tooling
# parses it.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(dirname "$HERE")
BIN=$ROOT/target/release/certlint

pass=0
fail=0
ok()   { pass=$((pass+1)); echo "ok   $*"; }
no()   { fail=$((fail+1)); echo "FAIL $*"; }
note() { echo "--- $*"; }

if [ ! -x "$BIN" ]; then
    echo "certlint: $BIN does not exist; run make test, not t/run.sh" >&2
    exit 2
fi
for f in "$ROOT"/src/*.rs "$ROOT"/Cargo.toml; do
    if [ "$f" -nt "$BIN" ]; then
        echo "certlint: $f is newer than $BIN; run make test, not t/run.sh" >&2
        exit 2
    fi
done

# Every fact this suite checks comes from one of these. A run without them
# would compare certlint against itself and report a row of passes, so it is
# a refusal and not a skip.
for tool in openssl certtool python3; do
    command -v $tool >/dev/null 2>&1 || {
        echo "certlint: $tool is not installed; it is an oracle for this" \
             "suite and a reduced run would report passes having checked" \
             "nothing" >&2
        exit 2
    }
done
python3 -c 'import cryptography' 2>/dev/null || {
    echo "certlint: python cryptography is not installed; it is the third" \
         "parser this suite compares against" >&2
    exit 2
}

W=$ROOT/t/scratch/w$$
mkdir -p "$W"
trap 'rm -rf "$W"' EXIT INT TERM

note "the tools themselves"
echo "    openssl:     $(openssl version | cut -d' ' -f1-2)"
echo "    gnutls:      certtool $(certtool --version 2>/dev/null | head -1 | awk '{print $2}')"
echo "    cryptography: $(python3 -c 'import cryptography;print(cryptography.__version__)')"

C=$ROOT/t/corpus
if [ ! -f "$C/.stamp" ] || [ "$HERE/mkcorpus.sh" -nt "$C/.stamp" ]; then
    note "generating the corpus (openssl req, openssl x509 -req)"
    sh "$HERE/mkcorpus.sh" || { echo "corpus generation failed" >&2; exit 2; }
    touch "$C/.stamp"
fi
ncert=$(ls "$C"/*.pem | wc -l)
note "corpus: $ncert certificates"

note "command line"
"$BIN" --help >/dev/null 2>&1 && ok "--help exits 0" || no "--help did not exit 0"
"$BIN" --help 2>/dev/null | grep -q 'usage: certlint' \
    && ok "--help prints a usage line" || no "--help printed no usage line"
"$BIN" --no-such-option >/dev/null 2>&1; [ $? -eq 2 ] \
    && ok "an unknown option exits 2" || no "an unknown option did not exit 2"
"$BIN" >/dev/null 2>&1; [ $? -eq 2 ] \
    && ok "no argument at all exits 2" || no "no argument did not exit 2"
"$BIN" --ca >/dev/null 2>&1; [ $? -eq 2 ] \
    && ok "an option missing its argument exits 2" \
    || no "an option missing its argument did not exit 2"
"$BIN" "$W/absent.pem" >/dev/null 2>&1; [ $? -eq 1 ] \
    && ok "an unreadable file exits 1" || no "an unreadable file did not exit 1"

note "PEM and base64 against openssl x509 -outform DER"
n=0
bad=0
for f in "$C"/*.pem; do
    openssl x509 -in "$f" -outform DER -out "$W/oracle.der" 2>/dev/null
    "$BIN" --der "$f" > "$W/ours.der" 2>"$W/err" || { bad=$((bad+1)); continue; }
    cmp -s "$W/oracle.der" "$W/ours.der" || { bad=$((bad+1)); echo "    $f differs"; }
    n=$((n+1))
done
[ "$bad" -eq 0 ] && [ "$n" -eq "$ncert" ] \
    && ok "every PEM decodes to the DER openssl writes ($n certificates)" \
    || no "$bad of $ncert PEM files decoded to something else"

# The same file as raw DER, to prove the no-BEGIN path is not the PEM path
# with a different name.
openssl x509 -in "$C/leaf-rsa.pem" -outform DER -out "$W/leaf.der"
"$BIN" --der "$W/leaf.der" | cmp -s - "$W/leaf.der" \
    && ok "a raw DER input passes through unchanged" \
    || no "a raw DER input did not pass through unchanged"

note "--asn1 against openssl asn1parse, TLV by TLV"
if python3 "$HERE/asn1cmp.py" "$BIN" "$C"/*.pem; then
    ok "every TLV agrees with asn1parse on offset, depth, hl, length, tag"
else
    no "asn1parse and certlint disagree about the DER structure"
fi

note "string character sets: where certlint is stricter than openssl"
# openssl refuses to ENCODE these and parses them without complaint, so each
# one is a refusal by us against an acceptance by the oracle. Counted as a
# refusal, which is a different number from a disagreement.
strict=0
both=0
accepted=0
strict_total=0
try_strict() {  # try_strict DESCRIPTION OCTETS
    strict_total=$((strict_total+1))
    printf "$2" > "$W/s.der"
    ossl=accepts
    openssl asn1parse -inform DER -in "$W/s.der" >/dev/null 2>&1 || ossl=refuses
    if "$BIN" --asn1 "$W/s.der" 2>&1 | grep -q ':<'; then
        if [ "$ossl" = refuses ]; then both=$((both+1)); else strict=$((strict+1)); fi
    else
        accepted=$((accepted+1))
        echo "    we accept what openssl $ossl: $1"
    fi
}
# Octal escapes, not hex: this runs under dash, whose printf has no \x.
try_strict "an asterisk in a PrintableString" '\023\004ab*c'
try_strict "a letter in a NumericString" '\022\00312x'
try_strict "a high byte in an IA5String" '\026\003ab\377'
try_strict "an ill-formed UTF8String" '\014\002\303('
try_strict "a BMPString with an odd length" '\036\003abc'
try_strict "a UniversalString whose length is not a multiple of four" '\034\005abcde'
try_strict "a control character in a VisibleString" '\032\003a\001b'
[ "$accepted" -eq 0 ] \
    && ok "$strict_total malformed strings refused: $strict where openssl parses them anyway, $both where openssl refuses too" \
    || no "$accepted of $strict_total malformed strings were accepted"

note "the OID table"
if python3 "$HERE/oidtable.py" "$BIN"; then
    ok "every OID certlint names is one openssl and cryptography accept"
else
    no "the OID table holds something that is not an object identifier"
fi

note "malformed PEM is refused"
mal_refused=0
mal_total=0
try_mal() {  # try_mal DESCRIPTION FILE
    mal_total=$((mal_total+1))
    "$BIN" --der "$2" >/dev/null 2>&1
    if [ $? -eq 1 ]; then mal_refused=$((mal_refused+1)); else echo "    accepted: $1"; fi
}
sed 's/^\(.\{10\}\)./\1!/' "$C/leaf-rsa.pem" | sed -n '2,$p' > "$W/badchar.pem"
printf -- '-----BEGIN CERTIFICATE-----\n' > "$W/badchar2.pem"
cat "$W/badchar.pem" >> "$W/badchar2.pem"
printf -- '-----END CERTIFICATE-----\n' >> "$W/badchar2.pem"
try_mal "a base64 character outside the alphabet" "$W/badchar2.pem"
grep -v -- '-----END' "$C/leaf-rsa.pem" > "$W/unclosed.pem"
try_mal "a block that is never closed" "$W/unclosed.pem"
printf -- '-----BEGIN CERTIFICATE-----\nQUJD\n-----END PRIVATE KEY-----\n' > "$W/mismatch.pem"
try_mal "an END label that does not match its BEGIN" "$W/mismatch.pem"
head -c 200 "$W/leaf.der" > "$W/trunc.der"
try_mal "a truncated DER certificate" "$W/trunc.der"
[ "$mal_refused" -eq "$mal_total" ] \
    && ok "$mal_refused of $mal_total malformed inputs refused with exit 1" \
    || no "only $mal_refused of $mal_total malformed inputs were refused"

note "source invariants"
n=$(cat "$ROOT"/src/*.rs | grep -c 'unsafe')
if [ "$n" -eq 0 ]; then
    ok "no unsafe in src (0 occurrences)"
else
    no "src contains $n occurrences of unsafe; the overread gate assumes none"
fi
if grep -A1 '^\[dependencies\]' "$ROOT/Cargo.toml" | tail -1 | grep -q '^ *$'; then
    ok "Cargo.toml declares no dependencies"
else
    no "Cargo.toml has grown a dependency"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
