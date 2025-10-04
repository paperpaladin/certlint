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
