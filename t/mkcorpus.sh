#!/bin/sh
# Generate the certificate corpus with openssl.
#
# Nothing in here is an oracle: it is the source of certificates that nobody
# in this repository wrote by hand. The oracles are the three parsers the
# suite compares against afterwards.
#
# Re-run only when this script is newer than the stamp, because RSA key
# generation dominates the suite's runtime.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=$HERE/corpus
mkdir -p "$OUT"
cd "$OUT"

# A serial with the 64 bits of entropy the Baseline Requirements want.
bigserial() { echo "0x00$(openssl rand -hex 16)"; }

req() {  # req SUBJ KEYSPEC OUT
    openssl req -new -newkey "$2" -nodes -keyout "$3.key" -out "$3.csr" \
        -subj "$1" >/dev/null 2>&1
}

selfsign() {  # selfsign NAME SUBJ KEYSPEC EXTFILE DAYS
    openssl req -x509 -newkey "$3" -nodes -keyout "$1.key" -out "$1.pem" \
        -subj "$2" -days "$5" -sha256 -extensions v3 -config "$4" \
        >/dev/null 2>&1
}

sign() {  # sign NAME CA EXTFILE DAYS [SERIAL]
    serial=${5:-$(bigserial)}
    openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" \
        -set_serial "$serial" -days "$4" -sha256 \
        -extfile "$3" -extensions v3 -out "$1.pem" >/dev/null 2>&1
}

cat > ca.ext <<'X'
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = unused
[ v3 ]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
X

cat > sub.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
X

cat > leaf.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:leaf.example.com,DNS:www.example.com
X

cat > leafec.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:ec.example.com,IP:192.0.2.7
X

# The ordinary RSA chain: root -> intermediate -> leaf.
selfsign root-rsa "/C=GB/O=certlint/CN=certlint RSA Root" rsa:2048 ca.ext 3650
req "/C=GB/O=certlint/CN=certlint RSA Intermediate" rsa:2048 inter-rsa
sign inter-rsa root-rsa sub.ext 1825
req "/C=GB/O=certlint/CN=leaf.example.com" rsa:2048 leaf-rsa
sign leaf-rsa inter-rsa leaf.ext 90

openssl ecparam -name prime256v1 -out p256.pem
openssl ecparam -name secp384r1 -out p384.pem

# The same shape over P-256 and P-384, so the EC signature paths get a
# certificate each rather than being reasoned about.
selfsign root-ec "/C=GB/O=certlint/CN=certlint EC Root" ec:p256.pem ca.ext 3650
req "/C=GB/O=certlint/CN=certlint EC Intermediate" ec:p384.pem inter-ec
sign inter-ec root-ec sub.ext 1825
req "/C=GB/O=certlint/CN=ec.example.com" ec:p256.pem leaf-ec
sign leaf-ec inter-ec leafec.ext 90

# P-521 and the other digests. Without these the suite holds curve
# parameters and digest cases that nothing reaches: the corpus is the
# thing that decides which code runs.
openssl ecparam -name secp521r1 -out p521.pem
selfsign root-ec521 "/C=GB/O=certlint/CN=certlint P-521 Root" ec:p521.pem ca.ext 3650
req "/C=GB/O=certlint/CN=p521.example.com" ec:p521.pem leaf-ec521
openssl x509 -req -in leaf-ec521.csr -CA root-ec521.pem -CAkey root-ec521.key \
    -set_serial "$(bigserial)" -days 90 -sha512 -extfile leafec.ext \
    -extensions v3 -out leaf-ec521.pem >/dev/null 2>&1
rm -f p521.pem

req "/C=GB/O=certlint/CN=sha512.example.com" rsa:2048 leaf-sha512
openssl x509 -req -in leaf-sha512.csr -CA inter-rsa.pem -CAkey inter-rsa.key \
    -set_serial "$(bigserial)" -days 90 -sha512 -extfile leaf.ext \
    -extensions v3 -out leaf-sha512.pem >/dev/null 2>&1
req "/C=GB/O=certlint/CN=sha1.example.com" rsa:2048 leaf-sha1
openssl x509 -req -in leaf-sha1.csr -CA inter-rsa.pem -CAkey inter-rsa.key \
    -set_serial "$(bigserial)" -days 90 -sha1 -extfile leaf.ext \
    -extensions v3 -out leaf-sha1.pem >/dev/null 2>&1

# One certificate carrying as many constructs as openssl will emit at
# once, so that the decoders for them are not checked against a corpus
# that holds none: all nine key usage bits, six extended key usages, five
# GeneralName types in the SAN, AIA, CRL distribution points and two
# policies with a CPS qualifier.
cat > full.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,encipherOnly,decipherOnly
extendedKeyUsage = serverAuth,clientAuth,emailProtection,timeStamping,OCSPSigning,codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
subjectAltName = @alt
authorityInfoAccess = OCSP;URI:http://ocsp.example.com/,caIssuers;URI:http://ca.example.com/ca.crt
crlDistributionPoints = URI:http://crl.example.com/a.crl,URI:ldap://crl.example.com/a
certificatePolicies = 2.23.140.1.2.1,@cps
[ alt ]
DNS.1 = wild.example.com
DNS.2 = *.wild.example.com
email = person@example.com
URI = https://example.com/path
IP.1 = 198.51.100.4
IP.2 = 2001:db8::1
RID = 1.2.3.4
[ cps ]
policyIdentifier = 1.3.6.1.4.1.99999.1
CPS.1 = http://cps.example.com/
X

req "/C=GB/O=certlint/OU=Testing/L=London/ST=Greater London/CN=full.example.com" rsa:2048 leaf-full
sign leaf-full inter-rsa full.ext 90
rm -f full.ext

# A root with name constraints, and two leaves: one inside the permitted
# subtrees and one inside an excluded one. Without these the name
# constraints code would be checked against a corpus that holds none.
cat > nc.ext <<'X'
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = unused
[ v3 ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
nameConstraints = critical,permitted;DNS:example.org,permitted;IP:192.0.2.0/255.255.255.0,permitted;email:example.org,excluded;DNS:bad.example.org,excluded;URI:.bad.example.net
X

cat > ncleaf.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:host.example.org,IP:192.0.2.9
X

cat > ncbad.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:host.bad.example.org
X

selfsign root-nc "/C=GB/O=certlint/CN=certlint Constrained Root" rsa:2048 nc.ext 3650
req "/C=GB/O=certlint/CN=host.example.org" rsa:2048 leaf-nc-ok
sign leaf-nc-ok root-nc ncleaf.ext 90
req "/C=GB/O=certlint/CN=host.bad.example.org" rsa:2048 leaf-nc-bad
sign leaf-nc-bad root-nc ncbad.ext 90

rm -f nc.ext ncleaf.ext ncbad.ext

# Awkward serial numbers. openssl refuses to encode an illegal string and
# will happily encode any of these, so they come from the generator rather
# than from a hand-written byte.
req "/C=GB/O=certlint/CN=negative serial" rsa:2048 serial-negative
sign serial-negative inter-rsa leaf.ext 90 -3
req "/C=GB/O=certlint/CN=zero serial" rsa:2048 serial-zero
sign serial-zero inter-rsa leaf.ext 90 0
req "/C=GB/O=certlint/CN=oversized serial" rsa:2048 serial-long
sign serial-long inter-rsa leaf.ext 90 \
    0x00ffeeddccbbaa998877665544332211009988776655

# The 2050 boundary, from both sides, and a notBefore in the 1990s so the
# two-digit year rule is exercised in the direction that means 19xx.
req "/C=GB/O=certlint/CN=utc 2049" rsa:2048 time-utc2049
openssl x509 -req -in time-utc2049.csr -CA inter-rsa.pem -CAkey inter-rsa.key \
    -set_serial "$(bigserial)" -sha256 -extfile leaf.ext -extensions v3 \
    -not_before 19950101000000Z -not_after 20491231235959Z \
    -out time-utc2049.pem >/dev/null 2>&1
req "/C=GB/O=certlint/CN=generalized 2050" rsa:2048 time-gen2050
openssl x509 -req -in time-gen2050.csr -CA inter-rsa.pem -CAkey inter-rsa.key \
    -set_serial "$(bigserial)" -sha256 -extfile leaf.ext -extensions v3 \
    -not_before 20490101000000Z -not_after 20500101000000Z \
    -out time-gen2050.pem >/dev/null 2>&1

# A cross-signed root. root-cross is self-signed; cross-rsa carries the
# same subject and the same public key and is signed by the RSA root. A
# leaf under that key therefore has two valid paths, one of length two
# and one of length three, and which one a builder finds depends on the
# order it tries candidates in. This is the shape that a builder taking
# the first matching issuer gets wrong, so without it in the corpus the
# backtracking search is never asked a question it could fail.
selfsign root-cross "/C=GB/O=certlint/CN=certlint Cross Root" rsa:2048 ca.ext 3650
openssl req -new -key root-cross.key -out cross-rsa.csr \
    -subj "/C=GB/O=certlint/CN=certlint Cross Root" >/dev/null 2>&1
openssl x509 -req -in cross-rsa.csr -CA root-rsa.pem -CAkey root-rsa.key \
    -set_serial "$(bigserial)" -days 1825 -sha256 -extfile sub.ext \
    -extensions v3 -out cross-rsa.pem >/dev/null 2>&1

cat > crossleaf.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:cross.example.com
X
req "/C=GB/O=certlint/CN=cross.example.com" rsa:2048 leaf-cross
sign leaf-cross root-cross crossleaf.ext 90
rm -f crossleaf.ext

# A fourth level under a pathlen:0 intermediate. inter-rsa says no CA may
# appear below it, so the chain leaf-deep -> subca-rsa -> inter-rsa ->
# root-rsa has one intermediate too many and must be refused. Counting
# that wrongly is invisible on every three-certificate chain, which is
# every other chain in this corpus.
req "/C=GB/O=certlint/CN=certlint RSA Sub-Intermediate" rsa:2048 subca-rsa
sign subca-rsa inter-rsa sub.ext 1825
req "/C=GB/O=certlint/CN=deep.example.com" rsa:2048 leaf-deep
sign leaf-deep subca-rsa leaf.ext 90

# A certificate issued by a leaf. openssl x509 -req signs with any key it
# is handed and does not ask whether the signer is a CA, so this is a
# real signature from a certificate whose basicConstraints says CA:FALSE.
req "/C=GB/O=certlint/CN=under-a-leaf.example.com" rsa:2048 leaf-under-leaf
openssl x509 -req -in leaf-under-leaf.csr -CA leaf-rsa.pem -CAkey leaf-rsa.key \
    -set_serial "$(bigserial)" -days 90 -sha256 -extfile leaf.ext \
    -extensions v3 -out leaf-under-leaf.pem >/dev/null 2>&1

# A key rollover certificate, which is the only reason the pathlen count
# excludes self-issued certificates. roll-rsa has the RSA root's subject
# and issuer and a new key, and is signed by the old root key; inter2 and
# leaf-roll hang off the new key. The path is four certificates long and
# root-rsa says pathlen:1, so it is legal only because roll-rsa does not
# count. Deleting the exclusion from the count is invisible without it.
openssl genrsa -out roll-rsa.key 2048 >/dev/null 2>&1
openssl req -new -key roll-rsa.key -out roll-rsa.csr \
    -subj "/C=GB/O=certlint/CN=certlint RSA Root" >/dev/null 2>&1
openssl x509 -req -in roll-rsa.csr -CA root-rsa.pem -CAkey root-rsa.key \
    -set_serial "$(bigserial)" -days 1825 -sha256 -extfile ca.ext \
    -extensions v3 -out roll-rsa.pem >/dev/null 2>&1
req "/C=GB/O=certlint/CN=certlint RSA Intermediate 2" rsa:2048 inter2-rsa
openssl x509 -req -in inter2-rsa.csr -CA roll-rsa.pem -CAkey roll-rsa.key \
    -set_serial "$(bigserial)" -days 1825 -sha256 -extfile sub.ext \
    -extensions v3 -out inter2-rsa.pem >/dev/null 2>&1
req "/C=GB/O=certlint/CN=rolled.example.com" rsa:2048 leaf-roll
sign leaf-roll inter2-rsa leaf.ext 90

# An intermediate with no basicConstraints at all. openssl will not emit
# one from a profile that mentions the extension, so the profile here
# simply leaves it out. RFC 5280 6.1.4 (k) says a certificate without it
# may not issue another one, and nothing in the corpus tested that while
# every CA in it carried the extension.
cat > nobc.ext <<'X'
[ v3 ]
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
X
req "/C=GB/O=certlint/CN=certlint Unconstrained Intermediate" rsa:2048 inter-nobc
sign inter-nobc root-rsa nobc.ext 1825
req "/C=GB/O=certlint/CN=nobc.example.com" rsa:2048 leaf-nobc
sign leaf-nobc inter-nobc leaf.ext 90
rm -f nobc.ext

# A CA that says it may sign CRLs and not certificates. basicConstraints
# and keyUsage are two separate claims and an implementation that reads
# only the first will issue under this one.
cat > nokcs.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,digitalSignature,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
X
req "/C=GB/O=certlint/CN=certlint CRL-only Intermediate" rsa:2048 inter-nokcs
sign inter-nokcs root-rsa nokcs.ext 1825
req "/C=GB/O=certlint/CN=nokcs.example.com" rsa:2048 leaf-nokcs
sign leaf-nokcs inter-nokcs leaf.ext 90
rm -f nokcs.ext

# A CA restricted to serverAuth issuing a clientAuth leaf. An
# extendedKeyUsage on a CA limits what that CA may issue, so --purpose
# clientAuth has to look at the whole path and not only at the leaf.
# openssl verify -purpose sslclient refuses this with error 26 at depth
# 1, so the rule has an oracle.
cat > ekuca.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
X
cat > ekuleaf.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:ekuc.example.com
X
req "/C=GB/O=certlint/CN=certlint serverAuth-only Intermediate" rsa:2048 inter-eku
sign inter-eku root-rsa ekuca.ext 1825
req "/C=GB/O=certlint/CN=ekuc.example.com" rsa:2048 leaf-eku
sign leaf-eku inter-eku ekuleaf.ext 90
rm -f ekuca.ext ekuleaf.ext

# A critical extension nobody knows, which RFC 5280 6.1.4 says must make a
# validator refuse the path, and an empty subject with a critical SAN,
# which is how a certificate with no DN at all is meant to be written.
cat > odd.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
subjectAltName = DNS:odd.example.com
1.2.3.4.5.6.7.8 = critical,DER:04:03:01:02:03
X
req "/C=GB/O=certlint/CN=unknown critical" rsa:2048 ext-unknown-critical
sign ext-unknown-critical inter-rsa odd.ext 90

cat > empty.ext <<'X'
[ v3 ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
subjectAltName = critical,DNS:anonymous.example.com
X
openssl req -new -newkey rsa:2048 -nodes -keyout subject-empty.key \
    -out subject-empty.csr -subj "/" >/dev/null 2>&1
sign subject-empty inter-rsa empty.ext 90
rm -f odd.ext empty.ext
rm -f ca.ext sub.ext leaf.ext leafec.ext p256.pem p384.pem *.csr
# The encodings openssl will not emit, built byte by byte and signed with
# openssl so that they are real certificates.
python3 "$HERE/mkodd.py"

n=$(ls *.pem | wc -l)
echo "corpus: $n certificates in $OUT"
