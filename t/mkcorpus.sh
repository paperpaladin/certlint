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
