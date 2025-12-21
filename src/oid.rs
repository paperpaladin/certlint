// The object identifiers certlint knows by name.
//
// Kept as dotted decimal strings rather than as encoded byte arrays. An
// encoded arc is the thing that gets typed wrongly, the dotted form is the
// thing a reader can check against RFC 5280 without a pencil, and a linear
// scan over eighty entries is not worth optimising. The names are the
// spellings the RFCs use, not the ones openssl prints: --asn1 prints dotted
// decimal precisely so the comparison against asn1parse does not depend on
// matching openssl's own name table.

use crate::der::Oid;

// Public key algorithms.
pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const ED25519: &str = "1.3.101.112";
pub const ED448: &str = "1.3.101.113";

// Signature algorithms.
pub const SHA1_RSA: &str = "1.2.840.113549.1.1.5";
pub const SHA224_RSA: &str = "1.2.840.113549.1.1.14";
pub const SHA256_RSA: &str = "1.2.840.113549.1.1.11";
pub const SHA384_RSA: &str = "1.2.840.113549.1.1.12";
pub const SHA512_RSA: &str = "1.2.840.113549.1.1.13";
pub const MD5_RSA: &str = "1.2.840.113549.1.1.4";
pub const ECDSA_SHA1: &str = "1.2.840.10045.4.1";
pub const ECDSA_SHA224: &str = "1.2.840.10045.4.3.1";
pub const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
pub const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
pub const ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";

// Digests, and MGF1 for PSS.
pub const SHA1: &str = "1.3.14.3.2.26";
pub const SHA224: &str = "2.16.840.1.101.3.4.2.4";
pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub const SHA512: &str = "2.16.840.1.101.3.4.2.3";
pub const MGF1: &str = "1.2.840.113549.1.1.8";

// Named curves.
pub const SECP256R1: &str = "1.2.840.10045.3.1.7";
pub const SECP384R1: &str = "1.3.132.0.34";
pub const SECP521R1: &str = "1.3.132.0.35";
pub const SECP256K1: &str = "1.3.132.0.10";

// Extensions.
pub const EXT_SUBJECT_KEY_ID: &str = "2.5.29.14";
pub const EXT_KEY_USAGE: &str = "2.5.29.15";
pub const EXT_SUBJECT_ALT_NAME: &str = "2.5.29.17";
pub const EXT_ISSUER_ALT_NAME: &str = "2.5.29.18";
pub const EXT_BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub const EXT_NAME_CONSTRAINTS: &str = "2.5.29.30";
pub const EXT_CRL_DISTRIBUTION: &str = "2.5.29.31";
pub const EXT_CERTIFICATE_POLICIES: &str = "2.5.29.32";
pub const EXT_POLICY_MAPPINGS: &str = "2.5.29.33";
pub const EXT_AUTHORITY_KEY_ID: &str = "2.5.29.35";
pub const EXT_POLICY_CONSTRAINTS: &str = "2.5.29.36";
pub const EXT_EXT_KEY_USAGE: &str = "2.5.29.37";
pub const EXT_INHIBIT_ANY_POLICY: &str = "2.5.29.54";
pub const EXT_AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";
pub const EXT_SUBJECT_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.11";
pub const EXT_SCT_LIST: &str = "1.3.6.1.4.1.11129.2.4.2";
pub const EXT_TLS_FEATURE: &str = "1.3.6.1.5.5.7.1.24";

// Extended key usage purposes.
pub const KP_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
pub const KP_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
pub const KP_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
pub const KP_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
pub const KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
pub const KP_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
pub const KP_ANY: &str = "2.5.29.37.0";

// Policies named by the Baseline Requirements.
pub const POLICY_ANY: &str = "2.5.29.32.0";
pub const POLICY_DV: &str = "2.23.140.1.2.1";
pub const POLICY_OV: &str = "2.23.140.1.2.2";
pub const POLICY_IV: &str = "2.23.140.1.2.3";
pub const POLICY_EV: &str = "2.23.140.1.1";

// Distinguished name attributes.
pub const AT_COMMON_NAME: &str = "2.5.4.3";
pub const AT_COUNTRY: &str = "2.5.4.6";
pub const AT_LOCALITY: &str = "2.5.4.7";
pub const AT_STATE: &str = "2.5.4.8";
pub const AT_ORGANISATION: &str = "2.5.4.10";
pub const AT_ORG_UNIT: &str = "2.5.4.11";
pub const AT_SERIAL_NUMBER: &str = "2.5.4.5";
pub const AT_EMAIL: &str = "1.2.840.113549.1.9.1";
pub const AT_DOMAIN_COMPONENT: &str = "0.9.2342.19200300.100.1.25";
pub const AT_ORGANISATION_ID: &str = "2.5.4.97";
pub const AT_BUSINESS_CATEGORY: &str = "2.5.4.15";

// (dotted, name, RFC 4514 short name). RFC 4514 section 3 names exactly
// nine attribute types and says everything else is written as a dotted OID.
// openssl prints names for a good many more, so a DN holding one of those
// is a DN whose string form the three printers cannot be compared on; the
// harness checks the structure instead and says how many strings it
// skipped.
const TABLE: &[(&str, &str, &str)] = &[
    (RSA_ENCRYPTION, "rsaEncryption", ""),
    (RSASSA_PSS, "rsassaPss", ""),
    (EC_PUBLIC_KEY, "id-ecPublicKey", ""),
    (ED25519, "Ed25519", ""),
    (ED448, "Ed448", ""),
    (MD5_RSA, "md5WithRSAEncryption", ""),
    (SHA1_RSA, "sha1WithRSAEncryption", ""),
    (SHA224_RSA, "sha224WithRSAEncryption", ""),
    (SHA256_RSA, "sha256WithRSAEncryption", ""),
    (SHA384_RSA, "sha384WithRSAEncryption", ""),
    (SHA512_RSA, "sha512WithRSAEncryption", ""),
    (ECDSA_SHA1, "ecdsa-with-SHA1", ""),
    (ECDSA_SHA224, "ecdsa-with-SHA224", ""),
    (ECDSA_SHA256, "ecdsa-with-SHA256", ""),
    (ECDSA_SHA384, "ecdsa-with-SHA384", ""),
    (ECDSA_SHA512, "ecdsa-with-SHA512", ""),
    (SHA1, "sha1", ""),
    (SHA224, "sha224", ""),
    (SHA256, "sha256", ""),
    (SHA384, "sha384", ""),
    (SHA512, "sha512", ""),
    (MGF1, "id-mgf1", ""),
    (SECP256R1, "secp256r1", ""),
    (SECP384R1, "secp384r1", ""),
    (SECP521R1, "secp521r1", ""),
    (SECP256K1, "secp256k1", ""),
    (EXT_SUBJECT_KEY_ID, "subjectKeyIdentifier", ""),
    (EXT_KEY_USAGE, "keyUsage", ""),
    (EXT_SUBJECT_ALT_NAME, "subjectAltName", ""),
    (EXT_ISSUER_ALT_NAME, "issuerAltName", ""),
    (EXT_BASIC_CONSTRAINTS, "basicConstraints", ""),
    (EXT_NAME_CONSTRAINTS, "nameConstraints", ""),
    (EXT_CRL_DISTRIBUTION, "cRLDistributionPoints", ""),
    (EXT_CERTIFICATE_POLICIES, "certificatePolicies", ""),
    (EXT_POLICY_MAPPINGS, "policyMappings", ""),
    (EXT_AUTHORITY_KEY_ID, "authorityKeyIdentifier", ""),
    (EXT_POLICY_CONSTRAINTS, "policyConstraints", ""),
    (EXT_EXT_KEY_USAGE, "extKeyUsage", ""),
    (EXT_INHIBIT_ANY_POLICY, "inhibitAnyPolicy", ""),
    (EXT_AUTHORITY_INFO_ACCESS, "authorityInfoAccess", ""),
    (EXT_SUBJECT_INFO_ACCESS, "subjectInfoAccess", ""),
    (EXT_SCT_LIST, "signedCertificateTimestampList", ""),
    (EXT_TLS_FEATURE, "tlsFeature", ""),
    ("2.5.29.9", "subjectDirectoryAttributes", ""),
    ("2.5.29.16", "privateKeyUsagePeriod", ""),
    ("2.5.29.46", "freshestCRL", ""),
    (KP_SERVER_AUTH, "serverAuth", ""),
    (KP_CLIENT_AUTH, "clientAuth", ""),
    (KP_CODE_SIGNING, "codeSigning", ""),
    (KP_EMAIL_PROTECTION, "emailProtection", ""),
    (KP_TIME_STAMPING, "timeStamping", ""),
    (KP_OCSP_SIGNING, "OCSPSigning", ""),
    (KP_ANY, "anyExtendedKeyUsage", ""),
    ("1.3.6.1.5.5.7.48.1", "id-ad-ocsp", ""),
    ("1.3.6.1.5.5.7.48.2", "id-ad-caIssuers", ""),
    ("1.3.6.1.5.5.7.2.1", "id-qt-cps", ""),
    ("1.3.6.1.5.5.7.2.2", "id-qt-unotice", ""),
    (POLICY_ANY, "anyPolicy", ""),
    (POLICY_DV, "domain-validated", ""),
    (POLICY_OV, "organization-validated", ""),
    (POLICY_IV, "individual-validated", ""),
    (POLICY_EV, "extended-validation", ""),
    (AT_COMMON_NAME, "commonName", "CN"),
    (AT_SERIAL_NUMBER, "serialNumber", ""),
    (AT_COUNTRY, "countryName", "C"),
    (AT_LOCALITY, "localityName", "L"),
    (AT_STATE, "stateOrProvinceName", "ST"),
    (AT_ORGANISATION, "organizationName", "O"),
    (AT_ORG_UNIT, "organizationalUnitName", "OU"),
    ("2.5.4.4", "surname", ""),
    ("2.5.4.12", "title", ""),
    ("2.5.4.42", "givenName", ""),
    ("2.5.4.9", "streetAddress", "STREET"),
    ("2.5.4.17", "postalCode", ""),
    (AT_BUSINESS_CATEGORY, "businessCategory", ""),
    (AT_ORGANISATION_ID, "organizationIdentifier", ""),
    (AT_EMAIL, "emailAddress", ""),
    (AT_DOMAIN_COMPONENT, "domainComponent", "DC"),
    ("0.9.2342.19200300.100.1.1", "userId", "UID"),
    ("1.3.6.1.4.1.311.60.2.1.1", "jurisdictionLocalityName", ""),
    ("1.3.6.1.4.1.311.60.2.1.2", "jurisdictionStateOrProvinceName", ""),
    ("1.3.6.1.4.1.311.60.2.1.3", "jurisdictionCountryName", ""),
];

// The name, or None. A caller that prints must fall back to dotted decimal:
// an OID we do not know is a number, and guessing at it is how a tool ends
// up naming the wrong extension.
pub fn name(oid: &Oid) -> Option<&'static str> {
    let d = oid.dotted();
    TABLE.iter().find(|e| e.0 == d).map(|e| e.1)
}

pub fn name_or_dotted(oid: &Oid) -> String {
    let d = oid.dotted();
    match TABLE.iter().find(|e| e.0 == d) {
        Some(e) => e.1.to_string(),
        None => d,
    }
}

// The RFC 4514 short name where there is one, otherwise the dotted form,
// which is what RFC 4514 section 2.3 says to do.
pub fn dn_short(oid: &Oid) -> String {
    let d = oid.dotted();
    match TABLE.iter().find(|e| e.0 == d && !e.2.is_empty()) {
        Some(e) => e.2.to_string(),
        None => d,
    }
}

pub fn is(oid: &Oid, dotted: &str) -> bool {
    oid.dotted() == dotted
}

// Every dotted string in the table, for the suite to hand to openssl and to
// python cryptography and ask whether they are well-formed identifiers.
pub fn all_dotted() -> Vec<&'static str> {
    TABLE.iter().map(|e| e.0).collect()
}
