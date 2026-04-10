// ECDSA verification over the three NIST prime curves.
//
// Jacobian coordinates, so there is no modular inversion inside the
// scalar multiplication, and one inversion at the end to get an affine
// x. All three curves have a == -3, which is the case the fast doubling
// formulas are written for, and the code refuses a curve it does not
// hold parameters for rather than guessing.
//
// The parameters are written out below and checked against openssl
// ecparam by the suite. A mistyped digit in a curve constant produces a
// verifier that rejects every signature, which looks like strictness.

use crate::bignum::{self, Limbs, Mont};

pub struct Curve {
    pub name: &'static str,
    pub oid: &'static str,
    pub p: &'static str,
    pub b: &'static str,
    pub gx: &'static str,
    pub gy: &'static str,
    pub n: &'static str,
    pub bits: usize,
}

pub const CURVES: &[Curve] = &[
    Curve {
        name: "secp256r1",
        oid: "1.2.840.10045.3.1.7",
        p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        bits: 256,
    },
    Curve {
        name: "secp384r1",
        oid: "1.3.132.0.34",
        p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
            ffffffff0000000000000000ffffffff",
        b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
            c656398d8a2ed19d2a85c8edd3ec2aef",
        gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
             5502f25dbf55296c3a545e3872760ab7",
        gy: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
             0a60b1ce1d7e819d7a431d7c90ea0e5f",
        n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
            581a0db248b0a77aecec196accc52973",
        bits: 384,
    },
    Curve {
        name: "secp521r1",
        oid: "1.3.132.0.35",
        p: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffff",
        b: "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1\
            09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503\
            f00",
        gx: "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d\
             3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5\
             bd66",
        gy: "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e\
             662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1\
             6650",
        n: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
            6409",
        bits: 521,
    },
];

pub fn curve_by_oid(dotted: &str) -> Option<&'static Curve> {
    CURVES.iter().find(|c| c.oid == dotted)
}

pub fn unhex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let clean = if clean.len() % 2 == 1 {
        format!("0{}", clean)
    } else {
        clean
    };
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap_or(0))
        .collect()
}

// A point in Jacobian coordinates, with every coordinate in Montgomery
// form. Infinity is Z == 0.
struct Jac {
    x: Limbs,
    y: Limbs,
    z: Limbs,
}

struct Field {
    m: Mont,
    one: Limbs,
    zero: Limbs,
}

impl Field {
    fn new(p: &[u8]) -> Option<Field> {
        let m = Mont::new(&bignum::from_be(p))?;
        let mut one_plain = vec![0u32; m.k];
        one_plain[0] = 1;
        let one = m.to_mont(&one_plain);
        let zero = vec![0u32; m.k];
        Some(Field { m, one, zero })
    }

    fn mul(&self, a: &[u32], b: &[u32]) -> Limbs {
        self.m.mul(a, b)
    }
    fn add(&self, a: &[u32], b: &[u32]) -> Limbs {
        self.m.add(a, b)
    }
    fn sub(&self, a: &[u32], b: &[u32]) -> Limbs {
        self.m.sub(a, b)
    }
    fn dbl(&self, a: &[u32]) -> Limbs {
        self.m.add(a, a)
    }
    fn is_zero(&self, a: &[u32]) -> bool {
        bignum::is_zero(a)
    }
}

impl Jac {
    fn infinity(f: &Field) -> Jac {
        Jac {
            x: f.one.clone(),
            y: f.one.clone(),
            z: f.zero.clone(),
        }
    }

    fn is_infinity(&self, f: &Field) -> bool {
        f.is_zero(&self.z)
    }

    // Doubling with a == -3, the usual dbl-2001-b formulas.
    fn double(&self, f: &Field) -> Jac {
        if self.is_infinity(f) {
            return Jac {
                x: self.x.clone(),
                y: self.y.clone(),
                z: self.z.clone(),
            };
        }
        let delta = f.mul(&self.z, &self.z);
        let gamma = f.mul(&self.y, &self.y);
        let beta = f.mul(&self.x, &gamma);
        let t = f.sub(&self.x, &delta);
        let u = f.add(&self.x, &delta);
        let tu = f.mul(&t, &u);
        let alpha = f.add(&f.dbl(&tu), &tu); // 3*(X-delta)*(X+delta)
        // X3 = alpha^2 - 8*beta. Four betas here produced a point that
        // was still on the curve and was not 2G.
        let eight_beta = f.dbl(&f.dbl(&f.dbl(&beta)));
        let x3 = f.sub(&f.mul(&alpha, &alpha), &eight_beta);
        let yz = f.add(&self.y, &self.z);
        let z3 = f.sub(&f.sub(&f.mul(&yz, &yz), &gamma), &delta);
        let g2 = f.mul(&gamma, &gamma);
        let y3 = f.sub(
            &f.mul(&alpha, &f.sub(&f.dbl(&f.dbl(&beta)), &x3)),
            &f.dbl(&f.dbl(&f.dbl(&g2))),
        );
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn add(&self, o: &Jac, f: &Field) -> Jac {
        if self.is_infinity(f) {
            return Jac {
                x: o.x.clone(),
                y: o.y.clone(),
                z: o.z.clone(),
            };
        }
        if o.is_infinity(f) {
            return Jac {
                x: self.x.clone(),
                y: self.y.clone(),
                z: self.z.clone(),
            };
        }
        let z1z1 = f.mul(&self.z, &self.z);
        let z2z2 = f.mul(&o.z, &o.z);
        let u1 = f.mul(&self.x, &z2z2);
        let u2 = f.mul(&o.x, &z1z1);
        let s1 = f.mul(&f.mul(&self.y, &o.z), &z2z2);
        let s2 = f.mul(&f.mul(&o.y, &self.z), &z1z1);
        if u1 == u2 {
            if s1 != s2 {
                return Jac::infinity(f);
            }
            return self.double(f);
        }
        let h = f.sub(&u2, &u1);
        let i = f.mul(&f.dbl(&h), &f.dbl(&h));
        let j = f.mul(&h, &i);
        let r = f.dbl(&f.sub(&s2, &s1));
        let v = f.mul(&u1, &i);
        let x3 = f.sub(&f.sub(&f.mul(&r, &r), &j), &f.dbl(&v));
        let y3 = f.sub(
            &f.mul(&r, &f.sub(&v, &x3)),
            &f.dbl(&f.mul(&s1, &j)),
        );
        let zz = f.add(&self.z, &o.z);
        let z3 = f.mul(&f.sub(&f.sub(&f.mul(&zz, &zz), &z1z1), &z2z2), &h);
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    // Double and add, most significant bit first. The scalar is public,
    // so there is nothing to hide by making it uniform.
    fn mul_scalar(&self, k: &[u8], f: &Field) -> Jac {
        let mut acc = Jac::infinity(f);
        let mut started = false;
        for byte in k {
            for bit in (0..8).rev() {
                if started {
                    acc = acc.double(f);
                }
                if byte >> bit & 1 == 1 {
                    acc = if started {
                        acc.add(self, f)
                    } else {
                        started = true;
                        Jac {
                            x: self.x.clone(),
                            y: self.y.clone(),
                            z: self.z.clone(),
                        }
                    };
                }
            }
        }
        acc
    }

    // The affine x, as plain big-endian octets.
    fn affine_x(&self, f: &Field, len: usize) -> Option<Vec<u8>> {
        if self.is_infinity(f) {
            return None;
        }
        let zinv = f.m.inv_mont(&self.z);
        let zinv2 = f.mul(&zinv, &zinv);
        let x = f.mul(&self.x, &zinv2);
        Some(bignum::to_be(&f.m.from_mont(&x), len))
    }
}

// A few facts about a curve that must hold if the parameters and the
// arithmetic are both right: the generator is on the curve, 1*G is G,
// and n*G is the point at infinity. Printed by --ec-check for the suite.
pub fn self_facts(curve: &Curve) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let f = match Field::new(&unhex(curve.p)) {
        Some(f) => f,
        None => return vec![("field".to_string(), "could not be built".to_string())],
    };
    let nbytes = (curve.bits + 7) / 8;
    let gx = f.m.to_mont(&f.m.reduce(&bignum::from_be(&unhex(curve.gx))));
    let gy = f.m.to_mont(&f.m.reduce(&bignum::from_be(&unhex(curve.gy))));
    let b = f.m.to_mont(&f.m.reduce(&bignum::from_be(&unhex(curve.b))));
    let lhs = f.mul(&gy, &gy);
    let x3 = f.mul(&f.mul(&gx, &gx), &gx);
    let three_x = f.add(&f.dbl(&gx), &gx);
    let rhs = f.add(&f.sub(&x3, &three_x), &b);
    out.push((
        "generator on curve".to_string(),
        (lhs == rhs).to_string(),
    ));
    let g = Jac {
        x: gx,
        y: gy,
        z: f.one.clone(),
    };
    let one = g.mul_scalar(&[1], &f);
    let hex = |v: Option<Vec<u8>>| match v {
        Some(b) => b.iter().map(|x| format!("{:02x}", x)).collect::<String>(),
        None => "infinity".to_string(),
    };
    out.push(("1G x".to_string(), hex(one.affine_x(&f, nbytes))));
    let two = g.double(&f);
    out.push(("2G x".to_string(), hex(two.affine_x(&f, nbytes))));
    let three = two.add(&g, &f);
    out.push(("3G x".to_string(), hex(three.affine_x(&f, nbytes))));
    let ng = g.mul_scalar(&unhex(curve.n), &f);
    out.push(("nG x".to_string(), hex(ng.affine_x(&f, nbytes))));
    out
}

pub enum EcError {
    UnknownCurve,
    BadPoint(String),
    BadSignature(String),
}

// ECDSA, FIPS 186-4 section 6.4.2.
pub fn verify(
    curve: &Curve,
    point: &[u8],
    digest: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<bool, EcError> {
    let p = unhex(curve.p);
    let f = match Field::new(&p) {
        Some(f) => f,
        None => return Err(EcError::UnknownCurve),
    };
    let nbytes = (curve.bits + 7) / 8;
    if point.len() != 1 + 2 * nbytes || point[0] != 0x04 {
        return Err(EcError::BadPoint("not an uncompressed point".to_string()));
    }
    let order = Mont::new(&bignum::from_be(&unhex(curve.n))).ok_or(EcError::UnknownCurve)?;

    let rn = bignum::from_be(r);
    let sn = bignum::from_be(s);
    if bignum::is_zero(&rn)
        || bignum::is_zero(&sn)
        || bignum::cmp(&rn, &order.n) != std::cmp::Ordering::Less
        || bignum::cmp(&sn, &order.n) != std::cmp::Ordering::Less
    {
        return Err(EcError::BadSignature(
            "r or s is zero or not below the group order".to_string(),
        ));
    }

    // Check that the public key is on the curve. A verifier that skips
    // this will happily do arithmetic in a group it was handed.
    let qx = f.m.to_mont(&f.m.reduce(&bignum::from_be(&point[1..1 + nbytes])));
    let qy = f.m.to_mont(&f.m.reduce(&bignum::from_be(&point[1 + nbytes..])));
    let b = f.m.to_mont(&f.m.reduce(&bignum::from_be(&unhex(curve.b))));
    let lhs = f.mul(&qy, &qy);
    let x3 = f.mul(&f.mul(&qx, &qx), &qx);
    let three_x = f.add(&f.dbl(&qx), &qx);
    let rhs = f.add(&f.sub(&x3, &three_x), &b);
    if lhs != rhs {
        return Err(EcError::BadPoint("the point is not on the curve".to_string()));
    }

    // e is the leftmost bits of the digest, as many as the group order
    // has. For P-521 and SHA-256 the digest is shorter than the order and
    // nothing is dropped; for P-256 and SHA-512 it is longer and the tail
    // goes.
    let mut e = digest.to_vec();
    let want = (curve.bits + 7) / 8;
    if e.len() > want {
        e.truncate(want);
    }
    let mut en = bignum::from_be(&e);
    let excess = (e.len() * 8).saturating_sub(curve.bits);
    if excess > 0 {
        en = shr(&en, excess);
    }
    let en = order.reduce(&en);

    // mont_mul(a*R, b) is the plain product a*b mod n, so the inverse is
    // kept in plain form and multiplied into a Montgomery-form operand.
    let w = order.inv_prime(&order.reduce(&sn));
    let u1 = order.mul(&order.to_mont(&en), &w);
    let u2 = order.mul(&order.to_mont(&order.reduce(&rn)), &w);

    let g = Jac {
        x: f.m.to_mont(&f.m.reduce(&bignum::from_be(&unhex(curve.gx)))),
        y: f.m.to_mont(&f.m.reduce(&bignum::from_be(&unhex(curve.gy)))),
        z: f.one.clone(),
    };
    let q = Jac {
        x: qx,
        y: qy,
        z: f.one.clone(),
    };
    let p1 = g.mul_scalar(&bignum::to_be(&u1, nbytes), &f);
    let p2 = q.mul_scalar(&bignum::to_be(&u2, nbytes), &f);
    let sum = p1.add(&p2, &f);
    let x = match sum.affine_x(&f, nbytes) {
        Some(x) => x,
        None => return Ok(false),
    };
    let xv = order.reduce(&bignum::from_be(&x));
    Ok(bignum::cmp(&xv, &order.reduce(&rn)) == std::cmp::Ordering::Equal)
}

fn shr(a: &[u32], bits: usize) -> Limbs {
    let words = bits / 32;
    let rest = bits % 32;
    let mut out = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        let lo = *a.get(i + words).unwrap_or(&0);
        let hi = *a.get(i + words + 1).unwrap_or(&0);
        out.push(if rest == 0 {
            lo
        } else {
            (lo >> rest) | (hi << (32 - rest))
        });
    }
    bignum::trim(&mut out);
    out
}
