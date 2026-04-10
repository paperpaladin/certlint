// The modular arithmetic signature verification needs.
//
// Fixed-width unsigned integers in 32-bit limbs, little-endian, with
// Montgomery multiplication for everything modular. Montgomery rather than
// a general division because the modulus is always odd here (an RSA
// modulus, a prime field, a prime group order) and because a schoolbook
// long division inside a 2048-bit exponentiation is slow enough to be felt
// in a test suite.
//
// Nothing here is constant time, and it does not need to be: every number
// in this program is public. A verifier handles a signature, a modulus and
// a public key, and all three are in the certificate. Said here because
// the next person to read this will wonder, and because copying it into
// something that signs would be a real mistake.

pub type Limbs = Vec<u32>;

pub fn from_be(bytes: &[u8]) -> Limbs {
    let mut out = Vec::with_capacity(bytes.len() / 4 + 1);
    let mut i = bytes.len();
    while i >= 4 {
        out.push(u32::from_be_bytes([
            bytes[i - 4],
            bytes[i - 3],
            bytes[i - 2],
            bytes[i - 1],
        ]));
        i -= 4;
    }
    if i > 0 {
        let mut w = 0u32;
        for b in &bytes[..i] {
            w = (w << 8) | u32::from(*b);
        }
        out.push(w);
    }
    trim(&mut out);
    out
}

pub fn to_be(a: &[u32], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for i in 0..len {
        let w = *a.get(i / 4).unwrap_or(&0);
        out[len - 1 - i] = (w >> (8 * (i % 4))) as u8;
    }
    out
}

pub fn trim(a: &mut Limbs) {
    while a.last() == Some(&0) {
        a.pop();
    }
}

pub fn is_zero(a: &[u32]) -> bool {
    a.iter().all(|w| *w == 0)
}

pub fn cmp(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let n = a.len().max(b.len());
    for i in (0..n).rev() {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        if x != y {
            return if x < y { Ordering::Less } else { Ordering::Greater };
        }
    }
    Ordering::Equal
}

pub fn bit_len(a: &[u32]) -> usize {
    for i in (0..a.len()).rev() {
        if a[i] != 0 {
            return i * 32 + (32 - a[i].leading_zeros() as usize);
        }
    }
    0
}

// a - b, with a >= b, both padded to k limbs.
fn sub_in_place(a: &mut [u32], b: &[u32]) {
    let mut borrow = 0i64;
    for i in 0..a.len() {
        let t = i64::from(a[i]) - i64::from(*b.get(i).unwrap_or(&0)) - borrow;
        if t < 0 {
            a[i] = (t + (1i64 << 32)) as u32;
            borrow = 1;
        } else {
            a[i] = t as u32;
            borrow = 0;
        }
    }
}

// The modulus, with the constants Montgomery multiplication needs.
pub struct Mont {
    pub n: Limbs,
    pub k: usize,
    n0inv: u32,
    r2: Limbs,
}

impl Mont {
    pub fn new(modulus: &[u32]) -> Option<Mont> {
        let mut n = modulus.to_vec();
        trim(&mut n);
        if n.is_empty() || n[0] & 1 == 0 {
            // Montgomery needs an odd modulus. Every modulus in X.509 is
            // odd; a caller that hits this has been handed a malformed key
            // and gets None rather than a wrong answer.
            return None;
        }
        let k = n.len();
        // -n^-1 mod 2^32, by Newton iteration: five doublings of accuracy
        // take one correct bit to thirty-two.
        let n0 = n[0];
        let mut inv: u32 = 1;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inv)));
        }
        let n0inv = inv.wrapping_neg();
        let mut m = Mont {
            n: n.clone(),
            k,
            n0inv,
            r2: vec![0; k],
        };
        // R^2 mod n = 2^(64k) mod n, reached by doubling 1 that many
        // times. No division anywhere, and it runs once per modulus.
        let mut acc = vec![0u32; k];
        acc[0] = 1;
        if cmp(&acc, &n) != std::cmp::Ordering::Less {
            sub_in_place(&mut acc, &n);
        }
        for _ in 0..(64 * k) {
            double_mod(&mut acc, &n);
        }
        m.r2 = acc;
        Some(m)
    }

    // CIOS Montgomery multiplication: a*b*R^-1 mod n, with a and b already
    // in Montgomery form and below n.
    pub fn mul(&self, a: &[u32], b: &[u32]) -> Limbs {
        let k = self.k;
        let mut t = vec![0u32; k + 2];
        for i in 0..k {
            let bi = u64::from(*b.get(i).unwrap_or(&0));
            let mut c: u64 = 0;
            for j in 0..k {
                let x = u64::from(t[j]) + u64::from(*a.get(j).unwrap_or(&0)) * bi + c;
                t[j] = x as u32;
                c = x >> 32;
            }
            let x = u64::from(t[k]) + c;
            t[k] = x as u32;
            t[k + 1] = (x >> 32) as u32;

            let m = (t[0] as u64 * u64::from(self.n0inv)) as u32;
            let x = u64::from(t[0]) + u64::from(m) * u64::from(self.n[0]);
            let mut c = x >> 32;
            for j in 1..k {
                let x = u64::from(t[j]) + u64::from(m) * u64::from(self.n[j]) + c;
                t[j - 1] = x as u32;
                c = x >> 32;
            }
            let x = u64::from(t[k]) + c;
            t[k - 1] = x as u32;
            t[k] = t[k + 1] + (x >> 32) as u32;
        }
        let mut out = t[..k].to_vec();
        if t[k] != 0 || cmp(&out, &self.n) != std::cmp::Ordering::Less {
            sub_in_place(&mut out, &self.n);
        }
        out
    }

    pub fn to_mont(&self, a: &[u32]) -> Limbs {
        self.mul(a, &self.r2)
    }

    pub fn from_mont(&self, a: &[u32]) -> Limbs {
        let mut one = vec![0u32; self.k];
        one[0] = 1;
        self.mul(a, &one)
    }

    // a mod n for any a, by the schoolbook shift-and-subtract. Used once
    // per operand, never inside a loop.
    pub fn reduce(&self, a: &[u32]) -> Limbs {
        let mut acc = vec![0u32; self.k];
        for i in (0..bit_len(a)).rev() {
            double_mod(&mut acc, &self.n);
            if a[i / 32] >> (i % 32) & 1 == 1 {
                // Add one, with the carry. Setting the low bit is not the
                // same thing: double_mod subtracts an odd modulus when it
                // has to, so acc can already be odd and the bit would be
                // lost. That cost an afternoon.
                let mut c = 1u64;
                for w in acc.iter_mut() {
                    let x = u64::from(*w) + c;
                    *w = x as u32;
                    c = x >> 32;
                    if c == 0 {
                        break;
                    }
                }
                if cmp(&acc, &self.n) != std::cmp::Ordering::Less {
                    sub_in_place(&mut acc, &self.n);
                }
            }
        }
        acc
    }

    pub fn add(&self, a: &[u32], b: &[u32]) -> Limbs {
        let mut out = vec![0u32; self.k];
        let mut c = 0u64;
        for i in 0..self.k {
            let x = u64::from(*a.get(i).unwrap_or(&0))
                + u64::from(*b.get(i).unwrap_or(&0))
                + c;
            out[i] = x as u32;
            c = x >> 32;
        }
        if c != 0 || cmp(&out, &self.n) != std::cmp::Ordering::Less {
            sub_in_place(&mut out, &self.n);
        }
        out
    }

    pub fn sub(&self, a: &[u32], b: &[u32]) -> Limbs {
        let mut out = vec![0u32; self.k];
        out[..a.len().min(self.k)].copy_from_slice(&a[..a.len().min(self.k)]);
        if cmp(a, b) == std::cmp::Ordering::Less {
            let mut t = out.clone();
            // a - b + n, which is in range because both are below n.
            let mut nb = self.n.clone();
            sub_in_place(&mut nb, b);
            let mut c = 0u64;
            for i in 0..self.k {
                let x = u64::from(t[i]) + u64::from(nb[i]) + c;
                t[i] = x as u32;
                c = x >> 32;
            }
            return t;
        }
        sub_in_place(&mut out, b);
        out
    }

    // base^exp mod n, with exp as big-endian bytes. Square and multiply,
    // left to right, in Montgomery form throughout.
    pub fn pow(&self, base: &[u32], exp: &[u8]) -> Limbs {
        let b = self.to_mont(&self.reduce(base));
        let mut one = vec![0u32; self.k];
        one[0] = 1;
        let mut acc = self.to_mont(&one);
        let mut started = false;
        for byte in exp {
            for bit in (0..8).rev() {
                if started {
                    acc = self.mul(&acc, &acc);
                }
                if byte >> bit & 1 == 1 {
                    acc = if started { self.mul(&acc, &b) } else { b.clone() };
                    started = true;
                }
            }
        }
        if !started {
            return one;
        }
        self.from_mont(&acc)
    }

    // The inverse of a value that is already in Montgomery form, as a
    // value in Montgomery form. Going through the plain form both ways is
    // the only version of this that is easy to get right: an exponentiation
    // of a Montgomery-form operand computes something else entirely, and
    // the result still looks like a field element.
    pub fn inv_mont(&self, a_mont: &[u32]) -> Limbs {
        let plain = self.from_mont(a_mont);
        self.to_mont(&self.inv_prime(&plain))
    }

    // The inverse by Fermat, which needs the modulus to be prime. The
    // operand and the result are both in plain form.
    pub fn inv_prime(&self, a: &[u32]) -> Limbs {
        let mut e = to_be(&self.n, self.k * 4);
        // n - 2
        let mut i = e.len();
        let mut borrow = 2u16;
        while borrow > 0 && i > 0 {
            i -= 1;
            let v = u16::from(e[i]);
            if v >= borrow {
                e[i] = (v - borrow) as u8;
                borrow = 0;
            } else {
                e[i] = (v + 256 - borrow) as u8;
                borrow = 1;
            }
        }
        self.pow(a, &e)
    }
}

// acc = 2*acc mod n, with acc below n.
fn double_mod(acc: &mut [u32], n: &[u32]) {
    let mut carry = 0u32;
    for w in acc.iter_mut() {
        let nc = *w >> 31;
        *w = (*w << 1) | carry;
        carry = nc;
    }
    if carry != 0 || cmp(acc, n) != std::cmp::Ordering::Less {
        sub_in_place(acc, n);
    }
}
