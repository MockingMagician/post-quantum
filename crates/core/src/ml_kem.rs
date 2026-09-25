//! ML-KEM-1024, implemented from FIPS 203 algorithms 3–21.
//! No source from a third-party implementation is incorporated.
use crate::{
    arithmetic::{self as a, Poly},
    hash,
};
use post_quantum_platform::Zeroizing;

const Q: u32 = 3329;
const K: usize = 4;
const ZETAS: [u32; 128] = a::roots::<Q, 128>(17, 7);
pub(crate) const PUBLIC_LEN: usize = 1568;
pub(crate) const CIPHERTEXT_LEN: usize = 1568;
#[cfg(test)]
const EXPANDED_LEN: usize = 3168;

#[derive(Clone)]
pub(crate) struct PublicKey {
    bytes: [u8; PUBLIC_LEN],
    t: [Poly; K],
    rho: [u8; 32],
    hash: [u8; 32],
}
pub(crate) struct PrivateKey {
    s: Zeroizing<[Poly; K]>,
    public: PublicKey,
    z: Zeroizing<[u8; 32]>,
}

fn ntt(f: &mut Poly) {
    let mut index = 1;
    let mut length = 128;
    while length >= 2 {
        for start in (0..256).step_by(2 * length) {
            let zeta = ZETAS[index];
            index += 1;
            for j in start..start + length {
                let t = a::mul::<Q>(zeta, f[j + length]);
                f[j + length] = a::sub::<Q>(f[j], t);
                f[j] = a::add::<Q>(f[j], t);
            }
        }
        length /= 2;
    }
}
fn inverse_ntt(f: &mut Poly) {
    let mut index = 127;
    let mut length = 2;
    while length <= 128 {
        for start in (0..256).step_by(2 * length) {
            let zeta = ZETAS[index];
            index -= 1;
            for j in start..start + length {
                let left = f[j];
                f[j] = a::add::<Q>(left, f[j + length]);
                f[j + length] = a::mul::<Q>(zeta, a::sub::<Q>(f[j + length], left));
            }
        }
        length *= 2;
    }
    for x in f {
        *x = a::mul::<Q>(*x, 3303);
    } // inverse of 128 modulo Q
}
fn multiply_accumulate(output: &mut Poly, left: &Poly, right: &Poly) {
    for i in 0..128 {
        // gamma = 17^(2 BitRev7(i)+1). Public index, fixed work.
        let gamma = a::mul::<Q>(17, a::mul::<Q>(ZETAS[i], ZETAS[i]));
        let (a0, a1, b0, b1) = (left[2 * i], left[2 * i + 1], right[2 * i], right[2 * i + 1]);
        output[2 * i] = a::add::<Q>(
            output[2 * i],
            a::add::<Q>(a::mul::<Q>(a0, b0), a::mul::<Q>(gamma, a::mul::<Q>(a1, b1))),
        );
        output[2 * i + 1] = a::add::<Q>(
            output[2 * i + 1],
            a::add::<Q>(a::mul::<Q>(a0, b1), a::mul::<Q>(a1, b0)),
        );
    }
}
fn matrix_entry(rho: &[u8; 32], row: usize, col: usize) -> Poly {
    let indices = [col as u8, row as u8];
    let mut xof = hash::shake128(&[rho, &indices]);
    let mut result = [0; 256];
    let mut filled = 0;
    while filled < 256 {
        let mut bytes = [0; 3];
        xof.read(&mut bytes);
        let x = u32::from(bytes[0]) + 256 * u32::from(bytes[1] & 15);
        let y = u32::from(bytes[1] >> 4) + 16 * u32::from(bytes[2]);
        // Rejection only depends on the public matrix seed.
        for value in [x, y] {
            if value < Q && filled < 256 {
                result[filled] = value;
                filled += 1;
            }
        }
    }
    result
}
fn noise(seed: &[u8; 32], nonce: u8, result: &mut Poly) {
    let mut bytes = Zeroizing::new([0u8; 128]);
    hash::shake256(&[seed, &[nonce]]).read(&mut bytes[..]);
    for (i, value) in result.iter_mut().enumerate() {
        let bits = (bytes[i / 2] >> (4 * (i % 2))) & 15;
        let positive = i32::from(bits & 1) + i32::from((bits >> 1) & 1);
        let negative = i32::from((bits >> 2) & 1) + i32::from((bits >> 3) & 1);
        *value = a::from_centered::<Q>(positive - negative);
    }
}

fn compress(value: u32, bits: usize) -> u32 {
    let numerator = (value << bits) + (Q / 2);
    // Reciprocal quotient followed by one correction: numerator < 2^24.
    let quotient = ((u64::from(numerator) * ((1u64 << 32) / u64::from(Q))) >> 32) as u32;
    let remainder = numerator - quotient * Q;
    let correction = (remainder.wrapping_sub(Q) >> 31) ^ 1;
    (quotient + correction) & ((1 << bits) - 1)
}
fn decompress(value: u32, bits: usize) -> u32 {
    (value * Q + (1 << (bits - 1))) >> bits
}

impl PublicKey {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        let bytes: [u8; PUBLIC_LEN] = bytes.try_into().map_err(|_| ())?;
        let mut t = [[0; 256]; K];
        for (i, poly) in t.iter_mut().enumerate() {
            a::unpack(&bytes[i * 384..(i + 1) * 384], 12, poly);
            if poly.iter().any(|&coefficient| coefficient >= Q) {
                return Err(());
            }
        }
        let mut rho = [0; 32];
        rho.copy_from_slice(&bytes[K * 384..]);
        let hash = hash::sha3_256(&[&bytes]);
        Ok(Self {
            bytes,
            t,
            rho,
            hash,
        })
    }
    pub(crate) fn as_bytes(&self) -> &[u8; PUBLIC_LEN] {
        &self.bytes
    }
    pub(crate) fn encapsulate(&self, message: &[u8; 32]) -> (Vec<u8>, Zeroizing<[u8; 32]>) {
        let expanded = Zeroizing::new(hash::sha3_512(&[message, &self.hash]));
        let mut secret = Zeroizing::new([0; 32]);
        secret.copy_from_slice(&expanded[..32]);
        let mut coins = Zeroizing::new([0; 32]);
        coins.copy_from_slice(&expanded[32..]);
        (self.encrypt(message, &coins), secret)
    }
    fn encrypt(&self, message: &[u8; 32], coins: &[u8; 32]) -> Vec<u8> {
        let mut r = Zeroizing::new([[0; 256]; K]);
        for (i, poly) in r.iter_mut().enumerate() {
            noise(coins, i as u8, poly);
            ntt(poly);
        }
        let mut result = vec![0; CIPHERTEXT_LEN];
        for i in 0..K {
            let mut u = Zeroizing::new([0; 256]);
            for (j, rj) in r.iter().enumerate() {
                multiply_accumulate(&mut u, &matrix_entry(&self.rho, j, i), rj);
            }
            inverse_ntt(&mut u);
            let mut error = Zeroizing::new([0; 256]);
            noise(coins, (K + i) as u8, &mut error);
            for (value, &error) in u.iter_mut().zip(error.iter()) {
                *value = compress(a::add::<Q>(*value, error), 11);
            }
            a::pack(&u[..], 11, &mut result[i * 352..(i + 1) * 352]);
        }
        let mut v = Zeroizing::new([0; 256]);
        for (tj, rj) in self.t.iter().zip(r.iter()) {
            multiply_accumulate(&mut v, tj, rj);
        }
        inverse_ntt(&mut v);
        let mut error = Zeroizing::new([0; 256]);
        noise(coins, (2 * K) as u8, &mut error);
        for (i, value) in v.iter_mut().enumerate() {
            let bit = u32::from((message[i / 8] >> (i % 8)) & 1);
            *value = compress(
                a::add::<Q>(a::add::<Q>(*value, error[i]), decompress(bit, 1)),
                5,
            );
        }
        a::pack(&v[..], 5, &mut result[1408..]);
        result
    }
}
impl PrivateKey {
    pub(crate) fn from_seed(seed: &[u8; 64]) -> Self {
        let expanded = Zeroizing::new(hash::sha3_512(&[&seed[..32], &[K as u8]]));
        let mut rho = [0; 32];
        rho.copy_from_slice(&expanded[..32]);
        let mut sigma = Zeroizing::new([0; 32]);
        sigma.copy_from_slice(&expanded[32..]);
        let mut s = Zeroizing::new([[0; 256]; K]);
        for (i, poly) in s.iter_mut().enumerate() {
            noise(&sigma, i as u8, poly);
            ntt(poly);
        }
        let mut t = [[0; 256]; K];
        for (i, ti) in t.iter_mut().enumerate() {
            noise(&sigma, (K + i) as u8, ti);
            ntt(ti);
            for (j, sj) in s.iter().enumerate() {
                multiply_accumulate(ti, &matrix_entry(&rho, i, j), sj);
            }
        }
        let mut bytes = [0; PUBLIC_LEN];
        for (i, ti) in t.iter().enumerate() {
            a::pack(ti, 12, &mut bytes[i * 384..(i + 1) * 384]);
        }
        bytes[K * 384..].copy_from_slice(&rho);
        let hash = hash::sha3_256(&[&bytes]);
        let public = PublicKey {
            bytes,
            t,
            rho,
            hash,
        };
        let mut z = Zeroizing::new([0; 32]);
        z.copy_from_slice(&seed[32..]);
        Self { s, public, z }
    }
    pub(crate) fn public_key(&self) -> PublicKey {
        self.public.clone()
    }
    pub(crate) fn decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, ()> {
        if ct.len() != CIPHERTEXT_LEN {
            return Err(());
        }
        let mut product = Zeroizing::new([0; 256]);
        for (i, si) in self.s.iter().enumerate() {
            let mut u = Zeroizing::new([0; 256]);
            a::unpack(&ct[i * 352..(i + 1) * 352], 11, &mut u[..]);
            for x in u.iter_mut() {
                *x = decompress(*x, 11);
            }
            ntt(&mut u);
            multiply_accumulate(&mut product, si, &u);
        }
        inverse_ntt(&mut product);
        let mut v = Zeroizing::new([0; 256]);
        a::unpack(&ct[1408..], 5, &mut v[..]);
        let mut message = Zeroizing::new([0; 32]);
        for i in 0..256 {
            let bit = compress(a::sub::<Q>(decompress(v[i], 5), product[i]), 1);
            message[i / 8] |= (bit as u8) << (i % 8);
        }
        let expanded = Zeroizing::new(hash::sha3_512(&[&message[..], &self.public.hash]));
        let mut coins = Zeroizing::new([0; 32]);
        coins.copy_from_slice(&expanded[32..]);
        // For an invalid input, this recomputed value is derived from the
        // private decryption result and is never released as a ciphertext.
        let expected = Zeroizing::new(self.public.encrypt(&message, &coins));
        let mask = a::equal_mask(ct, &expected);
        let mut secret = Zeroizing::new([0; 32]);
        hash::shake256(&[&self.z[..], ct]).read(&mut secret[..]);
        for i in 0..32 {
            secret[i] = a::select_byte(secret[i], expanded[i], mask);
        }
        Ok(secret)
    }
    #[cfg(test)]
    pub(crate) fn expanded_bytes(&self) -> Vec<u8> {
        let mut out = vec![0; EXPANDED_LEN];
        for (i, si) in self.s.iter().enumerate() {
            a::pack(si, 12, &mut out[i * 384..(i + 1) * 384]);
        }
        out[1536..3104].copy_from_slice(self.public.as_bytes());
        out[3104..3136].copy_from_slice(&self.public.hash);
        out[3136..].copy_from_slice(&self.z[..]);
        out
    }
    #[cfg(test)]
    pub(crate) fn from_expanded(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() != EXPANDED_LEN {
            return Err(());
        }
        let public = PublicKey::from_bytes(&bytes[1536..3104])?;
        if a::equal_mask(&public.hash, &bytes[3104..3136]) != 255 {
            return Err(());
        }
        let mut s = Zeroizing::new([[0; 256]; K]);
        for (i, si) in s.iter_mut().enumerate() {
            a::unpack(&bytes[i * 384..(i + 1) * 384], 12, si);
            for x in si {
                *x = a::reduce_once::<Q>(*x);
            }
        }
        let mut z = Zeroizing::new([0; 32]);
        z.copy_from_slice(&bytes[3136..]);
        Ok(Self { s, public, z })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transform_roundtrip_and_negacyclic_product() {
        let mut x = [0; 256];
        let mut y = [0; 256];
        for i in 0..256 {
            x[i] = (i * i + 7) as u32 % Q;
            y[i] = (13 * i + 31) as u32 % Q;
        }
        let mut transformed = x;
        ntt(&mut transformed);
        inverse_ntt(&mut transformed);
        assert_eq!(transformed, x);
        let mut expected = [0; 256];
        for (i, &xi) in x.iter().enumerate() {
            for (j, &yj) in y.iter().enumerate() {
                let term = ((u64::from(xi) * u64::from(yj)) % u64::from(Q)) as u32;
                let k = (i + j) % 256;
                expected[k] = if i + j < 256 {
                    (expected[k] + term) % Q
                } else {
                    (expected[k] + Q - term) % Q
                };
            }
        }
        ntt(&mut x);
        ntt(&mut y);
        let mut product = [0; 256];
        multiply_accumulate(&mut product, &x, &y);
        inverse_ntt(&mut product);
        assert_eq!(product, expected);
    }
    #[test]
    fn rounding_matches_integer_definition() {
        for d in [1, 5, 11] {
            for value in 0..Q {
                assert_eq!(
                    compress(value, d),
                    (((value << d) + Q / 2) / Q) & ((1 << d) - 1)
                );
            }
        }
    }
}
