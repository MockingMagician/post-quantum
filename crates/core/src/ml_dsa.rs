//! ML-DSA-87 written from FIPS 204, including the published 2026 errata.
//! Ordinary field residues and literal specification encodings are used. This
//! module does not incorporate any third-party implementation source.
use crate::{
    arithmetic::{self as a, Poly},
    hash,
};
use post_quantum_platform::Zeroizing;

const Q: u32 = 8380417;
const K: usize = 8;
const L: usize = 7;
const ETA: i32 = 2;
const TAU: usize = 60;
const BETA: u32 = 120;
const GAMMA1: u32 = 1 << 19;
const GAMMA2: u32 = (Q - 1) / 32;
const OMEGA: usize = 75;
const D: usize = 13;
const ZETAS: [u32; 256] = a::roots::<Q, 256>(1753, 8);
pub(crate) const PUBLIC_LEN: usize = 2592;
pub(crate) const SIGNATURE_LEN: usize = 4627;
const SIGNING_ATTEMPTS: usize = 1024; // >= corrected FIPS 204 Appendix C minimum 821
#[cfg(test)]
const EXPANDED_LEN: usize = 4896;

#[derive(Clone)]
pub(crate) struct PublicKey {
    bytes: [u8; PUBLIC_LEN],
    rho: [u8; 32],
    t1: [Poly; K],
    tr: [u8; 64],
}
pub(crate) struct PrivateKey {
    public: PublicKey,
    key: Zeroizing<[u8; 32]>,
    s1: Zeroizing<[Poly; L]>, // NTT representation
    s2: Zeroizing<[Poly; K]>,
    t0: Zeroizing<[Poly; K]>,
    matrix: Vec<Poly>, // Public, row-major K by L matrix in NTT representation.
}

fn ntt(f: &mut Poly) {
    let mut index = 1;
    let mut length = 128;
    while length != 0 {
        for start in (0..256).step_by(2 * length) {
            let zeta = ZETAS[index];
            index += 1;
            for j in start..start + length {
                let product = a::mul::<Q>(zeta, f[j + length]);
                f[j + length] = a::sub::<Q>(f[j], product);
                f[j] = a::add::<Q>(f[j], product);
            }
        }
        length /= 2;
    }
}
fn inverse_ntt(f: &mut Poly) {
    let mut index = 255;
    let mut length = 1;
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
        *x = a::mul::<Q>(*x, 8347681);
    } // 256^-1 modulo Q
}
fn matrix(rho: &[u8; 32]) -> Vec<Poly> {
    let mut matrix = Vec::with_capacity(K * L);
    for row in 0..K {
        for col in 0..L {
            let indices = [col as u8, row as u8];
            let mut stream = hash::shake128(&[rho, &indices]);
            let mut poly = [0; 256];
            let mut filled = 0;
            while filled < 256 {
                let mut bytes = [0; 3];
                stream.read(&mut bytes);
                let value = u32::from(bytes[0])
                    | (u32::from(bytes[1]) << 8)
                    | (u32::from(bytes[2] & 127) << 16);
                if value < Q {
                    poly[filled] = value;
                    filled += 1;
                }
            }
            matrix.push(poly);
        }
    }
    matrix
}
fn small_poly(seed: &[u8; 64], nonce: u16, poly: &mut Poly) {
    let nonce = nonce.to_le_bytes();
    let mut stream = hash::shake256(&[seed, &nonce]);
    let mut filled = 0;
    while filled < 256 {
        let mut byte = Zeroizing::new([0]);
        stream.read(&mut byte[..]);
        for half in [byte[0] & 15, byte[0] >> 4] {
            // FIPS rejection depends on fresh pseudorandom sampling output.
            if half < 15 && filled < 256 {
                // For half<15, reduction modulo 5 is exactly this reciprocal.
                let quotient = (u32::from(half) * 205) >> 10;
                let residue = u32::from(half) - 5 * quotient;
                poly[filled] = a::from_centered::<Q>(ETA - residue as i32);
                filled += 1;
            }
        }
    }
}
fn mask_poly(seed: &[u8; 64], nonce: u16, poly: &mut Poly) {
    let nonce = nonce.to_le_bytes();
    let mut bytes = Zeroizing::new([0; 640]);
    hash::shake256(&[seed, &nonce]).read(&mut bytes[..]);
    a::unpack(&bytes[..], 20, poly);
    for x in poly {
        *x = a::from_centered::<Q>(GAMMA1 as i32 - *x as i32);
    }
}
fn challenge(seed: &[u8; 64]) -> Poly {
    let mut stream = hash::shake256(&[seed]);
    let mut signs = [0; 8];
    stream.read(&mut signs);
    let signs = u64::from_le_bytes(signs);
    let mut result = [0; 256];
    for i in 256 - TAU..256 {
        let j = loop {
            let mut byte = [0];
            stream.read(&mut byte);
            if usize::from(byte[0]) <= i {
                break usize::from(byte[0]);
            }
        };
        result[i] = result[j];
        let sign = ((signs >> (i + TAU - 256)) & 1) as u32;
        result[j] = 1 + sign * (Q - 2);
    }
    result
}
fn matrix_product(matrix: &[Poly], v: &[Poly; L]) -> Zeroizing<[Poly; K]> {
    let mut output = Zeroizing::new([[0; 256]; K]);
    for (row, out) in output.iter_mut().enumerate() {
        for (column, vector) in v.iter().enumerate() {
            for (j, x) in out.iter_mut().enumerate() {
                *x = a::add::<Q>(*x, a::mul::<Q>(matrix[row * L + column][j], vector[j]));
            }
        }
        inverse_ntt(out);
    }
    output
}
fn challenge_product<const N: usize>(c: &Poly, v: &[Poly; N]) -> Zeroizing<[Poly; N]> {
    let mut output = Zeroizing::new([[0; 256]; N]);
    for (out, poly) in output.iter_mut().zip(v) {
        for i in 0..256 {
            out[i] = a::mul::<Q>(c[i], poly[i]);
        }
        inverse_ntt(out);
    }
    output
}
fn power2round(x: u32) -> (u32, i32) {
    let high = (x + (1 << (D - 1)) - 1) >> D;
    (high, x as i32 - ((high << D) as i32))
}
fn decompose(x: u32) -> (u32, i32) {
    const ALPHA: u32 = 2 * GAMMA2;
    let numerator = x + GAMMA2 - 1;
    let quotient = ((u64::from(numerator) * ((1u64 << 32) / u64::from(ALPHA))) >> 32) as u32;
    let remainder = numerator - quotient * ALPHA;
    let high = quotient + ((remainder.wrapping_sub(ALPHA) >> 31) ^ 1);
    // The exceptional high=16 is mapped to high=0, low one smaller (mod Q).
    let exceptional = high >> 4;
    (
        high & 15,
        x as i32 - (high * ALPHA) as i32 - exceptional as i32,
    )
}
fn norm_exceeds<const N: usize>(v: &[Poly; N], bound: u32) -> bool {
    let mut violation = 0u32;
    for poly in v {
        for &x in poly {
            let centered = a::centered::<Q>(x);
            let sign = centered >> 31;
            let absolute = ((centered ^ sign) - sign) as u32;
            violation |= (absolute.wrapping_sub(bound) >> 31) ^ 1;
        }
    }
    violation != 0
}
fn signed_pack(poly: &Poly, bound: i32, width: usize, out: &mut [u8]) {
    let mut shifted = Zeroizing::new([0; 256]);
    for (target, &x) in shifted.iter_mut().zip(poly) {
        *target = (bound - a::centered::<Q>(x)) as u32;
    }
    a::pack(&shifted[..], width, out);
}
fn signed_unpack(input: &[u8], bound: i32, width: usize) -> Poly {
    let mut result = [0; 256];
    a::unpack(input, width, &mut result);
    for x in &mut result {
        *x = a::from_centered::<Q>(bound - *x as i32);
    }
    result
}
fn encode_high(v: &[Poly; K]) -> [u8; 1024] {
    let mut output = [0; 1024];
    for (i, poly) in v.iter().enumerate() {
        let mut high = Zeroizing::new([0; 256]);
        for (h, &x) in high.iter_mut().zip(poly) {
            *h = decompose(x).0;
        }
        a::pack(&high[..], 4, &mut output[i * 128..(i + 1) * 128]);
    }
    output
}
fn hash64(parts: &[&[u8]]) -> [u8; 64] {
    let mut out = [0; 64];
    hash::shake256(parts).read(&mut out);
    out
}

impl PrivateKey {
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        let mut expanded = Zeroizing::new([0; 128]);
        hash::shake256(&[seed, &[K as u8, L as u8]]).read(&mut expanded[..]);
        let mut rho = [0; 32];
        rho.copy_from_slice(&expanded[..32]);
        let mut secret_seed = Zeroizing::new([0; 64]);
        secret_seed.copy_from_slice(&expanded[32..96]);
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&expanded[96..]);
        let matrix = matrix(&rho);
        let mut s1 = Zeroizing::new([[0; 256]; L]);
        let mut s2 = Zeroizing::new([[0; 256]; K]);
        for (i, poly) in s1.iter_mut().enumerate() {
            small_poly(&secret_seed, i as u16, poly);
            ntt(poly);
        }
        for (i, poly) in s2.iter_mut().enumerate() {
            small_poly(&secret_seed, (L + i) as u16, poly);
        }
        let mut t = matrix_product(&matrix, &s1);
        let mut t0 = Zeroizing::new([[0; 256]; K]);
        let mut t1 = [[0; 256]; K];
        for i in 0..K {
            for j in 0..256 {
                t[i][j] = a::add::<Q>(t[i][j], s2[i][j]);
                let (high, low) = power2round(t[i][j]);
                t1[i][j] = high;
                t0[i][j] = a::from_centered::<Q>(low);
            }
        }
        for poly in s2.iter_mut() {
            ntt(poly);
        }
        for poly in t0.iter_mut() {
            ntt(poly);
        }
        let mut bytes = [0; PUBLIC_LEN];
        bytes[..32].copy_from_slice(&rho);
        for (i, poly) in t1.iter().enumerate() {
            a::pack(poly, 10, &mut bytes[32 + i * 320..32 + (i + 1) * 320]);
        }
        let tr = hash64(&[&bytes]);
        Self {
            public: PublicKey { bytes, rho, t1, tr },
            key,
            s1,
            s2,
            t0,
            matrix,
        }
    }
    pub(crate) fn public_key(&self) -> PublicKey {
        self.public.clone()
    }
    pub(crate) fn sign(
        &self,
        message: &[u8],
        context: &[u8],
        randomness: &[u8; 32],
    ) -> Result<Vec<u8>, ()> {
        if context.len() > 255 {
            return Err(());
        }
        self.sign_parts(
            &[&[0, context.len() as u8], context, message],
            randomness,
            SIGNING_ATTEMPTS,
        )
    }
    fn sign_parts(
        &self,
        message: &[&[u8]],
        randomness: &[u8; 32],
        attempt_limit: usize,
    ) -> Result<Vec<u8>, ()> {
        let mut mu_parts = Vec::with_capacity(message.len() + 1);
        mu_parts.push(&self.public.tr[..]);
        mu_parts.extend_from_slice(message);
        let mu = Zeroizing::new(hash64(&mu_parts));
        let private_seed = Zeroizing::new(hash64(&[&self.key[..], randomness, &mu[..]]));
        for iteration in 0..attempt_limit.min(SIGNING_ATTEMPTS) {
            let mut y = Zeroizing::new([[0; 256]; L]);
            for (i, poly) in y.iter_mut().enumerate() {
                mask_poly(&private_seed, (iteration * L + i) as u16, poly);
            }
            let mut y_ntt = Zeroizing::new(*y);
            for poly in y_ntt.iter_mut() {
                ntt(poly);
            }
            let w = matrix_product(&self.matrix, &y_ntt);
            let encoded_high = Zeroizing::new(encode_high(&w));
            let commitment = Zeroizing::new(hash64(&[&mu[..], &encoded_high[..]]));
            let mut c = Zeroizing::new(challenge(&commitment));
            ntt(&mut c);
            let mut z = challenge_product(&c, &self.s1);
            for i in 0..L {
                for j in 0..256 {
                    z[i][j] = a::add::<Q>(z[i][j], y[i][j]);
                }
            }
            let cs2 = challenge_product(&c, &self.s2);
            let mut adjusted = Zeroizing::new([[0; 256]; K]);
            let mut low = Zeroizing::new([[0; 256]; K]);
            for i in 0..K {
                for j in 0..256 {
                    adjusted[i][j] = a::sub::<Q>(w[i][j], cs2[i][j]);
                    low[i][j] = a::from_centered::<Q>(decompose(adjusted[i][j]).1);
                }
            }
            // Accumulate each norm over the entire vectors. The only rejection
            // branch is the one required by the FIPS Fiat-Shamir-with-aborts loop.
            let first_rejection =
                norm_exceeds(&z, GAMMA1 - BETA) | norm_exceeds(&low, GAMMA2 - BETA);
            if first_rejection {
                continue;
            }
            let ct0 = challenge_product(&c, &self.t0);
            let mut hints = Zeroizing::new([[0u8; 256]; K]);
            let mut count = 0usize;
            for i in 0..K {
                for j in 0..256 {
                    let original = decompose(adjusted[i][j]).0;
                    let with_t0 = decompose(a::add::<Q>(adjusted[i][j], ct0[i][j])).0;
                    hints[i][j] = u8::from(original != with_t0);
                    count += usize::from(hints[i][j]);
                }
            }
            if norm_exceeds(&ct0, GAMMA2) || count > OMEGA {
                continue;
            }
            let mut signature = vec![0; SIGNATURE_LEN];
            signature[..64].copy_from_slice(&commitment[..]);
            for (i, poly) in z.iter().enumerate() {
                signed_pack(
                    poly,
                    GAMMA1 as i32,
                    20,
                    &mut signature[64 + i * 640..64 + (i + 1) * 640],
                );
            }
            let hint_start = 64 + L * 640;
            let mut cursor = 0;
            // These accepted hints are part of the public signature.
            for (i, poly) in hints.iter().enumerate() {
                for (j, &hint) in poly.iter().enumerate() {
                    if hint != 0 {
                        signature[hint_start + cursor] = j as u8;
                        cursor += 1;
                    }
                }
                signature[hint_start + OMEGA + i] = cursor as u8;
            }
            return Ok(signature);
        }
        // Exhaustion never releases the rejected response or secret scratch.
        Err(())
    }
    #[cfg(test)]
    pub(crate) fn expanded_bytes(&self) -> Vec<u8> {
        let mut result = vec![0; EXPANDED_LEN];
        result[..32].copy_from_slice(&self.public.rho);
        result[32..64].copy_from_slice(&self.key[..]);
        result[64..128].copy_from_slice(&self.public.tr);
        let mut offset = 128;
        for poly in self.s1.iter().chain(self.s2.iter()) {
            let mut ordinary = Zeroizing::new(*poly);
            inverse_ntt(&mut ordinary);
            signed_pack(&ordinary, ETA, 3, &mut result[offset..offset + 96]);
            offset += 96;
        }
        for poly in self.t0.iter() {
            let mut ordinary = Zeroizing::new(*poly);
            inverse_ntt(&mut ordinary);
            signed_pack(
                &ordinary,
                1 << (D - 1),
                D,
                &mut result[offset..offset + 416],
            );
            offset += 416;
        }
        result
    }
    #[cfg(test)]
    pub(crate) fn from_expanded(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() != EXPANDED_LEN {
            return Err(());
        }
        let mut rho = [0; 32];
        rho.copy_from_slice(&bytes[..32]);
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&bytes[32..64]);
        let mut tr = [0; 64];
        tr.copy_from_slice(&bytes[64..128]);
        let mut s1 = Zeroizing::new([[0; 256]; L]);
        let mut s2 = Zeroizing::new([[0; 256]; K]);
        let mut t0 = Zeroizing::new([[0; 256]; K]);
        let mut offset = 128;
        for poly in s1.iter_mut().chain(s2.iter_mut()) {
            *poly = signed_unpack(&bytes[offset..offset + 96], ETA, 3);
            ntt(poly);
            offset += 96;
        }
        for poly in t0.iter_mut() {
            *poly = signed_unpack(&bytes[offset..offset + 416], 1 << (D - 1), D);
            ntt(poly);
            offset += 416;
        }
        // ACVP signing uses tr from the supplied expanded key; public bytes are
        // unnecessary for this test-only entry point and are not exported.
        let public = PublicKey {
            bytes: [0; PUBLIC_LEN],
            rho,
            t1: [[0; 256]; K],
            tr,
        };
        let matrix = matrix(&rho);
        Ok(Self {
            public,
            key,
            s1,
            s2,
            t0,
            matrix,
        })
    }
    #[cfg(test)]
    pub(crate) fn sign_internal(
        &self,
        message: &[u8],
        randomness: &[u8; 32],
    ) -> Result<Vec<u8>, ()> {
        self.sign_parts(&[message], randomness, SIGNING_ATTEMPTS)
    }
}

impl PublicKey {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        let bytes: [u8; PUBLIC_LEN] = bytes.try_into().map_err(|_| ())?;
        let mut rho = [0; 32];
        rho.copy_from_slice(&bytes[..32]);
        let mut t1 = [[0; 256]; K];
        for (i, poly) in t1.iter_mut().enumerate() {
            a::unpack(&bytes[32 + i * 320..32 + (i + 1) * 320], 10, poly);
        }
        let tr = hash64(&[&bytes]);
        Ok(Self { bytes, rho, t1, tr })
    }
    pub(crate) fn as_bytes(&self) -> &[u8; PUBLIC_LEN] {
        &self.bytes
    }
    pub(crate) fn verify(&self, message: &[u8], context: &[u8], signature: &[u8]) -> bool {
        if context.len() > 255 {
            return false;
        }
        self.verify_parts(&[&[0, context.len() as u8], context, message], signature)
    }
    fn verify_parts(&self, message: &[&[u8]], signature: &[u8]) -> bool {
        if signature.len() != SIGNATURE_LEN {
            return false;
        }
        let mut commitment = [0; 64];
        commitment.copy_from_slice(&signature[..64]);
        let mut z = Zeroizing::new([[0; 256]; L]);
        for (i, poly) in z.iter_mut().enumerate() {
            *poly = signed_unpack(
                &signature[64 + i * 640..64 + (i + 1) * 640],
                GAMMA1 as i32,
                20,
            );
        }
        if norm_exceeds(&z, GAMMA1 - BETA) {
            return false;
        }
        let encoded_hint = &signature[64 + L * 640..];
        let mut hints = [[0u8; 256]; K];
        let mut cursor = 0usize;
        for (i, poly) in hints.iter_mut().enumerate() {
            let end = usize::from(encoded_hint[OMEGA + i]);
            if end < cursor || end > OMEGA {
                return false;
            }
            let first = cursor;
            while cursor < end {
                if cursor > first && encoded_hint[cursor - 1] >= encoded_hint[cursor] {
                    return false;
                }
                poly[usize::from(encoded_hint[cursor])] = 1;
                cursor += 1;
            }
        }
        if encoded_hint[cursor..OMEGA].iter().any(|&x| x != 0) {
            return false;
        }
        let mut mu_parts = Vec::with_capacity(message.len() + 1);
        mu_parts.push(&self.tr[..]);
        mu_parts.extend_from_slice(message);
        let mu = Zeroizing::new(hash64(&mu_parts));
        let mut c = challenge(&commitment);
        ntt(&mut c);
        for poly in z.iter_mut() {
            ntt(poly);
        }
        let mut w = matrix_product(&matrix(&self.rho), &z);
        let mut encoded = [0; 1024];
        for (i, poly) in self.t1.iter().enumerate() {
            let mut t = *poly;
            for x in &mut t {
                *x <<= D;
            }
            ntt(&mut t);
            for j in 0..256 {
                t[j] = a::mul::<Q>(t[j], c[j]);
            }
            inverse_ntt(&mut t);
            let mut high = [0; 256];
            for j in 0..256 {
                w[i][j] = a::sub::<Q>(w[i][j], t[j]);
                let (h, low) = decompose(w[i][j]);
                // Signature and public key inputs are public, but this also
                // avoids data-dependent branches for UseHint.
                let positive = ((low.wrapping_neg() as u32) >> 31) & 1;
                let step = positive * 2 + 15; // +1 or -1 modulo 16
                high[j] = (h + u32::from(hints[i][j]) * step) & 15;
            }
            a::pack(&high, 4, &mut encoded[i * 128..(i + 1) * 128]);
        }
        a::equal_mask(&commitment, &hash64(&[&mu[..], &encoded])) == 255
    }
    #[cfg(test)]
    pub(crate) fn verify_internal(&self, message: &[u8], signature: &[u8]) -> bool {
        self.verify_parts(&[message], signature)
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
        for i in 0..256 {
            x[i] = a::mul::<Q>(x[i], y[i]);
        }
        inverse_ntt(&mut x);
        assert_eq!(x, expected);
    }
    #[test]
    fn decomposition_matches_definition_exhaustively() {
        for r in 0..Q {
            let alpha = 2 * GAMMA2;
            let mut low = (r % alpha) as i32;
            if low > GAMMA2 as i32 {
                low -= alpha as i32;
            }
            let mut high = ((r as i32 - low) / alpha as i32) as u32;
            if high == 16 {
                high = 0;
                low -= 1;
            }
            assert_eq!(decompose(r), (high, low));
            let (h, l) = power2round(r);
            assert_eq!(h * (1 << D) + (l + (1 << D)) as u32, r + (1 << D));
            assert!(l > -(1 << (D - 1)) && l <= 1 << (D - 1));
        }
    }
    #[test]
    fn rejection_budget_failure_returns_no_signature() {
        let key = PrivateKey::from_seed(&[7; 32]);
        assert_eq!(key.sign_parts(&[b"budget"], &[3; 32], 0), Err(()));
        // This fixed seed/message/randomness rejects its first real candidate.
        // Exercise destruction after an actual attempt, not just an empty loop.
        assert_eq!(key.sign_parts(&[b"budget"], &[3; 32], 1), Err(()));
        let accepted = key
            .sign_parts(&[b"budget"], &[3; 32], SIGNING_ATTEMPTS)
            .unwrap();
        assert!(key.public_key().verify_internal(b"budget", &accepted));
        let signature = key.sign(b"message", b"context", &[4; 32]).unwrap();
        assert!(key.public_key().verify(b"message", b"context", &signature));
    }

    #[test]
    fn equivalent_but_noncanonical_hint_encodings_are_rejected() {
        let key = PrivateKey::from_seed(&[9; 32]);
        let public = key.public_key();
        let signature = key.sign(b"canonical", b"hints", &[12; 32]).unwrap();
        assert!(public.verify(b"canonical", b"hints", &signature));
        let offset = 64 + L * 640;
        let count = usize::from(signature[offset + OMEGA + K - 1]);
        assert!(count < OMEGA);
        let mut start = 0;
        let row = (0..K)
            .find(|&row| {
                let end = usize::from(signature[offset + OMEGA + row]);
                if end - start >= 2 {
                    true
                } else {
                    start = end;
                    false
                }
            })
            .unwrap();

        // Swapping these indices leaves the decoded hint polynomial unchanged.
        let mut unordered = signature.clone();
        unordered.swap(offset + start, offset + start + 1);
        assert!(!public.verify(b"canonical", b"hints", &unordered));

        // A duplicated index also leaves the polynomial unchanged if a decoder
        // merely sets each indexed bit. Its offsets otherwise remain valid.
        let mut duplicate = signature.clone();
        duplicate.copy_within(offset + start..offset + count, offset + start + 1);
        for i in row..K {
            duplicate[offset + OMEGA + i] += 1;
        }
        assert!(!public.verify(b"canonical", b"hints", &duplicate));

        // Padding is not part of any polynomial, but must still be all zero.
        let mut padding = signature;
        padding[offset + count] = 1;
        assert!(!public.verify(b"canonical", b"hints", &padding));
    }
}
