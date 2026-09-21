//! HMAC/HKDF-SHA-512 and RFC 8439 ChaCha20-Poly1305, written from their
//! specifications. This module is private: only the bounded PQRS API is exposed.

use crate::hash::{Sha512, sha512};
use post_quantum_platform::{Zeroize, Zeroizing};

struct Hmac512 {
    inner: Sha512,
    outer: Sha512,
}
impl Hmac512 {
    fn new(key: &[u8]) -> Self {
        let mut block = Zeroizing::new([0u8; 128]);
        if key.len() > 128 {
            let digest = Zeroizing::new(sha512(&[key]));
            block[..64].copy_from_slice(&*digest);
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        for byte in block.iter_mut() {
            *byte ^= 0x36;
        }
        let mut inner = Sha512::new();
        inner.update(&*block);
        for byte in block.iter_mut() {
            *byte ^= 0x36 ^ 0x5c;
        }
        let mut outer = Sha512::new();
        outer.update(&*block);
        Self { inner, outer }
    }
    fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }
    fn finish(self) -> [u8; 64] {
        let Self { inner, mut outer } = self;
        let digest = Zeroizing::new(inner.finish());
        outer.update(&*digest);
        outer.finish()
    }
}

pub(crate) fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut hmac = Hmac512::new(key);
    for part in parts {
        hmac.update(part);
    }
    hmac.finish()
}

/// RFC 5869 extract followed by expand; an empty salt has HMAC's all-zero-key
/// meaning. The 255-block limit is checked before producing any output.
pub(crate) fn hkdf_sha512(
    ikm: &[u8],
    salt: &[u8],
    info: &[&[u8]],
    output: &mut [u8],
) -> Result<(), ()> {
    if output.len() > 255 * 64 {
        return Err(());
    }
    let prk = Zeroizing::new(hmac_sha512(salt, &[ikm]));
    let mut previous = Zeroizing::new([0u8; 64]);
    let mut previous_length = 0;
    for (index, chunk) in output.chunks_mut(64).enumerate() {
        let mut hmac = Hmac512::new(&*prk);
        hmac.update(&previous[..previous_length]);
        for part in info {
            hmac.update(part);
        }
        hmac.update(&[(index + 1) as u8]);
        *previous = hmac.finish();
        chunk.copy_from_slice(&previous[..chunk.len()]);
        previous_length = 64;
    }
    Ok(())
}

fn quarter(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

pub(crate) fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut initial = Zeroizing::new([0u32; 16]);
    initial[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    for (word, bytes) in initial[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().expect("key word"));
    }
    initial[12] = counter;
    for (word, bytes) in initial[13..].iter_mut().zip(nonce.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().expect("nonce word"));
    }
    let mut state = Zeroizing::new(*initial);
    for _ in 0..10 {
        for column in 0..4 {
            quarter(&mut state, column, column + 4, column + 8, column + 12);
        }
        quarter(&mut state, 0, 5, 10, 15);
        quarter(&mut state, 1, 6, 11, 12);
        quarter(&mut state, 2, 7, 8, 13);
        quarter(&mut state, 3, 4, 9, 14);
    }
    let mut output = [0; 64];
    for (i, bytes) in output.chunks_exact_mut(4).enumerate() {
        bytes.copy_from_slice(&state[i].wrapping_add(initial[i]).to_le_bytes());
    }
    output
}

fn xor_stream(
    key: &[u8; 32],
    nonce: &[u8; 12],
    first_counter: u32,
    data: &mut [u8],
) -> Result<(), ()> {
    let blocks = data.len().div_ceil(64) as u64;
    if blocks > (u64::from(u32::MAX) + 1) - u64::from(first_counter) {
        return Err(());
    }
    for (index, chunk) in data.chunks_mut(64).enumerate() {
        let counter = first_counter + index as u32; // Range checked above, never wraps.
        let stream = Zeroizing::new(chacha20_block(key, nonce, counter));
        for (byte, mask) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= *mask;
        }
    }
    Ok(())
}

// Base 2^26 representation of Poly1305's accumulator modulo 2^130 - 5.
// Each product accumulation has at most five products with one factor <= 5*2^26
// and one <= 2^27. Thus it fits well within u64; every carry is explicit.
const LIMB_MASK: u64 = (1 << 26) - 1;
struct Poly1305 {
    r: [u64; 5],
    accumulator: [u64; 5],
    pad: [u8; 16],
    buffer: [u8; 16],
    used: usize,
}
impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let mut r_bytes = Zeroizing::new([0u8; 16]);
        r_bytes.copy_from_slice(&key[..16]);
        for index in [3, 7, 11, 15] {
            r_bytes[index] &= 15;
        }
        for index in [4, 8, 12] {
            r_bytes[index] &= 252;
        }
        let r = limbs(&r_bytes, false);
        let mut pad = [0; 16];
        pad.copy_from_slice(&key[16..]);
        Self {
            r,
            accumulator: [0; 5],
            pad,
            buffer: [0; 16],
            used: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        if self.used != 0 {
            let length = input.len().min(16 - self.used);
            self.buffer[self.used..self.used + length].copy_from_slice(&input[..length]);
            self.used += length;
            input = &input[length..];
            if self.used == 16 {
                let mut block = self.buffer;
                self.add_block(&block, true);
                block.zeroize();
                self.buffer.zeroize();
                self.used = 0;
            }
        }
        while input.len() >= 16 {
            self.add_block(input[..16].try_into().expect("full block"), true);
            input = &input[16..];
        }
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.used = input.len();
        }
    }

    fn add_block(&mut self, block: &[u8; 16], full: bool) {
        let mut message = limbs(block, full);
        for (h, m) in self.accumulator.iter_mut().zip(message.iter()) {
            *h += *m;
        }
        let mut product = [0u64; 5];
        // Terms of degree >= 5 use (2^26)^5 == 5 mod (2^130 - 5).
        for i in 0..5 {
            for j in 0..5 {
                let degree = i + j;
                let multiplier = if degree >= 5 { 5 } else { 1 };
                product[degree % 5] += self.accumulator[i] * self.r[j] * multiplier;
            }
        }
        for i in 0..4 {
            product[i + 1] += product[i] >> 26;
            product[i] &= LIMB_MASK;
        }
        product[0] += (product[4] >> 26) * 5;
        product[4] &= LIMB_MASK;
        product[1] += product[0] >> 26;
        product[0] &= LIMB_MASK;
        self.accumulator = product;
        message.zeroize();
        product.zeroize();
    }

    fn finish(mut self) -> [u8; 16] {
        if self.used != 0 {
            self.buffer[self.used] = 1;
            self.buffer[self.used + 1..].fill(0);
            let mut block = self.buffer;
            self.add_block(&block, false);
            block.zeroize();
        }
        // Normalize all limbs. The second pass resolves the possible carry in
        // limb 1 left by folding the top carry through the modulus.
        for _ in 0..2 {
            for i in 0..4 {
                self.accumulator[i + 1] += self.accumulator[i] >> 26;
                self.accumulator[i] &= LIMB_MASK;
            }
            self.accumulator[0] += (self.accumulator[4] >> 26) * 5;
            self.accumulator[4] &= LIMB_MASK;
        }
        let mut reduced = self.accumulator;
        reduced[0] += 5;
        for i in 0..4 {
            reduced[i + 1] += reduced[i] >> 26;
            reduced[i] &= LIMB_MASK;
        }
        // h+5 overflows bit 130 exactly when h >= 2^130-5. Mask selection
        // avoids a branch on this key/message-dependent condition.
        let choose_reduced = 0u64.wrapping_sub(reduced[4] >> 26);
        reduced[4] &= LIMB_MASK;
        for (h, reduced) in self.accumulator.iter_mut().zip(reduced.iter()) {
            *h = (*h & !choose_reduced) | (*reduced & choose_reduced);
        }
        let mut output = [0; 16];
        let mut carry = 0u16;
        for (index, byte) in output.iter_mut().enumerate() {
            let bit = index * 8;
            let limb = bit / 26;
            let shift = bit % 26;
            let mut value = self.accumulator[limb] >> shift;
            if shift > 18 && limb < 4 {
                value |= self.accumulator[limb + 1] << (26 - shift);
            }
            let total = u16::from(value as u8) + u16::from(self.pad[index]) + carry;
            *byte = total as u8;
            carry = total >> 8;
        }
        reduced.zeroize();
        carry.zeroize();
        output
    }
}
impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r.zeroize();
        self.accumulator.zeroize();
        self.pad.zeroize();
        self.buffer.zeroize();
        self.used.zeroize();
    }
}

fn limbs(bytes: &[u8; 16], full: bool) -> [u64; 5] {
    let mut output = [0u64; 5];
    for (index, byte) in bytes.iter().enumerate() {
        let bit = index * 8;
        let limb = bit / 26;
        let shift = bit % 26;
        output[limb] |= (u64::from(*byte) << shift) & LIMB_MASK;
        if shift > 18 && limb < 4 {
            output[limb + 1] |= u64::from(*byte) >> (26 - shift);
        }
    }
    output[4] |= u64::from(full) << 24;
    output
}

#[cfg(test)]
pub(crate) fn poly1305(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = Poly1305::new(key);
    for part in parts {
        mac.update(part);
    }
    mac.finish()
}

fn tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[&[u8]], ciphertext: &[u8]) -> [u8; 16] {
    let stream = Zeroizing::new(chacha20_block(key, nonce, 0));
    let mut poly_key = Zeroizing::new([0u8; 32]);
    poly_key.copy_from_slice(&stream[..32]);
    let mut mac = Poly1305::new(&poly_key);
    let mut aad_length = 0u64;
    for part in aad {
        aad_length = aad_length
            .checked_add(part.len() as u64)
            .expect("bounded AAD");
        mac.update(part);
    }
    const ZEROS: [u8; 16] = [0; 16];
    mac.update(&ZEROS[..((16 - aad_length % 16) % 16) as usize]);
    mac.update(ciphertext);
    mac.update(&ZEROS[..(16 - ciphertext.len() % 16) % 16]);
    mac.update(&aad_length.to_le_bytes());
    mac.update(&(ciphertext.len() as u64).to_le_bytes());
    mac.finish()
}

pub(crate) fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[&[u8]], plaintext: &[u8]) -> Vec<u8> {
    // All production callers validate the 16 MiB limit before entering here.
    assert!(plaintext.len() <= crate::MAX_MESSAGE_LEN);
    // Reserve the tag too: never reallocate the encryption work buffer.
    let mut output = Zeroizing::new(Vec::with_capacity(plaintext.len() + 16));
    output.extend_from_slice(plaintext);
    xor_stream(key, nonce, 1, &mut output).expect("bounded message counter");
    let authenticator = tag(key, nonce, aad, &output);
    output.extend_from_slice(&authenticator);
    // Output consists entirely of ciphertext/tag; the temporary remains guarded.
    output.to_vec()
}

pub(crate) fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[&[u8]],
    sealed: &[u8],
) -> Result<Vec<u8>, ()> {
    if sealed.len() < 16 || sealed.len() - 16 > crate::MAX_MESSAGE_LEN {
        return Err(());
    }
    let (ciphertext, supplied_tag) = sealed.split_at(sealed.len() - 16);
    let mut expected = tag(key, nonce, aad, ciphertext);
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(supplied_tag) {
        difference |= *a ^ *b;
    }
    let difference = post_quantum_platform::opaque_u8(difference);
    expected.zeroize();
    // Branch only after inspecting every tag byte. No plaintext exists yet.
    if difference != 0 {
        return Err(());
    }
    let mut plaintext = ciphertext.to_vec();
    if xor_stream(key, nonce, 1, &mut plaintext).is_err() {
        plaintext.zeroize();
        return Err(());
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn decode<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn rfc8439_quarter_block_and_poly1305() {
        let mut state = [0; 16];
        state[..4].copy_from_slice(&[0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567]);
        quarter(&mut state, 0, 1, 2, 3);
        assert_eq!(
            &state[..4],
            &[0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]
        );
        let key = std::array::from_fn(|i| i as u8);
        let nonce = decode("000000090000004a00000000");
        assert_eq!(
            chacha20_block(&key, &nonce, 1),
            decode(concat!(
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e",
                "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
            ))
        );
        let poly_key = decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        assert_eq!(
            poly1305(&poly_key, &[b"Cryptographic Forum Research Group"]),
            decode("a8061dc1305136c6c22b8baf0c0127a9")
        );
    }

    #[test]
    fn hkdf_expansion_limit_and_split_info() {
        let mut a = [0; 130];
        let mut b = [0; 130];
        hkdf_sha512(
            b"secret",
            b"salt",
            &[b"application", b":", b"context"],
            &mut a,
        )
        .unwrap();
        hkdf_sha512(b"secret", b"salt", &[b"application:context"], &mut b).unwrap();
        assert_eq!(a, b);
        let mut maximum = vec![0; 255 * 64];
        hkdf_sha512(b"key", b"", &[], &mut maximum).unwrap();
        maximum.push(0);
        assert_eq!(hkdf_sha512(b"key", b"", &[], &mut maximum), Err(()));
        assert_eq!(hkdf_sha512(b"key", b"", &[], &mut []), Ok(()));
    }

    #[test]
    fn counter_limit_and_aead_rejection() {
        let key = [0x11; 32];
        let nonce = [0x22; 12];
        let mut data = [7; 65];
        assert_eq!(xor_stream(&key, &nonce, u32::MAX, &mut data), Err(()));
        assert_eq!(data, [7; 65]);
        xor_stream(&key, &nonce, u32::MAX, &mut data[..64]).unwrap();
        for length in [0, 1, 15, 16, 17, 63, 64, 65, 129] {
            let plaintext = vec![0x33; length];
            let ciphertext = seal(&key, &nonce, &[b"associated", b" data"], &plaintext);
            assert_eq!(
                open(&key, &nonce, &[b"associated data"], &ciphertext),
                Ok(plaintext)
            );
            assert_eq!(open(&key, &nonce, &[b"bad data"], &ciphertext), Err(()));
            for i in 0..ciphertext.len() {
                let mut changed = ciphertext.clone();
                changed[i] ^= 1;
                assert_eq!(open(&key, &nonce, &[b"associated data"], &changed), Err(()));
            }
        }
    }
}
