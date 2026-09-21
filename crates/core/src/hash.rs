//! Scalar SHA-512 (FIPS 180-4) and Keccak/SHA-3/SHAKE (FIPS 202).
//! Independently written from the standards for this project. All indexing and
//! round counts depend on public positions/lengths, never on absorbed values.

use post_quantum_platform::Zeroize;

// FIPS 180-4, section 4.2.3: fractional cube roots of the first 80 primes.
const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub(crate) struct Sha512 {
    state: [u64; 8],
    buffer: [u8; 128],
    used: usize,
    bytes: u128,
}

impl Sha512 {
    pub(crate) fn new() -> Self {
        Self {
            // FIPS 180-4, section 5.3.5.
            state: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            buffer: [0; 128],
            used: 0,
            bytes: 0,
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        // Protocol messages are bounded at 16 MiB; internal callers also cannot
        // supply a representable slice anywhere near the SHA-512 bit-length cap.
        self.bytes = self
            .bytes
            .checked_add(input.len() as u128)
            .expect("SHA-512 length");
        if self.used != 0 {
            let take = input.len().min(128 - self.used);
            self.buffer[self.used..self.used + take].copy_from_slice(&input[..take]);
            self.used += take;
            input = &input[take..];
            if self.used == 128 {
                compress512(&mut self.state, &self.buffer);
                self.buffer.zeroize();
                self.used = 0;
            }
        }
        while input.len() >= 128 {
            compress512(
                &mut self.state,
                input[..128].try_into().expect("full block"),
            );
            input = &input[128..];
        }
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.used = input.len();
        }
    }

    pub(crate) fn finish(mut self) -> [u8; 64] {
        self.buffer[self.used] = 0x80;
        self.buffer[self.used + 1..].fill(0);
        if self.used >= 112 {
            compress512(&mut self.state, &self.buffer);
            self.buffer.zeroize();
        }
        let bits = self.bytes.checked_mul(8).expect("SHA-512 bit length");
        self.buffer[112..].copy_from_slice(&bits.to_be_bytes());
        compress512(&mut self.state, &self.buffer);
        let mut result = [0; 64];
        for (word, output) in self.state.iter().zip(result.chunks_exact_mut(8)) {
            output.copy_from_slice(&word.to_be_bytes());
        }
        result
    }
}

impl Drop for Sha512 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.used.zeroize();
        self.bytes.zeroize();
    }
}

fn compress512(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut words = [0u64; 80];
    for (word, input) in words[..16].iter_mut().zip(block.chunks_exact(8)) {
        *word = u64::from_be_bytes(input.try_into().expect("word"));
    }
    for i in 16..80 {
        let x = words[i - 15];
        let y = words[i - 2];
        let s0 = x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7);
        let s1 = y.rotate_right(19) ^ y.rotate_right(61) ^ (y >> 6);
        words[i] = words[i - 16]
            .wrapping_add(s0)
            .wrapping_add(words[i - 7])
            .wrapping_add(s1);
    }
    let mut working = *state;
    for i in 0..80 {
        let [a, b, c, d, e, f, g, h] = working;
        let sum1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let choose = (e & f) ^ (!e & g);
        let sum0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let t1 = h
            .wrapping_add(sum1)
            .wrapping_add(choose)
            .wrapping_add(SHA512_K[i])
            .wrapping_add(words[i]);
        let t2 = sum0.wrapping_add(majority);
        working = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    for (output, word) in state.iter_mut().zip(working) {
        *output = output.wrapping_add(word);
    }
    words.zeroize();
    working.zeroize();
}

pub(crate) fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha512::new();
    for part in parts {
        hash.update(part);
    }
    hash.finish()
}

// FIPS 202, algorithms 2-6. Coordinates use index x + 5*y.
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

fn keccak(state: &mut [u64; 25]) {
    let mut columns = [0; 5];
    let mut correction = [0; 5];
    let mut lanes = [0; 25];
    for constant in RC {
        for x in 0..5 {
            columns[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            correction[x] = columns[(x + 4) % 5] ^ columns[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                let index = x + 5 * y;
                state[index] ^= correction[x];
                lanes[y + 5 * ((2 * x + 3 * y) % 5)] = state[index].rotate_left(RHO[index]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] =
                    lanes[x + 5 * y] ^ ((!lanes[(x + 1) % 5 + 5 * y]) & lanes[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= constant;
    }
    columns.zeroize();
    correction.zeroize();
    lanes.zeroize();
}

/// A squeezing-only sponge. Callers cannot absorb after domain padding.
pub(crate) struct Xof {
    state: [u64; 25],
    rate: usize,
    position: usize,
}
impl Xof {
    fn absorb(parts: &[&[u8]], rate: usize, suffix: u8) -> Self {
        let mut result = Self {
            state: [0; 25],
            rate,
            position: 0,
        };
        for part in parts {
            for byte in *part {
                let position = result.position;
                result.state[position / 8] ^= u64::from(*byte) << ((position % 8) * 8);
                result.position += 1;
                if result.position == rate {
                    keccak(&mut result.state);
                    result.position = 0;
                }
            }
        }
        // SHA3's 01 suffix -> 0x06 with first pad bit; SHAKE's 1111 -> 0x1f.
        let position = result.position;
        result.state[position / 8] ^= u64::from(suffix) << ((position % 8) * 8);
        result.state[(rate - 1) / 8] ^= 0x80u64 << (((rate - 1) % 8) * 8);
        keccak(&mut result.state);
        result.position = 0;
        result
    }

    pub(crate) fn read(&mut self, destination: &mut [u8]) {
        for byte in destination {
            if self.position == self.rate {
                keccak(&mut self.state);
                self.position = 0;
            }
            *byte = (self.state[self.position / 8] >> ((self.position % 8) * 8)) as u8;
            self.position += 1;
        }
    }
}
impl Drop for Xof {
    fn drop(&mut self) {
        self.state.zeroize();
        self.position.zeroize();
    }
}

pub(crate) fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut result = [0; 32];
    Xof::absorb(parts, 136, 0x06).read(&mut result);
    result
}
pub(crate) fn sha3_512(parts: &[&[u8]]) -> [u8; 64] {
    let mut result = [0; 64];
    Xof::absorb(parts, 72, 0x06).read(&mut result);
    result
}
pub(crate) fn shake128(parts: &[&[u8]]) -> Xof {
    Xof::absorb(parts, 168, 0x1f)
}
pub(crate) fn shake256(parts: &[&[u8]]) -> Xof {
    Xof::absorb(parts, 136, 0x1f)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn standard_empty_and_abc_digests() {
        assert_eq!(
            hex(&sha512(&[b"abc"])),
            concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
        assert_eq!(
            hex(&sha512(&[])),
            concat!(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        );
        assert_eq!(
            hex(&sha3_256(&[b"abc"])),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hex(&sha3_512(&[b"abc"])),
            concat!(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e",
                "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            )
        );
        let mut output = [0; 32];
        shake128(&[]).read(&mut output);
        assert_eq!(
            hex(&output),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
        shake256(&[]).read(&mut output);
        assert_eq!(
            hex(&output),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    #[test]
    fn incremental_inputs_and_xof_reads_cross_every_boundary() {
        let input: Vec<u8> = (0..1000).map(|x| x as u8).collect();
        for length in [
            0, 1, 71, 72, 111, 112, 127, 128, 135, 136, 167, 168, 255, 256, 1000,
        ] {
            let message = &input[..length];
            for split in 0..=length {
                let parts = [&message[..split], &message[split..]];
                assert_eq!(sha512(&parts), sha512(&[message]));
                assert_eq!(sha3_256(&parts), sha3_256(&[message]));
                assert_eq!(sha3_512(&parts), sha3_512(&[message]));
                let mut expected = [0; 400];
                shake128(&[message]).read(&mut expected);
                let mut actual = [0; 400];
                let mut reader = shake128(&parts);
                for chunk in actual.chunks_mut(13) {
                    reader.read(chunk);
                }
                assert_eq!(actual, expected);
            }
        }
    }
}
