//! Statistical diagnostics, not a proof of constant time. PRNG output is public test data.
#![allow(dead_code)]
#[path = "../../../crates/core/src/arithmetic.rs"]
mod arithmetic;
#[path = "../../../crates/core/src/hash.rs"]
mod hash;
#[path = "../../../crates/core/src/symmetric.rs"]
mod symmetric;
use std::{hint::black_box, time::Instant};
const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;
const NAMES: [&str; 7] = [
    "chacha20-key",
    "hmac512-key",
    "aead-open-valid-key",
    "mlkem-rejection-secret-z-fixed-public-key",
    "aead-invalid-tag-first-versus-last",
    "kem-comparison-first-versus-last",
    "field-multiply-8380417-operands",
];
#[derive(Default)]
struct Stats {
    n: f64,
    mean: f64,
    m2: f64,
}
impl Stats {
    fn add(&mut self, x: f64) {
        self.n += 1.;
        let d = x - self.mean;
        self.mean += d / self.n;
        self.m2 += d * (x - self.mean);
    }
    fn variance(&self) -> f64 {
        self.m2 / (self.n - 1.)
    }
}
fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
fn run(scenario: usize, samples: usize, repetition: usize) -> f64 {
    let mut state = 0x9283_abdf_2468_1357u64.wrapping_add(repetition as u64);
    let keys: Vec<[u8; 32]> = (0..1024)
        .map(|_| core::array::from_fn(|_| random(&mut state) as u8))
        .collect();
    let zero = [0; 32];
    let nonce = [0; 12];
    let message = [0x55; 128];
    let aad = b"timing";
    let fixed_ct = symmetric::seal(&zero, &nonce, &[aad], &message);
    let ciphertexts: Vec<Vec<u8>> = keys
        .iter()
        .map(|key| symmetric::seal(key, &nonce, &[aad], &message))
        .collect();
    // Keep d and the resulting public key fixed. Only rejection secret z changes.
    // Both classes have equally sized pools, avoiding one hot key versus cold keys.
    let kem_key = |z: &[u8; 32]| {
        let mut out = b"PQRS\x01\x02\x40\x00\x00\x00".to_vec();
        out.extend(zero);
        out.extend(z);
        post_quantum_core::EncryptionPrivateKey::from_bytes(&out).unwrap()
    };
    let fixed_kem: Vec<_> = keys.iter().map(|_| kem_key(&zero)).collect();
    let varied_kem: Vec<_> = keys.iter().map(kem_key).collect();
    let fixed_public = fixed_kem[0].public_key().to_bytes();
    for key in &varied_kem {
        assert_eq!(key.public_key().to_bytes(), fixed_public);
    }
    let mut invalid_envelope = vec![0; 1734];
    invalid_envelope[..6].copy_from_slice(b"PQRS\x01\x10");
    invalid_envelope[6..10].copy_from_slice(&1724u32.to_le_bytes());
    assert!(post_quantum_core::decrypt(&fixed_kem[0], &invalid_envelope, aad).is_err());
    let mut stats = [Stats::default(), Stats::default()];
    let mut ct_buffer = vec![0; fixed_ct.len()];
    for i in 0..samples + 2000 {
        let class = (random(&mut state) & 1) as usize;
        let index = (random(&mut state) as usize) % keys.len();
        // Copy into same-address buffers before measurement; do not time preparation.
        let key_value = if class == 0 { zero } else { keys[index] };
        let key = black_box(&key_value);
        ct_buffer.copy_from_slice(if class == 0 {
            &fixed_ct
        } else {
            &ciphertexts[index]
        });
        if scenario == 4 {
            ct_buffer.copy_from_slice(&fixed_ct);
            let tag_byte = if class == 0 {
                fixed_ct.len() - 16
            } else {
                fixed_ct.len() - 1
            };
            ct_buffer[tag_byte] ^= 1;
        }
        let ct = black_box(&ct_buffer);
        let kem = black_box(if class == 0 {
            &fixed_kem[index]
        } else {
            &varied_kem[index]
        });
        let mut comparison = [0; 1568];
        comparison[if class == 0 { 0 } else { 1567 }] = 1;
        let comparison = black_box(&comparison);
        let operands: [u32; 128] = core::array::from_fn(|j| {
            if class == 0 {
                0
            } else {
                (u32::from(keys[index][j % 32]) * 32987 + j as u32) % 8380417
            }
        });
        let operands = black_box(&operands);
        let start = Instant::now();
        for _ in 0..if scenario == 3 { 1 } else { 4 } {
            match scenario {
                0 => {
                    black_box(symmetric::chacha20_block(key, &nonce, 1));
                }
                1 => {
                    black_box(symmetric::hmac_sha512(key, &[&message]));
                }
                2 => {
                    black_box(symmetric::open(key, &nonce, &[aad], ct).unwrap());
                }
                3 => {
                    assert!(
                        black_box(post_quantum_core::decrypt(kem, &invalid_envelope, aad)).is_err()
                    );
                }
                4 => {
                    assert!(black_box(symmetric::open(&zero, &nonce, &[aad], ct)).is_err());
                }
                5 => {
                    black_box(arithmetic::equal_mask(&[0; 1568], comparison));
                }
                _ => {
                    let mut total = 0u32;
                    for pair in operands.chunks_exact(2) {
                        total = arithmetic::add::<8380417>(
                            total,
                            arithmetic::mul::<8380417>(pair[0], pair[1]),
                        );
                    }
                    black_box(total);
                }
            }
        }
        let elapsed = start.elapsed().as_nanos() as f64;
        if i >= 2000 {
            stats[class].add(elapsed);
        }
    }
    let t = (stats[0].mean - stats[1].mean)
        / (stats[0].variance() / stats[0].n + stats[1].variance() / stats[1].n).sqrt();
    println!(
        "{{\"scenario\":\"{}\",\"repetition\":{},\"samples\":{},\"classes\":[{},{}],\"meansNs\":[{},{}],\"welchT\":{},\"flagged\":{}}}",
        NAMES[scenario],
        repetition,
        samples,
        stats[0].n,
        stats[1].n,
        stats[0].mean,
        stats[1].mean,
        t,
        t.abs() > 4.5
    );
    t
}
fn main() {
    let samples = std::env::args()
        .nth(1)
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(100000);
    assert!(samples >= 10000);
    let mut detected = false;
    for scenario in 0..NAMES.len() {
        let flags = (0..3)
            .filter(|&rep| run(scenario, samples, rep).abs() > 4.5)
            .count();
        detected |= flags >= 2;
    }
    println!(
        "{{\"reproducibleSignal\":{detected},\"threshold\":4.5,\"criterion\":\"at least two of three repetitions in one scenario\"}}"
    );
    if detected {
        std::process::exit(1);
    }
}
