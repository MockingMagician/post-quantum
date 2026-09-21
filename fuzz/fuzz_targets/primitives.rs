#![no_main]
#![allow(dead_code)]
use libfuzzer_sys::fuzz_target;
#[path = "../../crates/core/src/hash.rs"]
mod hash;
#[path = "../../crates/core/src/symmetric.rs"]
mod symmetric;
const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;
fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let cut = data.len() / 2;
    let parts = [&data[..cut], &[] as &[u8], &data[cut..]];
    assert_eq!(hash::sha512(&[data]), hash::sha512(&parts));
    assert_eq!(hash::sha3_256(&[data]), hash::sha3_256(&parts));
    assert_eq!(hash::sha3_512(&[data]), hash::sha3_512(&parts));
    let mut one = [0; 333];
    let mut chunks = [0; 333];
    hash::shake128(&[data]).read(&mut one);
    let mut x = hash::shake128(&parts);
    for out in chunks.chunks_mut(17) {
        x.read(out);
    }
    assert_eq!(one, chunks);
    hash::shake256(&[data]).read(&mut one);
    let mut x = hash::shake256(&parts);
    for out in chunks.chunks_mut(31) {
        x.read(out);
    }
    assert_eq!(one, chunks);
    let mut key = [0; 32];
    let n = data.len().min(32);
    key[..n].copy_from_slice(&data[..n]);
    let nonce = [0; 12];
    assert_eq!(
        symmetric::hmac_sha512(&key, &[data]),
        symmetric::hmac_sha512(&key, &parts)
    );
    let mut a = [0; 129];
    let mut b = [0; 129];
    symmetric::hkdf_sha512(data, &key, &[data], &mut a).unwrap();
    symmetric::hkdf_sha512(data, &key, &parts, &mut b).unwrap();
    assert_eq!(a, b);
    let mut ct = symmetric::seal(&key, &nonce, &parts, data);
    assert_eq!(symmetric::open(&key, &nonce, &[data], &ct).unwrap(), data);
    *ct.last_mut().unwrap() ^= 1;
    assert!(symmetric::open(&key, &nonce, &[data], &ct).is_err());
});
