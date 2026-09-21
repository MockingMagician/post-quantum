#![no_main]
use libfuzzer_sys::fuzz_target;
use post_quantum_core as pq;
use std::sync::OnceLock;
fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    static KEYS: OnceLock<(
        pq::EncryptionPublicKey,
        pq::EncryptionPrivateKey,
        pq::SigningPublicKey,
        pq::SigningPrivateKey,
    )> = OnceLock::new();
    let (ep, es, sp, ss) = KEYS.get_or_init(|| {
        let (ep, es) = pq::generate_encryption_key_pair().unwrap();
        let (sp, ss) = pq::generate_signing_key_pair().unwrap();
        (ep, es, sp, ss)
    });
    let aad = &data[..data.len().min(31)];
    let context = &data[..data.len().min(255)];
    let mut encrypted = pq::encrypt(ep, data, aad).unwrap();
    assert_eq!(pq::decrypt(es, &encrypted, aad).unwrap(), data);
    *encrypted.last_mut().unwrap() ^= 1;
    assert!(pq::decrypt(es, &encrypted, aad).is_err());
    let mut signature = pq::sign(ss, data, context).unwrap();
    assert!(pq::verify(sp, data, &signature, context).unwrap());
    *signature.last_mut().unwrap() ^= 1;
    assert!(!pq::verify(sp, data, &signature, context).unwrap());
});
