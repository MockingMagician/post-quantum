#![no_main]
use libfuzzer_sys::fuzz_target;
use post_quantum_core as pq;
use std::sync::OnceLock;
fn keys() -> &'static (pq::EncryptionPrivateKey, pq::SigningPublicKey) {
    static KEYS: OnceLock<(pq::EncryptionPrivateKey, pq::SigningPublicKey)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut enc = b"PQRS\x01\x02\x40\x00\x00\x00".to_vec();
        enc.extend(0..64u8);
        let mut sig = b"PQRS\x01\x04\x20\x00\x00\x00".to_vec();
        sig.extend(0..32u8);
        (
            pq::EncryptionPrivateKey::from_bytes(&enc).unwrap(),
            pq::SigningPrivateKey::from_bytes(&sig)
                .unwrap()
                .public_key(),
        )
    })
}
fuzz_target!(|data: &[u8]| {
    let Some((&kind, bytes)) = data.split_first() else {
        return;
    };
    match kind % 3 {
        0 => {
            let _ = pq::EncryptionPublicKey::from_bytes(bytes);
            let _ = pq::EncryptionPrivateKey::from_bytes(bytes);
            let _ = pq::SigningPublicKey::from_bytes(bytes);
            let _ = pq::SigningPrivateKey::from_bytes(bytes);
        }
        1 => {
            let _ = pq::decrypt(&keys().0, bytes, b"test-aad\0\xff");
        }
        _ => {
            let _ = pq::verify(&keys().1, b"\0\x01post-quantum\xff", bytes, b"author\0\xff");
        }
    }
});
