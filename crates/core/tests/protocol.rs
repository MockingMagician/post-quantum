//! Immutable PQRS protocol fixture produced by independent OpenSSL primitives.
use post_quantum_core as pq;
mod support;
use support::{hex, records};

#[test]
fn independent_openssl_protocol_v1_fixture() {
    let records = records(include_str!("../../../validation/kat/protocol-v1.kat"));
    let fixture = &records[0];
    let bytes = |field: &str| hex(fixture[field]);
    let encryption = pq::EncryptionPrivateKey::from_bytes(&bytes("encryptionPrivate")).unwrap();
    let signing = pq::SigningPrivateKey::from_bytes(&bytes("signingPrivate")).unwrap();
    let encryption_public =
        pq::EncryptionPublicKey::from_bytes(&bytes("encryptionPublic")).unwrap();
    let signing_public = pq::SigningPublicKey::from_bytes(&bytes("signingPublic")).unwrap();
    assert_eq!(
        encryption.public_key().to_bytes(),
        bytes("encryptionPublic")
    );
    assert_eq!(signing.public_key().to_bytes(), bytes("signingPublic"));
    let message = bytes("message");
    let aad = bytes("aad");
    let context = bytes("context");
    assert_eq!(
        pq::decrypt(&encryption, &bytes("envelope"), &aad).unwrap(),
        message
    );
    assert!(pq::verify(&signing_public, &message, &bytes("signature"), &context).unwrap());
    assert!(!pq::verify(&signing_public, &message, &bytes("signature"), b"wrong").unwrap());
    assert_eq!(
        pq::decrypt(&encryption, &bytes("envelope"), b"wrong"),
        Err(pq::Error::AuthenticationFailed)
    );
    // Imported public keys must also remain usable for new protocol messages.
    let ciphertext = pq::encrypt(&encryption_public, &message, &aad).unwrap();
    assert_eq!(
        pq::decrypt(&encryption, &ciphertext, &aad).unwrap(),
        message
    );
}
