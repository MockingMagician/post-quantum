use super::*;

struct FailingRandom;
impl TryRandom for FailingRandom {
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> core::result::Result<(), ()> {
        if !bytes.is_empty() {
            bytes[0] = 0xA5;
        }
        Err(())
    }
}
struct FailSecondRequest(usize);
impl TryRandom for FailSecondRequest {
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> core::result::Result<(), ()> {
        self.0 += 1;
        if self.0 == 1 {
            bytes.fill(7);
            Ok(())
        } else {
            Err(())
        }
    }
}

#[test]
fn entropy_failure_is_reported_without_output() {
    assert!(matches!(
        generate_encryption_with_rng(&mut FailingRandom),
        Err(Error::RandomnessFailed)
    ));
    assert!(matches!(
        generate_signing_with_rng(&mut FailingRandom),
        Err(Error::RandomnessFailed)
    ));
    let (ep, _) = generate_encryption_key_pair().unwrap();
    let (_, ss) = generate_signing_key_pair().unwrap();
    assert_eq!(
        encrypt_with_rng(&ep, b"message", b"", &mut FailingRandom),
        Err(Error::RandomnessFailed)
    );
    assert_eq!(
        encrypt_with_rng(&ep, b"message", b"", &mut FailSecondRequest(0)),
        Err(Error::RandomnessFailed)
    );
    assert_eq!(
        sign_with_rng(&ss, b"message", b"", &mut FailingRandom),
        Err(Error::RandomnessFailed)
    );
}

#[test]
fn roundtrip_empty_binary_and_randomized() {
    let (ep, es) = generate_encryption_key_pair().unwrap();
    let (sp, ss) = generate_signing_key_pair().unwrap();
    for message in [b"".as_slice(), b"hello\0\xff\xfe"] {
        let first = encrypt(&ep, message, b"metadata").unwrap();
        let second = encrypt(&ep, message, b"metadata").unwrap();
        assert_ne!(first, second);
        assert_eq!(decrypt(&es, &first, b"metadata").unwrap(), message);
        let first = sign(&ss, message, b"app:1").unwrap();
        let second = sign(&ss, message, b"app:1").unwrap();
        assert_ne!(first, second);
        assert!(verify(&sp, message, &first, b"app:1").unwrap());
        assert!(!verify(&sp, message, &first, b"app:2").unwrap());
    }
}

#[test]
fn key_exports_are_typed_and_exact() {
    let (ep, es) = generate_encryption_key_pair().unwrap();
    let (sp, ss) = generate_signing_key_pair().unwrap();
    let exports = [ep.to_bytes(), es.to_bytes(), sp.to_bytes(), ss.to_bytes()];
    assert_eq!(exports.map(|x| x.len()), [1578, 74, 2602, 42]);
    let ep2 = EncryptionPublicKey::from_bytes(&ep.to_bytes()).unwrap();
    let es2 = EncryptionPrivateKey::from_bytes(&es.to_bytes()).unwrap();
    let sp2 = SigningPublicKey::from_bytes(&sp.to_bytes()).unwrap();
    let ss2 = SigningPrivateKey::from_bytes(&ss.to_bytes()).unwrap();
    assert_eq!(es2.public_key().to_bytes(), ep.to_bytes());
    assert_eq!(ss2.public_key().to_bytes(), sp.to_bytes());
    assert_eq!(
        decrypt(&es2, &encrypt(&ep2, b"hello", b"").unwrap(), b"").unwrap(),
        b"hello"
    );
    assert!(verify(&sp2, b"hello", &sign(&ss2, b"hello", b"").unwrap(), b"").unwrap());
    for mut bytes in [ep.to_bytes(), es.to_bytes(), sp.to_bytes(), ss.to_bytes()] {
        bytes.push(0);
        assert!(EncryptionPublicKey::from_bytes(&bytes).is_err());
        assert!(EncryptionPrivateKey::from_bytes(&bytes).is_err());
        assert!(SigningPublicKey::from_bytes(&bytes).is_err());
        assert!(SigningPrivateKey::from_bytes(&bytes).is_err());
    }
    assert!(EncryptionPublicKey::from_bytes(&sp.to_bytes()).is_err());
    assert!(SigningPublicKey::from_bytes(&ep.to_bytes()).is_err());
    assert!(EncryptionPrivateKey::from_bytes(&ss.to_bytes()).is_err());
    assert!(SigningPrivateKey::from_bytes(&es.to_bytes()).is_err());
}

#[test]
fn encryption_rejects_wrong_key_metadata_and_alterations() {
    let (ep, es) = generate_encryption_key_pair().unwrap();
    let (_, other) = generate_encryption_key_pair().unwrap();
    let ciphertext = encrypt(&ep, b"secret", b"aad").unwrap();
    assert_eq!(
        decrypt(&other, &ciphertext, b"aad"),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(
        decrypt(&es, &ciphertext, b"wrong"),
        Err(Error::AuthenticationFailed)
    );
    for index in [
        0,
        4,
        5,
        6,
        9,
        10,
        1577,
        1578,
        1589,
        1590,
        ciphertext.len() - 1,
    ] {
        let mut modified = ciphertext.clone();
        modified[index] ^= 1;
        assert!(decrypt(&es, &modified, b"aad").is_err(), "index {index}");
    }
    for len in [0, 1, 9, 10, 1589, 1590, 1605, ciphertext.len() - 1] {
        assert!(decrypt(&es, &ciphertext[..len], b"aad").is_err());
    }
    let mut extended = ciphertext;
    extended.push(0);
    assert!(decrypt(&es, &extended, b"aad").is_err());
}

#[test]
fn signatures_reject_wrong_key_messages_context_and_noncanonical_bytes() {
    let (sp, ss) = generate_signing_key_pair().unwrap();
    let (other, _) = generate_signing_key_pair().unwrap();
    let signature = sign(&ss, b"claim", b"invoice").unwrap();
    assert!(!verify(&other, b"claim", &signature, b"invoice").unwrap());
    assert!(!verify(&sp, b"Claim", &signature, b"invoice").unwrap());
    assert!(!verify(&sp, b"claim", &signature, b"other").unwrap());
    for index in [0, 4, 5, 6, 9, 10, signature.len() - 1] {
        let mut modified = signature.clone();
        modified[index] ^= 1;
        assert!(!verify(&sp, b"claim", &modified, b"invoice").unwrap());
    }
    for len in [0, 1, 9, 10, signature.len() - 1] {
        assert!(!verify(&sp, b"claim", &signature[..len], b"invoice").unwrap());
    }
    let mut extended = signature;
    extended.push(0);
    assert!(!verify(&sp, b"claim", &extended, b"invoice").unwrap());
}

#[test]
fn limits_accept_boundary_and_reject_one_over() {
    let (ep, es) = generate_encryption_key_pair().unwrap();
    let (sp, ss) = generate_signing_key_pair().unwrap();
    let boundary = vec![0xAC; MAX_MESSAGE_LEN];
    let envelope = encrypt(&ep, &boundary, &boundary).unwrap();
    assert_eq!(envelope.len(), MAX_ENVELOPE_LEN);
    assert_eq!(decrypt(&es, &envelope, &boundary).unwrap(), boundary);
    let context = [0xCD; MAX_CONTEXT_LEN];
    let signature = sign(&ss, &boundary, &context).unwrap();
    assert!(verify(&sp, &boundary, &signature, &context).unwrap());
    let over = vec![0; MAX_MESSAGE_LEN + 1];
    assert_eq!(encrypt(&ep, &over, b""), Err(Error::MessageTooLarge));
    assert_eq!(encrypt(&ep, b"", &over), Err(Error::MessageTooLarge));
    assert_eq!(decrypt(&es, &envelope, &over), Err(Error::MessageTooLarge));
    assert_eq!(sign(&ss, &over, b""), Err(Error::MessageTooLarge));
    assert_eq!(verify(&sp, &over, b"", b""), Err(Error::MessageTooLarge));
    assert_eq!(
        sign(&ss, b"", &[0; MAX_CONTEXT_LEN + 1]),
        Err(Error::ContextTooLong)
    );
    assert_eq!(
        verify(&sp, b"", b"", &[0; MAX_CONTEXT_LEN + 1]),
        Err(Error::ContextTooLong)
    );
    let mut oversized = envelope;
    oversized.push(0);
    assert_eq!(decrypt(&es, &oversized, b""), Err(Error::MessageTooLarge));
}

#[test]
fn parser_rejects_huge_declared_lengths_and_invalid_kem_modulus() {
    let mut bytes = header(ENC_PUBLIC, 0).to_vec();
    bytes[6..].fill(0xFF);
    assert!(EncryptionPublicKey::from_bytes(&bytes).is_err());
    let invalid_modulus = encode(ENC_PUBLIC, &[0xFF; 1568]);
    assert!(matches!(
        EncryptionPublicKey::from_bytes(&invalid_modulus),
        Err(Error::InvalidKey)
    ));
    let mut unknown = encode(SIG_PRIVATE, &[1; 32]);
    unknown[4] = 2;
    assert!(matches!(
        SigningPrivateKey::from_bytes(&unknown),
        Err(Error::UnsupportedVersion)
    ));
}
