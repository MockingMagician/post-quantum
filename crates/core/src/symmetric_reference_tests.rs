//! Frozen outputs from a distinct integer Poly1305 model and OpenSSL AEAD.
use crate::symmetric;
use crate::validation_support::{hex, records};

#[test]
fn independent_poly1305_limb_carry_clamp_and_partition_cases() {
    let cases = records(include_str!(
        "../../../validation/kat/symmetric-independent.kat"
    ));
    let mut count = 0;
    for case in cases.iter().filter(|c| c["kind"] == "poly1305") {
        let key: [u8; 32] = hex(case["key"]).try_into().unwrap();
        let message = hex(case["message"]);
        let expected = hex(case["expected"]);
        for split in [0, message.len() / 2, message.len().min(15), message.len()] {
            let parts = [&message[..split], &[], &message[split..]];
            assert_eq!(
                symmetric::poly1305(&key, &parts).as_slice(),
                expected,
                "case={} split={split}",
                case["case"]
            );
        }
        count += 1;
    }
    assert_eq!(count, 256);
}

#[test]
fn independent_openssl_aead_padding_and_partitions() {
    let cases = records(include_str!(
        "../../../validation/kat/symmetric-independent.kat"
    ));
    let mut count = 0;
    for case in cases.iter().filter(|c| c["kind"] == "aead") {
        let key: [u8; 32] = hex(case["key"]).try_into().unwrap();
        let nonce: [u8; 12] = hex(case["nonce"]).try_into().unwrap();
        let message = hex(case["message"]);
        let aad = hex(case["aad"]);
        let expected = hex(case["expected"]);
        for split in [0, aad.len().min(15), aad.len() / 2, aad.len()] {
            let parts = [&aad[..split], &[], &aad[split..]];
            assert_eq!(
                symmetric::seal(&key, &nonce, &parts, &message),
                expected,
                "case={} split={split}",
                case["case"]
            );
            assert_eq!(
                symmetric::open(&key, &nonce, &parts, &expected).unwrap(),
                message
            );
        }
        for index in [0, expected.len() - 16, expected.len() - 1] {
            let mut changed = expected.clone();
            changed[index] ^= 0x80;
            assert!(symmetric::open(&key, &nonce, &[&aad], &changed).is_err());
        }
        count += 1;
    }
    assert_eq!(count, 128);
}
