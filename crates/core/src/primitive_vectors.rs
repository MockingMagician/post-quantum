//! Official byte-oriented NIST ACVP primitive vectors and RFC 8439 examples.
use crate::validation_support::{hex, records};
use crate::{hash, symmetric};

#[test]
fn nist_1771_hash_xof_hmac_hkdf_cases() {
    let cases = records(include_str!("../../../validation/kat/primitives.kat"));
    assert_eq!(cases.len(), 1771);
    for c in cases {
        let expected = hex(c["expected"]);
        if c["algorithm"].starts_with("KDA") {
            let mut output = vec![0; expected.len()];
            let info = hex(c["info"]);
            let cut = info.len() / 2;
            symmetric::hkdf_sha512(
                &hex(c["ikm"]),
                &hex(c["salt"]),
                &[&info[..cut], &info[cut..]],
                &mut output,
            )
            .unwrap();
            assert_eq!(output, expected, "{} tcId={}", c["algorithm"], c["tcId"]);
            continue;
        }
        let msg = hex(c["message"]);
        let cut = msg.len() / 2;
        let parts: [&[u8]; 4] = [&[], &msg[..cut], &msg[cut..], &[]];
        let output = match c["algorithm"] {
            "SHA2-512-1.0" => hash::sha512(&parts).to_vec(),
            "SHA3-256-2.0" => hash::sha3_256(&parts).to_vec(),
            "SHA3-512-2.0" => hash::sha3_512(&parts).to_vec(),
            "SHAKE-128-FIPS202" => {
                let mut x = hash::shake128(&parts);
                let mut out = vec![0; expected.len()];
                let n = out.len() / 2;
                x.read(&mut out[..n]);
                x.read(&mut []);
                x.read(&mut out[n..]);
                out
            }
            "SHAKE-256-FIPS202" => {
                let mut x = hash::shake256(&parts);
                let mut out = vec![0; expected.len()];
                for part in out.chunks_mut(17) {
                    x.read(part);
                }
                out
            }
            "HMAC-SHA2-512-2.0" => {
                symmetric::hmac_sha512(&hex(c["key"]), &parts)[..expected.len()].to_vec()
            }
            a => panic!("unsupported fixture algorithm {a}"),
        };
        assert_eq!(output, expected, "{} tcId={}", c["algorithm"], c["tcId"]);
    }
}

#[test]
fn rfc8439_chacha_block_2_3_2() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let nonce = hex("000000090000004a00000000");
    let expected = hex(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
    );
    assert_eq!(
        symmetric::chacha20_block(&key, nonce.as_slice().try_into().unwrap(), 1).as_slice(),
        expected
    );
}

#[test]
fn rfc8439_poly1305_2_5_2_with_every_partition() {
    let key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let message = b"Cryptographic Forum Research Group";
    let expected = hex("a8061dc1305136c6c22b8baf0c0127a9");
    for cut in 0..=message.len() {
        assert_eq!(
            symmetric::poly1305(
                key.as_slice().try_into().unwrap(),
                &[&message[..cut], &message[cut..]]
            )
            .as_slice(),
            expected,
            "partition={cut}"
        );
    }
}

#[test]
fn rfc8439_aead_2_8_2() {
    let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
    let nonce = hex("070000004041424344454647");
    let nonce: &[u8; 12] = nonce.as_slice().try_into().unwrap();
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let message=b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = hex(concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b6116",
        "1ae10b594f09e26a7e902ecbd0600691"
    ));
    assert_eq!(symmetric::seal(&key, nonce, &[&aad], message), expected);
    assert_eq!(
        symmetric::open(&key, nonce, &[&aad], &expected).unwrap(),
        message
    );
    for index in 0..expected.len() {
        let mut damaged = expected.clone();
        damaged[index] ^= 1;
        assert!(symmetric::open(&key, nonce, &[&aad], &damaged).is_err());
    }
}
