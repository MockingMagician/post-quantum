//! These tests call this crate's implementations, never a third-party oracle crate.
use super::test_support as local;
use crate::validation_support::{hex, records};
fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../validation/kat")
            .join(format!("{name}.kat")),
    )
    .unwrap()
}
#[test]
fn nist_ml_kem_keygen_25() {
    let data = fixture("ML-KEM-keyGen-FIPS203");
    let cases = records(&data);
    assert_eq!(cases.len(), 25);
    for c in cases {
        let mut seed = hex(c["d"]);
        seed.extend(hex(c["z"]));
        let (ek, dk) = local::kem_keygen(seed.as_slice().try_into().unwrap());
        assert_eq!(ek, hex(c["ek"]), "ek tcId={}", c["tcId"]);
        assert_eq!(dk, hex(c["dk"]), "dk tcId={}", c["tcId"]);
    }
}
#[test]
fn nist_ml_kem_encapsulation_decapsulation_validation_55() {
    let data = fixture("ML-KEM-encapDecap-FIPS203");
    let cases = records(&data);
    assert_eq!(cases.len(), 55);
    for c in cases {
        match c["function"] {
            "encapsulation" => {
                let (ct, ss) = local::kem_encapsulate(
                    &hex(c["ek"]),
                    hex(c["m"]).as_slice().try_into().unwrap(),
                )
                .unwrap();
                assert_eq!(ct, hex(c["c"]), "ct tcId={}", c["tcId"]);
                assert_eq!(ss.as_slice(), hex(c["k"]), "ss tcId={}", c["tcId"]);
            }
            "decapsulation" => {
                assert_eq!(
                    local::kem_decapsulate(&hex(c["dk"]), &hex(c["c"]))
                        .unwrap()
                        .as_slice(),
                    hex(c["k"]),
                    "tcId={}",
                    c["tcId"]
                );
            }
            "encapsulationKeyCheck" => assert_eq!(
                local::kem_check_public(&hex(c["ek"])),
                c["testPassed"] == "true",
                "tcId={}",
                c["tcId"]
            ),
            "decapsulationKeyCheck" => assert_eq!(
                local::kem_check_private(&hex(c["dk"])),
                c["testPassed"] == "true",
                "tcId={}",
                c["tcId"]
            ),
            f => panic!("unsupported function {f}"),
        }
    }
}
#[test]
fn nist_ml_dsa_keygen_25() {
    let data = fixture("ML-DSA-keyGen-FIPS204");
    let cases = records(&data);
    assert_eq!(cases.len(), 25);
    for c in cases {
        let (pk, sk) = local::dsa_keygen(hex(c["seed"]).as_slice().try_into().unwrap());
        assert_eq!(pk, hex(c["pk"]), "pk tcId={}", c["tcId"]);
        assert_eq!(sk, hex(c["sk"]), "sk tcId={}", c["tcId"]);
    }
}
fn transcript(c: &std::collections::BTreeMap<&str, &str>) -> Vec<u8> {
    let mut msg = Vec::new();
    if c["signatureInterface"] == "external" {
        let ctx = hex(c["context"]);
        msg.extend([0, u8::try_from(ctx.len()).unwrap()]);
        msg.extend(ctx);
    }
    msg.extend(hex(c["message"]));
    msg
}
#[test]
fn nist_ml_dsa_signatures_60() {
    let data = fixture("ML-DSA-sigGen-FIPS204");
    let cases = records(&data);
    assert_eq!(cases.len(), 60);
    for c in cases {
        let rnd = if c["deterministic"] == "true" {
            vec![0; 32]
        } else {
            hex(c["rnd"])
        };
        assert_eq!(
            local::dsa_sign_internal(
                &hex(c["sk"]),
                &transcript(&c),
                rnd.as_slice().try_into().unwrap()
            )
            .unwrap(),
            hex(c["signature"]),
            "tcId={}",
            c["tcId"]
        );
    }
}
#[test]
fn nist_ml_dsa_verification_30() {
    let data = fixture("ML-DSA-sigVer-FIPS204");
    let cases = records(&data);
    assert_eq!(cases.len(), 30);
    for c in cases {
        assert_eq!(
            local::dsa_verify_internal(&hex(c["pk"]), &transcript(&c), &hex(c["signature"])),
            c["testPassed"] == "true",
            "tcId={}",
            c["tcId"]
        );
    }
}
