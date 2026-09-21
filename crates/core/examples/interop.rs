//! Validation-only line-input / JSON-output bridge, with no external crates.
use post_quantum_core as pq;
use std::io::Read;
#[path = "../tests/support/mod.rs"]
mod support;
fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let records = support::records(&input);
    let v = &records[0];
    let bytes = |field: &str| support::hex(v[field]);
    let message = bytes("message");
    let aad = bytes("aad");
    let context = bytes("context");
    let enc = pq::EncryptionPrivateKey::from_bytes(&bytes("encryptionPrivate")).unwrap();
    let sig = pq::SigningPrivateKey::from_bytes(&bytes("signingPrivate")).unwrap();
    if v["op"] == "produce" {
        let ep = encode(&enc.public_key().to_bytes());
        let sp = encode(&sig.public_key().to_bytes());
        let ciphertext = encode(&pq::encrypt(&enc.public_key(), &message, &aad).unwrap());
        let signature = encode(&pq::sign(&sig, &message, &context).unwrap());
        println!(
            "{{\"encryptionPublic\":\"{ep}\",\"signingPublic\":\"{sp}\",\"envelope\":\"{ciphertext}\",\"signature\":\"{signature}\"}}"
        );
    } else {
        let plaintext = encode(&pq::decrypt(&enc, &bytes("envelope"), &aad).unwrap());
        let valid = pq::verify(&sig.public_key(), &message, &bytes("signature"), &context).unwrap();
        println!("{{\"plaintext\":\"{plaintext}\",\"valid\":{valid}}}");
    }
}
