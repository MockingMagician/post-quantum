//! Small, strict reader for validation data. No third-party test dependency.
use std::collections::BTreeMap;
pub fn records(text: &str) -> Vec<BTreeMap<&str, &str>> {
    text.trim_end()
        .split("\n\n")
        .filter(|s| !s.is_empty())
        .map(|record| {
            let mut result = BTreeMap::new();
            for line in record.lines() {
                let (key, value) = line.split_once('=').expect("fixture key=value");
                assert!(
                    result.insert(key, value).is_none(),
                    "duplicate fixture field"
                );
            }
            result
        })
        .collect()
}
pub fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            fn nibble(v: u8) -> u8 {
                match v {
                    b'0'..=b'9' => v - b'0',
                    b'a'..=b'f' => v - b'a' + 10,
                    b'A'..=b'F' => v - b'A' + 10,
                    _ => panic!("invalid fixture hex"),
                }
            }
            (nibble(pair[0]) << 4) | nibble(pair[1])
        })
        .collect()
}
