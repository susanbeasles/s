//! Canonical JSON: sorted keys, no whitespace, 7-bit printable ASCII only.
//!
//! `decode` rejects any input that is not byte-identical to its own re-encoding, so
//! duplicate keys, unsorted keys, whitespace and alternate escapes are all refused.

use serde::{de::DeserializeOwned, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonError {
    NotAscii,
    NotCanonical,
    Json(String),
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAscii => f.write_str("payload is not 7-bit printable ASCII"),
            Self::NotCanonical => f.write_str("payload is not canonical JSON"),
            Self::Json(e) => write!(f, "json: {e}"),
        }
    }
}

impl std::error::Error for CanonError {}

fn json(e: serde_json::Error) -> CanonError {
    CanonError::Json(e.to_string())
}

pub fn ascii(b: &[u8]) -> bool {
    b.iter().all(|&c| (0x20..0x7f).contains(&c))
}

pub fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, CanonError> {
    // serde_json::Map is a BTreeMap (no `preserve_order`), so Value output is key-sorted.
    let val = serde_json::to_value(v).map_err(json)?;
    let out = serde_json::to_vec(&val).map_err(json)?;
    if !ascii(&out) {
        return Err(CanonError::NotAscii);
    }
    Ok(out)
}

pub fn decode<T: DeserializeOwned>(b: &[u8]) -> Result<T, CanonError> {
    if !ascii(b) {
        return Err(CanonError::NotAscii);
    }
    let val: serde_json::Value = serde_json::from_slice(b).map_err(json)?;
    if serde_json::to_vec(&val).map_err(json)? != b {
        return Err(CanonError::NotCanonical);
    }
    serde_json::from_value(val).map_err(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct T {
        z: u64,
        a: String,
    }

    #[test]
    fn sorted_and_strict() {
        let t = T { z: 1, a: "x".into() };
        let b = encode(&t).unwrap();
        assert_eq!(b, br#"{"a":"x","z":1}"#);
        assert_eq!(decode::<T>(&b).unwrap(), t);
        assert_eq!(decode::<T>(br#"{"z":1,"a":"x"}"#), Err(CanonError::NotCanonical));
        assert_eq!(decode::<T>(br#"{"a":"x", "z":1}"#), Err(CanonError::NotCanonical));
        assert_eq!(decode::<T>(br#"{"a":"x","a":"y","z":1}"#), Err(CanonError::NotCanonical));
        assert_eq!(decode::<T>(br#"{"a":"\u0078","z":1}"#), Err(CanonError::NotCanonical));
        assert!(matches!(decode::<T>(br#"{"a":"x","b":2,"z":1}"#), Err(CanonError::Json(_))));
        assert_eq!(decode::<T>("{\"a\":\"\u{e9}\",\"z\":1}".as_bytes()), Err(CanonError::NotAscii));
        assert_eq!(encode(&T { z: 0, a: "\u{e9}".into() }), Err(CanonError::NotAscii));
    }
}
