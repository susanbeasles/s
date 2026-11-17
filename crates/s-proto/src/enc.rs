//! Lowercase hex, strict RFC 4648 base64 (standard alphabet, padded), SHA-256.

use sha2::{Digest, Sha256};

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn hex(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some(v(p[0])? << 4 | v(p[1])?))
        .collect()
}

pub fn unhex32(s: &str) -> Option<[u8; 32]> {
    unhex(s)?.try_into().ok()
}

/// True if `s` is lowercase hex of exactly `bytes` bytes.
pub fn is_hex(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2 && unhex(s).is_some()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        s.push(B64[(n >> 18) as usize & 63] as char);
        s.push(B64[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    s
}

/// Strict decode: rejects bad length, misplaced padding and non-zero trailing bits.
pub fn unb64(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.len() % 4 != 0 {
        return None;
    }
    let val = |c: u8| B64.iter().position(|&x| x == c).map(|p| p as u32);
    let quads = s.len() / 4;
    let mut out = Vec::with_capacity(quads * 3);
    for (i, q) in s.chunks(4).enumerate() {
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != quads) {
            return None;
        }
        let mut n = 0u32;
        for (j, &c) in q.iter().enumerate() {
            let d = if j >= 4 - pad { 0 } else { val(c)? };
            n = n << 6 | d;
        }
        if (pad == 1 && n & 0xff != 0) || (pad == 2 && n & 0xffff != 0) {
            return None;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let v = [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")];
        for (raw, enc) in v {
            assert_eq!(b64(raw.as_bytes()), enc);
            assert_eq!(unb64(enc).unwrap(), raw.as_bytes());
        }
    }

    #[test]
    fn strict_rejects() {
        for bad in ["Zg=", "Z===", "Zg==Zg==", "Zh==", "Zm9=", "Zm 9", "Zm9v\n"] {
            assert!(unb64(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex(&[0, 0xab, 0xff]), "00abff");
        assert_eq!(unhex("00abff").unwrap(), vec![0, 0xab, 0xff]);
        assert!(unhex("AB").is_none());
        assert!(unhex("abc").is_none());
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
