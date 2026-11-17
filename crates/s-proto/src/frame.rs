//! Length-prefixed frames: big-endian `u16` length, 1..=65535 bytes of body.

use std::io::{self, Read, Write};

pub const MAX_FRAME: usize = 65535;

pub fn write<W: Write>(w: &mut W, body: &[u8]) -> io::Result<()> {
    if body.is_empty() || body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame size out of range"));
    }
    let mut buf = Vec::with_capacity(body.len() + 2);
    buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
    buf.extend_from_slice(body);
    w.write_all(&buf)?;
    w.flush()
}

pub fn read<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h)?;
    let n = u16::from_be_bytes(h) as usize;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty frame"));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_caps() {
        let mut wire = Vec::new();
        write(&mut wire, b"hello").unwrap();
        assert_eq!(&wire[..2], &[0, 5]);
        assert_eq!(read(&mut wire.as_slice()).unwrap(), b"hello");
        assert!(write(&mut Vec::new(), &[]).is_err());
        assert!(write(&mut Vec::new(), &vec![0; MAX_FRAME + 1]).is_err());
        write(&mut Vec::new(), &vec![0; MAX_FRAME]).unwrap();
        assert!(read(&mut [0u8, 0].as_slice()).is_err());
        assert!(read(&mut [0u8, 9, 1].as_slice()).is_err());
    }
}
