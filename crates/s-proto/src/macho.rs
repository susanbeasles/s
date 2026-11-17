//! Pure-Rust Mach-O 64-bit / Universal binary parser for embedded Apple CodeDirectory
//! (`LC_CODE_SIGNATURE` -> `CSMAGIC_EMBEDDED_SIGNATURE` -> `CSMAGIC_CODEDIRECTORY`),
//! computing the SHA-256 `CDHash` (20-byte canonical Apple CDHash + full 32-byte digest)
//! and extracting the signing identifier, Team ID, and page-slot hashes without macOS APIs.
//!
//! On macOS hosts, `SVMHost` additionally runs `SecStaticCodeCheckValidityWithErrors`
//! to verify the CMS / Apple Root CA chain before handing bundles to `s-vsockd`.

use crate::enc;
use sha2::{Digest, Sha256};
use std::fmt;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const FAT_MAGIC: u32 = 0xcafe_babe;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CS_HASHTYPE_SHA256: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignatureInfo {
    /// Canonical 20-byte Apple CDHash (hex, 40 chars).
    pub cdhash: String,
    /// Full 32-byte SHA-256 of the CodeDirectory blob (hex, 64 chars).
    pub cd_sha256: String,
    pub identifier: String,
    pub team_id: Option<String>,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachOError {
    Truncated,
    NotMachO,
    Unsigned,
    MalformedSuperBlob,
    NoSha256CodeDirectory,
    PageHashMismatch { page: u32 },
    InvalidUtf8,
}

impl fmt::Display for MachOError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated Mach-O or signature blob"),
            Self::NotMachO => f.write_str("not a 64-bit or universal Mach-O binary"),
            Self::Unsigned => f.write_str("Mach-O lacks LC_CODE_SIGNATURE"),
            Self::MalformedSuperBlob => f.write_str("malformed CS_SuperBlob / CodeDirectory"),
            Self::NoSha256CodeDirectory => f.write_str("no SHA-256 CodeDirectory found"),
            Self::PageHashMismatch { page } => write!(f, "code page {page} fails CodeDirectory hash"),
            Self::InvalidUtf8 => f.write_str("non-UTF-8 identifier or Team ID in CodeDirectory"),
        }
    }
}

impl std::error::Error for MachOError {}

/// Inspects a thin 64-bit or universal Mach-O, verifies every code-page SHA-256 slot
/// against the image bytes, and returns the primary SHA-256 `CodeSignatureInfo`.
pub fn verify_macho_cdhash(bytes: &[u8]) -> Result<CodeSignatureInfo, MachOError> {
    if bytes.len() < 8 {
        return Err(MachOError::Truncated);
    }
    let magic_be = u32::from_be_bytes(bytes[..4].try_into().unwrap());
    if magic_be == FAT_MAGIC {
        let narch = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        if narch == 0 || bytes.len() < 8 + narch * 20 {
            return Err(MachOError::Truncated);
        }
        let mut first = None;
        for i in 0..narch {
            let base = 8 + i * 20;
            let off = u32::from_be_bytes(bytes[base + 8..base + 12].try_into().unwrap()) as usize;
            let sz = u32::from_be_bytes(bytes[base + 12..base + 16].try_into().unwrap()) as usize;
            let slice = bytes.get(off..off.saturating_add(sz)).ok_or(MachOError::Truncated)?;
            let info = inspect_thin_64(slice)?;
            if first.is_none() {
                first = Some(info);
            }
        }
        return first.ok_or(MachOError::NotMachO);
    }
    inspect_thin_64(bytes)
}

fn inspect_thin_64(slice: &[u8]) -> Result<CodeSignatureInfo, MachOError> {
    if slice.len() < 32 {
        return Err(MachOError::Truncated);
    }
    let magic = u32::from_le_bytes(slice[..4].try_into().unwrap());
    if magic != MH_MAGIC_64 {
        return Err(MachOError::NotMachO);
    }
    let ncmds = u32::from_le_bytes(slice[16..20].try_into().unwrap()) as usize;
    let sizeofcmds = u32::from_le_bytes(slice[20..24].try_into().unwrap()) as usize;
    let cmds = slice.get(32..32usize.saturating_add(sizeofcmds)).ok_or(MachOError::Truncated)?;

    let mut pos = 0usize;
    let mut sig_range = None;
    for _ in 0..ncmds {
        let hdr = cmds.get(pos..pos + 8).ok_or(MachOError::Truncated)?;
        let cmd = u32::from_le_bytes(hdr[..4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        if cmdsize < 8 || pos + cmdsize > cmds.len() {
            return Err(MachOError::Truncated);
        }
        if cmd == LC_CODE_SIGNATURE {
            if cmdsize < 16 {
                return Err(MachOError::Truncated);
            }
            let dataoff = u32::from_le_bytes(cmds[pos + 8..pos + 12].try_into().unwrap()) as usize;
            let datasize = u32::from_le_bytes(cmds[pos + 12..pos + 16].try_into().unwrap()) as usize;
            sig_range = Some((dataoff, datasize));
        }
        pos += cmdsize;
    }

    let (dataoff, datasize) = sig_range.ok_or(MachOError::Unsigned)?;
    let superblob = slice
        .get(dataoff..dataoff.saturating_add(datasize))
        .ok_or(MachOError::Truncated)?;
    parse_superblob(slice, superblob)
}

fn parse_superblob(image: &[u8], sb: &[u8]) -> Result<CodeSignatureInfo, MachOError> {
    if sb.len() < 12 {
        return Err(MachOError::Truncated);
    }
    let magic = u32::from_be_bytes(sb[..4].try_into().unwrap());
    let length = u32::from_be_bytes(sb[4..8].try_into().unwrap()) as usize;
    let count = u32::from_be_bytes(sb[8..12].try_into().unwrap()) as usize;
    if magic != CSMAGIC_EMBEDDED_SIGNATURE || length > sb.len() || 12 + count * 8 > length {
        return Err(MachOError::MalformedSuperBlob);
    }
    let sb = &sb[..length];
    for i in 0..count {
        let idx = 12 + i * 8;
        let _slot_type = u32::from_be_bytes(sb[idx..idx + 4].try_into().unwrap());
        let off = u32::from_be_bytes(sb[idx + 4..idx + 8].try_into().unwrap()) as usize;
        let rem = sb.get(off..).ok_or(MachOError::MalformedSuperBlob)?;
        if rem.len() < 8 {
            return Err(MachOError::MalformedSuperBlob);
        }
        let bmagic = u32::from_be_bytes(rem[..4].try_into().unwrap());
        let blen = u32::from_be_bytes(rem[4..8].try_into().unwrap()) as usize;
        if bmagic == CSMAGIC_CODEDIRECTORY {
            let cd = rem.get(..blen).ok_or(MachOError::MalformedSuperBlob)?;
            if let Some(info) = parse_code_directory(image, cd)? {
                return Ok(info);
            }
        }
    }
    Err(MachOError::NoSha256CodeDirectory)
}

fn parse_code_directory(image: &[u8], cd: &[u8]) -> Result<Option<CodeSignatureInfo>, MachOError> {
    if cd.len() < 44 {
        return Err(MachOError::MalformedSuperBlob);
    }
    let version = u32::from_be_bytes(cd[8..12].try_into().unwrap());
    let flags = u32::from_be_bytes(cd[12..16].try_into().unwrap());
    let hash_offset = u32::from_be_bytes(cd[16..20].try_into().unwrap()) as usize;
    let ident_offset = u32::from_be_bytes(cd[20..24].try_into().unwrap()) as usize;
    let n_code_slots = u32::from_be_bytes(cd[28..32].try_into().unwrap());
    let code_limit = u32::from_be_bytes(cd[32..36].try_into().unwrap()) as usize;
    let hash_size = cd[36] as usize;
    let hash_type = cd[37];
    let page_shift = cd[39];
    if hash_type != CS_HASHTYPE_SHA256 || hash_size != 32 {
        return Ok(None);
    }
    if code_limit > image.len() {
        return Err(MachOError::Truncated);
    }
    let page_size = if page_shift == 0 { code_limit.max(1) } else { 1usize << page_shift };
    for slot in 0..n_code_slots as usize {
        let start = slot * page_size;
        let end = (start + page_size).min(code_limit);
        let page = image.get(start..end).ok_or(MachOError::Truncated)?;
        let expected_off = hash_offset.saturating_add(slot * hash_size);
        let expected = cd
            .get(expected_off..expected_off + hash_size)
            .ok_or(MachOError::MalformedSuperBlob)?;
        if Sha256::digest(page).as_slice() != expected {
            return Err(MachOError::PageHashMismatch { page: slot as u32 });
        }
    }

    let identifier = read_cstr(cd, ident_offset)?;
    let team_id = if version >= 0x20200 && cd.len() >= 52 {
        let team_off = u32::from_be_bytes(cd[48..52].try_into().unwrap()) as usize;
        if team_off == 0 { None } else { Some(read_cstr(cd, team_off)?) }
    } else {
        None
    };

    let digest: [u8; 32] = Sha256::digest(cd).into();
    Ok(Some(CodeSignatureInfo {
        cdhash: enc::hex(&digest[..20]),
        cd_sha256: enc::hex(&digest),
        identifier,
        team_id,
        flags,
    }))
}

fn read_cstr(buf: &[u8], offset: usize) -> Result<String, MachOError> {
    let tail = buf.get(offset..).ok_or(MachOError::MalformedSuperBlob)?;
    let end = tail.iter().position(|&b| b == 0).ok_or(MachOError::MalformedSuperBlob)?;
    std::str::from_utf8(&tail[..end])
        .map(str::to_owned)
        .map_err(|_| MachOError::InvalidUtf8)
}
