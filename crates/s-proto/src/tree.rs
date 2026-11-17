//! Deterministic SHA-256 tree digest (`liveMountDigest`) over a directory root.
//!
//! Symlinks are refused in `/s` lineups (no escape out of the read-only image).
//! Entries are sorted lexicographically by relative `/`-joined path.

use crate::enc;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::Path,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub rel_path: String,
    pub mode_exec: bool,
    pub size: u64,
    pub sha256: String,
}

/// Walks `root` to arbitrary depth inside the `/s` staging/live mount, rejecting symlinks
/// and non-regular files, and computes a deterministic tree SHA-256.
pub fn digest_dir(root: &Path) -> io::Result<(String, Vec<FileEntry>)> {
    let mut entries = Vec::new();
    collect(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    let mut h = Sha256::new();
    h.update(b"s-tree-v1\n");
    for e in &entries {
        let kind = if e.mode_exec { "x" } else { "f" };
        h.update(format!("{kind}:{}:{}:{}\n", e.rel_path, e.size, e.sha256).as_bytes());
    }
    let out: [u8; 32] = h.finalize().into();
    Ok((enc::hex(&out), entries))
}

fn collect(root: &Path, cur: &Path, out: &mut Vec<FileEntry>) -> io::Result<()> {
    let mut names = Vec::new();
    for entry in fs::read_dir(cur)? {
        let entry = entry?;
        names.push(entry.path());
    }
    names.sort();
    for path in names {
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("symlink forbidden in /s volume: {}", path.display()),
            ));
        }
        if meta.is_dir() {
            collect(root, &path, out)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let sha = file_sha256(&path)?;
            #[cfg(unix)]
            let mode_exec = {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o111 != 0
            };
            #[cfg(not(unix))]
            let mode_exec = false;
            out.push(FileEntry { rel_path: rel, mode_exec, size: meta.len(), sha256: sha });
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("special file forbidden in /s volume: {}", path.display()),
            ));
        }
    }
    Ok(())
}

pub fn file_sha256(path: &Path) -> io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let d: [u8; 32] = h.finalize().into();
    Ok(enc::hex(&d))
}
