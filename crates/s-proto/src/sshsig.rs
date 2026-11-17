//! OpenSSH `SSHSIG` verifier for `sk-ssh-ed25519@openssh.com` hardware FIDO2 keys.
//!
//! Enforces:
//! - PEM armor `-----BEGIN SSH SIGNATURE-----` / `-----END SSH SIGNATURE-----`
//! - `SSHSIG` magic + version `1`
//! - Key type `sk-ssh-ed25519@openssh.com` matching a pinned root key (`pubkey` + `application`)
//! - Exact namespace (e.g. `"s-policy-v1"`), non-empty, `sha512` hash algorithm
//! - WebAuthn authenticator flags: User Presence (`flags & 0x01 != 0`) AND
//!   User Verification (`flags & 0x04 != 0`)
//! - Ed25519 signature over `SHA256(application) || flags || counter || SHA256(M)` where
//!   `M = "SSHSIG" || string(namespace) || string(reserved) || string("sha512") || string(SHA512(message))`

use crate::enc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;

pub const KEY_TYPE: &str = "sk-ssh-ed25519@openssh.com";
pub const POLICY_NAMESPACE: &str = "s-policy-v1";
pub const FLAG_USER_PRESENT: u8 = 0x01;
pub const FLAG_USER_VERIFIED: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedSkKey {
    pub pubkey: [u8; 32],
    pub application: String,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSig {
    pub key_fingerprint_sha256: String,
    pub application: String,
    pub flags: u8,
    pub counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshSigError {
    Armor,
    Base64,
    Wire(&'static str),
    UnsupportedVersion(u32),
    UnsupportedKeyType(String),
    UnsupportedHash(String),
    NamespaceMismatch { expected: String, got: String },
    UntrustedKey,
    MissingUserPresence(u8),
    MissingUserVerification(u8),
    BadSignature,
}

impl fmt::Display for SshSigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Armor => f.write_str("invalid SSHSIG PEM armor"),
            Self::Base64 => f.write_str("invalid base64 in SSHSIG or public key"),
            Self::Wire(w) => write!(f, "malformed SSH wire encoding: {w}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported SSHSIG version {v}"),
            Self::UnsupportedKeyType(k) => write!(f, "key type {k} rejected (need {KEY_TYPE})"),
            Self::UnsupportedHash(h) => write!(f, "unsupported SSHSIG hash {h}"),
            Self::NamespaceMismatch { expected, got } => {
                write!(f, "SSHSIG namespace {got:?} != {expected:?}")
            }
            Self::UntrustedKey => f.write_str("signing key is not in pinned hardware allowlist"),
            Self::MissingUserPresence(fl) => write!(f, "FIDO UP flag (0x01) clear: flags=0x{fl:02x}"),
            Self::MissingUserVerification(fl) => {
                write!(f, "FIDO UV flag (0x04) clear: flags=0x{fl:02x}")
            }
            Self::BadSignature => f.write_str("Ed25519 signature verification failed"),
        }
    }
}

impl std::error::Error for SshSigError {}

impl PinnedSkKey {
    /// Parses `<KEY_TYPE> <base64-wire-blob> [comment]`.
    pub fn parse_authorized_line(line: &str) -> Result<Self, SshSigError> {
        let mut parts = line.split_whitespace();
        let kt = parts.next().ok_or(SshSigError::Wire("empty key line"))?;
        if kt != KEY_TYPE {
            return Err(SshSigError::UnsupportedKeyType(kt.into()));
        }
        let b64 = parts.next().ok_or(SshSigError::Wire("missing key blob"))?;
        let comment = parts.collect::<Vec<_>>().join(" ");
        let raw = enc::unb64(b64).ok_or(SshSigError::Base64)?;
        let (pubkey, application) = parse_sk_pubkey_blob(&raw)?;
        Ok(Self { pubkey, application, comment })
    }

    pub fn to_authorized_line(&self) -> String {
        let blob = encode_sk_pubkey_blob(&self.pubkey, &self.application);
        if self.comment.is_empty() {
            format!("{KEY_TYPE} {}", enc::b64(&blob))
        } else {
            format!("{KEY_TYPE} {} {}", enc::b64(&blob), self.comment)
        }
    }

    pub fn fingerprint_sha256(&self) -> String {
        enc::hex(&enc::sha256(&encode_sk_pubkey_blob(&self.pubkey, &self.application)))
    }
}

pub fn parse_allowlist(text: &str) -> Result<Vec<PinnedSkKey>, SshSigError> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(PinnedSkKey::parse_authorized_line)
        .collect()
}

pub fn verify(
    armored_sig: &str,
    expected_namespace: &str,
    message: &[u8],
    allowlist: &[PinnedSkKey],
) -> Result<VerifiedSig, SshSigError> {
    let raw = dearmor(armored_sig)?;
    let mut r = Reader(&raw);
    if r.fixed(6)? != b"SSHSIG" {
        return Err(SshSigError::Wire("missing SSHSIG magic"));
    }
    let ver = r.u32()?;
    if ver != 1 {
        return Err(SshSigError::UnsupportedVersion(ver));
    }
    let pk_blob = r.bytes()?;
    let ns = r.string()?;
    let reserved = r.bytes()?;
    let hash_alg = r.string()?;
    let sig_blob = r.bytes()?;
    r.eof()?;

    if ns != expected_namespace {
        return Err(SshSigError::NamespaceMismatch {
            expected: expected_namespace.into(),
            got: ns.into(),
        });
    }
    let (pubkey, app) = parse_sk_pubkey_blob(pk_blob)?;
    let pinned = allowlist
        .iter()
        .find(|k| k.pubkey == pubkey && k.application == app)
        .ok_or(SshSigError::UntrustedKey)?;

    let msg_hash: Vec<u8> = match hash_alg {
        "sha512" => Sha512::digest(message).to_vec(),
        "sha256" => Sha256::digest(message).to_vec(),
        other => return Err(SshSigError::UnsupportedHash(other.into())),
    };

    let mut sr = Reader(sig_blob);
    let sig_type = sr.string()?;
    if sig_type != KEY_TYPE {
        return Err(SshSigError::UnsupportedKeyType(sig_type.into()));
    }
    let raw_sig: [u8; 64] = sr
        .bytes()?
        .try_into()
        .map_err(|_| SshSigError::Wire("ed25519 sig len"))?;
    let flags = sr.u8()?;
    let counter = sr.u32()?;
    sr.eof()?;

    if flags & FLAG_USER_PRESENT == 0 {
        return Err(SshSigError::MissingUserPresence(flags));
    }
    if flags & FLAG_USER_VERIFIED == 0 {
        return Err(SshSigError::MissingUserVerification(flags));
    }

    let signed_wrapper = build_sshsig_wrapper(ns.as_bytes(), reserved, hash_alg.as_bytes(), &msg_hash);
    let mut sk_msg = Vec::with_capacity(69);
    sk_msg.extend_from_slice(&Sha256::digest(app.as_bytes()));
    sk_msg.push(flags);
    sk_msg.extend_from_slice(&counter.to_be_bytes());
    sk_msg.extend_from_slice(&Sha256::digest(&signed_wrapper));

    let vk = VerifyingKey::from_bytes(&pubkey).map_err(|_| SshSigError::BadSignature)?;
    let sig = Signature::from_bytes(&raw_sig);
    vk.verify(&sk_msg, &sig).map_err(|_| SshSigError::BadSignature)?;

    Ok(VerifiedSig {
        key_fingerprint_sha256: pinned.fingerprint_sha256(),
        application: app,
        flags,
        counter,
    })
}

pub(crate) fn build_sshsig_wrapper(
    namespace: &[u8],
    reserved: &[u8],
    hash_alg: &[u8],
    msg_hash: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + 16 + namespace.len() + reserved.len() + hash_alg.len() + msg_hash.len());
    out.extend_from_slice(b"SSHSIG");
    put_bytes(&mut out, namespace);
    put_bytes(&mut out, reserved);
    put_bytes(&mut out, hash_alg);
    put_bytes(&mut out, msg_hash);
    out
}

pub(crate) fn encode_sk_pubkey_blob(pubkey: &[u8; 32], application: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, KEY_TYPE.as_bytes());
    put_bytes(&mut out, pubkey);
    put_bytes(&mut out, application.as_bytes());
    out
}

fn parse_sk_pubkey_blob(blob: &[u8]) -> Result<([u8; 32], String), SshSigError> {
    let mut r = Reader(blob);
    let kt = r.string()?;
    if kt != KEY_TYPE {
        return Err(SshSigError::UnsupportedKeyType(kt.into()));
    }
    let pk: [u8; 32] = r.bytes()?.try_into().map_err(|_| SshSigError::Wire("sk pubkey len"))?;
    let app = r.string()?.to_owned();
    if app.is_empty() {
        return Err(SshSigError::Wire("empty sk application"));
    }
    r.eof()?;
    Ok((pk, app))
}

pub(crate) fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn dearmor(s: &str) -> Result<Vec<u8>, SshSigError> {
    const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
    const END: &str = "-----END SSH SIGNATURE-----";
    let mut lines = s.lines().map(str::trim).filter(|l| !l.is_empty());
    if lines.next() != Some(BEGIN) {
        return Err(SshSigError::Armor);
    }
    let mut body = String::new();
    let mut saw_end = false;
    for line in lines {
        if line == END {
            saw_end = true;
            break;
        }
        body.push_str(line);
    }
    if !saw_end || body.is_empty() {
        return Err(SshSigError::Armor);
    }
    enc::unb64(&body).ok_or(SshSigError::Base64)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn fixed(&mut self, n: usize) -> Result<&'a [u8], SshSigError> {
        if self.0.len() < n {
            return Err(SshSigError::Wire("truncated"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8, SshSigError> {
        Ok(self.fixed(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, SshSigError> {
        Ok(u32::from_be_bytes(self.fixed(4)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> Result<&'a [u8], SshSigError> {
        let n = self.u32()? as usize;
        self.fixed(n)
    }

    fn string(&mut self) -> Result<&'a str, SshSigError> {
        std::str::from_utf8(self.bytes()?).map_err(|_| SshSigError::Wire("utf8"))
    }

    fn eof(&self) -> Result<(), SshSigError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(SshSigError::Wire("trailing bytes"))
        }
    }
}
