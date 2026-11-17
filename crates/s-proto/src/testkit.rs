//! Deterministic test fixtures: software `sk-ssh-ed25519@openssh.com` signer (for offline
//! protocol tests where no physical YubiKey is plugged in) and synthetic signed 64-bit Mach-O
//! generator with valid `LC_CODE_SIGNATURE` + `CSMAGIC_CODEDIRECTORY` SHA-256 page slots.

use crate::{
    enc,
    sshsig::{
        build_sshsig_wrapper, encode_sk_pubkey_blob, put_bytes, PinnedSkKey, FLAG_USER_PRESENT,
        FLAG_USER_VERIFIED, KEY_TYPE,
    },
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256, Sha512};

pub struct MockFidoKey {
    signing: SigningKey,
    pub application: String,
    pub comment: String,
}

impl MockFidoKey {
    pub fn from_seed(seed: [u8; 32], comment: &str) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
            application: "ssh:".into(),
            comment: comment.into(),
        }
    }

    pub fn pinned(&self) -> PinnedSkKey {
        PinnedSkKey {
            pubkey: self.signing.verifying_key().to_bytes(),
            application: self.application.clone(),
            comment: self.comment.clone(),
        }
    }

    pub fn sign_sshsig(&self, namespace: &str, message: &[u8], flags: u8, counter: u32) -> String {
        let pk_blob =
            encode_sk_pubkey_blob(&self.signing.verifying_key().to_bytes(), &self.application);
        let msg_hash = Sha512::digest(message);
        let wrapper = build_sshsig_wrapper(namespace.as_bytes(), b"", b"sha512", &msg_hash);

        let mut sk_msg = Vec::with_capacity(69);
        sk_msg.extend_from_slice(&Sha256::digest(self.application.as_bytes()));
        sk_msg.push(flags);
        sk_msg.extend_from_slice(&counter.to_be_bytes());
        sk_msg.extend_from_slice(&Sha256::digest(&wrapper));
        let sig = self.signing.sign(&sk_msg);

        let mut sig_blob = Vec::new();
        put_bytes(&mut sig_blob, KEY_TYPE.as_bytes());
        put_bytes(&mut sig_blob, &sig.to_bytes());
        sig_blob.push(flags);
        sig_blob.extend_from_slice(&counter.to_be_bytes());

        let mut raw = Vec::new();
        raw.extend_from_slice(b"SSHSIG");
        raw.extend_from_slice(&1u32.to_be_bytes());
        put_bytes(&mut raw, &pk_blob);
        put_bytes(&mut raw, namespace.as_bytes());
        put_bytes(&mut raw, b"");
        put_bytes(&mut raw, b"sha512");
        put_bytes(&mut raw, &sig_blob);

        let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
        for chunk in enc::b64(&raw).as_bytes().chunks(70) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END SSH SIGNATURE-----\n");
        out
    }

    pub fn sign_touch_uv(&self, namespace: &str, message: &[u8], counter: u32) -> String {
        self.sign_sshsig(namespace, message, FLAG_USER_PRESENT | FLAG_USER_VERIFIED, counter)
    }
}

/// Builds a minimal valid 64-bit arm64 Mach-O image with a single `LC_CODE_SIGNATURE`
/// load command and embedded SHA-256 `CodeDirectory` (version `0x20400`) covering all
/// code bytes up to `codeLimit`, returning `(macho_bytes, sha256_hex, cdhash_hex)`.
pub fn synthetic_signed_macho(identifier: &str, team_id: &str, payload: &[u8]) -> (Vec<u8>, String, String) {
    let mut image = Vec::new();
    // mach_header_64 (32 bytes): magic, cputype ARM64 (0x0100000c), cpusubtype 0, filetype MH_EXECUTE (2),
    // ncmds = 1, sizeofcmds = 16, flags = 0, reserved = 0.
    image.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    image.extend_from_slice(&0x0100_000cu32.to_le_bytes());
    image.extend_from_slice(&0u32.to_le_bytes());
    image.extend_from_slice(&2u32.to_le_bytes());
    image.extend_from_slice(&1u32.to_le_bytes());
    image.extend_from_slice(&16u32.to_le_bytes());
    image.extend_from_slice(&0u32.to_le_bytes());
    image.extend_from_slice(&0u32.to_le_bytes());
    // Placeholder LC_CODE_SIGNATURE (16 bytes) at offset 32..48.
    image.extend_from_slice(&0x1du32.to_le_bytes());
    image.extend_from_slice(&16u32.to_le_bytes());
    image.extend_from_slice(&0u32.to_le_bytes()); // dataoff patched below
    image.extend_from_slice(&0u32.to_le_bytes()); // datasize patched below
    image.extend_from_slice(payload);
    while image.len() % 16 != 0 {
        image.push(0);
    }
    let code_limit = image.len();

    // Build CodeDirectory first after patching dataoff (dataoff = code_limit).
    // Wait: LC_CODE_SIGNATURE bytes are inside 0..code_limit, so datasize must be known
    // BEFORE hashing code pages! Compute exact SuperBlob length deterministically first.
    let ident_bytes = [identifier.as_bytes(), &[0u8]].concat();
    let team_bytes = [team_id.as_bytes(), &[0u8]].concat();
    let page_shift: u8 = 12; // 4096-byte pages
    let page_size = 1usize << page_shift;
    let n_code_slots = code_limit.div_ceil(page_size) as u32;
    let cd_hdr_len = 52usize; // version 0x20200 header through teamOffset
    let ident_off = cd_hdr_len;
    let team_off = ident_off + ident_bytes.len();
    let hash_off = team_off + team_bytes.len();
    let cd_len = hash_off + (n_code_slots as usize) * 32;
    let sb_len = 12 + 8 + cd_len;

    image[40..44].copy_from_slice(&(code_limit as u32).to_le_bytes());
    image[44..48].copy_from_slice(&(sb_len as u32).to_le_bytes());

    let mut cd = Vec::with_capacity(cd_len);
    cd.extend_from_slice(&0xfade_0c02u32.to_be_bytes());
    cd.extend_from_slice(&(cd_len as u32).to_be_bytes());
    cd.extend_from_slice(&0x0002_0400u32.to_be_bytes()); // version
    cd.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // flags (adhoc/runtime)
    cd.extend_from_slice(&(hash_off as u32).to_be_bytes());
    cd.extend_from_slice(&(ident_off as u32).to_be_bytes());
    cd.extend_from_slice(&0u32.to_be_bytes()); // nSpecialSlots
    cd.extend_from_slice(&n_code_slots.to_be_bytes());
    cd.extend_from_slice(&(code_limit as u32).to_be_bytes());
    cd.push(32); // hashSize
    cd.push(2); // hashType = SHA-256
    cd.push(0); // platform
    cd.push(page_shift);
    cd.extend_from_slice(&0u32.to_be_bytes()); // spare2
    cd.extend_from_slice(&0u32.to_be_bytes()); // scatterOffset
    cd.extend_from_slice(&(team_off as u32).to_be_bytes());
    cd.extend_from_slice(&ident_bytes);
    cd.extend_from_slice(&team_bytes);
    for slot in 0..n_code_slots as usize {
        let s = slot * page_size;
        let e = (s + page_size).min(code_limit);
        cd.extend_from_slice(&Sha256::digest(&image[s..e]));
    }
    debug_assert_eq!(cd.len(), cd_len);

    let cd_digest: [u8; 32] = Sha256::digest(&cd).into();
    let cdhash = enc::hex(&cd_digest[..20]);

    let mut sb = Vec::with_capacity(sb_len);
    sb.extend_from_slice(&0xfade_0cc0u32.to_be_bytes());
    sb.extend_from_slice(&(sb_len as u32).to_be_bytes());
    sb.extend_from_slice(&1u32.to_be_bytes()); // 1 blob
    sb.extend_from_slice(&0u32.to_be_bytes()); // CSSLOT_CODEDIRECTORY
    sb.extend_from_slice(&20u32.to_be_bytes()); // offset from SuperBlob start
    sb.extend_from_slice(&cd);
    debug_assert_eq!(sb.len(), sb_len);

    image.extend_from_slice(&sb);
    let sha = enc::hex(&enc::sha256(&image));
    (image, sha, cdhash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        macho::verify_macho_cdhash,
        noise::{keypair, Channel},
        sshsig::{
            verify, SshSigError, FLAG_USER_PRESENT, FLAG_USER_VERIFIED, POLICY_NAMESPACE,
        },
    };
    use std::{os::unix::net::UnixStream, thread};

    #[test]
    fn sshsig_enforces_up_uv_namespace_and_allowlist() {
        let key = MockFidoKey::from_seed([7u8; 32], "op@yubikey");
        let rogue = MockFidoKey::from_seed([9u8; 32], "rogue@yubikey");
        let allow = vec![key.pinned()];
        let msg = br#"{"nonce":"01","prevLedgerSha256":"00","proposedPolicySha256":"ff","seq":1}"#;

        let good = key.sign_touch_uv(POLICY_NAMESPACE, msg, 42);
        let ok = verify(&good, POLICY_NAMESPACE, msg, &allow).unwrap();
        assert_eq!(ok.counter, 42);
        assert_eq!(ok.flags, FLAG_USER_PRESENT | FLAG_USER_VERIFIED);

        // Missing UV (UP only -> 0x01) must fail.
        let no_uv = key.sign_sshsig(POLICY_NAMESPACE, msg, FLAG_USER_PRESENT, 43);
        assert_eq!(
            verify(&no_uv, POLICY_NAMESPACE, msg, &allow),
            Err(SshSigError::MissingUserVerification(FLAG_USER_PRESENT))
        );

        // Missing UP (UV only -> 0x04) must fail.
        let no_up = key.sign_sshsig(POLICY_NAMESPACE, msg, FLAG_USER_VERIFIED, 44);
        assert_eq!(
            verify(&no_up, POLICY_NAMESPACE, msg, &allow),
            Err(SshSigError::MissingUserPresence(FLAG_USER_VERIFIED))
        );

        // Wrong namespace rejected.
        assert!(matches!(
            verify(&good, "other-ns", msg, &allow),
            Err(SshSigError::NamespaceMismatch { .. })
        ));

        // Tampered message rejected.
        assert_eq!(verify(&good, POLICY_NAMESPACE, b"tampered", &allow), Err(SshSigError::BadSignature));

        // Unpinned hardware key rejected.
        let rogue_sig = rogue.sign_touch_uv(POLICY_NAMESPACE, msg, 1);
        assert_eq!(verify(&rogue_sig, POLICY_NAMESPACE, msg, &allow), Err(SshSigError::UntrustedKey));
    }

    #[test]
    fn macho_cdhash_verifies_and_catches_page_tampering() {
        let (mut bin, _sha, cdhash) = synthetic_signed_macho("com.stone.rg", "TEAM123456", &[0x90; 9000]);
        let info = verify_macho_cdhash(&bin).unwrap();
        assert_eq!(info.cdhash, cdhash);
        assert_eq!(info.identifier, "com.stone.rg");
        assert_eq!(info.team_id.as_deref(), Some("TEAM123456"));

        // Flip 1 byte in page 1 -> page slot hash mismatch.
        bin[4100] ^= 0x01;
        assert_eq!(verify_macho_cdhash(&bin), Err(crate::macho::MachOError::PageHashMismatch { page: 1 }));
    }

    #[test]
    fn noise_ik_mutual_auth_and_rogue_rejection() {
        let host = keypair().unwrap();
        let guest = keypair().unwrap();
        let rogue = keypair().unwrap();

        let (a, b) = UnixStream::pair().unwrap();
        let g_priv = guest.private;
        let h_pub = host.public;
        let srv = thread::spawn(move || {
            let mut ch = Channel::accept(b, &g_priv, &[h_pub]).unwrap();
            let v: serde_json::Value = ch.recv().unwrap();
            ch.send(&v).unwrap();
        });
        let mut cli = Channel::connect(a, &host.private, &guest.public).unwrap();
        cli.send(&serde_json::json!({"ping": 1})).unwrap();
        let echo: serde_json::Value = cli.recv().unwrap();
        assert_eq!(echo, serde_json::json!({"ping": 1}));
        srv.join().unwrap();

        // Rogue initiator rejected by responder allowlist.
        let (a2, b2) = UnixStream::pair().unwrap();
        let srv2 = thread::spawn(move || Channel::accept(b2, &guest.private, &[host.public]));
        let _ = Channel::connect(a2, &rogue.private, &guest.public);
        assert!(srv2.join().unwrap().is_err());
    }
}
