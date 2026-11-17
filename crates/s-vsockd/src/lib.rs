//! Core state machine for `s-vsockd`: enforces the 3-volume boundary (`master`, `ledger`, `live`),
//! 60-second single-use policy challenges, FIDO2 `SSHSIG` UP+UV verification, and Mach-O CDHash
//! bundle quarantine.

pub mod transport;

use s_ledger::{Ledger, LedgerRecord, ProvenanceArtifact, GENESIS_PREV_SHA256};
use s_proto::{
    enc,
    macho::verify_macho_cdhash,
    msg::{
        ChallengePolicyReq, ChallengePolicyResp, ChallengeSignable, CommitPolicyReq,
        CommitPolicyResp, Envelope, IngestBundleReq, IngestBundleResp, Lineup, PolicyAction,
        PolicyProposal, Request, StatusResp, VerifyResp, BUNDLE_SSHSIG_NAMESPACE,
        CHALLENGE_TTL_SECS,
    },
    noise::Channel,
    sshsig::{verify, PinnedSkKey, POLICY_NAMESPACE},
    tree::digest_dir,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuarantineMeta {
    bundle_name: String,
    version: String,
    sha256: String,
    cdhash: String,
    team_id: String,
    identifier: String,
    signer_fingerprint: String,
}

#[derive(Debug, Clone)]
struct PendingChallenge {
    nonce: String,
    seq: u64,
    prev_ledger_sha256: String,
    proposed_policy_sha256: String,
    proposal: PolicyProposal,
    issued_unix: u64,
}

pub struct Volumes {
    pub master_dir: PathBuf,
    pub ledger_dir: PathBuf,
    pub live_dir: PathBuf,
}

pub struct Engine {
    volumes: Volumes,
    ledger: Ledger,
    allowlist: Vec<PinnedSkKey>,
    boot: Instant,
    active_generation: u64,
    policy_revision: u64,
    state: String,
    challenges: BTreeMap<String, PendingChallenge>,
    consumed_nonces: BTreeSet<String>,
    clock_override: Option<u64>,
}

impl Engine {
    pub fn open(volumes: Volumes, allowlist: Vec<PinnedSkKey>) -> Result<Self, String> {
        if allowlist.is_empty() {
            return Err("hardware allowlist cannot be empty".into());
        }
        fs::create_dir_all(volumes.master_dir.join("quarantine")).map_err(|e| e.to_string())?;
        fs::create_dir_all(volumes.master_dir.join("generations")).map_err(|e| e.to_string())?;
        fs::create_dir_all(volumes.master_dir.join("dropbox")).map_err(|e| e.to_string())?;
        fs::create_dir_all(&volumes.live_dir).map_err(|e| e.to_string())?;

        let ledger =
            Ledger::open(&volumes.ledger_dir, Some(&allowlist)).map_err(|e| e.to_string())?;
        let (active_generation, policy_revision, state) = match ledger.tip() {
            Some(tip) => (
                tip.record.resulting_generation,
                tip.record.resulting_policy_revision,
                tip.record.state.clone(),
            ),
            None => (0, 0, "UNINITIALIZED".into()),
        };

        Ok(Self {
            volumes,
            ledger,
            allowlist,
            boot: Instant::now(),
            active_generation,
            policy_revision,
            state,
            challenges: BTreeMap::new(),
            consumed_nonces: BTreeSet::new(),
            clock_override: None,
        })
    }

    pub fn set_clock_for_test(&mut self, unix_secs: Option<u64>) {
        self.clock_override = unix_secs;
    }

    fn now_unix(&self) -> u64 {
        self.clock_override.unwrap_or_else(|| {
            SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
        })
    }

    pub fn serve_channel<S: Read + Write>(&mut self, mut ch: Channel<S>) -> io::Result<()> {
        loop {
            let req: Request = match ch.recv() {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            match req {
                Request::Status(_) => ch.send(&self.handle_status())?,
                Request::Verify(r) => ch.send(&self.handle_verify(r.observed_host_digest))?,
                Request::IngestBundle(r) => ch.send(&self.handle_ingest(r))?,
                Request::ChallengePolicy(r) => ch.send(&self.handle_challenge(r))?,
                Request::CommitPolicy(r) => ch.send(&self.handle_commit(r))?,
            }
        }
    }

    pub fn handle_status(&self) -> Envelope<StatusResp> {
        let live_digest = digest_dir(&self.volumes.live_dir)
            .map(|(d, _)| d)
            .unwrap_or_else(|_| GENESIS_PREV_SHA256.to_owned());
        Envelope::ok(StatusResp {
            active_generation: self.active_generation,
            live_mount_digest: live_digest,
            policy_revision: self.policy_revision,
            vm_uptime: self.boot.elapsed().as_secs(),
            ledger_tip_sha256: self.ledger.tip_sha256(),
            state: self.state.clone(),
        })
    }

    pub fn handle_verify(&self, observed_host_digest: Option<String>) -> Envelope<VerifyResp> {
        let live_digest = match digest_dir(&self.volumes.live_dir) {
            Ok((d, _)) => d,
            Err(e) => return Envelope::err("LIVE_READ_FAILED", e.to_string()),
        };
        let expected = match self.ledger.tip() {
            Some(tip) => tip.record.live_mount_digest.clone(),
            None => live_digest.clone(),
        };
        let clone_matches = live_digest == expected;
        let host_matches = observed_host_digest.as_ref().map(|h| h == &expected).unwrap_or(true);
        let verified = clone_matches && host_matches;
        let detail = if verified {
            "live mount and ledger tip match".into()
        } else if !clone_matches {
            "guest live.sparseimage diverges from ledger tip".into()
        } else {
            "host /s digest diverges from guest ledger tip".into()
        };
        Envelope::ok(VerifyResp {
            verified,
            active_generation: self.active_generation,
            expected_digest: expected,
            live_clone_digest: live_digest,
            observed_host_digest,
            ledger_chain_length: self.ledger.len(),
            ledger_tip_sha256: self.ledger.tip_sha256(),
            detail,
        })
    }

    pub fn handle_ingest(&mut self, req: IngestBundleReq) -> Envelope<IngestBundleResp> {
        if !enc::is_hex(&req.expected_sha256, 32) || !enc::is_hex(&req.expected_cdhash, 20) {
            return Envelope::err("INVALID_DIGEST", "expected_sha256 or expected_cdhash malformed");
        }
        let bytes = match (&req.binary_b64, &req.quarantine_rel_path) {
            (Some(b64), None) => match enc::unb64(b64) {
                Some(b) => b,
                None => return Envelope::err("INVALID_BASE64", "binary_b64 is not strict base64"),
            },
            (None, Some(rel)) => {
                if !s_proto::msg::is_safe_rel_path(rel) {
                    return Envelope::err("INVALID_PATH", "unsafe quarantine_rel_path");
                }
                let p = self.volumes.master_dir.join("dropbox").join(rel);
                match fs::read(&p) {
                    Ok(b) => {
                        let _ = fs::remove_file(&p);
                        b
                    }
                    Err(e) => return Envelope::err("DROPBOX_READ", e.to_string()),
                }
            }
            _ => {
                return Envelope::err(
                    "INVALID_SOURCE",
                    "provide exactly one of binary_b64 or quarantine_rel_path",
                )
            }
        };

        let sha = enc::hex(&enc::sha256(&bytes));
        if sha != req.expected_sha256 {
            return Envelope::err(
                "SHA256_MISMATCH",
                format!("computed {sha} != expected {}", req.expected_sha256),
            );
        }
        let macho = match verify_macho_cdhash(&bytes) {
            Ok(m) => m,
            Err(e) => return Envelope::err("MACHO_REJECTED", e.to_string()),
        };
        if macho.cdhash != req.expected_cdhash {
            return Envelope::err(
                "CDHASH_MISMATCH",
                format!("computed {} != expected {}", macho.cdhash, req.expected_cdhash),
            );
        }
        if macho.team_id.as_deref() != Some(req.expected_team_id.as_str()) {
            return Envelope::err(
                "TEAM_ID_MISMATCH",
                format!("Mach-O team {:?} != expected {}", macho.team_id, req.expected_team_id),
            );
        }
        let sig_ok = match verify(
            &req.detached_sshsig,
            BUNDLE_SSHSIG_NAMESPACE,
            &bytes,
            &self.allowlist,
        ) {
            Ok(v) => v,
            Err(e) => return Envelope::err("BUNDLE_SIG_REJECTED", e.to_string()),
        };

        let qdir = self.volumes.master_dir.join("quarantine");
        let bin_path = qdir.join(format!("{sha}.bin"));
        let meta_path = qdir.join(format!("{sha}.json"));
        let meta = QuarantineMeta {
            bundle_name: req.bundle_name,
            version: req.version,
            sha256: sha.clone(),
            cdhash: macho.cdhash.clone(),
            team_id: req.expected_team_id.clone(),
            identifier: macho.identifier.clone(),
            signer_fingerprint: sig_ok.key_fingerprint_sha256.clone(),
        };
        if let Err(e) = write_readonly_file(&bin_path, &bytes, false) {
            return Envelope::err("QUARANTINE_WRITE", e.to_string());
        }
        let meta_bytes = match s_proto::canon::encode(&meta) {
            Ok(b) => b,
            Err(e) => return Envelope::err("CANON_ENCODE", e.to_string()),
        };
        if let Err(e) = write_readonly_file(&meta_path, &meta_bytes, false) {
            return Envelope::err("QUARANTINE_META", e.to_string());
        }

        Envelope::ok(IngestBundleResp {
            quarantine_id: sha.clone(),
            sha256: sha,
            cdhash: macho.cdhash,
            team_id: req.expected_team_id,
            identifier: macho.identifier,
            signer_fingerprint: sig_ok.key_fingerprint_sha256,
        })
    }

    pub fn handle_challenge(&mut self, req: ChallengePolicyReq) -> Envelope<ChallengePolicyResp> {
        let now = self.now_unix();
        self.challenges.retain(|_, c| now <= c.issued_unix.saturating_add(CHALLENGE_TTL_SECS));

        match req.action {
            PolicyAction::Enforce => {
                let Some(lineup) = &req.lineup else {
                    return Envelope::err("MISSING_LINEUP", "ENFORCE requires lineup");
                };
                if req.rollback_generation.is_some() {
                    return Envelope::err("INVALID_PARAMS", "ENFORCE forbids rollback_generation");
                }
                if let Err(e) = lineup.validate() {
                    return Envelope::err("INVALID_LINEUP", e);
                }
                if lineup.policy_revision <= self.policy_revision {
                    return Envelope::err(
                        "STALE_REVISION",
                        format!(
                            "lineup policy_revision {} must exceed active {}",
                            lineup.policy_revision, self.policy_revision
                        ),
                    );
                }
                if let Err(e) = self.verify_quarantine_coverage(lineup) {
                    return Envelope::err("MISSING_QUARANTINE_BUNDLE", e);
                }
            }
            PolicyAction::Suspend => {
                if req.lineup.is_some() || req.rollback_generation.is_some() {
                    return Envelope::err("INVALID_PARAMS", "SUSPEND takes no lineup or generation");
                }
            }
            PolicyAction::Rollback => {
                if req.lineup.is_some() {
                    return Envelope::err("INVALID_PARAMS", "ROLLBACK forbids inline lineup");
                }
                let Some(gen) = req.rollback_generation else {
                    return Envelope::err("MISSING_GENERATION", "ROLLBACK requires generation");
                };
                if self.ledger.find_generation(gen).is_none()
                    || !self.generation_dir(gen).is_dir()
                {
                    return Envelope::err(
                        "UNKNOWN_GENERATION",
                        format!("generation {gen} does not exist in master/ledger"),
                    );
                }
            }
        }

        let proposal = PolicyProposal {
            action: req.action,
            lineup: req.lineup,
            rollback_generation: req.rollback_generation,
        };
        let proposed_sha = match proposal.sha256_hex() {
            Ok(h) => h,
            Err(e) => return Envelope::err("CANON_ENCODE", e.to_string()),
        };
        let nonce = match random_nonce_hex() {
            Ok(n) => n,
            Err(e) => return Envelope::err("RNG_FAILED", e.to_string()),
        };
        let seq = self.ledger.next_seq();
        let prev = self.ledger.tip_sha256();
        self.challenges.insert(
            nonce.clone(),
            PendingChallenge {
                nonce: nonce.clone(),
                seq,
                prev_ledger_sha256: prev.clone(),
                proposed_policy_sha256: proposed_sha.clone(),
                proposal,
                issued_unix: now,
            },
        );
        Envelope::ok(ChallengePolicyResp {
            nonce,
            seq,
            prev_ledger_sha256: prev,
            proposed_policy_sha256: proposed_sha,
            expires_in_secs: CHALLENGE_TTL_SECS,
        })
    }

    pub fn handle_commit(&mut self, req: CommitPolicyReq) -> Envelope<CommitPolicyResp> {
        if self.consumed_nonces.contains(&req.challenge_nonce) {
            return Envelope::err("CHALLENGE_REPLAYED", "challenge nonce already consumed");
        }
        let Some(ch) = self.challenges.get(&req.challenge_nonce).cloned() else {
            return Envelope::err("UNKNOWN_CHALLENGE", "unknown or purged challenge nonce");
        };
        let now = self.now_unix();
        if now > ch.issued_unix.saturating_add(CHALLENGE_TTL_SECS) {
            self.challenges.remove(&req.challenge_nonce);
            return Envelope::err("CHALLENGE_EXPIRED", "60-second challenge TTL elapsed");
        }
        if ch.seq != self.ledger.next_seq() || ch.prev_ledger_sha256 != self.ledger.tip_sha256() {
            self.challenges.remove(&req.challenge_nonce);
            return Envelope::err(
                "STALE_CHALLENGE",
                "ledger advanced since challenge was issued; re-challenge required",
            );
        }

        let signable = ChallengeSignable {
            nonce: ch.nonce.clone(),
            prev_ledger_sha256: ch.prev_ledger_sha256.clone(),
            proposed_policy_sha256: ch.proposed_policy_sha256.clone(),
            seq: ch.seq,
        };
        let msg = match signable.canonical_bytes() {
            Ok(b) => b,
            Err(e) => return Envelope::err("CANON_ENCODE", e.to_string()),
        };
        let sig_info = match verify(&req.fido_ssh_sig, POLICY_NAMESPACE, &msg, &self.allowlist) {
            Ok(v) => v,
            Err(e) => return Envelope::err("FIDO_SIG_REJECTED", e.to_string()),
        };

        let (new_gen, new_rev, new_state, artifacts) = match ch.proposal.action {
            PolicyAction::Enforce => {
                let lineup = ch.proposal.lineup.as_ref().unwrap();
                let next_gen = self.next_generation_id();
                if let Err(e) = self.materialize_generation(next_gen, lineup) {
                    return Envelope::err("MATERIALIZE_FAILED", e);
                }
                if let Err(e) = clone_readonly_tree(&self.generation_dir(next_gen), &self.volumes.live_dir) {
                    return Envelope::err("LIVE_SWAP_FAILED", e.to_string());
                }
                let arts = lineup
                    .entries
                    .iter()
                    .map(|e| ProvenanceArtifact {
                        install_rel_path: e.install_rel_path.clone(),
                        bundle_name: e.bundle_name.clone(),
                        version: e.version.clone(),
                        sha256: e.sha256.clone(),
                        cdhash: e.cdhash.clone(),
                        team_id: e.team_id.clone(),
                    })
                    .collect();
                (next_gen, lineup.policy_revision, "ENFORCING".to_owned(), arts)
            }
            PolicyAction::Suspend => {
                if let Err(e) = wipe_dir(&self.volumes.live_dir) {
                    return Envelope::err("LIVE_WIPE_FAILED", e.to_string());
                }
                (
                    self.active_generation,
                    self.policy_revision + 1,
                    "SUSPENDED".to_owned(),
                    Vec::new(),
                )
            }
            PolicyAction::Rollback => {
                let target_gen = ch.proposal.rollback_generation.unwrap();
                let Some(orig) = self.ledger.find_generation(target_gen).cloned() else {
                    return Envelope::err("UNKNOWN_GENERATION", "target generation missing");
                };
                if let Err(e) =
                    clone_readonly_tree(&self.generation_dir(target_gen), &self.volumes.live_dir)
                {
                    return Envelope::err("LIVE_SWAP_FAILED", e.to_string());
                }
                (
                    target_gen,
                    self.policy_revision + 1,
                    "ENFORCING".to_owned(),
                    orig.record.artifacts,
                )
            }
        };

        let live_digest = match digest_dir(&self.volumes.live_dir) {
            Ok((d, _)) => d,
            Err(e) => return Envelope::err("LIVE_DIGEST_FAILED", e.to_string()),
        };

        let record = LedgerRecord {
            seq: ch.seq,
            timestamp_unix: now,
            prev_record_sha256: ch.prev_ledger_sha256,
            challenge_nonce: ch.nonce.clone(),
            proposed_policy_sha256: ch.proposed_policy_sha256,
            proposal: ch.proposal,
            resulting_generation: new_gen,
            resulting_policy_revision: new_rev,
            live_mount_digest: live_digest.clone(),
            state: new_state.clone(),
            signer_fingerprint_sha256: sig_info.key_fingerprint_sha256,
            fido_flags: sig_info.flags,
            fido_counter: sig_info.counter,
            fido_ssh_sig: req.fido_ssh_sig,
            artifacts,
        };
        let indexed = match self.ledger.append(record, &self.allowlist) {
            Ok(i) => i,
            Err(e) => return Envelope::err("LEDGER_APPEND_FAILED", e.to_string()),
        };

        self.challenges.remove(&req.challenge_nonce);
        self.consumed_nonces.insert(req.challenge_nonce);
        self.active_generation = new_gen;
        self.policy_revision = new_rev;
        self.state = new_state.clone();

        Envelope::ok(CommitPolicyResp {
            active_generation: new_gen,
            live_mount_digest: live_digest,
            policy_revision: new_rev,
            ledger_seq: indexed.record.seq,
            ledger_record_sha256: indexed.record_sha256,
            state: new_state,
        })
    }

    fn generation_dir(&self, gen: u64) -> PathBuf {
        self.volumes.master_dir.join("generations").join(format!("gen-{gen:06}"))
    }

    fn next_generation_id(&self) -> u64 {
        self.ledger
            .records()
            .iter()
            .map(|r| r.record.resulting_generation)
            .max()
            .unwrap_or(0)
            + 1
    }

    fn verify_quarantine_coverage(&self, lineup: &Lineup) -> Result<(), String> {
        let qdir = self.volumes.master_dir.join("quarantine");
        for e in &lineup.entries {
            let meta_path = qdir.join(format!("{}.json", e.sha256));
            let bin_path = qdir.join(format!("{}.bin", e.sha256));
            if !bin_path.is_file() || !meta_path.is_file() {
                return Err(format!("bundle {} ({}) not ingested", e.bundle_name, e.sha256));
            }
            let bytes = fs::read(&meta_path).map_err(|err| err.to_string())?;
            let meta: QuarantineMeta =
                s_proto::canon::decode(&bytes).map_err(|err| err.to_string())?;
            if meta.cdhash != e.cdhash || meta.team_id != e.team_id {
                return Err(format!(
                    "quarantine metadata mismatch for {} (cdhash/team_id)",
                    e.install_rel_path
                ));
            }
        }
        Ok(())
    }

    fn materialize_generation(&self, gen: u64, lineup: &Lineup) -> Result<(), String> {
        let gdir = self.generation_dir(gen);
        if gdir.exists() {
            return Err(format!("generation {gen} directory already exists"));
        }
        fs::create_dir_all(&gdir).map_err(|e| e.to_string())?;
        let qdir = self.volumes.master_dir.join("quarantine");
        for e in &lineup.entries {
            let src = qdir.join(format!("{}.bin", e.sha256));
            let bytes = fs::read(&src).map_err(|err| err.to_string())?;
            if enc::hex(&enc::sha256(&bytes)) != e.sha256 {
                return Err(format!("quarantine corruption on {}", e.sha256));
            }
            let dst = gdir.join(&e.install_rel_path);
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent).map_err(|err| err.to_string())?;
            }
            write_readonly_file(&dst, &bytes, true).map_err(|err| err.to_string())?;
        }
        Ok(())
    }
}

fn write_readonly_file(path: &Path, bytes: &[u8], exec: bool) -> io::Result<()> {
    if path.exists() {
        let mut p = fs::metadata(path)?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            p.set_mode(0o600);
        }
        let _ = fs::set_permissions(path, p);
        fs::remove_file(path)?;
    }
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if exec { 0o555 } else { 0o444 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn wipe_dir(dir: &Path) -> io::Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        make_writable_recursive(&p)?;
        if p.is_dir() {
            fs::remove_dir_all(&p)?;
        } else {
            fs::remove_file(&p)?;
        }
    }
    Ok(())
}

fn make_writable_recursive(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(path)?;
        if meta.is_dir() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            for entry in fs::read_dir(path)? {
                make_writable_recursive(&entry?.path())?;
            }
        } else {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn clone_readonly_tree(src: &Path, dst: &Path) -> io::Result<()> {
    wipe_dir(dst)?;
    copy_dir_inner(src, dst)
}

fn copy_dir_inner(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let sp = entry.path();
        let dp = dst.join(entry.file_name());
        let meta = fs::symlink_metadata(&sp)?;
        if meta.is_dir() {
            copy_dir_inner(&sp, &dp)?;
        } else if meta.is_file() {
            let bytes = fs::read(&sp)?;
            write_readonly_file(&dp, &bytes, true)?;
        }
    }
    Ok(())
}

fn random_nonce_hex() -> io::Result<String> {
    let mut f = fs::File::open("/dev/urandom")?;
    let mut b = [0u8; 16];
    f.read_exact(&mut b)?;
    Ok(enc::hex(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use s_proto::{
        client::Client,
        msg::LineupEntry,
        noise::keypair,
        sshsig::FLAG_USER_PRESENT,
        testkit::{synthetic_signed_macho, MockFidoKey},
    };
    use std::{os::unix::net::UnixStream, thread};

    fn temp_volumes(tag: &str) -> (PathBuf, Volumes) {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let base = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("vsockd-test")
            .join(format!("{tag}-{nanos}"));
        let v = Volumes {
            master_dir: base.join("master.sparseimage"),
            ledger_dir: base.join("ledger.sparseimage"),
            live_dir: base.join("live.sparseimage"),
        };
        (base, v)
    }

    #[test]
    fn full_5_verb_lifecycle_replay_ttl_and_rollback() {
        let (base, vols) = temp_volumes("lifecycle");
        let fido = MockFidoKey::from_seed([11u8; 32], "stone-op@yk");
        let mut engine = Engine::open(vols, vec![fido.pinned()]).unwrap();
        engine.set_clock_for_test(Some(1_700_000_000));

        // 1. Ingest signed Mach-O bundle.
        let (macho, sha, cdhash) = synthetic_signed_macho("com.stone.rg", "TEAMSTONE1", b"rg-v1");
        let bundle_sig = fido.sign_touch_uv(BUNDLE_SSHSIG_NAMESPACE, &macho, 1);
        let ing = engine.handle_ingest(IngestBundleReq {
            bundle_name: "ripgrep".into(),
            version: "14.1.0".into(),
            binary_b64: Some(enc::b64(&macho)),
            quarantine_rel_path: None,
            expected_sha256: sha.clone(),
            expected_cdhash: cdhash.clone(),
            expected_team_id: "TEAMSTONE1".into(),
            detached_sshsig: bundle_sig,
        });
        assert!(ing.ok, "{ing:?}");

        // 2. Challenge ENFORCE lineup -> verify 60s TTL expiration first.
        let lineup = Lineup {
            schema_version: 1,
            policy_revision: 1,
            description: "gen1 tools".into(),
            entries: vec![LineupEntry {
                install_rel_path: "bin/rg".into(),
                bundle_name: "ripgrep".into(),
                version: "14.1.0".into(),
                sha256: sha.clone(),
                cdhash: cdhash.clone(),
                team_id: "TEAMSTONE1".into(),
            }],
        };
        let ch_exp = engine
            .handle_challenge(ChallengePolicyReq {
                action: PolicyAction::Enforce,
                lineup: Some(lineup.clone()),
                rollback_generation: None,
            })
            .result
            .unwrap();
        engine.set_clock_for_test(Some(1_700_000_061)); // +61s > 60s TTL
        let sig_exp = fido.sign_touch_uv(
            POLICY_NAMESPACE,
            &ch_exp.signable().canonical_bytes().unwrap(),
            2,
        );
        let exp_res = engine.handle_commit(CommitPolicyReq {
            challenge_nonce: ch_exp.nonce,
            fido_ssh_sig: sig_exp,
        });
        assert_eq!(exp_res.error.unwrap().code, "CHALLENGE_EXPIRED");

        // 3. Re-challenge within TTL; test UP-only signature rejected, then UP+UV succeeds.
        let ch1 = engine
            .handle_challenge(ChallengePolicyReq {
                action: PolicyAction::Enforce,
                lineup: Some(lineup),
                rollback_generation: None,
            })
            .result
            .unwrap();
        let signable_bytes = ch1.signable().canonical_bytes().unwrap();
        let bad_no_uv = fido.sign_sshsig(POLICY_NAMESPACE, &signable_bytes, FLAG_USER_PRESENT, 3);
        let no_uv_res = engine.handle_commit(CommitPolicyReq {
            challenge_nonce: ch1.nonce.clone(),
            fido_ssh_sig: bad_no_uv,
        });
        assert_eq!(no_uv_res.error.unwrap().code, "FIDO_SIG_REJECTED");

        let good_sig = fido.sign_touch_uv(POLICY_NAMESPACE, &signable_bytes, 4);
        let com1 = engine
            .handle_commit(CommitPolicyReq {
                challenge_nonce: ch1.nonce.clone(),
                fido_ssh_sig: good_sig.clone(),
            })
            .result
            .unwrap();
        assert_eq!(com1.active_generation, 1);
        assert_eq!(com1.state, "ENFORCING");

        // 4. Replay of exact same nonce+sig MUST fail immediately.
        let replay = engine.handle_commit(CommitPolicyReq {
            challenge_nonce: ch1.nonce,
            fido_ssh_sig: good_sig,
        });
        assert_eq!(replay.error.unwrap().code, "CHALLENGE_REPLAYED");

        // 5. Over Noise_IK channel: STATUS + VERIFY + SUSPEND + ROLLBACK to generation 1.
        let host_kp = keypair().unwrap();
        let guest_kp = keypair().unwrap();
        let (c_sock, s_sock) = UnixStream::pair().unwrap();
        let g_priv = guest_kp.private;
        let h_pub = host_kp.public;
        let srv = thread::spawn(move || {
            let ch = Channel::accept(s_sock, &g_priv, &[h_pub]).unwrap();
            engine.serve_channel(ch).unwrap();
            engine
        });
        let mut client =
            Client::new(Channel::connect(c_sock, &host_kp.private, &guest_kp.public).unwrap());
        let st = client.status().unwrap();
        assert_eq!(st.active_generation, 1);
        let vf = client.verify(Some(st.live_mount_digest.clone())).unwrap();
        assert!(vf.verified);
        let vf_bad = client.verify(Some(GENESIS_PREV_SHA256.into())).unwrap();
        assert!(!vf_bad.verified);

        // SUSPEND then ROLLBACK to gen 1.
        let ch_sus = client
            .challenge_policy(ChallengePolicyReq {
                action: PolicyAction::Suspend,
                lineup: None,
                rollback_generation: None,
            })
            .unwrap();
        let sig_sus = fido.sign_touch_uv(
            POLICY_NAMESPACE,
            &ch_sus.signable().canonical_bytes().unwrap(),
            5,
        );
        let sus = client
            .commit_policy(CommitPolicyReq {
                challenge_nonce: ch_sus.nonce,
                fido_ssh_sig: sig_sus,
            })
            .unwrap();
        assert_eq!(sus.state, "SUSPENDED");

        let ch_rb = client
            .challenge_policy(ChallengePolicyReq {
                action: PolicyAction::Rollback,
                lineup: None,
                rollback_generation: Some(1),
            })
            .unwrap();
        let sig_rb = fido.sign_touch_uv(
            POLICY_NAMESPACE,
            &ch_rb.signable().canonical_bytes().unwrap(),
            6,
        );
        let rb = client
            .commit_policy(CommitPolicyReq {
                challenge_nonce: ch_rb.nonce,
                fido_ssh_sig: sig_rb,
            })
            .unwrap();
        assert_eq!(rb.active_generation, 1);
        assert_eq!(rb.live_mount_digest, st.live_mount_digest);
        drop(client);
        let _engine = srv.join().unwrap();

        let _ = fs::remove_dir_all(&base);
    }
}
