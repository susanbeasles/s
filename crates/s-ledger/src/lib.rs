//! `ledger.sparseimage` append-only hash-chained ledger (`000000001-<sha256>.json`).
//!
//! Every record commits to `prev_record_sha256` = SHA-256 of the *exact* canonical JSON bytes
//! of the preceding record (`0000...0000` for `seq == 1`), plus the verified FIDO2 `SSHSIG`,
//! policy proposal, active generation, `live_mount_digest`, and `cdhash` provenance list.

use s_proto::{
    canon, enc,
    msg::{ChallengeSignable, PolicyAction, PolicyProposal},
    sshsig::{verify, PinnedSkKey, POLICY_NAMESPACE},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub const GENESIS_PREV_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceArtifact {
    pub install_rel_path: String,
    pub bundle_name: String,
    pub version: String,
    pub sha256: String,
    pub cdhash: String,
    pub team_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRecord {
    pub seq: u64,
    pub timestamp_unix: u64,
    pub prev_record_sha256: String,
    pub challenge_nonce: String,
    pub proposed_policy_sha256: String,
    pub proposal: PolicyProposal,
    pub resulting_generation: u64,
    pub resulting_policy_revision: u64,
    pub live_mount_digest: String,
    pub state: String,
    pub signer_fingerprint_sha256: String,
    pub fido_flags: u8,
    pub fido_counter: u32,
    pub fido_ssh_sig: String,
    pub artifacts: Vec<ProvenanceArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedRecord {
    pub record: LedgerRecord,
    pub record_sha256: String,
    pub path: PathBuf,
}

#[derive(Debug)]
pub enum LedgerError {
    Io(io::Error),
    Canon(String),
    BadFilename(String),
    SequenceGap { expected: u64, got: u64 },
    HashMismatch { seq: u64, filename_sha: String, computed_sha: String },
    BrokenChain { seq: u64, expected_prev: String, got_prev: String },
    PolicyDigestMismatch { seq: u64 },
    InvalidSignature { seq: u64, reason: String },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ledger io: {e}"),
            Self::Canon(e) => write!(f, "ledger canonical json: {e}"),
            Self::BadFilename(n) => write!(f, "invalid ledger record filename: {n}"),
            Self::SequenceGap { expected, got } => {
                write!(f, "ledger sequence gap: expected {expected}, got {got}")
            }
            Self::HashMismatch { seq, filename_sha, computed_sha } => {
                write!(f, "record {seq} filename sha {filename_sha} != content sha {computed_sha}")
            }
            Self::BrokenChain { seq, expected_prev, got_prev } => {
                write!(f, "record {seq} prev_record_sha256 {got_prev} != {expected_prev}")
            }
            Self::PolicyDigestMismatch { seq } => {
                write!(f, "record {seq} proposed_policy_sha256 does not match proposal")
            }
            Self::InvalidSignature { seq, reason } => {
                write!(f, "record {seq} FIDO SSHSIG invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<io::Error> for LedgerError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub struct Ledger {
    dir: PathBuf,
    records: Vec<IndexedRecord>,
    by_cdhash: BTreeMap<String, Vec<u64>>,
}

impl Ledger {
    /// Opens `dir`, creating it if missing, and verifies every existing record's canonical
    /// encoding, filename digest, hash chain, proposal hash, and (if `allowlist` is Some)
    /// embedded FIDO2 `SSHSIG`.
    pub fn open(dir: impl Into<PathBuf>, allowlist: Option<&[PinnedSkKey]>) -> Result<Self, LedgerError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let mut files = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().into_string().map_err(|_| {
                LedgerError::BadFilename("<non-utf8>".into())
            })?;
            if name.starts_with('.') {
                continue;
            }
            files.push((name, entry.path()));
        }
        files.sort_by(|a, b| a.0.cmp(&b.0));

        let mut records = Vec::with_capacity(files.len());
        let mut by_cdhash: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        let mut expected_seq = 1u64;
        let mut expected_prev = GENESIS_PREV_SHA256.to_owned();

        for (name, path) in files {
            let (seq_from_name, sha_from_name) = parse_filename(&name)?;
            if seq_from_name != expected_seq {
                return Err(LedgerError::SequenceGap { expected: expected_seq, got: seq_from_name });
            }
            let bytes = fs::read(&path)?;
            let computed_sha = enc::hex(&enc::sha256(&bytes));
            if computed_sha != sha_from_name {
                return Err(LedgerError::HashMismatch {
                    seq: expected_seq,
                    filename_sha: sha_from_name,
                    computed_sha,
                });
            }
            let rec: LedgerRecord =
                canon::decode(&bytes).map_err(|e| LedgerError::Canon(e.to_string()))?;
            if rec.seq != expected_seq {
                return Err(LedgerError::SequenceGap { expected: expected_seq, got: rec.seq });
            }
            if rec.prev_record_sha256 != expected_prev {
                return Err(LedgerError::BrokenChain {
                    seq: rec.seq,
                    expected_prev,
                    got_prev: rec.prev_record_sha256,
                });
            }
            let prop_sha =
                rec.proposal.sha256_hex().map_err(|e| LedgerError::Canon(e.to_string()))?;
            if prop_sha != rec.proposed_policy_sha256 {
                return Err(LedgerError::PolicyDigestMismatch { seq: rec.seq });
            }
            if let Some(keys) = allowlist {
                let signable = ChallengeSignable {
                    nonce: rec.challenge_nonce.clone(),
                    prev_ledger_sha256: rec.prev_record_sha256.clone(),
                    proposed_policy_sha256: rec.proposed_policy_sha256.clone(),
                    seq: rec.seq,
                };
                let msg = signable
                    .canonical_bytes()
                    .map_err(|e| LedgerError::Canon(e.to_string()))?;
                verify(&rec.fido_ssh_sig, POLICY_NAMESPACE, &msg, keys).map_err(|e| {
                    LedgerError::InvalidSignature { seq: rec.seq, reason: e.to_string() }
                })?;
            }
            for a in &rec.artifacts {
                by_cdhash.entry(a.cdhash.clone()).or_default().push(rec.seq);
            }
            expected_prev = computed_sha.clone();
            expected_seq += 1;
            records.push(IndexedRecord { record: rec, record_sha256: computed_sha, path });
        }

        Ok(Self { dir, records, by_cdhash })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn len(&self) -> u64 {
        self.records.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn next_seq(&self) -> u64 {
        self.len() + 1
    }

    pub fn tip_sha256(&self) -> String {
        self.records
            .last()
            .map(|r| r.record_sha256.clone())
            .unwrap_or_else(|| GENESIS_PREV_SHA256.to_owned())
    }

    pub fn tip(&self) -> Option<&IndexedRecord> {
        self.records.last()
    }

    pub fn records(&self) -> &[IndexedRecord] {
        &self.records
    }

    pub fn lookup_cdhash(&self, cdhash: &str) -> &[u64] {
        self.by_cdhash.get(cdhash).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Finds the most recent ENFORCE record that produced `generation`.
    pub fn find_generation(&self, generation: u64) -> Option<&IndexedRecord> {
        self.records.iter().rev().find(|r| {
            r.record.proposal.action == PolicyAction::Enforce
                && r.record.resulting_generation == generation
        })
    }

    pub fn append(
        &mut self,
        rec: LedgerRecord,
        allowlist: &[PinnedSkKey],
    ) -> Result<IndexedRecord, LedgerError> {
        let expected_seq = self.next_seq();
        if rec.seq != expected_seq {
            return Err(LedgerError::SequenceGap { expected: expected_seq, got: rec.seq });
        }
        let expected_prev = self.tip_sha256();
        if rec.prev_record_sha256 != expected_prev {
            return Err(LedgerError::BrokenChain {
                seq: rec.seq,
                expected_prev,
                got_prev: rec.prev_record_sha256,
            });
        }
        let prop_sha = rec.proposal.sha256_hex().map_err(|e| LedgerError::Canon(e.to_string()))?;
        if prop_sha != rec.proposed_policy_sha256 {
            return Err(LedgerError::PolicyDigestMismatch { seq: rec.seq });
        }
        let signable = ChallengeSignable {
            nonce: rec.challenge_nonce.clone(),
            prev_ledger_sha256: rec.prev_record_sha256.clone(),
            proposed_policy_sha256: rec.proposed_policy_sha256.clone(),
            seq: rec.seq,
        };
        let msg = signable.canonical_bytes().map_err(|e| LedgerError::Canon(e.to_string()))?;
        verify(&rec.fido_ssh_sig, POLICY_NAMESPACE, &msg, allowlist)
            .map_err(|e| LedgerError::InvalidSignature { seq: rec.seq, reason: e.to_string() })?;

        let bytes = canon::encode(&rec).map_err(|e| LedgerError::Canon(e.to_string()))?;
        let sha = enc::hex(&enc::sha256(&bytes));
        let filename = format!("{:09}-{sha}.json", rec.seq);
        let final_path = self.dir.join(&filename);
        let stage_path = self.dir.join(format!(".stage-{filename}"));

        {
            let mut f = fs::OpenOptions::new().create_new(true).write(true).open(&stage_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&stage_path, &final_path)?;
        if let Ok(d) = fs::File::open(&self.dir) {
            let _ = d.sync_all();
        }

        for a in &rec.artifacts {
            self.by_cdhash.entry(a.cdhash.clone()).or_default().push(rec.seq);
        }
        let indexed = IndexedRecord { record: rec, record_sha256: sha, path: final_path };
        self.records.push(indexed.clone());
        Ok(indexed)
    }
}

fn parse_filename(name: &str) -> Result<(u64, String), LedgerError> {
    let stem = name
        .strip_suffix(".json")
        .ok_or_else(|| LedgerError::BadFilename(name.into()))?;
    let (seq_s, sha_s) =
        stem.split_once('-').ok_or_else(|| LedgerError::BadFilename(name.into()))?;
    if seq_s.len() != 9 || !seq_s.bytes().all(|b| b.is_ascii_digit()) || !enc::is_hex(sha_s, 32) {
        return Err(LedgerError::BadFilename(name.into()));
    }
    let seq: u64 = seq_s.parse().map_err(|_| LedgerError::BadFilename(name.into()))?;
    Ok((seq, sha_s.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use s_proto::testkit::MockFidoKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join("ledger-test")
            .join(format!("{tag}-{nanos}"))
    }

    fn make_rec(
        key: &MockFidoKey,
        seq: u64,
        prev: &str,
        nonce: &str,
        gen: u64,
    ) -> LedgerRecord {
        let proposal = PolicyProposal {
            action: PolicyAction::Suspend,
            lineup: None,
            rollback_generation: None,
        };
        let prop_sha = proposal.sha256_hex().unwrap();
        let signable = ChallengeSignable {
            nonce: nonce.into(),
            prev_ledger_sha256: prev.into(),
            proposed_policy_sha256: prop_sha.clone(),
            seq,
        };
        let sig = key.sign_touch_uv(POLICY_NAMESPACE, &signable.canonical_bytes().unwrap(), seq as u32);
        LedgerRecord {
            seq,
            timestamp_unix: 1_700_000_000 + seq,
            prev_record_sha256: prev.into(),
            challenge_nonce: nonce.into(),
            proposed_policy_sha256: prop_sha,
            proposal,
            resulting_generation: gen,
            resulting_policy_revision: seq,
            live_mount_digest: GENESIS_PREV_SHA256.into(),
            state: "SUSPENDED".into(),
            signer_fingerprint_sha256: key.pinned().fingerprint_sha256(),
            fido_flags: 0x05,
            fido_counter: seq as u32,
            fido_ssh_sig: sig,
            artifacts: vec![],
        }
    }

    #[test]
    fn append_reopen_and_tamper_detection() {
        let dir = scratch_dir("chain");
        let key = MockFidoKey::from_seed([3u8; 32], "op@yk");
        let allow = vec![key.pinned()];

        let mut ledger = Ledger::open(&dir, Some(&allow)).unwrap();
        assert_eq!(ledger.tip_sha256(), GENESIS_PREV_SHA256);

        let r1 = ledger.append(make_rec(&key, 1, GENESIS_PREV_SHA256, "n1", 0), &allow).unwrap();
        assert!(r1.path.file_name().unwrap().to_string_lossy().starts_with("000000001-"));
        let r2 = ledger.append(make_rec(&key, 2, &r1.record_sha256, "n2", 0), &allow).unwrap();

        let reopened = Ledger::open(&dir, Some(&allow)).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.tip_sha256(), r2.record_sha256);

        // Corrupt record 1 bytes -> HashMismatch on reopen.
        let mut corrupt = fs::read(&r1.path).unwrap();
        corrupt[10] ^= 1;
        fs::write(&r1.path, corrupt).unwrap();
        assert!(matches!(Ledger::open(&dir, Some(&allow)), Err(LedgerError::HashMismatch { seq: 1, .. })));

        let _ = fs::remove_dir_all(&dir);
    }
}
