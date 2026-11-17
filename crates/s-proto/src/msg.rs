//! Exact 5-verb wire contract for `sctl` <-> `s-vsockd` (Section 2.1 of Stone Constitution).
//!
//! Verbs (and ONLY these 5 verbs):
//! 1. `STATUS`
//! 2. `VERIFY`
//! 3. `INGEST_BUNDLE`
//! 4. `CHALLENGE_POLICY`
//! 5. `COMMIT_POLICY`

use crate::{canon, enc};
use serde::{Deserialize, Serialize};

pub const DEFAULT_VSOCK_CID: u32 = 3;
pub const DEFAULT_VSOCK_PORT: u32 = 7001;
pub const CHALLENGE_TTL_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", content = "params", deny_unknown_fields)]
pub enum Request {
    #[serde(rename = "STATUS")]
    Status(StatusReq),
    #[serde(rename = "VERIFY")]
    Verify(VerifyReq),
    #[serde(rename = "INGEST_BUNDLE")]
    IngestBundle(IngestBundleReq),
    #[serde(rename = "CHALLENGE_POLICY")]
    ChallengePolicy(ChallengePolicyReq),
    #[serde(rename = "COMMIT_POLICY")]
    CommitPolicy(CommitPolicyReq),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusReq {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyReq {
    /// Optional host-observed `/s` tree digest computed locally by `sctl` to compare
    /// against the guest ledger tip and active generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_host_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestBundleReq {
    pub bundle_name: String,
    pub version: String,
    /// Inline base64 Mach-O binary (within the 64 KiB frame cap) or staged quarantine name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_b64: Option<String>,
    /// Pre-staged path relative to the guest quarantine dropbox for binaries >48 KiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_rel_path: Option<String>,
    pub expected_sha256: String,
    pub expected_cdhash: String,
    pub expected_team_id: String,
    /// Detached `SSHSIG` (`sk-ssh-ed25519@openssh.com`, namespace `"s-bundle-v1"`) over
    /// the raw binary bytes from a pinned release/hardware key.
    pub detached_sshsig: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    #[serde(rename = "ENFORCE")]
    Enforce,
    #[serde(rename = "SUSPEND")]
    Suspend,
    #[serde(rename = "ROLLBACK")]
    Rollback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lineup {
    pub schema_version: u32,
    pub policy_revision: u64,
    pub description: String,
    pub entries: Vec<LineupEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineupEntry {
    /// Install path under `/s` (e.g. `"bin/rg"` - relative, no `..`, no leading `/`).
    pub install_rel_path: String,
    pub bundle_name: String,
    pub version: String,
    pub sha256: String,
    pub cdhash: String,
    pub team_id: String,
}

impl Lineup {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!("unsupported lineup schema_version {}", self.schema_version));
        }
        if self.policy_revision == 0 {
            return Err("policy_revision must be >= 1".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for e in &self.entries {
            if !is_safe_rel_path(&e.install_rel_path) {
                return Err(format!("unsafe install_rel_path {:?}", e.install_rel_path));
            }
            if !seen.insert(&e.install_rel_path) {
                return Err(format!("duplicate install_rel_path {:?}", e.install_rel_path));
            }
            if !enc::is_hex(&e.sha256, 32) {
                return Err(format!("invalid sha256 for {}", e.install_rel_path));
            }
            if !enc::is_hex(&e.cdhash, 20) {
                return Err(format!("invalid 20-byte cdhash for {}", e.install_rel_path));
            }
            if e.team_id.is_empty() || !e.team_id.bytes().all(|c| c.is_ascii_alphanumeric()) {
                return Err(format!("invalid team_id for {}", e.install_rel_path));
            }
        }
        Ok(())
    }
}

pub fn is_safe_rel_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.ends_with('/')
        && p.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengePolicyReq {
    pub action: PolicyAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineup: Option<Lineup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_generation: Option<u64>,
}

/// Canonical object hashed into `proposedPolicySha256` and committed to the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProposal {
    pub action: PolicyAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineup: Option<Lineup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_generation: Option<u64>,
}

impl PolicyProposal {
    pub fn sha256_hex(&self) -> Result<String, canon::CanonError> {
        Ok(enc::hex(&enc::sha256(&canon::encode(self)?)))
    }
}

/// Exact canonical payload signed by the operator's FIDO2 `sk-ssh-ed25519` hardware key
/// under SSHSIG namespace `"s-policy-v1"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeSignable {
    pub nonce: String,
    #[serde(rename = "prevLedgerSha256")]
    pub prev_ledger_sha256: String,
    #[serde(rename = "proposedPolicySha256")]
    pub proposed_policy_sha256: String,
    pub seq: u64,
}

impl ChallengeSignable {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, canon::CanonError> {
        canon::encode(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitPolicyReq {
    #[serde(rename = "challengeNonce")]
    pub challenge_nonce: String,
    #[serde(rename = "fidoSshSig")]
    pub fido_ssh_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<WireError>,
}

impl<T> Envelope<T> {
    pub fn ok(result: T) -> Self {
        Self { ok: true, result: Some(result), error: None }
    }
    pub fn err(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(WireError { code: code.into(), message: message.into() }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponsePayload {
    Status(StatusResp),
    Verify(VerifyResp),
    IngestBundle(IngestBundleResp),
    ChallengePolicy(ChallengePolicyResp),
    CommitPolicy(CommitPolicyResp),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResp {
    #[serde(rename = "activeGeneration")]
    pub active_generation: u64,
    #[serde(rename = "liveMountDigest")]
    pub live_mount_digest: String,
    #[serde(rename = "policyRevision")]
    pub policy_revision: u64,
    #[serde(rename = "vmUptime")]
    pub vm_uptime: u64,
    #[serde(rename = "ledgerTipSha256")]
    pub ledger_tip_sha256: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyResp {
    pub verified: bool,
    #[serde(rename = "activeGeneration")]
    pub active_generation: u64,
    #[serde(rename = "expectedDigest")]
    pub expected_digest: String,
    #[serde(rename = "liveCloneDigest")]
    pub live_clone_digest: String,
    #[serde(rename = "observedHostDigest", skip_serializing_if = "Option::is_none")]
    pub observed_host_digest: Option<String>,
    #[serde(rename = "ledgerChainLength")]
    pub ledger_chain_length: u64,
    #[serde(rename = "ledgerTipSha256")]
    pub ledger_tip_sha256: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestBundleResp {
    #[serde(rename = "quarantineId")]
    pub quarantine_id: String,
    pub sha256: String,
    pub cdhash: String,
    #[serde(rename = "teamId")]
    pub team_id: String,
    pub identifier: String,
    #[serde(rename = "signerFingerprint")]
    pub signer_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengePolicyResp {
    pub nonce: String,
    pub seq: u64,
    #[serde(rename = "prevLedgerSha256")]
    pub prev_ledger_sha256: String,
    #[serde(rename = "proposedPolicySha256")]
    pub proposed_policy_sha256: String,
    #[serde(rename = "expiresInSecs")]
    pub expires_in_secs: u64,
}

impl ChallengePolicyResp {
    pub fn signable(&self) -> ChallengeSignable {
        ChallengeSignable {
            nonce: self.nonce.clone(),
            prev_ledger_sha256: self.prev_ledger_sha256.clone(),
            proposed_policy_sha256: self.proposed_policy_sha256.clone(),
            seq: self.seq,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitPolicyResp {
    #[serde(rename = "activeGeneration")]
    pub active_generation: u64,
    #[serde(rename = "liveMountDigest")]
    pub live_mount_digest: String,
    #[serde(rename = "policyRevision")]
    pub policy_revision: u64,
    #[serde(rename = "ledgerSeq")]
    pub ledger_seq: u64,
    #[serde(rename = "ledgerRecordSha256")]
    pub ledger_record_sha256: String,
    pub state: String,
}

pub const BUNDLE_SSHSIG_NAMESPACE: &str = "s-bundle-v1";
