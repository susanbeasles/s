# `s` - Out-of-Host Userland-SIP Plane

Clean-room implementation of Stone Portfolio Repository **#1 (`s`)**: an air-gapped sibling-VM authority plane mounting immutable, hardware-attested binaries onto `/s` on macOS hosts.

## Architecture

| Component | Target | Role |
| --- | --- | --- |
| `crates/s-proto` | Host + Guest (Rust) | `Noise_IK_25519_ChaChaPoly_SHA256` 64 KiB framing, canonical sorted-key 7-bit ASCII JSON, 5-verb wire schema, OpenSSH `SSHSIG` (`sk-ssh-ed25519@openssh.com` UP+UV) verifier, pure-Rust Mach-O 64/Universal `CDHash` verifier |
| `crates/s-ledger` | Host + Guest (Rust) | Append-only hash-chained ledger (`000000001-<sha256>.json`, `prev_record_sha256` over full canonical bytes) + `CDHash` provenance index |
| `crates/s-vsockd` | Sibling Linux VM (Rust) | Guest authority daemon listening on `AF_VSOCK` port `7001`, owning `master.sparseimage`, `ledger.sparseimage`, and staging `live.sparseimage` |
| `crates/sctl` | Host CLI (Rust) | Operator CLI (`status`, `verify`, `ingest`, `policy plan|challenge|commit|apply|rollback`, `ledger verify|inspect`) |
| `Sources/SVMHost` | macOS Host (Swift 6) | `Virtualization.framework` headless VM launcher (3 Virtio block images, `VZVirtioSocketDevice`, zero NICs/VirtioFS), `SecStaticCode` Apple anchor + Team ID verifier, and `rdonly,nobrowse,owners,nodev,nosuid` `/s` mount swapper |

## Five-Verb Wire Surface (`AF_VSOCK` CID 3, Port 7001)

1. `STATUS` -> `{activeGeneration, liveMountDigest, policyRevision, vmUptime, ledgerTipSha256, state}`
2. `VERIFY` -> Compares guest `live.sparseimage` and optional host `/s` digest against the signed ledger tip
3. `INGEST_BUNDLE` -> Verifies SHA-256, Mach-O `CDHash`, `TeamIdentifier`, and detached `sk-ssh-ed25519@openssh.com` `SSHSIG` (`s-bundle-v1`, UP+UV) before writing read-only into `master/quarantine`
4. `CHALLENGE_POLICY` -> Validates `Lineup` (`ENFORCE`), `SUSPEND`, or `ROLLBACK`, returning a single-use 60-second `{nonce, seq, prevLedgerSha256, proposedPolicySha256}`
5. `COMMIT_POLICY` -> Verifies operator FIDO2 `SSHSIG` (`s-policy-v1`, `flags & 0x01 != 0 && flags & 0x04 != 0`), materializes generation, clones read-only to `live.sparseimage`, and appends to `ledger.sparseimage`

## Offline Verification

```bash
./scripts/check
```
