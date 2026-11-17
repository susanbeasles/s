//! `s` wire contract shared by `sctl` (host) and `s-vsockd` (guest).
//!
//! Transport: `AF_VSOCK` (guest CID 3, port 7001) or an untrusted host relay socket,
//! carrying `u16`-length frames (max 65535 bytes) of `Noise_IK_25519_ChaChaPoly_SHA256`
//! ciphertext. Plaintext is sorted-key, 7-bit printable ASCII JSON (see [`canon`]).

pub mod canon;
pub mod client;
pub mod enc;
pub mod frame;
pub mod macho;
pub mod msg;
pub mod noise;
pub mod sshsig;
pub mod tree;

#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
