//! `Noise_IK_25519_ChaChaPoly_SHA256` over length-prefixed frames (`MAX_FRAME` = 65535).
//!
//! Host `sctl` is Initiator (knows pinned guest static public key; authenticates its own
//! host static key inside the encrypted first flight). Guest `s-vsockd` is Responder
//! and checks the initiator static public key against its pinned host allowlist.

use crate::{canon, frame};
use serde::{de::DeserializeOwned, Serialize};
use snow::{Builder, TransportState};
use std::io::{self, Read, Write};

pub const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
/// Plaintext cap: 65535 frame minus 16-byte ChaCha20-Poly1305 tag.
pub const MAX_PLAINTEXT: usize = frame::MAX_FRAME - 16;

#[derive(Clone)]
pub struct Keypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

pub fn keypair() -> io::Result<Keypair> {
    let kp = Builder::new(PATTERN.parse().unwrap())
        .generate_keypair()
        .map_err(noise_err)?;
    Ok(Keypair {
        private: kp.private.try_into().map_err(|_| bad("key len"))?,
        public: kp.public.try_into().map_err(|_| bad("key len"))?,
    })
}

fn noise_err(e: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("noise: {e}"))
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

pub struct Channel<S> {
    io: S,
    state: TransportState,
    peer_static: [u8; 32],
}

impl<S: Read + Write> Channel<S> {
    pub fn connect(mut io: S, local_priv: &[u8; 32], remote_pub: &[u8; 32]) -> io::Result<Self> {
        let mut hs = Builder::new(PATTERN.parse().unwrap())
            .local_private_key(local_priv)
            .remote_public_key(remote_pub)
            .build_initiator()
            .map_err(noise_err)?;
        let mut buf = vec![0u8; 256];
        let n = hs.write_message(&[], &mut buf).map_err(noise_err)?;
        frame::write(&mut io, &buf[..n])?;
        let reply = frame::read(&mut io)?;
        hs.read_message(&reply, &mut buf).map_err(noise_err)?;
        let state = hs.into_transport_mode().map_err(noise_err)?;
        Ok(Self { io, state, peer_static: *remote_pub })
    }

    pub fn accept(
        mut io: S,
        local_priv: &[u8; 32],
        allowed_initiators: &[[u8; 32]],
    ) -> io::Result<Self> {
        let mut hs = Builder::new(PATTERN.parse().unwrap())
            .local_private_key(local_priv)
            .build_responder()
            .map_err(noise_err)?;
        let mut buf = vec![0u8; 256];
        let msg1 = frame::read(&mut io)?;
        hs.read_message(&msg1, &mut buf).map_err(noise_err)?;
        let peer: [u8; 32] = hs
            .get_remote_static()
            .ok_or_else(|| bad("missing initiator static key"))?
            .try_into()
            .map_err(|_| bad("initiator key len"))?;
        if !allowed_initiators.iter().any(|k| k == &peer) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted initiator static key",
            ));
        }
        let n = hs.write_message(&[], &mut buf).map_err(noise_err)?;
        frame::write(&mut io, &buf[..n])?;
        let state = hs.into_transport_mode().map_err(noise_err)?;
        Ok(Self { io, state, peer_static: peer })
    }

    pub fn peer_static(&self) -> &[u8; 32] {
        &self.peer_static
    }

    pub fn send_bytes(&mut self, plain: &[u8]) -> io::Result<()> {
        if plain.is_empty() || plain.len() > MAX_PLAINTEXT {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "plaintext size out of range"));
        }
        let mut ct = vec![0u8; plain.len() + 16];
        let n = self.state.write_message(plain, &mut ct).map_err(noise_err)?;
        frame::write(&mut self.io, &ct[..n])
    }

    pub fn recv_bytes(&mut self) -> io::Result<Vec<u8>> {
        let ct = frame::read(&mut self.io)?;
        let mut pt = vec![0u8; ct.len()];
        let n = self.state.read_message(&ct, &mut pt).map_err(noise_err)?;
        pt.truncate(n);
        Ok(pt)
    }

    pub fn send<T: Serialize>(&mut self, msg: &T) -> io::Result<()> {
        let bytes = canon::encode(msg).map_err(|e| bad(&e.to_string()))?;
        self.send_bytes(&bytes)
    }

    pub fn recv<T: DeserializeOwned>(&mut self) -> io::Result<T> {
        let bytes = self.recv_bytes()?;
        canon::decode(&bytes).map_err(|e| bad(&e.to_string()))
    }
}
