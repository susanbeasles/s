//! Typed 5-verb client over `noise::Channel`.

use crate::{
    msg::{
        ChallengePolicyReq, ChallengePolicyResp, CommitPolicyReq, CommitPolicyResp, Envelope,
        IngestBundleReq, IngestBundleResp, Request, StatusReq, StatusResp, VerifyReq, VerifyResp,
        WireError,
    },
    noise::Channel,
};
use serde::de::DeserializeOwned;
use std::{
    fmt,
    io::{self, Read, Write},
};

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    Remote(WireError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "transport: {e}"),
            Self::Remote(w) => write!(f, "{}: {}", w.code, w.message),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub struct Client<S> {
    ch: Channel<S>,
}

impl<S: Read + Write> Client<S> {
    pub fn new(ch: Channel<S>) -> Self {
        Self { ch }
    }

    fn rpc<R: DeserializeOwned>(&mut self, req: &Request) -> Result<R, ClientError> {
        self.ch.send(req)?;
        let env: Envelope<R> = self.ch.recv()?;
        if env.ok {
            env.result.ok_or_else(|| {
                ClientError::Io(io::Error::new(io::ErrorKind::InvalidData, "missing result"))
            })
        } else {
            Err(ClientError::Remote(env.error.unwrap_or(WireError {
                code: "UNKNOWN".into(),
                message: "remote error without detail".into(),
            })))
        }
    }

    pub fn status(&mut self) -> Result<StatusResp, ClientError> {
        self.rpc(&Request::Status(StatusReq {}))
    }

    pub fn verify(&mut self, observed_host_digest: Option<String>) -> Result<VerifyResp, ClientError> {
        self.rpc(&Request::Verify(VerifyReq { observed_host_digest }))
    }

    pub fn ingest_bundle(&mut self, req: IngestBundleReq) -> Result<IngestBundleResp, ClientError> {
        self.rpc(&Request::IngestBundle(req))
    }

    pub fn challenge_policy(
        &mut self,
        req: ChallengePolicyReq,
    ) -> Result<ChallengePolicyResp, ClientError> {
        self.rpc(&Request::ChallengePolicy(req))
    }

    pub fn commit_policy(&mut self, req: CommitPolicyReq) -> Result<CommitPolicyResp, ClientError> {
        self.rpc(&Request::CommitPolicy(req))
    }
}
