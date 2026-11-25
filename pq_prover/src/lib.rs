//! Proofs of many XMSS signatures at once: the spec's `stark` module (`ProveAggregates`,
//! `MergeProofs` and `VerifyAggregates`), behind [`ProverBackend`].
//!
//! Every method may block for seconds. Never call one on an async executor thread.

use std::sync::{Arc, OnceLock};

use thiserror::Error;
use xmss::{MESSAGE_SIZE, XmssPublicKey, XmssSignature};

pub use crate::{in_process::InProcessBackend, reference::ReferenceBackend};

mod in_process;
mod reference;

/// The spec's `XMSSAggregateStatement`: each of `pubkeys` signed `message` at `leaf_index`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Statement {
    pub pubkeys: Vec<XmssPublicKey>,
    pub leaf_index: u64,
    pub message: [u8; MESSAGE_SIZE],
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{statements} statements but {groups} signature groups")]
    GroupCountMismatch { statements: usize, groups: usize },
    #[error("statement {statement} has {pubkeys} public keys but {signatures} signatures")]
    SignatureCountMismatch {
        statement: usize,
        pubkeys: usize,
        signatures: usize,
    },
    #[error("signature {signature} of statement {statement} is invalid")]
    InvalidSignature { statement: usize, signature: usize },
    #[error("child {child} has a proof but no claims, or claims but no proof")]
    ProofDoesNotMatchClaims { child: usize },
    #[error("the proof of child {child} is malformed")]
    MalformedProof { child: usize },
    #[error("the prover proved {actual} claims instead of the {expected} requested")]
    ClaimsMismatch { expected: usize, actual: usize },
    #[error("leanVM: {0}")]
    LeanVm(lean_vm::AggregateError),
}

/// The spec's `stark` module.
pub trait ProverBackend: Send + Sync {
    /// A short name for logs and metrics.
    fn name(&self) -> &'static str;

    /// `ProveAggregates`: `signatures` holds one group per statement, in order, and within a
    /// group one signature per public key, in the order of [`Statement::pubkeys`].
    fn prove(
        &self,
        statements: &[Statement],
        signatures: &[Vec<XmssSignature>],
    ) -> Result<Vec<u8>, Error>;

    /// `MergeProofs`: one proof of the concatenation, in order, of the children's statements.
    /// Children are assumed valid.
    fn merge(&self, children: &[(&[Statement], &[u8])]) -> Result<Vec<u8>, Error>;

    /// `VerifyAggregates`. `Ok(false)` means the proof is invalid. `Err` means the backend could
    /// not decide.
    fn verify(&self, statements: &[Statement], proof: &[u8]) -> Result<bool, Error>;
}

impl<B: ProverBackend + ?Sized> ProverBackend for Arc<B> {
    fn name(&self) -> &'static str {
        (**self).name()
    }

    fn prove(
        &self,
        statements: &[Statement],
        signatures: &[Vec<XmssSignature>],
    ) -> Result<Vec<u8>, Error> {
        (**self).prove(statements, signatures)
    }

    fn merge(&self, children: &[(&[Statement], &[u8])]) -> Result<Vec<u8>, Error> {
        (**self).merge(children)
    }

    fn verify(&self, statements: &[Statement], proof: &[u8]) -> Result<bool, Error> {
        (**self).verify(statements, proof)
    }
}

static AGGREGATE_BACKEND: OnceLock<Box<dyn ProverBackend>> = OnceLock::new();
static BLOCK_BACKEND: OnceLock<Box<dyn ProverBackend>> = OnceLock::new();

/// The backend for gossip aggregates. [`ReferenceBackend`] until one is installed.
pub fn aggregate_backend() -> &'static dyn ProverBackend {
    AGGREGATE_BACKEND
        .get()
        .map_or(&ReferenceBackend, AsRef::as_ref)
}

/// Installs the backend for gossip aggregates. Fails if one is already installed.
pub fn install_aggregate_backend(
    backend: Box<dyn ProverBackend>,
) -> Result<(), Box<dyn ProverBackend>> {
    AGGREGATE_BACKEND.set(backend)
}

/// The backend that verifies the `proof` of blocks during state transitions.
///
/// [`ReferenceBackend`] unless another one was installed with [`install_block_backend`].
#[must_use]
pub fn block_backend() -> &'static dyn ProverBackend {
    BLOCK_BACKEND.get().map_or(&ReferenceBackend, AsRef::as_ref)
}

/// Sets the backend returned by [`block_backend`]. Fails if one was already installed.
pub fn install_block_backend(
    backend: Box<dyn ProverBackend>,
) -> Result<(), Box<dyn ProverBackend>> {
    BLOCK_BACKEND.set(backend)
}

fn check_shape(statements: &[Statement], signatures: &[Vec<XmssSignature>]) -> Result<(), Error> {
    if statements.len() != signatures.len() {
        return Err(Error::GroupCountMismatch {
            statements: statements.len(),
            groups: signatures.len(),
        });
    }

    for (statement_index, (statement, group)) in statements.iter().zip(signatures).enumerate() {
        if statement.pubkeys.len() != group.len() {
            return Err(Error::SignatureCountMismatch {
                statement: statement_index,
                pubkeys: statement.pubkeys.len(),
                signatures: group.len(),
            });
        }
    }

    Ok(())
}
