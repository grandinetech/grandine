//! Proofs from a `leanvm-sidecar` process over its Unix socket, through leanVM's own client at the
//! pinned revision, so that the protocol and the verifier the sidecar proves for stay in step with
//! it.
//!
//! An aggregate proof attests `(pubkey, message)` claims, sorted and without duplicates. Leaf
//! indices are not part of them: [`ProverBackend::verify`] cannot check them, and
//! [`ProverBackend::prove`] refuses signatures made at another leaf than their statement's.

use core::time::Duration;
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use lean_xmss::{LeanXmssPublicKey, LeanXmssSignature};
use leanvm_claims::{AggregateClaims, OutputClaims};
use leanvm_sidecar::{Client, SidecarError};
use parking_lot::Mutex;
use xmss::XmssSignature;

use crate::{Error, ProverBackend, Statement, check_shape};

/// The most children one aggregate request takes.
const MAX_CHILDREN_PER_AGGREGATE: usize = 16;

/// `log_inv_rate` of the proofs requested: higher gives smaller proofs that take longer to make.
/// A proof verifies whatever rate it was made at.
const LOG_INV_RATE: usize = 2;

// The sidecar proves one request at a time, so these include waiting behind others.
const PROVE_TIMEOUT: Duration = Duration::from_secs(300);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

/// Proves and verifies through a `leanvm-sidecar` built from the pinned leanVM revision.
///
/// A proof is the sidecar's proof alone: the verifier rebuilds the claims from the statements. The
/// empty proof stands for nothing to prove (the sidecar refuses to prove no claims), and verifies
/// only against statements with no public keys.
///
/// Two connections are kept, one for proving, where requests queue in the sidecar, and one for
/// verifying, which the sidecar answers without waiting for proofs in progress. Each is reopened
/// after a failure.
pub struct SidecarBackend {
    socket: PathBuf,
    prove_connection: Mutex<Option<Client>>,
    verify_connection: Mutex<Option<Client>>,
}

impl SidecarBackend {
    /// Opens both connections, so that a missing or incompatible sidecar is reported now. Returns
    /// the prover the sidecar runs as well.
    pub fn connect(socket: impl Into<PathBuf>) -> Result<(Self, String), Error> {
        let socket = socket.into();
        let prove_connection = open(&socket, PROVE_TIMEOUT)?;
        let verify_connection = open(&socket, VERIFY_TIMEOUT)?;
        let prover = verify_connection.prover().to_owned();

        let backend = Self {
            socket,
            prove_connection: Mutex::new(Some(prove_connection)),
            verify_connection: Mutex::new(Some(verify_connection)),
        };

        Ok((backend, prover))
    }

    // Checks the sidecar proved exactly `expected`.
    fn aggregate(
        &self,
        children: &[(AggregateClaims, Vec<u8>)],
        signatures: &[(LeanXmssPublicKey, lean_xmss::Message, LeanXmssSignature)],
        expected: &AggregateClaims,
    ) -> Result<Vec<u8>, Error> {
        // A proof may still be made after its connection fails, so it is not requested again.
        let (claims, proof) = with_connection(
            &self.socket,
            &self.prove_connection,
            PROVE_TIMEOUT,
            false,
            |client| {
                client.aggregate(
                    children,
                    signatures,
                    &[],
                    &[],
                    OutputClaims::All,
                    LOG_INV_RATE,
                )
            },
        )?;

        if claims != *expected {
            return Err(Error::ClaimsMismatch {
                expected: expected.num_signature_claims(),
                actual: claims.num_signature_claims(),
            });
        }

        Ok(proof)
    }
}

impl ProverBackend for SidecarBackend {
    fn name(&self) -> &'static str {
        "sidecar"
    }

    fn prove(
        &self,
        statements: &[Statement],
        signatures: &[Vec<XmssSignature>],
    ) -> Result<Vec<u8>, Error> {
        check_shape(statements, signatures)?;

        let expected = claims(statements);

        if expected.lean_xmss.is_empty() {
            return Ok(vec![]);
        }

        let mut raw_signatures = vec![];

        for (statement_index, (statement, group)) in statements.iter().zip(signatures).enumerate() {
            for (signature_index, (pubkey, signature)) in
                statement.pubkeys.iter().zip(group).enumerate()
            {
                if u64::from(signature.leaf_index()) != statement.leaf_index {
                    return Err(Error::InvalidSignature {
                        statement: statement_index,
                        signature: signature_index,
                    });
                }

                raw_signatures.push((
                    LeanXmssPublicKey::from_bytes(pubkey.as_array()),
                    statement.message,
                    LeanXmssSignature::from_bytes(signature.as_array()),
                ));
            }
        }

        self.aggregate(&[], &raw_signatures, &expected)
    }

    // Folds the children `MAX_CHILDREN_PER_AGGREGATE` at a time until one proof remains. A single
    // child is returned as it is.
    fn merge(&self, children: &[(&[Statement], &[u8])]) -> Result<Vec<u8>, Error> {
        let mut level = vec![];

        for (index, (statements, proof)) in children.iter().enumerate() {
            let claims = claims(statements);

            match (claims.lean_xmss.is_empty(), proof.is_empty()) {
                (true, true) => {}
                (false, false) => level.push((claims, proof.to_vec())),
                _ => return Err(Error::ProofDoesNotMatchClaims { child: index }),
            }
        }

        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(MAX_CHILDREN_PER_AGGREGATE));

            for chunk in level.chunks(MAX_CHILDREN_PER_AGGREGATE) {
                if let [only] = chunk {
                    next.push(only.clone());
                    continue;
                }

                let expected = union(chunk);
                let proof = self.aggregate(chunk, &[], &expected)?;

                next.push((expected, proof));
            }

            level = next;
        }

        Ok(level.pop().map(|(_, proof)| proof).unwrap_or_default())
    }

    fn verify(&self, statements: &[Statement], proof: &[u8]) -> Result<bool, Error> {
        let claims = claims(statements);

        if claims.lean_xmss.is_empty() || proof.is_empty() {
            return Ok(claims.lean_xmss.is_empty() && proof.is_empty());
        }

        with_connection(
            &self.socket,
            &self.verify_connection,
            VERIFY_TIMEOUT,
            true,
            |client| client.verify(&claims, proof),
        )
    }
}

/// The claims a proof of `statements` attests: every `(pubkey, message)` pair, sorted by its bytes,
/// without duplicates.
fn claims(statements: &[Statement]) -> AggregateClaims {
    let mut pairs = statements
        .iter()
        .flat_map(|statement| {
            statement
                .pubkeys
                .iter()
                .map(|pubkey| (*pubkey.as_array(), statement.message))
        })
        .collect::<Vec<_>>();

    // Tuples of byte arrays order as their concatenations do.
    pairs.sort_unstable();
    pairs.dedup();

    AggregateClaims {
        lean_xmss: pairs
            .into_iter()
            .map(|(pubkey, message)| (LeanXmssPublicKey::from_bytes(&pubkey), message))
            .collect(),
        lean_sphincs: vec![],
        da_commitment: None,
    }
}

fn union(children: &[(AggregateClaims, Vec<u8>)]) -> AggregateClaims {
    let mut lean_xmss = children
        .iter()
        .flat_map(|(claims, _)| claims.lean_xmss.iter().copied())
        .collect::<Vec<_>>();

    lean_xmss.sort_unstable_by_key(|(pubkey, message)| (pubkey.to_bytes(), *message));
    lean_xmss.dedup();

    AggregateClaims {
        lean_xmss,
        lean_sphincs: vec![],
        da_commitment: None,
    }
}

fn open(socket: &Path, timeout: Duration) -> Result<Client, Error> {
    let client = Client::connect(socket).map_err(Error::Sidecar)?;

    client
        .set_timeout(Some(timeout))
        .map_err(|error| Error::Sidecar(SidecarError::Io(error)))?;

    Ok(client)
}

/// Runs `call` on the connection in `slot`, opening it first if needed. A failed connection is
/// dropped unless the sidecar refused the request. With `retry`, a request on a reused connection
/// that turns out to be closed is sent once more on a new one.
fn with_connection<T>(
    socket: &Path,
    slot: &Mutex<Option<Client>>,
    timeout: Duration,
    retry: bool,
    mut call: impl FnMut(&mut Client) -> Result<T, SidecarError>,
) -> Result<T, Error> {
    let mut slot = slot.lock();
    let mut reused = slot.is_some();

    loop {
        let client = match slot.as_mut() {
            Some(client) => client,
            None => slot.insert(open(socket, timeout)?),
        };

        match call(client) {
            Ok(value) => return Ok(value),
            Err(error @ SidecarError::Rejected(..)) => return Err(Error::Sidecar(error)),
            Err(SidecarError::Io(error))
                if retry
                    && reused
                    && !matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
            {
                *slot = None;
                reused = false;
            }
            Err(error) => {
                *slot = None;
                return Err(Error::Sidecar(error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use xmss::XmssPublicKey;

    use super::*;

    fn statement(pubkeys: &[u8], message: u8) -> Statement {
        Statement {
            pubkeys: pubkeys
                .iter()
                .map(|byte| XmssPublicKey::from_array([*byte; 32]))
                .collect(),
            leaf_index: 7,
            message: [message; 32],
        }
    }

    #[test]
    fn claims_are_sorted_pairs_without_duplicates() {
        let statements = [
            statement(&[9, 3], 0xaa),
            statement(&[3, 1], 0x11),
            statement(&[9], 0xaa),
        ];

        let pairs = claims(&statements)
            .lean_xmss
            .into_iter()
            .map(|(pubkey, message)| (pubkey.to_bytes()[0], message[0]))
            .collect::<Vec<_>>();

        assert_eq!(pairs, [(1, 0x11), (3, 0x11), (3, 0xaa), (9, 0xaa)]);

        let reordered = [
            statement(&[9], 0xaa),
            statement(&[1, 3], 0x11),
            statement(&[3, 9], 0xaa),
        ];

        assert_eq!(claims(&reordered), claims(&statements));

        let bytes = claims(&statements).to_bytes();

        assert_eq!(
            AggregateClaims::from_bytes(&bytes),
            Some(claims(&statements))
        );
    }

    #[test]
    fn the_union_of_children_is_sorted() {
        let first = (claims(&[statement(&[5, 2], 1)]), vec![1]);
        let second = (claims(&[statement(&[2, 4], 1)]), vec![2]);

        assert_eq!(union(&[first, second]), claims(&[statement(&[2, 4, 5], 1)]),);
    }

    // Needs a `leanvm-sidecar` built from the pinned revision, listening on the socket in
    // `LEANVM_SIDECAR_SOCKET`. Takes a minute with the stable prover.
    #[test]
    #[ignore = "needs a running leanvm-sidecar"]
    fn proofs_from_a_sidecar_merge_and_verify() -> Result<(), Box<dyn core::error::Error>> {
        let socket = std::env::var("LEANVM_SIDECAR_SOCKET")?;
        let (backend, _) = SidecarBackend::connect(socket)?;

        let keys = [1, 2, 3].map(|byte| xmss::XmssSecretKey::from_seed(&[byte; 32]));
        let leaf_index = 5;

        let mut children = vec![];

        for (message, signers) in [(0x11, &keys[..2]), (0x22, &keys[1..])] {
            let message = [message; 32];

            let statement = Statement {
                pubkeys: signers
                    .iter()
                    .map(xmss::XmssSecretKey::public_key)
                    .collect(),
                leaf_index,
                message,
            };

            let signatures = signers
                .iter()
                .map(|key| key.sign(&message, 5))
                .collect::<Result<Vec<_>, _>>()?;

            let proof = backend.prove(core::slice::from_ref(&statement), &[signatures])?;

            assert!(backend.verify(core::slice::from_ref(&statement), &proof)?);

            children.push((vec![statement], proof));
        }

        let merged = backend.merge(
            &children
                .iter()
                .map(|(statements, proof)| (statements.as_slice(), proof.as_slice()))
                .collect::<Vec<_>>(),
        )?;

        let mut statements = children
            .iter()
            .flat_map(|(statements, _)| statements.clone())
            .collect::<Vec<_>>();

        assert!(backend.verify(&statements, &merged)?);

        statements[0].message = [0x33; 32];

        assert!(!backend.verify(&statements, &merged)?);

        let wrong_leaf = Statement {
            pubkeys: vec![keys[0].public_key()],
            leaf_index: 6,
            message: [0x11; 32],
        };

        let signature = keys[0].sign(&[0x11; 32], 5)?;

        assert!(matches!(
            backend.prove(&[wrong_leaf], &[vec![signature]]),
            Err(Error::InvalidSignature { .. }),
        ));

        Ok(())
    }

    #[test]
    fn a_missing_sidecar_is_reported() {
        let socket = std::env::temp_dir().join("grandine-no-such-leanvm-sidecar.sock");

        assert!(matches!(
            SidecarBackend::connect(socket),
            Err(Error::Sidecar(_)),
        ));
    }
}
