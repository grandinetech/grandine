//! Proofs made in this process with leanVM at the pinned revision.
//!
//! An aggregate proof attests `(pubkey, message)` claims, sorted and without duplicates. Leaf
//! indices are not part of them: [`ProverBackend::verify`] cannot check them, and
//! [`ProverBackend::prove`] refuses signatures made at another leaf than their statement's.

use lean_vm::{
    AggregateClaims, AggregateProof, MAX_RECURSIONS, OutputClaims,
    lean_xmss::{LeanXmssPublicKey, LeanXmssSignature, Message},
};
use xmss::XmssSignature;

use crate::{Error, ProverBackend, Statement, check_shape};

/// `log_inv_rate` of the proofs made: higher gives smaller proofs that take longer to make. A
/// proof verifies whatever rate it was made at.
const LOG_INV_RATE: usize = 2;

/// Proves and verifies with leanVM in this process. Proofs are made one at a time.
///
/// A proof is leanVM's proof alone: the verifier rebuilds the claims from the statements. The
/// empty proof stands for nothing to prove (leanVM refuses to prove no claims), and verifies only
/// against statements with no public keys.
#[derive(Debug)]
pub struct InProcessBackend {
    _private: (),
}

impl InProcessBackend {
    /// Starts leanVM's prover with `threads` threads (0 for its default, about one per core) and
    /// builds its aggregation program. Blocks for as long as that takes. Call it once per process:
    /// leanVM panics if its prover already runs with another thread count.
    #[must_use]
    pub fn start(threads: usize) -> Self {
        lean_vm::setup(threads);
        Self { _private: () }
    }

    // Checks leanVM proved exactly `expected`.
    fn aggregate(
        children: &[(AggregateClaims, AggregateProof)],
        signatures: Vec<(LeanXmssPublicKey, Message, LeanXmssSignature)>,
        expected: &AggregateClaims,
    ) -> Result<AggregateProof, Error> {
        let (claims, proof) = lean_vm::aggregate(
            children,
            signatures,
            vec![],
            None,
            OutputClaims::All,
            LOG_INV_RATE,
        )
        .map_err(Error::LeanVm)?;

        if claims != *expected {
            return Err(Error::ClaimsMismatch {
                expected: expected.num_signature_claims(),
                actual: claims.num_signature_claims(),
            });
        }

        Ok(proof)
    }
}

impl ProverBackend for InProcessBackend {
    fn name(&self) -> &'static str {
        "leanVM"
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

        Self::aggregate(&[], raw_signatures, &expected).map(|proof| proof.to_bytes())
    }

    // Folds the children `MAX_RECURSIONS` at a time until one proof remains. A single child is
    // returned as it is.
    fn merge(&self, children: &[(&[Statement], &[u8])]) -> Result<Vec<u8>, Error> {
        let mut level = vec![];

        for (index, (statements, proof)) in children.iter().enumerate() {
            let claims = claims(statements);

            match (claims.lean_xmss.is_empty(), proof.is_empty()) {
                (true, true) => {}
                (false, false) => {
                    let proof = AggregateProof::from_bytes(proof)
                        .ok_or(Error::MalformedProof { child: index })?;

                    level.push((claims, proof));
                }
                _ => return Err(Error::ProofDoesNotMatchClaims { child: index }),
            }
        }

        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(MAX_RECURSIONS));

            for chunk in level.chunks(MAX_RECURSIONS) {
                if let [only] = chunk {
                    next.push(only.clone());
                    continue;
                }

                let expected = union(chunk.iter().map(|(claims, _)| claims));
                let proof = Self::aggregate(chunk, vec![], &expected)?;

                next.push((expected, proof));
            }

            level = next;
        }

        Ok(level
            .pop()
            .map(|(_, proof)| proof.to_bytes())
            .unwrap_or_default())
    }

    fn verify(&self, statements: &[Statement], proof: &[u8]) -> Result<bool, Error> {
        let claims = claims(statements);

        if claims.lean_xmss.is_empty() || proof.is_empty() {
            return Ok(claims.lean_xmss.is_empty() && proof.is_empty());
        }

        Ok(AggregateProof::from_bytes(proof).is_some_and(|proof| proof.verify(&claims)))
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

fn union<'claims>(children: impl IntoIterator<Item = &'claims AggregateClaims>) -> AggregateClaims {
    let mut lean_xmss = children
        .into_iter()
        .flat_map(|claims| claims.lean_xmss.iter().copied())
        .collect::<Vec<_>>();

    lean_xmss.sort_unstable_by_key(|(pubkey, message)| (pubkey.to_bytes(), *message));
    lean_xmss.dedup();

    AggregateClaims {
        lean_xmss,
        lean_sphincs: vec![],
        da_commitment: None,
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
        let first = claims(&[statement(&[5, 2], 1)]);
        let second = claims(&[statement(&[2, 4], 1)]);

        assert_eq!(
            union([&first, &second]),
            claims(&[statement(&[2, 4, 5], 1)])
        );
    }

    // Slow outside release builds, and starts a prover on every core.
    #[test]
    #[ignore = "proves for real"]
    fn proofs_merge_and_verify() -> Result<(), Box<dyn core::error::Error>> {
        let backend = InProcessBackend::start(0);

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
}
