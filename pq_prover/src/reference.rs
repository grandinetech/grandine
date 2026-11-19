use xmss::{SIGNATURE_SIZE, XmssSignature};

use crate::{Error, ProverBackend, Statement, check_shape};

/// The spec's reference stand-in for a recursive STARK: `prove` and `merge` concatenate, and
/// `verify` checks each signature in turn at its statement's leaf.
#[derive(Clone, Copy, Default, Debug)]
pub struct ReferenceBackend;

impl ProverBackend for ReferenceBackend {
    fn name(&self) -> &'static str {
        "reference"
    }

    // Each signature is checked so that a bad one is reported here rather than in a block.
    fn prove(
        &self,
        statements: &[Statement],
        signatures: &[Vec<XmssSignature>],
    ) -> Result<Vec<u8>, Error> {
        check_shape(statements, signatures)?;

        let count = signatures.iter().map(Vec::len).sum::<usize>();
        let mut proof = Vec::with_capacity(count.saturating_mul(SIGNATURE_SIZE));

        for (statement_index, (statement, group)) in statements.iter().zip(signatures).enumerate() {
            for (signature_index, (pubkey, signature)) in
                statement.pubkeys.iter().zip(group).enumerate()
            {
                if !xmss::verify_u64(pubkey, statement.leaf_index, &statement.message, signature) {
                    return Err(Error::InvalidSignature {
                        statement: statement_index,
                        signature: signature_index,
                    });
                }

                proof.extend_from_slice(signature.as_ref());
            }
        }

        Ok(proof)
    }

    fn merge(&self, children: &[(&[Statement], &[u8])]) -> Result<Vec<u8>, Error> {
        Ok(children
            .iter()
            .flat_map(|(_, proof)| *proof)
            .copied()
            .collect())
    }

    fn verify(&self, statements: &[Statement], proof: &[u8]) -> Result<bool, Error> {
        let mut signatures = proof.chunks(SIGNATURE_SIZE);

        for statement in statements {
            for pubkey in &statement.pubkeys {
                let Some(Ok(signature)) = signatures.next().map(XmssSignature::from_slice) else {
                    return Ok(false);
                };

                if !xmss::verify_u64(pubkey, statement.leaf_index, &statement.message, &signature) {
                    return Ok(false);
                }
            }
        }

        Ok(signatures.next().is_none())
    }
}

#[cfg(test)]
mod tests {
    use xmss::{LeafIndex, XmssSecretKey};

    use super::*;

    const LEAF: LeafIndex = (1 << 15) + 3;

    fn signed(
        keys: &[XmssSecretKey],
        leaf_index: LeafIndex,
        message: [u8; 32],
    ) -> Result<(Statement, Vec<XmssSignature>), xmss::Error> {
        let statement = Statement {
            pubkeys: keys.iter().map(XmssSecretKey::public_key).collect(),
            leaf_index: leaf_index.into(),
            message,
        };

        let signatures = keys
            .iter()
            .map(|key| key.sign(&message, leaf_index))
            .collect::<Result<_, _>>()?;

        Ok((statement, signatures))
    }

    #[test]
    fn prove_merge_verify() -> Result<(), Box<dyn core::error::Error>> {
        let backend = ReferenceBackend;
        let keys = (1..=3)
            .map(|byte| XmssSecretKey::from_seed(&[byte; 32]))
            .collect::<Vec<_>>();

        let (first, first_signatures) = signed(&keys[..2], LEAF, [1; 32])?;
        let (second, second_signatures) = signed(&keys, LEAF + 1, [2; 32])?;

        let left_statements = [first];
        let left = backend.prove(&left_statements, &[first_signatures])?;
        let right_statements = [second];
        let right = backend.prove(&right_statements, &[second_signatures])?;

        assert!(backend.verify(&left_statements, &left)?);
        assert!(backend.verify(&right_statements, &right)?);

        let merged = backend.merge(&[(&left_statements, &left), (&right_statements, &right)])?;
        let all_statements = [left_statements.as_slice(), &right_statements].concat();

        assert_eq!(merged.len(), 5 * SIGNATURE_SIZE);
        assert!(backend.verify(&all_statements, &merged)?);

        // Order matters, and so do missing or extra signatures.
        let swapped = [right_statements.as_slice(), &left_statements].concat();

        assert!(!backend.verify(&swapped, &merged)?);
        assert!(!backend.verify(&all_statements, &merged[..merged.len() - 1])?);
        assert!(!backend.verify(&left_statements, &merged)?);

        Ok(())
    }

    #[test]
    fn prove_rejects_wrong_leaf_and_shape() -> Result<(), Box<dyn core::error::Error>> {
        let backend = ReferenceBackend;
        let keys = [XmssSecretKey::from_seed(&[7; 32])];
        let (mut statement, signatures) = signed(&keys, LEAF, [4; 32])?;

        statement.leaf_index += 1;

        assert!(matches!(
            backend.prove(
                core::slice::from_ref(&statement),
                core::slice::from_ref(&signatures),
            ),
            Err(Error::InvalidSignature { .. }),
        ));
        assert!(matches!(
            backend.prove(&[statement], &[signatures.clone(), signatures]),
            Err(Error::GroupCountMismatch { .. }),
        ));

        Ok(())
    }
}
