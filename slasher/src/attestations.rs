use anyhow::Result;
use database::Database;
use ssz::SszHash as _;
use types::{
    phase0::{
        containers::{AttesterSlashing, IndexedAttestation},
        primitives::{Epoch, ValidatorIndex},
    },
    preset::Preset,
};

use crate::{
    attestation_votes::AttestationVotes, indexed_attestations::IndexedAttestations,
    slasher_config::SlasherConfig, status::AttesterSlashingReason,
    status::ExplainedAttesterSlashing, targets::Targets,
};

#[expect(clippy::struct_field_names)]
pub struct Attestations<P: Preset> {
    config: SlasherConfig,
    attestation_votes: AttestationVotes,
    indexed_attestations: IndexedAttestations<P>,
    targets: Targets<P>,
}

impl<P: Preset> Attestations<P> {
    pub const fn new(
        config: SlasherConfig,
        votes_db: Database,
        attestations_db: Database,
        min_targets_db: Database,
        max_targets_db: Database,
    ) -> Self {
        Self {
            config,
            attestation_votes: AttestationVotes::new(votes_db),
            indexed_attestations: IndexedAttestations::new(attestations_db),
            targets: Targets::new(min_targets_db, max_targets_db),
        }
    }

    pub fn update(
        &self,
        validator_index: ValidatorIndex,
        attestation: &IndexedAttestation<P>,
        current_epoch: Epoch,
    ) -> Result<()> {
        self.attestation_votes.insert(
            validator_index,
            attestation.data.target.epoch,
            attestation.data,
        )?;

        self.indexed_attestations
            .insert(attestation.data.target.epoch, attestation)?;

        self.targets
            .update(validator_index, attestation, current_epoch)?;

        Ok(())
    }

    pub fn find_slashing(
        &self,
        validator_index: ValidatorIndex,
        attestation: &IndexedAttestation<P>,
    ) -> Result<Option<ExplainedAttesterSlashing<P>>> {
        if let Some(slashing_status) = self.check_double_vote(validator_index, attestation)? {
            return Ok(Some(slashing_status));
        }

        if let Some(target_epoch) = self
            .targets
            .check_for_surrounding_entry(validator_index, attestation)?
        {
            if let Some(existing) = self.find_indexed_attestation(validator_index, target_epoch)? {
                let slashing = AttesterSlashing {
                    attestation_1: existing,
                    attestation_2: attestation.clone(),
                };

                return Ok(Some(ExplainedAttesterSlashing {
                    slashing,
                    reason: AttesterSlashingReason::Surrounding,
                }));
            }
        }

        if let Some(target_epoch) = self
            .targets
            .check_for_surrounded_entry(validator_index, attestation)?
        {
            if let Some(existing) = self.find_indexed_attestation(validator_index, target_epoch)? {
                let slashing = AttesterSlashing {
                    attestation_1: existing,
                    attestation_2: attestation.clone(),
                };

                return Ok(Some(ExplainedAttesterSlashing {
                    slashing,
                    reason: AttesterSlashingReason::Surrounded,
                }));
            }
        }

        Ok(None)
    }

    pub fn cleanup(&self, current_epoch: Epoch) -> Result<()> {
        let epochs_to_keep = self.config.slashing_history_limit;

        if epochs_to_keep >= current_epoch {
            return Ok(());
        }

        self.attestation_votes
            .cleanup(current_epoch, epochs_to_keep)?;
        self.indexed_attestations
            .cleanup(current_epoch, epochs_to_keep)?;

        Ok(())
    }

    fn find_indexed_attestation(
        &self,
        validator_index: ValidatorIndex,
        target_epoch: Epoch,
    ) -> Result<Option<IndexedAttestation<P>>> {
        if let Some(existing_root) = self.attestation_votes.find(validator_index, target_epoch)? {
            return self.indexed_attestations.find(existing_root, target_epoch);
        }

        Ok(None)
    }

    fn check_double_vote(
        &self,
        validator_index: ValidatorIndex,
        attestation: &IndexedAttestation<P>,
    ) -> Result<Option<ExplainedAttesterSlashing<P>>> {
        let target_epoch = attestation.data.target.epoch;

        if let Some(existing_root) = self.attestation_votes.find(validator_index, target_epoch)? {
            if existing_root != attestation.data.hash_tree_root() {
                if let Some(existing) = self
                    .indexed_attestations
                    .find(existing_root, target_epoch)?
                {
                    let slashing = AttesterSlashing {
                        attestation_1: existing,
                        attestation_2: attestation.clone(),
                    };

                    return Ok(Some(ExplainedAttesterSlashing {
                        slashing,
                        reason: AttesterSlashingReason::DoubleVote,
                    }));
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use types::preset::Mainnet;
    use unwrap_none::UnwrapNone as _;

    use crate::targets::TARGETS_LENGTH;

    use super::*;

    fn build_attestation<P: Preset>(source: Epoch, target: Epoch) -> IndexedAttestation<P> {
        let mut indexed_attestation = IndexedAttestation::default();
        indexed_attestation.data.source.epoch = source;
        indexed_attestation.data.target.epoch = target;
        indexed_attestation
    }

    fn build_attestations<P: Preset>() -> Attestations<P> {
        let config = SlasherConfig {
            slashing_history_limit: 3,
        };

        Attestations::new(
            config,
            Database::in_memory(),
            Database::in_memory(),
            Database::in_memory(),
            Database::in_memory(),
        )
    }

    #[test]
    fn slasher_attestation_votes_cleanup_test() -> Result<()> {
        let current_epoch = 11;
        let attestations = build_attestations::<Mainnet>();
        let data = [(2, 5), (3, 7), (10, 11), (8, 10), (12, 14)];

        for (source_epoch, target_epoch) in data {
            let indexed_attestation = build_attestation(source_epoch, target_epoch);
            attestations.update(1, &indexed_attestation, current_epoch)?;

            assert!(attestations
                .attestation_votes
                .find(1, target_epoch)?
                .is_some());
        }

        attestations.cleanup(current_epoch)?;

        attestations.attestation_votes.find(1, 5)?.unwrap_none();
        attestations.attestation_votes.find(1, 7)?.unwrap_none();

        assert!(attestations.attestation_votes.find(1, 10)?.is_some());
        assert!(attestations.attestation_votes.find(1, 11)?.is_some());
        assert!(attestations.attestation_votes.find(1, 14)?.is_some());

        Ok(())
    }

    #[test]
    fn slasher_indexed_attestations_cleanup_test() -> Result<()> {
        let current_epoch = 11;
        let attestations = build_attestations::<Mainnet>();

        let build_and_update = |source_epoch, target_epoch| -> Result<_> {
            let attestation = build_attestation(source_epoch, target_epoch);

            attestations.update(1, &attestation, current_epoch)?;

            assert!(attestations
                .indexed_attestations
                .find(attestation.data.hash_tree_root(), target_epoch)?
                .is_some());

            Ok(attestation)
        };

        let at_1 = build_and_update(2, 5)?;
        let at_2 = build_and_update(3, 7)?;
        let at_3 = build_and_update(10, 11)?;
        let at_4 = build_and_update(8, 10)?;
        let at_5 = build_and_update(12, 14)?;

        attestations.cleanup(current_epoch)?;

        attestations
            .indexed_attestations
            .find(at_1.data.hash_tree_root(), 5)?
            .unwrap_none();

        attestations
            .indexed_attestations
            .find(at_2.data.hash_tree_root(), 7)?
            .unwrap_none();

        assert!(attestations
            .indexed_attestations
            .find(at_3.data.hash_tree_root(), 11)?
            .is_some());

        assert!(attestations
            .indexed_attestations
            .find(at_4.data.hash_tree_root(), 10)?
            .is_some());

        assert!(attestations
            .indexed_attestations
            .find(at_5.data.hash_tree_root(), 14)?
            .is_some());

        Ok(())
    }

    //       S          T
    //                    S  T
    //   S     T
    // 1 2 3 4 5 6 7 8 9 10 11
    #[test]
    fn slasher_attestation_storage_test() -> Result<()> {
        let attestations = build_attestations::<Mainnet>();

        // valid attestation data
        let at_1 = build_attestation(2, 5);
        let at_2 = build_attestation(10, 11);
        let at_3 = build_attestation(4, 9);

        // slashing violations
        let at_4 = build_attestation(1, 6);
        let at_5 = build_attestation(1, 5);
        let at_6 = build_attestation(7, 8);

        // violations are not slashable on empty db
        attestations.find_slashing(1, &at_1)?.unwrap_none();
        attestations.find_slashing(1, &at_2)?.unwrap_none();
        attestations.find_slashing(1, &at_3)?.unwrap_none();
        attestations.find_slashing(1, &at_4)?.unwrap_none();
        attestations.find_slashing(1, &at_5)?.unwrap_none();
        attestations.find_slashing(1, &at_6)?.unwrap_none();

        attestations.update(1, &at_1, 14)?;
        attestations.update(1, &at_2, 14)?;
        attestations.update(1, &at_3, 14)?;

        // surrounds at_1
        let explained_slashing = attestations
            .find_slashing(1, &at_4)?
            .expect("Surrounding slashing must be found");

        assert_eq!(
            explained_slashing.reason,
            AttesterSlashingReason::Surrounding,
        );
        assert_eq!(explained_slashing.slashing.attestation_1, at_1);
        assert_eq!(explained_slashing.slashing.attestation_2, at_4);

        // double vote
        let explained_slashing = attestations
            .find_slashing(1, &at_5)?
            .expect("Double vote violation should be found");

        assert_eq!(
            explained_slashing.reason,
            AttesterSlashingReason::DoubleVote,
        );
        assert_eq!(explained_slashing.slashing.attestation_1, at_1);
        assert_eq!(explained_slashing.slashing.attestation_2, at_5);

        // is surrounded by
        let explained_slashing = attestations
            .find_slashing(1, &at_6)?
            .expect("Surrounded attestation violation should be found");

        assert_eq!(
            explained_slashing.reason,
            AttesterSlashingReason::Surrounded,
        );
        assert_eq!(explained_slashing.slashing.attestation_1, at_3);
        assert_eq!(explained_slashing.slashing.attestation_2, at_6);

        Ok(())
    }

    #[test]
    fn slasher_out_of_bounds_attestation_storage_test() -> Result<()> {
        let attestations = build_attestations::<Mainnet>();
        let length = TARGETS_LENGTH;

        // valid attestation data
        let at_1 = build_attestation(length - 3, length);
        let at_2 = build_attestation(length + 5, length + 6);
        let at_3 = build_attestation(length - 1, length + 4);

        // slashing violations
        let at_4 = build_attestation(length - 4, length + 1);
        let at_5 = build_attestation(length - 4, length);
        let at_6 = build_attestation(length + 2, length + 3);

        // violations are not slashable on empty db
        attestations.find_slashing(1, &at_1)?.unwrap_none();
        attestations.find_slashing(1, &at_2)?.unwrap_none();
        attestations.find_slashing(1, &at_3)?.unwrap_none();
        attestations.find_slashing(1, &at_4)?.unwrap_none();
        attestations.find_slashing(1, &at_5)?.unwrap_none();
        attestations.find_slashing(1, &at_6)?.unwrap_none();

        let current_epoch = length + 7;

        // build db
        attestations.update(1, &at_1, current_epoch)?;
        attestations.update(1, &at_2, current_epoch)?;
        attestations.update(1, &at_3, current_epoch)?;

        // surrounds at_1
        let explained_slashing = attestations
            .find_slashing(1, &at_4)?
            .expect("Surrounding slashing must be found");

        assert_eq!(
            explained_slashing.reason,
            AttesterSlashingReason::Surrounding,
        );
        assert_eq!(explained_slashing.slashing.attestation_1, at_1);
        assert_eq!(explained_slashing.slashing.attestation_2, at_4);

        // double vote
        let explained_slashing = attestations
            .find_slashing(1, &at_5)?
            .expect("Double vote violation should be found");

        assert_eq!(
            explained_slashing.reason,
            AttesterSlashingReason::DoubleVote,
        );
        assert_eq!(explained_slashing.slashing.attestation_1, at_1);
        assert_eq!(explained_slashing.slashing.attestation_2, at_5);

        // is surrounded by
        let explained_slashing = attestations
            .find_slashing(1, &at_6)?
            .expect("Surrounded attestation violation should be found");

        assert_eq!(
            explained_slashing.reason,
            AttesterSlashingReason::Surrounded,
        );
        assert_eq!(explained_slashing.slashing.attestation_1, at_3);
        assert_eq!(explained_slashing.slashing.attestation_2, at_6);

        Ok(())
    }
}
