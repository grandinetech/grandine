use std::{collections::HashMap, path::Path};

use anyhow::Result;
use bls::PublicKeyBytes;
use educe::Educe;
use fs_err::File;
use helper_functions::{accessors, misc, signing::SignForSingleFork};
use itertools::Itertools as _;
use log::{debug, info, warn};
use rusqlite::{Connection, OptionalExtension, Rows, Transaction, TransactionBehavior};
use ssz::{SszReadDefault as _, SszWrite as _};
use thiserror::Error;
use types::{
    combined::BeaconState,
    config::Config,
    nonstandard::OwnAttestation,
    phase0::primitives::{Epoch, Slot, H256},
    preset::Preset,
};

use crate::interchange_format::{
    InterchangeAttestation, InterchangeBlock, InterchangeData, InterchangeFormat,
};

pub mod interchange_format;

#[allow(clippy::str_to_string)]
mod schema {
    use refinery::embed_migrations;
    embed_migrations!();
}

pub const DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT: u64 = 256;

const DB_PATH: &str = "slashing_protection.sqlite";
const CURRENT_EPOCH_KEY: &str = "current_epoch";

type ValidatorId = i32;

#[derive(Debug, Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum SlashingValidationError {
    #[error(
        "duplicate signed beacon block proposal \
         (proposal: {proposal:?}, matching proposal: {matching_proposal:?})"
    )]
    DuplicateProposal {
        proposal: BlockProposal,
        matching_proposal: BlockProposal,
    },
    #[error(
        "signed beacon block proposal attempts to change the past \
         (proposal: {proposal:?}, min slot: {min_slot:?})"
    )]
    PastProposal {
        proposal: BlockProposal,
        min_slot: Slot,
    },
    #[error("invalid attestation (attestation: {attestation:?})")]
    InvalidAttestation { attestation: AttestationProposal },
    #[error(
        "past epoch proposal (current_epoch: {current_epoch:?}, stored_epoch: {stored_epoch:?})"
    )]
    PastEpochPropoal {
        current_epoch: Epoch,
        stored_epoch: Epoch,
    },
}

#[derive(Debug, Error)]
#[error("validator not found in database (pubkey: {pubkey:?})")]
pub struct DbError {
    pubkey: PublicKeyBytes,
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum SlashingValidationOutcome {
    Accept,
    Ignore,
    Reject(SlashingValidationError),
}

#[cfg(test)]
impl SlashingValidationOutcome {
    const fn is_slashing_violation(&self) -> bool {
        match self {
            Self::Accept | Self::Ignore => false,
            Self::Reject(_) => true,
        }
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub struct BlockProposal {
    pub slot: Slot,
    pub signing_root: Option<H256>,
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub struct AttestationProposal {
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: Option<H256>,
}

#[derive(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct ImportReport {
    validators: ImportRecords<PublicKeyBytes>,
    blocks: ImportRecords<BlockProposal>,
    attestations: ImportRecords<AttestationProposal>,
}

impl ImportReport {
    #[must_use]
    pub fn imported_records(&self) -> usize {
        self.validators.succeeded.len()
            + self.blocks.succeeded.len()
            + self.attestations.succeeded.len()
    }

    #[must_use]
    pub fn failed_records(&self) -> usize {
        self.validators.failed.len() + self.blocks.failed.len() + self.attestations.failed.len()
    }
}

#[derive(Educe)]
#[educe(Default)]
#[cfg_attr(test, derive(Debug))]
pub struct ImportRecords<T> {
    succeeded: Vec<T>,
    failed: Vec<T>,
}

pub struct SlashingProtector {
    connection: Connection,
    history_limit: u64,
}

impl SlashingProtector {
    pub fn persistent(
        store_directory: impl AsRef<Path>,
        history_limit: u64,
        genesis_validators_root: H256,
    ) -> Result<Self> {
        remove_fork_version_from_validators_if_needed(
            &store_directory,
            history_limit,
            genesis_validators_root,
        )?;

        let connection = Self::initialize_persistent_db(store_directory)?;

        Ok(Self {
            connection,
            history_limit,
        })
    }

    pub fn in_memory(history_limit: u64) -> Result<Self> {
        let mut connection = Connection::open_in_memory()?;
        schema::migrations::runner().run(&mut connection)?;
        Self::set_shared_pragma(&connection)?;

        // See the last paragraph of <https://www.sqlite.org/pragma.html#pragma_journal_mode>.
        connection.pragma_update(None, "journal_mode", "MEMORY")?;

        Ok(Self {
            connection,
            history_limit,
        })
    }

    fn initialize_persistent_db(store_directory: impl AsRef<Path>) -> Result<Connection> {
        let store_directory = store_directory.as_ref();

        let mut connection = Self::open_connection_from_path(store_directory, DB_PATH)?;
        schema::migrations::runner().run(&mut connection)?;
        Self::set_shared_pragma(&connection)?;

        connection.pragma_update(None, "journal_mode", "WAL")?;

        Ok(connection)
    }

    fn set_shared_pragma(connection: &Connection) -> Result<()> {
        // Foreign key constraints are not enforced by default as of SQLite 3.41.2.
        // Enable enforcement for correctness.
        // See <https://sqlite.org/pragma.html#pragma_foreign_keys>.
        connection.pragma_update(None, "foreign_keys", true)?;

        // Increase the size of the page cache to over 20 MB to speed up attestation checks.
        // The default is -2000, which means a little over 2 MB.
        // See <https://sqlite.org/pragma.html#pragma_cache_size>.
        connection.pragma_update(None, "cache_size", -20000)?;

        Ok(())
    }

    fn open_connection_from_path(
        store_directory: impl AsRef<Path>,
        db_path: &str,
    ) -> Result<Connection> {
        let path = store_directory.as_ref().join(db_path);

        if !path.try_exists()? {
            fs_err::create_dir_all(store_directory)?;
        }

        Connection::open(path).map_err(Into::into)
    }

    pub fn import_interchange_file(
        &mut self,
        interchange_file_path: impl AsRef<Path>,
        genesis_validators_root: H256,
    ) -> Result<ImportReport> {
        let interchange = InterchangeFormat::load_from_file(interchange_file_path)?;

        debug!("loaded interchange file for import: {interchange:?}");

        interchange.validate(genesis_validators_root)?;

        self.import(interchange)
    }

    // https://ethereum-magicians.org/t/eip-3076-validator-client-interchange-format-slashing-protection/4883/3
    // Decision 1: Duplicate Pubkeys - ACCEPT
    // Decision 2: Importing Slashable Data - ACCEPT_PARTIAL
    // Decision 3: Ordering - UNORDERED
    // Decision 4: Signing Roots - OPTIONAL
    pub fn import(&mut self, interchange: InterchangeFormat) -> Result<ImportReport> {
        let mut report = ImportReport::default();

        for interchange_record in interchange.data {
            let transaction = self.transaction()?;
            let pubkey = interchange_record.pubkey;
            let result = Self::find_or_store_validator(&transaction, pubkey);

            if let Ok(validator_id) = result {
                debug!("Successfully imported validator (pubkey: {pubkey:?})");

                report.validators.succeeded.push(interchange_record.pubkey);

                for signed_block in interchange_record.signed_blocks {
                    let proposal = BlockProposal {
                        slot: signed_block.slot,
                        signing_root: signed_block.signing_root,
                    };

                    match Self::store_proposal(&transaction, validator_id, &proposal) {
                        Ok(()) => {
                            debug!("successfully imported block: {proposal:?}");
                            report.blocks.succeeded.push(proposal);
                        }
                        Err(error) => {
                            debug!("failed to import block (block: {proposal:?}, error: {error})");
                            report.blocks.failed.push(proposal);
                        }
                    }
                }

                for signed_attestation in interchange_record.signed_attestations {
                    let attestation = AttestationProposal {
                        source_epoch: signed_attestation.source_epoch,
                        target_epoch: signed_attestation.target_epoch,
                        signing_root: signed_attestation.signing_root,
                    };

                    match Self::store_attestation(&transaction, validator_id, &attestation) {
                        Ok(()) => {
                            debug!("successfully imported attestation: {attestation:?}");
                            report.attestations.succeeded.push(attestation);
                        }
                        Err(error) => {
                            debug!(
                                "failed to import attestation \
                                 (attestation: {attestation:?}, error: {error})",
                            );
                            report.attestations.failed.push(attestation);
                        }
                    }
                }
            } else {
                debug!("failed to import validator (pubkey: {pubkey:?})");
                report.validators.failed.push(pubkey);
                continue;
            }

            transaction.commit()?;
        }

        Ok(report)
    }

    pub fn export_to_interchange_file(
        &mut self,
        interchange_file_path: impl AsRef<Path>,
        genesis_validators_root: H256,
    ) -> Result<()> {
        let interchange = self.build_interchange_data(genesis_validators_root)?;

        let interchange_file_path = interchange_file_path.as_ref();

        info!("Saving validator information to interchange file: {interchange_file_path:?}");

        let file = File::create(interchange_file_path)?;
        serde_json::to_writer(file, &interchange)?;

        info!("Interchange file saved");

        Ok(())
    }

    pub fn build_interchange_data(
        &mut self,
        genesis_validators_root: H256,
    ) -> Result<InterchangeFormat> {
        let mut builder = InterchangeBuilder::default();

        let transaction = self.transaction()?;

        // export proposed blocks
        let mut stmt = transaction.prepare(
            "SELECT validator_id, pubkey, slot, signing_root
                FROM block_proposals, validators
                WHERE block_proposals.validator_id = validators.id",
        )?;

        let rows = stmt.query([])?;

        builder.append_blocks_from_rows(rows)?;

        // export proposed atttestations
        let mut stmt = transaction.prepare(
            "SELECT validator_id, pubkey, source_epoch, target_epoch, signing_root
                FROM attestation_proposals, validators
                WHERE attestation_proposals.validator_id = validators.id",
        )?;

        let rows = stmt.query([])?;

        builder.append_attestations_from_rows(rows)?;

        Ok(builder.build(genesis_validators_root))
    }

    pub fn build_interchange_data_for_validators(
        &mut self,
        genesis_validators_root: H256,
        validator_public_keys: impl IntoIterator<Item = PublicKeyBytes>,
    ) -> Result<InterchangeFormat> {
        let mut builder = InterchangeBuilder::default();

        let transaction = self.transaction()?;

        for pubkey in validator_public_keys {
            // export proposed blocks
            let mut stmt = transaction.prepare(
                "SELECT validator_id, pubkey, slot, signing_root
                    FROM block_proposals, validators
                    WHERE block_proposals.validator_id = validators.id
                    AND validators.pubkey = ?1",
            )?;

            let rows = stmt.query([pubkey.as_bytes()])?;

            builder.append_blocks_from_rows(rows)?;

            // export proposed atttestations
            let mut stmt = transaction.prepare(
                "SELECT validator_id, pubkey, source_epoch, target_epoch, signing_root
                    FROM attestation_proposals, validators
                    WHERE attestation_proposals.validator_id = validators.id
                    AND validators.pubkey = ?1",
            )?;

            let rows = stmt.query([pubkey.as_bytes()])?;

            builder.append_attestations_from_rows(rows)?;
        }

        Ok(builder.build(genesis_validators_root))
    }

    pub fn register_validators(
        &mut self,
        pubkeys: impl IntoIterator<Item = PublicKeyBytes>,
    ) -> Result<()> {
        let transaction = self.transaction()?;

        for pubkey in pubkeys {
            Self::find_or_store_validator(&transaction, pubkey)?;
        }

        transaction.commit()?;

        Ok(())
    }

    fn find_or_store_validator(
        transaction: &Transaction,
        pubkey: PublicKeyBytes,
    ) -> Result<ValidatorId> {
        if let Some(validator_id) = Self::find_validator_record(transaction, pubkey)? {
            return Ok(validator_id);
        }

        debug!("Saving validator information to slashing protection db (pubkey: {pubkey:?})",);

        transaction.execute(
            "INSERT INTO validators (pubkey) VALUES (?1)",
            [pubkey.as_bytes()],
        )?;

        Self::find_validator_record(transaction, pubkey)?
            .ok_or(DbError { pubkey })
            .map_err(Into::into)
    }

    fn find_validator_record(
        transaction: &Transaction,
        pubkey: PublicKeyBytes,
    ) -> Result<Option<ValidatorId>> {
        transaction
            .query_row(
                "SELECT id FROM validators WHERE pubkey = ?1",
                [pubkey.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn store_attestation(
        transaction: &Transaction,
        validator_id: ValidatorId,
        attestation: &AttestationProposal,
    ) -> Result<()> {
        transaction.execute(
            "INSERT INTO attestation_proposals (
                validator_id, source_epoch, target_epoch, signing_root
            ) VALUES (?1, ?2, ?3, ?4)",
            (
                validator_id,
                attestation.source_epoch,
                attestation.target_epoch,
                attestation.signing_root.as_ref().map(H256::as_bytes),
            ),
        )?;

        Ok(())
    }

    fn store_proposal(
        transaction: &Transaction,
        validator_id: ValidatorId,
        proposal: &BlockProposal,
    ) -> Result<()> {
        transaction.execute(
            "INSERT INTO block_proposals (validator_id, slot, signing_root) VALUES (?1, ?2, ?3)",
            (
                validator_id,
                proposal.slot,
                proposal.signing_root.as_ref().map(H256::as_bytes),
            ),
        )?;

        Ok(())
    }

    fn find_proposal(
        transaction: &Transaction,
        validator_id: ValidatorId,
        proposal: &BlockProposal,
    ) -> Result<Option<BlockProposal>> {
        Ok(transaction
            .query_row(
                "SELECT slot, signing_root
                FROM block_proposals
                WHERE validator_id = ?1
                AND slot = ?2",
                (validator_id, proposal.slot),
                |row| {
                    let (slot, signing_root_bytes) = row.try_into()?;
                    let signing_root = Option::map(signing_root_bytes, H256);
                    Ok(BlockProposal { slot, signing_root })
                },
            )
            .optional()?)
    }

    fn find_min_slot(transaction: &Transaction, validator_id: ValidatorId) -> Result<Option<Slot>> {
        transaction
            .query_row(
                "SELECT MIN(slot)
                FROM block_proposals
                WHERE validator_id = ?1",
                [validator_id],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub fn validate_and_store_proposal(
        &mut self,
        proposal: BlockProposal,
        pubkey: PublicKeyBytes,
        current_epoch: Epoch,
    ) -> Result<SlashingValidationOutcome> {
        if let Some(error) = self.validate_current_epoch(current_epoch)? {
            return Ok(error);
        }

        let transaction = self.transaction()?;
        let validator_id = Self::find_or_store_validator(&transaction, pubkey)?;
        let matching_proposal = Self::find_proposal(&transaction, validator_id, &proposal)?;

        if let Some(matching_proposal) = matching_proposal {
            if matching_proposal.signing_root == proposal.signing_root {
                debug!(
                    "found identical block proposal in database \
                     (matching proposal: {matching_proposal:?})",
                );
                return Ok(SlashingValidationOutcome::Ignore);
            }

            let error = SlashingValidationError::DuplicateProposal {
                proposal,
                matching_proposal,
            };

            return Ok(SlashingValidationOutcome::Reject(error));
        }

        let min_slot = Self::find_min_slot(&transaction, validator_id)?;
        if let Some(min_slot) = min_slot {
            if proposal.slot < min_slot {
                let error = SlashingValidationError::PastProposal { proposal, min_slot };
                return Ok(SlashingValidationOutcome::Reject(error));
            }
        }

        Self::store_proposal(&transaction, validator_id, &proposal)?;

        transaction.commit()?;

        debug!(
            "inserted block proposal into database (validator_id: {}, slot: {}, signing_root: {:?})",
            validator_id, proposal.slot, proposal.signing_root,
        );

        Ok(SlashingValidationOutcome::Accept)
    }

    fn validate_and_store_attestation_proposals(
        &mut self,
        attestations: impl IntoIterator<Item = (AttestationProposal, PublicKeyBytes)>,
    ) -> Result<Vec<Result<SlashingValidationOutcome>>> {
        let transaction = self.transaction()?;
        let result = attestations
            .into_iter()
            .map(|(proposal, pubkey)| {
                Self::validate_attestation_proposal(proposal, pubkey, &transaction)
            })
            .collect_vec();

        transaction.commit()?;

        Ok(result)
    }

    pub fn validate_and_store_own_attestations<'a, P: Preset>(
        &mut self,
        config: &Config,
        state: &BeaconState<P>,
        attestations: impl IntoIterator<Item = (&'a OwnAttestation<P>, PublicKeyBytes)> + Clone,
    ) -> Result<Vec<&'a OwnAttestation<P>>> {
        let current_epoch = accessors::get_current_epoch(state);

        if self.validate_current_epoch(current_epoch)?.is_some() {
            return Ok(vec![]);
        }

        let proposals = attestations
            .clone()
            .into_iter()
            .map(|(own_attestation, pubkey)| {
                let OwnAttestation { attestation, .. } = own_attestation;
                let data = attestation.data;
                let proposal = AttestationProposal {
                    source_epoch: data.source.epoch,
                    target_epoch: data.target.epoch,
                    signing_root: Some(data.signing_root(config, state)),
                };

                (proposal, pubkey)
            });

        let outcomes = self.validate_and_store_attestation_proposals(proposals)?;

        Ok(attestations
            .into_iter()
            .zip(outcomes)
            .filter_map(|((own_attestation, _), outcome_result)| {
                let OwnAttestation { attestation, .. } = own_attestation;

                match outcome_result {
                    Ok(outcome) => match outcome {
                        SlashingValidationOutcome::Accept => Some(own_attestation),
                        SlashingValidationOutcome::Ignore => {
                            warn!(
                                "slashing protector ignored duplicate attestation: {attestation:?}",
                            );

                            None
                        }
                        SlashingValidationOutcome::Reject(error) => {
                            warn!(
                                "slashing protector rejected slashable attestation \
                                 (error: {error}, attestation: {attestation:?})",
                            );

                            None
                        }
                    },
                    Err(error) => {
                        warn!(
                            "slashing protector returned an error while checking proposable \
                             attestation (error: {error}, attestation: {attestation:?})",
                        );
                        None
                    }
                }
            })
            .collect_vec())
    }

    fn validate_attestation_proposal(
        attestation: AttestationProposal,
        pubkey: PublicKeyBytes,
        transaction: &Transaction,
    ) -> Result<SlashingValidationOutcome> {
        let rows_changed = transaction.execute(
            "WITH
                validator AS (SELECT id FROM validators WHERE pubkey = ?1),
                matching AS (SELECT signing_root FROM attestation_proposals, validator WHERE validator_id = validator.id AND
                    (target_epoch = ?3
                        OR (source_epoch < ?2 AND target_epoch > ?3)
                        OR (source_epoch > ?2 AND target_epoch < ?3)
                    ))
            INSERT OR REPLACE INTO attestation_proposals(validator_id, source_epoch, target_epoch, signing_root)
                SELECT id, ?2, ?3, ?4 FROM validator
            WHERE (
                SELECT CASE
                    WHEN (SELECT matching.signing_root IS NULL AND ?4 IS NOT NULL from matching) THEN 1
                    WHEN (SELECT matching.signing_root IS NOT NULL AND matching.signing_root != ?4 from matching) THEN 1
                    WHEN ?2 < (SELECT MIN(source_epoch) FROM attestation_proposals, validator WHERE validator_id = validator.id) THEN 2
                    WHEN ?3 < (SELECT MIN(target_epoch) FROM attestation_proposals, validator WHERE validator_id = validator.id) THEN 3
                    ELSE 0
                END) == 0",
            (
                pubkey.as_bytes(),
                attestation.source_epoch,
                attestation.target_epoch,
                attestation.signing_root.as_ref().map(H256::as_bytes),
            ),
        )?;

        if rows_changed == 0 {
            let error = SlashingValidationError::InvalidAttestation { attestation };
            return Ok(SlashingValidationOutcome::Reject(error));
        }

        Ok(SlashingValidationOutcome::Accept)
    }

    fn validate_current_epoch(
        &mut self,
        current_epoch: Epoch,
    ) -> Result<Option<SlashingValidationOutcome>> {
        if let Some(stored_epoch) = self.stored_current_epoch()? {
            if current_epoch < stored_epoch {
                let error = SlashingValidationError::PastEpochPropoal {
                    current_epoch,
                    stored_epoch,
                };

                warn!("slashing protector rejected current_epoch: {error:?}");

                return Ok(Some(SlashingValidationOutcome::Reject(error)));
            }
        }

        Ok(None)
    }

    fn stored_current_epoch(&mut self) -> Result<Option<Epoch>> {
        let transaction = self.transaction()?;

        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT value FROM slashing_protection_meta WHERE id = ?1",
                [CURRENT_EPOCH_KEY],
                |row| row.get(0),
            )
            .optional()?;

        bytes
            .map(Epoch::from_ssz_default)
            .transpose()
            .map_err(Into::into)
    }

    fn store_current_epoch(&mut self, epoch: Epoch) -> Result<()> {
        let transaction = self.transaction()?;

        transaction.execute(
            "INSERT OR REPLACE INTO slashing_protection_meta (id, value) VALUES (?1, ?2)",
            (CURRENT_EPOCH_KEY, epoch.to_ssz()?),
        )?;

        transaction.commit().map_err(Into::into)
    }

    pub fn prune<P: Preset>(&mut self, current_epoch: Epoch) -> Result<()> {
        match self.stored_current_epoch()? {
            Some(stored_epoch) => {
                if current_epoch > stored_epoch {
                    self.store_current_epoch(current_epoch)?;
                }
            }
            None => self.store_current_epoch(current_epoch)?,
        }

        info!("Pruning slashing protection db, current epoch: {current_epoch}");

        let Some(prune_up_to_epoch) = current_epoch.checked_sub(self.history_limit) else {
            debug!("Skipping slashing protection db pruning for epoch: {current_epoch}");

            return Ok(());
        };

        let prune_up_to_slot = misc::compute_start_slot_at_epoch::<P>(prune_up_to_epoch);

        let mut run = || {
            self.prune_attestations(prune_up_to_epoch)?;
            self.prune_blocks(prune_up_to_slot)
        };

        match run() {
            Ok(()) => info!("Slashing protection db pruning completed for epoch: {current_epoch}"),
            Err(error) => warn!("Error occurred while pruning slashing protection db: {error:?}"),
        }

        Ok(())
    }

    fn prune_attestations(&mut self, epoch: Epoch) -> Result<()> {
        let transaction = self.transaction()?;

        transaction.execute(
            "DELETE FROM attestation_proposals WHERE target_epoch < ?1",
            [epoch],
        )?;

        transaction.commit().map_err(Into::into)
    }

    fn prune_blocks(&mut self, slot: Slot) -> Result<()> {
        let transaction = self.transaction()?;

        transaction.execute("DELETE FROM block_proposals WHERE slot < ?1", [slot])?;

        transaction.commit().map_err(Into::into)
    }

    fn transaction(&mut self) -> Result<Transaction> {
        self.connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .map_err(Into::into)
    }

    #[cfg(test)]
    fn count_attestations_with_target(&mut self, epoch: Epoch) -> Result<usize> {
        self.transaction()?
            .query_row(
                "SELECT count(*) FROM attestation_proposals WHERE target_epoch = ?1",
                [epoch],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    #[cfg(test)]
    fn count_blocks_at_slot(&mut self, slot: Slot) -> Result<usize> {
        self.transaction()?
            .query_row(
                "SELECT count(*) FROM block_proposals WHERE slot = ?1",
                [slot],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }
}

#[derive(Default)]
struct InterchangeBuilder {
    map: HashMap<
        ValidatorId,
        (
            PublicKeyBytes,
            Vec<InterchangeBlock>,
            Vec<InterchangeAttestation>,
        ),
    >,
}

impl InterchangeBuilder {
    fn append_blocks_from_rows(&mut self, mut rows: Rows<'_>) -> Result<()> {
        while let Some(row) = rows.next()? {
            let (validator_id, pubkey_bytes, slot, signing_root_bytes) = row.try_into()?;

            let pubkey = PublicKeyBytes(pubkey_bytes);
            let signing_root = Option::map(signing_root_bytes, H256);

            let interchange_block = InterchangeBlock { slot, signing_root };

            self.map
                .entry(validator_id)
                .or_insert_with(|| (pubkey, vec![], vec![]))
                .1
                .push(interchange_block);
        }

        Ok(())
    }

    fn append_attestations_from_rows(&mut self, mut rows: Rows<'_>) -> Result<()> {
        while let Some(row) = rows.next()? {
            let (validator_id, pubkey_bytes, source_epoch, target_epoch, signing_root_bytes) =
                row.try_into()?;

            let pubkey = PublicKeyBytes(pubkey_bytes);
            let signing_root = Option::map(signing_root_bytes, H256);

            let interchange_attestation = InterchangeAttestation {
                source_epoch,
                target_epoch,
                signing_root,
            };

            self.map
                .entry(validator_id)
                .or_insert_with(|| (pubkey, vec![], vec![]))
                .2
                .push(interchange_attestation);
        }

        Ok(())
    }

    fn build(self, genesis_validators_root: H256) -> InterchangeFormat {
        let data = self
            .map
            .into_values()
            .map(
                |(pubkey, signed_blocks, signed_attestations)| InterchangeData {
                    pubkey,
                    signed_blocks,
                    signed_attestations,
                },
            )
            .collect();

        InterchangeFormat::new(genesis_validators_root, data)
    }
}

fn remove_fork_version_from_validators_if_needed(
    store_directory: impl AsRef<Path>,
    history_limit: u64,
    genesis_validators_root: H256,
) -> Result<()> {
    let mut slashing_protector = SlashingProtector {
        connection: SlashingProtector::open_connection_from_path(&store_directory, DB_PATH)?,
        history_limit,
    };

    let Some(last_migration) = schema::migrations::runner()
        .get_last_applied_migration(&mut slashing_protector.connection)
        .ok()
        .flatten()
    else {
        return Ok(());
    };

    if last_migration.version() >= 3 {
        return Ok(());
    }

    info!("Migrating the slashing protection database. Please wait…");

    let interchange = slashing_protector.build_interchange_data(genesis_validators_root)?;

    let interchange_file_path = store_directory.as_ref().join(format!(
        "interchange-{}.json",
        chrono::Local::now().format("%Y-%m-%dT%H_%M_%S"),
    ));

    info!(
        "Saving validator information to interchange file as a backup: {}",
        interchange_file_path.display(),
    );

    let file = File::create(interchange_file_path)?;
    serde_json::to_writer(file, &interchange)?;

    info!("Interchange file saved");

    fs_err::remove_file(store_directory.as_ref().join(DB_PATH))?;

    let mut slashing_protector = SlashingProtector {
        connection: SlashingProtector::initialize_persistent_db(&store_directory)?,
        history_limit,
    };

    slashing_protector.import(interchange)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use bls::Signature;
    use duplicate::duplicate_item;
    use hex_literal::hex;
    use serde::{de::IgnoredAny, Deserialize};
    use tempfile::{Builder, TempDir};
    use test_case::test_case;
    use test_generator::test_resources;
    use types::{phase0::containers::Attestation, preset::Minimal, traits::BeaconState as _};

    use super::*;

    const PUBKEY: PublicKeyBytes = PublicKeyBytes(hex!(
        "b845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
    ));

    const BLOCK_SIGNING_ROOT: H256 = H256(hex!(
        "4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
    ));

    const ATTESTATION_SIGNING_ROOT: H256 = H256(hex!(
        "587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
    ));

    // Bundle `TempDir` with `SlashingProtector` to prevent the directory from being dropped early.
    // Calls to SQLite fail if the directory containing the database is deleted.
    // `libmdbx` doesn't seem to have the same problem.
    type ConstructorResult = Result<(SlashingProtector, Option<TempDir>)>;
    type Constructor = fn() -> ConstructorResult;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TestData {
        #[allow(dead_code)]
        name: IgnoredAny,
        genesis_validators_root: H256,
        steps: Vec<TestStep>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TestStep {
        should_succeed: bool,
        contains_slashable_data: bool,
        interchange: InterchangeFormat,
        blocks: Vec<TestBlock>,
        attestations: Vec<TestAttestation>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TestBlock {
        #[serde(with = "serde_utils::string_or_native")]
        slot: Slot,
        signing_root: H256,
        pubkey: PublicKeyBytes,
        #[allow(dead_code)]
        should_succeed: bool,
        should_succeed_complete: bool,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TestAttestation {
        #[serde(with = "serde_utils::string_or_native")]
        source_epoch: Epoch,
        #[serde(with = "serde_utils::string_or_native")]
        target_epoch: Epoch,
        signing_root: H256,
        pubkey: PublicKeyBytes,
        #[allow(dead_code)]
        should_succeed: bool,
        should_succeed_complete: bool,
    }

    fn build_own_attestation<P: Preset>(source: Epoch, target: Epoch) -> OwnAttestation<P> {
        let mut attestation = Attestation::default();
        attestation.data.source.epoch = source;
        attestation.data.target.epoch = target;

        OwnAttestation {
            attestation,
            signature: Signature::default(),
            validator_index: 1,
        }
    }

    fn build_persistent_slashing_protector() -> ConstructorResult {
        let temp_store_dir = Builder::new()
            .prefix("slashing_protector")
            .rand_bytes(10)
            .tempdir()?;

        let slashing_protector = SlashingProtector::persistent(
            temp_store_dir.path(),
            DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT,
            H256::default(),
        )?;

        Ok((slashing_protector, Some(temp_store_dir)))
    }

    fn build_in_memory_slashing_protector() -> ConstructorResult {
        Ok((
            SlashingProtector::in_memory(DEFAULT_SLASHING_PROTECTION_HISTORY_LIMIT)?,
            None,
        ))
    }

    // SQLite silently ignores invalid values in most pragma statements.
    // Invalid integers and booleans are converted to 0.
    // Invalid non-boolean keywords leave the pragma set to the current value.
    // Invalid encodings appear to be the only type rejected with an error message.
    #[test_case(build_persistent_slashing_protector)]
    #[test_case(build_in_memory_slashing_protector)]
    fn test_slashing_protection_shared_pragma(constructor: Constructor) -> Result<()> {
        let (slashing_protector, _dir) = constructor()?;

        let foreign_keys = slashing_protector.connection.query_row(
            "SELECT foreign_keys FROM pragma_foreign_keys",
            (),
            |row| row.get::<_, bool>(0),
        )?;

        let cache_size = slashing_protector.connection.query_row(
            "SELECT cache_size FROM pragma_cache_size",
            (),
            |row| row.get::<_, i64>(0),
        )?;

        assert!(foreign_keys);
        assert_eq!(cache_size, -20000);

        Ok(())
    }

    #[test_case(build_persistent_slashing_protector)]
    #[test_case(build_in_memory_slashing_protector)]
    fn test_slashing_protection_on_empty_db_block(constructor: Constructor) -> Result<()> {
        let (mut slashing_protector, _dir) = constructor()?;

        let proposal = BlockProposal {
            slot: 81952,
            signing_root: Some(BLOCK_SIGNING_ROOT),
        };

        let outcome = slashing_protector.validate_and_store_proposal(proposal, PUBKEY, 3007)?;

        assert_eq!(outcome, SlashingValidationOutcome::Accept);

        Ok(())
    }

    #[test_case(build_persistent_slashing_protector)]
    #[test_case(build_in_memory_slashing_protector)]
    fn test_slashing_protection_on_empty_db_attestation(constructor: Constructor) -> Result<()> {
        let (mut slashing_protector, _dir) = constructor()?;

        slashing_protector.register_validators(core::iter::once(PUBKEY))?;

        let attestation = AttestationProposal {
            source_epoch: 2290,
            target_epoch: 3007,
            signing_root: Some(ATTESTATION_SIGNING_ROOT),
        };

        let outcome = SlashingProtector::validate_attestation_proposal(
            attestation,
            PUBKEY,
            &slashing_protector.transaction()?,
        )?;

        assert_eq!(outcome, SlashingValidationOutcome::Accept);

        Ok(())
    }

    #[test_case(build_persistent_slashing_protector)]
    #[test_case(build_in_memory_slashing_protector)]
    fn test_slashing_protection_current_epoch(constructor: Constructor) -> Result<()> {
        let config = Config::minimal();

        let (mut slashing_protector, _dir) = constructor()?;

        assert_eq!(slashing_protector.stored_current_epoch()?, None);
        assert_eq!(slashing_protector.validate_current_epoch(0)?, None);

        slashing_protector.prune::<Minimal>(1024)?;

        assert_eq!(slashing_protector.stored_current_epoch()?, Some(1024));
        assert_eq!(
            slashing_protector.validate_current_epoch(0)?,
            Some(SlashingValidationOutcome::Reject(
                SlashingValidationError::PastEpochPropoal {
                    current_epoch: 0,
                    stored_epoch: 1024,
                },
            )),
        );

        slashing_protector.register_validators(core::iter::once(PUBKEY))?;

        let (mut state, _) = factory::min_genesis_state::<Minimal>(&config)?;

        let attestation = build_own_attestation(2, 32);

        let accepted_attestations = slashing_protector.validate_and_store_own_attestations(
            &config,
            &state,
            core::iter::once((&attestation, PUBKEY)),
        )?;

        assert_eq!(accepted_attestations.len(), 0);
        assert_eq!(
            slashing_protector.validate_current_epoch(32)?,
            Some(SlashingValidationOutcome::Reject(
                SlashingValidationError::PastEpochPropoal {
                    current_epoch: 32,
                    stored_epoch: 1024,
                },
            )),
        );

        *state.slot_mut() = misc::compute_start_slot_at_epoch::<Minimal>(1024);

        let accepted_attestations = slashing_protector.validate_and_store_own_attestations(
            &config,
            &state,
            core::iter::once((&attestation, PUBKEY)),
        )?;

        assert_eq!(slashing_protector.validate_current_epoch(1024)?, None);
        assert_eq!(accepted_attestations.len(), 1);

        let proposal = BlockProposal {
            slot: 32,
            signing_root: Some(BLOCK_SIGNING_ROOT),
        };

        assert_eq!(
            slashing_protector.validate_and_store_proposal(proposal.clone(), PUBKEY, 32)?,
            SlashingValidationOutcome::Reject(SlashingValidationError::PastEpochPropoal {
                current_epoch: 32,
                stored_epoch: 1024,
            }),
        );

        assert_eq!(
            slashing_protector.validate_and_store_proposal(proposal, PUBKEY, 1024)?,
            SlashingValidationOutcome::Accept,
        );

        Ok(())
    }

    #[test_case(build_persistent_slashing_protector)]
    #[test_case(build_in_memory_slashing_protector)]
    fn test_slashing_protection_attestation_proposal_pruning(
        constructor: Constructor,
    ) -> Result<()> {
        let config = Config::minimal();

        let (mut slashing_protector, _dir) = constructor()?;

        slashing_protector.register_validators(core::iter::once(PUBKEY))?;

        let (state, _) = factory::min_genesis_state::<Minimal>(&config)?;

        let attestation_1 = build_own_attestation(2, 32);
        let attestation_2 = build_own_attestation(34, 64);
        let attestation_3 = build_own_attestation(64, 66);

        let accepted_attestations = slashing_protector.validate_and_store_own_attestations(
            &config,
            &state,
            [
                (&attestation_1, PUBKEY),
                (&attestation_2, PUBKEY),
                (&attestation_3, PublicKeyBytes::default()),
            ],
        )?;

        assert_eq!(accepted_attestations.len(), 2);
        assert_eq!(slashing_protector.count_attestations_with_target(32)?, 1);
        assert_eq!(slashing_protector.count_attestations_with_target(64)?, 1);
        assert_eq!(slashing_protector.count_attestations_with_target(66)?, 0);

        slashing_protector.prune::<Minimal>(100)?;

        assert_eq!(slashing_protector.count_attestations_with_target(32)?, 1);
        assert_eq!(slashing_protector.count_attestations_with_target(64)?, 1);

        slashing_protector.prune::<Minimal>(290)?;

        assert_eq!(slashing_protector.count_attestations_with_target(32)?, 0);
        assert_eq!(slashing_protector.count_attestations_with_target(64)?, 1);

        Ok(())
    }

    #[test_case(build_persistent_slashing_protector)]
    #[test_case(build_in_memory_slashing_protector)]
    fn test_slashing_protection_block_proposal_pruning(constructor: Constructor) -> Result<()> {
        let (mut slashing_protector, _dir) = constructor()?;

        let proposal = BlockProposal {
            slot: 32,
            signing_root: Some(BLOCK_SIGNING_ROOT),
        };

        slashing_protector.validate_and_store_proposal(proposal, PUBKEY, 1)?;

        let proposal = BlockProposal {
            slot: 64,
            signing_root: Some(BLOCK_SIGNING_ROOT),
        };

        slashing_protector.validate_and_store_proposal(proposal, PUBKEY, 2)?;

        assert_eq!(slashing_protector.count_blocks_at_slot(32)?, 1);
        assert_eq!(slashing_protector.count_blocks_at_slot(64)?, 1);

        slashing_protector.prune::<Minimal>(100)?;

        assert_eq!(slashing_protector.count_blocks_at_slot(32)?, 1);
        assert_eq!(slashing_protector.count_blocks_at_slot(64)?, 1);

        slashing_protector.prune::<Minimal>(261)?;

        assert_eq!(slashing_protector.count_blocks_at_slot(32)?, 0);
        assert_eq!(slashing_protector.count_blocks_at_slot(64)?, 1);

        Ok(())
    }

    #[duplicate_item(
        glob                                                             function_name                     constructor;
        ["slashing-protection-interchange-tests/tests/generated/*.json"] [run_interchange_test_in_memory]  [build_in_memory_slashing_protector];
        ["slashing-protection-interchange-tests/tests/generated/*.json"] [run_interchange_test_persistent] [build_persistent_slashing_protector];
    )]
    #[test_resources(glob)]
    fn function_name(json_path: &str) {
        let run = || -> Result<()> {
            let (mut slashing_protector, _dir) = constructor()?;

            // read .json test file
            let json_path = Path::new("..").join(json_path);
            let bytes = fs_err::read(json_path)?;
            let data = serde_json::from_slice::<TestData>(bytes.as_slice())?;

            for step in data.steps {
                // validate & import interchange data
                let result = step
                    .interchange
                    .validate(data.genesis_validators_root)
                    .and_then(|()| slashing_protector.import(step.interchange));

                if step.should_succeed {
                    let import_report = result.expect("importing interchange data should succeed");

                    if !step.contains_slashable_data {
                        assert_eq!(import_report.failed_records(), 0);
                    }
                } else {
                    result.expect_err("importing interchange data should fail");
                }

                // process blocks
                for test_block in step.blocks {
                    let proposal = BlockProposal {
                        slot: test_block.slot,
                        signing_root: Some(test_block.signing_root),
                    };

                    let validation_outcome = slashing_protector.validate_and_store_proposal(
                        proposal,
                        test_block.pubkey,
                        0,
                    )?;

                    assert_ne!(
                        test_block.should_succeed_complete,
                        validation_outcome.is_slashing_violation(),
                    );

                    // Test that valid block proposals are persisted in DB
                    if test_block.should_succeed_complete {
                        let count: usize = slashing_protector.transaction()?.query_row(
                            "SELECT count(*) FROM block_proposals \
                             WHERE slot = ?1 \
                             AND validator_id = (select id from validators where pubkey = ?2)",
                            (test_block.slot, test_block.pubkey.as_bytes()),
                            |row| row.get(0),
                        )?;

                        assert_eq!(count, 1);
                    }
                }

                let outcomes = slashing_protector.validate_and_store_attestation_proposals(
                    step.attestations.iter().map(|test_attestation| {
                        let proposal = AttestationProposal {
                            source_epoch: test_attestation.source_epoch,
                            target_epoch: test_attestation.target_epoch,
                            signing_root: Some(test_attestation.signing_root),
                        };

                        (proposal, test_attestation.pubkey)
                    }),
                )?;

                for (test_attestation, outcome) in step.attestations.iter().zip(outcomes) {
                    assert_ne!(
                        test_attestation.should_succeed_complete,
                        outcome?.is_slashing_violation(),
                    );

                    // Test that valid attestation proposals are persisted in DB
                    if test_attestation.should_succeed_complete {
                        let count: usize = slashing_protector.transaction()?.query_row(
                            "SELECT count(*) FROM attestation_proposals \
                             WHERE source_epoch = ?1 \
                             AND target_epoch = ?2 \
                             AND validator_id = (select id from validators where pubkey = ?3)",
                            (
                                test_attestation.source_epoch,
                                test_attestation.target_epoch,
                                test_attestation.pubkey.as_bytes(),
                            ),
                            |row| row.get(0),
                        )?;

                        assert_eq!(count, 1);
                    }
                }
            }

            Ok(())
        };

        run().expect("slashing protection interchange test should succeed")
    }
}
