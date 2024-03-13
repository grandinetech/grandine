CREATE INDEX IF NOT EXISTS idx_attestation_proposals_validator_and_epochs on attestation_proposals (validator_id, source_epoch, target_epoch);
