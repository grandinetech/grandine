CREATE TABLE
IF NOT EXISTS validators
(
    id INTEGER PRIMARY KEY NOT NULL,
    pubkey BLOB NOT NULL,
    fork_version BLOB NOT NULL,
    UNIQUE
(pubkey)
);

CREATE TABLE
IF NOT EXISTS block_proposals
(
    id INTEGER PRIMARY KEY NOT NULL,
    validator_id INTEGER NOT NULL,
    slot INTEGER NOT NULL,
    signing_root BLOB,
    FOREIGN KEY
(validator_id) REFERENCES validators
(id),
    UNIQUE
(validator_id, slot)
);

CREATE TABLE
IF NOT EXISTS attestation_proposals
(
    id INTEGER PRIMARY KEY NOT NULL,
    validator_id INTEGER NOT NULL,
    source_epoch INTEGER NOT NULL,
    target_epoch INTEGER NOT NULL,
    signing_root BLOB,
    FOREIGN KEY
(validator_id) REFERENCES validators
(id),
    UNIQUE
(validator_id, target_epoch)
);

CREATE INDEX
IF NOT EXISTS idx_blocks_slot ON block_proposals
(slot);
CREATE INDEX
IF NOT EXISTS idx_attestations_target_epoch ON attestation_proposals
(target_epoch);

CREATE TABLE
IF NOT EXISTS slashing_protection_meta
(
    id TEXT PRIMARY KEY NOT NULL,
    value BLOB
);
