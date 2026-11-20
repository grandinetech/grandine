CREATE TABLE
IF NOT EXISTS signed_leaves
(
    id INTEGER PRIMARY KEY NOT NULL,
    validator_id INTEGER NOT NULL,
    leaf_index INTEGER NOT NULL,
    signing_root BLOB NOT NULL,
    FOREIGN KEY
(validator_id) REFERENCES validators
(id),
    UNIQUE
(validator_id, leaf_index)
);
