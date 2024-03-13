#![allow(clippy::string_slice)]

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    pub blobs: Vec<String>,
    pub commitments: Vec<String>,
    pub proofs: Vec<String>,
}

impl Input {
    pub fn get_commitments_bytes(&self) -> Vec<Vec<u8>> {
        self.commitments
            .iter()
            .map(|commitment| {
                hex::decode(&commitment[2..]).expect("should decode commitment bytes")
            })
            .collect()
    }

    pub fn get_proofs_bytes(&self) -> Vec<Vec<u8>> {
        self.proofs
            .iter()
            .map(|proof| hex::decode(&proof[2..]).expect("should decode proof bytes"))
            .collect()
    }
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    pub output: Option<bool>,
}
