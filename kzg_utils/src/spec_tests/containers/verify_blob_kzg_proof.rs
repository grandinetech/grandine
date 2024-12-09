#![expect(clippy::string_slice)]

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    pub blob: String,
    pub commitment: String,
    pub proof: String,
}

impl Input {
    pub fn get_commitment_bytes(&self) -> Vec<u8> {
        hex::decode(&self.commitment[2..]).expect("should decode commitment bytes")
    }

    pub fn get_proof_bytes(&self) -> Vec<u8> {
        hex::decode(&self.proof[2..]).expect("should decode proof bytes")
    }
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    pub output: Option<bool>,
}
