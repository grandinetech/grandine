#![expect(clippy::string_slice)]

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    pub commitment: String,
    pub z: String,
    pub y: String,
    pub proof: String,
}

impl Input {
    pub fn get_commitment_bytes(&self) -> Vec<u8> {
        hex::decode(&self.commitment[2..]).expect("should decode commitment bytes")
    }

    pub fn get_z_bytes(&self) -> Vec<u8> {
        hex::decode(&self.z[2..]).expect("should decode z bytes")
    }

    pub fn get_z_bytes_fixed(&self) -> [u8; 32] {
        self.get_z_bytes()
            .try_into()
            .expect("test input z bytes should fit into 32 byte array")
    }

    pub fn get_y_bytes(&self) -> Vec<u8> {
        hex::decode(&self.y[2..]).expect("should decode y bytes")
    }

    pub fn get_y_bytes_fixed(&self) -> [u8; 32] {
        self.get_y_bytes()
            .try_into()
            .expect("test input y bytes should fit into 32 byte array")
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
