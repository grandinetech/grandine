#![expect(clippy::string_slice)]

use serde::Deserialize;
use types::deneb::primitives::KzgProof;

#[derive(Deserialize)]
pub struct Input {
    pub blob: String,
    pub z: String,
}

impl Input {
    pub fn get_z_bytes(&self) -> Vec<u8> {
        hex::decode(&self.z[2..]).expect("should decode z bytes")
    }

    pub fn get_z_bytes_fixed(&self) -> Result<[u8; 32], Vec<u8>> {
        self.get_z_bytes().try_into()
    }
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    pub output: Option<(String, String)>,
}

impl Test {
    pub fn get_output(&self) -> (KzgProof, [u8; 32]) {
        let proof_str = &self.output.as_ref().expect("test output should exist").0;
        let proof =
            serde_yaml::from_str(proof_str).expect("should deserialize test output to proof");
        let y = self
            .get_output_bytes()
            .expect("test output should exist")
            .1
            .try_into()
            .expect("test output y bytes should fit into 32 byte array");
        (proof, y)
    }

    pub fn get_output_bytes(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        self.output.as_ref().map(|(proof, y)| {
            (
                hex::decode(&proof[2..]).expect("should decode proof bytes"),
                hex::decode(&y[2..]).expect("should decode y bytes"),
            )
        })
    }
}
