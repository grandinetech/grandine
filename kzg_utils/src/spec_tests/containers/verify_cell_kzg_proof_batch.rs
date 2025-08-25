use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    pub commitments: Vec<String>,
    pub cell_indices: Vec<u64>,
    pub cells: Vec<String>,
    pub proofs: Vec<String>,
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    pub output: Option<bool>,
}
