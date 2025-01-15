use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    pub blobs: Vec<String>,
    pub commitments: Vec<String>,
    pub proofs: Vec<String>,
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    pub output: Option<bool>,
}
