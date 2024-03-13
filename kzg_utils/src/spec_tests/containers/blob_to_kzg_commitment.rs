use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    pub blob: String,
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    pub output: Option<String>,
}
