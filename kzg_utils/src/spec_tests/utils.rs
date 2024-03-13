use anyhow::Result;
use serde::de::DeserializeOwned;

pub fn deserialize<T: DeserializeOwned>(input: &str) -> Result<T> {
    serde_yaml::from_str(input).map_err(Into::into)
}
