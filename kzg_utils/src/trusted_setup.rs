use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use kzg::eip_4844::{load_trusted_setup_rust, load_trusted_setup_string};

use crate::KZGSettings;

pub fn settings() -> &'static KZGSettings {
    static KZG_SETTINGS: OnceLock<KZGSettings> = OnceLock::new();

    KZG_SETTINGS.get_or_init(|| match load_settings() {
        Ok(settings) => settings,
        Err(error) => {
            panic!("failed to load kzg trusted setup: {error:?}");
        }
    })
}

fn load_settings() -> Result<KZGSettings> {
    let contents = include_str!("trusted_setup.txt");

    let (g1_monomial_bytes, g1_lagrange_bytes, g2_monomial_bytes) =
        load_trusted_setup_string(contents).map_err(|error| anyhow!(error))?;

    load_trusted_setup_rust(
        g1_monomial_bytes.as_slice(),
        g1_lagrange_bytes.as_slice(),
        g2_monomial_bytes.as_slice(),
    )
    .map_err(|error| anyhow!(error))
}
