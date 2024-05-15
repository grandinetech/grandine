use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use c_kzg::KzgSettings;
use kzg::eip_4844::{load_trusted_setup_string, BYTES_PER_G1, BYTES_PER_G2};

pub fn settings() -> &'static KzgSettings {
    static KZG_SETTINGS: OnceLock<KzgSettings> = OnceLock::new();

    KZG_SETTINGS.get_or_init(|| match load_kzg_settings() {
        Ok(settings) => settings,
        Err(error) => {
            panic!("failed to load kzg trusted setup: {error:?}");
        }
    })
}

fn load_kzg_settings() -> Result<KzgSettings> {
    let contents = include_str!("../../kzg_utils/src/trusted_setup.txt");
    let (g1_monomial_bytes, _g1_lagrange_bytes, g2_monomial_bytes) =
        load_trusted_setup_string(contents).map_err(|error| anyhow!(error))?;

    KzgSettings::load_trusted_setup(
        &g1_monomial_bytes
            .chunks_exact(BYTES_PER_G1)
            .map(|chunk| TryInto::<[u8; BYTES_PER_G1]>::try_into(chunk).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?,
        &g2_monomial_bytes
            .chunks_exact(BYTES_PER_G2)
            .map(|chunk| TryInto::<[u8; BYTES_PER_G2]>::try_into(chunk).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?,
    )
    .map_err(|error| anyhow!(error))
}
