use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use kzg::eip_4844::{load_trusted_setup_rust, load_trusted_setup_string};

fn load_trusted_setup() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    static CONTENTS: &str = include_str!("trusted_setup.txt");

    load_trusted_setup_string(CONTENTS).map_err(|error| anyhow!(error))
}

macro_rules! impl_settings {
    ($backend:ident, $settings_type:ty) => {
        pub fn $backend() -> &'static $settings_type {
            static KZG_SETTINGS: OnceLock<$settings_type> = OnceLock::new();

            KZG_SETTINGS.get_or_init(|| {
                let output = load_trusted_setup().and_then(
                    |(g1_monomial_bytes, g1_lagrange_bytes, g2_monomial_bytes)| {
                        load_trusted_setup_rust(
                            g1_monomial_bytes.as_slice(),
                            g1_lagrange_bytes.as_slice(),
                            g2_monomial_bytes.as_slice(),
                        )
                        .map_err(|err| anyhow!(err))
                    },
                );

                match output {
                    Ok(settings) => settings,
                    Err(error) => panic!("failed to load kzg trusted setup: {error}"),
                }
            })
        }
    };
}

#[cfg(feature = "arkworks")]
impl_settings!(
    arkworks_settings,
    rust_kzg_arkworks5::kzg_proofs::KZGSettings
);

#[cfg(feature = "blst")]
impl_settings!(
    blst_settings,
    rust_kzg_blst::types::kzg_settings::FsKZGSettings
);

#[cfg(feature = "constantine")]
impl_settings!(
    constantine_settings,
    rust_kzg_constantine::types::kzg_settings::CtKZGSettings
);

#[cfg(feature = "zkcrypto")]
impl_settings!(
    zkcrypto_settings,
    rust_kzg_zkcrypto::kzg_proofs::KZGSettings
);

#[cfg(feature = "mcl")]
impl_settings!(
    mcl_settings,
    rust_kzg_mcl::types::kzg_settings::MclKZGSettings
);
