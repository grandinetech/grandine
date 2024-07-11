use std::{
    path::Path,
    sync::OnceLock
};

use anyhow::{anyhow, Result};
use c_kzg::KzgSettings;

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
    let trusted_setup_file = Path::new("kzg_utils/src/trusted_setup.txt");
    println!("{:?}", trusted_setup_file);
    assert!(trusted_setup_file.exists());
    KzgSettings::load_trusted_setup_file(trusted_setup_file, 8).map_err(|error| anyhow!(error))
}
