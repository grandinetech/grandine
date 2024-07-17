use c_kzg::{KzgSettings, ethereum_kzg_settings};

pub fn settings() -> &'static KzgSettings {
    ethereum_kzg_settings(0)
}
