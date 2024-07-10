use c_kzg::{ethereum_kzg_settings, KzgSettings};

pub fn settings() -> &'static KzgSettings {
    ethereum_kzg_settings(0)
}
