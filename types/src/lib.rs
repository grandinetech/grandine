pub mod cache;
pub mod combined;
pub mod config;
pub mod nonstandard;
pub mod preset;
pub mod redacting_url;
pub mod traits;

pub mod phase0 {
    pub mod beacon_state;
    pub mod consts;
    pub mod containers;
    pub mod primitives;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod altair {
    pub mod beacon_state;
    pub mod consts;
    pub mod containers;
    pub mod primitives;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod bellatrix {
    pub mod beacon_state;
    pub mod containers;
    pub mod primitives;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod capella {
    pub mod beacon_state;
    pub mod consts;
    pub mod containers;
    pub mod primitives;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod deneb {
    pub mod beacon_state;
    pub mod consts;
    pub mod containers;
    pub mod primitives;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod eip7594;

pub mod electra {
    pub mod beacon_state;
    pub mod consts;
    pub mod containers;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

mod unphased {
    pub mod consts;

    #[cfg(test)]
    pub mod spec_tests;
}

mod collections;
