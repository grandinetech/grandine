pub mod cache;
pub mod combined;
pub mod config;
pub mod nonstandard;
pub mod preset;
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

<<<<<<< HEAD
pub mod electra {
    pub mod beacon_state;
    pub mod consts;
    pub mod containers;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

=======
>>>>>>> d3cead8 (WIP: move eip7594 types to types crate, add ssz_static tests for containers)
mod unphased {
    pub mod consts;

    #[cfg(test)]
    pub mod spec_tests;
}

mod collections;
