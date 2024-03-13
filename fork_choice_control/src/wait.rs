use std::sync::{Arc, Mutex};

use crossbeam_utils::sync::WaitGroup;

// TODO(feature/in-memory-db): Poisoning the extra `Mutex` is unreliable.
//                             Try reimplementing `WaitGroup` and poisoning that.

pub trait Wait: Clone + Default + Send + 'static {
    type Swappable: Clone + Default + Send + Sync;

    fn load_and_clone(swappable: &Self::Swappable) -> Self;

    fn poison(swappable: &Self::Swappable);
}

impl Wait for () {
    type Swappable = ();

    fn load_and_clone((): &Self::Swappable) -> Self {}

    fn poison((): &Self::Swappable) {}
}

impl Wait for WaitGroup {
    type Swappable = Arc<Mutex<Self>>;

    fn load_and_clone(swappable: &Self::Swappable) -> Self {
        swappable
            .lock()
            .expect("Store.wait_group mutex is poisoned")
            .clone()
    }

    fn poison(swappable: &Self::Swappable) {
        std::panic::catch_unwind(|| {
            let _guard = swappable.lock();
            panic!("panicking to poison Store.wait_group mutex");
        })
        .expect_err("closure should intentionally panic to poison mutex");
    }
}
