use std::sync::Mutex;

use crossbeam_utils::sync::WaitGroup;

pub trait Wait: Clone + Default + Send + 'static {
    type Swappable: Default + Send + Sync;

    fn load_and_clone(swappable: &Self::Swappable) -> Self;
}

impl Wait for () {
    type Swappable = ();

    fn load_and_clone((): &Self::Swappable) -> Self {}
}

impl Wait for WaitGroup {
    type Swappable = Mutex<Self>;

    fn load_and_clone(swappable: &Self::Swappable) -> Self {
        swappable
            .lock()
            .expect("Store.wait_group mutex is poisoned")
            .clone()
    }
}
