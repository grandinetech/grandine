#[macro_export]
macro_rules! par_iter {
    ($collection: expr) => {{
        #[cfg(target_os = "zkvm")]
        {
            $collection.iter()
        }

        #[cfg(not(target_os = "zkvm"))]
        {
            use rayon::iter::IntoParallelRefIterator as _;
            $collection.par_iter()
        }
    }};
}

#[macro_export]
macro_rules! into_par_iter {
    ($collection: expr) => {{
        #[cfg(target_os = "zkvm")]
        {
            $collection.into_iter()
        }

        #[cfg(not(target_os = "zkvm"))]
        {
            use rayon::iter::IntoParallelIterator as _;
            $collection.into_par_iter()
        }
    }};
}

pub fn join<T1: Send, T2: Send, F1: FnOnce() -> T1 + Send, F2: FnOnce() -> T2 + Send>(
    f1: F1,
    f2: F2,
) -> (T1, T2) {
    #[cfg(not(target_os = "zkvm"))]
    return rayon::join(f1, f2);

    #[cfg(target_os = "zkvm")]
    return (f1(), f2());
}
