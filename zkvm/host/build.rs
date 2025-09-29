#[cfg(feature = "pico")]
include!("src/backend/pico/build_helper.rs");

fn main() {
    #[cfg(feature = "sp1")]
    sp1_helper::build_program_with_args("../guest/sp1", Default::default());

    #[cfg(feature = "pico")]
    build_program("../guest/pico").expect("building zkvm-guest-pico failed");
}
