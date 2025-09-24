fn main() {
    #[cfg(feature = "sp1")]
    sp1_helper::build_program_with_args("../guest/sp1", Default::default());

    #[cfg(feature = "pico")]
    zkvm_pico_helper::build_program("../guest/pico").expect("building zkvm-guest-pico failed");
}
