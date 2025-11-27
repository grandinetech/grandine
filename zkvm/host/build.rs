fn main() {
    #[cfg(feature = "sp1")]
    sp1_helper::build_program_with_args("../guest/sp1", Default::default());

    #[cfg(feature = "ziren")]
    zkm_build::build_program("../guest/ziren");
}
