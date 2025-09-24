use std::{
    env,
    path::Path,
    process::Command,
};

const GUEST_PROGRAM: &str = "zkvm-guest-pico.elf";

pub fn build_program(path: &str) -> Result<(), String> {
    let package_dir = env::var_os("CARGO_MANIFEST_DIR").ok_or("CARGO_MANIFEST_DIR not found".to_string())?;
    let guest_program_dir = Path::new(&package_dir).join(path).canonicalize()
            .map_err(|e| e.to_string())?;
    let grandine_dir = Path::new(&package_dir).join("../../").canonicalize()
            .map_err(|e| e.to_string())?;

    // Tell Cargo to always rebuild guest program when grandine project change
    println!("cargo:rerun-if-changed={}", grandine_dir.display());

    let out_dir = env::var_os("OUT_DIR").ok_or("OUT_DIR not found".to_string())?;
    let dest_path = Path::new(&out_dir).join("elf/");

    let output = Command::new("cargo")
        .args(["pico", "build", "--elf-name", GUEST_PROGRAM, "--output-directory",
            dest_path.to_str().expect("dest_path failed")
        ])
        .current_dir(guest_program_dir)
        .status()
        .expect("`cargo pico` couldn't be executed - have you installed `cargo pico`?");

    assert!(
        output.success(),
        "Failed to build pico guest program. Exit code: {:?}", output.code()
    );

    Ok(())
}
