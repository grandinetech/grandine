use anyhow::{Result, Context};
use std::{env, process::Command, path::Path};

const GUEST_PROGRAM: &str = "zkvm-guest-pico.elf";

pub fn build_program(path: &str) -> Result<()> {
    let project_dir = env::var_os("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not found")?;
    let guest_dir = Path::new(&project_dir).join(path).canonicalize()?;

    // Tell Cargo to check the pico guest program and rerun
    println!("cargo:rerun-if-changed={}/src/main.rs", guest_dir.display());

    let out_dir = env::var_os("OUT_DIR").context("OUT_DIR not found")?;
    let dest_path = Path::new(&out_dir).join("elf/");
    println!("cargo:warning=zkvm-pico-guest dest_dir: {}", dest_path.display());

    let output = Command::new("cargo")
        .args(["pico", "build", "--elf-name", GUEST_PROGRAM, "--output-directory",
            dest_path.to_str().expect("dest_path failed")
        ])
        .current_dir(guest_dir)
        .status()
        .expect("`cargo pico` couldn't be executed - have you installed `cargo pico`?");

    assert!(
        output.success(),
        "Failed to build pico guest program. Exit code: {:?}", output.code()
    );

    Ok(())
}
