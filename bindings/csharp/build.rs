use std::{env, fs, path::PathBuf};

use toml::Value;

/// The path where the generated bindings file will be written, relative to the bindings folder.
const PATH_FOR_CSHARP_BINDINGS_FILE: &str = "csharp/Grandine.NethermindPlugin/NativeMethods.g.cs";

fn main() {
    let package_name_of_c_crate = get_package_name_of_c_crate();
    println!(
        "cargo:rerun-if-changed={}",
        path_to_bindings_folder().display()
    );

    let parent = path_to_bindings_folder();
    let path_to_output_file = parent.join(PATH_FOR_CSHARP_BINDINGS_FILE);

    bindgen::Builder::default()
        .header(path_to_c_crate().join("build/grandine.h").to_str().unwrap())
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .generate()
        .expect("bindgen failed")
        .write_to_file("./src/generated.rs")
        .expect("failed to save bindgen output");

    csbindgen::Builder::default()
        .input_bindgen_file("./src/generated.rs")
        .csharp_namespace("Grandine.Native")
        .csharp_dll_name(package_name_of_c_crate)
        .csharp_class_name("NativeMethods")
        .csharp_use_nint_types(false)
        .csharp_class_accessibility("public")
        .csharp_generate_const_filter(|v| v.starts_with("GRANDINE_"))
        .method_filter(|v| v.starts_with("grandine_"))
        .generate_csharp_file(path_to_output_file)
        .expect("csharp bindgen failed to generate bindgen file");
}

fn path_to_bindings_folder() -> PathBuf {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let crate_dir = PathBuf::from(crate_dir);
    // Go up two directories to be at bindings parent directory
    let parent = crate_dir.parent().unwrap().to_path_buf();
    parent
}

fn path_to_c_crate() -> PathBuf {
    let parent = path_to_bindings_folder();
    parent.join("c")
}
fn get_package_name_of_c_crate() -> String {
    let path_to_c_crate = path_to_c_crate();
    let path_to_c_crate_cargo_toml = path_to_c_crate.join("Cargo.toml");

    // Read the Cargo.toml of the other crate
    let cargo_toml =
        fs::read_to_string(path_to_c_crate_cargo_toml).expect("Failed to read Cargo.toml");

    // Parse the Cargo.toml content
    let cargo_toml: Value = cargo_toml.parse().expect("Failed to parse Cargo.toml");

    // Access the library name from the parsed Cargo.toml
    let package_name = cargo_toml["lib"]["name"]
        .as_str()
        .expect("Failed to get package name");

    package_name.to_string()
}
