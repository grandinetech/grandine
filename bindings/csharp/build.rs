use std::{
    env,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
};

use clap::{Arg, CommandFactory, builder::ValueParser};
use convert_case::{Case, Casing};
use runtime::grandine_args::GrandineArgs;
use toml::Value;

fn main() {
    let package_name_of_c_crate = get_package_name_of_c_crate();
    println!(
        "cargo:rerun-if-changed={}",
        path_to_bindings_folder().display()
    );

    let parent = path_to_generated_csharp_artifacts_folder();
    fs::create_dir_all(&parent).unwrap();

    let path_to_output_file = parent.join("NativeMethods.g.cs");
    let path_to_output_interface_file = parent.join("IGrandineConfig.cs");
    let path_to_output_impl_file = parent.join("GrandineConfig.cs");

    File::create(path_to_output_interface_file)
        .and_then(|mut output| generate_csharp_config_interface(&mut output))
        .expect("failed to generate IGrandineConfig.cs file");

    File::create(path_to_output_impl_file)
        .and_then(|mut output| generate_csharp_config_implementation(&mut output))
        .expect("failed to generate GrandineConfig.cs file");

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

fn filter_argument(arg: &Arg) -> bool {
    let id = arg.get_id();

    id != "back_sync" && id != "eth1_rpc_urls" && id != "jwt_secret"
}

fn generate_csharp_config_implementation(mut buffer: impl Write) -> Result<(), io::Error> {
    let command = GrandineArgs::command();

    writeln!(buffer, "namespace Grandine.NethermindPlugin;")?;
    writeln!(buffer, "")?;
    writeln!(buffer, "public class GrandineConfig : IGrandineConfig")?;
    writeln!(buffer, "{{")?;
    writeln!(buffer, "    public bool Enabled {{ get; set; }} = true;")?;

    for arg in command.get_arguments().filter(|arg| filter_argument(arg)) {
        let arg_name = arg
            .get_long()
            .expect(format!("Argument {} don't have long form", arg.get_id()).as_str());

        let field_name = arg_name.to_case(Case::Pascal);
        let field_type = if arg.get_value_parser().type_id() == ValueParser::bool().type_id() {
            "bool"
        } else {
            "string?"
        };

        writeln!(buffer, "")?;
        writeln!(
            buffer,
            "    public {field_type} {field_name} {{ get; set; }}"
        )?;
    }

    write!(buffer, "}}")?;

    Ok(())
}

fn generate_csharp_config_interface(mut buffer: impl Write) -> Result<(), io::Error> {
    let command = GrandineArgs::command();

    let undocumented_arguments = command
        .get_arguments()
        .filter(|arg| filter_argument(arg) && arg.get_help().is_none())
        .map(|arg| arg.get_id().as_str())
        .collect::<Vec<_>>();

    if !undocumented_arguments.is_empty() {
        println!(
            "cargo::error=Argument(s) {} not documented",
            undocumented_arguments.join(", ")
        );

        panic!("undocumented arguments found");
    }

    writeln!(buffer, "namespace Grandine.NethermindPlugin;")?;
    writeln!(buffer, "")?;
    writeln!(buffer, "using System;")?;
    writeln!(buffer, "using Nethermind.Config;")?;
    writeln!(buffer, "")?;
    writeln!(buffer, "public interface IGrandineConfig : IConfig")?;
    writeln!(buffer, "{{")?;
    writeln!(
        buffer,
        r#"    [ConfigItem(Description = "Whether to enable embedded grandine CL", DefaultValue = "false")]"#
    )?;
    writeln!(buffer, "    public bool Enabled {{ get; set; }}")?;

    for arg in command.get_arguments().filter(|arg| filter_argument(arg)) {
        let description = arg.get_help().expect("checked before").to_string();

        let arg_name = arg
            .get_long()
            .expect(format!("Argument {} don't have long form", arg.get_id()).as_str());

        let default_value = {
            let all_values = arg.get_default_values();

            if all_values.is_empty() {
                None
            } else {
                let delimiter = arg.get_value_delimiter().unwrap_or(',').to_string();
                let values = all_values
                    .iter()
                    .map(|v| {
                        v.to_str()
                            .expect("Default value is not valid unicode.")
                            .to_string()
                    })
                    .collect::<Vec<_>>();
                Some(values.join(&delimiter))
            }
        };

        let field_name = arg_name.to_case(Case::Pascal);
        let field_type = if arg.get_value_parser().type_id() == ValueParser::bool().type_id() {
            "bool"
        } else {
            "string?"
        };

        writeln!(buffer, "")?;
        writeln!(
            buffer,
            r#"    [ConfigItem(Description = {description:?}{default})]"#,
            default = default_value
                .map(|v| format!(", DefaultValue = {v:?}"))
                .unwrap_or("".to_owned())
        )?;
        writeln!(buffer, r#"    [GrandineConfigItem(Name = "--{arg_name}")]"#)?;
        writeln!(
            buffer,
            "    public {field_type} {field_name} {{ get; set; }}"
        )?;
    }

    write!(buffer, "}}")?;

    Ok(())
}

fn path_to_generated_csharp_artifacts_folder() -> PathBuf {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let crate_dir = PathBuf::from(crate_dir);

    crate_dir.join("generated")
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
