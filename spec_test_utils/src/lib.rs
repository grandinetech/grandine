use core::ops::Range;
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use derive_more::From;
use serde::{
    de::{DeserializeOwned, IgnoredAny},
    Deserialize,
};
use serde_repr::Deserialize_repr;
use snap::raw::Decoder;
use ssz::{SszRead, SszReadDefault, H256};

#[derive(Clone, Copy, Default, Deserialize_repr)]
#[repr(u8)]
pub enum BlsSetting {
    #[default]
    Optional = 0,
    Required = 1,
    Ignored = 2,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Meta {
    // Used in tests from multiple categories.
    pub bls_setting: BlsSetting,
    pub blocks_count: usize,

    // Used in `ssz_generic` tests.
    pub root: H256,

    // Used in `genesis` tests.
    pub deposits_count: usize,
    pub execution_payload_header: bool,

    // Used in `transition` tests.
    pub post_fork: String,
    pub fork_epoch: u64,
    pub fork_block: Option<usize>,

    // Present in some metadata files but not used in our test runners.
    pub description: IgnoredAny,
    pub reveal_deadlines_setting: IgnoredAny,
}

#[derive(Clone, Copy, From)]
pub struct Case<'path> {
    pub case_path_relative_to_workspace_root: &'path str,
}

impl<'path> Case<'path> {
    #[must_use]
    pub fn meta(self) -> Meta {
        self.try_yaml("meta").unwrap_or_default()
    }

    pub fn glob(self, relative_pattern: impl AsRef<str>) -> impl Iterator<Item = PathBuf> + 'path {
        let owned_pattern = self.resolve(relative_pattern.as_ref());

        let pattern = owned_pattern
            .to_str()
            .expect("pattern is formed by concatenating UTF-8 strings");

        glob::glob(pattern)
            .expect("pattern should be valid")
            .map(move |result| self.unresolve(result.expect("every path should be accessible")))
    }

    pub fn numbered_default<T: SszReadDefault + 'path>(
        self,
        file_name: &'path str,
        range: Range<usize>,
    ) -> impl Iterator<Item = T> + Clone + 'path {
        self.numbered(&(), file_name, range)
    }

    pub fn numbered<C, T: SszRead<C>>(
        self,
        context: &'path C,
        file_name: &'path str,
        range: Range<usize>,
    ) -> impl Iterator<Item = T> + Clone + 'path {
        range.map(move |index| self.ssz(context, format!("{file_name}_{index}")))
    }

    pub fn exists(self, file_name: impl AsRef<Path>) -> bool {
        self.resolve(file_name)
            .with_extension("ssz_snappy")
            .try_exists()
            .expect("could not check if file exists")
    }

    pub fn bytes(self, file_name: impl AsRef<Path>) -> Vec<u8> {
        let source = try_read(self.resolve(file_name)).expect("the file should exist");
        Decoder::new()
            .decompress_vec(source.as_slice())
            .expect("the file should be compressed with Snappy")
    }

    pub fn ssz_uncompressed_default<T: SszReadDefault>(self, file_name: impl AsRef<Path>) -> T {
        self.ssz_uncompressed(&(), file_name)
    }

    pub fn ssz_uncompressed<C, T: SszRead<C>>(self, context: &C, file_name: impl AsRef<Path>) -> T {
        let file_path = self.resolve(file_name).with_extension("ssz");
        let bytes = try_read(file_path).expect("the SSZ file should exist");
        T::from_ssz(context, bytes)
            .expect("the file should contain a value encoded in SSZ according to configuration")
    }

    pub fn ssz_default<T: SszReadDefault>(self, file_name: impl AsRef<Path>) -> T {
        self.ssz(&(), file_name)
    }

    pub fn ssz<C, T: SszRead<C>>(self, context: &C, file_name: impl AsRef<Path>) -> T {
        self.try_ssz(context, file_name)
            .expect("the SSZ Snappy file should exist")
    }

    pub fn yaml<T: DeserializeOwned>(self, file_name: impl AsRef<Path>) -> T {
        self.try_yaml(file_name)
            .expect("the YAML file should exist")
    }

    pub fn try_ssz_default<T: SszReadDefault>(self, file_name: impl AsRef<Path>) -> Option<T> {
        self.try_ssz(&(), file_name)
    }

    // `consensus-spec-tests` uses the raw Snappy format. See:
    // <https://github.com/ethereum/consensus-specs/tree/0b76c8367ed19014d104e3fbd4718e73f459a748/tests/formats#common-output-formats>
    pub fn try_ssz<C, T: SszRead<C>>(self, context: &C, file_name: impl AsRef<Path>) -> Option<T> {
        let file_path = self.resolve(file_name).with_extension("ssz_snappy");
        let source = try_read(file_path)?;
        let bytes = Decoder::new()
            .decompress_vec(source.as_slice())
            .expect("the file should contain a value encoded in SSZ and compressed with Snappy");
        let value =
            T::from_ssz(context, bytes).expect("the file should contain a value encoded in SSZ");
        Some(value)
    }

    fn try_yaml<T: DeserializeOwned>(self, file_name: impl AsRef<Path>) -> Option<T> {
        let file_path = self.resolve(file_name).with_extension("yaml");
        let bytes = try_read(file_path)?;
        let value = serde_yaml::from_slice(bytes.as_slice())
            .expect("the file should contain a value encoded in YAML");
        Some(value)
    }

    fn resolve(self, relative_path: impl AsRef<Path>) -> PathBuf {
        workspace_root_relative_to_tested_crate_root()
            .join(self.case_path_relative_to_workspace_root)
            .join(relative_path)
    }

    fn unresolve(self, path: impl AsRef<Path>) -> PathBuf {
        path.as_ref()
            .strip_prefix(workspace_root_relative_to_tested_crate_root())
            .expect(
                "paths produced by Case::resolve start with components leading to workspace root",
            )
            .strip_prefix(self.case_path_relative_to_workspace_root)
            .expect("paths produced by Case::resolve contain case path")
            .to_path_buf()
    }
}

fn try_read(file_path: impl AsRef<Path>) -> Option<Vec<u8>> {
    match fs_err::read(file_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => panic!("could not read file: {error:?}"),
    }
}

// This is needed to make `Case` work with `test_generator::test_resources`.
// Cargo runs procedural macros and tests in different working directories.
// Procedural macros are run in the workspace root.
// Tests are run in the crate root.
// See <https://github.com/frehberg/test-generator/issues/6>.
//
// `env!("CARGO_MANIFEST_DIR")` expands to the absolute path of `spec_test_utils`.
// As a result, this crate will not work correctly when used from other workspaces.
fn workspace_root_relative_to_tested_crate_root() -> PathBuf {
    let mut workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(workspace_root.pop());

    let tested_crate_root =
        std::env::current_dir().expect("current directory should exist and be accessible");

    pathdiff::diff_paths(workspace_root, tested_crate_root)
        .expect("spec_test_utils should only be used by crates inside the same workspace")
}
