//! VRF state artifacts: the branch of slot 0 in the VRF tree of each genesis validator, which saves
//! building the trees.
//!
//! A record is the root, the slot as a little-endian `u32` (always 0) and the 31 siblings of the
//! leaf of slot 0, bottom-up. A validator cannot know its root without building its tree, so
//! records are found by their first sibling, the leaf of slot 1, which takes one hash of the seed.
//! The siblings below `CACHE_HEIGHT` are checked against the subtree built from the seed. The ones
//! above are not, so a bad artifact costs proposals, which the state transition refuses.

use core::{
    fmt::{Display, Formatter, Result as FmtResult},
    time::Duration,
};
use std::{collections::HashMap, path::PathBuf};

use anyhow::{Result, anyhow, bail, ensure};
use itertools::Itertools as _;
use reqwest::{Client, header};
use ssz::H256;
use types::redacting_url::RedactingUrl;

// `VRF_TREE_DEPTH`.
const BRANCH_LENGTH: usize = 31;
const RECORD_SIZE: usize = 32 + 4 + BRANCH_LENGTH * 32;

// Enough for the 10,000 keys of the devnet mnemonic, with room to spare.
const MAX_ARTIFACT_SIZE: usize = RECORD_SIZE * 100_000;

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

pub enum VrfStateSource {
    File(PathBuf),
    Http(RedactingUrl),
}

impl Display for VrfStateSource {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        match self {
            Self::File(path) => path.display().fmt(formatter),
            Self::Http(url) => url.fmt(formatter),
        }
    }
}

impl VrfStateSource {
    /// An HTTP(S) URL, a `file://` URL or a local path.
    pub fn new(value: &str) -> Result<Self> {
        let Ok(redacting_url) = value.parse::<RedactingUrl>() else {
            ensure!(!value.is_empty(), "empty VRF state URL");
            return Ok(Self::File(value.into()));
        };

        let url = redacting_url.clone().into_url();

        match url.scheme() {
            "http" | "https" => Ok(Self::Http(redacting_url)),
            "file" => url
                .to_file_path()
                .map(Self::File)
                .map_err(|()| anyhow!("invalid VRF state file URL {redacting_url}")),
            scheme => bail!("unsupported VRF state URL scheme {scheme}"),
        }
    }

    pub async fn load(&self, client: &Client) -> Result<VrfStateArtifact> {
        let bytes = match self {
            Self::File(path) => fs_err::tokio::read(path).await?,
            Self::Http(url) => {
                let response = client
                    .get(url.clone().into_url())
                    .timeout(DOWNLOAD_TIMEOUT)
                    .header(header::ACCEPT_ENCODING, "identity")
                    .send()
                    .await?
                    .error_for_status()?;

                ensure!(
                    response
                        .content_length()
                        .is_none_or(|length| length <= MAX_ARTIFACT_SIZE as u64),
                    "VRF state artifact exceeds {MAX_ARTIFACT_SIZE} bytes",
                );

                response.bytes().await?.to_vec()
            }
        };

        VrfStateArtifact::new(&bytes)
    }
}

pub struct VrfStateArtifact {
    // Records by their first sibling. `None` for a sibling that more than one record has.
    records: HashMap<H256, Option<Record>>,
}

struct Record {
    root: H256,
    branch: Vec<H256>,
}

impl VrfStateArtifact {
    fn new(bytes: &[u8]) -> Result<Self> {
        let (records, remainder) = bytes.as_chunks::<RECORD_SIZE>();

        ensure!(
            remainder.is_empty() && !records.is_empty() && bytes.len() <= MAX_ARTIFACT_SIZE,
            "VRF state artifact of {} bytes is not a list of {RECORD_SIZE}-byte records",
            bytes.len(),
        );

        let mut by_first_sibling = HashMap::with_capacity(records.len());

        for record in records {
            let (root, rest) = record.split_at(32);
            let (slot, branch) = rest.split_at(4);

            ensure!(slot == [0; 4], "VRF state records must describe slot 0");

            let (siblings, _) = branch.as_chunks::<32>();
            let branch = siblings.iter().copied().map(H256).collect_vec();
            let first_sibling = branch.first().copied().unwrap_or_default();

            let record = Record {
                root: H256::from_slice(root),
                branch,
            };

            by_first_sibling
                .entry(first_sibling)
                .and_modify(|record| *record = None)
                .or_insert(Some(record));
        }

        Ok(Self {
            records: by_first_sibling,
        })
    }

    /// The root and the branch of slot 0 in the tree whose leaf of slot 1 is `slot_1_leaf`,
    /// unchecked.
    pub fn record(&self, slot_1_leaf: H256) -> Result<(H256, &[H256])> {
        match self.records.get(&slot_1_leaf) {
            Some(Some(Record { root, branch })) => Ok((*root, branch.as_slice())),
            Some(None) => bail!("more than one VRF state record starts with {slot_1_leaf:?}"),
            None => bail!("no VRF state record starts with {slot_1_leaf:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use types::pq::consts::VRF_TREE_DEPTH;

    use super::*;

    #[test]
    fn branches_span_the_tree() {
        assert_eq!(u64::try_from(BRANCH_LENGTH), Ok(VRF_TREE_DEPTH));
    }

    fn record_bytes(root: H256, slot: u32, sibling: u8) -> Vec<u8> {
        let mut record = root.as_bytes().to_vec();
        record.extend(slot.to_le_bytes());
        record.extend(core::iter::repeat_n(sibling, BRANCH_LENGTH * 32));
        record
    }

    #[test]
    fn records_are_found_by_their_first_sibling() -> Result<()> {
        let bytes = [
            record_bytes(H256::repeat_byte(1), 0, 1),
            record_bytes(H256::repeat_byte(2), 0, 2),
            record_bytes(H256::repeat_byte(3), 0, 3),
            record_bytes(H256::repeat_byte(4), 0, 3),
        ]
        .concat();

        let artifact = VrfStateArtifact::new(&bytes)?;
        let (root, branch) = artifact.record(H256::repeat_byte(2))?;

        assert_eq!(root, H256::repeat_byte(2));
        assert_eq!(branch, [H256::repeat_byte(2); BRANCH_LENGTH]);

        artifact
            .record(H256::repeat_byte(3))
            .expect_err("ambiguous records are refused");
        artifact
            .record(H256::repeat_byte(5))
            .expect_err("missing records are refused");

        Ok(())
    }

    #[test]
    fn malformed_artifacts_are_refused() {
        let valid = record_bytes(H256::repeat_byte(1), 0, 1);

        VrfStateArtifact::new(&valid[1..]).err().expect("truncated");
        VrfStateArtifact::new(&[]).err().expect("empty");
        VrfStateArtifact::new(&record_bytes(H256::repeat_byte(1), 1, 1))
            .err()
            .expect("not slot 0");
    }

    #[test]
    fn sources_are_urls_or_paths() -> Result<()> {
        assert!(matches!(
            VrfStateSource::new("https://example.com/vrf")?,
            VrfStateSource::Http(_)
        ));
        assert!(matches!(
            VrfStateSource::new("file:///tmp/vrf")?,
            VrfStateSource::File(_)
        ));
        assert!(matches!(
            VrfStateSource::new("/tmp/vrf")?,
            VrfStateSource::File(_)
        ));
        VrfStateSource::new("ftp://example.com/vrf")
            .err()
            .expect("unsupported scheme");

        Ok(())
    }
}
