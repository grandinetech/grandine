//! XMSS cache artifacts: the trees of keys generated from the devnet mnemonic, which save building
//! them.
//!
//! Record `i` is leanVM's `cache_to_bytes` of the key at `m/12381/3600/i/0/0`: the top tree, then
//! the bottom trees of the first attestation leaves and the first slot-duty leaves. A key's record
//! is found through the state, which holds the key's public key at the index of a genesis validator.
//! The public parameter that ends the public key is cheap to derive from the seed, so it finds the
//! entry. Records are checked against those public keys, so the artifact needs no trust. Where a
//! derivation index differs from the validator index, the record does not match and the key is
//! built instead.

use core::{
    fmt::{Display, Formatter, Result as FmtResult},
    time::Duration,
};
use std::{collections::HashMap, io::SeekFrom, path::PathBuf};

use anyhow::{Result, anyhow, bail, ensure};
use bls::PublicKeyBytes;
use futures::{StreamExt as _, stream};
use reqwest::{Client, StatusCode, header};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use types::{
    nonstandard::PubkeyList, pq::validator_list::unpadded_pubkey, redacting_url::RedactingUrl,
};
use xmss::{PUBLIC_PARAMETER_SIZE, XmssPublicKey};

// The top tree, then two bottom trees, each with its index and the top layer's signature of it.
const RECORD_SIZE: usize = 4096 + 2 * 5300;
const RECORD_SIZE_U64: u64 = RECORD_SIZE as u64;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONCURRENT_REQUESTS: usize = 64;

/// The cached trees of a key, unchecked.
pub struct XmssCacheRecord {
    pub public_key: XmssPublicKey,
    pub bytes: Vec<u8>,
}

pub enum XmssCacheSource {
    File(PathBuf),
    Http(RedactingUrl),
}

impl Display for XmssCacheSource {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        match self {
            Self::File(path) => path.display().fmt(formatter),
            Self::Http(url) => url.fmt(formatter),
        }
    }
}

impl XmssCacheSource {
    /// An HTTP(S) URL, a `file://` URL or a local path.
    pub fn new(value: &str) -> Result<Self> {
        let Ok(redacting_url) = value.parse::<RedactingUrl>() else {
            ensure!(!value.is_empty(), "empty XMSS cache URL");
            return Ok(Self::File(value.into()));
        };

        let url = redacting_url.clone().into_url();

        match url.scheme() {
            "http" | "https" => Ok(Self::Http(redacting_url)),
            "file" => url
                .to_file_path()
                .map(Self::File)
                .map_err(|()| anyhow!("invalid XMSS cache file URL {redacting_url}")),
            scheme => bail!("unsupported XMSS cache URL scheme {scheme}"),
        }
    }

    /// The records of the keys with `public_parameters` among the padded XMSS public keys
    /// `pubkeys` of a PQ state, by the BLS public keys the parameters are given with. Keys whose
    /// records cannot be fetched are left out.
    pub async fn records(
        &self,
        client: &Client,
        pubkeys: &PubkeyList,
        public_parameters: Vec<(PublicKeyBytes, [u8; PUBLIC_PARAMETER_SIZE])>,
    ) -> (HashMap<PublicKeyBytes, XmssCacheRecord>, Vec<anyhow::Error>) {
        let mut by_parameter = HashMap::new();

        for (index, pubkey) in (0..).zip(pubkeys.iter()) {
            let public_key = unpadded_pubkey(pubkey);

            by_parameter
                .entry(public_key.public_parameter())
                .and_modify(|entry| *entry = None)
                .or_insert(Some((index, public_key)));
        }

        let mut errors = vec![];

        let requests = public_parameters
            .into_iter()
            .filter_map(|(bls_public_key, public_parameter)| {
                match by_parameter.get(&public_parameter) {
                    Some(Some((index, public_key))) => Some((bls_public_key, *index, *public_key)),
                    Some(None) => {
                        errors.push(anyhow!(
                            "more than one validator has the public parameter of {bls_public_key:?}",
                        ));
                        None
                    }
                    // Not a validator yet, or not one at all.
                    None => None,
                }
            })
            .collect::<Vec<_>>();

        let results = stream::iter(requests)
            .map(|(bls_public_key, index, public_key)| async move {
                let bytes = self.record(client, index).await.map_err(|error| {
                    error.context(format!("cannot fetch the XMSS cache record {index}"))
                })?;

                Ok((bls_public_key, XmssCacheRecord { public_key, bytes }))
            })
            .buffer_unordered(CONCURRENT_REQUESTS)
            .collect::<Vec<Result<_>>>()
            .await;

        let mut records = HashMap::new();

        for result in results {
            match result {
                Ok((bls_public_key, record)) => {
                    records.insert(bls_public_key, record);
                }
                Err(error) => errors.push(error),
            }
        }

        (records, errors)
    }

    async fn record(&self, client: &Client, index: u64) -> Result<Vec<u8>> {
        let start = index
            .checked_mul(RECORD_SIZE_U64)
            .ok_or_else(|| anyhow!("XMSS cache record {index} is out of range"))?;
        let end = start.saturating_add(RECORD_SIZE_U64.saturating_sub(1));

        match self {
            Self::File(path) => {
                let mut file = fs_err::tokio::File::open(path).await?;
                let length = file.metadata().await?.len();

                ensure!(
                    length.is_multiple_of(RECORD_SIZE_U64) && end < length,
                    "{} has no record {index}",
                    path.display(),
                );

                file.seek(SeekFrom::Start(start)).await?;

                let mut bytes = vec![0; RECORD_SIZE];
                file.read_exact(&mut bytes).await?;

                Ok(bytes)
            }
            Self::Http(url) => {
                let response = client
                    .get(url.clone().into_url())
                    .timeout(REQUEST_TIMEOUT)
                    .header(header::RANGE, format!("bytes={start}-{end}"))
                    .header(header::ACCEPT_ENCODING, "identity")
                    .send()
                    .await?;

                // A server that ignores the range would send the whole artifact.
                ensure!(
                    response.status() == StatusCode::PARTIAL_CONTENT,
                    "XMSS cache range request returned {}",
                    response.status(),
                );

                let bytes = response.bytes().await?;

                ensure!(
                    bytes.len() == RECORD_SIZE,
                    "XMSS cache record {index} has {} bytes",
                    bytes.len(),
                );

                Ok(bytes.to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_records_are_read_by_index() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("cache.xmss");
        let bytes = [vec![1; RECORD_SIZE], vec![2; RECORD_SIZE]].concat();

        fs_err::write(&path, &bytes)?;

        let source = XmssCacheSource::new(path.to_str().expect("the path is UTF-8"))?;
        let client = Client::new();

        assert_eq!(source.record(&client, 1).await?, [2; RECORD_SIZE]);
        source
            .record(&client, 2)
            .await
            .expect_err("there are only two records");

        fs_err::write(&path, &bytes[1..])?;

        source
            .record(&client, 0)
            .await
            .expect_err("a truncated artifact is refused");

        Ok(())
    }
}
