use std::sync::Arc;

use anyhow::{ensure, Result};
use ethereum_types::H32;
use fork_choice_control::{AttestationVerifierMessage, Controller};
use futures::channel::mpsc::UnboundedSender;
use grandine_version::{APPLICATION_COMMIT, APPLICATION_NAME, APPLICATION_VERSION};
use logging::{info_with_peers, warn_with_peers};
use serde::{Deserialize, Serialize, Serializer};

use crate::{endpoints::ClientVersions, eth1_execution_engine::Eth1ExecutionEngine};

pub type AttestationVerifierSender<P, W> = UnboundedSender<AttestationVerifierMessage<P, W>>;

pub type ApiController<P, W> =
    Arc<Controller<P, Arc<Eth1ExecutionEngine<P>>, AttestationVerifierSender<P, W>, W>>;

pub type RealController<P> = ApiController<P, ()>;

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum ClientCode {
    Besu,
    EthereumJS,
    Erigon,
    GoEthereum,
    Grandine,
    Lighthouse,
    Lodestar,
    Nethermind,
    Nimbus,
    TrinExecution,
    Teku,
    Prysm,
    Reth,
    Unknown(String),
}

impl ClientCode {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Besu => "BS",
            Self::EthereumJS => "EJ",
            Self::Erigon => "EG",
            Self::GoEthereum => "GE",
            Self::Grandine => "GR",
            Self::Lighthouse => "LH",
            Self::Lodestar => "LS",
            Self::Nethermind => "NM",
            Self::Nimbus => "NB",
            Self::TrinExecution => "TE",
            Self::Teku => "TK",
            Self::Prysm => "PM",
            Self::Reth => "RH",
            Self::Unknown(s) => s,
        }
    }
}

impl Serialize for ClientCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ClientCode {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ClientCodeVisitor;

        impl serde::de::Visitor<'_> for ClientCodeVisitor {
            type Value = ClientCode;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a 2-letter client code string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(match value {
                    "BS" => ClientCode::Besu,
                    "EJ" => ClientCode::EthereumJS,
                    "EG" => ClientCode::Erigon,
                    "GE" => ClientCode::GoEthereum,
                    "GR" => ClientCode::Grandine,
                    "LH" => ClientCode::Lighthouse,
                    "LS" => ClientCode::Lodestar,
                    "NM" => ClientCode::Nethermind,
                    "NB" => ClientCode::Nimbus,
                    "TE" => ClientCode::TrinExecution,
                    "TK" => ClientCode::Teku,
                    "PM" => ClientCode::Prysm,
                    "RH" => ClientCode::Reth,
                    other => {
                        info_with_peers!(
                            "received unknown client code from execution client: {other}"
                        );
                        ClientCode::Unknown(other.to_owned())
                    }
                })
            }
        }

        deserializer.deserialize_str(ClientCodeVisitor)
    }
}

pub struct WithClientVersions<T> {
    pub client_versions: Option<Arc<ClientVersions>>,
    pub result: T,
}

impl<T: Clone> Clone for WithClientVersions<T> {
    fn clone(&self) -> Self {
        Self {
            client_versions: self.client_versions.clone(),
            result: self.result.clone(),
        }
    }
}

impl<T> WithClientVersions<T> {
    pub const fn none(result: T) -> Self {
        Self {
            client_versions: None,
            result,
        }
    }

    #[must_use]
    pub fn map<U>(self, function: impl FnOnce(T) -> U) -> WithClientVersions<U> {
        let Self {
            client_versions,
            result,
        } = self;

        let result = function(result);

        WithClientVersions {
            client_versions,
            result,
        }
    }

    pub fn result(self) -> T {
        self.result
    }
}

/// [`ClientVersionV1`](https://github.com/ethereum/execution-apis/blob/f1ea4623e07516ece737e89a2a713dcdea9b8100/src/engine/identification.md#ClientVersionV1)
#[derive(Debug, Deserialize, Serialize, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ClientVersionV1 {
    pub code: ClientCode,
    pub name: String,
    pub version: String,
    #[serde(serialize_with = "serde_utils::hex_slice::serialize")]
    pub commit: H32,
}

impl ClientVersionV1 {
    #[must_use]
    pub fn own() -> Self {
        Self {
            code: ClientCode::Grandine,
            name: APPLICATION_NAME.to_owned(),
            version: APPLICATION_VERSION.to_owned(),
            commit: Self::own_commit(),
        }
    }

    #[expect(
        clippy::string_slice,
        reason = "false positive: index comes from a known valid position, \
                 obtained via `char_indices` over the same string"
    )]
    #[must_use]
    pub fn graffiti_string(&self) -> String {
        let code_string = self.code.as_str();

        let end = code_string
            .char_indices()
            .nth(2)
            .map(|(i, _)| i)
            .unwrap_or(code_string.len());

        let commit = format!("{:x}", self.commit);
        let own_commit = format!("{:x}", Self::own_commit());

        format!(
            "{}{}{}{}",
            &code_string[..end],
            &commit[..4],
            ClientCode::Grandine.as_str(),
            &own_commit[..4],
        )
    }

    fn own_commit() -> H32 {
        Self::try_own_commit()
            .inspect_err(|error| {
                warn_with_peers!("unable to produce H32 from {APPLICATION_COMMIT}: {error:?}")
            })
            .unwrap_or_default()
    }

    fn try_own_commit() -> Result<H32> {
        let decoded = hex::decode(APPLICATION_COMMIT)?;
        ensure!(decoded.len() == H32::len_bytes());
        Ok(H32::from_slice(&decoded))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use hex_literal::hex;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_client_code() -> Result<()> {
        // conversion to string
        assert_eq!(format!("{}", ClientCode::Grandine.as_str()), "GR");
        assert_eq!(
            format!("{}", ClientCode::Unknown("other".to_owned()).as_str()),
            "other"
        );

        // serialization
        assert_eq!(json!("GR"), serde_json::to_value(ClientCode::Grandine)?);
        assert_eq!(
            json!("other"),
            serde_json::to_value(ClientCode::Unknown("other".to_owned()))?
        );

        // deserialization
        assert_eq!(
            serde_json::from_value::<ClientCode>(json!("GR"))?,
            ClientCode::Grandine
        );

        assert_eq!(
            serde_json::from_value::<ClientCode>(json!("other"))?,
            ClientCode::Unknown("other".to_owned()),
        );

        Ok(())
    }

    #[test]
    fn test_client_version_own() -> Result<()> {
        let own_client_version = ClientVersionV1::own();
        let client_version_json = serde_json::to_value(&own_client_version)?;

        assert_eq!(own_client_version.code, ClientCode::Grandine);
        assert_eq!(own_client_version.name, "Grandine");
        assert_ne!(own_client_version.commit, H32::zero());

        assert_eq!(
            serde_json::from_value::<ClientVersionV1>(client_version_json)?,
            own_client_version,
        );

        Ok(())
    }

    #[test]
    fn test_known_client_version() {
        let known_client = ClientVersionV1 {
            code: ClientCode::Unknown("BS".to_owned()),
            name: "Besu".to_owned(),
            version: "25.7.0".to_owned(),
            commit: H32(hex!("4e2efab6")),
        };

        let graffiti_string = known_client.graffiti_string();

        assert!(graffiti_string.contains("BS4e2eGR"));
        assert_eq!(graffiti_string.len(), 12);
    }

    #[test]
    fn test_unknown_client_version() -> Result<()> {
        let unknown_client_json = json!({
            "code": "UNKNOWN",
            "name": "Unknown",
            "version": "1.0.0+20130313144700",
            "commit": "61adad94",
        });

        let expected_unknown_client = ClientVersionV1 {
            code: ClientCode::Unknown("UNKNOWN".to_owned()),
            name: "Unknown".to_owned(),
            version: "1.0.0+20130313144700".to_owned(),
            commit: H32(hex!("61adad94")),
        };

        let actual_unknown_client = serde_json::from_value::<ClientVersionV1>(unknown_client_json)?;

        assert_eq!(expected_unknown_client, actual_unknown_client);

        assert_eq!(
            serde_json::to_value(&expected_unknown_client)?,
            json!({
                "code": "UNKNOWN",
                "name": "Unknown",
                "version": "1.0.0+20130313144700",
                "commit": "61adad94",
            })
        );

        let graffiti_string = expected_unknown_client.graffiti_string();

        assert!(graffiti_string.contains("UN61adGR"));
        assert_eq!(graffiti_string.len(), 12);

        Ok(())
    }
}
