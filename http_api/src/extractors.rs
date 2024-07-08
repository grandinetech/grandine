//! Custom extractors for the [Eth Beacon Node API].
//!
//! The extractors provided by `axum` report errors in plain text with various status codes.
//! The [Eth Beacon Node API] requires errors to be reported in JSON with the 400 status code.
//!
//! [Eth Beacon Node API]: https://ethereum.github.io/beacon-APIs/

use std::sync::Arc;

use anyhow::{Error as AnyhowError, Result};
use axum::{
    async_trait,
    body::{Body, Bytes},
    extract::{FromRef, FromRequest, FromRequestParts, Path},
    http::{request::Parts, Request},
    Json, RequestExt as _, RequestPartsExt as _,
};
use axum_extra::{extract::Query, headers::ContentType, TypedHeader};
use builder_api::unphased::containers::SignedValidatorRegistrationV1;
use eth2_libp2p::PeerId;
use http_api_utils::{BlockId, StateId};
use p2p::{BeaconCommitteeSubscription, SyncCommitteeSubscription};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;
use serde_with::{As, DisplayFromStr};
use ssz::SszRead;
use types::{
    altair::containers::SignedContributionAndProof,
    config::Config,
    phase0::{
        containers::{
            Attestation, AttesterSlashing, ProposerSlashing, SignedAggregateAndProof,
            SignedVoluntaryExit,
        },
        primitives::{Epoch, ValidatorIndex},
    },
    preset::Preset,
};

use crate::{
    error::Error,
    misc::ProposerData,
    validator_status::{ValidatorId, ValidatorIdsAndStatusesBody},
};

// This has multiple `FromRequest` impls to make error messages more specific.
// They all use `FromStr`, whereas the one for `Path` uses `DeserializeOwned`.
pub struct EthPath<T>(pub T);

#[async_trait]
impl<S> FromRequestParts<S> for EthPath<BlockId> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extract::<Path<String>>()
            .await
            .map_err(AnyhowError::new)?
            .parse()
            .map(Self)
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidBlockId)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for EthPath<StateId> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extract::<Path<String>>()
            .await
            .map_err(AnyhowError::new)?
            .parse()
            .map(Self)
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidStateId)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for EthPath<PeerId> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extract::<Path<String>>()
            .await
            .map_err(AnyhowError::new)?
            .parse()
            .map(Self)
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidPeerId)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for EthPath<ValidatorId> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extract::<Path<String>>()
            .await
            .map_err(AnyhowError::new)?
            .parse()
            .map(Self)
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidValidatorId)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for EthPath<Epoch> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extract::<Path<String>>()
            .await
            .map_err(AnyhowError::new)?
            .parse()
            .map(Self)
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidEpoch)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for EthPath<(StateId, ValidatorId)> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Path((state_id, validator_id)) = parts
            .extract::<Path<(String, String)>>()
            .await
            .map_err(AnyhowError::new)?;

        let state_id = state_id
            .parse()
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidStateId)?;

        let validator_id = validator_id
            .parse()
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidValidatorId)?;

        Ok(Self((state_id, validator_id)))
    }
}

pub struct EthQuery<T>(pub T);

#[async_trait]
impl<S, T: DeserializeOwned + 'static> FromRequestParts<S> for EthQuery<T> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extract()
            .await
            .map(|Query(query)| Self(query))
            .map_err(Error::InvalidQuery)
    }
}

// This has multiple `FromRequest` impls to make error messages more specific.
pub struct EthJson<T>(pub T);

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<Box<ProposerSlashing>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(slashing)| Self(slashing))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<Box<SignedVoluntaryExit>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(slashing)| Self(slashing))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S, P: Preset> FromRequest<S, Body> for EthJson<Box<AttesterSlashing<P>>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(slashing)| Self(slashing))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S, P: Preset> FromRequest<S, Body> for EthJson<Vec<Arc<Attestation<P>>>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(attestation)| Self(attestation))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<Vec<Value>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(values)| Self(values))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<Vec<ValidatorIndex>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(with = "As::<Vec<DisplayFromStr>>")] Vec<ValidatorIndex>);

        request
            .extract()
            .await
            .map(|Json(Wrapper(indices))| Self(indices))
            .map_err(Error::InvalidValidatorIndices)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<Vec<ValidatorId>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(indices)| Self(indices))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<ValidatorIdsAndStatusesBody> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(ids_and_statuses)| Self(ids_and_statuses))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<Vec<SyncCommitteeSubscription>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(subscription)| Self(subscription))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<Vec<BeaconCommitteeSubscription>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(subscription)| Self(subscription))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S, P: Preset> FromRequest<S, Body> for EthJson<Vec<Arc<SignedAggregateAndProof<P>>>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(aggregate_and_proof)| Self(aggregate_and_proof))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S, P: Preset> FromRequest<S, Body> for EthJson<Vec<SignedContributionAndProof<P>>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(contribution_and_proof)| Self(contribution_and_proof))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<Vec<ProposerData>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(proposer_data)| Self(proposer_data))
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<Vec<SignedValidatorRegistrationV1>> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(registrations)| Self(registrations))
            .map_err(Error::InvalidJsonBody)
    }
}

pub struct EthJsonOrSsz<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S, Body> for EthJsonOrSsz<T>
where
    Arc<Config>: FromRef<S>,
    S: Send + Sync,
    T: SszRead<Config> + DeserializeOwned + 'static,
{
    type Rejection = Error;

    async fn from_request(mut request: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let run = async {
            let TypedHeader(content_type) =
                request.extract_parts::<TypedHeader<ContentType>>().await?;

            if content_type == ContentType::octet_stream() {
                let config = Arc::from_ref(state);
                let bytes = Bytes::from_request(request, state).await?;
                let block = T::from_ssz(&config, bytes)?;
                return Ok(Self(block));
            }

            let Json(block) = request.extract().await?;

            Ok(Self(block))
        };

        run.await.map_err(Error::InvalidBlock)
    }
}
