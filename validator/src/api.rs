use core::time::Duration;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
};

use anyhow::{Error as AnyhowError, Result};
use axum::{
    async_trait,
    body::Body,
    extract::{FromRef, FromRequest, FromRequestParts, Path as RequestPath, State},
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, RequestExt as _, RequestPartsExt as _, Router, Server, TypedHeader,
};
use bls::PublicKeyBytes;
use directories::Directories;
use educe::Educe;
use jwt_simple::{
    algorithms::{HS256Key, MACLike as _},
    claims::{JWTClaims, NoCustomClaims},
    reexports::coarsetime::Clock,
};
use keymanager::{KeyManager, KeymanagerOperationStatus, RemoteKey, ValidatingPubkey};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std_ext::ArcExt as _;
use thiserror::Error;
use tower_http::cors::AllowOrigin;
use types::{bellatrix::primitives::Gas, phase0::primitives::ExecutionAddress};
use zeroize::Zeroizing;

const VALIDATOR_API_TOKEN_PATH: &str = "api-token.txt";
const VALIDATOR_API_SECRET_PATH: &str = "api-secret.txt";
const VALIDATOR_API_DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Educe)]
#[educe(Default(expression = "Self::with_address(Ipv4Addr::LOCALHOST, 5055)"))]
pub struct ValidatorApiConfig {
    pub address: SocketAddr,
    pub allow_origin: AllowOrigin,
    pub timeout: Duration,
}

impl ValidatorApiConfig {
    #[must_use]
    pub fn with_address(ip_address: impl Into<IpAddr>, port: u16) -> Self {
        let address = (ip_address, port).into();

        let allowed_origin = format!("http://{address}")
            .try_into()
            .expect("http:// followed by a socket address should be a valid header value");

        Self {
            address,
            allow_origin: AllowOrigin::list([allowed_origin]),
            timeout: VALIDATOR_API_DEFAULT_TIMEOUT,
        }
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("internal error")]
    Internal(#[from] AnyhowError),
    #[error("invalid JSON body")]
    InvalidJsonBody(#[source] AnyhowError),
    #[error("invalid public key")]
    InvalidPublicKey(#[source] AnyhowError),
    #[error("authentication error")]
    Unauthorized(#[source] AnyhowError),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidJsonBody(_) | Self::InvalidPublicKey(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
        }
        .into_response()
    }
}

#[derive(Serialize)]
struct EthResponse<T> {
    data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    slashing_protection: Option<String>,
}

impl<T> EthResponse<T> {
    const fn json(data: T) -> Self {
        Self {
            data,
            slashing_protection: None,
        }
    }

    fn slashing_protection(mut self, slashing_protection_json: String) -> Self {
        self.slashing_protection = Some(slashing_protection_json);
        self
    }

    fn into_json(self) -> Json<Self> {
        let Self {
            data,
            slashing_protection,
        } = self;

        let response_body = Self {
            data,
            slashing_protection,
        };

        Json(response_body)
    }
}

impl<T: Serialize> IntoResponse for EthResponse<T> {
    fn into_response(self) -> Response {
        let run = || {
            let response_body = self.into_json();
            Ok(response_body)
        };

        run().map_err(Error::Internal).into_response()
    }
}

// This has multiple `FromRequest` impls to make error messages more specific.
struct EthJson<T>(pub T);

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<SetFeeRecipientQuery> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(query)| Self(query))
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<SetGasLimitQuery> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(query)| Self(query))
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<SetGraffitiQuery> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(query)| Self(query))
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<KeystoreImportQuery> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(query)| Self(query))
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<KeystoreDeleteQuery> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(query)| Self(query))
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<RemoteKeysImportQuery> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(query)| Self(query))
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidJsonBody)
    }
}

#[async_trait]
impl<S> FromRequest<S, Body> for EthJson<RemoteKeysDeleteQuery> {
    type Rejection = Error;

    async fn from_request(request: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        request
            .extract()
            .await
            .map(|Json(query)| Self(query))
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidJsonBody)
    }
}

// This may have multiple `FromRequest` impls to make error messages more specific.
struct EthPath<T>(pub T);

#[async_trait]
impl<S> FromRequestParts<S> for EthPath<PublicKeyBytes> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extract::<RequestPath<String>>()
            .await
            .map_err(AnyhowError::new)?
            .parse()
            .map(Self)
            .map_err(AnyhowError::new)
            .map_err(Error::InvalidPublicKey)
    }
}

#[derive(Clone)]
struct ValidatorApiState {
    keymanager: Arc<KeyManager>,
    secret: Arc<Secret>,
}

impl FromRef<ValidatorApiState> for Arc<KeyManager> {
    fn from_ref(state: &ValidatorApiState) -> Self {
        state.keymanager.clone_arc()
    }
}

impl FromRef<ValidatorApiState> for Arc<Secret> {
    fn from_ref(state: &ValidatorApiState) -> Self {
        state.secret.clone_arc()
    }
}

#[derive(Deserialize)]
struct SetFeeRecipientQuery {
    ethaddress: ExecutionAddress,
}

#[derive(Deserialize)]
struct SetGasLimitQuery {
    #[serde(with = "serde_utils::string_or_native")]
    gas_limit: Gas,
}

#[derive(Deserialize)]
struct SetGraffitiQuery {
    graffiti: String,
}

#[derive(Deserialize)]
struct KeystoreImportQuery {
    keystores: Vec<String>,
    passwords: Vec<Zeroizing<String>>,
    slashing_protection: Option<String>,
}

#[derive(Deserialize)]
struct KeystoreDeleteQuery {
    pubkeys: Vec<PublicKeyBytes>,
}

#[derive(Deserialize)]
struct RemoteKeysImportQuery {
    remote_keys: Vec<RemoteKey>,
}

#[derive(Deserialize)]
struct RemoteKeysDeleteQuery {
    pubkeys: Vec<PublicKeyBytes>,
}

#[derive(Serialize)]
struct ProposerConfigResponse {
    pubkey: PublicKeyBytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    ethaddress: Option<ExecutionAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_limit: Option<Gas>,
    #[serde(skip_serializing_if = "Option::is_none")]
    graffiti: Option<String>,
}

/// `GET /eth/v1/validator/{pubkey}/feerecipient`
async fn keymanager_list_fee_recipient(
    State(keymanager): State<Arc<KeyManager>>,
    EthPath(pubkey): EthPath<PublicKeyBytes>,
) -> Result<EthResponse<ProposerConfigResponse>, Error> {
    let fee_recipient = keymanager.proposer_configs().fee_recipient(pubkey)?;

    let response = ProposerConfigResponse {
        pubkey,
        ethaddress: Some(fee_recipient),
        gas_limit: None,
        graffiti: None,
    };

    Ok(EthResponse::json(response))
}

/// `POST /eth/v1/validator/{pubkey}/feerecipient`
async fn keymanager_set_fee_recipient(
    State(keymanager): State<Arc<KeyManager>>,
    EthPath(pubkey): EthPath<PublicKeyBytes>,
    EthJson(query): EthJson<SetFeeRecipientQuery>,
) -> Result<StatusCode, Error> {
    let SetFeeRecipientQuery { ethaddress } = query;

    keymanager
        .proposer_configs()
        .set_fee_recipient(pubkey, ethaddress)?;

    Ok(StatusCode::ACCEPTED)
}

/// `DELETE /eth/v1/validator/{pubkey}/feerecipient`
async fn keymanager_delete_fee_recipient(
    State(keymanager): State<Arc<KeyManager>>,
    EthPath(pubkey): EthPath<PublicKeyBytes>,
) -> Result<StatusCode, Error> {
    keymanager.proposer_configs().delete_fee_recipient(pubkey)?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /eth/v1/validator/{pubkey}/gas_limit`
async fn keymanager_get_gas_limit(
    State(keymanager): State<Arc<KeyManager>>,
    EthPath(pubkey): EthPath<PublicKeyBytes>,
) -> Result<EthResponse<ProposerConfigResponse>, Error> {
    let gas_limit = keymanager.proposer_configs().gas_limit(pubkey)?;

    let response = ProposerConfigResponse {
        pubkey,
        ethaddress: None,
        gas_limit: Some(gas_limit),
        graffiti: None,
    };

    Ok(EthResponse::json(response))
}

/// `POST /eth/v1/validator/{pubkey}/gas_limit`
async fn keymanager_set_gas_limit(
    State(keymanager): State<Arc<KeyManager>>,
    EthPath(pubkey): EthPath<PublicKeyBytes>,
    EthJson(query): EthJson<SetGasLimitQuery>,
) -> Result<StatusCode, Error> {
    let SetGasLimitQuery { gas_limit } = query;

    keymanager
        .proposer_configs()
        .set_gas_limit(pubkey, gas_limit)?;

    Ok(StatusCode::ACCEPTED)
}

/// `DELETE /eth/v1/validator/{pubkey}/gas_limit`
async fn keymanager_delete_gas_limit(
    State(keymanager): State<Arc<KeyManager>>,
    EthPath(pubkey): EthPath<PublicKeyBytes>,
) -> Result<StatusCode, Error> {
    keymanager.proposer_configs().delete_gas_limit(pubkey)?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /eth/v1/validator/{pubkey}/graffiti`
async fn keymanager_get_graffiti(
    State(keymanager): State<Arc<KeyManager>>,
    EthPath(pubkey): EthPath<PublicKeyBytes>,
) -> Result<EthResponse<ProposerConfigResponse>, Error> {
    let graffiti = keymanager.proposer_configs().graffiti(pubkey)?;

    let response = ProposerConfigResponse {
        pubkey,
        ethaddress: None,
        gas_limit: None,
        graffiti: Some(graffiti),
    };

    Ok(EthResponse::json(response))
}

/// `POST /eth/v1/validator/{pubkey}/graffiti`
async fn keymanager_set_graffiti(
    State(keymanager): State<Arc<KeyManager>>,
    EthPath(pubkey): EthPath<PublicKeyBytes>,
    EthJson(query): EthJson<SetGraffitiQuery>,
) -> Result<StatusCode, Error> {
    let SetGraffitiQuery { graffiti } = query;

    keymanager
        .proposer_configs()
        .set_graffiti(pubkey, &graffiti)?;

    Ok(StatusCode::ACCEPTED)
}

/// `DELETE /eth/v1/validator/{pubkey}/graffiti`
async fn keymanager_delete_graffiti(
    State(keymanager): State<Arc<KeyManager>>,
    EthPath(pubkey): EthPath<PublicKeyBytes>,
) -> Result<StatusCode, Error> {
    keymanager.proposer_configs().delete_graffiti(pubkey)?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /eth/v1/keystores`
async fn keymanager_list_validating_pubkeys(
    State(keymanager): State<Arc<KeyManager>>,
) -> Result<EthResponse<Vec<ValidatingPubkey>>, Error> {
    let pubkeys = keymanager.keystores().list_validating_pubkeys().await;

    Ok(EthResponse::json(pubkeys))
}

/// `POST /eth/v1/keystores`
async fn keymanager_import_keystores(
    State(keymanager): State<Arc<KeyManager>>,
    EthJson(query): EthJson<KeystoreImportQuery>,
) -> Result<EthResponse<Vec<KeymanagerOperationStatus>>, Error> {
    let KeystoreImportQuery {
        keystores,
        passwords,
        slashing_protection,
    } = query;

    let import_statuses = keymanager
        .keystores()
        .import(keystores, passwords, slashing_protection)
        .await?;

    Ok(EthResponse::json(import_statuses))
}

/// `DELETE /eth/v1/keystores`
async fn keymanager_delete_keystores(
    State(keymanager): State<Arc<KeyManager>>,
    EthJson(query): EthJson<KeystoreDeleteQuery>,
) -> Result<EthResponse<Vec<KeymanagerOperationStatus>>, Error> {
    let KeystoreDeleteQuery { pubkeys } = query;

    let (delete_statuses, slashing_protection) = keymanager.keystores().delete(pubkeys).await?;

    Ok(EthResponse::json(delete_statuses).slashing_protection(slashing_protection))
}

/// `GET /eth/v1/remotekeys`
async fn keymanager_list_remote_keys(
    State(keymanager): State<Arc<KeyManager>>,
) -> Result<EthResponse<Vec<ValidatingPubkey>>, Error> {
    let remote_keys = keymanager.remote_keys().list().await;

    Ok(EthResponse::json(remote_keys))
}

/// `POST /eth/v1/remotekeys`
async fn keymanager_import_remote_keys(
    State(keymanager): State<Arc<KeyManager>>,
    EthJson(query): EthJson<RemoteKeysImportQuery>,
) -> Result<EthResponse<Vec<KeymanagerOperationStatus>>, Error> {
    let RemoteKeysImportQuery { remote_keys } = query;

    let import_statuses = keymanager.remote_keys().import(remote_keys).await?;

    Ok(EthResponse::json(import_statuses))
}

/// `DELETE /eth/v1/remotekeys`
async fn keymanager_delete_remote_keys(
    State(keymanager): State<Arc<KeyManager>>,
    EthJson(query): EthJson<RemoteKeysDeleteQuery>,
) -> Result<EthResponse<Vec<KeymanagerOperationStatus>>, Error> {
    let RemoteKeysDeleteQuery { pubkeys } = query;

    let delete_statuses = keymanager.remote_keys().delete(pubkeys).await;

    Ok(EthResponse::json(delete_statuses))
}

async fn authorize_token(
    State(secret): State<Arc<Secret>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, Error> {
    secret
        .key
        .verify_token::<NoCustomClaims>(auth.token(), None)
        .map_err(Error::Unauthorized)?;

    let response = next.run(request).await;
    Ok(response)
}

#[allow(clippy::module_name_repetitions)]
pub async fn run_validator_api(
    validator_api_config: ValidatorApiConfig,
    keymanager: Arc<KeyManager>,
    directories: Arc<Directories>,
) -> Result<()> {
    let Auth { secret, token } = load_or_build_auth_token(&directories)?;

    info!(
        "Validator API is listening on {}, authorization token: {token}",
        validator_api_config.address
    );

    let state = ValidatorApiState {
        keymanager,
        secret: Arc::new(secret),
    };

    let router = eth_v1_keymanager_routes()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authorize_token,
        ))
        .with_state(state);

    Server::bind(&validator_api_config.address)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(AnyhowError::new)
}

fn eth_v1_keymanager_routes() -> Router<ValidatorApiState> {
    Router::new()
        .route(
            "/eth/v1/validator/:pubkey/feerecipient",
            get(keymanager_list_fee_recipient),
        )
        .route(
            "/eth/v1/validator/:pubkey/feerecipient",
            post(keymanager_set_fee_recipient),
        )
        .route(
            "/eth/v1/validator/:pubkey/feerecipient",
            delete(keymanager_delete_fee_recipient),
        )
        .route(
            "/eth/v1/validator/:pubkey/gas_limit",
            get(keymanager_get_gas_limit),
        )
        .route(
            "/eth/v1/validator/:pubkey/gas_limit",
            post(keymanager_set_gas_limit),
        )
        .route(
            "/eth/v1/validator/:pubkey/gas_limit",
            delete(keymanager_delete_gas_limit),
        )
        .route(
            "/eth/v1/validator/:pubkey/graffiti",
            get(keymanager_get_graffiti),
        )
        .route(
            "/eth/v1/validator/:pubkey/graffiti",
            post(keymanager_set_graffiti),
        )
        .route(
            "/eth/v1/validator/:pubkey/graffiti",
            delete(keymanager_delete_graffiti),
        )
        .route("/eth/v1/keystores", get(keymanager_list_validating_pubkeys))
        .route("/eth/v1/keystores", post(keymanager_import_keystores))
        .route("/eth/v1/keystores", delete(keymanager_delete_keystores))
        .route("/eth/v1/remotekeys", get(keymanager_list_remote_keys))
        .route("/eth/v1/remotekeys", post(keymanager_import_remote_keys))
        .route("/eth/v1/remotekeys", delete(keymanager_delete_remote_keys))
}

fn load_or_build_auth_token(directories: &Arc<Directories>) -> Result<Auth> {
    match directories.validator_dir.clone() {
        Some(validator_dir) => match Auth::load_from_path(validator_dir.as_path()) {
            Ok(auth) => Ok(auth),
            Err(error) => {
                debug!("Unable to read validator API auth token/secret: {error:?}");

                let auth = Auth::generate()?;
                auth.store_on_path(validator_dir.as_path())?;
                Ok(auth)
            }
        },
        None => Auth::generate(),
    }
}

struct Auth {
    secret: Secret,
    token: String,
}

impl Auth {
    fn load_from_path(validator_dir: &Path) -> Result<Self> {
        let token = fs_err::read_to_string(validator_dir.join(VALIDATOR_API_TOKEN_PATH))?;
        let bytes =
            fs_err::read(validator_dir.join(VALIDATOR_API_SECRET_PATH)).map(Zeroizing::new)?;
        let secret = Secret::from_hex(bytes.as_slice())?;

        Ok(Self { secret, token })
    }

    fn generate() -> Result<Self> {
        let secret = Secret::generate();
        let now = Some(Clock::now_since_epoch());

        // Use JWTClaims directly as Claims does not have API for non-expiring JWTClaims creation
        let claims = JWTClaims {
            issued_at: now,
            expires_at: None,
            invalid_before: now,
            audiences: None,
            issuer: None,
            jwt_id: None,
            subject: None,
            nonce: None,
            custom: NoCustomClaims {},
        };

        let token = secret.key.authenticate(claims)?;

        Ok(Self { secret, token })
    }

    fn store_on_path(&self, validator_dir: &Path) -> Result<()> {
        fs_err::write(validator_dir.join(VALIDATOR_API_TOKEN_PATH), &self.token)?;
        fs_err::write(
            validator_dir.join(VALIDATOR_API_SECRET_PATH),
            hex::encode(self.secret.key.to_bytes()),
        )?;

        Ok(())
    }
}

struct Secret {
    key: HS256Key,
}

impl Secret {
    fn generate() -> Self {
        Self {
            key: HS256Key::generate(),
        }
    }

    fn from_hex(digits: &[u8]) -> Result<Self> {
        let bytes = hex::decode(digits).map(Zeroizing::new)?;
        let key = HS256Key::from_bytes(bytes.as_slice());

        Ok(Self { key })
    }
}
