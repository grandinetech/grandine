use core::{
    fmt::{Debug, Formatter, Result as FmtResult},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use std::{
    error::Error as StdError,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{ensure, Error as AnyhowError, Result};
use axum::{
    async_trait,
    body::Body,
    extract::{
        rejection::JsonRejection, FromRef, FromRequest, FromRequestParts, Path as RequestPath,
        State,
    },
    http::{request::Parts, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, RequestExt as _, RequestPartsExt as _, Router,
};
use axum_extra::{
    extract::{Query, QueryRejection},
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use bls::PublicKeyBytes;
use constant_time_eq::constant_time_eq;
use directories::Directories;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use helper_functions::{accessors, signing::SignForSingleFork};
use http_api_utils::{ApiError, ApiMetrics};
use keymanager::{
    KeyManager, KeymanagerOperationStatus, ListedRemoteKey, RemoteKey, ValidatingPubkey,
};
use log::{debug, info};
use prometheus_metrics::Metrics;
use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};
use signer::{Signer, SigningMessage};
use ssz::H256;
use std_ext::ArcExt as _;
use thiserror::Error;
use tower_http::cors::AllowOrigin;
use types::{
    bellatrix::primitives::Gas,
    phase0::{
        containers::{SignedVoluntaryExit, VoluntaryExit},
        primitives::{Epoch, ExecutionAddress},
    },
    preset::Preset,
};
use zeroize::Zeroizing;

const VALIDATOR_API_TOKEN_PATH: &str = "api-token.txt";
const VALIDATOR_API_DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct ValidatorApiConfig {
    pub address: SocketAddr,
    pub allow_origin: AllowOrigin,
    pub timeout: Duration,
    pub token_file: Option<PathBuf>,
}

impl Default for ValidatorApiConfig {
    fn default() -> Self {
        Self::with_address(Ipv4Addr::LOCALHOST, 5055)
    }
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
            token_file: None,
        }
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("internal error")]
    Internal(#[from] AnyhowError),
    #[error("invalid JSON body")]
    InvalidJsonBody(#[source] JsonRejection),
    #[error("invalid public key")]
    InvalidPublicKey(#[source] AnyhowError),
    #[error("invalid query string")]
    InvalidQuery(#[source] QueryRejection),
    #[error("authentication error")]
    Unauthorized,
    #[error("validator {pubkey:?} not found")]
    ValidatorNotFound { pubkey: PublicKeyBytes },
    #[error("validator {pubkey:?} is not managed by validator client")]
    ValidatorNotOwned { pubkey: PublicKeyBytes },
}

impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.format_sources())
    }
}

#[derive(Serialize)]
struct ErrorResponse<'error> {
    message: &'error Error,
}

impl ApiError for Error {
    fn sources(&self) -> impl Iterator<Item = &dyn StdError> {
        let first: &dyn StdError = self;

        let skip_duplicates = || match self {
            Self::InvalidQuery(_) => first.source()?.source()?.source(),
            _ => first.source(),
        };

        let mut next = skip_duplicates();

        core::iter::once(first).chain(core::iter::from_fn(move || {
            let source = next?.source();
            core::mem::replace(&mut next, source)
        }))
    }
}

impl Error {
    const fn body(&self) -> ErrorResponse {
        ErrorResponse { message: self }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidJsonBody(json_rejection) => json_rejection.status(),
            Self::InvalidPublicKey(_) | Self::InvalidQuery(_) => StatusCode::BAD_REQUEST,
            Self::ValidatorNotFound { pubkey: _ } | Self::ValidatorNotOwned { pubkey: _ } => {
                StatusCode::NOT_FOUND
            }
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status_code = self.status_code();
        let body = Json(self.body()).into_response();
        (status_code, body).into_response()
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

struct EthQuery<T>(pub T);

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

#[derive(Clone)]
struct ValidatorApiState<P: Preset, W: Wait> {
    controller: ApiController<P, W>,
    keymanager: Arc<KeyManager>,
    signer: Arc<Signer>,
    token: Arc<ApiToken>,
}

impl<P: Preset, W: Wait> FromRef<ValidatorApiState<P, W>> for ApiController<P, W> {
    fn from_ref(state: &ValidatorApiState<P, W>) -> Self {
        state.controller.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<ValidatorApiState<P, W>> for Arc<KeyManager> {
    fn from_ref(state: &ValidatorApiState<P, W>) -> Self {
        state.keymanager.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<ValidatorApiState<P, W>> for Arc<Signer> {
    fn from_ref(state: &ValidatorApiState<P, W>) -> Self {
        state.signer.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<ValidatorApiState<P, W>> for Arc<ApiToken> {
    fn from_ref(state: &ValidatorApiState<P, W>) -> Self {
        state.token.clone_arc()
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

#[derive(Deserialize)]
struct CreateVoluntaryExitQuery {
    epoch: Option<Epoch>,
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
    let pubkeys = keymanager.keystores().list_validating_pubkeys();

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
) -> Result<EthResponse<Vec<ListedRemoteKey>>, Error> {
    let remote_keys = keymanager.remote_keys().list();

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

    let delete_statuses = keymanager.remote_keys().delete(&pubkeys);

    Ok(EthResponse::json(delete_statuses))
}

/// `POST /eth/v1/validator/{pubkey}/voluntary_exit`
async fn keymanager_create_voluntary_exit<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(signer): State<Arc<Signer>>,
    EthPath(pubkey): EthPath<PublicKeyBytes>,
    EthQuery(query): EthQuery<CreateVoluntaryExitQuery>,
) -> Result<EthResponse<SignedVoluntaryExit>, Error> {
    let state = controller.preprocessed_state_at_current_slot()?;

    let epoch = query
        .epoch
        .unwrap_or_else(|| accessors::get_current_epoch(&state));

    let signer_snapshot = signer.load();

    if !signer_snapshot.has_key(pubkey) {
        return Err(Error::ValidatorNotOwned { pubkey });
    }

    let validator_index = accessors::index_of_public_key(&state, pubkey)
        .ok_or(Error::ValidatorNotFound { pubkey })?;

    let voluntary_exit = VoluntaryExit {
        epoch,
        validator_index,
    };

    let signature = signer_snapshot
        .sign_without_slashing_protection(
            SigningMessage::VoluntaryExit(voluntary_exit),
            voluntary_exit.signing_root(controller.chain_config(), &state),
            Some(state.as_ref().into()),
            pubkey,
        )
        .await?;

    Ok(EthResponse::json(SignedVoluntaryExit {
        message: voluntary_exit,
        signature: signature.into(),
    }))
}

async fn authorize_token(
    State(token): State<Arc<ApiToken>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, Error> {
    if !token.verify_token(auth.token()) {
        return Err(Error::Unauthorized);
    }

    let response = next.run(request).await;
    Ok(response)
}

#[allow(clippy::module_name_repetitions)]
pub async fn run_validator_api<P: Preset, W: Wait>(
    validator_api_config: ValidatorApiConfig,
    controller: ApiController<P, W>,
    directories: Arc<Directories>,
    keymanager: Arc<KeyManager>,
    signer: Arc<Signer>,
    metrics: Option<Arc<Metrics>>,
) -> Result<()> {
    let ValidatorApiConfig {
        address,
        allow_origin,
        timeout,
        token_file,
    } = validator_api_config;

    let token_file_path = token_file.map(TokenFilePath::User).unwrap_or_else(|| {
        TokenFilePath::Default(
            directories
                .validator_dir
                .clone()
                .expect("validator directory must be present to run Validator API")
                .join(VALIDATOR_API_TOKEN_PATH),
        )
    });

    let token = ApiToken::load_or_build_from(&token_file_path).map_err(|error| {
        TokenLoadError::UnableToLoad {
            error,
            token_file_path,
        }
    })?;

    info!(
        "Validator API is listening on {address}, authorization token: {:?}",
        *Zeroizing::new(hex::encode(&token.bytes)),
    );

    let state = ValidatorApiState {
        controller,
        keymanager,
        token: Arc::new(token),
        signer,
    };

    let router = eth_v1_keymanager_routes()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            authorize_token,
        ))
        .with_state(state);

    let router = http_api_utils::extend_router_with_middleware::<Error>(
        router,
        Some(timeout),
        allow_origin,
        metrics.map(ApiMetrics::validator),
    );

    let listener = tokio::net::TcpListener::bind(&address).await?;

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(AnyhowError::new)
}

fn eth_v1_keymanager_routes<P: Preset, W: Wait>() -> Router<ValidatorApiState<P, W>> {
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
        .route(
            "/eth/v1/validator/:pubkey/voluntary_exit",
            post(keymanager_create_voluntary_exit),
        )
        .route("/eth/v1/keystores", get(keymanager_list_validating_pubkeys))
        .route("/eth/v1/keystores", post(keymanager_import_keystores))
        .route("/eth/v1/keystores", delete(keymanager_delete_keystores))
        .route("/eth/v1/remotekeys", get(keymanager_list_remote_keys))
        .route("/eth/v1/remotekeys", post(keymanager_import_remote_keys))
        .route("/eth/v1/remotekeys", delete(keymanager_delete_remote_keys))
}

#[derive(Debug, Error)]
enum TokenLoadError {
    #[error("error while loading Validator API token from {token_file_path:?}: {error:?}")]
    UnableToLoad {
        error: AnyhowError,
        token_file_path: TokenFilePath,
    },
    #[error("the Validator API token must be at least 256 bits in length")]
    TokenTooShort,
}

enum TokenFilePath {
    Default(PathBuf),
    User(PathBuf),
}

impl Debug for TokenFilePath {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Default(path) => write!(f, "{path:?}"),
            Self::User(path) => write!(f, "User specified token file: {path:?}"),
        }
    }
}

#[cfg_attr(test, derive(Debug))]
struct ApiToken {
    bytes: Zeroizing<Vec<u8>>,
}

impl ApiToken {
    fn load_or_build_from(token_file_path: &TokenFilePath) -> Result<Self> {
        match token_file_path {
            TokenFilePath::Default(token_file_path) => {
                match Self::load(token_file_path.as_path()) {
                    Ok(auth) => Ok(auth),
                    Err(error) => {
                        debug!("unable to read Validator API token from default path: {error:?}");

                        let token = Self::new();
                        token.store(token_file_path.as_path())?;
                        Ok(token)
                    }
                }
            }
            TokenFilePath::User(token_file_path) => Self::load(token_file_path.as_path()),
        }
    }

    pub fn new() -> Self {
        Self {
            // Initialize token with cryptographically random content
            // [`H256::random`]: https://docs.rs/ethereum-types/0.14.1/ethereum_types/struct.H256.html#method.random
            bytes: Zeroizing::new(H256::random().as_bytes().to_vec()),
        }
    }

    fn store(&self, token_file_path: &Path) -> Result<()> {
        fs_err::write(token_file_path, Zeroizing::new(hex::encode(&self.bytes)))?;
        Ok(())
    }

    fn load(token_file_path: &Path) -> Result<Self> {
        let token = fs_err::read_to_string(token_file_path)?;

        ensure!(token.bytes().len() >= 32, TokenLoadError::TokenTooShort);

        let bytes = Zeroizing::new(hex::decode(token)?);

        Ok(Self { bytes })
    }

    fn verify_token(&self, token: &str) -> bool {
        constant_time_eq(
            Zeroizing::new(hex::encode(&self.bytes)).as_bytes(),
            token.as_bytes(),
        )
    }
}

#[allow(clippy::needless_pass_by_value)]
#[cfg(test)]
mod tests {
    use anyhow::Result as AnyhowResult;
    use axum::{extract::rejection::MissingJsonContentType, Error as AxumError};
    use itertools::Itertools as _;
    use serde_json::{json, Result, Value};
    use tempfile::{Builder, NamedTempFile};
    use test_case::test_case;

    use super::*;

    #[test_case(
        Error::ValidatorNotFound { pubkey: PublicKeyBytes::default() },
        json!({
            "message": "validator 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 not found",
        })
    )]
    fn error_is_serialized_correctly(error: Error, expected_json: Value) -> Result<()> {
        let actual_json = serde_json::to_value(error.body())?;
        assert_eq!(actual_json, expected_json);
        Ok(())
    }

    #[test]
    fn test_api_token_load() -> AnyhowResult<()> {
        let token_file = token_file()?;
        let bytes = "c41a68e090dd1db0f4e6ffb9177fba2d1c5b6e737c6b2851dbff758fe4d5443e";

        fs_err::write(token_file.path(), bytes)?;

        let token = ApiToken::load(token_file.path())?;
        assert!(token.verify_token(bytes));

        Ok(())
    }

    #[test]
    fn test_api_token_load_non_existing_file() {
        assert_eq!(
            ApiToken::load(Path::new("nonexisting-token.txt"))
                .expect_err("opening non-existing file should fail")
                .to_string(),
            "failed to open file `nonexisting-token.txt`"
        )
    }

    #[test]
    fn test_api_token_load_token_too_short() -> AnyhowResult<()> {
        let token_file = token_file()?;
        let bytes = "c41a68e090dd1db0f4e6";

        fs_err::write(token_file.path(), bytes)?;

        assert_eq!(
            ApiToken::load(token_file.path())
                .expect_err("tokens shorter than 256 bits should not be loaded")
                .to_string(),
            "the Validator API token must be at least 256 bits in length"
        );

        Ok(())
    }

    #[test]
    fn test_api_token_load_token_invalid_value() -> AnyhowResult<()> {
        let token_file = token_file()?;
        let bytes = "c41a68e090dd1db0f4e6ffb9177fba2d1c5b6e737c6b2851dbff758fe4d5443y";

        fs_err::write(token_file.path(), bytes)?;

        assert_eq!(
            ApiToken::load(token_file.path())
                .expect_err("inalid tokens should not be loaded")
                .to_string(),
            "Invalid character 'y' at position 63"
        );

        Ok(())
    }

    // Old versions of `axum::extract::rejection::JsonRejection` duplicate error sources.
    // The underlying bug in `axum-core` was fixed in <https://github.com/tokio-rs/axum/pull/2030>.
    // The fix was backported in <https://github.com/tokio-rs/axum/pull/2098> but not released.
    #[test]
    fn error_sources_does_not_yield_duplicates_from_json_rejection() {
        let error = Error::InvalidJsonBody(JsonRejection::from(MissingJsonContentType::default()));

        assert_eq!(
            error.sources().map(ToString::to_string).collect_vec(),
            [
                "invalid JSON body",
                "Expected request with `Content-Type: application/json`",
            ],
        );
    }

    // `axum_extra::extract::QueryRejection` and `axum::Error` duplicate error sources.
    // `axum::Error` has not been fixed in any version yet.
    // `axum::extract::rejection::QueryRejection` is even worse and harder to work around.
    #[test]
    fn error_sources_does_not_yield_triplicates_from_query_rejection() {
        let axum_error = AxumError::new("error");
        let error = Error::InvalidQuery(QueryRejection::FailedToDeserializeQueryString(axum_error));

        assert_eq!(
            error.sources().map(ToString::to_string).collect_vec(),
            ["invalid query string", "error"],
        );
    }

    fn token_file() -> AnyhowResult<NamedTempFile> {
        Ok(Builder::new().tempfile()?)
    }
}
