use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use rembrane_channel_mobile_share::{
    MobileShareCredentialReferences, MobileShareHttpStatus, MobileShareVerifier,
    mobile_share_http_status,
};
use rembrane_config::SecretReference;
use rembrane_crypto::RecordCipher;
use rembrane_crypto_configured::ConfiguredRecordCipher;
use rembrane_secret_local::LocalSecretResolver;
use rembrane_store_sqlite::SqliteStore;

const MAXIMUM_ENVELOPE_BYTES: usize = 64 * 1024;
const DEFAULT_MAXIMUM_EVENT_AGE_SECONDS: u64 = 300;
const DEFAULT_REPLAY_WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_MAXIMUM_REPLAY_EVENTS: usize = 100_000;

struct AppState<C = ConfiguredRecordCipher> {
    inner: Arc<Inner<C>>,
}

impl<C> Clone for AppState<C> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct Inner<C> {
    store: Mutex<SqliteStore<C>>,
    verifier: MobileShareVerifier,
    maximum_event_age_seconds: u64,
    replay_window_seconds: u64,
    maximum_replay_events: usize,
}

impl AppState<ConfiguredRecordCipher> {
    fn from_environment() -> Result<Self> {
        let database = required_environment("REMBRANE_DATABASE")?;
        let verifier = MobileShareCredentialReferences::new(
            configured_secret_reference(
                "REMBRANE_MOBILE_SHARE_SIGNING_SECRET_REFERENCE",
                "REMBRANE_MOBILE_SHARE_SIGNING_SECRET",
            )?,
            configured_secret_reference(
                "REMBRANE_MOBILE_SHARE_BINDING_LOOKUP_SECRET_REFERENCE",
                "REMBRANE_MOBILE_SHARE_BINDING_LOOKUP_SECRET",
            )?,
        )
        .and_then(|references| references.resolve(&LocalSecretResolver))
        .map_err(|_| anyhow::anyhow!("invalid or unavailable mobile-share credentials"))?;
        let cipher = ConfiguredRecordCipher::from_environment()
            .context("failed to load the channel inbox cipher")?;
        let store = SqliteStore::open(database)
            .context("failed to open the Rembrane channel store")?
            .with_cipher(cipher);
        Ok(Self {
            inner: Arc::new(Inner {
                store: Mutex::new(store),
                verifier,
                maximum_event_age_seconds: positive_environment_u64(
                    "REMBRANE_MOBILE_SHARE_MAXIMUM_EVENT_AGE_SECONDS",
                    DEFAULT_MAXIMUM_EVENT_AGE_SECONDS,
                )?,
                replay_window_seconds: positive_environment_u64(
                    "REMBRANE_MOBILE_SHARE_REPLAY_WINDOW_SECONDS",
                    DEFAULT_REPLAY_WINDOW_SECONDS,
                )?,
                maximum_replay_events: positive_environment_usize(
                    "REMBRANE_MOBILE_SHARE_MAXIMUM_REPLAY_EVENTS",
                    DEFAULT_MAXIMUM_REPLAY_EVENTS,
                )?,
            }),
        })
    }
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn receive_share<C: RecordCipher + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: HeaderMap,
    payload: Bytes,
) -> StatusCode {
    let Some(signature) = headers
        .get("x-rembrane-signature-256")
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::UNAUTHORIZED;
    };
    let now_epoch_seconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE,
    };
    let result = match state.inner.store.lock() {
        Ok(mut store) => state.inner.verifier.ingest_durable(
            &mut *store,
            signature,
            &payload,
            now_epoch_seconds,
            state.inner.maximum_event_age_seconds,
            state.inner.replay_window_seconds,
            state.inner.maximum_replay_events,
        ),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE,
    };
    status_code(mobile_share_http_status(&result))
}

const fn status_code(status: MobileShareHttpStatus) -> StatusCode {
    match status {
        MobileShareHttpStatus::Ok => StatusCode::OK,
        MobileShareHttpStatus::Accepted => StatusCode::ACCEPTED,
        MobileShareHttpStatus::BadRequest => StatusCode::BAD_REQUEST,
        MobileShareHttpStatus::Unauthorized => StatusCode::UNAUTHORIZED,
        MobileShareHttpStatus::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        MobileShareHttpStatus::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn required_environment(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn configured_secret_reference(
    locator_name: &str,
    default_variable: &str,
) -> Result<SecretReference> {
    match std::env::var(locator_name) {
        Ok(locator) => selected_secret_reference(&locator, default_variable)
            .with_context(|| format!("invalid secret reference in {locator_name}")),
        Err(std::env::VarError::NotPresent) => selected_secret_reference("", default_variable),
        Err(error) => Err(error).with_context(|| format!("failed to read {locator_name}")),
    }
}

fn selected_secret_reference(locator: &str, default_variable: &str) -> Result<SecretReference> {
    if locator.is_empty() {
        SecretReference::environment(default_variable)
            .map_err(|_| anyhow::anyhow!("invalid default secret reference"))
    } else {
        locator
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid secret reference"))
    }
}

fn positive_environment_u64(name: &str, default: u64) -> Result<u64> {
    std::env::var(name).map_or(Ok(default), |value| {
        value
            .parse::<u64>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .with_context(|| format!("{name} must be a positive integer"))
    })
}

fn positive_environment_usize(name: &str, default: usize) -> Result<usize> {
    std::env::var(name).map_or(Ok(default), |value| {
        value
            .parse::<usize>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .with_context(|| format!("{name} must be a positive integer"))
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let state = AppState::from_environment()?;
    let configured_address = std::env::var("REMBRANE_MOBILE_SHARE_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8791".to_owned());
    let address = configured_address
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("invalid listen address {configured_address}"))?;
    let allow_non_loopback =
        std::env::var("REMBRANE_MOBILE_SHARE_ALLOW_NON_LOOPBACK").as_deref() == Ok("1");
    anyhow::ensure!(
        address.ip().is_loopback() || allow_non_loopback,
        "non-loopback HTTP requires REMBRANE_MOBILE_SHARE_ALLOW_NON_LOOPBACK=1 and a trusted TLS proxy"
    );
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind {address}"))?;
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/shares", post(receive_share))
        .layer(DefaultBodyLimit::max(MAXIMUM_ENVELOPE_BYTES))
        .with_state(state);
    axum::serve(listener, app)
        .await
        .context("mobile-share gateway failed")
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use rembrane_application::{
        ChannelInboxRepository, ChannelSenderBindingRepository, WorkspaceRepository,
    };
    use rembrane_channel_mobile_share::{
        MobileShareHttpStatus, MobileShareVerifier, derive_binding_lookup_keys,
    };
    use rembrane_contracts::{ChannelKind, ChannelSenderBinding};
    use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
    use rembrane_domain::{
        ClientId, Membership, Principal, PrincipalId, Workspace, WorkspaceId, WorkspaceRole,
    };
    use rembrane_store_sqlite::SqliteStore;
    use ring::hmac;

    use super::{AppState, Inner, receive_share, selected_secret_reference, status_code};

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    #[test]
    fn maps_every_transport_status() {
        assert_eq!(status_code(MobileShareHttpStatus::Ok), StatusCode::OK);
        assert_eq!(
            status_code(MobileShareHttpStatus::Accepted),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            status_code(MobileShareHttpStatus::BadRequest),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_code(MobileShareHttpStatus::Unauthorized),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_code(MobileShareHttpStatus::PayloadTooLarge),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            status_code(MobileShareHttpStatus::ServiceUnavailable),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn secret_locator_defaults_without_accepting_inline_values() {
        let default = selected_secret_reference("", "REMBRANE_MOBILE_SHARE_SIGNING_SECRET")
            .expect("default environment reference");
        assert_eq!(
            default.environment_variable(),
            Some("REMBRANE_MOBILE_SHARE_SIGNING_SECRET")
        );
        let file = selected_secret_reference(
            "file:/run/secrets/mobile-signing",
            "REMBRANE_MOBILE_SHARE_SIGNING_SECRET",
        )
        .expect("file reference");
        assert_eq!(file.file_path(), Some("/run/secrets/mobile-signing"));
        assert!(
            selected_secret_reference("inline-secret", "REMBRANE_MOBILE_SHARE_SIGNING_SECRET")
                .is_err()
        );
    }

    #[tokio::test]
    async fn authenticated_explicit_share_reaches_the_encrypted_inbox() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should be valid")
            .as_secs();
        let signing_secret = vec![7; 32];
        let lookup_secret = vec![9; 32];
        let lookup = derive_binding_lookup_keys(lookup_secret.clone(), "account_01", "device_01")
            .expect("lookup should derive");
        let mut store = SqliteStore::open_in_memory().expect("store should initialize");
        let workspace_id = WorkspaceId::new("workspace_01");
        let principal_id = PrincipalId::new("principal_01");
        store
            .initialize_personal_workspace(
                Principal::new(principal_id.clone()),
                Workspace::personal(workspace_id.clone()),
                Membership::new(
                    workspace_id.clone(),
                    principal_id.clone(),
                    WorkspaceRole::Owner,
                ),
            )
            .expect("workspace should initialize");
        store
            .insert_channel_sender_binding(
                ChannelSenderBinding::new(
                    ChannelKind::MobileShare,
                    lookup.account_lookup_key(),
                    lookup.device_lookup_key(),
                    workspace_id,
                    principal_id,
                    ClientId::new("client_mobile_01"),
                )
                .expect("binding should validate"),
            )
            .expect("binding should persist");
        let cipher =
            RustCryptoRecordCipher::new("mobile-gateway-test-key", [23; 32]).expect("valid key");
        let state = AppState {
            inner: Arc::new(Inner {
                store: Mutex::new(store.with_cipher(cipher)),
                verifier: MobileShareVerifier::new(signing_secret.clone(), lookup_secret)
                    .expect("verifier should initialize"),
                maximum_event_age_seconds: 300,
                replay_window_seconds: 86_400,
                maximum_replay_events: 100,
            }),
        };
        let payload = format!(
            r#"{{"account_id":"account_01","device_id":"device_01","event_id":"share.gateway-e2e","text":"continue on another assistant","shared_at_epoch_seconds":{now}}}"#
        );
        let signature_key = hmac::Key::new(hmac::HMAC_SHA256, &signing_secret);
        let signature = format!(
            "sha256={}",
            encode_hex(hmac::sign(&signature_key, payload.as_bytes()).as_ref())
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-rembrane-signature-256",
            HeaderValue::from_str(&signature).expect("valid signature header"),
        );

        assert_eq!(
            receive_share(
                State(state.clone()),
                headers.clone(),
                Bytes::copy_from_slice(payload.as_bytes()),
            )
            .await,
            StatusCode::OK
        );
        let pending = state
            .inner
            .store
            .lock()
            .expect("store lock should be available")
            .claim_channel_messages(
                &WorkspaceId::new("workspace_01"),
                "gateway-test-lease",
                now,
                now + 60,
                10,
            )
            .expect("encrypted inbox should recover");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].text(), "continue on another assistant");
        assert_eq!(
            receive_share(State(state), headers, Bytes::from(payload)).await,
            StatusCode::OK
        );
    }
}
