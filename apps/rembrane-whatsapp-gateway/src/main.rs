use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rembrane_channel_whatsapp::{
    WhatsAppHttpStatus, WhatsAppSubscriptionVerifier, WhatsAppWebhookVerifier, webhook_http_status,
};
use rembrane_crypto::RecordCipher;
use rembrane_crypto_configured::ConfiguredRecordCipher;
use rembrane_store_sqlite::SqliteStore;
use serde::Deserialize;
use zeroize::Zeroizing;

const MAXIMUM_WEBHOOK_BYTES: usize = 3 * 1024 * 1024;
const DEFAULT_MAXIMUM_EVENT_AGE_SECONDS: u64 = 300;
const DEFAULT_REPLAY_WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_MAXIMUM_REPLAY_EVENTS: usize = 1_000_000;

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
    runtime: Mutex<Runtime<C>>,
    webhook_verifier: WhatsAppWebhookVerifier,
    subscription_verifier: WhatsAppSubscriptionVerifier,
    maximum_event_age_seconds: u64,
    replay_window_seconds: u64,
    maximum_replay_events: usize,
}

struct Runtime<C> {
    store: SqliteStore<C>,
}

#[derive(Deserialize)]
struct SubscriptionQuery {
    #[serde(rename = "hub.mode")]
    mode: String,
    #[serde(rename = "hub.verify_token")]
    verification_token: String,
    #[serde(rename = "hub.challenge")]
    challenge: String,
}

impl AppState<ConfiguredRecordCipher> {
    fn from_environment() -> Result<Self> {
        let database = required_environment("REMBRANE_DATABASE")?;
        let app_secret = required_secret("REMBRANE_WHATSAPP_APP_SECRET")?;
        let binding_lookup_secret = required_secret("REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET")?;
        let verification_token = required_secret("REMBRANE_WHATSAPP_WEBHOOK_VERIFICATION_TOKEN")?;
        let maximum_event_age_seconds = positive_environment_u64(
            "REMBRANE_WHATSAPP_MAXIMUM_EVENT_AGE_SECONDS",
            DEFAULT_MAXIMUM_EVENT_AGE_SECONDS,
        )?;
        let replay_window_seconds = positive_environment_u64(
            "REMBRANE_WHATSAPP_REPLAY_WINDOW_SECONDS",
            DEFAULT_REPLAY_WINDOW_SECONDS,
        )?;
        let maximum_replay_events = positive_environment_usize(
            "REMBRANE_WHATSAPP_MAXIMUM_REPLAY_EVENTS",
            DEFAULT_MAXIMUM_REPLAY_EVENTS,
        )?;
        let cipher = ConfiguredRecordCipher::from_environment()
            .context("failed to load the channel inbox cipher")?;
        let store = SqliteStore::open(database)
            .context("failed to open the Rembrane channel store")?
            .with_cipher(cipher);
        let webhook_verifier = WhatsAppWebhookVerifier::new(
            app_secret.as_bytes().to_vec(),
            binding_lookup_secret.as_bytes().to_vec(),
        )
        .map_err(|_| anyhow::anyhow!("invalid WhatsApp webhook secrets"))?;
        let subscription_verifier =
            WhatsAppSubscriptionVerifier::new(verification_token.as_bytes().to_vec())
                .map_err(|_| anyhow::anyhow!("invalid WhatsApp verification token"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                runtime: Mutex::new(Runtime { store }),
                webhook_verifier,
                subscription_verifier,
                maximum_event_age_seconds,
                replay_window_seconds,
                maximum_replay_events,
            }),
        })
    }
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn verify_subscription<C: Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    Query(query): Query<SubscriptionQuery>,
) -> Response {
    match state.inner.subscription_verifier.verify_challenge(
        &query.mode,
        query.verification_token.as_bytes(),
        &query.challenge,
    ) {
        Ok(challenge) => (StatusCode::OK, challenge).into_response(),
        Err(_) => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn receive_webhook<C: RecordCipher + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: HeaderMap,
    payload: Bytes,
) -> StatusCode {
    let Some(signature) = headers
        .get("x-hub-signature-256")
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::UNAUTHORIZED;
    };
    let now_epoch_seconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE,
    };
    let result = match state.inner.runtime.lock() {
        Ok(mut runtime) => state.inner.webhook_verifier.ingest_text_durable(
            &mut runtime.store,
            signature,
            &payload,
            now_epoch_seconds,
            state.inner.maximum_event_age_seconds,
            state.inner.replay_window_seconds,
            state.inner.maximum_replay_events,
        ),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE,
    };
    status_code(webhook_http_status(&result))
}

const fn status_code(status: WhatsAppHttpStatus) -> StatusCode {
    match status {
        WhatsAppHttpStatus::Ok => StatusCode::OK,
        WhatsAppHttpStatus::Accepted => StatusCode::ACCEPTED,
        WhatsAppHttpStatus::BadRequest => StatusCode::BAD_REQUEST,
        WhatsAppHttpStatus::Unauthorized => StatusCode::UNAUTHORIZED,
        WhatsAppHttpStatus::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        WhatsAppHttpStatus::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        WhatsAppHttpStatus::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn required_environment(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn required_secret(name: &str) -> Result<Zeroizing<String>> {
    let value = Zeroizing::new(required_environment(name)?);
    anyhow::ensure!(!value.is_empty(), "{name} is empty");
    Ok(value)
}

fn positive_environment_u64(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse::<u64>()
                .with_context(|| format!("{name} must be a positive integer"))?;
            anyhow::ensure!(parsed > 0, "{name} must be a positive integer");
            Ok(parsed)
        }
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("failed to read {name}")),
    }
}

fn positive_environment_usize(name: &str, default: usize) -> Result<usize> {
    match std::env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse::<usize>()
                .with_context(|| format!("{name} must be a positive integer"))?;
            anyhow::ensure!(parsed > 0, "{name} must be a positive integer");
            Ok(parsed)
        }
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("failed to read {name}")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let state = AppState::from_environment()?;
    let configured_address =
        std::env::var("REMBRANE_WHATSAPP_LISTEN").unwrap_or_else(|_| "127.0.0.1:8790".to_owned());
    let address = configured_address
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("invalid listen address {configured_address}"))?;
    let allow_non_loopback =
        std::env::var("REMBRANE_WHATSAPP_ALLOW_NON_LOOPBACK").as_deref() == Ok("1");
    anyhow::ensure!(
        address.ip().is_loopback() || allow_non_loopback,
        "non-loopback HTTP requires REMBRANE_WHATSAPP_ALLOW_NON_LOOPBACK=1 and a trusted TLS proxy"
    );
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind {address}"))?;
    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/webhooks/whatsapp",
            get(verify_subscription).post(receive_webhook),
        )
        .layer(DefaultBodyLimit::max(MAXIMUM_WEBHOOK_BYTES))
        .with_state(state);
    axum::serve(listener, app)
        .await
        .context("WhatsApp gateway failed")
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
    use rembrane_channel_whatsapp::{
        WhatsAppHttpStatus, WhatsAppSubscriptionVerifier, WhatsAppWebhookVerifier,
        derive_binding_lookup_keys,
    };
    use rembrane_contracts::{ChannelKind, ChannelSenderBinding};
    use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
    use rembrane_domain::{
        ClientId, Membership, Principal, PrincipalId, Workspace, WorkspaceId, WorkspaceRole,
    };
    use rembrane_store_sqlite::SqliteStore;
    use ring::hmac;

    use super::{AppState, Inner, Runtime, receive_webhook, status_code};

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
        assert_eq!(status_code(WhatsAppHttpStatus::Ok), StatusCode::OK);
        assert_eq!(
            status_code(WhatsAppHttpStatus::Accepted),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            status_code(WhatsAppHttpStatus::BadRequest),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_code(WhatsAppHttpStatus::Unauthorized),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_code(WhatsAppHttpStatus::PayloadTooLarge),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            status_code(WhatsAppHttpStatus::TooManyRequests),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status_code(WhatsAppHttpStatus::ServiceUnavailable),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn authenticated_bound_delivery_and_replay_cross_the_real_sqlite_boundary() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock should be valid")
            .as_secs();
        let app_secret = vec![7; 32];
        let lookup_secret = vec![9; 32];
        let account_id = "15550000001";
        let sender_id = "15550000002";
        let lookup = derive_binding_lookup_keys(lookup_secret.clone(), account_id, sender_id)
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
                    ChannelKind::WhatsAppBusiness,
                    lookup.account_lookup_key(),
                    lookup.sender_lookup_key(),
                    workspace_id,
                    principal_id,
                    ClientId::new("client_whatsapp_01"),
                )
                .expect("binding should validate"),
            )
            .expect("binding should persist");
        let cipher =
            RustCryptoRecordCipher::new("gateway-test-key", [23; 32]).expect("key should validate");
        let state = AppState {
            inner: Arc::new(Inner {
                runtime: Mutex::new(Runtime {
                    store: store.with_cipher(cipher),
                }),
                webhook_verifier: WhatsAppWebhookVerifier::new(app_secret.clone(), lookup_secret)
                    .expect("verifier should initialize"),
                subscription_verifier: WhatsAppSubscriptionVerifier::new(vec![11; 32])
                    .expect("subscription verifier should initialize"),
                maximum_event_age_seconds: 300,
                replay_window_seconds: 86_400,
                maximum_replay_events: 100,
            }),
        };
        let payload = format!(
            r#"{{"object":"whatsapp_business_account","entry":[{{"changes":[{{"field":"messages","value":{{"metadata":{{"phone_number_id":"{account_id}"}},"messages":[{{"from":"{sender_id}","id":"wamid.gateway-e2e","timestamp":"{now}","type":"text","text":{{"body":"continue"}}}}]}}}}]}}]}}"#
        );
        let signature_key = hmac::Key::new(hmac::HMAC_SHA256, &app_secret);
        let signature = format!(
            "sha256={}",
            encode_hex(hmac::sign(&signature_key, payload.as_bytes()).as_ref())
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-hub-signature-256",
            HeaderValue::from_str(&signature).expect("signature header should validate"),
        );

        assert_eq!(
            receive_webhook(
                State(state.clone()),
                headers.clone(),
                Bytes::copy_from_slice(payload.as_bytes()),
            )
            .await,
            StatusCode::OK
        );
        let pending = state
            .inner
            .runtime
            .lock()
            .expect("runtime lock should be available")
            .store
            .pending_channel_messages(&WorkspaceId::new("workspace_01"), 10)
            .expect("encrypted inbox should recover");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].text(), "continue");
        assert_eq!(
            receive_webhook(
                State(state),
                headers,
                Bytes::copy_from_slice(payload.as_bytes()),
            )
            .await,
            StatusCode::OK
        );
    }
}
