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
use rembrane_store_sqlite::{MissingCipher, SqliteStore};
use serde::Deserialize;
use zeroize::Zeroizing;

const MAXIMUM_WEBHOOK_BYTES: usize = 3 * 1024 * 1024;
const DEFAULT_MAXIMUM_EVENT_AGE_SECONDS: u64 = 300;
const DEFAULT_REPLAY_WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_MAXIMUM_REPLAY_EVENTS: usize = 1_000_000;

#[derive(Clone)]
struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    runtime: Mutex<Runtime>,
    webhook_verifier: WhatsAppWebhookVerifier,
    subscription_verifier: WhatsAppSubscriptionVerifier,
    maximum_event_age_seconds: u64,
    replay_window_seconds: u64,
    maximum_replay_events: usize,
}

struct Runtime {
    store: SqliteStore<MissingCipher>,
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

impl AppState {
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
        let store =
            SqliteStore::open(database).context("failed to open the Rembrane channel store")?;
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

async fn verify_subscription(
    State(state): State<AppState>,
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

async fn receive_webhook(
    State(state): State<AppState>,
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
        Ok(mut runtime) => state.inner.webhook_verifier.ingest_text(
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
    use axum::http::StatusCode;
    use rembrane_channel_whatsapp::WhatsAppHttpStatus;

    use super::status_code;

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
}
